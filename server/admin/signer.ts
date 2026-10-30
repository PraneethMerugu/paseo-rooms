// Admin signing on the owner's daemon (identity-model.md section 5.3; room-log-v2.md section 2;
// implementation plan I-7). Not wired into the plugin until I-8: reached only by unit tests.
//
// - Interactive admin statements are signed only after a confirmation: `prepare` returns a one-time
//   `confirmToken` and a description of exactly what will be signed; `confirm(token)` signs that
//   statement and nothing else. This is a usability guard, NOT a security boundary (S-12): same-user
//   code can call `confirm` as easily as the UI can. Protection against same-user callers needs the
//   dedicated OS user (identity-model 7.6).
// - Policy-automatic statements (`device.add.approved` in mode "auto", after its hold) and the no-op
//   `producer.fence` are signed without a token. `device.rekey.approved` is refused by
//   `signAutomatic`: the daemon signs it only together with the MLS commit that applies it (decision
//   round 6), through `signWithCommit`, which the admin-route commit builder calls (I-12).
// - Admin key rotation (keys-rotation-recovery.md 4.3; I-12): `stageRotation` writes the new key to
//   `admin-key.next.sealed` before `admin.key.rotated` is signed with the old key; `promote` installs it
//   once the log carries the rotation (also at start, so a crash in between loses nothing).
// - One statement at a time (section 2, forward base): while a signed statement is outstanding (no
//   receipt and no definite rejection), nothing but a fence is signed. Outstanding statements are kept
//   in `admin/<roomId>/state.sealed` before they are returned, so a restart still knows them.
//   `reconcile` settles them against the log: carried by an entry = applied (the entry is the
//   receipt); a later sequenced statement of this key with `base.seq` at or after its own = can never
//   take effect ("Not applied. Sign again?").
// The admin key is read from `admin/<roomId>/admin-key.sealed` (sealed under the KEK). Nothing here
// logs key material, tokens or statement bodies.
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { inspect } from "node:util";
import type { KeyObject } from "node:crypto";
import { z } from "zod";
import { bodyHash } from "../authority/entries";
import { b64uBytes, firstIssue, Kid, MemberId, RoomId } from "../authority/schema";
import { producerKindAllowed, STATEMENT_TYPES, type KeyChange, type SignedStatement, type StatementBody, type StatementType } from "../authority/statements";
import type { Kek } from "../keystore/keystore";
import { SECURITY_EVENTS } from "../host/room-host";
import { log } from "../log";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_KEY_CHANGE_NEW, stmtContext } from "../proto/contexts";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { sign } from "../proto/tbs";

export const ADMIN_KEY_FILE = "admin-key.sealed";
export const ADMIN_STATE_FILE = "state.sealed";
/** Lifetime of a confirmation token. */
export const CONFIRM_TOKEN_TTL_MS = 5 * 60 * 1000;

export const adminDir = (dataDir: string, roomId: string) => nodePath.join(dataDir, "admin", roomId);
export const adminKeyPath = (dataDir: string, roomId: string) => nodePath.join(adminDir(dataDir, roomId), ADMIN_KEY_FILE);
export const adminStatePath = (dataDir: string, roomId: string) => nodePath.join(adminDir(dataDir, roomId), ADMIN_STATE_FILE);
export const adminKeyPurpose = (roomId: string) => `admin-key:${roomId}`;
export const ADMIN_NEXT_KEY_FILE = "admin-key.next.sealed";
export const adminNextKeyPath = (dataDir: string, roomId: string) => nodePath.join(adminDir(dataDir, roomId), ADMIN_NEXT_KEY_FILE);
export const adminStatePurpose = (roomId: string) => `admin-state:${roomId}`;

const AdminKeyFile = z.strictObject({
  v: z.literal(2),
  typ: z.literal("admin-key"),
  roomId: RoomId,
  genesisHash: b64uBytes(32),
  memberId: MemberId,
  kid: Kid,
  seed: b64uBytes(32),
});
export type AdminKeyFile = z.infer<typeof AdminKeyFile>;

const Outstanding = z.strictObject({
  bodyHash: b64uBytes(32),
  type: z.string().min(1).max(64),
  baseSeq: z.number().int().min(-1),
  signedAt: z.number().int().min(0),
  statement: z.unknown(),
});
const AdminStateFile = z.strictObject({
  v: z.literal(2),
  typ: z.literal("admin-state"),
  roomId: RoomId,
  /** Highest base.seq of this key's statements known to be sequenced (local forward rule). */
  sequencedMaxBase: z.number().int().min(-2),
  outstanding: z.array(Outstanding).max(64),
});
type AdminStateFile = z.infer<typeof AdminStateFile>;
export type OutstandingStatement = z.infer<typeof Outstanding>;

export function writeAdminKey(dataDir: string, kek: Kek, file: AdminKeyFile): void {
  const plain = Buffer.from(rjcs(file));
  try {
    kek.writeSealed(adminKeyPath(dataDir, file.roomId), adminKeyPurpose(file.roomId), plain);
  } finally {
    plain.fill(0);
  }
}

export type AdminSignerErrorCode =
  | "admin_key_missing"
  | "admin_key_invalid"
  | "not_admin_statement"
  | "bad_data"
  | "needs_confirmation"
  | "bad_token"
  | "token_expired"
  | "outstanding"
  | "base_not_forward"
  | "needs_mls_commit";

export class AdminSignerError extends Error {
  constructor(
    readonly code: AdminSignerErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AdminSignerError";
  }
}

/** What the confirmation dialog shows: the exact statement that `confirm` will sign. */
export type SigningDescription = {
  type: StatementType;
  roomId: string;
  producerKid: string;
  base: { seq: number; hash: string };
  data: unknown;
  /** True for the types of section 4.6: every member will see a notice. */
  visibleToMembers: boolean;
};

export type StatementRequest<T extends StatementType = StatementType> = { type: T; data: StatementBody<T>["data"]; base: { seq: number; hash: string } };

/** Types that `signAutomatic` may sign without a prompt (identity-model 5.3, policy-automatic). */
const AUTOMATIC_TYPES = new Set<StatementType>(["device.add.approved", "device.rekey.approved"]);

/** A view of the log the signer settles against (RoomHost, or a member's verified copy). */
export interface LogView {
  findBody(bodyHash: string): number | undefined;
  maxBaseOf(kid: string): number | undefined;
}

export type Reconciled = { applied: { bodyHash: string; type: string; seq: number }[]; notApplied: { bodyHash: string; type: string }[]; pending: { bodyHash: string; type: string }[] };

export class AdminSigner {
  readonly kid: string;
  readonly #key: KeyObject;
  readonly #tokens = new Map<string, { body: StatementBody; expiresAt: number }>();
  private st: AdminStateFile;

  private constructor(
    private readonly dataDir: string,
    private readonly kek: Kek,
    readonly roomId: string,
    readonly memberId: string,
    readonly genesisHash: string,
    key: KeyObject,
    kid: string,
    state: AdminStateFile,
    private readonly now: () => number,
    private readonly tokenTtlMs: number,
  ) {
    this.#key = key;
    this.kid = kid;
    this.st = state;
  }

  static load(o: { dataDir: string; kek: Kek; roomId: string; now?: () => number; tokenTtlMs?: number }): AdminSigner {
    const plain = o.kek.readSealed(adminKeyPath(o.dataDir, o.roomId), adminKeyPurpose(o.roomId));
    if (!plain) throw new AdminSignerError("admin_key_missing", "No admin key for this room on this daemon");
    let file: AdminKeyFile;
    let key: KeyObject;
    try {
      const parsed = AdminKeyFile.safeParse(rjcsParse(plain));
      if (!parsed.success) throw new AdminSignerError("admin_key_invalid", `admin key file: ${firstIssue(parsed.error)}`);
      file = parsed.data;
      if (file.roomId !== o.roomId) throw new AdminSignerError("admin_key_invalid", "admin key file names another room");
      const seed = b64uDecode(file.seed, 32);
      key = ed25519PrivateKeyFromSeed(seed);
      seed.fill(0);
      if (kidOf("ed25519", rawPublicKey(key)) !== file.kid) throw new AdminSignerError("admin_key_invalid", "admin key does not match its kid");
    } finally {
      plain.fill(0);
    }
    const statePlain = o.kek.readSealed(adminStatePath(o.dataDir, o.roomId), adminStatePurpose(o.roomId));
    let state: AdminStateFile = { v: 2, typ: "admin-state", roomId: o.roomId, sequencedMaxBase: -2, outstanding: [] };
    if (statePlain) {
      const parsed = AdminStateFile.safeParse(rjcsParse(statePlain));
      if (!parsed.success || parsed.data.roomId !== o.roomId) throw new AdminSignerError("admin_key_invalid", "admin state file is invalid");
      state = parsed.data;
    }
    return new AdminSigner(o.dataDir, o.kek, o.roomId, file.memberId, file.genesisHash, key, file.kid, state, o.now ?? Date.now, o.tokenTtlMs ?? CONFIRM_TOKEN_TTL_MS);
  }

  /** The admin public key (raw 32 bytes). */
  publicKey(): Buffer {
    return rawPublicKey(this.#key);
  }

  /** Step 1 of an interactive action: the description to show and a one-time token. Signs nothing. */
  prepare<T extends StatementType>(req: StatementRequest<T>): { confirmToken: string; description: SigningDescription; expiresAt: number } {
    if (req.type === "producer.fence") throw new AdminSignerError("not_admin_statement", "use fence() for producer.fence");
    const body = this.buildBody(req);
    this.checkCanSign(body);
    this.pruneTokens();
    const confirmToken = b64u(randomBytes(32));
    const expiresAt = this.now() + this.tokenTtlMs;
    this.#tokens.set(confirmToken, { body, expiresAt });
    return { confirmToken, description: describe(body), expiresAt };
  }

  /** Step 2: signs exactly the prepared statement. The token is consumed even if signing then fails. */
  confirm(confirmToken: string): SignedStatement {
    const t = typeof confirmToken === "string" ? this.#tokens.get(confirmToken) : undefined;
    if (!t) throw new AdminSignerError("bad_token", "Unknown or already used confirmation token");
    this.#tokens.delete(confirmToken);
    if (this.now() > t.expiresAt) throw new AdminSignerError("token_expired", "The confirmation expired; show the dialog again");
    this.checkCanSign(t.body);
    return this.signAndRecord(t.body);
  }

  /**
   * Policy-automatic signing (identity-model 5.3): `device.add.approved` with mode "auto" only. The
   * caller has checked the hold on the daemon's own clock and the room policy.
   */
  signAutomatic(req: StatementRequest<"device.add.approved" | "device.rekey.approved">): SignedStatement {
    if (!AUTOMATIC_TYPES.has(req.type) || (req.data as { mode?: string }).mode !== "auto") {
      throw new AdminSignerError("needs_confirmation", `${req.type} needs a confirmation`);
    }
    if (req.type === "device.rekey.approved") throw new AdminSignerError("needs_mls_commit", "a rekey approval is signed only together with its MLS commit (I-13)");
    const body = this.buildBody(req);
    this.checkCanSign(body);
    return this.signAndRecord(body);
  }

  /**
   * `device.rekey.approved` (mode "auto" after the hold on this daemon's clock, or "admin") for the
   * admin route only (mls-integration.md 4.4): the caller submits it with its Remove plus Add commit
   * in one `commit.submit`, so the host sequences both or neither. Not for `stmt.submit`.
   */
  signWithCommit(req: StatementRequest<"device.rekey.approved">): SignedStatement {
    if (req.type !== "device.rekey.approved") throw new AdminSignerError("not_admin_statement", "only device.rekey.approved travels with a commit");
    const body = this.buildBody(req);
    this.checkCanSign(body);
    return this.signAndRecord(body);
  }

  /**
   * Admin key rotation, step 1 (keys 4.3): a fresh key, sealed in `admin-key.next.sealed` before
   * anything is signed, and its KeyChange with `newKeySig`. Reuses a staged key that is not installed
   * yet, so a retry signs the same change.
   */
  stageRotation(): { change: KeyChange; newKeySig: string } {
    const path = adminNextKeyPath(this.dataDir, this.roomId);
    let seed: Buffer | null = null;
    const plain = this.kek.readSealed(path, adminKeyPurpose(this.roomId));
    if (plain) {
      try {
        const p = AdminKeyFile.safeParse(rjcsParse(plain));
        if (p.success && p.data.roomId === this.roomId && p.data.memberId === this.memberId) seed = b64uDecode(p.data.seed, 32);
      } finally {
        plain.fill(0);
      }
    }
    if (!seed) {
      seed = randomBytes(32);
      const key = ed25519PrivateKeyFromSeed(seed);
      const file: AdminKeyFile = { v: 2, typ: "admin-key", roomId: this.roomId, genesisHash: this.genesisHash, memberId: this.memberId, kid: kidOf("ed25519", rawPublicKey(key)), seed: b64u(seed) };
      const out = Buffer.from(rjcs(file));
      try {
        this.kek.writeSealed(path, adminKeyPurpose(this.roomId), out);
      } finally {
        out.fill(0);
      }
    }
    try {
      const key = ed25519PrivateKeyFromSeed(seed);
      const change: KeyChange = { v: 2, typ: "key-change", roomId: this.roomId, subject: { kind: "admin", id: this.memberId }, old: this.kid, newSig: b64u(rawPublicKey(key)), newDh: null };
      return { change, newKeySig: b64u(sign(key, CTX_KEY_CHANGE_NEW, rjcs(change))) };
    } finally {
      seed.fill(0);
    }
  }

  /**
   * Admin key rotation, last step: when `isActive(nextKid)` (the log carries the rotation), the staged
   * key replaces `admin-key.sealed` and the staged file is deleted. Returns the signer for the new
   * key, or null when nothing was staged or the rotation is not in the log.
   */
  promote(isActive: (kid: string) => boolean): AdminSigner | null {
    const path = adminNextKeyPath(this.dataDir, this.roomId);
    const plain = this.kek.readSealed(path, adminKeyPurpose(this.roomId));
    if (!plain) return null;
    let file: AdminKeyFile;
    try {
      const p = AdminKeyFile.safeParse(rjcsParse(plain));
      if (!p.success || p.data.roomId !== this.roomId) return null;
      file = p.data;
    } finally {
      plain.fill(0);
    }
    if (!isActive(file.kid)) return null;
    writeAdminKey(this.dataDir, this.kek, file);
    fs.rmSync(path, { force: true });
    log("admin_key_promoted", { roomId: this.roomId, kid: file.kid });
    return AdminSigner.load({ dataDir: this.dataDir, kek: this.kek, roomId: this.roomId, now: this.now, tokenTtlMs: this.tokenTtlMs });
  }

  /** `producer.fence` (section 4.8): settles outstanding statements. Allowed while others are outstanding. */
  fence(base: { seq: number; hash: string }): SignedStatement {
    const body = this.buildBody({ type: "producer.fence", data: {}, base });
    this.checkCanSign(body);
    return this.signAndRecord(body);
  }

  outstanding(): readonly OutstandingStatement[] {
    return this.st.outstanding;
  }

  /** A definite answer for one statement: `receipt` (sequenced at `seq`) or `rejected` (never logged). */
  settle(hash: string, outcome: { receipt: { seq: number } } | { rejected: true }): void {
    const o = this.st.outstanding.find((x) => x.bodyHash === hash);
    if (!o) return;
    const next = { ...this.st, outstanding: this.st.outstanding.filter((x) => x.bodyHash !== hash) };
    if ("receipt" in outcome) next.sequencedMaxBase = Math.max(next.sequencedMaxBase, o.baseSeq);
    this.persist(next);
  }

  /** Settles outstanding statements against a log (section 2, "After a lost reply"). */
  reconcile(view: LogView): Reconciled {
    const out: Reconciled = { applied: [], notApplied: [], pending: [] };
    const maxBase = view.maxBaseOf(this.kid);
    const keep: OutstandingStatement[] = [];
    let sequencedMaxBase = Math.max(this.st.sequencedMaxBase, maxBase ?? -2);
    for (const o of this.st.outstanding) {
      const seq = view.findBody(o.bodyHash);
      if (seq !== undefined) out.applied.push({ bodyHash: o.bodyHash, type: o.type, seq });
      else if (maxBase !== undefined && maxBase >= o.baseSeq) out.notApplied.push({ bodyHash: o.bodyHash, type: o.type });
      else {
        out.pending.push({ bodyHash: o.bodyHash, type: o.type });
        keep.push(o);
      }
    }
    if (keep.length !== this.st.outstanding.length || sequencedMaxBase !== this.st.sequencedMaxBase) {
      this.persist({ ...this.st, sequencedMaxBase, outstanding: keep });
    }
    if (out.notApplied.length) log("admin_statement_not_applied", { roomId: this.roomId, types: out.notApplied.map((x) => x.type) });
    return out;
  }

  toJSON(): { roomId: string; kid: string } {
    return { roomId: this.roomId, kid: this.kid };
  }

  [inspect.custom](): string {
    return `AdminSigner(${this.roomId}, ${this.kid})`;
  }

  // ------------------------------------------------------------------------------- internals

  private buildBody<T extends StatementType>(req: StatementRequest<T>): StatementBody {
    const def = (STATEMENT_TYPES as Record<string, { data: z.ZodType }>)[req.type];
    if (!def || !producerKindAllowed(req.type, "admin")) throw new AdminSignerError("not_admin_statement", `an admin key does not sign ${String(req.type)}`);
    const data = def.data.safeParse(req.data);
    if (!data.success) throw new AdminSignerError("bad_data", `${req.type} data: ${firstIssue(data.error)}`);
    return { v: 2, typ: "stmt", type: req.type, roomId: this.roomId, producer: { kind: "admin", kid: this.kid }, base: { seq: req.base.seq, hash: req.base.hash }, ts: this.now(), data: req.data as StatementBody["data"] };
  }

  private checkCanSign(body: StatementBody): void {
    if (body.type !== "producer.fence" && this.st.outstanding.some((o) => o.type !== "producer.fence")) {
      throw new AdminSignerError("outstanding", "A signed statement is not confirmed yet. Wait for it, or sign a fence to settle it.");
    }
    if (body.base.seq <= this.st.sequencedMaxBase) throw new AdminSignerError("base_not_forward", `base.seq ${body.base.seq} is not after this key's last sequenced base ${this.st.sequencedMaxBase}`);
  }

  private signAndRecord(body: StatementBody): SignedStatement {
    const stmt: SignedStatement = { body, sig: b64u(sign(this.#key, stmtContext(body.type), rjcs(body))) };
    const hash = bodyHash(rjcs(stmt));
    // Recorded before it is returned: a statement nobody knows about can never be settled.
    this.persist({ ...this.st, outstanding: [...this.st.outstanding, { bodyHash: hash, type: body.type, baseSeq: body.base.seq, signedAt: this.now(), statement: stmt }] });
    return stmt;
  }

  private persist(next: AdminStateFile): void {
    this.kek.writeSealed(adminStatePath(this.dataDir, this.roomId), adminStatePurpose(this.roomId), rjcs(next, 4 * 1024 * 1024));
    this.st = next;
  }

  private pruneTokens(): void {
    const now = this.now();
    for (const [k, v] of this.#tokens) if (now > v.expiresAt) this.#tokens.delete(k);
  }
}

function describe(body: StatementBody): SigningDescription {
  return { type: body.type, roomId: body.roomId, producerKid: body.producer.kid, base: body.base, data: structuredClone(body.data), visibleToMembers: SECURITY_EVENTS[body.type] !== undefined };
}
