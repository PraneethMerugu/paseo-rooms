// Room host core, offline (implementation plan I-7; room-log-v2.md sections 2, 3, 4.6, 4.7, 8.1;
// identity-model.md section 7.1). Not wired into the plugin until I-8: reached only by unit tests.
//
// - Opens one room: host keys from `host/<roomId>/keys.sealed` (sealed under the KEK), the genesis from
//   `host/<roomId>/genesis.json` checked against the genesisHash pinned in the sealed key file, the I-2
//   writer lock, then the log (torn-line rules in room-log-store.ts) re-folded from entry 0. The log is
//   the source of truth: no other state file is read.
// - `submit` is `stmt.submit`: strict parse, then the full fold check of the candidate entry
//   (producer key valid for the type at the head, signature, schema, base, uniqueness, forward base,
//   apply). Answers `stale_base`, `unknown_base` or `not_permitted` with the current head, or a
//   receipt (the signed entry). Rejected statements are not logged.
// - `emit` appends a host-produced statement (P-27: invite burns, alerts, grants and so on are log
//   entries signed by the host key).
// - Write ordering (8.1): fold check, append body, append entry (each fsynced, each after the lock's
//   ownership check), then advance the in-memory fold, then reply. A failed append stops the room
//   until it is reopened, which re-folds the log.
// - `securityNotices` lists the events of section 4.6 with their producer; `access.jsonl` (4.7) holds
//   the host-local access log.
//
// Not here (later milestones): sessions, log.fetch and subscribe (I-8), invites and enrollment (I-9),
// grants (I-10), host key rotation (the host refuses a host.key.rotated naming a key it does not hold;
// I-12), the adjacent rekey approval plus commit write (I-13), revocation enforce-first ordering
// (grants-v2 7.1; nothing to enforce before grants and sessions exist).
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import { bodyHash, entryHash, type LogEntry, type SignedEntry } from "../authority/entries";
import { FoldError, RoomLogFold, type FoldReason, type RoomState } from "../authority/fold";
import { verifyGenesis, type RoomGenesis } from "../authority/genesis";
import { b64uBytes, firstIssue, Kid, RoomId } from "../authority/schema";
import { parseSignedStatement, StatementError, STATEMENT_TYPES, type ProducerKind, type SignedStatement, type StatementBody, type StatementType } from "../authority/statements";
import type { Kek } from "../keystore/keystore";
import { log } from "../log";
import { appendLine, PersistFailedError, writePrivateFile } from "../platform/durable";
import { defaultProtection, type FileProtection } from "../platform/file-protection";
import { LogLockLostError, LogWriterLock, type LogLockOptions } from "../platform/log-lock";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_LOG_ENTRY, stmtContext } from "../proto/contexts";
import { isServerId } from "../proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../proto/keys";
import { rjcs, rjcsParse, rjcsText, RJCS_MAX_BYTES } from "../proto/rjcs";
import { sign } from "../proto/tbs";
import { hostLogDir, hostRoomDir, RoomLogStore, type StoredRecord, type TornReport } from "./room-log-store";

// ------------------------------------------------------------------------------- files and keys

export const GENESIS_FILE = "genesis.json";
export const HOST_KEYS_FILE = "keys.sealed";
export const ACCESS_LOG_FILE = "access.jsonl";

export const hostKeysPurpose = (roomId: string) => `host-keys:${roomId}`;
export const hostKeysPath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), HOST_KEYS_FILE);
export const genesisPath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), GENESIS_FILE);

const Seed = b64uBytes(32);
/**
 * Plaintext of `host/<roomId>/keys.sealed` (identity-model 7.1: host key, room endpoint key, lane
 * endpoint keys). The genesisHash is pinned here, inside the AEAD, so a swapped genesis.json is
 * detected. Secrets are 32-byte seeds in b64u; the file is only ever written sealed.
 */
const HostKeys = z.strictObject({
  v: z.literal(2),
  typ: z.literal("host-keys"),
  roomId: RoomId,
  genesisHash: b64uBytes(32),
  hostKeys: z.array(z.strictObject({ kid: Kid, seed: Seed })).min(1).max(64),
  endpoint: z.strictObject({ serverId: z.string().refine((s) => isServerId("roomEndpoint", s)), kid: Kid, secret: Seed }),
  lanes: z.record(z.string(), z.strictObject({ kid: Kid, secret: Seed })),
});
export type HostKeys = z.infer<typeof HostKeys>;

export function writeHostKeys(dataDir: string, kek: Kek, keys: HostKeys): void {
  const plain = Buffer.from(rjcs(keys));
  try {
    kek.writeSealed(hostKeysPath(dataDir, keys.roomId), hostKeysPurpose(keys.roomId), plain);
  } finally {
    plain.fill(0);
  }
}

export function readHostKeys(dataDir: string, kek: Kek, roomId: string): HostKeys | null {
  const plain = kek.readSealed(hostKeysPath(dataDir, roomId), hostKeysPurpose(roomId));
  if (!plain) return null;
  try {
    const parsed = HostKeys.safeParse(rjcsParse(plain));
    if (!parsed.success) throw new RoomHostError("host_keys_invalid", `host keys: ${firstIssue(parsed.error)}`);
    if (parsed.data.roomId !== roomId) throw new RoomHostError("host_keys_invalid", "host keys name another room");
    return parsed.data;
  } finally {
    plain.fill(0);
  }
}

/** genesis.json: the RJCS text of the signed genesis. Plaintext and public; pinned by hash in keys.sealed. */
export function writeGenesisFile(dataDir: string, genesis: RoomGenesis, roomId: string): void {
  writePrivateFile(genesisPath(dataDir, roomId), rjcsText(genesis));
}

// ------------------------------------------------------------------------- 4.6 security events

export type SecurityCategory = "policy" | "room" | "authority_keys" | "membership" | "lane_display" | "alert";

/**
 * Events that give every member a visible notice (room-log-v2.md section 4.6; P-27). The detection
 * results of section 6 (`fork`, `truncation`) are raised by members (I-8), and the "uncertified"
 * alerts come from the fold state (`uncertifiedAlerts`).
 */
export const SECURITY_EVENTS: Readonly<Partial<Record<StatementType, SecurityCategory>>> = {
  "room.policy.changed": "policy",
  "room.close.proposed": "room",
  "room.closed": "room",
  "admin.added": "authority_keys",
  "admin.removed": "authority_keys",
  "admin.key.rotated": "authority_keys",
  "admin.key.revoked": "authority_keys",
  "recovery.key.proposed": "authority_keys",
  "recovery.key.rotated": "authority_keys",
  "host.key.rotated": "authority_keys",
  "host.key.revoked": "authority_keys",
  "endpoint.rotated": "authority_keys",
  "lane.offer.rotated": "authority_keys",
  "member.admitted": "membership",
  "member.removed": "membership",
  "member.left": "membership",
  "member.device.replaced": "membership",
  "device.added": "membership",
  "device.add.vetoed": "membership",
  "device.add.approved": "membership",
  "device.removed": "membership",
  "device.rekeyed": "membership",
  "device.rekey.vetoed": "membership",
  "device.rekey.approved": "membership",
  "device.conflict.resolved": "membership",
  "device.leaf.repair.requested": "membership",
  "lane.names.changed": "lane_display",
  "grant.suspected-theft": "alert",
  "endpoint.evicted": "alert",
  "mls.stalled": "alert",
  "lane.degraded": "alert",
};

export type SecurityNotice = {
  seq: number;
  hts: number;
  type: StatementType;
  category: SecurityCategory;
  producer: { kind: ProducerKind; kid: string };
  /** The fold marked the entry after a re-fold (section 5.1): shown, but it no longer takes effect. */
  mark: "suspect" | "void" | null;
};

/** Host-produced statement types (catalogue producer H only or H among others). */
export const HOST_STATEMENT_TYPES = (Object.keys(STATEMENT_TYPES) as StatementType[]).filter((t) => (STATEMENT_TYPES[t].producers as readonly ProducerKind[]).includes("host"));

// ------------------------------------------------------------------------------ 4.7 access log

export type AccessEvent =
  | { event: "session.opened" | "session.closed"; deviceKid: string }
  | { event: "log.fetch"; deviceKid: string; fromSeq: number; toSeq: number }
  | { event: "rate_limited"; deviceKid: string | null; what: string }
  | { event: "preauth_failed"; reason: string };

/**
 * `host/<roomId>/access.jsonl` (section 4.7): owner-only, not sealed, never secrets. Access facts for
 * the owner, not shared facts, so they stay out of the room log. Strings from peers are bounded.
 */
export class AccessLog {
  readonly path: string;
  constructor(
    dataDir: string,
    roomId: string,
    private readonly now: () => number = Date.now,
  ) {
    this.path = nodePath.join(hostRoomDir(dataDir, roomId), ACCESS_LOG_FILE);
  }

  record(e: AccessEvent): void {
    const clip = (s: string) => s.replace(/[^\x20-\x7e]/g, "?").slice(0, 64);
    const fields: Record<string, unknown> = { t: this.now(), event: e.event };
    if ("deviceKid" in e) fields.deviceKid = e.deviceKid === null ? null : Kid.safeParse(e.deviceKid).success ? e.deviceKid : "invalid";
    if (e.event === "log.fetch") Object.assign(fields, { fromSeq: e.fromSeq, toSeq: e.toSeq });
    if (e.event === "rate_limited") fields.what = clip(e.what);
    if (e.event === "preauth_failed") fields.reason = clip(e.reason);
    appendLine(this.path, JSON.stringify(fields));
  }
}

// ------------------------------------------------------------------------------- the room host

export type RoomHostErrorCode = "room_not_found" | "host_keys_invalid" | "genesis_mismatch" | "host_key_missing" | "room_stopped";

export class RoomHostError extends Error {
  constructor(
    readonly code: RoomHostErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "RoomHostError";
  }
}

export type SubmitRejection = "stale_base" | "unknown_base" | "not_permitted";
export type SubmitResult =
  | { ok: true; receipt: SignedEntry }
  | { ok: false; code: SubmitRejection; reason: FoldReason | "bad_statement" | "unknown_type" | "submit_only_with_commit" | "host_statement" | "host_key_not_held"; message: string; head: SignedEntry | null };

/** Fold reasons that mean "the state moved" (section 2): a `ver` (or KeyChange.old) or the forward-base rule. */
const STALE_REASONS = new Set<FoldReason>(["stale_version", "base_regressed"]);
/** `base` is not an entry of this chain (wrong hash, or beyond the head). */
const UNKNOWN_BASE_REASONS = new Set<FoldReason>(["base_mismatch", "base_not_before_entry"]);

export interface OpenRoomHostOptions {
  dataDir: string;
  kek: Kek;
  roomId: string;
  /** Host clock in unix ms (entry `hts`). */
  now?: () => number;
  lock?: LogLockOptions;
  protection?: FileProtection;
}

type HostSigner = { kid: string; sign: (ctx: string, payload: Uint8Array) => Buffer };

export class RoomHost {
  readonly roomId: string;
  readonly genesisHash: string;
  readonly access: AccessLog;
  /** Torn tails moved aside when this host opened the log. */
  readonly tornOnOpen: TornReport[];
  private fold: RoomLogFold;
  private readonly records: StoredRecord[];
  private readonly signers: Map<string, HostSigner>;
  private stopped: string | null = null;
  private lastHts = 0;

  private constructor(
    private readonly opts: OpenRoomHostOptions,
    readonly genesis: RoomGenesis,
    genesisHash: string,
    signers: Map<string, HostSigner>,
    private readonly lock: LogWriterLock,
    private readonly store: RoomLogStore,
    loaded: { records: StoredRecord[]; torn: TornReport[] },
  ) {
    this.roomId = opts.roomId;
    this.genesisHash = genesisHash;
    this.signers = signers;
    this.access = new AccessLog(opts.dataDir, opts.roomId, this.now);
    this.tornOnOpen = loaded.torn;
    this.records = [];
    this.fold = RoomLogFold.fromGenesis(genesis);
    for (const r of loaded.records) {
      try {
        this.fold.append(r.signed, r.body);
      } catch (err) {
        // The log is the source of truth; an entry the fold rejects is not something a crash makes.
        if (err instanceof FoldError) {
          this.stopped = `entry ${err.seq} fails the fold (${err.reason})`;
          throw new RoomHostError("room_stopped", `The room log does not fold at entry ${err.seq} (${err.reason}). The room is stopped.`);
        }
        throw err;
      }
      this.records.push(r);
      this.lastHts = Math.max(this.lastHts, r.signed.entry.hts);
    }
  }

  /**
   * Opens a room created by `createRoom` (server/admin/genesis.ts). Throws RoomHostError,
   * RoomLogCorruptError (a bad line before the last), LogLockHeldError, or SealedFileError.
   */
  static async open(opts: OpenRoomHostOptions): Promise<RoomHost> {
    const keys = readHostKeys(opts.dataDir, opts.kek, opts.roomId);
    if (!keys) throw new RoomHostError("room_not_found", "No host keys for this room");
    const raw = fs.existsSync(genesisPath(opts.dataDir, opts.roomId)) ? fs.readFileSync(genesisPath(opts.dataDir, opts.roomId)) : null;
    if (!raw) throw new RoomHostError("room_not_found", "No genesis for this room");
    const v = verifyGenesis(new Uint8Array(raw));
    if (v.genesisHash !== keys.genesisHash || v.roomId !== opts.roomId) throw new RoomHostError("genesis_mismatch", "genesis.json does not match the genesisHash pinned in the host keys");

    const signers = new Map<string, HostSigner>();
    for (const k of keys.hostKeys) {
      const priv = ed25519PrivateKeyFromSeed(b64uDecode(k.seed, 32));
      if (kidOf("ed25519", rawPublicKey(priv)) !== k.kid) throw new RoomHostError("host_keys_invalid", "a host key does not match its kid");
      signers.set(k.kid, { kid: k.kid, sign: (ctx, payload) => sign(priv, ctx, payload) });
    }

    const dir = hostLogDir(opts.dataDir, opts.roomId);
    const protection = opts.protection ?? defaultProtection();
    const lock = new LogWriterLock(dir, { protection, ...opts.lock });
    await lock.acquire();
    try {
      const store = new RoomLogStore(dir, lock, opts.now ?? Date.now, protection);
      const loaded = store.load();
      const host = new RoomHost(opts, v.genesis, v.genesisHash, signers, lock, store, loaded);
      log("room_host_open", { roomId: opts.roomId, head: host.head.seq, torn: loaded.torn.length });
      return host;
    } catch (err) {
      lock.release();
      throw err;
    }
  }

  private readonly now = (): number => (this.opts.now ?? Date.now)();

  /** The head as `{seq, hash}`; `{-1, genesisHash}` before the first entry. */
  get head(): { seq: number; hash: string } {
    return this.fold.head;
  }

  /** The signed head entry, or null for an empty log. */
  get headEntry(): SignedEntry | null {
    return this.records.at(-1)?.signed ?? null;
  }

  get state(): Readonly<RoomState> {
    return this.fold.state;
  }

  get isStopped(): boolean {
    return this.stopped !== null;
  }

  roster() {
    return this.fold.roster();
  }

  rosterHash(): string {
    return this.fold.rosterHash();
  }

  /** Highest `base.seq` of a sequenced statement by this producer key (the forward rule). */
  maxBaseOf(kid: string): number | undefined {
    return this.fold.maxBaseOf(kid);
  }

  /** Seq of the entry that carries a body with this hash, if any (a receipt lookup). */
  findBody(hash: string): number | undefined {
    const i = this.records.findIndex((r) => r.signed.entry.bodyHash === hash);
    return i === -1 ? undefined : i;
  }

  /** Stored records `[fromSeq, toSeq]` (test and owner view; log.fetch is I-8). */
  entries(fromSeq = 0, toSeq = this.records.length - 1): readonly StoredRecord[] {
    return this.records.slice(Math.max(0, fromSeq), toSeq + 1);
  }

  /**
   * `stmt.submit` (section 2). Accepts the statement as RJCS bytes or as a value; either way the
   * logged body is its canonical encoding, and the value must already be canonical.
   */
  submit(input: Uint8Array | unknown): SubmitResult {
    this.assertRunning();
    let body: Uint8Array;
    let stmt: SignedStatement;
    try {
      body = input instanceof Uint8Array ? input : rjcs(input, RJCS_MAX_BYTES);
      stmt = parseSignedStatement(rjcsParse(body, RJCS_MAX_BYTES));
    } catch (err) {
      const reason = err instanceof StatementError ? err.reason : "bad_statement";
      return this.reject("not_permitted", reason, err instanceof Error ? err.message : "not strict RJCS");
    }
    const sb = stmt.body;
    // A rekey approval travels only with its MLS commit (commit.submit, I-13; decision round 6).
    if (sb.type === "device.rekey.approved") return this.reject("not_permitted", "submit_only_with_commit", "device.rekey.approved is submitted with its MLS commit");
    // Host and node statements are appended locally, never submitted.
    if (sb.producer.kind === "host" || sb.producer.kind === "node") return this.reject("not_permitted", "host_statement", "host and node statements are not submitted");
    if (sb.type === "host.key.rotated") {
      const newSig = (sb.data as { change: { newSig: string | null } }).change.newSig;
      if (!newSig || !this.signers.has(kidOf("ed25519", b64uDecode(newSig, 32)))) {
        return this.reject("not_permitted", "host_key_not_held", "the host does not hold the new host key");
      }
    }
    return this.sequence(sb, body);
  }

  /** Appends a host-produced statement (P-27), signed by the current host key with base = head. */
  emit<T extends StatementType>(type: T, data: StatementBody<T>["data"]): SignedEntry {
    this.assertRunning();
    if (!HOST_STATEMENT_TYPES.includes(type)) throw new TypeError(`${type} is not a host statement`);
    const signer = this.currentSigner();
    const body: StatementBody = {
      v: 2,
      typ: "stmt",
      type,
      roomId: this.roomId,
      producer: { kind: "host", kid: signer.kid },
      base: this.head,
      ts: this.now(),
      data: data as StatementBody["data"],
    };
    const signed: SignedStatement = { body, sig: b64u(signer.sign(stmtContext(type), rjcs(body))) };
    const res = this.sequence(body, rjcs(signed));
    if (!res.ok) throw new RoomHostError("room_stopped", `host statement ${type} refused by the fold: ${res.reason} (${res.message})`);
    return res.receipt;
  }

  /** Security notices of section 4.6 from `fromSeq` on, in log order. */
  securityNotices(fromSeq = 0): SecurityNotice[] {
    const out: SecurityNotice[] = [];
    for (const r of this.records.slice(Math.max(0, fromSeq))) {
      const e = r.signed.entry;
      if (e.cls !== "stmt") continue;
      const category = SECURITY_EVENTS[e.type as StatementType];
      if (!category) continue;
      const sb = (rjcsParse(r.body) as SignedStatement).body;
      out.push({ seq: e.seq, hts: e.hts, type: sb.type, category, producer: { kind: sb.producer.kind, kid: sb.producer.kid }, mark: this.fold.state.marks[e.seq] ?? null });
    }
    return out;
  }

  /** Section 4.6 "Alerts": a host key, the room endpoint or a lane offer left uncertified by a re-fold. */
  uncertifiedAlerts(): { subject: "host_key" | "endpoint" | "lane_offer"; id: string }[] {
    const a = this.fold.state.auth;
    return [
      ...a.hostKeys.filter((h) => h.uncertified).map((h) => ({ subject: "host_key" as const, id: h.kid })),
      ...(a.endpointUncertified ? [{ subject: "endpoint" as const, id: a.endpoint.serverId }] : []),
      ...Object.entries(a.lanes)
        .filter(([, l]) => l.uncertified)
        .map(([id]) => ({ subject: "lane_offer" as const, id })),
    ];
  }

  /** Clean shutdown: stops the heartbeat and deletes the lock. */
  close(): void {
    this.lock.release();
  }

  // ------------------------------------------------------------------------------- internals

  private assertRunning(): void {
    if (this.stopped) throw new RoomHostError("room_stopped", `The room is stopped: ${this.stopped}. Reopen it to re-fold the log.`);
  }

  private reject(code: SubmitRejection, reason: Extract<SubmitResult, { ok: false }>["reason"], message: string): SubmitResult {
    return { ok: false, code, reason, message, head: this.headEntry };
  }

  /** The host key valid for the next entry (the current one, by position). */
  private currentSigner(): HostSigner {
    const cur = this.fold.state.auth.hostKeys.find((h) => h.toSeq === null);
    const signer = cur && this.signers.get(cur.kid);
    if (!signer) throw new RoomHostError("host_key_missing", "The current host key is not held by this host");
    return signer;
  }

  private sequence(sb: StatementBody, body: Uint8Array): SubmitResult {
    const signer = this.currentSigner();
    const seq = this.head.seq + 1;
    // hts never goes backwards: holds are measured in hts (room-log-v2 5).
    const hts = Math.max(this.now(), this.lastHts);
    const entry: LogEntry = {
      v: 2,
      typ: "log-entry",
      roomId: this.roomId,
      seq,
      prev: this.head.hash,
      hts,
      epoch: this.fold.state.epoch,
      cls: "stmt",
      type: sb.type,
      bodyHash: bodyHash(body),
      hostKid: signer.kid,
    };
    const signed: SignedEntry = { entry, hash: entryHash(entry), hsig: b64u(signer.sign(CTX_LOG_ENTRY, rjcs(entry))) };
    try {
      this.fold.check(signed, body);
    } catch (err) {
      if (!(err instanceof FoldError)) throw err;
      const code: SubmitRejection = STALE_REASONS.has(err.reason) ? "stale_base" : UNKNOWN_BASE_REASONS.has(err.reason) ? "unknown_base" : "not_permitted";
      return this.reject(code, err.reason, err.message);
    }
    try {
      this.store.append(signed, body);
    } catch (err) {
      // The files may now hold the body, or the body and the entry; memory does not. Stop, and let a
      // reopen re-fold the log, which is the source of truth.
      this.stopped = err instanceof LogLockLostError ? "the log lock was lost" : err instanceof PersistFailedError ? "a log write failed" : "a log write failed unexpectedly";
      log("room_host_stopped", { roomId: this.roomId, reason: this.stopped, code: (err as { code?: string }).code ?? null });
      throw err;
    }
    this.fold.append(signed, body);
    this.records.push({ signed, body });
    this.lastHts = hts;
    return { ok: true, receipt: signed };
  }
}
