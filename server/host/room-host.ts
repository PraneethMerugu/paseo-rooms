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
// - I-13: `appendMls` sequences MLS messages (`mls.commit`, `mls.app`), and `submitWithCommit` writes a
//   `device.rekey.approved` and its commit as two adjacent entries in one durable write, or neither.
//
// - I-12 rotations: `stageHostKey` creates the next host key in `keys.sealed` (and as a signer) and
//   returns its KeyChange with `newKeySig`; the admin's `host.key.rotated` then makes it current by
//   position. `stageEndpoint` creates the next room endpoint (`endpointNext`); after `endpoint.rotated`
//   `promoteEndpoint` makes it current and keeps the old one in `endpointOld` for the 30 days of its
//   restricted mode (keys 4.6 step 4). The host refuses a host.key.rotated naming a key it does not
//   hold, and an endpoint.rotated naming an endpoint it does not serve (keys 4.5, 4.6; round 9, item 2).
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { z } from "zod";
import { bodyHash, entryHash, type LogEntry, type SignedEntry } from "../authority/entries";
import { FoldError, RoomLogFold, type FoldReason, type RoomState } from "../authority/fold";
import { verifyGenesis, type RoomGenesis } from "../authority/genesis";
import { b64uBytes, firstIssue, Kid, RoomId } from "../authority/schema";
import { parseSignedStatement, StatementError, STATEMENT_TYPES, type KeyChange, type ProducerKind, type SignedStatement, type StatementBody, type StatementType } from "../authority/statements";
import type { Kek } from "../keystore/keystore";
import { log } from "../log";
import { appendLine, PersistFailedError, writePrivateFile } from "../platform/durable";
import { defaultProtection, type FileProtection } from "../platform/file-protection";
import { LogLockLostError, LogWriterLock, type LogLockOptions } from "../platform/log-lock";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_KEY_CHANGE_NEW, CTX_LANE_GRANT, CTX_LOG_ENTRY, stmtContext } from "../proto/contexts";
import { isServerId, newServerId } from "../proto/ids";
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
const RoomEndpointKey = z.strictObject({ serverId: z.string().refine((s) => isServerId("roomEndpoint", s)), kid: Kid, secret: Seed });
const HostKeys = z.strictObject({
  v: z.literal(2),
  typ: z.literal("host-keys"),
  roomId: RoomId,
  genesisHash: b64uBytes(32),
  hostKeys: z.array(z.strictObject({ kid: Kid, seed: Seed })).min(1).max(64),
  endpoint: RoomEndpointKey,
  /**
   * A new endpoint created for a rotation (keys 4.6 step 1) and not yet installed by
   * `endpoint.rotated`. Written by the I-12 rotation; absent until then.
   */
  endpointNext: RoomEndpointKey.optional(),
  /**
   * Endpoints replaced by `endpoint.rotated`, kept for their restricted mode (`moved`) until `until`
   * (unix ms; keys 4.6 step 4: 30 days). Written by `promoteEndpoint` (I-12).
   */
  endpointOld: z.array(RoomEndpointKey.extend({ until: z.number().int().min(0) })).max(8).optional(),
  lanes: z.record(z.string(), z.strictObject({ kid: Kid, secret: Seed })),
  /** A lane's next offer key, staged before `lane.offer.rotated` (keys 4.7; I-12). */
  lanesNext: z.record(z.string(), z.strictObject({ kid: Kid, secret: Seed, serverId: z.string().refine((s) => isServerId("laneEndpoint", s)) })).optional(),
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

/** The room endpoints a host serves: the current one and one created for a rotation (keys 4.6). */
export function servedEndpoints(keys: HostKeys | null): { serverId: string; kid: string }[] {
  if (!keys) return [];
  return [keys.endpoint, ...(keys.endpointNext ? [keys.endpointNext] : [])].map((e) => ({ serverId: e.serverId, kid: e.kid }));
}

/** Restricted mode of a replaced room endpoint (keys 4.6 step 4). */
export const ENDPOINT_MOVED_KEEP_MS = 30 * 24 * 60 * 60 * 1000;

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

/**
 * Steps 1 and 2 of grants-v2 7.1 (decide, enforce): called with the state the entry will produce,
 * after the fold accepted it and before anything touches disk. Must not do log I/O; errors are logged
 * and never stop the append.
 */
export type DecideListener = (next: Readonly<RoomState>, prev: Readonly<RoomState>, type: StatementType) => void;

export type SubmitRejection = "stale_base" | "unknown_base" | "not_permitted";
export type SubmitResult =
  | { ok: true; receipt: SignedEntry }
  | { ok: false; code: SubmitRejection; reason: FoldReason | "bad_statement" | "unknown_type" | "submit_only_with_commit" | "host_statement" | "host_key_not_held" | "endpoint_not_served"; message: string; head: SignedEntry | null };

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
  /** Revocation ordering (grants-v2 7.1): called after the fold check, before the log append. */
  private readonly decideListeners: DecideListener[] = [];

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
      // A rotation sequenced just before a crash: the staged endpoint becomes current (keys 4.6).
      host.promoteEndpoint();
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
    if (sb.type === "endpoint.rotated") {
      // Keys 4.6 step 1: the host creates and serves the new endpoint first. Sequencing a rotation to
      // an endpoint nobody answers would send every member to a dead address (round 9, item 2).
      // Read at submit time (a rare statement), so an endpoint created after open counts.
      const d = sb.data as { serverId: string; dh: { kid: string } };
      let served: { serverId: string; kid: string }[] = [];
      try {
        served = servedEndpoints(readHostKeys(this.opts.dataDir, this.opts.kek, this.roomId));
      } catch {
        // An unreadable key file serves nothing; refusing is the safe answer.
      }
      if (!served.some((e) => e.serverId === d.serverId && e.kid === d.dh.kid)) {
        return this.reject("not_permitted", "endpoint_not_served", "the host does not serve the named endpoint");
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

  /** Registers a decide-and-enforce listener (grants-v2 7.1); returns the unregister function. */
  onDecide(fn: DecideListener): () => void {
    this.decideListeners.push(fn);
    return () => {
      const i = this.decideListeners.indexOf(fn);
      if (i >= 0) this.decideListeners.splice(i, 1);
    };
  }

  /**
   * Signs a lane grant (grants-v2 2) with the current host key, under the "lane-grant" context only.
   * Refused while that key is uncertified or revoked: such a key never issues grants.
   */
  signGrant(payload: Uint8Array): { kid: string; sig: Buffer } {
    this.assertRunning();
    const cur = this.fold.state.auth.hostKeys.find((h) => h.toSeq === null);
    if (!cur || cur.uncertified || cur.revoked) throw new RoomHostError("host_key_missing", "The current host key may not issue grants");
    const signer = this.currentSigner();
    return { kid: signer.kid, sig: signer.sign(CTX_LANE_GRANT, payload) };
  }

  /**
   * Keys 4.5 step 1: the next host key. Written to `keys.sealed` and added to the signers before the
   * admin signs `host.key.rotated`, so the host holds it when the rotation is sequenced. A staged key
   * that is not yet certified is reused. Returns the KeyChange (old: the current host key) and the new
   * key's `newKeySig`; nothing secret leaves.
   */
  stageHostKey(): { change: KeyChange; newKeySig: string } {
    this.assertRunning();
    const keys = readHostKeys(this.opts.dataDir, this.opts.kek, this.roomId);
    if (!keys) throw new RoomHostError("room_not_found", "No host keys for this room");
    const a = this.fold.state.auth;
    const cur = a.hostKeys.find((h) => h.toSeq === null);
    if (!cur) throw new RoomHostError("host_key_missing", "no current host key");
    const known = new Set(a.hostKeys.map((h) => h.kid));
    let staged = keys.hostKeys.find((k) => !known.has(k.kid));
    if (!staged) {
      if (keys.hostKeys.length >= 64) throw new RoomHostError("host_keys_invalid", "too many host keys held");
      const seed = randomBytes(32);
      staged = { kid: kidOf("ed25519", rawPublicKey(ed25519PrivateKeyFromSeed(seed))), seed: b64u(seed) };
      seed.fill(0);
      writeHostKeys(this.opts.dataDir, this.opts.kek, { ...keys, hostKeys: [...keys.hostKeys, staged] });
    }
    const priv = ed25519PrivateKeyFromSeed(b64uDecode(staged.seed, 32));
    if (!this.signers.has(staged.kid)) this.signers.set(staged.kid, { kid: staged.kid, sign: (ctx, payload) => sign(priv, ctx, payload) });
    const change: KeyChange = { v: 2, typ: "key-change", roomId: this.roomId, subject: { kind: "host", id: "host" }, old: cur.kid, newSig: b64u(rawPublicKey(priv)), newDh: null };
    log("host_key_staged", { roomId: this.roomId, kid: staged.kid });
    return { change, newKeySig: b64u(sign(priv, CTX_KEY_CHANGE_NEW, rjcs(change))) };
  }

  /**
   * Keys 4.6 step 1: the next room endpoint (new serverId and X25519 key) in `endpointNext`, which the
   * host serves once `endpoint.rotated` names it. Reuses a staged one. Returns public values only.
   */
  stageEndpoint(): { serverId: string; dh: { alg: "x25519"; kid: string; pub: string } } {
    this.assertRunning();
    const keys = readHostKeys(this.opts.dataDir, this.opts.kek, this.roomId);
    if (!keys) throw new RoomHostError("room_not_found", "No host keys for this room");
    let next = keys.endpointNext;
    if (!next) {
      const secret = new Uint8Array(randomBytes(32));
      next = { serverId: newServerId("roomEndpoint"), kid: kidOf("x25519", x25519.getPublicKey(secret)), secret: b64u(secret) };
      secret.fill(0);
      writeHostKeys(this.opts.dataDir, this.opts.kek, { ...keys, endpointNext: next });
    }
    const pub = x25519.getPublicKey(b64uDecode(next.secret, 32));
    return { serverId: next.serverId, dh: { alg: "x25519", kid: next.kid, pub: b64u(pub) } };
  }

  /**
   * Keys 4.6 after `endpoint.rotated`: when the folded endpoint is `endpointNext`, it becomes
   * `endpoint` and the old one moves to `endpointOld` until now + 30 days. Expired old endpoints are
   * dropped. Idempotent; also run at open, so a crash between the append and this write loses nothing.
   */
  promoteEndpoint(): boolean {
    const keys = readHostKeys(this.opts.dataDir, this.opts.kek, this.roomId);
    if (!keys) return false;
    const auth = this.fold.state.auth.endpoint;
    const now = this.now();
    const old = (keys.endpointOld ?? []).filter((e) => e.until > now);
    if (!keys.endpointNext || keys.endpointNext.serverId !== auth.serverId || keys.endpointNext.kid !== auth.dh.kid) {
      if (old.length !== (keys.endpointOld ?? []).length) writeHostKeys(this.opts.dataDir, this.opts.kek, { ...keys, endpointOld: old });
      return false;
    }
    const { endpointNext: next, ...rest } = keys;
    writeHostKeys(this.opts.dataDir, this.opts.kek, { ...rest, endpoint: next, endpointOld: [...old, { ...keys.endpoint, until: now + ENDPOINT_MOVED_KEEP_MS }].slice(-8) });
    log("room_endpoint_promoted", { roomId: this.roomId, serverId: next.serverId });
    return true;
  }

  /** The signed entry and body of the last `endpoint.rotated` (the `moved` answer of keys 4.6 step 4). */
  lastEndpointRotation(): { entry: SignedEntry; body: string } | null {
    for (let i = this.records.length - 1; i >= 0; i--) {
      const r = this.records[i];
      if (r.signed.entry.type === "endpoint.rotated" && this.fold.state.marks[i] === undefined) return { entry: r.signed, body: rjcsText(rjcsParse(r.body)) };
    }
    return null;
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

  /** A signed entry at `seq` after `prev`, signed by the current host key. */
  private buildEntry(seq: number, prev: string, hts: number, cls: "stmt" | "mls", type: string, body: Uint8Array, epoch: number | null): SignedEntry {
    const signer = this.currentSigner();
    const entry: LogEntry = { v: 2, typ: "log-entry", roomId: this.roomId, seq, prev, hts, epoch, cls, type: type as LogEntry["type"], bodyHash: bodyHash(body), hostKid: signer.kid };
    return { entry, hash: entryHash(entry), hsig: b64u(signer.sign(CTX_LOG_ENTRY, rjcs(entry))) };
  }

  /** Appends records to the store, then to the fold; a failed write stops the room (8.1). */
  private commitRecords(records: StoredRecord[], hts: number): void {
    try {
      if (records.length === 1) this.store.append(records[0].signed, records[0].body);
      else this.store.appendMany(records);
    } catch (err) {
      this.stopped = err instanceof LogLockLostError ? "the log lock was lost" : err instanceof PersistFailedError ? "a log write failed" : "a log write failed unexpectedly";
      log("room_host_stopped", { roomId: this.roomId, reason: this.stopped, code: (err as { code?: string }).code ?? null });
      throw err;
    }
    for (const r of records) {
      this.fold.append(r.signed, r.body);
      this.records.push(r);
    }
    this.lastHts = hts;
  }

  /**
   * Appends an MLS message (`mls.commit` or `mls.app`, room-log-v2.md 4.5) at the head. `epoch` is the
   * room group's epoch after this entry. The host cannot read the body; members validate it.
   */
  appendMls(type: "mls.commit" | "mls.app", body: Uint8Array, epoch: number | null): SignedEntry {
    this.assertRunning();
    const hts = Math.max(this.now(), this.lastHts);
    const signed = this.buildEntry(this.head.seq + 1, this.head.hash, hts, "mls", type, body, epoch);
    this.fold.check(signed, body);
    this.commitRecords([{ signed, body }], hts);
    return signed;
  }

  /**
   * `commit.submit {…, statement}` for `device.rekey.approved` (decision round 6; mls-integration.md 4.4,
   * 6.1): the statement at `s` and the commit at `s + 1`, adjacent, in one durable write, or neither.
   * `checkCommit` sees the state the statement produces (for `stale_roster`); a non-null answer refuses
   * both. A pair torn by a crash is moved aside on the next open (room-log-store.ts).
   */
  submitWithCommit(
    input: Uint8Array | unknown,
    commitBody: Uint8Array,
    commitEpoch: number | null,
    checkCommit: (next: Readonly<RoomState>) => { code: string; fields: Record<string, unknown> } | null,
  ): { ok: true; statement: SignedEntry; commit: SignedEntry } | Extract<SubmitResult, { ok: false }> | { ok: false; code: "commit_refused"; refusal: { code: string; fields: Record<string, unknown> } } {
    this.assertRunning();
    let body: Uint8Array;
    let stmt: SignedStatement;
    try {
      body = input instanceof Uint8Array ? input : rjcs(input, RJCS_MAX_BYTES);
      stmt = parseSignedStatement(rjcsParse(body, RJCS_MAX_BYTES));
    } catch (err) {
      const reason = err instanceof StatementError ? err.reason : "bad_statement";
      return this.reject("not_permitted", reason, err instanceof Error ? err.message : "not strict RJCS") as Extract<SubmitResult, { ok: false }>;
    }
    if (stmt.body.type !== "device.rekey.approved") return this.reject("not_permitted", "bad_statement", "only device.rekey.approved travels with a commit") as Extract<SubmitResult, { ok: false }>;
    const hts = Math.max(this.now(), this.lastHts);
    const s = this.head.seq + 1;
    const first = this.buildEntry(s, this.head.hash, hts, "stmt", stmt.body.type, body, this.fold.state.epoch);
    let next: Readonly<RoomState>;
    try {
      next = this.fold.check(first, body);
    } catch (err) {
      if (!(err instanceof FoldError)) throw err;
      const code: SubmitRejection = STALE_REASONS.has(err.reason) ? "stale_base" : UNKNOWN_BASE_REASONS.has(err.reason) ? "unknown_base" : "not_permitted";
      return this.reject(code, err.reason, err.message) as Extract<SubmitResult, { ok: false }>;
    }
    const refusal = checkCommit(next);
    if (refusal) return { ok: false, code: "commit_refused", refusal };
    const second = this.buildEntry(s + 1, first.hash, hts, "mls", "mls.commit", commitBody, commitEpoch);
    const prev = this.fold.state;
    for (const fn of [...this.decideListeners]) {
      try {
        fn(next, prev, stmt.body.type);
      } catch (err) {
        log("room_host_decide_failed", { roomId: this.roomId, type: stmt.body.type, error: String((err as Error)?.message ?? err).slice(0, 200) });
      }
    }
    this.commitRecords([{ signed: first, body }, { signed: second, body: commitBody }], hts);
    return { ok: true, statement: first, commit: second };
  }

  private sequence(sb: StatementBody, body: Uint8Array): SubmitResult {
    const seq = this.head.seq + 1;
    // hts never goes backwards: holds are measured in hts (room-log-v2 5).
    const hts = Math.max(this.now(), this.lastHts);
    const signed = this.buildEntry(seq, this.head.hash, hts, "stmt", sb.type, body, this.fold.state.epoch);
    let next: Readonly<RoomState>;
    try {
      next = this.fold.check(signed, body);
    } catch (err) {
      if (!(err instanceof FoldError)) throw err;
      const code: SubmitRejection = STALE_REASONS.has(err.reason) ? "stale_base" : UNKNOWN_BASE_REASONS.has(err.reason) ? "unknown_base" : "not_permitted";
      return this.reject(code, err.reason, err.message);
    }
    // Decide and enforce before the log write (grants-v2 7.1): access is cut even if the append fails.
    const prev = this.fold.state;
    for (const fn of [...this.decideListeners]) {
      try {
        fn(next, prev, sb.type);
      } catch (err) {
        log("room_host_decide_failed", { roomId: this.roomId, type: sb.type, error: String((err as Error)?.message ?? err).slice(0, 200) });
      }
    }
    // The files may now hold the body, or the body and the entry; memory does not. On failure the room
    // stops, and a reopen re-folds the log, which is the source of truth.
    this.commitRecords([{ signed, body }], hts);
    return { ok: true, receipt: signed };
  }
}
