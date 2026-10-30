// Roster and authority fold (room-log-v2.md section 5, with the re-fold of 5.1, the lineages and
// closure of 5.2, and the device holds of 4.3; keys-rotation-recovery.md sections 2 and 3).
//
//   state = init(genesis)
//   for entry in chain (seq ascending):
//       verify entry: prev link, entryHash, hsig with entry.hostKid valid at this position
//       if entry.cls == "mls": track epoch; continue
//       stmt = body; verify bodyHash, strict parse, schema
//       base rule, unique rule, producer and signature, forward rule, ref rule
//       if stmt is admin.key.revoked: state = refold(...)          (refold.ts)
//       else: state = apply(state, stmt, entry)
//       if the roster members changed: rosterSeq = entry.seq
//
// A rejected entry is `invalid_entry`: processing stops there and the state stays at the last
// accepted entry (never skip, section 5). Inside a re-fold, statements that no longer apply are
// void instead, and those of the revoked key from `fromSeq` on are suspect.
// Pure: no I/O, no clock. Nothing here logs key material or bodies.
import { b64uDecode } from "../proto/b64u";
import { isSignableStatementType } from "../proto/contexts";
import { isId } from "../proto/ids";
import { kid as kidOf } from "../proto/keys";
import { rjcsParse, RJCS_MAX_BYTES } from "../proto/rjcs";
import { bodyHash, EntryError, verifyChainedEntry, type LogEntry, type SignedEntry } from "./entries";
import { verifyGenesis } from "./genesis";
import { byOrForDevice, cancelRequests, checkApproval, openRequest, resolveConflict, vetoRequest, YOUNG_DEVICE_MS } from "./holds";
import { confirmClose, confirmFirstRecovery, proposeClose, proposeRecovery } from "./lineage";
import {
  checkAdminRevocation,
  checkLastAdmin,
  finishAdminRevocation,
  hostKeyAt,
  markRevoked,
  MAX_REVOCATION_DEPTH,
  refold,
  revocationDepth,
  revokeHostKey,
  type Rec,
  type Step,
} from "./refold";
import { buildRoster, membersFingerprint, rosterHash, sortDevices, type Roster } from "./roster";
import type { DeviceEntry, RosterEntry } from "./schema";
import { activeAdmins, edKid, FoldError, initState, keysInUse, versionKey, type Fail, type LaneState, type RoomState } from "./state";
import {
  parseSignedStatement,
  producerKindAllowed,
  StatementError,
  statementRef,
  verifyNewKeySig,
  verifyStatementSig,
  type KeyChange,
  type SignedStatement,
  type StatementBody,
  type StatementData,
  type StatementType,
} from "./statements";

export { FoldError, versionKey } from "./state";
export type {
  AdminKeyState,
  AuthorityState,
  CloseProposal,
  FoldReason,
  HostKeyState,
  KeyRefValue,
  LaneState,
  PendingRequest,
  RecoveryKeyState,
  RecoveryProposal,
  RepairRequest,
  Revocation,
  RoomState,
  Set_,
} from "./state";

/** Hold for `lane.closed` by the host after `lane.degraded` (room-log-v2.md 4.4), in ms of `hts`. */
export const LANE_DEGRADED_CLOSE_MS = 24 * 60 * 60 * 1000;
/** `device.leaf.repair.requested` rate limits (room-log-v2.md 4.3; decision round 8, item 1), in ms of `hts`. */
export const REPAIR_GROUP_INTERVAL_MS = 60 * 60 * 1000;
export const REPAIR_WINDOW_MS = 24 * 60 * 60 * 1000;
export const REPAIR_MAX_PER_WINDOW = 8;

/** Marked "(reserved)" in the catalogue: no defined effect yet. */
const RESERVED = new Set<StatementType>(["node.certified", "seat.added", "seat.removed"]);

type Producer =
  | { kind: "admin" | "recovery" | "host" | "node"; kid: string; pub: Uint8Array }
  | { kind: "device"; kid: string; pub: Uint8Array; memberId: string; deviceId: string };

/** The producer key held in `s` for this statement at `seq` (M-5), or null. */
function resolveProducer(s: RoomState, sb: StatementBody, seq: number): Producer | null {
  const kid = sb.producer.kid;
  const a = s.auth;
  switch (sb.producer.kind) {
    case "admin": {
      if (a.adminKeyDenylist[kid]) return null;
      const k = a.admins.find((x) => x.kid === kid && x.fromSeq <= seq && (x.toSeq === null || seq <= x.toSeq));
      return k ? { kind: "admin", kid, pub: b64uDecode(k.pub, 32) } : null;
    }
    case "recovery":
      return a.recovery && a.recovery.kid === kid && a.recovery.fromSeq <= seq ? { kind: "recovery", kid, pub: b64uDecode(a.recovery.pub, 32) } : null;
    case "host": {
      const pub = hostKeyAt(s, kid, seq);
      return pub ? { kind: "host", kid, pub } : null;
    }
    case "device":
      for (const m of Object.values(s.members)) {
        for (const d of m.devices) {
          const pub = b64uDecode(d.sig, 32);
          if (kidOf("ed25519", pub) === kid) return { kind: "device", kid, pub, memberId: m.memberId, deviceId: d.deviceId };
        }
      }
      return null;
    case "node":
      // Node keys come from node.certified, which is reserved (section 4.1).
      return null;
  }
}

// ---- the fold ----

export type FoldInputEntry = { signed: unknown; body?: Uint8Array };

/**
 * Incremental fold over one room log. `append` either accepts the entry and advances, or throws a
 * `FoldError` and leaves the fold exactly as it was, so a host can also use it to validate a
 * candidate before sequencing (`check`).
 */
export class RoomLogFold {
  private st: RoomState;
  private readonly initial: RoomState;
  private readonly hashes: string[] = [];
  private readonly bodySeq = new Map<string, number>();
  /** Forward rule (section 2): the highest base.seq per producer kid among signature-checked statements. */
  private readonly maxBase = new Map<string, number>();
  /** Accepted statement entries, for the re-fold (section 5.1). */
  private readonly records: Rec[] = [];
  /** Every accepted `admin.key.revoked` entry with its nesting depth (section 5.1, step 8). */
  private readonly revocationDepths: { seq: number; depth: number }[] = [];
  private readonly step: Step;

  private constructor(state: RoomState) {
    this.initial = state;
    this.st = structuredClone(state);
    this.step = makeStep(this.initial, this.records).live;
  }

  /** Throws FoldError(-1, "bad_genesis") when the genesis does not verify (identity-model 5.1). */
  static fromGenesis(genesis: Uint8Array | unknown): RoomLogFold {
    let v: ReturnType<typeof verifyGenesis>;
    try {
      v = verifyGenesis(genesis);
    } catch (err) {
      throw new FoldError(-1, "bad_genesis", err instanceof Error ? err.message : "genesis does not verify");
    }
    return new RoomLogFold(initState(v.genesis, v.genesisHash, v.roomId));
  }

  /** Read-only view of the current state. Callers must not mutate it. */
  get state(): Readonly<RoomState> {
    return this.st;
  }

  /** The head as `{seq, hash}`; `{-1, genesisHash}` before the first entry. */
  get head(): { seq: number; hash: string } {
    const seq = this.hashes.length - 1;
    return { seq, hash: seq < 0 ? this.st.genesisHash : this.hashes[seq] };
  }

  entryHashAt(seq: number): string | undefined {
    return seq === -1 ? this.st.genesisHash : this.hashes[seq];
  }

  maxBaseOf(kid: string): number | undefined {
    return this.maxBase.get(kid);
  }

  roster(): Roster {
    return buildRoster(this.st.roomId, this.st.rosterSeq, this.st.members);
  }

  rosterHash(): string {
    return rosterHash(this.roster());
  }

  /** Raw host key that may sign an entry at `seq`, by position only (keys-rotation-recovery.md 3). */
  hostKeyAt = (hostKid: string, seq: number): Uint8Array | null => hostKeyAt(this.st, hostKid, seq);

  append(signed: unknown, body?: Uint8Array): void {
    this.run(signed, body, true);
  }

  /** Every check of `append` without changing the fold. Returns the state the entry would produce. */
  check(signed: unknown, body?: Uint8Array): Readonly<RoomState> {
    return this.run(signed, body, false);
  }

  /**
   * Every failure leaves as a FoldError with a defined reason. An exception that no check anticipated
   * (a bug, or input that slipped past a schema) becomes `internal_error`, so a caller never has to
   * handle a second error type and a bad entry is rejected rather than crashing the fold.
   */
  private run(value: unknown, body: Uint8Array | undefined, commit: boolean): Readonly<RoomState> {
    const seq = this.hashes.length;
    try {
      return this.runChecks(seq, value, body, commit);
    } catch (err) {
      if (err instanceof FoldError) throw err;
      throw new FoldError(seq, "internal_error", err instanceof Error ? err.message : "unexpected failure");
    }
  }

  private runChecks(seq: number, value: unknown, body: Uint8Array | undefined, commit: boolean): Readonly<RoomState> {
    let signed: SignedEntry;
    try {
      signed = verifyChainedEntry(value, { roomId: this.st.roomId, seq, prevHash: this.head.hash }, this.hostKeyAt);
    } catch (err) {
      if (err instanceof EntryError) throw new FoldError(seq, err.reason, err.message);
      throw err;
    }
    const entry = signed.entry;
    if (body !== undefined && bodyHash(body) !== entry.bodyHash) throw new FoldError(seq, "body_hash_mismatch", "body does not match bodyHash");

    if (entry.cls === "mls") {
      // seq 0 must be the creator's admission (section 4.3).
      if (seq === 0) throw new FoldError(seq, "genesis_admission_required", "seq 0 must be the creator's member.admitted");
      const next = { ...this.st, epoch: entry.epoch };
      if (commit) {
        this.hashes.push(signed.hash);
        this.st = next;
      }
      return next;
    }

    if (body === undefined) throw new FoldError(seq, "missing_body", "statement entries need their body");
    let stmt: SignedStatement;
    try {
      stmt = parseSignedStatement(rjcsParse(body, RJCS_MAX_BYTES));
    } catch (err) {
      if (err instanceof StatementError) throw new FoldError(seq, err.reason, err.message);
      throw new FoldError(seq, "bad_body", err instanceof Error ? err.message : "body is not strict RJCS");
    }
    const sb = stmt.body;
    if (sb.type !== entry.type) throw new FoldError(seq, "type_mismatch", `entry type ${entry.type}, statement type ${sb.type}`);
    if (sb.roomId !== this.st.roomId) throw new FoldError(seq, "wrong_room", "statement names another room");
    // A catalogue type whose `stmt:<type>` context is outside the alphabet can never be signed or verified.
    if (!isSignableStatementType(sb.type)) throw new FoldError(seq, "unsignable_type", `stmt:${sb.type} is outside the context alphabet`);

    // Base rule: the producer's verified head lies strictly before this entry and is in this chain.
    if (!(sb.base.seq < seq)) throw new FoldError(seq, "base_not_before_entry", `base.seq ${sb.base.seq} is not before ${seq}`);
    if (this.entryHashAt(sb.base.seq) !== sb.base.hash) throw new FoldError(seq, "base_mismatch", `base hash is not the hash of entry ${sb.base.seq}`);

    // Unique rule.
    if (this.bodySeq.has(entry.bodyHash)) throw new FoldError(seq, "duplicate_statement", `statement already carried by entry ${this.bodySeq.get(entry.bodyHash)}`);

    // Producer allowed for the type, with a key held in the state (M-5), and its signature.
    if (!producerKindAllowed(sb.type, sb.producer.kind)) throw new FoldError(seq, "not_permitted", `${sb.producer.kind} may not sign ${sb.type}`);
    const producer = resolveProducer(this.st, sb, seq);
    if (!producer) throw new FoldError(seq, "unknown_producer", `no active ${sb.producer.kind} key with that kid`);
    if (!verifyStatementSig(stmt, producer.pub)) throw new FoldError(seq, "bad_signature", `statement signature does not verify under stmt:${sb.type}`);

    // Forward rule. Section 5 moves maxBase for every signature-checked statement, even one that
    // apply rejects; since any rejection stops the fold, committing it with the entry is equivalent.
    const prevMax = this.maxBase.get(sb.producer.kid);
    if (prevMax !== undefined && !(sb.base.seq > prevMax)) throw new FoldError(seq, "base_regressed", `base.seq ${sb.base.seq} is not after ${prevMax}`);

    // Ref rule: a statement naming a request or proposal was signed after seeing it.
    const ref = statementRef(sb);
    if (ref !== null) {
      const refSeq = this.bodySeq.get(ref);
      if (refSeq === undefined) throw new FoldError(seq, "unknown_ref", "ref names no earlier statement");
      if (sb.base.seq < refSeq) throw new FoldError(seq, "base_before_ref", `base.seq ${sb.base.seq} precedes the ref at ${refSeq}`);
    }

    // Nesting depth of a revocation, from positions only (section 5.1, step 8), before any re-fold.
    let depth = 0;
    if (sb.type === "admin.key.revoked") {
      depth = revocationDepth(this.revocationDepths, (sb.data as StatementData<"admin.key.revoked">).fromSeq, seq);
      if (depth > MAX_REVOCATION_DEPTH) throw new FoldError(seq, "revocation_too_deep", `nesting depth ${depth} exceeds ${MAX_REVOCATION_DEPTH}`);
    }

    const rec: Rec = { entry, stmt: sb };
    const next = this.step(this.st, rec);

    if (!commit) return next;
    if (depth > 0) this.revocationDepths.push({ seq, depth });
    this.st = next;
    this.hashes.push(signed.hash);
    this.bodySeq.set(entry.bodyHash, seq);
    this.maxBase.set(sb.producer.kid, sb.base.seq);
    this.records.push(rec);
    return next;
  }
}

/** Fold a whole chain. Stops at the first invalid entry and returns the state before it. */
export function foldLog(genesis: Uint8Array | unknown, entries: readonly FoldInputEntry[]): { fold: RoomLogFold; error: FoldError | null } {
  const fold = RoomLogFold.fromGenesis(genesis);
  for (const e of entries) {
    try {
      fold.append(e.signed, e.body);
    } catch (err) {
      if (err instanceof FoldError) return { fold, error: err };
      throw err;
    }
  }
  return { fold, error: null };
}

// ---- one statement: apply or re-fold, then the roster position ----

/**
 * The step of the live fold and of every re-fold pass. It resolves the producer in `s` (a key that a
 * suspect statement installed is gone in a pass, so its statements become void), applies the
 * statement to a copy of `s` and returns it, or throws FoldError. Only the live step re-folds; inside
 * a pass an earlier revocation is checked and marks its target, and never replays (section 5.1).
 */
function makeStep(initial: RoomState, records: readonly Rec[]): { live: Step; inPass: Step } {
  const make = (live: boolean): Step => {
    const step: Step = (s: RoomState, rec: Rec): RoomState => {
      const { entry, stmt: sb } = rec;
      const seq = entry.seq;
      const fail: Fail = (reason, message) => {
        throw new FoldError(seq, reason, message);
      };
      const producer = resolveProducer(s, sb, seq) ?? fail("unknown_producer", `no active ${sb.producer.kind} key with that kid`);
      preApply(s, sb, seq, fail);
      const before = membersFingerprint(s.members);
      let next: RoomState;
      if (sb.type === "admin.key.revoked") {
        const d = sb.data as StatementData<"admin.key.revoked">;
        checkAdminRevocation(s, d, producer, seq, fail);
        if (live) {
          const re = refold(initial, records, seq, s.auth.revocations, { kid: d.kid, fromSeq: d.fromSeq, seq }, inPass, fail);
          // A re-fold that changes the roster makes the revocation the roster position (R-7).
          re.rosterSeq = s.rosterSeq;
          next = finishAdminRevocation(s, re, d, seq, producer.kind, fail);
        } else {
          next = structuredClone(s);
          markRevoked(next, d, seq);
          checkLastAdmin(next, producer.kind, fail);
        }
      } else {
        next = structuredClone(s);
        applyStatement(next, sb, entry, producer, fail);
      }
      if (membersFingerprint(next.members) !== before) next.rosterSeq = seq;
      next.epoch = entry.epoch;
      return next;
    };
    return step;
  };
  const inPass = make(false);
  return { live: make(true), inPass };
}

/** Rules that hold for every statement type. */
function preApply(s: RoomState, sb: StatementBody, seq: number, fail: Fail): void {
  if (s.auth.closed) fail("room_closed", "no statement is accepted after room.closed");
  // seq 0 is the creator's admission, and only there (section 5).
  const isCreator = sb.type === "member.admitted" && (sb.data as StatementData<"member.admitted">).confirmation.method === "creator";
  if (seq === 0 && !isCreator) fail("genesis_admission_required", "seq 0 must be the creator's member.admitted");
  if (seq !== 0 && isCreator) fail("creator_not_at_genesis", `method "creator" at seq ${seq}`);
  if (RESERVED.has(sb.type)) fail("reserved_type", `${sb.type} is reserved`);
}

// ---- apply (mutates the clone it is given) ----

function applyStatement(s: RoomState, sb: StatementBody, entry: LogEntry, producer: Producer, fail: Fail): void {
  const seq = entry.seq;
  const hts = entry.hts;
  const type = sb.type;

  const versionOf = (key: string) => s.auth.versions[key] ?? -1;
  const checkVer = (key: string, ver: number) => {
    if (ver !== versionOf(key)) fail("stale_version", `${key}: ver ${ver}, current ${versionOf(key)}`);
  };
  const member = (memberId: string): RosterEntry => s.members[memberId] ?? fail("unknown_member", "member is not in the roster");
  const deviceOf = (memberId: string): Extract<Producer, { kind: "device" }> => {
    if (producer.kind !== "device" || producer.memberId !== memberId) fail("not_member_device", "producer is not a device of this member");
    return producer as Extract<Producer, { kind: "device" }>;
  };
  const lane = (laneId: string): LaneState => {
    const l = s.auth.lanes[laneId] ?? fail("unknown_lane", "lane does not exist");
    if (l.status === "closed") fail("lane_closed", "lane is closed");
    return l;
  };
  const freshDevice = (d: DeviceEntry, seen: Set<string>) => {
    if (s.used.devices[d.deviceId]) fail("id_reused", "deviceId was used before in this room");
    freshDeviceKeys(d, seen);
    for (const key of [d.sig, d.dh]) seen.add(key);
  };
  const freshDeviceKeys = (d: Pick<DeviceEntry, "sig" | "dh">, inUse: Set<string>) => {
    if (d.sig === d.dh) fail("key_reused", "signing and DH key are the same bytes");
    for (const key of [d.sig, d.dh]) {
      if (s.deviceDenylist[key] || s.auth.retiredKeys[key] || inUse.has(key)) fail("key_reused", "device key is denylisted, retired or already in use");
    }
  };
  const retireDevice = (d: DeviceEntry) => {
    for (const key of [d.sig, d.dh]) {
      s.deviceDenylist[key] = true;
      s.auth.retiredKeys[key] = true;
    }
  };
  const retireKey = (pub: string) => {
    s.auth.retiredKeys[pub] = true;
  };
  /** Open leaf repair requests end when the device leaves the roster or its keys change. */
  const cancelRepairs = (match: (deviceId: string, memberId: string) => boolean) => {
    for (const r of Object.values(s.repairs)) if (r.status === "open" && match(r.deviceId, r.memberId)) r.status = "cancelled";
  };
  /** A key the room certifies now: never retired, and not used for anything else. */
  const freshKey = (pub: string) => {
    if (s.auth.retiredKeys[pub] || keysInUse(s).has(pub)) fail("key_reused", "key is retired or already in use in this room");
  };
  /** KeyChange checks (keys-rotation-recovery.md section 2). Returns the new signing key. */
  const keyChange = (ch: KeyChange, newKeySig: string, want: { kind: KeyChange["subject"]["kind"]; id?: string; old: string | null; dh: boolean }): string => {
    if (ch.roomId !== s.roomId) fail("bad_key_change", "KeyChange names another room");
    if (ch.subject.kind !== want.kind) fail("bad_key_change", `subject kind must be ${want.kind}`);
    if (want.id !== undefined && ch.subject.id !== want.id) fail("bad_key_change", "subject id does not name the subject");
    if (want.kind === "admin" && !isId("member", ch.subject.id)) fail("bad_key_change", "an admin key's subject id is the admin's memberId");
    if (ch.newSig === null || (ch.newDh !== null) !== want.dh) fail("bad_key_change", "new keys do not fit the subject");
    if (ch.old !== want.old) fail("stale_version", "KeyChange.old does not name the subject's current key");
    if (!verifyNewKeySig(ch, newKeySig)) fail("bad_new_key_sig", "newKeySig does not verify under key-change-new");
    return ch.newSig as string;
  };
  const activeAdmin = (kid: string) => activeAdmins(s.auth).find((a) => a.kid === kid);
  const at = { kid: producer.kid, seq, hts, bodyHash: entry.bodyHash };

  switch (type) {
    // ---- 4.1 authority ----
    case "admin.added": {
      const d = sb.data as StatementData<"admin.added">;
      const pub = keyChange(d.change, d.newKeySig, { kind: "admin", old: null, dh: false });
      freshKey(pub);
      const kid = edKid(pub);
      if (s.auth.adminKeyDenylist[kid]) fail("key_reused", "admin key is denylisted");
      // A key added by R starts its own lineage; one added by an admin key joins that key's (5.2).
      const root = producer.kind === "recovery" ? kid : (activeAdmin(producer.kid) ?? fail("unknown_producer", "adding key is not active")).root;
      s.auth.admins.push({
        kid,
        pub,
        fromSeq: seq + 1,
        toSeq: null,
        suspectFromSeq: null,
        root,
        addedBy: producer.kind === "recovery" ? "recovery" : producer.kid,
        since: seq + 1,
        end: null,
      });
      return;
    }
    case "admin.removed": {
      const d = sb.data as StatementData<"admin.removed">;
      if (d.kid === producer.kid) fail("not_permitted", "an admin key is removed by another admin");
      const target = activeAdmin(d.kid) ?? fail("unknown_key", "kid is not an active admin key");
      if (activeAdmins(s.auth).length <= 1) fail("last_admin", "the last admin key cannot be removed");
      target.toSeq = seq;
      target.end = "removed";
      s.auth.adminKeyDenylist[d.kid] = true;
      retireKey(target.pub);
      return;
    }
    case "admin.key.rotated": {
      const d = sb.data as StatementData<"admin.key.rotated">;
      const cur = activeAdmin(producer.kid) ?? fail("unknown_producer", "rotating key is not active");
      const pub = keyChange(d.change, d.newKeySig, { kind: "admin", old: cur.kid, dh: false });
      freshKey(pub);
      const kid = edKid(pub);
      if (s.auth.adminKeyDenylist[kid]) fail("key_reused", "admin key is denylisted");
      cur.toSeq = seq;
      cur.end = "rotated";
      s.auth.adminKeyDenylist[cur.kid] = true;
      retireKey(cur.pub);
      // The new key keeps the lineage and the authority start of the key it replaces (5.1, 5.2).
      s.auth.admins.push({ kid, pub, fromSeq: seq + 1, toSeq: null, suspectFromSeq: null, root: cur.root, addedBy: cur.addedBy, since: cur.since, end: null });
      return;
    }
    case "recovery.key.proposed": {
      const d = sb.data as StatementData<"recovery.key.proposed">;
      if (s.auth.recovery) fail("recovery_exists", "recovery.key.proposed is valid only while the room has no recovery key");
      freshKey(keyChange(d.change, d.newKeySig, { kind: "recovery", id: "recovery", old: null, dh: false }));
      proposeRecovery(s, at, d.change, d.exp, fail);
      return;
    }
    case "recovery.key.rotated": {
      const d = sb.data as StatementData<"recovery.key.rotated">;
      const cur = s.auth.recovery;
      if (producer.kind === "recovery" && cur) {
        if (d.proposal !== null) fail("proposal_not_allowed", "R rotates itself with proposal null");
        const pub = keyChange(d.change, d.newKeySig, { kind: "recovery", id: "recovery", old: cur.kid, dh: false });
        freshKey(pub);
        retireKey(cur.pub);
        // A rotated recovery key keeps the authority start of the key it replaced.
        s.auth.recovery = { kid: edKid(pub), pub, fromSeq: seq + 1, since: cur.since };
        return;
      }
      if (cur) fail("recovery_exists", "with a recovery key in place only that key rotates it");
      const pub = keyChange(d.change, d.newKeySig, { kind: "recovery", id: "recovery", old: null, dh: false });
      freshKey(pub);
      confirmFirstRecovery(s, producer.kid, d.change, d.proposal, hts, fail);
      // A recovery key installed at i cannot reach back before i + 1 (5.2).
      s.auth.recovery = { kid: edKid(pub), pub, fromSeq: seq + 1, since: seq + 1 };
      return;
    }
    case "host.key.rotated": {
      const d = sb.data as StatementData<"host.key.rotated">;
      const cur = s.auth.hostKeys.find((h) => h.toSeq === null) ?? fail("unknown_key", "no current host key");
      const pub = keyChange(d.change, d.newKeySig, { kind: "host", id: "host", old: cur.kid, dh: false });
      freshKey(pub);
      // This entry is the last one the old key signs; grants from it stay valid until oldValidTo.
      cur.toSeq = seq;
      cur.validTo = d.oldValidTo;
      retireKey(cur.pub);
      s.auth.hostKeys.push({ kid: edKid(pub), pub, fromSeq: seq + 1, toSeq: null, suspectFromSeq: null, validFrom: Math.floor(hts / 1000), validTo: null, revoked: false, uncertified: false });
      return;
    }
    case "host.key.revoked": {
      revokeHostKey(s, sb.data as StatementData<"host.key.revoked">, producer, seq, fail);
      return;
    }
    case "room.close.proposed": {
      const d = sb.data as StatementData<"room.close.proposed">;
      proposeClose(s, at, d.exp, fail);
      return;
    }
    case "room.closed": {
      const d = sb.data as StatementData<"room.closed">;
      if (producer.kind === "recovery") {
        if (d.proposal !== null) fail("proposal_not_allowed", "R closes with proposal null");
      } else {
        if (d.proposal === null) fail("proposal_required", "an admin key closes only by confirming an independent admin's proposal");
        confirmClose(s, producer.kid, d.proposal, { seq, hts }, fail);
      }
      s.auth.closed = true;
      return;
    }
    // ---- 4.3 membership ----
    case "member.admitted": {
      const d = sb.data as StatementData<"member.admitted">;
      const m = d.member;
      if (s.used.members[m.memberId]) fail("id_reused", "memberId was used before in this room");
      const seen = keysInUse(s);
      for (const dev of m.devices) freshDevice(dev, seen);
      s.members[m.memberId] = { memberId: m.memberId, role: m.role, lanes: [...m.lanes], devices: sortDevices(m.devices) };
      s.used.members[m.memberId] = true;
      for (const dev of m.devices) {
        s.used.devices[dev.deviceId] = true;
        s.deviceSince[dev.deviceId] = hts;
      }
      // Initial versions of the member's fields: the admission entry (section 4.0).
      s.auth.versions[versionKey.role(m.memberId)] = seq;
      s.auth.versions[versionKey.lanes(m.memberId)] = seq;
      s.auth.versions[versionKey.devices(m.memberId)] = seq;
      return;
    }
    case "member.role.changed": {
      const d = sb.data as StatementData<"member.role.changed">;
      const m = member(d.memberId);
      checkVer(versionKey.role(d.memberId), d.ver);
      // An admin key ranks as role "admin", the highest, so "a role above the producing admin's own" cannot occur here.
      m.role = d.role;
      s.auth.versions[versionKey.role(d.memberId)] = seq;
      return;
    }
    case "member.lanes.changed": {
      const d = sb.data as StatementData<"member.lanes.changed">;
      const m = member(d.memberId);
      checkVer(versionKey.lanes(d.memberId), d.ver);
      m.lanes = [...d.lanes];
      s.auth.versions[versionKey.lanes(d.memberId)] = seq;
      return;
    }
    case "member.removed": {
      const d = sb.data as StatementData<"member.removed">;
      const m = member(d.memberId);
      for (const dev of m.devices) retireDevice(dev);
      delete s.members[d.memberId];
      cancelRequests(s, (p) => p.memberId === d.memberId);
      cancelRepairs((_, memberId) => memberId === d.memberId);
      return;
    }
    case "member.left": {
      const d = sb.data as StatementData<"member.left">;
      const m = member(d.memberId);
      deviceOf(d.memberId);
      if (m.devices.length !== 1) fail("not_sole_device", "member.left needs the member's only active device");
      for (const dev of m.devices) retireDevice(dev);
      delete s.members[d.memberId];
      cancelRequests(s, (p) => p.memberId === d.memberId);
      cancelRepairs((_, memberId) => memberId === d.memberId);
      return;
    }
    case "member.device.replaced": {
      const d = sb.data as StatementData<"member.device.replaced">;
      const m = member(d.memberId);
      checkVer(versionKey.devices(d.memberId), d.ver);
      const removed = d.removed.map((id) => m.devices.find((x) => x.deviceId === id) ?? fail("unknown_device", "removed device is not the member's"));
      freshDevice(d.added, keysInUse(s));
      const kept = m.devices.filter((x) => !d.removed.includes(x.deviceId));
      if (kept.length + 1 > 8) fail("too_many_devices", "a member has at most 8 devices");
      for (const dev of removed) {
        retireDevice(dev);
        cancelRequests(s, byOrForDevice(dev.deviceId));
        cancelRepairs((deviceId) => deviceId === dev.deviceId);
      }
      m.devices = sortDevices([...kept, d.added]);
      s.used.devices[d.added.deviceId] = true;
      s.deviceSince[d.added.deviceId] = hts;
      s.auth.versions[versionKey.devices(d.memberId)] = seq;
      return;
    }
    case "device.added": {
      const d = sb.data as StatementData<"device.added">;
      const requester = deviceOf(d.memberId);
      if (d.addedBy !== requester.deviceId) fail("not_permitted", "addedBy must be the signing device");
      const m = member(d.memberId);
      keyChange(d.change, d.newKeySig, { kind: "device", id: d.device.deviceId, old: null, dh: true });
      if (d.change.newSig !== d.device.sig || d.change.newDh !== d.device.dh) fail("bad_key_change", "KeyChange keys differ from the device entry");
      // The link the SAS was run on: created by a device of this member, used once.
      const linkRef = d.confirmation.linkRef;
      if (s.used.links[linkRef] !== d.memberId) fail("unknown_link", "linkRef names no device link of this member");
      if (s.used.linksConsumed[linkRef]) fail("link_used", "the link already added a device");
      freshDevice(d.device, keysInUse(s));
      // The deviceId is taken from the request on, so a request that is pending again after a re-fold keeps it.
      s.used.devices[d.device.deviceId] = true;
      s.used.linksConsumed[linkRef] = true;
      const since = s.deviceSince[requester.deviceId] ?? hts;
      openRequest(s, entry.bodyHash, {
        kind: "add",
        memberId: d.memberId,
        deviceId: d.device.deviceId,
        requester: requester.deviceId,
        device: structuredClone(d.device),
        seq,
        hts,
        sole: m.devices.length === 1,
        young: hts - since < YOUNG_DEVICE_MS,
      });
      return;
    }
    case "device.rekeyed": {
      const d = sb.data as StatementData<"device.rekeyed">;
      if (producer.kind !== "device") return fail("not_permitted", "a device rekeys itself");
      const m = member(producer.memberId);
      const dev = m.devices.find((x) => x.deviceId === producer.deviceId) ?? fail("unknown_device", "device is not in the roster");
      const sig = keyChange(d.change, d.newKeySig, { kind: "device", id: dev.deviceId, old: edKid(dev.sig), dh: true });
      const next = { ...dev, sig, dh: d.change.newDh as string };
      freshDeviceKeys(next, keysInUse(s));
      openRequest(s, entry.bodyHash, {
        kind: "rekey",
        memberId: m.memberId,
        deviceId: dev.deviceId,
        requester: dev.deviceId,
        device: next,
        seq,
        hts,
        sole: m.devices.length === 1,
        young: false,
      });
      return;
    }
    case "device.add.vetoed":
    case "device.rekey.vetoed": {
      const d = sb.data as StatementData<"device.add.vetoed">;
      deviceOf(d.memberId);
      vetoRequest(s, type === "device.add.vetoed" ? "add" : "rekey", d.memberId, d.ref, seq, fail);
      return;
    }
    case "device.conflict.resolved": {
      const d = sb.data as StatementData<"device.conflict.resolved">;
      resolveConflict(s, d.memberId, d.ver, seq, fail);
      return;
    }
    case "device.add.approved": {
      const d = sb.data as StatementData<"device.add.approved">;
      const p = checkApproval(s, "add", d, hts, fail);
      const m = member(d.memberId);
      if (m.devices.length + 1 > 8) fail("too_many_devices", "a member has at most 8 devices");
      freshDeviceKeys(p.device, keysInUse(s));
      m.devices = sortDevices([...m.devices, structuredClone(p.device)]);
      s.deviceSince[p.deviceId] = hts;
      s.auth.versions[versionKey.devices(d.memberId)] = seq;
      p.status = "approved";
      return;
    }
    case "device.rekey.approved": {
      const d = sb.data as StatementData<"device.rekey.approved">;
      const p = checkApproval(s, "rekey", d, hts, fail);
      const m = member(d.memberId);
      const dev = m.devices.find((x) => x.deviceId === d.deviceId) ?? fail("unknown_device", "device is not in the roster");
      freshDeviceKeys(p.device, keysInUse(s));
      retireDevice(dev);
      dev.sig = p.device.sig;
      dev.dh = p.device.dh;
      s.auth.versions[versionKey.devices(d.memberId)] = seq;
      p.status = "approved";
      // Requests signed by the old key are cancelled (section 4.3, R-8); so are its repair requests.
      cancelRequests(s, (q) => q.requester === d.deviceId);
      cancelRepairs((deviceId) => deviceId === d.deviceId);
      return;
    }
    case "device.removed": {
      const d = sb.data as StatementData<"device.removed">;
      const m = member(d.memberId);
      const dev = m.devices.find((x) => x.deviceId === d.deviceId) ?? fail("unknown_device", "device is not the member's");
      if (producer.kind === "device") {
        // A device removes only itself, and never as the member's last device (section 4.3).
        if (producer.deviceId !== d.deviceId) fail("not_permitted", "a device may remove only itself");
        if (m.devices.length === 1) fail("last_device_use_member_left", "the last device leaves with member.left");
      }
      retireDevice(dev);
      m.devices = m.devices.filter((x) => x.deviceId !== d.deviceId);
      s.auth.versions[versionKey.devices(d.memberId)] = seq;
      // Cancels the device's own pending rekey and every pending request it made (R-8).
      cancelRequests(s, byOrForDevice(d.deviceId));
      cancelRepairs((deviceId) => deviceId === d.deviceId);
      return;
    }
    case "device.leaf.repair.requested": {
      // Decision round 8, item 1 (room-log-v2.md 4.3 and 5; mls-integration.md 4.3, 4.4).
      const d = sb.data as StatementData<"device.leaf.repair.requested">;
      if (producer.kind !== "device" || producer.memberId !== d.memberId || producer.deviceId !== d.deviceId) {
        fail("not_permitted", "a device requests the repair of its own leaf only");
      }
      if (d.group.scope !== null && !(s.auth.scopes[d.group.scope] ?? []).includes(d.memberId)) fail("not_in_scope", "the member is not in that scope");
      for (const [h, r] of Object.entries(s.repairs)) if (hts - r.hts >= REPAIR_WINDOW_MS) delete s.repairs[h];
      const mine = Object.values(s.repairs).filter((r) => r.deviceId === d.deviceId);
      const sameGroup = mine.filter((r) => r.scope === d.group.scope && r.generation === d.group.generation);
      if (sameGroup.some((r) => hts - r.hts < REPAIR_GROUP_INTERVAL_MS)) fail("repair_too_soon", "one repair request per device and group per hour");
      if (mine.length >= REPAIR_MAX_PER_WINDOW) fail("repair_rate", `at most ${REPAIR_MAX_PER_WINDOW} repair requests per device per 24 h`);
      s.repairs[entry.bodyHash] = {
        memberId: d.memberId,
        deviceId: d.deviceId,
        scope: d.group.scope,
        generation: d.group.generation,
        keyPackageRef: d.keyPackageRef,
        seq,
        hts,
        status: "open",
      };
      return;
    }
    case "scope.membership.changed": {
      const d = sb.data as StatementData<"scope.membership.changed">;
      checkVer(versionKey.scope(d.scopeId), d.ver);
      s.auth.scopes[d.scopeId] = [...d.memberIds];
      s.auth.versions[versionKey.scope(d.scopeId)] = seq;
      return;
    }
    case "room.policy.changed": {
      const d = sb.data as StatementData<"room.policy.changed">;
      for (const c of d.changes) checkVer(versionKey.policy(c.setting), c.ver);
      for (const c of d.changes) {
        if (c.setting === "minVersion" && (c.value as number) < s.auth.policy.minVersion) fail("policy_downgrade", "minVersion may only rise");
        (s.auth.policy as Record<string, unknown>)[c.setting] = c.value;
        s.auth.versions[versionKey.policy(c.setting)] = seq;
      }
      return;
    }
    case "endpoint.rotated": {
      const d = sb.data as StatementData<"endpoint.rotated">;
      checkVer(versionKey.endpoint(), d.ver);
      if (d.dh.pub === s.auth.endpoint.dh.pub) fail("key_reused", "endpoint key did not change");
      freshKey(d.dh.pub);
      retireKey(s.auth.endpoint.dh.pub);
      s.auth.endpoint = { serverId: d.serverId, dh: d.dh, relay: d.relay };
      s.auth.endpointUncertified = false;
      s.auth.versions[versionKey.endpoint()] = seq;
      return;
    }
    // ---- 4.4 lanes ----
    case "lane.created": {
      const d = sb.data as StatementData<"lane.created">;
      if (s.used.lanes[d.laneId]) fail("id_reused", "laneId was used before in this room");
      freshKey(d.offer.dh.pub);
      s.auth.lanes[d.laneId] = { owner: d.owner, offer: d.offer, visibility: d.visibility, status: "open", degradedAtHts: null, showNames: false, uncertified: false };
      s.used.lanes[d.laneId] = true;
      s.auth.versions[versionKey.laneNames(d.laneId)] = seq;
      s.auth.versions[versionKey.laneOffer(d.laneId)] = seq;
      return;
    }
    case "lane.offer.rotated": {
      const d = sb.data as StatementData<"lane.offer.rotated">;
      const l = lane(d.laneId);
      checkVer(versionKey.laneOffer(d.laneId), d.ver);
      if (d.offer.dh.pub === l.offer.dh.pub) fail("key_reused", "lane key did not change");
      freshKey(d.offer.dh.pub);
      retireKey(l.offer.dh.pub);
      l.offer = d.offer;
      l.uncertified = false;
      s.auth.versions[versionKey.laneOffer(d.laneId)] = seq;
      return;
    }
    case "lane.names.changed": {
      const d = sb.data as StatementData<"lane.names.changed">;
      const l = lane(d.laneId);
      if (producer.kind !== "device" || producer.memberId !== l.owner) fail("not_lane_owner", "only a device of the lane's owner may change its names");
      if (d.show && s.auth.policy.projectNames === "hidden") fail("names_hidden", 'policy projectNames is "hidden"');
      checkVer(versionKey.laneNames(d.laneId), d.ver);
      l.showNames = d.show;
      s.auth.versions[versionKey.laneNames(d.laneId)] = seq;
      return;
    }
    case "lane.degraded": {
      const d = sb.data as StatementData<"lane.degraded">;
      const l = lane(d.laneId);
      if (l.status === "open") {
        l.status = "degraded";
        l.degradedAtHts = hts;
      }
      return;
    }
    case "lane.closed": {
      const d = sb.data as StatementData<"lane.closed">;
      const l = lane(d.laneId);
      if (producer.kind === "host" && !(l.status === "degraded" && l.degradedAtHts !== null && hts - l.degradedAtHts >= LANE_DEGRADED_CLOSE_MS)) {
        fail("not_permitted", "the host closes a lane only after lane.degraded for 24 h");
      }
      l.status = "closed";
      retireKey(l.offer.dh.pub);
      return;
    }
    // ---- 4.2 invites and links ----
    case "invite.created": {
      const d = sb.data as StatementData<"invite.created">;
      if (s.used.invites[d.inviteRef]) fail("id_reused", "invite already exists");
      s.used.invites[d.inviteRef] = true;
      return;
    }
    case "invite.revoked": {
      const d = sb.data as StatementData<"invite.revoked">;
      // A device may revoke only a link of its own member; invites are revoked by admins.
      if (producer.kind === "device") {
        const linkMember = "linkRef" in d ? s.used.links[d.linkRef] : undefined;
        if (linkMember === undefined || linkMember !== producer.memberId) fail("not_permitted", "a device may revoke only its member's own link");
      }
      return;
    }
    case "device.link.created": {
      const d = sb.data as StatementData<"device.link.created">;
      deviceOf(d.memberId);
      if (s.used.links[d.linkRef] !== undefined) fail("id_reused", "link already exists");
      s.used.links[d.linkRef] = d.memberId;
      return;
    }
    // Host and node statements, alerts and the fence: no roster or authority effect (section 4.0).
    case "invite.expired":
    case "invite.burned":
    case "invite.contested":
    case "enrollment.pending":
    case "enrollment.closed":
    case "endpoint.evicted":
    case "grant.issued":
    case "grant.revoked":
    case "grant.suspected-theft":
    case "mls.stalled":
    case "producer.fence":
      return;
    default:
      // admin.key.revoked is handled by the step (re-fold); reserved types never reach apply.
      fail("not_implemented", `${type} has no fold rule`);
  }
}

