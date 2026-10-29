// Roster and authority fold, core (room-log-v2.md section 5, without the re-fold of 5.1, the
// lineages and closure of 5.2, and the device holds; those are milestone I-6).
//
//   state = init(genesis)
//   for entry in chain (seq ascending):
//       verify entry: prev link, entryHash, hsig with entry.hostKid valid at this position
//       if entry.cls == "mls": track epoch; continue
//       stmt = body; verify bodyHash, strict parse, schema
//       base rule, unique rule, producer and signature, forward rule, ref rule
//       state = apply(state, stmt, entry)
//       if the roster members changed: rosterSeq = entry.seq
//
// A rejected entry is `invalid_entry`: processing stops there and the state stays at the last
// accepted entry (never skip, section 5). Statement types whose effect belongs to I-6 are refused
// with `not_implemented`, so the core never silently ignores an authority change.
// Pure: no I/O, no clock. Nothing here logs key material or bodies.
import { b64uDecode } from "../proto/b64u";
import { kid as kidOf } from "../proto/keys";
import { rjcsParse, RJCS_MAX_BYTES } from "../proto/rjcs";
import { bodyHash, EntryError, verifyChainedEntry, type LogEntry, type SignedEntry } from "./entries";
import { verifyGenesis, type RoomGenesis } from "./genesis";
import { buildRoster, membersFingerprint, rosterHash, sortDevices, type Roster } from "./roster";
import type { DeviceEntry, Policy, PolicySetting, RosterEntry } from "./schema";
import {
  parseSignedStatement,
  producerKindAllowed,
  StatementError,
  statementRef,
  verifyStatementSig,
  type SignedStatement,
  type StatementBody,
  type StatementData,
  type StatementType,
} from "./statements";

/** Hold for `lane.closed` by the host after `lane.degraded` (room-log-v2.md 4.4), in ms of `hts`. */
export const LANE_DEGRADED_CLOSE_MS = 24 * 60 * 60 * 1000;

export type FoldReason =
  // entry layer (entries.ts)
  | EntryError["reason"]
  // body and statement layer
  | "missing_body"
  | "body_hash_mismatch"
  | "bad_body"
  | "type_mismatch"
  | "unknown_type"
  | "bad_statement"
  // chain rules (section 5)
  | "base_not_before_entry"
  | "base_mismatch"
  | "duplicate_statement"
  | "not_permitted"
  | "unknown_producer"
  | "bad_signature"
  | "base_regressed"
  | "unknown_ref"
  | "base_before_ref"
  // apply
  | "genesis_admission_required"
  | "creator_not_at_genesis"
  | "room_closed"
  | "stale_version"
  | "id_reused"
  | "key_reused"
  | "unknown_member"
  | "unknown_device"
  | "unknown_lane"
  | "lane_closed"
  | "not_member_device"
  | "not_sole_device"
  | "last_device_use_member_left"
  | "too_many_devices"
  | "policy_downgrade"
  | "not_lane_owner"
  | "names_hidden"
  | "not_implemented"
  | "reserved_type";

export class FoldError extends Error {
  constructor(
    readonly seq: number,
    readonly reason: FoldReason,
    message: string,
  ) {
    super(`seq ${seq}: ${reason}: ${message}`);
    this.name = "FoldError";
  }
}

// ---- state ----

export type KeyRefValue = { alg: "ed25519" | "x25519"; kid: string; pub: string };
export type AdminKeyState = { kid: string; pub: string; fromSeq: number; toSeq: number | null; root: string; addedBy: string | null; since: number };
export type HostKeyState = { kid: string; pub: string; fromSeq: number; toSeq: number | null; validFrom: number; validTo: number | null };
export type LaneState = {
  owner: string;
  offer: { serverId: string; dh: KeyRefValue; relay: { host: string; port: number; tls: true } };
  visibility: "room" | "team";
  status: "open" | "degraded" | "closed";
  degradedAtHts: number | null;
  showNames: boolean;
};
export type Set_ = Record<string, true>;

export type AuthorityState = {
  admins: AdminKeyState[];
  recovery: { kid: string; pub: string; fromSeq: number; since: number } | null;
  hostKeys: HostKeyState[];
  adminKeyDenylist: Set_;
  /** Public keys (b64u) of every key that was valid in the room and was rotated out, removed or revoked. */
  retiredKeys: Set_;
  endpoint: { serverId: string; dh: KeyRefValue; relay: { host: string; port: number; tls: true } };
  lanes: Record<string, LaneState>;
  scopes: Record<string, string[]>;
  policy: Policy;
  /** Field versions (section 4.0). A missing key is version -1. */
  versions: Record<string, number>;
  closed: boolean;
};

export type RoomState = {
  roomId: string;
  genesisHash: string;
  auth: AuthorityState;
  members: Record<string, RosterEntry>;
  /** Device signing and DH keys (b64u) that were removed or rotated out (identity-model.md 6.2). */
  deviceDenylist: Set_;
  /** Ids that were ever used: memberId, deviceId, laneId, inviteRef; linkRef maps to its member. */
  used: { members: Set_; devices: Set_; lanes: Set_; invites: Set_; links: Record<string, string> };
  rosterSeq: number;
  epoch: number | null;
};

export const versionKey = {
  policy: (setting: PolicySetting) => `policy:${setting}`,
  role: (memberId: string) => `role:${memberId}`,
  lanes: (memberId: string) => `lanes:${memberId}`,
  devices: (memberId: string) => `devices:${memberId}`,
  scope: (scopeId: string) => `scope:${scopeId}`,
  laneNames: (laneId: string) => `laneNames:${laneId}`,
  laneOffer: (laneId: string) => `laneOffer:${laneId}`,
  endpoint: () => "endpoint",
};

function initState(genesis: RoomGenesis, genesisHash: string, roomId: string): RoomState {
  const g = genesis.body;
  return {
    roomId,
    genesisHash,
    auth: {
      // Genesis keys are their own lineage roots, with authority start 0 (section 5.1, 5.2).
      admins: g.admins.map((a) => ({ kid: a.kid, pub: a.pub, fromSeq: 0, toSeq: null, root: a.kid, addedBy: null, since: 0 })),
      recovery: g.recovery ? { kid: g.recovery.kid, pub: g.recovery.pub, fromSeq: 0, since: 0 } : null,
      hostKeys: [{ kid: g.host.key.kid, pub: g.host.key.pub, fromSeq: 0, toSeq: null, validFrom: g.host.notBefore, validTo: null }],
      adminKeyDenylist: {},
      retiredKeys: {},
      endpoint: structuredClone(g.endpoint),
      lanes: {},
      scopes: {},
      policy: structuredClone(g.policy),
      versions: {},
      closed: false,
    },
    members: {},
    deviceDenylist: {},
    used: { members: {}, devices: {}, lanes: {}, invites: {}, links: {} },
    rosterSeq: -1,
    epoch: null,
  };
}

/** I-6 owns the effect of these: key changes, revocation and re-fold, lineages, closure, device holds. */
const NOT_IN_CORE = new Set<StatementType>([
  "room.close.proposed",
  "room.closed",
  "admin.added",
  "admin.removed",
  "admin.key.rotated",
  "admin.key.revoked",
  "recovery.key.proposed",
  "recovery.key.rotated",
  "host.key.rotated",
  "host.key.revoked",
  "device.added",
  "device.add.vetoed",
  "device.add.approved",
  "device.rekeyed",
  "device.rekey.vetoed",
  "device.rekey.approved",
  "device.conflict.resolved",
]);
/** Marked "(reserved)" in the catalogue: no defined effect yet. */
const RESERVED = new Set<StatementType>(["node.certified", "seat.added", "seat.removed"]);

type Producer = { kind: "admin" | "recovery" | "host" | "node"; pub: Uint8Array } | { kind: "device"; pub: Uint8Array; memberId: string; deviceId: string };

// ---- the fold ----

export type FoldInputEntry = { signed: unknown; body?: Uint8Array };

/**
 * Incremental fold over one room log. `append` either accepts the entry and advances, or throws a
 * `FoldError` and leaves the fold exactly as it was, so a host can also use it to validate a
 * candidate before sequencing (`check`).
 */
export class RoomLogFold {
  private st: RoomState;
  private readonly hashes: string[] = [];
  private readonly bodySeq = new Map<string, number>();
  /** Forward rule (section 2): the highest base.seq per producer kid among signature-checked statements. */
  private readonly maxBase = new Map<string, number>();

  private constructor(state: RoomState) {
    this.st = state;
  }

  static fromGenesis(genesis: Uint8Array | unknown): RoomLogFold {
    const v = verifyGenesis(genesis);
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

  /** Raw host key that may sign an entry at `seq` (I-5: genesis host key; rotation and revocation are I-6). */
  hostKeyAt = (hostKid: string, seq: number): Uint8Array | null => {
    const k = this.st.auth.hostKeys.find((h) => h.kid === hostKid && h.fromSeq <= seq && (h.toSeq === null || seq <= h.toSeq));
    return k ? b64uDecode(k.pub, 32) : null;
  };

  append(signed: unknown, body?: Uint8Array): void {
    this.run(signed, body, true);
  }

  /** Every check of `append` without changing the fold. */
  check(signed: unknown, body?: Uint8Array): void {
    this.run(signed, body, false);
  }

  private run(value: unknown, body: Uint8Array | undefined, commit: boolean): void {
    const seq = this.hashes.length;
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
      if (commit) {
        this.hashes.push(signed.hash);
        this.st = { ...this.st, epoch: entry.epoch };
      }
      return;
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

    // Base rule: the producer's verified head lies strictly before this entry and is in this chain.
    if (!(sb.base.seq < seq)) throw new FoldError(seq, "base_not_before_entry", `base.seq ${sb.base.seq} is not before ${seq}`);
    if (this.entryHashAt(sb.base.seq) !== sb.base.hash) throw new FoldError(seq, "base_mismatch", `base hash is not the hash of entry ${sb.base.seq}`);

    // Unique rule.
    if (this.bodySeq.has(entry.bodyHash)) throw new FoldError(seq, "duplicate_statement", `statement already carried by entry ${this.bodySeq.get(entry.bodyHash)}`);

    // Producer allowed for the type, with a key held in the state (M-5), and its signature.
    if (!producerKindAllowed(sb.type, sb.producer.kind)) throw new FoldError(seq, "not_permitted", `${sb.producer.kind} may not sign ${sb.type}`);
    const producer = this.resolveProducer(sb, seq);
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

    const before = membersFingerprint(this.st.members);
    const next = structuredClone(this.st);
    applyStatement(next, sb, entry, producer);
    if (membersFingerprint(next.members) !== before) next.rosterSeq = seq;
    next.epoch = entry.epoch;

    if (!commit) return;
    this.st = next;
    this.hashes.push(signed.hash);
    this.bodySeq.set(entry.bodyHash, seq);
    this.maxBase.set(sb.producer.kid, sb.base.seq);
  }

  private resolveProducer(sb: StatementBody, seq: number): Producer | null {
    const kid = sb.producer.kid;
    const a = this.st.auth;
    switch (sb.producer.kind) {
      case "admin": {
        if (a.adminKeyDenylist[kid]) return null;
        const k = a.admins.find((x) => x.kid === kid && x.fromSeq <= seq && (x.toSeq === null || seq <= x.toSeq));
        return k ? { kind: "admin", pub: b64uDecode(k.pub, 32) } : null;
      }
      case "recovery":
        return a.recovery && a.recovery.kid === kid ? { kind: "recovery", pub: b64uDecode(a.recovery.pub, 32) } : null;
      case "host": {
        const pub = this.hostKeyAt(kid, seq);
        return pub ? { kind: "host", pub } : null;
      }
      case "device":
        for (const m of Object.values(this.st.members)) {
          for (const d of m.devices) {
            const pub = b64uDecode(d.sig, 32);
            if (kidOf("ed25519", pub) === kid) return { kind: "device", pub, memberId: m.memberId, deviceId: d.deviceId };
          }
        }
        return null;
      case "node":
        // Node keys come from node.certified, which is reserved (section 4.1).
        return null;
    }
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

// ---- apply (mutates the clone it is given) ----

function applyStatement(s: RoomState, sb: StatementBody, entry: LogEntry, producer: Producer): void {
  const seq = entry.seq;
  const fail = (reason: FoldReason, message: string): never => {
    throw new FoldError(seq, reason, message);
  };
  const type = sb.type;
  if (s.auth.closed) fail("room_closed", "no statement is accepted after room.closed");
  // seq 0 is the creator's admission, and only there (section 5).
  const isCreator = type === "member.admitted" && (sb.data as StatementData<"member.admitted">).confirmation.method === "creator";
  if (seq === 0 && !isCreator) fail("genesis_admission_required", "seq 0 must be the creator's member.admitted");
  if (seq !== 0 && isCreator) fail("creator_not_at_genesis", `method "creator" at seq ${seq}`);
  if (NOT_IN_CORE.has(type)) fail("not_implemented", `${type} is folded by milestone I-6`);
  if (RESERVED.has(type)) fail("reserved_type", `${type} is reserved`);

  const versionOf = (key: string) => s.auth.versions[key] ?? -1;
  const checkVer = (key: string, ver: number) => {
    if (ver !== versionOf(key)) fail("stale_version", `${key}: ver ${ver}, current ${versionOf(key)}`);
  };
  const member = (memberId: string): RosterEntry => s.members[memberId] ?? fail("unknown_member", "member is not in the roster");
  const deviceOf = (memberId: string) => {
    if (producer.kind !== "device" || producer.memberId !== memberId) fail("not_member_device", "producer is not a device of this member");
  };
  const lane = (laneId: string): LaneState => {
    const l = s.auth.lanes[laneId] ?? fail("unknown_lane", "lane does not exist");
    if (l.status === "closed") fail("lane_closed", "lane is closed");
    return l;
  };
  const freshDevice = (d: DeviceEntry, seen: Set<string>) => {
    if (s.used.devices[d.deviceId]) fail("id_reused", "deviceId was used before in this room");
    for (const key of [d.sig, d.dh]) {
      if (s.deviceDenylist[key] || s.auth.retiredKeys[key] || seen.has(key)) fail("key_reused", "device key is denylisted, retired or already in the roster");
      seen.add(key);
    }
  };
  const rosterKeys = (): Set<string> => {
    const keys = new Set<string>();
    for (const m of Object.values(s.members)) for (const d of m.devices) keys.add(d.sig).add(d.dh);
    return keys;
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
  const freshKey = (pub: string) => {
    if (s.auth.retiredKeys[pub]) fail("key_reused", "key is retired in this room");
  };

  switch (type) {
    case "member.admitted": {
      const d = sb.data as StatementData<"member.admitted">;
      const m = d.member;
      if (s.used.members[m.memberId]) fail("id_reused", "memberId was used before in this room");
      const seen = rosterKeys();
      for (const dev of m.devices) freshDevice(dev, seen);
      s.members[m.memberId] = { memberId: m.memberId, role: m.role, lanes: [...m.lanes], devices: sortDevices(m.devices) };
      s.used.members[m.memberId] = true;
      for (const dev of m.devices) s.used.devices[dev.deviceId] = true;
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
      // I-6: cancel the member's pending adds and rekeys.
      return;
    }
    case "member.left": {
      const d = sb.data as StatementData<"member.left">;
      const m = member(d.memberId);
      deviceOf(d.memberId);
      if (m.devices.length !== 1) fail("not_sole_device", "member.left needs the member's only active device");
      for (const dev of m.devices) retireDevice(dev);
      delete s.members[d.memberId];
      return;
    }
    case "member.device.replaced": {
      const d = sb.data as StatementData<"member.device.replaced">;
      const m = member(d.memberId);
      checkVer(versionKey.devices(d.memberId), d.ver);
      const removed = d.removed.map((id) => m.devices.find((x) => x.deviceId === id) ?? fail("unknown_device", "removed device is not the member's"));
      freshDevice(d.added, rosterKeys());
      const kept = m.devices.filter((x) => !d.removed.includes(x.deviceId));
      if (kept.length + 1 > 8) fail("too_many_devices", "a member has at most 8 devices");
      for (const dev of removed) retireDevice(dev);
      m.devices = sortDevices([...kept, d.added]);
      s.used.devices[d.added.deviceId] = true;
      s.auth.versions[versionKey.devices(d.memberId)] = seq;
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
      // I-6: cancel the device's own pending rekey and every pending request it made.
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
      s.auth.versions[versionKey.endpoint()] = seq;
      return;
    }
    case "lane.created": {
      const d = sb.data as StatementData<"lane.created">;
      if (s.used.lanes[d.laneId]) fail("id_reused", "laneId was used before in this room");
      freshKey(d.offer.dh.pub);
      s.auth.lanes[d.laneId] = { owner: d.owner, offer: d.offer, visibility: d.visibility, status: "open", degradedAtHts: null, showNames: false };
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
        l.degradedAtHts = entry.hts;
      }
      return;
    }
    case "lane.closed": {
      const d = sb.data as StatementData<"lane.closed">;
      const l = lane(d.laneId);
      if (producer.kind === "host" && !(l.status === "degraded" && l.degradedAtHts !== null && entry.hts - l.degradedAtHts >= LANE_DEGRADED_CLOSE_MS)) {
        fail("not_permitted", "the host closes a lane only after lane.degraded for 24 h");
      }
      l.status = "closed";
      retireKey(l.offer.dh.pub);
      return;
    }
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
    case "grant.suspected_theft":
    case "mls.stalled":
    case "producer.fence":
      return;
    default:
      fail("not_implemented", `${type} has no fold rule`);
  }
}
