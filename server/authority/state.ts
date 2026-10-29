// Fold state and errors (room-log-v2.md section 5; identity-model.md sections 5.2 and 6.1;
// keys-rotation-recovery.md section 3). Shared by fold.ts and its I-6 parts (refold.ts,
// lineage.ts, holds.ts). Pure data: no I/O, no key material beyond public keys.
import { b64uDecode } from "../proto/b64u";
import { kid as kidOf } from "../proto/keys";
import type { EntryError } from "./entries";
import type { RoomGenesis } from "./genesis";
import type { DeviceEntry, Policy, PolicySetting, RosterEntry } from "./schema";

export type FoldReason =
  // genesis (seq -1) and unanticipated exceptions (fold.ts)
  | "bad_genesis"
  | "internal_error"
  // entry layer (entries.ts)
  | EntryError["reason"]
  // body and statement layer
  | "missing_body"
  | "body_hash_mismatch"
  | "bad_body"
  | "type_mismatch"
  | "unknown_type"
  | "unsignable_type"
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
  | "reserved_type"
  // I-6: key changes (keys-rotation-recovery.md section 2)
  | "bad_key_change"
  | "bad_new_key_sig"
  // I-6: admin, recovery and host keys, revocations (room-log-v2.md 5.1)
  | "unknown_key"
  | "last_admin"
  | "already_revoked"
  | "revocation_out_of_bounds"
  | "revocation_before_since"
  | "host_key_current"
  | "recovery_exists"
  // I-6: proposals, lineages and closure (5.2)
  | "bad_exp"
  | "proposal_required"
  | "proposal_not_allowed"
  | "unknown_proposal"
  | "proposal_expired"
  | "proposal_mismatch"
  | "proposer_inactive"
  | "confirmer_not_independent"
  | "confirmer_after_proposal"
  | "close_too_early"
  // I-6: device requests, holds, vetoes and conflicts (4.3, 5)
  | "unknown_link"
  | "link_used"
  | "not_pending"
  | "request_cancelled"
  | "vetoed"
  | "auto_not_allowed"
  | "conflict_open"
  | "requester_too_young"
  | "hold_not_elapsed"
  | "no_conflict"
  // round 8: leaf repair requests and the revocation depth cap
  | "not_in_scope"
  | "repair_too_soon"
  | "repair_rate"
  | "revocation_too_deep";

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

export type Fail = (reason: FoldReason, message: string) => never;

// ---- state ----

export type KeyRefValue = { alg: "ed25519" | "x25519"; kid: string; pub: string };
export type AdminKeyState = {
  kid: string;
  pub: string;
  /** First position at which the key may sign. */
  fromSeq: number;
  /** Last position at which it may sign: the entry carrying its rotation, removal or revocation. */
  toSeq: number | null;
  /** Set by `admin.key.revoked`: its statements from here on are suspect (section 5.1). */
  suspectFromSeq: number | null;
  /** Lineage root (section 5.2). */
  root: string;
  /** Kid of the admin key that added it, `"recovery"`, or null for a genesis key. */
  addedBy: string | null;
  /** Authority start: bounds how far back its revocations reach (section 5.1 step 1). */
  since: number;
  end: "rotated" | "removed" | "revoked" | null;
};
export type RecoveryKeyState = { kid: string; pub: string; fromSeq: number; since: number };
export type HostKeyState = {
  kid: string;
  pub: string;
  fromSeq: number;
  toSeq: number | null;
  /** Entries signed by this key in `[suspectFromSeq, toSeq]` are suspect for ordering. */
  suspectFromSeq: number | null;
  /** unix s, grants only. */
  validFrom: number;
  validTo: number | null;
  /** Once set, every grant signed by this key is refused, whatever its `iat`. */
  revoked: boolean;
  /**
   * Set by a re-fold when the statement that installed this key is suspect or void (decision round
   * 8, item 3): the key keeps its positions for entries, but grants it signs are refused until a
   * valid admin rotates it (room-log-v2.md section 5.1, "Retired keys after a re-fold").
   */
  uncertified: boolean;
};
export type LaneState = {
  owner: string;
  offer: { serverId: string; dh: KeyRefValue; relay: { host: string; port: number; tls: true } };
  visibility: "room" | "team";
  status: "open" | "degraded" | "closed";
  degradedAtHts: number | null;
  showNames: boolean;
  /** The offer was installed by a statement a re-fold made suspect or void (round 8, item 3). */
  uncertified: boolean;
};
export type Set_ = Record<string, true>;
/** An admin-key revocation in effect: the pair `(kid, fromSeq)` and the position `seq` of its entry. */
export type Revocation = { kid: string; fromSeq: number; seq: number };
/** A `device.leaf.repair.requested` (round 8, item 1), kept for 24 h of `hts` for the rate limits. */
export type RepairRequest = {
  memberId: string;
  deviceId: string;
  scope: string | null;
  generation: number;
  keyPackageRef: string;
  seq: number;
  hts: number;
  /** Cancelled when the device leaves the roster or its keys change. Fulfilment is tracked by the MLS layer. */
  status: "open" | "cancelled";
};
export type CloseProposal = { kid: string; seq: number; hts: number; exp: number; closeDelay: number; used: boolean };
export type RecoveryProposal = { kid: string; seq: number; exp: number; change: string; used: boolean };

/** A held `device.added` or `device.rekeyed` (room-log-v2.md 4.3; identity-model.md 6.3). */
export type PendingRequest = {
  kind: "add" | "rekey";
  memberId: string;
  /** The device being added, or the device being rekeyed. */
  deviceId: string;
  /** The device that signed the request. */
  requester: string;
  /** The new device entry (add), or the device with its new keys (rekey). */
  device: DeviceEntry;
  seq: number;
  hts: number;
  /** The requester was the member's only active device when the request was sequenced. */
  sole: boolean;
  /** Adds only: the requester had been active for less than 24 h of `hts`. */
  young: boolean;
  status: "pending" | "vetoed" | "cancelled" | "approved";
};

export type AuthorityState = {
  admins: AdminKeyState[];
  recovery: RecoveryKeyState | null;
  hostKeys: HostKeyState[];
  adminKeyDenylist: Set_;
  /** Public keys (b64u) of every key that was valid in the room and was rotated out, removed or revoked. */
  retiredKeys: Set_;
  endpoint: { serverId: string; dh: KeyRefValue; relay: { host: string; port: number; tls: true } };
  /** The endpoint was installed by a statement a re-fold made suspect or void (round 8, item 3). */
  endpointUncertified: boolean;
  lanes: Record<string, LaneState>;
  scopes: Record<string, string[]>;
  policy: Policy;
  /** Field versions (section 4.0). A missing key is version -1. */
  versions: Record<string, number>;
  /** Admin-key revocations in effect, in chain order (section 5.1 step 3). */
  revocations: Revocation[];
  /** `room.close.proposed` by bodyHash. */
  pendingClose: Record<string, CloseProposal>;
  /** `recovery.key.proposed` by bodyHash. */
  pendingRecovery: Record<string, RecoveryProposal>;
  closed: boolean;
};

export type RoomState = {
  roomId: string;
  genesisHash: string;
  auth: AuthorityState;
  members: Record<string, RosterEntry>;
  /** Device signing and DH keys (b64u) that were removed or rotated out (identity-model.md 6.2). */
  deviceDenylist: Set_;
  /** Ids that were ever used: memberId, deviceId (from its request on), laneId, inviteRef; linkRef maps to its member. */
  used: { members: Set_; devices: Set_; lanes: Set_; invites: Set_; links: Record<string, string>; linksConsumed: Set_ };
  /** `hts` at which each active device became active (young-device rule). */
  deviceSince: Record<string, number>;
  /** Device requests by bodyHash, with their outcome. */
  pending: Record<string, PendingRequest>;
  /** Open device conflicts: memberId -> seq of the veto that opened it. */
  conflicts: Record<string, number>;
  /** Leaf repair requests of the last 24 h of `hts`, by bodyHash. */
  repairs: Record<string, RepairRequest>;
  /** History marks after a re-fold: seq -> suspect (signed by a revoked key) or void (no longer applies). */
  marks: Record<string, "suspect" | "void">;
  rosterSeq: number;
  epoch: number | null;
};

export const versionKey = {
  policy: (setting: PolicySetting) => `policy:${setting}`,
  role: (memberId: string) => `role:${memberId}`,
  lanes: (memberId: string) => `lanes:${memberId}`,
  devices: (memberId: string) => `devices:${memberId}`,
  conflict: (memberId: string) => `conflict:${memberId}`,
  scope: (scopeId: string) => `scope:${scopeId}`,
  laneNames: (laneId: string) => `laneNames:${laneId}`,
  laneOffer: (laneId: string) => `laneOffer:${laneId}`,
  endpoint: () => "endpoint",
};

export const edKid = (pub: string): string => kidOf("ed25519", b64uDecode(pub, 32));

export function initState(genesis: RoomGenesis, genesisHash: string, roomId: string): RoomState {
  const g = genesis.body;
  return {
    roomId,
    genesisHash,
    auth: {
      // Genesis keys are their own lineage roots, with authority start 0 (section 5.1, 5.2).
      admins: g.admins.map((a) => ({ kid: a.kid, pub: a.pub, fromSeq: 0, toSeq: null, suspectFromSeq: null, root: a.kid, addedBy: null, since: 0, end: null })),
      recovery: g.recovery ? { kid: g.recovery.kid, pub: g.recovery.pub, fromSeq: 0, since: 0 } : null,
      hostKeys: [{ kid: g.host.key.kid, pub: g.host.key.pub, fromSeq: 0, toSeq: null, suspectFromSeq: null, validFrom: g.host.notBefore, validTo: null, revoked: false, uncertified: false }],
      adminKeyDenylist: {},
      retiredKeys: {},
      endpoint: structuredClone(g.endpoint),
      endpointUncertified: false,
      lanes: {},
      scopes: {},
      policy: structuredClone(g.policy),
      versions: {},
      revocations: [],
      pendingClose: {},
      pendingRecovery: {},
      closed: false,
    },
    members: {},
    deviceDenylist: {},
    used: { members: {}, devices: {}, lanes: {}, invites: {}, links: {}, linksConsumed: {} },
    deviceSince: {},
    pending: {},
    conflicts: {},
    repairs: {},
    marks: {},
    rosterSeq: -1,
    epoch: null,
  };
}

/** Admin keys that may sign now (not rotated out, removed or revoked). */
export function activeAdmins(auth: AuthorityState): AdminKeyState[] {
  return auth.admins.filter((a) => a.toSeq === null && !auth.adminKeyDenylist[a.kid]);
}

/** Every public key the room currently uses for any subject; a new key must not be one of them. */
export function keysInUse(s: RoomState): Set<string> {
  const a = s.auth;
  const keys = new Set<string>();
  for (const k of a.admins) keys.add(k.pub);
  if (a.recovery) keys.add(a.recovery.pub);
  for (const h of a.hostKeys) keys.add(h.pub);
  keys.add(a.endpoint.dh.pub);
  for (const l of Object.values(a.lanes)) keys.add(l.offer.dh.pub);
  for (const m of Object.values(s.members)) for (const d of m.devices) keys.add(d.sig).add(d.dh);
  return keys;
}
