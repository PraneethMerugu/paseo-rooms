// Plugin RPC contracts of the Rooms runtime (identity v2; the only runtime since the I-15 cut-over).
// Enrollment (I-9): the owner creates invites
// and admits join requests after the SAS comparison; the member previews, joins, compares and
// confirms. Interactive admin actions (identity-model 5.3) take a one-time `confirmToken` that
// `rooms.v2.admin.prepare` returns together with a description of what will be signed; a token whose
// subject changed since it was issued is refused with `stale_base` and the UI asks again with the new
// value (room-log-v2 2, R-9). This is a usability guard, not a security boundary (S-12). An invite code
// is a bearer secret: it is returned once to the caller and never logged. Device links (I-11): a
// member device creates a `prl2.` link code (also a bearer secret, returned once), compares the SAS
// with the new device and confirms; the new device joins with `rooms.v2.join.*`. Members veto, admins
// approve held adds and resolve conflicts. `rooms.v2.chat.*` (R3.4, product M2) send, list and mark
// read the room's chat, which travels only inside the room's MLS group as messages signed by the
// sender's device (mls-integration 5.2). `rooms.v2.test.clock.advance` is TEST-ONLY and registered
// only on e2e test homes.
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

const Empty = z.object({});
const Ok = z.object({ ok: z.literal(true) });
const RoomIdIn = z.object({ roomId: z.string().regex(/^room_[0-9a-f]{32}$/) });
const Head = z.object({ seq: z.number().int(), hash: z.string() });

const PendingIdIn = RoomIdIn.extend({ pendingId: z.string().regex(/^pen_[0-9a-f]{32}$/) });
const RefIn = RoomIdIn.extend({ ref: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });
/** One-time confirmation of an interactive admin action (identity-model 5.3), from `rooms.v2.admin.prepare`. */
export const ConfirmToken = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const Confirmed = { confirmToken: ConfirmToken };
const Kid = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const Seq = z.object({ seq: z.number().int() });
const RoleName = z.enum(["guest", "watch", "comment", "steer", "approve", "maintain", "admin"]);
const MemberIdV2 = z.string().regex(/^mem_[0-9a-f]{32}$/);
const DeviceIdV2 = z.string().regex(/^dev_[0-9a-f]{32}$/);
const LaneIdV2 = z.string().regex(/^lane_[0-9a-f]{32}$/);
const Proposal = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

/** A recovery code offered once: on screen, as text to copy, and as the file of identity-model 5.4.1. */
export const RecoveryOfferV2 = z.object({
  kid: z.string(),
  code: z.string(),
  file: z.object({ name: z.string(), text: z.string() }),
});

// Inputs of the interactive admin actions, without the token (the action RPCs add `confirmToken`).
const InviteCreateIn = RoomIdIn.extend({
  role: RoleName.optional(),
  lanes: z.array(LaneIdV2).max(64).optional(),
  expS: z.number().int().min(300).max(86400).optional(),
  note: z.string().max(80).optional(),
  roomName: z.string().min(1).max(80).optional(),
});
const MemberRemoveIn = RoomIdIn.extend({ memberId: MemberIdV2, compromise: z.boolean().optional() });
const MemberRoleIn = RoomIdIn.extend({ memberId: MemberIdV2, role: RoleName });
const LaneCreateIn = RoomIdIn.extend({ agentId: z.string().min(1).max(200), label: z.string().min(1).max(80).optional() });
const DeviceRemoveIn = RoomIdIn.extend({ memberId: MemberIdV2, deviceId: DeviceIdV2, compromise: z.boolean() });
const ConflictIn = RoomIdIn.extend({ memberId: MemberIdV2 });
const KeyRevokeIn = RoomIdIn.extend({ kid: Kid, fromSeq: z.number().int().min(0) });
const LaneRotateIn = RoomIdIn.extend({ laneId: LaneIdV2 });
const ProposalIn = RoomIdIn.extend({ proposal: Proposal });

/** Every interactive admin action, as `rooms.v2.admin.prepare` names it. */
export const AdminActionV2 = z.discriminatedUnion("kind", [
  InviteCreateIn.extend({ kind: z.literal("invite.create") }),
  PendingIdIn.extend({ kind: z.literal("join.admit") }),
  MemberRemoveIn.extend({ kind: z.literal("member.remove") }),
  MemberRoleIn.extend({ kind: z.literal("member.role") }),
  LaneCreateIn.extend({ kind: z.literal("lane.create") }),
  DeviceRemoveIn.extend({ kind: z.literal("device.remove") }),
  RefIn.extend({ kind: z.literal("device.approve") }),
  ConflictIn.extend({ kind: z.literal("device.conflict.resolve") }),
  RoomIdIn.extend({ kind: z.literal("host.key.rotate") }),
  KeyRevokeIn.extend({ kind: z.literal("host.key.revoke") }),
  RoomIdIn.extend({ kind: z.literal("admin.key.rotate") }),
  KeyRevokeIn.extend({ kind: z.literal("admin.key.revoke") }),
  RoomIdIn.extend({ kind: z.literal("endpoint.rotate") }),
  LaneRotateIn.extend({ kind: z.literal("lane.rotate") }),
  LaneRotateIn.extend({ kind: z.literal("lane.close") }),
  RoomIdIn.extend({ kind: z.literal("room.close.propose") }),
  ProposalIn.extend({ kind: z.literal("room.close.confirm") }),
  RoomIdIn.extend({ kind: z.literal("recovery.create") }),
  ProposalIn.extend({ kind: z.literal("recovery.confirm") }),
]);
export type AdminActionV2 = z.infer<typeof AdminActionV2>;
export type AdminActionKind = AdminActionV2["kind"];

/** What the confirmation dialog shows: exactly what will be signed, and the current value it replaces. */
export const AdminDescriptionV2 = z.object({
  title: z.string(),
  details: z.array(z.string()),
  /** The current value the action changes ("Current role: comment"), shown again after `stale_base`. */
  current: z.string().nullable(),
  warning: z.string().nullable(),
  /** The dialog asks the person to type this text before the confirm button is enabled (destructive actions). */
  typeToConfirm: z.string().nullable(),
});

/**
 * Step one of an interactive admin action: the description and a one-time token (5 minutes). Step
 * two is the action RPC with `confirmToken`. A token is bound to the exact action and to the
 * current value it describes; if that value changed, the action RPC answers `stale_base`.
 */
export const roomsV2AdminPrepare = defineRpc({
  name: "rooms.v2.admin.prepare",
  input: z.object({ action: AdminActionV2 }),
  output: z.object({ confirmToken: ConfirmToken, expiresAt: z.number().int(), description: AdminDescriptionV2 }),
});

/** A held device add or rekey (room-log-v2 4.3): ids and times only. `effectiveAfter` null: an admin must approve. */
export const DeviceRequestV2View = z.object({
  ref: z.string(),
  kind: z.enum(["add", "rekey"]),
  memberId: z.string(),
  deviceId: z.string(),
  requester: z.string(),
  seq: z.number().int(),
  hts: z.number().int(),
  sole: z.boolean(),
  young: z.boolean(),
  status: z.enum(["pending", "vetoed", "cancelled", "approved"]),
  effectiveAfter: z.number().int().nullable(),
});

/** The linking device's view of one link (identity-model.md 6.4): attempts counted on this device. */
export const LinkV2View = z.object({
  linkId: z.string(),
  exp: z.number().int(),
  attempts: z.number().int(),
  burned: z.enum(["sas_mismatch", "attempts"]).nullable(),
  pending: z
    .object({
      pendingId: z.string(),
      deviceId: z.string(),
      label: z.string(),
      state: z.enum(["open", "revealed", "confirmed", "aborted", "closed"]),
      sas: z.string().nullable(),
      earlierAttempts: z.number().int(),
    })
    .nullable(),
});

export const InviteV2View = z.object({
  inviteId: z.string(),
  inviteRef: z.string(),
  role: z.string(),
  lanes: z.array(z.string()),
  note: z.string(),
  exp: z.number().int(),
  state: z.enum(["open", "claimed", "used", "revoked", "burned", "expired"]),
  failedProofs: z.number().int(),
  abandoned: z.number().int(),
});

/** A join request as the owner's card shows it (enrollment-v2.md 6.3). `sas` once the member revealed. */
export const JoinRequestV2View = z.object({
  pendingId: z.string(),
  kind: z.enum(["invite", "link"]),
  note: z.string(),
  label: z.string(),
  state: z.enum(["created", "sas_shown", "member_ok", "admin_ok", "held", "admitted", "closed"]),
  sas: z.string().nullable(),
  abandonedBefore: z.number().int(),
  contested: z.boolean(),
  expiresAt: z.number().int(),
  closedReason: z.string().nullable(),
  memberId: z.string().nullable(),
  deviceId: z.string().nullable(),
});

export const LaneV2View = z.object({
  laneId: z.string(),
  serverId: z.string(),
  status: z.enum(["open", "degraded", "closed"]),
  label: z.string().nullable(),
  agentId: z.string().nullable(),
  endpoint: z.enum(["starting", "online", "offline", "closed"]).nullable(),
  links: z.number().int(),
  routes: z.number().int(),
  showNames: z.boolean(),
});

/** Current grants by (device, lane): ids and times only, never tokens. */
export const GrantV2View = z.object({ deviceId: z.string(), laneId: z.string(), gid: z.string(), iat: z.number().int(), exp: z.number().int() });

/**
 * One activity notice (room-log-v2 4.6; R3.5), derived from this device's verified fold: ids, types and
 * setting values only. `type` is the entry type, or `uncertified_key`.
 */
export const ActivityV2Item = z.object({
  seq: z.number().int(),
  hts: z.number().int(),
  type: z.string(),
  alert: z.boolean(),
  memberId: z.string().optional(),
  deviceId: z.string().optional(),
  laneId: z.string().optional(),
  value: z.string().optional(),
  changes: z.array(z.object({ setting: z.string(), from: z.string(), to: z.string() })).optional(),
  sole: z.boolean().optional(),
  marked: z.number().int().optional(),
});

/** A member's display name from `member.profile` (R3.3): untrusted text; `collision` when another member's name looks the same. */
export const MemberNameV2View = z.object({ memberId: z.string(), name: z.string().nullable(), collision: z.boolean() });

/** A room alert as this device shows it; `acked`: acknowledged on this device (R3.5). */
const AlertV2 = z.object({ type: z.string(), seq: z.number().int(), acked: z.boolean() });

/** One roster entry as the owner's member list shows it. `label`: self-reported at enrollment, if known here. */
export const RosterMemberV2View = z.object({
  memberId: z.string(),
  role: z.string(),
  lanes: z.array(z.string()),
  label: z.string().nullable(),
  /** R3.3: the display name from `member.profile` (MLS), and whether it looks like another member's. */
  displayName: z.string().nullable(),
  nameCollision: z.boolean(),
  /** This daemon's own member entry (the creator). */
  self: z.boolean(),
  devices: z.array(z.object({ deviceId: z.string(), kind: z.enum(["person", "gateway"]), since: z.number().int().nullable(), connected: z.boolean() })),
});

/** R2.6: how "Also delete hosted rooms" can close a hosted room before deleting it (keys 6.8). */
export const HostedClosurePlanV2 = z.object({
  plan: z.enum(["already_closed", "confirm_proposal", "recovery_key", "none"]),
  reason: z.enum(["recovery_code_required", "second_admin_required", "no_admin_key"]).nullable(),
  message: z.string(),
});

export const OwnedRoomV2View = z.object({
  roomId: z.string(),
  serverId: z.string(),
  head: Head,
  endpoint: z.enum(["starting", "online", "offline", "closed"]),
  sessions: z.array(z.object({ memberId: z.string(), deviceId: z.string() })),
  members: z.number().int(),
  /** I-14: the roster with devices (ids, roles and self-reported labels; no keys). */
  roster: z.array(RosterMemberV2View),
  /** Room policy settings the dialogs explain (identity-model 5.2.1). */
  policy: z.object({
    deviceAddApproval: z.string(),
    soleDeviceChange: z.string(),
    rotateLaneOnRemove: z.string(),
    recoveryEscrow: z.string(),
    closeDelayS: z.number().int(),
  }),
  /** Independent admin lineages (room-log-v2 5.2): two or more need a second admin to confirm. */
  lineages: z.number().int(),
  /** R2.6: whether "Also delete hosted rooms" can close this room first (keys 6.8), and why not. */
  closeOnDelete: HostedClosurePlanV2.optional(),
  invites: z.array(InviteV2View),
  joinRequests: z.array(JoinRequestV2View),
  lanes: z.array(LaneV2View),
  grants: z.array(GrantV2View),
  grantTtlS: z.number().int(),
  /** grants-v2 7.2: access was cut but a save failed; retried every 10 s. */
  persistError: z.string().nullable(),
  /** grants-v2 6.4: devices with two suspected thefts within 7 days. */
  compromisedDevices: z.array(z.string()),
  /** Held device adds and rekeys of every member. */
  deviceRequests: z.array(DeviceRequestV2View),
  /** Members with an open device conflict (after a veto). */
  conflicts: z.array(z.string()),
  /** I-12: key ids and rotation state (no key material). */
  keys: z.object({
    hostKid: z.string().nullable(),
    hostKeys: z.array(z.object({ kid: z.string(), fromSeq: z.number().int(), toSeq: z.number().int().nullable(), validTo: z.number().int().nullable(), revoked: z.boolean(), uncertified: z.boolean() })),
    adminKid: z.string().nullable(),
    admins: z.array(z.object({ kid: z.string(), root: z.string() })),
    recoveryKid: z.string().nullable(),
    movedEndpoints: z.array(z.string()),
    closed: z.boolean(),
    closeProposals: z.array(z.object({ ref: z.string(), kid: z.string(), hts: z.number().int(), exp: z.number().int() })),
    /** I-14: open `recovery.key.proposed` (two lineages), for the other lineage's confirmation. */
    recoveryProposals: z.array(z.object({ ref: z.string(), kid: z.string(), exp: z.number().int() })).optional(),
  }),
  /** Room-log 4.6 alerts: a host key, the endpoint or a lane offer left uncertified by a re-fold. */
  uncertified: z.array(z.object({ subject: z.string(), id: z.string() })),
  /** R3.3: the room name and description from `room.profile` (MLS), null until one is set. */
  roomName: z.string().nullable(),
  roomDescription: z.string().nullable(),
  /** R3.6: display fingerprint of this daemon's admin key, which a joining member sees as the owner fingerprint. */
  adminFingerprint: z.string().nullable(),
  /** R3.5: newest first, from the owner device's own fold of the log. */
  activity: z.array(ActivityV2Item),
});

/** The member's side of a join (enrollment-v2.md 6.4, 7.3). */
export const JoiningV2View = z.object({
  roomId: z.string(),
  state: z.enum(["keys", "pending", "confirmed", "held", "admitted", "registered", "failed"]),
  roomName: z.string(),
  sas: z.string().nullable(),
  /** Enrollment 6.4 (R3.6): display fingerprints of the room's admin keys the pre-admission chain certified. */
  ownerFingerprints: z.array(z.string()),
  terms: z.object({ role: z.string(), lanes: z.array(z.string()) }).nullable(),
  expiresAt: z.number().int().nullable(),
  failure: z.string().nullable(),
  connection: z.enum(["idle", "connecting", "waiting", "retrying", "done"]),
  lastError: z.string().nullable(),
});

export const JoinedRoomV2View = z.object({
  roomId: z.string(),
  memberId: z.string(),
  deviceId: z.string(),
  status: z.enum(["idle", "connecting", "open", "closed", "ended"]),
  head: Head,
  lastError: z.string().nullable(),
  endedReason: z.string().nullable(),
  alerts: z.array(AlertV2),
  /** Room-log 6.6: fork, truncation or invalid_entry stopped sending; acknowledging an alert does not change it. */
  sendingStopped: z.boolean(),
  /** R3.3: room name, description and members' display names from MLS (null or empty until set). */
  roomName: z.string().nullable(),
  roomDescription: z.string().nullable(),
  names: z.array(MemberNameV2View),
  /** R3.5: newest first, from this device's verified fold. */
  activity: z.array(ActivityV2Item),
  registration: z.string().nullable(),
  /** Device links created on this device. */
  links: z.array(LinkV2View),
  /** I-12: this device's open rekey (keys-rotation-recovery 4.1), or null. */
  rekey: z.object({ ref: z.string().nullable(), requestedAt: z.number().int(), published: z.boolean() }).nullable(),
  /** The room endpoint in this device's verified state (changes with `endpoint.rotated`). */
  endpointServerId: z.string().nullable(),
  /** This member's held device requests: the "Was this you?" prompt (Not me = rooms.v2.device.veto). */
  deviceRequests: z.array(DeviceRequestV2View),
  conflict: z.boolean(),
  /** R3.1: active devices of this member in the verified roster (1: Leave signs `member.left`; more: only this device leaves). */
  memberDevices: z.number().int().nullable().optional(),
  /** This daemon hosts the room (the creator's own device): it cannot leave it. */
  hosted: z.boolean().optional(),
  lanes: z.array(
    z.object({
      laneId: z.string(),
      registrationId: z.string().nullable(),
      hostStatus: z.string().nullable(),
      gid: z.string().nullable(),
      lifetimeMs: z.number(),
      idleInMs: z.number(),
      forcedInMs: z.number(),
      rotations: z.number().int(),
      lastRotation: z.object({ reason: z.string(), at: z.number() }).nullable(),
      lastDecision: z.string().nullable(),
      lastError: z.string().nullable(),
    }),
  ),
});

/** The room group as one device sees it (mls-integration.md; I-13). No message text, no key material. */
export const MlsV2View = z.object({
  roomId: z.string(),
  inGroup: z.boolean(),
  epoch: z.number().int().nullable(),
  cursor: z.number().int(),
  leaves: z.number().int(),
  join: z.enum(["pending", "confirmed", "unconfirmed", "fork"]).nullable(),
  stalled: z.boolean(),
  disabled: z.string().nullable(),
  canSend: z.boolean(),
  /** Chat messages stored on this device for the room, and how many from others are unread (R3.4). */
  messages: z.number().int(),
  unread: z.number().int().optional(),
  alerts: z.array(AlertV2),
});

/** R3.7: a routed lane host that could not be removed from this daemon's host list yet. */
export const StaleHostV2View = z.object({
  roomId: z.string(),
  laneId: z.string(),
  registrationId: z.string(),
  label: z.string(),
  reason: z.enum(["access_ended", "lane_closed", "lane_removed", "left", "data_deleted"]),
  since: z.number().int(),
  lastError: z.string().nullable(),
});

export const roomsV2Status = defineRpc({
  name: "rooms.v2.status",
  input: Empty,
  output: z.object({
    protocol: z.literal("v2"),
    state: z.enum(["starting", "ready", "error"]),
    error: z.string().nullable(),
    keystore: z
      .object({
        state: z.string(),
        backend: z.string().nullable(),
        fallback: z.boolean(),
        /** identity-model 7.5 step 3: the persistent fallback notice. */
        notice: z.string().nullable().optional(),
        /** Why room operations stopped (locked, missing entry, ...); never key material. */
        message: z.string().nullable().optional(),
      })
      .nullable(),
    /** The start check found unprotected files (paths relative to plugin-data/rooms): offer "Fix permissions". */
    permissionProblems: z.array(z.object({ path: z.string(), code: z.string(), detail: z.string() })).optional(),
    /** The daemon's OS (`process.platform`): the About panel states the weaker durability on win32 (grants-v2 7.3). */
    platform: z.string().optional(),
    /**
     * Migration from M1 (migration.md section 2), null when this home never held M1 data: the archive
     * directory (relative), whether the one-time notice is still unread, the v1 key files still in the
     * archive, and the v1 lane agents left on this daemon ("Agents from closed rooms").
     */
    migration: z
      .object({
        archive: z.string(),
        notice: z.boolean(),
        gateway: z.enum(["none", "pending", "archived"]),
        member: z.enum(["none", "pending", "archived"]),
        hosts: z.enum(["none", "pending", "done"]),
        hostsRemoved: z.number().int(),
        keyFiles: z.array(z.string()),
        lanes: z.array(z.object({ laneId: z.string(), roomId: z.string(), agentId: z.string(), label: z.string(), origin: z.enum(["share", "fork"]) })),
      })
      .nullable()
      .optional(),
    owned: z.array(OwnedRoomV2View),
    joining: z.array(JoiningV2View),
    joined: z.array(JoinedRoomV2View),
    /** R3.7: routed lane hosts this daemon could not remove yet (ids and labels only). */
    staleHosts: z.array(StaleHostV2View).optional(),
    /** This daemon's member device in each room's MLS group (I-13): counts and states only, no content. */
    mls: z.array(MlsV2View),
    /** Only on an e2e test home with the test clock switch. */
    testClockOffsetMs: z.number().int().optional(),
  }),
});

/**
 * Creates a room (identity-model 5.4). `recovery: "create"` returns the recovery code once; the UI
 * preselects it. The RPC default stays "skip": a code returned to a caller that does not show it would
 * be a recovery key nobody holds, and a room with a recovery key cannot add a first one later.
 */
export const roomsV2RoomCreate = defineRpc({
  name: "rooms.v2.room.create",
  input: z.object({ recovery: z.enum(["create", "skip"]).optional() }),
  output: z.object({ roomId: z.string(), serverId: z.string(), recovery: RecoveryOfferV2.nullable(), recoverySkippedWarning: z.string().nullable() }),
});

// ------------------------------------------------------------------------------ owner

/** Creates an invite. Returns the `prc2.` code once; it is a bearer secret until used or expired. */
export const roomsV2InviteCreate = defineRpc({
  name: "rooms.v2.invite.create",
  input: InviteCreateIn.extend(Confirmed),
  output: z.object({ code: z.string(), inviteId: z.string(), inviteRef: z.string(), exp: z.number().int() }),
});

export const roomsV2InviteRevoke = defineRpc({
  name: "rooms.v2.invite.revoke",
  input: RoomIdIn.extend({ inviteId: z.string().regex(/^inv_[0-9a-f]{32}$/) }),
  output: Ok,
});

/** Admit: the owner heard the same six digits from the person (6.3). */
export const roomsV2JoinAdmit = defineRpc({
  name: "rooms.v2.join.admit",
  input: PendingIdIn.extend(Confirmed),
  output: z.object({ state: z.string() }),
});

/** "Codes do not match" (burns the invite) or Cancel (an abandoned attempt). */
export const roomsV2JoinReject = defineRpc({
  name: "rooms.v2.join.reject",
  input: PendingIdIn.extend({ reason: z.enum(["sas_mismatch", "cancel"]) }),
  output: Ok,
});

export const roomsV2MemberRemove = defineRpc({
  name: "rooms.v2.member.remove",
  /** `compromise`: "Do you suspect this person of misusing access?" (keys 4.7: rotates their lanes). */
  input: MemberRemoveIn.extend(Confirmed),
  output: z.object({ seq: z.number().int(), rotatedLanes: z.array(z.string()) }),
});

/** Lowers or changes a member's role: their grants at the old role stop working at once (S-9). */
export const roomsV2MemberRole = defineRpc({
  name: "rooms.v2.member.role",
  input: MemberRoleIn.extend(Confirmed),
  output: z.object({ seq: z.number().int() }),
});

/** Creates a lane that shares an existing agent of this daemon (no new agent). */
export const roomsV2LaneCreate = defineRpc({
  name: "rooms.v2.lane.create",
  input: LaneCreateIn.extend(Confirmed),
  output: z.object({ laneId: z.string(), serverId: z.string() }),
});

/** Owner only: the full text of errors viewers saw as generic text with a reference (grants-v2 13.1). */
export const roomsV2LaneErrors = defineRpc({
  name: "rooms.v2.lane.errors",
  input: RoomIdIn.extend({ laneId: z.string().regex(/^lane_[0-9a-f]{32}$/) }),
  output: z.object({
    errors: z.array(z.object({ source: z.string(), message: z.string(), firstAt: z.string(), lastAt: z.string(), count: z.number().int(), ref: z.string().optional() })),
  }),
});

// ------------------------------------------------------------------------------ member

/** Section 2.3: decode and check an invite; nothing is stored or connected. */
export const roomsV2JoinPreview = defineRpc({
  name: "rooms.v2.join.preview",
  input: z.object({ code: z.string().min(1).max(4096) }),
  output: z.object({
    roomId: z.string(),
    roomName: z.string(),
    endpointFingerprint: z.string(),
    relay: z.object({ host: z.string(), port: z.number().int(), trusted: z.boolean() }),
    exp: z.number().int(),
    unverified: z.literal(true),
  }),
});

/** "Join": `trustRelay` is the user's explicit "Trust this relay" for a relay not yet trusted. */
export const roomsV2JoinStart = defineRpc({
  name: "rooms.v2.join.start",
  input: z.object({ code: z.string().min(1).max(4096), label: z.string().min(1).max(80), trustRelay: z.boolean().optional() }),
  output: z.object({ roomId: z.string() }),
});

/** "Codes match" (match true) or "Codes do not match". */
export const roomsV2JoinConfirm = defineRpc({
  name: "rooms.v2.join.confirm",
  input: RoomIdIn.extend({ match: z.boolean() }),
  output: JoiningV2View,
});

export const roomsV2JoinCancel = defineRpc({
  name: "rooms.v2.join.cancel",
  input: RoomIdIn,
  output: Ok,
});

export const roomsV2JoinDismiss = defineRpc({
  name: "rooms.v2.join.dismiss",
  input: RoomIdIn,
  output: Ok,
});

/** Member daemon: open (or reopen) the room session and sync the log. */
export const roomsV2RoomConnect = defineRpc({
  name: "rooms.v2.room.connect",
  input: RoomIdIn,
  output: z.object({ status: JoinedRoomV2View.shape.status, lastError: z.string().nullable() }),
});

/**
 * R3.1: leave a joined room. The member's only active device signs `member.left`; with other active
 * devices, this device signs `device.removed {reason: "self"}` and the membership stays with them
 * (identity-model 6.2, room-log-v2 4.3). A room whose access already ended is forgotten locally
 * (`statement: null`). Then the lane hosts are removed and this device's keys and data for the room
 * are deleted. `confirm` is the word the person typed (not an admin action: no confirmToken).
 */
export const roomsV2RoomLeave = defineRpc({
  name: "rooms.v2.room.leave",
  input: RoomIdIn.extend({ confirm: z.literal("leave") }),
  output: z.object({
    statement: z.enum(["member.left", "device.removed"]).nullable(),
    seq: z.number().int().nullable(),
    hostsRemoved: z.number().int(),
    hostsRemaining: z.array(StaleHostV2View),
  }),
});

export const roomsV2RoomDisconnect = defineRpc({
  name: "rooms.v2.room.disconnect",
  input: RoomIdIn,
  output: Ok,
});

// ------------------------------------------------------------------------------ device links (I-11)

/** On a member device: "Link another device". Returns the `prl2.` code once (bearer secret, 10 minutes). */
export const roomsV2LinkCreate = defineRpc({
  name: "rooms.v2.link.create",
  input: RoomIdIn.extend({ roomName: z.string().min(1).max(80).optional() }),
  output: z.object({ code: z.string(), linkId: z.string(), exp: z.number().int() }),
});

/** On the linking device: "Codes match" (match true) or "Codes do not match" (burns the link). */
export const roomsV2LinkConfirm = defineRpc({
  name: "rooms.v2.link.confirm",
  input: PendingIdIn.extend({ match: z.boolean() }),
  output: Ok,
});

/** "Not me" on any active device of the member: vetoes a held add (opens a device conflict). */
export const roomsV2DeviceVeto = defineRpc({
  name: "rooms.v2.device.veto",
  input: RefIn,
  output: z.object({ seq: z.number().int() }),
});

/** Admin: interactive approval of a held device add (required when policy or a rule keeps it for an admin). */
export const roomsV2DeviceApprove = defineRpc({
  name: "rooms.v2.device.approve",
  input: RefIn.extend(Confirmed),
  output: z.object({ seq: z.number().int() }),
});

/** Admin: clears a member's device conflict. */
export const roomsV2ConflictResolve = defineRpc({
  name: "rooms.v2.device.conflict.resolve",
  input: ConflictIn.extend(Confirmed),
  output: z.object({ seq: z.number().int() }),
});

// ------------------------------------------------------------------------------ chat (R3.4, product M2)

/**
 * Sends a chat message in the room group (mls-integration 5.2): plain text, signed by this device's key,
 * encrypted for the room's current members. The host stores only ciphertext.
 */
export const roomsV2ChatSend = defineRpc({
  name: "rooms.v2.chat.send",
  input: RoomIdIn.extend({ text: z.string().min(1).max(4000) }),
  output: z.object({ seq: z.number().int() }),
});

/**
 * One chat message as this device stored it. `verified`: the signature and its binding to the group,
 * epoch and sending leaf checked out on receipt (`own` for this device's messages). `current`: the
 * sending device is still in the verified roster. `hts`: host time of the entry; `ts`: the sender's clock.
 * `text` is untrusted plain text: never render it as markup.
 */
export const ChatMessageV2View = z.object({
  seq: z.number().int(),
  hts: z.number().int(),
  ts: z.number().int(),
  memberId: z.string(),
  deviceId: z.string(),
  text: z.string(),
  own: z.boolean(),
  verified: z.enum(["verified", "own"]),
  current: z.boolean(),
});

/** Newest `limit` messages before `before` (a log position), oldest first; names of their senders (R3.3). */
export const roomsV2ChatList = defineRpc({
  name: "rooms.v2.chat.list",
  input: RoomIdIn.extend({ before: z.number().int().min(0).optional(), limit: z.number().int().min(1).max(200).optional() }),
  output: z.object({
    messages: z.array(ChatMessageV2View),
    more: z.boolean(),
    readSeq: z.number().int(),
    unread: z.number().int(),
    selfMemberId: z.string().nullable(),
    names: z.array(MemberNameV2View),
    /** Why this device cannot send now (`no_group`, `unconfirmed`, `blocked`, `ended`, ...), or null. */
    cannotSend: z.string().nullable(),
  }),
});

/** Moves the read marker forward to `seq` (this device only). */
export const roomsV2ChatRead = defineRpc({
  name: "rooms.v2.chat.read",
  input: RoomIdIn.extend({ seq: z.number().int().min(0) }),
  output: z.object({ unread: z.number().int() }),
});

/** Unread chat messages per room on this device, for the sidebar row (cheap; no text). */
export const roomsV2ChatUnread = defineRpc({
  name: "rooms.v2.chat.unread",
  input: Empty,
  output: z.object({ total: z.number().int(), rooms: z.array(z.object({ roomId: z.string(), unread: z.number().int() })) }),
});

/** TEST-ONLY: registered only on e2e test homes (server/platform/test-clock.ts). */
export const roomsV2TestClockAdvance = defineRpc({
  name: "rooms.v2.test.clock.advance",
  input: z.object({ ms: z.number().int().min(1).max(7 * 24 * 60 * 60 * 1000) }),
  output: z.object({ offsetMs: z.number().int() }),
});

// ------------------------------------------------------------------------------ rotation and recovery (I-12)

/** Member device: requests its own rekey (keys-rotation-recovery 4.1). Held 24 h (72 h for a sole device). */
export const roomsV2DeviceRekey = defineRpc({
  name: "rooms.v2.device.rekey",
  input: RoomIdIn,
  output: z.object({ ref: z.string(), seq: z.number().int() }),
});

/** Admin: removes one device; `compromise` rotates the member's lanes (keys 4.7, 6.3). */
export const roomsV2DeviceRemove = defineRpc({
  name: "rooms.v2.device.remove",
  input: DeviceRemoveIn.extend(Confirmed),
  output: z.object({ seq: z.number().int(), rotatedLanes: z.array(z.string()) }),
});

/** Admin: rotates the host key (keys 4.5); grants from the old key stay valid for 24 h. */
export const roomsV2HostKeyRotate = defineRpc({ name: "rooms.v2.host.key.rotate", input: RoomIdIn.extend(Confirmed), output: Seq.extend({ kid: z.string() }) });

/** Admin: revokes a host key already rotated out, from `fromSeq` (keys 4.5 step 6, 6.4). */
export const roomsV2HostKeyRevoke = defineRpc({ name: "rooms.v2.host.key.revoke", input: KeyRevokeIn.extend(Confirmed), output: Seq });

/** Admin: rotates this daemon's admin key (keys 4.3). */
export const roomsV2AdminKeyRotate = defineRpc({ name: "rooms.v2.admin.key.rotate", input: RoomIdIn.extend(Confirmed), output: Seq.extend({ kid: z.string() }) });

/** Admin: revokes another admin key from `fromSeq` (keys 6.6). */
export const roomsV2AdminKeyRevoke = defineRpc({ name: "rooms.v2.admin.key.revoke", input: KeyRevokeIn.extend(Confirmed), output: Seq });

/** Admin: rotates the room endpoint (keys 4.6); the old one answers `moved` for 30 days. */
export const roomsV2EndpointRotate = defineRpc({ name: "rooms.v2.endpoint.rotate", input: RoomIdIn.extend(Confirmed), output: Seq.extend({ serverId: z.string() }) });

/** Admin: rotates a lane offer (keys 4.7). */
export const roomsV2LaneRotate = defineRpc({ name: "rooms.v2.lane.rotate", input: LaneRotateIn.extend(Confirmed), output: Seq.extend({ serverId: z.string() }) });

/** Admin: closes a lane (R3.2, `lane.closed`): its endpoint stops, its grants stop working; final. */
export const roomsV2LaneClose = defineRpc({ name: "rooms.v2.lane.close", input: LaneRotateIn.extend(Confirmed), output: Seq });

// ------------------------------------------------------------------------------ data hygiene (R2.6, R3.7)

/** R3.7: retries removing the routed lane hosts this daemon could not remove before. */
export const roomsV2HostsCleanup = defineRpc({
  name: "rooms.v2.hosts.cleanup",
  input: Empty,
  output: z.object({ removed: z.number().int(), remaining: z.array(StaleHostV2View) }),
});

/**
 * R2.6 "Leave all rooms and delete keys": leaves every joined room (forgets those it cannot reach),
 * removes this plugin's lane hosts, deletes the KEK (keyring entry or fallback file) and the whole
 * plugin-data/rooms folder. Rooms this daemon hosts stop for good and need `deleteHosted: true`;
 * each is first closed with `room.closed` where this daemon may (keys 6.8; `hostedClosed`). Afterwards Rooms stays stopped (`data_deleted`) until the daemon restarts. `confirm` is the typed word.
 */
export const roomsV2DataDelete = defineRpc({
  name: "rooms.v2.data.delete",
  input: z.object({ confirm: z.literal("delete"), deleteHosted: z.boolean().optional() }),
  output: z.object({
    left: z.array(z.object({ roomId: z.string(), statement: z.enum(["member.left", "device.removed"]).nullable(), error: z.string().nullable() })),
    hostedDeleted: z.array(z.string()),
    /** What was done about closing each hosted room before it was deleted (keys 6.8). */
    hostedClosed: z.array(
      z.object({
        roomId: z.string(),
        outcome: z.enum(["closed", "already_closed", "not_closed"]),
        via: z.enum(["recovery_key", "confirmed_proposal"]).nullable(),
        seq: z.number().int().nullable(),
        reason: z.enum(["recovery_code_required", "second_admin_required", "no_admin_key", "error"]).nullable(),
        message: z.string(),
      }),
    ),
    hostsRemoved: z.number().int(),
    hostsRemaining: z.array(StaleHostV2View),
    keystore: z.object({ backend: z.string().nullable(), kek: z.enum(["deleted", "absent", "kept", "failed"]), message: z.string().nullable() }),
    dataDeleted: z.boolean(),
  }),
});

/** Admin: proposes closing the room (keys 6.8). */
export const roomsV2CloseProposed = defineRpc({ name: "rooms.v2.room.close.propose", input: RoomIdIn.extend(Confirmed), output: Seq.extend({ proposal: z.string(), earliest: z.number().int() }) });

/** Admin of another lineage: confirms a closure; refused before `closeDelay` on this daemon's clock. */
export const roomsV2CloseConfirm = defineRpc({ name: "rooms.v2.room.close.confirm", input: ProposalIn.extend(Confirmed), output: Seq });

/** Admin: a first recovery key (keys 4.4). The code is a secret, returned once and never stored. */
export const roomsV2RecoveryCreate = defineRpc({
  name: "rooms.v2.recovery.create",
  input: RoomIdIn.extend(Confirmed),
  output: Seq.extend({ proposal: z.string().nullable(), recovery: RecoveryOfferV2 }),
});

/** Admin of another lineage: confirms a recovery key proposal (keys 4.4). */
export const roomsV2RecoveryConfirm = defineRpc({ name: "rooms.v2.recovery.confirm", input: ProposalIn.extend(Confirmed), output: Seq });

/** A recovery procedure signed by the recovery key (keys 6.6, 6.8, 4.4); the code is used once and not stored. */
export const roomsV2RecoveryAct = defineRpc({
  name: "rooms.v2.recovery.act",
  input: RoomIdIn.extend({
    code: z.string().min(1).max(200),
    action: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("revoke_admin"), kid: Kid, fromSeq: z.number().int().min(0) }),
      z.object({ kind: z.literal("close") }),
      z.object({ kind: z.literal("rotate") }),
    ]),
  }),
  /** `recovery`: the new recovery code of a `rotate`, offered once like at creation. */
  output: Seq.extend({ freshAdminKid: z.string().optional(), recovery: RecoveryOfferV2.optional() }),
});

/**
 * R3.3: sets the room name (an admin of the room) or this member's display name. Both travel only
 * inside the room's MLS group (room.profile, member.profile): the host never sees them. Display-only,
 * untrusted text; sanitized on both sides. Not admin statements, so no confirmation token.
 */
export const roomsV2RoomProfileSet = defineRpc({
  name: "rooms.v2.room.profile.set",
  input: RoomIdIn.extend({ name: z.string().min(1).max(200), description: z.string().max(1000).optional() }),
  output: Seq,
});

export const roomsV2MemberProfileSet = defineRpc({
  name: "rooms.v2.member.profile.set",
  input: RoomIdIn.extend({ displayName: z.string().min(1).max(200) }),
  output: Seq,
});

/**
 * R3.5: acknowledges alerts on this device (their notice is hidden; the activity feed keeps them). It
 * changes nothing an alert stopped: sending stays stopped after a fork, truncation or invalid entry.
 */
export const roomsV2AlertsAck = defineRpc({
  name: "rooms.v2.alerts.ack",
  input: RoomIdIn.extend({ alerts: z.array(z.object({ type: z.string().regex(/^[a-z][a-z_.-]{0,39}$/), seq: z.number().int() })).min(1).max(64) }),
  output: Ok.extend({ acked: z.number().int() }),
});
