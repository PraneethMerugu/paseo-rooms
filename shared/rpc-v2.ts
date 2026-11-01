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
// approve held adds and resolve conflicts. `rooms.v2.mls.*` (I-13) send and read room group messages
// for development; the chat UI is product milestone M2. `rooms.v2.test.clock.advance` is TEST-ONLY and registered
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

/** One roster entry as the owner's member list shows it. `label`: self-reported at enrollment, if known here. */
export const RosterMemberV2View = z.object({
  memberId: z.string(),
  role: z.string(),
  lanes: z.array(z.string()),
  label: z.string().nullable(),
  /** This daemon's own member entry (the creator). */
  self: z.boolean(),
  devices: z.array(z.object({ deviceId: z.string(), kind: z.enum(["person", "gateway"]), since: z.number().int().nullable(), connected: z.boolean() })),
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
});

/** The member's side of a join (enrollment-v2.md 6.4, 7.3). */
export const JoiningV2View = z.object({
  roomId: z.string(),
  state: z.enum(["keys", "pending", "confirmed", "held", "admitted", "registered", "failed"]),
  roomName: z.string(),
  sas: z.string().nullable(),
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
  alerts: z.array(z.object({ type: z.string(), seq: z.number().int() })),
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
  messages: z.number().int(),
  alerts: z.array(z.object({ type: z.string(), seq: z.number().int() })),
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

// ------------------------------------------------------------------------------ MLS (I-13)

/** Development only: sends a `chat.message` in the room group (the chat UI is product milestone M2). */
export const roomsV2MlsSend = defineRpc({
  name: "rooms.v2.mls.send",
  input: RoomIdIn.extend({ text: z.string().min(1).max(4000) }),
  output: z.object({ seq: z.number().int() }),
});

/** Development only: the messages this device decrypted in the room group since the daemon started. */
export const roomsV2MlsMessages = defineRpc({
  name: "rooms.v2.mls.messages",
  input: RoomIdIn,
  output: z.object({
    messages: z.array(z.object({ seq: z.number().int(), epoch: z.number().int(), from: z.object({ memberId: z.string(), deviceId: z.string() }).nullable(), text: z.string() })),
  }),
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
