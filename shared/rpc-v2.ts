// Plugin RPC contracts of the identity v2 development runtime (PASEO_ROOMS_PROTOCOL=v2, decision D-2).
// Registered only when the switch is set; they never ship. Enrollment (I-9): the owner creates invites
// and admits join requests after the SAS comparison; the member previews, joins, compares and
// confirms. Admin calls are the confirmation of what they sign (the UI flow is I-14). An invite code
// is a bearer secret: it is returned once to the caller and never logged.
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

const Empty = z.object({});
const Ok = z.object({ ok: z.literal(true) });
const RoomIdIn = z.object({ roomId: z.string().regex(/^room_[0-9a-f]{32}$/) });
const Head = z.object({ seq: z.number().int(), hash: z.string() });

const PendingIdIn = RoomIdIn.extend({ pendingId: z.string().regex(/^pen_[0-9a-f]{32}$/) });

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
  note: z.string(),
  label: z.string(),
  state: z.enum(["created", "sas_shown", "member_ok", "admin_ok", "admitted", "closed"]),
  sas: z.string().nullable(),
  abandonedBefore: z.number().int(),
  contested: z.boolean(),
  expiresAt: z.number().int(),
  closedReason: z.string().nullable(),
  memberId: z.string().nullable(),
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

export const OwnedRoomV2View = z.object({
  roomId: z.string(),
  serverId: z.string(),
  head: Head,
  endpoint: z.enum(["starting", "online", "offline", "closed"]),
  sessions: z.array(z.object({ memberId: z.string(), deviceId: z.string() })),
  members: z.number().int(),
  invites: z.array(InviteV2View),
  joinRequests: z.array(JoinRequestV2View),
  lanes: z.array(LaneV2View),
  grants: z.array(GrantV2View),
  grantTtlS: z.number().int(),
  /** grants-v2 7.2: access was cut but a save failed; retried every 10 s. */
  persistError: z.string().nullable(),
  /** grants-v2 6.4: devices with two suspected thefts within 7 days. */
  compromisedDevices: z.array(z.string()),
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

export const roomsV2Status = defineRpc({
  name: "rooms.v2.status",
  input: Empty,
  output: z.object({
    protocol: z.literal("v2"),
    state: z.enum(["starting", "ready", "error"]),
    error: z.string().nullable(),
    keystore: z.object({ state: z.string(), backend: z.string().nullable(), fallback: z.boolean() }).nullable(),
    owned: z.array(OwnedRoomV2View),
    joining: z.array(JoiningV2View),
    joined: z.array(JoinedRoomV2View),
  }),
});

export const roomsV2RoomCreate = defineRpc({
  name: "rooms.v2.room.create",
  input: Empty,
  output: z.object({ roomId: z.string(), serverId: z.string() }),
});

// ------------------------------------------------------------------------------ owner

/** Creates an invite. Returns the `prc2.` code once; it is a bearer secret until used or expired. */
export const roomsV2InviteCreate = defineRpc({
  name: "rooms.v2.invite.create",
  input: RoomIdIn.extend({
    role: z.enum(["guest", "watch", "comment", "steer", "approve", "maintain", "admin"]).optional(),
    lanes: z.array(z.string().regex(/^lane_[0-9a-f]{32}$/)).max(64).optional(),
    expS: z.number().int().min(300).max(86400).optional(),
    note: z.string().max(80).optional(),
    roomName: z.string().min(1).max(80).optional(),
  }),
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
  input: PendingIdIn,
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
  input: RoomIdIn.extend({ memberId: z.string() }),
  output: z.object({ seq: z.number().int() }),
});

/** Lowers or changes a member's role: their grants at the old role stop working at once (S-9). */
export const roomsV2MemberRole = defineRpc({
  name: "rooms.v2.member.role",
  input: RoomIdIn.extend({ memberId: z.string(), role: z.enum(["guest", "watch", "comment", "steer", "approve", "maintain", "admin"]) }),
  output: z.object({ seq: z.number().int() }),
});

/** Creates a lane that shares an existing agent of this daemon (no new agent). */
export const roomsV2LaneCreate = defineRpc({
  name: "rooms.v2.lane.create",
  input: RoomIdIn.extend({ agentId: z.string().min(1).max(200), label: z.string().min(1).max(80).optional() }),
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
