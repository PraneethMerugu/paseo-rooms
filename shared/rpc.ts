// Plugin RPC contracts. Owner-side (gateway/host) and member-side calls share one plugin.
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";
import { InviteId, Lane, LaneId, LIMITS, Member, MemberId, Room, RoomEvent, RoomId, RoomSettings } from "./schemas";

const Empty = z.object({});
const Ok = z.object({ ok: z.literal(true) });

export const LaneOriginKind = z.enum(["fork", "share"]);

export const LaneView = z.object({
  lane: Lane,
  agentTitle: z.string().nullable(),
  /** Member links currently open on the lane endpoint. */
  connectedMembers: z.number().int().min(0),
  activeRoutes: z.number().int().min(0),
  endpoint: z.enum(["starting", "online", "offline", "closed"]),
});
export type LaneView = z.infer<typeof LaneView>;

export const InviteView = z.object({
  id: InviteId,
  laneId: LaneId,
  createdAt: z.string(),
  expiresAt: z.string(),
  grantTtlSeconds: z.number().int(),
  status: z.enum(["open", "used", "expired", "revoked", "burned"]),
});

export const MemberView = Member.omit({ devicePublicKey: true }).extend({
  connected: z.boolean(),
  grantExpiresAt: z.string().nullable(),
});
export type MemberView = z.infer<typeof MemberView>;

export const OwnedRoomView = z.object({
  room: Room,
  settings: RoomSettings,
  lanes: z.array(LaneView),
  members: z.array(MemberView),
  invites: z.array(InviteView),
});
export type OwnedRoomView = z.infer<typeof OwnedRoomView>;

export const JoinedRoomView = z.object({
  roomId: RoomId,
  roomName: z.string(),
  laneId: LaneId,
  laneLabel: z.string(),
  memberId: MemberId,
  joinedAt: z.string(),
  status: z.enum(["active", "revoked", "left", "error"]),
  hostStatus: z.string().nullable(),
  hostError: z.string().nullable(),
  laneServerId: z.string(),
  grantExpiresAt: z.string().nullable(),
  lastRotationAt: z.string().nullable(),
});
export type JoinedRoomView = z.infer<typeof JoinedRoomView>;

export const roomsBootstrap = defineRpc({
  name: "rooms.bootstrap",
  input: Empty,
  output: z.object({ ok: z.literal(true), version: z.string(), dataDir: z.literal("plugin-data/rooms") }),
});

export const roomsOverview = defineRpc({
  name: "rooms.overview",
  input: Empty,
  output: z.object({ owned: z.array(OwnedRoomView), joined: z.array(JoinedRoomView) }),
});

export const roomsCreate = defineRpc({
  name: "rooms.create",
  input: z.object({
    name: z.string().trim().min(1).max(80),
    agentId: z.string().min(1),
    origin: LaneOriginKind.default("fork"),
    laneLabel: z.string().trim().min(1).max(80).optional(),
    /** fork only: first instruction appended after the curated context. */
    instruction: z.string().trim().max(4000).optional(),
  }),
  output: z.object({ room: Room, lane: Lane }),
});

export const roomsLaneCreate = defineRpc({
  name: "rooms.lane.create",
  input: z.object({
    roomId: RoomId,
    agentId: z.string().min(1),
    origin: LaneOriginKind.default("fork"),
    laneLabel: z.string().trim().min(1).max(80).optional(),
    instruction: z.string().trim().max(4000).optional(),
  }),
  output: z.object({ lane: Lane }),
});

export const roomsLaneClose = defineRpc({
  name: "rooms.lane.close",
  input: z.object({ laneId: LaneId }),
  output: Ok,
});

export const roomsInviteCreate = defineRpc({
  name: "rooms.invite.create",
  input: z.object({
    laneId: LaneId,
    ttlSeconds: z
      .number()
      .int()
      .min(LIMITS.inviteTtlSeconds.min)
      .max(LIMITS.inviteTtlSeconds.max)
      .default(LIMITS.inviteTtlSeconds.default),
    grantTtlSeconds: z
      .number()
      .int()
      .min(LIMITS.grantTtlSeconds.min)
      .max(LIMITS.grantTtlSeconds.max)
      .default(LIMITS.grantTtlSeconds.default),
  }),
  /** `code` is a one-time secret. Show it once; never log it. */
  output: z.object({ inviteId: InviteId, code: z.string(), expiresAt: z.string() }),
});

export const roomsInviteRevoke = defineRpc({
  name: "rooms.invite.revoke",
  input: z.object({ inviteId: InviteId }),
  output: Ok,
});

export const roomsMemberRevoke = defineRpc({
  name: "rooms.member.revoke",
  input: z.object({ memberId: MemberId }),
  output: z.object({ ok: z.literal(true), cutLinks: z.number().int(), cutRoutes: z.number().int() }),
});

export const roomsLog = defineRpc({
  name: "rooms.log",
  input: z.object({ roomId: RoomId }),
  output: z.object({ events: z.array(RoomEvent), verified: z.boolean(), error: z.string().nullable() }),
});

/** Owner-only: set whether members see the shared agent's project name (recorded as room.policy.changed). */
export const roomsSettingsSet = defineRpc({
  name: "rooms.settings.set",
  input: z.object({ roomId: RoomId, showProjectName: z.boolean() }),
  output: z.object({ settings: RoomSettings }),
});

export const LaneErrorView = z.object({
  source: z.string(),
  message: z.string(),
  firstAt: z.string(),
  lastAt: z.string(),
  count: z.number().int().min(1),
});
export type LaneErrorView = z.infer<typeof LaneErrorView>;

/**
 * Owner-only: full text of the errors this lane's viewers received as generic text, newest first.
 * Served by the owner's own daemon to the owner's app; members cannot reach plugin RPCs through a
 * lane (plugin.rpc.invoke.request is denied by the Room Profile).
 */
export const roomsLaneErrors = defineRpc({
  name: "rooms.lane.errors",
  input: z.object({ laneId: LaneId }),
  output: z.object({ errors: z.array(LaneErrorView) }),
});

export const LaneAgentView = z.object({
  agentId: z.string(),
  laneId: LaneId,
  roomId: RoomId,
  roomName: z.string(),
  connectedMembers: z.number().int().min(0),
});

export const roomsLaneAgents = defineRpc({
  name: "rooms.lane.agents",
  input: Empty,
  output: z.object({ lanes: z.array(LaneAgentView) }),
});

// ---- member role ----

export const roomsJoin = defineRpc({
  name: "rooms.join",
  /** `code` is the invite code (secret). */
  input: z.object({ code: z.string().trim().min(20).max(4000), label: z.string().trim().min(1).max(80).optional() }),
  output: z.object({ joined: JoinedRoomView }),
});

export const roomsLeave = defineRpc({
  name: "rooms.leave",
  input: z.object({ laneId: LaneId }),
  output: Ok,
});

export const roomsRotate = defineRpc({
  name: "rooms.rotate",
  input: z.object({ laneId: LaneId, force: z.boolean().default(false) }),
  output: z.object({ rotated: z.boolean(), reason: z.string(), grantExpiresAt: z.string().nullable() }),
});
