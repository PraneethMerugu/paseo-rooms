// Versioned data schemas for Paseo Rooms (Milestone 1).
// Shared by the daemon (server/) and the app (client/). Plain zod only: no Node, no React.
import { z } from "zod";

export const SCHEMA_VERSION = 1 as const;

export const RoomId = z.string().regex(/^room_[a-f0-9]{16}$/);
export const LaneId = z.string().regex(/^lane_[a-f0-9]{16}$/);
export const MemberId = z.string().regex(/^mem_[a-f0-9]{16}$/);
export const InviteId = z.string().regex(/^inv_[a-f0-9]{16}$/);
export const GrantId = z.string().regex(/^g_[a-f0-9]{16}$/);
/** Lane relay serverId: 24 random bytes, base64url, prefixed. */
export const LaneServerId = z.string().regex(/^lane_[A-Za-z0-9_-]{32}$/);
/** Raw 32-byte Ed25519 public key, base64url. */
export const Ed25519PublicKey = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
/** Key id: first 16 hex chars of sha256(raw public key). */
export const KeyId = z.string().regex(/^[a-f0-9]{16}$/);

/** M1 implements only "watch". The other roles are reserved by rooms-architecture.md section 4. */
export const RoomRole = z.enum(["watch"]);
export type RoomRole = z.infer<typeof RoomRole>;
/** Full role ladder used by the classification table (section 4). */
export const ROLE_LADDER = ["guest", "watch", "comment", "steer", "approve", "maintain", "admin"] as const;
export type LadderRole = (typeof ROLE_LADDER)[number];

export const RelayEndpoint = z.object({
  endpoint: z.string().min(3).max(255),
  useTls: z.boolean(),
});

/** Owner-side room settings (gateway state only; never part of an invite, grant or member view). */
export const RoomSettings = z.object({
  /** Forward the shared agent's project display names and folder names to members. Default false. */
  showProjectName: z.boolean(),
});
export type RoomSettings = z.infer<typeof RoomSettings>;
export const DEFAULT_ROOM_SETTINGS: RoomSettings = { showProjectName: false };

export const Room = z.object({
  v: z.literal(SCHEMA_VERSION),
  id: RoomId,
  name: z.string().min(1).max(80),
  createdAt: z.string(),
  status: z.enum(["active", "archived"]),
});
export type Room = z.infer<typeof Room>;

export const LaneOrigin = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("share"), agentId: z.string().min(1) }),
  z.object({
    kind: z.literal("fork"),
    parentAgentId: z.string().min(1),
    contextItems: z.number().int().min(0),
    contextChars: z.number().int().min(0),
  }),
]);
export type LaneOrigin = z.infer<typeof LaneOrigin>;

export const Lane = z.object({
  v: z.literal(SCHEMA_VERSION),
  id: LaneId,
  roomId: RoomId,
  label: z.string().min(1).max(80),
  origin: LaneOrigin,
  agentId: z.string().min(1),
  workspaceId: z.string().min(1),
  /** Relay identity of the lane endpoint (public). */
  serverId: LaneServerId,
  publicKeyB64: z.string().min(40).max(64),
  relay: RelayEndpoint,
  createdAt: z.string(),
  status: z.enum(["open", "closed"]),
});
export type Lane = z.infer<typeof Lane>;

export const Member = z.object({
  v: z.literal(SCHEMA_VERSION),
  id: MemberId,
  roomId: RoomId,
  laneId: LaneId,
  label: z.string().min(1).max(80),
  /** The member daemon's device key (Ed25519). One per member daemon in M1. */
  devicePublicKey: Ed25519PublicKey,
  deviceKeyId: KeyId,
  /** Member daemon serverId as reported by the member plugin (informational). */
  daemonServerId: z.string().max(128).nullable(),
  role: RoomRole,
  /** Lifetime of each grant issued to this member, fixed by the invite. */
  grantTtlSeconds: z.number().int().positive(),
  joinedAt: z.string(),
  status: z.enum(["active", "revoked", "left"]),
  endedAt: z.string().nullable(),
});
export type Member = z.infer<typeof Member>;

/** Claims of a lane-scoped grant. The token is `prg1.<b64url claims>.<b64url Ed25519 sig>`. */
export const GrantClaims = z.object({
  v: z.literal(SCHEMA_VERSION),
  typ: z.literal("rooms.lane-grant"),
  /** Issuer: host key id (embedded host in M1). */
  iss: KeyId,
  roomId: RoomId,
  laneId: LaneId,
  /** Audience: the lane endpoint serverId. */
  aud: LaneServerId,
  /** Subject: member id. */
  sub: MemberId,
  /** Device key id the grant is bound to (proof of possession at enrollment and renewal). */
  dev: KeyId,
  role: RoomRole,
  gid: GrantId,
  iat: z.number().int(),
  exp: z.number().int(),
});
export type GrantClaims = z.infer<typeof GrantClaims>;

export const ROOM_EVENT_TYPES = [
  "room.created",
  "lane.created",
  "lane.closed",
  "invite.created",
  "invite.revoked",
  "member.joined",
  "member.left",
  "member.revoked",
  "grant.renewed",
  // Owner changed a room setting (data: setting, value). Additive type; the record format is unchanged.
  "room.policy.changed",
] as const;
export const RoomEventType = z.enum(ROOM_EVENT_TYPES);

/** One entry of the append-only, hash-chained, host-signed room log. */
export const RoomEvent = z.object({
  v: z.literal(SCHEMA_VERSION),
  roomId: RoomId,
  seq: z.number().int().min(0),
  ts: z.string(),
  type: RoomEventType,
  /** "owner" for local owner actions, a member id for member actions, "host" for automatic ones. */
  actor: z.string().min(1).max(64),
  data: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
  /** Hex sha256 of the previous event's `hash`, or 64 zeros for seq 0. */
  prev: z.string().regex(/^[a-f0-9]{64}$/),
  /** Hex sha256 over the canonical JSON of every field above. */
  hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Host key id and base64url Ed25519 signature over `hash`. */
  kid: KeyId,
  sig: z.string().min(80).max(90),
});
export type RoomEvent = z.infer<typeof RoomEvent>;

/** Payload of an invite (enrollment) code: `prc1.<base64url JSON>`. Contains a one-time secret. */
export const INVITE_CODE_PREFIX = "prc1.";
export const InvitePayload = z.object({
  v: z.literal(SCHEMA_VERSION),
  roomId: RoomId,
  roomName: z.string().min(1).max(80),
  laneId: LaneId,
  laneLabel: z.string().min(1).max(80),
  /** Lane endpoint offer: where to reach the lane and which Noise static key to pin. */
  offer: z.object({
    serverId: LaneServerId,
    publicKeyB64: z.string().min(40).max(64),
    relay: RelayEndpoint,
  }),
  /** Host key the member pins for grant and log verification. */
  host: z.object({ keyId: KeyId, publicKey: Ed25519PublicKey }),
  inviteId: InviteId,
  /** One-time enrollment token, 32 random bytes base64url. Secret. */
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  /** Unix seconds. */
  exp: z.number().int(),
});
export type InvitePayload = z.infer<typeof InvitePayload>;

export const LIMITS = {
  inviteTtlSeconds: { min: 60, max: 24 * 3600, default: 30 * 60 },
  /** Grants: hours to days (section 8.2). Values below 1 h are for tests only. */
  grantTtlSeconds: { min: 20, max: 7 * 24 * 3600, default: 24 * 3600 },
  maxFailedEnrollmentsPerInvite: 5,
  forkContextMaxItems: 40,
  forkContextMaxChars: 24_000,
} as const;
