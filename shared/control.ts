// Rooms control protocol v1 frames (docs/specs/rooms-control-protocol.md).
// Carried inside a protected (Noise NK) relay channel to a lane endpoint, one operation per channel.
import { z } from "zod";
import { Ed25519PublicKey, GrantClaims, KeyId, LaneId, LaneServerId, Member, RoomId } from "./schemas";

export const CONTROL_VERSION = 1 as const;
export const CONTROL_SIGNATURE_CONTEXT = "paseo-rooms/control/v1";
export const ControlOp = z.enum(["enroll", "renew", "status", "leave"]);
export type ControlOp = z.infer<typeof ControlOp>;

/** C -> G. First frame on the channel; selects the rooms control protocol instead of a Paseo hello. */
export const ControlHello = z.object({
  type: z.literal("rooms.control.hello"),
  v: z.literal(CONTROL_VERSION),
  op: ControlOp,
  laneId: LaneId,
  devicePublicKey: Ed25519PublicKey,
});

/** G -> C. Fresh nonce the member must sign. */
export const ControlChallenge = z.object({
  type: z.literal("rooms.control.challenge"),
  v: z.literal(CONTROL_VERSION),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  laneServerId: LaneServerId,
  hostKeyId: KeyId,
});

/** C -> G. Device key signature over the canonical transcript (see signedTranscript in the spec). */
export const ControlProof = z.object({
  type: z.literal("rooms.control.proof"),
  v: z.literal(CONTROL_VERSION),
  sig: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  /** enroll only: the one-time token from the invite code. */
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
  /** enroll only. */
  label: z.string().min(1).max(80).optional(),
  daemonServerId: z.string().max(128).nullable().optional(),
});

export const ControlRoomInfo = z.object({
  roomId: RoomId,
  roomName: z.string(),
  laneId: LaneId,
  laneLabel: z.string(),
});

/** G -> C. */
export const ControlResult = z.object({
  type: z.literal("rooms.control.result"),
  v: z.literal(CONTROL_VERSION),
  op: ControlOp,
  room: ControlRoomInfo,
  member: Member.pick({ id: true, label: true, role: true, status: true }),
  /** enroll / renew: the new grant (bearer secret, store only in the daemon's hosts.json). */
  grant: z.string().optional(),
  claims: GrantClaims.optional(),
  /** Live routed sessions this member currently has open on the lane. */
  activeRoutes: z.number().int().min(0),
});

export const ControlErrorCode = z.enum([
  "bad_frame",
  "unsupported_version",
  "unknown_lane",
  "lane_closed",
  "bad_signature",
  "invalid_token",
  "token_expired",
  "token_used",
  "not_member",
  "revoked",
  "busy",
  "internal",
]);
export type ControlErrorCode = z.infer<typeof ControlErrorCode>;

export const ControlError = z.object({
  type: z.literal("rooms.control.error"),
  v: z.literal(CONTROL_VERSION),
  code: ControlErrorCode,
  message: z.string().max(200),
});

export const ControlFromMember = z.discriminatedUnion("type", [ControlHello, ControlProof]);
export const ControlFromGateway = z.discriminatedUnion("type", [ControlChallenge, ControlResult, ControlError]);

/** Fields signed by the device key, serialized with canonicalJson (sorted keys, no whitespace). */
export interface ControlTranscript {
  ctx: typeof CONTROL_SIGNATURE_CONTEXT;
  op: ControlOp;
  laneId: string;
  laneServerId: string;
  hostKeyId: string;
  nonce: string;
  devicePublicKey: string;
  /** enroll only: hex sha256 of the token; null otherwise. */
  tokenHash: string | null;
  daemonServerId: string | null;
  label: string | null;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}
