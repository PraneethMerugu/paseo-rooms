// Shared zod building blocks for the signed objects of the room log and genesis
// (signatures-and-encoding.md sections 2.3, 4, 5; identity-model.md sections 5.1, 6.1, 8).
// zod's .strict() does not reach nested objects (I-1, signatures Q1), so every object here is a
// z.strictObject, at every nesting level. The schemas only validate: callers keep the parsed RJCS
// value for hashing and verify signatures over the received bytes.
import { z } from "zod";
import { b64uDecode, isB64u } from "../proto/b64u";
import { isId, isRoomId, isServerId, type EntityKind, type ServerIdKind } from "../proto/ids";
import { isValidEd25519PublicKey, kid as kidOf } from "../proto/keys";

export const int = () => z.number().int().min(-(2 ** 53 - 1)).max(2 ** 53 - 1);
export const nonNegInt = () => int().min(0);
/** A log position or `-1` (genesis / never set): `base.seq` and every `ver`. */
export const logPos = () => int().min(-1);

export const b64uBytes = (n: number) => z.string().refine((s) => isB64u(s, n), `expected ${n} bytes of strict base64url`);
/** 32-byte hashes and key ids. */
export const Hash32 = b64uBytes(32);
export const Kid = b64uBytes(32);
export const Sig64 = b64uBytes(64);

/** Ed25519 public key: 32 bytes, a canonical curve point, not of small order. */
export const Ed25519Pub = z.string().refine((s) => isB64u(s, 32) && isValidEd25519PublicKey(b64uDecode(s, 32)), "invalid Ed25519 public key");
/** X25519 public key: 32 bytes (the all-zero DH result is rejected at handshake time). */
export const X25519Pub = b64uBytes(32);

export const entityId = (kind: EntityKind) => z.string().refine((s) => isId(kind, s), `expected a ${kind} id`);
export const MemberId = entityId("member");
export const DeviceId = entityId("device");
export const LaneId = entityId("lane");
export const PendingId = entityId("pending");
export const ScopeId = entityId("scope");
export const GrantId = entityId("grant");
export const serverId = (kind: ServerIdKind) => z.string().refine((s) => isServerId(kind, s), `expected a ${kind} serverId`);
export const RoomId = z.string().refine(isRoomId, "expected a room id");

/** `{alg, kid, pub}` with `kid` checked against `pub` (comparisons still use `pub`, P-22). */
export const KeyRef = (alg: "ed25519" | "x25519") =>
  z
    .strictObject({ alg: z.literal(alg), kid: Kid, pub: alg === "ed25519" ? Ed25519Pub : X25519Pub })
    .refine((k) => kidOf(alg, b64uDecode(k.pub, 32)) === k.kid, "kid does not match pub");

export const Relay = z.strictObject({ host: z.string().min(1).max(253), port: int().min(1).max(65535), tls: z.literal(true) });

export const ROLES = ["guest", "watch", "comment", "steer", "approve", "maintain", "admin"] as const;
export const Role = z.enum(ROLES);
export type Role = (typeof ROLES)[number];

/** Strictly ascending (sorted and unique) by a string key. */
export function strictlySorted<T>(items: readonly T[], key: (item: T) => string): boolean {
  for (let i = 1; i < items.length; i++) if (!(key(items[i - 1]) < key(items[i]))) return false;
  return true;
}

export const LaneList = z.array(LaneId).max(4096).refine((l) => strictlySorted(l, (x) => x), "lanes must be sorted and unique");

export const DeviceEntry = z.strictObject({
  deviceId: DeviceId,
  kind: z.enum(["person", "gateway"]),
  sig: Ed25519Pub,
  dh: X25519Pub,
});
export type DeviceEntry = z.infer<typeof DeviceEntry>;

const rosterEntry = (minDevices: number) =>
  z.strictObject({
    memberId: MemberId,
    role: Role,
    lanes: LaneList,
    devices: z
      .array(DeviceEntry)
      .min(minDevices)
      .max(8)
      .refine((d) => strictlySorted(d, (x) => x.deviceId), "devices must be sorted by deviceId and unique"),
  });
/** identity-model.md 6.1: 0..8 devices in the roster. */
export const RosterEntry = rosterEntry(0);
/** `member.admitted` carries 1..8 devices (room-log-v2.md 4.3). */
export const AdmittedRosterEntry = rosterEntry(1);
export type RosterEntry = z.infer<typeof RosterEntry>;

// ---- policy (identity-model.md 5.1, 5.2.1) ----

export const POLICY_SETTINGS = {
  minVersion: int().min(2),
  sas: z.literal("sas6"),
  deviceAddApproval: z.enum(["same-person", "admin"]),
  rotateLaneOnRemove: z.enum(["compromise", "always"]),
  recoveryEscrow: z.enum(["none", "org"]),
  soleDeviceChange: z.enum(["held", "admin"]),
  projectNames: z.enum(["lane-owner", "hidden"]),
  grantTtl: int().min(3600).max(43200),
  closeDelay: int().min(0).max(518400),
} as const;
export type PolicySetting = keyof typeof POLICY_SETTINGS;
export const POLICY_SETTING_NAMES = Object.keys(POLICY_SETTINGS) as PolicySetting[];
export const Policy = z.strictObject(POLICY_SETTINGS);
export type Policy = z.infer<typeof Policy>;

/** Human-readable first issue of a failed parse, with its path. */
export function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  return issue ? `${issue.path.join(".") || "(root)"}: ${issue.message}` : "invalid";
}
