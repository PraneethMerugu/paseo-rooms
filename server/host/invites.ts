// Invites (enrollment-v2.md sections 2.1 to 2.3; room-log-v2.md 4.2; implementation plan I-9).
//
// - `prc2.` codes: "prc2." + b64u(RJCS(InvitePayload)), strictly decoded (prefix, strict base64url,
//   at most 2 KiB, strict RJCS, strict schema). `prc1.` codes get the older-version message.
// - The host keeps an InviteRecord with `tokenKey = HKDF(token, ...)`, never the token itself. The
//   log carries only `inviteRef = H("invite-ref", inviteId)` (S-5); the inviteId and the admin's note
//   stay in the sealed host state.
// - Relay host rule of 2.2: a DNS name; IP literals, `localhost` and single-label names only with the
//   development flag `PASEO_ROOMS_DEV_INSECURE_RELAY=1`, which an invite can never set.
import { z } from "zod";
import { b64uBytes, entityId, firstIssue, KeyRef, LaneList, nonNegInt, Relay, Role, RoomId, serverId } from "../authority/schema";
import { b64u, b64uDecode, b64uDecodeVar } from "../proto/b64u";
import { roomIdOf } from "../proto/ids";
import { rjcs, rjcsParse } from "../proto/rjcs";

export const INVITE_PREFIX = "prc2.";
export const OLD_INVITE_PREFIX = "prc1.";
export const INVITE_MAX_CHARS = 2048;
/** Invite lifetime bounds (2.1): default 30 min, 5 min to 24 h. */
export const INVITE_EXP_DEFAULT_S = 30 * 60;
export const INVITE_EXP_MIN_S = 5 * 60;
export const INVITE_EXP_MAX_S = 24 * 60 * 60;
export const INVITE_NOTE_MAX = 80;

export const DEV_INSECURE_RELAY_ENV = "PASEO_ROOMS_DEV_INSECURE_RELAY";

const DisplayText = (max: number) =>
  z
    .string()
    .max(max)
    .refine((s) => [...s].length <= max && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(s), "control characters");

export const InvitePayload = z
  .strictObject({
    v: z.literal(2),
    typ: z.literal("invite"),
    roomId: RoomId,
    genesisHash: b64uBytes(32),
    roomName: DisplayText(80),
    endpoint: z.strictObject({ serverId: serverId("roomEndpoint"), dh: KeyRef("x25519"), relay: Relay }),
    inviteId: entityId("invite"),
    token: b64uBytes(32),
    exp: nonNegInt(),
    sas: z.literal("sas6"),
  })
  .refine((p) => roomIdOf(b64uDecode(p.genesisHash, 32)) === p.roomId, "roomId does not match genesisHash");
export type InvitePayload = z.infer<typeof InvitePayload>;

export type InviteCodeErrorCode = "older_version" | "not_invite" | "too_large" | "malformed";

export const INVITE_CODE_MESSAGES: Readonly<Record<InviteCodeErrorCode, string>> = {
  older_version: "This invite is from an older version of Rooms. Ask the owner for a new invite.",
  not_invite: "This is not a Rooms invite code.",
  too_large: "This invite code is too long to be valid.",
  malformed: "This invite code is damaged. Ask the owner to send it again.",
};

export class InviteCodeError extends Error {
  constructor(readonly code: InviteCodeErrorCode) {
    super(INVITE_CODE_MESSAGES[code]);
    this.name = "InviteCodeError";
  }
}

export function encodeInvite(payload: InvitePayload): string {
  return INVITE_PREFIX + b64u(rjcs(InvitePayload.parse(payload)));
}

/** Strict decode of section 2.3 step 1 and 2. Throws InviteCodeError; never echoes the input. */
export function decodeInvite(code: unknown): InvitePayload {
  if (typeof code !== "string") throw new InviteCodeError("not_invite");
  const text = code.trim();
  if (text.startsWith(OLD_INVITE_PREFIX)) throw new InviteCodeError("older_version");
  if (!text.startsWith(INVITE_PREFIX)) throw new InviteCodeError("not_invite");
  if (text.length > INVITE_MAX_CHARS) throw new InviteCodeError("too_large");
  let value: unknown;
  try {
    value = rjcsParse(b64uDecodeVar(text.slice(INVITE_PREFIX.length), INVITE_MAX_CHARS));
  } catch {
    throw new InviteCodeError("malformed");
  }
  const parsed = InvitePayload.safeParse(value);
  if (!parsed.success) throw new InviteCodeError("malformed");
  return parsed.data;
}

// ----------------------------------------------------------------------------- relay host rule

/** Section 2.2, after lowercasing. */
export const RELAY_HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);

export function isDevInsecureRelay(env: NodeJS.ProcessEnv): boolean {
  return env[DEV_INSECURE_RELAY_ENV] === "1";
}

/** A relay host an invite may name: a DNS name, or anything with the development flag. */
export function relayHostAllowed(host: string, devInsecure: boolean): boolean {
  return RELAY_HOST_RE.test(host.toLowerCase()) || devInsecure;
}

/** Plain WebSocket is used only for a loopback relay with the development flag; otherwise TLS. */
export function memberRelayUseTls(host: string, devInsecure: boolean): boolean {
  return !(devInsecure && LOOPBACK.has(host.toLowerCase()));
}

export const relayKey = (r: { host: string; port: number }) => `${r.host.toLowerCase()}:${r.port}`;

// ------------------------------------------------------------------------------ host records

export const INVITE_STATES = ["open", "claimed", "used", "revoked", "burned", "expired"] as const;
export type InviteState = (typeof INVITE_STATES)[number];

export const InviteRecord = z.strictObject({
  inviteId: entityId("invite"),
  tokenKey: b64uBytes(32),
  role: Role,
  lanes: LaneList,
  note: DisplayText(INVITE_NOTE_MAX),
  createdAt: nonNegInt(),
  /** unix s */
  exp: nonNegInt(),
  state: z.enum(INVITE_STATES),
  failedProofs: nonNegInt(),
  abandoned: nonNegInt(),
  pendingId: entityId("pending").nullable(),
  usedBy: z.string().nullable(),
});
export type InviteRecord = z.infer<typeof InviteRecord>;

export function parseInviteTerms(i: { role?: unknown; lanes?: unknown; expS?: unknown; note?: unknown }): { role: z.infer<typeof Role>; lanes: string[]; expS: number; note: string } {
  const t = z
    .strictObject({
      role: Role.default("watch"),
      lanes: LaneList.default([]),
      expS: z.number().int().min(INVITE_EXP_MIN_S).max(INVITE_EXP_MAX_S).default(INVITE_EXP_DEFAULT_S),
      note: DisplayText(INVITE_NOTE_MAX).default(""),
    })
    .safeParse(Object.fromEntries(Object.entries(i).filter(([, v]) => v !== undefined)));
  if (!t.success) throw new Error(`invite terms: ${firstIssue(t.error)}`);
  return t.data;
}
