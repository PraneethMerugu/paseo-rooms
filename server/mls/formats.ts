// MLS formats of identity v2 (mls-integration.md sections 2.1 to 2.3, 3 and 5; signatures-and-encoding.md
// 3.2 and 3.3): group ids, the `paseo_room_authority` extension, the leaf credential (`MlsIdentity`),
// the authenticated data of every MLS message, and the epoch anchor. Pure: no ts-mls, no I/O.
import type { KeyObject } from "node:crypto";
import { z } from "zod";
import { DeviceId, Ed25519Pub, firstIssue, Hash32, logPos, MemberId, nonNegInt, RoomId, Sig64 } from "../authority/schema";
import { activeAdmins, type AuthorityState } from "../authority/state";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_CHAT_MESSAGE, CTX_MLS_IDENTITY, H_ADMIN_SET, H_MLS_EPOCH_AUTH, H_MLS_GROUP } from "../proto/contexts";
import { verify } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { H, sign } from "../proto/tbs";

export class MlsFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MlsFormatError";
  }
}

// ---- 2.1, 2.2 group ids ----

/** `H("mls-group", RJCS({genesisHash, generation}))`, with `scope` for a team subgroup. */
export function mlsGroupId(genesisHash: string, generation: number, scope: string | null = null): Uint8Array {
  return new Uint8Array(H(H_MLS_GROUP, rjcs(scope === null ? { genesisHash, generation } : { genesisHash, scope, generation })));
}

// ---- 2.3 authority extension ----

/** Sorted b64u public keys of every active admin key. */
export function adminSetOf(auth: Readonly<AuthorityState>): string[] {
  return activeAdmins(auth as AuthorityState)
    .map((a) => a.pub)
    .sort();
}

export function adminSetHash(adminSet: readonly string[]): string {
  return b64u(H(H_ADMIN_SET, rjcs([...adminSet])));
}

/** Extension data of `0xF0A1`: `RJCS({v: 2, genesisHash, adminSetHash, scope})`. */
export function authorityExtension(genesisHash: string, auth: Readonly<AuthorityState>, scope: string | null = null): Uint8Array {
  return rjcs({ v: 2, genesisHash, adminSetHash: adminSetHash(adminSetOf(auth)), scope });
}

// ---- 3 credentials ----

export const MlsIdentity = z.strictObject({
  v: z.literal(2),
  typ: z.literal("mls-identity"),
  roomId: RoomId,
  memberId: MemberId,
  deviceId: DeviceId,
  deviceSig: Ed25519Pub,
  mlsSig: Ed25519Pub,
  notBefore: nonNegInt(),
});
export type MlsIdentity = z.infer<typeof MlsIdentity>;
const SignedIdentity = z.strictObject({ id: MlsIdentity, sig: Sig64 });

/** Credential identity bytes: `RJCS({id, sig})` with `sig` by the device signing key under `mls-identity`. */
export function signMlsIdentity(id: MlsIdentity, deviceKey: KeyObject): Uint8Array {
  const parsed = MlsIdentity.parse(id);
  return rjcs({ id: parsed, sig: b64u(sign(deviceKey, CTX_MLS_IDENTITY, rjcs(parsed))) });
}

/**
 * Rule 2 of section 4.1: strict RJCS and the schema. The bytes must be the canonical encoding, so
 * a leaf credential compares byte for byte. Returns null on any failure.
 */
export function parseMlsIdentity(bytes: Uint8Array): { id: MlsIdentity; sig: string } | null {
  try {
    const v = rjcsParse(bytes);
    const p = SignedIdentity.safeParse(v);
    if (!p.success) return null;
    if (Buffer.compare(Buffer.from(rjcs(p.data)), Buffer.from(bytes)) !== 0) return null;
    return p.data;
  } catch {
    return null;
  }
}

/** Rule 5: the identity signature verifies with `deviceSig` under `mls-identity`. */
export function identitySigValid(p: { id: MlsIdentity; sig: string }): boolean {
  return verify(b64uDecode(p.id.deviceSig, 32), CTX_MLS_IDENTITY, rjcs(p.id), b64uDecode(p.sig, 64));
}

// ---- 5 authenticated data and epoch anchor ----

const Pos = z.strictObject({ seq: logPos(), hash: Hash32 });
export const MlsAad = z.strictObject({ v: z.literal(2), typ: z.literal("mls-aad"), roster: Pos, logHead: Pos, epochAuth: Hash32 });
export type MlsAad = z.infer<typeof MlsAad>;

export function encodeAad(a: Omit<MlsAad, "v" | "typ">): Uint8Array {
  return rjcs(MlsAad.parse({ v: 2, typ: "mls-aad", ...a }));
}

/** Strict parse (section 4.2 step 1). Throws MlsFormatError. */
export function parseAad(bytes: Uint8Array): MlsAad {
  let v: unknown;
  try {
    v = rjcsParse(bytes);
  } catch {
    throw new MlsFormatError("authenticated data is not strict RJCS");
  }
  const p = MlsAad.safeParse(v);
  if (!p.success) throw new MlsFormatError(`authenticated data: ${firstIssue(p.error)}`);
  return p.data;
}

/** `b64u(H("mls-epoch-auth", RJCS({v, typ, groupId, epoch, auth})))` (section 5). */
export function epochAuth(groupId: Uint8Array, epoch: number, authenticator: Uint8Array): string {
  return b64u(H(H_MLS_EPOCH_AUTH, rjcs({ v: 2, typ: "mls-epoch-auth", groupId: b64u(groupId), epoch, auth: b64u(authenticator) })));
}

// ---- chat message (mls-integration.md 5.2; R3.4) ----

/** Longest chat text, in UTF-16 code units (the RPC and the receiver enforce the same limit). */
export const CHAT_TEXT_MAX = 4000;

/**
 * The signed chat object inside a `chat.message` payload. The sender's device signing key signs it
 * under `chat-message`, bound to the group and the epoch the message is encrypted in, and naming the
 * sender's member and device. The receiver checks it against the leaf ts-mls decrypted the message
 * from (inferred from the secret tree, adapter.ts), so attribution does not rest on that inference alone.
 * `ts` is the sender's clock (ms): a claim, shown as such.
 */
export const ChatMessage = z.strictObject({
  v: z.literal(2),
  typ: z.literal("chat-message"),
  roomId: RoomId,
  groupId: Hash32,
  epoch: nonNegInt(),
  memberId: MemberId,
  deviceId: DeviceId,
  ts: nonNegInt(),
  text: z.string().min(1).max(CHAT_TEXT_MAX),
});
export type ChatMessage = z.infer<typeof ChatMessage>;

/** `{kind: "chat.message", msg, sig}` with `sig = Sign(deviceKey, "chat-message", RJCS(msg))`. */
export function signChatMessage(msg: ChatMessage, deviceKey: KeyObject): { kind: "chat.message"; msg: ChatMessage; sig: string } {
  const parsed = ChatMessage.parse(msg);
  return { kind: "chat.message", msg: parsed, sig: b64u(sign(deviceKey, CTX_CHAT_MESSAGE, rjcs(parsed))) };
}

export type ChatRefusal = "wrong_room" | "wrong_group" | "wrong_epoch" | "wrong_sender" | "bad_signature";

/**
 * Receiver check of 5.2: the object names this room, group and epoch and the decrypting leaf's member
 * and device, and the signature verifies with that leaf's `deviceSig`. Any failure rejects the message.
 */
export function checkChatMessage(
  p: { msg: ChatMessage; sig: string },
  expect: { roomId: string; groupId: Uint8Array; epoch: number; sender: { memberId: string; deviceId: string; deviceSig: string } },
): { ok: true } | { ok: false; reason: ChatRefusal } {
  const m = p.msg;
  if (m.roomId !== expect.roomId) return { ok: false, reason: "wrong_room" };
  if (m.groupId !== b64u(expect.groupId)) return { ok: false, reason: "wrong_group" };
  if (m.epoch !== expect.epoch) return { ok: false, reason: "wrong_epoch" };
  if (m.memberId !== expect.sender.memberId || m.deviceId !== expect.sender.deviceId) return { ok: false, reason: "wrong_sender" };
  let good = false;
  try {
    good = verify(b64uDecode(expect.sender.deviceSig, 32), CTX_CHAT_MESSAGE, rjcs(m), b64uDecode(p.sig, 64));
  } catch {
    good = false;
  }
  return good ? { ok: true } : { ok: false, reason: "bad_signature" };
}

// ---- application payloads (room-log-v2.md 4.5) ----

/**
 * Inner payloads used here. `chat.message` carries a signed `ChatMessage` (5.2; R3.4): plain text,
 * no thread or mentions yet (room-log-v2 4.5 lists them for later).
 * `room.profile` and `member.profile` (R3.3) are display-only, untrusted text: the receiver sanitizes
 * them again (server/member/room-book.ts) and never uses them for identity or authorization.
 * `room.profile.rev` is not in room-log-v2 4.5: it orders re-announcements after a rename (recorded
 * in the plan's Follow-ups).
 */
export const AppPayload = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("chat.message"), msg: ChatMessage, sig: Sig64 }),
  z.strictObject({ kind: z.literal("room.profile"), name: z.string().min(1).max(400), description: z.string().max(2000), rev: z.number().int().min(0).max(2 ** 31) }),
  z.strictObject({ kind: z.literal("member.profile"), memberId: MemberId, label: z.string().min(1).max(400) }),
  z.strictObject({
    kind: z.literal("log.witness"),
    witness: z.strictObject({ v: z.literal(2), typ: z.literal("log-witness"), roomId: RoomId, deviceId: DeviceId, head: Pos, roster: Pos }),
    sig: Sig64,
  }),
]);
export type AppPayload = z.infer<typeof AppPayload>;

export function parseAppPayload(bytes: Uint8Array): AppPayload | null {
  try {
    const p = AppPayload.safeParse(rjcsParse(bytes, 64 * 1024));
    return p.success ? p.data : null;
  } catch {
    return null;
  }
}
