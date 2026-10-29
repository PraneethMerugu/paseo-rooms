// Identifier formats (identity-model.md section 8). Entity ids are 128 random bits as
// 32 lowercase hex; endpoint serverIds are 192 random bits as 32 base64url characters.
import { randomBytes } from "node:crypto";
import { b64u, isB64u } from "./b64u";
import { H_INVITE_REF, H_LINK_REF } from "./contexts";
import { H, utf8 } from "./tbs";

export const ENTITY_PREFIXES = {
  member: "mem_",
  device: "dev_",
  invite: "inv_",
  link: "lnk_",
  pending: "pen_",
  lane: "lane_",
  scope: "scp_",
  kek: "kek_",
  grant: "g_",
} as const;
export type EntityKind = keyof typeof ENTITY_PREFIXES;

export const SERVER_ID_PREFIXES = { roomEndpoint: "rme_", laneEndpoint: "rle_" } as const;
export type ServerIdKind = keyof typeof SERVER_ID_PREFIXES;

export const ROOM_ID_PREFIX = "room_";

const HEX32_RE = /^[0-9a-f]{32}$/;

export function newId(kind: EntityKind): string {
  return ENTITY_PREFIXES[kind] + randomBytes(16).toString("hex");
}

export function isId(kind: EntityKind, text: unknown): text is string {
  const prefix = ENTITY_PREFIXES[kind];
  return typeof text === "string" && text.startsWith(prefix) && HEX32_RE.test(text.slice(prefix.length));
}

export function newServerId(kind: ServerIdKind): string {
  return SERVER_ID_PREFIXES[kind] + b64u(randomBytes(24));
}

export function isServerId(kind: ServerIdKind, text: unknown): text is string {
  const prefix = SERVER_ID_PREFIXES[kind];
  return typeof text === "string" && text.startsWith(prefix) && isB64u(text.slice(prefix.length), 24);
}

/** `room_` + hex of the first 16 bytes of genesisHash. Display and lookup only: security checks use the full hash. */
export function roomIdOf(genesisHash: Uint8Array): string {
  if (genesisHash.length !== 32) throw new Error("genesisHash must be 32 bytes");
  return ROOM_ID_PREFIX + Buffer.from(genesisHash.subarray(0, 16)).toString("hex");
}

export function isRoomId(text: unknown): text is string {
  return typeof text === "string" && text.startsWith(ROOM_ID_PREFIX) && HEX32_RE.test(text.slice(ROOM_ID_PREFIX.length));
}

/** inviteRef = b64u(H("invite-ref", utf8(inviteId))): the only form of an invite id in the log and MLS. */
export function inviteRef(inviteId: string): string {
  if (!isId("invite", inviteId)) throw new Error("bad inviteId");
  return b64u(H(H_INVITE_REF, utf8(inviteId)));
}

/** linkRef = b64u(H("link-ref", utf8(linkId))). */
export function linkRef(linkId: string): string {
  if (!isId("link", linkId)) throw new Error("bad linkId");
  return b64u(H(H_LINK_REF, utf8(linkId)));
}
