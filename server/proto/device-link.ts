// Device link formats shared by the confirming device, the new device and the host (identity-model.md
// 6.4; enrollment-v2.md 5.2, 6.2; room-log-v2.md 4.2, 4.3; implementation plan I-11). Pure: no I/O,
// nothing logged.
//
//   DeviceLinkPayload = { v:2, typ:"device-link", roomId, genesisHash, roomName, endpoint, linkId, token, exp, sas }
//   LinkCode          = "prl2." + b64u(RJCS(DeviceLinkPayload))
//   tokenKey          = HKDF(token, "", TBS("link-token-key", ""), 32)       (proto/enroll.ts tokenKeyOf)
//   linkRef           = b64u(H("link-ref", utf8(linkId)))                      (proto/ids.ts)
//   KeyChange         = { v:2, typ:"key-change", roomId, subject:{kind:"device", id}, old:null, newSig, newDh }
//   newKeySig         = Sign(newSigKey, TBS("key-change-new", RJCS(KeyChange)))
import type { KeyObject } from "node:crypto";
import { z } from "zod";
import { b64uBytes, entityId, nonNegInt, Relay, RoomId, serverId, KeyRef } from "../authority/schema";
import type { KeyChange, SignedStatement, StatementBody, StatementData, StatementType } from "../authority/statements";
import { b64u, b64uDecode, b64uDecodeVar } from "./b64u";
import { CTX_KEY_CHANGE_NEW, stmtContext } from "./contexts";
import { linkRef, roomIdOf } from "./ids";
import { rjcs, rjcsParse } from "./rjcs";
import { sign } from "./tbs";

export const LINK_PREFIX = "prl2.";
export const LINK_MAX_CHARS = 2048;
/** A link code lives at most 10 minutes (identity-model.md 6.4 step 2). */
export const LINK_EXP_MAX_S = 10 * 60;

const DisplayText = (max: number) =>
  z
    .string()
    .max(max)
    .refine((s) => [...s].length <= max && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(s), "control characters");

export const DeviceLinkPayload = z
  .strictObject({
    v: z.literal(2),
    typ: z.literal("device-link"),
    roomId: RoomId,
    genesisHash: b64uBytes(32),
    roomName: DisplayText(80),
    endpoint: z.strictObject({ serverId: serverId("roomEndpoint"), dh: KeyRef("x25519"), relay: Relay }),
    linkId: entityId("link"),
    token: b64uBytes(32),
    exp: nonNegInt(),
    sas: z.literal("sas6"),
  })
  .refine((p) => roomIdOf(b64uDecode(p.genesisHash, 32)) === p.roomId, "roomId does not match genesisHash");
export type DeviceLinkPayload = z.infer<typeof DeviceLinkPayload>;

export class LinkCodeError extends Error {
  constructor(readonly code: "not_link" | "too_large" | "malformed") {
    super(code);
    this.name = "LinkCodeError";
  }
}

export function encodeLink(payload: DeviceLinkPayload): string {
  return LINK_PREFIX + b64u(rjcs(DeviceLinkPayload.parse(payload)));
}

/** Strict decode, as for invites (enrollment-v2.md 2.3 steps 1 and 2). Never echoes the input. */
export function decodeLink(code: unknown): DeviceLinkPayload {
  if (typeof code !== "string") throw new LinkCodeError("not_link");
  const text = code.trim();
  if (!text.startsWith(LINK_PREFIX)) throw new LinkCodeError("not_link");
  if (text.length > LINK_MAX_CHARS) throw new LinkCodeError("too_large");
  let value: unknown;
  try {
    value = rjcsParse(b64uDecodeVar(text.slice(LINK_PREFIX.length), LINK_MAX_CHARS));
  } catch {
    throw new LinkCodeError("malformed");
  }
  const parsed = DeviceLinkPayload.safeParse(value);
  if (!parsed.success) throw new LinkCodeError("malformed");
  return parsed.data;
}

/** The KeyChange a new device signs with its own signing key (6.4 step 4; `old` is null). */
export function newDeviceKeyChange(roomId: string, deviceId: string, deviceSig: string, deviceDh: string): KeyChange {
  return { v: 2, typ: "key-change", roomId, subject: { kind: "device", id: deviceId }, old: null, newSig: deviceSig, newDh: deviceDh };
}

/** `newKeySig` over RJCS(change) under `key-change-new`, by the new signing key. */
export function signNewKey(newSigKey: KeyObject, change: KeyChange): string {
  return b64u(sign(newSigKey, CTX_KEY_CHANGE_NEW, rjcs(change)));
}

/** A statement signed by a device key (producer `device`), under `stmt:<type>`. */
export function signDeviceStatement<T extends StatementType>(i: {
  type: T;
  roomId: string;
  kid: string;
  key: KeyObject;
  base: { seq: number; hash: string };
  ts: number;
  data: StatementData<T>;
}): SignedStatement {
  const body: StatementBody = { v: 2, typ: "stmt", type: i.type, roomId: i.roomId, producer: { kind: "device", kid: i.kid }, base: { seq: i.base.seq, hash: i.base.hash }, ts: i.ts, data: i.data as StatementBody["data"] };
  return { body, sig: b64u(sign(i.key, stmtContext(i.type), rjcs(body))) };
}

/** `device.added.data` (identity-model.md 6.4) for device B, confirmed by device A over link `linkId`. */
export function deviceAddedData(i: {
  roomId: string;
  memberId: string;
  deviceId: string;
  deviceSig: string;
  deviceDh: string;
  newKeySig: string;
  addedBy: string;
  linkId: string;
  transcript: string;
}): StatementData<"device.added"> {
  return {
    memberId: i.memberId,
    device: { deviceId: i.deviceId, kind: "person", sig: i.deviceSig, dh: i.deviceDh },
    change: newDeviceKeyChange(i.roomId, i.deviceId, i.deviceSig, i.deviceDh),
    newKeySig: i.newKeySig,
    addedBy: i.addedBy,
    confirmation: { method: "sas6", linkRef: linkRef(i.linkId), transcript: i.transcript },
  } as StatementData<"device.added">;
}
