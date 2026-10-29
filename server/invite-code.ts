// Invite (enrollment) codes: `prc1.<base64url(JSON InvitePayload)>`. The code carries a one-time secret.
import { INVITE_CODE_PREFIX, InvitePayload } from "../shared/schemas";

export function encodeInviteCode(payload: InvitePayload): string {
  return `${INVITE_CODE_PREFIX}${Buffer.from(JSON.stringify(InvitePayload.parse(payload))).toString("base64url")}`;
}

export function decodeInviteCode(code: string): InvitePayload {
  const trimmed = code.trim();
  if (!trimmed.startsWith(INVITE_CODE_PREFIX)) throw new Error("Not a Paseo Rooms invite code");
  const body = trimmed.slice(INVITE_CODE_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) throw new Error("Invite code is malformed");
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    throw new Error("Invite code is malformed");
  }
  const parsed = InvitePayload.safeParse(json);
  if (!parsed.success) throw new Error("Invite code is malformed or from an unsupported version");
  return parsed.data;
}
