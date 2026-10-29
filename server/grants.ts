// Lane-scoped grants: `prg1.<base64url(canonical claims)>.<base64url Ed25519 signature>`.
// Issued by the (embedded) host key; verified offline by the lane endpoint against the pinned key.
import { canonicalJson } from "../shared/control";
import { GrantClaims } from "../shared/schemas";
import { fromB64u, randomHexId, signEd25519, verifyEd25519, type StoredEd25519Key } from "./crypto";

export const GRANT_PREFIX = "prg1";

export interface IssueGrantInput {
  roomId: string;
  laneId: string;
  laneServerId: string;
  memberId: string;
  deviceKeyId: string;
  ttlSeconds: number;
  nowMs?: number;
}

export function issueGrant(hostKey: StoredEd25519Key, input: IssueGrantInput): { token: string; claims: GrantClaims } {
  const now = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const claims = GrantClaims.parse({
    v: 1,
    typ: "rooms.lane-grant",
    iss: hostKey.keyId,
    roomId: input.roomId,
    laneId: input.laneId,
    aud: input.laneServerId,
    sub: input.memberId,
    dev: input.deviceKeyId,
    role: "watch",
    gid: randomHexId("g_"),
    iat: now,
    exp: now + input.ttlSeconds,
  });
  const body = `${GRANT_PREFIX}.${Buffer.from(canonicalJson(claims)).toString("base64url")}`;
  return { token: `${body}.${signEd25519(hostKey, body)}`, claims };
}

export type GrantFailure = "malformed" | "bad_signature" | "wrong_issuer" | "wrong_audience" | "not_yet_valid" | "expired";
export type GrantCheck = { ok: true; claims: GrantClaims } | { ok: false; reason: GrantFailure; claims?: GrantClaims };

/** Stateless part of grant verification. Membership and revocation are checked by the caller. */
export function verifyGrant(
  token: string,
  expected: { hostPublicKey: string; hostKeyId: string; laneId: string; laneServerId: string },
  nowMs = Date.now(),
): GrantCheck {
  if (typeof token !== "string" || token.length > 2048) return { ok: false, reason: "malformed" };
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== GRANT_PREFIX) return { ok: false, reason: "malformed" };
  if (!verifyEd25519(expected.hostPublicKey, `${parts[0]}.${parts[1]}`, parts[2])) return { ok: false, reason: "bad_signature" };
  let claims: GrantClaims;
  try {
    claims = GrantClaims.parse(JSON.parse(fromB64u(parts[1]).toString("utf8")));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (claims.iss !== expected.hostKeyId) return { ok: false, reason: "wrong_issuer", claims };
  if (claims.laneId !== expected.laneId || claims.aud !== expected.laneServerId) return { ok: false, reason: "wrong_audience", claims };
  const now = Math.floor(nowMs / 1000);
  if (claims.iat > now + 300) return { ok: false, reason: "not_yet_valid", claims };
  if (claims.exp <= now) return { ok: false, reason: "expired", claims };
  return { ok: true, claims };
}
