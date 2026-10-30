// Member-side invite checks before any network access (enrollment-v2.md section 2.3; P-20/C-15).
//
//   1. strict decode (invites.ts); 2. `prc1.` refused with the older-version message;
//   3. `exp` in the past (local clock, 5 min grace) refused;
//   4. relay: TLS is required (the payload schema accepts only `tls: true`); the host must be a DNS
//      name unless the daemon runs with PASEO_ROOMS_DEV_INSECURE_RELAY=1; a relay that is not in
//      `trustedRelays` (default relay.paseo.sh:443) needs the user's explicit "Trust this relay";
//   5. preview: room name and endpoint fingerprint marked unverified until the codes match.
// Nothing is stored or connected here. A device link code (`prl2.`, identity-model.md 6.4) gets the
// same checks (I-11).
import { fingerprintOfKid } from "../proto/keys";
import { decodeInvite, InviteCodeError, isDevInsecureRelay, relayHostAllowed, relayKey, type InvitePayload } from "../host/invites";
import { decodeLink, LINK_PREFIX, LinkCodeError, type DeviceLinkPayload } from "../proto/device-link";

export const DEFAULT_TRUSTED_RELAYS: readonly string[] = ["relay.paseo.sh:443"];
export const EXP_GRACE_S = 5 * 60;

export type JoinRefusal = "older_version" | "not_invite" | "too_large" | "malformed" | "expired" | "relay_not_allowed" | "relay_not_trusted";

export const JOIN_REFUSAL_MESSAGES: Readonly<Record<JoinRefusal, string>> = {
  older_version: "This invite is from an older version of Rooms. Ask the owner for a new invite.",
  not_invite: "This is not a Rooms invite code.",
  too_large: "This invite code is too long to be valid.",
  malformed: "This invite code is damaged. Ask the owner to send it again.",
  expired: "This invite has expired. Ask the owner for a new invite.",
  relay_not_allowed: "This invite names a relay address that Rooms does not connect to.",
  relay_not_trusted: "This invite uses a relay you have not used before. Confirm that you trust it to continue.",
};

export class JoinRefusedError extends Error {
  constructor(readonly code: JoinRefusal) {
    super(JOIN_REFUSAL_MESSAGES[code]);
    this.name = "JoinRefusedError";
  }
}

export type InvitePreview = {
  roomId: string;
  /** Display only: unverified until the codes match (2.3 step 5). */
  roomName: string;
  endpointFingerprint: string;
  relay: { host: string; port: number; trusted: boolean };
  exp: number;
  unverified: true;
  /** `device-link`: this code adds a device to the person's existing membership. */
  kind?: "invite" | "device-link";
};

/** Steps 1 to 4 and the preview. Throws JoinRefusedError; `relay.trusted` false means step 4 needs the user. */
export function checkInvite(code: unknown, o: { nowS: number; trustedRelays: readonly string[]; env?: NodeJS.ProcessEnv }): { payload: InvitePayload | DeviceLinkPayload; preview: InvitePreview } {
  let payload: InvitePayload | DeviceLinkPayload;
  try {
    payload = typeof code === "string" && code.trim().startsWith(LINK_PREFIX) ? decodeLink(code) : decodeInvite(code);
  } catch (err) {
    throw new JoinRefusedError(err instanceof InviteCodeError ? err.code : err instanceof LinkCodeError && err.code !== "not_link" ? err.code : "malformed");
  }
  if (payload.exp + EXP_GRACE_S < o.nowS) throw new JoinRefusedError("expired");
  const relay = payload.endpoint.relay;
  if (relay.tls !== true || !relayHostAllowed(relay.host, isDevInsecureRelay(o.env))) throw new JoinRefusedError("relay_not_allowed");
  const trusted = o.trustedRelays.includes(relayKey(relay));
  return {
    payload,
    preview: {
      roomId: payload.roomId,
      roomName: payload.roomName,
      endpointFingerprint: fingerprintOfKid(payload.endpoint.dh.kid),
      relay: { host: relay.host.toLowerCase(), port: relay.port, trusted },
      exp: payload.exp,
      unverified: true,
      kind: payload.typ,
    },
  };
}

/** Step 4 for Join: an untrusted relay continues only with the user's explicit trust. */
export function requireRelayTrust(preview: InvitePreview, trustRelay: boolean): void {
  if (!preview.relay.trusted && !trustRelay) throw new JoinRefusedError("relay_not_trusted");
}

/**
 * Lane host label (2.3, P-20): always "Room lane: " plus the room name, never an owner-chosen string
 * alone. The verified room name arrives with MLS (`room.profile`, I-13); until then the room id is used.
 */
export function laneHostLabel(room: { verifiedName: string | null; roomId: string }, laneLabel?: string | null): string {
  const clean = (s: string, n: number) => s.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, "").trim().slice(0, n);
  const name = room.verifiedName ? clean(room.verifiedName, 80) : room.roomId.slice(0, 13);
  const lane = laneLabel ? clean(laneLabel, 60) : "";
  return `Room lane: ${name || room.roomId.slice(0, 13)}${lane ? ` · ${lane}` : ""}`;
}
