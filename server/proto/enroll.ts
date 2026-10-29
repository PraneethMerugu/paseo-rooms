// Enrollment cryptography shared by the host and the member (enrollment-v2.md sections 2.1, 5.2, 6;
// implementation plan I-9). Pure: no I/O, nothing logged.
//
//   tokenKey      = HKDF(token, "", TBS("invite-token-key", ""), 32)
//   EnrollSigned  = { v:2, typ:"enroll-request", h, genesisHash, inviteId | linkId, deviceSig, deviceDh, label, sasCommit }
//   sig           = Sign(deviceSigKey, TBS("enroll-request", RJCS(EnrollSigned)))
//   tokenMac      = HMAC-SHA256(tokenKey, TBS("enroll-token", RJCS(EnrollSigned)))
//   sasCommit     = H("sas-commit", Nm)
//   info          = RJCS({ deviceDh, deviceSig, endpointDh, genesisHash, inviteId | linkId })
//   sasKey        = HKDF(Nm || Nh, salt = h, TBS("sas", info), 8)
//   sas           = uint64_be(sasKey) mod 10^6, six digits ("317 837" for display)
//   sasTranscript = H("sas-transcript", h || Nm || Nh || info)
import { timingSafeEqual, type KeyObject } from "node:crypto";
import { b64u, b64uDecode, isB64u } from "./b64u";
import { CTX_ENROLL_REQUEST, H_SAS_COMMIT, H_SAS_TRANSCRIPT, KDF_INVITE_TOKEN_KEY, KDF_LINK_TOKEN_KEY, KDF_SAS, MAC_ENROLL_TOKEN } from "./contexts";
import { isValidEd25519PublicKey, verify } from "./keys";
import { rjcs } from "./rjcs";
import { H, hkdf, hmac, sign } from "./tbs";

const EMPTY = new Uint8Array(0);

export type EnrollTarget = { inviteId: string } | { linkId: string };

export type EnrollSigned = {
  v: 2;
  typ: "enroll-request";
  h: string;
  genesisHash: string;
  deviceSig: string;
  deviceDh: string;
  label: string;
  sasCommit: string;
} & EnrollTarget;

export function enrollSigned(i: { h: string; genesisHash: string; target: EnrollTarget; deviceSig: string; deviceDh: string; label: string; sasCommit: string }): EnrollSigned {
  return { v: 2, typ: "enroll-request", h: i.h, genesisHash: i.genesisHash, ...i.target, deviceSig: i.deviceSig, deviceDh: i.deviceDh, label: i.label, sasCommit: i.sasCommit };
}

/** tokenKey of an invite (or, with `link`, of a device link): the host stores this, never the token. */
export function tokenKeyOf(token: Uint8Array, kind: "invite" | "link" = "invite"): Buffer {
  if (token.byteLength !== 32) throw new Error("token must be 32 bytes");
  return hkdf(token, EMPTY, kind === "invite" ? KDF_INVITE_TOKEN_KEY : KDF_LINK_TOKEN_KEY, EMPTY, 32);
}

export function enrollTokenMac(tokenKey: Uint8Array, signed: EnrollSigned): Buffer {
  return hmac(tokenKey, MAC_ENROLL_TOKEN, rjcs(signed));
}

/** Constant-time comparison of a received tokenMac (b64u) with the expected MAC. */
export function tokenMacMatches(tokenKey: Uint8Array, signed: EnrollSigned, received: string): boolean {
  const expected = enrollTokenMac(tokenKey, signed);
  const got = isB64u(received, 32) ? b64uDecode(received, 32) : Buffer.alloc(32);
  return timingSafeEqual(expected, got) && isB64u(received, 32);
}

export function signEnroll(deviceSigKey: KeyObject, signed: EnrollSigned): Buffer {
  return sign(deviceSigKey, CTX_ENROLL_REQUEST, rjcs(signed));
}

/** Verifies `sig` (b64u) by `signed.deviceSig` over EnrollSigned. Never throws. */
export function verifyEnrollSig(signed: EnrollSigned, sig: string): boolean {
  try {
    if (!isB64u(signed.deviceSig, 32) || !isB64u(sig, 64)) return false;
    const pub = b64uDecode(signed.deviceSig, 32);
    if (!isValidEd25519PublicKey(pub)) return false;
    return verify(pub, CTX_ENROLL_REQUEST, rjcs(signed), b64uDecode(sig, 64));
  } catch {
    return false;
  }
}

export function sasCommitOf(nm: Uint8Array): string {
  if (nm.byteLength !== 32) throw new Error("Nm must be 32 bytes");
  return b64u(H(H_SAS_COMMIT, nm));
}

export type SasInputs = {
  /** Pinned handshake hash (32 bytes). */
  h: Uint8Array;
  nm: Uint8Array;
  /** Host nonce (or the confirming device's Nc for a device link). */
  nh: Uint8Array;
  deviceDh: string;
  deviceSig: string;
  endpointDh: string;
  genesisHash: string;
  target: EnrollTarget;
};

export type Sas = { digits: string; display: string; transcript: string };

export function sasInfo(i: Pick<SasInputs, "deviceDh" | "deviceSig" | "endpointDh" | "genesisHash" | "target">): Uint8Array {
  return rjcs({ deviceDh: i.deviceDh, deviceSig: i.deviceSig, endpointDh: i.endpointDh, genesisHash: i.genesisHash, ...i.target });
}

/** Section 6.2. Both sides compute it from the pinned inputs only (5.6). */
export function computeSas(i: SasInputs): Sas {
  if (i.h.byteLength !== 32 || i.nm.byteLength !== 32 || i.nh.byteLength !== 32) throw new Error("SAS inputs must be 32 bytes each");
  const info = sasInfo(i);
  const key = hkdf(Buffer.concat([i.nm, i.nh]), i.h, KDF_SAS, info, 8);
  const digits = (key.readBigUInt64BE(0) % 1_000_000n).toString().padStart(6, "0");
  const transcript = b64u(H(H_SAS_TRANSCRIPT, Buffer.concat([i.h, i.nm, i.nh, info])));
  return { digits, display: `${digits.slice(0, 3)} ${digits.slice(3)}`, transcript };
}

/** Device label of `enroll.request` (5.2): 1..80 characters, NFC, no control characters. */
export function isValidLabel(label: unknown): label is string {
  return typeof label === "string" && label.length >= 1 && [...label].length <= 80 && label.normalize("NFC") === label && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(label);
}
