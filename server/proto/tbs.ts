// Domain-separated inputs (signatures-and-encoding.md section 3) on node:crypto:
//   TBS(ctx, payload) = "paseo-rooms/v2" || 0x00 || ctx || 0x00 || payload
// Sign, H, HMAC and HKDF all go through TBS. Verify is in keys.ts, next to the key and
// signature checks it needs. Nothing here logs key material.
import { createHash, createHmac, hkdfSync, sign as edSign, type KeyObject } from "node:crypto";
import { CTX_RE, HASH_CTX_PREFIX, PROTOCOL_PREFIX } from "./contexts";

const PREFIX_BYTES = Buffer.from(PROTOCOL_PREFIX, "ascii");
const ZERO = Buffer.from([0]);
const EMPTY = new Uint8Array(0);

export function utf8(text: string): Buffer {
  return Buffer.from(text, "utf8");
}

export function tbs(ctx: string, payload: Uint8Array = EMPTY): Buffer {
  if (!CTX_RE.test(ctx)) throw new Error("tbs: bad context");
  return Buffer.concat([PREFIX_BYTES, ZERO, Buffer.from(ctx, "ascii"), ZERO, payload]);
}

/** Ed25519 (RFC 8032, pure) over TBS(ctx, payload). Returns the 64-byte signature. */
export function sign(privateKey: KeyObject, ctx: string, payload: Uint8Array): Buffer {
  if (privateKey.asymmetricKeyType !== "ed25519" || privateKey.type !== "private") throw new Error("sign: need an Ed25519 private key");
  return edSign(null, tbs(ctx, payload), privateKey);
}

/** H(label, data) = SHA-256(TBS("h:" + label, data)). */
export function H(label: string, data: Uint8Array = EMPTY): Buffer {
  return createHash("sha256").update(tbs(HASH_CTX_PREFIX + label, data)).digest();
}

/** HMAC-SHA256(key, TBS(label, payload)). */
export function hmac(key: Uint8Array, label: string, payload: Uint8Array = EMPTY): Buffer {
  return createHmac("sha256", key).update(tbs(label, payload)).digest();
}

/**
 * HKDF-SHA256 (RFC 5869) with info = TBS(label, infoPayload). An empty salt is the RFC's
 * default (HashLen zero bytes). node:crypto limits info to 1024 bytes and throws above it.
 */
export function hkdf(ikm: Uint8Array, salt: Uint8Array, label: string, infoPayload: Uint8Array, length: number): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, tbs(label, infoPayload), length));
}
