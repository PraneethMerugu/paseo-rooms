// Keys, key ids, fingerprints and signature verification (signatures-and-encoding.md section 5).
// Ed25519 public keys are checked in pure JS (BigInt) before node:crypto sees them: the encoding
// must decode to a curve point (RFC 8032 section 5.1.3) and the point must not have small order.
// Nothing here logs key material.
import { createPrivateKey, createPublicKey, timingSafeEqual, verify as edVerify, type KeyObject } from "node:crypto";
import { b64u, b64uDecode } from "./b64u";
import { CTX_RE, H_KID } from "./contexts";
import { H, tbs } from "./tbs";

export type KeyAlg = "ed25519" | "x25519";

/** Algorithm byte of the kid input (section 5.2). */
export const ALG_BYTE: Record<KeyAlg, number> = { ed25519: 0x01, x25519: 0x02 };

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

// ---- key ids and fingerprints ----

/** The 32-byte digest H("kid", algByte || rawPublicKey). */
export function kidDigest(alg: KeyAlg, rawPublicKey: Uint8Array): Buffer {
  if (rawPublicKey.length !== 32) throw new Error("kid: public key must be 32 bytes");
  return H(H_KID, Buffer.concat([Buffer.from([ALG_BYTE[alg]]), rawPublicKey]));
}

/** 43-character key id (256 bits). A lookup handle only: comparisons use the full key (P-22). */
export function kid(alg: KeyAlg, rawPublicKey: Uint8Array): string {
  return b64u(kidDigest(alg, rawPublicKey));
}

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

/** Display fingerprint (section 5.3): lowercase base32 of the first 20 digest bytes, 8 groups of 4. */
export function fingerprintOfKid(kidText: string): string {
  const head = b64uDecode(kidText, 32).subarray(0, 20);
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of head) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return out.match(/.{4}/g)!.join("-");
}

export function fingerprint(alg: KeyAlg, rawPublicKey: Uint8Array): string {
  return fingerprintOfKid(kid(alg, rawPublicKey));
}

/** Constant-time equality of two public keys (or any two byte strings of public length). */
export function keyEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---- Ed25519 point checks (RFC 8032) ----

const P = 2n ** 255n - 19n;
/** Order of the prime-order subgroup. */
export const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

const invert = (a: bigint): bigint => powMod(a, P - 2n);
const D = mod(-121665n * invert(121666n));
const SQRT_M1 = powMod(2n, (P - 1n) / 4n);

type Point = { x: bigint; y: bigint };

function littleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/** RFC 8032 section 5.1.3. Returns null for a non-canonical y or an encoding that is not on the curve. */
function decodePoint(raw: Uint8Array): Point | null {
  if (raw.length !== 32) return null;
  const bytes = Uint8Array.from(raw);
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  const y = littleEndian(bytes);
  if (y >= P) return null;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  let x = (((u * v3) % P) * powMod((u * v7) % P, (P - 5n) / 8n)) % P;
  const vx2 = (((v * x) % P) * x) % P;
  if (vx2 === u) {
    // x is a square root
  } else if (vx2 === mod(-u)) {
    x = (x * SQRT_M1) % P;
  } else {
    return null;
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return { x, y };
}

/** Twisted Edwards addition (a = -1); complete for Ed25519, so it also doubles. */
function add(p: Point, q: Point): Point {
  const t = (((((D * p.x) % P) * q.x) % P) * ((p.y * q.y) % P)) % P;
  return {
    x: mod((p.x * q.y + p.y * q.x) * invert(1n + t)),
    y: mod((p.y * q.y + p.x * q.x) * invert(mod(1n - t))),
  };
}

/** True if the encoding decodes to a point and [8]P is the identity (the 8 points of order <= 8). */
export function isSmallOrderEd25519(raw: Uint8Array): boolean {
  const p = decodePoint(raw);
  return p !== null && hasSmallOrder(p);
}

function hasSmallOrder(p: Point): boolean {
  let q = p;
  for (let i = 0; i < 3; i++) q = add(q, q);
  return q.x === 0n && q.y === 1n;
}

/** Validation on receipt (section 5.1): 32 bytes, a canonical curve point, not of small order. */
export function isValidEd25519PublicKey(raw: Uint8Array): boolean {
  const p = decodePoint(raw);
  return p !== null && !hasSmallOrder(p);
}

/** True if the scalar S of a 64-byte signature is reduced (S < L). */
export function isSignatureScalarReduced(sig: Uint8Array): boolean {
  return sig.length === 64 && littleEndian(sig.subarray(32)) < ED25519_L;
}

// ---- KeyObjects ----

export function ed25519PublicKeyObject(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** Private key from a 32-byte RFC 8032 seed (secret). */
export function ed25519PrivateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

export function x25519PublicKeyObject(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** Private key from a 32-byte X25519 secret (secret). */
export function x25519PrivateKeyFromSecret(secret: Uint8Array): KeyObject {
  if (secret.length !== 32) throw new Error("X25519 secret must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, secret]), format: "der", type: "pkcs8" });
}

/** Raw 32-byte public key of an Ed25519 or X25519 key (private or public). */
export function rawPublicKey(key: KeyObject): Buffer {
  const pub = key.type === "private" ? createPublicKey(key) : key;
  const spki = pub.export({ type: "spki", format: "der" });
  return Buffer.from(spki.subarray(spki.length - 32));
}

// ---- verification ----

/**
 * Ed25519 verification of `message` with the checks of section 5.1: key validation, 64-byte
 * signature with S < L, then RFC 8032 cofactorless verification by node:crypto (OpenSSL).
 */
export function verifyEd25519(rawPub: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== 64 || !isSignatureScalarReduced(sig) || !isValidEd25519PublicKey(rawPub)) return false;
  try {
    return edVerify(null, message, ed25519PublicKeyObject(rawPub), sig);
  } catch {
    return false;
  }
}

/** Verify(pub, ctx, payload, sig): the counterpart of tbs.ts sign(), over the received payload bytes. */
export function verify(rawPub: Uint8Array, ctx: string, payload: Uint8Array, sig: Uint8Array): boolean {
  if (!CTX_RE.test(ctx)) return false;
  return verifyEd25519(rawPub, tbs(ctx, payload), sig);
}
