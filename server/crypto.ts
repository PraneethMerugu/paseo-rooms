// Ed25519 keys, signatures and hashes on node:crypto. Nothing here logs key material.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface StoredEd25519Key {
  v: 1;
  alg: "ed25519";
  keyId: string;
  publicKey: string; // raw, base64url
  privateKeyPkcs8: string; // DER, base64url (secret)
  createdAt: string;
}

export function b64u(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function fromB64u(text: string): Buffer {
  return Buffer.from(text, "base64url");
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function randomHexId(prefix: string, bytes = 8): string {
  return `${prefix}${randomBytes(bytes).toString("hex")}`;
}

export function keyIdOf(rawPublicKeyB64u: string): string {
  return sha256Hex(fromB64u(rawPublicKeyB64u)).slice(0, 16);
}

export function generateEd25519(): StoredEd25519Key {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const raw = spki.subarray(spki.length - 32);
  const pub = b64u(raw);
  return {
    v: 1,
    alg: "ed25519",
    keyId: keyIdOf(pub),
    publicKey: pub,
    privateKeyPkcs8: b64u(privateKey.export({ type: "pkcs8", format: "der" })),
    createdAt: new Date().toISOString(),
  };
}

export function publicKeyObject(rawPublicKeyB64u: string): KeyObject {
  const raw = fromB64u(rawPublicKeyB64u);
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

export function privateKeyObject(key: StoredEd25519Key): KeyObject {
  return createPrivateKey({ key: fromB64u(key.privateKeyPkcs8), format: "der", type: "pkcs8" });
}

export function signEd25519(key: StoredEd25519Key | KeyObject, message: string | Uint8Array): string {
  const k = "privateKeyPkcs8" in (key as StoredEd25519Key) ? privateKeyObject(key as StoredEd25519Key) : (key as KeyObject);
  return b64u(sign(null, typeof message === "string" ? Buffer.from(message) : message, k));
}

export function verifyEd25519(rawPublicKeyB64u: string, message: string | Uint8Array, signatureB64u: string): boolean {
  try {
    const sig = fromB64u(signatureB64u);
    if (sig.length !== 64) return false;
    return verify(null, typeof message === "string" ? Buffer.from(message) : message, publicKeyObject(rawPublicKeyB64u), sig);
  } catch {
    return false;
  }
}

/** Constant-time comparison of two hex digests. */
export function hexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
