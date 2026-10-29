// Sealed files (identity-model 7.2): every key and state file under plugin-data/rooms is sealed under
// the KEK.
//
//   Sealed  = { v: 2, typ: "sealed", alg: "xchacha20poly1305", kekId, purpose, nonce: b64u(24), ct: b64u }
//   fileKey = HKDF-SHA256(ikm = KEK, salt = "", info = TBS("file-key", utf8(purpose)), L = 32)
//   AAD     = RJCS({ v: 2, typ: "sealed", purpose, kekId })
//
// The file text is the canonical RJCS of the outer object; a reader accepts only that exact form, so
// any edit, truncation or extra field is refused before decryption. A file sealed for another purpose
// or under another KEK is refused by name (foreign file), and the AEAD would refuse it anyway because
// the purpose selects the file key and both purpose and kekId are in the AAD.
// Nothing here logs; errors name the problem, never key bytes, plaintext or full paths.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { b64u, b64uDecode, b64uDecodeVar } from "../proto/b64u";
import { KDF_FILE_KEY } from "../proto/contexts";
import { rjcs, rjcsParse, rjcsText } from "../proto/rjcs";
import { hkdf, utf8 } from "../proto/tbs";
import { writePrivateFile, type DurableDeps, type WriteResult } from "../platform/durable";

export const SEALED_VERSION = 2;
export const SEALED_ALG = "xchacha20poly1305";
export const KEK_BYTES = 32;
export const SEALED_NONCE_BYTES = 24;
const TAG_BYTES = 16;
/** Upper bound for one sealed file (MLS group state is the largest; this is generous). */
export const SEALED_MAX_BYTES = 8 * 1024 * 1024;
const SEALED_MAX_CT_BYTES = Math.floor((SEALED_MAX_BYTES * 3) / 4);

/** `"kek_"` + 32 lowercase hex characters (identity-model 7.2). */
export const KEK_ID_RE = /^kek_[0-9a-f]{32}$/;
/** File role and owner, for example `mls-state:<roomId>:<deviceId>`. ASCII only, so HKDF info stays small. */
export const PURPOSE_RE = /^[a-z][a-z0-9-]{0,31}(:[A-Za-z0-9_.-]{1,80}){0,4}$/;

export interface SealedObject {
  v: 2;
  typ: "sealed";
  alg: "xchacha20poly1305";
  kekId: string;
  purpose: string;
  nonce: string;
  ct: string;
}

export type SealedErrorCode =
  /** Not a canonical sealed object of this version: truncated, edited, extra or missing fields. */
  | "sealed_malformed"
  /** Sealed for another purpose (copied from another file role, room or device). */
  | "sealed_foreign_purpose"
  /** Sealed under another KEK (rotation in progress, or a file from another installation). */
  | "sealed_foreign_kek"
  /** Authentication failed: the ciphertext, nonce or binding was modified, or the KEK is wrong. */
  | "sealed_auth_failed";

export class SealedFileError extends Error {
  constructor(readonly code: SealedErrorCode, message: string) {
    super(message);
    this.name = "SealedFileError";
  }
}

export function newKekId(): string {
  return `kek_${randomBytes(16).toString("hex")}`;
}

export function checkPurpose(purpose: string): void {
  if (typeof purpose !== "string" || !PURPOSE_RE.test(purpose)) throw new Error("sealed: bad purpose");
}

function checkKek(kek: Uint8Array, kekId: string): void {
  if (!(kek instanceof Uint8Array) || kek.length !== KEK_BYTES) throw new Error("sealed: KEK must be 32 bytes");
  if (!KEK_ID_RE.test(kekId)) throw new Error("sealed: bad kekId");
}

/** fileKey for one purpose. Exported for the vector test; callers use seal/open. */
export function fileKey(kek: Uint8Array, purpose: string): Buffer {
  checkPurpose(purpose);
  return hkdf(kek, new Uint8Array(0), KDF_FILE_KEY, utf8(purpose), 32);
}

export function sealedAad(purpose: string, kekId: string): Uint8Array {
  return rjcs({ v: SEALED_VERSION, typ: "sealed", purpose, kekId });
}

/**
 * Seals `plaintext` for `purpose`. `nonce` is for test vectors only: production calls let it default to
 * 24 random bytes (XChaCha20's nonce is large enough for random nonces under one key).
 */
export function seal(kek: Uint8Array, kekId: string, purpose: string, plaintext: Uint8Array, nonce?: Uint8Array): SealedObject {
  checkKek(kek, kekId);
  const n = nonce ?? randomBytes(SEALED_NONCE_BYTES);
  if (n.length !== SEALED_NONCE_BYTES) throw new Error("sealed: nonce must be 24 bytes");
  const key = fileKey(kek, purpose);
  try {
    const ct = xchacha20poly1305(key, n, sealedAad(purpose, kekId)).encrypt(plaintext);
    return { v: SEALED_VERSION, typ: "sealed", alg: SEALED_ALG, kekId, purpose, nonce: b64u(n), ct: b64u(ct) };
  } finally {
    key.fill(0);
  }
}

const FIELDS = ["alg", "ct", "kekId", "nonce", "purpose", "typ", "v"];

/** Strict shape check of a parsed value. Throws SealedFileError("sealed_malformed"). */
export function parseSealedObject(value: unknown): SealedObject {
  const bad = (why: string) => new SealedFileError("sealed_malformed", `Sealed file is malformed (${why})`);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw bad("not an object");
  const o = value as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i])) throw bad("unexpected fields");
  if (o.v !== SEALED_VERSION) throw bad("version");
  if (o.typ !== "sealed") throw bad("typ");
  if (o.alg !== SEALED_ALG) throw bad("alg");
  if (typeof o.kekId !== "string" || !KEK_ID_RE.test(o.kekId)) throw bad("kekId");
  if (typeof o.purpose !== "string" || !PURPOSE_RE.test(o.purpose)) throw bad("purpose");
  try {
    b64uDecode(o.nonce as string, SEALED_NONCE_BYTES);
    const ct = b64uDecodeVar(o.ct as string, SEALED_MAX_CT_BYTES);
    if (ct.length < TAG_BYTES) throw new Error("short");
  } catch {
    throw bad("nonce or ct encoding");
  }
  return o as unknown as SealedObject;
}

/**
 * Opens a sealed object for the expected purpose under the given KEK. Refuses a foreign purpose or
 * KEK before decrypting, then lets the AEAD check the rest.
 */
export function open(kek: Uint8Array, kekId: string, purpose: string, value: unknown): Buffer {
  checkKek(kek, kekId);
  checkPurpose(purpose);
  const obj = parseSealedObject(value);
  if (obj.purpose !== purpose) throw new SealedFileError("sealed_foreign_purpose", "Sealed file belongs to another purpose");
  if (obj.kekId !== kekId) throw new SealedFileError("sealed_foreign_kek", "Sealed file was sealed under another KEK");
  const key = fileKey(kek, purpose);
  try {
    return Buffer.from(xchacha20poly1305(key, b64uDecode(obj.nonce, SEALED_NONCE_BYTES), sealedAad(purpose, kekId)).decrypt(b64uDecodeVar(obj.ct, SEALED_MAX_CT_BYTES)));
  } catch {
    throw new SealedFileError("sealed_auth_failed", "Sealed file failed authentication (modified, or the wrong key)");
  } finally {
    key.fill(0);
  }
}

/** Canonical file text of a sealed object (RJCS, no trailing newline). */
export function sealedText(obj: SealedObject): string {
  return rjcsText(obj);
}

/** Parses file bytes: canonical RJCS only (no BOM, no whitespace, no reordering), then the shape check. */
export function parseSealedBytes(bytes: Uint8Array): SealedObject {
  let value: unknown;
  try {
    value = rjcsParse(bytes, SEALED_MAX_BYTES);
  } catch (e) {
    throw new SealedFileError("sealed_malformed", `Sealed file is malformed (${(e as Error).message})`);
  }
  return parseSealedObject(value);
}

/** Seals and writes atomically and durably, owner-only (platform/durable). */
export function writeSealedFile(path: string, kek: Uint8Array, kekId: string, purpose: string, plaintext: Uint8Array, deps?: Partial<DurableDeps>): WriteResult {
  return writePrivateFile(path, sealedText(seal(kek, kekId, purpose, plaintext)), deps);
}

/** Reads and opens a sealed file; null if it does not exist. Throws SealedFileError on any other problem. */
export function readSealedFile(path: string, kek: Uint8Array, kekId: string, purpose: string): Buffer | null {
  let bytes: Buffer;
  try {
    bytes = fs.readFileSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
    throw e;
  }
  return open(kek, kekId, purpose, parseSealedBytes(bytes));
}

/** True if any `*.sealed` file exists below `root` (symlinks are not followed). Used before replacing an orphan KEK. */
export function hasSealedFiles(root: string, maxEntries = 100_000): boolean {
  const stack = [root];
  let seen = 0;
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") continue;
      throw e;
    }
    for (const e of entries) {
      if (++seen > maxEntries) return true; // cannot prove absence: answer the safe way
      if (e.isDirectory()) stack.push(nodePath.join(dir, e.name));
      else if (e.name.endsWith(".sealed")) return true;
    }
  }
  return false;
}
