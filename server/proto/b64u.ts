// Strict base64url without padding (signatures-and-encoding.md section 4).
// Buffer's own decoder is lenient, so it runs only after the alphabet and length checks,
// followed by a re-encode comparison that rejects non-zero trailing bits.

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

/** Text length of `n` bytes: ceil(8n/6). */
export function b64uLength(n: number): number {
  return Math.ceil((8 * n) / 6);
}

/** Decode a field of fixed byte length `n`. Throws on any non-canonical form. */
export function b64uDecode(text: string, n: number): Buffer {
  if (typeof text !== "string" || text.length !== b64uLength(n)) throw new Error(`b64u: expected ${n} bytes`);
  return decodeCanonical(text, n);
}

/** Decode a field whose size is not fixed (ciphertexts, token parts), up to `maxBytes`. */
export function b64uDecodeVar(text: string, maxBytes: number): Buffer {
  // A length of 4k+1 characters cannot encode whole bytes.
  if (typeof text !== "string" || text.length % 4 === 1 || text.length > b64uLength(maxBytes)) throw new Error("b64u: bad length");
  return decodeCanonical(text, Math.floor((text.length * 6) / 8));
}

export function isB64u(text: unknown, n: number): text is string {
  try {
    b64uDecode(text as string, n);
    return true;
  } catch {
    return false;
  }
}

function decodeCanonical(text: string, n: number): Buffer {
  if (!B64U_RE.test(text)) throw new Error("b64u: character outside [A-Za-z0-9_-]");
  const bytes = Buffer.from(text, "base64url");
  if (bytes.length !== n || bytes.toString("base64url") !== text) throw new Error("b64u: not canonical");
  return bytes;
}
