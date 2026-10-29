// RJCS: RFC 8785 (JCS) restricted to integers, ASCII keys and well-formed strings
// (signatures-and-encoding.md section 2). Pure JS: no Node modules.

export type RjcsValue = null | boolean | number | string | RjcsValue[] | { [key: string]: RjcsValue };

/** Default size limit for one RJCS encoding (section 2.1). */
export const RJCS_MAX_BYTES = 64 * 1024;
/** Limit for frames that carry MLS payloads (enrollment-v2.md section 3.4). */
export const RJCS_MAX_FRAME_BYTES = 4 * 1024 * 1024;
/** Maximum nesting of arrays and objects; the outermost container is depth 1. */
export const RJCS_MAX_DEPTH = 16;

const KEY_RE = /^[A-Za-z0-9_]{1,64}$/;
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);
// A high surrogate not followed by a low one, or a low surrogate not preceded by a high one.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Canonical RJCS text. Throws if the value is outside the value model of section 2.1. */
export function rjcsText(value: unknown): string {
  return encodeValue(value, 0);
}

/** Canonical RJCS bytes (UTF-8, no BOM). */
export function rjcs(value: unknown, maxBytes = RJCS_MAX_BYTES): Uint8Array {
  const bytes = encoder.encode(rjcsText(value));
  if (bytes.length > maxBytes) throw new Error(`rjcs: encoding is ${bytes.length} bytes, limit ${maxBytes}`);
  return bytes;
}

/**
 * Strict parse (section 2.3): size, fatal UTF-8 without BOM, JSON.parse, value model, and the
 * received bytes must equal the re-encoding. Signatures are then checked over `bytes` themselves.
 */
export function rjcsParse(bytes: Uint8Array, maxBytes = RJCS_MAX_BYTES): RjcsValue {
  if (bytes.length > maxBytes) throw new Error(`rjcs: input is ${bytes.length} bytes, limit ${maxBytes}`);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error("rjcs: byte order mark");
  let text: string;
  try {
    text = strictDecoder.decode(bytes);
  } catch {
    throw new Error("rjcs: invalid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("rjcs: not JSON");
  }
  // rjcsText enforces the value model; the comparison rejects every non-canonical spelling.
  if (rjcsText(parsed) !== text) throw new Error("rjcs: not canonical");
  return parsed as RjcsValue;
}

function encodeValue(value: unknown, depth: number): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) throw new Error("rjcs: number is not a safe integer");
      if (Object.is(value, -0)) throw new Error("rjcs: negative zero");
      return String(value);
    case "string":
      if (LONE_SURROGATE_RE.test(value)) throw new Error("rjcs: lone surrogate");
      // ES2019+ JSON.stringify: short escapes, lowercase \u00xx below U+0020, everything else literal.
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Error(`rjcs: ${typeof value} is not allowed`);
  }
  if (depth >= RJCS_MAX_DEPTH) throw new Error("rjcs: nesting too deep");
  if (Array.isArray(value)) return `[${value.map((v) => encodeValue(v, depth + 1)).join(",")}]`;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new Error("rjcs: only plain objects are allowed");
  const obj = value as Record<string, unknown>;
  // Keys are ASCII, so the default sort (UTF-16 code units) equals byte order.
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    if (!KEY_RE.test(key)) throw new Error("rjcs: key outside [A-Za-z0-9_]{1,64}");
    if (RESERVED_KEYS.has(key)) throw new Error(`rjcs: reserved key ${key}`);
    const v = obj[key];
    if (v === undefined) throw new Error(`rjcs: undefined value at ${key}`);
    parts.push(`${JSON.stringify(key)}:${encodeValue(v, depth + 1)}`);
  }
  return `{${parts.join(",")}}`;
}
