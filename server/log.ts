// JSON-lines logging to the plugin's stdout (visible in `paseo plugin logs rooms`).
// Secrets are never passed to the logger; as a second line of defence, known secret fields are redacted.
const SECRET_KEYS = /^(token|grant|password|inviteCode|secret|secretKey|secretKeyB64|privateKey|privateKeyPem|connection|sig|nonce)$/i;
const SECRET_VALUES = /(prg1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|prc1\.[A-Za-z0-9_-]+|password=[^&\s"]+)/g;

function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[depth]";
  if (typeof value === "string") return value.replace(SECRET_VALUES, "[redacted]");
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = SECRET_KEYS.test(k) ? "[redacted]" : redact(v, depth + 1);
    return out;
  }
  return value;
}

export function log(event: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ t: new Date().toISOString(), plugin: "rooms", event, ...(redact(fields) as object) }));
}

export function logError(event: string, error: unknown, fields: Record<string, unknown> = {}): void {
  const message = error instanceof Error ? error.message : String(error);
  log(event, { ...fields, error: message.slice(0, 300) });
}

/**
 * Bounds a value that came from a peer (viewer, member daemon) before it is logged: strings are cut to
 * `max` characters and control characters are replaced, so one frame cannot forge or flood log lines.
 */
export function clip(value: unknown, max = 64): string | null {
  if (value === undefined || value === null) return null;
  const s = typeof value === "string" ? value : typeof value === "number" || typeof value === "boolean" ? String(value) : `[${typeof value}]`;
  const cleaned = s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
  return cleaned.length > max ? `${cleaned.slice(0, max)}…(${cleaned.length})` : cleaned;
}

/**
 * Token-bucket limiter for log events keyed by source (for example one per link or route). When a
 * bucket is empty the event is counted, not written; the next written event carries `suppressed: n`.
 */
export class LogLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number; suppressed: number }>();
  constructor(
    private readonly burst = 20,
    private readonly perMinute = 20,
    private readonly maxKeys = 1024,
    private readonly now = () => Date.now(),
  ) {}

  log(key: string, event: string, fields: Record<string, unknown> = {}): boolean {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size >= this.maxKeys) this.buckets.delete(this.buckets.keys().next().value as string);
      b = { tokens: this.burst, at: t, suppressed: 0 };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.burst, b.tokens + ((t - b.at) / 60_000) * this.perMinute);
    b.at = t;
    if (b.tokens < 1) {
      b.suppressed++;
      return false;
    }
    b.tokens -= 1;
    const suppressed = b.suppressed;
    b.suppressed = 0;
    log(event, suppressed ? { ...fields, suppressed } : fields);
    return true;
  }

  forget(key: string): void {
    this.buckets.delete(key);
  }
}

export function short(id: string | null | undefined): string | null {
  if (!id) return id ?? null;
  return id.length > 14 ? `${id.slice(0, 10)}…` : id;
}

export const __testing = { redact };
