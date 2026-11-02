// Owner-only record of the error detail that viewers of a lane received as generic text (C-16,
// hardening plan "Viewer errors", decisions round 2). The sanitiser replaces every forwarded error
// with generic text and hands the original here. The owner reads it through the local plugin RPC
// rooms.lane.errors on their own daemon; nothing in this module is ever sent over the lane endpoint.
// Memory only: error text can carry absolute paths and is not written to disk.

import { randomBytes } from "node:crypto";

export interface LaneErrorEntry {
  /** Where the viewer would have seen it, e.g. "rpc_error:fetch_agent_request", "agent.lastError". */
  source: string;
  message: string;
  firstAt: string;
  lastAt: string;
  count: number;
  /** v2 (grants-v2 13.1): 8 lowercase base32 characters, random per error, shown to the viewer. */
  ref?: string;
}

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
/** 8 random lowercase base32 characters (40 bits). */
export function newErrorRef(): string {
  return [...randomBytes(8)].map((b) => BASE32[b & 31]).join("");
}

/** Receives the full text of an error that was replaced by generic text for a viewer. */
export interface ErrorSink {
  /** Returns the error reference when references are on (v2), else undefined. */
  record(source: string, message: string): string | undefined;
}

export const LANE_ERROR_LIMITS = { maxEntries: 50, maxChars: 4000 } as const;

export class LaneErrorLog implements ErrorSink {
  private readonly entries: LaneErrorEntry[] = [];

  constructor(
    private readonly maxEntries: number = LANE_ERROR_LIMITS.maxEntries,
    private readonly maxChars: number = LANE_ERROR_LIMITS.maxChars,
    private readonly now: () => number = () => Date.now(),
    /** v2: give every distinct error a reference the viewer sees (grants-v2 13.1). */
    private readonly refs: boolean = false,
  ) {}

  record(source: string, message: string): string | undefined {
    if (typeof message !== "string" || !message) return undefined;
    const text = message.length > this.maxChars ? `${message.slice(0, this.maxChars)}…` : message;
    const src = source.slice(0, 120);
    const at = new Date(this.now()).toISOString();
    // The same error repeats on every agent_update and every history fetch: count it instead.
    const i = this.entries.findIndex((e) => e.source === src && e.message === text);
    if (i >= 0) {
      const [e] = this.entries.splice(i, 1);
      e.lastAt = at;
      e.count++;
      this.entries.push(e);
      return e.ref;
    }
    const ref = this.refs ? newErrorRef() : undefined;
    this.entries.push({ source: src, message: text, firstAt: at, lastAt: at, count: 1, ...(ref ? { ref } : {}) });
    while (this.entries.length > this.maxEntries) this.entries.shift();
    return ref;
  }

  /** Newest first. Copies, so callers cannot change the log. */
  list(): LaneErrorEntry[] {
    return this.entries.map((e) => ({ ...e })).reverse();
  }

  clear(): void {
    this.entries.length = 0;
  }
}
