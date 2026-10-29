// Room event log: append-only JSON lines, hash-chained, every entry signed by the host key.
// M1 stores content as signed plaintext (ids, roles, timestamps only). MLS encryption is Milestone 2.
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, ftruncateSync } from "node:fs";
import { canonicalJson } from "../../shared/control";
import { RoomEvent } from "../../shared/schemas";
import { sha256Hex, signEd25519, verifyEd25519, type StoredEd25519Key } from "../crypto";
import { log } from "../log";
import { appendPrivateLine, writePrivateFile } from "../paths";

export const GENESIS_PREV = "0".repeat(64);
type EventData = RoomEvent["data"];

export function eventHash(e: Omit<RoomEvent, "hash" | "kid" | "sig">): string {
  return sha256Hex(canonicalJson({ v: e.v, roomId: e.roomId, seq: e.seq, ts: e.ts, type: e.type, actor: e.actor, data: e.data, prev: e.prev }));
}

export function buildEvent(
  hostKey: StoredEd25519Key,
  previous: RoomEvent | null,
  input: { roomId: string; type: RoomEvent["type"]; actor: string; data: EventData; ts?: string },
): RoomEvent {
  const base = {
    v: 1 as const,
    roomId: input.roomId,
    seq: previous ? previous.seq + 1 : 0,
    ts: input.ts ?? new Date().toISOString(),
    type: input.type,
    actor: input.actor,
    data: input.data,
    prev: previous ? previous.hash : GENESIS_PREV,
  };
  const hash = eventHash(base);
  return RoomEvent.parse({ ...base, hash, kid: hostKey.keyId, sig: signEd25519(hostKey, hash) });
}

export type ChainCheck = { ok: true } | { ok: false; seq: number; reason: string };

export function verifyChain(events: RoomEvent[], hostPublicKey: string, hostKeyId: string): ChainCheck {
  let prev: RoomEvent | null = null;
  for (const e of events) {
    const parsed = RoomEvent.safeParse(e);
    if (!parsed.success) return { ok: false, seq: (e as RoomEvent)?.seq ?? -1, reason: "schema" };
    if (prev && e.roomId !== prev.roomId) return { ok: false, seq: e.seq, reason: "room_mismatch" };
    if (e.seq !== (prev ? prev.seq + 1 : 0)) return { ok: false, seq: e.seq, reason: "sequence_gap" };
    if (e.prev !== (prev ? prev.hash : GENESIS_PREV)) return { ok: false, seq: e.seq, reason: "broken_link" };
    if (eventHash(e) !== e.hash) return { ok: false, seq: e.seq, reason: "hash_mismatch" };
    if (e.kid !== hostKeyId || !verifyEd25519(hostPublicKey, e.hash, e.sig)) return { ok: false, seq: e.seq, reason: "bad_signature" };
    prev = e;
  }
  return { ok: true };
}

export interface LogRead {
  events: RoomEvent[];
  /** 1-based line numbers that are not valid events (excluding a recovered torn tail). */
  corruptLines: number[];
}

/** Parses one log line into a schema-valid event, or null. */
function parseLine(line: string): RoomEvent | null {
  try {
    const parsed = RoomEvent.safeParse(JSON.parse(line));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/**
 * File-backed log for one room. Appends only; never rewrites earlier lines.
 *
 * Torn tail (C-11): a crash or full disk can leave a partial last line. On open, an unparsable or
 * schema-invalid LAST line (or a last line without its newline) is moved to
 * `events.jsonl.torn-<time>` (0600) and the file is truncated to the last complete event, so later
 * appends continue the chain instead of failing forever. A corrupt line in the middle is never
 * rewritten: reading skips it and verify() reports it.
 */
export class RoomEventLog {
  private last: RoomEvent | null = null;
  recoveredTornTail = false;

  constructor(private readonly path: string, private readonly hostKey: StoredEd25519Key) {
    this.recoverTornTail();
    const { events } = this.read();
    this.last = events.length ? events[events.length - 1] : null;
  }

  private recoverTornTail(): void {
    if (!existsSync(this.path)) return;
    const text = readFileSync(this.path, "utf8");
    if (!text) return;
    const endsClean = text.endsWith("\n");
    const body = endsClean ? text.slice(0, -1) : text;
    const cut = body.lastIndexOf("\n");
    const lastLine = body.slice(cut + 1);
    if (endsClean && (lastLine.trim() === "" || parseLine(lastLine))) return;
    if (!endsClean && parseLine(lastLine)) {
      // Complete event, only the newline is missing: finish the line instead of dropping the event.
      appendPrivateLine(this.path, "");
      return;
    }
    const keep = cut >= 0 ? text.slice(0, cut + 1) : "";
    const torn = text.slice(keep.length);
    const quarantine = `${this.path}.torn-${new Date().toISOString().replace(/[:.]/g, "-")}`;
    writePrivateFile(quarantine, torn);
    const fd = openSync(this.path, "r+");
    try {
      ftruncateSync(fd, Buffer.byteLength(keep, "utf8"));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.recoveredTornTail = true;
    log("room_log_torn_tail_recovered", { file: this.path.split("/").slice(-2).join("/"), bytes: Buffer.byteLength(torn, "utf8"), quarantine: quarantine.split("/").pop() });
  }

  read(): LogRead {
    if (!existsSync(this.path)) return { events: [], corruptLines: [] };
    const events: RoomEvent[] = [];
    const corruptLines: number[] = [];
    readFileSync(this.path, "utf8")
      .split("\n")
      .forEach((l, i) => {
        if (!l.trim()) return;
        const e = parseLine(l);
        if (e) events.push(e);
        else corruptLines.push(i + 1);
      });
    return { events, corruptLines };
  }

  readAll(): RoomEvent[] {
    return this.read().events;
  }

  append(input: { roomId: string; type: RoomEvent["type"]; actor: string; data: EventData }): RoomEvent {
    const event = buildEvent(this.hostKey, this.last, input);
    appendPrivateLine(this.path, JSON.stringify(event));
    this.last = event;
    return event;
  }

  verify(): ChainCheck {
    const { events, corruptLines } = this.read();
    if (corruptLines.length) return { ok: false, seq: -1, reason: `corrupt_line:${corruptLines[0]}` };
    return verifyChain(events, this.hostKey.publicKey, this.hostKey.keyId);
  }
}
