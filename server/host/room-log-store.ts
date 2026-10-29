// Host storage of one room log (room-log-v2.md section 8.1; identity-model.md section 7.1; C-11).
//
//   host/<roomId>/log/entries.jsonl   one line per entry:  RJCS({ entry, hash, hsig })
//   host/<roomId>/log/bodies.jsonl    one line per body:   RJCS({ seq, body: b64u })
//   host/<roomId>/log/writer.lock     the I-2 single-writer lock
//
// Append = body line, then entry line, each one write plus fsync, each after the lock's ownership
// check (LogWriterLock.append). The log is the source of truth: the host keeps no other copy of the
// fold state, and re-folds this file on every start (room-host.ts).
//
// Torn lines on load (section 8.1):
// - a final line without its newline, or a final line that is not strict RJCS of the expected shape,
//   is a torn write: its bytes are moved to `entries.torn.<unix ms>` (or `bodies.torn.<unix ms>`) and
//   the file is truncated to the last valid line. The host logs `log_torn_line`.
// - complete body lines past the last entry (a crash between the two appends) are moved aside the same
//   way: they were never acknowledged.
// - a bad line before the last one, a gap in `seq`, or an entry without its body is corruption: the
//   room stops (`RoomLogCorruptError`) and nothing is skipped or rewritten.
// A final line that parses but fails verification later (hash, signature, fold) is corruption, not a
// torn write: only a line that does not parse is attributed to a crash.
import * as fs from "node:fs";
import nodePath from "node:path";
import { b64u, b64uDecodeVar } from "../proto/b64u";
import { rjcs, rjcsParse, RJCS_MAX_BYTES, RJCS_MAX_FRAME_BYTES } from "../proto/rjcs";
import { SignedEntry } from "../authority/entries";
import { fsyncDir } from "../platform/durable";
import { defaultProtection, type FileProtection } from "../platform/file-protection";
import type { LogWriterLock } from "../platform/log-lock";
import { log } from "../log";

export const ENTRIES_FILE = "entries.jsonl";
export const BODIES_FILE = "bodies.jsonl";
/** One body line: an MLS body of up to 4 MiB in base64url, plus the wrapper. */
const BODY_LINE_MAX = Math.ceil((RJCS_MAX_FRAME_BYTES * 4) / 3) + 1024;

export function hostRoomDir(dataDir: string, roomId: string): string {
  return nodePath.join(dataDir, "host", roomId);
}

export function hostLogDir(dataDir: string, roomId: string): string {
  return nodePath.join(hostRoomDir(dataDir, roomId), "log");
}

/** Typed stop: the stored log is damaged before its last line. The owner UI shows it; nothing is served. */
export class RoomLogCorruptError extends Error {
  readonly code = "log_corrupt";
  constructor(
    readonly file: string,
    readonly line: number,
    detail: string,
  ) {
    super(`The room log is damaged (${file}, line ${line}: ${detail}). The room is stopped; lines are never skipped.`);
    this.name = "RoomLogCorruptError";
  }
}

export type StoredRecord = { signed: SignedEntry; body: Uint8Array };

export type TornReport = { file: string; movedTo: string; bytes: number; reason: "no_newline" | "unparsable" | "orphan_body" };

type Line = { text: string; start: number; end: number; complete: boolean };

function splitLines(buf: Buffer): Line[] {
  const lines: Line[] = [];
  let start = 0;
  while (start < buf.length) {
    const nl = buf.indexOf(0x0a, start);
    const end = nl === -1 ? buf.length : nl;
    lines.push({ text: buf.subarray(start, end).toString("utf8"), start, end: nl === -1 ? end : end + 1, complete: nl !== -1 });
    start = nl === -1 ? buf.length : nl + 1;
  }
  return lines;
}

function readOrEmpty(path: string): Buffer {
  try {
    return fs.readFileSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return Buffer.alloc(0);
    throw e;
  }
}

function parseEntryLine(text: string): SignedEntry | null {
  try {
    const value = rjcsParse(Buffer.from(text, "utf8"), RJCS_MAX_BYTES);
    const parsed = SignedEntry.safeParse(value);
    return parsed.success ? (value as SignedEntry) : null;
  } catch {
    return null;
  }
}

function parseBodyLine(text: string): { seq: number; body: Buffer } | null {
  try {
    if (text.length > BODY_LINE_MAX) return null;
    const value = rjcsParse(Buffer.from(text, "utf8"), BODY_LINE_MAX) as { seq?: unknown; body?: unknown };
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 2) return null;
    if (!Number.isSafeInteger(value.seq) || (value.seq as number) < 0 || typeof value.body !== "string") return null;
    return { seq: value.seq as number, body: b64uDecodeVar(value.body, RJCS_MAX_FRAME_BYTES) };
  } catch {
    return null;
  }
}

/**
 * The two log files of one room. Construct only while holding the room's LogWriterLock: `load` may
 * truncate a torn tail, and `append` writes through the lock's ownership check.
 */
export class RoomLogStore {
  readonly entriesPath: string;
  readonly bodiesPath: string;

  constructor(
    readonly dir: string,
    private readonly lock: LogWriterLock,
    private readonly now: () => number = Date.now,
    private readonly protection: FileProtection = defaultProtection(),
  ) {
    this.entriesPath = nodePath.join(dir, ENTRIES_FILE);
    this.bodiesPath = nodePath.join(dir, BODIES_FILE);
  }

  /**
   * Reads both files, moves a torn tail aside, and returns the records in `seq` order. Verification
   * of hashes, signatures and the fold is the caller's (room-host.ts re-folds every record).
   */
  load(): { records: StoredRecord[]; torn: TornReport[] } {
    const torn: TornReport[] = [];

    // ---- entries ----
    const ebuf = readOrEmpty(this.entriesPath);
    const elines = splitLines(ebuf);
    const entries: SignedEntry[] = [];
    let eValidEnd = 0;
    for (let i = 0; i < elines.length; i++) {
      const line = elines[i];
      const last = i === elines.length - 1;
      const parsed = line.complete ? parseEntryLine(line.text) : null;
      if (!parsed) {
        if (last) {
          torn.push(this.moveAside(this.entriesPath, "entries", ebuf, eValidEnd, line.complete ? "unparsable" : "no_newline"));
          break;
        }
        throw new RoomLogCorruptError(ENTRIES_FILE, i + 1, "not a valid entry line");
      }
      if (parsed.entry.seq !== entries.length) throw new RoomLogCorruptError(ENTRIES_FILE, i + 1, `seq ${parsed.entry.seq}, expected ${entries.length}`);
      entries.push(parsed);
      eValidEnd = line.end;
    }

    // ---- bodies ----
    const bbuf = readOrEmpty(this.bodiesPath);
    const blines = splitLines(bbuf);
    const bodies: Buffer[] = [];
    let bValidEnd = 0;
    for (let i = 0; i < blines.length; i++) {
      const line = blines[i];
      const last = i === blines.length - 1;
      const parsed = line.complete ? parseBodyLine(line.text) : null;
      if (!parsed) {
        if (last) {
          torn.push(this.moveAside(this.bodiesPath, "bodies", bbuf, bValidEnd, line.complete ? "unparsable" : "no_newline"));
          break;
        }
        throw new RoomLogCorruptError(BODIES_FILE, i + 1, "not a valid body line");
      }
      if (parsed.seq !== bodies.length) throw new RoomLogCorruptError(BODIES_FILE, i + 1, `seq ${parsed.seq}, expected ${bodies.length}`);
      bodies.push(parsed.body);
      bValidEnd = line.end;
    }

    // Body first, then entry: a body without its entry is an unacknowledged append; an entry
    // without its body cannot come from a crash.
    if (bodies.length < entries.length) throw new RoomLogCorruptError(BODIES_FILE, bodies.length + 1, `entry ${bodies.length} has no body`);
    if (bodies.length > entries.length) {
      const keepEnd = entries.length === 0 ? 0 : blines[entries.length - 1].end;
      // Recompute against the current file: a torn body tail may already have been moved.
      const current = readOrEmpty(this.bodiesPath);
      torn.push(this.moveAside(this.bodiesPath, "bodies", current, keepEnd, "orphan_body"));
      bodies.length = entries.length;
    }
    return { records: entries.map((signed, i) => ({ signed, body: bodies[i] })), torn };
  }

  /** Appends one record: the body line, then the entry line, each after the lock's ownership check. */
  append(signed: SignedEntry, body: Uint8Array): void {
    this.lock.append(this.bodiesPath, new TextDecoder().decode(rjcs({ seq: signed.entry.seq, body: b64u(body) }, BODY_LINE_MAX)));
    this.lock.append(this.entriesPath, new TextDecoder().decode(rjcs(signed)));
  }

  /** Copies the bytes after `keepEnd` to `<name>.torn.<unix ms>`, then truncates the file to `keepEnd`. */
  private moveAside(path: string, name: string, buf: Buffer, keepEnd: number, reason: TornReport["reason"]): TornReport {
    this.lock.assertOwned();
    const tail = buf.subarray(keepEnd);
    let target = nodePath.join(this.dir, `${name}.torn.${this.now()}`);
    for (let n = 1; fs.existsSync(target); n++) target = nodePath.join(this.dir, `${name}.torn.${this.now()}.${n}`);
    // The torn bytes are kept exactly (even a cut UTF-8 sequence), owner-only, flushed before the truncate.
    const out = this.protection.createFile(target, "wx");
    try {
      let off = 0;
      while (off < tail.length) off += fs.writeSync(out, tail, off, tail.length - off);
      fs.fsyncSync(out);
    } finally {
      fs.closeSync(out);
    }
    fsyncDir(this.dir);
    const fd = fs.openSync(path, "r+");
    try {
      fs.ftruncateSync(fd, keepEnd);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    log("log_torn_line", { file: nodePath.basename(path), reason, bytes: tail.length, movedTo: nodePath.basename(target) });
    return { file: nodePath.basename(path), movedTo: nodePath.basename(target), bytes: tail.length, reason };
  }
}
