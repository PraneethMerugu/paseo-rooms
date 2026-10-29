// Atomic, durable private writes and single-call appends (grants-v2 7.3; audit X-4, X-6, X-15).
//
// What "durable" means here, per OS (do not claim more):
// - Linux (and WSL on ext4): file fsync, rename, directory fsync. Tested on Linux.
// - macOS: same calls. Whether libuv's fsync is F_FULLFSYNC on Paseo's runtime is unverified.
// - Windows: file flush (FlushFileBuffers through fs.fsync), rename with retry. There is no directory
//   flush through Node, so a power loss right after the rename can lose the rename (dirSync
//   "skipped"). Untested on Windows.
// A directory fsync that the filesystem refuses (EINVAL, ENOTSUP, EISDIR, EPERM) is reported as
// "unsupported", not as success; any other error is thrown.
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { defaultProtection, type FileProtection } from "./file-protection";

/** Typed write failure (grants-v2 7.2): the caller reports `persist_failed`. Message holds no full path. */
export class PersistFailedError extends Error {
  readonly code = "persist_failed";
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "PersistFailedError";
  }
}

export type DirSync = "synced" | "unsupported" | "skipped" | "not_needed";

export interface WriteResult {
  /** Whether the directory entry (the rename) was flushed. "skipped" on win32, by design. */
  dirSync: DirSync;
}

export interface DurableDeps {
  platform: NodeJS.Platform;
  protection: FileProtection;
  writeSync: (fd: number, buf: Buffer, off: number, len: number) => number;
  fsyncSync: (fd: number) => void;
  closeSync: (fd: number) => void;
  openSync: (p: string, flags: string) => number;
  renameSync: (from: string, to: string) => void;
  unlinkSync: (p: string) => void;
  /** Blocking sleep for the rename backoff. */
  sleepSync: (ms: number) => void;
  now: () => number;
}

const sleepCell = new Int32Array(new SharedArrayBuffer(4));

function defaultDeps(): DurableDeps {
  return {
    platform: process.platform,
    protection: defaultProtection(),
    writeSync: (fd, buf, off, len) => fs.writeSync(fd, buf, off, len),
    fsyncSync: fs.fsyncSync,
    closeSync: fs.closeSync,
    openSync: (p, f) => fs.openSync(p, f),
    renameSync: fs.renameSync,
    unlinkSync: fs.unlinkSync,
    sleepSync: (ms) => void Atomics.wait(sleepCell, 0, 0, ms),
    now: Date.now,
  };
}

function withDefaults(deps?: Partial<DurableDeps>): DurableDeps {
  return deps ? { ...defaultDeps(), ...deps } : defaultDeps();
}

function errCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException)?.code;
}

/** Windows sharing violations (antivirus, indexer, backup) that clear on their own. */
const RENAME_RETRY_CODES = new Set(["EPERM", "EACCES", "EBUSY"]);
export const RENAME_RETRY_MS = 2_000;
const DIR_FSYNC_UNSUPPORTED = new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]);

/** fsync a directory so a rename or a new file in it survives a power cut. */
export function fsyncDir(dir: string, deps?: Partial<DurableDeps>): DirSync {
  const d = withDefaults(deps);
  if (d.platform === "win32") return "skipped";
  let fd: number | null = null;
  try {
    fd = d.openSync(dir, "r");
    d.fsyncSync(fd);
    return "synced";
  } catch (e) {
    if (DIR_FSYNC_UNSUPPORTED.has(errCode(e) ?? "")) return "unsupported";
    throw e;
  } finally {
    if (fd !== null) d.closeSync(fd);
  }
}

function writeAll(d: DurableDeps, fd: number, buf: Buffer): void {
  let off = 0;
  while (off < buf.length) off += d.writeSync(fd, buf, off, buf.length - off);
}

function renameWithRetry(d: DurableDeps, from: string, to: string): void {
  const start = d.now();
  let delay = 10;
  for (;;) {
    try {
      d.renameSync(from, to);
      return;
    } catch (e) {
      const retryable = d.platform === "win32" && RENAME_RETRY_CODES.has(errCode(e) ?? "");
      if (!retryable || d.now() - start >= RENAME_RETRY_MS) throw e;
      d.sleepSync(Math.min(delay, Math.max(1, RENAME_RETRY_MS - (d.now() - start))));
      delay = Math.min(delay * 2, 250);
    }
  }
}

/**
 * Atomic, durable owner-only write: exclusive-create temp file in the same directory, write, fsync,
 * rename (win32: retried for up to 2 s), fsync the directory. The target is never deleted first. The
 * temp file is removed in `finally` if the rename did not happen, since it may hold key material.
 * Throws ProtectionError (directory not owner-only) or PersistFailedError.
 */
export function writePrivateFile(path: string, contents: string, deps?: Partial<DurableDeps>): WriteResult {
  const d = withDefaults(deps);
  const dir = nodePath.dirname(path);
  d.protection.ensureDir(dir);
  const name = nodePath.basename(path);
  const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  let renamed = false;
  try {
    const fd = d.protection.createFile(tmp, "wx");
    try {
      writeAll(d, fd, Buffer.from(contents, "utf8"));
      d.fsyncSync(fd);
    } finally {
      d.closeSync(fd);
    }
    renameWithRetry(d, tmp, path);
    renamed = true;
  } catch (e) {
    if ((e as Error)?.name === "ProtectionError") throw e;
    throw new PersistFailedError(`Saving ${name} failed (${errCode(e) ?? (e as Error)?.message?.slice(0, 80) ?? "error"})`, e);
  } finally {
    if (!renamed) {
      try {
        d.unlinkSync(tmp);
      } catch {
        // already gone, or never created
      }
    }
  }
  try {
    return { dirSync: fsyncDir(dir, d) };
  } catch (e) {
    throw new PersistFailedError(`Saved ${name}, but flushing its directory failed (${errCode(e) ?? "error"})`, e);
  }
}

/**
 * Appends one line (adds the newline) with a single write call, then fsyncs. Creates the file
 * owner-only if needed and then flushes the directory. A short write is an error (the torn-line rules
 * of the reader handle the partial line).
 */
export function appendLine(path: string, line: string, deps?: Partial<DurableDeps>): WriteResult {
  const d = withDefaults(deps);
  const dir = nodePath.dirname(path);
  d.protection.ensureDir(dir);
  let created = false;
  let fd: number;
  try {
    fd = d.protection.createFile(path, "ax");
    created = true;
  } catch (e) {
    if (errCode(e) !== "EEXIST") throw e;
    fd = d.openSync(path, "a");
  }
  const buf = Buffer.from(line.endsWith("\n") ? line : `${line}\n`, "utf8");
  try {
    const n = d.writeSync(fd, buf, 0, buf.length);
    if (n !== buf.length) throw new PersistFailedError(`Appending to ${nodePath.basename(path)} wrote ${n} of ${buf.length} bytes`);
    d.fsyncSync(fd);
  } finally {
    d.closeSync(fd);
  }
  return { dirSync: created ? fsyncDir(dir, d) : "not_needed" };
}

/** Reads JSON, or null if the file does not exist. A leading UTF-8 BOM is ignored (X-15). */
export function readJsonFile<T>(path: string): T | null {
  let text: string;
  try {
    text = fs.readFileSync(path, "utf8");
  } catch (e) {
    if (errCode(e) === "ENOENT") return null;
    throw e;
  }
  return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as T;
}
