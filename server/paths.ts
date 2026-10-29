// Plugin data under $PASEO_HOME/plugin-data/rooms (dir 0700, files 0600, atomic and durable writes).
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

export function resolvePaseoHome(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.PASEO_HOME?.trim() || "~/.paseo";
  return resolve(raw.startsWith("~") ? join(homedir(), raw.slice(1)) : raw);
}

export function dataDir(home = resolvePaseoHome()): string {
  return join(home, "plugin-data", "rooms");
}

export function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

/** fsync a directory so a rename or new file in it survives a power cut. Best effort where unsupported. */
export function fsyncDir(path: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    fsyncSync(fd);
  } catch {
    // Some platforms and filesystems refuse fsync on directories; the file itself is still synced.
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

function writeAllSync(fd: number, contents: string): void {
  const buf = Buffer.from(contents, "utf8");
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
}

/**
 * Atomic, durable write with mode 0600: temp file in the same directory, fsync, rename, fsync the
 * directory. Callers that change access state (revocation) rely on this being durable once it returns.
 */
export function writePrivateFile(path: string, contents: string): void {
  const dir = dirname(path);
  ensurePrivateDir(dir);
  const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeAllSync(fd, contents);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  fsyncDir(dir);
}

/** Appends one line (adds the newline) and fsyncs it. Creates the file 0600 if needed. */
export function appendPrivateLine(path: string, line: string): void {
  const dir = dirname(path);
  ensurePrivateDir(dir);
  const created = !existsSync(path);
  const fd = openSync(path, "a", 0o600);
  try {
    writeAllSync(fd, line.endsWith("\n") ? line : `${line}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, 0o600);
  if (created) fsyncDir(dir);
}

export function readJsonFile<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function fileMode(path: string): number {
  return statSync(path).mode & 0o777;
}
