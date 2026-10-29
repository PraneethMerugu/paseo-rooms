// Plugin data under $PASEO_HOME/plugin-data/rooms. Thin M1 wrapper over server/platform (identity v2
// I-2), so M1 code gets owner-only protection checks, the durable-write fixes and the daemon's home
// semantics now. New code imports server/platform directly.
import { join, relative } from "node:path";
import { appendLine, fsyncDir as platformFsyncDir, readJsonFile as platformReadJsonFile, writePrivateFile as platformWritePrivateFile } from "./platform/durable";
import { defaultProtection } from "./platform/file-protection";
import { resolvePaseoHome as platformResolvePaseoHome } from "./platform/home";

export function resolvePaseoHome(env: NodeJS.ProcessEnv = process.env): string {
  return platformResolvePaseoHome(env);
}

export function dataDir(home = resolvePaseoHome()): string {
  return join(home, "plugin-data", "rooms");
}

/** Creates the directory owner-only, or checks an existing one. Never repairs silently (throws ProtectionError). */
export function ensurePrivateDir(path: string): void {
  defaultProtection().ensureDir(path);
}

/** fsync a directory. Returns "unsupported" where the filesystem refuses and "skipped" on win32. */
export function fsyncDir(path: string): void {
  platformFsyncDir(path);
}

/**
 * Atomic, durable owner-only write (grants-v2 7.3). Durable on Linux once it returns; on Windows the
 * rename itself is not flushed (no directory flush through Node). Throws PersistFailedError.
 */
export function writePrivateFile(path: string, contents: string): void {
  platformWritePrivateFile(path, contents);
}

/** Appends one line (adds the newline) with a single write and fsyncs it. Creates the file owner-only. */
export function appendPrivateLine(path: string, line: string): void {
  appendLine(path, line);
}

export function readJsonFile<T>(path: string): T | null {
  return platformReadJsonFile<T>(path);
}

/** A path for logs: relative to `base` (X-7). Never the absolute path, which can contain the user name. */
export function logPath(base: string, path: string): string {
  return relative(base, path) || ".";
}
