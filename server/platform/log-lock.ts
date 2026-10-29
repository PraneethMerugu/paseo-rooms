// Single-writer lock for one room log directory (grants-v2 7.3, re-review R-6; closes S-20).
//
// `writer.lock` is created with exclusive create and holds the pid and a random 128-bit instance id.
// No flock (Windows lacks it) and no trust in the pid (reused, especially in containers).
// 1. Heartbeat: the holder sets the lock's mtime every 10 s.
// 2. Ownership check before every append: read the lock, compare the instance id. On a mismatch or a
//    missing file the holder has lost the lock: it appends nothing, stops, reports `log_lock_lost`,
//    and never re-creates the lock itself.
// 3. Staleness: mtime older than 60 s. A waiter waits 30 s and checks the mtime did not move.
// 4. Atomic takeover: rename the stale lock to `writer.lock.stale.<own id>` (only one rename of a
//    source succeeds), create a new lock with `wx`, read it back. The caller then reloads the log.
// 5. Clean shutdown deletes the lock.
// Residual (accepted in the spec): a holder that stalls between its check and its write for more than
// 90 s can still write one line after a takeover; members detect that as a fork.
//
// Platform status: Linux tested (unit tests with a faked clock on a real filesystem). macOS, Windows,
// WSL (/mnt/c mtimes) and Docker bind mounts: untested.
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { log } from "../log";
import { appendLine, type DurableDeps, type WriteResult } from "./durable";
import { defaultProtection, type FileProtection } from "./file-protection";

export const LOCK_FILE = "writer.lock";
export const HEARTBEAT_MS = 10_000;
export const STALE_MS = 60_000;
export const STALE_WAIT_MS = 30_000;
const MAX_ATTEMPTS = 5;

export class LogLockHeldError extends Error {
  readonly code = "log_locked";
  constructor(detail = "another process is writing this room log") {
    super(`The room log is locked: ${detail}.`);
    this.name = "LogLockHeldError";
  }
}

export class LogLockLostError extends Error {
  readonly code = "log_lock_lost";
  constructor(detail: string) {
    super(`This process no longer holds the room log lock (${detail}); it stopped writing to the log.`);
    this.name = "LogLockLostError";
  }
}

interface LockContent {
  v: 1;
  pid: number;
  instanceId: string;
  createdAt: string;
}

export interface LogLockOptions {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  setInterval?: (fn: () => void, ms: number) => unknown;
  clearInterval?: (handle: unknown) => void;
  protection?: FileProtection;
  /** Passed to appendLine (tests inject faults here). */
  durable?: Partial<DurableDeps>;
  /** Called once when ownership is lost: close room sessions and raise `log_lock_lost` in the UI. */
  onLost?: (reason: string) => void;
  pid?: number;
  instanceId?: string;
}

export type LockState = "idle" | "held" | "lost" | "released";

export class LogWriterLock {
  readonly instanceId: string;
  private readonly lockPath: string;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly protection: FileProtection;
  private timer: unknown = null;
  private _state: LockState = "idle";

  constructor(private readonly dir: string, private readonly opts: LogLockOptions = {}) {
    this.instanceId = opts.instanceId ?? randomBytes(16).toString("hex");
    this.lockPath = nodePath.join(dir, LOCK_FILE);
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.protection = opts.protection ?? defaultProtection();
  }

  get state(): LockState {
    return this._state;
  }

  /**
   * Takes the lock, waiting out a stale one. Throws LogLockHeldError if a live holder has it.
   * `tookOver` tells the caller that a previous holder died: reload the log from disk (torn-line rules)
   * before serving.
   */
  async acquire(): Promise<{ tookOver: boolean }> {
    if (this._state === "held") return { tookOver: false };
    if (this._state !== "idle") throw new Error(`lock is ${this._state}; use a new LogWriterLock`);
    this.protection.ensureDir(this.dir);
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      if (this.tryCreate()) return this.held(false);
      const seen = this.readAt(this.lockPath);
      if (!seen) continue; // vanished between create and read: try again
      if (this.now() - seen.mtimeMs <= STALE_MS) throw new LogLockHeldError();
      await this.sleep(STALE_WAIT_MS);
      const again = this.readAt(this.lockPath);
      if (!again || again.mtimeMs !== seen.mtimeMs || again.instanceId !== seen.instanceId) continue; // it moved
      const staleName = `${this.lockPath}.stale.${this.instanceId}`;
      try {
        fs.renameSync(this.lockPath, staleName);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") continue; // another waiter won
        throw e;
      }
      const moved = this.readAt(staleName);
      if (moved?.instanceId !== seen.instanceId) {
        // We renamed a fresh lock that replaced the stale one in between: put it back (link fails if a
        // lock exists again) and start over. If that fails, its holder sees its lock gone and stops.
        try {
          fs.linkSync(staleName, this.lockPath);
        } catch {
          // fail closed: the other holder will detect the loss before its next append
        }
        this.unlinkQuiet(staleName);
        continue;
      }
      const created = this.tryCreate();
      this.unlinkQuiet(staleName);
      if (created) return this.held(true);
    }
    throw new LogLockHeldError("the lock changed hands repeatedly while waiting");
  }

  /** Ownership check (R-6). Throws LogLockLostError, after which the lock is permanently lost. */
  assertOwned(): void {
    if (this._state === "lost") throw new LogLockLostError("lost earlier");
    if (this._state !== "held") throw new LogLockLostError(`lock is ${this._state}`);
    const cur = this.readAt(this.lockPath);
    if (!cur) this.lose("the lock file is missing");
    else if (cur.instanceId !== this.instanceId) this.lose("another process took the lock over");
  }

  /** Checks ownership, then appends one line with a single write and fsync. */
  append(path: string, line: string): WriteResult {
    this.assertOwned();
    return appendLine(path, line, { protection: this.protection, ...this.opts.durable });
  }

  /** One heartbeat: check ownership, then move the mtime. Called by the timer; public for tests. */
  heartbeat(): void {
    if (this._state !== "held") return;
    try {
      this.assertOwned();
      const t = this.now() / 1000;
      fs.utimesSync(this.lockPath, t, t);
    } catch (e) {
      if (this._state === "held") this.lose(`heartbeat failed (${(e as NodeJS.ErrnoException).code ?? "error"})`, false);
    }
  }

  /** Clean shutdown: stop the heartbeat and delete the lock if it is still ours. */
  release(): void {
    this.stopTimer();
    if (this._state === "held") {
      const cur = this.readAt(this.lockPath);
      if (cur?.instanceId === this.instanceId) this.unlinkQuiet(this.lockPath);
    }
    if (this._state !== "lost") this._state = "released";
  }

  // ---------------------------------------------------------------------------------- internals

  private held(tookOver: boolean): { tookOver: boolean } {
    this._state = "held";
    const setI = this.opts.setInterval ?? ((fn: () => void, ms: number) => setInterval(fn, ms));
    this.timer = setI(() => this.heartbeat(), HEARTBEAT_MS);
    (this.timer as { unref?: () => void })?.unref?.();
    return { tookOver };
  }

  private stopTimer(): void {
    if (this.timer === null) return;
    (this.opts.clearInterval ?? ((h: unknown) => clearInterval(h as ReturnType<typeof setInterval>)))(this.timer);
    this.timer = null;
  }

  private lose(reason: string, throwIt = true): never | void {
    this._state = "lost";
    this.stopTimer();
    log("log_lock_lost", { dir: nodePath.basename(this.dir), reason });
    try {
      this.opts.onLost?.(reason);
    } catch {
      // the lock is lost either way
    }
    if (throwIt) throw new LogLockLostError(reason);
  }

  /** Creates the lock with wx and reads it back. False if a lock exists. */
  private tryCreate(): boolean {
    let fd: number;
    try {
      fd = this.protection.createFile(this.lockPath, "wx");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw e;
    }
    const content: LockContent = { v: 1, pid: this.opts.pid ?? process.pid, instanceId: this.instanceId, createdAt: new Date(this.now()).toISOString() };
    try {
      fs.writeSync(fd, `${JSON.stringify(content)}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    const t = this.now() / 1000;
    fs.utimesSync(this.lockPath, t, t);
    return this.readAt(this.lockPath)?.instanceId === this.instanceId;
  }

  /** Lock content and mtime, or null if the file is missing. An unreadable body counts as foreign. */
  private readAt(p: string): { instanceId: string | null; mtimeMs: number } | null {
    try {
      const mtimeMs = fs.statSync(p).mtimeMs;
      let instanceId: string | null = null;
      try {
        const parsed = JSON.parse(fs.readFileSync(p, "utf8")) as Partial<LockContent>;
        instanceId = typeof parsed.instanceId === "string" ? parsed.instanceId : null;
      } catch {
        instanceId = null;
      }
      return { instanceId, mtimeMs };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
  }

  private unlinkQuiet(p: string): void {
    try {
      fs.unlinkSync(p);
    } catch {
      // already gone
    }
  }
}
