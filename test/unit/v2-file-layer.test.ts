// I-2: file layer (audit X-1, X-2, X-4, X-6, X-7, X-8, X-9, X-15; grants-v2 7.3 log lock, R-6).
// POSIX checks run on the real Linux filesystem. Win32 branches run here with a simulated platform,
// fake fs and fake exec: that tests our logic, not Windows (untested). macOS, WSL and Docker: untested.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, symlinkSync, writeFileSync, type Stats } from "node:fs";
import nodePath, { join } from "node:path";
import { test } from "node:test";
import { registerAgentGuard, ROOM_LANE_ENV } from "../../server/gateway/agent-guard";
import { appendLine, fsyncDir, PersistFailedError, readJsonFile, RENAME_RETRY_MS, writePrivateFile } from "../../server/platform/durable";
import { checkSddl, foldWin32Path, parseSddl, posixProtection, ProtectionError, win32Protection, type PosixDeps, type Win32Deps } from "../../server/platform/file-protection";
import { canonicalHome, expandHomeDir, HomeResolutionError, resolvePaseoHome } from "../../server/platform/home";
import { HEARTBEAT_MS, LOCK_FILE, LogLockHeldError, LogLockLostError, LogWriterLock, STALE_MS } from "../../server/platform/log-lock";
import { logPath } from "../../server/paths";
import { RoomsRuntime } from "../../server/runtime";
import { tempDir } from "./helpers";

const realPosix = (): PosixDeps => ({
  lstatSync: fs.lstatSync,
  mkdirSync: (p, o) => void fs.mkdirSync(p, o),
  chmodSync: fs.chmodSync,
  openSync: (p, f, m) => fs.openSync(p, f, m),
  fchmodSync: fs.fchmodSync,
  fstatSync: (fd) => fs.fstatSync(fd),
  closeSync: fs.closeSync,
  unlinkSync: fs.unlinkSync,
  readdirSync: (p) => fs.readdirSync(p),
  geteuid: process.geteuid!.bind(process),
});

const mode = (p: string) => statSync(p).mode & 0o777;
const errno = (code: string) => Object.assign(new Error(code), { code });

// ------------------------------------------------------------------------------------------- home

test("X-8: home resolution copies the daemon's expandHomeDir", () => {
  const deps = { homedir: () => "/home/o", path: nodePath.posix };
  assert.equal(resolvePaseoHome({}, deps), "/home/o/.paseo");
  assert.equal(resolvePaseoHome({ PASEO_HOME: "~" }, deps), "/home/o");
  assert.equal(resolvePaseoHome({ PASEO_HOME: "~/x" }, deps), "/home/o/x");
  assert.equal(expandHomeDir("~\\x", deps), "~\\x", "the daemon does not expand ~\\ (not even on Windows)");
  assert.equal(expandHomeDir("~user/x", deps), "~user/x");
  assert.equal(expandHomeDir(" ~/x", deps), " ~/x", "no trimming");
  const win = { homedir: () => "C:\\Users\\o", path: nodePath.win32 };
  assert.equal(expandHomeDir("~/x", win), "C:\\Users\\o\\x");
  assert.equal(expandHomeDir("~\\x", win), "~\\x");
  // homedir() is only called for ~ forms; a failure is a typed "set PASEO_HOME" error.
  const broken = { homedir: () => { throw new Error("no passwd entry"); }, path: nodePath.posix };
  assert.equal(resolvePaseoHome({ PASEO_HOME: "/srv/paseo" }, broken), "/srv/paseo");
  assert.throws(() => resolvePaseoHome({}, broken), (e: unknown) => e instanceof HomeResolutionError && /set PASEO_HOME/i.test(e.message));
  assert.equal(canonicalHome("C:\\Users\\O\\.paseo", { platform: "win32", realpath: (p) => p }), "c:\\users\\o\\.paseo");
  assert.equal(canonicalHome("/Home/O", { platform: "linux", realpath: (p) => p }), "/Home/O");
});

test("X-7: log paths are relative, with the platform separator", () => {
  assert.equal(logPath("/a/b", "/a/b/c/d.json"), join("c", "d.json"));
  assert.equal(nodePath.win32.relative("C:\\Users\\o\\data", "C:\\Users\\o\\data\\rooms\\x.jsonl"), "rooms\\x.jsonl");
});

// ------------------------------------------------------------------------------------- POSIX check

test("X-2: ensureDir creates 0700, refuses an existing 0755 directory without repairing it", () => {
  const tmp = tempDir();
  try {
    const prot = posixProtection(realPosix());
    const d = join(tmp.dir, "a", "b");
    prot.ensureDir(d);
    assert.equal(mode(join(tmp.dir, "a")), 0o700);
    assert.equal(mode(d), 0o700);
    chmodSync(d, 0o755);
    assert.throws(() => prot.ensureDir(d), (e: unknown) => e instanceof ProtectionError && e.problems[0].code === "mode");
    assert.equal(mode(d), 0o755, "no silent repair");
  } finally {
    tmp.cleanup();
  }
});

test("X-2: verifyTree refuses a symlink, mode 0644 and a foreign owner; fix repairs only the mode", () => {
  const tmp = tempDir();
  try {
    const prot = posixProtection(realPosix());
    const root = join(tmp.dir, "rooms");
    writePrivateFile(join(root, "gateway", "state.json"), "{}", { protection: prot });
    assert.deepEqual(prot.verifyTree(root), { ok: true });

    chmodSync(join(root, "gateway", "state.json"), 0o644);
    const v = prot.verifyTree(root);
    assert.equal(v.ok, false);
    assert.deepEqual(!v.ok && v.problems.map((p) => [p.path, p.code]), [[join("gateway", "state.json"), "mode"]]);
    assert.ok(!v.ok && !v.problems[0].detail.includes(tmp.dir), "no absolute paths in problems");
    assert.deepEqual(prot.fix(root), { ok: true });
    assert.equal(mode(join(root, "gateway", "state.json")), 0o600);

    symlinkSync("/etc/hostname", join(root, "link"));
    const s = prot.verifyTree(root);
    assert.deepEqual(!s.ok && s.problems.map((p) => p.code), ["symlink"]);
    assert.equal(prot.fix(root).ok, false, "a symlink is never fixed");

    const foreign = posixProtection({ ...realPosix(), geteuid: () => process.geteuid!() + 1 });
    const f = foreign.verify(join(root, "gateway"));
    assert.deepEqual(!f.ok && f.problems.map((p) => p.code), ["foreign_owner"]);
  } finally {
    tmp.cleanup();
  }
});

test("X-2: a chmod that does not take effect (WSL drvfs) is refused, for directories and files", () => {
  const tmp = tempDir();
  try {
    const real = realPosix();
    const drvfs: PosixDeps = {
      ...real,
      chmodSync: () => undefined,
      fchmodSync: () => undefined,
      lstatSync: ((p: string) => {
        const st = real.lstatSync(p);
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { mode: (st.mode & ~0o777) | 0o777 });
      }) as PosixDeps["lstatSync"],
      fstatSync: (fd) => {
        const st = real.fstatSync(fd);
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { mode: (st.mode & ~0o777) | 0o777 });
      },
    };
    const prot = posixProtection(drvfs);
    assert.throws(() => prot.ensureDir(join(tmp.dir, "new")), (e: unknown) => e instanceof ProtectionError && e.problems[0].code === "mode_not_applied");
    assert.throws(() => prot.createFile(join(tmp.dir, "f"), "wx"), (e: unknown) => e instanceof ProtectionError && e.problems[0].code === "mode_not_applied");
    assert.equal(existsSync(join(tmp.dir, "f")), false, "the refused file is removed");
  } finally {
    tmp.cleanup();
  }
});

// ------------------------------------------------------------------------------------ durable write

test("X-4: a failing rename leaves no temp file and the old target intact", () => {
  const tmp = tempDir();
  try {
    const p = join(tmp.dir, "d", "state.json");
    writePrivateFile(p, "old");
    assert.throws(
      () => writePrivateFile(p, "new", { renameSync: () => { throw errno("EXDEV"); } }),
      (e: unknown) => e instanceof PersistFailedError && e.code === "persist_failed" && !e.message.includes(tmp.dir),
    );
    assert.deepEqual(readdirSync(join(tmp.dir, "d")), ["state.json"]);
    assert.equal(readFileSync(p, "utf8"), "old");
    // A failing write (disk full) also cleans up.
    assert.throws(() => writePrivateFile(p, "new", { writeSync: () => { throw errno("ENOSPC"); } }), PersistFailedError);
    assert.deepEqual(readdirSync(join(tmp.dir, "d")), ["state.json"]);
  } finally {
    tmp.cleanup();
  }
});

test("X-4: win32 rename retries EBUSY and succeeds; gives persist_failed after 2 s; POSIX does not retry", () => {
  const tmp = tempDir();
  try {
    const p = join(tmp.dir, "state.json");
    let t = 0;
    const sleeps: number[] = [];
    const clock = { now: () => t, sleepSync: (ms: number) => void (sleeps.push(ms), (t += ms)) };
    let fails = 2;
    const flaky = (from: string, to: string) => {
      if (fails-- > 0) throw errno("EBUSY");
      renameSync(from, to);
    };
    const r = writePrivateFile(p, "v1", { platform: "win32", renameSync: flaky, ...clock });
    assert.equal(readFileSync(p, "utf8"), "v1");
    assert.equal(sleeps.length, 2);
    assert.equal(r.dirSync, "skipped", "no directory flush on win32, and it says so");

    t = 0;
    sleeps.length = 0;
    assert.throws(
      () => writePrivateFile(p, "v2", { platform: "win32", renameSync: () => { throw errno("EPERM"); }, ...clock }),
      (e: unknown) => e instanceof PersistFailedError && e.code === "persist_failed",
    );
    assert.ok(t >= RENAME_RETRY_MS && t < RENAME_RETRY_MS + 300, `gave up after ${t} ms`);
    assert.deepEqual(readdirSync(tmp.dir), ["state.json"], "temp removed");
    assert.equal(readFileSync(p, "utf8"), "v1", "target never deleted first");

    let calls = 0;
    assert.throws(() => writePrivateFile(p, "v3", { platform: "linux", renameSync: () => { calls++; throw errno("EBUSY"); }, ...clock }), PersistFailedError);
    assert.equal(calls, 1);
  } finally {
    tmp.cleanup();
  }
});

test("X-6: directory fsync reports unsupported filesystems and rethrows real errors", () => {
  const tmp = tempDir();
  try {
    assert.equal(fsyncDir(tmp.dir), "synced");
    assert.equal(fsyncDir(tmp.dir, { platform: "win32" }), "skipped");
    assert.equal(fsyncDir(tmp.dir, { fsyncSync: () => { throw errno("EINVAL"); } }), "unsupported");
    assert.throws(() => fsyncDir(tmp.dir, { fsyncSync: () => { throw errno("EIO"); } }), /EIO/);
    let n = 0; // first fsync is the file, the second the directory
    const dirEio = { fsyncSync: (fd: number) => { if (n++ > 0) throw errno("EIO"); fs.fsyncSync(fd); } };
    assert.throws(() => writePrivateFile(join(tmp.dir, "x"), "1", dirEio), /flushing its directory failed/);
  } finally {
    tmp.cleanup();
  }
});

test("appendLine: one write per line, 0600 on create, a short write is an error", () => {
  const tmp = tempDir();
  try {
    const p = join(tmp.dir, "log", "entries.jsonl");
    let writes = 0;
    const counting = { writeSync: (fd: number, b: Buffer, o: number, l: number) => (writes++, fs.writeSync(fd, b, o, l)) };
    assert.equal(appendLine(p, "a", counting).dirSync, "synced");
    assert.equal(appendLine(p, "b\n", counting).dirSync, "not_needed");
    assert.equal(writes, 2);
    assert.equal(readFileSync(p, "utf8"), "a\nb\n");
    assert.equal(mode(p), 0o600);
    assert.throws(() => appendLine(p, "c", { writeSync: () => 1 }), PersistFailedError);
  } finally {
    tmp.cleanup();
  }
});

test("X-15: readJsonFile ignores a UTF-8 BOM and returns null for a missing file", () => {
  const tmp = tempDir();
  try {
    writeFileSync(join(tmp.dir, "limits.json"), "\uFEFF{\"a\":1}");
    assert.deepEqual(readJsonFile(join(tmp.dir, "limits.json")), { a: 1 });
    assert.equal(readJsonFile(join(tmp.dir, "missing.json")), null);
  } finally {
    tmp.cleanup();
  }
});

// ------------------------------------------------------------------------------------------- Win32

const USER = "S-1-5-21-1004336348-1177238915-682003330-1001";
const PROTECTED_ROOT = `O:${USER}G:${USER}D:P(A;OICI;FA;;;${USER})(A;OICI;FA;;;SY)`;

test("X-1: SDDL fixtures: a protected DACL with one user SID passes; inheriting or BU read access fails", () => {
  assert.deepEqual(checkSddl(PROTECTED_ROOT, USER, { root: true }), []);
  assert.deepEqual(checkSddl(`O:${USER}D:AI(A;ID;FA;;;${USER})`, USER, { root: false }), [], "a child may inherit from the protected root");
  assert.deepEqual(checkSddl(`O:${USER}D:AI(A;OICIID;FA;;;${USER})`, USER, { root: true }).map((p) => p.code), ["acl_not_protected"]);
  assert.deepEqual(checkSddl(`O:${USER}D:P(A;OICI;FA;;;${USER})(A;OICI;0x1200a9;;;BU)`, USER, { root: true }).map((p) => p.detail), ["BU has access"]);
  assert.deepEqual(checkSddl(`O:BAD:P(A;OICI;FA;;;${USER})`, USER, { root: true }).map((p) => p.code), ["foreign_owner"]);
  assert.deepEqual(checkSddl(`O:${USER}D:P(D;;FA;;;WD)(A;;FA;;;${USER})`, USER, { root: true }), [], "deny entries are fine");
  assert.equal(parseSddl(`O:${USER}G:SYD:PAI(A;;FA;;;SY)S:AI(AU;SA;FA;;;WD)`).aces.length, 1, "the SACL is not read as DACL");
  assert.equal(foldWin32Path("\\\\?\\C:\\Users\\O\\Data\\"), foldWin32Path("c:/users/o/data"));
});

function fakeStats(kind: "dir" | "file" | "link"): Stats {
  return { isDirectory: () => kind === "dir", isFile: () => kind === "file", isSymbolicLink: () => kind === "link", mode: 0o666, uid: 0 } as unknown as Stats;
}

function fakeWin(tree: Record<string, "dir" | "file" | "link">, sddl: Record<string, string>, over: Partial<Win32Deps> = {}) {
  const calls: { file: string; args: string[]; env?: NodeJS.ProcessEnv }[] = [];
  const W = nodePath.win32;
  const deps: Win32Deps = {
    lstatSync: ((p: string) => {
      if (!tree[p]) throw errno("ENOENT");
      return fakeStats(tree[p]);
    }) as Win32Deps["lstatSync"],
    mkdirSync: (p) => void (tree[p] = "dir"),
    openSync: () => 3,
    readdirSync: (p) => Object.keys(tree).filter((k) => W.dirname(k) === p && k !== p).map((k) => W.basename(k)),
    realpathNative: (p) => p.toUpperCase(), // casing differences only: must not count as a reparse point
    exec: (file, args, opts) => {
      calls.push({ file, args, env: opts.env });
      if (file.endsWith("whoami.exe")) return `"PC\\o","${USER}"\r\n`;
      if (file.endsWith("powershell.exe")) {
        const root = opts.env!.PASEO_ROOMS_ACL_PATH!;
        const keys = opts.env!.PASEO_ROOMS_ACL_RECURSE === "1" ? Object.keys(tree).filter((k) => k === root || k.startsWith(`${root}\\`)) : [root];
        return keys.map((k) => `${sddl[k]}|${k}`).join("\r\n");
      }
      return "";
    },
    env: { SystemRoot: "C:\\Windows" },
    ...over,
  };
  return { prot: win32Protection(deps), calls, tree };
}

test("X-1/X-2 win32 backend (simulated): tree check, absolute tools without a shell, reparse points, missing PowerShell", () => {
  const R = "C:\\Users\\o\\.paseo\\plugin-data\\rooms";
  const child = `O:${USER}D:AI(A;ID;FA;;;${USER})`;
  const tree = { [R]: "dir", [`${R}\\gateway`]: "dir", [`${R}\\gateway\\state.json`]: "file" } as Record<string, "dir" | "file" | "link">;
  const sddl = { [R]: PROTECTED_ROOT, [`${R}\\gateway`]: child, [`${R}\\gateway\\state.json`]: child };
  const ok = fakeWin({ ...tree }, sddl);
  assert.deepEqual(ok.prot.verifyTree(R), { ok: true });
  for (const c of ok.calls) assert.ok(nodePath.win32.isAbsolute(c.file) && c.file.startsWith("C:\\Windows\\System32\\"), c.file);
  const ps = ok.calls.find((c) => c.file.endsWith("powershell.exe"))!;
  assert.ok(!ps.args.join(" ").includes(R), "the path goes through the environment, not the script");
  assert.equal(ps.env!.PASEO_ROOMS_ACL_PATH, R);

  const leaky = fakeWin({ ...tree }, { ...sddl, [`${R}\\gateway\\state.json`]: `O:${USER}D:AI(A;ID;FA;;;${USER})(A;;FR;;;BU)` });
  const l = leaky.prot.verifyTree(R);
  assert.deepEqual(!l.ok && l.problems.map((p) => [p.path, p.code]), [["gateway\\state.json", "acl"]]);

  const linked = fakeWin({ ...tree, [`${R}\\member`]: "link" }, sddl);
  const j = linked.prot.verifyTree(R);
  assert.deepEqual(!j.ok && j.problems.map((p) => p.code), ["reparse_point"]);
  assert.ok(!linked.calls.some((c) => c.file.endsWith("powershell.exe")), "no recursion through a reparse point");

  const redirected = fakeWin({ ...tree }, sddl, { realpathNative: (p) => (p.endsWith("gateway") ? "D:\\elsewhere" : p) });
  assert.deepEqual((redirected.prot.verifyTree(R) as any).problems.map((p: any) => p.code), ["reparse_point"]);

  const noPs = fakeWin({ ...tree }, sddl, { exec: (file) => { if (file.endsWith("powershell.exe")) throw errno("ENOENT"); return `"PC\\o","${USER}"`; } });
  const u = noPs.prot.verifyTree(R);
  assert.deepEqual(!u.ok && u.problems.map((p) => p.code), ["unverifiable"], "safe fallback: refuse, never assume");
});

test("X-1 win32 backend (simulated): a new directory gets an explicit owner-only DACL by SID", () => {
  const R = "C:\\paseo\\plugin-data\\rooms";
  const w = fakeWin({ "C:\\paseo": "dir" }, { [`C:\\paseo\\plugin-data`]: PROTECTED_ROOT });
  w.prot.ensureDir(R);
  const icacls = w.calls.filter((c) => c.file.endsWith("icacls.exe"));
  assert.deepEqual(icacls.map((c) => c.args), [
    ["C:\\paseo\\plugin-data", "/inheritance:r", "/grant:r", `*${USER}:(OI)(CI)F`],
    [R, "/inheritance:r", "/grant:r", `*${USER}:(OI)(CI)F`],
  ]);
});

// ------------------------------------------------------------------------------------------- lock

test("R-6: log lock: a live holder blocks; a stalled holder loses ownership on takeover and stops appending", async () => {
  const tmp = tempDir();
  try {
    let t = Date.parse("2026-10-29T12:00:00Z");
    const fake = { now: () => t, setInterval: () => 1, clearInterval: () => undefined, sleep: async (ms: number) => void (t += ms) };
    const lost: string[] = [];
    const dir = join(tmp.dir, "log");
    const a = new LogWriterLock(dir, { ...fake, onLost: (r) => lost.push(r) });
    assert.deepEqual(await a.acquire(), { tookOver: false });
    const file = join(dir, "entries.jsonl");
    a.append(file, "e0");
    assert.equal(mode(join(dir, LOCK_FILE)), 0o600);

    const b = new LogWriterLock(dir, fake);
    t += HEARTBEAT_MS;
    a.heartbeat();
    await assert.rejects(b.acquire(), LogLockHeldError);

    // A stalls (laptop sleep): no heartbeat for longer than the stale time.
    t += STALE_MS + 1_000;
    const c = new LogWriterLock(dir, fake);
    assert.deepEqual(await c.acquire(), { tookOver: true });
    assert.ok(!readdirSync(dir).some((n) => n.includes(".stale.")), "renamed stale lock is deleted");
    assert.throws(() => a.append(file, "e1-from-stalled-holder"), LogLockLostError);
    assert.equal(lost.length, 1);
    assert.equal(a.state, "lost");
    a.heartbeat(); // never re-creates or touches the lock
    assert.throws(() => a.append(file, "again"), LogLockLostError);
    c.append(file, "e1");
    assert.equal(readFileSync(file, "utf8"), "e0\ne1\n");
    c.release();
    assert.equal(existsSync(join(dir, LOCK_FILE)), false, "clean shutdown deletes the lock");
  } finally {
    tmp.cleanup();
  }
});

test("R-6: a waiter that sees the stale lock's mtime move during the 30 s wait does not take over", async () => {
  const tmp = tempDir();
  try {
    let t = Date.parse("2026-10-29T12:00:00Z");
    const base = { now: () => t, setInterval: () => 1, clearInterval: () => undefined };
    const dir = join(tmp.dir, "log");
    const a = new LogWriterLock(dir, { ...base, sleep: async () => undefined });
    await a.acquire();
    t += STALE_MS + 1_000;
    // A wakes up during B's wait and heartbeats.
    const b = new LogWriterLock(dir, { ...base, sleep: async (ms) => { t += ms; a.heartbeat(); } });
    await assert.rejects(b.acquire(), LogLockHeldError);
    assert.equal(a.state, "held");
    a.append(join(dir, "entries.jsonl"), "ok");
    a.release();
  } finally {
    tmp.cleanup();
  }
});

// -------------------------------------------------------------------------------- runtime and guard

test("X-2: RoomsRuntime loads no keys when the start check fails, and starts after an explicit fix", async () => {
  const tmp = tempDir();
  const saved = process.env.PASEO_HOME;
  process.env.PASEO_HOME = tmp.dir;
  try {
    const data = join(tmp.dir, "plugin-data", "rooms");
    mkdirSync(join(data, "gateway"), { recursive: true, mode: 0o700 });
    chmodSync(join(tmp.dir, "plugin-data"), 0o700);
    chmodSync(data, 0o700);
    chmodSync(join(data, "gateway"), 0o700);
    writeFileSync(join(data, "limits.json"), "{}", { mode: 0o644 });
    chmodSync(join(data, "limits.json"), 0o644);
    const rt = new RoomsRuntime();
    assert.equal(rt.ready, false);
    assert.throws(() => rt.gateway, (e: unknown) => e instanceof ProtectionError && e.problems[0].path === "limits.json");
    assert.equal(existsSync(join(data, "gateway", "host-key.json")), false, "no key created or read");
    assert.equal(mode(join(data, "limits.json")), 0o644, "no silent repair");
    rt.start(); // no throw while not ready
    assert.deepEqual(rt.fixPermissions(), { ok: true, problems: [] });
    assert.equal(rt.ready, true);
    assert.equal(mode(join(data, "limits.json")), 0o600);
    assert.ok(existsSync(join(data, "gateway", "host-key.json")));
    await rt.stop();
  } finally {
    if (saved === undefined) delete process.env.PASEO_HOME;
    else process.env.PASEO_HOME = saved;
    tmp.cleanup();
  }
});

test("X-2: while not ready, the agent guard refuses room agent creates and writes nothing", () => {
  const tmp = tempDir();
  try {
    let handler: any = null;
    const server = { before: (name: string, h: any) => ((handler = name === "agent.create" ? h : handler), () => undefined) } as any;
    registerAgentGuard(server, tmp.dir, () => false);
    assert.equal(existsSync(join(tmp.dir, "inert-mcp.cjs")), false);
    assert.throws(() => handler({ request: { env: { [ROOM_LANE_ENV]: "lane_1" }, config: { provider: "claude" } } }), /permission check/);
    assert.equal(handler({ request: { env: {}, config: { provider: "claude" } } }), undefined, "other agents are untouched");
  } finally {
    tmp.cleanup();
  }
});
