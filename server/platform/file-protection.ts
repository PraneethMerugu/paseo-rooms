// Owner-only protection for everything under plugin-data/rooms (identity-model 7.8; audit X-1, X-2).
//
// Set on creation, verified at every start, never repaired silently: `fix` runs only when the user
// asks (the "Fix permissions" RPC). One interface, one backend per OS:
//
// - posix (Linux, macOS, WSL, Docker, other Unixes): explicit modes on create, then chmod and read the
//   mode back (refuses if it did not take effect, which catches WSL drvfs); the check lstats the whole
//   tree, refuses symlinks, requires owner == geteuid and no group or other bits.
// - win32: DACLs. Node has no ACL API and this plugin bundles no native module, so the backend runs
//   fixed system binaries by absolute path through execFileSync (no shell): icacls.exe with SID syntax
//   to set, whoami.exe for the user SID, and PowerShell 5.1 `Get-Acl ... .Sddl` to read (SDDL, never
//   localized icacls text). The path reaches PowerShell through an environment variable, not the
//   script text, so no quoting is involved. If a tool is missing, the check reports "unverifiable"
//   and the caller refuses to load keys (safe fallback; there is no silent downgrade).
// - unsupported (any other platform value): creates with POSIX modes but reports "unverifiable".
//
// Platform status: Linux tested (unit tests, real fs). macOS, WSL (/mnt/c), Docker volumes: untested.
// Windows: logic tested on Linux with a simulated platform and fake exec; never run on Windows.
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import nodePath from "node:path";

export type ProtectionProblemCode =
  | "symlink"
  | "reparse_point"
  | "foreign_owner"
  | "mode"
  | "mode_not_applied"
  | "not_file_or_dir"
  | "acl"
  | "acl_not_protected"
  | "unverifiable"
  | "io";

export interface ProtectionProblem {
  /** Relative to the checked root ("." for the root itself). Never an absolute path (X-7). */
  path: string;
  code: ProtectionProblemCode;
  detail: string;
}

export type VerifyResult = { ok: true } | { ok: false; problems: ProtectionProblem[] };

/** Typed startup and write error: the data directory is not owner-only, or cannot be checked. */
export class ProtectionError extends Error {
  readonly code = "permission_error";
  constructor(readonly problems: ProtectionProblem[]) {
    const shown = problems.slice(0, 3).map((p) => `${p.path}: ${p.detail}`);
    const more = problems.length > 3 ? ` (and ${problems.length - 3} more)` : "";
    super(`Rooms data is not protected: ${shown.join("; ")}${more}. Use "Fix permissions" in Rooms, or fix them by hand.`);
    this.name = "ProtectionError";
  }
}

export interface FileProtection {
  readonly backend: "posix" | "win32" | "unsupported";
  /** Creates the directory (and missing parents) owner-only, or checks an existing one. Throws ProtectionError. */
  ensureDir(path: string): void;
  /** Opens a NEW file owner-only with exclusive create ("wx" or "ax"); returns the fd. EEXIST is thrown as is. */
  createFile(path: string, flags?: "wx" | "ax"): number;
  /** Checks one entry. */
  verify(path: string): VerifyResult;
  /** Checks the root and everything below it. */
  verifyTree(root: string): VerifyResult;
  /** Explicit, user-requested repair of what can be repaired; returns the check after the repair. */
  fix(root: string): VerifyResult;
}

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

function errCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException)?.code;
}

function rel(root: string, p: string, path: typeof nodePath.posix): string {
  return path.relative(root, p) || ".";
}

function result(problems: ProtectionProblem[]): VerifyResult {
  return problems.length ? { ok: false, problems } : { ok: true };
}

/** Walks a tree with lstat, never following links. Calls visit for every entry including the root. */
function walk(root: string, deps: { lstatSync: typeof fs.lstatSync; readdirSync: (p: string) => string[] }, join: (a: string, b: string) => string, visit: (p: string, st: fs.Stats) => void): void {
  const stack = [root];
  while (stack.length) {
    const p = stack.pop()!;
    const st = deps.lstatSync(p);
    visit(p, st);
    if (st.isDirectory() && !st.isSymbolicLink()) for (const name of deps.readdirSync(p)) stack.push(join(p, name));
  }
}

/** Missing path components from the deepest existing ancestor down to `path`. */
function missingComponents(path: string, lstat: (p: string) => fs.Stats, dirname: (p: string) => string): string[] {
  const missing: string[] = [];
  let cur = path;
  for (;;) {
    try {
      lstat(cur);
      return missing;
    } catch (e) {
      if (errCode(e) !== "ENOENT") throw e;
      missing.unshift(cur);
      const parent = dirname(cur);
      if (parent === cur) return missing;
      cur = parent;
    }
  }
}

// ------------------------------------------------------------------------------------------- POSIX

export interface PosixDeps {
  lstatSync: typeof fs.lstatSync;
  mkdirSync: (p: string, opts: { mode: number }) => void;
  chmodSync: (p: string, mode: number) => void;
  openSync: (p: string, flags: string, mode: number) => number;
  fchmodSync: (fd: number, mode: number) => void;
  fstatSync: (fd: number) => fs.Stats;
  closeSync: (fd: number) => void;
  unlinkSync: (p: string) => void;
  readdirSync: (p: string) => string[];
  /** Undefined where the runtime has no geteuid; the owner check is then skipped and reported. */
  geteuid: (() => number) | undefined;
}

const realPosixDeps = (): PosixDeps => ({
  lstatSync: fs.lstatSync,
  mkdirSync: (p, o) => void fs.mkdirSync(p, o),
  chmodSync: fs.chmodSync,
  openSync: (p, f, m) => fs.openSync(p, f, m),
  fchmodSync: fs.fchmodSync,
  fstatSync: (fd) => fs.fstatSync(fd),
  closeSync: fs.closeSync,
  unlinkSync: fs.unlinkSync,
  readdirSync: (p) => fs.readdirSync(p),
  geteuid: typeof process.geteuid === "function" ? process.geteuid.bind(process) : undefined,
});

export function posixProtection(deps: PosixDeps = realPosixDeps()): FileProtection {
  const path = nodePath.posix;

  function checkEntry(root: string, p: string, st: fs.Stats): ProtectionProblem[] {
    const where = rel(root, p, path);
    if (st.isSymbolicLink()) return [{ path: where, code: "symlink", detail: "is a symbolic link" }];
    if (!st.isDirectory() && !st.isFile()) return [{ path: where, code: "not_file_or_dir", detail: "is not a regular file or directory" }];
    const out: ProtectionProblem[] = [];
    if (!deps.geteuid) out.push({ path: where, code: "unverifiable", detail: "owner cannot be checked (no geteuid)" });
    else if (st.uid !== deps.geteuid()) out.push({ path: where, code: "foreign_owner", detail: `owned by uid ${st.uid}, not the daemon's uid ${deps.geteuid()}` });
    if ((st.mode & 0o077) !== 0) out.push({ path: where, code: "mode", detail: `mode ${(st.mode & 0o777).toString(8)}, group or others have access` });
    return out;
  }

  function setAndReadBack(p: string, mode: number, root: string): void {
    deps.chmodSync(p, mode);
    const got = deps.lstatSync(p).mode & 0o777;
    if (got !== mode) {
      throw new ProtectionError([{ path: rel(root, p, path), code: "mode_not_applied", detail: `chmod ${mode.toString(8)} did not take effect (mode is ${got.toString(8)}; a filesystem without POSIX permissions, such as WSL /mnt/c without "metadata")` }]);
    }
  }

  const api: FileProtection = {
    backend: "posix",
    ensureDir(dir) {
      const missing = missingComponents(dir, deps.lstatSync, path.dirname);
      if (!missing.length) {
        const st = deps.lstatSync(dir);
        const problems = st.isDirectory() || st.isSymbolicLink() ? checkEntry(path.dirname(dir), dir, st) : [{ path: path.basename(dir), code: "not_file_or_dir" as const, detail: "is not a directory" }];
        if (problems.length) throw new ProtectionError(problems);
        return;
      }
      for (const m of missing) {
        try {
          deps.mkdirSync(m, { mode: DIR_MODE });
        } catch (e) {
          if (errCode(e) !== "EEXIST") throw e;
          const problems = checkEntry(path.dirname(m), m, deps.lstatSync(m));
          if (problems.length) throw new ProtectionError(problems);
          continue;
        }
        setAndReadBack(m, DIR_MODE, path.dirname(m));
      }
    },
    createFile(file, flags = "wx") {
      const fd = deps.openSync(file, flags, FILE_MODE);
      try {
        deps.fchmodSync(fd, FILE_MODE);
        const got = deps.fstatSync(fd).mode & 0o777;
        if (got !== FILE_MODE) {
          throw new ProtectionError([{ path: path.basename(file), code: "mode_not_applied", detail: `chmod 600 did not take effect (mode is ${got.toString(8)}; a filesystem without POSIX permissions, such as WSL /mnt/c without "metadata")` }]);
        }
        return fd;
      } catch (e) {
        deps.closeSync(fd);
        try {
          deps.unlinkSync(file);
        } catch {
          // best effort: the file is empty
        }
        throw e;
      }
    },
    verify(p) {
      try {
        return result(checkEntry(path.dirname(p), p, deps.lstatSync(p)));
      } catch (e) {
        return result([{ path: path.basename(p), code: "io", detail: `cannot be checked (${errCode(e) ?? "error"})` }]);
      }
    },
    verifyTree(root) {
      const problems: ProtectionProblem[] = [];
      try {
        walk(root, deps, path.join, (p, st) => problems.push(...checkEntry(root, p, st)));
      } catch (e) {
        problems.push({ path: ".", code: "io", detail: `cannot be checked (${errCode(e) ?? "error"})` });
      }
      return result(problems);
    },
    fix(root) {
      const problems: ProtectionProblem[] = [];
      try {
        walk(root, deps, path.join, (p, st) => {
          // Symlinks and foreign owners are never "fixed": that needs a human decision.
          if (st.isSymbolicLink() || (deps.geteuid && st.uid !== deps.geteuid())) return;
          const want = st.isDirectory() ? DIR_MODE : st.isFile() ? FILE_MODE : null;
          if (want === null || (st.mode & 0o777) === want) return;
          try {
            setAndReadBack(p, want, root);
          } catch (e) {
            if (e instanceof ProtectionError) problems.push(...e.problems);
            else problems.push({ path: rel(root, p, path), code: "io", detail: `chmod failed (${errCode(e) ?? "error"})` });
          }
        });
      } catch (e) {
        problems.push({ path: ".", code: "io", detail: `cannot be read (${errCode(e) ?? "error"})` });
      }
      const after = api.verifyTree(root);
      return after.ok && !problems.length ? after : result([...problems, ...(after.ok ? [] : after.problems)]);
    },
  };
  return api;
}

// ------------------------------------------------------------------------------------------- Win32

/** Runs a program without a shell; returns stdout. Throws on spawn failure, non-zero exit or timeout. */
export type ExecFile = (file: string, args: string[], opts: { env?: NodeJS.ProcessEnv; timeoutMs: number }) => string;

export interface Win32Deps {
  lstatSync: typeof fs.lstatSync;
  mkdirSync: (p: string) => void;
  openSync: (p: string, flags: string, mode: number) => number;
  readdirSync: (p: string) => string[];
  realpathNative: (p: string) => string;
  exec: ExecFile;
  env: NodeJS.ProcessEnv;
}

const realExec: ExecFile = (file, args, opts) =>
  execFileSync(file, args, { encoding: "utf8", env: opts.env, timeout: opts.timeoutMs, windowsHide: true, shell: false, stdio: ["ignore", "pipe", "pipe"] });

const realWin32Deps = (): Win32Deps => ({
  lstatSync: fs.lstatSync,
  mkdirSync: (p) => void fs.mkdirSync(p),
  openSync: (p, f, m) => fs.openSync(p, f, m),
  readdirSync: (p) => fs.readdirSync(p),
  realpathNative: fs.realpathSync.native,
  exec: realExec,
  env: process.env,
});

export interface ParsedSddl {
  owner: string | null;
  /** DACL flags, e.g. "P", "AI", "PAI". */
  daclFlags: string;
  aces: { type: string; flags: string; rights: string; sid: string }[];
}

/** Minimal SDDL reader: owner, DACL flags and ACEs (type;flags;rights;guid;guid;sid). */
export function parseSddl(sddl: string): ParsedSddl {
  const s = sddl.trim();
  const owner = /O:(.+?)(?=G:|D:|S:|$)/.exec(s)?.[1] ?? null;
  const d = s.indexOf("D:");
  if (d < 0) return { owner, daclFlags: "", aces: [] };
  let i = d + 2;
  let daclFlags = "";
  while (i < s.length && s[i] !== "(" && !(s[i] === "S" && s[i + 1] === ":")) daclFlags += s[i++];
  const aces: ParsedSddl["aces"] = [];
  while (i < s.length && s[i] === "(") {
    const end = s.indexOf(")", i);
    if (end < 0) break;
    const parts = s.slice(i + 1, end).split(";");
    aces.push({ type: parts[0] ?? "", flags: parts[1] ?? "", rights: parts[2] ?? "", sid: (parts[5] ?? "").toUpperCase() });
    i = end + 1;
  }
  return { owner: owner?.toUpperCase() ?? null, daclFlags, aces };
}

const SYSTEM_SIDS = new Set(["SY", "S-1-5-18"]);
const DENY_TYPES = new Set(["D", "OD", "XD"]);

/** Checks one SDDL against identity-model 7.8. `root` entries must have a protected DACL (D:P). */
export function checkSddl(sddl: string, userSid: string, opts: { root: boolean }): { code: ProtectionProblemCode; detail: string }[] {
  const parsed = parseSddl(sddl);
  const user = userSid.toUpperCase();
  const out: { code: ProtectionProblemCode; detail: string }[] = [];
  if (parsed.owner !== user) out.push({ code: "foreign_owner", detail: `owner is ${parsed.owner ?? "unknown"}, not the daemon user` });
  // Children may inherit from the protected root (all their ACEs are still checked below); the root
  // itself must not inherit from outside the tree.
  if (opts.root && !parsed.daclFlags.includes("P")) out.push({ code: "acl_not_protected", detail: "the access list inherits from its parent (not protected)" });
  for (const ace of parsed.aces) {
    if (DENY_TYPES.has(ace.type)) continue;
    if (ace.sid === user || SYSTEM_SIDS.has(ace.sid)) continue;
    out.push({ code: "acl", detail: `${ace.sid} has access` });
  }
  if (!parsed.aces.some((a) => a.sid === user && !DENY_TYPES.has(a.type))) out.push({ code: "acl", detail: "the daemon user has no access entry" });
  return out;
}

/** Case-folded, separator-normalised Windows path for comparisons (R-11). */
export function foldWin32Path(p: string): string {
  let s = p.replace(/\//g, "\\");
  if (s.startsWith("\\\\?\\UNC\\")) s = `\\\\${s.slice(8)}`;
  else if (s.startsWith("\\\\?\\")) s = s.slice(4);
  s = s.replace(/\\+$/, "");
  return s.toLowerCase();
}

/** Fixed PowerShell script: the path comes from the environment, never from the script text. */
const SDDL_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "[Console]::OutputEncoding=[Text.Encoding]::UTF8",
  "$r=Get-Item -LiteralPath $env:PASEO_ROOMS_ACL_PATH -Force",
  "$items=@($r)",
  "if($r.PSIsContainer -and $env:PASEO_ROOMS_ACL_RECURSE -eq '1'){$items+=@(Get-ChildItem -LiteralPath $r.FullName -Recurse -Force)}",
  "foreach($i in $items){(Get-Acl -LiteralPath $i.FullName).Sddl+'|'+$i.FullName}",
].join(";");

const EXEC_TIMEOUT_MS = 15_000;

export function win32Protection(deps: Win32Deps = realWin32Deps()): FileProtection {
  const path = nodePath.win32;
  const sysRoot = deps.env.SystemRoot || deps.env.windir || "C:\\Windows";
  const tool = {
    icacls: path.join(sysRoot, "System32", "icacls.exe"),
    whoami: path.join(sysRoot, "System32", "whoami.exe"),
    powershell: path.join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
  };
  let sid: string | null = null;

  function userSid(): string {
    if (sid) return sid;
    const out = deps.exec(tool.whoami, ["/user", "/fo", "csv", "/nh"], { timeoutMs: EXEC_TIMEOUT_MS });
    const m = /S-1-\d+(?:-\d+)+/.exec(out);
    if (!m) throw new Error("whoami returned no SID");
    sid = m[0].toUpperCase();
    return sid;
  }

  /** Explicit owner-only DACL, inheritance removed. Arguments are a path and a SID only. */
  function applyAcl(p: string, isDir: boolean): void {
    deps.exec(tool.icacls, [p, "/inheritance:r", "/grant:r", `*${userSid()}:${isDir ? "(OI)(CI)F" : "F"}`], { timeoutMs: EXEC_TIMEOUT_MS });
  }

  function readSddl(p: string, recurse: boolean): { path: string; sddl: string }[] {
    const out = deps.exec(tool.powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SDDL_SCRIPT], {
      env: { ...deps.env, PASEO_ROOMS_ACL_PATH: p, PASEO_ROOMS_ACL_RECURSE: recurse ? "1" : "0" },
      timeoutMs: EXEC_TIMEOUT_MS,
    });
    return out
      .split(/\r?\n/)
      .filter((l) => l.includes("|"))
      .map((l) => {
        const cut = l.indexOf("|");
        return { sddl: l.slice(0, cut), path: l.slice(cut + 1).trim() };
      });
  }

  function unverifiable(where: string, e: unknown): ProtectionProblem {
    return { path: where, code: "unverifiable", detail: `access list cannot be read or set (${errCode(e) ?? (e as Error)?.message?.slice(0, 80) ?? "error"}); keys are not loaded` };
  }

  /** lstat walk: refuses symlinks and junctions, and directories whose real path differs (R-11). */
  function checkLinks(root: string): { problems: ProtectionProblem[]; entries: string[] } {
    const problems: ProtectionProblem[] = [];
    const entries: string[] = [];
    walk(root, deps, path.join, (p, st) => {
      entries.push(p);
      const where = rel(root, p, path);
      if (st.isSymbolicLink()) problems.push({ path: where, code: "reparse_point", detail: "is a symbolic link or junction" });
      else if (st.isDirectory() && foldWin32Path(deps.realpathNative(p)) !== foldWin32Path(p)) problems.push({ path: where, code: "reparse_point", detail: "resolves to a different location" });
      else if (!st.isDirectory() && !st.isFile()) problems.push({ path: where, code: "not_file_or_dir", detail: "is not a regular file or directory" });
    });
    return { problems, entries };
  }

  function checkAcls(root: string, recurse: boolean): ProtectionProblem[] {
    let rows: { path: string; sddl: string }[];
    let user: string;
    try {
      user = userSid();
      rows = readSddl(root, recurse);
    } catch (e) {
      return [unverifiable(".", e)];
    }
    if (!rows.length) return [unverifiable(".", new Error("no access lists returned"))];
    const rootKey = foldWin32Path(root);
    return rows.flatMap((r) => checkSddl(r.sddl, user, { root: foldWin32Path(r.path) === rootKey }).map((p) => ({ path: rel(root, r.path, path), ...p })));
  }

  const api: FileProtection = {
    backend: "win32",
    ensureDir(dir) {
      const missing = missingComponents(dir, deps.lstatSync, path.dirname);
      if (!missing.length) {
        // Existing directory: only the cheap link check here. The ACL check runs at start (verifyTree),
        // because each one spawns PowerShell.
        const st = deps.lstatSync(dir);
        if (st.isSymbolicLink()) throw new ProtectionError([{ path: path.basename(dir), code: "reparse_point", detail: "is a symbolic link or junction" }]);
        if (!st.isDirectory()) throw new ProtectionError([{ path: path.basename(dir), code: "not_file_or_dir", detail: "is not a directory" }]);
        return;
      }
      for (const m of missing) {
        try {
          deps.mkdirSync(m);
        } catch (e) {
          if (errCode(e) !== "EEXIST") throw e;
          continue;
        }
        try {
          applyAcl(m, true);
        } catch (e) {
          throw new ProtectionError([unverifiable(path.basename(m), e)]);
        }
      }
      // Read back the new top directory (the others inherit its DACL and also got their own).
      const problems = checkAcls(missing[0], false);
      if (problems.length) throw new ProtectionError(problems);
    },
    createFile(file, flags = "wx") {
      // Files inherit the owner-only DACL of their protected directory; a per-file icacls on every
      // write would spawn a process per write. The start check covers files as well.
      return deps.openSync(file, flags, FILE_MODE);
    },
    verify(p) {
      try {
        const st = deps.lstatSync(p);
        if (st.isSymbolicLink()) return result([{ path: path.basename(p), code: "reparse_point", detail: "is a symbolic link or junction" }]);
      } catch (e) {
        return result([{ path: path.basename(p), code: "io", detail: `cannot be checked (${errCode(e) ?? "error"})` }]);
      }
      let user: string;
      let rows: { path: string; sddl: string }[];
      try {
        user = userSid();
        rows = readSddl(p, false);
      } catch (e) {
        return result([unverifiable(path.basename(p), e)]);
      }
      return result(rows.flatMap((r) => checkSddl(r.sddl, user, { root: false }).map((x) => ({ path: path.basename(p), ...x }))));
    },
    verifyTree(root) {
      let links: { problems: ProtectionProblem[] };
      try {
        links = checkLinks(root);
      } catch (e) {
        return result([{ path: ".", code: "io", detail: `cannot be checked (${errCode(e) ?? "error"})` }]);
      }
      // Never ask PowerShell to recurse through a reparse point.
      if (links.problems.length) return result(links.problems);
      return result(checkAcls(root, true));
    },
    fix(root) {
      const before = api.verifyTree(root);
      if (before.ok) return before;
      if (before.problems.some((p) => p.code === "reparse_point" || p.code === "not_file_or_dir" || p.code === "io")) return before;
      const problems: ProtectionProblem[] = [];
      try {
        const { entries } = checkLinks(root);
        const user = userSid();
        const rootKey = foldWin32Path(root);
        for (const p of entries) {
          if (foldWin32Path(p) !== rootKey) {
            // Children: drop explicit entries and inherit the root's owner-only DACL.
            deps.exec(tool.icacls, [p, "/reset"], { timeoutMs: EXEC_TIMEOUT_MS });
            continue;
          }
          applyAcl(p, deps.lstatSync(p).isDirectory());
          // /inheritance:r and /grant:r keep other explicit entries on the root; remove them by SID.
          for (const r of readSddl(p, false)) {
            for (const ace of parseSddl(r.sddl).aces) {
              if (ace.sid !== user && !SYSTEM_SIDS.has(ace.sid) && !DENY_TYPES.has(ace.type) && ace.sid.startsWith("S-1-")) {
                deps.exec(tool.icacls, [p, "/remove:g", `*${ace.sid}`], { timeoutMs: EXEC_TIMEOUT_MS });
              }
            }
          }
        }
        // The owner is never changed here: taking ownership needs a privilege and a human decision.
      } catch (e) {
        problems.push(unverifiable(".", e));
      }
      const after = api.verifyTree(root);
      return after.ok && !problems.length ? after : result([...problems, ...(after.ok ? [] : after.problems)]);
    },
  };
  return api;
}

// ------------------------------------------------------------------------------------- Unsupported

/** Any platform that is neither POSIX-like nor win32: creates with modes, but cannot verify. */
export function unsupportedProtection(platform: string): FileProtection {
  const posix = posixProtection();
  const no = (p: string): VerifyResult => result([{ path: p, code: "unverifiable", detail: `file protection is not implemented for platform ${platform}` }]);
  return { ...posix, backend: "unsupported", verify: () => no("."), verifyTree: () => no("."), fix: () => no(".") };
}

const POSIX_PLATFORMS = new Set<string>(["linux", "darwin", "freebsd", "openbsd", "netbsd", "sunos", "aix", "android", "cygwin"]);

export function createFileProtection(platform: NodeJS.Platform = process.platform): FileProtection {
  if (platform === "win32") return win32Protection();
  if (POSIX_PLATFORMS.has(platform)) return posixProtection();
  return unsupportedProtection(platform);
}

let shared: FileProtection | null = null;

/** The process-wide backend for process.platform. */
export function defaultProtection(): FileProtection {
  shared ??= createFileProtection();
  return shared;
}
