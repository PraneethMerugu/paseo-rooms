// PASEO_HOME resolution with the daemon's exact semantics (X-8), and the canonical home used to name
// the KeyStore entry (identity-model 7.3).
//
// The daemon (Paseo 0.13.2, paseo-home.js, verified in app.asar) does:
//   raw = env.PASEO_HOME ?? "~/.paseo"; expand only "~" and a "~/" prefix; path.resolve.
// No trimming, an empty value is NOT treated as unset, and "~\x" or "~user" are not expanded. The
// plugin must read the same directory as the daemon, so it copies this exactly, including the quirks.
import { realpathSync } from "node:fs";
import { homedir as osHomedir } from "node:os";
import nodePath from "node:path";

/** Typed failure: no usable home directory and PASEO_HOME is not set (containers without a passwd entry). */
export class HomeResolutionError extends Error {
  readonly code = "home_unresolved";
  constructor(cause: unknown) {
    super(`Cannot find the home directory (${(cause as Error)?.message ?? String(cause)}). Set PASEO_HOME to the daemon's home directory.`);
    this.name = "HomeResolutionError";
  }
}

export interface HomeDeps {
  homedir?: () => string;
  /** path module of the target platform; tests pass path.win32. */
  path?: typeof nodePath.posix;
}

function home(deps: HomeDeps): string {
  try {
    return (deps.homedir ?? osHomedir)();
  } catch (e) {
    throw new HomeResolutionError(e);
  }
}

/** The daemon's expandHomeDir, verbatim in behaviour. */
export function expandHomeDir(input: string, deps: HomeDeps = {}): string {
  const p = deps.path ?? nodePath;
  if (input.startsWith("~/")) return p.join(home(deps), input.slice(2));
  if (input === "~") return home(deps);
  return input;
}

export function resolvePaseoHome(env: NodeJS.ProcessEnv = process.env, deps: HomeDeps = {}): string {
  const p = deps.path ?? nodePath;
  const raw = env.PASEO_HOME ?? "~/.paseo";
  return p.resolve(expandHomeDir(raw, deps));
}

/**
 * canonicalHome per identity-model 7.3: realpath of PASEO_HOME, lower-cased on Windows because the
 * same home can be reached with different casing there.
 */
export function canonicalHome(paseoHome: string, opts: { platform?: NodeJS.Platform; realpath?: (p: string) => string } = {}): string {
  const real = (opts.realpath ?? realpathSync.native)(paseoHome);
  return (opts.platform ?? process.platform) === "win32" ? real.toLowerCase() : real;
}
