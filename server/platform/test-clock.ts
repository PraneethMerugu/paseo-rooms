// TEST-ONLY clock override for the identity v2 end-to-end tests (implementation plan I-11: "the hold is
// shortened only under a test-only clock override on the host and the admin daemon").
//
// The 24 h and 72 h device holds are measured in the host's `hts` and enforced by the admin daemon on
// its own clock (room-log-v2.md section 5). An e2e run cannot wait 72 hours, so a test daemon may move
// its own clock forward. The override is honoured only when ALL of these hold, checked once at start:
//
//   1. PASEO_ROOMS_TEST_CLOCK=1 in the daemon's environment;
//   2. the daemon's home resolves (realpath) to a directory named `v2-<name>` directly inside a
//      directory named `.test-homes` (the layout test/e2e-v2/run.sh creates and checks);
//   3. that home is not ~/.paseo and not inside it;
//   4. the home holds the marker file `rooms-test-home`, a regular file (not a symlink) owned by this
//      user whose content is exactly TEST_HOME_MARKER_TEXT, written by run.sh.
//
// Otherwise `advance` throws and `now` is Date.now. The offset only moves forward, lives in memory
// (a restart resets it; the host's `hts` never goes backwards anyway), and is used only for the
// room host's `hts` and the admin daemon's automatic approvals, never for sessions, grants or
// enrollment expiry.
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import nodePath from "node:path";

export const TEST_CLOCK_ENV = "PASEO_ROOMS_TEST_CLOCK";
export const TEST_HOME_MARKER = "rooms-test-home";
export const TEST_HOME_MARKER_TEXT = "paseo-rooms e2e test home; the test clock override may be used here\n";
/** At most this far forward in total (a week covers every hold and the 48 h approval window). */
export const TEST_CLOCK_MAX_OFFSET_MS = 7 * 24 * 60 * 60 * 1000;

/** Why the override is off, or null when it is allowed. */
export function testClockRefusal(env: NodeJS.ProcessEnv, paseoHome: string, deps: { homedir?: () => string; uid?: number } = {}): string | null {
  if (env[TEST_CLOCK_ENV] !== "1") return "switch_off";
  return testHomeRefusal(paseoHome, deps);
}

/**
 * Conditions 2 to 4 above: why `paseoHome` is not a marked e2e test home, or null when it is. Also
 * gates the development switches PASEO_ROOMS_DEV_* (I-15): they are honoured only on such a home.
 */
export function testHomeRefusal(paseoHome: string, deps: { homedir?: () => string; uid?: number } = {}): string | null {
  let real: string;
  try {
    real = realpathSync(paseoHome);
  } catch {
    return "home_missing";
  }
  const parent = nodePath.dirname(real);
  if (nodePath.basename(parent) !== ".test-homes" || !/^v2-[a-z0-9-]{1,32}$/.test(nodePath.basename(real))) return "not_a_test_home";
  let main: string;
  try {
    main = realpathSync(nodePath.join((deps.homedir ?? homedir)(), ".paseo"));
  } catch {
    main = nodePath.join((deps.homedir ?? homedir)(), ".paseo");
  }
  if (real === main || real.startsWith(main + nodePath.sep)) return "main_home";
  const marker = nodePath.join(real, TEST_HOME_MARKER);
  try {
    const st = lstatSync(marker);
    const uid = deps.uid ?? process.getuid?.();
    if (!st.isFile() || (uid !== undefined && st.uid !== uid)) return "bad_marker";
    if (readFileSync(marker, "utf8") !== TEST_HOME_MARKER_TEXT) return "bad_marker";
  } catch {
    return "no_marker";
  }
  return null;
}

export class TestClock {
  private offsetMs = 0;
  readonly enabled: boolean;
  readonly refusal: string | null;

  constructor(env: NodeJS.ProcessEnv, paseoHome: string, deps?: { homedir?: () => string; uid?: number }) {
    this.refusal = testClockRefusal(env, paseoHome, deps);
    this.enabled = this.refusal === null;
  }

  readonly now = (): number => Date.now() + this.offsetMs;

  get offset(): number {
    return this.offsetMs;
  }

  /** Moves this daemon's room-host and approval clock forward. Throws unless the override is allowed. */
  advance(ms: number): number {
    if (!this.enabled) throw new Error(`The test clock is not available on this daemon (${this.refusal})`);
    if (!Number.isInteger(ms) || ms <= 0 || this.offsetMs + ms > TEST_CLOCK_MAX_OFFSET_MS) throw new Error("bad clock advance");
    this.offsetMs += ms;
    return this.offsetMs;
  }
}

/** Prefix of the development switches (short grants, plain loopback relay, fast MLS timers). */
export const DEV_ENV_PREFIX = "PASEO_ROOMS_DEV_";

/**
 * The environment the runtime uses: every PASEO_ROOMS_DEV_* switch is removed unless the home is a
 * marked e2e test home (testHomeRefusal) or the caller is a unit test that allows them explicitly.
 * Returns the environment and the names of the switches that were dropped (for one log line).
 */
export function gateDevSwitches(env: NodeJS.ProcessEnv, paseoHome: string, opts: { allow?: boolean; deps?: { homedir?: () => string; uid?: number } } = {}): { env: NodeJS.ProcessEnv; dropped: string[]; refusal: string | null } {
  const names = Object.keys(env).filter((k) => k.startsWith(DEV_ENV_PREFIX) && env[k] !== undefined);
  if (names.length === 0) return { env, dropped: [], refusal: null };
  const refusal = opts.allow === true ? null : testHomeRefusal(paseoHome, opts.deps);
  if (refusal === null) return { env, dropped: [], refusal };
  const out: NodeJS.ProcessEnv = { ...env };
  for (const k of names) delete out[k];
  return { env: out, dropped: names, refusal };
}
