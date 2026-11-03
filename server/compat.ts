// Paseo compatibility guard (usability roadmap R2.7; decisions round 10, item 2).
//
// The Room Profile (server/room-profile/generated.ts) classifies every message type of one Paseo
// protocol release. A daemon outside the tested version range, or one that speaks a protocol the
// profile has no tested entry for, may send or accept messages the profile never classified. The
// filter already fails closed on unknown types, which breaks lanes silently. This guard makes the
// failure explicit: lanes are not served at all, and the owner sees why and what to do.
//
// The manifest range (paseo-plugin.json `requirements.paseo`) is the same range as PASEO_RANGE here;
// a unit test keeps them equal.
import { RawDaemon } from "./gateway/local-daemon";
import { ROOM_PROFILE_PROTOCOL_VERSION } from "./room-profile/generated";

/** Tested Paseo daemon versions: `>=min <below`. */
export const PASEO_RANGE = { min: "0.13.2", below: "0.15.0" } as const;
export const PASEO_RANGE_TEXT = `>=${PASEO_RANGE.min} <${PASEO_RANGE.below}`;

/**
 * Tested entries of the Room Profile: the daemon's WebSocket protocol number (`server_info.protocolVersion`)
 * and the @getpaseo/protocol release the profile was generated from. Add an entry only after the profile
 * was regenerated and reviewed for that protocol and the unit and e2e suites passed against it.
 *
 * Paseo 0.13.2 and 0.14.0 both report protocol 1 (websocket-server.js WS_PROTOCOL_VERSION), so the protocol
 * number cannot tell them apart; the version range above does. The 0.14.0 profile classifies every message
 * type and reviewed field of 0.13.2 as well (0.14.0 only adds types; test/unit/room-profile.test.ts checks
 * the 0.13.2 coverage). Tested: unit suite, and test/e2e-v2 against 0.13.2 and 0.14.0 daemons
 * (docs/design/paseo-0.14-compat.md).
 */
export const TESTED_PROFILE_ENTRIES: readonly { protocolVersion: number; profile: string }[] = [{ protocolVersion: 1, profile: "0.14.0" }];

export type CompatCode = "ok" | "version_unknown" | "version_untested" | "protocol_unknown" | "protocol_untested";

export interface CompatVerdict {
  ok: boolean;
  code: CompatCode;
  /** The daemon's reported version and protocol, if well-formed (never other server_info fields). */
  version: string | null;
  protocolVersion: number | null;
  testedRange: string;
  profile: string;
  /** One sentence for the owner: what is wrong. Null when ok. */
  message: string | null;
  /** One sentence for the owner: what to do. Null when ok. */
  action: string | null;
}

type Semver = [number, number, number];

function parseVersion(v: unknown): { core: Semver; pre: boolean } | null {
  if (typeof v !== "string") return null;
  const m = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$/.exec(v.trim());
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] !== undefined };
}

function cmp(a: Semver, b: Semver): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/** True when `version` lies in `>=min <below`. Pre-releases are outside every tested range (fail closed). */
export function inTestedRange(version: string, range: { min: string; below: string } = PASEO_RANGE): boolean {
  const v = parseVersion(version);
  const lo = parseVersion(range.min);
  const hi = parseVersion(range.below);
  if (!v || !lo || !hi || v.pre) return false;
  return cmp(v.core, lo.core) >= 0 && cmp(v.core, hi.core) < 0;
}

/**
 * The verdict for a daemon's `server_info` (fields read: `version`, `protocolVersion`). Fails closed:
 * a missing or malformed version or protocol is not served.
 */
export function checkPaseoCompat(info: { version?: unknown; protocolVersion?: unknown } | null | undefined, entries = TESTED_PROFILE_ENTRIES, range: { min: string; below: string } = PASEO_RANGE): CompatVerdict {
  const rangeText = `>=${range.min} <${range.below}`;
  const rawVersion = info?.version;
  const version = parseVersion(rawVersion) ? String(rawVersion).trim() : null;
  const pv = info?.protocolVersion;
  const protocolVersion = typeof pv === "number" && Number.isInteger(pv) && pv >= 0 && pv <= 1_000_000 ? pv : null;
  const base = { version, protocolVersion, testedRange: rangeText, profile: ROOM_PROFILE_PROTOCOL_VERSION };
  const update = "Check for a Rooms update that supports this Paseo version, or run a Paseo version in the tested range. Rooms (invites, members, chat) keeps working; only shared agents are paused.";
  if (version === null)
    return { ...base, ok: false, code: "version_unknown", message: "Shared agents are paused: this Paseo daemon did not report a version Rooms can check.", action: update };
  if (!inTestedRange(version, range))
    return { ...base, ok: false, code: "version_untested", message: `Shared agents are paused: Paseo ${version} is outside the versions this Rooms release was tested with (${rangeText}).`, action: update };
  if (protocolVersion === null)
    return { ...base, ok: false, code: "protocol_unknown", message: `Shared agents are paused: Paseo ${version} did not report a protocol version Rooms can check.`, action: update };
  if (!entries.some((e) => e.protocolVersion === protocolVersion && e.profile === ROOM_PROFILE_PROTOCOL_VERSION))
    return { ...base, ok: false, code: "protocol_untested", message: `Shared agents are paused: the Room Profile (Paseo ${ROOM_PROFILE_PROTOCOL_VERSION}) has no tested entry for protocol ${protocolVersion}.`, action: update };
  return { ...base, ok: true, code: "ok", message: null, action: null };
}

/**
 * Holds the latest verdict for the owner's daemon. Lanes report each `server_info` they read; the runtime
 * probes once at start (and retries until the daemon answers) so the notice shows before any lane starts.
 */
export class CompatGuard {
  verdict: CompatVerdict | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  constructor(private readonly o: { log?: (event: string, fields: Record<string, unknown>) => void; check?: typeof checkPaseoCompat } = {}) {}

  /** Records and returns the verdict for one `server_info`. Logs a change of verdict once. */
  observe(info: { version?: unknown; protocolVersion?: unknown } | null | undefined): CompatVerdict {
    const v = (this.o.check ?? checkPaseoCompat)(info);
    const prev = this.verdict;
    this.verdict = v;
    if (!prev || prev.code !== v.code || prev.version !== v.version || prev.protocolVersion !== v.protocolVersion)
      this.o.log?.(v.ok ? "paseo_compat_ok" : "paseo_compat_refused", { code: v.code, version: v.version, protocolVersion: v.protocolVersion, tested: v.testedRange, profile: v.profile });
    return v;
  }

  /** Reads the daemon's `server_info` over a capped local session; retries with backoff until it answers. */
  probe(paseoHome: string, opts: { connect?: (home: string) => Promise<{ version?: unknown; protocolVersion?: unknown }>; delays?: readonly number[] } = {}): void {
    const delays = opts.delays ?? [2_000, 5_000, 15_000, 30_000];
    const connect =
      opts.connect ??
      (async (home: string) => {
        const d = new RawDaemon(home);
        try {
          await d.connect("rooms-compat-probe");
          return (d.serverInfo ?? {}) as { version?: unknown; protocolVersion?: unknown };
        } finally {
          d.close();
        }
      });
    const attempt = (i: number) => {
      if (this.stopped) return;
      void connect(paseoHome).then(
        (info) => {
          if (!this.stopped) this.observe(info);
        },
        () => {
          if (this.stopped) return;
          this.timer = setTimeout(() => attempt(i + 1), delays[Math.min(i, delays.length - 1)]);
          (this.timer as { unref?: () => void }).unref?.();
        },
      );
    };
    attempt(0);
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}

// ------------------------------------------------------------------------------------------------
// Legacy fork room agents (agents Rooms 0.1 created for M1 fork lanes, kept after the migration).
//
// Their isolation rests on the stored agent record (tripwire.ts): an inert "paseo" MCP shadow and no
// other MCP servers. From Paseo 0.14.0 other plugins can attach MCP servers and tools in their
// "agent.session_open" hooks at launch time; these are not stored, so the tripwire cannot see them
// (docs/design/paseo-0.14-compat.md). Legacy fork agents are therefore resumed and served only where
// that injection provably does not exist: a Paseo 0.13.x daemon (>=0.13.2 <0.14.0, no pre-release)
// whose session-open request has no `tools` or `mcpServers`. Anything else is refused (fail closed).

/** Paseo versions without session-time MCP and tool injection by plugins. */
export const LEGACY_FORK_RANGE = { min: "0.13.2", below: "0.14.0" } as const;

export const LEGACY_FORK_REFUSED_MESSAGE =
  "Legacy room agents from Rooms 0.1 are not resumed or shared on Paseo 0.14 or later: other plugins can now attach tools to an agent when it starts, which Rooms cannot check. Archive these agents; Rooms 0.2 shares your existing agents live instead.";

/** True only for a well-formed Paseo 0.13.x version (from 0.13.2), never for an unknown version. */
export function legacyForkAgentsAllowed(version: unknown): boolean {
  return typeof version === "string" && inTestedRange(version, LEGACY_FORK_RANGE);
}

/** Whether an "agent.session_open" request is of the kind that lets plugins add tools or MCP servers (Paseo 0.14+). */
export function sessionOpenAllowsInjection(request: unknown): boolean {
  if (!request || typeof request !== "object") return true;
  return "mcpServers" in request || "tools" in request;
}
