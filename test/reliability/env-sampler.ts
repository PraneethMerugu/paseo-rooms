// Read-only /proc sampler for agent provider processes. Records which Paseo control routes a process
// could reach. Output holds names, paths, basenames and booleans only: env values are reported only
// for a short allowlist of non-secret variables, MCP URLs lose their query string (bearer tokens),
// and no file is ever opened for reading (credential checks use access(2) only).
//
// Tracked secrets (invite codes, tokens) can be passed in; the report then names the env variables
// whose value contains one, and says whether the command line does. Values are never reported.
//
// Library use: startSampler(match) / stop() from agent-environment-inspection.test.ts.
// CLI use (parent positive control, from run.sh):
//   env-sampler.ts <out.json> <seconds> <ownerListen>
import { accessSync, constants, existsSync, readFileSync, readdirSync, readlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOM_LANE_ENV = "PASEO_ROOMS_LANE";
const SAFE_VALUE = new Set([
  "PASEO_HOME",
  ROOM_LANE_ENV,
  "PASEO_LISTEN",
  "PASEO_DICTATION_ENABLED",
  "PASEO_VOICE_MODE_ENABLED",
  "HOME",
  "USER",
  "SHELL",
  "PWD",
  "ELECTRON_RUN_AS_NODE",
]);

export interface ProcReport {
  pid: number;
  ppid: number;
  exe: string;
  argv0: string;
  argv1: string | null;
  uid: string | null;
  sameUidAsSampler: boolean;
  envCount: number;
  /** Names of PASEO_*, CLAUDE*, ANTHROPIC*, MCP* variables. Value shown only for SAFE_VALUE names. */
  paseoRelatedEnv: Record<string, string>;
  roomLane: string | null;
  paseoHome: string | null;
  /** Variable names (not values) whose value mentions the given daemon listen addresses or ports. */
  envVarsMentioningOwnerDaemon: string[];
  envVarsMentioningMainDaemonPort: string[];
  pathDirsWithPaseoCli: string[];
  credentialReadable: { paseoHomeLocalCredential: boolean | null; mainHomeLocalCredential: boolean };
  /** access(2) only: the Rooms plugin's fallback KEK file and data directory under PASEO_HOME. */
  roomsDataReadable: { kekFallbackFile: boolean | null; dataDir: boolean | null };
  /** Names of env variables whose value contains a tracked secret; never the values. */
  envVarsWithTrackedSecret: string[];
  cmdlineHasTrackedSecret: boolean;
  callerAgentIds: string[];
  cmdlineHasPaseoAgentMcpUrl: boolean;
  cmdlineHasInertMcp: boolean;
  mcpConfig: Record<string, unknown> | "unparsable" | null;
  strictMcpConfig: boolean;
  settingSources: string | boolean | null;
  permissionMode: string | boolean | null;
  noNewPrivs: string | null;
  seccomp: string | null;
  sameNetNs: boolean;
  sameMntNs: boolean;
  sameUserNs: boolean;
}

function readEnv(pid: number): Map<string, string> | null {
  try {
    const m = new Map<string, string>();
    for (const kv of readFileSync(`/proc/${pid}/environ`, "utf8").split("\0")) {
      const i = kv.indexOf("=");
      if (i > 0) m.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return m;
  } catch {
    return null;
  }
}
function readArgv(pid: number): string[] {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean);
  } catch {
    return [];
  }
}
function statusField(pid: number | "self", f: string): string | null {
  try {
    return new RegExp(`^${f}:\\s+(\\S+)`, "m").exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? null;
  } catch {
    return null;
  }
}
function ns(pid: number | "self", kind: string): string | null {
  try {
    return readlinkSync(`/proc/${pid}/ns/${kind}`);
  } catch {
    return null;
  }
}
/** Permission check only (access(2)); the file is never opened. */
function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}
function flag(args: string[], name: string): string | boolean | null {
  const i = args.findIndex((a) => a === name || a.startsWith(name + "="));
  if (i < 0) return null;
  if (args[i].includes("=")) return args[i].split("=").slice(1).join("=");
  const next = args[i + 1];
  return next && !next.startsWith("--") ? next : true;
}
function stripQuery(u: unknown): string | undefined {
  return u ? String(u).split("?")[0] : undefined;
}

/** Summarises an MCP server map: type, command and first-arg basenames, URL without query, env/header NAMES. */
export function summariseMcpServers(servers: Record<string, any> | null | undefined): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(servers ?? {}).map(([k, v]) => [
      k,
      {
        type: v?.type ?? (v?.command ? "stdio" : v?.url ? "http" : "?"),
        command: v?.command ? basename(String(v.command)) : undefined,
        arg0: v?.args?.[0] ? basename(String(v.args[0])) : undefined,
        url: stripQuery(v?.url),
        envNames: v?.env ? Object.keys(v.env).sort() : undefined,
        headerNames: v?.headers ? Object.keys(v.headers).sort() : undefined,
      },
    ]),
  );
}
function mcpFromArgv(args: string[]): ProcReport["mcpConfig"] {
  const i = args.indexOf("--mcp-config");
  if (i < 0) return null;
  try {
    const j = JSON.parse(args[i + 1]);
    return summariseMcpServers(j.mcpServers ?? j);
  } catch {
    return "unparsable";
  }
}

export interface SamplerOptions {
  /** Owner test daemon listen address, e.g. 127.0.0.1:6930. */
  ownerListen: string;
  /** Decides which processes are recorded. Gets the process env and argv. */
  match: (env: Map<string, string>, argv: string[]) => boolean;
  intervalMs?: number;
  /** Secrets to look for in env values and the command line (at least 20 characters each). */
  secrets?: string[];
}

export function inspectProcess(pid: number, e: Map<string, string>, args: string[], ownerListen: string, secrets: string[] = []): ProcReport {
  const tracked = secrets.filter((x) => x.length >= 20);
  const ownerPort = ownerListen.split(":").pop()!;
  const names = [...e.keys()].sort();
  const paseoRelatedEnv: Record<string, string> = {};
  for (const n of names)
    if (/^(PASEO|CLAUDE|ANTHROPIC|MCP)/.test(n) || n === "ELECTRON_RUN_AS_NODE") paseoRelatedEnv[n] = SAFE_VALUE.has(n) ? e.get(n)! : "<set>";
  const home = e.get("PASEO_HOME") ?? null;
  const cmd = args.join(" ");
  let exe = "";
  try {
    exe = basename(readlinkSync(`/proc/${pid}/exe`));
  } catch {}
  return {
    pid,
    ppid: Number(statusField(pid, "PPid") ?? 0),
    exe,
    argv0: basename(args[0] ?? ""),
    argv1: args[1] ? basename(args[1]) : null,
    uid: statusField(pid, "Uid"),
    sameUidAsSampler: statusField(pid, "Uid") === statusField("self", "Uid"),
    envCount: names.length,
    paseoRelatedEnv,
    roomLane: e.get(ROOM_LANE_ENV) ?? null,
    paseoHome: home,
    envVarsMentioningOwnerDaemon: names.filter((n) => {
      const v = e.get(n)!;
      return v.includes(ownerListen) || new RegExp(`(^|[^0-9])${ownerPort}([^0-9]|$)`).test(v);
    }),
    envVarsMentioningMainDaemonPort: names.filter((n) => /(^|[^0-9])6767([^0-9]|$)/.test(e.get(n)!)),
    pathDirsWithPaseoCli: (e.get("PATH") ?? "").split(":").filter((d) => d && existsSync(join(d, "paseo"))),
    credentialReadable: {
      paseoHomeLocalCredential: home ? readable(join(home, "local-credential")) : null,
      mainHomeLocalCredential: readable(join(homedir(), ".paseo", "local-credential")),
    },
    roomsDataReadable: {
      kekFallbackFile: home ? (existsSync(join(home, "plugin-data", "rooms", "keystore", "kek.fallback")) ? readable(join(home, "plugin-data", "rooms", "keystore", "kek.fallback")) : null) : null,
      dataDir: home ? (existsSync(join(home, "plugin-data", "rooms")) ? readable(join(home, "plugin-data", "rooms")) : null) : null,
    },
    envVarsWithTrackedSecret: names.filter((n) => tracked.some((x) => e.get(n)!.includes(x))),
    cmdlineHasTrackedSecret: tracked.some((x) => cmd.includes(x)),
    callerAgentIds: [...new Set([...cmd.matchAll(/callerAgentId=([A-Za-z0-9_-]+)/g)].map((m) => m[1]))],
    cmdlineHasPaseoAgentMcpUrl: cmd.includes("/mcp/agents"),
    cmdlineHasInertMcp: cmd.includes("inert-mcp.cjs"),
    mcpConfig: mcpFromArgv(args),
    strictMcpConfig: args.includes("--strict-mcp-config"),
    settingSources: flag(args, "--setting-sources"),
    permissionMode: flag(args, "--permission-mode"),
    noNewPrivs: statusField(pid, "NoNewPrivs"),
    seccomp: statusField(pid, "Seccomp"),
    sameNetNs: ns(pid, "net") === ns("self", "net"),
    sameMntNs: ns(pid, "mnt") === ns("self", "mnt"),
    sameUserNs: ns(pid, "user") === ns("self", "user"),
  };
}

/** Samples /proc until stop() is called. Each matching pid is inspected once (first sighting). */
export function startSampler(opts: SamplerOptions): { stop: () => ProcReport[]; samples: () => number } {
  const seen = new Map<number, ProcReport>();
  let samples = 0;
  const tick = () => {
    samples++;
    for (const d of readdirSync("/proc")) {
      if (!/^\d+$/.test(d)) continue;
      const pid = Number(d);
      if (pid === process.pid || seen.has(pid)) continue;
      const e = readEnv(pid);
      if (!e) continue;
      const args = readArgv(pid);
      if (!opts.match(e, args)) continue;
      seen.set(pid, inspectProcess(pid, e, args, opts.ownerListen, opts.secrets));
    }
  };
  tick();
  const timer = setInterval(tick, opts.intervalMs ?? 40);
  return {
    stop: () => {
      clearInterval(timer);
      tick();
      return [...seen.values()];
    },
    samples: () => samples,
  };
}

// ------------------------------------------------------------------ CLI: parent positive control
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [out, secondsArg, ownerListen] = process.argv.slice(2);
  // The parent's provider process carries Paseo's agent MCP URL for the owner test daemon.
  const s = startSampler({ ownerListen, match: (_e, args) => args.join(" ").includes(`${ownerListen}/mcp/agents`) });
  const finish = () => {
    const procs = s.stop();
    writeFileSync(out, JSON.stringify({ samples: s.samples(), processes: procs }, null, 2), { mode: 0o600 });
    process.exit(0);
  };
  setTimeout(finish, Number(secondsArg) * 1000);
  process.on("SIGTERM", finish);
  process.on("SIGINT", finish);
}
