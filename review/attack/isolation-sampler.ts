// Samples /proc for room-agent processes (env PASEO_ROOMS_LANE) and records what control routes they
// could reach. Prints names, paths and booleans only: never env values that could be secrets, never
// MCP URLs' query strings (they carry bearer tokens), never file contents.
//   tsx isolation-sampler.ts <out.json> <durationSec>
import { accessSync, constants, existsSync, readFileSync, readdirSync, readlinkSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { connect } from "node:net";

const out = process.argv[2];
const durationSec = Number(process.argv[3] ?? 240);
const SAFE_VALUE = new Set(["PASEO_HOME", "PASEO_ROOMS_LANE", "HOME", "USER", "SHELL", "PWD", "PASEO_LISTEN", "PASEO_DICTATION_ENABLED", "PASEO_VOICE_MODE_ENABLED"]);
const seen = new Map<number, any>();

function env(pid: number): Map<string, string> | null {
  try {
    const raw = readFileSync(`/proc/${pid}/environ`, "utf8");
    const m = new Map<string, string>();
    for (const kv of raw.split("\0")) {
      const i = kv.indexOf("=");
      if (i > 0) m.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return m;
  } catch {
    return null;
  }
}
function argv(pid: number): string[] {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean);
  } catch {
    return [];
  }
}
function ppid(pid: number): number {
  try {
    return Number(/PPid:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 0);
  } catch {
    return 0;
  }
}
function statusField(pid: number, f: string): string | null {
  try {
    return new RegExp(`${f}:\\s+(\\S+)`).exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? null;
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
function mcpSummary(args: string[]): any {
  const i = args.indexOf("--mcp-config");
  if (i < 0) return null;
  try {
    const j = JSON.parse(args[i + 1]);
    const servers = j.mcpServers ?? j;
    return Object.fromEntries(
      Object.entries(servers).map(([k, v]: [string, any]) => [
        k,
        { type: v?.type ?? (v?.command ? "stdio" : "?"), command: v?.command ? basename(String(v.command)) : undefined, arg0: v?.args?.[0] ? basename(String(v.args[0])) : undefined, url: v?.url ? String(v.url).split("?")[0] : undefined },
      ]),
    );
  } catch {
    return "unparsable";
  }
}
function flag(args: string[], name: string): string | boolean | null {
  const i = args.findIndex((a) => a === name || a.startsWith(name + "="));
  if (i < 0) return null;
  if (args[i].includes("=")) return args[i].split("=").slice(1).join("=");
  const next = args[i + 1];
  return next && !next.startsWith("--") ? next : true;
}
function pathHasPaseo(p: string | undefined): string[] {
  return (p ?? "").split(":").filter((d) => d && existsSync(join(d, "paseo")));
}
function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK); // permission check only; the file is not opened or read
    return true;
  } catch {
    return false;
  }
}

function sample() {
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    const pid = Number(d);
    if (seen.has(pid)) continue;
    const e = env(pid);
    if (!e || !e.has("PASEO_ROOMS_LANE")) continue;
    const args = argv(pid);
    let exe = "";
    try {
      exe = basename(readlinkSync(`/proc/${pid}/exe`));
    } catch {}
    const names = [...e.keys()].sort();
    const paseoEnv: Record<string, string> = {};
    for (const n of names) if (n.startsWith("PASEO") || n.startsWith("CLAUDE") || n.startsWith("ANTHROPIC") || n === "ELECTRON_RUN_AS_NODE")
      paseoEnv[n] = SAFE_VALUE.has(n) ? e.get(n)! : "<set>";
    const home = e.get("PASEO_HOME");
    seen.set(pid, {
      pid,
      ppid: ppid(pid),
      exe,
      argv0: basename(args[0] ?? ""),
      argv1: args[1] ? basename(args[1]) : null,
      envCount: names.length,
      envNames: names,
      paseoEnv,
      HOME: e.get("HOME"),
      pathDirsWithPaseoCli: pathHasPaseo(e.get("PATH")),
      paseoHomeCredentialReadable: home ? readable(join(home, "local-credential")) : null,
      paseoHomePidReadable: home ? readable(join(home, "paseo.pid")) : null,
      mainHomeCredentialReadableBySameUid: readable(join(homedir(), ".paseo", "local-credential")),
      mcpConfig: mcpSummary(args),
      settingSources: flag(args, "--setting-sources"),
      strictMcpConfig: args.includes("--strict-mcp-config"),
      permissionMode: flag(args, "--permission-mode"),
      dangerouslySkip: args.some((a) => a.includes("dangerously-skip-permissions")),
      allowedTools: flag(args, "--allowedTools") ?? flag(args, "--allowed-tools"),
      noNewPrivs: statusField(pid, "NoNewPrivs"),
      seccomp: statusField(pid, "Seccomp"),
      uid: statusField(pid, "Uid"),
      sameNetNs: ns(pid, "net") === ns("self", "net"),
      sameMntNs: ns(pid, "mnt") === ns("self", "mnt"),
      sameUserNs: ns(pid, "user") === ns("self", "user"),
    });
  }
}

function userClaudeMcpNames(): any {
  const r: any = {};
  try {
    const j = JSON.parse(readFileSync(join(homedir(), ".claude.json"), "utf8"));
    r.userMcpServers = Object.keys(j.mcpServers ?? {});
  } catch {
    r.userMcpServers = "unreadable";
  }
  try {
    const s = JSON.parse(readFileSync(join(homedir(), ".claude", "settings.json"), "utf8"));
    r.enabledPlugins = Object.entries(s.enabledPlugins ?? {}).filter(([, v]) => v).map(([k]) => k);
  } catch {
    r.enabledPlugins = "unreadable";
  }
  return r;
}

async function tcpOpen(port: number): Promise<boolean> {
  return new Promise((res) => {
    const s = connect({ host: "127.0.0.1", port }, () => {
      s.destroy();
      res(true);
    });
    s.on("error", () => res(false));
    setTimeout(() => {
      s.destroy();
      res(false);
    }, 1000);
  });
}

const start = Date.now();
const timer = setInterval(sample, 40);
const finish = async () => {
  clearInterval(timer);
  const procs = [...seen.values()];
  const summary = {
    sampledSec: Math.round((Date.now() - start) / 1000),
    roomAgentProcesses: procs.length,
    procs,
    userClaudeConfig: userClaudeMcpNames(),
    ownerDaemonPortReachableFromSameNetns: await tcpOpen(Number(process.env.ATK_C_PORT ?? 6900)),
  };
  writeFileSync(out, JSON.stringify(summary, null, 2));
  process.exit(0);
};
setTimeout(finish, durationSec * 1000);
process.on("SIGTERM", finish);
process.on("SIGINT", finish);
void statSync;
