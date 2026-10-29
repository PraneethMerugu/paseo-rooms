// Isolation tripwire for room agents (C-iso2, protocol review P-6).
//
// Hook order on Paseo 0.13.2 (verified in @getpaseo/server 0.13.2,
// dist/server/server/plugins/runtime.js `before()`, and plugins/lifecycle/index.js):
//   - before hooks run sequentially over all running plugins sorted by plugin id
//     (String.localeCompare); each hook receives the previous plugin's output;
//   - "agent.create" may rewrite config and env, so any plugin whose id sorts after "rooms" runs
//     after our guard and can re-add MCP servers or preapprovals;
//   - "agent.session_open" may change env only (validateBeforeResult throws on anything else);
//   - agent-manager.js createAgentInternal: before("agent.create") -> prepareSessionConfig
//     (stored config, Paseo MCP injected unless a non-internal "paseo" entry exists) ->
//     before("agent.session_open") -> createSession -> registerSession (stored record written).
// So the final config is only observable after creation, in the daemon's stored agent record
// ($PASEO_HOME/agents/<cwd slug>/<agentId>.json, config.mcpServers / config.toolPolicy). The
// gateway creates room agents WITHOUT a prompt, runs this check, and only then sends the first
// prompt; on failure it archives the agent and refuses the lane. Lane endpoints re-check on every
// start, and the session_open hook re-checks before a lane agent is resumed (stored config is reused
// on resume; no agent.create hook runs then).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, win32 } from "node:path";
import { isInertMcp, type InertMcpServer } from "./agent-guard";

export interface TripwireResult {
  ok: boolean;
  problems: string[];
  file: string | null;
}

/** Same slug as @getpaseo/server 0.13.2 agent-storage.js projectDirNameFromCwd. */
export function projectDirNameFromCwd(cwd: string): string {
  const { root } = win32.parse(cwd);
  const withoutRoot = cwd.slice(root.length).replace(/[\\/]+$/, "");
  const sanitizedRoot = root.replace(/[:\\/]+/g, "-").replace(/^-+|-+$/g, "");
  const prefix = sanitizedRoot ? `${sanitizedRoot}-` : "";
  if (!withoutRoot) return sanitizedRoot || "root";
  return prefix + withoutRoot.replace(/[\\/]+/g, "-");
}

export function findStoredAgentRecord(paseoHome: string, agentId: string, cwd?: string | null): string | null {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(agentId)) return null;
  const agentsDir = join(paseoHome, "agents");
  if (cwd) {
    const p = join(agentsDir, projectDirNameFromCwd(cwd), `${agentId}.json`);
    if (existsSync(p)) return p;
  }
  try {
    for (const d of readdirSync(agentsDir, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      const p = join(agentsDir, d.name, `${agentId}.json`);
      if (existsSync(p)) return p;
    }
  } catch {
    return null;
  }
  return null;
}

/** Pure check of a stored record's config. Exported for tests. */
export function checkRoomAgentConfig(record: unknown, inert: InertMcpServer): string[] {
  const problems: string[] = [];
  const config = (record as { config?: Record<string, unknown> } | null)?.config;
  if (!config || typeof config !== "object") return ["stored record has no config"];
  const mcp = config.mcpServers as Record<string, unknown> | null | undefined;
  if (!mcp || typeof mcp !== "object") problems.push("no MCP servers: the inert paseo shadow is missing, so Paseo injects its control MCP");
  else {
    if (!isInertMcp(mcp.paseo, inert)) problems.push('"paseo" MCP entry is not the inert shadow');
    const extra = Object.keys(mcp).filter((k) => k !== "paseo");
    if (extra.length) problems.push(`unexpected MCP servers: ${extra.map((k) => k.slice(0, 40)).join(", ")}`);
    for (const [name, server] of Object.entries(mcp)) {
      const url = (server as { url?: unknown } | null)?.url;
      if (typeof url === "string" && url.includes("/mcp/agents")) problems.push(`MCP server ${name.slice(0, 40)} points at Paseo's agent MCP`);
    }
  }
  const pre = (config.toolPolicy as { preapproved?: unknown[] } | null | undefined)?.preapproved;
  if (Array.isArray(pre) && pre.length) problems.push(`tool preapprovals present (${pre.length})`);
  return problems;
}

/** Reads the stored record and checks it. A missing record is a failure (fail closed). */
export function verifyRoomAgent(paseoHome: string, agentId: string, cwd: string | null, inert: InertMcpServer): TripwireResult {
  const file = findStoredAgentRecord(paseoHome, agentId, cwd);
  if (!file) return { ok: false, problems: ["stored agent record not found"], file: null };
  let record: unknown;
  try {
    record = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    return { ok: false, problems: [`stored agent record unreadable: ${(e as Error).message.slice(0, 120)}`], file };
  }
  if ((record as { id?: unknown })?.id !== agentId) return { ok: false, problems: ["stored record id mismatch"], file };
  const problems = checkRoomAgentConfig(record, inert);
  return { ok: problems.length === 0, problems, file };
}

/** Polls for the stored record (written asynchronously after creation), then verifies it. */
export async function verifyRoomAgentEventually(paseoHome: string, agentId: string, cwd: string | null, inert: InertMcpServer, timeoutMs = 5000): Promise<TripwireResult> {
  const deadline = Date.now() + timeoutMs;
  let last = verifyRoomAgent(paseoHome, agentId, cwd, inert);
  while (!last.ok && last.file === null && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    last = verifyRoomAgent(paseoHome, agentId, cwd, inert);
  }
  return last;
}
