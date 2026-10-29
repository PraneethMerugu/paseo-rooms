// Tool restriction for room agents created by the gateway (rooms-architecture.md section 10,
// "confused deputy through Paseo's own MCP").
//
// Verified in @getpaseo/server 0.13.2 (dist/server/server/agent/agent-manager.js createAgentInternal,
// prepareSessionConfig; agent/runtime-mcp-config.js withRuntimePaseoMcpServer):
//   - before("agent.create") runs BEFORE Paseo injects its control MCP;
//   - injection adds mcpServers.paseo = http <daemon>/mcp/agents, UNLESS the config already holds a
//     server named "paseo" whose URL path is not /mcp/agents (then the stored config is used as is);
//   - a stored internal "paseo" entry is stripped and re-injected, so removing the key alone does nothing;
//   - injection is otherwise controlled only by the daemon-wide provider policy
//     providers.<id>.paseoTools.enabled, not per agent;
//   - providers with native Paseo tools (opencode with a bridge, omp) get the tools through the launch
//     context, not MCP; the hook cannot remove those.
// So: room agents get an inert stdio MCP server named "paseo" that exposes no tools, and fork lanes
// are allowed only for providers verified to respect this (shared/policy.ts FORK_VERIFIED_PROVIDERS,
// an allowlist since C-iso3). Later plugins can still undo the shadow (hooks run in plugin-id order),
// which tripwire.ts detects after creation and before the first prompt.
//
// This is NOT an isolation boundary: the room agent runs as the owner's OS user and can reach the
// paseo CLI, ~/.paseo and the daemon port with any shell tool (HARDENING-PLAN C-iso1). M1 lanes are
// watch-only, and filter.ts keeps every prompting message type denied for owner-uid lanes.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { PluginServerContext } from "@getpaseo/plugin/server";
import { isForkVerifiedProvider } from "../../shared/policy";
import { log } from "../log";
import { writePrivateFile } from "../paths";

export const ROOM_LANE_ENV = "PASEO_ROOMS_LANE";

const INERT_MCP_SOURCE = `// paseo-rooms: inert MCP server that shadows Paseo's control MCP for room agents. Exposes no tools.
"use strict";
let buf = "";
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id === undefined || msg.id === null) continue;
    if (msg.method === "initialize")
      send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: (msg.params && msg.params.protocolVersion) || "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "paseo-rooms-guard", version: "1" } } });
    else if (msg.method === "tools/list") send({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } });
    else if (msg.method === "ping") send({ jsonrpc: "2.0", id: msg.id, result: {} });
    else send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
});
process.stdin.on("end", () => process.exit(0));
`;

export interface InertMcpServer {
  type: "stdio";
  command: string;
  args: string[];
  env: Record<string, string>;
}

export function ensureInertMcp(dataDir: string): InertMcpServer {
  const path = join(dataDir, "inert-mcp.cjs");
  if (!existsSync(path) || readFileSync(path, "utf8") !== INERT_MCP_SOURCE) writePrivateFile(path, INERT_MCP_SOURCE);
  return { type: "stdio", command: process.execPath, args: [path], env: { ELECTRON_RUN_AS_NODE: "1" } };
}

export function isInertMcp(server: unknown, inert: InertMcpServer): boolean {
  const s = server as Partial<InertMcpServer> | undefined;
  return !!s && s.type === "stdio" && s.command === inert.command && Array.isArray(s.args) && s.args[0] === inert.args[0];
}

/** Rewrites a room agent's config: shadow Paseo's MCP, drop preapprovals. Pure; exported for tests. */
export function restrictRoomAgentConfig<C extends object>(config: C, inert: InertMcpServer): C {
  const current = (config as { mcpServers?: Record<string, unknown> }).mcpServers;
  const next = { ...config, mcpServers: { ...(current ?? {}), paseo: inert } };
  delete (next as { toolPolicy?: unknown }).toolPolicy;
  return next;
}

export function registerAgentGuard(server: PluginServerContext, dataDir: string): () => void {
  const inert = ensureInertMcp(dataDir);
  return server.before("agent.create", ({ request }) => {
    const laneId = request.env?.[ROOM_LANE_ENV];
    if (!laneId) return;
    const provider = String(request.config.provider ?? "");
    if (!isForkVerifiedProvider(provider)) {
      log("agent_guard_refused", { laneId, provider: provider.slice(0, 64) });
      throw new Error(`Room agents are not allowed for provider ${provider.slice(0, 64)}: it is not verified to respect the room agent guard`);
    }
    log("agent_guard_applied", { laneId, provider: provider.slice(0, 64) });
    return { ...request, config: restrictRoomAgentConfig(request.config, inert) };
  });
}
