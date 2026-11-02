// Tool restriction for room agents created by the gateway (Rooms architecture document section 10, not published;
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
// paseo CLI, ~/.paseo and the daemon port with any shell tool (hardening plan C-iso1). M1 lanes are
// watch-only, and filter.ts keeps every prompting message type denied for owner-uid lanes.
import { existsSync, readFileSync } from "node:fs";
import { join, posix, win32 } from "node:path";
import type { PluginServerContext } from "@getpaseo/plugin/server";
import { isForkVerifiedProvider } from "../../shared/policy";
import { log } from "../log";
import { writePrivateFile } from "../platform/durable";

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

export const INERT_MCP_FILE = "inert-mcp.cjs";

/** The inert server's descriptor, without writing anything (checks in an unverified data folder). */
export function inertMcpServer(dataDir: string): InertMcpServer {
  return { type: "stdio", command: process.execPath, args: [join(dataDir, INERT_MCP_FILE)], env: { ELECTRON_RUN_AS_NODE: "1" } };
}

export function ensureInertMcp(dataDir: string): InertMcpServer {
  const inert = inertMcpServer(dataDir);
  const path = inert.args[0];
  if (!existsSync(path) || readFileSync(path, "utf8") !== INERT_MCP_SOURCE) writePrivateFile(path, INERT_MCP_SOURCE);
  return inert;
}

/**
 * Basenames of Paseo binaries that may run the inert server with ELECTRON_RUN_AS_NODE (X-5), besides
 * the basename of the current process.execPath. Linux deb: /opt/Paseo/Paseo.bin (tested). Windows
 * Paseo.exe and macOS Paseo.app/Contents/MacOS/Paseo are untested assumptions.
 */
export const PASEO_BINARY_BASENAMES: readonly string[] = ["Paseo", "Paseo.bin", "Paseo.exe"];

export interface InertMcpCheckOptions {
  /** Defaults to process.platform. win32 and darwin compare paths case-insensitively. */
  platform?: NodeJS.Platform;
  /** Defaults to fs.existsSync. Decides whether a stored binary other than the current one is stale. */
  exists?: (path: string) => boolean;
}

export type InertMcpVerdict = { ok: true } | { ok: false; stale: boolean; reason: string };

export const STALE_INERT_MCP_MESSAGE =
  '"paseo" MCP entry points at a Paseo binary that no longer exists (stale lane after a Paseo update or move); close the lane and re-open the room agent after updating Paseo';

const caseInsensitivePaths = (platform: NodeJS.Platform) => platform === "win32" || platform === "darwin";

/**
 * Checks a stored "paseo" MCP entry against the inert shadow (C-iso2, X-5). Fail closed: accepted only
 * when every condition holds:
 *   - type "stdio";
 *   - args is exactly [<our inert-mcp.cjs>];
 *   - env is exactly { ELECTRON_RUN_AS_NODE: "1" } (no NODE_OPTIONS or other keys);
 *   - command is an absolute path whose basename is a Paseo binary (PASEO_BINARY_BASENAMES or the
 *     current execPath's basename) and that is either the current execPath or still exists.
 * A Paseo binary path that no longer exists is reported as stale, with a clear message.
 */
export function checkInertMcp(server: unknown, inert: InertMcpServer, opts: InertMcpCheckOptions = {}): InertMcpVerdict {
  const platform = opts.platform ?? process.platform;
  const exists = opts.exists ?? existsSync;
  const fold = caseInsensitivePaths(platform) ? (p: string) => p.toLowerCase() : (p: string) => p;
  const pathApi = platform === "win32" ? win32 : posix;
  const fail = (reason: string): InertMcpVerdict => ({ ok: false, stale: false, reason });
  const s = server as Partial<InertMcpServer> | null | undefined;
  if (!s || typeof s !== "object" || s.type !== "stdio") return fail("not a stdio server");
  if (!Array.isArray(s.args) || s.args.length !== 1 || typeof s.args[0] !== "string" || fold(s.args[0]) !== fold(inert.args[0]))
    return fail("args are not exactly the plugin's inert-mcp.cjs");
  const env = s.env as unknown;
  if (!env || typeof env !== "object" || Array.isArray(env)) return fail("ELECTRON_RUN_AS_NODE is not set");
  const envKeys = Object.keys(env);
  if (envKeys.length !== 1 || envKeys[0] !== "ELECTRON_RUN_AS_NODE" || (env as Record<string, unknown>).ELECTRON_RUN_AS_NODE !== "1")
    return fail("env is not exactly ELECTRON_RUN_AS_NODE=1");
  const command = s.command;
  if (typeof command !== "string" || !command || command.includes("\0") || !pathApi.isAbsolute(command))
    return fail("command is not an absolute path");
  const base = fold(pathApi.basename(pathApi.normalize(command)));
  const allowed = new Set([...PASEO_BINARY_BASENAMES, pathApi.basename(inert.command)].map(fold));
  if (!allowed.has(base)) return fail("command is not a Paseo binary");
  if (fold(pathApi.normalize(command)) === fold(pathApi.normalize(inert.command))) return { ok: true };
  if (!exists(command)) return { ok: false, stale: true, reason: STALE_INERT_MCP_MESSAGE };
  return { ok: true };
}

export function isInertMcp(server: unknown, inert: InertMcpServer, opts?: InertMcpCheckOptions): boolean {
  return checkInertMcp(server, inert, opts).ok;
}

/** Rewrites a room agent's config: shadow Paseo's MCP, drop preapprovals. Pure; exported for tests. */
export function restrictRoomAgentConfig<C extends object>(config: C, inert: InertMcpServer): C {
  const current = (config as { mcpServers?: Record<string, unknown> }).mcpServers;
  const next = { ...config, mcpServers: { ...(current ?? {}), paseo: inert } };
  delete (next as { toolPolicy?: unknown }).toolPolicy;
  return next;
}

/**
 * `isReady` is false while the start-time permission check has failed (audit X-2): the inert server
 * is not written into an unverified directory, and room agent creates are refused.
 */
export function registerAgentGuard(server: PluginServerContext, dataDir: string, isReady: () => boolean = () => true): () => void {
  let inert: InertMcpServer | null = isReady() ? ensureInertMcp(dataDir) : null;
  return server.before("agent.create", ({ request }) => {
    const laneId = request.env?.[ROOM_LANE_ENV];
    if (!laneId) return;
    if (!isReady()) {
      log("agent_guard_refused", { laneId, reason: "permission_error" });
      throw new Error("Room agents cannot be created: Rooms did not start because its data folder failed the permission check");
    }
    inert ??= ensureInertMcp(dataDir);
    const provider = String(request.config.provider ?? "");
    if (!isForkVerifiedProvider(provider)) {
      log("agent_guard_refused", { laneId, provider: provider.slice(0, 64) });
      throw new Error(`Room agents are not allowed for provider ${provider.slice(0, 64)}: it is not verified to respect the room agent guard`);
    }
    log("agent_guard_applied", { laneId, provider: provider.slice(0, 64) });
    return { ...request, config: restrictRoomAgentConfig(request.config, inert) };
  });
}
