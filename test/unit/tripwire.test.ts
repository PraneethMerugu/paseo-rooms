// C-iso2 tripwire on the room agent's final stored config, and C-iso3 provider allowlist.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ensureInertMcp, registerAgentGuard, restrictRoomAgentConfig, ROOM_LANE_ENV } from "../../server/gateway/agent-guard";
import { checkRoomAgentConfig, findStoredAgentRecord, projectDirNameFromCwd, verifyRoomAgent } from "../../server/gateway/tripwire";
import { FORK_VERIFIED_PROVIDERS, isForkVerifiedProvider } from "../../shared/policy";
import { tempDir } from "./helpers";

function storeRecord(home: string, agentId: string, cwd: string, config: unknown) {
  const dir = join(home, "agents", projectDirNameFromCwd(cwd));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${agentId}.json`), JSON.stringify({ id: agentId, provider: "claude", cwd, createdAt: "t", updatedAt: "t", labels: {}, config }));
}

test("storage slug matches @getpaseo/server 0.13.2 projectDirNameFromCwd", () => {
  // Observed in the M1 e2e logs: agents/test-e2e-scratch-lane-work/<id>.json
  assert.equal(projectDirNameFromCwd("test/e2e/scratch/lane-work"), "test-e2e-scratch-lane-work");
  assert.equal(projectDirNameFromCwd("/"), "root");
  assert.equal(projectDirNameFromCwd("/a/b/"), "a-b");
});

test("tripwire: intact config passes; re-added MCP, replaced shadow, Paseo MCP URL and preapprovals fail", () => {
  const tmp = tempDir();
  try {
    const inert = ensureInertMcp(tmp.dir);
    const good = restrictRoomAgentConfig({ provider: "claude" }, inert) as { provider: string; mcpServers: Record<string, unknown> };
    assert.deepEqual(checkRoomAgentConfig({ config: good }, inert), []);
    assert.match(checkRoomAgentConfig({ config: { ...good, mcpServers: { ...good.mcpServers, "zz-tools": { type: "stdio", command: "x" } } } }, inert).join(), /unexpected MCP servers: zz-tools/);
    assert.match(checkRoomAgentConfig({ config: { mcpServers: { paseo: { type: "http", url: "http://127.0.0.1:6767/mcp/agents?callerAgentId=x" } } } }, inert).join(), /not the inert shadow.*agent MCP/);
    assert.match(checkRoomAgentConfig({ config: { ...good, toolPolicy: { preapproved: [{ kind: "mcp", server: "paseo", tool: "x" }] } } }, inert).join(), /preapprovals/);
    assert.match(checkRoomAgentConfig({ config: {} }, inert).join(), /shadow is missing/);
    assert.match(checkRoomAgentConfig({}, inert).join(), /no config/);
  } finally {
    tmp.cleanup();
  }
});

test("tripwire: reads the daemon's stored record; a missing record fails closed", () => {
  const tmp = tempDir();
  try {
    const inert = ensureInertMcp(tmp.dir);
    const id = "90b43b0e-a87a-434c-baaa-fe0dd487b1c0";
    assert.deepEqual(verifyRoomAgent(tmp.dir, id, "/w", inert).problems, ["stored agent record not found"]);
    storeRecord(tmp.dir, id, "/home/o/w", restrictRoomAgentConfig({ provider: "claude" }, inert));
    assert.ok(findStoredAgentRecord(tmp.dir, id, null), "found by scanning when cwd is unknown");
    assert.equal(verifyRoomAgent(tmp.dir, id, "/home/o/w", inert).ok, true);
    storeRecord(tmp.dir, id, "/home/o/w", { mcpServers: { paseo: inert, telegram: { type: "http", url: "https://example" } } });
    const bad = verifyRoomAgent(tmp.dir, id, null, inert);
    assert.equal(bad.ok, false);
    assert.equal(findStoredAgentRecord(tmp.dir, "../../etc/passwd", null), null, "agent id is validated before it is used in a path");
  } finally {
    tmp.cleanup();
  }
});

// The resume tripwire (session_open) for room agents left by M1 is tested at runtime level in
// v2-migration.test.ts.

test("C-iso3: fork lanes only for verified providers (allowlist, exact provider id)", () => {
  assert.deepEqual([...FORK_VERIFIED_PROVIDERS], ["claude"]);
  assert.equal(isForkVerifiedProvider("claude"), true);
  assert.equal(isForkVerifiedProvider("claude/claude-haiku-4-5"), true);
  for (const p of ["codex", "opencode", "omp", "my-opencode", "claude-work", "Claude", "", "zz/claude"]) assert.equal(isForkVerifiedProvider(p), false, p);
});

test("C-iso3: the agent.create guard refuses room agents for unverified providers and shadows the rest", () => {
  const tmp = tempDir();
  try {
    let handler: any = null;
    const server = { before: (name: string, h: any) => ((handler = name === "agent.create" ? h : handler), () => undefined) } as any;
    registerAgentGuard(server, tmp.dir);
    assert.throws(() => handler({ request: { config: { provider: "opencode/x" }, env: { [ROOM_LANE_ENV]: "lane_x" } } }), /not verified/);
    const out = handler({ request: { config: { provider: "claude/haiku", toolPolicy: { preapproved: [] } }, env: { [ROOM_LANE_ENV]: "lane_x" } } });
    assert.equal(out.config.mcpServers.paseo.type, "stdio");
    assert.equal("toolPolicy" in out.config, false);
    assert.equal(handler({ request: { config: { provider: "opencode" }, env: {} } }), undefined, "non-room agents are untouched");
  } finally {
    tmp.cleanup();
  }
});
