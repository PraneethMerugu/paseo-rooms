// Secret hygiene (redaction, file modes, invite codes) and the room agent tool guard.
import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";
import { ensureInertMcp, isInertMcp, restrictRoomAgentConfig } from "../../server/gateway/agent-guard";
import { HostStore } from "../../server/host/host-store";
import { decodeInviteCode } from "../../server/invite-code";
import { __testing } from "../../server/log";
import { fileMode } from "../../server/paths";
import { tempDir } from "./helpers";

test("logger redacts secret fields and token-shaped values", () => {
  const out = JSON.stringify(
    __testing.redact({ token: "abc", grant: "x", nested: { password: "p", note: "relay://h/x?password=SECRET&ssl=true" }, msg: "got prg1.aaa.bbb and prc1.zzz" }),
  );
  for (const s of ["abc", "SECRET", "prg1.aaa.bbb", "prc1.zzz", '"p"']) assert.ok(!out.includes(s), s);
});

test("host files are 0600 in 0700 directories; invite code round-trips", () => {
  const tmp = tempDir();
  try {
    const host = new HostStore(tmp.dir);
    const room = host.createRoom("Lab");
    const lane = host.createLane({ roomId: room.id, label: "Live", origin: { kind: "share", agentId: "a" }, agentId: "a", workspaceId: "w" });
    const { code, invite } = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
    assert.equal(fileMode(join(tmp.dir, "gateway")), 0o700);
    assert.equal(fileMode(join(tmp.dir, "gateway", "host-key.json")), 0o600);
    assert.equal(fileMode(join(tmp.dir, "gateway", "state.json")), 0o600);
    assert.equal(fileMode(join(tmp.dir, "gateway", "rooms", room.id, "events.jsonl")), 0o600);
    const payload = decodeInviteCode(code);
    assert.equal(payload.laneId, lane.id);
    assert.equal(payload.offer.serverId, lane.serverId);
    assert.equal(payload.host.keyId, host.hostKey.keyId);
    assert.ok(!JSON.stringify(host.invites).includes(payload.token), "only the token hash is stored");
    assert.equal(invite.tokenHash.length, 64);
    assert.throws(() => decodeInviteCode("prc1.!!!"));
    assert.throws(() => decodeInviteCode("hello"));
  } finally {
    tmp.cleanup();
  }
});

test("room agent guard shadows Paseo's MCP with an inert non-HTTP server and drops preapprovals", () => {
  const tmp = tempDir();
  try {
    const inert = ensureInertMcp(tmp.dir);
    const config = { provider: "claude", toolPolicy: { preapproved: [{ server: "x", tool: "y" }] }, mcpServers: { other: { type: "http", url: "http://x/y" } } };
    const out = restrictRoomAgentConfig(config, inert) as any;
    assert.ok(isInertMcp(out.mcpServers.paseo, inert));
    // Paseo strips "paseo" only for http/sse servers on /mcp/agents and skips injection when the name is taken.
    assert.equal(out.mcpServers.paseo.type, "stdio");
    assert.equal(out.toolPolicy, undefined);
    assert.ok(out.mcpServers.other, "other servers are kept");
    assert.equal(fileMode(inert.args[0]), 0o600);
  } finally {
    tmp.cleanup();
  }
});

test("inert MCP server answers initialize and lists no tools", async () => {
  const { spawn } = await import("node:child_process");
  const tmp = tempDir();
  try {
    const inert = ensureInertMcp(tmp.dir);
    const child = spawn(inert.command, inert.args, { env: { ...process.env, ...inert.env }, stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) + "\n");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
    child.stdin.end();
    await new Promise((r) => child.on("close", r));
    const lines = out.trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[0].result.protocolVersion, "2025-06-18");
    assert.deepEqual(lines[1].result.tools, []);
  } finally {
    tmp.cleanup();
  }
});
