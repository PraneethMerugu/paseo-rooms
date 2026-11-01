// Secret hygiene (redaction) and the room agent tool guard. The M1 host file and invite code test was
// removed with the M1 host at the cut-over (I-15); v2 file modes are tested in v2-file-layer and
// v2-room-host, v2 invite codes in v2-enrollment.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ensureInertMcp, isInertMcp, restrictRoomAgentConfig } from "../../server/gateway/agent-guard";
import { __testing } from "../../server/log";
import { defaultProtection } from "../../server/platform/file-protection";
import { tempDir } from "./helpers";

test("logger redacts secret fields and token-shaped values", () => {
  const out = JSON.stringify(
    __testing.redact({ token: "abc", grant: "x", nested: { password: "p", note: "relay://h/x?password=SECRET&ssl=true" }, msg: "got prg1.aaa.bbb and prc1.zzz" }),
  );
  for (const s of ["abc", "SECRET", "prg1.aaa.bbb", "prc1.zzz", '"p"']) assert.ok(!out.includes(s), s);
});

test("logger redacts the v2 secret formats (prc2., prg2., prl2., prk2-) and v2 secret field names (V-2)", () => {
  const prk = `prk2${"-abcd".repeat(13)}-ef27`;
  const values = ["prc2.AAAA_bbbb-CCCC", "prg2.eyJjbGFpbXMi.c2lnbmF0dXJl", "prl2.LINK_code-123", prk];
  const msg = `invite ${values[0]} grant ${values[1]}, link ${values[2]}; recovery ${values[3]}.`;
  const out = JSON.stringify(__testing.redact({ msg, list: values, confirmToken: "t".repeat(43), seed: "s33d", recoveryCode: "x", linkCode: "y", code: "ENOENT", recovery: "created" }));
  for (const s of [...values, "t".repeat(43), "s33d", '"x"', '"y"', "prc2.", "prg2.", "prl2.", "prk2-"]) assert.ok(!out.includes(s), s);
  assert.equal((out.match(/\[redacted\]/g) ?? []).length, 4 + 4 + 4, "each value and each secret field is redacted");
  // Error codes and the recovery flag stay readable.
  assert.ok(out.includes('"code":"ENOENT"') && out.includes('"recovery":"created"'));
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
    assert.deepEqual(defaultProtection().verify(inert.args[0]), { ok: true });
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
