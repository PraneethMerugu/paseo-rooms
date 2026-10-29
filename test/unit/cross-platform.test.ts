// I-16: cross-platform audit X-3 (daemon listen address), X-5 (inert MCP identity), X-11 (CRLF CSV)
// and X-14 (drive root). Win32 and darwin branches run here through injected platform and fs
// adapters. That checks our logic on Linux, not the behaviour on Windows or macOS (untested).
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { WebSocketServer } from "ws";
import { checkInertMcp, ensureInertMcp, isInertMcp, STALE_INERT_MCP_MESSAGE, type InertMcpServer } from "../../server/gateway/agent-guard";
import { daemonTargetFromListen, openDaemonSocket } from "../../server/gateway/local-daemon";
import { checkRoomAgentConfig } from "../../server/gateway/tripwire";
import { redactPath } from "../../server/room-profile/sanitize";
import { CSV_PATH, FIELDS_CSV_PATH, readClassification, readFieldPolicy } from "../../tools/room-profile-lib";
import { tempDir } from "./helpers";

const HOME = () => "/home/o";

test("X-3: listen addresses map to connect targets", () => {
  const t = (listen: string) => daemonTargetFromListen(listen, HOME);
  assert.deepEqual(t("\\\\.\\pipe\\paseo"), { url: "ws://localhost/ws", socketPath: "\\\\.\\pipe\\paseo" });
  assert.deepEqual(t("pipe://\\\\.\\pipe\\paseo"), { url: "ws://localhost/ws", socketPath: "\\\\.\\pipe\\paseo" });
  assert.deepEqual(t("unix:/run/paseo.sock"), { url: "ws://localhost/ws", socketPath: "/run/paseo.sock" });
  assert.deepEqual(t("unix:///run/paseo.sock"), { url: "ws://localhost/ws", socketPath: "/run/paseo.sock" });
  assert.deepEqual(t("/abs/sock"), { url: "ws://localhost/ws", socketPath: "/abs/sock" });
  assert.deepEqual(t("~/.paseo/sock"), { url: "ws://localhost/ws", socketPath: "/home/o/.paseo/sock" });
  assert.deepEqual(t("[::1]:6767"), { url: "ws://[::1]:6767/ws" });
  assert.deepEqual(t("127.0.0.1:6767"), { url: "ws://127.0.0.1:6767/ws" });
  assert.deepEqual(t("localhost:6767"), { url: "ws://localhost:6767/ws" });
  assert.deepEqual(t("6767"), { url: "ws://127.0.0.1:6767/ws" });
});

test("X-3: wildcard binds connect to loopback", () => {
  assert.deepEqual(daemonTargetFromListen("0.0.0.0:6767", HOME), { url: "ws://127.0.0.1:6767/ws" });
  assert.deepEqual(daemonTargetFromListen("[::]:6767", HOME), { url: "ws://[::1]:6767/ws" });
});

test("X-3: non-listen forms are refused without echoing the input", () => {
  for (const bad of ["", "ssh://u@h", "relay://r.example:443/srv", "wss://example.com/ws", "~other/sock", "C:\\paseo.sock", "tcp://h:1?password=secret-value"]) {
    assert.throws(() => daemonTargetFromListen(bad, HOME), (e: Error) => !e.message.includes("secret-value") && /paseo\.pid/.test(e.message), bad);
  }
});

test("X-3: openDaemonSocket reaches a unix-socket listener", async () => {
  const tmp = tempDir();
  const sock = join(tmp.dir, "d.sock");
  const http = createServer();
  const wss = new WebSocketServer({ server: http, path: "/ws" });
  try {
    await new Promise<void>((r) => http.listen(sock, r));
    writeFileSync(join(tmp.dir, "paseo.pid"), JSON.stringify({ listen: `unix:${sock}` }));
    const ws = openDaemonSocket(tmp.dir);
    await new Promise<void>((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });
    ws.close();
  } finally {
    wss.close();
    await new Promise((r) => http.close(r));
    tmp.cleanup();
  }
});

const INERT: InertMcpServer = { type: "stdio", command: "/opt/Paseo/Paseo.bin", args: ["/data/rooms/inert-mcp.cjs"], env: { ELECTRON_RUN_AS_NODE: "1" } };
const stored = (over: Partial<Record<keyof InertMcpServer, unknown>>) => ({ ...INERT, ...over });
const none = () => false;
const all = () => true;

test("X-5: accepted inert entries", () => {
  assert.deepEqual(checkInertMcp(stored({}), INERT, { platform: "linux", exists: none }), { ok: true }, "current execPath needs no fs check");
  assert.ok(isInertMcp(stored({ command: "/tmp/.mount_PaseoX/Paseo" }), INERT, { platform: "linux", exists: all }), "another existing Paseo binary");
  const win: InertMcpServer = { ...INERT, command: "C:\\Users\\o\\AppData\\Local\\Programs\\Paseo\\Paseo.exe", args: ["C:\\Users\\o\\AppData\\Roaming\\rooms\\inert-mcp.cjs"] };
  assert.ok(isInertMcp({ ...win, command: "c:\\users\\o\\appdata\\local\\programs\\paseo\\paseo.exe", args: ["c:\\users\\o\\appdata\\roaming\\rooms\\INERT-MCP.cjs"] }, win, { platform: "win32", exists: none }), "win32 compares case-insensitively");
  assert.ok(isInertMcp({ ...win, command: "C:\\Program Files\\Paseo 0.14\\Paseo.exe" }, win, { platform: "win32", exists: all }), "per-version install directory");
  const mac: InertMcpServer = { ...INERT, command: "/Applications/Paseo.app/Contents/MacOS/Paseo", args: ["/Users/o/Library/rooms/inert-mcp.cjs"] };
  assert.ok(isInertMcp({ ...mac, args: ["/users/o/library/rooms/inert-mcp.cjs"] }, mac, { platform: "darwin", exists: none }), "darwin compares case-insensitively");
});

test("X-5: rejected inert entries (fail closed)", () => {
  const linux = { platform: "linux" as const, exists: all };
  const rejects = (server: unknown, why: RegExp, opts = linux) => {
    const v = checkInertMcp(server, INERT, opts);
    assert.equal(v.ok, false, JSON.stringify(server));
    if (!v.ok) assert.match(v.reason, why);
  };
  rejects(null, /stdio/);
  rejects(stored({ type: "http" }), /stdio/);
  rejects(stored({ command: "/usr/bin/node" }), /not a Paseo binary/);
  rejects(stored({ command: "/usr/bin/python3" }), /not a Paseo binary/);
  rejects(stored({ command: "/tmp/Paseo.bin.sh" }), /not a Paseo binary/);
  rejects(stored({ command: "Paseo.bin" }), /absolute/, linux);
  rejects(stored({ command: "/opt/Paseo/paseo.bin" }), /not a Paseo binary/, { platform: "linux", exists: all });
  rejects(stored({ args: ["/data/rooms/other.cjs"] }), /args/);
  rejects(stored({ args: ["/DATA/rooms/inert-mcp.cjs"] }), /args/, { platform: "linux", exists: all });
  rejects(stored({ args: [INERT.args[0], "--extra"] }), /args/);
  rejects(stored({ args: [] }), /args/);
  rejects(stored({ args: undefined }), /args/);
  rejects(stored({ env: undefined }), /ELECTRON_RUN_AS_NODE/);
  rejects(stored({ env: {} }), /ELECTRON_RUN_AS_NODE/);
  rejects(stored({ env: { ELECTRON_RUN_AS_NODE: "0" } }), /ELECTRON_RUN_AS_NODE/);
  rejects(stored({ env: { ELECTRON_RUN_AS_NODE: "1", NODE_OPTIONS: "--require /tmp/x.js" } }), /ELECTRON_RUN_AS_NODE/);
});

test("X-5: a stale Paseo binary path refuses the lane with a clear message", () => {
  const v = checkInertMcp(stored({ command: "/tmp/.mount_gone/Paseo" }), INERT, { platform: "linux", exists: none });
  assert.deepEqual(v, { ok: false, stale: true, reason: STALE_INERT_MCP_MESSAGE });
  const problems = checkRoomAgentConfig({ config: { mcpServers: { paseo: stored({ command: "/tmp/.mount_gone/Paseo" }) } } }, INERT, { platform: "linux", exists: none });
  assert.deepEqual(problems, [STALE_INERT_MCP_MESSAGE]);
  assert.match(problems[0], /re-open the room agent after updating Paseo/);
});

test("X-5: the guard's own entry passes on this host", () => {
  const tmp = tempDir();
  try {
    const inert = ensureInertMcp(tmp.dir);
    assert.ok(isInertMcp(structuredClone(inert), inert));
  } finally {
    tmp.cleanup();
  }
});

test("X-11: CSV tables parse with CRLF line endings", () => {
  const tmp = tempDir();
  try {
    const crlf = (src: string, name: string) => {
      const p = join(tmp.dir, name);
      writeFileSync(p, readFileSync(src, "utf8").replace(/\r?\n/g, "\r\n"));
      return p;
    };
    assert.deepEqual(readClassification(crlf(CSV_PATH, "c.csv")), readClassification());
    assert.deepEqual(readFieldPolicy(crlf(FIELDS_CSV_PATH, "f.csv")), readFieldPolicy());
  } finally {
    tmp.cleanup();
  }
});

test("X-14: a Windows drive root redacts to /room", () => {
  assert.equal(redactPath("C:\\"), "/room");
  assert.equal(redactPath("d:"), "/room");
  assert.equal(redactPath("C:\\Users\\o\\proj"), "/room/proj");
  assert.equal(redactPath("/home/o/proj"), "/room/proj");
});
