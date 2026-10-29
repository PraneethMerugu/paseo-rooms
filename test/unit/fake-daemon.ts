// A minimal fake Paseo daemon for unit tests: a loopback WebSocket server plus a PASEO_HOME with
// paseo.pid and a local credential. It records every hello and session message it receives and
// answers through a test-supplied handler. No real daemon, relay or network is involved.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { WebSocketServer, type WebSocket } from "ws";
import { tempDir } from "./helpers";

export interface FakeDaemon {
  home: string;
  hellos: any[];
  messages: any[];
  sockets: Set<WebSocket>;
  /** Set to false to keep sessions "not ready" (no server_info after hello). */
  sendServerInfo: boolean;
  onSession: (message: any, reply: (m: any) => void) => void;
  close(): Promise<void>;
}

export const FAKE_CREDENTIAL = "c".repeat(43);

export async function startFakeDaemon(): Promise<FakeDaemon> {
  const tmp = tempDir();
  const wss = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await new Promise<void>((r) => wss.once("listening", () => r()));
  const port = (wss.address() as { port: number }).port;
  writeFileSync(join(tmp.dir, "paseo.pid"), JSON.stringify({ pid: 1, listen: `127.0.0.1:${port}` }));
  writeFileSync(join(tmp.dir, "local-credential"), FAKE_CREDENTIAL);
  const fake: FakeDaemon = {
    home: tmp.dir,
    hellos: [],
    messages: [],
    sockets: new Set(),
    sendServerInfo: true,
    onSession: () => undefined,
    async close() {
      for (const s of fake.sockets) s.terminate();
      await new Promise<void>((r) => wss.close(() => r()));
      tmp.cleanup();
    },
  };
  wss.on("connection", (ws) => {
    fake.sockets.add(ws);
    ws.on("close", () => fake.sockets.delete(ws));
    const reply = (m: any) => ws.send(JSON.stringify({ type: "session", message: m }));
    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "hello") {
        fake.hellos.push(msg);
        if (fake.sendServerInfo)
          reply({ type: "status", payload: { status: "server_info", serverId: "srv_owner_secret", version: "0.13.2", protocolVersion: 1, permissions: ["workspace.read"], features: {} } });
        return;
      }
      if (msg.type === "session") {
        fake.messages.push(msg.message);
        fake.onSession(msg.message, reply);
      }
    });
  });
  return fake;
}

export async function waitFor(cond: () => boolean, timeoutMs = 3000, what = "condition"): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}
