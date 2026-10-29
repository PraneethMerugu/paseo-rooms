// In-process fake relay for tests (implementation plan I-8, F-7): relay protocol v2 pairing of server
// and client sockets, modelled on @getpaseo/relay 0.13.2 cloudflare-adapter.js (RelayDurableObject):
//   /ws?serverId&role=server&v=2                 server control socket, one per serverId (a new one
//                                                 replaces the old with 1008); gets {type:"sync"} on open
//   /ws?serverId&role=client&v=2[&connectionId]  client socket; the relay assigns a connectionId when
//                                                 none is given and sends {type:"connected"} to the control
//   /ws?serverId&role=server&v=2&connectionId    server data socket for one connection (one per id)
// Client messages are buffered (at most 200) until the data socket exists. When the last client socket
// of a connection closes, the data socket is closed (1001) and the control gets {type:"disconnected"};
// when a data socket closes, its clients are closed (1012). A JSON {type:"ping"} on the control socket
// gets {type:"pong"}. v1 and the nudge timers are not modelled. Loopback only; no network.
//
// Also runnable as a process for test/e2e-v2 (see fake-relay-main.ts there).
import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { WebSocketServer, type RawData, type WebSocket } from "ws";

type Role = "server" | "client";
type Attachment = { serverId: string; role: Role; connectionId: string | null };

export interface ForwardedMessage {
  serverId: string;
  connectionId: string;
  from: Role;
  data: Buffer;
  isBinary: boolean;
}

export interface FakeRelay {
  port: number;
  /** `host:port` for RelayAddress.endpoint (useTls false). */
  endpoint: string;
  /** Every message forwarded between a client and a server data socket, in order. */
  forwarded: ForwardedMessage[];
  /** Server control sockets replaced by a newer one (P-16 eviction). */
  evictions: number;
  /** Open server control sockets per serverId. */
  controls(serverId: string): number;
  /** Open client connection ids for a serverId. */
  clientConnections(serverId: string): string[];
  close(): Promise<void>;
}

export async function startFakeRelay(opts: { host?: string; port?: number; log?: (line: string) => void } = {}): Promise<FakeRelay> {
  const host = opts.host ?? "127.0.0.1";
  const wss = new WebSocketServer({ host, port: opts.port ?? 0, perMessageDeflate: false, maxPayload: 8 * 1024 * 1024 });
  await new Promise<void>((resolve, reject) => {
    wss.once("listening", () => resolve());
    wss.once("error", reject);
  });
  const port = (wss.address() as { port: number }).port;
  const sockets = new Map<WebSocket, Attachment>();
  const pending = new Map<string, { data: Buffer; isBinary: boolean }[]>();
  const say = opts.log ?? (() => {});

  const find = (pred: (a: Attachment) => boolean): WebSocket[] => [...sockets].filter(([, a]) => pred(a)).map(([ws]) => ws);
  const controlsOf = (serverId: string) => find((a) => a.serverId === serverId && a.role === "server" && a.connectionId === null);
  const dataOf = (serverId: string, id: string) => find((a) => a.serverId === serverId && a.role === "server" && a.connectionId === id);
  const clientsOf = (serverId: string, id: string) => find((a) => a.serverId === serverId && a.role === "client" && a.connectionId === id);
  const key = (serverId: string, id: string) => `${serverId}\u0000${id}`;
  const notify = (serverId: string, msg: unknown) => {
    for (const ws of controlsOf(serverId)) ws.send(JSON.stringify(msg));
  };
  const connectedIds = (serverId: string) => [...new Set(find((a) => a.serverId === serverId && a.role === "client").map((ws) => sockets.get(ws)!.connectionId!))];

  const relay: FakeRelay = {
    port,
    endpoint: `${host}:${port}`,
    forwarded: [],
    evictions: 0,
    controls: (serverId) => controlsOf(serverId).length,
    clientConnections: (serverId) => connectedIds(serverId),
    async close() {
      for (const ws of sockets.keys()) ws.terminate();
      await new Promise<void>((r) => wss.close(() => r()));
    },
  };

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    const url = new URL(req.url ?? "/", "http://relay.invalid");
    const role = url.searchParams.get("role");
    const serverId = url.searchParams.get("serverId");
    const v = url.searchParams.get("v");
    const given = (url.searchParams.get("connectionId") ?? "").trim();
    if (url.pathname !== "/ws" || (role !== "server" && role !== "client") || !serverId || v !== "2") {
      ws.close(1008, "bad request");
      return;
    }
    const connectionId = role === "client" ? given || `conn_${randomUUID().replace(/-/g, "").slice(0, 16)}` : given || null;
    if (role === "server" && connectionId === null) {
      for (const old of controlsOf(serverId)) {
        relay.evictions++;
        old.close(1008, "Replaced by new connection");
      }
    } else if (role === "server") {
      for (const old of dataOf(serverId, connectionId!)) old.close(1008, "Replaced by new connection");
    }
    sockets.set(ws, { serverId, role, connectionId });
    say(`v2:${role}${connectionId ? `(${connectionId})` : "(control)"} ${serverId.slice(0, 12)}`);

    if (role === "client") notify(serverId, { type: "connected", connectionId });
    if (role === "server" && connectionId === null) ws.send(JSON.stringify({ type: "sync", connectionIds: connectedIds(serverId) }));
    if (role === "server" && connectionId) {
      const queued = pending.get(key(serverId, connectionId)) ?? [];
      pending.delete(key(serverId, connectionId));
      for (const m of queued) ws.send(m.data, { binary: m.isBinary });
    }

    ws.on("message", (raw: RawData, isBinary: boolean) => {
      const a = sockets.get(ws);
      if (!a) return;
      const data = Array.isArray(raw) ? Buffer.concat(raw) : Buffer.from(raw as Buffer);
      if (a.connectionId === null) {
        // Control socket: legacy JSON keepalive only.
        try {
          if (JSON.parse(data.toString("utf8"))?.type === "ping") ws.send(JSON.stringify({ type: "pong", ts: Date.now() }));
        } catch {}
        return;
      }
      relay.forwarded.push({ serverId: a.serverId, connectionId: a.connectionId, from: a.role, data, isBinary });
      if (a.role === "client") {
        const servers = dataOf(a.serverId, a.connectionId);
        if (servers.length === 0) {
          const q = pending.get(key(a.serverId, a.connectionId)) ?? [];
          q.push({ data, isBinary });
          if (q.length > 200) q.splice(0, q.length - 200);
          pending.set(key(a.serverId, a.connectionId), q);
          return;
        }
        for (const s of servers) s.send(data, { binary: isBinary });
        return;
      }
      for (const c of clientsOf(a.serverId, a.connectionId)) c.send(data, { binary: isBinary });
    });

    ws.on("close", () => {
      const a = sockets.get(ws);
      sockets.delete(ws);
      if (!a || a.connectionId === null) return;
      if (a.role === "client") {
        if (clientsOf(a.serverId, a.connectionId).length > 0) return;
        pending.delete(key(a.serverId, a.connectionId));
        for (const s of dataOf(a.serverId, a.connectionId)) s.close(1001, "Client disconnected");
        notify(a.serverId, { type: "disconnected", connectionId: a.connectionId });
        return;
      }
      for (const c of clientsOf(a.serverId, a.connectionId)) c.close(1012, "Server disconnected");
    });
    ws.on("error", () => undefined);
  });

  return relay;
}

/** Waits until `f` returns a truthy value (polling), or throws after `timeoutMs`. */
export async function until<T>(what: string, f: () => T | null | undefined | false, timeoutMs = 5000, stepMs = 10): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = f();
    if (v) return v as T;
    if (Date.now() - start > timeoutMs) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

export type { RawData };
