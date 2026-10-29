// Server side of relay protocol v2 (enrollment-v2.md section 3.1; implementation plan I-8), shared by
// the M1 lane endpoint (server/gateway/lane-endpoint.ts) and the v2 room endpoint
// (server/host/room-endpoint.ts). Extracted from lane-endpoint.ts without behaviour change.
//
// Relay protocol v2 as implemented by @getpaseo/relay 0.13.2 (cloudflare-adapter.js):
//   - The server keeps one control socket: /ws?serverId=..&role=server&v=2. The relay sends
//     {type:"sync", connectionIds} when it opens, {type:"connected", connectionId} when a client
//     arrives and {type:"disconnected", connectionId} when the last client socket of a connection
//     closes. A new control socket for the same serverId replaces the old one (P-16).
//   - For each connection the server opens a data socket: ..&role=server&v=2&connectionId=<id>.
//     The relay forwards opaque messages between it and the client sockets of that connection,
//     buffering client messages until the data socket exists.
// Nothing here encrypts or authenticates: the lane endpoint runs Noise NK and the room endpoint
// Noise IK on top of a data socket.
import WebSocket from "ws";
import { buildRelayWebSocketUrl } from "@getpaseo/protocol/daemon-endpoints";
import type { Transport } from "@getpaseo/relay/e2ee";
import { clip, log, short } from "../log";

/** Where a relay is reached: `host:port`, and whether to use TLS. */
export type RelayAddress = { endpoint: string; useTls: boolean };

const KEEPALIVE_MS = 20_000;
const RECONNECT_MIN_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
/** Connection ids longer than this are ignored (a relay-supplied string). */
export const MAX_CONNECTION_ID_CHARS = 256;

/** URL of the server control socket (no connectionId) or of the data socket of one connection. */
export function relayServerUrl(relay: RelayAddress, serverId: string, connectionId?: string): string {
  return buildRelayWebSocketUrl({
    endpoint: relay.endpoint,
    useTls: relay.useTls,
    serverId,
    role: "server",
    version: "2",
    ...(connectionId ? { connectionId } : {}),
  });
}

/** URL a client opens; the relay assigns the connectionId. */
export function relayClientUrl(relay: RelayAddress, serverId: string): string {
  return buildRelayWebSocketUrl({ endpoint: relay.endpoint, useTls: relay.useTls, serverId, role: "client", version: "2" });
}

/**
 * Control notices: the connection that went away (if any) and the ids announced by `sync` or
 * `connected`, unvalidated (callers check type, length and caps, in this order, as M1 did).
 */
export function parseRelayNotice(msg: any): { disconnected: string | null; announced: unknown[] } {
  const disconnected = msg?.type === "disconnected" && typeof msg.connectionId === "string" ? msg.connectionId : null;
  const announced: unknown[] = msg?.type === "sync" ? (Array.isArray(msg.connectionIds) ? msg.connectionIds : []) : msg?.type === "connected" ? [msg.connectionId] : [];
  return { disconnected, announced };
}

export interface RelayControlOptions {
  /** Control socket URL (relayServerUrl without connectionId). */
  url: () => string;
  maxPayload: number;
  /** Event prefix: "lane" logs lane_relay_online, lane_relay_closed, lane_relay_error. */
  logPrefix: string;
  /** Fields added to every log line (for example { laneId }). */
  logFields: Record<string, unknown>;
  serverId: string;
  onNotice(msg: unknown): void;
  onStatus(status: "online" | "offline"): void;
  /** Every close of the control socket while not stopped (for example a 1008 eviction, P-16). */
  onClose?(code: number, reason: string): void;
}

/**
 * The server control socket: keepalive pings every 20 s, a JSON pong for a legacy JSON ping, and
 * reconnects from 1 s doubling to 30 s until stopped.
 */
export class RelayControlSocket {
  private ws: WebSocket | null = null;
  private keepalive: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectDelay = RECONNECT_MIN_MS;
  private stopped = false;

  constructor(private readonly o: RelayControlOptions) {}

  connect(): void {
    if (this.stopped) return;
    const ws = new WebSocket(this.o.url(), { perMessageDeflate: false, maxPayload: this.o.maxPayload });
    this.ws = ws;
    const p = this.o.logPrefix;
    ws.on("open", () => {
      this.reconnectDelay = RECONNECT_MIN_MS;
      this.o.onStatus("online");
      log(`${p}_relay_online`, { ...this.o.logFields, serverId: short(this.o.serverId) });
      this.keepalive = setInterval(() => ws.readyState === WebSocket.OPEN && ws.ping(), KEEPALIVE_MS);
    });
    ws.on("message", (raw) => {
      let msg: any;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (msg.type === "ping") return void ws.send(JSON.stringify({ type: "pong", ts: Date.now() }));
      this.o.onNotice(msg);
    });
    ws.on("close", (code, reason) => {
      if (this.keepalive) clearInterval(this.keepalive);
      this.keepalive = null;
      if (this.stopped) return;
      this.o.onStatus("offline");
      this.o.onClose?.(code, reason.toString());
      log(`${p}_relay_closed`, { ...this.o.logFields, code });
      this.reconnectTimer = setTimeout(() => this.connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MAX_MS);
    });
    ws.on("error", (err) => log(`${p}_relay_error`, { ...this.o.logFields, error: clip(err.message, 200) }));
  }

  stop(code: number, reason: string): void {
    if (this.stopped) return;
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.keepalive) clearInterval(this.keepalive);
    try {
      this.ws?.close(code, reason);
    } catch {}
  }
}

export interface RelayConnectionEvents {
  onOpen(): void;
  /** Binary data arrives as an ArrayBuffer copy, text as a string. */
  onMessage(data: ArrayBuffer | string, isBinary: boolean): void;
  onClose(code: number, reason: string): void;
  onError(err: Error): void;
}

/**
 * One relay data socket (the server side of one client connection). Owners layer their channel on
 * it: the lane endpoint through Paseo's e2ee `Transport` (`transport()`), the room endpoint with
 * raw binary messages (`sendBinary`).
 */
export class RelayConnection {
  private ws: WebSocket | null = null;

  constructor(
    readonly url: string,
    readonly maxPayload: number,
  ) {}

  open(events: RelayConnectionEvents): void {
    const ws = new WebSocket(this.url, { perMessageDeflate: false, maxPayload: this.maxPayload });
    this.ws = ws;
    ws.on("message", (data, isBinary) => {
      const payload = isBinary ? new Uint8Array(data as Buffer).slice().buffer : (data as Buffer).toString("utf8");
      events.onMessage(payload, isBinary);
    });
    ws.on("close", (code, reason) => events.onClose(code, reason.toString()));
    ws.on("error", (err) => events.onError(err));
    ws.on("open", () => events.onOpen());
  }

  get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Paseo's e2ee transport over this socket; events are wired by the caller through `open`. */
  transport(): Transport {
    return {
      send: (data) => new Promise<void>((resolve, reject) => (this.ws ? this.ws.send(data, (err) => (err ? reject(err) : resolve())) : reject(new Error("relay socket not open")))),
      close: (code, reason) => this.ws?.close(code, reason),
      onmessage: null,
      onclose: null,
      onerror: null,
    };
  }

  sendBinary(bytes: Uint8Array): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(bytes, { binary: true });
  }

  close(code?: number, reason?: string): void {
    try {
      this.ws?.close(code, reason);
    } catch {}
  }

  terminate(): void {
    this.ws?.terminate();
  }
}
