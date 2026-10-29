// Attack harness helpers (independent review). Never prints invite codes, grants or credentials.
import { appendFileSync, chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";
import { createHostChannelTransport } from "@getpaseo/client/internal/hosts";
import { openClientSecureChannel, type SecureChannel, type Transport } from "@getpaseo/relay/e2ee";
import { buildRelayWebSocketUrl } from "@getpaseo/protocol/daemon-endpoints";

export const C = process.env.ATK_OWNER_HOME!;
export const A = process.env.ATK_MEMBER_HOME!;
export const LOGDIR = process.env.ATK_LOGDIR!;
export const STATE = join(process.env.ATK_HOMES!, "attack-state.json"); // inside .homes (0700), may hold secrets
export const SECRETS = join(process.env.ATK_HOMES!, "secrets-for-scan.txt");
const T0 = Date.now();

export let failures = 0;
export function log(event: string, fields: Record<string, unknown> = {}) {
  const line = JSON.stringify({ t: ((Date.now() - T0) / 1000).toFixed(2), event, ...fields });
  console.log(line);
}
export function check(id: string, name: string, ok: boolean, fields: Record<string, unknown> = {}) {
  if (!ok) failures++;
  log(ok ? "PASS" : "FAIL", { id, check: name, ...fields });
}
export function rememberSecret(s: string) {
  if (!existsSync(SECRETS)) writeFileSync(SECRETS, "", { mode: 0o600 });
  chmodSync(SECRETS, 0o600);
  appendFileSync(SECRETS, s + "\n");
}
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export async function until<T>(what: string, f: () => Promise<T | null | undefined | false> | T | null | undefined | false, timeoutMs = 30_000, stepMs = 250): Promise<T> {
  const s = Date.now();
  for (;;) {
    const v = await f();
    if (v) return v as T;
    if (Date.now() - s > timeoutMs) throw new Error(`timeout: ${what}`);
    await sleep(stepMs);
  }
}
export async function timed<T>(f: () => Promise<T>) {
  const s = performance.now();
  try {
    return { ok: true as const, value: await f(), ms: Math.round(performance.now() - s) };
  } catch (e) {
    return { ok: false as const, error: String((e as Error)?.message ?? e).slice(0, 200), code: (e as any)?.code, ms: Math.round(performance.now() - s) };
  }
}
export function loadState(): any {
  return existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
}
export function saveState(s: any) {
  writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 });
}

export function listen(home: string) {
  return JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
}
function cred(home: string) {
  return readFileSync(join(home, "local-credential"), "utf8").trim();
}
const wsFactory = (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any;

export async function ownerClient(home: string, name: string): Promise<any> {
  const c: any = new DaemonClient({
    url: `ws://${listen(home)}/ws`,
    clientId: `rooms-atk-${name}-${randomUUID().slice(0, 8)}`,
    clientType: "cli",
    appVersion: "0.13.2",
    localCredential: () => cred(home),
    webSocketFactory: wsFactory,
    reconnect: { enabled: false },
  } as any);
  await c.connect();
  return c;
}
export async function rpc(client: any, method: string, input: unknown): Promise<any> {
  return client.invokePluginRpc("rooms", method, input);
}

/** App-style routed view through member daemon A (as e2e.ts does). */
export async function memberOrigin(): Promise<any> {
  const origin: any = new DaemonClient({
    url: `ws://${listen(A)}/ws`,
    clientId: `rooms-atk-app-${randomUUID().slice(0, 8)}`,
    clientType: "mobile",
    appVersion: "0.13.2",
    localCredential: () => cred(A),
    webSocketFactory: wsFactory,
  } as any);
  await origin.connect();
  return origin;
}
export function openRouted(origin: any, serverId: string): any {
  const clientId = randomUUID();
  return new DaemonClient({
    url: "ws://routed-host/ws",
    clientId,
    clientType: "mobile",
    appVersion: "0.13.2",
    transportFactory: createHostChannelTransport(origin, serverId, clientId, null),
  } as any) as any;
}

export function decodeInvite(code: string): any {
  return JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8"));
}

// ------------------------------------------------------------------------------------------------
/** Direct attacker connection to a lane endpoint over the relay (Noise NK to the pinned lane key). */
export class LaneConn {
  ws!: WebSocket;
  ch!: SecureChannel;
  closed = false;
  closeInfo: { code: number; reason: string } | null = null;
  readonly frames: any[] = [];
  readonly binaries: number[] = [];
  private waiters: Array<{ pred: (m: any) => boolean; resolve: (m: any) => void }> = [];

  static async open(offer: { serverId: string; publicKeyB64: string; relay: { endpoint: string; useTls: boolean } }, timeoutMs = 20_000): Promise<LaneConn> {
    const c = new LaneConn();
    const url = buildRelayWebSocketUrl({ endpoint: offer.relay.endpoint, useTls: offer.relay.useTls, serverId: offer.serverId, role: "client", version: "2" });
    const ws = new WebSocket(url, { perMessageDeflate: false, maxPayload: 200 * 1024 * 1024 });
    c.ws = ws;
    const transport: Transport = {
      send: (data) => new Promise<void>((res, rej) => ws.send(data, (e) => (e ? rej(e) : res()))),
      close: (code, reason) => ws.close(code, reason),
      onmessage: null,
      onclose: null,
      onerror: null,
    };
    ws.on("message", (data, isBinary) =>
      transport.onmessage?.({ data: isBinary ? new Uint8Array(data as Buffer).slice().buffer : (data as Buffer).toString("utf8"), isBinary }),
    );
    ws.on("close", (code, reason) => {
      c.closed = true;
      c.closeInfo = c.closeInfo ?? { code, reason: reason.toString() };
      transport.onclose?.(code, reason.toString());
      for (const w of c.waiters.splice(0)) w.resolve(null);
    });
    ws.on("error", (e) => transport.onerror?.(e));
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("relay open timeout")), timeoutMs);
      ws.once("open", () => {
        clearTimeout(t);
        resolve();
      });
      ws.once("error", (e) => {
        clearTimeout(t);
        reject(e);
      });
    });
    c.ch = await openClientSecureChannel(transport, {
      daemonPublicKeyB64: offer.publicKeyB64,
      minimumMode: "protected",
      events: {
        onopen: () => undefined,
        onmessage: (data) => {
          if (typeof data !== "string") {
            c.binaries.push((data as ArrayBuffer).byteLength);
            return;
          }
          let m: any;
          try {
            m = JSON.parse(data);
          } catch {
            return;
          }
          c.frames.push(m);
          for (const w of [...c.waiters]) if (w.pred(m)) {
            c.waiters.splice(c.waiters.indexOf(w), 1);
            w.resolve(m);
          }
        },
        onclose: (code?: number, reason?: string) => {
          c.closed = true;
          c.closeInfo = c.closeInfo ?? { code: code ?? 0, reason: reason ?? "" };
          for (const w of c.waiters.splice(0)) w.resolve(null);
        },
        onerror: () => undefined,
      } as any,
    });
    return c;
  }

  send(obj: unknown) {
    return this.ch.send(typeof obj === "string" ? obj : JSON.stringify(obj));
  }
  sendBinary(buf: Uint8Array) {
    return this.ch.send(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer);
  }
  next(pred: (m: any) => boolean, timeoutMs = 10_000): Promise<any> {
    const hit = this.frames.find(pred);
    if (hit) {
      this.frames.splice(this.frames.indexOf(hit), 1);
      return Promise.resolve(hit);
    }
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => {
      const w = { pred, resolve };
      this.waiters.push(w);
      setTimeout(() => {
        const i = this.waiters.indexOf(w);
        if (i >= 0) {
          this.waiters.splice(i, 1);
          resolve(null);
        }
      }, timeoutMs);
    });
  }
  async waitClosed(timeoutMs = 5000): Promise<boolean> {
    const s = Date.now();
    while (!this.closed && Date.now() - s < timeoutMs) await sleep(20);
    return this.closed;
  }
  close() {
    try {
      this.ch?.close(1000, "done");
    } catch {}
    try {
      this.ws?.close();
    } catch {}
  }

  // ---- host-link helpers
  async linkHello(password: string | null, extra: Record<string, unknown> = {}): Promise<"accepted" | "rejected" | "closed"> {
    await this.send({
      type: "hello",
      clientId: `atk-${randomUUID()}`,
      clientType: "cli",
      protocolVersion: 1,
      capabilities: { hello_rejection: true },
      ...(password !== null ? { auth: { kind: "password", password } } : {}),
      ...extra,
    });
    const m = await this.next((x) => x?.type === "hello.rejected" || (x?.type === "session" && x.message?.type === "status"), 8000);
    if (!m) return "closed";
    return m.type === "hello.rejected" ? "rejected" : "accepted";
  }
  private rid = 0;
  async session(message: Record<string, unknown>, waitType: string | null, timeoutMs = 8000): Promise<any> {
    const requestId = (message.requestId as string) ?? `atk-${++this.rid}`;
    await this.send({ type: "session", message: { ...message, requestId } });
    if (!waitType) return null;
    const m = await this.next((x) => x?.type === "session" && (x.message?.payload?.requestId === requestId || x.message?.requestId === requestId), timeoutMs);
    return m?.message ?? null;
  }
  async openRoute(channelId = `ch-${randomUUID()}`): Promise<string | null> {
    const r = await this.session({ type: "hosts.link.open.request", channelId }, "x");
    return r?.type === "hosts.link.open.response" ? r.payload.routeId : null;
  }
  async routeSend(routeId: string, envelope: unknown) {
    await this.send({ type: "session", message: { type: "hosts.route.frame.request", routeId, data: typeof envelope === "string" ? envelope : JSON.stringify(envelope) } });
  }
  /** Next routed envelope for routeId matching pred (parsed inner data). */
  async routeNext(routeId: string, pred: (env: any) => boolean, timeoutMs = 10_000): Promise<any> {
    const m = await this.next((x) => {
      if (x?.type !== "session") return false;
      const mm = x.message;
      if (mm?.type === "hosts.route.closed" && mm.payload?.subscriptionId === routeId) return true;
      if (mm?.type !== "hosts.route.frame" || mm.payload?.subscriptionId !== routeId) return false;
      try {
        return pred(JSON.parse(mm.payload.data));
      } catch {
        return false;
      }
    }, timeoutMs);
    if (!m) return null;
    if (m.message.type === "hosts.route.closed") return { __closed: m.message.payload };
    return JSON.parse(m.message.payload.data);
  }
  /** All parsed envelopes received so far on routeId (non-destructive). */
  routeEnvelopes(routeId: string): any[] {
    return this.frames
      .filter((x) => x?.type === "session" && x.message?.type === "hosts.route.frame" && x.message.payload?.subscriptionId === routeId)
      .map((x) => {
        try {
          return JSON.parse(x.message.payload.data);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  }
  async routeHello(routeId: string, extra: Record<string, unknown> = {}): Promise<any> {
    await this.routeSend(routeId, {
      type: "hello",
      clientId: `viewer-${randomUUID()}`,
      clientType: "mobile",
      protocolVersion: 1,
      appVersion: "0.13.2",
      capabilities: { hello_rejection: true, explicitEventSubscriptions: true, selectiveAgentTimeline: true },
      ...extra,
    });
    return this.routeNext(routeId, (e) => e?.type === "hello.rejected" || (e?.type === "session" && e.message?.type === "status"), 10_000);
  }
  private vrid = 0;
  /** Sends a session message on a route and waits for the response/rpc_error with the same requestId. */
  async routeRequest(routeId: string, message: Record<string, unknown>, timeoutMs = 8000): Promise<any> {
    const requestId = (message.requestId as string) ?? `v-${++this.vrid}-${randomUUID().slice(0, 6)}`;
    await this.routeSend(routeId, { type: "session", message: { ...message, requestId } });
    const env = await this.routeNext(routeId, (e) => e?.type === "session" && (e.message?.payload?.requestId === requestId || e.message?.requestId === requestId), timeoutMs);
    if (!env) return null;
    if (env.__closed) return env;
    return env.message;
  }
}
