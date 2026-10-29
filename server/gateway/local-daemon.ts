// Raw connections from the lane endpoint to the owner's own daemon (loopback), each capped with
// hello.sessionPermissions (honoured per permission on 0.13.2; security spike).
// The local credential is read from $PASEO_HOME and never logged.
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseHostTarget } from "@getpaseo/protocol/host-target";
import WebSocket from "ws";
import { FIELD_POLICY } from "../room-profile/generated";
import { REDACTORS } from "../room-profile/sanitize";

/** Permission ceiling for every upstream session a lane opens. */
export const UPSTREAM_CEILING = ["workspace.read"] as const;

export function readListen(home: string): string {
  const lock = JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8"));
  if (typeof lock.listen !== "string" || !lock.listen) throw new Error("daemon listen address not found in paseo.pid");
  return lock.listen;
}

export function readLocalCredential(home: string): string | undefined {
  try {
    const token = readFileSync(join(home, "local-credential"), "utf8").trim();
    return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : undefined;
  } catch {
    return undefined;
  }
}

/** Where to open the upstream socket: a ws URL, plus a socket path for named pipes and unix sockets. */
export interface DaemonTarget {
  url: string;
  socketPath?: string;
}

const WILDCARD_HOSTS: Record<string, string> = { "0.0.0.0": "127.0.0.1", "[::]": "[::1]" };

/**
 * Maps the daemon's listen address (paseo.pid `listen`, written by Paseo's formatListenTarget) to a
 * connect target (cross-platform audit X-3). Parsed with @getpaseo/protocol's parseHostTarget, the
 * grammar Paseo's own client uses. Forms: `host:port` (wildcard binds 0.0.0.0 and [::] map to
 * loopback), `/abs/sock`, `~/sock`, `unix:///sock`, the older `unix:/sock`, `\\.\pipe\name` and
 * `pipe://name`. Pipes and unix sockets connect to ws://localhost/ws over a socket opened on that
 * path. Relay, ssh and ws(s) URLs are not listen addresses and are refused.
 * Windows pipes and macOS are untested; the logic is unit-tested on Linux.
 */
export function daemonTargetFromListen(listen: string, home: () => string = homedir): DaemonTarget {
  let input = listen.trim();
  if (input.startsWith("unix:") && !input.startsWith("unix://")) input = `unix://${input.slice("unix:".length)}`;
  let target;
  try {
    target = parseHostTarget(input);
  } catch {
    throw new Error("daemon listen address in paseo.pid is not a supported form");
  }
  if (target.kind !== "socket" || target.offer || target.password !== undefined)
    throw new Error("daemon listen address in paseo.pid is not a local address");
  if (target.socketPath !== undefined) {
    let socketPath = target.socketPath;
    if (socketPath.startsWith("~/") || socketPath.startsWith("~\\")) socketPath = join(home(), socketPath.slice(2));
    else if (socketPath.startsWith("~")) throw new Error("daemon listen address in paseo.pid uses an unsupported ~user path");
    return { url: "ws://localhost/ws", socketPath };
  }
  const url = new URL(target.url);
  if (url.protocol !== "ws:") throw new Error("daemon listen address in paseo.pid is not a local address");
  const loopback = WILDCARD_HOSTS[url.hostname];
  if (loopback) url.hostname = loopback;
  return { url: url.toString() };
}

export function daemonTarget(home: string): DaemonTarget {
  return daemonTargetFromListen(readListen(home));
}

export function openDaemonSocket(home: string, maxPayload = 32 * 1024 * 1024): WebSocket {
  const target = daemonTarget(home);
  const socketPath = target.socketPath;
  // ws 8.22 ignores a `socketPath` option (initAsClient resets it), so pipes and unix sockets are
  // opened through createConnection instead.
  return new WebSocket(target.url, { maxPayload, perMessageDeflate: false, ...(socketPath !== undefined ? { createConnection: () => connect({ path: socketPath }) } : {}) });
}

/** Upstream client type. Not used for authorization by the 0.13.2 daemon; constant so it is never viewer-chosen. */
export const UPSTREAM_CLIENT_TYPE = "browser";

/**
 * Upstream hello, built from scratch (code review C-2, protocol review P-18). No viewer field is
 * spread into it:
 *   - clientId is chosen by the gateway (fixed per lane, member and route slot);
 *   - auth is the owner daemon's local credential; sessionPermissions is the read-only ceiling;
 *   - capabilities come from the reviewed table hello.capabilities: the three modern-mode flags are
 *     forced on (otherwise the daemon broadcasts every agent's streams to the session), rendering
 *     format flags are copied only when the viewer sets them to true, everything else is dropped
 *     (voice, pushNotifications, browser_host, unknown passthrough keys);
 *   - protocolVersion and appVersion are copied only when they are well-formed.
 */
export function buildUpstreamHello(home: string, viewer: Record<string, unknown> | null, clientId: string): Record<string, unknown> {
  const token = readLocalCredential(home);
  const v = viewer ?? {};
  const capsIn = (v.capabilities && typeof v.capabilities === "object" ? v.capabilities : {}) as Record<string, unknown>;
  const policy = FIELD_POLICY["hello.capabilities"] ?? {};
  const capabilities: Record<string, boolean> = {};
  for (const [name, action] of Object.entries(policy)) {
    if (action === "force") capabilities[name] = true;
    else if (action === "keep" && capsIn[name] === true) capabilities[name] = true;
  }
  const protocolVersion = REDACTORS["hello.protocolVersion"](v.protocolVersion, null as never, v);
  const appVersion = REDACTORS["hello.appVersion"](v.appVersion, null as never, v);
  return {
    type: "hello",
    clientId,
    clientType: UPSTREAM_CLIENT_TYPE,
    protocolVersion,
    ...(typeof appVersion === "string" ? { appVersion } : {}),
    capabilities,
    ...(token ? { auth: { kind: "localCredential", token } } : {}),
    sessionPermissions: [...UPSTREAM_CEILING],
  };
}

/** Minimal request/response client on a raw, capped daemon socket. */
export class RawDaemon {
  private ws: WebSocket | null = null;
  private waiters = new Map<string, (m: any) => void>();
  private seq = 0;
  serverInfo: any = null;
  closed = false;

  constructor(private readonly home: string) {}

  async connect(clientId: string, timeoutMs = 10_000): Promise<void> {
    const ws = openDaemonSocket(this.home);
    this.ws = ws;
    ws.on("close", () => {
      this.closed = true;
      for (const w of this.waiters.values()) w({ type: "rpc_error", payload: { error: "upstream closed" } });
      this.waiters.clear();
    });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("daemon connect timeout")), timeoutMs);
      ws.once("open", () =>
        ws.send(JSON.stringify(buildUpstreamHello(this.home, null, clientId))),
      );
      ws.once("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
      ws.on("message", (raw, isBinary) => {
        if (isBinary) return;
        let msg: any;
        try {
          msg = JSON.parse(raw.toString());
        } catch {
          return;
        }
        if (msg.type === "hello.rejected") {
          clearTimeout(timer);
          reject(new Error(`daemon rejected hello: ${msg.reason}`));
          return;
        }
        if (msg.type !== "session") return;
        const m = msg.message;
        if (m?.type === "status" && m.payload?.status === "server_info" && !this.serverInfo) {
          this.serverInfo = m.payload;
          clearTimeout(timer);
          resolve();
        }
        const rid = m?.payload?.requestId ?? m?.requestId;
        if (rid && this.waiters.has(rid)) {
          const w = this.waiters.get(rid)!;
          this.waiters.delete(rid);
          w(m);
        }
      });
    });
  }

  request(message: Record<string, unknown>, timeoutMs = 15_000): Promise<any> {
    const ws = this.ws;
    if (!ws || this.closed) return Promise.reject(new Error("upstream closed"));
    const requestId = `rooms-int-${++this.seq}-${Date.now()}`;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        this.waiters.delete(requestId);
        reject(new Error(`timeout waiting for ${String(message.type)}`));
      }, timeoutMs);
      this.waiters.set(requestId, (m) => {
        clearTimeout(t);
        resolve(m);
      });
      ws.send(JSON.stringify({ type: "session", message: { ...message, requestId } }));
    });
  }

  close(): void {
    try {
      this.ws?.close(1000, "done");
    } catch {}
    this.closed = true;
  }
}
