// Protocol-level test clients for the two security modules (credential-negative, resource-stress).
//
// These modules talk to the OWNER test daemon's own room endpoint and lane endpoints directly, as a
// member device would, so that they can send frames a correct member daemon never sends (tampered
// grants, replayed requests, oversized frames). The member side is built from the plugin's own code:
// RoomClient (Noise IK room sessions), the enrollment and device-link formats, and Paseo's client
// secure channel (Noise NK) for lane links. The member TEST DAEMON is not used by these modules.
//
// Loopback only: every connection goes to the fake relay that run.sh starts on 127.0.0.1 (port
// 6930-6939, `RL_RELAY_ENDPOINT`). Before any frame is sent, the room's relay (from the invite, the
// genesis or the lane offer) must equal that relay; otherwise the helpers throw. So no protocol traffic
// from these modules can reach relay.paseo.sh or any other host.
//
// Secrets (invite and link codes and tokens, grants) stay in memory, go to the cleanup's secret-scan
// file through lib.rememberSecret, and are never printed. SAS digits are compared, never logged.
import { randomBytes, randomUUID, type KeyObject } from "node:crypto";
import WebSocket from "ws";
import { openClientSecureChannel, type SecureChannel, type Transport } from "@getpaseo/relay/e2ee";
import type { RoomGenesis } from "../../server/authority/genesis";
import { edKid } from "../../server/authority/state";
import { decodeInvite, type InvitePayload } from "../../server/host/invites";
import { DeviceLinker } from "../../server/member/device-link";
import { RoomClient, RoomSessionError } from "../../server/member/room-client";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { decodeLink, type DeviceLinkPayload } from "../../server/proto/device-link";
import { computeSas, enrollSigned, enrollTokenMac, sasCommitOf, signEnroll, tokenKeyOf, type EnrollTarget } from "../../server/proto/enroll";
import { ed25519PrivateKeyFromSeed, rawPublicKey, x25519PrivateKeyFromSecret } from "../../server/proto/keys";
import type { Frame } from "../../server/transport/records";
import { relayClientUrl, type RelayAddress } from "../../server/transport/relay-server";
import { OWNER_HOME, PORT_MAX, PORT_MIN, adminRpc, ownedRoom, pluginLogsRaw, rememberSecret, sleep, until, verifyOwnerLog } from "./lib";

export { RoomSessionError };

// ------------------------------------------------------------------ loopback relay gate

/** The loopback relay run.sh started (`RL_RELAY_ENDPOINT=127.0.0.1:<port>`). Throws if unset or unsafe. */
export function loopbackRelay(): { endpoint: string; host: string; port: number } {
  const raw = process.env.RL_RELAY_ENDPOINT ?? "";
  const m = /^127\.0\.0\.1:(\d{4})$/.exec(raw);
  if (!m) throw new Error("refusing: RL_RELAY_ENDPOINT must be 127.0.0.1:<port> (run through test/reliability/run.sh)");
  const port = Number(m[1]);
  if (port === 6767 || port < PORT_MIN || port > PORT_MAX) throw new Error(`refusing: relay port ${port} outside ${PORT_MIN}-${PORT_MAX}`);
  return { endpoint: raw, host: "127.0.0.1", port };
}

/**
 * The relay address to use for a room or lane whose recorded relay is `relay`. Throws unless it is the
 * loopback test relay: these modules never send protocol traffic anywhere else.
 */
export function onLoopbackRelay(relay: { host: string; port: number }): RelayAddress {
  const lb = loopbackRelay();
  if (relay.host !== lb.host || relay.port !== lb.port) {
    throw new Error("refusing: this room is not on the loopback test relay (was the owner daemon restarted by run.sh?); no protocol traffic is sent");
  }
  return { endpoint: lb.endpoint, useTls: false };
}

// ------------------------------------------------------------------ test devices and codes

/**
 * A member device: an Ed25519 signing key and an X25519 DH key, in memory only. Fresh keys by default;
 * `sigSeed` reuses another device's signing key with a new DH key (the removed-device case).
 */
export class TestDevice {
  readonly label: string;
  readonly sigSeed: Buffer;
  readonly dhSecret: Buffer;
  readonly sigKey: KeyObject;
  readonly deviceSig: string;
  readonly dhPublic: Uint8Array;
  readonly deviceDh: string;

  constructor(label: string, sigSeed?: Buffer) {
    this.label = label;
    this.sigSeed = sigSeed ? Buffer.from(sigSeed) : randomBytes(32);
    this.dhSecret = randomBytes(32);
    this.sigKey = ed25519PrivateKeyFromSeed(this.sigSeed);
    this.deviceSig = b64u(rawPublicKey(this.sigKey));
    this.dhPublic = new Uint8Array(rawPublicKey(x25519PrivateKeyFromSecret(this.dhSecret)));
    this.deviceDh = b64u(this.dhPublic);
  }

  get sigKid(): string {
    return edKid(this.deviceSig);
  }

  noise(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return { publicKey: new Uint8Array(this.dhPublic), secretKey: new Uint8Array(this.dhSecret) };
  }
}

/** An invite (`prc2.`) or device link (`prl2.`) code, decoded strictly by the plugin's own decoders. */
export type JoinCode = { kind: "invite"; payload: InvitePayload } | { kind: "link"; payload: DeviceLinkPayload };

export function inviteCode(code: string): JoinCode {
  const payload = decodeInvite(code);
  onLoopbackRelay(payload.endpoint.relay);
  return { kind: "invite", payload };
}

export function linkCode(code: string): JoinCode {
  const payload = decodeLink(code);
  onLoopbackRelay(payload.endpoint.relay);
  return { kind: "link", payload };
}

export function targetOf(code: JoinCode): EnrollTarget {
  return code.kind === "invite" ? { inviteId: code.payload.inviteId } : { linkId: code.payload.linkId };
}

/** Tracks a code and its token for the cleanup's secret scan (never printed). */
export function rememberCode(code: string, parsed: JoinCode): void {
  rememberSecret(code);
  rememberSecret(parsed.payload.token);
}

/** Tracks a grant and its signature for the secret scan. */
export function rememberGrant(token: string): void {
  rememberSecret(token);
  const sig = token.split(".")[2];
  if (sig && sig.length >= 20) rememberSecret(sig);
}

// ------------------------------------------------------------------ room sessions

/** A pre-auth room session (handshake only) to the room endpoint named by a code. */
export async function preauthSession(code: JoinCode, device: TestDevice, pushes?: Frame[]): Promise<RoomClient> {
  const p = code.payload;
  const relay = onLoopbackRelay(p.endpoint.relay);
  const c = new RoomClient({
    target: { genesisHash: p.genesisHash, endpoint: { serverId: p.endpoint.serverId, dh: { pub: p.endpoint.dh.pub } } },
    device: device.noise(),
    relay,
    onPush: (f) => void pushes?.push(f),
  });
  await c.open();
  return c;
}

/**
 * An `enroll.request` exactly as enroll-client.ts builds it, signed over the session's handshake hash
 * `h`. `token: "wrong"` uses a random token for the MAC (a failed token proof). Passing another
 * session's `h` builds a request that is valid only for that other session (a replay).
 */
export function enrollRequest(code: JoinCode, device: TestDevice, h: string, o: { nm: Uint8Array; token: "valid" | "wrong"; target?: EnrollTarget }): Omit<Frame, "id"> {
  const target = o.target ?? targetOf(code);
  const sasCommit = sasCommitOf(o.nm);
  const signed = enrollSigned({ h, genesisHash: code.payload.genesisHash, target, deviceSig: device.deviceSig, deviceDh: device.deviceDh, label: device.label, sasCommit });
  const token = o.token === "valid" ? b64uDecode(code.payload.token, 32) : randomBytes(32);
  const key = tokenKeyOf(token, code.kind);
  try {
    return {
      t: "enroll.request",
      v: 2,
      ...target,
      deviceSig: device.deviceSig,
      deviceDh: device.deviceDh,
      label: device.label,
      sasCommit,
      tokenMac: b64u(enrollTokenMac(key, signed)),
      sig: b64u(signEnroll(device.sigKey, signed)),
    } as Omit<Frame, "id">;
  } finally {
    key.fill(0);
    token.fill(0);
  }
}

export type PreauthResult = { reply: Frame | null; error: RoomSessionError | null; h: string | null; busyWaitsMs: number };

/**
 * One pre-auth request in a fresh session from `device`, then the session is closed. The room
 * endpoint's pre-auth budget (5 at once, 10 per minute) answers `busy {retryAfter}` when spent; this
 * waits `retryAfter` and retries, at most `maxBusyWaitMs` in total. Used where the budget is not what
 * the test checks.
 */
export async function preauthCall(code: JoinCode, device: TestDevice, build: (h: string) => Omit<Frame, "id">, maxBusyWaitMs = 90_000): Promise<PreauthResult> {
  let waited = 0;
  for (;;) {
    const c = await preauthSession(code, device);
    const h = c.handshakeHash;
    try {
      const reply = await c.request(build(h!), 20_000);
      return { reply, error: null, h, busyWaitsMs: waited };
    } catch (e) {
      if (!(e instanceof RoomSessionError)) throw e;
      if (e.code === "busy" && waited < maxBusyWaitMs) {
        const ms = (Math.min(60, Math.max(1, Number(e.fields.retryAfter) || 6)) + 1) * 1000;
        waited += ms;
        await sleep(ms);
        continue;
      }
      return { reply: null, error: e, h, busyWaitsMs: waited };
    } finally {
      c.close();
    }
  }
}

/** A full room session of an admitted device (RoomClient.connect: hello, log sync, subscribe). */
export async function openMemberSession(device: TestDevice, genesis: RoomGenesis, relay: RelayAddress, pushes: Frame[]): Promise<RoomClient> {
  const c = new RoomClient({ genesis, device: device.noise(), relay, onPush: (f) => void pushes.push(f) });
  await c.connect();
  return c;
}

export type EnrolledDevice = {
  device: TestDevice;
  memberId: string;
  deviceId: string;
  genesis: RoomGenesis;
  relay: RelayAddress;
  session: RoomClient;
  /** Pushes on the current full session (grant.revoked, kp.low, access_ended arrives as an error). */
  pushes: Frame[];
};

/**
 * The real SAS enrollment of an in-process test device: enroll.request -> enroll.pending (its `h` must be
 * this session's) -> sas.reveal -> the owner's card shows the SAS -> TEST-ONLY programmatic comparison
 * (equal digits, never logged) -> enroll.confirm -> owner join.admit -> enroll.admitted push. Then a
 * full room session is opened.
 */
export async function enrollTestDevice(owner: any, roomId: string, code: JoinCode, label: string): Promise<EnrolledDevice> {
  if (code.kind !== "invite") throw new Error("enrollTestDevice takes an invite");
  const device = new TestDevice(label);
  const nm = randomBytes(32);
  const pre: Frame[] = [];
  let c: RoomClient | null = null;
  let pending: Frame | null = null;
  for (let waited = 0; !pending; ) {
    c = await preauthSession(code, device, pre);
    try {
      pending = await c.request(enrollRequest(code, device, c.handshakeHash!, { nm, token: "valid" }), 20_000);
    } catch (e) {
      c.close();
      if (e instanceof RoomSessionError && e.code === "busy" && waited < 90_000) {
        const ms = (Math.min(60, Math.max(1, Number(e.fields.retryAfter) || 6)) + 1) * 1000;
        waited += ms;
        await sleep(ms);
        continue;
      }
      throw e;
    }
  }
  const session = c!;
  try {
    if (pending.t !== "enroll.pending" || pending.h !== session.handshakeHash) throw new Error("enroll.pending is not pinned to this session");
    const pendingId = String(pending.pendingId);
    const sas = computeSas({
      h: b64uDecode(String(pending.h), 32),
      nm,
      nh: b64uDecode(String(pending.Nh), 32),
      deviceDh: device.deviceDh,
      deviceSig: device.deviceSig,
      endpointDh: code.payload.endpoint.dh.pub,
      genesisHash: code.payload.genesisHash,
      target: targetOf(code),
    });
    await session.request({ t: "sas.reveal", Nm: b64u(nm) });
    const card = await until("owner SAS card", async () => (await ownedRoom(owner, roomId))?.joinRequests.find((r: any) => r.pendingId === pendingId && r.sas), 30_000, 200);
    // TEST-ONLY comparison standing in for the people comparing by voice: never skipped, never logged.
    if (card.sas !== sas.display) {
      await session.request({ t: "enroll.abort", pendingId, reason: "sas_mismatch" }).catch(() => undefined);
      throw new Error("SAS mismatch between the test device and the owner: refusing to confirm");
    }
    await session.request({ t: "enroll.confirm", pendingId });
    await until("host saw the device's confirmation", async () => (await ownedRoom(owner, roomId))?.joinRequests.find((r: any) => r.pendingId === pendingId)?.state === "member_ok", 30_000, 200);
    await adminRpc(owner, "rooms.v2.join.admit", { roomId, pendingId });
    const admitted = await until("enroll.admitted push", () => pre.find((f) => f.t === "enroll.admitted") ?? null, 30_000, 100);
    const genesis = (pending as unknown as { genesis: RoomGenesis }).genesis;
    const relay = onLoopbackRelay(code.payload.endpoint.relay);
    session.close();
    const pushes: Frame[] = [];
    const full = await openMemberSession(device, genesis, relay, pushes);
    return { device, memberId: String(admitted.memberId), deviceId: String(admitted.deviceId), genesis, relay, session: full, pushes };
  } finally {
    session.close();
  }
}

/** Reopens the full room session of an enrolled device (after the host closed it, e.g. on bad_frame). */
export async function reconnect(d: EnrolledDevice): Promise<RoomClient> {
  d.session.close();
  d.pushes.length = 0;
  d.session = await openMemberSession(d.device, d.genesis, d.relay, d.pushes);
  return d.session;
}

/** A device-link code created by an enrolled device over its own session (DeviceLinker, in memory). */
export async function createLinkCode(d: EnrolledDevice, roomId: string): Promise<{ code: string; linkId: string }> {
  let state: unknown = undefined;
  const linker = new DeviceLinker({
    roomId,
    genesisHash: d.session.genesisHash,
    memberId: d.memberId,
    deviceId: d.deviceId,
    sigKid: d.device.sigKid,
    sigKey: () => d.device.sigKey,
    endpoint: () => (d.session.state as any).auth.endpoint,
    session: () => (d.session.status === "open" ? d.session : null),
    store: { read: () => state, write: (v) => void (state = v) },
  });
  const r = await linker.create({ roomName: "Security test" });
  return { code: r.code, linkId: r.linkId };
}

// ------------------------------------------------------------------ grants and lane offers

/** `grant.issue` over the device's session; retries `busy` (15 s between issues per device and lane). */
export async function issueGrant(d: EnrolledDevice, laneId: string, maxWaitMs = 40_000): Promise<{ token: string; gid: string; exp: number }> {
  const r = await until(
    "grant.issue",
    async () => {
      try {
        return await d.session.request({ t: "grant.issue", laneId });
      } catch (e) {
        if (e instanceof RoomSessionError && e.code === "busy") return null;
        throw e;
      }
    },
    maxWaitMs,
    2000,
  );
  const token = typeof r.grant === "string" ? r.grant : "";
  const claims = r.claims as { gid?: unknown; exp?: unknown } | undefined;
  if (!token.startsWith("prg2.") || typeof claims?.gid !== "string" || typeof claims.exp !== "number") throw new Error("bad grant.issue reply");
  rememberGrant(token);
  return { token, gid: claims.gid, exp: claims.exp };
}

export type LaneOffer = { serverId: string; publicKeyB64: string; relay: RelayAddress };

/** The lane's endpoint offer from the device's verified fold; the relay must be the loopback relay. */
export function laneOffer(d: EnrolledDevice, laneId: string): LaneOffer {
  const o = (d.session.state as any).auth.lanes[laneId]?.offer;
  if (!o) throw new Error("lane not in the device's verified log");
  return { serverId: o.serverId, publicKeyB64: Buffer.from(b64uDecode(o.dh.pub, 32)).toString("base64"), relay: onLoopbackRelay(o.relay) };
}

// ------------------------------------------------------------------ lane links (Noise NK over the relay)

export type HelloOutcome = { kind: "accepted"; status: any } | { kind: "rejected"; frame: any } | { kind: "closed" } | { kind: "timeout" };

/**
 * One relay client connection to a lane endpoint with Paseo's client secure channel (protected mode),
 * as a member daemon's connected-hosts link opens it. JSON frames in, JSON frames out.
 */
export class LaneLink {
  ws!: WebSocket;
  ch!: SecureChannel;
  opened = false;
  closed = false;
  readonly frames: any[] = [];
  private waiters: Array<{ pred: (m: any) => boolean; resolve: (m: any) => void }> = [];
  private openWaiters: Array<(ok: boolean) => void> = [];

  static async connect(offer: LaneOffer, timeoutMs = 10_000): Promise<LaneLink> {
    const l = new LaneLink();
    const ws = new WebSocket(relayClientUrl(offer.relay, offer.serverId), { perMessageDeflate: false, maxPayload: 64 * 1024 * 1024 });
    l.ws = ws;
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
      transport.onclose?.(code, reason.toString());
      l.markClosed();
    });
    ws.on("error", (e) => transport.onerror?.(e));
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("relay open timeout")), timeoutMs);
      ws.once("open", () => (clearTimeout(t), resolve()));
      ws.once("error", (e) => (clearTimeout(t), reject(e)));
    });
    l.ch = await openClientSecureChannel(transport, {
      daemonPublicKeyB64: offer.publicKeyB64,
      minimumMode: "protected",
      events: {
        onopen: () => {
          l.opened = true;
          for (const w of l.openWaiters.splice(0)) w(true);
        },
        onmessage: (data) => l.onMessage(data),
        onclose: () => l.markClosed(),
        onerror: () => undefined,
      },
    });
    return l;
  }

  private markClosed(): void {
    if (this.closed) return;
    this.closed = true;
    for (const w of this.waiters.splice(0)) w.resolve(null);
    for (const w of this.openWaiters.splice(0)) w(false);
  }

  private onMessage(data: string | ArrayBuffer): void {
    if (typeof data !== "string") return;
    let m: any;
    try {
      m = JSON.parse(data);
    } catch {
      return;
    }
    const w = this.waiters.find((x) => x.pred(m));
    if (w) {
      this.waiters.splice(this.waiters.indexOf(w), 1);
      w.resolve(m);
    } else this.frames.push(m);
  }

  /** Resolves true once the Noise handshake completed (the endpoint served this connection). */
  waitOpen(timeoutMs: number): Promise<boolean> {
    if (this.opened) return Promise.resolve(true);
    if (this.closed) return Promise.resolve(false);
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), timeoutMs);
      this.openWaiters.push((ok) => (clearTimeout(t), resolve(ok)));
    });
  }

  send(obj: unknown): Promise<void> {
    return this.ch.send(typeof obj === "string" ? obj : JSON.stringify(obj));
  }

  sendBinary(bytes: Uint8Array): Promise<void> {
    return this.ch.send(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  }

  /** The next frame matching `pred` (buffered or future); null on close or timeout. */
  next(pred: (m: any) => boolean, timeoutMs = 10_000): Promise<any> {
    const hit = this.frames.find(pred);
    if (hit) {
      this.frames.splice(this.frames.indexOf(hit), 1);
      return Promise.resolve(hit);
    }
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => {
      const w = { pred, resolve: (m: any) => (clearTimeout(t), resolve(m)) };
      const t = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        resolve(null);
      }, timeoutMs);
      this.waiters.push(w);
    });
  }

  /** Resolves true once the connection is closed (by either side), false after `timeoutMs`. */
  async waitClosed(timeoutMs: number): Promise<boolean> {
    const s = Date.now();
    while (!this.closed && Date.now() - s < timeoutMs) await sleep(100);
    return this.closed;
  }

  /** The host-link hello a member daemon sends, with `password` as the grant. */
  async hello(password: unknown, timeoutMs = 10_000): Promise<HelloOutcome> {
    await this.send({
      type: "hello",
      clientId: `rooms-sec-${randomUUID().slice(0, 8)}`,
      clientType: "cli",
      protocolVersion: 1,
      appVersion: "0.13.2",
      capabilities: { hello_rejection: true },
      auth: { kind: "password", password },
    });
    const m = await this.next((f) => f?.type === "hello.rejected" || (f?.type === "session" && f.message?.type === "status"), timeoutMs);
    if (m?.type === "hello.rejected") return { kind: "rejected", frame: m };
    if (m) return { kind: "accepted", status: m.message };
    return this.closed ? { kind: "closed" } : { kind: "timeout" };
  }

  ping(): Promise<void> {
    return this.send({ type: "ping" });
  }

  /** hosts.link.open.request: a routed view on this link. */
  async openRoute(requestId: string, timeoutMs = 10_000): Promise<{ routeId: string } | { error: any } | null> {
    await this.send({ type: "session", message: { type: "hosts.link.open.request", requestId, channelId: `ch-${requestId}` } });
    const m = await this.next(
      (f) => f?.type === "session" && f.message?.payload?.requestId === requestId && (f.message.type === "hosts.link.open.response" || f.message.type === "rpc_error"),
      timeoutMs,
    );
    if (!m) return null;
    return m.message.type === "hosts.link.open.response" ? { routeId: m.message.payload.routeId } : { error: m.message.payload };
  }

  /** One viewer message on a route (the JSON string inside hosts.route.frame.request). */
  routeSend(routeId: string, msg: unknown): Promise<void> {
    return this.send({ type: "session", message: { type: "hosts.route.frame.request", routeId, data: typeof msg === "string" ? msg : JSON.stringify(msg) } });
  }

  /** The next viewer frame on a route whose parsed content matches `pred`. */
  async routeNext(routeId: string, pred: (inner: any) => boolean, timeoutMs = 10_000): Promise<any> {
    const parse = (f: any) => {
      if (f?.type !== "session" || f.message?.type !== "hosts.route.frame" || f.message.payload?.subscriptionId !== routeId) return null;
      try {
        return JSON.parse(f.message.payload.data);
      } catch {
        return null;
      }
    };
    const m = await this.next((f) => {
      const inner = parse(f);
      return inner !== null && pred(inner);
    }, timeoutMs);
    return m ? parse(m) : null;
  }

  /** The `hosts.route.closed` notice for a route, or null. */
  routeClosed(routeId: string, timeoutMs = 10_000): Promise<any> {
    return this.next((f) => f?.type === "session" && f.message?.type === "hosts.route.closed" && f.message.payload?.subscriptionId === routeId, timeoutMs).then((m) => m?.message.payload ?? null);
  }

  close(): void {
    try {
      this.ch?.close(1000, "test done");
    } catch {}
    try {
      this.ws?.close(1000, "test done");
    } catch {}
    this.markClosed();
  }
}

/** Connects, sends the hello and returns the link and the outcome. */
export async function linkWith(offer: LaneOffer, password: unknown, timeoutMs = 10_000): Promise<{ link: LaneLink; outcome: HelloOutcome }> {
  const link = await LaneLink.connect(offer);
  const outcome = await link.hello(password, timeoutMs);
  return { link, outcome };
}

/** The generic refusal every bad grant gets on the link hello (grants-v2 section 4: no reason disclosed). */
export const GENERIC_HELLO_REJECTION = { type: "hello.rejected", reason: "incorrect_password", accepts: ["password"] };

// ------------------------------------------------------------------ owner-side state and leak checks

/** What a refused attempt must not change in the owner's room (status view; no secrets, no timings). */
export async function ownerSnap(owner: any, roomId: string) {
  const r = await ownedRoom(owner, roomId);
  if (!r) throw new Error("owned room not in status");
  const by = (k: string) => (a: any, b: any) => String(a[k]).localeCompare(String(b[k]));
  return {
    roster: r.roster.map((m: any) => ({ memberId: m.memberId, role: m.role, lanes: [...m.lanes].sort(), devices: m.devices.map((d: any) => d.deviceId).sort() })).sort(by("memberId")),
    invites: r.invites.map((i: any) => ({ inviteId: i.inviteId, state: i.state, failedProofs: i.failedProofs, abandoned: i.abandoned })).sort(by("inviteId")),
    joinRequests: r.joinRequests.map((j: any) => ({ pendingId: j.pendingId, state: j.state, closedReason: j.closedReason })).sort(by("pendingId")),
    grants: r.grants.map((g: any) => ({ deviceId: g.deviceId, laneId: g.laneId, gid: g.gid })).sort(by("gid")),
    lanes: r.lanes.map((l: any) => ({ laneId: l.laneId, status: l.status })).sort(by("laneId")),
    compromised: [...r.compromisedDevices].sort(),
    keys: { hostKid: r.keys.hostKid, adminKid: r.keys.adminKid },
  };
}

/** Number of entries in the owner's room log (independently verified fold of the files). */
export function logLength(roomId: string): number {
  return verifyOwnerLog(OWNER_HOME(), roomId).types.length;
}

/**
 * Types of the entries appended since `from`, without MLS delivery entries (`mls.*`), which the owner's
 * own device may append in the background. A refused attempt must append none.
 */
export function newEntryTypes(roomId: string, from: number): string[] {
  return verifyOwnerLog(OWNER_HOME(), roomId)
    .types.slice(from)
    .filter((t) => !t.startsWith("mls."));
}

/** True when none of `secrets` occurs in `text`. Never prints either. */
export function containsNone(text: string, secrets: readonly string[]): boolean {
  return !secrets.filter((s) => s.length >= 16).some((s) => text.includes(s));
}

/** The owner daemon's plugin log contains none of `secrets` (unredacted text, checked in memory only). */
export async function ownerLogsClean(secrets: readonly string[]): Promise<boolean> {
  return containsNone(await pluginLogsRaw(OWNER_HOME()), secrets);
}

/** A copy of a grant with one character of a part (0 prefix, 1 claims, 2 signature) changed. */
export function flipChar(token: string, part: 1 | 2, at = 10): string {
  const parts = token.split(".");
  const s = parts[part];
  const i = Math.min(at, s.length - 1);
  parts[part] = s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
  return parts.join(".");
}

/** A grant whose claims are re-encoded with `patch` applied, keeping the original signature (a forgery). */
export function reclaim(token: string, patch: Record<string, unknown>): string {
  const [prefix, claims, sig] = token.split(".");
  const obj = JSON.parse(Buffer.from(claims, "base64url").toString("utf8")) as Record<string, unknown>;
  const next = Object.fromEntries(Object.entries({ ...obj, ...patch }).sort(([a], [b]) => (a < b ? -1 : 1)));
  return `${prefix}.${Buffer.from(JSON.stringify(next)).toString("base64url")}.${sig}`;
}

/** A RoomSessionError's code and extra fields (the whole reply minus t and re), or null. */
export function errorOf(e: unknown): { code: string; fields: Record<string, unknown> } | null {
  return e instanceof RoomSessionError ? { code: e.code, fields: e.fields } : null;
}
