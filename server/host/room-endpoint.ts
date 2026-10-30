// Room endpoint: the host side of room sessions (implementation plan I-8; enrollment-v2.md 3.1, 3.3 to
// 3.6, 4, 4.1, 10; room-log-v2.md 6, 8.3).
//
// - Registers on the relay as the server for `endpoint.serverId` (relay protocol v2; the control and
//   data sockets of server/transport/relay-server.ts, shared with the M1 lane endpoint).
// - Each relay connection is a Noise IK responder bound to this room by the prologue (P-25). Before
//   the handshake completes, the client may send exactly one binary message of 96 bytes; anything
//   else closes the socket. 10 s per handshake step.
// - Key confirmation (S-10): a session counts only after the initiator's first transport message
//   decrypts and parses as a frame. Only then does it supersede an older session of the same device
//   static (the older one gets `superseded`). A replayed message 1 completes the responder side but
//   never confirms, so it is closed by the timer and cannot push the real device off.
// - Authorization after the handshake (section 4): `rs` an active device DH key -> session operations;
//   a known but ended device -> `access_ended` with its reason, revealed only now (P-23); anything
//   else may use only pre-auth operations (enrollment, server/host/enrollment.ts) and gets
//   `not_authorized` for any other frame. At most 8 sessions of statics that are not active devices
//   are open at a time (5.4); further ones are closed after message 1.
// - Served here: session.hello, log.fetch, log.subscribe (pushes `log.entries`), roster.get and
//   stmt.submit. Later operations of section 4 answer `not_permitted` until their milestone.
// - A session lasts at most 12 h; ping after 30 s of silence, close after 90 s.
// - Room changes (`afterAppend`): sessions of devices that are no longer active get `access_ended`
//   at once; subscribers then receive the new entries.
// - P-16: repeated eviction of the control socket (a relay "Replaced by new connection" close) is
//   logged as a host-produced `endpoint.evicted` statement.
//
// - Grants (I-10, grants-v2.md 3, 6.2, 6.3): `grant.issue`, `grant.status` and `grant.report` on an
//   active device's session, served by HostGrants when the room serves lanes (else `not_permitted`).
//   `pushToDevice` delivers `grant.revoked` events (theft, role change) to the device's session.
// - Revocation order (grants-v2 7.1): a RoomHost decide listener closes the sessions of devices the
//   next state no longer has, and remembers them, before the log append; so access stays cut even if
//   the append fails and the room stops.
//
// - Device links (I-11): `device.link.create`, `link.nonce`, `link.confirm` and `link.abort` from an
//   active device go to the enrollment host, which pushes `link.request`, `link.reveal` and
//   `link.closed` to the link's creator; a creator whose session opens gets what it has not answered.
//
// Not here (later milestones): per-device budgets of every operation (only grants are limited),
// endpoint rotation and `moved` (I-12), MLS operations (I-13).
import { x25519 } from "@noble/curves/ed25519.js";
import { RoomLogFold } from "../authority/fold";
import type { SignedEntry } from "../authority/entries";
import { edKid } from "../authority/state";
import type { SignedStatement } from "../authority/statements";
import { log, logError, short } from "../log";
import { createRoomIkResponder } from "../noise/prologue";
import type { NoiseHandshake, NoiseKeyPair } from "../noise/handshake-state";
import { NOISE_MAX_MESSAGE_BYTES } from "../noise/cipher-state";
import { b64u, b64uDecode } from "../proto/b64u";
import { RecordError, type Frame } from "../transport/records";
import { MAX_CONNECTION_ID_CHARS, parseRelayNotice, RelayConnection, RelayControlSocket, relayServerUrl, type RelayAddress } from "../transport/relay-server";
import {
  IK_MESSAGE1_BYTES,
  isInt,
  isRequestId,
  LATER_OPS,
  LOG_FETCH_MAX,
  LOG_PUSH_MAX,
  LOG_REPLY_BUDGET_BYTES,
  NON_CLOSING_ERRORS,
  PREAUTH_OPS,
  resolveTimings,
  SessionClock,
  SessionCrypto,
  type AccessEndedReason,
  type RoomErrorCode,
  type RoomSessionTimings,
} from "../transport/room-session";
import { EnrollmentHost, LINK_OPS, type EnrollmentHostOptions, type EnrollSession } from "./enrollment";
import { grantStatusFrame, isGrantId, isLaneIdV2, type HostGrants } from "./grants";
import type { RoomState } from "../authority/fold";
import { readHostKeys, type RoomHost, type SubmitResult } from "./room-host";
import type { Kek } from "../keystore/keystore";

export type RoomEndpointStatus = "starting" | "online" | "offline" | "closed";

export type DeviceAccess =
  | { kind: "active"; memberId: string; deviceId: string; role: string; sigKid: string }
  | { kind: "ended"; reason: AccessEndedReason }
  | { kind: "unknown" };

export interface RoomEndpointOptions {
  host: RoomHost;
  /** The room endpoint's X25519 static key (from host/<roomId>/keys.sealed). */
  endpointKey: NoiseKeyPair;
  /** Where the relay is reached (normally the genesis relay with TLS). */
  relay: RelayAddress;
  timings?: Partial<RoomSessionTimings>;
  /** Open relay connections at most (a relay-supplied count). */
  maxConnections?: number;
  /** `endpoint.evicted` after this many control-socket evictions within `evictionWindowS`. */
  evictionThreshold?: number;
  evictionWindowS?: number;
  /** Concurrent sessions of statics that are not active devices (5.4: 8). */
  maxPreauthSessions?: number;
  /** Serve enrollment (pre-auth operations). Without it they get the generic `enroll_rejected`. */
  enrollment?: Omit<EnrollmentHostOptions, "host" | "afterAppend" | "endpointDh" | "now" | "push">;
  /** Lane grants of this room (I-10). Without it the grant operations answer `not_permitted`. */
  grants?: HostGrants;
  /** Called at the end of every afterAppend (lane endpoints follow the log). */
  onAppended?: () => void;
  now?: () => number;
}

const DEFAULT_MAX_CONNECTIONS = 256;
const EMPTY = new Uint8Array(0);

/** The endpoint key held in the host's sealed key file, checked against the folded authority state. */
export function endpointKeyFromHost(dataDir: string, kek: Kek, host: RoomHost): NoiseKeyPair {
  const keys = readHostKeys(dataDir, kek, host.roomId);
  if (!keys) throw new Error("host keys missing");
  const secretKey = new Uint8Array(b64uDecode(keys.endpoint.secret, 32));
  const publicKey = x25519.getPublicKey(secretKey);
  const auth = host.state.auth.endpoint;
  if (keys.endpoint.serverId !== auth.serverId || b64u(publicKey) !== auth.dh.pub) {
    secretKey.fill(0);
    throw new Error("the held room endpoint key is not the room's current endpoint key");
  }
  return { publicKey, secretKey };
}

export class RoomEndpoint {
  status: RoomEndpointStatus = "starting";
  readonly serverId: string;
  readonly timings: RoomSessionTimings;
  readonly connections = new Map<string, RoomConnection>();
  /** Key-confirmed sessions of active devices, by device DH key (b64u): one per device (3.5). */
  private readonly live = new Map<string, RoomConnection>();
  /** Active device DH keys (b64u) at the current head. */
  private active = new Map<string, Extract<DeviceAccess, { kind: "active" }>>();
  /** Device DH keys that were in the roster and left it without a successor key (removed, left). */
  private readonly ended = new Map<string, AccessEndedReason>();
  /** Fold of the host's log kept here to learn why a device left the roster. */
  private readonly history: RoomLogFold;
  private control: RelayControlSocket | null = null;
  private stopped = false;
  private evictions: number[] = [];
  private evictionReported = 0;
  readonly now: () => number;
  readonly enrollment: EnrollmentHost | null;
  /** Device DH keys cut by a decision whose log append may not have happened (grants-v2 7.1, 7.2). */
  private readonly cut = new Map<string, AccessEndedReason>();
  /** The session whose own `stmt.submit` is being sequenced: it gets its receipt before it is cut. */
  submitting: RoomConnection | null = null;
  private readonly unhook: () => void;

  constructor(readonly o: RoomEndpointOptions) {
    this.serverId = o.host.state.auth.endpoint.serverId;
    this.timings = resolveTimings(o.timings);
    this.now = o.now ?? Date.now;
    if (b64u(o.endpointKey.publicKey) !== o.host.state.auth.endpoint.dh.pub) throw new Error("room endpoint key does not match the room's endpoint");
    this.history = RoomLogFold.fromGenesis(o.host.genesis);
    this.catchUp();
    this.enrollment = o.enrollment
      ? new EnrollmentHost({
          ...o.enrollment,
          host: o.host,
          now: this.now,
          afterAppend: () => this.afterAppend(),
          endpointDh: () => o.host.state.auth.endpoint.dh.pub,
          push: (deviceId, frame) => this.pushToDevice(deviceId, frame),
        })
      : null;
    this.unhook = o.host.onDecide((next, prev, type) => this.decide(next, prev, type));
    if (o.grants) o.grants.notify = (deviceId, frame) => this.pushToDevice(deviceId, frame);
  }

  get grants(): HostGrants | null {
    return this.o.grants ?? null;
  }

  /** Sends an event frame to a device's live session, if it has one. */
  pushToDevice(deviceId: string, frame: Record<string, unknown>): boolean {
    for (const c of this.live.values()) {
      if (c.access.kind === "active" && c.access.deviceId === deviceId) {
        c.send(frame as Frame);
        return true;
      }
    }
    return false;
  }

  /** 7.1 steps 1 and 2 for sessions: devices gone in `next` lose their sessions before the append. */
  private decide(next: Readonly<RoomState>, prev: Readonly<RoomState>, type: string): void {
    const after = devicesByDh(next.members);
    const stillThere = new Set([...after.values()].map((d) => d.deviceId));
    for (const [dh, d] of devicesByDh(prev.members)) {
      if (after.has(dh) || stillThere.has(d.deviceId)) continue;
      const reason: AccessEndedReason = type === "member.left" ? "left" : "removed";
      this.cut.set(dh, reason);
      const conn = this.live.get(dh);
      if (conn && conn !== this.submitting) conn.fail("access_ended", undefined, { reason });
    }
    if (next.auth.closed && !prev.auth.closed) for (const conn of [...this.live.values()]) conn.fail("access_ended", undefined, { reason: "room_closed" });
  }

  get host(): RoomHost {
    return this.o.host;
  }

  get roomId(): string {
    return this.o.host.roomId;
  }

  start(): void {
    if (this.stopped || this.control) return;
    this.control = new RelayControlSocket({
      url: () => relayServerUrl(this.o.relay, this.serverId),
      maxPayload: 64 * 1024,
      logPrefix: "room",
      logFields: { roomId: this.roomId },
      serverId: this.serverId,
      onNotice: (msg) => this.onRelayNotice(msg),
      onStatus: (s) => {
        if (!this.stopped) this.status = s;
      },
      onClose: (code, reason) => this.onControlClosed(code, reason),
    });
    this.control.connect();
  }

  stop(why = "stopped"): void {
    if (this.stopped) return;
    this.stopped = true;
    this.status = "closed";
    for (const c of [...this.connections.values()]) c.close(why);
    this.enrollment?.stop();
    this.unhook();
    this.control?.stop(1001, "room endpoint stopped");
    log("room_endpoint_stopped", { roomId: this.roomId, why });
  }

  /** Relay control notices: data sockets for new connections (capped), and disconnects. */
  onRelayNotice(msg: unknown): void {
    const notice = parseRelayNotice(msg);
    if (notice.disconnected !== null) this.connections.get(notice.disconnected)?.close("relay_disconnected");
    for (const id of notice.announced) {
      if (typeof id !== "string" || !id || id.length > MAX_CONNECTION_ID_CHARS || this.connections.has(id) || this.stopped) continue;
      if (this.connections.size >= (this.o.maxConnections ?? DEFAULT_MAX_CONNECTIONS)) {
        log("room_connection_cap", { roomId: this.roomId, open: this.connections.size });
        continue;
      }
      const conn = new RoomConnection(this, id);
      this.connections.set(id, conn);
      conn.start();
    }
  }

  /** What a device DH key (b64u) may do now (section 4). */
  accessOf(dh: string): DeviceAccess {
    const closed = this.o.host.state.auth.closed;
    const a = this.active.get(dh);
    if (closed) return a || this.ended.has(dh) ? { kind: "ended", reason: "room_closed" } : { kind: "unknown" };
    const cut = this.cut.get(dh);
    if (cut) return { kind: "ended", reason: cut };
    if (a) return a;
    const reason = this.ended.get(dh);
    return reason ? { kind: "ended", reason } : { kind: "unknown" };
  }

  /** `stmt.submit` on behalf of a session, or by the owner's own daemon; pushes and enforces on success. */
  submit(statement: unknown): SubmitResult {
    const res = this.o.host.submit(statement);
    if (res.ok) this.afterAppend();
    return res;
  }

  /**
   * Call after anything appended to the room log (also host-produced statements and statements the
   * owner's daemon submitted locally): ended devices lose their sessions at once, then subscribers
   * get the new entries.
   */
  afterAppend(): void {
    this.catchUp();
    for (const conn of [...this.live.values()]) {
      const access = this.accessOf(conn.deviceDh!);
      if (access.kind === "active") continue;
      if (access.kind === "ended") conn.fail("access_ended", undefined, { reason: access.reason });
      else conn.fail("not_authorized");
    }
    for (const conn of this.live.values()) conn.pump();
    try {
      this.enrollment?.onAppended();
    } catch (e) {
      logError("room_endpoint_enrollment_follow_failed", e, { roomId: this.roomId });
    }
    try {
      this.o.onAppended?.();
    } catch (e) {
      logError("room_endpoint_on_appended_failed", e, { roomId: this.roomId });
    }
  }

  /** Called by a connection once its key-confirmed static is an active device. */
  register(conn: RoomConnection): void {
    const dh = conn.deviceDh!;
    const old = this.live.get(dh);
    this.live.set(dh, conn);
    if (old && old !== conn) {
      log("room_session_superseded", { roomId: this.roomId, old: old.tag, by: conn.tag });
      old.fail("superseded");
    }
    if (conn.access.kind === "active") {
      const deviceId = conn.access.deviceId;
      // After the reply to the frame that confirmed the session: link requests the device has not answered.
      queueMicrotask(() => {
        try {
          if (conn.isOpen()) this.enrollment?.onDeviceOnline(deviceId);
        } catch (e) {
          logError("room_endpoint_link_repush_failed", e, { roomId: this.roomId });
        }
      });
    }
  }

  /** Open sessions (past message 1) whose static is not an active device. */
  preauthSessions(): number {
    let n = 0;
    for (const c of this.connections.values()) if ((c.state === "unconfirmed" || c.state === "open") && c.deviceDh && this.accessOf(c.deviceDh).kind !== "active") n++;
    return n;
  }

  unregister(conn: RoomConnection): void {
    if (conn.deviceDh && this.live.get(conn.deviceDh) === conn) this.live.delete(conn.deviceDh);
    this.connections.delete(conn.connectionId);
  }

  /** Live, key-confirmed sessions (owner view and tests). */
  sessions(): { deviceId: string; memberId: string; connection: string | null }[] {
    return [...this.live.values()].map((c) => ({ deviceId: (c.access as { deviceId: string }).deviceId, memberId: (c.access as { memberId: string }).memberId, connection: c.tag }));
  }

  // --------------------------------------------------------------------------------- internals

  /** Advances the history fold to the host's head and rebuilds the access maps. */
  private catchUp(): void {
    const host = this.o.host;
    const from = this.history.head.seq + 1;
    for (const r of host.entries(from)) {
      const before = devicesByDh(this.history.state.members);
      this.history.append(r.signed, r.body);
      const after = devicesByDh(this.history.state.members);
      const stillThere = new Set([...after.values()].map((d) => d.deviceId));
      for (const [dh, d] of before) {
        if (after.has(dh) || stillThere.has(d.deviceId)) continue; // present, or a rekey (old key retired)
        this.ended.set(dh, r.signed.entry.type === "member.left" ? "left" : "removed");
      }
    }
    this.active = new Map();
    for (const m of Object.values(host.state.members)) {
      for (const d of m.devices) this.active.set(d.dh, { kind: "active", memberId: m.memberId, deviceId: d.deviceId, role: m.role, sigKid: edKid(d.sig) });
    }
  }

  private onControlClosed(code: number, reason: string): void {
    if (this.stopped || code !== 1008 || !/replaced/i.test(reason)) return;
    const n = this.now();
    const windowMs = (this.o.evictionWindowS ?? 600) * 1000;
    this.evictions = [...this.evictions.filter((t) => n - t < windowMs), n];
    log("room_endpoint_evicted", { roomId: this.roomId, count: this.evictions.length });
    const threshold = this.o.evictionThreshold ?? 3;
    if (this.evictions.length >= threshold && n - this.evictionReported >= windowMs) {
      this.evictionReported = n;
      try {
        this.o.host.emit("endpoint.evicted", { serverId: this.serverId, count: this.evictions.length, windowS: Math.round(windowMs / 1000) });
        this.afterAppend();
      } catch (e) {
        logError("room_endpoint_evicted_emit_failed", e, { roomId: this.roomId });
      }
    }
  }
}

function devicesByDh(members: Readonly<Record<string, { memberId: string; devices: readonly { deviceId: string; dh: string }[] }>>): Map<string, { memberId: string; deviceId: string }> {
  const out = new Map<string, { memberId: string; deviceId: string }>();
  for (const m of Object.values(members)) for (const d of m.devices) out.set(d.dh, { memberId: m.memberId, deviceId: d.deviceId });
  return out;
}

// -------------------------------------------------------------------------------------------------

type ConnState = "handshake" | "unconfirmed" | "open" | "closed";

/** One relay connection: IK responder, then one room session. */
export class RoomConnection implements EnrollSession {
  state: ConnState = "handshake";
  access: DeviceAccess = { kind: "unknown" };
  /** Initiator static (b64u), known after message 1 authenticated. */
  deviceDh: string | null = null;
  /** Handshake hash `h` (b64u), known after message 2 was written. */
  h = "";
  private relay: RelayConnection | null = null;
  private hs: NoiseHandshake;
  private crypto: SessionCrypto | null = null;
  private stepTimer: ReturnType<typeof setTimeout> | null = null;
  private clock: SessionClock | null = null;
  /** Next seq to push to a subscriber, or null when not subscribed. */
  private cursor: number | null = null;

  constructor(
    readonly endpoint: RoomEndpoint,
    readonly connectionId: string,
  ) {
    const host = endpoint.host;
    this.hs = createRoomIkResponder({ binding: { genesisHash: b64uDecode(host.genesisHash, 32), serverId: endpoint.serverId }, endpointStatic: endpoint.o.endpointKey });
  }

  get tag(): string | null {
    return short(this.connectionId);
  }

  start(): void {
    const ep = this.endpoint;
    const rc = new RelayConnection(relayServerUrl(ep.o.relay, ep.serverId, this.connectionId), NOISE_MAX_MESSAGE_BYTES);
    this.relay = rc;
    rc.open({
      onOpen: () => this.arm("handshake_timeout"),
      onMessage: (data, isBinary) => this.onMessage(data, isBinary),
      onClose: () => this.close("data_socket_closed"),
      onError: (err) => log("room_conn_error", { roomId: ep.roomId, conn: this.tag, error: err.message.slice(0, 200) }),
    });
  }

  private arm(why: string): void {
    if (this.stepTimer) clearTimeout(this.stepTimer);
    this.stepTimer = setTimeout(() => {
      if (this.state === "handshake" || this.state === "unconfirmed") this.preauthFail(why);
    }, this.endpoint.timings.handshakeTimeoutMs);
  }

  private preauthFail(reason: string): void {
    this.endpoint.host.access.record({ event: "preauth_failed", reason });
    this.close(reason);
  }

  private onMessage(data: ArrayBuffer | string, isBinary: boolean): void {
    if (this.state === "closed") return;
    if (!isBinary || typeof data === "string") return this.preauthFail("text_message");
    const bytes = new Uint8Array(data);
    if (this.state === "handshake") return this.onHandshake(bytes);
    let frame: Frame | null;
    try {
      frame = this.crypto!.open(bytes);
    } catch (err) {
      if (this.state === "unconfirmed") return this.preauthFail("key_confirmation_failed");
      log("room_session_record_error", { roomId: this.endpoint.roomId, conn: this.tag, error: err instanceof RecordError ? err.message : "records" });
      return this.close("record_error");
    }
    this.clock?.received();
    if (!frame) return;
    if (this.state === "unconfirmed") this.confirm();
    if (this.state === "open") this.dispatch(frame);
  }

  /** Message 1: exactly 96 bytes (3.3), read, answer with message 2, split. */
  private onHandshake(msg: Uint8Array): void {
    if (msg.byteLength !== IK_MESSAGE1_BYTES) return this.preauthFail("bad_first_message");
    let reply: Uint8Array;
    try {
      this.hs.readMessage(msg);
      reply = this.hs.writeMessage(EMPTY);
      this.h = b64u(this.hs.handshakeHash());
      const keys = this.hs.split();
      this.crypto = new SessionCrypto(keys.send, keys.receive);
    } catch {
      return this.preauthFail("handshake_failed");
    }
    const dh = b64u(this.hs.remoteStatic()!);
    if (this.endpoint.accessOf(dh).kind !== "active" && this.endpoint.preauthSessions() >= (this.endpoint.o.maxPreauthSessions ?? 8)) {
      return this.preauthFail("preauth_sessions_cap");
    }
    this.deviceDh = dh;
    this.state = "unconfirmed";
    this.relay!.sendBinary(reply);
    // Key confirmation must follow within the handshake timeout (3.5, S-10).
    this.arm("key_confirmation_timeout");
  }

  /** First valid frame from the initiator: the session counts from here on. */
  private confirm(): void {
    if (this.stepTimer) clearTimeout(this.stepTimer);
    this.stepTimer = null;
    this.state = "open";
    const ep = this.endpoint;
    const t = ep.timings;
    this.clock = new SessionClock(t, ep.now, {
      onPing: () => this.send({ t: "ping" }),
      onIdle: () => this.close("idle"),
      onExpire: () => this.close("max_session"),
    });
    this.access = ep.accessOf(this.deviceDh!);
    if (this.access.kind === "active") {
      ep.register(this);
      ep.host.access.record({ event: "session.opened", deviceKid: this.access.sigKid });
      log("room_session_open", { roomId: ep.roomId, conn: this.tag, memberId: this.access.memberId, deviceId: this.access.deviceId });
    }
    // An ended device gets access_ended in reply to this first frame (dispatch), revealed only now,
    // to the holder of that device's DH key (P-23).
  }

  private dispatch(frame: Frame): void {
    const t = frame.t;
    if (t === "ping") return this.send({ t: "pong" });
    if (t === "pong") return;
    // The state may have moved since the session opened (a removal is enforced by afterAppend too).
    if (this.access.kind === "active") this.access = this.endpoint.accessOf(this.deviceDh!);
    const access = this.access;
    if (access.kind === "ended") return this.fail("access_ended", frame.id, { reason: access.reason });
    if (PREAUTH_OPS.has(t)) {
      const enrollment = this.endpoint.enrollment;
      if (enrollment) return enrollment.handle(this, frame);
      // Not served on this endpoint. The generic code reveals nothing about invites or state.
      this.endpoint.host.access.record({ event: "preauth_failed", reason: "enrollment_not_served" });
      return this.fail("enroll_rejected", frame.id);
    }
    if (access.kind === "unknown") {
      this.endpoint.host.access.record({ event: "preauth_failed", reason: "not_authorized" });
      return this.fail("not_authorized", frame.id);
    }
    if (!isRequestId(frame.id)) return this.fail("bad_frame");
    try {
      switch (t) {
        case "session.hello":
          return this.onHello(frame, access);
        case "log.fetch":
          return this.onFetch(frame, access);
        case "log.subscribe":
          return this.onSubscribe(frame);
        case "roster.get":
          return this.send({ t: "roster.get.ok", re: frame.id, roster: this.endpoint.host.roster(), rosterHash: this.endpoint.host.rosterHash() } as unknown as Frame);
        case "stmt.submit":
          return this.onSubmit(frame, access);
        case "grant.issue":
        case "grant.status":
        case "grant.report":
          return this.onGrant(frame, access);
        case "device.link.create":
        case "link.nonce":
        case "link.confirm":
        case "link.abort": {
          const enrollment = this.endpoint.enrollment;
          if (!enrollment || !LINK_OPS.has(t)) return this.fail("not_permitted", frame.id);
          this.endpoint.submitting = this;
          try {
            return enrollment.handleLink(this, frame, { memberId: access.memberId, deviceId: access.deviceId, sigKid: access.sigKid });
          } finally {
            this.endpoint.submitting = null;
          }
        }
        default:
          if (LATER_OPS.has(t)) return this.fail("not_permitted", frame.id);
          return this.fail("bad_frame", frame.id);
      }
    } catch (err) {
      logError("room_session_op_failed", err, { roomId: this.endpoint.roomId, conn: this.tag, op: t.slice(0, 32) });
      return this.fail("internal", frame.id);
    }
  }

  private onHello(frame: Frame, access: Extract<DeviceAccess, { kind: "active" }>): void {
    if (frame.v !== 2) return this.fail("unsupported_version", frame.id, { minVersion: 2 });
    const known = frame.known as { logSeq?: unknown; logHash?: unknown } | undefined;
    if (!known || typeof known !== "object" || Array.isArray(known) || Object.keys(known).length !== 2 || !isInt(known.logSeq, -1) || typeof known.logHash !== "string" || known.logHash.length > 64) {
      return this.fail("bad_frame", frame.id);
    }
    const head = this.endpoint.host.headEntry;
    this.send({
      t: "session.hello.ok",
      re: frame.id,
      serverTime: this.endpoint.now(),
      minVersion: 2,
      memberId: access.memberId,
      deviceId: access.deviceId,
      head: head ? { seq: head.entry.seq, hash: head.hash, hsig: head.hsig } : null,
      lastAck: null,
    });
  }

  private onFetch(frame: Frame, access: Extract<DeviceAccess, { kind: "active" }>): void {
    const { fromSeq, toSeq, limit, bodies } = frame as Record<string, unknown>;
    if (!isInt(fromSeq, 0) || (toSeq !== undefined && !isInt(toSeq, fromSeq)) || !isInt(limit, 1, LOG_FETCH_MAX) || (bodies !== "stmt" && bodies !== "all" && bodies !== "none")) {
      return this.fail("bad_frame", frame.id);
    }
    const host = this.endpoint.host;
    const last = Math.min(toSeq === undefined ? host.head.seq : (toSeq as number), fromSeq + limit - 1);
    const page = this.page(fromSeq, last, bodies);
    if (page.entries.length > 0) host.access.record({ event: "log.fetch", deviceKid: access.sigKid, fromSeq, toSeq: fromSeq + page.entries.length - 1 });
    this.send({ t: "log.fetch.ok", re: frame.id, entries: page.entries, bodies: page.bodies, head: host.headEntry } as unknown as Frame);
  }

  private onSubscribe(frame: Frame): void {
    if (!isInt(frame.fromSeq, 0)) return this.fail("bad_frame", frame.id);
    this.cursor = frame.fromSeq as number;
    this.send({ t: "log.subscribe.ok", re: frame.id, head: this.endpoint.host.headEntry } as unknown as Frame);
    this.pump();
  }

  /** Pushes entries from the subscription cursor to the head as `log.entries` frames. */
  pump(): void {
    if (this.state !== "open" || this.cursor === null) return;
    const host = this.endpoint.host;
    while (this.cursor <= host.head.seq && this.state === "open") {
      const page = this.page(this.cursor, Math.min(host.head.seq, this.cursor + LOG_PUSH_MAX - 1), "stmt");
      if (page.entries.length === 0) break;
      this.cursor += page.entries.length;
      this.send({ t: "log.entries", entries: page.entries, bodies: page.bodies, head: host.headEntry } as unknown as Frame);
    }
  }

  private page(from: number, to: number, mode: "stmt" | "all" | "none"): { entries: SignedEntry[]; bodies: { seq: number; body: string }[] } {
    const entries: SignedEntry[] = [];
    const bodies: { seq: number; body: string }[] = [];
    let bytes = 0;
    for (const r of this.endpoint.host.entries(from, to)) {
      const body = mode === "all" || (mode === "stmt" && r.signed.entry.cls === "stmt") ? b64u(r.body) : null;
      const size = JSON.stringify(r.signed).length + (body?.length ?? 0) + 32;
      if (entries.length > 0 && bytes + size > LOG_REPLY_BUDGET_BYTES) break;
      bytes += size;
      entries.push(r.signed);
      if (body !== null) bodies.push({ seq: r.signed.entry.seq, body });
    }
    return { entries, bodies };
  }

  private onSubmit(frame: Frame, access: Extract<DeviceAccess, { kind: "active" }>): void {
    const stmt = frame.statement as SignedStatement | undefined;
    const producer = (stmt as { body?: { producer?: { kind?: unknown; kid?: unknown } } } | undefined)?.body?.producer;
    // Own statements only; admin and recovery statements only from an admin's device (section 4).
    const own = producer?.kind === "device" && producer.kid === access.sigKid;
    const adminStmt = (producer?.kind === "admin" || producer?.kind === "recovery") && access.role === "admin";
    if (!own && !adminStmt) return this.fail("not_permitted", frame.id);
    this.endpoint.submitting = this;
    let res: SubmitResult;
    try {
      res = this.endpoint.host.submit(stmt);
    } finally {
      this.endpoint.submitting = null;
    }
    if (!res.ok) {
      const head = res.head ? { seq: res.head.entry.seq, hash: res.head.hash } : { seq: -1, hash: this.endpoint.host.genesisHash };
      return this.fail(res.code, frame.id, res.code === "not_permitted" ? {} : { head });
    }
    this.send({ t: "stmt.submit.ok", re: frame.id, receipt: res.receipt } as unknown as Frame);
    this.endpoint.afterAppend();
  }

  /** Grants-v2 3, 6.2 and 6.3. Errors other than `internal` keep the session open. */
  private onGrant(frame: Frame, access: Extract<DeviceAccess, { kind: "active" }>): void {
    const grants = this.endpoint.grants;
    if (!grants) return this.fail("not_permitted", frame.id);
    const laneId = frame.laneId;
    if (!isLaneIdV2(laneId)) return this.fail("bad_frame", frame.id);
    const dev = { memberId: access.memberId, deviceId: access.deviceId };
    if (frame.t === "grant.issue") {
      const r = grants.issue(dev, laneId);
      if (!r.ok) return this.fail(r.code, frame.id);
      return this.send({ t: "grant.issue.ok", re: frame.id, grant: r.token, claims: r.claims, serverTime: r.serverTime } as unknown as Frame);
    }
    if (frame.t === "grant.status") {
      const r = grants.status(access.deviceId, laneId);
      if (!r.ok) return this.fail(r.code, frame.id);
      return this.send(grantStatusFrame(frame.id!, r) as unknown as Frame);
    }
    if (frame.reason !== "unaccounted_link" || !isGrantId(frame.gid)) return this.fail("bad_frame", frame.id);
    const done = grants.suspectedTheft({ deviceId: access.deviceId, laneId, gid: frame.gid, reportedBy: "member" });
    return this.send({ t: "grant.report.ok", re: frame.id, unlisted: done } as unknown as Frame);
  }

  // ---- EnrollSession
  get rs(): string {
    return this.deviceDh ?? "";
  }

  isActive(): boolean {
    return this.access.kind === "active";
  }

  isOpen(): boolean {
    return this.state === "open";
  }

  /** After admission on this session: the device is active from now on (enrollment-v2.md 5.1). */
  promote(): void {
    if (this.state !== "open" || this.access.kind === "active") return;
    const access = this.endpoint.accessOf(this.deviceDh!);
    if (access.kind !== "active") return;
    this.access = access;
    this.endpoint.register(this);
    this.endpoint.host.access.record({ event: "session.opened", deviceKid: access.sigKid });
    log("room_session_open", { roomId: this.endpoint.roomId, conn: this.tag, memberId: access.memberId, deviceId: access.deviceId, enrolled: true });
  }

  send(frame: Frame): void {
    if (this.state !== "open" && this.state !== "unconfirmed") return;
    for (const m of this.crypto!.seal(frame)) this.relay?.sendBinary(m);
  }

  /** Sends `{t:"error", re?, code, ...fields}`; closes the session unless the code is non-closing. */
  fail(code: RoomErrorCode, re?: number, fields: Record<string, unknown> = {}): void {
    if (this.state === "closed") return;
    const frame = { t: "error", code, ...(isRequestId(re) ? { re } : {}), ...fields } as Frame;
    try {
      this.send(frame);
    } catch {}
    if (!NON_CLOSING_ERRORS.has(code) || this.access.kind !== "active") this.close(`error:${code}`);
  }

  close(why: string): void {
    if (this.state === "closed") return;
    const wasOpen = this.state === "open";
    this.state = "closed";
    if (this.stepTimer) clearTimeout(this.stepTimer);
    this.clock?.stop();
    this.cursor = null;
    this.endpoint.unregister(this);
    this.relay?.close(1000, "closed");
    if (wasOpen && this.access.kind === "active") {
      this.endpoint.host.access.record({ event: "session.closed", deviceKid: this.access.sigKid });
      log("room_session_closed", { roomId: this.endpoint.roomId, conn: this.tag, deviceId: this.access.deviceId, why });
    }
  }
}
