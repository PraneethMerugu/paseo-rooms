// Lane endpoint: one relay endpoint per lane, protected (Noise NK) only.
//
// Each relay connection carries one Paseo host link from a member daemon (connected-hosts DESTINATION
// side, as in the routed-lane spike): hello.auth.password must be a valid lane grant; only
// hosts.link.open, hosts.route.frame and hosts.route.close are served; every routed scope is a virtual
// session under the Room Profile with its own upstream session to the local daemon, capped at
// workspace.read.
// Grants come over the room session (grants-v2.md section 3). The M1 control channel was removed at the
// identity v2 cut-over (I-15): any first frame other than `hello` closes the connection.
//
// Grant checks go through a LaneGrantAuthority: server/host/lane-service.ts runs grants-v2 section 4
// against the room's authority state and the `gid` allowlist, and adds the link policy of section 6.1
// (one link per device and lane, theft detection), a failure token bucket (section 11) and 32 routes
// per link. Without `admitLink` (unit tests) a per-member link cap applies.
//
// Grants are checked on the link hello, on every hosts.link.open and on every routed hello.
// Revocation is PUSHED: the grant service calls enforce() synchronously; each link also has a timer
// at its grant's exp. No polling.
import { createHash, randomBytes } from "node:crypto";
import WebSocket from "ws";
import { openDaemonSecureChannel, SecureChannelRejectedError, type SecureChannel } from "@getpaseo/relay/e2ee";
import { clip, log, logError, LogLimiter, short } from "../log";
import { DEFAULT_LIMITS, TokenBucket, type ResourceLimits } from "../limits";
import {
  accessDenied,
  agentMatchesFilter,
  ALLOWED_SESSION_EVENTS,
  assertOwnerUidLaneIsWatchOnly,
  decideInbound,
  filterOutbound,
  FORWARDED_RESPONSES,
  linkServerInfo,
  requestIdOf,
  rewriteServerInfo,
  workspaceMatchesFilter,
  type LaneScope,
} from "../room-profile/filter";
import {
  newSanitizeContext,
  neutralProjectLabel,
  OMIT,
  sanitizeAgentListEntry,
  sanitizeWorkspace,
  type LaneAgentState,
  type ProjectNamePolicy,
  type SanitizeContext,
} from "../room-profile/sanitize";
import { LaneErrorLog } from "./lane-errors";
import { buildUpstreamHello, openDaemonSocket, RawDaemon } from "./local-daemon";
import { checkPaseoCompat, type CompatGuard } from "../compat";
import { MAX_CONNECTION_ID_CHARS, parseRelayNotice, RelayConnection, RelayControlSocket, relayServerUrl, type RelayAddress } from "../transport/relay-server";

/** What a lane endpoint needs to know about its lane (the owner-local binding plus the offer). */
export interface EndpointLane {
  id: string;
  roomId: string;
  label: string;
  /** "fork": a room agent created by Rooms, re-checked by the isolation tripwire before start. */
  origin: { kind: "share" | "fork" };
  agentId: string;
  workspaceId: string;
  /** Relay identity of the lane endpoint (public). */
  serverId: string;
  relay: RelayAddress;
}

const HANDSHAKE_TIMEOUT_MS = 15_000;
const FIRST_FRAME_TIMEOUT_MS = 15_000;
/** Lane start retries: 10 s doubling to 5 min. */
const START_RETRY_MIN_MS = 10_000;
const START_RETRY_MAX_MS = 5 * 60_000;
/** A missing (not archived) lane agent must be seen this many times, this far apart, before the lane closes. */
const AGENT_MISSING_CONFIRMATIONS = 3;
const AGENT_MISSING_MIN_SPAN_MS = 60_000;

export type EndpointStatus = "starting" | "online" | "offline" | "closed";

export type AgentGoneReason = "agent_archived" | "agent_missing";

/** The claim fields the lane endpoint uses (from v2 `GrantClaimsV2`). */
export interface LinkClaims {
  sub: string;
  dev: string;
  gid: string;
  exp: number;
}

export type LaneGrantCheck = { ok: true; claims: LinkClaims } | { ok: false; reason: string; claims?: LinkClaims };

/** How a lane endpoint checks grants and finds its keys (grants-v2; server/host/lane-service.ts). */
export interface LaneGrantAuthority {
  /** Checks a grant presented on the link hello, on hosts.link.open and on every routed hello. */
  check(token: string, laneId: string, opts?: { cheap?: boolean }): LaneGrantCheck;
  keyPair(laneId: string): { publicKey: Uint8Array; secretKey: Uint8Array };
  /**
   * Link policy (grants-v2 6.1), called once the grant passed. Resolves "accept" or "reject"; may
   * close other links. Absent (unit tests): the per-member link cap applies.
   */
  admitLink?(link: LinkSession): Promise<"accept" | "reject">;
  /** v2: failed link attempts per minute on this endpoint (section 11); only failures consume it. */
  failedAttemptsPerMinute?: number;
  /** The clock grants are checked against (unix ms); the expiry timer uses it too. Default Date.now. */
  now?(): number;
}

export interface LaneEndpointDeps {
  /** Grant checks and lane keys. */
  authority: LaneGrantAuthority;
  /** The lane's effective project-name policy (grants-v2 13.2), shared by its routes. Default: hidden. */
  projectNames?: ProjectNamePolicy;
  /** Viewer errors carry an error reference (grants-v2 13.1). */
  errorRefs?: boolean;
  paseoHome: string;
  limits?: ResourceLimits;
  /** Called once when the lane agent is archived or deleted; the lane service closes the lane (C-13). */
  onAgentGone?(laneId: string, reason: AgentGoneReason): void;
  /**
   * Isolation tripwire for fork lanes (C-iso2): verifies the room agent's final stored config.
   * A failure keeps the lane offline and is logged; it is not retried. Not wired in production since
   * the cut-over (v2 creates no fork lanes; LaneService does not pass it). Retained deliberately for a
   * future sandboxed room agent runner; tested in lane-endpoint.test.ts.
   */
  verifyRoomAgent?(lane: EndpointLane): { ok: boolean; problems: string[] };
  /** R2.7: records the daemon's version verdict for status; without it the check still runs. */
  compat?: CompatGuard;
}

/** Shared deny/limit log limiter (C-5): bounded per source key. */
const denyLog = new LogLimiter(20, 20);

export class LaneEndpoint {
  status: EndpointStatus = "starting";
  private control: RelayControlSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private startDelay = START_RETRY_MIN_MS;
  private startFailures = 0;
  private missingSeen: number[] = [];
  /** Why the lane cannot start (isolation tripwire, profile assertion), or null. */
  blockedReason: string | null = null;
  readonly connections = new Map<string, LaneConnection>();
  scope: LaneScope;
  upstreamVersion = "0.0.0";
  readonly directory: LaneDirectory;
  readonly limits: ResourceLimits;
  /** Last snapshot of the lane agent seen by any route (derives the workspace status, C-3). */
  readonly laneAgent: { current: LaneAgentState | null } = { current: null };
  /** Route slots in use per member: the upstream clientId is fixed per (lane, member, slot) (C-2). */
  private readonly routeSlots = new Map<string, Set<number>>();
  /** Project name visibility, shared by every route of this lane (room setting, default hidden). */
  readonly projectNames: ProjectNamePolicy;
  /** Full text of errors viewers got as generic text. Owner-only (rooms.lane.errors); never forwarded. */
  readonly errors: LaneErrorLog;
  readonly authority: LaneGrantAuthority;
  /** Failed link attempts (grants-v2 section 11). Null when the authority sets no rate (unit tests). */
  readonly failures: TokenBucket | null;

  constructor(readonly lane: EndpointLane, readonly deps: LaneEndpointDeps) {
    this.scope = { agentId: lane.agentId, workspaceId: lane.workspaceId };
    this.directory = new LaneDirectory(this);
    this.limits = deps.limits ?? DEFAULT_LIMITS;
    this.errors = new LaneErrorLog(undefined, undefined, undefined, deps.errorRefs === true);
    this.authority = deps.authority;
    const perMinute = this.authority.failedAttemptsPerMinute;
    this.failures = perMinute ? new TokenBucket(perMinute / 60, perMinute) : null;
    this.projectNames = deps.projectNames ?? { show: false, label: neutralProjectLabel(undefined, lane.label) };
  }

  sanitizeContext(): SanitizeContext {
    return newSanitizeContext(
      { laneId: this.lane.id, laneServerId: this.lane.serverId, agentId: this.scope.agentId, workspaceId: this.scope.workspaceId },
      {
        laneAgent: this.laneAgent,
        maxTimelineLimit: this.limits.maxTimelineLimit,
        allowedSessionEvents: ALLOWED_SESSION_EVENTS,
        projectNames: this.projectNames,
        errors: this.errors,
      },
    );
  }

  /** Every routed view of this lane that is open now. */
  get routes(): VirtualSession[] {
    return this.links.flatMap((l) => [...l.channels.values()]);
  }

  /**
   * Room setting changed: the shared policy applies to the next message of every route, and every
   * open route gets fresh agent and workspace upserts so names already shown are replaced now.
   */
  setProjectNamesVisible(show: boolean): number {
    if (this.projectNames.show === show) return 0;
    this.projectNames.show = show;
    const routes = this.routes;
    for (const r of routes) r.pushMetadata();
    log("lane_project_name_policy", { laneId: this.lane.id, show, routes: routes.length });
    return routes.length;
  }

  /** Lowest free route slot for a member, or null when the member is at its route cap. */
  takeRouteSlot(memberId: string): number | null {
    let used = this.routeSlots.get(memberId);
    if (!used) this.routeSlots.set(memberId, (used = new Set()));
    if (used.size >= this.limits.maxRoutesPerMember) return null;
    let slot = 0;
    while (used.has(slot)) slot++;
    used.add(slot);
    return slot;
  }

  releaseRouteSlot(memberId: string, slot: number): void {
    const used = this.routeSlots.get(memberId);
    used?.delete(slot);
    if (used && used.size === 0) this.routeSlots.delete(memberId);
  }

  linksOf(memberId: string): number {
    return this.links.filter((l) => l.claims?.sub === memberId).length;
  }

  /** Accepted links of one device (v2: at most one, grants-v2 6.1). */
  linksOfDevice(dev: string): LinkSession[] {
    return this.links.filter((l) => l.claims?.dev === dev);
  }

  get hostname(): string {
    return `room-lane-${this.lane.id.slice(5, 11)}`;
  }

  /** Links (member daemons) with an accepted host-link hello. */
  get links(): LinkSession[] {
    return [...this.connections.values()].map((c) => c.link).filter((l): l is LinkSession => !!l && l.accepted && !l.closed);
  }

  connectedMemberIds(): Set<string> {
    return new Set(this.links.map((l) => l.claims!.sub));
  }

  activeRoutes(memberId?: string): number {
    return this.links.filter((l) => !memberId || l.claims!.sub === memberId).reduce((n, l) => n + l.channels.size, 0);
  }

  relayUrl(connectionId?: string): string {
    return relayServerUrl(this.lane.relay, this.lane.serverId, connectionId);
  }

  keyPair() {
    return this.authority.keyPair(this.lane.id);
  }

  async start(): Promise<void> {
    if (this.stopped) return;
    try {
      assertOwnerUidLaneIsWatchOnly();
    } catch (e) {
      this.block("room_profile_allows_prompting", (e as Error).message);
      return;
    }
    if (this.lane.origin.kind === "fork" && this.deps.verifyRoomAgent) {
      const check = this.deps.verifyRoomAgent(this.lane);
      if (!check.ok) {
        this.block("room_agent_tripwire", check.problems.join("; "));
        return;
      }
    }
    try {
      const d = new RawDaemon(this.deps.paseoHome);
      await d.connect(`rooms-lane-${this.lane.id}-scope`);
      try {
        this.upstreamVersion = String(d.serverInfo?.version ?? "0.0.0");
        // R2.7 compatibility guard (decisions round 10, item 2): fail closed outside the tested range.
        const verdict = this.deps.compat ? this.deps.compat.observe(d.serverInfo) : checkPaseoCompat(d.serverInfo);
        if (!verdict.ok) {
          this.block(`paseo_${verdict.code}`, verdict.message ?? verdict.code);
          return;
        }
        const res = await d.request({ type: "fetch_agent_request", agentId: this.lane.agentId });
        const agent = res.payload?.agent;
        if (res.type === "fetch_agent_response" && agent === null && !res.payload?.error) {
          if (this.agentMissing()) return;
          throw new Error("lane agent not found on this daemon");
        }
        if (res.type !== "fetch_agent_response" || !agent || agent.id !== this.lane.agentId) throw new Error("lane agent lookup failed");
        if (agent.archivedAt) {
          this.agentGone("agent_archived");
          return;
        }
        this.missingSeen = [];
        this.scope = { agentId: agent.id, workspaceId: agent.workspaceId ?? this.lane.workspaceId };
        log("lane_upstream", { laneId: this.lane.id, version: this.upstreamVersion, grantedPermissions: d.serverInfo?.permissions });
      } finally {
        d.close();
      }
    } catch (e) {
      this.startFailures++;
      logError(this.startFailures === 1 || this.startFailures % 10 === 0 ? "lane_start_failed" : "lane_start_retry", e, {
        laneId: this.lane.id,
        failures: this.startFailures,
        retryMs: this.startDelay,
      });
      this.status = "offline";
      if (!this.stopped) this.reconnectTimer = setTimeout(() => void this.start(), this.startDelay);
      this.startDelay = Math.min(this.startDelay * 2, START_RETRY_MAX_MS);
      return;
    }
    this.startFailures = 0;
    this.startDelay = START_RETRY_MIN_MS;
    this.connectControl();
  }

  /** Records one "agent not found" observation; returns true once the lane was closed for it. */
  private agentMissing(): boolean {
    const now = Date.now();
    this.missingSeen.push(now);
    if (this.missingSeen.length >= AGENT_MISSING_CONFIRMATIONS && now - this.missingSeen[0] >= AGENT_MISSING_MIN_SPAN_MS) {
      this.agentGone("agent_missing");
      return true;
    }
    return false;
  }

  /** The lane agent was archived or deleted: stop retrying and hand the lane to the gateway to close. */
  agentGone(reason: AgentGoneReason): void {
    if (this.stopped) return;
    log("lane_agent_gone", { laneId: this.lane.id, agentId: this.lane.agentId, reason });
    this.status = "offline";
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    if (this.deps.onAgentGone) this.deps.onAgentGone(this.lane.id, reason);
    else void this.stop(reason);
  }

  private block(reason: string, detail: string): void {
    this.blockedReason = reason;
    this.status = "offline";
    log("lane_blocked", { laneId: this.lane.id, reason, detail: detail.slice(0, 400) });
  }

  private connectControl(): void {
    if (this.stopped) return;
    // Control socket, keepalive and reconnects: server/transport/relay-server.ts (same behaviour as M1).
    this.control = new RelayControlSocket({
      url: () => this.relayUrl(),
      maxPayload: this.limits.maxInboundFrameBytes,
      logPrefix: "lane",
      logFields: { laneId: this.lane.id },
      serverId: this.lane.serverId,
      onNotice: (msg) => this.onRelayControl(msg),
      onStatus: (status) => {
        this.status = status;
      },
    });
    this.control.connect();
  }

  /** Relay control-socket notices: new data connections (capped per lane) and disconnects. */
  onRelayControl(msg: any): void {
    const notice = parseRelayNotice(msg);
    if (notice.disconnected !== null) this.connections.get(notice.disconnected)?.close("relay_disconnected");
    for (const id of notice.announced) {
      if (typeof id !== "string" || !id || id.length > MAX_CONNECTION_ID_CHARS || this.connections.has(id) || this.stopped) continue;
      if (this.connections.size >= this.limits.maxConnectionsPerLane) {
        denyLog.log(`lane:${this.lane.id}:conn_cap`, "lane_connection_cap", { laneId: this.lane.id, open: this.connections.size, max: this.limits.maxConnectionsPerLane });
        continue;
      }
      const conn = new LaneConnection(this, id);
      this.connections.set(id, conn);
      conn.start();
    }
  }

  /** Re-checks every live link against the host's current state. Called synchronously on changes. */
  enforce(reason: string): { cutLinks: number; cutRoutes: number } {
    let cutLinks = 0;
    let cutRoutes = 0;
    for (const link of this.links) {
      const routes = link.channels.size;
      if (!link.recheck(reason)) {
        cutLinks++;
        cutRoutes += routes;
      }
    }
    return { cutLinks, cutRoutes };
  }

  async stop(why = "stopped"): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    this.status = "closed";
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    for (const c of this.connections.values()) {
      c.link?.cut(why);
      c.close(why);
    }
    this.directory.close();
    this.routeSlots.clear();
    this.control?.stop(1001, "lane endpoint stopped");
    log("lane_endpoint_stopped", { laneId: this.lane.id, why });
  }
}

// -------------------------------------------------------------------------------------------------
/**
 * One relay data socket (server/transport/relay-server.ts RelayConnection) after the Noise NK
 * handshake. Becomes a host link.
 */
export class LaneConnection {
  private relay: RelayConnection | null = null;
  channel: SecureChannel | null = null;
  link: LinkSession | null = null;
  private mode: "pending" | "link" = "pending";
  private closed = false;
  private firstFrameTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(readonly endpoint: LaneEndpoint, readonly connectionId: string) {}

  get tag(): string | null {
    return short(this.connectionId);
  }

  start(): void {
    const rc = new RelayConnection(this.endpoint.relayUrl(this.connectionId), this.endpoint.limits.maxInboundFrameBytes);
    this.relay = rc;
    const transport = rc.transport();
    rc.open({
      onMessage: (payload, isBinary) => transport.onmessage?.({ data: payload, isBinary }),
      onClose: (code, reason) => {
        transport.onclose?.(code, reason);
        this.close("data_socket_closed");
      },
      onError: (err) => transport.onerror?.(err),
      onOpen: async () => {
        const timer = setTimeout(() => rc.terminate(), HANDSHAKE_TIMEOUT_MS);
        try {
          this.channel = await openDaemonSecureChannel(transport, {
            daemonKeyPair: this.endpoint.keyPair(),
            minimumMode: "protected",
            events: {
              onmessage: (data) => this.onMessage(data),
              onclose: () => this.close("channel_closed"),
              onerror: (err) => log("lane_channel_error", { conn: this.tag, error: clip(err.message, 200) }),
            },
          });
          clearTimeout(timer);
          this.firstFrameTimer = setTimeout(() => this.mode === "pending" && this.close("first_frame_timeout"), FIRST_FRAME_TIMEOUT_MS);
        } catch (err) {
          clearTimeout(timer);
          if (err instanceof SecureChannelRejectedError) {
            log("lane_e2ee_rejected", { conn: this.tag, reason: clip(err.message, 200) });
            rc.close(err.closeCode, err.closeReason);
          } else {
            log("lane_e2ee_failed", { conn: this.tag, error: clip((err as Error).message, 200) });
            rc.close(1011, "E2EE handshake failed");
          }
        }
      },
    });
  }

  send(obj: unknown): void {
    if (!this.channel || this.closed) return;
    void this.channel.send(JSON.stringify(obj)).catch(() => undefined);
  }

  private onMessage(data: string | ArrayBuffer): void {
    if (typeof data !== "string") {
      // Binary route frames carry terminal and file streams; not in the watch profile.
      if (this.mode === "link") denyLog.log(`conn:${this.connectionId}`, "link_binary_dropped", { conn: this.tag, bytes: data.byteLength });
      return;
    }
    if (data.length > this.endpoint.limits.maxInboundFrameBytes) {
      denyLog.log(`conn:${this.connectionId}`, "frame_too_large", { conn: this.tag, chars: data.length });
      this.close("frame_too_large");
      return;
    }
    let msg: any;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (this.mode === "pending") {
      if (this.firstFrameTimer) clearTimeout(this.firstFrameTimer);
      if (msg?.type === "hello") {
        this.mode = "link";
        this.link = new LinkSession(this);
        void this.link.onHello(msg);
        return;
      }
      this.close("unexpected_first_frame");
      return;
    }
    if (this.link && !this.link.rate.take()) {
      denyLog.log(`conn:${this.connectionId}`, "link_rate_limited", { conn: this.tag, sub: this.link.claims?.sub ?? null });
      return;
    }
    this.link?.noteRx();
    if (msg?.type === "ping") return this.send({ type: "pong" });
    this.link?.onFrame(msg);
  }

  close(why: string): void {
    if (this.closed) return;
    this.closed = true;
    if (this.firstFrameTimer) clearTimeout(this.firstFrameTimer);
    this.link?.close(why);
    try {
      this.channel?.close(1000, "closed");
    } catch {}
    this.relay?.close();
    this.endpoint.connections.delete(this.connectionId);
    denyLog.forget(`conn:${this.connectionId}`);
  }
}

// -------------------------------------------------------------------------------------------------
/** Physical connected-hosts link from one member daemon. */
export class LinkSession {
  accepted = false;
  closed = false;
  private grant: string | null = null; // bearer secret, memory only
  claims: LinkClaims | null = null;
  /** When the hello was accepted (grants-v2 6.2 `since`), unix ms. */
  acceptedAt = 0;
  /** Last inbound frame on this link (liveness for grants-v2 6.1), unix ms. */
  lastRxAt = 0;
  readonly channels = new Map<string, VirtualSession>();
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly openedAt = Date.now();
  readonly rate: TokenBucket;

  constructor(readonly conn: LaneConnection) {
    this.rate = new TokenBucket(conn.endpoint.limits.linkFramesPerSecond, conn.endpoint.limits.linkFrameBurst);
  }

  get endpoint(): LaneEndpoint {
    return this.conn.endpoint;
  }

  sendSession(message: unknown): void {
    this.conn.send({ type: "session", message });
  }

  noteRx(): void {
    this.lastRxAt = Date.now();
  }

  async onHello(hello: any): Promise<void> {
    const auth = hello?.auth;
    let reason: "password_required" | "incorrect_password" | null = null;
    let detail: string | null = null;
    if (!auth) reason = "password_required";
    else if (auth.kind !== "password" || typeof auth.password !== "string") reason = "incorrect_password";
    else {
      const ep = this.endpoint;
      // v2 (section 11): an empty failure bucket leaves only the cheap path (current gid first).
      const cheap = ep.failures ? !ep.failures.peek() : false;
      const check = ep.authority.check(auth.password, ep.lane.id, { cheap });
      this.claims = check.claims ?? null;
      if (!check.ok) {
        reason = "incorrect_password";
        detail = check.reason;
        ep.failures?.take();
      } else this.grant = auth.password;
    }
    if (!reason && this.endpoint.authority.admitLink) {
      const verdict = await this.endpoint.authority.admitLink(this);
      if (verdict !== "accept" || this.closed) {
        this.grant = null;
        if (!this.closed) setTimeout(() => this.conn.close("link_policy"), 100);
        return;
      }
    } else if (!reason && this.endpoint.linksOf(this.claims!.sub) >= this.endpoint.limits.maxLinksPerMember) {
      // Not an auth failure: closing without hello.rejected keeps the member daemon from rotating.
      denyLog.log(`lane:${this.endpoint.lane.id}:links:${this.claims!.sub}`, "link_cap_reached", {
        conn: this.conn.tag,
        laneId: this.endpoint.lane.id,
        sub: this.claims!.sub,
        max: this.endpoint.limits.maxLinksPerMember,
      });
      this.grant = null;
      setTimeout(() => this.conn.close("link_cap"), 100);
      return;
    }
    if (reason) {
      denyLog.log(`lane:${this.endpoint.lane.id}:hello_rejected`, "link_hello_rejected", {
        conn: this.conn.tag,
        laneId: this.endpoint.lane.id,
        reason,
        detail,
        sub: this.claims?.sub ?? null,
        gid: this.claims?.gid ?? null,
      });
      if (auth || hello?.capabilities?.hello_rejection === true) this.conn.send({ type: "hello.rejected", reason, accepts: ["password"] });
      setTimeout(() => this.conn.channel?.close(4401, reason === "password_required" ? "Password required" : "Incorrect password"), 100);
      return;
    }
    this.accepted = true;
    this.acceptedAt = Date.now();
    this.armExpiry();
    log("link_hello_accepted", {
      conn: this.conn.tag,
      laneId: this.endpoint.lane.id,
      sub: this.claims!.sub,
      gid: this.claims!.gid,
      exp: new Date(this.claims!.exp * 1000).toISOString(),
      clientType: clip(hello.clientType, 16),
      appVersion: clip(hello.appVersion, 32),
    });
    this.sendSession({ type: "status", payload: linkServerInfo(this.endpoint.lane.serverId, this.endpoint.hostname, this.endpoint.upstreamVersion) });
  }

  private armExpiry(): void {
    if (!this.claims) return;
    const ms = Math.max(0, this.claims.exp * 1000 - (this.endpoint.authority.now?.() ?? Date.now())) + 50;
    this.expiryTimer = setTimeout(() => this.recheck("expiry_timer"), Math.min(ms, 2 ** 31 - 1));
  }

  onFrame(frame: any): void {
    if (!this.accepted) return;
    if (frame?.type !== "session" || !frame.message || typeof frame.message.type !== "string") return;
    const m = frame.message;
    switch (m.type) {
      case "hosts.link.open.request": {
        if (!this.recheck("link_open")) {
          this.sendSession({ type: "rpc_error", payload: { requestId: m.requestId, requestType: m.type, code: "permission_denied", error: "Lane grant is no longer valid" } });
          return;
        }
        const sub = this.claims!.sub;
        const ep = this.endpoint;
        const room = this.channels.size < ep.limits.maxRoutesPerLink && ep.routes.length < ep.limits.maxRoutesPerLane;
        const slot = room ? ep.takeRouteSlot(sub) : null;
        if (slot === null) {
          denyLog.log(`lane:${this.endpoint.lane.id}:routes:${sub}`, "route_cap_reached", { conn: this.conn.tag, sub, channels: this.channels.size });
          this.sendSession({ type: "rpc_error", payload: { requestId: m.requestId, requestType: m.type, code: "resource_limit", error: "Too many host channels" } });
          return;
        }
        const routeId = `lnk_${randomBytes(9).toString("base64url")}`;
        const vs = new VirtualSession(this, routeId, clip(m.channelId, 128) ?? "", slot);
        this.channels.set(routeId, vs);
        log("link_open", { conn: this.conn.tag, routeId, channels: this.channels.size });
        this.sendSession({ type: "hosts.link.open.response", payload: { requestId: m.requestId, routeId } });
        return;
      }
      case "hosts.route.frame.request": {
        const vs = typeof m.routeId === "string" ? this.channels.get(m.routeId) : undefined;
        if (!vs) return;
        if (typeof m.data === "string" && m.data.length > this.endpoint.limits.maxRouteMessageChars) {
          denyLog.log(`route:${m.routeId}`, "route_message_too_large", { routeId: m.routeId, chars: m.data.length });
          vs.close("resource_limit", "Message too large");
          return;
        }
        vs.feed(m.data);
        return;
      }
      case "hosts.route.close.request": {
        for (const [id, vs] of this.channels)
          if (m.routeId === id || (m.scopeId && m.scopeId === vs.channelId)) vs.close("host_offline", "Closed by member daemon");
        return;
      }
      default: {
        const rid = requestIdOf(m);
        denyLog.log(`conn:${this.conn.connectionId}`, "link_deny", { conn: this.conn.tag, type: clip(m.type) });
        if (rid && rid.length <= 256) this.sendSession(accessDenied(rid, clip(m.type, 96) ?? "unknown"));
      }
    }
  }

  /** Re-verifies the grant against the host's current state; cuts the link on failure. */
  recheck(trigger: string): boolean {
    if (this.closed) return false;
    if (!this.grant) return false;
    const check = this.endpoint.authority.check(this.grant, this.endpoint.lane.id);
    if (!check.ok) {
      this.cut(`${check.reason} (${trigger})`);
      return false;
    }
    return true;
  }

  cut(reason: string): void {
    if (this.closed) return;
    log("link_cut", { conn: this.conn.tag, laneId: this.endpoint.lane.id, reason, sub: this.claims?.sub ?? null, gid: this.claims?.gid ?? null, liveRoutes: this.channels.size });
    for (const vs of this.channels.values()) vs.close("permission_denied", "Lane access was revoked or expired");
    this.close(`cut:${reason}`);
    this.conn.close(`cut:${reason}`);
  }

  close(why: string): void {
    if (this.closed) return;
    this.closed = true;
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    for (const vs of this.channels.values()) vs.close("host_offline", "Lane link closed");
    this.grant = null;
    if (this.accepted) log("link_closed", { conn: this.conn.tag, why, sub: this.claims?.sub ?? null, ageMs: Date.now() - this.openedAt });
  }
}

// -------------------------------------------------------------------------------------------------
/** One routed scope: Room Profile session with its own capped upstream to the local daemon. */
export class VirtualSession {
  private helloDone = false;
  private upstream: WebSocket | null = null;
  private upstreamReady = false;
  private pendingToUpstream: string[] = [];
  /** requestId -> inbound type, for forwarded requests awaiting a response (bounded, C-4). */
  private forwarded = new Map<string, string>();
  private listRequests = new Map<string, any>();
  private outQueue: Promise<void> = Promise.resolve();
  private outQueued = 0;
  private closed = false;
  private readonly ctx: SanitizeContext;
  readonly stats = { forwarded: 0, denied: 0, outPassed: 0, outDropped: 0, built: 0 };

  constructor(private readonly link: LinkSession, readonly routeId: string, readonly channelId: string, readonly slot: number) {
    this.ctx = link.endpoint.sanitizeContext();
  }

  private get limits(): ResourceLimits {
    return this.link.endpoint.limits;
  }

  private track(map: Map<string, unknown>, key: string, value: any): void {
    map.delete(key);
    map.set(key, value);
    while (map.size > this.limits.maxTrackedRequestsPerRoute) map.delete(map.keys().next().value as string);
  }

  private sendViewer(envelope: unknown): void {
    if (this.closed) return;
    this.link.sendSession({ type: "hosts.route.frame", payload: { subscriptionId: this.routeId, data: JSON.stringify(envelope), binary: false } });
  }

  feed(data: unknown): void {
    if (this.closed || typeof data !== "string") return;
    let msg: any;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (!this.helloDone) {
      if (msg?.type !== "hello") return this.close("permission_denied", "Expected hello");
      this.onHello(msg);
      return;
    }
    if (msg?.type === "ping") return this.sendViewer({ type: "pong" });
    if (msg?.type !== "session" || !msg.message || typeof msg.message.type !== "string") return;
    this.onSessionMessage(msg.message);
  }

  private onHello(hello: any): void {
    this.helloDone = true;
    if (!this.link.recheck("routed_hello")) {
      this.sendViewer({ type: "hello.rejected", reason: "incorrect_password", accepts: ["password"] });
      this.close("authentication_failed", "Lane grant is no longer valid");
      return;
    }
    const ep = this.link.endpoint;
    const sub = this.link.claims!.sub;
    // Gateway-chosen and fixed per (lane, member, route slot); never derived from the viewer's hello (C-2).
    const clientId = `rooms-lane-${ep.lane.id}-watch-${createHash("sha256").update(JSON.stringify([ep.lane.id, sub, this.slot])).digest("hex").slice(0, 24)}`;
    log("route_hello", { routeId: this.routeId, sub, slot: this.slot, clientType: clip(hello.clientType, 16), routed: hello.routed === true });
    const up = openDaemonSocket(ep.deps.paseoHome, this.limits.maxUpstreamFrameBytes);
    this.upstream = up;
    up.on("open", () => up.send(JSON.stringify(buildUpstreamHello(ep.deps.paseoHome, hello, clientId))));
    up.on("message", (raw, isBinary) => {
      if (isBinary) {
        this.stats.outDropped++;
        return;
      }
      let msg: any;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (msg.type === "hello.rejected") {
        log("upstream_hello_rejected", { routeId: this.routeId, reason: msg.reason });
        this.close("host_offline", "Lane upstream unavailable");
        return;
      }
      if (msg.type !== "session" || !msg.message) return;
      const m = msg.message;
      if (this.outQueued >= this.limits.maxQueuedOutboundPerRoute) {
        log("route_out_queue_full", { routeId: this.routeId, queued: this.outQueued });
        this.close("resource_limit", "Viewer is too slow");
        return;
      }
      this.outQueued++;
      this.outQueue = this.outQueue
        .then(() => this.onUpstreamSession(m))
        .catch((e) => logError("route_out_error", e, { routeId: this.routeId }))
        .finally(() => {
          this.outQueued--;
        });
    });
    up.on("close", () => this.close("host_offline", "Lane upstream closed"));
    up.on("error", (err) => log("upstream_error", { routeId: this.routeId, error: err.message }));
  }

  private async onUpstreamSession(m: any): Promise<void> {
    if (this.closed) return;
    const ep = this.link.endpoint;
    if (m.type === "status") {
      if (m.payload?.status !== "server_info") return;
      this.sendViewer({ type: "session", message: { type: "status", payload: rewriteServerInfo(m.payload, ep.lane.serverId, ep.hostname) } });
      if (!this.upstreamReady) {
        this.upstreamReady = true;
        log("route_upstream_ready", { routeId: this.routeId, upstreamPermissions: m.payload.permissions });
        for (const s of this.pendingToUpstream) this.upstream?.send(s);
        this.pendingToUpstream = [];
      }
      return;
    }
    const rid = typeof m.payload?.requestId === "string" ? m.payload.requestId : null;
    let out = filterOutbound(m, ep.scope, this.forwarded, this.ctx);
    if (rid && this.forwarded.has(rid) && (m.type === "rpc_error" || (FORWARDED_RESPONSES[this.forwarded.get(rid)!] ?? []).includes(m.type))) this.forwarded.delete(rid);
    if (out && (m.type === "fetch_agents_response" || m.type === "fetch_workspaces_response")) {
      const req = this.listRequests.get(m.payload.requestId);
      this.listRequests.delete(m.payload.requestId);
      let built: any[] = [];
      if (m.type === "fetch_agents_response") {
        const e = await ep.directory.agentEntry();
        if (e) {
          const upstreamEntry = (m.payload.entries ?? []).find((x: any) => x?.agent?.id === ep.scope.agentId);
          const entry = sanitizeAgentListEntry({ agent: e.agent, project: e.project ?? upstreamEntry?.project ?? null, ...(upstreamEntry?.syncSeq ? { syncSeq: upstreamEntry.syncSeq } : {}) }, this.ctx);
          if (entry !== OMIT && agentMatchesFilter(entry as any, req)) built = [entry];
        }
      } else {
        await ep.directory.agentEntry().then((e) => e && sanitizeAgentListEntry({ agent: e.agent }, this.ctx)).catch(() => null);
        const w = await ep.directory.workspace();
        if (w) {
          const upstreamEntry = (m.payload.entries ?? []).find((x: any) => x?.id === ep.scope.workspaceId);
          const entry = sanitizeWorkspace({ ...w, ...(upstreamEntry?.syncSeq ? { syncSeq: upstreamEntry.syncSeq } : {}) }, this.ctx);
          if (entry !== OMIT && entry && workspaceMatchesFilter(entry, req)) built = [entry];
        }
      }
      out = { ...out, payload: { ...out.payload, entries: built } };
      this.stats.built++;
    }
    if (!out) {
      this.stats.outDropped++;
      return;
    }
    this.stats.outPassed++;
    this.sendViewer({ type: "session", message: out });
  }

  /**
   * Re-sends the lane agent and workspace as upserts built through the sanitiser (policy change).
   * Queued behind upstream traffic so ordering is kept. Best effort: failures are logged.
   */
  pushMetadata(): void {
    if (this.closed || !this.upstreamReady) return;
    const ep = this.link.endpoint;
    this.outQueue = this.outQueue
      .then(async () => {
        if (this.closed) return;
        const e = await ep.directory.agentEntry();
        if (e) {
          const out = filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: e.agent, project: e.project } }, ep.scope, this.forwarded, this.ctx);
          if (out) this.sendViewer({ type: "session", message: out });
        }
        const w = await ep.directory.workspace();
        if (w) {
          const out = filterOutbound({ type: "workspace_update", payload: { kind: "upsert", workspace: w } }, ep.scope, this.forwarded, this.ctx);
          if (out) this.sendViewer({ type: "session", message: out });
        }
      })
      .catch((err) => logError("route_metadata_push_failed", err, { routeId: this.routeId }));
  }

  private onSessionMessage(m: any): void {
    const d = decideInbound(m, this.link.endpoint.scope, this.ctx);
    if (d.action === "deny") {
      this.stats.denied++;
      denyLog.log(`route:${this.routeId}`, "route_deny", { routeId: this.routeId, type: clip(m.type), reason: d.reason });
      if (d.requestId) this.sendViewer({ type: "session", message: accessDenied(d.requestId, clip(m.type, 96) ?? "unknown") });
      return;
    }
    const rid = requestIdOf(d.message);
    if (rid && FORWARDED_RESPONSES[m.type]) this.track(this.forwarded, rid, m.type);
    if (rid && d.listKind) this.track(this.listRequests, rid, d.message);
    this.stats.forwarded++;
    const frame = JSON.stringify({ type: "session", message: d.message });
    if (this.upstreamReady && this.upstream?.readyState === WebSocket.OPEN) this.upstream.send(frame);
    else if (this.pendingToUpstream.length >= this.limits.maxPendingUpstreamFrames) {
      log("route_pending_overflow", { routeId: this.routeId, pending: this.pendingToUpstream.length });
      this.close("resource_limit", "Too many requests before the lane was ready");
    } else this.pendingToUpstream.push(frame);
  }

  close(code: string, message: string): void {
    if (this.closed) return;
    this.closed = true;
    this.link.sendSession({ type: "hosts.route.closed", payload: { subscriptionId: this.routeId, code, message } });
    this.link.channels.delete(this.routeId);
    if (this.link.claims) this.link.endpoint.releaseRouteSlot(this.link.claims.sub, this.slot);
    this.pendingToUpstream = [];
    this.forwarded.clear();
    this.listRequests.clear();
    denyLog.forget(`route:${this.routeId}`);
    log("route_closed", { routeId: this.routeId, code, stats: this.stats });
    try {
      this.upstream?.close(1000, "route closed");
    } catch {}
  }
}

// -------------------------------------------------------------------------------------------------
/** Gateway-built directory: the lane's own view of its scope, never a filtered daemon page. */
class LaneDirectory {
  private helper: RawDaemon | null = null;
  constructor(private readonly ep: LaneEndpoint) {}

  private async daemon(): Promise<RawDaemon> {
    if (this.helper && !this.helper.closed) return this.helper;
    const d = new RawDaemon(this.ep.deps.paseoHome);
    await d.connect(`rooms-lane-${this.ep.lane.id}-directory`);
    this.helper = d;
    return d;
  }

  async agentEntry(): Promise<{ agent: any; project: any } | null> {
    const d = await this.daemon();
    const res = await d.request({ type: "fetch_agent_request", agentId: this.ep.scope.agentId });
    const agent = res.payload?.agent;
    if (res.type !== "fetch_agent_response" || !agent || agent.id !== this.ep.scope.agentId) return null;
    return { agent, project: res.payload.project ?? null };
  }

  /** Protocol 0.13.2 has no single-workspace fetch, so this walks the pages internally. */
  async workspace(): Promise<any | null> {
    const d = await this.daemon();
    let cursor: string | undefined;
    for (let page = 0; page < 50; page++) {
      const res = await d.request({ type: "fetch_workspaces_request", page: { limit: 200, ...(cursor ? { cursor } : {}) } });
      const hit = (res.payload?.entries ?? []).find((w: any) => w?.id === this.ep.scope.workspaceId);
      if (hit) return hit;
      if (!res.payload?.pageInfo?.hasMore || !res.payload.pageInfo.nextCursor) return null;
      cursor = res.payload.pageInfo.nextCursor;
    }
    return null;
  }

  close(): void {
    this.helper?.close();
    this.helper = null;
  }
}
