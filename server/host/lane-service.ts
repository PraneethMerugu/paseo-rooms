// Lane endpoints of one owned room in the v2 runtime (implementation plan I-10; grants-v2.md sections
// 4, 6, 7, 11 and 13; room-log-v2.md 4.4).
//
// - A lane is created by the owner's daemon: a fresh lane endpoint key (X25519) and serverId are added
//   to `host/<roomId>/keys.sealed`, the owner-local binding (agent, workspace, label) is written to
//   `host/<roomId>/lanes.sealed` (agent ids never enter the room log), then the admin statement
//   `lane.created {laneId, owner, offer, visibility}` is submitted. The owner is the room creator's
//   member: this daemon's gateway serves the lane (embedded host, so lane endpoints share the host's
//   process and a revocation push cannot miss them, 7.2 S-23).
// - Each open lane with a binding and a key runs an M1 LaneEndpoint (Room Profile filter and
//   sanitizer kept) under a grants-v2 authority: section 4 checks against the folded state and the
//   allowlist (server/host/grants.ts), a failure bucket of 30 per minute, 32 routes per link and 256
//   per lane, no control channel, and the link policy of 6.1 below.
// - Link policy (6.1, with the pre-check result of grants Q2): Paseo 0.13.2's connected-host link has
//   no ping the destination side can send and the source answers (its DaemonClient only answers its
//   own pings with our pongs). The source does send its own liveness ping every 10 s. So when a second
//   link of the same (device, lane) passes steps 1 to 6, the endpoint watches the existing link for
//   up to `livenessWaitMs` (12 s, longer than the source's 10 s heartbeat; the spec's 5 s assumed a
//   destination ping): any inbound frame in that window means two live holders, so both links close
//   and the host records `grant.suspected-theft`; silence means the old link is dead and is replaced.
// - Offer rotation (keys-rotation-recovery.md 4.7; I-12): `rotateOffer` stages a new lane key and
//   serverId in `lanesNext`, submits `lane.offer.rotated`, then promotes the key; `sync` stops the old
//   lane endpoint at once and starts one for the new offer (every holder of the old offer is evicted).
//   `lanesToRotate` lists the lanes a removal flagged as compromise (or every removal under policy
//   `rotateLaneOnRemove = "always"`) must rotate.
// - Project names (13.2): shown only when `policy.projectNames == "lane-owner"` and the lane's
//   `showNames`; otherwise the neutral label. Viewer errors carry an error reference (13.1).
import { randomBytes } from "node:crypto";
import nodePath from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { z } from "zod";
import type { RoomState } from "../authority/fold";
import { firstIssue, LaneId, RoomId } from "../authority/schema";
import { edKid, versionKey } from "../authority/state";
import { LaneEndpoint, type AgentGoneReason, type EndpointLane, type LaneGrantAuthority, type LinkSession } from "../gateway/lane-endpoint";
import type { Kek } from "../keystore/keystore";
import { DEFAULT_LIMITS, resolveLimits, type ResourceLimits } from "../limits";
import { log } from "../log";
import { b64u, b64uDecode } from "../proto/b64u";
import { newId, newServerId } from "../proto/ids";
import { kid as kidOf } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { neutralProjectLabel, type ProjectNamePolicy } from "../room-profile/sanitize";
import type { RelayAddress } from "../transport/relay-server";
import type { HostGrants, LinkInfo } from "./grants";
import { readHostKeys, writeHostKeys, type RoomHost } from "./room-host";
import { hostRoomDir } from "./room-log-store";

export const LANES_FILE = "lanes.sealed";
export const lanesPurpose = (roomId: string) => `host-lanes:${roomId}`;
export const lanesPath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), LANES_FILE);
/** Grants-v2 section 11. */
export const FAILED_LINKS_PER_MINUTE = 30;
export const LIVENESS_WAIT_MS = 12_000;
/** Grants-v2 section 11 limits on top of the M1 defaults. */
export const V2_LANE_LIMITS: ResourceLimits = resolveLimits({ ...DEFAULT_LIMITS, maxRoutesPerLink: 32, maxRoutesPerLane: 256, maxRoutesPerMember: 256 });

const Binding = z.strictObject({ laneId: LaneId, agentId: z.string().min(1).max(200), workspaceId: z.string().min(1).max(200), label: z.string().min(1).max(80) });
export type LaneBinding = z.infer<typeof Binding>;
const LanesFile = z.strictObject({ v: z.literal(2), typ: z.literal("host-lanes"), roomId: RoomId, lanes: z.array(Binding).max(4096) });

export interface LaneServiceOptions {
  dataDir: string;
  kek: Kek;
  host: RoomHost;
  grants: HostGrants;
  /** Where the lane endpoints reach the relay (the room's relay, owner side). */
  relay: RelayAddress;
  paseoHome: string;
  limits?: ResourceLimits;
  livenessWaitMs?: number;
  /** Test only: build endpoints without starting them (no daemon, no relay). */
  autostart?: boolean;
  /**
   * C-13: the lane's agent was archived or deleted. The endpoint has already stopped serving; the
   * runtime closes the lane in the room log (`lane.closed`, signed by this daemon's admin key).
   */
  onAgentGone?(laneId: string, reason: AgentGoneReason): void;
}

export class LaneService {
  readonly endpoints = new Map<string, LaneEndpoint>();
  /** The offer serverId each running endpoint serves. */
  private readonly served = new Map<string, string>();
  private bindings: LaneBinding[];
  private stopped = false;
  /** Lanes whose agent is gone: no endpoint is started again in this process (C-13). */
  private readonly gone = new Set<string>();

  constructor(private readonly o: LaneServiceOptions) {
    this.bindings = this.readBindings();
    o.grants.enforce = (laneId, reason) => this.enforce(laneId, reason);
    o.grants.links = (deviceId, laneId) => this.linkInfo(deviceId, laneId);
  }

  get roomId(): string {
    return this.o.host.roomId;
  }

  /** Starts endpoints for open lanes (at runtime start, and after every append). */
  start(): void {
    this.sync();
  }

  /**
   * Creates a lane for an agent of this daemon. `submit` signs and submits `lane.created` as an admin
   * (confirmed by the caller). Returns the new lane.
   */
  createLane(i: { agentId: string; workspaceId: string; label: string; owner: string; submit: (data: unknown) => void }): { laneId: string; serverId: string } {
    const laneId = newId("lane");
    const serverId = newServerId("laneEndpoint");
    const secret = new Uint8Array(randomBytes(32));
    const pub = x25519.getPublicKey(secret);
    const keyKid = kidOf("x25519", pub);
    const keys = readHostKeys(this.o.dataDir, this.o.kek, this.roomId);
    if (!keys) throw new Error("host keys missing");
    keys.lanes[laneId] = { kid: keyKid, secret: b64u(secret) };
    secret.fill(0);
    // Key first, then binding, then the statement: a crash leaves an unused key or binding, never a
    // lane in the log that this daemon cannot serve.
    writeHostKeys(this.o.dataDir, this.o.kek, keys);
    const binding = Binding.parse({ laneId, agentId: i.agentId, workspaceId: i.workspaceId, label: i.label });
    this.writeBindings([...this.bindings, binding]);
    const relay = this.o.host.state.auth.endpoint.relay;
    i.submit({ laneId, owner: i.owner, offer: { serverId, dh: { alg: "x25519", kid: keyKid, pub: b64u(pub) }, relay: { host: relay.host, port: relay.port, tls: true } }, visibility: "room" });
    log("v2_lane_created", { roomId: this.roomId, laneId });
    this.sync();
    return { laneId, serverId };
  }

  /**
   * Keys 4.7: a new lane offer (serverId and X25519 key), staged in `lanesNext` before the admin's
   * `lane.offer.rotated` is submitted, promoted after it. `submit` signs and submits the statement.
   */
  rotateOffer(laneId: string, submit: (data: unknown) => void): { serverId: string } {
    const s = this.o.host.state;
    const l = s.auth.lanes[laneId];
    if (!l || l.status === "closed") throw new Error("Unknown or closed lane");
    const keys = readHostKeys(this.o.dataDir, this.o.kek, this.roomId);
    if (!keys?.lanes[laneId]) throw new Error("This daemon does not serve that lane");
    let next = keys.lanesNext?.[laneId];
    if (!next) {
      const secret = new Uint8Array(randomBytes(32));
      next = { kid: kidOf("x25519", x25519.getPublicKey(secret)), secret: b64u(secret), serverId: newServerId("laneEndpoint") };
      secret.fill(0);
      writeHostKeys(this.o.dataDir, this.o.kek, { ...keys, lanesNext: { ...(keys.lanesNext ?? {}), [laneId]: next } });
    }
    const pub = x25519.getPublicKey(b64uDecode(next.secret, 32));
    const relay = this.o.host.state.auth.endpoint.relay;
    const ver = s.auth.versions[versionKey.laneOffer(laneId)] ?? -1;
    submit({ laneId, offer: { serverId: next.serverId, dh: { alg: "x25519", kid: next.kid, pub: b64u(pub) }, relay: { host: relay.host, port: relay.port, tls: true } }, ver });
    log("v2_lane_offer_rotated", { roomId: this.roomId, laneId });
    this.sync();
    return { serverId: next.serverId };
  }

  /**
   * Lanes to rotate after a removal (keys 4.7, `rotateLaneOnRemove`): those the removed member had
   * access to, when the removal is flagged as a compromise or the policy says "always". Only lanes
   * this daemon serves.
   */
  lanesToRotate(prev: Readonly<RoomState>, memberId: string, compromise: boolean): string[] {
    if (!compromise && prev.auth.policy.rotateLaneOnRemove !== "always") return [];
    const served = new Set(this.bindings.map((b) => b.laneId));
    return (prev.members[memberId]?.lanes ?? []).filter((id) => served.has(id) && prev.auth.lanes[id]?.status === "open");
  }

  /** A staged lane key whose offer is now in the log becomes the lane's key (also after a crash). */
  private promoteOffers(): void {
    const keys = readHostKeys(this.o.dataDir, this.o.kek, this.roomId);
    if (!keys?.lanesNext || Object.keys(keys.lanesNext).length === 0) return;
    const s = this.o.host.state;
    const lanes = { ...keys.lanes };
    const next = { ...keys.lanesNext };
    let changed = false;
    for (const [laneId, n] of Object.entries(keys.lanesNext)) {
      const offer = s.auth.lanes[laneId]?.offer;
      if (offer && offer.serverId === n.serverId && offer.dh.kid === n.kid) {
        lanes[laneId] = { kid: n.kid, secret: n.secret };
        delete next[laneId];
        changed = true;
      }
    }
    if (changed) writeHostKeys(this.o.dataDir, this.o.kek, { ...keys, lanes, lanesNext: next });
  }

  /** Called after every append: lanes opened, closed, names policy changed. */
  sync(): void {
    if (this.stopped) return;
    const s = this.o.host.state;
    this.promoteOffers();
    for (const [laneId, ep] of [...this.endpoints]) {
      const l = s.auth.lanes[laneId];
      if (!l || l.status === "closed" || s.auth.closed || this.served.get(laneId) !== l.offer.serverId) {
        this.endpoints.delete(laneId);
        this.served.delete(laneId);
        void ep.stop(l && l.status !== "closed" && !s.auth.closed ? "offer_rotated" : "lane_closed");
        continue;
      }
      ep.setProjectNamesVisible(namesShown(s, laneId));
    }
    for (const b of this.bindings) {
      const l = s.auth.lanes[b.laneId];
      if (!l || l.status === "closed" || s.auth.closed || this.endpoints.has(b.laneId) || this.gone.has(b.laneId)) continue;
      const ep = this.makeEndpoint(b, l.offer.serverId);
      if (!ep) continue;
      this.endpoints.set(b.laneId, ep);
      this.served.set(b.laneId, l.offer.serverId);
      if (this.o.autostart !== false) void ep.start();
    }
  }

  /**
   * Lifecycle hook agent.archived (C-13): every running endpoint of that agent stops at once and is
   * handed to `onAgentGone`. Returns the lane ids.
   */
  onAgentArchived(agentId: string): string[] {
    const out: string[] = [];
    for (const [laneId, ep] of this.endpoints) {
      if (ep.lane.agentId !== agentId) continue;
      ep.agentGone("agent_archived");
      out.push(laneId);
    }
    return out;
  }

  /** The endpoint stopped for good (agent archived or missing): drop it and report it once. */
  private agentGone(laneId: string, reason: AgentGoneReason): void {
    const ep = this.endpoints.get(laneId);
    if (ep) {
      this.endpoints.delete(laneId);
      this.served.delete(laneId);
      void ep.stop(reason);
    }
    this.gone.add(laneId);
    log("v2_lane_agent_gone", { roomId: this.roomId, laneId, reason });
    try {
      this.o.onAgentGone?.(laneId, reason);
    } catch (e) {
      log("v2_lane_close_failed", { roomId: this.roomId, laneId, error: String((e as Error)?.message ?? e).slice(0, 200) });
    }
  }

  enforce(laneId: string, reason: string): { cutLinks: number; cutRoutes: number } {
    return this.endpoints.get(laneId)?.enforce(reason) ?? { cutLinks: 0, cutRoutes: 0 };
  }

  lanes() {
    const s = this.o.host.state;
    return Object.entries(s.auth.lanes).map(([laneId, l]) => {
      const ep = this.endpoints.get(laneId);
      const b = this.bindings.find((x) => x.laneId === laneId);
      return {
        laneId,
        serverId: l.offer.serverId,
        status: l.status,
        label: b?.label ?? null,
        agentId: b?.agentId ?? null,
        endpoint: ep?.status ?? null,
        links: ep?.links.length ?? 0,
        routes: ep?.routes.length ?? 0,
        showNames: namesShown(s, laneId),
      };
    });
  }

  /** Owner-only error log of a lane (grants-v2 13.1). */
  errors(laneId: string) {
    return this.endpoints.get(laneId)?.errors.list() ?? [];
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await Promise.all([...this.endpoints.values()].map((e) => e.stop("stopped")));
    this.endpoints.clear();
  }

  // ------------------------------------------------------------------------------ internals

  private linkInfo(deviceId: string, laneId: string): LinkInfo[] {
    const dev = deviceKid(this.o.host.state, deviceId);
    const ep = this.endpoints.get(laneId);
    if (!dev || !ep) return [];
    return ep.linksOfDevice(dev).map((l) => ({ since: l.acceptedAt, routes: l.channels.size }));
  }

  private makeEndpoint(b: LaneBinding, serverId: string): LaneEndpoint | null {
    const keys = readHostKeys(this.o.dataDir, this.o.kek, this.roomId);
    const k = keys?.lanes[b.laneId];
    if (!k) {
      log("v2_lane_key_missing", { roomId: this.roomId, laneId: b.laneId });
      return null;
    }
    const lane: EndpointLane = { id: b.laneId, roomId: this.roomId, label: b.label, origin: { kind: "share" }, agentId: b.agentId, workspaceId: b.workspaceId, serverId, relay: this.o.relay };
    const projectNames: ProjectNamePolicy = { show: namesShown(this.o.host.state, b.laneId), label: neutralProjectLabel(undefined, b.label) };
    return new LaneEndpoint(lane, {
      authority: this.authority(b.laneId, serverId),
      projectNames,
      errorRefs: true,
      paseoHome: this.o.paseoHome,
      limits: this.o.limits ?? V2_LANE_LIMITS,
      onAgentGone: (laneId, reason) => this.agentGone(laneId, reason),
    });
  }

  private authority(laneId: string, aud: string): LaneGrantAuthority {
    return {
      failedAttemptsPerMinute: FAILED_LINKS_PER_MINUTE,
      check: (token, id, opts) => (id === laneId ? this.o.grants.verify(token, { laneId, aud }, opts) : { ok: false, reason: "wrong_audience" }),
      keyPair: () => {
        const keys = readHostKeys(this.o.dataDir, this.o.kek, this.roomId);
        const k = keys?.lanes[laneId];
        if (!k) throw new Error("lane keys missing");
        const secretKey = new Uint8Array(b64uDecode(k.secret, 32));
        return { publicKey: x25519.getPublicKey(secretKey), secretKey };
      },
      admitLink: (link) => this.admitLink(laneId, link),
    };
  }

  /** Grants-v2 6.1 with the heartbeat-observation rule (see the header). */
  async admitLink(laneId: string, link: LinkSession): Promise<"accept" | "reject"> {
    const claims = link.claims!;
    const ep = link.endpoint;
    const others = () => ep.linksOfDevice(claims.dev).filter((l) => l !== link && !l.closed);
    if (others().length === 0) return "accept";
    const t0 = Date.now();
    const wait = this.o.livenessWaitMs ?? LIVENESS_WAIT_MS;
    while (Date.now() - t0 < wait && !link.closed && others().length > 0 && !others().some((l) => l.lastRxAt >= t0)) {
      await new Promise((r) => setTimeout(r, Math.min(100, wait)));
    }
    if (link.closed) return "reject";
    const existing = others();
    const live = existing.filter((l) => l.lastRxAt >= t0);
    if (live.length === 0) {
      for (const l of existing) l.cut("replaced_dead_link");
      log("link_replaced_dead", { laneId, gid: claims.gid });
      return "accept";
    }
    // Two live holders of the same grant: close both, unlist the gid, record the theft.
    for (const l of existing) l.cut("suspected_theft");
    const deviceId = deviceIdOfKid(this.o.host.state, claims.sub, claims.dev);
    if (deviceId) this.o.grants.suspectedTheft({ deviceId, laneId, gid: claims.gid, reportedBy: "endpoint" });
    return "reject";
  }

  private readBindings(): LaneBinding[] {
    const plain = this.o.kek.readSealed(lanesPath(this.o.dataDir, this.roomId), lanesPurpose(this.roomId));
    if (!plain) return [];
    try {
      const parsed = LanesFile.safeParse(rjcsParse(plain, 4 * 1024 * 1024));
      if (!parsed.success || parsed.data.roomId !== this.roomId) throw new Error(`lanes file: ${parsed.success ? "other room" : firstIssue(parsed.error)}`);
      return parsed.data.lanes;
    } finally {
      plain.fill(0);
    }
  }

  private writeBindings(lanes: LaneBinding[]): void {
    const plain = Buffer.from(rjcs({ v: 2, typ: "host-lanes", roomId: this.roomId, lanes }, 4 * 1024 * 1024));
    try {
      this.o.kek.writeSealed(lanesPath(this.o.dataDir, this.roomId), lanesPurpose(this.roomId), plain);
    } finally {
      plain.fill(0);
    }
    this.bindings = lanes;
  }
}

/** Grants-v2 13.2: the effective value the lane owner's gateway applies. */
export function namesShown(s: Readonly<RoomState>, laneId: string): boolean {
  return s.auth.policy.projectNames === "lane-owner" && s.auth.lanes[laneId]?.showNames === true;
}

function deviceKid(s: Readonly<RoomState>, deviceId: string): string | null {
  for (const m of Object.values(s.members)) for (const d of m.devices) if (d.deviceId === deviceId) return edKid(d.sig);
  return null;
}

function deviceIdOfKid(s: Readonly<RoomState>, memberId: string, dev: string): string | null {
  return s.members[memberId]?.devices.find((d) => edKid(d.sig) === dev)?.deviceId ?? null;
}
