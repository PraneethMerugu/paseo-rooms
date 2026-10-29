// Gateway role (owner daemon): rooms, lanes, lane endpoints, fork, invites, revocation.
// The embedded host (HostStore) holds membership and grants; this class owns the live endpoints and
// pushes every access change into them synchronously.
import type { PaseoAgentConfig, PaseoApi } from "@getpaseo/client";
import { LIMITS, type Lane, type LaneOrigin, type Room } from "../../shared/schemas";
import type { LaneView, MemberView, OwnedRoomView } from "../../shared/rpc";
import { randomHexId } from "../crypto";
import { isForkVerifiedProvider } from "../../shared/policy";
import { HostStore, type HostChange } from "../host/host-store";
import { DEFAULT_LIMITS, type ResourceLimits } from "../limits";
import { log, logError } from "../log";
import { ensureInertMcp, restrictRoomAgentConfig, ROOM_LANE_ENV } from "./agent-guard";
import { LaneEndpoint, type AgentGoneReason } from "./lane-endpoint";
import { verifyRoomAgent, verifyRoomAgentEventually } from "./tripwire";

export interface CreateLaneInput {
  roomId: string;
  agentId: string;
  origin: "fork" | "share";
  laneLabel?: string;
  instruction?: string;
}

export interface CuratedContext {
  text: string;
  items: number;
  chars: number;
}

/** Builds the fork seed from the parent's user and assistant messages only (no tool output, no reasoning). */
export async function curateContext(paseo: PaseoApi, agentId: string, maxItems = LIMITS.forkContextMaxItems, maxChars = LIMITS.forkContextMaxChars): Promise<CuratedContext> {
  const timeline = paseo.agents.ref(agentId).timeline;
  const collected: Array<{ role: string; text: string }> = [];
  let page = await timeline.refetch({ direction: "tail", limit: 50, projection: "projected" });
  for (let i = 0; i < 10; i++) {
    const items = page.entries
      .map((e) => e.item)
      .filter((it): it is Extract<typeof it, { type: "user_message" | "assistant_message" }> => it.type === "user_message" || it.type === "assistant_message")
      .map((it) => ({ role: it.type === "user_message" ? "User" : "Agent", text: it.text.trim() }))
      .filter((it) => it.text);
    collected.unshift(...items);
    if (collected.length >= maxItems || !page.hasOlder || !page.startCursor) break;
    page = await timeline.refetch({ direction: "before", cursor: page.startCursor, limit: 50, projection: "projected" });
  }
  const recent = collected.slice(-maxItems);
  const parts: string[] = [];
  let chars = 0;
  for (let i = recent.length - 1; i >= 0; i--) {
    const block = `${recent[i].role}: ${recent[i].text}`;
    if (chars + block.length > maxChars) break;
    parts.unshift(block);
    chars += block.length;
  }
  return { text: parts.join("\n\n"), items: parts.length, chars };
}

export class Gateway {
  readonly host: HostStore;
  readonly endpoints = new Map<string, LaneEndpoint>();
  private unsubscribe: (() => void) | null = null;
  private lastEnforce = { cutLinks: 0, cutRoutes: 0 };
  private readonly agentTitles = new Map<string, string | null>();

  constructor(
    readonly dataDir: string,
    readonly paseoHome: string,
    relay?: { endpoint: string; useTls: boolean },
    readonly limits: ResourceLimits = DEFAULT_LIMITS,
  ) {
    this.host = new HostStore(dataDir, relay);
  }

  start(): void {
    this.unsubscribe = this.host.onChange((c) => this.onHostChange(c));
    for (const lane of this.host.lanes) if (lane.status === "open") this.startEndpoint(lane);
    log("gateway_started", { lanes: this.endpoints.size, hostKeyId: this.host.hostKey.keyId });
  }

  private startEndpoint(lane: Lane): void {
    if (this.endpoints.has(lane.id)) return;
    const inert = ensureInertMcp(this.dataDir);
    const ep = new LaneEndpoint(lane, {
      host: this.host,
      paseoHome: this.paseoHome,
      limits: this.limits,
      onAgentGone: (laneId, reason) => this.onLaneAgentGone(laneId, reason),
      verifyRoomAgent: (l) => {
        const r = verifyRoomAgent(this.paseoHome, l.agentId, null, inert);
        return { ok: r.ok, problems: r.problems };
      },
    });
    this.endpoints.set(lane.id, ep);
    void ep.start();
  }

  private onHostChange(change: HostChange): void {
    switch (change.kind) {
      case "member_revoked":
      case "member_left":
      case "grant_revoked": {
        const ep = this.endpoints.get(change.laneId);
        this.lastEnforce = ep ? ep.enforce(change.kind) : { cutLinks: 0, cutRoutes: 0 };
        return;
      }
      case "lane_closed": {
        const ep = this.endpoints.get(change.laneId);
        this.endpoints.delete(change.laneId);
        void ep?.stop("lane_closed");
        return;
      }
      case "lane_opened": {
        const lane = this.host.lane(change.laneId);
        if (lane) this.startEndpoint(lane);
        return;
      }
      case "room_settings_changed": {
        for (const ep of this.endpoints.values()) if (ep.lane.roomId === change.roomId) ep.setProjectNamesVisible(change.settings.showProjectName);
        return;
      }
    }
  }

  /** C-13: the lane agent was archived or deleted. Close the lane and record why; never retry. */
  private onLaneAgentGone(laneId: string, reason: AgentGoneReason): void {
    try {
      this.host.closeLane(laneId, { actor: "host", reason });
    } catch (e) {
      logError("lane_close_failed", e, { laneId, reason });
    }
  }

  /** Lifecycle hook agent.archived: close every open lane bound to that agent (fork or share). */
  onAgentArchived(agentId: string): number {
    let closed = 0;
    for (const lane of this.host.lanes)
      if (lane.status === "open" && lane.agentId === agentId) {
        this.onLaneAgentGone(lane.id, "agent_archived");
        closed++;
      }
    return closed;
  }

  /** The open fork lane whose room agent is `agentId`, if any (session_open tripwire). */
  forkLaneOfAgent(agentId: string) {
    return this.host.lanes.find((l) => l.status === "open" && l.origin.kind === "fork" && l.agentId === agentId);
  }

  /** Re-verifies a fork lane agent's stored config before it is resumed. Throws to refuse the open. */
  assertRoomAgentIntact(agentId: string): void {
    const lane = this.forkLaneOfAgent(agentId);
    if (!lane) return;
    const r = verifyRoomAgent(this.paseoHome, agentId, null, ensureInertMcp(this.dataDir));
    if (r.ok) return;
    log("room_agent_tripwire", { laneId: lane.id, agentId, when: "session_open", problems: r.problems });
    throw new Error(`Room agent failed the isolation check: ${r.problems.join("; ")}`);
  }

  async stop(): Promise<void> {
    this.unsubscribe?.();
    await Promise.all([...this.endpoints.values()].map((ep) => ep.stop("plugin_stopped")));
    this.endpoints.clear();
  }

  // ------------------------------------------------------------------ owner operations
  async createRoom(paseo: PaseoApi, input: { name: string } & Omit<CreateLaneInput, "roomId">): Promise<{ room: Room; lane: Lane }> {
    const room = this.host.createRoom(input.name);
    try {
      const lane = await this.createLane(paseo, { ...input, roomId: room.id });
      return { room, lane };
    } catch (e) {
      this.host.abandonRoom(room.id);
      throw e;
    }
  }

  async createLane(paseo: PaseoApi, input: CreateLaneInput): Promise<Lane> {
    const room = this.host.room(input.roomId);
    if (!room || room.status !== "active") throw new Error("Room not found");
    const source = await paseo.agents.ref(input.agentId).refresh();
    if (!source || source.agent.id !== input.agentId) throw new Error("Agent not found on this daemon");
    const parent = source.agent;
    if (parent.archivedAt) throw new Error("Agent is archived");
    const laneId = randomHexId("lane_");
    let agentId = parent.id;
    let workspaceId = parent.workspaceId ?? null;
    let origin: LaneOrigin = { kind: "share", agentId: parent.id };
    let title = parent.title ?? null;
    if (input.origin === "fork") {
      const provider = String(parent.provider);
      if (!isForkVerifiedProvider(provider))
        throw new Error(`Fork lanes are not supported for ${provider}: only providers verified to respect the room agent guard are allowed`);
      const context = await curateContext(paseo, parent.id);
      const instruction = input.instruction?.trim() || "Read the context above. Reply with one short line confirming you are ready, and wait for instructions.";
      const prompt = [
        `You are a fork of another agent, created for the room "${room.name}". Below is curated context from the parent conversation (user and agent messages only).`,
        "<parent_context>",
        context.text || "(no messages yet)",
        "</parent_context>",
        "",
        instruction,
      ].join("\n");
      const inert = ensureInertMcp(this.dataDir);
      const baseConfig: PaseoAgentConfig = { provider: parent.model ? `${provider}/${parent.model}` : provider };
      const config = restrictRoomAgentConfig(baseConfig, inert) as PaseoAgentConfig;
      title = `${room.name} · fork`;
      // Created WITHOUT a prompt: the isolation tripwire checks the final stored config (after every
      // plugin's agent.create hook) before the agent does anything.
      const handle = await paseo.agents.create({
        config,
        cwd: parent.cwd,
        parent: parent.id,
        title,
        labels: { "rooms.lane": laneId, "rooms.room": room.id },
        env: { [ROOM_LANE_ENV]: laneId },
      });
      const check = await verifyRoomAgentEventually(this.paseoHome, handle.id, parent.cwd, inert);
      if (!check.ok) {
        log("room_agent_tripwire", { laneId, agentId: handle.id, when: "create", problems: check.problems });
        await handle.archive().catch((e) => logError("room_agent_archive_failed", e, { agentId: handle.id }));
        throw new Error(`Room agent failed the isolation check and was archived: ${check.problems.join("; ")}`);
      }
      await handle.send(prompt);
      const created = (await handle.refresh())?.agent;
      agentId = handle.id;
      workspaceId = created?.workspaceId ?? handle.workspaceId ?? null;
      origin = { kind: "fork", parentAgentId: parent.id, contextItems: context.items, contextChars: context.chars };
      log("fork_created", { laneId, parentAgentId: parent.id, agentId, contextItems: context.items, contextChars: context.chars });
    }
    if (!workspaceId) throw new Error("Agent has no workspace");
    this.agentTitles.set(agentId, title);
    return this.host.createLane({
      id: laneId,
      roomId: room.id,
      label: input.laneLabel ?? (input.origin === "fork" ? "Fork" : "Live"),
      origin,
      agentId,
      workspaceId,
    });
  }

  closeLane(laneId: string): void {
    this.host.closeLane(laneId, { actor: "owner", reason: "owner_closed" });
  }

  /** Owner opt-in: show the project name to the room's members (applies to open routes now). */
  setShowProjectName(roomId: string, show: boolean) {
    return this.host.setShowProjectName(roomId, show);
  }

  /**
   * Full error detail that this lane's viewers received as generic text. For the owner's local RPC
   * only; the lane endpoint never sends it. Empty for a closed lane (the log lives with the endpoint).
   */
  laneErrors(laneId: string) {
    if (!this.host.lane(laneId)) throw new Error("Lane not found");
    return this.endpoints.get(laneId)?.errors.list() ?? [];
  }

  revokeMember(memberId: string): { cutLinks: number; cutRoutes: number } {
    this.lastEnforce = { cutLinks: 0, cutRoutes: 0 };
    this.host.revokeMember(memberId);
    return this.lastEnforce;
  }

  // ------------------------------------------------------------------ views
  private async agentTitle(paseo: PaseoApi | null, agentId: string): Promise<string | null> {
    if (this.agentTitles.has(agentId)) return this.agentTitles.get(agentId) ?? null;
    if (!paseo) return null;
    try {
      const r = await paseo.agents.ref(agentId).refresh();
      const t = r?.agent.title ?? null;
      this.agentTitles.set(agentId, t);
      return t;
    } catch {
      return null;
    }
  }

  async overview(paseo: PaseoApi | null): Promise<OwnedRoomView[]> {
    const out: OwnedRoomView[] = [];
    for (const room of this.host.rooms) {
      if (room.status !== "active") continue;
      const lanes: LaneView[] = [];
      for (const lane of this.host.lanes.filter((l) => l.roomId === room.id)) {
        const ep = this.endpoints.get(lane.id);
        lanes.push({
          lane,
          agentTitle: await this.agentTitle(paseo, lane.agentId),
          connectedMembers: ep ? ep.connectedMemberIds().size : 0,
          activeRoutes: ep ? ep.activeRoutes() : 0,
          endpoint: lane.status === "closed" ? "closed" : (ep?.status ?? "offline"),
        });
      }
      const members: MemberView[] = this.host.members
        .filter((m) => m.roomId === room.id)
        .map(({ devicePublicKey: _d, ...m }) => {
          const g = this.host.latestGrant(m.id);
          return {
            ...m,
            connected: !!this.endpoints.get(m.laneId)?.connectedMemberIds().has(m.id),
            grantExpiresAt: g && m.status === "active" ? new Date(g.exp * 1000).toISOString() : null,
          };
        });
      const invites = this.host.invites
        .filter((i) => i.roomId === room.id)
        .map((i) => ({ id: i.id, laneId: i.laneId, createdAt: i.createdAt, expiresAt: i.expiresAt, grantTtlSeconds: i.grantTtlSeconds, status: this.host.inviteStatus(i) }));
      out.push({ room, settings: this.host.roomSettings(room.id), lanes, members, invites });
    }
    return out;
  }

  laneAgents() {
    return this.host.lanes
      .filter((l) => l.status === "open")
      .map((l) => ({
        agentId: l.agentId,
        laneId: l.id,
        roomId: l.roomId,
        roomName: this.host.room(l.roomId)?.name ?? "Room",
        connectedMembers: this.endpoints.get(l.id)?.connectedMemberIds().size ?? 0,
      }));
  }
}
