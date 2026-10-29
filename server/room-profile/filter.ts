// Room Profile v1 (watch role) for one lane: default deny, exact-id binding, gateway-built lists.
// The generated table (generated.ts, from profile/classification.csv) is the outer gate: a type that
// is not "forward" or "gateway" there is denied before any binding code runs. A type that is allowed
// by the table but has no binding below is also denied (the conformance test keeps them equal).
//
// Field level: every forwarded message is rebuilt from the reviewed field table (sanitize.ts and
// profile/fields.csv), inbound and outbound.
//
// Isolation guard (HARDENING-PLAN decision 2): lanes run as the owner's OS user (fork lanes are
// ordinary agents of the owner's daemon, share lanes ARE the owner's agent). Such a lane must never
// receive member input that prompts or drives the agent. PROMPTING_INBOUND (future role steer or
// approve in the classification) is denied before the table is consulted, and
// assertOwnerUidLaneIsWatchOnly() refuses to start a lane endpoint if the table ever allows one of
// them. Steering requires sandboxed lanes (a future runner node kind), not a table edit.
import { INBOUND_WATCH, OUTBOUND_WATCH, PROMPTING_INBOUND } from "./generated";
import { newSanitizeContext, sanitizeInboundMessage, sanitizeOutboundPayload, type SanitizeContext } from "./sanitize";

export interface LaneScope {
  agentId: string;
  workspaceId: string;
}

/** Inbound types that prompt, steer or approve, in addition to the classification-derived set. */
export const ALWAYS_PROMPTING: readonly string[] = [
  "send_agent_message_request",
  "agent_permission_response",
  "cancel_agent_request",
  "abort_request",
  "create_agent_request",
  "agent.create.request",
  "clear_agent_attention",
  "agent.fork_context.request",
];

export function isPromptingType(type: unknown): boolean {
  return typeof type === "string" && (PROMPTING_INBOUND.has(type) || ALWAYS_PROMPTING.includes(type));
}

/** Lane runner kinds. M1 has only owner-uid lanes; "sandboxed" is reserved for the runner node kind. */
export type LaneRunner = "owner-uid";
export const M1_LANE_RUNNER: LaneRunner = "owner-uid";

/**
 * Throws if the Room Profile lets any member input prompt or drive an owner-uid lane. Called when a
 * lane endpoint starts; a failure keeps the lane offline.
 */
export function assertOwnerUidLaneIsWatchOnly(table: Readonly<Record<string, string>> = INBOUND_WATCH, runner: LaneRunner = M1_LANE_RUNNER): void {
  if (runner !== "owner-uid") return;
  const allowed = Object.keys(table).filter((t) => table[t] !== "deny" && isPromptingType(t));
  if (allowed.length)
    throw new Error(`Room Profile allows prompting types on an owner-uid lane (${allowed.join(", ")}). Steering requires sandboxed lanes.`);
}

function defaultContext(scope: LaneScope): SanitizeContext {
  return newSanitizeContext({ laneId: "lane_unknown", laneServerId: "lane_unknown", agentId: scope.agentId, workspaceId: scope.workspaceId }, { allowedSessionEvents: ALLOWED_SESSION_EVENTS });
}

export type InboundDecision =
  | { action: "forward"; message: Record<string, any>; listKind: "agents" | "workspaces" | null }
  | { action: "deny"; requestId: string | null; reason: string };

/** Inbound type -> response types that pass back for that request. */
export const FORWARDED_RESPONSES: Readonly<Record<string, readonly string[]>> = {
  fetch_workspaces_request: ["fetch_workspaces_response"],
  fetch_agents_request: ["fetch_agents_response"],
  fetch_agent_request: ["fetch_agent_response"],
  fetch_agent_timeline_request: ["fetch_agent_timeline_response"],
  "agent.timeline.set_subscription.request": ["agent.timeline.set_subscription.response"],
  "session.events.set_subscription.request": ["session.events.set_subscription.response"],
  "subscription.release.request": ["subscription.release.response"],
};

/** Inbound types with a binding implemented below. */
export const IMPLEMENTED_INBOUND = Object.keys(FORWARDED_RESPONSES).sort();
/** Outbound types with a binding implemented in filterOutbound (plus status/server_info). */
export const IMPLEMENTED_OUTBOUND = [
  "agent.timeline.replacement",
  "agent.timeline.set_subscription.response",
  "agent_attention_required",
  "agent_permission_request",
  "agent_permission_resolved",
  "agent_status",
  "agent_stream",
  "agent_update",
  "fetch_agent_response",
  "fetch_agent_timeline_response",
  "fetch_agents_response",
  "fetch_workspaces_response",
  "rpc_error",
  "session.events.set_subscription.response",
  "status",
  "subscription.release.response",
  "workspace_update",
].sort();

/** Session event streams a watch viewer may subscribe to; each is agent-scoped and filtered outbound. */
export const ALLOWED_SESSION_EVENTS: ReadonlySet<string> = new Set([
  "agent_attention_required",
  "agent_permission_request",
  "agent_permission_resolved",
  "status.server_info",
]);

export function requestIdOf(msg: Record<string, any>): string | null {
  if (typeof msg?.requestId === "string") return msg.requestId;
  if (msg?.payload && typeof msg.payload.requestId === "string") return msg.payload.requestId;
  return null;
}

function tableAllows(table: Readonly<Record<string, string>>, type: unknown): boolean {
  return typeof type === "string" && Object.prototype.hasOwnProperty.call(table, type) && table[type] !== "deny";
}

export function decideInbound(msg: Record<string, any>, scope: LaneScope, ctx: SanitizeContext = defaultContext(scope)): InboundDecision {
  const rawId = requestIdOf(msg);
  const requestId = rawId && rawId.length <= 256 ? rawId : null;
  const deny = (reason: string): InboundDecision => ({ action: "deny", requestId, reason });
  if (!msg || typeof msg.type !== "string") return deny("malformed");
  if (isPromptingType(msg.type)) return deny("owner_uid_lane_not_promptable");
  if (!tableAllows(INBOUND_WATCH, msg.type)) return deny("type_not_in_room_profile");
  if (typeof msg.requestId === "string" && msg.requestId.length > 256) return deny("malformed");
  const forward = (listKind: "agents" | "workspaces" | null): InboundDecision => {
    const message = sanitizeInboundMessage(msg.type, msg, ctx);
    return message ? { action: "forward", message, listKind } : deny("no_field_policy");
  };
  switch (msg.type) {
    case "fetch_workspaces_request":
      return forward("workspaces");
    case "fetch_agents_request":
      return forward("agents");
    case "fetch_agent_request":
    case "fetch_agent_timeline_request":
      // Exact match only: the daemon also resolves id prefixes and titles.
      return msg.agentId === scope.agentId ? forward(null) : deny("agent_out_of_scope");
    case "agent.timeline.set_subscription.request": {
      const ids: unknown = msg.agentIds;
      if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => id !== scope.agentId)) return deny("agent_out_of_scope");
      return forward(null);
    }
    case "session.events.set_subscription.request": {
      const d = forward(null);
      if (d.action === "forward") d.message = { ...d.message, events: Array.isArray(d.message.events) ? d.message.events : [], notifications: false };
      return d;
    }
    case "subscription.release.request":
      return forward(null);
    default:
      return deny("binding_not_implemented");
  }
}

export function accessDenied(requestId: string, requestType: string): Record<string, any> {
  const type = requestType.length > 96 ? `${requestType.slice(0, 96)}…` : requestType;
  return {
    type: "rpc_error",
    payload: { requestId, requestType: type, error: `Room is not authorized for ${type}`, code: "access_denied" },
  };
}

/**
 * Filters one outbound session message. `forwarded` maps requestId -> inbound type for requests this
 * viewer was allowed to send. List responses are reduced here and then rebuilt by the gateway.
 * Returns null to drop. `status` is handled by rewriteServerInfo, never passed through.
 */
export function filterOutbound(
  msg: Record<string, any>,
  scope: LaneScope,
  forwarded: ReadonlyMap<string, string>,
  ctx: SanitizeContext = defaultContext(scope),
): Record<string, any> | null {
  const decided = decideOutbound(msg, scope, forwarded);
  if (!decided) return null;
  const payload = sanitizeOutboundPayload(decided.type, decided.payload ?? {}, ctx);
  return payload ? { type: decided.type, payload } : null;
}

/** Type and scope decision only (no field rebuilding). */
function decideOutbound(msg: Record<string, any>, scope: LaneScope, forwarded: ReadonlyMap<string, string>): Record<string, any> | null {
  if (!msg || !tableAllows(OUTBOUND_WATCH, msg.type)) return null;
  const p = msg.payload ?? {};
  const rid = typeof p.requestId === "string" ? p.requestId : null;
  const inboundType = rid ? forwarded.get(rid) : undefined;
  const isResponseTo = (t: string) => !!inboundType && (FORWARDED_RESPONSES[inboundType] ?? []).includes(t);

  switch (msg.type) {
    case "rpc_error":
      return inboundType ? msg : null;
    case "fetch_workspaces_response":
    case "fetch_agents_response":
      // Entries are scoped (and later rebuilt by the gateway) in the field handlers.
      return isResponseTo(msg.type) ? msg : null;
    case "fetch_agent_response":
      if (!isResponseTo(msg.type)) return null;
      if (p.agent && p.agent.id !== scope.agentId) return null;
      return msg;
    case "fetch_agent_timeline_response":
      if (!isResponseTo(msg.type)) return null;
      return p.agentId === scope.agentId && (!p.agent || p.agent.id === scope.agentId) ? msg : null;
    case "agent.timeline.set_subscription.response":
    case "session.events.set_subscription.response":
    case "subscription.release.response":
      return isResponseTo(msg.type) ? msg : null;
    case "agent_update":
      if (p.kind === "upsert") return p.agent?.id === scope.agentId ? msg : null;
      if (p.kind === "remove") return p.agentId === scope.agentId ? msg : null;
      return null;
    case "workspace_update":
      if (p.kind === "upsert") return p.workspace?.id === scope.workspaceId ? msg : null;
      if (p.kind === "remove") return p.id === scope.workspaceId ? msg : null;
      return null;
    case "agent_status":
      return p.agentId === scope.agentId && (!p.info || p.info.id === scope.agentId) ? msg : null;
    case "agent_stream":
    case "agent.timeline.replacement":
    case "agent_permission_request":
    case "agent_permission_resolved":
    case "agent_attention_required":
      return p.agentId === scope.agentId ? msg : null;
    default:
      // includes "status": only server_info, rewritten by the caller
      return null;
  }
}

/** Data-shape and rendering flags kept from the daemon's server_info. No action flags. */
export const KEPT_FEATURES = [
  "ownedSubscriptions",
  "directorySync",
  "selectiveAgentTimeline",
  "explicitEventSubscriptions",
  "canonicalSubmittedPrompts",
  "agentMessageProvenance",
  "stableProjectIdentity",
  "workspaceMultiplicity",
  "pluginTimelineItems",
  "agentThinkingUpdate",
  "workspaceSortTimes",
  "projectedSubagentTimeline",
] as const;

/**
 * server_info for a routed virtual session. `connectedHosts` is required by the member daemon to
 * accept a route (routed-lane spike, deviation 1); hosts.* requests are still denied.
 */
export function rewriteServerInfo(payload: Record<string, any>, laneServerId: string, hostname: string): Record<string, any> {
  const upstream = payload?.features ?? {};
  const features: Record<string, boolean> = {};
  for (const f of KEPT_FEATURES) if (upstream[f] === true) features[f] = true;
  features.relayProtectedSecurity = true;
  features.connectedHosts = true;
  return {
    status: "server_info",
    protocolVersion: payload?.protocolVersion,
    serverId: laneServerId,
    hostname,
    version: payload?.version,
    permissions: ["workspace.read"],
    desktopManaged: false,
    features,
  };
}

/** server_info for the physical host-link session (member daemon). */
export function linkServerInfo(laneServerId: string, hostname: string, version: string): Record<string, any> {
  return {
    status: "server_info",
    protocolVersion: 1,
    serverId: laneServerId,
    hostname,
    version,
    permissions: ["workspace.read"],
    desktopManaged: false,
    features: { connectedHosts: true, hostMultiplexing: true, relayProtectedSecurity: true },
  };
}

export function agentMatchesFilter(entry: { agent: any; project: any }, req: any): boolean {
  const f = req?.filter ?? {};
  const a = entry.agent;
  if (Array.isArray(f.statuses) && !f.statuses.includes(a.status)) return false;
  if (f.includeArchived !== true && a.archivedAt) return false;
  if (f.requiresAttention === true && a.requiresAttention !== true) return false;
  if (Array.isArray(f.projectKeys) && !f.projectKeys.includes(entry.project?.projectKey)) return false;
  if (f.labels && typeof f.labels === "object")
    for (const [k, v] of Object.entries(f.labels)) if (a.labels?.[k] !== v) return false;
  return true;
}

export function workspaceMatchesFilter(w: any, req: any): boolean {
  const f = req?.filter ?? {};
  if (typeof f.projectId === "string" && w.projectId !== f.projectId) return false;
  if (typeof f.query === "string" && f.query && !JSON.stringify([w.name, w.title, w.branch]).toLowerCase().includes(f.query.toLowerCase()))
    return false;
  return true;
}
