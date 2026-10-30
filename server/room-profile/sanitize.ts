// Field-level allowlists for the Room Profile (code review C-3, C-6, C-16; protocol review P-18,
// P-19, P-26). The type-level gate in filter.ts decides WHICH messages pass; this module decides
// WHICH FIELDS of them pass. Every forwarded object is rebuilt from the reviewed table in
// profile/fields.csv (generated into FIELD_POLICY):
//   keep     copy the value
//   drop     omit
//   nested   rebuild the value with the table "<object>.<field>"
//   redact   replace through the handler REDACTORS["<object>.<field>"]
//   gateway  produced by the gateway through the same handler table
//   force    (hello.capabilities only) always true
// Fields that are not in the table are dropped, so a protocol bump that adds a field cannot leak it.
// The conformance test fails on any field that the installed protocol has and the table lacks.
//
// Project display names (HARDENING-PLAN decisions round 2): hidden from viewers unless the owner
// opts in per room. While hidden, every name field is replaced by the lane's neutral label and the
// basename of every redacted path is replaced by a keyed hash, so "/room/<project folder>" does not
// reveal the name either. The policy object is shared by every route of a lane, so a change applies
// to the next message of every open route.
//
// Errors (same decision): viewers get generic text. The original text goes to ctx.errors, the
// owner-only LaneErrorLog read through the local RPC rooms.lane.errors; it is never forwarded.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { deriveAgentStateBucket } from "@getpaseo/protocol/agent-state-bucket";
import type { ErrorSink } from "../gateway/lane-errors";
import { FIELD_POLICY } from "./generated";

export const OMIT = Symbol("omit");
type Out = unknown | typeof OMIT;

export interface LaneAgentState {
  status?: string;
  pendingPermissionCount?: number;
  attentionReason?: string | null;
  requiresAttention?: boolean;
  updatedAt?: string | null;
  lastUserMessageAt?: string | null;
}

/** Owner's per-room choice, shared by every route of a lane (mutated in place on a policy change). */
export interface ProjectNamePolicy {
  /** true: forward the project's display names and folder names. Default false. */
  show: boolean;
  /** Neutral name used while hidden, e.g. "<room name> · <lane label>". */
  label: string;
}

export const DEFAULT_NEUTRAL_LABEL = "Shared lane";

/** Neutral project label for a lane: the room and lane names the member already got with the invite. */
export function neutralProjectLabel(roomName: string | undefined, laneLabel: string | undefined): string {
  const parts = [roomName, laneLabel].map((p) => (typeof p === "string" ? p.trim() : "")).filter(Boolean);
  const label = parts.join(" · ") || DEFAULT_NEUTRAL_LABEL;
  return label.length > 120 ? `${label.slice(0, 119)}…` : label;
}

/** Per-route context for outbound sanitising. Counters rebase directory sequence numbers (P-26). */
export interface SanitizeContext {
  laneId: string;
  laneServerId: string;
  agentId: string;
  workspaceId: string;
  seq: { agents: number; workspaces: number };
  /** Random per route; suffix of every directory generation the viewer sees. */
  routeTag: string;
  /** Last snapshot of the lane agent (shared by the lane), used to derive the workspace status. */
  laneAgent: { current: LaneAgentState | null };
  /** Inbound only. */
  maxTimelineLimit: number;
  /** Inbound only: session events a viewer may subscribe to. */
  allowedSessionEvents: ReadonlySet<string>;
  /** Project name visibility (shared by the lane's routes). */
  projectNames: ProjectNamePolicy;
  /** Owner-only sink for the full text of errors replaced by generic text; null drops it. */
  errors: ErrorSink | null;
}

export function newSanitizeContext(scope: { laneId: string; laneServerId: string; agentId: string; workspaceId: string }, extra: Partial<SanitizeContext> = {}): SanitizeContext {
  return {
    ...scope,
    seq: { agents: 0, workspaces: 0 },
    routeTag: randomBytes(6).toString("base64url"),
    laneAgent: { current: null },
    maxTimelineLimit: 1000,
    allowedSessionEvents: new Set(),
    projectNames: { show: false, label: DEFAULT_NEUTRAL_LABEL },
    errors: null,
    ...extra,
  };
}

const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Absolute path -> "/room/<basename>". Keeps relations between equal paths, hides the owner's tree. */
export function redactPath(p: unknown): Out {
  if (p === null) return null;
  if (typeof p !== "string") return OMIT;
  const base = p.split(/[\\/]+/).filter(Boolean).pop() ?? "";
  // A Windows drive root ("C:\\", "C:") maps to "/room", not "/room/C:" (X-14; untested on Windows).
  return base && !/^[A-Za-z]:$/.test(base) ? `/room/${base}` : "/room";
}

/**
 * Per-process key for hidden folder names. Keyed, so a viewer cannot test guesses of a project name
 * against the hash; stable for the life of the plugin process, so equal paths stay equal.
 */
const FOLDER_KEY = randomBytes(32);

/** Path redaction under the room's project name policy: the basename is hashed while names are hidden. */
export function redactPathFor(p: unknown, ctx: SanitizeContext): Out {
  const r = redactPath(p);
  if (ctx.projectNames.show || typeof r !== "string" || r === "/room") return r;
  const base = r.slice("/room/".length);
  return `/room/folder-${createHmac("sha256", FOLDER_KEY).update(base).digest("hex").slice(0, 10)}`;
}

/** Project display name field: the value when the owner shows names, else the neutral label. */
function projectName(v: unknown, ctx: SanitizeContext): Out {
  if (v === undefined) return OMIT;
  if (ctx.projectNames.show) return v;
  return v === null ? null : ctx.projectNames.label;
}

const lastSegment = (v: string) => v.split(/[\\/]+/).filter(Boolean).pop() ?? "";

/** Lower-cased project names of one object: name fields, their last "owner/repo" segment, folder basenames. */
function projectNamesOf(parent: Record<string, unknown>, nameFields: readonly string[], folders: (p: Record<string, unknown>) => unknown[]): Set<string> {
  const out = new Set<string>();
  for (const f of nameFields) {
    const v = parent[f];
    if (typeof v === "string" && v.trim()) {
      out.add(v.trim().toLowerCase());
      out.add(lastSegment(v).toLowerCase());
    }
  }
  for (const p of folders(parent)) if (typeof p === "string" && lastSegment(p)) out.add(lastSegment(p).toLowerCase());
  out.delete("");
  return out;
}

/**
 * A workspace name that repeats the project name or the project folder name (a local checkout is
 * often named after its folder) is replaced too; other names (branches, worktree slugs) are kept.
 */
function nameUnlessProject(nameFields: readonly string[], folders: (p: Record<string, unknown>) => unknown[]): Redactor {
  return (v, ctx, parent) => {
    if (v === undefined) return OMIT;
    if (ctx.projectNames.show || typeof v !== "string") return v;
    const names = projectNamesOf(parent, nameFields, folders);
    return names.has(v.trim().toLowerCase()) || names.has(lastSegment(v).toLowerCase()) ? ctx.projectNames.label : v;
  };
}

const placementFolders = (p: Record<string, unknown>): unknown[] => {
  const c = isRecord(p.checkout) ? p.checkout : {};
  return [c.mainRepoRoot, c.isPaseoOwnedWorktree === true ? null : c.worktreeRoot];
};
const workspaceFolders = (w: Record<string, unknown>): unknown[] => [w.projectRootPath];

export const GENERIC_ERROR = "The owner's daemon could not complete this request";
export const GENERIC_AGENT_ERROR = "The agent reported an error";
/** v2 viewer text (grants-v2 13.1), followed by the error reference. */
export const GENERIC_ERROR_V2 = "The agent hit an error. The lane owner can see the details.";

/** Keeps the full text for the owner. Returns the viewer text: M1's generic text, or v2's with its reference. */
function keepForOwner(ctx: SanitizeContext, source: string, v: unknown, m1Text: string = GENERIC_AGENT_ERROR): string {
  const ref = typeof v === "string" && v ? ctx.errors?.record(source, v) : undefined;
  return ref ? `${GENERIC_ERROR_V2} Error reference: ${ref}.` : m1Text;
}

function genericError(source: string): Redactor {
  return (v, ctx) => {
    if (v === null) return null;
    if (v === undefined) return OMIT;
    return keepForOwner(ctx, source, v, GENERIC_ERROR);
  };
}

/** Live stream events: turn failures and timeline error items carry provider and daemon error text. */
function sanitizeStreamEvent(v: Record<string, unknown>, ctx: SanitizeContext): Out {
  if (v.type === "turn_failed") {
    const detail = [v.error, v.diagnostic].filter((x) => typeof x === "string" && x).join("\n\n");
    const text = keepForOwner(ctx, "agent.turn_failed", detail);
    const { diagnostic: _d, code, ...rest } = v;
    return { ...rest, error: text, ...(typeof code === "string" && /^[a-z_]{1,40}$/.test(code) ? { code } : {}) };
  }
  if (v.type === "timeline" && isRecord(v.item)) {
    const item = sanitizeTimelineItem(v.item, ctx);
    return item === v.item ? v : { ...v, item };
  }
  return v;
}

/** A timeline item of type "error" gets generic text; every other item is watch content and passes. */
function sanitizeTimelineItem(item: Record<string, unknown>, ctx: SanitizeContext): Record<string, unknown> {
  if (item.type !== "error") return item;
  return { ...item, message: keepForOwner(ctx, "agent.timeline_error", item.message) };
}

/** Daemon directory generation -> opaque per-route generation. */
function routeGeneration(v: unknown, ctx: SanitizeContext): string {
  const base = typeof v === "string" ? createHash("sha256").update(v).digest("base64url").slice(0, 12) : "room";
  return `${base}.${ctx.routeTag}`;
}

function nextSeq(ctx: SanitizeContext, kind: "agents" | "workspaces"): number {
  ctx.seq[kind] += 1;
  return ctx.seq[kind];
}

function headSeq(ctx: SanitizeContext, kind: "agents" | "workspaces"): number {
  if (ctx.seq[kind] === 0) ctx.seq[kind] = 1;
  return ctx.seq[kind];
}

/**
 * Directory sync metadata for a list response. Inbound `sync` cursors are dropped, so the daemon
 * always answers with a snapshot; the gateway rebuilds the single lane entry and rebases headSeq on
 * a per-route counter, so the daemon's change counts never reach the viewer (P-26).
 */
function scopeSync(sync: unknown, _keepId: string, ctx: SanitizeContext, kind: "agents" | "workspaces"): Out {
  if (!isRecord(sync)) return OMIT;
  const out: Record<string, unknown> = {
    generation: routeGeneration(sync.generation, ctx),
    headSeq: headSeq(ctx, kind),
    mode: "snapshot",
    removals: [],
  };
  if (typeof sync.reason === "string" && ["no_cursor", "generation_changed", "cursor_expired", "changes_too_large"].includes(sync.reason)) out.reason = sync.reason;
  return out;
}

function observeLaneAgent(agent: Record<string, unknown>, ctx: SanitizeContext): void {
  if (agent.id !== ctx.agentId) return;
  ctx.laneAgent.current = {
    status: typeof agent.status === "string" ? agent.status : undefined,
    pendingPermissionCount: Array.isArray(agent.pendingPermissions) ? agent.pendingPermissions.length : 0,
    attentionReason: (agent.attentionReason as string | null | undefined) ?? null,
    requiresAttention: agent.requiresAttention === true,
    updatedAt: typeof agent.updatedAt === "string" ? agent.updatedAt : null,
    lastUserMessageAt: typeof agent.lastUserMessageAt === "string" ? agent.lastUserMessageAt : null,
  };
}

export function sanitizeAgentSnapshot(agent: unknown, ctx: SanitizeContext): Out {
  if (agent === null) return null;
  if (!isRecord(agent)) return OMIT;
  observeLaneAgent(agent, ctx);
  return applyPolicy("AgentSnapshot", agent, ctx);
}

export function sanitizeProjectPlacement(project: unknown, ctx: SanitizeContext): Out {
  if (project === null) return null;
  if (!isRecord(project)) return OMIT;
  return applyPolicy("ProjectPlacement", project, ctx);
}

export function sanitizeWorkspace(w: unknown, ctx: SanitizeContext): Out {
  if (w === null) return null;
  if (!isRecord(w)) return OMIT;
  return applyPolicy("WorkspaceDescriptor", w, ctx);
}

export function sanitizeAgentListEntry(e: unknown, ctx: SanitizeContext): Out {
  if (!isRecord(e)) return OMIT;
  return applyPolicy("AgentListEntry", e, ctx);
}

function laneBucket(ctx: SanitizeContext): string {
  const a = ctx.laneAgent.current;
  if (!a) return "done";
  return deriveAgentStateBucket({
    status: a.status as any,
    pendingPermissionCount: a.pendingPermissionCount,
    attentionReason: a.attentionReason as any,
    requiresAttention: a.requiresAttention,
  });
}

type Redactor = (value: unknown, ctx: SanitizeContext, parent: Record<string, unknown>) => Out;

/** Handlers for every "redact" and "gateway" field in profile/fields.csv (the test checks the sets match). */
export const REDACTORS: Readonly<Record<string, Redactor>> = {
  // ---- upstream hello (B1). The hello is rebuilt by buildUpstreamHello; these handle viewer values.
  "hello.type": () => "hello",
  "hello.sessionPermissions": () => OMIT, // set by the builder
  "hello.clientId": () => OMIT, // set by the builder
  "hello.clientType": () => OMIT, // set by the builder
  "hello.auth": () => OMIT, // set by the builder
  "hello.protocolVersion": (v) => (typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 16 ? v : 1),
  "hello.appVersion": (v) => (typeof v === "string" && /^\d{1,4}\.\d{1,4}\.\d{1,6}(-[0-9A-Za-z.]{1,32})?$/.test(v) ? v : OMIT),

  // ---- inbound
  "in:fetch_agent_timeline_request.limit": (v, ctx) => {
    if (typeof v !== "number" || !Number.isFinite(v)) return OMIT;
    const n = Math.floor(v);
    return n <= 0 || n > ctx.maxTimelineLimit ? ctx.maxTimelineLimit : n;
  },
  "in:session.events.set_subscription.request.events": (v, ctx) =>
    Array.isArray(v) ? v.filter((e) => typeof e === "string" && ctx.allowedSessionEvents.has(e)) : [],
  "in:session.events.set_subscription.request.notifications": () => false,

  // ---- outbound payloads
  "out:fetch_agent_response.agent": (v, ctx) => sanitizeAgentSnapshot(v, ctx),
  "out:fetch_agent_response.project": (v, ctx) => sanitizeProjectPlacement(v, ctx),
  "out:fetch_agent_response.error": genericError("fetch_agent_response.error"),
  "out:fetch_agents_response.entries": (v, ctx) =>
    Array.isArray(v) ? v.filter((e) => isRecord(e) && isRecord(e.agent) && e.agent.id === ctx.agentId).map((e) => sanitizeAgentListEntry(e, ctx)).filter((e) => e !== OMIT) : [],
  "out:fetch_agents_response.pageInfo": () => ({ nextCursor: null, prevCursor: null, hasMore: false }),
  "out:fetch_agents_response.sync": (v, ctx) => scopeSync(v, ctx.agentId, ctx, "agents"),
  "out:fetch_workspaces_response.entries": (v, ctx) =>
    Array.isArray(v) ? v.filter((w) => isRecord(w) && w.id === ctx.workspaceId).map((w) => sanitizeWorkspace(w, ctx)).filter((w) => w !== OMIT) : [],
  "out:fetch_workspaces_response.emptyProjects": () => [],
  "out:fetch_workspaces_response.pageInfo": () => ({ nextCursor: null, prevCursor: null, hasMore: false }),
  "out:fetch_workspaces_response.sync": (v, ctx) => scopeSync(v, ctx.workspaceId, ctx, "workspaces"),
  "out:agent_update.agent": (v, ctx) => sanitizeAgentSnapshot(v, ctx),
  "out:agent_update.project": (v, ctx) => sanitizeProjectPlacement(v, ctx),
  "out:agent_update.generation": (v, ctx) => (v === undefined ? OMIT : routeGeneration(v, ctx)),
  "out:agent_update.seq": (v, ctx) => (typeof v === "number" ? nextSeq(ctx, "agents") : OMIT),
  "out:agent_status.info": (v, ctx) => sanitizeAgentSnapshot(v, ctx),
  "out:workspace_update.workspace": (v, ctx) => sanitizeWorkspace(v, ctx),
  "out:workspace_update.generation": (v, ctx) => (v === undefined ? OMIT : routeGeneration(v, ctx)),
  "out:workspace_update.seq": (v, ctx) => (typeof v === "number" ? nextSeq(ctx, "workspaces") : OMIT),
  "out:agent_stream.event": (v, ctx) => {
    // Watch content passes, but a legacy attention event carries the owner daemon's serverId (C-6).
    // Error text is replaced by generic text (the owner keeps it, see sanitizeStreamEvent).
    if (!isRecord(v)) return OMIT;
    if (v.type !== "attention_required" || !hasOwn(v, "notification")) return sanitizeStreamEvent(v, ctx);
    return { ...v, notification: rewriteNotification(v.notification, ctx) };
  },
  "out:agent_attention_required.notification": (v, ctx) => rewriteNotification(v, ctx),
  "out:rpc_error.error": (v, ctx, parent) => {
    return keepForOwner(ctx, `rpc_error:${typeof parent.requestType === "string" ? parent.requestType.slice(0, 96) : "unknown"}`, v, GENERIC_ERROR);
  },
  "out:rpc_error.code": (v) => (typeof v === "string" && /^[a-z_]{1,40}$/.test(v) ? v : OMIT),
  "out:fetch_agent_timeline_response.agent": (v, ctx) => sanitizeAgentSnapshot(v, ctx),
  "out:fetch_agent_timeline_response.error": genericError("fetch_agent_timeline_response.error"),
  "out:fetch_agent_timeline_response.entries": (v, ctx) =>
    Array.isArray(v) ? v.map((e) => (isRecord(e) && isRecord(e.item) ? { ...e, item: sanitizeTimelineItem(e.item, ctx) } : e)) : OMIT,

  // ---- objects
  "AgentListEntry.agent": (v, ctx) => sanitizeAgentSnapshot(v, ctx),
  "AgentListEntry.project": (v, ctx) => sanitizeProjectPlacement(v, ctx),
  "AgentListEntry.syncSeq": (v, ctx) => (typeof v === "number" ? headSeq(ctx, "agents") : OMIT),
  "AgentSnapshot.cwd": redactPathFor,
  "AgentSnapshot.persistence": () => null,
  "AgentSnapshot.lastError": (v, ctx) => {
    if (typeof v !== "string" || !v) return OMIT;
    return keepForOwner(ctx, "agent.lastError", v);
  },
  "AgentSnapshot.labels": (v) => {
    if (!isRecord(v)) return {};
    const out: Record<string, string> = {};
    for (const [k, val] of Object.entries(v)) if (k.startsWith("rooms.") && typeof val === "string") out[k] = val;
    return out;
  },
  "AgentSnapshot.runtimeInfo.sessionId": (v) => (v === undefined ? OMIT : null),
  "ProjectPlacement.projectKey": (_v, ctx) => `room:${ctx.laneId}`,
  "ProjectPlacement.projectName": projectName,
  "ProjectPlacement.workspaceName": nameUnlessProject(["projectName"], placementFolders),
  "ProjectPlacement.checkout.cwd": redactPathFor,
  "ProjectPlacement.checkout.remoteUrl": () => null,
  "ProjectPlacement.checkout.worktreeRoot": redactPathFor,
  "ProjectPlacement.checkout.mainRepoRoot": redactPathFor,
  "WorkspaceDescriptor.projectDisplayName": projectName,
  "WorkspaceDescriptor.projectCustomName": projectName,
  "WorkspaceDescriptor.name": nameUnlessProject(["projectDisplayName", "projectCustomName"], workspaceFolders),
  "WorkspaceDescriptor.title": nameUnlessProject(["projectDisplayName", "projectCustomName"], workspaceFolders),
  "WorkspaceDescriptor.projectRootPath": redactPathFor,
  "WorkspaceDescriptor.workspaceDirectory": redactPathFor,
  "WorkspaceDescriptor.status": (_v, ctx) => laneBucket(ctx),
  "WorkspaceDescriptor.statusEnteredAt": (_v, ctx) => ctx.laneAgent.current?.updatedAt ?? null,
  "WorkspaceDescriptor.activityAt": (_v, ctx) => ctx.laneAgent.current?.updatedAt ?? null,
  "WorkspaceDescriptor.lastUserMessageAt": (_v, ctx) => ctx.laneAgent.current?.lastUserMessageAt ?? null,
  "WorkspaceDescriptor.diffStat": () => null,
  "WorkspaceDescriptor.scripts": () => [],
  "WorkspaceDescriptor.githubRuntime": () => null,
  "WorkspaceDescriptor.project": (v, ctx) => (v === undefined ? OMIT : sanitizeProjectPlacement(v, ctx)),
  "WorkspaceDescriptor.syncSeq": (v, ctx) => (typeof v === "number" ? headSeq(ctx, "workspaces") : OMIT),
};

function rewriteNotification(n: unknown, ctx: SanitizeContext): Out {
  if (n === undefined) return OMIT;
  if (!isRecord(n)) return OMIT;
  const data = isRecord(n.data) ? n.data : {};
  return {
    title: typeof n.title === "string" ? n.title : "",
    body: typeof n.body === "string" ? n.body : "",
    data: {
      serverId: ctx.laneServerId,
      ...(typeof data.workspaceId === "string" ? { workspaceId: ctx.workspaceId } : {}),
      agentId: ctx.agentId,
      ...(typeof data.reason === "string" ? { reason: data.reason } : {}),
    },
  };
}

/**
 * Rebuilds `value` from the reviewed table for `object`. Unknown fields are dropped. Returns OMIT
 * when there is no table (deny by default).
 */
export function applyPolicy(object: string, value: Record<string, unknown>, ctx: SanitizeContext): Out {
  const table = FIELD_POLICY[object];
  if (!table) return OMIT;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    if (!hasOwn(table, key)) continue;
    const action = table[key];
    const v = value[key];
    let r: Out = OMIT;
    switch (action) {
      case "keep":
        r = v;
        break;
      case "force":
        r = true;
        break;
      case "nested":
        r = v === null ? null : isRecord(v) ? applyPolicy(`${object}.${key}`, v, ctx) : OMIT;
        break;
      case "redact":
      case "gateway": {
        const fn = REDACTORS[`${object}.${key}`];
        r = fn ? fn(v, ctx, value) : OMIT;
        break;
      }
      default:
        r = OMIT;
    }
    if (r !== OMIT && r !== undefined) out[key] = r;
  }
  return out;
}

/** Outbound payload of one allowed message type. */
export function sanitizeOutboundPayload(type: string, payload: unknown, ctx: SanitizeContext): Record<string, unknown> | null {
  if (!isRecord(payload)) return null;
  const r = applyPolicy(`out:${type}`, payload, ctx);
  return r === OMIT ? null : (r as Record<string, unknown>);
}

/** Inbound message of one allowed type, rebuilt from its field table. */
export function sanitizeInboundMessage(type: string, msg: Record<string, unknown>, ctx: SanitizeContext): Record<string, unknown> | null {
  const r = applyPolicy(`in:${type}`, msg, ctx);
  return r === OMIT ? null : (r as Record<string, unknown>);
}

/** Field paths with a redact/gateway action, for the conformance test. */
export function fieldsNeedingHandlers(): string[] {
  const out: string[] = [];
  for (const [object, table] of Object.entries(FIELD_POLICY))
    for (const [field, action] of Object.entries(table)) if (action === "redact" || action === "gateway") out.push(`${object}.${field}`);
  return out.sort();
}
