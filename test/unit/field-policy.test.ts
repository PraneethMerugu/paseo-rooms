// B1/B2: field-level Room Profile. Conformance of the reviewed field table against the installed
// protocol, and leakage tests with realistic daemon descriptors.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CLIENT_CAPS } from "@getpaseo/protocol/client-capabilities";
import * as messages from "@getpaseo/protocol/messages";
import { fieldCoverage, protocolFields, readClassification, readFieldPolicy } from "../../tools/room-profile-lib";
import { FIELD_POLICY, INBOUND_WATCH } from "../../server/room-profile/generated";
import { ALLOWED_SESSION_EVENTS, assertOwnerUidLaneIsWatchOnly, decideInbound, filterOutbound } from "../../server/room-profile/filter";
import { fieldsNeedingHandlers, newSanitizeContext, REDACTORS, sanitizeAgentListEntry, sanitizeWorkspace } from "../../server/room-profile/sanitize";
import { buildUpstreamHello } from "../../server/gateway/local-daemon";
import { agentSnapshot, LANE, leaks, OTHER_AGENT, projectPlacement, workspaceDescriptor } from "./fixtures";
import { tempDir } from "./helpers";

const SCOPE = { agentId: LANE.agentId, workspaceId: LANE.workspaceId };
const ctx = () => newSanitizeContext(LANE, { allowedSessionEvents: ALLOWED_SESSION_EVENTS, maxTimelineLimit: 1000 });
const fieldRows = readFieldPolicy();
const classification = readClassification();

test("every field of every forwarded message and gateway-built object is reviewed (field conformance gate)", () => {
  const r = fieldCoverage(fieldRows, classification);
  assert.deepEqual(r, { unclassified: [], stale: [], duplicates: [], missingObjects: [], missingNested: [] });
});

test("the field gate fails on an unreviewed field, a stale field and a missing message table", () => {
  const withoutCwd = fieldRows.filter((r) => !(r.object === "AgentSnapshot" && r.field === "cwd"));
  assert.deepEqual(fieldCoverage(withoutCwd, classification).unclassified, ["AgentSnapshot#cwd"]);
  const stale = [...fieldRows, { object: "AgentSnapshot", field: "noSuchField", action: "keep" as const, reason: "" }];
  assert.deepEqual(fieldCoverage(stale, classification).stale, ["AgentSnapshot#noSuchField"]);
  const noTable = fieldRows.filter((r) => r.object !== "out:agent_status");
  assert.deepEqual(fieldCoverage(noTable, classification).missingObjects, ["out:agent_status"]);
  const noNested = fieldRows.filter((r) => r.object !== "AgentSnapshot.runtimeInfo");
  assert.deepEqual(fieldCoverage(noNested, classification).missingNested, ["AgentSnapshot.runtimeInfo"]);
});

test("every redact/gateway field has exactly one handler", () => {
  assert.deepEqual(Object.keys(REDACTORS).sort(), fieldsNeedingHandlers());
});

test("hello capabilities: every CLIENT_CAPS name is reviewed", () => {
  for (const cap of Object.values(CLIENT_CAPS)) assert.ok(FIELD_POLICY["hello.capabilities"][cap], `unreviewed capability ${cap}`);
  assert.ok(protocolFields("hello.capabilities").includes("pushNotifications"));
});

test("B1: upstream hello is built from scratch; modern mode forced; viewer fields never spread", () => {
  const tmp = tempDir();
  try {
    const viewer = {
      type: "hello",
      clientId: "viewer-chosen-id",
      clientType: "mobile",
      protocolVersion: 1,
      appVersion: "0.13.2",
      routed: true,
      producer: { serverId: "srv_x", sourceId: "y" },
      sessionPermissions: ["workspace.write", "hub.execute"],
      auth: { kind: "password", password: "prg1.viewer.grant" },
      capabilities: { voice: true, pushNotifications: true, browser_host: { enabled: true }, reasoning_merge_enum: true, timeline_notifications: "yes", zzz_future: true },
      extraTopLevel: "FUTURE",
    };
    const up = buildUpstreamHello(tmp.dir, viewer, "rooms-lane-x-watch-abc");
    assert.deepEqual(Object.keys(up).sort(), ["appVersion", "capabilities", "clientId", "clientType", "protocolVersion", "sessionPermissions", "type"].sort());
    assert.equal(up.clientId, "rooms-lane-x-watch-abc");
    assert.equal(up.clientType, "browser");
    assert.deepEqual(up.sessionPermissions, ["workspace.read"]);
    const caps = up.capabilities as Record<string, boolean>;
    for (const forced of ["owned_subscriptions", "explicit_event_subscriptions", "selective_agent_timeline", "hello_rejection"]) assert.equal(caps[forced], true, forced);
    assert.equal(caps.reasoning_merge_enum, true);
    for (const dropped of ["voice", "pushNotifications", "browser_host", "zzz_future", "timeline_notifications"]) assert.equal(dropped in caps, false, dropped);
    // A viewer that omits the modern flags (legacy mode) still gets them upstream.
    const legacy = buildUpstreamHello(tmp.dir, { type: "hello", clientId: "x", clientType: "cli", protocolVersion: 99, appVersion: "1.0.0; drop table" }, "id");
    assert.equal((legacy.capabilities as any).selective_agent_timeline, true);
    assert.equal(legacy.protocolVersion, 1);
    assert.equal("appVersion" in legacy, false);
  } finally {
    tmp.cleanup();
  }
});

test("B2: agent snapshot in every outbound carrier leaks no path, prompt, session id, parent or owner label", () => {
  const fwd = new Map([
    ["q1", "fetch_agent_request"],
    ["q2", "fetch_agent_timeline_request"],
  ]);
  const c = ctx();
  const carriers = [
    filterOutbound({ type: "fetch_agent_response", payload: { requestId: "q1", agent: agentSnapshot(), project: projectPlacement(), error: null } }, SCOPE, fwd, c),
    filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), project: projectPlacement(), generation: "gen-1", seq: 4242 } }, SCOPE, fwd, c),
    filterOutbound({ type: "agent_status", payload: { agentId: LANE.agentId, status: "idle", info: agentSnapshot() } }, SCOPE, fwd, c),
    filterOutbound({ type: "fetch_agent_timeline_response", payload: { requestId: "q2", agentId: LANE.agentId, agent: agentSnapshot(), entries: [], error: "SECRET /home/owner" } }, SCOPE, fwd, c),
  ];
  for (const out of carriers) {
    assert.ok(out, "carrier must pass");
    assert.deepEqual(leaks(out), [], JSON.stringify(out).slice(0, 400));
  }
  const agent = carriers[0]!.payload.agent;
  assert.equal(agent.persistence, null);
  // Project names are hidden by default: the folder basename is a keyed hash (see viewer-policy.test.ts).
  assert.match(agent.cwd, /^\/room\/folder-[a-f0-9]{10}$/);
  assert.deepEqual(agent.labels, { "rooms.lane": LANE.laneId, "rooms.room": "room_0123456789abcdef" });
  assert.equal(agent.runtimeInfo.sessionId, null);
  assert.equal("extra" in agent.runtimeInfo, false);
  assert.equal("futureField" in agent, false);
  assert.equal(carriers[0]!.payload.project.projectKey, `room:${LANE.laneId}`);
  assert.equal(carriers[0]!.payload.project.checkout.remoteUrl, null);
  // Watch content and rendering fields survive.
  assert.equal(agent.title, "Room fork");
  assert.equal(agent.model, "claude-haiku-4-5");
  assert.deepEqual(agent.availableModes, [{ id: "default", label: "Default" }]);
});

test("B2: workspace descriptor leaks no path, remote, PR, script port, proxy URL or aggregate; status comes from the lane agent", () => {
  const c = ctx();
  // The lane agent is idle while the parent (same workspace) is running.
  filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot({ status: "idle" }) } }, SCOPE, new Map(), c);
  const upd = filterOutbound({ type: "workspace_update", payload: { kind: "upsert", workspace: workspaceDescriptor(), generation: "gen-1", seq: 77, emptyProject: { id: "OTHER-SECRET" }, removedProjectId: "prj-SECRET" } }, SCOPE, new Map(), c);
  assert.ok(upd);
  assert.deepEqual(leaks(upd), [], JSON.stringify(upd).slice(0, 400));
  const w = upd!.payload.workspace;
  assert.equal(w.status, "done", "workspace status must be derived from the idle lane agent, not the running parent");
  assert.deepEqual(w.scripts, []);
  assert.equal(w.githubRuntime, null);
  assert.equal(w.diffStat, null);
  assert.deepEqual(w.gitRuntime, { currentBranch: "main", isPaseoOwnedWorktree: false });
  assert.equal(w.projectRootPath, w.workspaceDirectory, "equal paths stay equal after redaction");
  assert.match(w.projectRootPath, /^\/room\/folder-[a-f0-9]{10}$/);
  assert.equal(w.activityAt, "2026-10-28T10:05:00.000Z");
  assert.equal("pinnedAt" in w || "labels" in w || "futureWorkspaceField" in w || "projectCustomIconRevision" in w, false);
  const wsList = filterOutbound(
    { type: "fetch_workspaces_response", payload: { requestId: "q", entries: [workspaceDescriptor(), workspaceDescriptor({ id: "wks_other" })], emptyProjects: [{ id: "x" }], pageInfo: { hasMore: true, nextCursor: "c" }, sync: { generation: "g", headSeq: 9999, mode: "changes", removals: [{ id: "wks_other", seq: 3 }] } } },
    SCOPE,
    new Map([["q", "fetch_workspaces_request"]]),
    c,
  );
  assert.equal(wsList!.payload.entries.length, 1);
  assert.deepEqual(leaks(wsList), []);
  assert.equal(wsList!.payload.sync.headSeq < 9999, true, "headSeq is rebased per route");
  assert.deepEqual(wsList!.payload.sync.removals, []);
});

test("B2: gateway-built entries are sanitised", () => {
  const c = ctx();
  const entry = sanitizeAgentListEntry({ agent: agentSnapshot(), project: projectPlacement(), syncSeq: 5555, searchScore: 1, searchMatches: ["SECRET"] }, c);
  assert.deepEqual(leaks(entry), []);
  const w = sanitizeWorkspace(workspaceDescriptor(), c);
  assert.deepEqual(leaks(w), []);
});

test("C-6: owner serverId never leaves in attention notifications (pushed and legacy stream)", () => {
  const c = ctx();
  const notification = { title: "Done", body: "Room fork finished", data: { serverId: "srv_owner_SECRET", workspaceId: LANE.workspaceId, agentId: LANE.agentId, reason: "finished" } };
  const a = filterOutbound({ type: "agent_attention_required", payload: { agentId: LANE.agentId, reason: "finished", timestamp: "t", shouldNotify: true, notification } }, SCOPE, new Map(), c);
  assert.equal(a!.payload.notification.data.serverId, LANE.laneServerId);
  const s = filterOutbound({ type: "agent_stream", payload: { agentId: LANE.agentId, event: { type: "attention_required", provider: "claude", reason: "finished", timestamp: "t", shouldNotify: true, notification }, timestamp: "t" } }, SCOPE, new Map(), c);
  assert.equal(s!.payload.event.notification.data.serverId, LANE.laneServerId);
  assert.deepEqual(leaks([a, s]), []);
  // Ordinary timeline content (watch content) passes untouched.
  const item = { type: "timeline", provider: "claude", item: { type: "assistant_message", text: "hello" } };
  assert.deepEqual(filterOutbound({ type: "agent_stream", payload: { agentId: LANE.agentId, event: item, timestamp: "t", seq: 3, epoch: "e" } }, SCOPE, new Map(), c)!.payload.event, item);
});

test("C-16: forwarded error text is generic", () => {
  const out = filterOutbound(
    { type: "rpc_error", payload: { requestId: "q", requestType: "fetch_agent_request", error: "EACCES: /home/owner/secret-project SECRET", code: "internal error!" } },
    SCOPE,
    new Map([["q", "fetch_agent_request"]]),
  );
  assert.deepEqual(leaks(out), []);
  assert.equal("code" in out!.payload, false);
});

test("P-26: sequence numbers and generations are rebased per route", () => {
  const c = ctx();
  const fwd = new Map([["q", "fetch_agents_request"]]);
  const list = filterOutbound({ type: "fetch_agents_response", payload: { requestId: "q", entries: [{ agent: agentSnapshot(), syncSeq: 900 }], sync: { generation: "daemon-gen", headSeq: 901, mode: "snapshot", removals: [] } } }, SCOPE, fwd, c)!;
  const head = list.payload.sync.headSeq;
  assert.ok(head >= 1 && head < 900);
  const u1 = filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), generation: "daemon-gen", seq: 950 } }, SCOPE, fwd, c)!;
  const u2 = filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), generation: "daemon-gen", seq: 999 } }, SCOPE, fwd, c)!;
  assert.equal(u1.payload.seq, head + 1);
  assert.equal(u2.payload.seq, head + 2);
  assert.equal(u1.payload.generation, list.payload.sync.generation);
  assert.notEqual(u1.payload.generation, "daemon-gen");
  const other = ctx();
  const u3 = filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), generation: "daemon-gen", seq: 950 } }, SCOPE, fwd, other)!;
  assert.notEqual(u3.payload.generation, u1.payload.generation, "generations differ per route");
});

test("P-18: allowed inbound messages are rebuilt from their field table", () => {
  const c = ctx();
  const tl = decideInbound(
    { type: "fetch_agent_timeline_request", requestId: "r", agentId: LANE.agentId, direction: "tail", limit: 0, includeChildren: true, workspaceId: "wks_other", subagentId: "x" },
    SCOPE,
    c,
  );
  assert.equal(tl.action, "forward");
  if (tl.action === "forward") {
    assert.deepEqual(Object.keys(tl.message).sort(), ["agentId", "direction", "limit", "requestId", "type"]);
    assert.equal(tl.message.limit, 1000, "limit 0 (all rows) is clamped");
  }
  const big = decideInbound({ type: "fetch_agent_timeline_request", requestId: "r", agentId: LANE.agentId, limit: 1e9 }, SCOPE, c);
  assert.equal(big.action === "forward" && big.message.limit, 1000);
  const list = decideInbound(
    { type: "fetch_agents_request", requestId: "r", filter: { includeInternal: true, includeBackground: true, labels: { a: "b" }, future: 1 }, includeBackground: true, sync: { generation: "g", afterSeq: 3 }, subscribe: { subscriptionId: "s", future: 1 }, page: { limit: 5, cursor: "c" } },
    SCOPE,
    c,
  );
  assert.equal(list.action, "forward");
  if (list.action === "forward") {
    assert.deepEqual(list.message.filter, { labels: { a: "b" } });
    assert.deepEqual(list.message.subscribe, { subscriptionId: "s" });
    assert.equal("sync" in list.message || "includeBackground" in list.message, false);
  }
  const ws = decideInbound({ type: "fetch_workspaces_request", requestId: "r", filter: { idPrefix: "wks_o", query: "x" } }, SCOPE, c);
  assert.equal(ws.action === "forward" && JSON.stringify(ws.message.filter), JSON.stringify({ query: "x" }));
  const sub = decideInbound({ type: "session.events.set_subscription.request", requestId: "r", events: ["agent_permission_request", "project.update"], notifications: true, future: 1 }, SCOPE, c);
  assert.equal(sub.action, "forward");
  if (sub.action === "forward") assert.deepEqual(sub.message, { type: "session.events.set_subscription.request", requestId: "r", events: ["agent_permission_request"], notifications: false });
});

test("isolation guard: prompting types are denied on owner-uid lanes and a profile that allows one refuses to start", () => {
  for (const t of ["send_agent_message_request", "agent_permission_response", "cancel_agent_request", "abort_request"]) {
    const d = decideInbound({ type: t, requestId: "r", agentId: LANE.agentId }, SCOPE);
    assert.equal(d.action, "deny", t);
    if (d.action === "deny") assert.equal(d.reason, "owner_uid_lane_not_promptable");
  }
  assert.doesNotThrow(() => assertOwnerUidLaneIsWatchOnly());
  assert.throws(() => assertOwnerUidLaneIsWatchOnly({ ...INBOUND_WATCH, send_agent_message_request: "forward" }), /sandboxed lanes/);
});

test("outbound for another agent is still dropped after field rebuilding", () => {
  const c = ctx();
  assert.equal(filterOutbound({ type: "agent_status", payload: { agentId: LANE.agentId, status: "idle", info: agentSnapshot({ id: OTHER_AGENT }) } }, SCOPE, new Map(), c), null);
  assert.equal(filterOutbound({ type: "fetch_agent_timeline_response", payload: { requestId: "q", agentId: LANE.agentId, agent: agentSnapshot({ id: OTHER_AGENT }) } }, SCOPE, new Map([["q", "fetch_agent_timeline_request"]]), c), null);
});

test("sanitised outbound messages still parse with the installed protocol schema (the app must accept them)", () => {
  const S = (messages as any).SessionOutboundMessageSchema;
  const c = ctx();
  const fwd = new Map([
    ["q1", "fetch_agent_request"],
    ["q2", "fetch_workspaces_request"],
    ["q3", "fetch_agents_request"],
    ["q4", "fetch_agent_timeline_request"],
  ]);
  const page = { nextCursor: null, prevCursor: null, hasMore: false };
  const sync = { generation: "g", headSeq: 5, mode: "snapshot", removals: [] };
  const msgs: any[] = [
    { type: "fetch_agent_response", payload: { requestId: "q1", agent: agentSnapshot(), project: projectPlacement(), error: null } },
    { type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), project: projectPlacement(), generation: "g", seq: 4 } },
    { type: "agent_status", payload: { agentId: LANE.agentId, status: "idle", info: agentSnapshot() } },
    { type: "workspace_update", payload: { kind: "upsert", workspace: workspaceDescriptor(), generation: "g", seq: 4 } },
    { type: "fetch_workspaces_response", payload: { requestId: "q2", entries: [workspaceDescriptor()], emptyProjects: [], pageInfo: page, sync } },
    { type: "fetch_agents_response", payload: { requestId: "q3", entries: [{ agent: agentSnapshot(), project: projectPlacement(), syncSeq: 3 }], pageInfo: page, sync } },
    { type: "agent_attention_required", payload: { agentId: LANE.agentId, reason: "finished", timestamp: "t", shouldNotify: true, notification: { title: "a", body: "b", data: { serverId: "s", workspaceId: "w", agentId: LANE.agentId, reason: "finished" } } } },
    { type: "rpc_error", payload: { requestId: "q1", requestType: "fetch_agent_request", error: "/home/owner SECRET", code: "internal" } },
  ];
  for (const m of msgs) {
    assert.equal(S.safeParse(m).success, true, `fixture ${m.type} must be valid upstream`);
    const out = filterOutbound(m, SCOPE, fwd, c);
    const parsed = S.safeParse(out);
    assert.equal(parsed.success, true, `${m.type}: ${parsed.success ? "" : JSON.stringify(parsed.error.issues.slice(0, 3))}`);
  }
});
