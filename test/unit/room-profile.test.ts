// Room Profile conformance: classification coverage, generated module freshness, and a
// default-deny fuzz over every protocol type (no bypass, no leak).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { coverage, GENERATED_PATH, protocolTypes, readClassification, renderGenerated } from "../../tools/room-profile-lib";
import { INBOUND_WATCH, OUTBOUND_WATCH, ROOM_PROFILE_PROTOCOL_VERSION } from "../../server/room-profile/generated";
import {
  ALLOWED_SESSION_EVENTS,
  decideInbound,
  filterOutbound,
  IMPLEMENTED_INBOUND,
  IMPLEMENTED_OUTBOUND,
  KEPT_FEATURES,
  linkServerInfo,
  rewriteServerInfo,
} from "../../server/room-profile/filter";

const LANE = { agentId: "a1b2c3d4-1111-4111-8111-abcdefabcdef", workspaceId: "wks_lane" };
const OTHER = "22222222-2222-4222-8222-222222222222";
const types = protocolTypes();
const rows = readClassification();

test("every protocol type is classified (conformance gate)", () => {
  const r = coverage(rows, types);
  assert.deepEqual(r.unclassified, { inbound: [], outbound: [] }, "unclassified protocol types");
  assert.deepEqual(r.stale, { inbound: [], outbound: [] }, "classification rows for types not in the protocol");
  assert.deepEqual(r.duplicates, []);
  assert.equal(types.version, ROOM_PROFILE_PROTOCOL_VERSION);
});

test("the conformance gate fails when a type is missing", () => {
  const dropped = rows.filter((r) => r.type !== "fetch_agent_request");
  assert.deepEqual(coverage(dropped, types).unclassified.inbound, ["fetch_agent_request"]);
});

test("generated module matches the checked-in classification", () => {
  assert.equal(readFileSync(GENERATED_PATH, "utf8").replace(/\r\n/g, "\n"), renderGenerated(rows, types.version), "run `npm run gen:profile`");
  assert.equal(Object.keys(INBOUND_WATCH).length, types.inbound.length);
  assert.equal(Object.keys(OUTBOUND_WATCH).length, types.outbound.length);
});

test("allowed types in the table are exactly the types with a binding", () => {
  const allowed = (t: Record<string, string>) => Object.keys(t).filter((k) => t[k] !== "deny").sort();
  assert.deepEqual(allowed(INBOUND_WATCH), IMPLEMENTED_INBOUND);
  assert.deepEqual(allowed(OUTBOUND_WATCH), IMPLEMENTED_OUTBOUND);
});

test("inbound: every type with foreign ids is denied with the requestId echoed", () => {
  const idFree = new Set(["fetch_workspaces_request", "fetch_agents_request", "session.events.set_subscription.request", "subscription.release.request"]);
  for (const t of types.inbound) {
    const foreign = { type: t, requestId: "r1", agentId: OTHER, agentIds: [OTHER], workspaceId: "wks_other", cwd: "/", terminalId: "t1", parentAgentId: OTHER };
    const d = decideInbound(foreign, LANE);
    if (idFree.has(t)) assert.equal(d.action, "forward", t);
    else {
      assert.equal(d.action, "deny", `${t} must be denied with foreign ids`);
      if (d.action === "deny") assert.equal(d.requestId, "r1", `${t} must echo requestId`);
    }
  }
});

test("inbound: with lane ids, only the implemented set is forwarded", () => {
  const forwarded: string[] = [];
  for (const t of types.inbound) {
    const own = { type: t, requestId: "r1", agentId: LANE.agentId, agentIds: [LANE.agentId], workspaceId: LANE.workspaceId, cwd: "/", parentAgentId: LANE.agentId };
    if (decideInbound(own, LANE).action === "forward") forwarded.push(t);
  }
  assert.deepEqual(forwarded.sort(), IMPLEMENTED_INBOUND);
});

test("inbound: exact-id binding (prefix, title, empty and mixed lists denied)", () => {
  for (const agentId of [LANE.agentId.slice(0, 8), "Lane agent title", LANE.agentId.toUpperCase(), ` ${LANE.agentId}`, ""]) {
    assert.equal(decideInbound({ type: "fetch_agent_request", requestId: "r", agentId }, LANE).action, "deny", agentId);
    assert.equal(decideInbound({ type: "fetch_agent_timeline_request", requestId: "r", agentId }, LANE).action, "deny", agentId);
  }
  for (const agentIds of [[], [LANE.agentId, OTHER], "x", null]) {
    assert.equal(decideInbound({ type: "agent.timeline.set_subscription.request", requestId: "r", agentIds }, LANE).action, "deny");
  }
});

test("inbound: hosts.*, plugin RPC, terminals, writes, steer and approve are denied", () => {
  const must = [
    "hosts.list.request", "hosts.add.request", "hosts.link.open.request", "hosts.route.open.request",
    "send_agent_message_request", "cancel_agent_request", "agent_permission_response", "archive_agent_request",
    "create_agent_request", "terminal_input", "create_terminal_request", "get_daemon_config_request", "agent.fork_context.request",
  ];
  for (const t of must) if (types.inbound.includes(t)) assert.equal(decideInbound({ type: t, requestId: "r", agentId: LANE.agentId }, LANE).action, "deny", t);
  const pluginRpc = types.inbound.filter((t) => t.startsWith("plugin"));
  assert.ok(pluginRpc.length > 0);
  for (const t of pluginRpc) assert.equal(decideInbound({ type: t, requestId: "r" }, LANE).action, "deny", t);
});

test("inbound: session events narrowed and notifications forced off", () => {
  const d = decideInbound(
    { type: "session.events.set_subscription.request", requestId: "r", events: ["project.update", "agent_permission_request", "status.daemon_config_changed", 7], notifications: true },
    LANE,
  );
  assert.equal(d.action, "forward");
  if (d.action === "forward") {
    assert.deepEqual(d.message.events, ["agent_permission_request"]);
    assert.equal(d.message.notifications, false);
    for (const e of d.message.events) assert.ok(ALLOWED_SESSION_EVENTS.has(e));
  }
});

test("outbound: every type, unsolicited or about another agent, is dropped", () => {
  const leaked: string[] = [];
  for (const t of types.outbound) {
    const foreign = {
      type: t,
      payload: {
        requestId: "not-forwarded",
        agentId: OTHER,
        kind: "upsert",
        agent: { id: OTHER },
        workspace: { id: "wks_other" },
        id: "wks_other",
        entries: [{ agent: { id: OTHER } }, { id: "wks_other" }],
        status: "server_info",
      },
    };
    if (filterOutbound(foreign, LANE, new Map()) !== null) leaked.push(t);
  }
  assert.deepEqual(leaked, []);
});

test("outbound: pushes about the lane agent pass; removals for other agents do not", () => {
  const fwd = new Map<string, string>();
  for (const t of ["agent_stream", "agent_status", "agent.timeline.replacement", "agent_permission_request", "agent_permission_resolved", "agent_attention_required"])
    assert.ok(filterOutbound({ type: t, payload: { agentId: LANE.agentId } }, LANE, fwd), t);
  assert.ok(filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: { id: LANE.agentId } } }, LANE, fwd));
  assert.equal(filterOutbound({ type: "agent_update", payload: { kind: "remove", agentId: OTHER } }, LANE, fwd), null);
  assert.equal(filterOutbound({ type: "workspace_update", payload: { kind: "remove", id: "wks_other" } }, LANE, fwd), null);
  assert.equal(filterOutbound({ type: "status", payload: { status: "server_info" } }, LANE, fwd), null, "status is rewritten, never passed");
});

test("outbound: responses are scoped and only for forwarded requests", () => {
  const fwd = new Map([
    ["q1", "fetch_agents_request"],
    ["q2", "fetch_workspaces_request"],
    ["q3", "fetch_agent_request"],
  ]);
  const ag = filterOutbound(
    { type: "fetch_agents_response", payload: { requestId: "q1", entries: [{ agent: { id: OTHER } }, { agent: { id: LANE.agentId } }], pageInfo: { hasMore: true }, sync: { removals: [{ id: OTHER }] } } },
    LANE,
    fwd,
  );
  assert.equal(ag?.payload.entries.length, 1);
  assert.equal(ag?.payload.sync.removals.length, 0);
  assert.equal(ag?.payload.pageInfo.hasMore, false);
  const ws = filterOutbound({ type: "fetch_workspaces_response", payload: { requestId: "q2", entries: [{ id: "wks_other" }, { id: LANE.workspaceId }], emptyProjects: [{}] } }, LANE, fwd);
  assert.equal(ws?.payload.entries.length, 1);
  assert.equal(ws?.payload.emptyProjects.length, 0);
  assert.equal(filterOutbound({ type: "fetch_agent_response", payload: { requestId: "q3", agent: { id: OTHER } } }, LANE, fwd), null);
  assert.equal(filterOutbound({ type: "fetch_agents_response", payload: { requestId: "q3", entries: [] } }, LANE, fwd), null, "response type must match request");
  assert.ok(filterOutbound({ type: "rpc_error", payload: { requestId: "q3" } }, LANE, fwd));
  assert.equal(filterOutbound({ type: "rpc_error", payload: { requestId: "zz" } }, LANE, fwd), null);
});

test("server_info advertises only kept data-shape flags plus connectedHosts", () => {
  const all = Object.fromEntries([...KEPT_FEATURES, "terminals", "plugins", "hostMultiplexing", "voice", "hub"].map((k) => [k, true]));
  const si = rewriteServerInfo({ features: all, version: "0.13.2", protocolVersion: 1 }, "lane_x", "h");
  assert.deepEqual(Object.keys(si.features).sort(), [...KEPT_FEATURES, "connectedHosts", "relayProtectedSecurity"].sort());
  assert.deepEqual(si.permissions, ["workspace.read"]);
  assert.equal(si.serverId, "lane_x");
  assert.deepEqual(Object.keys(linkServerInfo("lane_x", "h", "0.13.2").features).sort(), ["connectedHosts", "hostMultiplexing", "relayProtectedSecurity"]);
});

test("malformed inbound frames are denied", () => {
  for (const m of [{}, { type: 5 }, { type: "__proto__", requestId: "r" }, { type: "constructor" }, { type: "toString" }])
    assert.equal(decideInbound(m as any, LANE).action, "deny", JSON.stringify(m));
});
