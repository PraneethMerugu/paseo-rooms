// hardening plan decisions round 2: viewer errors and project display names.
//  - Viewers get generic error text; the full text goes to the owner-only LaneErrorLog, read through
//    the local RPC rooms.v2.lane.errors and never through the lane endpoint.
//  - Project names are hidden from viewers by default (neutral label, hashed folder names); with the
//    owner's opt-in (identity v2: policy projectNames "lane-owner" and the lane's lane.names.changed,
//    tested in v2-grants) the shared policy object flips open routes.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import * as messages from "@getpaseo/protocol/messages";
import { LaneEndpoint, LinkSession, LaneConnection } from "../../server/gateway/lane-endpoint";
import { LaneErrorLog } from "../../server/gateway/lane-errors";
import { ALLOWED_SESSION_EVENTS, decideInbound, filterOutbound } from "../../server/room-profile/filter";
import { GENERIC_AGENT_ERROR, GENERIC_ERROR, neutralProjectLabel, newSanitizeContext, sanitizeAgentListEntry, sanitizeWorkspace } from "../../server/room-profile/sanitize";
import { agentSnapshot, LANE, leaks, projectPlacement, workspaceDescriptor } from "./fixtures";
import { startFakeDaemon, waitFor, type FakeDaemon } from "./fake-daemon";
import { tempDir } from "./helpers";
import { TestAuthority, testLane } from "./lane-harness";

const SCOPE = { agentId: LANE.agentId, workspaceId: LANE.workspaceId };
const LABEL = "Lab · Live";
const PROJECT = "secret-project";

function ctx(show = false) {
  const errors = new LaneErrorLog();
  const c = newSanitizeContext(LANE, { allowedSessionEvents: ALLOWED_SESSION_EVENTS, projectNames: { show, label: LABEL }, errors });
  return { c, errors };
}

/** Every outbound carrier of a project name, through the sanitiser of one route context. */
function carriers(c: ReturnType<typeof ctx>["c"]) {
  const fwd = new Map([
    ["q1", "fetch_agent_request"],
    ["q2", "fetch_workspaces_request"],
    ["q3", "fetch_agents_request"],
  ]);
  const ws = workspaceDescriptor({ name: PROJECT, title: "Secret-Project" });
  return [
    filterOutbound({ type: "fetch_agent_response", payload: { requestId: "q1", agent: agentSnapshot(), project: projectPlacement(), error: null } }, SCOPE, fwd, c),
    filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot(), project: { ...projectPlacement(), workspaceName: PROJECT } } }, SCOPE, fwd, c),
    filterOutbound({ type: "workspace_update", payload: { kind: "upsert", workspace: ws } }, SCOPE, fwd, c),
    filterOutbound({ type: "fetch_workspaces_response", payload: { requestId: "q2", entries: [ws], emptyProjects: [], pageInfo: { nextCursor: null, prevCursor: null, hasMore: false } } }, SCOPE, fwd, c),
    filterOutbound({ type: "fetch_agents_response", payload: { requestId: "q3", entries: [{ agent: agentSnapshot(), project: projectPlacement() }], pageInfo: { nextCursor: null, prevCursor: null, hasMore: false } } }, SCOPE, fwd, c),
    sanitizeAgentListEntry({ agent: agentSnapshot(), project: projectPlacement() }, c),
    sanitizeWorkspace(ws, c),
  ];
}

// ------------------------------------------------------------------ project names

test("project names: hidden by default in every carrier (neutral label, hashed folders, matching workspace names)", () => {
  const { c } = ctx();
  const out = carriers(c);
  for (const o of out) {
    assert.ok(o, "carrier must pass");
    assert.equal(JSON.stringify(o).toLowerCase().includes(PROJECT), false, JSON.stringify(o).slice(0, 300));
    assert.deepEqual(leaks(o), []);
  }
  const [agentRes, agentUpd, wsUpd] = out as any[];
  assert.equal(agentRes.payload.project.projectName, LABEL);
  assert.equal(agentRes.payload.project.workspaceName, "main", "a workspace name that is not the project name is kept");
  assert.equal(agentUpd.payload.project.workspaceName, LABEL);
  assert.match(agentRes.payload.agent.cwd, /^\/room\/folder-[a-f0-9]{10}$/);
  assert.equal(agentRes.payload.agent.cwd, agentRes.payload.project.checkout.cwd, "equal paths stay equal");
  const w = wsUpd.payload.workspace;
  assert.equal(w.projectDisplayName, LABEL);
  assert.equal(w.projectCustomName, null, "a null custom name stays null");
  assert.equal(w.name, LABEL);
  assert.equal(w.title, LABEL, "matching is case-insensitive");
  assert.equal(w.project.projectName, LABEL);
  // owner/repo display names are matched on their last segment too.
  const repo = sanitizeWorkspace(workspaceDescriptor({ projectDisplayName: "acme/widget", name: "widget" }), c) as any;
  assert.equal(repo.projectDisplayName, LABEL);
  assert.equal(repo.name, LABEL);
});

test("project names: with the owner's opt-in the viewer sees them, and the shared policy flips an existing route", () => {
  const { c } = ctx(false);
  const hidden = carriers(c)[2] as any;
  assert.equal(hidden.payload.workspace.projectDisplayName, LABEL);
  c.projectNames.show = true; // what LaneEndpoint.setProjectNamesVisible does to the shared object
  const [agentRes, , wsUpd] = carriers(c) as any[];
  assert.equal(agentRes.payload.project.projectName, PROJECT);
  assert.equal(agentRes.payload.agent.cwd, `/room/${PROJECT}`);
  assert.equal(wsUpd.payload.workspace.projectDisplayName, PROJECT);
  assert.equal(wsUpd.payload.workspace.name, PROJECT);
  // Opt-in reveals names only: paths stay basenames and the other redactions still hold.
  assert.deepEqual(leaks(carriers(c)), []);
});

test("project names: the neutral label is the room and lane name, bounded", () => {
  assert.equal(neutralProjectLabel("Lab", "Live"), "Lab · Live");
  assert.equal(neutralProjectLabel(undefined, " "), "Shared lane");
  assert.ok(neutralProjectLabel("x".repeat(80), "y".repeat(80)).length <= 120);
});

test("project names: the endpoint's policy object is shared by its routes and flips with setProjectNamesVisible", () => {
  const lane = testLane({ label: "Live" });
  const ep = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: "/nonexistent" });
  assert.deepEqual(ep.projectNames, { show: false, label: "Live" }, "hidden by default");
  assert.equal(ep.sanitizeContext().projectNames, ep.projectNames, "routes share the endpoint's policy object");
  assert.equal(ep.setProjectNamesVisible(true), 0, "no open route to push to");
  assert.equal(ep.projectNames.show, true);
  assert.equal(ep.setProjectNamesVisible(true), 0, "no-op");
  ep.setProjectNamesVisible(false);
  assert.equal(ep.projectNames.show, false);
  const shown = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: "/nonexistent", projectNames: { show: true, label: "Lab · Live" } });
  assert.equal(shown.projectNames.show, true, "new endpoints start with the lane's effective policy");
});

// ------------------------------------------------------------------ errors

test("errors: viewers get generic text in every carrier; the owner's lane log keeps the full text", () => {
  const { c, errors } = ctx();
  const detail = "ENOENT: /home/owner/secret-project/.env SECRET";
  const fwd = new Map([
    ["q1", "fetch_agent_request"],
    ["q2", "fetch_agent_timeline_request"],
    ["q3", "fetch_agent_request"],
  ]);
  const out = [
    filterOutbound({ type: "rpc_error", payload: { requestId: "q1", requestType: "fetch_agent_request", error: `rpc ${detail}`, code: "internal" } }, SCOPE, fwd, c),
    filterOutbound({ type: "agent_update", payload: { kind: "upsert", agent: agentSnapshot({ lastError: `last ${detail}` }) } }, SCOPE, fwd, c),
    filterOutbound({ type: "fetch_agent_response", payload: { requestId: "q3", agent: null, project: null, error: `fetch ${detail}` } }, SCOPE, fwd, c),
    filterOutbound(
      {
        type: "fetch_agent_timeline_response",
        payload: { requestId: "q2", agentId: LANE.agentId, entries: [{ seq: 1, item: { type: "error", message: `item ${detail}` } }, { seq: 2, item: { type: "assistant_message", text: "hello" } }], error: `tl ${detail}` },
      },
      SCOPE,
      fwd,
      c,
    ),
    filterOutbound({ type: "agent_stream", payload: { agentId: LANE.agentId, event: { type: "turn_failed", provider: "claude", error: `turn ${detail}`, diagnostic: `diag ${detail}`, code: "provider_error" }, timestamp: "t" } }, SCOPE, fwd, c),
    filterOutbound({ type: "agent_stream", payload: { agentId: LANE.agentId, event: { type: "timeline", provider: "claude", item: { type: "error", message: `live ${detail}` } }, timestamp: "t" } }, SCOPE, fwd, c),
  ];
  for (const o of out) {
    assert.ok(o);
    assert.deepEqual(leaks(o), [], JSON.stringify(o).slice(0, 300));
    assert.equal(JSON.stringify(o).includes("ENOENT"), false);
  }
  assert.equal((out[0] as any).payload.error, GENERIC_ERROR);
  assert.equal((out[1] as any).payload.agent.lastError, GENERIC_AGENT_ERROR);
  assert.equal((out[3] as any).payload.entries[0].item.message, GENERIC_AGENT_ERROR);
  assert.equal((out[3] as any).payload.entries[1].item.text, "hello", "other timeline content passes");
  const turn = (out[4] as any).payload.event;
  assert.equal(turn.error, GENERIC_AGENT_ERROR);
  assert.equal("diagnostic" in turn, false);
  assert.equal(turn.code, "provider_error");
  // The owner's log has every original text, with its source.
  const list = errors.list();
  // list() is newest first; keep the newest message per source.
  const bySource = Object.fromEntries([...list].reverse().map((e) => [e.source, e.message]));
  assert.equal(bySource["rpc_error:fetch_agent_request"], `rpc ${detail}`);
  assert.equal(bySource["agent.lastError"], `last ${detail}`);
  assert.equal(bySource["fetch_agent_response.error"], `fetch ${detail}`);
  assert.equal(bySource["fetch_agent_timeline_response.error"], `tl ${detail}`);
  assert.equal(bySource["agent.timeline_error"], `live ${detail}`, "newest text per source comes first");
  assert.ok(list.some((e) => e.source === "agent.timeline_error" && e.message === `item ${detail}`));
  assert.equal(bySource["agent.turn_failed"], `turn ${detail}\n\ndiag ${detail}`);
  // Sanitised error carriers still parse with the protocol schema.
  const S = (messages as any).SessionOutboundMessageSchema;
  for (const o of [out[0], out[1], out[4], out[5]]) assert.equal(S.safeParse(o).success, true, (o as any).type);
});

test("errors: the lane log deduplicates repeats, is bounded and clips long text", () => {
  let now = 0;
  const log = new LaneErrorLog(3, 10, () => (now += 1000));
  log.record("a", "same");
  log.record("a", "same");
  assert.equal(log.list().length, 1);
  assert.equal(log.list()[0].count, 2);
  assert.notEqual(log.list()[0].firstAt, log.list()[0].lastAt);
  for (const m of ["1", "2", "3"]) log.record("b", m);
  assert.deepEqual(log.list().map((e) => e.message), ["3", "2", "1"], "newest first, oldest evicted");
  log.record("c", "x".repeat(50));
  assert.equal(log.list()[0].message, `${"x".repeat(10)}…`);
  log.record("c", "");
  assert.equal(log.list().length, 3);
});

test("errors: plugin RPCs (rooms.v2.lane.errors) are not reachable through a lane", () => {
  const d = decideInbound({ type: "plugin.rpc.invoke.request", requestId: "r", pluginId: "rooms", method: "rooms.v2.lane.errors", input: { laneId: LANE.laneId } }, SCOPE);
  assert.equal(d.action, "deny");
});

// ------------------------------------------------------------------ through a real route (fake daemon)

let fake: FakeDaemon;
const realStart = LaneConnection.prototype.start;
before(async () => {
  fake = await startFakeDaemon();
  LaneConnection.prototype.start = function () {};
});
after(async () => {
  LaneConnection.prototype.start = realStart;
  await fake.close();
});

async function openViewer(ep: LaneEndpoint, token: string) {
  const conn = new LaneConnection(ep, "c1");
  const sent: any[] = [];
  conn.send = (f: unknown) => void sent.push(f);
  ep.connections.set("c1", conn);
  (conn as any).mode = "link";
  conn.link = new LinkSession(conn);
  await conn.link.onHello({ type: "hello", clientType: "cli", auth: { kind: "password", password: token } });
  const l = conn.link;
  l.onFrame({ type: "session", message: { type: "hosts.link.open.request", requestId: "o", channelId: "ch" } });
  const routeId = sent.find((f) => f?.message?.type === "hosts.link.open.response")!.message.payload.routeId as string;
  const frame = (msg: unknown) => l.onFrame({ type: "session", message: { type: "hosts.route.frame.request", routeId, data: JSON.stringify(msg) } });
  frame({ type: "hello", clientId: "v", clientType: "browser", protocolVersion: 1 });
  const vs = l.channels.get(routeId) as any;
  await waitFor(() => vs.upstreamReady === true, 3000, "upstream ready");
  /** Session messages the viewer received on this route. */
  const viewer = () =>
    sent
      .filter((f) => f?.message?.type === "hosts.route.frame" && f.message.payload.subscriptionId === routeId)
      .map((f) => JSON.parse(f.message.payload.data))
      .filter((m) => m.type === "session")
      .map((m) => m.message);
  return { frame, viewer, sent };
}

test("route: a viewer never receives full errors or the hidden project name; the owner RPC data has them; opt-in pushes to the open route", async () => {
  const tmp = tempDir();
  const agent = () => agentSnapshot({ id: "agent-1", workspaceId: "wks_1", lastError: "EACCES /home/owner/secret-project SECRET" });
  fake.onSession = (m, reply) => {
    if (m.type === "fetch_agent_request" && m.requestId === "boom")
      reply({ type: "rpc_error", payload: { requestId: m.requestId, requestType: m.type, error: "daemon exploded at /home/owner/secret-project SECRET", code: "internal" } });
    else if (m.type === "fetch_agent_request") reply({ type: "fetch_agent_response", payload: { requestId: m.requestId, agent: agent(), project: projectPlacement(), error: null } });
    else if (m.type === "fetch_workspaces_request")
      reply({
        type: "fetch_workspaces_response",
        payload: { requestId: m.requestId, entries: [workspaceDescriptor({ id: "wks_1" })], emptyProjects: [], pageInfo: { nextCursor: null, prevCursor: null, hasMore: false } },
      });
  };
  const host = new TestAuthority();
  const lane = testLane({ label: "Live" });
  const ep = new LaneEndpoint(lane, { authority: host, paseoHome: fake.home, projectNames: { show: false, label: "Lab · Live" } });
  try {
    const { token } = host.enroll(lane.id);
    const v = await openViewer(ep, token);
    v.frame({ type: "session", message: { type: "fetch_agent_request", requestId: "boom", agentId: "agent-1" } });
    v.frame({ type: "session", message: { type: "fetch_agent_request", requestId: "ok", agentId: "agent-1" } });
    await waitFor(() => v.viewer().filter((m) => m.type === "rpc_error" || m.type === "fetch_agent_response").length >= 2, 3000, "responses");
    const seen = JSON.stringify(v.sent);
    for (const s of ["exploded", "EACCES", "/home/owner", PROJECT]) assert.equal(seen.includes(s), false, `viewer path carried ${s}`);
    assert.equal(v.viewer().find((m) => m.type === "rpc_error").payload.error, GENERIC_ERROR);
    const res = v.viewer().find((m) => m.type === "fetch_agent_response");
    assert.equal(res.payload.project.projectName, "Lab · Live");
    // The owner's RPC data (rooms.v2.lane.errors -> LaneService.errors -> the endpoint's log) has the full text.
    const errs = ep.errors.list();
    assert.ok(errs.some((e) => e.source === "rpc_error:fetch_agent_request" && e.message.includes("daemon exploded at /home/owner/secret-project")));
    assert.ok(errs.some((e) => e.source === "agent.lastError" && e.message.includes("EACCES")));
    // Owner opts in: the open route gets fresh upserts with the real name, without reconnecting.
    const before = v.viewer().length;
    ep.setProjectNamesVisible(true);
    await waitFor(() => v.viewer().slice(before).some((m) => m.type === "workspace_update"), 3000, "pushed upserts");
    const pushed = v.viewer().slice(before);
    const upd = pushed.find((m) => m.type === "agent_update");
    const wsu = pushed.find((m) => m.type === "workspace_update");
    assert.equal(upd.payload.project.projectName, PROJECT);
    assert.equal(wsu.payload.workspace.projectDisplayName, PROJECT);
    assert.equal(upd.payload.agent.lastError, GENERIC_AGENT_ERROR, "errors stay generic with names shown");
    const S = (messages as any).SessionOutboundMessageSchema;
    for (const m of [upd, wsu]) assert.equal(S.safeParse(m).success, true, m.type);
    assert.deepEqual(leaks(pushed), []);
  } finally {
    fake.onSession = () => undefined;
    await ep.stop();
    tmp.cleanup();
  }
});
