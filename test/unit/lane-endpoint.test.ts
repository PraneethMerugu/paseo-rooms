// B1 and B3 at the lane endpoint, plus C-13 and the C-iso2 start check. Uses a fake loopback daemon
// (test/unit/fake-daemon.ts); relay sockets are never opened (LaneConnection.start is stubbed).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, test } from "node:test";
import { LaneEndpoint, LinkSession, LaneConnection } from "../../server/gateway/lane-endpoint";
import { DEFAULT_LIMITS, resolveLimits, LIMIT_BOUNDS, type ResourceLimits } from "../../server/limits";
import { startFakeDaemon, waitFor, type FakeDaemon } from "./fake-daemon";
import { tempDir } from "./helpers";
import { TestAuthority, testLane } from "./lane-harness";

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

function setup(limits: Partial<ResourceLimits> = {}) {
  const tmp = tempDir();
  const host = new TestAuthority();
  const lane = testLane();
  const ep = new LaneEndpoint(lane, { authority: host, paseoHome: fake.home, limits: resolveLimits({ ...DEFAULT_LIMITS, ...limits }) });
  return { tmp, host, lane, ep };
}

function enroll(host: TestAuthority, laneId: string) {
  return host.enroll(laneId);
}

async function link(ep: LaneEndpoint, id: string, grant: string) {
  const conn = new LaneConnection(ep, id);
  const sent: any[] = [];
  conn.send = (f: unknown) => void sent.push(f);
  ep.connections.set(id, conn);
  (conn as any).mode = "link";
  conn.link = new LinkSession(conn);
  await conn.link.onHello({ type: "hello", clientType: "cli", auth: { kind: "password", password: grant } });
  return { conn, sent, link: conn.link };
}

function openRoute(l: LinkSession, sent: any[], rid: string): string | null {
  l.onFrame({ type: "session", message: { type: "hosts.link.open.request", requestId: rid, channelId: `ch-${rid}` } });
  const res = sent.find((f) => f?.message?.type === "hosts.link.open.response" && f.message.payload.requestId === rid);
  return res ? res.message.payload.routeId : null;
}

function routeFrame(l: LinkSession, routeId: string, msg: unknown) {
  l.onFrame({ type: "session", message: { type: "hosts.route.frame.request", routeId, data: JSON.stringify(msg) } });
}

const expectedClientId = (laneId: string, sub: string, slot: number) =>
  `rooms-lane-${laneId}-watch-${createHash("sha256").update(JSON.stringify([laneId, sub, slot])).digest("hex").slice(0, 24)}`;

test("limits: defaults are inside their bounds and overrides are clamped", () => {
  for (const [k, b] of Object.entries(LIMIT_BOUNDS)) assert.ok(b.default >= b.min && b.default <= b.max, k);
  const r = resolveLimits({ maxLinksPerMember: 0, maxInboundFrameBytes: 1e12, maxRoutesPerLink: "lots", unknown: 5 });
  assert.equal(r.maxLinksPerMember, LIMIT_BOUNDS.maxLinksPerMember.min);
  assert.equal(r.maxInboundFrameBytes, LIMIT_BOUNDS.maxInboundFrameBytes.max);
  assert.equal(r.maxRoutesPerLink, DEFAULT_LIMITS.maxRoutesPerLink);
});

test("B3: relay connections per lane are capped", async () => {
  const { tmp, ep } = setup({ maxConnectionsPerLane: 4 });
  try {
    ep.onRelayControl({ type: "sync", connectionIds: Array.from({ length: 40 }, (_, i) => `c${i}`) });
    assert.equal(ep.connections.size, 4);
    ep.onRelayControl({ type: "connected", connectionId: "x".repeat(300) });
    assert.equal(ep.connections.size, 4);
  } finally {
    await ep.stop();
    tmp.cleanup();
  }
});

test("B3: links per member are capped without an auth failure", async () => {
  const { tmp, host, lane, ep } = setup({ maxLinksPerMember: 2 });
  try {
    const { token } = enroll(host, lane.id);
    const a = await link(ep, "c1", token);
    const b = await link(ep, "c2", token);
    const c = await link(ep, "c3", token);
    assert.equal(a.link.accepted && b.link.accepted, true);
    assert.equal(c.link.accepted, false);
    assert.equal(c.sent.some((f) => f?.type === "hello.rejected"), false, "a cap is not reported as a bad password");
    assert.equal(ep.links.length, 2);
  } finally {
    await ep.stop();
    tmp.cleanup();
  }
});

test("B1 + B3: routes are capped per link and per member; upstream clientId is fixed per route slot and ignores the viewer", async () => {
  const { tmp, host, lane, ep } = setup({ maxRoutesPerLink: 3, maxRoutesPerMember: 4 });
  try {
    const { token, member } = enroll(host, lane.id);
    const one = await link(ep, "c1", token);
    const two = await link(ep, "c2", token);
    const r = ["a", "b", "c", "d"].map((x) => openRoute(one.link, one.sent, x));
    assert.deepEqual(r.map((x) => x !== null), [true, true, true, false], "per-link cap");
    const r2 = ["e", "f"].map((x) => openRoute(two.link, two.sent, x));
    assert.deepEqual(r2.map((x) => x !== null), [true, false], "per-member cap across links");
    const before = fake.hellos.length;
    routeFrame(one.link, r[0]!, { type: "hello", clientId: "viewer-A", clientType: "mobile", protocolVersion: 1, capabilities: {} });
    routeFrame(one.link, r[1]!, { type: "hello", clientId: "viewer-A", clientType: "mobile", protocolVersion: 1, capabilities: {} });
    await waitFor(() => fake.hellos.length >= before + 2, 3000, "upstream hellos");
    const ids = fake.hellos.slice(before).map((h) => h.clientId);
    assert.deepEqual(ids.sort(), [expectedClientId(lane.id, member.id, 0), expectedClientId(lane.id, member.id, 1)].sort());
    for (const h of fake.hellos.slice(before)) {
      assert.equal(h.capabilities.selective_agent_timeline, true);
      assert.equal(h.auth.kind, "localCredential");
      assert.deepEqual(h.sessionPermissions, ["workspace.read"]);
    }
    // Closing route slot 0 frees it; the next route reuses the same upstream clientId.
    one.link.onFrame({ type: "session", message: { type: "hosts.route.close.request", routeId: r[0] } });
    const again = openRoute(one.link, one.sent, "g");
    assert.ok(again);
    routeFrame(one.link, again!, { type: "hello", clientId: "viewer-B", clientType: "browser", protocolVersion: 1 });
    await waitFor(() => fake.hellos.length >= before + 3, 3000, "third hello");
    assert.equal(fake.hellos[before + 2].clientId, expectedClientId(lane.id, member.id, 0));
  } finally {
    await ep.stop();
    tmp.cleanup();
  }
});

test("B3: the pending queue before the upstream is ready is bounded (overflow closes the route)", async () => {
  const { tmp, host, lane, ep } = setup({ maxPendingUpstreamFrames: 8 });
  fake.sendServerInfo = false;
  try {
    const { token } = enroll(host, lane.id);
    const { link: l, sent } = await link(ep, "c1", token);
    const routeId = openRoute(l, sent, "a")!;
    routeFrame(l, routeId, { type: "hello", clientId: "v", clientType: "browser", protocolVersion: 1 });
    for (let i = 0; i < 20; i++) routeFrame(l, routeId, { type: "session", message: { type: "fetch_agent_request", requestId: `q${i}`, agentId: "agent-1" } });
    const closed = sent.find((f) => f?.message?.type === "hosts.route.closed");
    assert.equal(closed?.message.payload.code, "resource_limit");
    assert.equal(l.channels.size, 0);
  } finally {
    fake.sendServerInfo = true;
    await ep.stop();
    tmp.cleanup();
  }
});

test("B3: tracked request maps are bounded and entries are removed on response", async () => {
  const { tmp, host, lane, ep } = setup({ maxTrackedRequestsPerRoute: 16, linkFrameBurst: 5000 });
  fake.onSession = (m, reply) => {
    if (m.type === "fetch_agent_request" && m.requestId === "answer-me") reply({ type: "fetch_agent_response", payload: { requestId: m.requestId, agent: null, project: null, error: null } });
  };
  try {
    const { token } = enroll(host, lane.id);
    const { link: l, sent } = await link(ep, "c1", token);
    const routeId = openRoute(l, sent, "a")!;
    routeFrame(l, routeId, { type: "hello", clientId: "v", clientType: "browser", protocolVersion: 1 });
    const vs = l.channels.get(routeId) as any;
    await waitFor(() => vs.upstreamReady === true, 3000, "upstream ready");
    for (let i = 0; i < 100; i++) routeFrame(l, routeId, { type: "session", message: { type: "fetch_agent_request", requestId: `q${i}`, agentId: "agent-1" } });
    assert.ok(vs.forwarded.size <= 16, `forwarded map size ${vs.forwarded.size}`);
    routeFrame(l, routeId, { type: "session", message: { type: "fetch_agent_request", requestId: "answer-me", agentId: "agent-1" } });
    assert.equal(vs.forwarded.has("answer-me"), true);
    await waitFor(() => !vs.forwarded.has("answer-me"), 3000, "entry removed on response");
  } finally {
    fake.onSession = () => undefined;
    await ep.stop();
    tmp.cleanup();
  }
});

test("B3 + C-5: oversized frames close the connection; per-link rate limit drops floods", async () => {
  const { tmp, host, lane, ep } = setup({ maxInboundFrameBytes: 64 * 1024, linkFramesPerSecond: 1, linkFrameBurst: 10 });
  try {
    const { token } = enroll(host, lane.id);
    const a = await link(ep, "c1", token);
    for (let i = 0; i < 50; i++)
      (a.conn as any).onMessage(JSON.stringify({ type: "session", message: { type: `bogus.${"x".repeat(500)}.${i}`, requestId: `r${i}` } }));
    const denied = a.sent.filter((f) => f?.message?.type === "rpc_error").length;
    assert.ok(denied <= 11 && denied >= 9, `rate limited to the burst, got ${denied}`);
    for (const f of a.sent.filter((x) => x?.message?.type === "rpc_error")) assert.ok(f.message.payload.requestType.length <= 100, "echoed type is clipped");
    const b = await link(ep, "c2", token);
    (b.conn as any).onMessage("x".repeat(64 * 1024 + 1));
    assert.equal(ep.connections.has("c2"), false);
  } finally {
    await ep.stop();
    tmp.cleanup();
  }
});

test("C-13: an archived lane agent stops the retries and hands the lane to the lane service", async () => {
  const tmp = tempDir();
  try {
    const host = new TestAuthority();
    const lane = testLane({ agentId: "agent-arch" });
    fake.onSession = (m, reply) => {
      if (m.type === "fetch_agent_request") reply({ type: "fetch_agent_response", payload: { requestId: m.requestId, agent: m.agentId === "agent-arch" ? { id: "agent-arch", archivedAt: "2026-10-28T00:00:00Z" } : null, project: null, error: null } });
    };
    const gone: string[] = [];
    const ep = new LaneEndpoint(lane, { authority: host, paseoHome: fake.home, onAgentGone: (id, reason) => void gone.push(`${id}:${reason}`) });
    await ep.start();
    assert.deepEqual(gone, [`${lane.id}:agent_archived`]);
    assert.equal((ep as any).reconnectTimer, null, "no retry timer");
    // A missing agent is not closed on the first sighting (could be a daemon still loading).
    const lane2 = testLane({ roomId: lane.roomId, agentId: "agent-missing" });
    const ep2 = new LaneEndpoint(lane2, { authority: host, paseoHome: fake.home, onAgentGone: (id, reason) => void gone.push(`${id}:${reason}`) });
    await ep2.start();
    assert.equal(gone.length, 1);
    assert.equal(ep2.status, "offline");
    await ep2.stop();
    await ep.stop();
  } finally {
    fake.onSession = () => undefined;
    tmp.cleanup();
  }
});

test("C-iso2: a fork lane whose room agent fails the tripwire never starts", async () => {
  const tmp = tempDir();
  try {
    const host = new TestAuthority();
    const lane = testLane({ label: "Fork", origin: { kind: "fork" }, agentId: "agent-f" });
    const before = fake.hellos.length;
    const ep = new LaneEndpoint(lane, { authority: host, paseoHome: fake.home, verifyRoomAgent: () => ({ ok: false, problems: ["unexpected MCP servers: zz-tools"] }) });
    await ep.start();
    assert.equal(ep.blockedReason, "room_agent_tripwire");
    assert.equal(ep.status, "offline");
    assert.equal(fake.hellos.length, before, "no daemon contact");
    await ep.stop();
  } finally {
    tmp.cleanup();
  }
});
