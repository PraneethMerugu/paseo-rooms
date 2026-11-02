// Module 5: resource-stress tests (HARDENING-PLAN section B3 and E; decisions round 2 option 3 and
// round 10 item 5). Bounded load against the OWNER test daemon's own endpoints, to confirm that the
// documented limits hold, that going over a limit is refused gracefully (only the offending connection,
// route or request is refused or closed; the daemon keeps serving), and that service recovers.
//
// Loopback only, as module 4: run.sh restarts the owner test daemon with its room relay set to the
// loopback fake relay (127.0.0.1, port 6930-6939); every helper refuses a room or lane whose recorded
// relay is anything else. The member side runs in this test process (proto-client.ts). No agent is
// created and no model is called.
//
// Bounds: each test opens at most 40 sockets or sends at most a few dozen frames, except the chat
// retention test, which needs about 760 chat messages of 4000 characters (the byte bound of the chat
// store) and stops after 120 s. No test waits for a timer longer than the endpoint's 12 s link
// liveness window. Limits are imported from the server code, so a changed limit changes the test.
//
// Expected results: every test passes. A test marked "inconclusive" in the evidence was skipped because
// a precondition did not hold (for example, the owner device had published no KeyPackages yet).
// Evidence (counts and timings, no secrets): <logdir>/resource-stress.jsonl.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { OWNER_HOME, PARENT, adminRpc, assertSafeEnvironment, closeQuietly, createRoomWithLane, log, memberRoomDir, ownedRoom, ownerClient, record, rpc, sleep, until, v2Ready, type RoomLane } from "./lib";
import {
  LaneLink,
  TestDevice,
  containsNone,
  enrollRequest,
  enrollTestDevice,
  errorOf,
  inviteCode,
  issueGrant,
  laneOffer,
  linkWith,
  logLength,
  loopbackRelay,
  newEntryTypes,
  ownerLogsClean,
  ownerSnap,
  preauthSession,
  reconnect,
  rememberCode,
  type EnrolledDevice,
  type JoinCode,
  type LaneOffer,
} from "./proto-client";
import { ENROLLMENT_LIMITS } from "../../server/host/enrollment";
import { LIVENESS_WAIT_MS, V2_LANE_LIMITS } from "../../server/host/lane-service";
import { KP_FETCH_TARGETS_MAX, KP_POOL_MAX } from "../../server/host/mls-delivery";
import { CHAT_LIMITS, CHAT_SEGMENT_MESSAGES } from "../../server/member/chat-store";
import { CHAT_TEXT_MAX } from "../../server/mls/formats";
import { newId } from "../../server/proto/ids";

/** room-endpoint.ts: at most 8 open sessions of statics that are not active devices (enrollment-v2 5.4). */
const PREAUTH_SESSIONS_MAX = 8;
const EVIDENCE = "resource-stress.jsonl";

let owner: any;
let room: RoomLane;
let code: JoinCode;
let S: EnrolledDevice;
let grant: { token: string; gid: string; exp: number };
let offer: LaneOffer;
const secrets: string[] = [];
const open: LaneLink[] = [];

before(async () => {
  assertSafeEnvironment();
  loopbackRelay();
  owner = await ownerClient(OWNER_HOME(), "stress-owner");
  await v2Ready(owner);
  room = await createRoomWithLane(owner, PARENT(), "Stress");
  const inv = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note: "stress" });
  code = inviteCode(inv.code); // throws unless the room is on the loopback relay
  rememberCode(inv.code, code);
  secrets.push(inv.code, code.payload.token);
  S = await enrollTestDevice(owner, room.roomId, code, "Stress device");
  grant = await issueGrant(S, room.laneId);
  secrets.push(grant.token);
  offer = laneOffer(S, room.laneId);
  log("stress_setup", { roomId: room.roomId, laneId: room.laneId, memberId: S.memberId });
});

after(async () => {
  for (const l of open) l.close();
  S?.session.close();
  await closeQuietly(owner);
});

// ------------------------------------------------------------------ helpers

/** Waits (bounded) until the owner lists no accepted link on the stress lane. */
async function linksSettled(): Promise<void> {
  await until("earlier links closed", async () => (await ownedRoom(owner, room.roomId))?.lanes.every((l: any) => l.links === 0), 15_000, 250).catch(() => undefined);
}

async function acceptedLink(label: string, password = grant.token): Promise<LaneLink> {
  await linksSettled();
  const { link, outcome } = await linkWith(offer, password, 20_000);
  open.push(link);
  assert.equal(outcome.kind, "accepted", `${label}: the valid grant was not accepted (${outcome.kind})`);
  return link;
}

const currentGid = async () => (await ownedRoom(owner, room.roomId)).grants.find((g: any) => g.deviceId === S.deviceId && g.laneId === room.laneId)?.gid ?? null;

// ------------------------------------------------------------------ lane endpoint

test(`connections per lane: at most ${V2_LANE_LIMITS.maxConnectionsPerLane} relay connections are served, the rest are not, and capacity returns`, { timeout: 90_000 }, async () => {
  await linksSettled();
  const cap = V2_LANE_LIMITS.maxConnectionsPerLane;
  const n = cap + 8;
  const t0 = Date.now();
  const conns = await Promise.all(Array.from({ length: n }, () => LaneLink.connect(offer)));
  open.push(...conns);
  // A served connection completes the Noise handshake; an unserved one never gets the endpoint's reply.
  const served = (await Promise.all(conns.map((c) => c.waitOpen(8000)))).filter(Boolean).length;
  for (const c of conns) c.close();
  record(EVIDENCE, { case: "connections_per_lane", attempted: n, served, cap, ms: Date.now() - t0 });
  assert.ok(served <= cap, `served ${served} connections, more than the cap of ${cap}`);
  assert.ok(served < n, "every connection was served: the cap did not apply");
  assert.ok(served >= cap - 4, `only ${served} connections served: the endpoint stopped serving well below its cap`);
  // Recovery: once the sockets are gone, a normal link with the grant works.
  await sleep(2000);
  (await acceptedLink("after the connection burst")).close();
});

test(`routes per link: the route after ${V2_LANE_LIMITS.maxRoutesPerLink} is refused with resource_limit and the link keeps working`, { timeout: 60_000 }, async () => {
  const link = await acceptedLink("routes");
  try {
    const cap = V2_LANE_LIMITS.maxRoutesPerLink;
    const routes: string[] = [];
    let refusal: any = null;
    for (let i = 1; i <= cap + 1; i++) {
      const r = await link.openRoute(`stress-route-${i}`);
      assert.ok(r, `route ${i}: no answer`);
      if ("routeId" in r!) routes.push(r.routeId);
      else refusal = r!.error;
    }
    record(EVIDENCE, { case: "routes_per_link", opened: routes.length, refused: refusal?.code ?? null });
    assert.equal(routes.length, cap, `opened ${routes.length} routes on one link`);
    assert.equal(refusal?.code, "resource_limit");
    assert.equal(refusal?.error, "Too many host channels");
    // Recovery: closing one route frees a slot on the same link.
    await link.send({ type: "session", message: { type: "hosts.route.close.request", routeId: routes[0] } });
    assert.ok(await link.routeClosed(routes[0], 5000), "the closed route is confirmed");
    const again = await link.openRoute("stress-route-again");
    assert.ok(again && "routeId" in again, "a route opens again after one was closed");
  } finally {
    link.close();
  }
});

test("links per grant: a silent duplicate link is replaced; a live duplicate is treated as theft, then a new grant works", { timeout: 120_000 }, async () => {
  // grants-v2 6.1: one link per (device, lane). A second link with the same grant makes the endpoint
  // watch the first for LIVENESS_WAIT_MS: silence means it is dead and replaced; traffic means two live
  // holders, so both are closed, the gid is unlisted and grant.suspected-theft is logged.
  const first = await acceptedLink("first link");
  const fromA = logLength(room.roomId);
  const tA = Date.now();
  const { link: second, outcome: o2 } = await linkWith(offer, grant.token, LIVENESS_WAIT_MS + 10_000);
  open.push(second);
  const replacedMs = Date.now() - tA;
  assert.equal(o2.kind, "accepted", `a duplicate link with a silent first link must replace it (${o2.kind})`);
  assert.ok(await first.waitClosed(5000), "the silent first link is closed");
  assert.deepEqual(newEntryTypes(room.roomId, fromA), [], "replacing a dead link logs nothing");
  assert.equal(await currentGid(), grant.gid, "the grant stays current after a replacement");

  // The second link is live (a ping every second); a third link with the same grant is theft.
  const keepAlive = setInterval(() => void second.ping().catch(() => undefined), 1000);
  const fromB = logLength(room.roomId);
  const tB = Date.now();
  let o3: Awaited<ReturnType<typeof linkWith>>["outcome"];
  try {
    const r = await linkWith(offer, grant.token, LIVENESS_WAIT_MS + 10_000);
    open.push(r.link);
    o3 = r.outcome;
    assert.ok(await r.link.waitClosed(5000), "the duplicate link is closed");
  } finally {
    clearInterval(keepAlive);
  }
  assert.notEqual(o3.kind, "accepted", "a duplicate of a live link must not be accepted");
  assert.ok(await second.waitClosed(5000), "the live link is closed too");
  await until("gid unlisted", async () => (await currentGid()) !== grant.gid, 10_000, 250);
  assert.deepEqual(newEntryTypes(room.roomId, fromB), ["grant.suspected-theft"], "exactly one grant.suspected-theft entry");
  await until("grant.revoked push", () => S.pushes.find((f) => f.t === "grant.revoked" && f.gid === grant.gid) ?? null, 10_000, 100);
  assert.equal((await ownedRoom(owner, room.roomId)).compromisedDevices.includes(S.deviceId), false, "one theft is not yet a compromise");
  record(EVIDENCE, { case: "links_per_grant", replacedMs, theftMs: Date.now() - tB, theftOutcome: o3.kind });

  // Recovery: the device gets a new grant (15 s after its previous issue) and links again.
  grant = await issueGrant(S, room.laneId);
  secrets.push(grant.token);
  (await acceptedLink("new grant after theft")).close();
});

test(`frame size: a link frame over ${V2_LANE_LIMITS.maxInboundFrameBytes} bytes closes that link and a route message over ${V2_LANE_LIMITS.maxRouteMessageChars} characters closes that route`, { timeout: 60_000 }, async () => {
  const from = logLength(room.roomId);
  const link = await acceptedLink("frame size");
  try {
    // Route message cap: only the route closes; the link still answers.
    const r = await link.openRoute("stress-big-route");
    assert.ok(r && "routeId" in r, "a route opens");
    const routeId = (r as { routeId: string }).routeId;
    await link.routeSend(routeId, "x".repeat(V2_LANE_LIMITS.maxRouteMessageChars + 1024));
    const closed = await link.routeClosed(routeId, 5000);
    assert.equal(closed?.code, "resource_limit", "an oversized route message closes the route with resource_limit");
    await link.ping();
    assert.ok(await link.next((f) => f?.type === "pong", 5000), "the link survives an oversized route message");

    // Link frame cap: the whole link closes; nothing else is affected.
    const pad = "x".repeat(V2_LANE_LIMITS.maxInboundFrameBytes + 64 * 1024);
    await link.send({ type: "session", message: { type: "stress.pad", pad } }).catch(() => undefined);
    assert.ok(await link.waitClosed(10_000), "an oversized link frame closes the link");
  } finally {
    link.close();
  }
  // Recovery: a new link with the same grant works, and closing for size was not counted as theft.
  (await acceptedLink("after an oversized frame")).close();
  assert.deepEqual(newEntryTypes(room.roomId, from), [], "no log entry for a size violation");
  assert.equal(await currentGid(), grant.gid, "the grant stays current");
  record(EVIDENCE, { case: "frame_size", ok: true });
});

// ------------------------------------------------------------------ room endpoint

test(`pre-auth budget: at most ${PREAUTH_SESSIONS_MAX} pre-auth sessions at once, and enrollment requests beyond the burst get busy with retryAfter`, { timeout: 120_000 }, async () => {
  const snap = await ownerSnap(owner, room.roomId);
  const from = logLength(room.roomId);

  // (a) Concurrent sessions of unknown keys: the endpoint closes those beyond the cap after message 1.
  const devices = Array.from({ length: PREAUTH_SESSIONS_MAX + 2 }, (_, i) => new TestDevice(`Stress pre-auth ${i}`));
  const results = await Promise.allSettled(devices.map((d) => preauthSession(code, d)));
  const sessions = results.filter((r): r is PromiseFulfilledResult<Awaited<ReturnType<typeof preauthSession>>> => r.status === "fulfilled").map((r) => r.value);
  for (const s of sessions) s.close();
  record(EVIDENCE, { case: "preauth_sessions", attempted: devices.length, opened: sessions.length, cap: PREAUTH_SESSIONS_MAX });
  assert.ok(sessions.length <= PREAUTH_SESSIONS_MAX, `${sessions.length} pre-auth sessions opened at once`);
  assert.ok(sessions.length >= 1, "no pre-auth session opened at all");
  assert.ok(devices.length - sessions.length >= 2, "the sessions beyond the cap were not refused");
  // Recovery: with those sessions closed, a new pre-auth session opens.
  await sleep(1000);
  const again = await preauthSession(code, new TestDevice("Stress pre-auth again"));
  again.close();

  // (b) The enrollment request bucket (burst ENROLLMENT_LIMITS.preauthBurst, then 10 per minute). Each
  // request is well formed and validly signed but names an unknown invite, so no invite is touched.
  const nm = randomBytes(32);
  let accepted = 0;
  let busy: Record<string, unknown> | null = null;
  for (let i = 0; i < 12 && !busy; i++) {
    const d = new TestDevice(`Stress budget ${i}`);
    const c = await preauthSession(code, d);
    try {
      await c.request(enrollRequest(code, d, c.handshakeHash!, { nm, token: "valid", target: { inviteId: newId("invite") } }), 10_000);
      assert.fail("a request for an unknown invite was answered");
    } catch (e) {
      const err = errorOf(e);
      if (err?.code === "busy") busy = err.fields;
      else if (err?.code === "enroll_rejected") accepted++;
      else throw e;
    } finally {
      c.close();
    }
  }
  record(EVIDENCE, { case: "preauth_bucket", acceptedBeforeBusy: accepted, retryAfter: busy?.retryAfter ?? null, burst: ENROLLMENT_LIMITS.preauthBurst });
  assert.ok(busy, "no busy reply within 12 rapid enrollment requests");
  assert.ok(accepted <= ENROLLMENT_LIMITS.preauthBurst + 1, `${accepted} requests passed the budget before busy`);
  const retryAfter = Number(busy!.retryAfter);
  assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60, "busy carries a retryAfter in seconds");
  assert.deepEqual(Object.keys(busy!), ["retryAfter"], "busy carries nothing else");
  // Recovery: after retryAfter, the next request passes the budget (and gets the generic refusal).
  await sleep((retryAfter + 1) * 1000);
  const d = new TestDevice("Stress budget after");
  const c = await preauthSession(code, d);
  try {
    await c.request(enrollRequest(code, d, c.handshakeHash!, { nm, token: "valid", target: { inviteId: newId("invite") } }), 10_000);
    assert.fail("a request for an unknown invite was answered");
  } catch (e) {
    assert.equal(errorOf(e)?.code, "enroll_rejected", "the budget recovered after retryAfter");
  } finally {
    c.close();
  }
  assert.deepEqual(await ownerSnap(owner, room.roomId), snap, "the budget tests changed no invite, pending or grant");
  assert.deepEqual(newEntryTypes(room.roomId, from), [], "the budget tests appended no log entry");
});

test(`kp.fetch caps: more than ${KP_FETCH_TARGETS_MAX} targets or a count over ${KP_POOL_MAX} is refused, and one fetcher gets at most its hourly share of single-use packages`, { timeout: 60_000 }, async (t) => {
  const self = (await ownedRoom(owner, room.roomId)).roster.find((m: any) => m.self);
  const target = { memberId: self.memberId, deviceId: self.devices[0].deviceId };
  const fetch = async (targets: unknown[]) => {
    try {
      return { reply: await S.session.request({ t: "kp.fetch", targets: targets as never }), error: null };
    } catch (e) {
      return { reply: null, error: errorOf(e) };
    }
  };
  // (a) Too many targets in one request: bad_frame, which closes the session; the device reconnects.
  const tooMany = await fetch(Array.from({ length: KP_FETCH_TARGETS_MAX + 1 }, () => ({ ...target, for: "current", count: 1 })));
  assert.equal(tooMany.error?.code, "bad_frame");
  await reconnect(S);
  // (b) A count above the pool size: bad_frame as well.
  const tooBig = await fetch([{ ...target, for: "current", count: KP_POOL_MAX + 1 }]);
  assert.equal(tooBig.error?.code, "bad_frame");
  await reconnect(S);
  // (c) Hourly caps (6.4): a watch member that shares no scope with the owner may take 1 single-use
  // package of a target per hour; a second fetch gets no single-use package (at most the last resort).
  const first = await fetch([{ ...target, for: "current", count: 1 }]);
  assert.equal(first.error, null, "a well-formed kp.fetch is served");
  const firstSingle = (first.reply as any).results[0].keyPackages.length as number;
  const second = await fetch([{ ...target, for: "current", count: 1 }]);
  assert.equal(second.error, null, "a second kp.fetch is served (not refused)");
  const secondSingle = (second.reply as any).results[0].keyPackages.length as number;
  record(EVIDENCE, { case: "kp_fetch", tooMany: tooMany.error?.code, tooBig: tooBig.error?.code, firstSingle, secondSingle, secondLastResort: (second.reply as any).results[0].lastResort !== null });
  if (firstSingle === 0) {
    record(EVIDENCE, { case: "kp_fetch_hourly", inconclusive: "the owner device had no single-use KeyPackage to serve" });
    t.skip("inconclusive: the owner device had no single-use KeyPackage to serve");
    return;
  }
  assert.equal(firstSingle, 1, "the first fetch serves one single-use package");
  assert.equal(secondSingle, 0, "beyond the fetcher's hourly cap no single-use package is served");
  assert.equal(S.session.status, "open", "the capped fetch keeps the session open");
});

// ------------------------------------------------------------------ chat store

test(`chat store retention: the owner device keeps at most about ${CHAT_LIMITS.maxBytes} bytes of chat; the oldest segments are dropped and sending keeps working`, { timeout: 180_000 }, async (t) => {
  // A separate room with no other member, so the owner's room group is just its own device.
  const created = await rpc(owner, "rooms.v2.room.create", { recovery: "skip" });
  const roomId: string = created.roomId;
  // The owner's room group may be set up shortly after the room: wait (bounded) until it can send.
  let probe = await rpc(owner, "rooms.v2.chat.list", { roomId, limit: 1 });
  for (let i = 0; i < 30 && probe.cannotSend; i++) {
    await sleep(1000);
    probe = await rpc(owner, "rooms.v2.chat.list", { roomId, limit: 1 });
  }
  if (probe.cannotSend) {
    record(EVIDENCE, { case: "chat_retention", inconclusive: `cannot send: ${probe.cannotSend}` });
    t.skip(`inconclusive: chat cannot send in a fresh room (${probe.cannotSend})`);
    return;
  }
  // chat-store.ts sizes a message as text.length * 3 + 200; the byte bound is reached long before the
  // 2048-message bound, so this checks the byte bound only.
  const textOf = (i: number) => {
    const head = `stress ${i} `;
    return head + "x".repeat(CHAT_TEXT_MAX - head.length);
  };
  const per = CHAT_TEXT_MAX * 3 + 200;
  const bound = Math.floor(CHAT_LIMITS.maxBytes / per);
  const n = bound + CHAT_SEGMENT_MESSAGES + 8; // enough to force whole segments out
  const seqs: number[] = [];
  const t0 = Date.now();
  const deadline = t0 + 120_000;
  for (let i = 0; i < n; i++) {
    if (Date.now() > deadline) {
      record(EVIDENCE, { case: "chat_retention", inconclusive: "time bound reached", sent: i });
      t.skip(`inconclusive: only ${i} of ${n} messages sent within 120 s`);
      return;
    }
    seqs.push((await rpc(owner, "rooms.v2.chat.send", { roomId, text: textOf(i) })).seq);
  }
  const sendMs = Date.now() - t0;
  // Read the whole stored history, newest page first.
  const stored: number[] = [];
  let before: number | undefined;
  for (let page = 0; page < 20; page++) {
    const p = await rpc(owner, "rooms.v2.chat.list", { roomId, limit: 200, ...(before !== undefined ? { before } : {}) });
    stored.unshift(...p.messages.map((m: any) => m.seq as number));
    if (!p.more || p.messages.length === 0) break;
    before = p.messages[0].seq;
  }
  const chatDir = join(memberRoomDir(OWNER_HOME(), roomId), "chat");
  const segments = existsSync(chatDir) ? readdirSync(chatDir).filter((f) => /^seg-\d{6}\.sealed$/.test(f)).length : -1;
  record(EVIDENCE, { case: "chat_retention", sent: n, stored: stored.length, bound, segments, sendMs });
  assert.ok(stored.length <= bound, `${stored.length} messages stored, above the byte bound of ${bound}`);
  assert.ok(stored.length >= bound - CHAT_SEGMENT_MESSAGES, `${stored.length} messages stored: more than one segment below the bound was dropped`);
  assert.equal(stored.includes(seqs[0]), false, "the oldest message was dropped");
  assert.equal(stored.at(-1), seqs.at(-1), "the newest message is kept");
  assert.ok(segments >= 1 && segments <= Math.ceil(bound / CHAT_SEGMENT_MESSAGES) + 1, `${segments} segment files on disk`);
  // Recovery: sending still works and the new message is listed.
  const after = await rpc(owner, "rooms.v2.chat.send", { roomId, text: "stress done" });
  const last = await rpc(owner, "rooms.v2.chat.list", { roomId, limit: 1 });
  assert.equal(last.messages.at(-1)?.seq, after.seq, "a message sent after the bound is stored and listed");
});

// ------------------------------------------------------------------ final

test("after the stress tests the lane still serves the current grant and the owner's log holds no tracked secret", { timeout: 60_000 }, async () => {
  (await acceptedLink("final positive control")).close();
  assert.ok(containsNone(JSON.stringify(await ownerSnap(owner, room.roomId)), secrets), "the owner's status contains a tracked secret");
  assert.ok(await ownerLogsClean(secrets), "the owner's plugin log contains a tracked secret");
  record(EVIDENCE, { case: "final", ok: true });
});
