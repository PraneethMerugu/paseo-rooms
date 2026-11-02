// Module 4: credential-negative tests (hardening plan section E "grant replay and forgery" and "invite
// reuse"; decisions round 2 option 3 and round 10 item 5). Protocol-level refusals of the OWNER test
// daemon's own room endpoint and lane endpoints.
//
// How: run.sh restarts the owner test daemon with its room relay set to a loopback fake relay
// (127.0.0.1, port 6930-6939), so every room this module creates registers there. The module then acts
// as member devices in this test process (proto-client.ts: the plugin's own RoomClient, enrollment and
// device-link formats, and Paseo's client secure channel), which lets it send frames a correct member
// daemon never sends. Every helper refuses to connect unless the room's recorded relay is that
// loopback relay. The member test daemon is not used. No agent is created and no model is called: the
// lanes share the run's existing throwaway parent, and the one prompting message this module sends
// names a made-up agent id, so even a broken filter could not prompt a real agent.
//
// Setup: one room with two share-live lanes (A and B) on the parent. Device A (watch, lanes A and B)
// and device B (watch, lane A only) enroll by the real SAS flow, with a TEST-ONLY programmatic SAS
// comparison (digits never logged). Each case below then:
//   1. takes an owner snapshot (status view: roster, invites, join requests, grants, lanes, keys) and
//      the length of the independently verified room log;
//   2. sends the bad credential and checks the refusal is the documented GENERIC one (the same reply
//      for every reason, so a prober learns nothing);
//   3. checks that nothing changed (the snapshot is equal and no non-MLS log entry was appended), or
//      exactly the change the spec requires (an invite burned after its third failed proof);
//   4. checks that no tracked secret (grants and their signatures, invite and link codes and tokens,
//      the tampered variants) appears in any reply or in the owner's plugin log.
// The SAS, codes and grants are never printed. Evidence (ids, outcomes, timings; no secrets):
// <logdir>/credential-negative.jsonl.
//
// Pre-auth budget: the room endpoint allows 5 enrollment requests at once and 10 per minute. Cases
// that are not about the budget wait out `busy` replies (proto-client preauthCall), so this module
// takes a few minutes.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { OWNER_HOME, PARENT, adminRpc, assertSafeEnvironment, closeQuietly, createRoomWithLane, log, ownedRoom, ownerClient, record, rpc, sleep, until, v2Ready, type RoomLane } from "./lib";
import {
  GENERIC_HELLO_REJECTION,
  TestDevice,
  containsNone,
  createLinkCode,
  enrollRequest,
  enrollTestDevice,
  errorOf,
  flipChar,
  inviteCode,
  issueGrant,
  laneOffer,
  linkCode,
  linkWith,
  logLength,
  loopbackRelay,
  newEntryTypes,
  openMemberSession,
  ownerLogsClean,
  ownerSnap,
  preauthCall,
  preauthSession,
  reclaim,
  rememberCode,
  RoomSessionError,
  type EnrolledDevice,
  type JoinCode,
  type LaneLink,
  type LaneOffer,
} from "./proto-client";
import { b64u } from "../../server/proto/b64u";
import { newId } from "../../server/proto/ids";
import { rjcsText } from "../../server/proto/rjcs";
import type { RjcsValue } from "../../server/proto/rjcs";

const EVIDENCE = "credential-negative.jsonl";
let owner: any;
let room: RoomLane;
let laneB: string;
let A: EnrolledDevice;
let B: EnrolledDevice;
let codeA: JoinCode;
let grantA: { token: string; gid: string; exp: number };
let grantAB: { token: string; gid: string; exp: number };
let grantB: { token: string; gid: string; exp: number };
let offerA: LaneOffer;
let offerB: LaneOffer;
/** Every secret this module handled; checked against replies and the owner's log, never printed. */
const secrets: string[] = [];
const links: LaneLink[] = [];

function track(...s: string[]): void {
  for (const x of s) if (x && x.length >= 16) secrets.push(x);
}

before(async () => {
  assertSafeEnvironment();
  loopbackRelay();
  owner = await ownerClient(OWNER_HOME(), "credneg-owner");
  await v2Ready(owner);
  room = await createRoomWithLane(owner, PARENT(), "Negative A");
  const lb = await adminRpc(owner, "rooms.v2.lane.create", { roomId: room.roomId, agentId: PARENT(), label: "Negative B" });
  laneB = lb.laneId;
  await until("lane B online", async () => (await ownedRoom(owner, room.roomId))?.lanes.find((l: any) => l.laneId === laneB && l.endpoint === "online"), 60_000, 500);

  // inviteCode() decodes strictly and throws unless the room's relay is the loopback relay.
  const invA = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId, laneB].sort(), note: "negative A" });
  codeA = inviteCode(invA.code);
  rememberCode(invA.code, codeA);
  track(invA.code, codeA.payload.token);
  A = await enrollTestDevice(owner, room.roomId, codeA, "Negative A");

  const invB = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note: "negative B" });
  const codeB = inviteCode(invB.code);
  rememberCode(invB.code, codeB);
  track(invB.code, codeB.payload.token);
  B = await enrollTestDevice(owner, room.roomId, codeB, "Negative B");

  grantA = await issueGrant(A, room.laneId);
  grantAB = await issueGrant(A, laneB);
  grantB = await issueGrant(B, room.laneId);
  for (const g of [grantA, grantAB, grantB]) track(g.token, g.token.split(".")[2]);
  offerA = laneOffer(A, room.laneId);
  offerB = laneOffer(A, laneB);
  log("credneg_setup", { roomId: room.roomId, laneA: room.laneId, laneB, memberA: A.memberId, memberB: B.memberId });
});

after(async () => {
  for (const l of links) l.close();
  A?.session.close();
  B?.session.close();
  await closeQuietly(owner);
});

// ------------------------------------------------------------------ shared checks

/** Runs `attempt` between two owner snapshots and asserts that nothing changed. */
async function expectNoChange<T>(label: string, attempt: () => Promise<T>): Promise<T> {
  const before = await ownerSnap(owner, room.roomId);
  const from = logLength(room.roomId);
  const out = await attempt();
  await sleep(500); // let a wrong reaction (a late log entry or state write) land before comparing
  assert.deepEqual(await ownerSnap(owner, room.roomId), before, `${label}: the owner's room state changed`);
  assert.deepEqual(newEntryTypes(room.roomId, from), [], `${label}: log entries were appended`);
  return out;
}

/** No tracked secret in the replies or in the owner's plugin log. Checked before any assertion prints a reply. */
async function expectNoLeak(label: string, replies: unknown[]): Promise<void> {
  assert.ok(containsNone(JSON.stringify(replies), secrets), `${label}: a reply contains a tracked secret`);
  assert.ok(await ownerLogsClean(secrets), `${label}: the owner's plugin log contains a tracked secret`);
}

/**
 * A link hello with `password` must get exactly the generic refusal, then the endpoint must close the
 * link, and no session frame may arrive.
 */
async function expectGenericRefusal(label: string, offer: LaneOffer, password: unknown): Promise<unknown> {
  const { link, outcome } = await linkWith(offer, password);
  links.push(link);
  try {
    assert.equal(outcome.kind, "rejected", `${label}: expected the generic hello.rejected, got ${outcome.kind}`);
    const frame = (outcome as { frame: unknown }).frame;
    assert.ok(containsNone(JSON.stringify(frame), secrets), `${label}: the refusal contains a tracked secret`);
    assert.deepEqual(frame, GENERIC_HELLO_REJECTION, `${label}: the refusal must be the generic one`);
    assert.ok(await link.waitClosed(5000), `${label}: the endpoint must close the link after refusing`);
    assert.equal(link.frames.some((f) => f?.type === "session"), false, `${label}: a session frame arrived after a refusal`);
    return frame;
  } finally {
    link.close();
  }
}

/** Waits (bounded) until the owner lists no accepted link on the room's lanes. */
async function linksSettled(): Promise<void> {
  await until("earlier links closed", async () => (await ownedRoom(owner, room.roomId))?.lanes.every((l: any) => l.links === 0), 15_000, 250).catch(() => undefined);
}

/**
 * A link hello with `password` must be accepted (a positive control: the method can tell). By default
 * it first waits until earlier links of this module are gone: a second link of the same device and
 * lane is held for up to 12 s while the endpoint checks whether the first is still alive (grants-v2 6.1).
 */
async function expectAccepted(label: string, offer: LaneOffer, password: string, settle = true): Promise<LaneLink> {
  if (settle) await linksSettled();
  const { link, outcome } = await linkWith(offer, password, 20_000);
  links.push(link);
  assert.equal(outcome.kind, "accepted", `${label}: a valid grant was not accepted (${outcome.kind})`);
  assert.ok(containsNone(JSON.stringify((outcome as { status: unknown }).status), secrets), `${label}: the status frame contains a tracked secret`);
  return link;
}

/** A refused pre-auth request: the error code and extra fields of the reply. */
function refusal(label: string, r: { reply: unknown; error: RoomSessionError | null }): { code: string; fields: Record<string, unknown> } {
  assert.equal(r.reply, null, `${label}: expected a refusal, got a reply`);
  const e = errorOf(r.error);
  assert.ok(e, `${label}: expected a room session error`);
  return e!;
}

// ------------------------------------------------------------------ lane grants

test("positive control: device A's current grant opens a link on lane A", { timeout: 60_000 }, async () => {
  const link = await expectAccepted("current grant", offerA, grantA.token);
  link.close();
  record(EVIDENCE, { case: "positive_control", ok: true });
});

test("tampered grants all get the same generic refusal and change nothing", { timeout: 180_000 }, async () => {
  // Each variant fails a different step of grants-v2 section 4 (format, signature); the endpoint must
  // not reveal which. The real reason goes only to the owner's log, and never with the token.
  const t = grantA.token;
  const [prefix, claims] = t.split(".");
  const variants: Array<[string, unknown]> = [
    ["claims_byte_changed", flipChar(t, 1)],
    ["signature_byte_changed", flipChar(t, 2)],
    ["claims_forged_role_admin", reclaim(t, { role: "admin" })],
    ["claims_forged_longer_exp", reclaim(t, { exp: grantA.exp + 86_400 })],
    ["random_signature", `${prefix}.${claims}.${b64u(randomBytes(64))}`],
    ["wrong_prefix", `prg1.${t.slice(5)}`],
    ["signature_missing", `${prefix}.${claims}`],
    ["oversize", `${t}${"A".repeat(2000)}`],
    ["empty", ""],
    ["not_a_string", 12345],
  ];
  for (const [, v] of variants) if (typeof v === "string") track(v);
  const replies: unknown[] = [];
  for (const [name, password] of variants) {
    replies.push(await expectNoChange(`tampered ${name}`, () => expectGenericRefusal(`tampered ${name}`, offerA, password)));
    record(EVIDENCE, { case: "tampered_grant", variant: name, refused: true });
  }
  await expectNoLeak("tampered grants", replies);
});

test("a grant for another lane is refused (wrong audience); each lane accepts its own grant", { timeout: 90_000 }, async () => {
  const r1 = await expectNoChange("lane A grant at lane B", () => expectGenericRefusal("lane A grant at lane B", offerB, grantA.token));
  const r2 = await expectNoChange("lane B grant at lane A", () => expectGenericRefusal("lane B grant at lane A", offerA, grantAB.token));
  (await expectAccepted("lane B grant at lane B", offerB, grantAB.token)).close();
  await expectNoLeak("other lane", [r1, r2]);
  record(EVIDENCE, { case: "other_lane", refused: true });
});

test("a replayed grant is refused once a newer grant was issued to the same device and lane", { timeout: 120_000 }, async () => {
  // grants-v2 section 4 step 6: only the current gid per (device, lane) is valid. Issuing waits out the
  // 15 s minimum interval between issues.
  const old = grantA;
  grantA = await issueGrant(A, room.laneId);
  track(grantA.token, grantA.token.split(".")[2]);
  assert.notEqual(grantA.gid, old.gid);
  const current = (await ownedRoom(owner, room.roomId)).grants.find((g: any) => g.deviceId === A.deviceId && g.laneId === room.laneId);
  assert.equal(current?.gid, grantA.gid, "the owner lists the new gid as current");
  const r = await expectNoChange("replayed grant", () => expectGenericRefusal("replayed grant", offerA, old.token));
  (await expectAccepted("new grant", offerA, grantA.token)).close();
  await expectNoLeak("replayed grant", [r]);
  record(EVIDENCE, { case: "replayed_grant", refused: true });
});

test("a grant relabelled for another device is refused; a device without lane access gets no grant", { timeout: 90_000 }, async () => {
  // Claims bind the grant to its member and device (sub, dev); changing them breaks the host signature.
  const relabelled = reclaim(grantA.token, { sub: B.memberId, dev: B.device.sigKid });
  track(relabelled);
  const r1 = await expectNoChange("relabelled grant", () => expectGenericRefusal("relabelled grant", offerA, relabelled));
  // Device B's invite named lane A only: asking for lane B is refused on its session, which stays open.
  const denied = await expectNoChange("grant.issue for a lane without access", async () => {
    try {
      await B.session.request({ t: "grant.issue", laneId: laneB });
      return null;
    } catch (e) {
      return errorOf(e);
    }
  });
  assert.equal(denied?.code, "not_permitted", "grant.issue for a lane the device has no access to");
  assert.deepEqual(denied?.fields, {}, "the refusal carries no detail");
  assert.equal(B.session.status, "open", "a refused grant.issue keeps the session open");
  // Positive control: the two devices' own grants link side by side (one link per device and lane).
  const la = await expectAccepted("device A grant", offerA, grantA.token);
  const lbk = await expectAccepted("device B grant", offerA, grantB.token, false);
  la.close();
  lbk.close();
  await expectNoLeak("other device", [r1, denied]);
  record(EVIDENCE, { case: "other_device", refused: true });
});

test("an expired grant is refused", { skip: "needs a validly signed grant past its exp: grants last at least 1 h outside marked e2e homes (PASEO_ROOMS_DEV_SHORT_GRANTS is dropped here) and the module never holds the host key. Covered by test/unit/v2-grants.test.ts and the e2e forced rotation." }, () => {});

// ------------------------------------------------------------------ invites and device links

test("an invite cannot be reused after it was used", { timeout: 120_000 }, async () => {
  // Device A used codeA. A new device proving the right token learns only `invite_used` (5.3 step 7).
  const C = new TestDevice("Negative C");
  const r = await expectNoChange("reused invite", () => preauthCall(codeA, C, (h) => enrollRequest(codeA, C, h, { nm: randomBytes(32), token: "valid" })));
  const e = refusal("reused invite", r);
  await expectNoLeak("reused invite", [e]);
  assert.equal(e.code, "invite_used");
  assert.deepEqual(e.fields, {});
  record(EVIDENCE, { case: "invite_reused_after_use", code: e.code, busyWaitsMs: r.busyWaitsMs });
});

test("an invite is burned after 3 failed token proofs and is then refused even with the right token", { timeout: 300_000 }, async () => {
  const inv = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note: "negative burn" });
  const code = inviteCode(inv.code);
  rememberCode(inv.code, code);
  track(inv.code, code.payload.token);
  const D = new TestDevice("Negative D");
  const nm = randomBytes(32);
  const inviteState = async () => (await ownedRoom(owner, room.roomId)).invites.find((i: any) => i.inviteId === inv.inviteId);
  const errors: unknown[] = [];

  // P-15: a request naming an unknown inviteId touches no invite.
  const unknown = await expectNoChange("unknown inviteId", () => preauthCall(code, D, (h) => enrollRequest(code, D, h, { nm, token: "valid", target: { inviteId: newId("invite") } })));
  errors.push(refusal("unknown inviteId", unknown));
  // P-23: the signature over THIS session's h is checked before any lookup; a bad one counts nothing.
  const badSig = await expectNoChange("signature over another h", () => preauthCall(code, D, () => enrollRequest(code, D, b64u(randomBytes(32)), { nm, token: "valid" })));
  errors.push(refusal("signature over another h", badSig));

  // Three wrong token proofs: the same generic refusal each time; the third burns the invite (5.4).
  for (let i = 1; i <= 3; i++) {
    const from = logLength(room.roomId);
    const r = await preauthCall(code, D, (h) => enrollRequest(code, D, h, { nm, token: "wrong" }));
    errors.push(refusal(`wrong token ${i}`, r));
    await sleep(500);
    const st = await inviteState();
    assert.equal(st?.failedProofs, i, `failed proofs counted after attempt ${i}`);
    assert.equal(st?.state, i < 3 ? "open" : "burned", `invite state after attempt ${i}`);
    assert.deepEqual(newEntryTypes(room.roomId, from), i < 3 ? [] : ["invite.burned"], `log entries after attempt ${i}`);
  }
  // The right token on a burned invite: the requester proved the token, so it may learn the state.
  const right = await expectNoChange("right token after burn", () => preauthCall(code, D, (h) => enrollRequest(code, D, h, { nm, token: "valid" })));
  const last = refusal("right token after burn", right);

  await expectNoLeak("invite burn", errors.concat([last]));
  for (const e of errors) assert.deepEqual(e, { code: "enroll_rejected", fields: {} }, "every refusal before the token proof is the same generic one");
  assert.deepEqual(last, { code: "invite_revoked", fields: {} }, "a burned invite is refused as revoked");
  record(EVIDENCE, { case: "invite_burn", attempts: 3, final: last.code });
});

test("a device link code is burned after 3 failed token proofs and is then refused", { timeout: 300_000 }, async () => {
  // Device A (an active device) creates a link over its own session; the host logs device.link.created.
  const created = await createLinkCode(A, room.roomId);
  const code = linkCode(created.code);
  rememberCode(created.code, code);
  track(created.code, code.payload.token);
  const E = new TestDevice("Negative E");
  const nm = randomBytes(32);
  const errors: unknown[] = [];
  for (let i = 1; i <= 3; i++) {
    const from = logLength(room.roomId);
    const r = await preauthCall(code, E, (h) => enrollRequest(code, E, h, { nm, token: "wrong" }));
    errors.push(refusal(`wrong link token ${i}`, r));
    await sleep(500);
    assert.deepEqual(newEntryTypes(room.roomId, from), i < 3 ? [] : ["invite.burned"], `log entries after attempt ${i}`);
  }
  const right = await expectNoChange("right link token after burn", () => preauthCall(code, E, (h) => enrollRequest(code, E, h, { nm, token: "valid" })));
  const last = refusal("right link token after burn", right);
  await expectNoLeak("link burn", errors.concat([last]));
  for (const e of errors) assert.deepEqual(e, { code: "enroll_rejected", fields: {} });
  assert.deepEqual(last, { code: "invite_revoked", fields: {} });
  // Device A never got a link.request: no pending enrollment was formed.
  assert.equal(A.pushes.some((f) => f.t === "link.request"), false, "no link.request reached the creating device");
  record(EVIDENCE, { case: "link_burn", attempts: 3, final: last.code });
});

test("enrollment resume: a request replayed in another session and a resume from another key are refused; h stays pinned", { timeout: 180_000 }, async () => {
  const inv = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note: "negative resume" });
  const code = inviteCode(inv.code);
  rememberCode(inv.code, code);
  track(inv.code, code.payload.token);
  const F = new TestDevice("Negative F");
  const nm = randomBytes(32);

  // Session 1: a valid request; the host pins this session's h (enrollment-v2 5.6).
  let frame1: ReturnType<typeof enrollRequest> | null = null;
  const first = await preauthCall(code, F, (h) => (frame1 = enrollRequest(code, F, h, { nm, token: "valid" })));
  assert.equal(first.reply?.t, "enroll.pending", "the first request creates a pending enrollment");
  const h1 = first.h!;
  const { t: _t, re: _re, ...content } = first.reply!;
  const pendingId = String(content.pendingId);
  assert.equal(content.h, h1, "the pending is pinned to session 1's h");

  // (a) The same request bytes in a new session: its signature covers h1, not this session's h.
  const replay = await expectNoChange("request replayed in another session", () => preauthCall(code, F, () => frame1!));
  const eReplay = refusal("request replayed in another session", replay);
  assert.notEqual(replay.h, h1);

  // (b) enroll.resume from the same key: the stored pending, byte for byte, still pinned to h1.
  const s3 = await preauthSession(code, F);
  let resumed: Record<string, unknown>;
  try {
    resumed = await expectNoChange("resume from the same key", () => s3.request({ t: "enroll.resume", pendingId }));
    assert.notEqual(s3.handshakeHash, h1);
  } finally {
    s3.close();
  }
  assert.equal(resumed.t, "enroll.resume.ok");
  const pending = resumed.pending as Record<string, unknown>;
  assert.equal(pending.h, h1, "resume returns the h pinned in session 1, never the new session's");
  assert.equal(rjcsText(pending as RjcsValue), rjcsText(content as RjcsValue), "resume returns the stored pending byte for byte");

  // (c) enroll.resume of F's pending from another static key: generic (5.6 rule 1).
  const G = new TestDevice("Negative G");
  const other = await expectNoChange("resume from another key", () => preauthCall(code, G, () => ({ t: "enroll.resume", pendingId })));
  const eOther = refusal("resume from another key", other);

  await expectNoLeak("resume", [eReplay, eOther, resumed]);
  assert.deepEqual(eReplay, { code: "enroll_rejected", fields: {} });
  assert.deepEqual(eOther, { code: "enroll_rejected", fields: {} });

  // Cleanup: F abandons its attempt (counts one abandoned attempt on this invite, by design).
  const abort = await preauthCall(code, F, () => ({ t: "enroll.abort", pendingId, reason: "cancelled" }));
  assert.equal(abort.reply?.t, "enroll.abort.ok");
  record(EVIDENCE, { case: "resume_h_pinned", replay: eReplay.code, otherKey: eOther.code });
});

// ------------------------------------------------------------------ removed device

test("a removed device: its session ends, reconnecting and its grant are refused, its key cannot re-enroll", { timeout: 180_000 }, async () => {
  await adminRpc(owner, "rooms.v2.member.remove", { roomId: room.roomId, memberId: B.memberId });
  await until("device B's session ended", () => (B.session.status === "ended" ? true : null), 15_000, 100);
  assert.equal(B.session.endedReason, "removed");
  await until("removal settled on the owner", async () => {
    const r = await ownedRoom(owner, room.roomId);
    return !r.roster.some((m: any) => m.memberId === B.memberId) && !r.grants.some((g: any) => g.deviceId === B.deviceId);
  }, 15_000, 250);

  // (a) A new session with the removed device's DH key: access_ended {removed}, revealed only to the
  //     holder of that key and only after the handshake (P-23).
  const reconnect = await expectNoChange("removed device reconnects", async () => {
    try {
      await openMemberSession(B.device, B.genesis, B.relay, []);
      return null;
    } catch (e) {
      return errorOf(e);
    }
  });
  assert.deepEqual(reconnect, { code: "access_ended", fields: { reason: "removed" } });

  // (b) Its grant, issued before the removal.
  const rGrant = await expectNoChange("removed device's grant", () => expectGenericRefusal("removed device's grant", offerA, grantB.token));

  // (c) Its signing key with a new DH key, on a fresh invite with the right token: the key is not
  //     reusable (5.3 step 8), so the generic refusal; the invite stays open and untouched.
  const inv = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note: "negative reuse key" });
  const code = inviteCode(inv.code);
  rememberCode(inv.code, code);
  track(inv.code, code.payload.token);
  const reuse = new TestDevice("Negative B again", B.device.sigSeed);
  const r = await expectNoChange("removed signing key re-enrolls", () => preauthCall(code, reuse, (h) => enrollRequest(code, reuse, h, { nm: randomBytes(32), token: "valid" })));
  const eReuse = refusal("removed signing key re-enrolls", r);
  await rpc(owner, "rooms.v2.invite.revoke", { roomId: room.roomId, inviteId: inv.inviteId });

  await expectNoLeak("removed device", [reconnect, rGrant, eReuse]);
  assert.deepEqual(eReuse, { code: "enroll_rejected", fields: {} });
  record(EVIDENCE, { case: "removed_device", reconnect: reconnect?.code, reuse: eReuse.code });
});

// ------------------------------------------------------------------ viewer role

test("a viewer (watch) route cannot call owner-only RPCs or send out-of-profile messages", { timeout: 120_000 }, async () => {
  const link = await expectAccepted("viewer link", offerA, grantA.token);
  try {
    const opened = await link.openRoute("sec-route-1");
    assert.ok(opened && "routeId" in opened, "a route opens on an accepted link");
    const routeId = (opened as { routeId: string }).routeId;
    await link.routeSend(routeId, { type: "hello", clientId: "rooms-sec-viewer", clientType: "mobile", protocolVersion: 1, appVersion: "0.13.2", capabilities: {} });
    const status = await link.routeNext(routeId, (m) => m?.type === "session" && m.message?.type === "status", 20_000);
    assert.ok(status, "the routed view gets the lane's server_info");

    const reply = (rid: string) => link.routeNext(routeId, (m) => m?.type === "session" && m.message?.payload?.requestId === rid, 10_000);
    // Positive control: the lane's own agent is readable (forwarded, read only).
    await link.routeSend(routeId, { type: "session", message: { type: "fetch_agent_request", requestId: "sec-ok-1", agentId: PARENT() } });
    const ok = await reply("sec-ok-1");
    assert.equal(ok?.message?.type, "fetch_agent_response", "the lane agent is readable through the route");

    const bogusAgent = `agent-does-not-exist-${randomBytes(4).toString("hex")}`;
    const parentBefore = await owner.fetchAgent(PARENT());
    const ownedBefore = (await rpc(owner, "rooms.v2.status", {})).owned.length;
    // Owner-only plugin RPCs and messages outside the watch profile. Prompting and archive messages name
    // a made-up agent: if the filter ever failed, they still could not reach a real agent or a model.
    const denied: Array<[string, Record<string, unknown>]> = [
      ["plugin.rpc.invoke.request", { pluginId: "rooms", method: "rooms.v2.status", input: {} }],
      ["plugin.rpc.invoke.request", { pluginId: "rooms", method: "rooms.v2.lane.errors", input: { roomId: room.roomId, laneId: room.laneId } }],
      ["plugin.rpc.invoke.request", { pluginId: "rooms", method: "rooms.v2.admin.prepare", input: { action: { kind: "invite.create", roomId: room.roomId } } }],
      ["send_agent_message_request", { agentId: bogusAgent, text: "security test: must be refused" }],
      ["archive_agent_request", { agentId: bogusAgent }],
      ["capture_terminal_request", { terminalId: "term-does-not-exist" }],
      ["fetch_agent_request", { agentId: bogusAgent }],
      ["rooms.security.unknown_request", {}],
    ];
    const replies: unknown[] = [];
    await expectNoChange("viewer out-of-profile messages", async () => {
      let i = 0;
      for (const [type, fields] of denied) {
        const rid = `sec-deny-${++i}`;
        await link.routeSend(routeId, { type: "session", message: { type, requestId: rid, ...fields } });
        const m = await reply(rid);
        replies.push(m);
        assert.ok(containsNone(JSON.stringify(m), secrets), `${type}: the refusal contains a tracked secret`);
        assert.equal(m?.message?.type, "rpc_error", `${type}: expected a refusal`);
        assert.deepEqual(m.message.payload, { requestId: rid, requestType: type, error: `Room is not authorized for ${type}`, code: "access_denied" }, `${type}: generic refusal only`);
      }
    });
    // A message without a requestId is dropped silently; a binary link frame is dropped; both keep the link.
    await link.routeSend(routeId, { type: "session", message: { type: "send_agent_message_request", agentId: bogusAgent, text: "no request id" } });
    await link.sendBinary(new Uint8Array(64));
    await link.ping();
    assert.ok(await link.next((f) => f?.type === "pong", 5000), "the link still answers after dropped frames");
    await link.routeSend(routeId, { type: "session", message: { type: "fetch_agent_request", requestId: "sec-ok-2", agentId: PARENT() } });
    assert.equal((await reply("sec-ok-2"))?.message?.type, "fetch_agent_response", "the route still works after the refusals");

    const parentAfter = await owner.fetchAgent(PARENT());
    assert.equal(parentAfter?.agent?.status, parentBefore?.agent?.status, "the lane agent's status is unchanged");
    assert.equal(parentAfter?.agent?.archivedAt ?? null, null, "the lane agent is not archived");
    assert.equal((await rpc(owner, "rooms.v2.status", {})).owned.length, ownedBefore, "no room was created or removed");
    await expectNoLeak("viewer route", replies);
    record(EVIDENCE, { case: "viewer_route", denied: denied.length });
  } finally {
    link.close();
  }
});

test("a viewer device cannot run admin-only room session operations", { timeout: 60_000 }, async () => {
  const self = (await ownedRoom(owner, room.roomId)).roster.find((m: any) => m.self);
  const ownerDevice = self?.devices[0]?.deviceId;
  assert.ok(self && ownerDevice, "the owner's own member and device are in the roster");
  const attempt = async (frame: Record<string, RjcsValue>) => {
    try {
      await A.session.request(frame as never);
      return null;
    } catch (e) {
      return errorOf(e);
    }
  };
  const results = await expectNoChange("viewer admin operations", async () => ({
    // An admin statement from a watch device: refused before the statement is even parsed (section 4).
    adminStatement: await attempt({ t: "stmt.submit", statement: { body: { producer: { kind: "admin", kid: A.device.sigKid } } } }),
    // KeyPackages of the rekey pool are for admin devices only (mls-integration 6.4).
    rekeyPackages: await attempt({ t: "kp.fetch", targets: [{ memberId: self.memberId, deviceId: ownerDevice, for: "rekey", count: 1 }] }),
  }));
  await expectNoLeak("viewer admin operations", [results]);
  assert.deepEqual(results.adminStatement, { code: "not_permitted", fields: {} });
  assert.deepEqual(results.rekeyPackages, { code: "not_permitted", fields: {} });
  assert.equal(A.session.status, "open", "refusals keep the device's session open");
  record(EVIDENCE, { case: "viewer_session_ops", refused: 2 });
});

// ------------------------------------------------------------------ final

test("after every refusal the current grant still works and the owner's log holds no tracked secret", { timeout: 60_000 }, async () => {
  (await expectAccepted("final positive control", offerA, grantA.token)).close();
  assert.ok(await ownerLogsClean(secrets), "the owner's plugin log contains a tracked secret");
  log("credneg_done", { secretsChecked: secrets.length });
  record(EVIDENCE, { case: "final", secretsChecked: secrets.length });
});
