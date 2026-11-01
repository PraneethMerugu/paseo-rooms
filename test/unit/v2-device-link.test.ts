// Identity v2 milestone I-11: device linking and holds (identity-model.md 6.3, 6.4; enrollment-v2.md
// 5.2, 5.4, 6.2; room-log-v2.md 4.2, 4.3, 5; HARDENING-PLAN decisions round 4, R-2, S-13).
//
// - The `deviceLink` vectors, read from vectors.json, reproduced by the production code.
// - The confirming device's own limits (R-2), with a scripted host: the host cannot choose Nc; a
//   fourth link request is refused locally, also after a restart.
// - End to end in process over the fake relay, with the owner's runtime on a test home whose clock may
//   be moved forward (server/platform/test-clock.ts): a sole device's add is held 72 h and then
//   approved automatically; a veto opens a conflict; under policy soleDeviceChange "admin" only an
//   admin's approval admits the device.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { AdminHoldClock } from "../../server/admin/hold-clock";
import { autoApprovalBlocker, autoApprovalEndsAt, HOLD_MS, SOLE_HOLD_MS } from "../../server/authority/holds";
import type { RoomState } from "../../server/authority/state";
import type { Kek } from "../../server/keystore/keystore";
import { DeviceLinker, LINK_LIMITS } from "../../server/member/device-link";
import { checkInvite } from "../../server/member/invite-check";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { decodeLink, deviceAddedData, encodeLink, LinkCodeError, newDeviceKeyChange, signDeviceStatement, signNewKey } from "../../server/proto/device-link";
import { computeSas, enrollSigned, enrollTokenMac, sasCommitOf, signEnroll, tokenKeyOf, type EnrollSigned } from "../../server/proto/enroll";
import { linkRef, newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid, rawPublicKey } from "../../server/proto/keys";
import { rjcsText } from "../../server/proto/rjcs";
import { TEST_CLOCK_ENV, TEST_HOME_MARKER, TEST_HOME_MARKER_TEXT, TestClock, testClockRefusal } from "../../server/platform/test-clock";
import type { Frame } from "../../server/transport/records";
import { startFakeRelay, until } from "./fake-relay";
import { tempDir } from "./helpers";

const V = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json"), "utf8")) as any;
const D = V.deviceLink;
const hex = (h: string) => Buffer.from(h, "hex");
const seedKey = (name: string) => ed25519PrivateKeyFromSeed(hex(V.keys[name].seedHex));
const HOUR = 60 * 60 * 1000;

// ------------------------------------------------------------------------------ vectors

test("deviceLink vectors: prl2 code, linkRef, link token key, B's request, token MAC", () => {
  assert.equal(encodeLink(D.payload), D.code);
  assert.deepEqual(decodeLink(D.code), D.payload);
  assert.throws(() => decodeLink(V.invite.code), (e: unknown) => e instanceof LinkCodeError && e.code === "not_link");
  assert.throws(() => decodeLink("prl2.AAAA"), (e: unknown) => e instanceof LinkCodeError && e.code === "malformed");
  assert.equal(linkRef(D.payload.linkId), D.linkRef);
  const tokenKey = tokenKeyOf(b64uDecode(D.payload.token, 32), "link");
  assert.equal(tokenKey.toString("hex"), D.tokenKeyHex);
  // B's EnrollSigned names the link, signed by B's (phone) key; the MAC uses the link's token key.
  const signed = enrollSigned({
    h: b64u(hex(D.noise.handshakeHash)),
    genesisHash: D.payload.genesisHash,
    target: { linkId: D.payload.linkId },
    deviceSig: D.signedObject.deviceSig,
    deviceDh: D.signedObject.deviceDh,
    label: D.signedObject.label,
    sasCommit: D.signedObject.sasCommit,
  });
  assert.equal(rjcsText(signed), rjcsText(D.signedObject));
  assert.equal(b64u(signEnroll(seedKey("phoneSig"), signed)), D.sig);
  assert.equal(b64u(enrollTokenMac(tokenKey, signed)), D.tokenMac);
  // A device link code passes the member-side checks of an invite (enrollment-v2 2.3) and says so.
  const checked = checkInvite(D.code, { nowS: D.payload.exp - 60, trustedRelays: ["relay.paseo.sh:443"] });
  assert.equal(checked.preview.kind, "device-link");
  assert.equal(checked.preview.relay.trusted, true);
});

test("deviceLink vectors: the SAS uses the confirming device's nonce Nc; device.link.created and device.added", () => {
  const sas = computeSas({
    h: hex(D.noise.handshakeHash),
    nm: hex(D.sas.NmHex),
    nh: hex(D.sas.NhHex),
    deviceDh: D.signedObject.deviceDh,
    deviceSig: D.signedObject.deviceSig,
    endpointDh: D.payload.endpoint.dh.pub,
    genesisHash: D.payload.genesisHash,
    target: { linkId: D.payload.linkId },
  });
  assert.equal(sas.digits, D.sas.digits);
  assert.equal(sas.display, D.sas.display);
  assert.equal(sas.transcript, D.sas.transcriptHash);
  assert.equal(sasCommitOf(hex(D.sas.NmHex)), D.sas.commit);

  // A's statements, reproduced byte for byte by the production signer (Ed25519 is deterministic).
  const lc = D.linkCreated.body;
  const created = signDeviceStatement({ type: "device.link.created", roomId: lc.roomId, kid: lc.producer.kid, key: seedKey("devSig"), base: lc.base, ts: lc.ts, data: lc.data });
  assert.equal(rjcsText(created), rjcsText(D.linkCreated));
  const da = D.deviceAdded.body;
  const dev = da.data.device;
  const change = newDeviceKeyChange(da.roomId, dev.deviceId, dev.sig, dev.dh);
  assert.equal(rjcsText(change), rjcsText(da.data.change));
  assert.equal(signNewKey(seedKey("phoneSig"), change), da.data.newKeySig);
  const data = deviceAddedData({ roomId: da.roomId, memberId: da.data.memberId, deviceId: dev.deviceId, deviceSig: dev.sig, deviceDh: dev.dh, newKeySig: da.data.newKeySig, addedBy: da.data.addedBy, linkId: D.payload.linkId, transcript: D.sas.transcriptHash });
  assert.equal(rjcsText(data), rjcsText(da.data));
  const added = signDeviceStatement({ type: "device.added", roomId: da.roomId, kid: da.producer.kid, key: seedKey("devSig"), base: da.base, ts: da.ts, data });
  assert.equal(rjcsText(added), rjcsText(D.deviceAdded));
  // The vector's approval comes exactly 72 h after the request of a sole device.
  assert.equal(D.chain.holdMs, SOLE_HOLD_MS);
  assert.equal(D.chain.entries[2].entry.hts - D.chain.entries[1].entry.hts, SOLE_HOLD_MS);
});

// ------------------------------------------------------------------------------ the confirming device's limits (R-2)

type Event = ["write"] | ["send", string];

function scriptedHost() {
  let stored: unknown = undefined;
  const events: Event[] = [];
  const sent: Frame[] = [];
  const session = {
    head: { seq: 3, hash: b64u(randomBytes(32)) },
    async request(frame: Omit<Frame, "id">): Promise<Frame> {
      events.push(["send", String(frame.t)]);
      sent.push(frame as Frame);
      if (frame.t === "device.link.create") return { t: "device.link.create.ok", re: 1, receipt: { entry: { seq: 4 }, hash: b64u(randomBytes(32)) } } as unknown as Frame;
      return { t: `${frame.t}.ok`, re: 1 } as Frame;
    },
  };
  const store = {
    read: () => stored,
    write: (v: unknown) => {
      events.push(["write"]);
      stored = structuredClone(v);
    },
  };
  return { session, store, events, sent };
}

function linker(host: ReturnType<typeof scriptedHost>, o: { now?: () => number; random?: (n: number) => Buffer } = {}) {
  const P = D.payload;
  const key = seedKey("devSig");
  return new DeviceLinker({
    roomId: P.roomId,
    genesisHash: P.genesisHash,
    memberId: D.linkCreated.body.data.memberId,
    deviceId: D.deviceAdded.body.data.addedBy,
    sigKid: kid("ed25519", rawPublicKey(key)),
    sigKey: () => key,
    endpoint: () => P.endpoint,
    session: () => host.session,
    store: host.store,
    ...o,
  });
}

/** A new device B's request as the host pushes it to A (6.4 step 2): B's keys, any h, B's commitment. */
function linkRequest(linkId: string, o: { pendingId?: string; h?: string; nm?: Buffer; b?: { sig: ReturnType<typeof generateKeyPairSync>; dh: string } } = {}) {
  const sigPair = o.b?.sig ?? generateKeyPairSync("ed25519");
  const deviceSig = b64u(rawPublicKey(sigPair.publicKey));
  const deviceDh = o.b?.dh ?? b64u(rawPublicKey(generateKeyPairSync("x25519").publicKey));
  const nm = o.nm ?? randomBytes(32);
  const request: EnrollSigned = enrollSigned({ h: o.h ?? b64u(randomBytes(32)), genesisHash: D.payload.genesisHash, target: { linkId }, deviceSig, deviceDh, label: "Sam phone", sasCommit: sasCommitOf(nm) });
  const pendingId = o.pendingId ?? newId("pending");
  const deviceId = newId("device");
  const frame = { t: "link.request", pendingId, linkId, deviceId, request, sig: b64u(signEnroll(sigPair.privateKey, request)) } as unknown as Frame;
  return { frame, nm, pendingId, deviceId, deviceSig, deviceDh, sigKey: sigPair.privateKey, b: { sig: sigPair, dh: deviceDh } };
}

const tick = () => new Promise((r) => setImmediate(r));
const sentOf = (host: ReturnType<typeof scriptedHost>, t: string) => host.sent.filter((f) => f.t === t);

test("R-2: the host cannot choose Nc; A pins the request and persists before link.nonce; a changed re-push burns the link", async () => {
  const host = scriptedHost();
  const ncs: Buffer[] = [];
  const random = (n: number) => {
    const b = randomBytes(n);
    if (n === 32) ncs.push(Buffer.from(b));
    return b;
  };
  const a = linker(host, { random });
  const { linkId, code } = await a.create({ roomName: "Lab" });
  assert.ok(code.startsWith("prl2.") && decodeLink(code).linkId === linkId);
  assert.equal(code.includes(b64u(tokenKeyOf(b64uDecode(decodeLink(code).token, 32), "link"))), false, "the code carries the token, never the token key");
  const create = sentOf(host, "device.link.create")[0];
  assert.equal((create.statement as { body: { data: { linkRef: string } } }).body.data.linkRef, linkRef(linkId));
  assert.equal(typeof create.tokenKey, "string");
  assert.equal(JSON.stringify(create).includes(decodeLink(code).token), false, "the token never reaches the host");

  const r1 = linkRequest(linkId);
  host.events.length = 0;
  a.onPush(r1.frame);
  await tick();
  // Pin and counter written (sealed, fsync) before the nonce goes out.
  assert.deepEqual(host.events, [["write"], ["send", "link.nonce"]]);
  const n1 = sentOf(host, "link.nonce")[0];
  assert.equal(n1.Nc, b64u(ncs.at(-1)!), "Nc comes from A's own randomness; the request carries no nonce field the host could set");
  // A lost reply: the identical request gets the same pinned Nc, not a new one.
  a.onPush(r1.frame);
  await tick();
  assert.deepEqual(sentOf(host, "link.nonce").map((f) => f.Nc), [n1.Nc, n1.Nc]);
  // The host reveals B's Nm: A checks the commitment and computes the SAS from its pinned inputs and its Nc.
  const change = newDeviceKeyChange(D.payload.roomId, r1.deviceId, r1.deviceSig, r1.deviceDh);
  a.onPush({ t: "link.reveal", pendingId: r1.pendingId, Nm: b64u(r1.nm), newKeySig: signNewKey(r1.sigKey, change) } as unknown as Frame);
  await tick();
  const expected = computeSas({ h: b64uDecode((r1.frame.request as unknown as EnrollSigned).h, 32), nm: r1.nm, nh: b64uDecode(n1.Nc as string, 32), deviceDh: r1.deviceDh, deviceSig: r1.deviceSig, endpointDh: D.payload.endpoint.dh.pub, genesisHash: D.payload.genesisHash, target: { linkId } });
  assert.equal(a.view()[0].pending?.sas, expected.display);
  // A re-push of the same pendingId with a different commitment (a host grinding B') burns the link.
  const ground = linkRequest(linkId, { pendingId: r1.pendingId, h: (r1.frame.request as unknown as EnrollSigned).h, b: r1.b });
  a.onPush(ground.frame);
  await tick();
  assert.equal(a.view()[0].burned, "attempts");
  assert.equal(sentOf(host, "link.abort").at(-1)?.reason, "attempts");
  assert.equal(sentOf(host, "link.nonce").length, 2, "no nonce for the changed request");
  await assert.rejects(a.confirm(r1.pendingId, true), /aborted/);
});

test("R-2: a reveal that does not open the commitment, or a bad newKeySig, shows no SAS", async () => {
  const host = scriptedHost();
  const a = linker(host);
  const { linkId } = await a.create();
  const r = linkRequest(linkId);
  a.onPush(r.frame);
  await tick();
  const change = newDeviceKeyChange(D.payload.roomId, r.deviceId, r.deviceSig, r.deviceDh);
  a.onPush({ t: "link.reveal", pendingId: r.pendingId, Nm: b64u(randomBytes(32)), newKeySig: signNewKey(r.sigKey, change) } as unknown as Frame);
  await tick();
  assert.equal(a.view()[0].pending?.sas, null);
  assert.equal(a.view()[0].pending?.state, "aborted");
  assert.equal(sentOf(host, "link.abort").at(-1)?.reason, "cancelled");
});

test("R-2: one open pending per link; a fourth link request is refused locally, and still after a restart", async () => {
  const host = scriptedHost();
  let now = Date.now();
  const a = linker(host, { now: () => now });
  const { linkId } = await a.create();
  const nonces = () => sentOf(host, "link.nonce").length;
  // Attempt 1. A second request while it is open gets no answer and does not count.
  const r1 = linkRequest(linkId);
  a.onPush(r1.frame);
  await tick();
  a.onPush(linkRequest(linkId).frame);
  await tick();
  assert.equal(nonces(), 1);
  assert.equal(a.view()[0].attempts, 1);
  // The host closes attempt 1 (abandoned); attempt 2 is answered.
  a.onPush({ t: "link.closed", linkId, pendingId: r1.pendingId, reason: "abandoned" } as unknown as Frame);
  const r2 = linkRequest(linkId);
  a.onPush(r2.frame);
  await tick();
  assert.equal(nonces(), 2);
  // Attempt 2 stays open (no link.closed): another request is still not answered, minutes later.
  now += 5 * 60 * 1000;
  a.onPush(linkRequest(linkId).frame);
  await tick();
  assert.equal(nonces(), 2, "still open");
  a.onPush({ t: "link.closed", linkId, pendingId: r2.pendingId, reason: "timeout" } as unknown as Frame);
  const r3 = linkRequest(linkId);
  a.onPush(r3.frame);
  await tick();
  assert.equal(nonces(), 3);
  assert.equal(a.view()[0].pending?.earlierAttempts, 2, "the confirmation screen shows 2 earlier attempts");
  a.onPush({ t: "link.closed", linkId, pendingId: r3.pendingId, reason: "abandoned" } as unknown as Frame);
  // The fourth request: no nonce, the link is burned and the host told so.
  const r4 = linkRequest(linkId);
  a.onPush(r4.frame);
  await tick();
  assert.equal(nonces(), 3, "no link.nonce for a fourth attempt");
  assert.equal(a.view()[0].burned, "attempts");
  assert.deepEqual(sentOf(host, "link.abort").map((f) => [f.pendingId, f.reason]), [[r4.pendingId, "attempts"]]);
  // A restart of A (a new instance over the same sealed state): the count is still 3 and nothing is answered.
  const restarted = linker(host, { now: () => now });
  assert.equal(restarted.view()[0].attempts, 3);
  assert.equal(restarted.view()[0].burned, "attempts");
  restarted.onPush(linkRequest(linkId).frame);
  await tick();
  assert.equal(nonces(), 3);
  assert.equal(sentOf(host, "link.abort").length, 1, "a burned link answers nothing further");
});

test("R-2: a request for a link past its exp on A's clock gets no nonce and does not count", async () => {
  const host = scriptedHost();
  let now = Date.now();
  // The link is created 9 minutes back on A's clock; the second request comes after its exp.
  const a = linker(host, { now: () => now });
  now -= 9 * 60 * 1000;
  const { linkId } = await a.create();
  now += 9 * 60 * 1000 - 30_000; // 30 s before exp
  const r1 = linkRequest(linkId);
  a.onPush(r1.frame);
  await tick();
  assert.equal(sentOf(host, "link.nonce").length, 1);
  now += LINK_LIMITS.openPendingTtlMs + 1000; // r1 is past 15 minutes, and the link is past exp + grace
  a.onPush(linkRequest(linkId).frame);
  await tick();
  assert.equal(sentOf(host, "link.nonce").length, 1, "expired: no answer");
  assert.equal(a.view()[0].attempts, 1, "and no count");
  assert.equal(a.view()[0].burned, null);
});

test("R-2: the count survives a restart before the limit too; Codes do not match burns the link locally", async () => {
  const host = scriptedHost();
  const a = linker(host);
  const { linkId } = await a.create();
  for (let i = 0; i < 3; i++) {
    const r = linkRequest(linkId);
    linker(host).onPush(r.frame); // a fresh instance each time: every attempt is read back from the sealed state
    await tick();
    linker(host).onPush({ t: "link.closed", linkId, pendingId: r.pendingId, reason: "timeout" } as unknown as Frame);
  }
  assert.equal(linker(host).view()[0].attempts, 3);
  linker(host).onPush(linkRequest(linkId).frame);
  await tick();
  assert.equal(sentOf(host, "link.nonce").length, 3);

  const host2 = scriptedHost();
  const b = linker(host2);
  const l2 = await b.create();
  const r = linkRequest(l2.linkId);
  b.onPush(r.frame);
  await tick();
  b.onPush({ t: "link.reveal", pendingId: r.pendingId, Nm: b64u(r.nm), newKeySig: signNewKey(r.sigKey, newDeviceKeyChange(D.payload.roomId, r.deviceId, r.deviceSig, r.deviceDh)) } as unknown as Frame);
  await tick();
  await b.confirm(r.pendingId, false);
  assert.equal(b.view()[0].burned, "sas_mismatch");
  assert.equal(sentOf(host2, "link.abort").at(-1)?.reason, "sas_mismatch");
  assert.equal(sentOf(host2, "link.confirm").length, 0);
});

// ------------------------------------------------------------------------------ test clock gate

test("test clock: only on a marked v2-* home under .test-homes with the switch; never on ~/.paseo", () => {
  const t = tempDir();
  try {
    const homes = join(t.dir, ".test-homes");
    const home = join(homes, "v2-owner");
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const env = { [TEST_CLOCK_ENV]: "1" };
    assert.equal(testClockRefusal({}, home), "switch_off");
    assert.equal(testClockRefusal(env, home), "no_marker");
    writeFileSync(join(home, TEST_HOME_MARKER), "something else\n");
    assert.equal(testClockRefusal(env, home), "bad_marker");
    writeFileSync(join(home, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT);
    assert.equal(testClockRefusal(env, home), null);
    // Elsewhere: not a .test-homes/v2-* directory, or the user's main home, even with a marker.
    const other = join(t.dir, "v2-owner");
    mkdirSync(other);
    writeFileSync(join(other, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT);
    assert.equal(testClockRefusal(env, other), "not_a_test_home");
    assert.equal(testClockRefusal(env, home, { homedir: () => join(homes, "v2-owner", "..", "v2-owner", "..") }), null);
    const fakeUser = join(t.dir, "user");
    mkdirSync(join(fakeUser), { recursive: true });
    symlinkSync(home, join(fakeUser, ".paseo"));
    assert.equal(testClockRefusal(env, home, { homedir: () => fakeUser }), "main_home", "a test home that is ~/.paseo is refused");
    // A symlinked marker is refused.
    const h2 = join(homes, "v2-member");
    mkdirSync(h2);
    symlinkSync(join(home, TEST_HOME_MARKER), join(h2, TEST_HOME_MARKER));
    assert.equal(testClockRefusal(env, h2), "bad_marker");
    const off = new TestClock({}, home);
    assert.equal(off.enabled, false);
    assert.throws(() => off.advance(HOUR), /not available/);
    const on = new TestClock(env, home);
    const before = on.now();
    on.advance(HOUR);
    assert.ok(on.now() - before >= HOUR);
    assert.throws(() => on.advance(-1));
    assert.throws(() => on.advance(8 * 24 * HOUR));
  } finally {
    t.cleanup();
  }
});

// ------------------------------------------------------------------------------ end to end in process

type Rt = InstanceType<typeof import("../../server/runtime-v2").RoomsRuntimeV2>;

async function linkEnv() {
  const { RoomsRuntimeV2 } = await import("../../server/runtime-v2");
  const t = tempDir();
  const relay = await startFakeRelay();
  const base = { PASEO_ROOMS_KEYSTORE: "fallback-file", PASEO_ROOMS_RELAY_ENDPOINT: `127.0.0.1:${relay.port}`, PASEO_ROOMS_RELAY_TLS: "false", PASEO_ROOMS_DEV_INSECURE_RELAY: "1" };
  const homes = join(t.dir, ".test-homes");
  const mk = (name: string, clock: boolean) => {
    const home = join(homes, `v2-${name}`);
    mkdirSync(home, { recursive: true, mode: 0o700 });
    if (clock) writeFileSync(join(home, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT, { mode: 0o600 });
    return new RoomsRuntimeV2({ PASEO_HOME: home, ...base, ...(clock ? { [TEST_CLOCK_ENV]: "1" } : {}) }, undefined, { allowDevSwitches: true });
  };
  const owner = mk("owner", true);
  const phone = mk("phone", false);
  await Promise.all([owner.start(), phone.start()]);
  assert.equal(owner.clock.enabled, true);
  assert.equal(phone.clock.enabled, false, "no switch, no marker: the real clock");
  return {
    owner,
    phone,
    async cleanup() {
      await phone.stop();
      await owner.stop();
      await relay.close();
      t.cleanup();
    },
  };
}

/**
 * The owner's own device A (the creator, the member's only device) links device B on another
 * daemon. The owner's clock is first moved 25 h forward so A is not a young device. Returns when B is
 * held, after both screens showed the same SAS and both pressed "Codes match".
 */
async function linkPhone(owner: Rt, phone: Rt, o: { policy?: (roomId: string) => void } = {}) {
  const { roomId } = await owner.createRoom();
  await until("endpoint online", () => owner.status().owned.find((r) => r.roomId === roomId)?.endpoint === "online");
  o.policy?.(roomId);
  owner.advanceTestClock(25 * HOUR);
  const c = await owner.connect(roomId);
  assert.equal(c.status, "open");
  const { code } = await owner.createLink(roomId, "Lab");
  assert.ok(code.startsWith("prl2."));
  await phone.startJoin({ code, label: "Sam phone", trustRelay: true });
  const join_ = () => phone.status().joining.find((j) => j.roomId === roomId);
  const link = () => owner.status().joined.find((j) => j.roomId === roomId)!.links[0];
  const bSas = await until("B's SAS", () => join_()?.sas, 5000);
  const aSas = await until("A's SAS", () => link()?.pending?.sas, 5000);
  assert.equal(bSas, aSas, "the person sees the same six digits on both devices");
  assert.equal(link().pending?.earlierAttempts, 0);
  // The host never chose the nonce: B's pinned pending carries A's Nc as Nh.
  const bPending = JSON.parse(phone.joining.get(roomId)!.journal.e.pending!);
  const { readLinkSection } = await import("../../server/member/enrollment-journal");
  const aState = readLinkSection({ dataDir: owner.dataDir, kek: (owner as unknown as { kek: never }).kek, roomId }) as { links: { pins: { nc: string }[] }[] };
  assert.equal(bPending.Nh, aState.links[0].pins[0].nc);
  assert.equal(bPending.deviceId, link().pending?.deviceId);
  await phone.confirmJoin(roomId, true);
  await owner.confirmLink(roomId, link().pending!.pendingId, true);
  await until("B held", () => join_()?.state === "held", 5000);
  const room = () => owner.status().owned.find((r) => r.roomId === roomId)!;
  const req = room().deviceRequests[0];
  assert.equal(req.kind, "add");
  assert.equal(req.status, "pending");
  assert.equal(req.sole, true, "A is the member's only active device");
  assert.equal(req.young, false, "A was active for more than 24 h");
  return { roomId, join: join_, room, req, memberId: req.memberId };
}

test("a sole device's link is held 72 h (not 71), then approved by the admin daemon; B joins as the same person", async () => {
  const env = await linkEnv();
  try {
    const { owner, phone } = env;
    const { roomId, join: join_, room, req, memberId } = await linkPhone(owner, phone);
    // The admin daemon times the hold from when it first saw the request (its own clock), which is at
    // or just after the entry's hts; enroll.held names the hts end the fold checks.
    assert.ok(req.effectiveAfter! >= req.hts + 72 * HOUR && req.effectiveAfter! < req.hts + 72 * HOUR + 2000, `effectiveAfter ${req.effectiveAfter! - req.hts}`);
    assert.equal(phone.joining.get(roomId)!.journal.e.held?.effectiveAfter, req.hts + 72 * HOUR, "enroll.held names when the hold ends");
    // The member's own devices see the request ("Was this you?").
    assert.equal(owner.status().joined.find((j) => j.roomId === roomId)!.deviceRequests[0]?.ref, req.ref);
    owner.advanceTestClock(71 * HOUR);
    owner.autoApprove(roomId);
    assert.equal(room().deviceRequests[0].status, "pending", "71 h: still held");
    assert.equal(join_()?.state, "held");
    owner.advanceTestClock(1 * HOUR + 1000);
    await until("approved", () => room().deviceRequests[0].status === "approved", 5000);
    await until("B admitted and connected", () => phone.status().joined.find((j) => j.roomId === roomId)?.status === "open", 5000);
    const b = phone.status().joined.find((j) => j.roomId === roomId)!;
    assert.equal(b.memberId, memberId, "the same person");
    assert.equal(b.deviceId, req.deviceId);
    const member = owner.ownedHostState(roomId).members[memberId];
    assert.equal(member.devices.length, 2, "one member, two devices, each with its own keys");
    assert.notEqual(member.devices[0].sig, member.devices[1].sig);
    await until("B synced", () => phone.status().joined.find((j) => j.roomId === roomId)!.head.seq === room().head.seq, 5000);
    assert.deepEqual(phone.status().joined.find((j) => j.roomId === roomId)!.alerts, [], "B's own fold accepts the chain, including the 72 h approval");
    assert.equal(owner.status().owned[0].joinRequests.find((p) => p.kind === "link")?.state, "admitted");
  } finally {
    await env.cleanup();
  }
});

test("Not me: a veto closes B's join, opens a device conflict that blocks automatic approval until an admin resolves it", async () => {
  const env = await linkEnv();
  try {
    const { owner, phone } = env;
    const { roomId, join: join_, room, req, memberId } = await linkPhone(owner, phone);
    await owner.vetoDevice(roomId, req.ref);
    await until("B's join closed: vetoed", () => join_()?.state === "failed", 5000);
    assert.equal(join_()?.failure, "closed:vetoed");
    assert.equal(room().deviceRequests[0].status, "vetoed");
    assert.deepEqual(room().conflicts, [memberId]);
    assert.equal(owner.status().joined.find((j) => j.roomId === roomId)!.conflict, true);
    owner.advanceTestClock(73 * HOUR);
    owner.autoApprove(roomId);
    assert.equal(room().deviceRequests[0].status, "vetoed", "no approval of a vetoed request");
    await assert.rejects(owner.approveDevice(roomId, req.ref), /vetoed/, "an admin cannot approve it either");
    await owner.resolveConflict(roomId, memberId);
    assert.deepEqual(room().conflicts, []);
    assert.equal(owner.ownedHostState(roomId).members[memberId].devices.length, 1);
  } finally {
    await env.cleanup();
  }
});

test("policy soleDeviceChange admin: no hold and no automatic approval; an admin's approval admits B", async () => {
  const env = await linkEnv();
  try {
    const { owner, phone } = env;
    const setPolicy = (roomId: string) => {
      const ver = owner.ownedHostState(roomId).auth.versions["policy:soleDeviceChange"] ?? -1;
      (owner as unknown as { adminSubmit(r: string, t: string, d: unknown): unknown }).adminSubmit(roomId, "room.policy.changed", { changes: [{ setting: "soleDeviceChange", value: "admin", ver }] });
    };
    const { roomId, join: join_, room, req, memberId } = await linkPhone(owner, phone, { policy: setPolicy });
    assert.equal(req.effectiveAfter, null, "an admin must approve");
    assert.equal(phone.joining.get(roomId)!.journal.e.held?.effectiveAfter, null);
    const st = owner.ownedHostState(roomId);
    assert.equal(autoApprovalBlocker(st, st.pending[req.ref])?.reason, "auto_not_allowed");
    assert.equal(autoApprovalEndsAt(st, st.pending[req.ref]), null);
    owner.advanceTestClock(80 * HOUR);
    owner.autoApprove(roomId);
    assert.equal(room().deviceRequests[0].status, "pending", "never approved automatically");
    assert.equal(join_()?.state, "held");
    await owner.approveDevice(roomId, req.ref);
    await until("B admitted", () => phone.status().joined.find((j) => j.roomId === roomId)?.status === "open", 5000);
    assert.equal(owner.ownedHostState(roomId).members[memberId].devices.length, 2);
    // Enrollment 5.7 (round 9, item 3): the held and admission entries were checked against the log.
    const anchors = phone.joining.get(roomId)!.journal.preAdmissionAnchors();
    assert.deepEqual(anchors.map((a) => [a.source, a.signed.entry.type]), [["held", "device.added"], ["admission", "device.add.approved"]]);
    assert.deepEqual(phone.status().joined.find((j) => j.roomId === roomId)?.alerts, []);
  } finally {
    await env.cleanup();
  }
});

test("removing the requesting device cancels the held add in the fold; B's join closes (rejected)", async () => {
  const env = await linkEnv();
  try {
    const { owner, phone } = env;
    const { roomId, join: join_, room, req, memberId } = await linkPhone(owner, phone);
    // An admin removes the member's only device A (lost): the add A requested is cancelled (R-8).
    (owner as unknown as { adminSubmit(r: string, t: string, d: unknown): unknown }).adminSubmit(roomId, "device.removed", { memberId, deviceId: req.requester, reason: "lost" });
    await until("B's join closed", () => join_()?.state === "failed", 5000);
    assert.equal(join_()?.failure, "closed:rejected");
    assert.equal(room().deviceRequests[0].status, "cancelled");
    owner.advanceTestClock(73 * HOUR);
    owner.autoApprove(roomId);
    assert.equal(room().deviceRequests[0].status, "cancelled");
    await assert.rejects(owner.approveDevice(roomId, req.ref), /cancelled/);
    assert.equal(owner.ownedHostState(roomId).members[memberId].devices.length, 0);
  } finally {
    await env.cleanup();
  }
});

test("admin hold clock: the hold runs on the admin daemon's own clock from first sight, not from a back-dated hts; persisted", () => {
  const files = new Map<string, Buffer>();
  const kek = { readSealed: (p: string) => (files.has(p) ? Buffer.from(files.get(p)!) : null), writeSealed: (p: string, _purpose: string, b: Uint8Array) => void files.set(p, Buffer.from(b)) } as unknown as Kek;
  let now = 1_793_400_000_000;
  const clock = () => now;
  const roomId = `room_${randomBytes(16).toString("hex")}`;
  const ref = b64u(randomBytes(32));
  const req = { kind: "add", memberId: newId("member"), deviceId: newId("device"), requester: newId("device"), device: {}, seq: 7, hts: now - 30 * 24 * 3_600_000, sole: false, young: false, status: "pending" };
  const st = { pending: { [ref]: req }, conflicts: {}, auth: { policy: { deviceAddApproval: "same-person", soleDeviceChange: "held" } } } as unknown as RoomState;
  // A standalone host claims the request is 30 days old: by hts alone the hold is long over.
  assert.ok(autoApprovalEndsAt(st, req as never)! < now);
  const holds = new AdminHoldClock("/data", kek, roomId, clock);
  assert.equal(holds.endsAt(st, ref, req as never), null, "not seen yet: no approval");
  holds.observe(st);
  assert.equal(holds.endsAt(st, ref, req as never), now + HOLD_MS, "24 h from first sight on the daemon's clock");
  now += HOLD_MS - 1000;
  holds.observe(st);
  // A restart keeps the first-seen time.
  const again = new AdminHoldClock("/data", kek, roomId, clock);
  assert.equal(again.endsAt(st, ref, req as never), holds.endsAt(st, ref, req as never));
  assert.ok(now < again.endsAt(st, ref, req as never)!, "still held");
  // A request that is no longer pending is forgotten.
  (req as { status: string }).status = "approved";
  again.observe(st);
  assert.equal(again.firstSeen(ref), undefined);
});

test("R3.1: a device of a member with two active devices leaves alone (device.removed, self); the other device stays", async () => {
  const env = await linkEnv();
  try {
    const { owner, phone } = env;
    const { roomId, room, req, memberId } = await linkPhone(owner, phone);
    owner.advanceTestClock(72 * HOUR + 1000);
    await until("approved", () => room().deviceRequests[0].status === "approved", 5000);
    const b = () => phone.status().joined.find((j) => j.roomId === roomId);
    await until("B open and synced with two devices", () => b()?.status === "open" && b()?.memberDevices === 2, 5000);
    const res = await phone.leaveRoom(roomId);
    assert.equal(res.statement, "device.removed", "one of several devices removes only itself");
    const m = owner.ownedHostState(roomId).members[memberId];
    assert.deepEqual(m.devices.map((d) => d.deviceId), [owner.status().joined.find((j) => j.roomId === roomId)!.deviceId], "A stays; the membership stays");
    assert.ok(!m.devices.some((d) => d.deviceId === req.deviceId));
    assert.equal(b(), undefined);
    // A is the creator's own device on the hosting daemon: a host does not leave its own room.
    await assert.rejects(owner.leaveRoom(roomId), /host cannot leave/);
  } finally {
    await env.cleanup();
  }
});
