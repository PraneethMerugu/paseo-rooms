// Identity v2 milestone I-8: room endpoint transport and sessions, over the in-process fake relay
// (test/unit/fake-relay.ts). Rooms are created in temporary homes with keys sealed through a fake
// keyring; no real keyring, no network (loopback only).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import WebSocket from "ws";
import { createRoom, type CreatedRoom } from "../../server/admin/genesis";
import { entryHash, isEquivocationProof, type SignedEntry } from "../../server/authority/entries";
import type { SignedStatement, StatementType } from "../../server/authority/statements";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import { ACCESS_LOG_FILE, readHostKeys } from "../../server/host/room-host";
import { hostRoomDir } from "../../server/host/room-log-store";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { RoomClient, RoomSessionError } from "../../server/member/room-client";
import { generateNoiseKeyPair, type NoiseKeyPair } from "../../server/noise/handshake-state";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { CTX_LOG_ENTRY, stmtContext } from "../../server/proto/contexts";
import { newId, newServerId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { H, sign } from "../../server/proto/tbs";
import { relayClientUrl } from "../../server/transport/relay-server";
import { IK_MESSAGE1_BYTES, IK_MESSAGE2_BYTES } from "../../server/transport/room-session";
import { startFakeRelay, until, type FakeRelay } from "./fake-relay";
import { tempDir } from "./helpers";

const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };
const FAST = { handshakeTimeoutMs: 400 };

function fakeKeyring(): () => { ok: true; backend: KeyStoreBackend; how: string } {
  const store = new Map<string, Buffer>();
  const backend: KeyStoreBackend = {
    name: "linux-secret-service",
    fallback: false,
    probe: async () => "available",
    get: async () => (store.get("kek") ? Buffer.from(store.get("kek")!) : null),
    put: async (kek) => void store.set("kek", Buffer.from(kek)),
    delete: async () => store.delete("kek"),
  };
  return () => ({ ok: true, backend, how: "fake" });
}

type Device = { memberId: string; deviceId: string; dh: NoiseKeyPair; sigPriv: ReturnType<typeof ed25519PrivateKeyFromSeed>; sigPub: string; sigKid: string };

function newDevice(): Device {
  const sigPriv = ed25519PrivateKeyFromSeed(randomBytes(32));
  const pub = rawPublicKey(sigPriv);
  return { memberId: newId("member"), deviceId: newId("device"), dh: generateNoiseKeyPair(), sigPriv, sigPub: b64u(pub), sigKid: kidOf("ed25519", pub) };
}

interface Env {
  relay: FakeRelay;
  room: CreatedRoom;
  dataDir: string;
  kek: Kek;
  endpoint: RoomEndpoint;
  clients: RoomClient[];
  cleanup(): Promise<void>;
}

async function setup(endpointExtra: Partial<ConstructorParameters<typeof RoomEndpoint>[0]> = {}): Promise<Env> {
  const t = tempDir();
  const home = join(t.dir, "home");
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
  if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
  const relay = await startFakeRelay();
  const room = await createRoom({ dataDir, kek: s.kek, relay: { host: "127.0.0.1", port: relay.port, tls: true }, recovery: "skip", lock: NO_TIMER });
  const endpoint = new RoomEndpoint({
    host: room.host,
    endpointKey: endpointKeyFromHost(dataDir, s.kek, room.host),
    relay: { endpoint: relay.endpoint, useTls: false },
    timings: FAST,
    ...endpointExtra,
  });
  endpoint.start();
  await until("endpoint online", () => endpoint.status === "online");
  const env: Env = {
    relay,
    room,
    dataDir,
    kek: s.kek,
    endpoint,
    clients: [],
    async cleanup() {
      for (const c of env.clients) c.close();
      endpoint.stop();
      room.host.close();
      await relay.close();
      t.cleanup();
    },
  };
  return env;
}

/** Admin statement through the confirmation token, submitted through the endpoint (pushes, enforces). */
function adminDo(env: Env, type: StatementType, data: unknown): number {
  const p = env.room.signer.prepare({ type, data: data as never, base: env.room.host.head });
  const res = env.endpoint.submit(env.room.signer.confirm(p.confirmToken));
  assert.ok(res.ok, res.ok ? "" : `${type}: ${res.code} ${res.reason}`);
  env.room.signer.reconcile(env.room.host);
  return res.receipt.entry.seq;
}

/** A hand-made roster entry (the exit criterion of I-8; enrollment is I-9). */
function admit(env: Env, d: Device): number {
  return adminDo(env, "member.admitted", {
    member: { memberId: d.memberId, role: "watch", lanes: [], devices: [{ deviceId: d.deviceId, kind: "person", sig: d.sigPub, dh: b64u(d.dh.publicKey) }] },
    confirmation: { method: "sas6", inviteRef: b64u(H("test-invite", randomBytes(8))), transcript: b64u(H("test-transcript", randomBytes(8))) },
  });
}

/** room.policy.changed of grantTtl with the current field version. */
function setGrantTtl(env: Env, value: number): number {
  const ver = env.room.host.state.auth.versions["policy:grantTtl"] ?? -1;
  return adminDo(env, "room.policy.changed", { changes: [{ setting: "grantTtl", value, ver }] });
}

function client(env: Env, d: Device, extra: Partial<ConstructorParameters<typeof RoomClient>[0]> = {}): RoomClient {
  const c = new RoomClient({ genesis: env.room.genesis, device: d.dh, relay: { endpoint: env.relay.endpoint, useTls: false }, timings: FAST, ...extra });
  env.clients.push(c);
  return c;
}

function deviceStatement(env: Env, d: Device, type: StatementType, data: unknown): SignedStatement {
  const body = { v: 2 as const, typ: "stmt" as const, type, roomId: env.room.roomId, producer: { kind: "device" as const, kid: d.sigKid }, base: env.room.host.head, ts: Date.now(), data };
  return { body, sig: b64u(sign(d.sigPriv, stmtContext(type), rjcs(body))) } as SignedStatement;
}

function accessLog(env: Env): any[] {
  return readFileSync(join(hostRoomDir(env.dataDir, env.room.roomId), ACCESS_LOG_FILE), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
}

/** Raw relay client socket: binary messages in arrival order. */
async function rawClient(env: Env): Promise<{ ws: WebSocket; got: Buffer[]; closed: () => boolean }> {
  const ws = new WebSocket(relayClientUrl({ endpoint: env.relay.endpoint, useTls: false }, env.endpoint.serverId), { perMessageDeflate: false });
  const got: Buffer[] = [];
  let closed = false;
  ws.on("message", (d) => got.push(Buffer.from(d as Buffer)));
  ws.on("close", () => (closed = true));
  ws.on("error", () => undefined);
  await new Promise<void>((r) => ws.once("open", () => r()));
  return { ws, got, closed: () => closed };
}

// -------------------------------------------------------------------------------------------------

test("a member with a hand-made roster entry opens a session, syncs the log and receives pushed entries", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    setGrantTtl(env, 7200);
    const c = client(env, d);
    const hello = await c.connect();
    assert.equal(hello.memberId, d.memberId);
    assert.equal(hello.deviceId, d.deviceId);
    assert.equal(hello.minVersion, 2);
    assert.deepEqual(hello.head, { seq: env.room.host.head.seq, hash: env.room.host.head.hash, hsig: env.room.host.headEntry!.hsig });
    assert.deepEqual(c.head, env.room.host.head);
    assert.equal(c.state.auth.policy.grantTtl, 7200);
    assert.equal(c.alerts.length, 0);
    assert.deepEqual(env.endpoint.sessions().map((s) => s.deviceId), [d.deviceId]);

    // log.subscribe: a later entry arrives without a request.
    const seq = setGrantTtl(env, 3600);
    await until("pushed entry", () => c.head.seq === seq);
    assert.equal(c.state.auth.policy.grantTtl, 3600);
    assert.deepEqual(c.head, env.room.host.head);

    // roster.get answers with the host's roster.
    const r = await c.request({ t: "roster.get" });
    assert.equal(r.rosterHash, env.room.host.rosterHash());
    // A later operation (I-10) answers not_permitted and keeps the session.
    await assert.rejects(c.request({ t: "grant.issue" }), (e: unknown) => e instanceof RoomSessionError && e.code === "not_permitted");
    assert.equal(c.status, "open");
    // Unknown types are a bad frame and close the session.
    await assert.rejects(c.request({ t: "nonsense.op" }), (e: unknown) => e instanceof RoomSessionError && e.code === "bad_frame");
    await until("closed", () => c.status === "closed");
    await until("endpoint dropped the session", () => env.endpoint.sessions().length === 0);

    const events = accessLog(env).map((e) => e.event);
    assert.ok(events.includes("session.opened") && events.includes("log.fetch") && events.includes("session.closed"), events.join(","));
    assert.ok(!readFileSync(join(hostRoomDir(env.dataDir, env.room.roomId), ACCESS_LOG_FILE), "utf8").includes(b64u(d.dh.publicKey)), "access log holds kids, not keys");
  } finally {
    await env.cleanup();
  }
});

test("a wrong prologue fails the handshake; the first message must be exactly 96 bytes and binary", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    // Same keys, another serverId in the prologue (also stands for another room or protocol version).
    const wrong = client(env, d, { bindingOverride: { genesisHash: b64uDecode(env.room.genesisHash, 32), serverId: newServerId("roomEndpoint") } });
    await assert.rejects(wrong.connect(), (e: unknown) => e instanceof RoomSessionError && e.code === "handshake_failed");
    const otherGenesis = client(env, d, { bindingOverride: { genesisHash: randomBytes(32), serverId: env.endpoint.serverId } });
    await assert.rejects(otherGenesis.connect(), (e: unknown) => e instanceof RoomSessionError && e.code === "handshake_failed");
    assert.equal(env.endpoint.sessions().length, 0);

    assert.equal(IK_MESSAGE1_BYTES, 96);
    const short = await rawClient(env);
    short.ws.send(randomBytes(95), { binary: true });
    await until("95-byte message closes", () => short.closed());
    assert.equal(short.got.length, 0);
    const text = await rawClient(env);
    text.ws.send("x".repeat(96));
    await until("text message closes", () => text.closed());

    const reasons = accessLog(env).filter((e) => e.event === "preauth_failed").map((e) => e.reason);
    assert.deepEqual(reasons.sort(), ["bad_first_message", "handshake_failed", "handshake_failed", "text_message"]);

    // The right binding still works.
    await client(env, d).connect();
  } finally {
    await env.cleanup();
  }
});

test("an unknown static gets not_authorized after any non-pre-auth frame; pre-auth frames get the generic enroll code", async () => {
  const env = await setup();
  try {
    const stranger = newDevice(); // never admitted
    const c = client(env, stranger);
    await assert.rejects(c.connect(), (e: unknown) => e instanceof RoomSessionError && e.code === "not_authorized");
    assert.equal(c.lastError, "not_authorized");
    assert.equal(env.endpoint.sessions().length, 0);

    // Enrollment is I-9: a pre-auth operation is answered with the generic enroll_rejected.
    const c2 = client(env, stranger);
    await c2.open();
    await assert.rejects(c2.request({ t: "enroll.request" }), (e: unknown) => e instanceof RoomSessionError && e.code === "enroll_rejected");
    await until("closed", () => c2.status === "closed");
    assert.ok(accessLog(env).some((e) => e.event === "preauth_failed" && e.reason === "not_authorized"));
  } finally {
    await env.cleanup();
  }
});

test("a removed device gets access_ended: at once on its live session, and after the handshake on a new one", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const c = client(env, d);
    await c.connect();
    const removedAt = adminDo(env, "member.removed", { memberId: d.memberId, reason: "admin" });
    await until("live session ended", () => c.status === "ended");
    assert.equal(c.endedReason, "removed");
    assert.equal(c.lastError, "access_ended");
    // Cut before the push: the removed device's last view is what it had at removal.
    assert.ok(c.head.seq < removedAt);
    assert.equal(env.endpoint.sessions().length, 0);

    const again = client(env, d);
    await assert.rejects(again.connect(), (e: unknown) => e instanceof RoomSessionError && e.code === "access_ended" && e.fields.reason === "removed");
    assert.equal(again.status, "ended");
    // The same answer is not given to a stranger (P-23): it gets not_authorized.
    await assert.rejects(client(env, newDevice()).connect(), (e: unknown) => e instanceof RoomSessionError && e.code === "not_authorized");
  } finally {
    await env.cleanup();
  }
});

test("stmt.submit of the device's own member.left: receipt, then access_ended left", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const c = client(env, d);
    await c.connect();
    // Another device's statement is refused (own statements only), without closing the session.
    const other = newDevice();
    await assert.rejects(c.request({ t: "stmt.submit", statement: deviceStatement(env, other, "member.left", { memberId: d.memberId }) as never }), (e: unknown) => e instanceof RoomSessionError && e.code === "not_permitted");
    // A stale base is answered with the head.
    const stale = deviceStatement(env, d, "member.left", { memberId: d.memberId });
    setGrantTtl(env, 7200);
    await until("synced", () => c.head.seq === env.room.host.head.seq);
    const staleBody = { ...stale.body, base: { seq: env.room.host.head.seq + 5, hash: env.room.host.head.hash } };
    const bad = { body: staleBody, sig: b64u(sign(d.sigPriv, stmtContext("member.left"), rjcs(staleBody))) };
    await assert.rejects(c.request({ t: "stmt.submit", statement: bad as never }), (e: unknown) => e instanceof RoomSessionError && e.code === "unknown_base" && (e.fields.head as { seq: number }).seq === env.room.host.head.seq);
    assert.equal(c.status, "open");

    const reply = await c.request({ t: "stmt.submit", statement: deviceStatement(env, d, "member.left", { memberId: d.memberId }) as never });
    const receipt = reply.receipt as unknown as SignedEntry;
    assert.equal(receipt.entry.type, "member.left");
    await until("ended", () => c.status === "ended");
    assert.equal(c.endedReason, "left");
    await assert.rejects(client(env, d).connect(), (e: unknown) => e instanceof RoomSessionError && e.fields.reason === "left");
  } finally {
    await env.cleanup();
  }
});

test("a replayed message 1 cannot push out a live session; a key-confirmed new session supersedes the old one", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const c = client(env, d);
    await c.connect();
    const live = env.relay.forwarded.find((m) => m.from === "client" && m.data.byteLength === IK_MESSAGE1_BYTES)!;
    assert.ok(live, "captured message 1");

    // The recorder replays message 1: the responder completes its side (message 2 comes back)...
    const replay = await rawClient(env);
    replay.ws.send(live.data, { binary: true });
    await until("message 2", () => replay.got.length === 1);
    assert.equal(replay.got[0].byteLength, IK_MESSAGE2_BYTES);
    // ...but cannot produce a valid transport message. Garbage fails key confirmation and closes.
    await until("unconfirmed replay closed by the timer", () => replay.closed(), 3000);
    assert.equal(c.status, "open");
    assert.deepEqual(env.endpoint.sessions().map((s) => s.deviceId), [d.deviceId]);
    await c.request({ t: "roster.get" });

    const replay2 = await rawClient(env);
    replay2.ws.send(live.data, { binary: true });
    await until("message 2 again", () => replay2.got.length === 1);
    replay2.ws.send(randomBytes(64), { binary: true });
    await until("bad transport message closes", () => replay2.closed());
    assert.equal(c.status, "open");
    assert.ok(accessLog(env).some((e) => e.event === "preauth_failed" && e.reason === "key_confirmation_timeout"));
    assert.ok(accessLog(env).some((e) => e.event === "preauth_failed" && e.reason === "key_confirmation_failed"));

    // The real device reconnecting (key-confirmed) supersedes its old session.
    const c2 = client(env, d);
    await c2.connect();
    await until("old session superseded", () => c.status === "closed");
    assert.equal(c.lastError, "superseded");
    assert.equal(c2.status, "open");
    assert.equal(env.endpoint.sessions().length, 1);
  } finally {
    await env.cleanup();
  }
});

test("equivocation is detected from two signed heads; a claim without evidence is unverified_head_claim", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const c = client(env, d, { evidenceTimeoutMs: 200 });
    await c.connect();
    const s = c.head.seq;
    const real = c.entry(s)!;
    // The host key signs a second, different entry at the same seq (what an equivocating host does).
    const keys = readHostKeys(env.dataDir, env.kek, env.room.roomId)!;
    const hostPriv = ed25519PrivateKeyFromSeed(b64uDecode(keys.hostKeys[0].seed, 32));
    const entry = { ...real.entry, bodyHash: b64u(randomBytes(32)) };
    const forged: SignedEntry = { entry, hash: entryHash(entry), hsig: b64u(sign(hostPriv, CTX_LOG_ENTRY, rjcs(entry))) };
    const peer = { memberId: newId("member"), deviceId: newId("device") };

    assert.equal(await c.checkPeerHead(peer, s, real.hash), "consistent");
    assert.equal(await c.checkPeerHead(peer, s, forged.hash), "unverified_head_claim");
    assert.equal(c.alerts.at(-1)!.type, "unverified_head_claim");
    assert.deepEqual(c.alerts.at(-1)!.peer, peer);
    assert.equal(c.sendingStopped, false, "an unverified claim stops nothing (S-7)");

    // An unsigned or badly signed "proof" is not enough.
    assert.equal(await c.checkPeerHead(peer, s, forged.hash, async () => ({ ...forged, hsig: real.hsig })), "unverified_head_claim");
    // A valid second signed entry is.
    assert.equal(await c.checkPeerHead(peer, s, forged.hash, async () => forged), "fork");
    const fork = c.alerts.at(-1)!;
    assert.equal(fork.type, "fork");
    assert.ok(isEquivocationProof(fork.proof[0], fork.proof[1], (kid) => (kid === keys.hostKeys[0].kid ? rawPublicKey(hostPriv) : null)));
    assert.equal(c.sendingStopped, true);

    // A peer head beyond the host's: the host does not serve it, the peer proves it was signed.
    const ahead = { ...real.entry, seq: s + 1, prev: real.hash };
    const signedAhead: SignedEntry = { entry: ahead, hash: entryHash(ahead), hsig: b64u(sign(hostPriv, CTX_LOG_ENTRY, rjcs(ahead))) };
    assert.equal(await c.checkPeerHead(peer, s + 1, signedAhead.hash, async () => signedAhead), "withholding");
  } finally {
    await env.cleanup();
  }
});

test("enrollment 5.7 (round 9, item 3): pre-admission entries must be in the fetched log with the same hash", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    const admittedAt = admit(env, d);
    const keys = readHostKeys(env.dataDir, env.kek, env.room.roomId)!;
    const hostPriv = ed25519PrivateKeyFromSeed(b64uDecode(keys.hostKeys[0].seed, 32));
    const signEntry = (entry: SignedEntry["entry"]): SignedEntry => ({ entry, hash: entryHash(entry), hsig: b64u(sign(hostPriv, CTX_LOG_ENTRY, rjcs(entry))) });

    // Matching anchors: no alert, all checked.
    const ok = client(env, d);
    await ok.connect();
    const real = ok.entry(admittedAt)!;
    const first = ok.entry(0)!;
    ok.close();
    const c1 = client(env, d, { anchors: [{ source: "authority_chain", signed: first }, { source: "admission", signed: real }] });
    await c1.connect();
    assert.deepEqual(c1.alerts, []);
    assert.equal(c1.uncheckedAnchors, 0);
    assert.equal(c1.sendingStopped, false);
    c1.close();

    // A chain entry the host showed before admission differs from the log's entry at that seq: fork,
    // with the two host-signed entries as the proof.
    const forged = signEntry({ ...first.entry, bodyHash: b64u(randomBytes(32)) });
    const c2 = client(env, d, { anchors: [{ source: "authority_chain", signed: forged }] });
    await c2.connect();
    const fork = c2.alerts.find((a) => a.type === "fork")!;
    assert.ok(fork, "fork raised");
    assert.equal(fork.seq, 0);
    assert.equal(fork.reason, "pre_admission:authority_chain");
    assert.ok(isEquivocationProof(fork.proof[0], fork.proof[1], (kid) => (kid === keys.hostKeys[0].kid ? rawPublicKey(hostPriv) : null)));
    assert.equal(c2.sendingStopped, true);
    c2.close();

    // An admission entry beyond the host's head: the host signed it and no longer serves it.
    const head = env.room.host.headEntry!;
    const ahead = signEntry({ ...head.entry, seq: head.entry.seq + 1, prev: head.hash });
    const c3 = client(env, d, { anchors: [{ source: "admission", signed: ahead }] });
    await c3.connect();
    assert.deepEqual(c3.alerts.map((a) => [a.type, a.reason]), [["truncation", "pre_admission:admission"]]);
    assert.equal(c3.sendingStopped, true);
  } finally {
    await env.cleanup();
  }
});

test("session timers: pings keep a quiet session alive; repeated eviction is logged as endpoint.evicted", async () => {
  const env = await setup({ timings: { ...FAST, pingAfterMs: 60, idleCloseMs: 200 }, evictionThreshold: 1 });
  try {
    const d = newDevice();
    admit(env, d);
    const c = client(env, d, { timings: { ...FAST, pingAfterMs: 60, idleCloseMs: 200 } });
    await c.connect();
    await new Promise((r) => setTimeout(r, 700));
    assert.equal(c.status, "open", "pings answered by pongs keep the session");
    assert.equal(env.endpoint.sessions().length, 1);

    // Someone who knows the serverId opens a server control socket: the relay evicts the host's (P-16).
    const before = env.room.host.head.seq;
    const evil = new WebSocket(`ws://${env.relay.endpoint}/ws?serverId=${env.endpoint.serverId}&role=server&v=2`);
    evil.on("error", () => undefined);
    await until("endpoint.evicted logged", () => env.room.host.head.seq > before, 3000);
    const last = env.room.host.entries(env.room.host.head.seq)[0];
    assert.equal(last.signed.entry.type, "endpoint.evicted");
    evil.close();
    await until("pushed to the member", () => c.head.seq === env.room.host.head.seq, 3000);
  } finally {
    await env.cleanup();
  }
});

test("v2 runtime in-process: relay address rules, owner and member runtimes over the fake relay", async () => {
  const { relayAddress, genesisRelay, RoomsRuntimeV2 } = await import("../../server/runtime-v2");
  assert.deepEqual(genesisRelay({}), { host: "relay.paseo.sh", port: 443, tls: true });
  assert.deepEqual(relayAddress({ host: "relay.paseo.sh", port: 443 }, { PASEO_ROOMS_RELAY_TLS: "false" }), { endpoint: "relay.paseo.sh:443", useTls: true }, "plain ws only for loopback");
  assert.deepEqual(relayAddress({ host: "127.0.0.1", port: 6923 }, { PASEO_ROOMS_RELAY_TLS: "false" }), { endpoint: "127.0.0.1:6923", useTls: false });

  const t = tempDir();
  const relay = await startFakeRelay();
  const mk = (name: string) => {
    const home = join(t.dir, name);
    mkdirSync(home, { mode: 0o700 });
    return new RoomsRuntimeV2({ PASEO_HOME: home, PASEO_ROOMS_KEYSTORE: "fallback-file", PASEO_ROOMS_RELAY_ENDPOINT: `127.0.0.1:${relay.port}`, PASEO_ROOMS_RELAY_TLS: "false", PASEO_ROOMS_DEV_INSECURE_RELAY: "1" }, undefined, { allowDevSwitches: true });
  };
  const owner = mk("owner");
  const member = mk("member");
  try {
    await Promise.all([owner.start(), member.start()]);
    assert.equal(owner.status().state, "ready");
    assert.equal(owner.status().keystore?.backend, "fallback-file");
    const { roomId } = await owner.createRoom();
    await until("endpoint online", () => owner.status().owned[0]?.endpoint === "online");
    // Real enrollment (I-9): invite, preview, relay trust, SAS on both sides, confirm, admit.
    const { code } = await owner.createInvite({ roomId, note: "for Sam" });
    const preview = await member.previewJoin(code);
    assert.equal(preview.roomId, roomId);
    assert.equal(preview.relay.trusted, false, "a loopback relay is never in the default trusted list");
    await assert.rejects(member.startJoin({ code, label: "Sam laptop" }), /relay you have not used before/);
    await member.startJoin({ code, label: "Sam laptop", trustRelay: true });
    const mSas = await until("member SAS", () => member.status().joining[0]?.sas, 5000);
    const oSas = await until("owner SAS", () => owner.status().owned[0].joinRequests[0]?.sas, 5000);
    assert.equal(mSas, oSas, "both sides show the same six digits");
    await member.confirmJoin(roomId, true);
    const pendingId = owner.status().owned[0].joinRequests[0].pendingId;
    await until("member confirmed on the host", () => owner.status().owned[0].joinRequests[0].state === "member_ok", 5000);
    await owner.admitJoin(roomId, pendingId);
    await until("member session open", () => member.status().joined[0]?.status === "open", 5000);
    // No lanes: registered right after the session's first sync (the I-10 gate), with no lane work.
    await until("no lanes: registered once synced", () => member.status().joining[0].state === "registered", 2000);
    await until("member synced", () => member.status().joined[0].head.seq === owner.status().owned[0].head.seq, 5000);
    assert.deepEqual(member.status().joined[0].head, owner.status().owned[0].head);
    assert.equal(owner.status().owned[0].sessions.length, 1);
    assert.equal(owner.status().owned[0].invites[0].state, "used");
    const memberId = member.status().joined[0].memberId;
    await owner.removeMember(roomId, memberId);
    await until("member ended", () => member.status().joined[0].status === "ended");
    assert.equal(member.status().joined[0].endedReason, "removed");
    // Nothing secret-looking leaves the runtime in its views.
    const text = JSON.stringify([owner.status(), member.status()]);
    assert.ok(!/seed|secret/i.test(text));
  } finally {
    await member.stop();
    await owner.stop();
    await relay.close();
    t.cleanup();
  }
});
