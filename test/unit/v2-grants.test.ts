// Identity v2 milestone I-10: lane grants v2 (grants-v2.md 2 to 11, 13). Rooms in temporary homes with
// a fake keyring, the room endpoint on the in-process fake relay, lane endpoints built but not started
// (LaneConnection.start stubbed: no relay data sockets, no daemon). No network beyond loopback.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { createRoom, type CreatedRoom } from "../../server/admin/genesis";
import type { RoomState } from "../../server/authority/fold";
import type { StatementType } from "../../server/authority/statements";
import { LaneConnection, LinkSession, type LaneEndpoint } from "../../server/gateway/lane-endpoint";
import { LaneErrorLog } from "../../server/gateway/lane-errors";
import { grantTtlS, HOST_KEY_SKEW_S, HostGrants, parseGrantToken, verifyGrantV2, PRUNE_HELD_MS, type CurrentGrant } from "../../server/host/grants";
import { LaneService, V2_LANE_LIMITS } from "../../server/host/lane-service";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { GrantScheduler, idleDecision, scheduleOf, type GrantSchedulerDeps } from "../../server/member/grant-scheduler";
import { admissionGate, LaneRegistrar, type HostsApi } from "../../server/member/lane-registration";
import { RoomClient, RoomSessionError } from "../../server/member/room-client";
import { generateNoiseKeyPair, type NoiseKeyPair } from "../../server/noise/handshake-state";
import { b64u } from "../../server/proto/b64u";
import { newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { H } from "../../server/proto/tbs";
import { GENERIC_ERROR_V2, newSanitizeContext, sanitizeAgentListEntry } from "../../server/room-profile/sanitize";
import { startFakeRelay, until, type FakeRelay } from "./fake-relay";
import { tempDir } from "./helpers";

const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };
const FAST = { handshakeTimeoutMs: 400 };
const V = JSON.parse(readFileSync(join(__dirname, "../../docs/specs/identity-v2/vectors/vectors.json"), "utf8"));

const realStart = LaneConnection.prototype.start;
before(() => {
  LaneConnection.prototype.start = function () {};
});
after(() => {
  LaneConnection.prototype.start = realStart;
});

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

type Device = { memberId: string; deviceId: string; dh: NoiseKeyPair; sigPub: string; sigKid: string };
function newDevice(): Device {
  const pub = rawPublicKey(ed25519PrivateKeyFromSeed(randomBytes(32)));
  return { memberId: newId("member"), deviceId: newId("device"), dh: generateNoiseKeyPair(), sigPub: b64u(pub), sigKid: kidOf("ed25519", pub) };
}

interface Env {
  relay: FakeRelay;
  room: CreatedRoom;
  dataDir: string;
  kek: Kek;
  grants: HostGrants;
  lanes: LaneService;
  endpoint: RoomEndpoint;
  laneId: string;
  ep: LaneEndpoint;
  notified: { deviceId: string; frame: Record<string, unknown> }[];
  clients: RoomClient[];
  fail: { write: boolean };
  cleanup(): Promise<void>;
}

async function setup(o: { env?: NodeJS.ProcessEnv; livenessWaitMs?: number; now?: () => number } = {}): Promise<Env> {
  const t = tempDir();
  const home = join(t.dir, "home");
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
  if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
  const relay = await startFakeRelay();
  const room = await createRoom({ dataDir, kek: s.kek, relay: { host: "127.0.0.1", port: relay.port, tls: true }, recovery: "skip", lock: NO_TIMER });
  const fail = { write: false };
  const grants = new HostGrants({
    dataDir,
    kek: s.kek,
    host: room.host,
    env: o.env ?? {},
    retryMs: 50,
    ...(o.now ? { now: o.now } : {}),
    write: {
      fsyncSync: (fd: number) => {
        if (fail.write) throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
        require("node:fs").fsyncSync(fd);
      },
    },
  });
  let lanes: LaneService | null = null;
  const endpoint = new RoomEndpoint({
    host: room.host,
    endpointKey: endpointKeyFromHost(dataDir, s.kek, room.host),
    relay: { endpoint: relay.endpoint, useTls: false },
    timings: FAST,
    grants,
    onAppended: () => lanes?.sync(),
  });
  grants.afterAppend = () => endpoint.afterAppend();
  lanes = new LaneService({ dataDir, kek: s.kek, host: room.host, grants, relay: { endpoint: relay.endpoint, useTls: false }, paseoHome: join(t.dir, "no-daemon"), autostart: false, livenessWaitMs: o.livenessWaitMs ?? 300 });
  const notified: Env["notified"] = [];
  const realNotify = grants.notify;
  grants.notify = (deviceId, frame) => {
    notified.push({ deviceId, frame });
    realNotify(deviceId, frame);
  };
  endpoint.start();
  await until("endpoint online", () => endpoint.status === "online");
  const env = { relay, room, dataDir, kek: s.kek, grants, lanes, endpoint, notified, clients: [] as RoomClient[], fail } as unknown as Env;
  const creator = Object.values(room.host.state.members)[0].memberId;
  env.laneId = lanes.createLane({ agentId: "agent-1", workspaceId: "wks-1", label: "Live", owner: creator, submit: (data) => void adminDo(env, "lane.created", data) }).laneId;
  env.ep = lanes.endpoints.get(env.laneId)!;
  env.cleanup = async () => {
    for (const c of env.clients) c.close();
    await lanes!.stop();
    grants.stop();
    endpoint.stop();
    room.host.close();
    await relay.close();
    t.cleanup();
  };
  return env;
}

function adminDo(env: Env, type: StatementType, data: unknown): number {
  const p = env.room.signer.prepare({ type, data: data as never, base: env.room.host.head });
  const res = env.endpoint.submit(env.room.signer.confirm(p.confirmToken));
  assert.ok(res.ok, res.ok ? "" : `${type}: ${res.code} ${res.reason}`);
  env.room.signer.reconcile(env.room.host);
  return res.receipt.entry.seq;
}

function admit(env: Env, d: Device, lanes: string[] = [env.laneId], role = "watch"): number {
  return adminDo(env, "member.admitted", {
    member: { memberId: d.memberId, role, lanes, devices: [{ deviceId: d.deviceId, kind: "person", sig: d.sigPub, dh: b64u(d.dh.publicKey) }] },
    confirmation: { method: "sas6", inviteRef: b64u(H("test-invite", randomBytes(8))), transcript: b64u(H("test-transcript", randomBytes(8))) },
  });
}

function issue(env: Env, d: Device): { token: string; gid: string; iat: number; exp: number } {
  const r = env.grants.issue({ memberId: d.memberId, deviceId: d.deviceId }, env.laneId);
  assert.ok(r.ok, r.ok ? "" : r.code);
  return { token: r.token, gid: r.claims.gid, iat: r.claims.iat, exp: r.claims.exp };
}

/** A token signed by the room's host key over arbitrary claims (to reach each verification step). */
function forge(env: Env, claims: Record<string, unknown>): string {
  const payload = rjcs(claims);
  return `prg2.${b64u(payload)}.${b64u(env.room.host.signGrant(payload).sig)}`;
}

async function link(ep: LaneEndpoint, id: string, grant: string): Promise<{ link: LinkSession; sent: any[]; conn: LaneConnection }> {
  const conn = new LaneConnection(ep, id);
  const sent: any[] = [];
  conn.send = (f: unknown) => void sent.push(f);
  ep.connections.set(id, conn);
  (conn as any).mode = "link";
  conn.link = new LinkSession(conn);
  await conn.link.onHello({ type: "hello", clientType: "cli", auth: { kind: "password", password: grant } });
  return { conn, sent, link: conn.link };
}

function logTypes(env: Env): string[] {
  return env.room.host.entries().map((r) => r.signed.entry.type);
}

// ------------------------------------------------------------------------------------------ format

test("grant vector: prg2 token parses to the vector claims and verifies under its host key", () => {
  const g = V.grant;
  const t = parseGrantToken(g.token)!;
  assert.deepEqual(t.claims, g.claims);
  const c = g.claims;
  const state = {
    roomId: c.roomId,
    auth: { closed: false, lanes: { [c.laneId]: { status: "open" } }, hostKeys: [{ kid: V.keys.host.kid, pub: V.keys.host.pub, validFrom: 0, validTo: null, revoked: false, uncertified: false }] },
    members: { [c.sub]: { memberId: c.sub, role: "watch", lanes: [c.laneId], devices: [{ deviceId: "dev_" + "1".repeat(32), sig: V.keys.devSig.pub, dh: V.keys.devDh.pub }] } },
  } as unknown as RoomState;
  const cur: CurrentGrant = { gid: c.gid, iat: c.iat, exp: c.exp, role: "watch", memberId: c.sub };
  const ctx = { state, laneId: c.laneId, aud: c.aud, nowS: c.iat + 10, current: () => cur, notBefore: () => c.iat };
  assert.deepEqual(verifyGrantV2(g.token, ctx), { ok: true, claims: g.claims });
  // The signature covers the claims: one changed character fails.
  const [p, body, sig] = g.token.split(".");
  const flipped = `${p}.${body}.${sig.slice(0, 10)}${sig[10] === "A" ? "B" : "A"}${sig.slice(11)}`;
  assert.equal(verifyGrantV2(flipped, ctx).ok, false);
  // An uncertified host key never verifies a grant (round 8, item 3).
  (state.auth.hostKeys[0] as { uncertified: boolean }).uncertified = true;
  assert.deepEqual(verifyGrantV2(g.token, ctx), { ok: false, reason: "host_key_not_valid", claims: g.claims });
});

test("lifetime: 12 h fixed; policy only shortens; below 1 h only with the development switch", () => {
  assert.equal(grantTtlS(43200, {}), 43200);
  assert.equal(grantTtlS(7200, {}), 7200);
  assert.equal(grantTtlS(99999, {}), 43200, "never lengthened");
  assert.equal(grantTtlS(10, {}), 3600, "1 h minimum without the switch");
  assert.equal(grantTtlS(43200, { PASEO_ROOMS_DEV_SHORT_GRANTS: "1" }), 60);
  assert.equal(grantTtlS(43200, { PASEO_ROOMS_DEV_SHORT_GRANTS: "1", PASEO_ROOMS_DEV_GRANT_TTL_S: "3" }), 10);
  assert.equal(grantTtlS(43200, { PASEO_ROOMS_DEV_GRANT_TTL_S: "30" }), 43200, "the TTL variable alone does nothing");
});

// ------------------------------------------------------------------------------ verification order

test("section 9 skew: a host clock a little behind the host key's validFrom still issues usable grants; far behind is refused clearly", async () => {
  let offsetMs = 0;
  const env = await setup({ now: () => Date.now() + offsetMs });
  const logged: string[] = [];
  const realLog = console.log;
  try {
    const d = newDevice();
    admit(env, d);
    const hk = env.room.host.state.auth.hostKeys.find((h) => h.toSeq === null)!;
    const v = (tok: string) => env.grants.verify(tok, { laneId: env.laneId, aud: env.ep.lane.serverId });
    // NTP steps the clock back 2 minutes after the room was created: within HOST_KEY_SKEW_S.
    offsetMs = -(Math.floor(Date.now() / 1000) - hk.validFrom + 120) * 1000;
    const g = issue(env, d);
    assert.ok(g.iat < hk.validFrom, "the grant predates the key's validFrom");
    assert.deepEqual(v(g.token), { ok: true, claims: parseGrantToken(g.token)!.claims }, "accepted within the tolerance");
    // At the edge: iat = validFrom - HOST_KEY_SKEW_S passes step 2, one second more does not.
    const base = parseGrantToken(g.token)!.claims;
    const step2 = (iat: number) => {
      const r = v(forge(env, { ...base, iat }));
      return r.ok ? "ok" : r.reason;
    };
    assert.notEqual(step2(hk.validFrom - HOST_KEY_SKEW_S), "host_key_not_valid");
    assert.equal(step2(hk.validFrom - HOST_KEY_SKEW_S - 1), "host_key_not_valid");
    // A step back of 20 minutes: the host refuses to sign a grant every lane endpoint would refuse,
    // as retryable (busy), and logs why.
    offsetMs = -(Math.floor(Date.now() / 1000) - hk.validFrom + 20 * 60) * 1000;
    console.log = (...a: unknown[]) => void logged.push(a.map(String).join(" "));
    const r = env.grants.issue({ memberId: d.memberId, deviceId: d.deviceId }, env.laneId);
    console.log = realLog;
    assert.deepEqual(r, { ok: false, code: "busy" });
    const line = logged.find((l) => l.includes("grant_refused_clock_behind"));
    assert.ok(line && /behind the room's host key start time/.test(line) && /"toleranceS":300/.test(line), line);
    assert.equal(env.grants.currentOf(d.deviceId, env.laneId)?.gid, g.gid, "the previous grant stays current");
    // Once the clock is right again, issuance resumes (the refused attempt used no rate-limit slot).
    offsetMs = 0;
    assert.ok(issue(env, d).iat >= hk.validFrom);
  } finally {
    console.log = realLog;
    await env.cleanup();
  }
});


test("section 4: each verification step refuses in order; only the current gid of an active device passes", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const v = (tok: string) => env.grants.verify(tok, { laneId: env.laneId, aud: env.ep.lane.serverId });
    assert.equal(v(g.token).ok, true);
    const base = parseGrantToken(g.token)!.claims;
    const reason = (tok: string) => {
      const r = v(tok);
      return r.ok ? "ok" : r.reason;
    };
    // 1. format
    assert.equal(reason("prg1." + g.token.slice(5)), "malformed");
    assert.equal(reason(g.token + ".x"), "malformed");
    assert.equal(reason(g.token + "A".repeat(1024)), "malformed");
    assert.equal(reason(`prg2.${b64u(Buffer.from(JSON.stringify(base, null, 1)))}.${g.token.split(".")[2]}`), "malformed", "not RJCS");
    assert.equal(reason(forge(env, { ...base, cnf: "x" })), "malformed", "cnf is reserved and must be absent");
    // 2. host key
    assert.equal(reason(forge(env, { ...base, hostKid: b64u(randomBytes(32)) })), "unknown_host_key");
    assert.equal(reason(forge(env, { ...base, iat: 0 })), "host_key_not_valid", "iat before the key's window");
    const other = g.token.split(".");
    assert.equal(reason(`${other[0]}.${b64u(rjcs({ ...base, role: "admin" }))}.${other[2]}`), "bad_signature");
    // 3. audience
    assert.equal(reason(forge(env, { ...base, aud: "rle_" + b64u(randomBytes(24)) })), "wrong_audience");
    // 4. time (lane endpoint clock; iat up to 120 s ahead)
    const now = Math.floor(Date.now() / 1000);
    assert.equal(reason(forge(env, { ...base, iat: now + 300 })), "not_yet_valid");
    assert.equal(reason(forge(env, { ...base, exp: now - 1 })), "expired");
    // 5. roster
    assert.equal(reason(forge(env, { ...base, sub: newId("member") })), "not_member");
    assert.equal(reason(forge(env, { ...base, dev: b64u(randomBytes(32)) })), "not_device");
    assert.equal(reason(forge(env, { ...base, role: "steer" })), "role_mismatch");
    // 6. allowlist: a validly signed grant with any other gid fails (P-12)
    assert.equal(reason(forge(env, { ...base, gid: newId("grant") })), "not_current");
    // notBefore: an older iat fails even with the current gid (restored state file, section 8)
    const nb = verifyGrantV2(g.token, { state: env.room.host.state, laneId: env.laneId, aud: base.aud, nowS: base.iat, current: () => env.grants.currentOf(d.deviceId, env.laneId), notBefore: () => base.iat + 1 });
    assert.equal(nb.ok ? "ok" : nb.reason, "before_not_before");
    // The failure bucket's cheap path: a non-current gid is refused before any signature check.
    assert.equal(env.grants.verify(forge(env, { ...base, gid: newId("grant") }), { laneId: env.laneId, aud: env.ep.lane.serverId }, { cheap: true }).ok, false);
    assert.equal(env.grants.verify(g.token, { laneId: env.laneId, aud: env.ep.lane.serverId }, { cheap: true }).ok, true, "a current grant still gets in");
    // A second issue supersedes: the first token stops working.
    await new Promise((r) => setTimeout(r, 20));
    (env.grants as any).issues.clear();
    const g2 = issue(env, d);
    assert.equal(reason(g.token), "not_current");
    assert.equal(reason(g2.token), "ok");
    assert.ok(logTypes(env).filter((t) => t === "grant.issued").length === 2);
  } finally {
    await env.cleanup();
  }
});

test("section 4 step 5: a member without the lane, and a closed lane, are refused; issue answers not_permitted", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d, []);
    assert.deepEqual(env.grants.issue({ memberId: d.memberId, deviceId: d.deviceId }, env.laneId), { ok: false, code: "not_permitted" });
    const e = newDevice();
    admit(env, e);
    const g = issue(env, e);
    const forged = forge(env, { ...parseGrantToken(g.token)!.claims, sub: d.memberId, dev: d.sigKid });
    const r = env.grants.verify(forged, { laneId: env.laneId, aud: env.ep.lane.serverId });
    assert.equal(r.ok ? "ok" : r.reason, "no_lane_access");
  } finally {
    await env.cleanup();
  }
});

test("clock skew: iat up to 120 s ahead is accepted, more is refused; exp is strict on the endpoint clock", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const c = parseGrantToken(g.token)!.claims;
    const ctx = (nowS: number) => ({ state: env.room.host.state, laneId: env.laneId, aud: c.aud, nowS, current: () => ({ gid: c.gid, iat: c.iat, exp: c.exp, role: c.role, memberId: c.sub }), notBefore: () => c.iat });
    assert.equal(verifyGrantV2(g.token, ctx(c.iat - 120)).ok, true);
    const early = verifyGrantV2(g.token, ctx(c.iat - 121));
    assert.equal(early.ok ? "ok" : early.reason, "not_yet_valid");
    assert.equal(verifyGrantV2(g.token, ctx(c.exp - 1)).ok, true);
    const late = verifyGrantV2(g.token, ctx(c.exp));
    assert.equal(late.ok ? "ok" : late.reason, "expired");
  } finally {
    await env.cleanup();
  }
});

// ------------------------------------------------------------------------------ lane endpoint

test("lane endpoint v2: no control channel; failed attempts consume the bucket; 32 routes per link", async () => {
  const env = await setup();
  try {
    const conn = new LaneConnection(env.ep, "ctl");
    let closed = "";
    conn.close = (why: string) => void (closed = why);
    (conn as any).onMessage(JSON.stringify({ type: "rooms.control.hello", v: 1 }));
    assert.equal(closed, "unexpected_first_frame");
    assert.equal(V2_LANE_LIMITS.maxRoutesPerLink, 32);
    assert.equal(V2_LANE_LIMITS.maxRoutesPerLane, 256);
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    for (let i = 0; i < 31; i++) await link(env.ep, `bad${i}`, forge(env, { ...parseGrantToken(g.token)!.claims, gid: newId("grant") }));
    assert.equal(env.ep.failures!.peek(), false, "30 failures empty the bucket");
    const ok = await link(env.ep, "good", g.token);
    assert.equal(ok.link.accepted, true, "a current grant is still accepted with an empty bucket (S-21)");
  } finally {
    await env.cleanup();
  }
});

test("C-13: an archived lane agent stops its endpoint at once and the lane is closed (lane.closed); once only", async () => {
  const env = await setup();
  try {
    const gone: string[] = [];
    (env.lanes as unknown as { o: { onAgentGone(laneId: string, reason: string): void } }).o.onAgentGone = (laneId, reason) => {
      gone.push(`${laneId}:${reason}`);
      adminDo(env, "lane.closed", { laneId });
    };
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const l = await link(env.ep, "c1", g.token);
    assert.equal(l.link.accepted, true);
    assert.deepEqual(env.lanes.onAgentArchived("some-other-agent"), []);
    assert.deepEqual(env.lanes.onAgentArchived("agent-1"), [env.laneId]);
    assert.deepEqual(gone, [`${env.laneId}:agent_archived`]);
    assert.equal(env.lanes.endpoints.has(env.laneId), false, "endpoint stopped and dropped");
    assert.equal(l.link.closed, true, "the open link is cut");
    assert.equal(env.room.host.state.auth.lanes[env.laneId].status, "closed");
    assert.deepEqual(env.lanes.onAgentArchived("agent-1"), [], "idempotent");
    env.lanes.sync();
    assert.equal(env.lanes.endpoints.has(env.laneId), false, "not restarted");
  } finally {
    await env.cleanup();
  }
});

test("P-9: a stolen grant on a second live link closes both links, unlists the gid and logs grant.suspected-theft", async () => {
  const env = await setup({ livenessWaitMs: 400 });
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const first = await link(env.ep, "c1", g.token);
    assert.equal(first.link.accepted, true);
    // The real holder keeps sending its liveness pings while the thief connects.
    const ping = setInterval(() => first.link.noteRx(), 50);
    const second = await link(env.ep, "c2", g.token);
    clearInterval(ping);
    assert.equal(second.link.accepted, false);
    assert.equal(first.link.closed, true, "the existing link is closed too");
    assert.equal(env.grants.currentOf(d.deviceId, env.laneId), undefined, "the gid stops working everywhere");
    assert.ok(logTypes(env).includes("grant.suspected-theft"));
    assert.deepEqual(env.notified.map((n) => n.frame.reason), ["suspected_theft"]);
    assert.equal(env.ep.links.length, 0);
    // A second event within 7 days marks the device as compromised (6.4).
    (env.grants as any).issues.clear();
    const g2 = issue(env, d);
    await link(env.ep, "c3", g2.token);
    assert.equal(env.grants.suspectedTheft({ deviceId: d.deviceId, laneId: env.laneId, gid: g2.gid, reportedBy: "member" }), true);
    assert.deepEqual(env.grants.compromisedDevices(), [d.deviceId]);
  } finally {
    await env.cleanup();
  }
});

test("6.1: a silent existing link is treated as dead and replaced, without a theft record", async () => {
  const env = await setup({ livenessWaitMs: 200 });
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const first = await link(env.ep, "c1", g.token);
    const second = await link(env.ep, "c2", g.token);
    assert.equal(first.link.closed, true);
    assert.equal(second.link.accepted, true);
    assert.ok(!logTypes(env).includes("grant.suspected-theft"));
    assert.equal(env.grants.currentOf(d.deviceId, env.laneId)?.gid, g.gid);
    const st = env.grants.status(d.deviceId, env.laneId);
    assert.ok(st.ok && st.links.length === 1 && st.links[0].since === second.link.acceptedAt && st.links[0].routes === 0);
  } finally {
    await env.cleanup();
  }
});

test("S-9: lowering a member's role cuts the live link before the log append and asks the device to reissue", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d, [env.laneId], "steer");
    const g = issue(env, d);
    const l = await link(env.ep, "c1", g.token);
    assert.equal(l.link.accepted, true);
    let linkClosedBeforeAppend: boolean | null = null;
    // Observe the order: a decide listener registered after the grants one sees the link already cut.
    env.room.host.onDecide((_n, _p, type) => {
      if (type === "member.role.changed") linkClosedBeforeAppend = l.link.closed && env.room.host.entries().every((r) => r.signed.entry.type !== "member.role.changed");
    });
    adminDo(env, "member.role.changed", { memberId: d.memberId, role: "watch", ver: env.room.host.state.auth.versions[`role:${d.memberId}`] ?? -1 });
    assert.equal(linkClosedBeforeAppend, true);
    assert.equal(l.link.closed, true);
    assert.equal(env.grants.currentOf(d.deviceId, env.laneId), undefined);
    assert.deepEqual(env.notified.map((n) => n.frame.reason), ["role_changed"]);
    const r = env.grants.verify(g.token, { laneId: env.laneId, aud: env.ep.lane.serverId });
    assert.equal(r.ok ? "ok" : r.reason, "role_mismatch");
    // Reissue at the new role works.
    (env.grants as any).issues.clear();
    const g2 = issue(env, d);
    assert.equal(parseGrantToken(g2.token)!.claims.role, "watch");
  } finally {
    await env.cleanup();
  }
});

// ------------------------------------------------------------------------------ enforce then persist

test("7.1/7.2: removal cuts the link before anything is saved; a failed save is persist_failed, kept cut, retried", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const l = await link(env.ep, "c1", g.token);
    assert.equal(l.link.accepted, true);
    env.fail.write = true;
    adminDo(env, "member.removed", { memberId: d.memberId, reason: "admin" });
    assert.equal(l.link.closed, true, "cut although the grant list could not be written");
    assert.equal(env.grants.persistError !== null, true, "persist_failed is visible");
    assert.equal(env.grants.currentOf(d.deviceId, env.laneId), undefined, "the in-memory state stays revoked");
    const again = await link(env.ep, "c2", g.token);
    assert.equal(again.link.accepted, false);
    env.fail.write = false;
    await until("retry clears the error", () => env.grants.persistError === null, 3000);
    // A restart reads the saved list: the removed device has no current grant.
    const reread = new HostGrants({ dataDir: env.dataDir, kek: env.kek, host: env.room.host, env: {} });
    try {
      assert.equal(reread.currentOf(d.deviceId, env.laneId), undefined);
      assert.ok(reread.revoked.has(g.gid));
    } finally {
      reread.stop();
    }
  } finally {
    await env.cleanup();
  }
});

test("section 3: a failed persist on issue delivers no grant (the previous one is already cut)", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const g = issue(env, d);
    const l = await link(env.ep, "c1", g.token);
    (env.grants as any).issues.clear();
    env.fail.write = true;
    const r = env.grants.issue({ memberId: d.memberId, deviceId: d.deviceId }, env.laneId);
    assert.deepEqual(r, { ok: false, code: "internal" });
    assert.equal(l.link.closed, true, "superseded links are cut in step 2");
    assert.equal(logTypes(env).filter((t) => t === "grant.issued").length, 1, "no grant.issued for the failed issue");
    env.fail.write = false;
  } finally {
    await env.cleanup();
  }
});

test("section 8: the denylist is pruned only after exp + 10 min and 24 h of held time, or 30 days past exp", async () => {
  const env = await setup();
  try {
    let wall = Date.now();
    let mono = 0;
    const g = new HostGrants({ dataDir: env.dataDir, kek: env.kek, host: env.room.host, env: {}, now: () => wall, mono: () => mono });
    try {
      const expS = Math.floor(wall / 1000);
      g.revoked.set("g_" + "a".repeat(32), { gid: "g_" + "a".repeat(32), exp: expS, heldMs: 0 });
      const accrue = () => (g as any).accrue();
      // Wall clock jumps two days forward: not pruned, held time is still near zero.
      wall += 2 * 24 * 3_600_000;
      accrue();
      assert.equal(g.revoked.size, 1);
      // 24 h of monotonic time: pruned now (exp + 10 min is long past).
      mono += PRUNE_HELD_MS;
      accrue();
      assert.equal(g.revoked.size, 0);
      // Held long enough but exp + 10 min not reached: kept.
      g.revoked.set("g_" + "b".repeat(32), { gid: "g_" + "b".repeat(32), exp: Math.floor(wall / 1000) + 60, heldMs: PRUNE_HELD_MS });
      accrue();
      assert.equal(g.revoked.size, 1);
      // Backstop: 30 days past exp prunes whatever heldMs says.
      g.revoked.set("g_" + "c".repeat(32), { gid: "g_" + "c".repeat(32), exp: Math.floor(wall / 1000) - 31 * 86400, heldMs: 0 });
      accrue();
      assert.equal(g.revoked.has("g_" + "c".repeat(32)), false);
    } finally {
      g.stop();
    }
  } finally {
    await env.cleanup();
  }
});

// ------------------------------------------------------------------------------ room session ops

test("grant.issue, grant.status and grant.report over the room session; busy within 15 s; not for another lane", async () => {
  const env = await setup();
  try {
    const d = newDevice();
    admit(env, d);
    const c = new RoomClient({ genesis: env.room.genesis, device: d.dh, relay: { endpoint: env.relay.endpoint, useTls: false }, timings: FAST });
    env.clients.push(c);
    await c.connect();
    const r = await c.request({ t: "grant.issue", laneId: env.laneId });
    assert.ok(typeof r.grant === "string" && r.grant.startsWith("prg2.") && r.grant.length <= 1024);
    assert.equal((r.claims as any).dev, d.sigKid);
    assert.equal(typeof r.serverTime, "number");
    await assert.rejects(c.request({ t: "grant.issue", laneId: env.laneId }), (e: unknown) => e instanceof RoomSessionError && e.code === "busy");
    await assert.rejects(c.request({ t: "grant.issue", laneId: newId("lane") }), (e: unknown) => e instanceof RoomSessionError && e.code === "not_permitted");
    const st = await c.request({ t: "grant.status", laneId: env.laneId });
    assert.equal(st.gid, (r.claims as any).gid);
    assert.deepEqual(st.links, []);
    const pushed: any[] = [];
    (c as any).o.onPush = (f: any) => pushed.push(f);
    const rep = await c.request({ t: "grant.report", laneId: env.laneId, gid: (r.claims as any).gid, reason: "unaccounted_link" });
    assert.equal(rep.unlisted, true);
    await until("grant.revoked push", () => pushed.some((f) => f.t === "grant.revoked" && f.reason === "suspected_theft"));
    assert.equal(c.status, "open");
  } finally {
    await env.cleanup();
  }
});

// ------------------------------------------------------------------------------ member schedule

test("schedule (P-24): idle at 50 %, forced at 75 %, last resort at L - 60 s only when later; deferral retry", () => {
  assert.deepEqual(scheduleOf(43_200_000), { idle: 21_600_000, forced: 32_400_000, last: 43_140_000, deferRetry: 5_400_000 });
  const short = scheduleOf(60_000);
  assert.equal(short.last, null);
  assert.equal(short.deferRetry, 60_000);
});

test("idle rule (P-9): only the member's own busy link defers; an unaccounted link never does", () => {
  const reg = { status: "online" as const, onlineSince: 1_000_000, offlineSince: null };
  const st = (links: { since: number; routes: number }[], serverTime = 2_000_000) => ({ gid: "g", links, serverTime });
  // Host clock 5 s ahead: since is converted with serverTime.
  assert.deepEqual(idleDecision(st([{ since: 1_005_000 + 2_000, routes: 2 }], 2_005_000), reg, 1_999_000, 2_001_000), { action: "defer", reason: "own_link_busy" });
  assert.equal(idleDecision(st([{ since: 1_000_000, routes: 0 }]), reg, 1_999_000, 2_001_000).action, "rotate", "idle link: rotate");
  assert.equal(idleDecision(st([]), reg, 0, 0).action, "rotate");
  assert.deepEqual(idleDecision(st([{ since: 1_500_000, routes: 3 }]), reg, 1_999_000, 2_001_000), { action: "rotate", reason: "link_start_mismatch" });
  assert.deepEqual(idleDecision(st([{ since: 1_000_000, routes: 3 }]), { status: "online", onlineSince: null, offlineSince: null }, 1_999_000, 2_001_000), { action: "rotate", reason: "online_time_unknown" });
  assert.deepEqual(idleDecision(st([{ since: 1_000_000, routes: 3 }]), { status: "offline", onlineSince: null, offlineSince: 1_900_000 }, 1_999_000, 2_001_000), { action: "report", reason: "unaccounted_link" });
  assert.deepEqual(idleDecision(st([{ since: 1_000_000, routes: 3 }]), { status: "connecting", onlineSince: null, offlineSince: 1_990_000 }, 1_999_000, 2_001_000), { action: "rotate", reason: "registration_not_online" });
});

function fakeTimers() {
  let now = 0;
  const timers: { at: number; f: () => void; id: number }[] = [];
  let next = 1;
  return {
    mono: () => now,
    setTimer: (f: () => void, ms: number) => {
      const t = { at: now + ms, f, id: next++ };
      timers.push(t);
      return t.id;
    },
    clearTimer: (id: unknown) => {
      const i = timers.findIndex((t) => t.id === id);
      if (i >= 0) timers.splice(i, 1);
    },
    async advance(ms: number) {
      const end = now + ms;
      for (;;) {
        timers.sort((a, b) => a.at - b.at);
        const t = timers[0];
        if (!t || t.at > end) break;
        timers.shift();
        now = t.at;
        t.f();
        for (let i = 0; i < 5; i++) await Promise.resolve();
        await new Promise((r) => setImmediate(r));
      }
      now = end;
    },
  };
}

test("scheduler: a busy own link defers the idle attempt; the forced point rotates anyway; restart with a clock moved back rotates at once", async () => {
  const ft = fakeTimers();
  const rotations: string[] = [];
  let routes = 2;
  let wall = 10_000_000;
  const deps: GrantSchedulerDeps = {
    roomId: "room_x",
    laneId: "lane_x",
    mono: ft.mono,
    wall: () => wall + ft.mono(),
    rotate: async (reason) => {
      rotations.push(reason);
      return { gid: `g${rotations.length}`, iat: 0, exp: 600 };
    },
    status: async () => ({ gid: "g0", links: [{ since: wall, routes }], serverTime: wall + ft.mono() }),
    registration: () => ({ status: "online", onlineSince: wall, offlineSince: null }),
    report: async () => undefined,
    save: () => undefined,
    setTimer: ft.setTimer,
    clearTimer: ft.clearTimer,
  };
  const s = new GrantScheduler(deps);
  s.armNew({ gid: "g0", iat: 0, exp: 600 });
  await ft.advance(300_000);
  assert.deepEqual(rotations, [], "idle attempt deferred: own link with routes");
  assert.equal(s.lastDecision, "defer:own_link_busy");
  await ft.advance(150_000);
  assert.deepEqual(rotations, ["forced"]);
  routes = 0;
  await ft.advance(300_000);
  assert.deepEqual(rotations, ["forced", "idle"], "idle link rotates at 50 % of the new grant");
  s.stop();

  const r2: string[] = [];
  const s2 = new GrantScheduler({ ...deps, rotate: async (reason) => (r2.push(reason), { gid: "n", iat: 0, exp: 600 }) });
  s2.restore({ gid: "old", lifetimeMs: 600_000, receivedWall: wall + 1_000_000 });
  await ft.advance(0);
  assert.deepEqual(r2, ["restart"], "clock moved back: rotate at once");
  s2.stop();
});

// ------------------------------------------------------------------------------ admission gate

test("gate: no grant is requested and no host registered before the member's fold accepts the admission entry", async () => {
  const admission = { seq: 3, hash: "h".repeat(43) };
  const fold = { entries: new Map<number, { hash: string }>(), sendingStopped: false, alerts: [] as { type: string }[], entry(seq: number) { return this.entries.get(seq); } };
  const gate = () => admissionGate(fold, admission, () => false);
  const issued: string[] = [];
  const timers: (() => void)[] = [];
  const hosts: HostsApi = { list: async () => ({ hosts: [] }), add: async () => ({ registrationId: "reg1" }), update: async () => ({ registrationId: "reg1" }) };
  const r = new LaneRegistrar(
    {
      roomId: "room_x",
      pluginId: "rooms",
      hosts: () => hosts,
      gate,
      connectionFor: async (laneId) => (issued.push(laneId), "uri"),
      label: () => "Lane",
      record: () => undefined,
      done: () => undefined,
      setTimer: (f) => void timers.push(f),
      clearTimer: () => undefined,
    },
    ["lane_1"],
    {},
  );
  await r.run();
  assert.deepEqual(issued, [], "fold has not reached the admission entry");
  assert.equal(r.status, "retrying");
  assert.equal(r.lastError, "admission_unverified");
  fold.entries.set(3, { hash: "x".repeat(43) });
  assert.equal(gate(), "refused", "a different entry at that seq is refused");
  fold.entries.set(3, { hash: admission.hash });
  fold.alerts.push({ type: "fork" });
  assert.equal(gate(), "refused", "a fork alert refuses");
  fold.alerts.length = 0;
  assert.equal(gate(), "accepted");
  await r.run();
  assert.deepEqual(issued, ["lane_1"]);
  assert.equal(r.status, "done");

  // Refused: registration stops for good.
  const issued2: string[] = [];
  const r2 = new LaneRegistrar({ roomId: "room_y", pluginId: "rooms", hosts: () => hosts, gate: () => "refused", connectionFor: async (l) => (issued2.push(l), "uri"), label: () => "L", record: () => undefined, done: () => undefined }, ["lane_1"], {});
  await r2.run();
  assert.equal(r2.status, "refused");
  assert.deepEqual(issued2, []);
  assert.equal(admissionGate(null, admission, () => true), "waiting", "no session yet");
});

// ------------------------------------------------------------------------------ viewer policy (13)

test("13.1: v2 viewers get the fixed generic text with an 8-character error reference; the owner keeps the text", () => {
  const errors = new LaneErrorLog(undefined, undefined, undefined, true);
  const ctx = newSanitizeContext({ laneId: "lane_x", laneServerId: "rle_x", agentId: "a1", workspaceId: "w1" }, { laneAgent: { current: null }, maxTimelineLimit: 100, allowedSessionEvents: new Set(), projectNames: { show: false, label: "Live" }, errors });
  const out = sanitizeAgentListEntry({ agent: { id: "a1", lastError: "ENOENT /home/alice/secret-project/x.ts", cwd: "/home/alice/secret-project" } }, ctx) as any;
  const m = /^(.*) Error reference: ([a-z2-7]{8})\.$/.exec(out.agent.lastError);
  assert.ok(m, out.agent.lastError);
  assert.equal(m![1], GENERIC_ERROR_V2);
  assert.ok(!JSON.stringify(out).includes("secret-project"), "no path or project name reaches the viewer");
  const [entry] = errors.list();
  assert.equal(entry.ref, m![2]);
  assert.ok(entry.message.includes("ENOENT"));
});
