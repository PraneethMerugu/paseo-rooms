// Usability roadmap R3.1 (leave a room), R3.2 (close a lane), R3.7 (stale routed hosts) and R2.6
// ("Leave all rooms and delete keys"): the lane registrar's skip and drop, the stale-host list, the
// KeyStore deletion (file keystore and an injected fake keyring only; the user's keyring is never
// touched), the lane.close confirmation, and the runtimes of an owner and a member in process over the
// fake relay with a fake PaseoApi (no daemon, no network, never ~/.paseo).
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { describeAdminAction, type DescribeContext } from "../../server/admin/confirmations";
import type { RoomState } from "../../server/authority/state";
import { readHostKeys } from "../../server/host/room-host";
import { deleteKeyStore, openKeyStore, type NativeLoad, type OpenKeyStoreOptions } from "../../server/keystore/keystore";
import type { KeyStoreBackend } from "../../server/keystore/types";
import { LaneRegistrar, type HostsApi } from "../../server/member/lane-registration";
import { isUnknownHost, mergeStale, readStaleHosts, removeHosts, staleHostsPath, writeStaleHosts, type StaleHost } from "../../server/member/stale-hosts";
import { memberRoomDir } from "../../server/member/enrollment-journal";
import { startFakeRelay, until } from "./fake-relay";
import { tempDir } from "./helpers";

const ROOM = `room_${"a".repeat(32)}`;
const LANE_A = `lane_${"1".repeat(32)}`;
const LANE_B = `lane_${"2".repeat(32)}`;

// ------------------------------------------------------------------------------ pure parts

test("R3.7 registrar: skipped lanes are not registered (also not while the gate waits); drop forgets a registration", async () => {
  const added: string[] = [];
  const hosts: HostsApi = { list: async () => ({ hosts: [] }), add: async (i) => (added.push(i.sourceKey), { registrationId: `reg-${i.sourceKey}` }), update: async (id) => ({ registrationId: id }) };
  const skip = new Set([LANE_A]);
  let done = 0;
  const r = new LaneRegistrar(
    { roomId: ROOM, pluginId: "rooms", hosts: () => hosts, gate: () => "accepted", connectionFor: async () => "uri", label: () => "L", record: () => undefined, done: () => void done++, skip: (l) => skip.has(l), setTimer: () => null },
    [LANE_A, LANE_B],
    {},
  );
  await r.run();
  assert.deepEqual(added, [LANE_B], "a closed or removed lane is not registered");
  assert.equal(r.status, "done");
  assert.equal(done, 1);
  // A registration dropped after its host was removed is registered again only if no longer skipped.
  r.drop(LANE_B);
  skip.add(LANE_B);
  await r.run();
  assert.deepEqual(added, [LANE_B]);
  // While the gate waits, only lanes that are not skipped count.
  const waiting = new LaneRegistrar({ roomId: ROOM, pluginId: "rooms", hosts: () => hosts, gate: () => "waiting", connectionFor: async () => "uri", label: () => "L", record: () => undefined, done: () => undefined, skip: () => true, setTimer: () => null }, [LANE_A], {});
  await waiting.run();
  assert.equal(waiting.status, "done", "nothing left to register");
});

test("R3.7 stale hosts: no API keeps them (no_api), a failure keeps them with its code, an unknown host counts as removed", async () => {
  const h = (id: string): StaleHost => ({ roomId: ROOM, laneId: LANE_A, registrationId: id, label: "Room aaaaaa · lane 11111111", reason: "left", since: 1, lastError: null });
  const none = await removeHosts(null, [h("r1")]);
  assert.deepEqual(none.removed, []);
  assert.equal(none.remaining[0].lastError, "no_api");
  const removed: string[] = [];
  const api = {
    remove: async (id: string) => {
      if (id === "gone") throw Object.assign(new Error("Unknown host registration"), { code: "host_unknown" });
      if (id === "busy") throw Object.assign(new Error("daemon busy"), { code: "timeout" });
      removed.push(id);
    },
  };
  const r = await removeHosts(api, [h("r1"), h("gone"), h("busy")]);
  assert.deepEqual(r.removed, ["r1", "gone"]);
  assert.deepEqual(r.remaining.map((x) => [x.registrationId, x.lastError]), [["busy", "timeout"]]);
  assert.ok(isUnknownHost(new Error("host_unknown: Unknown host registration")));
  assert.ok(!isUnknownHost(new Error("permission_denied")));
  assert.deepEqual(mergeStale([h("a"), h("b")], [{ ...h("b"), lastError: "x" }]).map((x) => [x.registrationId, x.lastError]), [["a", null], ["b", "x"]]);

  const t = tempDir();
  try {
    const dataDir = join(t.dir, "rooms");
    assert.deepEqual(readStaleHosts(dataDir), []);
    writeStaleHosts(dataDir, [h("busy")]);
    assert.deepEqual(readStaleHosts(dataDir).map((x) => x.registrationId), ["busy"]);
    const text = readFileSync(staleHostsPath(dataDir), "utf8");
    assert.ok(!/prg2\.|connection/.test(text), "ids and labels only");
    writeFileSync(staleHostsPath(dataDir), "{not json");
    assert.deepEqual(readStaleHosts(dataDir), [], "a damaged file is ignored");
    writeStaleHosts(dataDir, []);
    assert.equal(existsSync(staleHostsPath(dataDir)), false, "an empty list removes the file");
  } finally {
    t.cleanup();
  }
});

test("R3.2 confirmation: closing a lane is typed (close), counts the members who have it, refuses a closed lane", () => {
  const me = `mem_${"0".repeat(32)}`;
  const st = (status: string) =>
    ({
      members: { [me]: { memberId: me, role: "admin", lanes: [LANE_A], devices: [] }, [`mem_${"9".repeat(32)}`]: { memberId: `mem_${"9".repeat(32)}`, role: "watch", lanes: [LANE_A], devices: [] } },
      auth: { lanes: { [LANE_A]: { status, offer: { serverId: "srv_x" } } }, versions: {}, closed: false },
      pending: {},
      conflicts: {},
    }) as unknown as RoomState;
  const ctx = (s: RoomState): DescribeContext => ({ state: s, label: () => null, lanes: [{ laneId: LANE_A, label: "Live", status: "open", agentId: "a" }], joinRequest: () => null, ownAdminKid: null, ownMemberId: me });
  const d = describeAdminAction(ctx(st("open")), { kind: "lane.close", roomId: ROOM, laneId: LANE_A });
  assert.equal(d.typeToConfirm, "close");
  assert.match(d.title, /Close lane "Live"/);
  assert.ok(d.details.some((x) => /^1 member\(s\) have this lane/.test(x)), JSON.stringify(d.details));
  assert.ok(d.warning && /cannot be reopened/.test(d.warning));
  assert.notEqual(describeAdminAction(ctx(st("degraded")), { kind: "lane.close", roomId: ROOM, laneId: LANE_A }).subject, d.subject, "a status change since the dialog is stale_base");
  assert.throws(() => describeAdminAction(ctx(st("closed")), { kind: "lane.close", roomId: ROOM, laneId: LANE_A }), /already closed/);
  assert.throws(() => describeAdminAction(ctx(st("open")), { kind: "lane.close", roomId: ROOM, laneId: LANE_B }), /Unknown lane/);
});

test("R3.7 laneLost: a closed lane, or one the member no longer has; nothing for a member not in the roster", async () => {
  const { laneLost } = await import("../../server/runtime-v2");
  const m = `mem_${"3".repeat(32)}`;
  const st = { members: { [m]: { lanes: [LANE_A] } }, auth: { lanes: { [LANE_A]: { status: "open" }, [LANE_B]: { status: "closed" } } } } as unknown as RoomState;
  assert.equal(laneLost(st, m, LANE_A), null);
  assert.equal(laneLost(st, m, LANE_B), "lane_closed");
  const st2 = { members: { [m]: { lanes: [] } }, auth: { lanes: { [LANE_A]: { status: "open" } } } } as unknown as RoomState;
  assert.equal(laneLost(st2, m, LANE_A), "lane_removed");
  assert.equal(laneLost(st2, `mem_${"4".repeat(32)}`, LANE_A), null, "access ended is handled by the session, not here");
});

// ------------------------------------------------------------------------------ KeyStore deletion (R2.6)

function fakeKeyring() {
  const store = new Map<string, Buffer>();
  const calls: string[] = [];
  const backend: KeyStoreBackend = {
    name: "linux-secret-service",
    fallback: false,
    probe: async () => "available",
    get: async () => (calls.push("get"), store.get("kek") ? Buffer.from(store.get("kek")!) : null),
    put: async (k) => void (calls.push("put"), store.set("kek", Buffer.from(k))),
    delete: async () => (calls.push("delete"), store.delete("kek")),
  };
  return { store, calls, load: (): NativeLoad => ({ ok: true, backend, how: "fake" }) };
}

test("R2.6 deleteKeyStore: the fallback file and meta.json go; a new start creates a new KEK", async () => {
  const t = tempDir();
  try {
    const home = join(t.dir, "home");
    mkdirSync(home, { mode: 0o700 });
    const dataDir = join(home, "plugin-data", "rooms");
    const opts: OpenKeyStoreOptions = { dataDir, paseoHome: home, env: { PASEO_ROOMS_KEYSTORE: "fallback-file" }, platform: "linux", timeoutMs: 100 };
    const s1 = await openKeyStore(opts);
    assert.equal(s1.state, "ready");
    const kekId = s1.state === "ready" ? s1.kek.kekId : "";
    const del = await deleteKeyStore(opts);
    assert.deepEqual(del, { backend: "fallback-file", kek: "deleted", message: null });
    assert.equal(existsSync(join(dataDir, "keystore", "kek.fallback")), false);
    assert.equal(existsSync(join(dataDir, "keystore", "meta.json")), false);
    assert.deepEqual(await deleteKeyStore(opts), { backend: null, kek: "absent", message: null }, "twice: nothing left");
    const s2 = await openKeyStore(opts);
    assert.ok(s2.state === "ready" && s2.kek.kekId !== kekId);
  } finally {
    t.cleanup();
  }
});

test("R2.6 deleteKeyStore: a keyring entry is deleted through the backend (fake keyring); unreachable keyring and operator file are reported", async () => {
  const t = tempDir();
  try {
    const home = join(t.dir, "home");
    mkdirSync(home, { mode: 0o700 });
    const dataDir = join(home, "plugin-data", "rooms");
    const ring = fakeKeyring();
    const opts: OpenKeyStoreOptions = { dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: ring.load };
    assert.equal((await openKeyStore(opts)).state, "ready");
    assert.equal(ring.store.size, 1);
    const del = await deleteKeyStore(opts);
    assert.deepEqual(del, { backend: "linux-secret-service", kek: "deleted", message: null });
    assert.equal(ring.store.size, 0, "the keyring entry is gone");
    assert.ok(ring.calls.includes("delete"));
    assert.equal(existsSync(join(dataDir, "keystore", "meta.json")), false);

    // A keyring that cannot be reached now: meta.json stays, the person is told what to remove.
    const ring2 = fakeKeyring();
    assert.equal((await openKeyStore({ ...opts, native: ring2.load })).state, "ready");
    const off = await deleteKeyStore({ ...opts, native: () => ({ ok: false, reason: "binding_missing", detail: "no binding" }) });
    assert.equal(off.kek, "failed");
    assert.match(off.message ?? "", /paseo-rooms/);
    assert.equal(existsSync(join(dataDir, "keystore", "meta.json")), true);
    assert.equal((await deleteKeyStore({ ...opts, native: ring2.load })).kek, "deleted");

    // The operator's KEK file is never deleted.
    const kekFile = join(t.dir, "operator.kek");
    writeFileSync(kekFile, Buffer.alloc(32, 7), { mode: 0o600 });
    const op: OpenKeyStoreOptions = { ...opts, env: { PASEO_ROOMS_KEK_FILE: kekFile } };
    assert.equal((await openKeyStore(op)).state, "ready");
    assert.equal((await deleteKeyStore(op)).kek, "kept");
    assert.equal(existsSync(kekFile), true);
  } finally {
    t.cleanup();
  }
});

// ------------------------------------------------------------------------------ in process: owner and member

type Rt = InstanceType<typeof import("../../server/runtime-v2").RoomsRuntimeV2>;

/** A fake PaseoApi: one agent on the owner; hosts add, update, list, remove (optionally failing) and observe. */
function fakePaseo(o: { failRemove?: () => boolean } = {}) {
  const hosts = new Map<string, { registrationId: string; source: { id: string; key: string } }>();
  const removed: string[] = [];
  let n = 0;
  const api = {
    agents: { ref: (id: string) => ({ refresh: async () => ({ agent: { id, workspaceId: "ws_1", archivedAt: null } }) }) },
    hosts: {
      list: async () => ({ hosts: [...hosts.values()] }),
      add: async (i: { sourceKey: string }) => {
        const registrationId = `reg_${++n}`;
        hosts.set(registrationId, { registrationId, source: { id: "plugin:rooms", key: i.sourceKey } });
        return { registrationId };
      },
      update: async (id: string) => ({ registrationId: id }),
      remove: async (id: string) => {
        if (o.failRemove?.()) throw Object.assign(new Error("daemon busy"), { code: "timeout" });
        if (!hosts.delete(id)) throw Object.assign(new Error("Unknown host registration"), { code: "host_unknown" });
        removed.push(id);
      },
      observe: () => ({ release: async () => undefined, subscribe: () => undefined, ready: Promise.resolve({ hosts: [] }) }),
    },
  };
  return { api, hosts, removed };
}

async function twoRuntimes() {
  const { RoomsRuntimeV2 } = await import("../../server/runtime-v2");
  const t = tempDir();
  const relay = await startFakeRelay();
  const mk = (name: string) => {
    const home = join(t.dir, name);
    mkdirSync(home, { mode: 0o700 });
    return new RoomsRuntimeV2({ PASEO_HOME: home, PASEO_ROOMS_KEYSTORE: "fallback-file", PASEO_ROOMS_RELAY_ENDPOINT: `127.0.0.1:${relay.port}`, PASEO_ROOMS_RELAY_TLS: "false", PASEO_ROOMS_DEV_INSECURE_RELAY: "1" }, undefined, { allowDevSwitches: true, retryMs: [50] });
  };
  const owner = mk("owner");
  const member = mk("member");
  await Promise.all([owner.start(), member.start()]);
  return {
    owner,
    member,
    async cleanup() {
      await member.stop();
      await owner.stop();
      await relay.close();
      t.cleanup();
    },
  };
}

/** Owner creates a room with two lanes; the member joins with both (real SAS enrollment) and registers both. */
async function joinedWithTwoLanes(owner: Rt, member: Rt, memberPaseo: ReturnType<typeof fakePaseo>) {
  owner.attach(fakePaseo().api as never);
  member.attach(memberPaseo.api as never);
  const { roomId } = await owner.createRoom();
  await until("endpoint online", () => owner.status().owned.find((r) => r.roomId === roomId)?.endpoint === "online", 5000);
  const a = await owner.createLane({ roomId, agentId: "agent-a", label: "Live A" });
  const b = await owner.createLane({ roomId, agentId: "agent-b", label: "Live B" });
  const { code } = await owner.createInvite({ roomId, lanes: [a.laneId, b.laneId] });
  await member.startJoin({ code, label: "Sam laptop", trustRelay: true });
  const room = () => owner.status().owned.find((r) => r.roomId === roomId)!;
  const mSas = await until("member SAS", () => member.status().joining.find((j) => j.roomId === roomId)?.sas, 5000);
  assert.equal(mSas, await until("owner SAS", () => room().joinRequests[0]?.sas, 5000));
  await member.confirmJoin(roomId, true);
  await until("member_ok", () => room().joinRequests[0].state === "member_ok", 5000);
  await owner.admitJoin(roomId, room().joinRequests[0].pendingId);
  await until("both lanes registered", () => member.status().joining.find((j) => j.roomId === roomId)?.state === "registered" && memberPaseo.hosts.size === 2, 10_000, 20);
  const joined = () => member.status().joined.find((j) => j.roomId === roomId);
  const regs = () => member.joining.get(roomId)!.journal.e.registrations;
  return { roomId, laneA: a.laneId, laneB: b.laneId, room, joined, regs, memberId: joined()!.memberId };
}

test("R3.2 + R3.7: closing a lane stops it, drops its grants and key; the member removes that lane host only", async () => {
  const env = await twoRuntimes();
  try {
    const { owner, member } = env;
    const mp = fakePaseo();
    const r = await joinedWithTwoLanes(owner, member, mp);
    await until("grants for both lanes", () => r.room().grants.length === 2, 5000);
    const regA = r.regs()[r.laneA];
    assert.ok(regA && r.regs()[r.laneB]);
    const before = r.room().head.seq;
    const { seq } = await owner.closeLane(r.roomId, r.laneA);
    assert.ok(seq > before);
    const lane = r.room().lanes.find((l) => l.laneId === r.laneA)!;
    assert.equal(lane.status, "closed");
    assert.equal(lane.links, 0);
    assert.deepEqual(r.room().grants.map((g) => g.laneId), [r.laneB], "the closed lane's grant left the allowlist");
    assert.equal(r.room().persistError, null);
    const kek = (owner as unknown as { kek: never }).kek;
    const keys = readHostKeys(owner.dataDir, kek, r.roomId)!;
    assert.equal(keys.lanes[r.laneA], undefined, "the closed lane's endpoint key is deleted");
    assert.ok(keys.lanes[r.laneB]);
    await assert.rejects(owner.closeLane(r.roomId, r.laneA), /already closed/);
    // The member's fold sees lane.closed: the lane host is removed, the other stays.
    await until("lane A host removed", () => mp.removed.includes(regA), 5000);
    assert.equal(mp.hosts.size, 1);
    assert.equal(r.regs()[r.laneA], undefined, "the journal forgets the registration");
    assert.deepEqual(r.joined()!.lanes.map((l) => l.laneId), [r.laneB]);
    assert.deepEqual(member.status().staleHosts, []);
  } finally {
    await env.cleanup();
  }
});

test("R3.1: the member's only device leaves (member.left): roster, grants, lane hosts and member data are gone; the host cannot leave", async () => {
  const env = await twoRuntimes();
  try {
    const { owner, member } = env;
    const mp = fakePaseo();
    const r = await joinedWithTwoLanes(owner, member, mp);
    await until("synced", () => r.joined()?.memberDevices === 1, 5000);
    await assert.rejects(owner.leaveRoom(r.roomId), /host cannot leave its own room/);
    const dir = memberRoomDir(member.dataDir, r.roomId);
    assert.ok(existsSync(dir));
    const res = await member.leaveRoom(r.roomId);
    assert.equal(res.statement, "member.left");
    assert.ok(typeof res.seq === "number" && res.seq > 0);
    assert.equal(res.hostsRemoved, 2);
    assert.deepEqual(res.hostsRemaining, []);
    assert.equal(mp.hosts.size, 0, "both lane hosts removed");
    assert.equal(owner.ownedHostState(r.roomId).members[r.memberId], undefined, "the member left the roster");
    await until("owner: no session, no grant", () => r.room().sessions.length === 0 && r.room().grants.length === 0, 5000);
    assert.equal(member.status().joined.length, 0);
    assert.equal(member.status().joining.length, 0);
    assert.equal(existsSync(dir), false, "the device's keys and data for the room are deleted");
    await assert.rejects(member.leaveRoom(r.roomId), /not a member/);
  } finally {
    await env.cleanup();
  }
});

test("R3.7: lane hosts that cannot be removed are kept, shown and retried; R2.6 then deletes everything", async () => {
  const env = await twoRuntimes();
  try {
    const { owner, member } = env;
    let failing = true;
    const mp = fakePaseo({ failRemove: () => failing });
    const r = await joinedWithTwoLanes(owner, member, mp);
    // Removed by the owner: access ends, the hosts cannot be removed yet.
    await owner.removeMember(r.roomId, r.memberId);
    await until("stale hosts recorded", () => (member.status().staleHosts ?? []).length === 2, 5000);
    const stale = member.status().staleHosts!;
    assert.ok(stale.every((h) => h.reason === "access_ended" && h.lastError === "timeout"));
    failing = false;
    const c = await member.cleanUpStaleHosts();
    assert.equal(c.removed, 2);
    assert.deepEqual(c.remaining, []);
    assert.deepEqual(member.status().staleHosts, []);
    assert.equal(mp.hosts.size, 0);

    // R2.6 on the owner: refused while it hosts rooms unless the person also chose to delete them.
    await assert.rejects(owner.deleteAllData({ deleteHosted: false }), /hosts 1 room/);
    // R2.6 on the member: the ended room is forgotten, the KEK (file keystore here) and the data go.
    const res = await member.deleteAllData({ deleteHosted: false });
    assert.deepEqual(res.left.map((l) => [l.roomId, l.statement]), [[r.roomId, null]]);
    assert.equal(res.keystore.kek, "deleted");
    assert.equal(res.keystore.backend, "fallback-file");
    assert.equal(res.dataDeleted, true);
    assert.equal(existsSync(member.dataDir), false);
    const s = member.status();
    assert.equal(s.state, "error");
    assert.equal(s.error, "data_deleted");
    assert.deepEqual([s.joined.length, s.joining.length, s.owned.length], [0, 0, 0]);
    await assert.rejects(member.leaveRoom(r.roomId), /data_deleted/);
    assert.equal(existsSync(member.dataDir), false, "nothing is recreated by later calls");
  } finally {
    await env.cleanup();
  }
});

test("R2.6: the owner may delete hosted rooms too; lane hosts of this plugin unknown to any journal are removed", async () => {
  const env = await twoRuntimes();
  try {
    const { owner, member } = env;
    const mp = fakePaseo();
    const r = await joinedWithTwoLanes(owner, member, mp);
    // A leftover registration of this plugin that no journal knows (an earlier install, say).
    await mp.api.hosts.add({ sourceKey: `lane_${"7".repeat(32)}` });
    assert.equal(mp.hosts.size, 3);
    const res = await member.deleteAllData({ deleteHosted: false });
    assert.deepEqual(res.left.map((l) => l.statement), ["member.left"]);
    assert.equal(res.hostsRemoved, 3);
    assert.equal(mp.hosts.size, 0);
    assert.equal(owner.ownedHostState(r.roomId).members[r.memberId], undefined);
    const o = await owner.deleteAllData({ deleteHosted: true });
    assert.deepEqual(o.hostedDeleted, [r.roomId]);
    assert.equal(o.keystore.kek, "deleted");
    assert.equal(existsSync(owner.dataDir), false);
    assert.equal(owner.laneAgents().length, 0);
  } finally {
    await env.cleanup();
  }
});
