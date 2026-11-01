// Migration from M1 (docs/specs/identity-v2/migration.md section 6, tests 1 and 2; plan I-15).
//
// 1. A fixture v1 tree (test/unit/fixtures.ts writeV1Tree): the migration archives `gateway/` and the
//    v1 part of `member/` by rename, records it in migration.json, and a second run does nothing.
//    Also: win32 sharing violations leave the step pending for the next start; the member's v1
//    registrations are removed through the hosts API (retried until done); "Delete keys" unlinks the
//    key files and keeps the logs; the runtime reports it all in rooms.v2.status and keeps the M1 fork
//    agents under the resume tripwire.
// 2. A v2 member given a `prc1.` code answers with the upgrade message and makes no network call.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { createServer } from "node:net";
import nodePath, { join } from "node:path";
import { test } from "node:test";
import { ensureInertMcp, restrictRoomAgentConfig } from "../../server/gateway/agent-guard";
import { projectDirNameFromCwd } from "../../server/gateway/tripwire";
import { JoinRefusedError } from "../../server/member/invite-check";
import { archivedKeyFiles, deleteArchivedKeys, detectV1, migrateV1, readMigration, removeV1Registrations } from "../../server/migration/v1";
import { defaultProtection } from "../../server/platform/file-protection";
import { gateDevSwitches, TEST_HOME_MARKER, TEST_HOME_MARKER_TEXT } from "../../server/platform/test-clock";
import { RoomsRuntimeV2 } from "../../server/runtime-v2";
import { roomsV2Status } from "../../shared/rpc-v2";
import { V1, writeV1Tree } from "./fixtures";
import { tempDir } from "./helpers";

const NOW = () => new Date("2026-11-01T10:00:00Z");
const ARCHIVE = "v1-archive-2026-11-01";

function home(): { dir: string; data: string; cleanup(): void } {
  const t = tempDir();
  const dir = join(t.dir, "home");
  fs.mkdirSync(dir, { mode: 0o700 });
  const data = join(dir, "plugin-data", "rooms");
  fs.mkdirSync(data, { recursive: true, mode: 0o700 });
  writeV1Tree(data, fs, nodePath);
  return { dir, data, cleanup: t.cleanup };
}

/** Every file under a directory, relative, sorted. */
function tree(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of fs.readdirSync(d)) {
      const p = join(d, n);
      if (fs.lstatSync(p).isDirectory()) walk(p);
      else out.push(nodePath.relative(dir, p).split(nodePath.sep).join("/"));
    }
  };
  walk(dir);
  return out.sort();
}

test("migration 1: a v1 tree is archived by rename, recorded in migration.json, and a second run does nothing", async () => {
  const h = home();
  try {
    // v2 data of a home that also ran the development runtime: it must stay in member/.
    fs.mkdirSync(join(h.data, "member", "rooms", "room_v2"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(join(h.data, "member", "settings.json"), "{}", { mode: 0o600 });
    assert.deepEqual(detectV1(h.data), { gateway: true, member: true });
    const before = tree(h.data);

    const r = await migrateV1(h.data, { now: NOW });
    assert.equal(r.changed, true);
    assert.deepEqual(detectV1(h.data), { gateway: false, member: false });
    const after = tree(h.data);
    assert.deepEqual(after, [
      "limits.json",
      "member/settings.json",
      "migration.json",
      `${ARCHIVE}/gateway/host-key.json`,
      `${ARCHIVE}/gateway/rooms/${V1.roomId}/events.jsonl`,
      `${ARCHIVE}/gateway/state.json`,
      `${ARCHIVE}/member/device.json`,
      `${ARCHIVE}/member/rooms.json`,
    ]);
    assert.ok(fs.existsSync(join(h.data, "member", "rooms", "room_v2")), "v2 member data stays in place");
    assert.equal(before.length + 1, after.length, "nothing lost: every file moved, plus migration.json");
    // Owner-only everywhere (identity-model 7.8): the start check of the runtime passes.
    assert.deepEqual(defaultProtection().verifyTree(h.data), { ok: true });
    assert.equal(fs.statSync(join(h.data, ARCHIVE)).mode & 0o777, 0o700);
    assert.equal(fs.statSync(join(h.data, "migration.json")).mode & 0o777, 0o600);

    const rec = readMigration(h.data)!;
    assert.equal(rec.archive, ARCHIVE);
    assert.equal(rec.detectedAt, NOW().toISOString());
    assert.deepEqual([rec.gateway, rec.member, rec.hosts], ["archived", "archived", "pending"]);
    assert.deepEqual(
      rec.ownerLanes.map((l) => [l.laneId, l.agentId, l.origin]),
      [
        [V1.shareLane, V1.shareAgent, "share"],
        [V1.forkLane, V1.forkAgent, "fork"],
      ],
    );
    assert.deepEqual(rec.memberLanes, [{ laneId: V1.joinedLane, registrationId: V1.registrationId }]);
    assert.equal(fs.readFileSync(join(h.data, "migration.json"), "utf8").includes(V1.secret), false, "no key material in the record");

    // Second run: nothing to do, nothing changes.
    const text = fs.readFileSync(join(h.data, "migration.json"), "utf8");
    const again = await migrateV1(h.data, { now: () => new Date("2026-11-02T10:00:00Z") });
    assert.equal(again.changed, false);
    assert.deepEqual(tree(h.data), after);
    assert.equal(fs.readFileSync(join(h.data, "migration.json"), "utf8"), text);
  } finally {
    h.cleanup();
  }
});

test("migration 1: no v1 data, no record; a win32 sharing violation leaves the step pending and the next start finishes it", async () => {
  const t = tempDir();
  try {
    assert.deepEqual(await migrateV1(t.dir), { record: null, changed: false });
    assert.equal(fs.existsSync(join(t.dir, "migration.json")), false);
  } finally {
    t.cleanup();
  }
  const h = home();
  try {
    const sleeps: number[] = [];
    const busy = Object.assign(new Error("busy"), { code: "EBUSY" });
    const r = await migrateV1(h.data, {
      now: NOW,
      platform: "win32",
      sleep: async (ms) => void sleeps.push(ms),
      renameSync: (from, to) => {
        if (from.endsWith("gateway")) throw busy;
        fs.renameSync(from, to);
      },
    });
    assert.deepEqual([r.record?.gateway, r.record?.member], ["pending", "archived"]);
    assert.ok(sleeps.length >= 5, "retried with backoff");
    assert.ok(fs.existsSync(join(h.data, "gateway", "host-key.json")), "v1 data left in place");
    // On Linux the same error is not retried: it is unexpected, and the start reports it.
    await assert.rejects(migrateV1(h.data, { now: NOW, platform: "linux", renameSync: () => { throw busy; } }), /busy/);
    // Next start, the file is free again: the same archive is completed.
    const done = await migrateV1(h.data, { now: () => new Date("2026-11-03T10:00:00Z") });
    assert.deepEqual([done.record?.archive, done.record?.gateway, done.record?.member], [ARCHIVE, "archived", "archived"]);
    assert.ok(fs.existsSync(join(h.data, ARCHIVE, "gateway", "host-key.json")));
    assert.equal(done.record?.attempts, 3);
  } finally {
    h.cleanup();
  }
});

test("migration 1: v1 registrations are removed (plugin:rooms, v1 lane ids only), retried until done; Delete keys keeps the logs", async () => {
  const h = home();
  try {
    await migrateV1(h.data, { now: NOW });
    const hosts = [
      { registrationId: V1.registrationId, source: { id: "plugin:rooms", key: V1.joinedLane } },
      { registrationId: "other-plugin", source: { id: "plugin:other", key: V1.joinedLane } },
      { registrationId: "v2-lane", source: { id: "plugin:rooms", key: `lane_${"d".repeat(32)}` } },
      { registrationId: "manual", source: null },
    ];
    const removed: string[] = [];
    let fail = true;
    const api = {
      list: async () => ({ hosts: hosts.filter((x) => !removed.includes(x.registrationId)) }),
      remove: async (id: string) => {
        if (fail) throw new Error("daemon busy");
        removed.push(id);
      },
    };
    await assert.rejects(removeV1Registrations(h.data, api), /busy/);
    assert.equal(readMigration(h.data)?.hosts, "pending", "a failure keeps the step pending");
    fail = false;
    assert.equal(await removeV1Registrations(h.data, api), 1);
    assert.deepEqual(removed, [V1.registrationId]);
    assert.deepEqual([readMigration(h.data)?.hosts, readMigration(h.data)?.hostsRemoved], ["done", 1]);
    assert.equal(await removeV1Registrations(h.data, api), 0, "done: no second pass");

    assert.deepEqual(archivedKeyFiles(h.data), [`${ARCHIVE}/gateway/host-key.json`, `${ARCHIVE}/gateway/state.json`, `${ARCHIVE}/member/device.json`]);
    const gone = deleteArchivedKeys(h.data, NOW);
    assert.equal(gone.length, 3);
    assert.deepEqual(archivedKeyFiles(h.data), []);
    assert.deepEqual(tree(join(h.data, ARCHIVE)), [`gateway/rooms/${V1.roomId}/events.jsonl`, "member/rooms.json"], "the logs stay");
    for (const f of tree(h.data)) assert.equal(fs.readFileSync(join(h.data, f), "utf8").includes(V1.secret), false, `${f} holds no v1 secret`);
    assert.equal(readMigration(h.data)?.keysDeletedAt, NOW().toISOString());
  } finally {
    h.cleanup();
  }
});

test("migration 1 (runtime): start archives v1 data before the keystore, status shows it, hosts are cleaned on attach, M1 forks keep the tripwire", async () => {
  const h = home();
  const rt = new RoomsRuntimeV2({ PASEO_HOME: h.dir, PASEO_ROOMS_KEYSTORE: "fallback-file" });
  try {
    await rt.start();
    const s = rt.status();
    assert.equal(s.state, "ready", s.error ?? "");
    roomsV2Status.output.parse(s);
    assert.ok(s.migration);
    assert.equal(s.migration.notice, true);
    assert.equal(s.migration.keyFiles.length, 3);
    assert.deepEqual(s.migration.lanes.map((l) => l.agentId).sort(), [V1.shareAgent, V1.forkAgent].sort());
    assert.ok(!JSON.stringify(s.migration).includes(V1.secret));
    assert.equal(rt.laneAgents().length, 0, "no v1 lane is served");

    // attach: the v1 registration is removed through the PaseoApi.
    const removed: string[] = [];
    const paseo = {
      hosts: {
        list: async () => ({ hosts: [{ registrationId: V1.registrationId, source: { id: "plugin:rooms", key: V1.joinedLane } }].filter((x) => !removed.includes(x.registrationId)) }),
        remove: async (id: string) => void removed.push(id),
        observe: () => ({ release: async () => undefined, subscribe: () => undefined, ready: Promise.resolve({ hosts: [] }) }),
      },
    };
    rt.attach(paseo as never);
    for (let i = 0; i < 100 && rt.status().migration?.hosts !== "done"; i++) await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(removed, [V1.registrationId]);
    assert.equal(rt.status().migration?.hosts, "done");

    // The M1 fork agent: intact shadow passes, an altered stored config refuses the resume.
    const inert = ensureInertMcp(join(h.dir, "plugin-data", "rooms"));
    const store = (config: unknown) => {
      const d = join(h.dir, "agents", projectDirNameFromCwd("/w"));
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(join(d, `${V1.forkAgent}.json`), JSON.stringify({ id: V1.forkAgent, provider: "claude", cwd: "/w", labels: {}, config }));
    };
    store(restrictRoomAgentConfig({ provider: "claude" }, inert));
    assert.doesNotThrow(() => rt.assertRoomAgentIntact(V1.forkAgent));
    assert.doesNotThrow(() => rt.assertRoomAgentIntact(V1.shareAgent), "share lanes used the owner's own agent: not checked");
    store({ mcpServers: { paseo: { type: "http", url: "http://127.0.0.1/mcp/agents" } } });
    assert.throws(() => rt.assertRoomAgentIntact(V1.forkAgent), /isolation check/);

    await rt.dismissMigrationNotice();
    assert.equal(rt.status().migration?.notice, false);
    assert.equal((await rt.deleteV1Keys()).removed.length, 3);
    assert.deepEqual(rt.status().migration?.keyFiles, []);
  } finally {
    await rt.stop();
    h.cleanup();
  }
});

test("migration 2: a prc1. code gets the upgrade message and no network call", async () => {
  // Anything that tried to reach the relay or the lane named in the code would connect here.
  let connections = 0;
  const server = createServer((s) => {
    connections++;
    s.destroy();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  const t = tempDir();
  const dir = join(t.dir, "home");
  fs.mkdirSync(dir, { mode: 0o700 });
  const rt = new RoomsRuntimeV2({ PASEO_HOME: dir, PASEO_ROOMS_KEYSTORE: "fallback-file", PASEO_ROOMS_RELAY_ENDPOINT: `127.0.0.1:${port}`, PASEO_ROOMS_RELAY_TLS: "false", PASEO_ROOMS_DEV_INSECURE_RELAY: "1" }, undefined, { allowDevSwitches: true });
  try {
    await rt.start();
    // An M1 invite payload (shared/schemas.ts InvitePayload at m1-baseline) naming the local server.
    const payload = {
      v: 1,
      roomId: "room_00112233445566aa",
      roomName: "Old room",
      laneId: "lane_aaaaaaaaaaaaaaaa",
      laneLabel: "Live",
      offer: { serverId: `lane_${"S".repeat(32)}`, publicKeyB64: "A".repeat(44), relay: { endpoint: `127.0.0.1:${port}`, useTls: false } },
      host: { keyId: "0123456789abcdef", publicKey: "B".repeat(43) },
      inviteId: "inv_0011223344556677",
      token: "t".repeat(43),
      exp: Math.floor(Date.now() / 1000) + 600,
    };
    const code = `prc1.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
    const upgrade = /older version of Rooms\. Ask the owner for a new invite/;
    const isUpgrade = (e: unknown) => e instanceof JoinRefusedError && e.code === "older_version" && upgrade.test(e.message);
    await assert.rejects(rt.previewJoin(code), isUpgrade);
    await assert.rejects(rt.startJoin({ code, label: "Laptop", trustRelay: true }), isUpgrade);
    await assert.rejects(rt.previewJoin(`  ${code}\n`), isUpgrade, "surrounding whitespace does not change the answer");
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(connections, 0, "no network call");
    assert.equal(rt.status().joining.length, 0, "nothing journaled");
    assert.equal(fs.existsSync(join(dir, "plugin-data", "rooms", "member", "rooms")), false);
  } finally {
    await rt.stop();
    server.close();
    t.cleanup();
  }
});

test("I-15: PASEO_ROOMS_DEV_* switches are honoured only on a marked e2e test home", () => {
  const t = tempDir();
  try {
    const env = { PASEO_ROOMS_DEV_SHORT_GRANTS: "1", PASEO_ROOMS_DEV_INSECURE_RELAY: "1", PASEO_ROOMS_KEYSTORE: "fallback-file" };
    const plain = join(t.dir, "home");
    fs.mkdirSync(plain, { mode: 0o700 });
    const g = gateDevSwitches(env, plain);
    assert.deepEqual(g.dropped.sort(), ["PASEO_ROOMS_DEV_INSECURE_RELAY", "PASEO_ROOMS_DEV_SHORT_GRANTS"]);
    assert.deepEqual(g.env, { PASEO_ROOMS_KEYSTORE: "fallback-file" });
    assert.equal(g.refusal, "not_a_test_home");
    const test = join(t.dir, ".test-homes", "v2-owner");
    fs.mkdirSync(test, { recursive: true, mode: 0o700 });
    assert.equal(gateDevSwitches(env, test).refusal, "no_marker");
    fs.writeFileSync(join(test, TEST_HOME_MARKER), "something else\n", { mode: 0o600 });
    assert.equal(gateDevSwitches(env, test).refusal, "bad_marker");
    fs.writeFileSync(join(test, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT, { mode: 0o600 });
    assert.deepEqual(gateDevSwitches(env, test), { env, dropped: [], refusal: null });
    assert.deepEqual(gateDevSwitches({ PASEO_ROOMS_KEYSTORE: "x" }, plain).dropped, [], "nothing to drop");
    assert.deepEqual(gateDevSwitches(env, plain, { allow: true }).dropped, [], "unit tests may allow them explicitly");
  } finally {
    t.cleanup();
  }
});
