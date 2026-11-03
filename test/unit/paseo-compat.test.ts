// R2.7 compatibility guard (decisions round 10, item 2): the manifest range, the verdict for simulated
// daemon versions and protocols, the start probe, and a lane that refuses to serve on an untested
// daemon. Uses the fake loopback daemon; no real daemon, relay or network.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { checkPaseoCompat, CompatGuard, inTestedRange, legacyForkAgentsAllowed, PASEO_RANGE_TEXT, sessionOpenAllowsInjection, TESTED_PROFILE_ENTRIES } from "../../server/compat";
import { LaneConnection, LaneEndpoint } from "../../server/gateway/lane-endpoint";
import { ROOM_PROFILE_PROTOCOL_VERSION } from "../../server/room-profile/generated";
import { startFakeDaemon, type FakeDaemon } from "./fake-daemon";
import { TestAuthority, testLane } from "./lane-harness";

const root = join(__dirname, "..", "..");

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

test("compat: the manifest range, the guard's range and the profile's protocol release agree", () => {
  const manifest = JSON.parse(readFileSync(join(root, "paseo-plugin.json"), "utf8"));
  assert.equal(manifest.requirements.paseo, ">=0.13.2 <0.15.0");
  assert.equal(PASEO_RANGE_TEXT, manifest.requirements.paseo);
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.equal(pkg.dependencies["@getpaseo/protocol"], ROOM_PROFILE_PROTOCOL_VERSION);
  assert.ok(TESTED_PROFILE_ENTRIES.some((e) => e.profile === ROOM_PROFILE_PROTOCOL_VERSION), "the current profile has a tested entry");
});

test("compat: simulated daemon versions against >=0.13.2 <0.15.0", () => {
  for (const v of ["0.13.2", "0.13.3", "0.13.99", "v0.13.2", "0.13.4+build.7", "0.14.0", "0.14.1", "0.14.99"]) assert.equal(inTestedRange(v), true, v);
  for (const v of ["0.13.1", "0.12.9", "0.15.0", "0.15.1", "1.0.0", "0.13.3-beta.1", "0.14.0-beta.2", "0.14.1-rc.1", "0.15.0-beta.1", "0.14", "latest", ""])
    assert.equal(inTestedRange(v), false, v);
  for (const v of ["0.13.2", "0.13.5", "0.14.0"]) assert.equal(checkPaseoCompat({ version: v, protocolVersion: 1 }).ok, true, v);
});

test("compat: fails closed with a clear owner message on every untested or unreadable daemon", () => {
  const cases: [Record<string, unknown> | null, string][] = [
    [{ version: "0.15.0", protocolVersion: 1 }, "version_untested"],
    [{ version: "0.15.0-beta.1", protocolVersion: 1 }, "version_untested"],
    [{ version: "0.13.1", protocolVersion: 1 }, "version_untested"],
    [{ version: "0.13.3-beta.1", protocolVersion: 1 }, "version_untested"],
    [{ version: "0.14.0-beta.2", protocolVersion: 1 }, "version_untested"],
    [{ version: "1.2.3", protocolVersion: 2 }, "version_untested"],
    [{ protocolVersion: 1 }, "version_unknown"],
    [{ version: null, protocolVersion: 1 }, "version_unknown"],
    [{ version: "not-a-version", protocolVersion: 1 }, "version_unknown"],
    [null, "version_unknown"],
    [{ version: "0.13.2" }, "protocol_unknown"],
    [{ version: "0.13.2", protocolVersion: "1" }, "protocol_unknown"],
    [{ version: "0.13.2", protocolVersion: 2 }, "protocol_untested"],
    [{ version: "0.13.2", protocolVersion: 0 }, "protocol_untested"],
    [{ version: "0.14.0", protocolVersion: 2 }, "protocol_untested"],
  ];
  for (const [info, code] of cases) {
    const v = checkPaseoCompat(info);
    assert.equal(v.ok, false, JSON.stringify(info));
    assert.equal(v.code, code, JSON.stringify(info));
    assert.match(v.message ?? "", /Shared agents are paused/);
    assert.match(v.action ?? "", /Rooms update|tested range/);
    assert.equal(v.testedRange, ">=0.13.2 <0.15.0");
  }
  const v = checkPaseoCompat({ version: "0.15.0", protocolVersion: 1 });
  assert.match(v.message!, /Paseo 0\.15\.0 is outside .*>=0\.13\.2 <0\.15\.0/);
  assert.equal(v.version, "0.15.0");
  assert.equal(v.protocolVersion, 1);
  // A tested protocol needs an entry for the profile the plugin was built with.
  assert.equal(checkPaseoCompat({ version: "0.13.2", protocolVersion: 1 }, [{ protocolVersion: 1, profile: "0.12.0" }]).code, "protocol_untested");
  assert.equal(checkPaseoCompat({ version: "0.14.0", protocolVersion: 1 }, [{ protocolVersion: 1, profile: "0.13.2" }]).code, "protocol_untested");
});

test("compat: the start probe retries until the daemon answers, then records the verdict once", async () => {
  const events: string[] = [];
  const g = new CompatGuard({ log: (e) => void events.push(e) });
  let calls = 0;
  await new Promise<void>((resolve) => {
    g.probe("/nonexistent", {
      delays: [1],
      connect: async () => {
        calls++;
        if (calls < 3) throw new Error("daemon not listening yet");
        setImmediate(resolve);
        return { version: "0.15.2", protocolVersion: 1 };
      },
    });
  });
  assert.equal(calls, 3);
  assert.equal(g.verdict?.code, "version_untested");
  g.observe({ version: "0.15.2", protocolVersion: 1 });
  assert.deepEqual(events, ["paseo_compat_refused"], "an unchanged verdict is logged once");
  g.stop();
});

test("compat: a lane on an untested daemon is not served and the guard records why; a tested daemon serves", async () => {
  // Loopback relay address on a closed port: a lane that does start never leaves this machine.
  const lane = testLane({ relay: { endpoint: "127.0.0.1:1", useTls: false } });
  try {
    for (const [sv, blocked] of [
      [{ version: "0.15.0", protocolVersion: 1 }, "paseo_version_untested"],
      [{ version: "0.13.2", protocolVersion: 2 }, "paseo_protocol_untested"],
      [{ version: "0.13.2" }, "paseo_protocol_unknown"],
    ] as const) {
      fake.serverVersion = sv;
      const guard = new CompatGuard();
      const before = fake.messages.length;
      const ep = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: fake.home, compat: guard });
      await ep.start();
      assert.equal(ep.blockedReason, blocked, JSON.stringify(sv));
      assert.equal(ep.status, "offline");
      assert.equal(fake.messages.length, before, "no request after the server_info");
      assert.equal(guard.verdict?.ok, false);
      await ep.stop();
    }
    // Without a guard the check still runs (fail closed by default).
    fake.serverVersion = { version: "1.0.0", protocolVersion: 1 };
    const bare = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: fake.home });
    await bare.start();
    assert.equal(bare.blockedReason, "paseo_version_untested");
    await bare.stop();
    // The tested versions: the lane proceeds to look up its agent.
    fake.onSession = (m, reply) => {
      if (m.type === "fetch_agent_request") reply({ type: "fetch_agent_response", payload: { requestId: m.requestId, agent: { id: lane.agentId, workspaceId: lane.workspaceId } } });
    };
    for (const version of ["0.13.2", "0.14.0"]) {
      fake.serverVersion = { version, protocolVersion: 1 };
      const guard = new CompatGuard();
      const ok = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: fake.home, compat: guard });
      await ok.start();
      assert.equal(ok.blockedReason, null, version);
      assert.equal(guard.verdict?.ok, true, version);
      await ok.stop();
    }
  } finally {
    fake.serverVersion = { version: "0.13.2", protocolVersion: 1 };
    fake.onSession = () => undefined;
  }
});

test("compat: legacy fork room agents are allowed only on provable Paseo 0.13.x without session-time injection", () => {
  for (const v of ["0.13.2", "0.13.9", "v0.13.2"]) assert.equal(legacyForkAgentsAllowed(v), true, v);
  for (const v of ["0.14.0", "0.14.1", "0.15.0", "0.13.1", "0.13.3-beta.1", "0.14.0-beta.2", "", "x", null, undefined, 13]) assert.equal(legacyForkAgentsAllowed(v), false, String(v));
  const open0132 = { agentId: "a", workspaceId: null, provider: "claude", cwd: "/w", reason: "resume", purpose: "interactive", env: {} };
  assert.equal(sessionOpenAllowsInjection(open0132), false);
  assert.equal(sessionOpenAllowsInjection({ ...open0132, title: null, labels: {}, tools: [], mcpServers: {} }), true);
  assert.equal(sessionOpenAllowsInjection({ ...open0132, mcpServers: {} }), true);
  assert.equal(sessionOpenAllowsInjection(null), true, "fails closed");
});

test("compat: a legacy fork lane is served on Paseo 0.13.2 and refused on 0.14.0; a share lane is served on both", async () => {
  fake.onSession = (m, reply) => {
    if (m.type === "fetch_agent_request") reply({ type: "fetch_agent_response", payload: { requestId: m.requestId, agent: { id: m.agentId, workspaceId: "wks_1" } } });
  };
  try {
    for (const [version, kind, blocked] of [
      ["0.13.2", "fork", null],
      ["0.14.0", "fork", "legacy_fork_agent_refused"],
      ["0.14.0", "share", null],
      ["0.13.2", "share", null],
    ] as const) {
      fake.serverVersion = { version, protocolVersion: 1 };
      const lane = testLane({ origin: { kind }, relay: { endpoint: "127.0.0.1:1", useTls: false } });
      const ep = new LaneEndpoint(lane, { authority: new TestAuthority(), paseoHome: fake.home, compat: new CompatGuard(), verifyRoomAgent: () => ({ ok: true, problems: [] }) });
      await ep.start();
      assert.equal(ep.blockedReason, blocked, `${version} ${kind}`);
      await ep.stop();
    }
  } finally {
    fake.serverVersion = { version: "0.13.2", protocolVersion: 1 };
    fake.onSession = () => undefined;
  }
});
