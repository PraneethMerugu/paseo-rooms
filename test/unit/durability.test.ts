// D: revocation enforce-then-persist (P-13), durable writes, safe pruning and the grant allowlist
// (P-12/C-9), torn room log recovery (C-11), log clipping and limiting (C-5), member timers (C-12),
// archived-agent lane closure (C-13).
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { generateEd25519, signEd25519 } from "../../server/crypto";
import { Gateway } from "../../server/gateway/gateway";
import { issueGrant } from "../../server/grants";
import { RoomEventLog } from "../../server/host/event-log";
import { HostStore, REVOKED_GRANT_RETENTION_S } from "../../server/host/host-store";
import { decodeInviteCode } from "../../server/invite-code";
import { clip, LogLimiter } from "../../server/log";
import { MemberRole } from "../../server/member/member";
import { writePrivateFile } from "../../server/paths";
import { defaultProtection } from "../../server/platform/file-protection";
import { tempDir } from "./helpers";

function setup(nowRef = { t: Date.parse("2026-10-28T12:00:00Z") }) {
  const tmp = tempDir();
  const host = new HostStore(tmp.dir, { endpoint: "relay.example:443", useTls: true }, () => nowRef.t);
  const room = host.createRoom("Lab");
  const lane = host.createLane({ roomId: room.id, label: "Live", origin: { kind: "share", agentId: "agent-1" }, agentId: "agent-1", workspaceId: "wks_1" });
  return { tmp, host, room, lane, nowRef };
}

function enroll(host: HostStore, laneId: string, device = generateEd25519()) {
  const { code } = host.createInvite({ laneId, ttlSeconds: 600, grantTtlSeconds: 3600 });
  const invite = decodeInviteCode(code);
  const transcript = (tokenHash: string) =>
    HostStore.transcript({ op: "enroll", laneId, laneServerId: invite.offer.serverId, hostKeyId: host.hostKey.keyId, nonce: "n".repeat(43), devicePublicKey: device.publicKey, tokenHash, daemonServerId: null, label: "Ada" });
  return host.enroll({
    laneId,
    token: invite.token,
    devicePublicKey: device.publicKey,
    label: "Ada",
    daemonServerId: null,
    verifySignature: (h) => host.verifyDeviceSignature(device.publicKey, transcript(h), signEd25519(device, transcript(h))),
  });
}

/** Makes the next state.json write fail: a non-empty directory in its place blocks the rename. */
function blockStateFile(dir: string): () => void {
  const p = join(dir, "gateway", "state.json");
  const saved = readFileSync(p);
  rmSync(p);
  mkdirSync(join(p, "blocker"), { recursive: true });
  return () => {
    rmSync(p, { recursive: true, force: true });
    writeFileSync(p, saved, { mode: 0o600 });
  };
}

test("P-13: revocation is enforced even when saving fails, reports it, and persists once the disk is back", () => {
  const { tmp, host, lane } = setup();
  let unblock: (() => void) | null = null;
  try {
    const { member, token } = enroll(host, lane.id);
    const pushed: string[] = [];
    host.onChange((c) => void pushed.push(c.kind));
    unblock = blockStateFile(tmp.dir);
    assert.throws(() => host.revokeMember(member.id), /in effect now/);
    assert.deepEqual(pushed, ["member_revoked"], "live sessions were told before the write");
    assert.equal(host.checkGrantLive(token, lane.id).ok, false);
    assert.equal(host.dirty, true);
    unblock();
    unblock = null;
    (host as any).save();
    assert.equal(host.dirty, false);
    const reloaded = new HostStore(tmp.dir, { endpoint: "relay.example:443", useTls: true });
    assert.equal(reloaded.member(member.id)?.status, "revoked");
    assert.equal(reloaded.checkGrantLive(token, lane.id).ok, false);
    host.dispose();
  } finally {
    unblock?.();
    host.dispose();
    tmp.cleanup();
  }
});

test("durable writes leave no temp files and keep 0600", () => {
  const tmp = tempDir();
  try {
    const p = join(tmp.dir, "x", "state.json");
    writePrivateFile(p, "{}");
    writePrivateFile(p, '{"a":1}');
    assert.equal(readFileSync(p, "utf8"), '{"a":1}');
    assert.deepEqual(readdirSync(join(tmp.dir, "x")), ["state.json"]);
    assert.deepEqual(defaultProtection().verify(p), { ok: true });
  } finally {
    tmp.cleanup();
  }
});

test("P-12/C-9: only the member's current grant is accepted; revoked ids are kept past exp plus a margin", () => {
  const { tmp, host, lane, nowRef } = setup();
  try {
    const { member, token } = enroll(host, lane.id);
    // A second validly signed grant for the same active member and device that the host never recorded
    // (e.g. after a clock step revived a pruned id, or minted elsewhere) is refused.
    const stray = issueGrant(host.hostKey, { roomId: lane.roomId, laneId: lane.id, laneServerId: lane.serverId, memberId: member.id, deviceKeyId: member.deviceKeyId, ttlSeconds: 3600, nowMs: nowRef.t });
    assert.equal(host.checkGrantLive(stray.token, lane.id).reason, "superseded_grant");
    assert.equal(host.checkGrantLive(token, lane.id).ok, true);
    const renewed = host.renew(member);
    assert.equal(host.checkGrantLive(token, lane.id).ok, false);
    assert.equal(host.checkGrantLive(renewed.token, lane.id).ok, true);
    // Pruning: still listed just after exp, gone after exp + retention.
    const revokedIds = () => (host as any).state.revokedGrantIds.map((g: any) => g.gid);
    const oldGid = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).gid;
    nowRef.t += 3601_000;
    host.createRoom("tick");
    assert.ok(revokedIds().includes(oldGid));
    nowRef.t += REVOKED_GRANT_RETENTION_S * 1000;
    host.createRoom("tick2");
    assert.ok(!revokedIds().includes(oldGid));
  } finally {
    tmp.cleanup();
  }
});

test("P-13: re-enrolment logs the replaced membership; lane close records its reason", () => {
  const { tmp, host, lane, room } = setup();
  try {
    const device = generateEd25519();
    const first = enroll(host, lane.id, device);
    enroll(host, lane.id, device);
    const left = host.events(room.id).filter((e) => e.type === "member.left");
    assert.equal(left.length, 1);
    assert.equal(left[0].data.memberId, first.member.id);
    assert.equal(left[0].data.reason, "re_enrolled");
    host.closeLane(lane.id, { actor: "host", reason: "agent_archived" });
    const closed = host.events(room.id).find((e) => e.type === "lane.closed")!;
    assert.equal(closed.actor, "host");
    assert.equal(closed.data.reason, "agent_archived");
    assert.equal(host.verifyLog(room.id).ok, true);
  } finally {
    tmp.cleanup();
  }
});

test("C-11: a torn last log line is quarantined and the log keeps working", () => {
  const { tmp, host, room } = setup();
  try {
    const file = join(tmp.dir, "gateway", "rooms", room.id, "events.jsonl");
    const before = host.events(room.id).length;
    writeFileSync(file, readFileSync(file, "utf8") + '{"v":1,"roomId":"room_', { flag: "w" });
    const log = new RoomEventLog(file, host.hostKey);
    assert.equal(log.recoveredTornTail, true);
    assert.ok(readdirSync(join(tmp.dir, "gateway", "rooms", room.id)).some((n) => n.startsWith("events.jsonl.torn-")));
    log.append({ roomId: room.id, type: "invite.revoked", actor: "owner", data: { inviteId: "inv_x" } });
    assert.equal(log.readAll().length, before + 1);
    assert.deepEqual(log.verify(), { ok: true });
    // A fresh HostStore (plugin restart) also works: record() no longer throws.
    const host2 = new HostStore(tmp.dir, { endpoint: "relay.example:443", useTls: true });
    host2.createLane({ roomId: room.id, label: "Again", origin: { kind: "share", agentId: "a" }, agentId: "a", workspaceId: "w" });
    assert.equal(host2.verifyLog(room.id).ok, true);
  } finally {
    tmp.cleanup();
  }
});

test("C-11: a complete last event missing only its newline is kept; a corrupt middle line is reported, not rewritten", () => {
  const { tmp, host, room } = setup();
  try {
    const file = join(tmp.dir, "gateway", "rooms", room.id, "events.jsonl");
    const text = readFileSync(file, "utf8");
    writeFileSync(file, text.slice(0, -1));
    const log = new RoomEventLog(file, host.hostKey);
    assert.equal(log.recoveredTornTail, false);
    assert.ok(readFileSync(file, "utf8").endsWith("\n"));
    assert.deepEqual(log.verify(), { ok: true });
    const lines = readFileSync(file, "utf8").split("\n");
    lines.splice(1, 0, "garbage");
    writeFileSync(file, lines.join("\n"));
    const log2 = new RoomEventLog(file, host.hostKey);
    const v = log2.verify();
    assert.equal(v.ok, false);
    assert.match((v as any).reason, /^corrupt_line:2$/);
    log2.append({ roomId: room.id, type: "invite.revoked", actor: "owner", data: { inviteId: "inv_y" } });
    assert.ok(readFileSync(file, "utf8").includes("garbage"), "the middle line is never rewritten");
  } finally {
    tmp.cleanup();
  }
});

test("C-5: peer strings are clipped and deny logs are limited per source", () => {
  assert.equal(clip("a\nb\u0000c"), "a?b?c");
  assert.match(clip("x".repeat(500))!, /…\(500\)$/);
  let t = 0;
  const lim = new LogLimiter(3, 60, 10, () => t);
  const written = Array.from({ length: 10 }, () => lim.log("k", "test_event", {})).filter(Boolean).length;
  assert.equal(written, 3);
  t += 1000; // one token per second at 60/min
  assert.equal(lim.log("k", "test_event", {}), true);
  assert.equal(lim.log("other", "test_event", {}), true, "buckets are per key");
});

test("C-12: member rotation timers are armed at plugin start; a timer that fires before the API is attached is parked", async () => {
  const tmp = tempDir();
  try {
    const nowS = Math.floor(Date.now() / 1000);
    mkdirSync(join(tmp.dir, "member"), { recursive: true });
    const rec = {
      v: 1,
      roomId: "room_0123456789abcdef",
      roomName: "Lab",
      laneId: "lane_0123456789abcdef",
      laneLabel: "Live",
      memberId: "mem_0123456789abcdef",
      offer: { serverId: `lane_${"A".repeat(32)}`, publicKeyB64: "k".repeat(44), relay: { endpoint: "relay.example:443", useTls: true } },
      host: { keyId: "0123456789abcdef", publicKey: "p".repeat(43) },
      joinedAt: new Date().toISOString(),
      status: "active",
      registrationId: "reg_1",
      grantGid: "g_0123456789abcdef",
      grantIat: nowS - 100,
      grantExp: nowS + 20, // past half-life: fires after the 1 s minimum
      lastRotationAt: null,
    };
    writeFileSync(join(tmp.dir, "member", "rooms.json"), JSON.stringify({ v: 1, rooms: [rec, { ...rec, laneId: "lane_ffffffffffffffff", status: "left" }] }));
    const m = new MemberRole(tmp.dir);
    m.start();
    assert.deepEqual(m.timerState().armed, ["lane_0123456789abcdef"]);
    await new Promise((r) => setTimeout(r, 1200));
    assert.deepEqual(m.timerState(), { armed: [], pending: ["lane_0123456789abcdef"] });
    await m.stop();
  } finally {
    tmp.cleanup();
  }
});

test("C-13: agent.archived closes every open lane of that agent and records it", async () => {
  const tmp = tempDir();
  const gw = new Gateway(tmp.dir, join(tmp.dir, "no-daemon-home"), { endpoint: "relay.example:443", useTls: true });
  try {
    gw.start();
    const room = gw.host.createRoom("Lab");
    const lane = gw.host.createLane({ roomId: room.id, label: "Live", origin: { kind: "share", agentId: "agent-z" }, agentId: "agent-z", workspaceId: "w" });
    assert.ok(gw.endpoints.has(lane.id));
    assert.equal(gw.onAgentArchived("agent-z"), 1);
    assert.equal(gw.host.lane(lane.id)?.status, "closed");
    assert.equal(gw.endpoints.has(lane.id), false);
    const ev = gw.host.events(room.id).find((e) => e.type === "lane.closed")!;
    assert.deepEqual([ev.actor, ev.data.reason], ["host", "agent_archived"]);
    assert.equal(gw.onAgentArchived("agent-z"), 0, "idempotent");
  } finally {
    await gw.stop();
    gw.host.dispose();
    tmp.cleanup();
  }
});

test("a failed durable write leaves the previous file intact", () => {
  const tmp = tempDir();
  try {
    const dir = join(tmp.dir, "d");
    writePrivateFile(join(dir, "f.json"), "1");
    mkdirSync(join(dir, "g.json", "blocker"), { recursive: true });
    assert.throws(() => writePrivateFile(join(dir, "g.json"), "2"));
    assert.equal(readFileSync(join(dir, "f.json"), "utf8"), "1");
    assert.ok(existsSync(join(dir, "f.json")));
  } finally {
    tmp.cleanup();
  }
});
