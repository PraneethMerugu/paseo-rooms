// Grants, enrollment, renewal and revocation in the embedded host.
import assert from "node:assert/strict";
import { test } from "node:test";
import { generateEd25519, sha256Hex, signEd25519 } from "../../server/crypto";
import { issueGrant, verifyGrant } from "../../server/grants";
import { ControlFailure, HostStore } from "../../server/host/host-store";
import { decodeInviteCode } from "../../server/invite-code";
import { tempDir } from "./helpers";

function setup(nowRef = { t: Date.parse("2026-10-28T12:00:00Z") }) {
  const tmp = tempDir();
  const host = new HostStore(tmp.dir, { endpoint: "relay.example:443", useTls: true }, () => nowRef.t);
  const room = host.createRoom("Lab");
  const lane = host.createLane({ roomId: room.id, label: "Fork", origin: { kind: "share", agentId: "agent-1" }, agentId: "agent-1", workspaceId: "wks_1" });
  return { tmp, host, room, lane, nowRef };
}

function enrollDevice(host: HostStore, laneId: string, code: string, device = generateEd25519(), label = "Ada") {
  const invite = decodeInviteCode(code);
  const nonce = "n".repeat(43);
  const transcript = (tokenHash: string) =>
    HostStore.transcript({ op: "enroll", laneId, laneServerId: invite.offer.serverId, hostKeyId: host.hostKey.keyId, nonce, devicePublicKey: device.publicKey, tokenHash, daemonServerId: null, label });
  const sig = (tokenHash: string) => signEd25519(device, transcript(tokenHash));
  const res = host.enroll({
    laneId,
    token: invite.token,
    devicePublicKey: device.publicKey,
    label,
    daemonServerId: null,
    verifySignature: (tokenHash) => host.verifyDeviceSignature(device.publicKey, transcript(tokenHash), sig(tokenHash)),
  });
  return { ...res, device, invite };
}

test("grant: issue and verify; tampering, wrong lane, wrong issuer and expiry fail", () => {
  const key = generateEd25519();
  const other = generateEd25519();
  const exp = { hostPublicKey: key.publicKey, hostKeyId: key.keyId, laneId: "lane_0123456789abcdef", laneServerId: `lane_${"A".repeat(32)}` };
  const now = Date.parse("2026-10-28T12:00:00Z");
  const { token, claims } = issueGrant(key, { roomId: "room_0123456789abcdef", laneId: exp.laneId, laneServerId: exp.laneServerId, memberId: "mem_0123456789abcdef", deviceKeyId: "0123456789abcdef", ttlSeconds: 3600, nowMs: now });
  assert.ok(verifyGrant(token, exp, now).ok);
  assert.equal(claims.exp - claims.iat, 3600);
  const [p, body, sig] = token.split(".");
  const forged = JSON.parse(Buffer.from(body, "base64url").toString());
  forged.role = "admin";
  assert.equal(verifyGrant(`${p}.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${sig}`, exp, now).ok, false);
  assert.deepEqual(verifyGrant(token, { ...exp, laneId: "lane_ffffffffffffffff" }, now), { ok: false, reason: "wrong_audience", claims });
  assert.equal((verifyGrant(token, { ...exp, hostPublicKey: other.publicKey }, now) as any).reason, "bad_signature");
  assert.equal((verifyGrant(token, exp, now + 3600_000) as any).reason, "expired");
  assert.equal((verifyGrant("prg1.x.y", exp, now) as any).reason, "bad_signature");
  assert.equal((verifyGrant("nonsense", exp, now) as any).reason, "malformed");
});

test("enroll: one-time token, grant valid on the lane, device-bound", () => {
  const { tmp, host, lane } = setup();
  try {
    const { code } = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
    const res = enrollDevice(host, lane.id, code);
    assert.equal(res.member.status, "active");
    assert.ok(host.checkGrantLive(res.token, lane.id).ok);
    assert.throws(() => enrollDevice(host, lane.id, code), (e: unknown) => e instanceof ControlFailure && e.code === "token_used");
  } finally {
    tmp.cleanup();
  }
});

test("enroll: expired invite, bad signature, and burn after repeated bad tokens", () => {
  const { tmp, host, lane, nowRef } = setup();
  try {
    const { code } = host.createInvite({ laneId: lane.id, ttlSeconds: 60, grantTtlSeconds: 3600 });
    const invite = decodeInviteCode(code);
    const device = generateEd25519();
    assert.throws(
      () => host.enroll({ laneId: lane.id, token: invite.token, devicePublicKey: device.publicKey, label: "x", daemonServerId: null, verifySignature: () => false }),
      (e: unknown) => e instanceof ControlFailure && e.code === "bad_signature",
    );
    nowRef.t += 61_000;
    assert.throws(() => enrollDevice(host, lane.id, code), (e: unknown) => e instanceof ControlFailure && e.code === "token_expired");
    const fresh = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
    for (let i = 0; i < 5; i++)
      assert.throws(
        () => host.enroll({ laneId: lane.id, token: "A".repeat(43), devicePublicKey: device.publicKey, label: "x", daemonServerId: null, verifySignature: () => true }),
        (e: unknown) => e instanceof ControlFailure && e.code === "invalid_token",
      );
    assert.equal(host.inviteStatus(fresh.invite), "burned");
    assert.throws(() => enrollDevice(host, lane.id, fresh.code), (e: unknown) => e instanceof ControlFailure && e.code === "invalid_token");
  } finally {
    tmp.cleanup();
  }
});

test("revocation: member revoke invalidates the grant and pushes a change synchronously", () => {
  const { tmp, host, lane } = setup();
  try {
    const { code } = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
    const res = enrollDevice(host, lane.id, code);
    const changes: string[] = [];
    host.onChange((c) => changes.push(c.kind));
    host.revokeMember(res.member.id);
    assert.deepEqual(changes, ["member_revoked"], "pushed before revokeMember returns");
    assert.equal(host.checkGrantLive(res.token, lane.id).reason, "member_revoked");
    assert.throws(() => host.memberForDevice(lane.id, res.device.publicKey), (e: unknown) => e instanceof ControlFailure && e.code === "revoked");
  } finally {
    tmp.cleanup();
  }
});

test("renewal: new grant valid, superseded grant revoked, expiry enforced", () => {
  const { tmp, host, lane, nowRef } = setup();
  try {
    const { code } = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 120 });
    const res = enrollDevice(host, lane.id, code);
    const changes: string[] = [];
    host.onChange((c) => changes.push(c.kind));
    const renewed = host.renew(host.memberForDevice(lane.id, res.device.publicKey));
    assert.ok(host.checkGrantLive(renewed.token, lane.id).ok);
    assert.equal(host.checkGrantLive(res.token, lane.id).reason, "revoked_grant");
    assert.deepEqual(changes, ["grant_revoked"]);
    nowRef.t += 121_000;
    assert.equal(host.checkGrantLive(renewed.token, lane.id).reason, "expired");
  } finally {
    tmp.cleanup();
  }
});

test("grant from one lane is not accepted on another lane; closed lane rejects all", () => {
  const { tmp, host, room, lane } = setup();
  try {
    const lane2 = host.createLane({ roomId: room.id, label: "Other", origin: { kind: "share", agentId: "agent-2" }, agentId: "agent-2", workspaceId: "wks_2" });
    const { code } = host.createInvite({ laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
    const res = enrollDevice(host, lane.id, code);
    assert.equal(host.checkGrantLive(res.token, lane2.id).reason, "wrong_audience");
    host.closeLane(lane.id);
    assert.equal(host.checkGrantLive(res.token, lane.id).reason, "lane_closed");
    assert.equal(host.laneKeys(lane.id), undefined, "lane secret key deleted on close");
  } finally {
    tmp.cleanup();
  }
});

test("control transcript binds nonce, lane, host key and token hash", () => {
  const device = generateEd25519();
  const base = { op: "enroll" as const, laneId: "lane_0123456789abcdef", laneServerId: `lane_${"A".repeat(32)}`, hostKeyId: "0123456789abcdef", nonce: "a".repeat(43), devicePublicKey: device.publicKey, tokenHash: sha256Hex("t"), daemonServerId: null, label: "x" };
  const sig = signEd25519(device, HostStore.transcript(base));
  const host = { verify: (t: string) => new HostStore(tempDir().dir).verifyDeviceSignature(device.publicKey, t, sig) };
  assert.equal(host.verify(HostStore.transcript(base)), true);
  for (const change of [{ nonce: "b".repeat(43) }, { laneId: "lane_ffffffffffffffff" }, { hostKeyId: "ffffffffffffffff" }, { tokenHash: sha256Hex("u") }, { op: "renew" as const }])
    assert.equal(host.verify(HostStore.transcript({ ...base, ...change })), false, JSON.stringify(change));
});
