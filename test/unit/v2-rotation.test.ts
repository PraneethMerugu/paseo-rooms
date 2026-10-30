// Rotation and recovery operations (implementation plan I-12; keys-rotation-recovery.md sections 4
// and 6; mls-integration.md 4.4). Vectors are read directly from
// docs/specs/identity-v2/vectors/vectors.json (statements.deviceRekeyed, adminKeyRotated,
// hostKeyRotated, deviceRekey.chain). The operations run on a real room host with the MLS delivery
// service (test/unit/mls-harness.ts): no relay, no network, no real keyring.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { x25519 } from "@noble/curves/ed25519.js";
import { closeConfirmationBlocker, freshKeyChange, newRecoveryKey, RecoveryKey, recoverFromStolenAdmin } from "../../server/admin/recovery";
import { AdminSigner, adminKeyPath, adminNextKeyPath, writeAdminKey } from "../../server/admin/signer";
import { AdminHoldClock } from "../../server/admin/hold-clock";
import { bodyHash, type LogEntry } from "../../server/authority/entries";
import { foldLog, RoomLogFold, type FoldInputEntry } from "../../server/authority/fold";
import { HOLD_MS } from "../../server/authority/holds";
import { activeAdmins, edKid, type RoomState } from "../../server/authority/state";
import type { KeyChange, SignedStatement, StatementType } from "../../server/authority/statements";
import { HostGrants, verifyGrantV2 } from "../../server/host/grants";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import { readHostKeys, type RoomHost } from "../../server/host/room-host";
import { LaneService } from "../../server/host/lane-service";
import { MlsMemberError } from "../../server/mls/member";
import { parseLeaves } from "../../server/mls/roster-rule";
import { movedTarget, rekeyRequest, rekeyStatus } from "../../server/member/rotation";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { signNewKey } from "../../server/proto/device-link";
import { stmtContext } from "../../server/proto/contexts";
import { newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { sign } from "../../server/proto/tbs";
import { FAST, Harness, type Dev } from "./mls-harness";

const V = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json"), "utf8"));
const KEYS = V.keys as Record<string, { seedHex?: string; pub: string; kid: string }>;
const keyOf = (name: string) => ed25519PrivateKeyFromSeed(Buffer.from(KEYS[name].seedHex!, "hex"));
const HOUR = 3600_000;

type VEntry = { entry: LogEntry; hash: string; hsig: string; statement: SignedStatement };
const input = (e: VEntry): FoldInputEntry => ({ signed: { entry: e.entry, hash: e.hash, hsig: e.hsig }, body: rjcs(e.statement) });
const mainPrefix = (): FoldInputEntry[] => V.log.entries.slice(0, 4).map((signed: unknown, i: number) => ({ signed, body: rjcs(V.log.bodies[i].statement) }));

// ------------------------------------------------------------------------------ vectors

test("vectors: the member's rekey request reproduces statements.deviceRekeyed and deviceRekey.deviceRekeyed byte for byte", () => {
  for (const want of [V.statements.deviceRekeyed, V.deviceRekey.deviceRekeyed] as SignedStatement[]) {
    const ch = want.body.data as { change: KeyChange };
    const r = rekeyRequest({
      roomId: want.body.roomId,
      deviceId: ch.change.subject.id,
      currentSig: KEYS.devSig.pub,
      currentKey: keyOf("devSig"),
      next: { sigSeed: Buffer.from(KEYS.devSig2.seedHex!, "hex"), sig: KEYS.devSig2.pub, dh: KEYS.devDh2.pub },
      base: want.body.base,
      ts: want.body.ts,
    });
    assert.deepEqual(r.statement, want);
    assert.equal(rjcs(r.statement).toString(), rjcs(want).toString());
  }
  assert.equal(bodyHash(rjcs(V.deviceRekey.deviceRekeyed)), V.deviceRekey.deviceRekeyedBodyHash);
});

test("vectors: newKeySig of the admin and host rotations (adminKeyRotated, hostKeyRotated) under key-change-new", () => {
  const a = V.statements.adminKeyRotated.body.data;
  assert.equal(signNewKey(keyOf("adminA2"), a.change), a.newKeySig);
  const h = V.statements.hostKeyRotated.body.data;
  assert.equal(signNewKey(keyOf("host2"), h.change), h.newKeySig);
  // oldValidTo is the rotation time + 24 h (keys 4.5 step 2), in unix seconds.
  assert.equal(h.oldValidTo, Math.floor(V.statements.hostKeyRotated.body.ts / 1000) + 24 * 3600);
});

test("vectors: rekeyStatus over deviceRekey.chain: pending after the request, approved after the 72 h approval", () => {
  const ch = V.deviceRekey.chain;
  const next = { sig: KEYS.devSig2.pub, ref: V.deviceRekey.deviceRekeyedBodyHash };
  const sam = ch.entries[1].statement.body.data.memberId as string;
  const deviceId = V.deviceRekey.deviceRekeyed.body.data.change.subject.id as string;
  const before = foldLog(V.genesis.signed, [...mainPrefix(), ...ch.entries.slice(0, -1).map(input)]);
  assert.equal(before.error, null);
  assert.equal(rekeyStatus(before.fold.state, sam, deviceId, next), "pending");
  const after = foldLog(V.genesis.signed, [...mainPrefix(), ...ch.entries.map(input)]);
  assert.equal(after.error, null);
  assert.equal(rekeyStatus(after.fold.state, sam, deviceId, next), "approved");
});

// ------------------------------------------------------------------------------ helpers

function newKey() {
  const k = ed25519PrivateKeyFromSeed(Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))));
  return { key: k, pub: b64u(rawPublicKey(k)), kid: kidOf("ed25519", rawPublicKey(k)) };
}

/** Room with the creator C (admin), and members A and D (watch), all in the room group. */
async function room(timings = FAST): Promise<{ h: Harness; C: Dev; A: Dev; D: Dev }> {
  const h = await Harness.create(timings);
  await h.settle();
  // One at a time: devices added by the same commit only witness for each other later (see Follow-ups).
  h.admit("A");
  await h.settle();
  h.admit("D");
  await h.settle();
  for (const n of ["C", "A", "D"]) assert.equal(h.dev(n).member.inGroup, true, n);
  for (const n of ["A", "D"]) assert.equal(h.dev(n).member.view().join?.status, "confirmed", n);
  return { h, C: h.dev("C"), A: h.dev("A"), D: h.dev("D") };
}

async function deliver(h: Harness): Promise<void> {
  h.syncAll();
  for (const d of h.devs.values()) await d.member.idle();
}

/** D requests a rekey (device.rekeyed by its current key); with `publish`, its rekey KeyPackages too. */
async function requestRekey(h: Harness, D: Dev, publish = true): Promise<{ ref: string; next: ReturnType<typeof newKey>; dh: string }> {
  const next = newKey();
  const dhSecret = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
  const dh = b64u(x25519.getPublicKey(dhSecret));
  const seedKey = next.key.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const r = rekeyRequest({ roomId: h.room.roomId, deviceId: D.deviceId, currentSig: D.sigPub, currentKey: D.sigKey, next: { sigSeed: seedKey, sig: next.pub, dh }, base: h.room.host.head, ts: h.clock });
  const res = h.endpoint.submit(r.statement);
  assert.ok(res.ok, `device.rekeyed: ${!res.ok && res.reason}`);
  await deliver(h);
  if (publish) await D.member.prepareRekey({ sigPub: next.pub, sigKey: next.key });
  return { ref: r.ref, next, dh };
}

/** An admin statement signed by any key (a second admin, a fresh admin key). */
function signAdmin(h: Harness, key: ReturnType<typeof newKey>, type: StatementType, data: unknown): SignedStatement {
  const body = { v: 2 as const, typ: "stmt" as const, type, roomId: h.room.roomId, producer: { kind: "admin" as const, kid: key.kid }, base: h.room.host.head, ts: h.clock, data };
  return { body, sig: b64u(sign(key.key, stmtContext(type), rjcs(body))) } as SignedStatement;
}

function submitOk(h: Harness, s: SignedStatement): number {
  const r = h.endpoint.submit(s);
  if (!r.ok) throw new Error(`${s.body.type}: ${r.code} ${r.reason} ${r.message}`);
  return r.receipt.entry.seq;
}

/** Every entry of the host log folds from genesis (the fold stays valid after each operation). */
function refoldsClean(host: RoomHost): Readonly<RoomState> {
  const r = foldLog(host.genesis, host.entries().map((x) => ({ signed: x.signed, body: x.body })));
  assert.equal(r.error, null, r.error?.message);
  return r.fold.state;
}

// ------------------------------------------------------------------------------ device rekey

test("device rekey with no admin daemon: stays requested past the hold, the old keys keep working", async () => {
  const { h, C, D } = await room();
  try {
    const { ref } = await requestRekey(h, D);
    h.advance(HOLD_MS + HOUR);
    await h.settle();
    // Nobody signs: the request stays pending, D is still in the roster with its old key and in the group.
    assert.equal(h.room.host.state.pending[ref].status, "pending");
    assert.equal(h.room.host.state.members[D.memberId].devices[0].sig, D.sigPub);
    await D.member.sendText("old keys still work");
    await deliver(h);
    assert.ok(C.member.messages.some((m) => m.text === "old keys still work"));
    refoldsClean(h.room.host);
  } finally {
    h.cleanup();
  }
});

test("device rekey whose new-credential KeyPackage is missing is not approved (nothing is signed)", async () => {
  const { h, C, D } = await room();
  try {
    const { ref } = await requestRekey(h, D, false);
    h.advance(HOLD_MS + HOUR);
    let signed = false;
    await assert.rejects(
      C.member.approveRekey(ref, (base) => {
        signed = true;
        return h.room.signer.signWithCommit({ type: "device.rekey.approved", data: { memberId: D.memberId, deviceId: D.deviceId, ref, mode: "auto" }, base });
      }),
      (e: unknown) => e instanceof MlsMemberError && e.code === "no_key_package",
    );
    assert.equal(signed, false, "no approval signed without the package");
    assert.equal(h.room.signer.outstanding().length, 0);
    assert.ok(!h.room.host.entries().some((r) => r.signed.entry.type === "device.rekey.approved"));
  } finally {
    h.cleanup();
  }
});

test("device rekey, automatic after the 24 h hold on the admin daemon's clock: adjacent pair, the device rejoins by Welcome, chat continues, the fold stays valid", async () => {
  const { h, C, A, D } = await room();
  try {
    const { ref, next, dh } = await requestRekey(h, D);
    const holds = new AdminHoldClock(h.dataDir, h.kek, h.room.roomId, h.now);
    holds.observe(h.room.host.state);
    const p = h.room.host.state.pending[ref];
    assert.equal(p.sole, true);
    // A sole device: 72 h on both clocks before the admin daemon may sign.
    assert.equal(holds.endsAt(h.room.host.state, ref, p), p.hts + 72 * HOUR);
    h.advance(72 * HOUR);
    const r = await C.member.approveRekey(ref, (base) => h.room.signer.signWithCommit({ type: "device.rekey.approved", data: { memberId: D.memberId, deviceId: D.deviceId, ref, mode: "auto" }, base }));
    h.room.signer.reconcile(h.room.host);
    assert.equal(h.room.signer.outstanding().length, 0);
    assert.equal(r.seq, r.statementSeq + 1);
    await h.settle();
    const st = refoldsClean(h.room.host);
    const dev = st.members[D.memberId].devices[0];
    assert.deepEqual({ sig: dev.sig, dh: dev.dh }, { sig: next.pub, dh });
    assert.ok(st.deviceDenylist[D.sigPub], "old signing key denylisted");
    assert.equal(D.member.inGroup, true, JSON.stringify(D.member.alerts));
    assert.equal(parseLeaves(h.adapter.leaves((C.member as unknown as { state: never }).state))!.find((l) => l.deviceId === D.deviceId)?.deviceSig, next.pub);
    await C.member.sendText("after the rekey");
    await h.settle();
    assert.ok(D.member.messages.some((m) => m.text === "after the rekey"));
    assert.equal(D.member.view().join?.status, "confirmed", JSON.stringify({ j: D.member.view().join, e: h.room.host.entries(r.seq).map((x) => x.signed.entry.type), al: [C, A, D].map((d) => d.member.alerts) }));
    await D.member.sendText("from the new leaf");
    await deliver(h);
    assert.ok(A.member.messages.some((m) => m.text === "from the new leaf"));
    for (const d of [C, A, D]) assert.equal(d.member.alerts.filter((a) => a.type === "roster_mismatch").length, 0, d.name);
  } finally {
    h.cleanup();
  }
});

test("device rekey: a refused pair leaves no outstanding approval (the signer is free for the next statement)", async () => {
  const { h, C, D } = await room();
  try {
    const { ref } = await requestRekey(h, D);
    // Mode auto before the hold: the fold refuses the approval, so the host refuses both entries.
    await assert.rejects(C.member.approveRekey(ref, (base) => h.room.signer.signWithCommit({ type: "device.rekey.approved", data: { memberId: D.memberId, deviceId: D.deviceId, ref, mode: "auto" }, base })));
    const pending = h.room.signer.outstanding();
    assert.equal(pending.length, 1);
    h.room.signer.reconcile(h.room.host);
    assert.equal(h.room.host.findBody(pending[0].bodyHash), undefined);
    h.room.signer.settle(pending[0].bodyHash, { rejected: true });
    assert.equal(h.room.signer.outstanding().length, 0);
    h.admin("room.policy.changed", { changes: [{ setting: "grantTtl", value: 7200, ver: -1 }] });
  } finally {
    h.cleanup();
  }
});

test("periodic leaf refresh: an UpdatePath after the message budget, credential unchanged, accepted by everyone", async () => {
  const { h, C, A, D } = await room({ ...FAST, refreshMessages: 2 });
  try {
    const leavesBefore = parseLeaves(h.adapter.leaves((A.member as unknown as { state: never }).state))!;
    const epoch = A.member.epoch!;
    await A.member.sendText("one");
    await A.member.sendText("two");
    await A.member.maintain();
    await deliver(h);
    assert.ok(C.member.epoch! > epoch, "a commit moved the epoch");
    const after = parseLeaves(h.adapter.leaves((C.member as unknown as { state: never }).state))!;
    const mine = (ls: typeof after) => ls.find((l) => l.deviceId === A.deviceId)!;
    assert.equal(mine(after).deviceSig, mine(leavesBefore).deviceSig, "credential unchanged");
    assert.equal(after.length, leavesBefore.length);
    for (const d of [C, A, D]) assert.equal(d.member.alerts.length, 0, `${d.name}: ${JSON.stringify(d.member.alerts)}`);
    assert.equal((A.store.record as { refresh?: { sent: number } }).refresh?.sent, 0);
    await C.member.sendText("after refresh");
    await deliver(h);
    assert.ok(A.member.messages.some((m) => m.text === "after refresh"));
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ admin key

test("admin key rotation: staged before signing, installed after; the old key is retired and the new one signs", async () => {
  const h = await Harness.create();
  try {
    const old = h.room.signer;
    const staged = old.stageRotation();
    assert.ok(existsSync(adminNextKeyPath(h.dataDir, h.room.roomId)));
    assert.deepEqual(old.stageRotation().change, staged.change, "a retry signs the same change");
    // Before the log carries it, nothing is promoted (a crash here keeps the old key).
    assert.equal(old.promote((kid) => activeAdmins(h.room.host.state.auth).some((a) => a.kid === kid)), null);
    h.admin("admin.key.rotated", staged);
    const next = AdminSigner.load({ dataDir: h.dataDir, kek: h.kek, roomId: h.room.roomId, now: h.now }).promote((kid) => activeAdmins(h.room.host.state.auth).some((a) => a.kid === kid));
    assert.ok(next);
    assert.equal(next.kid, edKid(staged.change.newSig!));
    assert.ok(!existsSync(adminNextKeyPath(h.dataDir, h.room.roomId)));
    assert.equal(AdminSigner.load({ dataDir: h.dataDir, kek: h.kek, roomId: h.room.roomId }).kid, next.kid);
    const st = h.room.host.state;
    assert.ok(st.auth.adminKeyDenylist[old.kid] && st.auth.retiredKeys[b64u(old.publicKey())]);
    next.reconcile(h.room.host);
    const p = next.prepare({ type: "room.policy.changed", data: { changes: [{ setting: "grantTtl", value: 7200, ver: -1 }] } as never, base: h.room.host.head });
    const res = h.endpoint.submit(next.confirm(p.confirmToken));
    assert.ok(res.ok);
    refoldsClean(h.room.host);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ host key

/** A grant payload of the room, signed by the host's current key (the claims of grants-v2 2). */
function grantFor(h: Harness, deviceSig: string, memberId: string, laneId: string, aud: string, iat: number) {
  const hostKid = h.room.host.state.auth.hostKeys.find((x) => x.toSeq === null)!.kid;
  const claims = { v: 2, typ: "lane-grant", roomId: h.room.roomId, laneId, aud, sub: memberId, dev: edKid(deviceSig), role: "watch", gid: newId("grant"), iat, exp: iat + 3600, hostKid };
  const payload = rjcs(claims);
  const s = h.room.host.signGrant(payload);
  return { token: `prg2.${b64u(payload)}.${b64u(s.sig)}`, claims };
}

test("host key rotation: staged and held first; later entries and grants use the new key; old grants hold until oldValidTo; revocation refuses them", async () => {
  const h = await Harness.create();
  try {
    const host = h.room.host;
    const oldKid = host.state.auth.hostKeys[0].kid;
    const staged = host.stageHostKey();
    assert.deepEqual(host.stageHostKey().change, staged.change, "a staged key is reused");
    assert.equal(readHostKeys(h.dataDir, h.kek, h.room.roomId)!.hostKeys.length, 2);
    const nowS = Math.floor(h.clock / 1000);
    const lane = { laneId: `lane_${"1".repeat(32)}`, aud: `rle_${"2".repeat(32)}` };
    const C = h.dev("C");
    const g0 = grantFor(h, C.sigPub, C.memberId, lane.laneId, lane.aud, nowS);
    assert.equal(g0.claims.hostKid, oldKid);
    const seq = h.admin("host.key.rotated", { ...staged, oldValidTo: nowS + 24 * 3600 });
    const newKid = edKid(staged.change.newSig!);
    // The rotation entry is the last one the old key signs; the next one uses the new key.
    assert.equal(host.entries(seq, seq)[0].signed.entry.hostKid, oldKid);
    const s2 = h.admin("room.policy.changed", { changes: [{ setting: "grantTtl", value: 7200, ver: -1 }] });
    assert.equal(host.entries(s2, s2)[0].signed.entry.hostKid, newKid);
    h.advance(2000);
    const g1 = grantFor(h, C.sigPub, C.memberId, lane.laneId, lane.aud, Math.floor(h.clock / 1000));
    assert.equal(g1.claims.hostKid, newKid);
    // Step 2 of the grant check against the folded state (the allowlist is not the point here).
    const check = (tok: string, iat: number) => {
      const r = verifyGrantV2(tok, { state: host.state, laneId: lane.laneId, aud: lane.aud, nowS: iat + 1, current: () => undefined, notBefore: () => undefined });
      return r.ok ? "ok" : r.reason;
    };
    assert.equal(check(g0.token, g0.claims.iat), "no_lane_access", "old-key grant passes the host key step until oldValidTo");
    assert.equal(check(g1.token, g1.claims.iat), "no_lane_access", "new-key grant passes the host key step");
    // Revoke the rotated-out key: its grants fail at once.
    h.admin("host.key.revoked", { kid: oldKid, fromSeq: seq });
    assert.equal(check(g0.token, g0.claims.iat), "host_key_not_valid");
    assert.equal(check(g1.token, g1.claims.iat), "no_lane_access");
    refoldsClean(host);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ recovery key

test("recovery from a stolen admin key with R: the host key it installed becomes uncertified (grants refused) until a fresh admin added by R re-certifies it; retired keys never return", async () => {
  const h = await Harness.create();
  try {
    const host = h.room.host;
    // A first recovery key in a one-lineage room: installed alone (proposal null).
    const rk = newRecoveryKey(h.room.roomId);
    h.admin("recovery.key.rotated", { change: rk.change, newKeySig: rk.newKeySig, proposal: null });
    assert.equal(host.state.auth.recovery?.kid, rk.kid);
    // "The thief" (the only admin key) rotates the host key.
    const staged = host.stageHostKey();
    const rot = h.admin("host.key.rotated", { ...staged, oldValidTo: Math.floor(h.clock / 1000) + 86400 });
    host.signGrant(new Uint8Array([1]));
    const stolen = h.room.signer.kid;
    const memberId = h.room.signer.memberId;
    const stolenPriv = (() => {
      const plain = h.kek.readSealed(adminKeyPath(h.dataDir, h.room.roomId), `admin-key:${h.room.roomId}`)!;
      return ed25519PrivateKeyFromSeed(b64uDecode((JSON.parse(plain.toString("utf8")) as { seed: string }).seed, 32));
    })();
    // R revokes the stolen key from the rotation on; that leaves no admin key, so R adds a fresh one.
    assert.throws(() => RecoveryKey.fromCode(newRecoveryKey(h.room.roomId).code, host.state), /not the current recovery key|wrong_key/);
    const r = RecoveryKey.fromCode(rk.code, host.state, h.now);
    const out = await recoverFromStolenAdmin({ r, state: () => host.state, head: () => host.head, submit: (s) => void submitOk(h, s), stolenKid: stolen, fromSeq: rot, ownKid: stolen, freshFor: memberId });
    r.dispose();
    assert.ok(out.fresh, "R added a fresh admin key");
    const st = host.state;
    assert.equal(st.marks[rot], "suspect");
    assert.ok(st.auth.hostKeys.find((k) => k.toSeq === null)!.uncertified, "the host key from the suspect rotation is uncertified");
    assert.throws(() => host.signGrant(new Uint8Array([1])), /may not issue grants/);
    assert.deepEqual(host.uncertifiedAlerts().map((a) => a.subject), ["host_key"]);
    assert.deepEqual(activeAdmins(st.auth).map((a) => a.kid), [out.fresh.kid]);
    assert.equal(activeAdmins(st.auth)[0].root, out.fresh.kid, "R's key starts its own lineage");
    // The fresh key becomes this daemon's admin key, then re-certifies the host key.
    writeAdminKey(h.dataDir, h.kek, { v: 2, typ: "admin-key", roomId: h.room.roomId, genesisHash: host.genesisHash, memberId, kid: out.fresh.kid, seed: b64u(out.fresh.seed) });
    const fresh = AdminSigner.load({ dataDir: h.dataDir, kek: h.kek, roomId: h.room.roomId, now: h.now });
    fresh.reconcile(host);
    const again = host.stageHostKey();
    const p = fresh.prepare({ type: "host.key.rotated", data: { ...again, oldValidTo: Math.floor(h.clock / 1000) + 86400 } as never, base: host.head });
    assert.ok(h.endpoint.submit(fresh.confirm(p.confirmToken)).ok);
    fresh.reconcile(host);
    assert.equal(host.state.auth.hostKeys.find((k) => k.toSeq === null)!.uncertified, false);
    assert.equal(host.signGrant(new Uint8Array([1])).kid, edKid(again.change.newSig!));
    // Retired keys never return (round 8): the stolen admin key cannot be added again, even by R's admin.
    const stolenKey = { key: stolenPriv, pub: b64u(rawPublicKey(stolenPriv)), kid: stolen };
    const back = { v: 2 as const, typ: "key-change" as const, roomId: h.room.roomId, subject: { kind: "admin" as const, id: memberId }, old: null, newSig: stolenKey.pub, newDh: null };
    const p2 = fresh.prepare({ type: "admin.added", data: { change: back, newKeySig: signNewKey(stolenKey.key, back) } as never, base: host.head });
    const refused = h.endpoint.submit(fresh.confirm(p2.confirmToken));
    assert.ok(!refused.ok && refused.reason === "key_reused", JSON.stringify(!refused.ok && refused.reason));
    refoldsClean(host);
  } finally {
    h.cleanup();
  }
});

test("closure with two lineages: the confirming daemon refuses before closeDelay on its own clock; then the room closes", async () => {
  const h = await Harness.create();
  try {
    const host = h.room.host;
    const rk = newRecoveryKey(h.room.roomId);
    h.admin("recovery.key.rotated", { change: rk.change, newKeySig: rk.newKeySig, proposal: null });
    // R adds a second admin: an independent lineage.
    const second = newKey();
    const ch = { v: 2 as const, typ: "key-change" as const, roomId: h.room.roomId, subject: { kind: "admin" as const, id: h.room.signer.memberId }, old: null, newSig: second.pub, newDh: null };
    const r = RecoveryKey.fromCode(rk.code, host.state, h.now);
    submitOk(h, r.sign("admin.added", { change: ch, newKeySig: signNewKey(second.key, ch) }, host.head));
    r.dispose();
    // One lineage confirming its own proposal is refused before anything is signed.
    const seq = h.admin("room.close.proposed", { exp: Math.floor(h.clock / 1000) + 3 * 86400 });
    const proposal = host.entries(seq, seq)[0].signed.entry.bodyHash;
    assert.equal(closeConfirmationBlocker(host.state, proposal, h.room.signer.kid, h.clock)?.reason, "confirmer_not_independent");
    assert.equal(closeConfirmationBlocker(host.state, proposal, second.kid, h.clock)?.reason, "close_too_early");
    h.advance(24 * HOUR);
    // A host that back-dated the proposal: the daemon measures from when it first saw it.
    assert.equal(closeConfirmationBlocker(host.state, proposal, second.kid, h.clock, h.clock - HOUR)?.reason, "close_too_early");
    assert.equal(closeConfirmationBlocker(host.state, proposal, second.kid, h.clock), null);
    submitOk(h, signAdmin(h, second, "room.closed", { proposal }));
    assert.equal(host.state.auth.closed, true);
    refoldsClean(host);
  } finally {
    h.cleanup();
  }
});

test("recovery key: R rotates itself (a new code); the old code is then refused", async () => {
  const h = await Harness.create();
  try {
    const rk = newRecoveryKey(h.room.roomId);
    h.admin("recovery.key.rotated", { change: rk.change, newKeySig: rk.newKeySig, proposal: null });
    const r = RecoveryKey.fromCode(rk.code, h.room.host.state, h.now);
    const x = r.rotate(h.room.host.head);
    submitOk(h, x.statement);
    r.dispose();
    assert.equal(h.room.host.state.auth.recovery?.kid, x.kid);
    assert.throws(() => RecoveryKey.fromCode(rk.code, h.room.host.state));
    assert.ok(RecoveryKey.fromCode(x.code, h.room.host.state));
    // R signs only its four statement types.
    assert.throws(() => RecoveryKey.fromCode(x.code, h.room.host.state).sign("member.removed" as never, {} as never, h.room.host.head), /does not sign/);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ endpoint

test("endpoint rotation: staged then served, promoted after endpoint.rotated; the old endpoint answers moved with a checkable entry", async () => {
  const h = await Harness.create();
  try {
    const host = h.room.host;
    const oldServer = host.state.auth.endpoint.serverId;
    const oldKey = endpointKeyFromHost(h.dataDir, h.kek, host);
    const next = host.stageEndpoint();
    assert.deepEqual(host.stageEndpoint(), next);
    const seq = h.admin("endpoint.rotated", { serverId: next.serverId, dh: next.dh, relay: host.state.auth.endpoint.relay, ver: -1 });
    assert.equal(host.promoteEndpoint(), true);
    const keys = readHostKeys(h.dataDir, h.kek, h.room.roomId)!;
    assert.equal(keys.endpoint.serverId, next.serverId);
    assert.equal(keys.endpointNext, undefined);
    assert.equal(keys.endpointOld?.[0].serverId, oldServer);
    assert.equal(keys.endpointOld![0].until, h.clock + 30 * 24 * HOUR);
    // The main endpoint moves; the restricted one serves the old serverId.
    h.endpoint.rotateTo(endpointKeyFromHost(h.dataDir, h.kek, host));
    assert.equal(h.endpoint.serverId, next.serverId);
    const moved = new RoomEndpoint({ host, endpointKey: oldKey, relay: { endpoint: "127.0.0.1:1", useTls: false }, restricted: { serverId: oldServer, endpointKey: oldKey, until: h.clock + 1000 }, now: h.now });
    assert.equal(moved.serverId, oldServer);
    const fields = moved.movedFields()!;
    assert.equal((fields.entry as { entry: { seq: number } }).entry.seq, seq);
    const t = movedTarget(fields, h.room.roomId, RoomLogFold.fromGenesis(host.genesis).state);
    assert.ok(t);
    assert.deepEqual(t.endpoint, { serverId: next.serverId, dh: next.dh.pub, relay: { host: "relay.example.org", port: 443 } });
    assert.equal(t.hsigChecked, true);
    // A body that does not match the entry, or another room, is refused.
    const body = JSON.parse(fields.body as string);
    body.body.data.serverId = `rme_${"3".repeat(32)}`;
    assert.equal(movedTarget({ ...fields, body: Buffer.from(rjcs(body)).toString("utf8") }, h.room.roomId, null), null);
    assert.equal(movedTarget(fields, `room_${"4".repeat(32)}`, null), null);
    moved.stop();
    refoldsClean(host);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ lanes

test("lane offer rotation: staged, logged, promoted; the old endpoint is replaced; a compromise removal names the member's lanes", async () => {
  const h = await Harness.create();
  try {
    const host = h.room.host;
    const grants = new HostGrants({ dataDir: h.dataDir, kek: h.kek, host, env: {} });
    const lanes = new LaneService({ dataDir: h.dataDir, kek: h.kek, host, grants, relay: { endpoint: "127.0.0.1:1", useTls: false }, paseoHome: join(h.dataDir, "..", ".."), autostart: false });
    try {
      const C = h.dev("C");
      const { laneId, serverId } = lanes.createLane({ agentId: "agent-1", workspaceId: "ws-1", label: "Live", owner: C.memberId, submit: (d) => void h.admin("lane.created", d) });
      lanes.sync();
      const before = lanes.endpoints.get(laneId);
      assert.ok(before);
      const D = h.admit("D");
      h.admin("member.lanes.changed", { memberId: D.memberId, lanes: [laneId], ver: host.state.auth.versions[`lanes:${D.memberId}`] ?? -1 });
      // Default policy "compromise": only a compromise removal rotates.
      assert.deepEqual(lanes.lanesToRotate(host.state, D.memberId, false), []);
      assert.deepEqual(lanes.lanesToRotate(host.state, D.memberId, true), [laneId]);
      const prev = host.state;
      h.admin("member.removed", { memberId: D.memberId, reason: "compromise" });
      const r = lanes.rotateOffer(laneId, (d) => void h.admin("lane.offer.rotated", d));
      assert.notEqual(r.serverId, serverId);
      const offer = host.state.auth.lanes[laneId].offer;
      assert.equal(offer.serverId, r.serverId);
      const keys = readHostKeys(h.dataDir, h.kek, h.room.roomId)!;
      assert.equal(keys.lanes[laneId].kid, offer.dh.kid, "promoted");
      assert.deepEqual(keys.lanesNext, {});
      assert.equal(b64u(x25519.getPublicKey(b64uDecode(keys.lanes[laneId].secret, 32))), offer.dh.pub);
      assert.notEqual(lanes.endpoints.get(laneId), before, "the old lane endpoint was replaced");
      assert.ok(prev.auth.lanes[laneId].offer.dh.pub !== offer.dh.pub && host.state.auth.retiredKeys[prev.auth.lanes[laneId].offer.dh.pub]);
      refoldsClean(host);
    } finally {
      await lanes.stop();
      grants.stop();
    }
  } finally {
    h.cleanup();
  }
});

test("admin key file stays sealed: no plaintext admin or staged key file", async () => {
  const h = await Harness.create();
  try {
    h.room.signer.stageRotation();
    for (const p of [adminKeyPath(h.dataDir, h.room.roomId), adminNextKeyPath(h.dataDir, h.room.roomId)]) {
      const text = readFileSync(p).toString("latin1");
      assert.ok(!/"seed"/.test(text) && !text.includes(h.room.signer.memberId), p);
    }
    // freshKeyChange gives a verifiable KeyChange for any subject.
    const f = freshKeyChange(h.room.roomId, { kind: "admin", id: h.room.signer.memberId }, null);
    assert.equal(f.kid, edKid(f.change.newSig!));
    f.seed.fill(0);
  } finally {
    h.cleanup();
  }
});

test("device rekey: the device's current lane grant leaves the allowlist (it names the old key) and the device is told to reissue", async () => {
  const { h, C, D } = await room();
  const host = h.room.host;
  const grants = new HostGrants({ dataDir: h.dataDir, kek: h.kek, host, env: {} });
  const lanes = new LaneService({ dataDir: h.dataDir, kek: h.kek, host, grants, relay: { endpoint: "127.0.0.1:1", useTls: false }, paseoHome: join(h.dataDir, "..", ".."), autostart: false });
  try {
    const { laneId } = lanes.createLane({ agentId: "agent-1", workspaceId: "ws-1", label: "Live", owner: C.memberId, submit: (d) => void h.admin("lane.created", d) });
    h.admin("member.lanes.changed", { memberId: D.memberId, lanes: [laneId], ver: host.state.auth.versions[`lanes:${D.memberId}`] ?? -1 });
    const pushed: Record<string, unknown>[] = [];
    grants.notify = (deviceId, f) => void (deviceId === D.deviceId && pushed.push(f));
    const g = grants.issue({ memberId: D.memberId, deviceId: D.deviceId }, laneId);
    assert.ok(g.ok);
    const gid = grants.currentOf(D.deviceId, laneId)!.gid;
    const { ref } = await requestRekey(h, D);
    assert.equal(grants.currentOf(D.deviceId, laneId)?.gid, gid, "the request alone changes nothing");
    h.advance(72 * HOUR);
    await C.member.approveRekey(ref, (base) => h.room.signer.signWithCommit({ type: "device.rekey.approved", data: { memberId: D.memberId, deviceId: D.deviceId, ref, mode: "auto" }, base }));
    assert.equal(grants.currentOf(D.deviceId, laneId), undefined);
    assert.ok(grants.revoked.has(gid));
    assert.deepEqual(pushed.map((f) => [f.t, f.reason]), [["grant.revoked", "superseded"]]);
  } finally {
    await lanes.stop();
    grants.stop();
    h.cleanup();
  }
});
