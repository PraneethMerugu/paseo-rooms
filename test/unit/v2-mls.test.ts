// Identity v2 milestone I-13: MLS adapter and host delivery service (mls-integration.md section 10,
// tests 1 to 10, 12 and 13; test 11 ran in Step 0, Spike A). ts-mls 1.6.4 through server/mls/adapter.ts.
// Only test code imports ts-mls internals: the zero-commit-secret attack of test 1, the forked
// createCommit of test 10 (production never forks it), and the library's own KeyPackageRef and
// KeyPackage signature check to compare with the adapter's. No network, no real keyring.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { MlsAdapter, type MlsLib, type MlsState } from "../../server/mls/adapter";
import { checkCredential, MlsAuthService, referenceRosterOf } from "../../server/mls/auth-service";
import { authorityExtension, encodeAad, epochAuth, mlsGroupId, parseAad, parseMlsIdentity, signMlsIdentity } from "../../server/mls/formats";
import { MemoryMlsStore, type MemberRecord } from "../../server/mls/member";
import { checkCommit, parseLeaves, rosterEquality } from "../../server/mls/roster-rule";
import { b64u, b64uDecodeVar } from "../../server/proto/b64u";
import { CTX_KEY_CHANGE_NEW } from "../../server/proto/contexts";
import { newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { sign } from "../../server/proto/tbs";
import { FAST, Harness, type Dev } from "./mls-harness";

const acceptAll = { validateCredential: async () => true };
const nowS = () => Math.floor(Date.now() / 1000);

// ------------------------------------------------------------------------------ helpers

/** A device's group state from its store, under an accept-all config (the attacker's own copy). */
function rawState(h: Harness, d: Dev): MlsState {
  const rec = d.store.record!;
  return h.adapter.decodeState(b64uDecodeVar(rec.state!, 8 << 20), h.adapter.config(acceptAll));
}

/** AAD naming the host's current roster (or `roster`) and head, with the state's own anchor. */
function aadFor(h: Harness, st: MlsState, roster?: { seq: number; hash: string }): Uint8Array {
  const ref = referenceRosterOf(h.room.host.state);
  return encodeAad({ roster: roster ?? { seq: ref.seq, hash: ref.hash }, logHead: h.room.host.head, epochAuth: epochAuth(h.adapter.groupId(st), h.adapter.epoch(st), h.adapter.epochAuthenticator(st)) });
}

const dhOf = (h: Harness, d: Dev) => h.room.host.state.members[d.memberId].devices.find((x) => x.deviceId === d.deviceId)!.dh;

async function submitRaw(h: Harness, d: Dev, st: MlsState, commit: Uint8Array, welcome?: Uint8Array | null): Promise<Record<string, unknown>> {
  return h.endpoint.localRequest(dhOf(h, d), { t: "commit.submit", epoch: h.adapter.epoch(st), commit: b64u(commit), ...(welcome ? { welcome: b64u(welcome) } : {}) });
}

async function refusal(p: Promise<unknown>): Promise<{ code: string; fields: Record<string, unknown> }> {
  try {
    await p;
  } catch (e) {
    return { code: (e as { code: string }).code, fields: (e as { fields?: Record<string, unknown> }).fields ?? {} };
  }
  throw new Error("expected a refusal");
}

/** A KeyPackage with an identity of our choosing, signed by `sigKey` (an attacker's or a test device's). */
async function craftKp(h: Harness, id: { memberId: string; deviceId: string; deviceSig?: string; sigPub?: string }, sigKey: ReturnType<typeof ed25519PrivateKeyFromSeed>, lifetime?: { notBefore: number; notAfter: number }, roomId = h.room.roomId) {
  const signer = await h.adapter.newLeafSigner();
  const identity = signMlsIdentity({ v: 2, typ: "mls-identity", roomId, memberId: id.memberId, deviceId: id.deviceId, deviceSig: (id.deviceSig ?? id.sigPub)!, mlsSig: b64u(signer.publicKey), notBefore: nowS() }, sigKey);
  const hs = Math.floor(h.clock / 1000);
  return { ...(await h.adapter.keyPackage(identity, signer, lifetime ?? { notBefore: hs - 60, notAfter: hs + 86400 })), signer, identity };
}

function newKey() {
  const k = ed25519PrivateKeyFromSeed(randomBytes(32));
  return { key: k, pub: b64u(rawPublicKey(k)), kid: kidOf("ed25519", rawPublicKey(k)) };
}

/** Room with the creator C (admin), and members A and B (watch), all in the room group. */
async function three(timings = FAST, random?: () => number): Promise<Harness> {
  const h = await Harness.create(timings, random);
  await h.settle();
  h.admit("A");
  h.admit("B");
  await h.settle();
  for (const n of ["C", "A", "B"]) assert.equal(h.dev(n).member.inGroup, true, `${n} in group: ${JSON.stringify(h.dev(n).member.alerts)}`);
  return h;
}

const alertsOf = (d: Dev, type: string) => d.member.alerts.filter((a) => a.type === type);

function leafOf(h: Harness, st: MlsState, d: Dev): number {
  return parseLeaves(h.adapter.leaves(st))!.find((l) => l.deviceId === d.deviceId)!.leafIndex;
}

/** Feeds the log to every device and waits for processing, without maintenance (no automatic commits). */
async function deliver(h: Harness): Promise<void> {
  h.syncAll();
  for (const d of h.devs.values()) await d.member.idle();
}

// ------------------------------------------------------------------------------ tests 1 and 2

type Internals = { initializeEpoch: (initSecret: Uint8Array, commitSecret: Uint8Array, gc: unknown, psk: Uint8Array, kdf: unknown) => Promise<{ keySchedule: { exporterSecret: Uint8Array } }> };

/**
 * Test 1 (ported from spikes/security/src/mls-proto.ts): after a Remove, the removed member cannot
 * decrypt under the honest, forced, stale and zero-commit-secret views. Returns what each view got.
 */
async function removalRegression(adapter: MlsAdapter, internals: Internals) {
  const cfg = adapter.config(acceptAll);
  const nb = nowS() - 60;
  const kp = async (name: string) => adapter.keyPackage(new TextEncoder().encode(name), await adapter.newLeafSigner(), { notBefore: nb, notAfter: nb + 86400 });
  const [ka, kb, kc, kd] = await Promise.all(["A", "B", "C", "D"].map(kp));
  let a = await adapter.createGroup(new TextEncoder().encode("room-removal"), ka, new TextEncoder().encode("{}"), cfg);
  const add = await adapter.commit(a, { adds: [kb, kc, kd].map((k) => k.publicPackage) }, new Uint8Array(0));
  a = add.newState;
  let b = await adapter.join(add.welcome!, kb, cfg);
  let c = await adapter.join(add.welcome!, kc, cfg);
  const d = await adapter.join(add.welcome!, kd, cfg);
  const stale = d;
  const dLeaf = 3;
  const rm = await adapter.commit(a, { removes: [dLeaf] }, new Uint8Array(0));
  a = rm.newState;
  for (const who of ["b", "c"] as const) {
    const r = await adapter.process(who === "b" ? b : c, rm.commit, () => true);
    assert.ok(r.kind === "commit" && r.accepted);
    if (who === "b") b = r.newState;
    else c = r.newState;
  }
  let honest: MlsState | null = null;
  try {
    const r = await adapter.process(d, rm.commit, () => true);
    if (r.kind === "commit" && r.accepted) honest = r.newState;
  } catch {
    honest = null;
  }
  const msg = await adapter.encrypt(a, new TextEncoder().encode("secret after removal"), new Uint8Array(0));
  const got = await adapter.process(b, msg.message, () => true);
  assert.ok(got.kind === "application" && new TextDecoder().decode(got.plaintext) === "secret after removal", "remaining member reads");
  const attempt = async (s: MlsState | null) => {
    if (!s) return "no-state";
    try {
      const r = await adapter.process(s, msg.message, () => true);
      return r.kind === "application" ? "DECRYPTED" : r.kind;
    } catch {
      return "error";
    }
  };
  const forced = honest ? ({ ...honest, groupActiveState: { kind: "active" } } as MlsState) : null;
  const zeros = new Uint8Array(adapter.cs.kdf.size);
  const forged = await internals.initializeEpoch(stale.keySchedule.initSecret, zeros, a.groupContext, zeros, adapter.cs.kdf);
  const eq = (x: Uint8Array, y: Uint8Array) => Buffer.compare(Buffer.from(x), Buffer.from(y)) === 0;
  return {
    honest: await attempt(honest),
    forced: await attempt(forced),
    stale: await attempt(stale),
    honestDerivesEpoch: !!honest && eq(honest.keySchedule.exporterSecret, a.keySchedule.exporterSecret),
    zeroCommitDerivesEpoch: eq(forged.keySchedule.exporterSecret, a.keySchedule.exporterSecret),
  };
}

test("MLS 1: removal regression on ts-mls 1.6.4 (honest, forced, stale and zero-commit-secret views)", async () => {
  const adapter = await MlsAdapter.create();
  const r = await removalRegression(adapter, require("ts-mls/keySchedule.js") as Internals);
  assert.notEqual(r.honest, "DECRYPTED");
  assert.notEqual(r.forced, "DECRYPTED");
  assert.notEqual(r.stale, "DECRYPTED");
  assert.equal(r.honestDerivesEpoch, false);
  assert.equal(r.zeroCommitDerivesEpoch, false);
  assert.equal(JSON.parse(readFileSync(join(process.cwd(), "node_modules", "ts-mls", "package.json"), "utf8")).version, "1.6.4", "pinned version");
});

test("MLS 2: positive control, the same regression fails on ts-mls 1.6.2 (spike install, offline)", async (t) => {
  // The dev alias `ts-mls-162` could not be added to the plugin: its exact @noble/ciphers 2.1.1 peer
  // conflicts with the plugin's 2.4.0 and npm 9 refuses an override for an aliased package. The
  // control loads the copy Spike A installed under spikes/security, when it is there.
  const dir = join(process.cwd(), "..", "spikes", "security", "node_modules", "ts-mls-162", "dist", "src");
  if (!existsSync(join(dir, "index.js"))) return t.skip("spikes/security/node_modules/ts-mls-162 not installed");
  const lib = require(join(dir, "index.js")) as MlsLib;
  const adapter = await MlsAdapter.create(lib);
  const r = await removalRegression(adapter, require(join(dir, "keySchedule.js")) as Internals);
  const broken = [r.honest, r.forced, r.stale].includes("DECRYPTED") || r.honestDerivesEpoch || r.zeroCommitDerivesEpoch;
  assert.equal(broken, true, `1.6.2 must fail the removal check: ${JSON.stringify(r)}`);
});

// ------------------------------------------------------------------------------ adapter internals

test("adapter: KeyPackageRef and KeyPackage signature check equal the library's own (public API only in production)", async () => {
  const adapter = await MlsAdapter.create();
  const internal = require("ts-mls/keyPackage.js") as { makeKeyPackageRef(kp: unknown, h: unknown): Promise<Uint8Array>; verifyKeyPackage(kp: unknown, s: unknown): Promise<boolean> };
  const kp = await adapter.keyPackage(new TextEncoder().encode("x"), await adapter.newLeafSigner(), { notBefore: nowS(), notAfter: nowS() + 3600 });
  assert.equal(kp.ref, b64u(await internal.makeKeyPackageRef(kp.publicPackage, adapter.cs.hash)));
  const info = adapter.decodeKeyPackage(kp.bytes);
  assert.equal(info.signatureValid, true);
  assert.equal(await internal.verifyKeyPackage(kp.publicPackage, adapter.cs.signature), true);
  const tampered = new Uint8Array(kp.bytes);
  tampered[tampered.length - 5] ^= 1;
  assert.equal(adapter.decodeKeyPackage(tampered).signatureValid, false);
  assert.throws(() => adapter.decodeState(new Uint8Array(1), undefined as never), /required/);
});

// ------------------------------------------------------------------------------ test 3

test("MLS 3: authentication service refuses forged, wrong mlsSig, unknown device, denylisted, wrong room and no reference roster", async () => {
  const h = await three();
  try {
    const A = h.dev("A");
    const st = h.room.host.state;
    const ref = referenceRosterOf(st);
    const ok = await craftKp(h, { memberId: A.memberId, deviceId: A.deviceId, deviceSig: A.sigPub }, A.sigKey);
    const cred = (kp: { publicPackage: { leafNode: { credential: unknown; signaturePublicKey: Uint8Array } } }) => [kp.publicPackage.leafNode.credential as { credentialType: string; identity: Uint8Array }, kp.publicPackage.leafNode.signaturePublicKey] as const;
    assert.equal(checkCredential(ref, ...cred(ok)).ok, true);
    // Forged: deviceSig names A's key, signed by another key.
    const other = newKey();
    const forged = await craftKp(h, { memberId: A.memberId, deviceId: A.deviceId, deviceSig: A.sigPub }, other.key);
    assert.deepEqual(checkCredential(ref, ...cred(forged)), { ok: false, reason: "bad_identity_sig" });
    // Wrong mlsSig: the leaf key is not the one the identity names.
    assert.deepEqual(checkCredential(ref, cred(ok)[0], (await h.adapter.newLeafSigner()).publicKey), { ok: false, reason: "mls_sig_mismatch" });
    // A valid credential of a device that is not in the reference roster.
    const ghost = await craftKp(h, { memberId: newId("member"), deviceId: newId("device"), deviceSig: other.pub }, other.key);
    assert.deepEqual(checkCredential(ref, ...cred(ghost)), { ok: false, reason: "not_in_roster" });
    // Wrong room.
    const wrongRoom = await craftKp(h, { memberId: A.memberId, deviceId: A.deviceId, deviceSig: A.sigPub }, A.sigKey, undefined, "room_" + "0".repeat(32));
    assert.deepEqual(checkCredential(ref, ...cred(wrongRoom)), { ok: false, reason: "wrong_room" });
    // Denylisted: A removed; its key is denylisted and A is out of the roster.
    h.admin("member.removed", { memberId: A.memberId, reason: "admin" });
    const after = referenceRosterOf(h.room.host.state);
    assert.deepEqual(checkCredential(after, ...cred(ok)), { ok: false, reason: "not_in_roster" });
    const synthetic = { ...ref, denylist: { [A.sigPub]: true as const } };
    assert.deepEqual(checkCredential(synthetic, ...cred(ok)), { ok: false, reason: "denylisted" });
    // No reference roster: the closure fails closed.
    const svc = new MlsAuthService();
    assert.equal(await svc.validateCredential(...(cred(ok) as unknown as [never, Uint8Array])), false);
    assert.equal(svc.refusals.at(-1)?.reason, "no_reference_roster");
    svc.set(ref);
    assert.equal(await svc.validateCredential(...(cred(ok) as unknown as [never, Uint8Array])), true);
    svc.clear();
    assert.equal(await svc.validateCredential(...(cred(ok) as unknown as [never, Uint8Array])), false);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 4

test("MLS 4: a decoded state keeps the authentication service: a ghost Add is rejected", async () => {
  const h = await three();
  try {
    // A restarts: its state is decoded from the store (config re-attached by decodeState).
    const A = h.restart("A");
    await deliver(h);
    const epochBefore = A.member.epoch;
    const B = h.dev("B");
    const st = rawState(h, B);
    const other = newKey();
    const ghost = await craftKp(h, { memberId: newId("member"), deviceId: newId("device"), deviceSig: other.pub }, other.key);
    const c = await h.adapter.commit(st, { adds: [ghost.publicPackage] }, aadFor(h, st));
    await submitRaw(h, B, st, c.commit, c.welcome);
    await deliver(h);
    assert.equal(A.member.epoch, epochBefore, "state not advanced");
    assert.equal(alertsOf(A, "roster_mismatch").length, 1);
    assert.equal(alertsOf(h.dev("C"), "roster_mismatch").length, 1);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 5

async function maliciousCommit(build: (h: Harness, st: MlsState) => Promise<{ adds?: unknown[]; removes?: number[] }>): Promise<{ h: Harness; accepted: boolean; A: Dev }> {
  const h = await three();
  const A = h.dev("A");
  const B = h.dev("B");
  const before = A.member.epoch;
  const st = rawState(h, B);
  const parts = await build(h, st);
  const c = await h.adapter.commit(st, parts as never, aadFor(h, st));
  await submitRaw(h, B, st, c.commit, c.welcome);
  await deliver(h);
  const accepted = A.member.epoch === before! + 1 && alertsOf(A, "roster_mismatch").length === 0;
  return { h, accepted, A };
}

test("MLS 5: roster equality rejects extra, swapped, duplicate and removed-roster leaves; state not advanced", async () => {
  const cases: [string, (h: Harness, st: MlsState) => Promise<{ adds?: unknown[]; removes?: number[] }>][] = [
    [
      "extra leaf",
      async (h) => {
        const k = newKey();
        return { adds: [(await craftKp(h, { memberId: newId("member"), deviceId: newId("device"), deviceSig: k.pub }, k.key)).publicPackage] };
      },
    ],
    [
      "leaf with a swapped memberId",
      async (h) => {
        const B = h.dev("B");
        return { adds: [(await craftKp(h, { memberId: h.dev("A").memberId, deviceId: B.deviceId, deviceSig: B.sigPub }, B.sigKey)).publicPackage] };
      },
    ],
    [
      "two leaves for one (memberId, deviceId) by a device that is not an admin",
      async (h) => {
        const A = h.dev("A");
        return { adds: [(await craftKp(h, { memberId: A.memberId, deviceId: A.deviceId, deviceSig: A.sigPub }, A.sigKey)).publicPackage] };
      },
    ],
    ["removal of a leaf whose triple is in the roster", async (h, st) => ({ removes: [leafOf(h, st, h.dev("C"))] })],
  ];
  for (const [name, build] of cases) {
    const { h, accepted, A } = await maliciousCommit(build);
    try {
      assert.equal(accepted, false, name);
      assert.equal(alertsOf(A, "roster_mismatch").length, 1, name);
    } finally {
      h.cleanup();
    }
  }
});

test("MLS 5 (round 7): a commit by a device that is not an admin may leave a pending add open, and may resolve it", async () => {
  const h = await three();
  try {
    const A = h.dev("A");
    const B = h.dev("B");
    const D = h.admit("D");
    await D.member.maintain(); // D publishes its KeyPackages; nobody commits yet
    // B's empty commit (UpdatePath only) while D is a pending add: accepted.
    let st = rawState(h, B);
    const empty = await h.adapter.commit(st, {}, aadFor(h, st));
    await submitRaw(h, B, st, empty.commit);
    await deliver(h);
    assert.equal(alertsOf(A, "roster_mismatch").length, 0);
    assert.equal(A.member.epoch, h.adapter.epoch(empty.newState));
    // Then B resolves the add with D's package, fetched like any device of the group may (round 7).
    st = empty.newState;
    const fetched = (await h.endpoint.localRequest(dhOf(h, B), { t: "kp.fetch", targets: [{ memberId: D.memberId, deviceId: D.deviceId, for: "current", count: 1 }] })) as { results: { keyPackages: string[] }[] };
    const kp = h.adapter.decodeKeyPackage(b64uDecodeVar(fetched.results[0].keyPackages[0], 65536)).keyPackage;
    const add = await h.adapter.commit(st, { adds: [kp] }, aadFor(h, st));
    await submitRaw(h, B, st, add.commit, add.welcome);
    await deliver(h);
    assert.equal(alertsOf(A, "roster_mismatch").length, 0);
    assert.equal(A.member.epoch, h.adapter.epoch(add.newState));
    assert.equal(D.member.inGroup, true, JSON.stringify(D.member.alerts));
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 6

test("MLS 6: a Welcome whose authority extension has another adminSetHash is refused", async () => {
  const h = await three();
  try {
    const B = h.dev("B");
    const D = h.admit("D");
    await D.member.maintain();
    const st = rawState(h, B);
    const fetched = (await h.endpoint.localRequest(dhOf(h, B), { t: "kp.fetch", targets: [{ memberId: D.memberId, deviceId: D.deviceId, for: "current", count: 1 }] })) as { results: { keyPackages: string[] }[] };
    const kp = h.adapter.decodeKeyPackage(b64uDecodeVar(fetched.results[0].keyPackages[0], 65536)).keyPackage;
    const aad = aadFor(h, st);
    const real = await h.adapter.commit(st, { adds: [kp] }, aad);
    // The Welcome comes from a copy of the state whose authority extension names another admin set.
    const wrongExt = rjcs({ v: 2, genesisHash: h.room.genesisHash, adminSetHash: b64u(randomBytes(32)), scope: null });
    const forked = { ...st, groupContext: { ...st.groupContext, extensions: [{ extensionType: 0xf0a1, extensionData: wrongExt }] } } as MlsState;
    const fake = await h.adapter.commit(forked, { adds: [kp] }, aad);
    await submitRaw(h, B, st, real.commit, fake.welcome);
    await deliver(h);
    assert.equal(D.member.inGroup, false);
    const refused = alertsOf(D, "welcome_refused");
    assert.equal(refused.length, 1);
    assert.match(refused[0].detail ?? "", /authority extension/);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 7

class FlakyStore extends MemoryMlsStore {
  /** Fails the first write whose cursor reaches this entry (other writes, e.g. KeyPackage records, pass). */
  failAt: number | null = null;
  write(r: MemberRecord): void {
    if (this.failAt !== null && r.cursor >= this.failAt) {
      this.failAt = null;
      throw new Error("crash before the state write");
    }
    super.write(r);
  }
}

test("MLS 7: write ordering, a crash before the state write or before the ack loses and repeats nothing; a restored older state is refused", async () => {
  const h = await three();
  try {
    const C = h.dev("C");
    let A = h.dev("A");
    // Crash between steps 1 and 2: the processed message is not written, so it is processed again.
    const flaky = new FlakyStore();
    flaky.record = structuredClone(A.store.record);
    A = h.restart("A", flaky);
    await h.settle(); // witnesses of the earlier adds are sent first
    flaky.failAt = h.room.host.head.seq + 1;
    await C.member.sendText("m1");
    await deliver(h);
    assert.equal(A.member.messages.length, 0, "the crash happened before the state write");
    A = h.restart("A", flaky);
    await deliver(h);
    assert.deepEqual(A.member.messages.map((m) => m.text), ["m1"], "processed once from the stored state");
    // Crash between steps 2 and 3: written, not acknowledged; after a restart it is not applied twice.
    const lastAckBefore = h.ds.lastAck(A.deviceId);
    await C.member.sendText("m2");
    h.syncAll();
    await A.member.idle();
    const snapshot = structuredClone(flaky.record!);
    A = h.restart("A", flaky);
    await deliver(h);
    assert.deepEqual(A.member.messages.map((m) => m.text), [], "m2 is not processed again after the restart");
    await C.member.sendText("m3");
    await deliver(h);
    assert.deepEqual(A.member.messages.map((m) => m.text), ["m3"], "the ratchet continues");
    assert.ok(h.ds.lastAck(A.deviceId)!.seq > (lastAckBefore?.seq ?? -1));
    // 8.4: a stored state older than the host's lastAck (restored from a backup) is refused.
    const restored = new MemoryMlsStore();
    restored.record = snapshot;
    restored.record.cursor = 0;
    A = h.restart("A", restored);
    assert.equal(A.member.checkRollback(h.ds.lastAck(A.deviceId)), false);
    assert.equal(alertsOf(A, "state_rollback").length, 1);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 8

test("MLS 8: subgroup isolation, a room member outside a scope cannot process subgroup ciphertext", async () => {
  const h = await three();
  try {
    const [C, A, B] = ["C", "A", "B"].map((n) => h.dev(n));
    const scopeId = newId("scope");
    h.admin("scope.membership.changed", { scopeId, memberIds: [A.memberId, C.memberId].sort(), ver: -1 });
    const st = h.room.host.state;
    const ref = referenceRosterOf(st, scopeId);
    const auth = new MlsAuthService();
    const cfg = h.adapter.config(auth);
    const kpC = await craftKp(h, C, C.sigKey);
    const kpA = await craftKp(h, A, A.sigKey);
    const kpB = await craftKp(h, B, B.sigKey);
    let c = await auth.with(ref, () => h.adapter.createGroup(mlsGroupId(h.room.genesisHash, 0, scopeId), kpC, authorityExtension(h.room.genesisHash, st.auth, scopeId), cfg));
    // B is not in the scope: rule 7 refuses its credential for the subgroup.
    await assert.rejects(auth.with(ref, () => h.adapter.commit(c, { adds: [kpB.publicPackage] }, new Uint8Array(0))));
    assert.equal(auth.refusals.at(-1)?.reason, "not_in_scope");
    const add = await auth.with(ref, () => h.adapter.commit(c, { adds: [kpA.publicPackage] }, new Uint8Array(0)));
    c = add.newState;
    const a = await auth.with(ref, () => h.adapter.join(add.welcome!, kpA, cfg));
    const msg = await h.adapter.encrypt(c, new TextEncoder().encode("team only"), new Uint8Array(0));
    const got = await h.adapter.process(a, msg.message, () => false);
    assert.ok(got.kind === "application" && new TextDecoder().decode(got.plaintext) === "team only");
    // B holds only the room group state.
    await assert.rejects(h.adapter.process(rawState(h, B), msg.message, () => true));
    assert.notEqual(b64u(h.adapter.groupId(c)), b64u(h.adapter.groupId(rawState(h, B))));
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 9

test("MLS 9: a commit naming an older roster gets stale_roster from the host and is rejected by members, even with that roster's leaf set", async () => {
  const h = await three();
  try {
    const [C, A, B] = ["C", "A", "B"].map((n) => h.dev(n));
    const oldRef = referenceRosterOf(h.room.host.state);
    for (const d of h.devs.values()) d.unhook(); // no pending_remove pushes: nobody commits the removal
    h.admin("member.removed", { memberId: B.memberId, reason: "admin" });
    await deliver(h); // no maintenance: the removal stays pending
    const st = rawState(h, A);
    // Leaf set {C, A, B} equals the older roster; the commit names it.
    const c = await h.adapter.commit(st, {}, aadFor(h, st, { seq: oldRef.seq, hash: oldRef.hash }));
    const r = await refusal(submitRaw(h, A, st, c.commit));
    assert.equal(r.code, "stale_roster");
    assert.equal((r.fields.roster as { seq: number }).seq, h.room.host.state.rosterSeq);
    // A host that sequences it anyway: members reject it and do not advance.
    const before = C.member.epoch;
    h.room.host.appendMls("mls.commit", c.commit, h.adapter.epoch(st) + 1);
    h.endpoint.afterAppend();
    await deliver(h);
    assert.equal(C.member.epoch, before);
    assert.match(alertsOf(C, "roster_mismatch")[0]?.detail ?? "", /names roster/);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ test 10

async function rekeyRequest(h: Harness, D: Dev): Promise<{ ref: string; next: ReturnType<typeof newKey> }> {
  const next = newKey();
  const dh = b64u(randomBytes(32));
  const change = { v: 2, typ: "key-change", roomId: h.room.roomId, subject: { kind: "device", id: D.deviceId }, old: D.sigKid, newSig: next.pub, newDh: dh };
  const r = h.deviceStatement(D, "device.rekeyed", { change, newKeySig: b64u(sign(next.key, CTX_KEY_CHANGE_NEW, rjcs(change))) });
  assert.ok(r.ok, `device.rekeyed: ${r.code} ${r.reason}`);
  const ref = Object.entries(h.room.host.state.pending).find(([, p]) => p.kind === "rekey" && p.deviceId === D.deviceId)![0];
  await D.member.prepareRekey({ sigPub: next.pub, sigKey: next.key });
  return { ref, next };
}

function signApproval(h: Harness, D: Dev, ref: string) {
  return (base: { seq: number; hash: string }) => {
    const p = h.room.signer.prepare({ type: "device.rekey.approved", data: { memberId: D.memberId, deviceId: D.deviceId, ref, mode: "admin" } as never, base });
    return h.room.signer.confirm(p.confirmToken);
  };
}

test("MLS 10: admin-route rekey, the pair is adjacent, carries a pending add, and the rekeyed device joins by Welcome without a previous-key exception", async () => {
  const h = await three();
  try {
    const [C, A] = ["C", "A"].map((n) => h.dev(n));
    const D = h.admit("D");
    await h.settle();
    assert.equal(D.member.inGroup, true);
    const { ref, next } = await rekeyRequest(h, D);
    // The host refuses device.rekey.approved through stmt.submit.
    const lone = signApproval(h, D, ref)(h.room.host.head);
    const refused = h.endpoint.submit(lone);
    assert.ok(!refused.ok && refused.code === "not_permitted" && refused.reason === "submit_only_with_commit");
    h.endpoint.submit(h.room.signer.fence(h.room.host.head));
    h.room.signer.reconcile(h.room.host);
    // Another device's add is pending (E published, nobody committed yet).
    const E = h.admit("E");
    await E.member.maintain();
    await deliver(h);
    const r = await C.member.approveRekey(ref, signApproval(h, D, ref));
    h.room.signer.reconcile(h.room.host);
    assert.equal(r.seq, r.statementSeq + 1, "adjacent");
    const [s, s1] = h.room.host.entries(r.statementSeq, r.seq).map((x) => x.signed.entry);
    assert.equal(s.type, "device.rekey.approved");
    assert.equal(s1.type, "mls.commit");
    await h.settle();
    for (const n of ["C", "A", "B", "D", "E"]) assert.equal(alertsOf(h.dev(n), "roster_mismatch").length, 0, n);
    assert.equal(D.member.inGroup, true, JSON.stringify(D.member.alerts));
    assert.equal(E.member.inGroup, true, "the pair carried E's pending add too");
    const leaves = parseLeaves(h.adapter.leaves(rawState(h, A)))!;
    assert.equal(leaves.find((l) => l.deviceId === D.deviceId)?.deviceSig, next.pub, "D's leaf carries the new key");
    assert.equal(leaves.filter((l) => l.deviceId === D.deviceId).length, 1);
    assert.equal(D.store.record!.join?.seq, r.seq);
    // Round 7 note: a pair without E's add would also pass roster equality (pending adds tolerated).
    const refS = referenceRosterOf(h.room.host.state);
    const withoutE = leaves.filter((l) => l.deviceId !== E.deviceId);
    assert.equal(rosterEquality(refS, withoutE, withoutE).ok, true);
    // Messages flow on the new leaf.
    await C.member.sendText("after rekey");
    await deliver(h);
    assert.ok(D.member.messages.some((m) => m.text === "after rekey"));
  } finally {
    h.cleanup();
  }
});

/** Rekey approved by a host that drops the commit: the statement alone at `s` (a malicious host). */
async function splitSetup(): Promise<{ h: Harness; D: Dev; next: ReturnType<typeof newKey>; s: number }> {
  const h = await three();
  const D = h.admit("D");
  await h.settle();
  const { ref, next } = await rekeyRequest(h, D);
  // No pushes: honest devices would otherwise repair the split at once (pending_remove).
  for (const d of h.devs.values()) d.unhook();
  const stmt = signApproval(h, D, ref)(h.room.host.head);
  const res = (h.room.host as unknown as { sequence(sb: unknown, body: Uint8Array): { ok: boolean; receipt: { entry: { seq: number } } } }).sequence(stmt.body, rjcs(stmt));
  assert.ok(res.ok);
  h.room.signer.reconcile(h.room.host);
  h.endpoint.afterAppend();
  await deliver(h);
  return { h, D, next, s: res.receipt.entry.seq };
}

test("MLS 10: after a host split, a commit naming roster s that keeps the old-key leaf is rejected", async () => {
  const { h } = await splitSetup();
  try {
    const B = h.dev("B");
    const st = rawState(h, B);
    const c = await h.adapter.commit(st, {}, aadFor(h, st));
    await submitRaw(h, B, st, c.commit);
    await deliver(h);
    assert.equal(alertsOf(h.dev("A"), "roster_mismatch").length, 1);
    assert.match(alertsOf(h.dev("A"), "roster_mismatch")[0].detail ?? "", /leaf_not_in_roster/);
  } finally {
    h.cleanup();
  }
});

test("MLS 10: after a host split, a device that is not an admin commits Remove plus Add as an ordinary commit; accepted, the device rejoins", async () => {
  const { h, D, next } = await splitSetup();
  try {
    const B = h.dev("B");
    await B.member.maintain();
    await h.settle();
    for (const n of ["C", "A", "B"]) assert.equal(alertsOf(h.dev(n), "roster_mismatch").length, 0, n);
    assert.equal(D.member.inGroup, true, JSON.stringify(D.member.alerts));
    assert.equal(parseLeaves(h.adapter.leaves(rawState(h, h.dev("A"))))!.find((l) => l.deviceId === D.deviceId)?.deviceSig, next.pub);
  } finally {
    h.cleanup();
  }
});

test("MLS 10: after a host split, a commit removing only the old-key leaf is accepted (D pending add); an admin's repair commit then adds D", async () => {
  const { h, D } = await splitSetup();
  try {
    const B = h.dev("B");
    const st = rawState(h, B);
    const old = leafOf(h, st, D);
    const c = await h.adapter.commit(st, { removes: [old] }, aadFor(h, st));
    await submitRaw(h, B, st, c.commit);
    await deliver(h);
    const A = h.dev("A");
    assert.equal(alertsOf(A, "roster_mismatch").length, 0);
    assert.equal(parseLeaves(h.adapter.leaves(rawState(h, A)))!.some((l) => l.deviceId === D.deviceId), false, "D is a pending add");
    // The admin's repair (4.4): C adds D's new-key package.
    await h.dev("C").member.maintain();
    await deliver(h);
    assert.equal(alertsOf(A, "roster_mismatch").length, 0);
    assert.equal(D.member.inGroup, true, JSON.stringify(D.member.alerts));
  } finally {
    h.cleanup();
  }
});

test("MLS 10: a host that sequences the approval and then any other entry is reported as withholding", async () => {
  const { h } = await splitSetup();
  try {
    h.admin("room.policy.changed", { changes: [{ setting: "grantTtl", value: 7200, ver: -1 }] });
    await deliver(h);
    for (const n of ["C", "A", "B"]) assert.equal(alertsOf(h.dev(n), "withholding").length, 1, n);
  } finally {
    h.cleanup();
  }
});

// Continuity: test code forks createCommit to send an UpdatePath with a changed credential (Spike A
// case (a)); production never does. Ported from spikes/security/src/mls-rekey-updatepath-welcome.ts.
async function forkedUpdatePath(adapter: MlsAdapter, state: MlsState, newCred: { credentialType: "basic"; identity: Uint8Array }, newKp: { publicKey: Uint8Array; signKey: Uint8Array }, aad: Uint8Array): Promise<Uint8Array> {
  const I = (m: string) => require(`ts-mls/${m}.js`);
  const cs = adapter.cs as any;
  const st = state as any;
  const { makePskIndex, applyProposals, nextEpochContext } = I("clientState");
  const { leafToNodeIndex, toLeafIndex, leafWidth } = I("treemath");
  const res = await applyProposals(st, [], toLeafIndex(st.privatePath.leafIndex), makePskIndex(st, {}), true, cs);
  const own = leafToNodeIndex(toLeafIndex(st.privatePath.leafIndex));
  const patched = res.tree.slice();
  patched[own] = { nodeType: "leaf", leaf: { ...patched[own].leaf, credential: newCred, signaturePublicKey: newKp.publicKey } };
  const [tree, updatePath, pathSecrets] = await I("updatePath").createUpdatePath(patched, toLeafIndex(st.privatePath.leafIndex), st.groupContext, newKp.signKey, cs, []);
  const last = pathSecrets.at(-1);
  const commitSecret = await I("pathSecrets").getCommitSecret(tree, I("treemath").toNodeIndex(last.nodeIndex), last.secret, cs.kdf);
  const { signature, framedContent } = await I("framedContent").createContentCommitSignature(st.groupContext, "mls_private_message", { proposals: [], path: updatePath }, { senderType: "member", leafIndex: st.privatePath.leafIndex }, aad, st.signaturePrivateKey, cs.signature);
  const treeHash = await I("treeHash").treeHashRoot(tree, cs.hash);
  const gc = await nextEpochContext(st.groupContext, "mls_private_message", framedContent, signature, treeHash, st.confirmationTag, cs.hash);
  const epochSecrets = await I("keySchedule").initializeEpoch(st.keySchedule.initSecret, commitSecret, gc, res.pskSecret, cs.kdf);
  const confirmationTag = await I("framedContent").createConfirmationTag(epochSecrets.keySchedule.confirmationKey, gc.confirmedTranscriptHash, cs.hash);
  void leafWidth;
  const p = await I("messageProtection").protect(st.keySchedule.senderDataSecret, aad, st.groupContext, st.secretTree, { ...framedContent, auth: { contentType: framedContent.contentType, signature, confirmationTag } }, st.privatePath.leafIndex, st.clientConfig.paddingConfig, cs);
  const lib = require("ts-mls") as MlsLib;
  return lib.encodeMlsMessage({ version: "mls10", wireformat: "mls_private_message", privateMessage: p.privateMessage } as never);
}

test("MLS 10: continuity, an UpdatePath that changes mlsSig (accepted by the authentication service) or deviceId is rejected after processing", async () => {
  for (const variant of ["mlsSig", "deviceId", "deviceSig", "memberId"] as const) {
    const h = await three();
    try {
      const [A, B] = ["A", "B"].map((n) => h.dev(n));
      const before = A.member.epoch;
      const st = rawState(h, B);
      const signer = await h.adapter.newLeafSigner();
      const k = newKey();
      const id = { v: 2 as const, typ: "mls-identity" as const, roomId: h.room.roomId, memberId: variant === "memberId" ? A.memberId : B.memberId, deviceId: variant === "deviceId" ? newId("device") : B.deviceId, deviceSig: variant === "deviceSig" ? k.pub : B.sigPub, mlsSig: b64u(signer.publicKey), notBefore: nowS() };
      const identity = signMlsIdentity(id, variant === "deviceSig" ? k.key : B.sigKey);
      const bytes = await forkedUpdatePath(h.adapter, st, { credentialType: "basic", identity }, signer, aadFor(h, st));
      await submitRaw(h, B, st, bytes);
      await deliver(h);
      assert.equal(A.member.epoch, before, `${variant}: state not advanced`);
      const mm = alertsOf(A, "roster_mismatch");
      assert.equal(mm.length, 1, variant);
      if (variant === "mlsSig") assert.match(mm[0].detail ?? "", /continuity/, "only the continuity check catches a new leaf key under a valid credential");
    } finally {
      h.cleanup();
    }
  }
});

// ------------------------------------------------------------------------------ test 12

test("MLS 12: kp.publish refuses wrong deviceSig, member, device, suite, lifetime and a reused ref", async () => {
  const h = await three();
  try {
    const [A, B] = ["A", "B"].map((n) => h.dev(n));
    const pub = (kps: Uint8Array[]) => h.endpoint.localRequest(dhOf(h, A), { t: "kp.publish", for: "current", keyPackages: kps.map(b64u) });
    const other = newKey();
    const wrongSig = await craftKp(h, { memberId: A.memberId, deviceId: A.deviceId, deviceSig: other.pub }, other.key);
    const wrongMember = await craftKp(h, { memberId: B.memberId, deviceId: A.deviceId, deviceSig: A.sigPub }, A.sigKey);
    const wrongDevice = await craftKp(h, { memberId: A.memberId, deviceId: B.deviceId, deviceSig: A.sigPub }, A.sigKey);
    const hs = Math.floor(h.clock / 1000);
    const long = await craftKp(h, A, A.sigKey, { notBefore: hs - 60, notAfter: hs + 40 * 86400 });
    const good = await craftKp(h, A, A.sigKey);
    const suite = new Uint8Array(good.bytes);
    suite[5] = 0x03; // cipher_suite after version and wire format: suite 3
    for (const [name, b] of [["wrong deviceSig", wrongSig.bytes], ["wrong member", wrongMember.bytes], ["wrong device", wrongDevice.bytes], ["lifetime over 30 days", long.bytes], ["another suite", suite]] as const) {
      assert.equal((await refusal(pub([b]))).code, "not_permitted", name);
    }
    assert.equal((await pub([good.bytes])).stored, 1);
    assert.equal((await refusal(pub([good.bytes]))).code, "not_permitted", "reused ref");
    // Without 0xF0A1 in the capabilities: refused.
    const lib = require("ts-mls") as MlsLib;
    const signer = await h.adapter.newLeafSigner();
    const identity = signMlsIdentity({ v: 2, typ: "mls-identity", roomId: h.room.roomId, memberId: A.memberId, deviceId: A.deviceId, deviceSig: A.sigPub, mlsSig: b64u(signer.publicKey), notBefore: nowS() }, A.sigKey);
    const noCap = await lib.generateKeyPackageWithKey({ credentialType: "basic", identity }, lib.defaultCapabilities(), { notBefore: BigInt(hs - 60), notAfter: BigInt(hs + 3600) }, [], signer, h.adapter.cs);
    assert.equal((await refusal(pub([h.adapter.encodeKeyPackage(noCap.publicPackage)]))).code, "not_permitted", "no 0xF0A1 capability");
  } finally {
    h.cleanup();
  }
});

test("MLS 12: kp.fetch serves single-use packages once, the last resort only when short, caps per fetcher (k) and per target (g + 2), and refuses rekey and unknown targets", async () => {
  const h = await three();
  try {
    const [C, A, B] = ["C", "A", "B"].map((n) => h.dev(n));
    const E = h.admit("E");
    const F = h.admit("F");
    const T = h.admit("T"); // the target: publishes 6 single-use packages and a last resort
    T.unhook(); // no automatic top-up on kp.low, so the counts below are the host's alone
    const kps = await Promise.all([1, 2, 3, 4, 5, 6].map(() => craftKp(h, T, T.sigKey)));
    const last = await craftKp(h, T, T.sigKey);
    await h.endpoint.localRequest(dhOf(h, T), { t: "kp.publish", for: "current", keyPackages: kps.map((k) => b64u(k.bytes)), lastResort: b64u(last.bytes) });
    const fetch = async (d: Dev, count = 1) => ((await h.endpoint.localRequest(dhOf(h, d), { t: "kp.fetch", targets: [{ memberId: T.memberId, deviceId: T.deviceId, for: "current", count }] })) as { results: { keyPackages: string[]; lastResort: string | null }[] }).results[0];
    const b1 = await fetch(B);
    assert.equal(b1.keyPackages.length, 1);
    assert.equal(b1.lastResort, null);
    // Per-fetcher cap k = 1 (one shared group): B gets only the last resort now.
    const b2 = await fetch(B);
    assert.deepEqual([b2.keyPackages.length, b2.lastResort !== null], [0, true]);
    const a1 = await fetch(A);
    const c1 = await fetch(C);
    assert.equal(new Set([b1.keyPackages[0], a1.keyPackages[0], c1.keyPackages[0]]).size, 3, "a single-use package is served once");
    // Global cap g + 2 = 3 per target and hour: the fourth fetcher gets only the last resort, though 3 remain.
    const e1 = await fetch(E);
    assert.deepEqual([e1.keyPackages.length, e1.lastResort === b64u(last.bytes)], [0, true]);
    assert.equal(h.ds.poolView(T.deviceId).current, 3);
    // After an hour the caps reset; asking for more than the pool holds adds the last resort.
    h.advance(3_600_001);
    const f1 = await fetch(F, 1);
    assert.deepEqual([f1.keyPackages.length, f1.lastResort], [1, null]);
    // rekey target from a device that is not an admin, and an unknown target: not_permitted.
    assert.equal((await refusal(h.endpoint.localRequest(dhOf(h, B), { t: "kp.fetch", targets: [{ memberId: T.memberId, deviceId: T.deviceId, for: "rekey", count: 1 }] }))).code, "not_permitted");
    assert.equal((await refusal(h.endpoint.localRequest(dhOf(h, B), { t: "kp.fetch", targets: [{ memberId: newId("member"), deviceId: newId("device"), for: "current", count: 1 }] }))).code, "not_permitted");
  } finally {
    h.cleanup();
  }
});

test("MLS 12: the fetcher rejects a package the host should have refused; the last resort joins two groups", async () => {
  const h = await three();
  try {
    const C = h.dev("C");
    const E = h.admit("E");
    E.unhook();
    // The host serves a forged package for E (a key that is not E's roster key) ahead of E's own.
    const other = newKey();
    const forged = await craftKp(h, { memberId: E.memberId, deviceId: E.deviceId, deviceSig: other.pub }, other.key);
    (h.ds as unknown as { f: { pools: Record<string, { current: { sig: string; single: { ref: string; kp: string }[]; lastResort: null } }> } }).f.pools[E.deviceId] = { current: { sig: E.sigPub, single: [{ ref: forged.ref, kp: b64u(forged.bytes) }], lastResort: null } };
    await deliver(h);
    await C.member.maintain();
    assert.ok(alertsOf(C, "host_fault").length >= 1);
    assert.equal(E.member.inGroup, false, "no commit with a forged package");
    // Adapter level: one last-resort package used for two groups.
    const lr = await craftKp(h, E, E.sigKey);
    const ref = referenceRosterOf(h.room.host.state);
    const auth = new MlsAuthService();
    const cfg = h.adapter.config(auth);
    for (const g of ["g1", "g2"]) {
      const kpC = await craftKp(h, C, C.sigKey);
      const st = await auth.with(ref, () => h.adapter.createGroup(new TextEncoder().encode(g), kpC, new Uint8Array(1), cfg));
      const add = await auth.with(ref, () => h.adapter.commit(st, { adds: [lr.publicPackage] }, new Uint8Array(0)));
      const joined = await auth.with(ref, () => h.adapter.join(add.welcome!, lr, cfg));
      assert.equal(h.adapter.epoch(joined), 1, g);
    }
  } finally {
    h.cleanup();
  }
});

test("MLS 12: Welcome routing by KeyPackageRef without group state; a Welcome for a used single-use package is refused, the admin's leaf replacement accepted", async () => {
  const h = await three();
  try {
    const [C, A] = ["C", "A"].map((n) => h.dev(n));
    const E = h.admit("E");
    await h.settle();
    assert.equal(E.member.inGroup, true);
    // The admin replaces E's leaf with a package E holds no private key for (as a replayed package looks to E).
    const consumed = (E.store.record!.kps ?? []).map((k) => k.ref);
    const st = rawState(h, C);
    // Re-create a package with E's identity whose private key E does not hold (as a replay looks to E).
    const replay = await craftKp(h, E, E.sigKey);
    assert.ok(!consumed.includes(replay.ref));
    const c = await h.adapter.commit(st, { removes: [leafOf(h, st, E)], adds: [replay.publicPackage] }, aadFor(h, st));
    // The host routes the Welcome by the ref it never stored? It routes only refs it stored: publish first.
    await h.endpoint.localRequest(dhOf(h, E), { t: "kp.publish", for: "current", keyPackages: [b64u(replay.bytes)] });
    const peek = h.adapter.peek(c.welcome!);
    assert.ok(peek.wireformat === "mls_welcome" && peek.refs.includes(replay.ref), "refs readable without group state");
    await submitRaw(h, C, st, c.commit, c.welcome);
    await deliver(h);
    assert.equal(alertsOf(A, "roster_mismatch").length, 0, "the admin's leaf replacement is accepted");
    assert.equal(alertsOf(E, "welcome_refused").length, 1, "E holds no private key for that package");
    assert.equal(E.member.inGroup, false);
  } finally {
    h.cleanup();
  }
});

test("roster rule: leaf replacement by a device that is not an admin needs an open repair request naming the added package", () => {
  const [k1, k2] = [newKey(), newKey()];
  const [m1, d1, m2, d2] = [newId("member"), newId("device"), newId("member"), newId("device")];
  const room = "room_" + "1".repeat(32);
  const ident = (m: string, d: string, k: ReturnType<typeof newKey>) => signMlsIdentity({ v: 2, typ: "mls-identity", roomId: room, memberId: m, deviceId: d, deviceSig: k.pub, mlsSig: k.pub, notBefore: 0 }, k.key);
  const members = {
    [m1]: { memberId: m1, role: "watch", lanes: [], devices: [{ deviceId: d1, kind: "person", sig: k1.pub, dh: k1.pub }] },
    [m2]: { memberId: m2, role: "admin", lanes: [], devices: [{ deviceId: d2, kind: "person", sig: k2.pub, dh: k2.pub }] },
  };
  const ref = { roomId: room, seq: 3, hash: "h", denylist: {}, scope: null, members } as never;
  const leaf = (i: number, m: string, d: string, k: ReturnType<typeof newKey>) => ({ leafIndex: i, memberId: m, deviceId: d, deviceSig: k.pub, identity: ident(m, d, k), signaturePublicKey: new Uint8Array([i]) });
  const before = [leaf(0, m1, d1, k1), leaf(1, m2, d2, k2)];
  const replace = (i: number, m: string, d: string, k: ReturnType<typeof newKey>, r: string) => [{ type: "remove" as const, leafIndex: i }, { type: "add" as const, identity: ident(m, d, k), signaturePublicKey: new Uint8Array(32), ref: r }];
  const base = { ref, before, expectedAuthority: new Uint8Array(0), reinitAllowed: false };
  // m1's device (not an admin) replaces m2's leaf.
  assert.deepEqual(checkCommit({ ...base, proposals: replace(1, m2, d2, k2, "REF"), senderLeafIndex: 0, repairs: [] }), { ok: false, reason: "replacement_not_allowed", detail: `${m2}/${d2}` });
  assert.equal(checkCommit({ ...base, proposals: replace(1, m2, d2, k2, "REF"), senderLeafIndex: 0, repairs: [{ bodyHash: "b", memberId: m2, deviceId: d2, keyPackageRef: "OTHER" }] }).ok, false);
  const ok = checkCommit({ ...base, proposals: replace(1, m2, d2, k2, "REF"), senderLeafIndex: 0, repairs: [{ bodyHash: "b", memberId: m2, deviceId: d2, keyPackageRef: "REF" }] });
  assert.ok(ok.ok && ok.repairUsed === "b");
  // The admin may replace another device's leaf without a request.
  assert.equal(checkCommit({ ...base, proposals: replace(0, m1, d1, k1, "R"), senderLeafIndex: 1, repairs: [] }).ok, true);
});

// ------------------------------------------------------------------------------ test 13

test("MLS 13: epoch_authenticator is public in ts-mls 1.6.4; two members and a joiner of one epoch compute the same epochAuth", async () => {
  const h = await three();
  try {
    const J = h.admit("J");
    await h.settle();
    const states = ["C", "A", "B", "J"].map((n) => rawState(h, h.dev(n)));
    const anchors = states.map((s) => epochAuth(h.adapter.groupId(s), h.adapter.epoch(s), h.adapter.epochAuthenticator(s)));
    assert.equal(new Set(anchors).size, 1);
    assert.equal(h.adapter.epochAuthenticator(states[0]).length, 32);
    assert.equal(J.store.record!.join?.anchor, anchors[0]);
  } finally {
    h.cleanup();
  }
});

test("MLS 13: a Welcome for a different epoch makes the joiner raise epoch_fork and refuse to send", async () => {
  const h = await three();
  try {
    const [C, A] = ["C", "A"].map((n) => h.dev(n));
    const J = h.admit("J");
    await J.member.maintain();
    const st = rawState(h, A);
    const fetched = (await h.endpoint.localRequest(dhOf(h, A), { t: "kp.fetch", targets: [{ memberId: J.memberId, deviceId: J.deviceId, for: "current", count: 1 }] })) as { results: { keyPackages: string[] }[] };
    const kp = h.adapter.decodeKeyPackage(b64uDecodeVar(fetched.results[0].keyPackages[0], 65536)).keyPackage;
    const aad = aadFor(h, st);
    const real = await h.adapter.commit(st, { adds: [kp] }, aad);
    // Same epoch number, other secrets. Ed25519 is deterministic and an add-only commit has no path, so the
    // fork differs in its authenticated data (part of the confirmed transcript hash).
    const otherAad = encodeAad({ ...parseAad(aad), logHead: { seq: 0, hash: b64u(randomBytes(32)) } });
    const other = await h.adapter.commit(st, { adds: [kp] }, otherAad);
    assert.notDeepEqual(Buffer.from(other.commit), Buffer.from(real.commit));
    await submitRaw(h, A, st, real.commit, other.welcome);
    await deliver(h);
    assert.equal(J.member.inGroup, true, JSON.stringify(J.member.alerts));
    assert.equal(J.member.canSendReason(), "unconfirmed");
    await C.member.sendText("hello epoch");
    await deliver(h);
    assert.equal(alertsOf(J, "epoch_fork").length, 1);
    assert.equal(J.member.canSendReason(), "epoch_fork");
    await assert.rejects(J.member.sendText("x"));
  } finally {
    h.cleanup();
  }
});

test("MLS 13: a decryptable message with a wrong anchor gives epoch_anchor_mismatch; two matching senders confirm; with nobody else, epoch_unconfirmed after 5 minutes", async () => {
  const h = await three({ ...FAST, witnessMaxDelayMs: 24 * 3_600_000 }, () => 0.99); // no witness inside the test window
  try {
    const [C, A] = ["C", "A"].map((n) => h.dev(n));
    const J = h.admit("J");
    await h.settle();
    assert.equal(J.member.canSendReason(), "unconfirmed");
    // A sends with a wrong anchor.
    const st = rawState(h, A);
    const ref = referenceRosterOf(h.room.host.state);
    const bad = encodeAad({ roster: { seq: ref.seq, hash: ref.hash }, logHead: h.room.host.head, epochAuth: b64u(randomBytes(32)) });
    const m = await h.adapter.encrypt(st, rjcs({ kind: "chat.message", text: "liar" }), bad);
    await h.endpoint.localRequest(dhOf(h, A), { t: "msg.send", epoch: h.adapter.epoch(st), message: b64u(m.message) });
    await deliver(h);
    const mm = alertsOf(J, "epoch_anchor_mismatch");
    assert.equal(mm.length, 1);
    assert.equal(mm[0].peer?.deviceId, A.deviceId);
    // Timeout with nobody else (fake clock).
    h.advance(5 * 60_000);
    await J.member.maintain();
    assert.equal(alertsOf(J, "epoch_unconfirmed").length, 1);
    assert.equal(J.member.canSendReason(), null, "it may send after the timeout");
    // A second joiner is confirmed by two other leaves.
    const K = h.admit("K");
    await h.settle();
    assert.equal(K.member.canSendReason(), "unconfirmed");
    await C.member.sendText("one");
    await h.dev("B").member.sendText("two");
    await deliver(h);
    assert.equal(K.store.record!.join?.status, "confirmed");
    assert.equal(K.member.canSendReason(), null);
  } finally {
    h.cleanup();
  }
});

test("MLS 13 (round 9, item 4): a joiner of a two-leaf group is confirmed by the one other leaf; no epoch_unconfirmed", async () => {
  const h = await Harness.create();
  try {
    await h.settle();
    const J = h.admit("J");
    await h.settle();
    assert.equal(J.member.inGroup, true);
    assert.equal(J.store.record!.join?.needed, 1, "min(2, other leaves) with one other leaf");
    assert.equal(J.store.record!.join?.status, "confirmed", JSON.stringify(J.member.alerts));
    assert.equal(J.member.canSendReason(), null);
    h.advance(10 * 60_000);
    await J.member.maintain();
    assert.deepEqual(J.member.alerts, []);
    // With two or more other leaves, two confirmers are still needed.
    const K = h.admit("K");
    await h.settle();
    assert.equal(K.store.record!.join?.needed, 2);
  } finally {
    h.cleanup();
  }
});

test("prompt Add (round 9, item 5): the admitting admin daemon adds the device as soon as it publishes; the repair delay is the fallback", async () => {
  const h = await Harness.create({ ...FAST, repairDelayMs: 60_000, repairJitterMs: 60_000 });
  try {
    await h.settle();
    const C = h.dev("C");
    const t0 = h.clock;
    // The runtime calls promptAdd when its own admin key logged the admission (runtime-v2 feed).
    const J = h.admit("J");
    C.member.promptAdd([J.deviceId]);
    await h.settle();
    assert.equal(h.clock, t0, "no time passed");
    assert.equal(J.member.inGroup, true, "added at once, before any repair delay");
    // A device admitted without the prompt (another admin daemon, say) waits for the repair delay.
    const K = h.admit("K");
    await h.settle();
    assert.equal(K.member.inGroup, false, "no add before the repair delay");
    h.advance(60_000);
    await h.settle();
    assert.equal(K.member.inGroup, true, "the repair path adds it after the delay");
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ removal (e2e shape)

test("removal: the removed device's leaf is committed out at once and it cannot read the next message", async () => {
  const h = await three();
  try {
    const [C, A, B] = ["C", "A", "B"].map((n) => h.dev(n));
    const stale = rawState(h, B);
    h.admin("member.removed", { memberId: B.memberId, reason: "admin" });
    await h.settle();
    assert.equal(parseLeaves(h.adapter.leaves(rawState(h, A)))!.some((l) => l.deviceId === B.deviceId), false);
    await C.member.sendText("after removal");
    await deliver(h);
    assert.ok(A.member.messages.some((m) => m.text === "after removal"));
    const last = h.room.host.entries().filter((r) => r.signed.entry.type === "mls.app").at(-1)!;
    await assert.rejects(h.adapter.process(stale, last.body, () => true));
    assert.ok(!B.member.messages.some((m) => m.text === "after removal"));
  } finally {
    h.cleanup();
  }
});
