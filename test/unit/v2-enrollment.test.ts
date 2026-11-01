// Identity v2 milestone I-9: enrollment (enrollment-v2.md sections 2, 5 to 10; room-log-v2.md 4.2) and
// the D fixes P-15/C-7, P-23/C-8, P-20/C-15, C-10, P-27. Over the in-process fake relay; rooms in
// temporary homes with keys sealed through a fake keyring; no network beyond loopback.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createRoom, type CreatedRoom } from "../../server/admin/genesis";
import type { SignedStatement, StatementType } from "../../server/authority/statements";
import { AUTHORITY_CHAIN_TYPES, AuthorityChainError, verifyAuthorityChain } from "../../server/authority/authority-chain";
import { EnrollmentHost, TokenBucket } from "../../server/host/enrollment";
import { decodeInvite, encodeInvite, InviteCodeError, type InvitePayload } from "../../server/host/invites";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import type { SubmitResult } from "../../server/host/room-host";
import type { SignedEntry } from "../../server/authority/entries";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { MemberEnrollment } from "../../server/member/enroll-client";
import { EnrollmentJournal, MAX_SENT_H } from "../../server/member/enrollment-journal";
import { checkInvite, JoinRefusedError, laneHostLabel, requireRelayTrust } from "../../server/member/invite-check";
import { LaneRegistrar, REGISTRATION_BACKOFF_MS, type HostsApi } from "../../server/member/lane-registration";
import { RoomClient, RoomSessionError } from "../../server/member/room-client";
import { generateNoiseKeyPair, type NoiseKeyPair } from "../../server/noise/handshake-state";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { computeSas, enrollSigned, enrollTokenMac, sasCommitOf, signEnroll, tokenKeyOf, verifyEnrollSig } from "../../server/proto/enroll";
import { inviteRef } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, fingerprintOfKid, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcsParse, rjcsText } from "../../server/proto/rjcs";
import { hkdf, sign, tbs } from "../../server/proto/tbs";
import { memberRelayAddress } from "../../server/runtime-v2";
import { startFakeRelay, until, type FakeRelay } from "./fake-relay";
import { tempDir } from "./helpers";

// Read directly, as v2-vectors-encoding.test.ts does.
const V = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json"), "utf8")) as any;
const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };
const FAST = { handshakeTimeoutMs: 400 };
const hex = (h: string) => Buffer.from(h, "hex");

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

async function openKek(base: string, name: string): Promise<{ dataDir: string; kek: Kek }> {
  const home = join(base, name);
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
  if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
  return { dataDir, kek: s.kek };
}

interface Env {
  relay: FakeRelay;
  room: CreatedRoom;
  dataDir: string;
  kek: Kek;
  endpoint: RoomEndpoint;
  en: EnrollmentHost;
  member: { dataDir: string; kek: Kek };
  now: { ms: number | null };
  closers: (() => void)[];
  cleanup(): Promise<void>;
}

const OPEN_LIMITS = { preauthBurst: 1000, preauthPerMinute: 100000 };

async function setup(o: { limits?: Record<string, number>; maxPreauthSessions?: number } = {}): Promise<Env> {
  const t = tempDir();
  const owner = await openKek(t.dir, "owner");
  const member = await openKek(t.dir, "member");
  const relay = await startFakeRelay();
  const now = { ms: null as number | null };
  const clock = () => now.ms ?? Date.now();
  const room = await createRoom({ dataDir: owner.dataDir, kek: owner.kek, relay: { host: "127.0.0.1", port: relay.port, tls: true }, recovery: "skip", lock: NO_TIMER });
  const endpoint: RoomEndpoint = new RoomEndpoint({
    host: room.host,
    endpointKey: endpointKeyFromHost(owner.dataDir, owner.kek, room.host),
    relay: { endpoint: relay.endpoint, useTls: false },
    timings: FAST,
    now: clock,
    ...(o.maxPreauthSessions ? { maxPreauthSessions: o.maxPreauthSessions } : {}),
    enrollment: {
      dataDir: owner.dataDir,
      kek: owner.kek,
      sweepMs: 0,
      limits: { ...OPEN_LIMITS, ...o.limits },
      admin: (type: StatementType, data: unknown): { statement: SignedStatement; receipt: SignedEntry } => {
        const p = room.signer.prepare({ type, data: data as never, base: room.host.head });
        const statement = room.signer.confirm(p.confirmToken);
        const res: SubmitResult = endpoint.submit(statement);
        room.signer.reconcile(room.host);
        if (!res.ok) throw new Error(`${type}: ${res.code} ${res.reason}`);
        return { statement, receipt: res.receipt };
      },
    },
  });
  endpoint.start();
  await until("endpoint online", () => endpoint.status === "online");
  const env: Env = {
    relay,
    room,
    dataDir: owner.dataDir,
    kek: owner.kek,
    endpoint,
    en: endpoint.enrollment!,
    member,
    now,
    closers: [],
    async cleanup() {
      for (const c of env.closers) c();
      endpoint.stop();
      room.host.close();
      await relay.close();
      t.cleanup();
    },
  };
  return env;
}

const relayOf = (env: Env) => ({ endpoint: env.relay.endpoint, useTls: false });

/** Types of host-produced statements in the log, in order. */
function hostTypes(env: Env): string[] {
  return env.room.host
    .entries(0)
    .filter((r) => (rjcsParse(r.body) as SignedStatement).body.producer.kind === "host")
    .map((r) => r.signed.entry.type);
}

function stmtsOf(env: Env, type: string): SignedStatement[] {
  return env.room.host
    .entries(0)
    .filter((r) => r.signed.entry.type === type)
    .map((r) => rjcsParse(r.body) as SignedStatement);
}

/** A member enrollment driven by the real journal and driver. */
function memberJoin(env: Env, code: string, label = "Sam laptop"): MemberEnrollment {
  const journal = EnrollmentJournal.begin({ dataDir: env.member.dataDir, kek: env.member.kek, invite: decodeInvite(code), label });
  return resumeMember(env, journal);
}

function resumeMember(env: Env, journal: EnrollmentJournal, onAdmitted?: () => void): MemberEnrollment {
  const m = new MemberEnrollment({ journal, relay: relayOf(env), timings: FAST, retryMs: [50], onAdmitted });
  env.closers.push(() => m.close());
  void m.start();
  return m;
}

function reread(env: Env, roomId: string): EnrollmentJournal {
  return EnrollmentJournal.read({ dataDir: env.member.dataDir, kek: env.member.kek, roomId })!;
}

/** A raw pre-auth session as the given device (an attacker or a hand-driven member). */
async function rawSession(env: Env, dh: NoiseKeyPair = generateNoiseKeyPair()): Promise<{ c: RoomClient; h: string; dh: NoiseKeyPair; pushed: any[] }> {
  const ep = env.room.host.state.auth.endpoint;
  const pushed: any[] = [];
  const c = new RoomClient({ target: { genesisHash: env.room.genesisHash, endpoint: { serverId: ep.serverId, dh: { pub: ep.dh.pub } } }, device: dh, relay: relayOf(env), timings: FAST, onPush: (f) => pushed.push(f) });
  env.closers.push(() => c.close());
  await c.open();
  return { c, h: c.handshakeHash!, dh, pushed };
}

type Req = { inviteId: string; token?: Buffer; tokenKey?: Buffer; sigSeed?: Buffer; nm?: Buffer; label?: string; hOverride?: string; badSig?: boolean };

function requestFrame(env: Env, s: { h: string; dh: NoiseKeyPair }, r: Req) {
  const priv = ed25519PrivateKeyFromSeed(r.sigSeed ?? randomBytes(32));
  const deviceSig = b64u(rawPublicKey(priv));
  const deviceDh = b64u(s.dh.publicKey);
  const sasCommit = sasCommitOf(r.nm ?? randomBytes(32));
  const signed = enrollSigned({ h: r.hOverride ?? s.h, genesisHash: env.room.genesisHash, target: { inviteId: r.inviteId }, deviceSig, deviceDh, label: r.label ?? "probe", sasCommit });
  const tokenKey = r.tokenKey ?? (r.token ? tokenKeyOf(r.token) : randomBytes(32));
  const sig = signEnroll(priv, signed);
  if (r.badSig) sig[0] ^= 1;
  return { t: "enroll.request", v: 2, inviteId: r.inviteId, deviceSig, deviceDh, label: r.label ?? "probe", sasCommit, tokenMac: b64u(enrollTokenMac(tokenKey, signed)), sig: b64u(sig) };
}

async function errorOf(p: Promise<unknown>): Promise<{ code: string; fields: Record<string, unknown> }> {
  try {
    await p;
  } catch (e) {
    if (e instanceof RoomSessionError) return { code: e.code, fields: e.fields };
    throw e;
  }
  throw new Error("expected an error");
}

const tokenOf = (code: string) => b64uDecode(decodeInvite(code).token, 32);

// ------------------------------------------------------------------------------------------ vectors

test("vectors: invite payload, prc2 code and inviteRef", () => {
  const p = decodeInvite(V.invite.code);
  assert.deepEqual(p, V.invite.payload);
  assert.equal(encodeInvite(V.invite.payload as InvitePayload), V.invite.code);
  assert.equal(V.invite.code.length, 720);
  assert.equal(inviteRef(p.inviteId), V.invite.inviteRef);
  // Strict decoding: prc1, a flipped character, tls false, extra field.
  assert.throws(() => decodeInvite("prc1.abc"), (e: unknown) => e instanceof InviteCodeError && e.code === "older_version");
  assert.throws(() => decodeInvite(V.invite.code.slice(0, -2) + "AA"), (e: unknown) => e instanceof InviteCodeError && e.code === "malformed");
  const tlsFalse = "prc2." + Buffer.from(rjcsText({ ...V.invite.payload, endpoint: { ...V.invite.payload.endpoint, relay: { ...V.invite.payload.endpoint.relay, tls: false } } })).toString("base64url");
  assert.throws(() => decodeInvite(tlsFalse), (e: unknown) => e instanceof InviteCodeError && e.code === "malformed");
  const extra = "prc2." + Buffer.from(rjcsText({ ...V.invite.payload, note: "x" })).toString("base64url");
  assert.throws(() => decodeInvite(extra), (e: unknown) => e instanceof InviteCodeError);
});

test("vectors: EnrollSigned, signature, token key and MAC, request frame", () => {
  const E = V.enrollment;
  const so = E.signedObject;
  // The pinned h is the IK handshake hash of the enrollment handshake vector.
  assert.equal(so.h, b64u(hex(V.noise.enrollment.handshakeHash)));
  const signed = enrollSigned({ h: so.h, genesisHash: so.genesisHash, target: { inviteId: so.inviteId }, deviceSig: so.deviceSig, deviceDh: so.deviceDh, label: so.label, sasCommit: so.sasCommit });
  assert.equal(rjcsText(signed), E.signedCanonical);
  assert.equal(tbs("enroll-request", Buffer.from(E.signedCanonical)).toString("hex"), E.tbsHex);
  const priv = ed25519PrivateKeyFromSeed(hex(V.keys.devSig.seedHex));
  assert.equal(b64u(signEnroll(priv, signed)), E.sig);
  assert.ok(verifyEnrollSig(signed, E.sig));
  assert.ok(!verifyEnrollSig({ ...signed, h: b64u(randomBytes(32)) }, E.sig), "bound to h");
  const tokenKey = tokenKeyOf(b64uDecode(V.invite.payload.token, 32));
  assert.equal(tokenKey.toString("hex"), E.tokenKeyHex);
  assert.equal(b64u(enrollTokenMac(tokenKey, signed)), E.tokenMac);
  assert.deepEqual({ t: "enroll.request", v: 2, inviteId: so.inviteId, deviceSig: so.deviceSig, deviceDh: so.deviceDh, label: so.label, sasCommit: so.sasCommit, tokenMac: E.tokenMac, sig: E.sig }, E.frame);
});

test("vectors: SAS commitment, digits 317 837, transcript hash", () => {
  const S = V.enrollment.sas;
  const so = V.enrollment.signedObject;
  const nm = hex(S.NmHex);
  const nh = hex(S.NhHex);
  assert.equal(sasCommitOf(nm), S.commit);
  assert.equal(S.commit, so.sasCommit);
  const inputs = { h: b64uDecode(so.h, 32), nm, nh, deviceDh: so.deviceDh, deviceSig: so.deviceSig, endpointDh: V.keys.endpoint.pub, genesisHash: so.genesisHash, target: { inviteId: so.inviteId } };
  assert.equal(rjcsText(JSON.parse(S.infoCanonical)), S.infoCanonical);
  assert.equal(hkdf(Buffer.concat([nm, nh]), b64uDecode(so.h, 32), "sas", Buffer.from(S.infoCanonical), 8).toString("hex"), S.keyHex);
  const sas = computeSas(inputs);
  assert.equal(sas.digits, S.digits);
  assert.equal(sas.display, S.display);
  assert.equal(sas.transcript, S.transcriptHash);
  // Every pinned input changes the code (or the transcript).
  assert.notEqual(computeSas({ ...inputs, h: randomBytes(32) }).transcript, S.transcriptHash);
  assert.notEqual(computeSas({ ...inputs, nh: randomBytes(32) }).transcript, S.transcriptHash);
});

// ------------------------------------------------------------------------------ the full flow

test("enrollment end to end: SAS matches on both sides; member.admitted carries inviteRef and the SAS transcript", async () => {
  const env = await setup();
  try {
    const { code, inviteId } = env.en.createInvite({ note: "for Sam" });
    assert.ok(stmtsOf(env, "invite.created").length === 1);
    assert.ok(!JSON.stringify(env.room.host.entries(0).map((r) => Buffer.from(r.body).toString())).includes(inviteId), "the inviteId never appears in the log (S-5)");
    let admitted = 0;
    const journal = EnrollmentJournal.begin({ dataDir: env.member.dataDir, kek: env.member.kek, invite: decodeInvite(code), label: "Sam laptop" });
    const m = resumeMember(env, journal, () => admitted++);
    await until("member SAS", () => m.view().sas);
    const req = await until("host SAS", () => (env.en.pendings()[0]?.sas ? env.en.pendings()[0] : null));
    assert.equal(m.view().sas, req.sas);
    assert.equal(req.note, "for Sam");
    assert.equal(req.label, "Sam laptop");
    assert.equal(req.state, "sas_shown");
    // The admin may admit first; the host waits for the member's confirmation (5.1).
    assert.equal(env.en.admit(req.pendingId), "admin_ok");
    assert.equal(stmtsOf(env, "member.admitted").length, 1, "only the creator so far");
    await m.confirm(true);
    await until("admitted", () => admitted === 1);
    assert.equal(m.journal.state, "admitted");
    const adm = stmtsOf(env, "member.admitted")[1];
    const d = adm.body.data as any;
    assert.equal(d.confirmation.method, "sas6");
    assert.equal(d.confirmation.inviteRef, inviteRef(inviteId));
    assert.equal(d.confirmation.transcript, m.journal.e.transcript);
    assert.equal(d.member.devices[0].dh, m.journal.e.deviceDh);
    assert.equal(d.member.memberId, m.journal.e.memberId);
    assert.ok(env.room.host.state.members[d.member.memberId]);
    assert.equal(env.en.invites()[0].state, "used");
    assert.equal(m.journal.e.nm, null, "Nm and the token key are deleted after admission");
    assert.deepEqual(hostTypes(env), ["enrollment.pending"]);
    // The enrolling session became an active session (5.1); after the driver closed it a normal session opens.
    // 5.7 (round 9, item 3): the admission entry, as received, is a pre-admission anchor.
    const anchors = m.journal.preAdmissionAnchors();
    assert.deepEqual(anchors.map((a) => [a.source, a.signed.entry.type]), [["admission", "member.admitted"]]);
    assert.equal(anchors[0].signed.hash, m.journal.e.admission!.hash);
    const c = new RoomClient({ genesis: Buffer.from(m.journal.e.genesis!), device: { publicKey: b64uDecode(m.journal.e.deviceDh, 32), secretKey: m.journal.deviceKeys().dhSecret }, relay: relayOf(env), timings: FAST, anchors });
    env.closers.push(() => c.close());
    const hello = await c.connect();
    assert.equal(hello.memberId, d.member.memberId);
    assert.deepEqual(c.head, env.room.host.head);
    assert.equal(c.uncheckedAnchors, 0);
    assert.deepEqual(c.alerts, []);
  } finally {
    await env.cleanup();
  }
});

test("enroll.pending discloses only the genesis and the authority-key chain: no member, invite, lane or chat entries", async () => {
  const env = await setup();
  try {
    // History a stolen invite must not reveal: a member admitted through an earlier invite, a policy
    // change, and an authority change (a second admin key) that the chain must carry.
    const first = env.en.createInvite({ note: "first" });
    let admitted = false;
    const m1 = resumeMember(env, EnrollmentJournal.begin({ dataDir: env.member.dataDir, kek: env.member.kek, invite: decodeInvite(first.code), label: "first" }), () => (admitted = true));
    await until("sas", () => m1.view().sas);
    await m1.confirm(true);
    await until("member ok", () => env.en.pendings()[0].state === "member_ok");
    env.en.admit(env.en.pendings()[0].pendingId);
    await until("admitted", () => admitted);
    const firstMemberId = m1.journal.e.memberId!;
    const admin = (type: StatementType, data: unknown) => {
      const p = env.room.signer.prepare({ type, data: data as never, base: env.room.host.head });
      const res = env.endpoint.submit(env.room.signer.confirm(p.confirmToken));
      env.room.signer.reconcile(env.room.host);
      assert.ok(res.ok, res.ok ? "" : `${type}: ${res.reason}`);
    };
    admin("room.policy.changed", { changes: [{ setting: "grantTtl", value: 3600, ver: env.room.host.state.auth.versions["policy:grantTtl"] ?? -1 }] });
    const newAdmin = ed25519PrivateKeyFromSeed(randomBytes(32));
    const change = { v: 2, typ: "key-change", roomId: env.room.roomId, subject: { kind: "admin", id: env.room.memberId }, old: null, newSig: b64u(rawPublicKey(newAdmin)), newDh: null };
    admin("admin.added", { change, newKeySig: b64u(sign(newAdmin, "key-change-new", Buffer.from(rjcsText(change)))) });
    const second = env.en.createInvite({ note: "second" });

    const s = await rawSession(env);
    const pending = await s.c.request(requestFrame(env, s, { inviteId: second.inviteId, token: tokenOf(second.code) }));
    assert.equal(pending.t, "enroll.pending");
    const auth = pending.authority as any;
    const types = auth.entries.map((e: any) => e.entry.type);
    assert.deepEqual(types, ["admin.added"], "only the authority-key chain");
    assert.ok(types.every((t: string) => AUTHORITY_CHAIN_TYPES.has(t as StatementType)));
    assert.equal(auth.seq, auth.entries[0].entry.seq, "seq names the last chain entry, not the log head");
    assert.ok(auth.seq < env.room.host.head.seq);
    const text = rjcsText(pending);
    for (const leak of [firstMemberId, m1.journal.e.deviceDh, first.inviteRef, second.inviteRef, "member.admitted", "invite.created", "enrollment.pending", "room.policy.changed", "lane.", "grant.", "mls."]) {
      assert.ok(!text.includes(leak), `enroll.pending must not contain ${leak}`);
    }
    // The member verifies the chain (admin.added certified by the genesis admin) and reaches the SAS.
    const r = verifyAuthorityChain(pending.genesis, auth, (b) => b64uDecode(b, Math.floor((b.length * 6) / 8)));
    assert.equal(r.adminKids.length, 2);
    assert.equal(r.endpoint.dh.pub, env.room.host.state.auth.endpoint.dh.pub);
    const third = env.en.createInvite({ note: "third" });
    const m2 = memberJoin(env, third.code, "third");
    await until("third member SAS", () => m2.view().sas);
    assert.equal(m2.journal.state, "pending", "the member accepted the minimal chain");
    // R3.6 (enrollment 6.4): the SAS screen shows the owner fingerprints, genesis admin first.
    const genesisAdmin = (pending.genesis as any).body.admins[0].kid as string;
    const newKid = kidOf("ed25519", rawPublicKey(newAdmin));
    assert.deepEqual(r.currentAdminKids, [genesisAdmin, newKid]);
    assert.deepEqual(m2.view().ownerFingerprints, [fingerprintOfKid(genesisAdmin), fingerprintOfKid(newKid)]);
    assert.match(m2.view().ownerFingerprints[0], /^[a-z2-7]{4}( [a-z2-7]{4}){7}$|^[a-z2-7]{4}(-[a-z2-7]{4}){7}$/);
    assert.deepEqual(m2.journal.preAdmissionAnchors().map((a) => [a.source, a.signed.entry.type]), [["authority_chain", "admin.added"]]);
    // Tampering and non-chain entries are refused.
    const dec = (b: string) => b64uDecode(b, Math.floor((b.length * 6) / 8));
    const tampered = { ...auth, bodies: [{ ...auth.bodies[0], body: b64u(Buffer.from(rjcsText({ ...rjcsParse(dec(auth.bodies[0].body)) as object, sig: b64u(randomBytes(64)) }))) }] };
    assert.throws(() => verifyAuthorityChain(pending.genesis, tampered, dec), AuthorityChainError);
    const rec = env.room.host.entries(0).find((x) => x.signed.entry.type === "member.admitted")!;
    const smuggled = { seq: rec.signed.entry.seq, entries: [rec.signed], bodies: [{ seq: rec.signed.entry.seq, body: b64u(rec.body) }] };
    assert.throws(() => verifyAuthorityChain(pending.genesis, smuggled, dec), /outside the authority chain/);
    // A removed admin key is no longer shown as an owner fingerprint (display only; the chain still verifies).
    admin("admin.removed", { kid: newKid });
    const fourth = env.en.createInvite({ note: "fourth" });
    const s2 = await rawSession(env);
    const pending2 = await s2.c.request(requestFrame(env, s2, { inviteId: fourth.inviteId, token: tokenOf(fourth.code) }));
    const r2 = verifyAuthorityChain(pending2.genesis, pending2.authority as any, dec);
    assert.deepEqual(r2.currentAdminKids, [genesisAdmin]);
    assert.equal(r2.adminKids.length, 2, "certified keys are not narrowed");
  } finally {
    await env.cleanup();
  }
});

// ------------------------------------------------------------------- check order, P-23 and P-15

test("check order (P-23): a bad signature never reaches the lookup; every failure before the token proof looks the same", async () => {
  const env = await setup();
  try {
    const { code, inviteId } = env.en.createInvite({});
    const token = tokenOf(code);
    const replies: unknown[] = [];
    const cases: Req[] = [
      { inviteId, token, badSig: true }, // real invite, right token, bad signature
      { inviteId, badSig: true }, // real invite, wrong token, bad signature: no failedProofs (no lookup)
      { inviteId: "inv_" + randomBytes(16).toString("hex"), token }, // unknown invite
      { inviteId, token, hOverride: b64u(randomBytes(32)) }, // signed for another session's h (relayed frames)
    ];
    for (const r of cases) {
      const s = await rawSession(env);
      replies.push(await errorOf(s.c.request(requestFrame(env, s, r))));
    }
    for (const r of replies) assert.deepEqual(r, { code: "enroll_rejected", fields: {} });
    assert.equal(env.en.invites()[0].failedProofs, 0, "no lookup happened for a bad signature or a foreign h");
    assert.equal(env.en.invites()[0].state, "open");
    // A good signature with a wrong token is the same generic reply, and it counts against that invite only.
    const s = await rawSession(env);
    assert.deepEqual(await errorOf(s.c.request(requestFrame(env, s, { inviteId }))), { code: "enroll_rejected", fields: {} });
    assert.equal(env.en.invites()[0].failedProofs, 1);
    // A deviceDh other than the session's static is refused before the lookup too.
    const s2 = await rawSession(env);
    const f = requestFrame(env, s2, { inviteId, token });
    f.deviceDh = b64u(generateNoiseKeyPair().publicKey);
    assert.equal((await errorOf(s2.c.request(f))).code, "enroll_rejected");
    assert.equal(env.en.invites()[0].failedProofs, 1);
    assert.equal(env.en.pendings().length, 0);
  } finally {
    await env.cleanup();
  }
});

test("P-15: wrong tokens from many statics burn nothing; three failed proofs burn only the invite they name", async () => {
  const env = await setup();
  try {
    const a = env.en.createInvite({ note: "A" });
    env.en.createInvite({ note: "B" });
    // A past invitee knows only the endpoint key: random inviteIds from 12 statics.
    for (let i = 0; i < 12; i++) {
      const s = await rawSession(env);
      assert.equal((await errorOf(s.c.request(requestFrame(env, s, { inviteId: "inv_" + randomBytes(16).toString("hex") })))).code, "enroll_rejected");
    }
    assert.deepEqual(
      env.en.invites().map((i) => [i.state, i.failedProofs]),
      [
        ["open", 0],
        ["open", 0],
      ],
    );
    for (let i = 0; i < 3; i++) {
      const s = await rawSession(env);
      await errorOf(s.c.request(requestFrame(env, s, { inviteId: a.inviteId })));
    }
    const [ia, ib] = env.en.invites();
    assert.equal(ia.state, "burned");
    assert.equal(ib.state, "open");
    assert.equal(ib.failedProofs, 0);
    const burned = stmtsOf(env, "invite.burned");
    assert.deepEqual(burned.map((x) => x.body.data), [{ inviteRef: a.inviteRef, reason: "attempts" }]);
    // The holder of the token now learns the state.
    const s = await rawSession(env);
    assert.equal((await errorOf(s.c.request(requestFrame(env, s, { inviteId: a.inviteId, token: tokenOf(a.code) })))).code, "invite_revoked");
  } finally {
    await env.cleanup();
  }
});

test("pre-auth budget: the endpoint bucket answers busy with retryAfter; at most 8 pre-auth sessions", async () => {
  const env = await setup({ limits: { preauthBurst: 5, preauthPerMinute: 10 }, maxPreauthSessions: 3 });
  try {
    const { inviteId } = env.en.createInvite({});
    const codes: string[] = [];
    for (let i = 0; i < 6; i++) {
      const s = await rawSession(env);
      const e = await errorOf(s.c.request(requestFrame(env, s, { inviteId })));
      codes.push(e.code);
      if (e.code === "busy") assert.ok(Number(e.fields.retryAfter) >= 1);
    }
    assert.deepEqual(codes, ["enroll_rejected", "enroll_rejected", "enroll_rejected", "enroll_rejected", "enroll_rejected", "busy"]);
    const b = new TokenBucket(10, 5, () => 0);
    for (let i = 0; i < 5; i++) assert.ok(b.take());
    assert.ok(!b.take());
    assert.equal(b.retryAfter(), 6);
    // Concurrent pre-auth sessions (cap set to 3 here): the fourth is closed after message 1.
    const open = [await rawSession(env), await rawSession(env), await rawSession(env)];
    await assert.rejects(rawSession(env), (e: unknown) => e instanceof RoomSessionError && e.code === "handshake_failed");
    open[0].c.close();
    await until("slot freed", () => env.endpoint.preauthSessions() < 3);
    await rawSession(env);
  } finally {
    await env.cleanup();
  }
});

// ---------------------------------------------------------------- attempt limits and SAS grinding

test("the third abandoned attempt burns the invite; a man in the middle gets at most 3 SAS comparisons", async () => {
  const env = await setup();
  try {
    const { code, inviteId, inviteRef: ref } = env.en.createInvite({});
    const token = tokenOf(code);
    const sasSeen: string[] = [];
    for (let i = 0; i < 3; i++) {
      // The attacker holds the token, plays the member, learns the host's SAS, and aborts on mismatch.
      const s = await rawSession(env);
      const nm = randomBytes(32);
      const pending = await s.c.request(requestFrame(env, s, { inviteId, token, nm }));
      assert.equal(pending.t, "enroll.pending");
      await s.c.request({ t: "sas.reveal", Nm: b64u(nm) });
      sasSeen.push(env.en.pendings().find((p) => p.pendingId === pending.pendingId)!.sas!);
      await s.c.request({ t: "enroll.abort", pendingId: pending.pendingId as string, reason: "cancelled" });
      assert.equal(env.en.invites()[0].abandoned, i + 1);
    }
    assert.equal(sasSeen.length, 3);
    assert.equal(env.en.invites()[0].state, "burned");
    assert.deepEqual(stmtsOf(env, "invite.burned").map((x) => x.body.data), [{ inviteRef: ref, reason: "abandoned" }]);
    assert.equal(stmtsOf(env, "enrollment.closed").length, 3);
    const s = await rawSession(env);
    assert.equal((await errorOf(s.c.request(requestFrame(env, s, { inviteId, token })))).code, "invite_revoked", "no fourth comparison");
    // A timeout and the admin's Cancel count the same way (fresh invite).
    const two = env.en.createInvite({});
    const s2 = await rawSession(env);
    const p2 = await s2.c.request(requestFrame(env, s2, { inviteId: two.inviteId, token: tokenOf(two.code) }));
    env.en.reject(p2.pendingId as string, "cancel");
    assert.equal(env.en.invites()[1].abandoned, 1);
    assert.equal(env.en.invites()[1].state, "open");
    const s3 = await rawSession(env);
    await s3.c.request(requestFrame(env, s3, { inviteId: two.inviteId, token: tokenOf(two.code) }));
    env.now.ms = Date.now() + 16 * 60 * 1000;
    env.en.sweep();
    env.now.ms = null;
    assert.equal(env.en.invites()[1].abandoned, 2);
    assert.equal(env.en.pendings().at(-1)!.closedReason, "timeout");
  } finally {
    await env.cleanup();
  }
});

test("SAS grinding resistance (S-3): the host never re-pins h; another static cannot resume; a reveal must open the commitment", async () => {
  const env = await setup();
  try {
    const { code, inviteId } = env.en.createInvite({});
    const token = tokenOf(code);
    const dh = generateNoiseKeyPair();
    const sigSeed = randomBytes(32);
    const nm = randomBytes(32);
    const s1 = await rawSession(env, dh);
    const first = await s1.c.request(requestFrame(env, s1, { inviteId, token, sigSeed, nm }));
    const pinned = first.h as string;
    assert.equal(pinned, s1.h);
    s1.c.close();
    // Same keys and commitment from a new session (new h'): the original pending, with the ORIGINAL h.
    const s2 = await rawSession(env, dh);
    assert.notEqual(s2.h, pinned);
    const again = await s2.c.request(requestFrame(env, s2, { inviteId, token, sigSeed, nm }));
    assert.equal(again.t, "enroll.resume.ok");
    const { t: _t, re: _re, ...content } = first;
    assert.equal(rjcsText(again.pending), rjcsText(content), "byte-identical pending, same Nh, same pinned h");
    // The host's SAS uses the pinned h, not h'.
    await s2.c.request({ t: "sas.reveal", Nm: b64u(nm) });
    const hostSas = env.en.pendings()[0].sas;
    const inputs = { nm, nh: b64uDecode(first.Nh as string, 32), deviceDh: b64u(dh.publicKey), deviceSig: b64u(rawPublicKey(ed25519PrivateKeyFromSeed(sigSeed))), endpointDh: env.room.host.state.auth.endpoint.dh.pub, genesisHash: env.room.genesisHash, target: { inviteId } };
    assert.equal(hostSas, computeSas({ ...inputs, h: b64uDecode(pinned, 32) }).display);
    assert.notEqual(computeSas({ ...inputs, h: b64uDecode(s2.h, 32) }).transcript, computeSas({ ...inputs, h: b64uDecode(pinned, 32) }).transcript);
    // A man in the middle on another static cannot resume, reveal into or confirm this pending.
    const mitm = await rawSession(env);
    assert.equal((await errorOf(mitm.c.request({ t: "enroll.resume", pendingId: first.pendingId as string }))).code, "enroll_rejected");
    const mitm2 = await rawSession(env);
    assert.equal((await errorOf(mitm2.c.request({ t: "enroll.confirm", pendingId: first.pendingId as string }))).code, "enroll_rejected");
    // A second reveal with another Nm is refused; the pending keeps its first Nm.
    const s3 = await rawSession(env, dh);
    await s3.c.request({ t: "enroll.resume", pendingId: first.pendingId as string });
    assert.equal((await errorOf(s3.c.request({ t: "sas.reveal", Nm: b64u(randomBytes(32)) }))).code, "enroll_rejected");
    assert.equal(env.en.pendings()[0].sas, hostSas);
    // Same keys with a different commitment: the member lost its journal; the old attempt is abandoned.
    const s4 = await rawSession(env, dh);
    assert.equal((await errorOf(s4.c.request(requestFrame(env, s4, { inviteId, token, sigSeed, nm: randomBytes(32) })))).code, "enroll_rejected");
    assert.equal(env.en.pendings()[0].closedReason, "aborted");
    assert.equal(env.en.invites()[0].abandoned, 1);
    // A reveal that does not open the commitment closes the pending as abandoned.
    const s5 = await rawSession(env);
    await s5.c.request(requestFrame(env, s5, { inviteId, token, nm: randomBytes(32) }));
    assert.equal((await errorOf(s5.c.request({ t: "sas.reveal", Nm: b64u(randomBytes(32)) }))).code, "enroll_rejected");
    assert.equal(env.en.invites()[0].abandoned, 2);
  } finally {
    await env.cleanup();
  }
});

test("member: a resume with a changed pending is refused (S-3); an enroll.pending whose h is not in sentH is refused (R-4)", async () => {
  const env = await setup();
  try {
    // S-3: the host (here: tampered host state) answers a resume with another Nh.
    const one = env.en.createInvite({});
    const m = memberJoin(env, one.code);
    await until("pending", () => m.view().sas);
    m.close();
    const pid = m.journal.e.pendingId!;
    const rec = (env.en as any).pending(pid);
    const content = rjcsParse(Buffer.from(rec.content)) as any;
    (env.en as any).updatePending(pid, { content: rjcsText({ ...content, Nh: b64u(randomBytes(32)) }) });
    const again = resumeMember(env, reread(env, decodeInvite(one.code).roomId));
    await until("failed", () => again.journal.state === "failed");
    assert.equal(again.journal.e.failure, "resume_mismatch");
    assert.equal(again.journal.e.keys, null, "keys deleted");
    await until("host closed it", () => env.en.pendings()[0].state === "closed");
    assert.equal(env.en.invites()[0].abandoned, 1);

    // R-4: an enroll.pending pinned to an h the member never sent.
    const env2 = await setup();
    try {
      const two = env2.en.createInvite({});
      const create = (env2.en as any).create.bind(env2.en);
      (env2.en as any).create = (s: unknown, re: number, inv: unknown, req: { h: string }) => create(s, re, inv, { ...req, h: b64u(randomBytes(32)) });
      const m2 = memberJoin(env2, two.code);
      await until("refused", () => m2.journal.state === "failed");
      assert.equal(m2.journal.e.failure, "unpinned_h");
      assert.equal(m2.journal.e.sas, null, "no SAS was computed or shown");
      assert.equal(env2.en.pendings()[0].sas, null, "Nm was never revealed");
    } finally {
      await env2.cleanup();
    }
  } finally {
    await env.cleanup();
  }
});

// --------------------------------------------------------------------------------- restarts

test("restart in every journal state resumes correctly (keys after the request, pending, confirmed, admitted)", async () => {
  const env = await setup();
  try {
    const { code } = env.en.createInvite({});
    const roomId = decodeInvite(code).roomId;
    // keys: the request was sent, then the member crashed before enroll.pending arrived (R-4).
    const j0 = EnrollmentJournal.begin({ dataDir: env.member.dataDir, kek: env.member.kek, invite: decodeInvite(code), label: "Sam laptop" });
    const keys = j0.deviceKeys();
    const dh = { publicKey: b64uDecode(j0.e.deviceDh, 32), secretKey: new Uint8Array(keys.dhSecret) };
    const s = await rawSession(env, dh as NoiseKeyPair);
    j0.addSentH(s.h);
    const driver = new MemberEnrollment({ journal: j0, relay: relayOf(env) });
    const frame = (driver as any).requestFrame(s.h, keys.sigSeed);
    await s.c.request(frame);
    s.c.close();
    assert.equal(reread(env, roomId).state, "keys");
    // Restart: a new session (h'), the same request, resume.ok with the original h; codes match.
    const m1 = resumeMember(env, reread(env, roomId));
    await until("member SAS", () => m1.view().sas);
    const hostSas = await until("host SAS", () => env.en.pendings()[0].sas);
    assert.equal(m1.view().sas, hostSas);
    assert.equal(m1.journal.e.sentH.length, 2);
    assert.equal(env.en.pendings().length, 1, "no second pending");
    // pending: restart shows the stored SAS and the host's is unchanged.
    m1.close();
    const m2 = resumeMember(env, reread(env, roomId));
    await until("waiting", () => m2.connection === "waiting");
    assert.equal(m2.view().sas, hostSas);
    assert.equal(env.en.pendings()[0].sas, hostSas);
    // confirmed: journaled, then the member crashed before enroll.confirm left.
    m2.close();
    const j3 = reread(env, roomId);
    j3.confirm();
    let admitted = false;
    const m3 = resumeMember(env, j3, () => (admitted = true));
    await until("host has the confirm", () => env.en.pendings()[0].state === "member_ok");
    env.en.admit(env.en.pendings()[0].pendingId);
    await until("admitted", () => admitted);
    // admitted: the journal is the local record; a restart does not enroll again.
    m3.close();
    const j4 = reread(env, roomId);
    assert.equal(j4.state, "admitted");
    assert.ok(j4.e.memberId && j4.e.deviceId);
    assert.equal(j4.e.sentH.length, 2, "resumes do not open a new request");
  } finally {
    await env.cleanup();
  }
});

test("a fifth session for one join deletes the keys and asks for a new invite", async () => {
  const t = tempDir();
  try {
    const { dataDir, kek } = await openKek(t.dir, "m");
    const j = EnrollmentJournal.begin({ dataDir, kek, invite: decodeInvite(V.invite.code), label: "x" });
    for (let i = 0; i < MAX_SENT_H; i++) j.addSentH(b64u(randomBytes(32)));
    assert.throws(() => j.addSentH(b64u(randomBytes(32))), /too many sessions/);
    assert.equal(j.e.tokenKey !== null, true);
    j.fail("too_many_sessions");
    const back = EnrollmentJournal.read({ dataDir, kek, roomId: j.roomId })!;
    assert.equal(back.state, "failed");
    assert.equal(back.e.keys, null);
    assert.equal(back.e.invite.token, null, "the token itself is never stored");
  } finally {
    t.cleanup();
  }
});

// ------------------------------------------------------------------------------------- races

test("races of section 9", async (t) => {
  const cases: { name: string; run(env: Env): Promise<void> }[] = [
    {
      name: "two requesters with valid proofs: the second gets invite_in_use; invite.contested is logged and flagged",
      async run(env) {
        const { code, inviteId, inviteRef: ref } = env.en.createInvite({});
        const a = await rawSession(env);
        const pa = await a.c.request(requestFrame(env, a, { inviteId, token: tokenOf(code) }));
        const b = await rawSession(env);
        assert.equal((await errorOf(b.c.request(requestFrame(env, b, { inviteId, token: tokenOf(code) })))).code, "invite_in_use");
        assert.deepEqual(stmtsOf(env, "invite.contested").map((x) => x.body.data), [{ inviteRef: ref, pendingId: pa.pendingId }]);
        assert.equal(env.en.pendings()[0].contested, true);
        // The admin then rejects the first: the invite is burned (it leaked).
        env.en.reject(pa.pendingId as string, "sas_mismatch");
        assert.equal(env.en.invites()[0].state, "burned");
      },
    },
    {
      name: "admin revokes the invite during pending: the pending closes with invite_revoked and the member fails",
      async run(env) {
        const { code, inviteId } = env.en.createInvite({});
        const m = memberJoin(env, code);
        await until("pending", () => m.view().sas);
        env.en.revokeInvite(inviteId);
        await until("member failed", () => m.journal.state === "failed");
        assert.equal(m.journal.e.failure, "closed:invite_revoked");
        assert.equal(env.en.pendings()[0].closedReason, "invite_revoked");
        assert.equal(stmtsOf(env, "invite.revoked").length, 1);
      },
    },
    {
      name: "member presses Codes match after the admin pressed Codes do not match: enroll_closed rejected wins",
      async run(env) {
        const { code } = env.en.createInvite({});
        const m = memberJoin(env, code);
        await until("pending", () => m.view().sas);
        m.close(); // the member's session is gone while the admin decides
        env.en.reject(env.en.pendings()[0].pendingId, "sas_mismatch");
        const j = reread(env, decodeInvite(code).roomId);
        j.confirm();
        const again = resumeMember(env, j);
        await until("failed", () => again.journal.state === "failed");
        assert.equal(again.journal.e.failure, "closed:rejected");
        assert.equal(env.en.invites()[0].state, "burned");
      },
    },
    {
      name: "the member says the codes do not match: the invite burns with sas_mismatch",
      async run(env) {
        const { code, inviteRef: ref } = env.en.createInvite({});
        const m = memberJoin(env, code);
        await until("pending", () => m.view().sas);
        await m.confirm(false);
        await until("host closed", () => env.en.pendings()[0].state === "closed");
        assert.equal(m.journal.e.failure, "sas_mismatch");
        assert.deepEqual(stmtsOf(env, "invite.burned").map((x) => x.body.data), [{ inviteRef: ref, reason: "sas_mismatch" }]);
      },
    },
    {
      name: "a used invite reports invite_used to a token holder; an expired one invite_expired and logs it once",
      async run(env) {
        const { code, inviteId } = env.en.createInvite({ expS: 300 });
        let admitted = false;
        const j = EnrollmentJournal.begin({ dataDir: env.member.dataDir, kek: env.member.kek, invite: decodeInvite(code), label: "a" });
        const m = resumeMember(env, j, () => (admitted = true));
        await until("pending", () => m.view().sas);
        await m.confirm(true);
        await until("member ok", () => env.en.pendings()[0].state === "member_ok");
        env.en.admit(env.en.pendings()[0].pendingId);
        await until("admitted", () => admitted);
        const s = await rawSession(env);
        assert.equal((await errorOf(s.c.request(requestFrame(env, s, { inviteId, token: tokenOf(code) })))).code, "invite_used");
        const late = env.en.createInvite({ expS: 300 });
        env.now.ms = Date.now() + 301_000;
        for (let i = 0; i < 2; i++) {
          const s2 = await rawSession(env);
          assert.equal((await errorOf(s2.c.request(requestFrame(env, s2, { inviteId: late.inviteId, token: tokenOf(late.code) })))).code, "invite_expired");
        }
        env.now.ms = null;
        assert.equal(stmtsOf(env, "invite.expired").length, 1);
      },
    },
    {
      name: "host restart during pending: pending, invite and pinned inputs survive; the member resumes",
      async run(env) {
        const { code } = env.en.createInvite({});
        const m = memberJoin(env, code);
        const sas = await until("pending", () => m.view().sas);
        await until("host has the reveal", () => env.en.pendings()[0].sas);
        m.close();
        // A new EnrollmentHost over the same state file (the endpoint's is replaced for this check).
        const fresh = new EnrollmentHost({ host: env.room.host, dataDir: env.dataDir, kek: env.kek, admin: null, afterAppend: () => undefined, endpointDh: () => env.room.host.state.auth.endpoint.dh.pub, sweepMs: 0 });
        assert.equal(fresh.pendings()[0].sas, sas);
        assert.equal(fresh.invites()[0].state, "claimed");
        fresh.stop();
        const again = resumeMember(env, reread(env, decodeInvite(code).roomId));
        await until("waiting", () => again.connection === "waiting");
        assert.equal(again.view().sas, sas);
      },
    },
  ];
  for (const c of cases) {
    await t.test(c.name, async () => {
      const env = await setup();
      try {
        await c.run(env);
      } finally {
        await env.cleanup();
      }
    });
  }
});

// ------------------------------------------------------------------------- P-20/C-15 relay rules

test("P-20: plaintext and IP-literal relays are refused; an unknown relay needs the user's trust; lane labels are prefixed", () => {
  const nowS = Math.floor(Date.now() / 1000);
  const base = { ...V.invite.payload, exp: nowS + 600 } as InvitePayload;
  const code = (p: InvitePayload) => encodeInvite(p);
  const withRelay = (host: string, port = 443) => code({ ...base, endpoint: { ...base.endpoint, relay: { host, port, tls: true } } });
  const trusted = ["relay.paseo.sh:443"];
  assert.equal(checkInvite(code(base), { nowS, trustedRelays: trusted, env: {} }).preview.relay.trusted, true);
  for (const host of ["127.0.0.1", "localhost", "relay", "10.0.0.1"]) {
    assert.throws(() => checkInvite(withRelay(host), { nowS, trustedRelays: trusted, env: {} }), (e: unknown) => e instanceof JoinRefusedError && e.code === "relay_not_allowed", host);
  }
  assert.equal(checkInvite(withRelay("127.0.0.1", 6923), { nowS, trustedRelays: trusted, env: { PASEO_ROOMS_DEV_INSECURE_RELAY: "1" } }).preview.relay.trusted, false);
  const unknown = checkInvite(withRelay("relay.example.org"), { nowS, trustedRelays: trusted, env: {} }).preview;
  assert.equal(unknown.relay.trusted, false);
  assert.equal(unknown.unverified, true);
  assert.throws(() => requireRelayTrust(unknown, false), (e: unknown) => e instanceof JoinRefusedError && e.code === "relay_not_trusted");
  requireRelayTrust(unknown, true);
  // A non-443 port on the known relay is an unknown relay.
  assert.equal(checkInvite(withRelay("relay.paseo.sh", 8443), { nowS, trustedRelays: trusted, env: {} }).preview.relay.trusted, false);
  assert.throws(() => checkInvite(code({ ...base, exp: nowS - 301 }), { nowS, trustedRelays: trusted, env: {} }), (e: unknown) => e instanceof JoinRefusedError && e.code === "expired");
  checkInvite(code({ ...base, exp: nowS - 299 }), { nowS, trustedRelays: trusted, env: {} });
  assert.throws(() => checkInvite("prc1.xyz", { nowS, trustedRelays: trusted }), (e: unknown) => e instanceof JoinRefusedError && e.code === "older_version");
  // TLS always for the member, plain ws only for a loopback relay with the development flag.
  assert.deepEqual(memberRelayAddress({ host: "relay.paseo.sh", port: 443 }, { PASEO_ROOMS_DEV_INSECURE_RELAY: "1", PASEO_ROOMS_RELAY_TLS: "false" }), { endpoint: "relay.paseo.sh:443", useTls: true });
  assert.deepEqual(memberRelayAddress({ host: "127.0.0.1", port: 6923 }, { PASEO_ROOMS_RELAY_TLS: "false" }), { endpoint: "127.0.0.1:6923", useTls: true });
  assert.deepEqual(memberRelayAddress({ host: "127.0.0.1", port: 6923 }, { PASEO_ROOMS_DEV_INSECURE_RELAY: "1" }), { endpoint: "127.0.0.1:6923", useTls: false });
  assert.equal(laneHostLabel({ verifiedName: "Lab‮ analysis", roomId: "room_0123456789abcdef" }, "GPU box"), "Room lane: Lab analysis (room_01234567) · GPU box");
  assert.equal(laneHostLabel({ verifiedName: null, roomId: "room_0123456789abcdef" }), "Room lane: room_01234567");
});

// ----------------------------------------------------------------------------------- C-10

test("C-10: hosts.add failure retries with backoff and keeps the local record; registration is idempotent", async () => {
  const timers: { ms: number; f: () => void }[] = [];
  const recorded: [string, string][] = [];
  let done = 0;
  let fails = 2;
  const calls: string[] = [];
  const dir: { registrationId: string; source: { id: string; key: string } }[] = [];
  const hosts: HostsApi = {
    list: async () => (calls.push("list"), { hosts: dir }),
    add: async (i) => {
      calls.push("add");
      if (fails-- > 0) throw Object.assign(new Error("daemon busy"), { code: "busy" });
      const reg = { registrationId: `reg_${dir.length + 1}`, source: { id: "plugin:rooms", key: i.sourceKey } };
      dir.push(reg);
      return reg;
    },
    update: async (id) => (calls.push("update"), { registrationId: id }),
  };
  const deps = {
    roomId: "room_x",
    pluginId: "rooms",
    hosts: () => hosts,
    connectionFor: async () => "secret-connection-uri",
    label: (l: string) => laneHostLabel({ verifiedName: null, roomId: "room_x" }, l),
    record: (l: string, r: string) => recorded.push([l, r]),
    done: () => done++,
    setTimer: (f: () => void, ms: number) => timers.push({ ms, f }),
    clearTimer: () => undefined,
  };
  const lanes = ["lane_" + "1".repeat(32), "lane_" + "2".repeat(32)];
  const r = new LaneRegistrar(deps, lanes, {});
  await r.run();
  assert.equal(r.status, "retrying");
  assert.equal(r.lastError, "busy");
  assert.deepEqual(timers.map((t) => t.ms), [REGISTRATION_BACKOFF_MS[0]]);
  await timers.shift()!.f();
  await until("second retry armed", () => timers.length === 1);
  assert.equal(timers[0].ms, REGISTRATION_BACKOFF_MS[1]);
  await timers.shift()!.f();
  await until("done", () => done === 1);
  assert.deepEqual(recorded, [
    [lanes[0], "reg_1"],
    [lanes[1], "reg_2"],
  ]);
  // Idempotent: a restart without the journal's ids finds the registrations by sourceKey and updates them.
  calls.length = 0;
  const again = new LaneRegistrar({ ...deps, record: () => undefined, done: () => done++ }, lanes, {});
  await again.run();
  assert.deepEqual(calls, ["list", "update", "list", "update"]);
  assert.equal(dir.length, 2, "no second registration");
  // No API yet: retried, nothing lost.
  const noApi = new LaneRegistrar({ ...deps, hosts: () => null }, lanes, {});
  await noApi.run();
  assert.equal(noApi.lastError, "no_api");
  // Backoff caps at 60 s.
  assert.equal(REGISTRATION_BACKOFF_MS.at(-1), 60_000);
});

test("C-10: the journal reaches admitted before any hosts call, and registered after the lanes", async () => {
  const t = tempDir();
  try {
    const { dataDir, kek } = await openKek(t.dir, "m");
    const j = EnrollmentJournal.begin({ dataDir, kek, invite: decodeInvite(V.invite.code), label: "x" });
    j.addSentH(b64u(randomBytes(32)));
    j.recordPending({ pendingId: "pen_" + "a".repeat(32), content: "{}", sas: "317837", transcript: b64u(randomBytes(32)), terms: { role: "watch", lanes: ["lane_" + "1".repeat(32)] }, expiresAt: 1, genesis: "{}" });
    assert.throws(() => j.registration("lane_" + "1".repeat(32), "reg"), /journal is pending/, "no hosts registration before admission");
    j.admitted("mem_" + "b".repeat(32), "dev_" + "c".repeat(32));
    const r = new LaneRegistrar(
      {
        roomId: j.roomId,
        pluginId: "rooms",
        hosts: () => ({ list: async () => ({ hosts: [] }), add: async () => ({ registrationId: "reg_1" }), update: async (id) => ({ registrationId: id }) }),
        connectionFor: async () => "uri",
        label: () => "Room lane: x",
        record: (l, id) => j.registration(l, id),
        done: () => j.registered(),
      },
      j.e.terms!.lanes,
      j.e.registrations,
    );
    await r.run();
    const back = EnrollmentJournal.read({ dataDir, kek, roomId: j.roomId })!;
    assert.equal(back.state, "registered");
    assert.deepEqual(back.e.registrations, { ["lane_" + "1".repeat(32)]: "reg_1" });
  } finally {
    t.cleanup();
  }
});
