// Identity v2 milestone I-7: room host core, offline. Room creation (genesis, admin, host and endpoint
// keys, the recovery key offered by default and skippable), the admin signer behind a confirmation
// token, the host log store under the I-2 writer lock with the torn-line rules, re-fold on restart,
// stmt.submit answers (stale_base, unknown_base, not_permitted), outstanding statements settled by a
// producer.fence, and the security events of room-log-v2 4.6 with their producers (P-27).
// Keys are sealed through the I-3 KeyStore over a fake keyring backend; no real keyring, no network.
import assert from "node:assert/strict";
import { appendFileSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createRoom, CreateRoomError, decodeRecoveryCode, encodeRecoveryCode, memberKeysPath, memberKeysPurpose, RECOVERY_SKIP_WARNING, type CreatedRoom } from "../../server/admin/genesis";
import { adminKeyPath, adminKeyPurpose, AdminSigner, AdminSignerError, adminStatePath } from "../../server/admin/signer";
import { bodyHash } from "../../server/authority/entries";
import { verifyGenesis } from "../../server/authority/genesis";
import { STATEMENT_TYPES, type SignedStatement, type StatementType } from "../../server/authority/statements";
import { RoomHost, RoomHostError, genesisPath, hostKeysPath, hostKeysPurpose, HOST_STATEMENT_TYPES, SECURITY_EVENTS } from "../../server/host/room-host";
import { BODIES_FILE, ENTRIES_FILE, hostLogDir, RoomLogCorruptError } from "../../server/host/room-log-store";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { SealedFileError } from "../../server/keystore/sealed";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { LOCK_FILE } from "../../server/platform/log-lock";
import { b64u } from "../../server/proto/b64u";
import { CTX_KEY_CHANGE_NEW, stmtContext } from "../../server/proto/contexts";
import { inviteRef, newId, newServerId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey, x25519PrivateKeyFromSecret } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { sign } from "../../server/proto/tbs";
import { tempDir } from "./helpers";
import { randomBytes, type KeyObject } from "node:crypto";

const RELAY = { host: "relay.example.test", port: 443, tls: true as const };
const T0 = Date.parse("2026-10-29T12:00:00Z");
/** No heartbeat timers in tests: a "crashed" host must not touch the lock later. */
const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };

/** A fake native keyring over a Map. Never touches a real keyring. */
function fakeKeyring(): () => { ok: true; backend: KeyStoreBackend; how: string } {
  const store = new Map<string, Buffer>();
  const backend: KeyStoreBackend = {
    name: "linux-secret-service",
    fallback: false,
    probe: async () => "available",
    get: async () => {
      const v = store.get("kek");
      return v ? Buffer.from(v) : null;
    },
    put: async (kek) => void store.set("kek", Buffer.from(kek)),
    delete: async () => store.delete("kek"),
  };
  return () => ({ ok: true, backend, how: "fake" });
}

async function setup() {
  const t = tempDir();
  const home = join(t.dir, "home");
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
  if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
  let clock = T0;
  const now = () => clock;
  const advance = (ms: number) => void (clock += ms);
  return { t, dataDir, kek: s.kek as Kek, now, advance };
}

type Env = Awaited<ReturnType<typeof setup>>;

async function newRoom(env: Env, extra: Partial<Parameters<typeof createRoom>[0]> = {}): Promise<CreatedRoom> {
  return createRoom({ dataDir: env.dataDir, kek: env.kek, relay: RELAY, now: env.now, lock: NO_TIMER, ...extra });
}

function reopen(env: Env, roomId: string, lock: object = NO_TIMER): Promise<RoomHost> {
  return RoomHost.open({ dataDir: env.dataDir, kek: env.kek, roomId, now: env.now, lock });
}

/** Interactive admin action through the confirmation token, then stmt.submit; returns the receipt seq. */
function adminDo<T extends StatementType>(host: RoomHost, signer: AdminSigner, type: T, data: unknown): number {
  const p = signer.prepare({ type, data: data as never, base: host.head });
  const stmt = signer.confirm(p.confirmToken);
  const res = host.submit(stmt);
  assert.ok(res.ok, res.ok ? "" : `${type}: ${res.code} ${res.reason} ${res.message}`);
  signer.reconcile(host);
  return res.receipt.entry.seq;
}

const newEd = () => {
  const priv = ed25519PrivateKeyFromSeed(randomBytes(32));
  const pub = rawPublicKey(priv);
  return { priv, pub: b64u(pub), kid: kidOf("ed25519", pub) };
};
const newX = () => {
  const pub = rawPublicKey(x25519PrivateKeyFromSecret(randomBytes(32)));
  return { alg: "x25519" as const, kid: kidOf("x25519", pub), pub: b64u(pub) };
};

/** A statement signed by a key the test holds (a second admin's daemon, or the recovery key offline). */
function signAs(host: RoomHost, priv: KeyObject, kind: "admin" | "recovery" | "device", kid: string, type: StatementType, data: unknown): SignedStatement {
  const body = { v: 2 as const, typ: "stmt" as const, type, roomId: host.roomId, producer: { kind, kid }, base: host.head, ts: 0, data };
  return { body, sig: b64u(sign(priv, stmtContext(type), rjcs(body))) } as SignedStatement;
}

function keyChange(roomId: string, subject: { kind: "admin" | "recovery"; id: string }, old: string | null, k: ReturnType<typeof newEd>) {
  const change = { v: 2 as const, typ: "key-change" as const, roomId, subject, old, newSig: k.pub, newDh: null };
  return { change, newKeySig: b64u(sign(k.priv, CTX_KEY_CHANGE_NEW, rjcs(change))) };
}

const mode = (p: string) => statSync(p).mode & 0o777;

function allFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...allFiles(p));
    else out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------------------- creation

test("create a room in a temporary home: genesis, sealed key files, creator admitted at seq 0, reload re-folds", async () => {
  const env = await setup();
  try {
    const room = await newRoom(env);
    const g = verifyGenesis(room.genesis);
    assert.equal(g.roomId, room.roomId);
    assert.equal(g.genesisHash, room.genesisHash);
    const b = room.genesis.body;
    assert.equal(b.admins.length, 1);
    assert.equal(b.admins[0].kid, room.signer.kid);
    assert.equal(b.policy.closeDelay, 86400);
    assert.equal(b.policy.deviceAddApproval, "same-person");
    assert.deepEqual(b.endpoint.relay, RELAY);
    assert.match(b.endpoint.serverId, /^rme_/);
    // Recovery key offered by default: in genesis; the code is the seed and is never stored.
    assert.ok(b.recovery && room.recovery);
    assert.equal(room.recoverySkippedWarning, null);
    const seed = decodeRecoveryCode(room.recovery.code);
    assert.equal(kidOf("ed25519", rawPublicKey(ed25519PrivateKeyFromSeed(seed))), b.recovery.kid);
    assert.equal(encodeRecoveryCode(seed), room.recovery.code);
    assert.equal(JSON.parse(room.recovery.fileText).kid, b.recovery.kid);
    for (const f of allFiles(env.dataDir)) {
      const text = readFileSync(f, "latin1");
      assert.ok(!text.includes(room.recovery.code) && !text.includes(b64u(seed)), "recovery seed never on disk");
    }

    // seq 0 is the creator's admission, by the admin key.
    assert.equal(room.host.head.seq, 0);
    const roster = room.host.roster();
    assert.equal(roster.seq, 0);
    assert.deepEqual(roster.members.map((m) => [m.memberId, m.role, m.devices[0].deviceId]), [[room.memberId, "admin", room.deviceId]]);
    assert.deepEqual(room.signer.outstanding(), []);

    // Files: owner-only, sealed under their purposes.
    for (const p of [hostKeysPath(env.dataDir, room.roomId), adminKeyPath(env.dataDir, room.roomId), memberKeysPath(env.dataDir, room.roomId), adminStatePath(env.dataDir, room.roomId)]) {
      assert.equal(mode(p), 0o600, p);
      assert.equal(JSON.parse(readFileSync(p, "utf8")).typ, "sealed");
    }
    assert.equal(mode(genesisPath(env.dataDir, room.roomId)), 0o600);
    assert.equal(mode(join(hostLogDir(env.dataDir, room.roomId), ENTRIES_FILE)), 0o600);
    assert.equal(mode(join(env.dataDir, "admin", room.roomId)), 0o700);
    assert.ok(env.kek.readSealed(memberKeysPath(env.dataDir, room.roomId), memberKeysPurpose(room.roomId)));
    assert.throws(() => env.kek.readSealed(hostKeysPath(env.dataDir, room.roomId), adminKeyPurpose(room.roomId)), SealedFileError);
    assert.throws(() => env.kek.readSealed(adminKeyPath(env.dataDir, room.roomId), hostKeysPurpose(room.roomId)), SealedFileError);
    // No secret-looking field in plaintext anywhere.
    for (const f of allFiles(env.dataDir)) assert.ok(!/"(seed|secret)"/.test(readFileSync(f, "utf8")), f);

    // The lock is held while open; a second host on the same room is refused.
    await assert.rejects(reopen(env, room.roomId), (e: Error) => e.name === "LogLockHeldError");
    const rosterHash = room.host.rosterHash();
    room.host.close();
    const again = await reopen(env, room.roomId);
    assert.equal(again.head.seq, 0);
    assert.equal(again.rosterHash(), rosterHash);
    assert.deepEqual(again.tornOnOpen, []);
    again.close();
  } finally {
    env.t.cleanup();
  }
});

test("recovery key: skippable in one choice with the warning; required when org escrow is set", async () => {
  const env = await setup();
  try {
    const skipped = await newRoom(env, { recovery: "skip" });
    assert.equal(skipped.genesis.body.recovery, null);
    assert.equal(skipped.recovery, null);
    assert.equal(skipped.recoverySkippedWarning, RECOVERY_SKIP_WARNING);
    skipped.host.close();
    await assert.rejects(newRoom(env, { recovery: "skip", policy: { recoveryEscrow: "org" } }), (e: unknown) => e instanceof CreateRoomError && e.code === "recovery_required");
    const org = await newRoom(env, { policy: { recoveryEscrow: "org", deviceAddApproval: "admin" } });
    assert.ok(org.genesis.body.recovery);
    assert.equal(org.genesis.body.policy.recoveryEscrow, "org");
    org.host.close();
    await assert.rejects(newRoom(env, { policy: { grantTtl: 50000 } }), (e: unknown) => e instanceof CreateRoomError && e.code === "bad_policy");
    await assert.rejects(newRoom(env, { relay: { ...RELAY, tls: false as unknown as true } }), (e: unknown) => e instanceof CreateRoomError && e.code === "bad_relay");
    assert.throws(() => decodeRecoveryCode("prk2-abcd"), /length/);
  } finally {
    env.t.cleanup();
  }
});

// ---------------------------------------------------------------------------------- signer

test("admin signer: one-time confirm token, expiry, automatic signing limited, one statement at a time", async () => {
  const env = await setup();
  try {
    const { host, signer, roomId } = await newRoom(env);
    const p = signer.prepare({ type: "room.policy.changed", data: { changes: [{ setting: "closeDelay", value: 3600, ver: -1 }] }, base: host.head });
    assert.equal(p.description.type, "room.policy.changed");
    assert.equal(p.description.visibleToMembers, true);
    assert.deepEqual(p.description.base, host.head);
    assert.throws(() => signer.confirm("not-a-token"), (e: unknown) => e instanceof AdminSignerError && e.code === "bad_token");
    // Expired tokens are refused and consumed.
    env.advance(6 * 60 * 1000);
    assert.throws(() => signer.confirm(p.confirmToken), (e: unknown) => e instanceof AdminSignerError && e.code === "token_expired");
    assert.throws(() => signer.confirm(p.confirmToken), (e: unknown) => e instanceof AdminSignerError && e.code === "bad_token");
    // Data is checked before a token is issued; only admin-producible types.
    assert.throws(() => signer.prepare({ type: "room.policy.changed", data: { changes: [] } as never, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "bad_data");
    assert.throws(() => signer.prepare({ type: "member.left", data: { memberId: newId("member") }, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "not_admin_statement");

    const p2 = signer.prepare({ type: "room.policy.changed", data: { changes: [{ setting: "closeDelay", value: 3600, ver: -1 }] }, base: host.head });
    const stmt = signer.confirm(p2.confirmToken);
    assert.throws(() => signer.confirm(p2.confirmToken), (e: unknown) => (e as AdminSignerError).code === "bad_token");
    // Outstanding until settled: nothing else is signed, and the record survives a restart.
    assert.equal(signer.outstanding().length, 1);
    assert.throws(() => signer.prepare({ type: "room.close.proposed", data: { exp: 0 }, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "outstanding");
    const reloaded = AdminSigner.load({ dataDir: env.dataDir, kek: env.kek, roomId, now: env.now });
    assert.equal(reloaded.outstanding()[0].bodyHash, bodyHash(rjcs(stmt)));
    const res = host.submit(stmt);
    assert.ok(res.ok);
    assert.deepEqual(reloaded.reconcile(host).applied.map((a) => a.seq), [1]);
    assert.equal(reloaded.outstanding().length, 0);
    assert.equal(host.state.auth.policy.closeDelay, 3600);

    // Policy-automatic signing: device.add.approved in mode auto only; a rekey approval waits for I-13.
    const approval = { memberId: newId("member"), deviceId: newId("device"), ref: b64u(randomBytes(32)) };
    assert.throws(() => reloaded.signAutomatic({ type: "device.add.approved", data: { ...approval, mode: "admin" }, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "needs_confirmation");
    assert.throws(() => reloaded.signAutomatic({ type: "device.rekey.approved", data: { ...approval, mode: "auto" }, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "needs_mls_commit");
    assert.throws(() => reloaded.signAutomatic({ type: "room.closed" as never, data: { proposal: null } as never, base: host.head }), (e: unknown) => (e as AdminSignerError).code === "needs_confirmation");
    // The local forward rule: a base at or before this key's last sequenced base is refused.
    assert.throws(() => reloaded.prepare({ type: "room.close.proposed", data: { exp: 0 }, base: { seq: 0, hash: host.entries(0, 0)[0].signed.hash } }), (e: unknown) => (e as AdminSignerError).code === "base_not_forward");
    // The signer never shows its key.
    assert.ok(!JSON.stringify(reloaded).includes("seed") && !String(reloaded).includes("seed"));
    host.close();
  } finally {
    env.t.cleanup();
  }
});

// ---------------------------------------------------------------------------------- the log

test("append, crash and reload: torn final lines and an orphan body are moved aside; the log is re-folded", async () => {
  const env = await setup();
  try {
    const { host, signer, roomId } = await newRoom(env);
    const laneId = newId("lane");
    adminDo(host, signer, "invite.created", { inviteRef: inviteRef(newId("invite")), role: "watch", lanes: [], exp: Math.floor(T0 / 1000) + 3600 });
    adminDo(host, signer, "lane.created", { laneId, owner: signer.memberId, offer: { serverId: newServerId("laneEndpoint"), dh: newX(), relay: RELAY }, visibility: "room" });
    adminDo(host, signer, "room.policy.changed", { changes: [{ setting: "projectNames", value: "hidden", ver: -1 }] });
    const head = host.head;
    const rosterHash = host.rosterHash();
    // Crash: no close(), the lock file stays; then a body written without its entry, and a half entry.
    const dir = hostLogDir(env.dataDir, roomId);
    appendFileSync(join(dir, BODIES_FILE), `${new TextDecoder().decode(rjcs({ seq: head.seq + 1, body: b64u(Buffer.from("{}")) }))}\n`);
    appendFileSync(join(dir, ENTRIES_FILE), '{"entry":{"bodyHash":"');
    assert.ok(readdirSync(dir).includes(LOCK_FILE));

    // A live-looking lock refuses; a stale one is taken over after the wait (faked clock).
    await assert.rejects(reopen(env, roomId), (e: Error) => e.name === "LogLockHeldError");
    const later = Date.now() + 120_000;
    const h2 = await reopen(env, roomId, { ...NO_TIMER, now: () => later, sleep: async () => {} });
    assert.deepEqual(h2.head, head);
    assert.equal(h2.rosterHash(), rosterHash);
    assert.deepEqual(h2.tornOnOpen.map((t) => [t.file, t.reason]).sort(), [
      [BODIES_FILE, "orphan_body"],
      [ENTRIES_FILE, "no_newline"],
    ]);
    const tornFiles = readdirSync(dir).filter((n) => n.includes(".torn."));
    assert.equal(tornFiles.length, 2);
    for (const n of tornFiles) assert.equal(mode(join(dir, n)), 0o600);
    assert.equal(readFileSync(join(dir, tornFiles.find((n) => n.startsWith("entries"))!), "utf8"), '{"entry":{"bodyHash":"');

    // The host continues the chain; the signer settles against the reopened host.
    const signer2 = AdminSigner.load({ dataDir: env.dataDir, kek: env.kek, roomId, now: env.now });
    const seq = adminDo(h2, signer2, "lane.offer.rotated", { laneId, offer: { serverId: newServerId("laneEndpoint"), dh: newX(), relay: RELAY }, ver: 2 });
    assert.equal(seq, head.seq + 1);
    // A complete final line that does not parse is torn, too.
    h2.close();
    appendFileSync(join(dir, ENTRIES_FILE), "not json\n");
    const h3 = await reopen(env, roomId);
    assert.deepEqual(h3.tornOnOpen.map((t) => t.reason), ["unparsable"]);
    assert.equal(h3.head.seq, head.seq + 1);
    assert.equal(h3.entries().length, head.seq + 2);
    assert.equal(readFileSync(join(dir, ENTRIES_FILE), "utf8").split("\n").length, head.seq + 3);
    h3.close();
  } finally {
    env.t.cleanup();
  }
});

test("a bad middle line stops the room; an entry that fails the fold stops it too; nothing is skipped", async () => {
  const env = await setup();
  try {
    const { host, signer, roomId } = await newRoom(env);
    adminDo(host, signer, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 0, ver: -1 }] });
    adminDo(host, signer, "room.policy.changed", { changes: [{ setting: "grantTtl", value: 7200, ver: -1 }] });
    host.close();
    const path = join(hostLogDir(env.dataDir, roomId), ENTRIES_FILE);
    const good = readFileSync(path, "utf8");
    const lines = good.trimEnd().split("\n");
    assert.equal(lines.length, 3);

    writeFileSync(path, [lines[0], "garbage", lines[2]].join("\n") + "\n");
    await assert.rejects(reopen(env, roomId), (e: unknown) => e instanceof RoomLogCorruptError && e.code === "log_corrupt" && e.line === 2);
    // Nothing was rewritten, and the lock was released after the failure.
    assert.equal(readFileSync(path, "utf8").split("\n")[1], "garbage");
    await assert.rejects(reopen(env, roomId), RoomLogCorruptError);

    // A parsable middle entry whose signature no longer verifies: the fold rejects it.
    const tampered = JSON.parse(lines[1]);
    tampered.entry.hts += 1;
    writeFileSync(path, [lines[0], new TextDecoder().decode(rjcs(tampered)), lines[2]].join("\n") + "\n");
    await assert.rejects(reopen(env, roomId), (e: unknown) => e instanceof RoomHostError && e.code === "room_stopped");

    writeFileSync(path, good);
    const ok = await reopen(env, roomId);
    assert.equal(ok.head.seq, 2);
    ok.close();
  } finally {
    env.t.cleanup();
  }
});

// ---------------------------------------------------------------------------------- stmt.submit

test("stmt.submit: stale_base after a concurrent admin change, unknown_base, not_permitted; rejected statements are not logged", async () => {
  const env = await setup();
  try {
    const { host, signer, roomId } = await newRoom(env);
    // A second admin, whose key lives on another daemon (held by the test).
    const b = newEd();
    adminDo(host, signer, "admin.added", keyChange(roomId, { kind: "admin", id: signer.memberId }, null, b));

    // Both admins see closeDelay at version -1 and decide; B's change is sequenced first.
    const p = signer.prepare({ type: "room.policy.changed", data: { changes: [{ setting: "closeDelay", value: 0, ver: -1 }] }, base: host.head });
    const mine = signer.confirm(p.confirmToken);
    const theirs = host.submit(signAs(host, b.priv, "admin", b.kid, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 172800, ver: -1 }] }));
    assert.ok(theirs.ok);
    const before = host.head.seq;
    const res = host.submit(mine);
    assert.ok(!res.ok);
    assert.equal(res.code, "stale_base");
    assert.equal(res.reason, "stale_version");
    assert.deepEqual(res.head, theirs.receipt);
    assert.equal(host.head.seq, before);
    assert.equal(host.state.auth.policy.closeDelay, 172800);
    // A definite rejection settles the outstanding statement; the dialog shows the new value and re-signs.
    signer.settle(bodyHash(rjcs(mine)), { rejected: true });
    adminDo(host, signer, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 0, ver: host.state.auth.versions["policy:closeDelay"] }] });
    assert.equal(host.state.auth.policy.closeDelay, 0);

    // unknown_base: a base hash that is not in the chain, and a base beyond the head.
    const wrongHash = signAs(host, b.priv, "admin", b.kid, "producer.fence", {});
    wrongHash.body.base = { seq: host.head.seq, hash: b64u(randomBytes(32)) };
    wrongHash.sig = b64u(sign(b.priv, stmtContext("producer.fence"), rjcs(wrongHash.body)));
    const r1 = host.submit(wrongHash);
    assert.ok(!r1.ok && r1.code === "unknown_base");
    const beyond = signAs(host, b.priv, "admin", b.kid, "producer.fence", {});
    beyond.body.base = { seq: host.head.seq + 5, hash: host.head.hash };
    beyond.sig = b64u(sign(b.priv, stmtContext("producer.fence"), rjcs(beyond.body)));
    const r2 = host.submit(beyond);
    assert.ok(!r2.ok && r2.code === "unknown_base");

    // not_permitted: bad signature, wrong room, a rekey approval outside commit.submit, a host statement,
    // a host key rotation to a key the host does not hold, non-canonical bytes.
    const badSig = signAs(host, b.priv, "admin", b.kid, "producer.fence", {});
    badSig.body.ts = 1;
    const codes = [
      host.submit(badSig),
      host.submit(signAs(host, b.priv, "admin", b.kid, "device.rekey.approved", { memberId: signer.memberId, deviceId: newId("device"), ref: b64u(randomBytes(32)), mode: "admin" })),
      host.submit(signAs(host, b.priv, "host" as "admin", b.kid, "mls.stalled", { epoch: 0, sinceMs: 0 })),
      host.submit(signAs(host, b.priv, "admin", b.kid, "host.key.rotated", { ...keyChange(roomId, { kind: "admin", id: "host" }, host.state.auth.hostKeys[0].kid, newEd()), oldValidTo: 0 })),
      host.submit(new TextEncoder().encode(" {}")),
    ].map((r) => (r.ok ? "ok" : `${r.code}:${r.reason}`));
    assert.deepEqual(codes, ["not_permitted:bad_signature", "not_permitted:submit_only_with_commit", "not_permitted:host_statement", "not_permitted:host_key_not_held", "not_permitted:bad_statement"]);
    const headBefore = host.head.seq;
    host.close();
    const again = await reopen(env, roomId);
    assert.equal(again.head.seq, headBefore, "rejected statements are not logged");
    again.close();
  } finally {
    env.t.cleanup();
  }
});

test("an outstanding statement is made void by a producer.fence", async () => {
  const env = await setup();
  try {
    const { host, signer, roomId } = await newRoom(env);
    // Signed, then the reply is lost: the statement is outstanding ("not confirmed").
    const p = signer.prepare({ type: "room.policy.changed", data: { changes: [{ setting: "rotateLaneOnRemove", value: "always", ver: -1 }] }, base: host.head });
    const lost = signer.confirm(p.confirmToken);
    assert.equal(signer.outstanding().length, 1);
    assert.deepEqual(signer.reconcile(host).pending.map((x) => x.type), ["room.policy.changed"]);

    // The producer settles it at once with a fence, which is allowed while the statement is outstanding.
    const fence = signer.fence(host.head);
    const fr = host.submit(fence);
    assert.ok(fr.ok);
    const settled = AdminSigner.load({ dataDir: env.dataDir, kek: env.kek, roomId, now: env.now }).reconcile(host);
    assert.deepEqual(settled.notApplied.map((x) => x.type), ["room.policy.changed"]);
    assert.deepEqual(settled.applied.map((x) => x.type), ["producer.fence"]);

    // A host that held the statement back can no longer sequence it: the forward-base rule.
    const late = host.submit(lost);
    assert.ok(!late.ok);
    assert.equal(late.code, "stale_base");
    assert.equal(late.reason, "base_regressed");
    assert.equal(host.state.auth.policy.rotateLaneOnRemove, "compromise");
    host.close();
  } finally {
    env.t.cleanup();
  }
});

// ---------------------------------------------------------------------------------- 4.6 and 4.7

/** room-log-v2.md 4.6, copied from the spec table. */
const SPEC_4_6: Record<string, string[]> = {
  policy: ["room.policy.changed"],
  room: ["room.close.proposed", "room.closed"],
  authority_keys: ["admin.added", "admin.removed", "admin.key.rotated", "admin.key.revoked", "recovery.key.proposed", "recovery.key.rotated", "host.key.rotated", "host.key.revoked", "endpoint.rotated", "lane.offer.rotated"],
  membership: [
    "member.admitted",
    "member.removed",
    "member.left",
    "member.device.replaced",
    "device.added",
    "device.add.vetoed",
    "device.add.approved",
    "device.removed",
    "device.rekeyed",
    "device.rekey.vetoed",
    "device.rekey.approved",
    "device.conflict.resolved",
    "device.leaf.repair.requested",
  ],
  lane_display: ["lane.names.changed"],
  alert: ["grant.suspected_theft", "endpoint.evicted", "mls.stalled", "lane.degraded"],
};

test("4.6 (P-27): every security event is in the notice table, and each appears in the log with its producer", async () => {
  const fromTable: Record<string, string[]> = {};
  for (const [type, cat] of Object.entries(SECURITY_EVENTS)) (fromTable[cat!] ??= []).push(type);
  for (const k of Object.keys(SPEC_4_6)) assert.deepEqual([...fromTable[k]].sort(), [...SPEC_4_6[k]].sort(), k);
  for (const type of Object.keys(SECURITY_EVENTS)) assert.ok(type in STATEMENT_TYPES, type);

  const env = await setup();
  try {
    const { host, signer, roomId, recovery, genesis } = await newRoom(env);
    const hostKid = host.state.auth.hostKeys[0].kid;
    const b = newEd();
    const laneId = newId("lane");
    const bob = newId("member");
    const ref = inviteRef(newId("invite"));
    adminDo(host, signer, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 3600, ver: -1 }] });
    adminDo(host, signer, "admin.added", keyChange(roomId, { kind: "admin", id: signer.memberId }, null, b));
    adminDo(host, signer, "lane.created", { laneId, owner: signer.memberId, offer: { serverId: newServerId("laneEndpoint"), dh: newX(), relay: RELAY }, visibility: "room" });
    adminDo(host, signer, "lane.offer.rotated", { laneId, offer: { serverId: newServerId("laneEndpoint"), dh: newX(), relay: RELAY }, ver: host.state.auth.versions[`laneOffer:${laneId}`] });
    adminDo(host, signer, "endpoint.rotated", { serverId: newServerId("roomEndpoint"), dh: newX(), relay: RELAY, ver: -1 });
    adminDo(host, signer, "invite.created", { inviteRef: ref, role: "watch", lanes: [], exp: Math.floor(T0 / 1000) + 3600 });
    const bobDev = { deviceId: newId("device"), kind: "person" as const, sig: newEd().pub, dh: newX().pub };
    adminDo(host, signer, "member.admitted", { member: { memberId: bob, role: "watch", lanes: [], devices: [bobDev] }, confirmation: { method: "sas6", inviteRef: ref, transcript: b64u(randomBytes(32)) } });
    adminDo(host, signer, "device.removed", { memberId: bob, deviceId: bobDev.deviceId, reason: "lost" });
    adminDo(host, signer, "member.removed", { memberId: bob, reason: "admin" });

    // Host-produced events (P-27): alerts and the invite burn are log entries signed by the host key.
    host.emit("lane.degraded", { laneId, reason: "endpoint_failing" });
    host.emit("endpoint.evicted", { serverId: host.state.auth.endpoint.serverId, count: 3, windowS: 600 });
    host.emit("mls.stalled", { epoch: 0, sinceMs: 60_000 });
    // Spec gap (reported, not fixed here): "stmt:grant.suspected_theft" is outside the context alphabet
    // ^[a-z0-9.:-]{1,64}$ of signatures-and-encoding 3.1, so no key can sign this statement type yet.
    assert.throws(() => host.emit("grant.suspected_theft", { memberId: signer.memberId, deviceId: newId("device"), laneId, gid: newId("grant"), reportedBy: "endpoint" }), /bad statement type/);
    host.emit("invite.burned", { inviteRef: ref, reason: "attempts" });
    assert.throws(() => host.emit("room.closed" as never, { proposal: null } as never), TypeError);

    // The recovery key, used offline from its printed code, rotates itself; another admin is removed.
    const rPriv = ed25519PrivateKeyFromSeed(decodeRecoveryCode(recovery!.code));
    const r2 = newEd();
    assert.ok(host.submit(signAs(host, rPriv, "recovery", genesis.body.recovery!.kid, "recovery.key.rotated", { ...keyChange(roomId, { kind: "recovery", id: "recovery" }, genesis.body.recovery!.kid, r2), proposal: null })).ok);
    adminDo(host, signer, "admin.removed", { kid: b.kid });
    adminDo(host, signer, "room.close.proposed", { exp: Math.floor(env.now() / 1000) + 2 * 86400 });
    // The new recovery key closes the room.
    assert.ok(host.submit(signAs(host, r2.priv, "recovery", r2.kid, "room.closed", { proposal: null })).ok);

    const notices = host.securityNotices();
    const seen = new Map(notices.map((n) => [n.type, n.producer]));
    const expected: [StatementType, string][] = [
      ["member.admitted", "admin"],
      ["room.policy.changed", "admin"],
      ["admin.added", "admin"],
      ["lane.offer.rotated", "admin"],
      ["endpoint.rotated", "admin"],
      ["device.removed", "admin"],
      ["member.removed", "admin"],
      ["lane.degraded", "host"],
      ["endpoint.evicted", "host"],
      ["mls.stalled", "host"],
      ["recovery.key.rotated", "recovery"],
      ["admin.removed", "admin"],
      ["room.close.proposed", "admin"],
      ["room.closed", "recovery"],
    ];
    for (const [type, kind] of expected) assert.equal(seen.get(type)?.kind, kind, type);
    for (const n of notices) {
      assert.ok((STATEMENT_TYPES[n.type].producers as readonly string[]).includes(n.producer.kind), `${n.type} by ${n.producer.kind}`);
      if (n.producer.kind === "host") assert.equal(n.producer.kid, hostKid);
      if (n.producer.kind === "admin" && n.type !== "member.admitted") assert.ok([signer.kid, b.kid].includes(n.producer.kid));
    }
    // Not notices: invite.created, lane.created, invite.burned are logged but not shown as 4.6 notices.
    assert.ok(!seen.has("invite.created") && !seen.has("invite.burned") && !seen.has("lane.created"));
    assert.ok(host.entries().some((r) => r.signed.entry.type === "invite.burned"));
    assert.deepEqual(host.uncertifiedAlerts(), []);
    assert.ok(HOST_STATEMENT_TYPES.includes("invite.burned") && !HOST_STATEMENT_TYPES.includes("room.closed"));
    // After room.closed nothing more is sequenced.
    host.submit(signer.fence(host.head));
    const after = host.submit(signer.outstanding()[0].statement);
    assert.ok(!after.ok && after.reason === "room_closed");

    // The notices survive a reload (re-fold of the stored log).
    host.close();
    const again = await reopen(env, roomId);
    assert.deepEqual(again.securityNotices(), notices);
    again.close();
  } finally {
    env.t.cleanup();
  }
});

test("4.7: access.jsonl is owner-only, holds no secrets and bounds peer strings", async () => {
  const env = await setup();
  try {
    const { host } = await newRoom(env);
    const devKid = newEd().kid;
    host.access.record({ event: "session.opened", deviceKid: devKid });
    host.access.record({ event: "log.fetch", deviceKid: devKid, fromSeq: 0, toSeq: 0 });
    host.access.record({ event: "preauth_failed", reason: "bad\nline\u0000" + "x".repeat(200) });
    host.access.record({ event: "rate_limited", deviceKid: "not-a-kid", what: "log.fetch" });
    assert.equal(mode(host.access.path), 0o600);
    const lines = readFileSync(host.access.path, "utf8").trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(lines.map((l) => l.event), ["session.opened", "log.fetch", "preauth_failed", "rate_limited"]);
    assert.equal(lines[2].reason.length, 64);
    assert.ok(!lines[2].reason.includes("\n"));
    assert.equal(lines[3].deviceKid, "invalid");
    host.close();
  } finally {
    env.t.cleanup();
  }
});
