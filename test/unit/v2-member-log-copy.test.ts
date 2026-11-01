// Roadmap R2.1 (room-log-v2.md 6.1, 6.4 and 8.2): the member's verified log copy, maxSignedHead,
// receipts and stopping alerts survive a restart, so truncation and fork detection do too. A "restart"
// is a new RoomClient on the same sealed store. A host rollback is simulated by closing the host and
// restoring a copy of its data directory taken earlier (same keys, shorter log). In-process fake relay,
// fake keyring, temporary homes; no network beyond loopback.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmodSync, cpSync, mkdirSync, statSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { AdminSigner } from "../../server/admin/signer";
import { createRoom, type CreatedRoom } from "../../server/admin/genesis";
import { entryHash, isEquivocationProof, type SignedEntry } from "../../server/authority/entries";
import type { StatementType } from "../../server/authority/statements";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import { ACCESS_LOG_FILE, readHostKeys, RoomHost } from "../../server/host/room-host";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { LOG_SEGMENT_ENTRIES, memberLogDir, memberLogHeadPath, memberLogSegPath, SealedLogCopy } from "../../server/member/log-copy";
import { RoomClient } from "../../server/member/room-client";
import { generateNoiseKeyPair, type NoiseKeyPair } from "../../server/noise/handshake-state";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { CTX_LOG_ENTRY } from "../../server/proto/contexts";
import { newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, rawPublicKey } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { H, sign } from "../../server/proto/tbs";
import { startFakeRelay, until, type FakeRelay } from "./fake-relay";
import { tempDir } from "./helpers";

const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };
const FAST = { handshakeTimeoutMs: 400 };

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

interface Env {
  relay: FakeRelay;
  room: CreatedRoom;
  dataDir: string;
  /** The member daemon's data directory (separate, so a host rollback does not touch it). */
  memberDir: string;
  root: string;
  kek: Kek;
  endpoint: RoomEndpoint;
  clients: RoomClient[];
  device: { memberId: string; deviceId: string; dh: NoiseKeyPair };
  cleanup(): Promise<void>;
}

async function setup(): Promise<Env> {
  const t = tempDir();
  const home = join(t.dir, "home");
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const memberDir = join(t.dir, "member-home", "plugin-data", "rooms");
  mkdirSync(memberDir, { recursive: true, mode: 0o700 });
  const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
  if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
  const relay = await startFakeRelay();
  const room = await createRoom({ dataDir, kek: s.kek, relay: { host: "127.0.0.1", port: relay.port, tls: true }, recovery: "skip", lock: NO_TIMER });
  const env: Env = {
    relay,
    room,
    dataDir,
    memberDir,
    root: t.dir,
    kek: s.kek,
    endpoint: null as unknown as RoomEndpoint,
    clients: [],
    device: { memberId: newId("member"), deviceId: newId("device"), dh: generateNoiseKeyPair() },
    async cleanup() {
      for (const c of env.clients) c.close();
      env.endpoint.stop();
      env.room.host.close();
      await relay.close();
      t.cleanup();
    },
  };
  await startEndpoint(env);
  const sigPub = rawPublicKey(ed25519PrivateKeyFromSeed(randomBytes(32)));
  adminDo(env, "member.admitted", {
    member: { memberId: env.device.memberId, role: "watch", lanes: [], devices: [{ deviceId: env.device.deviceId, kind: "person", sig: b64u(sigPub), dh: b64u(env.device.dh.publicKey) }] },
    confirmation: { method: "sas6", inviteRef: b64u(H("test-invite", randomBytes(8))), transcript: b64u(H("test-transcript", randomBytes(8))) },
  });
  return env;
}

async function startEndpoint(env: Env): Promise<void> {
  env.endpoint = new RoomEndpoint({ host: env.room.host, endpointKey: endpointKeyFromHost(env.dataDir, env.kek, env.room.host), relay: { endpoint: env.relay.endpoint, useTls: false }, timings: FAST });
  env.endpoint.start();
  await until("endpoint online", () => env.endpoint.status === "online");
}

function stopHost(env: Env): void {
  for (const c of env.clients) c.close();
  env.endpoint.stop();
  env.room.host.close();
}

/** Reopens the host from its data directory (after a restore, that is the rolled-back log). */
async function reopenHost(env: Env): Promise<void> {
  env.room.host = await RoomHost.open({ dataDir: env.dataDir, kek: env.kek, roomId: env.room.roomId, lock: NO_TIMER });
  env.room.signer = AdminSigner.load({ dataDir: env.dataDir, kek: env.kek, roomId: env.room.roomId });
  await startEndpoint(env);
}

function adminDo(env: Env, type: StatementType, data: unknown): number {
  const p = env.room.signer.prepare({ type, data: data as never, base: env.room.host.head });
  const res = env.endpoint.submit(env.room.signer.confirm(p.confirmToken));
  assert.ok(res.ok, res.ok ? "" : `${type}: ${res.code} ${res.reason}`);
  env.room.signer.reconcile(env.room.host);
  return res.receipt.entry.seq;
}

function setGrantTtl(env: Env, value: number): number {
  const ver = env.room.host.state.auth.versions["policy:grantTtl"] ?? -1;
  return adminDo(env, "room.policy.changed", { changes: [{ setting: "grantTtl", value, ver }] });
}

function store(env: Env): SealedLogCopy {
  return new SealedLogCopy({ dataDir: env.memberDir, kek: env.kek, roomId: env.room.roomId, genesisHash: env.room.genesisHash });
}

/** A member daemon "start": a new client over the same sealed copy. */
function member(env: Env, extra: Partial<ConstructorParameters<typeof RoomClient>[0]> = {}): RoomClient {
  const c = new RoomClient({ genesis: env.room.genesis, device: env.device.dh, relay: { endpoint: env.relay.endpoint, useTls: false }, timings: FAST, store: store(env), ...extra });
  env.clients.push(c);
  return c;
}

function hostSigner(env: Env): (entry: SignedEntry["entry"]) => SignedEntry {
  const keys = readHostKeys(env.dataDir, env.kek, env.room.roomId)!;
  const priv = ed25519PrivateKeyFromSeed(b64uDecode(keys.hostKeys[0].seed, 32));
  return (entry) => ({ entry, hash: entryHash(entry), hsig: b64u(sign(priv, CTX_LOG_ENTRY, rjcs(entry))) });
}

function hostKeyAt(env: Env): (kid: string) => Uint8Array | null {
  const keys = readHostKeys(env.dataDir, env.kek, env.room.roomId)!;
  const pub = rawPublicKey(ed25519PrivateKeyFromSeed(b64uDecode(keys.hostKeys[0].seed, 32)));
  return (kid) => (kid === keys.hostKeys[0].kid ? pub : null);
}

/** Room access log events of `log.fetch` with their fromSeq. */
function fetchesFrom(env: Env): number[] {
  const dir = join(env.dataDir, "host", env.room.roomId);
  return readFileSync(join(dir, ACCESS_LOG_FILE), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l))
    .filter((e) => e.event === "log.fetch")
    .map((e) => e.fromSeq);
}

function hostEntryHash(env: Env, seq: number): string {
  return env.room.host.entries(seq, seq)[0]?.signed.hash ?? "";
}

/** cpSync keeps contents but not modes; the host refuses data that is not owner-only. */
function copyTree(from: string, to: string, _o?: unknown): void {
  cpSync(from, to, { recursive: true });
  const fix = (src: string, dst: string) => {
    chmodSync(dst, statSync(src).mode & 0o777);
    if (statSync(src).isDirectory()) for (const n of readdirSync(src)) fix(join(src, n), join(dst, n));
  };
  fix(from, to);
}

// -------------------------------------------------------------------------------------------------

test("R2.1: the verified copy is re-folded at start (across segments) and log.fetch resumes from its head", async () => {
  const env = await setup();
  try {
    for (let i = 0; i < LOG_SEGMENT_ENTRIES + 6; i++) setGrantTtl(env, 3600 + i);
    const c1 = member(env);
    assert.equal(c1.head.seq, -1, "nothing stored yet");
    await c1.connect();
    assert.deepEqual(c1.head, env.room.host.head);
    c1.close();
    assert.ok(readdirSync(memberLogDir(env.memberDir, env.room.roomId)).filter((n) => n.startsWith("seg-")).length >= 2, "two segments");
    const fileText = readFileSync(memberLogSegPath(env.memberDir, env.room.roomId, 0), "utf8");
    assert.ok(!fileText.includes(env.room.host.entries(0, 0)[0].signed.hash) && !fileText.includes("hsig"), "segments are sealed");

    // Restart: the copy is there before any network access, with the same fold state.
    const c2 = member(env);
    assert.deepEqual(c2.head, env.room.host.head);
    assert.equal(c2.state.auth.policy.grantTtl, 3600 + LOG_SEGMENT_ENTRIES + 5);
    assert.deepEqual(c2.alerts, []);
    const seen: number[] = [];
    const c3 = member(env, { onIngest: (s) => seen.push(s.entry.seq) });
    const extra = setGrantTtl(env, 7200);
    await c3.connect();
    assert.deepEqual(c3.head, env.room.host.head);
    assert.deepEqual(c3.alerts, []);
    assert.deepEqual(seen, Array.from({ length: extra + 1 }, (_, i) => i), "restored entries are handed to onIngest once, then the new one");
    assert.equal(fetchesFrom(env).at(-1), extra - 1, "fetch overlaps the stored head by one entry");
  } finally {
    await env.cleanup();
  }
});

test("R2.1: a host head below the stored maxSignedHead after a restart is truncation; the shorter log is not accepted", async () => {
  const env = await setup();
  try {
    stopHost(env);
    const snap = join(env.root, "snap");
    copyTree(env.dataDir, snap, { recursive: true });
    await reopenHost(env);
    setGrantTtl(env, 4000);
    const top = setGrantTtl(env, 5000);
    const c1 = member(env);
    await c1.connect();
    assert.equal(c1.head.seq, top);
    const max = c1.maxSignedHead!;
    c1.close();

    // The host is rolled back to the earlier copy of its data (shorter log, same keys).
    stopHost(env);
    rmSync(env.dataDir, { recursive: true, force: true });
    copyTree(snap, env.dataDir, { recursive: true });
    await reopenHost(env);
    assert.ok(env.room.host.head.seq < top);

    const c2 = member(env);
    await c2.connect();
    const tr = c2.alerts.find((a) => a.type === "truncation");
    assert.ok(tr, `truncation raised: ${JSON.stringify(c2.alerts.map((a) => a.type))}`);
    assert.equal(tr.seq, top);
    assert.equal(tr.proof[0].hash, max.hash, "maxSignedHead is the proof");
    assert.equal(c2.sendingStopped, true);
    assert.equal(c2.head.seq, top, "the own head does not go back to the host's");
    assert.equal(c2.maxSignedHead!.hash, max.hash);
    c2.close();

    // Another restart: the alert and the stop survive, before any network access.
    const c3 = member(env);
    assert.equal(c3.sendingStopped, true);
    assert.ok(c3.alerts.some((a) => a.type === "truncation" && a.restored));
    await c3.connect();
    assert.equal(c3.alerts.filter((a) => a.type === "truncation" && a.seq === top).length, 1, "not raised twice");
  } finally {
    await env.cleanup();
  }
});

test("R2.1: a host that re-signs a different history after the member restarted is a fork with an equivocation proof", async () => {
  const env = await setup();
  try {
    stopHost(env);
    const snap = join(env.root, "snap");
    copyTree(env.dataDir, snap, { recursive: true });
    await reopenHost(env);
    setGrantTtl(env, 4000);
    const top = setGrantTtl(env, 5000);
    const c1 = member(env);
    await c1.connect();
    const mine = c1.entry(top)!;
    c1.close();

    // Roll back, then sign other entries at the same seqs: the host's head is not below ours.
    stopHost(env);
    rmSync(env.dataDir, { recursive: true, force: true });
    copyTree(snap, env.dataDir, { recursive: true });
    await reopenHost(env);
    setGrantTtl(env, 4100);
    setGrantTtl(env, 5100);
    const other = setGrantTtl(env, 6100);
    assert.ok(other > top);
    assert.notEqual(hostEntryHash(env, top), mine.hash);

    const c2 = member(env);
    await c2.connect();
    const fork = c2.alerts.find((a) => a.type === "fork");
    assert.ok(fork, `fork raised: ${JSON.stringify(c2.alerts.map((a) => a.type))}`);
    assert.ok(isEquivocationProof(fork.proof[0], fork.proof[1], hostKeyAt(env)), "two host-signed entries at one seq");
    assert.equal(c2.sendingStopped, true);
    assert.ok(c2.head.seq <= top, "the other history is not folded in");
  } finally {
    await env.cleanup();
  }
});

test("R2.1: a damaged local copy is reported, dropped and re-verified against the stored maxSignedHead, not taken from the host", async () => {
  const env = await setup();
  try {
    stopHost(env);
    const snap = join(env.root, "snap");
    copyTree(env.dataDir, snap, { recursive: true });
    await reopenHost(env);
    for (let i = 0; i < 3; i++) setGrantTtl(env, 4000 + i);
    const c1 = member(env);
    await c1.connect();
    const top = c1.head.seq;
    c1.close();

    // Damage the segment (one character of the ciphertext).
    const seg = memberLogSegPath(env.memberDir, env.room.roomId, 0);
    const text = readFileSync(seg, "utf8");
    const at = text.indexOf('"ct":"') + 10;
    writeFileSync(seg, text.slice(0, at) + (text[at] === "A" ? "B" : "A") + text.slice(at + 1));

    const c2 = member(env);
    assert.equal(c2.head.seq, -1, "the damaged chain is not used");
    assert.ok(c2.alerts.some((a) => a.type === "local_copy_corrupt" && /segment_unreadable:0/.test(a.reason ?? "")));
    assert.equal(c2.maxSignedHead!.entry.seq, top, "the sealed head record still pins maxSignedHead");
    assert.ok(readdirSync(memberLogDir(env.memberDir, env.room.roomId)).some((n) => n.startsWith("corrupt-")), "damaged files moved aside");

    // A rolled-back host cannot use the damage to pass a shorter log.
    stopHost(env);
    const keep = join(env.root, "keep");
    copyTree(env.dataDir, keep, { recursive: true });
    rmSync(env.dataDir, { recursive: true, force: true });
    copyTree(snap, env.dataDir, { recursive: true });
    await reopenHost(env);
    await c2.connect();
    assert.ok(c2.alerts.some((a) => a.type === "truncation" && a.seq === top), "truncation despite the damaged copy");
    assert.equal(c2.sendingStopped, true);
    c2.close();

    // The honest host again: a fresh member copy is rebuilt and checked against maxSignedHead.
    stopHost(env);
    rmSync(env.dataDir, { recursive: true, force: true });
    copyTree(keep, env.dataDir, { recursive: true });
    await reopenHost(env);
    rmSync(memberLogDir(env.memberDir, env.room.roomId), { recursive: true, force: true });
    const c1b = member(env);
    await c1b.connect();
    c1b.close();
    const seg2 = memberLogSegPath(env.memberDir, env.room.roomId, 0);
    writeFileSync(seg2, "{}");
    const c3 = member(env);
    assert.ok(c3.alerts.some((a) => a.type === "local_copy_corrupt"));
    await c3.connect();
    assert.deepEqual(c3.head, env.room.host.head);
    assert.deepEqual(c3.alerts.map((a) => a.type), ["local_copy_corrupt"], "honest host: only the local notice");
    c3.close();
    const c4 = member(env);
    assert.deepEqual(c4.head, env.room.host.head, "the copy was rewritten");
    assert.deepEqual(c4.alerts, []);

    // A damaged head record with good segments: the segments' tail stands in for maxSignedHead.
    writeFileSync(memberLogHeadPath(env.memberDir, env.room.roomId), "not sealed");
    const c5 = member(env);
    assert.deepEqual(c5.head, env.room.host.head);
    assert.ok(c5.alerts.some((a) => a.type === "local_copy_corrupt" && a.reason === "head_unreadable"));
  } finally {
    await env.cleanup();
  }
});

test("R2.1: a receipt for an own statement survives a restart; a host that then does not serve it is truncation", async () => {
  const env = await setup();
  try {
    const c1 = member(env);
    await c1.connect();
    const sign1 = hostSigner(env);
    const head = env.room.host.headEntry!;
    // A host-signed receipt the host later drops (it answered stmt.submit, then lost the entry).
    const dropped = sign1({ ...head.entry, seq: head.entry.seq + 1, prev: head.hash, bodyHash: b64u(randomBytes(32)) });
    c1.noteReceipt(dropped);
    assert.equal(c1.alerts.length, 0);
    c1.close();

    const c2 = member(env);
    await c2.connect();
    const tr = c2.alerts.find((a) => a.type === "truncation");
    assert.ok(tr, "truncation raised");
    assert.equal(tr.reason, "receipt:own_statement");
    assert.equal(tr.proof[0].hash, dropped.hash);
  } finally {
    await env.cleanup();
  }
});
