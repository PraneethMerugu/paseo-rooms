// Identity v2 milestone I-6: key changes, revocation and re-fold, lineages and closure, device
// holds. Read directly from docs/specs/identity-v2/vectors/vectors.json (log.refold, log.closure,
// deviceLink.chain(.cases), deviceRekey.chain(.cases), deviceRekey.vetoed,
// deviceRekey.soleDeviceChangeAdmin, the recovery-key statements), so the tests and the spec cannot
// drift. Further cases build small chains signed with the vector's test-only seeds.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { bodyHash, entryHash, type LogEntry } from "../../server/authority/entries";
import { foldLog, FoldError, RoomLogFold, type FoldInputEntry, type FoldReason } from "../../server/authority/fold";
import { verifyGenesis } from "../../server/authority/genesis";
import { HOLD_MS, SOLE_HOLD_MS } from "../../server/authority/holds";
import { lineageCount } from "../../server/authority/lineage";
import { rosterHash } from "../../server/authority/roster";
import { parseSignedStatement, verifyNewKeySig, type KeyChange, type SignedStatement } from "../../server/authority/statements";
import { b64u } from "../../server/proto/b64u";
import { CTX_GENESIS, CTX_KEY_CHANGE_NEW, CTX_LOG_ENTRY, stmtContext } from "../../server/proto/contexts";
import { ed25519PrivateKeyFromSeed } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { sign } from "../../server/proto/tbs";

const VECTORS_PATH = join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json");
const V = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
const L = V.log;
const GENESIS = V.genesis.signed;
const ROOM = V.genesis.roomId as string;
type VKey = { alg: string; seedHex?: string; pub: string; kid: string };
const KEYS = V.keys as Record<string, VKey>;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const HOUR = 3600_000;

type VEntry = { entry: LogEntry; hash: string; hsig: string; statement: SignedStatement };
const input = (e: VEntry): FoldInputEntry => ({ signed: { entry: e.entry, hash: e.hash, hsig: e.hsig }, body: rjcs(e.statement) });
const mainPrefix = (): FoldInputEntry[] => L.entries.slice(0, 4).map((signed: unknown, i: number) => ({ signed, body: rjcs(L.bodies[i].statement) }));

function expectFold(fn: () => void, reason: FoldReason): void {
  assert.throws(fn, (err: unknown) => err instanceof FoldError && err.reason === reason, `expected ${reason}`);
}
/** Folds the prefix, then expects `last` to be rejected with `reason` at `seq` and the fold to stay put. */
function expectCase(prefix: FoldInputEntry[], last: VEntry, reason: string, seq = 6): void {
  assert.equal(bodyHash(rjcs(last.statement)), last.entry.bodyHash);
  const res = foldLog(GENESIS, [...prefix, input(last)]);
  assert.equal(res.error?.reason, reason, `expected ${reason}, got ${res.error?.message}`);
  assert.equal(res.error?.seq, seq);
  assert.equal(res.fold.head.seq, seq - 1);
}

// ---- log.refold ----

test("log.refold: the recovery key revokes adminC; the ghost leaves; the revocation is the roster position", () => {
  const r = L.refold;
  const before = foldLog(GENESIS, [...mainPrefix(), ...r.entries.slice(0, 2).map(input)]);
  assert.equal(before.error, null);
  const ghost = r.entries[1].statement.body.data.member;
  assert.ok(before.fold.state.members[ghost.memberId], "ghost admitted by adminC");
  assert.deepEqual({ seq: before.fold.roster().seq, hash: before.fold.rosterHash() }, r.rosterBefore);
  assert.equal(lineageCount(before.fold.state.auth), 1, "adminC shares adminA's root");

  const { fold, error } = foldLog(GENESIS, [...mainPrefix(), ...r.entries.map(input)]);
  assert.equal(error, null);
  assert.deepEqual({ seq: fold.roster().seq, hash: fold.rosterHash() }, r.rosterAfter);
  assert.equal(fold.state.members[ghost.memberId], undefined);
  assert.equal(fold.state.marks[5], "suspect");
  const st = fold.state;
  assert.ok(st.auth.adminKeyDenylist[KEYS.adminC.kid] && st.auth.retiredKeys[KEYS.adminC.pub]);
  assert.deepEqual(st.auth.revocations, [{ kid: KEYS.adminC.kid, fromSeq: 5, seq: 6 }]);
  // Ids and keys of the ghost never return.
  assert.ok(st.used.members[ghost.memberId] && st.used.devices[ghost.devices[0].deviceId]);
  assert.ok(st.deviceDenylist[KEYS.ghostSig.pub] && st.auth.retiredKeys[KEYS.ghostDh.pub]);
  // adminC can sign nothing more.
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminC")), "unknown_producer");
});

test("log.refold: a revocation reaching back before the revoker's authority start is rejected", () => {
  const c = L.refold.rejectRevocationBeforeStart;
  const prefix = [...mainPrefix(), input(L.refold.entries[0])];
  expectCase(prefix, { ...c.entry, statement: c.statement }, c.expect, 5);
});

// ---- log.closure ----

test("log.closure: an independent admin confirms 25 h after the proposal; nothing is accepted after", () => {
  const c = L.closure;
  const { fold, error } = foldLog(GENESIS, [...mainPrefix(), ...c.entries.map(input)]);
  assert.equal(error, null);
  assert.equal(fold.state.auth.closed, true);
  assert.equal(fold.state.auth.policy.closeDelay, c.closeDelayS);
  assert.equal(lineageCount(fold.state.auth), 2, "adminB, added by R, is its own root");
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminA")), "room_closed");
});

test("log.closure: too early, same lineage and a confirmer added after the proposal are rejected", () => {
  assert.equal(L.closure.cases.length, 3);
  for (const c of L.closure.cases) expectCase([...mainPrefix(), ...c.chain.map(input)], { ...c.entry, statement: c.statement }, c.expect);
});

// ---- deviceLink ----

const dlPrefix = () => [...mainPrefix(), ...V.deviceLink.chain.entries.slice(0, 2).map(input)];

test("deviceLink.chain: a sole device's add is approved after 72 h and the phone joins", () => {
  const ch = V.deviceLink.chain;
  assert.equal(ch.holdMs, SOLE_HOLD_MS);
  const { fold, error } = foldLog(GENESIS, [...mainPrefix(), ...ch.entries.map(input)]);
  assert.equal(error, null);
  const sam = ch.entries[1].statement.body.data.memberId;
  assert.equal(fold.state.members[sam].devices.length, 2);
  assert.equal(fold.roster().seq, 6);
  const p = fold.state.pending[V.deviceLink.deviceAddedBodyHash];
  assert.equal(p.status, "approved");
  assert.ok(p.sole && !p.young);
  // The same link cannot add a second device.
  const again = clone(ch.entries[1].statement.body.data);
  expectFold(() => add(fold, build(fold, "device.added", again, "devSig", { hts: ch.entries[2].entry.hts + HOUR })), "link_used");
});

test("deviceLink.chain.cases: each is rejected with the vector's reason", () => {
  assert.equal(V.deviceLink.chain.cases.length, 5);
  for (const c of V.deviceLink.chain.cases) {
    const seq = c.entry.entry.seq;
    expectCase([...dlPrefix(), ...c.chain.map(input)], { ...c.entry, statement: c.statement }, c.expect, seq);
  }
});

test("deviceLink: an admin may remove a last device; the member stays with none and the add is cancelled", () => {
  const removed = V.deviceLink.chain.cases.find((c: { name: string }) => c.name === "approvalAfterRequesterRemoved");
  const { fold, error } = foldLog(GENESIS, [...dlPrefix(), ...removed.chain.map(input)]);
  assert.equal(error, null);
  const sam = removed.chain[0].statement.body.data.memberId;
  assert.equal(fold.state.members[sam].devices.length, 0);
  assert.equal(fold.roster().seq, 6);
  assert.equal(fold.state.pending[V.deviceLink.deviceAddedBodyHash].status, "cancelled");
});

test("deviceLink: a veto opens a conflict, cleared only by device.conflict.resolved naming the veto's version", () => {
  const veto = V.deviceLink.chain.cases.find((c: { name: string }) => c.name === "approvalAfterVeto");
  const res = foldLog(GENESIS, [...dlPrefix(), ...veto.chain.map(input)]);
  assert.equal(res.error, null);
  const fold = res.fold;
  const sam = veto.chain[0].statement.body.data.memberId;
  assert.equal(fold.state.conflicts[sam], 6);
  // The vector statement names ver 6 and base seq 6; sequence it at seq 7.
  const stmt = V.statements.deviceConflictResolved as SignedStatement;
  assert.deepEqual(stmt.body.base, fold.head);
  const stale = build(fold, "device.conflict.resolved", { memberId: sam, ver: 5 }, "adminA");
  expectFold(() => add(fold, stale), "stale_version");
  fold.append(hostEntry(fold, stmt, fold.state.pending[V.deviceLink.deviceAddedBodyHash].hts + 2 * HOUR), rjcs(stmt));
  assert.equal(fold.state.conflicts[sam], undefined);
  expectFold(() => add(fold, build(fold, "device.conflict.resolved", { memberId: sam, ver: 7 }, "adminA")), "no_conflict");
});

// ---- deviceRekey ----

test("deviceRekey.chain: a sole device's rekey is approved after 72 h; old keys denylisted", () => {
  const ch = V.deviceRekey.chain;
  assert.equal(ch.holdMs, SOLE_HOLD_MS);
  const { fold, error } = foldLog(GENESIS, [...mainPrefix(), ...ch.entries.map(input)]);
  assert.equal(error, null);
  const sam = ch.entries[1].statement.body.data.memberId;
  const dev = fold.state.members[sam].devices[0];
  assert.deepEqual({ sig: dev.sig, dh: dev.dh }, { sig: KEYS.devSig2.pub, dh: KEYS.devDh2.pub });
  assert.ok(fold.state.deviceDenylist[KEYS.devSig.pub] && fold.state.deviceDenylist[KEYS.devDh.pub]);
  assert.equal(fold.roster().seq, 5);
  assert.equal(fold.state.pending[V.deviceRekey.deviceRekeyedBodyHash].status, "approved");
  // The old signing key can no longer sign.
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "devSig")), "unknown_producer");
  add(fold, build(fold, "producer.fence", {}, "devSig2"));
});

test("deviceRekey.chain.cases, deviceRekey.vetoed, deviceRekey.soleDeviceChangeAdmin", () => {
  for (const c of V.deviceRekey.chain.cases) expectCase([...mainPrefix(), ...c.chain.map(input)], { ...c.entry, statement: c.statement }, c.expect, 5);
  const v = V.deviceRekey.vetoed;
  assert.equal(v.expect, "vetoed");
  const vetoed = foldLog(GENESIS, [...mainPrefix(), ...v.chain.map(input)]);
  assert.equal(vetoed.error, null);
  const sam = v.chain[1].statement.body.data.memberId;
  assert.equal(vetoed.fold.state.conflicts[sam], 5);
  assert.equal(vetoed.fold.state.members[sam].devices[0].sig, KEYS.devSig.pub, "a veto keeps the old keys");
  expectCase([...mainPrefix(), ...v.chain.map(input)], { ...v.entry, statement: v.statement }, v.expect);

  const sa = V.deviceRekey.soleDeviceChangeAdmin;
  const ok = foldLog(GENESIS, [...mainPrefix(), ...sa.entries.map(input)]);
  assert.equal(ok.error, null);
  assert.equal(ok.fold.state.auth.policy.soleDeviceChange, "admin");
  assert.equal(ok.fold.state.members[sam].devices[0].sig, KEYS.devSig2.pub);
  assert.equal(ok.fold.roster().seq, 6);
  assert.equal(sa.cases.length, 1);
  for (const c of sa.cases) expectCase([...mainPrefix(), ...c.chain.map(input)], { ...c.entry, statement: c.statement }, c.expect);
});

// ---- recovery-key statements (format only: the vector genesis already has a recovery key) ----

test("statements: first recovery key from null with a proposal, format only; folded here it is refused", () => {
  const p = V.statements.recoveryKeyProposed as SignedStatement;
  const r = V.statements.recoveryKeyRotated as SignedStatement;
  parseSignedStatement(p);
  parseSignedStatement(r);
  const pd = p.body.data as { change: KeyChange; newKeySig: string };
  const rd = r.body.data as { change: KeyChange; newKeySig: string; proposal: string };
  assert.equal(pd.change.old, null);
  assert.deepEqual(rd.change, pd.change);
  assert.equal(rd.proposal, bodyHash(rjcs(p)));
  assert.ok(verifyNewKeySig(rd.change, rd.newKeySig));
  assert.notEqual(p.body.producer.kid, r.body.producer.kid);
  const fold = base4();
  expectFold(() => add(fold, build(fold, "recovery.key.proposed", clone(pd), "adminA")), "recovery_exists");
});

// ---- builders for small chains ----

const seedKey = (name: string) => ed25519PrivateKeyFromSeed(Buffer.from(KEYS[name].seedHex!, "hex"));
const KIND: Record<string, "admin" | "device" | "host" | "recovery"> = {
  adminA: "admin",
  adminA2: "admin",
  adminB: "admin",
  adminC: "admin",
  recovery: "recovery",
  recovery2: "recovery",
  host: "host",
  host2: "host",
  creatorDevSig: "device",
  devSig: "device",
  devSig2: "device",
  phoneSig: "device",
  ghostSig: "device",
};
type Built = { signed: { entry: LogEntry; hash: string; hsig: string }; body: Uint8Array; stmt: SignedStatement };
type Opts = { hts?: number; host?: string; room?: string };

function entryFor(fold: RoomLogFold, stmt: SignedStatement, opts: Opts): Built {
  const head = fold.head;
  const body = rjcs(stmt);
  const host = opts.host ?? "host";
  const entry: LogEntry = {
    v: 2,
    typ: "log-entry",
    roomId: opts.room ?? ROOM,
    seq: head.seq + 1,
    prev: head.hash,
    hts: opts.hts ?? 1793300000100 + (head.seq + 1) * 1000,
    epoch: 0,
    cls: "stmt",
    type: stmt.body.type,
    bodyHash: bodyHash(body),
    hostKid: KEYS[host].kid,
  };
  return { signed: { entry, hash: entryHash(entry), hsig: b64u(sign(seedKey(host), CTX_LOG_ENTRY, rjcs(entry))) }, body, stmt };
}
function build(fold: RoomLogFold, type: string, data: unknown, signer: string, opts: Opts = {}): Built {
  const head = fold.head;
  const body = { v: 2, typ: "stmt", type, roomId: opts.room ?? ROOM, producer: { kind: KIND[signer], kid: KEYS[signer].kid }, base: head, ts: 1793300000000 + head.seq, data };
  const stmt = { body, sig: b64u(sign(seedKey(signer), stmtContext(type), rjcs(body))) } as SignedStatement;
  return entryFor(fold, stmt, opts);
}
const hostEntry = (fold: RoomLogFold, stmt: SignedStatement, hts: number) => entryFor(fold, stmt, { hts }).signed;
const add = (fold: RoomLogFold, b: Built) => fold.append(b.signed, b.body);

/** KeyChange with `newKeySig` by the new signing key. */
function keyChange(subject: KeyChange["subject"], old: string | null, sigName: string, dhName: string | null, room = ROOM) {
  const change = { v: 2, typ: "key-change", roomId: room, subject, old, newSig: KEYS[sigName].pub, newDh: dhName ? KEYS[dhName].pub : null } as KeyChange;
  return { change, newKeySig: b64u(sign(seedKey(sigName), CTX_KEY_CHANGE_NEW, rjcs(change))) };
}

const CREATOR = L.bodies[0].statement.body.data.member.memberId as string;
const BOB = L.bodies[2].statement.body.data.member.memberId as string;
const BOB_DEV = L.bodies[2].statement.body.data.member.devices[0].deviceId as string;
const ADMITTED_HTS = L.entries[2].entry.hts as number;
const ref = (label: string) => b64u(createHash("sha256").update(label).digest());
const devId = (byte: string) => "dev_" + byte.repeat(16);
const memId = (byte: string) => "mem_" + byte.repeat(16);

function base4(): RoomLogFold {
  const fold = RoomLogFold.fromGenesis(GENESIS);
  for (const x of mainPrefix()) fold.append(x.signed, x.body);
  return fold;
}

/** Device link plus device.added by `signer` (a device of `memberId`) for a new device with the given keys. */
function linkAndAdd(fold: RoomLogFold, memberId: string, signer: string, signerDev: string, newDev: string, sigName: string, dhName: string, hts: number) {
  const linkRef = ref(`link/${newDev}/${hts}`);
  add(fold, build(fold, "device.link.created", { memberId, linkRef, exp: Math.floor(hts / 1000) + 600 }, signer, { hts }));
  const kc = keyChange({ kind: "device", id: newDev }, null, sigName, dhName);
  const device = { deviceId: newDev, kind: "person", sig: KEYS[sigName].pub, dh: KEYS[dhName].pub };
  const b = build(fold, "device.added", { memberId, device, ...kc, addedBy: signerDev, confirmation: { method: "sas6", linkRef, transcript: ref("t") } }, signer, { hts: hts + 1000 });
  add(fold, b);
  return b.signed.entry.bodyHash;
}

// ---- key changes ----

test("admin.key.rotated: the old key signs its last entry; the new key keeps lineage and start; the old never returns", () => {
  const fold = base4();
  const stmt = V.statements.adminKeyRotated as SignedStatement;
  fold.append(hostEntry(fold, stmt, 1793300000000), rjcs(stmt));
  const a = fold.state.auth;
  const [old, neu] = a.admins;
  assert.deepEqual([old.toSeq, old.end, neu.fromSeq, neu.root, neu.since], [4, "rotated", 5, KEYS.adminA.kid, 0]);
  assert.ok(a.adminKeyDenylist[KEYS.adminA.kid] && a.retiredKeys[KEYS.adminA.pub]);
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminA")), "unknown_producer");
  // The new key cannot re-add the old one.
  const back = keyChange({ kind: "admin", id: CREATOR }, null, "adminA", null);
  expectFold(() => add(fold, build(fold, "admin.added", back, "adminA2")), "key_reused");
  add(fold, build(fold, "producer.fence", {}, "adminA2"));
});

test("key changes: old must name the current key, the binding must verify, and keys must fit the subject", () => {
  const fold = base4();
  const stale = keyChange({ kind: "admin", id: CREATOR }, KEYS.adminB.kid, "adminA2", null);
  expectFold(() => add(fold, build(fold, "admin.key.rotated", stale, "adminA")), "stale_version");
  const badSig = keyChange({ kind: "admin", id: CREATOR }, KEYS.adminA.kid, "adminA2", null);
  badSig.newKeySig = keyChange({ kind: "admin", id: CREATOR }, KEYS.adminA.kid, "adminB", null).newKeySig;
  expectFold(() => add(fold, build(fold, "admin.key.rotated", badSig, "adminA")), "bad_new_key_sig");
  const withDh = keyChange({ kind: "admin", id: CREATOR }, KEYS.adminA.kid, "adminA2", "devDh2");
  expectFold(() => add(fold, build(fold, "admin.key.rotated", withDh, "adminA")), "bad_key_change");
  const notMember = keyChange({ kind: "admin", id: "recovery" }, null, "adminB", null);
  expectFold(() => add(fold, build(fold, "admin.added", notMember, "adminA")), "bad_key_change");
  // A key already used for another subject (the host key) is not certified as an admin key.
  const hostAsAdmin = keyChange({ kind: "admin", id: CREATOR }, null, "host", null);
  expectFold(() => add(fold, build(fold, "admin.added", hostAsAdmin, "adminA")), "key_reused");
  const otherRoom = keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null, "room_" + "00".repeat(16));
  expectFold(() => add(fold, build(fold, "admin.added", otherRoom, "adminA")), "bad_key_change");
});

test("host.key.rotated and host.key.revoked: position decides; the current key is rotated before it is revoked", () => {
  const fold = base4();
  const stmt = V.statements.hostKeyRotated as SignedStatement;
  fold.append(hostEntry(fold, stmt, 1793300000000), rjcs(stmt));
  const [h1, h2] = fold.state.auth.hostKeys;
  assert.deepEqual([h1.toSeq, h1.validTo, h2.fromSeq], [4, 1793326600, 5]);
  // No entry after the rotation may use the old key.
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminA")), "unknown_host_key");
  add(fold, build(fold, "producer.fence", {}, "adminA", { host: "host2" }));
  expectFold(() => add(fold, build(fold, "host.key.revoked", { kid: KEYS.host2.kid, fromSeq: 5 }, "adminA", { host: "host2" })), "host_key_current");
  expectFold(() => add(fold, build(fold, "host.key.revoked", { kid: KEYS.host.kid, fromSeq: 7 }, "adminA", { host: "host2" })), "revocation_out_of_bounds");
  add(fold, build(fold, "host.key.revoked", { kid: KEYS.host.kid, fromSeq: 2 }, "adminA", { host: "host2" }));
  const revoked = fold.state.auth.hostKeys[0];
  assert.deepEqual([revoked.revoked, revoked.suspectFromSeq], [true, 2]);
  assert.equal(fold.roster().seq, 2, "a host-key revocation does not recompute the roster");
  expectFold(() => add(fold, build(fold, "host.key.revoked", { kid: KEYS.host.kid, fromSeq: 2 }, "adminA", { host: "host2" })), "already_revoked");
});

// ---- revocations ----

test("revocation: R wins the race; the stolen key's revocation of the honest admin becomes suspect", () => {
  const fold = base4();
  // R adds adminB (own root) at 4; adminB (stolen) revokes adminA from 5 at 5.
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "recovery"));
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 5 }, "adminB"));
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminA")), "unknown_producer");
  // adminA may not revoke back; R revokes adminB from 5 at 6.
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminB.kid, fromSeq: 5 }, "recovery"));
  assert.equal(fold.state.marks[5], "suspect");
  assert.deepEqual(
    fold.state.auth.revocations.map((r) => r.kid),
    [KEYS.adminB.kid],
  );
  add(fold, build(fold, "producer.fence", {}, "adminA"));
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminB")), "unknown_producer");
  // An admin key never revokes R, nor itself.
  expectFold(() => add(fold, build(fold, "admin.key.revoked", { kid: KEYS.recovery.kid, fromSeq: 8 }, "adminA")), "unknown_key");
  expectFold(() => add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 8 }, "adminA")), "not_permitted");
});

test("revocation: statements depending on suspect ones are void; versions and keys are recomputed", () => {
  const fold = base4();
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminC", null), "adminA")); // 4
  // adminC (stolen) adds adminB to its lineage, raises Bob's role, and adminB admits a ghost.
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "adminC")); // 5
  add(fold, build(fold, "member.role.changed", { memberId: BOB, role: "comment", ver: 2 }, "adminC")); // 6
  const ghost = { memberId: memId("9a"), role: "watch", lanes: [], devices: [{ deviceId: devId("9a"), kind: "person", sig: KEYS.ghostSig.pub, dh: KEYS.ghostDh.pub }] };
  add(fold, build(fold, "member.admitted", { member: ghost, confirmation: { method: "sso-v1" } }, "adminB")); // 7
  // adminA changes Bob's role on top of adminC's change (ver 6), then R revokes adminC from 5.
  add(fold, build(fold, "member.role.changed", { memberId: BOB, role: "steer", ver: 6 }, "adminA")); // 8
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminC.kid, fromSeq: 5 }, "recovery")); // 9
  const st = fold.state;
  assert.deepEqual([st.marks[5], st.marks[6], st.marks[7], st.marks[8]], ["suspect", "suspect", "void", "void"]);
  assert.equal(st.members[BOB].role, "watch");
  assert.equal(st.members[ghost.memberId], undefined);
  assert.equal(st.auth.versions[`role:${BOB}`], 2);
  assert.equal(fold.roster().seq, 9);
  // adminB (added by a suspect statement) is gone and denylisted; adminC is still a valid key before 5, so it stays listed as revoked.
  assert.ok(st.auth.adminKeyDenylist[KEYS.adminB.kid]);
  assert.ok(st.used.members[ghost.memberId] && st.deviceDenylist[KEYS.ghostSig.pub]);
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminB")), "unknown_producer");
  // The honest admin re-issues what it wants to keep, against the recomputed version.
  add(fold, build(fold, "member.role.changed", { memberId: BOB, role: "steer", ver: 2 }, "adminA"));
});

test("revocation: bounds; the last admin key is never revoked or removed", () => {
  const fold = base4();
  expectFold(() => add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 5 }, "recovery")), "revocation_out_of_bounds");
  expectFold(() => add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 0 }, "recovery")), "last_admin");
  expectFold(() => add(fold, build(fold, "admin.removed", { kid: KEYS.adminA.kid }, "adminA")), "not_permitted");
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "recovery")); // 4
  add(fold, build(fold, "admin.removed", { kid: KEYS.adminB.kid }, "adminA")); // 5
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "adminB")), "unknown_producer");
  // Re-adding a removed key is refused.
  expectFold(() => add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "recovery")), "key_reused");
});

// ---- closure ----

test("closure: R closes alone; proposals need exp in range; a revoked proposer voids its proposal", () => {
  const r = base4();
  expectFold(() => add(r, build(r, "room.closed", { proposal: null }, "adminA")), "proposal_required");
  add(r, build(r, "room.closed", { proposal: null }, "recovery"));
  assert.equal(r.state.auth.closed, true);

  const fold = base4();
  const hts = 1793400000000;
  const s = Math.floor(hts / 1000);
  expectFold(() => add(fold, build(fold, "room.close.proposed", { exp: s + 3600 }, "adminA", { hts })), "bad_exp");
  expectFold(() => add(fold, build(fold, "room.close.proposed", { exp: s + 8 * 86400 }, "adminA", { hts })), "bad_exp");
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "recovery", { hts })); // 4
  const p = build(fold, "room.close.proposed", { exp: s + 2 * 86400 }, "adminA", { hts: hts + 1000 }); // 5
  add(fold, p);
  expectFold(() => add(fold, build(fold, "room.closed", { proposal: p.signed.entry.bodyHash }, "recovery", { hts: hts + 25 * HOUR })), "proposal_not_allowed");
  expectFold(() => add(fold, build(fold, "room.closed", { proposal: p.signed.entry.bodyHash }, "adminB", { hts: hts + 3 * 86400_000 })), "proposal_expired");
  // R revokes the proposer (adminA) from 5: the proposal is suspect and void.
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 5 }, "recovery", { hts: hts + 2 * HOUR })); // 6
  expectFold(() => add(fold, build(fold, "room.closed", { proposal: p.signed.entry.bodyHash }, "adminB", { hts: hts + 25 * HOUR })), "unknown_proposal");
});

test("closure: a proposer whose key is removed (not suspect) voids the proposal too", () => {
  const fold = base4();
  const hts = 1793400000000;
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminB", null), "recovery", { hts }));
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminC", null), "recovery", { hts }));
  const p = build(fold, "room.close.proposed", { exp: Math.floor(hts / 1000) + 2 * 86400 }, "adminA", { hts });
  add(fold, p);
  add(fold, build(fold, "admin.removed", { kid: KEYS.adminA.kid }, "adminC", { hts }));
  expectFold(() => add(fold, build(fold, "room.closed", { proposal: p.signed.entry.bodyHash }, "adminB", { hts: hts + 25 * HOUR })), "proposer_inactive");
});

// ---- first recovery key (own genesis without a recovery key) ----

function genesisWith(admins: string[]): { genesis: unknown; room: string } {
  const body = clone(GENESIS.body);
  body.admins = admins.map((n) => ({ alg: "ed25519", kid: KEYS[n].kid, pub: KEYS[n].pub }));
  body.recovery = null;
  const genesis = { body, kid: KEYS.adminA.kid, sig: b64u(sign(seedKey("adminA"), CTX_GENESIS, rjcs(body))) };
  return { genesis, room: verifyGenesis(genesis).roomId };
}
function openRoom(admins: string[]) {
  const { genesis, room } = genesisWith(admins);
  const fold = RoomLogFold.fromGenesis(genesis);
  const creator = clone(L.bodies[0].statement.body.data);
  add(fold, build(fold, "member.admitted", creator, "adminA", { room }));
  return { fold, room };
}

test("first recovery key: alone in a one-lineage room; with two lineages only by an independent confirmation", () => {
  const one = openRoom(["adminA"]);
  const rc = keyChange({ kind: "recovery", id: "recovery" }, null, "recovery2", null, one.room);
  expectFold(() => add(one.fold, build(one.fold, "recovery.key.rotated", { ...rc, proposal: L.entries[0].hash }, "adminA", { room: one.room })), "unknown_ref");
  add(one.fold, build(one.fold, "recovery.key.rotated", { ...rc, proposal: null }, "adminA", { room: one.room }));
  assert.deepEqual([one.fold.state.auth.recovery?.kid, one.fold.state.auth.recovery?.since], [KEYS.recovery2.kid, 2]);
  // A recovery key installed at 1 cannot reach back before 2.
  expectFold(() => add(one.fold, build(one.fold, "admin.key.revoked", { kid: KEYS.adminA.kid, fromSeq: 1 }, "recovery2", { room: one.room })), "revocation_before_since");

  const two = openRoom(["adminA", "adminB"]);
  const f = two.fold;
  const o = { room: two.room, hts: 1793400000000 };
  const ch = keyChange({ kind: "recovery", id: "recovery" }, null, "recovery2", null, two.room);
  expectFold(() => add(f, build(f, "recovery.key.rotated", { ...ch, proposal: null }, "adminA", o)), "proposal_required");
  const prop = build(f, "recovery.key.proposed", { ...ch, exp: Math.floor(o.hts / 1000) + 86400 }, "adminA", o);
  add(f, prop);
  const ph = prop.signed.entry.bodyHash;
  expectFold(() => add(f, build(f, "recovery.key.rotated", { ...ch, proposal: ph }, "adminA", o)), "confirmer_not_independent");
  const other = keyChange({ kind: "recovery", id: "recovery" }, null, "adminC", null, two.room);
  expectFold(() => add(f, build(f, "recovery.key.rotated", { ...other, proposal: ph }, "adminB", o)), "proposal_mismatch");
  expectFold(() => add(f, build(f, "recovery.key.rotated", { ...ch, proposal: ph }, "adminB", { ...o, hts: o.hts + 2 * 86400_000 })), "proposal_expired");
  add(f, build(f, "recovery.key.rotated", { ...ch, proposal: ph }, "adminB", o));
  assert.equal(f.state.auth.recovery?.kid, KEYS.recovery2.kid);
  // With R in place admins may neither propose nor install; R rotates itself.
  expectFold(() => add(f, build(f, "recovery.key.proposed", { ...other, exp: Math.floor(o.hts / 1000) + 86400 }, "adminA", o)), "recovery_exists");
  const rot = keyChange({ kind: "recovery", id: "recovery" }, KEYS.recovery2.kid, "adminC", null, two.room);
  add(f, build(f, "recovery.key.rotated", { ...rot, proposal: null }, "recovery2", o));
  assert.deepEqual([f.state.auth.recovery?.kid, f.state.auth.recovery?.since], [KEYS.adminC.kid, 3]);
});

// ---- holds ----

/** Bob gets a second device (phone) by admin replacement, so he is no longer a sole device. */
function bobWithTwoDevices(hts: number): RoomLogFold {
  const fold = base4();
  add(fold, build(fold, "member.device.replaced", { memberId: BOB, removed: [], added: { deviceId: devId("aa"), kind: "person", sig: KEYS.phoneSig.pub, dh: KEYS.phoneDh.pub }, ver: 2 }, "adminA", { hts }));
  return fold;
}

test("holds: 24 h for a device with siblings, 72 h for a sole device; deviceAddApproval admin forbids auto", () => {
  const T = ADMITTED_HTS + 48 * HOUR;
  const fold = bobWithTwoDevices(T - 30 * HOUR);
  const req = linkAndAdd(fold, BOB, "devSig", BOB_DEV, devId("bb"), "ghostSig", "ghostDh", T);
  const approve = (mode: string, hts: number) => build(fold, "device.add.approved", { memberId: BOB, deviceId: devId("bb"), ref: req, mode }, "adminA", { hts });
  assert.equal(fold.state.pending[req].sole, false);
  expectFold(() => add(fold, approve("auto", T + 1000 + HOLD_MS - 1)), "hold_not_elapsed");
  add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "deviceAddApproval", value: "admin", ver: -1 }] }, "adminA", { hts: T + 2000 }));
  expectFold(() => add(fold, approve("auto", T + 1000 + HOLD_MS)), "auto_not_allowed");
  add(fold, approve("admin", T + 3000));
  assert.equal(fold.state.members[BOB].devices.length, 3);
});

test("holds: a device younger than 24 h cannot request an automatic add; an admin may approve it", () => {
  const fold = base4();
  const T = ADMITTED_HTS + 2 * HOUR;
  const req = linkAndAdd(fold, BOB, "devSig", BOB_DEV, devId("bb"), "ghostSig", "ghostDh", T);
  assert.deepEqual([fold.state.pending[req].sole, fold.state.pending[req].young], [true, true]);
  const d = { memberId: BOB, deviceId: devId("bb"), ref: req };
  expectFold(() => add(fold, build(fold, "device.add.approved", { ...d, mode: "auto" }, "adminA", { hts: T + SOLE_HOLD_MS + 1000 })), "requester_too_young");
  add(fold, build(fold, "device.add.approved", { ...d, mode: "admin" }, "adminA", { hts: T + 2000 }));
  expectFold(() => add(fold, build(fold, "device.add.approved", { ...d, mode: "admin" }, "adminA", { hts: T + 3000 })), "not_pending");
});

test("holds: an open conflict blocks auto approvals of other requests until resolved", () => {
  const T = ADMITTED_HTS + 48 * HOUR;
  const fold = bobWithTwoDevices(T - 30 * HOUR);
  const first = linkAndAdd(fold, BOB, "devSig", BOB_DEV, devId("bb"), "ghostSig", "ghostDh", T);
  const second = linkAndAdd(fold, BOB, "devSig", BOB_DEV, devId("cc"), "devSig2", "devDh2", T + 5000);
  add(fold, build(fold, "device.add.vetoed", { memberId: BOB, ref: first }, "phoneSig", { hts: T + 6000 }));
  const vetoSeq = fold.head.seq;
  const approve = (hts: number) => build(fold, "device.add.approved", { memberId: BOB, deviceId: devId("cc"), ref: second, mode: "auto" }, "adminA", { hts });
  expectFold(() => add(fold, approve(T + 25 * HOUR)), "conflict_open");
  expectFold(() => add(fold, build(fold, "device.add.vetoed", { memberId: BOB, ref: first }, "devSig", { hts: T + 7000 })), "not_pending");
  // A device of another member cannot veto.
  expectFold(() => add(fold, build(fold, "device.add.vetoed", { memberId: BOB, ref: second }, "creatorDevSig", { hts: T + 7000 })), "not_member_device");
  add(fold, build(fold, "device.conflict.resolved", { memberId: BOB, ver: vetoSeq }, "adminA", { hts: T + 8000 }));
  add(fold, approve(T + 25 * HOUR));
  assert.equal(fold.state.members[BOB].devices.length, 3);
});

test("holds: removal or an approved rekey cancels the requester's pending requests", () => {
  const T = ADMITTED_HTS + 48 * HOUR;
  // The requester rekeys; its own pending add is cancelled when the rekey is approved.
  const fold = bobWithTwoDevices(T - 30 * HOUR);
  const addReq = linkAndAdd(fold, BOB, "devSig", BOB_DEV, devId("bb"), "ghostSig", "ghostDh", T);
  const rk = build(fold, "device.rekeyed", keyChange({ kind: "device", id: BOB_DEV }, KEYS.devSig.kid, "devSig2", "devDh2"), "devSig", { hts: T + 2000 });
  add(fold, rk);
  assert.equal(fold.state.pending[rk.signed.entry.bodyHash].sole, false);
  add(fold, build(fold, "device.rekey.approved", { memberId: BOB, deviceId: BOB_DEV, ref: rk.signed.entry.bodyHash, mode: "auto" }, "adminA", { hts: T + 2000 + HOLD_MS }));
  assert.equal(fold.state.pending[addReq].status, "cancelled");
  expectFold(
    () => add(fold, build(fold, "device.add.approved", { memberId: BOB, deviceId: devId("bb"), ref: addReq, mode: "admin" }, "adminA", { hts: T + 30 * HOUR })),
    "request_cancelled",
  );

  // Removing the device being rekeyed cancels its rekey; member.removed cancels everything of the member.
  const f2 = bobWithTwoDevices(T - 30 * HOUR);
  const rk2 = build(f2, "device.rekeyed", keyChange({ kind: "device", id: BOB_DEV }, KEYS.devSig.kid, "devSig2", "devDh2"), "devSig", { hts: T });
  add(f2, rk2);
  add(f2, build(f2, "device.removed", { memberId: BOB, deviceId: BOB_DEV, reason: "lost" }, "adminA", { hts: T + 1000 }));
  assert.equal(f2.state.pending[rk2.signed.entry.bodyHash].status, "cancelled");
  const f3 = bobWithTwoDevices(T - 30 * HOUR);
  const req3 = linkAndAdd(f3, BOB, "phoneSig", devId("aa"), devId("bb"), "ghostSig", "ghostDh", T);
  add(f3, build(f3, "member.removed", { memberId: BOB, reason: "compromise" }, "adminA", { hts: T + 2000 }));
  assert.equal(f3.state.pending[req3].status, "cancelled");
});

test("device requests: link checks, key-change checks, rekey keys fresh; member.left only from a sole device", () => {
  const T = ADMITTED_HTS + 48 * HOUR;
  const fold = bobWithTwoDevices(T - 30 * HOUR);
  const kc = keyChange({ kind: "device", id: devId("bb") }, null, "ghostSig", "ghostDh");
  const device = { deviceId: devId("bb"), kind: "person", sig: KEYS.ghostSig.pub, dh: KEYS.ghostDh.pub };
  const data = { memberId: BOB, device, ...kc, addedBy: BOB_DEV, confirmation: { method: "sas6", linkRef: ref("no-link"), transcript: ref("t") } };
  expectFold(() => add(fold, build(fold, "device.added", data, "devSig", { hts: T })), "unknown_link");
  const linkRef = ref("link-x");
  add(fold, build(fold, "device.link.created", { memberId: BOB, linkRef, exp: Math.floor(T / 1000) + 600 }, "devSig", { hts: T }));
  const withLink = { ...data, confirmation: { ...data.confirmation, linkRef } };
  expectFold(() => add(fold, build(fold, "device.added", { ...withLink, addedBy: devId("aa") }, "devSig", { hts: T + 1000 })), "not_permitted");
  const badBinding = { ...withLink, newKeySig: keyChange({ kind: "device", id: devId("bb") }, null, "devSig2", "ghostDh").newKeySig };
  expectFold(() => add(fold, build(fold, "device.added", badBinding, "devSig", { hts: T + 1000 })), "bad_new_key_sig");
  const mismatch = { ...withLink, device: { ...device, dh: KEYS.devDh2.pub } };
  expectFold(() => add(fold, build(fold, "device.added", mismatch, "devSig", { hts: T + 1000 })), "bad_key_change");
  // A rekey to a key already in the roster, or naming a stale old key.
  const toPhone = keyChange({ kind: "device", id: BOB_DEV }, KEYS.devSig.kid, "phoneSig", "devDh2");
  expectFold(() => add(fold, build(fold, "device.rekeyed", toPhone, "devSig", { hts: T + 1000 })), "key_reused");
  const staleOld = keyChange({ kind: "device", id: BOB_DEV }, KEYS.phoneSig.kid, "devSig2", "devDh2");
  expectFold(() => add(fold, build(fold, "device.rekeyed", staleOld, "devSig", { hts: T + 1000 })), "stale_version");
  const otherDevice = keyChange({ kind: "device", id: devId("aa") }, KEYS.devSig.kid, "devSig2", "devDh2");
  expectFold(() => add(fold, build(fold, "device.rekeyed", otherDevice, "devSig", { hts: T + 1000 })), "bad_key_change");
  expectFold(() => add(fold, build(fold, "member.left", { memberId: BOB }, "devSig", { hts: T + 1000 })), "not_sole_device");
});

test("refold: an approved rekey made suspect puts the request back to pending with its new keys usable", () => {
  const fold = base4();
  const T = ADMITTED_HTS + 48 * HOUR;
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminC", null), "adminA", { hts: T })); // 4
  const rk = build(fold, "device.rekeyed", keyChange({ kind: "device", id: BOB_DEV }, KEYS.devSig.kid, "devSig2", "devDh2"), "devSig", { hts: T }); // 5
  add(fold, rk);
  const ref5 = rk.signed.entry.bodyHash;
  add(fold, build(fold, "device.rekey.approved", { memberId: BOB, deviceId: BOB_DEV, ref: ref5, mode: "admin" }, "adminC", { hts: T + 1000 })); // 6
  assert.equal(fold.state.members[BOB].devices[0].sig, KEYS.devSig2.pub);
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminC.kid, fromSeq: 6 }, "recovery", { hts: T + 2000 })); // 7
  const st = fold.state;
  assert.equal(st.members[BOB].devices[0].sig, KEYS.devSig.pub, "old keys back");
  assert.equal(st.pending[ref5].status, "pending");
  assert.ok(!st.deviceDenylist[KEYS.devSig2.pub] && !st.auth.retiredKeys[KEYS.devSig2.pub]);
  assert.equal(fold.roster().seq, 7);
  add(fold, build(fold, "device.rekey.approved", { memberId: BOB, deviceId: BOB_DEV, ref: ref5, mode: "admin" }, "adminA", { hts: T + 3000 }));
  assert.equal(fold.state.members[BOB].devices[0].sig, KEYS.devSig2.pub);
});

test("refold: a device removed by a suspect statement returns, and its keys are not denylisted", () => {
  const fold = base4();
  add(fold, build(fold, "admin.added", keyChange({ kind: "admin", id: CREATOR }, null, "adminC", null), "adminA")); // 4
  add(fold, build(fold, "device.removed", { memberId: BOB, deviceId: BOB_DEV, reason: "compromise" }, "adminC")); // 5
  assert.equal(fold.state.members[BOB].devices.length, 0);
  add(fold, build(fold, "admin.key.revoked", { kid: KEYS.adminC.kid, fromSeq: 5 }, "recovery")); // 6
  const st = fold.state;
  assert.equal(st.members[BOB].devices[0].sig, KEYS.devSig.pub);
  assert.ok(!st.deviceDenylist[KEYS.devSig.pub] && !st.auth.retiredKeys[KEYS.devDh.pub]);
  assert.equal(fold.roster().seq, 6);
  add(fold, build(fold, "producer.fence", {}, "devSig"));
});
