// Identity v2 milestone I-5: statements, entries, genesis and the core fold against
// docs/design/specs/identity-v2/vectors/vectors.json (sections genesis, statements, log.entries,
// log.rosterAfter, log.foldChecks, log.equivocationExample), read directly so the tests and the
// spec cannot drift. Further cases build small chains signed with the vector's test-only seeds.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { bodyHash, entryHash, isEquivocationProof, type LogEntry } from "../../server/authority/entries";
import { foldLog, FoldError, RoomLogFold, versionKey, type FoldReason } from "../../server/authority/fold";
import { GenesisError, verifyGenesis } from "../../server/authority/genesis";
import { rosterHash } from "../../server/authority/roster";
import { parseSignedStatement, STATEMENT_TYPE_NAMES, STATEMENT_TYPES, StatementError, verifyStatementSig, type SignedStatement } from "../../server/authority/statements";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { CTX_KEY_CHANGE_NEW, CTX_LOG_ENTRY, CTX_RE, isSignableStatementType, STMT_LOG_WITNESS, stmtContext } from "../../server/proto/contexts";
import { ed25519PrivateKeyFromSeed, verify } from "../../server/proto/keys";
import { rjcs, rjcsText } from "../../server/proto/rjcs";
import { sign } from "../../server/proto/tbs";

const VECTORS_PATH = join(import.meta.dirname, "..", "..", "docs", "design", "specs", "identity-v2", "vectors", "vectors.json");
const V = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
const L = V.log;
const GENESIS = V.genesis.signed;
const ROOM = V.genesis.roomId as string;

type VKey = { alg: string; seedHex?: string; pub: string; kid: string };
const KEYS = V.keys as Record<string, VKey>;
const keyByKid = (k: string): VKey => {
  const found = Object.values(KEYS).find((x) => x.kid === k);
  assert.ok(found, "vector key for kid");
  return found;
};
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** The main chain as fold input: signed entries with RJCS(SignedStatement) bodies. */
const mainChain = () => L.entries.map((signed: unknown, i: number) => ({ signed, body: rjcs(L.bodies[i].statement) }));

function expectFold(fn: () => void, reason: FoldReason): void {
  assert.throws(fn, (err: unknown) => err instanceof FoldError && err.reason === reason, `expected ${reason}`);
}

// ---- genesis ----

test("genesis: verifies, canonical bytes, genesisHash and roomId match the vector", () => {
  const v = verifyGenesis(GENESIS);
  assert.equal(v.genesisHash, V.genesis.genesisHash);
  assert.equal(v.roomId, V.genesis.roomId);
  assert.equal(rjcsText(GENESIS), V.genesis.canonical);
  assert.equal(verifyGenesis(new TextEncoder().encode(V.genesis.canonical)).genesisHash, V.genesis.genesisHash);
  assert.equal(L.genesisHashAsPrev, V.genesis.genesisHash);
});

test("genesis: nested unknown field, bad signature, unlisted signer and non-canonical bytes are refused", () => {
  const extra = clone(GENESIS);
  extra.body.policy.extra = 1;
  assert.throws(() => verifyGenesis(extra), GenesisError);
  const extraRelay = clone(GENESIS);
  extraRelay.body.endpoint.relay.path = "/";
  assert.throws(() => verifyGenesis(extraRelay), GenesisError);
  const badSig = clone(GENESIS);
  badSig.body.createdAt += 1;
  assert.throws(() => verifyGenesis(badSig), /bad signature/);
  const otherSigner = clone(GENESIS);
  otherSigner.kid = KEYS.adminB.kid;
  assert.throws(() => verifyGenesis(otherSigner), /not a listed admin/);
  const badKid = clone(GENESIS);
  badKid.body.admins[0].kid = KEYS.adminB.kid;
  assert.throws(() => verifyGenesis(badKid), GenesisError);
  const ttl = clone(GENESIS);
  ttl.body.policy.grantTtl = 43201;
  assert.throws(() => verifyGenesis(ttl), GenesisError);
  assert.throws(() => verifyGenesis(new TextEncoder().encode(V.genesis.canonical + "\n")), /not canonical/);
});

// ---- statements ----

const STATEMENT_VECTORS = Object.entries(V.statements).filter(([name]) => name !== "newKeySigCtx") as [string, SignedStatement][];

test("statements: every vector parses strictly and its signature verifies under stmt:<type> only", () => {
  assert.equal(V.statements.newKeySigCtx, CTX_KEY_CHANGE_NEW);
  assert.ok(STATEMENT_VECTORS.length >= 21);
  for (const [name, stmt] of STATEMENT_VECTORS) {
    parseSignedStatement(stmt);
    const pub = b64uDecode(keyByKid(stmt.body.producer.kid).pub, 32);
    assert.ok(verifyStatementSig(stmt, pub), `${name}: signature`);
    const other = STATEMENT_TYPE_NAMES.find((t) => t !== stmt.body.type)!;
    assert.equal(verify(pub, stmtContext(other), rjcs(stmt.body), b64uDecode(stmt.sig, 64)), false, `${name}: other context`);
    const data = stmt.body.data as { change?: { newSig: string | null }; newKeySig?: string };
    if (data.change) {
      assert.ok(data.change.newSig && data.newKeySig, `${name}: newKeySig present`);
      assert.ok(verify(b64uDecode(data.change.newSig, 32), CTX_KEY_CHANGE_NEW, rjcs(data.change), b64uDecode(data.newKeySig, 64)), `${name}: newKeySig`);
    }
    // base names a position and the hash of that position (or the genesis for -1).
    assert.ok(stmt.body.base.seq >= -1);
  }
});

test("statements: strict at every level; unknown types and bad field values are refused", () => {
  const reason = (value: unknown) => {
    try {
      parseSignedStatement(value);
      return "ok";
    } catch (err) {
      assert.ok(err instanceof StatementError);
      return err.reason;
    }
  };
  const s = V.statements;
  const nested = clone(s.deviceRekeyed);
  nested.body.data.change.subject.extra = 1;
  assert.equal(reason(nested), "bad_statement");
  const inEntry = clone(s.creatorAdmitted);
  inEntry.body.data.member.devices[0].label = "x";
  assert.equal(reason(inEntry), "bad_statement");
  const inBase = clone(s.memberLeft);
  inBase.body.base.extra = 1;
  assert.equal(reason(inBase), "bad_statement");
  const outer = clone(s.memberLeft);
  outer.extra = 1;
  assert.equal(reason(outer), "bad_statement");
  const unknown = clone(s.memberLeft);
  unknown.body.type = "member.teleported";
  assert.equal(reason(unknown), "unknown_type");
  const unsorted = clone(s.roomPolicyChanged);
  unsorted.body.data.changes.reverse();
  assert.equal(reason(unsorted), "bad_statement");
  const outOfRange = clone(s.roomPolicyChanged);
  outOfRange.body.data.changes = [{ setting: "closeDelay", value: 518401, ver: -1 }];
  assert.equal(reason(outOfRange), "bad_statement");
  const badVer = clone(s.memberRoleChanged);
  badVer.body.data.ver = -2;
  assert.equal(reason(badVer), "bad_statement");
  const creatorWithInvite = clone(s.creatorAdmitted);
  creatorWithInvite.body.data.confirmation.inviteRef = s.memberAdmitted.body.data.confirmation.inviteRef;
  assert.equal(reason(creatorWithInvite), "bad_statement");
  const noDevices = clone(s.memberAdmitted);
  noDevices.body.data.member.devices = [];
  assert.equal(reason(noDevices), "bad_statement");
  assert.equal(STATEMENT_TYPE_NAMES.length, 50);
});

test("statements: every catalogue type yields a valid stmt:<type> context (signatures 3.1)", () => {
  for (const type of [...STATEMENT_TYPE_NAMES, STMT_LOG_WITNESS]) {
    assert.match(type, /^[a-z0-9.-]+$/, type);
    assert.ok(isSignableStatementType(type), type);
    const ctx = stmtContext(type);
    assert.equal(ctx, `stmt:${type}`);
    assert.ok(CTX_RE.test(ctx), ctx);
  }
  assert.ok(STATEMENT_TYPE_NAMES.includes("grant.suspected-theft" as never));
  // The old name could not be signed: "_" is outside the context alphabet.
  assert.equal(isSignableStatementType("grant.suspected_theft"), false);
  assert.throws(() => stmtContext("grant.suspected_theft"), /bad statement type/);
});

// ---- log.entries, log.rosterAfter ----

test("log.entries: hashes, body hashes and prev links; the fold accepts the main chain", () => {
  let prev = V.genesis.genesisHash;
  L.entries.forEach((e: { entry: LogEntry; hash: string; hsig: string }, i: number) => {
    assert.equal(e.entry.seq, i);
    assert.equal(e.entry.prev, prev);
    assert.equal(entryHash(e.entry), e.hash);
    assert.equal(bodyHash(rjcs(L.bodies[i].statement)), e.entry.bodyHash);
    assert.ok(verify(b64uDecode(KEYS.host.pub, 32), CTX_LOG_ENTRY, rjcs(e.entry), b64uDecode(e.hsig, 64)));
    prev = e.hash;
  });
  const { fold, error } = foldLog(GENESIS, mainChain());
  assert.equal(error, null);
  assert.deepEqual(fold.head, { seq: 4, hash: L.entries[4].hash });
  // After member.left at seq 4 only the creator remains.
  assert.deepEqual(Object.keys(fold.state.members), [L.bodies[0].statement.body.data.member.memberId]);
  assert.ok(fold.state.deviceDenylist[KEYS.devSig.pub] && fold.state.deviceDenylist[KEYS.devDh.pub]);
});

test("log.rosterAfter: roster position stays at the last roster-changing entry, with the vector hash", () => {
  const chain = mainChain();
  for (const expected of L.rosterAfter) {
    const { fold, error } = foldLog(GENESIS, chain.slice(0, expected.headSeq + 1));
    assert.equal(error, null);
    assert.equal(fold.head.seq, expected.headSeq);
    const roster = fold.roster();
    assert.equal(roster.seq, expected.rosterSeq, `rosterSeq at head ${expected.headSeq}`);
    assert.equal(rosterHash(roster), expected.rosterHash, `rosterHash at head ${expected.headSeq}`);
    assert.equal(fold.rosterHash(), expected.rosterHash);
  }
});

// ---- log.foldChecks ----

function foldChecksPrefix(): RoomLogFold {
  const fold = RoomLogFold.fromGenesis(GENESIS);
  for (const x of mainChain().slice(0, 4)) fold.append(x.signed, x.body);
  for (const r of L.foldChecks.roleChain) fold.append({ entry: r.entry, hash: r.hash, hsig: r.hsig }, rjcs(r.statement));
  return fold;
}

test("log.foldChecks: role change and its reversal are accepted, with versions at their entries", () => {
  const fold = foldChecksPrefix();
  assert.equal(fold.head.seq, 5);
  const bob = L.foldChecks.roleChain[0].statement.body.data.memberId;
  assert.equal(fold.state.members[bob].role, "watch");
  assert.equal(fold.state.auth.versions[versionKey.role(bob)], 5);
  assert.equal(fold.state.rosterSeq, 5, "a role change is a roster change");
  assert.equal(fold.maxBaseOf(KEYS.adminA.kid), 4);
});

test("log.foldChecks: each case is rejected with the expected reason and leaves the fold unchanged", () => {
  assert.equal(L.foldChecks.cases.length, 5);
  for (const c of L.foldChecks.cases) {
    const fold = foldChecksPrefix();
    const before = { head: fold.head, roster: fold.rosterHash(), versions: clone(fold.state.auth.versions) };
    const body = rjcs(c.statement);
    assert.equal(bodyHash(body), c.entry.entry.bodyHash, `${c.name}: bodyHash`);
    expectFold(() => fold.check(c.entry, body), c.expect);
    expectFold(() => fold.append(c.entry, body), c.expect);
    assert.deepEqual({ head: fold.head, roster: fold.rosterHash(), versions: fold.state.auth.versions }, before, `${c.name}: unchanged`);
    // foldLog stops there too, at the state of seq 5.
    const all = [...mainChain().slice(0, 4), ...L.foldChecks.roleChain.map((r: any) => ({ signed: { entry: r.entry, hash: r.hash, hsig: r.hsig }, body: rjcs(r.statement) })), { signed: c.entry, body }];
    const res = foldLog(GENESIS, all);
    assert.equal(res.error?.reason, c.expect);
    assert.equal(res.error?.seq, 6);
    assert.equal(res.fold.head.seq, 5);
  }
});

// ---- log.equivocationExample ----

test("log.equivocationExample: two valid signed entries at seq 4 are a proof; anything less is not", () => {
  const eq = L.equivocationExample;
  const fold = RoomLogFold.fromGenesis(GENESIS);
  assert.ok(isEquivocationProof(eq.a, eq.b, fold.hostKeyAt));
  assert.equal(bodyHash(rjcs(eq.bStatement)), eq.b.entry.bodyHash);
  parseSignedStatement(eq.bStatement);
  assert.equal(isEquivocationProof(eq.a, eq.a, fold.hostKeyAt), false, "same hash");
  const forged = clone(eq.b);
  forged.hsig = eq.a.hsig;
  assert.equal(isEquivocationProof(eq.a, forged, fold.hostKeyAt), false, "bad hsig");
  const otherSeq = clone(eq.b);
  otherSeq.entry.seq = 3;
  otherSeq.hash = entryHash(otherSeq.entry);
  assert.equal(isEquivocationProof(eq.a, otherSeq, fold.hostKeyAt), false, "different seq");
  // Under a key that is not a host key at that position, nothing is a proof.
  assert.equal(isEquivocationProof(eq.a, eq.b, () => null), false);
  // Each side alone extends the chain at seq 3; a member that folded one rejects the other's seq 4 as a gap.
  const a = foldLog(GENESIS, mainChain());
  assert.equal(a.error, null);
  expectFold(() => a.fold.check(eq.b, rjcs(eq.bStatement)), "seq_gap");
  const b = foldLog(GENESIS, [...mainChain().slice(0, 4), { signed: eq.b, body: rjcs(eq.bStatement) }]);
  assert.equal(b.error, null);
  assert.equal(b.fold.roster().seq, 4);
});

// ---- small chains built with the vector's test-only seeds ----

const seedKey = (name: string) => ed25519PrivateKeyFromSeed(Buffer.from(KEYS[name].seedHex!, "hex"));
const PRODUCER_KIND: Record<string, "admin" | "device" | "host" | "recovery"> = {
  adminA: "admin",
  creatorDevSig: "device",
  devSig: "device",
  phoneSig: "device",
  host: "host",
  recovery: "recovery",
};

type Built = { signed: { entry: LogEntry; hash: string; hsig: string }; body: Uint8Array; stmt: SignedStatement };

/** Builds the next entry on `fold` (statement base = the fold's head unless given). */
function build(fold: RoomLogFold, type: string, data: unknown, signer: string, opts: { base?: { seq: number; hash: string }; hts?: number; ts?: number; sigCtx?: string } = {}): Built {
  const head = fold.head;
  const body = {
    v: 2,
    typ: "stmt",
    type,
    roomId: ROOM,
    producer: { kind: PRODUCER_KIND[signer], kid: KEYS[signer].kid },
    base: opts.base ?? head,
    ts: opts.ts ?? 1793300000000 + head.seq + 1,
    data,
  };
  const stmt = { body, sig: b64u(sign(seedKey(signer), opts.sigCtx ?? stmtContext(type), rjcs(body))) } as SignedStatement;
  const bodyBytes = rjcs(stmt);
  const entry: LogEntry = {
    v: 2,
    typ: "log-entry",
    roomId: ROOM,
    seq: head.seq + 1,
    prev: head.hash,
    hts: opts.hts ?? 1793300000100 + (head.seq + 1) * 1000,
    epoch: 0,
    cls: "stmt",
    type,
    bodyHash: bodyHash(bodyBytes),
    hostKid: KEYS.host.kid,
  };
  const signed = { entry, hash: entryHash(entry), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(entry))) };
  return { signed, body: bodyBytes, stmt };
}
const add = (fold: RoomLogFold, b: Built) => fold.append(b.signed, b.body);

const BOB = L.bodies[2].statement.body.data.member.memberId as string;
const BOB_DEV = L.bodies[2].statement.body.data.member.devices[0].deviceId as string;
const CREATOR = L.bodies[0].statement.body.data.member.memberId as string;
const LANE = L.bodies[1].statement.body.data.laneId as string;

/** entries 0..3: creator, lane, Bob (watch, one device), grant. */
function base4(): RoomLogFold {
  const fold = RoomLogFold.fromGenesis(GENESIS);
  for (const x of mainChain().slice(0, 4)) fold.append(x.signed, x.body);
  return fold;
}
const phone = () => ({ deviceId: "dev_" + "ab".repeat(16), kind: "person", sig: KEYS.phoneSig.pub, dh: KEYS.phoneDh.pub });

test("fold: seq 0 must be the creator's admission, and 'creator' only at seq 0", () => {
  const empty = RoomLogFold.fromGenesis(GENESIS);
  const lane = L.bodies[1].statement.body.data;
  expectFold(() => add(empty, build(empty, "lane.created", lane, "adminA")), "genesis_admission_required");
  const fold = base4();
  const m = clone(L.bodies[0].statement.body.data);
  m.member.memberId = "mem_" + "cd".repeat(16);
  m.member.devices = [phone()];
  expectFold(() => add(fold, build(fold, "member.admitted", m, "adminA")), "creator_not_at_genesis");
});

test("fold: an admission is never replayed after member.left, and its ids and keys never return", () => {
  const { fold, error } = foldLog(GENESIS, mainChain());
  assert.equal(error, null);
  // Replay of the signed admission: duplicate body (unique rule), even though Bob is gone.
  const replay = L.entries[2];
  const e: LogEntry = { ...replay.entry, seq: 5, prev: fold.head.hash, hts: replay.entry.hts + 10_000_000 };
  const signed = { entry: e, hash: entryHash(e), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(e))) };
  expectFold(() => fold.append(signed, rjcs(L.bodies[2].statement)), "duplicate_statement");
  // A fresh admission with Bob's memberId, or with Bob's retired keys, is refused by apply.
  const again = clone(L.bodies[2].statement.body.data);
  again.member.devices = [phone()];
  expectFold(() => add(fold, build(fold, "member.admitted", again, "adminA")), "id_reused");
  const oldKeys = clone(L.bodies[2].statement.body.data);
  oldKeys.member.memberId = "mem_" + "ef".repeat(16);
  oldKeys.member.devices[0].deviceId = "dev_" + "ef".repeat(16);
  expectFold(() => add(fold, build(fold, "member.admitted", oldKeys, "adminA")), "key_reused");
});

test("fold: producers must be allowed for the type and hold a key in the state", () => {
  const fold = base4();
  // A device may not change roles; the host may not admit.
  expectFold(() => add(fold, build(fold, "member.role.changed", { memberId: BOB, role: "comment", ver: 2 }, "devSig")), "not_permitted");
  // The recovery key is in the genesis, but member.left needs a device.
  expectFold(() => add(fold, build(fold, "member.left", { memberId: BOB }, "recovery")), "not_permitted");
  // A device key that is not in the roster.
  expectFold(() => add(fold, build(fold, "producer.fence", {}, "phoneSig")), "unknown_producer");
  // member.left signed by a device of another member.
  expectFold(() => add(fold, build(fold, "member.left", { memberId: BOB }, "creatorDevSig")), "not_member_device");
  // A signature by the right kid but over other bytes.
  const b = build(fold, "producer.fence", {}, "devSig");
  const forged = clone(b.stmt);
  forged.body.ts += 1;
  const body = rjcs(forged);
  const e = { ...b.signed.entry, bodyHash: bodyHash(body) };
  const signed = { entry: e, hash: entryHash(e), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(e))) };
  expectFold(() => fold.append(signed, body), "bad_signature");
  assert.equal(fold.head.seq, 3);
});

test("fold: entry layer checks (hsig, prev, hash, body, type) stop the fold", () => {
  const fold = base4();
  const b = build(fold, "producer.fence", {}, "devSig");
  expectFold(() => fold.append({ ...b.signed, hsig: L.entries[0].hsig }, b.body), "bad_hsig");
  expectFold(() => fold.append({ ...b.signed, hash: L.entries[0].hash }, b.body), "hash_mismatch");
  expectFold(() => fold.append(b.signed, rjcs(L.bodies[0].statement)), "body_hash_mismatch");
  expectFold(() => fold.append(b.signed), "missing_body");
  const e = { ...b.signed.entry, prev: L.entries[0].hash };
  expectFold(() => fold.append({ entry: e, hash: entryHash(e), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(e))) }, b.body), "prev_mismatch");
  const t = { ...b.signed.entry, type: "producer.fenced" };
  expectFold(() => fold.append({ entry: t, hash: entryHash(t), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(t))) }, b.body), "type_mismatch");
  const extra = { ...b.signed, extra: 1 };
  expectFold(() => fold.append(extra, b.body), "bad_entry");
  // Signed by a key that is not a host key.
  const sAdmin = { ...b.signed, hsig: b64u(sign(seedKey("adminA"), CTX_LOG_ENTRY, rjcs(b.signed.entry))) };
  expectFold(() => fold.append(sAdmin, b.body), "bad_hsig");
  fold.append(b.signed, b.body);
  assert.equal(fold.head.seq, 4);
});

test("fold: an unknown statement type stops processing; later entries are not applied", () => {
  const fold = base4();
  const unknown = build(fold, "member.teleported", { memberId: BOB }, "adminA");
  const later = mainChain()[4];
  const res = foldLog(GENESIS, [...mainChain().slice(0, 4), { signed: unknown.signed, body: unknown.body }, later]);
  assert.equal(res.error?.reason, "unknown_type");
  assert.equal(res.fold.head.seq, 3);
  assert.ok(res.fold.state.members[BOB], "member.left after the invalid entry was not applied");
});

test("fold: versions per field; ABA on lanes and policy is refused; minVersion only rises", () => {
  const fold = base4();
  add(fold, build(fold, "member.lanes.changed", { memberId: BOB, lanes: [], ver: 2 }, "adminA"));
  add(fold, build(fold, "member.lanes.changed", { memberId: BOB, lanes: [LANE], ver: 4 }, "adminA"));
  assert.equal(fold.roster().seq, 5);
  // The held first change names ver 2; lanes are back to [LANE] but the version is 5.
  expectFold(() => add(fold, build(fold, "member.lanes.changed", { memberId: BOB, lanes: [], ver: 2 }, "adminA")), "stale_version");
  // Different fields have independent versions: the role is still at its admission version.
  add(fold, build(fold, "member.role.changed", { memberId: BOB, role: "comment", ver: 2 }, "adminA"));
  // Policy: one ver per setting.
  add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 0, ver: -1 }] }, "adminA"));
  assert.equal(fold.state.auth.policy.closeDelay, 0);
  expectFold(() => add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 86400, ver: -1 }] }, "adminA")), "stale_version");
  add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "closeDelay", value: 86400, ver: 7 }, { setting: "minVersion", value: 3, ver: -1 }] }, "adminA"));
  expectFold(() => add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "minVersion", value: 2, ver: 8 }] }, "adminA")), "policy_downgrade");
  // Policy changes are not roster changes.
  assert.equal(fold.roster().seq, 6);
});

test("fold: lane names follow the owner and projectNames; lanes and their keys never return", () => {
  const fold = base4();
  expectFold(() => add(fold, build(fold, "lane.names.changed", { laneId: LANE, show: true, ver: 1 }, "devSig")), "not_lane_owner");
  add(fold, build(fold, "lane.names.changed", { laneId: LANE, show: true, ver: 1 }, "creatorDevSig"));
  assert.equal(fold.state.auth.lanes[LANE].showNames, true);
  add(fold, build(fold, "room.policy.changed", { changes: [{ setting: "projectNames", value: "hidden", ver: -1 }] }, "adminA"));
  expectFold(() => add(fold, build(fold, "lane.names.changed", { laneId: LANE, show: true, ver: 4 }, "creatorDevSig")), "names_hidden");
  // The host closes a lane only after it was degraded for 24 h of hts.
  const hts = 1793400000000;
  add(fold, build(fold, "lane.degraded", { laneId: LANE, reason: "agent_missing" }, "host", { hts }));
  expectFold(() => add(fold, build(fold, "lane.closed", { laneId: LANE }, "host", { hts: hts + 23 * 3600_000 })), "not_permitted");
  add(fold, build(fold, "lane.closed", { laneId: LANE }, "host", { hts: hts + 24 * 3600_000 }));
  assert.equal(fold.state.auth.lanes[LANE].status, "closed");
  const lane = L.bodies[1].statement.body.data;
  expectFold(() => add(fold, build(fold, "lane.created", lane, "adminA")), "id_reused");
  const newId = clone(lane);
  newId.laneId = "lane_" + "12".repeat(16);
  expectFold(() => add(fold, build(fold, "lane.created", newId, "adminA")), "key_reused");
});

test("fold: device removal, self-only; the last device leaves with member.left; replacement restores", () => {
  const fold = base4();
  expectFold(() => add(fold, build(fold, "device.removed", { memberId: BOB, deviceId: BOB_DEV, reason: "self" }, "devSig")), "last_device_use_member_left");
  expectFold(() => add(fold, build(fold, "device.removed", { memberId: CREATOR, deviceId: L.bodies[0].statement.body.data.member.devices[0].deviceId, reason: "admin" }, "devSig")), "not_permitted");
  // An admin may remove a last device: Bob stays with no devices (roster change).
  add(fold, build(fold, "device.removed", { memberId: BOB, deviceId: BOB_DEV, reason: "lost" }, "adminA"));
  assert.equal(fold.state.members[BOB].devices.length, 0);
  assert.equal(fold.roster().seq, 4);
  // Restored with member.device.replaced (removed: []), naming the devices version 4.
  expectFold(() => add(fold, build(fold, "member.device.replaced", { memberId: BOB, removed: [], added: phone(), ver: 2 }, "adminA")), "stale_version");
  const old = { deviceId: "dev_" + "77".repeat(16), kind: "person", sig: KEYS.devSig.pub, dh: KEYS.devDh.pub };
  expectFold(() => add(fold, build(fold, "member.device.replaced", { memberId: BOB, removed: [], added: old, ver: 4 }, "adminA")), "key_reused");
  add(fold, build(fold, "member.device.replaced", { memberId: BOB, removed: [], added: phone(), ver: 4 }, "adminA"));
  assert.equal(fold.state.members[BOB].devices[0].sig, KEYS.phoneSig.pub);
  // The phone is now Bob's only device and may leave for him.
  add(fold, build(fold, "member.left", { memberId: BOB }, "phoneSig"));
  assert.equal(fold.state.members[BOB], undefined);
  assert.equal(fold.roster().seq, 6);
});

test("fold: the forward rule holds across types, and a fence kills a held statement", () => {
  const fold = base4();
  const held = build(fold, "member.role.changed", { memberId: BOB, role: "steer", ver: 2 }, "adminA");
  add(fold, build(fold, "producer.fence", {}, "adminA"));
  // Re-sequence the held statement at the new head: same body, so its base (3) is not after the fence's (3).
  const e: LogEntry = { ...held.signed.entry, seq: 5, prev: fold.head.hash };
  expectFold(() => fold.append({ entry: e, hash: entryHash(e), hsig: b64u(sign(seedKey("host"), CTX_LOG_ENTRY, rjcs(e))) }, held.body), "base_regressed");
  assert.equal(fold.state.members[BOB].role, "watch");
});

test("fold: reserved types are refused; a ref must name an earlier statement (I-6 types are folded in v2-fold-authority)", () => {
  const fold = base4();
  expectFold(() => add(fold, build(fold, "seat.removed", { deviceId: BOB_DEV }, "adminA")), "reserved_type");
  // A ref that names nothing in the chain.
  expectFold(() => add(fold, build(fold, "device.add.vetoed", { memberId: BOB, ref: L.entries[0].hash }, "devSig")), "unknown_ref");
  // A close proposal is now accepted (milestone I-6).
  add(fold, build(fold, "room.close.proposed", { exp: 1793498800 }, "adminA", { hts: 1793300000000 }));
  assert.equal(fold.head.seq, 4);
});

test("fold: the host's own statements need the host key valid at that position", () => {
  const fold = base4();
  add(fold, build(fold, "grant.revoked", { gid: L.bodies[3].statement.body.data.gid, reason: "superseded" }, "host"));
  add(fold, build(fold, "mls.stalled", { epoch: 0, sinceMs: 1000 }, "host"));
  assert.equal(fold.head.seq, 5);
  assert.equal(fold.roster().seq, 2, "host statements change no roster");
});

// ---- every fold failure is a FoldError ----

test("fold: an unsignable catalogue type, an unexpected exception and a bad genesis are FoldErrors with a reason", () => {
  // A catalogue entry whose stmt:<type> context is outside the alphabet (as grant.suspected_theft was).
  const catalogue = STATEMENT_TYPES as unknown as Record<string, unknown>;
  const bad = "grant.bad_type";
  catalogue[bad] = { producers: ["admin"], data: STATEMENT_TYPES["producer.fence"].data };
  try {
    const fold = base4();
    const b = build(fold, bad, {}, "adminA", { sigCtx: stmtContext("producer.fence") });
    const before = fold.head;
    expectFold(() => fold.check(b.signed, b.body), "unsignable_type");
    expectFold(() => add(fold, b), "unsignable_type");
    assert.deepEqual(fold.head, before);
    const res = foldLog(GENESIS, [...mainChain().slice(0, 4), b]);
    assert.equal(res.error?.reason, "unsignable_type");
    assert.equal(res.error?.seq, 4);
  } finally {
    delete catalogue[bad];
  }

  // An exception no check anticipated becomes internal_error at that seq; the fold is unchanged.
  const fold = base4();
  const next = build(fold, "producer.fence", {}, "adminA");
  const head = fold.head;
  fold.hostKeyAt = () => {
    throw new TypeError("lookup failed");
  };
  assert.throws(
    () => fold.append(next.signed, next.body),
    (e: unknown) => e instanceof FoldError && e.reason === "internal_error" && e.seq === 4 && /lookup failed/.test(e.message),
  );
  assert.deepEqual(fold.head, head);

  // A genesis that does not verify is FoldError(-1, "bad_genesis"), from fromGenesis and foldLog alike.
  const badGenesis = clone(GENESIS);
  badGenesis.body.createdAt += 1;
  for (const fn of [() => RoomLogFold.fromGenesis(badGenesis), () => foldLog(badGenesis, []), () => RoomLogFold.fromGenesis("not a genesis")]) {
    assert.throws(fn, (e: unknown) => e instanceof FoldError && e.reason === "bad_genesis" && e.seq === -1);
  }
});
