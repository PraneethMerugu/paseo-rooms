// Module 1: state across daemon restarts (C-12 member rotation after restart, P-13 revocation
// durability). Uses a share-live lane on the throwaway parent (no new agent) and stops/starts the
// two TEST daemons only, through the paseo CLI with --home.
//
// The tests in this file are sequential steps of one scenario; a failed step can make later steps
// fail too. Read the first failure first. Evidence: <logdir>/restart-persistence.jsonl.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import {
  MEMBER_HOME,
  OWNER_HOME,
  PARENT,
  assertSafeEnvironment,
  closeQuietly,
  deviceKeyHash,
  harvestGrants,
  invite,
  joinedRecord,
  laneHost,
  log,
  memberRecordOnDisk,
  openLaneView,
  ownedLaneView,
  ownerClient,
  ownerSnapshot,
  record,
  rpc,
  sha256,
  sleep,
  startDaemon,
  stopDaemon,
  timed,
  until,
} from "./lib";

let c: any;
let a: any;
let lane: { id: string; serverId: string; roomId: string };
let baseline: ReturnType<typeof ownerSnapshot>;
let baselineDevice: string | null;
let baselineEvents: string[] = [];
let memberId = "";
let revokedMemberId = "";
let revokedGid = "";

const C = () => OWNER_HOME();
const A = () => MEMBER_HOME();

async function reconnectOwner() {
  await closeQuietly(c);
  c = await ownerClient(C(), "restart-owner");
}
async function reconnectMember() {
  await closeQuietly(a);
  a = await ownerClient(A(), "restart-member");
}
async function restartOwner(): Promise<{ stopMs: number; startMs: number }> {
  await closeQuietly(c);
  const stopMs = await stopDaemon(C());
  const startMs = await startDaemon(C());
  await reconnectOwner();
  return { stopMs, startMs };
}
async function restartMember(): Promise<{ stopMs: number; startMs: number }> {
  await closeQuietly(a);
  const stopMs = await stopDaemon(A());
  const startMs = await startDaemon(A());
  await reconnectMember();
  return { stopMs, startMs };
}
async function logEventHashes(): Promise<{ verified: boolean; error: string | null; hashes: string[]; types: string[] }> {
  const lg = await rpc(c, "rooms.log", { roomId: lane.roomId });
  return { verified: lg.verified, error: lg.error, hashes: lg.events.map((e: any) => sha256(JSON.stringify(e))), types: lg.events.map((e: any) => e.type) };
}

/** Keys, log chain and revocation list unchanged (or only appended to) since the baseline. */
async function assertOwnerStatePersisted(step: string) {
  const now = ownerSnapshot(C(), lane.id);
  const lg = await logEventHashes();
  const fields = {
    step,
    hostKeyUnchanged: now.hostKeyHash === baseline.hostKeyHash && now.hostKeyId === baseline.hostKeyId,
    laneKeyUnchanged: now.laneKeyHash !== null && now.laneKeyHash === baseline.laneKeyHash,
    logVerified: lg.verified,
    logPrefixPreserved: baselineEvents.every((h, i) => lg.hashes[i] === h),
    logEvents: lg.hashes.length,
    revokedListSuperset: [...baseline.revokedGids].every((g) => now.revokedGids.has(g)),
  };
  record("restart-persistence.jsonl", fields);
  log("owner_state", fields);
  assert.ok(fields.hostKeyUnchanged, "host key changed");
  assert.ok(fields.laneKeyUnchanged, "lane key changed or missing");
  assert.ok(fields.logVerified, `room log does not verify: ${lg.error}`);
  assert.ok(fields.logPrefixPreserved, "room log events before the restart changed");
  assert.ok(fields.revokedListSuperset, "revocation list lost entries");
  baselineEvents = lg.hashes;
  baseline = { ...now };
}

async function laneBackOnline(): Promise<{ endpointMs: number; memberHostMs: number }> {
  const s = Date.now();
  await until("lane endpoint online", async () => (await ownedLaneView(c, lane.id))?.lane.endpoint === "online", 90_000, 500);
  const endpointMs = Date.now() - s;
  await until("member lane host online", async () => (await laneHost(a, lane))?.status === "online", 90_000, 500);
  return { endpointMs, memberHostMs: Date.now() - s };
}

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(C(), "restart-owner");
  a = await ownerClient(A(), "restart-member");
  const created = await rpc(c, "rooms.create", { name: "Reliability restart", agentId: PARENT(), origin: "share", laneLabel: "Restart" });
  lane = { id: created.lane.id, serverId: created.lane.serverId, roomId: created.room.id };
  await until("share lane endpoint online", async () => (await ownedLaneView(c, lane.id))?.lane.endpoint === "online", 60_000, 500);
});

after(async () => {
  try {
    if ((await joinedRecord(a, lane.id).catch(() => null))?.status === "active") await rpc(a, "rooms.leave", { laneId: lane.id });
    await rpc(c, "rooms.lane.close", { laneId: lane.id });
  } catch {
    // Cleanup in run.sh stops the daemons and deletes the homes anyway.
  }
  await closeQuietly(a, c);
});

test("baseline: member enrolls on the share lane", { timeout: 120_000 }, async () => {
  const inv = await invite(c, lane.id, 3600);
  const j = await rpc(a, "rooms.join", { code: inv.code, label: "Reliability restart" });
  memberId = j.joined.memberId;
  harvestGrants();
  await until("member lane host online", async () => (await laneHost(a, lane))?.status === "online", 60_000, 250);
  baseline = ownerSnapshot(C(), lane.id);
  baselineDevice = deviceKeyHash(A());
  baselineEvents = (await logEventHashes()).hashes;
  assert.ok(baseline.laneKeyHash);
  assert.equal(baseline.memberStatus[memberId], "active");
});

test("owner restart while idle: keys, log and membership persist; lane recovers", { timeout: 360_000 }, async () => {
  const r = await restartOwner();
  await assertOwnerStatePersisted("owner_idle");
  const back = await laneBackOnline();
  record("restart-persistence.jsonl", { step: "owner_idle_recovery", ...r, ...back });
  assert.equal(ownerSnapshot(C(), lane.id).memberStatus[memberId], "active");
});

test("owner restart with a live read-only view open: view recovers", { timeout: 420_000 }, async () => {
  const view = await openLaneView(A(), lane.serverId);
  try {
    assert.ok((await timed(() => view.routed.fetchAgent(PARENT()))).ok, "view not readable before restart");
    const before = view.statuses.length;
    const r = await restartOwner();
    const dropped = view.statuses.slice(before).some((s) => s.status !== "connected");
    await assertOwnerStatePersisted("owner_live_view");
    const back = await laneBackOnline();
    const s = Date.now();
    const readable = await timed(() => until("view readable again", async () => (await timed(() => view.routed.fetchAgent(PARENT()))).ok, 120_000, 1000));
    record("restart-persistence.jsonl", { step: "owner_live_view_recovery", ...r, ...back, viewDropped: dropped, viewRecoveredMs: readable.ok ? Date.now() - s : null });
    assert.ok(readable.ok, "open view did not recover after owner restart");
  } finally {
    await closeQuietly(view.routed, view.origin);
  }
});

test("member restart while idle: device key and membership persist; lane recovers", { timeout: 360_000 }, async () => {
  const recBefore = memberRecordOnDisk(A(), lane.id);
  const r = await restartMember();
  const recAfter = memberRecordOnDisk(A(), lane.id);
  const back = await laneBackOnline();
  const fields = { step: "member_idle", ...r, ...back, deviceKeyUnchanged: deviceKeyHash(A()) === baselineDevice, statusAfter: recAfter?.status, sameGrantOrRotated: recAfter?.grantGid === recBefore?.grantGid || (recAfter?.grantExp ?? 0) > (recBefore?.grantExp ?? 0) };
  record("restart-persistence.jsonl", fields);
  assert.ok(fields.deviceKeyUnchanged, "member device key changed");
  assert.equal(recAfter?.status, "active");
  assert.ok(fields.sameGrantOrRotated);
});

test("member restart with a live read-only view open: a new view works after restart", { timeout: 360_000 }, async () => {
  const view = await openLaneView(A(), lane.serverId);
  assert.ok((await timed(() => view.routed.fetchAgent(PARENT()))).ok);
  const r = await restartMember();
  // The old view's origin connection was to the stopped daemon; report whether it came back on its own.
  const oldViewBack = await timed(() => until("old view readable", async () => (await timed(() => view.routed.fetchAgent(PARENT()))).ok, 30_000, 1000));
  await closeQuietly(view.routed, view.origin);
  const back = await laneBackOnline();
  const fresh = await openLaneView(A(), lane.serverId);
  try {
    const ok = await timed(() => fresh.routed.fetchAgent(PARENT()));
    record("restart-persistence.jsonl", { step: "member_live_view", ...r, ...back, oldViewRecoveredItself: oldViewBack.ok, freshViewReadable: ok.ok });
    assert.ok(ok.ok, "fresh view not readable after member restart");
  } finally {
    await closeQuietly(fresh.routed, fresh.origin);
  }
});

test("P-13: a revoked member stays revoked across owner and member restarts", { timeout: 600_000 }, async () => {
  revokedMemberId = memberId;
  revokedGid = ownerSnapshot(C(), lane.id).latestGrantGid[memberId];
  await rpc(c, "rooms.member.revoke", { memberId });
  await until(
    "member marks revoked and removes host",
    async () => (await joinedRecord(a, lane.id))?.status === "revoked" && !(await laneHost(a, lane)),
    60_000,
    500,
  );
  const snap = ownerSnapshot(C(), lane.id);
  assert.ok(snap.revokedGids.has(revokedGid), "revoked grant id not persisted before restart");
  baseline = snap;

  await restartOwner();
  await restartMember();
  await assertOwnerStatePersisted("after_revocation");
  const after = ownerSnapshot(C(), lane.id);
  // Watch for 20 s that the member does not come back (no host, still revoked on both sides).
  let hostSeen = false;
  for (let i = 0; i < 20; i++) {
    if (await laneHost(a, lane)) hostSeen = true;
    await sleep(1000);
  }
  const memberView = await joinedRecord(a, lane.id);
  const lg = await logEventHashes();
  const fields = {
    step: "revocation_durable",
    ownerStatus: after.memberStatus[revokedMemberId],
    revokedGidPersisted: after.revokedGids.has(revokedGid),
    memberStatus: memberView?.status ?? null,
    memberDiskStatus: memberRecordOnDisk(A(), lane.id)?.status ?? null,
    laneHostReappeared: hostSeen,
    logHasRevocation: lg.types.includes("member.revoked"),
  };
  record("restart-persistence.jsonl", fields);
  assert.equal(fields.ownerStatus, "revoked");
  assert.ok(fields.revokedGidPersisted);
  assert.equal(fields.memberStatus, "revoked");
  assert.equal(fields.laneHostReappeared, false);
  assert.ok(fields.logHasRevocation);
});

test("C-12: member grant rotation recovers after a restart across expiry", { timeout: 600_000 }, async () => {
  const inv = await invite(c, lane.id, 30);
  const j = await rpc(a, "rooms.join", { code: inv.code, label: "Reliability restart (short grant)" });
  memberId = j.joined.memberId;
  harvestGrants();
  await until("member lane host online", async () => (await laneHost(a, lane))?.status === "online", 60_000, 250);
  const rec0 = memberRecordOnDisk(A(), lane.id);
  const exp0 = (rec0?.grantExp ?? 0) * 1000;
  assert.ok(exp0 > Date.now(), "grant expiry not recorded");

  await closeQuietly(a);
  await stopDaemon(A());
  if (Date.now() < exp0 + 3000) await sleep(exp0 + 3000 - Date.now());
  await startDaemon(A()); // startDaemon probes rooms.bootstrap, which is a plugin RPC (first contact).
  const tStart = Date.now();

  // Observe from disk only (no further RPCs) for 15 s: did the parked rotation run on its own?
  let rotatedBeforeFurtherContact = false;
  for (let i = 0; i < 15 && !rotatedBeforeFurtherContact; i++) {
    rotatedBeforeFurtherContact = (memberRecordOnDisk(A(), lane.id)?.grantExp ?? 0) * 1000 > exp0;
    await sleep(1000);
  }
  await reconnectMember();
  const recovered = await timed(() =>
    until(
      "rotation after restart",
      async () => {
        const jr = await joinedRecord(a, lane.id);
        return jr?.status === "active" && Date.parse(jr.grantExpiresAt) > exp0 && (await laneHost(a, lane))?.status === "online" ? jr : null;
      },
      120_000,
      500,
    ),
  );
  harvestGrants();
  const fields = {
    step: "c12_rotation_after_restart",
    restartedMsAfterExpiry: tStart - exp0,
    rotatedBeforeFurtherContact,
    recovered: recovered.ok,
    recoveredMsAfterStart: recovered.ok ? Date.now() - tStart : null,
    error: recovered.ok ? null : recovered.error.message,
  };
  record("restart-persistence.jsonl", fields);
  log("c12", fields);
  assert.ok(recovered.ok, "member did not rotate and come back online after restart");
});

test("final: owner keys and log chain intact after all restarts", async () => {
  await assertOwnerStatePersisted("final");
});
