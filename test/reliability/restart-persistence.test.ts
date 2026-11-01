// Module 1: state across daemon restarts on identity v2 (P-13 revocation durability, the member's
// grant scheduler after a restart (C-12), and the member's verified log copy at rest, roadmap R2.1).
// Uses one room with a share-live lane on the throwaway parent (no new agent) and stops and starts
// the two TEST daemons only, through the paseo CLI with --home.
//
// The tests in this file are sequential steps of one scenario; a failed step can make later steps
// fail too. Read the first failure first. Evidence: <logdir>/restart-persistence.jsonl.
//
// What is compared: public key ids and server ids from `rooms.v2.status` (sealed files are re-sealed
// with a fresh nonce on every write, so their bytes are not a fingerprint), and the per-entry hashes of
// the owner's room log after an independent fold of the file. Nothing secret is logged.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MEMBER_HOME,
  OWNER_HOME,
  PARENT,
  adminRpc,
  assertSafeEnvironment,
  closeQuietly,
  createRoomWithLane,
  enroll,
  harvestGrants,
  invite,
  joinedRoom,
  laneHost,
  laneOnline,
  log,
  memberRoomDir,
  openLaneView,
  ownedRoom,
  ownerClient,
  ownerSnapshot,
  record,
  rpc,
  sleep,
  startDaemon,
  stopDaemon,
  timed,
  until,
  v2Ready,
  verifyOwnerLog,
  type RoomLane,
} from "./lib";

let c: any;
let a: any;
let room: RoomLane;
let baseline: Awaited<ReturnType<typeof ownerSnapshot>>;
let baselineHashes: string[] = [];
let memberId = "";
let deviceId = "";

const C = () => OWNER_HOME();
const A = () => MEMBER_HOME();

async function restartOwner(): Promise<{ stopMs: number; startMs: number }> {
  await closeQuietly(c);
  const stopMs = await stopDaemon(C());
  const startMs = await startDaemon(C());
  c = await ownerClient(C(), "restart-owner");
  await v2Ready(c);
  return { stopMs, startMs };
}
async function restartMember(): Promise<{ stopMs: number; startMs: number }> {
  await closeQuietly(a);
  const stopMs = await stopDaemon(A());
  const startMs = await startDaemon(A());
  a = await ownerClient(A(), "restart-member");
  await v2Ready(a);
  return { stopMs, startMs };
}

/** Keys and endpoints unchanged, log verifies and keeps every entry from before the restart. */
async function assertOwnerStatePersisted(step: string) {
  const now = await ownerSnapshot(c, room);
  const lg = verifyOwnerLog(C(), room.roomId);
  const fields = {
    step,
    hostKidUnchanged: now.hostKid !== null && now.hostKid === baseline.hostKid,
    adminKidUnchanged: now.adminKid !== null && now.adminKid === baseline.adminKid,
    endpointUnchanged: now.endpointServerId === baseline.endpointServerId,
    laneOfferUnchanged: now.laneServerId !== null && now.laneServerId === baseline.laneServerId,
    logVerified: true,
    logPrefixPreserved: baselineHashes.every((h, i) => lg.hashes[i] === h),
    logEntries: lg.hashes.length,
  };
  record("restart-persistence.jsonl", fields);
  log("owner_state", fields);
  assert.ok(fields.hostKidUnchanged, "host key changed");
  assert.ok(fields.adminKidUnchanged, "admin key changed");
  assert.ok(fields.endpointUnchanged, "room endpoint changed");
  assert.ok(fields.laneOfferUnchanged, "lane offer changed or missing");
  assert.ok(fields.logPrefixPreserved, "room log entries from before the restart changed");
  baselineHashes = lg.hashes;
  baseline = now;
}

/** Endpoints online on the owner; the member's session open (connects it if needed) and its lane host online. */
async function backOnline(): Promise<{ endpointMs: number; sessionMs: number; reconnectedItself: boolean; laneMs: number }> {
  const s = Date.now();
  await until("room and lane endpoints online", async () => {
    const r = await ownedRoom(c, room.roomId);
    return r?.endpoint === "online" && r.lanes.find((l: any) => l.laneId === room.laneId)?.endpoint === "online";
  }, 90_000, 500);
  const endpointMs = Date.now() - s;
  // Reported, not asserted: automatic member reconnect after the host restarts is an I-8 follow-up.
  const itself = await timed(() => until("member session reopened by itself", async () => (await joinedRoom(a, room.roomId))?.status === "open", 15_000, 500));
  if (!itself.ok) await rpc(a, "rooms.v2.room.connect", { roomId: room.roomId });
  await until("member session open", async () => (await joinedRoom(a, room.roomId))?.status === "open", 60_000, 500);
  const sessionMs = Date.now() - s;
  await laneOnline(a, room, 90_000);
  return { endpointMs, sessionMs, reconnectedItself: itself.ok, laneMs: Date.now() - s };
}

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(C(), "restart-owner");
  a = await ownerClient(A(), "restart-member");
  await v2Ready(c);
  await v2Ready(a);
  room = await createRoomWithLane(c, PARENT(), "Restart");
});

after(async () => {
  await closeQuietly(a, c);
});

test("baseline: member enrolls (SAS) and its lane comes online", { timeout: 180_000 }, async () => {
  const inv = await invite(c, room, "reliability restart");
  const j = await enroll(c, a, room, inv.code, "Reliability restart");
  memberId = j.memberId;
  deviceId = j.deviceId;
  await laneOnline(a, room);
  harvestGrants();
  baseline = await ownerSnapshot(c, room);
  baselineHashes = verifyOwnerLog(C(), room.roomId).hashes;
  assert.ok(baseline.roster.get(memberId)?.includes(deviceId), "member device in the owner's roster");
  assert.ok(baseline.grants.some((g) => g.deviceId === deviceId), "a current grant for the member's device");
});

test("owner restart while idle: keys, endpoints, log and roster persist; the member and lane recover", { timeout: 420_000 }, async () => {
  const r = await restartOwner();
  await assertOwnerStatePersisted("owner_idle");
  const back = await backOnline();
  record("restart-persistence.jsonl", { step: "owner_idle_recovery", ...r, ...back });
  assert.ok((await ownerSnapshot(c, room)).roster.get(memberId)?.includes(deviceId));
});

test("owner restart with a live read-only view open: the view recovers", { timeout: 480_000 }, async () => {
  const view = await openLaneView(A(), room.serverId);
  try {
    assert.ok((await timed(() => view.routed.fetchAgent(PARENT()))).ok, "view not readable before restart");
    const before = view.statuses.length;
    const r = await restartOwner();
    const dropped = view.statuses.slice(before).some((s) => s.status !== "connected");
    await assertOwnerStatePersisted("owner_live_view");
    const back = await backOnline();
    const s = Date.now();
    const readable = await timed(() => until("view readable again", async () => (await timed(() => view.routed.fetchAgent(PARENT()))).ok, 120_000, 1000));
    record("restart-persistence.jsonl", { step: "owner_live_view_recovery", ...r, ...back, viewDropped: dropped, viewRecoveredMs: readable.ok ? Date.now() - s : null });
    assert.ok(readable.ok, "open view did not recover after owner restart");
  } finally {
    await closeQuietly(view.routed, view.origin);
  }
});

test("member restart while idle: device, membership, grant and verified log copy persist (R2.1)", { timeout: 420_000 }, async () => {
  const before = await joinedRoom(a, room.roomId);
  const r = await restartMember();
  const startedHead = (await joinedRoom(a, room.roomId))?.head ?? null;
  const back = await backOnline();
  const after = await joinedRoom(a, room.roomId);
  const lane = after?.lanes.find((l: any) => l.laneId === room.laneId);
  const logDir = join(memberRoomDir(A(), room.roomId), "log");
  const headFile = join(logDir, "head.sealed");
  const copySealed = existsSync(headFile) && existsSync(join(logDir, "seg-000000.sealed")) && /"typ":"sealed"/.test(readFileSync(headFile, "utf8")) && !readFileSync(headFile, "utf8").includes("hsig");
  const fields = {
    step: "member_idle",
    ...r,
    ...back,
    sameDevice: after?.deviceId === deviceId && after?.memberId === memberId,
    headNotBehind: (after?.head.seq ?? -1) >= (before?.head.seq ?? 0),
    restoredBeforeSync: startedHead !== null && startedHead.seq >= (before?.head.seq ?? 0),
    alerts: (after?.alerts ?? []).map((x: any) => x.type),
    copySealed,
    grantCurrent: !!lane?.gid && lane.lifetimeMs > 0,
  };
  record("restart-persistence.jsonl", fields);
  assert.ok(fields.sameDevice, "member device or membership changed");
  assert.ok(fields.headNotBehind, "member head went back");
  assert.deepEqual(fields.alerts, [], "no alerts after an honest restart");
  assert.ok(copySealed, "the member's log copy is on disk and sealed");
  assert.ok(fields.grantCurrent, "no current grant after the member restart");
});

test("member restart with a live read-only view open: a new view works after the restart", { timeout: 420_000 }, async () => {
  const view = await openLaneView(A(), room.serverId);
  assert.ok((await timed(() => view.routed.fetchAgent(PARENT()))).ok);
  const r = await restartMember();
  // The old view's origin connection was to the stopped daemon; report whether it came back on its own.
  const oldViewBack = await timed(() => until("old view readable", async () => (await timed(() => view.routed.fetchAgent(PARENT()))).ok, 30_000, 1000));
  await closeQuietly(view.routed, view.origin);
  const back = await backOnline();
  const fresh = await openLaneView(A(), room.serverId);
  try {
    const ok = await timed(() => fresh.routed.fetchAgent(PARENT()));
    record("restart-persistence.jsonl", { step: "member_live_view", ...r, ...back, oldViewRecoveredItself: oldViewBack.ok, freshViewReadable: ok.ok });
    assert.ok(ok.ok, "fresh view not readable after member restart");
  } finally {
    await closeQuietly(fresh.routed, fresh.origin);
  }
});

test("P-13: a removed member stays removed across owner and member restarts", { timeout: 720_000 }, async () => {
  const removed = await adminRpc(c, "rooms.v2.member.remove", { roomId: room.roomId, memberId });
  await until("member session ended and lane host removed", async () => {
    const j = await joinedRoom(a, room.roomId);
    return j?.status === "ended" && j.endedReason === "removed" && !(await laneHost(a, room));
  }, 60_000, 500);
  await restartOwner();
  await restartMember();
  await assertOwnerStatePersisted("after_removal");
  // A new session of the removed device must end again; watch 20 s that the lane host does not return.
  const again = await rpc(a, "rooms.v2.room.connect", { roomId: room.roomId }).catch((e: unknown) => ({ status: "error", lastError: String((e as Error).message).slice(0, 80) }));
  let hostSeen = false;
  for (let i = 0; i < 20; i++) {
    if (await laneHost(a, room)) hostSeen = true;
    await sleep(1000);
  }
  const snap = await ownerSnapshot(c, room);
  const lg = verifyOwnerLog(C(), room.roomId);
  const fields = {
    step: "removal_durable",
    removedSeq: removed.seq,
    ownerRosterHasMember: snap.roster.has(memberId),
    ownerGrantsForDevice: snap.grants.filter((g) => g.deviceId === deviceId).length,
    newSession: again.status,
    newSessionError: again.lastError,
    memberStatus: (await joinedRoom(a, room.roomId))?.status ?? null,
    laneHostReappeared: hostSeen,
    logHasRemoval: lg.types.includes("member.removed"),
  };
  record("restart-persistence.jsonl", fields);
  assert.equal(fields.ownerRosterHasMember, false);
  assert.equal(fields.ownerGrantsForDevice, 0);
  assert.equal(fields.newSession, "ended");
  assert.equal(fields.newSessionError, "access_ended");
  assert.equal(fields.laneHostReappeared, false);
  assert.ok(fields.logHasRemoval);
});

test("final: owner keys and log chain intact after all restarts", async () => {
  await assertOwnerStatePersisted("final");
});
