// Module 2: enrollment reliability on identity v2 (enrollment-v2 SAS flow; the M1 intermittent
// enrollment failure, m1-results.md open issue 8, was in the lane host step that follows admission).
//
// N = 10 (RL_ENROLL_CYCLES overrides, capped at 20) sequential cycles. A member daemon can join a
// given room only once and v2 has no leave RPC yet, so every cycle uses a fresh room with one
// share-live lane on the throwaway parent (no new agent):
//   room + lane (both endpoints online) -> fresh invite -> join.start on the member -> both sides show
//   the SAS -> TEST-ONLY programmatic comparison (equal digits, never logged) -> join.confirm ->
//   join.admit -> member session open -> lane registered with a grant and its routed host online ->
//   member.remove -> member session ended (removed) -> lane host removed.
// No artificial delays: each cycle starts right after the previous lane host was removed, which is the
// M1 timing. Every step's timing is recorded; a failure records non-secret error details (redacted)
// and redacted plugin log tails of both daemons. Evidence: <logdir>/enrollment-cycles.jsonl.
// Rooms are not closed afterwards (closing needs the close delay); the run's cleanup stops the daemons.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  LOGDIR,
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
  joiningRoom,
  laneHost,
  laneOnline,
  log,
  ownedRoom,
  ownerClient,
  pluginLogs,
  record,
  timed,
  until,
  v2Ready,
  verifyOwnerLog,
  type RoomLane,
} from "./lib";

const N = Math.min(20, Math.max(1, Number(process.env.RL_ENROLL_CYCLES ?? 10)));
let c: any;
let a: any;
const results: Array<{ cycle: number; ok: boolean; failedStep: string | null; roomId: string | null; admitted: boolean; removed: boolean }> = [];

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(OWNER_HOME(), "enroll-owner");
  a = await ownerClient(MEMBER_HOME(), "enroll-member");
  await v2Ready(c);
  await v2Ready(a);
  log("enroll_start", { cycles: N });
});

after(async () => {
  await closeQuietly(a, c);
  const failed = results.filter((r) => !r.ok);
  writeFileSync(join(LOGDIR(), "enrollment-summary.json"), JSON.stringify({ cycles: results.length, failures: failed.length, failedCycles: failed }, null, 2));
});

async function captureFailureContext(cycle: number, step: string): Promise<void> {
  const [member, owner] = await Promise.all([pluginLogs(MEMBER_HOME()).catch((e) => `unavailable: ${e}`), pluginLogs(OWNER_HOME()).catch((e) => `unavailable: ${e}`)]);
  const tail = (s: string) => s.split("\n").slice(-200).join("\n");
  writeFileSync(join(LOGDIR(), `enroll-failure-${cycle}-${step}-member.log`), tail(member));
  writeFileSync(join(LOGDIR(), `enroll-failure-${cycle}-${step}-owner.log`), tail(owner));
}

test(`enrollment v2: ${N} sequential room -> invite -> SAS join -> admit -> lane -> remove cycles`, { timeout: N * 240_000 }, async () => {
  let previousHostRemovedAt: number | null = null;
  for (let i = 1; i <= N; i++) {
    const row: Record<string, unknown> = { cycle: i, startedAt: new Date().toISOString(), msSincePreviousHostRemoved: previousHostRemovedAt ? Date.now() - previousHostRemovedAt : null };
    const res = { cycle: i, ok: false, failedStep: null as string | null, roomId: null as string | null, admitted: false, removed: false };
    const fail = (step: string, error: unknown) => {
      res.failedStep ??= step;
      row[`${step}Error`] = error;
    };
    let room: RoomLane | null = null;
    const made = await timed(() => createRoomWithLane(c, PARENT(), `Enroll ${i}`));
    row.roomMs = made.ms;
    if (!made.ok) fail("room", made.error);
    else {
      room = made.value;
      res.roomId = room.roomId;
      const inv = await timed(() => invite(c, room!, `reliability cycle ${i}`));
      row.inviteMs = inv.ms;
      if (!inv.ok) fail("invite", inv.error);
      else {
        const joined = await timed(() => enroll(c, a, room!, inv.value.code, `Reliability ${i}`));
        row.enrollMs = joined.ms;
        if (!joined.ok) {
          fail("enroll", joined.error);
          // Where did it stop? States only (no SAS, no keys).
          row.memberJoinAfterFailure = await joiningRoom(a, room.roomId).then((j) => (j ? { state: j.state, connection: j.connection, failure: j.failure } : null)).catch(() => null);
          row.ownerCardsAfterFailure = await ownedRoom(c, room.roomId).then((r) => r?.joinRequests.map((x: any) => ({ state: x.state, closedReason: x.closedReason })) ?? null).catch(() => null);
        } else {
          res.admitted = true;
          row.steps = joined.value.steps;
          const online = await timed(() => laneOnline(a, room!, 60_000));
          row.laneOnlineMs = online.ms;
          harvestGrants();
          if (!online.ok) {
            fail("lane_online", online.error);
            row.laneAfterFailure = await joinedRoom(a, room.roomId).then((j) => j?.lanes.map((l: any) => ({ hostStatus: l.hostStatus, gid: !!l.gid, lastError: l.lastError })) ?? null).catch(() => null);
          }
          const removed = await timed(() => adminRpc(c, "rooms.v2.member.remove", { roomId: room!.roomId, memberId: joined.value.memberId }));
          row.removeMs = removed.ms;
          if (!removed.ok) fail("remove", removed.error);
          else {
            res.removed = true;
            const ended = await timed(() => until("member session ended", async () => {
              const j = await joinedRoom(a, room!.roomId);
              return j?.status === "ended" ? j : null;
            }, 30_000, 100));
            row.endedMs = ended.ms;
            if (!ended.ok) fail("ended", ended.error);
            else row.endedReason = ended.value.endedReason;
            const gone = await timed(() => until("lane host removed", async () => !(await laneHost(a, room!)), 30_000, 100));
            row.hostRemovedMs = gone.ms;
            if (!gone.ok) fail("host_removed", gone.error);
            previousHostRemovedAt = Date.now();
          }
        }
      }
    }
    res.ok = res.failedStep === null;
    row.ok = res.ok;
    row.failedStep = res.failedStep;
    record("enrollment-cycles.jsonl", row);
    results.push(res);
    log(res.ok ? "CYCLE_OK" : "CYCLE_FAIL", { cycle: i, failedStep: res.failedStep, enrollMs: row.enrollMs ?? null });
    if (res.failedStep) await captureFailureContext(i, res.failedStep);
  }
  const failed = results.filter((r) => !r.ok);
  assert.equal(failed.length, 0, `failed cycles: ${JSON.stringify(failed.map((f) => ({ cycle: f.cycle, step: f.failedStep })))} (details in enrollment-cycles.jsonl)`);
});

test("every cycle's room log verifies by an independent fold and holds the admission and the removal", () => {
  const problems: string[] = [];
  for (const r of results) {
    if (!r.roomId) continue;
    try {
      const lg = verifyOwnerLog(OWNER_HOME(), r.roomId);
      // The owner's own admission is in the genesis, not the log: each cycle adds exactly one member.
      const admitted = lg.types.filter((t) => t === "member.admitted").length;
      const removed = lg.types.filter((t) => t === "member.removed").length;
      if (r.admitted && admitted !== 1) problems.push(`cycle ${r.cycle}: member.admitted x${admitted}`);
      if (r.removed && removed !== 1) problems.push(`cycle ${r.cycle}: member.removed x${removed}`);
    } catch (e) {
      problems.push(`cycle ${r.cycle}: log does not verify (${String((e as Error).message).slice(0, 120)})`);
    }
  }
  log("enroll_logs", { rooms: results.filter((r) => r.roomId).length, problems: problems.length });
  assert.deepEqual(problems, []);
});
