// Module 2: the M1 intermittent enrollment failure (M1-RESULTS open issue 8).
//
// N = 20 (RL_ENROLL_CYCLES overrides, capped at 50) sequential, ordinary cycles on one share-live lane
// bound to the throwaway parent (no new agent):
//   fresh invite -> rooms.join on the member -> lane host online on the member -> rooms.leave ->
//   lane host removed.
// No artificial delays: the M1 failure happened about 0.7 s after the member removed a host, which
// these back-to-back cycles reproduce naturally. Every step's timing is recorded; a failure records
// non-secret error details (name, message, code, cause / AggregateError chain, all redacted) plus
// redacted plugin log tails from both daemons. Evidence: <logdir>/enrollment-cycles.jsonl.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  LOGDIR,
  MEMBER_HOME,
  OWNER_HOME,
  PARENT,
  assertSafeEnvironment,
  closeQuietly,
  harvestGrants,
  invite,
  joinedRecord,
  laneHost,
  log,
  ownedLaneView,
  ownerClient,
  pluginLogs,
  record,
  rpc,
  timed,
  until,
} from "./lib";

const N = Math.min(50, Math.max(1, Number(process.env.RL_ENROLL_CYCLES ?? 20)));
let c: any;
let a: any;
let lane: { id: string; serverId: string } | null = null;
const results: Array<{ cycle: number; ok: boolean; failedStep: string | null }> = [];

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(OWNER_HOME(), "enroll-owner");
  a = await ownerClient(MEMBER_HOME(), "enroll-member");
  const created = await rpc(c, "rooms.create", { name: "Reliability enrollment", agentId: PARENT(), origin: "share", laneLabel: "Enroll" });
  lane = { id: created.lane.id, serverId: created.lane.serverId };
  await until("share lane endpoint online", async () => (await ownedLaneView(c, lane!.id))?.lane.endpoint === "online", 60_000, 500);
  log("enroll_lane_ready", { laneId: lane.id, cycles: N });
});

after(async () => {
  if (lane) {
    if ((await joinedRecord(a, lane.id).catch(() => null))?.status === "active") await rpc(a, "rooms.leave", { laneId: lane.id }).catch(() => undefined);
    await rpc(c, "rooms.lane.close", { laneId: lane.id }).catch(() => undefined);
  }
  await closeQuietly(a, c);
  const failed = results.filter((r) => !r.ok);
  writeFileSync(
    join(LOGDIR(), "enrollment-summary.json"),
    JSON.stringify({ cycles: results.length, failures: failed.length, failedCycles: failed }, null, 2),
  );
});

async function captureFailureContext(cycle: number, step: string): Promise<void> {
  const [member, owner] = await Promise.all([pluginLogs(MEMBER_HOME()).catch((e) => `unavailable: ${e}`), pluginLogs(OWNER_HOME()).catch((e) => `unavailable: ${e}`)]);
  const tail = (s: string) => s.split("\n").slice(-200).join("\n");
  writeFileSync(join(LOGDIR(), `enroll-failure-${cycle}-${step}-member.log`), tail(member));
  writeFileSync(join(LOGDIR(), `enroll-failure-${cycle}-${step}-owner.log`), tail(owner));
}

test(`enrollment: ${N} sequential invite -> join -> leave cycles`, { timeout: N * 120_000 }, async () => {
  assert.ok(lane);
  let previousLeaveDoneAt: number | null = null;
  for (let i = 1; i <= N; i++) {
    const row: Record<string, unknown> = { cycle: i, startedAt: new Date().toISOString(), msSincePreviousHostRemoved: previousLeaveDoneAt ? Date.now() - previousLeaveDoneAt : null };
    let failedStep: string | null = null;

    const inv = await timed(() => invite(c, lane!.id, 3600));
    row.inviteMs = inv.ms;
    if (!inv.ok) {
      failedStep = "invite";
      row.inviteError = inv.error;
    } else {
      const joined = await timed(() => rpc(a, "rooms.join", { code: inv.value.code, label: `Reliability ${i}` }));
      row.joinMs = joined.ms;
      if (!joined.ok) {
        failedStep = "join";
        row.joinError = joined.error;
        // Did the gateway see the enrollment? (M1: it did not.)
        const ov = await ownedLaneView(c, lane!.id).catch(() => null);
        row.ownerActiveMembersAfterFailure = ov ? ov.room.members.filter((m: any) => m.laneId === lane!.id && m.status === "active").length : null;
        row.memberRecordAfterFailure = await joinedRecord(a, lane!.id).then((j) => (j ? { status: j.status, hostStatus: j.hostStatus, hostError: j.hostError } : null)).catch(() => null);
      } else {
        harvestGrants();
        const online = await timed(() => until("lane host online", async () => (await laneHost(a, lane!))?.status === "online", 30_000, 100));
        row.hostOnlineMs = online.ms;
        if (!online.ok) {
          failedStep = "host_online";
          row.hostStatus = (await laneHost(a, lane!).catch(() => null))?.status ?? null;
        }
      }
      // Leave whenever the member holds an active membership, so the next cycle starts clean.
      if ((await joinedRecord(a, lane!.id).catch(() => null))?.status === "active") {
        const left = await timed(() => rpc(a, "rooms.leave", { laneId: lane!.id }));
        row.leaveMs = left.ms;
        if (!left.ok) {
          failedStep ??= "leave";
          row.leaveError = left.error;
        } else {
          const gone = await timed(() => until("lane host removed", async () => !(await laneHost(a, lane!)), 20_000, 100));
          row.hostRemovedMs = gone.ms;
          if (!gone.ok) failedStep ??= "host_removed";
          previousLeaveDoneAt = Date.now();
        }
      }
    }
    row.ok = failedStep === null;
    row.failedStep = failedStep;
    record("enrollment-cycles.jsonl", row);
    results.push({ cycle: i, ok: failedStep === null, failedStep });
    log(failedStep ? "CYCLE_FAIL" : "CYCLE_OK", { cycle: i, failedStep, joinMs: row.joinMs ?? null });
    if (failedStep) await captureFailureContext(i, failedStep);
  }
  const failed = results.filter((r) => !r.ok);
  assert.equal(failed.length, 0, `failed cycles: ${JSON.stringify(failed)} (details in enrollment-cycles.jsonl)`);
});

test("owner log chain verifies after the cycles and records every join and leave", async () => {
  const view = await ownedLaneView(c, lane!.id);
  const lg = await rpc(c, "rooms.log", { roomId: view.room.room.id });
  assert.equal(lg.verified, true, lg.error ?? "");
  const joins = lg.events.filter((e: any) => e.type === "member.joined").length;
  const leaves = lg.events.filter((e: any) => e.type === "member.left").length;
  const okCycles = results.filter((r) => r.ok).length;
  log("enroll_log", { events: lg.events.length, joins, leaves, okCycles });
  assert.ok(joins >= okCycles && leaves >= okCycles);
});
