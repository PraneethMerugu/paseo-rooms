// Module 3: read-only inspection of a fork lane agent's real process environment (C-1 / P-5).
//
// Creates ONE fork lane from the throwaway parent (this is throwaway agent #2). The gateway creates
// the fork without a prompt, runs its tripwire, then sends the instruction below, which is the only
// prompt the fork ever gets. While that first turn runs, /proc is sampled for processes carrying
// PASEO_ROOMS_LANE=<laneId>. Nothing else is sent to the agent.
//
// Expected: the guard checks pass (inert MCP only, no Paseo agent MCP URL). The isolation checks are
// marked `todo`: M1 forks run as the owner's OS user, so they are EXPECTED to fail and document the
// known owner-uid gap (HARDENING-PLAN "Correction to earlier claims", decision 2: watch-only).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { startSampler, summariseMcpServers, type ProcReport } from "./env-sampler";
import {
  LOGDIR,
  OWNER_HOME,
  PARENT,
  assertSafeEnvironment,
  closeQuietly,
  findStoredAgentRecord,
  listen,
  log,
  ownerClient,
  registerAgent,
  rpc,
  tcpOpen,
  timed,
} from "./lib";

const TRIVIAL_PROMPT = "Reply with the word OK and nothing else.";

let c: any;
let laneId = "";
let forkId = "";
let procs: ProcReport[] = [];
let stored: { file: string; rec: any } | null = null;
let ownerPortReachable = false;

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(OWNER_HOME(), "env-owner");
  const ownerListen = listen(OWNER_HOME());
  const sampler = startSampler({ ownerListen, match: (e) => e.has("PASEO_ROOMS_LANE") });
  try {
    const created = await timed(() =>
      rpc(c, "rooms.create", { name: "Reliability env inspection", agentId: PARENT(), origin: "fork", laneLabel: "Env", instruction: TRIVIAL_PROMPT }),
    );
    if (!created.ok) throw new Error(`rooms.create failed: ${created.error.message}`);
    laneId = created.value.lane.id;
    forkId = created.value.lane.agentId;
    registerAgent(forkId);
    log("fork_created", { laneId, fork: forkId.slice(0, 8), ms: created.ms });
    const done = await timed(() => c.waitForFinish(forkId, 180_000));
    log("fork_first_turn", { ok: done.ok, ms: done.ms, error: done.ok ? null : done.error.message });
    await new Promise((r) => setTimeout(r, 1000));
  } finally {
    procs = sampler.stop().filter((p) => !laneId || p.roomLane === laneId);
  }
  stored = findStoredAgentRecord(OWNER_HOME(), forkId);
  ownerPortReachable = await tcpOpen(Number(ownerListen.split(":").pop()));

  const parentControlPath = process.env.RL_PARENT_ENV_REPORT;
  const parentControl = parentControlPath && existsSync(parentControlPath) ? JSON.parse(readFileSync(parentControlPath, "utf8")) : null;
  const cfg = stored?.rec?.config ?? stored?.rec ?? {};
  const report = {
    laneId,
    forkAgent: forkId.slice(0, 8),
    storedConfig: stored
      ? {
          file: stored.file,
          mcpServers: summariseMcpServers(cfg.mcpServers),
          toolPolicyKeys: cfg.toolPolicy ? Object.keys(cfg.toolPolicy).sort() : [],
          envNames: cfg.env ? Object.keys(cfg.env).sort() : [],
          cwdIsParentCwd: null as boolean | null,
        }
      : null,
    forkProcesses: procs,
    ownerTestDaemonPortReachableFromSameNetns: ownerPortReachable,
    mainDaemonPortProbed: false,
    parentPositiveControl: parentControl
      ? { processes: parentControl.processes?.length ?? 0, withPaseoAgentMcpUrl: (parentControl.processes ?? []).filter((p: ProcReport) => p.cmdlineHasPaseoAgentMcpUrl).length }
      : "not available",
  };
  const parentRec = findStoredAgentRecord(OWNER_HOME(), PARENT());
  if (report.storedConfig && parentRec) report.storedConfig.cwdIsParentCwd = (parentRec.rec?.cwd ?? parentRec.rec?.config?.cwd) === (stored!.rec?.cwd ?? cfg.cwd);
  writeFileSync(join(LOGDIR(), "agent-environment.json"), JSON.stringify(report, null, 2), { mode: 0o600 });
  log("env_report_written", { file: "agent-environment.json", forkProcesses: procs.length });
});

after(async () => {
  if (laneId) await rpc(c, "rooms.lane.close", { laneId }).catch(() => undefined);
  await closeQuietly(c);
});

// ---------------------------------------------------------------- guard claims (expected to pass)
test("fork provider processes were observed during the first turn", () => {
  assert.ok(procs.length > 0, "no process with PASEO_ROOMS_LANE=<lane> was seen; the inspection is inconclusive");
});

test("stored fork config holds only the inert paseo MCP server and no preapprovals", () => {
  assert.ok(stored, "stored agent record not found");
  const cfg = stored!.rec?.config ?? stored!.rec;
  const servers = cfg?.mcpServers ?? {};
  assert.deepEqual(Object.keys(servers), ["paseo"]);
  assert.equal(servers.paseo.type, "stdio");
  assert.ok(String(servers.paseo.args?.[0] ?? "").endsWith("inert-mcp.cjs"));
  const toolPolicy = cfg?.toolPolicy;
  const preapproved = toolPolicy && typeof toolPolicy === "object" ? Object.values(toolPolicy).flat().filter(Boolean) : [];
  assert.equal(preapproved.length, 0, "toolPolicy carries preapprovals");
});

test("no fork process command line carries Paseo's agent MCP URL", () => {
  assert.equal(procs.filter((p) => p.cmdlineHasPaseoAgentMcpUrl || p.callerAgentIds.length > 0).length, 0);
});

test("parent positive control saw Paseo's agent MCP URL (validates the method)", (t) => {
  const p = process.env.RL_PARENT_ENV_REPORT;
  if (!p || !existsSync(p)) return t.skip("parent control report not available");
  const ctl = JSON.parse(readFileSync(p, "utf8"));
  assert.ok((ctl.processes ?? []).some((x: ProcReport) => x.cmdlineHasPaseoAgentMcpUrl));
});

// ---------------------------------------------------------------- isolation (known owner-uid gap)
const GAP = "known owner-uid gap (C-1/P-5): M1 forks run as the owner's OS user; expected to fail until sandboxed lanes exist";

test("fork runs under a different uid than the owner", { todo: GAP }, () => {
  assert.ok(procs.length > 0 && procs.every((p) => !p.sameUidAsSampler));
});

test("fork cannot read the test daemon's local credential", { todo: GAP }, () => {
  assert.ok(procs.every((p) => p.credentialReadable.paseoHomeLocalCredential !== true));
});

test("fork cannot read ~/.paseo/local-credential (access(2) check only)", { todo: GAP }, () => {
  assert.ok(procs.every((p) => !p.credentialReadable.mainHomeLocalCredential));
});

test("paseo CLI is not on the fork's PATH", { todo: GAP }, () => {
  assert.ok(procs.every((p) => p.pathDirsWithPaseoCli.length === 0));
});

test("fork env names no daemon address and no PASEO_HOME", { todo: GAP }, () => {
  assert.ok(procs.every((p) => p.envVarsMentioningOwnerDaemon.length === 0 && p.paseoHome === null));
});

test("fork has its own network namespace (daemon port unreachable)", { todo: GAP }, () => {
  assert.ok(procs.every((p) => !p.sameNetNs) || !ownerPortReachable);
});

test("fork has its own mount namespace", { todo: GAP }, () => {
  assert.ok(procs.every((p) => !p.sameMntNs));
});
