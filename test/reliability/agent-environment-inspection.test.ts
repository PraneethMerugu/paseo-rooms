// Module 3: read-only inspection of the shared agent's real process environment (C-1 / P-5, identity v2).
//
// v2 shares the live agent only (no fork lanes, I-15). So the agent a room exposes is the owner's own
// throwaway parent, and the question is what sharing changes about it and what it could reach. The
// module creates a room with a share-live lane on the parent and one invite (never used), then sends the
// parent ONE trivial prompt (the second and last model turn of the run). While that turn runs, /proc is
// sampled for the parent's provider processes (command line carrying the owner test daemon's
// `/mcp/agents` URL, the same match as the positive control run.sh takes during the parent's first
// turn, before anything was shared). Nothing else is sent to the agent.
//
// Read-only: env and command lines come from /proc; file checks use access(2) only and never open the
// file (the test home's local-credential, ~/.paseo/local-credential, the plugin's fallback KEK file).
// The main daemon (6767) is never contacted. Values are reported only for a short allowlist of
// non-secret variables; tracked secrets are matched in memory and only variable names are reported.
//
// Expected: sharing changes nothing (stored config, env names) and no room secret reaches the agent.
// The isolation checks are marked `todo`: a share-live agent is the owner's own agent and runs as the
// owner's OS user by design, so it can reach what the owner can. They document that reach; viewers
// cannot prompt the agent (lane permissions are workspace.read only, checked in the e2e).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { startSampler, summariseMcpServers, ROOM_LANE_ENV, type ProcReport } from "./env-sampler";
import {
  LOGDIR,
  OWNER_HOME,
  PARENT,
  SECRETS_FILE,
  assertSafeEnvironment,
  closeQuietly,
  createRoomWithLane,
  findStoredAgentRecord,
  invite,
  listen,
  log,
  ownerClient,
  tcpOpen,
  timed,
  v2Ready,
  type RoomLane,
} from "./lib";

const TRIVIAL_PROMPT = "Reply with the word OK and nothing else.";

let c: any;
let room: RoomLane | null = null;
let procs: ProcReport[] = [];
let control: { processes?: ProcReport[] } | null = null;
let configBefore: ReturnType<typeof configSummary> = null;
let configAfter: ReturnType<typeof configSummary> = null;
let ownerPortReachable = false;

function configSummary(): { mcpServers: Record<string, unknown>; toolPolicyKeys: string[]; envNames: string[] } | null {
  const stored = findStoredAgentRecord(OWNER_HOME(), PARENT());
  if (!stored) return null;
  const cfg = stored.rec?.config ?? stored.rec ?? {};
  return {
    mcpServers: summariseMcpServers(cfg.mcpServers),
    toolPolicyKeys: cfg.toolPolicy ? Object.keys(cfg.toolPolicy).sort() : [],
    envNames: cfg.env ? Object.keys(cfg.env).sort() : [],
  };
}

function envNames(list: ProcReport[]): string[] {
  return [...new Set(list.flatMap((p) => Object.keys(p.paseoRelatedEnv)))].sort();
}

before(async () => {
  assertSafeEnvironment();
  c = await ownerClient(OWNER_HOME(), "env-owner");
  await v2Ready(c);
  configBefore = configSummary();
  room = await createRoomWithLane(c, PARENT(), "Env");
  await invite(c, room, "reliability env inspection (never used)");
  configAfter = configSummary();
  const secrets = existsSync(SECRETS_FILE()) ? readFileSync(SECRETS_FILE(), "utf8").split("\n").filter((x) => x.trim().length >= 20) : [];
  const ownerListen = listen(OWNER_HOME());
  const sampler = startSampler({ ownerListen, secrets, match: (_e, args) => args.join(" ").includes(`${ownerListen}/mcp/agents`) });
  try {
    const sent = await timed(() => c.sendAgentMessage(PARENT(), TRIVIAL_PROMPT));
    log("shared_agent_prompted", { ok: sent.ok, error: sent.ok ? null : sent.error.message });
    const done = await timed(() => c.waitForFinish(PARENT(), 180_000));
    log("shared_agent_turn", { ok: done.ok, ms: done.ms, error: done.ok ? null : done.error.message });
    await new Promise((r) => setTimeout(r, 1000));
  } finally {
    procs = sampler.stop();
  }
  ownerPortReachable = await tcpOpen(Number(ownerListen.split(":").pop()));
  const p = process.env.RL_PARENT_ENV_REPORT;
  control = p && existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
  const report = {
    roomId: room.roomId,
    laneId: room.laneId,
    sharedAgent: PARENT().slice(0, 8),
    storedConfig: { beforeSharing: configBefore, afterSharing: configAfter },
    sharedAgentProcesses: procs,
    envNamesBeforeSharing: control ? envNames(control.processes ?? []) : "not available",
    envNamesAfterSharing: envNames(procs),
    ownerTestDaemonPortReachableFromSameNetns: ownerPortReachable,
    mainDaemonPortProbed: false,
    secretsTracked: secrets.length,
  };
  writeFileSync(join(LOGDIR(), "agent-environment.json"), JSON.stringify(report, null, 2), { mode: 0o600 });
  log("env_report_written", { file: "agent-environment.json", processes: procs.length });
});

after(async () => {
  await closeQuietly(c);
});

// ---------------------------------------------------------------- what sharing changes (expected to pass)
test("the shared agent's provider processes were observed during the post-share turn", () => {
  assert.ok(procs.length > 0, "no process carrying the owner's /mcp/agents URL was seen; the inspection is inconclusive");
});

test("sharing changes neither the agent's stored MCP servers, tool policy nor env", () => {
  assert.ok(configBefore && configAfter, "stored agent record not found");
  assert.deepEqual(configAfter, configBefore);
});

test("sharing adds no environment variable to the agent's processes", (t) => {
  if (!control) return t.skip("positive control report not available");
  const before = new Set(envNames(control.processes ?? []));
  const added = envNames(procs).filter((n) => !before.has(n));
  assert.deepEqual(added, []);
  assert.ok(procs.every((p) => p.roomLane === null), `no ${ROOM_LANE_ENV} marker`);
});

test("no room secret (invite code or token) is in the agent's environment or command line", () => {
  assert.ok(procs.every((p) => p.envVarsWithTrackedSecret.length === 0 && !p.cmdlineHasTrackedSecret));
});

test("positive control saw Paseo's agent MCP URL before sharing (validates the method)", (t) => {
  if (!control) return t.skip("positive control report not available");
  assert.ok((control.processes ?? []).some((x) => x.cmdlineHasPaseoAgentMcpUrl));
});

// ---------------------------------------------------------------- reach of the owner's own agent (by design)
const BY_DESIGN = "share-live: the shared agent is the owner's own agent and runs as the owner's OS user; this documents its reach (sandboxed lanes do not exist)";

test("the shared agent runs under a different uid than the owner", { todo: BY_DESIGN }, () => {
  assert.ok(procs.length > 0 && procs.every((p) => !p.sameUidAsSampler));
});

test("the shared agent cannot read the test daemon's local credential (access(2) only)", { todo: BY_DESIGN }, () => {
  assert.ok(procs.every((p) => p.credentialReadable.paseoHomeLocalCredential !== true));
});

test("the shared agent cannot read ~/.paseo/local-credential (access(2) only)", { todo: BY_DESIGN }, () => {
  assert.ok(procs.every((p) => !p.credentialReadable.mainHomeLocalCredential));
});

test("the shared agent cannot read the Rooms fallback KEK file or data directory (access(2) only)", { todo: BY_DESIGN }, () => {
  assert.ok(procs.every((p) => p.roomsDataReadable.kekFallbackFile !== true && p.roomsDataReadable.dataDir !== true));
});

test("paseo CLI is not on the shared agent's PATH", { todo: BY_DESIGN }, () => {
  assert.ok(procs.every((p) => p.pathDirsWithPaseoCli.length === 0));
});

test("the shared agent has its own network namespace (daemon port unreachable)", { todo: BY_DESIGN }, () => {
  assert.ok(procs.every((p) => !p.sameNetNs) || !ownerPortReachable);
});
