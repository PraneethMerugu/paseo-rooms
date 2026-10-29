// End-to-end driver. Talks to owner C and member A like the CLI and the app do:
//   - plugin RPCs via an owner DaemonClient (local credential),
//   - the lane through A exactly as the app opens a routed host
//     (DaemonClient + createHostChannelTransport over A's connection).
// Prints evidence as JSON lines. Never prints invite codes, grants or credentials.
import { appendFileSync, chmodSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";
import { createHostChannelTransport } from "@getpaseo/client/internal/hosts";

const C = process.env.E2E_OWNER_HOME!;
const A = process.env.E2E_MEMBER_HOME!;
const PARENT = process.env.E2E_PARENT!;
const AGENTS_FILE = process.env.E2E_AGENTS_FILE!;
const SECRETS_FILE = process.env.E2E_SECRETS_FILE!;
const PLUGIN = "rooms";
const T0 = Date.now();

let failures = 0;
function log(event: string, fields: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ t: ((Date.now() - T0) / 1000).toFixed(2), event, ...fields }));
}
function check(name: string, ok: boolean, fields: Record<string, unknown> = {}) {
  if (!ok) failures++;
  log(ok ? "PASS" : "FAIL", { check: name, ...fields });
}
function rememberSecret(s: string) {
  if (!existsSync(SECRETS_FILE)) writeFileSync(SECRETS_FILE, "", { mode: 0o600 });
  chmodSync(SECRETS_FILE, 0o600);
  appendFileSync(SECRETS_FILE, s + "\n");
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until<T>(what: string, f: () => Promise<T | null | undefined | false> | T | null | undefined | false, timeoutMs = 30_000, stepMs = 250): Promise<T> {
  const s = Date.now();
  for (;;) {
    const v = await f();
    if (v) return v as T;
    if (Date.now() - s > timeoutMs) throw new Error(`timeout: ${what}`);
    await sleep(stepMs);
  }
}

function listen(home: string) {
  return JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
}
function cred(home: string) {
  return readFileSync(join(home, "local-credential"), "utf8").trim();
}
const wsFactory = (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any;

async function ownerClient(home: string, name: string): Promise<any> {
  const c: any = new DaemonClient({
    url: `ws://${listen(home)}/ws`,
    clientId: `rooms-e2e-${name}-${randomUUID().slice(0, 8)}`,
    clientType: "cli",
    appVersion: "0.13.2",
    localCredential: () => cred(home),
    webSocketFactory: wsFactory,
    reconnect: { enabled: false },
  } as any);
  await c.connect();
  return c;
}
async function rpc(client: any, method: string, input: unknown): Promise<any> {
  return client.invokePluginRpc(PLUGIN, method, input);
}
async function timed<T>(f: () => Promise<T>) {
  const s = performance.now();
  try {
    return { ok: true as const, value: await f(), ms: Math.round(performance.now() - s) };
  } catch (e) {
    return { ok: false as const, error: String((e as Error)?.message ?? e).slice(0, 160), code: (e as any)?.code, ms: Math.round(performance.now() - s) };
  }
}

/** Collect grant passwords stored by A (for the secret scan only; never printed). */
function harvestGrants() {
  const p = join(A, "hosts.json");
  if (!existsSync(p)) return;
  const text = readFileSync(p, "utf8");
  for (const m of text.matchAll(/prg1\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]{86})/g)) rememberSecret(m[1]);
}

function findAgentRecord(home: string, agentId: string): any | null {
  const stack = [home];
  while (stack.length) {
    const d = stack.pop()!;
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!["models", "node_modules", "plugins", "plugin-data"].includes(name)) stack.push(p);
      } else if (name.endsWith(".json") && st.size < 5_000_000) {
        const text = readFileSync(p, "utf8");
        if (!text.includes(agentId) || !text.includes("mcpServers")) continue;
        try {
          const j = JSON.parse(text);
          const rec = j.id === agentId ? j : Array.isArray(j) ? j.find((x: any) => x?.id === agentId) : null;
          if (rec) return { file: p.slice(home.length + 1), rec };
        } catch {}
      }
    }
  }
  return null;
}

function scanProcesses() {
  let parentPaseoMcp = 0;
  let forkPaseoMcp = 0;
  let inertMcp = 0;
  let anyPaseoMcpOnC = 0;
  let scanned = 0;
  for (const pid of readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(pid)) continue;
    let cmd = "";
    try {
      cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8");
    } catch {
      continue;
    }
    scanned++;
    if (cmd.includes(`callerAgentId=${PARENT}`)) parentPaseoMcp++;
    if (FORK_ID && cmd.includes(`callerAgentId=${FORK_ID}`)) forkPaseoMcp++;
    if (cmd.includes("inert-mcp.cjs")) inertMcp++;
    if (cmd.includes("127.0.0.1:6891/mcp/agents")) anyPaseoMcpOnC++;
  }
  return { scanned, parentPaseoMcp, forkPaseoMcp, inertMcp, anyPaseoMcpOnC };
}
let FORK_ID = "";

async function main() {
  const c = await ownerClient(C, "owner");
  const a = await ownerClient(A, "member");
  log("connected", { ownerVersion: c.getLastServerInfoMessage()?.version, memberVersion: a.getLastServerInfoMessage()?.version });

  // ---------------------------------------------------------------- 1. create room + fork lane on C
  const created = await timed(() =>
    rpc(c, "rooms.create", { name: "E2E room", agentId: PARENT, origin: "fork", laneLabel: "Fork", instruction: "Reply with the word OK and nothing else." }),
  );
  check("room created via plugin RPC", created.ok, { ms: created.ms, error: created.ok ? null : created.error });
  if (!created.ok) throw new Error("cannot continue");
  const { room, lane } = created.value;
  const FORK = lane.agentId as string;
  FORK_ID = FORK;
  appendFileSync(AGENTS_FILE, FORK + "\n");
  log("lane", { roomId: room.id, laneId: lane.id, laneServerId: lane.serverId.slice(0, 12), origin: lane.origin, forkAgent: FORK.slice(0, 8), parent: PARENT.slice(0, 8) });
  check("fork is a new agent with parent link", FORK !== PARENT && lane.origin.kind === "fork" && lane.origin.parentAgentId === PARENT);
  const fork = await c.fetchAgent(FORK);
  check("fork labels", fork?.agent?.labels?.["rooms.lane"] === lane.id, { labels: fork?.agent?.labels, parentAgentId: fork?.agent?.parentAgentId ?? null });
  check("fork seeded with curated context", lane.origin.contextItems >= 2, { contextItems: lane.origin.contextItems, contextChars: lane.origin.contextChars });

  // MCP guard: the stored config must hold the inert "paseo" server (Paseo then skips its injection).
  const stored = findAgentRecord(C, FORK);
  const mcp = stored?.rec?.config?.mcpServers ?? stored?.rec?.mcpServers ?? null;
  check("fork config shadows Paseo MCP with inert stdio server", !!mcp?.paseo && mcp.paseo.type === "stdio" && String(mcp.paseo.args?.[0] ?? "").endsWith("inert-mcp.cjs"), {
    file: stored?.file ?? null,
    paseoServer: mcp?.paseo ? { type: mcp.paseo.type, script: String(mcp.paseo.args?.[0] ?? "").split("/").pop() } : null,
  });
  const parentRec = findAgentRecord(C, PARENT);
  log("parent_config_mcp", { file: parentRec?.file ?? null, mcpServers: Object.keys(parentRec?.rec?.config?.mcpServers ?? {}) });

  const forkDone = await timed(() => c.waitForFinish(FORK, 180_000));
  check("fork first turn finished", forkDone.ok, { ms: forkDone.ms, error: forkDone.ok ? null : forkDone.error });
  const forkTl = await c.fetchAgentTimeline(FORK, { direction: "tail", limit: 10 });
  const forkReply = forkTl.entries.filter((e: any) => e.item.type === "assistant_message").map((e: any) => e.item.text).join(" ").slice(0, 60);
  log("fork_reply", { reply: forkReply });
  // Launch-level check: the provider processes' command lines (read from /proc, never printed) must
  // show Paseo's agent MCP URL for the parent (positive control) and only the inert server for the fork.
  const parentProcs = JSON.parse(readFileSync(process.env.E2E_PARENT_PROCS!, "utf8"));
  log("mcp_positive_control", { parentProvidersWithPaseoMcp: parentProcs.paseoAgentMcpOnC });

  // share-live lane on the parent: no new agent, the lane is bound to the parent itself
  const share = await timed(() => rpc(c, "rooms.lane.create", { roomId: room.id, agentId: PARENT, origin: "share", laneLabel: "Live" }));
  check("share-live lane binds the existing agent (no new agent)", share.ok && share.value.lane.agentId === PARENT && share.value.lane.origin.kind === "share", {
    error: share.ok ? null : share.error,
  });
  if (share.ok) {
    const shareOnline = await timed(() =>
      until("share lane endpoint online", async () => (await rpc(c, "rooms.overview", {})).owned[0].lanes.find((l: any) => l.lane.id === share.value.lane.id)?.endpoint === "online", 20_000),
    );
    check("share lane endpoint online on the relay", shareOnline.ok, { ms: shareOnline.ms });
    await rpc(c, "rooms.lane.close", { laneId: share.value.lane.id });
  }

  // ---------------------------------------------------------------- 2. invite + enroll from A
  const inv = await rpc(c, "rooms.invite.create", { laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
  rememberSecret(inv.code);
  rememberSecret(JSON.parse(Buffer.from(inv.code.slice(5), "base64url").toString()).token);
  check("invite code format", inv.code.startsWith("prc1.") && inv.code.length < 1200, { length: inv.code.length, expiresAt: inv.expiresAt });
  const joined = await timed(() => rpc(a, "rooms.join", { code: inv.code, label: "Member A" }));
  check("member A enrolled via plugin RPC", joined.ok, { ms: joined.ms, error: joined.ok ? null : joined.error, status: joined.ok ? joined.value.joined.status : null });
  if (!joined.ok) throw new Error("cannot continue");
  harvestGrants();
  const reuse = await timed(() => rpc(a, "rooms.join", { code: inv.code, label: "Member A again" }));
  check("invite is one-time", !reuse.ok && /already used|token_used/i.test(reuse.error ?? ""), { error: reuse.ok ? null : reuse.error });

  // ---------------------------------------------------------------- 3. app-style client through A
  const origin: any = new DaemonClient({
    url: `ws://${listen(A)}/ws`,
    clientId: `rooms-e2e-app-${randomUUID().slice(0, 8)}`,
    clientType: "mobile",
    appVersion: "0.13.2",
    localCredential: () => cred(A),
    webSocketFactory: wsFactory,
  } as any);
  await origin.connect();
  const hostsSeen: any[] = [];
  const obs = origin.observeHosts();
  obs.subscribe({
    snapshot: (d: any) => hostsSeen.push(d),
    update: (m: any) => m.type === "hosts.changed" && hostsSeen.push(m.payload.directory),
  });
  const laneHost = () => origin.listHosts().then((d: any) => d.hosts.find((h: any) => h.serverId === lane.serverId || h.source?.key === lane.id));
  const online = await timed(() => until("lane online on A", async () => (await laneHost())?.status === "online" && laneHost(), 30_000));
  check("lane visible as routed host on A", online.ok, { ms: online.ms, host: online.ok ? { label: online.value.label, status: online.value.status, source: online.value.source?.id } : null });

  const openRouted = () => {
    const clientId = randomUUID();
    return new DaemonClient({
      url: "ws://routed-host/ws",
      clientId,
      clientType: "mobile",
      appVersion: "0.13.2",
      transportFactory: createHostChannelTransport(origin, lane.serverId, clientId, null),
    } as any) as any;
  };
  const routed = openRouted();
  const streamEvents: Record<string, number> = {};
  routed.subscribeRawMessages((m: any) => {
    if (m.type === "agent_stream") {
      const k = `${m.payload?.event?.type}${m.payload?.event?.item?.type ? ":" + m.payload.event.item.type : ""}`;
      streamEvents[k] = (streamEvents[k] ?? 0) + 1;
    }
  });
  const statusLog: Array<{ at: number; status: string }> = [];
  routed.subscribeConnectionStatus((s: any) => statusLog.push({ at: Date.now(), status: s.status }));
  const rc = await timed(() => routed.connect());
  check("routed session connects", rc.ok, { ms: rc.ms, error: rc.ok ? null : rc.error });
  const info = routed.getLastServerInfoMessage();
  check("routed server_info is the lane, workspace.read only", info?.serverId === lane.serverId && JSON.stringify(info?.permissions) === '["workspace.read"]', {
    permissions: info?.permissions,
    features: Object.keys(info?.features ?? {}).sort(),
  });
  const ws = await routed.fetchWorkspaces();
  const ag = await routed.fetchAgents();
  const ids = ag.entries.map((e: any) => e.agent.id);
  check("exactly one agent visible (the fork)", ids.length === 1 && ids[0] === FORK, { agents: ids.map((x: string) => x.slice(0, 8)), workspaces: ws.entries.length });
  const tl = await routed.fetchAgentTimeline(FORK, { direction: "tail", limit: 20 });
  check("lane timeline readable", tl.entries.length >= 2, { entries: tl.entries.length, types: tl.entries.map((e: any) => e.item.type) });

  const fake = randomUUID();
  const denials: Array<[string, () => Promise<unknown>]> = [
    ["fetchAgent(parent in same daemon)", () => routed.fetchAgent(PARENT)],
    ["fetchAgent(random id)", () => routed.fetchAgent(fake)],
    ["fetchAgent(prefix of fork id)", () => routed.fetchAgent(FORK.slice(0, 8))],
    ["fetchAgent(title of fork)", () => routed.fetchAgent("E2E room · fork")],
    ["fetchAgentTimeline(parent)", () => routed.fetchAgentTimeline(PARENT, { direction: "tail", limit: 5 })],
    ["sendAgentMessage(fork)", () => routed.sendAgentMessage(FORK, "should be denied")],
    ["cancelAgent(fork)", () => routed.cancelAgent(FORK)],
    ["archiveAgent(fork)", () => routed.archiveAgent(FORK)],
    ["listTerminals", () => routed.listTerminals("/tmp")],
    ["getDaemonConfig", () => routed.getDaemonConfig()],
    ["listHosts on routed session", () => routed.listHosts()],
    ["invokePluginRpc on routed session", () => routed.invokePluginRpc(PLUGIN, "rooms.overview", {})],
  ];
  const denialResults = [];
  for (const [op, f] of denials) {
    const r = await timed(f);
    denialResults.push({ op, denied: !r.ok && /not authorized|access_denied|denied/i.test(`${r.error} ${r.code ?? ""}`), ms: r.ms, error: r.ok ? `LEAK ${JSON.stringify(r.value).slice(0, 60)}` : r.error?.slice(0, 70) });
  }
  check("all out-of-scope operations denied", denialResults.every((d) => d.denied), { denials: denialResults });

  // live timeline: prompt the fork on C, watch it through the lane
  const sub = routed.observeTimeline([FORK]);
  await sub.ready?.catch(() => undefined);
  const before = { ...streamEvents };
  const tPrompt = Date.now();
  const procMax = { forkPaseoMcp: 0, inertMcp: 0, anyPaseoMcpOnC: 0 };
  const sampler = setInterval(() => {
    const p = scanProcesses();
    procMax.forkPaseoMcp = Math.max(procMax.forkPaseoMcp, p.forkPaseoMcp);
    procMax.inertMcp = Math.max(procMax.inertMcp, p.inertMcp);
    procMax.anyPaseoMcpOnC = Math.max(procMax.anyPaseoMcpOnC, p.anyPaseoMcpOnC);
  }, 50);
  await c.sendAgentMessage(FORK, "Reply with the word OK and nothing else.");
  await until("live turn through lane", () => (streamEvents["turn_completed"] ?? 0) > (before["turn_completed"] ?? 0), 120_000, 200);
  clearInterval(sampler);
  const parentControl = JSON.parse(readFileSync(process.env.E2E_PARENT_PROCS!, "utf8")).paseoAgentMcpOnC;
  check("fork provider process runs without Paseo MCP (parent had it: positive control)", parentControl > 0 && procMax.forkPaseoMcp === 0 && procMax.inertMcp > 0, {
    parentControl,
    ...procMax,
  });
  check("live turn streamed through the lane", (streamEvents["turn_started"] ?? 0) > (before["turn_started"] ?? 0) && (streamEvents["timeline:assistant_message"] ?? 0) > 0, {
    ms: Date.now() - tPrompt,
    streamEvents,
  });

  // owner view
  const ov = await rpc(c, "rooms.overview", {});
  const ownedLane = ov.owned[0]?.lanes.find((l: any) => l.lane.id === lane.id);
  check("owner overview shows 1 connected member", ownedLane?.connectedMembers === 1 && ov.owned[0].members.length === 1, {
    connectedMembers: ownedLane?.connectedMembers,
    activeRoutes: ownedLane?.activeRoutes,
    endpoint: ownedLane?.endpoint,
  });
  const la = await rpc(c, "rooms.lane.agents", {});
  check("composer pill data for the fork", la.lanes.some((l: any) => l.agentId === FORK && l.connectedMembers === 1), { lanes: la.lanes.length });
  const ja = await rpc(a, "rooms.overview", {});
  check("member overview shows joined room", ja.joined.some((j: any) => j.laneId === lane.id && j.status === "active"), {
    joined: ja.joined.map((j: any) => ({ status: j.status, hostStatus: j.hostStatus })),
  });

  // ---------------------------------------------------------------- 4. revoke -> immediate cut
  const memberId = ov.owned[0].members[0].id;
  const statusBefore = statusLog.length;
  const tRevoke = Date.now();
  const rv = await rpc(c, "rooms.member.revoke", { memberId });
  const rpcMs = Date.now() - tRevoke;
  await until("routed client disconnected", () => statusLog.slice(statusBefore).some((s) => s.status !== "connected"), 10_000, 20);
  const cutAt = statusLog.slice(statusBefore).find((s) => s.status !== "connected")!.at;
  check("revocation cuts live route immediately", rv.cutLinks === 1 && rv.cutRoutes >= 1 && cutAt - tRevoke < 1500, {
    rpcMs,
    cutLinks: rv.cutLinks,
    cutRoutes: rv.cutRoutes,
    routedDisconnectedAfterMs: cutAt - tRevoke,
  });
  const denied = await timed(() => routed.fetchAgent(FORK));
  check("no access after revoke", !denied.ok, { error: denied.ok ? null : denied.error });
  const removed = await timed(() =>
    until(
      "member plugin handles revocation",
      async () => {
        const o = await rpc(a, "rooms.overview", {});
        const j = o.joined.find((x: any) => x.laneId === lane.id);
        const h = await laneHost();
        return j?.status === "revoked" && !h ? { status: j.status } : null;
      },
      40_000,
      500,
    ),
  );
  check("member A marks room revoked and removes the lane host", removed.ok, { ms: removed.ms, error: removed.ok ? null : removed.error });
  await routed.close().catch(() => undefined);

  // ---------------------------------------------------------------- 5. expiry + rotation recovery
  const inv2 = await rpc(c, "rooms.invite.create", { laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 30 });
  rememberSecret(inv2.code);
  rememberSecret(JSON.parse(Buffer.from(inv2.code.slice(5), "base64url").toString()).token);
  const j2 = await rpc(a, "rooms.join", { code: inv2.code, label: "Member A (short grant)" });
  harvestGrants();
  const exp1 = Date.parse(j2.joined.grantExpiresAt);
  log("short_grant", { expiresInMs: exp1 - Date.now() });
  await until("lane online again", async () => (await laneHost())?.status === "online", 30_000);
  const routed2 = openRouted();
  const st2: Array<{ at: number; status: string }> = [];
  routed2.subscribeConnectionStatus((s: any) => st2.push({ at: Date.now(), status: s.status }));
  await routed2.connect();
  check("routed session open with short grant", (await timed(() => routed2.fetchAgent(FORK))).ok);
  // Busy: half-life rotation must be deferred while this route is open; expiry then cuts the link.
  await until("route cut at expiry", () => st2.some((s) => s.status !== "connected" && s.at >= exp1 - 1000), 45_000, 100);
  const cut2 = st2.find((s) => s.status !== "connected" && s.at >= exp1 - 1000)!.at;
  check("expiry cuts the live link at exp", Math.abs(cut2 - exp1) < 2500, { cutAfterExpMs: cut2 - exp1 });
  const rotated = await timed(() =>
    until(
      "rotation after auth failure",
      async () => {
        const o = await rpc(a, "rooms.overview", {});
        const j = o.joined.find((x: any) => x.laneId === lane.id && x.status === "active");
        return j && Date.parse(j.grantExpiresAt) > exp1 && (await laneHost())?.status === "online" ? j : null;
      },
      60_000,
      500,
    ),
  );
  check("member rotates (hosts.update) and the lane is online again", rotated.ok, { msAfterCut: rotated.ok ? Date.now() - cut2 : null, error: rotated.ok ? null : rotated.error });
  harvestGrants();
  const back = await timed(() => until("routed client reconnects", async () => (await timed(() => routed2.fetchAgent(FORK))).ok, 60_000, 500));
  check("open view recovers after rotation (client backoff)", back.ok, { msAfterCut: Date.now() - cut2 });
  await routed2.close().catch(() => undefined);

  // idle rotation before expiry (no open routes)
  const j3 = (await rpc(a, "rooms.overview", {})).joined.find((x: any) => x.laneId === lane.id && x.status === "active");
  const exp2 = Date.parse(j3.grantExpiresAt);
  const idleRot = await timed(() =>
    until(
      "idle rotation before expiry",
      async () => {
        const j = (await rpc(a, "rooms.overview", {})).joined.find((x: any) => x.laneId === lane.id && x.status === "active");
        return j && Date.parse(j.grantExpiresAt) > exp2 ? j : null;
      },
      40_000,
      500,
    ),
  );
  check("idle member rotates before expiry", idleRot.ok && Date.now() < exp2, { rotatedBeforeExpMs: exp2 - Date.now() });
  harvestGrants();

  // ---------------------------------------------------------------- 6. leave, log, cleanup
  const lv = await timed(() => rpc(a, "rooms.leave", { laneId: lane.id }));
  check("member leaves; lane host removed", lv.ok && !(await laneHost()), { error: lv.ok ? null : lv.error });
  const lg = await rpc(c, "rooms.log", { roomId: room.id });
  const types = lg.events.map((e: any) => e.type);
  check("room log hash chain and signatures verify", lg.verified === true, { events: lg.events.length, types });
  for (const t of ["room.created", "lane.created", "lane.closed", "invite.created", "member.joined", "member.revoked", "grant.renewed", "member.left"])
    check(`log has ${t}`, types.includes(t));

  const fileModes: Record<string, string> = {};
  for (const [home, rel] of [
    [C, "plugin-data/rooms"],
    [C, "plugin-data/rooms/gateway/state.json"],
    [C, "plugin-data/rooms/gateway/host-key.json"],
    [A, "plugin-data/rooms/member/device.json"],
    [A, "plugin-data/rooms/member/rooms.json"],
  ] as const)
    fileModes[`${home === C ? "C" : "A"}:${rel}`] = (statSync(join(home, rel)).mode & 0o777).toString(8);
  check("plugin data modes 0700/0600", Object.entries(fileModes).every(([k, m]) => (k.endsWith("rooms") ? m === "700" : m === "600")), { fileModes });
  const gwState = readFileSync(join(C, "plugin-data/rooms/gateway/state.json"), "utf8");
  check("gateway state holds no grant tokens", !/prg1\./.test(gwState));

  await obs.release().catch(() => undefined);
  await origin.close().catch(() => undefined);
  await rpc(c, "rooms.lane.close", { laneId: lane.id });
  await c.close();
  await a.close();
  log("SUMMARY", { failures, seconds: Math.round((Date.now() - T0) / 1000) });
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  log("FATAL", { error: String(e?.message ?? e).slice(0, 300) });
  process.exit(1);
});
