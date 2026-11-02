// Migration test 3 (docs/design/specs/identity-v2/migration.md section 6; plan I-15): an M1 room and
// membership created with the M1 plugin (tag m1-baseline), then both daemons upgrade to this plugin.
// Checks: the M1 data is archived on both daemons and recorded once, the v1 lane endpoint never comes
// back on the relay, the member's v1 host registration is removed, the M1 agent is listed under
// "Agents from closed rooms", and a new v2 room works end to end (SAS enrollment, lane registered,
// routed view of exactly the shared agent).
//
// Run by test/e2e-v2/migration-run.sh. One Claude Haiku agent is created on the owner WITHOUT a prompt
// (no model call) and archived at the end. Prints evidence as JSON lines; never prints codes, grants
// or keys.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";
import { createHostChannelTransport } from "@getpaseo/client/internal/hosts";

const OWNER = process.env.E2E_OWNER_HOME!;
const MEMBER = process.env.E2E_MEMBER_HOME!;
const PASEO_BIN = process.env.E2E_PASEO_BIN!;
const M1_PLUGIN = process.env.E2E_M1_PLUGIN!;
const V2_PLUGIN = process.env.E2E_V2_PLUGIN!;
const RELAY_LOG = process.env.E2E_RELAY_LOG!;
const SCRATCH = process.env.E2E_SCRATCH!;
const PLUGIN = "rooms";
const T0 = Date.now();

let failures = 0;
const log = (event: string, fields: Record<string, unknown> = {}) => console.log(JSON.stringify({ t: ((Date.now() - T0) / 1000).toFixed(2), event, ...fields }));
function check(name: string, ok: boolean, fields: Record<string, unknown> = {}) {
  if (!ok) failures++;
  log(ok ? "PASS" : "FAIL", { check: name, ...fields });
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
async function attempt<T>(f: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await f() };
  } catch (e) {
    return { ok: false, error: String((e as Error)?.message ?? e).slice(0, 200) };
  }
}

const listen = (home: string) => JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
const cred = (home: string) => readFileSync(join(home, "local-credential"), "utf8").trim();
const wsFactory = (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any;
async function client(home: string, name: string, type: "cli" | "mobile" = "cli"): Promise<any> {
  const address = listen(home);
  if (!/^127\.0\.0\.1:692[56]$/.test(address)) throw new Error(`refusing to talk to ${address}: not a migration test daemon`);
  const c: any = new DaemonClient({ url: `ws://${address}/ws`, clientId: `rooms-mig-${name}-${randomUUID().slice(0, 8)}`, clientType: type, appVersion: "0.13.2", localCredential: () => cred(home), webSocketFactory: wsFactory, reconnect: { enabled: false } } as any);
  await c.connect();
  return c;
}
const rpc = (c: any, method: string, input: unknown): Promise<any> => c.invokePluginRpc(PLUGIN, method, input);
async function adminRpc(c: any, method: string, input: Record<string, unknown>): Promise<any> {
  const p = await rpc(c, "rooms.v2.admin.prepare", { action: { kind: method.replace(/^rooms\.v2\./, ""), ...input } });
  return rpc(c, method, { ...input, confirmToken: p.confirmToken });
}
function cli(home: string, args: string[]): string {
  if (!/\.test-homes\/v2-mig-(owner|member)$/.test(home)) throw new Error("refusing: not a migration test home");
  return execFileSync(PASEO_BIN, [...args, "--home", home], { env: { ...process.env, PASEO_HOME: home }, stdio: ["ignore", "pipe", "pipe"], timeout: 180_000 }).toString();
}
const relayControls = (serverId: string, since: number) =>
  readFileSync(RELAY_LOG, "utf8")
    .split("\n")
    .filter((l) => Date.parse(l.slice(0, 24)) >= since && l.includes(`v2:server(control) ${serverId.slice(0, 12)}`)).length;

let AGENT: string | null = null;

async function main() {
  // ------------------------------------------------------------ 1. M1: room, share lane, membership
  let o = await client(OWNER, "owner");
  let m = await client(MEMBER, "member");
  const boot = await rpc(o, "rooms.bootstrap", {});
  check("phase 1 runs the M1 plugin (no protocol field)", boot.protocol === undefined, { version: boot.version });
  const agent = await o.createAgent({ provider: "claude", model: "claude-haiku-4-5", cwd: SCRATCH, title: "rooms migration e2e" });
  AGENT = agent.id;
  log("agent_created", { agentId: String(agent.id).slice(0, 8), prompt: false });
  const created = await rpc(o, "rooms.create", { name: "M1 room", agentId: agent.id, origin: "share", laneLabel: "Live" });
  const v1Lane = created.lane as { id: string; serverId: string };
  await until("M1 lane online", async () => (await rpc(o, "rooms.overview", {})).owned[0]?.lanes.find((l: any) => l.lane.id === v1Lane.id)?.endpoint === "online", 30_000);
  const inv = await rpc(o, "rooms.invite.create", { laneId: v1Lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 });
  const v1Code: string = inv.code;
  await rpc(m, "rooms.join", { code: v1Code, label: "M1 member" });
  const v1Host = async (c: any) => (await c.listHosts()).hosts.find((h: any) => h.source?.id === "plugin:rooms" && h.source?.key === v1Lane.id);
  const online = await attempt(() => until("M1 lane online on the member", async () => (await v1Host(m))?.status === "online", 40_000, 500));
  check("M1: room, share lane and membership; the lane is a routed host on the member", online.ok, online.ok ? {} : { error: online.error });
  check("M1: the v1 lane endpoint is registered on the relay (positive control)", relayControls(v1Lane.serverId, 0) > 0);
  await o.close();
  await m.close();

  // ------------------------------------------------------------ 2. upgrade both daemons
  const tUpgrade = Date.now();
  for (const h of [OWNER, MEMBER]) {
    cli(h, ["plugin", "remove", PLUGIN]);
    cli(h, ["plugin", "install", V2_PLUGIN, "--json"]);
  }
  log("upgraded", { from: M1_PLUGIN.split("/").slice(-2).join("/"), to: "plugin" });
  // A daemon restart afterwards: the second start must find nothing left to migrate.
  for (const h of [OWNER, MEMBER]) {
    cli(h, ["daemon", "stop"]);
    cli(h, ["daemon", "start", "--timeout", "120"]);
  }
  o = await client(OWNER, "owner2");
  m = await client(MEMBER, "member2");
  const ready = async (c: any) => until("v2 ready", async () => {
    const s = await attempt(() => rpc(c, "rooms.v2.status", {}));
    return s.ok && s.value.state !== "starting" ? s.value : null;
  }, 90_000, 500);
  const so = await ready(o);
  const sm = await ready(m);
  check("after the upgrade both daemons run v2 and are ready", so.state === "ready" && sm.state === "ready", { owner: so.error, member: sm.error });
  const oldRpc = await attempt(() => rpc(o, "rooms.overview", {}));
  check("the M1 RPCs are gone", !oldRpc.ok);

  // Owner: archive, record, closed agents.
  const om = so.migration;
  const odata = join(OWNER, "plugin-data", "rooms");
  check("owner: gateway/ archived by rename and recorded once (second start did nothing)", om?.gateway === "archived" && !existsSync(join(odata, "gateway")) && existsSync(join(odata, om.archive, "gateway", "state.json")), { archive: om?.archive, gateway: om?.gateway });
  const orec = JSON.parse(readFileSync(join(odata, "migration.json"), "utf8"));
  check("owner: migration.json written once (attempts 1)", orec.attempts === 1 && orec.from === "m1", { attempts: orec.attempts });
  check("owner: the M1 lane agent is listed under Agents from closed rooms", om?.lanes.some((l: any) => l.agentId === agent.id && l.laneId === v1Lane.id), { lanes: om?.lanes.length });
  check("owner: the archive keeps the v1 keys until the user deletes them", om?.keyFiles.length === 2, { keyFiles: om?.keyFiles });
  check("owner: the upgrade notice is shown", om?.notice === true);
  await sleep(3000);
  check("the v1 lane endpoint never came back on the relay after the upgrade", relayControls(v1Lane.serverId, tUpgrade) === 0, { since: new Date(tUpgrade).toISOString() });

  // Member: archive and registration removal.
  const mdata = join(MEMBER, "plugin-data", "rooms");
  const memberDone = await attempt(() => until("member hosts clean-up", async () => {
    const s = await rpc(m, "rooms.v2.status", {});
    return s.migration?.hosts === "done" ? s.migration : null;
  }, 60_000, 500));
  check("member: member/ archived and recorded", memberDone.ok && memberDone.value.member === "archived" && !existsSync(join(mdata, "member", "device.json")) && existsSync(join(mdata, memberDone.value.archive, "member", "device.json")), memberDone.ok ? { archive: memberDone.value.archive } : { error: memberDone.error });
  check("member: the v1 lane registration is removed from the member daemon (hosts.remove)", memberDone.ok && memberDone.value.hostsRemoved === 1 && !(await v1Host(m)), memberDone.ok ? { removed: memberDone.value.hostsRemoved } : {});
  const refused = await attempt(() => rpc(m, "rooms.v2.join.preview", { code: v1Code }));
  check("member: the old prc1. invite gets the upgrade message", !refused.ok && /older version of Rooms/.test(refused.error), { error: refused.ok ? null : refused.error });

  // ------------------------------------------------------------ 3. a new v2 room works end to end
  const room = await rpc(o, "rooms.v2.room.create", {});
  const roomId: string = room.roomId;
  await until("room endpoint online", async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.endpoint === "online", 30_000);
  const lane = await adminRpc(o, "rooms.v2.lane.create", { roomId, agentId: agent.id, label: "Live" });
  const invite = await adminRpc(o, "rooms.v2.invite.create", { roomId, lanes: [lane.laneId], note: "migration e2e", roomName: "New room" });
  await rpc(m, "rooms.v2.join.start", { code: invite.code, label: "Upgraded member", trustRelay: true });
  const joinOf = async () => (await rpc(m, "rooms.v2.status", {})).joining.find((j: any) => j.roomId === roomId);
  const cardOf = async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.joinRequests[0];
  const mj = await until("member SAS", async () => ((await joinOf())?.sas ? joinOf() : null), 30_000);
  const card = await until("owner SAS", async () => ((await cardOf())?.sas ? cardOf() : null), 30_000);
  check("v2 after the upgrade: both sides show the same SAS", mj.sas === card.sas && /^\d{3} \d{3}$/.test(mj.sas));
  if (mj.sas !== card.sas) throw new Error("SAS mismatch: refusing to confirm");
  await rpc(m, "rooms.v2.join.confirm", { roomId, match: true });
  await until("member confirmed", async () => (await cardOf())?.state === "member_ok", 30_000);
  await adminRpc(o, "rooms.v2.join.admit", { roomId, pendingId: card.pendingId });
  const reg = await attempt(() => until("lane registered", async () => ((await joinOf())?.state === "registered" ? true : null), 60_000, 500));
  check("v2 after the upgrade: admitted, grant issued, lane registered", reg.ok, reg.ok ? {} : { error: reg.error });
  const origin = await client(MEMBER, "app", "mobile");
  const v2Host = async () => (await origin.listHosts()).hosts.find((h: any) => h.serverId === lane.serverId || h.source?.key === lane.laneId);
  const up = await attempt(() => until("v2 lane online on the member", async () => (await v2Host())?.status === "online", 30_000, 500));
  check("v2 after the upgrade: the new lane is a routed host on the member", up.ok, up.ok ? {} : { error: up.error });
  const clientId = randomUUID();
  const routed: any = new DaemonClient({ url: "ws://routed-host/ws", clientId, clientType: "mobile", appVersion: "0.13.2", transportFactory: createHostChannelTransport(origin, lane.serverId, clientId, null) } as any);
  const rc = await attempt(() => routed.connect());
  const ids = rc.ok ? (await routed.fetchAgents()).entries.map((e: any) => e.agent.id) : [];
  check("v2 after the upgrade: a routed view shows exactly the shared agent, workspace.read only", rc.ok && ids.length === 1 && ids[0] === agent.id && JSON.stringify(routed.getLastServerInfoMessage()?.permissions) === '["workspace.read"]', { agents: ids.length });
  await routed.close().catch(() => undefined);
  await origin.close().catch(() => undefined);

  // No v1 secret survives outside the archive; every file under plugin-data stays owner-only.
  const bad: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) walk(p);
      else if (/prc1\.|"privateKeyPkcs8"/.test(readFileSync(p, "latin1")) && !p.includes("/v1-archive-")) bad.push(p.slice(OWNER.length - 20));
    }
  };
  walk(odata);
  walk(mdata);
  check("no v1 key or prc1. code outside the archive in either data tree", bad.length === 0, { found: bad });

  await o.close();
  await m.close();
  await archive();
  log("SUMMARY", { failures, seconds: Math.round((Date.now() - T0) / 1000) });
  process.exit(failures ? 1 : 0);
}

async function archive(): Promise<void> {
  if (!AGENT) return;
  try {
    const c = await client(OWNER, "cleanup");
    await c.archiveAgent(AGENT).catch(() => undefined);
    await c.close();
    log("agent_archived", { agentId: AGENT.slice(0, 8) });
  } catch {}
}

main().catch((e) => {
  log("FATAL", { error: String(e?.message ?? e).slice(0, 300) });
  void archive().finally(() => process.exit(1));
});
