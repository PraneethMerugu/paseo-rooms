// Identity v2 e2e driver (implementation plan I-8, I-9, I-10). Talks to the two test daemons like the
// CLI does (DaemonClient with the local credential) and calls the v2 plugin RPCs; the lane is viewed
// through the member daemon exactly as the app opens a routed host (createHostChannelTransport over
// the member's connection). Creates ONE agent on the owner (Claude Haiku, created WITHOUT a prompt, so
// no model call is made) for the lane to share, and archives it at the end. Prints evidence as JSON
// lines; never prints keys, credentials, the genesis, invite codes, grants or their tokens.
//
// Grants are short: the run script sets PASEO_ROOMS_DEV_SHORT_GRANTS=1 and
// PASEO_ROOMS_DEV_GRANT_TTL_S (40 s): idle rotation at 20 s, forced at 30 s.
//
// Flow: v2 runtime up on both daemons (fallback-file keystore) -> owner creates a room, its endpoint
// registers on the relay -> owner shares an agent as a lane -> owner creates an invite for the lane
// -> an invite naming an unknown relay is refused
// without the user's trust (both modes, no network); offline, the loopback relay also needs trust,
// live, relay.paseo.sh:443 is trusted by default (P-20) -> member joins: both sides show a SAS -> the codes are
// compared -> BOTH daemons restart mid-pending -> the pending resumes with the same codes on both
// sides -> member confirms, owner admits -> the member is in the roster, its session syncs the log
// -> the member's own fold accepts the admission, then it gets a grant and registers the lane: the
// lane is online as a routed host on the member -> a routed view shows exactly the shared agent,
// workspace.read only, project names hidden, prompting denied -> with the view open the idle attempt
// defers (own busy link) and the forced rotation at 75 % cuts and the view recovers -> with the view
// closed the idle rotation happens at 50 % -> the owner removes the member: the open view is cut within
// milliseconds, access_ended removed, the member removes its lane host -> no plaintext secret fields;
// no `prc2.` and no `prg2.` in any file of either home except the member daemon's hosts.json (grant
// by design), and no grant or invite in the logs.
//
// TEST-ONLY: the SAS comparison that people do by voice is done here by reading the code from the
// owner's join card (rooms.v2.status) and from the member's join view, and checking they are equal
// before pressing "Codes match" and "Admit" programmatically. A mismatch fails the run.
import { readdirSync, readFileSync, statSync, lstatSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";
import { createHostChannelTransport } from "@getpaseo/client/internal/hosts";

const OWNER = process.env.E2E_OWNER_HOME!;
const MEMBER = process.env.E2E_MEMBER_HOME!;
const LIVE = process.env.E2E_LIVE === "1";
const RELAY_LOG = process.env.E2E_RELAY_LOG ?? "";
const PASEO_BIN = process.env.E2E_PASEO_BIN!;
const SCRATCH = process.env.E2E_SCRATCH!;
const GRANT_TTL_S = Number(process.env.PASEO_ROOMS_DEV_GRANT_TTL_S ?? 40);
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

const listen = (home: string) => JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
const cred = (home: string) => readFileSync(join(home, "local-credential"), "utf8").trim();
const wsFactory = (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any;

async function daemonClient(home: string, name: string): Promise<any> {
  const address = listen(home);
  if (!/^127\.0\.0\.1:692[0-9]$/.test(address)) throw new Error(`refusing to talk to ${address}: not a v2 test daemon`);
  const c: any = new DaemonClient({
    url: `ws://${address}/ws`,
    clientId: `rooms-e2e-v2-${name}-${randomUUID().slice(0, 8)}`,
    clientType: "cli",
    appVersion: "0.13.2",
    localCredential: () => cred(home),
    webSocketFactory: wsFactory,
    reconnect: { enabled: false },
  } as any);
  await c.connect();
  return c;
}
const rpc = (client: any, method: string, input: unknown): Promise<any> => client.invokePluginRpc(PLUGIN, method, input);
async function attempt<T>(f: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await f() };
  } catch (e) {
    return { ok: false, error: String((e as Error)?.message ?? e).slice(0, 200) };
  }
}

/** Files under a tree (no node_modules, plugins or models). */
function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules") continue;
    const p = join(dir, name);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) out.push(...files(p));
    else if (st.size < 20_000_000) out.push(p);
  }
  return out;
}

/** RJCS for the ASCII-only invite payload: sorted keys, no whitespace (signatures-and-encoding.md 2). */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** Restarts one test daemon (same home and port; the plugin restarts with it). */
function restartDaemon(home: string): void {
  if (!/\.test-homes\/v2-[a-z]+$/.test(home)) throw new Error("refusing to restart a daemon outside .test-homes/v2-*");
  const env = { ...process.env, PASEO_HOME: home };
  execFileSync(PASEO_BIN, ["daemon", "stop", "--home", home], { env, stdio: ["ignore", "ignore", "ignore"], timeout: 120_000 });
  execFileSync(PASEO_BIN, ["daemon", "start", "--timeout", "120", "--home", home], { env, stdio: ["ignore", "ignore", "ignore"], timeout: 180_000 });
}

async function v2Ready(c: any, what: string): Promise<any> {
  return until(`${what} v2 ready`, async () => {
    const s = await attempt(() => rpc(c, "rooms.v2.status", {}));
    return s.ok && s.value.state !== "starting" ? s.value : null;
  }, 90_000, 500);
}

async function main() {
  log("mode", { relay: LIVE ? "live" : "fake" });
  // Plugin RPCs are served only once the plugin process is up.
  let o = await daemonClient(OWNER, "owner");
  let m = await daemonClient(MEMBER, "member");

  // ------------------------------------------------------------ 1. v2 runtime on both daemons
  const so = await v2Ready(o, "owner");
  const sm = await v2Ready(m, "member");
  check("v2 runtime ready on both daemons", so.state === "ready" && sm.state === "ready", { owner: so.state, member: sm.state, ownerError: so.error, memberError: sm.error });
  check("keystore is the protected fallback file (no keyring)", so.keystore?.backend === "fallback-file" && sm.keystore?.backend === "fallback-file", { owner: so.keystore, member: sm.keystore });
  const m1 = await attempt(() => rpc(o, "rooms.overview", {}));
  check("M1 RPCs are not registered under the v2 switch", !m1.ok, { error: m1.ok ? null : m1.error });
  const dev = await attempt(() => rpc(o, "rooms.v2.dev.member.admit", {}));
  check("the I-8 stand-in admission RPCs are gone", !dev.ok, { error: dev.ok ? null : dev.error });

  // ------------------------------------------------------------ 2. owner creates a room and an invite
  const created = await rpc(o, "rooms.v2.room.create", {});
  const roomId: string = created.roomId;
  log("room_created", { roomId, serverId: `${String(created.serverId).slice(0, 10)}…` });
  const online = await attempt(() => until("endpoint online", async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.endpoint === "online", 30_000));
  check("room endpoint registered on the relay", online.ok, online.ok ? {} : { error: online.error });
  // The lane's agent: one Claude Haiku agent created WITHOUT a prompt (no model call).
  const agent = await o.createAgent({ provider: "claude", model: "claude-haiku-4-5", cwd: SCRATCH, title: "rooms v2 e2e lane" });
  AGENT_ID = agent.id;
  log("lane_agent_created", { agentId: String(agent.id).slice(0, 8), prompt: false });
  const lane = await rpc(o, "rooms.v2.lane.create", { roomId, agentId: agent.id, label: "Live" });
  const laneId: string = lane.laneId;
  const laneUp = await attempt(() => until("lane endpoint online", async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.lanes.find((l: any) => l.laneId === laneId)?.endpoint === "online", 30_000));
  check("lane created (lane.created in the log) and its endpoint online on the relay", laneUp.ok, laneUp.ok ? { laneId } : { error: laneUp.error });
  const so2 = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("grant lifetime is the development short value (switch on the host only)", so2?.grantTtlS === GRANT_TTL_S, { grantTtlS: so2?.grantTtlS });
  const invite = await rpc(o, "rooms.v2.invite.create", { roomId, lanes: [laneId], note: "for the e2e member", roomName: "E2E room" });
  const code: string = invite.code;
  const token = JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8")).token as string;
  check("invite code is prc2 and about 700 characters", code.startsWith("prc2.") && code.length > 500 && code.length < 2048, { length: code.length, inviteRef: `${String(invite.inviteRef).slice(0, 8)}…` });

  // ------------------------------------------------------------ 3. member preview and relay trust (P-20)
  // An invite naming a relay the member never used needs the user's explicit trust. Checked in both
  // modes with a copy of the invite pointing at an unknown relay host: preview and the refused join
  // happen before any network access, and trust is never given for it, so nothing connects there.
  const payload = JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8"));
  payload.endpoint.relay = { host: "relay.example.org", port: 443, tls: true };
  const unknownRelayCode = "prc2." + Buffer.from(canonical(payload), "utf8").toString("base64url");
  const unknownPreview = await rpc(m, "rooms.v2.join.preview", { code: unknownRelayCode });
  check("preview of an invite naming an unknown relay: not trusted", unknownPreview.relay.trusted === false && unknownPreview.relay.host === "relay.example.org", { relay: unknownPreview.relay });
  const refused = await attempt(() => rpc(m, "rooms.v2.join.start", { code: unknownRelayCode, label: "E2E member laptop" }));
  check("join via an unknown relay without the user's trust is refused", !refused.ok && /relay/i.test(refused.error), { error: refused.ok ? null : refused.error });
  const preview = await rpc(m, "rooms.v2.join.preview", { code });
  if (LIVE) {
    check("preview: room, unverified, relay.paseo.sh:443 trusted by default", preview.roomId === roomId && preview.unverified === true && preview.relay.trusted === true && preview.relay.host === "relay.paseo.sh" && preview.relay.port === 443, { relay: preview.relay, roomName: preview.roomName });
    await rpc(m, "rooms.v2.join.start", { code, label: "E2E member laptop" });
  } else {
    check("preview: room, unverified, loopback relay not trusted by default", preview.roomId === roomId && preview.unverified === true && preview.relay.trusted === false, { relay: preview.relay, roomName: preview.roomName });
    const untrusted = await attempt(() => rpc(m, "rooms.v2.join.start", { code, label: "E2E member laptop" }));
    check("join without trusting the loopback relay is refused", !untrusted.ok && /relay/i.test(untrusted.error), { error: untrusted.ok ? null : untrusted.error });
    await rpc(m, "rooms.v2.join.start", { code, label: "E2E member laptop", trustRelay: true });
  }

  // ------------------------------------------------------------ 4. SAS on both sides
  const joinOf = async (c: any) => (await rpc(c, "rooms.v2.status", {})).joining.find((j: any) => j.roomId === roomId);
  const cardOf = async (c: any) => (await rpc(c, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.joinRequests[0];
  const mj = await until("member SAS", async () => ((await joinOf(m))?.sas ? joinOf(m) : null), 30_000);
  const card = await until("owner SAS", async () => ((await cardOf(o))?.sas ? cardOf(o) : null), 30_000);
  // TEST-ONLY comparison (people compare by voice): the codes must be equal, never skipped.
  const sasBefore = mj.sas as string;
  check("member and owner show the same 6-digit SAS", /^\d{3} \d{3}$/.test(sasBefore) && sasBefore === card.sas, { memberState: mj.state, ownerState: card.state, equal: sasBefore === card.sas });
  check("owner's join card: note, self-reported label, no earlier attempts", card.note === "for the e2e member" && card.label === "E2E member laptop" && card.abandonedBefore === 0 && card.contested === false);

  // ------------------------------------------------------------ 5. restart both daemons mid-pending
  await o.close();
  await m.close();
  const tr = Date.now();
  restartDaemon(OWNER);
  restartDaemon(MEMBER);
  o = await daemonClient(OWNER, "owner");
  m = await daemonClient(MEMBER, "member");
  await v2Ready(o, "owner (restarted)");
  await v2Ready(m, "member (restarted)");
  const resumed = await attempt(() => until("member resumed", async () => {
    const j = await joinOf(m);
    return j?.connection === "waiting" ? j : null;
  }, 60_000, 250));
  const cardAfter = await cardOf(o);
  check("after restarting both daemons the pending resumes with the same SAS on both sides", resumed.ok && resumed.value.sas === sasBefore && cardAfter?.sas === sasBefore && cardAfter?.pendingId === card.pendingId, resumed.ok ? { memberState: resumed.value.state, ownerState: cardAfter?.state, ms: Date.now() - tr } : { error: resumed.error });

  // ------------------------------------------------------------ 6. confirm and admit (TEST-ONLY programmatic buttons)
  const mjNow = await joinOf(m);
  const cardNow = await cardOf(o);
  if (mjNow?.sas !== cardNow?.sas) throw new Error("SAS mismatch: refusing to confirm");
  await rpc(m, "rooms.v2.join.confirm", { roomId, match: true });
  await until("host saw the member's confirmation", async () => (await cardOf(o))?.state === "member_ok", 30_000);
  const t1 = Date.now();
  await rpc(o, "rooms.v2.join.admit", { roomId, pendingId: card.pendingId });
  const joinedOk = await attempt(() => until("member session open", async () => {
    const st = await rpc(m, "rooms.v2.status", {});
    const j = st.joined.find((r: any) => r.roomId === roomId);
    return j?.status === "open" ? { j, join: st.joining.find((r: any) => r.roomId === roomId) } : null;
  }, 30_000, 250));
  check("admitted: member room session open", joinedOk.ok, joinedOk.ok ? { ms: Date.now() - t1, memberId: joinedOk.value.j.memberId } : { error: joinedOk.error });
  const ownerView = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  const memberJoined = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
  check("owner sees the member in the roster and the invite used", ownerView?.members === 2 && ownerView.invites[0]?.state === "used" && ownerView.joinRequests[0]?.memberId === memberJoined?.memberId, { members: ownerView?.members, invite: ownerView?.invites[0]?.state });
  // The head moves while the member's grant is issued (grant.issued), so both views are read together.
  const synced = await until("member synced", async () => {
    const j = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
    const ow = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
    return j?.head.seq === ow?.head.seq ? { j, ow } : null;
  }, 15_000).catch(() => null);
  const mv = synced?.j ?? (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
  const ov = synced?.ow ?? (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("member synced the log to the owner's head", mv?.head.seq === ov?.head.seq && mv?.head.hash === ov?.head.hash, { memberHead: mv?.head.seq, ownerHead: ov?.head.seq });
  check("owner sees exactly one live session, for that device", ov?.sessions.length === 1 && ov.sessions[0].deviceId === mv?.deviceId, { sessions: ov?.sessions.length });
  check("no alerts on the member", (mv?.alerts ?? []).length === 0, { alerts: mv?.alerts });

  // ------------------------------------------------------------ 7. lane through the member (grants v2)
  const memberLane = async () => (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId)?.lanes.find((l: any) => l.laneId === laneId);
  const reg = await attempt(() => until("lane registered with a grant", async () => {
    const st = await rpc(m, "rooms.v2.status", {});
    const j = st.joining.find((r: any) => r.roomId === roomId);
    const l = st.joined.find((r: any) => r.roomId === roomId)?.lanes.find((x: any) => x.laneId === laneId);
    return j?.state === "registered" && l?.gid ? { j, l } : null;
  }, 60_000, 250));
  check("after the fold accepted the admission: one grant issued and the lane registered", reg.ok, reg.ok ? { registration: reg.value.j.state, rotations: reg.value.l.rotations } : { error: reg.error });
  const ownerGrantLog = await attempt(() => until("owner grant", async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.grants.find((g: any) => g.laneId === laneId), 10_000));
  check("owner's allowlist holds exactly one current grant for the device and lane", ownerGrantLog.ok && ownerGrantLog.value.deviceId === memberJoined?.deviceId && ownerGrantLog.value.exp - ownerGrantLog.value.iat === GRANT_TTL_S, ownerGrantLog.ok ? { ttl: ownerGrantLog.value.exp - ownerGrantLog.value.iat } : { error: ownerGrantLog.error });

  const origin: any = new DaemonClient({
    url: `ws://${listen(MEMBER)}/ws`,
    clientId: `rooms-e2e-v2-app-${randomUUID().slice(0, 8)}`,
    clientType: "mobile",
    appVersion: "0.13.2",
    localCredential: () => cred(MEMBER),
    webSocketFactory: wsFactory,
  } as any);
  await origin.connect();
  const laneServerId = so2.lanes.find((l: any) => l.laneId === laneId).serverId;
  const laneHost = () => origin.listHosts().then((d: any) => d.hosts.find((h: any) => h.serverId === laneServerId || h.source?.key === laneId));
  const laneOnline = await attempt(() => until("lane online on the member", async () => (await laneHost())?.status === "online" && laneHost(), 30_000));
  check("lane visible as a routed host on the member daemon", laneOnline.ok, laneOnline.ok ? { label: laneOnline.value.label, status: laneOnline.value.status, source: laneOnline.value.source?.id } : { error: laneOnline.error });
  const openRouted = () => {
    const clientId = randomUUID();
    return new DaemonClient({ url: "ws://routed-host/ws", clientId, clientType: "mobile", appVersion: "0.13.2", transportFactory: createHostChannelTransport(origin, laneServerId, clientId, null) } as any) as any;
  };
  const routed = openRouted();
  const statusLog: Array<{ at: number; status: string }> = [];
  routed.subscribeConnectionStatus((st: any) => statusLog.push({ at: Date.now(), status: st.status }));
  const rc = await attempt(() => routed.connect());
  check("routed session through the member connects", rc.ok, rc.ok ? {} : { error: rc.error });
  const info = routed.getLastServerInfoMessage();
  check("routed server_info is the lane, workspace.read only", info?.serverId === laneServerId && JSON.stringify(info?.permissions) === '["workspace.read"]', { permissions: info?.permissions });
  const ag = await routed.fetchAgents();
  const ids = ag.entries.map((e: any) => e.agent.id);
  check("exactly one agent visible (the shared one)", ids.length === 1 && ids[0] === agent.id, { agents: ids.length });
  const viewText = JSON.stringify(ag.entries);
  check("project names and paths hidden from the viewer (13.2 default)", !viewText.includes(SCRATCH) && !viewText.includes("v2-scratch"), {});
  const denied = await attempt(() => routed.sendAgentMessage(agent.id, "should be denied"));
  check("prompting through the lane is denied", !denied.ok, { error: denied.ok ? null : denied.error });

  // ------------------------------------------------------------ 8. rotation: deferral, forced at 75 %, idle at 50 %
  const g0 = (await memberLane())!;
  const forced = await attempt(() => until("forced rotation", async () => {
    const l = await memberLane();
    return l && l.rotations >= 1 && l.lastRotation?.reason === "forced" ? l : null;
  }, GRANT_TTL_S * 1000 + 20_000, 250));
  check("open view: the idle attempt defers on the member's own busy link, then rotation is forced at 75 %", forced.ok && forced.value.gid !== g0.gid, forced.ok ? { lastDecision: forced.value.lastDecision, gidChanged: forced.value.gid !== g0.gid } : { error: forced.error, last: await memberLane() });
  check("the deferral was the member's own link (P-9 rule)", forced.ok && /defer:own_link_busy/.test(String(forced.value.lastDecision ?? "")) , { lastDecision: forced.ok ? forced.value.lastDecision : null });
  const cutByRotation = statusLog.some((x) => x.status !== "connected");
  const back = await attempt(() => until("view recovers", async () => (await attempt(() => routed.fetchAgent(agent.id))).ok, 60_000, 500));
  check("the forced rotation restarted the link and the open view recovered", cutByRotation && back.ok, { cutSeen: cutByRotation, error: back.ok ? null : back.error });
  await routed.close().catch(() => undefined);
  const nRot = (await memberLane())!.rotations;
  const idle = await attempt(() => until("idle rotation", async () => {
    const l = await memberLane();
    return l && l.rotations > nRot && l.lastRotation?.reason === "idle" ? l : null;
  }, GRANT_TTL_S * 1000 + 20_000, 250));
  check("view closed: idle rotation at 50 % (no routes)", idle.ok, idle.ok ? { lastDecision: idle.value.lastDecision } : { error: idle.error, last: await memberLane() });
  await until("lane online after rotation", async () => (await laneHost())?.status === "online", 30_000).catch(() => null);

  // Positive control for the secret scan: while registered, the member daemon's hosts.json (written by
  // Paseo, 0600) holds the current grant, and no other file of either home does.
  const grantFiles: string[] = [];
  for (const [label, home] of [["owner", OWNER], ["member", MEMBER]] as const) {
    for (const f of files(home)) {
      if (/node_modules|\/plugins\//.test(f)) continue;
      if (/prg2\.[A-Za-z0-9_-]{20}/.test(readFileSync(f).toString("latin1"))) grantFiles.push(`${label}:${f.slice(home.length + 1)}`);
    }
  }
  check("secret scan sees the live grant only in the member's hosts.json", grantFiles.length >= 1 && grantFiles.every((f) => /^member:(.*\/)?hosts\.json$/.test(f)), { files: grantFiles });

  // ------------------------------------------------------------ 9. revoke: removal cuts the open view at once
  const routed2 = openRouted();
  const st2: Array<{ at: number; status: string }> = [];
  routed2.subscribeConnectionStatus((x: any) => st2.push({ at: Date.now(), status: x.status }));
  const rc2 = await attempt(() => until("routed again", async () => (await attempt(() => routed2.connect())).ok, 30_000, 1000));
  check("routed view open again before the removal", rc2.ok && (await attempt(() => routed2.fetchAgent(agent.id))).ok);
  const before = st2.length;
  const t2 = Date.now();
  const removed = await rpc(o, "rooms.v2.member.remove", { roomId, memberId: mv.memberId });
  const rpcMs = Date.now() - t2;
  const cut = await attempt(() => until("routed view cut", () => st2.slice(before).find((x) => x.status !== "connected"), 10_000, 5));
  check("revocation cuts the open lane view immediately", cut.ok && cut.value.at - t2 < 1500, cut.ok ? { rpcMs, cutAfterMs: cut.value.at - t2 } : { error: cut.error });
  const noAccess = await attempt(() => routed2.fetchAgent(agent.id));
  check("no lane access after the removal", !noAccess.ok, { error: noAccess.ok ? null : noAccess.error });
  await routed2.close().catch(() => undefined);
  const ended = await attempt(() => until("member ended", async () => {
    const j = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
    return j?.status === "ended" ? j : null;
  }, 20_000, 100));
  check("removal ends the live session with access_ended removed", ended.ok && ended.value.endedReason === "removed", ended.ok ? { endedReason: ended.value.endedReason, removedSeq: removed.seq, ms: Date.now() - t2 } : { error: ended.error });
  const hostGone = await attempt(() => until("lane host removed", async () => !(await laneHost()), 20_000, 250));
  check("the member removes its lane host after access ended", hostGone.ok, hostGone.ok ? {} : { error: hostGone.error });
  const after = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("owner: no live session, no lane link, no current grant, no persist error", after?.sessions.length === 0 && after.lanes[0].links === 0 && after.grants.length === 0 && after.persistError === null, { sessions: after?.sessions.length, links: after?.lanes[0].links, grants: after?.grants.length, persistError: after?.persistError });
  const again = await rpc(m, "rooms.v2.room.connect", { roomId });
  check("a new session of the removed device gets access_ended", again.status === "ended" && again.lastError === "access_ended", again);
  await origin.close().catch(() => undefined);

  // ------------------------------------------------------------ 8. files, logs and relay evidence
  const plaintextSecrets: string[] = [];
  const tokenFound: string[] = [];
  const prefixHits: string[] = [];
  const grantsInHostsJson: string[] = [];
  const modes: Record<string, string> = {};
  for (const [label, home] of [["owner", OWNER], ["member", MEMBER]] as const) {
    const root = join(home, "plugin-data", "rooms");
    modes[`${label}:plugin-data/rooms`] = (statSync(root).mode & 0o777).toString(8);
    for (const f of files(root)) {
      const text = readFileSync(f, "utf8");
      const rel = f.slice(home.length + 1);
      if (/"(seed|secret|secretKey|sigSeed|dhSecret|tokenKey)"\s*:/.test(text)) plaintextSecrets.push(`${label}:${rel}`);
      if (/\.sealed$/.test(f)) {
        modes[`${label}:${rel}`] = (statSync(f).mode & 0o777).toString(8);
        if (JSON.parse(text).typ !== "sealed") plaintextSecrets.push(`${label}:${rel}`);
      }
    }
    for (const f of files(home)) {
      if (/node_modules|\/plugins\//.test(f)) continue;
      const text = readFileSync(f).toString("latin1");
      const rel = f.slice(home.length + 1);
      if (text.includes(token) || text.includes(code.slice(5, 80))) tokenFound.push(`${label}:${rel}`);
      // Secret scan by prefix: invite codes (prc2.) nowhere; grants (prg2.) only in the member
      // daemon's own hosts.json, where Paseo keeps the connection password by design.
      if (/prc2\.[A-Za-z0-9_-]{20}/.test(text)) prefixHits.push(`${label}:${rel}:prc2`);
      if (/prg2\.[A-Za-z0-9_-]{20}/.test(text)) {
        if (label === "member" && /(^|\/)hosts\.json$/.test(rel)) grantsInHostsJson.push(rel);
        else prefixHits.push(`${label}:${rel}:prg2`);
      }
    }
  }
  check("no plaintext secret fields in either data tree; key and state files sealed", plaintextSecrets.length === 0, { found: plaintextSecrets });
  check("the invite code and token appear in no file of either home (data, logs)", tokenFound.length === 0, { found: tokenFound });
  check("secret scan: no prc2. and no prg2. outside the member's hosts.json (logs, plugin data, owner)", prefixHits.length === 0, { found: prefixHits, hostsJsonWithGrant: grantsInHostsJson.length });
  check("data dirs 0700 and sealed files 0600", Object.entries(modes).every(([k, v]) => (k.endsWith("rooms") ? v === "700" : v === "600")), { modes });
  if (!LIVE && RELAY_LOG && existsSync(RELAY_LOG)) {
    const lines = readFileSync(RELAY_LOG, "utf8");
    check("traffic went through the local fake relay", /v2:server\(control\)/.test(lines) && /v2:client\(conn_/.test(lines) && /v2:server\(conn_/.test(lines));
  }

  await o.close();
  await m.close();
  await archiveAgent();
  log("SUMMARY", { failures, seconds: Math.round((Date.now() - T0) / 1000) });
  process.exit(failures ? 1 : 0);
}

let AGENT_ID: string | null = null;

/** Archives the lane agent (best effort); the daemons are stopped and the homes deleted afterwards. */
async function archiveAgent(): Promise<void> {
  if (!AGENT_ID) return;
  try {
    const c = await daemonClient(OWNER, "cleanup");
    await c.archiveAgent(AGENT_ID).catch(() => undefined);
    await c.close();
    log("lane_agent_archived", { agentId: AGENT_ID.slice(0, 8) });
  } catch {}
}

main().catch((e) => {
  log("FATAL", { error: String(e?.message ?? e).slice(0, 300) });
  void archiveAgent().finally(() => process.exit(1));
});
