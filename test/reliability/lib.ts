// Shared helpers for the reliability modules (identity v2 RPCs, `rooms.v2.*`). Talks to the two test
// daemons the same way test/e2e-v2/e2e.ts does (owner-style DaemonClient with the test home's local
// credential, routed lane view through the member daemon). Never prints invite codes, grants, keys,
// SAS digits or credentials.
//
// Every module calls assertSafeEnvironment() first: it re-checks the run.sh safety gates
// (homes under test/reliability/.homes, never ~/.paseo; ports 6930-6939 only).
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";
import { createHostChannelTransport } from "@getpaseo/client/internal/hosts";
import { RoomLogFold } from "../../server/authority/fold";

export const PLUGIN = "rooms";
export const PASEO_CLI = "/opt/Paseo/resources/bin/paseo";
export const PORT_MIN = 6930;
export const PORT_MAX = 6939;
export const RELIABILITY_DIR = dirname(fileURLToPath(import.meta.url));

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name} (run through test/reliability/run.sh)`);
  return v;
}

export const OWNER_HOME = () => env("RL_OWNER_HOME");
export const MEMBER_HOME = () => env("RL_MEMBER_HOME");
export const PARENT = () => env("RL_PARENT");
export const LOGDIR = () => env("RL_LOGDIR");
export const AGENTS_FILE = () => env("RL_AGENTS_FILE");
export const SECRETS_FILE = () => env("RL_SECRETS_FILE");

// ------------------------------------------------------------------ safety gates (defence in depth)
function real(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

export function listen(home: string): string {
  return JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
}

export function configuredPort(home: string): number {
  const cfg = JSON.parse(readFileSync(join(home, "config.json"), "utf8"));
  const l = String(cfg?.daemon?.listen ?? "");
  const m = /^127\.0\.0\.1:(\d+)$/.exec(l);
  if (!m) throw new Error(`unsafe listen address in ${home}/config.json`);
  return Number(m[1]);
}

export function assertSafeEnvironment(): void {
  const homesRoot = real(join(RELIABILITY_DIR, ".homes"));
  const mainHome = real(join(homedir(), ".paseo"));
  for (const h of [OWNER_HOME(), MEMBER_HOME()]) {
    const r = real(h);
    if (r === mainHome || r.startsWith(mainHome + "/")) throw new Error(`refusing: home resolves to ~/.paseo (${h})`);
    if (!r.startsWith(homesRoot + "/")) throw new Error(`refusing: home outside test/reliability/.homes (${h})`);
    const port = configuredPort(h);
    if (port === 6767 || port < PORT_MIN || port > PORT_MAX) throw new Error(`refusing: port ${port} outside ${PORT_MIN}-${PORT_MAX}`);
  }
}

// ------------------------------------------------------------------ logging and secrets
const T0 = Date.now();
export function log(event: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ t: ((Date.now() - T0) / 1000).toFixed(2), event, ...fields });
  console.log(line);
}

/** Append one JSON record to a module's evidence file in the run's log directory. */
export function record(file: string, obj: Record<string, unknown>): void {
  mkdirSync(LOGDIR(), { recursive: true });
  appendFileSync(join(LOGDIR(), file), JSON.stringify(obj) + "\n");
}

/** Track a secret so the cleanup's secret scan can look for it in homes and logs. Never printed. */
export function rememberSecret(s: string): void {
  const f = SECRETS_FILE();
  if (!existsSync(f)) writeFileSync(f, "", { mode: 0o600 });
  chmodSync(f, 0o600);
  appendFileSync(f, s + "\n");
}

/** A `prc2.` invite code and its token (the bearer part). */
export function rememberInvite(code: string): void {
  rememberSecret(code);
  try {
    rememberSecret(JSON.parse(Buffer.from(code.slice(5), "base64url").toString()).token);
  } catch {
    // Format changed: the code itself is still tracked.
  }
}

/** Grant signatures (`prg2.<claims>.<sig>`) the member daemon stores in hosts.json, for the secret scan only. */
export function harvestGrants(): void {
  const p = join(MEMBER_HOME(), "hosts.json");
  if (!existsSync(p)) return;
  for (const m of readFileSync(p, "utf8").matchAll(/prg2\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]{86})/g)) rememberSecret(m[1]);
}

/** Removes anything that looks like an invite, a link code, a grant or a long opaque token from free text. */
export function redact(text: string): string {
  return text
    .replace(/pr[cl][12]\.[A-Za-z0-9_-]+/g, "<invite-code>")
    .replace(/prg[12]\.[A-Za-z0-9_.-]+/g, "<grant>")
    .replace(/(token|password|secret|credential|authorization|bearer)(["'\s:=]+)[^\s"',}]+/gi, "$1$2<redacted>")
    .replace(/[A-Za-z0-9_-]{40,}/g, "<opaque>");
}

export function sha256(s: string | Buffer): string {
  return createHash("sha256").update(s).digest("hex");
}

// ------------------------------------------------------------------ timing helpers
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until<T>(what: string, f: () => Promise<T | null | undefined | false> | T | null | undefined | false, timeoutMs = 30_000, stepMs = 250): Promise<T> {
  const s = Date.now();
  for (;;) {
    let v: T | null | undefined | false = null;
    try {
      v = await f();
    } catch {
      v = null;
    }
    if (v) return v as T;
    if (Date.now() - s > timeoutMs) throw new Error(`timeout: ${what}`);
    await sleep(stepMs);
  }
}

export interface ErrorDetails {
  name: string | null;
  message: string;
  code: string | null;
  requestType: string | null;
  causes: Array<{ name: string | null; message: string; code: string | null; errno: number | null; syscall: string | null }>;
  aggregated: Array<{ name: string | null; message: string; code: string | null }>;
}

/** Non-secret error details: name, message, code and the cause / AggregateError chain, redacted. */
export function errorDetails(e: unknown): ErrorDetails {
  const err = e as any;
  const causes: ErrorDetails["causes"] = [];
  let c = err?.cause;
  for (let i = 0; c && i < 5; i++, c = c.cause)
    causes.push({ name: c?.name ?? null, message: redact(String(c?.message ?? c)).slice(0, 300), code: c?.code ?? null, errno: c?.errno ?? null, syscall: c?.syscall ?? null });
  const aggregated = Array.isArray(err?.errors)
    ? err.errors.slice(0, 10).map((x: any) => ({ name: x?.name ?? null, message: redact(String(x?.message ?? x)).slice(0, 300), code: x?.code ?? null }))
    : [];
  return {
    name: err?.name ?? null,
    message: redact(String(err?.message ?? err)).slice(0, 600),
    code: err?.code != null ? String(err.code) : null,
    requestType: err?.requestType ?? null,
    causes,
    aggregated,
  };
}

export type Timed<T> = { ok: true; value: T; ms: number } | { ok: false; error: ErrorDetails; ms: number };
export async function timed<T>(f: () => Promise<T>): Promise<Timed<T>> {
  const s = performance.now();
  try {
    return { ok: true, value: await f(), ms: Math.round(performance.now() - s) };
  } catch (e) {
    return { ok: false, error: errorDetails(e), ms: Math.round(performance.now() - s) };
  }
}

// ------------------------------------------------------------------ daemon clients
function cred(home: string): string {
  return readFileSync(join(home, "local-credential"), "utf8").trim();
}
const wsFactory = (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any;

export async function ownerClient(home: string, name: string): Promise<any> {
  const c: any = new DaemonClient({
    url: `ws://${listen(home)}/ws`,
    clientId: `rooms-rl-${name}-${randomUUID().slice(0, 8)}`,
    clientType: "cli",
    appVersion: "0.13.2",
    localCredential: () => cred(home),
    webSocketFactory: wsFactory,
    reconnect: { enabled: false },
  } as any);
  await c.connect();
  return c;
}

export async function rpc(client: any, method: string, input: unknown): Promise<any> {
  return client.invokePluginRpc(PLUGIN, method, input);
}

export async function closeQuietly(...clients: Array<{ close(): Promise<unknown> } | null | undefined>): Promise<void> {
  for (const c of clients) await c?.close().catch(() => undefined);
}

export async function laneHost(memberClient: any, lane: { laneId: string; serverId: string }): Promise<any | null> {
  const d = await memberClient.listHosts();
  return d.hosts.find((h: any) => h.serverId === lane.serverId || h.source?.key === lane.laneId) ?? null;
}

// ------------------------------------------------------------------ v2 room operations
export async function status(client: any): Promise<any> {
  return rpc(client, "rooms.v2.status", {});
}
export async function ownedRoom(owner: any, roomId: string): Promise<any | null> {
  return (await status(owner)).owned.find((r: any) => r.roomId === roomId) ?? null;
}
export async function joinedRoom(member: any, roomId: string): Promise<any | null> {
  return (await status(member)).joined.find((r: any) => r.roomId === roomId) ?? null;
}
export async function joiningRoom(member: any, roomId: string): Promise<any | null> {
  return (await status(member)).joining.find((r: any) => r.roomId === roomId) ?? null;
}

/** An interactive admin action (I-14): `rooms.v2.admin.prepare` returns a one-time token, the action uses it. */
export async function adminRpc(client: any, method: string, input: Record<string, unknown>): Promise<any> {
  const kind = method.replace(/^rooms\.v2\./, "");
  const p = await rpc(client, "rooms.v2.admin.prepare", { action: { kind, ...input } });
  return rpc(client, method, { ...input, confirmToken: p.confirmToken });
}

/** Waits until the plugin's v2 runtime answers with a state other than `starting`. */
export async function v2Ready(client: any): Promise<any> {
  return until("v2 runtime ready", async () => {
    const s = await status(client).catch(() => null);
    return s && s.state !== "starting" ? s : null;
  }, 120_000, 500);
}

export type RoomLane = { roomId: string; laneId: string; serverId: string };

/** A room (no recovery key: a throwaway test room) with one share-live lane on `agentId`, both endpoints online. */
export async function createRoomWithLane(owner: any, agentId: string, label: string): Promise<RoomLane> {
  const created = await rpc(owner, "rooms.v2.room.create", { recovery: "skip" });
  const roomId: string = created.roomId;
  await until("room endpoint online", async () => (await ownedRoom(owner, roomId))?.endpoint === "online", 60_000, 500);
  const lane = await adminRpc(owner, "rooms.v2.lane.create", { roomId, agentId, label });
  const laneId: string = lane.laneId;
  const l = await until("lane endpoint online", async () => (await ownedRoom(owner, roomId))?.lanes.find((x: any) => x.laneId === laneId && x.endpoint === "online"), 60_000, 500);
  return { roomId, laneId, serverId: l.serverId };
}

/** A fresh one-time invite for the room and lane. The code goes to the secret-scan file only. */
export async function invite(owner: any, room: RoomLane, note: string): Promise<{ code: string; inviteRef: string }> {
  const inv = await adminRpc(owner, "rooms.v2.invite.create", { roomId: room.roomId, lanes: [room.laneId], note });
  rememberInvite(inv.code);
  return { code: inv.code, inviteRef: inv.inviteRef };
}

export type EnrollSteps = { startMs: number; sasMs: number; confirmMs: number; admitMs: number; openMs: number };

/**
 * The real SAS enrollment (enrollment-v2): join.start on the member, both sides show the 6-digit SAS,
 * a TEST-ONLY programmatic comparison stands in for the people comparing by voice (the digits must be
 * equal and well-formed; they are never logged), then the member confirms and the owner admits.
 * Relay trust: only the default relay may be used; a relay that needs the user's trust is refused here.
 */
export async function enroll(owner: any, member: any, room: RoomLane, code: string, label: string): Promise<{ memberId: string; deviceId: string; steps: EnrollSteps }> {
  const t = () => performance.now();
  const preview = await rpc(member, "rooms.v2.join.preview", { code });
  if (preview.roomId !== room.roomId) throw new Error("preview names another room");
  if (preview.relay?.trusted !== true) throw new Error("refusing: the invite's relay is not trusted by default (the reliability suite never grants relay trust)");
  let s = t();
  await rpc(member, "rooms.v2.join.start", { code, label });
  const startMs = Math.round(t() - s);
  s = t();
  const mine = await until("member SAS", async () => {
    const j = await joiningRoom(member, room.roomId);
    if (j?.state === "failed") throw new Error(`join failed: ${j.failure}`);
    return j?.sas ? j : null;
  }, 60_000, 200);
  const card = await until("owner SAS", async () => (await ownedRoom(owner, room.roomId))?.joinRequests.find((r: any) => r.sas && r.state !== "closed" && r.label === label), 60_000, 200);
  const sasMs = Math.round(t() - s);
  // TEST-ONLY comparison: never skipped, never logged.
  if (!/^\d{3} \d{3}$/.test(String(mine.sas)) || mine.sas !== card.sas) {
    await rpc(member, "rooms.v2.join.confirm", { roomId: room.roomId, match: false }).catch(() => undefined);
    throw new Error("SAS mismatch between member and owner: refusing to confirm");
  }
  s = t();
  await rpc(member, "rooms.v2.join.confirm", { roomId: room.roomId, match: true });
  await until("host saw the member's confirmation", async () => (await ownedRoom(owner, room.roomId))?.joinRequests.find((r: any) => r.pendingId === card.pendingId)?.state === "member_ok", 60_000, 200);
  const confirmMs = Math.round(t() - s);
  s = t();
  await adminRpc(owner, "rooms.v2.join.admit", { roomId: room.roomId, pendingId: card.pendingId });
  const admitMs = Math.round(t() - s);
  s = t();
  const j = await until("member session open", async () => {
    const r = await joinedRoom(member, room.roomId);
    return r?.status === "open" ? r : null;
  }, 60_000, 200);
  return { memberId: j.memberId, deviceId: j.deviceId, steps: { startMs, sasMs, confirmMs, admitMs, openMs: Math.round(t() - s) } };
}

/** Lane registered on the member (journal `registered`, a current grant) and its routed host online. */
export async function laneOnline(member: any, room: RoomLane, timeoutMs = 60_000): Promise<any> {
  return until("lane registered and online on the member", async () => {
    const st = await status(member);
    const j = st.joining.find((r: any) => r.roomId === room.roomId);
    const l = st.joined.find((r: any) => r.roomId === room.roomId)?.lanes.find((x: any) => x.laneId === room.laneId);
    if (j?.state !== "registered" || !l?.gid) return null;
    return (await laneHost(member, room))?.status === "online" ? l : null;
  }, timeoutMs, 250);
}

/**
 * Opens a read-only lane view exactly as the app does: a mobile-type client on the member daemon,
 * then a DaemonClient over createHostChannelTransport to the lane's serverId.
 */
export async function openLaneView(memberHome: string, laneServerId: string): Promise<{ origin: any; routed: any; statuses: Array<{ at: number; status: string }> }> {
  const origin: any = new DaemonClient({
    url: `ws://${listen(memberHome)}/ws`,
    clientId: `rooms-rl-app-${randomUUID().slice(0, 8)}`,
    clientType: "mobile",
    appVersion: "0.13.2",
    localCredential: () => cred(memberHome),
    webSocketFactory: wsFactory,
  } as any);
  await origin.connect();
  const clientId = randomUUID();
  const routed: any = new DaemonClient({
    url: "ws://routed-host/ws",
    clientId,
    clientType: "mobile",
    appVersion: "0.13.2",
    transportFactory: createHostChannelTransport(origin, laneServerId, clientId, null),
  } as any);
  const statuses: Array<{ at: number; status: string }> = [];
  routed.subscribeConnectionStatus((s: any) => statuses.push({ at: Date.now(), status: s.status }));
  await routed.connect();
  return { origin, routed, statuses };
}

// ------------------------------------------------------------------ daemon lifecycle (test homes only)
function runCli(home: string, args: string[], timeoutMs = 180_000): Promise<{ code: number; stdout: string; stderr: string }> {
  assertSafeEnvironment();
  return new Promise((res) => {
    const child = execFile(
      PASEO_CLI,
      [...args, "--home", home],
      { env: { ...process.env, PASEO_HOME: home, PASEO_DICTATION_ENABLED: "false", PASEO_VOICE_MODE_ENABLED: "false" }, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => res({ code: err ? ((err as any).code ?? 1) : 0, stdout: String(stdout), stderr: String(stderr) }),
    );
    child.stdin?.end();
  });
}

export function tcpOpen(port: number, timeoutMs = 1000): Promise<boolean> {
  return new Promise((res) => {
    const s = connect({ host: "127.0.0.1", port }, () => {
      s.destroy();
      res(true);
    });
    s.on("error", () => res(false));
    setTimeout(() => {
      s.destroy();
      res(false);
    }, timeoutMs);
  });
}

export async function stopDaemon(home: string): Promise<number> {
  const port = configuredPort(home);
  const s = Date.now();
  const r = await runCli(home, ["daemon", "stop"]);
  await until(`port ${port} closed`, async () => !(await tcpOpen(port)), 60_000, 250);
  const ms = Date.now() - s;
  log("daemon_stopped", { home: home.split("/").pop(), cliExit: r.code, ms });
  return ms;
}

export async function startDaemon(home: string): Promise<number> {
  const port = configuredPort(home);
  const s = Date.now();
  const r = await runCli(home, ["daemon", "start", "--timeout", "120"]);
  if (r.code !== 0) throw new Error(`daemon start failed (exit ${r.code}): ${redact(r.stderr).slice(0, 300)}`);
  await until(`port ${port} open`, () => tcpOpen(port), 120_000, 250);
  // The plugin must be loaded again before RPCs work.
  await until(
    "plugin RPC answers after start",
    async () => {
      const c = await ownerClient(home, "probe");
      try {
        return (await rpc(c, "rooms.bootstrap", {}))?.ok === true;
      } finally {
        await closeQuietly(c);
      }
    },
    120_000,
    500,
  );
  const ms = Date.now() - s;
  log("daemon_started", { home: home.split("/").pop(), ms });
  return ms;
}

export async function pluginLogs(home: string): Promise<string> {
  const r = await runCli(home, ["plugin", "logs", PLUGIN], 60_000);
  return redact(r.stdout + r.stderr);
}

// ------------------------------------------------------------------ on-disk plugin state (read-only)
export function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}
export function roomsDataDir(home: string): string {
  return join(home, "plugin-data", "rooms");
}
export function hostRoomDir(home: string, roomId: string): string {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(roomId)) throw new Error("bad room id");
  return join(roomsDataDir(home), "host", roomId);
}
export function memberRoomDir(home: string, roomId: string): string {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(roomId)) throw new Error("bad room id");
  return join(roomsDataDir(home), "member", "rooms", roomId);
}

/**
 * Independent fold of the owner's room log file (genesis, every entry, statement bodies): the hash
 * chain, host and statement signatures and the fold rules. Returns per-entry hashes (public data) and
 * the types; throws if anything does not verify.
 */
export function verifyOwnerLog(home: string, roomId: string): { head: { seq: number; hash: string }; hashes: string[]; types: string[] } {
  const dir = hostRoomDir(home, roomId);
  const fold = RoomLogFold.fromGenesis(new Uint8Array(readFileSync(join(dir, "genesis.json"))));
  const bodies = new Map<number, string>();
  for (const l of readFileSync(join(dir, "log", "bodies.jsonl"), "utf8").split("\n").filter(Boolean)) {
    const b = JSON.parse(l) as { seq: number; body: string };
    bodies.set(b.seq, b.body);
  }
  const hashes: string[] = [];
  const types: string[] = [];
  for (const l of readFileSync(join(dir, "log", "entries.jsonl"), "utf8").split("\n").filter(Boolean)) {
    const e = JSON.parse(l);
    const b = bodies.get(e.entry.seq);
    fold.append(e, b ? new Uint8Array(Buffer.from(b, "base64url")) : undefined);
    hashes.push(e.hash);
    types.push(e.entry.type);
  }
  return { head: fold.head, hashes, types };
}

/** Public key ids and server ids of the owner's room (status view): what must not change across restarts. */
export async function ownerSnapshot(owner: any, room: RoomLane) {
  const r = await ownedRoom(owner, room.roomId);
  if (!r) throw new Error("owned room not in status");
  return {
    hostKid: r.keys.hostKid as string | null,
    adminKid: r.keys.adminKid as string | null,
    endpointServerId: r.serverId as string,
    laneServerId: (r.lanes.find((l: any) => l.laneId === room.laneId)?.serverId ?? null) as string | null,
    roster: new Map<string, string[]>(r.roster.map((m: any) => [m.memberId, m.devices.map((d: any) => d.deviceId)])),
    grants: (r.grants as Array<{ deviceId: string; laneId: string; gid: string; exp: number }>).filter((g) => g.laneId === room.laneId),
  };
}

/** Stored agent record: $PASEO_HOME/agents/<cwd slug>/<agentId>.json (read-only scan). */
export function findStoredAgentRecord(home: string, agentId: string): { file: string; rec: any } | null {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(agentId)) return null;
  const dir = join(home, "agents");
  if (!existsSync(dir)) return null;
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const p = join(dir, d.name, `${agentId}.json`);
    if (existsSync(p)) return { file: p.slice(home.length + 1), rec: readJson(p) };
  }
  return null;
}

export function registerAgent(agentId: string): void {
  appendFileSync(AGENTS_FILE(), agentId + "\n");
}
