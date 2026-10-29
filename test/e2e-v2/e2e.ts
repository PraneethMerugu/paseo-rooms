// Identity v2 e2e driver (implementation plan I-8). Talks to the two test daemons like the CLI does
// (DaemonClient with the local credential) and calls only the v2 plugin RPCs. Creates no agents and
// makes no model calls. Prints evidence as JSON lines; never prints keys, credentials or the genesis.
//
// Flow: v2 runtime up on both daemons (fallback-file keystore) -> owner creates a room, its endpoint
// registers on the relay -> member prepares device keys from the public genesis -> a session before
// admission gets not_authorized -> owner admits the device (hand-made roster entry) -> member opens a
// session and syncs the log to the owner's head -> owner removes the member -> the live session gets
// access_ended removed -> no plaintext secret fields in either data tree.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";

const OWNER = process.env.E2E_OWNER_HOME!;
const MEMBER = process.env.E2E_MEMBER_HOME!;
const LIVE = process.env.E2E_LIVE === "1";
const RELAY_LOG = process.env.E2E_RELAY_LOG ?? "";
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
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...files(p));
    else if (st.size < 20_000_000) out.push(p);
  }
  return out;
}

async function main() {
  log("mode", { relay: LIVE ? "live" : "fake" });
  // Plugin RPCs are served only once the plugin process is up.
  const o = await daemonClient(OWNER, "owner");
  const m = await daemonClient(MEMBER, "member");

  // ------------------------------------------------------------ 1. v2 runtime on both daemons
  const so = await until("owner v2 ready", async () => {
    const s = await attempt(() => rpc(o, "rooms.v2.status", {}));
    return s.ok && s.value.state !== "starting" ? s.value : null;
  }, 60_000, 500);
  const sm = await until("member v2 ready", async () => {
    const s = await attempt(() => rpc(m, "rooms.v2.status", {}));
    return s.ok && s.value.state !== "starting" ? s.value : null;
  }, 60_000, 500);
  check("v2 runtime ready on both daemons", so.state === "ready" && sm.state === "ready", { owner: so.state, member: sm.state, ownerError: so.error, memberError: sm.error });
  check("keystore is the protected fallback file (no keyring)", so.keystore?.backend === "fallback-file" && sm.keystore?.backend === "fallback-file", { owner: so.keystore, member: sm.keystore });
  const m1 = await attempt(() => rpc(o, "rooms.overview", {}));
  check("M1 RPCs are not registered under the v2 switch", !m1.ok, { error: m1.ok ? null : m1.error });

  // ------------------------------------------------------------ 2. owner creates a room
  const created = await rpc(o, "rooms.v2.room.create", {});
  const roomId: string = created.roomId;
  log("room_created", { roomId, serverId: `${String(created.serverId).slice(0, 10)}…` });
  const online = await attempt(() => until("endpoint online", async () => (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId)?.endpoint === "online", 30_000));
  check("room endpoint registered on the relay", online.ok, online.ok ? {} : { error: online.error });

  // ------------------------------------------------------------ 3. member device keys from the public genesis
  const { genesis } = await rpc(o, "rooms.v2.dev.room.descriptor", { roomId });
  const dev = await rpc(m, "rooms.v2.dev.device.prepare", { genesis });
  check("member prepared device keys for the room", dev.roomId === roomId && /^dev_/.test(dev.deviceId), { memberId: dev.memberId, deviceId: dev.deviceId });

  // ------------------------------------------------------------ 4. session before admission
  const early = await rpc(m, "rooms.v2.dev.room.connect", { roomId });
  check("a device not in the roster gets not_authorized after the handshake", early.lastError === "not_authorized", early);

  // ------------------------------------------------------------ 5. admit (hand-made roster entry), connect, sync
  const admitted = await rpc(o, "rooms.v2.dev.member.admit", { roomId, memberId: dev.memberId, deviceId: dev.deviceId, sig: dev.sig, dh: dev.dh });
  log("admitted", { seq: admitted.seq });
  const t1 = Date.now();
  const conn = await rpc(m, "rooms.v2.dev.room.connect", { roomId });
  const connectMs = Date.now() - t1;
  check("member opens a session after admission", conn.status === "open", { ...conn, connectMs });
  const ownerView = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  const memberView = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
  check("member synced the log to the owner's head", memberView?.head.seq === ownerView?.head.seq && memberView?.head.hash === ownerView?.head.hash, { memberHead: memberView?.head.seq, ownerHead: ownerView?.head.seq });
  check("owner sees exactly one live session, for that device", ownerView?.sessions.length === 1 && ownerView.sessions[0].deviceId === dev.deviceId, { sessions: ownerView?.sessions.length });
  check("no alerts on the member", (memberView?.alerts ?? []).length === 0, { alerts: memberView?.alerts });

  // ------------------------------------------------------------ 6. removal ends the live session
  const t2 = Date.now();
  const removed = await rpc(o, "rooms.v2.dev.member.remove", { roomId, memberId: dev.memberId });
  const ended = await attempt(() => until("member ended", async () => {
    const j = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
    return j?.status === "ended" ? j : null;
  }, 20_000, 100));
  check("removal ends the live session with access_ended removed", ended.ok && ended.value.endedReason === "removed", ended.ok ? { endedReason: ended.value.endedReason, removedSeq: removed.seq, ms: Date.now() - t2 } : { error: ended.error });
  const after = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("owner has no live session after the removal", after?.sessions.length === 0, { sessions: after?.sessions.length });
  const again = await rpc(m, "rooms.v2.dev.room.connect", { roomId });
  check("a new session of the removed device gets access_ended", again.status === "ended" && again.lastError === "access_ended", again);

  // ------------------------------------------------------------ 7. files and relay evidence
  const plaintextSecrets: string[] = [];
  const modes: Record<string, string> = {};
  for (const [label, home] of [["owner", OWNER], ["member", MEMBER]] as const) {
    const root = join(home, "plugin-data", "rooms");
    modes[`${label}:plugin-data/rooms`] = (statSync(root).mode & 0o777).toString(8);
    for (const f of files(root)) {
      const text = readFileSync(f, "utf8");
      const rel = f.slice(home.length + 1);
      if (/"(seed|secret|secretKey)"\s*:/.test(text)) plaintextSecrets.push(`${label}:${rel}`);
      if (/keys\.sealed$|admin-key\.sealed$/.test(f)) {
        modes[`${label}:${rel}`] = (statSync(f).mode & 0o777).toString(8);
        if (JSON.parse(text).typ !== "sealed") plaintextSecrets.push(`${label}:${rel}`);
      }
    }
  }
  check("no plaintext secret fields in either data tree; key files sealed", plaintextSecrets.length === 0, { found: plaintextSecrets });
  check("data dirs 0700 and key files 0600", Object.entries(modes).every(([k, v]) => (k.endsWith("rooms") ? v === "700" : v === "600")), { modes });
  if (!LIVE && RELAY_LOG && existsSync(RELAY_LOG)) {
    const lines = readFileSync(RELAY_LOG, "utf8");
    check("traffic went through the local fake relay", /v2:server\(control\)/.test(lines) && /v2:client\(conn_/.test(lines) && /v2:server\(conn_/.test(lines));
  }

  await o.close();
  await m.close();
  log("SUMMARY", { failures, seconds: Math.round((Date.now() - T0) / 1000) });
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  log("FATAL", { error: String(e?.message ?? e).slice(0, 300) });
  process.exit(1);
});
