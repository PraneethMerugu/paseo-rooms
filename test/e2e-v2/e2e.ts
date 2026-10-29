// Identity v2 e2e driver (implementation plan I-8, I-9). Talks to the two test daemons like the CLI
// does (DaemonClient with the local credential) and calls only the v2 plugin RPCs. Creates no agents
// and makes no model calls. Prints evidence as JSON lines; never prints keys, credentials, the
// genesis, the invite code or its token.
//
// Flow: v2 runtime up on both daemons (fallback-file keystore) -> owner creates a room, its endpoint
// registers on the relay -> owner creates an invite -> an invite naming an unknown relay is refused
// without the user's trust (both modes, no network); offline, the loopback relay also needs trust,
// live, relay.paseo.sh:443 is trusted by default (P-20) -> member joins: both sides show a SAS -> the codes are
// compared -> BOTH daemons restart mid-pending -> the pending resumes with the same codes on both
// sides -> member confirms, owner admits -> the member is in the roster, its session syncs the log
// -> owner removes the member -> access_ended removed -> no
// plaintext secret fields and no invite token in either data tree or in the logs.
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

const OWNER = process.env.E2E_OWNER_HOME!;
const MEMBER = process.env.E2E_MEMBER_HOME!;
const LIVE = process.env.E2E_LIVE === "1";
const RELAY_LOG = process.env.E2E_RELAY_LOG ?? "";
const PASEO_BIN = process.env.E2E_PASEO_BIN!;
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
  const invite = await rpc(o, "rooms.v2.invite.create", { roomId, note: "for the e2e member", roomName: "E2E room" });
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
  check("admitted: member journal registered (no lanes) and its room session open", joinedOk.ok && joinedOk.value.join?.state === "registered", joinedOk.ok ? { ms: Date.now() - t1, memberId: joinedOk.value.j.memberId } : { error: joinedOk.error });
  const ownerView = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  const memberJoined = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
  check("owner sees the member in the roster and the invite used", ownerView?.members === 2 && ownerView.invites[0]?.state === "used" && ownerView.joinRequests[0]?.memberId === memberJoined?.memberId, { members: ownerView?.members, invite: ownerView?.invites[0]?.state });
  await until("member synced", async () => {
    const j = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
    const ow = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
    return j?.head.seq === ow?.head.seq;
  }, 15_000).catch(() => null);
  const mv = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
  const ov = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("member synced the log to the owner's head", mv?.head.seq === ov?.head.seq && mv?.head.hash === ov?.head.hash, { memberHead: mv?.head.seq, ownerHead: ov?.head.seq });
  check("owner sees exactly one live session, for that device", ov?.sessions.length === 1 && ov.sessions[0].deviceId === mv?.deviceId, { sessions: ov?.sessions.length });
  check("no alerts on the member", (mv?.alerts ?? []).length === 0, { alerts: mv?.alerts });

  // ------------------------------------------------------------ 7. removal ends the live session
  const t2 = Date.now();
  const removed = await rpc(o, "rooms.v2.member.remove", { roomId, memberId: mv.memberId });
  const ended = await attempt(() => until("member ended", async () => {
    const j = (await rpc(m, "rooms.v2.status", {})).joined.find((r: any) => r.roomId === roomId);
    return j?.status === "ended" ? j : null;
  }, 20_000, 100));
  check("removal ends the live session with access_ended removed", ended.ok && ended.value.endedReason === "removed", ended.ok ? { endedReason: ended.value.endedReason, removedSeq: removed.seq, ms: Date.now() - t2 } : { error: ended.error });
  const after = (await rpc(o, "rooms.v2.status", {})).owned.find((r: any) => r.roomId === roomId);
  check("owner has no live session after the removal", after?.sessions.length === 0, { sessions: after?.sessions.length });
  const again = await rpc(m, "rooms.v2.room.connect", { roomId });
  check("a new session of the removed device gets access_ended", again.status === "ended" && again.lastError === "access_ended", again);

  // ------------------------------------------------------------ 8. files, logs and relay evidence
  const plaintextSecrets: string[] = [];
  const tokenFound: string[] = [];
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
      if (text.includes(token) || text.includes(code.slice(5, 80))) tokenFound.push(`${label}:${f.slice(home.length + 1)}`);
    }
  }
  check("no plaintext secret fields in either data tree; key and state files sealed", plaintextSecrets.length === 0, { found: plaintextSecrets });
  check("the invite code and token appear in no file of either home (data, logs)", tokenFound.length === 0, { found: tokenFound });
  check("data dirs 0700 and sealed files 0600", Object.entries(modes).every(([k, v]) => (k.endsWith("rooms") ? v === "700" : v === "600")), { modes });
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
