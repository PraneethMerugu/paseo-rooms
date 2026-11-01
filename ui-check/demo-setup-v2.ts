// Demo state for the identity v2 UI check. Called by up-v2.sh; not part of the plugin bundle.
//
//   owner   (6912): "UI check room v2" with a recovery key (code discarded in memory, never shown or
//                   saved), one lane on a Claude Haiku agent created WITHOUT a prompt (no model call),
//                   one open unused invite; "SAS demo room" (recovery skipped) with a pending join.
//   member  (6913): admitted to room 1 by the real enrollment flow (invite, SAS, confirm, admit); lane
//                   registered with a grant; two MLS chat messages exchanged with the owner's device;
//                   pending join of "SAS demo room" (one abandoned attempt before it), SAS shown.
//   member2 (6914): the member's second device, linked from 6913 (link SAS, both confirm) and held:
//                   device A is younger than 24 h, so an admin must approve and A sees "Was this you?".
//                   Its attempt to reuse the SAS demo invite marks that request as contested.
//
// TEST-ONLY: the six-digit SAS that people compare by voice is read here from both screens' status
// and checked equal before "Codes match" and "Admit" are pressed programmatically.
// Never prints or writes invite codes, link codes, grants, tokens or the recovery code. At the end it
// scans every file under .homes-v2 for the codes and tokens it held, and fails if one is found.
import { appendFileSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";

const OWNER = process.env.UI_OWNER_HOME!;
const MEMBER = process.env.UI_MEMBER_HOME!;
const MEMBER2 = process.env.UI_MEMBER2_HOME!;
const WORK = process.env.UI_WORK!;
const AGENTS_FILE = process.env.UI_AGENTS_FILE!;
const OFFLINE = process.env.UI_OFFLINE === "1";
const HOMES = dirname(OWNER);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const say = (msg: string) => console.log(`   ${msg}`);
const listen = (home: string) => JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
const cred = (home: string) => readFileSync(join(home, "local-credential"), "utf8").trim();

async function until<T>(what: string, f: () => Promise<T | null | undefined | false>, timeoutMs = 30_000, stepMs = 300): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await f().catch(() => null);
    if (v) return v as T;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
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

async function client(home: string, name: string): Promise<any> {
  const address = listen(home);
  if (!/^127\.0\.0\.1:691[2-4]$/.test(address)) throw new Error(`refusing to talk to ${address}: not a v2 UI-check daemon`);
  const c: any = new DaemonClient({
    url: `ws://${address}/ws`,
    clientId: `rooms-ui-check-v2-${name}-${randomUUID().slice(0, 8)}`,
    clientType: "cli",
    appVersion: "0.13.2",
    localCredential: () => cred(home),
    webSocketFactory: (url: string, o?: any) => new WebSocket(url, o?.protocols, { headers: o?.headers, perMessageDeflate: false }) as any,
    reconnect: { enabled: false },
  } as any);
  await c.connect();
  return c;
}
const rpc = (c: any, method: string, input: unknown): Promise<any> => c.invokePluginRpc("rooms", method, input);
/** An interactive admin action: prepare returns a one-time token (what the confirmation dialog does). */
async function adminRpc(c: any, method: string, input: Record<string, unknown>): Promise<any> {
  const kind = method.replace(/^rooms\.v2\./, "");
  const p = await rpc(c, "rooms.v2.admin.prepare", { action: { kind, ...input } });
  return rpc(c, method, { ...input, confirmToken: p.confirmToken });
}
const status = (c: any) => rpc(c, "rooms.v2.status", {});
const owned = async (c: any, roomId: string) => (await status(c)).owned.find((r: any) => r.roomId === roomId);
const joining = async (c: any, roomId: string) => (await status(c)).joining.find((j: any) => j.roomId === roomId);
const joined = async (c: any, roomId: string) => (await status(c)).joined.find((j: any) => j.roomId === roomId);
const mlsOf = async (c: any, roomId: string) => (await status(c)).mls.find((r: any) => r.roomId === roomId);
const openCard = async (c: any, roomId: string, kind: "invite" | "link") =>
  (await owned(c, roomId))?.joinRequests.find((p: any) => p.kind === kind && p.state !== "closed" && p.state !== "admitted");
const tokenOf = (code: string) => JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8")).token as string;
const trust = OFFLINE ? { trustRelay: true } : {};

/** Secrets held in memory only, for the final scan. Never printed. */
const secrets: string[] = [];

async function main() {
  const o = await client(OWNER, "owner");
  const m = await client(MEMBER, "member");
  const m2 = await client(MEMBER2, "member2");

  for (const [name, c] of [["v2-owner", o], ["v2-member", m], ["v2-member2", m2]] as const) {
    const s = await until(`${name} v2 runtime`, async () => {
      const r = await status(c);
      return r.state !== "starting" ? r : null;
    }, 90_000, 500);
    if (s.state !== "ready") throw new Error(`${name}: v2 runtime ${s.state}: ${s.error}`);
    if (s.keystore?.backend !== "fallback-file") throw new Error(`${name}: keystore is not the fallback file`);
    if (s.testClockOffsetMs !== undefined) throw new Error(`${name}: test clock is on; refusing`);
  }
  say("v2 runtime ready on all three daemons (fallback-file keystore, no test clock)");

  // ---------------------------------------------------------------- room 1 with a recovery key
  const created = await rpc(o, "rooms.v2.room.create", { recovery: "create" });
  const roomId: string = created.roomId;
  if (created.recovery?.code) {
    // Discarded: kept in memory only for the leak scan at the end, never shown or written.
    secrets.push(created.recovery.code, created.recovery.code.replace(/[^A-Za-z0-9]/g, ""));
  } else throw new Error("room created without a recovery key");
  created.recovery = null;
  await until("room endpoint online", async () => (await owned(o, roomId))?.endpoint === "online", 60_000);
  say(`room 1 ${roomId.slice(0, 13)}… created with a recovery key (code discarded, not shown); endpoint online`);

  const agent = await o.createAgent({ provider: "claude", model: "claude-haiku-4-5", cwd: WORK, title: "UI check v2 lane agent" });
  appendFileSync(AGENTS_FILE, `${agent.id}\n`);
  say(`lane agent ${String(agent.id).slice(0, 8)} created (Claude Haiku, no prompt: no model call)`);
  const { laneId } = await adminRpc(o, "rooms.v2.lane.create", { roomId, agentId: agent.id, label: "Demo lane" });
  await until("lane endpoint online", async () => (await owned(o, roomId))?.lanes.find((l: any) => l.laneId === laneId)?.endpoint === "online", 60_000);
  say(`lane "Demo lane" online`);

  // ---------------------------------------------------------------- enrollment of the member (6913)
  const invite = await adminRpc(o, "rooms.v2.invite.create", { roomId, lanes: [laneId], note: "for demo-member", roomName: "UI check room v2" });
  secrets.push(invite.code, tokenOf(invite.code));
  await rpc(m, "rooms.v2.join.preview", { code: invite.code });
  await rpc(m, "rooms.v2.join.start", { code: invite.code, label: "demo-member laptop", ...trust });
  invite.code = null;
  const mSas = await until("member SAS", async () => (await joining(m, roomId))?.sas, 60_000);
  const card = await until("owner SAS", async () => {
    const c = await openCard(o, roomId, "invite");
    return c?.sas ? c : null;
  }, 60_000);
  // TEST-ONLY: the comparison people make by voice. A mismatch stops the setup.
  if (mSas !== card.sas) throw new Error("SAS mismatch between member and owner: refusing to confirm");
  await rpc(m, "rooms.v2.join.confirm", { roomId, match: true });
  await until("owner saw the member's confirmation", async () => (await openCard(o, roomId, "invite"))?.state === "member_ok", 30_000);
  await adminRpc(o, "rooms.v2.join.admit", { roomId, pendingId: card.pendingId });
  await until("member session open", async () => (await joined(m, roomId))?.status === "open", 60_000);
  say("demo-member admitted (SAS compared programmatically, test-only)");
  await until("lane registered with a grant", async () => {
    const st = await status(m);
    const j = st.joining.find((r: any) => r.roomId === roomId);
    const l = st.joined.find((r: any) => r.roomId === roomId)?.lanes.find((x: any) => x.laneId === laneId);
    return j?.state === "registered" && l?.gid ? true : null;
  }, 90_000);
  say("lane registered on demo-member with a grant (routed host)");

  // ---------------------------------------------------------------- MLS chat messages
  await until("member in the room group", async () => {
    const [a, b] = [await mlsOf(o, roomId), await mlsOf(m, roomId)];
    return a?.canSend && b?.inGroup && b.canSend && a.epoch === b.epoch ? true : null;
  }, 120_000, 500);
  const texts = ["Welcome to the UI check room.", "Thanks, the demo lane shows up here.", "Second device link is pending; please check the hold."];
  await rpc(o, "rooms.v2.mls.send", { roomId, text: texts[0] });
  await rpc(m, "rooms.v2.mls.send", { roomId, text: texts[1] });
  await rpc(o, "rooms.v2.mls.send", { roomId, text: texts[2] });
  const read = async (c: any) => ((await rpc(c, "rooms.v2.mls.messages", { roomId })).messages as any[]).map((x) => x.text);
  await until("chat messages delivered", async () => {
    const [ot, mt] = [await read(o), await read(m)];
    return ot.includes(texts[1]) && mt.includes(texts[0]) && mt.includes(texts[2]) ? true : null;
  }, 30_000);
  say("3 MLS messages exchanged between the owner's device and demo-member");

  // ---------------------------------------------------------------- device link to 6914, held
  const link = await rpc(m, "rooms.v2.link.create", { roomId, roomName: "UI check room v2" });
  secrets.push(link.code, tokenOf(link.code));
  await rpc(m2, "rooms.v2.join.preview", { code: link.code });
  await rpc(m2, "rooms.v2.join.start", { code: link.code, label: "demo-member phone", ...trust });
  link.code = null;
  const bSas = await until("B's link SAS", async () => (await joining(m2, roomId))?.sas, 60_000);
  const aView = await until("A's link SAS", async () => {
    const l = (await joined(m, roomId))?.links.find((x: any) => x.linkId === link.linkId);
    return l?.pending?.sas ? l : null;
  }, 60_000);
  if (bSas !== aView.pending.sas) throw new Error("link SAS mismatch: refusing to confirm");
  await rpc(m2, "rooms.v2.join.confirm", { roomId, match: true });
  await rpc(m, "rooms.v2.link.confirm", { roomId, pendingId: aView.pending.pendingId, match: true });
  await until("B held", async () => (await joining(m2, roomId))?.state === "held", 60_000);
  const req = await until("owner sees the held device add", async () => (await owned(o, roomId))?.deviceRequests.find((r: any) => r.kind === "add" && r.status === "pending"), 30_000);
  await until("A sees 'Was this you?'", async () => (await joined(m, roomId))?.deviceRequests.some((r: any) => r.ref === req.ref && r.status === "pending"), 30_000);
  say(`second device linked and held (sole=${req.sole}, young=${req.young}, ${req.effectiveAfter === null ? "an admin must approve" : "auto-approves later"}); left pending`);

  // ---------------------------------------------------------------- an open, unused invite in room 1
  const spare = await adminRpc(o, "rooms.v2.invite.create", { roomId, note: "spare invite (unused)", expS: 86400, roomName: "UI check room v2" });
  secrets.push(spare.code, tokenOf(spare.code));
  spare.code = null;
  say("one open invite left unused in room 1 (code discarded)");

  // ---------------------------------------------------------------- room 2: pending join with SAS shown
  const room2 = await rpc(o, "rooms.v2.room.create", { recovery: "skip" });
  const roomId2: string = room2.roomId;
  await until("room 2 endpoint online", async () => (await owned(o, roomId2))?.endpoint === "online", 60_000);
  const inv2 = await adminRpc(o, "rooms.v2.invite.create", { roomId: roomId2, note: "SAS demo (left pending)", roomName: "SAS demo room" });
  secrets.push(inv2.code, tokenOf(inv2.code));
  const code2: string = inv2.code;
  inv2.code = null;
  // First attempt, cancelled by the member: the owner's card then shows one abandoned attempt.
  await rpc(m, "rooms.v2.join.start", { code: code2, label: "demo-member laptop", ...trust });
  await until("first attempt SAS on the owner", async () => (await openCard(o, roomId2, "invite"))?.sas, 60_000);
  await rpc(m, "rooms.v2.join.cancel", { roomId: roomId2 });
  await until("first attempt closed", async () => !(await openCard(o, roomId2, "invite")), 30_000);
  await attempt(() => rpc(m, "rooms.v2.join.dismiss", { roomId: roomId2 }));
  const again = await attempt(() => rpc(m, "rooms.v2.join.start", { code: code2, label: "demo-member laptop", ...trust }));
  if (!again.ok) throw new Error(`second join attempt on the SAS demo invite failed: ${again.error}`);
  const mSas2 = await until("member SAS (room 2)", async () => (await joining(m, roomId2))?.sas, 60_000);
  const card2 = await until("owner SAS (room 2)", async () => {
    const c = await openCard(o, roomId2, "invite");
    return c?.sas ? c : null;
  }, 60_000);
  say(`SAS demo room: pending join from demo-member, both sides show the code (${mSas2 === card2.sas ? "equal" : "DIFFERENT"}), abandoned attempts before: ${card2.abandonedBefore}; left pending (15 min)`);
  // The member's second device tries the same invite while it is claimed: the host refuses it and
  // marks the request as contested (red banner on the owner's card). A real flow, not injected state.
  await attempt(() => rpc(m2, "rooms.v2.join.start", { code: code2, label: "demo-member phone", ...trust }));
  const contested = await attempt(() => until("contested", async () => (await openCard(o, roomId2, "invite"))?.contested, 30_000));
  say(contested.ok ? "second device's attempt on the same invite refused: owner's card marked contested" : `contested notice not produced (${contested.error})`);

  // ---------------------------------------------------------------- summary and leak scan
  const so = await status(o);
  const r1 = so.owned.find((r: any) => r.roomId === roomId);
  const r2 = so.owned.find((r: any) => r.roomId === roomId2);
  say(
    `owner: room 1 members=${r1.members}, lanes=${r1.lanes.length}, open invites=${r1.invites.filter((i: any) => i.state === "open").length}, ` +
      `grants=${r1.grants.length}, device requests pending=${r1.deviceRequests.filter((d: any) => d.status === "pending").length}, recovery key=${r1.keys.recoveryKid ? "yes" : "no"}; ` +
      `room 2 open join requests=${r2.joinRequests.filter((j: any) => j.state !== "closed").length}`,
  );
  const sm = await status(m);
  const sm2 = await status(m2);
  say(`member: joined=${sm.joined.length}, joining=${sm.joining.filter((j: any) => j.state !== "registered").length} (room 2), mls messages=${sm.mls.find((x: any) => x.roomId === roomId)?.messages}`);
  say(`member2: joining=${sm2.joining.map((j: any) => j.state).join(",")}`);

  const found: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules") continue;
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p);
      else if (st.size < 20_000_000) {
        const text = readFileSync(p).toString("latin1");
        if (secrets.some((s) => s && s.length >= 16 && text.includes(s))) found.push(p.slice(HOMES.length + 1));
      }
    }
  };
  walk(HOMES);
  secrets.length = 0;
  if (found.length) throw new Error(`a code or token was found in files: ${found.join(", ")}`);
  say("scan: no invite code, link code, token or recovery code in any file under .homes-v2");

  await o.close?.();
  await m.close?.();
  await m2.close?.();
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`demo setup failed: ${String((e as Error)?.message ?? e).slice(0, 240)}`);
    process.exit(1);
  },
);
