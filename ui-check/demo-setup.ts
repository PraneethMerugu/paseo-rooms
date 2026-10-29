// Demo room setup for the UI check. Called by up.sh; not part of the plugin bundle.
//   owner  (demo-owner):  rooms.create (fork lane on the parent agent), rooms.invite.create
//   member (demo-member): rooms.join, then waits until the lane is an online routed host
// Never prints the invite code, grant or credentials. Appends the fork agent id to the agents file.
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { DaemonClient } from "@getpaseo/client/internal/daemon-client";

const OWNER = process.env.UI_OWNER_HOME!;
const MEMBER = process.env.UI_MEMBER_HOME!;
const PARENT = process.env.UI_PARENT!;
const AGENTS_FILE = process.env.UI_AGENTS_FILE!;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const say = (msg: string) => console.log(`   ${msg}`);
const listen = (home: string) => JSON.parse(readFileSync(join(home, "paseo.pid"), "utf8")).listen as string;
const cred = (home: string) => readFileSync(join(home, "local-credential"), "utf8").trim();

async function until<T>(what: string, f: () => Promise<T | null | undefined | false>, timeoutMs: number): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await f().catch(() => null);
    if (v) return v as T;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(500);
  }
}

async function client(home: string, name: string): Promise<any> {
  const c: any = new DaemonClient({
    url: `ws://${listen(home)}/ws`,
    clientId: `rooms-ui-check-${name}-${randomUUID().slice(0, 8)}`,
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

async function main() {
  const owner = await client(OWNER, "owner");
  const member = await client(MEMBER, "member");

  const { room, lane } = await rpc(owner, "rooms.create", {
    name: "UI check room",
    agentId: PARENT,
    origin: "fork",
    laneLabel: "Fork lane",
    instruction: "Reply with the word OK and nothing else.",
  });
  appendFileSync(AGENTS_FILE, `${lane.agentId}\n`);
  say(`room "${room.name}" with fork lane "${lane.label}" (fork agent ${String(lane.agentId).slice(0, 8)})`);

  await until(
    "lane endpoint online on the relay",
    async () => (await rpc(owner, "rooms.overview", {})).owned.flatMap((r: any) => r.lanes).find((l: any) => l.lane.id === lane.id)?.endpoint === "online",
    60_000,
  );
  say("lane endpoint online on the Paseo relay");

  await owner.waitForFinish(lane.agentId, 180_000).catch((e: unknown) => say(`fork first turn did not finish cleanly: ${String((e as Error)?.message ?? e).slice(0, 120)}`));
  say("fork agent finished its first turn");

  const invite = await rpc(owner, "rooms.invite.create", { laneId: lane.id, ttlSeconds: 600, grantTtlSeconds: 3600 * 24 });
  say("one-time invite created on demo-owner (code passed to demo-member in memory, not printed)");
  const joined = await rpc(member, "rooms.join", { code: invite.code, label: "demo-member" });
  say(`demo-member joined: status ${joined.joined.status}`);

  const host = await until(
    "lane online as a routed host on demo-member",
    async () => {
      const j = (await rpc(member, "rooms.overview", {})).joined.find((x: any) => x.laneId === lane.id);
      return j?.hostStatus === "online" ? j : null;
    },
    60_000,
  );
  say(`routed host on demo-member: "${host.roomName} · ${host.laneLabel}" is ${host.hostStatus}`);

  await owner.close?.();
  await member.close?.();
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`demo setup failed: ${String((e as Error)?.message ?? e).slice(0, 240)}`);
    process.exit(1);
  },
);
