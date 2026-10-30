// Test harness for the MLS adapter and delivery service (implementation plan I-13). A real room host
// (createRoom over a fake keyring, temporary home) with the delivery service behind a RoomEndpoint that is
// never started: every device reaches it in process through `localRequest`, the way the owner's own
// device does, and follows the host log through its own fold. No relay, no network, no real keyring.
// A fake clock drives the host (hts), the delivery service and every member.
import { randomBytes, type KeyObject } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { createRoom, memberKeysPath, memberKeysPurpose, type CreatedRoom } from "../../server/admin/genesis";
import { RoomLogFold } from "../../server/authority/fold";
import type { SignedStatement, StatementType } from "../../server/authority/statements";
import { MlsDelivery } from "../../server/host/mls-delivery";
import { endpointKeyFromHost, RoomEndpoint } from "../../server/host/room-endpoint";
import { openKeyStore, type Kek } from "../../server/keystore/keystore";
import { KeyStoreError, type KeyStoreBackend } from "../../server/keystore/types";
import { MlsAdapter, mlsAdapter } from "../../server/mls/adapter";
import { MemoryMlsStore, MlsMember, type MlsLink, type MlsTimings } from "../../server/mls/member";
import { generateNoiseKeyPair } from "../../server/noise/handshake-state";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { stmtContext } from "../../server/proto/contexts";
import { newId } from "../../server/proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../../server/proto/keys";
import { rjcs, rjcsParse } from "../../server/proto/rjcs";
import { H, sign } from "../../server/proto/tbs";
import { tempDir } from "./helpers";

const NO_TIMER = { setInterval: () => null, clearInterval: () => {} };
export const FAST: Partial<MlsTimings> = { repairDelayMs: 0, repairJitterMs: 0, witnessMaxDelayMs: 0, retryMs: 0 };

function fakeKeyring(): () => { ok: true; backend: KeyStoreBackend; how: string } {
  const store = new Map<string, Buffer>();
  const backend: KeyStoreBackend = {
    name: "linux-secret-service",
    fallback: false,
    probe: async () => "available",
    get: async () => (store.get("kek") ? Buffer.from(store.get("kek")!) : null),
    put: async (kek) => void store.set("kek", Buffer.from(kek)),
    delete: async () => store.delete("kek"),
  };
  return () => ({ ok: true, backend, how: "fake" });
}

export type Dev = {
  name: string;
  memberId: string;
  deviceId: string;
  sigKey: KeyObject;
  sigPub: string;
  sigKid: string;
  dh: string;
  store: MemoryMlsStore;
  member: MlsMember;
  fold: RoomLogFold;
  unhook: () => void;
  /** Out of the roster: its feed stops at the removal, as a cut session would. */
  frozen?: boolean;
};

export class Harness {
  readonly devs = new Map<string, Dev>();
  clock = 1_793_300_000_000;
  readonly now = () => this.clock;
  private constructor(
    readonly adapter: MlsAdapter,
    readonly room: CreatedRoom,
    readonly kek: Kek,
    readonly dataDir: string,
    readonly endpoint: RoomEndpoint,
    readonly ds: MlsDelivery,
    private readonly cleanupDir: () => void,
    readonly timings: Partial<MlsTimings>,
    readonly random: () => number,
  ) {}

  static async create(timings: Partial<MlsTimings> = FAST, random: () => number = () => 0): Promise<Harness> {
    const t = tempDir();
    const home = join(t.dir, "home");
    mkdirSync(home, { mode: 0o700 });
    const dataDir = join(home, "plugin-data", "rooms");
    const s = await openKeyStore({ dataDir, paseoHome: home, env: {}, platform: "linux", timeoutMs: 100, native: fakeKeyring() });
    if (s.state !== "ready") throw new KeyStoreError("unavailable", s.message);
    const adapter = await mlsAdapter();
    let h: Harness | null = null;
    const now = () => h?.clock ?? 1_793_300_000_000;
    const room = await createRoom({ dataDir, kek: s.kek, relay: { host: "relay.example.org", port: 443, tls: true }, recovery: "skip", lock: NO_TIMER, now });
    let endpoint: RoomEndpoint | null = null;
    const ds = new MlsDelivery({ dataDir, kek: s.kek, host: room.host, adapter, now, push: (d, f) => endpoint!.pushToDevice(d, f), afterAppend: () => endpoint!.afterAppend() });
    endpoint = new RoomEndpoint({ host: room.host, endpointKey: endpointKeyFromHost(dataDir, s.kek, room.host), relay: { endpoint: "127.0.0.1:1", useTls: false }, mls: ds, onAppended: () => h?.syncAll(), now });
    h = new Harness(adapter, room, s.kek, dataDir, endpoint, ds, t.cleanup, timings, random);
    // The creator's own device (member keys written by createRoom).
    const plain = s.kek.readSealed(memberKeysPath(dataDir, room.roomId), memberKeysPurpose(room.roomId))!;
    const keys = rjcsParse(plain) as { memberId: string; deviceId: string; sig: { seed: string }; dh: { secret: string } };
    const sigKey = ed25519PrivateKeyFromSeed(b64uDecode(keys.sig.seed, 32));
    const dhPub = room.host.state.members[keys.memberId].devices[0].dh;
    h.addDevice("C", keys.memberId, keys.deviceId, sigKey, dhPub, true);
    h.syncAll();
    return h;
  }

  /** A device with its MLS member, following the host log through its own fold. */
  addDevice(name: string, memberId: string, deviceId: string, sigKey: KeyObject, dh: string, creator = false, store = new MemoryMlsStore()): Dev {
    const sigPub = b64u(rawPublicKey(sigKey));
    const link: MlsLink = { request: (frame) => this.endpoint.localRequest(this.currentDh(memberId, deviceId) ?? dh, frame) };
    const member = new MlsMember({ adapter: this.adapter, roomId: this.room.roomId, genesisHash: this.room.genesisHash, memberId, deviceId, device: { sigPub, sigKey }, store, link: () => link, creator, now: this.now, random: this.random, timings: this.timings });
    const d: Dev = { name, memberId, deviceId, sigKey, sigPub, sigKid: kidOf("ed25519", rawPublicKey(sigKey)), dh, store, member, fold: RoomLogFold.fromGenesis(this.room.genesis), unhook: () => {} };
    d.unhook = this.endpoint.onLocalPush(deviceId, (f) => member.onPush(f));
    this.devs.set(name, d);
    return d;
  }

  /** Restarts a device's MLS member from its store (a process restart): a fresh fold replays the log. */
  restart(name: string, store?: MemoryMlsStore): Dev {
    const d = this.dev(name);
    d.member.stop();
    d.unhook();
    this.devs.delete(name);
    const n = this.addDevice(name, d.memberId, d.deviceId, d.sigKey, d.dh, name === "C", store ?? d.store);
    this.syncAll();
    return n;
  }

  private currentDh(memberId: string, deviceId: string): string | undefined {
    return this.room.host.state.members[memberId]?.devices.find((x) => x.deviceId === deviceId)?.dh;
  }

  dev(name: string): Dev {
    const d = this.devs.get(name);
    if (!d) throw new Error(`no device ${name}`);
    return d;
  }

  /** Feeds every device's fold and MLS member up to the host head (devices out of the roster stop at their removal, as a cut session would). */
  syncAll(): void {
    for (const d of this.devs.values()) {
      if (d.frozen) continue;
      for (const r of this.room.host.entries(d.fold.head.seq + 1)) {
        const before = d.fold.state;
        d.fold.append(r.signed, r.body);
        d.member.ingest(r.signed, before, d.fold.state);
        if (!d.fold.state.members[d.memberId]?.devices.some((x) => x.deviceId === d.deviceId) && before.members[d.memberId]?.devices.some((x) => x.deviceId === d.deviceId)) {
          d.frozen = true;
          break;
        }
      }
    }
  }

  /** Runs maintenance and processing until nothing changes. */
  async settle(rounds = 12): Promise<void> {
    let last = -2;
    for (let i = 0; i < rounds; i++) {
      this.syncAll();
      for (const d of this.devs.values()) await d.member.idle();
      for (const d of this.devs.values()) if (!d.frozen) await d.member.maintain();
      this.syncAll();
      for (const d of this.devs.values()) await d.member.idle();
      const head = this.room.host.head.seq;
      if (head === last) return;
      last = head;
    }
  }

  /** Admin statement through the confirmation token, submitted through the endpoint. */
  admin(type: StatementType, data: unknown): number {
    const p = this.room.signer.prepare({ type, data: data as never, base: this.room.host.head });
    const res = this.endpoint.submit(this.room.signer.confirm(p.confirmToken));
    this.room.signer.reconcile(this.room.host);
    if (!res.ok) throw new Error(`${type}: ${res.code} ${res.reason}`);
    return res.receipt.entry.seq;
  }

  /** Admits a member with one new device (role watch unless given) and registers it. */
  admit(name: string, role = "watch"): Dev {
    const seed = randomBytes(32);
    const sigKey = ed25519PrivateKeyFromSeed(seed);
    const dh = b64u(generateNoiseKeyPair().publicKey);
    const memberId = newId("member");
    const deviceId = newId("device");
    this.admin("member.admitted", {
      member: { memberId, role, lanes: [], devices: [{ deviceId, kind: "person", sig: b64u(rawPublicKey(sigKey)), dh }] },
      confirmation: { method: "sas6", inviteRef: b64u(H("test-invite", randomBytes(8))), transcript: b64u(H("test-transcript", randomBytes(8))) },
    });
    const d = this.addDevice(name, memberId, deviceId, sigKey, dh);
    this.syncAll();
    return d;
  }

  /** A device-signed statement (e.g. device.rekeyed), submitted through the endpoint. */
  deviceStatement(d: Dev, type: StatementType, data: unknown): { ok: boolean; seq?: number; code?: string; reason?: string } {
    const body = { v: 2 as const, typ: "stmt" as const, type, roomId: this.room.roomId, producer: { kind: "device" as const, kid: d.sigKid }, base: this.room.host.head, ts: this.clock, data };
    const stmt = { body, sig: b64u(sign(d.sigKey, stmtContext(type), rjcs(body))) } as SignedStatement;
    const r = this.endpoint.submit(stmt);
    return r.ok ? { ok: true, seq: r.receipt.entry.seq } : { ok: false, code: r.code, reason: r.reason };
  }

  advance(ms: number): void {
    this.clock += ms;
  }

  cleanup(): void {
    for (const d of this.devs.values()) d.member.stop();
    this.endpoint.stop();
    this.room.host.close();
    this.cleanupDir();
  }
}
