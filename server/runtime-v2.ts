// Identity v2 development runtime (implementation plan I-8; decision D-2). Used only when the plugin
// starts with PASEO_ROOMS_PROTOCOL=v2; it never ships, and the M1 runtime is unchanged otherwise.
//
// Start (asynchronous): the plugin-data/rooms tree is created or checked (owner-only, no symlinks),
// the KeyStore is opened (I-3), then every owned room is reopened from its log (RoomHost.open re-folds)
// and its room endpoint registered on the relay. Joined rooms are not reconnected at start: the member
// journal is I-9; `connect` is explicit.
//
// Relay: the genesis records `PASEO_ROOMS_RELAY_ENDPOINT` (host:port; default relay.paseo.sh:443) with
// tls true. `PASEO_ROOMS_RELAY_TLS=false` (development and the offline e2e fake relay only) is honoured
// for loopback hosts only.
//
// Key handling: device and endpoint secrets stay in sealed files; RPC results carry public keys only.
// With an explicit file keystore (`PASEO_ROOMS_KEYSTORE=fallback-file` or `operator-file`) the native
// keyring is not probed at all, so test daemons never touch the user's keyring.
import * as fs from "node:fs";
import nodePath from "node:path";
import { randomBytes } from "node:crypto";
import { createRoom, memberKeysPath, memberKeysPurpose } from "./admin/genesis";
import { AdminSigner, adminKeyPath } from "./admin/signer";
import { verifyGenesis, type RoomGenesis } from "./authority/genesis";
import type { StatementType } from "./authority/statements";
import { endpointKeyFromHost, RoomEndpoint } from "./host/room-endpoint";
import { genesisPath, RoomHost } from "./host/room-host";
import { ENV_KEYSTORE, openKeyStore, type Kek, type KeyStoreStatus } from "./keystore/keystore";
import { log, logError } from "./log";
import { RoomClient } from "./member/room-client";
import { generateNoiseKeyPair } from "./noise/handshake-state";
import { dataDir as roomsDataDir, resolvePaseoHome } from "./paths";
import { writePrivateFile } from "./platform/durable";
import { defaultProtection, ProtectionError, type FileProtection } from "./platform/file-protection";
import { b64u, b64uDecode } from "./proto/b64u";
import { isId, isRoomId, newId } from "./proto/ids";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey, x25519PrivateKeyFromSecret } from "./proto/keys";
import { rjcs, rjcsParse, rjcsText } from "./proto/rjcs";
import { H } from "./proto/tbs";
import type { RelayAddress } from "./transport/relay-server";

export const PROTOCOL_ENV = "PASEO_ROOMS_PROTOCOL";

/** Read once at plugin start (contribute). */
export function roomsProtocol(env: NodeJS.ProcessEnv = process.env): "v1" | "v2" {
  return env[PROTOCOL_ENV] === "v2" ? "v2" : "v1";
}

const DEFAULT_RELAY = { host: "relay.paseo.sh", port: 443 };
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);

export function genesisRelay(env: NodeJS.ProcessEnv = process.env): { host: string; port: number; tls: true } {
  const raw = env.PASEO_ROOMS_RELAY_ENDPOINT;
  if (!raw) return { ...DEFAULT_RELAY, tls: true };
  const m = /^([A-Za-z0-9.-]{1,253}):(\d{1,5})$/.exec(raw);
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) throw new Error("PASEO_ROOMS_RELAY_ENDPOINT must be host:port");
  return { host: m[1], port: Number(m[2]), tls: true };
}

/** Where to reach a room's relay: TLS unless the development override applies to a loopback host. */
export function relayAddress(relay: { host: string; port: number }, env: NodeJS.ProcessEnv = process.env): RelayAddress {
  const plain = env.PASEO_ROOMS_RELAY_TLS === "false" && LOOPBACK.has(relay.host);
  return { endpoint: `${relay.host}:${relay.port}`, useTls: !plain };
}

type Owned = { host: RoomHost; signer: AdminSigner | null; endpoint: RoomEndpoint };
type Joined = { client: RoomClient; memberId: string; deviceId: string };

const MemberKeysFile = (v: unknown) => v as { v: 2; typ: "member-keys"; roomId: string; genesisHash: string; memberId: string; deviceId: string; sig: { kid: string; seed: string }; dh: { kid: string; secret: string } };

export class RoomsRuntimeV2 {
  readonly paseoHome: string;
  readonly dataDir: string;
  state: "starting" | "ready" | "error" = "starting";
  error: string | null = null;
  keystore: KeyStoreStatus | null = null;
  private kek: Kek | null = null;
  readonly owned = new Map<string, Owned>();
  readonly joined = new Map<string, Joined>();
  private started: Promise<void> | null = null;

  constructor(
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly protection: FileProtection = defaultProtection(),
  ) {
    this.paseoHome = resolvePaseoHome(env);
    this.dataDir = roomsDataDir(this.paseoHome);
  }

  start(): Promise<void> {
    this.started ??= this.startInner().catch((e) => {
      this.state = "error";
      this.error = e instanceof ProtectionError ? "permission_error" : String((e as Error)?.message ?? e).slice(0, 200);
      logError("v2_runtime_start_failed", e);
    });
    return this.started;
  }

  private async startInner(): Promise<void> {
    this.protection.ensureDir(this.dataDir);
    const check = this.protection.verifyTree(this.dataDir);
    if (!check.ok) throw new ProtectionError(check.problems);
    const explicitFile = this.env[ENV_KEYSTORE] === "fallback-file" || this.env[ENV_KEYSTORE] === "operator-file";
    const status = await openKeyStore({
      dataDir: this.dataDir,
      paseoHome: this.paseoHome,
      env: this.env,
      log,
      ...(explicitFile ? { native: () => ({ ok: false as const, reason: "not_probed", detail: "an explicit file keystore is configured" }) } : {}),
    });
    this.keystore = status;
    if (status.state !== "ready") throw new Error(`keystore ${status.state}`);
    this.kek = status.kek;
    const hostDir = nodePath.join(this.dataDir, "host");
    for (const roomId of fs.existsSync(hostDir) ? fs.readdirSync(hostDir) : []) {
      if (!isRoomId(roomId) || !fs.existsSync(genesisPath(this.dataDir, roomId))) continue;
      try {
        const host = await RoomHost.open({ dataDir: this.dataDir, kek: this.kek, roomId });
        const signer = fs.existsSync(adminKeyPath(this.dataDir, roomId)) ? AdminSigner.load({ dataDir: this.dataDir, kek: this.kek, roomId }) : null;
        this.serve(host, signer);
      } catch (e) {
        logError("v2_room_open_failed", e, { roomId });
      }
    }
    this.state = "ready";
    log("v2_runtime_started", { owned: this.owned.size, keystore: status.backend });
  }

  private async ready(): Promise<Kek> {
    await this.start();
    if (this.state !== "ready" || !this.kek) throw new Error(`Rooms v2 is not ready: ${this.error ?? this.state}`);
    return this.kek;
  }

  private serve(host: RoomHost, signer: AdminSigner | null): void {
    const g = host.state.auth.endpoint.relay;
    const endpoint = new RoomEndpoint({ host, endpointKey: endpointKeyFromHost(this.dataDir, this.kek!, host), relay: relayAddress(g, this.env) });
    this.owned.set(host.roomId, { host, signer, endpoint });
    endpoint.start();
  }

  status() {
    const ks = this.keystore;
    return {
      protocol: "v2" as const,
      state: this.state,
      error: this.error,
      keystore: ks ? { state: ks.state, backend: ks.backend, fallback: ks.state === "ready" ? ks.fallback : false } : null,
      owned: [...this.owned.values()].map(({ host, endpoint }) => ({
        roomId: host.roomId,
        serverId: endpoint.serverId,
        head: host.head,
        endpoint: endpoint.status,
        sessions: endpoint.sessions().map((s) => ({ memberId: s.memberId, deviceId: s.deviceId })),
        members: Object.keys(host.state.members).length,
      })),
      joined: [...this.joined.entries()].map(([roomId, j]) => ({
        roomId,
        memberId: j.memberId,
        deviceId: j.deviceId,
        status: j.client.status,
        head: j.client.head,
        lastError: j.client.lastError,
        endedReason: j.client.endedReason,
        alerts: j.client.alerts.map((a) => ({ type: a.type, seq: a.seq })),
      })),
    };
  }

  async createRoom(): Promise<{ roomId: string; serverId: string }> {
    const kek = await this.ready();
    // Development runtime: the recovery key is skipped so no recovery code is ever produced here.
    const room = await createRoom({ dataDir: this.dataDir, kek, relay: genesisRelay(this.env), recovery: "skip" });
    this.serve(room.host, room.signer);
    return { roomId: room.roomId, serverId: room.genesis.body.endpoint.serverId };
  }

  descriptor(roomId: string): { genesis: string } {
    const o = this.ownedRoom(roomId);
    return { genesis: rjcsText(o.host.genesis) };
  }

  /** Member side: fresh device keys for the room in `genesis`, sealed; public keys returned. */
  async prepareDevice(genesisText: string): Promise<{ roomId: string; memberId: string; deviceId: string; sig: string; dh: string }> {
    const kek = await this.ready();
    const v = verifyGenesis(new Uint8Array(Buffer.from(genesisText, "utf8")));
    const roomId = v.roomId;
    const keysPath = memberKeysPath(this.dataDir, roomId);
    if (fs.existsSync(keysPath)) throw new Error("This daemon already holds device keys for that room");
    const sigSeed = randomBytes(32);
    const dhSecret = randomBytes(32);
    try {
      const sigPub = rawPublicKey(ed25519PrivateKeyFromSeed(sigSeed));
      const dhPub = rawPublicKey(x25519PrivateKeyFromSecret(dhSecret));
      const memberId = newId("member");
      const deviceId = newId("device");
      const plain = Buffer.from(
        rjcs({ v: 2, typ: "member-keys", roomId, genesisHash: v.genesisHash, memberId, deviceId, sig: { kid: kidOf("ed25519", sigPub), seed: b64u(sigSeed) }, dh: { kid: kidOf("x25519", dhPub), secret: b64u(dhSecret) } }),
      );
      try {
        kek.writeSealed(keysPath, memberKeysPurpose(roomId), plain);
      } finally {
        plain.fill(0);
      }
      writePrivateFile(nodePath.join(nodePath.dirname(keysPath), "genesis.json"), genesisText);
      log("v2_device_prepared", { roomId, memberId, deviceId });
      return { roomId, memberId, deviceId, sig: b64u(sigPub), dh: b64u(dhPub) };
    } finally {
      sigSeed.fill(0);
      dhSecret.fill(0);
    }
  }

  /** Owner side: hand-made roster entry for those public keys (stands in for enrollment, I-9). */
  async admitDev(i: { roomId: string; memberId: string; deviceId: string; sig: string; dh: string }): Promise<{ seq: number }> {
    await this.ready();
    if (!isId("member", i.memberId) || !isId("device", i.deviceId)) throw new Error("bad member or device id");
    const marker = H("dev-admit", Buffer.from(i.memberId));
    return this.adminDo(i.roomId, "member.admitted", {
      member: { memberId: i.memberId, role: "watch", lanes: [], devices: [{ deviceId: i.deviceId, kind: "person", sig: i.sig, dh: i.dh }] },
      // No SAS ran: development stand-in (I-9 replaces this RPC). Marked by fixed-label hashes.
      confirmation: { method: "sas6", inviteRef: b64u(marker), transcript: b64u(H("dev-admit-transcript", marker)) },
    });
  }

  async removeDev(roomId: string, memberId: string): Promise<{ seq: number }> {
    await this.ready();
    return this.adminDo(roomId, "member.removed", { memberId, reason: "admin" });
  }

  private adminDo(roomId: string, type: StatementType, data: unknown): { seq: number } {
    const o = this.ownedRoom(roomId);
    if (!o.signer) throw new Error("No admin key for this room on this daemon");
    // The RPC caller is the confirmation (development runtime; the UI flow is I-14).
    const p = o.signer.prepare({ type, data: data as never, base: o.host.head });
    const res = o.endpoint.submit(o.signer.confirm(p.confirmToken));
    o.signer.reconcile(o.host);
    if (!res.ok) throw new Error(`${type} refused: ${res.code} (${res.reason})`);
    log("v2_admin_statement", { roomId, type, seq: res.receipt.entry.seq });
    return { seq: res.receipt.entry.seq };
  }

  /** Member side: opens (or reopens) the room session with the sealed device key. */
  async connect(roomId: string): Promise<{ status: RoomClient["status"]; lastError: string | null }> {
    const kek = await this.ready();
    this.joined.get(roomId)?.client.close();
    const keysPath = memberKeysPath(this.dataDir, roomId);
    const plain = kek.readSealed(keysPath, memberKeysPurpose(roomId));
    if (!plain) throw new Error("No device keys for that room on this daemon");
    let keys: ReturnType<typeof MemberKeysFile>;
    try {
      keys = MemberKeysFile(rjcsParse(plain));
    } finally {
      plain.fill(0);
    }
    const secret = new Uint8Array(b64uDecode(keys.dh.secret, 32));
    const publicKey = rawPublicKey(x25519PrivateKeyFromSecret(secret));
    const genesisFile = nodePath.join(nodePath.dirname(keysPath), "genesis.json");
    const genesis: RoomGenesis | Uint8Array = fs.existsSync(genesisFile) ? new Uint8Array(fs.readFileSync(genesisFile)) : this.ownedRoom(roomId).host.genesis;
    const v = verifyGenesis(genesis);
    const client = new RoomClient({ genesis, device: { publicKey: new Uint8Array(publicKey), secretKey: secret }, relay: relayAddress(v.genesis.body.endpoint.relay, this.env) });
    this.joined.set(roomId, { client, memberId: keys.memberId, deviceId: keys.deviceId });
    try {
      await client.connect();
    } catch (e) {
      log("v2_connect_failed", { roomId, code: (e as { code?: string }).code ?? "error" });
    }
    return { status: client.status, lastError: client.lastError };
  }

  disconnect(roomId: string): void {
    this.joined.get(roomId)?.client.close();
  }

  private ownedRoom(roomId: string): Owned {
    const o = this.owned.get(roomId);
    if (!o) throw new Error("Unknown room");
    return o;
  }

  async stop(): Promise<void> {
    for (const j of this.joined.values()) j.client.close();
    for (const o of this.owned.values()) {
      o.endpoint.stop();
      o.host.close();
    }
    this.kek?.dispose();
    log("v2_runtime_stopped", {});
  }
}
