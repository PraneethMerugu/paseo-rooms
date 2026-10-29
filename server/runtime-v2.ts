// Identity v2 development runtime (implementation plan I-8; decision D-2). Used only when the plugin
// starts with PASEO_ROOMS_PROTOCOL=v2; it never ships, and the M1 runtime is unchanged otherwise.
//
// Start (asynchronous): the plugin-data/rooms tree is created or checked (owner-only, no symlinks),
// the KeyStore is opened (I-3), then every owned room is reopened from its log (RoomHost.open re-folds)
// and its room endpoint, which serves enrollment, registered on the relay. Then every member journal
// (I-9) resumes from its state: a pending join resumes with `enroll.resume`, an admitted one runs lane
// registration and opens its room session (C-12: armed at start, not on first app contact).
//
// Enrollment (I-9): the owner creates invites and admits join requests after the SAS comparison; the
// member previews and joins with a `prc2.` code, compares the SAS and confirms. Admin actions are
// signed through the AdminSigner's confirmation token; the RPC call is the confirmation in this
// development runtime (the UI flow is I-14).
//
// Relay: the genesis records `PASEO_ROOMS_RELAY_ENDPOINT` (host:port; default relay.paseo.sh:443) with
// tls true. Owner side: `PASEO_ROOMS_RELAY_TLS=false` is honoured for loopback hosts only. Member side
// (P-20): TLS always, a DNS-name relay, and a relay outside `trustedRelays` only after the user's
// explicit trust; plain ws to a loopback relay only with PASEO_ROOMS_DEV_INSECURE_RELAY=1.
//
// Key handling: device and endpoint secrets stay in sealed files; RPC results carry public keys only.
// With an explicit file keystore (`PASEO_ROOMS_KEYSTORE=fallback-file` or `operator-file`) the native
// keyring is not probed at all, so test daemons never touch the user's keyring.
import * as fs from "node:fs";
import nodePath from "node:path";
import type { PaseoApi } from "@getpaseo/client";
import { createRoom, memberKeysPath, memberKeysPurpose } from "./admin/genesis";
import { AdminSigner, adminKeyPath } from "./admin/signer";
import { verifyGenesis, type RoomGenesis } from "./authority/genesis";
import type { StatementType } from "./authority/statements";
import type { PendingView, InviteView } from "./host/enrollment";
import { isDevInsecureRelay, memberRelayUseTls, relayKey } from "./host/invites";
import { endpointKeyFromHost, RoomEndpoint } from "./host/room-endpoint";
import { genesisPath, RoomHost } from "./host/room-host";
import { ENV_KEYSTORE, openKeyStore, type Kek, type KeyStoreStatus } from "./keystore/keystore";
import { log, logError } from "./log";
import { MemberEnrollment, type JoinView } from "./member/enroll-client";
import { EnrollmentJournal } from "./member/enrollment-journal";
import { checkInvite, DEFAULT_TRUSTED_RELAYS, laneHostLabel, requireRelayTrust, type InvitePreview } from "./member/invite-check";
import { LaneRegistrar, type HostsApi } from "./member/lane-registration";
import { RoomClient } from "./member/room-client";
import { dataDir as roomsDataDir, resolvePaseoHome } from "./paths";
import { writePrivateFile } from "./platform/durable";
import { defaultProtection, ProtectionError, type FileProtection } from "./platform/file-protection";
import { b64uDecode } from "./proto/b64u";
import { isValidLabel } from "./proto/enroll";
import { isId, isRoomId } from "./proto/ids";
import { rawPublicKey, x25519PrivateKeyFromSecret } from "./proto/keys";
import { rjcsParse } from "./proto/rjcs";
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

/** Member side (P-20): TLS unless PASEO_ROOMS_DEV_INSECURE_RELAY=1 and the relay is on loopback. */
export function memberRelayAddress(relay: { host: string; port: number }, env: NodeJS.ProcessEnv = process.env): RelayAddress {
  return { endpoint: `${relay.host}:${relay.port}`, useTls: memberRelayUseTls(relay.host, isDevInsecureRelay(env)) };
}

/** Owner side: where the room endpoint reaches its relay. TLS unless the development override applies to a loopback host. */
export function relayAddress(relay: { host: string; port: number }, env: NodeJS.ProcessEnv = process.env): RelayAddress {
  const plain = env.PASEO_ROOMS_RELAY_TLS === "false" && LOOPBACK.has(relay.host);
  return { endpoint: `${relay.host}:${relay.port}`, useTls: !plain };
}


type Owned = { host: RoomHost; signer: AdminSigner | null; endpoint: RoomEndpoint };
type Joined = { client: RoomClient; memberId: string; deviceId: string };

const MemberKeysFile = (v: unknown) => v as { v: 2; typ: "member-keys"; roomId: string; genesisHash: string; memberId: string; deviceId: string; sig: { kid: string; seed: string }; dh: { kid: string; secret: string } };

const SETTINGS_FILE = "settings.json";
const PLUGIN_ID = "rooms";

export class RoomsRuntimeV2 {
  readonly paseoHome: string;
  readonly dataDir: string;
  state: "starting" | "ready" | "error" = "starting";
  error: string | null = null;
  keystore: KeyStoreStatus | null = null;
  private kek: Kek | null = null;
  readonly owned = new Map<string, Owned>();
  readonly joined = new Map<string, Joined>();
  /** Member journals by room: running enrollments and failed joins kept for the UI. */
  readonly joining = new Map<string, MemberEnrollment>();
  private readonly registrars = new Map<string, LaneRegistrar>();
  private paseo: PaseoApi | null = null;
  private started: Promise<void> | null = null;
  private stopping = false;

  constructor(
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly protection: FileProtection = defaultProtection(),
    /** Test only: shorter session timers and retries. */
    private readonly tuning: { timings?: ConstructorParameters<typeof RoomClient>[0]["timings"]; retryMs?: number[] } = {},
  ) {
    this.paseoHome = resolvePaseoHome(env);
    this.dataDir = roomsDataDir(this.paseoHome);
  }

  /** The PaseoApi of the latest RPC context: lane registration waits for it (section 8). */
  attach(paseo: PaseoApi | null | undefined): void {
    if (paseo) this.paseo = paseo;
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
    // Member journals (7.3 "On restart").
    for (const roomId of EnrollmentJournal.rooms(this.dataDir)) {
      if (!isRoomId(roomId)) continue;
      try {
        const j = EnrollmentJournal.read({ dataDir: this.dataDir, kek: this.kek, roomId });
        if (j) this.resumeJournal(j);
      } catch (e) {
        logError("v2_journal_open_failed", e, { roomId });
      }
    }
    this.state = "ready";
    log("v2_runtime_started", { owned: this.owned.size, joining: this.joining.size, keystore: status.backend });
  }

  private async ready(): Promise<Kek> {
    await this.start();
    if (this.state !== "ready" || !this.kek) throw new Error(`Rooms v2 is not ready: ${this.error ?? this.state}`);
    return this.kek;
  }

  private serve(host: RoomHost, signer: AdminSigner | null): void {
    const g = host.state.auth.endpoint.relay;
    const roomId = host.roomId;
    const endpoint = new RoomEndpoint({
      host,
      endpointKey: endpointKeyFromHost(this.dataDir, this.kek!, host),
      relay: relayAddress(g, this.env),
      ...(this.tuning.timings ? { timings: this.tuning.timings } : {}),
      enrollment: { dataDir: this.dataDir, kek: this.kek!, admin: signer ? (type, data) => this.adminSubmit(roomId, type, data) : null },
    });
    this.owned.set(roomId, { host, signer, endpoint });
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
        invites: (endpoint.enrollment?.invites() ?? []).map(inviteView),
        joinRequests: (endpoint.enrollment?.pendings() ?? []).map(pendingView),
      })),
      joining: [...this.joining.values()].map((e) => joinView(e.view())),
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

  // ------------------------------------------------------------------------------ owner: enrollment

  /** Creates an invite. The returned code is a bearer secret until used or expired (2.2). */
  async createInvite(i: { roomId: string; role?: string; expS?: number; note?: string; roomName?: string }): Promise<{ code: string; inviteId: string; inviteRef: string; exp: number }> {
    await this.ready();
    return this.enrollmentOf(i.roomId).createInvite({ role: i.role, expS: i.expS, note: i.note, roomName: i.roomName });
  }

  async revokeInvite(roomId: string, inviteId: string): Promise<void> {
    await this.ready();
    if (!isId("invite", inviteId)) throw new Error("bad inviteId");
    this.enrollmentOf(roomId).revokeInvite(inviteId);
  }

  /** Admit: the owner compared the SAS with the person and pressed Admit (6.3). */
  async admitJoin(roomId: string, pendingId: string): Promise<{ state: string }> {
    await this.ready();
    return { state: this.enrollmentOf(roomId).admit(pendingId) };
  }

  async rejectJoin(roomId: string, pendingId: string, reason: "sas_mismatch" | "cancel"): Promise<void> {
    await this.ready();
    this.enrollmentOf(roomId).reject(pendingId, reason);
  }

  async removeMember(roomId: string, memberId: string): Promise<{ seq: number }> {
    await this.ready();
    if (!isId("member", memberId)) throw new Error("bad memberId");
    return { seq: this.adminSubmit(roomId, "member.removed", { memberId, reason: "admin" }).receipt.entry.seq };
  }

  /** Signs (the RPC call is the confirmation in the development runtime) and submits through the endpoint. */
  private adminSubmit(roomId: string, type: StatementType, data: unknown) {
    const o = this.ownedRoom(roomId);
    if (!o.signer) throw new Error("No admin key for this room on this daemon");
    const p = o.signer.prepare({ type, data: data as never, base: o.host.head });
    const statement = o.signer.confirm(p.confirmToken);
    const res = o.endpoint.submit(statement);
    o.signer.reconcile(o.host);
    if (!res.ok) throw new Error(`${type} refused: ${res.code} (${res.reason})`);
    log("v2_admin_statement", { roomId, type, seq: res.receipt.entry.seq });
    return { statement, receipt: res.receipt };
  }

  private enrollmentOf(roomId: string) {
    const e = this.ownedRoom(roomId).endpoint.enrollment;
    if (!e) throw new Error("Enrollment is not served for this room");
    return e;
  }

  // ------------------------------------------------------------------------------ member: joining

  /** Section 2.3 steps 1 to 5. Nothing is stored or connected. */
  async previewJoin(code: string): Promise<InvitePreview> {
    await this.ready();
    return checkInvite(code, { nowS: Math.floor(Date.now() / 1000), trustedRelays: this.trustedRelays(), env: this.env }).preview;
  }

  /** "Join": checks again, trusts the relay if the user ticked it, journals the keys, starts enrollment. */
  async startJoin(i: { code: string; label: string; trustRelay?: boolean }): Promise<{ roomId: string }> {
    const kek = await this.ready();
    const { payload, preview } = checkInvite(i.code, { nowS: Math.floor(Date.now() / 1000), trustedRelays: this.trustedRelays(), env: this.env });
    requireRelayTrust(preview, i.trustRelay === true);
    if (!isValidLabel(i.label)) throw new Error("The device label must be 1 to 80 characters without control characters");
    const roomId = payload.roomId;
    if (this.owned.has(roomId)) throw new Error("This daemon hosts that room");
    if (this.joined.has(roomId)) throw new Error("This daemon is already a member of that room");
    const old = EnrollmentJournal.read({ dataDir: this.dataDir, kek, roomId });
    if (old && old.state !== "failed") throw new Error(`A join of that room is already ${old.state}`);
    this.joining.get(roomId)?.close();
    old?.remove();
    if (!preview.relay.trusted) this.trustRelay(payload.endpoint.relay);
    const j = EnrollmentJournal.begin({ dataDir: this.dataDir, kek, invite: payload, label: i.label });
    log("join_started", { roomId, relayTrusted: preview.relay.trusted });
    this.resumeJournal(j);
    return { roomId };
  }

  /** "Codes match" (true) or "Codes do not match" (false), after comparing with the owner. */
  async confirmJoin(roomId: string, match: boolean): Promise<JoinView> {
    await this.ready();
    const e = this.joining.get(roomId);
    if (!e) throw new Error("No join in progress for that room");
    await e.confirm(match);
    return e.view();
  }

  async cancelJoin(roomId: string): Promise<void> {
    await this.ready();
    const e = this.joining.get(roomId);
    if (!e) throw new Error("No join in progress for that room");
    await e.cancel();
  }

  /** Removes a failed join's record (its keys are already deleted). */
  async dismissJoin(roomId: string): Promise<void> {
    await this.ready();
    const e = this.joining.get(roomId);
    if (!e || e.journal.state !== "failed") throw new Error("Only a failed join can be dismissed");
    e.close();
    e.journal.remove();
    this.joining.delete(roomId);
  }

  private resumeJournal(j: EnrollmentJournal): void {
    const relay = memberRelayAddress(j.e.invite.endpoint.relay, this.env);
    const e = new MemberEnrollment({ journal: j, relay, timings: this.tuning.timings, retryMs: this.tuning.retryMs, onAdmitted: () => this.afterAdmitted(j) });
    this.joining.set(j.roomId, e);
    if (j.state === "admitted" || j.state === "registered") this.afterAdmitted(j);
    else if (j.state !== "failed") void e.start();
  }

  /** Section 8: lane registration (journal already `admitted`), then the room session. */
  private afterAdmitted(j: EnrollmentJournal): void {
    if (this.stopping) return;
    const roomId = j.roomId;
    if (j.state === "admitted" && !this.registrars.has(roomId)) {
      const r = new LaneRegistrar(
        {
          roomId,
          pluginId: PLUGIN_ID,
          hosts: () => (this.paseo?.hosts as unknown as HostsApi | undefined) ?? null,
          // Lane grants are I-10 (grants-v2.md section 3).
          connectionFor: async () => {
            throw Object.assign(new Error("lane grants are not available yet"), { code: "grants_unavailable" });
          },
          label: (laneId) => laneHostLabel({ verifiedName: null, roomId }, laneId),
          record: (laneId, registrationId) => j.registration(laneId, registrationId),
          done: () => j.registered(),
        },
        j.e.terms?.lanes ?? [],
        j.e.registrations,
      );
      this.registrars.set(roomId, r);
      r.start();
    }
    void this.connect(roomId).catch((e) => logError("v2_connect_after_join_failed", e, { roomId }));
  }

  private trustedRelays(): string[] {
    const p = nodePath.join(this.dataDir, "member", SETTINGS_FILE);
    try {
      const v = JSON.parse(fs.readFileSync(p, "utf8")) as { trustedRelays?: unknown };
      if (Array.isArray(v.trustedRelays) && v.trustedRelays.every((x) => typeof x === "string")) return v.trustedRelays as string[];
    } catch {}
    return [...DEFAULT_TRUSTED_RELAYS];
  }

  private trustRelay(relay: { host: string; port: number }): void {
    const list = [...new Set([...this.trustedRelays(), relayKey(relay)])].slice(-64);
    const dir = nodePath.join(this.dataDir, "member");
    this.protection.ensureDir(dir);
    writePrivateFile(nodePath.join(dir, SETTINGS_FILE), JSON.stringify({ trustedRelays: list }, null, 2));
    log("relay_trusted", { relay: relayKey(relay) });
  }

  // ------------------------------------------------------------------------------ member: sessions

  /** Member side: opens (or reopens) the room session with the device key from the journal. */
  async connect(roomId: string): Promise<{ status: RoomClient["status"]; lastError: string | null }> {
    const kek = await this.ready();
    this.joined.get(roomId)?.client.close();
    const keys = this.deviceFor(kek, roomId);
    const v = verifyGenesis(keys.genesis);
    const client = new RoomClient({ genesis: keys.genesis, device: keys.device, relay: keys.relay(v.genesis), timings: this.tuning.timings });
    this.joined.set(roomId, { client, memberId: keys.memberId, deviceId: keys.deviceId });
    try {
      await client.connect();
      const m = client.state.members[keys.memberId];
      if (!m?.devices.some((d) => d.deviceId === keys.deviceId)) log("v2_admission_not_in_log", { roomId, memberId: keys.memberId });
    } catch (e) {
      log("v2_connect_failed", { roomId, code: (e as { code?: string }).code ?? "error" });
    }
    return { status: client.status, lastError: client.lastError };
  }

  private deviceFor(kek: Kek, roomId: string): { genesis: RoomGenesis | Uint8Array; device: { publicKey: Uint8Array; secretKey: Uint8Array }; memberId: string; deviceId: string; relay(g: RoomGenesis): RelayAddress } {
    const j = this.joining.get(roomId)?.journal;
    if (j && (j.state === "admitted" || j.state === "registered") && j.e.genesis) {
      const { sigSeed, dhSecret } = j.deviceKeys();
      sigSeed.fill(0);
      const secret = new Uint8Array(dhSecret);
      dhSecret.fill(0);
      return {
        genesis: new Uint8Array(Buffer.from(j.e.genesis, "utf8")),
        device: { publicKey: new Uint8Array(rawPublicKey(x25519PrivateKeyFromSecret(secret))), secretKey: secret },
        memberId: j.e.memberId!,
        deviceId: j.e.deviceId!,
        relay: (g) => memberRelayAddress(g.body.endpoint.relay, this.env),
      };
    }
    // The creator's own device keys (createRoom), for a room this daemon hosts.
    const plain = kek.readSealed(memberKeysPath(this.dataDir, roomId), memberKeysPurpose(roomId));
    if (!plain) throw new Error("No device keys for that room on this daemon");
    let keys: ReturnType<typeof MemberKeysFile>;
    try {
      keys = MemberKeysFile(rjcsParse(plain));
    } finally {
      plain.fill(0);
    }
    const secret = new Uint8Array(b64uDecode(keys.dh.secret, 32));
    return {
      genesis: this.ownedRoom(roomId).host.genesis,
      device: { publicKey: new Uint8Array(rawPublicKey(x25519PrivateKeyFromSecret(secret))), secretKey: secret },
      memberId: keys.memberId,
      deviceId: keys.deviceId,
      relay: (g) => relayAddress(g.body.endpoint.relay, this.env),
    };
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
    this.stopping = true;
    for (const r of this.registrars.values()) r.stop();
    for (const e of this.joining.values()) e.close();
    for (const j of this.joined.values()) j.client.close();
    for (const o of this.owned.values()) {
      o.endpoint.stop();
      o.host.close();
    }
    this.kek?.dispose();
    log("v2_runtime_stopped", {});
  }
}

function inviteView(i: InviteView) {
  return { inviteId: i.inviteId, inviteRef: i.inviteRef, role: i.role, lanes: i.lanes, note: i.note, exp: i.exp, state: i.state, failedProofs: i.failedProofs, abandoned: i.abandoned };
}

function pendingView(p: PendingView) {
  return { pendingId: p.pendingId, note: p.note, label: p.label, state: p.state, sas: p.sas, abandonedBefore: p.abandonedBefore, contested: p.contested, expiresAt: p.expiresAt, closedReason: p.closedReason, memberId: p.memberId };
}

function joinView(v: JoinView) {
  return { roomId: v.roomId, state: v.state, roomName: v.roomName, sas: v.sas, terms: v.terms, expiresAt: v.expiresAt, failure: v.failure, connection: v.connection, lastError: v.lastError };
}

