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
// Lanes and grants (I-10): the owner creates a lane for an agent of its daemon (`lane.created`), the
// lane endpoint runs under grants v2 (server/host/grants.ts, lane-service.ts) and revocations are
// enforced before they are persisted (grants-v2 7.1; `persist_failed` is returned and shown). The
// member asks for grants over its room session only after its own fold accepted the admission entry
// (the gate in lane-registration.ts), registers each lane as a connected host, and rotates grants on
// the schedule of grants-v2 5 (server/member/grant-scheduler.ts), on `grant.revoked` pushes and on
// authentication failures of its registration. Short grants for tests: PASEO_ROOMS_DEV_SHORT_GRANTS=1
// on the host (PASEO_ROOMS_DEV_GRANT_TTL_S, default 60).
//
// Device links (I-11): a member's active device creates a `prl2.` link code, answers the host's
// `link.request` with its own nonce, compares the SAS on its own screen and signs `device.added`
// (server/member/device-link.ts). The new device joins with that code like an invite and waits in
// `held`. The admin daemon (the owner's, with the admin key) signs `device.add.approved {mode:"auto"}`
// once the hold has passed on its own clock (24 h, 72 h for a sole device), unless policy, a young
// requester or a device conflict requires an admin, who approves with `rooms.v2.device.approve`. Any
// active device of the member may veto (`device.add.vetoed`, which opens a conflict); an admin
// resolves the conflict. TEST-ONLY: `rooms.v2.test.clock.advance` moves the room host's `hts` and the
// approval clock forward, only on a test home (server/platform/test-clock.ts).
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
import type { StatementData, StatementType } from "./authority/statements";
import { autoApprovalEndsAt } from "./authority/holds";
import { edKid, versionKey, type RoomState } from "./authority/state";
import { DeviceLinker } from "./member/device-link";
import { readLinkSection, writeLinkSection } from "./member/enrollment-journal";
import { TestClock } from "./platform/test-clock";
import type { KeyObject } from "node:crypto";
import type { PendingView, InviteView } from "./host/enrollment";
import { isDevInsecureRelay, memberRelayUseTls, relayKey } from "./host/invites";
import { endpointKeyFromHost, RoomEndpoint } from "./host/room-endpoint";
import { genesisPath, RoomHost } from "./host/room-host";
import { ENV_KEYSTORE, openKeyStore, type Kek, type KeyStoreStatus } from "./keystore/keystore";
import { log, logError } from "./log";
import { HostGrants } from "./host/grants";
import { LaneService } from "./host/lane-service";
import { PersistFailedError } from "./platform/durable";
import { GrantScheduler, type RegistrationObservation, type StoredSchedule } from "./member/grant-scheduler";
import { memberRoomDir } from "./member/enrollment-journal";
import { admissionGate } from "./member/lane-registration";
import { serializeRelayConnectionUri } from "@getpaseo/protocol/daemon-endpoints";
import { RoomSessionError } from "./member/room-client";
import type { Frame } from "./transport/records";
import { MemberEnrollment, type JoinView } from "./member/enroll-client";
import { EnrollmentJournal } from "./member/enrollment-journal";
import { checkInvite, DEFAULT_TRUSTED_RELAYS, laneHostLabel, requireRelayTrust, type InvitePreview } from "./member/invite-check";
import { LaneRegistrar, type HostsApi } from "./member/lane-registration";
import { RoomClient } from "./member/room-client";
import { RoomLogFold } from "./authority/fold";
import { MlsDelivery } from "./host/mls-delivery";
import { mlsAdapter, type MlsAdapter } from "./mls/adapter";
import { MlsMember, type MlsTimings } from "./mls/member";
import { SealedMlsStore } from "./mls/sealed-store";
import { dataDir as roomsDataDir, resolvePaseoHome } from "./paths";
import { writePrivateFile } from "./platform/durable";
import { defaultProtection, ProtectionError, type FileProtection } from "./platform/file-protection";
import { b64u, b64uDecode } from "./proto/b64u";
import { isValidLabel } from "./proto/enroll";
import { isId, isRoomId } from "./proto/ids";
import { ed25519PrivateKeyFromSeed, rawPublicKey, x25519PrivateKeyFromSecret } from "./proto/keys";
import { rjcsParse } from "./proto/rjcs";
import type { RelayAddress } from "./transport/relay-server";

export const PROTOCOL_ENV = "PASEO_ROOMS_PROTOCOL";
/** DEV-ONLY: short MLS timers (repair delay, witness, joiner check) so the offline e2e runs in seconds. */
export const ENV_DEV_MLS_FAST = "PASEO_ROOMS_DEV_MLS_FAST";
const DEV_MLS_TIMINGS: Partial<MlsTimings> = { repairDelayMs: 0, repairJitterMs: 0, witnessMaxDelayMs: 1000, epochConfirmMs: 5000, retryMs: 2000 };

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


type Owned = { host: RoomHost; signer: AdminSigner | null; endpoint: RoomEndpoint; grants: HostGrants; lanes: LaneService; approver: ReturnType<typeof setInterval> | null; mls: MlsDelivery | null; mlsTick: ReturnType<typeof setInterval> | null; ownFeed: (() => void) | null };
type Joined = { client: RoomClient; memberId: string; deviceId: string };

const SCHEDULE_FILE = "grant-schedule.json";
const AUTH_FAILURE_CODES = new Set(["authentication_failed", "auth_failed", "incorrect_password", "password_required"]);

/** Thrown to RPC callers when access was cut but the change could not be saved (grants-v2 7.2). */
export class PersistFailedRpcError extends Error {
  readonly code = "persist_failed";
  constructor(what: string) {
    super(`persist_failed: ${what}. Access was cut, but the change could not be saved. It will be lost if the daemon restarts. Free disk space or fix permissions.`);
    this.name = "PersistFailedRpcError";
  }
}

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
  /** Member: grant schedulers by room, then lane. */
  private readonly schedulers = new Map<string, Map<string, GrantScheduler>>();
  /** Member: hosts.observe view of our lane registrations, by registrationId. */
  private readonly registrations = new Map<string, RegistrationObservation & { code: string | null }>();
  private readonly authRetryAt = new Map<string, number>();
  private observing: { release(): Promise<void> } | null = null;
  /** Notices sessions that ended (access_ended) and stops their lanes. */
  private endedWatch: ReturnType<typeof setInterval> | null = null;
  private paseo: PaseoApi | null = null;
  private started: Promise<void> | null = null;
  private stopping = false;
  /** Member: the confirming-device side of device links, by room. */
  private readonly linkers = new Map<string, DeviceLinker>();
  /** MLS (I-13): the adapter, and this daemon's member device of each room it is in (owned or joined). */
  private mlsLib: MlsAdapter | null = null;
  readonly mlsMembers = new Map<string, MlsMember>();
  /** Admin daemon: automatic approvals that failed, retried after this time (by request bodyHash). */
  private readonly approveRetryAt = new Map<string, number>();
  /**
   * Clock of the room hosts' `hts` and of automatic approvals. Date.now, except on an e2e test home
   * with PASEO_ROOMS_TEST_CLOCK=1 (server/platform/test-clock.ts), where tests may move it forward.
   */
  readonly clock: TestClock;

  constructor(
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly protection: FileProtection = defaultProtection(),
    /** Test only: shorter session timers and retries. */
    private readonly tuning: { timings?: ConstructorParameters<typeof RoomClient>[0]["timings"]; retryMs?: number[] } = {},
  ) {
    this.paseoHome = resolvePaseoHome(env);
    this.dataDir = roomsDataDir(this.paseoHome);
    this.clock = new TestClock(env, this.paseoHome);
  }

  /** The PaseoApi of the latest RPC context: lane registration waits for it (section 8). */
  attach(paseo: PaseoApi | null | undefined): void {
    if (!paseo) return;
    this.paseo = paseo;
    if (!this.observing && !this.stopping) this.observeHosts(paseo);
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
    try {
      this.mlsLib = await mlsAdapter();
    } catch (e) {
      logError("v2_mls_unavailable", e);
    }
    if (this.mlsLib && this.env[ENV_DEV_MLS_FAST] === "1") log("dev_mls_fast_timers", { warning: "DEV-ONLY short MLS timers", timings: DEV_MLS_TIMINGS });
    const hostDir = nodePath.join(this.dataDir, "host");
    for (const roomId of fs.existsSync(hostDir) ? fs.readdirSync(hostDir) : []) {
      if (!isRoomId(roomId) || !fs.existsSync(genesisPath(this.dataDir, roomId))) continue;
      try {
        const host = await RoomHost.open({ dataDir: this.dataDir, kek: this.kek, roomId, now: this.clock.now });
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
    this.endedWatch = setInterval(() => {
      for (const [roomId, j] of this.joined) if (j.client.status === "ended" && this.schedulers.has(roomId)) this.stopLanes(roomId);
    }, 1000);
    (this.endedWatch as { unref?: () => void }).unref?.();
    this.state = "ready";
    if (this.clock.enabled) log("test_clock_enabled", { warning: "TEST-ONLY clock override available on this test home" });
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
    const grants = new HostGrants({ dataDir: this.dataDir, kek: this.kek!, host, env: this.env });
    let lanes: LaneService | null = null;
    let endpoint: RoomEndpoint | null = null;
    let ownFeed: (() => void) | null = null;
    const mls = this.mlsLib
      ? new MlsDelivery({ dataDir: this.dataDir, kek: this.kek!, host, adapter: this.mlsLib, now: this.clock.now, push: (d, f) => endpoint?.pushToDevice(d, f) ?? false, afterAppend: () => endpoint?.afterAppend() })
      : null;
    endpoint = new RoomEndpoint({
      host,
      endpointKey: endpointKeyFromHost(this.dataDir, this.kek!, host),
      relay: relayAddress(g, this.env),
      ...(this.tuning.timings ? { timings: this.tuning.timings } : {}),
      enrollment: { dataDir: this.dataDir, kek: this.kek!, admin: signer ? (type, data) => this.adminSubmit(roomId, type, data) : null },
      grants,
      ...(mls ? { mls } : {}),
      onAppended: () => {
        lanes?.sync();
        ownFeed?.();
      },
    });
    grants.afterAppend = () => endpoint.afterAppend();
    lanes = new LaneService({ dataDir: this.dataDir, kek: this.kek!, host, grants, relay: relayAddress(g, this.env), paseoHome: this.paseoHome });
    // The admin daemon's automatic approvals of held device adds (identity-model.md 6.3).
    const approver = signer ? setInterval(() => this.autoApprove(roomId), 2000) : null;
    (approver as { unref?: () => void } | null)?.unref?.();
    const mlsTick = mls ? setInterval(() => mls.tick(), 30_000) : null;
    (mlsTick as { unref?: () => void } | null)?.unref?.();
    const owned: Owned = { host, signer, endpoint, grants, lanes, approver, mls, mlsTick, ownFeed: null };
    this.owned.set(roomId, owned);
    endpoint.start();
    lanes.start();
    try {
      ownFeed = this.startOwnMember(owned);
      owned.ownFeed = ownFeed;
    } catch (e) {
      logError("v2_mls_member_failed", e, { roomId });
    }
  }

  // ------------------------------------------------------------------------------ MLS (I-13)

  private mlsTimings(): Partial<MlsTimings> | undefined {
    return this.env[ENV_DEV_MLS_FAST] === "1" ? DEV_MLS_TIMINGS : undefined;
  }

  /**
   * The owner's own member device in the room group (the creator's device, member keys written by
   * createRoom). It reaches the delivery service in process and follows the host log through its own
   * fold, so the owner holds no relay session to its own room. Returns the feed to call after appends.
   */
  private startOwnMember(o: Owned): (() => void) | null {
    const roomId = o.host.roomId;
    if (!this.mlsLib || !o.mls || !fs.existsSync(memberKeysPath(this.dataDir, roomId))) return null;
    const kek = this.kek!;
    const plain = kek.readSealed(memberKeysPath(this.dataDir, roomId), memberKeysPurpose(roomId));
    if (!plain) return null;
    let memberId: string;
    let deviceId: string;
    try {
      const k = MemberKeysFile(rjcsParse(plain));
      memberId = k.memberId;
      deviceId = k.deviceId;
    } finally {
      plain.fill(0);
    }
    const sigKey = this.sigKeyFor(kek, roomId);
    const endpoint = o.endpoint;
    const host = o.host;
    const dhOf = () => host.state.members[memberId]?.devices.find((d) => d.deviceId === deviceId)?.dh ?? "";
    const member = new MlsMember({
      adapter: this.mlsLib,
      roomId,
      genesisHash: host.genesisHash,
      memberId,
      deviceId,
      device: { sigPub: b64u(rawPublicKey(sigKey)), sigKey },
      store: new SealedMlsStore({ dataDir: this.dataDir, kek, roomId, deviceId }),
      link: () => ({ request: (frame) => endpoint.localRequest(dhOf(), frame) }),
      creator: true,
      now: this.clock.now,
      timings: this.mlsTimings(),
      blocked: () => host.isStopped,
      onAlert: (a) => log("mls_member_alert", { roomId, type: a.type, seq: a.seq }),
    });
    this.mlsMembers.set(roomId, member);
    endpoint.onLocalPush(deviceId, (f) => void member.onPush(f));
    const fold = RoomLogFold.fromGenesis(host.genesis);
    const feed = () => {
      for (const r of host.entries(fold.head.seq + 1)) {
        const before = fold.state;
        fold.append(r.signed, r.body);
        member.ingest(r.signed, before, fold.state);
      }
    };
    feed();
    member.checkRollback(o.mls.lastAck(deviceId));
    member.start();
    return feed;
  }

  /** A joined room's member device: its MLS member persists across sessions; the link is the current session. */
  private memberMlsFor(kek: Kek, roomId: string, genesisHash: string, memberId: string, deviceId: string): MlsMember | null {
    const have = this.mlsMembers.get(roomId);
    if (have || !this.mlsLib) return have ?? null;
    const sigKey = this.sigKeyFor(kek, roomId);
    const member = new MlsMember({
      adapter: this.mlsLib,
      roomId,
      genesisHash,
      memberId,
      deviceId,
      device: { sigPub: b64u(rawPublicKey(sigKey)), sigKey },
      store: new SealedMlsStore({ dataDir: this.dataDir, kek, roomId, deviceId }),
      link: () => {
        const c = this.joined.get(roomId)?.client;
        if (!c || c.status !== "open") return null;
        return {
          request: async (frame, timeoutMs) => {
            try {
              return (await c.request(frame as Omit<Frame, "id">, timeoutMs)) as Record<string, unknown>;
            } catch (e) {
              throw e instanceof RoomSessionError ? Object.assign(new Error(e.code), { code: e.code, fields: e.fields ?? {} }) : e;
            }
          },
        };
      },
      timings: this.mlsTimings(),
      onAlert: (a) => log("mls_member_alert", { roomId, type: a.type, seq: a.seq }),
    });
    this.mlsMembers.set(roomId, member);
    member.start();
    return member;
  }

  /** Sends a chat message in the room group (development RPC; the chat UI is M2). */
  async mlsSend(roomId: string, text: string): Promise<{ seq: number }> {
    await this.ready();
    const m = this.mlsMembers.get(roomId);
    if (!m) throw new Error("No MLS group member for that room on this daemon");
    return m.sendText(text);
  }

  async mlsMessages(roomId: string): Promise<{ messages: { seq: number; epoch: number; from: { memberId: string; deviceId: string } | null; text: string }[] }> {
    await this.ready();
    const m = this.mlsMembers.get(roomId);
    if (!m) throw new Error("No MLS group member for that room on this daemon");
    await m.idle();
    return { messages: m.messages.map((x) => ({ seq: x.seq, epoch: x.epoch, from: x.from, text: x.text })) };
  }

  private mlsView() {
    return [...this.mlsMembers.entries()].map(([roomId, m]) => {
      const v = m.view();
      return { roomId, inGroup: v.inGroup, epoch: v.epoch, cursor: v.cursor, leaves: v.leaves.length, join: v.join?.status ?? null, stalled: v.stalled !== null, disabled: v.disabled, canSend: v.canSend, messages: m.messages.length, alerts: m.alerts.slice(-16).map((a) => ({ type: a.type, seq: a.seq })) };
    });
  }

  /**
   * `device.add.approved {mode:"auto"}` for every pending add whose hold has passed on this daemon's
   * clock and that no rule keeps for an admin (policy, sole-device policy, conflict, young requester).
   * The fold checks the same rules against `hts`; this is the real enforcement (room-log-v2 5).
   */
  autoApprove(roomId: string): void {
    const o = this.owned.get(roomId);
    if (!o?.signer || o.host.isStopped || this.stopping) return;
    const st = o.host.state;
    const now = this.clock.now();
    for (const [ref, p] of Object.entries(st.pending)) {
      if (p.kind !== "add" || p.status !== "pending") continue;
      const at = autoApprovalEndsAt(st, p);
      if (at === null || now < at || (this.approveRetryAt.get(ref) ?? 0) > Date.now()) continue;
      try {
        const r = this.adminSubmit(roomId, "device.add.approved", { memberId: p.memberId, deviceId: p.deviceId, ref, mode: "auto" });
        log("device_add_auto_approved", { roomId, memberId: p.memberId, deviceId: p.deviceId, seq: r.receipt.entry.seq, sole: p.sole });
      } catch (e) {
        this.approveRetryAt.set(ref, Date.now() + 60_000);
        log("device_add_auto_approve_failed", { roomId, deviceId: p.deviceId, error: String((e as Error)?.message ?? e).slice(0, 160) });
      }
    }
  }

  status() {
    const ks = this.keystore;
    return {
      protocol: "v2" as const,
      state: this.state,
      error: this.error,
      ...(this.clock.enabled ? { testClockOffsetMs: this.clock.offset } : {}),
      keystore: ks ? { state: ks.state, backend: ks.backend, fallback: ks.state === "ready" ? ks.fallback : false } : null,
      owned: [...this.owned.values()].map(({ host, endpoint, grants, lanes }) => ({
        roomId: host.roomId,
        serverId: endpoint.serverId,
        head: host.head,
        endpoint: endpoint.status,
        sessions: endpoint.sessions().map((s) => ({ memberId: s.memberId, deviceId: s.deviceId })),
        members: Object.keys(host.state.members).length,
        invites: (endpoint.enrollment?.invites() ?? []).map(inviteView),
        joinRequests: (endpoint.enrollment?.pendings() ?? []).map(pendingView),
        lanes: lanes.lanes(),
        grants: grants.view().current,
        grantTtlS: grants.ttlS(),
        persistError: grants.persistError ?? (host.isStopped ? "room_stopped" : null),
        compromisedDevices: grants.compromisedDevices(),
        deviceRequests: deviceRequestsView(host.state),
        conflicts: Object.keys(host.state.conflicts).sort(),
      })),
      mls: this.mlsView(),
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
        registration: this.registrars.get(roomId)?.status ?? null,
        links: this.linkers.get(roomId)?.view() ?? [],
        // The member's own pending device requests: the "Was this you?" prompt with Not me (6.3).
        deviceRequests: j.client.status === "open" || j.client.head.seq >= 0 ? deviceRequestsView(j.client.state, j.memberId) : [],
        conflict: j.client.head.seq >= 0 ? j.client.state.conflicts[j.memberId] !== undefined : false,
        lanes: [...(this.schedulers.get(roomId)?.entries() ?? [])].map(([laneId, sc]) => {
          const regId = this.joining.get(roomId)?.journal.e.registrations[laneId] ?? null;
          const reg = regId ? this.registrations.get(regId) : undefined;
          return { laneId, registrationId: regId, hostStatus: reg?.status ?? null, ...sc.view() };
        }),
      })),
    };
  }

  async createRoom(): Promise<{ roomId: string; serverId: string }> {
    const kek = await this.ready();
    // Development runtime: the recovery key is skipped so no recovery code is ever produced here.
    const room = await createRoom({ dataDir: this.dataDir, kek, relay: genesisRelay(this.env), recovery: "skip", now: this.clock.now });
    this.serve(room.host, room.signer);
    return { roomId: room.roomId, serverId: room.genesis.body.endpoint.serverId };
  }

  // ------------------------------------------------------------------------------ owner: enrollment

  /** Creates an invite. The returned code is a bearer secret until used or expired (2.2). */
  async createInvite(i: { roomId: string; role?: string; lanes?: string[]; expS?: number; note?: string; roomName?: string }): Promise<{ code: string; inviteId: string; inviteRef: string; exp: number }> {
    await this.ready();
    return this.enrollmentOf(i.roomId).createInvite({ role: i.role, lanes: i.lanes ? [...new Set(i.lanes)].sort() : undefined, expS: i.expS, note: i.note, roomName: i.roomName });
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

  /**
   * Removal (grants-v2 7.1): sessions and lane links are cut in the decide step, before the log
   * append; a failed save of the grants file or of the log answers `persist_failed`.
   */
  async removeMember(roomId: string, memberId: string): Promise<{ seq: number }> {
    await this.ready();
    if (!isId("member", memberId)) throw new Error("bad memberId");
    return this.reducing(roomId, () => ({ seq: this.adminSubmit(roomId, "member.removed", { memberId, reason: "admin" }).receipt.entry.seq }));
  }

  /** Lowers or changes a member's role (S-9: grants at the old role stop working at once). */
  async changeRole(roomId: string, memberId: string, role: string): Promise<{ seq: number }> {
    await this.ready();
    if (!isId("member", memberId)) throw new Error("bad memberId");
    const o = this.ownedRoom(roomId);
    const ver = o.host.state.auth.versions[`role:${memberId}`] ?? -1;
    return this.reducing(roomId, () => ({ seq: this.adminSubmit(roomId, "member.role.changed", { memberId, role, ver }).receipt.entry.seq }));
  }

  private reducing<T>(roomId: string, f: () => T): T {
    const o = this.ownedRoom(roomId);
    let out: T;
    try {
      out = f();
    } catch (e) {
      if (e instanceof PersistFailedError || o.host.isStopped) throw new PersistFailedRpcError("the room log could not be written");
      throw e;
    }
    if (o.grants.persistError) throw new PersistFailedRpcError("the grant list could not be written");
    return out;
  }

  // ------------------------------------------------------------------------------ owner: device holds

  /** The folded state of a room this daemon hosts (owner view and tests). */
  ownedHostState(roomId: string): Readonly<RoomState> {
    return this.ownedRoom(roomId).host.state;
  }

  /** An admin's interactive approval of a pending device add (no hold; identity-model.md 6.3). */
  async approveDevice(roomId: string, ref: string): Promise<{ seq: number }> {
    await this.ready();
    const p = this.ownedRoom(roomId).host.state.pending[ref];
    if (!p || p.kind !== "add") throw new Error("Unknown device request");
    // Checked before signing: a refused admin statement stays outstanding until a fence (I-7).
    if (p.status !== "pending") throw new Error(`The device request is ${p.status}`);
    return { seq: this.adminSubmit(roomId, "device.add.approved", { memberId: p.memberId, deviceId: p.deviceId, ref, mode: "admin" }).receipt.entry.seq };
  }

  /** Clears a member's device conflict (after a veto); automatic approvals resume for that member. */
  async resolveConflict(roomId: string, memberId: string): Promise<{ seq: number }> {
    await this.ready();
    if (!isId("member", memberId)) throw new Error("bad memberId");
    const st = this.ownedRoom(roomId).host.state;
    if (st.conflicts[memberId] === undefined) throw new Error("That member has no open device conflict");
    const ver = st.auth.versions[versionKey.conflict(memberId)] ?? -1;
    return { seq: this.adminSubmit(roomId, "device.conflict.resolved", { memberId, ver }).receipt.entry.seq };
  }

  /** TEST-ONLY (test homes with PASEO_ROOMS_TEST_CLOCK=1): moves the hts and approval clock forward. */
  advanceTestClock(ms: number): { offsetMs: number } {
    const offsetMs = this.clock.advance(ms);
    log("test_clock_advanced", { byMs: ms, offsetMs });
    for (const roomId of this.owned.keys()) this.autoApprove(roomId);
    return { offsetMs };
  }

  // ------------------------------------------------------------------------------ member: device links

  /** "Link another device": the `prl2.` code, shown once (a bearer secret for 10 minutes). */
  async createLink(roomId: string, roomName?: string): Promise<{ code: string; linkId: string; exp: number }> {
    await this.ready();
    return this.linkerOf(roomId).create({ roomName });
  }

  /** On the linking device: "Codes match" (true) or "Codes do not match" for a link request. */
  async confirmLink(roomId: string, pendingId: string, match: boolean): Promise<void> {
    await this.ready();
    if (!isId("pending", pendingId)) throw new Error("bad pendingId");
    await this.linkerOf(roomId).confirm(pendingId, match);
  }

  /** "Not me": vetoes a pending add of this member's (any active device may; opens a conflict). */
  async vetoDevice(roomId: string, ref: string): Promise<{ seq: number }> {
    await this.ready();
    const j = this.joined.get(roomId);
    const p = j?.client.state.pending[ref];
    if (!j || !p || p.memberId !== j.memberId || p.status !== "pending") throw new Error("No pending device request of yours with that reference");
    const type = p.kind === "add" ? "device.add.vetoed" : "device.rekey.vetoed";
    return this.linkerOf(roomId).submitOwn(type, { memberId: j.memberId, ref } as StatementData<typeof type>);
  }

  private linkerOf(roomId: string): DeviceLinker {
    const l = this.linkers.get(roomId);
    if (!l) throw new Error("Not connected to that room as a member device");
    return l;
  }

  private linkerFor(kek: Kek, roomId: string, genesisHash: string, memberId: string, deviceId: string, client: RoomClient): DeviceLinker {
    const existing = this.linkers.get(roomId);
    if (existing) return existing;
    const sigKid = edKid(b64u(rawPublicKey(this.sigKeyFor(kek, roomId))));
    const linker = new DeviceLinker({
      roomId,
      genesisHash,
      memberId,
      deviceId,
      sigKid,
      sigKey: () => this.sigKeyFor(kek, roomId),
      endpoint: () => client.state.auth.endpoint as never,
      session: () => {
        const c = this.joined.get(roomId)?.client;
        return c && c.status === "open" ? c : null;
      },
      store: { read: () => readLinkSection({ dataDir: this.dataDir, kek, roomId }), write: (v) => writeLinkSection({ dataDir: this.dataDir, kek, roomId, genesisHash }, v) },
    });
    this.linkers.set(roomId, linker);
    return linker;
  }

  /** This daemon's signing key for a room (its sealed journal, or the creator's key file). */
  private sigKeyFor(kek: Kek, roomId: string): KeyObject {
    const j = this.joining.get(roomId)?.journal;
    if (j && (j.state === "admitted" || j.state === "registered")) {
      const { sigSeed, dhSecret } = j.deviceKeys();
      dhSecret.fill(0);
      try {
        return ed25519PrivateKeyFromSeed(sigSeed);
      } finally {
        sigSeed.fill(0);
      }
    }
    const plain = kek.readSealed(memberKeysPath(this.dataDir, roomId), memberKeysPurpose(roomId));
    if (!plain) throw new Error("No device keys for that room on this daemon");
    try {
      const seed = b64uDecode(MemberKeysFile(rjcsParse(plain)).sig.seed, 32);
      try {
        return ed25519PrivateKeyFromSeed(seed);
      } finally {
        seed.fill(0);
      }
    } finally {
      plain.fill(0);
    }
  }

  // ------------------------------------------------------------------------------ owner: lanes

  /** Creates a lane for an agent of this daemon (share; no new agent). The caller confirms `lane.created`. */
  async createLane(i: { roomId: string; agentId: string; label?: string }): Promise<{ laneId: string; serverId: string }> {
    const kek = await this.ready();
    const o = this.ownedRoom(i.roomId);
    if (!o.signer) throw new Error("No admin key for this room on this daemon");
    if (!this.paseo) throw new Error("The Paseo API is not available yet");
    const ref = await this.paseo.agents.ref(i.agentId).refresh();
    const agent = ref?.agent;
    if (!agent || agent.id !== i.agentId) throw new Error("Agent not found on this daemon");
    if (agent.archivedAt) throw new Error("Agent is archived");
    if (!agent.workspaceId) throw new Error("The agent has no workspace");
    const owner = this.ownMemberId(kek, i.roomId);
    return o.lanes.createLane({ agentId: agent.id, workspaceId: agent.workspaceId, label: i.label ?? "Live", owner, submit: (data) => void this.adminSubmit(i.roomId, "lane.created", data) });
  }

  /** Owner-only full error text of a lane (grants-v2 13.1); never crosses a lane endpoint. */
  async laneErrors(roomId: string, laneId: string) {
    await this.ready();
    return this.ownedRoom(roomId).lanes.errors(laneId);
  }

  private ownMemberId(kek: Kek, roomId: string): string {
    const plain = kek.readSealed(memberKeysPath(this.dataDir, roomId), memberKeysPurpose(roomId));
    if (!plain) throw new Error("No device keys for that room on this daemon");
    try {
      return MemberKeysFile(rjcsParse(plain)).memberId;
    } finally {
      plain.fill(0);
    }
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
    const lanes = j.e.terms?.lanes ?? [];
    if (!this.registrars.has(roomId)) {
      // Gate (I-10): nothing below asks for a grant until our own fold accepted the admission entry.
      const gate = () => {
        const c = this.joined.get(roomId)?.client;
        return admissionGate(c && c.status === "open" ? c : c?.sendingStopped ? c : null, j.e.admission, () => !!c?.state.members[j.e.memberId!]?.devices.some((d) => d.deviceId === j.e.deviceId));
      };
      const r = new LaneRegistrar(
        {
          roomId,
          pluginId: PLUGIN_ID,
          hosts: () => (this.paseo?.hosts as unknown as HostsApi | undefined) ?? null,
          gate,
          connectionFor: async (laneId) => {
            const g = await this.issueConnection(roomId, laneId, gate);
            this.schedulerFor(roomId, laneId).armNew(g);
            return g.connection;
          },
          label: (laneId) => laneHostLabel({ verifiedName: null, roomId }, laneId),
          record: (laneId, registrationId) => j.registration(laneId, registrationId),
          done: () => j.registered(),
          ...(this.tuning.retryMs ? { setTimer: (f: () => void, ms: number) => setTimeout(f, Math.min(ms, this.tuning.retryMs![0] ?? ms)) } : {}),
        },
        lanes,
        j.e.registrations,
      );
      this.registrars.set(roomId, r);
      // Registered lanes from before a restart: re-arm their schedules (C-12).
      const stored = this.readSchedules(roomId);
      for (const laneId of lanes) {
        const sc = this.schedulerFor(roomId, laneId);
        const st = stored[laneId];
        if (st && j.e.registrations[laneId]) sc.restore(st);
      }
    }
    void this.connect(roomId)
      .then(() => this.registrars.get(roomId)?.run())
      .catch((e) => logError("v2_connect_after_join_failed", e, { roomId }));
  }

  /** `grant.issue` over the room session, then the connection URI for Paseo's hosts API. Never logged. */
  private async issueConnection(roomId: string, laneId: string, gate?: () => string): Promise<{ connection: string; gid: string; iat: number; exp: number }> {
    if (gate && gate() !== "accepted") throw Object.assign(new Error("admission not yet in the fold"), { code: "admission_unverified" });
    const c = this.joined.get(roomId)?.client;
    if (!c || c.status !== "open") throw Object.assign(new Error("no room session"), { code: "no_session" });
    const offer = c.state.auth.lanes[laneId]?.offer;
    if (!offer) throw Object.assign(new Error("lane not in the verified log"), { code: "unknown_lane" });
    let reply: Frame;
    try {
      reply = await c.request({ t: "grant.issue", laneId });
    } catch (e) {
      throw Object.assign(new Error("grant.issue failed"), { code: e instanceof RoomSessionError ? e.code : "error" });
    }
    const token = typeof reply.grant === "string" ? reply.grant : "";
    const claims = reply.claims as { gid?: unknown; iat?: unknown; exp?: unknown; laneId?: unknown } | undefined;
    if (!token.startsWith("prg2.") || !claims || claims.laneId !== laneId || typeof claims.gid !== "string" || typeof claims.iat !== "number" || typeof claims.exp !== "number") {
      throw Object.assign(new Error("bad grant.issue reply"), { code: "bad_reply" });
    }
    const relay = memberRelayAddress(offer.relay, this.env);
    const connection = serializeRelayConnectionUri({
      offer: { v: 2, serverId: offer.serverId, daemonPublicKeyB64: b64uDecode(offer.dh.pub, 32).toString("base64"), relay: { endpoint: relay.endpoint, useTls: relay.useTls }, minimumSecurityMode: "protected" },
      password: token,
    } as Parameters<typeof serializeRelayConnectionUri>[0]);
    return { connection, gid: claims.gid, iat: claims.iat, exp: claims.exp };
  }

  private schedulerFor(roomId: string, laneId: string): GrantScheduler {
    let byLane = this.schedulers.get(roomId);
    if (!byLane) this.schedulers.set(roomId, (byLane = new Map()));
    let sc = byLane.get(laneId);
    if (sc) return sc;
    sc = new GrantScheduler({
      roomId,
      laneId,
      mono: () => performance.now(),
      wall: () => Date.now(),
      rotate: async () => this.rotateGrant(roomId, laneId),
      status: async () => {
        const c = this.joined.get(roomId)?.client;
        if (!c || c.status !== "open") throw Object.assign(new Error("no room session"), { code: "no_session" });
        const r = await c.request({ t: "grant.status", laneId });
        return { gid: (r.gid as string | null) ?? null, links: Array.isArray(r.links) ? (r.links as { since: number; routes: number }[]).slice(0, 4) : [], serverTime: Number(r.serverTime) };
      },
      registration: () => {
        const id = this.joining.get(roomId)?.journal.e.registrations[laneId];
        return (id && this.registrations.get(id)) || { status: "unknown", onlineSince: null, offlineSince: null };
      },
      report: async (gid) => {
        const c = this.joined.get(roomId)?.client;
        if (c?.status === "open") await c.request({ t: "grant.report", laneId, gid, reason: "unaccounted_link" });
      },
      save: (st) => this.saveSchedule(roomId, laneId, st),
    });
    byLane.set(laneId, sc);
    return sc;
  }

  /** A new grant registered with Paseo through hosts.update (the registration exists already). */
  private async rotateGrant(roomId: string, laneId: string): Promise<{ gid: string; iat: number; exp: number }> {
    const j = this.joining.get(roomId)?.journal;
    const registrationId = j?.e.registrations[laneId];
    const hosts = this.paseo?.hosts as unknown as HostsApi | undefined;
    if (!registrationId) throw Object.assign(new Error("lane not registered yet"), { code: "not_registered" });
    if (!hosts) throw Object.assign(new Error("no Paseo API yet"), { code: "no_api" });
    const g = await this.issueConnection(roomId, laneId);
    const metadata = { "rooms.roomId": roomId, "rooms.laneId": laneId, "rooms.role": "lane" };
    await hosts.update(registrationId, { connection: g.connection, label: laneHostLabel({ verifiedName: null, roomId }, laneId), metadata, enabled: true });
    return { gid: g.gid, iat: g.iat, exp: g.exp };
  }

  private schedulePath(roomId: string): string {
    return nodePath.join(memberRoomDir(this.dataDir, roomId), SCHEDULE_FILE);
  }

  private readSchedules(roomId: string): Record<string, StoredSchedule> {
    try {
      const v = JSON.parse(fs.readFileSync(this.schedulePath(roomId), "utf8")) as Record<string, StoredSchedule>;
      return v && typeof v === "object" ? v : {};
    } catch {
      return {};
    }
  }

  /** Grant timing only (gid, lifetime, receive time): never the grant itself, which lives in Paseo's hosts.json. */
  private saveSchedule(roomId: string, laneId: string, st: StoredSchedule): void {
    try {
      writePrivateFile(this.schedulePath(roomId), JSON.stringify({ ...this.readSchedules(roomId), [laneId]: st }));
    } catch (e) {
      log("grant_schedule_save_failed", { roomId, code: (e as { code?: string }).code ?? "error" });
    }
  }

  /** hosts.observe: our registrations' status for the idle rule, and auth failures for rotation. */
  private observeHosts(paseo: PaseoApi): void {
    try {
      const sub = (paseo.hosts as unknown as { observe(): { release(): Promise<void>; subscribe(h: unknown): void; ready: Promise<unknown> } }).observe();
      this.observing = sub;
      const apply = (dir: unknown) => {
        const hosts = (dir as { hosts?: unknown[] } | undefined)?.hosts;
        if (Array.isArray(hosts)) this.onHosts(hosts as { registrationId: string; status?: string; error?: { code?: string } | null }[]);
      };
      sub.subscribe({
        snapshot: (snap: any) => apply(snap?.hosts ? snap : snap?.directory ?? snap?.value),
        update: (m: any) => m?.type === "hosts.changed" && apply(m.payload?.directory),
        error: (e: unknown) => logError("hosts_observe_error", e),
      });
      void sub.ready.then((snap: any) => apply(snap?.hosts ? snap : snap?.directory ?? snap?.value)).catch((e) => logError("hosts_observe_failed", e));
    } catch (e) {
      logError("hosts_observe_unavailable", e);
    }
  }

  private onHosts(hosts: { registrationId: string; status?: string; error?: { code?: string } | null }[]): void {
    const now = Date.now();
    for (const h of hosts) {
      const lane = this.laneOfRegistration(h.registrationId);
      if (!lane) continue;
      const status = (["online", "offline", "connecting", "error"].includes(h.status ?? "") ? h.status : "unknown") as RegistrationObservation["status"];
      const prev = this.registrations.get(h.registrationId);
      const next = {
        status,
        onlineSince: status === "online" ? (prev ? (prev.status === "online" ? prev.onlineSince : now) : null) : null,
        offlineSince: status === "online" ? null : prev && prev.status !== "online" ? prev.offlineSince : prev ? now : null,
        code: h.error?.code ?? null,
      };
      this.registrations.set(h.registrationId, next);
      if (prev?.status !== status) log("lane_host_status", { roomId: lane.roomId, laneId: lane.laneId, status, error: next.code });
      if (status === "error" && next.code && AUTH_FAILURE_CODES.has(next.code) && this.joined.get(lane.roomId)?.client.status === "open") {
        const key = `${lane.roomId} ${lane.laneId}`;
        if ((this.authRetryAt.get(key) ?? 0) > now) continue;
        this.authRetryAt.set(key, now + 15_000);
        void this.schedulers.get(lane.roomId)?.get(lane.laneId)?.rotate("auth_failed");
      }
    }
  }

  private laneOfRegistration(registrationId: string): { roomId: string; laneId: string } | null {
    for (const [roomId, e] of this.joining) for (const [laneId, id] of Object.entries(e.journal.e.registrations)) if (id === registrationId) return { roomId, laneId };
    return null;
  }

  /** Session pushes: `grant.revoked` (theft, role change) asks for a new grant through the session. */
  private onSessionPush(roomId: string, frame: Frame): void {
    if (this.linkers.get(roomId)?.onPush(frame)) return;
    // MLS pushes of an owned room reach the owner's device in process (endpoint.onLocalPush).
    if (frame.t === "pending_remove" || frame.t === "kp.low") {
      if (!this.owned.has(roomId)) this.mlsMembers.get(roomId)?.onPush(frame as Record<string, unknown>);
      return;
    }
    if (frame.t !== "grant.revoked" || typeof frame.laneId !== "string") return;
    log("grant_revoked_push", { roomId, laneId: frame.laneId, reason: String(frame.reason ?? "").slice(0, 32) });
    void this.schedulers.get(roomId)?.get(frame.laneId)?.rotate(`revoked_${String(frame.reason ?? "unknown").slice(0, 24)}`);
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
    const mls = this.memberMlsFor(kek, roomId, v.genesisHash, keys.memberId, keys.deviceId);
    const client = new RoomClient({
      genesis: keys.genesis,
      device: keys.device,
      relay: keys.relay(v.genesis),
      timings: this.tuning.timings,
      onPush: (f) => this.onSessionPush(roomId, f),
      ...(mls && !this.owned.has(roomId) ? { onIngest: (s, b, a) => mls.ingest(s, b, a) } : {}),
    });
    this.joined.set(roomId, { client, memberId: keys.memberId, deviceId: keys.deviceId });
    this.linkerFor(kek, roomId, v.genesisHash, keys.memberId, keys.deviceId, client);
    try {
      const hello = await client.connect();
      if (mls && !this.owned.has(roomId)) {
        const la = hello.lastAck as { seq?: unknown; epoch?: unknown } | null;
        mls.checkRollback(la && Number.isSafeInteger(la.seq) && Number.isSafeInteger(la.epoch) ? { seq: la.seq as number, epoch: la.epoch as number } : null);
        void mls.maintain().catch(() => undefined);
      }
      const m = client.state.members[keys.memberId];
      if (!m?.devices.some((d) => d.deviceId === keys.deviceId)) log("v2_admission_not_in_log", { roomId, memberId: keys.memberId });
    } catch (e) {
      log("v2_connect_failed", { roomId, code: (e as { code?: string }).code ?? "error" });
    }
    if (client.status === "ended" && this.schedulers.has(roomId)) this.stopLanes(roomId);
    return { status: client.status, lastError: client.lastError };
  }

  /** Access ended: stop rotating and remove our lane registrations (their grants no longer work). */
  private stopLanes(roomId: string): void {
    for (const sc of this.schedulers.get(roomId)?.values() ?? []) sc.stop();
    this.schedulers.delete(roomId);
    this.registrars.get(roomId)?.stop();
    const regs = this.joining.get(roomId)?.journal.e.registrations ?? {};
    const hosts = this.paseo?.hosts as unknown as { remove?(id: string): Promise<unknown> } | undefined;
    for (const id of Object.values(regs)) void hosts?.remove?.(id).catch((e) => logError("lane_host_remove_failed", e, { roomId }));
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
    if (this.endedWatch) clearInterval(this.endedWatch);
    for (const r of this.registrars.values()) r.stop();
    for (const m of this.schedulers.values()) for (const sc of m.values()) sc.stop();
    void this.observing?.release().catch(() => undefined);
    for (const e of this.joining.values()) e.close();
    for (const j of this.joined.values()) j.client.close();
    for (const m of this.mlsMembers.values()) m.stop();
    for (const o of this.owned.values()) {
      if (o.approver) clearInterval(o.approver);
      if (o.mlsTick) clearInterval(o.mlsTick);
      await o.lanes.stop();
      o.grants.stop();
      o.endpoint.stop();
      o.host.close();
    }
    this.kek?.dispose();
    log("v2_runtime_stopped", {});
  }
}

/** Pending device requests in a fold state (optionally one member's), newest first, ids and times only. */
function deviceRequestsView(st: Readonly<RoomState>, memberId?: string) {
  return Object.entries(st.pending)
    .filter(([, p]) => !memberId || p.memberId === memberId)
    .sort(([, a], [, b]) => b.seq - a.seq)
    .slice(0, 64)
    .map(([ref, p]) => ({ ref, kind: p.kind, memberId: p.memberId, deviceId: p.deviceId, requester: p.requester, seq: p.seq, hts: p.hts, sole: p.sole, young: p.young, status: p.status, effectiveAfter: autoApprovalEndsAt(st, p) }));
}

function inviteView(i: InviteView) {
  return { inviteId: i.inviteId, inviteRef: i.inviteRef, role: i.role, lanes: i.lanes, note: i.note, exp: i.exp, state: i.state, failedProofs: i.failedProofs, abandoned: i.abandoned };
}

function pendingView(p: PendingView) {
  return { pendingId: p.pendingId, kind: p.kind, note: p.note, label: p.label, state: p.state, sas: p.sas, abandonedBefore: p.abandonedBefore, contested: p.contested, expiresAt: p.expiresAt, closedReason: p.closedReason, memberId: p.memberId, deviceId: p.deviceId };
}

function joinView(v: JoinView) {
  return { roomId: v.roomId, state: v.state, roomName: v.roomName, sas: v.sas, terms: v.terms, expiresAt: v.expiresAt, failure: v.failure, connection: v.connection, lastError: v.lastError };
}

