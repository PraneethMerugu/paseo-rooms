// Rooms runtime (identity v2; implementation plan I-8 to I-15). Since the cut-over (I-15) it is the
// only runtime: the M1 code and the PASEO_ROOMS_PROTOCOL development switch are gone.
//
// Start (asynchronous): the plugin-data/rooms tree is created or checked (owner-only, no symlinks),
// M1 data found there is archived (server/migration/v1.ts, migration.md section 2; the member's v1
// host registrations are removed once a PaseoApi is attached), the KeyStore is opened (I-3), then every owned room is reopened from its log (RoomHost.open re-folds)
// and its room endpoint, which serves enrollment, registered on the relay. Then every member journal
// (I-9) resumes from its state: a pending join resumes with `enroll.resume`, an admitted one runs lane
// registration and opens its room session (C-12: armed at start, not on first app contact).
//
// Enrollment (I-9): the owner creates invites and admits join requests after the SAS comparison; the
// member previews and joins with a `prc2.` code, compares the SAS and confirms. Interactive admin
// actions are confirmed in the Rooms UI (I-14, identity-model 5.3): `prepareAdmin` describes the
// action and issues a one-time token bound to it and to the current values it depends on, and
// `takeAdmin` consumes that token before the action runs (`stale_base` when the values changed;
// server/admin/confirmations.ts). Policy-automatic approvals are signed without a token.
//
// Lanes and grants (I-10): the owner creates a lane for an agent of its daemon (`lane.created`), the
// lane endpoint runs under grants v2 (server/host/grants.ts, lane-service.ts) and revocations are
// enforced before they are persisted (grants-v2 7.1; `persist_failed` is returned and shown). The
// member asks for grants over its room session only after its own fold accepted the admission entry
// (the gate in lane-registration.ts), registers each lane as a connected host, and rotates grants on
// the schedule of grants-v2 5 (server/member/grant-scheduler.ts), on `grant.revoked` pushes and on
// authentication failures of its registration. Short grants for tests: PASEO_ROOMS_DEV_SHORT_GRANTS=1
// on the host (PASEO_ROOMS_DEV_GRANT_TTL_S, default 60). Every PASEO_ROOMS_DEV_* switch is honoured only
// on a marked e2e test home (server/platform/test-clock.ts testHomeRefusal) and dropped elsewhere.
//
// Lane agents (C-13): when a lane's agent is archived (hook agent.archived) or found archived or
// missing at start, its lane endpoint stops at once and this daemon's admin key signs `lane.closed`.
// An admin also closes a lane by hand (R3.2, `rooms.v2.lane.close`).
//
// Leaving and data hygiene (R3.1, R3.7, R2.6): a member leaves a room with `member.left` from its only
// active device, or with `device.removed {reason: "self"}` from one of several (room-log-v2 4.3); the
// lane hosts are removed through Paseo's hosts API and the device's keys and data for the room are
// deleted. Lane hosts of a closed lane, of a lane the member no longer has, and of a room whose access
// ended are removed the same way; what cannot be removed now is kept in member/stale-hosts.json,
// retried, and shown. "Leave all rooms and delete keys" leaves every room, removes every lane host of
// this plugin, deletes the KEK through the KeyStore and the plugin-data/rooms folder, and leaves the
// runtime stopped (`data_deleted`).
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
// Rotation and recovery (I-12, keys-rotation-recovery.md 4 and 6): a member device requests its own
// rekey (`device.rekeyed`, next keys sealed in its journal first, `rekey` KeyPackages published); the
// admin daemon approves it after the hold on its own clock (or an admin interactively) by the admin
// route: `device.rekey.approved` and the Remove plus Add commit in one `commit.submit`, sequenced
// adjacently or not at all; with no admin daemon online nothing is signed and the old keys keep
// working. The device then reconnects with its new DH key and rejoins the room group by Welcome. The
// owner rotates the admin key, the host key (staged in keys.sealed first; `oldValidTo` = now + 24 h),
// the room endpoint (staged in `endpointNext`; the old one answers `moved` for 30 days) and lane offers
// (also after a removal flagged as compromise, or every removal under `rotateLaneOnRemove = "always"`);
// it proposes and confirms closures (the confirming daemon refuses before `closeDelay` on its own
// clock); and runs the recovery-key procedures (a recovery code typed for one action, never stored).
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
import type { PluginHandlerContext } from "@getpaseo/plugin/server";
import { randomBytes } from "node:crypto";
import { createRoom, memberKeysPath, memberKeysPurpose, recoveryOfferOf, type RecoveryKeyOffer } from "./admin/genesis";
import { ConfirmationBook, describeAdminAction, type DescribeContext, type Described } from "./admin/confirmations";
import type { AdminActionV2 } from "../shared/rpc-v2";
import { AdminSigner, adminKeyPath, writeAdminKey } from "./admin/signer";
import { closeConfirmationBlocker, newRecoveryKey, RecoveryKey, recoverFromStolenAdmin } from "./admin/recovery";
import { bodyHash, type SignedEntry } from "./authority/entries";
import { activeAdmins } from "./authority/state";
import { lineageCount } from "./authority/lineage";
import type { SignedStatement } from "./authority/statements";
import { movedTarget, rekeyRequest, rekeyStatus } from "./member/rotation";
import { rjcs } from "./proto/rjcs";
import { verifyGenesis, type RoomGenesis } from "./authority/genesis";
import type { StatementData, StatementType } from "./authority/statements";
import { autoApprovalEndsAt } from "./authority/holds";
import { AdminHoldClock } from "./admin/hold-clock";
import { edKid, versionKey, type RoomState } from "./authority/state";
import { DeviceLinker } from "./member/device-link";
import { readLinkSection, writeLinkSection } from "./member/enrollment-journal";
import { TestClock } from "./platform/test-clock";
import type { KeyObject } from "node:crypto";
import type { PendingView, InviteView } from "./host/enrollment";
import { isDevInsecureRelay, memberRelayUseTls, relayKey } from "./host/invites";
import { endpointKeyFromHost, movedEndpointKeys, RoomEndpoint } from "./host/room-endpoint";
import { genesisPath, RoomHost } from "./host/room-host";
import { CompatGuard } from "./compat";
import { deleteKeyStore, ENV_KEYSTORE, openKeyStore, type Kek, type KeyStoreDeletion, type KeyStoreStatus, type OpenKeyStoreOptions } from "./keystore/keystore";
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
import { mergeStale, readStaleHosts, removeHosts, writeStaleHosts, type HostsRemover, type StaleHost } from "./member/stale-hosts";
import { RoomClient } from "./member/room-client";
import { SealedLogCopy } from "./member/log-copy";
import { RoomLogFold } from "./authority/fold";
import { MlsDelivery } from "./host/mls-delivery";
import { mlsAdapter, type MlsAdapter } from "./mls/adapter";
import { MlsMember, type MlsMessage, type MlsProfileEvent, type MlsTimings } from "./mls/member";
import type { AppPayload } from "./mls/formats";
import { ActivityFeed } from "./member/activity";
import { ChatStore } from "./member/chat-store";
import { RoomBook, ROOM_DESCRIPTION_MAX, ROOM_NAME_MAX, MEMBER_NAME_MAX, SealedRoomBookStore, sanitizeDisplayText } from "./member/room-book";
import { SealedMlsStore } from "./mls/sealed-store";
import { writePrivateFile } from "./platform/durable";
import { resolvePaseoHome } from "./platform/home";
import { gateDevSwitches, testHomeRefusal } from "./platform/test-clock";
import { inertMcpServer } from "./gateway/agent-guard";
import { isMarkedRoomAgent, readStoredAgentRecord, verifyRoomAgent } from "./gateway/tripwire";
import { archivedKeyFiles, deleteArchivedKeys, dismissNotice, HOSTS_BACKOFF_MS, migrateV1, readMigration, removeV1Registrations, v1ForkAgentIds, type HostsRemoveApi, type MigrationRecord } from "./migration/v1";
import { defaultProtection, ProtectionError, type FileProtection, type ProtectionProblem } from "./platform/file-protection";
import { b64u, b64uDecode } from "./proto/b64u";
import { isValidLabel } from "./proto/enroll";
import { isId, isRoomId } from "./proto/ids";
import { ed25519PrivateKeyFromSeed, fingerprintOfKid, rawPublicKey, x25519PrivateKeyFromSecret } from "./proto/keys";
import { rjcsParse } from "./proto/rjcs";
import type { RelayAddress } from "./transport/relay-server";

/** Paseo's API handle, taken from the host SDK (the plugin does not depend on @getpaseo/client at run time). */
type PaseoApi = PluginHandlerContext["paseo"];

/**
 * DEV-ONLY: short MLS timers (witness, joiner check, retries) so the offline e2e runs in seconds. The
 * repair delay keeps its production value: joins go through the prompt Add (round 9, item 5).
 */
export const ENV_DEV_MLS_FAST = "PASEO_ROOMS_DEV_MLS_FAST";
const DEV_MLS_TIMINGS: Partial<MlsTimings> = { witnessMaxDelayMs: 1000, epochConfirmMs: 5000, retryMs: 2000 };

const DEFAULT_RELAY = { host: "relay.paseo.sh", port: 443 };
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);

export function genesisRelay(env: NodeJS.ProcessEnv): { host: string; port: number; tls: true } {
  const raw = env.PASEO_ROOMS_RELAY_ENDPOINT;
  if (!raw) return { ...DEFAULT_RELAY, tls: true };
  const m = /^([A-Za-z0-9.-]{1,253}):(\d{1,5})$/.exec(raw);
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) throw new Error("PASEO_ROOMS_RELAY_ENDPOINT must be host:port");
  return { host: m[1], port: Number(m[2]), tls: true };
}

/** Member side (P-20): TLS unless PASEO_ROOMS_DEV_INSECURE_RELAY=1 and the relay is on loopback. */
export function memberRelayAddress(relay: { host: string; port: number }, env: NodeJS.ProcessEnv): RelayAddress {
  return { endpoint: `${relay.host}:${relay.port}`, useTls: memberRelayUseTls(relay.host, isDevInsecureRelay(env)) };
}

/** Owner side: where the room endpoint reaches its relay. TLS unless the development override applies to a loopback host. */
export function relayAddress(relay: { host: string; port: number }, env: NodeJS.ProcessEnv): RelayAddress {
  const plain = env.PASEO_ROOMS_RELAY_TLS === "false" && LOOPBACK.has(relay.host);
  return { endpoint: `${relay.host}:${relay.port}`, useTls: !plain };
}


type Owned = {
  host: RoomHost;
  signer: AdminSigner | null;
  holds: AdminHoldClock | null;
  endpoint: RoomEndpoint;
  /** Replaced room endpoints in their restricted (`moved`) mode (keys 4.6 step 4). */
  moved: RoomEndpoint[];
  grants: HostGrants;
  lanes: LaneService;
  approver: ReturnType<typeof setInterval> | null;
  mls: MlsDelivery | null;
  mlsTick: ReturnType<typeof setInterval> | null;
  ownFeed: (() => void) | null;
};
type Joined = { client: RoomClient; memberId: string; deviceId: string };
/** R2.6: what "delete hosted rooms" can do about closing a hosted room (keys 6.8). */
export type HostedClosurePlan = {
  plan: "already_closed" | "confirm_proposal" | "recovery_key" | "none";
  reason: "recovery_code_required" | "second_admin_required" | "no_admin_key" | null;
  message: string;
};
export type HostedClosure = {
  roomId: string;
  outcome: "closed" | "already_closed" | "not_closed";
  via: "recovery_key" | "confirmed_proposal" | null;
  seq: number | null;
  reason: HostedClosurePlan["reason"] | "error";
  message: string;
};

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
  /** R2.7: the owner daemon's Paseo version and protocol against the tested range; lanes refuse to serve outside it. */
  readonly compat = new CompatGuard({ log });
  private paseo: PaseoApi | null = null;
  private started: Promise<void> | null = null;
  private stopping = false;
  /** Member: the confirming-device side of device links, by room. */
  private readonly linkers = new Map<string, DeviceLinker>();
  /** MLS (I-13): the adapter, and this daemon's member device of each room it is in (owned or joined). */
  private mlsLib: MlsAdapter | null = null;
  readonly mlsMembers = new Map<string, MlsMember>();
  /** R3.3: names (room.profile, member.profile) and alert acknowledgements of each room, sealed at rest. */
  private readonly books = new Map<string, RoomBook>();
  /** R3.5: activity notices of each room from this daemon's own verified fold (owner or member device). */
  private readonly feeds = new Map<string, ActivityFeed>();
  /** R3.4: the chat history of each room on this device, sealed at rest (member/chat-store.ts). */
  private readonly chats = new Map<string, ChatStore>();
  /** Admin daemon: automatic approvals that failed, retried after this time (by request bodyHash). */
  private readonly approveRetryAt = new Map<string, number>();
  /** Admin daemon: rekey approvals in flight (the admin route is asynchronous), by request bodyHash. */
  private readonly rekeyInFlight = new Set<string>();
  /** Member: reconnects after `superseded` or `moved`, not before this time (by room). */
  private readonly reconnectAt = new Map<string, number>();
  /** Member: rooms whose rekey packages are published (in this process). */
  private readonly rekeyPublished = new Set<string>();
  /** I-14: one-time confirmations of interactive admin actions (identity-model 5.3). */
  readonly confirmations = new ConfirmationBook();
  /** Files the start check found unprotected (relative paths), until "Fix permissions" succeeds. */
  private permissionProblems: ProtectionProblem[] | null = null;
  /**
   * Clock of the room hosts' `hts` and of automatic approvals. Date.now, except on an e2e test home
   * with PASEO_ROOMS_TEST_CLOCK=1 (server/platform/test-clock.ts), where tests may move it forward.
   */
  readonly clock: TestClock;
  /**
   * True only on a marked e2e test home (testHomeRefusal). No RPC depends on it since R3.4 replaced the
   * development chat RPCs (`rooms.v2.mls.send`, `rooms.v2.mls.messages`) with `rooms.v2.chat.*`.
   */
  readonly testHome: boolean;

  /** The environment in use: PASEO_ROOMS_DEV_* removed unless this is a marked e2e test home. */
  private readonly env: NodeJS.ProcessEnv;
  /** Migration from M1 (migration.md section 2): the record, once read at start. */
  private migration: MigrationRecord | null = null;
  private hostsCleanup: Promise<void> | null = null;
  /** The options the KeyStore was opened with (R2.6 deletes the KEK through the same backend). */
  private keystoreOpts: OpenKeyStoreOptions | null = null;
  /** R3.7: next retry of stale lane host removals, and whether one runs. */
  private staleRetryAt = 0;
  private staleBusy = false;

  constructor(
    env: NodeJS.ProcessEnv = process.env,
    private readonly protection: FileProtection = defaultProtection(),
    /**
     * Test only: shorter session timers and retries; `allowDevSwitches` keeps PASEO_ROOMS_DEV_* on a
     * temporary home (unit tests), which the test-home guard would otherwise drop.
     */
    private readonly tuning: { timings?: ConstructorParameters<typeof RoomClient>[0]["timings"]; retryMs?: number[]; allowDevSwitches?: boolean } = {},
  ) {
    this.paseoHome = resolvePaseoHome(env);
    this.dataDir = nodePath.join(this.paseoHome, "plugin-data", "rooms");
    const gated = gateDevSwitches(env, this.paseoHome, { allow: tuning.allowDevSwitches === true });
    if (gated.dropped.length) log("dev_switches_ignored", { switches: gated.dropped, reason: gated.refusal });
    this.env = gated.env;
    this.clock = new TestClock(env, this.paseoHome);
    this.testHome = testHomeRefusal(this.paseoHome) === null;
  }

  /** The PaseoApi of the latest RPC context: lane registration waits for it (section 8). */
  attach(paseo: PaseoApi | null | undefined): void {
    if (!paseo) return;
    this.paseo = paseo;
    if (!this.observing && !this.stopping) this.observeHosts(paseo);
    this.cleanUpV1Hosts();
  }

  // ------------------------------------------------------------------------------ migration from M1

  /** Migration 2.3 step 2: removes the member's v1 registrations, retried with backoff until done. */
  private cleanUpV1Hosts(): void {
    if (this.hostsCleanup || this.stopping || !this.paseo || this.migration?.hosts !== "pending") return;
    const hosts = this.paseo.hosts as unknown as HostsRemoveApi;
    this.hostsCleanup = (async () => {
      for (let i = 0; !this.stopping; i++) {
        try {
          const n = await removeV1Registrations(this.dataDir, hosts, PLUGIN_ID);
          this.migration = readMigration(this.dataDir);
          log("v1_registrations_removed", { removed: n });
          return;
        } catch (e) {
          logError("v1_registrations_remove_failed", e, { attempt: i + 1 });
          await new Promise<void>((r) => (setTimeout(r, HOSTS_BACKOFF_MS[Math.min(i, HOSTS_BACKOFF_MS.length - 1)]) as { unref?: () => void }).unref?.());
        }
      }
    })().finally(() => {
      this.hostsCleanup = null;
    });
  }

  /** Status view of the migration (notice 2.5, archive notice 2.4, routed-entry note 2.3 step 4). */
  private migrationView() {
    const m = this.migration;
    if (!m) return null;
    return {
      archive: m.archive,
      notice: m.noticeDismissedAt === null,
      gateway: m.gateway,
      member: m.member,
      hosts: m.hosts,
      hostsRemoved: m.hostsRemoved,
      keyFiles: archivedKeyFiles(this.dataDir),
      lanes: m.ownerLanes.map((l) => ({ laneId: l.laneId, roomId: l.roomId, agentId: l.agentId, label: l.label, origin: l.origin })),
    };
  }

  /**
   * V-6: archive actions change files only in a data folder that passed the permission check, both at
   * start (`ready`) and now (the tree may have changed since).
   */
  private async requireVerifiedTree(): Promise<void> {
    await this.start();
    if (this.state !== "ready") throw new Error("Rooms did not start because its data folder failed the permission check. Fix permissions first.");
    const check = this.protection.verifyTree(this.dataDir);
    if (!check.ok) {
      this.permissionProblems = check.problems;
      throw new ProtectionError(check.problems);
    }
  }

  /** "Delete keys" (migration 2.4): the user's explicit action. Keeps the room logs. */
  async deleteV1Keys(expected?: readonly string[]): Promise<{ removed: string[] }> {
    await this.requireVerifiedTree();
    if (expected) {
      const now = archivedKeyFiles(this.dataDir).sort();
      const shown = [...new Set(expected)].sort();
      if (now.length !== shown.length || now.some((f, i) => f !== shown[i])) throw new Error("The key files changed since the dialog opened. Review them and confirm again.");
    }
    const removed = deleteArchivedKeys(this.dataDir);
    this.migration = readMigration(this.dataDir);
    log("v1_archive_keys_deleted", { files: removed.length });
    return { removed };
  }

  async dismissMigrationNotice(): Promise<void> {
    await this.requireVerifiedTree();
    dismissNotice(this.dataDir);
    this.migration = readMigration(this.dataDir);
  }

  // ------------------------------------------------------------------------------ lane agents

  /** Open lanes this daemon serves, by agent (composer pill, "Open room…" redirect). */
  laneAgents(): Array<{ agentId: string; laneId: string; roomId: string; roomName: string; connectedMembers: number }> {
    const out: Array<{ agentId: string; laneId: string; roomId: string; roomName: string; connectedMembers: number }> = [];
    for (const o of this.owned.values()) {
      if (o.host.state.auth.closed) continue;
      for (const l of o.lanes.lanes()) {
        if (l.status === "closed" || !l.agentId) continue;
        out.push({ agentId: l.agentId, laneId: l.laneId, roomId: o.host.roomId, roomName: this.bookIfOpen(o.host.roomId)?.room?.name ?? `Room ${o.host.roomId.slice(5, 11)}`, connectedMembers: l.links });
      }
    }
    return out;
  }

  /** Lifecycle hook agent.archived (C-13): lanes of that agent stop serving and are closed. */
  onAgentArchived(agentId: string): string[] {
    const closed: string[] = [];
    for (const o of this.owned.values()) closed.push(...o.lanes.onAgentArchived(agentId));
    return closed;
  }

  /**
   * Tripwire on resume (C-iso2) for room agents created by Rooms: M1 fork lanes left behind by the
   * migration keep their inert MCP shadow (migration 2.2 step 4). Throws to refuse the open.
   *
   * Fails closed (V-1), independent of the runtime state and of the in-memory migration record. An
   * agent is a room agent when its stored record carries a Rooms marker (isMarkedRoomAgent) or it is
   * an M1 fork listed in migration.json, an unarchived v1 `gateway/state.json` or an archive
   * (read synchronously here, so this works before start reaches the migration and after a failed
   * permission check). A room agent must pass verifyRoomAgent. The resume is also refused when the
   * agent's stored record exists but cannot be read, and when the record is missing while the list
   * of M1 forks cannot be read (migration.json unreadable).
   */
  assertRoomAgentIntact(agentId: string): void {
    const forks = v1ForkAgentIds(this.dataDir);
    for (const l of this.migration?.ownerLanes ?? []) if (l.origin === "fork") forks.ids.add(l.agentId);
    const known = forks.complete || this.migration !== null;
    const stored = readStoredAgentRecord(this.paseoHome, agentId, null);
    const room = (stored.state === "ok" && isMarkedRoomAgent(stored.record)) || forks.ids.has(agentId);
    const refuse = (problems: string[]): never => {
      log("room_agent_tripwire", { agentId, when: "session_open", forksKnown: known, problems });
      throw new Error(`Room agent failed the isolation check: ${problems.join("; ")}`);
    };
    if (!room) {
      if (stored.state === "unreadable") refuse(["stored agent record unreadable; Rooms cannot tell whether this is a room agent"]);
      if (stored.state === "missing" && !known) refuse(["stored agent record not found and the list of room agents (migration.json) is not readable"]);
      return;
    }
    // A pure descriptor: nothing is written into a data folder that may have failed the permission check.
    const r = verifyRoomAgent(this.paseoHome, agentId, null, inertMcpServer(this.dataDir));
    if (!r.ok) refuse(r.problems);
  }

  /** C-13: the lane's agent is gone. The admin key of this daemon closes the lane in the log. */
  private closeLaneForAgent(roomId: string, laneId: string, reason: string): void {
    const o = this.owned.get(roomId);
    if (!o?.signer) {
      log("v2_lane_close_skipped", { roomId, laneId, reason, why: "no admin key on this daemon" });
      return;
    }
    const l = o.host.state.auth.lanes[laneId];
    if (!l || l.status === "closed") return;
    this.adminSubmit(roomId, "lane.closed", { laneId });
    log("lanes_closed_for_archived_agent", { roomId, laneId, reason });
  }

  start(): Promise<void> {
    this.started ??= this.startInner().catch((e) => {
      this.state = "error";
      this.error = e instanceof ProtectionError ? "permission_error" : String((e as Error)?.message ?? e).slice(0, 200);
      if (e instanceof ProtectionError) this.permissionProblems = e.problems;
      else if (this.keystore?.state === "permission_error") this.permissionProblems = this.keystore.problems ?? [];
      logError("v2_runtime_start_failed", e);
    });
    return this.started;
  }

  /**
   * "Fix permissions" (I-2, audit X-2): only after the start check failed on file protection. Repairs
   * what the protection backend may repair (never symlinks or foreign owners), then starts again.
   */
  async fixPermissions(): Promise<{ ok: boolean; problems: ProtectionProblem[] }> {
    await this.start();
    if (this.state === "ready") return { ok: true, problems: [] };
    if (this.permissionProblems === null) return { ok: false, problems: [] };
    const r = this.protection.fix(this.dataDir);
    log("permissions_fix", { ok: r.ok, problems: r.ok ? [] : r.problems.slice(0, 10) });
    if (!r.ok) {
      this.permissionProblems = r.problems;
      return { ok: false, problems: r.problems };
    }
    this.permissionProblems = null;
    this.state = "starting";
    this.error = null;
    this.started = null;
    await this.start();
    return { ok: (this.state as RoomsRuntimeV2["state"]) === "ready", problems: this.permissionProblems ?? [] };
  }

  private async startInner(): Promise<void> {
    // R2.7: read the daemon's version and protocol in the background; lanes check it again at start.
    if (!this.stopping) this.compat.probe(this.paseoHome);
    this.protection.ensureDir(this.dataDir);
    const check = this.protection.verifyTree(this.dataDir);
    if (!check.ok) throw new ProtectionError(check.problems);
    // Migration from M1 before any key is read (migration.md 2): archive v1 data, record it.
    try {
      this.migration = (await migrateV1(this.dataDir, { log })).record;
    } catch (e) {
      logError("v1_migration_failed", e);
      this.migration = readMigrationSafe(this.dataDir);
    }
    this.cleanUpV1Hosts();
    const explicitFile = this.env[ENV_KEYSTORE] === "fallback-file" || this.env[ENV_KEYSTORE] === "operator-file";
    this.keystoreOpts = {
      dataDir: this.dataDir,
      paseoHome: this.paseoHome,
      env: this.env,
      log,
      ...(explicitFile ? { native: () => ({ ok: false as const, reason: "not_probed", detail: "an explicit file keystore is configured" }) } : {}),
    };
    const status = await openKeyStore(this.keystoreOpts);
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
      for (const [roomId, j] of this.joined) if (j.client.status === "ended" && this.schedulers.has(roomId)) void this.stopLanes(roomId);
      for (const roomId of this.joined.keys()) this.followRotation(roomId);
      this.retryStaleHosts();
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

  private serve(host: RoomHost, signer0: AdminSigner | null): void {
    // An admin key rotation logged before a crash: the staged key becomes this daemon's key (keys 4.3).
    let signer = signer0;
    try {
      signer = signer0?.promote((kid) => activeAdmins(host.state.auth).some((a) => a.kid === kid)) ?? signer0;
    } catch (e) {
      logError("admin_key_promote_failed", e, { roomId: host.roomId });
    }
    const g = host.state.auth.endpoint.relay;
    const roomId = host.roomId;
    const grants = new HostGrants({ dataDir: this.dataDir, kek: this.kek!, host, env: this.env, now: this.clock.now });
    let lanes: LaneService | null = null;
    let endpoint: RoomEndpoint | null = null;
    let ownFeed: (() => void) | null = null;
    const mls = this.mlsLib
      ? new MlsDelivery({ dataDir: this.dataDir, kek: this.kek!, host, adapter: this.mlsLib, now: this.clock.now, push: (d, f) => endpoint?.pushToDevice(d, f) ?? false, afterAppend: () => endpoint?.afterAppend(), onPublished: (d) => this.mlsMembers.get(roomId)?.packagesPublished(d) })
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
        this.observeHolds(roomId);
      },
    });
    grants.afterAppend = () => endpoint.afterAppend();
    lanes = new LaneService({
      dataDir: this.dataDir,
      kek: this.kek!,
      host,
      grants,
      relay: relayAddress(g, this.env),
      paseoHome: this.paseoHome,
      onAgentGone: (laneId, reason) => this.closeLaneForAgent(roomId, laneId, reason),
      compat: this.compat,
    });
    // The admin daemon's automatic approvals of held device adds (identity-model.md 6.3).
    const approver = signer ? setInterval(() => this.autoApprove(roomId), 2000) : null;
    (approver as { unref?: () => void } | null)?.unref?.();
    const mlsTick = mls ? setInterval(() => mls.tick(), 30_000) : null;
    (mlsTick as { unref?: () => void } | null)?.unref?.();
    const holds = signer ? new AdminHoldClock(this.dataDir, this.kek!, roomId, this.clock.now) : null;
    const moved = movedEndpointKeys(this.dataDir, this.kek!, roomId, this.clock.now()).map((m) => new RoomEndpoint({ host, endpointKey: m.endpointKey, relay: relayAddress(g, this.env), restricted: m, ...(this.tuning.timings ? { timings: this.tuning.timings } : {}) }));
    const owned: Owned = { host, signer, holds, endpoint, moved, grants, lanes, approver, mls, mlsTick, ownFeed: null };
    this.owned.set(roomId, owned);
    this.observeHolds(roomId);
    endpoint.start();
    for (const m of moved) m.start();
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
      onProfile: (e) => this.onProfile(roomId, e),
      storeMessages: (ms) => this.storeChat(roomId, ms),
      announce: () => this.announcements(roomId, memberId, () => host.state),
    });
    this.mlsMembers.set(roomId, member);
    endpoint.onLocalPush(deviceId, (f) => void member.onPush(f));
    const fold = RoomLogFold.fromGenesis(host.genesis);
    const activity = this.feedOf(roomId);
    const feed = () => {
      for (const r of host.entries(fold.head.seq + 1)) {
        const before = fold.state;
        fold.append(r.signed, r.body);
        member.ingest(r.signed, before, fold.state);
        activity.push(r.signed, before, fold.state);
        // Prompt Add (MLS 4.4; round 9, item 5): devices this daemon's admin key just admitted.
        const kid = o.signer?.kid;
        if (kid && r.signed.entry.cls === "stmt") {
          const added = newDeviceIds(before, fold.state);
          if (added.length > 0 && statementProducerKid(r.body) === kid) member.promptAdd(added);
        }
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
      onProfile: (e) => this.onProfile(roomId, e),
      storeMessages: (ms) => this.storeChat(roomId, ms),
      announce: () => this.announcements(roomId, memberId, () => this.joined.get(roomId)?.client.state ?? null),
    });
    this.mlsMembers.set(roomId, member);
    // A rekey requested before a restart: its next key again (its packages are in the sealed record).
    const j = this.joining.get(roomId)?.journal;
    if (j?.rekey?.ref) {
      const { sigSeed, dhSecret } = j.rekeyKeys();
      dhSecret.fill(0);
      member.resumeRekey({ sigPub: j.rekey.sig, sigKey: ed25519PrivateKeyFromSeed(sigSeed) });
      sigSeed.fill(0);
      this.rekeyPublished.add(roomId);
    }
    member.start();
    return member;
  }

  // ------------------------------------------------------------------------------ names and activity (R3.3, R3.5)

  /** The names book of a room, opened on first use (null before the keystore is ready). */
  private bookIfOpen(roomId: string): RoomBook | null {
    const have = this.books.get(roomId);
    if (have || !this.kek) return have ?? null;
    const book = new RoomBook(roomId, new SealedRoomBookStore({ dataDir: this.dataDir, kek: this.kek, roomId }));
    if (book.problem) log("room_book_reset", { roomId, problem: book.problem });
    this.books.set(roomId, book);
    return book;
  }

  private bookOf(roomId: string): RoomBook {
    const b = this.bookIfOpen(roomId);
    if (!b) throw new Error("Rooms is not ready");
    return b;
  }

  private feedOf(roomId: string): ActivityFeed {
    let f = this.feeds.get(roomId);
    if (!f) this.feeds.set(roomId, (f = new ActivityFeed()));
    return f;
  }

  /** A profile from another device of the room group; the book decides (admin for the room name, own id for a display name). */
  private onProfile(roomId: string, e: MlsProfileEvent): void {
    try {
      const r = this.bookOf(roomId).apply({ seq: e.seq, from: e.from, payload: e.payload });
      if (r === "refused") log("room_profile_refused", { roomId, kind: e.payload.kind, seq: e.seq, fromDevice: e.from.deviceId });
    } catch (err) {
      logError("room_book_save_failed", err, { roomId });
    }
  }

  /** What this device re-announces after an Add (R3.3): the room name if its member is an admin, its own display name. */
  private announcements(roomId: string, memberId: string, state: () => Readonly<RoomState> | null): AppPayload[] {
    const book = this.bookIfOpen(roomId);
    if (!book) return [];
    const out: AppPayload[] = [];
    const r = book.room;
    if (r && state()?.members[memberId]?.role === "admin") out.push({ kind: "room.profile", name: r.name, description: r.description, rev: r.rev });
    const n = book.memberName(memberId);
    if (n) out.push({ kind: "member.profile", memberId, label: n });
    return out;
  }

  /** This daemon's member and its verified roster in a room (the owner's own device for an owned room). */
  private selfIn(kek: Kek, roomId: string): { memberId: string; state: Readonly<RoomState> } {
    const o = this.owned.get(roomId);
    if (o) return { memberId: this.ownMemberId(kek, roomId), state: o.host.state };
    const j = this.joined.get(roomId);
    if (!j || j.client.head.seq < 0) throw new Error("Not a member of that room on this daemon");
    return { memberId: j.memberId, state: j.client.state };
  }

  /** R3.3: sends `room.profile` in the room group (admins only). The host never sees the name. */
  async setRoomProfile(roomId: string, name: string, description?: string): Promise<{ seq: number }> {
    const kek = await this.ready();
    const m = this.mlsMembers.get(roomId);
    if (!m) throw new Error("No MLS group member for that room on this daemon");
    const self = this.selfIn(kek, roomId);
    if (self.state.members[self.memberId]?.role !== "admin") throw new Error("Only an admin of the room can change its name");
    const clean = sanitizeDisplayText(name, ROOM_NAME_MAX);
    if (!clean) throw new Error(`The room name must have 1 to ${ROOM_NAME_MAX} visible characters`);
    const desc = sanitizeDisplayText(description ?? "", ROOM_DESCRIPTION_MAX) ?? "";
    const book = this.bookOf(roomId);
    const payload = { kind: "room.profile" as const, name: clean, description: desc, rev: (book.room?.rev ?? -1) + 1 };
    const r = await m.sendProfile(payload);
    book.apply({ seq: r.seq, from: { memberId: self.memberId, role: "admin" }, payload });
    log("room_profile_sent", { roomId, seq: r.seq, rev: payload.rev });
    return { seq: r.seq };
  }

  /** R3.3: sends this member's `member.profile` (display name) in the room group. */
  async setMemberProfile(roomId: string, displayName: string): Promise<{ seq: number }> {
    const kek = await this.ready();
    const m = this.mlsMembers.get(roomId);
    if (!m) throw new Error("No MLS group member for that room on this daemon");
    const self = this.selfIn(kek, roomId);
    const clean = sanitizeDisplayText(displayName, MEMBER_NAME_MAX);
    if (!clean) throw new Error(`The display name must have 1 to ${MEMBER_NAME_MAX} visible characters`);
    const payload = { kind: "member.profile" as const, memberId: self.memberId, label: clean };
    const r = await m.sendProfile(payload);
    this.bookOf(roomId).apply({ seq: r.seq, from: { memberId: self.memberId, role: self.state.members[self.memberId]?.role ?? "" }, payload });
    log("member_profile_sent", { roomId, seq: r.seq });
    return { seq: r.seq };
  }

  /** R3.5: hides alert notices on this device. Sending stays stopped where an alert stopped it (room-log 6.6). */
  async ackAlerts(roomId: string, alerts: readonly { type: string; seq: number }[]): Promise<{ ok: true; acked: number }> {
    await this.ready();
    if (!this.owned.has(roomId) && !this.joined.has(roomId) && !this.mlsMembers.has(roomId)) throw new Error("Unknown room");
    const acked = this.bookOf(roomId).ack(alerts, Date.now());
    log("room_alerts_acknowledged", { roomId, acked });
    return { ok: true, acked };
  }

  // ------------------------------------------------------------------------------ chat (R3.4)

  /** The chat store of a room, opened on first use. Throws before the keystore is ready. */
  private chatOf(roomId: string): ChatStore {
    const have = this.chats.get(roomId);
    if (have) return have;
    if (!this.kek) throw new Error("Rooms is not ready");
    const store = new ChatStore({ dataDir: this.dataDir, kek: this.kek, roomId });
    if (store.problems.length) log("chat_store_damaged", { roomId, problems: store.problems.slice(0, 8) });
    this.chats.set(roomId, store);
    return store;
  }

  /** The MLS member's write-ordering hook (8.2): messages are sealed on disk before the state and the ack. Throws on failure. */
  private storeChat(roomId: string, ms: MlsMessage[]): void {
    this.chatOf(roomId).add(ms.map((m) => ({ seq: m.seq, epoch: m.epoch, hts: m.hts, ts: m.ts, memberId: m.from.memberId, deviceId: m.from.deviceId, text: m.text, own: false })));
  }

  /**
   * The room group member of a room this daemon is in, for chat. Only rooms this daemon owns or joined
   * have one: lane viewers are not group members, and chat is never served through a lane.
   */
  private chatMember(roomId: string): MlsMember {
    const m = this.mlsMembers.get(roomId);
    if (!m || (!this.owned.has(roomId) && !this.joined.has(roomId))) throw new Error("This daemon is not a member of that room");
    return m;
  }

  /** R3.4: sends a signed chat message in the room group and stores it here. */
  async chatSend(roomId: string, text: string): Promise<{ seq: number }> {
    await this.ready();
    const m = this.chatMember(roomId);
    const j = this.joined.get(roomId);
    if (j && j.client.status === "ended") throw new Error("This device no longer has access to the room");
    const r = await m.sendText(text);
    try {
      this.chatOf(roomId).add([{ seq: r.seq, epoch: r.epoch, hts: Date.now(), ts: r.ts, memberId: r.from.memberId, deviceId: r.from.deviceId, text, own: true }]);
    } catch (err) {
      // Sent: the others have it. Only this device's copy is missing.
      logError("chat_store_failed", err, { roomId });
    }
    log("chat_sent", { roomId, seq: r.seq });
    return { seq: r.seq };
  }

  /** R3.4: a page of this device's chat history of a room, with the senders' names and verification state. */
  async chatList(roomId: string, before?: number, limit = 50) {
    const kek = await this.ready();
    const m = this.chatMember(roomId);
    await m.idle();
    const store = this.chatOf(roomId);
    const page = store.page(before ?? null, limit);
    let self: { memberId: string; state: Readonly<RoomState> } | null = null;
    try {
      self = this.selfIn(kek, roomId);
    } catch {
      self = null;
    }
    const st = self?.state ?? null;
    const ids = [...new Set(page.messages.map((x) => x.memberId))];
    const names = this.bookIfOpen(roomId)?.names(ids) ?? ids.map((memberId) => ({ memberId, name: null, collision: false }));
    const j = this.joined.get(roomId);
    const why = j?.client.status === "ended" ? "ended" : m.canSendReason();
    return {
      messages: page.messages.map((x) => ({
        seq: x.seq,
        hts: x.hts,
        ts: x.ts,
        memberId: x.memberId,
        deviceId: x.deviceId,
        text: x.text,
        own: x.own,
        verified: x.own ? ("own" as const) : ("verified" as const),
        current: !!st?.members[x.memberId]?.devices.some((d) => d.deviceId === x.deviceId),
      })),
      more: page.more,
      readSeq: store.read,
      unread: store.unread,
      selfMemberId: self?.memberId ?? null,
      names,
      cannotSend: why,
    };
  }

  /** R3.4: moves this device's read marker of a room. */
  async chatRead(roomId: string, seq: number): Promise<{ unread: number }> {
    await this.ready();
    this.chatMember(roomId);
    return { unread: this.chatOf(roomId).markRead(seq) };
  }

  /** R3.4: unread counts of every room this daemon is a group member of. */
  async chatUnread(): Promise<{ total: number; rooms: { roomId: string; unread: number }[] }> {
    await this.ready();
    const rooms = [...this.mlsMembers.keys()].filter((r) => this.owned.has(r) || this.joined.has(r)).map((roomId) => ({ roomId, unread: this.chatOf(roomId).unread }));
    return { total: rooms.reduce((n, r) => n + r.unread, 0), rooms };
  }

  private mlsView() {
    return [...this.mlsMembers.entries()].map(([roomId, m]) => {
      const v = m.view();
      const book = this.bookIfOpen(roomId);
      const chat = this.kek ? this.chatOf(roomId) : null;
      return { roomId, inGroup: v.inGroup, epoch: v.epoch, cursor: v.cursor, leaves: v.leaves.length, join: v.join?.status ?? null, stalled: v.stalled !== null, disabled: v.disabled, canSend: v.canSend, messages: chat?.size ?? 0, unread: chat?.unread ?? 0, alerts: m.alerts.slice(-16).map((a) => ({ type: a.type, seq: a.seq, acked: book?.isAcked(a.type, a.seq) ?? false })) };
    });
  }

  /**
   * `device.add.approved {mode:"auto"}` for every pending add whose hold has passed on this daemon's
   * clock and that no rule keeps for an admin (policy, sole-device policy, conflict, young requester).
   * The fold checks the same rules against `hts`; this is the real enforcement (room-log-v2 5).
   */
  autoApprove(roomId: string): void {
    const o = this.owned.get(roomId);
    if (!o?.signer || !o.holds || o.host.isStopped || this.stopping) return;
    const st = o.host.state;
    this.observeHolds(roomId);
    const now = this.clock.now();
    for (const [ref, p] of Object.entries(st.pending)) {
      if (p.status !== "pending") continue;
      // The hold on this daemon's own clock from when it first saw the request (identity 6.3).
      const at = o.holds.endsAt(st, ref, p);
      if (at === null || now < at || (this.approveRetryAt.get(ref) ?? 0) > Date.now()) continue;
      if (p.kind === "rekey") {
        // Keys 4.1 step 7: the admin route, approval and commit together (asynchronous).
        if (this.rekeyInFlight.has(ref)) continue;
        void this.approveRekeyNow(roomId, ref, "auto")
          .then((r) => log("device_rekey_auto_approved", { roomId, deviceId: p.deviceId, seq: r.seq, sole: p.sole }))
          .catch((e) => {
            // no_key_package: B publishes soon. stale_roster: another entry (a grant reissue, say) was
            // sequenced between the approval and its commit; a transient race, so retry soon.
            this.approveRetryAt.set(ref, Date.now() + (["no_key_package", "stale_roster"].includes((e as { code?: string }).code ?? "") ? 5_000 : 60_000));
            log("device_rekey_auto_approve_failed", { roomId, deviceId: p.deviceId, code: (e as { code?: string }).code ?? "error", error: String((e as Error)?.message ?? e).slice(0, 160) });
          });
        continue;
      }
      try {
        const r = this.adminSubmit(roomId, "device.add.approved", { memberId: p.memberId, deviceId: p.deviceId, ref, mode: "auto" });
        log("device_add_auto_approved", { roomId, memberId: p.memberId, deviceId: p.deviceId, seq: r.receipt.entry.seq, sole: p.sole });
      } catch (e) {
        this.approveRetryAt.set(ref, Date.now() + 60_000);
        log("device_add_auto_approve_failed", { roomId, deviceId: p.deviceId, error: String((e as Error)?.message ?? e).slice(0, 160) });
      }
    }
  }

  /** Records when this admin daemon first saw each pending request (its own clock; persisted). */
  private observeHolds(roomId: string): void {
    const o = this.owned.get(roomId);
    if (!o?.holds || o.host.isStopped) return;
    try {
      o.holds.observe(o.host.state);
    } catch (e) {
      logError("admin_holds_save_failed", e, { roomId });
    }
  }

  status() {
    const ks = this.keystore;
    return {
      protocol: "v2" as const,
      state: this.state,
      error: this.error,
      ...(this.clock.enabled ? { testClockOffsetMs: this.clock.offset } : {}),
      keystore: ks
        ? { state: ks.state, backend: ks.backend, fallback: ks.state === "ready" ? ks.fallback : false, notice: ks.state === "ready" ? ks.notice : null, message: ks.state === "ready" ? null : ks.message }
        : null,
      ...(this.permissionProblems ? { permissionProblems: this.permissionProblems.slice(0, 20).map((p) => ({ path: p.path, code: p.code, detail: p.detail })) } : {}),
      platform: process.platform,
      paseoCompat: this.compat.verdict,
      migration: this.migrationView(),
      owned: [...this.owned.values()].map(({ host, endpoint, grants, lanes, holds, signer, moved }) => ({
        roomId: host.roomId,
        serverId: endpoint.serverId,
        head: host.head,
        endpoint: endpoint.status,
        sessions: endpoint.sessions().map((s) => ({ memberId: s.memberId, deviceId: s.deviceId })),
        members: Object.keys(host.state.members).length,
        roster: rosterView(host.state, endpoint, signer?.memberId ?? null, this.bookIfOpen(host.roomId)),
        policy: {
          deviceAddApproval: host.state.auth.policy.deviceAddApproval,
          soleDeviceChange: host.state.auth.policy.soleDeviceChange,
          rotateLaneOnRemove: host.state.auth.policy.rotateLaneOnRemove,
          recoveryEscrow: host.state.auth.policy.recoveryEscrow,
          closeDelayS: host.state.auth.policy.closeDelay,
        },
        lineages: lineageCount(host.state.auth),
        closeOnDelete: this.closurePlanFor(host.roomId),
        invites: (endpoint.enrollment?.invites() ?? []).map(inviteView),
        joinRequests: (endpoint.enrollment?.pendings() ?? []).map(pendingView),
        lanes: lanes.lanes(),
        grants: grants.view().current,
        grantTtlS: grants.ttlS(),
        persistError: grants.persistError ?? (host.isStopped ? "room_stopped" : null),
        compromisedDevices: grants.compromisedDevices(),
        deviceRequests: deviceRequestsView(host.state, undefined, holds),
        conflicts: Object.keys(host.state.conflicts).sort(),
        // I-12: keys in use (ids only) and rotation state.
        keys: {
          hostKid: host.state.auth.hostKeys.find((h) => h.toSeq === null)?.kid ?? null,
          hostKeys: host.state.auth.hostKeys.map((h) => ({ kid: h.kid, fromSeq: h.fromSeq, toSeq: h.toSeq, validTo: h.validTo, revoked: h.revoked, uncertified: h.uncertified })),
          adminKid: signer?.kid ?? null,
          admins: activeAdmins(host.state.auth).map((a) => ({ kid: a.kid, root: a.root })),
          recoveryKid: host.state.auth.recovery?.kid ?? null,
          movedEndpoints: moved.filter((m) => m.status !== "closed").map((m) => m.serverId),
          closed: host.state.auth.closed,
          closeProposals: Object.entries(host.state.auth.pendingClose).filter(([, p]) => !p.used).map(([ref, p]) => ({ ref, kid: p.kid, hts: p.hts, exp: p.exp })),
          recoveryProposals: Object.entries(host.state.auth.pendingRecovery).filter(([, p]) => !p.used).map(([ref, p]) => ({ ref, kid: p.kid, exp: p.exp })),
        },
        uncertified: host.uncertifiedAlerts(),
        roomName: this.bookIfOpen(host.roomId)?.room?.name ?? null,
        roomDescription: this.bookIfOpen(host.roomId)?.room?.description || null,
        adminFingerprint: signer ? fingerprintOfKid(signer.kid) : null,
        activity: this.feeds.get(host.roomId)?.items(50) ?? [],
      })),
      mls: this.mlsView(),
      staleHosts: this.state === "ready" ? readStaleHosts(this.dataDir) : [],
      joining: [...this.joining.values()].map((e) => joinView(e.view())),
      joined: [...this.joined.entries()].map(([roomId, j]) => ({
        roomId,
        memberId: j.memberId,
        deviceId: j.deviceId,
        status: j.client.status,
        head: j.client.head,
        lastError: j.client.lastError,
        endedReason: j.client.endedReason,
        alerts: j.client.alerts.map((a) => ({ type: a.type, seq: a.seq, acked: this.bookIfOpen(roomId)?.isAcked(a.type, a.seq) ?? false })),
        sendingStopped: j.client.sendingStopped,
        roomName: this.bookIfOpen(roomId)?.room?.name ?? null,
        roomDescription: this.bookIfOpen(roomId)?.room?.description || null,
        names: j.client.head.seq >= 0 ? (this.bookIfOpen(roomId)?.names(Object.keys(j.client.state.members).sort()) ?? []) : [],
        activity: this.feeds.get(roomId)?.items(50) ?? [],
        registration: this.registrars.get(roomId)?.status ?? null,
        links: this.linkers.get(roomId)?.view() ?? [],
        // I-12: this device's own rekey, if one is open (ids and times only).
        rekey: (() => {
          const r = this.joining.get(roomId)?.journal.rekey;
          return r ? { ref: r.ref, requestedAt: r.at, published: this.rekeyPublished.has(roomId) } : null;
        })(),
        endpointServerId: j.client.head.seq >= 0 ? j.client.state.auth.endpoint.serverId : null,
        // The member's own pending device requests: the "Was this you?" prompt with Not me (6.3).
        deviceRequests: j.client.status === "open" || j.client.head.seq >= 0 ? deviceRequestsView(j.client.state, j.memberId) : [],
        conflict: j.client.head.seq >= 0 ? j.client.state.conflicts[j.memberId] !== undefined : false,
        memberDevices: j.client.head.seq >= 0 ? (j.client.state.members[j.memberId]?.devices.length ?? 0) : null,
        hosted: this.owned.has(roomId),
        lanes: [...(this.schedulers.get(roomId)?.entries() ?? [])].map(([laneId, sc]) => {
          const regId = this.joining.get(roomId)?.journal.e.registrations[laneId] ?? null;
          const reg = regId ? this.registrations.get(regId) : undefined;
          return { laneId, registrationId: regId, hostStatus: reg?.status ?? null, ...sc.view() };
        }),
      })),
    };
  }

  /**
   * Identity-model 5.4: the create-room dialog preselects "Create a recovery key"; the code is
   * returned once and never stored. Default "skip" for callers that would not show it.
   */
  async createRoom(recovery: "create" | "skip" = "skip"): Promise<{ roomId: string; serverId: string; recovery: RecoveryOfferView | null; recoverySkippedWarning: string | null }> {
    const kek = await this.ready();
    const room = await createRoom({ dataDir: this.dataDir, kek, relay: genesisRelay(this.env), recovery, now: this.clock.now });
    this.serve(room.host, room.signer);
    return { roomId: room.roomId, serverId: room.genesis.body.endpoint.serverId, recovery: room.recovery ? offerView(room.recovery) : null, recoverySkippedWarning: room.recoverySkippedWarning };
  }

  // ------------------------------------------------------------------------------ owner: confirmations (I-14)

  /** Step one of an interactive admin action: what will be signed, and a one-time token (identity-model 5.3). */
  async prepareAdmin(action: AdminActionV2): Promise<{ confirmToken: string; expiresAt: number; description: Omit<Described, "subject"> }> {
    await this.ready();
    const d = this.describe(action);
    const t = this.confirmations.prepare(action, d);
    const { subject: _subject, ...description } = d;
    return { ...t, description };
  }

  /** Step two: consumes the token before the action runs; `stale_base` when what it described changed. */
  async takeAdmin(confirmToken: string, action: AdminActionV2): Promise<void> {
    await this.ready();
    this.confirmations.take(confirmToken, action, () => this.describe(action));
  }

  private describe(action: AdminActionV2): Described {
    const o = this.ownedRoom(action.roomId);
    const pendings = o.endpoint.enrollment?.pendings() ?? [];
    const ctx: DescribeContext = {
      state: o.host.state,
      label: (memberId) => pendings.find((p) => p.memberId === memberId)?.label ?? null,
      lanes: o.lanes.lanes(),
      joinRequest: (pendingId) => {
        const p = pendings.find((x) => x.pendingId === pendingId);
        return p ? pendingView(p) : null;
      },
      ownAdminKid: o.signer?.kid ?? null,
      ownMemberId: o.signer?.memberId ?? null,
    };
    return describeAdminAction(ctx, action);
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
  async removeMember(roomId: string, memberId: string, compromise = false): Promise<{ seq: number; rotatedLanes: string[] }> {
    await this.ready();
    if (!isId("member", memberId)) throw new Error("bad memberId");
    const o = this.ownedRoom(roomId);
    // Keys 4.7: lanes are rotated after a removal flagged as compromise (or always, by policy).
    const toRotate = o.lanes.lanesToRotate(o.host.state, memberId, compromise);
    const seq = this.reducing(roomId, () => this.adminSubmit(roomId, "member.removed", { memberId, reason: compromise ? "compromise" : "admin" }).receipt.entry.seq);
    return { seq, rotatedLanes: this.rotateLanesAfterRemoval(roomId, toRotate) };
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
    if (!p) throw new Error("Unknown device request");
    // Checked before signing: a refused admin statement stays outstanding until a fence (I-7).
    if (p.status !== "pending") throw new Error(`The device request is ${p.status}`);
    if (p.kind === "rekey") return this.approveRekeyNow(roomId, ref, "admin");
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

  /**
   * Keys 4.1 step 7, the admin route (mls-integration.md 4.4): this daemon's own device in the room
   * group fetches the device's `rekey` KeyPackage (no package: nothing is signed), signs
   * `device.rekey.approved` and submits it with the Remove plus Add commit; the host sequences both
   * adjacently or neither. A pair the host refused is settled as rejected, so the signer is free again.
   */
  private async approveRekeyNow(roomId: string, ref: string, mode: "auto" | "admin"): Promise<{ seq: number }> {
    const o = this.ownedRoom(roomId);
    const member = this.mlsMembers.get(roomId);
    if (!o.signer) throw Object.assign(new Error("No admin key for this room on this daemon"), { code: "no_admin_key" });
    if (!member) throw Object.assign(new Error("This daemon's device is not in the room group"), { code: "no_group" });
    const p = o.host.state.pending[ref];
    if (!p || p.kind !== "rekey" || p.status !== "pending") throw new Error("No pending rekey with that reference");
    const signer = o.signer;
    let stmt: SignedStatement | null = null;
    this.rekeyInFlight.add(ref);
    try {
      o.ownFeed?.();
      const r = await member.approveRekey(ref, (base) => (stmt = signer.signWithCommit({ type: "device.rekey.approved", data: { memberId: p.memberId, deviceId: p.deviceId, ref, mode }, base })));
      signer.reconcile(o.host);
      log("device_rekey_approved", { roomId, deviceId: p.deviceId, mode, seq: r.statementSeq });
      return { seq: r.statementSeq };
    } catch (e) {
      if (stmt) {
        const h = bodyHash(rjcs(stmt));
        signer.reconcile(o.host);
        // commit.submit refused both entries: the approval was never logged (a definite rejection).
        if (o.host.findBody(h) === undefined) signer.settle(h, { rejected: true });
      }
      throw e;
    } finally {
      this.rekeyInFlight.delete(ref);
    }
  }

  /** Keys 4.5: stage the next host key in keys.sealed, then `host.key.rotated` with oldValidTo = now + 24 h. */
  async rotateHostKey(roomId: string): Promise<{ seq: number; kid: string }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    const staged = o.host.stageHostKey();
    const oldValidTo = Math.floor(this.clock.now() / 1000) + 24 * 3600;
    const r = this.adminSubmit(roomId, "host.key.rotated", { ...staged, oldValidTo });
    return { seq: r.receipt.entry.seq, kid: edKid(staged.change.newSig!) };
  }

  /** Keys 4.5 step 6 and 6.4: revokes a host key that is already rotated out, from `fromSeq`. */
  async revokeHostKey(roomId: string, kid: string, fromSeq: number): Promise<{ seq: number }> {
    await this.ready();
    const h = this.ownedRoom(roomId).host.state.auth.hostKeys.find((k) => k.kid === kid);
    if (!h) throw new Error("Unknown host key");
    if (h.toSeq === null) throw new Error("The current host key cannot be revoked; rotate it first");
    return this.reducing(roomId, () => ({ seq: this.adminSubmit(roomId, "host.key.revoked", { kid, fromSeq }).receipt.entry.seq }));
  }

  /** Keys 4.3: a new admin key, staged before `admin.key.rotated` is signed by the old one, installed after. */
  async rotateAdminKey(roomId: string): Promise<{ seq: number; kid: string }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    if (!o.signer) throw new Error("No admin key for this room on this daemon");
    const staged = o.signer.stageRotation();
    const r = this.adminSubmit(roomId, "admin.key.rotated", staged);
    const next = o.signer.promote((kid) => activeAdmins(o.host.state.auth).some((a) => a.kid === kid));
    if (!next) throw new Error("The rotation is logged but the new admin key could not be installed; it is installed at the next start");
    o.signer = next;
    next.reconcile(o.host);
    return { seq: r.receipt.entry.seq, kid: next.kid };
  }

  /** Keys 6.6: this admin revokes another admin key from `fromSeq` (its statements from there on become suspect). */
  async revokeAdminKey(roomId: string, kid: string, fromSeq: number): Promise<{ seq: number }> {
    await this.ready();
    return this.reducing(roomId, () => ({ seq: this.adminSubmit(roomId, "admin.key.revoked", { kid, fromSeq }).receipt.entry.seq }));
  }

  /**
   * Keys 4.6: the host creates and serves the next endpoint (`endpointNext`), the admin logs
   * `endpoint.rotated`, live sessions get the entry and are closed with `moved`, and the old endpoint
   * keeps answering `moved` to active devices for 30 days.
   */
  async rotateEndpoint(roomId: string): Promise<{ seq: number; serverId: string }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    const old = { serverId: o.endpoint.serverId, endpointKey: o.endpoint.endpointKey };
    const next = o.host.stageEndpoint();
    const relay = o.host.state.auth.endpoint.relay;
    const r = this.adminSubmit(roomId, "endpoint.rotated", { serverId: next.serverId, dh: next.dh, relay, ver: o.host.state.auth.versions[versionKey.endpoint()] ?? -1 });
    o.host.promoteEndpoint();
    o.endpoint.rotateTo(endpointKeyFromHost(this.dataDir, this.kek!, o.host));
    const until = this.clock.now() + 30 * 24 * 3600 * 1000;
    const restricted = new RoomEndpoint({ host: o.host, endpointKey: old.endpointKey, relay: relayAddress(relay, this.env), restricted: { ...old, until }, ...(this.tuning.timings ? { timings: this.tuning.timings } : {}) });
    o.moved.push(restricted);
    restricted.start();
    return { seq: r.receipt.entry.seq, serverId: next.serverId };
  }

  /** Keys 4.7: a new lane offer; the old lane endpoint stops at once. */
  async rotateLane(roomId: string, laneId: string): Promise<{ seq: number; serverId: string }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    let seq = -1;
    const r = o.lanes.rotateOffer(laneId, (data) => (seq = this.adminSubmit(roomId, "lane.offer.rotated", data).receipt.entry.seq));
    return { seq, serverId: r.serverId };
  }

  /** Keys 4.7 after a removal: the lanes `rotateLaneOnRemove` names are rotated; failures are logged. */
  private rotateLanesAfterRemoval(roomId: string, lanes: string[]): string[] {
    const o = this.ownedRoom(roomId);
    const done: string[] = [];
    for (const laneId of lanes) {
      try {
        o.lanes.rotateOffer(laneId, (data) => void this.adminSubmit(roomId, "lane.offer.rotated", data));
        done.push(laneId);
      } catch (e) {
        logError("lane_rotate_after_removal_failed", e, { roomId, laneId });
      }
    }
    return done;
  }

  /** Keys 6.1, 6.3: an admin removes one device; `compromise` also rotates the lanes the member could use. */
  async removeDevice(roomId: string, memberId: string, deviceId: string, compromise: boolean): Promise<{ seq: number; rotatedLanes: string[] }> {
    await this.ready();
    if (!isId("member", memberId) || !isId("device", deviceId)) throw new Error("bad memberId or deviceId");
    const o = this.ownedRoom(roomId);
    const toRotate = o.lanes.lanesToRotate(o.host.state, memberId, compromise);
    const seq = this.reducing(roomId, () => this.adminSubmit(roomId, "device.removed", { memberId, deviceId, reason: compromise ? "compromise" : "admin" }).receipt.entry.seq);
    return { seq, rotatedLanes: this.rotateLanesAfterRemoval(roomId, toRotate) };
  }

  /** Keys 6.8: `room.close.proposed` with `exp` (default: closeDelay + 3 days, at most 7 days ahead). */
  async proposeClose(roomId: string): Promise<{ seq: number; proposal: string; earliest: number }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    const delayS = o.host.state.auth.policy.closeDelay;
    const exp = Math.floor(this.clock.now() / 1000) + Math.min(7 * 24 * 3600 - 60, delayS + 3 * 24 * 3600);
    const r = this.adminSubmit(roomId, "room.close.proposed", { exp });
    return { seq: r.receipt.entry.seq, proposal: r.receipt.entry.bodyHash, earliest: r.receipt.entry.hts + delayS * 1000 };
  }

  /** Keys 6.8: an admin of another lineage confirms; refused here before closeDelay on this daemon's clock. */
  async confirmClose(roomId: string, proposal: string): Promise<{ seq: number }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    if (!o.signer) throw new Error("No admin key for this room on this daemon");
    this.observeHolds(roomId);
    const blocked = closeConfirmationBlocker(o.host.state, proposal, o.signer.kid, this.clock.now(), o.holds?.firstSeen(proposal));
    if (blocked) throw Object.assign(new Error(blocked.message), { code: blocked.reason });
    return { seq: this.adminSubmit(roomId, "room.closed", { proposal }).receipt.entry.seq };
  }

  /**
   * Keys 4.4: a first recovery key. One lineage: installed at once (`proposal: null`). Two or more:
   * `recovery.key.proposed` (exp in 3 days), which an admin of another lineage confirms. The code is a
   * secret, returned once and never stored or logged.
   */
  async createRecoveryKey(roomId: string): Promise<{ seq: number; proposal: string | null; recovery: RecoveryOfferView }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    if (o.host.state.auth.recovery) throw new Error("This room already has a recovery key; rotate it with the recovery code");
    const k = newRecoveryKey(roomId);
    if (lineageCount(o.host.state.auth) <= 1) {
      const r = this.adminSubmit(roomId, "recovery.key.rotated", { change: k.change, newKeySig: k.newKeySig, proposal: null });
      return { seq: r.receipt.entry.seq, proposal: null, recovery: offerView(recoveryOfferOf(k.kid, k.code, roomId, o.host.genesisHash)) };
    }
    const exp = Math.floor(this.clock.now() / 1000) + 3 * 24 * 3600;
    const r = this.adminSubmit(roomId, "recovery.key.proposed", { change: k.change, newKeySig: k.newKeySig, exp });
    return { seq: r.receipt.entry.seq, proposal: r.receipt.entry.bodyHash, recovery: offerView(recoveryOfferOf(k.kid, k.code, roomId, o.host.genesisHash)) };
  }

  /** Keys 4.4 (two lineages): confirms another lineage's proposal with its byte-identical change. */
  async confirmRecoveryKey(roomId: string, proposal: string): Promise<{ seq: number }> {
    await this.ready();
    const o = this.ownedRoom(roomId);
    const at = o.host.findBody(proposal);
    const rec = at === undefined ? undefined : o.host.entries(at, at)[0];
    if (!rec || rec.signed.entry.type !== "recovery.key.proposed") throw new Error("No recovery.key.proposed with that reference");
    const d = (rjcsParse(rec.body) as SignedStatement).body.data as StatementData<"recovery.key.proposed">;
    return { seq: this.adminSubmit(roomId, "recovery.key.rotated", { change: d.change, newKeySig: d.newKeySig, proposal }).receipt.entry.seq };
  }

  /**
   * The recovery procedures with R (keys 6.6 step 4, 6.8, 4.4), one action per typed code:
   * - `revoke_admin`: R revokes `kid` from `fromSeq`; when that leaves no active admin key or retires
   *   this daemon's key, R adds a fresh admin key, sealed here as this daemon's admin key (R8-5a).
   * - `close`: `room.closed {proposal: null}`, final.
   * - `rotate`: a new recovery code (returned once).
   */
  async recoveryAction(roomId: string, code: string, a: { kind: "revoke_admin"; kid: string; fromSeq: number } | { kind: "close" } | { kind: "rotate" }): Promise<{ seq: number; freshAdminKid?: string; recovery?: RecoveryOfferView }> {
    const kek = await this.ready();
    const o = this.ownedRoom(roomId);
    const r = RecoveryKey.fromCode(code, o.host.state, this.clock.now);
    const submit = (stmt: SignedStatement) => {
      const res = o.endpoint.submit(stmt);
      if (!res.ok) throw new Error(`${stmt.body.type} refused: ${res.code} (${res.reason})`);
      log("v2_recovery_statement", { roomId, type: stmt.body.type, seq: res.receipt.entry.seq });
    };
    try {
      if (a.kind === "close") {
        submit(r.sign("room.closed", { proposal: null }, o.host.head));
        return { seq: o.host.head.seq };
      }
      if (a.kind === "rotate") {
        const x = r.rotate(o.host.head);
        submit(x.statement);
        return { seq: o.host.head.seq, recovery: offerView(recoveryOfferOf(x.kid, x.code, roomId, o.host.genesisHash)) };
      }
      const memberId = o.signer?.memberId ?? this.ownMemberId(kek, roomId);
      const out = await recoverFromStolenAdmin({ r, state: () => o.host.state, head: () => o.host.head, submit, stolenKid: a.kid, fromSeq: a.fromSeq, ownKid: o.signer?.kid ?? null, freshFor: memberId });
      if (out.fresh) {
        try {
          writeAdminKey(this.dataDir, kek, { v: 2, typ: "admin-key", roomId, genesisHash: o.host.genesisHash, memberId, kid: out.fresh.kid, seed: b64u(out.fresh.seed) });
        } finally {
          out.fresh.seed.fill(0);
        }
        o.signer = AdminSigner.load({ dataDir: this.dataDir, kek, roomId });
        o.signer.reconcile(o.host);
      }
      return { seq: o.host.head.seq, ...(out.fresh ? { freshAdminKid: out.fresh.kid } : {}) };
    } finally {
      r.dispose();
    }
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

  /**
   * R3.2: closes a lane (`lane.closed`, final). Grants for the lane are dropped and pushed to its
   * endpoint before the append (grants-v2 7.1); the endpoint stops and its key is deleted after it.
   */
  async closeLane(roomId: string, laneId: string): Promise<{ seq: number }> {
    await this.ready();
    const l = this.ownedRoom(roomId).host.state.auth.lanes[laneId];
    if (!l) throw new Error("Unknown lane");
    if (l.status === "closed") throw new Error("The lane is already closed");
    return this.reducing(roomId, () => ({ seq: this.adminSubmit(roomId, "lane.closed", { laneId }).receipt.entry.seq }));
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

  /** Signs (the caller took the confirmation token, or the action is policy-automatic) and submits through the endpoint. */
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
          label: (laneId) => laneHostLabel({ verifiedName: this.bookIfOpen(roomId)?.room?.name ?? null, roomId }, laneId),
          record: (laneId, registrationId) => j.registration(laneId, registrationId),
          done: () => j.registered(),
          skip: (laneId: string) => {
            const c = this.joined.get(roomId)?.client;
            return !!c && c.head.seq >= 0 && laneLost(c.state, j.e.memberId!, laneId) !== null;
          },
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
    await hosts.update(registrationId, { connection: g.connection, label: laneHostLabel({ verifiedName: this.bookIfOpen(roomId)?.room?.name ?? null, roomId }, laneId), metadata, enabled: true });
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

  // ------------------------------------------------------------------------------ member: rekey (I-12)

  /**
   * Keys 4.1 steps 1 and 2 on a joined device: the next keys are sealed in the journal, then
   * `device.rekeyed` (signed by the current key) is submitted over the session, then `rekey`
   * KeyPackages under the new credential are published. The old keys stay in use until the approval
   * is in the log; `followRotation` then switches.
   */
  async requestRekey(roomId: string): Promise<{ ref: string; seq: number }> {
    const kek = await this.ready();
    const j = this.joining.get(roomId)?.journal;
    const joined = this.joined.get(roomId);
    if (!j || !(j.state === "admitted" || j.state === "registered") || !joined) throw new Error("Only a device that joined this room can request its own rekey here");
    const c = joined.client;
    if (c.status !== "open") throw new Error("The room is not connected");
    if (j.rekey?.ref && rekeyStatus(c.state, joined.memberId, joined.deviceId, j.rekey) === "pending") throw new Error("A rekey of this device is already waiting");
    const me = c.state.members[joined.memberId]?.devices.find((d) => d.deviceId === joined.deviceId);
    if (!me) throw new Error("This device is not in the roster");
    j.abandonRekey();
    const sigSeed = randomBytes(32);
    const dhSecret = randomBytes(32);
    try {
      j.beginRekey({ sigSeed, dhSecret });
    } finally {
      sigSeed.fill(0);
      dhSecret.fill(0);
    }
    const next = j.rekey!;
    const keys = j.rekeyKeys();
    keys.dhSecret.fill(0);
    let req: ReturnType<typeof rekeyRequest>;
    try {
      req = rekeyRequest({ roomId, deviceId: joined.deviceId, currentSig: me.sig, currentKey: this.sigKeyFor(kek, roomId), next: { sigSeed: keys.sigSeed, sig: next.sig, dh: next.dh }, base: c.head, ts: Date.now() });
    } finally {
      keys.sigSeed.fill(0);
    }
    let seq: number;
    try {
      const reply = await c.request({ t: "stmt.submit", statement: req.statement });
      seq = Number((reply.receipt as { entry?: { seq?: number } } | undefined)?.entry?.seq ?? -1);
    } catch (e) {
      j.abandonRekey();
      throw new Error(`device.rekeyed refused: ${(e as { code?: string }).code ?? "error"}`);
    }
    j.rekeyRequested(req.ref);
    log("device_rekey_requested", { roomId, deviceId: joined.deviceId, seq });
    await this.publishRekey(roomId).catch(() => undefined);
    return { ref: req.ref, seq };
  }

  /** Keys 4.1 step 7: `rekey` KeyPackages under the next credential (retried by `followRotation`). */
  private async publishRekey(roomId: string): Promise<void> {
    const j = this.joining.get(roomId)?.journal;
    const mls = this.mlsMembers.get(roomId);
    if (!j?.rekey?.ref || !mls || this.rekeyPublished.has(roomId)) return;
    const { sigSeed, dhSecret } = j.rekeyKeys();
    dhSecret.fill(0);
    const sigKey = ed25519PrivateKeyFromSeed(sigSeed);
    sigSeed.fill(0);
    try {
      await mls.prepareRekey({ sigPub: j.rekey.sig, sigKey });
      this.rekeyPublished.add(roomId);
    } catch (e) {
      log("device_rekey_publish_failed", { roomId, code: (e as { code?: string }).code ?? "error" });
      throw e;
    }
  }

  /**
   * Every second for each joined room: a rekey approved in the log switches the journal to the new
   * keys and reconnects (the host closes the old session with `superseded`); a vetoed or cancelled
   * one is dropped; a session closed with `superseded` or `moved` is reopened (2 s apart at most).
   */
  private followRotation(roomId: string): void {
    if (this.stopping) return;
    const joined = this.joined.get(roomId);
    const j = this.joining.get(roomId)?.journal;
    if (!joined || !j || this.owned.has(roomId)) return;
    const c = joined.client;
    const r = j.rekey;
    if (r && c.head.seq >= 0) {
      const st = rekeyStatus(c.state, joined.memberId, joined.deviceId, r);
      if (st === "approved") {
        this.finishRekey(roomId);
        return;
      }
      if (st === "ended") {
        j.abandonRekey();
        this.mlsMembers.get(roomId)?.cancelRekey();
        this.rekeyPublished.delete(roomId);
        log("device_rekey_ended", { roomId, deviceId: joined.deviceId });
      } else if (st === "pending" && c.status === "open" && !this.rekeyPublished.has(roomId)) void this.publishRekey(roomId).catch(() => undefined);
    }
    if (c.status === "closed" && (c.lastError === "superseded" || c.lastError === "moved") && (this.reconnectAt.get(roomId) ?? 0) <= Date.now()) {
      this.reconnectAt.set(roomId, Date.now() + 2000);
      void this.connect(roomId).catch((e) => logError("v2_reconnect_failed", e, { roomId }));
    }
  }

  /** The approval is in the log: new keys in the journal, old ones deleted, new session, new grants. */
  private finishRekey(roomId: string): void {
    const j = this.joining.get(roomId)?.journal;
    if (!j?.rekey) return;
    j.completeRekey();
    this.rekeyPublished.delete(roomId);
    this.linkers.delete(roomId);
    log("device_rekey_completed", { roomId });
    this.reconnectAt.set(roomId, Date.now() + 2000);
    void this.connect(roomId)
      .then(() => {
        // Keys 4.1 step 6: the old grants named the old key; ask for new ones.
        for (const sc of this.schedulers.get(roomId)?.values() ?? []) void sc.rotate("rekeyed");
      })
      .catch((e) => logError("v2_reconnect_after_rekey_failed", e, { roomId }));
  }

  /** Entries of a joined room's verified log that need action here (endpoint and lane offer rotations). */
  private onMemberEntry(roomId: string, signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): void {
    const t = signed.entry.type;
    if (t === "endpoint.rotated") {
      const e = after.auth.endpoint;
      try {
        this.joining.get(roomId)?.journal.setEndpoint({ serverId: e.serverId, dh: e.dh.pub, relay: { host: e.relay.host, port: e.relay.port } });
      } catch (err) {
        logError("v2_endpoint_save_failed", err, { roomId });
      }
      log("room_endpoint_rotated_seen", { roomId, seq: signed.entry.seq });
    }
    if (t === "lane.closed" || t === "member.lanes.changed") this.dropLostLanes(roomId, after);
    if (t === "lane.offer.rotated") {
      for (const [laneId, l] of Object.entries(after.auth.lanes)) {
        if (before.auth.lanes[laneId]?.offer.serverId === l.offer.serverId) continue;
        // Keys 4.7 step 3: new grants for the new offer, and hosts.update with the new connection.
        void this.schedulers.get(roomId)?.get(laneId)?.rotate("offer_rotated");
      }
    }
  }

  // ------------------------------------------------------------------------------ member: sessions

  /** Member side: opens (or reopens) the room session with the device key from the journal. */
  async connect(roomId: string, opts: { nextKeys?: boolean; moved?: SignedEntry; depth?: number } = {}): Promise<{ status: RoomClient["status"]; lastError: string | null }> {
    const kek = await this.ready();
    const prev = this.joined.get(roomId)?.client;
    prev?.close();
    const keys = this.deviceFor(kek, roomId, opts.nextKeys === true);
    const v = verifyGenesis(keys.genesis);
    const mls = this.memberMlsFor(kek, roomId, v.genesisHash, keys.memberId, keys.deviceId);
    const j = this.owned.has(roomId) ? undefined : this.joining.get(roomId)?.journal;
    // Keys 4.6: the last endpoint this device verified, when the room endpoint has rotated.
    const ep = j?.endpoint;
    const useEp = ep && ep.serverId !== v.genesis.body.endpoint.serverId ? ep : null;
    const client = new RoomClient({
      genesis: keys.genesis,
      device: keys.device,
      relay: useEp ? memberRelayAddress(useEp.relay, this.env) : keys.relay(v.genesis),
      ...(useEp ? { endpoint: { serverId: useEp.serverId, dh: { pub: useEp.dh } } } : {}),
      timings: this.tuning.timings,
      onPush: (f) => this.onSessionPush(roomId, f),
      // Enrollment 5.7 (round 9, item 3): what the host showed before admission must be in the log;
      // so must the `endpoint.rotated` a moved endpoint showed (keys 4.6).
      anchors: [...(j?.preAdmissionAnchors() ?? []), ...(opts.moved ? [{ source: "moved", signed: opts.moved }] : [])],
      // Room-log 8.2 (R2.1): the verified copy, maxSignedHead, receipts and stopping alerts at rest.
      store: new SealedLogCopy({ dataDir: this.dataDir, kek, roomId, genesisHash: v.genesisHash }),
      onIngest: (s, b, a) => {
        if (mls && !this.owned.has(roomId)) mls.ingest(s, b, a);
        if (!this.owned.has(roomId)) this.feedOf(roomId).push(s, b, a);
        this.onMemberEntry(roomId, s, b, a);
      },
    });
    this.joined.set(roomId, { client, memberId: keys.memberId, deviceId: keys.deviceId });
    if (opts.nextKeys) this.linkers.delete(roomId);
    this.linkerFor(kek, roomId, v.genesisHash, keys.memberId, keys.deviceId, client);
    try {
      const hello = await client.connect();
      // Keys 4.1: a session with the next keys is open, so the approval is in the log.
      if (opts.nextKeys && j?.rekey) {
        j.completeRekey();
        this.rekeyPublished.delete(roomId);
        this.linkers.delete(roomId);
        this.linkerFor(kek, roomId, v.genesisHash, keys.memberId, keys.deviceId, client);
        log("device_rekey_completed", { roomId, via: "reconnect" });
        for (const sc of this.schedulers.get(roomId)?.values() ?? []) void sc.rotate("rekeyed");
      }
      if (mls && !this.owned.has(roomId)) {
        const la = hello.lastAck as { seq?: unknown; epoch?: unknown } | null;
        mls.checkRollback(la && Number.isSafeInteger(la.seq) && Number.isSafeInteger(la.epoch) ? { seq: la.seq as number, epoch: la.epoch as number } : null);
        void mls.maintain().catch(() => undefined);
      }
      const m = client.state.members[keys.memberId];
      if (!m?.devices.some((d) => d.deviceId === keys.deviceId)) log("v2_admission_not_in_log", { roomId, memberId: keys.memberId });
    } catch (e) {
      const code = (e as { code?: string }).code ?? "error";
      log("v2_connect_failed", { roomId, code });
      const depth = opts.depth ?? 0;
      // Keys 4.1: the old DH key is unknown once the approval is logged; try the next keys.
      if (code === "not_authorized" && !opts.nextKeys && j?.rekey?.ref && depth < 2) return this.connect(roomId, { ...opts, nextKeys: true, depth: depth + 1 });
      // Keys 4.6 step 4: a replaced endpoint answered `moved`; go to the endpoint it names.
      if (code === "moved" && j && depth < 2) {
        const target = movedTarget(client.lastErrorFields, roomId, prev && prev.head.seq >= 0 ? prev.state : client.state);
        if (target) {
          j.setEndpoint(target.endpoint);
          log("room_moved", { roomId, hsigChecked: target.hsigChecked });
          return this.connect(roomId, { ...opts, moved: target.anchor, depth: depth + 1 });
        }
        log("room_moved_unusable", { roomId });
      }
    }
    if (client.status === "open" && j) {
      const e = client.state.auth.endpoint;
      if (e.serverId !== v.genesis.body.endpoint.serverId || j.endpoint) j.setEndpoint({ serverId: e.serverId, dh: e.dh.pub, relay: { host: e.relay.host, port: e.relay.port } });
    }
    if (client.status === "ended" && this.schedulers.has(roomId)) void this.stopLanes(roomId);
    return { status: client.status, lastError: client.lastError };
  }

  /**
   * Access ended (or the member leaves): stop rotating and remove our lane registrations (their grants
   * no longer work). What cannot be removed now goes to the stale-host list (R3.7).
   */
  private stopLanes(roomId: string, reason: StaleHost["reason"] = "access_ended"): Promise<{ removed: number; remaining: StaleHost[] }> {
    for (const sc of this.schedulers.get(roomId)?.values() ?? []) sc.stop();
    this.schedulers.delete(roomId);
    this.registrars.get(roomId)?.stop();
    const regs = this.joining.get(roomId)?.journal.e.registrations ?? {};
    return this.removeLaneHosts(roomId, Object.entries(regs).map(([laneId, registrationId]) => ({ laneId, registrationId })), reason);
  }

  // ------------------------------------------------------------------------------ member: leaving and lane hosts (R3.1, R3.7)

  /**
   * R3.7: the verified log closed a lane or removed it from this member's lanes. Its grant schedule
   * stops, the registrar forgets it, and its host entry is removed (or kept as stale and shown).
   */
  private dropLostLanes(roomId: string, st: Readonly<RoomState>): void {
    const joined = this.joined.get(roomId);
    const j = this.joining.get(roomId)?.journal;
    if (!joined || !j || this.owned.has(roomId) || !st.members[joined.memberId]) return;
    const byLane = this.schedulers.get(roomId);
    const laneIds = new Set([...Object.keys(j.e.registrations), ...(byLane?.keys() ?? [])]);
    for (const laneId of laneIds) {
      const reason = laneLost(st, joined.memberId, laneId);
      if (!reason) continue;
      byLane?.get(laneId)?.stop();
      byLane?.delete(laneId);
      this.registrars.get(roomId)?.drop(laneId);
      const registrationId = j.e.registrations[laneId];
      if (!registrationId) continue;
      try {
        j.dropRegistration(laneId);
      } catch (e) {
        logError("lane_registration_drop_failed", e, { roomId, laneId });
      }
      void this.removeLaneHosts(roomId, [{ laneId, registrationId }], reason);
    }
  }

  private hostsRemover(): HostsRemover | null {
    const h = this.paseo?.hosts as unknown as Partial<HostsRemover> | undefined;
    return h && typeof h.remove === "function" ? (h as HostsRemover) : null;
  }

  /** Removes lane host registrations through Paseo; failures (or no PaseoApi yet) are kept as stale. */
  private async removeLaneHosts(roomId: string, regs: { laneId: string; registrationId: string }[], reason: StaleHost["reason"]): Promise<{ removed: number; remaining: StaleHost[] }> {
    if (regs.length === 0) return { removed: 0, remaining: [] };
    const since = Date.now();
    const entries = regs.map((r) => ({ roomId, laneId: r.laneId, registrationId: r.registrationId, label: laneHostLabel({ verifiedName: null, roomId }, r.laneId), reason, since, lastError: null }));
    const r = await removeHosts(this.hostsRemover(), entries);
    for (const id of r.removed) this.registrations.delete(id);
    if (reason !== "data_deleted") this.updateStale(r.removed, r.remaining);
    log("lane_hosts_removed", { roomId, reason, removed: r.removed.length, remaining: r.remaining.length, error: r.remaining[0]?.lastError ?? null });
    return { removed: r.removed.length, remaining: r.remaining };
  }

  /** member/stale-hosts.json: drop the removed ids, add (or refresh) the remaining entries. */
  private updateStale(removed: readonly string[], add: readonly StaleHost[]): void {
    try {
      const before = readStaleHosts(this.dataDir);
      const next = mergeStale(before.filter((h) => !removed.includes(h.registrationId)), add);
      if (add.length > 0 || next.length !== before.length) writeStaleHosts(this.dataDir, next, this.protection);
    } catch (e) {
      logError("stale_hosts_save_failed", e);
    }
  }

  /** R3.7 "Retry": removes the stale lane hosts now. */
  async cleanUpStaleHosts(): Promise<{ removed: number; remaining: StaleHost[] }> {
    await this.ready();
    const cur = readStaleHosts(this.dataDir);
    if (cur.length === 0) return { removed: 0, remaining: [] };
    const r = await removeHosts(this.hostsRemover(), cur);
    this.updateStale(r.removed, r.remaining);
    return { removed: r.removed.length, remaining: readStaleHosts(this.dataDir) };
  }

  /** Every 30 s at most, while a PaseoApi is attached and stale entries exist. */
  private retryStaleHosts(): void {
    if (this.stopping || this.state !== "ready" || !this.paseo || this.staleBusy || Date.now() < this.staleRetryAt) return;
    this.staleRetryAt = Date.now() + 30_000;
    if (readStaleHosts(this.dataDir).length === 0) return;
    this.staleBusy = true;
    void this.cleanUpStaleHosts()
      .catch((e) => logError("stale_hosts_retry_failed", e))
      .finally(() => {
        this.staleBusy = false;
      });
  }

  /**
   * R3.1: leaves a joined room. The member's only active device signs `member.left`; one of several
   * signs `device.removed {reason: "self"}` (room-log-v2 4.3: a device removes only itself, and the
   * last device leaves with member.left). A room whose access already ended, or a join that never
   * completed, is forgotten here only. Then lane hosts are removed and the room's member data deleted.
   */
  async leaveRoom(roomId: string): Promise<{ statement: "member.left" | "device.removed" | null; seq: number | null; hostsRemoved: number; hostsRemaining: StaleHost[] }> {
    await this.ready();
    if (this.owned.has(roomId)) throw new Error("This daemon hosts that room. The host cannot leave its own room.");
    const e = this.joining.get(roomId);
    if (!this.joined.has(roomId) && !e) throw new Error("This daemon is not a member of that room");
    let statement: "member.left" | "device.removed" | null = null;
    let seq: number | null = null;
    const admitted = e ? e.journal.state === "admitted" || e.journal.state === "registered" : true;
    if (!admitted) {
      // A join in progress: cancel it (the host closes the attempt); nothing was admitted.
      if (e!.journal.state !== "failed") await e!.cancel().catch((err) => logError("join_cancel_failed", err, { roomId }));
    } else if (this.joined.get(roomId)?.client.status !== "ended") {
      if (this.joined.get(roomId)?.client.status !== "open") await this.connect(roomId).catch(() => undefined);
      const j = this.joined.get(roomId);
      const c = j?.client;
      if (!j || !c || (c.status !== "open" && c.status !== "ended")) throw new Error("The room cannot be reached right now. Nothing was changed. Reconnect and try again.");
      if (c.status === "open") {
        const me = c.state.members[j.memberId];
        if (!me?.devices.some((d) => d.deviceId === j.deviceId)) throw new Error("This device is not in the room's member list yet. Try again after the room has synced.");
        statement = me.devices.length === 1 ? "member.left" : "device.removed";
        try {
          const linker = this.linkerOf(roomId);
          seq = (statement === "member.left" ? await linker.submitOwn("member.left", { memberId: j.memberId }) : await linker.submitOwn("device.removed", { memberId: j.memberId, deviceId: j.deviceId, reason: "self" })).seq;
        } catch (err) {
          throw new Error(`${statement} refused: ${(err as { code?: string }).code ?? "error"}. Nothing was changed.`);
        }
      }
    }
    const hosts = await this.forgetRoom(roomId, statement ? "left" : "access_ended");
    log("room_left", { roomId, statement, seq, hostsRemoved: hosts.removed, hostsRemaining: hosts.remaining.length });
    return { statement, seq, hostsRemoved: hosts.removed, hostsRemaining: hosts.remaining };
  }

  /** Local teardown of a joined room: lanes, session, MLS member, linker, journal and member/rooms/<roomId>. */
  private async forgetRoom(roomId: string, reason: StaleHost["reason"]): Promise<{ removed: number; remaining: StaleHost[] }> {
    const hosts = await this.stopLanes(roomId, reason);
    this.registrars.delete(roomId);
    this.joined.get(roomId)?.client.close();
    this.joined.delete(roomId);
    const mls = this.mlsMembers.get(roomId);
    if (mls && !this.owned.has(roomId)) {
      mls.stop();
      this.mlsMembers.delete(roomId);
      this.chats.delete(roomId);
      await Promise.race([mls.idle().catch(() => undefined), new Promise<void>((r) => (setTimeout(r, 2000) as { unref?: () => void }).unref?.())]);
    }
    this.linkers.delete(roomId);
    this.joining.get(roomId)?.close();
    this.joining.delete(roomId);
    this.rekeyPublished.delete(roomId);
    this.reconnectAt.delete(roomId);
    for (const k of [...this.authRetryAt.keys()]) if (k.startsWith(`${roomId} `)) this.authRetryAt.delete(k);
    if (reason !== "data_deleted") fs.rmSync(memberRoomDir(this.dataDir, roomId), { recursive: true, force: true });
    return hosts;
  }

  /**
   * R2.6 with "Also delete hosted rooms": how this daemon can close a room it hosts before deleting it,
   * without asking for anything more (keys 6.8). `confirm_proposal`: an open `room.close.proposed` of
   * another lineage that this admin key may confirm now. `recovery_key`: one admin lineage and no
   * recovery key, so this admin adds a recovery key alone and closes with it (6.8, last bullet); the
   * key is used once and never shown or stored. `none`: the room has a recovery key (its code is
   * needed) or two lineages (a second admin is needed), or this daemon holds no admin key; the room
   * then stops without a closure and its members see it go offline.
   */
  closurePlanFor(roomId: string): HostedClosurePlan {
    const o = this.ownedRoom(roomId);
    const a = o.host.state.auth;
    if (a.closed) return { plan: "already_closed", reason: null, message: "The room is already closed." };
    if (!o.signer) return { plan: "none", reason: "no_admin_key", message: "This daemon holds no admin key for this room, so it cannot close it. Members will see it offline." };
    for (const [ref, p] of Object.entries(a.pendingClose)) {
      if (p.used) continue;
      if (!closeConfirmationBlocker(o.host.state, ref, o.signer.kid, this.clock.now(), o.holds?.firstSeen(ref))) return { plan: "confirm_proposal", reason: null, message: "This daemon confirms the open closure proposal of the other admin." };
    }
    if (a.recovery) return { plan: "none", reason: "recovery_code_required", message: "Closing this room needs its recovery code. Close it first (Keys, recovery code, Close room) or it stops without a closure and members see it offline." };
    if (lineageCount(a) > 1) return { plan: "none", reason: "second_admin_required", message: "Closing this room needs an admin of another lineage. Ask them to confirm a closure first, or it stops without a closure and members see it offline." };
    return { plan: "recovery_key", reason: null, message: "This daemon adds a one-time recovery key and signs the closure with it. Members see the room as closed." };
  }

  /** Signs the closure `closurePlanFor` allows. Never throws: the outcome is returned and logged. */
  private closeHostedForDeletion(roomId: string): HostedClosure {
    const plan = this.closurePlanFor(roomId);
    const o = this.ownedRoom(roomId);
    let out: HostedClosure;
    try {
      if (plan.plan === "confirm_proposal") {
        const ref = Object.entries(o.host.state.auth.pendingClose).find(([r, p]) => !p.used && !closeConfirmationBlocker(o.host.state, r, o.signer!.kid, this.clock.now(), o.holds?.firstSeen(r)))![0];
        const seq = this.reducing(roomId, () => this.adminSubmit(roomId, "room.closed", { proposal: ref }).receipt.entry.seq);
        out = { roomId, outcome: "closed", via: "confirmed_proposal", seq, reason: null, message: "Closed by confirming the other admin's proposal." };
      } else if (plan.plan === "recovery_key") {
        const k = newRecoveryKey(roomId);
        this.reducing(roomId, () => this.adminSubmit(roomId, "recovery.key.rotated", { change: k.change, newKeySig: k.newKeySig, proposal: null }));
        const r = RecoveryKey.fromCode(k.code, o.host.state, this.clock.now);
        try {
          const res = this.reducing(roomId, () => o.endpoint.submit(r.sign("room.closed", { proposal: null }, o.host.head)));
          if (!res.ok) throw new Error(`room.closed refused: ${res.code} (${res.reason})`);
          out = { roomId, outcome: "closed", via: "recovery_key", seq: res.receipt.entry.seq, reason: null, message: "Closed with a one-time recovery key." };
        } finally {
          r.dispose();
        }
      } else {
        out = { roomId, outcome: plan.plan === "already_closed" ? "already_closed" : "not_closed", via: null, seq: null, reason: plan.reason, message: plan.message };
      }
    } catch (e) {
      out = { roomId, outcome: "not_closed", via: null, seq: null, reason: "error", message: `The closure failed: ${String((e as Error)?.message ?? e).slice(0, 200)}. The room stops without a closure.` };
    }
    log("hosted_room_closure_for_deletion", { roomId, outcome: out.outcome, via: out.via, seq: out.seq, reason: out.reason });
    return out;
  }

  /** Waits (at most `ms`) until the hosted rooms have no live session, so access_ended reaches members. */
  private async drainSessions(roomIds: string[], ms = 3000): Promise<void> {
    const t0 = Date.now();
    while (Date.now() - t0 < ms && roomIds.some((id) => (this.owned.get(id)?.endpoint.sessions().length ?? 0) > 0)) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 200));
  }

  /**
   * R2.6 "Leave all rooms and delete keys" (the user's typed confirmation): leaves every joined room
   * (a room that cannot be reached is forgotten here; its owner still lists the member), removes every
   * lane host this plugin registered, stops the runtime, deletes the KEK through the KeyStore and the
   * plugin-data/rooms folder. Rooms this daemon hosts stop for good: refused unless `deleteHosted`.
   */
  async deleteAllData(i: { deleteHosted: boolean }): Promise<{
    left: { roomId: string; statement: "member.left" | "device.removed" | null; error: string | null }[];
    hostedDeleted: string[];
    hostedClosed: HostedClosure[];
    hostsRemoved: number;
    hostsRemaining: StaleHost[];
    keystore: KeyStoreDeletion;
    dataDeleted: boolean;
  }> {
    await this.requireVerifiedTree();
    const hosted = [...this.owned.keys()];
    if (hosted.length && !i.deleteHosted) throw new Error(`This daemon hosts ${hosted.length} room(s). Deleting the keys stops them for good and their members lose access. Confirm deleting hosted rooms too.`);
    // Hosted rooms are closed first where this daemon may (keys 6.8): connected members get
    // access_ended room_closed and see the room closed, not just offline.
    const hostedClosed = hosted.map((roomId) => this.closeHostedForDeletion(roomId));
    if (hostedClosed.some((c) => c.outcome === "closed")) await this.drainSessions(hosted);
    const left: { roomId: string; statement: "member.left" | "device.removed" | null; error: string | null }[] = [];
    let hostsRemoved = 0;
    for (const roomId of new Set([...this.joining.keys(), ...this.joined.keys()])) {
      if (this.owned.has(roomId)) continue;
      try {
        const r = await this.leaveRoom(roomId);
        left.push({ roomId, statement: r.statement, error: null });
        hostsRemoved += r.hostsRemoved;
      } catch (e) {
        const r = await this.forgetRoom(roomId, "data_deleted");
        hostsRemoved += r.removed;
        left.push({ roomId, statement: null, error: String((e as Error)?.message ?? e).slice(0, 200) });
      }
    }
    // Every lane host of this plugin, including stale ones and ones no journal knows any more.
    let todo: StaleHost[] = readStaleHosts(this.dataDir).map((h) => ({ ...h, reason: "data_deleted" as const }));
    const api = this.paseo?.hosts as unknown as Partial<HostsApi> | undefined;
    if (api?.list) {
      try {
        const dir = await api.list();
        for (const h of dir.hosts) {
          if (h.source?.id !== `plugin:${PLUGIN_ID}` || todo.some((x) => x.registrationId === h.registrationId)) continue;
          const laneId = String(h.source.key ?? "");
          todo.push({ roomId: "", laneId, registrationId: h.registrationId, label: laneId ? `Lane ${laneId.slice(5, 13)}` : "Rooms lane", reason: "data_deleted", since: Date.now(), lastError: null });
        }
      } catch (e) {
        logError("hosts_list_failed", e);
      }
    }
    const r = await removeHosts(this.hostsRemover(), todo);
    hostsRemoved += r.removed.length;
    todo = r.remaining;
    await this.stop();
    const keystore = await deleteKeyStore(this.keystoreOpts ?? { dataDir: this.dataDir, paseoHome: this.paseoHome, env: this.env, log, native: () => ({ ok: false as const, reason: "not_probed", detail: "keystore was not opened" }) });
    let dataDeleted = false;
    try {
      fs.rmSync(this.dataDir, { recursive: true, force: true });
      dataDeleted = true;
    } catch (e) {
      logError("data_delete_failed", e);
    }
    for (const m of [this.owned, this.joined, this.joining, this.registrars, this.schedulers, this.registrations, this.linkers, this.mlsMembers] as Map<string, unknown>[]) m.clear();
    this.kek = null;
    this.keystore = null;
    this.migration = null;
    this.state = "error";
    this.error = "data_deleted";
    log("rooms_data_deleted", { left: left.length, hosted: hosted.length, hostedClosed: hostedClosed.filter((c) => c.outcome === "closed").length, hostsRemoved, hostsRemaining: todo.length, kek: keystore.kek, dataDeleted });
    return { left, hostedDeleted: hosted, hostedClosed, hostsRemoved, hostsRemaining: todo, keystore, dataDeleted };
  }

  private deviceFor(kek: Kek, roomId: string, nextKeys = false): { genesis: RoomGenesis | Uint8Array; device: { publicKey: Uint8Array; secretKey: Uint8Array }; memberId: string; deviceId: string; relay(g: RoomGenesis): RelayAddress } {
    const j = this.joining.get(roomId)?.journal;
    if (j && (j.state === "admitted" || j.state === "registered") && j.e.genesis) {
      const { sigSeed, dhSecret } = nextKeys && j.rekey ? j.rekeyKeys() : j.deviceKeys();
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
    this.compat.stop();
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
      for (const m of o.moved) m.stop();
      o.host.close();
    }
    this.kek?.dispose();
    log("v2_runtime_stopped", {});
  }
}

/** R3.7: why a member's lane host has to go (closed, or no longer among the member's lanes), or null. */
export function laneLost(st: Readonly<RoomState>, memberId: string, laneId: string): "lane_closed" | "lane_removed" | null {
  if (st.auth.lanes[laneId]?.status === "closed") return "lane_closed";
  const m = st.members[memberId];
  return m && !m.lanes.includes(laneId) ? "lane_removed" : null;
}

function readMigrationSafe(dataDir: string): MigrationRecord | null {
  try {
    return readMigration(dataDir);
  } catch {
    return null;
  }
}

/** Pending device requests in a fold state (optionally one member's), newest first, ids and times only. */
function deviceRequestsView(st: Readonly<RoomState>, memberId?: string, holds?: AdminHoldClock | null) {
  return Object.entries(st.pending)
    .filter(([, p]) => !memberId || p.memberId === memberId)
    .sort(([, a], [, b]) => b.seq - a.seq)
    .slice(0, 64)
    .map(([ref, p]) => ({ ref, kind: p.kind, memberId: p.memberId, deviceId: p.deviceId, requester: p.requester, seq: p.seq, hts: p.hts, sole: p.sole, young: p.young, status: p.status, effectiveAfter: holds ? holds.endsAt(st, ref, p) : autoApprovalEndsAt(st, p) }));
}

type RecoveryOfferView = { kid: string; code: string; file: { name: string; text: string } };
function offerView(r: RecoveryKeyOffer): RecoveryOfferView {
  return { kid: r.kid, code: r.code, file: { name: r.fileName, text: r.fileText } };
}

/** The owner's member list: roles, lanes, devices (ids only), the self-reported label from enrollment and the MLS display name (R3.3). */
function rosterView(st: Readonly<RoomState>, endpoint: RoomEndpoint, selfMemberId: string | null, book: RoomBook | null) {
  const online = new Set(endpoint.sessions().map((x) => x.deviceId));
  const pendings = endpoint.enrollment?.pendings() ?? [];
  const names = new Map((book?.names(Object.keys(st.members).sort()) ?? []).map((n) => [n.memberId, n]));
  return Object.values(st.members)
    .map((m) => ({
      memberId: m.memberId,
      role: m.role,
      lanes: [...m.lanes],
      label: m.memberId === selfMemberId ? null : (pendings.find((p) => p.memberId === m.memberId && p.label)?.label ?? null),
      displayName: names.get(m.memberId)?.name ?? null,
      nameCollision: names.get(m.memberId)?.collision ?? false,
      self: m.memberId === selfMemberId,
      devices: m.devices.map((d) => ({ deviceId: d.deviceId, kind: d.kind, since: st.deviceSince[d.deviceId] ?? null, connected: online.has(d.deviceId) })),
    }))
    .sort((a, b) => Number(b.self) - Number(a.self) || a.memberId.localeCompare(b.memberId));
}

function inviteView(i: InviteView) {
  return { inviteId: i.inviteId, inviteRef: i.inviteRef, role: i.role, lanes: i.lanes, note: i.note, exp: i.exp, state: i.state, failedProofs: i.failedProofs, abandoned: i.abandoned };
}

function pendingView(p: PendingView) {
  return { pendingId: p.pendingId, kind: p.kind, note: p.note, label: p.label, state: p.state, sas: p.sas, abandonedBefore: p.abandonedBefore, contested: p.contested, expiresAt: p.expiresAt, closedReason: p.closedReason, memberId: p.memberId, deviceId: p.deviceId };
}

function joinView(v: JoinView) {
  return { roomId: v.roomId, state: v.state, roomName: v.roomName, sas: v.sas, ownerFingerprints: v.ownerFingerprints, terms: v.terms, expiresAt: v.expiresAt, failure: v.failure, connection: v.connection, lastError: v.lastError };
}

/** Device ids in the roster of `after` that `before` did not have (admissions and approved adds). */
function newDeviceIds(before: Readonly<RoomState>, after: Readonly<RoomState>): string[] {
  const had = new Set<string>();
  for (const m of Object.values(before.members)) for (const d of m.devices) had.add(d.deviceId);
  const out: string[] = [];
  for (const m of Object.values(after.members)) for (const d of m.devices) if (!had.has(d.deviceId)) out.push(d.deviceId);
  return out;
}

/** The producer kid of a logged statement body, or null. */
function statementProducerKid(body: Uint8Array): string | null {
  try {
    const kid = (rjcsParse(body) as { body?: { producer?: { kid?: unknown } } }).body?.producer?.kid;
    return typeof kid === "string" ? kid : null;
  } catch {
    return null;
  }
}
