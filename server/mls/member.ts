// Member side of one MLS group of a room (mls-integration.md sections 4 to 6, 8, 9; room-log-v2.md 4.5,
// 6.5, 6.6; implementation plan I-13). One instance per device and group; the runtime runs the room group.
//
// Input is the member's verified room log: `ingest` gets every entry the room client's fold accepted,
// with the fold state before and after it, so each commit is judged against the roster before its own
// entry (4.2 step 2) without a second fold. MLS bodies come from the host with `msg.fetch` and must match
// the verified entry's `bodyHash`. Entries are processed in log order, one at a time, under one lock
// that also covers sending, committing and joining.
//
// - Commits (4.2): strict AAD; `roster` must be the roster before the entry; processed with the
//   reference roster set on the authentication service and the 4.3 checks in the IncomingMessageCallback
//   (sender read from the current tree); then roster equality again and the continuity check on the new
//   state. Any failure raises `roster_mismatch`, discards the new state and stops this group (9).
// - The device's own commit is not processed: its new state is adopted when the entry with its bodyHash
//   appears (set before `commit.submit` is sent, so the entry can never race the reply).
// - Joining (4.1, 2.3, 5.1): `welcome.fetch` returns the Welcome with its commit's signed entry; the
//   joiner processes the log up to that entry, uses the roster the commit named as the reference roster,
//   checks the authority extension and the tree against it, then the epoch anchors of later messages.
//   ts-mls 1.6.4 exposes neither the GroupInfo signer nor the sender of an application message through
//   its public API; the sender is derived from the secret tree (adapter.ts), and an epoch counts as
//   confirmed once decryptable messages with the joiner's anchor came from min(2, other leaves) other
//   leaves (5.1; decision round 9, item 4): with two or more other leaves at least one confirmer is not
//   the GroupInfo signer; in a group of two the only other leaf confirms alone.
// - Committing (4.2, 4.4, 6.3): a commit carries every pending removal (old-key leaves included) and the
//   pending adds it has a valid KeyPackage for. Removals are committed at once (`pending_remove`). The
//   admitting admin daemon adds a device it admitted at once (`promptAdd`, 4.4; decision round 9, item
//   5): when the admission is logged and again whenever that device publishes KeyPackages. Any other
//   pending add waits for the repair delay (60 s, plus up to 60 s at random for devices that are not
//   admins), which is only the fallback. Every
//   fetched KeyPackage is checked against the reference roster before use (6.4). The device runs the
//   4.2 checks on its own result before it submits.
// - Admin route (4.4): `approveRekey` fetches the device's `rekey` package, signs `device.rekey.approved`
//   through a callback, predicts roster `s`, builds Remove plus Add (with the other pending changes) and
//   submits both with `commit.submit {…, statement}`. The rekeyed device skips the commit at `s + 1` with
//   its old state and joins by Welcome.
// - Periodic leaf refresh (keys-rotation-recovery.md 4.2; I-12): every 7 days or 1 000 sent messages
//   the device commits an UpdatePath with the public `createCommit` (no Add, every pending removal),
//   credential unchanged; a refresh of the HPKE key only. `resumeRekey` restores the next device key of
//   a rekey requested before a restart (its `rekey` packages are already in the sealed record).
// - State at rest (8): the group state is sealed (MlsStore) before `msg.ack`; `checkRollback` refuses a
//   stored state older than the host's `lastAck` (8.4).
// - Chat (5.2; R3.4): `chat.message` carries a `ChatMessage` signed by the sender's device key, bound to
//   the group and epoch. It is accepted only when it names the leaf the message decrypted from and the
//   signature verifies with that leaf's `deviceSig`; otherwise it is dropped and `chat_attribution_failed`
//   is raised. Accepted messages go to `storeMessages` (the sealed chat store) before the state that
//   consumed them is written, and both before `msg.ack` (8.2): a crash in between re-delivers the
//   message, which the store drops by log position.
// Nothing here logs key material, messages or package bytes.
import type { KeyObject } from "node:crypto";
import { bodyHash, type SignedEntry } from "../authority/entries";
import type { RoomState } from "../authority/state";
import { log } from "../log";
import { b64u, b64uDecodeVar } from "../proto/b64u";
import { stmtContext, STMT_LOG_WITNESS } from "../proto/contexts";
import { rjcs } from "../proto/rjcs";
import { sign } from "../proto/tbs";
import { AUTHORITY_EXTENSION_TYPE, MLS_MESSAGE_MAX_BYTES, MLS_SUITE, type MlsAdapter, type MlsClientConfig, type MlsKeyPackage, type MlsPrivateKeyPackage, type MlsState } from "./adapter";
import { checkCredential, MlsAuthService, referenceRosterOf, type ReferenceRoster } from "./auth-service";
import { AppPayload, authorityExtension, checkChatMessage, encodeAad, epochAuth, mlsGroupId, parseAad, parseAppPayload, signChatMessage, signMlsIdentity, type MlsAad } from "./formats";
import { checkCommit, continuity, parseLeaves, pendingChanges, rosterEquality, type Leaf, type OpenRepair, type RuleRefusal } from "./roster-rule";

export type MlsAlertType =
  | "roster_mismatch"
  | "withholding"
  | "epoch_fork"
  | "epoch_anchor_mismatch"
  | "epoch_unconfirmed"
  | "leaf_replaced_unrequested"
  | "state_rollback"
  | "welcome_refused"
  | "host_fault"
  | "chat_attribution_failed";

export type MlsAlert = { type: MlsAlertType; seq: number; at: number; detail?: string; peer?: { memberId: string; deviceId: string } };
/**
 * A chat message whose signature and binding checked out (5.2). `hts`: the host time of its log entry;
 * `ts`: the sender's own clock (a claim).
 */
export type MlsMessage = { seq: number; epoch: number; hts: number; ts: number; from: { memberId: string; deviceId: string }; text: string };
/** A `room.profile` or `member.profile` (R3.3), with the sender's leaf and its role in the verified roster at delivery. */
export type MlsProfileEvent = { seq: number; epoch: number; from: { memberId: string; deviceId: string; role: string }; payload: Extract<AppPayload, { kind: "room.profile" | "member.profile" }> };

/** One room session's request channel (room-client.ts, or the owner's local endpoint). Rejects with `{code, fields}`. */
export interface MlsLink {
  request(frame: Record<string, unknown>, timeoutMs?: number): Promise<Record<string, unknown>>;
}

type KpRecord = { ref: string; pool: "current" | "rekey"; lastResort: boolean; sig: string; pub: string; priv: { init: string; hpke: string; sig: string }; at: number };
/** `needed`: confirming leaves required, min(2, other leaves) at the join (absent in older records: 2). */
type JoinRecord = { seq: number; epoch: number; at: number; anchor: string; confirmers: string[]; needed?: number; status: "pending" | "confirmed" | "unconfirmed" | "fork" };

/** Sealed per device and group (8.1). Holds private keys: never logged. */
export type MemberRecord = {
  v: 2;
  typ: "mls-member";
  roomId: string;
  deviceId: string;
  groupId: string;
  cursor: number;
  logHead: { seq: number; hash: string };
  state: string | null;
  join: JoinRecord | null;
  usedRepairs: string[];
  kps: KpRecord[];
  sent: string[];
  stalled: string | null;
  /** Last leaf refresh (4.2): when, and messages sent since. Absent in records written before I-12. */
  refresh?: { at: number; sent: number };
};

export interface MlsStore {
  read(): MemberRecord | null;
  write(r: MemberRecord): void;
}

export class MemoryMlsStore implements MlsStore {
  record: MemberRecord | null = null;
  read(): MemberRecord | null {
    return this.record ? structuredClone(this.record) : null;
  }
  write(r: MemberRecord): void {
    this.record = structuredClone(r);
  }
}

export type MlsTimings = {
  /** Repair rule (4.4): pending adds older than this are committed. */
  repairDelayMs: number;
  /** Extra random delay for devices that are not admins (4.4). */
  repairJitterMs: number;
  /** `log.witness` after a commit with an Add: random delay up to this (5.1). */
  witnessMaxDelayMs: number;
  /** Joiner check timeout (5.1). */
  epochConfirmMs: number;
  /** Retry of fetches and publications. */
  retryMs: number;
  /** Periodic leaf refresh (keys 4.2): an UpdatePath after this long, or after `refreshMessages` sent. */
  refreshMs: number;
  refreshMessages: number;
};
export const MLS_TIMINGS: Readonly<MlsTimings> = { repairDelayMs: 60_000, repairJitterMs: 60_000, witnessMaxDelayMs: 30_000, epochConfirmMs: 5 * 60_000, retryMs: 60_000, refreshMs: 7 * 24 * 3600 * 1000, refreshMessages: 1000 };

export interface MlsMemberOptions {
  adapter: MlsAdapter;
  roomId: string;
  genesisHash: string;
  memberId: string;
  deviceId: string;
  /** The device signing key (vouches for the leaf key, section 3). */
  device: { sigPub: string; sigKey: KeyObject };
  store: MlsStore;
  link: () => MlsLink | null;
  /** The creator's first device creates the room group (2.1). */
  creator?: boolean;
  scope?: string | null;
  now?: () => number;
  random?: () => number;
  timings?: Partial<MlsTimings>;
  /** Room-level stop (fork, truncation, invalid entry): no application messages (room-log-v2 6.6). */
  blocked?: () => boolean;
  /** Admin-signed `device.rekey.approved` for the admin route (4.4); only on an admin daemon. */
  onAlert?(a: MlsAlert): void;
  onMessage?(m: MlsMessage): void;
  /**
   * Persists the chat messages one entry delivered, before the state that consumed them is written and
   * before the ack (8.2; R3.4). Must be idempotent by `seq` and throw when it could not write.
   */
  storeMessages?(m: MlsMessage[]): void;
  /** Profile payloads of other devices, once the state that consumed them is written (R3.3). */
  onProfile?(e: MlsProfileEvent): void;
  /**
   * Payloads to re-announce in the group after a commit with an Add and after this device joins
   * (R3.3): a joiner cannot read messages from before its epoch. Asked at send time.
   */
  announce?(): AppPayload[];
}

type Queued = { signed: SignedEntry; before: Readonly<RoomState>; after: Readonly<RoomState> };

export class MlsMemberError extends Error {
  constructor(
    readonly code: "no_group" | "not_ready" | "blocked" | "unconfirmed" | "stalled" | "no_session" | "refused" | "no_key_package",
    message: string,
  ) {
    super(message);
    this.name = "MlsMemberError";
  }
}

const SENT_MAX = 256;
const KP_KEEP = 32;
const LAST_RESORT_KEEP_MS = 7 * 24 * 3600 * 1000;
const KP_LIFETIME_S = 30 * 24 * 3600 - 600;
// Back-dates notBefore so a receiver whose clock is behind ours still accepts the package (ts-mls checks
// the lifetime against its own wall clock). Device clocks commonly differ by minutes.
const KP_SKEW_S = 3600;

export class MlsMember {
  readonly groupId: Uint8Array;
  readonly groupKey: string;
  readonly alerts: MlsAlert[] = [];
  readonly messages: MlsMessage[] = [];
  /** Profile payloads received (newest 200), for tests and the runtime's names book. */
  readonly profiles: MlsProfileEvent[] = [];
  /** Settable after construction (tests); the runtime passes them as options. */
  onProfile: ((e: MlsProfileEvent) => void) | null;
  storeMessages: ((m: MlsMessage[]) => void) | null;
  announce: (() => AppPayload[]) | null;
  private rec: MemberRecord;
  private state: MlsState | null = null;
  private readonly auth = new MlsAuthService();
  private readonly config: MlsClientConfig;
  private readonly t: MlsTimings;
  private readonly queue: Queued[] = [];
  private latest: { state: Readonly<RoomState>; head: { seq: number; hash: string } } | null = null;
  private lock: Promise<unknown> = Promise.resolve();
  private bodies = new Map<number, Uint8Array>();
  private pendingOwn: { bodyHash: string; newState: MlsState; adds: number; refresh?: boolean } | null = null;
  private welcomeCache: { welcome: Uint8Array; entry: SignedEntry } | null = null;
  private expectCommitAt = -1;
  private addSeen = new Map<string, number>();
  /** Devices this admin daemon admitted, still pending adds (round 9, item 5). */
  private readonly promptEligible = new Set<string>();
  /** Eligible devices to try now: armed at admission and when the device publishes KeyPackages. */
  private readonly promptArmed = new Set<string>();
  private witnessAt: number | null = null;
  /** Profile re-announcement (R3.3): after a commit with an Add, and after this device joined. */
  private announceAt: number | null = null;
  private anchorsSeen = new Map<number, Set<string>>();
  private retryAt = 0;
  private refreshRetryAt = 0;
  private stopped = false;
  private disabled: string | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private pumpRun: Promise<void> | null = null;
  /** The head of the queue could not be processed (no body yet, or a failed write); retried by maintain. */
  private pumpStuck = false;
  private sawGroupCommit = false;
  private deliverAfterSave: MlsMessage[] = [];
  private profilesAfterSave: MlsProfileEvent[] = [];
  private device: { sigPub: string; sigKey: KeyObject };
  private nextDevice: { sigPub: string; sigKey: KeyObject } | null = null;
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly o: MlsMemberOptions) {
    this.t = { ...MLS_TIMINGS, ...o.timings };
    this.now = o.now ?? Date.now;
    this.random = o.random ?? Math.random;
    this.device = o.device;
    this.onProfile = o.onProfile ?? null;
    this.storeMessages = o.storeMessages ?? null;
    this.announce = o.announce ?? null;
    this.groupId = mlsGroupId(o.genesisHash, 0, o.scope ?? null);
    this.groupKey = b64u(this.groupId);
    this.config = o.adapter.config(this.auth);
    const stored = o.store.read();
    if (stored && (stored.roomId !== o.roomId || stored.deviceId !== o.deviceId || stored.groupId !== this.groupKey)) throw new Error("MLS state of another room, device or group");
    this.rec = stored ?? { v: 2, typ: "mls-member", roomId: o.roomId, deviceId: o.deviceId, groupId: this.groupKey, cursor: -1, logHead: { seq: -1, hash: o.genesisHash }, state: null, join: null, usedRepairs: [], kps: [], sent: [], stalled: null };
    if (this.rec.state) this.state = o.adapter.decodeState(b64uDecodeVar(this.rec.state, 8 * 1024 * 1024), this.config);
  }

  // ------------------------------------------------------------------------------ public

  /** Starts the maintenance timer (pending changes, witnesses, joiner timeout, KeyPackages). */
  start(tickMs = 1000): void {
    if (this.timer || this.stopped) return;
    this.timer = setInterval(() => void this.maintain().catch((e) => log("mls_maintain_failed", { roomId: this.o.roomId, error: String((e as Error)?.message ?? e).slice(0, 160) })), tickMs);
    (this.timer as { unref?: () => void }).unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Every entry the member's fold accepted, in order, with the fold state before and after it. */
  ingest(signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): void {
    this.latest = { state: after, head: { seq: signed.entry.seq, hash: signed.hash } };
    if (signed.entry.seq <= this.rec.cursor) return;
    this.queue.push({ signed, before, after });
    void this.pump();
  }

  /** Waits until every ingested entry is processed, or processing is stuck (tests and RPCs). */
  async idle(): Promise<void> {
    await this.pump();
    await this.locked(async () => undefined);
  }

  /** 8.4: a stored state older than the host's `lastAck` was restored or copied; it is not used. */
  checkRollback(lastAck: { seq: number; epoch: number } | null): boolean {
    if (!lastAck || lastAck.seq <= this.rec.cursor) return true;
    this.disable("state_rollback", lastAck.seq, `stored state at ${this.rec.cursor}, host acknowledged ${lastAck.seq}`);
    return false;
  }

  /** Pushes from the host (`pending_remove`, `kp.low`). */
  onPush(frame: Record<string, unknown>): boolean {
    if (frame.t === "pending_remove") {
      void this.maintain().catch(() => undefined);
      return true;
    }
    if (frame.t === "kp.low") {
      const pool = frame.for === "rekey" ? "rekey" : "current";
      if (pool === "current") void this.locked(() => this.publish("current", 2, true)).catch((e) => log("mls_kp_publish_failed", { roomId: this.o.roomId, code: (e as { code?: string }).code ?? "error", error: String((e as Error)?.message ?? e).slice(0, 120) }));
      return true;
    }
    return false;
  }

  get epoch(): number | null {
    return this.state ? this.o.adapter.epoch(this.state) : null;
  }

  get inGroup(): boolean {
    return !!this.state && this.o.adapter.isActive(this.state);
  }

  view() {
    const leaves = this.state ? (parseLeaves(this.o.adapter.leaves(this.state)) ?? []) : [];
    return {
      inGroup: this.inGroup,
      epoch: this.epoch,
      cursor: this.rec.cursor,
      leaves: leaves.map((l) => ({ memberId: l.memberId, deviceId: l.deviceId })),
      join: this.rec.join ? { seq: this.rec.join.seq, epoch: this.rec.join.epoch, status: this.rec.join.status, confirmers: this.rec.join.confirmers.length } : null,
      stalled: this.rec.stalled,
      disabled: this.disabled,
      canSend: this.canSendReason() === null,
      packages: { current: this.rec.kps.filter((k) => k.pool === "current" && !k.lastResort).length, lastResort: this.rec.kps.some((k) => k.pool === "current" && k.lastResort) },
    };
  }

  /** Why the device may not send now, or null (5.1, 6.3, 9; room-log-v2 6.6). */
  canSendReason(): string | null {
    if (this.disabled) return this.disabled;
    if (!this.state || !this.o.adapter.isActive(this.state)) return "no_group";
    if (this.rec.stalled) return "stalled";
    if (this.o.blocked?.()) return "blocked";
    const j = this.rec.join;
    if (j && (j.status === "pending" || j.status === "fork")) return j.status === "fork" ? "epoch_fork" : "unconfirmed";
    return null;
  }

  /**
   * Sends a signed `chat.message` (5.2): the device key of this device's own leaf signs the text bound
   * to the group and the current epoch. Pending removals are committed first (6.3). The device does not
   * process its own message, so the caller stores it with the returned `seq`.
   */
  async sendText(text: string): Promise<{ seq: number; epoch: number; ts: number; from: { memberId: string; deviceId: string } }> {
    await this.idle();
    await this.maintain({ removalsOnly: true });
    return this.locked(async () => {
      const why = this.canSendReason();
      if (why) throw new MlsMemberError(why === "no_group" ? "no_group" : why === "stalled" ? "stalled" : why === "unconfirmed" ? "unconfirmed" : "blocked", `cannot send: ${why}`);
      const own = this.currentLeaves().find((l) => l.leafIndex === this.o.adapter.ownLeafIndex(this.state!));
      const key = [this.device, this.nextDevice].find((d) => d && own && d.sigPub === own.deviceSig);
      if (!own || !key) throw new MlsMemberError("not_ready", "cannot send: this device's leaf does not hold its current key");
      const epoch = this.o.adapter.epoch(this.state!);
      const ts = this.now();
      const payload = signChatMessage({ v: 2, typ: "chat-message", roomId: this.o.roomId, groupId: this.groupKey, epoch, memberId: own.memberId, deviceId: own.deviceId, ts, text }, key.sigKey);
      const r = await this.sendPayload(rjcs(payload, 64 * 1024));
      return { seq: r.seq, epoch, ts, from: { memberId: own.memberId, deviceId: own.deviceId } };
    });
  }

  /**
   * Sends a `room.profile` or `member.profile` (R3.3), checked against the payload schema. The device
   * does not process its own message, so the caller applies it locally with the returned `seq`.
   */
  async sendProfile(p: Extract<AppPayload, { kind: "room.profile" | "member.profile" }>): Promise<{ seq: number }> {
    const parsed = AppPayload.safeParse(p);
    if (!parsed.success || (parsed.data.kind !== "room.profile" && parsed.data.kind !== "member.profile")) throw new MlsMemberError("refused", "not a profile payload");
    await this.idle();
    await this.maintain({ removalsOnly: true });
    return this.locked(async () => {
      const why = this.canSendReason();
      if (why) throw new MlsMemberError(why === "no_group" ? "no_group" : why === "stalled" ? "stalled" : why === "unconfirmed" ? "unconfirmed" : "blocked", `cannot send: ${why}`);
      return this.sendPayload(rjcs(parsed.data, 64 * 1024));
    });
  }

  /**
   * One maintenance pass: create the group (creator), publish KeyPackages, commit pending changes,
   * send a due witness, time out the joiner check. Safe to call often.
   */
  async maintain(opts: { removalsOnly?: boolean } = {}): Promise<void> {
    if (this.stopped || this.disabled) return;
    this.pumpStuck = false;
    await this.pump();
    await this.locked(async () => {
      if (this.queue.length > 0 || !this.latest) return;
      const st = this.latest.state;
      const me = st.members[this.o.memberId]?.devices.find((d) => d.deviceId === this.o.deviceId);
      if (!me) return;
      if (this.nextDevice && me.sig === this.nextDevice.sigPub) {
        this.device = this.nextDevice;
        this.nextDevice = null;
      }
      if (me.sig !== this.device.sigPub) return;
      if (!this.state && this.o.creator && this.rec.cursor >= 0 && !this.groupCommitted()) await this.createGroup();
      if (!opts.removalsOnly && this.now() >= this.retryAt) {
        try {
          await this.ensurePackages();
        } catch (e) {
          this.retryAt = this.now() + this.t.retryMs;
          log("mls_kp_publish_failed", { roomId: this.o.roomId, code: (e as { code?: string }).code ?? "error", error: String((e as Error)?.message ?? e).slice(0, 120) });
        }
      }
      if (this.state && this.o.adapter.isActive(this.state) && !this.rec.stalled) {
        await this.commitPending(opts.removalsOnly === true);
        if (!opts.removalsOnly) await this.dueWitness();
        if (!opts.removalsOnly) await this.dueAnnounce();
        if (!opts.removalsOnly) await this.dueRefresh();
      }
      this.checkJoinTimeout();
    });
  }

  /**
   * Prompt Add (4.4; decision round 9, item 5): this admin daemon just logged the admission of these
   * devices. Each is added to the group at the next maintenance pass, and again whenever it publishes
   * KeyPackages, until a commit adds it; the repair delay stays the fallback for everyone else.
   */
  promptAdd(deviceIds: readonly string[]): void {
    for (const id of deviceIds) {
      this.promptEligible.add(id);
      this.promptArmed.add(id);
    }
    if (deviceIds.length > 0) void this.maintain().catch(() => undefined);
  }

  /** The delivery service stored `current` KeyPackages of this device (the host side calls this). */
  packagesPublished(deviceId: string): void {
    if (!this.promptEligible.has(deviceId)) return;
    this.promptArmed.add(deviceId);
    void this.maintain().catch(() => undefined);
  }

  /** After a restart during a rekey's hold: the next device key again, without publishing (its packages are stored). */
  resumeRekey(next: { sigPub: string; sigKey: KeyObject }): void {
    if (next.sigPub !== this.device.sigPub) this.nextDevice = next;
  }

  /** The rekey was vetoed or cancelled: the next key is forgotten (its packages expire unused). */
  cancelRekey(): void {
    this.nextDevice = null;
  }

  /** True while a rekey of this device waits for its approval (its next key is known). */
  get rekeyPending(): boolean {
    return this.nextDevice !== null;
  }

  /** Prepares a rekey (keys-rotation-recovery 4.1 step 2): publishes `rekey` KeyPackages under the new key. */
  async prepareRekey(next: { sigPub: string; sigKey: KeyObject }): Promise<void> {
    this.nextDevice = next;
    await this.locked(() => this.publish("rekey", 2, true));
  }

  /**
   * Admin route (4.4) on an admin daemon that is a leaf of the room group. `signApproval(base)` signs
   * `device.rekey.approved` (mode "auto" after the hold, or "admin") with that base.
   */
  async approveRekey(ref: string, signApproval: (base: { seq: number; hash: string }) => unknown): Promise<{ statementSeq: number; seq: number }> {
    await this.idle();
    return this.locked(async () => {
      if (!this.state || !this.latest) throw new MlsMemberError("no_group", "not a leaf of the room group");
      const st = this.latest.state;
      const p = st.pending[ref];
      if (!p || p.kind !== "rekey" || p.status !== "pending") throw new MlsMemberError("refused", "no pending rekey with that ref");
      const link = this.requireLink();
      const head = this.latest.head;
      const s = head.seq + 1;
      // Roster s: the fold's apply of the approval (new keys for the device).
      const predicted = structuredClone(st) as RoomState;
      const m = predicted.members[p.memberId];
      const dev = m?.devices.find((d) => d.deviceId === p.deviceId);
      if (!dev) throw new MlsMemberError("refused", "device not in the roster");
      dev.sig = p.device.sig;
      dev.dh = p.device.dh;
      predicted.rosterSeq = s;
      const ref_ = referenceRosterOf(predicted, this.o.scope ?? null);
      // Step 1: the room group's rekey package; stop without it (no approval is signed).
      const kp = await this.fetchPackage(link, { memberId: p.memberId, deviceId: p.deviceId, for: "rekey" }, ref_);
      if (!kp) throw new MlsMemberError("no_key_package", "Waiting for the device to publish its new keys");
      const leaves = this.currentLeaves();
      const pend = pendingChanges(ref_, leaves);
      const adds: MlsKeyPackage[] = [kp];
      for (const a of pend.adds) {
        if (a.deviceId === p.deviceId) continue;
        const other = await this.fetchPackage(link, { memberId: a.memberId, deviceId: a.deviceId, for: "current" }, ref_);
        if (other) adds.push(other);
      }
      const removes = pend.removals.map((l) => l.leafIndex);
      const built = await this.buildCommit(ref_, head, adds, removes);
      const statement = signApproval(head);
      this.pendingOwn = { bodyHash: bodyHash(built.commit), newState: built.newState, adds: adds.length };
      try {
        const reply = await link.request({ t: "commit.submit", epoch: this.o.adapter.epoch(this.state), commit: b64u(built.commit), ...(built.welcome ? { welcome: b64u(built.welcome) } : {}), statement });
        return { statementSeq: Number(reply.statementSeq), seq: Number(reply.seq) };
      } catch (e) {
        this.pendingOwn = null;
        throw e;
      }
    });
  }

  // ------------------------------------------------------------------------------ processing

  /** Processes queued entries in order; concurrent callers share the run in flight. */
  private pump(): Promise<void> {
    if (this.pumpRun) return this.pumpRun;
    if (this.stopped) return Promise.resolve();
    this.pumpRun = this.pumpLoop().finally(() => {
      this.pumpRun = null;
      if (this.queue.length > 0 && !this.stopped && !this.disabled && !this.pumpStuck) void this.pump();
    });
    return this.pumpRun;
  }

  private async pumpLoop(): Promise<void> {
    this.pumpStuck = false;
    while (this.queue.length > 0 && !this.stopped && !this.disabled) {
      const q = this.queue[0];
      let done: boolean;
      try {
        done = await this.locked(() => this.process(q));
      } catch (e) {
        // A failed write (8.2): the entry stays queued and is processed again from the stored state.
        log("mls_process_failed", { roomId: this.o.roomId, seq: q.signed.entry.seq, error: String((e as Error)?.message ?? e).slice(0, 160) });
        this.reload();
        this.pumpStuck = true;
        return;
      }
      if (!done) {
        this.pumpStuck = true;
        return;
      }
      this.queue.shift();
    }
  }

  private async process(q: Queued): Promise<boolean> {
    const e = q.signed.entry;
    if (e.seq <= this.rec.cursor) return true;
    if (this.expectCommitAt === e.seq && e.type !== "mls.commit") this.raise("withholding", e.seq, "the entry after device.rekey.approved is not its commit");
    if (e.cls === "stmt") {
      if (e.type === "device.rekey.approved") this.expectCommitAt = e.seq + 1;
      this.rec.cursor = e.seq;
      this.rec.logHead = { seq: e.seq, hash: q.signed.hash };
      return true;
    }
    const body = await this.bodyFor(e.seq);
    if (!body) return false;
    if (bodyHash(body) !== e.bodyHash) {
      this.raise("host_fault", e.seq, "MLS body does not match its entry");
      return false;
    }
    let peek: ReturnType<MlsAdapter["peek"]>;
    try {
      peek = this.o.adapter.peek(body);
    } catch {
      return this.advance(q, false);
    }
    if (peek.wireformat !== "mls_private_message" || b64u(peek.groupId) !== this.groupKey) return this.advance(q, false);
    if (e.type === "mls.commit") this.sawGroupCommit = true;
    if (e.type === "mls.commit") await this.onCommit(q, body, peek);
    else await this.onApplication(q, body, peek);
    return this.advance(q, true);
  }

  /** Persists the record (state first, 8.2), then acknowledges MLS entries. */
  private async advance(q: Queued, mls: boolean): Promise<boolean> {
    this.rec.cursor = q.signed.entry.seq;
    this.rec.logHead = { seq: q.signed.entry.seq, hash: q.signed.hash };
    this.bodies.delete(q.signed.entry.seq);
    if (!mls) return true;
    try {
      // The chat store first, then the state (8.2): a crash between them re-delivers, never loses.
      if (this.deliverAfterSave.length > 0 && this.storeMessages) this.storeMessages(this.deliverAfterSave.map((m) => ({ ...m, from: { ...m.from } })));
      this.save();
    } catch (e) {
      this.deliverAfterSave = [];
      this.profilesAfterSave = [];
      throw e;
    }
    for (const m of this.deliverAfterSave.splice(0)) {
      this.messages.push(m);
      if (this.messages.length > 500) this.messages.shift();
      this.o.onMessage?.(m);
    }
    for (const p of this.profilesAfterSave.splice(0)) {
      this.profiles.push(p);
      if (this.profiles.length > 200) this.profiles.shift();
      try {
        this.onProfile?.(p);
      } catch (e) {
        log("mls_profile_hook_failed", { roomId: this.o.roomId, error: String((e as Error)?.message ?? e).slice(0, 120) });
      }
    }
    const link = this.o.link();
    if (link) await link.request({ t: "msg.ack", seq: q.signed.entry.seq, epoch: this.epoch ?? 0 }).catch(() => undefined);
    return true;
  }

  private async onCommit(q: Queued, body: Uint8Array, peek: Extract<ReturnType<MlsAdapter["peek"]>, { wireformat: "mls_private_message" }>): Promise<void> {
    const e = q.signed.entry;
    let aad: MlsAad;
    try {
      aad = parseAad(peek.authenticatedData);
    } catch {
      if (this.state) this.stall(e.seq, "bad authenticated data");
      return;
    }
    const ref = referenceRosterOf(q.before, this.o.scope ?? null);
    const rosterOk = aad.roster.seq === ref.seq && aad.roster.hash === ref.hash;
    // Own commit: adopt the state built for it (the device cannot process its own PrivateMessage).
    if (this.pendingOwn && this.pendingOwn.bodyHash === e.bodyHash) {
      if (!rosterOk) {
        this.pendingOwn = null;
        this.stall(e.seq, "own commit sequenced against another roster");
        return;
      }
      this.state = this.pendingOwn.newState;
      if (this.pendingOwn.refresh) this.rec.refresh = { at: this.now(), sent: 0 };
      // The committer holds the new epoch too and witnesses it like every other device (5.1).
      if (this.pendingOwn.adds > 0) this.witnessAt = this.now() + Math.floor(this.random() * this.t.witnessMaxDelayMs);
      if (this.pendingOwn.adds > 0) this.announceAt = this.now() + Math.floor(this.random() * this.t.witnessMaxDelayMs);
      this.pendingOwn = null;
      this.rec.stalled = null;
      return;
    }
    const myRosterDev = q.before.members[this.o.memberId]?.devices.find((d) => d.deviceId === this.o.deviceId);
    const myLeaf = this.state ? this.currentLeaves().find((l) => l.leafIndex === this.o.adapter.ownLeafIndex(this.state!)) : undefined;
    if (!myRosterDev) {
      // Out of the roster: this commit removes the leaf; the old state is of no further use.
      if (this.state) {
        this.state = null;
        this.rec.join = null;
      }
      return;
    }
    if (!this.state || (myLeaf && myLeaf.deviceSig !== myRosterDev.sig)) {
      // Not in the group, or rekeyed: the commit at s + 1 is not processed with the old state; the
      // device joins at its new leaf by Welcome (4.4).
      if (this.state) {
        this.state = null;
        this.rec.join = null;
      }
      if (rosterOk) await this.tryJoin(q, peek, ref);
      return;
    }
    if (this.rec.stalled) return;
    if (!rosterOk) return this.stall(e.seq, `commit names roster ${aad.roster.seq}, the roster before it is ${ref.seq}`);
    const epoch = this.o.adapter.epoch(this.state);
    if (peek.epoch !== epoch) {
      if (peek.epoch > epoch) this.stall(e.seq, `commit for epoch ${peek.epoch}, state at ${epoch}`);
      return;
    }
    const before = this.currentLeaves();
    const repairs = this.openRepairs(q.before, e.hts);
    let verdict: ReturnType<typeof checkCommit> | null = null;
    let result: Awaited<ReturnType<MlsAdapter["process"]>>;
    try {
      result = await this.auth.with(ref, () =>
        this.o.adapter.process(this.state!, body, (inc) => {
          if (inc.kind !== "commit") return false;
          verdict = checkCommit({ ref, before, senderLeafIndex: inc.senderLeafIndex, proposals: inc.proposals, expectedAuthority: authorityExtension(this.o.genesisHash, q.before.auth, this.o.scope ?? null), reinitAllowed: q.before.auth.revocations.length > 0, repairs });
          return verdict.ok;
        }),
      );
    } catch (err) {
      this.joinerCheck(e.seq, peek.epoch, aad, false, null);
      // ts-mls 1.6.4 cannot process a commit whose UpdatePath skips this device's removed leaf (a leaf
      // replacement). A Welcome routed to this device for the entry is then the way back (2.4).
      const joined = await this.tryJoin(q, peek, ref);
      if (joined !== "none") {
        if (joined === "refused") {
          this.state = null;
          this.rec.join = null;
        }
        return;
      }
      return this.stall(e.seq, `commit does not process: ${String((err as Error)?.message ?? err).slice(0, 80)}`);
    }
    const v = verdict as ReturnType<typeof checkCommit> | null;
    if (result.kind !== "commit" || !result.accepted || !v || !v.ok) {
      const reason: RuleRefusal | string = v && !v.ok ? v.reason : this.auth.refusals.at(-1)?.reason ?? "rejected";
      return this.stall(e.seq, `commit refused: ${reason}`);
    }
    // Step 4 on the new state.
    const removedSelf = !this.o.adapter.isActive(result.newState);
    if (!removedSelf) {
      const after = parseLeaves(this.o.adapter.leaves(result.newState));
      const eqv = after ? rosterEquality(ref, before, after) : { ok: false as const, reason: "unparseable_leaf" as const };
      if (!eqv.ok) return this.stall(e.seq, `after processing: ${eqv.reason}`);
      const cont = continuity(before, after!, result.senderLeafIndex);
      if (!cont.ok) return this.stall(e.seq, "continuity: the sender's credential changed");
    }
    this.joinerCheck(e.seq, peek.epoch, aad, true, result.senderLeafIndex ?? null, before);
    if (v.repairUsed) this.rec.usedRepairs = [...this.rec.usedRepairs, v.repairUsed].slice(-64);
    if (removedSelf) {
      const mine = before.find((l) => l.leafIndex === this.o.adapter.ownLeafIndex(this.state!));
      const replacedWithMyTriple = mine && v.after.some((l) => l.memberId === mine.memberId && l.deviceId === mine.deviceId && l.deviceSig === mine.deviceSig);
      if (replacedWithMyTriple && !repairs.some((r) => r.deviceId === this.o.deviceId)) this.raise("leaf_replaced_unrequested", e.seq, "own leaf replaced without an own open repair request");
      this.state = null;
      this.rec.join = null;
      log("mls_left_group", { roomId: this.o.roomId, seq: e.seq });
      if (replacedWithMyTriple) await this.tryJoin(q, peek, ref);
      return;
    }
    this.state = result.newState;
    if (v.adds > 0) this.witnessAt = this.now() + Math.floor(this.random() * this.t.witnessMaxDelayMs);
    if (v.adds > 0) this.announceAt = this.now() + Math.floor(this.random() * this.t.witnessMaxDelayMs);
  }

  private async onApplication(q: Queued, body: Uint8Array, peek: Extract<ReturnType<MlsAdapter["peek"]>, { wireformat: "mls_private_message" }>): Promise<void> {
    const e = q.signed.entry;
    if (this.rec.sent.includes(e.bodyHash) || !this.state || this.rec.stalled) return;
    let aad: MlsAad;
    try {
      aad = parseAad(peek.authenticatedData);
    } catch {
      return;
    }
    let r: Awaited<ReturnType<MlsAdapter["process"]>>;
    try {
      r = await this.auth.with(referenceRosterOf(q.before, this.o.scope ?? null), () => this.o.adapter.process(this.state!, body, () => false));
    } catch {
      this.joinerCheck(e.seq, peek.epoch, aad, false, null);
      return;
    }
    if (r.kind !== "application") return;
    this.state = r.newState;
    const leaves = this.currentLeaves();
    const sender = r.senderLeafIndex === null ? undefined : leaves.find((l) => l.leafIndex === r.senderLeafIndex);
    // Messages from leaves absent from the current roster are ignored (9).
    const cur = this.latest?.state ?? q.after;
    if (!sender || cur.members[sender.memberId]?.devices.find((d) => d.deviceId === sender.deviceId)?.sig !== sender.deviceSig) return;
    this.joinerCheck(e.seq, peek.epoch, aad, true, r.senderLeafIndex);
    this.noteAnchor(peek.epoch, aad.epochAuth, sender.deviceId);
    const payload = parseAppPayload(r.plaintext);
    if (payload?.kind === "chat.message") {
      // 5.2: the signed object must name this group, this epoch and the leaf it decrypted from.
      const v = checkChatMessage(payload, { roomId: this.o.roomId, groupId: this.groupId, epoch: peek.epoch, sender });
      if (!v.ok) this.raise("chat_attribution_failed", e.seq, `chat message refused: ${v.reason}`, { memberId: sender.memberId, deviceId: sender.deviceId });
      // Shown once the state that consumed it is written (8.2): a crash before the write shows it once, later.
      else this.deliverAfterSave.push({ seq: e.seq, epoch: peek.epoch, hts: e.hts, ts: payload.msg.ts, from: { memberId: sender.memberId, deviceId: sender.deviceId }, text: payload.msg.text });
    }
    if (payload?.kind === "room.profile" || payload?.kind === "member.profile") {
      // The sender's role in the verified roster now (room.profile needs an admin; room-book.ts decides).
      const role = cur.members[sender.memberId]?.role ?? "";
      this.profilesAfterSave.push({ seq: e.seq, epoch: peek.epoch, from: { memberId: sender.memberId, deviceId: sender.deviceId, role }, payload });
    }
  }

  /** Joiner epoch check (5.1) for one message of the group after the join. */
  private joinerCheck(seq: number, epoch: number, aad: MlsAad, decrypted: boolean, senderLeaf: number | null, leavesBefore?: Leaf[]): void {
    const j = this.rec.join;
    if (!j || j.status === "fork" || epoch !== j.epoch || seq <= j.seq) return;
    const leaves = leavesBefore ?? (this.state ? this.currentLeaves() : []);
    const sender = senderLeaf === null ? undefined : leaves.find((l) => l.leafIndex === senderLeaf);
    if (aad.epochAuth === j.anchor) {
      if (decrypted && sender && sender.deviceId !== this.o.deviceId && !j.confirmers.includes(sender.deviceId)) {
        j.confirmers = [...j.confirmers, sender.deviceId];
        if (j.confirmers.length >= (j.needed ?? 2) && (j.status === "pending" || j.status === "unconfirmed")) {
          j.status = "confirmed";
          log("mls_epoch_confirmed", { roomId: this.o.roomId, epoch });
        }
      }
      return;
    }
    if (decrypted) {
      this.raise("epoch_anchor_mismatch", seq, "a decryptable message carries another anchor", sender ? { memberId: sender.memberId, deviceId: sender.deviceId } : undefined);
      return;
    }
    j.status = "fork";
    this.raise("epoch_fork", seq, `joined at entry ${j.seq}; a message of epoch ${epoch} with another anchor does not decrypt`);
  }

  private checkJoinTimeout(): void {
    const j = this.rec.join;
    if (j && j.status === "pending" && this.now() - j.at >= this.t.epochConfirmMs) {
      j.status = "unconfirmed";
      this.raise("epoch_unconfirmed", j.seq, "no confirming anchor within the timeout");
      this.save();
    }
  }

  private noteAnchor(epoch: number, anchor: string, deviceId: string): void {
    if (!this.state || epoch !== this.o.adapter.epoch(this.state) || anchor !== this.anchor()) return;
    const set = this.anchorsSeen.get(epoch) ?? new Set<string>();
    set.add(deviceId);
    this.anchorsSeen.set(epoch, set);
  }

  /** 4.1 "Reference roster for a Welcome": joins from the Welcome of the commit at this entry. */
  private async tryJoin(q: Queued, peek: { epoch: number }, ref: ReferenceRoster): Promise<"none" | "joined" | "refused"> {
    const e = q.signed.entry;
    const mine = ref.members[this.o.memberId]?.devices.find((d) => d.deviceId === this.o.deviceId);
    if (!mine) return "none";
    const link = this.o.link();
    if (!link) return "none";
    for (let i = 0; i < 8 && (!this.welcomeCache || this.welcomeCache.entry.entry.seq < e.seq); i++) {
      const stale = this.welcomeCache;
      this.welcomeCache = null;
      let reply: Record<string, unknown>;
      try {
        reply = await link.request({ t: "welcome.fetch", ...(stale ? { ack: stale.entry.entry.seq } : {}) });
      } catch {
        return "none";
      }
      if (reply.none || typeof reply.welcome !== "string") return "none";
      this.welcomeCache = { welcome: b64uDecodeVar(reply.welcome, MLS_MESSAGE_MAX_BYTES), entry: reply.entry as SignedEntry };
    }
    const w = this.welcomeCache;
    if (!w || w.entry.entry?.seq !== e.seq) return "none";
    this.welcomeCache = null;
    const ack = () => link.request({ t: "welcome.fetch", ack: e.seq }).catch(() => undefined);
    if (w.entry.hash !== q.signed.hash) {
      this.raise("host_fault", e.seq, "Welcome names another entry");
      await ack();
      return "refused";
    }
    let refs: string[];
    try {
      const wp = this.o.adapter.peek(w.welcome);
      refs = wp.wireformat === "mls_welcome" && wp.suite === MLS_SUITE ? wp.refs : [];
    } catch {
      refs = [];
    }
    const kp = this.rec.kps.find((k) => refs.includes(k.ref) && k.sig === mine.sig);
    if (!kp) {
      this.raise("welcome_refused", e.seq, "the Welcome names no KeyPackage this device holds");
      await ack();
      return "refused";
    }
    let state: MlsState;
    try {
      state = await this.auth.with(ref, () => this.o.adapter.join(w.welcome, this.packageOf(kp), this.config));
    } catch (err) {
      this.raise("welcome_refused", e.seq, `Welcome refused: ${this.auth.refusals.at(-1)?.reason ?? String((err as Error)?.message ?? err).slice(0, 60)}`);
      await ack();
      return "refused";
    }
    // 2.3 authority extension and the tree against the roster its commit named.
    const ext = this.o.adapter.authorityExtension(state);
    const want = authorityExtension(this.o.genesisHash, q.before.auth, this.o.scope ?? null);
    const leaves = parseLeaves(this.o.adapter.leaves(state));
    const eqv = leaves ? rosterEquality(ref, [], leaves) : { ok: false as const, reason: "unparseable_leaf" };
    if (!ext || Buffer.compare(Buffer.from(ext), Buffer.from(want)) !== 0 || !eqv.ok || this.o.adapter.epoch(state) !== peek.epoch + 1) {
      this.raise("welcome_refused", e.seq, !ext || Buffer.compare(Buffer.from(ext), Buffer.from(want)) !== 0 ? "authority extension mismatch" : "tree does not match the roster");
      await ack();
      return "refused";
    }
    this.state = state;
    this.rec.stalled = null;
    this.rec.kps = this.rec.kps.filter((k) => k.ref !== kp.ref || k.lastResort);
    if (this.nextDevice && mine.sig === this.nextDevice.sigPub) {
      this.device = this.nextDevice;
      this.nextDevice = null;
    }
    const epoch = this.o.adapter.epoch(state);
    // 5.1 (round 9, item 4): min(2, other leaves) confirmers. No other leaf cannot happen (the committer
    // stays a leaf); it would leave nothing to compare with, so the epoch counts as confirmed.
    const needed = Math.min(2, (leaves ?? []).filter((l) => l.deviceId !== this.o.deviceId).length);
    this.rec.join = { seq: e.seq, epoch, at: this.now(), anchor: this.anchor(), confirmers: [], needed, status: needed === 0 ? "confirmed" : "pending" };
    this.rec.cursor = e.seq;
    this.save();
    await ack();
    log("mls_joined", { roomId: this.o.roomId, seq: e.seq, epoch, lastResort: kp.lastResort });
    // R3.3: tell the group this device's profile once it may send (after the joiner check).
    this.announceAt = this.now();
    if (kp.lastResort) this.retryAt = 0;
    return "joined";
  }

  // ------------------------------------------------------------------------------ committing

  /** 4.2 "a commit carries every pending removal"; adds after the repair delay (4.4). */
  private async commitPending(removalsOnly: boolean): Promise<void> {
    if (!this.state || !this.latest || this.pendingOwn) return;
    const st = this.latest.state;
    const ref = referenceRosterOf(st, this.o.scope ?? null);
    const leaves = this.currentLeaves();
    const pend = pendingChanges(ref, leaves);
    const now = this.now();
    const seen = new Set<string>();
    for (const a of pend.adds) {
      const k = `${a.deviceId}/${a.deviceSig}`;
      seen.add(k);
      if (!this.addSeen.has(k)) this.addSeen.set(k, now + this.t.repairDelayMs + (this.isAdmin(st) ? 0 : Math.floor(this.random() * this.t.repairJitterMs)));
    }
    for (const k of [...this.addSeen.keys()]) if (!seen.has(k)) this.addSeen.delete(k);
    // Prompt adds (round 9, item 5): an armed device this daemon admitted is tried now, once per arming.
    const pendingIds = new Set(pend.adds.map((a) => a.deviceId));
    for (const id of [...this.promptEligible]) if (!pendingIds.has(id)) (this.promptEligible.delete(id), this.promptArmed.delete(id));
    const prompt = new Set(removalsOnly ? [] : pend.adds.filter((a) => this.promptArmed.has(a.deviceId)).map((a) => a.deviceId));
    for (const id of prompt) this.promptArmed.delete(id);
    const dueAdds = removalsOnly ? [] : pend.adds.filter((a) => prompt.has(a.deviceId) || ((this.addSeen.get(`${a.deviceId}/${a.deviceSig}`) ?? Infinity) <= now && now >= this.retryAt));
    if (pend.removals.length === 0 && dueAdds.length === 0) return;
    const link = this.o.link();
    if (!link) return;
    const adds: MlsKeyPackage[] = [];
    let repairMissed = false;
    for (const a of dueAdds.slice(0, 8)) {
      const kp = await this.fetchPackage(link, { memberId: a.memberId, deviceId: a.deviceId, for: "current" }, ref);
      if (kp) adds.push(kp);
      // A prompt add without a package waits for the device's kp.publish, not for the retry timer.
      else if (!prompt.has(a.deviceId)) repairMissed = true;
    }
    if (repairMissed) this.retryAt = now + this.t.retryMs;
    if (pend.removals.length === 0 && adds.length === 0) return;
    const built = await this.buildCommit(ref, this.latest.head, adds, pend.removals.map((l) => l.leafIndex));
    this.pendingOwn = { bodyHash: bodyHash(built.commit), newState: built.newState, adds: adds.length };
    try {
      const reply = await link.request({ t: "commit.submit", epoch: this.o.adapter.epoch(this.state), commit: b64u(built.commit), ...(built.welcome ? { welcome: b64u(built.welcome) } : {}) });
      log("mls_commit_submitted", { roomId: this.o.roomId, seq: reply.seq, removes: pend.removals.length, adds: adds.length });
    } catch (e) {
      this.pendingOwn = null;
      const code = (e as { code?: string }).code;
      if (code !== "stale_epoch" && code !== "stale_roster") log("mls_commit_refused", { roomId: this.o.roomId, code: code ?? "error" });
    }
  }

  /** createCommit with the reference roster set, then the 4.2 checks on the result before submitting. */
  private async buildCommit(ref: ReferenceRoster, head: { seq: number; hash: string }, adds: MlsKeyPackage[], removes: number[]): Promise<{ newState: MlsState; commit: Uint8Array; welcome: Uint8Array | null }> {
    const state = this.state!;
    const aad = encodeAad({ roster: { seq: ref.seq, hash: ref.hash }, logHead: head, epochAuth: this.anchor() });
    const before = this.currentLeaves();
    const built = await this.auth.with(ref, () => this.o.adapter.commit(state, { adds, removes }, aad));
    const after = parseLeaves(this.o.adapter.leaves(built.newState));
    const eqv = after ? rosterEquality(ref, before, after) : { ok: false as const, reason: "unparseable_leaf" };
    if (!eqv.ok) throw new MlsMemberError("refused", `own commit fails roster equality (${eqv.reason}); not submitted`);
    return built;
  }

  /** `kp.fetch` of one package, checked by the fetcher against the reference roster (6.4). */
  private async fetchPackage(link: MlsLink, target: { memberId: string; deviceId: string; for: "current" | "rekey" }, ref: ReferenceRoster): Promise<MlsKeyPackage | null> {
    let reply: Record<string, unknown>;
    try {
      reply = await link.request({ t: "kp.fetch", targets: [{ ...target, count: 1 }] });
    } catch {
      return null;
    }
    const res = (reply.results as { deviceId: string; keyPackages: string[]; lastResort: string | null }[] | undefined)?.find((r) => r.deviceId === target.deviceId);
    for (const text of [...(res?.keyPackages ?? []), ...(res?.lastResort ? [res.lastResort] : [])]) {
      const kp = this.checkFetched(text, target, ref);
      if (kp) return kp;
      this.raise("host_fault", this.rec.cursor, `a fetched KeyPackage of ${target.deviceId} fails the fetcher's checks`);
    }
    return null;
  }

  private checkFetched(text: string, target: { memberId: string; deviceId: string }, ref: ReferenceRoster): MlsKeyPackage | null {
    try {
      const info = this.o.adapter.decodeKeyPackage(b64uDecodeVar(text, 64 * 1024));
      if (info.suite !== MLS_SUITE || !info.capabilityExtensions.includes(AUTHORITY_EXTENSION_TYPE) || !info.signatureValid) return null;
      const nowS = Math.floor(this.now() / 1000);
      if (info.notBefore > nowS + 300 || info.notAfter <= nowS) return null;
      const v = checkCredential(ref, { credentialType: info.credentialType, identity: info.identity ?? undefined }, info.signaturePublicKey);
      if (!v.ok || v.id.memberId !== target.memberId || v.id.deviceId !== target.deviceId) return null;
      return info.keyPackage;
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------------------------ sending

  private async sendPayload(payload: Uint8Array): Promise<{ seq: number }> {
    const link = this.requireLink();
    const st = this.latest!.state;
    const ref = referenceRosterOf(st, this.o.scope ?? null);
    const aad = encodeAad({ roster: { seq: ref.seq, hash: ref.hash }, logHead: this.latest!.head, epochAuth: this.anchor() });
    const r = await this.o.adapter.encrypt(this.state!, payload, aad);
    // The ratchet moved: the state is written before the message leaves (8.2).
    this.state = r.newState;
    this.rec.sent = [...this.rec.sent, bodyHash(r.message)].slice(-SENT_MAX);
    this.rec.refresh = { at: this.rec.refresh?.at ?? this.now(), sent: (this.rec.refresh?.sent ?? 0) + 1 };
    this.save();
    const reply = await link.request({ t: "msg.send", epoch: this.o.adapter.epoch(this.state), message: b64u(r.message) });
    return { seq: Number(reply.seq) };
  }

  /**
   * Keys 4.2: an UpdatePath commit with the public `createCommit` every `refreshMs` or `refreshMessages`
   * sent, whichever comes first. It adds nobody and carries every pending removal (4.2), so it passes
   * the same checks as any commit; the credential stays byte-identical (continuity check).
   */
  private async dueRefresh(): Promise<void> {
    if (!this.state || !this.latest || this.pendingOwn || this.rec.stalled || !this.o.adapter.isActive(this.state) || this.now() < this.refreshRetryAt) return;
    const r = this.rec.refresh;
    if (!r) {
      this.rec.refresh = { at: this.now(), sent: 0 };
      this.save();
      return;
    }
    if (this.now() - r.at < this.t.refreshMs && r.sent < this.t.refreshMessages) return;
    const link = this.o.link();
    if (!link) return;
    const ref = referenceRosterOf(this.latest.state, this.o.scope ?? null);
    const pend = pendingChanges(ref, this.currentLeaves());
    const built = await this.buildCommit(ref, this.latest.head, [], pend.removals.map((l) => l.leafIndex));
    this.pendingOwn = { bodyHash: bodyHash(built.commit), newState: built.newState, adds: 0, refresh: true };
    try {
      const reply = await link.request({ t: "commit.submit", epoch: this.o.adapter.epoch(this.state), commit: b64u(built.commit) });
      log("mls_leaf_refreshed", { roomId: this.o.roomId, seq: reply.seq });
    } catch (e) {
      this.pendingOwn = null;
      this.refreshRetryAt = this.now() + Math.max(this.t.retryMs, 1000);
      log("mls_leaf_refresh_refused", { roomId: this.o.roomId, code: (e as { code?: string }).code ?? "error" });
    }
  }

  /** `log.witness` (room-log-v2 4.5) in the new epoch after a commit with an Add (5.1). */
  private async dueWitness(): Promise<void> {
    if (this.witnessAt === null || this.now() < this.witnessAt || !this.state || !this.latest) return;
    this.witnessAt = null;
    const epoch = this.o.adapter.epoch(this.state);
    if ((this.anchorsSeen.get(epoch)?.size ?? 0) >= 2 || this.canSendReason() !== null) return;
    const st = this.latest.state;
    const ref = referenceRosterOf(st, this.o.scope ?? null);
    const witness = { v: 2, typ: "log-witness", roomId: this.o.roomId, deviceId: this.o.deviceId, head: this.latest.head, roster: { seq: ref.seq, hash: ref.hash } };
    const sig = b64u(sign(this.device.sigKey, stmtContext(STMT_LOG_WITNESS), rjcs(witness)));
    try {
      await this.sendPayload(rjcs({ kind: "log.witness", witness, sig }));
    } catch (e) {
      log("mls_witness_failed", { roomId: this.o.roomId, code: (e as { code?: string }).code ?? "error" });
    }
  }

  /**
   * R3.3: re-announce profiles (the runtime's `announce`) after a commit with an Add, so a joiner, which
   * cannot read earlier epochs, learns the room name and members' display names. Waits while the device
   * may not send (a joiner until its epoch is confirmed); the payloads are taken at send time.
   */
  private async dueAnnounce(): Promise<void> {
    if (this.announceAt === null || this.now() < this.announceAt || !this.state || !this.latest || !this.announce) return;
    if (this.canSendReason() !== null) return;
    this.announceAt = null;
    let list: AppPayload[];
    try {
      list = this.announce();
    } catch {
      return;
    }
    for (const p of list.slice(0, 4)) {
      if (p.kind !== "room.profile" && p.kind !== "member.profile") continue;
      try {
        await this.sendPayload(rjcs(p, 64 * 1024));
      } catch (e) {
        log("mls_announce_failed", { roomId: this.o.roomId, kind: p.kind, code: (e as { code?: string }).code ?? "error" });
      }
    }
  }

  // ------------------------------------------------------------------------------ KeyPackages

  /** 6.4 "When a device publishes": one per group plus one spare, and a last-resort package. */
  private async ensurePackages(): Promise<void> {
    const cur = this.rec.kps.filter((k) => k.pool === "current" && k.sig === this.device.sigPub);
    const singles = cur.filter((k) => !k.lastResort).length;
    const hasLast = cur.some((k) => k.lastResort && this.now() - k.at < LAST_RESORT_KEEP_MS);
    if (singles >= 2 && hasLast) return;
    await this.publish("current", Math.max(0, 2 - singles), !hasLast);
  }

  private async publish(pool: "current" | "rekey", count: number, lastResort: boolean): Promise<void> {
    const link = this.requireLink();
    const dev = pool === "rekey" ? this.nextDevice : this.device;
    if (!dev || (count === 0 && !lastResort)) return;
    const made: KpRecord[] = [];
    for (let i = 0; i < count + (lastResort ? 1 : 0); i++) made.push(await this.makePackage(pool, dev, lastResort && i === count));
    const singles = made.filter((k) => !k.lastResort);
    const last = made.find((k) => k.lastResort);
    // Private parts are written before the public parts leave (a Welcome may follow at once).
    const keep = this.rec.kps;
    this.rec.kps = pruneKps([...keep.filter((k) => !(last && k.lastResort && k.pool === pool && this.now() - k.at > LAST_RESORT_KEEP_MS)), ...made], this.now());
    this.save();
    await link.request({ t: "kp.publish", for: pool, keyPackages: singles.map((k) => k.pub), ...(last ? { lastResort: last.pub } : {}) });
    log("mls_kp_published", { roomId: this.o.roomId, pool, singles: singles.length, lastResort: !!last });
  }

  private async makePackage(pool: "current" | "rekey", dev: { sigPub: string; sigKey: KeyObject }, lastResort: boolean): Promise<KpRecord> {
    const a = this.o.adapter;
    const signer = await a.newLeafSigner();
    const nowS = Math.floor(this.now() / 1000);
    const identity = signMlsIdentity({ v: 2, typ: "mls-identity", roomId: this.o.roomId, memberId: this.o.memberId, deviceId: this.o.deviceId, deviceSig: dev.sigPub, mlsSig: b64u(signer.publicKey), notBefore: nowS }, dev.sigKey);
    const kp = await a.keyPackage(identity, signer, { notBefore: nowS - KP_SKEW_S, notAfter: nowS + KP_LIFETIME_S });
    return { ref: kp.ref, pool, lastResort, sig: dev.sigPub, pub: b64u(kp.bytes), priv: { init: b64u(kp.privatePackage.initPrivateKey), hpke: b64u(kp.privatePackage.hpkePrivateKey), sig: b64u(kp.privatePackage.signaturePrivateKey) }, at: this.now() };
  }

  private packageOf(k: KpRecord): { publicPackage: MlsKeyPackage; privatePackage: MlsPrivateKeyPackage } {
    const info = this.o.adapter.decodeKeyPackage(b64uDecodeVar(k.pub, 64 * 1024));
    return { publicPackage: info.keyPackage, privatePackage: { initPrivateKey: b64uDecodeVar(k.priv.init, 128), hpkePrivateKey: b64uDecodeVar(k.priv.hpke, 128), signaturePrivateKey: b64uDecodeVar(k.priv.sig, 128) } };
  }

  // ------------------------------------------------------------------------------ helpers

  private async createGroup(): Promise<void> {
    const st = this.latest!.state;
    const kp = await this.makePackage("current", this.device, false);
    const ref = referenceRosterOf(st, this.o.scope ?? null);
    this.state = await this.auth.with(ref, () => this.o.adapter.createGroup(this.groupId, this.packageOf(kp), authorityExtension(this.o.genesisHash, st.auth, this.o.scope ?? null), this.config));
    this.save();
    log("mls_group_created", { roomId: this.o.roomId });
  }

  /** A commit of this group in the log means the group exists; the creator never re-creates it. */
  private groupCommitted(): boolean {
    return this.sawGroupCommit;
  }

  private currentLeaves(): Leaf[] {
    return this.state ? (parseLeaves(this.o.adapter.leaves(this.state)) ?? []) : [];
  }

  private anchor(): string {
    return epochAuth(this.groupId, this.o.adapter.epoch(this.state!), this.o.adapter.epochAuthenticator(this.state!));
  }

  private isAdmin(st: Readonly<RoomState>): boolean {
    return st.members[this.o.memberId]?.role === "admin";
  }

  /** Open, unused repair requests for this group at an entry (room-log-v2 4.3: open for 24 h of hts). */
  private openRepairs(st: Readonly<RoomState>, hts: number): OpenRepair[] {
    const scope = this.o.scope ?? null;
    return Object.entries(st.repairs)
      .filter(([h, r]) => r.status === "open" && r.scope === scope && r.generation === 0 && hts - r.hts < 24 * 3600 * 1000 && !this.rec.usedRepairs.includes(h))
      .map(([h, r]) => ({ bodyHash: h, memberId: r.memberId, deviceId: r.deviceId, keyPackageRef: r.keyPackageRef }));
  }

  private async bodyFor(seq: number): Promise<Uint8Array | null> {
    const have = this.bodies.get(seq);
    if (have) return have;
    const link = this.o.link();
    if (!link) return null;
    let reply: Record<string, unknown>;
    try {
      reply = await link.request({ t: "msg.fetch", fromSeq: seq, limit: 500 });
    } catch {
      return null;
    }
    for (const b of (reply.bodies as { seq: number; body: string }[] | undefined) ?? []) {
      if (Number.isSafeInteger(b.seq) && b.seq >= seq && typeof b.body === "string") this.bodies.set(b.seq, b64uDecodeVar(b.body, MLS_MESSAGE_MAX_BYTES));
    }
    if (this.bodies.size > 1000) for (const k of [...this.bodies.keys()].slice(0, this.bodies.size - 1000)) this.bodies.delete(k);
    return this.bodies.get(seq) ?? null;
  }

  private requireLink(): MlsLink {
    const l = this.o.link();
    if (!l) throw new MlsMemberError("no_session", "no room session");
    return l;
  }

  private stall(seq: number, detail: string): void {
    this.rec.stalled = detail.slice(0, 160);
    this.raise("roster_mismatch", seq, detail);
  }

  private disable(type: MlsAlertType, seq: number, detail: string): void {
    this.disabled = type;
    this.raise(type, seq, detail);
  }

  private raise(type: MlsAlertType, seq: number, detail?: string, peer?: { memberId: string; deviceId: string }): void {
    const a: MlsAlert = { type, seq, at: this.now(), ...(detail ? { detail: detail.slice(0, 200) } : {}), ...(peer ? { peer } : {}) };
    this.alerts.push(a);
    if (this.alerts.length > 100) this.alerts.shift();
    log("mls_alert", { roomId: this.o.roomId, type, seq, ...(peer ? { peerDevice: peer.deviceId } : {}) });
    this.o.onAlert?.(a);
  }

  /** Back to the stored record after a failed write: memory never runs ahead of disk. */
  private reload(): void {
    const stored = this.o.store.read();
    if (!stored) return;
    this.rec = stored;
    this.state = stored.state ? this.o.adapter.decodeState(b64uDecodeVar(stored.state, 8 * 1024 * 1024), this.config) : null;
    this.pendingOwn = null;
  }

  private save(): void {
    this.rec.state = this.state ? b64u(this.o.adapter.encodeState(this.state)) : null;
    this.o.store.write(this.rec);
  }

  private locked<T>(f: () => Promise<T>): Promise<T> {
    const run = this.lock.then(f, f);
    this.lock = run.catch(() => undefined);
    return run;
  }
}

function pruneKps(kps: KpRecord[], now: number): KpRecord[] {
  const keep = kps.filter((k) => !k.lastResort || now - k.at < LAST_RESORT_KEEP_MS + 24 * 3600 * 1000);
  const singles = keep.filter((k) => !k.lastResort);
  const drop = new Set(singles.slice(0, Math.max(0, singles.length - KP_KEEP)).map((k) => k.ref));
  return keep.filter((k) => !drop.has(k.ref));
}
