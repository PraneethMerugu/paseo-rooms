// Embedded Room Host (rooms-architecture.md sections 5, 8.1): membership, grant issuance,
// revocation, invites and the signed room log. Runs inside the owner's gateway in Milestone 1.
// State: <data>/gateway/state.json (0600). Host key: <data>/gateway/host-key.json (0600).
// Changes that affect live access are pushed synchronously to listeners (no polling).
import { join } from "node:path";
import { exportPublicKey, exportSecretKey, generateKeyPair } from "@getpaseo/relay/e2ee";
import { canonicalJson, type ControlErrorCode, type ControlTranscript, CONTROL_SIGNATURE_CONTEXT } from "../../shared/control";
import { DEFAULT_ROOM_SETTINGS, Lane, LIMITS, Member, Room, type RoomSettings, type GrantClaims, type InvitePayload, type LaneOrigin, type RoomEvent } from "../../shared/schemas";
import { generateEd25519, hexEqual, keyIdOf, randomHexId, randomToken, sha256Hex, verifyEd25519, type StoredEd25519Key } from "../crypto";
import { issueGrant, verifyGrant, type GrantCheck } from "../grants";
import { encodeInviteCode } from "../invite-code";
import { log } from "../log";
import { ensurePrivateDir, readJsonFile, writePrivateFile } from "../paths";
import { RoomEventLog } from "./event-log";
import { randomBytes } from "node:crypto";

export const DEFAULT_RELAY = { endpoint: "relay.paseo.sh:443", useTls: true };

/**
 * Revoked grant ids are kept this long after their exp before pruning (P-12, C-9). Acceptance also
 * requires the member's CURRENT grant id (allowlist), so the denylist is defence in depth and audit.
 */
export const REVOKED_GRANT_RETENTION_S = 7 * 24 * 3600;
/** Retry interval for a state save that failed after the change was already enforced (P-13). */
const SAVE_RETRY_MS = 5_000;

export interface InviteRecord {
  id: string;
  roomId: string;
  laneId: string;
  tokenHash: string;
  createdAt: string;
  expiresAt: string;
  grantTtlSeconds: number;
  usedAt: string | null;
  usedBy: string | null;
  revokedAt: string | null;
  failedAttempts: number;
}

interface LaneKeys {
  publicKeyB64: string;
  secretKeyB64: string;
}

interface IssuedGrantRecord {
  gid: string;
  memberId: string;
  exp: number;
}

export interface HostState {
  v: 1;
  rooms: Room[];
  lanes: Lane[];
  laneKeys: Record<string, LaneKeys>;
  members: Member[];
  invites: InviteRecord[];
  /** Latest grant per member (no token). */
  grants: IssuedGrantRecord[];
  revokedGrantIds: IssuedGrantRecord[];
  /** Owner room settings by room id. Optional: state files written before it have none (defaults). */
  roomSettings?: Record<string, RoomSettings>;
}

export type HostChange =
  | { kind: "member_revoked"; memberId: string; laneId: string }
  | { kind: "member_left"; memberId: string; laneId: string }
  | { kind: "grant_revoked"; gid: string; laneId: string }
  | { kind: "lane_closed"; laneId: string }
  | { kind: "lane_opened"; laneId: string }
  | { kind: "room_settings_changed"; roomId: string; settings: RoomSettings }
  | { kind: "updated" };

export class ControlFailure extends Error {
  constructor(readonly code: ControlErrorCode, message: string) {
    super(message);
  }
}

export interface GrantLiveCheck {
  ok: boolean;
  reason: string;
  claims?: GrantClaims;
}

export class HostStore {
  readonly hostKey: StoredEd25519Key;
  private state: HostState;
  private readonly listeners = new Set<(change: HostChange) => void>();
  private readonly logs = new Map<string, RoomEventLog>();
  private readonly dir: string;
  private saveRetry: ReturnType<typeof setTimeout> | null = null;
  /** True while in-memory state holds changes that are enforced but not yet on disk. */
  dirty = false;

  constructor(dataDir: string, private readonly relay = DEFAULT_RELAY, private readonly now = () => Date.now()) {
    this.dir = join(dataDir, "gateway");
    ensurePrivateDir(this.dir);
    const keyPath = join(this.dir, "host-key.json");
    let key = readJsonFile<StoredEd25519Key>(keyPath);
    if (!key) {
      key = generateEd25519();
      writePrivateFile(keyPath, JSON.stringify(key, null, 2));
      log("host_key_created", { keyId: key.keyId });
    }
    this.hostKey = key;
    this.state = readJsonFile<HostState>(join(this.dir, "state.json")) ?? {
      v: 1,
      rooms: [],
      lanes: [],
      laneKeys: {},
      members: [],
      invites: [],
      grants: [],
      revokedGrantIds: [],
    };
  }

  onChange(listener: (change: HostChange) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(change: HostChange): void {
    for (const l of this.listeners) {
      try {
        l(change);
      } catch (e) {
        log("host_listener_error", { error: (e as Error).message });
      }
    }
  }

  /** Durable, atomic save (fsync file and directory). Throws on I/O failure. */
  private save(): void {
    const nowS = Math.floor(this.now() / 1000);
    this.state.revokedGrantIds = this.state.revokedGrantIds.filter((g) => g.exp + REVOKED_GRANT_RETENTION_S > nowS);
    try {
      writePrivateFile(join(this.dir, "state.json"), JSON.stringify(this.state, null, 2));
    } catch (e) {
      this.dirty = true;
      this.scheduleSaveRetry();
      throw e;
    }
    this.dirty = false;
    if (this.saveRetry) clearTimeout(this.saveRetry);
    this.saveRetry = null;
  }

  private scheduleSaveRetry(): void {
    if (this.saveRetry) return;
    this.saveRetry = setTimeout(() => {
      this.saveRetry = null;
      if (!this.dirty) return;
      try {
        this.save();
        log("host_state_saved_after_retry", {});
      } catch (e) {
        log("host_state_save_failed", { error: (e as Error).message?.slice(0, 200) });
      }
    }, SAVE_RETRY_MS);
    (this.saveRetry as unknown as { unref?: () => void }).unref?.();
  }

  /**
   * Persists an access change that is ALREADY enforced in memory and in live sessions (P-13). If the
   * write fails, enforcement stays in place, a retry is scheduled, and the caller gets an error that
   * says so.
   */
  private persistEnforced(what: string): void {
    try {
      this.save();
    } catch (e) {
      log("host_state_save_failed", { what, error: (e as Error).message?.slice(0, 200) });
      throw new Error(`${what} is in effect now, but saving it failed (${(e as Error).message?.slice(0, 120)}). It is retried every ${SAVE_RETRY_MS / 1000} s; until then a restart would undo it.`);
    }
  }

  /** Stops the save retry timer (plugin shutdown). */
  dispose(): void {
    if (this.saveRetry) clearTimeout(this.saveRetry);
    this.saveRetry = null;
  }

  private eventLog(roomId: string): RoomEventLog {
    let l = this.logs.get(roomId);
    if (!l) {
      l = new RoomEventLog(join(this.dir, "rooms", roomId, "events.jsonl"), this.hostKey);
      this.logs.set(roomId, l);
    }
    return l;
  }

  /**
   * Appends to the room log. A log failure never undoes or blocks an access change that is already
   * enforced (C-11): it is logged loudly and the operation continues.
   */
  private record(roomId: string, type: RoomEvent["type"], actor: string, data: RoomEvent["data"]): void {
    try {
      this.eventLog(roomId).append({ roomId, type, actor, data });
    } catch (e) {
      log("room_log_append_failed", { roomId, type, error: (e as Error).message?.slice(0, 200) });
    }
  }

  private iso(ms = this.now()): string {
    return new Date(ms).toISOString();
  }

  // ---------------------------------------------------------------- reads
  get rooms(): readonly Room[] {
    return this.state.rooms;
  }
  get lanes(): readonly Lane[] {
    return this.state.lanes;
  }
  get members(): readonly Member[] {
    return this.state.members;
  }
  get invites(): readonly InviteRecord[] {
    return this.state.invites;
  }
  room(id: string): Room | undefined {
    return this.state.rooms.find((r) => r.id === id);
  }
  lane(id: string): Lane | undefined {
    return this.state.lanes.find((l) => l.id === id);
  }
  laneKeys(id: string): LaneKeys | undefined {
    return this.state.laneKeys[id];
  }
  member(id: string): Member | undefined {
    return this.state.members.find((m) => m.id === id);
  }
  latestGrant(memberId: string): IssuedGrantRecord | undefined {
    return this.state.grants.find((g) => g.memberId === memberId);
  }
  events(roomId: string): RoomEvent[] {
    return this.eventLog(roomId).readAll();
  }
  verifyLog(roomId: string) {
    return this.eventLog(roomId).verify();
  }
  roomSettings(roomId: string): RoomSettings {
    return { ...DEFAULT_ROOM_SETTINGS, ...(this.state.roomSettings?.[roomId] ?? {}) };
  }

  // ---------------------------------------------------------------- owner actions
  createRoom(name: string): Room {
    const room = Room.parse({ v: 1, id: randomHexId("room_"), name, createdAt: this.iso(), status: "active" });
    this.state.rooms.push(room);
    this.save();
    this.record(room.id, "room.created", "owner", { name, hostKeyId: this.hostKey.keyId });
    return room;
  }

  /**
   * Owner opt-in to show the project name to members. Applied to live routes first (emit), then
   * recorded as room.policy.changed and persisted, like the access changes (P-13).
   */
  setShowProjectName(roomId: string, show: boolean, actor = "owner"): RoomSettings {
    const room = this.room(roomId);
    if (!room || room.status !== "active") throw new Error("Room not found");
    const current = this.roomSettings(roomId);
    if (current.showProjectName === show) return current;
    const settings: RoomSettings = { ...current, showProjectName: show };
    this.state.roomSettings = { ...(this.state.roomSettings ?? {}), [roomId]: settings };
    this.emit({ kind: "room_settings_changed", roomId, settings });
    this.record(roomId, "room.policy.changed", actor, { setting: "showProjectName", value: show });
    this.persistEnforced(show ? "Showing the project name" : "Hiding the project name");
    return settings;
  }

  /** Archives a room that never got a lane (failed creation). */
  abandonRoom(roomId: string): void {
    const room = this.room(roomId);
    if (!room || this.state.lanes.some((l) => l.roomId === roomId)) return;
    room.status = "archived";
    this.save();
  }

  createLane(input: { id?: string; roomId: string; label: string; origin: LaneOrigin; agentId: string; workspaceId: string }): Lane {
    const room = this.room(input.roomId);
    if (!room || room.status !== "active") throw new Error("Room not found");
    const kp = generateKeyPair();
    const lane = Lane.parse({
      v: 1,
      id: input.id ?? randomHexId("lane_"),
      roomId: room.id,
      label: input.label,
      origin: input.origin,
      agentId: input.agentId,
      workspaceId: input.workspaceId,
      serverId: `lane_${randomBytes(24).toString("base64url")}`,
      publicKeyB64: exportPublicKey(kp.publicKey),
      relay: this.relay,
      createdAt: this.iso(),
      status: "open",
    });
    this.state.lanes.push(lane);
    this.state.laneKeys[lane.id] = { publicKeyB64: lane.publicKeyB64, secretKeyB64: exportSecretKey(kp.secretKey) };
    this.save();
    this.record(room.id, "lane.created", "owner", {
      laneId: lane.id,
      origin: input.origin.kind,
      agentId: input.agentId,
      laneServerId: lane.serverId,
      ...(input.origin.kind === "fork" ? { parentAgentId: input.origin.parentAgentId } : {}),
    });
    this.emit({ kind: "lane_opened", laneId: lane.id });
    return lane;
  }

  /** Enforce (stop the endpoint), then record and persist. */
  closeLane(laneId: string, opts: { actor?: string; reason?: string } = {}): void {
    const lane = this.lane(laneId);
    if (!lane || lane.status === "closed") return;
    lane.status = "closed";
    const revokedInvites: string[] = [];
    for (const inv of this.state.invites)
      if (inv.laneId === laneId && !inv.usedAt && !inv.revokedAt) {
        inv.revokedAt = this.iso();
        revokedInvites.push(inv.id);
      }
    delete this.state.laneKeys[laneId];
    this.emit({ kind: "lane_closed", laneId });
    this.record(lane.roomId, "lane.closed", opts.actor ?? "owner", { laneId, reason: opts.reason ?? "owner_closed", invitesRevoked: revokedInvites.length });
    this.persistEnforced("Closing the lane");
  }

  createInvite(input: { laneId: string; ttlSeconds: number; grantTtlSeconds: number }): { invite: InviteRecord; code: string } {
    const lane = this.lane(input.laneId);
    if (!lane || lane.status !== "open") throw new Error("Lane is not open");
    const room = this.room(lane.roomId)!;
    const token = randomToken(32);
    const nowMs = this.now();
    const invite: InviteRecord = {
      id: randomHexId("inv_"),
      roomId: lane.roomId,
      laneId: lane.id,
      tokenHash: sha256Hex(token),
      createdAt: this.iso(nowMs),
      expiresAt: this.iso(nowMs + input.ttlSeconds * 1000),
      grantTtlSeconds: input.grantTtlSeconds,
      usedAt: null,
      usedBy: null,
      revokedAt: null,
      failedAttempts: 0,
    };
    this.state.invites.push(invite);
    this.save();
    this.record(lane.roomId, "invite.created", "owner", { inviteId: invite.id, laneId: lane.id, expiresAt: invite.expiresAt, grantTtlSeconds: input.grantTtlSeconds });
    const payload: InvitePayload = {
      v: 1,
      roomId: room.id,
      roomName: room.name,
      laneId: lane.id,
      laneLabel: lane.label,
      offer: { serverId: lane.serverId, publicKeyB64: lane.publicKeyB64, relay: lane.relay },
      host: { keyId: this.hostKey.keyId, publicKey: this.hostKey.publicKey },
      inviteId: invite.id,
      token,
      exp: Math.floor((nowMs + input.ttlSeconds * 1000) / 1000),
    };
    return { invite, code: encodeInviteCode(payload) };
  }

  revokeInvite(inviteId: string): void {
    const inv = this.state.invites.find((i) => i.id === inviteId);
    if (!inv || inv.revokedAt || inv.usedAt) return;
    inv.revokedAt = this.iso();
    this.save();
    this.record(inv.roomId, "invite.revoked", "owner", { inviteId });
  }

  inviteStatus(inv: InviteRecord): "open" | "used" | "expired" | "revoked" | "burned" {
    if (inv.usedAt) return "used";
    if (inv.revokedAt) return inv.failedAttempts >= LIMITS.maxFailedEnrollmentsPerInvite ? "burned" : "revoked";
    if (Date.parse(inv.expiresAt) <= this.now()) return "expired";
    return "open";
  }

  /** Enforce first (in memory and live sessions, independent of I/O), then record and persist (P-13). */
  revokeMember(memberId: string, actor = "owner"): Member {
    const m = this.member(memberId);
    if (!m) throw new Error("Member not found");
    const changed = m.status === "active";
    if (changed) {
      m.status = "revoked";
      m.endedAt = this.iso();
      this.revokeLatestGrant(m.id);
    }
    this.emit({ kind: "member_revoked", memberId: m.id, laneId: m.laneId });
    if (changed) {
      this.record(m.roomId, "member.revoked", actor, { memberId: m.id, laneId: m.laneId });
      this.persistEnforced("The revocation");
    }
    return m;
  }

  private revokeLatestGrant(memberId: string): void {
    const g = this.latestGrant(memberId);
    if (g && !this.state.revokedGrantIds.some((r) => r.gid === g.gid)) this.state.revokedGrantIds.push(g);
  }

  // ---------------------------------------------------------------- control protocol (member actions)
  /** Builds the transcript the member's device key must sign. Shared by gateway and member code. */
  static transcript(t: Omit<ControlTranscript, "ctx">): string {
    return canonicalJson({ ctx: CONTROL_SIGNATURE_CONTEXT, ...t });
  }

  enroll(input: {
    laneId: string;
    token: string;
    devicePublicKey: string;
    label: string;
    daemonServerId: string | null;
    verifySignature: (tokenHash: string) => boolean;
  }): { member: Member; token: string; claims: GrantClaims } {
    const lane = this.lane(input.laneId);
    if (!lane) throw new ControlFailure("unknown_lane", "Unknown lane");
    if (lane.status !== "open") throw new ControlFailure("lane_closed", "Lane is closed");
    const tokenHash = sha256Hex(input.token);
    const invite = this.state.invites.find((i) => i.laneId === lane.id && hexEqual(i.tokenHash, tokenHash));
    if (!invite) {
      // Count failures against every open invite of this lane; burn after the limit.
      for (const i of this.state.invites)
        if (i.laneId === lane.id && !i.usedAt && !i.revokedAt) {
          i.failedAttempts++;
          if (i.failedAttempts >= LIMITS.maxFailedEnrollmentsPerInvite) i.revokedAt = this.iso();
        }
      this.save();
      throw new ControlFailure("invalid_token", "Invite is not valid");
    }
    if (invite.usedAt) throw new ControlFailure("token_used", "Invite was already used");
    if (invite.revokedAt) throw new ControlFailure("invalid_token", "Invite was revoked");
    if (Date.parse(invite.expiresAt) <= this.now()) throw new ControlFailure("token_expired", "Invite expired");
    if (!input.verifySignature(tokenHash)) throw new ControlFailure("bad_signature", "Device signature is not valid");
    const deviceKeyId = keyIdOf(input.devicePublicKey);
    // A device re-enrolling on the same lane replaces its earlier membership (enforced now, logged).
    for (const old of this.state.members)
      if (old.laneId === lane.id && old.deviceKeyId === deviceKeyId && old.status === "active") {
        old.status = "left";
        old.endedAt = this.iso();
        this.revokeLatestGrant(old.id);
        this.emit({ kind: "member_left", memberId: old.id, laneId: lane.id });
        this.record(lane.roomId, "member.left", "host", { memberId: old.id, laneId: lane.id, reason: "re_enrolled" });
      }
    const member = Member.parse({
      v: 1,
      id: randomHexId("mem_"),
      roomId: lane.roomId,
      laneId: lane.id,
      label: input.label,
      devicePublicKey: input.devicePublicKey,
      deviceKeyId,
      daemonServerId: input.daemonServerId,
      role: "watch",
      grantTtlSeconds: invite.grantTtlSeconds,
      joinedAt: this.iso(),
      status: "active",
      endedAt: null,
    });
    invite.usedAt = this.iso();
    invite.usedBy = member.id;
    this.state.members.push(member);
    const grant = this.issueFor(member, lane);
    this.save();
    this.record(lane.roomId, "member.joined", member.id, {
      memberId: member.id,
      laneId: lane.id,
      inviteId: invite.id,
      deviceKeyId,
      label: member.label,
      role: "watch",
    });
    return { member, ...grant };
  }

  private issueFor(member: Member, lane: Lane): { token: string; claims: GrantClaims } {
    const grant = issueGrant(this.hostKey, {
      roomId: lane.roomId,
      laneId: lane.id,
      laneServerId: lane.serverId,
      memberId: member.id,
      deviceKeyId: member.deviceKeyId,
      ttlSeconds: member.grantTtlSeconds,
      nowMs: this.now(),
    });
    this.state.grants = this.state.grants.filter((g) => g.memberId !== member.id);
    this.state.grants.push({ gid: grant.claims.gid, memberId: member.id, exp: grant.claims.exp });
    return grant;
  }

  /** Finds the active member for a device on a lane; throws a ControlFailure otherwise. */
  memberForDevice(laneId: string, devicePublicKey: string): Member {
    const lane = this.lane(laneId);
    if (!lane) throw new ControlFailure("unknown_lane", "Unknown lane");
    const deviceKeyId = keyIdOf(devicePublicKey);
    const members = this.state.members.filter((m) => m.laneId === laneId && m.deviceKeyId === deviceKeyId);
    const active = members.find((m) => m.status === "active");
    if (active) {
      if (lane.status !== "open") throw new ControlFailure("lane_closed", "Lane is closed");
      return active;
    }
    if (members.some((m) => m.status === "revoked")) throw new ControlFailure("revoked", "Membership was revoked");
    throw new ControlFailure("not_member", "Not a member of this lane");
  }

  renew(member: Member): { token: string; claims: GrantClaims } {
    const lane = this.lane(member.laneId)!;
    const previous = this.latestGrant(member.id);
    const grant = this.issueFor(member, lane);
    if (previous) {
      if (!this.state.revokedGrantIds.some((r) => r.gid === previous.gid)) this.state.revokedGrantIds.push(previous);
      this.emit({ kind: "grant_revoked", gid: previous.gid, laneId: lane.id });
    }
    this.record(lane.roomId, "grant.renewed", member.id, { memberId: member.id, laneId: lane.id, exp: grant.claims.exp });
    this.save();
    return grant;
  }

  leave(member: Member): void {
    if (member.status !== "active") return;
    member.status = "left";
    member.endedAt = this.iso();
    this.revokeLatestGrant(member.id);
    this.emit({ kind: "member_left", memberId: member.id, laneId: member.laneId });
    this.record(member.roomId, "member.left", member.id, { memberId: member.id, laneId: member.laneId });
    this.persistEnforced("Leaving");
  }

  verifyDeviceSignature(devicePublicKey: string, transcript: string, sig: string): boolean {
    return verifyEd25519(devicePublicKey, transcript, sig);
  }

  /** Full check used by the lane endpoint on link hello, every link open and every routed hello. */
  checkGrantLive(token: string, laneId: string, nowMs = this.now()): GrantLiveCheck {
    const lane = this.lane(laneId);
    if (!lane || lane.status !== "open") return { ok: false, reason: "lane_closed" };
    const check: GrantCheck = verifyGrant(
      token,
      { hostPublicKey: this.hostKey.publicKey, hostKeyId: this.hostKey.keyId, laneId: lane.id, laneServerId: lane.serverId },
      nowMs,
    );
    if (!check.ok) return { ok: false, reason: check.reason, claims: check.claims };
    const member = this.member(check.claims.sub);
    if (!member || member.laneId !== lane.id) return { ok: false, reason: "unknown_member", claims: check.claims };
    if (member.status !== "active") return { ok: false, reason: `member_${member.status}`, claims: check.claims };
    if (member.deviceKeyId !== check.claims.dev) return { ok: false, reason: "device_mismatch", claims: check.claims };
    if (this.state.revokedGrantIds.some((g) => g.gid === check.claims.gid)) return { ok: false, reason: "revoked_grant", claims: check.claims };
    // Allowlist (P-12, C-9): only the member's current grant is accepted, whatever the clock or the
    // denylist pruning does.
    if (this.latestGrant(member.id)?.gid !== check.claims.gid) return { ok: false, reason: "superseded_grant", claims: check.claims };
    return { ok: true, reason: "ok", claims: check.claims };
  }
}
