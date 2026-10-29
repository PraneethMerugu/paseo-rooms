// Member role: joined rooms on this (member) daemon. Holds the device key, enrolls through the lane
// endpoint's control channel, registers each lane as a connected host (context.paseo.hosts), watches
// the hosts directory and rotates the grant on authentication failure or near expiry (only when the
// lane reports no open routes for this member). The grant lives only in the daemon's hosts.json.
import { join } from "node:path";
import type { PaseoApi } from "@getpaseo/client";
import { serializeRelayConnectionUri } from "@getpaseo/protocol/daemon-endpoints";
import type { HostDirectory, HostSummary } from "@getpaseo/client";
import type { JoinedRoomView } from "../../shared/rpc";
import type { InvitePayload } from "../../shared/schemas";
import { generateEd25519, type StoredEd25519Key } from "../crypto";
import { decodeInviteCode } from "../invite-code";
import { log, logError } from "../log";
import { readJsonFile, writePrivateFile } from "../paths";
import { ControlClientError, controlRequest, type ControlResultFrame } from "./control-client";

export interface JoinedRoomRecord {
  v: 1;
  roomId: string;
  roomName: string;
  laneId: string;
  laneLabel: string;
  memberId: string;
  offer: InvitePayload["offer"];
  host: InvitePayload["host"];
  joinedAt: string;
  status: "active" | "revoked" | "left";
  registrationId: string | null;
  grantGid: string | null;
  grantIat: number | null;
  grantExp: number | null;
  lastRotationAt: string | null;
}

interface MemberFile {
  v: 1;
  rooms: JoinedRoomRecord[];
}

const AUTH_FAILURE_CODES = new Set(["authentication_failed", "auth_failed", "incorrect_password", "password_required"]);
const TERMINAL_CONTROL_CODES = new Set(["revoked", "not_member", "lane_closed", "unknown_lane"]);

export function laneConnectionUri(rec: Pick<JoinedRoomRecord, "offer">, grant: string): string {
  return serializeRelayConnectionUri({
    offer: {
      v: 2,
      serverId: rec.offer.serverId,
      daemonPublicKeyB64: rec.offer.publicKeyB64,
      relay: { endpoint: rec.offer.relay.endpoint, useTls: rec.offer.relay.useTls },
      minimumSecurityMode: "protected",
    },
    password: grant,
  } as Parameters<typeof serializeRelayConnectionUri>[0]);
}

export class MemberRole {
  private readonly file: string;
  private readonly deviceFile: string;
  private state: MemberFile;
  private device: StoredEd25519Key | null = null;
  private paseo: PaseoApi | null = null;
  private observation: { release(): Promise<void> } | null = null;
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly rotating = new Map<string, Promise<unknown>>();
  private readonly lastHost = new Map<string, HostSummary>();
  private readonly authRetryAt = new Map<string, number>();
  /** Lanes whose rotation timer fired before the PaseoApi was available (C-12). */
  private readonly pendingRotations = new Set<string>();
  private stopped = false;

  constructor(dataDir: string, private readonly pluginId = "rooms") {
    this.file = join(dataDir, "member", "rooms.json");
    this.deviceFile = join(dataDir, "member", "device.json");
    this.state = readJsonFile<MemberFile>(this.file) ?? { v: 1, rooms: [] };
  }

  private save(): void {
    writePrivateFile(this.file, JSON.stringify(this.state, null, 2));
  }

  private deviceKey(): StoredEd25519Key {
    if (this.device) return this.device;
    let key = readJsonFile<StoredEd25519Key>(this.deviceFile);
    if (!key) {
      key = generateEd25519();
      writePrivateFile(this.deviceFile, JSON.stringify(key, null, 2));
      log("device_key_created", { keyId: key.keyId });
    }
    this.device = key;
    return key;
  }

  get rooms(): readonly JoinedRoomRecord[] {
    return this.state.rooms;
  }

  /**
   * Arms rotation timers from rooms.json at plugin start (C-12), before any PaseoApi exists. A timer
   * that fires before attach() is parked and runs as soon as the API arrives; the renewal itself needs
   * only the device key, but registering the new grant (hosts.update) needs the API, and renewing
   * without registering would revoke the grant the member daemon still uses.
   */
  start(): void {
    if (this.stopped) return;
    for (const rec of this.state.rooms) if (rec.status === "active") this.schedule(rec);
    const armed = this.timers.size;
    if (armed) log("member_timers_armed", { lanes: armed });
  }

  /** Called with the plugin's PaseoApi on first contact (RPC, hook or UI). Starts observation. */
  attach(paseo: PaseoApi): void {
    if (this.paseo || this.stopped) return;
    this.paseo = paseo;
    this.observe();
    const pending = [...this.pendingRotations];
    this.pendingRotations.clear();
    for (const rec of this.state.rooms) {
      if (rec.status !== "active") continue;
      if (pending.includes(rec.laneId)) void this.onTimer(rec.laneId);
      else this.schedule(rec);
    }
  }

  /** For tests and the overview: lanes with an armed rotation timer, and parked rotations. */
  timerState(): { armed: string[]; pending: string[] } {
    return { armed: [...this.timers.keys()], pending: [...this.pendingRotations] };
  }

  private observe(): void {
    const paseo = this.paseo!;
    try {
      const sub = paseo.hosts.observe();
      this.observation = sub;
      const apply = (dir: HostDirectory | undefined) => dir && this.onDirectory(dir);
      sub.subscribe({
        snapshot: (snap: any) => apply(snap?.hosts ? snap : snap?.directory ?? snap?.value),
        update: (m: any) => {
          if (m?.type === "hosts.changed") apply(m.payload?.directory);
        },
        error: (e: unknown) => logError("hosts_observe_error", e),
      });
      void sub.ready.then((snap: any) => apply(snap?.hosts ? snap : snap?.directory ?? snap?.value)).catch((e) => logError("hosts_observe_failed", e));
    } catch (e) {
      logError("hosts_observe_unavailable", e);
    }
  }

  private recordFor(h: HostSummary): JoinedRoomRecord | undefined {
    const laneId = h.metadata?.["rooms.laneId"] ?? h.source?.key;
    return this.state.rooms.find((r) => r.laneId === laneId && (r.registrationId === h.registrationId || h.source?.key === r.laneId));
  }

  private onDirectory(dir: HostDirectory): void {
    for (const h of dir.hosts) {
      const rec = this.recordFor(h);
      if (!rec || rec.status !== "active") continue;
      const prev = this.lastHost.get(rec.laneId);
      this.lastHost.set(rec.laneId, h);
      if (prev?.status !== h.status) log("lane_host_status", { laneId: rec.laneId, status: h.status, error: h.error?.code ?? null });
      if (h.status === "error" && h.error && AUTH_FAILURE_CODES.has(h.error.code)) {
        const now = Date.now();
        if ((this.authRetryAt.get(rec.laneId) ?? 0) > now) continue;
        this.authRetryAt.set(rec.laneId, now + 15_000);
        log("lane_auth_failed", { laneId: rec.laneId, action: "rotate" });
        void this.rotate(rec.laneId, { force: true, reason: "auth_failed" }).catch((e) => logError("rotate_failed", e, { laneId: rec.laneId }));
      }
    }
  }

  // ------------------------------------------------------------------ scheduling (no polling)
  private schedule(rec: JoinedRoomRecord, delayMs?: number): void {
    const old = this.timers.get(rec.laneId);
    if (old) clearTimeout(old);
    if (this.stopped || rec.status !== "active" || !rec.grantExp || !rec.grantIat) return;
    const nowS = Date.now() / 1000;
    const ttl = rec.grantExp - rec.grantIat;
    const halfLife = rec.grantIat + ttl / 2;
    const ms = delayMs ?? Math.max(1000, (halfLife - nowS) * 1000);
    const t = setTimeout(() => void this.onTimer(rec.laneId), Math.min(ms, 2 ** 31 - 1));
    this.timers.set(rec.laneId, t);
  }

  private async onTimer(laneId: string): Promise<void> {
    const rec = this.state.rooms.find((r) => r.laneId === laneId);
    if (!rec || rec.status !== "active" || !rec.grantExp || !rec.grantIat) return;
    this.timers.delete(laneId);
    if (!this.paseo) {
      if (!this.pendingRotations.has(laneId)) log("rotation_waiting_for_api", { laneId });
      this.pendingRotations.add(laneId);
      return;
    }
    const reason = rec.grantExp * 1000 <= Date.now() ? "expired" : "near_expiry";
    const res = await this.rotate(laneId, { force: false, reason }).catch((e) => {
      logError("rotate_failed", e, { laneId });
      return null;
    });
    if (res?.rotated) return;
    // Busy or failed: retry at a quarter of the remaining lifetime, at least 5 s. After expiry the
    // lane cuts the link and the auth-failure path rotates.
    const remainingMs = rec.grantExp * 1000 - Date.now();
    if (remainingMs > 2000) this.schedule(rec, Math.max(5000, remainingMs / 4));
  }

  // ------------------------------------------------------------------ operations
  private requirePaseo(): PaseoApi {
    if (!this.paseo) throw new Error("Rooms member role is not attached yet");
    return this.paseo;
  }

  async join(paseo: PaseoApi, code: string, label?: string): Promise<JoinedRoomRecord> {
    this.attach(paseo);
    const invite = decodeInviteCode(code);
    if (invite.exp * 1000 <= Date.now()) throw new Error("This invite has expired. Ask the room owner for a new one.");
    const device = this.deviceKey();
    let self: string | null = null;
    try {
      self = (await paseo.hosts.list()).self.serverId;
    } catch {}
    const res = await controlRequest({
      op: "enroll",
      laneId: invite.laneId,
      offer: invite.offer,
      host: invite.host,
      device,
      token: invite.token,
      label: label ?? `Member ${device.keyId.slice(0, 6)}`,
      daemonServerId: self,
    });
    if (!res.grant || !res.claims) throw new Error("Lane did not return a grant");
    const existing = this.state.rooms.find((r) => r.laneId === invite.laneId);
    const rec: JoinedRoomRecord = {
      v: 1,
      roomId: invite.roomId,
      roomName: res.room.roomName,
      laneId: invite.laneId,
      laneLabel: res.room.laneLabel,
      memberId: res.member.id,
      offer: invite.offer,
      host: invite.host,
      joinedAt: new Date().toISOString(),
      status: "active",
      registrationId: existing?.registrationId ?? null,
      grantGid: res.claims.gid,
      grantIat: res.claims.iat,
      grantExp: res.claims.exp,
      lastRotationAt: null,
    };
    rec.registrationId = await this.register(paseo, rec, res.grant);
    this.state.rooms = [...this.state.rooms.filter((r) => r.laneId !== rec.laneId), rec];
    this.save();
    this.schedule(rec);
    log("room_joined", { roomId: rec.roomId, laneId: rec.laneId, memberId: rec.memberId, registrationId: rec.registrationId, exp: new Date(rec.grantExp! * 1000).toISOString() });
    return rec;
  }

  /** Adds or updates the connected-host registration. The connection (with grant) is never logged. */
  private async register(paseo: PaseoApi, rec: JoinedRoomRecord, grant: string): Promise<string> {
    const connection = laneConnectionUri(rec, grant);
    const label = `${rec.roomName} · ${rec.laneLabel}`;
    const metadata = { "rooms.roomId": rec.roomId, "rooms.laneId": rec.laneId, "rooms.role": "lane" };
    let registrationId = rec.registrationId;
    if (!registrationId) {
      const dir = await paseo.hosts.list();
      registrationId = dir.hosts.find((h) => h.source?.key === rec.laneId && h.source?.id === `plugin:${this.pluginId}`)?.registrationId ?? null;
    }
    if (registrationId) {
      const h = await paseo.hosts.update(registrationId, { connection, label, metadata, enabled: true });
      return h.registrationId;
    }
    const h = await paseo.hosts.add({ connection, label, sourceKey: rec.laneId, metadata });
    return h.registrationId;
  }

  async rotate(laneId: string, opts: { force: boolean; reason: string }): Promise<{ rotated: boolean; reason: string }> {
    const inflight = this.rotating.get(laneId);
    if (inflight) return (await inflight) as { rotated: boolean; reason: string };
    const p = this.rotateInner(laneId, opts).finally(() => this.rotating.delete(laneId));
    this.rotating.set(laneId, p);
    return p;
  }

  private async rotateInner(laneId: string, opts: { force: boolean; reason: string }): Promise<{ rotated: boolean; reason: string }> {
    const paseo = this.requirePaseo();
    const rec = this.state.rooms.find((r) => r.laneId === laneId);
    if (!rec) throw new Error("Not a member of this lane");
    if (rec.status !== "active") return { rotated: false, reason: rec.status };
    const device = this.deviceKey();
    const base = { laneId, offer: rec.offer, host: rec.host, device };
    try {
      if (!opts.force) {
        const status = await controlRequest({ ...base, op: "status" });
        if (status.activeRoutes > 0) {
          log("rotate_deferred", { laneId, activeRoutes: status.activeRoutes, reason: opts.reason });
          return { rotated: false, reason: "busy" };
        }
      }
      const res: ControlResultFrame = await controlRequest({ ...base, op: "renew" });
      if (!res.grant || !res.claims) throw new Error("Lane did not return a grant");
      rec.registrationId = await this.register(paseo, rec, res.grant);
      rec.grantGid = res.claims.gid;
      rec.grantIat = res.claims.iat;
      rec.grantExp = res.claims.exp;
      rec.lastRotationAt = new Date().toISOString();
      this.save();
      this.schedule(rec);
      this.authRetryAt.delete(laneId);
      log("grant_rotated", { laneId, reason: opts.reason, gid: res.claims.gid, exp: new Date(res.claims.exp * 1000).toISOString() });
      return { rotated: true, reason: opts.reason };
    } catch (e) {
      if (e instanceof ControlClientError && TERMINAL_CONTROL_CODES.has(e.code)) {
        await this.end(rec, e.code === "revoked" ? "revoked" : "left", `control:${e.code}`);
        return { rotated: false, reason: e.code };
      }
      throw e;
    }
  }

  async leave(laneId: string): Promise<void> {
    const rec = this.state.rooms.find((r) => r.laneId === laneId);
    if (!rec) throw new Error("Not a member of this lane");
    if (rec.status === "active") {
      try {
        await controlRequest({ op: "leave", laneId, offer: rec.offer, host: rec.host, device: this.deviceKey() });
      } catch (e) {
        logError("leave_notify_failed", e, { laneId });
      }
    }
    await this.end(rec, "left", "user_leave");
  }

  /** Removal: drop the connected-host registration and the stored grant. */
  private async end(rec: JoinedRoomRecord, status: "revoked" | "left", why: string): Promise<void> {
    const t = this.timers.get(rec.laneId);
    if (t) clearTimeout(t);
    this.timers.delete(rec.laneId);
    if (rec.registrationId && this.paseo) {
      try {
        await this.paseo.hosts.remove(rec.registrationId);
      } catch (e) {
        logError("host_remove_failed", e, { laneId: rec.laneId });
      }
    }
    rec.status = status;
    rec.registrationId = null;
    rec.grantGid = null;
    this.save();
    log("room_membership_ended", { laneId: rec.laneId, status, why });
  }

  view(): JoinedRoomView[] {
    return this.state.rooms.map((r) => {
      const h = this.lastHost.get(r.laneId);
      return {
        roomId: r.roomId,
        roomName: r.roomName,
        laneId: r.laneId,
        laneLabel: r.laneLabel,
        memberId: r.memberId,
        joinedAt: r.joinedAt,
        status: r.status,
        hostStatus: r.status === "active" ? (h?.status ?? null) : null,
        hostError: r.status === "active" ? (h?.error?.code ?? null) : null,
        laneServerId: r.offer.serverId,
        grantExpiresAt: r.grantExp && r.status === "active" ? new Date(r.grantExp * 1000).toISOString() : null,
        lastRotationAt: r.lastRotationAt,
      };
    });
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
    this.pendingRotations.clear();
    await this.observation?.release().catch(() => undefined);
  }
}
