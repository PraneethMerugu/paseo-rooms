// MLS delivery service on the room host (mls-integration.md sections 6.1 to 6.4, 8.2, 8.4; room-log-v2.md
// 2 and 4.5; implementation plan I-13). Served on active devices' room sessions by room-endpoint.ts.
//
// The host stores KeyPackages and Welcomes and sequences MLS messages in the room log. It cannot read
// commits or application messages (PrivateMessage) and is trusted for availability only: members
// validate every commit (server/mls/member.ts) and every fetched KeyPackage.
//
// - `kp.publish` (6.4): only an active device, for itself; every package must decode as a suite-1
//   KeyPackage listing 0xF0A1, carry a credential passing rules 1 to 5 of 4.1 with the caller's ids,
//   `deviceSig` equal to the caller's roster key (`current`) or the `newSig` of its pending rekey
//   (`rekey`), a valid signature, a lifetime that has started and ends at most 30 days ahead, and a
//   KeyPackageRef this room never stored. At most 10 single-use packages and one last-resort per pool.
// - `kp.fetch` (6.4, round 7 and round 8): `current` packages of active devices for any active device
//   (every active device shares the room group); `rekey` packages for admin devices only, for a device
//   with a pending rekey; `{ref}` only for an open repair request naming it. Single-use packages are
//   deleted when served and the deletion is written before the reply. Caps per hour: `g + 2` per target
//   and pool, `k` per fetcher, target and pool; beyond either only the last-resort package is served.
// - `commit.submit` (6.1, 6.2): one commit per epoch and group, `stale_epoch`, `stale_roster` when the
//   authenticated data does not name the current roster, and `device.rekey.approved` only here, written
//   with the commit as two adjacent entries in one durable write or not at all (RoomHost).
// - `welcome.fetch`: the oldest Welcome naming one of the caller's KeyPackageRefs that it has not
//   acknowledged, with the signed entry of its commit; `ack` drops it for that device.
// - `msg.send`, `msg.fetch`, `msg.ack` (8.2, 8.4): application messages are `mls.app` entries; the last
//   acknowledged position is returned as `lastAck` in `session.hello.ok`.
// - Pushes: `pending_remove {seq}` (6.3) after a roster change that removed a device, and on session
//   open while the room group has not committed since; `kp.low` (6.4).
// - `mls.stalled` (6.2): a room group commit that some device that acknowledged before has not
//   acknowledged 5 minutes later is logged once.
//
// State: `host/<roomId>/mls.sealed` (pools, the refs ever stored, Welcomes, acknowledgements), written
// before every reply that depends on it. Welcomes are written before the commit's log append; on load,
// a Welcome whose entry is missing or carries another body is dropped. Group epochs come from the log.
// Nothing here logs package bytes, Welcomes or messages.
import nodePath from "node:path";
import { z } from "zod";
import { bodyHash, type SignedEntry } from "../authority/entries";
import type { RoomState } from "../authority/state";
import { buildRoster, rosterHash } from "../authority/roster";
import type { RosterEntry } from "../authority/schema";
import type { Kek } from "../keystore/keystore";
import { log } from "../log";
import { b64u, b64uDecodeVar } from "../proto/b64u";
import { rjcs, rjcsParse } from "../proto/rjcs";
import type { RoomErrorCode } from "../transport/room-session";
import { AUTHORITY_EXTENSION_TYPE, MLS_MESSAGE_MAX_BYTES, MLS_SUITE, type MlsAdapter } from "../mls/adapter";
import { identitySigValid, mlsGroupId, parseAad, parseMlsIdentity } from "../mls/formats";
import { hostRoomDir } from "./room-log-store";
import type { RoomHost } from "./room-host";

export const MLS_FILE = "mls.sealed";
export const hostMlsPurpose = (roomId: string) => `host-mls:${roomId}`;
export const hostMlsPath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), MLS_FILE);

export const KP_POOL_MAX = 10;
export const KP_MAX_LIFETIME_S = 30 * 24 * 3600;
export const KP_FETCH_TARGETS_MAX = 8;
export const MSG_FETCH_MAX = 500;
export const STALLED_AFTER_MS = 5 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const REPAIR_OPEN_MS = 24 * HOUR_MS;
const WELCOMES_MAX = 256;
const REPLY_BUDGET = 3 * 1024 * 1024;
const LIFETIME_SKEW_S = 300;

/** Session operations served here (enrollment-v2.md 4). */
export const MLS_OPS: ReadonlySet<string> = new Set(["kp.publish", "kp.fetch", "commit.submit", "welcome.fetch", "msg.send", "msg.fetch", "msg.ack"]);

export type DsAccess = { memberId: string; deviceId: string; role: string; sigKid: string };
export type DsReply = { ok: true; frame: Record<string, unknown> } | { ok: false; code: RoomErrorCode; fields?: Record<string, unknown> };

type Pkg = { ref: string; kp: string };
type Pool = { sig: string; single: Pkg[]; lastResort: Pkg | null };
type PoolName = "current" | "rekey";

const PkgS = z.strictObject({ ref: z.string().max(64), kp: z.string().max(64 * 1024) });
const PoolS = z.strictObject({ sig: z.string().max(64), single: z.array(PkgS).max(KP_POOL_MAX), lastResort: PkgS.nullable() });
const FileS = z.strictObject({
  v: z.literal(2),
  typ: z.literal("host-mls"),
  roomId: z.string(),
  pools: z.record(z.string(), z.strictObject({ current: PoolS.nullable(), rekey: PoolS.nullable() })),
  /** Every KeyPackageRef ever stored for this room, with its device (RJCS keys cannot hold base64url). */
  refs: z.array(z.tuple([z.string().max(64), z.string().max(64)])).max(1_000_000),
  welcomes: z.array(z.strictObject({ seq: z.number().int().min(0), commitHash: z.string(), welcome: z.string(), targets: z.array(z.string()).max(64), at: z.number().int() })).max(WELCOMES_MAX),
  acks: z.record(z.string(), z.strictObject({ seq: z.number().int().min(-1), epoch: z.number().int().min(0) })),
});
type HostMlsFile = z.infer<typeof FileS>;

export interface MlsDeliveryOptions {
  dataDir: string;
  kek: Kek;
  host: RoomHost;
  adapter: MlsAdapter;
  now?: () => number;
  /** Sends an event frame to a device's session (or the owner's local device). */
  push?: (deviceId: string, frame: Record<string, unknown>) => boolean;
  /** Called after every log append made here (sessions, pushes, subscribers). */
  afterAppend?: () => void;
  /** After a stored `current` publication (the admitting admin daemon's prompt Add, round 9 item 5). */
  onPublished?: (deviceId: string) => void;
  stalledAfterMs?: number;
}

const isB64uText = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max && /^[A-Za-z0-9_-]+$/.test(v);
const isInt = (v: unknown, min: number, max = Number.MAX_SAFE_INTEGER): v is number => Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max;

export class MlsDelivery {
  readonly roomId: string;
  private f: HostMlsFile;
  /** `f.refs` as a map: ref -> deviceId. */
  private refs = new Map<string, string>();
  /** b64u groupId -> epoch of the group after its last commit in the log. */
  private readonly epochs = new Map<string, number>();
  private lastRoomCommit: { seq: number; hts: number; epoch: number } | null = null;
  private stalledReported = -1;
  /** Single-use packages served in the last hour: target, pool, fetcher. */
  private served: { t: number; target: string; pool: PoolName; fetcher: string }[] = [];
  private rosterKeys = new Map<string, string>();
  private lastRemovalSeq = -1;
  private readonly roomGroup: string;
  private readonly now: () => number;

  constructor(private readonly o: MlsDeliveryOptions) {
    this.roomId = o.host.roomId;
    this.now = o.now ?? Date.now;
    this.roomGroup = b64u(mlsGroupId(o.host.genesisHash, 0));
    this.f = { v: 2, typ: "host-mls", roomId: this.roomId, pools: {}, refs: [], welcomes: [], acks: {} };
    this.load();
    for (const r of o.host.entries()) this.trackEntry(r.signed, r.body);
    this.rosterKeys = deviceKeys(o.host.state.members);
    this.follow();
  }

  /** The device's last acknowledged position (enrollment-v2 4.1 `lastAck`). */
  lastAck(deviceId: string): { seq: number; epoch: number } | null {
    return this.f.acks[deviceId] ?? null;
  }

  /** Epoch of a group in the log (0 before its first commit). */
  epochOf(groupId: string): number {
    return this.epochs.get(groupId) ?? 0;
  }

  handle(access: DsAccess, frame: Record<string, unknown>): DsReply {
    switch (frame.t) {
      case "kp.publish":
        return this.publish(access, frame);
      case "kp.fetch":
        return this.fetchPackages(access, frame);
      case "commit.submit":
        return this.submitCommit(access, frame);
      case "welcome.fetch":
        return this.fetchWelcome(access, frame);
      case "msg.send":
        return this.sendMessage(frame);
      case "msg.fetch":
        return this.fetchMessages(frame);
      case "msg.ack":
        return this.ack(access, frame);
      default:
        return { ok: false, code: "bad_frame" };
    }
  }

  /** After every append to the room log (from any path): pools follow the fold; removals are pushed. */
  onAppended(): void {
    const host = this.o.host;
    for (const r of host.entries(this.trackedTo + 1)) this.trackEntry(r.signed, r.body);
    const keys = deviceKeys(host.state.members);
    let removed = false;
    for (const [dev, sig] of this.rosterKeys) if (keys.get(dev) !== sig) removed = true;
    this.rosterKeys = keys;
    if (removed) {
      this.lastRemovalSeq = host.state.rosterSeq;
      for (const dev of keys.keys()) this.o.push?.(dev, { t: "pending_remove", seq: host.state.rosterSeq });
    }
    this.follow();
  }

  /** A device's session opened: a removal the room group has not committed yet is pushed again. */
  onSessionOpen(deviceId: string): void {
    if (this.lastRemovalSeq >= 0 && (this.lastRoomCommit?.seq ?? -1) < this.lastRemovalSeq) this.o.push?.(deviceId, { t: "pending_remove", seq: this.lastRemovalSeq });
  }

  /** `mls.stalled` (6.2). Call periodically. */
  tick(): void {
    const c = this.lastRoomCommit;
    if (!c || c.seq === this.stalledReported || this.o.host.isStopped) return;
    const since = this.now() - c.hts;
    if (since < (this.o.stalledAfterMs ?? STALLED_AFTER_MS)) return;
    const behind = [...this.rosterKeys.keys()].some((d) => {
      const a = this.f.acks[d];
      return a !== undefined && a.seq >= 0 && a.seq < c.seq;
    });
    if (!behind) return;
    this.stalledReported = c.seq;
    try {
      this.o.host.emit("mls.stalled", { epoch: c.epoch, sinceMs: Math.max(0, Math.round(since)) });
      log("mls_stalled", { roomId: this.roomId, epoch: c.epoch });
      this.o.afterAppend?.();
    } catch (e) {
      log("mls_stalled_emit_failed", { roomId: this.roomId, error: String((e as Error)?.message ?? e).slice(0, 120) });
    }
  }

  /** Pool sizes (owner view and tests). */
  poolView(deviceId: string): { current: number; currentLastResort: boolean; rekey: number; rekeyLastResort: boolean } {
    const p = this.f.pools[deviceId];
    return { current: p?.current?.single.length ?? 0, currentLastResort: !!p?.current?.lastResort, rekey: p?.rekey?.single.length ?? 0, rekeyLastResort: !!p?.rekey?.lastResort };
  }

  // ------------------------------------------------------------------------------ kp.publish

  private publish(access: DsAccess, frame: Record<string, unknown>): DsReply {
    const pool = frame.for;
    const list = frame.keyPackages;
    const lr = frame.lastResort;
    if ((pool !== "current" && pool !== "rekey") || !Array.isArray(list) || list.length > KP_POOL_MAX || (lr !== undefined && !isB64uText(lr, 64 * 1024))) return { ok: false, code: "bad_frame" };
    if (!list.every((x) => isB64uText(x, 64 * 1024))) return { ok: false, code: "bad_frame" };
    const st = this.o.host.state;
    const dev = st.members[access.memberId]?.devices.find((d) => d.deviceId === access.deviceId);
    if (!dev) return { ok: false, code: "not_permitted" };
    let sig: string;
    if (pool === "current") sig = dev.sig;
    else {
      const req = Object.values(st.pending).find((p) => p.kind === "rekey" && p.status === "pending" && p.deviceId === access.deviceId && p.memberId === access.memberId);
      if (!req) return { ok: false, code: "not_permitted" };
      sig = req.device.sig;
    }
    const nowS = Math.floor(this.now() / 1000);
    const checked: Pkg[] = [];
    const seen = new Set<string>();
    for (const text of [...list, ...(lr === undefined ? [] : [lr])] as string[]) {
      const ref = this.checkPackage(text, access, sig, nowS);
      if (!ref || seen.has(ref)) return { ok: false, code: "not_permitted" };
      seen.add(ref);
      checked.push({ ref, kp: text });
    }
    const pools = (this.f.pools[access.deviceId] ??= { current: null, rekey: null });
    const target: Pool = pools[pool] && pools[pool]!.sig === sig ? pools[pool]! : { sig, single: [], lastResort: null };
    const singles = lr === undefined ? checked : checked.slice(0, -1);
    if (target.single.length + singles.length > KP_POOL_MAX) return { ok: false, code: "not_permitted" };
    const next: Pool = { sig, single: [...target.single, ...singles], lastResort: lr === undefined ? target.lastResort : checked.at(-1)! };
    const before = structuredClone(this.f);
    pools[pool] = next;
    for (const c of checked) this.f.refs.push([c.ref, access.deviceId]);
    if (!this.persist("kp.publish")) {
      this.f = before;
      return { ok: false, code: "persist_failed" };
    }
    for (const c of checked) this.refs.set(c.ref, access.deviceId);
    if (pool === "current" && checked.length > 0) queueMicrotask(() => this.o.onPublished?.(access.deviceId));
    return { ok: true, frame: { t: "kp.publish.ok", stored: singles.length, lastResort: next.lastResort !== null } };
  }

  /** Publishing rules 1 to 5 of 6.4. Returns the KeyPackageRef, or null. */
  private checkPackage(text: string, access: DsAccess, sig: string, nowS: number): string | null {
    try {
      const info = this.o.adapter.decodeKeyPackage(b64uDecodeVar(text, 64 * 1024));
      if (info.suite !== MLS_SUITE || info.version !== "mls10" || !info.capabilityExtensions.includes(AUTHORITY_EXTENSION_TYPE)) return null;
      if (info.credentialType !== "basic" || !info.identity) return null;
      const p = parseMlsIdentity(info.identity);
      if (!p || p.id.roomId !== this.roomId || p.id.memberId !== access.memberId || p.id.deviceId !== access.deviceId) return null;
      if (Buffer.compare(Buffer.from(p.id.mlsSig, "base64url"), Buffer.from(info.signaturePublicKey)) !== 0 || !identitySigValid(p)) return null;
      if (p.id.deviceSig !== sig) return null;
      if (!info.signatureValid) return null;
      if (info.notBefore > nowS + LIFETIME_SKEW_S || info.notAfter > nowS + KP_MAX_LIFETIME_S + LIFETIME_SKEW_S || info.notAfter <= nowS) return null;
      if (this.refs.has(info.ref)) return null;
      return info.ref;
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------------------------ kp.fetch

  private fetchPackages(access: DsAccess, frame: Record<string, unknown>): DsReply {
    const targets = frame.targets;
    if (!Array.isArray(targets) || targets.length < 1 || targets.length > KP_FETCH_TARGETS_MAX) return { ok: false, code: "bad_frame" };
    const st = this.o.host.state;
    const fetcher = st.members[access.memberId];
    if (!fetcher?.devices.some((d) => d.deviceId === access.deviceId)) return { ok: false, code: "not_permitted" };
    type T = { memberId: string; deviceId: string; pool: PoolName; count: number; ref: string | null };
    const parsed: T[] = [];
    for (const t of targets as Record<string, unknown>[]) {
      if (!t || typeof t !== "object" || typeof t.memberId !== "string" || typeof t.deviceId !== "string") return { ok: false, code: "bad_frame" };
      const keys = Object.keys(t).sort().join(",");
      if (keys === "count,deviceId,for,memberId") {
        if ((t.for !== "current" && t.for !== "rekey") || !isInt(t.count, 1, KP_POOL_MAX)) return { ok: false, code: "bad_frame" };
        parsed.push({ memberId: t.memberId, deviceId: t.deviceId, pool: t.for, count: t.count, ref: null });
      } else if (keys === "deviceId,memberId,ref") {
        if (!isB64uText(t.ref, 43)) return { ok: false, code: "bad_frame" };
        parsed.push({ memberId: t.memberId, deviceId: t.deviceId, pool: "current", count: 1, ref: t.ref as string });
      } else return { ok: false, code: "bad_frame" };
    }
    // Authorization for the whole frame first (6.4 "Targets").
    const nowMs = this.now();
    for (const t of parsed) {
      const target = st.members[t.memberId];
      const dev = target?.devices.find((d) => d.deviceId === t.deviceId);
      if (t.ref !== null) {
        const req = openRepair(st, t.memberId, t.deviceId, t.ref, nowMs);
        if (!dev || !req || !sharesGroup(st, access.memberId, t.memberId, req.scope)) return { ok: false, code: "not_permitted" };
      } else if (t.pool === "current") {
        if (!dev) return { ok: false, code: "not_permitted" };
      } else {
        const gateway = dev?.kind === "gateway";
        const allowed = fetcher.role === "admin" || (fetcher.role === "maintain" && gateway);
        const pending = Object.values(st.pending).some((p) => p.kind === "rekey" && p.status === "pending" && p.deviceId === t.deviceId && p.memberId === t.memberId);
        if (!allowed || !dev || !pending) return { ok: false, code: "not_permitted" };
      }
    }
    this.served = this.served.filter((s) => nowMs - s.t < HOUR_MS);
    const before = structuredClone(this.f);
    const servedBefore = this.served.slice();
    const results: { deviceId: string; keyPackages: string[]; lastResort: string | null }[] = [];
    const low: { deviceId: string; pool: PoolName; remaining: number }[] = [];
    let changed = false;
    for (const t of parsed) {
      const pool = this.f.pools[t.deviceId]?.[t.pool] ?? null;
      const g = 1 + scopesOf(st, t.memberId).length;
      const gateway = st.members[t.memberId]?.devices.find((d) => d.deviceId === t.deviceId)?.kind === "gateway";
      const k = fetcher.role === "admin" || (fetcher.role === "maintain" && gateway) ? g : 1 + scopesOf(st, t.memberId).filter((s) => (st.auth.scopes[s] ?? []).includes(access.memberId)).length;
      const servedTarget = () => this.served.filter((s) => s.target === t.deviceId && s.pool === t.pool).length;
      const servedByMe = () => this.served.filter((s) => s.target === t.deviceId && s.pool === t.pool && s.fetcher === access.deviceId).length;
      const out = { deviceId: t.deviceId, keyPackages: [] as string[], lastResort: null as string | null };
      if (t.ref !== null) {
        // By reference: that one package, single use, never substituted (round 8).
        const i = pool ? pool.single.findIndex((p) => p.ref === t.ref) : -1;
        if (pool && i >= 0 && servedTarget() < g + 2 && servedByMe() < k) {
          out.keyPackages.push(pool.single[i].kp);
          pool.single.splice(i, 1);
          this.served.push({ t: nowMs, target: t.deviceId, pool: t.pool, fetcher: access.deviceId });
          changed = true;
        }
        results.push(out);
        continue;
      }
      let need = t.count;
      while (pool && need > 0 && pool.single.length > 0 && servedTarget() < g + 2 && servedByMe() < k) {
        out.keyPackages.push(pool.single.shift()!.kp);
        this.served.push({ t: nowMs, target: t.deviceId, pool: t.pool, fetcher: access.deviceId });
        need--;
        changed = true;
      }
      if (need > 0 && pool?.lastResort) out.lastResort = pool.lastResort.kp;
      if (!pool || pool.single.length <= 2 || out.lastResort !== null || out.keyPackages.length + (out.lastResort ? 1 : 0) === 0) low.push({ deviceId: t.deviceId, pool: t.pool, remaining: pool?.single.length ?? 0 });
      results.push(out);
    }
    if (changed && !this.persist("kp.fetch")) {
      this.f = before;
      this.served = servedBefore;
      return { ok: false, code: "persist_failed" };
    }
    for (const l of low) this.o.push?.(l.deviceId, { t: "kp.low", for: l.pool, remaining: l.remaining });
    return { ok: true, frame: { t: "kp.fetch.ok", results } };
  }

  // ------------------------------------------------------------------------------ commit.submit

  private submitCommit(access: DsAccess, frame: Record<string, unknown>): DsReply {
    const { epoch, commit, welcome, statement } = frame;
    if (!isInt(epoch, 0) || !isB64uText(commit, Math.ceil((MLS_MESSAGE_MAX_BYTES * 4) / 3)) || (welcome !== undefined && !isB64uText(welcome, Math.ceil((MLS_MESSAGE_MAX_BYTES * 4) / 3)))) return { ok: false, code: "bad_frame" };
    if (frame.ratchetTree !== undefined && frame.ratchetTree !== null) return { ok: false, code: "bad_frame" };
    const host = this.o.host;
    let bytes: Uint8Array;
    let peek: ReturnType<MlsAdapter["peek"]>;
    try {
      bytes = b64uDecodeVar(commit as string, MLS_MESSAGE_MAX_BYTES);
      peek = this.o.adapter.peek(bytes);
    } catch {
      return { ok: false, code: "not_permitted" };
    }
    if (peek.wireformat !== "mls_private_message" || peek.contentType !== "commit" || peek.epoch !== epoch) return { ok: false, code: "not_permitted" };
    const group = b64u(peek.groupId);
    if (!this.knownGroup(group)) return { ok: false, code: "not_permitted" };
    const current = this.epochOf(group);
    if (epoch !== current) return { ok: false, code: "stale_epoch", fields: { epoch: current } };
    let aad: ReturnType<typeof parseAad>;
    try {
      aad = parseAad(peek.authenticatedData);
    } catch {
      return { ok: false, code: "not_permitted" };
    }
    let welcomeRec: { welcome: string; targets: string[] } | null = null;
    if (welcome !== undefined) {
      try {
        const w = this.o.adapter.peek(b64uDecodeVar(welcome as string, MLS_MESSAGE_MAX_BYTES));
        if (w.wireformat !== "mls_welcome" || w.suite !== MLS_SUITE) return { ok: false, code: "not_permitted" };
        welcomeRec = { welcome: welcome as string, targets: [...new Set(w.refs.map((r) => this.refs.get(r)).filter((d): d is string => !!d))] };
      } catch {
        return { ok: false, code: "not_permitted" };
      }
    }
    const isRoom = group === this.roomGroup;
    const epochAfter = isRoom ? current + 1 : host.state.epoch;
    const commitHash = bodyHash(bytes);
    const rosterOf = (s: Readonly<RoomState>) => ({ seq: s.rosterSeq, hash: rosterHash(buildRoster(s.roomId, s.rosterSeq, s.members as Record<string, RosterEntry>)) });

    if (statement !== undefined) {
      // device.rekey.approved travels only here, from an admin device, for the room group (4.4).
      const producer = (statement as { body?: { producer?: { kind?: unknown } } } | null)?.body?.producer;
      if (!isRoom || access.role !== "admin" || producer?.kind !== "admin") return { ok: false, code: "not_permitted" };
      const seq = host.head.seq + 2;
      const stage = this.stageWelcome(welcomeRec, seq, commitHash);
      if (stage === "persist_failed") return { ok: false, code: "persist_failed" };
      const r = host.submitWithCommit(statement, bytes, epochAfter, (next) => {
        const want = rosterOf(next);
        return aad.roster.seq === want.seq && aad.roster.hash === want.hash ? null : { code: "stale_roster", fields: { roster: want } };
      });
      if (!r.ok) {
        this.unstageWelcome(seq);
        if (r.code === "commit_refused") return { ok: false, code: "stale_roster", fields: r.refusal.fields };
        const head = r.head ? { seq: r.head.entry.seq, hash: r.head.hash } : { seq: -1, hash: host.genesisHash };
        return { ok: false, code: r.code, fields: r.code === "not_permitted" ? {} : { head } };
      }
      this.o.afterAppend?.();
      log("mls_rekey_pair", { roomId: this.roomId, seq: r.statement.entry.seq });
      return { ok: true, frame: { t: "commit.submit.ok", seq: r.commit.entry.seq, epoch: current + 1, statementSeq: r.statement.entry.seq } };
    }

    const want = rosterOf(host.state);
    if (aad.roster.seq !== want.seq || aad.roster.hash !== want.hash) return { ok: false, code: "stale_roster", fields: { roster: want } };
    const seq = host.head.seq + 1;
    if (this.stageWelcome(welcomeRec, seq, commitHash) === "persist_failed") return { ok: false, code: "persist_failed" };
    let signed: SignedEntry;
    try {
      signed = host.appendMls("mls.commit", bytes, epochAfter);
    } catch (e) {
      this.unstageWelcome(seq);
      throw e;
    }
    this.o.afterAppend?.();
    return { ok: true, frame: { t: "commit.submit.ok", seq: signed.entry.seq, epoch: current + 1 } };
  }

  private stageWelcome(rec: { welcome: string; targets: string[] } | null, seq: number, commitHash: string): "ok" | "persist_failed" {
    if (!rec || rec.targets.length === 0) return "ok";
    const before = this.f.welcomes;
    this.f.welcomes = [...before, { seq, commitHash, welcome: rec.welcome, targets: rec.targets, at: this.now() }].slice(-WELCOMES_MAX);
    if (!this.persist("welcome")) {
      this.f.welcomes = before;
      return "persist_failed";
    }
    return "ok";
  }

  private unstageWelcome(seq: number): void {
    const n = this.f.welcomes.length;
    this.f.welcomes = this.f.welcomes.filter((w) => w.seq !== seq || this.o.host.entries(seq, seq)[0]?.signed.entry.bodyHash === w.commitHash);
    if (this.f.welcomes.length !== n) this.persist("welcome_unstage");
  }

  // ------------------------------------------------------------------------------ welcome.fetch

  private fetchWelcome(access: DsAccess, frame: Record<string, unknown>): DsReply {
    if (frame.ack !== undefined) {
      if (!isInt(frame.ack, 0)) return { ok: false, code: "bad_frame" };
      const before = this.f.welcomes;
      this.f.welcomes = before.map((w) => (w.seq === frame.ack ? { ...w, targets: w.targets.filter((d) => d !== access.deviceId) } : w)).filter((w) => w.targets.length > 0);
      if (!this.persist("welcome_ack")) {
        this.f.welcomes = before;
        return { ok: false, code: "persist_failed" };
      }
    }
    const w = this.f.welcomes.filter((x) => x.targets.includes(access.deviceId)).sort((a, b) => a.seq - b.seq)[0];
    const entry = w ? this.o.host.entries(w.seq, w.seq)[0] : undefined;
    if (!w || !entry) return { ok: true, frame: { t: "welcome.fetch.ok", none: true } };
    return { ok: true, frame: { t: "welcome.fetch.ok", welcome: w.welcome, ratchetTree: null, entry: entry.signed } };
  }

  // ------------------------------------------------------------------------------ msg.*

  private sendMessage(frame: Record<string, unknown>): DsReply {
    const { epoch, message } = frame;
    if (!isInt(epoch, 0) || !isB64uText(message, Math.ceil((MLS_MESSAGE_MAX_BYTES * 4) / 3))) return { ok: false, code: "bad_frame" };
    let bytes: Uint8Array;
    let peek: ReturnType<MlsAdapter["peek"]>;
    try {
      bytes = b64uDecodeVar(message as string, MLS_MESSAGE_MAX_BYTES);
      peek = this.o.adapter.peek(bytes);
    } catch {
      return { ok: false, code: "not_permitted" };
    }
    if (peek.wireformat !== "mls_private_message" || peek.contentType !== "application" || peek.epoch !== epoch) return { ok: false, code: "not_permitted" };
    const group = b64u(peek.groupId);
    if (!this.knownGroup(group)) return { ok: false, code: "not_permitted" };
    const current = this.epochOf(group);
    if (epoch > current) return { ok: false, code: "stale_epoch", fields: { epoch: current } };
    const signed = this.o.host.appendMls("mls.app", bytes, this.o.host.state.epoch);
    this.o.afterAppend?.();
    return { ok: true, frame: { t: "msg.send.ok", seq: signed.entry.seq } };
  }

  private fetchMessages(frame: Record<string, unknown>): DsReply {
    const { fromSeq, limit } = frame;
    if (!isInt(fromSeq, 0) || !isInt(limit, 1, MSG_FETCH_MAX)) return { ok: false, code: "bad_frame" };
    const host = this.o.host;
    const entries: SignedEntry[] = [];
    const bodies: { seq: number; body: string }[] = [];
    let bytes = 0;
    let next = fromSeq as number;
    for (const r of host.entries(fromSeq as number, (fromSeq as number) + (limit as number) - 1)) {
      if (r.signed.entry.cls === "mls") {
        const body = b64u(r.body);
        if (entries.length > 0 && bytes + body.length > REPLY_BUDGET) break;
        bytes += body.length + 512;
        entries.push(r.signed);
        bodies.push({ seq: r.signed.entry.seq, body });
      }
      next = r.signed.entry.seq + 1;
    }
    return { ok: true, frame: { t: "msg.fetch.ok", entries, bodies, next } };
  }

  private ack(access: DsAccess, frame: Record<string, unknown>): DsReply {
    const { seq, epoch } = frame;
    if (!isInt(seq, -1, this.o.host.head.seq) || !isInt(epoch, 0)) return { ok: false, code: "bad_frame" };
    const prev = this.f.acks[access.deviceId];
    if (prev && prev.seq >= (seq as number)) return { ok: true, frame: { t: "msg.ack.ok", lastAck: prev } };
    this.f.acks[access.deviceId] = { seq: seq as number, epoch: epoch as number };
    if (!this.persist("ack")) {
      if (prev) this.f.acks[access.deviceId] = prev;
      else delete this.f.acks[access.deviceId];
      return { ok: false, code: "persist_failed" };
    }
    return { ok: true, frame: { t: "msg.ack.ok", lastAck: this.f.acks[access.deviceId] } };
  }

  // ------------------------------------------------------------------------------ internals

  private trackedTo = -1;

  private trackEntry(signed: SignedEntry, body: Uint8Array): void {
    this.trackedTo = signed.entry.seq;
    if (signed.entry.cls !== "mls" || signed.entry.type !== "mls.commit") return;
    try {
      const p = this.o.adapter.peek(body);
      if (p.wireformat !== "mls_private_message") return;
      const g = b64u(p.groupId);
      this.epochs.set(g, p.epoch + 1);
      if (g === this.roomGroup) this.lastRoomCommit = { seq: signed.entry.seq, hts: signed.entry.hts, epoch: p.epoch + 1 };
    } catch {
      // A body the host itself accepted always peeks; nothing to track otherwise.
    }
  }

  private knownGroup(group: string): boolean {
    if (group === this.roomGroup) return true;
    return Object.keys(this.o.host.state.auth.scopes).some((s) => b64u(mlsGroupId(this.o.host.genesisHash, 0, s)) === group);
  }

  /** Pools follow the fold (6.4, "Two pools per device"); Welcomes for devices that left are dropped. */
  private follow(): void {
    const st = this.o.host.state;
    const keys = deviceKeys(st.members);
    let changed = false;
    for (const [dev, pools] of Object.entries(this.f.pools)) {
      const sig = keys.get(dev);
      if (sig === undefined) {
        delete this.f.pools[dev];
        changed = true;
        continue;
      }
      if (pools.current && pools.current.sig !== sig) {
        pools.current = null;
        changed = true;
      }
      if (pools.rekey && pools.rekey.sig === sig) {
        // The rekey was approved: its pool becomes the current one.
        pools.current = pools.rekey;
        pools.rekey = null;
        changed = true;
      } else if (pools.rekey && !Object.values(st.pending).some((p) => p.kind === "rekey" && p.status === "pending" && p.deviceId === dev && p.device.sig === pools.rekey!.sig)) {
        pools.rekey = null;
        changed = true;
      }
    }
    const welcomes = this.f.welcomes.map((w) => ({ ...w, targets: w.targets.filter((d) => keys.has(d)) })).filter((w) => w.targets.length > 0);
    if (welcomes.length !== this.f.welcomes.length || welcomes.some((w, i) => w.targets.length !== this.f.welcomes[i].targets.length)) {
      this.f.welcomes = welcomes;
      changed = true;
    }
    for (const d of Object.keys(this.f.acks)) if (!keys.has(d)) delete this.f.acks[d];
    if (changed) this.persist("follow");
  }

  private load(): void {
    const plain = this.o.kek.readSealed(hostMlsPath(this.o.dataDir, this.roomId), hostMlsPurpose(this.roomId));
    if (!plain) return;
    try {
      const p = FileS.safeParse(rjcsParse(plain, 64 * 1024 * 1024));
      if (!p.success || p.data.roomId !== this.roomId) {
        log("mls_state_invalid", { roomId: this.roomId });
        return;
      }
      this.f = p.data;
      this.refs = new Map(this.f.refs);
      // A Welcome staged for a commit that never reached the log is dropped (written before the append).
      this.f.welcomes = this.f.welcomes.filter((w) => this.o.host.entries(w.seq, w.seq)[0]?.signed.entry.bodyHash === w.commitHash);
    } finally {
      plain.fill(0);
    }
  }

  private persist(why: string): boolean {
    const plain = Buffer.from(rjcs(this.f, 64 * 1024 * 1024));
    try {
      this.o.kek.writeSealed(hostMlsPath(this.o.dataDir, this.roomId), hostMlsPurpose(this.roomId), plain);
      return true;
    } catch (e) {
      log("mls_persist_failed", { roomId: this.roomId, why, code: String((e as { code?: string }).code ?? "error").slice(0, 32) });
      return false;
    } finally {
      plain.fill(0);
    }
  }
}

function deviceKeys(members: Readonly<Record<string, RosterEntry>>): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of Object.values(members)) for (const d of m.devices) out.set(d.deviceId, d.sig);
  return out;
}

function scopesOf(st: Readonly<RoomState>, memberId: string): string[] {
  return Object.entries(st.auth.scopes)
    .filter(([, ids]) => ids.includes(memberId))
    .map(([s]) => s);
}

function sharesGroup(st: Readonly<RoomState>, a: string, b: string, scope: string | null): boolean {
  if (scope === null) return !!st.members[a] && !!st.members[b];
  const ids = st.auth.scopes[scope] ?? [];
  return ids.includes(a) && ids.includes(b);
}

/** An open repair request (room-log-v2 4.3) of this device naming `ref`, by the host's own clock. */
function openRepair(st: Readonly<RoomState>, memberId: string, deviceId: string, ref: string, nowMs: number): { scope: string | null } | null {
  for (const r of Object.values(st.repairs)) {
    if (r.status === "open" && r.memberId === memberId && r.deviceId === deviceId && r.keyPackageRef === ref && nowMs - r.hts < REPAIR_OPEN_MS) return { scope: r.scope };
  }
  return null;
}
