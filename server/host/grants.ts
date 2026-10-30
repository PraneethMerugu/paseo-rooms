// Lane grants v2 on the room host (implementation plan I-10; grants-v2.md sections 2 to 9 and 11).
// Replaces server/grants.ts and HostStore.checkGrantLive for the v2 runtime only.
//
// - Tokens: `prg2.` + b64u(RJCS(GrantClaims)) + "." + b64u(Sign(hostKey, "lane-grant", RJCS(claims))).
//   No optional fields; at most 1024 characters. A token is a bearer secret: it is never logged and
//   never stored here (only its `gid`).
// - `current[(deviceId, laneId)]` is the allowlist and the primary revocation check (section 4 step 6,
//   P-12). `notBefore[(deviceId, laneId)]` is the iat of the current grant (section 8). The denylist
//   (`revoked`, keyed by gid) is for audit and the theft check; it is pruned only after
//   `exp + 10 min` and 24 h of held monotonic time (`heldMs`, persisted, R-11), or 30 days past `exp`.
// - Issuance order (section 3): claims, then `current` set and pushed to the lane endpoint (which
//   cuts links presenting the old gid), then persist, then `grant.issued`, then the reply. A failed
//   persist replies `internal` and delivers nothing.
// - Revocation (section 7.1): `decide` runs from RoomHost.onDecide, after the fold accepted the entry
//   and before the log append: drop entries the next state no longer allows (member or device gone,
//   lane access removed, lane closed, role changed, host key revoked or uncertified), push to the lane
//   endpoints (enforce), persist. The log append follows in RoomHost. A failed persist keeps the
//   revocation in memory, sets `persistError` (shown to the owner) and retries every 10 s.
// - Lifetime (section 5): 12 h; room policy `grantTtl` may only shorten it (1 h minimum by schema);
//   below 1 h only with PASEO_ROOMS_DEV_SHORT_GRANTS=1 on the host (PASEO_ROOMS_DEV_GRANT_TTL_S,
//   default 60, at least 10).
// - Stolen grants (section 6): the lane endpoint reports two live holders, or the member reports an
//   unaccounted link; either way the gid is unlisted, links cut, `grant.suspected-theft` appended and
//   the device told on its room session to reissue.
import nodePath from "node:path";
import { z } from "zod";
import type { RoomState } from "../authority/fold";
import { firstIssue, GrantId, Kid, LaneId, MemberId, Role, RoomId, serverId as serverIdSchema } from "../authority/schema";
import { edKid } from "../authority/state";
import type { StatementType } from "../authority/statements";
import type { Kek } from "../keystore/keystore";
import { log, logError } from "../log";
import type { DurableDeps } from "../platform/durable";
import { b64u, b64uDecode, b64uDecodeVar, isB64u } from "../proto/b64u";
import { CTX_LANE_GRANT } from "../proto/contexts";
import { newId } from "../proto/ids";
import { verify } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { hostRoomDir } from "./room-log-store";
import type { RoomHost } from "./room-host";

export const GRANT_PREFIX_V2 = "prg2";
export const GRANT_MAX_CHARS = 1024;
/** Fixed lifetime (decision round 3): 12 h. */
export const GRANT_TTL_MAX_S = 43_200;
export const GRANT_TTL_MIN_S = 3_600;
export const ENV_DEV_SHORT_GRANTS = "PASEO_ROOMS_DEV_SHORT_GRANTS";
export const ENV_DEV_GRANT_TTL = "PASEO_ROOMS_DEV_GRANT_TTL_S";
/** Section 9: iat up to 120 s in the future is accepted. */
export const IAT_SKEW_S = 120;
export const PRUNE_AFTER_EXP_MS = 10 * 60_000;
export const PRUNE_HELD_MS = 24 * 3_600_000;
export const PRUNE_BACKSTOP_MS = 30 * 24 * 3_600_000;
export const PERSIST_RETRY_MS = 10_000;
export const HELD_FLUSH_MS = 3_600_000;
export const STATUS_PER_HOUR = 60;
export const ISSUE_MIN_INTERVAL_MS = 15_000;
export const THEFT_WINDOW_MS = 7 * 24 * 3_600_000;

export const GRANTS_FILE = "grants.sealed";
export const grantsPurpose = (roomId: string) => `host-grants:${roomId}`;
export const grantsPath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), GRANTS_FILE);

export const GrantClaims = z.strictObject({
  v: z.literal(2),
  typ: z.literal("lane-grant"),
  roomId: RoomId,
  laneId: LaneId,
  aud: serverIdSchema("laneEndpoint"),
  sub: MemberId,
  dev: Kid,
  role: Role,
  gid: GrantId,
  iat: z.number().int().min(0).max(2 ** 40),
  exp: z.number().int().min(0).max(2 ** 40),
  hostKid: Kid,
});
export type GrantClaimsV2 = z.infer<typeof GrantClaims>;

/** Reasons of section 4, in check order. Logged by the lane endpoint, never sent to the link. */
export type GrantFailure =
  | "malformed"
  | "unknown_host_key"
  | "host_key_not_valid"
  | "bad_signature"
  | "wrong_audience"
  | "not_yet_valid"
  | "expired"
  | "not_member"
  | "not_device"
  | "no_lane_access"
  | "lane_closed"
  | "role_mismatch"
  | "not_current"
  | "before_not_before";

export type GrantCheck = { ok: true; claims: GrantClaimsV2 } | { ok: false; reason: GrantFailure; claims?: GrantClaimsV2 };

export type CurrentGrant = { gid: string; iat: number; exp: number; role: string; memberId: string };

export interface VerifyContext {
  state: Readonly<RoomState>;
  laneId: string;
  aud: string;
  nowS: number;
  current(deviceId: string, laneId: string): CurrentGrant | undefined;
  notBefore(deviceId: string, laneId: string): number | undefined;
  /** Token bucket empty (section 11): only a token whose gid is current gets the signature check. */
  cheap?: boolean;
}

/** Step 1: format. Returns the claims and the signed bytes, or null. */
export function parseGrantToken(token: unknown): { claims: GrantClaimsV2; payload: Uint8Array; sig: Uint8Array } | null {
  if (typeof token !== "string" || token.length > GRANT_MAX_CHARS) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== GRANT_PREFIX_V2 || !isB64u(parts[2], 64)) return null;
  try {
    const payload = new Uint8Array(b64uDecodeVar(parts[1], GRANT_MAX_CHARS));
    const parsed = GrantClaims.safeParse(rjcsParse(payload));
    if (!parsed.success) return null;
    return { claims: parsed.data, payload, sig: new Uint8Array(b64uDecode(parts[2], 64)) };
  } catch {
    return null;
  }
}

/** Device of a member by the kid of its signing key (full stored key compared, section 4 step 5). */
function deviceOf(state: Readonly<RoomState>, memberId: string, devKid: string): { deviceId: string } | null {
  const m = state.members[memberId];
  return m?.devices.find((d) => edKid(d.sig) === devKid) ?? null;
}

/**
 * Section 4, steps 1 to 6, in order (step 7, the link policy, is the lane endpoint's). With `cheap`
 * (empty failure bucket) the allowlist is checked before the signature, so a flood of stale or
 * forged tokens costs no signature checks and current grants still get in (S-21).
 */
export function verifyGrantV2(token: unknown, c: VerifyContext): GrantCheck {
  const t = parseGrantToken(token);
  if (!t) return { ok: false, reason: "malformed" };
  const claims = t.claims;
  const s = c.state;
  if (c.cheap) {
    const dev = deviceOf(s, claims.sub, claims.dev);
    if (!dev || c.current(dev.deviceId, claims.laneId)?.gid !== claims.gid) return { ok: false, reason: "not_current", claims };
  }
  // Step 2: the issuing host key, by its stored public key, valid at iat, not revoked, certified.
  const hk = s.auth.hostKeys.find((h) => h.kid === claims.hostKid);
  if (!hk) return { ok: false, reason: "unknown_host_key", claims };
  if (hk.revoked || hk.uncertified || claims.iat < hk.validFrom || (hk.validTo !== null && claims.iat > hk.validTo)) return { ok: false, reason: "host_key_not_valid", claims };
  if (!verify(b64uDecode(hk.pub, 32), CTX_LANE_GRANT, t.payload, t.sig)) return { ok: false, reason: "bad_signature", claims };
  // Step 3.
  if (claims.roomId !== s.roomId || claims.laneId !== c.laneId || claims.aud !== c.aud) return { ok: false, reason: "wrong_audience", claims };
  // Step 4 (lane endpoint clock).
  if (claims.iat > c.nowS + IAT_SKEW_S) return { ok: false, reason: "not_yet_valid", claims };
  if (!(claims.exp > c.nowS)) return { ok: false, reason: "expired", claims };
  // Step 5.
  const m = s.members[claims.sub];
  if (!m) return { ok: false, reason: "not_member", claims };
  const dev = deviceOf(s, claims.sub, claims.dev);
  if (!dev) return { ok: false, reason: "not_device", claims };
  if (!m.lanes.includes(claims.laneId)) return { ok: false, reason: "no_lane_access", claims };
  const lane = s.auth.lanes[claims.laneId];
  if (!lane || lane.status === "closed" || s.auth.closed) return { ok: false, reason: "lane_closed", claims };
  if (claims.role !== m.role) return { ok: false, reason: "role_mismatch", claims };
  // Step 6: the allowlist, then notBefore (defence in depth, section 8).
  if (c.current(dev.deviceId, claims.laneId)?.gid !== claims.gid) return { ok: false, reason: "not_current", claims };
  const nb = c.notBefore(dev.deviceId, claims.laneId);
  if (nb !== undefined && claims.iat < nb) return { ok: false, reason: "before_not_before", claims };
  return { ok: true, claims };
}

/**
 * Effective lifetime (section 5): 12 h, shortened by policy, never lengthened. Below 1 h only with
 * the development switch on the host.
 */
export function grantTtlS(policyTtl: number, env: NodeJS.ProcessEnv = process.env): number {
  const base = Math.max(GRANT_TTL_MIN_S, Math.min(GRANT_TTL_MAX_S, Math.floor(policyTtl)));
  if (env[ENV_DEV_SHORT_GRANTS] !== "1") return base;
  const dev = Number(env[ENV_DEV_GRANT_TTL] ?? 60);
  return Number.isFinite(dev) ? Math.max(10, Math.min(base, Math.floor(dev))) : base;
}

/**
 * Issues per (device, lane) per hour: 6 (section 11). With development short grants the cap grows so
 * that a rotation every half lifetime, plus retries, still fits; it never goes below 6.
 */
export function issuesPerHour(ttlS: number): number {
  return Math.max(6, 4 * Math.ceil(3600 / Math.max(1, ttlS)));
}

// ------------------------------------------------------------------------------- persisted state

const Key = z.strictObject({ deviceId: z.string().max(64), laneId: LaneId });
const GrantsFile = z.strictObject({
  v: z.literal(2),
  typ: z.literal("host-grants"),
  roomId: RoomId,
  current: z.array(Key.extend({ gid: GrantId, iat: z.number().int(), exp: z.number().int(), role: Role, memberId: MemberId })).max(65_536),
  notBefore: z.array(Key.extend({ iat: z.number().int() })).max(65_536),
  revoked: z.array(z.strictObject({ gid: GrantId, exp: z.number().int(), heldMs: z.number().int().min(0) })).max(1_000_000),
});
type GrantsFile = z.infer<typeof GrantsFile>;

export type RevokedEntry = { gid: string; exp: number; heldMs: number };
export type DropReason = "superseded" | "removed" | "role_changed" | "lane_closed" | "host_key_revoked" | "suspected_theft";
export type IssueResult = { ok: true; token: string; claims: GrantClaimsV2; serverTime: number } | { ok: false; code: "not_permitted" | "busy" | "internal" };
export type LinkInfo = { since: number; routes: number };

const key = (deviceId: string, laneId: string) => `${deviceId} ${laneId}`;

export interface HostGrantsOptions {
  dataDir: string;
  kek: Kek;
  host: RoomHost;
  env?: NodeJS.ProcessEnv;
  /** Wall clock, unix ms. */
  now?: () => number;
  /** Monotonic clock, ms (heldMs). */
  mono?: () => number;
  /** Test only: durable-write fault injection for the grants file. */
  write?: Partial<DurableDeps>;
  retryMs?: number;
}

export class HostGrants {
  readonly roomId: string;
  private readonly current = new Map<string, CurrentGrant & { deviceId: string; laneId: string }>();
  private readonly notBefore = new Map<string, number>();
  readonly revoked = new Map<string, RevokedEntry>();
  private readonly issues = new Map<string, number[]>();
  private readonly statusCalls = new Map<string, number[]>();
  private lastMono: number;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly flushTimer: ReturnType<typeof setInterval>;
  private stopped = false;
  /** Set while the last persist failed (grants-v2 7.2); cleared by a successful retry. */
  persistError: string | null = null;
  private readonly now: () => number;
  private readonly mono: () => number;
  private readonly unhook: () => void;

  /** Section 3 step 2 and 7.1 step 2: re-check the links of a lane now. Set by the lane service. */
  enforce: (laneId: string, reason: string) => void = () => undefined;
  /** Pushes a frame to a device's live room session, if any. Set by the room endpoint wiring. */
  notify: (deviceId: string, frame: Record<string, unknown>) => void = () => undefined;
  /** Live links of (device, lane) on the lane endpoint (section 6.2). */
  links: (deviceId: string, laneId: string) => LinkInfo[] = () => [];
  /** After a host statement was appended (subscribers, session enforcement). */
  afterAppend: () => void = () => undefined;

  constructor(private readonly o: HostGrantsOptions) {
    this.roomId = o.host.roomId;
    this.now = o.now ?? Date.now;
    this.mono = o.mono ?? (() => performance.now());
    this.lastMono = this.mono();
    this.load();
    this.unhook = o.host.onDecide((next, prev, type) => this.decide(next, prev, type));
    this.flushTimer = setInterval(() => this.persist("held_flush"), HELD_FLUSH_MS);
    (this.flushTimer as { unref?: () => void }).unref?.();
  }

  ttlS(): number {
    return grantTtlS(this.o.host.state.auth.policy.grantTtl, this.o.env);
  }

  currentOf(deviceId: string, laneId: string): CurrentGrant | undefined {
    return this.current.get(key(deviceId, laneId));
  }

  /** Section 4 against the host's state and this allowlist. */
  verify(token: unknown, lane: { laneId: string; aud: string }, opts: { cheap?: boolean } = {}): GrantCheck {
    return verifyGrantV2(token, {
      state: this.o.host.state,
      laneId: lane.laneId,
      aud: lane.aud,
      nowS: Math.floor(this.now() / 1000),
      current: (d, l) => this.current.get(key(d, l)),
      notBefore: (d, l) => this.notBefore.get(key(d, l)),
      cheap: opts.cheap,
    });
  }

  /** `grant.issue` (section 3) for an authenticated device session. */
  issue(dev: { memberId: string; deviceId: string }, laneId: string): IssueResult {
    const s = this.o.host.state;
    const m = s.members[dev.memberId];
    const d = m?.devices.find((x) => x.deviceId === dev.deviceId);
    const lane = s.auth.lanes[laneId];
    if (!m || !d || !m.lanes.includes(laneId) || !lane || lane.status === "closed" || s.auth.closed) return { ok: false, code: "not_permitted" };
    const ttl = this.ttlS();
    const k = key(dev.deviceId, laneId);
    const nowMs = this.now();
    const recent = (this.issues.get(k) ?? []).filter((t) => nowMs - t < 3_600_000);
    if (recent.length >= issuesPerHour(ttl) || (recent.length > 0 && nowMs - recent[recent.length - 1] < Math.min(ISSUE_MIN_INTERVAL_MS, (ttl * 1000) / 4))) {
      this.issues.set(k, recent);
      return { ok: false, code: "busy" };
    }
    recent.push(nowMs);
    this.issues.set(k, recent);
    // 1. Claims.
    const iat = Math.floor(nowMs / 1000);
    const hostKid = s.auth.hostKeys.find((h) => h.toSeq === null)?.kid;
    if (!hostKid) return { ok: false, code: "internal" };
    const claims: GrantClaimsV2 = { v: 2, typ: "lane-grant", roomId: this.roomId, laneId, aud: lane.offer.serverId, sub: m.memberId, dev: edKid(d.sig), role: m.role, gid: newId("grant"), iat, exp: iat + ttl, hostKid };
    let token: string;
    try {
      const payload = rjcs(claims);
      const signed = this.o.host.signGrant(payload);
      if (signed.kid !== hostKid) return { ok: false, code: "internal" };
      token = `${GRANT_PREFIX_V2}.${b64u(payload)}.${b64u(signed.sig)}`;
    } catch (e) {
      logError("grant_sign_failed", e, { roomId: this.roomId });
      return { ok: false, code: "internal" };
    }
    // 2. Allowlist and push: links presenting the previous gid are superseded and cut now.
    const prev = this.current.get(k);
    this.accrue();
    if (prev) this.revoked.set(prev.gid, { gid: prev.gid, exp: prev.exp, heldMs: 0 });
    this.current.set(k, { deviceId: dev.deviceId, laneId, memberId: m.memberId, gid: claims.gid, iat, exp: claims.exp, role: m.role });
    this.notBefore.set(k, iat);
    this.enforce(laneId, "superseded");
    // 3. Persist. On failure the new grant is not delivered (the old one is already cut): safe.
    if (!this.persist("issue")) return { ok: false, code: "internal" };
    // 4. Log.
    try {
      this.o.host.emit("grant.issued", { memberId: m.memberId, deviceId: dev.deviceId, laneId, gid: claims.gid, exp: claims.exp });
      this.afterAppend();
    } catch (e) {
      logError("grant_issued_append_failed", e, { roomId: this.roomId });
      return { ok: false, code: "internal" };
    }
    log("grant_issued", { roomId: this.roomId, laneId, deviceId: dev.deviceId, gid: claims.gid, ttlS: ttl });
    // 5. Reply.
    return { ok: true, token, claims, serverTime: this.now() };
  }

  /** `grant.status` (section 6.2): the current gid and the live link, with its start time. */
  status(deviceId: string, laneId: string): { ok: true; gid: string | null; links: LinkInfo[]; serverTime: number } | { ok: false; code: "busy" } {
    const nowMs = this.now();
    const recent = (this.statusCalls.get(deviceId) ?? []).filter((t) => nowMs - t < 3_600_000);
    if (recent.length >= Math.max(STATUS_PER_HOUR, issuesPerHour(this.ttlS()) * 2)) {
      this.statusCalls.set(deviceId, recent);
      return { ok: false, code: "busy" };
    }
    recent.push(nowMs);
    this.statusCalls.set(deviceId, recent);
    return { ok: true, gid: this.current.get(key(deviceId, laneId))?.gid ?? null, links: this.links(deviceId, laneId).slice(0, 1), serverTime: nowMs };
  }

  /**
   * Two live holders (6.1 step 3) or a member report (6.3): unlist the gid, cut, persist, log
   * `grant.suspected-theft`, tell the device. Returns false when the gid is not current (nothing done).
   */
  suspectedTheft(i: { deviceId: string; laneId: string; gid: string; reportedBy: "endpoint" | "member" }): boolean {
    const k = key(i.deviceId, i.laneId);
    const cur = this.current.get(k);
    if (!cur || cur.gid !== i.gid) return false;
    // Decide and enforce.
    this.accrue();
    this.current.delete(k);
    this.revoked.set(cur.gid, { gid: cur.gid, exp: cur.exp, heldMs: 0 });
    this.enforce(i.laneId, "suspected_theft");
    // Persist, then log.
    this.persist("theft");
    try {
      this.o.host.emit("grant.suspected-theft", { memberId: cur.memberId, deviceId: i.deviceId, laneId: i.laneId, gid: cur.gid, reportedBy: i.reportedBy });
      this.afterAppend();
    } catch (e) {
      logError("grant_theft_append_failed", e, { roomId: this.roomId });
    }
    log("grant_suspected_theft", { roomId: this.roomId, laneId: i.laneId, deviceId: i.deviceId, gid: cur.gid, reportedBy: i.reportedBy, repeated: this.repeatedTheft(i.deviceId) });
    this.notify(i.deviceId, { t: "grant.revoked", laneId: i.laneId, gid: cur.gid, reason: "suspected_theft" });
    return true;
  }

  /** Section 6.4: two suspected thefts for the same device within 7 days mean a device compromise. */
  repeatedTheft(deviceId: string): boolean {
    const since = this.now() - THEFT_WINDOW_MS;
    let n = 0;
    for (const r of this.o.host.entries()) {
      if (r.signed.entry.type !== "grant.suspected-theft" || r.signed.entry.hts < since) continue;
      const data = (rjcsParse(r.body) as { body: { data: { deviceId: string } } }).body.data;
      if (data.deviceId === deviceId) n++;
    }
    return n >= 2;
  }

  /** Devices with repeated suspected thefts (owner view). */
  compromisedDevices(): string[] {
    const ids = new Set<string>();
    for (const c of this.current.values()) ids.add(c.deviceId);
    for (const r of this.o.host.entries()) if (r.signed.entry.type === "grant.suspected-theft") ids.add((rjcsParse(r.body) as { body: { data: { deviceId: string } } }).body.data.deviceId);
    return [...ids].filter((d) => this.repeatedTheft(d));
  }

  /**
   * Steps 1 to 3 of section 7.1 for a log entry about to be appended: drop every current grant the
   * next state no longer allows, push to the lane endpoints, persist. A lowered role also tells the
   * member's devices to reissue at the new role (S-9).
   */
  decide(next: Readonly<RoomState>, _prev: Readonly<RoomState>, _type: StatementType): void {
    const dropped: { c: CurrentGrant & { deviceId: string; laneId: string }; reason: DropReason }[] = [];
    for (const c of this.current.values()) {
      const reason = dropReason(next, c);
      if (reason) dropped.push({ c, reason });
    }
    if (dropped.length === 0) return;
    this.accrue();
    const lanes = new Set<string>();
    for (const { c } of dropped) {
      this.current.delete(key(c.deviceId, c.laneId));
      this.revoked.set(c.gid, { gid: c.gid, exp: c.exp, heldMs: 0 });
      lanes.add(c.laneId);
    }
    for (const laneId of lanes) this.enforce(laneId, "revoked");
    for (const { c, reason } of dropped) {
      if (reason === "role_changed") this.notify(c.deviceId, { t: "grant.revoked", laneId: c.laneId, gid: c.gid, reason });
    }
    this.persist("revoke");
    log("grants_revoked", { roomId: this.roomId, grants: dropped.length, reasons: [...new Set(dropped.map((d) => d.reason))] });
  }

  view() {
    return {
      current: [...this.current.values()].map((c) => ({ deviceId: c.deviceId, laneId: c.laneId, gid: c.gid, iat: c.iat, exp: c.exp })),
      revoked: this.revoked.size,
      persistError: this.persistError,
      ttlS: this.ttlS(),
    };
  }

  stop(): void {
    this.stopped = true;
    this.unhook();
    clearInterval(this.flushTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }

  // ------------------------------------------------------------------------------ internals

  /** Adds the monotonic time since the last accrual to every denylist entry, then prunes (section 8). */
  private accrue(): void {
    const m = this.mono();
    const delta = Math.max(0, Math.round(m - this.lastMono));
    this.lastMono = m;
    const wall = this.now();
    for (const [gid, e] of this.revoked) {
      e.heldMs += delta;
      const expMs = e.exp * 1000;
      if ((expMs + PRUNE_AFTER_EXP_MS < wall && e.heldMs >= PRUNE_HELD_MS) || wall > expMs + PRUNE_BACKSTOP_MS) this.revoked.delete(gid);
    }
  }

  /** Durable sealed write. Returns false on failure (error kept, retried every 10 s). Never throws. */
  private persist(why: string): boolean {
    if (this.stopped) return false;
    this.accrue();
    const file: GrantsFile = {
      v: 2,
      typ: "host-grants",
      roomId: this.roomId,
      current: [...this.current.values()].map((c) => ({ deviceId: c.deviceId, laneId: c.laneId, gid: c.gid, iat: c.iat, exp: c.exp, role: c.role as GrantsFile["current"][number]["role"], memberId: c.memberId })),
      notBefore: [...this.notBefore.entries()].map(([k, iat]) => ({ deviceId: k.split(" ")[0], laneId: k.split(" ")[1], iat })),
      revoked: [...this.revoked.values()].map((e) => ({ ...e })),
    };
    const plain = Buffer.from(rjcs(file, 64 * 1024 * 1024));
    try {
      this.o.kek.writeSealed(grantsPath(this.o.dataDir, this.roomId), grantsPurpose(this.roomId), plain, this.o.write);
      if (this.persistError) log("grants_persisted_after_failure", { roomId: this.roomId, why });
      this.persistError = null;
      return true;
    } catch (e) {
      this.persistError = String((e as { code?: string }).code ?? (e as Error).name ?? "error").slice(0, 64);
      log("grants_persist_failed", { roomId: this.roomId, why, code: this.persistError });
      this.scheduleRetry();
      return false;
    } finally {
      plain.fill(0);
    }
  }

  private scheduleRetry(): void {
    if (this.retryTimer || this.stopped) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (this.persistError && !this.stopped && !this.persist("retry")) this.scheduleRetry();
    }, this.o.retryMs ?? PERSIST_RETRY_MS);
    (this.retryTimer as { unref?: () => void }).unref?.();
  }

  /** Loads the sealed file; entries the folded log no longer allows are dropped (the log is the truth). */
  private load(): void {
    const plain = this.o.kek.readSealed(grantsPath(this.o.dataDir, this.roomId), grantsPurpose(this.roomId));
    if (!plain) return;
    try {
      const parsed = GrantsFile.safeParse(rjcsParse(plain, 64 * 1024 * 1024));
      if (!parsed.success) throw new Error(`grants file: ${firstIssue(parsed.error)}`);
      if (parsed.data.roomId !== this.roomId) throw new Error("grants file names another room");
      for (const r of parsed.data.revoked) this.revoked.set(r.gid, { ...r });
      for (const n of parsed.data.notBefore) this.notBefore.set(key(n.deviceId, n.laneId), n.iat);
      for (const c of parsed.data.current) {
        if (dropReason(this.o.host.state, c)) this.revoked.set(c.gid, { gid: c.gid, exp: c.exp, heldMs: 0 });
        else this.current.set(key(c.deviceId, c.laneId), { ...c });
      }
    } finally {
      plain.fill(0);
    }
  }
}

/** Why a current grant no longer holds under a state, or null. */
function dropReason(s: Readonly<RoomState>, c: { memberId: string; deviceId: string; laneId: string; role: string }): DropReason | null {
  const m = s.members[c.memberId];
  if (!m || !m.devices.some((d) => d.deviceId === c.deviceId) || !m.lanes.includes(c.laneId)) return "removed";
  const lane = s.auth.lanes[c.laneId];
  if (!lane || lane.status === "closed" || s.auth.closed) return "lane_closed";
  if (m.role !== c.role) return "role_changed";
  const hk = s.auth.hostKeys.find((h) => h.toSeq === null);
  if (!hk || hk.revoked || hk.uncertified) return "host_key_revoked";
  return null;
}

/** `grant.status.ok` for the wire. */
export function grantStatusFrame(re: number, st: { gid: string | null; links: LinkInfo[]; serverTime: number }) {
  return { t: "grant.status.ok", re, gid: st.gid, links: st.links, serverTime: st.serverTime };
}

/** The `GrantId` check for incoming report frames. */
export const isGrantId = (v: unknown): v is string => GrantId.safeParse(v).success;
export const isLaneIdV2 = (v: unknown): v is string => LaneId.safeParse(v).success;
