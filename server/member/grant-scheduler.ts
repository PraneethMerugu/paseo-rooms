// Member-side grant rotation (implementation plan I-10; grants-v2.md sections 5, 6.2, 6.3 and 9; P-24,
// P-9, C-12).
//
// - The member never compares `iat` or `exp` with its own wall clock. On receiving a grant at local
//   monotonic time t0 it takes L = exp - iat and schedules: t0 + 0.5 L idle rotation attempt,
//   t0 + 0.75 L forced rotation, t0 + L - 60 s last resort (only when that is after 0.75 L).
// - Idle attempt (section 5, read with 6.2): `grant.status` reports the live link and its routes. A
//   link without routes is idle: rotate now, it costs nothing. With routes open, defer only if ALL
//   hold: exactly one link; the member's own registration for the lane is `online` in
//   hosts.observe; the lane's link start time is within 30 s of when the member saw its registration
//   become online (both on the member's clock via `serverTime`). Otherwise rotate: routes on a link
//   the member cannot account for never defer rotation (P-9). A deferral retries after
//   max(L/8, 60 s); the forced point comes regardless.
// - Unaccounted link (6.3): the lane reports a live link while the member's registration has been
//   offline for at least 30 s: `grant.report` (reason `unaccounted_link`), then rotate. Uncertain
//   cases (the registration was already online when first observed, so its online time is unknown)
//   only rotate, never report: a report records a suspected theft.
// - Restart (C-12): the schedule is stored as {gid, lifetimeMs, receivedWall}. The wall clock is
//   used only to estimate the time elapsed since; an estimate below zero (clock moved back) or past
//   the lifetime rotates at once.
import { log } from "../log";

export const ONLINE_MATCH_MS = 30_000;
export const LAST_RESORT_BEFORE_EXP_MS = 60_000;
export const MIN_DEFER_RETRY_MS = 60_000;
export const ROTATE_RETRY_MS = 15_000;

export type StoredSchedule = { gid: string; lifetimeMs: number; receivedWall: number };

export type GrantStatus = { gid: string | null; links: { since: number; routes: number }[]; serverTime: number };

/** The member's observation of its own registration for the lane (hosts.observe). */
export type RegistrationObservation = {
  status: "online" | "offline" | "connecting" | "error" | "unknown";
  /** Local wall time the registration was seen becoming online; null if it was online when first seen. */
  onlineSince: number | null;
  /** Local wall time it was seen leaving online; null while online or unknown. */
  offlineSince: number | null;
};

export type IdleDecision = { action: "rotate" | "defer"; reason: string } | { action: "report"; reason: "unaccounted_link" };

export function scheduleOf(lifetimeMs: number): { idle: number; forced: number; last: number | null; deferRetry: number } {
  const forced = 0.75 * lifetimeMs;
  const last = lifetimeMs - LAST_RESORT_BEFORE_EXP_MS;
  return { idle: 0.5 * lifetimeMs, forced, last: last > forced ? last : null, deferRetry: Math.max(lifetimeMs / 8, MIN_DEFER_RETRY_MS) };
}

/**
 * The idle rule. `requestedAt` and `receivedAt` are the member's wall times around the status call;
 * the host's `serverTime` is mapped to the member's clock at their midpoint.
 */
export function idleDecision(st: GrantStatus, reg: RegistrationObservation, requestedAt: number, receivedAt: number): IdleDecision {
  if (st.links.length === 0) return { action: "rotate", reason: "no_link" };
  const routes = st.links.reduce((n, l) => n + l.routes, 0);
  if (routes === 0) return { action: "rotate", reason: "idle" };
  const offset = st.serverTime - (requestedAt + receivedAt) / 2;
  if (reg.status !== "online" && reg.offlineSince !== null && receivedAt - reg.offlineSince >= ONLINE_MATCH_MS) return { action: "report", reason: "unaccounted_link" };
  if (st.links.length !== 1) return { action: "rotate", reason: "several_links" };
  if (reg.status !== "online") return { action: "rotate", reason: "registration_not_online" };
  if (reg.onlineSince === null) return { action: "rotate", reason: "online_time_unknown" };
  const sinceLocal = st.links[0].since - offset;
  if (Math.abs(sinceLocal - reg.onlineSince) > ONLINE_MATCH_MS) return { action: "rotate", reason: "link_start_mismatch" };
  return { action: "defer", reason: "own_link_busy" };
}

export interface GrantSchedulerDeps {
  roomId: string;
  laneId: string;
  /** Monotonic ms. */
  mono(): number;
  /** Wall ms (only to store the schedule and estimate elapsed time after a restart). */
  wall(): number;
  /** Issues a new grant and registers it with Paseo (hosts.update); resolves with the new grant's facts. */
  rotate(reason: string): Promise<{ gid: string; iat: number; exp: number }>;
  status(): Promise<GrantStatus>;
  registration(): RegistrationObservation;
  report(gid: string): Promise<void>;
  save(s: StoredSchedule): void;
  setTimer?(f: () => void, ms: number): unknown;
  clearTimer?(t: unknown): void;
}

export class GrantScheduler {
  private t0 = 0;
  private lifetimeMs = 0;
  gid: string | null = null;
  private timers: unknown[] = [];
  private rotating: Promise<void> | null = null;
  private stopped = false;
  rotations = 0;
  lastRotation: { reason: string; at: number } | null = null;
  lastDecision: string | null = null;
  lastError: string | null = null;

  constructor(private readonly d: GrantSchedulerDeps) {}

  /** A grant was received now (section 5): t0 is now. */
  armNew(g: { gid: string; iat: number; exp: number }): void {
    const lifetimeMs = Math.max(1000, (g.exp - g.iat) * 1000);
    this.arm(g.gid, lifetimeMs, this.d.mono());
    this.d.save({ gid: g.gid, lifetimeMs, receivedWall: this.d.wall() });
  }

  /** After a restart: re-arm from the stored schedule, or rotate at once when the estimate is unsure. */
  restore(s: StoredSchedule): void {
    const elapsed = this.d.wall() - s.receivedWall;
    if (!(elapsed >= 0) || elapsed >= s.lifetimeMs) {
      this.gid = s.gid;
      log("grant_restore_rotate", { roomId: this.d.roomId, laneId: this.d.laneId, reason: elapsed < 0 ? "clock_moved_back" : "past_lifetime" });
      void this.rotate("restart");
      return;
    }
    this.arm(s.gid, s.lifetimeMs, this.d.mono() - elapsed);
  }

  /** Rotation now (auth failure, `grant.revoked` push, forced points). Coalesces concurrent calls. */
  rotate(reason: string): Promise<void> {
    if (this.stopped) return Promise.resolve();
    this.rotating ??= (async () => {
      try {
        const g = await this.d.rotate(reason);
        this.rotations++;
        this.lastRotation = { reason, at: this.d.wall() };
        this.lastError = null;
        log("grant_rotated", { roomId: this.d.roomId, laneId: this.d.laneId, reason, gid: g.gid });
        if (!this.stopped) this.armNew(g);
      } catch (e) {
        this.lastError = String((e as { code?: string }).code ?? (e as Error).name ?? "error").slice(0, 64);
        log("grant_rotate_failed", { roomId: this.d.roomId, laneId: this.d.laneId, reason, code: this.lastError });
        if (!this.stopped) this.at(ROTATE_RETRY_MS, () => void this.rotate(`${reason.replace(/_retry$/, "")}_retry`));
      } finally {
        this.rotating = null;
      }
    })();
    return this.rotating;
  }

  stop(): void {
    this.stopped = true;
    this.clear();
  }

  /** Next scheduled points, relative to t0 (for status views). */
  view() {
    const s = scheduleOf(this.lifetimeMs);
    return { gid: this.gid, lifetimeMs: this.lifetimeMs, idleInMs: Math.round(this.t0 + s.idle - this.d.mono()), forcedInMs: Math.round(this.t0 + s.forced - this.d.mono()), rotations: this.rotations, lastRotation: this.lastRotation, lastDecision: this.lastDecision, lastError: this.lastError };
  }

  // ------------------------------------------------------------------------------ internals

  private arm(gid: string, lifetimeMs: number, t0: number): void {
    this.clear();
    this.gid = gid;
    this.lifetimeMs = lifetimeMs;
    this.t0 = t0;
    const s = scheduleOf(lifetimeMs);
    const now = this.d.mono();
    this.at(t0 + s.idle - now, () => void this.onIdle());
    this.at(t0 + s.forced - now, () => void this.rotate("forced"));
    if (s.last !== null) this.at(t0 + s.last - now, () => void this.rotate("last_resort"));
  }

  private async onIdle(): Promise<void> {
    if (this.stopped || this.rotating) return;
    const s = scheduleOf(this.lifetimeMs);
    let decision: IdleDecision;
    try {
      const requestedAt = this.d.wall();
      const st = await this.d.status();
      decision = idleDecision(st, this.d.registration(), requestedAt, this.d.wall());
    } catch (e) {
      decision = { action: "rotate", reason: `status_failed:${String((e as { code?: string }).code ?? "error").slice(0, 24)}` };
    }
    this.lastDecision = `${decision.action}:${decision.reason}`;
    log("grant_idle_decision", { roomId: this.d.roomId, laneId: this.d.laneId, action: decision.action, reason: decision.reason });
    if (decision.action === "defer") {
      const next = this.d.mono() + s.deferRetry;
      if (next < this.t0 + s.forced) this.at(s.deferRetry, () => void this.onIdle());
      return;
    }
    if (decision.action === "report" && this.gid) {
      try {
        await this.d.report(this.gid);
      } catch (e) {
        log("grant_report_failed", { roomId: this.d.roomId, laneId: this.d.laneId, code: String((e as { code?: string }).code ?? "error").slice(0, 32) });
      }
    }
    await this.rotate(decision.action === "report" ? "unaccounted_link" : "idle");
  }

  private at(ms: number, f: () => void): void {
    const t = (this.d.setTimer ?? ((g, d) => setTimeout(g, d)))(f, Math.min(Math.max(0, ms), 2 ** 31 - 1));
    this.timers.push(t);
  }

  private clear(): void {
    for (const t of this.timers) (this.d.clearTimer ?? ((x) => clearTimeout(x as ReturnType<typeof setTimeout>)))(t);
    this.timers = [];
  }
}
