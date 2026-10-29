// Enrollment on the room host (enrollment-v2.md sections 2.1, 5, 6, 7.1, 7.2, 9, 10; room-log-v2.md
// 4.2; implementation plan I-9; HARDENING-PLAN D: P-15/C-7, P-23/C-8, P-27).
//
// - Check order of 5.3 for `enroll.request`: strict frame, version, pre-auth budget, then the
//   device signature over EnrollSigned with THIS session's handshake hash `h` and the room's
//   genesisHash (and `deviceDh == rs`) BEFORE any lookup, so a bad signature learns nothing (P-23).
//   Then the invite lookup and the constant-time token MAC check; every failure up to here is the
//   same `enroll_rejected`. Only a requester who proved token knowledge learns the invite's state.
// - Attempt limits of 5.4 per invite: 3 failed token proofs, 3 abandoned attempts, 1 SAS rejection
//   each burn the invite and log `invite.burned`. A request naming an unknown inviteId touches no
//   invite (P-15: a past invitee who knows only the endpoint key cannot burn anything).
// - Pre-auth budget: a token bucket (10 per minute, burst 5) per room endpoint, consumed only by
//   statics that are not active devices; 16 open pending enrollments per room.
// - SAS commit-then-reveal (6.1): the host pins `h`, `sasCommit` and `Nh` when it accepts a request
//   and never re-pins (5.6, S-3). `enroll.resume` and a repeated `enroll.request` from the same keys
//   return the stored `enroll.pending` content byte for byte; a changed `sasCommit` closes the old
//   pending as abandoned.
// - Admission (7.2) needs both confirmations. The admin's Admit is the confirmation of the
//   `member.admitted` statement (identity 5.3); when the member's confirm arrives later the daemon
//   signs then. Log append (fsync) comes before the host state and before `enroll.admitted`; a crash
//   in between is repaired at load from the log.
// - P-27: every invite and pending transition except open -> claimed -> open is a host-produced log
//   entry (invite.expired, invite.burned, invite.contested, enrollment.pending, enrollment.closed).
// - State: `host/<roomId>/state.sealed` (invites with tokenKey, pending enrollments), sealed under
//   the KEK and written before any log entry or reply that depends on it.
//
// Not here: device links (`linkId`, I-11; a linkId request gets the generic rejection after the
// signature check), the daily expiry sweep of unused invites (expiry is computed lazily on lookup),
// per-device budgets of active devices (I-10).
import { randomBytes } from "node:crypto";
import nodePath from "node:path";
import { z } from "zod";
import { authorityChainOf } from "../authority/authority-chain";
import type { SignedEntry } from "../authority/entries";
import { b64uBytes, entityId, Hash32, nonNegInt } from "../authority/schema";
import type { SignedStatement, StatementType } from "../authority/statements";
import { keysInUse } from "../authority/state";
import type { Kek } from "../keystore/keystore";
import { log, logError } from "../log";
import { b64u, b64uDecode } from "../proto/b64u";
import { computeSas, enrollSigned, isValidLabel, sasCommitOf, tokenKeyOf, tokenMacMatches, verifyEnrollSig, type Sas } from "../proto/enroll";
import { edKid } from "../authority/state";
import { inviteRef, isId, newId } from "../proto/ids";
import { rjcs, rjcsParse, rjcsText, RJCS_MAX_FRAME_BYTES } from "../proto/rjcs";
import type { Frame } from "../transport/records";
import { isRequestId, type RoomErrorCode } from "../transport/room-session";
import { encodeInvite, InviteRecord, parseInviteTerms, type InvitePayload } from "./invites";
import { hostRoomDir } from "./room-log-store";
import type { RoomHost } from "./room-host";

export const HOST_STATE_FILE = "state.sealed";
export const hostStatePath = (dataDir: string, roomId: string) => nodePath.join(hostRoomDir(dataDir, roomId), HOST_STATE_FILE);
export const hostStatePurpose = (roomId: string) => `host-state:${roomId}`;

export interface EnrollmentLimits {
  failedProofs: number;
  abandoned: number;
  preauthPerMinute: number;
  preauthBurst: number;
  maxPending: number;
  /** A pending enrollment lives at most this long (and never past the invite's exp). */
  pendingTtlMs: number;
  /** Closed and admitted pending records are kept this long to answer `enroll.resume`. */
  keepClosedMs: number;
}

export const ENROLLMENT_LIMITS: Readonly<EnrollmentLimits> = {
  failedProofs: 3,
  abandoned: 3,
  preauthPerMinute: 10,
  preauthBurst: 5,
  maxPending: 16,
  pendingTtlMs: 15 * 60 * 1000,
  keepClosedMs: 24 * 60 * 60 * 1000,
};

export type ClosedReason = "rejected" | "timeout" | "invite_revoked" | "room_closed" | "aborted" | "vetoed";
const CLOSED_REASONS = ["rejected", "timeout", "invite_revoked", "room_closed", "aborted", "vetoed"] as const;

const PendingRecord = z.strictObject({
  pendingId: entityId("pending"),
  inviteId: entityId("invite"),
  /** Pinned inputs (5.6). */
  h: Hash32,
  sasCommit: Hash32,
  nh: Hash32,
  nm: Hash32.nullable(),
  deviceSig: b64uBytes(32),
  deviceDh: b64uBytes(32),
  label: z.string().max(400),
  createdAt: nonNegInt(),
  expiresAt: nonNegInt(),
  /** RJCS text of the `enroll.pending` content (the frame minus `t` and `re`): resent byte for byte. */
  content: z.string(),
  memberOk: z.boolean(),
  adminOk: z.boolean(),
  contested: z.boolean(),
  status: z.enum(["open", "admitted", "closed"]),
  closedReason: z.enum(CLOSED_REASONS).nullable(),
  /** RJCS text of the `enroll.admitted` frame, once admitted. */
  admitted: z.string().nullable(),
  endedAt: nonNegInt().nullable(),
});
type PendingRecord = z.infer<typeof PendingRecord>;

const HostState = z.strictObject({
  v: z.literal(2),
  typ: z.literal("host-state"),
  roomId: z.string(),
  invites: z.array(InviteRecord).max(4096),
  pendings: z.array(PendingRecord).max(4096),
});
type HostState = z.infer<typeof HostState>;

const STATE_MAX_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------------- frames

const B32 = b64uBytes(32);
const EnrollRequestFrame = z.union([
  z.strictObject({ t: z.literal("enroll.request"), id: z.number(), v: z.number().int(), inviteId: z.string().max(64), deviceSig: B32, deviceDh: B32, label: z.string().max(400), sasCommit: B32, tokenMac: B32, sig: b64uBytes(64) }),
  z.strictObject({ t: z.literal("enroll.request"), id: z.number(), v: z.number().int(), linkId: z.string().max(64), deviceSig: B32, deviceDh: B32, label: z.string().max(400), sasCommit: B32, tokenMac: B32, sig: b64uBytes(64) }),
]);
const RevealFrame = z.strictObject({ t: z.literal("sas.reveal"), id: z.number(), Nm: B32 });
const ConfirmFrame = z.strictObject({ t: z.literal("enroll.confirm"), id: z.number(), pendingId: z.string().max(64) });
const AbortFrame = z.strictObject({ t: z.literal("enroll.abort"), id: z.number(), pendingId: z.string().max(64), reason: z.enum(["sas_mismatch", "cancelled"]) });
const ResumeFrame = z.strictObject({ t: z.literal("enroll.resume"), id: z.number(), pendingId: z.string().max(64) });

/** What the enrollment code needs from one room session (server/host/room-endpoint.ts). */
export interface EnrollSession {
  /** This session's handshake hash, b64u. */
  readonly h: string;
  /** The initiator static (device DH key), b64u. */
  readonly rs: string;
  readonly tag: string | null;
  /** `rs` is an active device in the roster. */
  isActive(): boolean;
  isOpen(): boolean;
  send(frame: Frame): void;
  fail(code: RoomErrorCode, re?: number, fields?: Record<string, unknown>): void;
  /** After admission: the same session becomes an active-device session. */
  promote(): void;
}

export interface EnrollmentHostOptions {
  host: RoomHost;
  dataDir: string;
  kek: Kek;
  /**
   * Signs and submits an admin statement (the admin's UI confirmation is the caller's action:
   * create invite, revoke invite, Admit). Returns the statement and its receipt, or throws.
   */
  admin: ((type: StatementType, data: unknown) => { statement: SignedStatement; receipt: SignedEntry }) | null;
  /** After any host-produced entry (pushes to subscribers, enforces). */
  afterAppend: () => void;
  endpointDh: () => string;
  now?: () => number;
  limits?: Partial<EnrollmentLimits>;
  /** Sweep interval for pending expiry; 0 disables the timer (tests call `sweep`). */
  sweepMs?: number;
}

export class EnrollmentError extends Error {
  constructor(
    readonly code: "unknown_invite" | "unknown_pending" | "not_open" | "not_revealed" | "no_admin_key" | "refused",
    message: string,
  ) {
    super(message);
    this.name = "EnrollmentError";
  }
}

/** Pre-auth token bucket (5.4). */
export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(
    private readonly perMinute: number,
    private readonly burst: number,
    private readonly now: () => number,
  ) {
    this.tokens = burst;
    this.last = now();
  }
  take(): boolean {
    this.refill();
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
  /** Seconds until one token is available. */
  retryAfter(): number {
    this.refill();
    return this.tokens >= 1 ? 0 : Math.max(1, Math.ceil(((1 - this.tokens) * 60) / this.perMinute));
  }
  private refill(): void {
    const n = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((n - this.last) / 60_000) * this.perMinute);
    this.last = n;
  }
}

export type PendingView = {
  pendingId: string;
  inviteRef: string;
  note: string;
  inviteCreatedAt: number;
  label: string;
  state: "created" | "sas_shown" | "member_ok" | "admin_ok" | "admitted" | "closed";
  /** "317 837" once the member revealed Nm; null before. */
  sas: string | null;
  abandonedBefore: number;
  contested: boolean;
  expiresAt: number;
  closedReason: ClosedReason | null;
  memberId: string | null;
};

export type InviteView = Omit<InviteRecord, "tokenKey"> & { inviteRef: string };

export class EnrollmentHost {
  readonly limits: EnrollmentLimits;
  private st: HostState;
  private readonly bucket: TokenBucket;
  /** The session last attached to each open pending (for pushes). */
  private readonly sessions = new Map<string, EnrollSession>();
  private readonly timer: ReturnType<typeof setInterval> | null;
  private readonly now: () => number;

  constructor(private readonly o: EnrollmentHostOptions) {
    this.limits = { ...ENROLLMENT_LIMITS, ...o.limits };
    this.now = o.now ?? Date.now;
    this.bucket = new TokenBucket(this.limits.preauthPerMinute, this.limits.preauthBurst, this.now);
    this.st = this.load();
    this.repairAdmitted();
    this.sweep();
    const every = o.sweepMs ?? 1000;
    this.timer = every > 0 ? setInterval(() => this.safeSweep(), every) : null;
    (this.timer as { unref?: () => void } | null)?.unref?.();
  }

  get roomId(): string {
    return this.o.host.roomId;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.sessions.clear();
  }

  // ------------------------------------------------------------------------------ admin actions

  /** Creates an invite (the caller's confirmation signs `invite.created`). Returns the bearer code. */
  createInvite(i: { role?: unknown; lanes?: unknown; expS?: unknown; note?: unknown; roomName?: string }): { code: string; inviteId: string; inviteRef: string; exp: number } {
    const terms = parseInviteTerms({ role: i.role, lanes: i.lanes, expS: i.expS, note: i.note });
    const admin = this.requireAdmin();
    const host = this.o.host;
    const inviteId = newId("invite");
    const token = randomBytes(32);
    const exp = Math.floor(this.now() / 1000) + terms.expS;
    const ref = inviteRef(inviteId);
    try {
      // Log first: a crash after the entry leaves an invite that no record can redeem (harmless);
      // the reverse would leave a redeemable invite the log never mentioned.
      admin("invite.created", { inviteRef: ref, role: terms.role, lanes: terms.lanes, exp });
      const record: InviteRecord = { inviteId, tokenKey: b64u(tokenKeyOf(token)), role: terms.role, lanes: terms.lanes, note: terms.note, createdAt: this.now(), exp, state: "open", failedProofs: 0, abandoned: 0, pendingId: null, usedBy: null };
      this.persist({ ...this.st, invites: [...this.st.invites, record] });
      const ep = host.state.auth.endpoint;
      const payload: InvitePayload = {
        v: 2,
        typ: "invite",
        roomId: host.roomId,
        genesisHash: host.genesisHash,
        roomName: (i.roomName ?? "Room").slice(0, 80),
        endpoint: { serverId: ep.serverId, dh: { alg: "x25519", kid: ep.dh.kid, pub: ep.dh.pub }, relay: { host: ep.relay.host, port: ep.relay.port, tls: true } },
        inviteId,
        token: b64u(token),
        exp,
        sas: "sas6",
      };
      log("invite_created", { roomId: this.roomId, inviteRef: ref, exp });
      return { code: encodeInvite(payload), inviteId, inviteRef: ref, exp };
    } finally {
      token.fill(0);
    }
  }

  revokeInvite(inviteId: string): void {
    const inv = this.invite(inviteId);
    if (!inv) throw new EnrollmentError("unknown_invite", "Unknown invite");
    if (inv.state !== "open" && inv.state !== "claimed") throw new EnrollmentError("not_open", `The invite is ${inv.state}`);
    this.requireAdmin()("invite.revoked", { inviteRef: inviteRef(inviteId) });
    const pendingId = inv.state === "claimed" ? inv.pendingId : null;
    this.updateInvite(inviteId, { state: "revoked", pendingId: null });
    if (pendingId) this.closePending(pendingId, "invite_revoked", "none");
  }

  invites(): InviteView[] {
    return this.st.invites.map(({ tokenKey: _t, ...rest }) => ({ ...rest, inviteRef: inviteRef(rest.inviteId) }));
  }

  pendings(): PendingView[] {
    return this.st.pendings.map((p) => {
      const inv = this.invite(p.inviteId);
      return {
        pendingId: p.pendingId,
        inviteRef: inviteRef(p.inviteId),
        note: inv?.note ?? "",
        inviteCreatedAt: inv?.createdAt ?? 0,
        label: p.label,
        state: stateOf(p),
        sas: p.nm && p.status !== "closed" ? this.sasOf(p).display : null,
        abandonedBefore: inv?.abandoned ?? 0,
        contested: p.contested,
        expiresAt: p.expiresAt,
        closedReason: p.closedReason,
        memberId: p.admitted ? ((rjcsParse(Buffer.from(p.admitted), RJCS_MAX_FRAME_BYTES) as { memberId: string }).memberId ?? null) : null,
      };
    });
  }

  /** The admin pressed Admit (enabled only once the member revealed Nm). */
  admit(pendingId: string): PendingView["state"] {
    const p = this.openPending(pendingId);
    if (!p.nm) throw new EnrollmentError("not_revealed", "The member has not revealed the code yet");
    this.requireAdmin();
    this.updatePending(pendingId, { adminOk: true });
    if (p.memberOk) this.admitNow(pendingId);
    return stateOf(this.pending(pendingId)!);
  }

  /** "Codes do not match" (burns the invite) or Cancel (an abandoned attempt). */
  reject(pendingId: string, why: "sas_mismatch" | "cancel"): void {
    this.openPending(pendingId);
    this.closePending(pendingId, "rejected", why === "sas_mismatch" ? "sas_mismatch" : "abandoned");
  }

  // ------------------------------------------------------------------------------ session frames

  /** A pre-auth operation from a room session (section 4). */
  handle(s: EnrollSession, frame: Frame): void {
    try {
      switch (frame.t) {
        case "enroll.request":
          return this.onRequest(s, frame);
        case "sas.reveal":
          return this.onReveal(s, frame);
        case "enroll.confirm":
          return this.onConfirm(s, frame);
        case "enroll.abort":
          return this.onAbort(s, frame);
        case "enroll.resume":
          return this.onResume(s, frame);
        default:
          return s.fail("bad_frame", frame.id);
      }
    } catch (err) {
      logError("enroll_op_failed", err, { roomId: this.roomId, conn: s.tag, op: frame.t.slice(0, 32) });
      return s.fail("internal", frame.id);
    }
  }

  /** Section 5.3, in order. */
  private onRequest(s: EnrollSession, frame: Frame): void {
    // 1. canonical (records.ts) and schema
    const f = EnrollRequestFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const r = f.data;
    // 2. version
    if (r.v !== 2) return s.fail("unsupported_version", r.id, { minVersion: 2 });
    // 3. pre-auth budget (only statics that are not active devices count)
    if (!s.isActive() && !this.bucket.take()) {
      this.reject_(s, r.id, "busy");
      return s.fail("busy", r.id, { retryAfter: this.bucket.retryAfter() });
    }
    // 4. deviceDh == rs, and the signature over EnrollSigned with THIS session's h. No lookup yet (P-23).
    const target = "inviteId" in r ? { inviteId: r.inviteId } : { linkId: r.linkId };
    if (r.deviceDh !== s.rs || r.deviceSig === r.deviceDh || !isValidLabel(r.label)) return this.generic(s, r.id, "request_fields");
    const signed = enrollSigned({ h: s.h, genesisHash: this.o.host.genesisHash, target, deviceSig: r.deviceSig, deviceDh: r.deviceDh, label: r.label, sasCommit: r.sasCommit });
    if (!verifyEnrollSig(signed, r.sig)) return this.generic(s, r.id, "bad_signature");
    // 5. lookup (device links are I-11)
    if (!("inviteId" in r) || !isId("invite", r.inviteId)) return this.generic(s, r.id, "unknown_target");
    const inv = this.invite(r.inviteId);
    if (!inv) return this.generic(s, r.id, "unknown_target");
    // 6. token proof, constant time
    if (!tokenMacMatches(b64uDecode(inv.tokenKey, 32), signed, r.tokenMac)) {
      this.failedProof(inv);
      return this.generic(s, r.id, "bad_token");
    }
    // 7. the requester knows the token: the invite's state may be disclosed
    const cur = this.expireIfDue(inv.inviteId);
    if (cur.state === "expired") return s.fail("invite_expired", r.id);
    if (cur.state === "used") return s.fail("invite_used", r.id);
    if (cur.state === "revoked" || cur.state === "burned") return s.fail("invite_revoked", r.id);
    if (cur.state === "claimed") {
      const holder = cur.pendingId ? this.pending(cur.pendingId) : undefined;
      if (holder && holder.deviceDh !== s.rs) {
        this.contest(holder);
        return s.fail("invite_in_use", r.id);
      }
    }
    // 8. keys already in the roster, retired or denylisted -> generic; the same keys in a pending -> resume
    const st = this.o.host.state;
    const inUse = keysInUse(st);
    if ([r.deviceSig, r.deviceDh].some((k) => inUse.has(k) || st.auth.retiredKeys[k] || st.deviceDenylist[k])) return this.generic(s, r.id, "keys_in_use");
    const same = this.st.pendings.find((p) => p.status === "open" && (p.deviceDh === r.deviceDh || p.deviceSig === r.deviceSig || p.deviceDh === r.deviceSig || p.deviceSig === r.deviceDh));
    if (same) {
      if (same.deviceDh !== s.rs || same.deviceSig !== r.deviceSig || same.inviteId !== inv.inviteId) return this.generic(s, r.id, "keys_in_other_pending");
      if (same.sasCommit !== r.sasCommit) {
        // The member lost its journal: the old attempt is abandoned; never re-pin (5.6).
        this.closePending(same.pendingId, "aborted", "abandoned");
        return this.generic(s, r.id, "commit_changed");
      }
      return this.resumeReply(s, r.id, same);
    }
    // 9. create the pending enrollment
    if (this.st.pendings.filter((p) => p.status === "open").length >= this.limits.maxPending) {
      this.reject_(s, r.id, "pending_cap");
      return s.fail("busy", r.id, { retryAfter: 60 });
    }
    this.create(s, r.id, cur, { h: s.h, sasCommit: r.sasCommit, deviceSig: r.deviceSig, deviceDh: r.deviceDh, label: r.label });
  }

  private create(s: EnrollSession, re: number, inv: InviteRecord, req: { h: string; sasCommit: string; deviceSig: string; deviceDh: string; label: string }): void {
    const host = this.o.host;
    const pendingId = newId("pending");
    const now = this.now();
    const expiresAt = Math.min(inv.exp * 1000, now + this.limits.pendingTtlMs);
    const nh = randomBytes(32);
    // Only the genesis and the authority-key chain: no roster, invite, lane, grant or chat entry
    // reaches a requester before admission (server/authority/authority-chain.ts).
    const content = {
      pendingId,
      h: req.h,
      Nh: b64u(nh),
      genesis: host.genesis,
      authority: authorityChainOf(host.entries(0), b64u),
      terms: { role: inv.role, lanes: inv.lanes },
      expiresAt,
    };
    const text = rjcsText(content);
    const record: PendingRecord = {
      pendingId,
      inviteId: inv.inviteId,
      h: req.h,
      sasCommit: req.sasCommit,
      nh: b64u(nh),
      nm: null,
      deviceSig: req.deviceSig,
      deviceDh: req.deviceDh,
      label: req.label,
      createdAt: now,
      expiresAt,
      content: text,
      memberOk: false,
      adminOk: false,
      contested: false,
      status: "open",
      closedReason: null,
      admitted: null,
      endedAt: null,
    };
    // Persist (claimed + pending) before the log entry and before the reply.
    this.persist({
      ...this.st,
      invites: this.st.invites.map((i) => (i.inviteId === inv.inviteId ? { ...i, state: "claimed" as const, pendingId } : i)),
      pendings: [...this.st.pendings, record],
    });
    this.emit("enrollment.pending", { inviteRef: inviteRef(inv.inviteId), pendingId, deviceKid: edKid(req.deviceSig) });
    this.sessions.set(pendingId, s);
    log("enroll_pending", { roomId: this.roomId, pendingId, conn: s.tag });
    s.send({ t: "enroll.pending", re, ...(content as unknown as Record<string, never>) });
  }

  private onReveal(s: EnrollSession, frame: Frame): void {
    const f = RevealFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const p = this.st.pendings.find((x) => x.deviceDh === s.rs && x.status === "open") ?? this.lastOf(s.rs);
    if (!p) return this.generic(s, f.data.id, "reveal_without_pending");
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    if (p.status === "admitted") return s.send({ t: "sas.reveal.ok", re: f.data.id });
    if (p.nm !== null) {
      if (p.nm === f.data.Nm) return s.send({ t: "sas.reveal.ok", re: f.data.id });
      return this.generic(s, f.data.id, "reveal_changed");
    }
    if (sasCommitOf(b64uDecode(f.data.Nm, 32)) !== p.sasCommit) {
      // The requester gets the generic reply below, not the closed push.
      this.sessions.delete(p.pendingId);
      this.closePending(p.pendingId, "aborted", "abandoned");
      return this.generic(s, f.data.id, "commit_mismatch");
    }
    this.updatePending(p.pendingId, { nm: f.data.Nm });
    this.sessions.set(p.pendingId, s);
    log("enroll_sas_revealed", { roomId: this.roomId, pendingId: p.pendingId });
    s.send({ t: "sas.reveal.ok", re: f.data.id });
  }

  private onConfirm(s: EnrollSession, frame: Frame): void {
    const f = ConfirmFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const p = this.pending(f.data.pendingId);
    if (!p || p.deviceDh !== s.rs) return this.generic(s, f.data.id, "confirm_unknown");
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    if (!p.nm) return s.fail("bad_frame", f.data.id);
    this.sessions.set(p.pendingId, s);
    if (p.status === "open" && !p.memberOk) this.updatePending(p.pendingId, { memberOk: true });
    s.send({ t: "enroll.confirm.ok", re: f.data.id });
    const now = this.pending(p.pendingId)!;
    if (now.status === "admitted") return this.deliverAdmitted(now);
    if (now.status !== "open" || !now.adminOk) return;
    try {
      this.admitNow(p.pendingId);
    } catch (err) {
      // The pending stays open with both confirmations; the admin's next Admit retries.
      logError("enroll_admit_failed", err, { roomId: this.roomId, pendingId: p.pendingId });
    }
  }

  private onAbort(s: EnrollSession, frame: Frame): void {
    const f = AbortFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const p = this.pending(f.data.pendingId);
    if (!p || p.deviceDh !== s.rs) return this.generic(s, f.data.id, "abort_unknown");
    if (p.status !== "open") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    this.sessions.delete(p.pendingId);
    this.closePending(p.pendingId, "aborted", f.data.reason === "sas_mismatch" ? "sas_mismatch" : "abandoned");
    s.send({ t: "enroll.abort.ok", re: f.data.id });
  }

  private onResume(s: EnrollSession, frame: Frame): void {
    const f = ResumeFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const p = this.pending(f.data.pendingId);
    // Only the session whose rs is the pending's deviceDh (5.6 rule 1).
    if (!p || p.deviceDh !== s.rs) return this.generic(s, f.data.id, "resume_other_static");
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    return this.resumeReply(s, f.data.id, p);
  }

  private resumeReply(s: EnrollSession, re: number, p: PendingRecord): void {
    this.sessions.set(p.pendingId, s);
    const pending = rjcsParse(Buffer.from(p.content), RJCS_MAX_FRAME_BYTES);
    const admitted = p.admitted ? rjcsParse(Buffer.from(p.admitted), RJCS_MAX_FRAME_BYTES) : undefined;
    // An admitted pending reports the last pre-admission state together with `admitted`.
    const state = p.status === "admitted" ? "member_ok" : stateOf(p);
    log("enroll_resumed", { roomId: this.roomId, pendingId: p.pendingId, state, conn: s.tag });
    s.send({ t: "enroll.resume.ok", re, pending, state, ...(admitted ? { admitted } : {}) } as Frame);
    if (p.status === "admitted") s.promote();
  }

  // ------------------------------------------------------------------------------ transitions

  /** Both confirmations are in: sign member.admitted, append (fsync), persist, deliver (7.2). */
  private admitNow(pendingId: string): void {
    const p = this.pending(pendingId)!;
    const inv = this.invite(p.inviteId)!;
    const admin = this.requireAdmin();
    const memberId = newId("member");
    const deviceId = newId("device");
    const sas = this.sasOf(p);
    const { statement, receipt } = admin("member.admitted", {
      member: { memberId, role: inv.role, lanes: inv.lanes, devices: [{ deviceId, kind: "person", sig: p.deviceSig, dh: p.deviceDh }] },
      confirmation: { method: "sas6", inviteRef: inviteRef(inv.inviteId), transcript: sas.transcript },
    });
    this.recordAdmitted(p, memberId, deviceId, statement, receipt);
  }

  private recordAdmitted(p: PendingRecord, memberId: string, deviceId: string, statement: SignedStatement, entry: SignedEntry): void {
    const host = this.o.host;
    const head = host.headEntry!;
    const frame = { t: "enroll.admitted", pendingId: p.pendingId, memberId, deviceId, statement, entry, roster: host.roster(), head: { seq: head.entry.seq, hash: head.hash, hsig: head.hsig } };
    this.persist({
      ...this.st,
      invites: this.st.invites.map((i) => (i.inviteId === p.inviteId ? { ...i, state: "used" as const, usedBy: memberId } : i)),
      pendings: this.st.pendings.map((x) => (x.pendingId === p.pendingId ? { ...x, memberOk: true, adminOk: true, status: "admitted" as const, admitted: rjcsText(frame), endedAt: this.now() } : x)),
    });
    log("enroll_admitted", { roomId: this.roomId, pendingId: p.pendingId, memberId, deviceId, seq: entry.entry.seq });
    this.deliverAdmitted(this.pending(p.pendingId)!);
  }

  private deliverAdmitted(p: PendingRecord): void {
    const s = this.sessions.get(p.pendingId);
    if (!s || !s.isOpen() || !p.admitted) return;
    s.send(rjcsParse(Buffer.from(p.admitted), RJCS_MAX_FRAME_BYTES) as Frame);
    s.promote();
  }

  /**
   * Ends a pending enrollment. `count`: "abandoned" (5.4: +1, the third burns), "sas_mismatch"
   * (burns at once), or "none" (the invite already changed: revoked, room closed).
   */
  private closePending(pendingId: string, reason: ClosedReason, count: "abandoned" | "sas_mismatch" | "none"): void {
    const p = this.pending(pendingId);
    if (!p || p.status !== "open") return;
    const inv = this.invite(p.inviteId);
    let burn: "abandoned" | "sas_mismatch" | null = null;
    let expired = false;
    let invPatch: Partial<InviteRecord> = {};
    if (inv && inv.state === "claimed" && inv.pendingId === pendingId && count !== "none") {
      if (count === "sas_mismatch") burn = "sas_mismatch";
      else {
        const abandoned = inv.abandoned + 1;
        invPatch.abandoned = abandoned;
        if (abandoned >= this.limits.abandoned) burn = "abandoned";
        else if (inv.exp * 1000 <= this.now()) expired = true;
      }
      invPatch = { ...invPatch, state: burn ? "burned" : expired ? "expired" : "open", pendingId: null };
    }
    this.persist({
      ...this.st,
      invites: this.st.invites.map((i) => (inv && i.inviteId === inv.inviteId ? { ...i, ...invPatch } : i)),
      pendings: this.st.pendings.map((x) => (x.pendingId === pendingId ? { ...x, status: "closed" as const, closedReason: reason, endedAt: this.now() } : x)),
    });
    this.emit("enrollment.closed", { pendingId, reason });
    if (inv && burn) this.emit("invite.burned", { inviteRef: inviteRef(inv.inviteId), reason: burn });
    if (inv && expired) this.emit("invite.expired", { inviteRef: inviteRef(inv.inviteId) });
    log("enroll_closed", { roomId: this.roomId, pendingId, reason, invite: burn ? `burned:${burn}` : (invPatch.state ?? inv?.state ?? null) });
    const s = this.sessions.get(pendingId);
    this.sessions.delete(pendingId);
    if (s && s.isOpen()) {
      s.send({ t: "enroll.closed", pendingId, reason });
      if (!s.isActive()) s.fail("enroll_closed", undefined, { reason });
    }
  }

  private failedProof(inv: InviteRecord): void {
    if (inv.state !== "open" && inv.state !== "claimed") return;
    const failedProofs = inv.failedProofs + 1;
    const burn = failedProofs >= this.limits.failedProofs;
    const pendingId = inv.state === "claimed" ? inv.pendingId : null;
    this.updateInvite(inv.inviteId, burn ? { failedProofs, state: "burned", pendingId: null } : { failedProofs });
    if (!burn) return;
    this.emit("invite.burned", { inviteRef: inviteRef(inv.inviteId), reason: "attempts" });
    log("invite_burned", { roomId: this.roomId, inviteRef: inviteRef(inv.inviteId), reason: "attempts" });
    if (pendingId) this.closePending(pendingId, "invite_revoked", "none");
  }

  private contest(holder: PendingRecord): void {
    if (!holder.contested) this.updatePending(holder.pendingId, { contested: true });
    this.emit("invite.contested", { inviteRef: inviteRef(holder.inviteId), pendingId: holder.pendingId });
    log("invite_contested", { roomId: this.roomId, pendingId: holder.pendingId });
  }

  /** Lazy expiry of an open invite (7.1): logged once, the first time it is looked at. */
  private expireIfDue(inviteId: string): InviteRecord {
    const inv = this.invite(inviteId)!;
    if (inv.state !== "open" || inv.exp * 1000 > this.now()) return inv;
    this.updateInvite(inviteId, { state: "expired" });
    this.emit("invite.expired", { inviteRef: inviteRef(inviteId) });
    return this.invite(inviteId)!;
  }

  /** Pending expiry, room closure and pruning of old closed records. */
  sweep(): void {
    const now = this.now();
    const closed = this.o.host.state.auth.closed;
    for (const p of this.st.pendings) {
      if (p.status !== "open") continue;
      if (closed) this.closePending(p.pendingId, "room_closed", "none");
      else if (p.expiresAt <= now) this.closePending(p.pendingId, "timeout", "abandoned");
    }
    const keep = this.st.pendings.filter((p) => p.status === "open" || (p.endedAt ?? now) + this.limits.keepClosedMs > now);
    if (keep.length !== this.st.pendings.length) this.persist({ ...this.st, pendings: keep });
  }

  private safeSweep(): void {
    try {
      if (!this.o.host.isStopped) this.sweep();
    } catch (err) {
      logError("enroll_sweep_failed", err, { roomId: this.roomId });
    }
  }

  /**
   * A crash after the `member.admitted` append and before the host state write leaves an open
   * pending whose keys are in the roster: rebuild its `enroll.admitted` from the log.
   */
  private repairAdmitted(): void {
    const host = this.o.host;
    for (const p of this.st.pendings) {
      if (p.status !== "open" || !p.memberOk || !p.adminOk) continue;
      for (const r of host.entries(0)) {
        if (r.signed.entry.type !== "member.admitted") continue;
        const stmt = rjcsParse(r.body) as SignedStatement;
        const m = (stmt.body.data as { member: { memberId: string; devices: { deviceId: string; dh: string }[] } }).member;
        const d = m.devices.find((x) => x.dh === p.deviceDh);
        if (!d) continue;
        log("enroll_admitted_repaired", { roomId: this.roomId, pendingId: p.pendingId, seq: r.signed.entry.seq });
        this.recordAdmitted(p, m.memberId, d.deviceId, stmt, r.signed);
        break;
      }
    }
  }

  // ------------------------------------------------------------------------------ helpers

  private sasOf(p: PendingRecord): Sas {
    return computeSas({
      h: b64uDecode(p.h, 32),
      nm: b64uDecode(p.nm!, 32),
      nh: b64uDecode(p.nh, 32),
      deviceDh: p.deviceDh,
      deviceSig: p.deviceSig,
      endpointDh: this.o.endpointDh(),
      genesisHash: this.o.host.genesisHash,
      target: { inviteId: p.inviteId },
    });
  }

  private generic(s: EnrollSession, re: number | undefined, why: string): void {
    this.reject_(s, re, why);
    s.fail("enroll_rejected", re);
  }

  private reject_(_s: EnrollSession, _re: number | undefined, why: string): void {
    this.o.host.access.record({ event: "preauth_failed", reason: `enroll:${why}` });
  }

  private requireAdmin(): NonNullable<EnrollmentHostOptions["admin"]> {
    if (!this.o.admin) throw new EnrollmentError("no_admin_key", "No admin key for this room on this daemon");
    return this.o.admin;
  }

  private emit<T extends StatementType>(type: T, data: unknown): void {
    this.o.host.emit(type, data as never);
    this.o.afterAppend();
  }

  private invite(inviteId: string): InviteRecord | undefined {
    return this.st.invites.find((i) => i.inviteId === inviteId);
  }

  private pending(pendingId: string): PendingRecord | undefined {
    return this.st.pendings.find((p) => p.pendingId === pendingId);
  }

  private lastOf(rs: string): PendingRecord | undefined {
    return this.st.pendings.filter((p) => p.deviceDh === rs).at(-1);
  }

  private openPending(pendingId: string): PendingRecord {
    const p = this.pending(pendingId);
    if (!p) throw new EnrollmentError("unknown_pending", "Unknown join request");
    if (p.status !== "open") throw new EnrollmentError("not_open", `The join request is ${p.status}`);
    return p;
  }

  private updateInvite(inviteId: string, patch: Partial<InviteRecord>): void {
    this.persist({ ...this.st, invites: this.st.invites.map((i) => (i.inviteId === inviteId ? { ...i, ...patch } : i)) });
  }

  private updatePending(pendingId: string, patch: Partial<PendingRecord>): void {
    this.persist({ ...this.st, pendings: this.st.pendings.map((p) => (p.pendingId === pendingId ? { ...p, ...patch } : p)) });
  }

  private load(): HostState {
    const plain = this.o.kek.readSealed(hostStatePath(this.o.dataDir, this.roomId), hostStatePurpose(this.roomId));
    if (!plain) return { v: 2, typ: "host-state", roomId: this.roomId, invites: [], pendings: [] };
    try {
      const parsed = HostState.safeParse(rjcsParse(plain, STATE_MAX_BYTES));
      if (!parsed.success || parsed.data.roomId !== this.roomId) throw new Error("host state file is invalid");
      return parsed.data;
    } finally {
      plain.fill(0);
    }
  }

  /** Sealed write (durable) first; memory follows only after it succeeded. */
  private persist(next: HostState): void {
    const plain = Buffer.from(rjcs(next, STATE_MAX_BYTES));
    try {
      this.o.kek.writeSealed(hostStatePath(this.o.dataDir, this.roomId), hostStatePurpose(this.roomId), plain);
    } finally {
      plain.fill(0);
    }
    this.st = next;
  }
}

function stateOf(p: PendingRecord): PendingView["state"] {
  if (p.status === "closed") return "closed";
  if (p.status === "admitted") return "admitted";
  if (!p.nm) return "created";
  if (p.memberOk) return "member_ok";
  if (p.adminOk) return "admin_ok";
  return "sas_shown";
}
