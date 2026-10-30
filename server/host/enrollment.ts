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
// Device links (I-11; identity-model.md 6.4, enrollment-v2.md 5.4, 7.2): an active device creates a
// link (`device.link.create`, which logs its own `device.link.created`); the host keeps a LinkRecord
// with the link's tokenKey and runs the same check order and per-link limits as for an invite. The
// pending enrollment of a link has the creating device A as its confirmer: the host pushes
// `link.request` to A and answers B's `enroll.request` with `enroll.pending` only once A sent
// `link.nonce` (Nh = A's Nc; the host never chooses it). B's `sas.reveal` (with `newKeySig`) is
// forwarded as `link.reveal`; A's `link.confirm` carries A's signed `device.added`. With both
// confirmations the host logs `device.added`, the pending enters `held` and B gets `enroll.held`.
// The fold decides the rest: an approval (`device.add.approved`, by the admin daemon) admits B; a
// veto, a cancellation (requester or member removed) or 48 h past the hold close it. A is told with
// `link.closed`. Pending link enrollments of a device that is no longer active are closed.
//
// Not here: the daily expiry sweep of unused invites (expiry is computed lazily on lookup),
// per-device budgets of active devices (I-10), `invite.contested` for links (its data names only an
// inviteRef), and link revocation (`invite.revoked {linkRef}`; the link expires after 10 minutes).
import { randomBytes } from "node:crypto";
import nodePath from "node:path";
import { z } from "zod";
import { authorityChainOf } from "../authority/authority-chain";
import type { SignedEntry } from "../authority/entries";
import { autoApprovalEndsAt } from "../authority/holds";
import { b64uBytes, entityId, Hash32, nonNegInt } from "../authority/schema";
import { parseSignedStatement, verifyNewKeySig, type SignedStatement, type StatementType } from "../authority/statements";
import { keysInUse } from "../authority/state";
import { deviceAddedData, LINK_EXP_MAX_S, newDeviceKeyChange } from "../proto/device-link";
import type { Kek } from "../keystore/keystore";
import { log, logError } from "../log";
import { b64u, b64uDecode } from "../proto/b64u";
import { computeSas, enrollSigned, isValidLabel, sasCommitOf, tokenKeyOf, tokenMacMatches, verifyEnrollSig, type Sas } from "../proto/enroll";
import { bodyHash as bodyHashOf } from "../authority/entries";
import { edKid } from "../authority/state";
import { inviteRef, isId, linkRef, newId } from "../proto/ids";
import { rjcs, rjcsParse, rjcsText, RJCS_MAX_FRAME_BYTES } from "../proto/rjcs";
import type { Frame } from "../transport/records";
import { isRequestId, type RoomErrorCode } from "../transport/room-session";
import { encodeInvite, INVITE_STATES, InviteRecord, parseInviteTerms, type InvitePayload } from "./invites";
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
  /** A held device add closes this long after its hold ended without an approval (identity 6.4 step 8). */
  heldTimeoutMs: number;
}

export const ENROLLMENT_LIMITS: Readonly<EnrollmentLimits> = {
  failedProofs: 3,
  abandoned: 3,
  preauthPerMinute: 10,
  preauthBurst: 5,
  maxPending: 16,
  pendingTtlMs: 15 * 60 * 1000,
  keepClosedMs: 24 * 60 * 60 * 1000,
  heldTimeoutMs: 48 * 60 * 60 * 1000,
};

export type ClosedReason = "rejected" | "timeout" | "invite_revoked" | "room_closed" | "aborted" | "vetoed";
const CLOSED_REASONS = ["rejected", "timeout", "invite_revoked", "room_closed", "aborted", "vetoed"] as const;

/** identity-model.md 6.4: the invite state machine and limits, per link. The token never reaches the host. */
const LinkRecord = z.strictObject({
  linkId: entityId("link"),
  tokenKey: b64uBytes(32),
  memberId: entityId("member"),
  createdBy: entityId("device"),
  createdAt: nonNegInt(),
  /** unix s */
  exp: nonNegInt(),
  state: z.enum(INVITE_STATES),
  failedProofs: nonNegInt(),
  abandoned: nonNegInt(),
  pendingId: entityId("pending").nullable(),
  usedBy: z.string().nullable(),
});
type LinkRecord = z.infer<typeof LinkRecord>;

const PendingRecord = z.strictObject({
  pendingId: entityId("pending"),
  /** Exactly one of inviteId and linkId. */
  inviteId: entityId("invite").nullable(),
  linkId: entityId("link").nullable().default(null),
  /** Device links: B's assigned deviceId and its request signature (re-pushed to A). */
  deviceId: entityId("device").nullable().default(null),
  requestSig: b64uBytes(64).nullable().default(null),
  /** Pinned inputs (5.6). For a link, `nh` is A's Nc and stays null until `link.nonce`. */
  h: Hash32,
  sasCommit: Hash32,
  nh: Hash32.nullable(),
  nm: Hash32.nullable(),
  /** Device links: B's newKeySig (from `sas.reveal`) and A's signed `device.added` (RJCS text). */
  newKeySig: b64uBytes(64).nullable().default(null),
  linkStatement: z.string().nullable().default(null),
  deviceSig: b64uBytes(32),
  deviceDh: b64uBytes(32),
  label: z.string().max(400),
  createdAt: nonNegInt(),
  expiresAt: nonNegInt(),
  /** RJCS text of the `enroll.pending` content (the frame minus `t` and `re`): resent byte for byte. Null for a link until A's Nc. */
  content: z.string().nullable(),
  memberOk: z.boolean(),
  /** The admin's Admit, or for a link A's `link.confirm`. */
  adminOk: z.boolean(),
  contested: z.boolean(),
  status: z.enum(["open", "held", "admitted", "closed"]),
  /** Device links in `held`: the `enroll.held` frame (RJCS text), the request's bodyHash, and when the hold ends (hts ms; the entry's hts if an admin must approve). */
  held: z.string().nullable().default(null),
  heldRef: Hash32.nullable().default(null),
  heldUntil: nonNegInt().nullable().default(null),
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
  links: z.array(LinkRecord).max(4096).default([]),
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
const RevealFrame = z.strictObject({ t: z.literal("sas.reveal"), id: z.number(), Nm: B32, newKeySig: b64uBytes(64).optional() });
// Device link operations of the confirming device A (identity-model.md 6.4; enrollment-v2.md 4).
const LinkCreateFrame = z.strictObject({ t: z.literal("device.link.create"), id: z.number(), linkId: z.string().max(64), tokenKey: B32, exp: nonNegInt(), statement: z.unknown() });
const LinkNonceFrame = z.strictObject({ t: z.literal("link.nonce"), id: z.number(), pendingId: z.string().max(64), Nc: B32 });
const LinkConfirmFrame = z.strictObject({ t: z.literal("link.confirm"), id: z.number(), pendingId: z.string().max(64), statement: z.unknown() });
const LinkAbortFrame = z.strictObject({ t: z.literal("link.abort"), id: z.number(), linkId: z.string().max(64), pendingId: z.string().max(64), reason: z.enum(["sas_mismatch", "attempts", "cancelled"]) });

export const LINK_OPS: ReadonlySet<string> = new Set(["device.link.create", "link.nonce", "link.confirm", "link.abort"]);

/** The active device behind a session (server/host/room-endpoint.ts DeviceAccess). */
export type LinkCaller = { memberId: string; deviceId: string; sigKid: string };

type Target = { kind: "invite"; rec: InviteRecord } | { kind: "link"; rec: LinkRecord };
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
  /** Sends an event frame to a device's live session (device links: `link.request`, `link.reveal`, `link.closed`). */
  push?: (deviceId: string, frame: Record<string, unknown>) => boolean;
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
  kind: "invite" | "link";
  /** inviteRef, or the linkRef of a device link. */
  inviteRef: string;
  note: string;
  inviteCreatedAt: number;
  label: string;
  state: "created" | "sas_shown" | "member_ok" | "admin_ok" | "held" | "admitted" | "closed";
  /** "317 837" once the member revealed Nm; null before. */
  sas: string | null;
  abandonedBefore: number;
  contested: boolean;
  expiresAt: number;
  closedReason: ClosedReason | null;
  memberId: string | null;
  /** Device links: the assigned deviceId. */
  deviceId: string | null;
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
  /** Device links: B's `enroll.request` waiting for A's Nc, answered with `enroll.pending` (6.4 step 4). */
  private readonly waiting = new Map<string, { s: EnrollSession; re: number }>();
  private reacting = false;

  constructor(private readonly o: EnrollmentHostOptions) {
    this.limits = { ...ENROLLMENT_LIMITS, ...o.limits };
    this.now = o.now ?? Date.now;
    this.bucket = new TokenBucket(this.limits.preauthPerMinute, this.limits.preauthBurst, this.now);
    this.st = this.load();
    this.repairAdmitted();
    this.repairHeld();
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
    this.waiting.clear();
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
      const t = this.targetOf(p);
      const inv = t?.kind === "invite" ? t.rec : undefined;
      return {
        pendingId: p.pendingId,
        kind: p.linkId ? ("link" as const) : ("invite" as const),
        inviteRef: p.linkId ? linkRef(p.linkId) : inviteRef(p.inviteId!),
        note: inv?.note ?? "",
        inviteCreatedAt: t?.rec.createdAt ?? 0,
        label: p.label,
        state: stateOf(p),
        // A device link's code is shown by the confirming device, never by the owner.
        sas: p.nm && p.nh && !p.linkId && p.status !== "closed" ? this.sasOf(p).display : null,
        abandonedBefore: t?.rec.abandoned ?? 0,
        contested: p.contested,
        expiresAt: p.expiresAt,
        closedReason: p.closedReason,
        memberId: p.admitted ? ((rjcsParse(Buffer.from(p.admitted), RJCS_MAX_FRAME_BYTES) as { memberId: string }).memberId ?? null) : p.linkId ? (this.link(p.linkId)?.memberId ?? null) : null,
        deviceId: p.deviceId,
      };
    });
  }

  /** The admin pressed Admit (enabled only once the member revealed Nm). */
  admit(pendingId: string): PendingView["state"] {
    const p = this.openPending(pendingId);
    if (p.linkId) throw new EnrollmentError("refused", "A device link is confirmed by the member's own device; an admin approves the held add instead");
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

  /** Device link operations of an active device (A), section 4 of enrollment-v2.md. */
  handleLink(s: EnrollSession, frame: Frame, caller: LinkCaller): void {
    try {
      switch (frame.t) {
        case "device.link.create":
          return this.onLinkCreate(s, frame, caller);
        case "link.nonce":
          return this.onLinkNonce(s, frame, caller);
        case "link.confirm":
          return this.onLinkConfirm(s, frame, caller);
        case "link.abort":
          return this.onLinkAbort(s, frame, caller);
        default:
          return s.fail("bad_frame", frame.id);
      }
    } catch (err) {
      logError("link_op_failed", err, { roomId: this.roomId, conn: s.tag, op: frame.t.slice(0, 32) });
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
    const named = "inviteId" in r ? { inviteId: r.inviteId } : { linkId: r.linkId };
    if (r.deviceDh !== s.rs || r.deviceSig === r.deviceDh || !isValidLabel(r.label)) return this.generic(s, r.id, "request_fields");
    const signed = enrollSigned({ h: s.h, genesisHash: this.o.host.genesisHash, target: named, deviceSig: r.deviceSig, deviceDh: r.deviceDh, label: r.label, sasCommit: r.sasCommit });
    if (!verifyEnrollSig(signed, r.sig)) return this.generic(s, r.id, "bad_signature");
    // 5. lookup of the invite or the device link
    let found: Target | undefined;
    if ("inviteId" in r) {
      const inv = isId("invite", r.inviteId) ? this.invite(r.inviteId) : undefined;
      found = inv && { kind: "invite", rec: inv };
    } else {
      const link = isId("link", r.linkId) ? this.link(r.linkId) : undefined;
      found = link && { kind: "link", rec: link };
    }
    if (!found) return this.generic(s, r.id, "unknown_target");
    // 6. token proof, constant time
    if (!tokenMacMatches(b64uDecode(found.rec.tokenKey, 32), signed, r.tokenMac)) {
      this.failedProof(found);
      return this.generic(s, r.id, "bad_token");
    }
    // 7. the requester knows the token: the invite's (or link's) state may be disclosed
    const target = this.expireIfDue(found);
    const cur = target.rec;
    if (cur.state === "expired") return s.fail("invite_expired", r.id);
    if (cur.state === "used") return s.fail("invite_used", r.id);
    if (cur.state === "revoked" || cur.state === "burned") return s.fail("invite_revoked", r.id);
    if (cur.state === "claimed") {
      const holder = cur.pendingId ? this.pending(cur.pendingId) : undefined;
      if (holder && holder.deviceDh !== s.rs) {
        if (target.kind === "invite") this.contest(holder);
        return s.fail("invite_in_use", r.id);
      }
    }
    // 8. keys already in the roster, retired or denylisted -> generic; the same keys in a pending -> resume
    const st = this.o.host.state;
    const inUse = keysInUse(st);
    if ([r.deviceSig, r.deviceDh].some((k) => inUse.has(k) || st.auth.retiredKeys[k] || st.deviceDenylist[k])) return this.generic(s, r.id, "keys_in_use");
    const same = this.st.pendings.find((p) => p.status === "open" && (p.deviceDh === r.deviceDh || p.deviceSig === r.deviceSig || p.deviceDh === r.deviceSig || p.deviceSig === r.deviceDh));
    if (same) {
      if (same.deviceDh !== s.rs || same.deviceSig !== r.deviceSig || targetKey(same) !== targetKeyOf(target)) return this.generic(s, r.id, "keys_in_other_pending");
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
    if (target.kind === "link" && !this.creatorActive(target.rec)) return s.fail("invite_revoked", r.id);
    this.create(s, r.id, target, { h: s.h, sasCommit: r.sasCommit, deviceSig: r.deviceSig, deviceDh: r.deviceDh, label: r.label, sig: r.sig });
  }

  /** The `enroll.pending` content (5.2). Only the genesis and the authority-key chain (authority-chain.ts). */
  private pendingContent(i: { pendingId: string; h: string; nh: string; deviceId: string | null; terms: { role: string; lanes: string[] }; expiresAt: number }): string {
    const host = this.o.host;
    return rjcsText({
      pendingId: i.pendingId,
      h: i.h,
      Nh: i.nh,
      ...(i.deviceId ? { deviceId: i.deviceId } : {}),
      genesis: host.genesis,
      authority: authorityChainOf(host.entries(0), b64u),
      terms: i.terms,
      expiresAt: i.expiresAt,
    });
  }

  private create(s: EnrollSession, re: number, target: Target, req: { h: string; sasCommit: string; deviceSig: string; deviceDh: string; label: string; sig: string }): void {
    const pendingId = newId("pending");
    const now = this.now();
    const expiresAt = Math.min(target.rec.exp * 1000, now + this.limits.pendingTtlMs);
    const link = target.kind === "link" ? target.rec : null;
    // An invite's host nonce is chosen here. A link's Nh is A's Nc, which arrives with `link.nonce`.
    const nh = link ? null : b64u(randomBytes(32));
    const deviceId = link ? newId("device") : null;
    const record: PendingRecord = {
      pendingId,
      inviteId: target.kind === "invite" ? target.rec.inviteId : null,
      linkId: link?.linkId ?? null,
      deviceId,
      requestSig: link ? req.sig : null,
      h: req.h,
      sasCommit: req.sasCommit,
      nh,
      nm: null,
      newKeySig: null,
      linkStatement: null,
      deviceSig: req.deviceSig,
      deviceDh: req.deviceDh,
      label: req.label,
      createdAt: now,
      expiresAt,
      content: target.kind === "invite" ? this.pendingContent({ pendingId, h: req.h, nh: nh!, deviceId: null, terms: { role: target.rec.role, lanes: target.rec.lanes }, expiresAt }) : null,
      memberOk: false,
      adminOk: false,
      contested: false,
      status: "open",
      held: null,
      heldRef: null,
      heldUntil: null,
      closedReason: null,
      admitted: null,
      endedAt: null,
    };
    // Persist (claimed + pending) before the log entry and before the reply.
    this.persist(this.withTarget({ ...this.st, pendings: [...this.st.pendings, record] }, target, { state: "claimed", pendingId }));
    this.emit("enrollment.pending", { ...refData(target), pendingId, deviceKid: edKid(req.deviceSig) });
    this.sessions.set(pendingId, s);
    log("enroll_pending", { roomId: this.roomId, pendingId, conn: s.tag, link: !!link });
    if (link) {
      // B waits for A's nonce; A gets the request now or when its session opens.
      this.waiting.set(pendingId, { s, re });
      this.pushLinkRequest(this.pending(pendingId)!);
      return;
    }
    s.send({ t: "enroll.pending", re, ...(rjcsParse(Buffer.from(record.content!), RJCS_MAX_FRAME_BYTES) as Record<string, never>) });
  }

  private onReveal(s: EnrollSession, frame: Frame): void {
    const f = RevealFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const p = this.st.pendings.find((x) => x.deviceDh === s.rs && x.status === "open") ?? this.lastOf(s.rs);
    if (!p) return this.generic(s, f.data.id, "reveal_without_pending");
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    if (p.status === "admitted" || p.status === "held") return s.send({ t: "sas.reveal.ok", re: f.data.id });
    // newKeySig travels with a device link's reveal only (5.2); B cannot reveal before it saw Nh.
    if (!!p.linkId !== (f.data.newKeySig !== undefined) || !p.nh) return this.generic(s, f.data.id, "reveal_fields");
    if (p.nm !== null) {
      if (p.nm === f.data.Nm && p.newKeySig === (f.data.newKeySig ?? null)) return s.send({ t: "sas.reveal.ok", re: f.data.id });
      return this.generic(s, f.data.id, "reveal_changed");
    }
    const keyOk = !p.linkId || verifyNewKeySig(newDeviceKeyChange(this.roomId, p.deviceId!, p.deviceSig, p.deviceDh), f.data.newKeySig!);
    if (sasCommitOf(b64uDecode(f.data.Nm, 32)) !== p.sasCommit || !keyOk) {
      // The requester gets the generic reply below, not the closed push.
      this.sessions.delete(p.pendingId);
      this.closePending(p.pendingId, "aborted", "abandoned");
      return this.generic(s, f.data.id, keyOk ? "commit_mismatch" : "bad_new_key_sig");
    }
    this.updatePending(p.pendingId, { nm: f.data.Nm, newKeySig: f.data.newKeySig ?? null });
    this.sessions.set(p.pendingId, s);
    log("enroll_sas_revealed", { roomId: this.roomId, pendingId: p.pendingId });
    s.send({ t: "sas.reveal.ok", re: f.data.id });
    if (p.linkId) this.pushLinkReveal(this.pending(p.pendingId)!);
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
    if (now.status === "held") return this.deliverHeld(now);
    if (now.status !== "open" || !now.adminOk) return;
    try {
      if (now.linkId) this.finishLink(now.pendingId);
      else this.admitNow(p.pendingId);
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
    if (p.content === null) {
      // A device link whose confirming device has not sent its nonce yet: answer when it does.
      this.waiting.set(p.pendingId, { s, re });
      this.pushLinkRequest(p);
      return;
    }
    const pending = rjcsParse(Buffer.from(p.content), RJCS_MAX_FRAME_BYTES);
    const admitted = p.admitted ? rjcsParse(Buffer.from(p.admitted), RJCS_MAX_FRAME_BYTES) : undefined;
    const held = p.held ? rjcsParse(Buffer.from(p.held), RJCS_MAX_FRAME_BYTES) : undefined;
    // An admitted pending reports the last pre-admission state together with `admitted`.
    const state = p.status === "admitted" ? "member_ok" : stateOf(p);
    log("enroll_resumed", { roomId: this.roomId, pendingId: p.pendingId, state, conn: s.tag });
    s.send({ t: "enroll.resume.ok", re, pending, state, ...(held ? { held } : {}), ...(admitted ? { admitted } : {}) } as Frame);
    if (p.status === "admitted") s.promote();
  }

  // ------------------------------------------------------------------------------ device links

  /** `device.link.create` (identity-model.md 6.4 step 2): logs A's `device.link.created`, stores the LinkRecord. */
  private onLinkCreate(s: EnrollSession, frame: Frame, caller: LinkCaller): void {
    const f = LinkCreateFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id) || !isId("link", f.data.linkId)) return s.fail("bad_frame", frame.id);
    const r = f.data;
    let stmt: SignedStatement;
    try {
      stmt = parseSignedStatement(r.statement);
    } catch {
      return s.fail("bad_frame", r.id);
    }
    const d = stmt.body.data as { memberId?: string; linkRef?: string; exp?: number };
    const nowS = Math.floor(this.now() / 1000);
    const ok =
      stmt.body.type === "device.link.created" &&
      stmt.body.producer.kind === "device" &&
      stmt.body.producer.kid === caller.sigKid &&
      d.memberId === caller.memberId &&
      d.linkRef === linkRef(r.linkId) &&
      d.exp === r.exp &&
      r.exp > nowS &&
      r.exp <= nowS + LINK_EXP_MAX_S + 60 &&
      !this.link(r.linkId);
    if (!ok) return s.fail("not_permitted", r.id);
    // Log first, as for invites: a crash after the entry leaves a link no record can redeem.
    const res = this.o.host.submit(stmt);
    if (!res.ok) {
      const head = res.head ? { seq: res.head.entry.seq, hash: res.head.hash } : { seq: -1, hash: this.o.host.genesisHash };
      return s.fail(res.code, r.id, res.code === "not_permitted" ? {} : { head });
    }
    const record: LinkRecord = { linkId: r.linkId, tokenKey: r.tokenKey, memberId: caller.memberId, createdBy: caller.deviceId, createdAt: this.now(), exp: r.exp, state: "open", failedProofs: 0, abandoned: 0, pendingId: null, usedBy: null };
    this.persist({ ...this.st, links: [...this.st.links, record] });
    log("link_created", { roomId: this.roomId, linkRef: d.linkRef, deviceId: caller.deviceId, exp: r.exp });
    s.send({ t: "device.link.create.ok", re: r.id, receipt: res.receipt } as unknown as Frame);
    this.o.afterAppend();
  }

  /** The open link pending `pendingId` of a link created by this caller, or a reason it is not. */
  private callerLinkPending(pendingId: string, caller: LinkCaller): { p: PendingRecord; link: LinkRecord } | null {
    const p = isId("pending", pendingId) ? this.pending(pendingId) : undefined;
    const link = p?.linkId ? this.link(p.linkId) : undefined;
    if (!p || !link || link.createdBy !== caller.deviceId || link.memberId !== caller.memberId) return null;
    return { p, link };
  }

  /** `link.nonce` (6.4 step 3): A's Nc becomes Nh; B gets `enroll.pending`. The host never picks it. */
  private onLinkNonce(s: EnrollSession, frame: Frame, caller: LinkCaller): void {
    const f = LinkNonceFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const found = this.callerLinkPending(f.data.pendingId, caller);
    if (!found) return s.fail("not_permitted", f.data.id);
    const { p, link } = found;
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    if (p.nh !== null) {
      // A re-sends its pinned Nc after a lost reply; a different one is refused.
      if (p.nh !== f.data.Nc) return s.fail("not_permitted", f.data.id);
      return s.send({ t: "link.nonce.ok", re: f.data.id });
    }
    const member = this.o.host.state.members[link.memberId];
    if (!member) return s.fail("not_permitted", f.data.id);
    const content = this.pendingContent({ pendingId: p.pendingId, h: p.h, nh: f.data.Nc, deviceId: p.deviceId, terms: { role: member.role, lanes: [...member.lanes] }, expiresAt: p.expiresAt });
    this.updatePending(p.pendingId, { nh: f.data.Nc, content });
    log("link_nonce", { roomId: this.roomId, pendingId: p.pendingId });
    s.send({ t: "link.nonce.ok", re: f.data.id });
    const w = this.waiting.get(p.pendingId);
    this.waiting.delete(p.pendingId);
    if (w && w.s.isOpen()) w.s.send({ t: "enroll.pending", re: w.re, ...(rjcsParse(Buffer.from(content), RJCS_MAX_FRAME_BYTES) as Record<string, never>) });
  }

  /** `link.confirm` (6.4 step 6): A's "Codes match" with A's signed `device.added`. */
  private onLinkConfirm(s: EnrollSession, frame: Frame, caller: LinkCaller): void {
    const f = LinkConfirmFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const found = this.callerLinkPending(f.data.pendingId, caller);
    if (!found) return s.fail("not_permitted", f.data.id);
    const { p, link } = found;
    if (p.status === "closed") return s.fail("enroll_closed", f.data.id, { reason: p.closedReason ?? "aborted" });
    if (p.status !== "open") return s.send({ t: "link.confirm.ok", re: f.data.id });
    if (!p.nm || !p.newKeySig || !p.nh) return s.fail("not_permitted", f.data.id);
    let stmt: SignedStatement;
    try {
      stmt = parseSignedStatement(f.data.statement);
    } catch {
      return s.fail("bad_frame", f.data.id);
    }
    const expected = deviceAddedData({
      roomId: this.roomId,
      memberId: link.memberId,
      deviceId: p.deviceId!,
      deviceSig: p.deviceSig,
      deviceDh: p.deviceDh,
      newKeySig: p.newKeySig,
      addedBy: caller.deviceId,
      linkId: link.linkId,
      transcript: this.sasOf(p).transcript,
    });
    const ok = stmt.body.type === "device.added" && stmt.body.producer.kind === "device" && stmt.body.producer.kid === caller.sigKid && rjcsText(stmt.body.data) === rjcsText(expected);
    if (!ok) return s.fail("not_permitted", f.data.id);
    this.updatePending(p.pendingId, { adminOk: true, linkStatement: rjcsText(stmt) });
    log("link_confirmed", { roomId: this.roomId, pendingId: p.pendingId });
    s.send({ t: "link.confirm.ok", re: f.data.id });
    if (this.pending(p.pendingId)!.memberOk) this.finishLink(p.pendingId);
  }

  /** `link.abort` (6.4 step 6 and A's own limits): the link is burned for `sas_mismatch` and `attempts`. */
  private onLinkAbort(s: EnrollSession, frame: Frame, caller: LinkCaller): void {
    const f = LinkAbortFrame.safeParse(frame);
    if (!f.success || !isRequestId(frame.id)) return s.fail("bad_frame", frame.id);
    const link = isId("link", f.data.linkId) ? this.link(f.data.linkId) : undefined;
    if (!link || link.createdBy !== caller.deviceId || link.memberId !== caller.memberId) return s.fail("not_permitted", f.data.id);
    const p = isId("pending", f.data.pendingId) ? this.pending(f.data.pendingId) : undefined;
    if (p && p.linkId === link.linkId && p.status === "open") {
      this.closePending(p.pendingId, "aborted", f.data.reason === "sas_mismatch" ? "sas_mismatch" : f.data.reason === "attempts" ? "none" : "abandoned");
    }
    const cur = this.link(link.linkId)!;
    if (f.data.reason === "attempts" && (cur.state === "open" || cur.state === "claimed")) {
      this.persist(this.withTarget(this.st, { kind: "link", rec: cur }, { state: "burned", pendingId: null }));
      this.emit("invite.burned", { linkRef: linkRef(cur.linkId), reason: "attempts" });
      log("link_burned", { roomId: this.roomId, linkRef: linkRef(cur.linkId), reason: "attempts", by: "confirming_device" });
    }
    s.send({ t: "link.abort.ok", re: f.data.id });
  }

  /**
   * Both confirmations of a device link: log A's `device.added` (fsync), then the pending is `held`
   * (7.2) and B gets `enroll.held` with the time the hold ends, or null when an admin must approve.
   */
  private finishLink(pendingId: string): void {
    const p = this.pending(pendingId)!;
    const link = this.link(p.linkId!)!;
    const res = this.o.host.submit(rjcsParse(Buffer.from(p.linkStatement!), RJCS_MAX_FRAME_BYTES));
    if (!res.ok) {
      log("link_add_refused", { roomId: this.roomId, pendingId, code: res.code, reason: res.reason });
      this.closePending(pendingId, "rejected", "abandoned");
      return;
    }
    this.o.afterAppend();
    this.recordHeld(p, link, res.receipt);
  }

  private recordHeld(p: PendingRecord, link: LinkRecord, entry: SignedEntry): void {
    const st = this.o.host.state;
    const req = st.pending[entry.entry.bodyHash];
    const effectiveAfter = req ? autoApprovalEndsAt(st, req) : null;
    const frame = { t: "enroll.held", pendingId: p.pendingId, entry, effectiveAfter };
    this.persist({
      ...this.withTarget(this.st, { kind: "link", rec: link }, { state: "used", pendingId: null, usedBy: p.deviceId }),
      pendings: this.st.pendings.map((x) =>
        x.pendingId === p.pendingId ? { ...x, memberOk: true, adminOk: true, status: "held" as const, held: rjcsText(frame), heldRef: entry.entry.bodyHash, heldUntil: effectiveAfter ?? entry.entry.hts } : x,
      ),
    });
    log("link_held", { roomId: this.roomId, pendingId: p.pendingId, seq: entry.entry.seq, effectiveAfter, sole: req?.sole ?? null });
    this.deliverHeld(this.pending(p.pendingId)!);
  }

  private deliverHeld(p: PendingRecord): void {
    const s = this.sessions.get(p.pendingId);
    if (s && s.isOpen() && p.held) s.send(rjcsParse(Buffer.from(p.held), RJCS_MAX_FRAME_BYTES) as Frame);
  }

  /** Called after every log append: held adds follow the fold; pendings of ended creators close. */
  onAppended(): void {
    if (this.reacting) return;
    this.reacting = true;
    try {
      const st = this.o.host.state;
      for (const p of [...this.st.pendings]) {
        if (p.status === "held") {
          const req = p.heldRef ? st.pending[p.heldRef] : undefined;
          if (!req || req.status === "cancelled") this.closePending(p.pendingId, "rejected", "none");
          else if (req.status === "vetoed") this.closePending(p.pendingId, "vetoed", "none");
          else if (req.status === "approved") this.admitLinked(p);
        } else if (p.status === "open" && p.linkId) {
          const link = this.link(p.linkId);
          if (!link || !this.creatorActive(link)) this.closePending(p.pendingId, "rejected", "none");
        }
      }
      // A link whose creating device left the roster can no longer be redeemed.
      const dead = this.st.links.filter((l) => (l.state === "open" || l.state === "claimed") && !this.creatorActive(l));
      if (dead.length) this.persist({ ...this.st, links: this.st.links.map((l) => (dead.includes(l) ? { ...l, state: "revoked" as const, pendingId: null } : l)) });
    } finally {
      this.reacting = false;
    }
  }

  /** A link's creator may still confirm: an active device of the link's member. */
  private creatorActive(link: LinkRecord): boolean {
    return !!this.o.host.state.members[link.memberId]?.devices.some((d) => d.deviceId === link.createdBy);
  }

  /** `device.add.approved` for a held link pending: B is admitted (`enroll.admitted` with that statement). */
  private admitLinked(p: PendingRecord): void {
    const host = this.o.host;
    for (const r of host.entries(0)) {
      if (r.signed.entry.type !== "device.add.approved") continue;
      const stmt = rjcsParse(r.body) as SignedStatement;
      const d = stmt.body.data as { memberId: string; deviceId: string; ref: string };
      if (d.ref !== p.heldRef) continue;
      const head = host.headEntry!;
      const frame = { t: "enroll.admitted", pendingId: p.pendingId, memberId: d.memberId, deviceId: d.deviceId, statement: stmt, entry: r.signed, roster: host.roster(), head: { seq: head.entry.seq, hash: head.hash, hsig: head.hsig } };
      this.persist({ ...this.st, pendings: this.st.pendings.map((x) => (x.pendingId === p.pendingId ? { ...x, status: "admitted" as const, admitted: rjcsText(frame), endedAt: this.now() } : x)) });
      log("link_admitted", { roomId: this.roomId, pendingId: p.pendingId, memberId: d.memberId, deviceId: d.deviceId, seq: r.signed.entry.seq });
      this.deliverAdmitted(this.pending(p.pendingId)!);
      return;
    }
  }

  /** A's session opened: (re)send what it has not answered (6.4 steps 2 and 5). */
  onDeviceOnline(deviceId: string): void {
    for (const p of this.st.pendings) {
      if (p.status !== "open" || !p.linkId || this.link(p.linkId)?.createdBy !== deviceId) continue;
      if (p.nh === null) this.pushLinkRequest(p);
      else if (p.nm !== null && p.linkStatement === null) this.pushLinkReveal(p);
    }
  }

  private pushLinkRequest(p: PendingRecord): void {
    const link = this.link(p.linkId!);
    if (!link || !this.o.push) return;
    const request = enrollSigned({ h: p.h, genesisHash: this.o.host.genesisHash, target: { linkId: link.linkId }, deviceSig: p.deviceSig, deviceDh: p.deviceDh, label: p.label, sasCommit: p.sasCommit });
    this.o.push(link.createdBy, { t: "link.request", pendingId: p.pendingId, linkId: link.linkId, deviceId: p.deviceId, request, sig: p.requestSig });
  }

  private pushLinkReveal(p: PendingRecord): void {
    const link = this.link(p.linkId!);
    if (!link || !this.o.push) return;
    this.o.push(link.createdBy, { t: "link.reveal", pendingId: p.pendingId, Nm: p.nm, newKeySig: p.newKeySig });
  }

  // ------------------------------------------------------------------------------ transitions

  /** Both confirmations are in: sign member.admitted, append (fsync), persist, deliver (7.2). */
  private admitNow(pendingId: string): void {
    const p = this.pending(pendingId)!;
    const inv = this.invite(p.inviteId!)!;
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
    if (!p || (p.status !== "open" && p.status !== "held")) return;
    const target = this.targetOf(p);
    const rec = target?.rec;
    let burn: "abandoned" | "sas_mismatch" | null = null;
    let expired = false;
    let patch: Partial<InviteRecord & LinkRecord> = {};
    if (target && rec && rec.state === "claimed" && rec.pendingId === pendingId && count !== "none") {
      if (count === "sas_mismatch") burn = "sas_mismatch";
      else {
        const abandoned = rec.abandoned + 1;
        patch.abandoned = abandoned;
        if (abandoned >= this.limits.abandoned) burn = "abandoned";
        else if (rec.exp * 1000 <= this.now()) expired = true;
      }
      patch = { ...patch, state: burn ? "burned" : expired ? "expired" : "open", pendingId: null };
    } else if (target && rec && rec.state === "claimed" && rec.pendingId === pendingId) {
      // Closed without counting (revoked, room closed, the link's device gone): free the claim.
      patch = { state: rec.exp * 1000 <= this.now() ? "expired" : "open", pendingId: null };
    }
    const next = target ? this.withTarget(this.st, target, patch) : this.st;
    this.persist({ ...next, pendings: next.pendings.map((x) => (x.pendingId === pendingId ? { ...x, status: "closed" as const, closedReason: reason, endedAt: this.now() } : x)) });
    this.waiting.delete(pendingId);
    this.emit("enrollment.closed", { pendingId, reason });
    if (target && burn) this.emit("invite.burned", { ...refData(target), reason: burn });
    if (target && expired) this.emit("invite.expired", refData(target));
    log("enroll_closed", { roomId: this.roomId, pendingId, reason, [target?.kind ?? "invite"]: burn ? `burned:${burn}` : (patch.state ?? rec?.state ?? null) });
    if (target?.kind === "link" && this.o.push) {
      this.o.push(target.rec.createdBy, { t: "link.closed", linkId: target.rec.linkId, pendingId, reason: count === "abandoned" ? "abandoned" : reason });
    }
    const s = this.sessions.get(pendingId);
    this.sessions.delete(pendingId);
    if (s && s.isOpen()) {
      s.send({ t: "enroll.closed", pendingId, reason });
      if (!s.isActive()) s.fail("enroll_closed", undefined, { reason });
    }
  }

  private failedProof(target: Target): void {
    const rec = target.rec;
    if (rec.state !== "open" && rec.state !== "claimed") return;
    const failedProofs = rec.failedProofs + 1;
    const burn = failedProofs >= this.limits.failedProofs;
    const pendingId = rec.state === "claimed" ? rec.pendingId : null;
    this.persist(this.withTarget(this.st, target, burn ? { failedProofs, state: "burned", pendingId: null } : { failedProofs }));
    if (!burn) return;
    this.emit("invite.burned", { ...refData(target), reason: "attempts" });
    log("invite_burned", { roomId: this.roomId, ...refData(target), reason: "attempts" });
    if (pendingId) this.closePending(pendingId, "invite_revoked", "none");
  }

  private contest(holder: PendingRecord): void {
    if (!holder.contested) this.updatePending(holder.pendingId, { contested: true });
    this.emit("invite.contested", { inviteRef: inviteRef(holder.inviteId!), pendingId: holder.pendingId });
    log("invite_contested", { roomId: this.roomId, pendingId: holder.pendingId });
  }

  /** Lazy expiry of an open invite or link (7.1): logged once, the first time it is looked at. */
  private expireIfDue(target: Target): Target {
    const rec = target.rec;
    if (rec.state !== "open" || rec.exp * 1000 > this.now()) return target;
    this.persist(this.withTarget(this.st, target, { state: "expired" }));
    this.emit("invite.expired", refData(target));
    return this.reload(target);
  }

  /** Pending expiry, room closure and pruning of old closed records. */
  sweep(): void {
    const now = this.now();
    const closed = this.o.host.state.auth.closed;
    for (const p of this.st.pendings) {
      if (p.status === "held") {
        // 48 h after the hold ended (or after device.added, when an admin must approve) without approval.
        if (closed) this.closePending(p.pendingId, "room_closed", "none");
        else if (p.heldUntil !== null && p.heldUntil + this.limits.heldTimeoutMs <= now) this.closePending(p.pendingId, "timeout", "none");
        continue;
      }
      if (p.status !== "open") continue;
      if (closed) this.closePending(p.pendingId, "room_closed", "none");
      else if (p.expiresAt <= now) this.closePending(p.pendingId, "timeout", "abandoned");
    }
    const keep = this.st.pendings.filter((p) => p.status === "open" || p.status === "held" || (p.endedAt ?? now) + this.limits.keepClosedMs > now);
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
      if (p.status !== "open" || !p.memberOk || !p.adminOk || p.linkId) continue;
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

  /** A crash after the `device.added` append and before the host state write: the pending is held. */
  private repairHeld(): void {
    for (const p of this.st.pendings) {
      if (p.status !== "open" || !p.linkId || !p.linkStatement || !p.memberOk || !p.adminOk) continue;
      const body = rjcs(rjcsParse(Buffer.from(p.linkStatement), RJCS_MAX_FRAME_BYTES));
      const seq = this.o.host.findBody(bodyHashOf(body));
      const link = this.link(p.linkId);
      if (seq === undefined || !link) continue;
      log("link_held_repaired", { roomId: this.roomId, pendingId: p.pendingId, seq });
      this.recordHeld(p, link, this.o.host.entries(seq, seq)[0].signed);
    }
  }

  // ------------------------------------------------------------------------------ helpers

  private sasOf(p: PendingRecord): Sas {
    return computeSas({
      h: b64uDecode(p.h, 32),
      nm: b64uDecode(p.nm!, 32),
      nh: b64uDecode(p.nh!, 32),
      deviceDh: p.deviceDh,
      deviceSig: p.deviceSig,
      endpointDh: this.o.endpointDh(),
      genesisHash: this.o.host.genesisHash,
      target: p.linkId ? { linkId: p.linkId } : { inviteId: p.inviteId! },
    });
  }

  private link(linkId: string): LinkRecord | undefined {
    return this.st.links.find((l) => l.linkId === linkId);
  }

  /** Link records of the room (owner view and tests). Never the tokenKey. */
  links(): Omit<LinkRecord, "tokenKey">[] {
    return this.st.links.map(({ tokenKey: _t, ...rest }) => rest);
  }

  private targetOf(p: PendingRecord): Target | undefined {
    if (p.linkId) {
      const rec = this.link(p.linkId);
      return rec && { kind: "link", rec };
    }
    const rec = p.inviteId ? this.invite(p.inviteId) : undefined;
    return rec && { kind: "invite", rec };
  }

  private reload(t: Target): Target {
    return t.kind === "invite" ? { kind: "invite", rec: this.invite(t.rec.inviteId)! } : { kind: "link", rec: this.link(t.rec.linkId)! };
  }

  /** `st` with the invite or link record patched. */
  private withTarget(st: HostState, t: Target, patch: Partial<InviteRecord & LinkRecord>): HostState {
    const { state, failedProofs, abandoned, pendingId, usedBy } = patch;
    const p = Object.fromEntries(Object.entries({ state, failedProofs, abandoned, pendingId, usedBy }).filter(([, v]) => v !== undefined));
    if (t.kind === "invite") return { ...st, invites: st.invites.map((i) => (i.inviteId === t.rec.inviteId ? { ...i, ...p } : i)) };
    return { ...st, links: st.links.map((l) => (l.linkId === t.rec.linkId ? { ...l, ...p } : l)) };
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
    if (!plain) return { v: 2, typ: "host-state", roomId: this.roomId, invites: [], links: [], pendings: [] };
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

/** `{inviteRef}` or `{linkRef}`: the only forms of the ids in the log (room-log-v2 4.2, S-5). */
function refData(t: Target): { inviteRef: string } | { linkRef: string } {
  return t.kind === "invite" ? { inviteRef: inviteRef(t.rec.inviteId) } : { linkRef: linkRef(t.rec.linkId) };
}

function targetKey(p: PendingRecord): string {
  return p.linkId ?? p.inviteId ?? "";
}

function targetKeyOf(t: Target): string {
  return t.kind === "invite" ? t.rec.inviteId : t.rec.linkId;
}

function stateOf(p: PendingRecord): PendingView["state"] {
  if (p.status === "closed") return "closed";
  if (p.status === "admitted") return "admitted";
  if (p.status === "held") return "held";
  if (!p.nm) return "created";
  if (p.memberOk) return "member_ok";
  if (p.adminOk) return "admin_ok";
  return "sas_shown";
}
