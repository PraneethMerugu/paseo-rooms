// Member enrollment journal (enrollment-v2.md sections 5.6, 7.3 and 8; implementation plan I-9).
//
// Stored in `member/rooms/<roomId>/state.sealed` (purpose `member-state:<roomId>`) under `enrollment`,
// sealed under the KEK, written durably BEFORE the step it enables:
//
//   keys       user pressed Join: device keys, Nm and sasCommit, before the relay socket opens;
//              then per session the session's `h` in `sentH` before `enroll.request` (at most 4)
//   pending    `enroll.pending` verified with its `h` in `sentH`: pendingId, the content bytes and
//              the SAS digits, before `sas.reveal`
//   confirmed  member pressed "Codes match", before `enroll.confirm`
//   held       device links (I-11)
//   admitted   `enroll.admitted` verified, before any call to Paseo's hosts API (C-10)
//   registered every lane host registered
//   failed     closed or refused: keys deleted, reason kept for the UI until dismissed
//
// The invite token is not kept: only its `tokenKey`, which is what the MAC needs. Nothing here logs
// keys, nonces, the token key or the SAS.
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import { b64uBytes, entityId, LaneList, nonNegInt, Role } from "../authority/schema";
import type { Kek } from "../keystore/keystore";
import { InvitePayload } from "../host/invites";
import { b64u, b64uDecode } from "../proto/b64u";
import { sasCommitOf, tokenKeyOf } from "../proto/enroll";
import { ed25519PrivateKeyFromSeed, rawPublicKey, x25519PrivateKeyFromSecret } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";

export const MEMBER_STATE_FILE = "state.sealed";
export const memberRoomDir = (dataDir: string, roomId: string) => nodePath.join(dataDir, "member", "rooms", roomId);
export const memberStatePath = (dataDir: string, roomId: string) => nodePath.join(memberRoomDir(dataDir, roomId), MEMBER_STATE_FILE);
export const memberStatePurpose = (roomId: string) => `member-state:${roomId}`;

/** A fifth session for one enrollment deletes the keys and asks for a new invite (5.6). */
export const MAX_SENT_H = 4;
const STATE_MAX_BYTES = 16 * 1024 * 1024;

export const JOURNAL_STATES = ["keys", "pending", "confirmed", "held", "admitted", "registered", "failed"] as const;
export type JournalState = (typeof JOURNAL_STATES)[number];

const Hash32 = b64uBytes(32);
const InviteNoToken = z.strictObject({ ...InvitePayload.shape, token: z.null() });

const Enrollment = z.strictObject({
  state: z.enum(JOURNAL_STATES),
  invite: InviteNoToken,
  tokenKey: Hash32.nullable(),
  /** Device keys: Ed25519 seed and X25519 secret. Null once failed (deleted). */
  keys: z.strictObject({ sigSeed: Hash32, dhSecret: Hash32 }).nullable(),
  deviceSig: Hash32,
  deviceDh: Hash32,
  label: z.string().max(400),
  nm: Hash32.nullable(),
  sasCommit: Hash32,
  sentH: z.array(Hash32).max(MAX_SENT_H),
  pendingId: entityId("pending").nullable(),
  /** RJCS text of the verified `enroll.pending` content (frame minus `t` and `re`). */
  pending: z.string().nullable(),
  sas: z.string().regex(/^[0-9]{6}$/).nullable(),
  transcript: Hash32.nullable(),
  terms: z.strictObject({ role: Role, lanes: LaneList }).nullable(),
  expiresAt: nonNegInt().nullable(),
  memberId: entityId("member").nullable(),
  deviceId: entityId("device").nullable(),
  /**
   * The admission entry from `enroll.admitted` (I-10 gate): lane grants and registration wait until
   * the post-admission fold over log.fetch holds this entry with this hash. Absent in journals
   * written before I-10.
   */
  admission: z.strictObject({ seq: nonNegInt(), hash: Hash32 }).nullable().optional(),
  /** RJCS text of the verified genesis, once known. */
  genesis: z.string().nullable(),
  registrations: z.record(z.string(), z.string()),
  failure: z.string().max(64).nullable(),
  updatedAt: nonNegInt(),
});
export type EnrollmentRecord = z.infer<typeof Enrollment>;

const MemberState = z.strictObject({
  v: z.literal(2),
  typ: z.literal("member-state"),
  roomId: z.string(),
  genesisHash: Hash32,
  enrollment: Enrollment,
});
type MemberState = z.infer<typeof MemberState>;

export class JournalError extends Error {
  constructor(
    readonly code: "too_many_sessions" | "bad_transition" | "no_keys",
    message: string,
  ) {
    super(message);
    this.name = "JournalError";
  }
}

export class EnrollmentJournal {
  private constructor(
    private readonly dataDir: string,
    private readonly kek: Kek,
    readonly roomId: string,
    private st: MemberState,
    private readonly now: () => number,
  ) {}

  /** Journal of a room, or null. */
  static read(o: { dataDir: string; kek: Kek; roomId: string; now?: () => number }): EnrollmentJournal | null {
    const plain = o.kek.readSealed(memberStatePath(o.dataDir, o.roomId), memberStatePurpose(o.roomId));
    if (!plain) return null;
    try {
      const parsed = MemberState.safeParse(rjcsParse(plain, STATE_MAX_BYTES));
      if (!parsed.success || parsed.data.roomId !== o.roomId) throw new Error("member state file is invalid");
      return new EnrollmentJournal(o.dataDir, o.kek, o.roomId, parsed.data, o.now ?? Date.now);
    } finally {
      plain.fill(0);
    }
  }

  /** Rooms with a member journal. */
  static rooms(dataDir: string): string[] {
    const dir = nodePath.join(dataDir, "member", "rooms");
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).filter((r) => fs.existsSync(memberStatePath(dataDir, r)));
  }

  /**
   * State `keys` (user pressed Join): fresh per-room device keys, Nm and sasCommit, persisted before
   * any network access. `random` is for tests (vectors).
   */
  static begin(o: { dataDir: string; kek: Kek; invite: InvitePayload; label: string; now?: () => number; random?: (n: number) => Buffer }): EnrollmentJournal {
    const rnd = o.random ?? randomBytes;
    const sigSeed = rnd(32);
    const dhSecret = rnd(32);
    const nm = rnd(32);
    const now = (o.now ?? Date.now)();
    const roomId = o.invite.roomId;
    try {
      const enrollment: EnrollmentRecord = {
        state: "keys",
        invite: { ...o.invite, token: null },
        tokenKey: b64u(tokenKeyOf(b64uDecode(o.invite.token, 32))),
        keys: { sigSeed: b64u(sigSeed), dhSecret: b64u(dhSecret) },
        deviceSig: b64u(rawPublicKey(ed25519PrivateKeyFromSeed(sigSeed))),
        deviceDh: b64u(rawPublicKey(x25519PrivateKeyFromSecret(dhSecret))),
        label: o.label,
        nm: b64u(nm),
        sasCommit: sasCommitOf(nm),
        sentH: [],
        pendingId: null,
        pending: null,
        sas: null,
        transcript: null,
        terms: null,
        expiresAt: null,
        memberId: null,
        deviceId: null,
        genesis: null,
        registrations: {},
        failure: null,
        updatedAt: now,
      };
      const j = new EnrollmentJournal(o.dataDir, o.kek, roomId, { v: 2, typ: "member-state", roomId, genesisHash: o.invite.genesisHash, enrollment }, o.now ?? Date.now);
      fs.mkdirSync(memberRoomDir(o.dataDir, roomId), { recursive: true, mode: 0o700 });
      j.persist(j.st);
      return j;
    } finally {
      sigSeed.fill(0);
      dhSecret.fill(0);
      nm.fill(0);
    }
  }

  get e(): Readonly<EnrollmentRecord> {
    return this.st.enrollment;
  }

  get state(): JournalState {
    return this.st.enrollment.state;
  }

  get genesisHash(): string {
    return this.st.genesisHash;
  }

  /** The device keys (caller zeroes them after use). Throws once deleted. */
  deviceKeys(): { sigSeed: Buffer; dhSecret: Buffer } {
    const k = this.st.enrollment.keys;
    if (!k) throw new JournalError("no_keys", "The device keys were deleted");
    return { sigSeed: b64uDecode(k.sigSeed, 32), dhSecret: b64uDecode(k.dhSecret, 32) };
  }

  nm(): Buffer {
    if (!this.st.enrollment.nm) throw new JournalError("no_keys", "Nm was deleted");
    return b64uDecode(this.st.enrollment.nm, 32);
  }

  tokenKey(): Buffer {
    if (!this.st.enrollment.tokenKey) throw new JournalError("no_keys", "The invite token key was deleted");
    return b64uDecode(this.st.enrollment.tokenKey, 32);
  }

  /** Before `enroll.request` in a session: that session's `h`. A fifth session fails the join. */
  addSentH(h: string): void {
    this.expect("keys", "pending", "confirmed");
    const e = this.st.enrollment;
    if (e.sentH.includes(h)) return;
    if (e.sentH.length >= MAX_SENT_H) throw new JournalError("too_many_sessions", "too many sessions for one join");
    this.update({ sentH: [...e.sentH, h] });
  }

  /** `enroll.pending` verified: before `sas.reveal`. */
  recordPending(p: { pendingId: string; content: string; sas: string; transcript: string; terms: { role: z.infer<typeof Role>; lanes: string[] }; expiresAt: number; genesis: string }): void {
    this.expect("keys");
    this.update({ state: "pending", pendingId: p.pendingId, pending: p.content, sas: p.sas, transcript: p.transcript, terms: p.terms, expiresAt: p.expiresAt, genesis: p.genesis });
  }

  /** "Codes match": before `enroll.confirm`. */
  confirm(): void {
    this.expect("pending", "confirmed");
    if (this.state === "pending") this.update({ state: "confirmed" });
  }

  /** `enroll.admitted` verified: before any hosts API call. The nonce and token key are no longer needed. */
  admitted(memberId: string, deviceId: string, admission: { seq: number; hash: string } | null = null): void {
    this.expect("pending", "confirmed", "held", "admitted");
    this.update({ state: "admitted", memberId, deviceId, admission, nm: null, tokenKey: null });
  }

  registration(laneId: string, registrationId: string): void {
    this.expect("admitted", "registered");
    this.update({ registrations: { ...this.st.enrollment.registrations, [laneId]: registrationId } });
  }

  registered(): void {
    this.expect("admitted", "registered");
    if (this.state === "admitted") this.update({ state: "registered" });
  }

  /** Terminal failure: keys, nonce and token key deleted; the reason stays for the UI. */
  fail(reason: string): void {
    this.update({ state: "failed", failure: reason.slice(0, 64), keys: null, nm: null, tokenKey: null });
  }

  /** Removes the journal file (after the user dismissed a failed join). */
  remove(): void {
    fs.rmSync(memberStatePath(this.dataDir, this.roomId), { force: true });
  }

  private expect(...states: JournalState[]): void {
    if (!states.includes(this.state)) throw new JournalError("bad_transition", `journal is ${this.state}`);
  }

  private update(patch: Partial<EnrollmentRecord>): void {
    this.persist({ ...this.st, enrollment: { ...this.st.enrollment, ...patch, updatedAt: this.now() } });
  }

  private persist(next: MemberState): void {
    const plain = Buffer.from(rjcs(next, STATE_MAX_BYTES));
    try {
      this.kek.writeSealed(memberStatePath(this.dataDir, this.roomId), memberStatePurpose(this.roomId), plain);
    } finally {
      plain.fill(0);
    }
    this.st = next;
  }
}
