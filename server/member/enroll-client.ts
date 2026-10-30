// Member side of enrollment (enrollment-v2.md sections 5.1, 5.2, 5.5, 5.6, 6, 7.3; implementation
// plan I-9). Drives one room's journal (enrollment-journal.ts) over IK sessions to the room endpoint
// named by the invite.
//
// - State `keys`: per session, `h` is journaled in `sentH` before `enroll.request` (same keys, Nm and
//   sasCommit on every retry, signed over that session's `h`).
// - `enroll.pending` (or `enroll.resume.ok` after a lost reply) is accepted only if its `h` is in
//   `sentH` (R-4), its genesis hashes to the invite's genesisHash and is signed by a listed admin, its
//   endpoint equals the invite's, and the authority-key chain verifies and yields that endpoint (5.5;
//   server/authority/authority-chain.ts: no roster or history is sent before admission). The SAS is
//   computed once from the pinned `h`, Nm and Nh, journaled with the content bytes, and only then is
//   `sas.reveal` sent.
// - States `pending` and `confirmed` resume with `enroll.resume`; the returned pending must be byte
//   identical to the journaled one, else the member aborts (`cancelled`) and deletes its keys (S-3).
//   The member never sends Nm into another pending, and the SAS it shows is always the stored one.
// - "Codes match" journals `confirmed` before `enroll.confirm`; "Codes do not match" sends
//   `enroll.abort sas_mismatch` and fails the join.
// - `enroll.admitted` is checked against the journal (pendingId, own keys, inviteRef, the SAS
//   transcript) and journaled before anything else; the caller then registers lanes and opens a
//   normal session, whose log sync folds and verifies the admission entry.
// Transport failures retry with backoff; terminal errors fail the journal (keys deleted).
import { z } from "zod";
import { bodyHash, SignedEntry as SignedEntrySchema } from "../authority/entries";
import { verifyAuthorityChain } from "../authority/authority-chain";
import { verifyGenesis } from "../authority/genesis";
import { b64uBytes, entityId, LaneList, nonNegInt, Role } from "../authority/schema";
import type { SignedStatement } from "../authority/statements";
import { log } from "../log";
import { b64u, b64uDecode, b64uDecodeVar } from "../proto/b64u";
import { computeSas, enrollSigned, enrollTokenMac, signEnroll } from "../proto/enroll";
import { inviteRef } from "../proto/ids";
import { ed25519PrivateKeyFromSeed, rawPublicKey, x25519PrivateKeyFromSecret } from "../proto/keys";
import { rjcs, rjcsText, RJCS_MAX_BYTES, RJCS_MAX_FRAME_BYTES } from "../proto/rjcs";
import type { Frame } from "../transport/records";
import type { RelayAddress } from "../transport/relay-server";
import type { RoomSessionTimings } from "../transport/room-session";
import { JournalError, type EnrollmentJournal, type JournalState } from "./enrollment-journal";
import { RoomClient, RoomSessionError } from "./room-client";

export const ENROLL_RETRY_MS: readonly number[] = [1000, 2000, 4000, 8000, 15000, 30000];

const PendingContent = z.strictObject({
  pendingId: entityId("pending"),
  h: b64uBytes(32),
  Nh: b64uBytes(32),
  deviceId: entityId("device").optional(),
  genesis: z.unknown(),
  authority: z.strictObject({
    seq: z.number().int().min(-1),
    entries: z.array(z.unknown()).max(4096),
    bodies: z.array(z.strictObject({ seq: nonNegInt(), body: z.string() })).max(4096),
  }),
  terms: z.strictObject({ role: Role, lanes: LaneList }),
  expiresAt: nonNegInt(),
});

const Admitted = z.strictObject({
  t: z.literal("enroll.admitted"),
  pendingId: entityId("pending"),
  memberId: entityId("member"),
  deviceId: entityId("device"),
  statement: z.unknown(),
  entry: SignedEntrySchema,
  roster: z.unknown(),
  head: z.unknown(),
});

/** Member-side reasons a join ends (shown by the UI; codes only). */
export type JoinFailure =
  | "sas_mismatch"
  | "cancelled"
  | "identity_mismatch"
  | "unpinned_h"
  | "resume_mismatch"
  | "too_many_sessions"
  | "bad_admission"
  | "enroll_rejected"
  | "invite_expired"
  | "invite_used"
  | "invite_revoked"
  | "invite_in_use"
  | "removed"
  | `closed:${string}`;

class Refuse extends Error {
  constructor(readonly reason: JoinFailure) {
    super(reason);
  }
}

export interface MemberEnrollmentOptions {
  journal: EnrollmentJournal;
  relay: RelayAddress;
  timings?: Partial<RoomSessionTimings>;
  retryMs?: readonly number[];
  /** Called once the journal reached `admitted`. */
  onAdmitted?(e: MemberEnrollment): void;
  onChange?(e: MemberEnrollment): void;
}

export type JoinView = {
  roomId: string;
  state: JournalState;
  roomName: string;
  /** "317 837" once computed. */
  sas: string | null;
  terms: { role: string; lanes: string[] } | null;
  expiresAt: number | null;
  failure: string | null;
  connection: "idle" | "connecting" | "waiting" | "retrying" | "done";
  lastError: string | null;
};

export class MemberEnrollment {
  connection: JoinView["connection"] = "idle";
  lastError: string | null = null;
  private client: RoomClient | null = null;
  private attempt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private running: Promise<void> | null = null;
  private watchdog: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly o: MemberEnrollmentOptions) {}

  get journal(): EnrollmentJournal {
    return this.o.journal;
  }

  get roomId(): string {
    return this.o.journal.roomId;
  }

  view(): JoinView {
    const e = this.o.journal.e;
    return {
      roomId: this.roomId,
      state: e.state,
      roomName: e.invite.roomName,
      sas: e.sas ? `${e.sas.slice(0, 3)} ${e.sas.slice(3)}` : null,
      terms: e.terms,
      expiresAt: e.expiresAt,
      failure: e.failure,
      connection: this.connection,
      lastError: this.lastError,
    };
  }

  /** Runs from the journal state (also at plugin start). Resolves when this attempt settled. */
  start(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    // While waiting for the other side, a dropped session is reopened (with enroll.resume).
    this.watchdog ??= setInterval(() => {
      const st = this.o.journal.state;
      if ((st === "pending" || st === "confirmed") && this.connection === "waiting" && this.client?.status !== "open" && !this.running) void this.start();
    }, 2000);
    (this.watchdog as { unref?: () => void }).unref?.();
    this.running ??= this.step().finally(() => (this.running = null));
    return this.running;
  }

  /** "Codes match" (true) or "Codes do not match" (false). */
  async confirm(match: boolean): Promise<void> {
    const j = this.o.journal;
    if (j.state !== "pending" && j.state !== "confirmed") throw new Error(`Nothing to confirm (join is ${j.state})`);
    if (!match) {
      await this.sendAbort("sas_mismatch");
      return this.fail("sas_mismatch");
    }
    j.confirm();
    this.changed();
    if (this.client?.status === "open") {
      try {
        await this.client.request({ t: "enroll.confirm", pendingId: j.e.pendingId! });
      } catch (err) {
        this.onError(err);
      }
    } else void this.start();
  }

  /** Cancel: an abandoned attempt on the host; the keys are deleted here. */
  async cancel(): Promise<void> {
    const j = this.o.journal;
    if (j.state === "admitted" || j.state === "registered" || j.state === "failed") throw new Error(`Cannot cancel (join is ${j.state})`);
    if (j.e.pendingId) await this.sendAbort("cancelled");
    this.fail("cancelled");
  }

  close(): void {
    this.stopped = true;
    if (this.watchdog) clearInterval(this.watchdog);
    this.watchdog = null;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.client?.close();
    this.client = null;
  }

  // ------------------------------------------------------------------------------- internals

  private async step(): Promise<void> {
    const j = this.o.journal;
    if (!["keys", "pending", "confirmed", "held"].includes(j.state)) return;
    this.timer = null;
    this.client?.close();
    const keys = j.deviceKeys();
    const dhPub = rawPublicKey(x25519PrivateKeyFromSecret(keys.dhSecret));
    const inv = j.e.invite;
    const client = new RoomClient({
      target: { genesisHash: inv.genesisHash, endpoint: { serverId: inv.endpoint.serverId, dh: { pub: inv.endpoint.dh.pub } } },
      device: { publicKey: new Uint8Array(dhPub), secretKey: new Uint8Array(keys.dhSecret) },
      relay: this.o.relay,
      timings: this.o.timings,
      onPush: (f) => this.onPush(f),
    });
    keys.dhSecret.fill(0);
    this.client = client;
    this.connection = "connecting";
    this.changed();
    try {
      await client.open();
      const h = client.handshakeHash!;
      let resume: { state: string; admitted?: unknown } | null = null;
      if (j.state === "keys") {
        j.addSentH(h);
        const reply = await client.request(this.requestFrame(h, keys.sigSeed));
        keys.sigSeed.fill(0);
        if (reply.t === "enroll.pending") {
          const { t: _t, re: _re, ...content } = reply;
          this.acceptPending(content);
          resume = { state: "created" };
        } else if (reply.t === "enroll.resume.ok") {
          this.acceptPending(reply.pending);
          resume = { state: String(reply.state), admitted: reply.admitted };
        } else throw new RoomSessionError("bad_frame");
      } else {
        keys.sigSeed.fill(0);
        const reply = await client.request({ t: "enroll.resume", pendingId: j.e.pendingId! });
        if (reply.t !== "enroll.resume.ok" || rjcsTextOrNull(reply.pending) !== j.e.pending) {
          // A changed pending (another Nh, pendingId or terms) is never accepted (5.6 rule 3).
          await this.sendAbort("cancelled");
          throw new Refuse("resume_mismatch");
        }
        resume = { state: String(reply.state), admitted: reply.admitted };
      }
      if (resume.admitted) return this.onAdmittedFrame(resume.admitted);
      if (resume.state === "created") await client.request({ t: "sas.reveal", Nm: b64u(j.nm()) });
      if (j.state === "confirmed" && resume.state !== "member_ok") await client.request({ t: "enroll.confirm", pendingId: j.e.pendingId! });
      this.attempt = 0;
      this.connection = "waiting";
      this.lastError = null;
      this.changed();
    } catch (err) {
      keys.sigSeed.fill(0);
      this.onError(err);
    }
  }

  private requestFrame(h: string, sigSeed: Buffer): Omit<Frame, "id"> {
    const j = this.o.journal;
    const e = j.e;
    const priv = ed25519PrivateKeyFromSeed(sigSeed);
    const deviceSig = b64u(rawPublicKey(priv));
    const signed = enrollSigned({ h, genesisHash: e.invite.genesisHash, target: { inviteId: e.invite.inviteId }, deviceSig, deviceDh: e.deviceDh, label: e.label, sasCommit: e.sasCommit });
    const tokenKey = j.tokenKey();
    try {
      return {
        t: "enroll.request",
        v: 2,
        inviteId: e.invite.inviteId,
        deviceSig,
        deviceDh: e.deviceDh,
        label: e.label,
        sasCommit: e.sasCommit,
        tokenMac: b64u(enrollTokenMac(tokenKey, signed)),
        sig: b64u(signEnroll(priv, signed)),
      };
    } finally {
      tokenKey.fill(0);
    }
  }

  /** Section 5.5 and the pinned-h rule (R-4); journals `pending` with the SAS before anything is revealed. */
  private acceptPending(value: unknown): void {
    const j = this.o.journal;
    const e = j.e;
    const parsed = PendingContent.safeParse(value);
    if (!parsed.success) throw new RoomSessionError("bad_frame");
    const p = parsed.data;
    if (!e.sentH.includes(p.h)) throw new Refuse("unpinned_h");
    let genesisText: string;
    try {
      const v = verifyGenesis(p.genesis);
      if (v.genesisHash !== e.invite.genesisHash) throw new Error("genesis hash");
      if (rjcsText(v.genesis.body.endpoint) !== rjcsText(e.invite.endpoint)) throw new Error("endpoint");
      genesisText = rjcsText(v.genesis);
      // The authority-key chain only (no roster or history before admission); the full fold runs
      // over log.fetch once admitted.
      const ep = verifyAuthorityChain(v.genesis, p.authority, (b) => new Uint8Array(b64uDecodeVar(b, RJCS_MAX_BYTES))).endpoint;
      const inv = e.invite.endpoint;
      if (ep.serverId !== inv.serverId || ep.dh.pub !== inv.dh.pub || rjcsText(ep.relay) !== rjcsText(inv.relay)) throw new Error("endpoint moved");
    } catch {
      throw new Refuse("identity_mismatch");
    }
    const sas = computeSas({
      h: b64uDecode(p.h, 32),
      nm: j.nm(),
      nh: b64uDecode(p.Nh, 32),
      deviceDh: e.deviceDh,
      deviceSig: e.deviceSig,
      endpointDh: e.invite.endpoint.dh.pub,
      genesisHash: e.invite.genesisHash,
      target: { inviteId: e.invite.inviteId },
    });
    j.recordPending({ pendingId: p.pendingId, content: rjcsText(value), sas: sas.digits, transcript: sas.transcript, terms: p.terms, expiresAt: p.expiresAt, genesis: genesisText });
    log("join_pending", { roomId: this.roomId, pendingId: p.pendingId });
    this.changed();
  }

  private onPush(frame: Frame): void {
    if (frame.t === "enroll.admitted") return this.onAdmittedFrame(frame);
    if (frame.t === "enroll.closed") return this.fail(`closed:${String(frame.reason).slice(0, 24)}`);
  }

  private onAdmittedFrame(value: unknown): void {
    const j = this.o.journal;
    if (j.state === "admitted" || j.state === "registered" || j.state === "failed") return;
    const e = j.e;
    try {
      const a = Admitted.parse(value);
      const stmt = a.statement as SignedStatement;
      const d = (stmt?.body?.data ?? {}) as { member?: { memberId?: string; devices?: { deviceId: string; sig: string; dh: string }[] }; confirmation?: { method?: string; inviteRef?: string; transcript?: string } };
      const dev = d.member?.devices?.find((x) => x.deviceId === a.deviceId);
      const ok =
        a.pendingId === e.pendingId &&
        a.entry.entry.type === "member.admitted" &&
        a.entry.entry.bodyHash === bodyHash(rjcs(stmt, RJCS_MAX_FRAME_BYTES)) &&
        stmt.body.type === "member.admitted" &&
        stmt.body.roomId === this.roomId &&
        d.member?.memberId === a.memberId &&
        dev?.sig === e.deviceSig &&
        dev?.dh === e.deviceDh &&
        d.confirmation?.method === "sas6" &&
        d.confirmation.inviteRef === inviteRef(e.invite.inviteId) &&
        d.confirmation.transcript === e.transcript;
      if (!ok) throw new Refuse("bad_admission");
      j.admitted(a.memberId, a.deviceId, { seq: a.entry.entry.seq, hash: a.entry.hash });
    } catch (err) {
      return this.fail(err instanceof Refuse ? err.reason : "bad_admission");
    }
    log("join_admitted", { roomId: this.roomId, memberId: j.e.memberId, deviceId: j.e.deviceId });
    this.connection = "done";
    this.client?.close();
    this.client = null;
    this.changed();
    this.o.onAdmitted?.(this);
  }

  private onError(err: unknown): void {
    const j = this.o.journal;
    if (j.state === "failed" || j.state === "admitted" || j.state === "registered") return;
    if (err instanceof Refuse) {
      void this.sendAbort("cancelled");
      return this.fail(err.reason);
    }
    if (err instanceof JournalError && err.code === "too_many_sessions") return this.fail("too_many_sessions");
    if (err instanceof RoomSessionError) {
      const c = err.code;
      if (c === "enroll_closed") return this.fail(`closed:${String(err.fields.reason ?? "unknown").slice(0, 24)}`);
      if (c === "enroll_rejected" || c === "invite_expired" || c === "invite_used" || c === "invite_revoked" || c === "invite_in_use") return this.fail(c);
      if (c === "access_ended") return this.fail("removed");
    }
    this.lastError = err instanceof RoomSessionError ? err.code : "error";
    this.client?.close();
    this.client = null;
    if (this.stopped) return;
    const retry = this.o.retryMs ?? ENROLL_RETRY_MS;
    const delay = retry[Math.min(this.attempt, retry.length - 1)];
    this.attempt++;
    this.connection = "retrying";
    log("join_retry", { roomId: this.roomId, code: this.lastError, attempt: this.attempt, delayMs: delay });
    this.changed();
    this.timer = setTimeout(() => void this.start(), delay);
  }

  private async sendAbort(reason: "sas_mismatch" | "cancelled"): Promise<void> {
    const pendingId = this.o.journal.e.pendingId;
    if (!pendingId || this.client?.status !== "open") return;
    try {
      await this.client.request({ t: "enroll.abort", pendingId, reason }, 5000);
    } catch {}
  }

  private fail(reason: JoinFailure): void {
    const j = this.o.journal;
    if (j.state !== "failed") j.fail(reason);
    log("join_failed", { roomId: this.roomId, reason });
    this.connection = "done";
    this.close();
    this.changed();
  }

  private changed(): void {
    this.o.onChange?.(this);
  }
}

function rjcsTextOrNull(v: unknown): string | null {
  try {
    return rjcsText(v);
  } catch {
    return null;
  }
}
