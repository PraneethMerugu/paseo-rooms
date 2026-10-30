// Room session rules shared by the room endpoint (server/host/room-endpoint.ts) and the member's room
// client (server/member/room-client.ts): enrollment-v2.md sections 3.3 to 3.6, 4 and 10.
// Pure: no sockets, no I/O.
import { CipherState } from "../noise/cipher-state";
import { handshakeMessageBytes } from "../noise/handshake-state";
import { FrameOpener, sealFrame, type Frame } from "./records";

/** Timers of sections 3.3 and 3.5. Tests shorten them; production uses the defaults. */
export interface RoomSessionTimings {
  /** Per handshake message, and for key confirmation by the initiator (3.3, 3.5). */
  handshakeTimeoutMs: number;
  /** A session lasts at most 12 hours (3.5). */
  maxSessionMs: number;
  /** Either side pings after 30 s of silence (3.5). */
  pingAfterMs: number;
  /** ...and closes after 90 s without traffic (3.5). */
  idleCloseMs: number;
}

export const ROOM_SESSION_TIMINGS: Readonly<RoomSessionTimings> = {
  handshakeTimeoutMs: 10_000,
  maxSessionMs: 12 * 60 * 60 * 1000,
  pingAfterMs: 30_000,
  idleCloseMs: 90_000,
};

export function resolveTimings(t: Partial<RoomSessionTimings> = {}): RoomSessionTimings {
  return { ...ROOM_SESSION_TIMINGS, ...t };
}

/** IK message 1 with an empty payload: e (32) + encrypted s (48) + empty payload tag (16) = 96 bytes. */
export const IK_MESSAGE1_BYTES = handshakeMessageBytes("IK", 0);
/** IK message 2 with an empty payload: e (32) + empty payload tag (16) = 48 bytes. */
export const IK_MESSAGE2_BYTES = handshakeMessageBytes("IK", 1);

/** Error codes of section 10. */
export const ROOM_ERROR_CODES = [
  "bad_frame",
  "unsupported_version",
  "busy",
  "enroll_rejected",
  "invite_expired",
  "invite_used",
  "invite_revoked",
  "invite_in_use",
  "enroll_closed",
  "not_authorized",
  "access_ended",
  "not_permitted",
  "stale_base",
  "unknown_base",
  "stale_roster",
  "stale_epoch",
  "superseded",
  "moved",
  "persist_failed",
  "internal",
] as const;
export type RoomErrorCode = (typeof ROOM_ERROR_CODES)[number];

/** Every error closes the session except these (section 10). */
export const NON_CLOSING_ERRORS: ReadonlySet<RoomErrorCode> = new Set(["not_permitted", "busy", "stale_base", "unknown_base", "stale_roster", "stale_epoch", "persist_failed"]);

export type AccessEndedReason = "removed" | "left" | "room_closed";

/** Operations any initiator may call before it is known (section 4). Served from I-9 on. */
export const PREAUTH_OPS: ReadonlySet<string> = new Set(["enroll.request", "sas.reveal", "enroll.confirm", "enroll.abort", "enroll.resume"]);

/** Active-device operations served (I-8; grants from I-10, when the room serves them; device links from I-11). */
export const SESSION_OPS: ReadonlySet<string> = new Set([
  "session.hello",
  "log.fetch",
  "log.subscribe",
  "roster.get",
  "stmt.submit",
  "grant.issue",
  "grant.status",
  "grant.report",
  "device.link.create",
  "link.nonce",
  "link.confirm",
  "link.abort",
]);

/** Active-device operations of section 4 that later milestones serve; answered `not_permitted` until then. */
export const LATER_OPS: ReadonlySet<string> = new Set([
  "authority.get",
  "device.rekey",
  "kp.publish",
  "kp.fetch",
  "commit.submit",
  "welcome.fetch",
  "msg.send",
  "msg.fetch",
  "msg.ack",
]);

/** `log.fetch` bounds (room-log-v2.md 8.3). */
export const LOG_FETCH_MAX = 1000;
/** Entries per `log.entries` push. */
export const LOG_PUSH_MAX = 100;
/** A reply that carries log entries stops adding them past this many bytes, well below the 4 MiB frame cap. */
export const LOG_REPLY_BUDGET_BYTES = 3 * 1024 * 1024;

/** Transport keys of one session after Split(): frames out, frames in. Any failure is fatal (3.4). */
export class SessionCrypto {
  private readonly opener: FrameOpener;
  constructor(
    private readonly send: CipherState,
    receive: CipherState,
  ) {
    this.opener = new FrameOpener(receive);
  }
  seal(frame: Frame): Uint8Array[] {
    return sealFrame(this.send, frame);
  }
  /** One transport message in; a frame when its last fragment arrived, else null. Throws RecordError. */
  open(message: Uint8Array): Frame | null {
    return this.opener.open(message);
  }
}

/**
 * Silence and lifetime timers of section 3.5: `onPing` after `pingAfterMs` without received traffic
 * (again every `pingAfterMs`), `onIdle` after `idleCloseMs`, `onExpire` at `maxSessionMs`.
 */
export class SessionClock {
  private lastRx: number;
  private lastPing = 0;
  private readonly tick: ReturnType<typeof setInterval>;
  private readonly expire: ReturnType<typeof setTimeout>;

  constructor(
    private readonly t: RoomSessionTimings,
    private readonly now: () => number,
    private readonly cb: { onPing(): void; onIdle(): void; onExpire(): void },
  ) {
    this.lastRx = now();
    const step = Math.max(5, Math.min(1000, Math.floor(Math.min(t.pingAfterMs, t.idleCloseMs) / 3)));
    this.tick = setInterval(() => this.check(), step);
    this.expire = setTimeout(() => cb.onExpire(), Math.min(t.maxSessionMs, 2 ** 31 - 1));
  }

  received(): void {
    this.lastRx = this.now();
  }

  private check(): void {
    const n = this.now();
    if (n - this.lastRx >= this.t.idleCloseMs) return this.cb.onIdle();
    if (n - this.lastRx >= this.t.pingAfterMs && n - this.lastPing >= this.t.pingAfterMs) {
      this.lastPing = n;
      this.cb.onPing();
    }
  }

  stop(): void {
    clearInterval(this.tick);
    clearTimeout(this.expire);
  }
}

/** Request id check of section 3.6: 1..2^31. */
export function isRequestId(v: unknown): v is number {
  return Number.isSafeInteger(v) && (v as number) >= 1 && (v as number) <= 2 ** 31;
}

export function isInt(v: unknown, min: number, max = Number.MAX_SAFE_INTEGER): v is number {
  return Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max;
}
