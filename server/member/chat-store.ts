// A device's chat history of one room (usability roadmap R3.4; mls-integration.md 5.2 and 8.2): the
// chat messages this device sent or accepted from the room group, sealed under the KEK.
//
// Layout, under `member/rooms/<roomId>/chat/`, every file sealed (I-3) and written with the durable
// layer (temp file, fsync, rename, directory fsync):
//
//   seg-<index>.sealed   purpose `member-chat-seg:<roomId>:<index>`; up to CHAT_SEGMENT_MESSAGES
//                        messages in the order this device stored them. Only the newest segment is
//                        rewritten; older ones are only deleted (retention).
//   read.sealed          purpose `member-chat-read:<roomId>`; the read marker (a log position).
//
// Order is the room log position (`seq`): one total order every member shares. A message is stored
// once per position (`add` is idempotent), which is what the MLS member's write ordering needs: the
// store is written before the group state and the ack, so a crash in between re-delivers a message
// the store already holds (8.2).
//
// Retention and size: at most `maxMessages` messages and about `maxBytes` of text; whole segments are
// dropped oldest first, and segments whose newest message was stored more than `maxAgeMs` ago (local
// clock, not the host's) are dropped too. The newest segment is never dropped. Worst case on disk:
// about (maxMessages / 64 + 1) segments of 64 messages of at most CHAT_TEXT_MAX code units.
//
// Text is untrusted. It is stored after `chatDisplayText`: control characters other than newline and
// tab, and bidi embedding, override and isolate characters are removed. The UI renders plain text only.
// Nothing here logs message text.
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import type { Kek } from "../keystore/keystore";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { memberRoomDir } from "./enrollment-journal";

export const CHAT_SEGMENT_MESSAGES = 64;
export const CHAT_LIMITS = { maxMessages: 2048, maxBytes: 8 * 1024 * 1024, maxAgeMs: 90 * 24 * 3600 * 1000 };
const SEGMENT_MAX_BYTES = 2 * 1024 * 1024;

export const chatDir = (dataDir: string, roomId: string) => nodePath.join(memberRoomDir(dataDir, roomId), "chat");
export const chatSegPath = (dataDir: string, roomId: string, index: number) => nodePath.join(chatDir(dataDir, roomId), `seg-${String(index).padStart(6, "0")}.sealed`);
export const chatReadPath = (dataDir: string, roomId: string) => nodePath.join(chatDir(dataDir, roomId), "read.sealed");
export const chatSegPurpose = (roomId: string, index: number) => `member-chat-seg:${roomId}:${index}`;
export const chatReadPurpose = (roomId: string) => `member-chat-read:${roomId}`;

/** Plain chat text as stored and shown: no control characters but newline and tab, no bidi controls. */
export function chatDisplayText(raw: string): string {
  return raw
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .replace(/[\u2028\u2029]/g, "\n");
}

const Stored = z.strictObject({
  seq: z.number().int().min(0),
  epoch: z.number().int().min(0),
  /** Host time of the log entry (ms); for own messages the local time at sending. */
  hts: z.number().int(),
  /** The sender's clock (ms), from the signed message: a claim. */
  ts: z.number().int(),
  /** Local time this device stored it (ms): retention is measured on this clock. */
  rx: z.number().int(),
  memberId: z.string(),
  deviceId: z.string(),
  text: z.string(),
  own: z.boolean(),
});
export type ChatRecord = z.infer<typeof Stored>;
export type ChatInput = Omit<ChatRecord, "rx" | "text"> & { text: string };

const Segment = z.strictObject({ v: z.literal(1), typ: z.literal("member-chat-seg"), roomId: z.string(), index: z.number().int().min(0), messages: z.array(Stored).max(CHAT_SEGMENT_MESSAGES) });
const ReadMark = z.strictObject({ v: z.literal(1), typ: z.literal("member-chat-read"), roomId: z.string(), readSeq: z.number().int() });

type SegInfo = { index: number; seqs: number[]; bytes: number; newestRx: number };

const sizeOf = (m: ChatRecord) => m.text.length * 3 + 200;

export class ChatStore {
  /** Every stored message, ordered by `seq`. */
  private msgs: ChatRecord[] = [];
  private readonly seqs = new Set<number>();
  private segs: SegInfo[] = [];
  /** Messages of the newest segment (rewritten on each add). */
  private tail: ChatRecord[] = [];
  private tailIndex = 0;
  private readSeq = -1;
  /** Damage found while loading (`segment_unreadable:<i>`, `read_unreadable`); the rest is used. */
  readonly problems: string[] = [];
  private readonly limits: typeof CHAT_LIMITS;
  private readonly now: () => number;

  constructor(private readonly o: { dataDir: string; kek: Kek; roomId: string; now?: () => number; limits?: Partial<typeof CHAT_LIMITS> }) {
    this.limits = { ...CHAT_LIMITS, ...o.limits };
    this.now = o.now ?? Date.now;
    this.load();
  }

  private load(): void {
    const { dataDir, kek, roomId } = this.o;
    let names: string[] = [];
    try {
      names = fs.readdirSync(chatDir(dataDir, roomId));
    } catch {
      names = [];
    }
    const indices = names
      .map((n) => /^seg-(\d{6})\.sealed$/.exec(n))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => Number(m[1]))
      .sort((a, b) => a - b);
    let lastGood: ChatRecord[] | null = null;
    for (const index of indices) {
      try {
        const plain = kek.readSealed(chatSegPath(dataDir, roomId, index), chatSegPurpose(roomId, index));
        if (!plain) continue;
        try {
          const s = Segment.parse(rjcsParse(plain, SEGMENT_MAX_BYTES));
          if (s.roomId !== roomId || s.index !== index) throw new Error("names another room or index");
          const kept = s.messages.filter((m) => !this.seqs.has(m.seq));
          for (const m of kept) this.seqs.add(m.seq);
          this.msgs.push(...kept);
          this.segs.push({ index, seqs: kept.map((m) => m.seq), bytes: kept.reduce((n, m) => n + sizeOf(m), 0), newestRx: Math.max(0, ...kept.map((m) => m.rx)) });
          lastGood = index === indices[indices.length - 1] ? s.messages : null;
        } finally {
          plain.fill(0);
        }
      } catch {
        this.problems.push(`segment_unreadable:${index}`);
      }
    }
    this.msgs.sort((a, b) => a.seq - b.seq);
    const last = indices.length ? indices[indices.length - 1] : -1;
    // A damaged newest segment is not rewritten over; new messages go to a fresh one.
    if (lastGood && lastGood.length < CHAT_SEGMENT_MESSAGES) {
      this.tailIndex = last;
      this.tail = lastGood;
    } else {
      this.tailIndex = last + 1;
      this.tail = [];
    }
    try {
      const plain = kek.readSealed(chatReadPath(dataDir, roomId), chatReadPurpose(roomId));
      if (plain) {
        try {
          const r = ReadMark.parse(rjcsParse(plain, 4096));
          if (r.roomId === roomId) this.readSeq = r.readSeq;
        } finally {
          plain.fill(0);
        }
      }
    } catch {
      this.problems.push("read_unreadable");
    }
  }

  /**
   * Stores messages not stored yet (by `seq`). Throws when a write failed; memory then stays as it was,
   * so the caller (the MLS member) neither writes its state nor acknowledges, and retries (8.2).
   */
  add(input: readonly ChatInput[]): number {
    const fresh: ChatRecord[] = [];
    for (const m of input) {
      if (this.seqs.has(m.seq) || fresh.some((f) => f.seq === m.seq)) continue;
      const text = chatDisplayText(m.text);
      if (!text.trim()) continue;
      fresh.push(Stored.parse({ ...m, text, rx: this.now() }));
    }
    if (fresh.length === 0) return 0;
    // Plan the writes first; commit to memory only after every write succeeded.
    let tail = [...this.tail];
    let tailIndex = this.tailIndex;
    let changed = false;
    const writes: { index: number; messages: ChatRecord[] }[] = [];
    for (const m of fresh) {
      if (tail.length >= CHAT_SEGMENT_MESSAGES) {
        if (changed) writes.push({ index: tailIndex, messages: tail });
        tailIndex += 1;
        tail = [];
      }
      tail.push(m);
      changed = true;
    }
    writes.push({ index: tailIndex, messages: tail });
    const done = new Map<number, ChatRecord[]>();
    for (const w of writes) {
      this.writeSegment(w.index, w.messages);
      done.set(w.index, w.messages);
    }
    for (const [index, messages] of done) {
      const info: SegInfo = { index, seqs: messages.map((m) => m.seq), bytes: messages.reduce((n, m) => n + sizeOf(m), 0), newestRx: Math.max(0, ...messages.map((m) => m.rx)) };
      const at = this.segs.findIndex((s) => s.index === index);
      if (at >= 0) this.segs[at] = info;
      else this.segs.push(info);
    }
    this.tail = tail;
    this.tailIndex = tailIndex;
    for (const m of fresh) this.seqs.add(m.seq);
    this.msgs.push(...fresh);
    this.msgs.sort((a, b) => a.seq - b.seq);
    this.prune();
    return fresh.length;
  }

  /** Drops whole segments, oldest first, past the count, size or age limit. Never the newest one. */
  prune(): void {
    const cutoff = this.now() - this.limits.maxAgeMs;
    let count = this.msgs.length;
    let bytes = this.segs.reduce((n, s) => n + s.bytes, 0);
    const drop = new Set<number>();
    for (const s of this.segs) {
      if (s.index === this.tailIndex) break;
      if (count > this.limits.maxMessages || bytes > this.limits.maxBytes || s.newestRx < cutoff) {
        drop.add(s.index);
        count -= s.seqs.length;
        bytes -= s.bytes;
      } else break;
    }
    if (drop.size === 0) return;
    const gone = new Set<number>();
    for (const s of this.segs.filter((x) => drop.has(x.index))) {
      fs.rmSync(chatSegPath(this.o.dataDir, this.o.roomId, s.index), { force: true });
      for (const q of s.seqs) gone.add(q);
    }
    this.segs = this.segs.filter((s) => !drop.has(s.index));
    this.msgs = this.msgs.filter((m) => !gone.has(m.seq));
    for (const q of gone) this.seqs.delete(q);
  }

  private writeSegment(index: number, messages: ChatRecord[]): void {
    const plain = Buffer.from(rjcs({ v: 1, typ: "member-chat-seg", roomId: this.o.roomId, index, messages }, SEGMENT_MAX_BYTES));
    try {
      this.o.kek.writeSealed(chatSegPath(this.o.dataDir, this.o.roomId, index), chatSegPurpose(this.o.roomId, index), plain);
    } finally {
      plain.fill(0);
    }
  }

  /** Messages before `before` (a log position), newest `limit` of them, oldest first; `more` if older ones exist. */
  page(before: number | null, limit: number): { messages: ChatRecord[]; more: boolean } {
    const cutoff = this.now() - this.limits.maxAgeMs;
    const all = this.msgs.filter((m) => m.rx >= cutoff && (before === null || m.seq < before));
    const n = Math.max(1, Math.min(limit, 200));
    return { messages: all.slice(-n).map((m) => ({ ...m })), more: all.length > n };
  }

  get size(): number {
    return this.msgs.length;
  }

  get lastSeq(): number {
    return this.msgs.length ? this.msgs[this.msgs.length - 1].seq : -1;
  }

  get read(): number {
    return this.readSeq;
  }

  /** Messages from others after the read marker. */
  get unread(): number {
    const cutoff = this.now() - this.limits.maxAgeMs;
    let n = 0;
    for (let i = this.msgs.length - 1; i >= 0 && this.msgs[i].seq > this.readSeq; i--) if (!this.msgs[i].own && this.msgs[i].rx >= cutoff) n++;
    return n;
  }

  /** Moves the read marker forward to `seq` (never past the newest stored message, never back). */
  markRead(seq: number): number {
    const to = Math.min(seq, this.lastSeq);
    if (to <= this.readSeq) return this.unread;
    const plain = Buffer.from(rjcs({ v: 1, typ: "member-chat-read", roomId: this.o.roomId, readSeq: to }));
    try {
      this.o.kek.writeSealed(chatReadPath(this.o.dataDir, this.o.roomId), chatReadPurpose(this.o.roomId), plain);
    } finally {
      plain.fill(0);
    }
    this.readSeq = to;
    return this.unread;
  }
}
