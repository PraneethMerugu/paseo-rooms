// A device's names book for one room (usability roadmap R3.3 and R3.5): the room name and the members'
// display names learned from `room.profile` and `member.profile` MLS application messages
// (room-log-v2.md 4.5 and 7), and the alerts this device's user acknowledged.
//
// Names are display-only and untrusted text. Every name is sanitized here again, whatever the sender
// did: Unicode NFC, no control, format (bidi overrides, zero-width), private-use or surrogate code
// points, whitespace collapsed, at most two combining marks in a row, a length limit in code points.
// Names never decide identity or authorization; ids do. Acceptance rules:
//   - `room.profile` only from a device whose member is an admin in the verified roster at delivery
//     (the MLS member passes the role; the spec names no producer rule, recorded in the plan);
//     a higher `rev` wins, then the later log position;
//   - `member.profile` only for the sender's own `memberId` (the MLS sender leaf, not the payload,
//     names the member); the later log position wins.
// Spoofing is made visible, not prevented: `names()` marks two members whose names look the same
// (`nameSkeleton`), and the UI always shows a short member id next to a name.
//
// At rest: `member/rooms/<roomId>/book.sealed`, purpose `member-book:<roomId>`, sealed under the KEK.
// The host never sees these names: they travel only inside MLS. Nothing here logs a name.
import nodePath from "node:path";
import { z } from "zod";
import type { Kek } from "../keystore/keystore";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { memberRoomDir } from "./enrollment-journal";

export const ROOM_NAME_MAX = 64;
export const ROOM_DESCRIPTION_MAX = 280;
export const MEMBER_NAME_MAX = 48;
const ACKS_MAX = 256;
const BOOK_MAX_BYTES = 1024 * 1024;

export const roomBookPath = (dataDir: string, roomId: string) => nodePath.join(memberRoomDir(dataDir, roomId), "book.sealed");
export const roomBookPurpose = (roomId: string) => `member-book:${roomId}`;

/**
 * Display text as Rooms shows it, or null when nothing printable is left. Removes control, format
 * (bidi overrides, zero-width joiners), private-use, surrogate and line/paragraph separator code
 * points; collapses whitespace; keeps at most two combining marks in a row; cuts at `max` code points.
 */
export function sanitizeDisplayText(raw: unknown, max: number): string | null {
  if (typeof raw !== "string") return null;
  let s = raw.normalize("NFC");
  s = s.replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/gu, " ");
  s = s.replace(/[\s\p{Zs}]+/gu, " ");
  s = s.replace(/(\p{M}{2})\p{M}+/gu, "$1");
  s = Array.from(s.trim()).slice(0, max).join("").trim();
  return s.length > 0 ? s : null;
}

/**
 * A comparison key for look-alike names: NFKC, case folded, letters and digits only, a few common
 * confusions folded (0/o, 1/l/i, 5/s, rn/m, vv/w). Display names that share a key are flagged.
 */
export function nameSkeleton(name: string): string {
  return name
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, "")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[0]/g, "o")
    .replace(/[1i|]/g, "l")
    .replace(/5/g, "s");
}

const RoomEntry = z.strictObject({ name: z.string(), description: z.string(), rev: z.number().int().min(0), seq: z.number().int(), by: z.string() });
const MemberEntry = z.strictObject({ name: z.string(), seq: z.number().int() });
const BookFile = z.strictObject({
  v: z.literal(1),
  typ: z.literal("member-room-book"),
  roomId: z.string(),
  room: RoomEntry.nullable(),
  members: z.record(z.string(), MemberEntry),
  /** Alerts acknowledged on this device, with the time (ms), oldest first. */
  acks: z.array(z.strictObject({ type: z.string().max(40), seq: z.number().int(), at: z.number().int() })).max(ACKS_MAX),
});
type BookFile = z.infer<typeof BookFile>;

export interface RoomBookStore {
  read(): unknown | null;
  write(b: BookFile): void;
}

export class MemoryRoomBookStore implements RoomBookStore {
  value: BookFile | null = null;
  read(): unknown | null {
    return this.value ? structuredClone(this.value) : null;
  }
  write(b: BookFile): void {
    this.value = structuredClone(b);
  }
}

export class SealedRoomBookStore implements RoomBookStore {
  constructor(private readonly o: { dataDir: string; kek: Kek; roomId: string }) {}
  read(): unknown | null {
    const plain = this.o.kek.readSealed(roomBookPath(this.o.dataDir, this.o.roomId), roomBookPurpose(this.o.roomId));
    if (!plain) return null;
    try {
      return rjcsParse(plain, BOOK_MAX_BYTES);
    } finally {
      plain.fill(0);
    }
  }
  write(b: BookFile): void {
    const plain = Buffer.from(rjcs(b, BOOK_MAX_BYTES));
    try {
      this.o.kek.writeSealed(roomBookPath(this.o.dataDir, this.o.roomId), roomBookPurpose(this.o.roomId), plain);
    } finally {
      plain.fill(0);
    }
  }
}

/** A profile as received (MLS) or sent by this device: the sender from the MLS leaf, its role in the verified roster. */
export type ProfileInput = {
  seq: number;
  from: { memberId: string; role: string };
  payload: { kind: "room.profile"; name: string; description: string; rev: number } | { kind: "member.profile"; memberId: string; label: string };
};

export type ProfileOutcome = "applied" | "unchanged" | "refused";

export type NameView = { memberId: string; name: string | null; collision: boolean };

export class RoomBook {
  private b: BookFile;
  /** A failed read leaves an empty book; the next write replaces the damaged file. */
  readonly problem: string | null = null;

  constructor(
    readonly roomId: string,
    private readonly store: RoomBookStore,
  ) {
    const empty: BookFile = { v: 1, typ: "member-room-book", roomId, room: null, members: {}, acks: [] };
    let loaded: BookFile = empty;
    try {
      const raw = store.read();
      if (raw !== null) {
        const p = BookFile.safeParse(raw);
        if (!p.success || p.data.roomId !== roomId) this.problem = "book_invalid";
        else loaded = p.data;
      }
    } catch {
      this.problem = "book_unreadable";
    }
    this.b = loaded;
  }

  /** Applies a profile under the rules of the header. Persists when it changed something. */
  apply(e: ProfileInput): ProfileOutcome {
    const p = e.payload;
    if (p.kind === "room.profile") {
      if (e.from.role !== "admin") return "refused";
      const name = sanitizeDisplayText(p.name, ROOM_NAME_MAX);
      if (!name) return "refused";
      const description = sanitizeDisplayText(p.description, ROOM_DESCRIPTION_MAX) ?? "";
      const cur = this.b.room;
      if (cur && (p.rev < cur.rev || (p.rev === cur.rev && e.seq <= cur.seq))) return "unchanged";
      if (cur && cur.name === name && cur.description === description && cur.rev === p.rev) {
        this.b.room = { ...cur, seq: e.seq };
        return "unchanged";
      }
      this.b.room = { name, description, rev: p.rev, seq: e.seq, by: e.from.memberId };
      this.save();
      return "applied";
    }
    if (p.memberId !== e.from.memberId) return "refused";
    const name = sanitizeDisplayText(p.label, MEMBER_NAME_MAX);
    if (!name) return "refused";
    const cur = this.b.members[p.memberId];
    if (cur && e.seq <= cur.seq) return "unchanged";
    if (cur && cur.name === name) {
      this.b.members[p.memberId] = { name, seq: e.seq };
      return "unchanged";
    }
    this.b.members[p.memberId] = { name, seq: e.seq };
    this.save();
    return "applied";
  }

  get room(): { name: string; description: string; rev: number } | null {
    const r = this.b.room;
    return r ? { name: r.name, description: r.description, rev: r.rev } : null;
  }

  memberName(memberId: string): string | null {
    return this.b.members[memberId]?.name ?? null;
  }

  /**
   * Names of the given members (the verified roster), each flagged when another listed member's name
   * looks the same. Names of members no longer in the roster are not shown.
   */
  names(memberIds: readonly string[]): NameView[] {
    const keys = new Map<string, number>();
    for (const id of memberIds) {
      const n = this.memberName(id);
      if (n) keys.set(nameSkeleton(n), (keys.get(nameSkeleton(n)) ?? 0) + 1);
    }
    return memberIds.map((memberId) => {
      const name = this.memberName(memberId);
      return { memberId, name, collision: name !== null && (keys.get(nameSkeleton(name)) ?? 0) > 1 };
    });
  }

  isAcked(type: string, seq: number): boolean {
    return this.b.acks.some((a) => a.type === type && a.seq === seq);
  }

  /** Acknowledges alerts (R3.5): hides their notice on this device. It does not change what the alert stopped. */
  ack(alerts: readonly { type: string; seq: number }[], at: number): number {
    let n = 0;
    for (const a of alerts) {
      if (this.isAcked(a.type, a.seq)) continue;
      this.b.acks.push({ type: a.type.slice(0, 40), seq: a.seq, at });
      n++;
    }
    if (n === 0) return 0;
    this.b.acks = this.b.acks.slice(-ACKS_MAX);
    this.save();
    return n;
  }

  private save(): void {
    this.store.write(this.b);
  }
}
