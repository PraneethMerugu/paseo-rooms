// The member's verified log copy at rest (room-log-v2.md 6.1 and 8.2; usability roadmap R2.1).
//
// Layout, under `member/rooms/<roomId>/log/`, every file sealed under the KEK (I-3) and written with
// the durable layer (I-2: temp file, fsync, rename, directory fsync):
//
//   seg-<index>.sealed   purpose `member-log-seg:<roomId>:<index>`; entries `index * 64` to
//                        `index * 64 + 63` with their statement bodies. A full segment is never
//                        rewritten; only the tail segment is.
//   head.sealed          purpose `member-log-head:<roomId>`; `maxSignedHead`, the receipts of this
//                        device's own statements not yet seen in the chain, and the alerts that stop
//                        sending (fork, truncation, invalid_entry) or warn (withholding).
//
// Segments are written before the head record, so after a crash the segments are at or beyond the
// head record. The purpose binds each file to its room and segment index, so a segment copied to
// another index or room does not open; `genesisHash` inside binds it to the room's genesis.
//
// Storage bound: at most LOG_COPY_MAX_ENTRIES entries (about 64 bytes of overhead plus the entry and
// its statement body each; statement bodies are at most 64 KiB) are kept in segments. Past that cap only
// the head record moves on. That keeps detection intact: entries are hash-linked, so `maxSignedHead`
// alone pins every entry below it, and a chain the host serves later must reach it with the same hash.
// Receipts are kept until the chain contains them (then the chain pins them), at most
// LOG_COPY_MAX_RECEIPTS, newest kept. Alerts: the newest LOG_COPY_MAX_ALERTS.
//
// The spec places `maxSignedHead` and receipts inside `state.sealed`; they are in their own sealed file
// here so the enrollment journal's read-modify-write sections stay as they are (recorded in the plan).
//
// Loading never throws: an unreadable or inconsistent file is reported as a `problem`, and the caller
// re-verifies against the host with whatever authentic anchors are left. Nothing here logs secrets;
// sealed-file errors carry no key bytes or plaintext.
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import { SignedEntry, type SignedEntry as SignedEntryT } from "../authority/entries";
import type { Kek } from "../keystore/keystore";
import { b64u, b64uDecodeVar } from "../proto/b64u";
import { rjcs, rjcsParse, RJCS_MAX_BYTES } from "../proto/rjcs";
import { memberRoomDir } from "./enrollment-journal";

export const LOG_SEGMENT_ENTRIES = 64;
export const LOG_COPY_MAX_ENTRIES = 16_384;
export const LOG_COPY_MAX_RECEIPTS = 256;
export const LOG_COPY_MAX_ALERTS = 32;
/** One segment's plaintext: 64 entries with bodies of at most 64 KiB (b64u) stay below this. */
const SEGMENT_MAX_BYTES = 6 * 1024 * 1024;
const HEAD_MAX_BYTES = 4 * 1024 * 1024;
const CORRUPT_PREFIX = "corrupt-";

export const memberLogDir = (dataDir: string, roomId: string) => nodePath.join(memberRoomDir(dataDir, roomId), "log");
export const memberLogHeadPath = (dataDir: string, roomId: string) => nodePath.join(memberLogDir(dataDir, roomId), "head.sealed");
export const memberLogSegPath = (dataDir: string, roomId: string, index: number) => nodePath.join(memberLogDir(dataDir, roomId), `seg-${String(index).padStart(6, "0")}.sealed`);
export const memberLogHeadPurpose = (roomId: string) => `member-log-head:${roomId}`;
export const memberLogSegPurpose = (roomId: string, index: number) => `member-log-seg:${roomId}:${index}`;

const Segment = z.strictObject({
  v: z.literal(1),
  typ: z.literal("member-log-seg"),
  roomId: z.string(),
  genesisHash: z.string(),
  index: z.number().int().min(0),
  entries: z.array(SignedEntry).max(LOG_SEGMENT_ENTRIES),
  bodies: z.array(z.strictObject({ seq: z.number().int().min(0), body: z.string() })).max(LOG_SEGMENT_ENTRIES),
});

const StoredAlert = z.strictObject({
  type: z.enum(["fork", "truncation", "invalid_entry", "withholding"]),
  seq: z.number().int(),
  at: z.number().int(),
  proof: z.array(SignedEntry).max(2),
  peer: z.strictObject({ memberId: z.string(), deviceId: z.string() }).optional(),
  reason: z.string().max(200).optional(),
});
export type StoredAlert = z.infer<typeof StoredAlert>;

const Head = z.strictObject({
  v: z.literal(1),
  typ: z.literal("member-log-head"),
  roomId: z.string(),
  genesisHash: z.string(),
  /** Entries in segments when this record was written (segments may be ahead after a crash). */
  stored: z.number().int().min(0),
  maxSignedHead: SignedEntry.nullable(),
  receipts: z.array(SignedEntry).max(LOG_COPY_MAX_RECEIPTS),
  alerts: z.array(StoredAlert).max(LOG_COPY_MAX_ALERTS),
  updatedAt: z.number().int(),
});

export type LoadedLogCopy = {
  /** Contiguous entries from seq 0, each with its statement body if it had one. Not yet folded. */
  entries: { signed: SignedEntryT; body?: Uint8Array }[];
  /** From the head record (null if none or unreadable). */
  maxSignedHead: SignedEntryT | null;
  receipts: SignedEntryT[];
  alerts: StoredAlert[];
  /** Local damage found while loading: `head_unreadable`, `segment_unreadable:<i>`, `segment_invalid:<i>`. */
  problems: string[];
};

export type LogCopySnapshot = {
  chain: readonly SignedEntryT[];
  bodyAt(seq: number): Uint8Array | undefined;
  maxSignedHead: SignedEntryT | null;
  receipts: readonly SignedEntryT[];
  alerts: readonly StoredAlert[];
};

/** What RoomClient needs from a store (tests may supply their own). */
export interface LogCopyStore {
  load(): LoadedLogCopy;
  /** Called after the client discarded the stored chain: segments are moved aside, the head record stays. */
  discardChain(): void;
  /** Writes what changed. Throws on a failed write (the caller logs and goes on). */
  save(s: LogCopySnapshot): void;
}

export class SealedLogCopy implements LogCopyStore {
  /** Entries known to be on disk and consistent with the client's chain. */
  private durable = 0;

  constructor(private readonly o: { dataDir: string; kek: Kek; roomId: string; genesisHash: string; now?: () => number }) {}

  load(): LoadedLogCopy {
    const out: LoadedLogCopy = { entries: [], maxSignedHead: null, receipts: [], alerts: [], problems: [] };
    const { dataDir, kek, roomId, genesisHash } = this.o;
    try {
      const plain = kek.readSealed(memberLogHeadPath(dataDir, roomId), memberLogHeadPurpose(roomId));
      if (plain) {
        try {
          const h = Head.parse(rjcsParse(plain, HEAD_MAX_BYTES));
          if (h.roomId !== roomId || h.genesisHash !== genesisHash) throw new Error("head record names another room");
          out.maxSignedHead = h.maxSignedHead;
          out.receipts = h.receipts;
          out.alerts = h.alerts;
        } finally {
          plain.fill(0);
        }
      }
    } catch {
      out.problems.push("head_unreadable");
    }
    for (let index = 0; index * LOG_SEGMENT_ENTRIES < LOG_COPY_MAX_ENTRIES; index++) {
      let plain: Buffer | null;
      try {
        plain = kek.readSealed(memberLogSegPath(dataDir, roomId, index), memberLogSegPurpose(roomId, index));
      } catch {
        out.problems.push(`segment_unreadable:${index}`);
        break;
      }
      if (!plain) break;
      try {
        const s = Segment.parse(rjcsParse(plain, SEGMENT_MAX_BYTES));
        const first = index * LOG_SEGMENT_ENTRIES;
        if (s.roomId !== roomId || s.genesisHash !== genesisHash || s.index !== index) throw new Error("names another room or index");
        if (s.entries.some((e, i) => e.entry.seq !== first + i)) throw new Error("seq gap");
        const bodies = new Map<number, Uint8Array>();
        for (const b of s.bodies) bodies.set(b.seq, new Uint8Array(b64uDecodeVar(b.body, RJCS_MAX_BYTES)));
        for (const signed of s.entries) out.entries.push({ signed, ...(bodies.has(signed.entry.seq) ? { body: bodies.get(signed.entry.seq) } : {}) });
        if (s.entries.length < LOG_SEGMENT_ENTRIES) break;
      } catch {
        out.problems.push(`segment_invalid:${index}`);
        break;
      } finally {
        plain.fill(0);
      }
    }
    // Entries of a damaged segment and after it are not used; the caller decides about the rest.
    if (out.problems.some((p) => p.startsWith("segment_"))) out.entries = [];
    this.durable = out.entries.length;
    return out;
  }

  discardChain(): void {
    this.durable = 0;
    const dir = memberLogDir(this.o.dataDir, this.o.roomId);
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch {
      return;
    }
    const segs = names.filter((n) => /^seg-\d{6}\.sealed$/.test(n));
    if (segs.length === 0) return;
    // Keep the newest damaged copy for inspection, one only, so damage cannot grow storage.
    for (const n of names) if (n.startsWith(CORRUPT_PREFIX)) fs.rmSync(nodePath.join(dir, n), { recursive: true, force: true });
    const aside = nodePath.join(dir, `${CORRUPT_PREFIX}${(this.o.now ?? Date.now)()}`);
    fs.mkdirSync(aside, { mode: 0o700 });
    for (const n of segs) fs.renameSync(nodePath.join(dir, n), nodePath.join(aside, n));
  }

  save(s: LogCopySnapshot): void {
    const { dataDir, kek, roomId, genesisHash } = this.o;
    const limit = Math.min(s.chain.length, LOG_COPY_MAX_ENTRIES);
    if (limit < this.durable) this.durable = 0; // the chain was reset under us; rewrite from 0
    for (let index = Math.floor(this.durable / LOG_SEGMENT_ENTRIES); index * LOG_SEGMENT_ENTRIES < limit; index++) {
      const first = index * LOG_SEGMENT_ENTRIES;
      const entries = s.chain.slice(first, Math.min(first + LOG_SEGMENT_ENTRIES, limit));
      if (index * LOG_SEGMENT_ENTRIES + entries.length <= this.durable) continue;
      const bodies: { seq: number; body: string }[] = [];
      for (const e of entries) {
        const b = s.bodyAt(e.entry.seq);
        if (b) bodies.push({ seq: e.entry.seq, body: b64u(b) });
      }
      const plain = Buffer.from(rjcs({ v: 1, typ: "member-log-seg", roomId, genesisHash, index, entries, bodies }, SEGMENT_MAX_BYTES));
      try {
        kek.writeSealed(memberLogSegPath(dataDir, roomId, index), memberLogSegPurpose(roomId, index), plain);
      } finally {
        plain.fill(0);
      }
      this.durable = first + entries.length;
    }
    const head = {
      v: 1,
      typ: "member-log-head",
      roomId,
      genesisHash,
      stored: this.durable,
      maxSignedHead: s.maxSignedHead,
      receipts: s.receipts.slice(-LOG_COPY_MAX_RECEIPTS),
      alerts: s.alerts.slice(-LOG_COPY_MAX_ALERTS),
      updatedAt: (this.o.now ?? Date.now)(),
    };
    const plain = Buffer.from(rjcs(head, HEAD_MAX_BYTES));
    try {
      kek.writeSealed(memberLogHeadPath(dataDir, roomId), memberLogHeadPurpose(roomId), plain);
    } finally {
      plain.fill(0);
    }
  }
}
