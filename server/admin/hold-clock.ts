// The admin daemon's own clock for device holds (identity-model.md 6.3; room-log-v2.md section 5;
// implementation plan I-11 follow-up, written into the specs after round 9).
//
// The fold measures a hold in the host's `hts`, which members cannot verify. The admin daemon is the
// real enforcement: it times each held request on its OWN clock from the moment it first saw the
// request, and signs an automatic approval only when both that time and the `hts` hold (which the fold
// checks anyway) have passed. A host that back-dates a request's `hts` therefore cannot shorten the
// hold the admin daemon applies. In the embedded deployment host and admin daemon are one process, so
// the two clocks agree; a standalone host is where this matters.
//
// First-seen times are kept in `admin/<roomId>/holds.sealed`, so a restart does not restart a 72 h
// hold (a lost file only makes holds longer). Entries are dropped once their request is no longer
// pending. Nothing here logs request contents.
import nodePath from "node:path";
import { z } from "zod";
import { autoApprovalEndsAt, holdMs } from "../authority/holds";
import { Hash32, RoomId } from "../authority/schema";
import type { PendingRequest, RoomState } from "../authority/state";
import type { Kek } from "../keystore/keystore";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { adminDir } from "./signer";

export const ADMIN_HOLDS_FILE = "holds.sealed";
export const adminHoldsPath = (dataDir: string, roomId: string) => nodePath.join(adminDir(dataDir, roomId), ADMIN_HOLDS_FILE);
export const adminHoldsPurpose = (roomId: string) => `admin-holds:${roomId}`;

const MAX_REQUESTS = 4096;
const HoldsFile = z.strictObject({
  v: z.literal(2),
  typ: z.literal("admin-holds"),
  roomId: RoomId,
  /** [request ref (bodyHash), first seen in ms on this daemon's clock] (RJCS keys cannot hold b64u). */
  seen: z.array(z.tuple([Hash32, z.number().int().min(0)])).max(MAX_REQUESTS),
});

export class AdminHoldClock {
  private seen: Record<string, number>;

  constructor(
    private readonly dataDir: string,
    private readonly kek: Kek,
    private readonly roomId: string,
    private readonly now: () => number,
  ) {
    this.seen = {};
    try {
      const plain = kek.readSealed(adminHoldsPath(dataDir, roomId), adminHoldsPurpose(roomId));
      if (plain) {
        const p = HoldsFile.safeParse(rjcsParse(plain));
        if (p.success && p.data.roomId === roomId) this.seen = Object.fromEntries(p.data.seen);
      }
    } catch {
      // Unreadable: start empty. Every pending request is then first seen now, which only lengthens holds.
    }
  }

  /** Records the first sighting of every pending request and forgets requests that are no longer pending. */
  observe(st: Readonly<RoomState>): void {
    const now = this.now();
    const next: Record<string, number> = {};
    let changed = false;
    for (const [ref, p] of Object.entries(st.pending)) {
      if (p.status !== "pending") continue;
      if (Object.keys(next).length >= MAX_REQUESTS) break;
      const t = this.seen[ref];
      next[ref] = t ?? now;
      if (t === undefined) changed = true;
    }
    if (!changed && Object.keys(next).length === Object.keys(this.seen).length) return;
    this.seen = next;
    this.kek.writeSealed(adminHoldsPath(this.dataDir, this.roomId), adminHoldsPurpose(this.roomId), rjcs({ v: 2, typ: "admin-holds", roomId: this.roomId, seen: Object.entries(next) }));
  }

  firstSeen(ref: string): number | undefined {
    return this.seen[ref];
  }

  /**
   * When this daemon may sign the automatic approval: the later of the hold on its own clock from
   * first sight and the `hts` hold the fold checks. Null when the request needs an admin, or when
   * it has not been seen yet (call `observe` first).
   */
  endsAt(st: Readonly<RoomState>, ref: string, p: PendingRequest): number | null {
    const byHts = autoApprovalEndsAt(st, p);
    const seen = this.seen[ref];
    if (byHts === null || seen === undefined) return null;
    return Math.max(byHts, seen + holdMs(p));
  }
}
