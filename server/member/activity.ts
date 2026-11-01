// Activity feed of a room (usability roadmap R3.5; room-log-v2.md 4.6): what changed, derived from the
// device's own verified fold, never from host claims. Each item comes from an entry the fold accepted
// (hash chain, host signature, statement signature and every fold rule checked), and its fields from
// the difference between the fold state before and after that entry. So a host can withhold or delay
// an entry (room-log-v2 6.4), but cannot make the feed show something the log does not prove.
//
// Items carry ids, types and setting values only; the UI turns them into text (client/v2-text.ts) and
// puts display names next to ids. Detection alerts (fork, truncation, MLS alerts) are not entries; the
// runtime adds them to the view from the device's own checks.
import type { SignedEntry } from "../authority/entries";
import type { RoomState } from "../authority/state";

/** Entry types that produce a notice (room-log-v2 4.6), plus lane creation and closing. */
export const NOTICE_TYPES: ReadonlySet<string> = new Set([
  "room.policy.changed",
  "room.close.proposed",
  "room.closed",
  "admin.added",
  "admin.removed",
  "admin.key.rotated",
  "admin.key.revoked",
  "recovery.key.proposed",
  "recovery.key.rotated",
  "host.key.rotated",
  "host.key.revoked",
  "endpoint.rotated",
  "lane.offer.rotated",
  "member.admitted",
  "member.role.changed",
  "member.removed",
  "member.left",
  "member.device.replaced",
  "device.added",
  "device.add.vetoed",
  "device.add.approved",
  "device.removed",
  "device.rekeyed",
  "device.rekey.vetoed",
  "device.rekey.approved",
  "device.conflict.resolved",
  "device.leaf.repair.requested",
  "lane.created",
  "lane.closed",
  "lane.names.changed",
  "lane.degraded",
  "grant.suspected-theft",
  "endpoint.evicted",
  "mls.stalled",
]);

/** Types shown as security alerts (room-log-v2 4.6 "Alerts"). */
export const ALERT_TYPES: ReadonlySet<string> = new Set(["grant.suspected-theft", "endpoint.evicted", "mls.stalled", "lane.degraded", "uncertified_key"]);

export type ActivityItem = {
  seq: number;
  /** Host time of the entry (ms); members cannot verify it. */
  hts: number;
  /** The entry type, or `uncertified_key` when a re-fold left a key uncertified. */
  type: string;
  alert: boolean;
  memberId?: string;
  deviceId?: string;
  laneId?: string;
  /** member.role.changed: the new role. lane.names.changed: "shown" or "hidden". */
  value?: string;
  /** room.policy.changed: each changed setting with its old and new value. */
  changes?: { setting: string; from: string; to: string }[];
  /** device.added and device.rekeyed: the request came from the member's only active device. */
  sole?: boolean;
  /** Earlier entries this entry's re-fold marked suspect or void. */
  marked?: number;
};

const devicesOf = (st: Readonly<RoomState>) => {
  const m = new Map<string, string>();
  for (const x of Object.values(st.members)) for (const d of x.devices) m.set(d.deviceId, x.memberId);
  return m;
};

const uncertifiedCount = (st: Readonly<RoomState>) => st.auth.hostKeys.filter((h) => h.uncertified).length + (st.auth.endpointUncertified ? 1 : 0) + Object.values(st.auth.lanes).filter((l) => l.uncertified).length;

/** The notices of one accepted entry (pure). */
export function activityOf(signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): ActivityItem[] {
  const e = signed.entry;
  if (e.cls !== "stmt" || !NOTICE_TYPES.has(e.type)) return [];
  const base = { seq: e.seq, hts: e.hts, type: e.type, alert: ALERT_TYPES.has(e.type) };
  const out: ActivityItem[] = [];
  const devB = devicesOf(before);
  const devA = devicesOf(after);
  const pendingHere = Object.values(after.pending).find((p) => p.seq === e.seq);
  const statusChanged = Object.entries(after.pending).find(([ref, p]) => before.pending[ref] && before.pending[ref].status !== p.status);
  switch (e.type) {
    case "member.admitted":
      for (const id of Object.keys(after.members)) if (!before.members[id]) out.push({ ...base, memberId: id });
      break;
    case "member.removed":
    case "member.left":
      for (const id of Object.keys(before.members)) if (!after.members[id]) out.push({ ...base, memberId: id });
      break;
    case "member.role.changed":
      for (const [id, m] of Object.entries(after.members)) if (before.members[id] && before.members[id].role !== m.role) out.push({ ...base, memberId: id, value: m.role });
      break;
    case "member.device.replaced":
    case "device.add.approved":
    case "device.rekey.approved":
      for (const [d, m] of devA) if (!devB.has(d) || (e.type === "device.rekey.approved" && statusChanged?.[1].deviceId === d)) out.push({ ...base, memberId: m, deviceId: d });
      if (out.length === 0 && statusChanged) out.push({ ...base, memberId: statusChanged[1].memberId, deviceId: statusChanged[1].deviceId });
      break;
    case "device.removed":
      for (const [d, m] of devB) if (!devA.has(d)) out.push({ ...base, memberId: m, deviceId: d });
      break;
    case "device.added":
    case "device.rekeyed":
      if (pendingHere) out.push({ ...base, memberId: pendingHere.memberId, deviceId: pendingHere.deviceId, sole: pendingHere.sole });
      break;
    case "device.add.vetoed":
    case "device.rekey.vetoed":
      if (statusChanged) out.push({ ...base, memberId: statusChanged[1].memberId, deviceId: statusChanged[1].deviceId });
      break;
    case "device.conflict.resolved":
      for (const id of Object.keys(before.conflicts)) if (after.conflicts[id] === undefined) out.push({ ...base, memberId: id });
      break;
    case "device.leaf.repair.requested": {
      const r = Object.values(after.repairs).find((x) => x.seq === e.seq);
      out.push(r ? { ...base, memberId: r.memberId, deviceId: r.deviceId } : base);
      break;
    }
    case "room.policy.changed": {
      const changes: { setting: string; from: string; to: string }[] = [];
      for (const [k, v] of Object.entries(after.auth.policy)) {
        const old = (before.auth.policy as Record<string, unknown>)[k];
        if (old !== v) changes.push({ setting: k, from: String(old), to: String(v) });
      }
      out.push({ ...base, changes });
      break;
    }
    case "lane.created":
    case "lane.closed":
    case "lane.offer.rotated":
    case "lane.degraded":
    case "lane.names.changed": {
      for (const [id, l] of Object.entries(after.auth.lanes)) {
        const b = before.auth.lanes[id];
        const changed = !b || b.status !== l.status || b.offer.serverId !== l.offer.serverId || b.showNames !== l.showNames;
        if (changed) out.push({ ...base, laneId: id, ...(e.type === "lane.names.changed" ? { value: l.showNames ? "shown" : "hidden" } : {}), ...(e.type === "lane.created" ? { memberId: l.owner } : {}) });
      }
      if (out.length === 0) out.push(base);
      break;
    }
    default:
      out.push(base);
  }
  const marked = Object.keys(after.marks).filter((k) => before.marks[k] === undefined).length;
  if (marked > 0) for (const x of out) x.marked = marked;
  if (uncertifiedCount(after) > uncertifiedCount(before)) out.push({ seq: e.seq, hts: e.hts, type: "uncertified_key", alert: true });
  return out;
}

/** The newest items of a room, in log order; entries at or below the last seen seq are ignored (replays). */
export class ActivityFeed {
  private readonly list: ActivityItem[] = [];
  private last = -1;

  constructor(private readonly max = 200) {}

  push(signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): void {
    if (signed.entry.seq <= this.last) return;
    this.last = signed.entry.seq;
    for (const x of activityOf(signed, before, after)) this.list.push(x);
    if (this.list.length > this.max) this.list.splice(0, this.list.length - this.max);
  }

  get lastSeq(): number {
    return this.last;
  }

  /** Newest first. */
  items(limit = 50): ActivityItem[] {
    return this.list.slice(-limit).reverse();
  }
}
