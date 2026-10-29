// Roster (identity-model.md section 6.1; room-log-v2.md section 5).
//   Roster     = { roomId, seq: rosterSeq, members: [RosterEntry...] sorted by memberId }
//   rosterHash = H("roster", RJCS(Roster))
// `rosterSeq` is the seq of the last roster-changing entry, not the head.
import { b64u } from "../proto/b64u";
import { H_ROSTER } from "../proto/contexts";
import { rjcs } from "../proto/rjcs";
import { H } from "../proto/tbs";
import type { DeviceEntry, RosterEntry } from "./schema";

export type Roster = { roomId: string; seq: number; members: RosterEntry[] };

/** Members in canonical order: by memberId, each with lanes sorted and devices sorted by deviceId. */
export function sortedMembers(members: Record<string, RosterEntry>): RosterEntry[] {
  return Object.keys(members)
    .sort()
    .map((id) => {
      const m = members[id];
      return { memberId: m.memberId, role: m.role, lanes: [...m.lanes].sort(), devices: sortDevices(m.devices) };
    });
}

export function sortDevices(devices: readonly DeviceEntry[]): DeviceEntry[] {
  return [...devices].sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0));
}

export function buildRoster(roomId: string, rosterSeq: number, members: Record<string, RosterEntry>): Roster {
  return { roomId, seq: rosterSeq, members: sortedMembers(members) };
}

export function rosterHash(roster: Roster): string {
  return b64u(H(H_ROSTER, rjcs(roster, Number.MAX_SAFE_INTEGER)));
}

/** Canonical text of the members alone, to tell whether an entry changed the roster. */
export function membersFingerprint(members: Record<string, RosterEntry>): string {
  return new TextDecoder().decode(rjcs(sortedMembers(members), Number.MAX_SAFE_INTEGER));
}
