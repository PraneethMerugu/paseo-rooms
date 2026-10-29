// Device adds and rekeys held for approval (room-log-v2.md sections 4.3 and 5; identity-model.md
// 6.3; keys-rotation-recovery.md 4.1; decision rounds 3, 4 item 2, 5 item 3).
//
//   request (device.added | device.rekeyed)  -> pending, with `sole` and `young` fixed at its entry
//   veto    (device.add.vetoed | device.rekey.vetoed) -> vetoed; opens a device conflict
//   cancel  (requester removed or rekeyed, rekeyed device removed, member removed or left)
//   approve (device.add.approved | device.rekey.approved) -> approved, if every rule below holds
//
// Holds are measured in `hts` between the request entry and the approval entry. The fold cannot
// verify the host clock; the real enforcement is the admin daemon's own clock (section 5).
import { versionKey, type Fail, type PendingRequest, type RoomState } from "./state";

const HOUR_MS = 60 * 60 * 1000;
/** Hold before an automatic approval. */
export const HOLD_MS = 24 * HOUR_MS;
/** Hold when the requester was the member's only active device (sole-device request). */
export const SOLE_HOLD_MS = 72 * HOUR_MS;
/** A device active for less than this cannot request an automatically approved add. */
export const YOUNG_DEVICE_MS = 24 * HOUR_MS;

export function holdMs(p: PendingRequest): number {
  return p.sole ? SOLE_HOLD_MS : HOLD_MS;
}

export function openRequest(s: RoomState, bodyHash: string, req: Omit<PendingRequest, "status">): void {
  s.pending[bodyHash] = { ...req, status: "pending" };
}

/** Cancels every pending request that matches (section 4.3, R-8). */
export function cancelRequests(s: RoomState, match: (p: PendingRequest) => boolean): void {
  for (const p of Object.values(s.pending)) if (p.status === "pending" && match(p)) p.status = "cancelled";
}

/** Requests a removed device made, and the pending rekeys of that device. */
export const byOrForDevice = (deviceId: string) => (p: PendingRequest) => p.requester === deviceId || (p.kind === "rekey" && p.deviceId === deviceId);

/** A veto by an active device of the same member (the caller checks the producer). */
export function vetoRequest(s: RoomState, kind: PendingRequest["kind"], memberId: string, ref: string, seq: number, fail: Fail): void {
  const p = s.pending[ref];
  if (!p || p.kind !== kind || p.memberId !== memberId) fail("not_pending", `ref is not a ${kind} request of this member`);
  if (p.status !== "pending") fail("not_pending", `the request is ${p.status}`);
  p.status = "vetoed";
  s.conflicts[memberId] = seq;
  s.auth.versions[versionKey.conflict(memberId)] = seq;
}

export function resolveConflict(s: RoomState, memberId: string, ver: number, seq: number, fail: Fail): void {
  if (s.conflicts[memberId] === undefined) fail("no_conflict", "the member has no open device conflict");
  const current = s.auth.versions[versionKey.conflict(memberId)] ?? -1;
  if (ver !== current) fail("stale_version", `conflict: ver ${ver}, current ${current}`);
  delete s.conflicts[memberId];
  s.auth.versions[versionKey.conflict(memberId)] = seq;
}

/**
 * Every rule an approval must meet (room-log-v2.md section 5). Returns the request, still pending;
 * the caller applies the change and then marks it approved.
 */
export function checkApproval(
  s: RoomState,
  kind: PendingRequest["kind"],
  d: { memberId: string; deviceId: string; ref: string; mode: "auto" | "admin" },
  hts: number,
  fail: Fail,
): PendingRequest {
  const p = s.pending[d.ref];
  if (!p || p.kind !== kind || p.memberId !== d.memberId || p.deviceId !== d.deviceId) fail("not_pending", `ref is not a ${kind} request for this device`);
  if (p.status === "cancelled") fail("request_cancelled", "the request was cancelled");
  if (p.status === "vetoed") fail("vetoed", "the request was vetoed");
  if (p.status !== "pending") fail("not_pending", "the request was already approved");
  if (d.mode === "auto") {
    const policy = s.auth.policy;
    if (policy.deviceAddApproval === "admin") fail("auto_not_allowed", 'policy deviceAddApproval is "admin"');
    if (p.sole && policy.soleDeviceChange === "admin") fail("auto_not_allowed", 'sole-device request under policy soleDeviceChange "admin"');
    if (s.conflicts[d.memberId] !== undefined) fail("conflict_open", "the member has an open device conflict");
    if (p.young) fail("requester_too_young", "the requesting device was active for less than 24 h");
    if (hts - p.hts < holdMs(p)) fail("hold_not_elapsed", `less than ${holdMs(p) / HOUR_MS} h since the request`);
  }
  return p;
}
