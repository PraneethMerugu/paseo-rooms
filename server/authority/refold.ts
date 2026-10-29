// Revocations and the re-fold (room-log-v2.md section 5.1; keys-rotation-recovery.md sections 3,
// 6.4, 6.6; decision round 8, items 3 and 4).
//
// admin.key.revoked {kid, fromSeq} at position r:
//   bounds: fromSeq <= r; fromSeq >= the position where kid became valid; fromSeq >= the
//           authority start of the revoking key (admin key or R)
//   depth:  1 + the largest depth of the revocation entries at positions in [fromSeq, r); at most 8
//           (checked by the fold before the re-fold, from positions only)
//   state  = fold of chain[0..r) in which every statement signed by a revoked kid at a position
//            >= its fromSeq is suspect (no effect) and every statement that no longer applies is void
//   from r on kid is invalid, on the admin-key denylist and retired
//
// The re-fold is a fixed point over flat passes, never a recursion (round 8, item 4):
//   E := pairs of the revocations in effect before r, plus the new pair
//   repeat (at most MAX_REFOLD_PASSES times):
//       pass  = one fold of chain[0..r) from genesis with every pair of E imposed from the start;
//               an earlier revocation entry is classified (suspect, void or in effect) and, if in
//               effect, only marks its target revoked; it never starts a replay of its own
//       E'    := the new pair plus the pairs the pass found in effect
//       if E' == E: the pass is the result; else E := E'
// Each pass costs one step per statement, so a re-fold costs at most MAX_REFOLD_PASSES * r steps:
// linear in the chain, independent of how revocations nest.
//
// After the passes, keys and ids never return (round 8, item 3): every id and key retired before r
// stays so, a device whose recomputed keys are retired leaves the roster, a request whose new keys
// are retired is cancelled, and host keys, the room endpoint and lane offers keep the keys they had
// before r (marked uncertified when the statement that installed them is now suspect or void).
//
// host.key.revoked {kid, fromSeq} at r marks entries signed by kid in [fromSeq, r) suspect for
// ordering; the roster is not recomputed.
import { b64uDecode } from "../proto/b64u";
import type { LogEntry } from "./entries";
import { cancelRequests, byOrForDevice } from "./holds";
import {
  activeAdmins,
  FoldError,
  keysInUse,
  versionKey,
  type Fail,
  type HostKeyState,
  type Revocation,
  type RoomState,
} from "./state";
import type { StatementBody, StatementData } from "./statements";

/** One accepted statement entry, kept so the fold can be recomputed. */
export type Rec = { entry: LogEntry; stmt: StatementBody };
export type Imposed = readonly { kid: string; fromSeq: number }[];
/** Re-applies one statement inside a pass; throws FoldError when it no longer applies. */
export type Step = (s: RoomState, rec: Rec) => RoomState;

/** Nesting depth cap for `admin.key.revoked` (round 8, item 4). */
export const MAX_REVOCATION_DEPTH = 8;
/** Passes a re-fold may take before it is rejected as too deep. */
export const MAX_REFOLD_PASSES = MAX_REVOCATION_DEPTH + 1;

/** Work counters for tests of the linear bound. Not used for any decision. */
export const refoldCounters = { passes: 0, steps: 0 };

export function isSuspect(imposed: Imposed, kid: string, seq: number): boolean {
  return imposed.some((r) => r.kid === kid && seq >= r.fromSeq);
}

/**
 * Nesting depth of a revocation at `seq` with `fromSeq` (room-log-v2.md section 5.1, step 8):
 * 1 plus the largest depth among earlier revocation entries at positions in `[fromSeq, seq)`.
 * Every revocation entry counts, whether it is in effect, suspect or void.
 */
export function revocationDepth(earlier: readonly { seq: number; depth: number }[], fromSeq: number, seq: number): number {
  let max = 0;
  for (const e of earlier) if (e.seq >= fromSeq && e.seq < seq && e.depth > max) max = e.depth;
  return max + 1;
}

/** Authority start of the revoking key (section 5.1 step 1). */
function authorityStart(s: RoomState, producer: { kind: string; kid: string }): number | null {
  if (producer.kind === "recovery") return s.auth.recovery && s.auth.recovery.kid === producer.kid ? s.auth.recovery.since : null;
  return s.auth.admins.find((a) => a.kid === producer.kid)?.since ?? null;
}

function checkBounds(
  s: RoomState,
  target: { fromSeq: number },
  d: { fromSeq: number },
  producer: { kind: string; kid: string },
  seq: number,
  fail: Fail,
): void {
  if (!(d.fromSeq <= seq) || d.fromSeq < target.fromSeq) fail("revocation_out_of_bounds", "fromSeq must lie between the key's first valid position and the revocation");
  const start = authorityStart(s, producer) ?? fail("unknown_producer", "revoking key has no authority start");
  if (d.fromSeq < start) fail("revocation_before_since", `fromSeq ${d.fromSeq} is before the revoking key's authority start ${start}`);
}

export function checkAdminRevocation(s: RoomState, d: StatementData<"admin.key.revoked">, producer: { kind: string; kid: string }, seq: number, fail: Fail): void {
  // R can never be revoked by an admin key: the target is always an admin key.
  const target = s.auth.admins.find((a) => a.kid === d.kid) ?? fail("unknown_key", "kid is not an admin key of this room");
  if (producer.kind === "admin" && producer.kid === d.kid) fail("not_permitted", "an admin key is revoked by another admin key or by R");
  // Once per key: a revocation in effect names it already. A key whose revocation a re-fold made
  // suspect or void stays retired (round 8, item 3) but may be revoked again, once.
  if (s.auth.revocations.some((r) => r.kid === d.kid)) fail("already_revoked", "admin key is already revoked");
  checkBounds(s, target, d, producer, seq, fail);
}

/**
 * One pass: the state of `chain[0..r)` from `initial` with every pair of `imposed` applied from the
 * start. Suspect and void statements are marked and skipped; nothing here stops the fold.
 */
export function pass(initial: RoomState, records: readonly Rec[], r: number, imposed: Imposed, step: Step): RoomState {
  refoldCounters.passes++;
  let s = structuredClone(initial);
  for (const rec of records) {
    const seq = rec.entry.seq;
    if (seq >= r) break;
    refoldCounters.steps++;
    if (isSuspect(imposed, rec.stmt.producer.kid, seq)) {
      s.marks[seq] = "suspect";
      s.epoch = rec.entry.epoch;
      continue;
    }
    try {
      s = step(s, rec);
    } catch (err) {
      if (!(err instanceof FoldError)) throw err;
      s.marks[seq] = "void";
      s.epoch = rec.entry.epoch;
    }
  }
  return s;
}

const pairKey = (p: Revocation) => `${p.seq}`;
function sameSet(a: readonly Revocation[], b: readonly Revocation[]): boolean {
  if (a.length !== b.length) return false;
  const keys = new Set(a.map(pairKey));
  return b.every((p) => keys.has(pairKey(p)));
}

/**
 * The fixed point of section 5.1 step 3 for a new revocation at `r`. `inEffect` are the revocations
 * in effect before `r`. Returns the state of the last pass, whose `auth.revocations` holds the
 * earlier revocations still in effect (without the new one).
 */
export function refold(initial: RoomState, records: readonly Rec[], r: number, inEffect: readonly Revocation[], added: Revocation, step: Step, fail: Fail): RoomState {
  let set: Revocation[] = [...inEffect, added];
  for (let n = 0; n < MAX_REFOLD_PASSES; n++) {
    const state = pass(initial, records, r, set, step);
    const next = [...state.auth.revocations, added];
    if (sameSet(set, next)) return state;
    set = next;
  }
  return fail("revocation_too_deep", `the re-fold did not settle within ${MAX_REFOLD_PASSES} passes`);
}

/**
 * The part of a revocation that does not replay: the target's window ends at `seq`, its statements
 * from `fromSeq` on are suspect, and the key is denylisted and retired. Used for the new revocation
 * and for earlier ones that a pass finds in effect.
 */
export function markRevoked(s: RoomState, d: StatementData<"admin.key.revoked">, seq: number): void {
  const target = s.auth.admins.find((a) => a.kid === d.kid);
  if (target) {
    target.toSeq = target.toSeq === null ? seq : Math.min(target.toSeq, seq);
    target.suspectFromSeq = d.fromSeq;
    target.end = "revoked";
    s.auth.retiredKeys[target.pub] = true;
  }
  s.auth.adminKeyDenylist[d.kid] = true;
  s.auth.revocations.push({ kid: d.kid, fromSeq: d.fromSeq, seq });
}

/**
 * Only R may leave the room without an active admin key (round 8, item 3: keys never return, so R
 * may have to revoke a thief who revoked every honest key, and then add a fresh one).
 */
export function checkLastAdmin(s: RoomState, producerKind: string, fail: Fail): void {
  if (activeAdmins(s.auth).length === 0 && producerKind !== "recovery") fail("last_admin", "an admin key may not leave the room without an active admin key");
}

/**
 * Completes an admin-key revocation on the recomputed state `re` (`before` is the state the
 * revocation was sequenced against). Nothing that left use before `r` returns (round 8, item 3).
 */
export function finishAdminRevocation(before: RoomState, re: RoomState, d: StatementData<"admin.key.revoked">, seq: number, producerKind: string, fail: Fail): RoomState {
  // Ids never return.
  for (const k of ["members", "devices", "lanes", "invites", "linksConsumed"] as const) Object.assign(re.used[k], before.used[k]);
  Object.assign(re.used.links, before.used.links);

  // Retired keys and denylists only grow.
  Object.assign(re.auth.retiredKeys, before.auth.retiredKeys);
  Object.assign(re.deviceDenylist, before.deviceDenylist);
  Object.assign(re.auth.adminKeyDenylist, before.auth.adminKeyDenylist);
  for (const a of re.auth.admins) {
    const b = before.auth.admins.find((x) => x.kid === a.kid);
    if (b && b.toSeq !== null && a.toSeq === null) Object.assign(a, { toSeq: b.toSeq, end: b.end, suspectFromSeq: b.suspectFromSeq });
  }
  for (const a of before.auth.admins) if (!re.auth.admins.some((x) => x.kid === a.kid)) re.auth.adminKeyDenylist[a.kid] = true;

  // Host keys are positional: the table of `before` stays, so no retired host key signs again and
  // the current key can carry the fix. A key whose installing statement did not apply is uncertified.
  const certified = new Map(re.auth.hostKeys.map((h) => [h.kid, h]));
  re.auth.hostKeys = before.auth.hostKeys.map((h): HostKeyState => {
    const p = certified.get(h.kid);
    const revoked = h.revoked || (p?.revoked ?? false);
    return { ...structuredClone(h), revoked, suspectFromSeq: h.suspectFromSeq ?? p?.suspectFromSeq ?? null, uncertified: p === undefined };
  });

  // The room endpoint and lane offers keep the keys they had; a recomputed key differs only when it
  // was rotated out by a statement that is now suspect or void, and such a key is retired.
  if (re.auth.endpoint.dh.pub !== before.auth.endpoint.dh.pub) {
    re.auth.endpoint = structuredClone(before.auth.endpoint);
    re.auth.endpointUncertified = true;
  } else re.auth.endpointUncertified = false;
  for (const [laneId, l] of Object.entries(re.auth.lanes)) {
    const b = before.auth.lanes[laneId];
    if (!b) {
      // Created by a statement that was void before and applies again: its key left use then.
      if (re.auth.retiredKeys[l.offer.dh.pub]) l.status = "closed";
      continue;
    }
    l.uncertified = l.offer.dh.pub !== b.offer.dh.pub;
    if (l.uncertified) l.offer = structuredClone(b.offer);
    if (b.status === "closed") l.status = "closed";
  }
  if (re.auth.recovery && re.auth.retiredKeys[re.auth.recovery.pub]) re.auth.recovery = null;

  // Keys that leave use through the re-fold are retired (device keys also denylisted).
  const stillUsed = keysInUse(re);
  for (const key of keysInUse(before)) if (!stillUsed.has(key)) re.auth.retiredKeys[key] = true;
  for (const m of Object.values(before.members)) for (const dev of m.devices) for (const key of [dev.sig, dev.dh]) if (!stillUsed.has(key)) re.deviceDenylist[key] = true;

  // A device whose recomputed keys are retired does not come back; nor does a request for retired keys.
  const out = (key: string) => re.auth.retiredKeys[key] === true || re.deviceDenylist[key] === true;
  for (const m of Object.values(re.members)) {
    for (const dev of m.devices.filter((x) => out(x.sig) || out(x.dh))) {
      cancelRequests(re, byOrForDevice(dev.deviceId));
      for (const rp of Object.values(re.repairs)) if (rp.deviceId === dev.deviceId) rp.status = "cancelled";
      delete re.deviceSince[dev.deviceId];
      re.deviceDenylist[dev.sig] = true;
      re.deviceDenylist[dev.dh] = true;
    }
    const kept = m.devices.filter((x) => !(out(x.sig) || out(x.dh)));
    // Dropping a device changes the member's device set at this entry (section 4.0).
    if (kept.length !== m.devices.length) re.auth.versions[versionKey.devices(m.memberId)] = seq;
    m.devices = kept;
  }
  cancelRequests(re, (p) => out(p.device.sig) || out(p.device.dh));

  markRevoked(re, d, seq);
  checkLastAdmin(re, producerKind, fail);
  return re;
}

/** `host.key.revoked` (section 5.1, last paragraph). Mutates `s`. */
export function revokeHostKey(s: RoomState, d: StatementData<"host.key.revoked">, producer: { kind: string; kid: string }, seq: number, fail: Fail): void {
  const k: HostKeyState = s.auth.hostKeys.find((h) => h.kid === d.kid) ?? fail("unknown_key", "kid is not a host key of this room");
  if (k.revoked) fail("already_revoked", "host key is already revoked");
  // Revoking the current key would leave no key to sign the next entry: rotate first.
  if (k.toSeq === null) fail("host_key_current", "rotate the host key (host.key.rotated) before revoking it");
  checkBounds(s, k, d, producer, seq, fail);
  k.revoked = true;
  k.suspectFromSeq = d.fromSeq;
  s.auth.retiredKeys[k.pub] = true;
}

/** Raw host key that may sign the entry at `seq`, by position only (S-15). */
export function hostKeyAt(s: RoomState, hostKid: string, seq: number): Uint8Array | null {
  const k = s.auth.hostKeys.find((h) => h.kid === hostKid && h.fromSeq <= seq && (h.toSeq === null || seq <= h.toSeq));
  return k ? b64uDecode(k.pub, 32) : null;
}
