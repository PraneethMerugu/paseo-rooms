// Revocations and the re-fold (room-log-v2.md section 5.1; keys-rotation-recovery.md sections 3,
// 6.4, 6.6).
//
// admin.key.revoked {kid, fromSeq} at position r:
//   bounds: fromSeq <= r; fromSeq >= the position where kid became valid; fromSeq >= the
//           authority start of the revoking key (admin key or R)
//   state  = fold of chain[0..r) in which every statement signed by kid at a position >= fromSeq
//            is suspect (no effect) and every statement that no longer applies is void
//   from r on kid is invalid, on the admin-key denylist and retired
// Several revocations compose: each one adds its pair to the imposed set of the replay, and a
// revocation inside the replayed range is itself re-applied (or becomes suspect or void).
//
// host.key.revoked {kid, fromSeq} at r marks entries signed by kid in [fromSeq, r) suspect for
// ordering; the roster is not recomputed.
import { b64uDecode } from "../proto/b64u";
import type { LogEntry } from "./entries";
import {
  activeAdmins,
  FoldError,
  keysInUse,
  type Fail,
  type HostKeyState,
  type RoomState,
} from "./state";
import type { StatementBody, StatementData } from "./statements";

/** One accepted statement entry, kept so the fold can be recomputed. */
export type Rec = { entry: LogEntry; stmt: StatementBody };
export type Imposed = readonly { kid: string; fromSeq: number }[];
/** Re-applies one statement during a replay; throws FoldError when it no longer applies. */
export type Step = (s: RoomState, rec: Rec, imposed: Imposed) => RoomState;

export function isSuspect(imposed: Imposed, kid: string, seq: number): boolean {
  return imposed.some((r) => r.kid === kid && seq >= r.fromSeq);
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
  if (target.end === "revoked") fail("already_revoked", "admin key is already revoked");
  checkBounds(s, target, d, producer, seq, fail);
}

/**
 * Recomputes the state of `chain[0..r)` from `initial` with the imposed revocations. Suspect and
 * void statements are marked and skipped; nothing here stops the fold.
 */
export function replay(initial: RoomState, records: readonly Rec[], r: number, imposed: Imposed, step: Step): RoomState {
  let s = structuredClone(initial);
  for (const rec of records) {
    const seq = rec.entry.seq;
    if (seq >= r) break;
    if (isSuspect(imposed, rec.stmt.producer.kid, seq)) {
      s.marks[seq] = "suspect";
      s.epoch = rec.entry.epoch;
      continue;
    }
    try {
      s = step(s, rec, imposed);
    } catch (err) {
      if (!(err instanceof FoldError)) throw err;
      s.marks[seq] = "void";
      s.epoch = rec.entry.epoch;
    }
  }
  return s;
}

/**
 * Completes an admin-key revocation on the recomputed state `re` (the state `before` is the one
 * the revocation was sequenced against). Ids and keys never return: every id used before stays
 * used, and every key that was retired or denylisted before, or leaves use through the re-fold,
 * is retired (device keys also denylisted), unless the re-fold puts it back in use (a device a
 * suspect statement removed) or it is a new key of a request that is pending again
 * (keys-rotation-recovery.md 6.6 step 5). Admin keys that the re-fold drops are denylisted.
 */
export function finishAdminRevocation(before: RoomState, re: RoomState, d: StatementData<"admin.key.revoked">, seq: number, fail: Fail): RoomState {
  for (const k of ["members", "devices", "lanes", "invites", "linksConsumed"] as const) Object.assign(re.used[k], before.used[k]);
  Object.assign(re.used.links, before.used.links);

  const stillUsed = keysInUse(re);
  const pendingKeys = new Set<string>();
  for (const p of Object.values(re.pending)) if (p.status === "pending") pendingKeys.add(p.device.sig).add(p.device.dh);
  // A key retired or denylisted only by a suspect or void statement is back in use; every other one stays out.
  const keep = (key: string) => !stillUsed.has(key) && !pendingKeys.has(key);
  for (const key of Object.keys(before.deviceDenylist)) if (keep(key)) re.deviceDenylist[key] = true;
  for (const key of Object.keys(before.auth.retiredKeys)) if (keep(key)) re.auth.retiredKeys[key] = true;
  for (const m of Object.values(before.members)) for (const dev of m.devices) for (const key of [dev.sig, dev.dh]) if (keep(key)) re.deviceDenylist[key] = true;
  for (const key of keysInUse(before)) if (keep(key)) re.auth.retiredKeys[key] = true;
  for (const a of before.auth.admins) if (!re.auth.admins.some((x) => x.kid === a.kid)) re.auth.adminKeyDenylist[a.kid] = true;

  const target = re.auth.admins.find((a) => a.kid === d.kid);
  if (target) {
    target.toSeq = target.toSeq === null ? seq : Math.min(target.toSeq, seq);
    target.suspectFromSeq = d.fromSeq;
    target.end = "revoked";
    re.auth.retiredKeys[target.pub] = true;
  }
  re.auth.adminKeyDenylist[d.kid] = true;
  re.auth.revocations.push({ kid: d.kid, fromSeq: d.fromSeq, seq });
  if (activeAdmins(re.auth).length === 0) fail("last_admin", "the revocation would leave no active admin key; add one first");
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
