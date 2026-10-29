// Admin lineages, room closure and the first recovery key (room-log-v2.md section 5.2;
// keys-rotation-recovery.md sections 4.3, 4.4, 6.8; decision rounds 3 to 5).
//
//   root(genesis key) = itself; root(key added by R) = itself;
//   root(key added by admin key K) = root(K); root(key installed by rotation of K) = root(K).
//   Two keys are independent when their roots differ. A room has as many lineages as there are
//   distinct roots among its active admin keys.
import { rjcsText } from "../proto/rjcs";
import { activeAdmins, type AdminKeyState, type AuthorityState, type Fail, type RoomState } from "./state";
import type { KeyChange } from "./statements";

const DAY_MS = 24 * 60 * 60 * 1000;
/** `room.close.proposed` and `recovery.key.proposed`: `exp` at most 7 days ahead. */
export const PROPOSAL_MAX_MS = 7 * DAY_MS;

export function lineageCount(auth: AuthorityState): number {
  return new Set(activeAdmins(auth).map((a) => a.root)).size;
}

export function independent(a: AdminKeyState, b: AdminKeyState): boolean {
  return a.root !== b.root;
}

function activeAdmin(auth: AuthorityState, kid: string): AdminKeyState | undefined {
  return activeAdmins(auth).find((a) => a.kid === kid);
}

/** `exp` (unix s) lies after `earliestMs` and at most 7 days after the entry. */
function checkExp(exp: number, hts: number, earliestMs: number, fail: Fail): void {
  if (!(exp * 1000 > earliestMs) || exp * 1000 > hts + PROPOSAL_MAX_MS) fail("bad_exp", "exp must be later than the earliest confirmation and at most 7 days ahead");
}

// ---- closure ----

export function proposeClose(s: RoomState, at: { kid: string; seq: number; hts: number; bodyHash: string }, exp: number, fail: Fail): void {
  const closeDelay = s.auth.policy.closeDelay;
  checkExp(exp, at.hts, at.hts + closeDelay * 1000, fail);
  s.auth.pendingClose[at.bodyHash] = { kid: at.kid, seq: at.seq, hts: at.hts, exp, closeDelay, used: false };
}

/**
 * `room.closed {proposal}` by admin key `confirmerKid` at `seq` (rules 1 to 4 of section 5.2).
 * Marks the proposal used; the caller sets `closed`.
 */
export function confirmClose(s: RoomState, confirmerKid: string, proposal: string, at: { seq: number; hts: number }, fail: Fail): void {
  const a = s.auth;
  const p = a.pendingClose[proposal];
  if (!p || p.used) fail("unknown_proposal", "proposal is not an open room.close.proposed");
  if (at.hts > p.exp * 1000) fail("proposal_expired", "the proposal's exp has passed");
  const proposer = activeAdmin(a, p.kid) ?? fail("proposer_inactive", "the proposing key is no longer active, so the proposal is void");
  const confirmer = activeAdmin(a, confirmerKid) ?? fail("unknown_producer", "confirming key is not active");
  if (!independent(proposer, confirmer)) fail("confirmer_not_independent", "proposer and confirmer share a lineage root");
  if (!(confirmer.fromSeq <= p.seq)) fail("confirmer_after_proposal", "the confirming key was not valid at the proposal");
  const delayS = Math.max(p.closeDelay, a.policy.closeDelay);
  if (at.hts - p.hts < delayS * 1000) fail("close_too_early", `confirmation less than ${delayS} s after the proposal`);
  p.used = true;
}

// ---- first recovery key ----

export function proposeRecovery(s: RoomState, at: { kid: string; seq: number; hts: number; bodyHash: string }, change: KeyChange, exp: number, fail: Fail): void {
  if (s.auth.recovery) fail("recovery_exists", "recovery.key.proposed is valid only while the room has no recovery key");
  checkExp(exp, at.hts, at.hts, fail);
  s.auth.pendingRecovery[at.bodyHash] = { kid: at.kid, seq: at.seq, exp, change: rjcsText(change), used: false };
}

/**
 * Admin-signed `recovery.key.rotated` from `null`: alone in a one-lineage room, otherwise confirming
 * an independent admin's proposal with a byte-identical `change` (section 5.2).
 */
export function confirmFirstRecovery(s: RoomState, signerKid: string, change: KeyChange, proposal: string | null, hts: number, fail: Fail): void {
  const a = s.auth;
  if (lineageCount(a) <= 1) {
    if (proposal !== null) fail("proposal_not_allowed", "a room with one admin lineage installs its first recovery key with proposal null");
    return;
  }
  if (proposal === null) fail("proposal_required", "a room with two or more admin lineages needs a proposal by an independent admin");
  const p = a.pendingRecovery[proposal];
  if (!p || p.used) fail("unknown_proposal", "proposal is not an open recovery.key.proposed");
  if (hts > p.exp * 1000) fail("proposal_expired", "the proposal's exp has passed");
  const proposer = activeAdmin(a, p.kid) ?? fail("proposer_inactive", "the proposing key is no longer active");
  const signer = activeAdmin(a, signerKid) ?? fail("unknown_producer", "signing key is not active");
  if (!independent(proposer, signer)) fail("confirmer_not_independent", "proposer and confirmer share a lineage root");
  if (!(signer.fromSeq <= p.seq)) fail("confirmer_after_proposal", "the confirming key was not valid at the proposal");
  if (rjcsText(change) !== p.change) fail("proposal_mismatch", "change differs from the proposal's");
  p.used = true;
}
