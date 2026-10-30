// The room recovery key R and the rotation and recovery procedures that need more than one signed
// statement (keys-rotation-recovery.md sections 4.3, 4.4, 6.6 and 6.8; room-log-v2.md sections 5.1
// and 5.2; implementation plan I-12).
//
// - R is never online for routine work and is never stored by a daemon: `RecoveryKey.fromCode` derives
//   it from the typed recovery code for one action and `dispose` drops it. It signs only the four
//   statements of 4.4: `admin.key.revoked`, `admin.added`, `recovery.key.rotated` and `room.closed`.
// - Installing a first recovery key (4.4; room-log-v2 5.2): one admin lineage installs alone with
//   `recovery.key.rotated {proposal: null}`; two or more lineages need `recovery.key.proposed` by one
//   admin and the byte-identical change confirmed by an admin of another lineage. The confirmer copies
//   `newKeySig` from the proposal (Ed25519 is deterministic, so it is the same signature).
// - Stolen admin key with R (6.6 steps 1 and 4; decision round 8, R8-5a): R revokes the stolen key from
//   `fromSeq`; when that leaves no active admin key (or retires this daemon's own key), R adds a fresh
//   admin key, which starts its own lineage. Retired keys never return: the fresh key is new.
// - Closure (6.8): `closeConfirmationBlocker` is the confirming daemon's own check before it signs
//   `room.closed {proposal}`. It applies the rules of room-log-v2 5.2 on the daemon's clock, measured
//   from the later of the proposal's `hts` and when this daemon first saw it, so a host that
//   back-dates the proposal cannot shorten the delay.
// Nothing here logs key material or recovery codes.
import { randomBytes, type KeyObject } from "node:crypto";
import { encodeRecoveryCode, recoverySeedForKey } from "./genesis";
import { independent } from "../authority/lineage";
import { activeAdmins, type RoomState } from "../authority/state";
import type { KeyChange, SignedStatement, StatementBody, StatementData, StatementType } from "../authority/statements";
import { b64u } from "../proto/b64u";
import { CTX_KEY_CHANGE_NEW, stmtContext } from "../proto/contexts";
import { ed25519PrivateKeyFromSeed, kid as kidOf, rawPublicKey } from "../proto/keys";
import { rjcs } from "../proto/rjcs";
import { sign } from "../proto/tbs";

/** The statement types R may sign (keys 4.4). */
export const RECOVERY_TYPES = ["admin.key.revoked", "admin.added", "recovery.key.rotated", "room.closed"] as const;
export type RecoveryType = (typeof RECOVERY_TYPES)[number];

export class RecoveryError extends Error {
  constructor(
    readonly code: "no_recovery_key" | "not_recovery_statement" | "close_blocked" | "not_needed",
    message: string,
  ) {
    super(message);
    this.name = "RecoveryError";
  }
}

/** A fresh Ed25519 key and the KeyChange + `newKeySig` that certifies it for a subject. */
export function freshKeyChange(roomId: string, subject: KeyChange["subject"], old: string | null): { change: KeyChange; newKeySig: string; seed: Buffer; kid: string } {
  const seed = randomBytes(32);
  const key = ed25519PrivateKeyFromSeed(seed);
  const pub = rawPublicKey(key);
  const change: KeyChange = { v: 2, typ: "key-change", roomId, subject, old, newSig: b64u(pub), newDh: null };
  return { change, newKeySig: b64u(sign(key, CTX_KEY_CHANGE_NEW, rjcs(change))), seed, kid: kidOf("ed25519", pub) };
}

/** R, derived from the recovery code for one action. */
export class RecoveryKey {
  readonly kid: string;
  #key: KeyObject | null;

  private constructor(
    key: KeyObject,
    readonly roomId: string,
    private readonly now: () => number,
  ) {
    this.#key = key;
    this.kid = kidOf("ed25519", rawPublicKey(key));
  }

  /** Throws RecoveryCodeError (typo, wrong_key, ...) or RecoveryError("no_recovery_key"). */
  static fromCode(code: string, st: Readonly<RoomState>, now: () => number = Date.now): RecoveryKey {
    const r = st.auth.recovery;
    if (!r) throw new RecoveryError("no_recovery_key", "This room has no recovery key");
    const seed = recoverySeedForKey(code, r.kid);
    try {
      return new RecoveryKey(ed25519PrivateKeyFromSeed(seed), st.roomId, now);
    } finally {
      seed.fill(0);
    }
  }

  sign<T extends RecoveryType>(type: T, data: StatementData<T>, base: { seq: number; hash: string }): SignedStatement {
    if (!(RECOVERY_TYPES as readonly string[]).includes(type)) throw new RecoveryError("not_recovery_statement", `the recovery key does not sign ${type}`);
    if (!this.#key) throw new Error("recovery key disposed");
    const body: StatementBody = { v: 2, typ: "stmt", type: type as StatementType, roomId: this.roomId, producer: { kind: "recovery", kid: this.kid }, base: { seq: base.seq, hash: base.hash }, ts: this.now(), data: data as StatementBody["data"] };
    return { body, sig: b64u(sign(this.#key, stmtContext(type), rjcs(body))) };
  }

  /** `recovery.key.rotated` by R itself (4.4): a new code, shown once. */
  rotate(base: { seq: number; hash: string }): { statement: SignedStatement; code: string; kid: string } {
    const f = freshKeyChange(this.roomId, { kind: "recovery", id: "recovery" }, this.kid);
    try {
      return { statement: this.sign("recovery.key.rotated", { change: f.change, newKeySig: f.newKeySig, proposal: null }, base), code: encodeRecoveryCode(f.seed), kid: f.kid };
    } finally {
      f.seed.fill(0);
    }
  }

  dispose(): void {
    this.#key = null;
  }
}

/** A first recovery key (4.4): the change to sign, `newKeySig`, and the code (shown once). */
export function newRecoveryKey(roomId: string): { change: KeyChange; newKeySig: string; code: string; kid: string } {
  const f = freshKeyChange(roomId, { kind: "recovery", id: "recovery" }, null);
  try {
    return { change: f.change, newKeySig: f.newKeySig, code: encodeRecoveryCode(f.seed), kid: f.kid };
  } finally {
    f.seed.fill(0);
  }
}

/**
 * Steps of the stolen-admin-key procedure with R (6.6 step 4; R8-5a), in order: R revokes `stolenKid`
 * from `fromSeq`; then, when no admin key would be active or `ownKid` is no longer active after the
 * revocation's re-fold, R adds a fresh admin key for `freshFor` (a new lineage). `submit` sequences a
 * statement and returns the state after it (it throws when refused). Returns the fresh key's seed for
 * the caller to seal as this daemon's admin key, or null when none was needed.
 */
export async function recoverFromStolenAdmin(i: {
  r: RecoveryKey;
  state: () => Readonly<RoomState>;
  head: () => { seq: number; hash: string };
  submit: (s: SignedStatement) => Promise<void> | void;
  stolenKid: string;
  fromSeq: number;
  ownKid: string | null;
  freshFor: string;
}): Promise<{ revokedAt: { seq: number }; fresh: { kid: string; seed: Buffer } | null }> {
  await i.submit(i.r.sign("admin.key.revoked", { kid: i.stolenKid, fromSeq: i.fromSeq }, i.head()));
  const revokedAt = { seq: i.head().seq };
  const st = i.state();
  const active = activeAdmins(st.auth);
  const ownActive = i.ownKid !== null && active.some((a) => a.kid === i.ownKid);
  if (active.length > 0 && ownActive) return { revokedAt, fresh: null };
  const f = freshKeyChange(st.roomId, { kind: "admin", id: i.freshFor }, null);
  try {
    await i.submit(i.r.sign("admin.added", { change: f.change, newKeySig: f.newKeySig }, i.head()));
  } catch (e) {
    f.seed.fill(0);
    throw e;
  }
  return { revokedAt, fresh: { kid: f.kid, seed: f.seed } };
}

/**
 * The confirming daemon's check before it signs `room.closed {proposal}` (6.8; room-log-v2 5.2), on
 * its own clock. `firstSeen` is when this daemon first saw the proposal (ms), if recorded. Null when
 * it may sign now.
 */
export function closeConfirmationBlocker(
  st: Readonly<RoomState>,
  proposal: string,
  confirmerKid: string,
  now: number,
  firstSeen?: number,
): { reason: "unknown_proposal" | "proposal_expired" | "proposer_inactive" | "confirmer_not_independent" | "confirmer_after_proposal" | "close_too_early"; message: string; earliest?: number } | null {
  const a = st.auth;
  const p = a.pendingClose[proposal];
  if (!p || p.used) return { reason: "unknown_proposal", message: "No open room.close.proposed with that reference" };
  if (now > p.exp * 1000) return { reason: "proposal_expired", message: "The proposal has expired" };
  const active = activeAdmins(a);
  const proposer = active.find((x) => x.kid === p.kid);
  if (!proposer) return { reason: "proposer_inactive", message: "The proposing key is no longer active; the proposal is void" };
  const confirmer = active.find((x) => x.kid === confirmerKid);
  if (!confirmer || !independent(proposer, confirmer)) return { reason: "confirmer_not_independent", message: "Only an admin of another lineage may confirm a closure" };
  if (!(confirmer.fromSeq <= p.seq)) return { reason: "confirmer_after_proposal", message: "This admin key was not active when the closure was proposed" };
  const delayMs = Math.max(p.closeDelay, a.policy.closeDelay) * 1000;
  const earliest = Math.max(p.hts, firstSeen ?? p.hts) + delayMs;
  if (now < earliest) return { reason: "close_too_early", message: `The closure can be confirmed from ${new Date(earliest).toISOString()}`, earliest };
  return null;
}
