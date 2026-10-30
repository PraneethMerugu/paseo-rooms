// MLS authentication service (mls-integration.md section 4.1; decisions rounds 6 and 7).
//
// A closure over the reference roster. The adapter's caller sets the roster before each processMessage,
// joinGroup or createCommit and clears it after; with no roster set every credential is refused (fail
// closed). Rules 1 to 8 of section 4.1 apply to every credential the library passes, during commit
// processing, commit creation and Welcome processing alike. Rule 6 has no exception for a previous
// key: the round-4 `prevSig` window is removed entirely (decision round 7, item 1).
import type { RosterEntry } from "../authority/schema";
import type { RoomState } from "../authority/state";
import { buildRoster, rosterHash } from "../authority/roster";
import type { AuthServiceLike, MlsCredential } from "./adapter";
import { identitySigValid, parseMlsIdentity, type MlsIdentity } from "./formats";

/** The roster a message names (section 4.2), with what the rules need from the fold at that position. */
export type ReferenceRoster = {
  roomId: string;
  seq: number;
  hash: string;
  members: Readonly<Record<string, RosterEntry>>;
  /** Device signing and DH keys that left use (rule 8). */
  denylist: Readonly<Record<string, true>>;
  /** Team subgroup: the scope and its member list (rule 7); null for the room group. */
  scope: { scopeId: string; memberIds: readonly string[] } | null;
};

/** The reference roster of a fold state (the roster at `state.rosterSeq`). */
export function referenceRosterOf(state: Readonly<RoomState>, scopeId: string | null = null): ReferenceRoster {
  const roster = buildRoster(state.roomId, state.rosterSeq, state.members as Record<string, RosterEntry>);
  return {
    roomId: state.roomId,
    seq: state.rosterSeq,
    hash: rosterHash(roster),
    members: state.members,
    denylist: state.deviceDenylist,
    scope: scopeId === null ? null : { scopeId, memberIds: state.auth.scopes[scopeId] ?? [] },
  };
}

export type CredentialVerdict = { ok: true; id: MlsIdentity } | { ok: false; reason: CredentialRefusal };
export type CredentialRefusal =
  | "no_reference_roster"
  | "not_basic"
  | "bad_identity"
  | "wrong_room"
  | "mls_sig_mismatch"
  | "bad_identity_sig"
  | "not_in_roster"
  | "not_roster_key"
  | "not_in_scope"
  | "denylisted";

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Rules 1 to 8 of section 4.1 for one credential and the leaf's signature key. */
export function checkCredential(ref: ReferenceRoster | null, credential: { credentialType: string; identity?: Uint8Array }, signaturePublicKey: Uint8Array): CredentialVerdict {
  if (!ref) return { ok: false, reason: "no_reference_roster" };
  if (credential.credentialType !== "basic" || !credential.identity) return { ok: false, reason: "not_basic" };
  const p = parseMlsIdentity(credential.identity);
  if (!p) return { ok: false, reason: "bad_identity" };
  const id = p.id;
  if (id.roomId !== ref.roomId) return { ok: false, reason: "wrong_room" };
  if (!eq(Buffer.from(id.mlsSig, "base64url"), signaturePublicKey)) return { ok: false, reason: "mls_sig_mismatch" };
  if (!identitySigValid(p)) return { ok: false, reason: "bad_identity_sig" };
  const dev = ref.members[id.memberId]?.devices.find((d) => d.deviceId === id.deviceId);
  if (!dev) return { ok: false, reason: "not_in_roster" };
  if (dev.sig !== id.deviceSig) return { ok: false, reason: "not_roster_key" };
  if (ref.scope && !ref.scope.memberIds.includes(id.memberId)) return { ok: false, reason: "not_in_scope" };
  if (ref.denylist[id.deviceSig]) return { ok: false, reason: "denylisted" };
  return { ok: true, id };
}

/**
 * The closure handed to ts-mls as `authService`. `refusals` keeps the last refusals (reason and
 * member/device ids only) for diagnostics and tests; it never holds key material.
 */
export class MlsAuthService implements AuthServiceLike {
  private ref: ReferenceRoster | null = null;
  readonly refusals: { reason: CredentialRefusal; memberId?: string; deviceId?: string }[] = [];

  set(ref: ReferenceRoster): void {
    this.ref = ref;
  }

  clear(): void {
    this.ref = null;
  }

  get current(): ReferenceRoster | null {
    return this.ref;
  }

  /** Runs `f` with `ref` as the reference roster, and clears it afterwards whatever happens. */
  async with<T>(ref: ReferenceRoster, f: () => Promise<T>): Promise<T> {
    this.set(ref);
    try {
      return await f();
    } finally {
      this.clear();
    }
  }

  async validateCredential(credential: MlsCredential, signaturePublicKey: Uint8Array): Promise<boolean> {
    const v = checkCredential(this.ref, credential as { credentialType: string; identity?: Uint8Array }, signaturePublicKey);
    if (!v.ok) {
      const p = credential.credentialType === "basic" ? parseMlsIdentity(credential.identity) : null;
      this.refusals.push({ reason: v.reason, ...(p ? { memberId: p.id.memberId, deviceId: p.id.deviceId } : {}) });
      if (this.refusals.length > 32) this.refusals.shift();
    }
    return v.ok;
  }
}
