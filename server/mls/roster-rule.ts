// Roster equality and who may commit what (mls-integration.md sections 4.2 and 4.3, in their round 7 and
// round 8 form). Pure: the member calls these from the IncomingMessageCallback (sender read from the
// current tree by `senderLeafIndex`) and again on the state after processing (step 4, with the
// continuity check that neither the callback nor ts-mls performs, Spike A case (b)).
//
// Leaf identity is the triple (memberId, deviceId, deviceSig) of the leaf's credential, compared with
// (memberId, deviceId, signing key) of each active device of the reference roster. With R the roster
// triples, B the leaves before and A the leaves after a commit, roster equality is:
//   1. every leaf of A has its triple in R;
//   2. no two leaves of A share (memberId, deviceId);
//   3. every leaf of B whose triple is in R still has its triple in A.
import type { LeafView, ProposalView } from "./adapter";
import type { ReferenceRoster } from "./auth-service";
import { parseMlsIdentity } from "./formats";

export type Leaf = { leafIndex: number; memberId: string; deviceId: string; deviceSig: string; identity: Uint8Array; signaturePublicKey: Uint8Array };

export type RuleRefusal =
  | "unparseable_leaf"
  | "leaf_not_in_roster"
  | "duplicate_device_leaf"
  | "roster_leaf_removed"
  | "external_commit"
  | "proposal_message"
  | "forbidden_proposal"
  | "sender_unknown"
  | "add_has_leaf"
  | "replacement_not_allowed"
  | "admin_only"
  | "authority_mismatch"
  | "reinit_not_allowed"
  | "continuity"
  | "unknown_leaf";

export type RuleResult = { ok: true } | { ok: false; reason: RuleRefusal; detail?: string };

const key = (memberId: string, deviceId: string) => `${memberId}/${deviceId}`;
const tripleKey = (l: { memberId: string; deviceId: string; deviceSig: string }) => `${l.memberId}/${l.deviceId}/${l.deviceSig}`;
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Triples of the active devices of the reference roster (only the scope's members for a subgroup). */
export function rosterTriples(ref: ReferenceRoster): Set<string> {
  const out = new Set<string>();
  for (const m of Object.values(ref.members)) {
    if (ref.scope && !ref.scope.memberIds.includes(m.memberId)) continue;
    for (const d of m.devices) out.add(tripleKey({ memberId: m.memberId, deviceId: d.deviceId, deviceSig: d.sig }));
  }
  return out;
}

/** Parses tree leaves; null when any leaf credential does not parse (it could never have been valid). */
export function parseLeaves(views: readonly LeafView[]): Leaf[] | null {
  const out: Leaf[] = [];
  for (const v of views) {
    const p = v.credentialType === "basic" ? parseMlsIdentity(v.identity) : null;
    if (!p) return null;
    out.push({ leafIndex: v.leafIndex, memberId: p.id.memberId, deviceId: p.id.deviceId, deviceSig: p.id.deviceSig, identity: v.identity, signaturePublicKey: v.signaturePublicKey });
  }
  return out;
}

/** Rules 1 to 3. */
export function rosterEquality(ref: ReferenceRoster, before: readonly Leaf[], after: readonly Leaf[]): RuleResult {
  const R = rosterTriples(ref);
  const seen = new Set<string>();
  for (const l of after) {
    if (!R.has(tripleKey(l))) return { ok: false, reason: "leaf_not_in_roster", detail: key(l.memberId, l.deviceId) };
    const k = key(l.memberId, l.deviceId);
    if (seen.has(k)) return { ok: false, reason: "duplicate_device_leaf", detail: k };
    seen.add(k);
  }
  const A = new Set(after.map(tripleKey));
  for (const l of before) {
    if (R.has(tripleKey(l)) && !A.has(tripleKey(l))) return { ok: false, reason: "roster_leaf_removed", detail: key(l.memberId, l.deviceId) };
  }
  return { ok: true };
}

/** A device's open `device.leaf.repair.requested` for this group (section 4.5). */
export type OpenRepair = { bodyHash: string; memberId: string; deviceId: string; keyPackageRef: string };

export type CommitContext = {
  ref: ReferenceRoster;
  /** Leaves of the current tree (before the commit). */
  before: readonly Leaf[];
  senderLeafIndex: number | undefined;
  proposals: readonly ProposalView[];
  /** The `0xF0A1` data the authority state at the commit's roster position gives. */
  expectedAuthority: Uint8Array;
  /** ReInit is allowed only after `admin.key.revoked` (keys-rotation-recovery.md 6.6). */
  reinitAllowed: boolean;
  /** Open, unused repair requests for this group at the commit's entry. */
  repairs: readonly OpenRepair[];
};

export type CommitVerdict = { ok: true; after: Leaf[]; repairUsed: string | null; adds: number } | { ok: false; reason: RuleRefusal; detail?: string };

/**
 * The committer column of section 4.3 plus roster equality on the computed leaf set (4.2 step 3).
 * Added leaves were validated under 4.1 by the authentication service; here their triples are read.
 */
export function checkCommit(c: CommitContext): CommitVerdict {
  if (c.senderLeafIndex === undefined) return { ok: false, reason: "external_commit" };
  const sender = c.before.find((l) => l.leafIndex === c.senderLeafIndex);
  if (!sender) return { ok: false, reason: "sender_unknown" };
  const senderMember = c.ref.members[sender.memberId];
  const senderIsAdmin = senderMember?.role === "admin" && senderMember.devices.some((d) => d.deviceId === sender.deviceId && d.sig === sender.deviceSig);

  const R = rosterTriples(c.ref);
  const removes: number[] = [];
  const adds: Leaf[] = [];
  let gce: { type: number; data: Uint8Array }[] | null = null;
  let reinit = false;
  for (const p of c.proposals) {
    if (p.type === "remove") removes.push(p.leafIndex);
    else if (p.type === "add") {
      const parsed = p.identity ? parseMlsIdentity(p.identity) : null;
      if (!parsed) return { ok: false, reason: "unparseable_leaf" };
      adds.push({ leafIndex: -1, memberId: parsed.id.memberId, deviceId: parsed.id.deviceId, deviceSig: parsed.id.deviceSig, identity: p.identity!, signaturePublicKey: p.signaturePublicKey, ...{ ref: p.ref } } as Leaf & { ref: string });
    } else if (p.type === "group_context_extensions") gce = p.extensions;
    else if (p.type === "reinit") reinit = true;
    else return { ok: false, reason: "forbidden_proposal", detail: p.name };
  }

  // GroupContextExtensions and ReInit: admin devices only (4.3).
  if (gce) {
    if (!senderIsAdmin) return { ok: false, reason: "admin_only", detail: "group_context_extensions" };
    const auth = gce.filter((e) => e.type === 0xf0a1);
    if (auth.length !== 1 || !eq(auth[0].data, c.expectedAuthority)) return { ok: false, reason: "authority_mismatch" };
  }
  if (reinit && (!senderIsAdmin || !c.reinitAllowed)) return { ok: false, reason: "reinit_not_allowed" };

  // Removes: a leaf absent from R (pending removal or old-key leaf), or a leaf replacement.
  let repairUsed: string | null = null;
  const removed = new Set<number>();
  for (const idx of removes) {
    const leaf = c.before.find((l) => l.leafIndex === idx);
    if (!leaf) return { ok: false, reason: "unknown_leaf" };
    removed.add(idx);
    if (!R.has(tripleKey(leaf))) continue;
    // The only commit that may remove a leaf whose triple is in R: Remove + Add of the same triple.
    const replacement = adds.find((a) => tripleKey(a) === tripleKey(leaf)) as (Leaf & { ref: string }) | undefined;
    if (!replacement) return { ok: false, reason: "roster_leaf_removed", detail: key(leaf.memberId, leaf.deviceId) };
    if (senderIsAdmin) continue;
    const req = c.repairs.find((r) => r.memberId === leaf.memberId && r.deviceId === leaf.deviceId && r.keyPackageRef === replacement.ref);
    if (!req || repairUsed) return { ok: false, reason: "replacement_not_allowed", detail: key(leaf.memberId, leaf.deviceId) };
    repairUsed = req.bodyHash;
  }

  // Adds: roster-determined; the device had no leaf with its roster triple, except inside a replacement.
  const kept = c.before.filter((l) => !removed.has(l.leafIndex));
  for (const a of adds) {
    if (kept.some((l) => tripleKey(l) === tripleKey(a))) return { ok: false, reason: "add_has_leaf", detail: key(a.memberId, a.deviceId) };
  }
  const after = [...kept, ...adds];
  const eqv = rosterEquality(c.ref, c.before, after);
  if (!eqv.ok) return eqv;
  return { ok: true, after, repairUsed, adds: adds.length };
}

/**
 * Step 4 continuity (4.2): the sender's leaf credential and signature key are byte-identical before and
 * after a commit. A credential never changes in place (section 3).
 */
export function continuity(before: readonly Leaf[], after: readonly Leaf[], senderLeafIndex: number | undefined): RuleResult {
  if (senderLeafIndex === undefined) return { ok: false, reason: "external_commit" };
  const b = before.find((l) => l.leafIndex === senderLeafIndex);
  const a = after.find((l) => l.leafIndex === senderLeafIndex);
  if (!b || !a) return { ok: false, reason: "continuity", detail: "sender leaf missing" };
  if (!eq(a.identity, b.identity) || !eq(a.signaturePublicKey, b.signaturePublicKey)) return { ok: false, reason: "continuity", detail: key(b.memberId, b.deviceId) };
  return { ok: true };
}

/** Pending changes of a group against the current roster (4.2): leaves to remove and devices to add. */
export function pendingChanges(ref: ReferenceRoster, leaves: readonly Leaf[]): { removals: Leaf[]; adds: { memberId: string; deviceId: string; deviceSig: string }[] } {
  const R = rosterTriples(ref);
  const have = new Set(leaves.map(tripleKey));
  const removals = leaves.filter((l) => !R.has(tripleKey(l)));
  const adds: { memberId: string; deviceId: string; deviceSig: string }[] = [];
  for (const m of Object.values(ref.members)) {
    if (ref.scope && !ref.scope.memberIds.includes(m.memberId)) continue;
    for (const d of m.devices) if (!have.has(tripleKey({ memberId: m.memberId, deviceId: d.deviceId, deviceSig: d.sig }))) adds.push({ memberId: m.memberId, deviceId: d.deviceId, deviceSig: d.sig });
  }
  return { removals, adds };
}
