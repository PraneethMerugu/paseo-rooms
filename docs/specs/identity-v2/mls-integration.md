# MLS integration (identity v2)

- **Status:** proposed specification, not implemented. Applies from Milestone 2 (room chat), but its formats are fixed now (P-3, P-7 and P-14 are M2 blockers).
- **Resolves:** A2 on the MLS side (P-3, P-29), the MLS parts of A3, A5 and A7, and the spike findings (custom authentication service, state holds private keys, removal advisory).
- **Inputs:** `spikes/security/RESULTS.md` Spike A; ts-mls 1.6.4 type definitions (`authenticationService.d.ts`, `clientConfig.d.ts`, `incomingMessageAction.d.ts`, `createCommit.d.ts`).
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): commits must name the current roster, device rekey by UpdatePath, roster position defined as the last roster-changing entry. Revised again after the re-review (decisions round 4): the rekey window (`prevSig`, R-5), which credentials ts-mls is expected to pass to the authentication service, and the offline test that must confirm it first (section 10, test 11). Revised again after Spike A (decisions round 6, 2026-10-29): device rekeys use the admin route (section 4.4), the leaf identity used by roster equality includes `deviceSig`, the continuity check runs after processing, the `prevSig` exception is removed, and ts-mls must be at least 1.6.4. Follow-up the same day: KeyPackage publication, fetch, consumption and last-resort rules (section 6.4), pending adds (section 4.2), a commit carries every pending change, repair of a pending rekey (section 4.4), and a leaf replacement row (section 4.3). Revised again under decisions round 7 (2026-10-29): `prevSig` is removed entirely (R7-1); any device of a group may commit a roster-determined Add, and roster equality tolerates pending adds (R7-2; sections 4.2 to 4.4, 6.4, Q7 answered). Revised under decisions round 8 (2026-10-29): a device may request the replacement of its own dead leaf, which any leaf of the group may then commit (sections 4.3, 4.5, 6.4), and a joiner compares its epoch with an anchor that other members put in the authenticated data of their messages (sections 5, 5.1).

## 1. Library and version policy

| Rule | Detail |
|---|---|
| Library | `ts-mls`, pinned to **exactly `1.6.4`** in `package.json` (no range) and by lockfile integrity hash. **Floor: 1.6.4.** No version below it is acceptable, because the removal check fails on 1.6.2 (observed in Spike A case (f) and in the earlier spike). |
| Public API only | The adapter uses only the public ts-mls API. It does not fork `createCommit` or import library internals through the `./*.js` subpath exports. This is why device rekeys use the admin route (section 4.4; decisions round 6, item 1). |
| Explicit dependencies | `@noble/hashes` and `@noble/ciphers` at exact versions (ts-mls imports them without declaring them; spike surprise 3). Spike A case (g) observed identical results with the plugin's `@noble/*` 2.4.0. Inferred, not tried: ts-mls's exact `@noble/ciphers` 2.1.1 peer will need an npm `overrides` entry. |
| Suite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (suite 1) only. Groups with any other suite are refused. |
| Config import | `defaultClientConfig` from `ts-mls/clientConfig.js`, then override `authService` and `keyRetentionConfig` (section 8.3). Never spread an `undefined` config. |
| Adapter | All ts-mls calls go through `server/mls/adapter.ts` (create, keyPackage, commit, processMessage, encrypt, decrypt, encodeState, decodeState). Nothing else imports ts-mls. This keeps the 2.0 migration local. |
| Advisories | `npm audit` does not report ts-mls advisories (spike surprise 2). The release checklist includes reading `github.com/LukaJCB/ts-mls/security/advisories` before any upgrade and once per release. |
| Upgrade gate | An upgrade requires the regression suite of section 10 to pass on the new version, and the positive control to still fail on 1.6.2. |

## 2. Groups

### 2.1 Room group

One MLS group per room:

```
groupId = H("mls-group", RJCS({ genesisHash, generation }))     // no scope field; generation starts at 0; ReInit increments it
```

- **Leaves:** one per active device in the roster (`kind: "person"` devices of every member, and later `kind: "gateway"` devices of seated-agent gateways). The host is never a leaf.
- **Created** by the creator's first device at room creation, with its own leaf only. Every later device joins by Welcome.
- **External joins are disabled.** The host does not publish GroupInfo, and members reject external commits (section 4.3).
- **PSKs** are not used.

### 2.2 Team-visibility subgroups

A lane or thread with `visibility: team` gets its own group for its chat:

```
groupId = H("mls-group", RJCS({ genesisHash, scope: <scopeId>, generation }))
```

- Scope membership is an admin statement `scope.membership.changed {scopeId, memberIds}`. The scope roster is the room roster restricted to those members.
- The same authentication service applies, with the scope roster in place of the room roster. A device must be in the room roster to be in any scope.
- Key packages are single-use, so each subgroup needs its own key packages (spike A.2).
- MLS does not link the room group and subgroups. The roster-equality rule (section 4.2), applied per group against the right roster, keeps them consistent.

### 2.3 Group context extension: room authority

A custom GroupContext extension, type `0xF0A1` (private-use range), named `paseo_room_authority`:

```
RJCS({ v: 2, genesisHash, adminSetHash: b64u(H("admin-set", RJCS(adminSet))), scope: null | scopeId })
adminSet = [ b64u(pub) of every active admin key ], sorted as strings
```

- Set at group creation. Changed only by a GroupContextExtensions commit from an admin device after an admin key change (`keys-rotation-recovery.md` section 4.3).
- A Welcome whose extension does not match the joiner's verified authority state is rejected. This prevents a host or a ghost leaf from steering a new member into a group with a different authority (P-3 recommendation 4).
- Required capability: every leaf lists `0xF0A1` in its capabilities.
- Vectors: `mls.adminSet`, `mls.adminSetHash`, `mls.authorityExtension`, `mls.groupIds` (room group and a scope group).

## 3. Credentials

Every leaf uses a **basic credential** whose `identity` bytes are:

```
MlsIdentity = {
  v: 2, typ: "mls-identity",
  roomId, memberId, deviceId,
  deviceSig: <device signing pub>,
  mlsSig: <this leaf's signature_key>,
  notBefore: <unix s>
}
identity = RJCS({ id: MlsIdentity, sig: b64u(Sign(deviceSigningKey, "mls-identity", RJCS(MlsIdentity))) })
```

- The MLS leaf signature key is **separate** from the device signing key. It is replaced together with the leaf at a device rekey (section 4.4). The public ts-mls API cannot change a leaf's credential or signature key in an UpdatePath (Spike A case a0, observed), so the device does not rotate it on its own (`keys-rotation-recovery.md` section 4.2).
- **A leaf's credential never changes in place.** A leaf keeps its credential, byte for byte, from the commit that adds it to the commit that removes it. Only its HPKE key changes, through UpdatePaths.
- The device signing key vouches for the MLS key; the admin-signed roster vouches for the device signing key. That chain is the whole authentication path.
- Vector: `vectors/vectors.json` → `mls`.

## 4. Authentication service and roster rule

### 4.1 Credential validation

**Observed calls** (Spike A cases (a), (c) and (d), ts-mls 1.6.4, section 10 test 11). ts-mls calls `authService.validateCredential(credential, signaturePublicKey)`:

- while processing a commit: for the committer's UpdatePath leaf (`processMessages.js:136`) and for the leaf of each added KeyPackage, and for no other leaf;
- while creating an Add commit: for each added KeyPackage;
- while processing a Welcome: for the GroupInfo signer (`clientState.js:578`), then for every leaf of the tree (`validateRatchetTree`, `clientState.js:264`), stopping at the first refusal.

It does not compare an UpdatePath's new leaf with the old one, and it does not validate the sender of an incoming commit again. The `IncomingMessageCallback` receives only `{kind, proposals, senderLeafIndex}` and never sees the UpdatePath leaf (case (b)). Role checks therefore read the sender's leaf from the current tree by `senderLeafIndex`, and the continuity check runs after processing (section 4.2 step 4).

Our implementation is a closure over the room's verified state. It returns `true` only if **all** of these hold:

1. `credential.credentialType === "basic"`.
2. `identity` passes strict RJCS parsing and the `MlsIdentity` schema.
3. `roomId` equals this room's.
4. `mlsSig` equals `signaturePublicKey` byte for byte.
5. The `sig` verifies with `deviceSig` under context `mls-identity`.
6. In the **reference roster** (section 4.2), `memberId` has an active device `deviceId` whose stored signing key equals `deviceSig` byte for byte. There is no exception for a previous key: the `prevSig` rekey window of the round-4 revision is removed entirely, in `joinGroup` and everywhere else (decisions round 7, item 1; section 4.4 explains why it is no longer needed).
7. For a subgroup: `memberId` is in the scope roster.
8. `deviceSig` is not in the device denylist as of the reference roster position. Rule 6 already implies this; the check stays as a second guard.

The same rules apply to every credential the library passes, during commit processing, commit creation and Welcome processing alike. The adapter no longer classifies leaves as "unchanged". Spike A case a-stale showed why that rule was unsafe: a post-approval UpdatePath that kept the old `deviceSig` was byte-identical to the current leaf, was classed as unchanged, and was accepted through the `prevSig` exception.

**Reference roster for a Welcome.** `welcome.fetch` returns the log entry of the Add commit that produced the Welcome. The joiner reads the commit's authenticated data without group state (Spike A case (e), observed), verifies its log up to that entry as in section 4.2 step 2, and uses the roster named there as the reference roster for `joinGroup`. A Welcome processed late is therefore judged against the roster its commit named, not against the joiner's current roster.

The authentication service has no other inputs, so the adapter sets the reference roster on the closure **before** each `processMessage`, `joinGroup` or `createCommit` call, and clears it after. A missing reference roster makes the closure return `false` (fail closed).

The closure is attached on every state load. ts-mls does not serialize `clientConfig`; a decoded state without it silently uses the accept-all default (spike surprise 3). The adapter's `decodeState` therefore takes the room context as a required argument and has no code path that returns a state without our config. A unit test loads a state and processes a commit that adds a forged credential; it must be rejected.

### 4.2 Roster equality

Every handshake message carries authenticated data (section 5) naming a roster position `{seq, hash}`. That roster is the **reference roster** for the message. `seq` is always the last roster-changing entry (`identity-model.md` section 6.1), never an arbitrary log position.

**A commit must name the current roster** (review finding S-6). Let `c` be the `seq` of the log entry that carries the commit. The commit's `roster.seq` must equal the `rosterSeq` of the fold over the entries before `c`. A commit that names an older roster is rejected, even if its leaf set equals that older roster. Otherwise a member could commit against a roster from before a removal, and keep a leaf that is pending removal, or use a role it has since lost. The committer's role is also judged in this roster (section 4.3).

The host checks the same rule before it sequences a commit (it can read the authenticated data, section 6.2) and answers `stale_roster` with the current position, so an honest committer rebuilds instead of being rejected by every member. Application messages may name an older roster; for them it is only gossip.

Before processing a commit, the member:

1. decodes the outer `MLSMessage` without processing it, reads `authenticated_data`, and parses it strictly;
2. makes sure its own verified log reaches the commit's entry `c`, that `roster.seq` is the last roster-changing entry before `c`, and that the hash of that roster equals `roster.hash`; if its log is behind, it fetches and verifies up to `c` first; if the host cannot provide it within 30 s, the commit is parked and a `withholding` alert is raised (`room-log-v2.md` section 6.5);
3. sets that roster as the reference roster and processes the commit with an `IncomingMessageCallback` that checks the committer's role (section 4.3, sender read from the current tree by `senderLeafIndex`), computes the resulting leaf set (current leaves minus Removes plus Adds, from the credentials) and returns `"reject"` unless it satisfies **roster equality** (below) against the reference roster (scope roster for subgroups);
4. after processing, checks the new state and discards it (the old sealed state is still on disk) and raises `roster_mismatch` on any failure:
   - **roster equality again:** the leaf set recomputed from the new state, compared with the leaf set of the old state, satisfies roster equality;
   - **continuity:** if the commit has a path, the sender's leaf credential in the new state is byte-identical to its credential before processing (sender index from the callback). This catches a changed `memberId`, `deviceId`, `deviceSig` or `mlsSig` in an UpdatePath, which neither the callback nor the library checks. Spike A case (b) observed that, with an accept-all authentication service, ts-mls accepts a changed `deviceId` and only this comparison detects it.

**Leaf identity** for equality is the triple `(memberId, deviceId, deviceSig)` from the leaf's credential, compared with `(memberId, deviceId, signing key)` of each active roster device. Including `deviceSig` makes an approved device rekey a pending change, like a pending removal: the first commit that names the post-approval roster must remove the device's old-key leaf (section 4.4).

**Roster equality** (decisions round 7, item 2; answers Q7). Let `R` be the triples of the active devices of the reference roster, `B` the leaves before the commit and `A` the leaves after it. The commit satisfies roster equality when all of these hold:

1. every leaf of `A` has its triple in `R`. So every leaf absent from the roster is removed (pending removals, old-key leaves after a rekey or a re-fold), and every added leaf belongs to a roster device under its current key;
2. no two leaves of `A` share `(memberId, deviceId)`;
3. every leaf of `B` whose triple is in `R` still has its triple in `A`. A commit may therefore leave out of `A` only devices of `R` that had no leaf with their roster triple before it: pending adds, including a device whose old-key leaf this commit removes.

In short, the leaf set equals the reference roster minus devices that have no leaf yet, and every leaf absent from the roster is removed. Old-key leaves must still be removed, so no tree and no Welcome ever contains one, and the `prevSig` exception stays unnecessary (section 4.4).

So **a commit carries every pending removal** of its group, including old-key leaves, not only the change its author set out to make. Pending adds, and the Add half of a pending rekey, are optional: a committer includes every one for which it holds a KeyPackage that passes the fetcher's checks (section 6.4), and leaves the others for a later commit. A committer runs the checks of steps 3 and 4 on its own result before it submits, so a commit that members would reject is never sent.

Consequences:

- A host, a holder of the host key, or a malicious member cannot add a ghost device: no admin-signed statement admits it, so no roster contains it, so every honest member rejects the commit (P-3).
- A device removed in the roster but still in the group is a **pending removal**, not a mismatch, as long as no commit has been made since the roster change. The first commit after a removal must include the Remove, because it must name the newer roster. Members do not send application messages to a group with a pending removal older than 60 s (section 6.3). Devices that leave the roster because a revocation made their admission suspect (`room-log-v2.md` section 5.1) become pending removals the same way.
- An Update or an empty commit references the current roster and removes nothing, so it is valid only when no removal or old-key leaf is pending. Pending adds do not block it.
- A device whose rekey is approved but whose leaf still carries the old `deviceSig` is a **pending rekey**. Any commit naming the post-approval roster must remove the old-key leaf. Any device of the group may do that, and may also add one of the device's new KeyPackages (section 4.3). If it does not add one, the device becomes a pending add. The admin route makes this state transient in the room group (section 4.4).
- A device that is active in the roster but has no leaf yet (just admitted, linked, or added by `member.device.replaced`) is a **pending add**. Any device of the group can resolve it with one of the device's KeyPackages (sections 4.3, 6.4), and no commit is required to.
- **Liveness cost.** Before round 7 every commit had to resolve every pending add and rekey, so a group with one pending and no admin leaf online could not commit at all. Now pending adds block nothing: any device can commit Removes and UpdatePaths while an add waits, and any device that holds a KeyPackage can complete the add. What remains: a device stays out of a group until some device of that group commits its Add, and the old-key leaf of a pending rekey blocks commits that do not remove it, as any pending removal does. Section 6.4 keeps the wait short (KeyPackages published as soon as a device is active, a last-resort KeyPackage, a waiting notice when a pending add has none), and section 4.4 has the repair rule.

### 4.3 Who may commit what

| Commit content | Allowed committer | Extra check |
|---|---|---|
| Add (roster-determined, decisions round 7) | any device that is a leaf of the group (the room group, or the scope's subgroup) | every added leaf validates under 4.1 against the reference roster; the added device had no leaf with its roster triple before the commit (a pending add, or a pending rekey whose old-key leaf the same commit removes), except inside an admin's leaf replacement; the result satisfies roster equality (section 4.2) |
| Remove | any member device | the removed leaf's `(memberId, deviceId, deviceSig)` is absent from the reference roster |
| Update / UpdatePath only | any member device | the committer's leaf credential is byte-identical before and after (continuity, section 4.2 step 4); only its HPKE key changes |
| Device rekey (Remove of the old leaf + Add of a KeyPackage with the new credential, same `memberId` and `deviceId`) | any device that is a leaf of the group; in the room group normally the admin device that signs the approval (section 4.4) | this is a Remove row plus an Add row: the reference roster is the current roster, as for every commit, and in it the device's signing key is the new one, so the old leaf is absent from it and the added leaf carries the new `deviceSig`. In the room group the first such commit is the entry right after `device.rekey.approved`; in subgroups, and after a host split, it is a later ordinary commit (section 4.4) |
| Leaf replacement (Remove of a leaf + Add of a fresh KeyPackage with the same `(memberId, deviceId, deviceSig)`) | an admin device; or any device that is a leaf of the group, when the commit carries out an open `device.leaf.repair.requested` of the replaced device (section 4.5; decision round 8, item 1) | the replaced leaf is in the reference roster; used when a device cannot use the Welcome for its leaf, for example after a replayed KeyPackage (section 6.4). Without an admin, the commit must name a request that is open at the commit's entry, signed by the replaced device for this group (scope and generation), and the added KeyPackage's KeyPackageRef must equal the request's `keyPackageRef`; each request is used by at most one commit. This is the only commit that may remove a leaf whose triple is in the reference roster |
| GroupContextExtensions | admin device | new `paseo_room_authority` matches the authority state at `seq` |
| ReInit | admin device | only after `admin.key.revoked` (`keys-rotation-recovery.md` section 6.6) |
| External commit, external proposals, PSK proposals | nobody | rejected |

A commit may combine rows; each part must meet its row. Only leaf replacement (without a repair request), GroupContextExtensions and ReInit still depend on the committer's role. Adds no longer do: since round 7 the roster, not the committer's role, decides which leaves may be added (section 4.4, "Decided").

The `IncomingMessageCallback` of 4.2 enforces the committer column using the sender's leaf credential, read from the current tree by `senderLeafIndex`, and the sender's role in the reference roster. It cannot rely on `validateCredential` for the sender, because ts-mls does not call it for the sender of an incoming commit (section 4.1, observed). It cannot see an UpdatePath leaf, so the UpdatePath row is enforced by the continuity check after processing (section 4.2 step 4).

### 4.4 Device rekey: the admin route

Decided in round 6 (2026-10-29) after Spike A. The device does not commit its own rekey. The admin daemon that signs `device.rekey.approved` also applies it in MLS, in the same submission. This stays the primary path. Since round 7, any device that is a leaf of a group may also complete a rekey there (subgroups, repair after a host split), because the Add is roster-determined (section 4.3).

**Why.** Spike A observed that receivers accept and validate an UpdatePath that carries a new credential, but the public `createCommit` always copies the old credential and signature key into the UpdatePath (case a0). The device could send one only through an adapter-owned fork of `createCommit` that imports library internals. Round 6 rejected the fork. Remove plus Add uses only public APIs.

**Inputs.** When the device requests the rekey (`keys-rotation-recovery.md` section 4.1 step 2), it publishes KeyPackages that carry its new `MlsIdentity` (new `deviceSig`, new `mlsSig`) with `kp.publish {for: "rekey"}`: one per group it is a leaf of, plus one spare, and a last-resort KeyPackage (section 6.4). KeyPackages are single-use (spike A.2).

**Ordering.** When the hold has passed (automatic approval) or an admin approves interactively, the admin daemon:

1. fetches with `kp.fetch` (section 6.4) one of the device's new-credential KeyPackages (`for: "rekey"`) for each group the device is a leaf of, and, where it can, one `for: "current"` KeyPackage for every other pending add in the room group (section 4.2). It stops if the room-group `rekey` KeyPackage is missing (see below). A missing package for another pending add or for a subgroup does not stop it: that add is left pending (section 4.2) and the repair rule covers it;
2. signs `device.rekey.approved` with `base` at the current head `h`, and expects it to be sequenced at `s = h.seq + 1`;
3. computes the roster that the fold produces at `s` (new keys, old keys denylisted) and its `rosterHash`;
4. builds the room-group commit with the public `createCommit`: Remove of the device's old leaf and Add of its new KeyPackage, plus every other pending removal of the room group and the pending adds it holds packages for (section 4.2), authenticated data naming roster `{seq: s, hash}`, with that roster set as the reference roster, so the committer's own validation of the added KeyPackages uses the new keys. It checks its own result against roster `s` as in section 4.2 before it submits;
5. sends both in one `commit.submit {…, statement}` (section 6.1). The host sequences the statement at `s` and the commit at `s + 1`, with nothing in between, in one durable write, or sequences neither. If the head has moved, the predicted roster no longer matches and the host answers `stale_roster`. On `stale_base`, `stale_epoch` or `stale_roster` the daemon discards both, keeps the fetched KeyPackages (section 6.4, "Use"), and starts again from step 2. After a lost reply it treats the pair as outstanding (`room-log-v2.md` section 2): it re-reads the head, and if the statement is not there it may sign a new pair with the same KeyPackages. At most one pair can take effect, because the second approval names a `ref` the first one closed;
6. after the room-group commit is sequenced, commits the same Remove plus Add in each team subgroup the device is in, naming the current roster (roster `s` unless a later roster change was sequenced) and carrying that subgroup's other pending removals. These are ordinary commits, and any device of the subgroup may make them instead (section 4.3). A subgroup the daemon is not a leaf of, or that it does not reach before going offline, is handled by the repair rule below.

Members process the commit at `s + 1` with roster `s` as reference. It removes the old-key leaf and adds a leaf with the roster's new triple, so it passes roster equality. A commit at `s + 1` that does not remove the device's old-key leaf fails roster equality (section 4.2, rule 1) and is rejected. Since round 7 a commit at `s + 1` that removes the old leaf without adding the new one would also pass, and would leave the device a pending add; the admin daemon does not build one (step 1).

**Is anything pending visible to a joiner?** In the room group, no. Approval and application are adjacent log entries, so no commit, and therefore no Welcome, can come between them. If the host splits them anyway (it sequences the statement and drops the commit), the room group simply has a pending rekey: roster equality (section 4.2) rejects every commit that names roster `s` or later and does not remove the old-key leaf. Any device of the group may make that commit, with or without the new leaf (repair, below), so no Welcome can be built over a tree that still holds the old key. The host may sequence `device.rekey.approved` only through `commit.submit` (section 6.1; `room-log-v2.md` section 2), so a member that finds any entry other than an `mls.commit` at `s + 1` raises `withholding` (`room-log-v2.md` section 6.5). Subgroups go through a short pending rekey between steps 5 and 6 under the same rule. In every case a Welcome's tree matches the roster its Add commit names.

**Why the `prevSig` exception is removed.** Spike A case (c) needed it because a Welcome was built while a rekey was approved and the device's leaf still had the old key. Under this section that cannot happen, for two reasons. An approved but unapplied rekey can still exist briefly (a split by the host, or a subgroup between steps 5 and 6), but with `deviceSig` in the leaf identity no commit naming the post-approval roster passes roster equality unless it removes the old-key leaf (section 4.2, rule 1), so no Add, and no Welcome, can be built over it. Round 7's tolerance of pending adds does not change this: it lets a commit leave a device without a leaf, never keep a leaf absent from the roster. A Welcome built before the approval is judged against the roster its own commit named (section 4.1), in which the old key is still the device's key. So every leaf of every valid Welcome carries the key of its reference roster, and rule 6 needs no exception, in `joinGroup` or anywhere else. Keeping the exception would only reopen case a-stale. The same argument covers concurrent Adds: a commit built before `s` names an older roster and gets `stale_epoch` or `stale_roster` once the pair is sequenced, and a commit built after it must remove the old-key leaf.

**What a malicious host can do with the pair.**

- *Sequence the commit without the statement.* Not possible: the commit names roster `s`, and without the approval no roster-changing entry sits at `s`, so members reject it (section 4.2 step 2).
- *Sequence the statement and drop or delay the commit.* Once any other entry appears at `s + 1`, the two signed entries prove the split and members raise `withholding`; a host that simply stops after `s` is a stall, which the host can cause at any time. The device's old keys are denylisted and its old session is closed, so it is out of the room group until some device repairs the leaf. Every commit meanwhile must remove the old-key leaf (section 4.2), so the next commit by any device ends the old leaf even if no new KeyPackage is at hand. The old leaf's keys keep decrypting until that commit, so if the rekey was prompted by a suspected exposure, that exposure lasts longer. Any delay before approval has the same effect; a confirmed compromise is a removal, not a rekey (`keys-rotation-recovery.md` section 4.1).
- *Delay or refuse the pair.* The rekey is delayed and the device keeps its old, still valid keys. The host can deny service this way for any operation.
- *Withhold the device's Welcome.* The device sees the commit at `s + 1` in the log but no Welcome from `welcome.fetch`; after 30 s it raises `withholding`.

**Repair.** Any device that is a leaf of a group, and finds a pending rekey or pending add there older than 60 s, fetches the missing KeyPackages (section 6.4) and commits the missing changes as an ordinary commit naming the current roster. A device that is not an admin waits a further random delay of up to 60 s first, so that devices seeing the same pending change rarely fetch for it at once (section 6.4, "Rate"). A pending rekey's old-key leaf is removed by the next commit of any device, whether or not a new KeyPackage is available. This covers a host split, subgroups after step 5, an approving daemon that went offline, pending changes left by a re-fold (`keys-rotation-recovery.md` section 6.6), and team subgroups with no admin device. Repairers that race are ordered by the host's one-commit-per-epoch rule (section 6.2).

**If no admin daemon is online.** Nothing happens. Automatic approval is already signed by an admin daemon after the hold (`identity-model.md` section 6.3), and the same daemon builds the commit. A rekey whose hold has passed stays requested, and the device keeps its old keys, which remain valid, until an admin daemon comes online. The device is never in a state where the roster has its new keys and the room group still has its old leaf. If the admin daemon is online but a KeyPackage is missing (step 1), it does not sign the approval. It asks the device to publish KeyPackages and tells the admin: "Waiting for *<device>* to publish its new keys."

**Member's experience.** On the rekeyed device:

- During the hold, as now: "Your device *<label>* is changing its keys at *<time>*."
- After the hold, while no admin daemon is online: "Waiting for an admin device to finish the key change. Your current keys keep working."
- When the pair is sequenced: the host closes the old session with `superseded`; the device reconnects with its new DH key. It does not process the commit at `s + 1` with its old state (that commit removes its old leaf). It fetches the Welcome, joins at the new leaf after verifying the tree against roster `s`, then writes the new sealed state and deletes the old one. Chat pauses for that reconnect only. Messages that others send meanwhile are in the new epoch and readable after the join. Messages it had queued under the old epoch are re-encrypted and sent again. Local history is kept.
- Other members see the existing key-change notice for the device. They see no MLS-specific step.

**Decided (round 7, item 2): subgroups and pending adds.** Before round 7 only an admin could Add, and every commit had to resolve every pending add. A team subgroup with no admin device could then neither add a new device nor apply a rekey, and after the first admission or rekey nobody in it could commit again, Removes included. Of the options considered ((a) a scope must contain an admin; (b) roster-determined Adds by any device of the group; (c) roster equality that tolerates pending adds), round 7 adopted (b) and (c), for subgroups and for the room group alike:

- **(b)** any device that is a leaf of a group may commit an Add whose every added leaf validates under section 4.1 against the reference roster, for a device that has no leaf with its roster triple yet, when the result satisfies roster equality (section 4.3, Add row);
- **(c)** roster equality tolerates pending adds (section 4.2, rules 1 to 3; answers Q7).

The admin route above stays the primary path for rekeys in the room group, because the approving daemon already holds the packages and builds the pair. Option (a) was not adopted: it would make every team scope readable by an admin.

**What a compromised device that is not an admin can do afterwards.** Take an attacker who holds the keys of one active roster device `X` and its leaf in some groups. `X` is not an admin and holds no admin key.

It cannot:

- add a device that is not active in the reference roster, or a leaf whose `deviceSig` is not the roster's current key for that device. Rules 6 and 7 of section 4.1 and roster equality rule 1 refuse it, as before;
- forge a KeyPackage for another device. The credential must be signed by that device's roster signing key and the package by the leaf key the credential names. It can only use packages the device published itself;
- give a device a second leaf, or add a leaf for a device that already has a valid one (rule 2, and the Add row);
- remove the valid leaf of another device. A Remove of a leaf whose triple is in the reference roster is allowed only inside an admin's leaf replacement (section 4.3; roster equality rule 3);
- keep a removed device, or an old-key leaf, in the group past the next commit (rule 1);
- commit in a group it is not a leaf of. Rule 7 and the per-scope groups keep it out of scopes its member is not in;
- change the authority extension or ReInit (admin rows, unchanged);
- fetch `rekey` packages, fetch for devices it shares no group with, or take more than its share of `current` packages per hour (section 6.4).

It can:

- choose when a pending add is resolved, and which of the packages it fetched is used. It can leave a pending add open by committing first with commits that omit it, as often as the host's one-commit-per-epoch rule and its request budget (`enrollment-v2.md` section 5.4) let it win. Honest devices then add the device in the next epoch. A device that keeps winning epochs is visible to members, because commit senders are decryptable, and an admin can remove it. Any member device could already delay commits this way before round 7;
- drain single-use packages of devices it shares a group with, up to its per-fetcher cap (section 6.4, "Rate"). Adds then fall back to the target's last-resort package, which weakens forward secrecy for those joins (section 6.4, attacks table). It cannot make an Add impossible while the target has published a last-resort package;
- put one fetched single-use package into two groups, or send no Welcome or a broken one. The target then has a dead leaf in a group: it cannot open the second Welcome, because it deleted the init key at its first join (section 6.4, replay row). Since round 8 the target repairs this itself: it signs `device.leaf.repair.requested` and any leaf of the group, honest devices included, replaces the leaf (section 4.5). `X` can delay the repair by winning epochs, as for any pending add, but cannot choose the package, because the request names it. The attacker gains no plaintext from this; it is denial of service against one device in one group;
- send a joiner a Welcome that is inconsistent with the commit it sent to the group. Inferred from RFC 9420 Welcome processing, not tested: the joiner checks that the GroupInfo signature, tree and confirmation tag agree with each other, but all of them come from the committer, so the joiner cannot tell at join time that its epoch differs from the other members'. Our checks still hold for that tree (every leaf roster-valid, authority extension matching), so the attacker cannot add a ghost leaf. The joiner would sit in a fork: it could not read others' messages, and its own messages would be readable only by `X`, which as a member could read them anyway. Before round 7 only a compromised admin device could do this; now any device of the group can. The joiner sees decryption failures from the first message of another member. Since round 8 the joiner also compares its epoch with the anchors other members put in their messages and raises `epoch_fork` on a mismatch (section 5.1).

Net effect: the roster decides who is in each group, as before. What moves from admins to every device of a group is timing, the choice among published packages, and the ability to send Welcomes. Each misuse of these is denial of service against specific devices, never admission of a device the roster does not contain, and never access to plaintext `X` could not already read.

**Resolved in round 8** (the two gaps left open after round 7):

- **Dead leaves in groups without an admin.** The affected device signs `device.leaf.repair.requested`, and any leaf of the group may carry out the replacement (section 4.5). Leaf replacement without a request stays admin-only, so a compromised device still cannot force another device to rejoin.
- **Fork detection for joiners.** Members anchor a hash of the MLS `epoch_authenticator` in the authenticated data of every message, and a joiner compares its own (section 5.1). Not yet checked against ts-mls 1.6.4 (section 10, test 13).

### 4.5 Leaf repair requested by the device

Decided in round 8 (item 1). A device has a **dead leaf** in a group when the group's tree holds a leaf with its roster triple but the device cannot use it: the Welcome for that leaf was missing for 30 s after its commit was sequenced, failed to process, or named a KeyPackage whose private init key the device no longer holds (a replayed single-use package, section 6.4). Before round 8 only an admin device could repair it (section 4.3, leaf replacement), so in a team subgroup with no admin device the device stayed unable to read the group.

**Procedure.**

1. The device publishes a fresh single-use KeyPackage for the group (`kp.publish {for: "current"}`, section 6.4) and computes its KeyPackageRef.
2. It signs `device.leaf.repair.requested {memberId, deviceId, group: {scope, generation}, keyPackageRef}` and submits it with `stmt.submit` (`room-log-v2.md` section 4.3). The fold accepts it only from the device itself, for a group of its scope, at most once per group per hour and 8 times per 24 h.
3. Any device that is a leaf of that group and sees the open request fetches the named package with `kp.fetch` by `ref` (section 6.1) after the repair delay of section 4.4 (60 s, plus up to 60 s at random for devices that are not admins), checks it as in section 6.4 ("Authentication by the fetcher"), and commits the leaf replacement: Remove of the device's current leaf and Add of that package, naming the current roster, together with every other pending removal of the group.
4. Members check the commit as in sections 4.2 and 4.3: the Remove and Add concern one device with one triple, the request is open at the commit's entry and names this group and the device, and the added package's KeyPackageRef equals `keyPackageRef`. A second commit that uses the same request is rejected (`roster_mismatch`), and so is a replacement after the request was cancelled in the fold or more than 24 h of `hts` after its entry.
5. The device joins at its new leaf by Welcome. If the commit removes its leaf and adds any package other than the one it named, or if no request of its own is open, it raises `leaf_replaced_unrequested` (`room-log-v2.md` section 6.6).

**Why a statement and not an open right.** Opening leaf replacement to any device would let a compromised device force any other device to rejoin, and choose the package. With the request, the device decides when its leaf is replaced and with which package, and the committer only executes. The abuse analysis is in `room-log-v2.md` section 4.3: a holder of one device's keys can only replace that device's own leaf, at a rate-limited cost of one commit, visibly.

**Rate.** The fold's limits (1 per group per hour, 8 per device per 24 h, `room-log-v2.md` section 4.3) bound the commits a request can cause. The host applies the same limits on its own clock, and `kp.fetch` by `ref` counts toward the fetcher's per-target cap of section 6.4.

## 5. Authenticated data and epoch anchoring

Every MLS message (commits and application messages) carries:

```
authenticated_data = RJCS({
  v: 2, typ: "mls-aad",
  roster:  { seq, hash },         // reference roster (section 4.2)
  logHead: { seq, hash },         // the sender's latest verified log head
  epochAuth: b64u(H("mls-epoch-auth", RJCS({ v: 2, typ: "mls-epoch-auth", groupId: b64u(groupId), epoch, auth: b64u(epoch_authenticator) })))
                                  // the sender's epoch anchor (section 5.1)
})
```

- For commits, `roster.seq` is the last roster-changing entry before the commit's own entry (section 4.2). For a commit that carries a Remove, that is the removal statement or a later roster change.
- Vector: `mls.authenticatedData`, where `roster.seq` is 2 while `logHead.seq` is 3, because entry 3 (`grant.issued`) does not change the roster (S-14).
- `logHead` is how members gossip log heads to each other through a channel the host cannot alter (`room-log-v2.md` section 6.2). The host can only drop whole messages.
- The host records each commit in the log with `cls: "mls"`, `type: "mls.commit"`, the resulting `epoch`, and `bodyHash` of the commit bytes. Log entries carry the current `epoch`. Each commit names a log position, and the log records each commit: the MLS transcript and the room log are anchored to each other (P-7).
- `epochAuth` is computed over the epoch the message is sent in: for an application message, the current epoch; for a commit, the epoch it is built on (the new epoch does not exist yet). `epoch_authenticator` is the MLS value of RFC 9420 section 8.7 (cited from memory, not rechecked offline), derived from the epoch secret, so two devices get the same value only if they are in the same epoch state. The hash hides the value from the host, which sees the authenticated data; it reveals nothing about the other epoch secrets. Vector: `mls.epochAuth`, with a placeholder authenticator, and `mls.authenticatedData`.

### 5.1 Joiner epoch check

Decided in round 8 (item 2). A Welcome comes from one committer, so a joiner cannot tell at join time whether its epoch is the one the other members are in (section 4.4: a malicious committer can send a Welcome inconsistent with its commit). The joiner therefore compares its epoch with the anchors other members wrote.

**Does existing anchoring already carry a suitable value?** No. The room log anchors each commit's `bodyHash`, the epoch number, the roster position and the log head (section 5; `room-log-v2.md` sections 3 and 6.2). None of them depends on the epoch secrets: a joiner in a forked epoch computes the same epoch number and roster, and it cannot decrypt the commit to compare its confirmation tag. What is reused is the channel: the authenticated data of MLS messages, which the joiner reads without group state (Spike A case (e)) from entries every device fetches from the same log. The new field `epochAuth` carries the anchor.

**What is anchored, and when.** Every MLS message carries `epochAuth` for the epoch it is sent in (section 5). To make sure an anchor appears soon after a join, every device that processes a commit containing an Add sends a `log.witness` application message (`room-log-v2.md` section 4.5) in the new epoch after a random delay of 0 to 30 s, unless it has already seen, in that epoch, anchors from two other devices that it could decrypt.

**Check by the joiner.** After joining at epoch `n` of a group from a Welcome whose Add commit is at entry `c`:

1. It computes its own anchor `A` for `(groupId, n)`.
2. For each MLS message of that group in the log after `c` with epoch `n` (read from the message, not from the entry) that it did not send, it reads `epochAuth` without decrypting:
   - equal to `A`: if the message decrypts and its sender is a leaf other than the Welcome's GroupInfo signer, the epoch is **confirmed**;
   - different from `A`, and the message decrypts: the sender is in the joiner's epoch and lied. Raise `epoch_anchor_mismatch` naming the sender's credential, as for `unverified_head_claim`; this stops nothing;
   - different from `A`, and the message does not decrypt: the joiner and the sender are in different epoch states. Raise **`epoch_fork`**: a visible security event with the Welcome's commit entry, the GroupInfo signer and the message as evidence, sent to admins. The device refuses to send application messages in that group from then on, keeps reading, and asks an admin to remove and re-add its leaf (or requests a repair, section 4.5).
3. Until the epoch is confirmed, the joiner does not send application messages in that group.
4. **Timeout.** If no confirming anchor arrives within 5 minutes of the join, the joiner raises `epoch_unconfirmed`: a warning badge for that group and a notice to admins. It may then send, because the only device that could read its messages in a forked epoch is the committer, which is a member of the group anyway; what the joiner risks is not being heard. It keeps checking anchors as they arrive and raises `epoch_fork` if one does not match. A message of the next epoch that the joiner cannot process (a commit it cannot decrypt) is handled under section 9.

A group with only the joiner and the committer online has no third device to confirm. The check then times out and the joiner shows `epoch_unconfirmed` until another member's message arrives.

## 6. Delivery service on the host

### 6.1 Operations (room session, `enrollment-v2.md` section 4)

```
kp.publish   { for: "current" | "rekey", keyPackages: [b64u...], lastResort?: b64u }      section 6.4
   → ok { stored, lastResort: bool } | error not_permitted
kp.fetch     { targets: [ { memberId, deviceId, for: "current" | "rekey", count: 1..10 }
                       | { memberId, deviceId, ref } ] }   ≤ 8 targets; section 6.4; `ref` for a leaf repair (4.5)
   → ok { results: [ { deviceId, keyPackages: [b64u...], lastResort: b64u | null } ] } | error not_permitted
kp.low       (host → device push) { for: "current" | "rekey", remaining }                  section 6.4
commit.submit{ epoch, commit: b64u, welcome?: b64u, ratchetTree?: b64u, statement?: SignedStatement }
   → ok { seq, epoch } | error stale_epoch { epoch } | error stale_roster { roster } | error stale_base { head }
   | error not_permitted
welcome.fetch{ ack?: seq } → { welcome: b64u, ratchetTree: b64u, entry } | none
msg.send     { epoch, message: b64u }              application message (PrivateMessage)
msg.fetch    { fromSeq, limit ≤ 500 }
```

- `statement` is allowed only for `device.rekey.approved`, and `device.rekey.approved` is accepted only this way (`stmt.submit` refuses it with `not_permitted`). The host validates the statement as for `stmt.submit` (`room-log-v2.md` section 2), checks the commit's authenticated data against the roster after the statement, and then sequences the statement and the commit as two adjacent entries, or neither (section 4.4).
- `welcome.fetch` returns the oldest Welcome that names one of the caller's KeyPackages (section 6.4, "Welcome routing") and that the caller has not acknowledged. A device in several groups calls it until `none`. It acknowledges a Welcome with `ack` (the `seq` of its commit entry) after writing the joined state (section 8.2); the host then drops it.

### 6.2 Sequencing

- The host accepts **one commit per epoch**: the first that names the current epoch and comes from an active roster device wins. Later ones get `stale_epoch`, and their senders rebuild on the new epoch.
- The host cannot verify commit contents (they are PrivateMessages). It checks only the outer epoch, size (≤ 1 MiB), sender session, and that the authenticated data names the current roster (`stale_roster` otherwise, section 4.2). Members do the real validation (section 4). A commit that honest members reject leaves those members at the old epoch and raises `roster_mismatch`; the host sees members stop advancing and logs `mls.stalled` after 5 minutes.
- Handshake messages use the **PrivateMessage** wire format, so the host does not learn proposal contents or senders. Content type and authenticated data stay visible to it (RFC 9420 section 6.3). Spike A case (e) observed that ts-mls 1.6.4 creates `mls_private_message` commits with `wireAsPublicMessage: false`, and that `decodeMlsMessage` without group state yields the wire format, epoch, content type and the `authenticated_data` bytes (Q2 answered yes).

### 6.3 Removal latency

A removal is enforced on grants and sessions at once (`grants-v2.md` section 7). The MLS Remove follows as soon as any member device is online:

- The host pushes `pending_remove {seq}` to every connected device. The first device to commit wins.
- A sender that sees a pending removal older than 60 s commits it before sending its next application message.
- If no device is online, the removed device still cannot fetch new messages from the host (its session is refused), but it could decrypt messages a colluding member forwards. MLS secrecy for it starts at the Remove commit.

### 6.4 KeyPackages: publish, fetch and consumption

Every Add needs one KeyPackage of the added device: admissions, device links, rekeys (section 4.4), subgroup joins, leaf replacements and ReInit. The host stores KeyPackages and hands them out. It is trusted for availability only; the fetcher authenticates every package against the roster.

**Two pools per device.** `for: "current"` packages carry the device's current roster signing key as `deviceSig`. `for: "rekey"` packages carry the `newSig` of the device's pending `device.rekeyed` (`keys-rotation-recovery.md` section 4.1 step 2). When `device.rekey.approved` is sequenced, the host deletes the `current` pool (its `deviceSig` is now denylisted) and moves the `rekey` pool into it. When the rekey is vetoed or cancelled in the fold, the host deletes the `rekey` pool. When the device leaves the roster, both pools are deleted. The pools follow the fold, re-folds included (`keys-rotation-recovery.md` section 6.6 step 5).

**Publishing (`kp.publish`).** Only an active device, for itself. The host rejects the whole frame with `not_permitted` unless every package:

1. decodes strictly as an MLS KeyPackage of suite 1 whose capabilities list `0xF0A1`;
2. has a credential whose `identity` passes rules 1 to 5 of section 4.1, with the caller's `memberId` and `deviceId`;
3. has `deviceSig` equal to the caller's roster key (`current`), or to the `newSig` of the caller's pending, uncancelled `device.rekeyed` once that statement is sequenced (`rekey`);
4. has a signature that verifies with its leaf `signature_key`, and a leaf lifetime that has started and ends at most 30 days after publication;
5. has a KeyPackageRef (RFC 9420 section 5.2) the host has never stored for this room.

Limits: at most 10 single-use packages per pool, plus at most one last-resort package per pool. A new `lastResort` replaces the stored one. Publishing counts toward the per-device request budget (`enrollment-v2.md` section 5.4).

**When a device publishes.**

- As soon as it is active: after `enroll.admitted` (any admitting statement: `member.admitted`, `device.add.approved`, `member.device.replaced`), on the same session, before anything else. It publishes `current` packages, one per group it will join (the room group and each team scope of its member) plus one spare, capped at 10, and a last-resort package.
- When it requests a rekey: the same set for `rekey`.
- When the host pushes `kp.low` (single-use packages in a pool at 2 or fewer, or its last-resort package was served), and after it joins a group with its last-resort package: it tops the pool up and replaces the last-resort package.
- When it has a dead leaf (section 4.5): one fresh single-use `current` package for that group, whose KeyPackageRef it names in `device.leaf.repair.requested`.

**Fetching (`kp.fetch`).**

- **Who** (decisions round 7, item 2). Any active device of the current roster may fetch `current` packages of devices it shares a group with: every active device shares the room group, and a device whose member is in a team scope also shares that scope's subgroup with the scope's other devices. These are the committers allowed to Add (section 4.3). Only a device whose member has role `admin` may fetch `rekey` packages, because they are needed only to build the approval pair (section 4.4); after approval the `rekey` pool becomes the `current` pool. A `maintain` device keeps its right to fetch both pools for targets of `kind: "gateway"`.
- **Targets.** For `current`, an active device of the current roster; for `rekey`, a device with a pending, uncancelled rekey. Any other target, a `rekey` target from a caller that is not an admin, or a target that shares no group with the caller makes the frame `not_permitted`.
- **By reference** (decision round 8, item 1). A target `{memberId, deviceId, ref}` asks for the one package with that KeyPackageRef. The host serves it only while the device has an open `device.leaf.repair.requested` naming that `ref`, only to an active device that shares the request's group with the target, and as a single-use package (deleted when served). It never substitutes another package. If the package is gone (served to another repairer, or never published), the result is empty and the device publishes again and signs a new request after the 1 h interval.
- **Single use.** The host deletes each single-use package at the moment it serves it. It never serves it again, to anyone, so two committers never receive the same single-use package from an honest host.
- **Last resort.** Served only when the pool has fewer single-use packages than `count`, to make up the rest. It is served as often as needed and kept until the device replaces it. It exists because a device stays out of a group until a package for it is used (section 4.2), and because draining (below) must not make Adds impossible: as long as a device has published once, an honest host can always give a committer a package for it. RFC 9420 section 10 allows such a reusable last-resort package (cited from memory, not rechecked offline). It is our own marking, not an MLS extension; other members cannot tell it apart.
- **None available.** The result for that target is empty. The host pushes `kp.low` to the device if it is connected. The fetcher builds no commit and, for a rekey, signs no approval (section 4.4). It retries every 60 s while the pending change exists and shows "Waiting for *<device>* to publish its keys." A pending add with no package for 24 h is shown to admins as "*<device>* has not finished joining. Remove it?", because the device stays out of the group meanwhile. It no longer blocks other commits (section 4.2).
- **Rate.** Per target device and pool, the host serves at most `g + 2` single-use packages per hour across all fetchers, where `g` is 1 plus the number of team scopes of the target's member (the host knows scopes from the plaintext `scope.membership.changed` statements). Since round 7 it also caps each fetcher: per fetcher, target and pool, at most `k` single-use packages per hour, where `k` is the number of groups the fetcher's member shares with the target's member (1 for the room group plus the shared team scopes). For a fetcher with role `admin`, and for `maintain` with gateway targets, `k = g`. Beyond either cap the host serves only the last-resort package. Fetches also count toward the caller's request budget.
- **Draining, rechecked for round 7.** Honest demand is one package per group, `g` in total, at admission or after a rekey approval. The 2 extra cover a committer whose commit lost a race and a lost reply. Opening `kp.fetch` to every device adds two kinds of extra demand. Honest racers: several devices may fetch for the same pending add before one commit is sequenced. The repair delay (section 4.4: 60 s, plus up to 60 s at random for devices that are not admins) makes this rare, and a racer that loses discards its package once the Add is sequenced. Hostile fetchers: a compromised device that is not an admin takes at most `k ≤ g` per target per hour, so alone it cannot exhaust the hourly cap and leaves at least 2 for honest committers. Several colluding compromised devices, or a compromised admin, can exhaust it, as before. In every case the fallback is the last-resort package, so Adds stay possible; the cost is weaker forward secrecy for the joins that use it, which the device sees and repairs by replacing the package. The global cap is therefore unchanged: raising it would help a drainer as much as honest racers. The per-fetcher cap is the only addition.

**Authentication by the fetcher.** The host's checks are not trusted. Before it uses a package, the fetcher checks steps 1 and 4 of publishing, that the credential's `(memberId, deviceId)` are the target's, and that the credential passes all of section 4.1 against the reference roster the commit will name (for a rekey, the predicted roster `s` of section 4.4). A package that fails is discarded and reported to the admin as a host fault, because the host should have refused it. ts-mls validates each added package again inside `createCommit` (section 4.1, observed in case (d)).

**Use.** A fetched single-use package goes into at most one group. If the commit that carries it is refused (`stale_*`), the fetcher may reuse it in its rebuilt commit for the same group, because at most one of those commits is sequenced. It discards the package once a commit carrying it is sequenced, or one hour after fetching. A last-resort package may go into several groups.

**Welcome routing.** A Welcome names each new member by KeyPackageRef in its plaintext `secrets` list (RFC 9420 section 12.4.3.1). The host computed the refs at publication, so it can deliver each Welcome through `welcome.fetch` to the devices whose packages it names. Not yet checked: that the ts-mls 1.6.4 decoder exposes those refs without group state (test 12).

**Attacks and limits.**

| Attempt | Result |
|---|---|
| A device that shares no group with the target, or that is not an admin, fetches `rekey` packages | `not_permitted` |
| A compromised device that is not an admin drains a device's `current` packages | At most `k` per hour, below the global cap `g + 2`; Adds stay possible through the last-resort package, with weaker forward secrecy for those joins (round 7, section 4.4) |
| A compromised admin device, or several colluding devices, drain them | Bounded by the global rate limit; Adds stay possible through the last-resort package. A compromised admin key can do worse by signing admissions; this adds nothing new |
| The host drops, withholds or deletes packages | Denial of service only: fetchers see empty results and admins see the waiting notices. The host can refuse any operation anyway |
| The host forges or alters a package | Fails the fetcher's checks: the credential is bound to `deviceSig` in the admin-signed roster, and the package is signed by the leaf key named in the credential |
| The host serves a package of an old key (before a rekey), a `rekey` package as `current`, or one from another room | Fails section 4.1 rule 6, 8 or 3 against the reference roster |
| The host replays a single-use package that was already used | The device deleted that package's private init key when it first joined, so it cannot open the Welcome. It refuses it and reports to the admin through the room session (section 9), then requests a repair of its own leaf, which any leaf of the group carries out (section 4.5); an admin may also replace the leaf. Bounded by the 30-day lifetime. A compromised device of the group can cause the same effect by using one package in two groups (section 4.4) |
| The host serves a package other than the one a repair request names | Fails the members' check of section 4.5 step 4 (KeyPackageRef differs from the request), so the replacement commit is rejected |
| The host serves the last-resort package while single-use ones remain | Several Welcomes are encrypted to one init key, which weakens forward secrecy for those joins. The device sees it (Welcomes naming its last-resort ref) and replaces the package after each use |

**Last-resort key lifetime.** The device keeps the last-resort private init key until it has replaced the package and no unacknowledged Welcome names it, and for at most 7 days after replacing it. Someone who steals the key before then can open the captured Welcomes encrypted to it, which give the group secrets of the joining epochs. A device replaces its last-resort package at least every 7 days.

## 7. Gateway members for seated agents (future)

Not built in M2. Fixed now so the formats do not change:

- A seated agent's gateway gets a roster device with `kind: "gateway"`, admitted by `seat.added {memberId of the agent owner, deviceId, agentRef, lanes}` (admin or `maintain`).
- Its leaf is in the room group (or only in a team subgroup) while seated. `seat.removed` removes it with a commit.
- The gateway's keys live on the node, under the node's KEK. The dedicated OS user recommendation applies (`identity-model.md` section 7.6).
- A seated agent sees decrypted chat. That is its purpose. What it may read is limited by `PromptPolicy` and the room tools (architecture section 6.3), not by MLS.
- Decision 2 applies: an agent that non-owners can prompt must run in a sandboxed runner.

## 8. State at rest

### 8.1 Sealing

- `encodeGroupState` output is sealed (`identity-model.md` section 7.2) with purpose `mls-state:<roomId>:<deviceId>[:<scopeId>]`, under a file key derived from the KEK that sits in the OS keyring.
- This protects the state, which contains the leaf's private keys and epoch secrets, against backups and disk theft. It does not protect it against same-user processes (decision 1, `identity-model.md` section 7.4). M1-RESULTS section 8 item 5 ("encrypt with a key derived from the device key") is withdrawn: that key sat next to the data.

### 8.2 Write ordering

1. Process a message into a new state in memory.
2. Seal and write the new state (temp file, fsync, rename, directory fsync).
3. Only then acknowledge the message to the host (`msg.ack {seq}`) and update the stored log head.

A crash between 1 and 2 reprocesses the message from the host. A crash between 2 and 3 re-delivers a message the state has already consumed; the adapter detects that by epoch and generation and drops it.

### 8.3 Key retention

`keyRetentionConfig`: `retainKeysForEpochs: 2`, `retainKeysForGenerations: 64`, `maximumForwardRatchetSteps: 1000`. Spike A measured state growth from retained receiver keys; these values bound it while tolerating short reordering. Old state files are not kept.

### 8.4 Rollback protection

The sealed state records `{epoch, logHead}`. On connect, `session.hello.ok` returns `lastAck`, the position this device last acknowledged (section 8.2). If the stored state is older than `lastAck`, it was restored from a backup or copied. The member refuses to use it and re-links the device (`identity-model.md` section 7.7). A host that lies about `lastAck` can only force a re-link or hide a restore; it gains no access.

## 9. Failure handling

| Situation | Member behaviour |
|---|---|
| Commit fails 4.1 or 4.2 | Do not advance. Raise `roster_mismatch` with the commit's `bodyHash`, sender `(memberId, deviceId)` if decryptable, and the reference roster. Keep receiving log entries. Show "Room security check failed. Messages are paused." |
| Two valid commits for the same epoch | Should not happen (host sequencing). If seen, it is host equivocation: `room-log-v2.md` section 6.3. |
| Welcome fails 2.3 or 4.1, or names a KeyPackage whose private init key the device no longer holds | Refuse to join. Report to the admin through the room session. If the tree already holds a leaf with the device's triple (a dead leaf), request a repair (section 4.5); an admin may also replace the leaf (section 4.3). |
| Joiner's epoch anchor check fails or times out | `epoch_fork`, `epoch_anchor_mismatch` or `epoch_unconfirmed` as in section 5.1. |
| Own leaf replaced without an own open repair request | `leaf_replaced_unrequested` (`room-log-v2.md` section 6.6). |
| Log entry references an unknown epoch | Fetch commits from the host; if missing after 30 s, `withholding`. |
| Removed device keeps sending | Host refuses its session. Members ignore messages from leaves absent from the reference roster. |

## 10. Tests (required before M2 ships)

1. **Removal regression** (ported from `spikes/security/src/mls-proto.ts`): after a Remove, the removed member cannot decrypt under the honest, forced, stale and zero-commit-secret attacks.
2. **Positive control:** the same test fails on `ts-mls@1.6.2` (installed under an alias in dev dependencies). The CI job asserts the failure.
3. **Authentication service:** forged credential, wrong `mlsSig`, valid credential for a device not in the reference roster, denylisted device, wrong room, missing reference roster: each rejected.
4. **Config re-attachment:** decode a state and process a ghost Add; rejected.
5. **Roster equality:** commit whose result has an extra leaf, a leaf with a swapped `memberId`, two leaves for one `(memberId, deviceId)`, a removed leaf whose triple is in the roster (outside an admin's leaf replacement), or a kept old-key leaf after a rekey approval: rejected; state not advanced. A commit by a device that is not an admin that leaves a pending add open, and one that resolves it with a valid package: accepted (round 7). An Add by a device that is not an admin of a device that already has a valid leaf: rejected.
6. **Authority extension:** Welcome with a different `adminSetHash`: rejected.
7. **Write ordering:** kill the process between steps of 8.2; restart; no message lost or double-applied.
8. **Subgroup isolation:** a room member outside a scope cannot process subgroup ciphertext (spike A.2 check, kept).
9. **Stale roster:** a commit that names a roster older than the current one is rejected by the host (`stale_roster`) and by members, including one whose leaf set equals that older roster.
10. **Device rekey (admin route, section 4.4):** an admin's Remove plus Add, naming the roster of the adjacent `device.rekey.approved`, is accepted, and the rekeyed device joins by Welcome; the same Remove plus Add from a device that is not an admin, as an ordinary commit after a host split, is accepted (round 7); a commit after the split that removes only the old-key leaf is accepted and leaves the device a pending add; a commit that names the post-approval roster without replacing the leaf is rejected by roster equality; the host refuses `device.rekey.approved` through `stmt.submit` and sequences the pair from `commit.submit` adjacently or not at all; a Welcome built after the rekey validates with no previous-key exception; with another device's add pending, the daemon's commit carries that Add too, and a pair without it fails the daemon's own check and is not submitted; a host that sequences the statement and then any other entry raises `withholding`, and an admin's repair commit is accepted. **Continuity:** an UpdatePath whose leaf changes `memberId`, `deviceId`, `deviceSig` or `mlsSig` (built in test code with a forked `createCommit`; production code never forks it) is rejected after processing with the state not advanced, including when the authentication service accepts the new credential.
11. **`mls-rekey-updatepath-welcome`** (offline unit test under `spikes/security`, ts-mls 1.6.4, no network; must run **first**, before the adapter is written; decisions round 4, item 4). Three members A, B, C. Cases: (a) B commits an UpdatePath whose new leaf has a new credential: record whether ts-mls accepts it and whether `validateCredential` receives the new credential; with the callback returning `false`, the commit must be rejected; (b) the same with a changed `deviceId`: our callback rejects it; (c) after B's rekey is approved in the test roster but before B's UpdatePath, A adds D and D processes the Welcome: record whether it fails without the `prevSig` rule and succeeds with it; (d) record whether ts-mls passes unchanged leaves to `validateCredential` while processing a commit. Outcomes: if (a) shows that a credential change is refused or not validated, device rekeys use only the admin fallback (`keys-rotation-recovery.md` section 4.1); if (c) cannot pass with the `prevSig` rule, the first Add after a rekey approval carries the fallback for every device still on its `prevSig`. The results go into `spikes/security/RESULTS.md` and this section.

    **Results (2026-10-29, executed offline on ts-mls 1.6.4 and 1.6.2, Node 24.20.0; details in `spikes/security/RESULTS.md`, section "Identity v2 Step 0, Spike A").**

    *Observed* in the runs:

    - (a0) The public `createCommit` produces an UpdatePath with a new HPKE key but a byte-identical credential and the same signature key. The public API cannot emit a rekey UpdatePath.
    - (a) With a forked `createCommit` (spike code only), receivers accept an UpdatePath whose leaf has a new credential and leaf key; `validateCredential` receives the new credential (`processMessages.js:136`); a `false` answer rejects the commit and leaves the receiver's state unchanged.
    - (b) The `IncomingMessageCallback` gets only `{kind, proposals, senderLeafIndex}` and never the UpdatePath leaf. The authentication service rejected the changed `deviceId` (device not in roster). With an accept-all service ts-mls accepted it, and only a comparison of the sender's leaf before and after processing detected it.
    - (c) D's Welcome fails without the `prevSig` rule and succeeds with it, when B's rekey is approved but B's leaf still has the old key.
    - (d) During commit processing ts-mls passes only the committer's UpdatePath leaf and added KeyPackage leaves to `validateCredential`; during a Welcome, the GroupInfo signer and then every leaf.
    - (a-stale) A post-approval UpdatePath that keeps the old `deviceSig` is classed "unchanged" by the round-4 rule and accepted through the `prevSig` exception.
    - (e) Commits are PrivateMessage, and their authenticated data decodes without group state (Q2: yes).
    - (f) The removal regression passes on 1.6.4 and fails on 1.6.2.
    - (g) Results are identical with `@noble/*` 2.4.0.

    *Source reading, not run:* `createUpdatePath` copies `credential` and `signaturePublicKey` from the existing leaf (`updatePath.js:37-40`).

    *Inferred and applied in this revision* (decisions round 6), not run as a whole: device rekeys use the admin route with public APIs only (section 4.4), so test 10 replaces the UpdatePath rekey; the continuity check runs after processing (section 4.2 step 4); leaf identity includes `deviceSig`, which removes the `prevSig` exception (section 4.1 rule 6, section 4.4); the floor is ts-mls 1.6.4 (section 1). The admin route's Remove plus Add and its Welcome were not run in Spike A; test 10 covers them.

12. **KeyPackages (section 6.4):** the host refuses packages with a wrong `deviceSig`, member, device, suite, lifetime or a reused ref; a single-use package is served once; the last-resort package is served only when the pool is short, and the device can join two groups with it (not yet tried on ts-mls 1.6.4); `kp.fetch` gets `not_permitted` for a `rekey` target from a caller that is not an admin and for a target that shares no group with the caller; a caller that is not an admin gets at most `k` single-use packages per target per hour, then the last-resort package; the rate limit falls back to the last-resort package; the fetcher rejects a package whose credential fails section 4.1 against the reference roster; a Welcome for a replayed single-use package is refused and the leaf replacement commit is accepted; the host reads the KeyPackageRefs of a Welcome without group state and routes it.

13. **Joiner epoch check (section 5.1; decision round 8, item 2):** ts-mls 1.6.4 exposes the `epoch_authenticator` of the current epoch to the adapter through a public API (not yet checked; if it does not, the adapter derives it with the public key-schedule export, or this check waits for an upstream request); two members and a joiner of the same epoch compute equal `epochAuth`; a committer that sends the joiner a Welcome for a different epoch (built in test code) makes the joiner raise `epoch_fork` on the first undecryptable message whose anchor differs, and refuse to send; a member that puts a wrong anchor in a decryptable message is reported with `epoch_anchor_mismatch`; with no other member online the joiner raises `epoch_unconfirmed` after 5 minutes (fake clock).
14. **Leaf repair (section 4.5; decision round 8, item 1):** in a team subgroup with no admin leaf, a device whose Welcome named a replayed package signs `device.leaf.repair.requested`, a device that is not an admin fetches the named package by `ref` and commits the replacement, and members accept it; members reject a replacement whose package differs from the request, one that reuses a request, one after the device was removed, and one by a device that is not an admin with no request; a device whose leaf is replaced without its own request raises `leaf_replaced_unrequested`.

## 11. Open questions

- **Q1.** Who commits Adds in the pair deployment when the owner's daemon is offline? Admission waits for the admin anyway (SAS needs the owner). Since round 7, once a device is admitted any device of the room group may commit its Add (section 4.3).
- **Q2.** Answered yes by Spike A case (e), observed: commits are PrivateMessage when `wireAsPublicMessage` is false, and `decodeMlsMessage` reads the authenticated data without group state. Not tried: a tampered commit.
- **Q3.** ts-mls 2.0 migration timing. The adapter limits the change, but 2.0's codec changes alter state encoding; a state migration or group ReInit will be needed.
- **Q4.** Should the host verify commit signatures on PublicMessage-framed commits so it can reject garbage early? That would require PublicMessage framing and leak proposal contents to the host. Proposed: no.
- **Q5.** An independent review of the adapter and the library's commit path before release (spike A.4 risk 1).
- **Q7.** Answered yes in round 7, item 2, with the proposed rule: a commit is valid when its leaf set equals the reference roster minus devices that have no leaf yet, and every leaf absent from the roster is removed (section 4.2, rules 1 to 3). Old-key leaves must still be removed, so no Welcome contains one and the `prevSig` exception stays unnecessary. Cost: a commit can leave a device out of a group until some device of the group adds it, which a malicious member could not cause but could prolong by committing first (section 4.4, "What a compromised device that is not an admin can do afterwards").
- **Q6.** Answered by test 11 (Spike A): ts-mls validates a changed UpdatePath credential on receipt and does not check continuity, but its public API cannot send one. Device rekeys therefore use the admin route (section 4.4). Still unchecked: whether ts-mls 2.0 exposes credential change through the public `createCommit` (upstream request, `README.md` section 6), and the RFC 9420 text on updated credentials, which was cited from memory.
