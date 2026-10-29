# Narrow re-review: identity v2 specs after revision

- **Date:** 2026-10-29
- **Reviewer:** independent; did not write the specs or the first review.
- **Scope:** the sections changed in response to `identity-v2-review.md` (S-1 to S-23), as mapped in `docs/specs/identity-v2/README.md` section 10, plus the round 3 decisions in `HARDENING-PLAN.md` and the regenerated vectors.
- **Method:** read-only reading of the specs; one run of the vector generator; an independent recomputation with `node:crypto`; static reading (not execution) of ts-mls 1.6.4 in `spikes/security/node_modules/ts-mls`. No spec was edited. Nothing touched `~/.paseo`, a daemon or the network.

## 1. Verdict

**Ready with small fixes, but fix R-1 to R-3 before any code.** Most findings are closed, and the deliberate deviations are sound in principle. Three new high findings remain. Each needs only a paragraph or a fold rule. Each also undercuts a property the revision claims:

- **R-1:** A host can hold back a signed statement and sequence it later, once the state has returned to the statement's `prev*` value (an "ABA" replay). This is the residue of S-1.
- **R-2:** Device A picks the confirmer nonce, but only the host, which is the adversary in this case, limits attempts. A malicious host can therefore grind link attempts until the SAS matches. This undoes the S-13 addition.
- **R-3:** Round 3 decision 5 can be bypassed with a single stolen admin key. The key can add a second admin key, or install a recovery key, and then close the room.

After these fixes, a spot check of the edited paragraphs is enough. Another full re-review is not needed.

## 2. Verified facts (executed)

| Check | Result |
|---|---|
| `node gen-vectors.mjs` with system Node 18.19.1 | Exit 2 with a clear message naming the Paseo command (S-19 fix works). |
| `ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin gen-vectors.mjs` (Node 24.20.0) | Exit 0, all self-checks pass. `vectors.json` was copied to `/tmp` first. The rewritten file is **byte-identical** (`cmp`); file sha256 `ff2c8ff7…4e54d`. The generator prints `b925f6c6…58f6`, which is the sha256 of compact `JSON.stringify(out)`, not of the file. That is harmless but confusing (R-12). |
| Independent recomputation (`/tmp/rr/check.mjs`, Node 18 `node:crypto`, own canonicalizer, no generator code) | **69 of 69 match.** Statement signatures with `base` for `member.role.changed`, `room.policy.changed`, `member.left` and the creator's `member.admitted`. Each of these fails under a wrong context and fails with a tampered `base`. Also: all five log entries (hash, `hsig`, `prev`, `bodyHash`, base rule); `prevPolicyHash` equals `H("policy", genesis.policy)`. Device link: `prl2.` code, `linkRef`, link `tokenKey` (HKDF), `h` equal to the IK handshake hash, `EnrollSigned` signature by the phone key, token MAC, `sasCommit`, SAS info, key, digits `973313` and transcript. `device.added`: its signature, the `newKeySig` under `key-change-new`, `old = null`, the transcript and `linkRef` match, and its `bodyHash`. `device.add.approved`: its signature, `ref`, and a `ts` gap of at least 24 h. Fold checks: the role chain hashes, and the replay case reuses the earlier `bodyHash`. |
| ts-mls 1.6.4, static reading | `processMessages.js:136` calls `validateLeafNodeUpdateOrCommit` on `commit.path.leafNode`, which calls `authService.validateCredential` on the **new** leaf credential only. It does not compare the new leaf with the old one. Incoming commits do **not** re-validate the sender's existing credential. Welcome processing validates **every** leaf in the tree (`clientState.js:263-265`) and the GroupInfo signer (`:578`). Nothing was executed. |

**Not verified:** Noise vectors (not recomputed here); XChaCha ciphertext; any runtime behaviour of ts-mls; Windows, macOS, WSL and Docker behaviour.

## 3. Per-finding status

| ID | Status | Where checked | Notes |
|---|---|---|---|
| S-1 | **Partial** | room log 2, 4, 5 | Exact replays of sequenced statements are blocked by the unique rule, and cross-fork replay by `base.hash`. A statement that was signed but never sequenced has no freshness bound, and `prev*` values are vulnerable to ABA (R-1). Liveness is fine: `base` only has to be *in* the chain, not at the head, so concurrent admins conflict only on the same field (see 4.6). |
| S-2 | **Closed** | identity 6.2, 6.3; room log 4.3, 5; keys 4.1, 6.3 | The deviations are sound (section 4.1). There are small fold gaps: held adds are not cancelled in the fold when the requester is removed, and the member left with zero devices is undefined (R-8). |
| S-3 | **Partial** | enrollment 5.6, 7.3 | The pinning of `pending` is correct. The path "restart in state `keys`" keeps the original `h` on the host, but the member never stored it (R-4). |
| S-4 | **Closed** for invites | enrollment 5.4, 7.1 | For device links, the count is kept by the host, which is the adversary in S-13's threat (R-2). |
| S-5 | **Closed** | room log 4.2; enrollment 5.4 | `inviteRef` and `linkRef` are hashes of 128-bit random ids, so they cannot be brute-forced. |
| S-6 | **Closed** | MLS 4.2, 6.2 | The host's `stale_roster` keeps honest committers live. |
| S-7 | **Closed** | room log 6.3, 6.6 | |
| S-8 | **Partial** | room log 4.1, 5.1; keys 6.6, 6.8 | The position-based re-fold and R precedence are good. Three gaps: R's `fromSeq` is unbounded; a stolen admin key can install a first recovery key or add a second admin key and so defeat R3-5 (R-3); and `rosterSeq` after a re-fold is undefined (R-7). |
| S-9 | **Closed** | grants 4 step 5, 7.1 | |
| S-10 | **Closed** | enrollment 3.5 | Supersede only after key confirmation is correct for IK. |
| S-11 | **Partial** | keys 4.1; MLS 4.1, 4.3, Q6 | The design is right. Static reading suggests ts-mls allows a credential change in an UpdatePath. But Welcome validates every leaf, so a rekey that is approved but not yet committed breaks every join (R-5). |
| S-12 | **Closed** | identity 5.3 | It is honestly restated as a usability guard. |
| S-13 | **Closed (formats); new problem** | identity 6.4; vectors | It is complete enough to implement. A-side attempt limits are missing (R-2). |
| S-14 | **Closed** | identity 6.1; room log 5; vectors | The edge case after a re-fold is R-7. |
| S-15 | **Closed** | room log 3; keys 3, 4.5 | |
| S-16 | **Closed** | grants 13.2; room log 4.4 | It matches R3-2. The owner's gateway applies the flag, so another admin cannot reveal names even by signing. |
| S-17 | **Closed** | grants 5; identity 5.1, 5.2.1 | The schema bounds 3600..43200 in genesis; the fold enforces the upper bound. |
| S-18 | **Closed** (items 2, 4, 5, 6, 7, 8 spot-checked) | enrollment 10; grants 2; identity 7.2, 8 | |
| S-19 | **Closed** | signatures 9; vectors | There are no vectors yet for revocation re-fold, `room.closed` or vetoes (R-12). |
| S-20 | **Partial** | identity 7.8; grants 7.3, 8; migration 2.2 | Items 1, 2 and 4 to 6 are fine. The heartbeat lock lacks an ownership check and an atomic takeover (R-6). Monotonic pruning is safe but may never prune (R-11). |
| S-21 | **Closed** | enrollment 5.4; grants 11 | |
| S-22 | **Closed** | signatures 2.1; vectors | All three reject vectors are present. |
| S-23 | **Closed** | grants 7.2 | |

Counts: 15 closed, 6 partial (S-1, S-3, S-8, S-11, S-20, and S-13 with a new problem). Several partials are new problems caused by the fix rather than the original issue left open.

## 4. The deliberate deviations

### 4.1 S-2: veto, `member.left`, rekey hold, young devices

- **The veto cancels the add and flags a conflict instead of removing the requester.** This is sound, and it is the only reading consistent with R3-1, under which a device removes only itself. A stolen device can veto honest adds, but that only pauses auto-approval until an admin acts. This is a denial of service with an audit trail, which is acceptable.
- **`member.left` only from a member's only device.** This is sound, because otherwise a stolen device could remove its siblings through `member.left`. Two costs remain. A thief who holds a copy of a sole device can still make the member leave, but the same thief could already self-remove that device, so nothing new is exposed. And two devices that remove themselves concurrently can leave the member with zero devices, which is undefined (R-8).
- **Automatic rekeys are also held for 24 h.** This is sound. Without the hold, a thief's rekey would denylist the real device at once. The cost is a 24 h delay on routine rekeys. Admin approval is the fast path, which is fine.
- **Devices younger than 24 h cannot request auto-adds.** This is sound and needed. Otherwise a thief could add B, then use B to add C, and each hop could be timed to land after the person stops watching.
- **Enforcement.** The fold checks the 24 h rules against host `hts`, which members cannot verify. The spec says so and puts the real enforcement on the admin daemon. In the embedded deployment the admin daemon and the host are the same process, so this is adequate for v2.

### 4.2 S-8: `admin.reaffirmed` removed

This is sound. Re-applying an old statement would conflict with the unique rule. A fresh statement with current `prev*` values is cleaner. The cost is that an admin re-issues by hand after a revocation, and the UI should offer "re-issue these" from the suspect list.

### 4.3 S-12: UI confirmation is a usability guard

This is correct and honest. A typed-back code would not help against same-user code, which can read it. There is nothing further to do within decision 1.

### 4.4 S-13: the confirming device picks the nonce

I checked the argument and it holds for a **single** attempt. Real B commits to `Nm_B` before it gets a nonce. A pins B′'s `h` and commitment before it sends `Nc`. So neither SAS can be steered within one attempt. The guarantee depends on A bounding the number of attempts itself, which the spec leaves to the host (R-2).

### 4.5 S-20: heartbeat lock and monotonic pruning

- **Heartbeat lock.** The staleness test compares the lock's modification time with the checker's wall clock. A forward clock step can make a live lock look stale. The "wait one interval and check that the time did not move" step catches this, provided the holder is not stalled. A holder can be stalled for longer than 10 s by laptop sleep, VM or WSL2 suspend, SIGSTOP, a debugger or a long synchronous operation. When it wakes, nothing in the spec makes it notice that it lost the lock, so two writers append. Each writer signs its own entry at the same `seq`. That is a valid equivocation proof, so members raise `fork` against an honest host, and the log files interleave. Takeover is also not atomic: two waiters can both "replace" the lock. Fixes are in R-6. On Windows, `utimes` and `wx` work through libuv. On Docker bind mounts and WSL `/mnt/c` (drvfs), modification-time propagation can lag; the wait margin should cover it. The design is otherwise OS-neutral, which was the point.
- **Monotonic pruning.** This is safe in every case I can think of: no premature pruning, because the monotonic clock never jumps forward. On Linux and macOS it also does not advance during suspend, which errs on the safe side. Across restarts the count resets, so on laptops that restart the daemon or sleep often, entries may never reach 24 h and the list grows without bound. Each entry is small and the allowlist is the real check, so this is only hygiene (R-11).

### 4.6 S-1 `base`: liveness

- **Concurrent admins.** `base` only has to be a verified position in the chain, not the head. Two admins conflict only when they change the same field, through `prev*`. `room.policy.changed` conflicts on any concurrent policy change because it hashes the whole policy. That is coarse but acceptable. One gap: an automatic re-sign after `stale_base` would silently overwrite the other admin's change ("lost update"). For interactive actions, `stale_base` should return to the confirmation dialog with the new current value (R-9).
- **Forks.** A statement bound to one branch cannot be sequenced on the other. That is the intended effect.
- **Stale base after a host restore or a torn tail.** The host answers `not_permitted` (room log 2), so the producer gets no hint. A producer whose `base` is a signed entry the host no longer serves holds truncation evidence (R-9).
- **Unbounded staleness.** Because `base` can be arbitrarily old, it gives no freshness. That is the root of R-1.

## 5. Round 3 decisions

| Decision | Implemented faithfully? | Notes |
|---|---|---|
| 1. 24 h hold and veto; a device removes only itself; admins remove any device | Yes | The extensions (rekey hold, young devices, `member.left` limit) are stated as consequences in README 7. That is reasonable, but they are the author's choices, and the user should know about them. |
| 2. Project names: lane owner only, admins can force hidden | Yes | |
| 3. Grant TTL fixed at 12 h; org can only shorten | Yes | |
| 4. 3 abandoned attempts burn an invite | Yes for invites | For device links, the counter lives on the host (R-2). |
| 5. `room.closed` needs R or a second admin; no undo | **To the letter, not in effect** | A single stolen admin key can add a second admin key (`admin.added`, possibly for a ghost member it admitted itself), propose with one key and confirm with the other. It can also install a recovery key (`recovery.key.rotated` from `null`) and close with it. README R3-5 claims "A single stolen admin key can no longer end a room" (R-3). README also says a single admin without R "cannot sign a closure", but identity 5.4 lets them add R and then close. |

## 6. New findings

| ID | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| R-1 | **high** | room log 2, 4, 5 | A statement that was signed but never sequenced has no expiry, and `prev*` values are vulnerable to ABA. Example: the admin promotes Bob (`prevRole: watch`). The host answers `internal` and keeps the signed statement. The admin re-signs, and the new statement is sequenced. Later the admin demotes Bob back to `watch`. The host now sequences the held promotion: `base` is still in the chain, the `bodyHash` is new, and `prevRole` matches again, so Bob is promoted. The same works for `prevLanes`, `prevShow`, `prevMemberIds`, and `prevPolicyHash` when a policy returns to an earlier value. Statements without a `prev*` field (`member.removed`, `lane.created`, `admin.removed`, `lane.closed`) can be replayed late with no check at all. The spec's claim that `prev*` "stop an old statement that was never sequenced" is false in the ABA case. | Two cheap fold rules. (a) **Version instead of value:** for state-setting statements, compare the position at which the target field last changed. For example, require `lastChangedSeq(field) ≤ base.seq` and drop the `prev*` values, or keep them for display only. Positions never repeat, so ABA is impossible. (b) **Monotonic base per producer:** reject a statement whose `base.seq` is lower than the `base.seq` of a statement by the same producer key that was already applied. Any held statement then dies as soon as the producer's next statement is sequenced. The host returns `stale_base` for both. Add an ABA vector (promote, demote, held promote) to `foldChecks`. |
| R-2 | **high** | identity 6.4; enrollment 5.4 | The S-13 argument assumes one attempt, but only the host counts attempts (`LinkRecord`), and in this threat the host is the adversary. A malicious host can push many `link.request`s with fresh B′ commitments, under new `pendingId`s and in parallel. A answers each one with a fresh `Nc` automatically. For each answer the host computes A's SAS from its own `Nm′` and drops the attempt (no `link.reveal`) unless the SAS matches the code real B already shows. About 10^6 tries are expected, and A answers in milliseconds. A 10-minute link allows a meaningful success rate, and parallel attempts raise it further. Then A shows a code that matches B, and the person signs B′'s keys. | **A enforces its own limits.** A sends at most one `Nc` per `pendingId`, at most one open pending per link at a time, and at most 3 `Nc` per `linkId` in total, after which A treats the link as burned locally. A persists these counters and the pinned `(pendingId, h, sasCommit, Nc)` in its sealed state before it sends `link.nonce`. On a re-pushed `link.request` with the same `pendingId` and different inputs, A aborts. Show "N earlier attempts" on A as on the admin card. Add a test: a fourth `link.request` gets no nonce. |
| R-3 | **high** | room log 4.1, 5.1; keys 4.3, 6.8; identity 5.4 | R3-5 can be bypassed in three ways. (1) A stolen admin key A1 signs `admin.added` for a second key A2 (or first admits a ghost member). It then proposes with A1 and confirms with A2. (2) In a room without R, A1 installs its own R through `recovery.key.rotated` from `null`. R then closes alone. (3) The bounds of room log 5.1 step 1 apply only when an admin key signs. An R installed late can therefore revoke the honest admin with `fromSeq` at the start of the room, voiding all of their statements. Closure is final, so a later revocation cannot undo it. | (a) **Independent confirmer:** the confirming admin key must have been active before the proposal, and it must not descend from the proposing key (record `addedBy` per admin key; genesis keys have no parent). (b) **Bound R like admins:** an R's `fromSeq` must not be earlier than the position where that R became valid. (c) **First R in a room with two or more admins** needs the same propose-and-confirm as closure. With exactly one admin, that admin alone may install it, since the power is equivalent. (d) Optionally require at least 24 h between `room.close.proposed` and `room.closed`, so that R or another admin can revoke a thief first. This is a delay, not an undo window; ask the user (Q1). Also fix README R3-5 and keys 6.8: a single admin can close today by first adding R. |
| R-4 | medium | enrollment 5.6 ("Restart before `enroll.pending` arrived"), 7.3 | In journal state `keys` the member has not stored `h`, because it persists before opening the socket. After a crash it sends a new request with `h′`. The host answers `enroll.resume.ok` and "keeps the original `h` for the SAS". But `enroll.pending` does not carry `h`, so the member computes with `h′` and the codes never match. The result is safe, because the invite burns, but an honest member whose daemon restarts at the wrong moment always fails. Letting the host re-pin `h′` instead would be unsafe: a man in the middle playing the member could reconnect to grind `h′`. | Store `h` in the journal right after the handshake and before sending `enroll.request`. Or include the pinned `h` in `enroll.resume.ok`. That is safe for the member because `Nm` is still unrevealed, so a man in the middle cannot steer the member-side SAS. Add the test "crash in `keys` after the request was sent; resume shows matching SAS". |
| R-5 | medium | MLS 4.1 rule 6, 4.3; keys 4.1 step 7 | By static reading of ts-mls 1.6.4, Welcome processing validates **every** leaf credential against our authentication service (`clientState.js:263-265`). After `device.rekey.approved`, and until that device commits its UpdatePath, its leaf carries the old `deviceSig`, which rule 6 rejects against the reference roster. Every Welcome in that window fails, and new members cannot join while any rekeyed device is offline. MLS 4.1 also says ts-mls validates "commit signers". It does so only for the GroupInfo signer, not for the sender of an incoming commit, so the role check in 4.3 must read the sender's leaf in the callback (the spec's callback approach already allows this). | Let the reference roster keep `prevSig` for a device from `device.rekey.approved` until its UpdatePath lands, and let rule 6 accept `prevSig` for a leaf that is not being changed. Or require the first Add commit after a rekey approval to include the admin fallback (Remove plus Add) for any device whose rekey is still pending. Correct the 4.1 sentence about commit signers. Keep MLS Q6, but note the static-reading result: an UpdatePath credential change reaches `validateCredential` for the new leaf only, and no continuity check exists in the library, so our callback must enforce that `memberId` and `deviceId` are unchanged. Confirm by test. |
| R-6 | medium | grants 7.3 | Heartbeat lock: (1) the holder never re-checks ownership, so a holder that wakes after a suspense longer than 70 s keeps appending next to the new holder. That produces two host-signed entries per `seq`, a false `fork` for every member, and an interleaved file. (2) Takeover by "replace" is not atomic between two waiters. (3) A wait of exactly one heartbeat interval leaves no margin for timer jitter. | (1) Before every append, the holder reads the lock and compares its instance id; on a mismatch it stops serving the room and raises an error. (2) Take over by renaming the stale lock to a unique name (only one rename succeeds), then `wx`-create, then read back and check the instance id. (3) Wait at least 3 intervals (30 s). Remove the lock on clean shutdown, so a normal restart does not wait 60 to 90 s. |
| R-7 | low | room log 5, 5.1 | When a re-fold changes the roster, the revocation entry at `r` is not marked as roster-changing. `rosterSeq` then names an older position whose roster hash differs from the hash members had witnessed for that same `seq`. The result is two hashes for one roster position, which confuses `log.witness` comparison and the MLS AAD check. | A revocation whose re-fold changes the roster sets `rosterSeq = r`. Add a vector. |
| R-8 | low | room log 4.3, 5; identity 6.1, 6.4; keys 6.1 | (1) Held `device.added` and `device.rekeyed` are cancelled in the fold only for a compromise removal (keys 6.3). Identity 6.4 step 8 has the host close the pending when A is removed, but the fold would still accept an admin-mode approval that names it. (2) `device.removed` of a member's last device (self, or by an admin) leaves a member with zero devices, but `RosterEntry.devices` is 1..8. Keys 6.1 step 3 assumes that a member with zero devices exists. | (1) Fold rule: removing or rekeying the requesting device cancels its pending adds and rekeys. (2) Either reject `device.removed` of the last device from D (use `member.left`) and allow zero devices only after an admin removal, documenting 0..8, or convert it to `member.left` or `member.removed`. |
| R-9 | low | room log 2; enrollment 10 | (1) A `base` that is not in the host's chain, or that lies beyond the host's head, gets `not_permitted`. The producer may hold a signed entry the host no longer serves, which is evidence of truncation. (2) An automatic re-sign after `stale_base` can overwrite a concurrent admin's change. | (1) Add `unknown_base` with `head`, and have the producer run the truncation check of 6.4. (2) For interactive actions, `stale_base` returns to the confirmation dialog with the new current value. Policy-automatic actions recompute and re-sign. |
| R-10 | low | room log 4.3; vectors `deviceLink` | In the vector, `device.add.approved` has `base.seq` 3, which is below any position its `ref` could occupy. The fold does not require the approver to have seen the request. | For statements with `ref`, require `base.seq ≥` the seq of the entry that carries `ref`. Regenerate the vector. |
| R-11 | low | grants 8; identity 7.8 | (1) Monotonic pruning resets at every restart, so it may never prune on laptops (safe; the list grows). (2) Windows check `fs.realpathSync.native(path) === path` will report false positives when only the casing of the path or the drive letter differs. | (1) Persist the accumulated held time per entry, or also prune when the wall clock is more than 30 days past `exp`, together with any held time. (2) Compare after case-folding and normalising the drive letter on Windows, or check `FILE_ATTRIBUTE_REPARSE_POINT` per component instead. |
| R-12 | low | signatures 9; vectors | There are no vectors for `admin.key.revoked` with a re-fold (the most complex fold logic), `room.close.proposed` with `room.closed`, `device.add.vetoed` or `device.conflict.resolved`, `recovery.key.rotated` from `null`, or the ABA case of R-1. The generator prints the sha256 of compact JSON, not of the file. | Add fold vectors for the re-fold (suspect plus void, R precedence) and for closure. Print the file hash, or label the printed hash. |

Counts: 3 high, 3 medium, 6 low.

## 7. Residual risks the author flagged

1. **A single admin without a recovery key cannot close a room.** This is mostly not true as written: identity 5.4 lets that admin add a recovery key and then close. That path is acceptable in a single-admin room, because the admin already holds every power, and it is the cheapest mitigation. Document it in keys 6.8 and README R3-5, and make the "Close room" flow in a single-admin room offer "create a recovery key to close". The R-3 fix (c) keeps this path for single-admin rooms while closing it for multi-admin rooms.
2. **A sole stolen device adds a thief device after 24 h with no veto.** This is real and inherent to "auto-approved by the same person". Cheap mitigations, in order:
   - Tell the person, at linking time and in help, that reporting a lost only device to an admin within 24 h cancels the hold. Removing A closes the pending add; make that a fold rule (R-8).
   - Make the owner notification for an auto-add by a member who has only one device more prominent ("Sam has only one device; it is adding another").
   - Optionally use a longer hold (for example 72 h) when the requester is the member's only device. That is a user decision (Q2).

   The strong fix, `deviceAddApproval = "admin"`, already exists as a policy.
3. **ts-mls 1.6.4 credential change through UpdatePath is unchecked.** Static reading suggests the library accepts it and calls `validateCredential` on the new leaf, with no continuity check of its own (section 2). That is what the spec needs, provided our callback enforces that `memberId` and `deviceId` are unchanged. The bigger risk is the Welcome side effect in R-5. Mitigation: a small local unit test under `spikes/security` (rekey by UpdatePath, then a Welcome while a rekey is pending) before implementation. The test needs no network. The admin fallback, Remove plus Add, remains as plan B.

## 8. Questions for the user

1. **Closure (R-3).** Do you accept these rules: the second admin's key must not have been added by the proposing key or its descendants; a first recovery key in a multi-admin room needs two admins; and a recovery key's revocation cannot reach back before the key itself was installed? Do you also want a minimum 24 h between proposal and closure? That is a delay before closure, not an undo window, but it changes decision R3-5 slightly.
2. **A sole device adding a second device (residual 2).** Keep 24 h for everyone, or use a longer hold when the requesting device is the member's only one?
3. **R-1 format.** May state-setting statements carry the position of the last change (a version) instead of, or in addition to, the old value? No v2 room exists, so this needs no migration.

## 9. Next steps

1. Fix R-1 to R-3 in the specs, then regenerate the vectors with the ABA, re-fold and closure cases.
2. Fix R-4 to R-6. Each is one paragraph.
3. Spot-check those paragraphs. A full re-review is not needed.
4. Before the MLS adapter: the ts-mls UpdatePath and Welcome unit test (residual 3 and R-5), alongside the existing open blockers (keyring packaging, PrivateMessage and AAD access, connected-host ping, RJCS cross-check in a second language).
