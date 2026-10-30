# Room log v2

- **Status:** proposed specification, not implemented.
- **Resolves:** A7 (P-7, M-1), P-27, C-11; the log side of P-3 and P-10.
- **Formats:** `signatures-and-encoding.md`. Vectors: `vectors/vectors.json` → `statements`, `log`, `deviceLink`, `deviceRekey`, `deviceLeafRepair`.
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): statement `base`, position-based revocation with re-fold, device hold and veto, invite references, fork only with proof. Revised again on 2026-10-29 after the re-review (`plugin/review/identity-v2-rereview.md`, decisions round 4): field versions instead of `prev*` values, producer `base` only moves forward, admin lineages and the closure rules, bounded recovery-key revocations, the 72 h hold for a sole device, and the roster position after a re-fold. Decision round 5, item 3 extends that hold, and policy `soleDeviceChange`, to rekeys (section 5). Decision round 6 (after Spike A): `device.rekey.approved` is submitted only together with its MLS commit and sequenced adjacent to it (section 2, section 4.3); the fold is unchanged. Decision round 8 (2026-10-29): `device.leaf.repair.requested` (section 4.3), keys that never return after a re-fold (section 5.1, step 9), a revocation nesting cap of 8 with a re-fold of linear cost (section 5.1, steps 3 and 8), the joiner's epoch alerts (section 6.6), and the rules the I-5 and I-6 implementation had chosen where this spec was silent (sections 4.1 to 4.4, 5, 5.1, 5.2).

## 1. Model

The room log is one append-only sequence per room. It carries three layers:

| Layer | Made by | Signed by | Purpose |
|---|---|---|---|
| **Statement** | the producer of an event (admin, device, host, gateway node) | the producer's key, context `stmt:<type>` | attribution: who decided or did what |
| **Entry** | the host, when it sequences a statement or an MLS message | the host key, context `log-entry` | order, hash chain, signed head |
| **Body** | a statement (plaintext, signed) or an MLS message (ciphertext) | as above, or MLS | content |

Chat messages, MLS commits and security events share the one sequence. That gives chat the same equivocation and truncation detection as membership events. Entries are small (about 350 bytes), and members fetch bodies only when they need them.

M1's log signed every event with the host key, including member actions (M-1). In v2 the host signs only the sequencing. A member action carries the member device's own signature, and an admin decision the admin key's.

## 2. Statements

```
Statement.body = {
  v: 2, typ: "stmt",
  type: <event type, section 4>,
  roomId,
  producer: { kind: "admin" | "device" | "host" | "node" | "recovery", kid },
  base: { seq, hash },                          // the log head the producer had verified when it signed
  ts: <unix ms, producer clock, display only>,
  data: { ... }                                  // per type, section 4
}
SignedStatement = { body, sig: b64u(Sign(producerKey, "stmt:" + type, RJCS(body))) }
```

- `base` binds the statement to a position in the chain (review finding S-1). `base.seq` is the `seq` of the newest entry the producer had verified and `base.hash` its `entryHash`. A producer that has seen no entry yet (the creator's first statement) uses `base = { seq: -1, hash: b64u(genesisHash) }`.
- **A producer's `base` only moves forward** (decision round 4, item 3; re-review finding R-1). Each producer key submits one statement at a time and waits for its receipt or a definite rejection before it signs the next. Its next statement then names a head at or after that receipt, so its `base.seq` is strictly greater. The fold rejects a statement whose `base.seq` is not greater than the `base.seq` of every earlier statement in the chain signed by the same key (section 5). A statement that the host held back therefore dies as soon as the producer's next statement is sequenced.
- **State-changing statements carry versions, not old values** (decision round 4, item 3). Section 4.0 lists which field each statement changes and the `ver` it must carry.
- Producers submit statements with `stmt.submit {statement}` on their room session, or (host and node) append them locally. The one exception is `device.rekey.approved`: it is submitted only inside `commit.submit {…, statement}` together with the MLS commit that applies it, and the host sequences the two as adjacent entries, written in one durable write, or neither (`mls-integration.md` sections 4.4 and 6.1; decision round 6). A host crash therefore cannot split them; a member that finds any entry other than an `mls.commit` right after a `device.rekey.approved` raises `withholding`, and an admin repairs the leaf (`mls-integration.md` section 4.4). `stmt.submit` refuses it with `not_permitted`. This is a sequencing rule for the host, not a fold rule: `apply` treats the statement exactly as before.
- The host validates before sequencing: strict parse; the producer key is valid for that `type` at the current head (section 4 matrix); the signature verifies; the `data` schema matches; the base, uniqueness and forward-base rules of section 5 hold; and `apply` (section 5) accepts the statement against the current state. The host answers:
  - `stale_base` with the current head when the statement failed only because the state moved: a `ver` no longer matches, or the forward-base rule failed. The producer re-reads the head and decides again (below).
  - `unknown_base` with the current head when `base` is not an entry of the host's chain (wrong hash, or a `seq` beyond the host's head). A producer whose `base` is a signed entry it verified, and that the host now does not serve, holds truncation evidence and runs the check of section 6.4 (re-review finding R-9).
  - `not_permitted` for every other failure. Rejected statements are not logged.
- **After `stale_base`** (R-9): an interactive admin action goes back to its confirmation dialog, which shows the new current value ("Bob's role was changed to *comment* by another admin. Still change it to *steer*?"). It is never re-signed silently, because that would overwrite a concurrent admin's change. Policy-automatic actions (`identity-model.md` section 5.3) recompute from the new state and re-sign only if the policy still calls for them.
- **After a lost reply** (`internal`, a dropped session or a timeout): the statement may or may not be sequenced later. The producer keeps it as **outstanding** in its sealed state, shows it as "not confirmed", and asks for the head with `log.fetch`. If an entry carries it, that entry is the receipt. If not, the producer's next sequenced statement makes it dead by the forward-base rule. To settle it at once, the producer signs a no-op `producer.fence` (section 4.8); once the fence is sequenced, the outstanding statement can never take effect, and the UI says "Not applied. Sign again?".
- On success the host returns a **receipt**: the signed entry that carries the statement. The producer stores it (section 6.4).

## 3. Entries

```
LogEntry = {
  v: 2, typ: "log-entry",
  roomId, seq: <0, 1, 2, ...>,
  prev: b64u(seq == 0 ? genesisHash : entryHash(seq - 1)),
  hts: <unix ms, host clock; never decreases along the chain>,
  epoch: <MLS epoch of the room group after this entry> | null,
  cls: "stmt" | "mls",
  type: <statement type> | "mls.commit" | "mls.app",
  bodyHash: b64u(H("log-body", bodyBytes)),
  hostKid
}
entryHash = H("log-entry", RJCS(LogEntry))
SignedEntry = { entry: LogEntry, hash: b64u(entryHash), hsig: b64u(Sign(hostKey, "log-entry", RJCS(LogEntry))) }
```

- `bodyBytes` is `RJCS(SignedStatement)` for `cls: "stmt"` and the raw `MLSMessage` bytes for `cls: "mls"`.
- `prev` of entry 0 is the `genesisHash`, so the chain is anchored to the room's authority.
- `hostKid` must name a host key that is valid **at this position** (`keys-rotation-recovery.md` section 3). Validity for entries is decided by position only: no entry after the entry carrying `host.key.rotated` or `host.key.revoked` for a key may be signed by that key, whatever its `hts` says (S-15).
- `hts` is monotonic: the host writes `max(its clock, hts of the previous entry)`, also across restarts (it takes the previous `hts` from the stored log). Holds and the closure delay are measured in `hts` (sections 4.3, 5, 5.2), so a host clock that steps back must not shorten or reverse them. The fold does not reject a decreasing `hts`; it is a host fault, like any other host clock error (section 5).
- Every `SignedEntry` is a **signed head**: the host commits to the whole chain up to `seq`. There is no separate checkpoint format.
- **Equivocation proof:** two `SignedEntry` values with the same `roomId` and `seq`, different `hash`, and valid `hsig` under host keys valid at that position. Anyone can verify it without trusting the reporter (vector: `log.equivocationExample`).

## 4. Event catalogue

Statement type names match `^[a-z0-9.-]+$` (lowercase letters, digits, `.` and `-`; words inside a segment are joined with `-`, never `_`), so the signature context `stmt:<type>` stays inside the context alphabet of `signatures-and-encoding.md` section 3.1. A type that broke this rule could not be signed; the fold rejects such a statement with `unsignable_type`. (`grant.suspected-theft` was first written `grant.suspected_theft`, which broke the rule; renamed after I-7.)

Producer kinds: **A** admin key, **D** device signing key (of the member concerned unless noted), **H** host key, **N** node key, **R** recovery key. "Roster" means the event changes the roster fold (section 5). "Authority" means it changes the authority state.

### 4.0 Field versions

The first revision carried the old value of the changed field (`prevRole`, `prevPolicyHash`, and so on). The re-review showed that values can return (R-1): an admin promotes Bob, the host holds the signed statement, the admin re-signs, later demotes Bob, and the host then sequences the held promotion, whose `prevRole` matches again. Decision round 4 (item 3) replaces old values with **versions**.

- The **version** of a field is the `seq` of the entry whose statement last changed it and took effect, or `-1` when the field still has its genesis value or has never been set. A suspect or void statement (section 5.1) does not change a version.
- A state-changing statement carries `ver`, the version of the field it changes as the producer saw it. `apply` rejects it unless `ver` equals the current version. Positions never repeat, so a held statement cannot match again after any later change, even one back to the old value.
- Members show the old value in notices by reading their own state; it is not in the statement.

| Statement | Field it changes | Initial version |
|---|---|---|
| `room.policy.changed` | each named setting, one `ver` per entry of `changes` | `-1` (genesis) |
| `member.role.changed` | the member's `role` | the member's admission entry |
| `member.lanes.changed` | the member's `lanes` | the member's admission entry |
| `member.device.replaced` | the member's device set | the last entry that added, removed or rekeyed one of the member's devices |
| `device.conflict.resolved` | the member's device conflict | the `device.add.vetoed` or `device.rekey.vetoed` entry that opened it |
| `scope.membership.changed` | the scope's member list | `-1` for a scope not yet defined |
| `lane.names.changed` | the lane's `showNames` | the `lane.created` entry |
| `lane.offer.rotated` | the lane's offer | the `lane.created` entry |
| `endpoint.rotated` | the room endpoint | `-1` (genesis) |

**Statements without `ver`.** These cannot be replayed into a returned state, because the object they name can be used only once or can never come back:

- Key changes (`device.rekeyed`, `admin.key.rotated`, `host.key.rotated`, `recovery.key.rotated`) name the current key in `KeyChange.old`. A key that was ever valid in the room can never be certified again for any subject (**retired keys**, section 5), so `old` works as a version.
- `member.removed`, `device.removed`, `member.left`, `admin.removed`, `admin.key.revoked`, `host.key.revoked` and `lane.closed` name a device, member, key or lane that cannot return once removed: device ids, member ids and lane ids are never reused, and retired keys are never re-admitted.
- Statements with `ref` (`device.add.approved`, `device.add.vetoed`, `device.rekey.approved`, `device.rekey.vetoed`, `room.closed`, `recovery.key.rotated` with a proposal) name one pending request by its `bodyHash`, which is closed after one use.
- Statements that create something (`member.admitted`, `lane.created`, `invite.created`, `device.added`, `admin.added`, `room.close.proposed`) are rejected if the object already exists or ever existed.
- Host and node statements (`grant.*`, `invite.burned`, `enrollment.*`, `lane.degraded`, and so on) change no roster or authority state that another producer sets.
- `device.leaf.repair.requested` changes no roster or authority state. Each one is a separate request, rate-limited per device and group, and used at most once by the MLS layer (section 4.3).

The forward-base rule (section 2) adds a second, independent barrier: a held statement dies as soon as its producer's next statement is sequenced, whatever it changes.

### 4.1 Authority

| Type | Producer | Plaintext `data` | Effect |
|---|---|---|---|
| `room.policy.changed` | A | `{ changes: [ { setting, value, ver } ] }`: the settings changed, sorted by `setting`, each with its new value and its version (section 4.0). Settings not named keep their values, so two admins who change different settings do not conflict. `minVersion` may only rise; `grantTtl` may not exceed 43 200; `closeDelay` is 0 to 518 400 (`identity-model.md` section 5.2.1). | Authority. Successor of M1's `room.policy.changed {setting, value}` (`../data-model.md`), which v2 does not import (`migration.md`). |
| `room.close.proposed` | A | `{ exp }` (unix s, at most 7 days ahead, and later than the earliest allowed confirmation, section 5.2) | none; shown to every member, with the earliest time it can be confirmed |
| `room.closed` | R, or A with a proposal | `{ proposal: bodyHash \| null }`. Signed by R with `proposal: null`, or by an admin key with `proposal` naming an unexpired `room.close.proposed` signed by an **independent** admin key, no earlier than `policy.closeDelay` after the proposal (section 5.2). | Authority, final: every session gets `access_ended room_closed`. Not reversible (decision round 3). |
| `admin.added` | A or R | `{ change: KeyChange, newKeySig }` with `change.subject = {kind:"admin", id: memberId}` and `change.old = null` | Authority. Records `addedBy` and the new key's lineage (section 5.2). Rejected if the key is retired |
| `admin.removed` | A (another admin) | `{ kid }` | Authority; `kid` to the admin-key denylist |
| `admin.key.rotated` | A (old key) | `{ change: KeyChange, newKeySig }` | Authority; old key to the admin-key denylist |
| `admin.key.revoked` | A (another admin) or R | `{ kid, fromSeq }` | Authority; section 5.1 (bounds and the nesting cap of 8 apply to R as well). `kid` to the admin-key denylist. A key that is already retired (rotated out or removed) may still be revoked, once, so that its statements in the window can be made suspect. Only R may leave the room with no active admin key (section 5.1, step 4) |
| `recovery.key.proposed` | A | `{ change: KeyChange, newKeySig, exp }` with `change.old = null`; `exp` at most 7 days ahead. Valid only while the room has no recovery key | none; shown to every member |
| `recovery.key.rotated` | R (old), or A when the room has no recovery key | `{ change: KeyChange, newKeySig, proposal: bodyHash \| null }`. `change.old` is `null` when adding the first recovery key. `proposal` is `null` when R signs or when the room has one admin lineage; with two or more lineages it names an unexpired `recovery.key.proposed` with the identical `change`, signed by an admin key independent of the signer (section 5.2) | Authority (`identity-model.md` section 5.4) |
| `host.key.rotated` | A | `{ change: KeyChange, newKeySig, oldValidTo }` (`oldValidTo`: unix s, for grants only) | Authority |
| `host.key.revoked` | A | `{ kid, fromSeq }` | Authority; section 5.1. `kid` must already be rotated out: the current host key is rotated with `host.key.rotated` first (`host_key_current`), because no key would be left to sign the next entry. The bounds of section 5.1 step 1 apply, including the revoking admin key's authority start. A host key is revoked at most once |
| `endpoint.rotated` | A | `{ serverId, dh, relay, ver }` | Authority |
| `endpoint.evicted` | H | `{ serverId, count, windowS }` | none (P-16 alert) |
| `node.certified` | A | `{ key, nodeRef }` | Authority (reserved) |

**Admin keys act with role `admin`.** An admin key is the authority of role `admin`, the highest role, whichever member's id its `KeyChange.subject` names. The rule "no role above the producing admin's own" (section 5) therefore never rejects a statement signed by an admin key; it exists for producers with a lower role (the reserved `maintain` statements).

**New keys are fresh.** A key that a statement certifies or installs (`admin.added`, `admin.key.rotated`, `recovery.key.proposed`, `recovery.key.rotated`, `host.key.rotated`, `endpoint.rotated`, `lane.created`, `lane.offer.rotated`, and every device key) must be neither retired nor equal to any key currently in use in the room for any subject: admin, recovery, host, endpoint, lane and device keys, signing and DH alike. A device's signing and DH keys must also differ from each other (`key_reused`).

`admin.reaffirmed` from the first draft is removed. Statements made suspect by a revocation no longer take effect at all (section 5.1); an admin who wants to keep one re-issues it as a new statement.

### 4.2 Invites and enrollment

Invite and link ids never appear in the log or in MLS. The log carries `inviteRef = b64u(H("invite-ref", utf8(inviteId)))` and `linkRef = b64u(H("link-ref", utf8(linkId)))` instead, so a member who reads the log cannot name an open invite in an `enroll.request` and burn it (S-5).

| Type | Producer | Plaintext `data` | Effect |
|---|---|---|---|
| `invite.created` | A | `{ inviteRef, role, lanes, exp }` | none |
| `invite.revoked` | A, or D for a link | `{ inviteRef }` or `{ linkRef }` | none. An admin may revoke any invite or link. A device may revoke only a link (`linkRef`), and only one created by a device of its own member (`device.link.created` with the same `memberId`) |
| `invite.expired` | H | `{ inviteRef }` | none |
| `invite.burned` | H | `{ inviteRef, reason: "attempts" \| "abandoned" \| "sas_mismatch" }` | none |
| `invite.contested` | H | `{ inviteRef, pendingId }` | none (alert) |
| `enrollment.pending` | H | `{ inviteRef \| linkRef, pendingId, deviceKid }` | none |
| `enrollment.closed` | H | `{ pendingId, reason }`, where `reason` takes exactly the values of `enroll.closed` (`enrollment-v2.md` section 5.2): `"rejected"`, `"timeout"`, `"invite_revoked"`, `"room_closed"`, `"aborted"`, `"vetoed"` | none |
| `device.link.created` | D | `{ memberId, linkRef, exp }` | none |

The same `.burned`, `.expired` and `.revoked` events with `linkRef` in place of `inviteRef` apply to device links (`identity-model.md` section 6.4).

### 4.3 Membership

| Type | Producer | Plaintext `data` | Effect |
|---|---|---|---|
| `member.admitted` | A | `{ member: RosterEntry, confirmation: { method: "sas6" \| "creator" \| "sso-v1", inviteRef?, transcript? } }`. `"creator"` is valid only at `seq` 0, and `seq` 0 must be the creator's admission. `member.devices` has 1 to 8 entries. A `memberId` that was ever in the roster is rejected | Roster: add member |
| `member.role.changed` | A | `{ memberId, role, ver }` | Roster. A downgrade revokes grants (`grants-v2.md` 7.1) |
| `member.lanes.changed` | A | `{ memberId, lanes, ver }` | Roster |
| `member.removed` | A | `{ memberId, reason: "admin" \| "compromise" }` | Roster: remove member; all device keys to denylist; the member's pending adds and rekeys cancelled. With `reason: "compromise"` (or policy `rotateLaneOnRemove = "always"`) the admin also rotates the member's lanes (`keys-rotation-recovery.md` 4.7) |
| `member.left` | D (the member's **only** active device) | `{ memberId }` | Roster: remove member; denylist; pending requests cancelled. A member with several devices leaves by removing each device (`device.removed`, self) until one is left |
| `member.device.replaced` | A | `{ memberId, removed: [deviceId], added: DeviceEntry, ver }` | Roster. Also restores a member left with no devices (`removed: []`, section 5). Cancels the pending requests and leaf repair requests of every removed device, as `device.removed` does |
| `device.added` | D (an active device of the same member) | `{ memberId, device: DeviceEntry, change: KeyChange, newKeySig, addedBy: deviceId, confirmation: { method: "sas6", linkRef, transcript } }` with `change.old = null` | none until approved; starts the hold: 24 h, or 72 h when the requester is the member's only active device (`identity-model.md` 6.3). `addedBy` is the signing device. `linkRef` must name a `device.link.created` of the same member, and a link adds at most one device (`unknown_link`, `link_used`). The `deviceId` is reserved from this entry on, whether the add is later approved, vetoed or cancelled |
| `device.add.vetoed` | D (any active device of the same member) | `{ memberId, ref: bodyHash }` | the add is cancelled; the member gets a device conflict |
| `device.add.approved` | A | `{ memberId, deviceId, ref: bodyHash, mode: "auto" \| "admin" }` | Roster: add device |
| `device.removed` | A, or D **for itself only** | `{ memberId, deviceId, reason: "lost" \| "admin" \| "compromise" \| "self" }` | Roster: remove device; denylist; cancels the device's own pending rekey and every pending add or rekey it requested. `"compromise"` triggers lane rotation as for `member.removed`. A device may not remove itself when it is the member's last device (it signs `member.left`); an admin may, which leaves the member with no devices (section 5) |
| `device.rekeyed` | D (old key) | `{ change: KeyChange, newKeySig }` | none until approved; starts the hold: 24 h, or 72 h when the device is the member's only active device (`keys-rotation-recovery.md` 4.1) |
| `device.rekey.vetoed` | D (any active device of the same member) | `{ memberId, ref: bodyHash }` | the rekey is cancelled; the member gets a device conflict |
| `device.rekey.approved` | A | `{ memberId, deviceId, ref: bodyHash, mode: "auto" \| "admin" }` | Roster: replace keys; old keys to denylist. The next entry is the MLS commit that replaces the device's leaf (section 2; `mls-integration.md` section 4.4) |
| `device.conflict.resolved` | A | `{ memberId, ver }` | clears the member's device conflict; `ver` names the veto that opened it |
| `device.leaf.repair.requested` | D (the affected device itself) | `{ memberId, deviceId, group: { scope: scopeId \| null, generation }, keyPackageRef }` | none in the fold. Asks that the device's leaf in that MLS group be replaced by a leaf built from the KeyPackage whose KeyPackageRef (RFC 9420 section 5.2) is `keyPackageRef`; any leaf of the group may then commit the replacement (`mls-integration.md` sections 4.3 and 4.5; decision round 8, item 1). Rules below |
| `scope.membership.changed` | A | `{ scopeId, memberIds, ver }` | scope roster |
| `seat.added`, `seat.removed` | A (or D with role `maintain`) | `{ memberId, device: DeviceEntry, agentRef }` / `{ deviceId }` | Roster (reserved) |

A device conflict blocks every `mode: "auto"` approval for that member until `device.conflict.resolved`. A veto never removes a device: a device can remove only itself, and only an admin can remove another device (decision round 3).

**Vetoes block every approval.** A vetoed request is closed: `apply` rejects an approval that names it in mode `"auto"` and in mode `"admin"` alike (`vetoed`). An admin who still wants the device approves nothing; the device is linked again with a new request after `device.conflict.resolved`.

**Leaf repair requests** (decision round 8, item 1). `apply` accepts `device.leaf.repair.requested` only if:

- it is signed by the device it names: the producer is the active device `deviceId` of member `memberId` (`not_permitted` otherwise). No device can ask for another device's leaf to be replaced, and an admin key cannot sign it;
- `group.scope` is `null` (the room group) or a scope whose current member list contains `memberId` (`not_in_scope`);
- the same device has no earlier request for the same group (`scope` and `generation`) less than 1 hour of `hts` before this entry (`repair_too_soon`);
- the same device has fewer than 8 requests, for any groups, in the 24 hours of `hts` before this entry (`repair_rate`).

A request is open for 24 hours of `hts` after its entry and is used at most once. It is cancelled in the fold when the device leaves the roster (`device.removed`, `member.device.replaced`, `member.removed`, `member.left`, or a re-fold that drops it) and when its rekey is approved, because the device's credential then changes. As with the holds, the `hts` limits catch a careless host; the host enforces the same limits on its own clock before sequencing.

*Abuse analysis.* The statement can only name the signer's own leaf, so the worst a holder of one device's keys can do with it is to replace that device's leaf: at most once per group per hour and 8 times a day, each costing the group one commit. A thief who holds a device's signing key and session key could use it to swap the honest device's leaf for one of its own and so read that group's later messages as that device. The thief already has that device's signing key, which is the compromise case of `keys-rotation-recovery.md` section 6.3 (removal), and the statement adds no power over other devices. It is visible: every member sees the request (section 4.6), and the honest device, which never signed it, sees its own leaf removed by a replacement it did not ask for and raises `leaf_replaced_unrequested` (section 6.6), prompting the person to have the device removed.

**Pending requests are cancelled in the fold** (re-review finding R-8). A pending `device.added` or `device.rekeyed` is cancelled when its requesting device is removed or its rekey is approved (the request was signed by a key that is no longer current), when the device being rekeyed is removed, or when the member is removed or leaves. A cancelled request cannot be approved in any mode; `apply` rejects an approval that names it. So an admin who removes a person's stolen only device also stops the thief's pending add, whatever the host does.

### 4.4 Lanes and access

| Type | Producer | Plaintext `data` | Effect |
|---|---|---|---|
| `lane.created` | A | `{ laneId, owner: memberId, offer: { serverId, dh, relay }, visibility: "room" \| "team" }` | Authority (lane table). `owner` is the member whose gateway serves the lane |
| `lane.offer.rotated` | A | `{ laneId, offer, ver }` | Authority |
| `lane.names.changed` | D of the lane's `owner` | `{ laneId, show, ver }` | Authority (lane table). `show: true` is rejected while `policy.projectNames = "hidden"` (`grants-v2.md` 13.2) |
| `lane.degraded` | H or N | `{ laneId, reason: "agent_missing" \| "endpoint_failing" }` | none (C-13) |
| `lane.closed` | A, or H after `lane.degraded` for 24 h | `{ laneId }` | Authority; grants revoked |
| `grant.issued` | H | `{ memberId, deviceId, laneId, gid, exp }` | none |
| `grant.revoked` | H | `{ gid, reason: "superseded" \| "removed" \| "role_changed" \| "lane_closed" \| "host_key_revoked" }` | none |
| `grant.suspected-theft` | H | `{ memberId, deviceId, laneId, gid, reportedBy: "endpoint" \| "member" }` | none (alert) |

**Lane existence.** `lane.offer.rotated`, `lane.names.changed`, `lane.degraded` and `lane.closed` need a lane that a `lane.created` made and that is not closed (`unknown_lane`, `lane_closed`). A closed lane never reopens; a new lane gets a new `laneId`. Lane lists in `member.admitted`, `member.lanes.changed` and `invite.created` are not checked against the lane table: they may name lanes created later or since closed, and access is decided when a grant is issued (`grants-v2.md`).

### 4.5 MLS and content

| Type | Producer | Body | Effect |
|---|---|---|---|
| `mls.commit` | any device (entry by H) | MLS commit, PrivateMessage | epoch advances |
| `mls.app` | any device (entry by H) | MLS application message | content |
| `mls.stalled` | H | statement `{ epoch, sinceMs }` | none (alert) |

Application message payloads (inside MLS, invisible to the host) are RJCS objects with their own `kind`:

| `kind` | Content |
|---|---|
| `chat.message` | text, thread, mentions (M2 chat spec) |
| `member.profile` | `{ memberId, label }` (labels never appear in plaintext) |
| `room.profile` | `{ name, description }` |
| `lane.meta` | `{ laneId, label, origin, agentId, parentAgentId, contextItems, contextChars }` |
| `invite.meta` | `{ inviteRef, note }` (only if the admin chose to share the note) |
| `log.witness` | `{ witness: LogWitness, sig }` with `LogWitness = { v: 2, typ: "log-witness", roomId, deviceId, head: {seq, hash}, roster: {seq, hash} }` and `sig = Sign(deviceSigningKey, "stmt:log.witness", RJCS(LogWitness))`, so it can be shown as evidence outside MLS (vector: `mls.witness`) |

### 4.6 Security-relevant events shown to members

These events produce a visible notice in every member's room view, not only an entry in the history. Policy changes are on the list because they change who can add devices, who holds recovery power, when lanes rotate, and what members can see.

| Category | Events |
|---|---|
| Policy | `room.policy.changed` (each changed setting named, old and new value; a change that weakens a setting fixed by an org policy is marked) |
| Room | `room.close.proposed` (with the earliest confirmation time), `room.closed` |
| Authority keys | `admin.added`, `admin.removed`, `admin.key.rotated`, `admin.key.revoked`, `recovery.key.proposed`, `recovery.key.rotated`, `host.key.rotated`, `host.key.revoked`, `endpoint.rotated`, `lane.offer.rotated` |
| Membership and devices | `member.admitted`, `member.removed`, `member.left`, `member.device.replaced`, `device.added` ("Sam is adding a device; it joins at <time>", and, when the requester is Sam's only device, "Sam has only one device in this room, and it is adding another"), `device.add.vetoed`, `device.add.approved` (with "added by their own device" or "approved by an admin"), `device.removed`, `device.rekeyed` (and, when the requester is Sam's only device, "Sam has only one device in this room, and it is changing its keys"), `device.rekey.vetoed`, `device.rekey.approved`, `device.conflict.resolved`, `device.leaf.repair.requested` ("Sam's laptop asked to repair its membership in *<group>*") |
| Lane display | `lane.names.changed` |
| Alerts | `grant.suspected-theft`, `endpoint.evicted`, `mls.stalled`, `lane.degraded`, the detection results of section 6 (`fork`, `truncation`), and a host key, room endpoint or lane offer left **uncertified** by a re-fold (section 5.1, step 9) |

The member's own devices additionally get the veto prompt for `device.added` and `device.rekeyed` (`identity-model.md` section 6.3).

M1 had no such list, which was finding P-27. Display-only settings are included deliberately: showing project names to members is a disclosure decision, so members are told when it changes.

### 4.7 Not in the room log

Host-local, in `host/<roomId>/access.jsonl` (owner-only, not sealed, no secrets): session opened and closed (`deviceKid`, time), `log.fetch` ranges served, rate-limit hits, pre-auth failures by reason. These are access logs for the owner, not shared facts, so they do not go in the shared log (P-27 "log reads"). The KEK's creation and rotation are recorded in `keystore/meta.json`.

### 4.8 Fence

| Type | Producer | Plaintext `data` | Effect |
|---|---|---|---|
| `producer.fence` | A or D | `{}` | none. Moves the producer's `base` forward, so any statement it signed earlier and the host held back can never take effect (section 2) |

## 5. Roster and authority fold

Members and the host compute the roster and authority state with one deterministic function:

```
state = init(genesis)       // admins (lineage roots), recovery, host keys, endpoint, policy; empty roster;
                            // empty denylists, retired keys, versions, pending requests; maxBase = {}
for entry in chain (seq ascending):
    verify entry: prev link, entryHash, hsig with entry.hostKid valid at this position
    if entry.cls == "mls": record epoch; continue
    stmt = body; verify bodyHash, strict parse, schema
    base rule:    stmt.base.seq < entry.seq, and stmt.base.hash == entryHash(stmt.base.seq)
                  (genesisHash when stmt.base.seq == -1)
    unique rule:  no earlier entry carried a statement with the same bodyHash
    require producer allowed for stmt.type in state (section 4); verify sig with the stored key
    forward rule: stmt.base.seq > maxBase[producer kid] (if present); then maxBase[producer kid] = stmt.base.seq
    ref rule:     if stmt has ref or proposal: stmt.base.seq >= seq of the entry that carries it
    depth rule:   if stmt is admin.key.revoked: its nesting depth is at most 8 (section 5.1, step 8)
    if stmt is admin.key.revoked: state = refold(...)                      // section 5.1
    else: state = apply(state, stmt, entry)     // pure; checks versions, holds; rejects impossible changes
    if the roster members after this entry differ from those before it: rosterSeq = entry.seq
Roster     = { roomId, seq: rosterSeq, members: sorted by memberId }
rosterHash = H("roster", RJCS(Roster))
```

`rosterSeq` is always the `seq` of the **last roster-changing entry**. Entries that do not change the roster (for example `lane.created` or `grant.issued`) leave it unchanged. A revocation whose re-fold changes the roster is itself the roster-changing entry, so `rosterSeq = r` (re-review finding R-7); otherwise one roster position would have two hashes, the one members witnessed before the revocation and the recomputed one. Every reference to a roster position (MLS authenticated data, `log.witness`) uses this value (S-14; vectors: `log.rosterAfter`, where the head at `seq` 3 still has roster position 2, and `log.refold`, where the revocation entry becomes the roster position).

**Epoch.** The fold records each entry's `epoch` and does not check it: it neither requires statement entries to repeat the previous epoch nor commit entries to advance it, because ReInit restarts the count and only members can judge commits (`mls-integration.md` section 4). Checks that need an epoch use the epoch inside the MLS message itself (`mls-integration.md` section 5.1).

`maxBase` is updated for every statement that passes the signature check, whether it later takes effect, becomes suspect or is void, so the forward rule does not depend on re-folds.

`apply` rejects (and the member raises `invalid_entry` and stops processing later entries, rather than skipping):

- adding a device whose keys are in the device denylist, retired, or already in the roster; adding a `memberId`, `deviceId` or `laneId` that was ever used in the room (a `deviceId` counts as used from the `device.added` that requested it);
- adding or certifying a key that is **retired**: any key that was ever valid in this room for any subject and was then rotated out, removed or revoked (device, admin, recovery, host, endpoint and lane keys alike). The admin-key denylist and the device denylist are the parts of this set that existing rules already named. A re-fold never takes a key out of this set (section 5.1, step 9);
- adding or certifying a key equal to any key currently in use in the room, for any subject (section 4.1, "New keys are fresh");
- removing the last active admin key (`admin.removed`), or an `admin.key.revoked` signed by an admin key that would leave no active admin key; R may (section 5.1, step 4);
- a role above the producing admin's own;
- a `ver` that does not equal the current version of the field (section 4.0), or a `KeyChange.old` that does not name the subject's current key;
- `member.admitted` with method `"creator"` anywhere but `seq` 0, or any other statement at `seq` 0;
- `member.left` signed by a device of a different member, or by a member with more than one active device;
- `device.removed` signed by a device for a device other than itself, or for itself when it is the member's last active device;
- `device.added` whose `addedBy` is not the signing device, whose `linkRef` names no `device.link.created` of the same member, or whose link already added a device;
- `device.leaf.repair.requested` that breaks the rules of section 4.3 (own leaf only, scope, rate);
- `device.add.approved` or `device.rekey.approved` whose `ref` is not a pending, uncancelled, unvetoed `device.added` or `device.rekeyed`, in any mode; and, for `mode: "auto"`: policy `deviceAddApproval = "admin"`; for a **sole-device request** (an add or a rekey whose requesting device was the member's only active device when the request was sequenced), policy `soleDeviceChange = "admin"`; a veto for `ref` earlier in the chain; an open device conflict for the member; less than the **hold** of `hts` between the request entry and the approval entry, where the hold is 72 h for a sole-device request and 24 h otherwise (decision round 4, item 2, for adds; decision round 5, item 3, for rekeys); or (for adds) a requesting device that had been active for less than 24 h of `hts` when its request was sequenced;
- `room.closed`, `recovery.key.rotated` from `null`, `admin.key.revoked` or `host.key.revoked` that breaks the rules of sections 5.1 and 5.2;
- `invite.revoked` signed by a device for an invite, or for a link of another member;
- a statement naming a lane that does not exist or is closed (section 4.4, "Lane existence");
- `lane.names.changed` from a device of a member other than the lane's `owner`, or with `show: true` under `projectNames = "hidden"`;
- a `minVersion` decrease, a `grantTtl` above 43 200, or a `closeDelay` outside 0 to 518 400;
- any statement after `room.closed`;
- any type the member does not know (`signatures-and-encoding.md` section 7 rule 7).

The base rule fails, the forward rule fails, or `apply` rejects: in each case a member that finds such an entry in the host's chain raises `invalid_entry`, because the host should have refused it (section 2).

**Members with no devices** (R-8). `RosterEntry.devices` holds 0 to 8 devices. A member reaches 0 only when an admin removes their last device (a device cannot remove itself when it is the last one; it signs `member.left`). Concurrent self-removals are therefore safe: the fold applies them in order, and the one that would remove the last device is rejected, so the host answers `stale_base` and that device signs `member.left` instead. A member with no devices has no MLS leaf, no session and no grants. An admin either restores them with `member.device.replaced` (`removed: []`, after a new invite and SAS; `keys-rotation-recovery.md` section 6.1) or removes them.

The 24 h and 72 h hold checks (for adds and rekeys) and the closure delay use the host's `hts`, which members cannot verify. They catch a careless host. The real enforcement is the admin's daemon, which signs an automatic approval only after the hold on its own clock, timed from when it first saw the request (`identity-model.md` section 6.3, "Whose clock"), and the confirming admin's daemon, which refuses to sign a closure before the delay on its own clock (section 5.2).

The base and unique rules stop a host, or a thief holding the host key and the log, from sequencing a validly signed old statement again (S-1). Versions stop a statement that was signed but never sequenced from taking effect after the field changed, even if it changed back (R-1). The forward rule stops it as soon as its producer has signed anything later. The vectors `log.foldChecks` show a replayed role change, a held statement killed by the forward rule, an ABA case killed by its version (the role is back at `watch`, so an old-value check would have passed), a `base` at the entry's own position and a `base` hash that is not in the chain, each rejected.

### 5.1 Revocations and the re-fold

Revocation cut-offs are log positions, not times (S-8).

`admin.key.revoked { kid, fromSeq }` at position `r`, signed by another admin key or by R:

1. **Bounds.** `kid` is an admin key of the room that no revocation in effect names yet (a key that is already rotated out or removed may be revoked, once); `fromSeq ≤ r`; `fromSeq` is not earlier than the position where `kid` became valid; and not earlier than the **authority start** of the revoking key, whether it is an admin key or R (decision round 4, item 1; re-review finding R-3). A key's authority start is the position where it became valid, except that a key installed by rotation (`admin.key.rotated`, `recovery.key.rotated` from a non-null key) inherits the start of the key it replaced, because the old key signed the change. So a newly added admin key, or a recovery key installed later, cannot reach back before its own existence and void an honest admin's earlier statements, while a routine rotation loses no reach. A genesis key's start is 0.
2. **Effect.** The state at `r` is recomputed as the fold of `chain[0..r)` in which every statement signed by `kid` at a position `≥ fromSeq` has **no effect**. Those statements are **suspect**: they stay in the log and history, marked, and never take effect again. Statements of other producers in that range are re-applied in order. One that no longer applies (because it depended on a suspect statement, or its `ver` no longer matches the recomputed version) is **void**: no effect, shown in history, no alert. From `r` on, `kid` is invalid and on the admin-key denylist.
3. **Several revocations** compose: the fold keeps the set `E` of `(kid, fromSeq)` pairs of the revocations in effect and recomputes with all of them. A revocation is **in effect** when it is neither suspect (its signer is covered by a pair of `E`) nor void (it breaks step 1 or step 4 in the recomputed state). Every member folds the same chain in the same order with the algorithm below, so all reach the same `E` and the same state. The algorithm is a fixed point over flat passes, never a recursion (decision round 8, item 4):

   ```
   E := pairs of the revocations in effect before r, plus (kid, fromSeq) of the new one
   repeat at most 9 times:
       pass := fold of chain[0..r) from genesis, with every pair of E imposed from the start:
               a statement by a covered kid at a position >= that pair's fromSeq is suspect;
               an earlier admin.key.revoked is classified as suspect, void or in effect,
               and if in effect it only marks its target revoked at its own position (no replay)
       E' := the new pair plus the pairs of the earlier revocations the pass found in effect
       if E' == E: the result is pass; stop
       E := E'
   if no pass settled: reject the new revocation with revocation_too_deep
   ```

   Imposing an earlier revocation's pair from the start of the pass, instead of at its position, gives the same result, because a revoked key never signs again after its revocation (step 9), so all of its statements lie before it. Each pass costs one step per entry before `r`, so a re-fold costs at most 9 times the length of the chain: linear in the chain, whatever the nesting. A recursive replay, where each earlier revocation replays the chain again, costs exponential time in the number of revocations and is not allowed. A revocation that changes no earlier revocation's classification settles in one pass, and the unit tests' chains in which one earlier revocation becomes suspect settle in two. The bound of 9 passes is a deterministic limit that every member applies the same way; that every chain within the depth cap of step 8 settles within it is expected but not proven.
4. **Precedence of the recovery key.** R can always revoke an admin key within the bounds of step 1, and R cannot be revoked by an admin key. If a stolen admin key revoked the honest admin first, R revokes the stolen key with a `fromSeq` at or before that revocation. The re-fold then makes the stolen key's revocation suspect: the honest admin's statements before it take effect again, but the honest admin's key does **not** return (step 9; decision round 8, item 3). R then adds a fresh key for the honest admin with `admin.added`, which starts its own lineage (section 5.2). Statements the honest admin made while revoked were refused by the host, so the honest admin re-submits them with the new key. Because no retired key returns, such a revocation may leave the room with no active admin key; **only R may do that**, since only R can then add a fresh one. An admin key may not leave the room without an active admin key (`last_admin`). In practice its own key stays active, because its authority start lies after the statement that installed it, so step 1 keeps that statement out of the revoked range; the rule still applies if a re-fold ever dropped it.
5. **Without R** two admins can race: whichever revocation the host sequences first stands. This is a stated limit. Rooms that matter should have a recovery key (offered by default, `identity-model.md` section 5.4).

6. **Roster position.** If the re-fold changes the roster members, `rosterSeq = r` (section 5, R-7).
7. **Versions and pending items after a re-fold.** Versions, pending device requests, conflicts and open proposals are recomputed with the rest of the state. A suspect `room.close.proposed` or `recovery.key.proposed` is void, so it can no longer be confirmed. A member whose devices step 9 drops gets `r` as the version of its device set.
8. **Nesting depth** (decision round 8, item 4). Each `admin.key.revoked` entry has a nesting depth: 1 plus the largest depth among the earlier `admin.key.revoked` entries at positions in `[fromSeq, r)`, or 1 if there is none. Every revocation entry in the chain counts, whether it is in effect, suspect or void, so the depth depends on positions only and is computed before the re-fold. `apply` rejects a revocation of depth greater than 8 with `revocation_too_deep`. A revocation whose range reaches back over many earlier revocations is then split: R or an admin first revokes the innermost keys, then the outer ones with a `fromSeq` after them. Vector: `log.revocationDepth` (depths 1 to 8 accepted, 9 rejected).
9. **Retired keys never return** (decision round 8, item 3). A re-fold recomputes the state, but it never puts a retired key back into use, even when it voids the rotation, removal or revocation that retired it. After the passes:
   - every id used and every key retired, denylisted or rotated out before `r` stays so, and every key that was in use before `r` and is not in the recomputed state is retired (device keys also denylisted);
   - an admin key that was revoked, removed or rotated out before `r` stays inactive, even if the statement that ended it is now suspect or void (step 4 gives the recovery path);
   - a device whose recomputed signing or DH key is retired is dropped from the roster, with its pending requests and leaf repair requests cancelled: for example a device removed by a suspect statement, or a device whose rekey approval is suspect (its old keys were retired at the approval, its new keys leave use now). A pending request whose new keys are retired is cancelled. The member gets the device back only through a fresh statement: `member.device.replaced` by a valid admin, or a new device link;
   - **host keys are positional:** the host-key table of the state before `r` is kept, so a host key rotated out before `r` never signs again and the current key can sign the entry that fixes it. A host key, the room endpoint, or a lane offer whose installing statement is suspect or void after the re-fold keeps the key it had before `r` and is marked **uncertified**. Members and lane endpoints refuse grants signed by an uncertified host key, as for a revoked one; members show the uncertified endpoint or lane offer as an alert (section 4.6) and keep using it only to reach the room, until a valid admin rotates it with `host.key.rotated`, `endpoint.rotated` or `lane.offer.rotated`. Those statements name the current (uncertified) key or the recomputed version as usual. A lane closed before `r` stays closed;
   - the recovery key cannot return either: one installed by a statement that is now suspect or void is gone and its key retired.

   The room then needs a fresh statement from a valid admin key or R for each subject it wants back. Vector: `log.noRevival` (a host-key rotation and a device removal by a stolen key; after the re-fold the old host key and the device's keys stay retired, and the new host key signs on, uncertified).

Suspect roster changes are therefore never part of the reference roster. A ghost device admitted by a stolen key leaves the roster at the re-fold, which makes its MLS leaf a pending removal (`mls-integration.md` section 4.2).

`host.key.revoked { kid, fromSeq }` at position `r`: `kid` must be a host key that was already rotated out (the current key is rotated first), not yet revoked, and `fromSeq` must meet the bounds of step 1, including the revoking admin key's authority start. Entries signed by `kid` at positions in `[fromSeq, r)` are **suspect for ordering**. The statements inside them keep their producers' signatures and stay valid if those producers' keys were valid, so the roster is not recomputed. Members compare heads with other members (section 6) to find equivocation in that range. Entries after `r` signed by `kid` are invalid. Grants signed by `kid` are refused once the revocation is applied, whatever their `iat` (`keys-rotation-recovery.md` section 3).

### 5.2 Admin lineages, recovery-key installation and closure

Decision round 3 (item 5) let `room.closed` be signed by R or by a second admin. The re-review showed that a single stolen admin key could meet that rule on its own (R-3): it could add a second admin key, or install a recovery key, and then close. Decision round 4 (item 1) closes both paths. This section gives the rules.

**Lineage.** Every admin key has a **lineage root**, recorded in the authority state together with `addedBy`:

- a genesis admin key is its own root;
- a key added by R (`admin.added` signed by R) is its own root, because whoever holds R already has every power that a new root gives;
- a key added by an admin key (`admin.added` signed by that key) has the same root as the key that added it;
- a key installed by `admin.key.rotated` has the same root as the key it replaced.

Two admin keys are **independent** when their roots differ. A ghost member admitted by a stolen key, and any admin key added for it, shares the stolen key's root. A room has as many **admin lineages** as there are distinct roots among its active admin keys.

**Why roots and not "not added by the proposer"** (deviation from the re-review's suggestion (a)). The re-review proposed that the confirming key must not descend from the proposing key. That rule still lets one stolen key close: it adds two keys, proposes with one and confirms with the other (neither descends from the other), or proposes with a key it added and confirms with the stolen key itself (an ancestor is not a descendant). Comparing roots is the smallest rule that blocks every combination of keys a single stolen key can create. Its cost: two admins of one lineage (a creator and a co-admin the creator added) cannot close together; they close with R, which their lineage may install alone (below).

**Closure by admins.** `room.closed {proposal}` signed by admin key C is valid only if all of these hold at its position:

1. `proposal` names a `room.close.proposed` entry `p` that is not suspect or void, whose `exp` has not passed, and that no earlier `room.closed` used;
2. the proposing key P and C are both active and independent (different roots). A proposal whose key is rotated, removed or revoked before the confirmation is void, even after a routine rotation; the admin proposes again with the new key;
3. C was already valid at `p` by its own first valid position (`C.fromSeq ≤ p`), so a key added after the proposal cannot confirm it, and neither can a key installed by rotation after the proposal, although its lineage existed then;
4. the `hts` of the confirmation entry is at least `closeDelay` seconds after the `hts` of `p`, where `closeDelay` is the larger of `policy.closeDelay` at `p` and at the confirmation. Default 86 400 (24 h), on by default (decision round 4, item 1). The delay gives R or another admin time to revoke a thief before the closure; it is not an undo window, since a closure stays final.

The confirming admin's daemon enforces the delay on its own clock: the Rooms UI shows "Closure proposed by *<admin>*. It can be confirmed after *<time>*" and refuses to sign earlier.

**Closure by R.** R signs `room.closed {proposal: null}` with no proposal and no delay. R is the highest authority in the room; a delay would protect against nobody who could act on it.

**First recovery key.** `recovery.key.rotated` with `change.old = null`:

- in a room with **one admin lineage**, any active admin key may sign it alone (`proposal: null`). One lineage is cryptographically one authority, so this gives a thief nothing they did not already have. This is the path by which a single admin, or a creator and the co-admins they added, can close a room: install R, then close with R;
- in a room with **two or more lineages**, an admin key P signs `recovery.key.proposed {change, newKeySig, exp}`, and an independent admin key C, active at the proposal, signs `recovery.key.rotated` with `proposal` naming it and a byte-identical `change`. No delay applies; the decision asked for two admins, not a wait.

Decision round 4 says "more than one admin". This spec counts lineages instead of keys, for the reason above: a second key of the same lineage can be created by one stolen key, so requiring it would protect nothing, while requiring an independent key in a one-lineage room would make R impossible to add.

**A newly installed R.** R's revocations are bounded by its authority start (section 5.1 step 1). An R installed at position `i` cannot void statements before `i + 1`.

**What remains** (stated limits):

- A stolen key of a room's only lineage can install R and close the room, as it can remove every member. Rooms that need protection against one stolen key have a second, independent admin (a second genesis admin or an R-added admin) or a recovery key held offline from the start.
- A stolen R can close the room at once. R is the top of the authority; protecting it is the holder's job (offline, escrow under org policy).
- Without R, two independent admins can still race to revoke each other (section 5.1 step 5). A thief who wins that race against every independent lineage leaves the room with one lineage, their own, and can then install R and close. At that point the room was already unrecoverable (`keys-rotation-recovery.md` section 6.6 step 6); the closure adds finality, not access. A recovery key present from the start prevents this: R revokes the thief with a `fromSeq` before the thief's revocation, and every key the thief can create shares the thief's root, so no independent confirmer is available to them.

## 6. Consistency between members

### 6.1 What each member stores

- The verified chain of entries up to its head, and the bodies it needs (statements always; MLS bodies until processed).
- `maxSignedHead`: the highest `SignedEntry` it has verified.
- Its own receipts (section 6.4).
- Witnesses received from other members: the latest `{deviceId, head, roster}` per device.

### 6.2 Gossip

Members learn each other's heads through MLS, where the host can drop messages but not change them:

1. Every MLS message carries `logHead` in its authenticated data (`mls-integration.md` section 5).
2. A device sends a `log.witness` application message after it processes a membership or authority statement, and otherwise every 6 hours while it has a session, if the head moved.
3. Members compare every head they receive (section 6.3).

A head claim from another member is that member's statement, not the host's. Only a host-signed entry is proof of what the host did.

### 6.3 Checks on a received head `(s, h_s)` from member P

| Case | Action |
|---|---|
| `s ≤` own head and own `entryHash(s) == h_s` | consistent |
| `s ≤` own head and own `entryHash(s) ≠ h_s` | Request the entry at `s` from the host (`log.fetch`) and ask P, through MLS, for its signed entry at `s` (`log.evidence.request`). If either returns a `SignedEntry` with `hash == h_s` and a valid `hsig`, the member holds two signed entries for `s`: raise **`fork`** with that equivocation proof. If no such entry arrives within 30 s, raise **`unverified_head_claim`** naming P's credential (`memberId`, `deviceId`). |
| `s >` own head | Fetch from own head to `s`. If the fetched chain extends the own chain and reaches `h_s` at `s`: consistent. If the host returns a different hash at `s`, or its signed head is below `s`, ask P for its signed entry at `s`. A valid one gives `fork` (different hash) or `withholding` with proof (the host signed an entry it now does not serve). Without it, `unverified_head_claim`. |

`unverified_head_claim` stops nothing. Without it, one malicious member could make every honest member stop sending by gossiping a false head (S-7). The alert is attributed to the sender's credential and shown to admins; repeated claims from one device are grounds for an admin to look at that device.

### 6.4 Truncation

- **Seen entries:** if the host ever presents a head with `seq` below `maxSignedHead.seq`, or a chain that does not contain `maxSignedHead`, the member raises `truncation`, with `maxSignedHead` as proof.
- **Own statements:** every producer keeps the receipts of its statements. If a later chain lacks a receipted entry at its `seq`, that is a fork with proof (the receipt is host-signed). So an admin who removed someone, or a member who left, detects a host that drops that event for others, once they see the others' heads.
- **Refused bases** (R-9): a producer whose statement gets `unknown_base`, while its `base` is a `SignedEntry` it verified, compares that entry with the `head` in the error and fetches the chain. If the host's chain no longer contains the entry, the producer raises `truncation` with that entry as proof.
- **Unseen entries:** a host can withhold the newest entries from everyone who has not seen them. Only the producer (via receipts) and gossip from members who did see them can reveal that. This is the limit of the design: without a third party, the newest unseen events can be delayed (architecture section 10 already says "could withhold or delay messages").

### 6.5 Withholding and drops

- MLS application messages carry per-sender generation numbers within an epoch. A gap in a sender's generations that is not filled within 5 minutes means the host dropped messages. Raise `withholding` with the sender and range.
- A head referenced by a peer that the host does not deliver within 30 s: handled by section 6.3 (`withholding` with proof, or `unverified_head_claim`).

### 6.6 Alerts

| Alert | Shown to | Member behaviour |
|---|---|---|
| `fork` (raised only with an equivocation proof) | the member; the proof sent to all members through MLS | stop sending application messages in this room; keep reading; show "This room's history differs between members. The host may be misbehaving." with an export of the evidence |
| `truncation` (with `maxSignedHead` or a receipt as proof) | the member; evidence to all | same as `fork` |
| `withholding` | the member | keep working; show a warning badge |
| `unverified_head_claim` | the member; the claim and sender to admins | keep working; no badge for the room. Admins see "A device reported a different history without evidence" |
| `roster_mismatch` | the member; evidence to admins | stop advancing MLS (`mls-integration.md` section 9) |
| `invalid_entry` | the member; evidence to admins | stop processing later entries; show "This room's history contains an invalid entry. The host may be misbehaving." |
| `suspect` statements | everyone | marked in history; they have no effect (section 5.1) |
| `uncertified_key` (a host key, the room endpoint or a lane offer left uncertified by a re-fold) | everyone; admins are asked to rotate it | keep working; refuse grants signed by an uncertified host key; show "A key of this room was set by a revoked admin key. An admin must replace it." (section 5.1, step 9) |
| `leaf_replaced_unrequested` (a device sees its own leaf replaced under a `device.leaf.repair.requested` it did not sign) | the device; evidence to admins | stop sending in that group; show "Someone used this device's identity to replace its membership. Ask an admin to remove this device." (section 4.3) |
| `epoch_fork`, `epoch_anchor_mismatch`, `epoch_unconfirmed` (joiner's epoch check) | as in `mls-integration.md` section 5.1 | `epoch_fork`: stop sending application messages in that group; the others as stated there |

No alert removes the member or deletes data automatically. Recovery is a human decision (`keys-rotation-recovery.md` section 6).

## 7. Encryption and plaintext metadata

The host needs some facts in plaintext to enforce access: who the devices are, their roles and lane access, and grant and invite state. Everything else is inside MLS.

| Plaintext on the host (signed) | Encrypted (MLS) |
|---|---|
| `roomId`, `genesisHash`, genesis (keys, endpoint, relay, policy) | room name and description (`room.profile`) |
| `seq`, `prev`, `hash`, `hts`, `epoch`, `cls`, `type`, `bodyHash` | chat messages, threads, mentions |
| member ids, device ids and keys, roles, lane ids per member | member labels (`member.profile`) |
| invite and link references (hashes of their ids), roles, lanes, expiry, attempt outcomes | invite notes (local, or `invite.meta` if shared) |
| lane ids, lane owner, lane endpoint `serverId`, key, relay, visibility, whether project names are shown | lane labels, agent ids, parent agent ids, fork context sizes (`lane.meta`) |
| grant ids, expiry, theft events | everything in application messages |

What the host still learns: the shape of the room (number of members and devices, join and leave times, roles), message timing and sizes, and which device sent each statement. The member UI's privacy panel says so. This replaces M1, where room name, labels, agent ids and parent agent ids were in the signed plaintext log (data-model section 4).

**Before MLS exists for a room** (the period between room creation and the creator's first group commit), there is no content to protect: the room profile is sent as the first MLS message after group creation, and no plaintext names are ever logged.

## 8. Storage

### 8.1 Host

- `host/<roomId>/genesis.json`: the signed genesis as RJCS text. It is public and not sealed; its `genesisHash` is pinned inside the sealed host key file `host/<roomId>/keys.sealed` (`identity-model.md` section 7.1). On open the host recomputes the hash of `genesis.json` and refuses the room if it differs from the pinned value or names another room, so a swapped genesis file is detected even though the file itself is not sealed.
- `host/<roomId>/log/entries.jsonl`: one line per entry, `RJCS({ entry, hash, hsig })`.
- `host/<roomId>/log/bodies.jsonl`: one line per body, `RJCS({ seq, body: b64u })`. Statement bodies are also kept in an index for fast folding.
- Append = write one full line in append mode under the single-writer lock, then flush (`grants-v2.md` section 7.3, platform-specific primitives).

**Write ordering.** For an operation that grants or changes state other than revocation: append body, append entry (both fsynced), then update the in-memory state, persist it, and only then reply or push. For revocations: `grants-v2.md` section 7.1 (enforce first). A crash after the log append and before the state write is repaired at start: the host re-folds the log and rebuilds state, so the log is the source of truth.

**Torn lines (C-11).** On load the host reads line by line:

- A final line without a trailing newline, or one that fails to parse (not strict RJCS of the expected shape), is a torn write: it is moved to `entries.torn.<unix ms>` (or `bodies.torn.<unix ms>`) and the head is the last valid entry. The host logs `log_torn_line` locally. If the torn entry had been acknowledged to anyone, members will report it as truncation, which is the correct outcome.
- Complete body lines after the last entry (a crash between the body append and the entry append) are moved aside the same way: they were never acknowledged.
- A bad line **before** the last one, a gap in `seq`, or an entry without its body is corruption: the host stops serving the room and raises an error in the owner UI. It never skips lines.
- A final line that parses but then fails verification (entry hash, `hsig`, chain link, body hash, or the fold) is corruption, not a torn write. Only a line that does not parse is attributed to a crash: a crash can cut a line short, but it cannot produce a complete, well-formed line with a wrong hash or signature. The host stops serving the room as above and does not move or truncate that line.

### 8.2 Member

- `member/rooms/<roomId>/log/entries.jsonl` and statement bodies, written the same way.
- `maxSignedHead`, receipts and witnesses inside `state.sealed`.
- On start the member re-verifies its stored chain and fold. A mismatch with the sealed head is local corruption: the member refetches from the host and compares.

### 8.3 Fetch API

```
log.fetch     { fromSeq, toSeq?, limit ≤ 1000, bodies: "stmt" | "all" | "none" }
   → { entries: [SignedEntry], bodies: [{ seq, body }], head: SignedEntry }
log.subscribe { fromSeq }    pushes new SignedEntry (and statement bodies) as they are appended
```

The host serves only to active devices. A removed device's last view is what it had at removal.

## 9. Open questions

- **Q1.** One chain for chat and security events: fine for rooms up to a few hundred members and moderate chat volume. For very busy rooms, splitting chat into its own chain anchored by periodic entries in the security chain may be needed.
- **Q2.** Should the host also sign periodic heads when nothing happens (heartbeat entries), so withholding of an idle room becomes detectable? Proposed: a `host.heartbeat` entry every 24 h if the room had no entries; costs little.
- **Q3.** Should a third-party witness (another member's daemon, or a public transparency service) countersign heads for rooms that need stronger truncation guarantees? Not in v2.
- **Q4.** Evidence export format for `fork` and `truncation` (so a lab can show an incident to someone outside the room).
