# Key rotation and compromise recovery (identity v2)

- **Status:** proposed specification, not implemented.
- **Resolves:** A5 (P-10); compromise handling referenced by P-2, P-3, P-9, P-16.
- **Formats:** statements and contexts in `room-log-v2.md` and `signatures-and-encoding.md`. Vectors: `vectors/vectors.json` → `statements.deviceRekeyed`, `deviceRekey` (sole-device rekey hold), `statements.adminKeyRotated`, `statements.hostKeyRotated`, `deviceLink.deviceAdded`.
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): positions instead of times for revocation, recovery-key precedence, suspect statements excluded from the fold, device rekey hold and UpdatePath, room closure by two signers. Revised again after the re-review (decisions round 4): retired keys, admin lineages, independent closure confirmers with a 24 h delay, two-admin installation of a first recovery key in multi-lineage rooms, bounded recovery-key revocations, the MLS rekey window (R-5) and its offline test. Decision round 5, item 3: the 72 h sole-device hold and policy `soleDeviceChange` also cover rekeys (section 4.1). Decision round 6 (after Spike A): device rekeys are applied in MLS by the approving admin daemon, Remove plus Add with public ts-mls APIs only; the `prevSig` window is removed (sections 4.1, 4.2, 5). Decision round 7: `prevSig` is removed entirely (R7-1); any device that is a leaf of a group may complete a rekey there with a roster-determined Remove plus Add, and roster equality tolerates pending adds (R7-2; sections 4.1, 5, 6.6). Decision round 8: retired keys never return, even when a re-fold voids the statement that retired them, and the recovery path is a fresh statement from a valid admin key or R (sections 2, 4.5, 6.4, 6.6; `room-log-v2.md` section 5.1, step 9).

## 1. Principles

1. **Every key change is a signed statement in the room log.** Members learn of it from the log, never from a side channel. An unexpected change is shown in the UI (A5; architecture section 8.1).
2. **Old signs new, new signs back.** For a planned rotation the old key signs the statement and the new key signs a `key-change-new` binding of itself. This proves continuity and possession.
3. **An authority above the key certifies it.** Admin keys certify host, endpoint, lane and node keys and the roster's device keys. A key change takes effect only once that authority's statement is in the log.
4. **Verification against several key ids.** Each certified key has a validity window: log positions for everything in the log, unix time for lane grants (section 3). Verifiers keep every key whose window covers the object, until objects signed by it can no longer be valid.
5. **Compromise is a different operation from rotation.** It names a log position `fromSeq`. Nothing new from that key is accepted after the revocation, and its statements from `fromSeq` on become suspect and lose their effect (`room-log-v2.md` section 5.1).

## 2. Key-change binding

```
KeyChange = {
  v: 2, typ: "key-change",
  roomId,
  subject: { kind: "device" | "admin" | "recovery" | "host" | "lane" | "node", id },
  old: <kid of the old key> | null,
  newSig: <Ed25519 pub b64u> | null,     // new signing key, if the subject has one
  newDh:  <X25519 pub b64u> | null       // new DH key, if the subject has one
}
newKeySig = Sign(newSigningKey, "key-change-new", RJCS(KeyChange))
```

- `subject.id` is the `deviceId` for a device, the admin's `memberId` for an admin key, `"recovery"` for the recovery key, `"host"` for the host key, the `laneId` for a lane and the `nodeRef` for a node.
- `old` is `null` in exactly four cases: `device.added` (a new device, `identity-model.md` section 6.4), `admin.added` (a new admin key), and `recovery.key.proposed` and `recovery.key.rotated` when the room has no recovery key yet. In every other case `old` must name the subject's current key, and `apply` rejects the statement otherwise (`room-log-v2.md` section 5, S-1).
- **Retired keys** (re-review finding R-1). A key that was ever valid in the room and was then rotated out, removed or revoked can never be certified again, for any subject. Because keys never return, `old` cannot match a returned state, and it acts as the version of the key field (`room-log-v2.md` section 4.0).
- **No return after a re-fold** (decision round 8, item 3). A revocation's re-fold never brings a retired key back into use, host keys included, even when it makes the rotation, removal or revocation that retired the key suspect or void. The subject then has no usable key, or keeps the key it had before the revocation marked uncertified (host key, room endpoint, lane offer), until a valid admin key or R signs a fresh statement for it (`room-log-v2.md` section 5.1, step 9).
- **New keys are fresh.** A new key must not equal any key currently in use in the room, for any subject (`room-log-v2.md` section 4.1).
- `newKeySig` is present whenever `newSig` is not null.
- X25519 keys cannot sign. Possession of a new DH key is proven by the first Noise handshake that uses it (device DH keys), or is vouched for by the certifying admin (endpoint and lane keys, which only the host or gateway holds).

Vectors: `deviceLink.deviceAdded` (old `null`), `statements.deviceRekeyed`, `statements.adminKeyRotated`, `statements.hostKeyRotated`.

## 3. Validity windows and multi-key verification

Validity for everything in the log is decided by **log position**. Only lane grants, which are checked outside the log, use time (review findings S-8 and S-15).

Every certified key has, in the authority state or roster:

```
{ kid, pub,
  fromSeq,                   // first position at which the key may sign (0 for genesis keys)
  toSeq: <seq> | null,       // last position at which it may sign: the entry carrying its rotation or revocation
  suspectFromSeq: <seq> | null,                // set by a revocation (room-log-v2.md section 5.1)
  since: <seq>,              // admin and recovery keys: authority start, bounds their revocations (room-log-v2.md 5.1)
  root: <kid>,               // admin keys: lineage root (room-log-v2.md 5.2)
  validFrom: <unix s>, validTo: <unix s> | null }   // host keys only, for grants
```

A rotation entry at position `r` is the last one the old key may sign (or, for host keys, the last entry signed with it), and the new key is valid from `r + 1`.

| Object | Judged by | Accepted if |
|---|---|---|
| Log entry (host) | its `seq` | `fromSeq ≤ seq ≤ toSeq` for the named `hostKid`. No entry after the entry carrying `host.key.rotated` or `host.key.revoked` may use the old key, whatever its `hts` (S-15). Entries in `[suspectFromSeq, toSeq]` are suspect for ordering |
| Statement (admin, device, recovery) | the `seq` of the entry that carries it | the producer key is active in the authority state or roster at that position, and the statement is not suspect (`room-log-v2.md` section 5.1) |
| Lane grant | `iat` | `validFrom ≤ iat < (validTo ?? ∞)`, the key is not revoked, and the grant is within its `exp`. Once a `host.key.revoked` for the key is applied, every grant from it is rejected regardless of `iat` |
| MLS credential | the reference roster named in the commit | `mls-integration.md` section 4 |

For host keys, a planned rotation sets `validTo` (grants only) to `now + 24 h`, because grants live up to 12 h and members may hold one issued just before the rotation. Admin and device keys need no overlap, since their statements are judged by position.

## 4. Rotation by key type

### 4.1 Device signing and DH keys

Trigger: scheduled (every 90 days by default), member request, or after a suspected exposure that is not a confirmed compromise. A confirmed compromise is a removal (section 6.3), not a rekey.

1. The device generates new keys and opens its room session with the **old** DH key.
2. It submits a `device.rekeyed` statement signed by the old signing key, containing `KeyChange` and `newKeySig` (`stmt:device.rekeyed`).
3. **Hold and veto** (review finding S-2). Under `policy.deviceAddApproval = "same-person"` the rekey is held for 24 hours, like a device add (`identity-model.md` section 6.3), or for **72 hours when the device being rekeyed is the member's only active device** when the request is sequenced (decision round 5, item 3). During the hold every active device of the member, including the device being rekeyed, shows "Your device *<label>* is changing its keys at *<time>*. Was this you?" with **Not me**, which signs `device.rekey.vetoed`. A veto cancels the rekey and opens a device conflict for the member. Without a veto, the admin's daemon signs `device.rekey.approved {mode: "auto"}` after the hold. For a sole device the admins' notification and the room notice are marked as for a sole-device add: "Sam has only one device in this room, and it is changing its keys. If Sam did not ask for this, remove the device." Under `"admin"`, under `policy.soleDeviceChange = "admin"` for a sole device, or with an open device conflict, an admin approves interactively (`mode: "admin"`) at any time. The old keys stay valid during the hold.
4. `device.rekey.approved` references the device statement's `bodyHash` and replaces the device entry's keys in the roster. The old keys enter the device denylist at that position.
5. The host closes the old session with `superseded`. The device reconnects with the new DH key.
6. Grants for that device are reissued (the `dev` key id changes), and old grants leave the allowlist.
7. MLS, **admin route** (decision round 6; `mls-integration.md` section 4.4). When it requests the rekey (step 2), the device publishes KeyPackages that carry its new `MlsIdentity` (new `deviceSig`, new MLS leaf key) with `kp.publish {for: "rekey"}` (`mls-integration.md` section 6.4). The admin daemon that signs `device.rekey.approved` (step 3, automatic or interactive) fetches them with `kp.fetch` and also builds a commit that removes the device's old leaf and adds one of those KeyPackages, together with every other pending removal of the room group and any pending add it holds a package for, naming the roster that the approval produces. It submits both together; the host sequences the approval and the commit as adjacent entries, or neither. The daemon then applies the same change in each team subgroup the device is in. Since round 7 any device that is a leaf of a group may complete the rekey there, so a subgroup the daemon is not in, or does not reach, is repaired by any of its devices, with or without an admin (`mls-integration.md` sections 4.3 and 4.4, repair). The admin route stays the primary path in the room group. The device rejoins by Welcome at its new leaf.
8. **No rekey window.** Because the approval and the room-group commit are adjacent, and because roster equality includes `deviceSig` (`mls-integration.md` section 4.2), no Welcome can be built while the device's leaf still has its old key. The `prevSig` exception of the round-4 revision (re-review finding R-5) is removed entirely (decision round 7, item 1). Round 7's tolerance of pending adds keeps this true: a commit may leave a device without a leaf, but must remove every old-key leaf. If no admin daemon is online when the hold ends, nothing is signed: the rekey stays requested and the old keys stay valid until an admin daemon is online. The device shows "Waiting for an admin device to finish the key change. Your current keys keep working."

Why the hold applies to rekeys too: without it, a thief with a copy of the device's keys could rekey the device and put the real device's keys on the denylist, which locks the real person out of that device at once. With the hold, the real device sees the notice and can say "Not me". When the device is the member's only one and the person has lost it, nobody can veto; the 72 h hold gives the person time to tell an admin, whose removal of the device also cancels the pending rekey in the fold (section 6.1; `room-log-v2.md` section 4.3). Org policy `soleDeviceChange = "admin"` removes this case (`identity-model.md` section 6.3).

**Why the admin route** (S-11, R-5, decision round 6). The first revision chose an UpdatePath committed by the device, because it keeps the leaf position and needs no admin online. Spike A (`mls-integration.md` section 10, test 11) observed that ts-mls 1.6.4 receivers accept and validate such an UpdatePath, but that its public `createCommit` always copies the old credential and signature key into the UpdatePath. Sending one would need an adapter-owned fork of `createCommit` built on library internals. Round 6 chose public APIs only. The cost is that an admin daemon must be online to finish a rekey. That costs little, because an admin daemon already signs every approval, automatic ones included. The member loses its leaf position and rejoins by Welcome, which pauses its chat for one reconnect.

### 4.2 MLS leaf signature key

Replaced together with the leaf at every device rekey (section 4.1 step 7). The public ts-mls API cannot put a new signature key or credential into an UpdatePath (Spike A case a0, observed), and a leaf's credential never changes in place (`mls-integration.md` section 3), so the device does not rotate this key on its own. Between rekeys, the device commits an UpdatePath with the public `createCommit` every 7 days or 1 000 sent messages, whichever comes first. That refreshes the leaf's HPKE key, which is what gives the group post-compromise security for this leaf, and keeps the credential and signature key byte-identical. A device that wants a new leaf signature key sooner requests a device rekey.

### 4.3 Admin key

Planned rotation:

1. The admin's device generates a new admin key.
2. It appends `admin.key.rotated` signed by the **old** admin key with `KeyChange` and `newKeySig`.
3. From the next chain position on, only the new key is valid for that admin. Members fold it into the authority state. The old key enters the admin-key denylist, so `admin.added` can never bring it back (S-1).
4. MLS: a GroupContextExtensions commit updates the `paseo_room_authority` extension (`mls-integration.md` section 2.3) with the new admin key set hash.

Adding an admin: `admin.added` by an existing admin or the recovery key, with a `KeyChange` (`old: null`) and `newKeySig`. A key added by an admin key joins that key's lineage; a key added by R starts its own (`room-log-v2.md` section 5.2). The add dialog says which: "This admin will share your lineage. Together you cannot close the room without a recovery key."  Removing an admin: `admin.removed` by another admin, or `admin.key.revoked` by another admin or the recovery key. Removed and revoked keys enter the admin-key denylist. An admin key cannot remove or revoke the last active admin key; only R may revoke it, and then adds a fresh one (`room-log-v2.md` section 5.1, step 4). A key that is already rotated out or removed may still be revoked once, to make its statements in the window suspect.

### 4.4 Recovery key

Optional and offered by default at room creation; it can also be added later, and org policy can require it together with an escrowed copy (`identity-model.md` section 5.4). Adding the first one later needs two independent admins when the room has two or more admin lineages (`room-log-v2.md` section 5.2; decision round 4, item 1). It is never online for routine work. It can sign only `admin.key.revoked`, `admin.added`, `recovery.key.rotated` and `room.closed` (section 6.8). Its revocations take precedence over those of admin keys (section 6.6), and they are bounded like admin revocations: a recovery key cannot void statements made before its authority start (`room-log-v2.md` section 5.1). A rotated recovery key keeps the start of the key it replaced. Rotating it requires the recovery key itself. Losing it changes nothing else.

### 4.5 Host key

1. The host generates a new key.
2. An admin appends `host.key.rotated` (admin-signed) with `KeyChange` (old host key as `old`), the new key's `newKeySig` and `oldValidTo = now + 24 h` (grants only).
3. The entry that carries this statement is the last one signed with the old key. Every later entry is signed with the new key; an entry after it that names the old `hostKid` is invalid (section 3). The host signs new grants with the new key at once.
4. Members and lane endpoints verify grants against both keys until the old key's `oldValidTo`.
5. No MLS change (the host is not an MLS member).
6. **Rotate before revoke.** `host.key.revoked` applies only to a key that is already rotated out; the current host key cannot be revoked, because no key would be left to sign the next entry (`room-log-v2.md` section 4.1). A suspected host key is rotated first and then revoked.
7. **After a re-fold.** If a re-fold makes the `host.key.rotated` that installed the current key suspect or void, that key keeps signing entries but is uncertified: members refuse its grants until a valid admin rotates it. The key it replaced stays retired and never signs again (`room-log-v2.md` section 5.1, step 9).

### 4.6 Room endpoint key

The endpoint key and `serverId` rotate together:

1. The host creates a new endpoint (new `serverId`, new X25519 key) and starts serving it.
2. An admin appends `endpoint.rotated` with the new `serverId`, key and relay.
3. Members with live sessions receive the entry and reconnect to the new endpoint.
4. The old endpoint keeps running for 30 days in a restricted mode. It completes handshakes only for active roster devices, answers every request with `{t:"error", code:"moved", entry}` where `entry` is the signed log entry carrying `endpoint.rotated`, then closes. The member verifies the entry against its stored chain and authority state and reconnects to the new endpoint.
5. A member offline for longer than 30 days cannot find the new endpoint. It needs a device link from another of its devices or a new invite. **Accepted** (decided 2026-10-29): stranding is rare because the endpoint rotates only on host compromise or admin request, and re-invitation is the recovery path. The member's daemon shows "This room moved while you were away. Ask an admin for a new invite." when the old endpoint no longer answers; an admin re-admits with "re-admit as the same member" (section 6.1 step 3).

### 4.7 Lane endpoint key

1. The gateway creates a new lane `serverId` and X25519 key.
2. An admin appends `lane.offer.rotated` with the new offer.
3. Member devices with access receive it, request new grants, and call `hosts.update` with the new connection (routes drop once).
4. The old lane endpoint stops at once (there is no reason to keep it: every holder of the old offer can be evicted).

Policy `genesis.policy.rotateLaneOnRemove` (decided 2026-10-29):

- `"compromise"` (default): rotate every lane the removed member or device had access to **only when the removal is flagged as a compromise** (`member.removed` or `device.removed` with `reason: "compromise"`). The removal dialog asks "Do you suspect this device or person of misusing access?" and sets the flag.
- `"always"`: rotate on every removal. Org policy can require this (`identity-model.md` section 5.2.1).

Residual risk with the default: a former member removed without the flag keeps the lane offer (`serverId` and endpoint key). Their grants are revoked and the allowlist refuses them, so they cannot read the lane. They can still reach the lane endpoint's pre-auth surface (rate-limited, P-15) and evict it on the relay (P-16) until the next rotation. The trade-off accepted is avoiding a route restart for every member of the lane on routine departures.

### 4.8 Node key

Reserved until a standalone host exists. Same pattern as the host key, certified by `node.certified` (admin).

### 4.9 Keystore wrapping key (KEK)

Local only. On request, after a backend change, or after the fallback file existed (`identity-model.md` section 7.5): generate a new KEK, re-seal every file (write new, fsync, rename), store the new KEK in the keyring, then delete the old one. No room statement, because nothing outside the device depends on it.

## 5. Effect on MLS groups

| Event | MLS action | Committed by |
|---|---|---|
| Member admitted, device linked | Add (one leaf per device) | any device that is a leaf of the group (roster-determined Add, decision round 7); normally the admitting admin daemon for the room group |
| Device rekeyed | Remove old leaf + Add a KeyPackage with the new credential (same `memberId` and `deviceId`, new `deviceSig` and leaf key), adjacent to `device.rekey.approved` | in the room group, the admin device that signs the approval; in subgroups and on repair, any device that is a leaf of the group (decision round 7) |
| Periodic leaf refresh | UpdatePath, credential unchanged (HPKE key only) | the device |
| Device removed, member removed or left | Remove of each affected leaf | any member device; the host asks the first online admin or member |
| Admin key rotated, added or removed | GroupContextExtensions (authority extension) | an admin device |
| Host key rotated | none | |
| Endpoint or lane key rotated | none | |
| Admin key compromised | Remove leaves whose devices left the roster at the re-fold; then ReInit to a new group | a remaining admin |
| Seated-agent gateway seated or unseated (future) | Add or Remove of the gateway leaf | any device that is a leaf of the group (roster-determined since decision round 7; `seat.added` itself needs an admin or `maintain` device) |

The authentication-service rules that enforce this table are in `mls-integration.md` section 4.

## 6. Compromise recovery procedures

Each procedure lists who acts, what is signed, and what stays exposed.

### 6.1 Lost device (not known to be compromised)

1. An admin removes it (`device.removed`, admin-signed). A device can remove only itself (decision round 3), so the member's other devices cannot; their UI offers "Ask an admin to remove this device", which notifies the admins. A member who still has the device and wants to retire it removes it from that device (`reason: "self"`).
2. Enforcement: sessions and grants of that device cut (`grants-v2.md` section 7); device keys enter the denylist; MLS Remove of its leaf.
3. If it was the member's only device: the member stays in the roster with no devices (`room-log-v2.md` section 5). The admin may later admit a new device for the same person with a new invite. The admin chooses "re-admit as the same member", which produces `member.device.replaced {removed: [], added, ver}` (admin-signed) linking the new device to the existing `memberId`. Other members see a key-change notice. Removing the device also cancels any device add or rekey it had requested, in the fold, which is what stops a thief who holds a stolen only device (`identity-model.md` section 6.3).
4. Exposure: everything the device could decrypt up to removal, and whatever state is on the lost disk (sealed under a KEK in its keyring; readable if the attacker can unlock that keyring).

### 6.2 Stolen grant

1. Detection: `grants-v2.md` section 6 (second live link, or a link the member cannot account for).
2. Automatic response: both links cut, the gid unlisted, `grant.suspected_theft` logged. The member reissues by proof of possession.
3. If it repeats: treat as 6.3.
4. Exposure: lane content (watch role) for the time the thief held a link. The grant gives nothing on the room endpoint, so no chat or log content.

### 6.3 Compromised member device

1. An admin removes the device with `reason: "compromise"`. The removal dialog lists every device the compromised device added (`device.added` with that `addedBy`, and anything those devices added in turn) and offers to remove them in the same step (S-2). Held adds and rekeys requested by the compromised device are cancelled by the fold (`room-log-v2.md` section 4.3), not only by the host.
2. MLS Remove gives post-compromise security for later messages. Earlier messages and retained epoch secrets on that device are exposed.
3. Rotate lane offers the device had access to (4.7), because the device knew them. This is the `reason: "compromise"` case, so it happens under the default policy.
4. The member re-links from a clean device (`identity-model.md` section 6.3) or is re-admitted.

### 6.4 Compromised host key or host state (standalone host, later)

The host cannot change membership. With the host key and state an attacker can: issue grants for real devices, read lane offers and the endpoint key (if the state includes them), reorder or drop log entries, and equivocate.

1. An admin rotates the host key to a key on the new host (`host.key.rotated`, section 4.5), then revokes the old one: `host.key.revoked {kid, fromSeq}`, with `fromSeq` the position of the earliest suspect entry and not before the revoking admin key's authority start. All grants from it fail at once; devices reissue from the new host.
2. Rotate the endpoint key (4.6) and every lane key (4.7).
3. Members re-check the log: entries signed by the old host key from `fromSeq` to the revocation are suspect for ordering, and later entries with that key are invalid. Statements inside them carry their producers' signatures and remain valid if those producers' keys were valid. Members compare heads (`room-log-v2.md` section 6) to find equivocation.
4. MLS: no change needed for confidentiality, because the host never had group secrets.

### 6.5 Compromised owner machine (embedded host)

In the pair deployment, the admin key, host key, endpoint and lane keys, the owner's device keys and the KEK are on one daemon (`identity-model.md` section 7.4). A compromise of that machine or OS user gives all of them. There is nothing to rotate to that the attacker cannot also see while they keep access.

1. Regain control of the machine first (outside this spec).
2. If the room has another admin on another machine, or a recovery key: that admin or the recovery key revokes the compromised admin key (6.6), then the remaining admin creates a new host elsewhere or on the cleaned machine.
3. Otherwise: create a **new room** from the clean machine. Members join with new invites and SAS. The old room is closed by any member who still trusts it, by leaving.
4. Recommendation: rooms that matter have a second admin on a different machine, or a recovery key kept offline.

### 6.6 Compromised admin key

1. Another admin, or the recovery key, appends `admin.key.revoked {kid, fromSeq}`. `fromSeq` is the position of the earliest statement by that key that its owner does not recognise; the UI lists the key's statements with their positions to help choose it. The bounds of `room-log-v2.md` section 5.1 apply to admin keys and to R: neither reaches back before its own authority start.
2. Every statement by that key at a position `≥ fromSeq` becomes **suspect** and loses its effect: the fold is recomputed without it (`room-log-v2.md` section 5.1). Statements that depended on it become void. A ghost device admitted by the stolen key therefore leaves the roster at once, without waiting for an admin to revert it. Members see the suspect and void statements marked in the history.
3. Remaining admins re-issue, as new statements, any suspect change they want to keep. `admin.reaffirmed` from the first draft is removed: re-applying an old statement would conflict with the replay rules of `room-log-v2.md` section 5.
4. **The recovery key wins races** (S-8). If the stolen key revoked the honest admin before the honest admin revoked it, the honest admin's revocation is refused. The recovery key then revokes the stolen key with a `fromSeq` at or before the stolen key's revocation (and not before R's own authority start). The re-fold makes that revocation suspect, so the honest admin's statements before it take effect again, but the honest admin's key stays retired (decision round 8, item 3). If that leaves no active admin key, R may still sign the revocation; R then adds a fresh key for the honest admin with `admin.added`, which starts its own lineage (`room-log-v2.md` section 5.1, step 4). Without a recovery key, the revocation the host sequences first stands, and a single remaining honest admin may lose. This is the main reason the create-room dialog offers a recovery key by default.
5. MLS: the devices that left the roster at the re-fold are pending removals, which the next commit must remove (`mls-integration.md` section 4.2). A `device.rekey.approved` signed by the revoked key at or after `fromSeq` loses its effect too. Its old keys were retired at the approval and its new keys leave use at the re-fold, so neither returns: the device leaves the roster, its `device.rekeyed` request is cancelled, and its leaf is a pending removal (`room-log-v2.md` section 5.1, step 9). A device that a suspect statement removed does not come back either. A remaining admin restores such a device with `member.device.replaced` (`removed: []`, new keys, new `deviceId`, after an invite and SAS), or the member links it again from another of its devices. Devices removed this way are listed in the admin's recovery view. Then a remaining admin runs **ReInit** to a new group (new group id, all current devices re-added by Welcome). ReInit is needed because the attacker may have learned group secrets through a ghost device it added.
6. If there is no other admin and no recovery key, the room cannot be recovered. Members must leave and start a new room (6.5 step 3).

### 6.7 Compromised lane endpoint key

Rotate the lane offer (4.7). Lane links are then unreachable for the old key holder. Content already streamed through the compromised key's sessions is exposed. Grants are not affected: an attacker with only the lane key can impersonate the lane endpoint to members and collect their bearer grants for that lane, which the allowlist then invalidates once the lane is rotated.

### 6.8 Closing a room

Decided in round 3 (2026-10-29): `room.closed` needs the recovery key or a second admin's signature, and it cannot be undone. Decision round 4 (item 1) made the second admin independent and added a delay (re-review finding R-3). The rules are in `room-log-v2.md` section 5.2.

- **With a recovery key:** the recovery key signs `room.closed {proposal: null}`. No delay.
- **With two independent admins:** one admin signs `room.close.proposed {exp}` (at most 7 days ahead), and an admin of a **different lineage**, already active when the proposal was sequenced, confirms with `room.closed {proposal: <bodyHash of the proposal>}` before `exp` and no earlier than `policy.closeDelay` after the proposal (24 h by default). Every member sees the proposal and its earliest confirmation time. A proposal whose signing key is removed, revoked or made suspect before confirmation is void.
- **Effect:** final. Every session ends with `access_ended room_closed`, grants are revoked and lane endpoints stop. There is no window to undo it; a group that wants to continue creates a new room. The delay comes before the closure, not after it.
- **One lineage without a recovery key** (one admin, or a creator and the co-admins they added): the admins cannot close with admin signatures, because none of them is independent of another. Any one of them can add a recovery key alone (`identity-model.md` section 5.4) and then close with it. The "Close room" dialog in such a room offers "Create a recovery key to close this room". This is not a weakness the rules leave open by mistake: one lineage is one authority, and its key can already remove every member. The first revision said that a single admin without a recovery key cannot close; that was wrong, since the admin can add a recovery key first.

**What the closure rules protect.** A single stolen admin key cannot close a room that has a recovery key or a second, independent admin lineage: it cannot confirm its own proposal with a key it created, it cannot install a first recovery key alone in a multi-lineage room, and a recovery key installed later cannot reach back before its own installation. The 24 h delay gives the holder of the recovery key or the independent admin time to revoke the stolen key first. A stolen key of a room's only lineage can close the room, as stated above.

This replaces the first draft, where any single admin key, including a stolen one, could close the room for good (S-8 (d)).

## 7. Open questions

Resolved and moved to `README.md` section 7 (decisions log): former Q2 (stranding after 30 days offline is accepted; re-invite, section 4.6). The rotation-on-removal default (4.7) was also decided there. Question numbers are kept stable.

- **Q1.** Default device key lifetime (90 days) and MLS leaf rotation (7 days or 1 000 messages): reasonable, or too frequent for rarely used rooms?
- **Q3.** Resolved by the revision: suspect statements have no effect from the moment of revocation, and admins re-issue what they keep (6.6).
- **Q4.** Threshold admin signatures (2-of-n) for removing admins would harden 6.6 further. Not in v2, apart from room closure (6.8); `adminThreshold` stays reserved in genesis.
