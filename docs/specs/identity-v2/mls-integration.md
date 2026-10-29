# MLS integration (identity v2)

- **Status:** proposed specification, not implemented. Applies from Milestone 2 (room chat), but its formats are fixed now (P-3, P-7 and P-14 are M2 blockers).
- **Resolves:** A2 on the MLS side (P-3, P-29), the MLS parts of A3, A5 and A7, and the spike findings (custom authentication service, state holds private keys, removal advisory).
- **Inputs:** `spikes/security/RESULTS.md` Spike A; ts-mls 1.6.4 type definitions (`authenticationService.d.ts`, `clientConfig.d.ts`, `incomingMessageAction.d.ts`, `createCommit.d.ts`).
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): commits must name the current roster, device rekey by UpdatePath, roster position defined as the last roster-changing entry. Revised again after the re-review (decisions round 4): the rekey window (`prevSig`, R-5), which credentials ts-mls is expected to pass to the authentication service, and the offline test that must confirm it first (section 10, test 11).

## 1. Library and version policy

| Rule | Detail |
|---|---|
| Library | `ts-mls`, pinned to **exactly `1.6.4`** in `package.json` (no range) and by lockfile integrity hash |
| Explicit dependencies | `@noble/hashes` and `@noble/ciphers` at exact versions (ts-mls imports them without declaring them; spike surprise 3) |
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

- The MLS leaf signature key is **separate** from the device signing key, so the device can rotate it with MLS Updates without an admin statement (`keys-rotation-recovery.md` section 4.2).
- The device signing key vouches for the MLS key; the admin-signed roster vouches for the device signing key. That chain is the whole authentication path.
- Vector: `vectors/vectors.json` → `mls`.

## 4. Authentication service and roster rule

### 4.1 Credential validation

**Expected calls (not verified).** By the re-review's static reading of the ts-mls 1.6.4 source (nothing executed): the library calls `authService.validateCredential(credential, signaturePublicKey)` for leaves that a commit adds or changes, including the new leaf of an UpdatePath (`processMessages.js:136`); for the GroupInfo signer and for **every** leaf of the tree when it processes a Welcome (`clientState.js:263-265`, `:578`). It does **not** validate the sender of an incoming commit again, and it does not compare an UpdatePath's new leaf with the old one. The first revision said ts-mls validates "commit signers"; that was wrong for incoming commits. The sender's role and continuity checks therefore live in our `IncomingMessageCallback` (section 4.3), which reads the sender's leaf. Test 11 (section 10) must confirm all of this before the adapter is written.

Our implementation is a closure over the room's verified state. It returns `true` only if **all** of these hold:

1. `credential.credentialType === "basic"`.
2. `identity` passes strict RJCS parsing and the `MlsIdentity` schema.
3. `roomId` equals this room's.
4. `mlsSig` equals `signaturePublicKey` byte for byte.
5. The `sig` verifies with `deviceSig` under context `mls-identity`.
6. In the **reference roster** (section 4.2), `memberId` has an active device `deviceId` whose stored signing key equals `deviceSig` byte for byte. After a device rekey this is the new key, so the device's UpdatePath credential validates. **Rekey window** (re-review finding R-5): for a leaf that the message does not add or change, `deviceSig` may instead equal the device's `prevSig`, the signing key that the device's latest `device.rekey.approved` replaced. An added or changed leaf must carry the roster key. So a Welcome sent while a rekeyed device has not yet committed its UpdatePath still validates, and a new leaf can never use an old key (`keys-rotation-recovery.md` section 4.1 step 8).
7. For a subgroup: `memberId` is in the scope roster.
8. For an added or changed leaf, `deviceSig` is not in the device denylist. The rekey-window exception of rule 6 is the only case in which a denylisted key is accepted, and only for an unchanged leaf.

**Which leaves are unchanged.** The callback receives no leaf position, so the adapter decides before each call. While processing a Welcome (`joinGroup`), every leaf other than the joiner's own is unchanged. While processing a commit, a credential is unchanged if it is byte-identical to the credential of the leaf with the same `(memberId, deviceId)` in the current tree; any other credential is added or changed. This rule gives the right answer whether or not ts-mls also passes unchanged leaves to `validateCredential` during commits, which test 11 records.

The callback has no other inputs, so the adapter sets the reference roster on the closure **before** each `processMessage`, `joinGroup` or `createCommit` call, and clears it after. A missing reference roster makes the closure return `false` (fail closed).

The closure is attached on every state load. ts-mls does not serialize `clientConfig`; a decoded state without it silently uses the accept-all default (spike surprise 3). The adapter's `decodeState` therefore takes the room context as a required argument and has no code path that returns a state without our config. A unit test loads a state and processes a commit that adds a forged credential; it must be rejected.

### 4.2 Roster equality

Every handshake message carries authenticated data (section 5) naming a roster position `{seq, hash}`. That roster is the **reference roster** for the message. `seq` is always the last roster-changing entry (`identity-model.md` section 6.1), never an arbitrary log position.

**A commit must name the current roster** (review finding S-6). Let `c` be the `seq` of the log entry that carries the commit. The commit's `roster.seq` must equal the `rosterSeq` of the fold over the entries before `c`. A commit that names an older roster is rejected, even if its leaf set equals that older roster. Otherwise a member could commit against a roster from before a removal, and keep a leaf that is pending removal, or use a role it has since lost. The committer's role is also judged in this roster (section 4.3).

The host checks the same rule before it sequences a commit (it can read the authenticated data, section 6.2) and answers `stale_roster` with the current position, so an honest committer rebuilds instead of being rejected by every member. Application messages may name an older roster; for them it is only gossip.

Before processing a commit, the member:

1. decodes the outer `MLSMessage` without processing it, reads `authenticated_data`, and parses it strictly;
2. makes sure its own verified log reaches the commit's entry `c`, that `roster.seq` is the last roster-changing entry before `c`, and that the hash of that roster equals `roster.hash`; if its log is behind, it fetches and verifies up to `c` first; if the host cannot provide it within 30 s, the commit is parked and a `withholding` alert is raised (`room-log-v2.md` section 6.5);
3. sets that roster as the reference roster and processes the commit with an `IncomingMessageCallback` that computes the resulting leaf set (current leaves minus Removes plus Adds, by `(memberId, deviceId)` from the credentials) and returns `"reject"` unless it **equals** the set of active devices in the reference roster (scope roster for subgroups);
4. after processing, recomputes the leaf set from the new state and checks equality again. On mismatch it discards the new state (the old sealed state is still on disk) and raises `roster_mismatch`.

Consequences:

- A host, a holder of the host key, or a malicious member cannot add a ghost device: no admin-signed statement admits it, so no roster contains it, so every honest member rejects the commit (P-3).
- A device removed in the roster but still in the group is a **pending removal**, not a mismatch, as long as no commit has been made since the roster change. The first commit after a removal must include the Remove, because it must name the newer roster. Members do not send application messages to a group with a pending removal older than 60 s (section 6.3). Devices that leave the roster because a revocation made their admission suspect (`room-log-v2.md` section 5.1) become pending removals the same way.
- An Update or an empty commit references the current roster and must leave the leaf set equal to it.

### 4.3 Who may commit what

| Commit content | Allowed committer | Extra check |
|---|---|---|
| Add | a device whose member has role `admin` (or `maintain` for seated gateways) in the reference roster | every added leaf validates under 4.1 |
| Remove | any member device | the removed leaf is absent from the reference roster |
| Update / UpdatePath only | any member device | `memberId` and `deviceId` unchanged in the committer's new credential; `deviceSig` either unchanged or equal to the key the reference roster now names for that device (device rekey) |
| Device rekey fallback (Remove old leaf + Add new leaf of the same `deviceId`) | an admin device | the reference roster names the new keys; used only when the device cannot commit its own UpdatePath (`keys-rotation-recovery.md` 4.1) |
| GroupContextExtensions | admin device | new `paseo_room_authority` matches the authority state at `seq` |
| ReInit | admin device | only after `admin.key.revoked` (`keys-rotation-recovery.md` section 6.6) |
| External commit, external proposals, PSK proposals | nobody | rejected |

The `IncomingMessageCallback` of 4.2 enforces this using the sender's leaf credential, read from the current tree for the commit's sender, and the sender's role in the reference roster. It cannot rely on `validateCredential` for the sender, because ts-mls is expected not to call it for the sender of an incoming commit (section 4.1). For an UpdatePath it also checks that the new leaf keeps the sender's `memberId` and `deviceId`; the library does not (section 4.1). After a `device.rekey.approved` for the sender, a changed leaf must carry the new key; an UpdatePath that keeps the old `deviceSig` is rejected.

## 5. Authenticated data and epoch anchoring

Every MLS message (commits and application messages) carries:

```
authenticated_data = RJCS({
  v: 2, typ: "mls-aad",
  roster:  { seq, hash },         // reference roster (section 4.2)
  logHead: { seq, hash }          // the sender's latest verified log head
})
```

- For commits, `roster.seq` is the last roster-changing entry before the commit's own entry (section 4.2). For a commit that carries a Remove, that is the removal statement or a later roster change.
- Vector: `mls.authenticatedData`, where `roster.seq` is 2 while `logHead.seq` is 3, because entry 3 (`grant.issued`) does not change the roster (S-14).
- `logHead` is how members gossip log heads to each other through a channel the host cannot alter (`room-log-v2.md` section 6.2). The host can only drop whole messages.
- The host records each commit in the log with `cls: "mls"`, `type: "mls.commit"`, the resulting `epoch`, and `bodyHash` of the commit bytes. Log entries carry the current `epoch`. Each commit names a log position, and the log records each commit: the MLS transcript and the room log are anchored to each other (P-7).

## 6. Delivery service on the host

### 6.1 Operations (room session, `enrollment-v2.md` section 4)

```
kp.publish   { keyPackages: [b64u...] }            ≤ 10 outstanding per device
commit.submit{ epoch, commit: b64u, welcome?: b64u, ratchetTree?: b64u }
   → ok { seq, epoch } | error stale_epoch { epoch } | error stale_roster { roster } | error not_permitted
welcome.fetch{ } → { welcome: b64u, ratchetTree: b64u, entry } | none
msg.send     { epoch, message: b64u }              application message (PrivateMessage)
msg.fetch    { fromSeq, limit ≤ 500 }
```

### 6.2 Sequencing

- The host accepts **one commit per epoch**: the first that names the current epoch and comes from an active roster device wins. Later ones get `stale_epoch`, and their senders rebuild on the new epoch.
- The host cannot verify commit contents (they are PrivateMessages). It checks only the outer epoch, size (≤ 1 MiB), sender session, and that the authenticated data names the current roster (`stale_roster` otherwise, section 4.2). Members do the real validation (section 4). A commit that honest members reject leaves those members at the old epoch and raises `roster_mismatch`; the host sees members stop advancing and logs `mls.stalled` after 5 minutes.
- Handshake messages use the **PrivateMessage** wire format, so the host does not learn proposal contents or senders. Content type and authenticated data stay visible to it (RFC 9420 section 6.3). Verify that ts-mls 1.6.4 creates PrivateMessage commits when `wireAsPublicMessage` is false (open question Q2).

### 6.3 Removal latency

A removal is enforced on grants and sessions at once (`grants-v2.md` section 7). The MLS Remove follows as soon as any member device is online:

- The host pushes `pending_remove {seq}` to every connected device. The first device to commit wins.
- A sender that sees a pending removal older than 60 s commits it before sending its next application message.
- If no device is online, the removed device still cannot fetch new messages from the host (its session is refused), but it could decrypt messages a colluding member forwards. MLS secrecy for it starts at the Remove commit.

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
| Welcome fails 2.3 or 4.1 | Refuse to join. Report to the admin through the room session. |
| Log entry references an unknown epoch | Fetch commits from the host; if missing after 30 s, `withholding`. |
| Removed device keeps sending | Host refuses its session. Members ignore messages from leaves absent from the reference roster. |

## 10. Tests (required before M2 ships)

1. **Removal regression** (ported from `spikes/security/src/mls-proto.ts`): after a Remove, the removed member cannot decrypt under the honest, forced, stale and zero-commit-secret attacks.
2. **Positive control:** the same test fails on `ts-mls@1.6.2` (installed under an alias in dev dependencies). The CI job asserts the failure.
3. **Authentication service:** forged credential, wrong `mlsSig`, valid credential for a device not in the reference roster, denylisted device, wrong room, missing reference roster: each rejected.
4. **Config re-attachment:** decode a state and process a ghost Add; rejected.
5. **Roster equality:** commit whose result has an extra leaf, a missing leaf, or a leaf with a swapped `memberId`: rejected; state not advanced.
6. **Authority extension:** Welcome with a different `adminSetHash`: rejected.
7. **Write ordering:** kill the process between steps of 8.2; restart; no message lost or double-applied.
8. **Subgroup isolation:** a room member outside a scope cannot process subgroup ciphertext (spike A.2 check, kept).
9. **Stale roster:** a commit that names a roster older than the current one is rejected by the host (`stale_roster`) and by members, including one whose leaf set equals that older roster.
10. **Device rekey:** an UpdatePath that changes `deviceSig` to the newly approved key is accepted; one that changes it to any other key, or before the approval entry, is rejected; one that changes `memberId` or `deviceId` is rejected.
11. **`mls-rekey-updatepath-welcome`** (offline unit test under `spikes/security`, ts-mls 1.6.4, no network; must run **first**, before the adapter is written; decisions round 4, item 4). Three members A, B, C. Cases: (a) B commits an UpdatePath whose new leaf has a new credential: record whether ts-mls accepts it and whether `validateCredential` receives the new credential; with the callback returning `false`, the commit must be rejected; (b) the same with a changed `deviceId`: our callback rejects it; (c) after B's rekey is approved in the test roster but before B's UpdatePath, A adds D and D processes the Welcome: record whether it fails without the `prevSig` rule and succeeds with it; (d) record whether ts-mls passes unchanged leaves to `validateCredential` while processing a commit. Outcomes: if (a) shows that a credential change is refused or not validated, device rekeys use only the admin fallback (`keys-rotation-recovery.md` section 4.1); if (c) cannot pass with the `prevSig` rule, the first Add after a rekey approval carries the fallback for every device still on its `prevSig`. The results go into `spikes/security/RESULTS.md` and this section.

## 11. Open questions

- **Q1.** Who commits Adds in the pair deployment when the owner's daemon is offline? Proposed: nobody; admission waits for the admin anyway (SAS needs the owner).
- **Q2.** Confirm ts-mls 1.6.4 emits commits as PrivateMessage when `wireAsPublicMessage` is false, and that authenticated data is readable before decryption with its decoders.
- **Q3.** ts-mls 2.0 migration timing. The adapter limits the change, but 2.0's codec changes alter state encoding; a state migration or group ReInit will be needed.
- **Q4.** Should the host verify commit signatures on PublicMessage-framed commits so it can reject garbage early? That would require PublicMessage framing and leak proposal contents to the host. Proposed: no.
- **Q5.** An independent review of the adapter and the library's commit path before release (spike A.4 risk 1).
- **Q6.** Does ts-mls 1.6.4 call `authService.validateCredential` for a changed credential in an UpdatePath, and does it allow the credential to change there? The re-review's static reading of the source says yes to both, with no continuity check of its own, and that Welcome processing validates every leaf (section 4.1). This is a reading, not a run. Our understanding that RFC 9420 leaves it to the authentication service to decide whether an updated credential still represents the same client is from memory and was not checked against the RFC text. Test 11 (section 10) answers it; the fallbacks are in `keys-rotation-recovery.md` section 4.1.
