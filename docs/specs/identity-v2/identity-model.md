# Identity model (identity v2)

- **Status:** proposed specification, not implemented. Independently reviewed on 2026-10-29 (`review/identity-v2-review.md`), revised, re-reviewed (`review/identity-v2-rereview.md`) and revised again under decisions round 4 (`README.md` section 10). Decision round 5, item 3 extends the 72 h sole-device hold to rekeys (section 6.3). Decision round 6: the admin daemon that approves a device rekey also applies it in MLS (section 5.3; `mls-integration.md` section 4.4). A targeted check of the R findings follows before code (decisions round 4, item 4).
- **Resolves:** A2 (P-3, P-29), A3 (P-4, P-14), A6 in part (P-22), A8 (P-2, M-6).
- **Depends on:** `signatures-and-encoding.md` for every byte format named here.

## 1. Scope

This document defines who the principals are, which keys each one holds, how keys are certified, and where they are stored. Protocol messages are in the other documents of this directory.

The M1 model was "one Ed25519 device key per member daemon, one member per (lane, daemon), and one host key that signs everything". Identity v2 replaces all three.

## 2. Terms

| Term | Meaning |
|---|---|
| **Device** | One installation of the `paseo-rooms` plugin on one Paseo daemon (one `PASEO_HOME`). App sessions that connect to that daemon are not devices. They act through it (P-21, see `grants-v2.md` section 10). |
| **Person** | A human. Never represented by a global identifier. Inside one room a person appears only as a room member. |
| **Room member** | A person's membership in one room: `memberId`, a role, lane access and one or more devices. |
| **Admin** | A room member whose admin key is in the room's admin set. Admin keys sign membership decisions. |
| **Host** | The component that orders the room log, stores ciphertext, runs the room endpoint and issues lane grants. Embedded in the owner's gateway in the pair deployment; standalone later. |
| **Gateway node** | A Paseo daemon running the plugin in the gateway role. It serves lane endpoints. |
| **Room endpoint** | The host's relay endpoint for a room (its own `serverId` and X25519 static key). Carries enrollment and every long-lived member session. Separate from lane endpoints (P-4). |
| **Lane endpoint** | The gateway's relay endpoint for one lane. Carries only Paseo connected-host links (Room Profile). |
| **Seated-agent gateway** | Future: a gateway that holds an MLS leaf so an agent can read and post in room chat. |

## 3. Principals

| Principal | Exists in | Identified by | Authenticated by | May |
|---|---|---|---|---|
| Room member | one room | `memberId` (`mem_` + 32 hex, random) | any of its active devices | act through its devices within its role |
| Device | one room | `deviceId` (`dev_` + 32 hex, random) and its keys | device signing key; device DH key in Noise IK | open sessions, request grants, send MLS messages, sign its own statements |
| Admin | one room | admin key id | admin key signature | create invites, admit, remove, change roles and lane access, certify host and endpoint keys, rotate admin keys |
| Host | one room | host key id | host key signature; room endpoint key in Noise | order the log, issue lane grants to roster devices, sign automatic events |
| Gateway node | one daemon | node key id | node key signature | sign lane endpoint status and seat events (reserved until a standalone host exists) |
| Lane endpoint | one lane | lane `serverId` | lane X25519 key (Noise NK, Paseo relay) | serve Paseo host links under the Room Profile |
| Seated-agent gateway (future) | one room | `deviceId` with `kind: "gateway"` | as a device | hold an MLS leaf while the agent is seated |

**The owner is not a principal.** The person who created the room is a room member with role `admin` whose admin key is in the genesis admin set. In M1 "owner" meant any caller with `daemon.manage` on the gateway daemon (P-29). In v2, every membership decision carries an admin key signature, and the owner's UI asks for confirmation before the daemon signs (section 5.3).

## 4. Keys

All signing keys are Ed25519. All Diffie-Hellman keys are X25519. Every key that leaves the device is **per room**.

| Key | Alg | Scope | Held by | Purpose | Certified by | Rotation |
|---|---|---|---|---|---|---|
| Device signing key | Ed25519 | device × room | device | signs enroll requests, the device's own statements, MLS identity bindings | admin, in the roster entry | `keys-rotation-recovery.md` 4.1 |
| Device DH key | X25519 | device × room | device | Noise IK initiator static on the room endpoint | admin, in the roster entry (and proven in the IK handshake) | 4.1 |
| MLS leaf signature key | Ed25519 | device × room | device | MLS leaf `signature_key` | device signing key (`mls-identity` binding) | replaced with the leaf at each device rekey, 4.2 (no in-place rotation: ts-mls 1.6.4's public API cannot change it, Spike A) |
| Admin key | Ed25519 | admin × room | an admin's device | signs genesis, admin statements | genesis, then admin key-change statements | 4.3 |
| Recovery key (optional, offered by default) | Ed25519 | room | offline, chosen by the creator; escrowed copy if org policy requires (section 5.4) | may add, revoke or rotate admin keys, rotate itself, and close the room | genesis | 4.4 |
| Host key | Ed25519 | room | host | signs log entries, lane grants and automatic statements | admin (`host.certified`) | 4.5 |
| Room endpoint key | X25519 | room | host | Noise IK responder static | admin (genesis, `endpoint.certified`) | 4.6 |
| Lane endpoint key | X25519 | lane | gateway | Paseo Noise NK responder static | admin (`lane.created`, `lane.offer.rotated`) | 4.7 |
| Node key | Ed25519 | gateway daemon | gateway | gateway identity to a standalone host | admin (`node.certified`) | 4.8 |
| Keystore wrapping key (KEK) | 256-bit symmetric | `PASEO_HOME` | OS keyring, or fallback file | seals every key file and MLS state at rest | n/a, never leaves the device | 4.9 |

### 4.1 Why the admin key is separate from the host key

The host key orders and transports. The admin key decides membership. M1 used one key for both (D2), so a stolen host key could mint membership (P-3). In v2:

- A host key can only issue grants to devices that are active in the **admin-signed roster**. It cannot add a device.
- The MLS authentication service accepts only leaves whose device is in the admin-signed roster (`mls-integration.md` section 4).
- In the embedded deployment both keys live on the same daemon. Separation then protects against **format confusion and future host separation**, not against a compromise of the owner's machine. Section 7.4 states this.

### 4.2 Why there is no person-level key

A person's devices in one room are tied together by the roster entry, which the admin signs. A separate "member identity key" (like Matrix cross-signing) was considered and rejected for v2:

- The admin must sign every device change anyway, because the authentication service accepts only admin-signed roster entries (A2). A member key would add a second signature without removing the admin one.
- A member key copied to every device has the widest exposure of any key. A member key held on one device makes that device a single point of failure for recovery.

The device-add flow is still signed by an existing device of the member (section 6.3), so a member can vouch for its own new device. This is listed as open question Q1.

### 4.3 Unlinkability across rooms

Rule: **no key, identifier or label is shared between two rooms.**

- Device keys, MLS keys and admin keys are generated per room.
- `memberId`, `deviceId` and every other id are random per room.
- The label shown to others is chosen per room. The member UI pre-fills it from the last label used but shows that it will be visible to that room's members.
- M1 sent `daemonServerId` in the control proof. That identifier is the same in every room. **v2 never sends it.**
- The local mapping "room → keys" lives only in the device's sealed key store.

What still links a member across rooms, stated in the threat model (`README.md` section 4):

- The relay operator sees the member daemon's IP address for every room. Gateways do not.
- Timing of activity, writing style and self-chosen labels.
- An owner who runs two rooms and asks the same person to compare SAS codes learns, by social means, that it is the same person.

## 5. Room authority

### 5.1 Genesis

A room is created by one admin. The admin's device builds and signs a genesis record (`signatures-and-encoding.md` context `genesis`):

```
RoomGenesis.body = {
  v: 2, typ: "room-genesis",
  createdAt: <unix s>,
  nonce: <16 random bytes, b64u>,
  admins: [ {alg:"ed25519", kid, pub} ],      // 1..8 entries
  adminThreshold: 1,                            // only 1 is defined in v2
  recovery: null | {alg:"ed25519", kid, pub},   // optional offline key
  host: { key: {alg, kid, pub}, notBefore, notAfter: null },
  endpoint: { serverId: "rme_<32 b64u>", dh: {alg:"x25519", kid, pub},
              relay: { host, port, tls: true } },
  policy: { minVersion: 2, sas: "sas6",
            deviceAddApproval: "same-person" | "admin",     // section 6.3
            rotateLaneOnRemove: "compromise" | "always",    // keys-rotation-recovery 4.7
            recoveryEscrow: "none" | "org",                 // section 5.4
            soleDeviceChange: "held" | "admin",                // section 6.3
            projectNames: "lane-owner" | "hidden",          // grants-v2 section 13.2
            grantTtl: <seconds, 3600..43200, default 43200>, // grants-v2 section 5
            closeDelay: <seconds, 0..518400, default 86400> } // room-log-v2 section 5.2
}
RoomGenesis = { body, kid: <signing admin kid>, sig }
genesisHash = H("genesis", RJCS(RoomGenesis))       // 32 bytes
roomId      = "room_" + hex(genesisHash[0..16])     // display and routing only
```

- `genesisHash` is the room's **authority anchor**. Invites carry it in full. Every member pins it.
- `roomId` is derived from the hash, so a host cannot pair a known `roomId` with a different genesis without a 128-bit second preimage. Every security check still uses the full `genesisHash`.
- The genesis record is plaintext. It contains no names. The room name is an MLS-encrypted `room.profile` event (`room-log-v2.md` section 4).

### 5.2 Authority state

Members derive the current authority by folding the verified room log over the genesis:

```
AuthorityState = {
  admins:   [ {kid, pub, fromSeq, toSeq|null, suspectFromSeq|null,
               root: kid, addedBy: kid | "recovery" | null, since} ],   // room-log-v2 5.1, 5.2
  recovery: {kid, pub, fromSeq, since} | null,
  hostKeys: [ {kid, pub, fromSeq, toSeq|null, suspectFromSeq|null,
               validFrom, validTo|null, revoked, uncertified} ],   // unix s fields: grants only
  adminKeyDenylist: [kid...],
  retiredKeys: [pub...],                                 // every key rotated out, removed or revoked; only grows
  endpoint: { serverId, dh, relay }, endpointUncertified,
  lanes: { laneId -> {owner, serverId, dh, relay, visibility, status, showNames, uncertified} },
  revocations: [ {kid, fromSeq, seq} ],                  // admin-key revocations in effect, room-log-v2 5.1
  policy,
  versions: { <field> -> seq | -1 },                     // room-log-v2 section 4.0
  pendingClose: [ { proposal: bodyHash, kid, seq, hts, exp } ],
  pendingRecovery: [ { proposal: bodyHash, kid, seq, change, exp } ],
  maxBase: { kid -> seq }                                // forward rule, room-log-v2 section 2
}
```

Key validity for statements and log entries is expressed in log positions (`fromSeq`, `toSeq`), never in time (review finding S-8; `keys-rotation-recovery.md` section 3). Only the host key's grant window uses unix seconds. `root` is the key's lineage root and `since` its authority start, which bounds how far back its revocations reach (`room-log-v2.md` sections 5.1 and 5.2). `uncertified` marks a host key, the endpoint or a lane offer whose installing statement a re-fold made suspect or void (`room-log-v2.md` section 5.1, step 9). Leaf repair requests (`device.leaf.repair.requested`) are kept with the roster state for 24 h of `hts`, for the rate limits and for the MLS layer (`room-log-v2.md` section 4.3).

Only admin statements (and recovery-key statements for admin changes and room closure) modify it, apart from `lane.names.changed`, which the lane owner's device signs. The table in `room-log-v2.md` section 4 lists which producer may emit which statement.

### 5.2.1 Room policy and org policy

`genesis.policy` holds the room's security settings. Defaults, all decided on 2026-10-29 (`README.md` section 7):

| Field | Default | Other value | Meaning |
|---|---|---|---|
| `sas` | `"sas6"` | (reserved: words format) | 6-digit SAS with commit-then-reveal (`enrollment-v2.md` section 6) |
| `deviceAddApproval` | `"same-person"` | `"admin"` | Who approves a new device (section 6.3) |
| `soleDeviceChange` | `"held"` | `"admin"` | When a member's only active device adds a second device or requests a rekey of its own keys: `"held"` holds the change for 72 h with a veto (section 6.3; `keys-rotation-recovery.md` section 4.1); `"admin"` requires an admin's approval instead (decision round 4, item 2, for adds; decision round 5, item 3, for rekeys). Ignored when `deviceAddApproval = "admin"`, which already requires an admin for every add and rekey |
| `rotateLaneOnRemove` | `"compromise"` | `"always"` | When removing a member or device rotates lane endpoint keys (`keys-rotation-recovery.md` 4.7) |
| `recoveryEscrow` | `"none"` | `"org"` | Whether a copy of the recovery key is held by the organisation (section 5.4) |
| `projectNames` | `"lane-owner"` | `"hidden"` | `"lane-owner"`: each lane owner decides for their own lanes whether viewers see project names (hidden until they choose to show them). `"hidden"`: names are hidden on every lane and lane owners cannot show them; this is how admins force names hidden (`grants-v2.md` section 13.2) |
| `grantTtl` | `43200` (12 h) | `3600` to `43199`, only from an org policy | Lane grant lifetime in seconds (`grants-v2.md` section 5) |
| `closeDelay` | `86400` (24 h) | `0` to `518400` (6 days) | Minimum time between `room.close.proposed` and an admin's `room.closed` (`room-log-v2.md` section 5.2; decision round 4, item 1). `0` turns the delay off. A lower value never shortens an open proposal: the larger of the values at proposal and at confirmation applies |

An admin changes policy with `room.policy.changed` (`room-log-v2.md` section 4.1). Every change is a security-relevant event shown to all members (`room-log-v2.md` section 4.6).

**Org policy.** v2 has no organisation principal in the protocol. An *org policy* is a local profile installed on an admin's daemon by the organisation (for example by lab IT) that fixes some of these fields to stricter values. The Rooms UI applies it at room creation and refuses changes that would weaken it. Org policy can require `deviceAddApproval = "admin"`, `soleDeviceChange = "admin"`, a minimum `closeDelay`, `rotateLaneOnRemove = "always"`, a recovery key, `recoveryEscrow = "org"`, `projectNames = "hidden"`, and a shorter `grantTtl` (never a longer one; decision round 3). The values themselves are in `genesis.policy` and the log, so members can see them. **Limit:** this is enforced by the admin's own plugin, not cryptographically. An admin who removes the profile from their own daemon can weaken the policy, and the `room.policy.changed` entry then shows the change to every member. The profile's file format and distribution belong to the deployment guide; this spec defines only the fields it may fix.

### 5.3 Admin signing on the owner's daemon

In the embedded deployment the admin key sits on the owner's daemon, and the daemon signs on the owner's behalf. To address P-29 the plugin applies these rules:

- **Interactive admin actions** (create invite, admit after SAS, remove member or device, change role or lane access, add or remove an admin, rotate host or endpoint keys, propose or confirm room closure, propose or confirm a first recovery key) require a confirmation in the Rooms UI. The RPC that performs them takes a one-time `confirmToken`, which a second RPC returns together with a description of what will be signed.
- **Policy-automatic admin actions** (approve a device add or a device rekey after its hold, 24 h or, when the request comes from a member's only active device, 72 h; section 6.3) are signed without a prompt. The owner sees a notification and every member sees a notice in the room. For a device rekey the same daemon also builds the MLS commit that replaces the device's leaf and submits it with the approval (`mls-integration.md` section 4.4); it does not sign the approval when it cannot build that commit.

**This is a usability guard, not a security boundary** (review finding S-12). It prevents accidental signing, and it makes an agent that calls `rooms.*` RPCs by mistake stop at a step a human normally takes. It does not stop deliberate same-user code: the CLI, an agent with a shell or another plugin can call the `confirmToken` RPC as easily as the UI does, and the daemon cannot tell those callers apart. A code shown in the app and typed back by the user does not help either, because the same code can read it through the same RPCs. Same-user code is out of scope by decision 1 (section 7.4). P-29 is therefore closed only to the extent of separating the admin key from the host key; protection against same-user callers needs the dedicated OS user (section 7.6) or an upstream per-caller confirmation primitive, which Paseo 0.13.2 does not offer as far as we know.

### 5.4 Recovery key and escrow

Decision (2026-10-29): the recovery key is **offered by default and optional**. Org escrow follows org policy.

- **Room creation.** The create-room dialog includes a "Create a recovery key" step, preselected. The creator can skip it with one click. The dialog says what skipping costs: "Without a recovery key, a room with one admin cannot be recovered if that admin's key is lost or stolen. Members would have to start a new room." This follows the opt-in preference in that the key is never forced on a room without org policy, while the default path produces one.
- **Form.** 32 random bytes (the Ed25519 seed), shown once as a printable code (section 5.4.1) and offered as a file to save. The seed is not stored on the daemon after the dialog closes. Only the public key enters `genesis.recovery`.
- **Adding later.** A room created without a recovery key can add one with `recovery.key.rotated` from `null`, signed by an admin key, since there is no previous recovery key. Members see a notice. In a room with one admin lineage (one admin, or a creator and the co-admins they added) one admin signs it alone. In a room with two or more independent admin lineages, one admin proposes it (`recovery.key.proposed`) and an admin of another lineage confirms it (decision round 4, item 1; `room-log-v2.md` section 5.2). So a single stolen admin key cannot install a recovery key of its own in a room that has an independent admin. A recovery key added later cannot revoke statements made before it was installed (`room-log-v2.md` section 5.1).
- **Org escrow.** When org policy sets `recoveryEscrow = "org"`, room creation also requires a recovery key and hands a copy of the seed to the organisation's escrow, as the org profile specifies (for example, encrypted to an org public key and saved for upload). `genesis.policy.recoveryEscrow = "org"` tells members that someone outside the room can revoke and add admin keys. The escrow transport and custody are outside this spec.
- **What the recovery key can do:** `admin.key.revoked`, `admin.added`, `recovery.key.rotated` and `room.closed` only (`keys-rotation-recovery.md` section 4.4). Its revocations take precedence over those of admin keys (`room-log-v2.md` section 5.1).

### 5.4.1 Recovery code format

The recovery code is the printable form of the recovery seed. It carries a checksum, so a typing error is reported as a typo and not confused with a correctly typed code of another key.

```
check = first 3 bytes of H("recovery-code", seed)             // signatures-and-encoding 3.3
body  = lowercase base32 (RFC 4648 alphabet, no padding) of seed ‖ check
        // 35 bytes = 280 bits = exactly 56 characters
code  = "prk2-" + body in 14 groups of 4 characters joined by "-"
        // e.g. prk2-abcd-efgh-...  (74 characters in total)
```

- **Alphabet.** `a` to `z` and `2` to `7`. The digits `0`, `1`, `8` and `9` never occur, which avoids the `0`/`o` and `1`/`l` confusion when the code is read aloud or copied by hand. Groups of 4 match the display fingerprints (`signatures-and-encoding.md` section 5.3).
- **Checksum.** 24 bits of a domain-separated hash of the seed. Under the usual model of SHA-256 as a random function, a corrupted code of the right length and alphabet passes the checksum with probability 2^-24 (about 1 in 16.8 million). The vector generator and the unit tests also check that every one of the 1736 single-character substitutions of the vector code is detected. The checksum is a usability aid, not a security control: the code is accepted only if its public key equals the room's current recovery key, which already rules out a wrong code.
- **Parsing.** Case is ignored; spaces, line breaks and hyphens anywhere are ignored. The checks run in this order and each has its own error and message:

| Error | When | Message |
|---|---|---|
| `not_recovery_code` | the text does not start with `prk2` | "This is not a Paseo room recovery code. Recovery codes start with prk2-." |
| `wrong_length` | not exactly 56 characters after the prefix | "The recovery code should have 14 groups of 4 characters after prk2-. A character is missing or extra." |
| `bad_character` | a character outside the alphabet | "The recovery code contains a character that recovery codes do not use. They use only the letters a to z and the digits 2 to 7." |
| `typo` | the checksum does not match | "The recovery code has a typo. Compare each group with your saved copy." |
| `wrong_key` | the checksum matches, but the public key of the seed is not the room's current recovery key | "This recovery code is typed correctly, but it is not the current recovery key of this room." |

- **Saved file.** The file offered at creation is `paseo-room-recovery-<roomId>.json` with `{ v: 2, typ: "recovery-key", roomId, genesisHash, kid, code }`. It holds the same code, so the same parser reads it.
- **Version.** The `2` in `prk2` is the format version. Codes printed by earlier development builds (52 characters, no checksum) are not accepted; none were issued outside tests.
- Vector: `vectors.json` → `recoveryCode` (encoding, three accepted spellings, and one rejected case per error).

## 6. Membership model

### 6.1 Roster

```
RosterEntry = {
  memberId: "mem_<32 hex>",
  role: "guest" | "watch" | "comment" | "steer" | "approve" | "maintain" | "admin",
  lanes: [ "lane_<32 hex>", ... ],         // lane access; sorted, unique
  devices: [ DeviceEntry, ... ]             // 0..8 active devices; sorted by deviceId (0 only after an admin
                                            // removed the last one: room-log-v2 section 5)
}
DeviceEntry = {
  deviceId: "dev_<32 hex>",
  kind: "person" | "gateway",
  sig: <Ed25519 pub b64u>,                   // device signing key
  dh:  <X25519 pub b64u>                     // device DH key
}
Roster     = { roomId, seq: rosterSeq, members: [RosterEntry...] sorted by memberId }
rosterHash = H("roster", RJCS(Roster))
```

- `rosterSeq` is the `seq` of the last log entry that changed the roster (`room-log-v2.md` section 5). "The roster at position `p`" means the roster after the fold of entries up to `p`, and its `seq` field is the last roster-changing entry at or before `p`, not `p` itself. MLS authenticated data and `log.witness` always name that value (review finding S-14).
- The roster is a deterministic fold over the verified log. Every member computes the same roster and hash.
- Labels are **not** in the roster. They travel as MLS-encrypted `member.profile` events, so the host does not learn them.
- Roles above `watch` are reserved for M2 and later. Their meaning is `rooms-architecture.md` section 4.

### 6.2 Revocation scopes

Every revocation names its scope. M1 had only "member on a lane" (P-4).

| Scope | Statement | Effect |
|---|---|---|
| Lane access | `member.lanes.changed` (admin) | grants for that lane revoked; lane links cut; room membership and MLS leaf unchanged |
| Role | `member.role.changed` downward (admin) | grants reissued at the new role; lane links at the old role cut (`grants-v2.md` 7.1) |
| Device | `device.removed` (admin for any device; a device only for itself) | that device's sessions, grants and MLS leaf removed; device keys enter the denylist |
| Member | `member.removed` (admin) or `member.left` (the member's only active device) | all devices removed; all grants revoked; MLS Remove of all leaves |

The **device key denylist** holds every device signing key and DH key that was ever removed or rotated out. A denylisted key cannot be admitted again in this room, from any invite. Keys are per room, so the list is small. The **admin-key denylist** does the same for admin keys that were removed, rotated out or revoked; `admin.added` cannot bring them back (S-1).

**A device can remove only itself** (decision round 3, review finding S-2). Removing another device of the same person needs an admin. So a stolen device cannot remove the person's other devices. `member.left` removes every device of the member, so a device may sign it only when it is the member's only active device. Conversely, a member's last device leaves with `member.left`, not with `device.removed`. Only an admin can remove a member's last device and keep the member, which leaves a member with no devices until the admin restores or removes them (`room-log-v2.md` section 5; re-review finding R-8).

### 6.3 Multi-device

A member adds a device by **device linking** (protocol in section 6.4). It reuses the enrollment protocol with the member's existing device A as the confirmer:

1. On A, the member chooses "Link another device". A creates a one-time link code (`prl2.`, 10 minutes).
2. Device B runs enrollment with that code. The SAS is shown on B and on A, which computes it itself. The person compares their own two screens.
3. A confirms and signs a `device.added` statement with B's keys and B's proof of possession (B signs the key-change binding with context `key-change-new`, `KeyChange.old = null`).
4. Approval follows `policy.deviceAddApproval`:
   - **`"same-person"` (default):** the add is **held for 24 hours** (decision round 3), or **72 hours when A is the member's only active device** (decision round 4, item 2). During the hold, every active device of the member, including A, shows "A new device, *<label>*, will join your membership in this room at *<time>*. Was this you?" with a **Not me** button. Every member sees "Sam is adding a device". When the hold passes with no veto, the admin's daemon signs `device.add.approved {mode: "auto"}` without a prompt. The owner gets a notification and every member sees "Sam added a device" with the key-change marker.
   - **Sole device.** When A is the member's only active device, the admins' notification is marked as such: "Sam has only one device in this room, and it is adding another. If Sam did not ask for this, remove the device." The room notice says the same. Org policy can set `soleDeviceChange = "admin"` (section 5.2.1), so these adds wait for an interactive admin approval instead of the 72 h hold.
   - **Not me** signs `device.add.vetoed`. The add is cancelled, so B never joins. The member is flagged with a **device conflict**: no automatic approval happens for that member until an admin signs `device.conflict.resolved`, and the admins see "Sam's devices disagree about a new device. One of them may be stolen." The veto removes no device. The admin decides which device, if any, to remove.
   - **Young devices cannot auto-add.** A device that has been active for less than 24 hours cannot request an automatically approved add. Its requests wait for an admin. Otherwise a thief could add B, wait out the hold, and use B to add C, timing each hop to land after the person stops watching.
   - **`"admin"`:** every device add needs an interactive admin approval (section 5.3, `mode: "admin"`), with no hold. Org policy can force this value (section 5.2.1). An admin can also approve a held add early, interactively.
   - **Admin approval is always required** when the person has no active device in the room (re-admission after losing every device, `keys-rotation-recovery.md` section 6.1), and for `member.device.replaced`. These go through an invite and SAS with the admin.

For several rooms, B runs one link per room. The UI batches this. Each room still sees an independent key set.

**Why a hold and a veto.** Decision round 2 auto-approves a device added by the same person. Without a brake, anyone holding a copy of A's keys could add a device of their own, remove the person's other devices and rekey A, leaving the person locked out (S-2). The hold gives the real person a day (three days when the request comes from their only device) to say "Not me" from any of their devices, or to tell an admin, and the self-only removal rule keeps their other devices in place meanwhile. The same hold and veto apply to automatic device rekeys, including the 72 h hold and the `soleDeviceChange` option when the rekeyed device is the member's only active device (decision round 5, item 3; `keys-rotation-recovery.md` section 4.1).

**What the hold does not cover.** A person who has only device A, and whose A is stolen, can veto only from A itself. If they no longer have A, nobody vetoes, and the thief's device joins after the 72 h hold. The same holds for a rekey of A requested with A's stolen keys: it takes effect after 72 h and denylists the keys the person still holds. The room notice and the owner notification are then the only signals. Org policy can set `soleDeviceChange = "admin"` (or `deviceAddApproval = "admin"` for every add and rekey) to remove this case.

**Guidance for a person who loses their only device.** Shown when a device is linked or a member joins, and in the Rooms help:

> "If you lose this device, or it is stolen, tell an admin of each room as soon as you can, and at the latest within 3 days. The admin removes the device. That also cancels any device the thief tried to add, or any key change the thief requested for this device, because both wait 3 days when they come from your only device. After that, the admin can let you back in with a new invite."

This works because removing A cancels every pending add that A requested, and A's own pending rekey, in the fold itself (`room-log-v2.md` section 4.3, re-review finding R-8). The admin's removal dialog for a sole device says "Removing this device also cancels the device it is adding (joins at *<time>*)" when such an add is pending. The guidance names "3 days" because it is the hold for this case; under `soleDeviceChange = "admin"` the admin approves every such add and rekey anyway, and the text drops the deadline.

**Losing every device** means the member can no longer prove anything. Recovery is a new invite, admitted by an admin, optionally reusing the old `memberId` (`keys-rotation-recovery.md` section 6.1).

### 6.4 Device link protocol

This subsection fixes the formats and states that the first draft left open (S-13). A device link is an enrollment (`enrollment-v2.md` section 5) with three differences: it names a link instead of an invite, the confirmer is device A instead of an admin, and **A, not the host, chooses the confirmer nonce**.

**Creating a link (on A).**

1. A generates `token` (32 random bytes) and `linkId = "lnk_" + 32 hex`. It computes `tokenKey = HKDF(token, "", TBS("link-token-key", ""), 32)` and `linkRef = b64u(H("link-ref", utf8(linkId)))`.
2. A signs `device.link.created { memberId, linkRef, exp }` with `exp ≤ now + 10 min`, and sends on its room session:
   `device.link.create { id, linkId, tokenKey, exp, statement }` → `device.link.create.ok { re }`.
   The host stores a `LinkRecord`, logs the statement and replies. The token never reaches the host.
3. A shows the code:

```
DeviceLinkPayload = {
  v: 2, typ: "device-link",
  roomId, genesisHash, roomName: <≤80 chars, display only>,
  endpoint: { serverId, dh: {alg:"x25519", kid, pub}, relay },
  linkId, token: <32 bytes b64u>, exp: <unix s>, sas: "sas6"
}
LinkCode   = "prl2." + b64u(RJCS(DeviceLinkPayload))
LinkRecord = { linkId, tokenKey, memberId, createdBy: deviceId, createdAt, exp,
               state, failedProofs: 0, abandoned: 0, pendingId: null, usedBy: null }
```

`LinkRecord.state` and the attempt limits are those of an invite (`enrollment-v2.md` sections 2.1, 5.4 and 7.1). B's daemon applies the same member-side checks to a `prl2.` code as to an invite (`enrollment-v2.md` section 2.3).

**Enrolling B.**

1. B sends `enroll.request` with `linkId` in place of `inviteId`, in both the frame and `EnrollSigned`. `tokenMac` uses the link's `tokenKey`. The host runs the check order of `enrollment-v2.md` section 5.3 against the `LinkRecord`.
2. At step 9 the host creates the pending enrollment with `confirmer: { kind: "device", deviceId: A }`, assigns B's `deviceId`, and pushes to A's session:
   `link.request { pendingId, linkId, deviceId, request: EnrollSigned, sig }`.
   A checks that `linkId` is its own open link and that `sig` verifies with `request.deviceSig`. It applies its own attempt limits (below). It pins `pendingId`, `request.h` and `request.sasCommit`.
3. A chooses `Nc` (32 random bytes), writes the pinned `(pendingId, h, sasCommit, Nc)` and its updated counters to its sealed state with fsync, and only then sends `link.nonce { id, pendingId, Nc }`.
4. The host sends B `enroll.pending` with `Nh = Nc` and the assigned `deviceId`. B verifies it (`enrollment-v2.md` section 5.5), signs `KeyChange { subject: {kind:"device", id: deviceId}, old: null, newSig, newDh }` with its new signing key, and sends `sas.reveal { Nm, newKeySig }`.
5. The host checks the commitment and forwards `link.reveal { pendingId, Nm, newKeySig }` to A. A checks `H("sas-commit", Nm)` against the pinned commitment itself, computes the SAS from the pinned `h`, `Nm`, `Nc` and the info object with `linkId` (`enrollment-v2.md` section 6.2), verifies `newKeySig`, and shows the SAS.
6. The person compares the two screens. On A, **Codes match** makes A sign `device.added` and send `link.confirm { id, pendingId, statement }`. On B, **Codes match** sends `enroll.confirm`. **Codes do not match** on either device aborts and burns the link: B sends `enroll.abort {reason: "sas_mismatch"}`, and A sends `link.abort { id, linkId, pendingId, reason: "sas_mismatch" }`. A also marks the link burned in its own sealed state, whatever the host does.
7. When both confirmations are in, the host logs `device.added`. The fold accepts it only if `linkRef` names a `device.link.created` of the same member and that link has not added a device yet; one link adds one device. B's `deviceId` is reserved from this entry on, so a vetoed or cancelled add burns it and a later link uses a new one (`room-log-v2.md` sections 4.3 and 5). The host then sends B `enroll.held { pendingId, entry, effectiveAfter }` (or `effectiveAfter: null` while it waits for an admin). B's journal moves to `held` and B may disconnect.
8. When `device.add.approved` is logged, B's next `enroll.resume` returns `enroll.admitted` carrying that statement. A veto, the removal of A or of the member (which cancels the add in the fold, `room-log-v2.md` section 4.3), or 48 hours without approval after the hold ends close the pending enrollment (`enroll.closed vetoed | rejected | timeout`). Under admin approval with no hold, the 48 hours count from `device.added`.

The host tells A when a pending enrollment on its link ends: `link.closed { linkId, pendingId, reason }`, with `reason` as in `enroll.closed` plus `"abandoned"`.

```
device.added.data = {
  memberId, device: DeviceEntry(B),
  change: KeyChange { subject: {kind:"device", id: B.deviceId}, old: null, newSig: B.sig, newDh: B.dh },
  newKeySig, addedBy: A.deviceId,
  confirmation: { method: "sas6", linkRef, transcript: H("sas-transcript", h ‖ Nm ‖ Nc ‖ info) }
}
```

**Why A chooses the nonce.** If the host chose it and passed only SAS inputs to A, a malicious host could run its own device B′ next to the real B. It could pick B′'s values after learning B's, until the two SAS codes matched, and A would then sign B′'s keys. Because A pins B′'s commitment and `h` before it sends `Nc`, the host must fix B′'s values before it learns `Nc`, which is the commit-then-reveal argument of `enrollment-v2.md` section 6.1. This keeps the A2 property that a host cannot add a device.

**A enforces its own attempt limits** (decision round 4; re-review finding R-2). The argument above holds for one attempt. The host keeps `LinkRecord` counters, but in this threat the host is the adversary: it could push many `link.request`s with fresh B′ commitments, under new `pendingId`s, and drop every attempt whose SAS on A does not match the code real B shows, until one does (about 10^6 tries; A answers in milliseconds). So A counts for itself and never relies on the host's counters:

| Limit on A | Value | Effect |
|---|---|---|
| `Nc` per `pendingId` | 1 | A re-push of the same `pendingId` with byte-identical inputs gets the same pinned `Nc` again (a lost reply); a re-push with different `h`, `sasCommit` or `deviceSig` makes A abort and burn the link |
| Open pending enrollments per link | 1 | A sends no `Nc` for a new `pendingId` while an earlier one is open. A pending is open from A's `link.nonce` until `link.closed`, A's own `link.confirm` or `link.abort`, or 15 minutes on A's clock, whichever comes first. A request that arrives while another is open gets no answer and does not count |
| `Nc` per `linkId` in total | 3 | After the third, A treats the link as burned: it sends `link.abort {reason: "attempts"}`, answers no further `link.request` for it, and shows "This link was used too many times. Create a new one if you still want to add a device." |

A persists the counters, the burned flag and the pinned inputs in `member/rooms/<roomId>/state.sealed` before it sends `link.nonce`, so a restart of A does not reset them. With these limits a malicious host gets at most 3 SAS comparisons per link, 3 × 10^-6, the same bound as an invite (`enrollment-v2.md` section 6.1). Like the admin's join card, A's confirmation screen shows "*N* earlier attempts on this link" when `N > 0`.

**Host states.** The `LinkRecord` follows the invite state machine (`enrollment-v2.md` 7.1). The pending enrollment follows 7.2, with A taking the admin's transitions, and adds a state `held` between "both confirmed" and `admitted`.

Vectors: `deviceLink` (payload and `prl2.` code, `linkRef`, token key, B's handshake hash, `EnrollSigned`, token MAC, SAS with A's nonce, `device.added`, `device.add.approved`, and a folded chain in which the approval comes 72 h after the request of a sole device that had been active for more than 24 h). `deviceRekey`: a sole device's rekey, whose automatic approval is rejected after 24 h and accepted after 72 h.

Required test (R-2): A receives a fourth `link.request` for one link, each with a new `pendingId`, and sends no `link.nonce` for it; after a restart of A, the count is still 3.

## 7. Key storage

### 7.1 Layout

All rooms data lives under `$PASEO_HOME/plugin-data/rooms/`: owner-only on every OS (POSIX `0700`/`0600`, Windows DACL; section 7.8), written atomically and durably per platform (`grants-v2.md` section 7.3).

| Path | Contents | Sealed under KEK | Integrity-critical |
|---|---|---|---|
| `keystore/meta.json` | backend name, `kekId`, creation time, fallback flag; the record that a keyring KEK exists (section 7.3) | no | yes |
| `keystore/kek.fallback` | only in fallback mode: the KEK (a DPAPI blob on Windows when available) | no (it is the KEK) | yes |
| `member/rooms/<roomId>/keys.sealed` | device signing, DH and MLS keys for this room; for the creator, written at room creation together with the admin and host key files | yes | yes |
| `member/rooms/<roomId>/state.sealed` | pinned `genesisHash`, authority state, roster, log heads, enrollment journal | yes | yes |
| `member/rooms/<roomId>/mls.sealed` | encoded MLS group state | yes | yes |
| `admin/<roomId>/admin-key.sealed` | admin key | yes | yes |
| `admin/<roomId>/state.sealed` | the admin's outstanding signed statements (no receipt and no definite rejection yet), written before a statement is returned, so a restart still knows them (room-log-v2 section 2, forward base) | yes | yes |
| `host/<roomId>/keys.sealed` | host key, room endpoint key, lane endpoint keys, and the pinned `genesisHash` of the room | yes | yes |
| `host/<roomId>/genesis.json` | the signed genesis, RJCS text; public | no (checked against the `genesisHash` pinned in `host/<roomId>/keys.sealed`) | yes |
| `host/<roomId>/state.sealed` | invites (token keys), pending enrollments, grant allowlist | yes | yes |
| `host/<roomId>/log/` | envelopes and bodies (`room-log-v2.md` section 8) | no (bodies are MLS ciphertext) | yes |

The host pins the room's `genesisHash` inside its sealed key file rather than sealing the genesis itself: the genesis is public and is sent to every joiner, but the host must not accept a different one. On open, the host refuses the room when `genesis.json` does not verify or its hash differs from the pinned value (`room-log-v2.md` section 8.1).

"Integrity-critical" closes M-6: whoever can modify a pinned key decides whom the device trusts. Sealing with an AEAD also detects modification.

### 7.2 Sealed file format

```
Sealed = { v: 2, typ: "sealed", alg: "xchacha20poly1305", kekId, purpose,
           nonce: <24 random bytes b64u>, ct: <b64u> }
fileKey = HKDF-SHA256(ikm = KEK, salt = "", info = TBS("file-key", utf8(purpose)), L = 32)
AAD     = RJCS({ v: 2, typ: "sealed", purpose, kekId })
```

`purpose` names the file role and owner, for example `mls-state:<roomId>:<deviceId>`. A sealed file copied to another purpose fails to open. `kekId` is `"kek_"` followed by 32 lowercase hex characters, chosen at random when the KEK is created and recorded in `keystore/meta.json`; it lets the plugin tell which KEK a file was sealed under during KEK rotation (`keys-rotation-recovery.md` 4.9). Vector: `vectors.json` → `sealed` (the KEK id, the AAD and the complete outer object).

### 7.3 KeyStore abstraction and backends

The plugin keeps exactly one secret outside its own files: the 32-byte KEK. All key-storage code goes through one interface:

```
KeyStore = {
  name: "macos-keychain" | "windows-credman" | "linux-secret-service" | "cli:<tool>" | "fallback-file",
  probe(timeoutMs)  -> "available" | "locked" | "unavailable",
  get(timeoutMs)    -> KEK bytes | null,        // null only means "no entry"; locked or OS errors throw
  put(kek, timeoutMs), delete(timeoutMs)
}
```

Entry name: service `paseo-rooms`, account `kek:<hex sha256(canonicalHome)[0..16]>`. `canonicalHome` is `fs.realpathSync.native(PASEO_HOME)` encoded as UTF-8; on Windows it is first converted to lower case, because Windows paths are case-insensitive and the same home can be reached with different casing.

**Backends** (keyring spike, `spikes/keyring/RESULTS.md`, 2026-10-29):

| Platform | Backend | Binding | Status |
|---|---|---|---|
| macOS | Keychain, login keychain, generic password | `@napi-rs/keyring` 2.1.2 | **Untested** (no macOS host). The binding has no ACL or partition-list option, so "item ACL limited to the Paseo binary" is **not available**; any same-user process the Keychain trusts can read the item. Prompt behaviour after unsigned or re-signed Paseo updates is a hypothesis to check. |
| Windows (native) | Credential Manager, generic credential (DPAPI-protected, per user) | `@napi-rs/keyring` 2.1.2 | **Untested** (no Windows host). No prompt. A service running as LocalSystem uses LocalSystem's vault, not the person's. |
| Linux desktop | Secret Service over D-Bus (GNOME Keyring; KWallet 5.97 and later through its Secret Service API) | `@napi-rs/keyring` 2.1.2, **always with `{ linux: { store: "secret-service" } }`** | **Tested** on Ubuntu 24.04 with GNOME Keyring under Paseo's runtime (Node 24.20.0, Electron 44.2.0, N-API 10): store, read, delete and search behave correctly. The `.node` file needs only libc-level libraries (libdbus is statically linked). |
| Linux, no session bus (servers, Docker, systemd system services) | fallback file (section 7.5) | none | Tested for the detection path: the pinned store throws at construction in under 1 ms. |
| WSL | as Linux. Usually no Secret Service, so the fallback file. Windows Credential Manager is not reachable from the Linux side. | | **Untested.** |
| Flatpak portal | not supported by the binding | | |

**The kernel keyring (Linux keyutils) is never an acceptable KEK backend.** It does not persist across logout or reboot, so a KEK stored there would be lost with every sealed file. The spike found that `@napi-rs/keyring`'s *default* Linux store silently falls back to keyutils when Secret Service is unreachable. The plugin therefore always pins the Secret Service store and never constructs the default one.

**Selection by capability detection**, at first start only:

1. If the operator configured a backend explicitly (`keystore.backend` in the plugin config, or `PASEO_ROOMS_KEYSTORE`), use it or fail; never substitute.
2. Load the native binding (loading rules below). If it loads, construct the platform store with a timeout. Linux: Secret Service only.
3. If the native binding cannot load, try the no-native CLI backend for the platform (below).
4. "No backend available" means exactly: the binding or CLI is missing, the store constructor throws, or the first `put` fails (for example, no default collection) while `meta.json` has no keyring record. Then use the fallback file (section 7.5).
5. Record the chosen backend in `keystore/meta.json`. After that, the backend never changes silently (section 7.5, last paragraph).

**Timeouts.** Every keyring call is asynchronous with an `AbortSignal` timeout of 10 s, so a pending unlock prompt cannot hang daemon start. A timeout is treated as "locked". Whether aborting cancels an unlock dialog that is already showing was not verified.

**Outcomes after first start** (`meta.backend` names a keyring):

| Result | Meaning | Action |
|---|---|---|
| `get` returns the KEK | normal | continue |
| `get` throws or times out | keyring locked or unreachable | stop room operations, ask the user to unlock; never fall back |
| `get` returns `null` | the entry is gone, **or** the collection is locked and the entry was never there | hard error; never regenerate the KEK silently |

The `null` row is why `meta.json` must record that a keyring KEK exists: a locked collection that lacks the entry also returns `null`, so the keyring alone cannot tell "never created" from "deleted".

**Linux session cases.** A systemd *user* service, a lingering user session, or a desktop login without PAM unlock can see a session bus whose login collection is **locked**. Reads then throw or wait for a prompt nobody answers. These cases get the "locked" handling with the timeout, not the fallback. libdbus finds the bus through `$XDG_RUNTIME_DIR/bus` when `DBUS_SESSION_BUS_ADDRESS` is unset, so detection must not rely on that variable alone. SSH sessions without a desktop were not tested.

**Loading the native binding.** `@napi-rs/keyring` ships one prebuilt `.node` file per platform through `optionalDependencies` (linux x64/arm64/armhf gnu and x64/arm64 musl, darwin x64/arm64, win32 x64/ia32/arm64). It uses N-API, so it does not depend on the Node or Electron ABI, and it has no install script. A `.node` file cannot be inlined into a JavaScript bundle. Whether Paseo's plugin compiler and `paseo plugin install` keep an external native dependency and the right platform package is **untested and blocks this design** (open question Q3). The intended rules, to confirm in that test:

- The binding is marked external in the plugin build and loaded lazily with `createRequire(pluginRoot)`. A load failure is caught and reported as "native keyring unavailable"; it never crashes the plugin.
- The platform package must be installed on the target platform (a directory installed on x64 Linux does not work on macOS). If Paseo's installer does not run `npm install` on the target, the plugin cannot rely on the native path and uses the no-native path below.
- The plugin does not download native code at run time.

**No-native path.** Used when the binding cannot load. The secret never appears in a command line, because other same-user processes can read process arguments on every OS (Linux `/proc/<pid>/cmdline`, `ps` on macOS, process query APIs on Windows). Secrets go through stdin and stdout only:

| Platform | Tool | Secret path | Status |
|---|---|---|---|
| Linux | `secret-tool` (package `libsecret-tools`, often not installed) | `store` reads stdin, `lookup` writes stdout; locked, missing and no-bus cases parsed from exit code and stderr | **Untested** (tool not installed on the spike machine) |
| macOS | `security -i` (interactive mode reads commands from stdin) | `add-generic-password` and `find-generic-password -w` sent on stdin | **Untested**; the plain `security add-generic-password -w <secret>` form puts the secret in argv and is forbidden |
| Windows | PowerShell 5.1 with DPAPI (`ProtectedData`, scope CurrentUser) wrapping the fallback file | KEK passed on stdin; output is the DPAPI blob written to `kek.fallback` | **Untested** |

If no CLI tool works, the fallback file is used.

**Clients hold no room keys.** All keys in section 4 live on daemons (devices are daemon installations, section 2). Paseo clients on desktop, web, iOS and Android reach rooms only through their daemon's RPCs, so they need no key storage. Client UI that handles secrets once (the recovery key in section 5.4) must work on every client: show the code on screen and offer it as a download or share-sheet file, never assuming a desktop file dialog.

### 7.4 What the keyring protects, and what it does not

**Protected:** copies of `plugin-data/rooms` in backups, disk images, synced folders, support bundles and stolen disks without the user's login secret. The sealed files are useless without the KEK.

**Not protected: any process running as the same OS user.** On Linux, Secret Service hands an unlocked secret to any same-user client without a prompt. On macOS the Keychain may prompt for a different binary, but same-user code can still drive the Paseo process or read its memory. Agents, other plugins and the `paseo` CLI run as that user.

**Same-user malware is out of scope** (decision 1). This includes a room agent with a shell running as the owner (P-5), any installed Paseo plugin (P-6), and any other program of that user. The specs in this directory do not claim protection against them. Isolation of room agents is section C of the hardening plan.

In the embedded deployment, the admin key, host key, endpoint keys and the owner's device keys all sit on the owner's daemon under one KEK. A compromise of that machine compromises all of them at once. `keys-rotation-recovery.md` section 6.5 covers recovery.

### 7.5 Fallback when no keyring is available

The fallback is always available on every platform. If no backend is available at first start (section 7.3, step 4), the plugin:

1. generates the KEK and writes it to `keystore/kek.fallback` in its own directory, with owner-only protection (section 7.8). On Windows without the native binding, the file holds a DPAPI blob when PowerShell is available (section 7.3, no-native path); otherwise the raw KEK.
2. records `backend: "fallback-file"` and `fallback: true` in `keystore/meta.json`,
3. shows a persistent notice in the Rooms UI: "Room keys are stored unprotected on disk. Anyone who can read this account's files or backups can read them." and logs `keystore_fallback` once per start,
4. migrates to the keyring automatically (re-seal under a new KEK, then delete the fallback file) once a backend becomes available.

**Operator-provided KEK.** Headless deployments can supply the KEK from a deployment secret instead: `PASEO_ROOMS_KEK_FILE` names a file with 32 random bytes (for example a Docker or Kubernetes secret mount, or a systemd credential). The plugin applies the same permission check (section 7.8) and records `backend: "operator-file"`. The secret then lives outside `PASEO_HOME` and its backups.

A raw fallback file protects nothing against a reader of the same files. It exists so headless gateways work. It is acceptable under a dedicated OS user (section 7.6), whose files the person's own account cannot read. Docker images and systemd system services always take this path (or the operator file); the spike confirmed that both lack a session bus.

The plugin never falls back silently from a working keyring. If `meta.json` says a keyring KEK exists and the keyring is now locked, missing the entry, or unreachable, the plugin stops room operations and asks the user (section 7.3, outcomes table).

### 7.6 Dedicated OS user (recommendation)

Recommended for every gateway that serves rooms to other people, and required for sandboxed runner lanes (decision 2):

- Run the room gateway daemon as its own OS user with its own `PASEO_HOME`, not as the person's login user.
- That daemon holds lane endpoint keys, host keys and, for a gateway-only node, no personal device keys.
- The person's own daemon (with their agents, credentials and personal rooms) stays under their login user. Same-user compromise of one no longer reads the other.
- On Linux servers this user usually has no session keyring, so it uses the fallback file or an operator-provided KEK file (section 7.5). The OS user boundary is then the protection. On Windows the equivalent is a separate local account; a service running as LocalSystem is not recommended because every administrator-level process can act as it.

Setup steps are left to the deployment guide. This spec states the recommendation and the trust boundary.

### 7.7 Backups

`plugin-data/rooms/` should be excluded from sync and backup tools. If it is backed up, sealed files are useless without the KEK, except in fallback mode. Restoring an old copy of a device's state is unsafe for MLS (old epochs, reused nonces) and is refused: each sealed state records the last log head and MLS epoch it processed. The host records the last position each device acknowledged and returns it in `session.hello.ok` (`enrollment-v2.md` section 4.1). A state older than that acknowledgement is a restored copy, and the plugin refuses to use it (`mls-integration.md` section 8.4). Recovery after a restore is device re-linking.

### 7.8 File protection on every OS

Every file under `plugin-data/rooms/` is readable and writable only by the OS user that runs the daemon. The plugin sets this on creation and **verifies it at every start on every OS**.

| OS | On creation | Startup check | Status |
|---|---|---|---|
| Linux, macOS, WSL (Linux filesystem) | explicit `mode` on every create (`0700` for directories, `0600` for files, passed to `open`/`mkdir`), then `chmod` to the same mode in case a umask removed bits. The process umask is never changed, because it is process-global in a daemon shared with other plugins | owner is the daemon's effective uid; no group or other permission bits; no symlinks inside the tree (`lstat`) | Linux tested in M1 (mode bits); the check itself is new |
| Windows (native) | directory and files get an explicit DACL with inheritance disabled, granting full control to the daemon user's SID only. Set with `icacls` using SID syntax (`*S-1-5-...`, never account names) or a native call if one is bundled; arguments are paths and SIDs, never secrets | read the security descriptor in SDDL form (PowerShell `(Get-Acl <path>).Sddl`, or a native call), never parsed `icacls` text, which is localized on non-English Windows. Require: owner is the daemon user's SID, no allow entry for any other SID except `SYSTEM` (`SY`), protected DACL (`D:P`). Refuse any reparse point inside the tree (symbolic links and junctions: `lstat().isSymbolicLink()`, which libuv is expected to report for junctions as well, to verify; plus a comparison of `fs.realpathSync.native(path)` with `path` for each directory, made after converting both to lower case and normalising the drive letter and separators, because Windows paths are case-insensitive and a plain string comparison reports a false positive when only casing differs; re-review finding R-11) | **Untested** |
| WSL with `PASEO_HOME` on a Windows drive (`/mnt/c`, drvfs) | `chmod` is ignored unless the drive is mounted with the `metadata` option | the check reads the mode back after `chmod`; if it did not take effect, refuse | **Untested** |
| Docker | as Linux inside the container; the volume must be owned by the container user | as Linux; a volume owned by another uid fails the check | **Untested** |

`SYSTEM` and administrators can read the files on Windows, as root can on POSIX systems. That is outside the threat model (section 7.4).

If the check fails, the plugin does not load keys. It shows "Room key files can be read by other users or accounts: `<path>`" with a **Fix permissions** button that re-applies the rules and checks again. It never repairs silently, because a wrong owner can mean another account wrote the file.

Paths in these specs are written with `/` and are logical. Implementations build them with `path.join` and keep them short (Windows `MAX_PATH` is 260 characters unless long paths are enabled; the deepest path here adds about 80 characters to `PASEO_HOME`).

Durable writes are specified per platform in `grants-v2.md` section 7.3.

### 7.9 Platform support matrix

Daemon-side plugin code must run on Linux, macOS, native Windows, WSL and headless or Docker hosts from the first release. Client code runs wherever Paseo's client runs (desktop, web, iOS, Android) and holds no room keys (section 7.3).

| Concern | Linux desktop | Linux headless / Docker | macOS | Windows (native) | WSL |
|---|---|---|---|---|---|
| KEK backend | Secret Service (tested) | fallback or operator file (detection tested) | Keychain (untested) | Credential Manager (untested) | usually fallback (untested) |
| No-native backend | `secret-tool` (untested) | none | `security -i` (untested) | PowerShell DPAPI (untested) | `secret-tool` if present (untested) |
| File protection | mode bits | mode bits | mode bits (untested) | DACL (untested) | mode bits; drvfs refused (untested) |
| Durable writes | fsync file and directory | same | `F_FULLFSYNC` via libuv (to verify) | `FlushFileBuffers`, no directory sync, rename retry (untested) | as Linux on the Linux filesystem |
| Native binding packaging | **blocker Q3** | **blocker Q3** (musl prebuild on Alpine) | **blocker Q3** | **blocker Q3** | **blocker Q3** |

Untested cells must be tested on a real host before the feature is called supported there. Nothing in the protocol formats depends on the platform.

## 8. Identifier formats

| Identifier | Format | Bits |
|---|---|---|
| Key id (`kid`) | `b64u(H("kid", algByte ‖ rawPublicKey))`, 43 characters | 256 |
| Entity ids | `mem_`, `dev_`, `inv_`, `lnk_`, `pen_`, `lane_`, `scp_` (scope), `kek_` (KEK id) + 32 lowercase hex | 128 random |
| Invite and link references | `b64u(H("invite-ref", utf8(inviteId)))`, `b64u(H("link-ref", utf8(linkId)))`; the only form in which these ids appear in the log or in MLS | 256 |
| Grant id | `g_` + 32 hex | 128 random |
| Room id | `room_` + 32 hex of `genesisHash` | 128, derived; security checks use the full `genesisHash` |
| Endpoint serverId | `rme_` (room endpoint) or `rle_` (lane endpoint) + 32 b64u | 192 random |
| Display fingerprint | base32 of the first 20 bytes of the `kid` digest, 8 groups of 4 | 160 |

**Comparisons always use the full public key** when the full key is stored (P-22, M-5). Key ids are lookup handles and never the only check.

## 9. Changes from M1

| M1 | v2 |
|---|---|
| One device key per daemon, reused in every room | Per-room device signing and DH keys |
| Member = (lane, daemon) | Room member with devices and lane access |
| Host key signs grants, log events, and implicitly decides membership | Admin key decides membership; host key orders and issues grants within the roster |
| 64-bit key ids | 256-bit key ids; full-key comparison |
| Plaintext JSON keys, 0600 | Sealed under a KEK held in the OS keyring, with a visible fallback |
| `daemonServerId` sent to the gateway | Never sent |
| "Owner" = any `daemon.manage` caller | Admin key signatures plus UI confirmation for interactive admin actions |

## 10. Open questions

Resolved and moved to `README.md` section 7 (decisions log): former Q2 (device-add approval, section 6.3), former Q5 (recovery key offered by default, section 5.4), and the binding choice in former Q3 (`@napi-rs/keyring` 2.1.2 pinned to Secret Service, section 7.3). Question numbers are kept stable.

- **Q1.** Is a per-room member identity key (cross-signing style) worth adding later so members can vouch for new devices without an admin round trip? v2 says no (section 4.2).
- **Q3. Blocker: native binding packaging.** Does Paseo's plugin compiler keep `@napi-rs/keyring` as an external dependency, and does `paseo plugin install` (directory and npm package) install the correct platform package from `optionalDependencies` on the target machine? A `.node` file cannot be inlined into a bundle. Untested. Until this is answered, the native keyring path cannot be relied on, and the no-native path (section 7.3) and fallback file carry every platform. Test on Linux x64 first, then macOS, Windows and an Alpine (musl) container.
- **Q4.** Should the Paseo daemon itself expose a keyring API to plugins upstream? That would remove Q3 for every plugin and would let the daemon apply a per-plugin ACL.
- **Q6.** Untested platforms (section 7.9): macOS Keychain prompts and code-signature behaviour, Windows Credential Manager and DACL checks, WSL, Docker volume ownership, all no-native CLI backends, real-desktop locked-keyring prompts and `AbortSignal` cancellation. Each needs a run on a real host before support is claimed.
- **Q7.** Org policy profiles (section 5.2.1): file format, who installs them, and how a member can verify that a room was created under an org profile rather than an admin's claim. v2 shows the values only.
