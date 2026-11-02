# Signatures, encoding and test vectors (identity v2)

- **Status:** proposed specification, not implemented. Test vectors generated and self-checked (section 9). Revised 2026-10-29 after the independent review and again after the re-review (`README.md` section 10), and for decision round 8 (`README.md` section 10.2).
- **Resolves:** A6 (P-11, P-22, C-14), P-25.
- **Applies to:** every signed, hashed or MACed object in this directory.

## 1. Summary of choices

| Topic | Choice |
|---|---|
| Canonical encoding | **RJCS**: RFC 8785 (JCS) restricted to integers, ASCII keys and well-formed strings, with a strict "bytes must equal re-encoding" parse rule |
| Signatures | Ed25519 (RFC 8032, pure), over a domain-separated "to be signed" string |
| Hash | SHA-256, always domain-separated |
| KDF and MAC | HKDF-SHA256 (RFC 5869), HMAC-SHA256 |
| AEAD | ChaCha20-Poly1305 inside Noise; XChaCha20-Poly1305 for sealed files |
| Binary in text | strict base64url without padding |
| Key ids | 256-bit, domain-separated hash of algorithm and raw key |
| Versions | `v: 2` in every object, version in every context string prefix and in the Noise prologue; no negotiation down |

### 1.1 Why RJCS and not deterministic CBOR

Deterministic CBOR (RFC 8949 section 4.2) is more compact and has no number ambiguity. RJCS was chosen because:

- The M1 code, zod schemas, logs and the Paseo protocol are JSON. M1's `canonicalJson` is already RJCS for the values it handles, so the change is small.
- Within the restrictions below, RJCS output equals `JSON.stringify` with sorted keys in JavaScript, and RFC 8785 libraries exist for other languages.
- No CBOR library is in the plugin's dependencies today. Adding one adds code to review.

The cost is base64url overhead for binary fields and the need for the strict parse rule (section 2.3), because `JSON.parse` silently accepts duplicate keys and other non-canonical input.

## 2. RJCS

### 2.1 Value model

| Allowed | Rule |
|---|---|
| object | keys match `^[A-Za-z0-9_]{1,64}$`, unique, and are not `__proto__`, `constructor` or `prototype` (S-22); no `undefined` values (optional fields are omitted) |
| array | any allowed values |
| string | well-formed Unicode (no lone surrogates); no normalization applied by the encoder |
| integer | `-(2^53-1)` to `2^53-1`; never `-0` |
| `true`, `false`, `null` | |

Not allowed: floats, exponents, `NaN`, `Infinity`, non-ASCII keys, nesting deeper than 16, encodings larger than 64 KiB (4 MiB for frames that carry MLS payloads, `enrollment-v2.md` section 3.4).

### 2.2 Serialization

RFC 8785 rules, which for this value model reduce to:

- no whitespace;
- object members sorted by key in code-unit order (keys are ASCII, so byte order);
- strings as `JSON.stringify` produces them in ES2019+: `"` and `\` escaped, `\b \f \n \r \t` short escapes, other code points below U+0020 as `\u00xx` with lowercase hex, everything else literal UTF-8 (including `/` and non-ASCII);
- integers in shortest decimal form.

Output is UTF-8 without a byte order mark.

### 2.3 Strict parsing

A receiver accepts RJCS bytes only if all of these hold:

1. size within the limit for that message kind;
2. valid UTF-8 (fatal decoding), no BOM;
3. `JSON.parse` succeeds;
4. every value is in the model of section 2.1;
5. **re-encoding the parsed value yields exactly the received bytes.**

Rule 5 rejects duplicate keys, whitespace, unsorted keys, `1.0`, `1e3`, unnecessary escapes and every other alternative spelling, without a custom parser. Signatures are then verified over the **received bytes** (which equal the canonical bytes).

Schema validation (zod) runs after the strict parse and must not strip unknown fields silently in signed objects. Signed objects must reject unknown fields **at every nesting level**: an unknown field is an error, because it would be covered by the signature but ignored by the code. With zod this means `z.strictObject(...)` (or `.strict()`) on every object schema inside a signed object, not only the outer one, because `.strict()` does not propagate to nested schemas (verified in the I-1 tests). A nested `z.object(...)` would strip an unknown field silently. The same applies to objects inside arrays and records.

### 2.4 Text fields

User-chosen strings (labels, room names) are normalized to NFC and stripped of control characters (U+0000 to U+001F, U+007F to U+009F, bidi overrides U+202A to U+202E and U+2066 to U+2069) **by the producer before signing**. Receivers reject strings that change under that normalization. This prevents two visually identical labels from having different signed bytes.

## 3. Domain separation

### 3.1 Layout

```
TBS(ctx, payload) = "paseo-rooms/v2" ‖ 0x00 ‖ ctx ‖ 0x00 ‖ payload
```

- `ctx` is ASCII matching `^[a-z0-9.:-]{1,64}$`, so it cannot contain `0x00` and the split is unambiguous.
- `payload` is RJCS bytes unless stated otherwise.
- The same layout is used for hash labels and KDF info strings, with distinct `ctx` namespaces, so a signature input can never equal a hash input.

```
Sign(key, ctx, payload)   = Ed25519.sign(key, TBS(ctx, payload))
H(label, data)            = SHA-256(TBS("h:" + label, data))
```

### 3.2 Signature contexts

| `ctx` | Signer | Signed object | Spec |
|---|---|---|---|
| `genesis` | admin | `RoomGenesis.body` | identity-model 5.1 |
| `stmt:<type>` | producer allowed for `<type>` | `Statement.body` (contains `type` again) | room-log-v2 2, 4 |
| `log-entry` | host | `LogEntry` | room-log-v2 3 |
| `lane-grant` | host | `GrantClaims` | grants-v2 2 |
| `enroll-request` | device signing key | `EnrollSigned` (includes Noise `h`) | enrollment-v2 5.2 |
| `key-change-new` | the **new** key | `KeyChange` | keys-rotation-recovery 2 |
| `mls-identity` | device signing key | `MlsIdentity` | mls-integration 3 |
| `chat-message` | device signing key | `ChatMessage` (inside MLS) | mls-integration 5.2 |

Each statement type is its own context (`stmt:member.admitted`, `stmt:member.removed`, …). Type names match `^[a-z0-9.-]+$` (`room-log-v2.md` section 4), so every `stmt:<type>` is inside the alphabet of section 3.1; a unit test checks this for every type in the catalogue. The full type list is `room-log-v2.md` section 4; decision round 8 adds `stmt:device.leaf.repair.requested`, signed by the device whose leaf it names (vector `deviceLeafRepair`). Every `Statement.body` carries `base: {seq, hash}`, the log head the producer had verified, and a producer's `base.seq` strictly increases from one of its statements to the next (`room-log-v2.md` section 2). State-changing statements carry `ver`, a log position, instead of the old value of the field they change (`room-log-v2.md` section 4.0). The `LogWitness` object, which travels inside MLS, is signed with `stmt:log.witness` so it can be shown as evidence outside the group. A signature for one type never verifies as another (the generator checks this).

MLS signatures use MLS's own `SignWithLabel` ("MLS 1.0 " labels, RFC 9420 section 5.1.2) with the separate MLS leaf key, so they cannot collide with these contexts either.

### 3.3 MAC, hash and KDF labels

| Label | Kind | Input | Use |
|---|---|---|---|
| `enroll-token` | HMAC-SHA256 TBS | `EnrollSigned` | token proof (key: `tokenKey`) |
| `invite-token-key` | HKDF info | empty | `tokenKey = HKDF(token, "", TBS("invite-token-key", ""), 32)` |
| `link-token-key` | HKDF info | empty | device link `tokenKey` (identity-model 6.4) |
| `sas` | HKDF info | SAS info object | enrollment-v2 6.2 |
| `file-key` | HKDF info | `purpose` (UTF-8) | identity-model 7.2 |
| `h:kid` | hash | `algByte ‖ rawPublicKey` | key ids |
| `h:genesis` | hash | `RJCS(RoomGenesis)` | `genesisHash` |
| `h:log-entry` | hash | `RJCS(LogEntry)` | entry hash, chain link |
| `h:log-body` | hash | statement or MLS message bytes | `bodyHash` |
| `h:roster` | hash | `RJCS(Roster)`, with `Roster.seq` the last roster-changing entry | `rosterHash` |
| `h:invite-ref` | hash | `utf8(inviteId)` | `inviteRef`, the only form of an invite id in the log and MLS |
| `h:link-ref` | hash | `utf8(linkId)` | `linkRef` |
| `h:admin-set` | hash | `RJCS(adminSet)`: array of the active admin public keys as b64u strings, sorted | MLS authority extension |
| `h:mls-group` | hash | `RJCS({genesisHash, generation})` for the room group; `RJCS({genesisHash, scope, generation})` for a scope group | MLS group ids |
| `h:mls-epoch-auth` | hash | `RJCS({v: 2, typ: "mls-epoch-auth", groupId, epoch, auth})`, with `auth` the b64u MLS `epoch_authenticator` | `epochAuth` in MLS authenticated data, the joiner's epoch anchor (mls-integration 5, 5.1; decision round 8) |
| `h:sas-commit` | hash | `Nm` | SAS commitment |
| `h:sas-transcript` | hash | `h ‖ Nm ‖ Nh ‖ info` | recorded in `member.admitted` |
| `h:recovery-code` | hash | the 32-byte recovery seed | recovery code checksum, first 3 bytes (identity-model 5.4.1) |
| `noise-ik` | prologue | `RJCS({genesisHash, serverId})` | enrollment-v2 3.3 |

Adding a new signed, hashed or derived object requires a new row here and a new vector.

## 4. Strict base64url

All binary values in RJCS objects and in token strings use base64url (RFC 4648 section 5) with these rules:

1. alphabet `[A-Za-z0-9_-]` only; no `=`, `+`, `/`, whitespace or line breaks;
2. length is exactly `ceil(8n/6)` for the expected byte length `n` (32 bytes: 43 characters; 64 bytes: 86; 16 bytes: 22; 24 bytes: 32);
3. **canonical trailing bits:** the unused low bits of the last character are zero. Check by decoding and re-encoding and comparing (C-14);
4. the expected length is fixed per field. A field that can hold different sizes names the size in the schema.

Node's `Buffer.from(x, "base64url")` is lenient (accepts padding and ignores bad characters), so it may only be used after the regex and length check, followed by the re-encode comparison.

## 5. Keys and identifiers

### 5.1 Algorithms and key validation

| Algorithm | Encoding | Validation on receipt |
|---|---|---|
| Ed25519 public key | 32 raw bytes | must decode to a curve point; reject small-order points (the 8 points of order ≤ 8; vector `ed25519.smallOrderPublicKeys` has two of them) |
| Ed25519 signature | 64 raw bytes | RFC 8032 verification with `S < L` (OpenSSL in Node 24 and `@noble/curves` 2.4.0 both reject the vector `ed25519.sNotReduced`); cofactorless |
| X25519 public key | 32 raw bytes | reject if the Noise DH result is all zero (enrollment-v2 3.3) |

### 5.2 Key ids

```
algByte: 0x01 = Ed25519, 0x02 = X25519
kid = b64u(H("kid", algByte ‖ rawPublicKey))        // 43 characters, 256 bits
```

Where the full key is available, comparisons use it (P-22). A `kid` in a signed object names a key that the verifier must already hold in its authority state or roster. Verification then uses the stored key, never a key presented next to the `kid` (M-5).

### 5.3 Display fingerprints

```
fingerprint = lowercase base32 (RFC 4648 alphabet, no padding) of the first 20 bytes of
              the kid digest, in 8 groups of 4: "y24p-audu-ridg-lqnz-pkt5-gjvg-qdiq-l2l3"
```

Shown for admin keys (the "owner fingerprint" on the member's SAS screen), device keys (member list, key-change notices) and endpoints.

## 6. Token strings

| Prefix | Content | Secret | Spec |
|---|---|---|---|
| `prc2.` | `b64u(RJCS(InvitePayload))` | yes (token) | enrollment-v2 2.2 |
| `prl2.` | `b64u(RJCS(DeviceLinkPayload))` | yes (token) | identity-model 6.4 |
| `prg2.` | `b64u(RJCS(GrantClaims)) + "." + b64u(Sign(host, "lane-grant", RJCS(GrantClaims)))` | yes (bearer) | grants-v2 2 |

Receivers split on `.` into exactly the expected number of parts, apply section 4 to each, strict-parse the RJCS part, and verify the signature over the decoded RJCS bytes. The prefix is not signed separately: the `typ` and `v` inside the signed object carry the same information, and the context separates grant signatures from everything else.

## 7. Versioning and downgrade rules

1. Every signed or persisted object has `v` and `typ`. v2 code accepts only `v: 2`.
2. Context strings start with `paseo-rooms/v2`. A future v3 uses `paseo-rooms/v3`, so v2 signatures can never be accepted as v3 objects or the reverse.
3. The Noise prologue contains the version, the room's `genesisHash` and the endpoint `serverId`. A version or room mismatch fails the handshake instead of negotiating.
4. Each room record on a member stores `minVersion` (from genesis policy). It never decreases. A later genesis policy change can raise it (admin statement `room.policy.changed`), never lower it.
5. Invites carry no "supported versions" list. The prefix (`prc2.`) and `v` decide. A v2 member refuses `prc1.` codes; a v1 member cannot parse `prc2.` codes.
6. There is no dual-stack period (`migration.md`). If a v3 appears, its spec must define how a v2 room is upgraded: by an admin statement that raises `minVersion` and is signed under the v2 context.
7. Unknown statement types inside a v2 log are an error for the member that cannot interpret them (it stops processing and shows "This room uses a newer version of Rooms"), not something to skip. Skipping could hide a removal.

## 8. Clock fields

| Field | Unit | Set by | Trusted for |
|---|---|---|---|
| `createdAt`, `iat`, `exp`, `notBefore`, `notAfter` | unix seconds | signer | validity windows, checked by the verifier with its own clock and the skew rules of `grants-v2.md` section 9 |
| `oldValidTo` (`host.key.rotated`) | unix seconds | admin | end of the old host key's window for grants |
| `ts` (statements) | unix milliseconds | producer | display only |
| `hts` (log entries) | unix milliseconds | host | display, and the hold and closure-delay checks of `room-log-v2.md` sections 5 and 5.2, which members treat as a plausibility check only. Not used for key validity: log objects are judged by position (`keys-rotation-recovery.md` section 3) |

## 9. Test vectors

### 9.1 Files

- `vectors/gen-vectors.mjs`: deterministic generator and self-check. Every secret is derived from a public label (`sha256("paseo-rooms/v2/test-seed/<name>")`).
- `vectors/vectors.json`: output.

Run:

```
ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin plugin/docs/specs/identity-v2/vectors/gen-vectors.mjs
```

The script needs Node 20 or later (it uses `String.prototype.isWellFormed`). It checks the version before loading anything else and exits with code 2 and a message naming the command above. The system Node on the development machine is 18.19.1, so use Paseo's Node 24 as shown. The script uses `node:crypto`, `@noble/curves`, `@noble/hashes`, `@noble/ciphers` 2.4.0 and the `dist/noise/` module of `@getpaseo/relay` 0.13.2 (loaded by file path, since it is not in the package exports), all from `plugin/node_modules`. Two consecutive runs produced byte-identical output (checked on 2026-10-28, on 2026-10-29 with Node 24.20.0, again on 2026-10-29 after the review revision, on 2026-10-29 after the re-review revision, and on 2026-10-29 after the round-8 revision, with `cmp`). The round-8 revision changed two existing values, both required by a rule change: `mls.authenticatedData` (it now carries `epochAuth`) and the text of `about.notes[3]` (the list of folded chains); every other existing value is unchanged. The post-I-7 revision (2026-10-29) added the section `recoveryCode` and changed no existing value: the rename of `grant.suspected_theft` to `grant.suspected-theft` does not reach the vectors, which contain no statement of that type. Two consecutive runs of that revision were byte-identical (`cmp`). The generator prints the SHA-256 of the file it writes (the first revision printed the hash of compact JSON instead, re-review finding R-12). The output records the Node version, so a run under another version changes `about.node`.

### 9.2 Coverage

| Section of `vectors.json` | Content |
|---|---|
| `keys` | seeds, public keys, `kid`s and fingerprints for admin (including a rotated admin key), recovery, host (two), device (laptop, rotated laptop, phone, creator's desktop), MLS, node, room endpoint, lane endpoint and device DH keys |
| `rjcs.accept` | canonical encodings (key order with `A`, `_`, `a`, `aa`; integer-like keys `"1"`, `"10"`, `"2"`, which JavaScript enumerates as 1, 2, 10; Unicode, emoji, control characters, `/`; extreme integers; empty containers) |
| `rjcs.reject` | 20 inputs that must be rejected: whitespace, unsorted, duplicate key, `1.0`, float, exponent, `-0`, `2^53`, lone surrogate, non-ASCII key, key with `-`, escaped printable, escaped `/`, uppercase hex escape, trailing newline, BOM, the keys `__proto__`, `constructor` and `prototype`, invalid UTF-8 |
| `base64url` | accepted and rejected forms: padding, `+` and `/`, non-zero trailing bits, wrong length, whitespace |
| `ed25519` | two small-order public keys (order 1 and order 2) that must be rejected, and a grant signature with `S` replaced by `S + L` that must fail |
| `recoveryCode` | the recovery code of the vector recovery key: seed, `kid`, the 3 checksum bytes and the `prk2-` code; `accept`: the code in upper case, with spaces instead of hyphens, and without separators; `reject`: one character changed (`typo`), two adjacent characters swapped (`typo`), a group missing (`wrong_length`), `0` in place of a letter (`bad_character`), prefix `prk1-` (`not_recovery_code`), and a correct code of another key (`wrong_key`) |
| `genesis` | signed genesis (with a recovery key and the revised policy, including `soleDeviceChange` and `closeDelay`), its canonical bytes, `genesisHash` and derived `roomId` |
| `invite` | payload, `prc2.` code and `inviteRef` |
| `noise.enrollment` | IK handshake with the room prologue and empty payloads; handshake hash `h` |
| `noise.ikCacophonyKeys` | IK with the cacophony test keys and the first four payloads; equal to the cacophony IK entry (see 9.3) |
| `noise.cacophonyChecks` | pinned source of the cacophony vectors and the result of each engine on NK and IK |
| `enrollment` | `EnrollSigned`, TBS bytes, signature, `tokenKey`, `tokenMac`, full frame; SAS nonces, commitment, key, digits (`317 837`), transcript hash |
| `deviceLink` | `DeviceLinkPayload` and `prl2.` code, `linkRef`, link token key, the new device's IK handshake hash, `EnrollSigned` with `linkId`, token MAC, SAS with the confirming device's nonce, `device.link.created`, `device.added` (with `KeyChange.old = null`) and `device.add.approved`; `chain`: these three folded at `seq` 4 to 6 after `log.entries[0..3]`, with the approval 72 h after the request of a sole device and a `base` after the request (R-10); `chain.cases`: an approval after only 24 h, an approval whose `base` precedes its `ref`, an approval after a veto, an approval after an admin removed the requesting device (R-8), and a self-removal of a last device, each rejected |
| `deviceRekey` | a `device.rekeyed` by Sam's laptop, Sam's only active device, and its `bodyHash`; `chain`: the request at `seq` 4 after `log.entries[0..3]` and an automatic `device.rekey.approved` at `seq` 5, 72 h later, which replaces the laptop's keys and denylists the old ones (decision round 5, item 3); `chain.cases`: the same approval after only 24 h, rejected with `hold_not_elapsed`; `vetoed`: the laptop, the device being rekeyed, signs `device.rekey.vetoed` at `seq` 5, which opens a conflict and keeps the old keys, and an automatic approval at `seq` 6, 73 h after the request, is rejected with `vetoed`; `soleDeviceChangeAdmin`: `room.policy.changed` sets `soleDeviceChange = "admin"` at `seq` 4, the laptop requests a rekey at `seq` 5, an interactive approval (`mode: "admin"`) 1 h later is accepted at `seq` 6, and an automatic approval even after 72 h is rejected with `auto_not_allowed` |
| `deviceLeafRepair` | a `device.leaf.repair.requested` by Sam's laptop for its own leaf in the room group (`scope: null`, `generation: 0`; `keyPackageRef` a placeholder); `chain`: two requests at `seq` 4 and 5, 61 min apart; `chain.cases`: a request by another member's device for the laptop's leaf (`not_permitted`), and a third request for the same group 10 min after the second (`repair_too_soon`); the rate parameters (1 h per group, 8 per 24 h) |
| `statements` | `member.admitted` (creator and invitee), `lane.created`, `grant.issued`, `member.left`, `member.role.changed` (with `ver`), `device.rekeyed`, `admin.key.rotated`, `host.key.rotated`, `room.policy.changed` (one `ver` per setting), `lane.names.changed` (with `ver`), `device.add.vetoed`, `device.conflict.resolved` (with `ver`), `device.removed`, `admin.added` by an admin and by the recovery key, `admin.key.revoked` by the recovery key, `room.close.proposed`, `room.closed`, `recovery.key.proposed` and `recovery.key.rotated` from `null` with a proposal, `device.leaf.repair.requested`; each with `base` and its key-change signature where one applies. The two recovery-key statements are format examples and are not folded, because the vector genesis already has a recovery key |
| `log` | five chained entries starting with the creator's admission at `seq` 0, their bodies, the roster position and hash after each entry (`rosterAfter`), an equivocation example at `seq` 4; `foldChecks`: five entries the fold must reject (replayed statement, a held statement stopped by the forward-base rule, an ABA statement stopped by its version while the role is back at its old value, `base` not before the entry, `base` hash not in the chain); `refold`: an admin key of the creator's lineage admits a ghost, the recovery key revokes it, the ghost leaves the roster and the revocation entry becomes the roster position (R-7), plus a revocation that reaches back before its signer's authority start, rejected; `closure`: a closure confirmed by an independent admin 25 h after the proposal, and three rejected confirmations (too early, same lineage, confirmer added after the proposal); `noRevival` (decision round 8, item 3): R adds adminB, adminB rotates the host key to host2 and removes Sam's laptop, R revokes adminB from the rotation, and adminA signs a fence on host2; after the re-fold the host-key table keeps host-1 retired and host2 current but uncertified (`hostKeysAfter`), the laptop stays out and the roster and its position are unchanged; cases: an entry signed by host-1 (`unknown_host_key`) and a statement by the laptop (`unknown_producer`); `revocationDepth` (decision round 8, item 4): R adds nine admin keys and revokes eight of them with depths 1 to 8, and the ninth revocation, of depth 9, is rejected with `revocation_too_deep` |
| `grant` | claims, TBS and `prg2.` token |
| `mls` | `MlsIdentity`, its signature, the credential identity bytes, an authenticated-data object whose roster position differs from its log head and which carries `epochAuth`, the epoch anchor `epochAuth` (input with a placeholder `epoch_authenticator`, and its hash), the admin set and its hash, the authority extension, room and scope group ids, a signed `log.witness` |
| `records` | a one-fragment record and a frame split into two fragments |
| `sealed` | KEK, `kekId`, purpose, file key, nonce, AAD, plaintext and the complete `Sealed` object with its XChaCha20-Poly1305 ciphertext |

Self-checks the generator performs before writing (it exits non-zero on any failure):

- the Node version is 20 or later (it exits with code 2 and a message naming the Paseo command otherwise);
- Ed25519 public keys and signatures agree between `node:crypto` and `@noble/curves`;
- every signature verifies, and the grant signature fails under every other context;
- each statement signature fails under another statement type's context, and the `log.witness` signature fails as `stmt:member.left`;
- every new-key signature verifies under `key-change-new`;
- every `rjcs.accept` entry parses strictly and every `rjcs.reject` entry is rejected; integer-like keys sort as strings;
- every base64url case behaves as labelled;
- both small-order keys are detected, and the `S + L` signature fails in `node:crypto` and `@noble/curves`;
- the fold accepts the main chain, keeps the roster position at the last roster-changing entry, accepts a role change and its reversal, and rejects each `foldChecks` case with the expected reason; a replay of an admission after `member.left` is rejected;
- the re-fold removes the ghost, sets the roster position to the revocation entry and yields the roster hash of the pre-ghost members at that position; a revocation before its signer's start is rejected;
- the closure chain closes the room, no statement is accepted after it, and each closure case is rejected with the expected reason;
- the device-link chain adds the phone after 72 h; a conflict is cleared by `device.conflict.resolved` naming the veto's version; an admin may remove a last device and the member stays with no devices; each device-link case is rejected with the expected reason;
- the sole-device rekey chain replaces the laptop's keys after 72 h and denylists the old signing key; the approval after 24 h is rejected with `hold_not_elapsed`;
- the rekey veto opens a conflict and keeps the old keys, and the later automatic approval is rejected with `vetoed`; under `soleDeviceChange = "admin"` the interactive approval is accepted and the automatic one rejected with `auto_not_allowed`;
- the leaf repair chain folds, and each leaf repair case is rejected with the expected reason;
- the no-revival chain folds with the laptop still out and denylisted, the roster and its position unchanged, host-1 retired and host2 current and uncertified; each no-revival case is rejected with the expected reason;
- revocations of depth 1 to 8 are accepted, depth 9 is rejected with `revocation_too_deep`, and the same ninth revocation with an empty range is accepted;
- the recovery code decodes to the recovery seed in every accepted spelling, each rejected case fails with its expected error, and every one of the 1736 single-character substitutions of the code is detected as a typo;
- record fragments reassemble into the frame; the sealed ciphertext decrypts;
- three Noise engines reproduce the cacophony vectors byte for byte, all six messages (two handshake, four transport): the generator's own engine (NK and IK), Paseo's published relay 0.13.2 NK module unchanged (NK), and the proposed vendoring, Paseo's `CipherState` and `SymmetricState` with an added IK `HandshakeState` (NK and IK; `enrollment-v2.md` section 3.2.1);
- IK handshakes complete with matching handshake hashes on both sides.

The cacophony entries are copied into the generator from `rweather/noise-c` `tests/vector/cacophony.txt` at commit `cfe25410979a87391bb9ac8d4d4bef64e9f268c6` (file SHA-256 `e1b0c410…38c9`, fetched read-only from GitHub on 2026-10-29). A negative check was run once on the first draft: changing one byte of the expected IK transport ciphertext made both IK-capable engines fail and the generator exit non-zero. It was not repeated for later revisions. For the re-review revision, a different negative check was run once: changing two expected fold errors (`heldStatement` and `approvalAfterRequesterRemoved`) made the generator report both mismatches, exit 1 and leave `vectors.json` unchanged; the expectations were then restored. For decision round 5, item 3, a copy of the generator whose rekey approval ignored the sole-device rule (a 24 h hold for every rekey) reported the `soleRekeyHoldTooShort` mismatch, exited 1 and left `vectors.json` unchanged; the copy was then deleted. For decision round 8, a copy that expected `repair_rate` for the `tooSoon` case, allowed depth 9, and never marked host keys uncertified reported all three mismatches, exited 1 and left `vectors.json` unchanged (same SHA-256 before and after); the copy was then deleted.

### 9.3 Verification status

| Item | Status |
|---|---|
| Ed25519, SHA-256, HKDF, HMAC, XChaCha20-Poly1305 | Standard primitives from two implementations (Node/OpenSSL and noble) where both exist; values not compared with a third party |
| Noise NK | **Verified** (2026-10-29): generator engine, Paseo relay 0.13.2 unchanged, and vendored Paseo + IK all match the cacophony NK entry, six of six messages |
| Noise IK | **Verified** (2026-10-29): generator engine and vendored Paseo + IK match the cacophony `Noise_IK_25519_ChaChaPoly_SHA256` entry, six of six messages. Cacophony has no handshake-hash field, so `h` itself is checked only by the two sides agreeing; the matching ciphertexts confirm it up to the final `MixHash`, because the running `h` is the AEAD associated data of every handshake payload. The production module must re-run these vectors in its own tests (`enrollment-v2.md` section 3.2.1). |
| RJCS | Checked against this document's rules only. A cross-check with an RFC 8785 library in a second language is recommended. |
| Everything else (formats, SAS, contexts) | Defined by this spec; the vectors are the reference, not an external check |

## 10. Open questions

- **Q1.** Answered by the I-1 tests: zod can reject unknown fields at every level, but only when each nested object schema is itself `z.strictObject` (or `.strict()`); `.strict()` on the outer schema does not propagate. Section 2.3 now requires a strict schema at each level.
- **Q2.** Should statement bodies above 64 KiB ever exist (for example large roster snapshots in rooms of 300)? A roster of 300 members with 2 devices is about 120 KiB. Proposed: roster snapshots are not signed objects themselves (each entry is backed by statements), so the limit holds; snapshots travel as frames up to 4 MiB.
- **Q3.** Ed25519 batch verification is not used. If log verification for large rooms is slow, revisit with a library that implements ZIP-215-consistent rules on both sides.
