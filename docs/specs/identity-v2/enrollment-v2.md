# Enrollment and room sessions (control protocol v2)

- **Status:** proposed specification, not implemented.
- **Resolves:** A1 (P-1), A4 (P-8), P-15/C-7, P-20/C-15, P-23/C-8, C-10, P-25; P-4 for the endpoint split.
- **Replaces:** `../rooms-control-protocol.md` (v1). v1 is removed, not kept alongside (`migration.md`).
- **Formats:** RJCS, contexts and base64url rules are in `signatures-and-encoding.md`. Example values are in `vectors/vectors.json` (`invite`, `noise.enrollment`, `enrollment`, `deviceLink`, `records`).
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): resume pinning (5.6), abandoned-attempt limit, invite references in the log, key confirmation before supersede, explicit error fields, no per-invite grant lifetime. Revised again after the re-review (decisions round 4): the pinned `h` travels in `enroll.pending` and the member records every `h` it signed (5.6, R-4); device-link attempt limits on the confirming device (R-2); `unknown_base`.

## 1. Goals

1. The owner admits a **person**, not "whoever held the invite first". A short authentication string (SAS) compared out of band binds the session the owner sees to the person they talk to.
2. Both sides authenticate with static keys in the handshake (mutual Noise). Long-lived sessions are bound to that handshake.
3. Nothing about membership or invite state is revealed before the requester proves something (a device signature bound to the session, then token knowledge).
4. A bad token burns at most the one invite it names.
5. The member daemon connects only to relays the user trusts, over TLS.
6. A crash at any point leaves both sides in a state they can resume or clean up.

## 2. Invites

### 2.1 Creation

An admin creates an invite in the Rooms UI. This is an interactive admin action (`identity-model.md` section 5.3): the UI shows the terms and asks for confirmation. Terms:

| Field | Default | Range |
|---|---|---|
| `role` | `watch` | any role up to the admin's own |
| `lanes` | all open lanes | subset of open lanes |
| `exp` | 30 min | 5 min to 24 h |
| `note` | empty | ≤ 80 characters, for the admin only ("for Sam"), never sent to the member |

The host stores:

```
InviteRecord = {
  inviteId: "inv_<32 hex>", tokenKey: <32 bytes>,     // tokenKey = HKDF(token, "", TBS("invite-token-key",""), 32)
  role, lanes, note, createdAt, exp,
  state: "open" | "claimed" | "used" | "revoked" | "burned" | "expired",
  failedProofs: 0, abandoned: 0, pendingId: null, usedBy: null
}
```

The token itself is never stored. `tokenKey` lets the host check a MAC without the token crossing the wire (section 5.2). The `invite.created` admin statement records `inviteRef = b64u(H("invite-ref", utf8(inviteId)))`, role, lanes and `exp`; the `inviteId` and the note stay local (review finding S-5). The grant lifetime is not an invite term: it is the room's `policy.grantTtl`, 12 hours unless an org policy shortens it (`grants-v2.md` section 5, decision round 3).

### 2.2 Format

```
InviteCode = "prc2." + b64u(RJCS(InvitePayload))
InvitePayload = {
  v: 2, typ: "invite",
  roomId, genesisHash: <32 bytes b64u>,
  roomName: <≤80 chars, display only, unverified>,
  endpoint: { serverId: "rme_<32 b64u>", dh: { alg: "x25519", kid, pub },
              relay: { host: <DNS name>, port: <1..65535>, tls: true } },
  inviteId, token: <32 bytes b64u>, exp: <unix s>, sas: "sas6"
}
```

- About 700 characters (vector: 720).
- `endpoint` has exactly the shape of `genesis.body.endpoint` (`identity-model.md` section 5.1), so section 5.5 compares the two objects field by field.
- `relay.tls` is the literal `true`. A payload with `false` or a missing field fails schema validation.
- `relay.host` must match `^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$` after lowercasing. IP literals, `localhost` and single-label names are refused unless the dev flag in section 2.3 is set. A port other than 443 is allowed but treated as an unknown relay (explicit confirmation, section 2.3).
- The code is a bearer secret until it is used or expires. The UI says so when it is copied.

### 2.3 Member-side checks and preview

`rooms.join(code)` runs these steps before any network access:

1. Strict decode: prefix, strict base64url, size ≤ 2 KiB, strict RJCS parse, schema.
2. `prc1.` codes are refused with "This invite is from an older version of Rooms. Ask the owner for a new invite." (`migration.md`).
3. `exp` in the past (local clock, 5 min grace) → refuse.
4. **Relay check.** The member plugin keeps `trustedRelays` in its settings, default `["relay.paseo.sh:443"]`.
   - Listed: continue.
   - Not listed: the preview shows "This invite uses relay `<host>:<port>`, which you have not used before. Rooms traffic is end-to-end encrypted, but the relay learns when you connect." The user must tick "Trust this relay" to continue. Trusting adds it to `trustedRelays`.
   - Non-TLS relays and IP literals are possible only when the daemon was started with `PASEO_ROOMS_DEV_INSECURE_RELAY=1`. An invite can never enable this.
5. **Preview.** The UI shows the room name and endpoint fingerprint, marked "(unverified until you compare the code with the owner)", the relay, and the expiry. Nothing is stored and nothing is connected until the user presses "Join".

Lane host labels registered later are always prefixed by the member plugin with "Room lane: " and the verified room name. Owner-chosen strings never appear alone as a host name (P-20).

## 3. Room endpoint transport

### 3.1 Relay

The host registers the room endpoint on the relay as a **server** for `endpoint.serverId` (relay protocol v2, the same server-side code path as M1's lane endpoint). Members connect as **clients**. The relay forwards opaque binary WebSocket messages. P-16 (unauthenticated server-role takeover) still applies: a party that knows the `serverId` can evict the host's control socket. That is a denial of service only, because it cannot complete a handshake without the endpoint key. The host alerts on repeated eviction (`endpoint.evicted`, `room-log-v2.md` section 4).

Lane endpoints keep serving Paseo host links only. v2 removes the `rooms.control.*` first-frame switch from lane endpoints.

### 3.2 Choice of Noise pattern: IK

The room endpoint runs **`Noise_IK_25519_ChaChaPoly_SHA256`**, built on Paseo's vendored Noise module (section 3.2.1).

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

Why IK:

- The member always knows the endpoint static key in advance (from the invite, later from the signed authority state). IK uses that and finishes in one round trip.
- Both statics enter the handshake, so the session is mutually authenticated and bound to both keys (A4). Signatures made inside the session also cover the handshake hash `h` where they matter (enrollment), so they cannot be relayed into another session.
- The initiator's static key is encrypted under `es`. A passive observer, and the relay, cannot learn which device connects.

Why not XX: XX costs 1.5 round trips and protects the responder's identity, which is not secret here (it is in every invite). Its advantage, not needing the responder key in advance, is not needed.

Why not the relay library as a dependency: `@getpaseo/relay` 0.13.2 implements only NK, and its public `SecureChannel` interface does not expose the handshake hash (`handshakeHash()` exists in `noise/index.ts` but the `noise` module is not in the package exports). We therefore cannot import it and bind to its handshake without an upstream change. Asking upstream to export the module, an IK pattern and the hash is recorded in `README.md` section 6 (request 1).

**IK caveats and the rules that address them:**

| IK property | Rule |
|---|---|
| The first message's payload has no forward secrecy and can be replayed. | Both handshake payloads are **empty**. Application data starts after `Split()`. |
| A stolen endpoint static key lets its holder impersonate the endpoint to members (key compromise impersonation against the endpoint). | Endpoint keys are rotatable and certified by the admin (`keys-rotation-recovery.md` 4.6). |
| The responder completes the handshake with any initiator static. | Authorization happens after the handshake. Unknown statics may use only the pre-auth operations (section 4). |

### 3.2.1 Noise implementation: vendor Paseo's module and add IK

Decision (HARDENING-PLAN, round 2, item 7): do not write a Noise engine from scratch. Vendor Paseo's existing, tested Noise module and add the IK pattern on top of it.

**Source.**

| Item | Value |
|---|---|
| Upstream path | `packages/relay/src/noise/` in `github.com/getpaseo/paseo`: `cipher-state.ts` (76 lines), `symmetric-state.ts` (83), `index.ts` (241, NK `HandshakeState`), `noise.test.ts`, `fixtures/nk-25519-chachapoly-sha256.json` |
| Pinned revision | commit `1467121b16742c2ce57320748d70d365aaf861c6` (2026-10-28; the repository's `packages/relay/package.json` there reads `0.14.0-beta.2`). The published `@getpaseo/relay@0.13.2` tarball contains the same module compiled to `dist/noise/` (structure and logic match by inspection; not byte-diffed against a build of the commit). |
| License | Apache-2.0. The root `LICENSE` grants Apache-2.0 for all of Paseo except third-party components, and the root `package.json` declares `"license": "Apache-2.0"`. `packages/relay/package.json` has no `license` field, and the published 0.13.2 tarball ships no `LICENSE` file, so the license comes from the repository. |
| Compatibility | Apache-2.0 code can be vendored into a plugin under MIT, Apache-2.0 or a proprietary license. Obligations (Apache-2.0 section 4): keep a copy of the license with the vendored files, keep the upstream copyright line ("Copyright (c) 2025-present Mohamed Boudra"), and mark each modified file as changed. Paseo has no `NOTICE` file, so there is no notice text to carry. The `paseo-rooms` `package.json` declares no license yet; that should be set before release. |
| Dependencies | `@noble/curves`, `@noble/hashes`, `@noble/ciphers` 2.4.0, added as direct, exact-version dependencies. |

**What is vendored unchanged:** `CipherState` (ChaChaPoly, nonce handling, nonce exhaustion, receive counter that advances only on successful authentication) and `SymmetricState` (SHA-256, HKDF, `mixKey`, `mixHash`, `encryptAndHash`, `split`, `handshakeHash`).

**What is added:** a `HandshakeState` that generalizes Paseo's token loop to the tokens `e`, `s`, `es`, `se`, `ss`, `ee` with a pattern table holding NK and IK. It keeps Paseo's rules: messages written and read strictly in turn, the 65 535-byte message limit, all-zero DH results rejected, ephemeral injection for tests only, ephemeral secret zeroed at `split()`. The `s` token reads 48 bytes when a key is set and 32 otherwise. The vectors generator contains a prototype of this class running on the published 0.13.2 `CipherState` and `SymmetricState` (`vectors/gen-vectors.mjs`, `VendoredHandshake`). The prototype omits the size limit and the zeroing, which do not affect the vectors.

**Required tests.** The vendored module must pass, in the plugin's own test suite:

1. the cacophony `Noise_NK_25519_ChaChaPoly_SHA256` vector (Paseo's fixture), all six messages;
2. the cacophony `Noise_IK_25519_ChaChaPoly_SHA256` vector, all six messages;
3. Paseo's existing negative tests from `noise.test.ts`, ported (tampered message, out-of-turn message, oversized message, invalid DH key);
4. IK-specific negatives: a message 1 with a modified encrypted static fails authentication; a responder reading message 1 learns the initiator static only after `es` decryption succeeds.

Status: the prototype passes tests 1 and 2 (`signatures-and-encoding.md` section 9.3). Tests 3 and 4 are for the implementation.

**Alternatives considered** (npm registry metadata and package contents, read 2026-10-29):

| Option | License | Maintenance | IK | Suite `25519_ChaChaPoly_SHA256` | Notes |
|---|---|---|---|---|---|
| Vendor Paseo's module + IK (**chosen**) | Apache-2.0 | Maintained by the upstream we already track | added by us (one class) | yes | Same `@noble` primitives as Paseo and the plugin; NK already cacophony-tested upstream; no new dependency tree |
| `noise-handshake` 4.2.0 (holepunchto) | Apache-2.0 | active (2025-12) | yes | **no**: hash is hard-coded to BLAKE2b | depends on `sodium-universal` (native addon in Node) |
| `noise-protocol` 3.0.2 (emilbayes) | ISC | last publish 2023-01 | yes | **no**: BLAKE2b only | depends on `sodium-universal` |
| `@chainsafe/libp2p-noise` 17.0.0 | Apache-2.0 OR MIT | active (2026-04) | **no**: XX only | yes | large libp2p dependency tree |
| `noise-c.wasm` 0.4.0 | 0BSD | last publish 2018-10 | yes | yes | unmaintained WebAssembly build of noise-c |

No maintained npm library offers IK with the SHA-256 suite on our existing primitives. Vendoring keeps our transport byte-compatible with Paseo's and makes adopting an upstream export (request 1) a drop-in replacement.

### 3.3 Prologue and handshake rules

```
prologue = "paseo-rooms/v2" ‖ 0x00 ‖ "noise-ik" ‖ 0x00 ‖ RJCS({ genesisHash, serverId })
```

- The protocol version, the room authority and the endpoint id are in the prologue. A member that targets the wrong room, a v1 endpoint or a different version fails the handshake, so there is no in-band version downgrade (P-25).
- A WebSocket message from the client before the handshake completes must be exactly one Noise message of the expected size (96 bytes for message 1 with an empty payload). Anything else closes the socket.
- Handshake timeout: 10 s per message.
- The initiator rejects an all-zero DH result (Noise rule), and the responder does the same.

### 3.4 Records

After `Split()` every WebSocket message is one Noise transport message (≤ 65 535 bytes, so ≤ 65 519 bytes of plaintext). The plaintext is a record:

```
Record = flags (1 byte) ‖ fragment
flags: 0x00 = last fragment of a frame, 0x01 = more fragments follow
```

A frame is the concatenation of its fragments, at most 4 MiB, and is one RJCS object (MLS payloads inside are base64url). Fragments of different frames do not interleave. The receiver closes the session on an oversized frame, a bad AEAD tag, or a non-canonical RJCS frame.

### 3.5 Session lifetime

- A session lasts at most 12 hours, then the member reconnects with a new handshake. This bounds nonce use and the life of transport keys without Noise rekey.
- Either side sends `{t:"ping"}` after 30 s of silence and closes after 90 s without traffic.
- One live session per device. A new session from the same device static supersedes the older one only after **key confirmation**: the first transport message from the initiator decrypts and parses as a valid frame. Until then the older session stays open, and a new session that never sends a valid frame is closed after the 10 s handshake timeout. The older session is then closed with `superseded`. A replayed IK message 1 lets a recorder complete the responder's side of a handshake, but it cannot produce a valid transport message, so it cannot push the real device off (review finding S-10).

### 3.6 Frame envelope

```
Frame = { t: <type>, id?: <client request id, 1..2^31>, ...fields }
Reply = { t: <type>.ok | "error", re: <id>, ...fields }
Error = { t: "error", re?: <id>, code: <ErrorCode>, ...per-code fields (section 10) }
```

Errors carry no free-text from the host. The member UI maps codes to text (P-20, C-16 spirit). The error schema is strict: each code allows exactly the extra fields listed for it in section 10, and no others.

## 4. Session operations

Who may call what depends on whether the initiator's static key (`rs` after the handshake) is an active device DH key in the current roster.

| Operation | Caller | Spec |
|---|---|---|
| `enroll.request`, `sas.reveal`, `enroll.confirm`, `enroll.abort` | any initiator (pre-auth) | this document, section 5 |
| `enroll.resume` | initiator whose `rs` matches a pending enrollment | section 5.6 |
| `session.hello` | active device | section 4.1 |
| `roster.get`, `log.fetch`, `log.subscribe`, `authority.get` | active device | `room-log-v2.md` section 8.3 |
| `stmt.submit` | active device (own statements); admin device (admin statements) | `room-log-v2.md` section 2 |
| `grant.issue`, `grant.status`, `grant.report` | active device with lane access | `grants-v2.md` sections 3, 6 |
| `device.link.create`, `link.nonce`, `link.confirm`, `link.abort` | active device (the link's creator for the last three) | `identity-model.md` 6.4. The host pushes `link.request` and `link.closed` to the creator |
| `device.rekey` | active device | `keys-rotation-recovery.md` 4.1 |
| `kp.publish`, `commit.submit`, `welcome.fetch`, `msg.send`, `msg.fetch` | active device | `mls-integration.md` section 6 |

A device whose `rs` is known but no longer active (removed, member left, room closed) may only receive `{t:"error", code:"access_ended", reason}` with `reason ∈ {removed, left, room_closed}`. This is disclosed only after the handshake proves possession of that device's DH key, so it is not an oracle for anyone else (P-23).

An `rs` that matches nothing gets `error not_authorized` after any non-pre-auth frame, then the session closes.

### 4.1 `session.hello`

```
M→H { t:"session.hello", id, v:2, known: { logSeq, logHash } }        // own verified head; logSeq -1 if none
H→M { t:"session.hello.ok", re, serverTime: <unix ms>, minVersion: 2,
      memberId, deviceId, head: { seq, hash, hsig },
      lastAck: { seq, epoch } | null }            // last position this device acknowledged (msg.ack)
```

The member compares `head` with its stored head before anything else (`room-log-v2.md` section 6).

## 5. Enrollment

### 5.1 Sequence

```
Member device (M)                         Host room endpoint (H)                Admin UI
  generate per-room keys (sig, dh); persist journal "keys" (sealed)
  choose Nm (32 random bytes); C = H("sas-commit", Nm)
  ── Noise IK msg1 (s = device DH) ───────▶
  ◀─ Noise IK msg2 ──────────────────────  h = handshake hash on both sides
  ── enroll.request {inviteId, keys, label, C, tokenMac, sig(h,…)} ─▶
                                           checks (5.3); invite → claimed; pending created
  ◀─ enroll.pending {pendingId, Nh, genesis, authority, terms, expiresAt}
  verify genesis hash = invite.genesisHash; journal "pending"
  ── sas.reveal {Nm} ─────────────────────▶ check C; compute SAS
  compute SAS; show it                      ─────────────── show SAS + request ──▶
                    <<< owner and member compare the 6 digits by voice or in person >>>
  member presses "Codes match" ── enroll.confirm ─▶
                                           ◀──── admin presses "Admit" (signs member.admitted)
                                           log entry appended and fsynced
  ◀─ enroll.admitted {entry, statement, roster, head}
  verify; journal "admitted"; register lane hosts (section 8)
```

The host waits for **both** confirmations. The admin may admit before the member confirms; the host then holds `enroll.admitted` until `enroll.confirm` arrives. Either side pressing "Codes do not match" ends the enrollment (section 7.2).

### 5.2 Messages

All are frames inside the IK session (section 3.6).

```
enroll.request = {
  t: "enroll.request", id, v: 2,
  inviteId | linkId,                         // exactly one; linkId for device links (identity-model.md 6.4)
  deviceSig: <Ed25519 pub>, deviceDh: <X25519 pub>,
  label: <1..80 chars, NFC, no control characters>,
  sasCommit: b64u(H("sas-commit", Nm)),
  tokenMac: b64u(HMAC-SHA256(tokenKey, TBS("enroll-token", RJCS(EnrollSigned)))),
  sig: b64u(Sign(deviceSigKey, TBS("enroll-request", RJCS(EnrollSigned))))
}
EnrollSigned = { v: 2, typ: "enroll-request", h: b64u(h), genesisHash,
                 inviteId | linkId, deviceSig, deviceDh, label, sasCommit }

enroll.pending = {
  t: "enroll.pending", re, pendingId: "pen_<32 hex>",
  h: <32 bytes b64u>,                         // the handshake hash bound into the EnrollSigned the host accepted (5.6)
  Nh: <32 random bytes b64u>,                // for a device link: the confirming device's Nc
  deviceId?: "dev_<32 hex>",                  // device links only (identity-model.md 6.4)
  genesis: RoomGenesis,                       // identity-model.md 5.1
  authority: { seq, entries: [ signed admin/host statements since genesis ] },
  terms: { role, lanes: [laneId...] },
  expiresAt: <unix ms>                        // min(invite exp, now + 15 min)
}

sas.reveal     = { t: "sas.reveal", id, Nm: <b64u>, newKeySig?: <b64u> }   // newKeySig: device links only
sas.reveal.ok  = { t: "sas.reveal.ok", re }
enroll.confirm = { t: "enroll.confirm", id, pendingId }     // member pressed "Codes match"
enroll.abort   = { t: "enroll.abort", id, pendingId, reason: "sas_mismatch" | "cancelled" }

enroll.admitted = {
  t: "enroll.admitted", pendingId,
  memberId, deviceId,
  statement: SignedStatement<member.admitted | device.add.approved | member.device.replaced>,
  entry: SignedEntry,                            // the log entry that carries it
  roster: Roster, head: { seq, hash, hsig }          // Roster as in identity-model.md 6.1
}
enroll.held   = { t: "enroll.held", pendingId, entry: SignedEntry<device.added>,
                  effectiveAfter: <unix ms> | null }      // device links only
enroll.closed = { t: "enroll.closed", pendingId,
                  reason: "rejected" | "timeout" | "invite_revoked" | "room_closed" | "aborted" | "vetoed" }
```

`enroll.resume` and `enroll.resume.ok` are in section 5.6.

Notes:

- `deviceDh` must equal the IK initiator static `rs`. This proves possession of the DH key. `sig` proves possession of the signing key and binds it to this handshake (`h`) and this room (`genesisHash`).
- The token never crosses the wire, even encrypted. Only a MAC bound to `h` does. A party that relays the member's frames into another session (different `h`) cannot reuse them.
- `authority.entries` is everything the member needs to compute the current admin set, host keys and endpoint from the genesis (`identity-model.md` section 5.2). It is verified, not trusted.

### 5.3 Host check order

The host processes `enroll.request` in this order. "Generic" means the reply is `error enroll_rejected` with nothing else.

1. Frame is canonical RJCS and matches the schema. Else `bad_frame`, close.
2. `v` is 2. Else `unsupported_version` with `minVersion: 2`, close.
3. Rate limit (section 5.4). Else `busy` with `retryAfter`, close.
4. `deviceDh == rs`, and `sig` verifies with `deviceSig` over `EnrollSigned` with **this session's** `h` and this room's `genesisHash`. Else generic. **No lookup has happened yet** (P-23).
5. Look up `inviteId` (or `linkId`). Missing → generic.
6. Constant-time compare of `tokenMac`. On mismatch: `failedProofs += 1`; if it reaches 3, `state = burned` and the host appends `invite.burned {inviteRef, reason:"attempts"}`. Reply generic either way.
7. The requester has now proven token knowledge, so state may be disclosed:
   - `expired` (or `exp` passed) → `invite_expired`
   - `used` → `invite_used`
   - `revoked` or `burned` → `invite_revoked`
   - `claimed` by another pending enrollment → `invite_in_use`, and the host appends `invite.contested {inviteRef, pendingId}` and flags the pending card in the admin UI (section 9).
8. `deviceSig` or `deviceDh` already appears in the roster or the denylist → generic. If they belong to a pending enrollment and `rs` equals its `deviceDh`, continue as a resume (section 5.6); another pending enrollment's keys → generic. Keys are per room, so this indicates a bug or a replay.
9. Create the pending enrollment, set `invite.state = claimed`, `invite.pendingId = pendingId`, persist (fsync), append `enrollment.pending {inviteRef, pendingId, deviceKid}`, reply `enroll.pending`. From this point the attempt has disclosed `Nh`, so if it ends without admission it counts as abandoned (section 5.4).

### 5.4 Attempt limits and rate limits

| Limit | Value | Scope | Effect |
|---|---|---|---|
| Failed token proofs | 3 | per invite (`inviteId` as named in the request) | invite burned; `invite.burned {reason:"attempts"}` logged |
| Abandoned attempts | 3 | per invite | invite burned; `invite.burned {reason:"abandoned"}` logged |
| Confirmer nonces | 3 per link, 1 per pending, 1 open pending at a time | per device link, **counted by the confirming device A**, not the host | A burns the link locally (`identity-model.md` section 6.4, R-2) |
| SAS rejections | 1 | per invite | invite burned with `reason:"sas_mismatch"` |
| Pre-auth requests | token bucket, 10 per minute, burst 5 | per room endpoint, statics **not** in the roster | `busy` |
| Concurrent pre-auth sessions | 8 | per room endpoint, statics not in the roster | new handshakes refused until one closes |
| Requests from active devices | token bucket, 60 per minute, burst 20 | per device | `busy` |
| Pending enrollments | 16 | per room | `busy` |

**Abandoned attempts** (decision round 3, review finding S-4). An attempt is abandoned when its pending enrollment reached `enroll.pending`, and so disclosed `Nh`, and then ended without admission for any reason other than a SAS rejection: `cancelled`, timeout, the admin's Cancel, a disconnect that outlasted `expiresAt`, or a failed resume. Each one sets `abandoned += 1` and returns the invite to `open`. The third burns the invite. Without this limit, a man in the middle holding the token could open a pending enrollment, compute the host-side SAS, and abort whenever it did not match, about 300 times over a 30-minute invite. With it, an attacker gets at most 3 SAS comparisons per invite, so it succeeds with probability at most 3 × 10^-6. The cost is that a member whose connection fails three times during one join needs a new invite; resume (section 5.6) keeps an ordinary network drop from counting. The admin's join card shows the count ("2 earlier attempts were abandoned").

**Who can touch an invite.** An attacker who only saw the endpoint key (any past invitee, P-15) can make requests, but steps 4 and 5 stop them before any invite is touched unless they name a real `inviteId`. The `inviteId` appears only inside the invite code, next to the token, and in the admin's local state. The log and MLS carry only `inviteRef`, a hash of the id, so members cannot learn the ids of open invites and burn them (S-5).

**Separate budgets.** The pre-auth bucket and slots count only handshakes whose static key is not an active device in the roster. Active devices have their own per-device budget. So a past invitee who floods the pre-auth path delays new enrollments but cannot block the sessions of members (S-21). The pre-auth budget is per endpoint because the relay hides source addresses.

### 5.5 Member verification of `enroll.pending`

The member checks, in order:

1. `H("genesis", RJCS(genesis)) == invite.genesisHash`, and the genesis signature verifies with a key in `genesis.body.admins`.
2. `genesis.body.endpoint` equals the invite's `endpoint` (same `serverId`, the same `dh` object, the same relay). A mismatch means the invite was altered: abort with `identity_mismatch`.
3. `authority.entries` verify and fold (`room-log-v2.md` section 5). The endpoint they yield is the one connected to.
4. `terms` are shown to the member with the SAS.

Only then does it send `sas.reveal`.

### 5.6 Resuming a pending enrollment

A member may lose its connection, or restart, while an enrollment is pending. Every reconnect is a new IK handshake with a new handshake hash `h′`. The SAS must not follow it. If either side recomputed the SAS with `h′`, or accepted a new `Nh` after the member had revealed `Nm`, a man in the middle who already knows `Nm` could choose its values until the two codes matched. That is the attack section 6.1 rules out (review finding S-3).

**Pinned inputs.** The SAS is computed once, from the pinned `h` (the one bound into the `EnrollSigned` the host accepted, usually the first session's), `Nm`, `Nh` and the info object. Both sides store these inputs with the pending enrollment:

- the host stores `h`, `sasCommit`, `Nh`, `Nm` (after `sas.reveal`) and the exact bytes of the `enroll.pending` frame it sent, minus `re`;
- the member stores `Nm` and `sasCommit` before it opens the first session (journal state `keys`). After each handshake, and before it sends `enroll.request` in that session, it appends that session's `h` to `sentH` in the journal (at most 4 entries; a fifth restart deletes the keys and asks for a new invite). Before it sends `sas.reveal` it stores `pendingId`, the verified `enroll.pending` bytes minus `re`, and the SAS digits (journal state `pending`).

**The pinned `h` travels with the pending** (re-review finding R-4). `enroll.pending` carries `h`, the handshake hash of the `EnrollSigned` the host accepted. The member accepts an `enroll.pending`, on first delivery or in `enroll.resume.ok`, only if its `h` is in `sentH`, and computes the SAS with that `h`. Without this, a member that restarted after sending its request, but before `enroll.pending` arrived, would compute the SAS with the new session's `h′` while the host kept the original `h`, and the codes would never match. Telling the member which `h` was pinned is safe: the member's `Nm` is still unrevealed at that point, so a man in the middle cannot predict the member's SAS under any `h`, and `sentH` holds only hashes of sessions the member itself ran. The host never re-pins: a host that accepted a new `h′` could be ground by a man in the middle playing the member and reconnecting.

**Resume.**

```
enroll.resume    = { t: "enroll.resume", id, pendingId }
enroll.resume.ok = { t: "enroll.resume.ok", re, pending: <the stored enroll.pending frame minus t and re>,
                     state: "created" | "sas_shown" | "member_ok" | "admin_ok" | "held",
                     held?: enroll.held, admitted?: enroll.admitted }
```

1. The host accepts `enroll.resume` only from a session whose `rs` equals the pending enrollment's `deviceDh`. Anything else gets `enroll_rejected`.
2. The host returns the stored `enroll.pending` content unchanged. It never issues a new `Nh`, a new `pendingId` or new terms for an existing pending enrollment. Authority changes during the pending period reach the member with `enroll.admitted`.
3. The member accepts the resume only if `pending` is byte-identical to what it stored. On any difference it aborts with `enroll.abort {reason: "cancelled"}`, deletes its keys and shows "The join could not be resumed safely. Ask for a new invite." The host closes the pending enrollment and counts an abandoned attempt (section 5.4).
4. The member never sends `Nm` into a pending enrollment other than the one it stored. If `state` is `created` (the host never received `sas.reveal`), it re-sends `sas.reveal` with the same `Nm`. The SAS it shows is the stored one.
5. Later states resume where they were: the member re-sends `enroll.confirm` if its journal says it confirmed and `state` is not yet `member_ok`; `held` and `admitted` deliver the stored frames.

**Restart before `enroll.pending` arrived.** A member whose journal is in state `keys` and has no `pendingId` opens a new session, appends `h′` to `sentH`, and sends a new `enroll.request` with the **same** keys, `Nm` and `sasCommit`, signed over `h′`. If the host already holds a pending enrollment for that `deviceDh`, it checks that `sasCommit` is the same, replies with `enroll.resume.ok` whose `pending` carries the original `h`, and keeps that `h` for the SAS. The member finds the original `h` in `sentH` and computes the SAS with it. If the host never received the first request, it creates the pending enrollment with `h′`. A different `sasCommit` for the same keys means the member lost its journal: the host closes the old pending enrollment as abandoned and replies `enroll_rejected`.

Required tests: a resumed session that receives a different `Nh` aborts; a different `pendingId` aborts; a resume from a session with another `rs` is rejected; the SAS shown after resume equals the SAS shown before; a crash in state `keys` after the request was sent, followed by a restart, shows matching SAS codes on both sides (R-4); an `enroll.pending` whose `h` is not in `sentH` is refused.

## 6. Short authentication string

### 6.1 Why a commitment

`h` alone is not a safe SAS input. In IK the responder chooses its ephemeral after seeing the initiator's. A man in the middle who substituted the endpoint key in the invite runs two sessions. It can finish the session with the real host first, learn that SAS, then try about 2^20 ephemerals in the member's session until the two SAS values match. That takes seconds.

The member therefore commits to a random `Nm` before it sees the host's `Nh`, and reveals `Nm` after. This is the standard commit-then-reveal SAS construction (as in ZRTP and Bluetooth numeric comparison):

- In the member's session the attacker plays the host. It must send `Nh` before it learns `Nm`, so it cannot steer that SAS.
- In the host's session the attacker plays the member. It has committed `Nm'` before it sees the real host's `Nh'`, so it cannot steer that SAS either.
- The two SAS values agree with probability 10^-6 per attempt. An invite allows at most 3 attempts that reach the SAS (3 abandoned attempts, or 1 SAS rejection, burn it; section 5.4), so an attacker succeeds with probability at most 3 × 10^-6 per invite.
- Both properties hold across reconnects only because the SAS inputs are pinned to the session whose request the host accepted (section 5.6).

### 6.2 Derivation

```
info   = RJCS({ deviceDh, deviceSig, endpointDh, genesisHash, inviteId })   // linkId in place of inviteId for device links
sasKey = HKDF-SHA256(ikm = Nm ‖ Nh, salt = h, info = TBS("sas", info), L = 8)
sas    = (uint64_be(sasKey) mod 10^6), zero-padded to 6 digits
display = first three digits, space, last three digits     ("317 837" in the vector)
sasTranscript = H("sas-transcript", h ‖ Nm ‖ Nh ‖ info)    // recorded in member.admitted
```

`sas6` is the only format in v2 (decided 2026-10-29: 6 digits with commit-then-reveal, not 8; see `README.md` decisions log). A `sas` field in the invite and genesis policy reserves room for a words format later (Q2).

### 6.3 What the owner sees (admin UI)

A "Join request" card in the room's member list:

- "Someone used the invite **for Sam** (created 10:42)." (the admin's own note)
- "They call themselves: Sam laptop (self-reported)."
- **Code: 015 136** in large digits.
- The number of earlier abandoned attempts on this invite, if any.
- "Call or meet the person you invited and ask them to read their code. Admit only if it is the same. Do not compare codes in the chat or email where you sent the invite."
- Buttons: **Admit** (enabled only once `sas.reveal` arrived), **Codes do not match**, **Cancel**.
- If `invite.contested` was raised: a red banner "Another device also tried to use this invite. It may have been copied. Compare the code carefully."
- Countdown to `expiresAt`.

### 6.4 What the member sees

- "Read this code to the room owner by voice or in person: **015 136**"
- Room name, owner fingerprint (admin key `kid` display form), role and lanes from `terms`, all marked "(unverified until the codes match)".
- Buttons: **Codes match**, **Codes do not match**, **Cancel**.
- After "Codes match": "Waiting for the owner to admit you…".

Either party reading and the other comparing is enough, as long as both press their button only after hearing the same digits. A mismatch on either side aborts.

### 6.5 What SAS does and does not establish

SAS establishes that the device in the session is the device of the person the owner is talking to, and that the member reached the real room endpoint. It relies on the comparison channel: if the owner cannot recognise the person's voice or face, SAS reduces to "someone who can talk to the owner". Comparing over the same chat that carried the invite gives no protection against whoever controls that chat. The UI says so (section 6.3).

## 7. State machines

### 7.1 Invite (host)

```
open ──(valid proof, step 9)──▶ claimed ──(admitted)──▶ used
  │                               │  ├─(abandoned: timeout, abort "cancelled", admin cancel, disconnect > expiresAt, failed resume)
  │                               │  │      abandoned += 1 ──▶ burned (if abandoned = 3) | open (if exp not passed) | expired
  │                               │  ├─(SAS mismatch from either side)──▶ burned
  │                               │  └─(admin revokes invite)──▶ revoked (pending closed: invite_revoked)
  ├─(3 failed proofs)──▶ burned
  ├─(admin revokes)──▶ revoked
  └─(exp passes)──▶ expired
```

Every transition except `open → claimed → open` appends a statement (`invite.used` is implied by `member.admitted`); the pending enrollment's own `enrollment.closed` records each abandoned attempt. `expired` is computed lazily and logged once, by the host, the next time the invite is looked at or by a daily sweep (`invite.expired`).

### 7.2 Pending enrollment (host)

```
created ──(sas.reveal ok)──▶ sas_shown ──(member confirm)──▶ member_ok ──┐
                               │ ──(admin admit)──▶ admin_ok ───────────┤
                               │                                         ▼
                               │                         (both) ──▶ admitted (terminal)
                               ├─(either "do not match")──▶ closed: aborted / rejected
                               ├─(admin cancel)──▶ closed: rejected
                               ├─(device link: both confirmed)──▶ held ──(device.add.approved)──▶ admitted
                               │                                    └─(veto, requester or member removed, hold + 48 h)──▶ closed: vetoed / rejected / timeout
                               ├─(expiresAt)──▶ closed: timeout
                               └─(invite revoked, room closed)──▶ closed: invite_revoked / room_closed
```

- `admitted` happens in one step on the host: build the roster entry, have the admin key sign `member.admitted` (with `confirmation = {method: "sas6", inviteRef, transcript}`), append the log entry with fsync, update and persist the grant allowlist and roster, then send `enroll.admitted`. If the process dies after the log append and before the send, the member gets `enroll.admitted` on `enroll.resume`.
- Pending records are persisted (sealed host state), so a host restart keeps them until `expiresAt`.

### 7.3 Member enrollment journal

Stored in `member/rooms/<roomId>/state.sealed` under `enrollment`:

| State | Entered when | Persisted before | On restart |
|---|---|---|---|
| `keys` | user pressed Join | opening the relay socket; stores the keys, `Nm` and `sasCommit`; then, per session, the session's `h` in `sentH` before sending `enroll.request` | open IK with the stored DH key; record the new `h` in `sentH`; `enroll.request` again with the same keys, `Nm` and `sasCommit` (section 5.6) |
| `pending` | `enroll.pending` verified, its `h` found in `sentH` | sending `sas.reveal`; stores `pendingId`, the `enroll.pending` content (with the pinned `h`) and the SAS digits | `enroll.resume`; accept only a byte-identical pending; show the stored SAS (section 5.6) |
| `confirmed` | member pressed "Codes match" | sending `enroll.confirm` | `enroll.resume` |
| `held` | `enroll.held` verified (device links) | n/a | `enroll.resume` until `enroll.admitted` or `enroll.closed` |
| `admitted` | `enroll.admitted` verified | registering any lane host | run registration (section 8) |
| `registered` | every lane host registered | n/a | normal operation |
| `failed` | `enroll.closed` or a verification failure | n/a | delete keys and the room record; show the reason |

`enroll.resume` is accepted only from a session whose `rs` equals the pending's `deviceDh`. Its rules are in section 5.6.

## 8. Atomic enrollment on the member side (C-10)

M1 consumed the invite on the gateway and then failed `hosts.add` with no local record. v2 orders the work so that every step after admission is retryable:

1. The journal reaches `admitted` (sealed write, fsync) **before** any call to Paseo's `hosts` API.
2. For each lane in `terms.lanes`, the member requests a grant (`grants-v2.md` section 3) and calls `hosts.add` with `sourceKey = laneId`. Before adding, it lists hosts and updates an existing registration with the same `sourceKey` instead (idempotent).
3. It records each `registrationId` in the journal as it succeeds.
4. On failure it retries with backoff (1 s, 2 s, 4 s … 60 s), logging `error.name` and `error.code`, never the grant. The room shows "Connected to the room; lane setup is retrying" meanwhile. Room chat does not depend on lane registration.
5. When all lanes are registered the journal moves to `registered`.

Timers and observers are armed from the journal at plugin start (`contribute()` time), not on first app contact (C-12). Only the `hosts` calls wait for a `PaseoApi`.

## 9. Races

| Race | Outcome |
|---|---|
| Two requesters with valid proofs for one invite | The first reaches step 9 and claims it. The second gets `invite_in_use`. `invite.contested` is logged and the admin sees the warning. If the admin then rejects the first, the invite is burned (both requesters had the token; it leaked). |
| Two requests from the same device keys (retry after a lost reply) | Step 8 sees the keys in a pending enrollment. If `rs` matches that pending's `deviceDh` and `sasCommit` is unchanged, the host treats it as a resume and returns the original pending (section 5.6); otherwise generic. |
| Admin revokes the invite during pending | Pending closes with `invite_revoked`; the member deletes its keys. |
| Admin removes the member right after admission | Normal removal (`grants-v2.md` section 7). If `enroll.admitted` was not yet delivered, the next `enroll.resume` returns `access_ended removed`. |
| Room closed during pending | `room_closed` to every pending session. |
| Admin key rotated during pending | The admission is signed by the admin key valid at that time; the member folds authority entries delivered with `enroll.admitted`. |
| Host restarts during pending | Pending survives (persisted). Member reconnects and resumes. |
| Member restarts during pending | Journal state `pending` or `confirmed`; member resumes with the same DH key. |
| Member presses "Codes match" after the admin pressed "Codes do not match" | `enroll.closed rejected` wins; the confirm gets `enroll_closed`. |
| Clock skew between member and host | Expiry is decided on the host clock only. The member shows the host's `expiresAt` relative to `serverTime`. |

## 10. Error codes

Every error frame is `{ t: "error", re?, code }` plus exactly the extra fields in the third column. Strict schemas reject any other field (review finding S-18).

| Code | Sent when | Extra fields | Reveals |
|---|---|---|---|
| `bad_frame` | non-canonical or invalid frame | none | nothing about state |
| `unsupported_version` | `v` ≠ 2 | `minVersion` | the minimum version |
| `busy` | a rate limit is hit | `retryAfter` (s) | that the endpoint is busy |
| `enroll_rejected` | any failure in steps 4 to 6 and 8, or a rejected resume | none | nothing: same code for unknown invite, bad MAC, bad signature, key reuse |
| `invite_expired`, `invite_used`, `invite_revoked`, `invite_in_use` | after a valid token proof | none | the state of an invite the requester holds the token for |
| `enroll_closed` | operation on a closed pending enrollment | `reason` (as in `enroll.closed`) | that it is closed |
| `not_authorized` | non-pre-auth frame from an unknown static | none | nothing |
| `access_ended` | authenticated static of an ended device | `reason`: `removed`, `left` or `room_closed` | the device's own status, to its key holder |
| `not_permitted` | an authenticated device asks for something its role or lanes do not allow, or submits a statement the host refuses | none | that the operation is not allowed |
| `stale_base` | a submitted statement's `ver` no longer matches the current version, or its `base` does not move the producer's base forward (`room-log-v2.md` section 2) | `head: {seq, hash}` | the current head, to an active device |
| `unknown_base` | a submitted statement's `base` is not an entry of the host's chain (`room-log-v2.md` section 2, R-9) | `head: {seq, hash}` | the current head, to an active device |
| `stale_roster` | a submitted commit names a roster that is not the current one (`mls-integration.md` section 4.2) | `roster: {seq, hash}` | the current roster position |
| `stale_epoch` | an MLS commit for an epoch that is no longer current (`mls-integration.md` 6.2) | `epoch` | the current epoch |
| `superseded` | a newer, key-confirmed session for the same device (section 3.5) | none | nothing |
| `moved` | session on a retired room endpoint (`keys-rotation-recovery.md` 4.6) | `entry` (the signed entry carrying `endpoint.rotated`) | the new endpoint |
| `persist_failed` | an access-reducing operation was enforced but could not be saved (`grants-v2.md` 7.2) | none | that the change is not durable yet |
| `internal` | unexpected failure | none | nothing; details only in the host's local log |

Every error closes the session except `not_permitted`, `busy`, `stale_base`, `unknown_base`, `stale_roster`, `stale_epoch` and `persist_failed` on authenticated sessions.

The local plugin RPCs that the Rooms UI calls use the same codes where they apply (`persist_failed` in particular).

## 11. Standalone host and SSO (later)

With a standalone host (Phase 3) the admin may not be online when a person enrolls. Decision 3 replaces SAS there with **SSO attestation**: the host's identity provider signs a statement binding the SSO subject to the device keys and `h`, and an admin policy admits attested subjects automatically. That needs its own spec. v2 reserves `confirmation.method = "sso-v1"` and changes nothing else in the formats.

## 12. Open questions

Resolved and moved to `README.md` section 7 (decisions log): former Q1 (SAS length: 6 digits) and former Q5 (Noise engine: vendor Paseo's module and add IK, section 3.2.1; upstream request recorded in `README.md` section 6). Remaining question numbers are kept stable.

- **Q2.** Add a word-list format (`sas-words`)? Needs a pinned, licence-compatible list and localisation decisions.
- **Q3.** Should the member also be able to admit without voice comparison when an owner explicitly chooses "trust on first use" for low-stakes rooms? The design preference is opt-in features; the risk is that it becomes the default habit. Proposed: not in v2.
- **Q4.** Relay eviction of the room endpoint (P-16) is a denial of service against enrollment and chat. Upstream server-role authentication is the real fix.
