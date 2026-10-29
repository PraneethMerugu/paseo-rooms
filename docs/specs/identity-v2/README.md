# Identity v2 specifications (paseo-rooms)

- **Date:** 2026-10-28
- **Status:** proposed. Written from the M1 reviews and the user-approved decisions in `plugin/review/HARDENING-PLAN.md`, including "Decisions, round 2", "round 3", "round 4", "round 5", "round 6", "round 7" and "round 8" (2026-10-29, section 7 below). **Not implemented.** Independently reviewed on 2026-10-29 (`plugin/review/identity-v2-review.md`, verdict "ready with fixes"), revised, re-reviewed (`plugin/review/identity-v2-rereview.md`, verdict "ready with small fixes") and revised again (section 10). Per round 4, item 4, the next step is a targeted check that each R finding is addressed and that the vectors regenerate, not another full review.
- **Evidence labels:** statements about Paseo, the relay library and ts-mls cite the source files read. Statements about our design are specification, not results. The executed artifacts are the test-vector generator (`vectors/`), which runs and self-checks (including the cacophony NK and IK vectors), the keyring spike (`spikes/keyring/RESULTS.md`), and Spike A on ts-mls rekey behaviour (`spikes/security/RESULTS.md`, last section; `mls-integration.md` section 10, test 11).

## 1. What this covers

Section A of the hardening plan (A1 to A8) and the protocol-touching D items: P-9, P-15/C-7, P-23/C-8, P-20/C-15, C-10, P-27. It follows the approved decisions:

1. Keys at rest in the OS keyring where available; same-user malware out of scope; dedicated OS user recommended.
2. Only sandboxed lanes can be prompted by non-owners (this spec reserves gateway members for that case but does not specify sandboxing).
3. SAS for host-less rooms; SSO attestation later for standalone hosts.
5. Specs first, then review, then implementation together with the protocol-touching D fixes.

It also applies the round 2 decisions (eight resolved questions, viewer errors, project names), the round 3 decisions (the review's five open questions), the round 4 decisions (the re-review's three questions and the process), the round 5 spec follow-ups and the cross-platform requirement; see section 7. Section 10 maps the review and re-review findings to their resolutions.

## 2. Documents

| File | Content |
|---|---|
| `identity-model.md` | Principals, keys, per-room unlinkable device keys, multi-device, admin key separate from host key, roster, identifiers, key storage (keyring, fallback, dedicated OS user) |
| `enrollment-v2.md` | Invites, relay rules, room endpoint with Noise IK, session operations, enrollment with SAS, check order, attempt limits, state machines, atomic member-side enrollment, races, error codes |
| `signatures-and-encoding.md` | RJCS canonical encoding, strict parsing, domain-separated contexts, strict base64url, key ids, versioning and downgrade rules, test vectors |
| `keys-rotation-recovery.md` | Key-change statements, validity windows, rotation for every key type, MLS effects, compromise recovery procedures |
| `grants-v2.md` | Lane grant format, issuance, verification with an allowlist, lifetime and rotation, stolen-grant handling, enforce-then-persist revocation, pruning, clock skew |
| `mls-integration.md` | ts-mls pinning and regression tests, group per room and subgroups, credentials, authentication service and roster-equality rule, epoch anchoring, delivery service, gateway members, state at rest |
| `room-log-v2.md` | Statements, entries and bodies; event catalogue with producers; roster fold; equivocation, truncation and withholding detection; plaintext metadata; storage |
| `migration.md` | M1 rooms are invalidated (prototype stage); what the plugin does on upgrade |
| `vectors/gen-vectors.mjs`, `vectors/vectors.json` | Deterministic test vectors and self-checks (run with `ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin plugin/docs/specs/identity-v2/vectors/gen-vectors.mjs`) |

Suggested reading order: identity model, signatures and encoding, enrollment, grants, room log, MLS, rotation and recovery, migration.

## 3. Key design choices

| Choice | Where | Short reason |
|---|---|---|
| Separate **room endpoint** per room (own `serverId` and X25519 key) for enrollment and all long-lived sessions; lane endpoints serve only Paseo host links | enrollment 3.1 | Room-level membership must not depend on a lane (P-4) |
| **Noise IK** on Paseo's vendored Noise module (`packages/relay/src/noise/`, Apache-2.0) with an added IK handshake | enrollment 3.2, 3.2.1 | The member always knows the endpoint key; IK is 1 RTT and mutual. The relay package implements only NK and does not export the module or the handshake hash. No maintained npm library offers IK with the SHA-256 suite. |
| **SAS with commit-then-reveal**, 6 digits, both sides confirm; inputs pinned across resume; at most 3 attempts per invite | enrollment 5.4, 5.6, 6 | `h` alone is grindable by a responder in the middle |
| Token proven by an **HMAC bound to `h`**, never sent | enrollment 5.2 | No token replay into another session; no plaintext token at a fake endpoint |
| **Signature first, then lookup**; one generic rejection code before token proof; state disclosed only to provers | enrollment 5.3, 10 | P-23 |
| **Per-room device keys** (signing and DH) plus a separate MLS leaf key; no global identifiers sent | identity 4 | Unlinkable across rooms (P-14) |
| **Admin key** signs membership; host key only orders and issues grants within the roster | identity 4.1 | P-3, P-29 |
| Every statement names the log head it was made at (`base`), and a producer's `base` only moves forward; state-changing statements carry the **version** (log position of the last change) of the field they change; duplicates and stale versions are rejected | room log 2, 4.0, 5 | A host cannot replay old statements or sequence a held one after the state returned to an old value (S-1, R-1) |
| Device adds and rekeys approved automatically only after a **24 h hold** (72 h when the request comes from a person's only device) with a veto from the person's devices; a device can remove only itself; removing a device cancels what it requested | identity 6.2, 6.3; keys 4.1; room log 4.3 | A stolen device cannot take over a membership (S-2, R-8) |
| **Admin lineages**: closure and a first recovery key need an independent second admin; a 24 h closure delay; revocations cannot reach back before the revoker's start | room log 5.1, 5.2; keys 6.8 | A single stolen admin key cannot end a room that has an independent admin or a recovery key (R-3) |
| The **confirming device counts its own link attempts** (3 per link) | identity 6.4 | A malicious host cannot grind device links (R-2) |
| No person-level key; devices tied by the admin-signed roster and device-signed linking | identity 4.2 | The admin signs every change anyway; fewer widely copied keys |
| **RJCS** (restricted RFC 8785) with "bytes must equal re-encoding" | signatures 1.1, 2 | Small change from M1 JSON; strict rule kills malleability |
| `TBS = "paseo-rooms/v2" ‖ 0 ‖ ctx ‖ 0 ‖ payload`, one context per statement type | signatures 3 | P-11 |
| Grant **allowlist of the current gid** per (device, lane); one link per (device, lane); forced rotation at 75 % | grants 4, 5, 6 | P-9, P-12 |
| **Enforce, then persist** with file and directory fsync; failures reported, never success | grants 7 | P-13 |
| One log sequence for security events, commits and chat; **producer signatures** plus host-signed entries; heads gossiped inside MLS authenticated data | room log 1 to 6 | P-7 |
| MLS **roster equality**: a commit must leave the leaf set, keyed by `(memberId, deviceId, deviceSig)`, equal to the admin-signed roster it names, minus devices that have no leaf yet; every leaf absent from the roster is removed. Adds are roster-determined and may be committed by any device of the group (R7-2) | MLS 4.2, 4.3 | P-3 |
| **Device rekey by the admin route**: the approving admin daemon removes the old leaf and adds the new KeyPackage in a commit sequenced next to the approval; public ts-mls APIs only. Any device of a group may complete a rekey there (R7-2) | MLS 4.4; keys 4.1 | ts-mls 1.6.4 cannot send a credential change in an UpdatePath without a fork (Spike A); no rekey window, so no `prevSig` exception |
| **KeyPackages** published by each device into two pools (current key, pending rekey key), fetched by any device sharing a group with the target (`rekey` pool by admins only), single-use and deleted when served, with one last-resort package per pool, a per-device rate limit and a per-fetcher cap; the fetcher checks every package against the roster | MLS 6.4; enrollment 4, 5.1 | Every Add needs one, and a device stays out of a group until one is used, so availability matters; the host is trusted for availability only |
| One KEK behind a **KeyStore** abstraction (Keychain, Credential Manager, Secret Service; never kernel keyutils) seals every key file and MLS state; owner-only fallback file on every OS | identity 7.3, 7.5 | Decision 1, P-2, keyring spike |
| **Owner-only files verified at startup on every OS** (POSIX modes, Windows DACL) and platform-aware durable writes | identity 7.8, 7.9; grants 7.3 | Cross-platform requirement (Linux, macOS, Windows, WSL, Docker) |
| Room **policy** in genesis, changed only by signed `room.policy.changed`; org policy can fix stricter values | identity 5.2.1; room log 4.1, 4.6 | Decisions round 2 |
| Viewers get **generic errors**; owners keep full errors. Project names hidden unless the **lane owner** shows them for their own lane; admins can force them hidden | grants 13 | Decisions rounds 2 and 3 |
| **Invalidate** M1 rooms | migration | Prototype stage |

## 4. Threat model

### 4.1 Attackers considered

From the protocol review: a curious or malicious member, a revoked member, a holder of a stolen invite or grant, a network or relay adversary, a compromised member daemon, a malicious or compromised host, a malicious owner (toward members), and a prompt-injected room agent. **Same-user code (other plugins, agents with a shell, malware) is out of scope** (section 5).

### 4.2 Findings resolved by these specs

| Item | Findings | Threat | Resolved in | Residual risk |
|---|---|---|---|---|
| **A1** | P-1 | A leaked or altered invite lets someone else enroll, or a man in the middle proxy both sides | enrollment 5, 5.6, 6, 7.2; identity 6.4; room log 4.3 (`confirmation`) | Depends on a comparison channel where the owner recognizes the person; at most 3 × 10^-6 per invite (3 attempts reach the SAS), and the same per device link, counted by the confirming device |
| **A2** | P-3, P-29 | Host or host-key thief adds ghost devices or replays admin statements; any `daemon.manage` caller acts as owner | identity 4.1, 5, 5.3, 6.4; MLS 2.3, 4; room log 2, 4, 5 | Embedded host: admin and host keys on one machine (identity 7.4). The UI confirmation is a usability guard only: same-user callers can obtain the `confirmToken` as the UI does (identity 5.3) |
| **A3** | P-4, P-14 | Revocation scope unclear; lane-bound chat; cross-room correlation by device key; a stolen device takes over a membership | identity 3, 4.3, 6; enrollment 3.1, 4 | Relay operator sees IPs; social correlation (identity 4.3). A person whose only device is stolen, and who no longer has it, cannot veto; the thief's new device joins after 72 h unless the person tells an admin, who removes the stolen device and so cancels the add (identity 6.3). The same applies to a rekey of the stolen device, which then denylists the keys the person still holds; it is also held 72 h and cancelled by the removal (round 5, item 3). Org policy `soleDeviceChange = "admin"` removes both cases |
| **A4** | P-8 | Holder of a lane key hijacks a long-lived session | enrollment 3.2 to 3.5 | Endpoint key theft allows impersonating the endpoint (KCI); recovered by rotation |
| **A5** | P-10 | No recovery after any key leak | keys 2 to 6; room log 4.1, 5.1, 5.2; identity 5.4 | Single admin who skipped the default-offered recovery key: room unrecoverable after admin key compromise (keys 6.5, 6.6), and two admins without a recovery key can race to revoke each other. A stolen key of a room's only admin lineage can install a recovery key and close the room (room log 5.2). Members offline more than 30 days across an endpoint rotation need a new invite (keys 4.6) |
| **A6** | P-11, P-22, C-14 | Cross-protocol signatures, ambiguous encodings, 64-bit ids, lenient base64 | signatures 2 to 5, 7, 9; identity 8 | RJCS not yet cross-checked with a second-language RFC 8785 library |
| **A7** | P-7 | Host fabricates member actions, forks or truncates the log | room log 2, 3, 6; MLS 5 | Newest entries nobody has seen can be delayed (room log 6.4). A member's unproven head claim raises only `unverified_head_claim` (room log 6.3) |
| **A8** | P-2 | Keys readable from backups and disk | identity 7; MLS 8 | Same-user processes read everything (decision 1); fallback file offers no protection against readers of the same account; native keyring packaging unverified (identity Q3) |
| D | P-9 | Stolen grant defers the victim's rotation | grants 5, 6 | Bearer on the Paseo link remains; theft window up to the next forced rotation or detection |
| D | P-15, C-7 | Anyone with the lane offer, or any member reading the log, burns every invite | enrollment 5.3 (steps 4 to 6), 5.4; room log 4.2 (`inviteRef`); keys 4.7 | An attacker holding an invite code can still burn that invite (it already had the token) |
| D | P-23, C-8 | Membership oracle before authentication | enrollment 4, 5.3 step 4, 10 | none known |
| D | P-20, C-15 | Invite chooses any relay, plaintext transport, deceptive host labels | enrollment 2.2, 2.3 | A trusted relay operator still sees connection metadata |
| D | C-10 | Invite consumed with no local record | enrollment 7.3, 8 | none known |
| D | P-27 | Security-relevant changes not logged | room log 4, 4.6, 4.7 | Host-local access log is not shared or signed |

### 4.3 Other findings these specs also address

| Finding | Resolved in |
|---|---|
| P-12, C-9 (denylist pruned by clock) | grants 4 step 6, 8 |
| P-13 (persist before enforce; no fsync) | grants 7 |
| P-16 (relay server-role eviction) | detection only: enrollment 3.1 (`endpoint.evicted`); keys 4.7 (rotate lanes on removal). Real fix is upstream. |
| P-17, C-4 (resource use, in part) | grants 11; enrollment 5.4. Remaining caps are hardening item B3. |
| P-21 (grant admits all daemon clients) | documented: grants 10 |
| P-22, M-5 (presented key vs stored key) | signatures 5.2; grants 4 step 5 |
| P-24 (clock skew) | grants 5, 9 |
| P-25 (downgrade) | signatures 7; enrollment 3.3 |
| C-11 (torn log line) | room log 8.1 |
| C-12 (timers re-armed only on contact) | enrollment 8; grants 5 |
| C-13 (archived lane agent) | room log 4.4 (`lane.degraded`, automatic close after 24 h) |
| M-1 (producer signatures) | room log 1, 2 |
| M-6 (integrity-critical files) | identity 7.1 |

## 5. Out of scope

| Topic | Why | Where it is handled |
|---|---|---|
| Same-user malware, other plugins, agents with a shell running as the owner (P-2 residual, P-5/C-1, P-6) | Decision 1. No user-space design can protect keys from code running as the same user. | Hardening plan section C (sandboxed runners), dedicated OS user (identity 7.6) |
| Key storage on clients (desktop, web, iOS, Android apps) | Clients hold no room keys; they act through their daemon | identity 7.3 |
| Room Profile field allowlists, hello rebuilding, metadata leaks (P-18, P-19, P-26, C-2, C-3, C-6, C-16) | Not identity; lane data plane | Hardening plan B1, B2 |
| General resource caps (C-4 beyond grants and enrollment) | Not identity | B3 |
| Provider allowlist (P-28) | Agent isolation | C-iso3 |
| Log injection in local logs (C-5) | Local hygiene | D, non-protocol |
| Availability against a malicious host or relay (dropping, delaying, evicting) | Cannot be prevented without other infrastructure | Detected: room log 6.4 to 6.6; enrollment 3.1 |
| Traffic analysis (timing, sizes, relay IP metadata) | Not addressed by this design | Stated in identity 4.3 and room log 7 |
| Malicious owner showing harmful or misleading lane content | Content, not identity | Lane labels are prefixed and verified (enrollment 2.3) |
| SSO attestation for standalone hosts | Decision 3: later | Reserved `confirmation.method = "sso-v1"` (enrollment 11) |
| History sharing to new devices, archives, escrow, mirrors | Separate features (architecture 8.3, 8.4) | Later specs |
| Post-quantum security | Suite 1 is classical | Revisit with ts-mls 2.x suites |
| Side channels in the crypto libraries | Library responsibility | Pin versions; review (MLS 1) |

## 6. Upstream requests

1. `@getpaseo/relay`: export the Noise module (`packages/relay/src/noise/`) from the package, add an IK pattern (or a pattern-table `HandshakeState` that accepts IK), and expose `handshakeHash()` on `SecureChannel`. Then the plugin can drop its vendored copy and bind to Paseo's handshake. Our IK addition and its cacophony test (enrollment 3.2.1) can be offered as the contribution. Also ask that `packages/relay/package.json` declare `"license": "Apache-2.0"` and that the published tarball include `LICENSE` (0.13.2 has neither).
2. Relay: authenticate the `role=server` socket (P-16).
3. Connected hosts: proof of possession or channel binding for link passwords (D3), and a Paseo-level ping the destination side can send (grants Q2).
4. Connected hosts: route permissions per origin session, so only app sessions can open routes to `plugin:rooms` hosts (P-21).
5. Plugin API: a keyring API for plugins, ideally with per-plugin access control (identity Q3, Q4). This would also remove the native-packaging blocker.
6. Plugin runtime: per-plugin permission scoping and a final, non-overridable hook phase (P-6).
7. Plugin compiler and installer: document and support external native dependencies with platform `optionalDependencies` (identity Q3).
8. ts-mls: allow a credential and signature-key change in an UpdatePath through the public `createCommit` (for example a new-leaf-credential option). Version 1.6.4 copies the old credential and signature key into every UpdatePath (`updatePath.js:37-40`; Spike A case a0). With it, a device could commit its own rekey without an admin online (MLS Q6). Held with the others (decisions round 6, item 3).

None of these requests has been sent. Sending them needs the user's go-ahead.

## 7. Decisions log

The eight open questions of the first draft were decided by the user on 2026-10-29 (`plugin/review/HARDENING-PLAN.md`, "Decisions, round 2"). Two related decisions from the same round and one later requirement are included.

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| 1 | SAS strength and format | 6 digits with commit-then-reveal (`sas6`). No 8-digit variant; a words format stays reserved. | The commitment stops an attacker from grinding SAS values, so each attempt succeeds with probability 10^-6. An invite allows at most 3 attempts that reach the SAS (round 3, item 4). Six digits are easy to read aloud. | enrollment 5.4, 6 |
| 2 | Device linking default | Auto-approved when another active device of the same person adds it, with a notice to the room, after the 24 h hold of round 3 (72 h when the person's only device adds one, round 4; the same for a rekey of a person's only device, round 5). Admin approval when the person has no device in the room. Org policy can require admin approval always (`deviceAddApproval = "admin"`). | The person proves control of an enrolled device and compares the SAS on their own two screens; admin approval would add a round trip without new evidence. Without a device there is nothing to prove, so it goes through the admin. | identity 5.2.1, 6.3, 6.4; room log 4.6 |
| 3 | Recovery key | Offered by default at room creation, optional (one click to skip). Org escrow when org policy says so (`recoveryEscrow = "org"`). | A single-admin room without one is unrecoverable after admin key loss. Offering by default makes the safe path easy without forcing it (opt-in preference). Escrow is an org decision, and members see it in the policy. | identity 5.4; keys 4.4 |
| 4 | Grant lifetime | 12 h grants; rotation preferably when idle (from 50 %), forced at 75 %. Fixed at 12 h by round 3, item 3. | Bounds the life of a stolen bearer grant to hours, and limits forced view interruptions (about 3 s when idle) to one per 9 h of continuous viewing. | grants 5 |
| 5 | Lane rotation on member removal | Only when the removal is flagged as a compromise (`rotateLaneOnRemove = "compromise"`); `"always"` available and org-enforceable. | Rotation restarts every member's routes on the lane. Revoked grants and the allowlist already keep removed members out of lane content; the residual (pre-auth surface, relay eviction) matters when misuse is suspected. | keys 4.7, 6.3; room log 4.3 |
| 6 | Long-offline members after endpoint rotation | Stranding after 30 days offline is accepted; the path back is a new invite (re-admit as the same member). | Endpoint rotation is rare (host compromise or admin request). An endpoint directory would need relay support. | keys 4.6 |
| 7 | Noise IK engine | Vendor Paseo's tested Noise module (commit `1467121`, also in `@getpaseo/relay` 0.13.2 `dist/noise/`, Apache-2.0) and add IK; request an upstream export. | No maintained npm library has IK with `25519_ChaChaPoly_SHA256` (BLAKE2b-only, XX-only or unmaintained). Vendoring reuses the same `@noble` primitives and Paseo's NK-tested code. The prototype passes the cacophony NK and IK vectors (signatures 9.3). | enrollment 3.2.1; section 6 request 1 |
| 8 | Keyring binding | Spike done (`spikes/keyring/RESULTS.md`): `@napi-rs/keyring` 2.1.2, Linux pinned to Secret Service, never keyutils; `meta.json` records that a keyring KEK exists; headless hosts use the fallback; locked keyrings handled with timeouts. **Native packaging is still an open blocker** (identity Q3). | Tested on Linux under Paseo's runtime; it is the only maintained option with prebuilt N-API binaries for all three OSes. | identity 7.3, 7.5 |
| R2 | Viewer error text | Viewers get a generic text with an error reference; owners keep full errors locally. | Error text can leak paths, provider details and prompts (hardening item B2). | grants 13.1 |
| R2 | Project display names | Hidden from viewers by default, with an owner option to show them. Refined by round 3, item 2. | Project names can reveal unpublished work. Opt-in matches the design preference. | grants 13.2; room log 4.4, 4.6 |
| R3 | Cross-platform support (coordinator request, 2026-10-29) | Daemon code targets Linux, macOS, native Windows, WSL and headless/Docker from day one; clients hold no room keys. KeyStore abstraction with capability detection, no-native CLI path and an always-available owner-only fallback; owner-only file protection verified at startup on every OS; platform-aware durable writes. Untested platforms are marked. | Labs use mixed machines and headless gateways. | identity 7.3, 7.5, 7.8, 7.9; grants 7.3, 8 |

The five open questions of the independent review (`identity-v2-review.md` section 6) were decided on 2026-10-29 ("Decisions, round 3"):

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R3-1 | Brakes on automatic device approval (S-2) | Automatically approved device adds are held for 24 h, and the person's other devices can veto them. A device can remove only itself; admins can remove any device. | Keeps "auto-approved with notice" (decision 2) while stopping a stolen device from adding its own device and removing the person's others. The spec applies the same hold to automatic device rekeys, stops devices younger than 24 h from auto-adding, and limits `member.left` to a member's only device; these follow from the decision rather than being separate choices. | identity 6.2, 6.3, 6.4; keys 4.1, 6.1, 6.3; room log 4.3, 5 |
| R3-2 | Who may reveal project names (S-16) | Only the lane owner, and only for their own lanes. Admins can force names hidden. | Revealing a project name is the lane owner's disclosure, not a room-wide decision. | grants 13.2; identity 5.2.1; room log 4.4 |
| R3-3 | Grant lifetime (S-17) | Fixed at 12 h. Org policy can shorten it, not lengthen it. No per-invite value. | One lifetime is easier to reason about; the first draft's 1 h to 24 h per-invite range was not asked for. | grants 5; identity 5.2.1; enrollment 2.1 |
| R3-4 | Abandoned join attempts (S-4) | An invite is burned after 3 abandoned attempts. | Bounds a man in the middle to 3 SAS comparisons per invite. A member whose join fails three times needs a new invite; resume keeps ordinary drops from counting. | enrollment 5.4, 5.6, 7.1 |
| R3-5 | Room closure (S-8) | `room.closed` needs the recovery key or a second admin's signature. No window to undo it. | Intended to stop a single stolen admin key from ending a room. The first revision claimed it did and that a single admin without a recovery key cannot close. Both claims were wrong (re-review R-3): one key could add a second key, or install a recovery key, and then close. Round 4, item 1 tightens the rule (below). A single admin can still close by first adding a recovery key, which is acceptable because one admin already holds every power. | room log 4.1, 5.2; keys 6.8 |

The three questions of the re-review (`identity-v2-rereview.md` section 8) and the process for this revision were decided on 2026-10-29 ("Decisions, round 4"):

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R4-1 | Closure (R-3) | The confirming key must be independent of the proposing key. Adding the first recovery key in a room with more than one admin needs two admins. Recovery-key revocations are bounded like admin revocations. A 24 h delay between proposing and confirming a closure is on by default. | Closes the three bypasses of R3-5. **Interpretation:** "independent" means a different **lineage root** (genesis key, or a key added by R); keys an admin adds share its root. The re-review's narrower rule ("not descended from the proposer") still lets one stolen key close with two keys it added. "More than one admin" is read as "more than one lineage", since a second key of the same lineage can be created by one stolen key. The delay is policy `closeDelay` (default 24 h, 0 turns it off); R closes without delay. | room log 4.1, 5.1, 5.2; keys 4.3, 4.4, 6.6, 6.8; identity 5.2, 5.2.1, 5.4 |
| R4-2 | A person's only device adds a second device (re-review residual 2) | The hold is 72 h instead of 24 h. Orgs can require admin approval instead. | A person who loses their only device needs time to tell an admin. Removing the stolen device cancels its pending add in the fold. Org option: policy `soleDeviceChange = "admin"` (named `soleDeviceAdd` until round 5). This decision covered adds; round 5, item 3 extends it to rekeys. | identity 5.2.1, 6.3; room log 4.3, 5 |
| R4-3 | Settings versions (R-1) | Each state-changing statement carries the version (log position of the last change) of the field it changes, instead of its old value. Each producer's `base` may only move forward. | Positions never repeat, so a held statement cannot match again after an ABA change; the forward rule kills held statements once the producer signs again. **Detail:** "forward" is strict (each producer key submits one statement at a time); statements naming single-use objects (keys, device ids, `ref`) need no version; `room.policy.changed` carries one version per setting, so two admins changing different settings do not conflict. | room log 2, 4.0, 4, 5; enrollment 10; signatures 3.2 |
| R4-4 | Process | One revision pass for R-1 to R-6 and the low findings, then a targeted check that each R finding is addressed and the vectors regenerate; no further full review. The ts-mls questions (S-11, R-5) get offline unit tests early in implementation. Then the implementation plan. | | this revision; MLS 10 test 11 |

Three spec follow-ups from the final revision pass were decided on 2026-10-29 ("Decisions, round 5", items 1 to 3; items 4 to 10 of that round concern the implementation plan):

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R5-1 | Deviations from the re-review's R-3 fix | Accepted: a closure's confirming key must come from a different lineage root than the proposer's, and a first recovery key needs two admins when the room has more than one lineage. | Confirms the interpretation recorded under R4-1. No spec change. | room log 5.2; keys 4.4, 6.8; identity 5.4 |
| R5-2 | Revoke race in a room with no recovery key | Residual risk accepted and documented, not fixed: a thief who wins the revoke race can install a recovery key and close the room. Recovery keys are offered by default. | The mitigation is that recovery keys are offered by default at room creation. | room log 5.1, 5.2; keys 6.6; section 4.2 (A5) |
| R5-3 | Rekeys requested by a person's only device | The 72 h hold of R4-2 also applies to automatic rekeys requested by a person's only active device. The org option covers both and is renamed `soleDeviceChange` (was `soleDeviceAdd`). | A thief holding a person's only device could otherwise rekey it after 24 h and denylist the keys the person still has. The person needs the same time to tell an admin, whose removal of the device cancels the pending rekey in the fold. | identity 5.2.1, 5.3, 6.3; keys 4.1; room log 4.3, 4.6, 5; vectors `deviceRekey` |

After Spike A (`spikes/security/RESULTS.md`, section "Identity v2 Step 0, Spike A"), the user decided on 2026-10-29 ("Decisions, round 6"):

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R6-1 | How device rekeys reach MLS | Admin route: the admin daemon that signs `device.rekey.approved` removes the old leaf and adds the new KeyPackage in one commit, submitted with the approval and sequenced next to it. Public ts-mls APIs only; no fork of `createCommit`. | The public `createCommit` cannot put a new credential into an UpdatePath (Spike A case a0). A fork would couple the adapter to library internals across upgrades. An admin daemon already signs every approval. | MLS 1, 3, 4.3, 4.4, 6.1; keys 4.1, 4.2, 5; room log 2, 4.3; identity 4, 5.3 |
| R6-2 | Spike A spec fixes | The continuity check runs after processing (sender's leaf before and after), not in the `IncomingMessageCallback`. The `prevSig` exception is removed, not just limited to `joinGroup`: with `deviceSig` in the roster-equality leaf identity and approval and application adjacent, no Welcome can be built over an unapplied rekey. ts-mls must be at least 1.6.4. | Observed: the callback never sees the UpdatePath leaf (case b); the round-4 "unchanged" rule let a stale UpdatePath through the `prevSig` exception (case a-stale); the removal check fails on 1.6.2 (case f). The decision allowed a `joinGroup`-only exception; the re-derivation in MLS 4.4 shows none is needed. | MLS 1, 4.1, 4.2, 4.4, 10 |
| R6-3 | Upstream | Ask ts-mls for credential change through the public `createCommit`. Held with the other requests until the user approves sending. | Would allow a device to commit its own rekey later. | section 6, item 8 |
| R6-4 | Next step | Start implementation with I-1 and I-16 in parallel. | | implementation plan |

The user decided on 2026-10-29 ("Decisions, round 7"; item 3 of that round concerns the e2e test budget, not the specs):

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R7-1 | Scope of the `prevSig` removal | `prevSig` is removed entirely, not limited to `joinGroup`. | Confirms the revised MLS spec (R6-2): with `deviceSig` in the leaf identity and every old-key leaf removed by the next commit, no valid Welcome contains an old-key leaf. | MLS 4.1, 4.4; keys 4.1 |
| R7-2 | Team subgroups with no admin, and pending adds that block commits | Options (b) and (c) of MLS 4.4. (b) Any device that is a leaf of a group (room group or subgroup) may commit an Add whose every added leaf validates against the reference roster and whose result satisfies roster equality. (c) Roster equality tolerates pending adds: the leaf set equals the reference roster minus devices with no leaf yet, and every leaf absent from the roster, old-key leaves included, is removed (answers MLS Q7). `kp.fetch` opens to devices that share a group with the target, for `current` packages, under the per-device rate cap plus a new per-fetcher cap; `rekey` packages stay admin-only. The admin route stays the primary rekey path; any device of a group may complete it there. Leaf replacement, GroupContextExtensions and ReInit stay admin-only. | The roster already fixes which leaves may exist, so the admin-only Add rule added only a second guard, at the price of groups that could not commit at all. A compromised device that is not an admin gains timing, choice among published packages and the ability to send Welcomes, which allow denial of service against specific devices but not admission of an unlisted device or new plaintext (MLS 4.4). Open: dead leaves in groups with no admin, and fork detection for joiners. | MLS 4.2, 4.3, 4.4, 6.4, 10, 11; keys 4.1, 5, 6.6; enrollment 4, 5.1 |

The user decided on 2026-10-29 ("Decisions, round 8"), after the I-5 and I-6 fold implementation:

| # | Question | Decision | Rationale | Applied in |
|---|---|---|---|---|
| R8-1 | Dead leaves in groups without an admin device | The affected device signs `device.leaf.repair.requested {memberId, deviceId, group: {scope, generation}, keyPackageRef}`; any leaf of the group may then commit the leaf replacement with exactly that KeyPackage. Signed only by the device itself; open 24 h; one per group per hour and 8 per device per 24 h; cancelled when the device leaves or rekeys. | Closes the round-7 gap without opening leaf replacement to every device: the device chooses when and with which package, the committer only executes. A holder of one device's keys can only replace that device's own leaf, visibly and at a bounded rate. | room log 4.0, 4.3, 4.6, 5, 6.6; MLS 4.3, 4.4, 4.5, 6.1, 6.4, 9, 10 (test 14); signatures 3.2, 9.2 |
| R8-2 | Joiner fork check | Every MLS message carries `epochAuth`, a hash of the MLS `epoch_authenticator` of the epoch it is sent in; devices that process an Add commit send a `log.witness` within 30 s. The joiner compares; a mismatch on a message it cannot decrypt raises `epoch_fork` and it refuses to send; a mismatch on one it can decrypt is `epoch_anchor_mismatch` against the sender; no confirmation within 5 min is `epoch_unconfirmed`. | Existing anchors (commit `bodyHash`, epoch number, roster, log head) do not depend on epoch secrets, so they cannot reveal a fork; the authenticated-data channel and the log are reused. | MLS 4.4, 5, 5.1, 9, 10 (test 13); room log 5, 6.6; signatures 3.3, 9.2 |
| R8-3 | Keys retired before a re-fold | Never return to use, host keys included, even when the re-fold voids the statement that retired them. Devices whose recomputed keys are retired leave the roster; host keys keep their positional table, and a host key, endpoint or lane offer whose installing statement is suspect or void stays in use but **uncertified** (grants refused, alert) until a valid admin rotates it. Recovery is a fresh statement by a valid admin key or R. | A retired key may already be deleted, handed to a thief, or acted on by sessions and KeyPackage pools; bringing it back would also break `KeyChange.old` as a version. | room log 4.6, 5, 5.1 (steps 4, 7, 9), 6.6; keys 2, 4.3, 4.5, 6.4, 6.6; identity 5.2 |
| R8-4 | Revocation nesting and re-fold cost | Nesting depth (positional) at most 8, else `revocation_too_deep`. The re-fold is a fixed point over flat passes (at most 9), each linear in the chain; no recursive replay. | The I-6 recursion replayed the chain once per earlier revocation, recursively, which is exponential in the number of revocations. | room log 5, 5.1 (steps 3, 8) |
| R8-5 | Points the I-5 and I-6 code decided where the spec was silent | Written as rules (list below). | The fold is the specification members run; silent points must not depend on one implementation. | room log 4.1 to 4.4, 5, 5.1, 5.2; identity 6.4; keys 4.3, 4.5 |

R8-5, the rules now written into the specs:

- I-5: a device may revoke only a link created by a device of its own member, and never an invite (room log 4.2); `enrollment.closed` reasons are exactly those of `enroll.closed` (room log 4.2); lane `visibility` is `"room"` or `"team"` (room log 4.4); the fold records each entry's `epoch` and does not check it, even with R8-2, because R8-2's checks use the epoch inside the MLS message (room log 5); lane statements need a lane that exists and is not closed, lane lists in memberships and invites are not checked against the lane table, and an admin key acts with role `admin` (room log 4.1, 4.4).
- I-6: a host key is rotated before it is revoked; the revoking key's authority start bounds `host.key.revoked` as it bounds `admin.key.revoked`; an admin key that is already rotated out or removed may be revoked once; a device id is reserved from its `device.added`; `device.added` names a link of the same member, and one link adds one device; `member.device.replaced` cancels the removed devices' requests; a closure proposal is void once its proposer's key is rotated, removed or revoked, and the confirmer must be valid at the proposal by its own first valid position; a veto blocks both automatic and admin approval; a new key may not equal any key currently in use in the room (room log 4.1, 4.3, 5, 5.1, 5.2; identity 6.4; keys 4.3, 4.5).
- **R8-5a, proposed amendment (needs confirmation, section 8 item 7).** The I-6 choice "nobody may revoke the last active admin key" is changed to "an admin key may not; R may". With R8-3, an honest admin key revoked by a thief stays retired after R revokes the thief, so R's revocation could otherwise be refused for leaving no admin key, and a thief who keeps revoking each fresh admin key R adds would block R for good. An admin revoker should not be able to trigger the rule in practice, because its own authority start keeps the statement that installed it out of the revoked range; the fold still checks it. Applied in room log 5 and 5.1 step 4, keys 4.3 and 6.6, and in the fold.
- Changed behaviour from the I-6 implementation, as consequences of R8-3: R's precedence no longer restores the honest admin's key (R adds a fresh one); a device removed by a suspect statement, or whose rekey approval is suspect, no longer returns (keys 6.6 step 5 rewritten); an admin key whose revocation became suspect stays retired but may be revoked again, once.

## 8. Open questions

Each document lists its own. These need the user or a test before implementation:

1. **Blocker: native keyring packaging** (identity Q3). Does Paseo's plugin compiler and installer keep `@napi-rs/keyring` external and install the right platform package? Until tested, the no-native CLI path and the fallback file carry every platform.
2. **Untested platforms** (identity Q6, 7.9): macOS, native Windows, WSL, Docker, and every no-native CLI backend.
3. **Org policy profiles** (identity Q7): format, distribution, and whether members can verify that a room was created under one.
4. **License of `paseo-rooms`**: `plugin/package.json` declares none. Needed before vendoring Apache-2.0 code is released (enrollment 3.2.1).
5. **SAS word format** (enrollment Q2) and **trust on first use** for low-stakes rooms (enrollment Q3, proposed: no).
6. **ts-mls rekey behaviour** (MLS Q6, test 11): resolved by Spike A and decision R6-1 (admin route). The subgroup gap and MLS Q7 are resolved by R7-2. The two gaps left after round 7 (dead leaves without an admin, a joiner's forked epoch) are specified by R8-1 and R8-2; whether ts-mls 1.6.4 exposes `epoch_authenticator` through its public API is not yet checked (MLS 10, test 13).
7. **Confirm the round-8 amendment R8-5a** (section 7): only R may revoke the last active admin key. It follows from R8-3, but it reverses the I-6 choice "nobody may revoke the last active admin key".

## 9. Verification still required before implementation

| Item | Status |
|---|---|
| Noise IK against cacophony IK vectors | **done** 2026-10-29: generator engine and vendored Paseo + IK prototype match 6 of 6 messages (signatures 9.3). The production module must repeat it in its tests. |
| Noise NK, Paseo relay 0.13.2 unchanged, against cacophony NK | **done** 2026-10-29, 6 of 6 messages |
| RJCS against an RFC 8785 library in a second language | not done |
| ts-mls 1.6.4: PrivateMessage commits and pre-decryption access to authenticated data | **done** 2026-10-29, Spike A case (e): yes to both (MLS Q2) |
| Paseo 0.13.2 connected-host link: a ping the destination side can send | not checked (grants Q2) |
| Keyring access on Linux under Paseo's runtime | done (keyring spike) |
| Native keyring packaging through Paseo's plugin compiler and installer | **not checked; blocker** (identity Q3) |
| macOS, Windows, WSL, Docker behaviour of key storage, file protection and durable writes | not checked (identity 7.9) |
| Independent review of this directory | **done** 2026-10-29 (`plugin/review/identity-v2-review.md`); revisions in section 10 |
| Narrow re-review of the revised sections and the new vectors | **done** 2026-10-29 (`plugin/review/identity-v2-rereview.md`); revisions in section 10 |
| Targeted check of the R-1 to R-12 fixes (decisions round 4, item 4) | pending |
| Vectors regenerated after the re-review revision, two runs byte-identical | **done** 2026-10-29 (signatures 9.1) |
| ts-mls 1.6.4: public access to `epoch_authenticator` for the joiner's epoch check (R8-2) | not checked (MLS 10, test 13) |
| Vectors regenerated after the round-8 revision, two runs byte-identical, existing values unchanged except `mls.authenticatedData` and one `about` note | **done** 2026-10-29 (signatures 9.1) |
| ts-mls 1.6.4: credential change in an UpdatePath (device rekey), Welcome during a pending rekey, which leaves reach `validateCredential` | **done** 2026-10-29, Spike A (MLS 10, test 11): receive side accepts and validates; public send API cannot; Welcome needs `prevSig` only if built over an unapplied rekey, which R6-1 prevents. The admin route itself (Remove plus Add, adjacent sequencing) is **not run**; MLS test 10 covers it |

## 10. Changes from review

The independent review (`plugin/review/identity-v2-review.md`, 2026-10-29) raised findings S-1 to S-23. This table maps each to its resolution. "As suggested" means the review's suggested fix was applied. Where the fix differs, the reason is given. Every finding was addressed; none was left open. The revised formats are covered by regenerated vectors (`signatures-and-encoding.md` section 9). None of this is implemented or tested beyond the vector generator.

| ID | Sev | Resolution | Where |
|---|---|---|---|
| S-1 | high | As suggested: every statement carries `base: {seq, hash}`; the fold requires `base.seq < entry.seq` and a matching hash, rejects a repeated `bodyHash`, and checks `prevRole`, `prevLanes`, `prevPolicyHash`, `prevShow`, `prevServerId`, `prevMemberIds` and `KeyChange.old`. Removed, rotated and revoked admin keys go on an admin-key denylist. Vectors and fold checks added (`log.foldChecks`). | room log 2, 4, 5; identity 6.2; keys 2 |
| S-2 | high | Per decision R3-1: 24 h hold with veto for automatic device adds and rekeys; young devices cannot auto-add; a device can remove only itself; compromise removal offers to cascade to devices it added. **Differs:** a veto cancels the add and opens a "device conflict" for an admin to resolve, instead of removing the requester as compromised, because removing the requester would let one device remove another, which R3-1 forbids. `member.left` is limited to a member's only device for the same reason. | identity 6.2, 6.3; keys 4.1, 6.1, 6.3; room log 4.3, 5 |
| S-3 | high | As suggested: new enrollment section 5.6 pins `h`, `Nm`, `Nh` and `pendingId`; the member accepts only a byte-identical pending and never re-reveals into another; the host never issues a new `Nh`; the member persists `Nm` before its first request. Tests listed. | enrollment 5.6, 7.3, 9 |
| S-4 | medium | As suggested, with the count from decision R3-4: 3 abandoned attempts burn the invite (`reason: "abandoned"`); the admin's card shows the count; the README claim now says at most 3 × 10^-6 per invite. | enrollment 5.4, 6.1, 6.3, 7.1 |
| S-5 | medium | As suggested (first option): the log and MLS carry `inviteRef` and `linkRef`, hashes of the ids. The 5.4 sentence and the README residual row are corrected. | room log 4.2, 4.5, 7; enrollment 2.1, 5.3, 5.4 |
| S-6 | medium | As suggested: a commit must name the last roster-changing entry before its own entry; committer role is judged there; the host answers `stale_roster`. | MLS 4.2, 4.3, 6; enrollment 10 |
| S-7 | medium | As suggested: `fork` only with an equivocation proof; otherwise `unverified_head_claim`, attributed to the sender, which stops nothing. | room log 6.2, 6.3, 6.6 |
| S-8 | medium | Revocation cut-offs are log positions (`fromSeq`) with the suggested bounds; suspect statements have no effect, through a defined re-fold; recovery-key revocations take precedence. `room.closed` per decision R3-5: recovery key or a second admin, not reversible. **Differs:** `admin.reaffirmed` is removed; admins re-issue what they keep, because re-applying an old statement conflicts with the S-1 replay rules. | room log 4.1, 5.1; keys 3, 6.6, 6.8; identity 5.2 |
| S-9 | medium | As suggested: role downgrades are access-reducing; the lane endpoint requires `claims.role` to equal the roster role. | grants 4, 7.1; room log 4.3 |
| S-10 | medium | As suggested: a new session supersedes the old one only after key confirmation (first valid transport frame). | enrollment 3.5 |
| S-11 | medium | First option of the suggestion: device rekey is an UpdatePath carrying a new credential, validated against the post-approval roster; an admin Remove plus Add is the fallback. **Superseded** by decision R6-1 after Spike A: the admin route (Remove plus Add) is the only rekey path, because the public ts-mls API cannot send the UpdatePath. | keys 4.1, 5; MLS 4.1, 4.3, 4.4, 10, Q6 |
| S-12 | medium | Second option: identity 5.3 now states that UI confirmation is a usability guard, not a boundary against same-user code; the README residual for A2 says so. A typed code would not help, because same-user code can read it through the same RPCs. | identity 5.3; README 4.2 |
| S-13 | medium | As suggested: new identity section 6.4 with `DeviceLinkPayload`, `LinkRecord`, frames for device A (`link.request`, `link.nonce`, `link.reveal`, `link.confirm`), host states (including `held`), and `device.added` contents; `KeyChange.old` is nullable in three listed cases; `prl2.`, `device.added` and `device.add.approved` vectors. **Addition:** the confirming device A, not the host, chooses the confirmer nonce. Without this a malicious host could choose its own device's values to match the SAS and get A to sign its keys. | identity 6.4; keys 2; enrollment 5.2, 7.2, 7.3 |
| S-14 | low | As suggested: `Roster.seq` is the last roster-changing entry; AAD and witnesses use it; vector `log.rosterAfter` and `mls.authenticatedData` show a non-roster entry in between. | identity 6.1; room log 5; MLS 4.2, 5 |
| S-15 | low | As suggested: log entries are judged by position only; time windows remain for grants. | keys 3, 4.5; room log 3; signatures 8 |
| S-16 | low | Per decision R3-2: per-lane `showNames`, changed only by the lane owner's device (`lane.names.changed`); policy `projectNames = "hidden"` lets admins force hiding. | grants 13.2; identity 5.1, 5.2.1; room log 4.4 |
| S-17 | low | Per decision R3-3: `policy.grantTtl` fixed at 12 h; only an org policy can shorten it; no per-invite value. | grants 5; identity 5.2.1; enrollment 2.1 |
| S-18 | low | As suggested: (1) grants 7.1 cites MLS 6.3; (2) error frames have an explicit per-code field list; (3) `persist_failed` added, `grant_expired` example replaced by existing codes, `stale_base` and `stale_roster` added; (4) the invite uses the `{alg, kid, pub}` key shape; (5) lane endpoint `serverId`s use `rle_`; (6) `kekId` defined as `kek_` + 32 hex; (7) `authoritySeq` removed from `session.hello`; (8) enrollment 5.6 written. | enrollment 2.2, 3.6, 4.1, 5.5, 5.6, 10; grants 2, 7.1, 13.1; identity 7.2, 8 |
| S-19 | low | As suggested: all listed vectors added; `seq` 0 is the creator's admission; the generator exits with a clear message below Node 20 (checked with the system Node 18.19.1). | signatures 9; `vectors/` |
| S-20 | low | As suggested, item by item: explicit file modes instead of umask; SDDL instead of localized `icacls` text; junctions and reparse points refused; migration rename retried on Windows; the redacted path form is a fixed logical string and Windows paths are matched. **Differs** in two places: stale log locks are detected by a heartbeat on the lock file's modification time instead of process start time, and denylist pruning counts 24 h of process monotonic time since load instead of using a boot identifier. Both avoid per-OS process queries and wall-clock-derived boot times. | identity 7.8; grants 7.3, 8, 13.2; migration 2.2, 2.3 |
| S-21 | low | As suggested: pre-auth budgets count only statics not in the roster; active devices have their own budget; the lane link bucket counts only failed attempts. | enrollment 5.4; grants 11 |
| S-22 | low | As suggested: RJCS rejects the keys `__proto__`, `constructor` and `prototype`; three reject vectors added. | signatures 2.1, 9.2 |
| S-23 | low | As suggested: a standalone lane gateway fetches the allowlist before accepting links and fails closed after 60 s without host contact. | grants 7.2 |

### 10.1 Changes from the re-review

The narrow re-review (`plugin/review/identity-v2-rereview.md`, 2026-10-29) found six of the S findings partly open and raised R-1 to R-12. The user decided its three questions in round 4 (section 7). This table maps each to its resolution. "As suggested" means the re-review's fix was applied. The revised formats are covered by regenerated vectors. Nothing here is implemented or tested beyond the vector generator, and no ts-mls behaviour was executed.

| ID | Sev | Resolution | Where |
|---|---|---|---|
| R-1 | high | Per decision R4-3: `ver` (log position of the last change) replaces every `prev*` value; `KeyChange.old` stays, because retired keys can never return; strict forward-base rule per producer key; outstanding statements and `producer.fence`. Vectors: a held statement killed by the forward rule and an ABA statement killed by its version (`log.foldChecks`). | room log 2, 4.0, 4, 5; keys 2; enrollment 10; signatures 3.2 |
| R-2 | high | As suggested: device A sends at most 1 `Nc` per pending, keeps at most 1 open pending, and sends at most 3 `Nc` per link, then burns it locally; counters and pinned inputs are sealed before `link.nonce`; changed inputs for a known `pendingId` abort; new frames `link.abort` and `link.closed`; required test. | identity 6.4; enrollment 4, 5.4 |
| R-3 | high | Per decision R4-1. **Differs** from suggestion (a): independence is a different lineage root, because "not descended from the proposer" still lets one stolen key close with two keys it added; the first recovery key needs two independent admins when the room has two or more lineages (decision says "more than one admin"; reason in R4-1). (b) and (c) as suggested; (d) adopted as default-on `closeDelay` of 24 h. README R3-5 and keys 6.8 corrected: a single admin can close by first adding a recovery key. Vectors: `log.closure`, `log.refold.rejectRevocationBeforeStart`. | room log 4.1, 5.1, 5.2; keys 4.3, 4.4, 6.6, 6.8; identity 5.2, 5.2.1, 5.4 |
| R-4 | medium | Both suggested options: the member records every session's `h` (`sentH`) before sending `enroll.request`, and `enroll.pending` carries the pinned `h`; the member accepts only an `h` it recorded. Test added. | enrollment 5.2, 5.6, 7.3 |
| R-5 | medium | First suggestion, with the second as fallback: the reference roster keeps `prevSig` from rekey approval, and rule 6 accepts it for unchanged leaves (all Welcome leaves but the joiner's); the adapter decides "unchanged" by byte comparison, so the rule holds whatever ts-mls does; the 4.1 sentence on commit signers is corrected; continuity and role checks read the sender's leaf in the callback. **Not verified:** the expected ts-mls behaviour is from the re-reviewer's static reading; offline test `mls-rekey-updatepath-welcome` must run first, with stated fallbacks. **Superseded** by decision R6-2: Spike A observed the expected receive-side behaviour, but also that the "unchanged" rule let a stale UpdatePath through `prevSig` and that the callback never sees the UpdatePath leaf. Under the admin route no Welcome is built over an unapplied rekey, so `prevSig` is removed and continuity is checked after processing. | MLS 4.1, 4.2, 4.3, 4.4, 10, Q6; keys 4.1 |
| R-6 | medium | As suggested: ownership check before every append, atomic takeover by rename, 30 s wait, lock removed on clean shutdown; residual window stated. | grants 7.3 |
| R-7 | low | As suggested: a revocation whose re-fold changes the roster sets `rosterSeq = r`. Vector `log.refold`. | room log 5, 5.1 |
| R-8 | low | As suggested: removing or rekeying a requesting device, or removing the member, cancels its pending requests in the fold; a device cannot remove itself when it is the last one (it signs `member.left`); an admin may, leaving a member with 0 devices (documented 0..8), restored by `member.device.replaced` or removed. Vectors in `deviceLink.chain.cases`. | room log 4.3, 5; identity 6.1, 6.2, 6.3; keys 6.1, 6.3 |
| R-9 | low | As suggested: `unknown_base` with `head`, and a truncation check for the producer; `stale_base` returns interactive actions to the confirmation dialog; automatic ones recompute. | room log 2, 6.4; enrollment 10 |
| R-10 | low | As suggested: a statement with `ref` or `proposal` needs `base.seq` at or after the entry that carries it. Vector regenerated (`deviceLink.deviceAddApproved` now has `base.seq` 5, after the request at 5), plus a rejected case. | room log 5; vectors |
| R-11 | low | As suggested: held time is persisted per denylist entry, plus a 30-day wall-clock backstop; the Windows path check compares after case-folding and drive-letter normalisation. | grants 8; identity 7.8 |
| R-12 | low | As suggested: vectors for the re-fold, closure, veto and conflict resolution, recovery key from `null` (format only, not folded), and the ABA case; the generator prints the file's SHA-256. | signatures 9; `vectors/` |
| Sole stolen device (residual 2) | | Per decisions R4-2 and R5-3: 72 h hold for adds and rekeys requested by a person's only device, org option `soleDeviceChange = "admin"`, a marked owner notification, and user guidance to tell an admin within the hold, which cancels the add or rekey. Vector `deviceRekey` covers the rekey hold. | identity 5.2.1, 6.3; keys 4.1; room log 4.6, 5; vectors |

Partial S findings from the re-review:

| ID | Remaining gap | Closed by |
|---|---|---|
| S-1 | No freshness bound for a signed, unsequenced statement; ABA on `prev*` values | R-1, R-9 |
| S-3 | Restart in state `keys` left the member without the pinned `h` | R-4 |
| S-8 | Unbounded R `fromSeq`; single-key closure bypass; roster position after a re-fold | R-3, R-7 |
| S-11 | Welcome fails while a rekey is approved but not committed; ts-mls behaviour unverified | R-5, then R6-1 and R6-2 (test 11 run as Spike A; admin route makes approval and application adjacent) |
| S-13 | Attempt limits counted only by the host | R-2 |
| S-20 | Heartbeat lock without ownership check or atomic takeover; pruning may never happen | R-6, R-11 |

### 10.2 Changes for decision round 8

Round 8 (2026-10-29) followed the I-5 and I-6 implementation of the fold. Each item maps to the sections it changed.

| Item | Change | Where |
|---|---|---|
| R8-1 dead-leaf self repair | New statement `device.leaf.repair.requested` (device itself, own leaf; scope check; 1 per group per hour, 8 per device per 24 h; open 24 h; cancelled on removal or rekey); leaf replacement by any leaf when it carries out an open request with the named KeyPackageRef; `kp.fetch` by `ref`; abuse analysis; alert `leaf_replaced_unrequested`; MLS test 14; vector `deviceLeafRepair` and `statements.deviceLeafRepairRequested` | room log 4.0, 4.3, 4.6, 5, 6.6; MLS 4.3, 4.4, 4.5, 6.1, 6.4, 9, 10; signatures 3.2, 9.2; fold (`statements.ts`, `fold.ts`) |
| R8-2 joiner fork check | `epochAuth` in every message's authenticated data (new hash label `h:mls-epoch-auth`); witness after an Add commit; joiner check with `epoch_fork`, `epoch_anchor_mismatch`, `epoch_unconfirmed` and a 5-minute timeout; existing anchoring found unsuitable, its channel reused; MLS test 13; vectors `mls.epochAuth`, `mls.authenticatedData` (changed) | MLS 4.4, 5, 5.1, 9, 10; room log 5, 6.6; signatures 3.3, 9.2 |
| R8-3 retired keys never return | Re-fold step 9; positional host-key table; `uncertified` host keys, endpoint and lane offers; devices with retired keys dropped; R precedence re-adds a fresh admin key; vector `log.noRevival` | room log 4.6, 5, 5.1, 6.6; keys 2, 4.3, 4.5, 6.4, 6.6; identity 5.2; fold (`refold.ts`, `state.ts`) |
| R8-4 nesting cap, linear re-fold | Positional nesting depth at most 8 (`revocation_too_deep`); fixed point over at most 9 flat passes; vector `log.revocationDepth`; unit test counting steps | room log 5, 5.1 steps 3 and 8; fold (`refold.ts`, `fold.ts`) |
| R8-5 silent points | The four I-5 and ten I-6 choices as rules, with amendment R8-5a (only R may revoke the last active admin key) | room log 4.1 to 4.4, 5, 5.1, 5.2; identity 6.4; keys 4.3, 4.5; README section 7 |
| Vector notes | `about.notes` now describes `deviceRekey.vetoed` and `deviceRekey.soleDeviceChangeAdmin` (added in I-6), and signatures 9.2 lists both | signatures 9.2; `vectors/` |

### 10.3 Changes after I-7

A fix pass after the I-7 implementation (room host core), 2026-10-29.

| Item | Change | Where |
|---|---|---|
| Unsignable statement type | `grant.suspected_theft` renamed to `grant.suspected-theft`: its context `stmt:grant.suspected_theft` was outside the context alphabet, so no key could sign it. The alphabet is unchanged; type names now match `^[a-z0-9.-]+$`, the fold rejects a type outside it with `unsignable_type`, and a unit test checks every catalogue type | room log 4, 4.4, 4.6; signatures 3.2; grants 6.1, 6.3, 6.4; keys 6.2 |
| Fold failures | Every failure of the fold is a `FoldError` with a reason: `bad_genesis` (seq -1), `unsignable_type`, and `internal_error` for an exception no check anticipated | fold (`fold.ts`, `state.ts`) |
| Recovery code | `prk2-` + base32 of seed and a 3-byte checksum `H("recovery-code", seed)`, 14 groups of 4; distinct errors for a typo and a wrong key; new hash label; vector `recoveryCode` | identity 5.4, 5.4.1; signatures 3.3, 9.1, 9.2 |
| I-7 storage | `host/<roomId>/genesis.json` with its hash pinned in the sealed host key file; `admin/<roomId>/state.sealed` for outstanding admin statements; creator device keys in `member/rooms/<roomId>/keys.sealed`; a final log line that parses but fails verification is corruption; `hts` never decreases | identity 7.1; room log 3, 8.1 |
