# Hardening plan: merged findings from the M1 reviews

- **Date:** 2026-10-28
- **Sources:**
  - `protocol-review.md`: findings P-1 to P-29, read-only design review.
  - `code-review.md`: findings C-1 to C-16 plus the Room Profile audit. The attack tests were **not run**.
- **Status:** all findings were derived from reading the specs and source. None was demonstrated at runtime.
- **Duplicates are merged:**
  - P-5 = C-1
  - P-15 = C-7
  - P-23 = C-8
  - P-12 = C-9
  - P-20 ≈ C-15
  - P-17 ≈ C-4
  - P-18/P-19/P-26 ≈ C-3/C-2/C-6/C-16

## Correction to earlier claims

**The M1 room-agent guard is not an isolation boundary.** M1 removes Paseo's MCP tools by shadowing the `paseo` entry (P-5, C-1). But a forked room agent runs as the owner's OS user. A shell-capable provider can therefore do all of the following:

- run the `paseo` CLI
- read `~/.paseo/local-credential`, which is 0600 but owned by the same user (checked)
- read room keys
- connect to the daemon port
- load other MCP servers

Earlier summaries said room agents "can't reach your other agents". That held only for the MCP route. M1 rooms are still **watch-only**: only the owner prompts the fork, so this is not exploitable by members today. It **is** a hard blocker for any feature that lets non-owners prompt an agent or seats agents in chat.

## A. Identity and key model ("identity v2"). Blocks M2.

These are format decisions that MLS will freeze. They are cheap now and expensive later.

| Item | Findings | Change |
|---|---|---|
| A1 | P-1 | Enrollment binds to the invite holder only. Add out-of-band confirmation: a short authentication string the owner and member compare. With a standalone host, use SSO attestation instead. |
| A2 | P-3, P-29 | Use a separate **owner/admin signing key**, not the host key. The MLS authentication service accepts only roster entries signed by that admin key. Members reject commits whose roster differs from the signed membership. |
| A3 | P-4, P-14 | Membership unit becomes **room member (person) → devices**, not lane × daemon. Use **per-room member keys** (unlinkable across rooms) and multi-device. |
| A4 | P-8 | Long-lived member and gateway sessions use **mutual Noise** (static keys on both sides), or signatures bound to the Noise handshake hash. |
| A5 | P-10 | Key rotation and compromise recovery for every key. Signed key-change events. Verification against multiple key ids. |
| A6 | P-11, P-22, C-14 | Domain-separated signature contexts per message type. One specified canonical encoding with test vectors. Full public keys or 256-bit ids, never 64-bit. Strict base64url. |
| A7 | P-7 | Room log: per-producer signatures, consistency checks between members (to detect equivocation and truncation), anchored to MLS epochs. |
| A8 | P-2 | Key storage at rest: same-user processes can always read plaintext files. **Needs a decision** (see the decisions section). |

## B. Lane endpoint and Room Profile. Fix in this pass.

| Item | Findings | Change |
|---|---|---|
| B1 | C-2 | Build the upstream `hello` from scratch. Never spread viewer fields into it. Use a fixed, gateway-chosen clientId per route. Use the protected mode only. |
| B2 | C-3, P-18, P-19, P-26, C-6, C-16 | Add **field-level** allowlists for outbound descriptors and snapshots: redact absolute paths, git remote, PR info, script ports and proxy URLs, parent-agent data, system prompts and the owner serverId. Sanitize error text. Allowed inbound messages get field allowlists too. |
| B3 | C-4, P-17 | Resource caps: connections per lane, links per grant, routes per link, frame size, and bounded queues and maps. |
| B4 | P-21 | Document that a grant admits every client of the member daemon. This is acceptable by design. |

## C. Agent isolation. Decide now, implement before Phase 2 (steer or seated agents).

| Item | Findings | Change |
|---|---|---|
| C-iso1 | P-5, C-1 | **Lanes that anyone other than the owner can prompt must run in an OS-level sandbox.** Options: a separate OS user, a container or runner node, or bubblewrap/firejail. Inside the sandbox there must be no access to `~/.paseo`, the `paseo` CLI, the daemon port or the owner's MCP configs. The MCP shadow stays as defence in depth only. |
| C-iso2 | P-6 | Other plugins can re-add tools (hook order is by plugin id; 0.14 adds new hooks). Verify the ordering on 0.13.2, add a tripwire that re-checks the final config, and document the plugin trust model. |
| C-iso3 | P-28 | Replace the provider denylist with an allowlist of providers verified to respect the guard. |

## D. Robustness and minor issues. Cheap ones in this pass, the rest later.

| Item | Findings | This pass? |
|---|---|---|
| Stolen grant defers the victim's rotation | P-9 | Yes: rotation is not suppressed by routes from unknown link instances |
| Denylist pruned by wall clock; revocation persisted before enforcement, not durable | P-12/C-9, P-13 | Yes: enforce then persist with fsync; prune only after `exp` plus a margin |
| Invite burn by bad tokens | P-15/C-7 | Yes: per-token attempt limits, not per lane |
| Membership oracle before authentication | P-23/C-8 | Yes: verify the signature first |
| Member trusts the invite's relay and TLS setting | P-20/C-15 | Yes: require `useTls`; allowlist known relays or confirm with the user |
| Relay serverId eviction | P-16 | Later (needs a relay-level fix); document |
| Clock skew, downgrade guards, log completeness | P-24, P-25, P-27 | P-27 yes; others later |
| Log injection, non-atomic enrollment, torn log line, rotation timers after restart, archived lane agent | C-5, C-10, C-11, C-12, C-13 | Yes, all cheap |
| UI: confirmations on close lane, leave and revoke | ui-check/ui-notes.md | Yes; other UI notes later |

## E. Verification gap

The attack tests in the code review (task C) **did not run**. These are:

- fuzzing
- grant replay and forgery
- invite reuse
- concurrent enrollment
- restarts
- the flaky-enrollment loop
- the real environment of the fork process

The reviewer's tool use was halted by a safety stop while it was writing the attack script, and it did not retry. Partial, unrun scaffolding is in `review/attack/`.

**Proposal:**
1. Write the harness as plain, reviewable test code: a fuzzer for our own endpoint plus scripted negative tests against our own test daemons.
2. The user reviews it.
3. It runs only with the user's explicit go-ahead.

## Decisions needed from the user

1. **Key storage (A8).**
   - (a) Use the OS keyring (libsecret, Keychain) where available, and document that same-user malware is out of scope.
   - (b) Additionally recommend running room gateways and runners under a dedicated OS user.
   - (c) Use a passphrase.
   - Recommendation: **a + b**.
2. **Agent isolation (C-iso1).** Recommendation: **only sandboxed lanes can be prompted by non-owners.** Watch-only rooms may keep using owner-uid forks. Steering arrives together with a sandboxed runner node kind.
3. **Enrollment confirmation (A1).** Recommendation: a short authentication string for host-less rooms; SSO attestation once a standalone host exists.
4. **Attack-test harness (E).** Approve writing it for review.
5. **Scope.** Section A is a substantial "identity v2" redesign. Recommendation:
   - first, specs for A (reviewed again before code)
   - then B, D and the A implementation
   - then M2 on top

## Decisions (user approved, 2026-10-28)

1. **Key storage:** use the OS keyring where available, and document that same-user malware is out of scope. Recommend a dedicated OS user for room gateways and runners.
2. **Isolation:** only sandboxed lanes can be prompted by non-owners. Watch-only rooms may keep using owner-uid forks. Steering ships together with a sandboxed runner node kind.
3. **Enrollment confirmation:** a short authentication string for host-less rooms; SSO attestation once a standalone host exists.
4. **Attack tests:** write the harness as reviewable test code. It runs only after the user approves it.
5. **Order of work:**
   1. Identity v2 specs, then an independent review of them.
   2. The B fixes and the non-protocol D fixes, in parallel with the specs.
   3. The identity v2 implementation, together with the protocol-touching D fixes (P-9, P-15/C-7, P-23/C-8, P-20/C-15, C-10, P-27).
   4. M2.

## Decisions, round 2 (user approved, 2026-10-29)

- **Security test suite:** option 3. Write the routine modules now (restart persistence, the flaky-enrollment loop, read-only environment inspection, README, and `run.sh` safety gates). The credential-negative and resource-stress modules are written or approved by the user later.
- **Identity v2 questions:**
  1. A 6-digit SAS with commit-then-reveal.
  2. A new device is auto-approved when another device of the same person adds it, with a notice to the room. Admin approval is required when the person has no existing device, and orgs can require it always.
  3. A recovery key is offered by default and is optional; org escrow follows org policy.
  4. 12 h grants, rotated preferably when idle, with a forced rotation at 75%.
  5. Lane endpoint keys are rotated on removal only when the removal is flagged as a compromise.
  6. Stranding members who have been offline more than 30 days is acceptable, because they can be re-invited.
  7. Build Noise IK now on Paseo's existing, tested Noise module (vendored) or a maintained library, not from scratch. Request an upstream export.
  8. Run a short keyring spike.
- **Viewer errors:** viewers get generic error text, and owners keep full errors.
- **Project display names:** hidden from viewers by default, with an owner option to show them.

## Decisions, round 3 (user approved, 2026-10-29)

These answer the open questions in `identity-v2-review.md`, section 6.

1. **Device auto-approval brakes (S-2):** devices added automatically are held for 24 h, and the person's other devices can veto them during that time. A device can remove only itself; admins can remove any device.
2. **Project names (S-16):** only the lane owner can show names, and only for their own lanes. Admins can force names hidden.
3. **Grant lifetime (S-17):** fixed at 12 h. Org policy can shorten it but not lengthen it.
4. **Abandoned join attempts (S-4):** an invite is burned after 3 abandoned attempts.
5. **Room closure (S-8):** `room.closed` requires the recovery key or a second admin's signature. There is no window to undo a closure.

## Decisions, round 4 (user approved, 2026-10-29)

These answer the questions in `identity-v2-rereview.md`.

1. **Room closure (R-3):** the confirming key must be independent of the proposing key. Adding the first recovery key in a room with more than one admin needs two admins. Recovery-key revocations are bounded the same way as admin revocations. A 24 h delay between proposing and confirming a closure is on by default.
2. **A person's only device adds a second device:** the hold is 72 h instead of 24 h. Orgs can require admin approval instead.
3. **Settings versions (R-1):** each state-changing statement carries the version (log position of the last change) of the field it changes, instead of its old value. Each producer's `base` may only move forward.
4. **Process:** one revision pass for R-1 to R-6 and the low findings, then a targeted check that each R finding is addressed and the vectors regenerate (no further full review). The ts-mls questions (S-11, R-5) get offline unit tests early in implementation. Then the implementation plan.

## Decisions, round 5 (user approved, 2026-10-29)

Spec follow-ups from the final revision pass:

1. **R-3 deviations accepted:** a closure's confirming key must come from a different lineage root than the proposer's. A first recovery key needs two admins when the room has more than one lineage.
2. **Residual risk accepted:** in a room with no recovery key, a thief who wins the revoke race can install a recovery key and close the room. The mitigation is that recovery keys are offered by default. This is documented, not fixed.
3. **72 h hold also covers device rekeys** requested by a person's only device, not only device adds.

Implementation plan (`docs/design/implementation-plan-identity-v2.md`, milestones renamed I-1 to I-17):

4. **D-1:** local git repository with no remote; the current code is tagged as the M1 baseline.
5. **D-2:** use the development-only switch `PASEO_ROOMS_PROTOCOL=v2` until cut-over (I-15). It never ships.
6. **Keyring fallback:** if Spike B fails, the protected file backend is the default on Linux desktops, with a visible warning.
7. **MLS placement:** the MLS adapter is built in this plan (I-13). Real MLS chat stays in plugin milestone M2.
8. **Network:** live-relay test runs are approved once, when work reaches I-7 to I-10. Until then, tests stay offline.
9. **License:** Apache-2.0.
10. **Upstream requests:** held until Spikes A and B are done. Nothing is sent without the user's go-ahead.

## Decisions, round 6 (user approved, 2026-10-29)

After Spike A (the Spike A results (design research, not published)):

1. **Device rekeys in MLS use the admin route.** The admin daemon applies an approved rekey by removing the old leaf and adding the new KeyPackage, using only public ts-mls APIs. No fork of `createCommit`.
2. **Spec fixes from Spike A:** the device-continuity check runs after processing, not in the library callback; the `prevSig` exception applies only when joining (`joinGroup`); ts-mls ≥ 1.6.4.
3. **Upstream:** ask ts-mls for credential change through the public `createCommit` (held with the other upstream requests until the user approves sending).
4. **Next:** start implementation with I-1 and I-16 in parallel.

## Decisions, round 7 (user approved, 2026-10-29)

1. **`prevSig` removed entirely** (not limited to `joinGroup`), as the revised MLS spec has it.
2. **Subgroups and pending adds:** options (b) and (c) of `mls-integration.md` section 4.4. Any scope device may commit an Add of a leaf the signed roster already contains (b), and roster equality tolerates pending adds that have no leaf yet (c, answers Q7). `kp.fetch` opens to scope devices, still under the per-device rate cap.
3. **Test budget:** up to 20 small model calls for e2e runs on test daemons before asking again. (The current e2e suites create agents without a prompt and make no model calls.)

## Decisions, round 8 (user approved, 2026-10-29)

1. **Dead leaves:** the affected device may sign a request for its own leaf replacement, which any leaf of the group may carry out. New signed statement type.
2. **Joiner fork check:** after joining, a device compares a hash of its epoch authenticator with the value other members anchor in the room log, and raises an alarm on mismatch.
3. **Retired keys never return to use,** including host keys, even when a re-fold voids the rotation that retired them. The room then needs a fresh statement from a valid admin.
4. **Revocation nesting is capped** in the spec (for example, depth 8), and the implementation's re-fold cost must grow linearly, not exponentially.
5. **Silent points:** the four I-5 choices and the other ten I-6 choices are written into the specs as rules.

## Decisions, round 9 (user approved, 2026-10-30)

1. **R8-5a confirmed:** an admin key may not revoke the last active admin key; the recovery key may, and then adds a fresh admin key.
2. **Proposal (a):** the host refuses an `endpoint.rotated` naming an endpoint it does not serve.
3. **Proposal (c):** after admission, the member checks every pre-admission authority-chain entry against the fetched log; a mismatch is equivocation evidence.
4. **Joiner confirmation:** a joiner's epoch is confirmed by matching anchors from min(2, number of other leaves) other leaves.
5. **Prompt Add:** the admitting admin daemon adds a newly admitted device to the room group at once; the repair path is only the fallback.

## Decisions, round 10 (user approved, 2026-11-02: "go with your recs")

1. **Publishing:** a GitHub repository, with the plugin installed from Git; npm later. The user creates the repository. Nothing is pushed without the user's go-ahead. (A private repository first was superseded by round 11: the repository is public.)
2. **Paseo version range:** `>=0.13.2 <0.14.0`, plus the R2.7 compatibility guard.
3. **Pilot platforms:** Linux only for v0.2. macOS and Windows stay marked untested.
4. **Upstream requests:** draft the upstream feature requests for the user's review. Nothing is sent without approval.
5. **Attack harness:** draft the remaining modules (credential-negative and resource-stress) as reviewable test code against our own test daemons only. They are not run until the user approves.
6. **Joiner witness:** joiners also send `log.witness` after processing their Welcome.
7. **v2 UI check:** the user runs it with `ui-check/up-v2.sh` before a labmate installs the plugin.

## Decisions, round 11 (user, 2026-11-02)

1. **License:** Apache-2.0 for the whole plugin (the user first chose MIT, then reverted to Apache-2.0 the same day). This matches the vendored Noise code from Paseo, which keeps its own NOTICE.
2. **Commit email:** kept as is in the public history.
3. **Public repository:** polished for installing and using: no local-development paths, portable scripts, user-facing README, cleaned history. Push only after the user reviews it.
