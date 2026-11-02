# Reliability and environment-inspection tests

These are routine tests for the `rooms` plugin, run against two disposable test daemons. They cover the "restarts", "flaky-enrollment loop" and "real environment of the room agent's process" items from `review/HARDENING-PLAN.md` section E, as approved in "Decisions, round 2". Since the identity v2 cut-over the room agent is the shared live agent (no fork lanes).

Modules 4 and 5 are the defensive security modules of section E, drafted under decisions round 2 option 3 and round 10 item 5: protocol-level negative tests for credentials (module 4) and bounded load against the documented limits (module 5). They target only the owner test daemon's own endpoints, over a loopback relay. Fuzzing and concurrency races remain **out of scope**.

**Status:** modules 1 to 3 were ported to the identity v2 RPCs (`rooms.v2.*`) on 2026-11-01; modules 4 and 5 were written on 2026-11-02. All are typechecked. **None has been run.** Running needs explicit approval: `run.sh` refuses to start without `--i-reviewed-this`. Modules 4 and 5 in particular are for the owner's review before any run.

## How to run

```bash
cd plugin
bash test/reliability/run.sh --i-reviewed-this
bash test/reliability/run.sh --i-reviewed-this --only enrollment-reliability
bash test/reliability/run.sh --i-reviewed-this --only credential-negative
bash test/reliability/run.sh --i-reviewed-this --only resource-stress
KEEP_HOMES=1 RL_ENROLL_CYCLES=5 bash test/reliability/run.sh --i-reviewed-this
```

Modules run in this order: environment inspection, enrollment, restarts, credential-negative, resource-stress. Restarts go after the other routine modules because they are the most disruptive. Before the first security module, run.sh starts the loopback relay and restarts the owner test daemon with it (see "Loopback relay" below). Each module is a `node:test` file run on the Node bundled with Paseo through tsx. One failing module does not stop the others. The exit code is non-zero if any module, the cleanup or the secret scan fails.

To typecheck: `npx tsc -p test/reliability/tsconfig.json`. The root `npm run typecheck` also covers these files.

## Shared steps (`lib.ts`)

- **Room with a lane:** `rooms.v2.room.create` (no recovery key: a throwaway room), then `rooms.v2.lane.create` on the parent agent (share-live). Both endpoints must be online on the relay.
- **Interactive admin actions** (invite, lane, admit, remove) go through `rooms.v2.admin.prepare` and its one-time `confirmToken`, as the UI does.
- **Enrollment** is the real SAS flow: `join.preview` (the relay must be trusted by default; the suite never grants relay trust), `join.start`, both sides show the 6-digit SAS, a **TEST-ONLY programmatic comparison** stands in for the people comparing by voice (the digits must be equal and well-formed, and are never logged; a mismatch sends `match: false` and fails the step), `join.confirm`, then `join.admit`.
- **Room log check:** an independent fold of the owner's `host/<roomId>/log` files (hash chain, host and statement signatures, fold rules).

## Modules

### 1. `restart-persistence.test.ts`

**Findings:** P-13 (revocation durability), C-12 (member grant scheduler after a restart) and roadmap R2.1 (the member's verified log copy at rest).

**Setup:** one room with a share-live lane on the throwaway parent, so no new agent is created. Only the test daemons are stopped and started, through `paseo daemon stop|start --home`.

The file is one scenario run as ordered steps. A failed step can make later steps fail, so read the first failure first. Fingerprints are public key ids and server ids from `rooms.v2.status` and the per-entry hashes of the owner's room log (sealed files are re-sealed with a fresh nonce on every write, so their bytes are not a fingerprint).

| Step | Checks |
|---|---|
| Baseline | The member enrolls (SAS) and its lane registers with a grant and comes online. The owner's roster lists the device; a current grant exists. |
| Owner restart, idle | Host key id, admin key id, room endpoint and lane offer unchanged. The room log verifies and keeps every entry from before. Endpoints come back online; the member's session reopens (whether it reopened by itself is recorded, not asserted: automatic member reconnect is an I-8 follow-up) and its lane comes back online. |
| Owner restart, live view open | An app-style read-only view (routed through the member daemon) is open during the restart. The view must become readable again; the recovery time is recorded. |
| Member restart, idle | Same member and device ids, head not behind, no alerts, a current grant, and the member's verified log copy (`member/rooms/<roomId>/log/head.sealed` and `seg-000000.sealed`) is on disk and sealed. |
| Member restart, live view open | A new view works after the restart. Whether the old view recovered by itself is recorded, not asserted. |
| P-13 removal | The owner removes the member (`member.remove`). After both daemons restart: the member is not in the roster, no grant for its device, a new session of the device ends with `access_ended`, the lane host does not reappear during a 20 s watch, and the log contains `member.removed` and verifies. |
| Final | Keys and the log chain are intact after all restarts. |

**Expected:** pass.

**Not ported:** the M1 step "grant rotation across expiry while the member daemon is stopped". It needs grants shorter than the 1 h minimum of `grantTtl`; the development short grants are honoured only on `.test-homes/v2-*` e2e homes, and the e2e covers forced and idle rotation with them.

**Evidence:** `restart-persistence.jsonl`.

### 2. `enrollment-reliability.test.ts`

**Finding:** the M1 intermittent enrollment failure (`M1-RESULTS.md`, open issue 8). In that failure, a join failed with an empty error message about 0.7 s after a lane host was removed.

**Setup:** N = 10 sequential cycles (`RL_ENROLL_CYCLES`, up to 20). A daemon can join a given room only once and v2 has no leave RPC yet, so each cycle uses a fresh room with one share-live lane on the parent:

1. room and lane, both endpoints online;
2. a fresh invite;
3. the SAS enrollment above, until the member's room session is open;
4. the lane registers with a grant and its routed host comes online on the member;
5. `member.remove`; the member's session ends (`removed`) and the lane host is removed.

There are no artificial delays: each cycle starts right after the previous lane host was removed, which is the M1 timing. Rooms are not closed afterwards (closing needs the close delay); the cleanup stops the daemons, which ends their relay registrations.

**What is recorded per cycle:** the time of every step (room, invite, enrollment sub-steps, lane online, removal, session end, host removal) and the time since the previous host was removed. **On a failure:** redacted error details with the cause chain, the member's join state and the owner's join cards (states only, never the SAS), and the last 200 lines of each daemon's plugin log, redacted.

**Expected:** pass, all cycles. A failure is a real result, not noise. Afterwards every cycle's room log must verify by an independent fold and hold exactly one `member.admitted` and one `member.removed`.

**Evidence:** `enrollment-cycles.jsonl`, `enrollment-summary.json`, `enroll-failure-<n>-<step>-{member,owner}.log`.

### 3. `agent-environment-inspection.test.ts`

**Findings:** C-1 and P-5 (what a room agent can reach).

v2 shares the live agent only (no fork lanes, I-15), so the agent a room exposes is the owner's own throwaway parent. The module creates a room with a share-live lane on the parent and one invite that is never used, then sends the parent one trivial prompt: "Reply with the word OK and nothing else." While that turn runs, the test samples `/proc` for the parent's provider processes (command line carrying the owner test daemon's `/mcp/agents` URL). For each process it reports:

- the names of `PASEO_*`, `CLAUDE*`, `ANTHROPIC*` and `MCP*` variables. Values are shown only for a short allowlist of non-secret variables, such as `PASEO_HOME`. Other values appear as `<set>`;
- the names, not values, of variables whose value contains a tracked room secret (the invite code and token), and whether the command line does;
- the names of variables that mention the daemon port; the `PATH` directories that contain a `paseo` CLI;
- whether `$PASEO_HOME/local-credential`, `~/.paseo/local-credential`, the Rooms fallback KEK file and the Rooms data directory are readable. This uses `access(2)` from the test process only, which is valid because the test process has the same uid and namespaces as the agent. The files are never opened;
- the MCP config from the command line (names, types, basenames, URLs without query), the uid, `NoNewPrivs`, the seccomp mode, and the namespaces.

The main daemon (6767) is never contacted.

**Before sharing (positive control):** run.sh runs the same sampler during the parent's first turn, before any room exists. It validates the method (the `/mcp/agents` URL is seen) and gives the env names before sharing.

| Test | Expected |
|---|---|
| Shared agent processes observed | pass. If it fails, the inspection is inconclusive. |
| Stored config (MCP servers, tool policy, env names) unchanged by sharing | pass |
| No environment variable added by sharing; no `PASEO_ROOMS_LANE` marker | pass |
| No room secret in env values or the command line | pass |
| Positive control saw the agent MCP URL | pass (skipped if the control report is missing) |
| Different uid; credential, fallback KEK and Rooms data not readable; no `paseo` on `PATH`; own network namespace | **Marked `todo`, by design.** A share-live agent is the owner's own agent and runs as the owner's OS user. These document its reach; viewers cannot prompt it (lane permissions are `workspace.read` only, checked in the e2e). `todo` failures are reported but do not fail the run. |

**Evidence:** `agent-environment.json` (0600), `parent-environment.json` (0600).

### 4. `credential-negative.test.ts`

**Findings:** HARDENING-PLAN section E ("grant replay and forgery", "invite reuse"), P-15/C-7 (invite burn), P-23/C-8 (signature before lookup), grants-v2 sections 4 and 6, enrollment-v2 5.3 to 5.6.

**How:** the module acts as member devices inside the test process (`proto-client.ts`): the plugin's own `RoomClient` (Noise IK room sessions), the enrollment and device-link formats, and Paseo's client secure channel for lane links (Noise NK). This lets it send frames that a correct member daemon never sends. The member test daemon is not used.

**Setup:** one room with two share-live lanes (A and B) on the run's parent agent. Two in-process devices enroll by the real SAS flow, with the TEST-ONLY programmatic SAS comparison: device A (watch, lanes A and B) and device B (watch, lane A only). Each gets grants over its room session.

**Each case checks:**

1. **Generic refusal.** The refusal is the documented generic one. On a lane link this is `hello.rejected {reason: "incorrect_password"}` for every grant failure, followed by the link closing. Before the token proof, enrollment answers `enroll_rejected` with no extra fields. Only a requester that proved the token learns the invite's state.
2. **No state change.** The owner's status view is unchanged (roster, invites, join requests, grants, lanes, key ids), and no non-MLS entry is appended to the independently verified room log. Where the spec requires a change, the test asserts exactly that change: an invite or link burned on the third failed proof.
3. **No leak.** No tracked secret appears in any reply or in the owner's unredacted plugin log. Tracked secrets are the grants and their signatures, invite and link codes and tokens, and every tampered variant. The log is checked in memory and never printed.

| Case | Expected |
|---|---|
| Positive control: device A's current grant | accepted |
| Tampered grants (10 variants): a changed claims byte, a changed signature byte, claims forged with role admin, claims forged with a longer exp, a random signature, the wrong prefix, a missing signature, oversize, empty, a non-string | each gets the same generic refusal; no change |
| A lane A grant at lane B, and a lane B grant at lane A | generic refusal; each lane accepts its own grant |
| A replayed grant: the previous gid after a new `grant.issue` (waits out the 15 s issue interval) | generic refusal; the new grant is accepted |
| A grant relabelled for another device (sub and dev of device B, original signature) | generic refusal |
| `grant.issue` by device B for lane B, which its invite did not name | `not_permitted` with no detail; session stays open |
| Devices A and B link side by side with their own grants | both accepted |
| An expired grant | **skipped by design.** It needs a validly signed grant past its `exp`. Grants last at least 1 h outside marked e2e homes, and the module never holds the host key. Covered by `test/unit/v2-grants.test.ts` and the e2e forced rotation. |
| An invite reused after use, by a new device with the right token | `invite_used`; no change |
| An unknown inviteId, and a signature over another session's `h` | generic; the invite's failed proofs stay 0 |
| Three wrong token proofs on a fresh invite | generic each; failed proofs count 1, 2, 3; the third burns the invite and appends exactly one `invite.burned` |
| The right token on the burned invite | `invite_revoked`; no change |
| A device link code created by device A, then three wrong token proofs and the right token | generic each; one `invite.burned`; then `invite_revoked`; device A never gets a `link.request` |
| Enrollment resume: the session 1 request replayed in a new session | generic (its signature covers session 1's `h`); no change |
| `enroll.resume` from the same key | the stored pending byte for byte, still pinned to session 1's `h`; no change |
| `enroll.resume` of that pending from another key | generic; no change |
| Device B removed: its live session | ends with `access_ended {removed}` |
| Device B reconnects with its DH key | `access_ended {removed}` (shown only to the holder of that key); no change |
| Device B's grant issued before removal | generic refusal; no change |
| Device B's signing key with a new DH key, right token of a fresh invite | generic (retired key); the invite stays open and is revoked afterwards |
| Viewer route (device A, watch): owner-only plugin RPCs (`rooms.v2.status`, `rooms.v2.lane.errors`, `rooms.v2.admin.prepare`) and out-of-profile messages (`send_agent_message_request`, `archive_agent_request`, `capture_terminal_request`, `fetch_agent_request` for another agent, an unknown type) | each `rpc_error {code: "access_denied"}` with only the generic text; the route and link keep working; the lane agent's status is unchanged; no room is created |
| A message with no requestId, and a binary link frame | dropped silently; the link still answers |
| Viewer device on its room session: an admin statement via `stmt.submit`, and `kp.fetch` of the rekey pool | `not_permitted`; session stays open; no change |
| Final: the current grant still works; the owner's log holds no tracked secret | pass |

**No model call:** the prompting and archive messages name a made-up agent id. Even if the filter failed, they could not reach the real agent or a provider.

**Duration:** a few minutes. The room endpoint's pre-auth budget allows 5 enrollment requests at once and 10 per minute. Cases that do not test the budget wait out `busy` replies.

**Expected:** pass, with one skipped case (expired grant).

**Evidence:** `credential-negative.jsonl` (case names, outcomes and error codes; no secrets).

### 5. `resource-stress.test.ts`

**Findings:** B3 (C-4, P-17), grants-v2 sections 6.1 and 11, enrollment-v2 5.4, mls-integration 6.4, the chat store bound (R3.4).

**How:** the same in-process member device as module 4, on its own room with one lane. The limits are imported from the server code (`V2_LANE_LIMITS`, `ENROLLMENT_LIMITS`, `KP_FETCH_TARGETS_MAX`, `KP_POOL_MAX`, `CHAT_LIMITS`), so a changed limit changes the test. Every test asserts three things: the limit holds; going over it refuses or closes only the offending connection, route or request; and service recovers afterwards.

| Case | Load | Expected |
|---|---|---|
| Connections per lane | 40 concurrent relay connections (cap 32) | at most 32 complete the handshake and at least 28 do; the rest are not served; afterwards a normal link works |
| Routes per link | 33 `hosts.link.open` on one link (cap 32) | 32 routes; the 33rd gets `resource_limit` ("Too many host channels"); after closing one route, a new one opens |
| Links per grant, silent duplicate | a second link with the same grant while the first is silent | accepted after the 12 s liveness window; the first link closes; no log entry; the grant stays current |
| Links per grant, live duplicate | a third link while the second pings every second | not accepted; both links close; the gid is unlisted; exactly one `grant.suspected-theft`; the device gets `grant.revoked`; not yet a compromise; a new grant links again |
| Frame size | a route message over 256 Ki characters, then a link frame over 1 MiB | the route closes with `resource_limit` and the link survives; then the link closes; a new link works; no log entry; the grant stays current |
| Pre-auth sessions | 10 concurrent handshakes from unknown keys (cap 8) | at most 8 open; at least 2 are refused; afterwards a new one opens |
| Pre-auth request budget | up to 12 rapid, validly signed enrollment requests naming unknown invites | `busy {retryAfter}` within burst + 1 requests, with `retryAfter` in 1 to 60 s and no other field; after `retryAfter`, a request passes the budget; no invite, pending or log change |
| `kp.fetch` caps | 9 targets; a count of 11; two fetches of the owner device's current package | `bad_frame` twice (the session closes and the device reconnects); the first fetch serves 1 single-use package and the second serves none (at most the last resort). **Inconclusive** (skipped) if the owner device had published no package. |
| Chat store retention | about 760 messages of 4000 characters from the owner device in a fresh room, stopped after 120 s | stored messages at most `floor(8 MiB / 12200)` = 687, and at least one segment (64) below that; the oldest is dropped and the newest kept; segment files bounded; a later message is stored. Only the byte bound is reached; the 2048-message bound would need minutes. **Inconclusive** (skipped) if the room cannot send or the time bound is hit. |
| Final | | the current grant still works; no tracked secret in the owner's status or plugin log |

**Duration:** about 3 minutes. The chat case is the longest (about 760 sends) and is capped at 120 s.

**Expected:** pass. A skip means inconclusive, not pass.

**Evidence:** `resource-stress.jsonl` (counts and timings; no secrets).

## Loopback relay (modules 4 and 5)

Lane and room endpoints are reachable only through a relay. The routine modules use the live relay, and their member daemon cannot use a plain-ws loopback relay outside marked e2e homes (`PASEO_ROOMS_DEV_INSECURE_RELAY` is dropped here). Modules 4 and 5 therefore run in a separate step:

1. `run.sh` starts `fake-relay-main.ts` (the unit-test fake relay) on `127.0.0.1:6932`.
2. It restarts the owner test daemon with `PASEO_ROOMS_RELAY_ENDPOINT=127.0.0.1:6932` and `PASEO_ROOMS_RELAY_TLS=false`. These are not development switches; the owner honours the plain-ws override for loopback hosts only.
3. Rooms created afterwards record this relay in their genesis. Rooms created earlier keep the live relay.
4. The modules act as the member in-process and connect only to this relay.

`proto-client.ts` checks the relay recorded in each invite, link code and lane offer against `RL_RELAY_ENDPOINT`. It refuses to connect otherwise, so no negative or load traffic can reach `relay.paseo.sh`.

## Resources used

- **Daemons:** two loopback test daemons, owner `127.0.0.1:6930` and member `127.0.0.1:6931`, plus the loopback fake relay on `127.0.0.1:6932` for modules 4 and 5. Only ports 6930 to 6939 are allowed.
- **Homes:** `PASEO_HOME` is under `test/reliability/.homes/` (0700, git-ignored). Each `config.json` is written before the first start, with daemon relay registration off, plugins on, and dictation and voice mode off, so no speech model is downloaded.
- **Keys:** `PASEO_ROOMS_KEYSTORE=fallback-file` (a protected file in each test home); the user's keyring is never read or written. `PASEO_ROOMS_KEK_FILE`, the relay overrides, the test clock and every `PASEO_ROOMS_DEV_*` switch are unset.
- **Agents:** one throwaway agent on the owner, Claude `claude-haiku-4-5`, with two short turns in total (its creation prompt, and the one prompt of module 3). Modules 1, 2, 4 and 5 share it, create no agents and make no model calls. The parent's creation prompt is part of run.sh's shared setup, so even `--only credential-negative` makes that one Haiku call.
- **Network:**
  - the Paseo relay (`relay.paseo.sh:443`), which room and lane endpoints of modules 1 to 3 use. Module 2 registers two endpoints per cycle (room and lane) until the daemons stop. After the owner restart, those earlier rooms reconnect to it. Modules 4 and 5 send no traffic to it;
  - the Claude provider, for the two turns.
- **Logs:** written to `test/reliability/logs/<UTC run id>/` (git-ignored). Each run gets a new directory, so earlier evidence is never overwritten.

## Safety gates (run.sh)

`run.sh` refuses to start in each of these cases:

- `--i-reviewed-this` is missing;
- a home resolves to `~/.paseo` or lies outside `.homes`;
- a port (owner, member or loopback relay) is 6767 or outside 6930 to 6939;
- a port is already in use;
- the `paseo` CLI is missing.

Every CLI call passes `--home` and sets `PASEO_HOME` explicitly. The TypeScript side re-checks the homes and ports (`assertSafeEnvironment`) before every daemon stop or start. Modules 4 and 5 also check that `RL_RELAY_ENDPOINT` is `127.0.0.1` with a port in 6930 to 6939, and that every room or lane they contact records exactly that relay.

## Cleanup guarantees

A trap runs on exit, including on failure and Ctrl-C. It does the following:

1. If the owner test daemon is down, it starts it, then archives every agent listed in `agents.txt`.
2. It saves the plugin and daemon logs.
3. It removes the plugin and stops both test daemons, then stops the loopback relay if it was started.
4. It runs the e2e secret scan (`test/reliability/secret-scan.ts`, moved from the removed M1 e2e) over the homes and logs. The scan uses the invite codes, invite tokens and grant signatures the modules tracked.
5. It checks that the daemon and relay ports are closed.
6. It deletes the homes, unless `KEEP_HOMES=1` is set.
7. It reports any process still referencing the homes.

If an agent cannot be archived, a port stays open, or a process is left, the cleanup reports it and the exit code is non-zero.

**Not guaranteed:** after `kill -9` of `run.sh`, the trap cannot run. In that case, stop the daemons manually:

```bash
paseo daemon stop --home test/reliability/.homes/{owner,member}
```

## Files

- `run.sh`: setup, the modules, and the always-run cleanup.
- `lib.ts`: clients, safety re-checks, daemon stop and start, on-disk snapshots, and redaction.
- `env-sampler.ts`: the read-only `/proc` sampler. It is a library, and also a CLI for the parent control.
- `proto-client.ts`: the in-process member device, lane link client and leak checks used by modules 4 and 5.
- `fake-relay-main.ts`: the loopback relay process for modules 4 and 5 (ports 6930 to 6939 only).
- `*.test.ts`: the five modules.
- `secret-scan.ts`: the cleanup's scan for tracked invite codes, tokens and grant signatures.
- `tsconfig.json`
- `.gitignore`
