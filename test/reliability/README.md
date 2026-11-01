# Reliability and environment-inspection tests

These are routine tests for the `rooms` plugin, run against two disposable test daemons. They cover the "restarts", "flaky-enrollment loop" and "real environment of the room agent's process" items from `review/HARDENING-PLAN.md` section E, as approved in "Decisions, round 2". Since the identity v2 cut-over the room agent is the shared live agent (no fork lanes).

Fuzzing, credential forgery and replay, concurrency races, and stress or resource-exhaustion tests are **out of scope**. They belong in `test/security/` and will be written or approved by the user separately.

**Status:** ported to the identity v2 RPCs (`rooms.v2.*`) on 2026-11-01 and typechecked. **Not run yet.** Running needs explicit approval: `run.sh` refuses to start without `--i-reviewed-this`.

## How to run

```bash
cd plugin
bash test/reliability/run.sh --i-reviewed-this
bash test/reliability/run.sh --i-reviewed-this --only enrollment-reliability
KEEP_HOMES=1 RL_ENROLL_CYCLES=5 bash test/reliability/run.sh --i-reviewed-this
```

Modules run in this order: environment inspection, then enrollment, then restarts. Restarts go last because they are the most disruptive. Each module is a `node:test` file run on the Node bundled with Paseo through tsx. One failing module does not stop the others. The exit code is non-zero if any module, the cleanup or the secret scan fails.

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

## Resources used

- **Daemons:** two loopback test daemons, owner `127.0.0.1:6930` and member `127.0.0.1:6931`. Only ports 6930 to 6939 are allowed.
- **Homes:** `PASEO_HOME` is under `test/reliability/.homes/` (0700, git-ignored). Each `config.json` is written before the first start, with daemon relay registration off, plugins on, and dictation and voice mode off, so no speech model is downloaded.
- **Keys:** `PASEO_ROOMS_KEYSTORE=fallback-file` (a protected file in each test home); the user's keyring is never read or written. `PASEO_ROOMS_KEK_FILE`, the relay overrides, the test clock and every `PASEO_ROOMS_DEV_*` switch are unset.
- **Agents:** one throwaway agent on the owner, Claude `claude-haiku-4-5`, with two short turns in total (its creation prompt, and the one prompt of module 3). Modules 1 and 2 share it and create no agents.
- **Network:**
  - the Paseo relay (`relay.paseo.sh:443`), which room and lane endpoints use. Module 2 registers two endpoints per cycle (room and lane) until the daemons stop;
  - the Claude provider, for the two turns.
- **Logs:** written to `test/reliability/logs/<UTC run id>/` (git-ignored). Each run gets a new directory, so earlier evidence is never overwritten.

## Safety gates (run.sh)

`run.sh` refuses to start in each of these cases:

- `--i-reviewed-this` is missing;
- a home resolves to `~/.paseo` or lies outside `.homes`;
- a port is 6767 or outside 6930 to 6939;
- a port is already in use;
- the `paseo` CLI is missing.

Every CLI call passes `--home` and sets `PASEO_HOME` explicitly. The TypeScript side re-checks the homes and ports (`assertSafeEnvironment`) before every daemon stop or start.

## Cleanup guarantees

A trap runs on exit, including on failure and Ctrl-C. It does the following:

1. If the owner test daemon is down, it starts it, then archives every agent listed in `agents.txt`.
2. It saves the plugin and daemon logs.
3. It removes the plugin and stops both test daemons.
4. It runs the e2e secret scan (`test/reliability/secret-scan.ts`, moved from the removed M1 e2e) over the homes and logs. The scan uses the invite codes, invite tokens and grant signatures the modules tracked.
5. It checks that both ports are closed.
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
- `*.test.ts`: the three modules.
- `secret-scan.ts`: the cleanup's scan for tracked invite codes, tokens and grant signatures.
- `tsconfig.json`
- `.gitignore`
