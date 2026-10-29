# Reliability and environment-inspection tests

These are routine tests for the `rooms` plugin, run against two disposable test daemons. They cover the "restarts", "flaky-enrollment loop" and "real environment of the fork process" items from `review/HARDENING-PLAN.md` section E, as approved in "Decisions, round 2".

Fuzzing, credential forgery and replay, concurrency races, and stress or resource-exhaustion tests are **out of scope**. They belong in `test/security/` and will be written or approved by the user separately.

**Status:** written and typechecked. **Not run yet.** Running needs explicit approval: `run.sh` refuses to start without `--i-reviewed-this`.

## How to run

```bash
cd plugin
bash test/reliability/run.sh --i-reviewed-this
bash test/reliability/run.sh --i-reviewed-this --only enrollment-reliability
KEEP_HOMES=1 RL_ENROLL_CYCLES=20 bash test/reliability/run.sh --i-reviewed-this
```

Modules run in this order: environment inspection, then enrollment, then restarts. Restarts go last because they are the most disruptive. Each module is a `node:test` file run on the Node bundled with Paseo through tsx. One failing module does not stop the others. The exit code is non-zero if any module, the cleanup or the secret scan fails.

To typecheck: `npx tsc -p test/reliability/tsconfig.json`. The root `npm run typecheck` also covers these files.

## Modules

### 1. `restart-persistence.test.ts`

**Findings:** C-12 (member rotation timers after restart) and P-13 (revocation durability).

**Setup:** a share-live lane bound to the throwaway parent, so no new agent is created. Only the test daemons are stopped and started, through `paseo daemon stop|start --home`.

The file is one scenario run as ordered steps. A failed step can make later steps fail, so read the first failure first.

| Step | Checks |
|---|---|
| Baseline | The member enrolls with a 1 h grant. The test records fingerprints of the host key, the lane key, the revocation list and the room log. Fingerprints are SHA-256 hashes kept in memory; only booleans are logged. |
| Owner restart, idle | The host key and lane key are unchanged. The room log verifies, and the events from before the restart are unchanged. The revocation list has lost no entries. The member is still active. The lane endpoint and the member's lane host come back online. |
| Owner restart, live view open | An app-style read-only view (routed through the member daemon, as in the e2e) is open during the restart. The view reconnects on its own. The test records the recovery time. |
| Member restart, idle | The device key is unchanged. The membership is still active, and the grant is either unchanged or rotated forward. The lane host comes back online. |
| Member restart, live view open | A new view works after the restart. Whether the old view recovered on its own is recorded but not asserted. |
| P-13 revocation | The owner revokes the member. After both daemons restart, all of the following hold: the owner still shows the member as `revoked`, the revoked grant id is in the persisted list, the member's view and `rooms.json` both show `revoked`, the lane host does not reappear during a 20 s watch, and the log contains `member.revoked` and verifies. |
| C-12 rotation | The member re-enrolls with a 30 s grant. The member daemon is stopped until 3 s past expiry, then started. For 15 s the test watches `rooms.json` on disk without making further RPCs, to see whether the parked rotation ran on its own. It then contacts the member daemon. Within 120 s the member must hold a newer grant and be online again. |
| Final | Keys and the log chain are intact after all restarts. |

**Expected:** pass.

Two outcomes in the C-12 step are informational only, not asserted:

- `rotatedBeforeFurtherContact`. C-12 is *partial* (`review/FIXES-B-D.md`): rotation needs a PaseoApi, which exists only after an RPC or hook. The `rooms.bootstrap` probe that `startDaemon` uses to confirm the plugin loaded is itself such a contact. This value is therefore not a measure of "no contact at all".
- `oldViewRecoveredItself` in the member live-view step.

**Evidence:** `restart-persistence.jsonl`.

### 2. `enrollment-reliability.test.ts`

**Finding:** the M1 intermittent enrollment failure (`M1-RESULTS.md`, open issue 8). In that failure, a `rooms.join` failed with an empty error message about 0.7 s after a host was removed, and the gateway never saw the attempt.

**Setup:** N = 20 sequential cycles on one share-live lane. N can be set with `RL_ENROLL_CYCLES`, up to 50. Each cycle does the following:

1. creates a fresh invite;
2. calls `rooms.join`;
3. waits for the lane host to come online;
4. calls `rooms.leave`;
5. waits for the lane host to be removed.

There are no artificial delays. Each cycle starts right after the previous host was removed, which is the M1 timing.

**What is recorded per cycle:**

- the time taken by every step;
- the time since the previous host was removed.

**On a failure, the test also records:**

- the error's name, message and code, its cause chain and any `AggregateError` members, all redacted;
- whether the owner saw the enrollment;
- the member's record;
- the last 200 lines of each daemon's plugin log, redacted.

**Expected:** pass, with 20 of 20 cycles succeeding. A connect retry was added after M1, so the failure may not reproduce. A failure is a real result, not noise: it is the M1 issue, now with diagnostics. After the cycles, the room log must verify and must contain a join and a leave for every successful cycle.

**Evidence:**

- `enrollment-cycles.jsonl`
- `enrollment-summary.json`
- `enroll-failure-<n>-<step>-{member,owner}.log`

### 3. `agent-environment-inspection.test.ts`

**Findings:** C-1 and P-5 (which control routes a room agent can reach).

**Setup:** creates one fork lane from the parent. This makes throwaway agent 2. The gateway creates the fork without a prompt, checks it with the tripwire, then sends the instruction "Reply with the word OK and nothing else." That is the only prompt the fork receives.

While that first turn runs, the test samples `/proc` for processes with `PASEO_ROOMS_LANE=<lane>`. This covers the provider process and its children, such as the inert MCP server. For each process it reads `environ` and `cmdline` and reports:

- the names of `PASEO_*`, `CLAUDE*`, `ANTHROPIC*` and `MCP*` variables. Values are shown only for a short allowlist of non-secret variables, such as `PASEO_HOME` and the lane id. Other values appear as `<set>`.
- the names, not values, of any variables that mention the daemon port;
- the `PATH` directories that contain a `paseo` CLI;
- whether `$PASEO_HOME/local-credential` and `~/.paseo/local-credential` are readable. This uses `access(2)` from the test process only, which is valid because the test process has the same uid and namespaces as the fork. The files are never opened.
- the MCP config from the command line: server names, types and basenames, with URLs stripped of their query string;
- the uid, `NoNewPrivs`, the seccomp mode, and whether the process shares the net, mount and user namespaces with the test process;
- whether the owner **test** daemon port accepts TCP connections.

The main daemon (6767) is never contacted. The test only reports whether any variable's value mentions that port.

The test also reports the fork's stored agent config: MCP server summary, `toolPolicy` keys and env names.

**Positive control:** the same sampler runs while the parent's turn runs, matching processes whose command line carries the owner's `/mcp/agents` URL.

**Expected:**

| Test | Expected |
|---|---|
| Fork processes observed | pass. If it fails, the inspection is inconclusive. |
| Stored config holds only the inert `paseo` server and no preapprovals | pass |
| No fork command line carries Paseo's agent MCP URL | pass |
| The parent control saw that URL | pass. It is skipped if the control report is missing. |
| Different uid; credential not readable; no `paseo` on `PATH`; no daemon address or `PASEO_HOME` in env; own network and mount namespaces | **Known failing, marked `todo`.** This documents the owner-uid gap: M1 forks run as the owner's OS user (HARDENING-PLAN, "Correction to earlier claims"). Rooms are watch-only by decision until sandboxed lanes exist. `todo` failures are reported but do not fail the run. |

**Evidence:**

- `agent-environment.json` (0600)
- `parent-environment.json` (0600)

## Resources used

- **Daemons:** two loopback test daemons, owner `127.0.0.1:6930` and member `127.0.0.1:6931`. Only ports 6930 to 6939 are allowed.
- **Homes:** `PASEO_HOME` is under `test/reliability/.homes/` (0700, git-ignored). Each `config.json` is written before the first start, with relay registration off, plugins on, and dictation and voice mode off, so no speech model is downloaded. The script also exports `PASEO_DICTATION_ENABLED=false` and `PASEO_VOICE_MODE_ENABLED=false`.
- **Agents:** at most 2 throwaway agents on the owner, both using Claude `claude-haiku-4-5` with a trivial prompt:
  1. the parent, created by `run.sh`;
  2. the fork, created by module 3.

  That makes two short turns in total. Modules 1 and 2 use share-live lanes on the parent and create no agents.
- **Network:**
  - the Paseo relay, which lanes use;
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

1. If the owner test daemon is down, it starts it, then archives every agent listed in `agents.txt`. Archiving the parent also archives its fork.
2. It saves the plugin and daemon logs.
3. It removes the plugin and stops both test daemons.
4. It runs the e2e secret scan (`test/e2e/secret-scan.ts`) over the homes and logs. The scan uses the invite codes, invite tokens and grant signatures the modules tracked.
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
- `tsconfig.json`
- `.gitignore`
