# Hardening fixes: sections B, C (iso2, iso3, isolation guard) and non-protocol D

- **Date:** 2026-10-29
- **Scope:** the items assigned from `docs/security/hardening-plan.md`. The enrollment and control protocol, the invite and grant formats and the room log format were **not changed**; identity v2 owns those. `docs/design/specs/identity-v2/` and `test/security/` were not touched. No git commits.
- **Verification:** `npm run typecheck` is clean. `npm test` gives 68 pass, 0 fail (it was 28). The e2e (`test/e2e/run.sh`) ran once on its own daemons (127.0.0.1:6891/6892, speech off before first start). Result: 42/42 checks, 0 failures, 67 s. Two throwaway agents were created and both archived. The secret scan found 0 unexpected files out of 43. Homes were deleted, no test processes were left, and both ports were closed afterwards. The main daemon and `~/.paseo` were not touched.
- **Raw data preserved:** the e2e overwrites `test/e2e/logs/`, so the M1 evidence logs were copied first to `test/e2e/logs-m1-2026-10-28/`. The new run's logs are in `test/e2e/logs/`.
- **Status legend:**
  - *fixed*: implemented and covered by a test.
  - *partial*: implemented, with a stated limit.
  - *deferred*: not done in this pass.
  - Runtime evidence is the unit tests plus the single e2e run. The real app UI was **not** exercised.

## Summary

| Item | Findings | Status |
|---|---|---|
| B1 upstream hello | C-2 | fixed |
| B2 field allowlists | C-3, P-18, P-19, P-26, C-6, C-16 | fixed (P-19: partial, see below) |
| B3 resource caps | C-4, P-17 | fixed (renew rate limit deferred) |
| B4 grant admits every client | P-21 | fixed (documentation) |
| Revocation durability | P-12/C-9, P-13 | fixed |
| Log injection and flooding | C-5 | fixed |
| Torn room log | C-11 | fixed |
| Member timers after restart | C-12 | partial |
| Archived or deleted lane agent | C-13 | fixed |
| Tripwire after all hooks | C-iso2 / P-6 | fixed for 0.13.2 |
| Provider allowlist | C-iso3 / P-28 | fixed |
| Isolation decision in code | C-iso1 decision | fixed (guard plus docs) |
| UI confirmations, copy, "Open room…" | ui-notes | fixed / partial |

## B1 (C-2): upstream hello built from scratch

**What changed.** `server/gateway/local-daemon.ts` `buildUpstreamHello(home, viewerHello | null, clientId)` now builds the upstream hello from constants. No viewer field is spread into it.

- **Fixed values:**
  - `type`
  - gateway `clientId`
  - `clientType: "browser"`
  - local-credential `auth`
  - `sessionPermissions: ["workspace.read"]`
- **Capabilities:** taken from the reviewed table `hello.capabilities` in `profile/fields.csv`.
  - **Forced on:** `owned_subscriptions`, `explicit_event_subscriptions`, `selective_agent_timeline`, `hello_rejection`.
  - **Copied only when the viewer sets them to `true`:** rendering-format flags.
  - **Dropped:** `voice`, `pushNotifications`, `browser_host`, provider and terminal flags, and every unknown passthrough key.
- **Validated:** `protocolVersion` (integer 1..16, else 1) and `appVersion` (plain semver, else omitted).
- **clientId** (`lane-endpoint.ts`) is `sha256([laneId, memberId, routeSlot])`. The slot is the member's lowest free route slot on the lane, so retained daemon sessions are bounded by the route cap, and the viewer's `clientId` is ignored.
- The internal `RawDaemon` helper sessions previously sent `capabilities: {}`, which is legacy mode. They now use the same builder.
- The design is protected only: `minimumMode: "protected"` was already enforced on lane endpoints, and nothing changed there.

**Tests:**
- `field-policy.test.ts` "B1: upstream hello…": a legacy viewer hello still gets the modern flags, and no viewer field survives.
- `lane-endpoint.test.ts` "B1 + B3: routes…": the fake daemon receives slot-derived clientIds. The viewer's id is ignored, and a freed slot is reused.

**Evidence:** both tests pass. In the e2e, the routed app-style client connected, read the lane, and every live-timeline check passed with the forced flags.

## B2 (C-3, P-18, P-19, P-26, C-6, C-16): field-level allowlists

**What changed.**

- **New `profile/fields.csv`:** 259 reviewed rows covering 38 objects. Actions are `keep`, `drop`, `redact`, `nested`, `gateway` and `force`. It covers:
  - every allowed inbound message;
  - every allowed outbound payload;
  - the upstream `hello` and its capabilities;
  - `AgentSnapshot`, `WorkspaceDescriptor`, `ProjectPlacement`, `AgentListEntry` and their nested objects.
- **Generator** (`tools/gen-room-profile.ts`, `tools/room-profile-lib.ts`):
  - It reads the field names from the installed protocol's zod schemas. For capabilities it also uses `CLIENT_CAPS`.
  - It **fails on any unreviewed or stale field**, on an allowed type with no table, and on a `nested` field with no table.
  - It emits `FIELD_POLICY` and `PROMPTING_INBOUND` into `generated.ts`.
- **New `server/room-profile/sanitize.ts`:** rebuilds every forwarded object from its table. Unknown fields are dropped, and every `redact` and `gateway` field has a handler (a test enforces this). `filter.ts` routes both inbound and outbound messages through it, and `lane-endpoint.ts` sanitises the entries the gateway builds itself.

**Decisions:**

- **Agent snapshot** (every carrier: `fetch_agent_response`, `fetch_agents_response` entries, `agent_update`, `agent_status.info`, and also `fetch_agent_timeline_response.agent`, which no review listed):
  - `cwd` becomes `/room/<basename>`.
  - `persistence` becomes `null`. This removes the system prompt, the daemon-wide appended prompt, the tool policy, the provider session id and the native handle.
  - `runtimeInfo.sessionId` becomes `null`, and `extra` is dropped.
  - Only `rooms.*` labels are kept, so `paseo.parent-agent-id` and the owner's labels are dropped.
  - `internal` is dropped.
  - `lastError` is replaced by generic text.
- **Workspace descriptor:**
  - Paths are redacted.
  - `scripts` becomes `[]` (ports, terminal ids, proxy URLs).
  - `githubRuntime` (pull request, checks, repo owner) becomes `null`, and `diffStat` becomes `null`.
  - `gitRuntime` keeps only `currentBranch` and `isPaseoOwnedWorktree`.
  - `status`, `statusEnteredAt`, `activityAt` and `lastUserMessageAt` are **derived from the lane agent only**. The daemon aggregates every agent in the workspace, which revealed the parent's activity.
  - `pinnedAt`, `labels`, `setupStatus`, `forge` and the icon revision are dropped.
  - On `workspace_update`, `emptyProject` and `removedProjectId` are dropped.
- **Project placement:**
  - `projectKey` becomes `room:<laneId>`. The daemon key is either the git remote or `host:<owner serverId>:<absolute path>`, which no review listed explicitly.
  - Checkout paths are redacted, and `remoteUrl` becomes `null`.
- **C-6:** `notification.data.serverId` is rewritten to the lane serverId, both in `agent_attention_required` and in legacy `agent_stream` attention events.
- **C-16:** `rpc_error.error` and the `error` fields of fetch responses become generic text. `code` is kept only if it matches `[a-z_]{1,40}`.
- **P-26:**
  - Inbound `sync` cursors are dropped, so the daemon always answers with a snapshot.
  - `headSeq`, update `seq` and entry `syncSeq` are rebased on a per-route counter.
  - `generation` becomes a per-route opaque value (a hash of the daemon generation plus a route tag).
  - Removals become `[]`.
- **P-18 inbound:** each allowed request is rebuilt from its table.
  - `includeInternal`, `includeBackground`, `idPrefix`, `sync` and unknown fields are dropped.
  - `fetch_agent_timeline_request.limit` of 0 or above the limit is clamped to `maxTimelineLimit` (default 1000).
  - `requestId` values longer than 256 characters are never echoed.

**Tests** (`field-policy.test.ts`, 15 tests):
- The conformance gate and its negative cases: an unreviewed field, a stale field, a missing table, a missing nested table.
- The handler set equals the set of fields that need handlers.
- Every `CLIENT_CAPS` name is reviewed.
- Leakage tests with realistic descriptors (`test/unit/fixtures.ts`). Each carries markers for paths, prompts, session ids, the parent id, owner labels, the owner serverId, the script port, the proxy URL, the git remote, the PR title and an unknown "future" field. No marker reaches the output in any carrier.
- Workspace status is derived from the idle lane agent while the parent is running.
- Notification serverId rewrite.
- Generic errors.
- Sequence and generation rebasing.
- Inbound rebuilding.
- **Sanitised messages still parse with `SessionOutboundMessageSchema`**, so the app accepts them.

**Evidence:** all pass. In the e2e, the routed client fetched agents, workspaces and the timeline through the sanitiser: exactly one agent, one workspace, and the live timeline arrived.

**Remaining:**
- **P-19 (content exposure):** partial. Watch content passes by design: timeline items, tool input and output, and pending permission inputs. These can contain absolute paths and anything the agent reads. The "preview fork context" and "share-live warning" UI items from P-19 were not done.
- **Kept on purpose:** `projectName` and `projectDisplayName`. For a git project these can be `owner/repo`.
- **Generic `lastError`:** this hides useful errors from watchers. It can be relaxed if the owner wants.

## B3 (C-4, P-17): resource caps

**What changed.** New `server/limits.ts` holds the defaults, hard bounds and a token bucket. The defaults can be overridden in `<PASEO_HOME>/plugin-data/rooms/limits.json`, which is read at plugin start; values are clamped and unknown keys are ignored.

| Limit | Default |
|---|---|
| Relay connections per lane (includes pre-auth and control connections; extra `connected` notices are ignored) | 32 |
| Links per member | 2 |
| Routes per link | 16 |
| Routes per member, across links | 32 |
| Inbound relay frame size (`maxPayload` on data and control sockets, plus a string check) | 1 MiB |
| Routed message size | 256 KiB |
| Upstream daemon frame size (was 100 MB) | 32 MiB |
| Queued requests before the upstream is ready (overflow closes the route) | 64 |
| Tracked request ids per route (deleted on response; the oldest is evicted) | 256 |
| Queued outbound messages per route (overflow closes the route) | 2048 |
| Frames per second per link (burst) | 50 (200) |
| Timeline limit clamp | 1000 |

Notes:
- `listRequests` is bounded too.
- A link over the per-member cap is closed **without** `hello.rejected`, so the member daemon does not treat it as an auth failure and rotate.

**Tests:** `lane-endpoint.test.ts` has 7 tests. They cover limit clamping, the connection cap, the link cap (with no auth-failure frame), the per-link and per-member route caps, pending-queue overflow, the bounded tracked map with removal on response, frame size and the rate limit.

**Not done:** per-member token buckets on control `renew` and `status` (P-17). The control protocol belongs to identity v2.

## B4 (P-21): a grant admits every client of the member daemon

**What changed:** documentation only.
- `README.md`, new section "Security model and limits".
- `OVERVIEW.md`: the member's app, paired devices and the member's own agents (through routed-host tools) can all read the lane, and a prompt-injected agent on the member's machine can exfiltrate it.

## D (non-protocol)

### P-12/C-9 and P-13: revocation

**What changed** (`server/host/host-store.ts`, `server/paths.ts`):

- **Order:** `revokeMember`, `leave` and `closeLane` now do the following, in order:
  1. mutate memory;
  2. **emit**, which cuts live links synchronously and does not depend on I/O;
  3. record;
  4. persist.
- **Save failures:** if the save fails, the RPC error says the change "is in effect now", `dirty` is set, and a retry runs every 5 s.
- **Durable writes:** `writePrivateFile` now fsyncs the temp file, renames it, then fsyncs the directory. `appendPrivateLine` fsyncs too.
- **Pruning:** revoked grant ids are pruned only after `exp` plus 7 days.
- **Allowlist:** `checkGrantLive` now also requires `gid == latestGrant(member).gid` (`superseded_grant`). A clock step or pruning cannot revive an old grant, and a stray validly signed grant is refused.
- **Re-enrollment:** a replaced membership is now logged as `member.left` with reason `re_enrolled`. This uses an existing event type with a data field; the log format is unchanged.

**Tests** (`durability.test.ts`):
- A blocked `state.json` write: the revocation is still pushed and enforced, the error says so, and after the disk recovers the save and a reload hold the revocation.
- No temp files are left, and the file mode is 0600.
- A failed write leaves the old file intact.
- The allowlist refuses a stray grant.
- The pruning margin.
- Re-enroll logging.

**Not tested:** fsync durability across real power loss.

### C-5: log injection and flooding

**What changed:**
- `clip()` bounds length and replaces control characters. It is applied to every peer-supplied string that is logged or echoed: `type`, `clientType`, `appVersion`, `channelId`, error text.
- `LogLimiter` rate-limits deny and limit logs per connection, route or lane. The next written line carries a `suppressed` count.
- `requestType` echoed in `rpc_error` is cut to 96 characters.

**Tests:** `durability.test.ts` "C-5", and the rate-limit and clipping assertions in `lane-endpoint.test.ts`.

### C-11: torn last log line

**What changed** (`server/host/event-log.ts`):
- **Torn last line:** on open, an unparsable or schema-invalid last line is moved to `events.jsonl.torn-<time>` (0600), and the file is truncated to the last complete event.
- **Missing newline:** a complete event that only lacks its newline is kept.
- **Corrupt middle line:** never rewritten. Reads skip it and `verify()` reports `corrupt_line:<n>`.
- **Append failures:** `record()` failures are logged (`room_log_append_failed`) and never block or undo an access change that is already enforced.

**Tests:** two tests in `durability.test.ts`. A plugin restart after a torn tail works and the chain verifies.

### C-12: member rotation timers after restart

**Status:** partial.

**What changed** (`server/member/member.ts`, `runtime.ts`):
- `MemberRole.start()` arms timers from `rooms.json` at `contribute()`.
- A timer that fires before any PaseoApi exists is **parked**, logged as `rotation_waiting_for_api`, and runs on first contact.

**Limit:** on 0.13.2 the plugin gets a PaseoApi only from RPCs and hooks. Rotating without it would renew a grant that cannot be registered and would revoke the one in use. So if no app connects and no agent opens, a grant can still expire. The expiry is recoverable: renewal needs only the device key, and the auth-failure path rotates once the app returns.

**Test:** `durability.test.ts` "C-12".

### C-13: archived or deleted lane agent

**What changed:**
- `LaneEndpoint.start()` treats `archivedAt` as final and calls `onAgentGone`.
- A missing agent (`agent: null`, no error) closes the lane only after 3 sightings spread over at least 60 s, which guards against a daemon that is still loading.
- Other failures back off from 10 s to 5 min, and logs are thinned.
- The gateway closes the lane with `actor: "host"` and `reason: agent_archived | agent_missing`, recorded in the existing `lane.closed` event.
- A new `server.on("agent.archived")` handler closes every open lane of that agent at once.

**Tests:** `lane-endpoint.test.ts` (an archived agent against the fake daemon, no retry timer; a single missing sighting does not close), and `durability.test.ts` (the gateway closes and records).

### UI (`client/`)

- **Confirmations:** a new `ConfirmButton` adds an inline confirm step with a busy state and blocks double presses. It is used for Close lane, Leave, Revoke invite and Revoke member.
- **Copy:** "renews before in 23 h" is replaced by "access expires in 23 h unless renewed" (owner) and "access renews automatically, expires in 23 h" (member).
- **"Open room…" on lane agents:** partial. The 0.13.2 Command Center has **no per-agent visibility predicate**, so the item cannot be hidden. On a lane agent it now opens Rooms instead, and the Open room screen shows "already shared as a lane".
- **Trivial ui-notes items done:**
  - Fork is disabled for unverified providers (note 3).
  - Compact keyboard hint (4).
  - Badge truncation (5).
  - "Shown shortened; Copy copies all" (6).
  - iOS mono font (7).
  - "No members yet" (8).
  - Join hint (9).
  - "Left" card text (ui-notes known edge 2).
- **Checks:** the RN audit has no hits outside two TypeScript-generic false positives. Typecheck is clean. **Nothing was seen in a real app.**

## C-iso2 (P-6): tripwire after all hooks

**Hook ordering on 0.13.2.** Verified by reading `@getpaseo/server@0.13.2`, packed into a fresh temp dir:

1. `plugins/runtime.js` `before()` sorts running plugins by id with `localeCompare` and chains them, so each gets the previous plugin's output.
2. `plugins/lifecycle/index.js`:
   - The hooks are `agent.create`, `agent.session_open` and `workspace.create`.
   - `validateBeforeResult` lets `agent.session_open` change only env.
   - `agent.create` can change config, but not `cwd`.
3. `agent/agent-manager.js` `createAgentInternal` runs, in order:
   - `before("agent.create")`
   - `prepareSessionConfig` (Paseo MCP injected unless a non-internal `paseo` entry exists)
   - `before("agent.session_open")`
   - `createSession`
   - `registerSession` (stored record)

So a plugin whose id sorts after `rooms` can re-add MCP servers or preapprovals after our guard. The final config is observable only in the stored record, `$PASEO_HOME/agents/<cwd slug>/<id>.json`. On 0.14, `agent.open.before` would be a new path; it does not exist in 0.13.2 and is not handled.

**What changed:**
- New `server/gateway/tripwire.ts`. The slug function matches the server's.
- The gateway now creates fork agents **without a prompt**, waits for the stored record, and verifies:
  - `mcpServers` is exactly `{paseo: inert}`;
  - no server URL contains `/mcp/agents`;
  - there are no preapprovals.
- Only then is the prompt sent. On failure the agent is archived, the lane is refused, and `room_agent_tripwire` is logged.
- The same check runs:
  - at every fork-lane endpoint start (the lane stays offline with `blockedReason`);
  - in `before("agent.session_open")` for resumes of fork-lane agents, which throws to refuse the open.
- A missing record fails closed.

**Tests:** `tripwire.test.ts` has 6 tests:
- slug parity with the e2e path;
- good and bad configs;
- the stored-record read, including path validation;
- the resume refusal;
- the allowlist;
- the guard.

`lane-endpoint.test.ts` checks that a blocked lane never contacts the daemon.

**Evidence:** in the e2e, the fork was created, verified and then prompted. "Fork first turn finished", the stored inert server and the process-level check passed: fork Paseo MCP 0, inert 2, parent control 1.

## C-iso3 (P-28): provider allowlist

**What changed:**
- New `shared/policy.ts`: `FORK_VERIFIED_PROVIDERS = ["claude"]`, matched exactly on the provider id before `/`. Custom ids and profiles are refused.
- It replaces the opencode/omp denylist in the gateway, the `agent.create` guard (which now throws) and the Open room UI.
- **How claude was verified:** the M1 e2e plus this run. The stored config holds only the inert server, no live provider process carries the fork's `/mcp/agents?callerAgentId=` URL, and the positive control holds.
- **Not on the list:**
  - Codex has not been run through that check.
  - opencode and omp get native tools through the launch context, which no hook can remove.
- The procedure to add a provider is documented in `shared/policy.ts`.

**Tests:** `tripwire.test.ts` (allowlist and guard).

## Isolation decision in code

**What changed:**
- `filter.ts` denies `PROMPTING_INBOUND` (classification `future_role` steer or approve, generated) plus a fixed list (send, permission response, cancel, abort, create, clear attention, fork context) **before** the table check. The deny reason is `owner_uid_lane_not_promptable`.
- `assertOwnerUidLaneIsWatchOnly()` makes a lane endpoint refuse to start if the table ever allows one of them.
- `M1_LANE_RUNNER = "owner-uid"` is the only runner kind.
- Doc notes say that steering requires sandboxed lanes, a future runner node kind: `agent-guard.ts`, `filter.ts`, README, OVERVIEW, `room-profile-v1.md`.

**Tests:** `field-policy.test.ts` "isolation guard". The e2e `sendAgentMessage` and `cancelAgent` denials pass.

## Deferred or not in scope

- **Protocol-touching D items:** P-9, P-15/C-7, P-23/C-8, P-20/C-15, C-10, P-27, plus P-16, P-24, P-25. These belong to identity v2.
- **Renew and status rate limits** (P-17 remainder).
- **P-19 UI:** fork context preview and the share-live warning.
- **Other ui-notes:** pill lag (10), closed-lane archiving (11), routed-host plugin screen (12).
- **Real-app UI check.**

## New findings

1. **Baseline `npm run typecheck` was red** because of the reviewer's unrun scaffolding, `review/attack/lib.ts(159)`. `review/` is now excluded in `tsconfig.json`. The file itself was not edited.
2. **`fetch_agent_timeline_response.agent`** carries a full agent snapshot (prompts, session id) and was not in the C-3 list. It is now sanitised.
3. **`ProjectPlacement.projectKey`** contains `host:<owner serverId>:<absolute path>` or the git remote. It is now redacted.
4. **Internal `RawDaemon` sessions** (directory and scope lookups) ran in legacy mode, so the daemon broadcast every agent's streams to them. They now use modern mode.
5. **Unbounded viewer strings** (`clientType`, `appVersion`) were logged on every link and route hello. They are now clipped.
6. **The daemon's default for `fetch_agent_timeline_request`** with `direction: "after"` and no `limit` is unlimited. It is not clamped, because clamping would change catch-up semantics.
7. **The 0.13.2 Command Center has no visibility predicate**, so "Open room…" cannot be hidden per agent. An upstream request is worth filing.
8. **Running the e2e deletes the previous `test/e2e/logs/*.log`.** That evidence was preserved by copying it first. The runner should archive old logs itself.
