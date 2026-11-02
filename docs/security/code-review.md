# paseo-rooms M1: independent code review

- **Date:** 2026-10-28
- **Scope:** `plugin/` (server, shared, client entry, profile CSV, tests, docs). Checked against `@getpaseo/protocol` 0.13.2 (installed) and `@getpaseo/server` 0.13.2. The server package was unpacked read-only with `npm pack` to a scratch directory, which has since been deleted.
- **Executed:** reading the source; `npm test` (28/28 pass); `npm run typecheck` (clean).
- **Not executed:** the attack tests in task C, including the restart tests, the flaky-enrollment repetition and the runtime agent-isolation inspection. No test daemons were started, no agents were created, and `.homes` was never created. Section 4 explains why. Every runtime claim below is therefore **unverified** and is based on source inspection only.

## 1. Findings

Severity is for M1 as shipped (watch only). "Blocks M2" means the finding must be fixed before members can steer, or before the plugin is used outside a test setting.

| ID | Sev | File:line | Description | Evidence | Fix | Blocks M2 |
|---|---|---|---|---|---|---|
| C-1 | High (M1: Medium) | `server/gateway/gateway.ts:149-157`, `agent-guard.ts:213-218` | **Room-agent isolation covers only the MCP entry named `paseo`.** The fork runs as the owner's uid with the daemon's environment. Paseo's provider env sanitizer removes only runtime-control keys, so `PASEO_HOME` and the rest of the daemon env pass through. The fork also runs with `cwd` = the parent's cwd. Claude runs with `settingSources: ["user","project","local"]`, so user-level, project and plugin MCP servers load unless they happen to be named `paseo`. From inside the agent, `$PASEO_HOME/local-credential` and `~/.paseo/local-credential` are readable by the same uid, the `paseo` CLI is reachable, and so is `127.0.0.1:<daemon port>`. Any shell-capable tool therefore gives full owner control of both the test daemon and the main daemon. This is harmless in M1, where no member input reaches the agent, but it is the confused-deputy path of architecture section 10 once members steer. | Source: server 0.13.2 `paseo-env.js` (`RUNTIME_CONTROL_ENV_KEYS` lists only `PASEO_NODE_ENV`, `PASEO_DESKTOP_MANAGED`, `PASEO_SUPERVISED`, `ELECTRON_*`, `ESBUILD_BINARY_PATH`); `agent/providers/claude/agent.js:44,2875` (setting sources); `provider-launch-config.js:84` (env copied from `process.env`). Runtime env inspection was not run (section 4). | Before M2: run room agents in a sandbox (separate uid, or bubblewrap/landlock with no access to `PASEO_HOME`/`~/.paseo`, network namespace or egress allowlist). Strip `PASEO_*` from the env overlay. Pass `--strict-mcp-config` or empty setting sources for room agents (needs an upstream per-agent option). Document that the inert-MCP measure alone is not isolation. | **Yes** |
| C-2 | Medium | `server/gateway/local-daemon.ts:300-309`; `lane-endpoint.ts:510` | **Viewer-controlled hello fields reach the owner daemon.** `buildUpstreamHello` spreads `...rest`, and protocol 0.13.2 `capabilities` is `.passthrough()`. A viewer that omits `owned_subscriptions`, `explicit_event_subscriptions` and `selective_agent_timeline` puts its upstream session in legacy mode. The daemon then broadcasts all agents' streams, events and binary frames to it, and `session.events` narrowing has no effect. Today the outbound filter still drops these, so it is the only gate left. The upstream `clientId` also hashes the viewer-chosen `hello.clientId`, so each distinct value creates a retained owner session (kept about 90 s after disconnect). | Profile audit R2 and R6 (`session.js:6781` legacyWantsEvent; `websocket-server.js:262`). | Build upstream capabilities from an allowlist and force the three modern flags to true. Drop `pushNotifications`, `voice` and `browser_host`. Derive the upstream clientId from (lane, member, route slot), not from viewer input. | Yes |
| C-3 | Medium | `server/gateway/lane-endpoint.ts:559-569`; `room-profile/filter.ts:131-160,165-172` | **Lane-scoped objects carry data from outside the room.** The workspace descriptor (`fetch_workspaces_response` built entry and `workspace_update`) includes `projectRootPath`, `workspaceDirectory`, the git remote URL, PR and check details, and `scripts[]` with ports, `terminalId` and proxy URLs (the public service proxy is unauthenticated). It also includes status, activity and diff aggregates over all agents in the shared workspace, which shows the parent's activity. The agent snapshot (`fetch_agent_response`, `agent_update`, `agent_status`) includes `persistence.metadata`, with `systemPrompt`, `daemonAppendSystemPrompt` (daemon-wide), `toolPolicy`, `cwd`, the label `paseo.parent-agent-id` and the provider session id. | Profile audit R3 and R5 (protocol `messages.js:3522` workspace descriptor; server `agent-projections.js:322`, `claude/agent.js:2292`). Partly known as open issue 3 and D1. | Gateway-built minimal entries using a field allowlist: workspace `{id, projectId, name, status derived from the lane agent}`, empty `scripts`, null git and GitHub runtime. Agent snapshot without `persistence.metadata`, `runtimeInfo.extra` or non-`rooms.*` labels. Apply the same allowlists to the pushes. | Yes |
| C-4 | Medium (DoS) | `lane-endpoint.ts:140-145,209,404,469-471,591-596`; `local-daemon.ts:290` | **Unbounded resources per member and per key holder.** There is no cap on relay connections per lane or on links per grant. Each link allows 128 routes, and each routed hello opens its own upstream daemon socket. `pendingToUpstream` is unbounded before the upstream is ready. The `forwarded` map is never pruned (one entry per request id for the route's lifetime). `listRequests` grows when responses are dropped. `maxPayload` is 100 MB on both the relay and the upstream sockets. Every pre-auth connection costs a socket plus 15 s + 15 s timers, and anyone holding the lane public key (every past invitee, including revoked ones) can open them. | Code inspection. Not measured. | Cap links per member (for example 2) and connections per lane. Count routes per member, not per link. Bound the pending queue and the maps (delete on response; cap size and close the route on overflow). Lower `maxPayload` to a few MB. Add a per-link token-bucket rate limit. | Yes |
| C-5 | Low | `lane-endpoint.ts:427,586`; `log.ts:410` | **Log injection and log flooding.** `link_deny` and `route_deny` log the viewer-supplied `m.type` without length limits (up to `maxPayload`). | Code inspection. | Truncate `type` to 64 characters and rate-limit deny logs. | No |
| C-6 | Low | `filter.ts:173-179` | The owner daemon's real `serverId` leaks in `agent_attention_required.payload.notification.data.serverId` and in legacy attention `agent_stream` events. | Profile audit R1 (`websocket-server.js:2090-2137`). | Rewrite the field to the lane serverId, or drop `notification`. | No |
| C-7 | Low | `host-store.ts:328-337` | **Anyone with the lane key can burn every open invite.** Five bad tokens burn all open invites of the lane. The failure is counted before any signature or membership check, and the attacker needs only the lane offer, which every past invitee has. | Code inspection. Matches open issue 5, but the cross-invite burn is not stated there. | Count failures per connection or per device key with backoff, not per lane. Optionally bind invites to an id hint sent in the hello so that only that invite is counted. | No |
| C-8 | Low | `control-server.ts:293-294`; `host-store.ts:399-411` | **Unauthenticated membership oracle.** `memberForDevice` runs before the signature check, so `status` with any device public key and a garbage signature reveals `revoked`, `not_member` or `lane_closed`. | Code inspection. | Verify the signature first, then look up membership. Return one generic error for all failures. | No |
| C-9 | Low | `host-store.ts:121-124,454` | Revocation uses a deny-list that is pruned at `exp`. It is correct today because `verifyGrant` rejects `exp <= now` with no leeway, but it is fragile: any future exp leeway or clock change reopens revoked grants. | Code inspection. | Also require `claims.gid === latestGrant(sub).gid` (allow-list). This makes the deny-list redundant. | No |
| C-10 | Low | `member/member.ts:355-386` | **Enrollment is not atomic on the member side.** If `register()` (`hosts.add`/`hosts.update`) throws after a successful enroll, the invite is consumed and the gateway has an active member, but the member keeps no record, so a retry fails with `token_used`. Errors from the Paseo client can have empty messages. | Code inspection. A candidate for the flaky failure (section 6), but it does not match M1's note that the gateway never saw the enrollment. | Persist the record (with grant id and expiry) before `register`. Retry `register` and log `error.code` and `name`. | No |
| C-11 | Low | `host/event-log.ts:62-66,70-74`; `host-store.ts:136-138` | A torn or corrupt last log line makes `readAll` throw, so every later `record()` for that room throws. That happens after `save()`, so state and log diverge and owner RPCs fail. | Code inspection. | Tolerate and quarantine a torn final line. Record the log entry before (or in the same step as) the state change. | No |
| C-12 | Low | `member/member.ts:264-269`; `runtime.ts:130-137` | Member rotation timers re-arm only on first contact (an RPC, a hook or the app's bootstrap). After a member daemon restart with no app contact, grants expire unrotated (U2). | Code inspection. Not run. | Arm timers at `contribute()` time from `rooms.json`. The PaseoApi is needed only for `hosts.update`, so defer only that step. | No |
| C-13 | Low | `lane-endpoint.ts:111-116` | If the lane agent is archived or deleted, `start()` retries every 10 s forever and the lane stays `open` (log spam; invites can still be created). | Code inspection. | Back off, then mark the lane as degraded or closed and log the event. | No |
| C-14 | Info | `server/crypto.ts:83-85,133-140` | Base64url decoding is lenient, so several signature encodings verify (for example with `=` padding). This is harmless because revocation keys on `gid`, but any token-string deny-list or cache would be bypassable. | Code inspection. | Require the canonical 86-character `[A-Za-z0-9_-]` form before decoding. | No |
| C-15 | Info | `schemas.ts:26-29`; `member.ts:346-364` | The invite chooses the relay endpoint, and `useTls: false` is allowed, so the member daemon connects wherever the invite says. The grant stays inside Noise, so this is not a secret leak, but it is an SSRF-style primitive and the UI does not show a non-default relay. | Code inspection. | Warn on a non-default relay or non-TLS, and allow-list relays in member settings. | No |
| C-16 | Info | `filter.ts:129-130` | `rpc_error` for forwarded ids passes the daemon's exception text through, which can include filesystem paths (audit R7). | Audit. | Replace the text with a generic message. | No |

Checked and found sound (by reading only): exact-id binding with `===` and no prefix, title or case match; the `hasOwnProperty` table gate (`__proto__` and similar keys are denied); `requestId` tracking per route; grant claims parsed with zod after signature verification over the exact string; issuer, audience, lane and expiry checks; transcript binding of nonce, lane, host key and token hash; one-time invites (`enroll` is synchronous, so concurrent enrollments with one invite cannot both succeed); revocation pushed synchronously before the RPC returns; atomic 0600 writes in 0700 directories; secret-key redaction in the logger.

## 2. Room Profile audit (allowed types)

The audit is from source inspection against protocol and server 0.13.2. RISK ids refer to the C-n findings above.

| Type | Dir | Verdict | Reason |
|---|---|---|---|
| fetch_agent_request | in | OK | Schema has only `agentId`. Exact match, so the daemon's prefix and title resolution never runs. |
| fetch_agent_timeline_request | in | OK | `direction`/`cursor`/`limit`/`projection`/`mergeWindow` only; no subagent selector. `limit:0` returns all rows (cost only). |
| agent.timeline.set_subscription.request | in | OK | Only `agentIds`, and every id must be the lane agent. No cap on the number of subscriptions (C-4). |
| session.events.set_subscription.request | in | RISK (C-2) | Narrowing is correct, but it has no effect in legacy mode. |
| subscription.release.request | in | OK | Acts only on the caller's own source. |
| fetch_agents_request | in | RISK (Low) | Filters and `subscribe`/`sync` run daemon-wide. Entries are discarded, but `sync` metadata passes through (open issue 3). |
| fetch_workspaces_request | in | RISK (Low) | Same as `fetch_agents_request`. |
| fetch_agent_response | out | RISK (C-3) | Snapshot leaks `persistence.metadata` and labels. |
| fetch_agent_timeline_response | out | OK* | Agent-scoped. Items can include absolute attachment paths and tool I/O, which is inherent to watching. No download path is reachable. |
| fetch_agents_response | out | RISK (C-3, open issue 3) | `...p` keeps `sync` headSeq/generation, plus the snapshot issue. |
| fetch_workspaces_response | out | RISK (C-3) | Workspace descriptor leaks paths, git, scripts, proxy URLs and aggregates. |
| workspace_update | out | RISK (C-3) | Same descriptor, pushed live. |
| agent_update | out | RISK (C-3) | Snapshot, plus `seq`/`generation` counters. |
| agent_status | out | RISK (C-3) | `info` is the full snapshot. |
| agent_stream | out | OK* | Agent-scoped. In legacy mode, attention events carry the owner's serverId (C-6). |
| agent.timeline.replacement | out | OK | Only `agentId` and `epoch`. |
| agent_attention_required | out | RISK (C-6) | `notification.data.serverId`. |
| agent_permission_request | out | OK* | Tool input can show paths and commands. Watch content. |
| agent_permission_resolved | out | OK | Agent-scoped. |
| agent.timeline.set_subscription.response | out | OK | Only for forwarded ids. |
| session.events.set_subscription.response | out | OK | `requestId`/`subscriptionId` only. |
| subscription.release.response | out | OK | Same. |
| rpc_error | out | OK* (C-16) | Only for forwarded ids. Carries exception text. |
| status | out | OK (Info) | `server_info` is rebuilt. Only the daemon `version` and `protocolVersion` pass through. |

Totals: 11 OK (4 of them OK* = OK, watch content only), 13 RISK. None of the RISKs exposes another agent's timeline or allows a write. They leak workspace or daemon metadata, and the legacy-mode issue removes one layer of defence.

## 3. Attack-test results

**Not executed.** I wrote harness scaffolding under `review/attack/` (`env.sh`, `lib.ts`, `isolation-sampler.ts`, `.gitignore`). The main attack driver was not completed, so none of the planned C tests ran. That driver covered fuzzing, grant replay, revocation and expiry, forgery, invite reuse, concurrent enrollment, revoke during enrollment, invite burning, the membership oracle and binary frames.

| Test group | Result |
|---|---|
| Lane endpoint and filter fuzzing (schema-invalid, oversized, unknown types, prefixes, titles, case, traversal, duplicate request ids, foreign binary frames) | NOT RUN |
| Old/rotated, revoked, expired, forged or tampered grants and invites; invite reuse; concurrent enrollments; revoke during enrollment | NOT RUN |
| Unit suite (`npm test`) | PASS 28/28 (existing tests, not mine) |
| Typecheck | PASS |

## 4. Why task C did not run, and restart results

A safety stop interrupted the attack driver while I was writing it. I did not retry it in another form. No daemons were started on ports 6900-6909, no agents were created (0 of 2 used), and no `.homes` directory exists, so nothing needs cleanup. The main daemon and `~/.paseo` were not touched.

Restart tests (owner C and member A, idle and with a live view; persistence of keys, room log and revocation list; rotation after restart): **NOT RUN**. From the code alone:

- Keys, `state.json` (revoked gids, members) and `events.jsonl` are persisted atomically or append-only and reloaded at construction.
- Endpoints restart from `state.json`.
- Revocation should hold after restart, because the member status and the revoked gids are persisted.
- Member timers do not re-arm without contact (C-12).

## 5. Flaky enrollment

Not reproduced (the N≥20 loop did not run). Candidate causes from the code:

1. A connect failure surfacing as an `AggregateError` with an empty message. The control client now retries this and reports error codes.
2. `register()` failing after a successful enroll (C-10). This consumes the invite with no local record. It conflicts with M1's observation that the gateway saw no enrollment, unless the gateway log was missed.
3. `hosts.list()` returning a registration that is still being removed. `end()` → `hosts.remove` runs about 0.7 s earlier, and `register` then calls `hosts.update` on a stale id.

Next step: run the loop with the plugin logging `error.name` and `code`, and with C-10 fixed.

## 6. Agent isolation

Runtime inspection of the fork's process was not run. The source-level result is C-1:

- The env contains `PASEO_HOME`.
- Same uid, mount and network namespace (no sandbox in the claude provider).
- The local credential files are readable.
- User, project and plugin MCP servers load through the setting sources.

`review/attack/isolation-sampler.ts` is ready to confirm this. It records env var names, the MCP config server names (URLs without the query string), setting sources, namespaces and credential readability, without printing values.

## 7. Next steps

1. Fix C-1 to C-4 before M2.
2. Run task C with a reviewed harness, as a separate, approved step.
3. Add regression tests:
   - legacy-mode hello (C-2);
   - field allow-lists on snapshots and workspace entries (C-3);
   - per-member link and route caps (C-4);
   - a signature check before the membership lookup (C-8).
