# Room Profile v1 (watch role)

- **Status:** implemented in Milestone 1. Generated table `server/room-profile/generated.ts`; bindings in `server/room-profile/filter.ts`; endpoint in `server/gateway/lane-endpoint.ts`.
- **Protocol pinned:** `@getpaseo/protocol` 0.13.2 (215 inbound and 234 outbound session message types).

## 1. Sources of truth

| Artifact | Role |
|---|---|
| `profile/classification.csv` | Checked-in table, one row per protocol type and direction: `daemon_permission`, `future_role` (watch, steer, approve, owner, never), `m1_watch` (forward, gateway, deny), and the binding or the reason for denial. Seeded from the Phase 0 message classification (design research, not published) by `tools/seed-classification.py`, then reviewed. |
| `tools/gen-room-profile.ts` | Enumerates the `type` literals of `SessionInboundMessageSchema` and `SessionOutboundMessageSchema` from the installed protocol package and writes `generated.ts`. It exits non-zero if any type is unclassified, stale or duplicated. |
| `test/unit/room-profile.test.ts` | Conformance: fails if any protocol type is unclassified, if `generated.ts` is stale, or if the allowed set in the table differs from the set of types with an implemented binding. |
| `profile/fields.csv` | Field-level review (added in the hardening pass, B2): one row per field of every allowed message (inbound message, outbound payload), of the upstream `hello` and its capabilities, and of the objects the gateway forwards (`AgentSnapshot`, `WorkspaceDescriptor`, `ProjectPlacement`, `AgentListEntry` and their nested objects). Action: `keep`, `drop`, `redact` or `gateway` (a handler in `server/room-profile/sanitize.ts`), `nested` (its own table), `force` (capabilities only). Generated into `FIELD_POLICY`. |
| `test/unit/field-policy.test.ts` | Field conformance: fails if the installed protocol has a field that `fields.csv` does not list, if a listed field no longer exists, if an allowed type has no field table, or if a `redact`/`gateway` field has no handler. Also checks that sanitised messages still parse with the protocol schema. |

## 2. Review of the Phase 0 flags

All 121 rows flagged in Phase 0 were reviewed (17 allowed, 104 denied) with the rule "unclear means deny". In M1 only types with an exact scope binding are allowed. Outcome by Phase 0 note:

| Phase 0 note | Rows | M1 decision |
|---|---|---|
| read op not in watch profile | 30 | deny (no scope binding; includes `wait_for_finish_request`, file explorer, checkout reads) |
| write op: maybe steer | 42 | deny (steer and maintain are not in M1) |
| terminal I/O | 10 | deny (code execution; owner only) |
| workspace-read push | 11 | deny (no lane-scoped filter; includes `agent_archived`, `agent_deleted`, `fs.file.update`) |
| filter response / filter by id | 26 | 15 allowed (forward or gateway) because M1 implements their binding; 11 deny (diff, search, subagent and checkout types) |
| status | 1 | gateway (only `server_info`, rewritten) |
| permission resolved needs workspace.write | 1 | forward (agent-scoped; clears a displayed prompt) |

Of the 328 unflagged rows, 7 are allowed (the core watch requests and their list types) and 321 deny.

## 3. Allowed types

**Inbound** (everything else: immediate `rpc_error` `access_denied` if the frame has a `requestId`, otherwise dropped):

| Type | Action | Binding |
|---|---|---|
| `fetch_agent_request`, `fetch_agent_timeline_request` | forward | `agentId === lane.agentId`, exact. The daemon resolves prefixes and titles otherwise. |
| `agent.timeline.set_subscription.request` | forward | `agentIds` non-empty, every id is the lane agent |
| `session.events.set_subscription.request` | forward | events narrowed to `agent_attention_required`, `agent_permission_request`, `agent_permission_resolved`, `status.server_info`; `notifications: false` |
| `subscription.release.request` | forward | id-free; acts only on the viewer's own upstream session |
| `fetch_agents_request`, `fetch_workspaces_request` | gateway | forwarded for subscription and sync metadata; entries are discarded and rebuilt by the gateway |

**Outbound:** responses only for request ids the viewer was allowed to send; `rpc_error` likewise; pushes `agent_update`, `workspace_update`, `agent_stream`, `agent.timeline.replacement`, `agent_status`, `agent_permission_request`, `agent_permission_resolved`, `agent_attention_required` only when their agent or workspace id is the lane's. List responses: `pageInfo` emptied, `emptyProjects` emptied, `sync.removals` filtered, entries replaced by the gateway-built lane entry (`fetch_agent`, and an internal walk over `fetch_workspaces` pages because 0.13.2 has no single-workspace fetch).

### 3.1 Field level (hardening pass)

Every forwarded object is rebuilt from its field table; fields not in the table are dropped, so a protocol bump cannot add a forwarded field silently. Main decisions (full table in `profile/fields.csv`):

- **Agent snapshot** (`fetch_agent_response`, `fetch_agents_response` entries, `agent_update`, `agent_status.info`, `fetch_agent_timeline_response.agent`): `cwd` becomes `/room/<basename>`; `persistence` is null (its metadata carries the system prompt, the daemon-wide appended prompt, the tool policy and the provider session id); `runtimeInfo.sessionId` null and `extra` dropped; only `rooms.*` labels (drops `paseo.parent-agent-id`); `lastError` generic.
- **Workspace descriptor:** paths become `/room/<basename>`; `scripts` empty; `githubRuntime` and `diffStat` null; `gitRuntime` keeps only `currentBranch` and `isPaseoOwnedWorktree`; `status`, `statusEnteredAt`, `activityAt` and `lastUserMessageAt` are derived from the lane agent only (the daemon aggregates every agent in the workspace).
- **Project placement:** `projectKey` becomes `room:<laneId>` (the daemon key is a git remote or `host:<serverId>:<path>`); checkout paths redacted, `remoteUrl` null.
- **Project names** (decisions round 2): hidden by default. `projectName`, `projectDisplayName`, `projectCustomName`, and a workspace `name`, `title` or `workspaceName` equal to the project or project folder name become the neutral label `<room name> · <lane label>`; path basenames become `/room/folder-<keyed hash>` (per-process key, so equal paths stay equal). The owner opts in per room (`rooms.settings.set`, persisted in gateway state, logged as `room.policy.changed`); the policy object is shared by the lane's routes, and open routes get fresh agent and workspace upserts. Names already shown are not recalled.
- **Notifications:** `notification.data.serverId` (pushed and in legacy `agent_stream` attention events) becomes the lane serverId.
- **Errors:** `rpc_error.error`, response `error` fields, `lastError`, `turn_failed.error` (and `diagnostic`, dropped) and timeline items of type `error` (live and in history) are replaced by a generic text. The original goes to an in-memory, owner-only per-lane log (50 entries, deduplicated) that the owner's app reads through the local plugin RPC `rooms.lane.errors`; it is never sent over the lane endpoint.
- **Directory sync:** inbound `sync` cursors are dropped, so the daemon answers with a snapshot; `headSeq`, update `seq` and entry `syncSeq` are rebased on a per-route counter and `generation` is a per-route opaque value, so the daemon's change counts do not reach the viewer.
- **Inbound:** each allowed request is rebuilt from its table (unknown fields, `includeInternal`, `includeBackground`, `idPrefix` and `sync` dropped); `fetch_agent_timeline_request.limit` 0 or above the limit becomes the limit (default 1000). A request with no `limit` and `direction: "after"` still returns every later row (daemon default).
- **Upstream hello:** built from constants, never from the viewer's object: gateway clientId per (lane, member, route slot); `clientType` constant; `owned_subscriptions`, `explicit_event_subscriptions`, `selective_agent_timeline` and `hello_rejection` forced on; rendering-format flags copied only when true; `voice`, `pushNotifications`, `browser_host` and unknown capabilities dropped.

### 3.2 Owner-uid isolation guard

Inbound types whose `future_role` is `steer` or `approve` (plus a fixed list: send, permission response, cancel, abort, create) are denied before the table is consulted, and a lane endpoint refuses to start if the table allows any of them. Lanes run as the owner's OS user, so prompting by members requires sandboxed lanes, not a table edit.

## 4. `server_info`

- Routed virtual session: `serverId` = lane serverId, `permissions: ["workspace.read"]`, features = the kept data-shape flags present upstream (`ownedSubscriptions`, `directorySync`, `selectiveAgentTimeline`, `explicitEventSubscriptions`, `canonicalSubmittedPrompts`, `agentMessageProvenance`, `stableProjectIdentity`, `workspaceMultiplicity`, `pluginTimelineItems`, `agentThinkingUpdate`, `workspaceSortTimes`, `projectedSubagentTimeline`) plus `relayProtectedSecurity` and `connectedHosts`.
- Physical link session: `connectedHosts`, `hostMultiplexing`, `relayProtectedSecurity` only.
- `connectedHosts` on routed sessions is required by the member daemon to accept a route. `hosts.*` requests are still denied.

## 5. Defence in depth

- Each routed scope gets its own upstream session to the local daemon with `hello.sessionPermissions: ["workspace.read"]` (honoured per permission on 0.13.2) and a gateway-chosen clientId fixed per (lane, member, route slot): `rooms-lane-<laneId>-watch-<hash>`. The viewer's `clientId` is ignored, so a viewer cannot create unbounded retained daemon sessions. Directory and scope lookups use separate clientIds.
- Binary route frames (terminal and file streams) are dropped.
- Resource limits (`server/limits.ts`, defaults): 32 relay connections per lane, 2 links per member, 16 routes per link and 32 per member, 1 MiB inbound frames, 256 KiB routed messages, 64 queued requests before the upstream is ready, 256 tracked request ids per route, 2048 queued upstream messages per route, 50 frames/s (burst 200) per link. Deny logs are clipped and rate limited.

## 6. Upgrading Paseo

Bump `@getpaseo/protocol`, run `npm run gen:profile`. New types fail generation until a row is added to `classification.csv`; new fields of allowed messages or forwarded objects fail generation until a row is added to `fields.csv`. Review both with the same rule (unclear means deny or drop), then run `npm test`.
