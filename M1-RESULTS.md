# Paseo Rooms plugin: Milestone 1 results

- **Date:** 2026-10-28
- **Status:** built, typechecked, unit-tested and end-to-end tested against two disposable Paseo 0.13.2 daemons and the live relay (`relay.paseo.sh:443`). **The client UI was not exercised in a real Paseo app** (it compiles in the daemon's plugin compiler and typechecks).
- **Plugin:** `plugin/` (id `rooms`, package `paseo-rooms`, `requirements.paseo >=0.13.2`). Map of files to the architecture doc: `README.md`.
- **Plugin docs used:** the paseo-plugin skill plus `public-docs/plugins/*.md` from the local Paseo checkout (main, 0.14.0-beta.2) and the published `@getpaseo/plugin@0.13.2` / `@getpaseo/server@0.13.2` type definitions and dist. paseo.sh was not fetched because the task's network allowlist excludes it.

## 1. Scope versus delivery

| # | Scope item | Status | Evidence |
|---|---|---|---|
| 1 | shared/: versioned zod schemas (Room, Lane, Grant, RoomEvent, invite codes, control frames), RPC contracts | **Done** | `shared/schemas.ts`, `shared/control.ts`, `shared/rpc.ts` |
| 2 | Generated Room Profile, checked-in classification, conformance gate, exact-id binding, gateway-built lists, immediate `rpc_error`, feature flags incl. `connectedHosts` exceptions | **Done** | `profile/classification.csv`, `tools/gen-room-profile.ts`, `server/room-profile/*`; 9 conformance tests; e2e 12/12 denials |
| 3 | Gateway: room + lane on owner daemon; origins share live and fork; fork via paged `timeline.refetch`, parent link, labels; MCP removal for room agents; lane endpoint with connected-hosts destination side; capped upstream; pushed revocation and expiry; keys under `plugin-data/rooms` | **Done**, with deviations D1-D4 | e2e: fork, share lane, MCP check, revocation 19-23 ms, expiry cut +70-74 ms |
| 4 | Embedded host: membership, Ed25519 grants (lane-scoped, per member daemon, TTL), revocation list, signed hash-chained log | **Done**; log is signed plaintext (D5) | unit tests; e2e log verified (12 events) |
| 5 | Invite + enrollment over the lane's relay channel with mutual auth; `hosts.add`; spec in docs/specs | **Done** | `docs/specs/rooms-control-protocol.md`; e2e enroll 241-246 ms; one-time check |
| 6 | Member role: joined rooms, `hosts.observe`, rotate on auth failure or near expiry only when idle, removal | **Done**; auth-failure *success* path not exercised (U3) | e2e: deferred while busy, expired rotation, idle rotation, revocation handled |
| 7 | Client UI: Command Center "Open room…", Open room screen, Rooms screen + sidebar item, composer pill | **Built, not seen in a real app** (U1) | typecheck; daemon compiled the client bundle on install; RN-only audit clean |
| 8 | Tests: unit (profile/filter, grants/revocation, log) and two-daemon e2e | **Done** | 28/28 unit; e2e 42/42 checks in the final run; 5 of 6 runs green (one flaky failure, open issue 8) |

## 2. Test evidence

**Commands** (from `plugin/`): `npm run typecheck` (clean), `npm test` (28 pass, 0 fail), `npm run test:e2e` (exit 0). Logs of the last run: `test/e2e/logs/` (`run-output.txt`, `e2e.log`, daemon and plugin logs, `secret-scan.json`).

**Last e2e run** (C = owner `127.0.0.1:6891`, A = member `127.0.0.1:6892`, both 0.13.2, relay registration off, speech off):

| Check | Result |
|---|---|
| Plugin installs and runs on both daemons | `running` on both (server and client bundles compiled by Paseo, deps `ws`, `@getpaseo/relay`, `@getpaseo/protocol` bundled) |
| `rooms.create` (fork) | 64-70 ms RPC (agent creation is asynchronous); fork agent created with `parent` link, labels `rooms.lane`, `rooms.room`, `paseo.parent-agent-id`; curated context 2 messages, 55 chars |
| Share-live lane | bound to the parent itself (no new agent); endpoint online on the relay in 255 ms; closed afterwards |
| Invite | `prc1.` code, 661 chars, one-time (reuse refused: "Invite was already used") |
| Enrollment from A via plugin RPC | 241 ms including relay round trips; lane host `online` on A, source `plugin:rooms` |
| Routed lane through A (app-style `DaemonClient` + `createHostChannelTransport`) | connect 73 ms; `server_info.serverId` = lane; `permissions ["workspace.read"]`; 14 feature flags (12 kept + `relayProtectedSecurity` + `connectedHosts`) |
| Exactly one agent | `fetchAgents` = [fork]; 1 workspace; although the parent lives in the same workspace on C |
| Denials (all `Room is not authorized for …`, 33-39 ms) | parent by id, random id, 8-char prefix, title, parent timeline, send, cancel, archive, terminals, daemon config, `hosts.list`, plugin RPC on the routed session |
| Live timeline | prompt on C → `turn_started`, `user_message`, `assistant_message`, `turn_completed` through the lane; 0.8-1.0 s for the whole turn |
| Owner view and pill data | 1 connected member, 1 active route, endpoint online; `rooms.lane.agents` lists the fork |
| Revoke | RPC 2 ms; `cutLinks 1`, `cutRoutes 1`; routed client disconnected **19-23 ms** after the call; later fetch fails |
| Member-side revocation | A sees `authentication_failed` (Paseo reports it about 5-7 s after the rejection), rotates, gets `revoked`, removes the host and marks the room revoked: 7.5 s end to end |
| Expiry (30 s grant, route open) | half-life rotation deferred 3 times (`activeRoutes 1`); link cut **+70-74 ms after `exp`**; member rotated 1.5 s after the cut (`hosts.update`); open view back 3.1 s after the cut |
| Idle rotation | with no routes open, rotation at half-life, 14.3 s before expiry |
| Leave | host removed on A; `member.left` logged |
| Room log | 12 events, chain and signatures verify (`room.created`, `lane.created` ×2, `lane.closed`, `invite.created` ×2, `member.joined` ×2, `member.revoked`, `grant.renewed` ×2, `member.left`; the fork lane is closed after the check) |
| Files | `plugin-data/rooms` 0700; `state.json`, `host-key.json`, `device.json`, `rooms.json` 0600; gateway state holds no grant |
| Secret scan | 8 secrets tracked (2 invite codes, 2 tokens, 4 grant signatures); 42 files scanned (both homes incl. daemon logs and plugin data, all e2e logs): **0 unexpected files**. No `prc1.`/`prg1.` strings in any log |
| Speech models | no download started (`features.dictation/voiceMode.enabled: false` before first start, plus env) |
| Cleanup | agents archived; plugin removed; daemons stopped; ports 6891/6892 closed; homes deleted; main daemon pid 3244997 unchanged throughout |

**Throwaway agents.** Each e2e run creates exactly two agents (parent, fork) with "Reply with the word OK" prompts: three turns per run. I ran the e2e six times: the first stopped at plugin install (an RPC name with an uppercase letter is rejected), before any agent. So ten agents and up to fifteen short Claude Haiku turns in total, all archived. Archiving the parent also archives its fork in 0.13.2; the cleanup handles `AGENT_ALREADY_ARCHIVED`.

## 3. MCP removal (scope item 3): verified, with limits

**Source facts** (`@getpaseo/server@0.13.2`, `dist/server/server/agent/agent-manager.js` `createAgentInternal` and `prepareSessionConfig`; `agent/runtime-mcp-config.js`):

1. `before("agent.create")` runs before Paseo injects its control MCP.
2. Injection adds `mcpServers.paseo` (HTTP, `/mcp/agents?callerAgentId=…`) **unless** the config already has a server named `paseo` whose URL path is not `/mcp/agents`.
3. Deleting the key in the hook does nothing: the internal entry is stripped and re-injected.
4. The only other switch is daemon-wide (`providers.<id>.paseoTools.enabled`, `daemon.mcp.injectIntoAgents`), not per agent.
5. Providers with native Paseo tools (OpenCode with a bridge, omp) receive the tools through the launch context. A hook cannot remove them.

**Implementation:** room agents get `mcpServers.paseo` = an inert stdio MCP server (`plugin-data/rooms/inert-mcp.cjs`, no tools) and no `toolPolicy` preapprovals. The gateway sets this when it creates the fork, and the `before("agent.create")` guard enforces it for any create carrying `PASEO_ROOMS_LANE` in its env. Fork lanes are refused for `opencode` and `omp`.

**Verified (e2e):**
- the fork's persisted config holds the inert server;
- during the fork's live turn, no process on the machine had `callerAgentId=<fork>` in its command line, while the inert server ran (2 matching processes);
- positive control: during the parent's run, one provider process carried C's `/mcp/agents` URL.

Command lines are read from `/proc` and only counts are logged, because they contain the MCP bearer token.

**Not verified:** behaviour on resume and refresh (the stored config is reused, so it should hold); providers other than Claude; share-live lanes. A share-live lane exposes the owner's own agent, which keeps Paseo's MCP. That is a known gap against architecture section 10, which is why fork is the default.

## 4. Deviations from rooms-architecture.md

| # | Doc says | M1 does | Why / choice | Alternatives |
|---|---|---|---|---|
| D1 | Lane = branch + worktree (3, 6.4) | Lane = one agent plus its workspace. The fork runs in the parent's cwd and workspace. | Task scope is watch-only sharing; worktrees matter once members steer. The workspace descriptor (name, branch) of a shared workspace is visible to members; other agents in it are not. | Create a worktree workspace per fork lane (`workspaces.create` with worktree) in M2/M3 |
| D2 | Separate node key and host key (8.1) | One Ed25519 key signs grants and log events (embedded host) | Embedded host runs in the same process; separation adds no protection there | Split when the host becomes standalone (Phase 3) |
| D3 | Grant gives proof-of-possession (8.1) | Grant is a bearer token on the Paseo host link; device signature only on the control channel | Paseo's link hello has no PoP field | Upstream: PoP or channel-bound passwords for connected hosts |
| D4 | Gateway ↔ host and member ↔ host channels with Noise IK/XX (8.2) | Member ↔ gateway control protocol over the lane's protected relay channel (Noise NK + device signature over a nonce transcript) | Embedded host; the lane endpoint already exists and is pinned in the invite | Dedicated host endpoint with XX when the host is standalone |
| D5 | Room log content MLS-encrypted from Phase 1 (8.3, 11) | Log is signed plaintext (ids, roles, timestamps, labels) | MLS is Milestone 2 per the task | M2 moves content into MLS application messages; keep signed metadata |
| D6 | Plugin obtains `context.paseo` (implicit) | `PaseoApi` is captured on first contact (any RPC, hook, or the client entry's `rooms.bootstrap` call) | 0.13.2 gives `paseo` only to handlers and hooks, not to `contribute()`. Lane endpoints do not need it (they use loopback with the local credential); member observation starts once an app or RPC touches the plugin | Upstream: expose `server.paseo` at contribute time |
| D7 | Revocation within one second | Pushed in process: route cut in 19-23 ms. The member daemon learns of it 5-7 s later | As designed; the member delay is Paseo's (G7) | |

## 5. Verified versus unverified

**Verified:** everything in section 2; MCP shadowing (section 3); conformance gate fails on a missing type (unit test); synchronous revocation push (unit + e2e); grant tampering, wrong lane, wrong issuer, expiry; transcript binding; log tamper detection.

**Unverified:**
- U1. **Real app UI**: Rooms screen, Open room screen, sidebar row, Command Center item, composer pill, theme colors, compact layout; how the real app renders a lane host and which screens error (routed-lane spike open question). Manual checklist: install on two test daemons as in `test/e2e/run.sh` with `KEEP_HOMES=1`, add host A to an app as a direct connection, then run through the screens in a dark and a light theme and on a narrow window.
- U2. Daemon restart and plugin reload with existing rooms (endpoints restart from `state.json`; member timers re-arm on first contact).
- U3. Rotation *succeeding* after `authentication_failed`. In the e2e, expiry recovery went through the deferred rotation timer 1 s after the cut, before Paseo reported the auth failure. The auth-failure trigger itself was exercised on revocation.
- U4. Daemons with a password or a unix-socket listen address (the loopback upstream reads `paseo.pid` and `local-credential`).
- U5. Multiple member daemons on one lane, and 128-route limits.
- U6. Whether daemon trace-level logging records plugin RPC payloads. The invite code passes through `rooms.join` and `rooms.invite.create`; nothing appeared at the default log level.

## 6. Open issues

1. **Stale routed hosts in the app** after leave or revoke (Paseo G3). The UI says so.
2. **Member delay**: Paseo reports a link auth failure 5-7 s after the lane rejects it, so revocation looks "online" on the member side for that long. Data access stops at once.
3. **Workspace metadata leak** under D1, and `sync.headSeq` reveals directory change counts on C (routed-lane spike deviation 4).
4. **Any installed server plugin holds `tunnel.manage`** and can replace these host registrations (G6).
5. **The control channel accepts enrollment attempts from anyone who has the lane's serverId and key** (only invitees). Invites burn after 5 bad tokens; there is no per-source rate limit, because the relay hides the source.
6. **Log truncation** of the newest events is not detectable without an external anchor.
7. **No room archive or rename** yet; closing a lane is the only teardown. Rooms without open lanes stay listed.
8. **One flaky e2e failure (run 5 of 6).** The second `rooms.join` (after revocation) failed with an empty error message about 0.7 s after the member removed the revoked host. The gateway never saw the enrollment, so the member failed before or while opening the relay socket. A Node `AggregateError` from a failed connect (empty `message`) fits, but this is **not confirmed**. Fixes applied: the control client now retries up to three times when the socket never opened (nothing was sent, so retrying is safe) and reports the underlying error codes. The next run passed. Also fixed: the logger redacted every field named `code`, which hid control error codes; it now redacts `inviteCode` instead.

## 7. Proposed edits to rooms-architecture.md (not applied)

1. Section 3, Lane: "In Milestone 1 a lane is one agent and its existing workspace; worktree lanes arrive with steering."
2. Section 6.1, Credential: replace "The prototype polled for this; Phase 1 pushes it" with "Pushed in process: measured 19-23 ms from the owner's revoke to the cut of live routes; the member daemon reports the failure 5-7 s later."
3. Section 8.1, Device key purpose: change "proof-of-possession for grants" to "proof-of-possession at enrollment and renewal; the grant itself is a bearer token on the Paseo host link (no PoP field in connected-hosts hellos)". Add an upstream request for it.
4. Section 8.2, add a row "Member plugin ↔ lane endpoint (embedded host), M1: rooms control protocol v1 (`plugin/docs/specs/rooms-control-protocol.md`)".
5. Section 10, Confused deputy: "Implemented for fork lanes by shadowing Paseo's `paseo` MCP entry with an inert server (verified on 0.13.2). Not possible per agent for providers with native Paseo tools (OpenCode bridge, omp) or for share-live lanes; fork is the default."
6. Section 11, Phase 1: state that the room log is signed plaintext until the MLS milestone.
7. Section 11, upstream proposals: add "`server.paseo` at contribute time", "per-agent opt-out of Paseo tools", "PoP for connected-host credentials".
8. Section 12: add the open questions in section 6 above (stale routed hosts, workspace metadata exposure).

## 8. Plan for Milestone 2: MLS room chat and chat UI

**Goal:** members and the owner chat in a room; content is end-to-end encrypted with MLS; the embedded host stores and orders ciphertext only.

1. **MLS adapter** (`server/mls/`): wrap `ts-mls` pinned at exactly 1.6.4 (plus `@noble/hashes` and `@noble/ciphers`) behind a small interface: create, key package, add, remove, commit, process, encrypt, decrypt, encode and decode state. Use `ts-mls/clientConfig.js` and re-attach our authentication service on every load. Port the security spike's removal test and its 1.6.2 positive control into `test/unit`.
2. **Authentication service:** an MLS credential = the device public key plus a host-signed attestation (host key over `{roomId, memberId, deviceKeyId}`), issued at enrollment. Reject any other credential.
3. **Host as delivery service:** extend the control protocol (v2) with a long-lived, authenticated session per member (subscribe), and ops `kp.publish`, `commit.submit`, `welcome.fetch`, `msg.send`, `msg.fetch(since)`. The host sequences one commit per epoch (first valid wins; others get `stale_epoch` and retry) and stores ciphertext and signed metadata only.
4. **Membership ↔ MLS:** join → owner device commits Add and Welcome; revoke or leave → Remove commit before `member.revoked` returns; the removed device must fail to decrypt (test).
5. **State at rest:** encrypt group state with a key derived from the device key (HKDF, AES-GCM), atomic writes, bounded key retention.
6. **Room log:** move event content into MLS application messages; keep the hash-chained signed envelope (ids and hashes) on the host; members keep the last hash they saw (truncation detection).
7. **UI:** a chat panel in the Rooms screen (per room) and an agent panel on lane agents. Text input, message list with sender labels, unread count in the sidebar row and the composer pill. Use `FlatList`, `theme.colors` text and compact layout. Show key-change events and safety numbers per member.
8. **Tests:** unit tests for the adapter and authentication service; an e2e extension where owner C and member A exchange messages, A is removed and cannot read the next message, and the host files contain no plaintext.
9. **Before M2 work starts:** run the manual app checks in U1 to learn how the real app treats lane hosts.
