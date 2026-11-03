# Paseo 0.14 compatibility (Rooms 0.2.1)

Date: 2026-11-02. Status: done; range widened to `>=0.13.2 <0.15.0`.

Trigger: a user on the Paseo 0.14.0 iPhone app saw `Plugin "rooms" requires Paseo >=0.13.2 <0.14.0. Your app is 0.14.0.`

Sources: the published npm tarballs of `@getpaseo/plugin`, `protocol`, `relay`, `server`, `client` and `cli` at 0.13.2 and 0.14.0, unpacked and compared file by file. "Verified" means read in those packages or observed in a test run. "Judgement" means an assessment that no test proves.

## Verified facts

### How `requirements.paseo` is evaluated

- `assertPluginCompatibility` (`@getpaseo/protocol/plugin-requirements`) is byte-identical in 0.13.2 and 0.14.0. It passes when the version, or its stable core for a pre-release, satisfies the range.
- The daemon checks the range against **its own version** when it loads or installs a plugin (`server/plugins/index.js`, `compiler-build.js`: `runtime: "daemon"`).
- The app checks the same range against **the app's version** before it evaluates the plugin's client bundle (web bundle of both releases: `assertPluginCompatibility({...manifest, version: this.dependencies.version, runtime: "app"})`). The client bundle is compiled by the daemon and served to the app.
- So one range gates both sides. With `<0.14.0`, a 0.14 app connected to a 0.13.2 daemon refused the Rooms UI even though the daemon ran Rooms. This was the reported error.

### Plugin server API and hooks

- New in 0.14: `defineAgentTool`, and `agent.session_open` requests carry `title`, `labels`, `tools` and `mcpServers`. Session-open hooks may now change `env`, `tools` and `mcpServers` (0.13.2: `env` only). Each plugin receives empty `tools` and `mcpServers` and the daemon merges the contributions; a plugin MCP server named `paseo` or named like a saved server is rejected (`resolveProviderLaunchConfig`).
- Plugin MCP servers and tools from session-open hooks are **launch-time only**. They are not written into the stored agent record.
- Plugin agent tools reach an agent through the Paseo tool catalog: the internal `paseo` MCP server, or native Paseo tools for providers that support them. A room agent's inert `paseo` shadow therefore also hides plugin agent tools for the fork-verified providers.
- Unchanged: `before("agent.create")` still runs before Paseo injects its MCP server (`createAgentInternal` order), `withRuntimePaseoMcpServer`, the storage slug and record format (`agent-storage.js` identical), hook order by plugin id, a session-open hook that returns `undefined` or throws, and `agent.archived` (same emit point and payload).
- New: `agentManager.invalidatePluginSessions()` marks sessions stale when a plugin with a session-open hook loads or unloads, and an idle-runtime cleanup (on by default) stops idle provider runtimes. A session opened again goes through `agent.session_open`, where the Rooms tripwire runs as before.
- The plugin client API (`@getpaseo/plugin` `dist/client`, `contracts`, `rpc`, `settings`) is unchanged. The `hosts.add/update/remove/list` API used for lane hosts is unchanged. `@getpaseo/client` adds `agents.ref(id).reload()`, local speech model calls and a `wholeTurns` timeline option.

### Daemon protocol

- `server_info.protocolVersion` is **1 in both releases** (`WS_PROTOCOL_VERSION`). `version` and `protocolVersion` are still sent, so `server/compat.ts` reads them unchanged.
- Session message types: 0.14.0 adds six and removes none (inbound 215 to 218, outbound 234 to 237): `speech.local_models.{list,download,delete}.{request,response}`. Paseo maps them to `daemon.read` (list) and `daemon.manage` (download, delete).
- Reviewed fields: one new field, `fetch_agent_timeline_request.wholeTurns`, used by the app only when `server_info.features.wholeTurnTimeline` is true. Other 0.14 additions (`speechSettings`, `idleRuntimeCleanupSetting`, `wholeTurnTimeline` features; daemon config fields) are in objects the gateway does not forward.
- 0.14 passes an absent timeline `limit` through to the store, whose default is 200 for every direction. 0.13.2 used 200 for `tail`/`before` and unbounded for `after`. The Rooms clamp (P-17) applies when a limit is present in both.
- The protocol modules Rooms imports at run time (`daemon-endpoints`, `host-target`, `agent-state-bucket`, `client-capabilities`) are byte-identical.

### Relay and Noise

- `@getpaseo/relay` 0.14.0 differs from 0.13.2 only in the `version` field of `package.json`. The E2EE and Noise wire format is unchanged, so the vendored Noise copy (from the 0.13-era commit 1467121) still matches. `CURRENT_RELAY_PROTOCOL_VERSION` is still `"2"`.

## Changes in Rooms 0.2.1

- Room Profile regenerated from `@getpaseo/protocol` 0.14.0. The six speech types are classified `deny` (future role `never`). `wholeTurns` is `drop`. `wholeTurnTimeline` is not in `KEPT_FEATURES`, so a 0.14 app viewing a lane uses item paging, as on 0.13.2. A new unit test checks that the profile also covers every type and reviewed field of protocol 0.13.2, and that every type newer than 0.13.2 is denied.
- `server/compat.ts`: range `>=0.13.2 <0.15.0`. Tested entry `{ protocolVersion: 1, profile: "0.14.0" }` replaces `{ 1, "0.13.2" }`. Unknown and other protocol numbers, unknown versions, versions outside the range and pre-releases still fail closed.
- Dependencies `@getpaseo/protocol`, `relay`, `client` and `plugin` are now 0.14.0. The modules used at run time are identical to 0.13.2 (above), so a Git install behaves the same on a 0.13.2 daemon. A development alias `@getpaseo/protocol-0.13.2` serves the coverage test.
- **Legacy fork room agents are refused on Paseo 0.14 and later** (user decision, 2026-11-02: take the safe option). These are agents Rooms 0.1 created for M1 fork lanes and kept after the migration. The session-open tripwire refuses to resume one when the session-open request carries `tools` or `mcpServers` (the 0.14 request shape), or when the daemon's known version is not 0.13.x (`>=0.13.2 <0.14.0`, no pre-release; `compat.ts` `LEGACY_FORK_RANGE`). A lane endpoint with a fork origin is blocked as `legacy_fork_agent_refused` unless the daemon reports 0.13.x. The owner sees a notice on the Rooms screen that lists the unarchived legacy agents and says to archive them; Rooms 0.2 shares live agents instead. On 0.13.2 the behaviour is unchanged. Unit tests cover both versions (`paseo-compat.test.ts`, `v2-migration.test.ts`).
- `tools/paseo-env.sh` accepts an npm-installed CLI as `PASEO_BIN` and runs it on `PASEO_NODE`. `test/e2e-v2/run.sh` accepts `PASEO_BIN_OWNER` and `PASEO_BIN_MEMBER` for mixed-version runs. The e2e reports the installed `@getpaseo/client` version as the app version.

## Tests run (Linux x64, 2026-11-02)

| Run | Result |
|---|---|
| Typecheck: server, client, reliability suite | pass |
| Unit suite on Paseo's Node 24.20 (`ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin`) | 400 tests: 399 pass, 1 skipped (the ts-mls 1.6.2 control, as before), after the legacy fork change |
| `test/e2e-v2/run.sh` offline, all daemons 0.14.0 (npm CLI and daemon) | 139 checks pass, 0 fail (run before and again after the legacy fork change) |
| same, all daemons 0.13.2 (`/opt/Paseo`) | 139 pass, 0 fail |
| mixed: owner 0.14.0, both member daemons 0.13.2 | 139 pass, 0 fail |
| mixed: owner 0.13.2, both member daemons 0.14.0 | 139 pass, 0 fail |

The 0.13.2 and mixed runs were done before the legacy fork change, which affects only legacy fork agents (none exist in the e2e). The e2e viewers use `@getpaseo/client` 0.14.0, so every run includes a 0.14 viewer client; mixed runs cover a 0.14 client against a 0.13.2 owner. Each daemon's compatibility probe logged `paseo_compat_ok` with its version. Not run: `--live-relay`, `migration-run.sh`, the reliability suite, and the real Paseo app (desktop or iPhone) on any version.

## Judgement

- **The 0.14 profile is safe for 0.13.2 daemons.** Both report protocol 1, 0.14 only adds types and fields, and anything a daemon sends that the profile does not allow is denied or dropped. The version range, not the protocol number, separates the two releases.
- **Legacy fork room agents (resolved by refusal).** On 0.14 another installed plugin can attach MCP servers with other names to any agent at session open, including a room agent migrated from 0.1. The tripwire reads the stored record, so it cannot see them, and Rooms cannot see other plugins' session-open contributions. Rooms 0.2.1 therefore refuses to resume or serve these agents wherever the daemon is not provably 0.13.x (see Changes). Ordinary agents and share lanes are not affected.
- **Patch releases 0.14.x are admitted, as 0.13.x patches were.** A later 0.14.x that adds message types still fails closed per type. A change to forwarded semantics would not be caught until someone tests it.
- The iPhone app error should go away once the user's daemon runs Rooms 0.2.1 (the app reads the manifest range from the daemon). This was not checked in a real app.
