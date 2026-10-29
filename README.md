# paseo-rooms (Milestone 1)

Paseo plugin `rooms` (package `paseo-rooms`). One plugin with three roles:

- **gateway** on the owner's daemon: rooms, lanes, one relay endpoint per lane, the Room Profile filter, fork creation and the room agent tool guard;
- **embedded host** inside the gateway: membership, Ed25519 grants, revocation, invites and the signed room log;
- **member** on each member's daemon: device key, enrollment, connected-host registration and grant rotation.

Design source: `../research/rooms-architecture.md`. Status, evidence and deviations: `M1-RESULTS.md`.

## Layout and map to the architecture doc

| Path | Runtime | What | Architecture doc |
|---|---|---|---|
| `shared/schemas.ts` | both | Versioned zod schemas: Room, Lane, Member, GrantClaims, RoomEvent, InvitePayload, limits | 3, 8.1 |
| `shared/control.ts` | both | Rooms control protocol frames, transcript, canonical JSON | 8.2 |
| `shared/rpc.ts` | both | Plugin RPC contracts (owner and member) | |
| `profile/classification.csv` | data | Room Profile classification table (one row per protocol type) | 6.1, 10 |
| `profile/fields.csv` | data | Reviewed field table: every field of every forwarded message and gateway-built object (keep, drop, redact, nested, gateway) | 6.1, 10 |
| `server/room-profile/generated.ts` | server | Generated from both CSVs and `@getpaseo/protocol` (`npm run gen:profile`) | 6.1 |
| `server/room-profile/filter.ts` | server | Exact-id bindings, outbound filter, `server_info` rewrite, owner-uid isolation guard | 6.1 |
| `server/room-profile/sanitize.ts` | server | Field-level rebuild of every forwarded message (paths, git, PR, scripts, prompts, serverId redacted) | 6.1 |
| `server/limits.ts` | server | Resource limits (connections, links, routes, frame sizes, queues), optional `limits.json` | |
| `shared/policy.ts` | both | Fork provider allowlist | 10 |
| `server/gateway/lane-endpoint.ts` | server | Lane relay endpoint: host-link destination side, virtual sessions, capped upstream, pushed revocation | 6.1, 8.2 |
| `server/gateway/control-server.ts` | server | Gateway side of the control protocol | 8.2 |
| `server/gateway/gateway.ts` | server | Rooms and lanes, fork with curated context, owner views | 5, 6.4, 7.2 |
| `server/gateway/agent-guard.ts` | server | `before("agent.create")` guard and inert MCP server for room agents | 10 (confused deputy) |
| `server/gateway/tripwire.ts` | server | Checks the room agent's final stored config after every plugin hook | 10 |
| `server/gateway/local-daemon.ts` | server | Loopback upstream with `hello.sessionPermissions` | 8.2 (defence in depth) |
| `server/host/host-store.ts` | server | Embedded host: members, grants, invites, revocation, change push | 5, 8.1 |
| `server/host/event-log.ts` | server | Hash-chained, host-signed room log | 3, 8.3 |
| `server/member/member.ts` | server | Member role: join, `hosts.add/update/remove`, `hosts.observe`, rotation | 8.2 native app path |
| `server/member/control-client.ts` | server | Member side of the control protocol | 8.2 |
| `client/` | app | Rooms screen, Open room screen, sidebar item, composer pills | 5 (Rooms UI) |
| `docs/specs/` | docs | Control protocol, Room Profile v1, data model and storage | 8.5 ("every protocol gets a written spec") |
| `tools/` | dev | Profile generator and the one-time CSV seed script | |
| `test/unit/` | dev | Unit and conformance tests (node:test) | |
| `test/e2e/` | dev | Two-daemon end-to-end test | |

`tools/` and `test/` are not imported by either entry, so Paseo does not bundle them, and they are excluded from the npm `files` list.

## Development setup

Requirements: Paseo 0.13.2 (`/opt/Paseo`), npm. Scripts run on the Node 24 bundled with Paseo (`ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin`).

```bash
cd plugin
npm install
npm run typecheck        # tsc --noEmit over entries, client, server, shared, tools and tests
npm run gen:profile      # regenerate server/room-profile/generated.ts after editing the CSV or bumping @getpaseo/protocol
npm test                 # unit and conformance tests
npm run test:e2e         # two disposable daemons; see below
```

Runtime dependencies (`@getpaseo/relay`, `@getpaseo/protocol`, `ws`) are bundled into the server entry by Paseo's plugin compiler. `PASEO_ROOMS_RELAY_ENDPOINT` (and `PASEO_ROOMS_RELAY_TLS=false`) override the relay for new lanes; the default is `relay.paseo.sh:443` with TLS.

## Tests

**Unit and conformance** (`npm test`, about 2 s):

- `room-profile.test.ts`: every protocol type classified (the gate fails on a missing type); generated module up to date; allowed set equals implemented bindings; default-deny fuzz over all 215 inbound and 234 outbound types with foreign ids; exact-id binding; `server_info` flags.
- `host-grants.test.ts`: grant signing and verification; one-time invites; expiry; invite burning; synchronous revocation push; renewal revokes the superseded grant; lane binding; transcript binding.
- `event-log.test.ts`: hash chain and signature verification; tampering, reordering, gaps and re-signing detected.
- `secrets-and-guard.test.ts`: log redaction; 0600/0700 modes; invite codes; the room agent guard and the inert MCP server.
- `field-policy.test.ts`: field conformance gate (fails on any unreviewed or stale field); upstream hello built from scratch; leakage tests with realistic agent and workspace descriptors; sanitised messages still parse with the protocol schema; prompting types denied on owner-uid lanes.
- `lane-endpoint.test.ts`: resource caps (connections, links, routes, pending queue, tracked requests, frame size, rate limit) against a fake loopback daemon; route-slot clientIds; archived lane agent; tripwire at lane start.
- `durability.test.ts`: revocation enforced before persisting and after a failed write; grant allowlist and pruning margin; torn room log recovery; log clipping; member timers armed at start; archived agent closes its lanes.
- `tripwire.test.ts`: stored-config tripwire, resume check, provider allowlist.

**End to end** (`npm run test:e2e`, about 2 minutes including daemon start):

- Creates `plugin/.test-homes/{owner-c,member-a}` (0700, git-ignored) and writes each `config.json` before the first start: listen `127.0.0.1:6891` / `6892`, `daemon.relay.enabled: false`, `pluginsEnabled: true`, `features.dictation.enabled` and `features.voiceMode.enabled: false` (no speech model download). It also exports `PASEO_DICTATION_ENABLED=false` and `PASEO_VOICE_MODE_ENABLED=false`.
- Every CLI call uses `--home`; `~/.paseo` and the main daemon are never touched.
- Installs this directory as plugin `rooms` on both daemons, creates one parent agent on C (Claude `claude-haiku-4-5`, trivial prompt; uses your Claude login), then runs `test/e2e/e2e.ts`: room and fork lane via RPC, share-live lane, invite, enrollment from A, routed lane through A as the app opens it, exactly one agent, live turn, 12 denials, revocation cut timing, member-side revocation handling, expiry cut and rotation recovery, idle rotation, leave, room log verification, file modes, process-level MCP check and a secret scan.
- Cleanup always runs: archives the agents (archiving the parent also archives its fork), removes the plugin, stops both daemons and deletes the homes (`KEEP_HOMES=1` keeps them). Logs go to `test/e2e/logs/`.
- Network: npm (install), the Paseo relay (lanes), and the Claude provider for two short turns.

## Security model and limits

- **Watch only, by construction.** Lanes run as the owner's OS user: a fork lane is an ordinary agent of the owner's daemon and a share lane is the owner's agent itself. The inert `paseo` MCP shadow is hygiene, not isolation: an agent with a shell can still reach the `paseo` CLI, `~/.paseo` and the daemon port. So member input must never prompt or drive a lane. Every prompting, steering and approval message type is denied before the Room Profile table is consulted, and a lane endpoint refuses to start if the table ever allows one. Steering requires sandboxed lanes (a future runner node kind), not a table change.
- **A grant admits every client of the member's daemon.** The lane is a connected host on the member's daemon, so the member's app, any paired device with access to that daemon, and the member's own agents (through Paseo's routed-host tools) can all read the lane. A prompt-injected agent on the member's machine can read and exfiltrate what the member can watch. This is by design in M1 (the grant never enters the app), but treat lane content as visible to everything on the member's daemon.
- **Fork lanes only for verified providers.** `shared/policy.ts` lists providers whose room agents were shown to run without Paseo's MCP (currently `claude`, verified by the e2e process check). Other providers, custom provider ids and profiles are refused.
- **Other plugins are trusted.** Paseo 0.13.2 runs `before` hooks in plugin-id order, so a plugin whose id sorts after `rooms` can re-add MCP servers to a room agent. The gateway creates room agents without a prompt, checks the final stored config (`server/gateway/tripwire.ts`), and archives the agent and refuses the lane if the shadow is gone or anything else was added. The same check runs when a lane starts and before a lane agent is resumed. `agent.session_open` hooks can change only env on 0.13.2.
- **Resource limits.** Defaults in `server/limits.ts`: 32 relay connections per lane, 2 links per member, 16 routes per link and 32 per member, 1 MiB inbound frames, 256 KiB routed messages, bounded queues and request maps, 50 frames/s per link, timeline pages of at most 1000 rows. Override in `<PASEO_HOME>/plugin-data/rooms/limits.json` (same keys, read at plugin start; values are clamped to safe bounds).

## Installing on a real daemon (not done by the tests)

Installing requires `pluginsEnabled: true` on the target daemon and trusts this code with owner permissions. Use `paseo plugin install /absolute/path/to/plugin` on the owner's and each member's daemon, then `paseo plugin ls` to check it is `running`. The UI was not exercised in a real app yet; see `M1-RESULTS.md` for the manual checklist.
