# paseo-rooms (identity v2)

Paseo plugin `rooms` (package `paseo-rooms`). One plugin, one runtime (`server/runtime-v2.ts`), with these roles on any daemon:

- **room host and admin** on the owner's daemon: the room's signed log, its room endpoint on the relay (Noise IK sessions), SAS enrollment, device links and holds, grants v2, key rotation and recovery, the MLS delivery service;
- **lane endpoints** on the owner's daemon: one relay endpoint per shared agent, the Room Profile filter and the field sanitizer, capped upstream sessions, pushed revocation;
- **member** on each member's daemon: per-room device keys, its own fold of the room log, the room session, grant requests and rotation, the connected-host registration of each lane, the MLS group.

Identity v2 replaced the Milestone 1 (M1) identity layer at the cut-over (implementation plan I-15, 2026-11-01). M1 is kept in git at tag `m1-baseline`; its results are in `M1-RESULTS.md`. On first start the plugin archives M1 data it finds and closes M1 rooms (`server/migration/v1.ts`, `docs/specs/identity-v2/migration.md`).

Design: `docs/specs/identity-v2/` (start with its `README.md`), `docs/specs/room-profile-v1.md`, and `../research/rooms-architecture.md`. Plan, follow-ups and open decisions: `docs/IMPLEMENTATION-PLAN-identity-v2.md`.

## Layout

| Path | Runtime | What |
|---|---|---|
| `index.server.ts`, `server/runtime-v2.ts` | server | RPC registration, the agent guard, the resume tripwire and the agent.archived hook; the runtime (start, owned and joined rooms) |
| `shared/rpc-v2.ts`, `shared/rpc.ts` | both | Plugin RPC contracts: the room calls (`rooms.v2.*`), and bootstrap, Fix permissions, lane agents, migration |
| `server/proto/`, `server/noise/`, `server/transport/` | server | Encoding (RJCS), keys and ids, invite and link codes; vendored Noise IK; records and the relay connection shared by room and lane endpoints |
| `server/authority/` | server | The fold of the room log: statements, entries, roster, holds, lineages, admin revocation re-folds |
| `server/admin/` | server | Genesis, the admin signer, one-time confirmations of admin actions, the hold clock, recovery |
| `server/host/` | server | Room host and log store, room endpoint, enrollment, grants v2, lane service, MLS delivery |
| `server/member/` | server | Enrollment client and journal, device link, room client, grant scheduler, lane registration, rotation |
| `server/mls/` | server | ts-mls adapter, authentication service, roster rule, member state |
| `server/keystore/` | server | Keyring (`@napi-rs/keyring`) or protected fallback file; sealed files |
| `server/platform/` | server | Home resolution, owner-only `FileProtection` (POSIX modes; win32 DACL, untested on Windows), durable writes, log writer lock, the TEST-ONLY clock and test-home guard |
| `server/migration/v1.ts` | server | Migration from M1: detect, archive by rename, `migration.json`, removal of v1 host registrations, "Delete keys" |
| `server/gateway/lane-endpoint.ts` | server | Lane relay endpoint: host-link destination side, virtual sessions, capped upstream, pushed revocation |
| `server/gateway/agent-guard.ts`, `tripwire.ts` | server | `before("agent.create")` guard with the inert MCP shadow for room agents; stored-config tripwire |
| `server/gateway/local-daemon.ts`, `lane-errors.ts` | server | Loopback upstream with `hello.sessionPermissions`; owner-only lane error log |
| `server/room-profile/`, `profile/*.csv` | server, data | Room Profile classification and field tables, generated module, filter and sanitizer |
| `server/limits.ts`, `server/log.ts`, `shared/policy.ts` | both | Resource limits (`limits.json`), redacting logger, provider allowlist |
| `client/` | app | Rooms screen, share ("Open room…") screen, dialogs, sidebar item, composer pills |
| `tools/` | dev | Profile generator |
| `test/unit/`, `test/e2e-v2/` | dev | Unit and conformance tests; end-to-end tests with disposable daemons |
| `test/m1-evidence/` | dev | Logs of the last M1 e2e runs (git-ignored raw evidence) |
| `ui-check/` | dev | Disposable daemons with demo state for a manual check in the real app |

`tools/` and `test/` are not imported by either entry, so Paseo does not bundle them, and they are excluded from the npm `files` list.

## Development setup

Requirements: Paseo 0.13.2 (`/opt/Paseo`), npm. Scripts run on the Node 24 bundled with Paseo (`ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin`).

```bash
cd plugin
npm install
npm run typecheck          # tsc --noEmit over entries, client, server, shared, tools and tests
npm run typecheck:client   # the client alone, without Node or DOM types (X-12)
npm run gen:profile        # regenerate server/room-profile/generated.ts after editing the CSVs
npm test                   # unit and conformance tests
npm run test:e2e           # offline end-to-end test; see below
```

Relay: the genesis of a new room records `PASEO_ROOMS_RELAY_ENDPOINT` (default `relay.paseo.sh:443`, TLS). Keystore: the system keyring, or `PASEO_ROOMS_KEYSTORE=fallback-file` for a protected file. Development switches (`PASEO_ROOMS_DEV_*`: short grants, plain loopback relay, fast MLS timers) are honoured only on a marked e2e test home (`server/platform/test-clock.ts`) and ignored elsewhere.

## Tests

**Unit and conformance** (`npm test`, 343 tests, about 10 s): the v2 vectors and encoding, Noise, records, keystore, file layer, fold core and authority, room host, room endpoint, enrollment, grants and lane service, device links, rotation, MLS, RPC contracts and the migration from M1 (`v2-*.test.ts`); the Room Profile and field tables, viewer policy, lane endpoint limits, relay connection, agent guard and tripwire.

**End to end, offline** (`bash test/e2e-v2/run.sh`, about 2.5 minutes): three disposable daemons on 6921, 6922 and 6924 and a fake relay on 6923, homes under `plugin/.test-homes/v2-*` (0700, git-ignored, deleted afterwards). Enrollment with SAS and a restart mid-pending, lane grants with rotation, a device link with the 72 h hold on the TEST-ONLY clock, MLS, host key rotation, device rekey, removal, the denials of out-of-scope operations, the one-time invite, a full file-mode check, secret scans, an independent fold of the owner's room log, and archiving the shared agent closing its lane. Two agents are created without a prompt: no model call. `--live-relay` uses relay.paseo.sh (network; run only with the user's go-ahead).

**Migration from M1** (`bash test/e2e-v2/migration-run.sh`, about 40 s): an M1 build from a temporary worktree of tag `m1-baseline`, two daemons on 6925 and 6926 and a fake relay on 6927. Creates an M1 room and membership, upgrades both plugins, checks the archive, `migration.json`, the removed host registration and the absent v1 lane endpoint, then runs a new v2 room end to end. No model call.

Every test daemon: config written before the first start (loopback listen, daemon relay registration off, speech off), every CLI call with `--home`, never `~/.paseo` or the main daemon, keys in the fallback file (never the user's keyring), ports 6920 to 6929 checked free at the end. The Haiku call budget is tracked in `test/e2e-v2/HAIKU-BUDGET.md`.

`test/reliability/` was written for M1 and is stale until rewritten against the v2 RPCs (its README says so).

## Security model and limits

- **Watch only, by construction.** A lane is the owner's own agent, running as the owner's OS user. Member input must never prompt or drive it: every prompting, steering and approval message type is denied before the Room Profile table is consulted, and a lane endpoint refuses to start if the table ever allows one. Steering needs sandboxed lanes, not a table change.
- **A grant admits every client of the member's daemon.** The lane is a connected host on the member's daemon, so the member's app, paired devices and the member's own agents (through Paseo's routed-host tools) can read the lane. Treat lane content as visible to everything on the member's daemon.
- **Joins are confirmed by people.** An invite is one-time and expires (30 minutes by default); the owner admits a join only after both sides compared the six-digit SAS. A device link waits 24 or 72 hours unless an admin approves it, and any of the member's devices can veto it.
- **Grants** last at most 12 hours, are bound to a device and a lane, and are revoked before the revocation is saved (a failed save is reported and retried).
- **Room agents created by Rooms** get the inert `paseo` MCP shadow (`agent-guard.ts`) and the stored-config tripwire before a resume. Identity v2 shares existing agents and creates none; the guard and tripwire still protect the fork agents M1 left on a daemon.
- **Other plugins are trusted.** Paseo 0.13.2 runs `before` hooks in plugin-id order, and every server plugin runs with owner permissions.
- **Resource limits.** Defaults in `server/limits.ts`, with the grants-v2 section 11 limits for lanes (32 routes per link, 256 per lane, 30 failed links per minute). Override in `<PASEO_HOME>/plugin-data/rooms/limits.json` (clamped to safe bounds).

## Installing on a real daemon (not done by the tests)

Installing requires `pluginsEnabled: true` on the target daemon and trusts this code with owner permissions. Use `paseo plugin install /absolute/path/to/plugin` on the owner's and each member's daemon, then `paseo plugin ls` to check it is `running`. The UI was not exercised in a real app yet; see `ui-check/README.md` for the manual checklist.
