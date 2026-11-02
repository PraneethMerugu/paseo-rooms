# Contributing to Paseo Rooms

Thank you for helping. Rooms is security-sensitive: it shares a live agent across machines. Please read the [security model](README.md#security-model) and, for protocol changes, the specifications in [`docs/design/specs/identity-v2/`](docs/design/specs/identity-v2/README.md) before changing behaviour. Report vulnerabilities privately ([SECURITY.md](SECURITY.md)), not in issues.

## Development setup

You need:

- **Node.js 20.19 or later** and npm, for installing, type checking and unit tests;
- **Paseo 0.13.x** (desktop app or CLI), for the end-to-end tests, the reliability suite and the UI check kit;
- **bash**, for the test scripts. They have only ever run on Linux.

```bash
git clone https://github.com/PraneethMerugu/paseo-rooms.git
cd paseo-rooms
npm ci
```

| Command | What it does |
|---|---|
| `npm run typecheck` | `tsc --noEmit` over the entries, `server/`, `shared/`, `client/`, `tools/` and the tests |
| `npm run typecheck:client` | The client alone, without Node or DOM types. The client bundle runs on desktop, web, iOS and Android, so `node:*`, `Buffer`, `process` and `document` must fail here. |
| `npm run typecheck:reliability` | The reliability suite (`test/reliability/`) |
| `npm test` | Unit and conformance tests (397, 10 to 30 s) on the `node` on your `PATH` |
| `npm run test:e2e` | Offline end-to-end test with disposable Paseo daemons (below) |
| `npm run gen:profile` | Regenerates `server/room-profile/generated.ts` after editing `profile/*.csv` |
| `npm run check:docs` | Checks that repository paths named in the user-facing Markdown files exist |

To run the unit tests on Paseo's bundled Node instead: `ELECTRON_RUN_AS_NODE=1 "$PASEO_NODE" --test --import tsx test/unit/*.test.ts`, with `PASEO_NODE` set to the Paseo executable (see below).

### Finding Paseo

The scripts that start daemons source [`tools/paseo-env.sh`](tools/paseo-env.sh). It reads two variables and falls back to per-OS defaults:

| Variable | Meaning | Linux default (verified) | macOS default (unverified) | Windows default (unverified) |
|---|---|---|---|---|
| `PASEO_BIN` | the `paseo` CLI | `/opt/Paseo/resources/bin/paseo` | `/Applications/Paseo.app/Contents/Resources/bin/paseo` | `%LOCALAPPDATA%\Programs\Paseo\resources\bin\paseo` |
| `PASEO_NODE` | Paseo's executable, used as Node with `ELECTRON_RUN_AS_NODE=1`, or any Node 20.19+ | `/opt/Paseo/Paseo.bin` | `/Applications/Paseo.app/Contents/Frameworks/Paseo Helper.app/Contents/MacOS/Paseo Helper` | `%LOCALAPPDATA%\Programs\Paseo\Paseo.exe` |

If a default is missing, `paseo` and `node` (20.19 or later) on `PATH` are used. Otherwise the script stops with a message naming the variable to set.

## Tests

### Unit and conformance tests

`npm test` covers the v2 test vectors and encoding, Noise, records, the keystore, the file layer, the room log fold, the room host and endpoint, enrollment, grants and the lane service, device links, rotation, MLS, the RPC contracts, migration from 0.1, the Room Profile and field tables, the viewer policy, lane endpoint limits, the relay connection, the agent guard and the tripwire.

One test, the ts-mls 1.6.2 positive control in `v2-mls.test.ts`, is skipped unless `ROOMS_TS_MLS_162_DIR` names the `dist/src` directory of a separate ts-mls 1.6.2 install. It shows that the removal regression test catches the bug fixed in 1.6.4.

### End-to-end tests (offline)

```bash
bash test/e2e-v2/run.sh               # about 2.5 minutes, no network
bash test/e2e-v2/migration-run.sh     # upgrade from 0.1; about 40 s
```

`run.sh` starts three disposable daemons (owner 6921, member 6922, the member's second device 6924) and a fake relay on 6923. It covers enrollment with the six-digit code and a restart mid-enrollment, lane grants with rotation, a device link with the 72 h hold on a test-only clock, MLS, host key rotation, device rekey, removal, closing a lane, leaving a room, denial of out-of-scope operations, the one-time invite, file modes, secret scans of every home, an independent fold of the owner's room log, archiving the shared agent, and detection of a truncated room log. It creates two agents without a prompt, so no model call is made. `--live-relay` uses `relay.paseo.sh` instead of the fake relay; run it only when you mean to use the network.

`migration-run.sh` builds 0.1 from a git worktree of the `m1-baseline` tag (or `M1_REF`), creates a 0.1 room on two daemons (6925, 6926, fake relay 6927), upgrades both and checks the migration. It needs that tag in your clone.

Rules every test daemon follows, and new tests must too:

- the config is written before the first start: loopback listen address, daemon relay registration off, speech features off;
- every CLI call passes `--home` and sets `PASEO_HOME`; scripts refuse to run against `~/.paseo` or the main daemon (port 6767);
- room keys use the fallback file (`PASEO_ROOMS_KEYSTORE=fallback-file`), never your keyring;
- homes live under `.test-homes/` (mode 0700, git-ignored) and are deleted afterwards unless `KEEP_HOMES=1`;
- ports 6920 to 6929 must be free before and after a run.

Development switches (`PASEO_ROOMS_DEV_*`, `PASEO_ROOMS_TEST_CLOCK`: short grants, a plain loopback relay, fast MLS timers, a movable clock) are honoured only on a home that carries the e2e marker file under `.test-homes` (`server/platform/test-clock.ts`). They are ignored everywhere else.

### Reliability and security suite (gated)

[`test/reliability/`](test/reliability/README.md) holds five modules: environment inspection of the shared agent's process, an enrollment loop, restarts, credential-negative tests and resource stress. They run against two disposable daemons on ports 6930 to 6932 and use the live relay for some modules. **None has been run yet.** `run.sh` refuses to start without `--i-reviewed-this`: read the module and its README first, then run it on purpose.

```bash
bash test/reliability/run.sh --i-reviewed-this --only enrollment-reliability
```

### UI check kit

[`ui-check/`](ui-check/README.md) starts three disposable daemons (6912 to 6914, fake relay 6915 with `--offline`) with demo rooms, so you can add them to your Paseo app and look at every Rooms screen. `ui-check/up-v2.sh` starts it and `ui-check/down-v2.sh` removes everything. Record what you see in `ui-check/ui-notes.md`.

### Test vectors

`docs/design/specs/identity-v2/vectors/vectors.json` is generated by `node docs/design/specs/identity-v2/vectors/gen-vectors.mjs` (Node 20.19+, after `npm ci`). The output must be byte-identical when nothing changed; the generator also self-checks.

## Code layout

| Path | Runs in | What |
|---|---|---|
| `index.server.ts`, `server/runtime-v2.ts` | daemon | RPC registration, the agent guard, the resume tripwire and the agent-archived hook; the runtime (start, owned and joined rooms) |
| `index.client.tsx`, `client/` | app | Rooms screen, share ("Open room…") screen, dialogs, chat, sidebar item, composer pills |
| `shared/` | both | Plugin RPC contracts (`rooms.v2.*`, bootstrap, migration), the provider allowlist |
| `server/proto/`, `server/noise/`, `server/transport/` | daemon | Canonical encoding (RJCS), keys and ids, invite and link codes; vendored Noise with IK; records and the relay connection |
| `server/authority/` | daemon | The fold of the room log: statements, entries, roster, holds, lineages, re-folds |
| `server/admin/` | daemon | Genesis, the admin signer, one-time confirmations, the hold clock, recovery |
| `server/host/` | daemon | Room host and log store, room endpoint, enrollment, grants, lane service, MLS delivery |
| `server/member/` | daemon | Enrollment client and journal, device links, room client, grant scheduler, lane registration, rotation, chat store |
| `server/mls/` | daemon | ts-mls adapter, authentication service, roster rule |
| `server/keystore/` | daemon | Keyring or protected fallback file; sealed files |
| `server/platform/` | daemon | Home resolution, owner-only file protection, durable writes, the log lock, the test-only clock and test-home guard |
| `server/gateway/` | daemon | Lane endpoint, agent guard and tripwire, loopback upstream, lane error log |
| `server/room-profile/`, `profile/*.csv` | daemon, data | Room Profile message and field tables, generated module, filter and sanitizer |
| `server/compat.ts`, `server/limits.ts`, `server/log.ts` | daemon | Paseo version guard, lane resource limits, redacting logger |
| `server/migration/v1.ts` | daemon | Migration from 0.1 |
| `tools/` | development | Room Profile generator, `paseo-env.sh`, the docs path check |
| `test/unit/`, `test/e2e-v2/`, `test/reliability/` | development | Tests, described above |
| `ui-check/` | development | Disposable daemons with demo state for a manual UI check |
| `docs/` | | Design specifications and security reviews ([index](docs/README.md)) |

Paseo compiles only what the two entries import, so `tools/`, `test/` and `ui-check/` never reach a user's daemon. Server code that the entries import must use only runtime `dependencies` (or host modules such as `@getpaseo/plugin` and `zod`), including for type-only imports: Paseo's compiler resolves those too, and Git installs omit development dependencies.

## Making changes

- Keep changes small and focused, with tests. A behaviour change to the protocol needs a spec change in `docs/design/specs/` in the same pull request.
- Run `npm run typecheck`, `npm run typecheck:client`, `npm test` and, when you touch the daemon side, `bash test/e2e-v2/run.sh` before opening a pull request. Say in the pull request which of them you ran and on which OS.
- Never log secrets: keys, grants, invite, link or recovery codes. Never print them in test output either.
- Mark what you did not test. In particular, say "untested" for macOS and Windows unless you ran it there.
- Supporting a new Paseo release: regenerate and review the Room Profile against the new `@getpaseo/protocol`, run both test suites against that Paseo, then widen the range in `paseo-plugin.json` and add a tested entry in `server/compat.ts`.

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
