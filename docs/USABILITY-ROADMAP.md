# Usability roadmap: from working prototype to v0.2 for a pilot lab

Date: 2026-11-01. Status: read-only audit. No code, test or configuration was changed, and no test was run for this document. It was written while the I-15 cut-over (M1 to v2) was in progress, so some items may already have moved. Check `git log` before acting on any of them.

## Summary

The protocol and security core of identity v2 are in place: enrollment with SAS, grants, revocation, device links, rotation and recovery, and the MLS transport. The project docs record 356 unit tests and a v2 end-to-end run over the live relay. What is missing is everything around that core. Install, onboarding, everyday journeys, cut-over hygiene and release engineering are still unbuilt.

Today only a developer can install the plugin on Linux, by cloning a directory, running `npm install` and running `paseo plugin install <dir>`. Nobody has used the UI in the real app. macOS and Windows have never run it. Three core journeys have no v2 implementation at all: leaving a room, closing a lane and room chat. The package is `private`, there is no CI, CHANGELOG or security policy, and the user-facing docs still describe M1.

The shortest credible path to "a pilot lab uses it day to day" has five milestones, below:

- **R1:** finish the cut-over and remove development surfaces.
- **R2:** fix the security and data-loss gaps.
- **R3:** complete the core journeys, including minimal chat.
- **R4:** make install and first run work for a non-developer.
- **R5:** set up release engineering.

R1 and R2 come before anyone outside the developer touches it. Roughly: R1 is M, R2 is L, R3 is L, R4 is M/L and R5 is M. Six items need the user's decision or outside action. They are listed at the end.

## Labels

- **Verified:** read in this repository, in Paseo 0.13.2 documentation (`public-docs/plugins/` in the research clone at commit 1467121), or on this machine.
- **Judgement:** my assessment. It is not tested.
- Sizes: **S** is under a day, **M** is a few days, **L** is a week or more, all for one focused agent or developer.

## 1. Current state, by area

### 1.1 Install, update and uninstall

| Topic | Verified facts | Judgement |
|---|---|---|
| How a labmate gets it | `package.json` has `"private": true` and the package is unpublished. There is no git remote, so there is no GitHub source. README documents only `paseo plugin install /absolute/path`. | Today only a developer can install it. |
| Install sources Paseo supports | Registry (`paseo plugin add owner/slug`), directory, Git/GitHub, npm. The registry accepts public npm or public GitHub sources after review. It requires a locked dependency tree (`npm-shrinkwrap.json` for npm) and a screenshot for visual plugins. | The registry path is the right target for labmates: one identifier pasted into Settings → Plugins. |
| npm on the daemon host | Paseo docs: "Install Node.js with npm on the daemon host". Git installs with runtime deps need a manifest `build` of `npm ci`, which also needs npm. No npm was found under `/opt/Paseo` (depth 4) on this Linux machine. | Most non-developer macOS and Windows users have no Node or npm. **Every install route needs npm on the daemon host.** This is the largest install blocker, and it is outside this repo. |
| Native keyring | `@napi-rs/keyring` 2.1.2 is loaded at runtime from the plugin directory, never bundled. Spike B passed on Linux x64 glibc, including an npm-source install from an offline registry. The lock lists darwin, win32 and linux platform packages. | macOS Keychain and Windows Credential Manager have never been run. A missing binding falls back to the protected file with a notice, so a failure does not stop install. |
| Paseo version | Manifest: `"paseo": ">=0.13.2"`, with no upper bound. The Room Profile is generated against `@getpaseo/protocol` 0.13.2. Nothing checks the daemon version at runtime. Unknown message types are denied and unknown fields are dropped. The app checks the range independently of the daemon. | A future Paseo release fails closed (no leak) but may silently break lanes. A tested upper bound, or a per-release compatibility run, is needed. **User decision.** |
| Prerequisite switch | `pluginsEnabled` must be true on every daemon. The app shows a trust warning. | This is fine, but the user guide must say so. |
| First run | The keystore is chosen once at first start and recorded in `meta.json`. It is never changed silently. A locked keyring stops room operations. The UI shows the fallback notice and "Fix permissions". | There is no first-run guidance. A Linux user with a locked keyring, or a macOS Keychain prompt, sees a stopped plugin and no explanation of what to do. |
| Update | npm and registry installs use `paseo plugin update rooms`. Directory installs are skipped. | There is no migration story beyond M1 to v2 (I-15). Every later change to sealed formats needs a version field and a tested upgrade. |
| Uninstall | `paseo plugin remove` deletes managed files for npm and Git and keeps a directory source. The plugin's data lives in `<PASEO_HOME>/plugin-data/rooms`. The KEK lives in the OS keyring. Paseo does not prune routed hosts. | Whether Paseo deletes `plugin-data/rooms` on remove is unknown and needs one check. There is no "leave all rooms and delete my keys" action. Members keep stale routed hosts. Grants expire within 12 h. |

### 1.2 Core journeys under v2

| Journey | State | Evidence |
|---|---|---|
| Create a room | Built: create dialog, recovery code dialog. Not seen in the app. | Verified: `client/v2-screen.tsx`, I-14 notes |
| Share an agent ("Open room…" from an agent) | Built for **share live** only. The v2 runtime has no fork lane. `createLane` shares the existing agent. README and OVERVIEW still describe forks as the default. | Verified: `runtime-v2.ts` `createLane` |
| Composer pill, and "Open room…" routing on lane agents | **Broken under v2.** Both call `rooms.lane.agents` (M1 contract), which `contributeV2` does not register. The errors are swallowed. | Verified: `index.client.tsx`, `client/composer-pills.ts`, `index.server.ts` |
| Archived agent closes its lane | **Not wired under v2.** `contributeV2` registers RPCs only, with no `agent.archived` hook. | Verified: `index.server.ts` |
| Invite | Built. The code is a bearer secret (`prc2.`, up to 2 KiB), single use, 30 min by default. | Verified |
| Join with SAS | Built: owner and member screens, contested and abandoned states. The member SAS screen lacks the owner fingerprint. Room and member names show as ids, because `room.profile` is missing. | Verified: I-14 gaps 4 and 5 |
| Watch a lane | Built. The lane appears as a routed host on the member's daemon. The e2e-v2 run over the live relay passed (per the plan; not re-run here). Disallowed controls stay visible and fail on use, because the app ignores `server_info.permissions`. | Verified (docs); upstream limitation |
| Room chat | **Missing (M2).** MLS transport exists. `rooms.v2.mls.send` and `rooms.v2.mls.messages` are development RPCs. Messages are kept in memory only (last 500). There is no application-level sender signature, which the plan requires before chat. | Verified: `shared/rpc-v2.ts`, plan follow-ups, grep of `server/mls` |
| Share results | Only what the lane timeline shows. Files, terminals and diffs are refused by the Room Profile. | Verified (OVERVIEW and profile). Whether a pilot needs more is a product question. |
| Leave a room | **Missing.** No v2 RPC (`member.left`). The card says "not available yet". | Verified: I-14 gap 1 |
| Close a lane | **Missing.** No v2 RPC. | Verified: I-14 gap 1 |
| Remove a member, revoke | Built, with typed confirmation. | Verified |
| Close a room | Built. It needs a recovery key or a second lineage, with a 24 h delay by default. Single-lineage rooms cannot propose closure in the UI. | Verified: I-14 notes |
| Link a second device | Built, including the 24 h or 72 h hold. | Verified |
| Activity notices (who joined, key changes) | Missing. Only alerts and holds are shown. The room-log 4.6 notice feed is not in the status view. | Verified: I-14 gap 2 |
| Owner offline | The embedded host only. The room is unavailable while the owner's daemon is offline. | Verified (architecture section 9). Judgement: for a lab, rooms that vanish when a laptop sleeps will feel broken. The standalone host is Phase 3. |

**UI calls to RPCs that are not product-ready.** The member card calls `rooms.v2.room.connect` and `rooms.v2.room.disconnect`. The I-8 follow-up describes these as explicit stand-ins for automatic reconnect. The runtime header now says sessions are armed at start, so check whether the buttons are still needed. The client also imports `roomsBootstrap`, `roomsLaneAgents` and `roomsPermissionsFix` from the M1 `shared/rpc.ts`. These need to survive or move during I-15. The UI does not call the development RPCs `mls.*` or `test.clock.advance`.

### 1.3 Verification status

| Item | State |
|---|---|
| UI in a real app | Never seen. The `ui-check/up-v2.sh` kit and checklist are ready. I-15 is on hold until the user runs it. |
| macOS, Windows, WSL, Docker, iOS, Android | Never run. The file layer, DACL backend and pipe support are implemented and unit-tested on Linux with fakes only. |
| Attack harness (hardening E) and reliability suite | Not run. Both need the user's approval. |
| Test tooling | Linux-only: `/opt/Paseo/Paseo.bin` paths, bash scripts, `/proc` in test samplers (X-10). |

## 2. Milestones toward v0.2

The v0.2 exit criterion: a pilot lab of about 5 people can install the plugin from a published source on Linux and macOS. Windows is allowed if it is verified, otherwise it is marked unsupported. An owner can create a room, share an agent, invite, admit by SAS, chat, and leave or close cleanly. Nobody can lose keys or room access silently. Every untested platform is marked as such.

### R1. Finish the cut-over and remove development surfaces (M)

| # | Item | Size | Why | Depends on |
|---|---|---|---|---|
| R1.1 | Complete I-15: v2 is the only runtime; delete M1 code, the `PASEO_ROOMS_PROTOCOL` switch and the "development" badge | M | The shipped plugin is still M1 by default | User runs the v2 UI check (on hold) |
| R1.2 | Remove or gate the development switches: `PASEO_ROOMS_DEV_INSECURE_RELAY`, `PASEO_ROOMS_DEV_SHORT_GRANTS`, `PASEO_ROOMS_DEV_GRANT_TTL_S`, `PASEO_ROOMS_DEV_MLS_FAST`. Gate them to test homes with the marker file, as the test clock already is | S | Verified: these are read on any home, while the test clock is gated. Judgement: low exploitability (same-user threat is out of scope), but they should not ship live | R1.1 |
| R1.3 | Keep `rooms.v2.mls.*` unregistered in release builds until R3.4 replaces them | S | The rpc-v2 header says they "never ship" | R1.1 |
| R1.4 | Re-wire the client entry for v2: lane-agent lookup for the composer pill and the "Open room…" redirect | S | Verified broken under v2 (section 1.2) | R1.1 |
| R1.5 | Register an `agent.archived` hook in v2 that closes the agent's lanes (C-13 parity) | S | Without it, an archived shared agent leaves a dangling lane | R3.2 (lane close) or a direct close |
| R1.6 | Update README and OVERVIEW to v2: share-live default, 12 h grants, SAS, recovery key, platform matrix | S | Both describe M1 behaviour (fork default, 24 h grants) | R1.1 |

### R2. Security and data-loss must-fixes (L)

Ordered by impact.

| # | Item | Size | Why | Depends on |
|---|---|---|---|---|
| R2.1 | Persist the member's verified log copy, `maxSignedHead` and receipts | M | Verified: `maxSignedHead` exists only in `room-client.ts` (memory). Truncation and withholding are detected only within one process lifetime, which weakens a principle-9 property across restarts | none |
| R2.2 | Run the attack harness (fuzzing, grant replay and forgery, invite reuse, concurrent enrollment) and the reliability suite on v2 | M | Hardening section E has never run. These are the negative tests for a security-first protocol | User approval; v2 ports of the harness |
| R2.3 | Key-loss paths: document the single-device-owner risk and make the recovery code the default (already preselected). Add a "back up this room" check in About. Test what happens when the recovery dialog is dismissed by closing the app | S/M | A lost owner device with no recovery key loses the room. Members must be re-invited | R4.3 |
| R2.4 | Keyring behaviour on macOS and Windows: run Spike B's probe cases B1 to B3 on a real Mac and a Windows machine. Test a denied Keychain prompt and a locked keyring | M | Verified untested. A wrong "locked" state stops all room operations | Access to a Mac and a Windows machine |
| R2.5 | Windows file protection and durability: run the unit and e2e suites on Windows, or mark Windows as **not supported** for v0.2 | M (run) / S (mark) | DACL via `icacls`, rename retry and pipe listen are untested. The audit marks Windows protection as broken in M1, fixed in code but unrun | R5.2 CI or a manual run |
| R2.6 | Uninstall and data hygiene: a "Leave all rooms and delete keys" action; verify what `paseo plugin remove` leaves behind; document keyring entry removal | S/M | Keys and member registrations outlive the plugin | R3.1 |
| R2.7 | Compatibility guard: refuse to serve lanes when the daemon's protocol differs from the profile version without a tested entry, and show a clear notice. Alternatively, add an upper bound to the manifest | S | The filter fails closed on unknown types, but nothing tells the owner why lanes broke after a Paseo update. **Implemented 2026-11-02 (decisions round 10, item 2):** manifest `>=0.13.2 <0.14.0` plus the guard in `server/compat.ts` (lanes not served, notice in status and the Rooms screen; unit tests with simulated versions). Not yet exercised against a real daemon of another version | User decision D2 (decided) |
| R2.8 | Re-review the cut-over diff (I-15) for leftover v1 paths and secret handling | S | Large deletion near security code | R1.1 |

### R3. Core journeys (L)

| # | Item | Size | Why | Depends on |
|---|---|---|---|---|
| R3.1 | Leave a room (`member.left`): RPC, statement, grant drop, `hosts.remove` of routed lanes, UI with confirmation | M | A user cannot undo joining today | R1.1 |
| R3.2 | Close a lane: RPC, `lane.closed`, endpoint teardown, UI with confirmation | S/M | An owner cannot stop sharing one agent without closing the room | R1.1 |
| R3.3 | `room.profile` over MLS: room name and member display names, used in cards and lane host labels | M | Rooms and lanes show as ids (I-14 gap 5). Judgement: the biggest everyday usability problem in the current UI | MLS (done) |
| R3.4 | Minimal room chat (product M2): an application-level sender signature inside the payload; a sealed on-disk message store; a chat view per room in the Rooms screen; unread count on the sidebar row | L | This is the missing piece of "chat in the room". The signature is required by the plan before chat ships | R3.3; MLS (done) |
| R3.5 | Activity feed from the fold (joined, removed, device added, key rotated, policy changed) | M | Members cannot see what changed (I-14 gap 2). The audit trail is principle 7 | none |
| R3.6 | Member SAS screen shows the owner fingerprint (I-14 gap 4) | S | Part of the enrollment spec | none |
| R3.7 | Stale routed hosts after leave or revoke: remove them where the plugin can (`hosts.remove`), and tell the member where it cannot | S | Verified: Paseo does not prune them. They look like a broken host | R3.1 |
| R3.8 | Decide whether fork lanes return in v2 (curated-context fork, Claude only) or whether v0.2 is share-live only | S (decision) / M (build) | A fork protects the owner's live agent from being watched mid-task. Share-live is simpler | User decision D5 |
| R3.9 | Invite delivery: a shorter code or a `paseo://` deep link, if the app supports one. At minimum, a one-tap copy and an explanation | S/M | A code of up to 2 KiB pasted through Slack works, but feels heavy next to the polish benchmarks (Slack Code, claudecord, Buzz) | Upstream deep-link support (unknown) |

### R4. Install and first run for a non-developer (M/L)

| # | Item | Size | Why | Depends on |
|---|---|---|---|---|
| R4.1 | Choose the distribution source and publish: npm package (scoped name, drop `private`, `repository`, `npm-shrinkwrap.json`) or a public GitHub repo. Then submit to the Paseo registry with `icon` and `media` screenshots | M | Without it, nobody else can install | User decisions D3 and D4; R5.1 |
| R4.2 | npm on the daemon host: document "install Node LTS" per OS in a user guide, and ask Paseo for a bundled npm or a plugin-native-dependency path (upstream requests 5 and 7) | S (doc) / outside (upstream) | Every route needs npm today (verified in the docs) | D1 |
| R4.3 | First-run screen in Rooms: plugins switch checked, keystore backend and what it means, "create your first room" and "join with a code" paths, how to compare codes (call, not chat) | M | There is no onboarding. A stopped keystore gives no clear next step | R1.1 |
| R4.4 | Owner-offline expectations: show on the member card when the owner's daemon was last seen, and say in OVERVIEW that rooms are online only while the owner's daemon is | S | The embedded host makes availability depend on one laptop | none |
| R4.5 | Fix the M1 UI notes that still apply in v2: the keyboard hint on mobile, the iOS monospace font, badge overflow, "0 of 0 connected" | S | Static review found these. The app check will confirm | v2 UI check |
| R4.6 | User guide for labmates (install, join, watch, leave, uninstall), separate from the developer README | S | README is developer-only | R1.6 |

### R5. Release engineering (M)

| # | Item | Size | Why | Depends on |
|---|---|---|---|---|
| R5.1 | Versioning: one source of truth (`VERSION` in `index.server.ts` and `package.json` are separate today); semver with 0.x minor for breaking changes; a version field in sealed and journal formats; a CHANGELOG | S | Verified: no CHANGELOG; two version constants | none |
| R5.2 | CI before release (the user deferred this until now): typecheck (server and client), unit tests and the offline e2e-v2 on Linux, macOS and Windows runners; port the test tooling off `/opt/Paseo/Paseo.bin`, bash and `/proc` (X-10); add `.gitattributes` (X-11) | M/L | Principle 10 requires per-OS CI before release. Nothing has run off Linux | A git remote (D4) |
| R5.3 | `SECURITY.md`: a private disclosure channel, supported versions, scope (same-user malware is out of scope; member daemon clients can read lanes) | S | A security-first plugin needs a reporting path | D4 |
| R5.4 | Licensing hygiene: Apache-2.0 is present at the root and in `plugin/`; check that the vendored Noise `NOTICE.md` ships in the package `files` list (it is under `server/`, so it should) and add a top-level NOTICE if required | S | The vendored Apache-2.0 code must keep its notice | none |
| R5.5 | Package check: `npm pack --dry-run`, then a clean install of the packed artifact on a fresh test daemon per OS; confirm `running` and the keyring backend chosen | S | Registry review requires it, and it is the real install test | R4.1 |
| R5.6 | Results document for v0.2 (I-17): platform matrix with every untested cell marked, and the traceability table | S | Planned and not done | R2, R3 |

## 3. Nice to have after v0.2

- Standalone Room Host (Phase 3), so rooms survive the owner's laptop sleeping. This is the main day-to-day gap after v0.2. (L)
- Push or relay-driven updates instead of 3 to 5 s polling. (M; needs plugin push upstream)
- Hiding disallowed controls on lane hosts. (Upstream: the app should honour `server_info.permissions`)
- Chat mirrors (Slack, Discord), opt-in, as explicit declassification. (L)
- Steering and approvals, which need OS-sandboxed lanes (decision C-iso1). (L)
- Automatic migration from the fallback file to a keyring, KEK rotation, CLI keyring backends. (M)
- Org policy profiles for the company and school pilots. The school pilot needs a self-hosted host for FERPA chat custody. (L)
- Scheduled 90-day rekeys, leaf-repair flow, ReInit after admin key revocation. (M)

## 4. Items that need the user's decision or outside action

| # | Item | Options and recommendation |
|---|---|---|
| D1 | Upstream requests 1 to 8 (identity-v2 README section 6) are held. Requests 5 (a plugin keyring API) and 7 (native optional dependencies) remove the native packaging workarounds. A bundled npm, or no npm requirement, would remove the largest install barrier. Also add "expose the sender leaf" to the ts-mls request. | Judgement: send 5, 7 and the npm question first, with Spike B's evidence. They affect every labmate's install. |
| D2 | Paseo version range: keep `>=0.13.2` open, or add an upper bound and run compatibility per Paseo release. | Judgement: add an upper bound (`<0.14.0`) and release a tested bump for each Paseo minor version. |
| D3 | Distribution: npm (scoped package; needs an npm account and a GitHub repository for registry ownership) or GitHub only; public registry listing or a private source for the pilot. | Judgement: a public GitHub repo plus npm with a shrinkwrap, then registry submission. A private pilot can use `paseo plugin add git:...` against a private repo first. |
| D4 | Create a git remote (none exists) and decide public versus private before the pilot. CI and the security policy depend on it. | User decision. |
| D5 | Fork lanes in v2, or share-live only for v0.2. | Judgement: share-live only for v0.2 and fork in v0.3. Fewer moving parts, and the agent guard and tripwire stay tested from M1 until then. |
| D7 | Approvals already pending: run the v2 UI check (unblocks I-15); approve the attack harness and reliability runs (R2.2); decide on `log.witness` from joiners (recommended yes). | User. |
| D8 | Access to a Mac and a Windows machine (or CI runners) for R2.4, R2.5 and R5.2, or an explicit "Linux-only pilot" scope. | User. |
