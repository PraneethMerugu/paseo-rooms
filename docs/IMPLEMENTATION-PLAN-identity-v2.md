# Implementation plan: identity v2 (paseo-rooms)

- **Date:** 2026-10-29
- **Status:** plan only. No product code, spec or test was changed to write it.
- **Naming:** milestones in this plan are I-1 to I-17 (identity v2 implementation), so they do not collide with the plugin milestones M1 (done) and M2 (MLS chat).
- **Inputs:** `docs/specs/identity-v2/` (all files, vectors), `review/HARDENING-PLAN.md` (decisions rounds 1 to 4), `review/cross-platform-audit.md` (X-1 to X-15), `review/FIXES-B-D.md`, `README.md`, `M1-RESULTS.md`, `OVERVIEW.md`, current `server/`, `shared/`, `client/`, `test/`, `spikes/keyring/RESULTS.md`, `spikes/security/RESULTS.md`, and principles 9 and 10 of `research/rooms-architecture.md`.

## Evidence labels

- **Verified:** read in our code, our specs, an installed package, or the Paseo 0.13.2 daemon sources inside `/opt/Paseo/resources/app.asar`; or shown by a command run for this plan.
- **Assumed:** expected behaviour that nobody has run. Each one names the milestone or spike that settles it.

Commands run for this plan (2026-10-29): `npm run typecheck` (clean) and `npm test` (77 pass, 0 fail). Nothing else was executed. No daemon was started, no network was used, and `~/.paseo` was not read.

Facts found while planning that the specs do not record:

| # | Fact | Basis | Consequence |
|---|---|---|---|
| F-1 | Paseo's plugin compiler bundles the server entry with esbuild (`bundle: true`, CJS, platform node). Only the plugin SDK and `zod` are external. | Verified: `@getpaseo/server/dist/server/server/plugins/compiler.js` in app.asar | A `.node` file cannot be bundled. The binding must be loaded outside esbuild's view. |
| F-2 | The server bundle runs through `eval`. Its `require` falls back to `createRequire(import.meta.url)` of Paseo's own `bundle-evaluator.js`. | Verified: `bundle-evaluator.js` | A plain `require("@napi-rs/keyring")` would resolve against Paseo's `node_modules`, not the plugin's. The plugin must call `createRequire(<plugin dir>)`. |
| F-3 | `PluginServerContext` exposes no plugin directory. Both directory and managed installs record `{ source: "directory", path }` under `plugins.<id>` in the daemon's `config.json`. | Verified: `@getpaseo/plugin/dist/server/contracts.d.ts`; `plugins/index.js` `installDirectory` and `installSource` | The plugin can find its directory only by reading the daemon config. This is fragile. Spike B tests it. |
| F-4 | A directory install runs no `npm install`. An npm-source install runs `npm install --ignore-scripts --legacy-peer-deps --omit=dev` on the target machine. The manifest `build` commands run only for managed (npm, git) sources. | Verified: `plugins/index.js`, `managed-source/npm.js`, `manifest.js` | Directory installs use whatever `node_modules` the developer installed. npm installs should fetch the right platform package, because optional dependencies are not omitted. |
| F-5 | ts-mls 1.6.4 declares exact peers `@noble/ciphers 2.1.1` and `@noble/curves 2.0.1`. The plugin has `@noble/*` 2.4.0, required by `@getpaseo/relay` (`^2.4.0`) and by the planned vendored Noise. | Verified: `spikes/security/node_modules/ts-mls/package.json`, `plugin/node_modules/@noble/*/package.json` | One plugin bundle will run ts-mls on noble 2.4.0. Nobody has tested that combination. Spike A case (g) tests it. |
| F-6 | The project is not under version control. | Verified: no `.git` in the project workspace or its parents | Replacing most of M1 without a baseline is risky. The migration end-to-end test also needs an M1 build to upgrade from. See decision D-1. |
| F-7 | `@getpaseo/relay` 0.13.2 ships client code and a Cloudflare adapter, not a Node relay server. | Verified: `package.json` exports, `dist/` | Offline end-to-end tests of the room endpoint need a small fake relay in test code. Live-relay runs need network. |
| F-8 | Port use: the M1 e2e uses 6891/6892, `ui-check` uses 6910/6911, `test/reliability` uses 6930 to 6939, and the unrun attack harness uses 6900/6901. | Verified: the scripts | This plan reserves **6920 to 6929** for identity v2 work (section 1.2, milestone 9). |

## 1. Step 0: gating work (offline, local only)

Run these items before Milestone 1. Each one can change the design or the order of the milestones.

### 1.1 Spike A: `mls-rekey-updatepath-welcome` (ts-mls 1.6.4)

**Where and how.** Add `spikes/security/src/mls-rekey-updatepath-welcome.ts`. Run it the same way as `mls-proto.ts`: `ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin src/mls-rekey-updatepath-welcome.ts`. ts-mls 1.6.4, 1.6.2 and the `@noble` packages are already installed in `spikes/security/node_modules` (verified), so no network is needed. The script uses a test authentication service with a settable reference roster, and it logs every `validateCredential` call (credential identity and the call site, read from a stack sample).

**Cases.** (a) to (d) come from `mls-integration.md` section 10, test 11. (e) to (g) are additions that use the same harness at almost no extra cost.

| Case | What is recorded | Pass condition |
|---|---|---|
| (a) | B commits an UpdatePath whose new leaf has a new credential (new `deviceSig`). Does ts-mls accept it, and does `validateCredential` receive the new credential? With the callback returning `false`, is the commit rejected? | Recorded. Rejected when the callback says no. |
| (b) | The same, with a changed `deviceId`. | Our `IncomingMessageCallback` rejects it. |
| (c) | B's rekey is approved in the test roster but B has not yet sent its UpdatePath. A adds D. D processes the Welcome. Does it fail without the `prevSig` rule and pass with it? | Recorded. Passes with `prevSig`. |
| (d) | Does ts-mls pass unchanged leaves to `validateCredential` while it processes a commit? | Recorded only. The adapter rule works either way. |
| (e) | MLS Q2: with `wireAsPublicMessage: false`, are commits framed as PrivateMessage, and can `authenticated_data` be read before decryption with the ts-mls decoders? | Both yes. |
| (f) | Sanity check: the removal regression from `mls-proto.ts` still passes in this harness, and fails under 1.6.2. | Same as the existing spike. |
| (g) | Cases (a) to (f) again, with `@noble/*` resolved to 2.4.0 (a scratch directory that symlinks the plugin's installed 2.4.0 packages; offline). | Same results as with the spike's pinned versions. |

**What each outcome changes.**

| Outcome | Change |
|---|---|
| (a) accepted and validated, (c) passes with `prevSig` | The spec design stands. Milestones 6, 12 and 13 follow `keys-rotation-recovery.md` 4.1 as written. |
| (a) refused, or the new credential is never validated | Device rekey uses only the admin fallback (Remove plus Add). Milestone 12 then needs an admin device online for every rekey, MLS test 10 is rewritten, and the UpdatePath branch of the commit table (MLS 4.3) is dropped. |
| (c) fails even with `prevSig` | The first Add after a rekey approval carries the fallback for every device still on its `prevSig` (MLS 10, test 11). This makes the Milestone 13 adapter larger. |
| (e) commits are not PrivateMessage, or AAD cannot be read before decryption | The host cannot answer `stale_roster` (MLS 4.2, 6.2). The choice is either members-only rejection or PublicMessage framing, which leaks proposals to the host (MLS Q4 says no). **This needs the user.** |
| (g) differs from the pinned run | Either ts-mls cannot share the plugin's noble 2.4.0, or the two noble versions must coexist in one bundle. Neither has been tried. Milestone 13 is blocked until a pin works. Record which versions do. |

The results go into `spikes/security/RESULTS.md`. During implementation they also go into `mls-integration.md` section 10, as the spec asks.

**Result (2026-10-29, run offline in `spikes/security/`, see the last section of its `RESULTS.md`; recorded in `mls-integration.md` section 10, test 11).** Observed: receivers accept and validate an UpdatePath with a new credential (a), but the public `createCommit` cannot produce one (a0); the callback never sees the UpdatePath leaf, so (b)'s pass condition cannot be met as written, and only a post-processing comparison catches a changed `deviceId` under an accept-all service; (c) fails without `prevSig` and passes with it; (d) only path and added leaves reach `validateCredential` during commits; a stale post-approval UpdatePath passes the round-4 `prevSig` rule (a-stale); (e) yes to both; (f) as before, fails on 1.6.2; (g) identical on noble 2.4.0. **Outcome selected by decision round 6:** none of the rows above as written. Device rekeys use the admin route (Remove plus Add by the approving admin daemon, sequenced next to the approval, public APIs only; `mls-integration.md` section 4.4). The continuity check runs after processing, the `prevSig` exception is removed, and the floor is ts-mls 1.6.4. Inferred, not tried: the plugin needs an npm `overrides` entry for ts-mls's exact `@noble/ciphers` peer.

Size: **S**.

### 1.2 Spike B: native keyring packaging through Paseo's plugin installer (identity Q3, X-13)

**Goal.** Find out whether a plugin installed by `paseo plugin install` can load `@napi-rs/keyring` 2.1.2 on Linux x64, and how it should do it.

**Probe plugin.** Create a throwaway plugin in `spikes/keyring-packaging/probe/`, with id `keyring-probe` (never `rooms`) and `requirements.paseo >=0.13.2`.

- Its server entry runs one check at `contribute()` time and logs the result as JSON. The result holds booleans and short strings only, never the secret.
- It finds its own directory from `$PASEO_HOME/config.json` `plugins["keyring-probe"].path` (F-3). It then loads the binding with `createRequire(join(dir, "package.json"))` and a variable specifier, so esbuild cannot see the import (F-1, F-2).
- It constructs `AsyncEntry("paseo-rooms-spike", "kek:packaging-probe", { linux: { store: "secret-service" } })`. It sets 32 random bytes, reads them back, compares in constant time, deletes the entry, and checks that a second read returns `null`. Every call has a 10 s `AbortSignal`.
- It reports: `bindingLoaded`, which platform package resolved (as a path relative to the plugin directory), `roundTrip`, `deleted`, error class names, the time each call took, and the `DBUS_SESSION_BUS_ADDRESS` it saw. The bus address is not a secret.
- `node_modules` is copied from `spikes/keyring/node_modules`. That directory already holds `@napi-rs/keyring`, `-linux-x64-gnu` and `-linux-x64-musl` 2.1.2 (verified), so no network is needed.

**Test daemon.** Use one throwaway daemon only.

- Home: `spikes/keyring-packaging/.home` (mode 0700, deleted afterwards).
- `config.json` is written before the first start, as `test/e2e/run.sh` does: listen `127.0.0.1:6920`, `daemon.relay.enabled: false`, `pluginsEnabled: true`, dictation and voice mode off. Also export `PASEO_DICTATION_ENABLED=false` and `PASEO_VOICE_MODE_ENABLED=false`.
- The script refuses to run if the port is 6767, is outside 6910 to 6939, or is already in use.
- Every CLI call sets `PASEO_HOME` and passes `--home`. The script records the main daemon's pid before and after, and fails if it changed. It never reads or writes `~/.paseo`.
- **The user's login keyring is never touched.** The daemon starts inside an isolated session: a temporary `HOME`, `XDG_RUNTIME_DIR` and `XDG_DATA_HOME`, a private `dbus-daemon` (`spikes/keyring/no-services.conf`), and a `gnome-keyring-daemon` unlocked with a throwaway password, as in `spikes/keyring/locked-test.sh`. The keyring spike found that leaving `XDG_RUNTIME_DIR` set reaches the real keyring (its section 3.4), so the probe's reported bus address must equal the private one, or the run is void.
- Cleanup always runs: `plugin remove`, `daemon stop`, kill the private bus and keyring, delete the temporary directories, and check that port 6920 is closed.

**Cases.**

| Case | Setup | Expected |
|---|---|---|
| B1 | Directory install of the probe | Compiles; binding loads from the probe's own `node_modules`; round trip passes in the isolated keyring |
| B2 | B1 with the platform package removed from a copy of the probe | Probe logs "native keyring unavailable"; plugin status stays `running` |
| B3 | B1, daemon started with `env -i HOME PATH PASEO_HOME` (no bus) | Pinned store throws at construction in under 1 s; probe reports "unavailable" (the fallback path) |
| B4 | npm-source install of a packed probe (`npm pack`), with `npm_config_offline=true` in the daemon's environment so its npm uses only the local cache | Platform package installed by Paseo's npm; binding loads. **Unknown** whether Paseo's npm source pattern accepts a local tarball, and whether the offline config reaches its npm. If either fails, record "not run: needs network" and ask the user. |
| B5 | Inspect the compiled server bundle (from plugin logs or the compiler error) | No `.node` content in the bundle; no esbuild loader error |

**What each outcome changes.**

| Outcome | Change |
|---|---|
| B1, B2, B3 pass; B4 passes | The native backend is the primary KEK store on Linux desktops. Q3 closes **for Linux x64 glibc only**. macOS, Windows, musl and arm stay untested until someone runs the same probe there. |
| B1 to B3 pass; B4 fails or cannot run offline | The native path works for directory installs (development). Releases through npm stay unproven. Milestone 3 ships the native backend behind capability detection and treats CLI backends and the fallback as the release default until B4 passes. |
| B1 fails (compile error, `createRequire` fails, or the directory cannot be found) | No native backend. Milestone 3 makes the no-native CLI backends (`secret-tool`, `security -i`, PowerShell DPAPI) and the fallback file the only paths. Linux desktops without `libsecret-tools` get the fallback file and its visible notice. Upstream requests 5 and 7 (`README.md` section 6) become important. **The user decides whether that is acceptable for a first release.** |
| B3 shows a hang instead of a fast throw | The 10 s timeout and the "locked" handling become a hard requirement of Milestone 3, and are tested before anything else in it. |

Size: **S/M**.

**Result (2026-10-29, run in `spikes/keyring-plugin/`, see its `RESULTS.md`).** B1 to B5 pass on Linux x64 glibc. B1: a directory install loads the gnu `.node` from the probe's `node_modules` and round-trips in the isolated keyring. B2: the missing platform package gives a clean load error, and the plugin stays `running`. B3: with no bus, the pinned store throws at construction in 0 ms. B4: an npm-source install from an offline local registry installs the linux-x64 platform packages and the probe loads them. Caveat: the tarballs came from the npm cache, so no real download was exercised. B5: the bundle holds no native code, and a static import fails to compile ("No loader is configured for .node files"). The directory locator (`$PASEO_HOME/config.json` `plugins[id].path`) worked for both install kinds. `__dirname` and `import.meta.url` are unavailable, so the locator stays fragile: `--id` installs and a daemon without `PASEO_HOME` were not tested. The first outcome row applies: the native backend is the primary KEK store on Linux x64 glibc desktops, and the fallback file is used only when the backend is unavailable. macOS, Windows, musl and arm are untested.

### 1.3 Other gates

| Gate | Why | Size |
|---|---|---|
| Targeted check of the R-1 to R-12 fixes, and regenerate the vectors twice with a byte-identical result | Decisions round 4, item 4. `README.md` section 9 lists it as pending. | S |
| User decisions D-1 and D-2 (section 5) | They decide how the code base is set up for the rewrite. | n/a |

## 2. Dependency order

```
Step 0 ──► I-1 encoding ──► I-4 Noise IK ──────────────────────┐
           I-2 file layer ─► I-3 KeyStore ──► I-7 room host core ─► I-8 room endpoint ─► I-9 enrollment ─► I-10 grants v2
           I-1 ──► I-5 fold core ──► I-6 fold authority ──► I-7        │                 │
                                                                   │                 └► I-11 device linking
                                                                   └► I-13 MLS adapter (Spike A done)
           I-12 rotation and recovery (after I-9, I-11; device rekey after I-13)
           I-14 Rooms UI v2 (after I-9; grows with I-10 to I-12)
           I-15 cut-over and migration (after I-10, I-14)
           I-16 X-3 and X-5 (independent; any time, suggested right after Step 0)
           I-17 traceability and docs (last)
```

I-1, I-2, I-4, I-5 and I-16 do not depend on each other and can run in parallel.

**Build next to M1, then cut over.** New code goes into new directories and is reached only by unit tests until Milestone 8. From Milestone 8 to Milestone 15, `index.server.ts` wires a v2 runtime only when a development switch is set (`PASEO_ROOMS_PROTOCOL=v2`, read once at start). The M1 runtime, its tests and its e2e stay green until Milestone 15 deletes them. No release happens in between, so the spec's "no dual-stack period" holds for releases. This is decision D-2.

**Proposed layout** (new directories under `server/`):

| Directory | Contents |
|---|---|
| `server/proto/` | RJCS, strict base64url, TBS, hashes, ids, key ids, fingerprints, strict zod schemas of signed objects |
| `server/platform/` | home resolution, `FileProtection` (POSIX and win32 backends), durable writes, log writer lock |
| `server/keystore/` | `KeyStore` interface, backends, `meta.json`, sealed files |
| `server/noise/` | vendored `CipherState` and `SymmetricState`, new `HandshakeState` (NK and IK), `LICENSE` (Apache-2.0) |
| `server/transport/` | relay server socket (extracted from `lane-endpoint.ts` `RelayConnection`), records and frames, room session base |
| `server/authority/` | statements, entries, fold, re-fold, lineages, holds, roster |
| `server/admin/` | genesis, admin signer and confirmation tokens, recovery key |
| `server/host/` | room log store, room host, room endpoint, invites, enrollment (host side), grants and allowlist, delivery service |
| `server/member/` | room client, enrollment journal, grant scheduler, device link, lane registration |
| `server/mls/` | adapter, authentication service, roster rule |
| `server/migration/` | M1 archive and member-side cleanup |

Unit tests use flat names (`test/unit/v2-*.test.ts`), so the existing `npm test` glob (`test/unit/*.test.ts`) picks them up unchanged.

## 3. Milestones

Every milestone ends with `npm run typecheck` clean and `npm test` green. "Linux" in the cross-platform notes means the development machine (Ubuntu 24.04, Paseo's Node 24.20.0). Win32 and darwin branches are unit-tested on Linux through injected `fs` and `spawn` adapters. That checks our logic, not the OS. Every non-Linux cell stays **untested** until someone runs it on a real host (architecture principle 10).

### I-1. Encoding, signatures and vectors

**Specs:** `signatures-and-encoding.md` sections 2 to 8; `identity-model.md` section 8.

**Add:**
- `server/proto/rjcs.ts`: serialize, plus a strict parse that requires the bytes to equal their re-encoding, and rejects duplicate keys, floats, `-0`, integers of 2^53 and above, non-ASCII keys, `__proto__`, `constructor` and `prototype`.
- `server/proto/b64u.ts`, `tbs.ts` (`TBS`, `Sign`, `Verify`, `H`, HKDF and HMAC labels), `ids.ts` (`mem_`, `dev_`, `inv_`, `lnk_`, `pen_`, `lane_`, `scp_`, `kek_`, `g_`, `rme_`, `rle_`, `room_`), `keys.ts` (`kid`, fingerprints, small-order key rejection, the `S + L` signature check).
- `server/proto/contexts.ts`: one constant per context and label, matching the tables in sections 3.2 and 3.3.

**Replaces:** `server/crypto.ts` helpers `keyIdOf` (64-bit), `randomHexId` (8 bytes) and `hexEqual`. M1 callers keep the old file until Milestone 15. `shared/control.ts` `canonicalJson` is not reused.

**Tests:**
- `v2-vectors-encoding.test.ts` reads `docs/specs/identity-v2/vectors/vectors.json` directly, so the tests and the spec cannot drift. It covers `rjcs.accept` and `rjcs.reject` (all 20 reject inputs), `base64url`, `ed25519` (small-order keys, `S + L`), `keys` (kids, fingerprints), the context separation of every statement signature, and `sealed` AAD bytes.
- Write the production code from the spec, not by copying `gen-vectors.mjs`. Otherwise the vectors only test the generator against itself.
- Answer signatures Q1 (zod `.strict()` on nested signed objects) with a test.

**Cross-platform:** pure JS, no platform code. Assumed to behave the same everywhere.

**Exit:** every vector section in scope passes.

**Size: M.**

### I-2. File layer: protection, durable writes, log lock (X-1, X-2, X-4, X-6, X-7, X-8, X-9, X-15)

**Specs:** `identity-model.md` 7.8; `grants-v2.md` 7.3.

**Add:**
- `server/platform/home.ts`: copy the daemon's `expandHomeDir` semantics exactly (X-8). If `homedir()` throws, report a typed "set PASEO_HOME" error. Also provides `canonicalHome` for the KeyStore entry name.
- `server/platform/file-protection.ts`: interface `{ ensureDir, createFile, verifyTree, fix }`.
  - POSIX backend: explicit modes on every create, then `chmod` and read the mode back (refuse if it did not take effect, which catches drvfs); `lstat` the whole tree, refuse symlinks, require the owner to equal `geteuid` and no group or other bits; no silent repair.
  - Win32 backend: `icacls` by absolute path with SID syntax through `execFile`; read SDDL through PowerShell; refuse reparse points; compare paths after case-folding (R-11).
- `server/platform/durable.ts`: `writePrivateFile` with an exclusive-create temp file (`wx`), fsync, rename, a win32 retry on EPERM, EACCES or EBUSY for up to 2 s, temp cleanup in `finally`, and never delete the target first. Directory fsync on POSIX, ignoring only EINVAL, ENOTSUP, EISDIR and EPERM. No directory fsync on win32. `appendLine` with a single `write`. `readJsonFile` strips a BOM (X-15).
- `server/platform/log-lock.ts`: `writer.lock` holding pid and instance id, 10 s heartbeat, ownership check before every append, 60 s staleness, 30 s wait, takeover by rename, deletion on clean shutdown (R-6).

**Change:** `server/paths.ts` becomes a thin wrapper over these modules, so M1 code gains the fixes now. Log path shortening uses `path.relative` (X-7: `runtime.ts:30`, `event-log.ts:114`). `MemberRole.save` gets the same retry as `HostStore` (X-4). `fileMode` in tests becomes `FileProtection.verify` (X-9).

**Startup check:** `RoomsRuntime` runs `verifyTree(dataDir)` before reading any key file. On failure it loads no keys, returns a typed error, and offers a "Fix permissions" RPC (X-2). An EPERM in the constructor becomes the same typed error.

**Tests:**
- Durable-write fault injection: a failing rename leaves no temp file; a win32 retry succeeds after two EBUSY errors; a rename that fails for 2 s gives `persist_failed`.
- `verifyTree`: a symlink, mode 0644, a foreign uid (faked) and a mode that did not change after chmod are each refused.
- Win32 SDDL fixtures: a protected DACL with one user SID passes; an inheriting DACL or `BU` read access fails.
- Lock: two in-process holders with a faked clock; a stalled holder loses ownership and stops appending.
- Home resolution: `~`, `~/x` and `~\x` forms.

**Cross-platform:**

| Item | Linux | macOS | Windows | WSL | Docker |
|---|---|---|---|---|---|
| POSIX modes and check | tested | untested | n/a | untested (drvfs refusal logic tested with a fake) | untested (volume ownership) |
| DACL apply and check | n/a | n/a | logic tested with fakes; OS untested | n/a | n/a |
| fsync and directory fsync | tested | `F_FULLFSYNC` unverified | `FlushFileBuffers` and rename retry untested | as Linux | as Linux |
| Lock takeover | tested | untested | untested | untested (mtime on `/mnt/c`) | untested (bind mounts) |

**Exit:** the M1 e2e still passes with the new file layer (one run on 6891/6892 as today, or moved into 6920 to 6929).

**Size: M.**

### I-3. KeyStore and sealed files (X-13, A8)

**Specs:** `identity-model.md` 7.1 to 7.5, 7.7; `keys-rotation-recovery.md` 4.9.

**Add:**
- `server/keystore/keystore.ts`: the interface and selection by capability detection.
  - An explicit backend (`PASEO_ROOMS_KEYSTORE` or plugin settings) is used or fails; it is never substituted.
  - Then the native binding, then the CLI backend, then the fallback file.
  - The choice is recorded in `meta.json` and never changes silently.
  - Every call is async with a 10 s timeout, and a timeout counts as "locked".
- `napi-backend.ts`: lazy `createRequire` load as Spike B settled; the Linux store is always pinned to Secret Service; never keyutils.
- `cli-secret-tool.ts`, `cli-macos-security.ts` (`security -i` with commands on stdin), `cli-win-dpapi.ts` (PowerShell 5.1, KEK on stdin). All three use absolute executable paths, `execFile` without a shell, and keep secrets out of argv.
- `fallback-file.ts` and `operator-file.ts` (`PASEO_ROOMS_KEK_FILE`).
- `sealed.ts`: XChaCha20-Poly1305 (`@noble/ciphers`), HKDF file keys, AAD binding of the purpose.
- `meta.ts`.
- Migration from the fallback to the keyring once a backend appears: re-seal under a new KEK, then delete the fallback file.
- KEK rotation: decide here whether it is in scope for this release (keys 4.9).

**Change:** `RoomsRuntime` start becomes asynchronous. `contribute()` must not block for 10 s, so the runtime gets the states `starting`, `locked`, `unprotected-fallback`, `permission-error` and `ready`, and RPCs return a typed error until it is `ready`. `index.server.ts` and the client must handle these states.

**Dependencies:** add `@napi-rs/keyring` at exactly 2.1.2 (if Spike B allows). Make `@noble/ciphers`, `@noble/hashes` and `@noble/curves` direct dependencies at exactly 2.4.0. The `sealed` vector uses `@noble/ciphers` 2.4.0 (verified in the spec).

**Tests:**
- The `sealed` vector.
- The outcome table of 7.3: the keyring returns the KEK; throws; returns `null` while `meta.json` says keyring; times out. Each case maps to the specified action, and the KEK is never regenerated silently.
- A `meta.json` that names a keyring never falls back.
- The fallback notice flag is raised.
- A CLI backend never puts the secret in argv (the spawn adapter captures argv).
- Opening a sealed file under the wrong purpose fails.
- A modified ciphertext fails.
- Live keyring tests run only on request (`ROOMS_LIVE_KEYRING=1`), and only inside the isolated keyring session from Spike B, never the user's login keyring.

**Cross-platform:** Linux Secret Service tested, if Spike B passes. Headless detection tested. Everything else untested: macOS Keychain, Windows Credential Manager, all three CLI backends (`secret-tool` is not installed on the development machine, per the keyring spike), WSL, Docker and musl.

**Exit:** a fresh `PASEO_HOME` in unit tests reaches `ready` with each backend kind faked. A sealed round trip works.

**Size: L.**

### I-4. Vendored Noise with IK, records and frames

**Specs:** `enrollment-v2.md` 3.2 to 3.6; signatures 9.3.

**Add:**
- `server/noise/cipher-state.ts` and `symmetric-state.ts`, vendored unchanged from Paseo commit `1467121`. Keep the upstream copyright line and a "changed" marker where we change anything.
- `server/noise/handshake-state.ts`: a pattern table with NK and IK; the 65 535-byte limit; all-zero DH results rejected; the ephemeral secret zeroed at `split()`; ephemeral injection for tests only.
- `server/noise/LICENSE` (Apache-2.0).
- `server/transport/records.ts`: one-byte flags, fragments, frames of at most 4 MiB, strict RJCS frames.

**Tests:**
- The cacophony NK and IK vectors, six of six messages each (copied from the generator's pinned source).
- `noise.enrollment` and `noise.ikCacophonyKeys`.
- Paseo's `noise.test.ts` negatives, ported: tampered message, out-of-turn message, oversized message, invalid DH key.
- IK negatives: a modified encrypted static fails; the responder learns the initiator's static only after `es`.
- The `records` vectors.

**Cross-platform:** pure JS on `@noble`. Assumed identical everywhere.

**Exit:** all required tests from 3.2.1 pass in `npm test`.

**Size: M.**

### I-5. Room log and fold, core

**Specs:** `room-log-v2.md` 1 to 3, 4.0, 4.2 to 4.5, 5 (without re-fold, lineages and holds), 8.1 parsing rules; `identity-model.md` 5.1, 5.2, 6.1.

**Add:**
- `server/authority/statements.ts`: zod schemas per statement type, strict. There are about 50 types in section 4 (counted).
- `entries.ts`: `LogEntry`, `SignedEntry`, the chain check.
- `fold.ts`, as a pure function. It covers:
  - the base, unique, forward and ref rules;
  - versions (`ver`) per field;
  - roster changes from admission, removal, leaving, role and lane changes;
  - `rosterSeq` at the last roster-changing entry;
  - the roster hash;
  - `invalid_entry` stops processing instead of skipping;
  - unknown types are an error.
- `roster.ts`.

**Replaces (later):** `server/host/event-log.ts` (host-signed plaintext log). It stays for M1 until Milestone 15.

**Tests:** `genesis`, `statements`, `log.entries`, `log.rosterAfter`, `log.foldChecks` (replay, held statement, ABA, base at its own position, base hash not in the chain), `log.equivocationExample`.

**Cross-platform:** pure. **Exit:** the fold accepts the main chain and rejects every `foldChecks` case with the expected reason. **Size: L.**

### I-6. Fold: key changes, revocation, lineages, closure, device holds

**Specs:** `room-log-v2.md` 4.1, 4.3, 5 (`apply` rules on holds), 5.1, 5.2; `keys-rotation-recovery.md` 2, 3; `identity-model.md` 6.2, 6.3.

**Add:**
- `server/authority/refold.ts`: `admin.key.revoked` and `host.key.revoked` with `fromSeq` bounds and authority starts, plus suspect and void marking.
- `lineage.ts`: lineage roots, independence for closure, the first recovery key needing two lineages.
- `holds.ts`: 24 h and 72 h holds measured in `hts`, vetoes, conflicts, cancellation when the requester is removed, no auto-add from devices younger than 24 h, the `soleDeviceChange` and `deviceAddApproval` policies.
- `KeyChange` and `key-change-new` verification; the retired-key set; the device and admin denylists.

**Spike A outcome:** the fold of `device.rekey.approved` is unchanged, and no `prevSig` bookkeeping is needed (decision round 6; `mls-integration.md` section 4.4).

**Tests:** `log.refold` (including `rejectRevocationBeforeStart`), `log.closure` (one accepted, three rejected), `deviceLink.chain` and `deviceLink.chain.cases`, the recovery-key `null` format examples (format only), and an admin key that adds a ghost which a recovery-key revocation removes. Also `deviceRekey` (sole-device rekey: 24 h rejected, 72 h accepted). Two vectors still missing from the generator must be added here: `device.rekey.vetoed`, and a sole-device rekey under `soleDeviceChange = "admin"` (needs `room.policy.changed` in the generator's fold).

**Cross-platform:** pure. **Exit:** every fold self-check the generator lists in signatures 9.2 is reproduced by the production fold. **Size: L.**

### I-7. Room host core, offline: genesis, admin signer, log store (P-27)

**Specs:** `identity-model.md` 5.1 to 5.4, 7.1; `room-log-v2.md` 2 (host validation, `stale_base`, `unknown_base`, outstanding statements, `producer.fence`), 4.6, 4.7, 8.1, 8.2.

**Add:**
- `server/admin/genesis.ts`: room creation, admin key, host key, room endpoint key, policy, and the recovery key offered by default and skippable in one click.
- `server/admin/signer.ts`: admin statements signed only after a UI confirmation token. The spec says this is a usability guard, not a security boundary (identity 5.3).
- `server/host/room-log-store.ts`: `entries.jsonl` and `bodies.jsonl` under the I-2 lock; torn-line handling; the log treated as the source of truth on restart (re-fold).
- `server/host/room-host.ts`: `stmt.submit` validation through the fold, receipts, and the host-produced events of 4.6 (P-27).
- Key files: `admin/<roomId>/admin-key.sealed` and `host/<roomId>/keys.sealed` through I-3.

**Tests:** create a room in a temporary home; append, crash and reload (torn final line moved aside; a bad middle line stops the room); `stale_base` after a concurrent change; an outstanding statement made void by a `producer.fence`; every security event in 4.6 appears with its producer.

**Cross-platform:** inherits I-2 and I-3. **Exit:** a room can be created, changed and reloaded entirely offline. **Size: L.**

### I-8. Room endpoint transport and sessions

**Specs:** `enrollment-v2.md` 3.1, 3.3 to 3.6, 4, 4.1; `room-log-v2.md` 6, 8.3.

**Add:**
- Extract `RelayConnection` from `server/gateway/lane-endpoint.ts` into `server/transport/relay-server.ts`. The lane endpoint and the room endpoint share it.
- `server/host/room-endpoint.ts`: IK responder with the room prologue; the first client message must be exactly 96 bytes; 10 s handshake timeout; records; a session lasts at most 12 h; ping after 30 s and close after 90 s; one session per device, superseding the old one only after key confirmation (S-10); pre-auth versus active-device operation gating; `access_ended` revealed only after the handshake.
- `server/member/room-client.ts`: IK initiator, `session.hello`, head comparison, `log.fetch`, `log.subscribe`, gossip checks (`unverified_head_claim`, `fork` only with proof, truncation), and alerts.
- `test/unit/fake-relay.ts`: an in-process relay that implements the relay protocol v2 pairing of server and client sockets (F-7).

**Wiring:** from here on, `index.server.ts` wires a v2 runtime when `PASEO_ROOMS_PROTOCOL=v2` is set (decision D-2).

**Tests:**
- Unit, over the fake relay: a wrong prologue fails; a replayed message 1 cannot push out a live session; an unknown static gets `not_authorized`; a removed device gets `access_ended`; equivocation is detected from two signed heads.
- **E2E (new, `test/e2e-v2/`):** two test daemons, owner `127.0.0.1:6921` and member `127.0.0.1:6922`, same safety gates as `run.sh`; homes under `plugin/.test-homes/v2-*`. The relay is either a local fake relay process on 6923 (offline) or the live relay (needs network and the user's go-ahead per run, as M1 did). Whether the fake faithfully models the real relay is an assumption that only a live run settles.

**Cross-platform:** Linux only. Relay, `ws` and Noise are pure JS. **Exit:** a member with a hand-made roster entry opens a session and syncs the log. **Size: L.**

### I-9. Enrollment v2 (A1; D fixes P-15/C-7, P-23/C-8, P-20/C-15, C-10, P-27)

**Specs:** `enrollment-v2.md` 2, 5 to 10; `room-log-v2.md` 4.2.

**Add:**
- `server/host/invites.ts`: `prc2.` codes; `tokenKey` from the HKDF; `inviteRef` in the log.
- `server/host/enrollment.ts`: the check order of 5.3 (signature first, then lookup, one generic rejection code before the token proof); token proven by an HMAC bound to `h`; per-invite limits (3 attempts that reach the SAS; 3 abandoned attempts burn the invite); pre-auth budgets counted per unknown static; the SAS commit-then-reveal; the pending state machine; `invite.contested`.
- `server/member/enrollment-journal.ts`: the journal states of 7.3, `sentH`, a byte-identical pending on resume, `Nm` persisted before the first request.
- `server/member/lane-registration.ts`: idempotent `hosts.add` and `hosts.update` with backoff (section 8, C-10). Port the `hosts.observe` logic from `member.ts`.
- Member-side invite checks: `useTls` required; relay allowlist or explicit user confirmation; verified, prefixed lane labels (2.2, 2.3; P-20/C-15).
- `member.admitted` carries the SAS transcript hash.

**Tests:**
- The `invite` and `enrollment` vectors (`EnrollSigned`, token MAC, SAS digits `317 837`, transcript hash).
- Check order: a bad signature never reaches the lookup, so no membership oracle exists (P-23).
- Wrong tokens from many statics burn nothing (P-15).
- The third abandoned attempt burns the invite.
- A resume with a changed pending is refused (S-3), and so is an unrecorded `h` (R-4).
- A restart in every journal state resumes correctly.
- `hosts.add` failure retries and leaves a local record (C-10).
- A plaintext relay is refused, and an unknown relay needs confirmation (P-20).
- The races of section 9, table-driven.
- **E2E (6921/6922):** create a room, invite, compare the SAS through the owner and member RPCs, admit, see the member in the roster, then restart both daemons mid-pending and resume.

**Cross-platform:** Linux only. **Exit:** a full SAS enrollment end to end on test daemons. **Size: L.**

### I-10. Grants v2 and lane endpoint (P-9; P-12, P-13, P-24 kept)

**Specs:** `grants-v2.md` 2 to 11, 13.

**Pre-check (offline reading):** grants Q2, whether Paseo 0.13.2's connected-host link has a ping that the destination side can send. If it has none, use the weaker socket-liveness rule and record it.

**Add:**
- `server/host/grants.ts`: `prg2.` tokens, the claims format, issuance with push-before-persist, `current[(deviceId, laneId)]`, the denylist with `heldMs` and the 30-day backstop, `notBefore`.
- `server/member/grant-scheduler.ts`: monotonic `t0`, idle rotation at 50 %, forced at 75 %, last resort at `L - 60 s`; the idle rule of section 5; `grant.status` and `grant.report`; re-arming after a restart.

**Change `lane-endpoint.ts`:**
- Delete the `rooms.control.*` first-frame switch (the `rooms.control.hello` branch and `control` mode in `RelayConnection`, around lines 365 to 490 today).
- Verify grants in the order of section 4, with the `gid` allowlist as the primary check and `role` equal to the roster role.
- At most one link per (device, lane), with the ping test and `grant.suspected-theft`.
- Count only failed attempts against the token bucket.
- Reduce routes per link to 32.

**Replaces:** `server/grants.ts` and `HostStore.checkGrantLive`.

**Keeps:** the Room Profile filter and sanitizer; viewer error and project-name behaviour from `FIXES-B-D.md` (`lane.names.changed` and policy `projectNames` replace `showProjectName`).

**Tests:**
- The `grant` vector.
- Each step of the verification order.
- A stolen grant on a second live link closes both links and logs theft (P-9).
- An unaccounted link never defers rotation.
- A role downgrade cuts the link (S-9).
- Enforce then persist, with `persist_failed` visible (port the M1 durability tests).
- Pruning only after `exp + 10 min` and 24 h held.
- Clock-skew cases.
- **E2E:** lane view through the member as in M1, a revoke cut within milliseconds, idle rotation and forced rotation with short grants (`PASEO_ROOMS_DEV_SHORT_GRANTS=1`), and a secret scan for `prg2.` and `prc2.`.

**Cross-platform:** Linux only. **Exit:** the M1 e2e scenarios pass on v2 with grants v2. **Size: L.**

### I-11. Device linking and holds

**Specs:** `identity-model.md` 6.3, 6.4; `enrollment-v2.md` 5.4 (link limits); `room-log-v2.md` 4.3.

**Add:**
- `server/member/device-link.ts`: `prl2.` codes, the frames `link.request`, `link.nonce`, `link.reveal`, `link.confirm`, `link.abort` and `link.closed`.
- On the confirming device, its own counters: at most 1 `Nc` per pending, 1 open pending, and 3 per link, sealed before `link.nonce` (R-2).
- The new device's enrollment reuses I-9 with a `linkId`.
- Host states including `held`; the admin daemon's automatic approval after the hold on its own clock; veto and conflict UI hooks; removing a device cancels its pending requests.

**Tests:** the `deviceLink` vectors; a malicious host cannot choose `Nc`; a fourth link attempt is refused locally; a 72 h hold for a sole device; a veto opens a conflict; an admin approval path when the policy requires it. E2E: a second member daemon on 6924 links as the same person; the hold is shortened only under a test-only clock override on the host and the admin daemon.

**Cross-platform:** Linux only. **Exit:** a person with two devices in one room, each with its own keys. **Size: L.**

### I-12. Rotation and recovery operations

**Specs:** `keys-rotation-recovery.md` 4, 6.

**Depends on:** I-13 for the MLS half of the device rekey.

**Add:** operations and UI flows for:
- device rekey by the admin route (decision round 6; `keys-rotation-recovery.md` 4.1, `mls-integration.md` 4.4): the device publishes new-credential KeyPackages with its request; after the hold, or on interactive approval, the admin daemon signs `device.rekey.approved`, builds the Remove plus Add commit naming the post-approval roster, and submits both with `commit.submit {…, statement}`; then it repeats the commit in each subgroup the device is in. With no admin daemon online nothing is signed and the device shows "Waiting for an admin device". The rekeyed device skips the commit with its old state, rejoins by Welcome and deletes the old state. The host refuses `device.rekey.approved` through `stmt.submit`;
- periodic leaf refresh: an UpdatePath from the public `createCommit` every 7 days or 1 000 messages, credential unchanged (`keys-rotation-recovery.md` 4.2);
- admin key rotation, add and revoke;
- the recovery key: install, rotate, and propose with two lineages;
- host key rotation with `oldValidTo`;
- room endpoint rotation, and the 30-day stranding rule;
- lane offer rotation on a compromise removal (`rotateLaneOnRemove`);
- closure with `closeDelay`;
- the recovery procedures of section 6 as guided flows.

**Tests:** each rotation keeps the fold valid and the grants valid within their windows; a rekey with the admin daemon offline stays requested and the old keys keep working; a rekey whose new-credential KeyPackage is missing is not approved; a revoked host key's grants are refused; a closure before the delay is refused by the confirming daemon; recovery from a stolen admin key with R. **Size: M.**

### I-13. MLS adapter and delivery service (Spike A done)

**Specs:** `mls-integration.md` all.

**Add:**
- `server/mls/adapter.ts`: the only importer of ts-mls, pinned at exactly 1.6.4 (floor 1.6.4; the removal check fails on 1.6.2). Public API only: no fork of `createCommit`, no imports through the `./*.js` subpath exports.
- `auth-service.ts`: a closure over the reference roster; fails closed when no roster is set; rule 6 requires the roster key with no `prevSig` exception (Spike A, decision round 6). For a Welcome, the reference roster is the one the Add commit names.
- `roster-rule.ts`: roster equality before and after processing, with leaf identity `(memberId, deviceId, deviceSig)`, in its round 7 form (`mls-integration.md` 4.2 rules 1 to 3): every leaf in the roster, at most one leaf per `(memberId, deviceId)`, no valid roster leaf removed, pending adds tolerated, old-key leaves removed; role checks in the `IncomingMessageCallback` by `senderLeafIndex`; the continuity check after processing (sender's leaf credential byte-identical before and after a path commit); who may commit what (4.3, decisions round 7): roster-determined Adds and rekey Remove plus Add by any device of the group, leaf replacement, GroupContextExtensions and ReInit by admin devices only.
- The admin route for device rekeys (`mls-integration.md` 4.4): Remove plus Add commit builder, `commit.submit` with `statement`, adjacent sequencing on the host, and the rekeyed device's rejoin by Welcome. The repair rule for any device of a group (60 s, plus up to 60 s of random delay for devices that are not admins).
- npm `overrides` for ts-mls's exact `@noble/ciphers` peer, so it shares the plugin's noble 2.4.0 (Spike A case (g); the override itself is untried).
- The authority extension `0xF0A1`.
- Sealed state written before the ack; rollback check against `lastAck`; key retention 2, 64 and 1000.
- Host delivery service: `kp.publish`, `kp.fetch` (any device for `current` packages of devices it shares a group with, `rekey` for admins only, the per-target `g + 2` cap and the per-fetcher `k` cap of 6.4), `commit.submit` (one commit per epoch, `stale_roster`, optional `device.rekey.approved` sequenced adjacently or not at all), `welcome.fetch`, `msg.send`, `msg.fetch`, `pending_remove`, and `mls.stalled` after 5 minutes.
- A dev-only alias `ts-mls-162` for the positive control.

**Tests:** MLS section 10, tests 1 to 10, with test 11 already done in Step 0. Test 10 is the admin-route rekey and the continuity check; its Remove plus Add path was not run in Spike A. E2E: two members exchange an application message; the removed one cannot read the next one; the host files hold no plaintext.

**Note:** chat UI is not in this plan (it is Milestone 2 of the product). See decision D-4 on whether this milestone ships with identity v2 or opens I-2.

**Size: L.**

### I-14. Rooms UI and RPCs for v2

**Add, in `client/` and `shared/rpc.ts`:**
- keystore state and fallback notice; "Fix permissions";
- recovery key display and download, working on every client (identity 7.3);
- the SAS screens for the owner and the member (enrollment 6.3, 6.4);
- admin confirmation dialogs, including the `stale_base` re-confirmation;
- device list, link, veto and conflict views;
- security alerts (fork, truncation, withholding, `roster_mismatch`);
- confirmations on close lane, leave and revoke;
- the weaker Windows durability statement in About;
- the "agents from closed rooms" list and the M1 archive notice.

The RPC contracts land with each earlier milestone. This milestone builds the screens.

**Tests:** a client typecheck with no node types (X-12: `tsconfig.client.json`); RPC contract tests. The real app UI stays unverified until someone runs the manual check (M1 U1), on a light and a dark theme and a narrow window.

**Size: M/L.**

### I-15. Cut-over and migration from M1

**Specs:** `migration.md`.

**Add:** `server/migration/v1.ts`:
- detect v1 data;
- archive `gateway/` and `member/` by rename, with the win32 retry;
- `hosts.remove` for v1 lane registrations once a `PaseoApi` is available;
- `migration.json`, idempotent;
- the archive notice with the "delete keys" action, which needs the user's consent and keeps the logs;
- a `prc1.` code gets the upgrade message and no network call.

**Delete:** `shared/control.ts`, `server/gateway/control-server.ts`, `server/member/control-client.ts`, `server/invite-code.ts`, `server/grants.ts`, `server/host/event-log.ts`, `server/host/host-store.ts`, the M1 parts of `server/member/member.ts` and `server/crypto.ts`, v1 schemas in `shared/schemas.ts`, the `PASEO_ROOMS_PROTOCOL` switch, `test/unit/host-grants.test.ts` and `event-log.test.ts`, and the v1 e2e flow. Mark `docs/specs/rooms-control-protocol.md` and `data-model.md` as superseded (migration 5).

**Tests:** migration tests 1 and 2 (unit, fixture v1 tree). Migration test 3 (e2e upgrade from an M1 build on 6925/6926) needs the M1 code base as a fixture, which depends on decision D-1.

**Exit:** no v1 code path remains; all unit tests and the v2 e2e are green. **Size: M.**

### I-16. X-3 and X-5 (independent of identity v2)

- **X-3** (`server/gateway/local-daemon.ts`): parse the listen address with `parseHostTarget` from `@getpaseo/protocol/host-target`; open `ws` with `socketPath` for pipes and unix sockets; map wildcard addresses to loopback; expand `~/`. Unit tests for `\\.\pipe\paseo`, `pipe://…`, `unix:/…`, `[::1]:6767` and `0.0.0.0:6767`.
- **X-5** (`agent-guard.ts`, `tripwire.ts`): accept any stored command whose resolved basename is a Paseo binary, with `ELECTRON_RUN_AS_NODE` set and `args[0]` exactly our `inert-mcp.cjs`; compare paths case-insensitively on win32 and darwin; refuse a stale lane with a clear message.
- Optional in the same change: X-11 (split CSV lines on `\r?\n`), X-14 (map a drive root to `/room`).

**Cross-platform:** pipe and Windows install layouts untested; logic unit-tested on Linux. **Size: S.**

### I-17. Traceability, documents and results

**Add:**
- a table that maps every finding resolved by the specs (README 4.2 and 4.3, the S and R findings, X-1 to X-15) to the tests that cover it;
- `IDENTITY-V2-RESULTS.md` (a results document in the style of `M1-RESULTS.md`) with the platform matrix, every non-Linux cell marked untested;
- the architecture edits of migration section 5;
- update `README.md` and `OVERVIEW.md`.

The attack harness of hardening section E is out of scope. It runs only after the user approves it. **Size: S.**

## 4. M1 code: replaced, kept, migrated

| M1 file | Fate | Milestone |
|---|---|---|
| `server/room-profile/*`, `profile/*.csv`, `tools/*` | kept | none (B fixes already done) |
| `server/gateway/agent-guard.ts`, `tripwire.ts` | kept; X-5 edit | I-16 |
| `server/gateway/local-daemon.ts` | kept; X-3 edit | I-16 |
| `server/gateway/lane-errors.ts`, `server/limits.ts`, `server/log.ts`, `shared/policy.ts` | kept; new limits; X-7 | I-2, I-10 |
| `server/gateway/gateway.ts` | kept for forks and curated context; room and lane creation rewired to admin statements | I-7, I-10 |
| `server/gateway/lane-endpoint.ts` | heavily changed: relay code extracted, control switch removed, grants v2 | I-8, I-10 |
| `server/paths.ts` | wrapper over `server/platform/`, then removed | I-2, I-15 |
| `server/runtime.ts`, `index.server.ts` | rewritten for async start and v2 RPCs | I-3, I-8, I-15 |
| `shared/rpc.ts`, `shared/schemas.ts` | v2 views; v1 schemas deleted (ids grow from 16 to 32 hex) | I-14, I-15 |
| `server/crypto.ts`, `server/grants.ts`, `server/invite-code.ts`, `shared/control.ts`, `server/gateway/control-server.ts`, `server/member/control-client.ts`, `server/host/event-log.ts`, `server/host/host-store.ts` | replaced, deleted at cut-over | I-1 to I-10, I-15 |
| `server/member/member.ts` | rewritten around the journal; `hosts.*` and observation logic ported | I-9, I-15 |
| `test/unit/room-profile`, `field-policy`, `viewer-policy`, `tripwire` tests | kept | none |
| `test/unit/lane-endpoint`, `durability`, `secrets-and-guard` tests | ported to v2 | I-2, I-10 |
| `test/unit/host-grants`, `event-log` tests | replaced | I-15 |
| `test/e2e/` | skeleton reused; flows rewritten; ports moved into 6920 to 6929 | I-8 to I-15 |
| `test/reliability/` | enrollment module rewritten; runs only with the user's approval | after I-9 |

**Data migration of existing test state.** M1 state exists in disposable test homes: `.test-homes/` (deleted by default after e2e), `ui-check` demo homes, and `test/reliability/.homes`. Delete them with their own `down` scripts instead of migrating them. The migration code is tested on a fixture v1 tree built in unit tests (from `test/unit/fixtures.ts`), and once end to end against an M1 build. If the M1 plugin was ever installed on a real daemon, the migration of `migration.md` section 2 runs there on first start. I did not check `~/.paseo`, so I do not know whether that applies.

## 5. Decisions and risks that need the user

| # | Question | Recommendation |
|---|---|---|
| D-1 | The project has no version control (F-6). | Put the project workspace under a local git repository (no remote) and tag the M1 baseline before I-1. This also provides the M1 build for migration test 3. |
| D-2 | Development switch `PASEO_ROOMS_PROTOCOL=v2` from I-8 to I-15, versus one large cut-over. | Use the switch. It keeps the M1 e2e green and lets v2 e2e grow milestone by milestone. It never ships. |
| D-3 | If Spike B fails: is a first release with the fallback file (and visible notice) as the Linux desktop default acceptable? | Decide after Spike B. |
| D-4 | Does the MLS adapter (I-13) ship with identity v2, or open product Milestone 2? | Ship it here. Its authentication service is identity-critical. Chat UI stays in I-2. |
| D-5 | Network: e2e runs against the live relay, and Spike B case B4 may need npm. | Approve per run, as for M1. The fake relay keeps routine runs offline. |
| D-6 | The plugin has no license (README open question 4). Vendored Apache-2.0 Noise needs one before release. | Choose before the first release, not before coding. |
| D-7 | Upstream requests 1 to 7 (`README.md` section 6) are unsent. Request 5 or 7 removes the F-2 and F-3 workarounds. | Send 1, 5 and 7 after Step 0, with Spike B's evidence. |

| Risk | Mitigation |
|---|---|
| Scope: 17 milestones, 9 of them L | Build next to M1; each milestone ships its own tests; I-1 to I-6 are pure and testable without daemons |
| The fold is complex, and it exists in two implementations (generator, production) | Write production code from the spec; the vectors catch divergence; add property tests (random statement sequences fold the same twice, re-folds are independent of order) |
| Native keyring loading depends on undocumented Paseo internals (F-2, F-3) | Capability detection with a fallback; upstream requests 5 and 7 |
| ts-mls with noble 2.4.0 untested (F-5) | Spike A case (g) |
| Windows, macOS, WSL and Docker code paths cannot be run here | Logic tested with fakes; every such cell marked untested until run on a real host |
| Async runtime start changes every RPC's error surface | Introduced once in I-3, with typed states, before any v2 protocol code depends on it |

## 6. Size summary

| Item | Size |
|---|---|
| Step 0: Spike A | S |
| Step 0: Spike B | S/M |
| Step 0: R-check and vector regeneration | S |
| I-1 encoding, signatures, vectors | M |
| I-2 file layer (X-1, X-2, X-4, X-6 and lows) | M |
| I-3 KeyStore and sealed files | L |
| I-4 Noise IK, records | M |
| I-5 fold core | L |
| I-6 fold authority, holds | L |
| I-7 room host core, P-27 | L |
| I-8 room endpoint and sessions | L |
| I-9 enrollment v2 (P-15, P-23, P-20, C-10) | L |
| I-10 grants v2 and lane endpoint (P-9) | L |
| I-11 device linking and holds | L |
| I-12 rotation and recovery | M |
| I-13 MLS adapter and delivery service | L |
| I-14 Rooms UI v2 | M/L |
| I-15 cut-over and migration | M |
| I-16 X-3, X-5 | S |
| I-17 traceability and results | S |

## Follow-ups recorded during implementation

- **I-3 (KeyStore), not yet done:** async runtime states and UI wiring; automatic move from the fallback file to a keyring (only detected now); KEK rotation (build on the same re-seal step); the CLI keyring backends and Windows DPAPI wrapping of the fallback file; Kubernetes secret mounts are symlinks and fail the permission check. Packaging: add `"@napi-rs/keyring": "2.1.2"` to dependencies; directory installs need `npm install` on the target machine.
- **I-2 (file layer):** no client button yet for `rooms.permissions.fix`.
- **I-7 (room host core), not yet done:** host key and endpoint key rotation (the host refuses a `host.key.rotated` naming a key it does not hold; `endpoint.rotated` is accepted without the host holding the new key, I-12); the adjacent `device.rekey.approved` plus commit write and automatic rekey approvals (I-13); `host/<roomId>/state.sealed` (invites, pending enrollments, grant allowlist; I-9, I-10); revocation enforce-first ordering (grants-v2 7.1; nothing to enforce before sessions and grants); org policy profiles (only `recoveryEscrow = "org"` forcing a recovery key is applied); clean-up of an interrupted room creation found at start. Spec gap found: `stmt:grant.suspected_theft` was outside the context alphabet of signatures 3.1, so that statement could not be signed; fixed after I-7 by renaming the type to `grant.suspected-theft` (alphabet unchanged). **Written into spec** (2026-10-29): the host's refusal of a `host.key.rotated` naming a key it does not hold (keys 4.5; README decision I9-7). Not written in, proposed instead (README section 8, item 8a): the host should likewise refuse an `endpoint.rotated` naming an endpoint it does not serve; I-12 should implement that if confirmed. **Done in round 9 (2026-10-30):** decided (R9-2), written into keys 4.6 and implemented in `room-host.ts` (`endpoint_not_served`; the served set is the current endpoint plus an optional `endpointNext` in `keys.sealed`, which the I-12 rotation will write).
- **I-8 (room endpoint and sessions), not yet done:** persistence of the member's verified log copy, `maxSignedHead` and receipts (member journal, I-9; today they are in memory, so truncation is detected only within one process lifetime); automatic member reconnect at start and after `max_session` (explicit `rooms.v2.dev.room.connect` today); per-device and pre-auth rate limits (`busy`, I-9/I-10); `authority.get` (answered `not_permitted` with the other later operations of section 4); MLS gossip transport for `log.witness` and `log.evidence.request` (I-13; `checkPeerHead` takes the evidence as a callback); `moved` and endpoint rotation (I-12). The `rooms.v2.dev.*` RPCs (hand-made roster entry with a `sas6` confirmation marker, no SAS) stand in for enrollment and must be deleted in I-9. The fake relay models relay protocol v2 from the 0.13.2 Cloudflare adapter without its nudge timers; only a live-relay run (`test/e2e-v2/run.sh --live-relay`) settles whether it is faithful.
- **I-9 (enrollment v2), not yet done or decided here:** device links (`linkId` requests get the generic rejection after the signature check; I-11); lane grants, so `LaneRegistrar` (`server/member/lane-registration.ts`) retries `grants_unavailable` for any invite with lanes (I-10); per-device budgets of active devices (60/min, I-10); the daily sweep of unused expired invites (expiry is lazy, on lookup); persistence of the member's verified log copy and `maxSignedHead` (still in memory); the verified room name for lane labels (MLS `room.profile`, I-13; labels use the room id meanwhile); `room_closed` during a pending is implemented in the sweep but not tested. Choices where the spec is silent: `enroll.confirm.ok` and `enroll.abort.ok` replies were added; `enroll.resume.ok` for an admitted pending reports `state: "member_ok"` with `admitted`; the pre-auth bucket counts `enroll.request` frames only; a `sas.reveal` that does not open the commitment closes the pending as abandoned; the admission's admin signature is checked by the member's log sync after admission, not on `enroll.admitted` itself. **Written into spec** (2026-10-29): all five (enrollment 5.2, 5.4, 5.6, 5.7, 7.1; README decisions I9-4 to I9-6). The spec now also requires, in 5.7, that the admission entry from `enroll.admitted` appear at its seq with the same hash in the fetched log (`fork` otherwise); `room-client.ts` does not check this explicitly yet. Proposed, not written in (README section 8, item 8b): lane grant requests and lane registration should wait until the fold has accepted the admission; `runtime-v2.ts` starts `LaneRegistrar` in parallel with the first session, which the I-10 lane grants should not keep. (The I-9 test line above said SAS `015 136`; corrected to the vector's `317 837`.) The `rooms.v2.dev.*` admission stand-ins are deleted; the remaining development calls are `rooms.v2.member.remove`, `rooms.v2.room.connect` and `rooms.v2.room.disconnect`.
- **I-9 format choice for the spec: `enroll.pending.authority` (minimal disclosure before admission).** The spec says "signed admin/host statements since genesis" without a format, and sending the whole log would show a holder of a stolen invite the roster, invites, lanes and history before the SAS is confirmed. Implemented (`server/authority/authority-chain.ts`): `authority = { seq, entries: SignedEntry[], bodies: [{seq, body}] }` holding only entries of the types `admin.added`, `admin.removed`, `admin.key.rotated`, `admin.key.revoked`, `recovery.key.rotated`, `host.key.rotated`, `host.key.revoked`, `endpoint.rotated`, with their statement bodies; `seq` is the seq of the last included entry (-1 if none), not the log head. Why it suffices: the SAS inputs (h, Nm, Nh, deviceDh, deviceSig, endpointDh, genesisHash, inviteId) all come from the handshake, the nonces, the member's keys and the invite, none from the log; the IK handshake proves the host holds the invite's endpoint key, and the voice comparison binds that key and the genesis to the person (6.1). The chain adds certification for display and endpoint checks: each entry verifies under a host key valid at its position (genesis key; a `host.key.rotated` key from the next seq), its body matches `bodyHash`, its statement is signed by an admin or recovery key that the genesis or an earlier chain entry certified (with a valid `newKeySig`), and the last certified endpoint must equal the invite's. Not checked before admission: chain links between the sparse entries (an omitted revocation is not detectable), and removals do not narrow the key set; the full fold runs over `log.fetch` right after admission. Residual disclosure: entry seq numbers and `hts` of the chain entries (an upper bound on log length and timing of key changes). Spec tension to resolve: 5.5 step 2 requires the genesis endpoint to equal the invite's, which an `endpoint.rotated` room can never satisfy; the implementation keeps step 2 as written (endpoint rotation is I-12). **Written into spec** (2026-10-29): enrollment 5.2.1 (format, the eight types, `seq` semantics, what is and is not verified, residual disclosure, full fold after admission) and 5.5 (tension resolved: the invite's endpoint must equal the **last certified endpoint** of the chain, not the genesis endpoint); README decisions I9-1 to I9-3. Two corrections to the note above: the chain seqs give a **lower** bound on the log's length, not an upper one; and the residual disclosure also includes each entry's MLS `epoch`, the `base` and `fromSeq` positions, admin member ids in `KeyChange.subject`, and `ver`. Code change needed (not made here): `member/enroll-client.ts` `acceptPending` still compares `genesis.body.endpoint` with the invite's endpoint, which must be dropped when endpoint rotation lands (I-12); the chain check that follows already implements the new rule. Proposed, not written in (README section 8, item 8c): after admission, check every pre-admission chain entry against the fetched log. **Done in round 9 (2026-10-30):** the genesis-endpoint comparison is dropped (only the last-certified-endpoint check remains), and 8c is decided (R9-3) and implemented: the journal keeps the `enroll.held` and `enroll.admitted` signed entries (`received`), `preAdmissionAnchors()` adds the chain entries, and `RoomClient` checks each anchor at its seq (`fork` with the two entries, or `truncation` if beyond the host's head; the explicit admission same-hash check of 5.7 is part of this).
- **I-10 (grants v2 and lane endpoint), done and choices where the spec is silent or differs:** pre-check grants Q2 (read in the 0.13.2 server and client packages): the destination side has no Paseo-level ping the source answers, but the source's DaemonClient sends its own liveness ping every 10 s; so 6.1 watches the existing link for 12 s (not 5 s) and any inbound frame in that window counts as a live second holder. The idle rule is read as: a link without routes rotates at once (idle); with routes, defer only under the three conditions of section 5; a report (6.3) is sent only when the member saw its registration offline for 30 s while the lane reports a link, never when its online time is unknown. Roster-driven revocations log only the reducing statement; no `grant.revoked` entries are emitted. A failed grants-file save answers `persist_failed` and is retried every 10 s; a failed log append still stops the room (I-7 behaviour), with access kept cut by the endpoint's in-memory overlay, and is shown as `room_stopped`, not retried. Grants state is in `host/<roomId>/grants.sealed`, lane bindings (agent, workspace, label) in `host/<roomId>/lanes.sealed`, not in `state.sealed`. The lane registration and every grant request wait until the member's own post-admission fold holds the admission entry with the seq and hash of `enroll.admitted` (journal field `admission`). Not yet done: the neutral project label has no room name (`<room name>` is I-13), lane host labels show the lane id; Q3 (endpoint key rotation on repeated theft); per-device budgets of non-grant operations; standalone lane gateways (S-23 fail-closed); a `lane.close` and `lane.names.changed` UI path (handled when they appear in the log). Development switch: `PASEO_ROOMS_DEV_SHORT_GRANTS=1` with `PASEO_ROOMS_DEV_GRANT_TTL_S` (default 60, at least 10), host only. **Written into spec** (2026-10-30, README 10.5): the admission gate (enrollment 8), the 12 s watch (grants 6.1, Q2), the idle and report rules (grants 5, 6.3), no `grant.revoked` for roster-driven reductions and the failed-append behaviour (grants 7.2), and the storage files (identity 7.1). The development switch is test-only and not written in.
- **I-11 (device linking and holds), done on 2026-10-30; choices where the spec is silent, and what is not done.** Code: `server/proto/device-link.ts` (`prl2.` codec, KeyChange and device statement signing), `server/member/device-link.ts` (confirming device A, R-2 counters), link support in `server/host/enrollment.ts`, `server/member/enroll-client.ts` and `enrollment-journal.ts`, `autoApprovalBlocker`/`autoApprovalEndsAt` in `server/authority/holds.ts`, the admin daemon's approver and RPCs in `server/runtime-v2.ts`, `server/platform/test-clock.ts`. Tests: `test/unit/v2-device-link.test.ts`; e2e section 8b with a third daemon on 6924. Verified: typecheck clean, `npm test` 303 pass, offline `test/e2e-v2/run.sh` 61 checks pass (live relay not run).
  - *Frames added (spec names no replies):* `device.link.create.ok {re, receipt}`, `link.nonce.ok`, `link.confirm.ok`, `link.abort.ok`. `link.abort.reason` also takes `"attempts"` (A's limit or a changed re-push) and `"cancelled"` (a reveal that does not open the commitment, or a bad `newKeySig`, seen by A); both burn or close as described below. `enroll.resume.ok` for a held pending carries `state: "held"` and `held: <enroll.held>`.
  - *Host:* B's `enroll.request` for a link gets no reply until A's `link.nonce`; then `enroll.pending` is sent with the request's `re` (a retry after B's 30 s timeout resumes and waits again). `terms` of a link pending are the member's role and lanes at `link.nonce`. The host verifies B's `newKeySig` at `sas.reveal` (a bad one closes the attempt as abandoned) and requires A's `device.added` data to equal exactly what the pinned inputs give before logging it. `link.request` and `link.reveal` are re-pushed when A's session opens. A pending link enrollment, and any open link, of a creator that is no longer an active device is closed (`rejected`) or marked revoked locally; there is no log entry for the latter, because the host may not sign `invite.revoked`. Held adds follow the fold after every append: approved admits B, vetoed closes `vetoed`, cancelled closes `rejected`; 48 h after the hold end (after `device.added` when an admin must approve) closes `timeout`. The owner's join-request list shows link pendings (`kind: "link"`, no SAS); Admit is refused for them.
  - *Spec gaps (not written into the specs):* `invite.contested` data names only `inviteRef`, so a second claimant of a link gets `invite_in_use` with no log entry. `enroll.held.entry` is a SignedEntry without its body, so B cannot check the memberId before `enroll.admitted`. Section 5.7 is written for `member.admitted`; for a link B checks: own pendingId, entry and statement type `device.add.approved`, bodyHash, room, its own deviceId in frame and data, `memberId` consistent, `ref` equal to the held entry's bodyHash, and seq after it; the I-10 admission gate then waits for that entry at that seq and hash in its own fold.
  - *Confirming device A:* besides the three R-2 limits, A answers no request for a link more than 60 s past its `exp` on A's clock (not in the spec). Because links live at most 10 minutes, the 15-minute open-pending window can only matter under clock skew; it is implemented but not separately observable in tests. A changed re-push of a pinned `pendingId` burns the link with `reason: "attempts"`. A's counters and pins live in `member/rooms/<roomId>/state.sealed` under `links`; that file's `enrollment` section is now optional, every writer replaces only its own section, and the creator's own device (no journal) gets a file with `links` only.
  - *Admin daemon:* the automatic approval compares the admin daemon's clock with the request entry's `hts`. In the embedded deployment host and admin daemon are one process, so this is "its own clock". A standalone host would need the admin daemon to measure from when it first saw the request; not done. **Done in round 9 (2026-10-30)** and written into identity 6.3 as a requirement: `server/admin/hold-clock.ts` records first sight on every append and approver pass, persists it in `admin/<roomId>/holds.sealed`, and the approver uses the later of that hold and the `hts` hold; unit test "admin hold clock". The approver runs every 2 s and retries a refused approval after 60 s. Interactive approval and conflict resolution check the fold state before signing, because a refused admin statement stays outstanding until a fence (I-7 behaviour). Automatic approval of rekeys is not done (I-12, I-13).
  - *TEST-ONLY clock:* moves only the room host's `hts` and the approver's clock, never session, grant or enrollment-expiry timers; honoured only with `PASEO_ROOMS_TEST_CLOCK=1` on a home that resolves to `.test-homes/v2-<name>`, is not `~/.paseo`, and holds the exact marker file `rooms-test-home` (regular file, owned by the user); the offset is in memory, forward only, at most 7 days; `rooms.v2.test.clock.advance` is registered only then. The e2e gives the switch and marker to the owner daemon only.
  - *Not done:* link revocation by the device (`invite.revoked {linkRef}`), the UI (veto prompt, sole-device admin notice, "N earlier attempts" screen; status fields `deviceRequests`, `conflict`, `links` exist for I-14), a periodic held-state poll by B instead of keeping its pre-auth session open, `member.device.replaced` and re-admission (I-12). One existing test assertion was timing-sensitive and now waits up to 2 s: `v2-room-endpoint.test.ts` "no lanes: registered at once" (the session reports `open` before the first sync, and the I-10 gate registers after it).
- **I-11 written into spec (2026-10-30, README 10.5):** the frames and abort reasons, B's waiting request, link `terms`, the host's checks, re-pushes, links of a removed creator, held-add outcomes, A's 60 s grace and B's admission checks (identity 6.4). Flagged instead of written (README section 8, item 9): the two spec gaps above. The TEST-ONLY clock is test infrastructure and not written in.
- **I-13 (MLS adapter and delivery service), implemented on 2026-10-30; not committed.** Code: `server/mls/` (`adapter.ts`, `formats.ts`, `auth-service.ts`, `roster-rule.ts`, `member.ts`, `sealed-store.ts`), `server/host/mls-delivery.ts`, the adjacent approval-plus-commit write (`room-host.ts` `submitWithCommit`, `room-log-store.ts` `appendMany` and the `unpaired_rekey` torn reason), the MLS operations in `room-endpoint.ts` and `room-session.ts`, `onIngest` in `room-client.ts`, the runtime wiring and `rooms.v2.mls.send`/`rooms.v2.mls.messages` plus a `mls` array in `rooms.v2.status` (development RPCs; the chat UI is M2, decision D-4 settled). Tests: `test/unit/v2-mls.test.ts` (26 tests over `test/unit/mls-harness.ts`); e2e MLS section in `test/e2e-v2/e2e.ts`. Verified: typecheck clean, `npm test` 329 pass, offline `test/e2e-v2/run.sh` 71 checks pass, ports 6920-6929 free afterwards (live relay and M1 e2e not run).
  - *Dependencies:* `ts-mls` exactly 1.6.4 with `overrides` mapping its `@noble/ciphers` and `@noble/curves` peers to the plugin's 2.4.0, installed with `npm install --offline` (one noble copy in `npm ls`). The `ts-mls-162` alias was not added: its exact peer `@noble/ciphers` 2.1.1 conflicts with 2.4.0 (ERESOLVE), npm 9.2 rejects an override for an alias, and `--legacy-peer-deps` left later installs broken. MLS test 2 (positive control) instead loads 1.6.2 from `spikes/security/node_modules/ts-mls-162` when present and is skipped otherwise.
  - *MLS test 13:* ts-mls 1.6.4 exposes `epoch_authenticator` publicly (`ClientState.keySchedule.epochAuthenticator`); members and a joiner of one epoch compute the same anchor. `epochAuth` uses the new hash label `mls-epoch-auth`.
  - *Library gaps and the choices made (spec not edited):* (1) ts-mls exposes neither the GroupInfo signer nor the sender of an application message; the sender is derived from the secret-tree change, and a joiner's epoch counts as confirmed only after matching anchors from **two** other leaves, so at least one is not the GroupInfo signer. Consequence: a joiner of a two-leaf group can never be confirmed and always ends in `epoch_unconfirmed` after the timeout (seen in the e2e for device A). Alternatives: accept one other leaf (spec 5.1 as written, weaker), or get the signer exposed upstream. (2) `defaultClientConfig` is only on a subpath export; the config is built from public `default*Config` exports. (3) ts-mls 1.6.4 cannot process a commit whose UpdatePath skips the device's own replaced leaf ("No overlap between provided private keys and update path"); the member then tries the Welcome routed to it for that entry (joins, or raises `welcome_refused`) and stalls only if none exists. (4) The committer adopts its own commit without processing it; it now also sends `log.witness` after its own Add commit (5.1 says "every device that processes a commit containing an Add"; read as including the committer).
  - *Spec tension:* MLS test 10's "a pair without the pending add fails the daemon's check" contradicts the round 7 rules, under which a commit may leave a pending add open; the tests follow round 7.
  - *Behaviour to note:* adds wait for the repair delay (60 s, plus up to 60 s for devices that are not admins), so a new member reaches the room group about a minute after admission; `PASEO_ROOMS_DEV_MLS_FAST=1` (dev runtime, e2e only) sets the delay to 0, witnesses to at most 1 s and the joiner check to 5 s. Decrypted messages are kept in memory only (the last 500); there is no message store.
  - **Round 9 and spec (2026-10-30):** library gap (1) is replaced by R9-4 (`min(2, other leaves)` confirmers, `JoinRecord.needed`); the "behaviour to note" is replaced by R9-5 (prompt Add: `MlsMember.promptAdd` from the owner's feed when its own admin key logged the admission, re-armed by `MlsDelivery.onPublished`; the dev MLS switch no longer shortens the repair delay; e2e joins measured at 0.28 s for A and 0.27 s for B); the test 10 tension is fixed in the spec text; (3), (4) and test 13's `epoch_authenticator` check are written into MLS 5.1, 9 and 10. (2) is an implementation detail and not written in. The secret-tree sender derivation is listed in README section 8, item 10, to re-check on upgrades.
  - *Not done:* the leaf-repair device flow (`device.leaf.repair.requested`, MLS test 14); automatic rekey approval (I-12; `approveRekey` exists and is tested); ReInit continuation after `admin.key.revoked`; GroupContextExtensions after admin key changes; member proposals (all proposal messages are refused); `room.profile` (room name, I-9/I-10 labels); feeding `log.witness` `logHead` values into the gossip head check (`checkPeerHead`); subgroups beyond the adapter and test 8.
- **Sender attribution of MLS application messages (before product M2 chat):** the adapter infers the sender leaf from which application ratchet advanced in the public `secretTree`, because ts-mls 1.6.4 does not return it. Chat attribution must not rest on that inference alone. Before M2, add an application-level signature by the sender's device key inside the encrypted payload, bound to groupId and epoch, and treat a mismatch with the inferred leaf as an alert. Also add "expose the sender leaf of application messages" to the held ts-mls upstream request.

- **I-12 (rotation and recovery), implemented on 2026-10-30; not committed.** Code: `server/admin/recovery.ts` (R from the typed code for one action, `recoverFromStolenAdmin`, `newRecoveryKey`, `closeConfirmationBlocker`), `server/member/rotation.ts` (`rekeyRequest`, `rekeyStatus`, `movedTarget`), `AdminSigner.signWithCommit`/`stageRotation`/`promote` (`admin-key.next.sealed`), `RoomHost.stageHostKey`/`stageEndpoint`/`promoteEndpoint`/`lastEndpointRotation`, `RoomEndpoint.rotateTo` and the `restricted` (`moved`) mode, `LaneService.rotateOffer`/`lanesToRotate` (`lanesNext` staging), the rekey grant drop in `HostGrants.decide`, the periodic leaf refresh in `MlsMember` (`refresh` in the sealed record), journal fields `rekey` and `endpoint`, the runtime flows and 13 development RPCs (`rooms.v2.device.rekey`, `.device.remove`, `.host.key.rotate|revoke`, `.admin.key.rotate|revoke`, `.endpoint.rotate`, `.lane.rotate`, `.room.close.propose|confirm`, `.recovery.create|confirm|act`; `member.remove` takes `compromise`). Tests: `test/unit/v2-rotation.test.ts` (17, vectors read directly); e2e sections 8a (host key rotation, grants after it) and 8c (device rekey by the admin route, chat across it). Verified: typecheck clean, `npm test` 350 pass, offline `test/e2e-v2/run.sh` 92 checks pass, ports 6920-6929 free afterwards (live relay and M1 e2e not run).
  - *Choices where the spec is silent:* (1) the `moved` answer carries `body` (the statement) besides `entry`: without it a device that missed the rotation cannot learn the new endpoint. Alternatives: (a) keep `body` (chosen); (b) answer `moved` with the entry only and let the device fetch the body from the old endpoint (needs a new restricted operation). (2) Staging files and fields: `endpointOld` (with `until`, 30 days) and `lanesNext` in `keys.sealed`, `admin-key.next.sealed`; each staged key is promoted after its statement is in the log, also at start. (3) The member keeps the last verified endpoint in its journal; after a restart it knows only the genesis host key (no persisted verified copy, I-8 follow-up), so a `moved` entry signed by a rotated host key is used with its hsig unchecked and verified by the full fold of the new session (the entry is an anchor: `fork` if different). (4) A rekeyed device learns of its approval by reconnecting: its old session is superseded before the entries are pushed, so the runtime retries with the next keys on `not_authorized` and completes the journal swap when that session opens. (5) On rekey approval the device's current grants are dropped (`superseded`, they name the old key); the push rarely reaches the superseded session, so the member rotates its grants after reconnecting. (6) The closure check on the confirming daemon measures `closeDelay` from the later of the proposal's `hts` and its first sight (the admin hold clock now also records open closure proposals). (7) The leaf refresh carries every pending removal and no Add.
  - *Gaps found (spec or earlier milestones), with choices:* (a) **MLS 5.1 co-joiners:** two devices added by the same commit each need `min(2, other leaves)` confirmers, but only devices that process the commit send `log.witness`; co-joiners join by Welcome and never witness, so each waits for a leaf that does not come and ends `epoch_unconfirmed` (seen in unit tests; the e2e adds devices one at a time). Options: (i) a joiner also sends `log.witness` once joined (recommended); (ii) `needed = min(2, leaves that processed the commit)`; (iii) leave as is. (b) **TEST-ONLY clock and host keys:** a new host key's `validFrom` comes from `hts` (test clock) while grant `iat` uses the wall clock, so a host key rotated after a test-clock advance refuses new grants (`host_key_not_valid`). Production uses one clock; the e2e rotates the host key before the clock moves. Option: let the test clock also drive grant `iat` (would change grant timing in the e2e).
  - *Not done:* GroupContextExtensions after admin key changes and ReInit after `admin.key.revoked` (MLS rows of keys section 5; I-13 follow-up); the removal dialog listing devices the compromised device added (6.3 step 1); rekey of the creator's own device (its keys are in `member/rooms/<roomId>/keys.sealed`, not a journal); the scheduled 90-day rekey trigger; `member.device.replaced` re-admission (6.1 step 3); the guided UI flows (I-14); runtime-level tests of `confirmRecoveryKey` (two lineages) and of the member's `moved` reconnect (unit tests cover the host side and `movedTarget`); endpoint and lane-offer rotation are not in the e2e.
- **MLS member pump (after the MLS 7 flake, 2026-10-30):** the flake was a test race; the crash simulation did not stop the instance. Fixed in the test. Product follow-ups: `idle()` restarts a stuck queue (a retry from stored state, harmless), which its comment does not say; decide whether to document or change it. Add a dedicated test for in-process retry after a failed state write.

- **I-14 (Rooms UI and RPCs for v2), implemented on 2026-10-30; not committed; the real app UI is unverified.** Code: `client/v2-screen.tsx` (screen, runtime notices, create-room dialog, "Agents from closed rooms", About, the v2 "Open room…" share flow), `client/v2-owner.tsx`, `client/v2-member.tsx`, `client/v2-dialogs.tsx` (admin confirmation, recovery code dialog, SAS digits, typed confirmation), `client/v2-text.ts`, `client/save-file.ts`, `client/protocol.ts`; `server/admin/confirmations.ts`; `tsconfig.client.json` and `npm run typecheck:client` (X-12: no Node and no DOM types). The client picks the v2 screens only when `rooms.bootstrap` reports `protocol: "v2"`; M1 stays the default. Tests: `test/unit/v2-rpc-contract.test.ts` (6; the server entry contributed to a fake server context, every call through the contract's input and output schemas, and handler results must have no field outside the contract).
  - *RPC changes:* `rooms.v2.admin.prepare {action}` returns `{confirmToken, expiresAt, description}` for the 18 interactive admin actions (identity 5.3 list plus lane create, device approve, conflict resolve, lane rotate, admin key revoke); each of those action RPCs now requires `confirmToken`. The token is single use, 5 minutes, in memory, bound to the canonical action and to a `subject` of the current values the action depends on (role and its version, pending status, current host key, ...). A changed subject answers `stale_base: This changed since you confirmed. <current value>`, and the dialog shows the new value and asks again (R-9); the host's own `stale_base` refusal is handled the same way. `rooms.v2.room.create {recovery?: "create"|"skip"}` (RPC default skip: an unshown code would be a recovery key nobody holds and blocks adding one later; the UI preselects create) and `recovery.create`/`recovery.act rotate` return `recovery: {kid, code, file: {name, text}}` (the 5.4.1 file). Status adds `roster`, `policy`, `lineages`, `keys.recoveryProposals`, keystore `notice`/`message`, `permissionProblems`, `platform`. `rooms.permissions.fix` is registered under v2 (I-2 follow-up done): it repairs and restarts the runtime after a protection or keystore permission failure. Not token-gated: invite revoke and join reject (not admin statements; inline confirmation), the member's own rekey and veto, and `recovery.act` (typed code plus typed word).
  - *Choices where the spec is silent:* the recovery dialog closes only after the last code group is typed back; the file is offered as a Blob download on web and desktop and through the share sheet on iOS and Android, with Copy as the fallback. Single-lineage rooms cannot propose a closure in the UI (no admin could confirm it, keys 6.8); the dialog offers "Create a recovery key to close this room" or the recovery-code closure. Members see mapped error codes only, never host text.
  - *Not done or gaps found:* (1) no v2 RPCs for leave (`member.left`) and lane close, so the cards say "not available yet"; (2) the room-log 4.6 notice feed (policy changes, admitted, removed, device added, key rotations, ...) is not in the status view, only the 6.6 alerts, uncertified keys, conflicts and holds; it needs a member-side notices view from the fold; (3) the owner notification for policy-automatic approvals (identity 5.3); (4) the member SAS screen lacks the owner fingerprint (admin key `kid` display form, enrollment 6.4): `JoiningV2View` has no field for it; the preview shows the endpoint fingerprint; (5) member names come only from enrollment pendings the host still keeps (no `room.profile`, I-13); rooms are shown by id; (6) the removal dialog lists the device a removed device is adding, not devices it added earlier (6.3 step 1); (7) the M1 archive notice waits for I-15 (`migration.json`); "Agents from closed rooms" lists lanes of closed rooms and closed lanes of this daemon only; (8) "Confirm closing" is enabled by the client's clock; the daemon refuses early confirmations on its own clock; (9) no `ui-check/up-v2.sh` kit; the README lists the manual steps; (10) `room.connect`/`room.disconnect` (development calls) back the Reconnect and Disconnect buttons; `mls.*` is not used by the UI.
- **MLS unit test time bomb (found during I-14, 2026-10-30, not fixed):** `test/unit/mls-harness.ts` fixes the fake clock at `1_793_300_000_000` (2026-10-29 18:53:20 UTC) and `v2-mls.test.ts` gives KeyPackages a lifetime of that time plus 24 h, but ts-mls checks lifetimes against the real wall clock. Since 2026-10-30 18:53:20 UTC five MLS tests fail with "Current time not within Lifetime" (MLS 4, 5, 8 and both MLS 12 tests); `npm test` reported 356/356 before that time and 351/356 after, with no code change in between. Fix: start the harness clock from `Date.now()` (rounded), or give ts-mls a clock if its config allows one.
- **KeyPackage clock skew (fixed 2026-10-30):** KeyPackages were back-dated by only 60 s, and ts-mls checks lifetimes against the receiver's wall clock, so a receiver whose clock ran more than a minute behind would refuse to join. `notBefore` is now back-dated 1 h (`KP_SKEW_S` in `server/mls/member.ts`). The spec (mls-integration 6.4 lifetime rule) should state the skew allowance. The MLS test harness clock now starts at the real time instead of a fixed 2026-10-29 value, which had made five tests fail once that date passed.
- **I-15 (cut-over and migration from M1), implemented on 2026-11-01; not committed.**
  - *Deleted:* `shared/control.ts`, `shared/schemas.ts` (all of it was v1), `server/gateway/control-server.ts`, `server/member/control-client.ts`, `server/invite-code.ts`, `server/grants.ts`, `server/host/event-log.ts`, `server/host/host-store.ts`, `server/member/member.ts`, `server/crypto.ts` (nothing outside v1 used it), `server/runtime.ts`, `server/paths.ts` (callers use `server/platform/`), `server/gateway/gateway.ts` (the M1 Gateway class over HostStore; fork creation and curated context went with it, see below), the M1 client screens (`client/rooms-screen.tsx`, `client/open-room-screen.tsx`, `client/protocol.ts`), the M1 RPC contracts, `PASEO_ROOMS_PROTOCOL`, `test/unit/host-grants.test.ts`, `event-log.test.ts`, the M1-only tests in `durability`, `secrets-and-guard`, `tripwire` and `viewer-policy`, `test/e2e/` and the M1 ui-check kit. Raw M1 e2e logs moved to `test/m1-evidence/`; `secret-scan.ts` moved to `test/reliability/` (its only user); `HAIKU-BUDGET.md` to `test/e2e-v2/`.
  - *Kept and moved:* the lane endpoint lost the control channel and its HostStore authority (`EndpointLane` replaces the M1 `Lane` type); its tests run on `test/unit/lane-harness.ts`. The agent guard and the session_open tripwire are registered by the v2 entry; the tripwire now covers the M1 fork agents listed by the migration. C-13 is ported: `agent.archived` (and an archived or missing agent at lane start) stops the lane endpoint at once and this daemon's admin key signs `lane.closed` (`LaneService.onAgentArchived`, `RoomsRuntimeV2.closeLaneForAgent`). `rooms.lane.agents` is served by v2 (composer pill, "Open room…" redirect).
  - *Added:* `server/migration/v1.ts` (2.1 to 2.5; `member/` moves entry by entry when v2 entries share it; win32 rename retry with backoff, otherwise pending for the next start), its status view and the RPCs `rooms.migration.keys.delete` (explicit, `confirm: true`) and `rooms.migration.dismiss`; the client notices. `PASEO_ROOMS_DEV_*` switches are honoured only on a marked e2e test home (`gateDevSwitches`, `testHomeRefusal` in `server/platform/test-clock.ts`); unit tests opt in with `allowDevSwitches`. Specs `rooms-control-protocol.md` and `data-model.md` marked superseded.
  - *Not ported (reason):* fork lanes (decision for I-15: v2 shares the live agent only), so the M1 e2e checks of the fork (new agent with parent link, labels, curated context, inert shadow in the stored config, fork turn, process-level MCP positive control) were dropped; the live turn streamed through the lane (needs a model call); expiry cutting the link at `exp` (v2 rotates at 50 %/75 %, checked instead); leave (no v2 RPC yet). Ported into `test/e2e-v2`: the out-of-scope denials, the one-time invite, the timeline read, the composer pill data, the full plugin-data mode check, the room log check (independent fold of the owner's file), archive closes the lane. Secret scan and file modes were already covered.
  - *Verified:* typecheck and client typecheck clean; `npm test` 343 pass; offline `test/e2e-v2/run.sh` 107 checks pass; `test/e2e-v2/migration-run.sh` (migration test 3, M1 build from a worktree of `m1-baseline`, removed afterwards) 19 checks pass; ports 6920-6929 free afterwards. No model calls. Live relay not run.
  - *Open:* `test/reliability/` still drives M1 RPCs and needs a rewrite; the fork code is only in `m1-baseline` if fork lanes return; the upgrade notices were not seen in a real app; `migration.json` is written but nothing prunes old archives.
- **R2.1 (the member's verified log copy at rest; usability roadmap), implemented on 2026-11-01; not committed.** Closes the persistence gap named in the I-8 and I-9 entries above.
  - *Code:* `server/member/log-copy.ts` (`SealedLogCopy`); `RoomClient` option `store` (re-fold at construction, anchors, receipts, persisted stopping alerts, `local_copy_corrupt`); the runtime passes a store in `connect()`; client text for `local_copy_corrupt`. Tests: `test/unit/v2-member-log-copy.test.ts` (5: restart re-folds across segments and fetch resumes from the stored head; truncation after a restart against a rolled-back host; fork with an equivocation proof after a restart; a damaged segment or head record is reported, dropped and re-checked against the sealed `maxSignedHead`, also against a rolled-back host; a stored receipt the host later does not serve is truncation). e2e-v2 section 10: after every other check, the owner's room log is cut below member A's head with the owner daemon stopped, both daemons start again, and A must raise `truncation` (or `fork` if the host signed past the cut) and keep its head.
  - *Layout and bound:* `member/rooms/<roomId>/log/seg-<n>.sealed` (64 entries with their statement bodies; only the tail segment is rewritten) and `log/head.sealed` (`maxSignedHead`, receipts not yet in the chain, at most 256, and the newest 32 fork, truncation, invalid_entry and withholding alerts with their proofs). All sealed under the KEK (purposes `member-log-seg:<roomId>:<n>`, `member-log-head:<roomId>`) and written with the durable layer; segments before the head record. At most 16,384 entries are kept in segments; past that only the head record moves on. Detection does not depend on the segments: entries are hash-linked, so the stored `maxSignedHead` pins every entry below it. Damaged segments are moved to one `log/corrupt-<ms>/` directory (older ones deleted, so damage cannot grow storage).
  - *Choices where the spec is silent or differs (spec not edited):* (1) Room-log 8.2 puts `maxSignedHead` and receipts in `state.sealed` and the entries in a plain `entries.jsonl` "written the same way" as the host's. Here both are separate sealed files: the enrollment journal's read-modify-write sections stay untouched, and the copy is confidential and tamper-evident under the KEK. Alternative: a `log` section in `state.sealed` (would need the journal and link writers to preserve it). (2) 6.6 has no alert for local damage; `local_copy_corrupt` (warn, sending continues) was added and is shown in the member view. Two different host-signed stored entries at one seq (segment versus head record) raise `fork`, not damage. (3) Stopping alerts persist and set `sendingStopped` again after a restart; there is no RPC or UI to acknowledge them (6.6 says recovery is a human decision). (4) Restored entries are handed to `onIngest` once the new session is open, in seq order, as the full refetch did before; MLS ingestion skips what its cursor already holds. (5) Receipts are taken from `stmt.submit` replies on the room session (device statements, rekey requests, link statements); the owner daemon's own admin statements are submitted locally and not tracked.
  - *Gaps:* deleting the whole `log/` directory is not detectable (no marker elsewhere); a cheap fix would be to also keep `maxSignedHead.seq` and hash in the enrollment journal on admission and every N entries. A crash loses at most the entries ingested since the last write (one fetch page or push), so the stored `maxSignedHead` can lag by that much. Witnesses of 6.1 are not persisted (gossip is not fed yet, I-13 entry). Every reconnect builds a new `RoomClient` and re-verifies the stored chain (CPU, no network). The I-12 choice (3) above improves: after a restart the member's fold includes rotated host keys, so a `moved` entry is checked against the restored state.
  - *Verified:* typecheck and client typecheck clean; `npm test` 348 pass; offline `test/e2e-v2/run.sh` 108 checks pass; ports 6920-6929 free afterwards. Live relay not run.
- **Reliability suite ported to v2 (R2.2 prerequisite), 2026-11-01; typechecked, not run (needs the user's approval).** `test/reliability/lib.ts` (v2 status helpers, `admin.prepare` tokens, the real SAS enrollment with a TEST-ONLY programmatic comparison, independent fold of the owner's log), the three modules and `run.sh` (now `PASEO_ROOMS_KEYSTORE=fallback-file`; dev switches, test clock, relay overrides and `PASEO_ROOMS_KEK_FILE` unset; the `--i-reviewed-this` gate, ports 6930-6939 and home checks unchanged). *Gaps found while porting:* (1) no v2 leave RPC and a daemon can join a room once, so the enrollment loop uses a fresh room per cycle (two relay registrations each; default 10 cycles, at most 20); (2) the M1 "grant rotation across expiry while the member is stopped" step is not portable: `grantTtl` is at least 1 h and the short-grant switch is honoured only on `.test-homes/v2-*` e2e homes; (3) the member does not reconnect by itself after the owner restarts (I-8 entry); the restart module records whether it did and then connects explicitly; (4) the environment inspection now covers the shared live agent (no forks): sharing must not change its stored config or env names and no room secret may reach it; its reach as the owner's OS user (credentials, fallback KEK file, Rooms data, all by access(2) only) is recorded as `todo`, by design for share-live.
- **Names, activity and owner fingerprint (roadmap R3.3, R3.5, R3.6), 2026-11-01.** *Built:* `room.profile {name, description, rev}` and `member.profile {memberId, label}` as MLS application payloads (`server/mls/formats.ts`); `MlsMember.sendProfile`, `onProfile` (delivered after the state write, with the sender leaf and its role in the verified roster) and `announce` (re-sent after every commit with an Add, and by a joiner once it may send, because a joiner cannot read earlier epochs). `server/member/room-book.ts`: per-room names book and alert acknowledgements, sealed at `member/rooms/<roomId>/book.sealed` (purpose `member-book:<roomId>`). `server/member/activity.ts`: notices of room-log 4.6 from each accepted entry's fold step (owner: the own device's fold; member: `RoomClient.onIngest`), replays ignored. RPCs `rooms.v2.room.profile.set` (admins), `rooms.v2.member.profile.set`, `rooms.v2.alerts.ack` (no confirmation token: not admin statements). Status: `roomName`, `roomDescription`, `names` / roster `displayName`, `nameCollision`, `activity`, `sendingStopped`, alerts with `acked`, owner `adminFingerprint`, join view `ownerFingerprints` (`AuthorityChainResult.currentAdminKids`, display only). Lane host labels use the room name followed by the short room id.
  - *Choices where the spec is silent:* (1) room-log 4.5 gives `room.profile` no producer rule; receivers accept it only from a device whose member is an admin in the verified roster at delivery. (2) `rev` is not in the spec: a rename increments it, re-announcements keep it, receivers keep the highest `rev` and then the later log position; without it a re-announcement racing a rename by another admin could revert the name. (3) `member.profile` is accepted only when its `memberId` equals the MLS sender's member (the payload field is redundant but kept as the spec writes it). (4) Names are sanitized on send and again on receipt (NFC; control, format, private-use, surrogate and separator code points removed; whitespace collapsed; at most two combining marks in a row; 64 code points for a room name, 48 for a display name, 280 for a description). Spoofing is made visible, not prevented: the UI always shows the short member id after a name and flags names with the same look-alike skeleton. (5) Acknowledging an alert hides its notice on that device only; it never clears `sendingStopped` (room-log 6.6: recovery is a human decision), and the card says sending stays stopped. (6) The SAS screen shows the fingerprints of all admin keys left by the pre-admission chain (rotations, additions, removals and revocations applied in order), genesis lineage first; an omitted entry is not detectable before admission, as for the endpoint.
  - *Gaps:* re-announcement costs one or two application messages per device per Add (fine for small rooms; a single designated announcer would scale better). A device that never comes online after a rename keeps the old name until the next Add. The activity feed lives in memory and is rebuilt from the verified copy on each start, so a joined room's feed is empty until its session opens after a restart; detection alerts (fork, truncation, MLS) are shown as notices, not as feed items. Device-add notices do not say "approved by an admin" versus "by their own device" (the mode is in the statement body, which `onIngest` does not carry). A room name change reaches the member's Paseo host label at the next grant rotation, not at once. The owner's activity needs the MLS adapter (it is built in the own device's feed). Spec text to add: producer rule and `rev` for `room.profile` (4.5), the acknowledgement semantics (6.6), and the owner-fingerprint source (enrollment 6.4).
- **R3.1, R3.2, R3.7 and R2.6 (leave a room, close a lane, stale routed hosts, "Leave all rooms and delete keys"; usability roadmap), implemented on 2026-11-01; not committed; the UI is unverified in a real app.**
  - *Code:* `rooms.v2.lane.close` (admin action `lane.close`, confirm token, typed `close`; `RoomsRuntimeV2.closeLane` through `reducing`, so grants are dropped and pushed before the append); `LaneService.sync` also deletes the endpoint key (current and staged) of a closed lane. `rooms.v2.room.leave {confirm: "leave"}` (`leaveRoom`): the member's only active device signs `member.left`, one of several signs `device.removed {reason: "self"}`; a room whose access already ended, or a join that never completed, is only forgotten locally; then lane hosts are removed and `member/rooms/<roomId>` is deleted. `server/member/stale-hosts.ts` and `member/stale-hosts.json`: lane hosts that could not be removed (no PaseoApi yet, or `hosts.remove` failed; an unknown registration counts as removed), retried every 30 s and by `rooms.v2.hosts.cleanup`, shown in the status (`staleHosts`). R3.7 triggers: access ended (as before, now recorded), `lane.closed` and `member.lanes.changed` in the member's own fold (`laneLost`; the registrar skips such lanes and the journal drops the registration). `rooms.v2.data.delete {confirm: "delete", deleteHosted?}` (`deleteAllData`): leaves every joined room (forgets the unreachable ones), removes every host whose source is `plugin:rooms` (also ones no journal knows), stops the runtime, deletes the KEK through `deleteKeyStore` (keystore.ts: keyring entry or fallback file, then meta.json; an operator KEK file is kept) and the whole `plugin-data/rooms` folder; the runtime stays in state `error`/`data_deleted` until the daemon restarts. Status adds `joined[].memberDevices`, `joined[].hosted` and `staleHosts`. UI: Close lane (Lanes tab), Leave room / Leave on this device / Remove from this device (member card, typed `leave`), the stale-host notice with Retry, and "Remove Rooms from this daemon" (typed `delete`, an explicit "Also delete hosted rooms" choice). README section "Leaving a room, closing a lane, and removing Rooms".
  - *`paseo plugin remove` (checked in the Paseo 0.13.2 daemon source, `PluginService.removePlugin` and `ManagedPluginSources.remove`; not run on any daemon):* stops the plugin, removes its config entry, clears its logs, deletes a managed install (`<PASEO_HOME>/plugins/<id>`; a directory install is not touched) and `<PASEO_HOME>/plugin-settings/<id>`. It leaves `plugin-data/rooms`, the keyring entry and the plugin's connected hosts. Paseo 0.13.2 lets only the registering source remove or replace a host (`manageSources: false` for app sessions: "Disable it to stop access"), so after removal the app can only disable the lane hosts. Upstream request (proposed): remove a plugin's hosts on plugin removal, or a plugin uninstall hook.
  - *Choices where the spec is silent:* (1) leaving needs the room session (the host must log the statement); with no session the RPC refuses and nothing changes, while the bulk action forgets unreachable rooms locally and reports them (their owners still list the member). (2) The owner's own device cannot leave a room this daemon hosts. (3) "Delete hosted rooms" signs nothing: the endpoints stop and the data is deleted, so members see the room go offline rather than `room.closed`; a closure needs a second lineage or the recovery code (keys 6.8), which this action does not ask for. (4) Closed lanes' endpoint keys are deleted (room-log 4.4: never reopened). (5) The stale-host file holds ids, labels and reasons only (plain JSON, 0600).
  - *Gaps found:* (a) a room created after the e2e TEST-ONLY clock moved forward cannot issue a usable grant: `HostGrants` stamps `iat` with the wall clock while the host key's `validFrom` is the genesis `hts` (test clock), so every link fails `host_key_not_valid`. The e2e creates its second room before the clock moves. The same mismatch would hit a real host whose clock steps back after creating a room; decide whether `iat` should follow the host clock or the check allow skew. (b) The MLS Remove after `member.left` and self `device.removed` is not asserted by the new tests (the removal path is). (c) Entries a member ingested before this change are not re-checked for lost lanes. (d) Keyring deletion was tested only with the file keystore and an injected fake keyring; the real Secret Service, Keychain and Credential Manager paths are untested (R2.4).
  - *Tests:* `test/unit/v2-leave.test.ts` (registrar skip and drop, stale-host list, `deleteKeyStore` with the fallback file, a fake keyring and an operator file, the lane.close description, `laneLost`, and in-process owner and member runtimes over the fake relay with a fake PaseoApi: close lane, leave with `member.left`, stale hosts and retry, delete all on member and owner); `v2-device-link.test.ts` (one of two devices leaves with `device.removed`); `v2-rpc-contract.test.ts` (typed words in the inputs, no token). E2e section 9b: a second room with two lanes, close lane 1 with a token (open view cut, grant gone, re-close refused, the member's routed host of lane 1 removed and lane 2's kept), leave with `member.left` (roster, sessions, grants, lane 2's routed host, the member's room folder), and an independent fold of room 2's log.
