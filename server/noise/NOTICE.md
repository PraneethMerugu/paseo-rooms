# Vendored Noise module

This directory contains code from Paseo, vendored for identity v2 milestone I-4
(`docs/IMPLEMENTATION-PLAN-identity-v2.md`; spec `docs/specs/identity-v2/enrollment-v2.md` 3.2.1).

## Origin

| Item | Value |
|---|---|
| Repository | `github.com/getpaseo/paseo` |
| Path | `packages/relay/src/noise/` |
| Commit | `1467121b16742c2ce57320748d70d365aaf861c6` (2026-10-28) |
| Copied from | a local clone at that commit, clean working tree (`git status` empty); no network used |
| Copyright | Copyright (c) 2025-present Mohamed Boudra |
| License | Apache-2.0, from the repository root `LICENSE` (copied unchanged to `./LICENSE`) and the root `package.json`. `packages/relay/package.json` declares no license. Paseo has no `NOTICE` file. |

SHA-256 of the upstream files at that commit:

| Upstream file | SHA-256 | Here |
|---|---|---|
| `packages/relay/src/noise/cipher-state.ts` | `51283ef7f08e427f5bd5c28e3168e61e2f32e57c479af80d9cfe3d1340357aaf` | `cipher-state.ts`, unchanged after a 4-line header |
| `packages/relay/src/noise/symmetric-state.ts` | `a3ae574c7667c44ba9bb784dd2313d705c507ef8ab741e7f111560939126b4c6` | `symmetric-state.ts`, unchanged after a 4-line header |
| `packages/relay/src/noise/index.ts` | `24faa17b926bf7b994ce4370f3d36d15f95c135c32fb479fc38f00e62c5f858e` | `handshake-state.ts`, **changed** |
| `LICENSE` | `79d5aedce6aa0adc547336dc1bd34c5cc9308ba110fac7079ed97515ee573ad3` | `LICENSE`, unchanged |

To diff against upstream: `tail -n +5 cipher-state.ts | diff - <upstream>/cipher-state.ts` (same for
`symmetric-state.ts`); `diff <upstream>/index.ts handshake-state.ts` for the changed file.

## Modifications (handshake-state.ts only)

- A pattern table with NK and IK replaces the NK-only token list; tokens `s`, `se`, `ss` added. The `s`
  token reads 48 bytes when a key is set, 32 otherwise.
- `pattern` is a required option of `createNoiseInitiator` and `createNoiseResponder`. IK initiators
  take `localStatic`; NK initiators refuse one.
- `remoteStatic()` added. An IK responder exposes the initiator static only after message 1
  authenticated in full (payload tag included).
- A failed `writeMessage` or `readMessage` poisons the handshake: later calls throw, and the ephemeral
  secret is zeroed.
- Key pairs are length-checked; `handshakeMessageBytes()` added.
- Kept from upstream: messages strictly in turn, the 65 535-byte limit, all-zero DH results rejected,
  ephemeral injection for tests only, ephemeral secret zeroed at `split()`, error texts.

`prologue.ts` is not vendored. It builds the room endpoint prologue of enrollment-v2.md section 3.3.

## Not vendored

`noise.test.ts` and `fixtures/nk-25519-chachapoly-sha256.json` were not copied. Their negatives are
ported in `test/unit/v2-noise.test.ts`; the NK and IK vectors come from
`test/unit/fixtures/cacophony-nk-ik-25519-chachapoly-sha256.json`, extracted from
`rweather/noise-c` `tests/vector/cacophony.txt` at commit `cfe25410979a87391bb9ac8d4d4bef64e9f268c6`
(file SHA-256 `e1b0c410…38c9`).

## Platforms

Pure JS on `@noble/curves`, `@noble/hashes` and `@noble/ciphers` 2.4.0; no native code, no file or
network access. Tested on Linux only (Paseo's Node 24.20.0). Win32 and darwin: **untested**, expected
identical by construction.

`@noble/*` are currently resolved as transitive dependencies (via `@getpaseo/relay`). The spec asks for
direct, exact-version dependencies; adding them to `package.json` is left for a lockfile update.
