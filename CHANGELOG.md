# Changelog

All notable changes to Paseo Rooms. Versions follow [semantic versioning](https://semver.org/); before 1.0, a minor version may break compatibility.

## 0.2.1: Paseo 0.14 support (unreleased)

### Changed

- **Paseo range widened to `>=0.13.2 <0.15.0`.** Paseo checks this range against both the daemon and the app version, so a Paseo 0.14 app no longer refuses Rooms served by a 0.13.2 daemon. Tested with 0.13.2 and 0.14.0 daemons, including an owner and members on different versions ([`docs/design/paseo-0.14-compat.md`](docs/design/paseo-0.14-compat.md)).
- **Room Profile regenerated from `@getpaseo/protocol` 0.14.0.** The new `speech.local_models.*` messages are denied and the new `wholeTurns` timeline field is dropped. The profile still covers every 0.13.2 message, which a new unit test checks. The version guard's tested entry is now protocol 1 with the 0.14.0 profile; untested versions, protocols and pre-releases still pause shared agents.
- **Legacy room agents from Rooms 0.1 are refused on Paseo 0.14 and later.** Paseo 0.14 lets other plugins attach tools and MCP servers when an agent starts, which the Rooms isolation check cannot see. Rooms no longer resumes or shares these agents unless the daemon is Paseo 0.13.x, and the Rooms screen lists them with advice to archive them. On 0.13.2 nothing changes.
- `@getpaseo/protocol`, `@getpaseo/relay`, `@getpaseo/client` and `@getpaseo/plugin` dependencies are 0.14.0. The modules Rooms uses at run time are unchanged from 0.13.2.
- Test scripts accept a Paseo CLI installed from npm (`PASEO_BIN`, run on `PASEO_NODE`), and the end-to-end test accepts one CLI for the owner and another for the members (`PASEO_BIN_OWNER`, `PASEO_BIN_MEMBER`).

## 0.2.0: identity v2 pilot (unreleased)

A rewrite of the identity, enrollment and access layer ("identity v2"). Pilot release for Linux; macOS and Windows are untested.

### Added

- **Signed room log** kept by the owner's daemon, with an independent copy on every member device that checks each entry and keeps its head across restarts, so truncation or inconsistent answers are noticed.
- **Room endpoint** on the Paseo relay with Noise IK sessions, separate from the per-agent lane endpoints.
- **Enrollment with a six-digit code (SAS)** compared by voice or video, one-time invites that expire, and owner admission. A member must confirm an unfamiliar relay before joining.
- **Grants v2:** access tokens bound to one device and one shared agent, valid for at most 12 hours, renewed automatically; revocation is enforced before it is saved.
- **Device linking** with a hold of up to 72 hours, vetoes from the member's other devices, and admin approval.
- **Key rotation and recovery:** device, admin, host, endpoint and lane keys; an optional recovery key; room closure.
- **Room chat** over an MLS group (ts-mls 1.6.4), with each message signed by the sending device and kept in a sealed store.
- **Keys at rest** in the system keyring (`@napi-rs/keyring`, Secret Service on Linux) or an owner-only fallback file with a visible notice; sealed key files and MLS state.
- **Rooms screen:** create, invite, join, members, lanes, devices, alerts, activity, keys and recovery, with typed confirmations for destructive actions; leave a room, close a lane, and "Leave all rooms and delete keys" before uninstalling.
- **Paseo version guard:** the manifest requires `>=0.13.2 <0.14.0`, and shared agents are paused (fail closed) on an untested daemon version or protocol.
- **Migration from 0.1:** 0.1 data is archived on first start and 0.1 rooms are closed.

### Changed

- The plugin id stays `rooms`; invite codes are now `prc2.`, device link codes `prl2.`, grants `prg2.`.
- Rooms shares the existing agent live. It no longer creates forked room agents.
- Removed the unused `limits.json` override: lane resource limits are compiled in.
- `npm test` runs on a plain Node 20.19 or later. Scripts that need Paseo find it through `PASEO_BIN` and `PASEO_NODE`, with per-OS defaults (`tools/paseo-env.sh`).
- Git installs work through a manifest `build` step (`npm ci --omit=dev`), and no runtime code depends on a development-only package.

### Not yet done

- The reliability and security test modules in `test/reliability/` are written but have not been run.
- A full manual check of the UI in the real app has not been recorded (`ui-check/`).
- Nothing has run on macOS or Windows.

## 0.1.0: Milestone 1 (2026-10-28, not released publicly)

The first working version. One owner daemon hosted a room and its lanes. Members joined with an invite over the lane's relay channel, received Ed25519 grants with revocation, and watched a forked or live agent through the Room Profile filter. A signed, hash-chained event log recorded changes. It was tested with unit tests and an end-to-end run between two Paseo 0.13.2 test daemons on the live relay; the app UI was not checked. Its reviews (in `docs/security/`) led to identity v2. Results: [`docs/design/m1-results.md`](docs/design/m1-results.md).
