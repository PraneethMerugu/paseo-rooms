# Paseo Rooms

Rooms is a [Paseo](https://paseo.sh) plugin for sharing a running agent, read-only, with other people who use Paseo. You create a room, share an agent in it and invite people. After a short voice or video check, the shared agent appears in their Paseo app as a separate host. They can watch its timeline and turns live, and chat with the room. They cannot prompt it, approve anything for it, or see anything else on your machine. You can remove them at any time.

## Status

**v0.2.1 is a pilot release for Linux.** It is used and tested on Linux only. Read the [security model](#security-model) before you share an agent, and share only with people you trust with what that agent shows.

| Area | State |
|---|---|
| Linux (x64, glibc) | Tested: unit and conformance tests, offline end-to-end tests with real Paseo test daemons, and a Git install. |
| macOS, Windows | **Untested.** The code has paths for both (Keychain, Credential Manager, Windows file ACLs), but none has run. Do not rely on Rooms there yet. |
| Paseo app UI | Built and typechecked. A full manual check in the real app ([`ui-check/`](ui-check/README.md)) has not been recorded yet. |
| Reliability and security test modules | Written and typechecked, **not run yet** ([`test/reliability/`](test/reliability/README.md)). |

## Requirements

- **Paseo 0.13.2 or later, up to 0.14.x** on every daemon and app that uses Rooms, both yours and your members'. The plugin declares `>=0.13.2 <0.15.0`; Paseo checks this range against both the daemon and the app version. Owners and members may run different versions in that range. On other Paseo versions Rooms keeps rooms and chat working but pauses shared agents (see [Troubleshooting](#troubleshooting)).
- **Plugins enabled** on each daemon (`pluginsEnabled: true`, or Settings → Plugins → Enable plugins in the app). Paseo plugins are trusted code: Rooms runs on your daemon with your permissions.
- **git and npm on the daemon host.** Paseo clones the repository and runs `npm ci --omit=dev` in it during install. Any recent npm works; the plugin itself runs on Paseo's bundled Node.
- **A system keyring** is recommended (on Linux, a Secret Service such as GNOME Keyring or KWallet). Without one, Rooms keeps its key in a protected file and says so.
- **Network access** to the Paseo relay (`relay.paseo.sh`) for the owner's and the members' daemons.

## Install

On each daemon host (yours and every member's):

```bash
paseo plugin install github:PraneethMerugu/paseo-rooms
paseo plugin ls          # rooms should show "running"
```

To pin a release or commit, add `--ref <tag or commit>`. To manage another daemon, add `--host <host>` (see `paseo plugin install --help`). Paseo shows a trust notice first: the plugin's server code and its install command (`npm ci`) run unsandboxed on the daemon host.

**From a local checkout** (for development): Paseo does not install dependencies for a directory install, so run `npm ci` yourself first.

```bash
git clone https://github.com/PraneethMerugu/paseo-rooms.git
cd paseo-rooms
npm ci --omit=dev
paseo plugin install "$PWD"
```

**Update:** `paseo plugin update rooms` (Git installs; a directory install is updated by pulling and running `paseo plugin reload rooms`).

## First run

Open the Paseo app. **Rooms** appears in the sidebar. On first start Rooms chooses where to keep its key, once:

- the system keyring, when one is available and unlocked. Your desktop may ask you to unlock it.
- otherwise a protected file in the daemon's home. The Rooms screen shows a notice that the file is in use.

The choice is recorded and never changes silently afterwards. To always use the file (for example on a headless host), start the daemon with `PASEO_ROOMS_KEYSTORE=fallback-file`.

## Quick start

**1. Create a room** (owner). Rooms → **Create room**. Rooms offers a recovery key: save it if you want to be able to recover the room after losing your admin key.

**2. Share an agent** (owner). Open the agent, open the Command Center and choose **Open room…**. Pick the room and press **Share**. The agent itself is shared, live and read-only. Rooms does not copy or fork it.

**3. Invite** (owner). On the room's card, **Create invite**, then **Copy code**. The code starts with `prc2.`, works once and expires after 30 minutes by default. Send it privately.

**4. Join** (member). Rooms → paste the code under "Join with an invite or device link code" → **Check code**. Confirm the relay if asked, enter a name for this device (for example "Sam laptop") and press **Join**.

**5. Compare the six-digit code.** Both of you now see six digits. Read them to each other by voice or video. The member presses **Codes match**. The owner presses **Admit** only if the digits match. If they differ, press **Codes do not match**: the join stops and the invite cannot be reused.

**6. Watch.** The shared agent appears in the member's app as a host named after the room's lane. The member's daemon renews access on its own while they stay in the room.

**7. Chat.** On the room card, **Chat** opens the room chat. Messages are end-to-end encrypted to the room's members and signed by the sending device.

**8. Leave or remove.**
- A member leaves with **Leave room** on the room card (type `leave` to confirm). This deletes the room's keys from that device.
- The owner removes a member with **Remove** in the Members tab. Their live view is cut immediately.
- The owner stops sharing an agent with **Close lane** in the Lanes tab (type `close`), or by archiving the agent.

More devices: a member can add another of their own devices with **Link another device**. The new device waits up to 72 hours unless an admin approves it sooner, and any of the member's devices can stop it.

## Security model

- **Watch only.** A shared agent runs as your OS user, so member input can never drive it. Every message type that could prompt, steer, approve, archive, open terminals or files, change settings or reach other agents is refused. Your daemon also gives each viewer session read-only permissions.
- **Only the shared agent.** Members see that agent, its workspace and its timeline. Project and folder names are hidden by default. Paths, git remotes, pull requests, scripts and your other agents are never sent.
- **People confirm every join.** Invites are one-time and expire. A join completes only after both people compare the six-digit code and the owner admits it. Removing a member takes effect at once. Access grants last at most 12 hours and are bound to one device and one shared agent.
- **Signed room log.** Your daemon keeps a signed log of who was admitted, which devices they use, what is shared and every change of access. Each member's daemon keeps its own copy and checks every entry, so inconsistent answers from the host are noticed.
- **Encrypted transport.** Room and lane traffic goes through the Paseo relay end to end encrypted (Noise IK sessions for the room, the relay's protected mode for lanes, MLS for chat). The relay does not see content.
- **Everything on a member's daemon can read what they can.** The shared agent is a host on the member's daemon, so their app, their paired devices and their own agents can read it too. Share only with people whose machines you would trust with what the agent shows.
- **Same-user software is trusted.** Rooms keeps keys in the system keyring or in owner-only files. Another program running as your OS user (including other Paseo plugins, which run with full permissions) is not something Rooms can defend against.
- **The owner's daemon must be online** for members to see the room and the shared agents.

The design and its reviews are in [`docs/`](docs/README.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Platforms and Paseo versions

- **Platforms:** Linux is the only tested platform for v0.2. macOS and Windows are untested.
- **Paseo versions:** `>=0.13.2 <0.15.0`, tested with 0.13.2 and 0.14.0, including an owner and members on different versions. Rooms filters traffic with a message table generated from Paseo's 0.14.0 protocol, which also covers every 0.13.2 message. At start, and again when each shared agent starts, Rooms checks the daemon's version and protocol. Outside the tested range it stops serving shared agents (fail closed) and the Rooms screen says "Shared agents are paused" with the reported and tested versions. Rooms, members and chat keep working. Pre-release Paseo builds count as untested.

## Uninstall

Leave your rooms and delete the keys **before** removing the plugin:

1. Rooms screen → **Remove Rooms from this daemon** (**Show**) → **Leave all rooms and delete keys** (type `delete`). This leaves every joined room, removes the lane hosts Rooms added, deletes the Rooms key from the keyring or file, and deletes `<PASEO_HOME>/plugin-data/rooms`. Rooms you host stop for good, so this asks for an extra "Also delete hosted rooms" choice and closes each hosted room where it can. The dialog lists any room it cannot close.
2. `paseo plugin remove rooms`.

`paseo plugin remove` on its own leaves `<PASEO_HOME>/plugin-data/rooms` (room keys, logs), the keyring entry and the lane hosts behind. If the plugin is already gone: delete `<PASEO_HOME>/plugin-data/rooms`, delete the keyring entry with service `paseo-rooms` using your OS keyring tool, and disable any hosts labelled "Room lane: …" in the app.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `paseo plugin install` fails with "npm" or "git" not found | Install git and Node.js with npm on the daemon host, then install again. |
| Rooms does not appear in the app | Check `paseo plugin ls`. If plugins are disabled, enable them (Settings → Plugins). If `rooms` is not `running`, read `paseo plugin logs rooms`. |
| Install refused because of the Paseo version, or the app says `Plugin "rooms" requires Paseo ...` | Rooms needs Paseo `>=0.13.2 <0.15.0` on the daemon and in the app. Update Rooms on the daemon (`paseo plugin install` again) and Paseo, or wait for a Rooms release that supports your version. |
| "Legacy room agents are not resumed" | These agents were created by Rooms 0.1. On Paseo 0.14 and later other plugins can attach tools to an agent when it starts, which Rooms cannot check, so Rooms refuses to start them. Archive them; Rooms 0.2 shares your existing agents live. |
| "Shared agents are paused" | The daemon's Paseo version or protocol is outside the tested range. Rooms and chat keep working; shared agents resume on a tested version. |
| "Keyring locked" | Unlock your system keyring, then reload the Rooms screen. Rooms waits instead of switching to another store. |
| Notice that keys are kept in a protected file | No system keyring was available at first start. This works; the key is protected by file permissions only. |
| "Rooms files are not protected" with **Fix permissions** | Files under `plugin-data/rooms` were readable or writable by other accounts. Rooms loaded no keys. Press **Fix permissions** after checking why that happened. |
| The invite code is rejected | Invites work once and expire (30 minutes by default). Ask the owner for a new one. |
| The member sees a different six-digit code | Press **Codes do not match**. Someone may have intercepted the invite. Ask for a new invite over a different channel. |
| A member cannot see the room | The owner's daemon must be online and reach `relay.paseo.sh`. |
| An old lane host stays in the member's host list | Rooms removes lane hosts when access ends and retries every 30 s. Use **Retry now** in the notice, or disable the host in the app. |

Plugin logs: `paseo plugin logs rooms`. Rooms never logs keys, and it redacts grants, invite, link and recovery codes as a second line of defence.

## Upgrading from 0.1

Rooms 0.1 rooms are closed on upgrade. Their invite codes (`prc1.`) stop working and their members lose access. The old data is moved to an archive folder. The Rooms screen offers to delete the old keys and lists agents from closed rooms. Create a new room and invite people again.

## Contributing and licence

Development setup, tests and the code layout are in [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

Licensed under the [Apache License 2.0](LICENSE). Rooms includes code from Paseo (`server/noise/`); see [NOTICE](NOTICE).
