# UI check: see the rooms plugin in your real Paseo app

This kit runs two disposable Paseo 0.13.2 daemons with the `rooms` plugin and a demo room, so you can add them to your Paseo app and look at the plugin UI. Your main daemon and `~/.paseo` are not touched: every CLI call passes `--home`, and the homes live in `ui-check/.homes` (mode 0700, git-ignored).

| Daemon | Address | Role |
|---|---|---|
| demo-owner | `127.0.0.1:6910` | gateway and embedded host; owns "UI check room" |
| demo-member | `127.0.0.1:6911` | member; the lane appears here as a routed host |

## Requirements and cost

- Paseo 0.13.2 at `/opt/Paseo`, and `npm install` already run in `plugin/`.
- Ports 6910 and 6911 free.
- Your Claude login on this machine. `up.sh` creates one throwaway parent agent (Claude Haiku, "Reply with the word OK") and the room's fork agent, which runs one short turn. Two short Haiku turns in total.
- Network: the Paseo relay (`relay.paseo.sh`) for the lane endpoint. Relay registration of the daemons themselves is off.

## Run

```bash
cd plugin/ui-check
./up.sh      # about 1 minute
```

`up.sh` writes each `config.json` before the first start (loopback listen, `daemon.relay.enabled: false`, `pluginsEnabled: true`, dictation and voice off, so no speech model download), starts both daemons, installs the plugin on both, creates the parent agent, then runs `demo-setup.ts`: room with a fork lane, a one-time invite, and enrollment of demo-member. The invite code is passed in memory and never printed or written.

## Add the test daemons to the app

In the Paseo app: **Settings → Add host → Direct connection**, once per daemon.

- demo-owner: Host `127.0.0.1`, Port `6910`, Use SSL off.
- demo-member: Host `127.0.0.1`, Port `6911`, Use SSL off.

No password is needed. The daemons have no password and listen on 127.0.0.1 only, like a default local daemon. Do not use "Pair device": relay pairing is off for these daemons.

Adding hosts changes your app's saved host list. Nothing in this kit edits app storage; you add and remove the hosts yourself.

## What to look at

- **demo-owner**: sidebar row **Rooms** → Rooms screen with "UI check room" (Fork lane, Online, member demo-member connected).
- **demo-owner**, agent "UI check parent": **Ctrl+K** → **Open room…** opens the Open room screen. Pressing "Create room" works but starts another fork and one more Haiku turn.
- **demo-owner**, the fork agent (lane agent): composer pill "● Room · 1 connected"; pressing it opens Rooms.
- **demo-member**: **Rooms** → "Rooms you joined" with the room, status Connected.
- **demo-member**: routed host "UI check room · Fork lane" in the host list, with exactly one agent (the fork), read-only.

## Checklist

Do each item on a wide desktop window and on a narrow window (compact layout), in a light and a dark theme (**Settings → Appearance**).

- [ ] Rooms sidebar row: icon and label render; row highlights when the screen is open.
- [ ] Rooms screen: headings, cards, badges and buttons are readable; no black text on a dark background.
- [ ] Open room screen: input placeholders, Fork/Share options and hints are readable.
- [ ] Composer pill on the lane agent renders and opens Rooms.
- [ ] "Create invite" shows the code box; "Hide" clears it. The code is a real one-time secret for this test room.
- [ ] Routed lane host on demo-member: one agent; timeline renders.
- [ ] Disallowed actions on the routed host (send a message, archive, terminals, new agent): note whether each is visible and how its error appears.
- [ ] Errors from plugin buttons appear as readable toasts.

Record findings in `ui-notes.md` (it already lists issues found by reading the code).

## What should work, and known rough edges

Expected to work (verified by the e2e test, not yet in a real app): room and lane listing, invite creation, member listing and revoke, join and leave, the routed lane host with one agent and a live timeline, denial of everything else on the routed host.

Known rough edges:

- **Disallowed buttons stay visible** on the routed host. The app does not read `server_info.permissions`, so controls such as the composer or archive appear and fail with "Room is not authorized for …" (research/rooms-feasibility.md 2.5).
- **Stale routed entries.** After leave or revoke, the routed host can stay in the app's list until you remove it (Paseo does not prune routed hosts).
- **Member delay.** After a revoke, demo-member reports the failure 5-7 s later; access stops at once.
- **No room archive or rename.** Closed lanes and rooms stay listed.
- Revoking demo-member or closing the lane is fine to try, but it ends the demo; rerun `down.sh` and `up.sh` to reset.

## Tear down

1. In the app, remove both hosts: **Settings → demo-owner (and demo-member) → Remove host**. If a routed "UI check room · Fork lane" entry remains, remove it too.
2. Run:

```bash
./down.sh
```

`down.sh` archives the demo agents (archiving the parent also archives its fork), stops both daemons, terminates leftover processes started from `.homes`, and deletes `.homes`. It is safe to run repeatedly and after a failed `up.sh`.

## Secrets

`.homes` holds each daemon's local credential, the member's grant (in `hosts.json`) and the plugin keys. It is 0700, git-ignored and deleted by `down.sh`. The scripts print no credential, invite code or grant.

## Files

- `up.sh`, `down.sh`: start and stop the kit.
- `demo-setup.ts`: room, lane, invite and enrollment through plugin RPCs (run by `up.sh` with the Node bundled in Paseo).
- `ui-notes.md`: client audit result and UI issues to confirm.
