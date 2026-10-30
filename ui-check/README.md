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

## Identity v2 screens (I-14)

The v2 screens appear only when the daemon runs the v2 runtime (`PASEO_ROOMS_PROTOCOL=v2`); `rooms.bootstrap` then reports `protocol: "v2"`. Without the switch the M1 screens above are shown, unchanged. `up.sh` and `demo-setup.ts` set up M1 only; a v2 kit (`up-v2.sh`) is not written yet. To look at the v2 screens, start two disposable daemons as `test/e2e-v2/run.sh` does (homes under `plugin/.test-homes/v2-*`, ports 6920-6929, `PASEO_ROOMS_PROTOCOL=v2`, `PASEO_ROOMS_KEYSTORE=fallback-file`, and either the fake relay with `PASEO_ROOMS_RELAY_ENDPOINT=127.0.0.1:6923 PASEO_ROOMS_RELAY_TLS=false PASEO_ROOMS_DEV_INSECURE_RELAY=1` or the live relay), add them as hosts, and walk through the list below by hand.

Nothing here was seen in a real app. The code passed `npm run typecheck:client` (no Node or DOM types) and the RPC contract tests only.

Do each item on a wide window and a narrow window (compact layout), in a light and a dark theme.

- [ ] Only under v2: the header badge "identity v2 (development)"; a daemon without the switch shows the M1 screen.
- [ ] Fallback keystore notice (the test daemons use the file keystore): persistent warning box at the top, readable in both themes.
- [ ] "Fix permissions": `chmod 755 <home>/plugin-data/rooms` on a stopped test daemon, start it, open Rooms: the problem list and the button; press it; Rooms starts.
- [ ] Create room: the dialog preselects "Create a recovery key"; choosing Skip shows the warning. After Create, the recovery code dialog: code in groups, "Download file" (desktop and web: a `paseo-room-recovery-<roomId>.json` download; check where Electron puts it), "Save or share file" on iOS and Android (share sheet), "Copy code", "Copy file contents". The dialog does not close (backdrop, Escape, close button) until the last group is typed; note what happens when it is dismissed anyway.
- [ ] Admin confirmation dialog for each action (create invite, admit, change role, remove member, remove device, approve device, resolve conflict, rotate host key, admin key, endpoint, lane, revoke keys, propose and confirm closing, create and confirm recovery key, share an agent from "Open room…"): title, "Now: …" line, details, warning colour, typed confirmation for remove, revoke and close.
- [ ] `stale_base`: open "Change role" for one member in two app windows, confirm in one, then in the other: the dialog stays open, shows "This changed since you opened the dialog" and the new current role, and asks again.
- [ ] Join request card (owner): note, self-reported name, six digits in large type, abandoned-attempts line, contested banner (red), countdown, Admit disabled until the code is revealed, "Codes do not match" asks before burning.
- [ ] Member join: paste code, "Check code" preview (room name marked unverified, fingerprint, relay trust button), name, Join; then the six digits, "Codes match", "Codes do not match", Cancel; "Waiting for the owner to admit you…".
- [ ] Device link: "Link another device" shows the `prl2.` code once with Copy; the second device joins with it; the first device shows the six digits, "N earlier attempts" when any, "Codes match" / "Codes do not match".
- [ ] "Was this you?" box with "Not me" on the member's devices during a hold; the owner's device request notice, including the sole-device text; the conflict notices on both sides.
- [ ] Alerts: member card boxes for fork, truncation, withholding, roster_mismatch (only reachable with a misbehaving host; check the layout with a fake alert if a dev build allows it).
- [ ] Owner tabs (Members, Lanes, Keys) on a narrow window: chips wrap, long ids do not push buttons off screen, the "Revoke from seq" inputs fit.
- [ ] Lane "Recent errors" opens a modal with full text (owner only); member cards never show free-text errors, only the mapped sentences.
- [ ] "Agents from closed rooms" after a room is closed with the recovery code; "Open agent" opens it.
- [ ] About: key storage, daemon OS, and the Windows durability sentence (highlighted on a Windows daemon).

Record what you see in `ui-notes.md` under "Observed in the app".

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
