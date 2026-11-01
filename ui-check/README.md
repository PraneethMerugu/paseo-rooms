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

The v2 screens appear only when the daemon runs the v2 runtime (`PASEO_ROOMS_PROTOCOL=v2`); `rooms.bootstrap` then reports `protocol: "v2"`. Without the switch the M1 screens above are shown, unchanged. `up.sh` and `demo-setup.ts` set up M1 only; use the v2 kit below for the v2 screens.

### Identity v2 kit (`up-v2.sh`)

Three disposable daemons with `PASEO_ROOMS_PROTOCOL=v2`. The two kits use different ports and homes and can run at the same time.

| Daemon | Address | Role |
|---|---|---|
| v2-owner | `127.0.0.1:6912` | owns "UI check room v2" and "SAS demo room", hosts the lane |
| v2-member | `127.0.0.1:6913` | member device A ("demo-member laptop") |
| v2-member2 | `127.0.0.1:6914` | the same member's second device B ("demo-member phone") |
| fake relay | `127.0.0.1:6915` | only with `--offline` |

```bash
cd plugin/ui-check
./up-v2.sh             # live relay relay.paseo.sh:443 for the room endpoint (about 45 s)
./up-v2.sh --offline   # fake relay on 127.0.0.1:6915, no network
./down-v2.sh           # archive the agent, stop everything, delete .homes-v2
```

**Cost: zero model calls.** `up-v2.sh` creates one Claude Haiku agent for the lane without a prompt, so no turn runs. Step 5 of the script checks this and fails otherwise: the agent's timeline is empty (`paseo logs`), its `LastUsage` is null (`paseo inspect`), and no daemon log has a finished turn ("Sending push notification"). The test runs on 2026-11-01 also showed no `claude` process under any test daemon.

**Network.** Live mode: only the room endpoint and the member connections to `relay.paseo.sh:443` (checked with `ss` on 2026-11-01: every non-loopback connection of the test daemons went to the relay's address). Offline mode: loopback only. The daemons' own relay registration is off in both modes.

**Safety.** Same gates as `up.sh` and `test/e2e-v2/run.sh`: homes must resolve under `ui-check/.homes-v2` (0700, git-ignored) and never to `~/.paseo`; ports outside 6912-6919, and 6767, are refused; every CLI call passes `--home` and `PASEO_HOME`; dictation and voice off; keys in the protected fallback file (`PASEO_ROOMS_KEYSTORE=fallback-file`), never the keyring; no development timers, short grants or test clock. Loopback listen, no password.

**What `up-v2.sh` sets up** (`demo-setup-v2.ts`, all through the plugin RPCs the app uses):

1. "UI check room v2" with a recovery key. The recovery code is discarded in memory: it is not shown, printed or saved.
2. Lane "Demo lane" on the Haiku agent.
3. demo-member admitted by the real enrollment flow: invite, join, SAS on both sides, "Codes match", Admit. TEST-ONLY: the script reads both six-digit codes from the status RPC and checks they are equal before pressing the buttons, as people would by voice.
4. The member's lane grant and routed host, and three MLS chat messages between the owner's device and device A.
5. Device link from A to B (link SAS compared the same way, both confirm). B is **held**: A was enrolled seconds ago (younger than 24 h), so the hold has no end time and an admin must approve.
6. One open, unused invite in room 1 (code discarded).
7. "SAS demo room" (recovery key skipped) with a **pending join** from device A, SAS shown on both sides. Before it, one attempt was started and cancelled (one abandoned attempt). Device B then tried the same invite while it was claimed: the host refused it and marked the request **contested**. This is the real host behaviour, not injected state.
8. A scan of every file under `.homes-v2` for the invite codes, link code, their tokens and the recovery code. The script fails if one is found.

The pending join times out **15 minutes** after setup (it then counts as a second abandoned attempt). To get a fresh owner-side SAS screen from the UI: on v2-owner, "SAS demo room" → **Lanes and invites** → **Create invite** → confirm → **Copy code**. On v2-member, press **Dismiss** on the old "SAS demo room" card if one is shown, paste the code under the join box, **Check code**, (offline only: **Trust this relay**), enter a name, **Join**. Both sides then show the six digits.

**Add the three hosts:** in the app, **Settings → Add host → Direct connection**, once per daemon: Host `127.0.0.1`, Port `6912`, `6913`, `6914`, Use SSL off. No password. Do not use "Pair device".

**What to look at** (sidebar row **Rooms** on each host):

- **v2-owner (6912)**: badge "identity v2 (development)"; the fallback keystore notice; About.
  - Room 1 card, **Members** tab: you and "demo-member laptop" (connected); the held device request for "demo-member phone" (sole device, admin must approve) with **Approve**.
  - **Lanes and invites**: "Demo lane" online with one link; the open invite "spare invite (unused)" with **Revoke invite**; **Create invite**.
  - **Keys**: host key, admin key, a recovery key present; rotate and revoke buttons (each opens the admin confirmation dialog; cancel to keep the demo).
  - "SAS demo room" card: join request with the note, the self-reported name, the six digits, the abandoned-attempts line ("1 earlier attempt(s) on this invite were abandoned."), the red **contested** text ("Another device also tried to use this invite …") and border, the countdown, **Admit** / **Codes do not match** / **Cancel**.
  - **Create room** opens the create dialog and, with "Create a recovery key", the recovery code dialog (adds a room; no model call).
- **v2-member (6913)**: "Rooms you joined": "UI check room v2" connected, the held-device box for the phone ("… will join your membership in this room when an admin approves it", sole-device line) with **Not me**, **Link another device**, **Replace this device's keys**. The joining card for "SAS demo room" with the six digits, **Codes match**, **Codes do not match**, **Cancel**. The host list also shows the routed lane host "Demo lane" with the one agent.
- **v2-member2 (6914)**: the held join of "UI check room v2" ("Your other device confirmed …"), and the failed join of "SAS demo room" (invite in use) with **Dismiss**.

The chat messages have no screen yet (chat UI is milestone M2); only the counts in the MLS state exist.

Actions that change the demo, worth trying last: **Not me** on v2-member (veto; conflict notices on both sides, **Resolve conflict** on the owner), **Approve** on v2-owner (B becomes an active device), **Admit** after "Codes match" on v2-member (A joins "SAS demo room"), removals and key rotations. Rerun `./down-v2.sh` and `./up-v2.sh` to reset.

**Tear down:** remove the three hosts (and any routed "Demo lane" host) from the app, then run `./down-v2.sh`. It archives the agent, stops the daemons and the fake relay, kills leftovers, deletes `.homes-v2`, and reports whether ports 6912-6919 are free. It is safe to run repeatedly.

### v2 checklist

Nothing here was seen in a real app. The code passed `npm run typecheck:client` (no Node or DOM types) and the RPC contract tests only.

Do each item on a wide window and a narrow window (compact layout), in a light and a dark theme (**Settings → Appearance**). With the v2 kit running, the join request card, member join, device link hold, "Was this you?", owner tabs, admin dialogs, Create room and About are ready to look at. "Fix permissions", `stale_base`, "Agents from closed rooms" and the alert boxes need the extra steps given in their items (for "Fix permissions", stop one daemon with `PASEO_HOME=<home> /opt/Paseo/resources/bin/paseo daemon stop --home <home>`, with `<home>` under `ui-check/.homes-v2`, and start it the same way).

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

`.homes` and `.homes-v2` hold each daemon's local credential, the member's grant (in `hosts.json`) and the plugin keys. Both are 0700, git-ignored and deleted by `down.sh` and `down-v2.sh`. The scripts print no credential, invite code, link code, grant or recovery code; `demo-setup-v2.ts` also checks that no code or token it handled is in any file under `.homes-v2`.

## Files

- `up.sh`, `down.sh`: start and stop the kit.
- `demo-setup.ts`: room, lane, invite and enrollment through plugin RPCs (run by `up.sh` with the Node bundled in Paseo).
- `up-v2.sh`, `down-v2.sh`: start and stop the v2 kit (`--offline` for the fake relay).
- `demo-setup-v2.ts`: v2 demo state through the plugin RPCs (run by `up-v2.sh`).
- `fake-relay-v2.ts`: the unit-test fake relay on a port in 6912-6919 (offline mode).
- `ui-notes.md`: client audit result and UI issues to confirm.
