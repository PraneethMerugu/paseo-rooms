# UI check: see the rooms plugin in your real Paseo app

This kit runs three disposable Paseo 0.13.2 daemons with the `rooms` plugin and demo state, so you can add them to your Paseo app and look at the Rooms screens. Your main daemon and `~/.paseo` are not touched: every CLI call passes `--home`, and the homes live in `ui-check/.test-homes` (mode 0700, git-ignored).

Since the identity v2 cut-over (I-15, 2026-11-01) this is the only kit. The M1 kit (`up.sh`, `down.sh`, `demo-setup.ts`, two daemons on 6910/6911 with a fork lane) was removed with the M1 code; it is in git at tag `m1-baseline`.

| Daemon | Address | Role |
|---|---|---|
| v2-owner | `127.0.0.1:6912` | owns "UI check room v2" and "SAS demo room", hosts the lane |
| v2-member | `127.0.0.1:6913` | member device A ("demo-member laptop") |
| v2-member2 | `127.0.0.1:6914` | the same member's second device B ("demo-member phone") |
| fake relay | `127.0.0.1:6915` | only with `--offline` |

## Run

| Daemon | Address | Role |
|---|---|---|
| v2-owner | `127.0.0.1:6912` | owns "UI check room v2" and "SAS demo room", hosts the lane |
| v2-member | `127.0.0.1:6913` | member device A ("demo-member laptop") |
| v2-member2 | `127.0.0.1:6914` | the same member's second device B ("demo-member phone") |
| fake relay | `127.0.0.1:6915` | only with `--offline` |

```bash
cd paseo-rooms/ui-check
./up-v2.sh             # live relay relay.paseo.sh:443 for the room endpoint (about 45 s)
./up-v2.sh --offline   # fake relay on 127.0.0.1:6915, no network
./down-v2.sh           # archive the agent, stop everything, delete .test-homes
```

**Cost: zero model calls.** `up-v2.sh` creates one Claude Haiku agent for the lane without a prompt, so no turn runs. Step 5 of the script checks this and fails otherwise: the agent's timeline is empty (`paseo logs`), its `LastUsage` is null (`paseo inspect`), and no daemon log has a finished turn ("Sending push notification"). The test runs on 2026-11-01 also showed no `claude` process under any test daemon.

**Network.** Live mode: only the room endpoint and the member connections to `relay.paseo.sh:443` (checked with `ss` on 2026-11-01: every non-loopback connection of the test daemons went to the relay's address). Offline mode: loopback only. The daemons' own relay registration is off in both modes.

**Safety.** Same gates as `test/e2e-v2/run.sh`: homes must resolve under `ui-check/.test-homes` (0700, git-ignored) and never to `~/.paseo`; ports outside 6912-6919, and 6767, are refused; every CLI call passes `--home` and `PASEO_HOME`; dictation and voice off; keys in the protected fallback file (`PASEO_ROOMS_KEYSTORE=fallback-file`), never the keyring; no development timers, short grants or test clock. Each home carries the test-home marker: the plugin honours `PASEO_ROOMS_DEV_*` switches (here only the loopback relay of `--offline`) only on such a home. Loopback listen, no password.

**What `up-v2.sh` sets up** (`demo-setup-v2.ts`, all through the plugin RPCs the app uses):

1. "UI check room v2" with a recovery key. The recovery code is discarded in memory: it is not shown, printed or saved.
2. Lane "Demo lane" on the Haiku agent.
3. demo-member admitted by the real enrollment flow: invite, join, SAS on both sides, "Codes match", Admit. TEST-ONLY: the script reads both six-digit codes from the status RPC and checks they are equal before pressing the buttons, as people would by voice.
4. The member's lane grant and routed host, and three MLS chat messages between the owner's device and device A.
5. Device link from A to B (link SAS compared the same way, both confirm). B is **held**: A was enrolled seconds ago (younger than 24 h), so the hold has no end time and an admin must approve.
6. One open, unused invite in room 1 (code discarded).
7. "SAS demo room" (recovery key skipped) with a **pending join** from device A, SAS shown on both sides. Before it, one attempt was started and cancelled (one abandoned attempt). Device B then tried the same invite while it was claimed: the host refused it and marked the request **contested**. This is the real host behaviour, not injected state.
8. A scan of every file under `.test-homes` for the invite codes, link code, their tokens and the recovery code. The script fails if one is found.

The pending join times out **15 minutes** after setup (it then counts as a second abandoned attempt). To get a fresh owner-side SAS screen from the UI: on v2-owner, "SAS demo room" → **Lanes and invites** → **Create invite** → confirm → **Copy code**. On v2-member, press **Dismiss** on the old "SAS demo room" card if one is shown, paste the code under the join box, **Check code**, (offline only: **Trust this relay**), enter a name, **Join**. Both sides then show the six digits.

**Add the three hosts:** in the app, **Settings → Add host → Direct connection**, once per daemon: Host `127.0.0.1`, Port `6912`, `6913`, `6914`, Use SSL off. No password. Do not use "Pair device".

**What to look at** (sidebar row **Rooms** on each host):

- **v2-owner (6912)**: the fallback keystore notice; About.
  - Room 1 card, **Members** tab: you and "demo-member laptop" (connected); the held device request for "demo-member phone" (sole device, admin must approve) with **Approve**.
  - **Lanes and invites**: "Demo lane" online with one link; the open invite "spare invite (unused)" with **Revoke invite**; **Create invite**.
  - **Keys**: host key, admin key, a recovery key present; rotate and revoke buttons (each opens the admin confirmation dialog; cancel to keep the demo).
  - "SAS demo room" card: join request with the note, the self-reported name, the six digits, the abandoned-attempts line ("1 earlier attempt(s) on this invite were abandoned."), the red **contested** text ("Another device also tried to use this invite …") and border, the countdown, **Admit** / **Codes do not match** / **Cancel**.
  - **Create room** opens the create dialog and, with "Create a recovery key", the recovery code dialog (adds a room; no model call).
- **v2-member (6913)**: "Rooms you joined": "UI check room v2" connected, the held-device box for the phone ("… will join your membership in this room when an admin approves it", sole-device line) with **Not me**, **Link another device**, **Replace this device's keys**. The joining card for "SAS demo room" with the six digits, **Codes match**, **Codes do not match**, **Cancel**. The host list also shows the routed lane host "Demo lane" with the one agent.
- **v2-member2 (6914)**: the held join of "UI check room v2" ("Your other device confirmed …"), and the failed join of "SAS demo room" (invite in use) with **Dismiss**.

The chat messages have no screen yet (chat UI is milestone M2); only the counts in the MLS state exist.

Actions that change the demo, worth trying last: **Not me** on v2-member (veto; conflict notices on both sides, **Resolve conflict** on the owner), **Approve** on v2-owner (B becomes an active device), **Admit** after "Codes match" on v2-member (A joins "SAS demo room"), removals and key rotations. Rerun `./down-v2.sh` and `./up-v2.sh` to reset.

**Tear down:** remove the three hosts (and any routed "Demo lane" host) from the app, then run `./down-v2.sh`. It archives the agent, stops the daemons and the fake relay, kills leftovers, deletes `.test-homes`, and reports whether ports 6912-6919 are free. It is safe to run repeatedly.

## Checklist

Nothing here was seen in a real app. The code passed `npm run typecheck:client` (no Node or DOM types) and the RPC contract tests only.

Do each item on a wide window and a narrow window (compact layout), in a light and a dark theme (**Settings → Appearance**). With the v2 kit running, the join request card, member join, device link hold, "Was this you?", owner tabs, admin dialogs, Create room and About are ready to look at. "Fix permissions", `stale_base`, "Agents from closed rooms" and the alert boxes need the extra steps given in their items (for "Fix permissions", stop one daemon with `PASEO_HOME=<home> "$PASEO_BIN" daemon stop --home <home>` (`PASEO_BIN` is the paseo CLI, see `tools/paseo-env.sh`), with `<home>` under `ui-check/.test-homes`, and start it the same way).

- [ ] No development badge; the screen is the only Rooms screen (the M1 screens were removed at the I-15 cut-over).
- [ ] Not in the demo: the upgrade notices (migration from M1: "Rooms was upgraded", the old keys box with "Delete keys" and its confirmation). They need a home that ran the M1 plugin; `test/e2e-v2/migration-run.sh` builds one but deletes it afterwards.
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

## Known rough edges

- **Disallowed buttons stay visible** on the routed host. The app does not read `server_info.permissions`, so controls such as the composer or archive appear and fail with "Room is not authorized for …" (the feasibility study (design research, not published) 2.5).
- **Stale routed entries.** After a removal, the routed host can stay in the app's list until you remove it (Paseo does not prune routed hosts).
- **No leave or lane close in the UI yet** (I-14 follow-up): the cards say "not available yet". Archiving the shared agent closes its lane.

## Secrets

`.test-homes` holds each daemon's local credential, the member's grant (in `hosts.json`) and the sealed plugin keys with the fallback key file. It is 0700, git-ignored and deleted by `down-v2.sh`. The scripts print no credential, invite code, link code, grant or recovery code; `demo-setup-v2.ts` also checks that no code or token it handled is in any file under `.test-homes`.

## Files

- `up-v2.sh`, `down-v2.sh`: start and stop the kit (`--offline` for the fake relay).
- `demo-setup-v2.ts`: demo state through the plugin RPCs (run by `up-v2.sh`).
- `fake-relay-v2.ts`: the unit-test fake relay on a port in 6912-6919 (offline mode).
- `ui-notes.md`: client audit result and UI issues to confirm.
