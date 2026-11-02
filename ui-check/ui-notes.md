# UI notes: paseo-rooms client

Status: **static code review only**. Nothing below was seen in the real app; the app check is the user's step (see README.md). Plugin source was not modified. Add app observations under "Observed in the app".

## Mobile/RN audit (paseo-plugin skill)

Command, from the repository root:

```bash
rg -n "document\.|window\.|localStorage|navigator\.|<[a-z]+[ >]|className=|onClick=" client/
```

One hit, a false positive: `client/ui.tsx:38` `ReturnType<typeof useStyles>` (a TypeScript generic matches `<[a-z]+[ >]`). No DOM globals, HTML elements, `className` or `onClick`. No hard-coded hex or rgb colors in `client/` or `index.client.tsx`. Every `Text` has a style from `theme.colors`; all four `TextInput`s set `placeholderTextColor` from the theme.

## Known rough edges (from docs/design/m1-results.md and the feasibility study (design research, not published) 2.5)

1. Disallowed actions stay visible on the routed lane host. The app ignores `server_info.permissions`, so the composer, archive, terminals and new-agent controls appear and fail with "Room is not authorized for …" when used. Check how each failure is shown (toast, inline, silent).
2. Stale routed host entries after leave or revoke (Paseo does not prune routed hosts). The joined card says so for `revoked`, but not for `left`.
3. Member-side status lags 5-7 s after a revoke.

## Issues found in the code (to confirm in the app)

Ordered by likely user impact.

1. **Copy bug: "renews before in 23 h".** `relativeTime` returns "in 23 h", and two strings prefix it with "before": member rows (`rooms-screen.tsx` `grant renews before ${relativeTime(...)}`) and the joined card (`access renews before ...`). Suggest "renews in 23 h" or "expires in 23 h".
2. **Destructive actions have no confirmation and no busy state.** "Close lane", "Leave" and "Revoke invite" fire on first press and can be double-pressed. "Revoke" (member) has a busy state but no confirmation.
3. **"Open room…" is offered on every agent**, including lane (fork) agents and agents whose provider cannot fork (opencode, omp). The refusal only shows as a toast after "Create room". Consider hiding the item on agents labelled `rooms.lane`, and disabling "Fork" for unsupported providers.
4. **Keyboard hint on mobile.** Empty-state and open-room texts say "press Ctrl+K or ⌘K"; there is no such key on a phone. Use `layout.compact` or platform to change the hint.
5. **Badge overflow.** On the joined card the badge label can be `hostError` (free text). `Badge` has no `numberOfLines` or `flexShrink`, so a long error may push the row off screen in the compact layout.
6. **Invite code display.** The 661-char code is rendered with `numberOfLines={3}`, so it looks truncated. "Copy code" copies the full value; a short note ("truncated; use Copy") or a scrollable box would avoid confusion.
7. **`fontFamily: "monospace"`** (`ui.tsx` `mono`) is an Android/web name; iOS does not know it and falls back (possibly with a warning). `Platform.select({ ios: "Menlo", default: "monospace" })` is the usual fix.
8. **Owner card with no members** shows a badge "0 of 0 connected". "No members yet" reads better.
9. **Join button disabled below 20 characters** with no hint why.
10. **Pill count lag.** The composer pill refreshes every 10 s by polling, the Rooms screen every 5 s, so the two can disagree briefly after a join or revoke. The pill dot "●" takes the pill's text color, not a status color.
11. **Closed lanes and rooms stay listed** (no archive or rename yet; M1 open issue 7).
12. **Plugin UI with the routed host selected.** If the app lets you pick the routed lane host in a plugin screen's host picker, plugin RPCs are denied there, so the Rooms screen should show "Could not load rooms: …". Check that this is readable and that the sidebar item does not break.

## Identity v2 screens (I-14), static review only

Files: `client/v2-screen.tsx`, `v2-owner.tsx`, `v2-member.tsx`, `v2-dialogs.tsx`, `v2-text.ts`, `save-file.ts`, `protocol.ts`. The checklist is in README.md, section "Identity v2 screens".

- The audit grep above now also hits `client/save-file.ts` (`g.document.createElement`, `g.document.body`). Intended: the web download path probes `globalThis.document` at run time only when `Platform.OS === "web"`, and falls back to the share sheet. `npm run typecheck:client` builds the client with no Node and no DOM types, so a direct DOM or Node use fails the check.
- Unverified assumptions: the desktop app reports `Platform.OS === "web"` and lets an `<a download>` click save a file (Electron may show a save dialog or save to Downloads silently); `Share.share` exists on react-native-web in the app and on iOS and Android; `Modal`'s `onOpenChange(false)` is the only way the host closes a dialog (the recovery dialog ignores it until the last group is typed).
- The recovery dialog cannot stop the app from being closed or the screen from unmounting; the code is then lost (by design it is not stored).
- Owner card length: an owner with many members, requests and alerts gets a long card; tabs keep the members, lanes and keys apart.
- No leave or lane-close buttons under v2 (no RPCs yet); the cards say so.

## Observed in the app

(fill in: window size, theme, host, what you saw)
