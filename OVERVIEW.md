Rooms lets you share one agent, read-only, with other people who run Paseo. You open a room from an agent, send someone a one-time invite code, and the agent appears in their Paseo app as a separate host they can watch live: its workspace, its timeline and its turns as they stream. Nothing else on your machine is visible to them, and you can revoke access at any time.

## How it works

The owner's daemon runs the room. Each shared agent gets its own endpoint on the Paseo relay, using the relay's protected (end-to-end encrypted) mode only. A member pastes the invite code into the Rooms screen on their own daemon. Their daemon proves possession of its own key, receives a time-limited access grant, and registers the shared agent as a connected host. The member's app reaches it through their own daemon, so the access grant never enters the app.

Everything a member's app sends is checked against a fixed allowlist bound to the one shared agent. Sending prompts, approving, archiving, terminals, files, settings and other hosts are refused. The owner's daemon session for each viewer is also capped at read-only permissions.

## Using it

- **Open a room:** in an agent, open the Command Center and choose "Open room…". Pick a fork (default) or share live.
  - A fork is a new agent seeded with the user and assistant messages of the current conversation (no tool output). It runs without Paseo's own control tools, so a viewer-facing agent cannot drive your other agents. Starting a fork runs one turn on your provider account.
  - Share live shares the agent itself, read-only.
- **Invite:** from Rooms in the sidebar, create an invite and copy the code. It works once and expires after 30 minutes.
- **Join:** on the member's side, paste the code under Rooms → "Join with an invite code". The room appears as a host named after the room.
- **Revoke:** revoking a member cuts their live view immediately. Access grants expire after 24 hours by default and the member's daemon renews them automatically while they remain a member.
- Agents shared in a room show a "Room · N connected" pill in the composer.

## Requirements and limits

- Paseo 0.13.2 or later on both the owner's and the member's daemon and app. Plugins must be enabled on both daemons.
- The owner's daemon must be online for members to see the room. Room traffic goes through the Paseo relay (relay.paseo.sh) end to end encrypted; the owner's daemon does not need its own relay pairing.
- Members only watch in this version. Shared agents run as your OS user, so member input can never prompt them; steering will need sandboxed agents.
- An access grant admits every client of the member's daemon: their app, their paired devices and their own agents can all read the shared agent. Share with people whose machines you would trust with what the agent shows.
- After a member leaves or is revoked, their app may keep a stale host entry until they remove it; Paseo does not prune routed hosts yet.
- Fork lanes are available only for providers verified to run without Paseo's control tools (currently Claude). Other installed plugins are trusted: if one re-adds tools to a fork, the room is refused.
- Members see the shared workspace's name and branch, but not its paths, git remote, pull requests, scripts or the activity of your other agents.
- The plugin stores its keys and room state under the daemon's home in `plugin-data/rooms` with owner-only file permissions. Like every Paseo server plugin, it runs with full owner permissions on the daemon, including managing connected hosts.
