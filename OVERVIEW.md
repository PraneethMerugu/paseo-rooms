Rooms lets you share an agent, read-only, with other people who run Paseo. You create a room, share an agent in it, and invite people. A person joins by comparing a six-digit code with you by voice; after that the agent appears in their Paseo app as a separate host they can watch live: its workspace, its timeline and its turns as they stream. Nothing else on your machine is visible to them, and you can remove them at any time.

## How it works

Your daemon hosts the room and keeps its signed log: who was admitted, which devices they use, which agents are shared, every change of access. Each room has its own keys, held on your daemon in the system keyring where one is available. Each member's daemon keeps its own copy of the log and checks every entry, so a member notices if the host shows them something inconsistent.

Each shared agent (a lane) gets its own endpoint on the Paseo relay, using the relay's protected (end-to-end encrypted) mode only. A member's daemon asks for a short access grant over its room session, registers the lane as a connected host, and renews the grant on its own. The member's app reaches the lane through their own daemon, so the grant never enters the app.

Everything a member's app sends is checked against a fixed allowlist bound to the one shared agent. Sending prompts, approving, archiving, terminals, files, settings and other hosts are refused. The owner's daemon session for each viewer is also capped at read-only permissions.

## Using it

- **Create a room:** Rooms in the sidebar → "Create room". Saving the recovery key it offers lets you recover the room if your admin key is lost or stolen.
- **Share an agent:** in an agent, open the Command Center and choose "Open room…", pick the room and confirm. The agent itself is shared, read-only, as it runs; Rooms does not copy or fork it.
- **Invite:** in the room's card, create an invite and send the code. It works once and expires after 30 minutes unless you choose otherwise.
- **Join:** the member pastes the code under Rooms → "Join with an invite code". Both of you then see six digits: compare them by voice or video, and the member presses "Codes match". You press "Admit" only when the digits match.
- **More devices:** a member links another device of their own from a device already in the room. The new device waits up to 72 hours before it is added automatically; any of their devices can stop it, and you can approve it earlier.
- **Remove:** removing a member cuts their live view immediately. Access grants last 12 hours at most and are renewed automatically while the member stays in the room.
- **Stop sharing an agent:** archive the agent; its lane closes at once.
- Agents shared in a room show a "Room · N connected" pill in the composer.

## Upgrading from the first version

Rooms from the first version of this plugin are closed on upgrade: their invite codes (starting with `prc1.`) no longer work, and members of those rooms lose access. Create a new room and invite people again. The old room data is moved to an archive folder; the Rooms screen offers to delete the old keys, which no longer work, and keeps the old room logs. Agents that were shared in old rooms stay on your daemon and are listed under "Agents from closed rooms".

## Requirements and limits

- Paseo 0.13.2 or later on both the owner's and the member's daemon and app. Plugins must be enabled on both daemons.
- The owner's daemon must be online for members to see the room. Room traffic goes through the Paseo relay (relay.paseo.sh) end to end encrypted; the owner's daemon does not need its own relay pairing. A member is asked before their daemon uses a relay it has not used before.
- Members only watch in this version. Shared agents run as your OS user, so member input can never prompt them; steering will need sandboxed agents.
- An access grant admits every client of the member's daemon: their app, their paired devices and their own agents can all read the shared agent. Share with people whose machines you would trust with what the agent shows.
- After a member is removed, their app may keep a stale host entry until they remove it; Paseo does not prune routed hosts yet.
- Members see the shared agent and its timeline. Project names and folder names are hidden by default and shown as the lane's name; paths, git remotes, pull requests, scripts and the activity of your other agents are never sent.
- Leaving a room and closing a lane from the Rooms screen are not available yet.
- Without a system keyring (some Linux setups, containers), keys are kept in a protected file instead, and the Rooms screen says so.
- The plugin stores its keys and room state under the daemon's home in `plugin-data/rooms` with owner-only file permissions. Like every Paseo server plugin, it runs with full owner permissions on the daemon, including managing connected hosts.
