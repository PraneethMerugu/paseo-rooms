Rooms lets you share a running agent, read-only, with other people who use Paseo. You create a room, share an agent in it and invite people. After a short voice or video check, the agent appears in their Paseo app as a separate host. They watch its timeline and turns live and can chat with the room. They cannot prompt it or see anything else on your machine, and you can remove them at any time.

## How it works

Your daemon hosts the room and keeps a signed log of who was admitted, which devices they use and what is shared. Each member's daemon keeps its own copy and checks every entry. A person joins with a one-time invite code. Both of you then compare six digits by voice or video, and you admit them only if the digits match.

Room traffic goes through the Paseo relay (relay.paseo.sh), end to end encrypted. A member's daemon holds a short access grant (12 hours at most) for each shared agent and renews it on its own. Everything a member's app sends is checked against a fixed allowlist for that one agent. Prompting, approving, archiving, terminals, files, settings and other agents are refused.

## Using it

- **Create a room:** Rooms in the sidebar, then "Create room". Save the recovery key it offers if you want to recover the room after losing your admin key.
- **Share an agent:** in the agent, open the Command Center, choose "Open room…", pick the room and press "Share".
- **Invite and join:** create an invite on the room card and send the code privately. The member pastes it under Rooms, joins, and you both compare the six digits.
- **Chat:** "Chat" on the room card. Messages are encrypted to the room's members and signed by the sending device.
- **Stop sharing:** close the lane in the Lanes tab, or archive the agent. Removing a member cuts their view at once. Members leave from the room card.

## Requirements and limits

- Pilot release for Linux. macOS and Windows are untested.
- Paseo 0.13.2 up to, not including, 0.14.0 on every daemon that uses Rooms, with plugins enabled. On other versions shared agents are paused; rooms and chat keep working.
- Your daemon must be online for members to see the room.
- Members only watch. Shared agents run as your OS user, so member input can never prompt them.
- A member's access covers everything on their daemon: their app, their paired devices and their own agents can read the shared agent. Share with people whose machines you would trust with what the agent shows.
- Project and folder names are hidden by default. Paths, git remotes, pull requests, scripts and your other agents are never sent.
- Keys are kept in the system keyring, or in an owner-only file when no keyring is available (the Rooms screen says so). Before removing the plugin, use "Leave all rooms and delete keys" on the Rooms screen.
- Rooms from version 0.1 are closed on upgrade. Create a new room and invite people again.
