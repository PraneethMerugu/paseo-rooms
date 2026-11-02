# Security policy

Rooms shares a live agent across machines, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Report privately through GitHub: on [github.com/PraneethMerugu/paseo-rooms](https://github.com/PraneethMerugu/paseo-rooms), open **Security → Report a vulnerability** (GitHub private vulnerability reporting). Please do not open a public issue, pull request or discussion for a vulnerability.

Include what you can of:

- the affected version or commit, the Paseo version and the operating system;
- what an attacker needs (an invite code, a member device, a position on the network, code on the victim's machine);
- steps to reproduce, or a proof of concept against your own test daemons;
- the impact you expect.

We aim to acknowledge reports within a week. This is a small project, so fixes may take longer. We will keep you informed and credit you in the release notes unless you prefer otherwise.

Test only against daemons and rooms you own. Do not test against other people's rooms or against the public Paseo relay beyond normal use.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x (identity v2, pilot, Linux) | Yes |
| 0.1.x | No. Its rooms are closed on upgrade to 0.2. |

## Scope

In scope, for example:

- a member or an invite holder seeing or doing more than watching the one shared agent (prompting, approving, reading other agents, paths or files, reaching the owner's daemon beyond the allowlist);
- a removed member, a revoked device or an expired grant keeping access;
- joining a room without the owner's admission, or defeating the six-digit comparison;
- forging, reordering or hiding room log entries without members noticing;
- reading room content (lanes, chat) from the relay or the network;
- keys, grants or invite codes written to logs or to files other accounts can read.

Out of scope:

- **Malware or other software running as the same OS user** as the daemon, including other Paseo plugins. Plugins run with the owner's full permissions, and same-user processes can read the user's files and keyring. Rooms does not claim to defend against them.
- Clients of a member's own daemon (their app, paired devices and agents) reading a lane the member can view. This is documented behaviour.
- Bugs in Paseo itself, the Paseo relay or the operating system keyring. Report those to their maintainers; we are glad to help coordinate if Rooms is affected.
- Platforms marked untested (macOS, Windows) behaving differently from Linux, unless the difference is a security issue.
- Denial of service that needs the owner's own credentials.

## Design and past reviews

The threat model, specifications and earlier review findings are in [`docs/`](docs/README.md), in particular [`docs/security/`](docs/security/).
