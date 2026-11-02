# Paseo Rooms documentation

For installing and using Rooms, start with the [README](../README.md). This folder holds the design and the security reviews behind it.

**These are working records.** Each document carries its own date and status. Reviews describe the code as it was when they were written, so they name files that were later renamed or removed (for example the 0.1 files `shared/control.ts` or `server/grants.ts`, and `plugin/…` paths from the development repository, where the plugin lived in a `plugin/` folder). The design was also informed by research notes that are not published; references to them say "design research, not published", and paths written `<spikes>/…` point into that unpublished material. "The user" in decision records is the project owner.

## Design (`design/`)

| Document | What |
|---|---|
| [Identity v2 specifications](design/specs/identity-v2/README.md) | The current protocol: identity model, enrollment, grants, room log, MLS integration, keys, rotation and recovery, encoding and signatures, migration, with test vectors. Start here. |
| [Room Profile v1](design/specs/room-profile-v1.md) | The message and field tables that decide what a member's app may send and receive |
| [Data model](design/specs/data-model.md) | 0.1 (Milestone 1) entities and files |
| [Rooms control protocol](design/specs/rooms-control-protocol.md) | 0.1 enrollment and grant protocol, replaced by identity v2 |
| [Implementation plan, identity v2](design/implementation-plan-identity-v2.md) | Milestones I-1 to I-17, spikes, follow-ups and decisions |
| [Usability roadmap](design/usability-roadmap.md) | State by area and the milestones toward v0.2 |
| [Milestone 1 results](design/m1-results.md) | What 0.1 delivered and how it was tested |

## Security (`security/`)

| Document | What |
|---|---|
| [Hardening plan](security/hardening-plan.md) | Merged findings of the 0.1 reviews and every decision round (1 to 11) |
| [Protocol review](security/protocol-review.md) | Design review of 0.1 (findings P-1 to P-29) |
| [Code review](security/code-review.md) | Code review of 0.1 (findings C-1 to C-16) and the Room Profile audit |
| [Fixes B to D](security/fixes-b-d.md) | Fixes for hardening plan sections B to D |
| [Identity v2 review](security/identity-v2-review.md) and [re-review](security/identity-v2-rereview.md) | Independent reviews of the identity v2 specifications |
| [Cross-platform audit](security/cross-platform-audit.md) | macOS, Windows and Linux differences (X-1 to X-15) |
| [Cut-over review](security/cutover-review.md) | Review of the switch from 0.1 to identity v2 |

Each review states what it ran and what it only read. To report a new issue, see [SECURITY.md](../SECURITY.md).
