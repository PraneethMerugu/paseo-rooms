# Data model, tokens and storage (v1)

- **Superseded (2026-11-01):** by `identity-v2/` (implementation plan I-15; `identity-v2/migration.md` section 5). The code this document describes was deleted at the identity v2 cut-over and is kept in git at tag `m1-baseline`. Kept for reference only.

Schemas are zod in `shared/schemas.ts` and `shared/control.ts`. Every persisted record has `v: 1`.

## 1. Entities (M1 subset of the Rooms architecture document (not published) section 3)

| Entity | Key fields | Notes |
|---|---|---|
| Room | `id room_<16 hex>`, `name`, `status active\|archived` | Lives on the owner's gateway (embedded host). |
| Lane | `id lane_<16 hex>`, `roomId`, `label`, `origin share\|fork`, `agentId`, `workspaceId`, `serverId lane_<32 b64url>`, `publicKeyB64`, `relay`, `status open\|closed` | One relay endpoint per lane. Fork lanes record `parentAgentId`, `contextItems`, `contextChars`. M1 lanes are not worktrees (see m1-results.md deviations). |
| Member | `id mem_<16 hex>`, `roomId`, `laneId`, `label`, `devicePublicKey`, `deviceKeyId`, `daemonServerId`, `role watch`, `grantTtlSeconds`, `status active\|revoked\|left` | One member per (lane, member daemon device key). |
| Invite | `id inv_<16 hex>`, `laneId`, `tokenHash`, `expiresAt`, `grantTtlSeconds`, `usedAt/usedBy`, `revokedAt`, `failedAttempts` | Token itself is never stored by the gateway. |
| Grant | claims below | Only the latest grant id per member is stored, never the token. |
| RoomEvent | below | Append-only log per room. |

## 2. Invite code

`prc1.` + base64url(JSON `InvitePayload`):

```json
{"v":1,"roomId":"room_…","roomName":"…","laneId":"lane_…","laneLabel":"…",
 "offer":{"serverId":"lane_…","publicKeyB64":"…","relay":{"endpoint":"relay.paseo.sh:443","useTls":true}},
 "host":{"keyId":"<16 hex>","publicKey":"<Ed25519 raw b64url>"},
 "inviteId":"inv_…","token":"<32 bytes b64url>","exp":<unix s>}
```

- Secret: anyone holding the code can enroll once before `exp`. Default lifetime 30 min (60 s to 24 h).
- About 660 characters.

## 3. Grant token

`prg1.<base64url(canonicalJson(claims))>.<base64url(Ed25519 signature over "prg1.<body>")>`

```json
{"v":1,"typ":"rooms.lane-grant","iss":"<host key id>","roomId":"room_…","laneId":"lane_…",
 "aud":"<lane serverId>","sub":"mem_…","dev":"<device key id>","role":"watch",
 "gid":"g_<16 hex>","iat":<unix s>,"exp":<unix s>}
```

- Lifetime fixed per invite: default 24 h, 20 s to 7 days (values under 1 h are for tests).
- Verified offline against the pinned host key, then against live membership and the revoked grant ids (section 5 of the control protocol).

## 4. Room event log

- File: `gateway/rooms/<roomId>/events.jsonl` (0600), one JSON object per line, append only.
- Event: `{v, roomId, seq, ts, type, actor, data, prev, hash, kid, sig}`.
  - `hash = sha256(canonicalJson({v, roomId, seq, ts, type, actor, data, prev}))`, hex.
  - `prev` is the previous event's `hash`, 64 zeros for `seq 0`.
  - `sig` is the host key's Ed25519 signature over the `hash` string; `kid` is the host key id.
- Types: `room.created`, `lane.created`, `lane.closed`, `invite.created`, `invite.revoked`, `member.joined`, `member.left`, `member.revoked`, `grant.renewed`, `room.policy.changed` (owner room setting; `data: {setting, value}`, e.g. `showProjectName`; added 2026-10-29, record format unchanged).
- `data` holds ids, roles, labels and timestamps only, never tokens.
- `verifyChain` detects edits, reordering, gaps, broken links and foreign signatures. It cannot detect truncation of the newest events without an external anchor (for example a member keeping the last hash it saw). M1 content is signed plaintext; MLS encryption is Milestone 2.

## 5. Storage

All under `$PASEO_HOME/plugin-data/rooms/`, directories 0700, files 0600, written atomically (temp file and rename).

| Path | Role | Contents | Secret |
|---|---|---|---|
| `gateway/host-key.json` | owner | Ed25519 host key (embedded host; signs grants and events) | yes |
| `gateway/state.json` | owner | rooms, lanes, lane X25519 secret keys, members, invites (token hashes), latest grant ids, revoked grant ids | yes (lane keys) |
| `gateway/rooms/<id>/events.jsonl` | owner | room log | no |
| `inert-mcp.cjs` | owner | inert MCP server script for room agents | no |
| `member/device.json` | member | Ed25519 device key of this member daemon | yes |
| `member/rooms.json` | member | joined rooms: lane offer, pinned host key, member id, grant id and expiry (no grant) | no |
| `<PASEO_HOME>/hosts.json` | member (written by Paseo) | connected-host registrations, including the current grant in the connection | yes |

`PASEO_HOME` comes from the daemon's environment (the daemon sets it for `--home`), defaulting to `~/.paseo`.
