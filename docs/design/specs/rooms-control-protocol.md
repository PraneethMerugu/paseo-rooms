# Rooms control protocol v1

- **Superseded (2026-11-01):** by `identity-v2/` (implementation plan I-15; `identity-v2/migration.md` section 5). The code this document describes was deleted at the identity v2 cut-over and is kept in git at tag `m1-baseline`. Kept for reference only.
- **Status:** implemented in Milestone 1 (removed at the cut-over) (`server/gateway/control-server.ts`, `server/member/control-client.ts`, schemas in `shared/control.ts`). Not yet externally reviewed.
- **Scope:** enrollment and grant lifecycle between a member plugin and the lane endpoint of a gateway with an embedded host. It replaces, for M1 only, the member-to-host channel of the Rooms architecture document (not published) section 8.2.

## 1. Transport

- The member opens a Paseo relay **client** socket to the lane's `serverId` (relay protocol v2), then a secure channel with `openClientSecureChannel` and `minimumMode: "protected"`. This is Noise `NK_25519_ChaChaPoly_SHA256` to the lane's static X25519 key, pinned from the invite code. Legacy mode is refused by both sides.
- The lane endpoint serves Paseo host links and control channels on the same relay endpoint. The **first application frame** decides the kind:
  - `{"type":"hello", …}`: a Paseo connected-hosts link (see `room-profile-v1.md`).
  - `{"type":"rooms.control.hello", …}`: this protocol.
  - Anything else, or nothing within 15 s: the connection is closed.
- One operation per channel. The gateway closes the channel about 200 ms after its last frame.
- All frames are JSON text. Unknown fields are stripped by the zod schemas; an invalid frame ends the channel with `bad_frame`.

## 2. Frames

| Dir | Frame | Fields |
|---|---|---|
| M→G | `rooms.control.hello` | `v: 1`, `op: "enroll" \| "renew" \| "status" \| "leave"`, `laneId`, `devicePublicKey` (raw Ed25519, base64url) |
| G→M | `rooms.control.challenge` | `v: 1`, `nonce` (32 random bytes, base64url), `laneServerId`, `hostKeyId` |
| M→G | `rooms.control.proof` | `v: 1`, `sig` (Ed25519, base64url), `token` (enroll only), `label` (enroll), `daemonServerId` (enroll, informational) |
| G→M | `rooms.control.result` | `v: 1`, `op`, `room {roomId, roomName, laneId, laneLabel}`, `member {id, label, role, status}`, `grant` + `claims` (enroll, renew), `activeRoutes` |
| G→M | `rooms.control.error` | `v: 1`, `code`, `message` (≤ 200 chars, no secrets) |

Error codes: `bad_frame`, `unsupported_version`, `unknown_lane`, `lane_closed`, `bad_signature`, `invalid_token`, `token_expired`, `token_used`, `not_member`, `revoked`, `busy` (reserved), `internal`.

## 3. Mutual authentication

- **Gateway to member:** the Noise NK handshake proves possession of the lane static key pinned in the invite. In addition the member checks that the challenge's `laneServerId` and `hostKeyId` equal the pinned values, and verifies every returned grant against the pinned host key (`verifyGrant`) and its own device key id (`claims.dev`).
- **Member to gateway:** the member signs the canonical transcript with its device key:

  ```json
  {"ctx":"paseo-rooms/control/v1","daemonServerId":…,"devicePublicKey":…,"hostKeyId":…,
   "label":…,"laneId":…,"laneServerId":…,"nonce":…,"op":…,"tokenHash":…}
  ```

  Serialization is `canonicalJson` (sorted keys, no whitespace, `undefined` omitted). `tokenHash` is the hex SHA-256 of the enrollment token for `enroll`, otherwise `null`. Binding the nonce, lane, host key and token hash prevents replay to another lane, another host or another invite.
- **Enrollment** additionally requires the one-time token. The gateway stores only its SHA-256 and compares in constant time.

## 4. Operations

| op | Gateway checks | Effect | Room log |
|---|---|---|---|
| `enroll` | Lane open; token matches an invite of this lane; invite unused, unrevoked, unexpired; signature | Creates a member (`role: watch`, `grantTtlSeconds` from the invite), marks the invite used, issues a grant. A device that re-enrolls on the same lane ends its earlier active membership. | `member.joined` |
| `renew` | Active member for this device on this lane; signature | Issues a new grant and revokes the previous grant id (live links using it are cut). | `grant.renewed` |
| `status` | Same as renew | Returns `activeRoutes` for this member, so the member rotates only when idle. | none |
| `leave` | Same as renew | Member status `left`, latest grant revoked, live links cut. | `member.left` |

Failed tokens count against every open invite of the lane. After 5 failures an invite is burned (`invite.status = "burned"`).

## 5. Grant use on the host link

- The member plugin builds `relay://…&security=protected&password=<grant>` (`serializeRelayConnectionUri`, with `ssl=true` for TLS relays) and registers it with `context.paseo.hosts.add` (source key = `laneId`). The grant is stored only in the member daemon's `hosts.json` (0600).
- The lane endpoint checks the grant on the link hello, on every `hosts.link.open` and on every routed hello: signature against the host key, `iss`, `aud` = lane serverId, `laneId`, `iat`, `exp`, member active, `dev` equals the member's device key id, grant id not revoked.
- Revocation, leave, renewal and lane close are **pushed** in process from the host store to the lane endpoint, which cuts the affected links and routes before the owner's RPC returns. Each link also has a timer at its grant's `exp`.

## 6. Member rotation policy

- Rotate at half of the grant lifetime if `status` reports `activeRoutes == 0`. Otherwise retry at a quarter of the remaining lifetime (at least 5 s).
- On `authentication_failed` (or other auth errors) in `hosts.observe`, rotate at once (at most every 15 s).
- On `revoked`, `not_member`, `lane_closed` or `unknown_lane`: remove the host registration and mark the room `revoked` or `left`.
- Each rotation calls `hosts.update`, which restarts the link and drops routed sessions (Paseo 0.13.2 behaviour, routed-lane spike G2).

## 7. Known limits

1. The grant is a bearer token on the Paseo host link. Paseo's link hello has no proof-of-possession field, so device binding is enforced only on this control channel (enroll, renew).
2. The control channel identifies the member daemon, not the person or app session (routed-lane spike, deviation 2).
3. No rate limit per source beyond invite burning. The relay hides member IPs from the gateway, so per-IP limits are not possible.
4. Clock skew: `iat` may be up to 300 s in the future. `exp` is enforced on the gateway clock.
5. The transcript does not include the Noise handshake hash, because `@getpaseo/relay` 0.13.2 does not expose it. Channel binding relies on the pinned lane key.
