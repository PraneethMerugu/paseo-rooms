# Lane grants v2

- **Status:** proposed specification, not implemented.
- **Resolves:** P-9, P-12/C-9, P-13, P-24, P-22 for grants; documents D3 and P-21.
- **Formats:** `signatures-and-encoding.md`. Vector: `vectors/vectors.json` → `grant`.
- **Revised** 2026-10-29 after the independent review (`README.md` section 10): fixed 12 h lifetime, role check, role downgrades revoke, standalone lane endpoints fail closed, per-lane project names. Revised again after the re-review (decisions round 4): log lock ownership check and atomic takeover (R-6), persisted held time for pruning (R-11).

## 1. Where proof of possession applies, and where bearer remains

| Path | Credential | Kind |
|---|---|---|
| Member device ↔ room endpoint (enrollment, sessions, grant issue, MLS delivery) | device DH key in Noise IK, plus device signatures where stated | **proof of possession** on every session |
| Member daemon ↔ lane endpoint (Paseo connected-host link, Room Profile) | lane grant in the relay connection password | **bearer** |

The second path is Paseo's own host-link protocol. Its hello has no field for proof of possession or channel binding (M1 deviation D3), and the plugin cannot change the member daemon's side of that link. v2 therefore keeps a bearer grant there and limits it:

- it is issued only over a proof-of-possession session, to a device in the admin-signed roster;
- it names one lane, one member and one device (full key id);
- the lane endpoint accepts only the **current** grant id for that device and lane (allowlist);
- at most one live link per (device, lane), with theft detection (section 6);
- lifetime 12 hours (an org policy may shorten it, never lengthen it), forced rotation at 75 % of lifetime regardless of activity.

The upstream request for proof of possession on connected-host links stands (`README.md` section 6). When it exists, the `cnf` field reserved in section 2 carries the device key binding.

## 2. Format

```
GrantClaims = {
  v: 2, typ: "lane-grant",
  roomId, laneId,
  aud: <lane endpoint serverId, "rle_" + 32 b64u>,
  sub: <memberId>,
  dev: <kid of the device signing key, 43 chars>,
  role, gid: "g_<32 hex>",
  iat: <unix s>, exp: <unix s>,
  hostKid: <kid of the issuing host key>
}
token = "prg2." + b64u(RJCS(GrantClaims)) + "." + b64u(Sign(hostKey, "lane-grant", RJCS(GrantClaims)))
```

- About 650 characters. Maximum accepted length 1024.
- No optional fields in v2. `cnf` (proof-of-possession binding) is reserved for a later version and must be absent.
- The token is a secret. It is never logged, and it is stored only in the member daemon's `hosts.json` (written by Paseo, 0600) and in memory.

## 3. Issuance

```
M→H { t:"grant.issue", id, laneId }
H→M { t:"grant.issue.ok", re, grant: <token>, claims: GrantClaims, serverTime: <unix ms> }
```

The host checks, on the authenticated session:

1. the device (`rs`) is active in the current roster;
2. its member has `laneId` in `lanes` and the lane is open;
3. rate limit: at most 6 issues per (device, lane) per hour, plus 1 per 15 s burst. Above that: `busy`.

Then, in this order:

1. build claims with a fresh `gid`, the member's current roster `role`, `iat = now`, `exp = now + policy.grantTtl` (section 5);
2. set `current[(deviceId, laneId)] = {gid, exp, iat}` in memory and **push** to the lane endpoint, which cuts links that present the previous `gid` (they are now superseded);
3. persist the allowlist (section 7.3);
4. append `grant.issued {memberId, deviceId, laneId, gid, exp}` (host statement);
5. reply.

If step 3 fails, the reply is `internal` and the new grant is not delivered. The previous grant was already cut in step 2, so the member is offline on that lane until a retry succeeds. That is the safe failure.

## 4. Verification on the lane endpoint

On the link hello, every `hosts.link.open` and every routed hello (as in M1), in this order:

1. length ≤ 1024; exactly three `.`-separated parts; prefix `prg2`; strict base64url; strict RJCS; schema.
2. `hostKid` is a host key in the authority state whose validity window covers `iat` and that is not revoked (`keys-rotation-recovery.md` section 3). Verify the signature with **that stored key**.
3. `roomId`, `laneId` and `aud` equal this lane's.
4. `iat ≤ now + 120 s` and `exp > now` (lane endpoint clock; section 9).
5. `sub` is an active member, `dev` is an active device of `sub` (compare the full stored key's kid), `laneId` is in the member's `lanes`, and `role` equals the member's current role in the roster (S-9).
6. `gid == current[(deviceId, laneId)].gid`. **This allowlist is the primary revocation check** (P-12). A validly signed grant with any other `gid` fails, including one forged with a stolen host key but without the host state.
7. Link policy (section 6.1).

All failures are reported to the link as Paseo's normal authentication failure. The endpoint logs the reason locally (never the token).

## 5. Lifetime and rotation

| Setting | Default | Range |
|---|---|---|
| `grantTtl` | 12 h (`policy.grantTtl = 43200`) | Fixed at 12 h (decision round 3). An org policy may shorten it to between 1 h and 12 h; nothing can lengthen it, and there is no per-invite value. Values below 1 h only with `PASEO_ROOMS_DEV_SHORT_GRANTS=1` on the host, for tests. |
| Idle rotation point | 50 % of lifetime | |
| Forced rotation point | 75 % of lifetime | |
| Deferral retry | 1/8 of lifetime, at least 60 s | |

**Member schedule (P-24).** The member never compares `iat` or `exp` with its own wall clock. On receiving a grant at local monotonic time `t0` it computes `L = exp - iat` and schedules:

- `t0 + 0.5 L`: idle rotation attempt;
- `t0 + 0.75 L`: forced rotation;
- `t0 + L - 60 s`: last resort, forced.

**Idle rotation rule.** At an idle attempt the member calls `grant.status` (section 6.2) and defers only if **all** hold:

- the lane reports exactly one live link for this device and lane;
- the member daemon's own registration for that lane is `online` in `hosts.observe`;
- the lane-reported link start time is within 30 s of the time the member saw its registration become online (both converted to the member's clock with `serverTime`).

Otherwise it rotates now. A link the member cannot account for never defers rotation (P-9).

Lifetime and schedule were decided on 2026-10-29 (`README.md` section 7): 12 h grants, rotation preferably when idle, forced at 75 %; the lifetime is fixed, and only an org policy can shorten it (round 3).

**Forced rotation** happens at 75 % regardless of routes. It costs a link restart (routes drop, views reconnect in about 3 s; M1 measured). Twelve-hour grants mean at most one forced interruption every 9 hours of continuous viewing.

**After restart** the member re-arms timers from the stored `t0`-relative schedule, using the wall clock only to estimate elapsed time; if the estimate is uncertain (clock jumped backwards), it rotates at once (C-12).

## 6. Stolen grants (P-9)

### 6.1 One link per device and lane

The lane endpoint keeps at most one accepted link per (deviceId, laneId).

When a second link presents a grant that passes steps 1 to 6 while a link for the same (device, lane) is live:

1. The endpoint sends a Paseo-level ping on the existing link and waits up to 5 s.
2. **Existing link does not answer:** it is treated as dead (the member's own reconnect after a network change). It is closed, the new link is accepted.
3. **Existing link answers:** two live holders of the same grant exist. The endpoint closes **both** links, removes `current[(deviceId, laneId)]` (so the gid stops working everywhere), and the host appends `grant.suspected_theft {memberId, deviceId, laneId, gid}`. The owner sees a notice. The member's device gets an event on its room session and re-issues through proof of possession; a thief cannot.

### 6.2 Status reports with link identity

```
M→H { t:"grant.status", id, laneId }
H→M { t:"grant.status.ok", re, gid, links: [ { since: <unix ms>, routes: <n> } ], serverTime }
```

`links` has at most one element under 6.1. The member uses `since` for the comparison in section 5.

### 6.3 Member-side report

If the member sees a live link it cannot account for (registration offline while the lane reports a link, or `since` far from its own connection time), it sends:

```
M→H { t:"grant.report", id, laneId, gid, reason: "unaccounted_link" }
```

The host treats it like 6.1 step 3 (cut, unlist, log `grant.suspected_theft` with `reportedBy: "member"`), then the member issues a new grant.

### 6.4 Repeated theft

Two `grant.suspected_theft` events for the same device within 7 days mean the device's `hosts.json` (or the device itself) is being read by someone else. The owner and the member are told to treat it as a **device compromise** (`keys-rotation-recovery.md` section 6.3): remove the device and re-link from a clean one.

## 7. Revocation: enforce, then persist

### 7.1 Ordering

Every operation that reduces access (member removed or left, device removed, lane access removed, **role lowered**, lane closed, grant superseded or suspected stolen, host key revoked) runs in this order. For a lowered role, step 1 clears `current[(device, lane)]` for every device of the member, and the member's devices are told to reissue at the new role (S-9).

1. **Decide** in memory: update roster, `current` allowlist and status.
2. **Enforce** synchronously: push to every affected lane endpoint and room session. Links and routes are cut, sessions closed, before anything touches disk. This step does no I/O and cannot fail on disk errors.
3. **Persist** state (section 7.3).
4. **Log**: append the statement or entry with fsync (`room-log-v2.md` section 8).
5. **MLS** (from M2): queue the Remove commit (`mls-integration.md` section 6.3).
6. **Return** to the caller.

### 7.2 Failure handling

- If step 3 or 4 fails, the in-memory state stays revoked (access remains cut while the process runs). The RPC returns `persist_failed`, not success. The Rooms UI shows a persistent error: "Access was cut, but the change could not be saved. It will be lost if the daemon restarts. Free disk space or fix permissions." The host retries every 10 s and clears the error on success.
- If the daemon restarts before a successful persist, the revocation is lost and the member's next grant check passes again. The owner saw `persist_failed` and the persistent error, so the loss is visible. A revocation the owner saw succeed is durable (section 7.3).
- Enforcement in step 2 never waits for the member: the member daemon learns of revocation from its session (`access_ended`) or from the link failure (Paseo reports it 5 to 7 s later, M1 open issue 2).
- **Unreachable lane endpoints** (S-23). With the embedded host, the lane endpoints share the host's process, so step 2 cannot miss them. A standalone lane gateway (later) keeps a connection to the host. When it (re)connects, it fetches the full allowlist and the revocation list before it accepts any link, and it accepts no link while it has none. After 60 s without contact with the host it stops accepting new links and closes existing ones (fail closed), until it has fetched the current allowlist again. So a push that missed a disconnected gateway cannot leave a revoked grant usable until its `exp`.

### 7.3 Durable writes

`writePrivateFile` gains durability (P-13). The steps are the same on every OS; the primitives differ.

1. Write a temporary file in the **same directory** as the target (a rename across volumes is not atomic on any OS), created with owner-only protection (`identity-model.md` section 7.8) and exclusive-create (`wx`) so a stale temporary file is never reused.
2. Flush the temporary file: `fsync` (Linux, WSL); `fsync`, which libuv maps to `F_FULLFSYNC` on macOS (to verify on the pinned runtime, because plain `fsync` on macOS does not flush the drive cache); `FlushFileBuffers` on Windows (Node's `fs.fsync`).
3. Replace the target: `rename` (atomic replace on POSIX). On Windows Node's `fs.rename` uses `MoveFileEx` with replace-existing. It fails with `EPERM`, `EACCES` or `EBUSY` while another process holds the target open without delete sharing (commonly antivirus or backup tools). The writer retries with backoff for up to 2 s, then reports `persist_failed` (section 7.2). It never deletes the target first, because a crash between delete and rename would lose the file.
4. Flush the directory: `fsync` on a directory handle on Linux and macOS. Windows has no directory flush through Node; the step is skipped there, so a power loss right after a rename may lose the rename. The Rooms UI's About panel states this weaker guarantee on Windows.

**Appends** to log files: one writer per room log, enforced by a lock file `log/writer.lock` created with exclusive-create (`wx`) and holding the daemon's process id and a random 128-bit instance id. This needs no per-OS way to read another process's start time, and it does not trust the process id, which can be reused (inside containers in particular). No `flock`, which Windows lacks.

1. **Heartbeat.** The holder rewrites the lock file's modification time every 10 s.
2. **Ownership check before every append** (re-review finding R-6). Before it writes an entry or body, the holder reads the lock file and checks that it still holds its own instance id. On a mismatch, or if the file is missing, it has lost the lock: it stops serving the room at once (closes its room sessions, appends nothing), and raises `log_lock_lost` in the owner UI. It never re-creates the lock itself. This matters after laptop sleep, a VM or WSL suspend, `SIGSTOP` or a debugger pause longer than the stale time: without the check, the woken holder and the new holder would both sign an entry at the same `seq`, which members would rightly report as a `fork` with proof, and the files would interleave.
3. **Staleness.** A lock is stale when its modification time is more than 60 s old. A daemon that finds a stale lock waits **30 s** (three heartbeat intervals, a margin for timer jitter and for modification times that propagate late on Docker bind mounts and WSL `/mnt/c`) and checks that the time did not move.
4. **Atomic takeover.** It then renames the stale lock to `writer.lock.stale.<own instance id>`. Only one rename of the same source can succeed, so of two waiters only one proceeds; the other sees `ENOENT` and starts again from step 3. The winner creates a new lock with `wx`, reads it back, checks its own instance id, reloads the log from disk (the torn-line rules of `room-log-v2.md` section 8.1 apply), and only then serves the room. It deletes the renamed stale file afterwards.
5. **Clean shutdown** deletes the lock after the last append is flushed, so an ordinary restart does not wait 90 s.

Residual: a holder that stalls between its ownership check and its `write` for more than 90 s (stale time plus wait) can still write one line after a takeover. That needs a single stall inside two adjacent calls; members would detect the result as a `fork`. This is accepted.

Each append writes one complete line in a single `write` call on a handle opened in append mode, then flushes as in step 2 of the durable write above (and the directory as in its step 4 when the file was created). On Windows, append mode is emulated by libuv; the single-writer lock makes cross-process atomicity unnecessary.

**Platform status:** Linux behaviour is what M1 uses. macOS `F_FULLFSYNC`, the Windows rename retry and the Windows append path are **untested**.

## 8. Revocation list and pruning

With the allowlist of section 4 step 6, a pruned or forgotten denylist entry can no longer revive a grant. The denylist (`revokedGrants`) is kept for audit and for the theft check of 6.1, with these pruning rules (P-12, C-9):

- An entry `{gid, exp, heldMs}` is pruned only when `exp + 10 min < now` on the wall clock **and** the entry has been held for at least 24 h of process monotonic time in total, across restarts. `heldMs` is that total: the process adds the monotonic time elapsed since its last save whenever it persists the list, and at least once an hour. A wall-clock jump forward therefore cannot prune an entry early, and no boot identifier is needed (a boot time derived from the wall clock would itself move with a clock step). Persisting `heldMs` fixes the first rule's flaw that a daemon restarted daily, or a laptop that sleeps often, never pruned (re-review finding R-11).
- Backstop: an entry is also pruned when the wall clock is more than 30 days past `exp`, whatever `heldMs` says. A forward clock step of 30 days could prune early, but the allowlist (section 4 step 6), not this list, decides whether a grant is accepted, so the only cost is audit history.
- Each member device also has `notBefore[(deviceId, laneId)] = iat` of the current grant. A grant with an older `iat` fails even if its `gid` were somehow listed. This is defence in depth against a restored old state file.
- The list is a `Set` keyed by `gid` (P-17 linear scan).

## 9. Clock skew

| Who checks | Rule |
|---|---|
| Lane endpoint (embedded host: same clock as the issuer) | `exp` strictly on its clock; `iat` up to 120 s in the future accepted |
| Lane endpoint on another node (standalone host, later) | the same, plus the host includes `serverTime` in pushes so the gateway can warn when its clock differs by more than 60 s |
| Member | never checks `exp` against its own clock; schedules from relative lifetimes (section 5); displays times converted with `serverTime` |
| Host statements | `ts` is display only |

A member whose clock is far off still rotates correctly. A gateway whose clock is far off cuts or accepts links early or late; the 120 s `iat` window and the warning bound the effect.

## 10. What a grant authorizes (P-21, documented)

A grant admits the **member daemon's link**. Every client of that daemon that can open routes through connected hosts can then read the lane: the member's own Paseo app sessions, paired devices with routed access, and the member's own agents through Paseo's MCP routed-host tools. A prompt-injected agent on the member's daemon can therefore read lane content and exfiltrate it.

This is accepted by design (the member's daemon is the member's trust boundary). The member UI states it on the join screen: "Anyone and anything that can use your Paseo daemon, including your agents, can see the lanes of this room." The upstream request for per-origin route permissions stands.

## 11. Limits

| Limit | Value |
|---|---|
| Links per (device, lane) | 1 (section 6.1) |
| Routes per link | 32 (M1: 128) |
| Routes per lane | 256 |
| Failed link attempts per lane endpoint | token bucket 30 per minute. Only failed attempts consume it. When it is empty the endpoint still runs the cheap checks of section 4 and accepts a link whose `gid` is current, and refuses every other attempt. So a removed member who floods the endpoint cannot block current members (S-21) |
| `grant.issue` per (device, lane) | 6 per hour, 1 per 15 s |
| `grant.status` per device | 60 per hour |

Other resource limits (frame sizes, queues) are hardening item B3 and not repeated here.

## 12. Open questions

Resolved and moved to `README.md` section 7 (decisions log): former Q1 (12 h grants, idle-preferred rotation, forced at 75 %). Question numbers are kept stable.

- **Q2.** The 5 s ping in 6.1 needs a Paseo-level ping on a connected-host link. Confirm that the 0.13.2 link protocol has one the destination side can send; otherwise use the relay's socket liveness only (weaker: a half-open socket looks alive until TCP times out).
- **Q3.** Should a suspected theft also rotate the lane endpoint key (evicting everyone who ever saw the lane offer)? Proposed: only on the second event (6.4), because rotation disrupts every member of the lane.

## 13. What viewers see: errors and project names

Decided on 2026-10-29 (HARDENING-PLAN, decisions round 2). This section is the source of truth for both rules in v2. The field-level mapping that implements them for Paseo 0.13.2 is in `../room-profile-v1.md` (fields `projectName` and related, `lastError`, `rpc_error.error`, `turn_failed`, timeline `error` items) and `profile/fields.csv`.

Terms: a **viewer** is anyone who reaches a lane through a lane grant, including other admins of the room. The **lane owner** is the person whose gateway daemon serves the lane, using that daemon's own app sessions.

### 13.1 Error text

| Audience | What they get |
|---|---|
| Viewer | A fixed generic text, "The agent hit an error. The lane owner can see the details.", plus an error reference: 8 lowercase base32 characters, random per error, which matches the owner's log entry. No original message, stack, path, provider name, diagnostic or error code from the upstream daemon. |
| Lane owner | The full original error, unchanged, through the gateway's local plugin RPC (`rooms.lane.errors`). Kept in memory, owner-only, per lane, at most 50 entries, deduplicated, each with its reference. |

Rules:

- Full error text never crosses a lane endpoint or a room session, for any role. An admin on another machine is a viewer of that lane.
- The rule applies to every error-bearing field, live and in history, including errors inside agent snapshots and timelines.
- Rooms protocol errors that the viewer's own daemon needs to act on (for example `access_ended`, `not_permitted`) are not upstream error text. They keep their codes from `enrollment-v2.md` section 10 and this document.
- The error reference is new in v2 (M1 shows only the generic text). It lets a viewer report "error k3x9…" to the owner without seeing the content.

### 13.2 Project display names

Decided in round 3 (2026-10-29, review finding S-16): only the lane owner can show project names, and only for their own lanes. Admins can force names hidden.

- **Default: hidden from viewers.** Project names, project display or custom names, and workspace names or titles equal to the project or project folder name are replaced by the neutral label `<room name> · <lane label>`. Path basenames become `/room/folder-<keyed hash>`. That replacement is a fixed, logical string in POSIX form whatever the owner's OS; the redaction also matches Windows paths (drive letters and `\` separators) on the owner's side.
- **Lane owner's choice, per lane.** Each lane has a `showNames` flag in the authority state, `false` when the lane is created. Only the lane's `owner` (the member named in `lane.created`, whose gateway serves the lane) can change it, with `lane.names.changed {laneId, show, ver}` signed by one of that member's devices (`ver`: `room-log-v2.md` section 4.0). Another admin cannot reveal the names of a lane they do not own. The change is shown to every member as a security-relevant event (`room-log-v2.md` section 4.6).
- **Admins can force hiding.** Room policy `projectNames` is `"lane-owner"` (default) or `"hidden"`. An admin sets `"hidden"` with `room.policy.changed`; then names are hidden on every lane, whatever `showNames` says, and `lane.names.changed` with `show: true` is rejected. Org policy can fix `"hidden"`.
- The lane owner's gateway applies the effective value (`policy.projectNames == "lane-owner" && lanes[laneId].showNames`). Turning names on applies to open routes immediately (fresh agent and workspace updates). Turning them off hides names in later updates but **cannot recall names already shown**; the confirmation dialog says so.
- The lane owner always sees real names in their own app, because their app talks to their daemon directly, not through the lane endpoint.
- Paths, git remotes, PR data and other fields stay redacted regardless of this setting (hardening item B2).
- M1 kept a room-wide setting in gateway state and logged it as `room.policy.changed {setting, value}`. v2 does not import it (`migration.md`).
