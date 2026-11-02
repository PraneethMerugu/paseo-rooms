# Migration from M1 to identity v2

- **Status:** implemented on 2026-11-01 (plan I-15): `server/migration/v1.ts`; tests 1 and 2 in `test/unit/v2-migration.test.ts`, test 3 in `test/e2e-v2/migration-run.sh`. Section 5: the two v1 documents are marked superseded; the architecture edits and the m1-results.md item are left to I-17.
- **Decision:** **M1 rooms are invalidated, not migrated.** The plugin is a prototype. M1 rooms exist only on test daemons and the owner's own machines, and none of them carries data anyone depends on. Invalidation is acceptable at this stage and is far simpler and safer than a migration path.

## 1. Why not migrate

| M1 artifact | Why it cannot carry over |
|---|---|
| Memberships | Bound to whoever held the invite first, without SAS (P-1). Carrying them over would grandfather exactly the weakness v2 removes. They are also per lane, not per room (P-4). |
| Device key | One key per daemon, reused across rooms (P-14). v2 keys are per room. |
| Host key | Signed membership decisions implicitly (P-3). v2 needs an admin key that never signed v1 objects. |
| Grants | 64-bit `dev`, no domain separation (P-11, P-22). Format incompatible. |
| Room log | Host-signed plaintext with names, labels and agent ids (P-7, section 7 of `room-log-v2.md`). Re-signing it under v2 would assert facts v2 cannot verify. |
| Invites (`prc1.`) | No SAS, no genesis hash, relay not validated. |

A migration would need an owner-run re-confirmation of every member anyway, which is the same work as re-inviting.

## 2. What the v2 plugin does on first start

The steps run once, are idempotent, and are recorded in `plugin-data/rooms/migration.json`.

### 2.1 Detect

v1 data exists if any of these is present under `plugin-data/rooms/`: `gateway/state.json` with `v: 1`, `gateway/host-key.json`, `member/device.json`, `member/rooms.json`.

### 2.2 Owner side (gateway)

1. Do not start any v1 lane endpoint. v1 members' links then fail (their lane is unreachable), and their control requests time out.
2. Move `gateway/` to `v1-archive-<UTC date>/gateway/` by rename (same filesystem, atomic). On Windows the rename can fail with `EPERM`, `EACCES` or `EBUSY` while an antivirus or indexer holds a file; the plugin retries with backoff as for durable writes (`grants-v2.md` section 7.3), and if it still fails it leaves v1 data in place, starts no v1 endpoint, and retries at the next start. The v1 room logs (`rooms/<id>/events.jsonl`) stay there for reference.
3. Leave v1 lane agents alone. Forks created for v1 lanes keep their persisted inert MCP configuration and their `rooms.lane` / `rooms.room` labels. The Rooms UI lists them under "Agents from closed rooms" with an archive action. Nothing archives them automatically, because an owner may want to keep a fork's work.
4. The agent guard keeps refusing to give Paseo's MCP back to any agent labelled `rooms.lane`, so an old fork does not regain tools when resumed.

### 2.3 Member side

1. Read `member/rooms.json` before moving it, to know the v1 lane ids.
2. Once a `PaseoApi` is available, call `hosts.remove` for every registration whose source is `plugin:rooms` and whose `sourceKey` is a v1 lane id. Retry with backoff until it succeeds. The grant inside `hosts.json` disappears with the registration.
3. Move `member/` to `v1-archive-<UTC date>/member/`, with the same retry rule as 2.2 step 2.
4. Paseo's app may still list stale routed entries for those lanes (M1 open issue 1, upstream G3). The Rooms UI says so once.

### 2.4 Secrets left in the archive

The archive contains plaintext v1 secrets: the v1 host key, lane X25519 secret keys and the v1 device key. After 2.2 and 2.3 they no longer grant access to anything (lane endpoints are gone and registrations removed), but they are still key material.

The plugin does **not** delete them automatically (deleting user data needs the user's consent). It shows a notice in the Rooms UI: "Keys from the previous version of Rooms are stored unprotected in `<path>`. They no longer work. Delete them?" with a button that unlinks `host-key.json`, `state.json`, `device.json` from the archive and keeps the logs. The archive directory stays owner-only (`identity-model.md` section 7.8).

### 2.5 Owner notice

The Rooms screen shows once, on both kinds of daemon: "Rooms from the previous version were closed during the upgrade. Create a new room and send new invites. Invite codes starting with `prc1.` no longer work."

### 2.6 Revisions of the v2 formats before release

The v2 formats were revised twice on 2026-10-29, after the independent review and after the re-review (`README.md` sections 10 and 10.1).

- After the review: statements gain `base`, state-setting statements gain `prev*` fields, the log carries invite and link references instead of ids, the invite endpoint uses the `{alg, kid, pub}` key shape, lane endpoint `serverId`s use the `rle_` prefix, room policy replaces `showProjectNames` with `projectNames` and adds `grantTtl`, and revocations name log positions.
- After the re-review (decisions round 4): every `prev*` field is replaced by `ver`, a log position (`room-log-v2.md` section 4.0); `room.policy.changed` drops `policy` and `prevPolicyHash` and carries one `ver` per changed setting, so the `h:policy` hash label is gone; `endpoint.rotated` and `lane.offer.rotated` drop `prevServerId`; `device.conflict.resolved` and `member.device.replaced` gain `ver`; new statement types `recovery.key.proposed` and `producer.fence`; `recovery.key.rotated` gains `proposal`; genesis policy gains `soleDeviceChange` and `closeDelay`; `enroll.pending` gains `h`; new frames `link.abort` and `link.closed`; new error code `unknown_base`; `RosterEntry.devices` may be empty; the authority state records admin lineages and authority starts.

No v2 room exists yet, because v2 is not implemented, so none of these changes needs a migration. Once v2 ships, any later format change needs a version step (`signatures-and-encoding.md` section 7).

## 3. Mixed versions

| Owner | Member | Result |
|---|---|---|
| v2 | v1 | The v1 member's lane host goes to an error state; its control client times out. It cannot join v2 rooms (`prc2.` does not parse). The member must upgrade. |
| v1 | v2 | The v2 member refuses `prc1.` codes with a clear message. Its v1 registrations were removed in 2.3. |
| v2 | v2 | Normal. |

There is no dual-stack period and no v1 code path in v2 (`signatures-and-encoding.md` section 7).

## 4. Downgrade

If the plugin is downgraded to v1 after v2 ran, v1 finds no `gateway/` or `member/` directory and starts empty. v2 state (`keystore/`, `member/rooms/`, `admin/`, `host/`) is ignored by v1. The archive is not restored automatically. Upgrading again resumes the v2 state.

## 5. Documents to update when v2 is implemented (not done here)

- `../rooms-control-protocol.md` and `../data-model.md`: mark as superseded by this directory.
- `../room-profile-v1.md`: unchanged by identity v2, apart from the B-section fixes and the removal of the `rooms.control.*` first-frame switch on lane endpoints.
- the Rooms architecture document (design research, not published) section 8: apply the edits proposed in `docs/security/protocol-review.md` section 4.4, adjusted to the choices here (room endpoint with Noise IK, admin key, per-room device keys, keyring storage).
- `docs/design/m1-results.md` section 8 item 5: withdrawn (`mls-integration.md` section 8.1).

## 6. Tests

1. Unit: a fixture v1 tree; run the migration; check the archive layout, `migration.json`, and that a second run does nothing.
2. Unit: a v2 member given a `prc1.` code returns the upgrade message and makes no network call.
3. E2E (two test daemons, existing harness): create an M1 room and membership with the v1 plugin, upgrade both plugins, and check that the lane endpoint is gone, the member's registration is removed, and a new v2 room works end to end.
