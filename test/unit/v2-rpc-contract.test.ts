// I-14: RPC contracts of the v2 runtime as the UI uses them. The plugin's server entry is contributed
// to a fake PluginServerContext (a temporary, marked test PASEO_HOME, the file keystore
// and the in-process fake relay; no network, never ~/.paseo); every call goes through the contract's
// input schema, the registered handler and the output schema, and the handler's result must equal
// its parsed form (no field outside the contract). Also: admin confirmation tokens (identity-model
// 5.3) and `stale_base` re-confirmation (room-log-v2 2, R-9), the recovery offer, and "Fix permissions".
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import type { PluginRpcContract } from "@getpaseo/plugin";
import { ConfirmationBook, ConfirmationError, CONFIRM_TTL_MS, describeAdminAction, type DescribeContext } from "../../server/admin/confirmations";
import type { RoomState } from "../../server/authority/state";
import { TEST_HOME_MARKER, TEST_HOME_MARKER_TEXT } from "../../server/platform/test-clock";
import * as rpc from "../../shared/rpc";
import * as v2 from "../../shared/rpc-v2";
import { startFakeRelay } from "./fake-relay";
import { tempDir } from "./helpers";

type Handler = (input: unknown, ctx: unknown) => unknown;
const contracts = (mod: Record<string, unknown>) => Object.values(mod).filter((x): x is PluginRpcContract => !!x && typeof x === "object" && typeof (x as PluginRpcContract).name === "string" && "input" in x && "output" in x);
const V2 = contracts(v2);
const ADMIN_KINDS = v2.AdminActionV2.options.map((o) => o.shape.kind.value);

// ------------------------------------------------------------------------------ pure parts

test("I-14 contracts: every admin action kind has exactly one action RPC, and it requires confirmToken", () => {
  const withToken = V2.filter((c) => "confirmToken" in ((c.input as unknown as { shape?: object }).shape ?? {})).map((c) => c.name);
  assert.deepEqual(withToken.sort(), ADMIN_KINDS.map((k) => `rooms.v2.${k}`).sort());
  for (const c of V2.filter((x) => withToken.includes(x.name))) assert.equal(c.input.safeParse({ roomId: `room_${"a".repeat(32)}` }).success, false, `${c.name} without a token`);
  // Member-side and code-based calls take no token.
  for (const name of ["rooms.v2.device.rekey", "rooms.v2.device.veto", "rooms.v2.recovery.act", "rooms.v2.join.reject", "rooms.v2.invite.revoke", "rooms.v2.link.confirm"]) assert.ok(!withToken.includes(name), name);
  assert.equal(new Set(V2.map((c) => c.name)).size, V2.length, "names unique");
});

test("I-14 confirmations: one use, bound to the action, expire after 5 minutes, stale_base on a changed subject", () => {
  let now = 1_000_000;
  const book = new ConfirmationBook(() => now);
  const a = { kind: "member.role" as const, roomId: `room_${"a".repeat(32)}`, memberId: `mem_${"b".repeat(32)}`, role: "steer" as const };
  const d = (subject: string, current = "Current role: comment.") => ({ title: "t", details: [], current, warning: null, typeToConfirm: null, subject });
  const t1 = book.prepare(a, d("comment"));
  assert.match(t1.confirmToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(t1.expiresAt, now + CONFIRM_TTL_MS);
  book.take(t1.confirmToken, a, () => d("comment"));
  assert.throws(() => book.take(t1.confirmToken, a, () => d("comment")), (e: ConfirmationError) => e.code === "bad_token", "used once");
  const t2 = book.prepare(a, d("comment"));
  assert.throws(() => book.take(t2.confirmToken, { ...a, role: "watch" }, () => d("comment")), (e: ConfirmationError) => e.code === "bad_token", "another action");
  const t3 = book.prepare(a, d("comment"));
  assert.throws(
    () => book.take(t3.confirmToken, a, () => d("watch", "Current role: watch.")),
    (e: ConfirmationError) => e.code === "stale_base" && /Current role: watch/.test(e.message),
  );
  const t4 = book.prepare(a, d("comment"));
  now += CONFIRM_TTL_MS + 1;
  assert.throws(() => book.take(t4.confirmToken, a, () => d("comment")), (e: ConfirmationError) => e.code === "bad_token", "expired");
  // member.remove: an absent `compromise` is the same action as false.
  const r = { kind: "member.remove" as const, roomId: a.roomId, memberId: a.memberId };
  const t5 = book.prepare(r, d("x"));
  book.take(t5.confirmToken, { ...r, compromise: false }, () => d("x"));
});

test("I-14 describe: a role changed by another admin since the dialog opened is shown as the new current value (R-9)", () => {
  const memberId = `mem_${"c".repeat(32)}`;
  const st = (role: string, ver: number) =>
    ({ members: { [memberId]: { memberId, role, lanes: [], devices: [] } }, auth: { versions: { [`role:${memberId}`]: ver } }, pending: {}, conflicts: {} }) as unknown as RoomState;
  const ctx = (s: RoomState): DescribeContext => ({ state: s, label: () => "Bob", lanes: [], joinRequest: () => null, ownAdminKid: null, ownMemberId: null });
  const a = { kind: "member.role" as const, roomId: `room_${"a".repeat(32)}`, memberId, role: "steer" as const };
  const before = describeAdminAction(ctx(st("watch", 0)), a);
  assert.equal(before.current, "Current role: watch.");
  assert.match(before.title, /Bob/);
  const book = new ConfirmationBook();
  const t = book.prepare(a, before);
  assert.throws(() => book.take(t.confirmToken, a, () => describeAdminAction(ctx(st("comment", 1)), a)), /stale_base: This changed since you confirmed\. Current role: comment\./);
  assert.throws(() => describeAdminAction(ctx(st("steer", 2)), a), /already steer/);
  const rm = describeAdminAction(ctx(st("watch", 0)), { kind: "member.remove", roomId: a.roomId, memberId });
  assert.equal(rm.typeToConfirm, "remove");
});

test("V-9: the invite dialog shows the room name its token is bound to", () => {
  const ctx = { state: { members: {}, auth: { lanes: {}, closed: false, versions: {} }, pending: {}, conflicts: {} } as unknown as RoomState, label: () => "", lanes: [], joinRequest: () => null, ownAdminKid: null, ownMemberId: null } as DescribeContext;
  const d = describeAdminAction(ctx, { kind: "invite.create", roomId: `room_${"a".repeat(32)}`, roomName: "Lab bench" });
  assert.ok(d.details.includes("Room name: Lab bench"), JSON.stringify(d.details));
});

// ------------------------------------------------------------------------------ through the server entry

test("I-14 contracts through the server entry: handlers, shapes, tokens, stale_base, recovery offer", async () => {
  const t = tempDir();
  const relay = await startFakeRelay();
  const home = join(t.dir, ".test-homes", "v2-contract");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  // A marked test home: the plugin honours PASEO_ROOMS_DEV_* only there (I-15).
  writeFileSync(join(home, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT, { mode: 0o600 });
  const env = {
    PASEO_HOME: home,
    PASEO_ROOMS_KEYSTORE: "fallback-file",
    PASEO_ROOMS_RELAY_ENDPOINT: `127.0.0.1:${relay.port}`,
    PASEO_ROOMS_RELAY_TLS: "false",
    PASEO_ROOMS_DEV_INSECURE_RELAY: "1",
  };
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  Object.assign(process.env, env);
  const handlers = new Map<string, Handler>();
  const server = {
    handle: (c: PluginRpcContract, fn: Handler) => void handlers.set(c.name, fn),
    before: () => () => undefined,
    on: () => () => undefined,
  };
  const { default: contribute } = await import("../../index.server");
  const dispose = (contribute as (s: unknown) => () => Promise<void>)(server);
  const call = async <C extends PluginRpcContract>(c: C, input: unknown) => {
    const fn = handlers.get(c.name);
    assert.ok(fn, `${c.name} is registered`);
    const raw = await fn(c.input.parse(input), { paseo: undefined });
    const parsed = c.output.parse(raw);
    assert.deepEqual(JSON.parse(JSON.stringify(parsed)), JSON.parse(JSON.stringify(raw)), `${c.name}: the handler returns only contract fields`);
    return parsed as ReturnType<C["output"]["parse"]>;
  };
  const prepared = async (action: v2.AdminActionV2) => (await call(v2.roomsV2AdminPrepare, { action })).confirmToken;
  try {
    // Registration: every v2 contract except the TEST-ONLY clock (no marker switch here), and every
    // contract of shared/rpc.ts (bootstrap, Fix permissions, lane agents, migration); no M1 call.
    const expected = [...V2.filter((c) => c.name !== "rooms.v2.test.clock.advance").map((c) => c.name), ...contracts(rpc).map((c) => c.name)].sort();
    assert.deepEqual([...handlers.keys()].sort(), expected);
    for (const m1 of ["rooms.overview", "rooms.create", "rooms.join", "rooms.invite.create", "rooms.member.revoke", "rooms.log"]) assert.equal(handlers.has(m1), false, m1);
    assert.deepEqual(await call(rpc.roomsLaneAgents, {}), { lanes: [] });

    assert.equal((await call(rpc.roomsBootstrap, {})).protocol, "v2");
    const s0 = await call(v2.roomsV2Status, {});
    assert.equal(s0.state, "ready");
    assert.equal(s0.keystore?.backend, "fallback-file");
    assert.equal(s0.keystore?.fallback, true);
    assert.match(s0.keystore?.notice ?? "", /unprotected on disk/);
    assert.equal(s0.platform, process.platform);
    assert.equal(s0.migration, null, "a fresh home has no M1 data to migrate");
    assert.equal(s0.permissionProblems, undefined);

    // Create with a recovery key: the code once, with the file of identity-model 5.4.1.
    const created = await call(v2.roomsV2RoomCreate, { recovery: "create" });
    const roomId = created.roomId;
    assert.ok(created.recovery);
    assert.match(created.recovery.code, /^prk2(-[a-z2-7]{4}){14}$/);
    assert.equal(created.recovery.file.name, `paseo-room-recovery-${roomId}.json`);
    const file = JSON.parse(created.recovery.file.text);
    assert.deepEqual([file.v, file.typ, file.roomId, file.code, file.kid], [2, "recovery-key", roomId, created.recovery.code, created.recovery.kid]);
    const s1 = await call(v2.roomsV2Status, {});
    assert.ok(!JSON.stringify(s1).includes(created.recovery.code), "the status never carries the code");
    const room = s1.owned.find((r) => r.roomId === roomId)!;
    assert.equal(room.roster.length, 1);
    assert.equal(room.roster[0].self, true);
    assert.equal(room.roster[0].role, "admin");
    assert.equal(room.lineages, 1);
    assert.equal(room.keys.recoveryKid, created.recovery.kid);
    assert.deepEqual(room.keys.recoveryProposals, []);
    assert.equal(room.policy.deviceAddApproval, "same-person");
    const skipped = await call(v2.roomsV2RoomCreate, {});
    assert.equal(skipped.recovery, null, "the RPC default is skip");
    assert.match(skipped.recoverySkippedWarning ?? "", /cannot be recovered/);

    // No token: refused by the input schema. A token is used once and only for its own action.
    assert.throws(() => v2.roomsV2HostKeyRotate.input.parse({ roomId }));
    const tok = await prepared({ kind: "host.key.rotate", roomId });
    const r1 = await call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: tok });
    assert.ok(r1.seq > 0);
    await assert.rejects(call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: tok }), /bad_token/);
    const forEndpoint = await prepared({ kind: "endpoint.rotate", roomId });
    await assert.rejects(call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: forEndpoint }), /bad_token: The confirmation was for a different action/);
    const otherRoom = await prepared({ kind: "host.key.rotate", roomId: skipped.roomId });
    await assert.rejects(call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: otherRoom }), /bad_token/);

    // stale_base: two dialogs open; the second confirms first; the first is refused with the new value.
    const prep = await call(v2.roomsV2AdminPrepare, { action: { kind: "host.key.rotate", roomId } });
    assert.match(prep.description.current ?? "", /Current host key/);
    const second = await prepared({ kind: "host.key.rotate", roomId });
    const r2 = await call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: second });
    await assert.rejects(call(v2.roomsV2HostKeyRotate, { roomId, confirmToken: prep.confirmToken }), (e: Error) => /^stale_base: This changed since you confirmed\. Current host key: /.test(e.message) && e.message.includes(r2.kid.slice(0, 8)));
    const s2 = await call(v2.roomsV2Status, {});
    assert.equal(s2.owned.find((r) => r.roomId === roomId)!.keys.hostKeys.length, 3, "the stale confirmation signed nothing");

    // Bound to the parameters: an invite token does not create a different invite.
    const inv = { roomId, role: "watch" as const, lanes: [], note: "for Sam" };
    const invTok = await prepared({ kind: "invite.create", ...inv });
    await assert.rejects(call(v2.roomsV2InviteCreate, { ...inv, role: "admin", confirmToken: invTok }), /bad_token/);
    const invTok2 = await prepared({ kind: "invite.create", ...inv });
    const invite = await call(v2.roomsV2InviteCreate, { ...inv, confirmToken: invTok2 });
    assert.match(invite.code, /^prc2\./);
    const s3 = await call(v2.roomsV2Status, {});
    assert.ok(!JSON.stringify(s3).includes(invite.code), "the status never carries the invite code");

    // Impossible actions fail at prepare: one lineage closes with the recovery key (keys 6.8).
    await assert.rejects(call(v2.roomsV2AdminPrepare, { action: { kind: "room.close.propose", roomId } }), /one admin lineage: close it with the recovery code/);
    await assert.rejects(call(v2.roomsV2AdminPrepare, { action: { kind: "recovery.create", roomId } }), /already has a recovery key/);
    const rec = await call(v2.roomsV2RecoveryCreate, { roomId: skipped.roomId, confirmToken: await prepared({ kind: "recovery.create", roomId: skipped.roomId }) });
    assert.equal(rec.proposal, null);
    assert.match(rec.recovery.code, /^prk2-/);
    assert.equal(JSON.parse(rec.recovery.file.text).code, rec.recovery.code);

    // Recovery procedure: rotate returns the new code as an offer (and needs no admin token).
    const rot = await call(v2.roomsV2RecoveryAct, { roomId, code: created.recovery.code, action: { kind: "rotate" } });
    assert.ok(rot.recovery && rot.recovery.code !== created.recovery.code);
    await assert.rejects(call(v2.roomsV2RecoveryAct, { roomId, code: created.recovery.code, action: { kind: "rotate" } }), /not the current recovery key/);
  } finally {
    await dispose();
    await relay.close();
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    t.cleanup();
  }
});

test("I-14 Fix permissions under v2: problems are reported in the status, the fix starts the runtime", async (tc) => {
  if (process.platform === "win32") return tc.skip("POSIX modes");
  const { RoomsRuntimeV2 } = await import("../../server/runtime-v2");
  const t = tempDir();
  try {
    const home = join(t.dir, "home");
    const data = join(home, "plugin-data", "rooms");
    mkdirSync(data, { recursive: true, mode: 0o700 });
    chmodSync(data, 0o755);
    const rt = new RoomsRuntimeV2({ PASEO_HOME: home, PASEO_ROOMS_KEYSTORE: "fallback-file" });
    await rt.start();
    const s = rt.status();
    assert.equal(s.state, "error");
    assert.ok(s.permissionProblems?.some((p) => p.code === "mode"), JSON.stringify(s.permissionProblems));
    assert.ok(s.permissionProblems?.every((p) => !p.path.startsWith("/")), "relative paths only");
    v2.roomsV2Status.output.parse(s);
    const fixed = await rt.fixPermissions();
    assert.deepEqual(fixed, { ok: true, problems: [] });
    assert.equal(rt.status().state, "ready");
    assert.equal(rt.status().permissionProblems, undefined);
    await rt.stop();
  } finally {
    t.cleanup();
  }
});

test("I-14 client texts: members see mapped codes only; ids and recovery codes are formatted for display", async () => {
  const { memberErrorText, alertText, shortId, recoveryCodeLines, recoveryCheckGroup, fmtSas } = await import("../../client/v2-text");
  const leaky = "lane_failed: /home/owner/secret-project/src/main.ts: ENOENT";
  const shown = memberErrorText(leaky) ?? "";
  assert.ok(!shown.includes("secret-project") && !shown.includes("/home"), shown);
  assert.equal(memberErrorText("removed"), "You were removed from this room.");
  assert.equal(memberErrorText(null), null);
  for (const type of ["fork", "truncation", "withholding", "roster_mismatch", "invalid_entry", "uncertified_key"]) assert.ok(alertText(type).text.length > 20, type);
  assert.equal(alertText("fork").stopsSending, true);
  assert.equal(alertText("<script>").text, "Security notice (script).");
  assert.equal(shortId(`mem_${"0123456789abcdef".repeat(2)}`), "01234567");
  assert.equal(shortId("ab_cdefgh-ijk"), "ab_cdefg", "a base64url key id is not a prefixed id");
  const code = `prk2-${Array.from({ length: 14 }, (_, i) => "abcd efgh ijkl mnop qrst uvwx yz23 4567 abce abcf abcg abch abci abcj".split(" ")[i]).join("-")}`;
  assert.deepEqual(recoveryCodeLines(code), ["prk2-", "abcd-efgh-ijkl-mnop", "qrst-uvwx-yz23-4567", "abce-abcf-abcg-abch", "abci-abcj"]);
  assert.equal(recoveryCheckGroup(code), "abcj");
  assert.equal(fmtSas("317837"), "317 837");
});

test("V-3: the development MLS RPCs (rooms.v2.mls.send, rooms.v2.mls.messages) are not registered outside a marked test home", async () => {
  const t = tempDir();
  const env: Record<string, string> = { PASEO_HOME: "", PASEO_ROOMS_KEYSTORE: "fallback-file" };
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  const { default: contribute } = await import("../../index.server");
  const registered = async (home: string) => {
    mkdirSync(home, { recursive: true, mode: 0o700 });
    Object.assign(process.env, { ...env, PASEO_HOME: home });
    const names = new Set<string>();
    const server = { handle: (c: PluginRpcContract) => void names.add(c.name), before: () => () => undefined, on: () => () => undefined };
    const dispose = (contribute as (s: unknown) => () => Promise<void>)(server);
    await dispose();
    return names;
  };
  try {
    const dev = ["rooms.v2.mls.send", "rooms.v2.mls.messages"];
    const plain = await registered(join(t.dir, "home"));
    assert.ok(plain.has("rooms.v2.status"), "the entry registered its RPCs");
    for (const n of dev) assert.equal(plain.has(n), false, `${n} on an ordinary home`);
    // Named like a test home but without the marker: still absent.
    const unmarked = await registered(join(t.dir, ".test-homes", "v2-unmarked"));
    for (const n of dev) assert.equal(unmarked.has(n), false, `${n} on an unmarked test-home path`);
    const markedHome = join(t.dir, ".test-homes", "v2-marked");
    mkdirSync(markedHome, { recursive: true, mode: 0o700 });
    writeFileSync(join(markedHome, TEST_HOME_MARKER), TEST_HOME_MARKER_TEXT, { mode: 0o600 });
    const marked = await registered(markedHome);
    for (const n of dev) assert.equal(marked.has(n), true, `${n} on a marked test home`);
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    t.cleanup();
  }
});
