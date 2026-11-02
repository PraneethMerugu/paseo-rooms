// Usability roadmap R3.4 (room chat, product M2): the signed chat payload (mls-integration.md 5.2), its
// vector, the receiver's binding checks in the MLS member, the sealed chat store (persistence across a
// restart, ordering, retention, read marker) and the write ordering of 8.2 with the store first.
// No network, no real keyring.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { chatDir, ChatStore, chatDisplayText, type ChatInput } from "../../server/member/chat-store";
import { checkChatMessage, ChatMessage, parseAppPayload, signChatMessage } from "../../server/mls/formats";
import type { MlsMember } from "../../server/mls/member";
import { b64u, b64uDecode } from "../../server/proto/b64u";
import { CTX_CHAT_MESSAGE, SIGNATURE_CONTEXTS } from "../../server/proto/contexts";
import { ed25519PrivateKeyFromSeed } from "../../server/proto/keys";
import { rjcs } from "../../server/proto/rjcs";
import { Harness, type Dev } from "./mls-harness";

const V = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "design", "specs", "identity-v2", "vectors", "vectors.json"), "utf8"));
const hex = (s: string) => Buffer.from(s, "hex");

async function three(): Promise<Harness> {
  const h = await Harness.create();
  await h.settle();
  h.admit("A");
  h.admit("B");
  await h.settle();
  for (const n of ["C", "A", "B"]) assert.equal(h.dev(n).member.inGroup, true, n);
  return h;
}

async function deliver(h: Harness): Promise<void> {
  h.syncAll();
  for (const d of h.devs.values()) await d.member.idle();
}

/** Sends raw payload bytes from a device's real leaf (test code only: a misbehaving member). */
async function sendRaw(d: Dev, payload: unknown): Promise<void> {
  const m = d.member as unknown as { locked<T>(f: () => Promise<T>): Promise<T>; sendPayload(b: Uint8Array): Promise<{ seq: number }> };
  await m.locked(() => m.sendPayload(rjcs(payload, 64 * 1024)));
}

function chatOf(d: Dev, h: Harness, text: string, over: Partial<ChatMessage> = {}): ChatMessage {
  return { v: 2, typ: "chat-message", roomId: h.room.roomId, groupId: d.member.groupKey, epoch: d.member.epoch!, memberId: d.memberId, deviceId: d.deviceId, ts: h.clock, text, ...over };
}

test("R3.4 vector mls.chatMessage: the signature, the payload bytes and the receiver checks match the generator", () => {
  assert.ok((SIGNATURE_CONTEXTS as readonly string[]).includes(CTX_CHAT_MESSAGE));
  const vec = V.mls.chatMessage;
  const key = ed25519PrivateKeyFromSeed(hex(V.keys.devSig.seedHex));
  const p = signChatMessage(vec.msg, key);
  assert.equal(p.sig, vec.sig);
  assert.equal(Buffer.from(rjcs(p)).toString("utf8"), vec.payload);
  const parsed = parseAppPayload(Buffer.from(vec.payload, "utf8"));
  assert.equal(parsed?.kind, "chat.message");
  const groupId = b64uDecode(vec.msg.groupId, 32);
  const sender = { memberId: vec.msg.memberId, deviceId: vec.msg.deviceId, deviceSig: V.keys.devSig.pub };
  const base = { roomId: vec.msg.roomId, groupId, epoch: 0, sender };
  assert.deepEqual(checkChatMessage(p, base), { ok: true });
  assert.deepEqual(checkChatMessage(p, { ...base, epoch: 1 }), { ok: false, reason: "wrong_epoch" });
  assert.deepEqual(checkChatMessage(p, { ...base, groupId: new Uint8Array(32) }), { ok: false, reason: "wrong_group" });
  assert.deepEqual(checkChatMessage(p, { ...base, roomId: `room_${"0".repeat(32)}` }), { ok: false, reason: "wrong_room" });
  assert.deepEqual(checkChatMessage(p, { ...base, sender: { ...sender, deviceId: `dev_${"0".repeat(32)}` } }), { ok: false, reason: "wrong_sender" });
  assert.deepEqual(checkChatMessage(p, { ...base, sender: { ...sender, deviceSig: V.keys.devSig2.pub } }), { ok: false, reason: "bad_signature" });
  // The unsigned development format is refused by the schema.
  assert.equal(parseAppPayload(rjcs({ kind: "chat.message", text: "hi" })), null);
});

test("R3.4 signature binding: a message signed for another group, another epoch or another sender is dropped and raises chat_attribution_failed", async () => {
  const h = await three();
  try {
    const [A, B, C] = ["A", "B", "C"].map((n) => h.dev(n));
    const r = await C.member.sendText("signed hello");
    assert.equal(r.from.deviceId, C.deviceId);
    await deliver(h);
    for (const d of [A, B]) assert.deepEqual(d.member.messages.map((m) => [m.text, m.from.deviceId, m.ts]), [["signed hello", C.deviceId, r.ts]]);
    // B misbehaves from its own leaf. Each payload decrypts fine; only the signed binding is wrong.
    const cases: { label: string; payload: unknown; reason: string }[] = [
      { label: "wrong group", payload: signChatMessage(chatOf(B, h, "g", { groupId: b64u(new Uint8Array(32).fill(7)) }), B.sigKey), reason: "wrong_group" },
      { label: "wrong epoch", payload: signChatMessage(chatOf(B, h, "e", { epoch: B.member.epoch! + 1 }), B.sigKey), reason: "wrong_epoch" },
      { label: "wrong sender, C's own signature replayed from B's leaf", payload: signChatMessage(chatOf(C, h, "s"), C.sigKey), reason: "wrong_sender" },
      { label: "names B, signed by another key", payload: signChatMessage(chatOf(B, h, "k"), A.sigKey), reason: "bad_signature" },
    ];
    for (const c of cases) {
      const before = A.member.alerts.length;
      await sendRaw(B, c.payload);
      await deliver(h);
      for (const d of [A, C]) {
        assert.ok(!d.member.messages.some((m) => m.from.deviceId === B.deviceId), `${c.label}: not delivered on ${d.name}`);
        const a = d.member.alerts.filter((x) => x.type === "chat_attribution_failed").at(-1);
        assert.ok(a && a.detail?.includes(c.reason) && a.peer?.deviceId === B.deviceId, `${c.label}: alert on ${d.name}`);
      }
      assert.equal(A.member.alerts.length, before + 1, `${c.label}: one alert`);
    }
    // The group goes on: a correctly signed message from B is accepted (after the witnesses confirm B's epoch).
    await h.settle();
    await A.member.sendText("witness for B");
    await deliver(h);
    await B.member.sendText("honest again");
    await deliver(h);
    assert.ok(A.member.messages.some((m) => m.text === "honest again" && m.from.deviceId === B.deviceId));
    assert.ok(C.member.canSendReason() === null, "the alert does not stop sending");
  } finally {
    h.cleanup();
  }
});

test("R3.4 ack after save: the chat store is written before the state and the ack; a failed store write is retried and acknowledged only after", async () => {
  const h = await three();
  try {
    const [A, C] = ["A", "C"].map((n) => h.dev(n));
    const store = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId: h.room.roomId, now: h.now });
    const order: string[] = [];
    let fail = true;
    A.member.storeMessages = (ms) => {
      const ackSeq = h.ds.lastAck(A.deviceId)?.seq ?? -1;
      order.push(`store:${ms.map((m) => m.seq).join(",")}:ack<${ackSeq < ms[0].seq}`);
      if (fail) {
        fail = false;
        throw new Error("disk full");
      }
      store.add(ms.map((m) => ({ seq: m.seq, epoch: m.epoch, hts: m.hts, ts: m.ts, memberId: m.from.memberId, deviceId: m.from.deviceId, text: m.text, own: false })));
    };
    const cursorBefore = A.store.record!.cursor;
    const sent = await C.member.sendText("must not be lost");
    await deliver(h);
    assert.equal(store.size, 0, "the failed write stored nothing");
    assert.equal(A.member.messages.length, 0, "not shown before it is stored");
    assert.ok((h.ds.lastAck(A.deviceId)?.seq ?? -1) < sent.seq, "no ack before the store write succeeded");
    assert.equal(A.store.record!.cursor, cursorBefore, "the group state was not written past the message");
    await A.member.maintain(); // the retry of a stuck queue (pump) processes it again from the stored state
    await A.member.idle();
    assert.equal(store.size, 1);
    assert.equal(store.page(null, 10).messages[0].text, "must not be lost");
    assert.deepEqual(A.member.messages.map((m) => m.text), ["must not be lost"]);
    assert.ok((h.ds.lastAck(A.deviceId)?.seq ?? -1) >= sent.seq, "acknowledged after the store write");
    assert.ok(order.length === 2 && order.every((o) => o.endsWith("ack<true")), JSON.stringify(order));
    // A re-delivery of an entry the store holds (crash between store and state write) is not duplicated.
    assert.equal(store.add([{ seq: sent.seq, epoch: 1, hts: 1, ts: 1, memberId: C.memberId, deviceId: C.deviceId, text: "must not be lost", own: false }]), 0);
    assert.equal(store.size, 1);
  } finally {
    h.cleanup();
  }
});

const msg = (seq: number, own = false, text = `m${seq}`): ChatInput => ({ seq, epoch: 1, hts: 1000 + seq, ts: 1000 + seq, memberId: `mem_${"a".repeat(32)}`, deviceId: `dev_${"b".repeat(32)}`, text, own });

test("R3.4 chat store: sealed on disk, persists across a restart, ordered by log position, paged, read marker kept", async () => {
  const h = await Harness.create();
  try {
    const roomId = h.room.roomId;
    let clock = 1_800_000_000_000;
    const now = () => clock;
    const s1 = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId, now });
    // Out of order (an own message's reply comes after later entries were stored) and duplicated.
    s1.add([msg(10), msg(12)]);
    s1.add([msg(11, true), msg(10)]);
    s1.add([msg(15, false, "a‮b\u0007c\r\nd")]);
    assert.deepEqual(s1.page(null, 50).messages.map((m) => m.seq), [10, 11, 12, 15]);
    assert.equal(s1.page(null, 50).messages[3].text, "abc\nd", "bidi override and control characters removed");
    assert.equal(s1.unread, 3, "own messages are not unread");
    assert.equal(s1.markRead(12), 1);
    assert.equal(s1.markRead(5), 1, "the marker never moves back");
    // Every file is sealed: no plaintext.
    for (const f of readdirSync(chatDir(h.dataDir, roomId))) {
      const raw = readFileSync(join(chatDir(h.dataDir, roomId), f), "utf8");
      assert.equal(JSON.parse(raw).typ, "sealed", f);
      assert.ok(!raw.includes("m10"), f);
    }
    clock += 1000;
    const s2 = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId, now });
    assert.deepEqual(s2.problems, []);
    assert.deepEqual(s2.page(null, 50).messages.map((m) => [m.seq, m.own]), [[10, false], [11, true], [12, false], [15, false]]);
    assert.equal(s2.read, 12);
    assert.equal(s2.unread, 1);
    // Paging: the newest `limit` before a position, oldest first.
    s2.add(Array.from({ length: 100 }, (_, i) => msg(100 + i)));
    const p1 = s2.page(null, 30);
    assert.deepEqual([p1.messages[0].seq, p1.messages.at(-1)!.seq, p1.more], [170, 199, true]);
    const p2 = s2.page(170, 200);
    assert.deepEqual([p2.messages[0].seq, p2.messages.at(-1)!.seq, p2.more], [10, 169, false]);
    // A store of another room cannot open these files (purpose binds the room).
    const other = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId: `room_${"f".repeat(32)}`, now });
    assert.equal(other.size, 0);
    assert.equal(chatDisplayText("x⁦y z"), "xy\nz");
  } finally {
    h.cleanup();
  }
});

test("R3.4 chat store retention: count and age limits drop whole old segments, never the newest; files stay bounded", async () => {
  const h = await Harness.create();
  try {
    const roomId = h.room.roomId;
    let clock = 1_800_000_000_000;
    const now = () => clock;
    const limits = { maxMessages: 128, maxAgeMs: 10 * 24 * 3600 * 1000 };
    const s = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId, now, limits });
    for (let i = 0; i < 640; i += 10) s.add(Array.from({ length: 10 }, (_, k) => msg(i + k)));
    const segs = () => readdirSync(chatDir(h.dataDir, roomId)).filter((f) => f.startsWith("seg-")).length;
    assert.ok(s.size <= 128 + 64, `count bounded: ${s.size}`);
    assert.ok(segs() <= 3, `segments bounded: ${segs()}`);
    assert.equal(s.lastSeq, 639, "the newest messages are kept");
    const firstKept = s.page(null, 200).messages[0].seq;
    assert.ok(firstKept > 0 && firstKept % 64 === 0, "dropped in whole segments");
    // Restart: the same messages.
    const s2 = new ChatStore({ dataDir: h.dataDir, kek: h.kek, roomId, now, limits });
    assert.equal(s2.size, s.size);
    // Age: 11 days later every old segment goes at the next write; the newest one stays.
    clock += 11 * 24 * 3600 * 1000;
    assert.equal(s2.page(null, 200).messages.length, 0, "expired messages are not listed");
    s2.add([msg(1000)]);
    assert.deepEqual(s2.page(null, 200).messages.map((m) => m.seq), [1000]);
    assert.ok(segs() <= 2, `old segments deleted: ${segs()}`);
  } finally {
    h.cleanup();
  }
});

// Silences the unused-type lint in some editors (the member type documents sendRaw's cast).
export type _M = MlsMember;
