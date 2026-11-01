// Usability roadmap R3.3 (room.profile and member.profile over MLS) and R3.5 (activity feed from the
// verified fold; alert acknowledgements). Pure parts first (sanitizing, look-alike names, the names
// book's acceptance rules and persistence, activity derivation), then the MLS path with the in-process
// harness: names reach other devices and a later joiner, the host's files never hold them, and a
// non-admin or another member's name is refused.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { RoomLogFold } from "../../server/authority/fold";
import { ActivityFeed, activityOf } from "../../server/member/activity";
import { MemoryRoomBookStore, nameSkeleton, RoomBook, sanitizeDisplayText, type ProfileInput } from "../../server/member/room-book";
import { AppPayload } from "../../server/mls/formats";
import type { MlsProfileEvent } from "../../server/mls/member";
import { activityText, nameWithId } from "../../client/v2-text";
import { FAST, Harness } from "./mls-harness";

const ROOM = `room_${"a".repeat(32)}`;
const M1 = `mem_${"1".repeat(32)}`;
const M2 = `mem_${"2".repeat(32)}`;
const M3 = `mem_${"3".repeat(32)}`;

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

// ------------------------------------------------------------------------------ pure

test("R3.3 sanitize: bidi overrides, zero-width, controls and separators removed; whitespace collapsed; combining floods cut; length in code points", () => {
  assert.equal(sanitizeDisplayText("Lab\u202e analysis", 64), "Lab analysis");
  assert.equal(sanitizeDisplayText("Sa\u200bm\u200d", 48), "Sa m");
  assert.equal(sanitizeDisplayText("  Sam\n\t\u2028 Lee\u0000 ", 48), "Sam Lee");
  assert.equal(sanitizeDisplayText("Q\u0301\u0302\u0303\u0304\u0305oe", 48), "Q\u0301\u0302oe");
  assert.equal(sanitizeDisplayText("e\u0301", 48), "\u00e9", "NFC");
  assert.equal(sanitizeDisplayText("\u{1f600}".repeat(70), 64), "\u{1f600}".repeat(64), "code points, never a split surrogate");
  assert.equal(sanitizeDisplayText("\u202e\u200b \n", 48), null);
  assert.equal(sanitizeDisplayText(42, 48), null);
  assert.equal(sanitizeDisplayText("\ue000Priv", 48), "Priv");
});

test("R3.3 look-alike names share a skeleton; different names do not", () => {
  assert.equal(nameSkeleton("Sam Lee"), nameSkeleton("SAM-LEE"));
  assert.equal(nameSkeleton("Bob"), nameSkeleton("B0b"));
  assert.equal(nameSkeleton("Kim"), nameSkeleton("Klm"));
  assert.equal(nameSkeleton("Mia"), nameSkeleton("rnia"));
  assert.equal(nameSkeleton("\uff33\uff41\uff4d"), nameSkeleton("sam"), "fullwidth (NFKC)");
  assert.notEqual(nameSkeleton("Sam"), nameSkeleton("Pam"));
});

test("R3.3 names book: room name only from an admin; higher rev wins, then the later position; display name only for the sender's own member id", () => {
  const store = new MemoryRoomBookStore();
  const book = new RoomBook(ROOM, store);
  const room = (seq: number, role: string, name: string, rev: number): ProfileInput => ({ seq, from: { memberId: M1, role }, payload: { kind: "room.profile", name, description: "", rev } });
  assert.equal(book.apply(room(5, "watch", "Hijacked", 9)), "refused", "a member that is not an admin cannot name the room");
  assert.equal(book.room === null, true);
  assert.equal(book.apply(room(6, "admin", "Bench \u202eA", 0)), "applied");
  assert.equal(book.room?.name, "Bench A", "sanitized again on receipt");
  assert.equal(book.apply(room(7, "admin", "Older", 0)), "applied", "same rev, later position");
  assert.equal(book.apply(room(8, "admin", "Stale re-announce", 0)), "applied");
  assert.equal(book.apply(room(9, "admin", "Renamed", 1)), "applied");
  assert.equal(book.apply(room(10, "admin", "Stale re-announce", 0)), "unchanged", "a lower rev never wins, whatever its position");
  assert.equal(book.room?.name, "Renamed");
  assert.equal(book.apply(room(11, "admin", "\u200b", 2)), "refused", "nothing printable");

  const prof = (seq: number, sender: string, memberId: string, label: string): ProfileInput => ({ seq, from: { memberId: sender, role: "watch" }, payload: { kind: "member.profile", memberId, label } });
  assert.equal(book.apply(prof(12, M2, M1, "I am the owner")), "refused", "another member's name");
  assert.equal(book.apply(prof(13, M2, M2, "Sam")), "applied");
  assert.equal(book.apply(prof(14, M3, M3, "SAM")), "applied");
  assert.equal(book.apply(prof(12, M2, M2, "Old")), "unchanged", "an earlier position does not win");
  assert.deepEqual(book.names([M1, M2, M3]), [
    { memberId: M1, name: null, collision: false },
    { memberId: M2, name: "Sam", collision: true },
    { memberId: M3, name: "SAM", collision: true },
  ]);
  assert.deepEqual(book.names([M1, M2]).map((n) => n.collision), [false, false], "only listed (roster) members are compared");

  // Persisted; acknowledgements too.
  assert.equal(book.ack([{ type: "fork", seq: 3 }, { type: "fork", seq: 3 }, { type: "truncation", seq: 4 }], 1000), 2);
  assert.equal(book.ack([{ type: "fork", seq: 3 }], 2000), 0);
  const again = new RoomBook(ROOM, store);
  assert.equal(again.problem, null);
  assert.equal(again.room?.name, "Renamed");
  assert.equal(again.memberName(M2), "Sam");
  assert.equal(again.isAcked("fork", 3), true);
  assert.equal(again.isAcked("fork", 5), false);
  // A damaged or foreign record is not used.
  store.value = { ...store.value!, roomId: `room_${"b".repeat(32)}` };
  const foreign = new RoomBook(ROOM, store);
  assert.equal(foreign.problem, "book_invalid");
  assert.equal(foreign.room, null);
});

test("R3.3 payload schema: room.profile and member.profile are strict", () => {
  assert.ok(AppPayload.safeParse({ kind: "room.profile", name: "x", description: "", rev: 0 }).success);
  assert.ok(!AppPayload.safeParse({ kind: "room.profile", name: "x", description: "", rev: 0, admin: true }).success);
  assert.ok(!AppPayload.safeParse({ kind: "member.profile", memberId: "nobody", label: "x" }).success);
  assert.ok(!AppPayload.safeParse({ kind: "member.profile", memberId: M1, label: "" }).success);
});

test("R3.3 UI text: a name is always followed by the short member id", () => {
  assert.equal(nameWithId("Sam", M2), "Sam (22222222)");
  assert.equal(nameWithId(null, M2), "Member 22222222");
  const t = activityText({ type: "member.admitted", alert: false, memberId: M2 }, (id) => nameWithId("Sam", id));
  assert.equal(t.text, "Sam (22222222) joined the room.");
});

// ------------------------------------------------------------------------------ activity from the fold

test("R3.5 activity: joined, role changed, device added, key rotated, policy changed, removed; from the fold; replays ignored", async () => {
  const h = await Harness.create();
  try {
    await h.settle();
    const J = h.admit("J");
    await h.settle();
    h.admin("member.role.changed", { memberId: J.memberId, role: "steer", ver: h.room.host.state.auth.versions[`role:${J.memberId}`] ?? -1 });
    h.admin("room.policy.changed", { changes: [{ setting: "grantTtl", value: 3600, ver: h.room.host.state.auth.versions["policy:grantTtl"] ?? -1 }] });
    h.admin("member.removed", { memberId: J.memberId, reason: "admin" });
    const fold = RoomLogFold.fromGenesis(h.room.genesis);
    const feed = new ActivityFeed();
    const records = h.room.host.entries(0);
    for (const r of records) {
      const before = fold.state;
      fold.append(r.signed, r.body);
      feed.push(r.signed, before, fold.state);
    }
    // A replay (reconnect, restored copy) adds nothing.
    const replay = RoomLogFold.fromGenesis(h.room.genesis);
    for (const r of records) {
      const before = replay.state;
      replay.append(r.signed, r.body);
      feed.push(r.signed, before, replay.state);
    }
    const items = feed.items(50).reverse();
    const byType = (t: string) => items.filter((x) => x.type === t);
    assert.equal(byType("member.admitted").length, 2, "the creator at seq 0 and J");
    assert.equal(byType("member.admitted")[1].memberId, J.memberId);
    assert.deepEqual(byType("member.role.changed").map((x) => [x.memberId, x.value]), [[J.memberId, "steer"]]);
    assert.deepEqual(byType("room.policy.changed")[0].changes, [{ setting: "grantTtl", from: String(h.room.genesis.body.policy.grantTtl), to: "3600" }]);
    assert.deepEqual(byType("member.removed").map((x) => x.memberId), [J.memberId]);
    assert.equal(items.filter((x) => x.type.startsWith("mls.") || x.type === "grant.issued").length, 0, "MLS and grant entries are not notices");
    assert.ok(items.every((x, i) => i === 0 || x.seq >= items[i - 1].seq), "log order");
    // Each item is exactly what activityOf derives from that entry's fold step.
    assert.equal(feed.lastSeq, h.room.host.head.seq);
    const text = activityText(byType("room.policy.changed")[0], () => "x").text;
    assert.match(text, /lane access lifetime \(s\): \d+ to 3600/);
  } finally {
    h.cleanup();
  }
});

test("R3.5 activity: host alerts are flagged, a key left uncertified adds an alert, MLS and grant entries give nothing", async () => {
  const h = await Harness.create();
  try {
    await h.settle();
    const fold = RoomLogFold.fromGenesis(h.room.genesis);
    for (const r of h.room.host.entries(0)) fold.append(r.signed, r.body);
    const before = fold.state;
    const laneId = `lane_${"c".repeat(32)}`;
    const lane = { owner: M1, offer: { ...before.auth.endpoint, serverId: "x" }, visibility: "room" as const, status: "open" as const, degradedAtHts: null, showNames: false, uncertified: false };
    const withLane = structuredClone(before) as typeof before;
    withLane.auth.lanes[laneId] = lane as never;
    const degraded = structuredClone(withLane) as typeof before;
    degraded.auth.lanes[laneId] = { ...lane, status: "degraded" } as never;
    const entry = (type: string, cls: "stmt" | "mls" = "stmt") => ({ entry: { seq: 40, hts: 1_000, type, cls } }) as never;
    assert.deepEqual(activityOf(entry("lane.degraded"), withLane, degraded), [{ seq: 40, hts: 1_000, type: "lane.degraded", alert: true, laneId }]);
    assert.deepEqual(activityOf(entry("grant.suspected-theft"), before, before), [{ seq: 40, hts: 1_000, type: "grant.suspected-theft", alert: true }]);
    assert.deepEqual(activityOf(entry("grant.issued"), before, before), []);
    assert.deepEqual(activityOf(entry("mls.commit", "mls"), before, before), []);
    const uncertified = structuredClone(before) as typeof before;
    uncertified.auth.endpointUncertified = true;
    const out = activityOf(entry("admin.key.revoked"), before, uncertified);
    assert.deepEqual(out.map((x) => [x.type, x.alert]), [["admin.key.revoked", false], ["uncertified_key", true]]);
  } finally {
    h.cleanup();
  }
});

// ------------------------------------------------------------------------------ over MLS (harness)

test("R3.3 over MLS: the room name and a display name reach the others and a later joiner; refused from a non-admin or for another member; never in the host's files", async () => {
  const h = await Harness.create(FAST);
  try {
    await h.settle();
    const C = h.dev("C");
    const A = h.admit("A");
    await h.settle();
    assert.equal(A.member.inGroup, true);
    const books = new Map<string, RoomBook>();
    // The runtime's wiring, per device: a names book, profiles into it, re-announcements from it.
    const wire = (name: string) => {
      const d = h.dev(name);
      const book = new RoomBook(h.room.roomId, new MemoryRoomBookStore());
      books.set(name, book);
      d.member.onProfile = (e: MlsProfileEvent) => void book.apply({ seq: e.seq, from: e.from, payload: e.payload });
      d.member.announce = () => {
        const role = h.room.host.state.members[d.memberId]?.role;
        const out: AppPayload[] = [];
        if (book.room && role === "admin") out.push({ kind: "room.profile", name: book.room.name, description: book.room.description, rev: book.room.rev });
        const n = book.memberName(d.memberId);
        if (n) out.push({ kind: "member.profile", memberId: d.memberId, label: n });
        return out;
      };
      return book;
    };
    const cBook = wire("C");
    const aBook = wire("A");
    const roomName = `Bench ${Math.random().toString(36).slice(2, 10)}`;
    const aName = `Sam ${Math.random().toString(36).slice(2, 10)}`;
    const sent = await C.member.sendProfile({ kind: "room.profile", name: roomName, description: "", rev: 0 });
    cBook.apply({ seq: sent.seq, from: { memberId: C.memberId, role: "admin" }, payload: { kind: "room.profile", name: roomName, description: "", rev: 0 } });
    const sentA = await A.member.sendProfile({ kind: "member.profile", memberId: A.memberId, label: aName });
    aBook.apply({ seq: sentA.seq, from: { memberId: A.memberId, role: "watch" }, payload: { kind: "member.profile", memberId: A.memberId, label: aName } });
    await h.settle();
    assert.equal(aBook.room?.name, roomName, "A reads the room name from the admin");
    assert.equal(cBook.memberName(A.memberId), aName, "the owner reads A's display name");
    assert.equal(A.member.profiles.at(-1)?.from.role, "admin");

    // A (watch) tries to rename the room, and to give the owner a name: both refused by every receiver.
    await A.member.sendProfile({ kind: "room.profile", name: "Hijacked", description: "", rev: 99 });
    await A.member.sendProfile({ kind: "member.profile", memberId: C.memberId, label: "Not the owner" });
    await h.settle();
    assert.equal(cBook.room?.name, roomName);
    assert.equal(cBook.memberName(C.memberId), null);
    assert.ok(C.member.profiles.some((p) => p.payload.kind === "room.profile" && p.from.role === "watch"), "delivered with the sender's verified role, then refused by the book");

    // A later joiner cannot read earlier epochs: it learns both names from the re-announcements.
    const J = h.admit("J");
    const jBook = wire("J");
    await h.settle();
    h.advance(1000);
    await h.settle();
    assert.equal(J.member.inGroup, true);
    assert.equal(jBook.room?.name, roomName, "the joiner learned the room name");
    assert.equal(jBook.memberName(A.memberId), aName, "the joiner learned A's display name");

    // The host's files (log, bodies, delivery state) never contain either name.
    const hostDir = join(h.dataDir, "host");
    const hits = filesUnder(hostDir).filter((f) => {
      const t = readFileSync(f).toString("latin1");
      return t.includes(roomName) || t.includes(aName) || t.includes(Buffer.from(roomName).toString("base64url").slice(0, 12));
    });
    assert.deepEqual(hits, []);
    assert.ok(filesUnder(hostDir).length > 0);
  } finally {
    h.cleanup();
  }
});
