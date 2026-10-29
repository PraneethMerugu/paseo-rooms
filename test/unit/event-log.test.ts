// Room log: hash chain and host signatures.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { generateEd25519 } from "../../server/crypto";
import { buildEvent, RoomEventLog, verifyChain } from "../../server/host/event-log";
import { tempDir } from "./helpers";

const ROOM = "room_0123456789abcdef";

function chain(n: number) {
  const key = generateEd25519();
  const events = [];
  let prev = null;
  for (let i = 0; i < n; i++) {
    prev = buildEvent(key, prev, { roomId: ROOM, type: i === 0 ? "room.created" : "member.joined", actor: "owner", data: { i } });
    events.push(prev);
  }
  return { key, events };
}

test("a valid chain verifies", () => {
  const { key, events } = chain(5);
  assert.deepEqual(verifyChain(events, key.publicKey, key.keyId), { ok: true });
});

test("tampered data, reordering, deletion and forged signatures are detected", () => {
  const { key, events } = chain(5);
  const tampered = events.map((e) => ({ ...e }));
  tampered[2] = { ...tampered[2], data: { i: 99 } };
  assert.equal((verifyChain(tampered, key.publicKey, key.keyId) as any).reason, "hash_mismatch");
  assert.equal((verifyChain([events[0], events[2], events[1]], key.publicKey, key.keyId) as any).reason, "sequence_gap");
  assert.equal((verifyChain([events[0], events[1], events[3]], key.publicKey, key.keyId) as any).reason, "sequence_gap");
  const other = generateEd25519();
  const resigned = buildEvent(other, events[1], { roomId: ROOM, type: "member.revoked", actor: "owner", data: {} });
  assert.equal((verifyChain([...events.slice(0, 2), resigned], key.publicKey, key.keyId) as any).reason, "bad_signature");
  const relinked = { ...events[3], prev: events[1].hash };
  assert.equal((verifyChain([...events.slice(0, 3), relinked], key.publicKey, key.keyId) as any).reason, "broken_link");
});

test("file-backed log appends and detects on-disk edits", () => {
  const tmp = tempDir();
  try {
    const key = generateEd25519();
    const path = join(tmp.dir, "events.jsonl");
    const log = new RoomEventLog(path, key);
    log.append({ roomId: ROOM, type: "room.created", actor: "owner", data: { name: "Lab" } });
    log.append({ roomId: ROOM, type: "lane.created", actor: "owner", data: { laneId: "lane_0123456789abcdef" } });
    const reopened = new RoomEventLog(path, key);
    reopened.append({ roomId: ROOM, type: "member.joined", actor: "mem_0123456789abcdef", data: {} });
    assert.equal(reopened.readAll().length, 3);
    assert.deepEqual(reopened.verify(), { ok: true });
    writeFileSync(path, readFileSync(path, "utf8").replace('"Lab"', '"Evil"'));
    assert.equal((reopened.verify() as any).reason, "hash_mismatch");
  } finally {
    tmp.cleanup();
  }
});
