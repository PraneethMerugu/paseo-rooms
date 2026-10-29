// Identity v2 milestone I-4: records and frames (enrollment-v2.md sections 3.4 and 3.6) against
// the `records` vectors in docs/specs/identity-v2/vectors/vectors.json, plus the fatal-error rules.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createNoiseInitiator, createNoiseResponder, generateNoiseKeyPair } from "../../server/noise/handshake-state";
import {
  FRAGMENT_MAX_BYTES,
  FRAME_ID_MAX,
  FRAME_MAX_BYTES,
  FrameAssembler,
  FrameOpener,
  frameToRecords,
  RECORD_MAX_BYTES,
  RecordError,
  sealFrame,
  type Frame,
} from "../../server/transport/records";

const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json"), "utf8"));
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const fromHex = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "hex"));
const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);
const record = (flags: number, text: string): Uint8Array => Uint8Array.from([flags, ...ascii(text)]);

test("records vector: single-fragment record", () => {
  const v = vectors.records.single;
  const frame = JSON.parse(v.frame) as Frame;
  assert.deepEqual(frameToRecords(frame).map(hex), [v.recordHex]);
  assert.deepEqual(new FrameAssembler().push(fromHex(v.recordHex)), frame);
});

test("records vector: a frame split into two fragments", () => {
  const v = vectors.records.split;
  const frame = JSON.parse(v.frame) as Frame;
  // The vector splits at an arbitrary byte (40); the encoder's own output carries the same frame bytes.
  const fragments = v.recordsHex.map((r: string) => fromHex(r));
  assert.deepEqual(fragments.map((r: Uint8Array) => r[0]), [1, 0]);
  const [single] = frameToRecords(frame);
  assert.equal(hex(Buffer.concat(fragments.map((r: Uint8Array) => r.subarray(1)))), hex(single.subarray(1)));
  assert.equal(hex(frameToRecords(frame, fragments[0].byteLength - 1)[0]), v.recordsHex[0]);
  const assembler = new FrameAssembler();
  assert.equal(assembler.push(fromHex(v.recordsHex[0])), null);
  assert.ok(assembler.pending());
  assert.deepEqual(assembler.push(fromHex(v.recordsHex[1])), frame);
  assert.ok(!assembler.pending());
});

test("default fragmentation fits one Noise transport message per record", () => {
  assert.equal(RECORD_MAX_BYTES, 65519);
  const frame: Frame = { t: "blob", data: "x".repeat(3 * FRAGMENT_MAX_BYTES) };
  const records = frameToRecords(frame);
  assert.equal(records.length, 4);
  assert.ok(records.every((r) => r.byteLength <= RECORD_MAX_BYTES));
  assert.deepEqual(records.map((r) => r[0]), [1, 1, 1, 0]);
  const assembler = new FrameAssembler();
  const out = records.map((r) => assembler.push(r));
  assert.deepEqual(out.slice(0, 3), [null, null, null]);
  assert.deepEqual(out[3], frame);
});

test("frames above 4 MiB are refused on both sides", () => {
  assert.throws(() => frameToRecords({ t: "blob", data: "x".repeat(FRAME_MAX_BYTES) }), RecordError);
  const assembler = new FrameAssembler();
  const chunk = new Uint8Array(RECORD_MAX_BYTES).fill(0x61);
  chunk[0] = 0x01;
  const needed = Math.ceil(FRAME_MAX_BYTES / (RECORD_MAX_BYTES - 1));
  for (let i = 0; i < needed - 1; i += 1) assert.equal(assembler.push(chunk), null);
  assert.throws(() => assembler.push(chunk), /frame too large/);
  assert.throws(() => assembler.push(record(0, '{"t":"ping"}')), /reader failed/);
});

test("bad records and non-canonical or malformed frames are fatal", () => {
  const cases: [string, Uint8Array[], RegExp][] = [
    ["bad flags", [record(0x02, '{"t":"ping"}')], /bad flags/],
    ["empty record", [new Uint8Array(0)], /empty fragment/],
    ["empty fragment", [Uint8Array.of(0x01)], /empty fragment/],
    ["oversized record", [new Uint8Array(RECORD_MAX_BYTES + 1)], /record too large/],
    ["whitespace", [record(0, '{"t": "ping"}')], /canonical/],
    ["unsorted keys", [record(0, '{"t":"x","a":1}')], /canonical/],
    ["float", [record(0, '{"n":1.5,"t":"x"}')], /canonical/],
    ["duplicate key", [record(0, '{"t":"x","t":"y"}')], /canonical/],
    ["not an object", [record(0, "[1]")], /not an object/],
    ["missing t", [record(0, '{"id":1}')], /bad t/],
    ["empty t", [record(0, '{"t":""}')], /bad t/],
    ["id zero", [record(0, '{"id":0,"t":"x"}')], /bad id/],
    ["id too large", [record(0, `{"id":${FRAME_ID_MAX + 1},"t":"x"}`)], /bad id/],
    ["bad re", [record(0, '{"re":"1","t":"error"}')], /bad re/],
  ];
  for (const [name, records, error] of cases) {
    const assembler = new FrameAssembler();
    const last = records.pop()!;
    for (const r of records) assembler.push(r);
    assert.throws(() => assembler.push(last), error, name);
    assert.throws(() => assembler.push(record(0, '{"t":"ping"}')), /reader failed/, `${name}: stays failed`);
  }
  assert.deepEqual(new FrameAssembler().push(record(0, `{"id":${FRAME_ID_MAX},"t":"x"}`)), { id: FRAME_ID_MAX, t: "x" });
});

test("sender refuses frames outside the envelope", () => {
  assert.throws(() => frameToRecords({ t: "" }), /bad t/);
  assert.throws(() => frameToRecords({ t: "x", id: 0 }), /bad id/);
  assert.throws(() => frameToRecords({ t: "x", n: 1.5 }), RecordError);
  assert.throws(() => frameToRecords({ t: "x" }, FRAGMENT_MAX_BYTES + 1), /fragment size/);
});

function session() {
  const endpoint = generateNoiseKeyPair();
  const device = generateNoiseKeyPair();
  const prologue = ascii("test");
  const i = createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, localStatic: device, prologue });
  const r = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
  r.readMessage(i.writeMessage(new Uint8Array(0)));
  i.readMessage(r.writeMessage(new Uint8Array(0)));
  return { member: i.split(), endpoint: r.split() };
}

test("frames over an IK session: round trip, then a bad tag is fatal", () => {
  const { member, endpoint } = session();
  const opener = new FrameOpener(endpoint.receive);
  const frame: Frame = { t: "msg.send", id: 7, message: "y".repeat(70000) };
  const messages = sealFrame(member.send, frame);
  assert.equal(messages.length, 2);
  assert.equal(opener.open(messages[0]), null);
  assert.deepEqual(opener.open(messages[1]), frame);
  const next = sealFrame(member.send, { t: "ping" })[0];
  next[next.length - 1] ^= 0x01;
  assert.throws(() => opener.open(next), /authentication failed/);
  assert.throws(() => opener.open(sealFrame(member.send, { t: "ping" })[0]), /reader failed/);
  // Reverse direction is independent.
  assert.deepEqual(new FrameOpener(member.receive).open(sealFrame(endpoint.send, { t: "ping" })[0]), { t: "ping" });
});
