// Identity v2 milestone I-4: vendored Paseo Noise module plus IK (enrollment-v2.md sections 3.2.1
// and 3.3; signatures-and-encoding.md section 9.3).
//   - cacophony NK and IK vectors, six of six messages each (fixture copied from the pinned
//     rweather/noise-c cacophony.txt; provenance inside the fixture);
//   - noise.enrollment and noise.ikCacophonyKeys from docs/specs/identity-v2/vectors/vectors.json;
//   - Paseo's noise.test.ts negatives, ported; IK and prologue negatives.
// Key material in the vectors is public test data; assertion messages never print keys.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  CipherState,
  createNoiseInitiator,
  createNoiseResponder,
  generateNoiseKeyPair,
  handshakeMessageBytes,
  NOISE_IK_PROTOCOL_NAME,
  NOISE_MAX_MESSAGE_BYTES,
  NOISE_NK_PROTOCOL_NAME,
  NoiseProtocolError,
  type NoiseHandshake,
  type NoisePattern,
} from "../../server/noise/handshake-state";
import { createRoomIkInitiator, createRoomIkResponder, roomNoisePrologue } from "../../server/noise/prologue";
import { b64uDecode } from "../../server/proto/b64u";

interface CacoVector {
  name: string;
  pattern: string;
  init_prologue: string;
  init_static?: string;
  init_ephemeral: string;
  init_remote_static: string;
  resp_prologue: string;
  resp_static: string;
  resp_ephemeral: string;
  messages: { payload: string; ciphertext: string }[];
}

const caco = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "cacophony-nk-ik-25519-chachapoly-sha256.json"), "utf8")) as {
  source: { commit: string; fileSha256: string };
  vectors: CacoVector[];
};
const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "specs", "identity-v2", "vectors", "vectors.json"), "utf8"));

const EMPTY = new Uint8Array(0);
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const fromHex = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "hex"));
const keyPair = (secretHex: string) => {
  const secretKey = fromHex(secretHex);
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
};

/** Runs a full handshake plus transport messages; returns every ciphertext in order. */
function run(initiator: NoiseHandshake, responder: NoiseHandshake, payloads: Uint8Array[]): string[] {
  const out: string[] = [];
  const m1 = initiator.writeMessage(payloads[0]);
  out.push(hex(m1));
  assert.equal(hex(responder.readMessage(m1)), hex(payloads[0]));
  const m2 = responder.writeMessage(payloads[1]);
  out.push(hex(m2));
  assert.equal(hex(initiator.readMessage(m2)), hex(payloads[1]));
  assert.ok(initiator.isComplete() && responder.isComplete());
  assert.equal(hex(initiator.handshakeHash()), hex(responder.handshakeHash()));
  const ik = initiator.split();
  const rk = responder.split();
  payloads.slice(2).forEach((payload, index) => {
    const fromInitiator = index % 2 === 0;
    const ct = (fromInitiator ? ik.send : rk.send).encryptWithAd(EMPTY, payload);
    out.push(hex(ct));
    assert.equal(hex((fromInitiator ? rk.receive : ik.receive).decryptWithAd(EMPTY, ct)), hex(payload));
  });
  return out;
}

function cacoHandshakes(v: CacoVector) {
  const pattern = v.pattern as NoisePattern;
  const responderStatic = keyPair(v.resp_static);
  assert.equal(hex(responderStatic.publicKey), v.init_remote_static);
  const initiator = createNoiseInitiator({
    pattern,
    remoteStatic: fromHex(v.init_remote_static),
    localStatic: v.init_static ? keyPair(v.init_static) : undefined,
    prologue: fromHex(v.init_prologue),
    ephemeral: keyPair(v.init_ephemeral),
  });
  const responder = createNoiseResponder({
    pattern,
    localStatic: responderStatic,
    prologue: fromHex(v.resp_prologue),
    ephemeral: keyPair(v.resp_ephemeral),
  });
  return { initiator, responder };
}

// ---- cacophony vectors ----

test("cacophony fixture is pinned to noise-c cfe2541 and holds exactly NK and IK", () => {
  assert.equal(caco.source.commit, "cfe25410979a87391bb9ac8d4d4bef64e9f268c6");
  assert.equal(caco.source.fileSha256, "e1b0c4100b6c6e76378705a4954c3293f3752a55b586a3a252cecbfc937538c9");
  assert.deepEqual(caco.vectors.map((v) => v.name), [NOISE_NK_PROTOCOL_NAME, NOISE_IK_PROTOCOL_NAME]);
});

for (const v of caco.vectors) {
  test(`cacophony ${v.name}: six of six messages`, () => {
    const { initiator, responder } = cacoHandshakes(v);
    assert.equal(v.messages.length, 6);
    const got = run(initiator, responder, v.messages.map((m) => fromHex(m.payload)));
    v.messages.forEach((m, k) => assert.equal(got[k], m.ciphertext, `${v.pattern} message ${k + 1}`));
  });

  test(`cacophony ${v.name}: a corrupted byte in each handshake message fails authentication`, () => {
    for (const index of [0, 1] as const) {
      for (const position of ["first", "last"] as const) {
        const { initiator, responder } = cacoHandshakes(v);
        const payloads = v.messages.map((m) => fromHex(m.payload));
        const m1 = initiator.writeMessage(payloads[0]);
        if (index === 0) {
          const bad = m1.slice();
          bad[position === "first" ? 0 : bad.length - 1] ^= 0x01;
          assert.throws(() => responder.readMessage(bad), NoiseProtocolError);
          assert.throws(() => responder.writeMessage(EMPTY), NoiseProtocolError, "poisoned after failure");
          continue;
        }
        responder.readMessage(m1);
        const bad = responder.writeMessage(payloads[1]).slice();
        bad[position === "first" ? 0 : bad.length - 1] ^= 0x01;
        assert.throws(() => initiator.readMessage(bad), NoiseProtocolError);
        assert.throws(() => initiator.split(), NoiseProtocolError);
      }
    }
  });
}

test("cacophony IK: a modified expected transport byte would be caught (negative control)", () => {
  const v = caco.vectors.find((x) => x.pattern === "IK")!;
  const { initiator, responder } = cacoHandshakes(v);
  const got = run(initiator, responder, v.messages.map((m) => fromHex(m.payload)));
  const expected = v.messages[2].ciphertext;
  const tampered = (expected[0] === "0" ? "1" : "0") + expected.slice(1);
  assert.notEqual(got[2], tampered);
  assert.equal(got[2], expected);
});

// ---- vectors.json: noise.enrollment and noise.ikCacophonyKeys ----

test("noise.ikCacophonyKeys equals the cacophony IK entry (first four messages)", () => {
  const n = vectors.noise.ikCacophonyKeys;
  assert.equal(n.protocol, NOISE_IK_PROTOCOL_NAME);
  const initiator = createNoiseInitiator({
    pattern: "IK",
    remoteStatic: keyPair(n.respStaticHex).publicKey,
    localStatic: keyPair(n.initStaticHex),
    prologue: fromHex(n.prologueHex),
    ephemeral: keyPair(n.initEphemeralHex),
  });
  const responder = createNoiseResponder({
    pattern: "IK",
    localStatic: keyPair(n.respStaticHex),
    prologue: fromHex(n.prologueHex),
    ephemeral: keyPair(n.respEphemeralHex),
  });
  const got = run(initiator, responder, n.messages.map((m: { payload: string }) => fromHex(m.payload)));
  n.messages.forEach((m: { ciphertext: string }, k: number) => assert.equal(got[k], m.ciphertext, `message ${k + 1}`));
  const ikEntry = caco.vectors.find((x) => x.pattern === "IK")!;
  n.messages.forEach((m: { ciphertext: string }, k: number) => assert.equal(m.ciphertext, ikEntry.messages[k].ciphertext));
});

test("noise.enrollment: room prologue, empty payloads, 96-byte message 1, handshake hash", () => {
  const n = vectors.noise.enrollment;
  const genesisHash = b64uDecode(vectors.enrollment.signedObject.genesisHash, 32);
  const serverId = vectors.genesis.signed.body.endpoint.serverId as string;
  const binding = { genesisHash, serverId };
  assert.equal(hex(roomNoisePrologue(binding)), n.prologueHex);
  const device = keyPair(vectors.keys.devDh.secretHex);
  const endpoint = keyPair(vectors.keys.endpoint.secretHex);
  const initiator = createRoomIkInitiator({ binding, endpointStatic: endpoint.publicKey, deviceStatic: device, ephemeral: keyPair(n.initEphemeralHex) });
  const responder = createRoomIkResponder({ binding, endpointStatic: endpoint, ephemeral: keyPair(n.respEphemeralHex) });
  const m1 = initiator.writeMessage(EMPTY);
  assert.equal(m1.byteLength, 96);
  assert.equal(handshakeMessageBytes("IK", 0), 96);
  assert.equal(hex(m1), n.messages[0].ciphertext);
  responder.readMessage(m1);
  assert.equal(hex(responder.remoteStatic()!), hex(device.publicKey));
  const m2 = responder.writeMessage(EMPTY);
  assert.equal(m2.byteLength, handshakeMessageBytes("IK", 1));
  assert.equal(hex(m2), n.messages[1].ciphertext);
  initiator.readMessage(m2);
  assert.equal(hex(initiator.handshakeHash()), n.handshakeHash);
  assert.equal(hex(responder.handshakeHash()), n.handshakeHash);
});

// ---- prologue binding ----

test("prologue mismatch fails the IK handshake at message 1 (room, endpoint, raw bytes)", () => {
  const endpoint = generateNoiseKeyPair();
  const device = generateNoiseKeyPair();
  const genesisHash = new Uint8Array(32).fill(7);
  const serverId = "rme_" + "A".repeat(32);
  const good = { genesisHash, serverId };
  const otherRoom = { genesisHash: new Uint8Array(32).fill(8), serverId };
  const otherEndpoint = { genesisHash, serverId: "rme_" + "B".repeat(32) };
  for (const responderBinding of [otherRoom, otherEndpoint]) {
    const initiator = createRoomIkInitiator({ binding: good, endpointStatic: endpoint.publicKey, deviceStatic: device });
    const responder = createRoomIkResponder({ binding: responderBinding, endpointStatic: endpoint });
    assert.throws(() => responder.readMessage(initiator.writeMessage(EMPTY)), /authentication failed/);
    assert.equal(responder.remoteStatic(), null, "no initiator static learned on failure");
  }
  // A different version or label byte in the raw prologue also fails.
  const prologue = roomNoisePrologue(good);
  const v1 = Uint8Array.from(prologue); // a copy: Buffer.slice would alias
  v1[13] = "1".charCodeAt(0); // "paseo-rooms/v2" -> "paseo-rooms/v1"
  const initiator = createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, localStatic: device, prologue: v1 });
  const responder = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
  assert.throws(() => responder.readMessage(initiator.writeMessage(EMPTY)), NoiseProtocolError);
  // Matching prologues complete.
  const i2 = createRoomIkInitiator({ binding: good, endpointStatic: endpoint.publicKey, deviceStatic: device });
  const r2 = createRoomIkResponder({ binding: good, endpointStatic: endpoint });
  r2.readMessage(i2.writeMessage(EMPTY));
  i2.readMessage(r2.writeMessage(EMPTY));
  assert.ok(i2.isComplete() && r2.isComplete());
});

test("roomNoisePrologue validates its inputs", () => {
  assert.throws(() => roomNoisePrologue({ genesisHash: new Uint8Array(31), serverId: "rme_" + "A".repeat(32) }));
  assert.throws(() => roomNoisePrologue({ genesisHash: new Uint8Array(32), serverId: "rle_" + "A".repeat(32) }));
});

// ---- IK-specific negatives ----

test("IK: a modified encrypted static in message 1 fails, and the static is learned only after authentication", () => {
  const endpoint = generateNoiseKeyPair();
  const device = generateNoiseKeyPair();
  const prologue = new TextEncoder().encode("test");
  for (const offset of [32, 32 + 31, 32 + 47]) {
    // bytes 32..79 of message 1 are the encrypted static (32) and its tag (16)
    const initiator = createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, localStatic: device, prologue });
    const responder = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
    const m1 = initiator.writeMessage(EMPTY);
    m1[offset] ^= 0x80;
    assert.equal(responder.remoteStatic(), null);
    assert.throws(() => responder.readMessage(m1), /authentication failed/);
    assert.equal(responder.remoteStatic(), null);
  }
  // A corrupted payload tag also leaves the static hidden, though `s` itself decrypted.
  const initiator = createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, localStatic: device, prologue });
  const responder = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
  const m1 = initiator.writeMessage(EMPTY);
  m1[m1.length - 1] ^= 0x01;
  assert.throws(() => responder.readMessage(m1), /authentication failed/);
  assert.equal(responder.remoteStatic(), null);
});

test("IK: initiator aimed at the wrong endpoint key fails; NK and IK option checks", () => {
  const endpoint = generateNoiseKeyPair();
  const other = generateNoiseKeyPair();
  const device = generateNoiseKeyPair();
  const prologue = EMPTY;
  const initiator = createNoiseInitiator({ pattern: "IK", remoteStatic: other.publicKey, localStatic: device, prologue });
  const responder = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
  assert.throws(() => responder.readMessage(initiator.writeMessage(EMPTY)), NoiseProtocolError);
  assert.throws(() => createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, prologue }), NoiseProtocolError);
  assert.throws(() => createNoiseInitiator({ pattern: "NK", remoteStatic: endpoint.publicKey, localStatic: device, prologue }), NoiseProtocolError);
  assert.throws(() => createNoiseInitiator({ pattern: "XX" as NoisePattern, remoteStatic: endpoint.publicKey, prologue }), NoiseProtocolError);
  assert.throws(() => createNoiseInitiator({ pattern: "NK", remoteStatic: new Uint8Array(31), prologue }), NoiseProtocolError);
});

test("IK: a low-order initiator static is rejected at ss", () => {
  const endpoint = generateNoiseKeyPair();
  const prologue = EMPTY;
  // All-zero public key with an arbitrary secret: the ss DH on the responder side is all zero.
  const lowOrder = { secretKey: generateNoiseKeyPair().secretKey, publicKey: new Uint8Array(32) };
  const initiator = createNoiseInitiator({ pattern: "IK", remoteStatic: endpoint.publicKey, localStatic: lowOrder, prologue });
  const responder = createNoiseResponder({ pattern: "IK", localStatic: endpoint, prologue });
  const m1 = initiator.writeMessage(EMPTY);
  assert.throws(() => responder.readMessage(m1), /invalid DH public key/);
  assert.equal(responder.remoteStatic(), null);
});

// ---- Paseo noise.test.ts negatives, ported (both patterns) ----

function pair(pattern: NoisePattern, prologue = new TextEncoder().encode("test")) {
  const daemon = generateNoiseKeyPair();
  const device = generateNoiseKeyPair();
  const make = () => ({
    initiator: createNoiseInitiator({ pattern, remoteStatic: daemon.publicKey, localStatic: pattern === "IK" ? device : undefined, prologue }),
    responder: createNoiseResponder({ pattern, localStatic: daemon, prologue }),
  });
  return { daemon, make };
}

for (const pattern of ["NK", "IK"] as const) {
  test(`${pattern}: rejects a replayed, reflected, or out-of-order transport message`, () => {
    const { initiator, responder } = pair(pattern).make();
    responder.readMessage(initiator.writeMessage(EMPTY));
    initiator.readMessage(responder.writeMessage(EMPTY));
    const client = initiator.split();
    const server = responder.split();
    const first = client.send.encryptWithAd(EMPTY, new Uint8Array([1]));
    const second = client.send.encryptWithAd(EMPTY, new Uint8Array([2]));
    assert.deepEqual(server.receive.decryptWithAd(EMPTY, first), new Uint8Array([1]));
    assert.throws(() => server.receive.decryptWithAd(EMPTY, first), NoiseProtocolError);
    assert.deepEqual(server.receive.decryptWithAd(EMPTY, second), new Uint8Array([2]));
    assert.throws(() => client.receive.decryptWithAd(EMPTY, second), NoiseProtocolError);
    const third = client.send.encryptWithAd(EMPTY, new Uint8Array([3]));
    const fourth = client.send.encryptWithAd(EMPTY, new Uint8Array([4]));
    assert.throws(() => server.receive.decryptWithAd(EMPTY, fourth), NoiseProtocolError);
    assert.deepEqual(server.receive.decryptWithAd(EMPTY, third), new Uint8Array([3]));
    assert.deepEqual(server.receive.decryptWithAd(EMPTY, fourth), new Uint8Array([4]));
  });

  test(`${pattern}: a recorded first message cannot derive the keys of a fresh responder`, () => {
    const { daemon, make } = pair(pattern);
    const { initiator, responder: original } = make();
    const msg1 = initiator.writeMessage(EMPTY);
    original.readMessage(msg1);
    initiator.readMessage(original.writeMessage(EMPTY));
    const record = initiator.split().send.encryptWithAd(EMPTY, new Uint8Array([7]));
    const replayTarget = createNoiseResponder({ pattern, localStatic: daemon, prologue: new TextEncoder().encode("test") });
    replayTarget.readMessage(msg1);
    replayTarget.writeMessage(EMPTY);
    assert.throws(() => replayTarget.split().receive.decryptWithAd(EMPTY, record), NoiseProtocolError);
  });

  test(`${pattern}: rejects a low-order remote ephemeral (invalid DH key)`, () => {
    const { responder } = pair(pattern).make();
    const zeroEphemeral = new Uint8Array(handshakeMessageBytes(pattern, 0));
    assert.throws(() => responder.readMessage(zeroEphemeral), /invalid DH public key/);
  });

  test(`${pattern}: refuses to proceed out of turn or after completion`, () => {
    const { initiator, responder } = pair(pattern, EMPTY).make();
    assert.throws(() => responder.writeMessage(EMPTY), /out of turn/);
    assert.throws(() => initiator.split(), /incomplete/);
    // Out-of-turn writes are refused before any state changes, so the handshake goes on.
    const { initiator: i2, responder: r2 } = pair(pattern, EMPTY).make();
    r2.readMessage(i2.writeMessage(EMPTY));
    assert.throws(() => i2.writeMessage(EMPTY), /out of turn/);
    assert.throws(() => i2.readMessage(EMPTY), NoiseProtocolError, "poisoned after the out-of-turn call");
  });

  test(`${pattern}: oversized and truncated handshake messages are refused`, () => {
    const { responder } = pair(pattern).make();
    assert.throws(() => responder.readMessage(new Uint8Array(NOISE_MAX_MESSAGE_BYTES + 1)), /too large/);
    const { initiator, responder: r2 } = pair(pattern).make();
    assert.throws(() => initiator.writeMessage(new Uint8Array(NOISE_MAX_MESSAGE_BYTES)), /too large/);
    assert.throws(() => r2.readMessage(new Uint8Array(20)), /truncated/);
  });

  test(`${pattern}: split zeroes the injected ephemeral secret and can run once`, () => {
    const ephemeral = generateNoiseKeyPair();
    const { daemon } = pair(pattern);
    const device = generateNoiseKeyPair();
    const initiator = createNoiseInitiator({ pattern, remoteStatic: daemon.publicKey, localStatic: pattern === "IK" ? device : undefined, prologue: EMPTY, ephemeral });
    const responder = createNoiseResponder({ pattern, localStatic: daemon, prologue: EMPTY });
    responder.readMessage(initiator.writeMessage(EMPTY));
    initiator.readMessage(responder.writeMessage(EMPTY));
    initiator.split();
    assert.ok(ephemeral.secretKey.every((b) => b === 0));
    assert.throws(() => initiator.split(), /already split/);
  });
}

test("CipherState stops at the last nonce in both directions and keeps state on a failed tag (vendored, unchanged)", () => {
  const MAX = (1n << 64n) - 1n;
  const key = new Uint8Array(32).map((_, i) => i + 1);
  const sender = new CipherState();
  const receiver = new CipherState();
  sender.initializeKey(key.slice(), MAX - 1n);
  receiver.initializeKey(key.slice(), MAX - 1n);
  const last = sender.encryptWithAd(EMPTY, new Uint8Array([1, 2, 3]));
  assert.equal(sender.nonce(), MAX);
  assert.throws(() => sender.encryptWithAd(EMPTY, new Uint8Array([4])), /nonce exhausted/);
  const tampered = last.slice();
  tampered[0] ^= 1;
  assert.throws(() => receiver.decryptWithAd(EMPTY, tampered), /authentication failed/);
  assert.equal(receiver.nonce(), MAX - 1n);
  assert.deepEqual(Array.from(receiver.decryptWithAd(EMPTY, last)), [1, 2, 3]);
  assert.throws(() => receiver.decryptWithAd(EMPTY, last), /nonce exhausted/);
});
