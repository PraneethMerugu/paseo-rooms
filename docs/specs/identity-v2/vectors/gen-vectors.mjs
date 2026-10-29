// Test-vector generator for the paseo-rooms identity v2 specs.
//
// Run from anywhere with Node 20 or later (Node 24 inside the Paseo binary; the script exits with a clear
// message on older Node):
//   ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin plugin/docs/specs/identity-v2/vectors/gen-vectors.mjs
//
// Writes vectors.json next to this file. Deterministic: every key, nonce and ephemeral is derived
// from fixed labels, so re-running must produce byte-identical output. The script also self-checks
// (signatures verify, negative cases are rejected, Ed25519 agrees between node:crypto and @noble,
// and three Noise engines reproduce the cacophony NK and IK vectors: this file's engine, Paseo's
// published relay 0.13.2 NK module, and Paseo's CipherState/SymmetricState with an added IK
// HandshakeState, which is the proposed vendoring). It exits non-zero on any failure.
//
// Libraries: node:crypto, the @noble packages already in plugin/node_modules (2.4.0), and
// @getpaseo/relay 0.13.2 (dist/noise/, loaded by file path) from plugin/node_modules.
// This file is a specification aid, not production code.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Node version guard. The generator needs Node 20 or later (String.prototype.isWellFormed, and the
// @noble 2.x packages). The @noble imports are dynamic so that this check runs before any of them load.
{
  const major = Number(process.versions.node.split(".")[0]);
  if (!(major >= 20)) {
    console.error(
      `gen-vectors.mjs needs Node 20 or later; this is Node ${process.version}.\n` +
        "Run it with Paseo's bundled Node 24 from the vectors directory:\n" +
        "  ELECTRON_RUN_AS_NODE=1 /opt/Paseo/Paseo.bin gen-vectors.mjs",
    );
    process.exit(2);
  }
}
const { ed25519, x25519 } = await import("@noble/curves/ed25519.js");
const { sha256 } = await import("@noble/hashes/sha2.js");
const { hmac } = await import("@noble/hashes/hmac.js");
const { hkdf } = await import("@noble/hashes/hkdf.js");
const { chacha20poly1305, xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");

const failures = [];
function check(cond, what) {
  if (!cond) failures.push(what);
}

// ------------------------------------------------------------------ bytes helpers
const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8 = (s) => te.encode(s);
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (h) => new Uint8Array(Buffer.from(h, "hex"));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ------------------------------------------------------------------ strict base64url (signatures-and-encoding.md section 4)
const B64U_RE = /^[A-Za-z0-9_-]*$/;
function b64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
/** Strict decode: alphabet, no padding, exact length, canonical trailing bits. Throws on violation. */
function fromB64uStrict(text, expectedBytes) {
  if (typeof text !== "string" || !B64U_RE.test(text)) throw new Error("b64u_alphabet");
  if (text.length % 4 === 1) throw new Error("b64u_length");
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  if (b64u(bytes) !== text) throw new Error("b64u_noncanonical");
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) throw new Error("b64u_size");
  return bytes;
}

// ------------------------------------------------------------------ RJCS: restricted JSON canonicalization (section 2)
const KEY_RE = /^[A-Za-z0-9_]{1,64}$/;
// Keys that are legal JSON but dangerous in JavaScript object handling (spreads, Object.assign, schema transforms).
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_DEPTH = 16;
const MAX_BYTES = 65536;
function rjcs(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error("rjcs_depth");
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error("rjcs_number");
      return String(value);
    case "string":
      if (!value.isWellFormed()) throw new Error("rjcs_lone_surrogate");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v) => rjcs(v, depth + 1)).join(",")}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new Error("rjcs_type");
      const keys = Object.keys(value);
      for (const k of keys) {
        if (!KEY_RE.test(k) || RESERVED_KEYS.has(k)) throw new Error("rjcs_key");
        if (value[k] === undefined) throw new Error("rjcs_undefined");
      }
      keys.sort(); // ASCII-only keys: code-unit order equals RFC 8785 order
      return `{${keys.map((k) => `${JSON.stringify(k)}:${rjcs(value[k], depth + 1)}`).join(",")}}`;
    }
    default:
      throw new Error("rjcs_type");
  }
}
const rjcsBytes = (v) => utf8(rjcs(v));
/** Strict parse: UTF-8, size, JSON, then the received bytes must equal the canonical re-encoding. */
function rjcsParseStrict(bytes) {
  if (bytes.length > MAX_BYTES) throw new Error("rjcs_size");
  const text = td.decode(bytes);
  const value = JSON.parse(text);
  if (rjcs(value) !== text) throw new Error("rjcs_noncanonical");
  return value;
}

// ------------------------------------------------------------------ domain separation (section 3)
const DOMAIN = "paseo-rooms/v2";
const CONTEXTS = [
  "genesis",
  "stmt",
  "log-entry",
  "lane-grant",
  "enroll-request",
  "enroll-token",
  "key-change-new",
  "mls-identity",
];
function tbs(ctx, payload) {
  if (!/^[a-z0-9.:-]{1,64}$/.test(ctx)) throw new Error("bad ctx");
  return concat(utf8(DOMAIN), Uint8Array.of(0), utf8(ctx), Uint8Array.of(0), payload);
}
/** Statement contexts are "stmt:" + event type, so each statement type is its own domain. */
const stmtCtx = (type) => `stmt:${type}`;
/** Domain-separated SHA-256 used for every hash label (kid, entry hash, sas commit, ...). */
function dhash(label, payload) {
  return sha256(tbs(`h:${label}`, payload));
}

// ------------------------------------------------------------------ keys
const ED25519_PKCS8_PREFIX = unhex("302e020100300506032b657004220420");
const ED25519_SPKI_PREFIX = unhex("302a300506032b6570032100");
const seedFor = (name) => sha256(utf8(`paseo-rooms/v2/test-seed/${name}`));
function edKey(name) {
  const seed = seedFor(name);
  const priv = createPrivateKey({ key: Buffer.from(concat(ED25519_PKCS8_PREFIX, seed)), format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  check(equalBytes(pub, ed25519.getPublicKey(seed)), `ed25519 pub mismatch node vs noble (${name})`);
  return { name, alg: "ed25519", seed, priv, pub };
}
function xKey(name) {
  const secret = seedFor(name);
  return { name, alg: "x25519", secret, pub: x25519.getPublicKey(secret) };
}
const ALG_BYTE = { ed25519: 0x01, x25519: 0x02 };
function kidOf(alg, pub) {
  return b64u(dhash("kid", concat(Uint8Array.of(ALG_BYTE[alg]), pub)));
}
function sigOf(key, ctx, payload) {
  const msg = tbs(ctx, payload);
  const sigNode = new Uint8Array(nodeSign(null, Buffer.from(msg), key.priv));
  const sigNoble = ed25519.sign(msg, key.seed);
  check(equalBytes(sigNode, sigNoble), `ed25519 signature mismatch node vs noble (${key.name}, ${ctx})`);
  return sigNode;
}
function verifySig(pub, ctx, payload, sig) {
  const k = createPublicKey({ key: Buffer.from(concat(ED25519_SPKI_PREFIX, pub)), format: "der", type: "spki" });
  return nodeVerify(null, Buffer.from(tbs(ctx, payload)), k, Buffer.from(sig));
}
/** Display fingerprint: base32 (RFC 4648, no padding, lowercase) of the first 20 bytes of the kid digest, groups of 4. */
function fingerprint(alg, pub) {
  const d = fromB64uStrict(kidOf(alg, pub), 32).subarray(0, 20);
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of d) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += A[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out.match(/.{4}/g).join("-");
}
const pubRec = (k) => ({ alg: k.alg, kid: kidOf(k.alg, k.pub), pub: b64u(k.pub) });
const det = (label, n) => sha256(utf8(`paseo-rooms/v2/test-random/${label}`)).subarray(0, n);
const detHex = (label, n) => hex(det(label, n));

const keys = {
  adminA: edKey("admin-a"),
  adminA2: edKey("admin-a-rotated"),
  adminB: edKey("admin-b"),
  adminC: edKey("admin-c"),
  recovery: edKey("recovery"),
  recovery2: edKey("recovery-2"),
  host: edKey("host-1"),
  host2: edKey("host-2"),
  creatorDevSig: edKey("alice-desktop-sig"),
  devSig: edKey("sam-laptop-sig"),
  devSig2: edKey("sam-laptop-sig-rotated"),
  devMls: edKey("sam-laptop-mls"),
  phoneSig: edKey("sam-phone-sig"),
  node: edKey("gateway-node"),
  endpoint: xKey("room-endpoint"),
  laneDh: xKey("lane-endpoint"),
  creatorDevDh: xKey("alice-desktop-dh"),
  devDh: xKey("sam-laptop-dh"),
  devDh2: xKey("sam-laptop-dh-rotated"),
  phoneDh: xKey("sam-phone-dh"),
  ghostSig: edKey("ghost-device-sig"),
  ghostDh: xKey("ghost-device-dh"),
};

// ------------------------------------------------------------------ Noise engine (IK and NK), Noise spec rev 34
function hkdfNoise(ck, ikm, n) {
  const temp = hmac(sha256, ck, ikm);
  const o1 = hmac(sha256, temp, Uint8Array.of(1));
  const o2 = hmac(sha256, temp, concat(o1, Uint8Array.of(2)));
  if (n === 2) return [o1, o2];
  const o3 = hmac(sha256, temp, concat(o2, Uint8Array.of(3)));
  return [o1, o2, o3];
}
function nonce12(n) {
  const b = new Uint8Array(12);
  new DataView(b.buffer).setBigUint64(4, BigInt(n), true);
  return b;
}
class Cipher {
  constructor(k = null) {
    this.k = k;
    this.n = 0;
  }
  enc(ad, pt) {
    if (!this.k) return pt;
    return chacha20poly1305(this.k, nonce12(this.n++), ad).encrypt(pt);
  }
  dec(ad, ct) {
    if (!this.k) return ct;
    return chacha20poly1305(this.k, nonce12(this.n++), ad).decrypt(ct);
  }
}
const PATTERNS = {
  NK: { pre: "s", msgs: [["e", "es"], ["e", "ee"]] },
  IK: { pre: "s", msgs: [["e", "es", "s", "ss"], ["e", "ee", "se"]] },
};
class Handshake {
  constructor({ pattern, initiator, prologue, s = null, rs = null, e }) {
    const name = `Noise_${pattern}_25519_ChaChaPoly_SHA256`;
    const nb = utf8(name);
    this.h = nb.length <= 32 ? concat(nb, new Uint8Array(32 - nb.length)) : sha256(nb);
    this.ck = this.h.slice();
    this.c = new Cipher();
    this.p = PATTERNS[pattern];
    this.init = initiator;
    this.s = s;
    this.rs = rs;
    this.e = e;
    this.re = null;
    this.i = 0;
    this.mixHash(prologue);
    this.mixHash(initiator ? rs : s.pub); // pre-message "<- s"
  }
  mixHash(d) {
    this.h = sha256(concat(this.h, d));
  }
  mixKey(ikm) {
    const [ck, k] = hkdfNoise(this.ck, ikm, 2);
    this.ck = ck;
    this.c = new Cipher(k);
  }
  encHash(pt) {
    const ct = this.c.enc(this.h, pt);
    this.mixHash(ct);
    return ct;
  }
  decHash(ct) {
    const pt = this.c.dec(this.h, ct);
    this.mixHash(ct);
    return pt;
  }
  dh(tok) {
    const I = this.init;
    let pair;
    if (tok === "ee") pair = [this.e.secret, this.re];
    else if (tok === "es") pair = I ? [this.e.secret, this.rs] : [this.s.secret, this.re];
    else if (tok === "se") pair = I ? [this.s.secret, this.re] : [this.e.secret, this.rs];
    else pair = [this.s.secret, this.rs];
    this.mixKey(x25519.getSharedSecret(pair[0], pair[1]));
  }
  write(payload) {
    const parts = [];
    for (const t of this.p.msgs[this.i]) {
      if (t === "e") {
        parts.push(this.e.pub);
        this.mixHash(this.e.pub);
      } else if (t === "s") parts.push(this.encHash(this.s.pub));
      else this.dh(t);
    }
    parts.push(this.encHash(payload));
    this.i++;
    return concat(...parts);
  }
  read(msg) {
    let o = 0;
    for (const t of this.p.msgs[this.i]) {
      if (t === "e") {
        this.re = msg.subarray(o, o + 32);
        o += 32;
        this.mixHash(this.re);
      } else if (t === "s") {
        const len = this.c.k ? 48 : 32;
        this.rs = this.decHash(msg.subarray(o, o + len));
        o += len;
      } else this.dh(t);
    }
    const pt = this.decHash(msg.subarray(o));
    this.i++;
    return pt;
  }
  split() {
    const [k1, k2] = hkdfNoise(this.ck, new Uint8Array(0), 2);
    return this.init ? { send: new Cipher(k1), recv: new Cipher(k2) } : { send: new Cipher(k2), recv: new Cipher(k1) };
  }
}
const kp = (secretHex) => {
  const secret = unhex(secretHex);
  return { secret, pub: x25519.getPublicKey(secret) };
};

// ------------------------------------------------------------------ cacophony reference vectors
// Copied verbatim from rweather/noise-c tests/vector/cacophony.txt at commit
// cfe25410979a87391bb9ac8d4d4bef64e9f268c6 (file sha256 e1b0c4100b6c6e76378705a4954c3293f3752a55b586a3a252cecbfc937538c9,
// fetched read-only on 2026-10-29). The NK entry is the same vector Paseo's relay tests use
// (packages/relay/src/noise/fixtures/nk-25519-chachapoly-sha256.json). All six messages of each entry are checked:
// two handshake messages, then four transport messages alternating initiator -> responder, responder -> initiator.
const CACOPHONY_SOURCE = {
  url: "https://raw.githubusercontent.com/rweather/noise-c/cfe25410979a87391bb9ac8d4d4bef64e9f268c6/tests/vector/cacophony.txt",
  sha256: "e1b0c4100b6c6e76378705a4954c3293f3752a55b586a3a252cecbfc937538c9",
};
const CACO_COMMON = {
  prologue: "4a6f686e2047616c74",
  init_ephemeral: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  resp_static: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  resp_ephemeral: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  init_remote_static: "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
};
const CACO_PAYLOADS = [
  "4c756477696720766f6e204d69736573",
  "4d757272617920526f746862617264",
  "462e20412e20486179656b",
  "4361726c204d656e676572",
  "4a65616e2d426170746973746520536179",
  "457567656e2042f6686d20766f6e2042617765726b",
];
const CACO_VECTORS = {
  NK: {
    name: "Noise_NK_25519_ChaChaPoly_SHA256",
    ...CACO_COMMON,
    init_static: null,
    ciphertexts: [
      "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448134d00711fdb390a0d178fa008f6d47d2891e5ea18ae136c3b4c23ac384efb0",
      "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438ea16e3701bc0d77744f117bee22451c9afa7f4cdbbcff00c04a8ee0913c88",
      "a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0",
      "174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff",
      "337e475ebb8eae60f91974c4e455a5af38d1d8628d1803b160d60442874b0a1777",
      "047e80e060b7bb08b53c5a23dfe9920cae135b9d1dc6302fc475003062723700366346ac9d",
    ],
  },
  IK: {
    name: "Noise_IK_25519_ChaChaPoly_SHA256",
    ...CACO_COMMON,
    init_static: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
    ciphertexts: [
      "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7",
      "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5",
      "050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8",
      "344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667",
      "62cdeeb172ad7ade7aa7d9e069da5790f12331bfa00177787a1d0810c67dc3b2b4",
      "029bead1b40992327044d409d9a1f3ad8f36c3c452775d557e18bbeb2e8dfcead32d514024",
    ],
  },
};
// Short aliases used by the vectors below.
const NK = { prologue: CACO_COMMON.prologue, init_ephemeral: CACO_COMMON.init_ephemeral, resp_static: CACO_COMMON.resp_static, resp_ephemeral: CACO_COMMON.resp_ephemeral };
const CACO = { init_static: CACO_VECTORS.IK.init_static, payloads: CACO_PAYLOADS.slice(0, 4) };

// Runs one cacophony entry through an engine adapter and compares every byte.
// adapter(pattern, initiator, opts) returns { write(payload), read(msg), split() -> { send, recv } }
// where send.enc(pt) and recv.dec(ct) use empty associated data.
function checkCacophony(engine, adapter, pattern) {
  const v = CACO_VECTORS[pattern];
  check(hex(x25519.getPublicKey(unhex(v.resp_static))) === v.init_remote_static, `${engine} ${pattern}: responder static mismatch`);
  const iOpts = { prologue: unhex(v.prologue), rs: unhex(v.init_remote_static), e: kp(v.init_ephemeral), s: v.init_static ? kp(v.init_static) : null };
  const rOpts = { prologue: unhex(v.prologue), s: kp(v.resp_static), e: kp(v.resp_ephemeral) };
  let ok = true;
  const expect = (cond, what) => {
    if (!cond) ok = false;
    check(cond, `${engine} ${pattern}: ${what}`);
  };
  try {
    const ini = adapter(pattern, true, iOpts);
    const res = adapter(pattern, false, rOpts);
    const m1 = ini.write(unhex(CACO_PAYLOADS[0]));
    expect(hex(m1) === v.ciphertexts[0], "message 1 ciphertext");
    expect(hex(res.read(m1)) === CACO_PAYLOADS[0], "message 1 payload");
    const m2 = res.write(unhex(CACO_PAYLOADS[1]));
    expect(hex(m2) === v.ciphertexts[1], "message 2 ciphertext");
    expect(hex(ini.read(m2)) === CACO_PAYLOADS[1], "message 2 payload");
    const ti = ini.split();
    const tr = res.split();
    for (let k = 2; k < CACO_PAYLOADS.length; k++) {
      const fromInit = k % 2 === 0;
      const ct = (fromInit ? ti.send : tr.send).enc(unhex(CACO_PAYLOADS[k]));
      expect(hex(ct) === v.ciphertexts[k], `transport message ${k + 1} ciphertext`);
      expect(hex((fromInit ? tr.recv : ti.recv).dec(ct)) === CACO_PAYLOADS[k], `transport message ${k + 1} payload`);
    }
  } catch (e) {
    expect(false, `threw ${e.message}`);
  }
  return ok ? `passed (${v.name}, 6 of 6 messages)` : "FAILED";
}

// Engine 1: the generator's own reference engine (Handshake class above).
const ownAdapter = (pattern, initiator, o) => {
  const hs = new Handshake({ pattern, initiator, prologue: o.prologue, s: o.s, rs: initiator ? o.rs : null, e: o.e });
  const z = new Uint8Array(0);
  return {
    write: (p) => hs.write(p),
    read: (m) => hs.read(m),
    split: () => {
      const { send, recv } = hs.split();
      return { send: { enc: (pt) => send.enc(z, pt) }, recv: { dec: (ct) => recv.dec(z, ct) } };
    },
  };
};

// Engines 2 and 3: Paseo's Noise module as published in @getpaseo/relay 0.13.2 (dist/noise/). It is not in the
// package exports, so it is loaded by file path from plugin/node_modules. Engine 2 is Paseo's NK HandshakeState,
// unchanged. Engine 3 is the proposed vendoring: Paseo's CipherState and SymmetricState used unchanged, with a
// HandshakeState that adds the IK tokens (s, se, ss) in the same token-by-token style as Paseo's NK code.
const relayNoiseDir = join(dirname(fileURLToPath(import.meta.url)), "../../../../node_modules/@getpaseo/relay/dist/noise");
const paseoNoise = await import(pathToFileURL(join(relayNoiseDir, "index.js")).href);
const { SymmetricState: PaseoSymmetricState } = await import(pathToFileURL(join(relayNoiseDir, "symmetric-state.js")).href);
const { NoiseProtocolError: PaseoNoiseError } = await import(pathToFileURL(join(relayNoiseDir, "cipher-state.js")).href);
const paseoKp = (k) => (k ? { secretKey: k.secret, publicKey: k.pub } : null);
const wrapPaseoSplit = (keys) => {
  const z = new Uint8Array(0);
  return { send: { enc: (pt) => keys.send.encryptWithAd(z, pt) }, recv: { dec: (ct) => keys.receive.decryptWithAd(z, ct) } };
};
const paseoNkAdapter = (pattern, initiator, o) => {
  if (pattern !== "NK") throw new Error("Paseo relay 0.13.2 ships NK only");
  const hs = initiator
    ? paseoNoise.createNoiseInitiator({ remoteStatic: o.rs, prologue: o.prologue, ephemeral: paseoKp(o.e) })
    : paseoNoise.createNoiseResponder({ localStatic: paseoKp(o.s), prologue: o.prologue, ephemeral: paseoKp(o.e) });
  return { write: (p) => hs.writeMessage(p), read: (m) => hs.readMessage(m), split: () => wrapPaseoSplit(hs.split()) };
};

const VENDORED_PATTERNS = {
  NK: [["e", "es"], ["e", "ee"]],
  IK: [["e", "es", "s", "ss"], ["e", "ee", "se"]],
};
class VendoredHandshake {
  constructor({ pattern, initiator, prologue, s, rs, e }) {
    this.messages = VENDORED_PATTERNS[pattern];
    this.symmetric = new PaseoSymmetricState(`Noise_${pattern}_25519_ChaChaPoly_SHA256`);
    this.initiator = initiator;
    this.s = s;
    this.rs = rs;
    this.e = e;
    this.re = null;
    this.index = 0;
    this.symmetric.mixHash(prologue);
    const pre = initiator ? rs : s?.publicKey; // pre-message "<- s" (NK and IK)
    if (!pre || pre.byteLength !== 32) throw new PaseoNoiseError("missing responder static key");
    this.symmetric.mixHash(pre);
  }
  tokens(selfWrites) {
    if (this.index >= this.messages.length) throw new PaseoNoiseError("handshake complete");
    const writerIsInitiator = this.index % 2 === 0;
    if (writerIsInitiator !== (selfWrites ? this.initiator : !this.initiator)) throw new PaseoNoiseError("handshake message out of turn");
    return this.messages[this.index];
  }
  dh(token) {
    // Noise rev 34 section 7: the first letter names the initiator's key, the second the responder's.
    const I = this.initiator;
    const [local, remote] = {
      ee: [this.e, this.re],
      es: I ? [this.e, this.rs] : [this.s, this.re],
      se: I ? [this.s, this.re] : [this.e, this.rs],
      ss: [this.s, this.rs],
    }[token];
    if (!local || !remote) throw new PaseoNoiseError("missing DH key");
    const shared = x25519.getSharedSecret(local.secretKey, remote);
    if (shared.every((b) => b === 0)) throw new PaseoNoiseError("invalid DH public key");
    this.symmetric.mixKey(shared);
    shared.fill(0);
  }
  writeMessage(payload) {
    const parts = [];
    for (const t of this.tokens(true)) {
      if (t === "e") {
        parts.push(this.e.publicKey);
        this.symmetric.mixHash(this.e.publicKey);
      } else if (t === "s") parts.push(this.symmetric.encryptAndHash(this.s.publicKey));
      else this.dh(t);
    }
    parts.push(this.symmetric.encryptAndHash(payload));
    this.index++;
    return concat(...parts);
  }
  readMessage(msg) {
    let o = 0;
    const take = (n) => {
      if (msg.byteLength < o + n) throw new PaseoNoiseError("handshake message truncated");
      const out = msg.slice(o, o + n);
      o += n;
      return out;
    };
    for (const t of this.tokens(false)) {
      if (t === "e") {
        this.re = take(32);
        this.symmetric.mixHash(this.re);
      } else if (t === "s") {
        this.rs = this.symmetric.decryptAndHash(take(this.symmetric.cipher.hasKey() ? 48 : 32));
      } else this.dh(t);
    }
    const payload = this.symmetric.decryptAndHash(msg.slice(o));
    this.index++;
    return payload;
  }
  split() {
    if (this.index < this.messages.length) throw new PaseoNoiseError("handshake incomplete");
    const [c1, c2] = this.symmetric.split();
    return this.initiator ? { send: c1, receive: c2 } : { send: c2, receive: c1 };
  }
}
const vendoredAdapter = (pattern, initiator, o) => {
  const hs = new VendoredHandshake({ pattern, initiator, prologue: o.prologue, s: paseoKp(o.s), rs: initiator ? o.rs : null, e: paseoKp(o.e) });
  return { write: (p) => hs.writeMessage(p), read: (m) => hs.readMessage(m), split: () => wrapPaseoSplit(hs.split()) };
};

const cacophonyChecks = {
  source: CACOPHONY_SOURCE,
  generatorEngine: { NK: checkCacophony("generator engine", ownAdapter, "NK"), IK: checkCacophony("generator engine", ownAdapter, "IK") },
  paseoRelay0132Unmodified: { NK: checkCacophony("paseo relay 0.13.2", paseoNkAdapter, "NK") },
  vendoredPaseoWithIk: { NK: checkCacophony("vendored paseo + IK", vendoredAdapter, "NK"), IK: checkCacophony("vendored paseo + IK", vendoredAdapter, "IK") },
};

function runIK({ prologue, iStatic, rStatic, iEph, rEph, payloads }) {
  const ini = new Handshake({ pattern: "IK", initiator: true, prologue, s: iStatic, rs: rStatic.pub, e: iEph });
  const res = new Handshake({ pattern: "IK", initiator: false, prologue, s: rStatic, e: rEph });
  const m1 = ini.write(payloads[0]);
  const p1 = res.read(m1);
  check(equalBytes(p1, payloads[0]), "IK payload 1 roundtrip");
  check(equalBytes(res.rs, iStatic.pub), "IK responder learned initiator static");
  const m2 = res.write(payloads[1]);
  const p2 = ini.read(m2);
  check(equalBytes(p2, payloads[1]), "IK payload 2 roundtrip");
  check(equalBytes(ini.h, res.h), "IK handshake hashes agree");
  const ti = ini.split();
  const tr = res.split();
  const out = [{ payload: hex(payloads[0]), ciphertext: hex(m1) }, { payload: hex(payloads[1]), ciphertext: hex(m2) }];
  for (let k = 2; k < payloads.length; k++) {
    const fromInit = k % 2 === 0;
    const ct = (fromInit ? ti.send : tr.send).enc(new Uint8Array(0), payloads[k]);
    const pt = (fromInit ? tr.recv : ti.recv).dec(new Uint8Array(0), ct);
    check(equalBytes(pt, payloads[k]), `IK transport ${k} roundtrip`);
    out.push({ payload: hex(payloads[k]), ciphertext: hex(ct) });
  }
  return { handshakeHash: hex(ini.h), messages: out };
}

// IK with the cacophony keys and the first four payloads. Checked byte for byte against the
// cacophony.txt entry "Noise_IK_25519_ChaChaPoly_SHA256" (CACO_VECTORS.IK) just below.
const ikCacophonyKeys = runIK({
  prologue: unhex(NK.prologue),
  iStatic: kp(CACO.init_static),
  rStatic: kp(NK.resp_static),
  iEph: kp(NK.init_ephemeral),
  rEph: kp(NK.resp_ephemeral),
  payloads: CACO.payloads.map(unhex),
});
ikCacophonyKeys.messages.forEach((m, k) =>
  check(m.ciphertext === CACO_VECTORS.IK.ciphertexts[k], `noise.ikCacophonyKeys message ${k + 1} differs from cacophony IK`),
);


// ------------------------------------------------------------------ room genesis (identity-model.md section 5)
const relay = { host: "relay.paseo.sh", port: 443, tls: true };
const endpointServerId = `rme_${b64u(det("endpoint-server-id", 24))}`;
const policy0 = {
  minVersion: 2,
  sas: "sas6",
  deviceAddApproval: "same-person",
  rotateLaneOnRemove: "compromise",
  recoveryEscrow: "none",
  soleDeviceChange: "held",
  projectNames: "lane-owner",
  grantTtl: 43200,
  closeDelay: 86400,
};
const genesisBody = {
  v: 2,
  typ: "room-genesis",
  createdAt: 1793232000,
  nonce: b64u(det("genesis-nonce", 16)),
  admins: [pubRec(keys.adminA)],
  adminThreshold: 1,
  recovery: pubRec(keys.recovery),
  host: { key: pubRec(keys.host), notBefore: 1793232000, notAfter: null },
  endpoint: { serverId: endpointServerId, dh: pubRec(keys.endpoint), relay },
  policy: policy0,
};
const genesisSig = sigOf(keys.adminA, "genesis", rjcsBytes(genesisBody));
const genesisSigned = { body: genesisBody, kid: kidOf("ed25519", keys.adminA.pub), sig: b64u(genesisSig) };
const genesisHash = dhash("genesis", rjcsBytes(genesisSigned));
const roomId = `room_${hex(genesisHash.subarray(0, 16))}`;
const endpointRec = { serverId: endpointServerId, dh: pubRec(keys.endpoint), relay };

// ------------------------------------------------------------------ invite (enrollment-v2.md section 2)
const inviteToken = det("invite-token", 32);
const inviteId = `inv_${detHex("invite-id", 16)}`;
const inviteRef = b64u(dhash("invite-ref", utf8(inviteId)));
const invitePayload = {
  v: 2,
  typ: "invite",
  roomId,
  genesisHash: b64u(genesisHash),
  roomName: "Lab analysis",
  endpoint: endpointRec,
  inviteId,
  token: b64u(inviteToken),
  exp: 1793233800,
  sas: "sas6",
};
const inviteCode = `prc2.${b64u(rjcsBytes(invitePayload))}`;

// ------------------------------------------------------------------ enrollment: Noise IK, token MAC, SAS
const noisePrologue = concat(
  utf8(DOMAIN),
  Uint8Array.of(0),
  utf8("noise-ik"),
  Uint8Array.of(0),
  rjcsBytes({ genesisHash: b64u(genesisHash), serverId: endpointServerId }),
);
const ephemeral = (label) => ({ secret: det(label, 32), pub: x25519.getPublicKey(det(label, 32)) });
const ikEnroll = runIK({
  prologue: noisePrologue,
  iStatic: { secret: keys.devDh.secret, pub: keys.devDh.pub },
  rStatic: { secret: keys.endpoint.secret, pub: keys.endpoint.pub },
  iEph: ephemeral("ik-init-ephemeral"),
  rEph: ephemeral("ik-resp-ephemeral"),
  payloads: [new Uint8Array(0), new Uint8Array(0)],
});
const h = unhex(ikEnroll.handshakeHash);
const Nm = det("sas-member-nonce", 32);
const Nh = det("sas-host-nonce", 32);
const sasCommit = dhash("sas-commit", Nm);
const enrollSigned = {
  v: 2,
  typ: "enroll-request",
  h: b64u(h),
  genesisHash: b64u(genesisHash),
  inviteId,
  deviceSig: b64u(keys.devSig.pub),
  deviceDh: b64u(keys.devDh.pub),
  label: "Sam laptop",
  sasCommit: b64u(sasCommit),
};
const enrollSig = sigOf(keys.devSig, "enroll-request", rjcsBytes(enrollSigned));
const tokenKey = hkdf(sha256, inviteToken, new Uint8Array(0), tbs("invite-token-key", new Uint8Array(0)), 32);
const tokenMac = hmac(sha256, tokenKey, tbs("enroll-token", rjcsBytes(enrollSigned)));
const enrollFrame = {
  t: "enroll.request",
  v: 2,
  inviteId,
  deviceSig: enrollSigned.deviceSig,
  deviceDh: enrollSigned.deviceDh,
  label: enrollSigned.label,
  sasCommit: enrollSigned.sasCommit,
  tokenMac: b64u(tokenMac),
  sig: b64u(enrollSig),
};
/** SAS derivation (enrollment-v2.md section 6.2). `target` is { inviteId } or { linkId }. */
function sasFor({ hBytes, nm, nc, deviceSigPub, deviceDhPub, target }) {
  const info = rjcsBytes({
    deviceDh: b64u(deviceDhPub),
    deviceSig: b64u(deviceSigPub),
    endpointDh: b64u(keys.endpoint.pub),
    genesisHash: b64u(genesisHash),
    ...target,
  });
  const key = hkdf(sha256, concat(nm, nc), hBytes, tbs("sas", info), 8);
  const num = new DataView(key.buffer, key.byteOffset, 8).getBigUint64(0, false) % 1000000n;
  const digits = num.toString().padStart(6, "0");
  const transcript = dhash("sas-transcript", concat(hBytes, nm, nc, info));
  return { info, key, digits, transcript };
}
const sas = sasFor({ hBytes: h, nm: Nm, nc: Nh, deviceSigPub: keys.devSig.pub, deviceDhPub: keys.devDh.pub, target: { inviteId } });

// ------------------------------------------------------------------ ids, roster entries, statements
const creatorMemberId = `mem_${detHex("creator-member-id", 16)}`;
const creatorDeviceId = `dev_${detHex("creator-device-id", 16)}`;
const memberId = `mem_${detHex("member-id", 16)}`;
const deviceId = `dev_${detHex("device-id", 16)}`;
const phoneDeviceId = `dev_${detHex("phone-device-id", 16)}`;
const laneId = `lane_${detHex("lane-id", 16)}`;
const laneServerId = `rle_${b64u(det("lane-server-id", 24))}`;
const laneOffer = { serverId: laneServerId, dh: pubRec(keys.laneDh), relay };
const deviceEntry = (id, sigK, dhK) => ({ deviceId: id, kind: "person", sig: b64u(sigK.pub), dh: b64u(dhK.pub) });
const creatorEntry = {
  memberId: creatorMemberId,
  role: "admin",
  lanes: [],
  devices: [deviceEntry(creatorDeviceId, keys.creatorDevSig, keys.creatorDevDh)],
};
const rosterEntry = { memberId, role: "watch", lanes: [laneId], devices: [deviceEntry(deviceId, keys.devSig, keys.devDh)] };

/** Roster hash for the roster whose last roster-changing entry is `rosterSeq` (room-log-v2.md section 5). */
function rosterHashOf(rosterSeq, members) {
  const sorted = [...members].sort((a, b) => (a.memberId < b.memberId ? -1 : a.memberId > b.memberId ? 1 : 0));
  return b64u(dhash("roster", rjcsBytes({ roomId, seq: rosterSeq, members: sorted })));
}
const genesisBase = { seq: -1, hash: b64u(genesisHash) };
const baseOf = (e) => ({ seq: e.entry.seq, hash: e.hash });
const producerKeys = new Map();
function statement(producerKey, producerKind, type, data, ts, base) {
  producerKeys.set(kidOf("ed25519", producerKey.pub), producerKey.pub);
  const body = { v: 2, typ: "stmt", type, roomId, producer: { kind: producerKind, kid: kidOf("ed25519", producerKey.pub) }, base, ts, data };
  const sig = sigOf(producerKey, stmtCtx(type), rjcsBytes(body));
  check(verifySig(producerKey.pub, stmtCtx(type), rjcsBytes(body), sig), `stmt ${type} verifies`);
  const other = type === "member.removed" ? "member.left" : "member.removed";
  check(!verifySig(producerKey.pub, stmtCtx(other), rjcsBytes(body), sig), `stmt ${type} must not verify under stmt:${other}`);
  return { body, sig: b64u(sig) };
}
const bodyHashOf = (stmtSigned) => b64u(dhash("log-body", rjcsBytes(stmtSigned)));

// ------------------------------------------------------------------ log entries (room-log-v2.md section 3)
function entryFor(seq, prevHashBytes, stmtSigned, hts, epoch, hostKey = keys.host) {
  const entry = {
    v: 2,
    typ: "log-entry",
    roomId,
    seq,
    prev: b64u(prevHashBytes),
    hts,
    epoch,
    cls: "stmt",
    type: stmtSigned.body.type,
    bodyHash: bodyHashOf(stmtSigned),
    hostKid: kidOf("ed25519", hostKey.pub),
  };
  const eb = rjcsBytes(entry);
  const hash = dhash("log-entry", eb);
  const hsig = sigOf(hostKey, "log-entry", eb);
  return { entry, hash: b64u(hash), hsig: b64u(hsig), hashBytes: hash, statement: stmtSigned };
}
const gid = `g_${detHex("grant-id", 16)}`;
// Main chain. seq 0 is the creator's own admission; seq 1 (lane.created) and seq 3 (grant.issued) do not change
// the roster, so the roster position stays at the last roster-changing entry (S-14).
const s0 = statement(keys.adminA, "admin", "member.admitted", { member: creatorEntry, confirmation: { method: "creator" } }, 1793232000050, genesisBase);
const e0 = entryFor(0, genesisHash, s0, 1793232000100, 0);
const s1 = statement(keys.adminA, "admin", "lane.created", { laneId, owner: creatorMemberId, offer: laneOffer, visibility: "room" }, 1793232060000, baseOf(e0));
const e1 = entryFor(1, e0.hashBytes, s1, 1793232060100, 0);
const s2 = statement(
  keys.adminA,
  "admin",
  "member.admitted",
  { member: rosterEntry, confirmation: { method: "sas6", inviteRef, transcript: b64u(sas.transcript) } },
  1793232300000,
  baseOf(e1),
);
const e2 = entryFor(2, e1.hashBytes, s2, 1793232300100, 0);
const s3 = statement(keys.host, "host", "grant.issued", { memberId, deviceId, laneId, gid, exp: 1793275600 }, 1793232400000, baseOf(e2));
const e3 = entryFor(3, e2.hashBytes, s3, 1793232400100, 0);
const s4 = statement(keys.devSig, "device", "member.left", { memberId }, 1793235900000, baseOf(e3));
const e4 = entryFor(4, e3.hashBytes, s4, 1793235900100, 0);
const chain = [e0, e1, e2, e3, e4];
const publicEntry = ({ entry, hash, hsig }) => ({ entry, hash, hsig });

// Fold (room-log-v2.md section 5) covering the rules these vectors exercise: chain links, host signatures,
// bodyHash, producer authority and signature, the base, unique, forward-base and ref rules (S-1, R-1, R-10),
// field versions (section 4.0), the creator rule for seq 0, device denylist and retired keys, device holds
// for adds and rekeys (24 h, 72 h for a sole device), vetoes, conflicts and cancellation (R-8), admin lineages and closure
// (section 5.2), and one level of revocation re-fold with the roster position rule (section 5.1, R-7).
// Decision round 8 adds: positional host keys and host.key.rotated, keys that never return after a re-fold
// (retired keys, devices with retired keys, the host-key table kept with an uncertified mark), the revocation
// nesting depth cap of 8, and device.leaf.repair.requested with its rate limits.
// It is a checking aid, not the full fold: nested or competing revocations are not modelled (the production
// fold's fixed point over flat passes is tested against these vectors instead).
const HOUR = 3600000;
const kidEd = (pub) => kidOf("ed25519", pub);
const sortById = (arr, k) => [...arr].sort((a, b) => (a[k] < b[k] ? -1 : a[k] > b[k] ? 1 : 0));
function initState() {
  const a = kidEd(keys.adminA.pub);
  return {
    hashes: [],
    seen: new Set(),
    members: new Map(), // memberId -> RosterEntry (exactly the roster fields)
    deviceSince: new Map(), // deviceId -> hts at which it became active
    everMember: new Set(),
    everDevice: new Set(),
    denied: new Set(),
    retired: new Set(),
    admins: new Map([[a, { pub: keys.adminA.pub, fromSeq: 0, since: 0, root: a, addedBy: null, revokedAt: null }]]),
    recovery: { kid: kidEd(keys.recovery.pub), pub: keys.recovery.pub, fromSeq: 0, since: 0 },
    hostKeys: [{ kid: kidEd(keys.host.pub), pub: keys.host.pub, fromSeq: 0, toSeq: null, uncertified: false }],
    repairs: [], // device.leaf.repair.requested of the last 24 h: { deviceId, scope, generation, hts }
    revDepths: [], // { seq, depth } of every admin.key.revoked entry
    policy: { ...policy0 },
    versions: new Map(),
    maxBase: new Map(),
    pending: new Map(), // bodyHash -> request
    conflicts: new Map(), // memberId -> seq of the veto
    proposals: new Map(), // bodyHash -> close proposal
    closed: false,
    rosterSeq: null,
    revs: [],
  };
}
const rosterKey = (st) => rjcs(sortById([...st.members.values()], "memberId"));
const ver = (st, field, initial = -1) => (st.versions.has(field) ? st.versions.get(field) : initial);
function findDevice(st, pub) {
  for (const m of st.members.values()) for (const d of m.devices) if (d.sig === b64u(pub)) return { member: m, device: d };
  return null;
}
function cancelPending(st, pred) {
  for (const p of st.pending.values()) if (!p.done && pred(p)) p.cancelled = true;
}
/** Producer authority at this position (room-log-v2.md section 4). Returns the public key or null. */
function producerPub(st, body) {
  const { kind, kid } = body.producer;
  if (kind === "admin") {
    const a = st.admins.get(kid);
    return a && a.revokedAt === null ? a.pub : null;
  }
  if (kind === "recovery") return st.recovery && st.recovery.kid === kid ? st.recovery.pub : null;
  if (kind === "host") {
    const h = st.hostKeys.find((x) => x.kid === kid && x.toSeq === null);
    return h ? h.pub : null;
  }
  if (kind === "device") {
    const pub = producerKeys.get(kid);
    return pub && findDevice(st, pub) ? pub : null;
  }
  return null;
}
/** apply: validates everything first, then mutates. Returns null on success or an error name. */
function apply(st, body, pub, entry, bodyHash) {
  const d = body.data;
  const seq = entry.seq;
  const hts = entry.hts;
  const producerKid = body.producer.kid;
  const kind = body.producer.kind;
  if (st.closed) return "room_closed";
  switch (body.type) {
    case "member.admitted": {
      if (kind !== "admin") return "producer_not_allowed";
      if (seq === 0 && d.confirmation.method !== "creator") return "seq0_not_creator";
      if (seq !== 0 && d.confirmation.method === "creator") return "creator_after_seq0";
      if (st.everMember.has(d.member.memberId)) return "member_id_reused";
      if (d.member.devices.length < 1 || d.member.devices.length > 8) return "device_count";
      for (const dev of d.member.devices) {
        if (st.everDevice.has(dev.deviceId)) return "device_id_reused";
        if (st.denied.has(dev.sig) || st.denied.has(dev.dh) || st.retired.has(dev.sig)) return "denylisted_key";
      }
      st.members.set(d.member.memberId, structuredClone(d.member));
      st.everMember.add(d.member.memberId);
      for (const dev of d.member.devices) {
        st.everDevice.add(dev.deviceId);
        st.deviceSince.set(dev.deviceId, hts);
      }
      st.versions.set(`role:${d.member.memberId}`, seq);
      st.versions.set(`lanes:${d.member.memberId}`, seq);
      st.versions.set(`devices:${d.member.memberId}`, seq);
      return null;
    }
    case "member.role.changed": {
      if (kind !== "admin") return "producer_not_allowed";
      const m = st.members.get(d.memberId);
      if (!m) return "unknown_member";
      if (d.ver !== ver(st, `role:${d.memberId}`)) return "stale_version";
      m.role = d.role;
      st.versions.set(`role:${d.memberId}`, seq);
      return null;
    }
    case "member.left": {
      const m = st.members.get(d.memberId);
      if (!m) return "unknown_member";
      if (m.devices.length !== 1 || m.devices[0].sig !== b64u(pub)) return "left_not_only_device";
      for (const dev of m.devices) st.denied.add(dev.sig).add(dev.dh);
      st.members.delete(d.memberId);
      cancelPending(st, (p) => p.memberId === d.memberId);
      return null;
    }
    case "member.removed": {
      if (kind !== "admin") return "producer_not_allowed";
      const m = st.members.get(d.memberId);
      if (!m) return "unknown_member";
      for (const dev of m.devices) st.denied.add(dev.sig).add(dev.dh);
      st.members.delete(d.memberId);
      cancelPending(st, (p) => p.memberId === d.memberId);
      return null;
    }
    case "device.link.created": {
      const f = findDevice(st, pub);
      if (kind !== "device" || !f || f.member.memberId !== d.memberId) return "producer_not_allowed";
      return null;
    }
    case "device.added": {
      const f = findDevice(st, pub);
      if (kind !== "device" || !f || f.member.memberId !== d.memberId || f.device.deviceId !== d.addedBy) return "producer_not_allowed";
      if (d.change.old !== null) return "stale_version";
      if (st.everDevice.has(d.device.deviceId)) return "device_id_reused";
      if (st.denied.has(d.device.sig) || st.denied.has(d.device.dh) || st.retired.has(d.device.sig)) return "denylisted_key";
      if (!verifySig(fromB64uStrict(d.change.newSig, 32), "key-change-new", rjcsBytes(d.change), fromB64uStrict(d.newKeySig, 64))) return "new_key_sig";
      st.pending.set(bodyHash, {
        kind: "add",
        memberId: d.memberId,
        device: d.device,
        requester: d.addedBy,
        seq,
        hts,
        sole: f.member.devices.length === 1,
        young: hts - st.deviceSince.get(d.addedBy) < 24 * HOUR,
        vetoed: false,
        cancelled: false,
        done: false,
      });
      return null;
    }
    case "device.add.vetoed": {
      const f = findDevice(st, pub);
      const p = st.pending.get(d.ref);
      if (kind !== "device" || !f || f.member.memberId !== d.memberId) return "producer_not_allowed";
      if (!p || p.done || p.cancelled || p.memberId !== d.memberId) return "not_pending";
      p.vetoed = true;
      p.done = true;
      st.conflicts.set(d.memberId, seq);
      st.versions.set(`conflict:${d.memberId}`, seq);
      return null;
    }
    case "device.rekey.vetoed": {
      const f = findDevice(st, pub);
      const p = st.pending.get(d.ref);
      if (kind !== "device" || !f || f.member.memberId !== d.memberId) return "producer_not_allowed";
      if (!p || p.kind !== "rekey" || p.done || p.cancelled || p.memberId !== d.memberId) return "not_pending";
      p.vetoed = true;
      p.done = true;
      st.conflicts.set(d.memberId, seq);
      st.versions.set(`conflict:${d.memberId}`, seq);
      return null;
    }
    case "room.policy.changed": {
      // One ver per setting (room-log-v2.md section 4.0); minVersion only rises.
      if (kind !== "admin") return "producer_not_allowed";
      for (const c of d.changes) if (c.ver !== ver(st, `policy:${c.setting}`)) return "stale_version";
      for (const c of d.changes) if (c.setting === "minVersion" && c.value < st.policy.minVersion) return "policy_downgrade";
      for (const c of d.changes) {
        st.policy[c.setting] = c.value;
        st.versions.set(`policy:${c.setting}`, seq);
      }
      return null;
    }
    case "device.conflict.resolved": {
      if (kind !== "admin") return "producer_not_allowed";
      if (!st.conflicts.has(d.memberId)) return "no_conflict";
      if (d.ver !== ver(st, `conflict:${d.memberId}`)) return "stale_version";
      st.conflicts.delete(d.memberId);
      st.versions.set(`conflict:${d.memberId}`, seq);
      return null;
    }
    case "device.add.approved": {
      if (kind !== "admin") return "producer_not_allowed";
      const p = st.pending.get(d.ref);
      if (!p || p.kind !== "add" || p.memberId !== d.memberId || p.device.deviceId !== d.deviceId) return "not_pending";
      if (p.cancelled) return "request_cancelled";
      if (p.vetoed) return "vetoed";
      if (p.done) return "not_pending";
      const m = st.members.get(d.memberId);
      if (!m) return "unknown_member";
      if (m.devices.length >= 8) return "device_count";
      if (d.mode === "auto") {
        if (st.policy.deviceAddApproval === "admin") return "auto_not_allowed";
        if (p.sole && st.policy.soleDeviceChange === "admin") return "auto_not_allowed";
        if (st.conflicts.has(d.memberId)) return "conflict_open";
        if (p.young) return "requester_too_young";
        if (hts - p.hts < (p.sole ? 72 : 24) * HOUR) return "hold_not_elapsed";
      }
      m.devices = sortById([...m.devices, structuredClone(p.device)], "deviceId");
      st.everDevice.add(d.deviceId);
      st.deviceSince.set(d.deviceId, hts);
      st.versions.set(`devices:${d.memberId}`, seq);
      p.done = true;
      return null;
    }
    case "device.rekeyed": {
      const f = findDevice(st, pub);
      const c = d.change;
      if (kind !== "device" || !f || c.subject.kind !== "device" || c.subject.id !== f.device.deviceId) return "producer_not_allowed";
      if (c.old !== kidEd(pub)) return "stale_version";
      if (st.denied.has(c.newSig) || st.denied.has(c.newDh) || st.retired.has(c.newSig)) return "denylisted_key";
      if (!verifySig(fromB64uStrict(c.newSig, 32), "key-change-new", rjcsBytes(c), fromB64uStrict(d.newKeySig, 64))) return "new_key_sig";
      st.pending.set(bodyHash, {
        kind: "rekey",
        memberId: f.member.memberId,
        device: { deviceId: f.device.deviceId, sig: c.newSig, dh: c.newDh },
        requester: f.device.deviceId,
        seq,
        hts,
        sole: f.member.devices.length === 1,
        vetoed: false,
        cancelled: false,
        done: false,
      });
      return null;
    }
    case "device.rekey.approved": {
      if (kind !== "admin") return "producer_not_allowed";
      const p = st.pending.get(d.ref);
      if (!p || p.kind !== "rekey" || p.memberId !== d.memberId || p.device.deviceId !== d.deviceId) return "not_pending";
      if (p.cancelled) return "request_cancelled";
      if (p.vetoed) return "vetoed";
      if (p.done) return "not_pending";
      const m = st.members.get(d.memberId);
      const dev = m && m.devices.find((x) => x.deviceId === d.deviceId);
      if (!dev) return "unknown_device";
      if (d.mode === "auto") {
        if (st.policy.deviceAddApproval === "admin") return "auto_not_allowed";
        if (p.sole && st.policy.soleDeviceChange === "admin") return "auto_not_allowed";
        if (st.conflicts.has(d.memberId)) return "conflict_open";
        if (hts - p.hts < (p.sole ? 72 : 24) * HOUR) return "hold_not_elapsed";
      }
      st.denied.add(dev.sig).add(dev.dh);
      st.retired.add(dev.sig);
      dev.sig = p.device.sig;
      dev.dh = p.device.dh;
      st.versions.set(`devices:${d.memberId}`, seq);
      p.done = true;
      // Requests signed by the old key are cancelled (room-log-v2.md section 4.3).
      cancelPending(st, (q) => q !== p && q.requester === d.deviceId);
      return null;
    }
    case "device.removed": {
      const m = st.members.get(d.memberId);
      if (!m) return "unknown_member";
      const target = m.devices.find((x) => x.deviceId === d.deviceId);
      if (!target) return "unknown_device";
      if (kind === "device") {
        if (target.sig !== b64u(pub)) return "device_removes_other";
        if (m.devices.length === 1) return "last_device_use_member_left";
      } else if (kind !== "admin") return "producer_not_allowed";
      st.denied.add(target.sig).add(target.dh);
      m.devices = m.devices.filter((x) => x.deviceId !== d.deviceId);
      st.versions.set(`devices:${d.memberId}`, seq);
      cancelPending(st, (p) => p.requester === d.deviceId || (p.kind === "rekey" && p.device.deviceId === d.deviceId));
      return null;
    }
    case "admin.added": {
      if (kind !== "admin" && kind !== "recovery") return "producer_not_allowed";
      const c = d.change;
      if (c.subject.kind !== "admin" || c.old !== null) return "stale_version";
      const newPub = fromB64uStrict(c.newSig, 32);
      const newKid = kidEd(newPub);
      if (st.admins.has(newKid) || st.retired.has(c.newSig)) return "retired_key";
      if (!verifySig(newPub, "key-change-new", rjcsBytes(c), fromB64uStrict(d.newKeySig, 64))) return "new_key_sig";
      const root = kind === "recovery" ? newKid : st.admins.get(producerKid).root;
      st.admins.set(newKid, { pub: newPub, fromSeq: seq + 1, since: seq + 1, root, addedBy: kind === "recovery" ? "recovery" : producerKid, revokedAt: null });
      return null;
    }
    case "room.close.proposed": {
      if (kind !== "admin") return "producer_not_allowed";
      const delayS = st.policy.closeDelay;
      if (d.exp > Math.floor(hts / 1000) + 7 * 86400 || d.exp <= Math.floor(hts / 1000) + delayS) return "bad_exp";
      st.proposals.set(bodyHash, { kid: producerKid, seq, hts, exp: d.exp, delayS, used: false });
      return null;
    }
    case "room.closed": {
      if (kind === "recovery") {
        if (d.proposal !== null) return "schema";
        st.closed = true;
        return null;
      }
      if (kind !== "admin") return "producer_not_allowed";
      const p = st.proposals.get(d.proposal);
      if (!p || p.used || p.exp < Math.floor(hts / 1000)) return "no_valid_proposal";
      const proposer = st.admins.get(p.kid);
      const confirmer = st.admins.get(producerKid);
      if (!proposer || proposer.revokedAt !== null) return "no_valid_proposal";
      if (proposer.root === confirmer.root) return "confirmer_not_independent";
      if (!(confirmer.fromSeq <= p.seq)) return "confirmer_after_proposal";
      if (hts - p.hts < Math.max(p.delayS, st.policy.closeDelay) * 1000) return "close_too_early";
      p.used = true;
      st.closed = true;
      return null;
    }
    case "host.key.rotated": {
      // keys-rotation-recovery.md section 4.5: this entry is the last one the old key signs.
      if (kind !== "admin") return "producer_not_allowed";
      const c = d.change;
      const cur = st.hostKeys.find((x) => x.toSeq === null);
      if (c.subject.kind !== "host" || c.old !== cur.kid) return "stale_version";
      const newPub = fromB64uStrict(c.newSig, 32);
      if (st.retired.has(c.newSig)) return "key_reused";
      if (!verifySig(newPub, "key-change-new", rjcsBytes(c), fromB64uStrict(d.newKeySig, 64))) return "new_key_sig";
      cur.toSeq = seq;
      st.retired.add(b64u(cur.pub));
      st.hostKeys.push({ kid: kidEd(newPub), pub: newPub, fromSeq: seq + 1, toSeq: null, uncertified: false });
      return null;
    }
    case "device.leaf.repair.requested": {
      // room-log-v2.md section 4.3 (decision round 8, item 1): the device itself, for its own leaf; one per
      // group per hour and at most 8 per device in 24 h of hts. Scopes are not modelled here (scope null only).
      const f = findDevice(st, pub);
      if (kind !== "device" || !f || f.member.memberId !== d.memberId || f.device.deviceId !== d.deviceId) return "not_permitted";
      if (d.group.scope !== null) return "not_in_scope";
      st.repairs = st.repairs.filter((r) => hts - r.hts < 24 * HOUR);
      const mine = st.repairs.filter((r) => r.deviceId === d.deviceId);
      if (mine.some((r) => r.scope === d.group.scope && r.generation === d.group.generation && hts - r.hts < HOUR)) return "repair_too_soon";
      if (mine.length >= 8) return "repair_rate";
      st.repairs.push({ deviceId: d.deviceId, scope: d.group.scope, generation: d.group.generation, hts });
      return null;
    }
    case "admin.key.revoked":
      return null; // handled in the main loop (bounds and re-fold)
    case "lane.created":
    case "grant.issued":
    case "producer.fence":
      return null; // no roster or authority change modelled here
    default:
      return "unknown_type";
  }
}
/**
 * One pass over `entries`. `revs` lists the revocations known from the start (refold mode): statements by a
 * revoked key at a position >= its fromSeq are suspect and have no effect; statements that no longer apply are
 * void. In the main pass (refold = false) a rejected statement stops the fold, as invalid_entry does on a member.
 */
function run(entries, revs, refold) {
  let st = initState();
  st.revs = [...revs];
  let prev = genesisHash;
  for (let i = 0; i < entries.length; i++) {
    const { entry, hash, hsig, statement: stm } = entries[i];
    const fail = (error) => ({ ok: false, error, seq: entry.seq });
    const eb = rjcsBytes(entry);
    if (entry.seq !== st.hashes.length) return fail("seq_gap");
    if (entry.prev !== b64u(prev)) return fail("prev_mismatch");
    const eh = dhash("log-entry", eb);
    if (b64u(eh) !== hash) return fail("entry_hash");
    // Host keys are judged by position (keys-rotation-recovery.md section 3). A re-fold pass does not re-check
    // entries: they were verified when they were appended.
    if (!refold) {
      const hk = st.hostKeys.find((x) => x.kid === entry.hostKid && x.fromSeq <= entry.seq && (x.toSeq === null || entry.seq <= x.toSeq));
      if (!hk) return fail("unknown_host_key");
      if (!verifySig(hk.pub, "log-entry", eb, fromB64uStrict(hsig, 64))) return fail("hsig");
    }
    const bodyHash = bodyHashOf(stm);
    if (entry.bodyHash !== bodyHash) return fail("body_hash");
    const { body } = stm;
    if (body.roomId !== roomId || body.type !== entry.type) return fail("schema");
    if (!(body.base.seq < entry.seq)) return fail("base_not_before_entry");
    const expected = body.base.seq === -1 ? b64u(genesisHash) : st.hashes[body.base.seq];
    if (body.base.hash !== expected) return fail("base_mismatch");
    if (st.seen.has(bodyHash)) return fail("duplicate_statement");
    const pub = producerPub(st, body);
    if (!pub) return fail("unknown_producer");
    if (!verifySig(pub, stmtCtx(body.type), rjcsBytes(body), fromB64uStrict(stm.sig, 64))) return fail("statement_sig");
    const kid = body.producer.kid;
    if (st.maxBase.has(kid) && !(body.base.seq > st.maxBase.get(kid))) return fail("base_regressed");
    st.maxBase.set(kid, body.base.seq);
    const ref = body.data.ref ?? body.data.proposal ?? null;
    if (ref !== null) {
      const at = entries.findIndex((e) => bodyHashOf(e.statement) === ref);
      if (at >= 0 && !(body.base.seq >= at)) return fail("base_before_ref");
    }
    st.seen.add(bodyHash);
    st.hashes.push(hash);
    prev = eh;
    const suspect = st.revs.some((r) => r.kid === kid && entry.seq >= r.fromSeq);
    if (suspect) continue;
    const before = rosterKey(st);
    if (body.type === "admin.key.revoked") {
      const d = body.data;
      const target = st.admins.get(d.kid);
      const signer = body.producer.kind === "recovery" ? st.recovery : st.admins.get(kid);
      let err = null;
      if (!target || target.revokedAt !== null || d.kid === kid) err = "bad_revocation";
      else if (!(d.fromSeq <= entry.seq) || d.fromSeq < target.fromSeq) err = "bad_revocation";
      else if (d.fromSeq < signer.since) err = "revocation_before_since";
      // Nesting depth (section 5.1, step 8): 1 + the largest depth among revocation entries in [fromSeq, r).
      let depth = 1;
      for (const x of st.revDepths) if (x.seq >= d.fromSeq && x.seq < entry.seq) depth = Math.max(depth, x.depth + 1);
      if (!err && !refold && depth > 8) err = "revocation_too_deep";
      if (err) {
        if (refold) continue;
        return fail(err);
      }
      if (!refold) {
        const newRevs = [...st.revs, { kid: d.kid, fromSeq: d.fromSeq }];
        const r = run(entries.slice(0, i), newRevs, true);
        if (!r.ok) return fail(`refold_${r.error}`);
        const rosterSeqBefore = st.rosterSeq;
        const re = r.state;
        re.seen.add(bodyHash);
        re.hashes.push(hash);
        re.maxBase = st.maxBase;
        re.revDepths = [...st.revDepths, { seq: entry.seq, depth }];
        // Decision round 8, item 3: nothing retired before r returns. Ids, retired keys and the device
        // denylist only grow; admin keys revoked or removed before stay so; the host-key table is positional and
        // stays as it was, with keys whose installing statement no longer applies marked uncertified.
        for (const k of ["everMember", "everDevice", "denied", "retired"]) for (const x of st[k]) re[k].add(x);
        for (const [kid, a] of st.admins) {
          const ra = re.admins.get(kid);
          if (!ra) re.admins.set(kid, { ...a, revokedAt: a.revokedAt ?? entry.seq });
          else if (a.revokedAt !== null && ra.revokedAt === null) ra.revokedAt = a.revokedAt;
        }
        const certified = new Set(re.hostKeys.map((x) => x.kid));
        re.hostKeys = st.hostKeys.map((x) => ({ ...x, uncertified: !certified.has(x.kid) }));
        // Keys of the state before r that the re-fold leaves out of use are retired too.
        for (const m of st.members.values()) for (const dev of m.devices) if (!findDevice(re, fromB64uStrict(dev.sig, 32))) re.denied.add(dev.sig).add(dev.dh);
        // A device whose recomputed keys are retired does not come back.
        for (const m of re.members.values()) {
          const out = m.devices.filter((x) => re.denied.has(x.sig) || re.denied.has(x.dh) || re.retired.has(x.sig));
          if (out.length) re.versions.set(`devices:${m.memberId}`, entry.seq);
          for (const x of out) cancelPending(re, (p) => p.requester === x.deviceId || p.device.deviceId === x.deviceId);
          m.devices = m.devices.filter((x) => !out.includes(x));
        }
        st = re;
        st.rosterSeq = rosterKey(st) !== before ? entry.seq : rosterSeqBefore;
      } else st.revDepths = [...st.revDepths, { seq: entry.seq, depth }];
      const t = st.admins.get(d.kid);
      t.revokedAt = entry.seq;
      st.retired.add(b64u(t.pub));
      for (const p of st.proposals.values()) if (p.kid === d.kid && p.seq >= d.fromSeq) p.used = true;
      continue;
    }
    const err = apply(st, body, pub, entry, bodyHash);
    if (err) {
      if (refold) continue; // void
      return fail(err);
    }
    if (rosterKey(st) !== before) st.rosterSeq = entry.seq;
  }
  return { ok: true, state: st };
}
function fold(entries) {
  const r = run(entries, [], false);
  if (!r.ok) return r;
  const st = r.state;
  return { ok: true, rosterSeq: st.rosterSeq, rosterHash: rosterHashOf(st.rosterSeq, st.members.values()), closed: st.closed, state: st };
}
const rosterAfter = chain.map((_, k) => {
  const r = fold(chain.slice(0, k + 1));
  check(r.ok, `fold of log.entries[0..${k}] ok (${r.error})`);
  return { headSeq: k, rosterSeq: r.rosterSeq, rosterHash: r.rosterHash };
});
check(rosterAfter[1].rosterSeq === 0 && rosterAfter[3].rosterSeq === 2, "roster position skips non-roster entries");

// Fold checks (S-1, R-1): a valid role change and back, then single invalid entries at seq 6.
const p3 = chain.slice(0, 4);
const r4s = statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "comment", ver: 2 }, 1793233000000, baseOf(e3));
const r4 = entryFor(4, e3.hashBytes, r4s, 1793233000100, 0);
const r5s = statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "watch", ver: 4 }, 1793233600000, baseOf(r4));
const r5 = entryFor(5, r4.hashBytes, r5s, 1793233600100, 0);
const roleChain = [r4, r5];
check(fold([...p3, ...roleChain]).ok, "role change chain folds");
// A promotion the admin signed at the head of seq 3 (before r4) and the host held back (R-1).
const heldPromotion = statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "comment", ver: 2 }, 1793232999000, baseOf(e3));
const badAt6 = {
  replayedStatement: entryFor(6, r5.hashBytes, r4s, 1793234200100, 0),
  heldStatement: entryFor(6, r5.hashBytes, heldPromotion, 1793234200100, 0),
  abaStaleVersion: entryFor(
    6,
    r5.hashBytes,
    statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "steer", ver: 2 }, 1793234200000, baseOf(r5)),
    1793234200100,
    0,
  ),
  baseNotBeforeEntry: entryFor(
    6,
    r5.hashBytes,
    statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "comment", ver: 5 }, 1793234200001, { seq: 6, hash: r5.hash }),
    1793234200100,
    0,
  ),
  baseHashMismatch: entryFor(
    6,
    r5.hashBytes,
    statement(keys.adminA, "admin", "member.role.changed", { memberId, role: "comment", ver: 5 }, 1793234200002, { seq: 5, hash: r4.hash }),
    1793234200100,
    0,
  ),
};
const expectedErrors = {
  replayedStatement: "duplicate_statement",
  heldStatement: "base_regressed",
  abaStaleVersion: "stale_version",
  baseNotBeforeEntry: "base_not_before_entry",
  baseHashMismatch: "base_mismatch",
};
const foldCases = Object.entries(badAt6).map(([name, e]) => {
  const r = fold([...p3, ...roleChain, e]);
  check(!r.ok && r.error === expectedErrors[name] && r.seq === 6, `fold case ${name}: expected ${expectedErrors[name]}, got ${r.error}`);
  return { name, entry: publicEntry(e), statement: e.statement, expect: expectedErrors[name] };
});
// The ABA case passes the base and forward rules; only the version stops it. The role is "watch" again, so a
// check of the old value would have accepted it.
check(fold([...p3, ...roleChain]).state.members.get(memberId).role === "watch", "ABA: role is back at watch before the stale statement");
// The held promotion also carries a stale version, so it would be rejected even if its producer had signed
// nothing since (for example, a statement held back from a different admin).
check(heldPromotion.body.data.ver !== ver(fold([...p3, ...roleChain]).state, `role:${memberId}`), "held promotion also has a stale version");
// Replaying the old admission after Sam left is caught twice over (duplicate statement, denylisted keys).
{
  const replay = entryFor(5, e4.hashBytes, s2, 1793236000100, 0);
  const r = fold([...chain, replay]);
  check(!r.ok && r.error === "duplicate_statement", "replayed admission after member.left rejected");
}

// Equivocation proof example: a second, different entry at seq 4 signed by the same host key.
const e4fork = entryFor(4, e3.hashBytes, statement(keys.adminA, "admin", "member.removed", { memberId, reason: "admin" }, 1793235900000, baseOf(e3)), 1793235900100, 0);

// ------------------------------------------------------------------ grant (grants-v2.md section 2)
const grantClaims = {
  v: 2,
  typ: "lane-grant",
  roomId,
  laneId,
  aud: laneServerId,
  sub: memberId,
  dev: kidOf("ed25519", keys.devSig.pub),
  role: "watch",
  gid,
  iat: 1793232400,
  exp: 1793275600,
  hostKid: kidOf("ed25519", keys.host.pub),
};
check(grantClaims.exp - grantClaims.iat === policy0.grantTtl, "grant lifetime equals policy.grantTtl");
const grantSig = sigOf(keys.host, "lane-grant", rjcsBytes(grantClaims));
const grantToken = `prg2.${b64u(rjcsBytes(grantClaims))}.${b64u(grantSig)}`;

// ------------------------------------------------------------------ key changes (keys-rotation-recovery.md section 2)
const kc = (subject, old, newSigKey, newDhKey) => ({
  v: 2,
  typ: "key-change",
  roomId,
  subject,
  old,
  newSig: newSigKey ? b64u(newSigKey.pub) : null,
  newDh: newDhKey ? b64u(newDhKey.pub) : null,
});
const sideBase = baseOf(e3); // standalone statements below name the head at seq 3

const rekeyChange = kc({ kind: "device", id: deviceId }, kidOf("ed25519", keys.devSig.pub), keys.devSig2, keys.devDh2);
const rekeyNewKeySig = sigOf(keys.devSig2, "key-change-new", rjcsBytes(rekeyChange));
const deviceRekeyed = statement(keys.devSig, "device", "device.rekeyed", { change: rekeyChange, newKeySig: b64u(rekeyNewKeySig) }, 1793240000000, sideBase);

const adminChange = kc({ kind: "admin", id: creatorMemberId }, kidOf("ed25519", keys.adminA.pub), keys.adminA2, null);
const adminNewKeySig = sigOf(keys.adminA2, "key-change-new", rjcsBytes(adminChange));
const adminKeyRotated = statement(keys.adminA, "admin", "admin.key.rotated", { change: adminChange, newKeySig: b64u(adminNewKeySig) }, 1793240100000, sideBase);

const hostChange = kc({ kind: "host", id: "host" }, kidOf("ed25519", keys.host.pub), keys.host2, null);
const hostNewKeySig = sigOf(keys.host2, "key-change-new", rjcsBytes(hostChange));
const hostKeyRotated = statement(
  keys.adminA,
  "admin",
  "host.key.rotated",
  { change: hostChange, newKeySig: b64u(hostNewKeySig), oldValidTo: 1793326600 },
  1793240200000,
  sideBase,
);

// Versions (room-log-v2.md section 4.0): both settings still have their genesis value, so ver is -1; the lane
// was created at seq 1, so its showNames version is 1.
const roomPolicyChanged = statement(
  keys.adminA,
  "admin",
  "room.policy.changed",
  {
    changes: [
      { setting: "deviceAddApproval", value: "admin", ver: -1 },
      { setting: "soleDeviceChange", value: "admin", ver: -1 },
    ],
  },
  1793240300000,
  sideBase,
);
const memberRoleChanged = r4s;
const laneNamesChanged = statement(keys.creatorDevSig, "device", "lane.names.changed", { laneId, show: true, ver: 1 }, 1793240400000, sideBase);
// First recovery key in a room with two admin lineages (room-log-v2.md section 5.2). Format example only: the
// vector genesis already has a recovery key, so these two are not folded. adminA proposes; adminB, of another
// lineage, confirms with the identical change.
const recoveryChange = kc({ kind: "recovery", id: "recovery" }, null, keys.recovery2, null);
const recoveryNewKeySig = b64u(sigOf(keys.recovery2, "key-change-new", rjcsBytes(recoveryChange)));
const recoveryKeyProposed = statement(
  keys.adminA,
  "admin",
  "recovery.key.proposed",
  { change: recoveryChange, newKeySig: recoveryNewKeySig, exp: 1793845000 },
  1793240500000,
  sideBase,
);
const recoveryKeyRotated = statement(
  keys.adminB,
  "admin",
  "recovery.key.rotated",
  { change: recoveryChange, newKeySig: recoveryNewKeySig, proposal: bodyHashOf(recoveryKeyProposed) },
  1793240600000,
  sideBase,
);
check(verifySig(keys.recovery2.pub, "key-change-new", rjcsBytes(recoveryChange), fromB64uStrict(recoveryNewKeySig, 64)), "recovery.key.rotated newKeySig verifies");

// ------------------------------------------------------------------ device link (identity-model.md section 6.4)
const linkToken = det("link-token", 32);
const linkId = `lnk_${detHex("link-id", 16)}`;
const linkRef = b64u(dhash("link-ref", utf8(linkId)));
const linkTokenKey = hkdf(sha256, linkToken, new Uint8Array(0), tbs("link-token-key", new Uint8Array(0)), 32);
const linkPayload = {
  v: 2,
  typ: "device-link",
  roomId,
  genesisHash: b64u(genesisHash),
  roomName: "Lab analysis",
  endpoint: endpointRec,
  linkId,
  token: b64u(linkToken),
  exp: 1793405700,
  sas: "sas6",
};
const linkCode = `prl2.${b64u(rjcsBytes(linkPayload))}`;
const ikLink = runIK({
  prologue: noisePrologue,
  iStatic: { secret: keys.phoneDh.secret, pub: keys.phoneDh.pub },
  rStatic: { secret: keys.endpoint.secret, pub: keys.endpoint.pub },
  iEph: ephemeral("link-init-ephemeral"),
  rEph: ephemeral("link-resp-ephemeral"),
  payloads: [new Uint8Array(0), new Uint8Array(0)],
});
const hLink = unhex(ikLink.handshakeHash);
const NmLink = det("link-member-nonce", 32);
const NcLink = det("link-confirmer-nonce", 32); // chosen by the confirming device A, not by the host
const linkSasCommit = dhash("sas-commit", NmLink);
const linkEnrollSigned = {
  v: 2,
  typ: "enroll-request",
  h: b64u(hLink),
  genesisHash: b64u(genesisHash),
  linkId,
  deviceSig: b64u(keys.phoneSig.pub),
  deviceDh: b64u(keys.phoneDh.pub),
  label: "Sam phone",
  sasCommit: b64u(linkSasCommit),
};
const linkEnrollSig = sigOf(keys.phoneSig, "enroll-request", rjcsBytes(linkEnrollSigned));
const linkTokenMac = hmac(sha256, linkTokenKey, tbs("enroll-token", rjcsBytes(linkEnrollSigned)));
const linkSas = sasFor({ hBytes: hLink, nm: NmLink, nc: NcLink, deviceSigPub: keys.phoneSig.pub, deviceDhPub: keys.phoneDh.pub, target: { linkId } });
check(linkSas.digits !== sas.digits, "link SAS differs from invite SAS");

const phoneEntry = deviceEntry(phoneDeviceId, keys.phoneSig, keys.phoneDh);
const phoneChange = kc({ kind: "device", id: phoneDeviceId }, null, keys.phoneSig, keys.phoneDh);
const phoneNewKeySig = sigOf(keys.phoneSig, "key-change-new", rjcsBytes(phoneChange));
// Folded device-link chain (identity-model.md section 6.4; room-log-v2.md sections 4.3, 5). Sam's laptop was
// admitted at seq 2 and is Sam's only device. 48 h later it creates a link (seq 4) and requests the phone
// (seq 5). The approval (seq 6) comes 72 h after the request, because the requester is a sole device
// (decision round 4, item 2), and names a base at or after the request (R-10).
const DL_T = e2.entry.hts + 48 * HOUR;
const linkCreated = statement(keys.devSig, "device", "device.link.created", { memberId, linkRef, exp: linkPayload.exp }, DL_T - 100, baseOf(e3));
const dl4 = entryFor(4, e3.hashBytes, linkCreated, DL_T, 0);
const deviceAdded = statement(
  keys.devSig,
  "device",
  "device.added",
  {
    memberId,
    device: phoneEntry,
    change: phoneChange,
    newKeySig: b64u(phoneNewKeySig),
    addedBy: deviceId,
    confirmation: { method: "sas6", linkRef, transcript: b64u(linkSas.transcript) },
  },
  DL_T + 300000 - 100,
  baseOf(dl4),
);
const dl5 = entryFor(5, dl4.hashBytes, deviceAdded, DL_T + 300000, 0);
const addRef = bodyHashOf(deviceAdded);
const deviceAddApproved = statement(
  keys.adminA,
  "admin",
  "device.add.approved",
  { memberId, deviceId: phoneDeviceId, ref: addRef, mode: "auto" },
  dl5.entry.hts + 72 * HOUR - 100,
  baseOf(dl5),
);
const dl6 = entryFor(6, dl5.hashBytes, deviceAddApproved, dl5.entry.hts + 72 * HOUR, 0);
const deviceLinkChain = [dl4, dl5, dl6];
check(verifySig(keys.phoneSig.pub, "key-change-new", rjcsBytes(phoneChange), phoneNewKeySig), "device.added newKeySig verifies");
check(verifySig(keys.devSig2.pub, "key-change-new", rjcsBytes(rekeyChange), rekeyNewKeySig), "device.rekeyed newKeySig verifies");
check(verifySig(keys.adminA2.pub, "key-change-new", rjcsBytes(adminChange), adminNewKeySig), "admin.key.rotated newKeySig verifies");
check(verifySig(keys.host2.pub, "key-change-new", rjcsBytes(hostChange), hostNewKeySig), "host.key.rotated newKeySig verifies");

// Re-fold (room-log-v2.md section 5.1, R-7, R-12). adminA adds adminC (same lineage); adminC admits a ghost;
// the recovery key revokes adminC from seq 5. The ghost admission becomes suspect, the roster returns to its
// state before seq 5, and the revocation entry becomes the roster position.
const ghostId = `mem_${detHex("ghost-member-id", 16)}`;
const ghostDeviceId = `dev_${detHex("ghost-device-id", 16)}`;
const adminCChange = kc({ kind: "admin", id: creatorMemberId }, null, keys.adminC, null);
const adminCAdded = statement(
  keys.adminA,
  "admin",
  "admin.added",
  { change: adminCChange, newKeySig: b64u(sigOf(keys.adminC, "key-change-new", rjcsBytes(adminCChange))) },
  1793236000000,
  baseOf(e3),
);
const rf4 = entryFor(4, e3.hashBytes, adminCAdded, 1793236000100, 0);
const ghostAdmitted = statement(
  keys.adminC,
  "admin",
  "member.admitted",
  {
    member: { memberId: ghostId, role: "watch", lanes: [laneId], devices: [deviceEntry(ghostDeviceId, keys.ghostSig, keys.ghostDh)] },
    confirmation: { method: "sas6", inviteRef, transcript: b64u(det("ghost-transcript", 32)) },
  },
  1793236060000,
  baseOf(rf4),
);
const rf5 = entryFor(5, rf4.hashBytes, ghostAdmitted, 1793236060100, 0);
const adminCRevoked = statement(keys.recovery, "recovery", "admin.key.revoked", { kid: kidEd(keys.adminC.pub), fromSeq: 5 }, 1793239600000, baseOf(rf5));
const rf6 = entryFor(6, rf5.hashBytes, adminCRevoked, 1793239600100, 0);
const refoldChain = [rf4, rf5, rf6];
const refoldBefore = fold([...p3, rf4, rf5]);
const refoldAfter = fold([...p3, ...refoldChain]);
check(refoldBefore.ok && refoldBefore.rosterSeq === 5 && refoldBefore.state.members.has(ghostId), "re-fold: ghost in roster before revocation");
check(refoldAfter.ok && !refoldAfter.state.members.has(ghostId), `re-fold: ghost removed (${refoldAfter.error})`);
check(refoldAfter.ok && refoldAfter.rosterSeq === 6, "re-fold: revocation entry is the roster position (R-7)");
check(refoldAfter.ok && refoldAfter.rosterHash === rosterHashOf(6, [creatorEntry, rosterEntry]), "re-fold: roster equals the pre-ghost roster at position 6");
check(refoldAfter.ok && refoldAfter.rosterHash !== rosterAfter[3].rosterHash, "re-fold: new position, new hash");
// adminC (authority start 5) may not reach back before its own start (section 5.1 step 1).
const refoldBad = entryFor(
  5,
  rf4.hashBytes,
  statement(keys.adminC, "admin", "admin.key.revoked", { kid: kidEd(keys.adminA.pub), fromSeq: 0 }, 1793236060000, baseOf(rf4)),
  1793236060100,
  0,
);
{
  const r = fold([...p3, rf4, refoldBad]);
  check(!r.ok && r.error === "revocation_before_since", `revocation before the revoker's start rejected (${r.error})`);
}

// Closure (room-log-v2.md section 5.2, R-3). R adds adminB (its own lineage root). adminA proposes; adminB
// confirms after the 24 h delay. Rejected: a confirmation 1 h after the proposal, a confirmer of adminA's
// lineage (adminC), and a confirmer added after the proposal.
const T0 = 1793239600100;
const adminBChange = kc({ kind: "admin", id: creatorMemberId }, null, keys.adminB, null);
const adminBAdded = statement(
  keys.recovery,
  "recovery",
  "admin.added",
  { change: adminBChange, newKeySig: b64u(sigOf(keys.adminB, "key-change-new", rjcsBytes(adminBChange))) },
  T0 - 100,
  baseOf(e3),
);
const cl4 = entryFor(4, e3.hashBytes, adminBAdded, T0, 0);
const closeProposed = statement(keys.adminA, "admin", "room.close.proposed", { exp: Math.floor(T0 / 1000) + 3 * 86400 }, T0 + 59900, baseOf(cl4));
const cl5 = entryFor(5, cl4.hashBytes, closeProposed, T0 + 60000, 0);
const closeRef = bodyHashOf(closeProposed);
const roomClosed = statement(keys.adminB, "admin", "room.closed", { proposal: closeRef }, T0 + 60000 + 25 * HOUR - 100, baseOf(cl5));
const cl6 = entryFor(6, cl5.hashBytes, roomClosed, T0 + 60000 + 25 * HOUR, 0);
const closureChain = [cl4, cl5, cl6];
{
  const r = fold([...p3, ...closureChain]);
  check(r.ok && r.closed, `closure by an independent admin after the delay accepted (${r.error})`);
  const after = entryFor(7, cl6.hashBytes, statement(keys.adminA, "admin", "producer.fence", {}, T0 + 60000 + 26 * HOUR, baseOf(cl6)), T0 + 60000 + 26 * HOUR + 100, 0);
  const r2 = fold([...p3, ...closureChain, after]);
  check(!r2.ok && r2.error === "room_closed", "no statement after room.closed");
}
const closeEarly = entryFor(
  6,
  cl5.hashBytes,
  statement(keys.adminB, "admin", "room.closed", { proposal: closeRef }, T0 + 60000 + HOUR - 100, baseOf(cl5)),
  T0 + 60000 + HOUR,
  0,
);
// Same-lineage confirmer: adminA adds adminC, adminA proposes, adminC confirms after the delay.
const sl4 = entryFor(4, e3.hashBytes, adminCAdded, T0, 0);
const slProposed = statement(keys.adminA, "admin", "room.close.proposed", { exp: Math.floor(T0 / 1000) + 3 * 86400 }, T0 + 59900, baseOf(sl4));
const sl5 = entryFor(5, sl4.hashBytes, slProposed, T0 + 60000, 0);
const sl6 = entryFor(
  6,
  sl5.hashBytes,
  statement(keys.adminC, "admin", "room.closed", { proposal: bodyHashOf(slProposed) }, T0 + 60000 + 25 * HOUR - 100, baseOf(sl5)),
  T0 + 60000 + 25 * HOUR,
  0,
);
// Confirmer added after the proposal: adminA proposes at 4, R adds adminB at 5, adminB confirms at 6.
const lateProposed = statement(keys.adminA, "admin", "room.close.proposed", { exp: Math.floor(T0 / 1000) + 3 * 86400 }, T0 - 100, baseOf(e3));
const la4 = entryFor(4, e3.hashBytes, lateProposed, T0, 0);
const lateBAdded = statement(
  keys.recovery,
  "recovery",
  "admin.added",
  { change: adminBChange, newKeySig: b64u(sigOf(keys.adminB, "key-change-new", rjcsBytes(adminBChange))) },
  T0 + 59900,
  baseOf(la4),
);
const la5 = entryFor(5, la4.hashBytes, lateBAdded, T0 + 60000, 0);
const la6 = entryFor(
  6,
  la5.hashBytes,
  statement(keys.adminB, "admin", "room.closed", { proposal: bodyHashOf(lateProposed) }, T0 + 60000 + 25 * HOUR - 100, baseOf(la5)),
  T0 + 60000 + 25 * HOUR,
  0,
);
const closureCases = [
  { name: "tooEarly", prefix: [...p3, cl4, cl5], entry: closeEarly, expect: "close_too_early" },
  { name: "sameLineage", prefix: [...p3, sl4, sl5], entry: sl6, expect: "confirmer_not_independent" },
  { name: "confirmerAddedAfterProposal", prefix: [...p3, la4, la5], entry: la6, expect: "confirmer_after_proposal" },
].map(({ name, prefix, entry, expect }) => {
  const r = fold([...prefix, entry]);
  check(!r.ok && r.error === expect && r.seq === 6, `closure case ${name}: expected ${expect}, got ${r.error}`);
  return {
    name,
    chain: prefix.slice(4).map((e) => ({ ...publicEntry(e), statement: e.statement })),
    entry: publicEntry(entry),
    statement: entry.statement,
    expect,
  };
});

// Device-link fold checks (R-8, R-10, decision round 4 item 2).
{
  const r = fold([...p3, ...deviceLinkChain]);
  check(r.ok && r.rosterSeq === 6 && r.state.members.get(memberId).devices.length === 2, `device link chain folds (${r.error})`);
}
const dlAt = (seq, prevEntry, st, hts) => entryFor(seq, prevEntry.hashBytes, st, hts, 0);
const dlVeto = statement(keys.devSig, "device", "device.add.vetoed", { memberId, ref: addRef }, dl5.entry.hts + HOUR - 100, baseOf(dl5));
const dl6veto = dlAt(6, dl5, dlVeto, dl5.entry.hts + HOUR);
const dlRemoved = statement(keys.adminA, "admin", "device.removed", { memberId, deviceId, reason: "lost" }, dl5.entry.hts + HOUR - 100, baseOf(dl5));
const dl6removed = dlAt(6, dl5, dlRemoved, dl5.entry.hts + HOUR);
const conflictResolved = statement(keys.adminA, "admin", "device.conflict.resolved", { memberId, ver: 6 }, dl5.entry.hts + 2 * HOUR - 100, baseOf(dl6veto));
{
  const r = fold([...p3, dl4, dl5, dl6veto, dlAt(7, dl6veto, conflictResolved, dl5.entry.hts + 2 * HOUR)]);
  check(r.ok && !r.state.conflicts.has(memberId), `conflict resolved with the veto's version (${r.error})`);
}
const lateApproval = (prevEntry) =>
  statement(keys.adminA, "admin", "device.add.approved", { memberId, deviceId: phoneDeviceId, ref: addRef, mode: "auto" }, dl5.entry.hts + 73 * HOUR - 100, baseOf(prevEntry));
const deviceLinkCases = [
  {
    name: "holdTooShort",
    prefix: [...p3, dl4, dl5],
    entry: dlAt(6, dl5, statement(keys.adminA, "admin", "device.add.approved", { memberId, deviceId: phoneDeviceId, ref: addRef, mode: "auto" }, dl5.entry.hts + 25 * HOUR - 100, baseOf(dl5)), dl5.entry.hts + 25 * HOUR),
    expect: "hold_not_elapsed",
    note: "the requester is the member's only device, so the hold is 72 h, not 24 h",
  },
  {
    name: "baseBeforeRef",
    prefix: [...p3, dl4, dl5],
    entry: dlAt(6, dl5, statement(keys.adminA, "admin", "device.add.approved", { memberId, deviceId: phoneDeviceId, ref: addRef, mode: "auto" }, dl5.entry.hts + 72 * HOUR - 50, baseOf(e3)), dl5.entry.hts + 72 * HOUR),
    expect: "base_before_ref",
    note: "the approval's base precedes the entry that carries ref (R-10)",
  },
  {
    name: "approvalAfterVeto",
    prefix: [...p3, dl4, dl5, dl6veto],
    entry: dlAt(7, dl6veto, lateApproval(dl6veto), dl5.entry.hts + 73 * HOUR),
    expect: "vetoed",
    note: "the laptop vetoed the add at seq 6",
  },
  {
    name: "approvalAfterRequesterRemoved",
    prefix: [...p3, dl4, dl5, dl6removed],
    entry: dlAt(7, dl6removed, lateApproval(dl6removed), dl5.entry.hts + 73 * HOUR),
    expect: "request_cancelled",
    note: "an admin removed the requesting (stolen, only) device at seq 6, which cancels its pending add in the fold (R-8)",
  },
  {
    name: "selfRemoveLastDevice",
    prefix: [...p3, dl4, dl5],
    entry: dlAt(6, dl5, statement(keys.devSig, "device", "device.removed", { memberId, deviceId, reason: "self" }, dl5.entry.hts + HOUR - 100, baseOf(dl5)), dl5.entry.hts + HOUR),
    expect: "last_device_use_member_left",
    note: "a member's last device leaves with member.left (R-8)",
  },
].map(({ name, prefix, entry, expect, note }) => {
  const r = fold([...prefix, entry]);
  check(!r.ok && r.error === expect, `device link case ${name}: expected ${expect}, got ${r.error}`);
  return {
    name,
    note,
    chain: prefix.slice(6).map((e) => ({ ...publicEntry(e), statement: e.statement })),
    entry: publicEntry(entry),
    statement: entry.statement,
    expect,
  };
});
{
  const r = fold([...p3, dl4, dl5, dl6removed]);
  check(r.ok && r.state.members.get(memberId).devices.length === 0 && r.rosterSeq === 6, `admin may remove the last device; member kept with no devices (${r.error})`);
}

// Sole-device rekey (keys-rotation-recovery.md section 4.1; decision round 5, item 3). Sam's laptop, Sam's only
// device, requests a rekey at seq 4, 48 h after its admission. An automatic approval 24 h later is rejected; one
// 72 h later is accepted and replaces the laptop's keys.
const RK_T = e2.entry.hts + 48 * HOUR;
const soleRekeyed = statement(keys.devSig, "device", "device.rekeyed", { change: rekeyChange, newKeySig: b64u(rekeyNewKeySig) }, RK_T - 100, baseOf(e3));
const rk4 = entryFor(4, e3.hashBytes, soleRekeyed, RK_T, 0);
const rekeyRef = bodyHashOf(soleRekeyed);
const rekeyApprovalAt = (hours) =>
  entryFor(
    5,
    rk4.hashBytes,
    statement(keys.adminA, "admin", "device.rekey.approved", { memberId, deviceId, ref: rekeyRef, mode: "auto" }, rk4.entry.hts + hours * HOUR - 100, baseOf(rk4)),
    rk4.entry.hts + hours * HOUR,
    0,
  );
const rk5 = rekeyApprovalAt(72);
const deviceRekeyChain = [rk4, rk5];
{
  const r = fold([...p3, ...deviceRekeyChain]);
  const dev = r.ok && r.state.members.get(memberId).devices[0];
  check(r.ok && r.rosterSeq === 5 && dev.sig === b64u(keys.devSig2.pub) && dev.dh === b64u(keys.devDh2.pub), `sole-device rekey approved after 72 h (${r.error})`);
  check(r.ok && r.state.denied.has(b64u(keys.devSig.pub)), "sole-device rekey: old signing key denylisted");
}
const deviceRekeyCases = [
  {
    name: "soleRekeyHoldTooShort",
    prefix: [...p3, rk4],
    entry: rekeyApprovalAt(24),
    expect: "hold_not_elapsed",
    note: "the requester is the member's only device, so the rekey hold is 72 h, not 24 h (decision round 5, item 3)",
  },
].map(({ name, prefix, entry, expect, note }) => {
  const r = fold([...prefix, entry]);
  check(!r.ok && r.error === expect, `device rekey case ${name}: expected ${expect}, got ${r.error}`);
  return {
    name,
    note,
    chain: prefix.slice(4).map((e) => ({ ...publicEntry(e), statement: e.statement })),
    entry: publicEntry(entry),
    statement: entry.statement,
    expect,
  };
});

// Rekey veto (room-log-v2.md section 4.3; keys-rotation-recovery.md section 4.1 step 3). The laptop, which is the
// device being rekeyed, answers "Not me" 1 h after the request: the rekey is cancelled and Sam has a device
// conflict, so an automatic approval 73 h after the request is rejected with vetoed.
const rekeyVetoed = statement(keys.devSig, "device", "device.rekey.vetoed", { memberId, ref: rekeyRef }, rk4.entry.hts + HOUR - 100, baseOf(rk4));
const rv5 = entryFor(5, rk4.hashBytes, rekeyVetoed, rk4.entry.hts + HOUR, 0);
const rv6 = entryFor(
  6,
  rv5.hashBytes,
  statement(keys.adminA, "admin", "device.rekey.approved", { memberId, deviceId, ref: rekeyRef, mode: "auto" }, rk4.entry.hts + 73 * HOUR - 100, baseOf(rv5)),
  rk4.entry.hts + 73 * HOUR,
  0,
);
{
  const r = fold([...p3, rk4, rv5]);
  check(r.ok && r.state.conflicts.get(memberId) === 5 && r.state.members.get(memberId).devices[0].sig === b64u(keys.devSig.pub), `rekey veto opens a conflict and keeps the old keys (${r.error})`);
  const r2 = fold([...p3, rk4, rv5, rv6]);
  check(!r2.ok && r2.error === "vetoed" && r2.seq === 6, `rekey approval after a veto rejected (${r2.error})`);
}
const rekeyVetoCase = {
  name: "approvalAfterVeto",
  note: "the laptop, the device being rekeyed, vetoed the rekey at seq 5; the approval names the vetoed request",
  chain: [rk4, rv5].map((e) => ({ ...publicEntry(e), statement: e.statement })),
  entry: publicEntry(rv6),
  statement: rv6.statement,
  expect: "vetoed",
};

// Sole-device rekey under policy soleDeviceChange = "admin" (identity-model.md sections 5.2.1 and 6.3; decision
// round 5, item 3). adminA sets the policy at seq 4; the laptop, Sam's only device, requests a rekey at seq 5; an
// admin approves interactively (mode "admin") 1 h later, with no hold. An automatic approval, even after 72 h,
// is rejected.
const saPolicy = statement(
  keys.adminA,
  "admin",
  "room.policy.changed",
  { changes: [{ setting: "soleDeviceChange", value: "admin", ver: -1 }] },
  RK_T - HOUR - 100,
  baseOf(e3),
);
const sa4 = entryFor(4, e3.hashBytes, saPolicy, RK_T - HOUR, 0);
const saRekeyed = statement(keys.devSig, "device", "device.rekeyed", { change: rekeyChange, newKeySig: b64u(rekeyNewKeySig) }, RK_T - 100, baseOf(sa4));
const sa5 = entryFor(5, sa4.hashBytes, saRekeyed, RK_T, 0);
const saRef = bodyHashOf(saRekeyed);
const saApprovalAt = (mode, hours) =>
  entryFor(
    6,
    sa5.hashBytes,
    statement(keys.adminA, "admin", "device.rekey.approved", { memberId, deviceId, ref: saRef, mode }, sa5.entry.hts + hours * HOUR - 100, baseOf(sa5)),
    sa5.entry.hts + hours * HOUR,
    0,
  );
const sa6 = saApprovalAt("admin", 1);
const soleAdminChain = [sa4, sa5, sa6];
{
  const r = fold([...p3, ...soleAdminChain]);
  const dev = r.ok && r.state.members.get(memberId).devices[0];
  check(r.ok && r.state.policy.soleDeviceChange === "admin" && r.rosterSeq === 6 && dev.sig === b64u(keys.devSig2.pub), `sole-device rekey approved by an admin under soleDeviceChange "admin" (${r.error})`);
}
const soleAdminCases = [
  {
    name: "autoApprovalAfterHold",
    prefix: [...p3, sa4, sa5],
    entry: saApprovalAt("auto", 72),
    expect: "auto_not_allowed",
    note: 'under soleDeviceChange "admin" a sole-device rekey needs an interactive admin approval, whatever the hold',
  },
].map(({ name, prefix, entry, expect, note }) => {
  const r = fold([...prefix, entry]);
  check(!r.ok && r.error === expect && r.seq === 6, `sole-device admin case ${name}: expected ${expect}, got ${r.error}`);
  return {
    name,
    note,
    chain: prefix.slice(4).map((e) => ({ ...publicEntry(e), statement: e.statement })),
    entry: publicEntry(entry),
    statement: entry.statement,
    expect,
  };
});

// Leaf repair (decision round 8, item 1; room-log-v2.md section 4.3; mls-integration.md sections 4.3, 4.4).
// Sam's laptop asks for its own leaf in the room group to be replaced at seq 4, naming the KeyPackageRef of
// the package the replacement must add, and again 61 min later at seq 5. Rejected: a request signed by
// another device, and a third request for the same group 10 min after the second.
const LR_T = e3.entry.hts + HOUR;
const repairData = (label) => ({ memberId, deviceId, group: { scope: null, generation: 0 }, keyPackageRef: b64u(det(label, 32)) });
const leafRepair = statement(keys.devSig, "device", "device.leaf.repair.requested", repairData("leaf-repair-kp-1"), LR_T - 100, baseOf(e3));
const lr4 = entryFor(4, e3.hashBytes, leafRepair, LR_T, 0);
const leafRepair2 = statement(keys.devSig, "device", "device.leaf.repair.requested", repairData("leaf-repair-kp-2"), LR_T + 61 * 60000 - 100, baseOf(lr4));
const lr5 = entryFor(5, lr4.hashBytes, leafRepair2, LR_T + 61 * 60000, 0);
const leafRepairChain = [lr4, lr5];
check(fold([...p3, ...leafRepairChain]).ok, `leaf repair chain folds (${fold([...p3, ...leafRepairChain]).error})`);
const leafRepairCases = [
  {
    name: "otherDevice",
    prefix: [...p3],
    entry: entryFor(4, e3.hashBytes, statement(keys.creatorDevSig, "device", "device.leaf.repair.requested", repairData("leaf-repair-kp-x"), LR_T - 100, baseOf(e3)), LR_T, 0),
    expect: "not_permitted",
    note: "Alice's desktop asks for Sam's laptop's leaf: a device requests the repair of its own leaf only",
  },
  {
    name: "tooSoon",
    prefix: [...p3, ...leafRepairChain],
    entry: entryFor(6, lr5.hashBytes, statement(keys.devSig, "device", "device.leaf.repair.requested", repairData("leaf-repair-kp-3"), LR_T + 71 * 60000 - 100, baseOf(lr5)), LR_T + 71 * 60000, 0),
    expect: "repair_too_soon",
    note: "a second request for the same group 10 min after the previous one",
  },
].map(({ name, prefix, entry, expect, note }) => {
  const r = fold([...prefix, entry]);
  check(!r.ok && r.error === expect && r.seq === entry.entry.seq, `leaf repair case ${name}: expected ${expect}, got ${r.error}`);
  return { name, note, chain: prefix.slice(4).map((e) => ({ ...publicEntry(e), statement: e.statement })), entry: publicEntry(entry), statement: entry.statement, expect };
});

// Retired keys never return (decision round 8, item 3; room-log-v2.md section 5.1). R adds adminB (seq 4, the
// closure chain's first entry). adminB, later known to be stolen, rotates the host key to host2 (seq 5, the last
// entry host-1 signs) and removes Sam's laptop (seq 6). R revokes adminB from 5 (seq 7). Both statements are
// suspect, but host-1 and the laptop's keys stay retired: host2 keeps signing entries, marked uncertified, and
// Sam stays with no device, so the roster members are those of position 6 and the position does not move.
const nrHostRotated = statement(
  keys.adminB,
  "admin",
  "host.key.rotated",
  { change: hostChange, newKeySig: b64u(hostNewKeySig), oldValidTo: Math.floor(T0 / 1000) + 3600 + 86400 },
  T0 + 3600000 - 100,
  baseOf(cl4),
);
const nr5 = entryFor(5, cl4.hashBytes, nrHostRotated, T0 + 3600000, 0);
const nrRemoved = statement(keys.adminB, "admin", "device.removed", { memberId, deviceId, reason: "admin" }, T0 + 2 * 3600000 - 100, baseOf(nr5));
const nr6 = entryFor(6, nr5.hashBytes, nrRemoved, T0 + 2 * 3600000, 0, keys.host2);
const nrRevoked = statement(keys.recovery, "recovery", "admin.key.revoked", { kid: kidEd(keys.adminB.pub), fromSeq: 5 }, T0 + 3 * 3600000 - 100, baseOf(nr6));
const nr7 = entryFor(7, nr6.hashBytes, nrRevoked, T0 + 3 * 3600000, 0, keys.host2);
const nrFence = statement(keys.adminA, "admin", "producer.fence", {}, T0 + 4 * 3600000 - 100, baseOf(nr7));
const nr8 = entryFor(8, nr7.hashBytes, nrFence, T0 + 4 * 3600000, 0, keys.host2);
const noRevivalChain = [cl4, nr5, nr6, nr7, nr8];
const noRevivalBefore = fold([...p3, cl4, nr5, nr6]);
const noRevivalAfter = fold([...p3, ...noRevivalChain]);
{
  const st = noRevivalAfter.ok && noRevivalAfter.state;
  check(noRevivalBefore.ok && noRevivalBefore.rosterSeq === 6, `no-revival: laptop removed at 6 (${noRevivalBefore.error})`);
  check(noRevivalAfter.ok, `no-revival chain folds (${noRevivalAfter.error})`);
  check(st && st.members.get(memberId).devices.length === 0 && st.denied.has(b64u(keys.devSig.pub)), "no-revival: the laptop stays out and denylisted");
  check(st && noRevivalAfter.rosterSeq === 6 && noRevivalAfter.rosterHash === noRevivalBefore.rosterHash, "no-revival: roster and its position unchanged by the re-fold");
  const [h1, h2] = st ? st.hostKeys : [];
  check(st && h1.toSeq === 5 && h2 && h2.kid === kidEd(keys.host2.pub) && h2.toSeq === null && h2.uncertified === true, "no-revival: host-1 stays retired, host2 current and uncertified");
}
const noRevivalCases = [
  {
    name: "retiredHostKeySigns",
    entry: entryFor(8, nr7.hashBytes, nrFence, T0 + 4 * 3600000, 0, keys.host),
    expect: "unknown_host_key",
    note: "host-1 was rotated out at 5 by a statement that is now suspect; it still may not sign",
  },
  {
    name: "removedDeviceSigns",
    entry: entryFor(8, nr7.hashBytes, statement(keys.devSig, "device", "producer.fence", {}, T0 + 4 * 3600000 - 100, baseOf(nr7)), T0 + 4 * 3600000, 0, keys.host2),
    expect: "unknown_producer",
    note: "the laptop was removed at 6 by a statement that is now suspect; its keys stay retired",
  },
].map(({ name, entry, expect, note }) => {
  const r = fold([...p3, cl4, nr5, nr6, nr7, entry]);
  check(!r.ok && r.error === expect && r.seq === 8, `no-revival case ${name}: expected ${expect}, got ${r.error}`);
  return { name, note, entry: publicEntry(entry), statement: entry.statement, expect };
});

// Revocation nesting depth (decision round 8, item 4; room-log-v2.md section 5.1, step 8). R adds nine admin
// keys (seq 4 to 12) and revokes them one by one from seq 13 (seq 13 to 20). The revocation at 13 + k has
// depth k + 1, because its range [13, 13 + k) holds the k earlier ones; the ninth, at seq 21, has depth 9.
const depthKeys = Array.from({ length: 9 }, (_, k) => edKey(`depth-admin-${k + 1}`));
const DP_T = T0 + 10 * 3600000;
const depthChain = [];
{
  let prevE = e3;
  depthKeys.forEach((k, idx) => {
    const ch = kc({ kind: "admin", id: creatorMemberId }, null, k, null);
    const st = statement(keys.recovery, "recovery", "admin.added", { change: ch, newKeySig: b64u(sigOf(k, "key-change-new", rjcsBytes(ch))) }, DP_T + idx * 60000 - 100, baseOf(prevE));
    prevE = entryFor(4 + idx, prevE.hashBytes, st, DP_T + idx * 60000, 0);
    depthChain.push(prevE);
  });
  depthKeys.slice(0, 8).forEach((k, idx) => {
    const st = statement(keys.recovery, "recovery", "admin.key.revoked", { kid: kidEd(k.pub), fromSeq: 13 }, DP_T + (9 + idx) * 60000 - 100, baseOf(prevE));
    prevE = entryFor(13 + idx, prevE.hashBytes, st, DP_T + (9 + idx) * 60000, 0);
    depthChain.push(prevE);
  });
}
const depthLast = depthChain.at(-1);
const depthTooDeep = entryFor(
  21,
  depthLast.hashBytes,
  statement(keys.recovery, "recovery", "admin.key.revoked", { kid: kidEd(depthKeys[8].pub), fromSeq: 13 }, DP_T + 17 * 60000 - 100, baseOf(depthLast)),
  DP_T + 17 * 60000,
  0,
);
{
  const r = fold([...p3, ...depthChain]);
  check(r.ok && r.state.revDepths.map((x) => x.depth).join(",") === "1,2,3,4,5,6,7,8", `depth chain folds with depths 1 to 8 (${r.error})`);
  const bad = fold([...p3, ...depthChain, depthTooDeep]);
  check(!bad.ok && bad.error === "revocation_too_deep" && bad.seq === 21, `depth 9 rejected (${bad.error})`);
  // The same revocation with fromSeq 21 (an empty range) has depth 1 and is accepted.
  const shallow = entryFor(
    21,
    depthLast.hashBytes,
    statement(keys.recovery, "recovery", "admin.key.revoked", { kid: kidEd(depthKeys[8].pub), fromSeq: 21 }, DP_T + 17 * 60000 - 100, baseOf(depthLast)),
    DP_T + 17 * 60000,
    0,
  );
  check(fold([...p3, ...depthChain, shallow]).ok, "the ninth revocation with an empty range is accepted");
}

// ------------------------------------------------------------------ MLS (mls-integration.md sections 2, 3, 5)
const mlsIdentity = {
  v: 2,
  typ: "mls-identity",
  roomId,
  memberId,
  deviceId,
  deviceSig: b64u(keys.devSig.pub),
  mlsSig: b64u(keys.devMls.pub),
  notBefore: 1793232300,
};
const mlsIdSig = sigOf(keys.devSig, "mls-identity", rjcsBytes(mlsIdentity));
const mlsCredentialIdentity = rjcs({ id: mlsIdentity, sig: b64u(mlsIdSig) });
// Reference roster: last roster-changing entry before the head (seq 2), while the head is seq 3 (grant.issued).
// Epoch anchor (decision round 8, item 2; mls-integration.md section 5.1). The epoch authenticator here is a
// placeholder from a public label; in a group it is MLS's epoch_authenticator for that epoch (RFC 9420 section 8.7).
const epochAuthenticator = det("mls-epoch-authenticator", 32);
const mlsAad = { v: 2, typ: "mls-aad", roster: { seq: rosterAfter[3].rosterSeq, hash: rosterAfter[3].rosterHash }, logHead: { seq: 3, hash: e3.hash }, epochAuth: null };
const adminSet = [b64u(keys.adminA.pub), b64u(keys.adminB.pub)].sort();
const adminSetHash = b64u(dhash("admin-set", rjcsBytes(adminSet)));
const authorityExtension = rjcs({ v: 2, genesisHash: b64u(genesisHash), adminSetHash, scope: null });
const scopeId = `scp_${detHex("scope-id", 16)}`;
const groupIds = {
  room: { input: rjcs({ genesisHash: b64u(genesisHash), generation: 0 }), groupIdHex: hex(dhash("mls-group", rjcsBytes({ genesisHash: b64u(genesisHash), generation: 0 }))) },
  scope: {
    input: rjcs({ genesisHash: b64u(genesisHash), scope: scopeId, generation: 0 }),
    groupIdHex: hex(dhash("mls-group", rjcsBytes({ genesisHash: b64u(genesisHash), scope: scopeId, generation: 0 }))),
  },
};
const epochAuthInput = { v: 2, typ: "mls-epoch-auth", groupId: b64u(dhash("mls-group", rjcsBytes({ genesisHash: b64u(genesisHash), generation: 0 }))), epoch: 0, auth: b64u(epochAuthenticator) };
const epochAuth = b64u(dhash("mls-epoch-auth", rjcsBytes(epochAuthInput)));
mlsAad.epochAuth = epochAuth;
const witness = { v: 2, typ: "log-witness", roomId, deviceId, head: { seq: 3, hash: e3.hash }, roster: { seq: rosterAfter[3].rosterSeq, hash: rosterAfter[3].rosterHash } };
const witnessSig = sigOf(keys.devSig, "stmt:log.witness", rjcsBytes(witness));
const witnessPayload = { kind: "log.witness", witness, sig: b64u(witnessSig) };

// ------------------------------------------------------------------ records (enrollment-v2.md section 3.4)
const pingFrame = rjcsBytes({ t: "ping" });
const bigFrame = rjcsBytes({ t: "msg.send", id: 7, epoch: 0, message: b64u(det("record-msg", 48)) });
const recordSingle = concat(Uint8Array.of(0x00), pingFrame);
const recordsSplit = [concat(Uint8Array.of(0x01), bigFrame.subarray(0, 40)), concat(Uint8Array.of(0x00), bigFrame.subarray(40))];
check(equalBytes(concat(...recordsSplit.map((r) => r.subarray(1))), bigFrame), "record fragments reassemble");

// ------------------------------------------------------------------ sealed file (identity-model.md section 7.2)
const kek = det("kek", 32);
const kekId = `kek_${detHex("kek-id", 16)}`;
const purpose = `mls-state:${roomId}:${deviceId}`;
const fileKey = hkdf(sha256, kek, new Uint8Array(0), tbs("file-key", utf8(purpose)), 32);
const sealNonce = det("seal-nonce", 24);
const sealAad = rjcsBytes({ v: 2, typ: "sealed", purpose, kekId });
const sealPt = utf8("example plaintext: encoded MLS group state bytes");
const sealCt = xchacha20poly1305(fileKey, sealNonce, sealAad).encrypt(sealPt);
const sealedObject = { v: 2, typ: "sealed", alg: "xchacha20poly1305", kekId, purpose, nonce: b64u(sealNonce), ct: b64u(sealCt) };
check(equalBytes(xchacha20poly1305(fileKey, sealNonce, sealAad).decrypt(sealCt), sealPt), "sealed roundtrip");

// ------------------------------------------------------------------ RJCS and base64url vectors
const rjcsAccept = [
  { value: { b: 1, a: [true, false, null], A: "x", _: 0, aa: { z: -9007199254740991, y: 9007199254740991 } } },
  { value: { s: "café 😀 \u0007 / \" \\ \n" } },
  { value: {} },
  { value: [] },
  { value: { k: "" } },
  { value: { 2: "c", 10: "b", 1: "a" } }, // integer-like keys: JS enumerates 1, 2, 10; RJCS order is "1", "10", "2"
].map(({ value }) => ({ canonical: rjcs(value), hex: hex(rjcsBytes(value)) }));
check(rjcsAccept[5].canonical === '{"1":"a","10":"b","2":"c"}', "integer-like keys sort as strings");
for (const v of rjcsAccept) {
  try {
    rjcsParseStrict(unhex(v.hex));
  } catch (e) {
    failures.push(`rjcs accept failed: ${v.canonical} (${e.message})`);
  }
}
const rjcsReject = [
  ['{"a":1, "b":2}', "whitespace"],
  ['{"b":1,"a":2}', "unsorted keys"],
  ['{"a":1,"a":2}', "duplicate key"],
  ['{"a":1.0}', "non-integer form"],
  ['{"a":1.5}', "float"],
  ['{"a":1e3}', "exponent"],
  ['{"a":-0}', "negative zero"],
  ['{"a":9007199254740992}', "integer beyond 2^53-1"],
  ['{"a":"\\ud800"}', "lone surrogate"],
  ['{"café":1}', "non-ASCII key"],
  ['{"a-b":1}', "key outside [A-Za-z0-9_]"],
  ['{"a":"\\u00e9"}', "escaped printable character"],
  ['{"a":"\\/"}', "escaped solidus"],
  ['{"a":"\\u001F"}', "uppercase hex escape"],
  ['{"a":1}\n', "trailing newline"],
  ['﻿{"a":1}', "byte order mark"],
  ['{"__proto__":1}', "reserved key __proto__"],
  ['{"constructor":1}', "reserved key constructor"],
  ['{"prototype":1}', "reserved key prototype"],
].map(([text, why]) => {
  let rejected = false;
  try {
    rjcsParseStrict(utf8(text));
  } catch {
    rejected = true;
  }
  check(rejected, `rjcs reject not rejected: ${why}`);
  return { hex: hex(utf8(text)), text, why };
});
// Invalid UTF-8 bytes.
{
  let rejected = false;
  try {
    rjcsParseStrict(unhex("7b2261223a22ff227d"));
  } catch {
    rejected = true;
  }
  check(rejected, "rjcs reject invalid utf-8");
  rjcsReject.push({ hex: "7b2261223a22ff227d", text: null, why: "invalid UTF-8" });
}
const good32 = b64u(keys.devSig.pub);
const lastIdx = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(good32.at(-1));
const nonCanonical32 = good32.slice(0, -1) + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[lastIdx | 1];
const b64uCases = [
  { text: good32, bytes: 32, ok: true, why: "canonical 32-byte key" },
  { text: `${good32}=`, bytes: 32, ok: false, why: "padding" },
  { text: nonCanonical32, bytes: 32, ok: false, why: "non-zero trailing bits" },
  { text: good32.slice(0, 42), bytes: 32, ok: false, why: "wrong length" },
  { text: ` ${good32}`, bytes: 32, ok: false, why: "whitespace" },
  { text: b64u(grantSig), bytes: 64, ok: true, why: "canonical 64-byte signature" },
  { text: `${b64u(grantSig)}==`, bytes: 64, ok: false, why: "padded signature" },
];
for (const c of b64uCases) {
  let ok = true;
  try {
    fromB64uStrict(c.text, c.bytes);
  } catch {
    ok = false;
  }
  check(ok === c.ok, `b64u case mismatch: ${c.why}`);
}
// Make sure the vector set includes a "+ or /" rejection even if the key above has none.
{
  const t = "ab+/";
  let ok = true;
  try {
    fromB64uStrict(t);
  } catch {
    ok = false;
  }
  check(!ok, "b64u standard-alphabet rejection");
  b64uCases.push({ text: t, bytes: null, ok: false, why: "'+' and '/' characters" });
}

// ------------------------------------------------------------------ Ed25519 negative cases (signatures-and-encoding.md section 5.1)
const smallOrder = [
  { hex: "0100000000000000000000000000000000000000000000000000000000000000", why: "identity point (order 1)" },
  { hex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", why: "point (0, -1) (order 2)" },
].map((c) => {
  let small = false;
  try {
    small = ed25519.Point.fromBytes(unhex(c.hex)).isSmallOrder();
  } catch {
    small = false;
  }
  check(small, `small-order key not detected: ${c.why}`);
  return { pub: b64u(unhex(c.hex)), why: c.why, expect: "reject" };
});
const sNotReduced = (() => {
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const S = BigInt(`0x${hex(grantSig.slice(32).reverse())}`);
  const S2 = S + L;
  const s2 = unhex(S2.toString(16).padStart(64, "0")).reverse();
  const bad = concat(grantSig.slice(0, 32), s2);
  const payload = rjcsBytes(grantClaims);
  check(!verifySig(keys.host.pub, "lane-grant", payload, bad), "Ed25519 S >= L rejected by node:crypto");
  check(!ed25519.verify(bad, tbs("lane-grant", payload), keys.host.pub), "Ed25519 S >= L rejected by @noble");
  return { pub: b64u(keys.host.pub), ctx: "lane-grant", payload: "grant.claims", sig: b64u(bad), why: "S replaced by S + L (same R)", expect: "reject" };
})();

// ------------------------------------------------------------------ cross-context negative checks
{
  const payload = rjcsBytes(grantClaims);
  for (const ctx of CONTEXTS) if (ctx !== "lane-grant") check(!verifySig(keys.host.pub, ctx, payload, grantSig), `grant signature verified under ${ctx}`);
  check(verifySig(keys.host.pub, "lane-grant", payload, grantSig), "grant signature verifies");
  check(verifySig(keys.adminA.pub, "genesis", rjcsBytes(genesisBody), genesisSig), "genesis verifies");
  check(verifySig(keys.devSig.pub, "enroll-request", rjcsBytes(enrollSigned), enrollSig), "enroll request verifies");
  check(verifySig(keys.phoneSig.pub, "enroll-request", rjcsBytes(linkEnrollSigned), linkEnrollSig), "link enroll request verifies");
  check(verifySig(keys.host.pub, "log-entry", rjcsBytes(e4fork.entry), fromB64uStrict(e4fork.hsig, 64)), "fork entry verifies");
  check(e4fork.hash !== e4.hash, "fork entry differs");
  check(verifySig(keys.devSig.pub, "stmt:log.witness", rjcsBytes(witness), witnessSig), "witness verifies");
  check(!verifySig(keys.devSig.pub, "stmt:member.left", rjcsBytes(witness), witnessSig), "witness does not verify as member.left");
}

// ------------------------------------------------------------------ output
const keyTable = Object.fromEntries(
  Object.entries(keys).map(([k, v]) => [
    k,
    v.alg === "ed25519"
      ? { alg: v.alg, seedHex: hex(v.seed), pub: b64u(v.pub), kid: kidOf(v.alg, v.pub), fingerprint: fingerprint(v.alg, v.pub) }
      : { alg: v.alg, secretHex: hex(v.secret), pub: b64u(v.pub), kid: kidOf(v.alg, v.pub), fingerprint: fingerprint(v.alg, v.pub) },
  ]),
);
const sasOut = (s, nm, nc, commit) => ({
  NmHex: hex(nm),
  NhHex: hex(nc),
  commit: b64u(commit),
  infoCanonical: td.decode(s.info),
  keyHex: hex(s.key),
  digits: s.digits,
  display: `${s.digits.slice(0, 3)} ${s.digits.slice(3)}`,
  transcriptHash: b64u(s.transcript),
});

const out = {
  about: {
    spec: "plugin/docs/specs/identity-v2/signatures-and-encoding.md",
    generator: "gen-vectors.mjs",
    node: process.version,
    libs: { "@noble/curves": "2.4.0", "@noble/hashes": "2.4.0", "@noble/ciphers": "2.4.0", "@getpaseo/relay": "0.13.2 (dist/noise)" },
    notes: [
      "All secrets are derived from public labels. Never use these keys outside tests.",
      "Timestamps: unix seconds for createdAt/iat/exp/notBefore/oldValidTo; unix milliseconds for ts/hts.",
      "noise.ikCacophonyKeys uses the cacophony keys and matches the cacophony.txt IK entry byte for byte (noise.cacophonyChecks).",
      "Statements outside log.entries name the head at seq 3 as their base unless they belong to a folded chain (deviceLink.chain, deviceRekey.chain, deviceRekey.vetoed, deviceRekey.soleDeviceChangeAdmin, deviceLeafRepair.chain, log.foldChecks, log.refold, log.noRevival, log.revocationDepth, log.closure); standalone ones are format examples.",
      "Every folded chain starts with log.entries[0..3]; chains and cases list only the entries after seq 3.",
      "Field versions (ver) are log positions; -1 means the genesis value (room-log-v2.md section 4.0).",
      "MLS commit entries are omitted from log.entries; epoch is 0 throughout.",
      "deviceRekey.vetoed: the device being rekeyed vetoes its own pending rekey at seq 5; an automatic approval 73 h after the request is rejected with vetoed (room-log-v2.md section 4.3).",
      "deviceRekey.soleDeviceChangeAdmin: room.policy.changed sets soleDeviceChange to admin at seq 4; the sole device requests a rekey at seq 5; an interactive admin approval 1 h later is accepted at seq 6, and an automatic one even after 72 h is rejected with auto_not_allowed (identity-model.md section 6.3).",
      "deviceLeafRepair: device.leaf.repair.requested by the device itself (decision round 8, item 1). keyPackageRef values are placeholders from public labels, not refs of real KeyPackages.",
      "log.noRevival: keys retired before a revocation stay retired after its re-fold (decision round 8, item 3); entries from seq 6 on are signed by host2.",
      "log.revocationDepth: nesting depth of admin.key.revoked is capped at 8 (decision round 8, item 4); the nine admin keys added there are derived from the labels depth-admin-1 to depth-admin-9 and are not listed in keys.",
      "mls.epochAuth uses a placeholder epoch_authenticator from a public label; mls.authenticatedData carries its hash (decision round 8, item 2).",
    ],
  },
  domain: { prefix: DOMAIN, tbsLayout: "utf8(prefix) || 0x00 || utf8(ctx) || 0x00 || payload", contexts: CONTEXTS, statementContext: "stmt:<type>", hashContext: "h:<label>" },
  keys: keyTable,
  rjcs: { accept: rjcsAccept, reject: rjcsReject },
  base64url: b64uCases,
  ed25519: { smallOrderPublicKeys: smallOrder, sNotReduced },
  genesis: { signed: genesisSigned, canonical: rjcs(genesisSigned), genesisHash: b64u(genesisHash), roomId },
  invite: { payload: invitePayload, code: inviteCode, inviteRef },
  noise: {
    cacophonyChecks,
    ikCacophonyKeys: { protocol: "Noise_IK_25519_ChaChaPoly_SHA256", prologueHex: NK.prologue, initStaticHex: CACO.init_static, respStaticHex: NK.resp_static, initEphemeralHex: NK.init_ephemeral, respEphemeralHex: NK.resp_ephemeral, ...ikCacophonyKeys },
    enrollment: {
      protocol: "Noise_IK_25519_ChaChaPoly_SHA256",
      prologueHex: hex(noisePrologue),
      initEphemeralHex: hex(det("ik-init-ephemeral", 32)),
      respEphemeralHex: hex(det("ik-resp-ephemeral", 32)),
      ...ikEnroll,
    },
  },
  enrollment: {
    signedObject: enrollSigned,
    signedCanonical: rjcs(enrollSigned),
    tbsHex: hex(tbs("enroll-request", rjcsBytes(enrollSigned))),
    sig: b64u(enrollSig),
    tokenKeyHex: hex(tokenKey),
    tokenMac: b64u(tokenMac),
    frame: enrollFrame,
    sas: sasOut(sas, Nm, Nh, sasCommit),
  },
  deviceLink: {
    payload: linkPayload,
    code: linkCode,
    linkRef,
    tokenKeyHex: hex(linkTokenKey),
    noise: { handshakeHash: ikLink.handshakeHash, initEphemeralHex: hex(det("link-init-ephemeral", 32)), respEphemeralHex: hex(det("link-resp-ephemeral", 32)) },
    signedObject: linkEnrollSigned,
    sig: b64u(linkEnrollSig),
    tokenMac: b64u(linkTokenMac),
    sas: { ...sasOut(linkSas, NmLink, NcLink, linkSasCommit), note: "NhHex is the confirming device's nonce (link.nonce), not a host nonce" },
    linkCreated,
    deviceAdded,
    deviceAddedBodyHash: addRef,
    deviceAddApproved,
    chain: {
      prefix: "log.entries[0..3], then these entries at seq 4, 5 and 6",
      entries: deviceLinkChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      holdMs: 72 * HOUR,
      cases: deviceLinkCases,
    },
  },
  deviceRekey: {
    deviceRekeyed: soleRekeyed,
    deviceRekeyedBodyHash: rekeyRef,
    chain: {
      prefix: "log.entries[0..3], then these entries at seq 4 and 5",
      entries: deviceRekeyChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      holdMs: 72 * HOUR,
      note: "the requester is the member's only active device, so the rekey hold is 72 h (decision round 5, item 3)",
      cases: deviceRekeyCases,
    },
    vetoed: rekeyVetoCase,
    soleDeviceChangeAdmin: {
      prefix: "log.entries[0..3], then these entries at seq 4 to 6",
      entries: soleAdminChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      note: 'room.policy.changed sets soleDeviceChange to "admin"; the sole device requests a rekey; an admin approves it interactively 1 h later',
      cases: soleAdminCases,
    },
  },
  deviceLeafRepair: {
    statement: leafRepair,
    chain: {
      prefix: "log.entries[0..3], then these entries at seq 4 and 5",
      entries: leafRepairChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      groupIntervalMs: HOUR,
      windowMs: 24 * HOUR,
      maxPerWindow: 8,
      note: "Sam's laptop asks twice, 61 min apart, for its own leaf in the room group (scope null, generation 0) to be replaced",
      cases: leafRepairCases,
    },
  },
  statements: {
    creatorAdmitted: s0,
    laneCreated: s1,
    memberAdmitted: s2,
    grantIssued: s3,
    memberLeft: s4,
    memberRoleChanged,
    deviceRekeyed,
    adminKeyRotated,
    hostKeyRotated,
    roomPolicyChanged,
    laneNamesChanged,
    deviceAddVetoed: dlVeto,
    deviceConflictResolved: conflictResolved,
    deviceRemoved: dlRemoved,
    adminAdded: adminCAdded,
    adminAddedByRecovery: adminBAdded,
    adminKeyRevoked: adminCRevoked,
    roomCloseProposed: closeProposed,
    roomClosed,
    recoveryKeyProposed,
    recoveryKeyRotated,
    deviceLeafRepairRequested: leafRepair,
    newKeySigCtx: "key-change-new",
  },
  log: {
    genesisHashAsPrev: b64u(genesisHash),
    entries: chain.map(publicEntry),
    bodies: chain.map((e) => ({ seq: e.entry.seq, statement: e.statement })),
    rosterAfter,
    equivocationExample: { a: publicEntry(e4), b: publicEntry(e4fork), bStatement: e4fork.statement },
    foldChecks: {
      prefix: "log.entries[0..3], then roleChain[0..1] at seq 4 and 5; each case is a single entry at seq 6",
      roleChain: roleChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      cases: foldCases,
      notes: [
        "heldStatement was signed at the head of seq 3, before roleChain[0]; the forward-base rule rejects it (R-1 fix b).",
        "abaStaleVersion names version 2 while the role is again 'watch' (version 5); an old-value check would have accepted it (R-1 fix a).",
      ],
    },
    refold: {
      prefix: "log.entries[0..3], then these entries at seq 4, 5 and 6",
      entries: refoldChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      rosterBefore: { seq: refoldBefore.rosterSeq, hash: refoldBefore.rosterHash },
      rosterAfter: { seq: refoldAfter.rosterSeq, hash: refoldAfter.rosterHash },
      notes: [
        "adminC (lineage of adminA) admits a ghost at seq 5; the recovery key revokes adminC from seq 5 at seq 6.",
        "The ghost admission becomes suspect, the roster returns to the members of position 2, and the roster position becomes 6 (R-7).",
      ],
      rejectRevocationBeforeStart: { prefix: "log.entries[0..3], refold.entries[0]", entry: publicEntry(refoldBad), statement: refoldBad.statement, expect: "revocation_before_since" },
    },
    noRevival: {
      prefix: "log.entries[0..3], then these entries at seq 4 to 8",
      entries: noRevivalChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      rosterBefore: { seq: noRevivalBefore.rosterSeq, hash: noRevivalBefore.rosterHash },
      rosterAfter: { seq: noRevivalAfter.rosterSeq, hash: noRevivalAfter.rosterHash },
      hostKeysAfter: noRevivalAfter.state.hostKeys.map((x) => ({ kid: x.kid, fromSeq: x.fromSeq, toSeq: x.toSeq, uncertified: x.uncertified })),
      notes: [
        "R adds adminB at 4; adminB rotates the host key to host2 at 5 and removes Sam's laptop at 6; R revokes adminB from 5 at 7; adminA signs a fence at 8.",
        "Both statements of adminB are suspect, but host-1 and the laptop's keys stay retired: host2 keeps signing, uncertified, and Sam keeps no device.",
        "Each case replaces seq 8 with case.entry.",
      ],
      cases: noRevivalCases,
    },
    revocationDepth: {
      prefix: "log.entries[0..3], then these entries at seq 4 to 20",
      entries: depthChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      depths: [1, 2, 3, 4, 5, 6, 7, 8],
      maxDepth: 8,
      notes: ["R adds nine admin keys at 4 to 12 and revokes eight of them from 13 at 13 to 20; the revocation at 13 + k has depth k + 1."],
      rejectTooDeep: { entry: publicEntry(depthTooDeep), statement: depthTooDeep.statement, expect: "revocation_too_deep" },
    },
    closure: {
      prefix: "log.entries[0..3], then these entries at seq 4, 5 and 6",
      entries: closureChain.map((e) => ({ ...publicEntry(e), statement: e.statement })),
      closeDelayS: policy0.closeDelay,
      notes: [
        "The recovery key adds adminB, which starts its own lineage; adminA proposes; adminB confirms 25 h later.",
        "Each case replaces seq 4 to 6 with case.chain (seq 4, 5) and case.entry (seq 6).",
      ],
      cases: closureCases,
    },
  },
  grant: { claims: grantClaims, token: grantToken, tbsHex: hex(tbs("lane-grant", rjcsBytes(grantClaims))) },
  mls: {
    identity: mlsIdentity,
    identitySig: b64u(mlsIdSig),
    credentialIdentityBytes: mlsCredentialIdentity,
    authenticatedData: rjcs(mlsAad),
    epochAuth: { input: rjcs(epochAuthInput), authenticatorHex: hex(epochAuthenticator), hash: epochAuth },
    adminSet,
    adminSetHash,
    authorityExtension,
    groupIds,
    witness: witnessPayload,
  },
  records: {
    single: { frame: td.decode(pingFrame), recordHex: hex(recordSingle) },
    split: { frame: td.decode(bigFrame), recordsHex: recordsSplit.map(hex) },
  },
  sealed: {
    kekHex: hex(kek),
    kekId,
    purpose,
    fileKeyHex: hex(fileKey),
    nonce: b64u(sealNonce),
    aad: td.decode(sealAad),
    plaintext: td.decode(sealPt),
    object: sealedObject,
    canonical: rjcs(sealedObject),
  },
};

if (failures.length) {
  console.error(`FAILED (${failures.length}):\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
const path = join(dirname(fileURLToPath(import.meta.url)), "vectors.json");
const fileText = `${JSON.stringify(out, null, 2)}\n`;
writeFileSync(path, fileText);
console.log(`ok: wrote ${path} (${Object.keys(out).length} sections); file sha256 ${createHash("sha256").update(fileText).digest("hex")}`);
