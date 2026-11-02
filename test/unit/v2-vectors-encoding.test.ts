// Identity v2 milestone I-1: RJCS, strict base64url, TBS and contexts, key ids, fingerprints and
// Ed25519 checks against docs/design/specs/identity-v2/vectors/vectors.json, read directly so the tests
// and the spec cannot drift. Seeds in the vectors are test-only (derived from public labels);
// assertion messages name keys, never print them.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { z } from "zod";
import { b64u, b64uDecode, b64uDecodeVar, b64uLength, isB64u } from "../../server/proto/b64u";
import {
  CTX_ENROLL_REQUEST,
  CTX_GENESIS,
  CTX_KEY_CHANGE_NEW,
  CTX_LANE_GRANT,
  CTX_LOG_ENTRY,
  CTX_MLS_IDENTITY,
  CTX_STMT_PREFIX,
  DERIVATION_LABELS,
  H_ADMIN_SET,
  H_GENESIS,
  H_LOG_BODY,
  H_LOG_ENTRY,
  H_MLS_GROUP,
  H_SAS_COMMIT,
  H_SAS_TRANSCRIPT,
  HASH_CTX_PREFIX,
  HASH_LABELS,
  KDF_FILE_KEY,
  KDF_INVITE_TOKEN_KEY,
  KDF_LINK_TOKEN_KEY,
  KDF_SAS,
  MAC_ENROLL_TOKEN,
  PROLOGUE_NOISE_IK,
  PROTOCOL_PREFIX,
  SIGNATURE_CONTEXTS,
  STMT_LOG_WITNESS,
  stmtContext,
} from "../../server/proto/contexts";
import { inviteRef, isId, isRoomId, isServerId, linkRef, newId, newServerId, roomIdOf, type EntityKind } from "../../server/proto/ids";
import {
  ed25519PrivateKeyFromSeed,
  fingerprint,
  fingerprintOfKid,
  isSignatureScalarReduced,
  isSmallOrderEd25519,
  isValidEd25519PublicKey,
  keyEqual,
  kid,
  rawPublicKey,
  verify,
  verifyEd25519,
  x25519PrivateKeyFromSecret,
  type KeyAlg,
} from "../../server/proto/keys";
import { rjcs, rjcsParse, rjcsText, RJCS_MAX_BYTES, RJCS_MAX_DEPTH } from "../../server/proto/rjcs";
import { H, hkdf, hmac, sign, tbs, utf8 } from "../../server/proto/tbs";

const VECTORS_PATH = join(import.meta.dirname, "..", "..", "docs", "design", "specs", "identity-v2", "vectors", "vectors.json");
const V = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));

const hex = (h: string) => Buffer.from(h, "hex");
const k32 = (text: string) => b64uDecode(text, 32);
const s64 = (text: string) => b64uDecode(text, 64);

interface VectorKey {
  alg: KeyAlg;
  seedHex?: string;
  secretHex?: string;
  pub: string;
  kid: string;
  fingerprint: string;
}
const KEYS = V.keys as Record<string, VectorKey>;
const keyByKid = new Map(Object.entries(KEYS).map(([name, k]) => [k.kid, { name, ...k }]));
const seedOf = (pub: string) => {
  const k = Object.values(KEYS).find((x) => x.pub === pub && x.seedHex);
  assert.ok(k, "vector key with this public key");
  return ed25519PrivateKeyFromSeed(hex(k.seedHex!));
};

interface SignedStatement {
  body: { typ: "stmt"; type: string; producer: { kind: string; kid: string }; data: any };
  sig: string;
}

/** Every signed statement anywhere in the vectors: standalone, log bodies, chains and fold cases. */
function allStatements(): { path: string; s: SignedStatement }[] {
  const out: { path: string; s: SignedStatement }[] = [];
  const walk = (node: unknown, path: string) => {
    if (!node || typeof node !== "object") return;
    const n = node as any;
    if (n.body && n.body.typ === "stmt" && typeof n.sig === "string") out.push({ path, s: n });
    for (const [k, child] of Object.entries(n)) walk(child, `${path}.${k}`);
  };
  walk(V, "$");
  return out;
}

// ---- RJCS (section 2) ----

test("rjcs.accept: strict parse accepts, and re-encoding gives the same bytes", () => {
  assert.equal(V.rjcs.accept.length, 6);
  for (const { canonical, hex: h } of V.rjcs.accept) {
    const bytes = hex(h);
    assert.equal(bytes.toString("utf8"), canonical);
    const value = rjcsParse(bytes);
    assert.deepEqual(Buffer.from(rjcs(value)), bytes, canonical);
  }
  // Integer-like keys enumerate as 1, 2, 10 in JavaScript but sort as strings.
  assert.equal(rjcsText({ "2": "c", "10": "b", "1": "a" }), '{"1":"a","10":"b","2":"c"}');
  assert.equal(rjcsText({ b: 1, aa: { z: -(2 ** 53 - 1), y: 2 ** 53 - 1 }, a: [true, false, null], _: 0, A: "x" }), V.rjcs.accept[0].canonical);
});

test("rjcs.reject: all 20 inputs are rejected by the strict parse", () => {
  assert.equal(V.rjcs.reject.length, 20);
  for (const { hex: h, why } of V.rjcs.reject) assert.throws(() => rjcsParse(hex(h)), Error, why);
});

test("rjcs encoder enforces the value model, depth and size limits", () => {
  for (const bad of [{ a: 1.5 }, { a: -0 }, { a: NaN }, { a: Infinity }, { a: 2 ** 53 }, { a: undefined }, { a: "\ud800" }, { "a-b": 1 }, { ["x".repeat(65)]: 1 }, { a: new Date(0) }, { a: 1n }, { a: () => 1 }])
    assert.throws(() => rjcs(bad));
  assert.throws(() => rjcs(JSON.parse('{"__proto__":1}')));
  assert.throws(() => rjcs({ constructor: 1 }));
  let nested: unknown = 0;
  for (let i = 0; i < RJCS_MAX_DEPTH; i++) nested = [nested];
  assert.doesNotThrow(() => rjcs(nested));
  assert.throws(() => rjcs([nested]));
  const big = { s: "x".repeat(RJCS_MAX_BYTES) };
  assert.throws(() => rjcs(big));
  assert.throws(() => rjcsParse(Buffer.from(JSON.stringify(big))));
  assert.doesNotThrow(() => rjcsParse(Buffer.from(JSON.stringify(big)), RJCS_MAX_BYTES * 2));
});

test("rjcs: every canonical object in the vectors strict-parses to itself", () => {
  for (const text of [V.genesis.canonical, V.sealed.canonical, V.sealed.aad, V.enrollment.signedCanonical, V.mls.credentialIdentityBytes, V.enrollment.sas.infoCanonical]) {
    assert.equal(rjcsText(rjcsParse(utf8(text))), text);
  }
});

// ---- base64url (section 4) ----

test("base64url: accepted and rejected forms", () => {
  assert.equal(V.base64url.length, 8);
  for (const c of V.base64url) {
    if (c.bytes === null) {
      assert.throws(() => b64uDecodeVar(c.text, 64), c.why);
      continue;
    }
    assert.equal(isB64u(c.text, c.bytes), c.ok, c.why);
    if (c.ok) assert.equal(b64u(b64uDecode(c.text, c.bytes)), c.text);
  }
  assert.deepEqual([16, 24, 32, 64].map(b64uLength), [22, 32, 43, 86]);
  assert.throws(() => b64uDecodeVar("A", 64), "4k+1 characters");
  assert.throws(() => b64uDecodeVar("AB", 64), "non-zero trailing bits");
  assert.equal(b64uDecodeVar("AA", 64).length, 1);
});

// ---- keys, kids, fingerprints (section 5) ----

test("keys: public keys from seeds, kids and fingerprints", () => {
  const names = Object.keys(KEYS);
  assert.ok(names.length >= 20);
  for (const [name, k] of Object.entries(KEYS)) {
    const pub = k32(k.pub);
    const priv = k.alg === "ed25519" ? ed25519PrivateKeyFromSeed(hex(k.seedHex!)) : x25519PrivateKeyFromSecret(hex(k.secretHex!));
    assert.ok(keyEqual(rawPublicKey(priv), pub), `${name}: public key from secret`);
    assert.equal(kid(k.alg, pub), k.kid, `${name}: kid`);
    assert.equal(k.kid.length, 43);
    assert.equal(fingerprint(k.alg, pub), k.fingerprint, `${name}: fingerprint`);
    assert.equal(fingerprintOfKid(k.kid), k.fingerprint);
    assert.match(k.fingerprint, /^([a-z2-7]{4}-){7}[a-z2-7]{4}$/);
    if (k.alg === "ed25519") assert.ok(isValidEd25519PublicKey(pub), `${name}: valid Ed25519 key`);
  }
  // The algorithm byte separates kids of the same 32 bytes.
  const pub = k32(KEYS.adminA.pub);
  assert.notEqual(kid("ed25519", pub), kid("x25519", pub));
  assert.ok(!keyEqual(pub, k32(KEYS.adminB.pub)));
});

// ---- Ed25519 (section 5.1) ----

test("ed25519: small-order public keys are rejected", () => {
  for (const c of V.ed25519.smallOrderPublicKeys) {
    const raw = k32(c.pub);
    assert.equal(c.expect, "reject");
    assert.ok(isSmallOrderEd25519(raw), c.why);
    assert.ok(!isValidEd25519PublicKey(raw), c.why);
    // A signature check under such a key fails before node:crypto sees it.
    assert.ok(!verifyEd25519(raw, utf8("x"), Buffer.alloc(64)), c.why);
  }
  // y >= p is not a canonical encoding (here y = p + 1, an alias of the identity).
  const nonCanonical = Buffer.alloc(32, 0xff);
  nonCanonical[0] = 0xee;
  nonCanonical[31] = 0x7f;
  assert.ok(!isValidEd25519PublicKey(nonCanonical));
  for (const k of Object.values(KEYS)) if (k.alg === "ed25519") assert.ok(!isSmallOrderEd25519(k32(k.pub)));
});

test("ed25519: the S + L signature fails, the original grant signature verifies", () => {
  const c = V.ed25519.sNotReduced;
  assert.equal(c.ctx, CTX_LANE_GRANT);
  assert.equal(c.payload, "grant.claims");
  const payload = rjcs(V.grant.claims);
  const [, , goodSig] = V.grant.token.split(".");
  assert.ok(verify(k32(c.pub), CTX_LANE_GRANT, payload, s64(goodSig)));
  assert.ok(isSignatureScalarReduced(s64(goodSig)));
  assert.ok(!isSignatureScalarReduced(s64(c.sig)));
  assert.ok(!verify(k32(c.pub), CTX_LANE_GRANT, payload, s64(c.sig)), c.why);
});

// ---- TBS and signatures (section 3) ----

test("domain: prefix, layout and context lists match the vectors", () => {
  assert.equal(V.domain.prefix, PROTOCOL_PREFIX);
  assert.deepEqual(tbs("x", utf8("p")), Buffer.concat([utf8(PROTOCOL_PREFIX), Buffer.from([0]), utf8("x"), Buffer.from([0]), utf8("p")]));
  const ours = new Set<string>([...SIGNATURE_CONTEXTS, "stmt", MAC_ENROLL_TOKEN]);
  assert.deepEqual(new Set(V.domain.contexts), ours);
  assert.equal(V.domain.statementContext, `${CTX_STMT_PREFIX}<type>`);
  assert.equal(V.domain.hashContext, `${HASH_CTX_PREFIX}<label>`);
  // Every context string and label is distinct once hash labels carry their h: prefix.
  const all = [...SIGNATURE_CONTEXTS, ...DERIVATION_LABELS, ...HASH_LABELS.map((l) => HASH_CTX_PREFIX + l)];
  assert.equal(new Set(all).size, all.length);
  for (const bad of ["", "A", "a b", "a\u0000b", "x".repeat(65), "é"]) assert.throws(() => tbs(bad));
  assert.throws(() => stmtContext("Member.Admitted"));
  assert.throws(() => stmtContext("a:b"));
});

test("genesis: signature, canonical bytes, genesisHash and roomId", () => {
  const g = V.genesis;
  const admin = KEYS.adminA;
  assert.equal(g.signed.kid, admin.kid);
  const body = rjcs(g.signed.body);
  assert.equal(b64u(sign(ed25519PrivateKeyFromSeed(hex(admin.seedHex!)), CTX_GENESIS, body)), g.signed.sig);
  assert.ok(verify(k32(admin.pub), CTX_GENESIS, body, s64(g.signed.sig)));
  for (const ctx of SIGNATURE_CONTEXTS.filter((c) => c !== CTX_GENESIS)) assert.ok(!verify(k32(admin.pub), ctx, body, s64(g.signed.sig)), ctx);
  const canonical = rjcs(g.signed);
  assert.equal(Buffer.from(canonical).toString("utf8"), g.canonical);
  const genesisHash = H(H_GENESIS, canonical);
  assert.equal(b64u(genesisHash), g.genesisHash);
  assert.equal(roomIdOf(genesisHash), g.roomId);
  assert.equal(V.log.genesisHashAsPrev, g.genesisHash);
});

test("grant: TBS bytes, deterministic signature, prg2 token and context separation", () => {
  const g = V.grant;
  const host = KEYS.host;
  assert.equal(g.claims.hostKid, host.kid);
  const payload = rjcs(g.claims);
  assert.equal(tbs(CTX_LANE_GRANT, payload).toString("hex"), g.tbsHex);
  const sig = sign(ed25519PrivateKeyFromSeed(hex(host.seedHex!)), CTX_LANE_GRANT, payload);
  assert.equal(`prg2.${b64u(payload)}.${b64u(sig)}`, g.token);
  for (const ctx of [...SIGNATURE_CONTEXTS, MAC_ENROLL_TOKEN, ...DERIVATION_LABELS, stmtContext("grant.issued")]) {
    assert.equal(verify(k32(host.pub), ctx, payload, sig), ctx === CTX_LANE_GRANT, ctx);
  }
  const parts = g.token.slice("prg2.".length).split(".");
  assert.equal(parts.length, 2);
  assert.deepEqual(rjcsParse(b64uDecodeVar(parts[0], RJCS_MAX_BYTES)), g.claims);
});

test("statements: every signature verifies only under its own stmt:<type> context", () => {
  const found = allStatements();
  const types = [...new Set(found.map((f) => f.s.body.type)), STMT_LOG_WITNESS];
  assert.ok(found.length >= 21, `found ${found.length} statements`);
  for (const { path, s } of found) {
    const key = keyByKid.get(s.body.producer.kid);
    assert.ok(key, `${path}: producer kid names a vector key`);
    const pub = k32(key.pub);
    const body = rjcs(s.body);
    const sig = s64(s.sig);
    assert.equal(b64u(sign(seedOf(key.pub), stmtContext(s.body.type), body)), s.sig, `${path}: deterministic signature`);
    for (const t of types) assert.equal(verify(pub, stmtContext(t), body, sig), t === s.body.type, `${path} as ${t}`);
    for (const ctx of SIGNATURE_CONTEXTS) assert.ok(!verify(pub, ctx, body, sig), `${path} as ${ctx}`);
  }
});

test("key changes: newKeySig verifies under key-change-new with the new key only", () => {
  assert.equal(V.statements.newKeySigCtx, CTX_KEY_CHANGE_NEW);
  const withChange = allStatements().filter((f) => f.s.body.data?.change);
  assert.ok(withChange.length >= 7);
  for (const { path, s } of withChange) {
    const { change, newKeySig } = s.body.data;
    assert.equal(change.typ, "key-change");
    if (change.newSig === null) continue;
    const payload = rjcs(change);
    const sig = s64(newKeySig);
    assert.ok(verify(k32(change.newSig), CTX_KEY_CHANGE_NEW, payload, sig), path);
    assert.ok(!verify(k32(change.newSig), stmtContext(s.body.type), payload, sig), path);
    const producer = keyByKid.get(s.body.producer.kid)!;
    if (producer.pub !== change.newSig) assert.ok(!verify(k32(producer.pub), CTX_KEY_CHANGE_NEW, payload, sig), path);
  }
});

test("log entries: entry hash, body hash and host signature", () => {
  const host = KEYS.host;
  assert.equal(V.log.entries.length, V.log.bodies.length);
  let prev = V.genesis.genesisHash;
  V.log.entries.forEach((e: any, i: number) => {
    const entry = rjcs(e.entry);
    assert.equal(e.entry.prev, prev, `seq ${i} chains`);
    assert.equal(b64u(H(H_LOG_ENTRY, entry)), e.hash, `seq ${i} hash`);
    assert.equal(V.log.bodies[i].seq, e.entry.seq);
    assert.equal(b64u(H(H_LOG_BODY, rjcs(V.log.bodies[i].statement))), e.entry.bodyHash, `seq ${i} bodyHash`);
    assert.equal(e.entry.hostKid, host.kid);
    assert.ok(verify(k32(host.pub), CTX_LOG_ENTRY, entry, s64(e.hsig)), `seq ${i} hsig`);
    assert.ok(!verify(k32(host.pub), CTX_LANE_GRANT, entry, s64(e.hsig)));
    prev = e.hash;
  });
});

test("mls: identity signature, credential bytes, witness, admin set and group ids", () => {
  const m = V.mls;
  const devPub = k32(m.identity.deviceSig);
  const identity = rjcs(m.identity);
  assert.ok(verify(devPub, CTX_MLS_IDENTITY, identity, s64(m.identitySig)));
  assert.ok(!verify(devPub, CTX_ENROLL_REQUEST, identity, s64(m.identitySig)));
  assert.equal(rjcsText({ id: m.identity, sig: m.identitySig }), m.credentialIdentityBytes);
  const witness = rjcs(m.witness.witness);
  assert.equal(m.witness.kind, STMT_LOG_WITNESS);
  assert.ok(verify(devPub, stmtContext(STMT_LOG_WITNESS), witness, s64(m.witness.sig)));
  assert.ok(!verify(devPub, stmtContext("member.left"), witness, s64(m.witness.sig)));
  assert.deepEqual([...m.adminSet].sort(), m.adminSet);
  assert.equal(b64u(H(H_ADMIN_SET, rjcs(m.adminSet))), m.adminSetHash);
  for (const g of [m.groupIds.room, m.groupIds.scope]) assert.equal(H(H_MLS_GROUP, utf8(g.input)).toString("hex"), g.groupIdHex);
  assert.equal(rjcsText({ genesisHash: V.genesis.genesisHash, generation: 0 }), m.groupIds.room.input);
});

// ---- MAC, KDF and token strings (sections 3.3 and 6) ----

test("invite and enrollment: prc2 code, inviteRef, tokenKey, tokenMac, signature and SAS hashes", () => {
  const inv = V.invite;
  assert.equal(`prc2.${b64u(rjcs(inv.payload))}`, inv.code);
  assert.equal(inviteRef(inv.payload.inviteId), inv.inviteRef);
  const e = V.enrollment;
  const tokenKey = hkdf(k32(inv.payload.token), new Uint8Array(0), KDF_INVITE_TOKEN_KEY, new Uint8Array(0), 32);
  assert.equal(tokenKey.toString("hex"), e.tokenKeyHex);
  const signed = rjcs(e.signedObject);
  assert.equal(Buffer.from(signed).toString("utf8"), e.signedCanonical);
  assert.equal(tbs(CTX_ENROLL_REQUEST, signed).toString("hex"), e.tbsHex);
  assert.ok(verify(k32(e.signedObject.deviceSig), CTX_ENROLL_REQUEST, signed, s64(e.sig)));
  assert.ok(!verify(k32(e.signedObject.deviceSig), CTX_MLS_IDENTITY, signed, s64(e.sig)));
  assert.equal(b64u(hmac(tokenKey, MAC_ENROLL_TOKEN, signed)), e.tokenMac);
  assert.equal(e.frame.tokenMac, e.tokenMac);
  const sas = e.sas;
  const h = k32(e.signedObject.h);
  const [nm, nh] = [hex(sas.NmHex), hex(sas.NhHex)];
  assert.equal(b64u(H(H_SAS_COMMIT, nm)), sas.commit);
  assert.equal(e.signedObject.sasCommit, sas.commit);
  assert.equal(hkdf(Buffer.concat([nm, nh]), h, KDF_SAS, utf8(sas.infoCanonical), 8).toString("hex"), sas.keyHex);
  assert.equal(b64u(H(H_SAS_TRANSCRIPT, Buffer.concat([h, nm, nh, utf8(sas.infoCanonical)]))), sas.transcriptHash);
  // Noise IK prologue (enrollment-v2.md section 3.3).
  const prologue = tbs(PROLOGUE_NOISE_IK, rjcs({ genesisHash: V.genesis.genesisHash, serverId: inv.payload.endpoint.serverId }));
  assert.equal(prologue.toString("hex"), V.noise.enrollment.prologueHex);
});

test("device link: prl2 code, linkRef, link tokenKey and tokenMac", () => {
  const d = V.deviceLink;
  assert.equal(`prl2.${b64u(rjcs(d.payload))}`, d.code);
  assert.equal(linkRef(d.payload.linkId), d.linkRef);
  const tokenKey = hkdf(k32(d.payload.token), new Uint8Array(0), KDF_LINK_TOKEN_KEY, new Uint8Array(0), 32);
  assert.equal(tokenKey.toString("hex"), d.tokenKeyHex);
  const signed = rjcs(d.signedObject);
  assert.ok(verify(k32(d.signedObject.deviceSig), CTX_ENROLL_REQUEST, signed, s64(d.sig)));
  assert.equal(b64u(hmac(tokenKey, MAC_ENROLL_TOKEN, signed)), d.tokenMac);
  // The invite-token label does not produce the link token key.
  assert.notEqual(hkdf(k32(d.payload.token), new Uint8Array(0), KDF_INVITE_TOKEN_KEY, new Uint8Array(0), 32).toString("hex"), d.tokenKeyHex);
});

test("sealed: AAD bytes, outer object and file key", () => {
  const s = V.sealed;
  assert.equal(rjcsText({ v: 2, typ: "sealed", purpose: s.purpose, kekId: s.kekId }), s.aad);
  assert.equal(rjcsText(s.object), s.canonical);
  assert.ok(isId("kek", s.kekId));
  assert.ok(isB64u(s.nonce, 24));
  assert.equal(hkdf(hex(s.kekHex), new Uint8Array(0), KDF_FILE_KEY, utf8(s.purpose), 32).toString("hex"), s.fileKeyHex);
  // The ciphertext is plaintext plus a 16-byte tag.
  assert.equal(b64uDecodeVar(s.object.ct, 1024).length, utf8(s.plaintext).length + 16);
});

// ---- identifiers (identity-model.md section 8) ----

test("ids: formats of every vector id and of new ids", () => {
  const kinds: [EntityKind, string][] = [
    ["member", V.grant.claims.sub],
    ["lane", V.grant.claims.laneId],
    ["grant", V.grant.claims.gid],
    ["invite", V.invite.payload.inviteId],
    ["link", V.deviceLink.payload.linkId],
    ["device", V.mls.identity.deviceId],
    ["scope", JSON.parse(V.mls.groupIds.scope.input).scope],
    ["kek", V.sealed.kekId],
  ];
  for (const [kind, id] of kinds) {
    assert.ok(isId(kind, id), `${kind} ${id}`);
    assert.ok(isId(kind, newId(kind)));
  }
  assert.ok(!isId("member", V.mls.identity.deviceId));
  assert.ok(!isId("member", "mem_" + "A".repeat(32)));
  assert.ok(!isId("member", "mem_" + "a".repeat(16)), "M1 64-bit ids are not v2 ids");
  assert.ok(isId("pending", newId("pending")));
  assert.ok(isRoomId(V.genesis.roomId));
  assert.ok(isServerId("roomEndpoint", V.genesis.signed.body.endpoint.serverId));
  assert.ok(isServerId("laneEndpoint", V.grant.claims.aud));
  assert.ok(!isServerId("laneEndpoint", V.genesis.signed.body.endpoint.serverId));
  assert.ok(isServerId("laneEndpoint", newServerId("laneEndpoint")));
  assert.throws(() => inviteRef("inv_short"));
});

// ---- signatures Q1: zod .strict() on nested signed objects ----

test("Q1: zod strictness is per object level; strictObject at every level rejects nested unknown fields", () => {
  const signed = { v: 2, typ: "key-change", subject: { kind: "device", id: "dev_x", extra: 1 } };
  // .strict() on the outer object does not reach nested objects: the unknown field is stripped silently.
  const OuterOnly = z.object({ v: z.literal(2), typ: z.string(), subject: z.object({ kind: z.string(), id: z.string() }) }).strict();
  assert.deepEqual(OuterOnly.parse(signed).subject, { kind: "device", id: "dev_x" });
  // Strict at every level: an error at the nested path, for objects, arrays of objects, optional and nullable fields.
  const Subject = z.strictObject({ kind: z.string(), id: z.string() });
  const Strict = z.strictObject({
    v: z.literal(2),
    typ: z.string(),
    subject: Subject,
    list: z.array(Subject).optional(),
    old: Subject.nullable().optional(),
  });
  const r = Strict.safeParse(signed);
  assert.equal(r.success, false);
  assert.equal(r.error!.issues[0].code, "unrecognized_keys");
  assert.deepEqual(r.error!.issues[0].path, ["subject"]);
  const clean = { v: 2, typ: "key-change", subject: { kind: "device", id: "dev_x" } };
  assert.ok(Strict.safeParse(clean).success);
  assert.equal(Strict.safeParse({ ...clean, list: [{ kind: "a", id: "b", x: 1 }] }).success, false);
  assert.equal(Strict.safeParse({ ...clean, old: { kind: "a", id: "b", x: 1 } }).success, false);
  assert.equal(Strict.safeParse({ ...clean, extra: 1 }).success, false);
  // Derived schemas keep strictness; a discriminated union of strict objects stays strict.
  assert.equal(Strict.extend({ more: z.number() }).safeParse({ ...clean, more: 1, extra: 1 }).success, false);
  assert.equal(Strict.pick({ v: true }).safeParse({ v: 2, typ: "x" }).success, false);
  const Union = z.discriminatedUnion("type", [z.strictObject({ type: z.literal("a"), n: z.number() }), z.strictObject({ type: z.literal("b") })]);
  assert.equal(Union.safeParse({ type: "a", n: 1, x: 1 }).success, false);
  assert.ok(Union.safeParse({ type: "a", n: 1 }).success);
  // The .strict() method on z.object behaves like z.strictObject.
  assert.equal(z.object({ a: z.number() }).strict().safeParse({ a: 1, b: 2 }).success, false);
});
