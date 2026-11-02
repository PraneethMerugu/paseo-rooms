// I-3: KeyStore and sealed files (identity-model 7.2, 7.3, 7.5; keyring spikes A and B).
// Every keyring here is a FAKE: no test loads @napi-rs/keyring or talks to Secret Service, Keychain or
// Credential Manager. Files live in temp directories only (never ~/.paseo).
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { inspect } from "node:util";
import { b64u } from "../../server/proto/b64u";
import { FALLBACK_NOTICE, parseFallbackFile } from "../../server/keystore/fallback-file";
import { ENV_KEK_FILE, ENV_KEYSTORE, Kek, openKeyStore, reportKeyStore, type KeyStoreStatus, type NativeLoad, type OpenKeyStoreOptions } from "../../server/keystore/keystore";
import { parseMeta } from "../../server/keystore/meta";
import { discoverPluginDir, keyringAccount, LINUX_ENTRY_OPTIONS, loadKeyringBinding, napiBackend, KEYRING_SERVICE, type KeyringBinding } from "../../server/keystore/napi-backend";
import { fileKey, open, parseSealedBytes, readSealedFile, seal, sealedAad, sealedText, SealedFileError, writeSealedFile } from "../../server/keystore/sealed";
import { KeyStoreError, type KeyStoreBackend, type NativeBackendName } from "../../server/keystore/types";
import { tempDir } from "./helpers";

const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "docs", "design", "specs", "identity-v2", "vectors", "vectors.json"), "utf8"));
const V = vectors.sealed;
const unhex = (h: string) => Buffer.from(h, "hex");

// ------------------------------------------------------------------------------------ sealed files

test("sealed vector: file key, AAD, outer object and canonical text match identity-model 7.2", () => {
  const kek = unhex(V.kekHex);
  assert.equal(fileKey(kek, V.purpose).toString("hex"), V.fileKeyHex);
  assert.equal(Buffer.from(sealedAad(V.purpose, V.kekId)).toString("utf8"), V.aad);
  const obj = seal(kek, V.kekId, V.purpose, Buffer.from(V.plaintext, "utf8"), Buffer.from(V.nonce, "base64url"));
  assert.deepEqual(obj, V.object);
  assert.equal(sealedText(obj), V.canonical);
  assert.equal(open(kek, V.kekId, V.purpose, parseSealedBytes(Buffer.from(V.canonical))).toString("utf8"), V.plaintext);
});

test("sealed: wrong purpose, wrong KEK id, wrong KEK and every modification are refused", () => {
  const kek = unhex(V.kekHex);
  const code = (c: string) => (e: unknown) => e instanceof SealedFileError && e.code === c;
  const otherPurpose = V.purpose.replace("mls-state", "keys");
  assert.throws(() => open(kek, V.kekId, otherPurpose, V.object), code("sealed_foreign_purpose"));
  assert.throws(() => open(kek, "kek_" + "0".repeat(32), V.purpose, V.object), code("sealed_foreign_kek"));
  // Relabelled to the other purpose: the purpose check passes, the AEAD (file key and AAD) refuses.
  assert.throws(() => open(kek, V.kekId, otherPurpose, { ...V.object, purpose: otherPurpose }), code("sealed_auth_failed"));
  const wrongKek = Buffer.from(kek);
  wrongKek[0] ^= 1;
  assert.throws(() => open(wrongKek, V.kekId, V.purpose, V.object), code("sealed_auth_failed"));
  const ct = Buffer.from(V.object.ct, "base64url");
  ct[3] ^= 0x80;
  assert.throws(() => open(kek, V.kekId, V.purpose, { ...V.object, ct: b64u(ct) }), code("sealed_auth_failed"));
  const nonce = Buffer.from(V.object.nonce, "base64url");
  nonce[0] ^= 1;
  assert.throws(() => open(kek, V.kekId, V.purpose, { ...V.object, nonce: b64u(nonce) }), code("sealed_auth_failed"));
  // Shape: extra or missing fields, other version, alg, short nonce, ciphertext shorter than the tag.
  for (const bad of [
    { ...V.object, extra: 1 },
    { ...V.object, v: 1 },
    { ...V.object, alg: "chacha20poly1305" },
    { ...V.object, nonce: V.object.nonce.slice(0, 30) },
    { ...V.object, ct: "AAAA" },
    { ...V.object, kekId: "kek_ABC" },
    (({ ct: _ct, ...rest }) => rest)(V.object),
    null,
    [],
  ]) {
    assert.throws(() => open(kek, V.kekId, V.purpose, bad), code("sealed_malformed"));
  }
  // File text: only the canonical form is accepted.
  for (const text of [V.canonical + "\n", JSON.stringify(V.object, null, 1), "﻿" + V.canonical, V.canonical.slice(0, -5), "not json"]) {
    assert.throws(() => parseSealedBytes(Buffer.from(text)), code("sealed_malformed"));
  }
});

test("sealed files: durable owner-only write, read back, corrupted and foreign files refused", () => {
  const t = tempDir();
  try {
    const kek = Buffer.alloc(32, 7);
    const kekId = "kek_" + "ab".repeat(16);
    const path = join(t.dir, "rooms", "admin", "room_x", "admin-key.sealed");
    writeSealedFile(path, kek, kekId, "admin-key:room_x", Buffer.from("secret-ish"));
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(readSealedFile(path, kek, kekId, "admin-key:room_x")?.toString(), "secret-ish");
    assert.equal(readSealedFile(join(t.dir, "missing.sealed"), kek, kekId, "admin-key:room_x"), null);
    // Copied to another role (foreign purpose).
    assert.throws(() => readSealedFile(path, kek, kekId, "host-keys:room_x"), (e: unknown) => (e as SealedFileError).code === "sealed_foreign_purpose");
    // Truncated on disk.
    writeFileSync(path, readFileSync(path).subarray(0, 40));
    assert.throws(() => readSealedFile(path, kek, kekId, "admin-key:room_x"), (e: unknown) => (e as SealedFileError).code === "sealed_malformed");
  } finally {
    t.cleanup();
  }
});

// ------------------------------------------------------------------------------- fake keyring

type Behaviour = { construct?: "throw"; get?: "throw" | "hang" | "null"; put?: "throw" };

/** A fake native backend over a Map. Never touches a real keyring. */
function fakeNative(store: Map<string, Buffer>, b: Behaviour = {}, name: NativeBackendName = "linux-secret-service") {
  const calls: string[] = [];
  const backend: KeyStoreBackend = {
    name,
    fallback: false,
    async probe() {
      calls.push("probe");
      return b.construct === "throw" ? "unavailable" : "available";
    },
    async get(timeoutMs) {
      calls.push("get");
      if (b.get === "throw") throw new KeyStoreError("locked", "Keyring read failed (unlock prompt was dismissed)");
      if (b.get === "hang") {
        await new Promise((r) => setTimeout(r, timeoutMs + 50));
        throw new KeyStoreError("timeout", "Keyring read timed out");
      }
      if (b.get === "null") return null;
      const v = store.get("kek");
      return v ? Buffer.from(v) : null;
    },
    async put(kek) {
      calls.push("put");
      if (b.put === "throw") throw new KeyStoreError("locked", "Secret Service: no result found");
      store.set("kek", Buffer.from(kek));
    },
    async delete() {
      calls.push("delete");
      return store.delete("kek");
    },
  };
  const load = (): NativeLoad => (b.construct === "throw" ? { ok: false, reason: "binding_missing", detail: "native keyring unavailable (Error: Cannot find native binding)" } : { ok: true, backend, how: "fake" });
  return { load, calls, backend };
}

function setup() {
  const t = tempDir();
  const home = join(t.dir, "home");
  mkdirSync(home, { mode: 0o700 });
  const dataDir = join(home, "plugin-data", "rooms");
  const logs: { event: string; fields: Record<string, unknown> }[] = [];
  const opts = (extra: Partial<OpenKeyStoreOptions>): OpenKeyStoreOptions => ({
    dataDir,
    paseoHome: home,
    env: {},
    platform: "linux",
    timeoutMs: 100,
    log: (event, fields) => logs.push({ event, fields }),
    ...extra,
  });
  return { t, home, dataDir, logs, opts };
}

function ready(s: KeyStoreStatus) {
  assert.equal(s.state, "ready", s.state === "ready" ? "" : `${s.state}: ${s.message}`);
  return s as Extract<KeyStoreStatus, { state: "ready" }>;
}

// ----------------------------------------------------------------------------- selection

test("first start with a working keyring: KEK stored, read back, meta records it; restart reads the same KEK", async () => {
  const { t, dataDir, logs, opts } = setup();
  try {
    const store = new Map<string, Buffer>();
    const f = fakeNative(store);
    const s1 = ready(await openKeyStore(opts({ native: f.load })));
    assert.equal(s1.backend, "linux-secret-service");
    assert.equal(s1.fallback, false);
    assert.equal(s1.notice, null);
    assert.deepEqual(f.calls, ["probe", "get", "put", "get"]);
    const meta = parseMeta(readFileSync(join(dataDir, "keystore", "meta.json"), "utf8"));
    assert.equal(meta.backend, "linux-secret-service");
    assert.equal(meta.kekId, s1.kek.kekId);
    assert.equal(existsSync(join(dataDir, "keystore", "kek.fallback")), false);
    const sealed = s1.kek.seal("keys:room_a", Buffer.from("x"));

    const s2 = ready(await openKeyStore(opts({ native: fakeNative(store).load })));
    assert.equal(s2.kek.kekId, s1.kek.kekId);
    assert.equal(s2.kek.open("keys:room_a", sealed).toString(), "x");
    assert.equal(s2.selection.how, "meta");
    assert.ok(logs.some((l) => l.event === "keystore_selected" && l.fields.backend === "linux-secret-service"));
    assert.ok(!logs.some((l) => l.event === "keystore_fallback"));
  } finally {
    t.cleanup();
  }
});

test("fallback selection: binding missing, constructor throws, or first write fails -> fallback file with the notice", async () => {
  for (const b of [{ construct: "throw" }, { put: "throw" }] as Behaviour[]) {
    const { t, dataDir, logs, opts } = setup();
    try {
      const s = ready(await openKeyStore(opts({ native: fakeNative(new Map(), b).load })));
      assert.equal(s.backend, "fallback-file");
      assert.equal(s.fallback, true);
      assert.equal(s.notice, FALLBACK_NOTICE);
      assert.ok(s.selection.nativeUnavailable, "the reason is reported to the owner");
      const report = reportKeyStore(s);
      assert.equal(report.notice, FALLBACK_NOTICE);
      assert.equal(report.state, "ready");
      const file = join(dataDir, "keystore", "kek.fallback");
      assert.equal(statSync(file).mode & 0o777, 0o600);
      assert.equal(parseFallbackFile(readFileSync(file)).kekId, s.kek.kekId);
      assert.equal(parseMeta(readFileSync(join(dataDir, "keystore", "meta.json"), "utf8")).fallback, true);
      assert.equal(logs.filter((l) => l.event === "keystore_fallback").length, 1);
      // Restart: the fallback notice stays, and a keyring that appears is only detected, not used silently.
      const s2 = ready(await openKeyStore(opts({ native: fakeNative(new Map()).load })));
      assert.equal(s2.kek.kekId, s.kek.kekId);
      assert.equal(s2.notice, FALLBACK_NOTICE);
      assert.equal(s2.migrationAvailable, true);
    } finally {
      t.cleanup();
    }
  }
});

test("a timeout at first start is 'locked', not a fallback", async () => {
  const { t, dataDir, opts } = setup();
  try {
    const s = await openKeyStore(opts({ native: fakeNative(new Map(), { get: "hang" }).load }));
    assert.equal(s.state, "locked");
    assert.equal(existsSync(join(dataDir, "keystore", "meta.json")), false);
    assert.equal(existsSync(join(dataDir, "keystore", "kek.fallback")), false);
  } finally {
    t.cleanup();
  }
});

test("7.3 outcomes once meta.json names a keyring: throw, timeout, null and unreachable never fall back or regenerate", async () => {
  const { t, dataDir, opts } = setup();
  try {
    const store = new Map<string, Buffer>();
    const first = ready(await openKeyStore(opts({ native: fakeNative(store).load })));
    const before = Buffer.from(store.get("kek")!);
    const cases: [Behaviour, string][] = [
      [{ get: "throw" }, "locked"],
      [{ get: "hang" }, "locked"],
      [{ get: "null" }, "kek_missing"],
      [{ construct: "throw" }, "unavailable"],
    ];
    for (const [b, want] of cases) {
      const f = fakeNative(store, b);
      const s = await openKeyStore(opts({ native: f.load }));
      assert.equal(s.state, want, JSON.stringify(b));
      assert.equal(s.backend, "linux-secret-service");
      assert.ok(!f.calls.includes("put"), "never regenerated");
      assert.equal(existsSync(join(dataDir, "keystore", "kek.fallback")), false, "never fell back");
      assert.equal(reportKeyStore(s).fallback, false);
    }
    assert.ok(store.get("kek")!.equals(before));
    assert.equal(parseMeta(readFileSync(join(dataDir, "keystore", "meta.json"), "utf8")).kekId, first.kek.kekId);
  } finally {
    t.cleanup();
  }
});

test("explicit backend: used or fails, never substituted; a mismatch with meta.json is refused", async () => {
  {
    const { t, opts } = setup();
    try {
      const s = await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "linux-secret-service" }, native: fakeNative(new Map(), { construct: "throw" }).load }));
      assert.equal(s.state, "unavailable");
      const s2 = await openKeyStore(opts({ configuredBackend: "linux-secret-service", native: fakeNative(new Map(), { put: "throw" }).load }));
      assert.equal(s2.state, "locked", "explicit keyring whose first write fails does not fall back");
      assert.equal((await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "keyutils" } }))).state, "misconfigured");
      assert.equal((await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "macos-keychain" } }))).state, "unavailable", "another platform's backend");
      assert.equal((await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "cli:secret-tool" } }))).state, "unavailable", "CLI backends not implemented yet");
    } finally {
      t.cleanup();
    }
  }
  {
    const { t, opts } = setup();
    try {
      const f = fakeNative(new Map());
      const s = ready(await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "fallback-file" }, native: f.load })));
      assert.equal(s.backend, "fallback-file");
      assert.equal(s.selection.how, "explicit");
      assert.deepEqual(f.calls, [], "explicit fallback never touches the keyring");
      const m = await openKeyStore(opts({ env: { [ENV_KEYSTORE]: "linux-secret-service" }, native: f.load }));
      assert.equal(m.state, "misconfigured");
    } finally {
      t.cleanup();
    }
  }
});

test("operator KEK file: exactly 32 bytes, owner-only; recorded as operator-file", async () => {
  const { t, opts } = setup();
  try {
    const kf = join(t.dir, "kek.bin");
    writeFileSync(kf, Buffer.alloc(32, 9), { mode: 0o600 });
    const s = ready(await openKeyStore(opts({ env: { [ENV_KEK_FILE]: kf } })));
    assert.equal(s.backend, "operator-file");
    assert.equal(s.notice, null);
    const sealed = s.kek.seal("keys:room_a", Buffer.from("y"));
    assert.equal(ready(await openKeyStore(opts({ env: { [ENV_KEK_FILE]: kf } }))).kek.open("keys:room_a", sealed).toString(), "y");
    chmodSync(kf, 0o644);
    assert.equal((await openKeyStore(opts({ env: { [ENV_KEK_FILE]: kf } }))).state, "permission_error");
    chmodSync(kf, 0o600);
    writeFileSync(kf, Buffer.alloc(31));
    assert.equal((await openKeyStore(opts({ env: { [ENV_KEK_FILE]: kf } }))).state, "misconfigured");
    assert.equal((await openKeyStore(opts({ env: {} }))).state, "misconfigured", "meta says operator-file but the variable is gone");
  } finally {
    t.cleanup();
  }
});

test("corrupted or foreign keystore files are refused, never rewritten", async () => {
  const { t, dataDir, opts } = setup();
  try {
    const s = ready(await openKeyStore(opts({ native: fakeNative(new Map(), { construct: "throw" }).load })));
    const kdir = join(dataDir, "keystore");
    const fb = join(kdir, "kek.fallback");
    const metaPath = join(kdir, "meta.json");
    const good = readFileSync(fb);
    const goodMeta = readFileSync(metaPath, "utf8");
    // kek.fallback from another KEK (foreign file).
    writeFileSync(fb, `{"kek":"${b64u(Buffer.alloc(32, 1))}","kekId":"kek_${"cd".repeat(16)}","typ":"kek-fallback","v":1}`);
    assert.equal((await openKeyStore(opts({}))).state, "inconsistent");
    // Corrupt kek.fallback.
    writeFileSync(fb, "{garbage");
    assert.equal((await openKeyStore(opts({}))).state, "inconsistent");
    writeFileSync(fb, good);
    // Corrupt or edited meta.json.
    writeFileSync(metaPath, goodMeta.replace('"fallback": true', '"fallback": false'));
    assert.equal((await openKeyStore(opts({}))).state, "inconsistent");
    writeFileSync(metaPath, "{");
    assert.equal((await openKeyStore(opts({}))).state, "inconsistent");
    writeFileSync(metaPath, goodMeta);
    // Readable by others.
    chmodSync(fb, 0o644);
    const p = await openKeyStore(opts({}));
    assert.equal(p.state, "permission_error");
    chmodSync(fb, 0o600);
    assert.equal(ready(await openKeyStore(opts({}))).kek.kekId, s.kek.kekId);
    assert.equal(readFileSync(metaPath, "utf8"), goodMeta, "nothing was rewritten");
  } finally {
    t.cleanup();
  }
});

test("orphan KEK without meta.json: replaced only while no sealed file exists", async () => {
  const { t, dataDir, logs, opts } = setup();
  try {
    const store = new Map<string, Buffer>([["kek", Buffer.alloc(32, 5)]]);
    const s = ready(await openKeyStore(opts({ native: fakeNative(store).load })));
    assert.ok(!store.get("kek")!.equals(Buffer.alloc(32, 5)), "interrupted first start: replaced");
    assert.ok(logs.some((l) => l.event === "keystore_orphan_replaced"));
    s.kek.writeSealed(join(dataDir, "member", "rooms", "room_a", "keys.sealed"), "keys:room_a", Buffer.from("k"));
    const prior = Buffer.from(store.get("kek")!);
    unlinkSync(join(dataDir, "keystore", "meta.json")); // meta.json lost

    const f = fakeNative(store);
    const r = await openKeyStore(opts({ native: f.load }));
    assert.equal(r.state, "inconsistent");
    assert.ok(!f.calls.includes("put") && !f.calls.includes("delete"));
    assert.ok(store.get("kek")!.equals(prior), "the KEK that sealed files depend on is untouched");
  } finally {
    t.cleanup();
  }
});

test("key material never reaches logs, JSON or inspect", async () => {
  const { t, dataDir, logs, opts } = setup();
  try {
    const store = new Map<string, Buffer>();
    const s = ready(await openKeyStore(opts({ native: fakeNative(store).load })));
    const kek = store.get("kek")!;
    const forms = [kek.toString("hex"), kek.toString("base64url"), kek.toString("base64")];
    const text = JSON.stringify(logs) + JSON.stringify(s) + inspect(s, { depth: 5 }) + JSON.stringify(reportKeyStore(s)) + readFileSync(join(dataDir, "keystore", "meta.json"), "utf8");
    for (const f of forms) assert.ok(!text.includes(f));
    assert.equal(JSON.stringify(s.kek), JSON.stringify({ kekId: s.kek.kekId }));
    assert.equal(inspect(s.kek), `Kek(${s.kek.kekId})`);
    assert.throws(() => new Kek(Buffer.alloc(31), s.kek.kekId));
  } finally {
    t.cleanup();
  }
});

// ------------------------------------------------------------------------ discovery and binding

function pluginDir(root: string, name = "paseo-rooms"): string {
  const d = join(root, `p-${Math.random().toString(16).slice(2)}`);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name }));
  return d;
}

test("discovery: config.json plugins[id].path, --id scan, and every failure is a typed reason", () => {
  const t = tempDir();
  try {
    const home = join(t.dir, "home");
    mkdirSync(home);
    const cfg = (plugins: unknown) => writeFileSync(join(home, "config.json"), JSON.stringify({ plugins }));
    const reason = (r: ReturnType<typeof discoverPluginDir>) => (r.ok ? "ok" : r.reason);
    assert.equal(reason(discoverPluginDir(home)), "config_missing");
    writeFileSync(join(home, "config.json"), "{not json");
    assert.equal(reason(discoverPluginDir(home)), "config_unreadable");
    cfg(undefined);
    assert.equal(reason(discoverPluginDir(home)), "not_registered");
    const own = pluginDir(t.dir);
    cfg({ rooms: { source: "directory", path: own } });
    const r = discoverPluginDir(home);
    assert.ok(r.ok && r.dir === own && r.how === "plugins.rooms.path");
    cfg({ rooms: { source: "directory", path: join(t.dir, "gone") } });
    assert.equal(reason(discoverPluginDir(home)), "not_registered");
    cfg({ rooms: { source: "directory", path: pluginDir(t.dir, "someone-else") } });
    assert.equal(reason(discoverPluginDir(home)), "not_registered", "an entry named rooms that is not our package");
    cfg({ "my-rooms": { source: "directory", path: own }, other: { path: pluginDir(t.dir, "x") } });
    const scanned = discoverPluginDir(home);
    assert.ok(scanned.ok && scanned.dir === own, "--id install found by package name");
    cfg({ a: { path: own }, b: { path: pluginDir(t.dir) } });
    assert.equal(reason(discoverPluginDir(home)), "ambiguous");
  } finally {
    t.cleanup();
  }
});

test("binding loader: missing, invalid and wrong-version bindings are 'unavailable'; never throws", () => {
  const t = tempDir();
  try {
    const home = join(t.dir, "home");
    mkdirSync(home);
    const own = pluginDir(t.dir);
    writeFileSync(join(home, "config.json"), JSON.stringify({ plugins: { rooms: { path: own } } }));
    // Real createRequire from a temp plugin directory without node_modules: the binding is absent.
    const real = loadKeyringBinding(home);
    assert.ok(!real.ok && real.reason === "binding_missing");
    const throwing = loadKeyringBinding(home, { requireFrom: () => () => { throw new Error("Cannot find native binding. npm has a bug related to optional dependencies"); } });
    assert.ok(!throwing.ok && throwing.reason === "binding_missing" && /Cannot find native binding/.test(throwing.detail));
    const invalid = loadKeyringBinding(home, { requireFrom: () => () => ({}) });
    assert.ok(!invalid.ok && invalid.reason === "binding_invalid");
    const v1 = loadKeyringBinding(home, { requireFrom: () => (s) => (s.endsWith("package.json") ? { version: "1.2.0" } : { AsyncEntry: class {} }) });
    assert.ok(!v1.ok && v1.reason === "binding_version", "1.x returned null for locked stores");
    const v2 = loadKeyringBinding(home, { requireFrom: () => (s) => (s.endsWith("package.json") ? { version: "2.1.2" } : { AsyncEntry: class {} }) });
    assert.ok(v2.ok);
  } finally {
    t.cleanup();
  }
});

test("default loader: discovery failure falls back with the reason reported (no real binding involved)", async () => {
  const { t, home, opts } = setup();
  try {
    // No config.json in this PASEO_HOME, so discovery fails before any require.
    const s = ready(await openKeyStore(opts({})));
    assert.equal(s.backend, "fallback-file");
    assert.equal(s.selection.nativeUnavailable?.reason, "config_missing");
    assert.equal(existsSync(join(home, "config.json")), false);
  } finally {
    t.cleanup();
  }
  const other = setup();
  try {
    const s = ready(await openKeyStore(other.opts({ platform: "freebsd" })));
    assert.equal(s.selection.nativeUnavailable?.reason, "platform_unsupported");
  } finally {
    other.t.cleanup();
  }
});

test("napi backend over a fake binding: Secret Service pin, service and account, copies, timeout = locked", async () => {
  const seen: { service: string; account: string; options: unknown }[] = [];
  let stored: number[] | null = null;
  let mode: "ok" | "hang" | "short" | "construct" = "ok";
  const binding: KeyringBinding = {
    AsyncEntry: class {
      constructor(service: string, account: string, options?: unknown) {
        if (mode === "construct") throw Object.assign(new Error("Platform failure: DBus error: Using X11 for dbus-daemon autolaunch was disabled"), { code: "GenericFailure" });
        seen.push({ service, account, options });
      }
      async getSecret(signal?: AbortSignal | null) {
        if (mode === "hang") return new Promise<null>(() => void signal);
        if (mode === "short") return [1, 2, 3];
        return stored ? [...stored] : null;
      }
      async setSecret(secret: Uint8Array) {
        stored = [...secret];
      }
      async deleteCredential() {
        const had = stored !== null;
        stored = null;
        return had;
      }
    },
  };
  const account = keyringAccount("/home/o/.paseo");
  assert.match(account, /^kek:[0-9a-f]{16}$/);
  const b = napiBackend(binding, "linux-secret-service", account);
  assert.equal(await b.probe(10), "available");
  assert.deepEqual(seen[0], { service: KEYRING_SERVICE, account, options: LINUX_ENTRY_OPTIONS });
  assert.deepEqual(LINUX_ENTRY_OPTIONS, { linux: { store: "secret-service" } });
  assert.equal(await b.get(50), null);
  const kek = Buffer.alloc(32, 3);
  await b.put(kek, 50);
  assert.ok((await b.get(50))!.equals(kek));
  mode = "short";
  await assert.rejects(b.get(50), (e: unknown) => (e as KeyStoreError).code === "kek_invalid");
  mode = "hang";
  // The backend's timer is unref'd (it must not keep a daemon alive). Here nothing else holds the
  // event loop open, and Node 20 would end the test before the timer fires, so hold it explicitly.
  const keepAlive = setInterval(() => {}, 1000);
  const t0 = Date.now();
  try {
    await assert.rejects(b.get(30), (e: unknown) => (e as KeyStoreError).code === "timeout");
  } finally {
    clearInterval(keepAlive);
  }
  assert.ok(Date.now() - t0 < 1000);
  mode = "ok";
  assert.equal(await b.delete(50), true);
  mode = "construct";
  const nobus = napiBackend(binding, "linux-secret-service", account);
  assert.equal(await nobus.probe(10), "unavailable");
  await assert.rejects(nobus.get(10), (e: unknown) => (e as KeyStoreError).code === "unavailable");
});
