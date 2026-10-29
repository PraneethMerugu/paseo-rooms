// KeyStore: backend selection, the KEK handle and the status reported to the owner
// (identity-model 7.3, 7.5; implementation plan I-3).
//
// Selection, at first start only (no keystore/meta.json yet):
//   1. An explicit backend (plugin setting keystore.backend, or PASEO_ROOMS_KEYSTORE) is used or fails;
//      it is never substituted. PASEO_ROOMS_KEK_FILE selects the operator file.
//   2. The native binding (napi-backend.ts). Linux: Secret Service only.
//   3. CLI backends: not implemented in this release (secret-tool, security -i, PowerShell DPAPI).
//   4. The fallback file, with the owner notice, when the native backend is unavailable: binding or
//      plugin directory missing, the store constructor throws, or the first write fails.
//   5. meta.json records the choice. Afterwards the backend never changes silently: a locked,
//      unreachable or empty keyring stops room operations and asks the owner.
//
// A timeout is "locked", also at first start: an unanswered unlock prompt is not a reason to fall back.
// Before a first-start KEK is written, an existing KEK without meta.json (an interrupted first start)
// is replaced only if no sealed file exists; otherwise the state is "inconsistent" and nothing changes.
//
// Not implemented here (reported as next steps): automatic migration from the fallback file to a
// keyring once one appears (only detected: `migrationAvailable`), KEK rotation (keys 4.9), CLI
// backends, and the asynchronous RoomsRuntime states that surface this status in the UI.
import { randomBytes, timingSafeEqual } from "node:crypto";
import * as fs from "node:fs";
import { inspect } from "node:util";
import nodePath from "node:path";
import type { DurableDeps, WriteResult } from "../platform/durable";
import { defaultProtection, ProtectionError, type FileProtection, type ProtectionProblem } from "../platform/file-protection";
import { canonicalHome as platformCanonicalHome } from "../platform/home";
import { FALLBACK_FILE, FALLBACK_NOTICE, fallbackFileBackend, KeystoreFileError, operatorFileBackend } from "./fallback-file";
import { keystoreDir, readMeta, writeMeta, type KeystoreMeta } from "./meta";
import { keyringAccount, loadKeyringBinding, napiBackend, nativeBackendName, type DiscoveryDeps, type RequireFrom } from "./napi-backend";
import { hasSealedFiles, KEK_BYTES, newKekId, open, readSealedFile, seal, writeSealedFile, type SealedObject } from "./sealed";
import { KeyStoreError, type BackendName, type KeyStoreBackend } from "./types";

export const KEYSTORE_TIMEOUT_MS = 10_000;
export const ENV_KEYSTORE = "PASEO_ROOMS_KEYSTORE";
export const ENV_KEK_FILE = "PASEO_ROOMS_KEK_FILE";

/** The KEK in memory. Holds the bytes in a private field: JSON, inspect and logs show only the kekId. */
export class Kek {
  readonly #key: Buffer;
  constructor(key: Uint8Array, readonly kekId: string) {
    if (key.length !== KEK_BYTES) throw new Error("Kek: need 32 bytes");
    this.#key = Buffer.from(key);
  }
  seal(purpose: string, plaintext: Uint8Array): SealedObject {
    return seal(this.#key, this.kekId, purpose, plaintext);
  }
  open(purpose: string, value: unknown): Buffer {
    return open(this.#key, this.kekId, purpose, value);
  }
  writeSealed(path: string, purpose: string, plaintext: Uint8Array, deps?: Partial<DurableDeps>): WriteResult {
    return writeSealedFile(path, this.#key, this.kekId, purpose, plaintext, deps);
  }
  readSealed(path: string, purpose: string): Buffer | null {
    return readSealedFile(path, this.#key, this.kekId, purpose);
  }
  /** Best-effort zeroing (JS may have copied the bytes elsewhere). */
  dispose(): void {
    this.#key.fill(0);
  }
  toJSON(): { kekId: string } {
    return { kekId: this.kekId };
  }
  [inspect.custom](): string {
    return `Kek(${this.kekId})`;
  }
}

/** Result of trying to construct the native backend. */
export type NativeLoad = { ok: true; backend: KeyStoreBackend; how: string } | { ok: false; reason: string; detail: string };

export interface OpenKeyStoreOptions {
  dataDir: string;
  paseoHome: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  /** `keystore.backend` from plugin settings; takes precedence over PASEO_ROOMS_KEYSTORE. */
  configuredBackend?: string;
  protection?: FileProtection;
  timeoutMs?: number;
  /** Native backend factory. Default: load the optional binding from the plugin directory. Tests inject fakes. */
  native?: () => NativeLoad;
  log?: (event: string, fields: Record<string, unknown>) => void;
  now?: () => Date;
}

export type SelectionHow = "meta" | "explicit" | "operator" | "native" | "fallback";

export interface Selection {
  firstStart: boolean;
  how: SelectionHow;
  /** Why the native keyring was not used (first start), or why it cannot be reached. No secrets, no absolute paths. */
  nativeUnavailable: { reason: string; detail: string } | null;
}

export type KeyStoreState = "ready" | "locked" | "unavailable" | "kek_missing" | "misconfigured" | "inconsistent" | "permission_error";

export type KeyStoreStatus =
  | { state: "ready"; kek: Kek; backend: BackendName; fallback: boolean; notice: string | null; selection: Selection; migrationAvailable: boolean }
  | { state: Exclude<KeyStoreState, "ready">; backend: BackendName | null; message: string; problems?: ProtectionProblem[] };

/** What the owner sees (RPC and UI): never key material. */
export interface KeyStoreReport {
  state: KeyStoreState;
  backend: BackendName | null;
  fallback: boolean;
  notice: string | null;
  message: string | null;
  migrationAvailable: boolean;
  nativeUnavailable: { reason: string; detail: string } | null;
}

export function reportKeyStore(s: KeyStoreStatus): KeyStoreReport {
  if (s.state === "ready") {
    return { state: s.state, backend: s.backend, fallback: s.fallback, notice: s.notice, message: null, migrationAvailable: s.migrationAvailable, nativeUnavailable: s.selection.nativeUnavailable };
  }
  return { state: s.state, backend: s.backend, fallback: false, notice: null, message: s.message, migrationAvailable: false, nativeUnavailable: null };
}

const NATIVE_NAMES = new Set(["linux-secret-service", "macos-keychain", "windows-credman"]);

function parseExplicit(value: string | undefined): BackendName | null {
  if (value === undefined || value === "") return null;
  if (NATIVE_NAMES.has(value) || value === "fallback-file" || value === "operator-file" || /^cli:[a-z0-9-]{1,32}$/.test(value)) return value as BackendName;
  throw new KeyStoreError("misconfigured", `Unknown keystore backend "${value.slice(0, 40)}"`);
}

function defaultNative(paseoHome: string, platform: NodeJS.Platform, deps: { discovery?: DiscoveryDeps; requireFrom?: RequireFrom } = {}): NativeLoad {
  const name = nativeBackendName(platform);
  if (!name) return { ok: false, reason: "platform_unsupported", detail: `no native keyring backend for ${platform}` };
  let account: string;
  try {
    account = keyringAccount(platformCanonicalHome(paseoHome, { platform }));
  } catch (e) {
    return { ok: false, reason: "home_unresolved", detail: `PASEO_HOME cannot be resolved (${(e as NodeJS.ErrnoException)?.code ?? "error"})` };
  }
  const loaded = loadKeyringBinding(paseoHome, deps);
  if (!loaded.ok) return loaded;
  return { ok: true, backend: napiBackend(loaded.binding, name, account), how: loaded.how };
}

class StateError extends Error {
  constructor(readonly state: Exclude<KeyStoreState, "ready">, message: string, readonly backend: BackendName | null = null) {
    super(message);
  }
}

/**
 * Opens (first start: creates) the KEK. Never throws for the expected outcomes: they come back as a
 * state the runtime maps to its own states (ready, ready with the fallback notice, locked,
 * permission-error, and typed errors for the rest). Unexpected errors (for example a failed durable
 * write) are thrown.
 */
export async function openKeyStore(o: OpenKeyStoreOptions): Promise<KeyStoreStatus> {
  const log = o.log ?? (() => {});
  let backendName: BackendName | null = null;
  try {
    const status = await openInner(o, log, (n) => (backendName = n));
    if (status.state === "ready") {
      log("keystore_selected", { backend: status.backend, kekId: status.kek.kekId, firstStart: status.selection.firstStart, how: status.selection.how, nativeUnavailable: status.selection.nativeUnavailable });
      if (status.fallback) log("keystore_fallback", { reason: status.selection.nativeUnavailable?.reason ?? status.selection.how });
      if (status.migrationAvailable) log("keystore_migration_available", { backend: status.backend });
    }
    return status;
  } catch (e) {
    let s: Exclude<KeyStoreStatus, { state: "ready" }>;
    if (e instanceof StateError) s = { state: e.state, backend: e.backend ?? backendName, message: e.message };
    else if (e instanceof ProtectionError) s = { state: "permission_error", backend: backendName, message: e.message, problems: e.problems };
    else if (e instanceof KeystoreFileError) s = { state: "inconsistent", backend: backendName, message: e.message };
    else if (e instanceof KeyStoreError) {
      const state = e.code === "timeout" || e.code === "locked" ? "locked" : e.code === "kek_invalid" ? "inconsistent" : e.code;
      s = { state, backend: backendName, message: e.message };
    } else throw e;
    log("keystore_not_ready", { state: s.state, backend: s.backend, message: s.message.slice(0, 200) });
    return s;
  }
}

async function openInner(o: OpenKeyStoreOptions, log: NonNullable<OpenKeyStoreOptions["log"]>, setBackend: (n: BackendName) => void): Promise<KeyStoreStatus> {
  const env = o.env ?? process.env;
  const platform = o.platform ?? process.platform;
  const protection = o.protection ?? defaultProtection();
  const timeoutMs = o.timeoutMs ?? KEYSTORE_TIMEOUT_MS;
  const native = o.native ?? (() => defaultNative(o.paseoHome, platform));
  const kdir = keystoreDir(o.dataDir);
  const fallbackPath = nodePath.join(kdir, FALLBACK_FILE);
  const operatorPath = env[ENV_KEK_FILE] || undefined;

  protection.ensureDir(kdir);
  const explicit = parseExplicit(o.configuredBackend ?? env[ENV_KEYSTORE]);
  if (operatorPath && explicit && explicit !== "operator-file") throw new KeyStoreError("misconfigured", `${ENV_KEK_FILE} is set, but the keystore backend is set to ${explicit}`);

  const backendFor = (name: BackendName, kekId: string): { backend: KeyStoreBackend; how: string } => {
    setBackend(name);
    if (name === "fallback-file") return { backend: fallbackFileBackend(fallbackPath, kekId, protection), how: "file" };
    if (name === "operator-file") {
      if (!operatorPath) throw new KeyStoreError("misconfigured", `The operator KEK file is selected, but ${ENV_KEK_FILE} is not set`);
      return { backend: operatorFileBackend(operatorPath, protection), how: ENV_KEK_FILE };
    }
    if (name.startsWith("cli:")) throw new StateError("unavailable", `Keystore backend ${name} is not implemented in this release`, name);
    if (name !== nativeBackendName(platform)) throw new StateError("unavailable", `Keystore backend ${name} is not available on ${platform}`, name);
    const n = native();
    if (!n.ok) throw new StateError("unavailable", `The ${name} keyring cannot be reached: ${n.detail}`, name);
    if (n.backend.name !== name) throw new StateError("unavailable", `Native backend is ${n.backend.name}, expected ${name}`, name);
    return { backend: n.backend, how: n.how };
  };

  // --------------------------------------------------------------------------------- existing KEK
  const meta = readMeta(o.dataDir, protection);
  if (meta) {
    setBackend(meta.backend);
    if (explicit && explicit !== meta.backend) {
      throw new StateError("misconfigured", `keystore/meta.json records ${meta.backend}, but ${explicit} is configured. The backend never changes silently.`, meta.backend);
    }
    const { backend } = backendFor(meta.backend, meta.kekId);
    const key = await backend.get(timeoutMs);
    if (key === null) {
      throw new StateError("kek_missing", `The KEK recorded in keystore/meta.json is missing from ${meta.backend}. It is never regenerated silently: restore the entry, or reset Rooms data.`, meta.backend);
    }
    const kek = new Kek(key, meta.kekId);
    key.fill(0);
    let migrationAvailable = false;
    if (meta.fallback) {
      const n = native();
      migrationAvailable = n.ok && (await n.backend.probe(timeoutMs).catch(() => "unavailable" as const)) === "available";
    }
    return { state: "ready", kek, backend: meta.backend, fallback: meta.fallback, notice: meta.fallback ? FALLBACK_NOTICE : null, selection: { firstStart: false, how: "meta", nativeUnavailable: null }, migrationAvailable };
  }

  // ---------------------------------------------------------------------------------- first start
  const now = (o.now ?? (() => new Date()))();
  const orphanCheck = async (where: string, replace: () => Promise<unknown>): Promise<void> => {
    if (hasSealedFiles(o.dataDir)) {
      throw new StateError("inconsistent", `A KEK exists in ${where} but keystore/meta.json is missing, and sealed files exist. Nothing was changed.`);
    }
    await replace();
    log("keystore_orphan_replaced", { where });
  };
  if (fs.existsSync(fallbackPath)) await orphanCheck("kek.fallback", async () => fs.unlinkSync(fallbackPath));

  const create = async (backend: KeyStoreBackend, kekId: string, how: SelectionHow, nativeUnavailable: Selection["nativeUnavailable"]): Promise<KeyStoreStatus> => {
    setBackend(backend.name);
    const key = randomBytes(KEK_BYTES);
    try {
      await backend.put(key, timeoutMs);
      if (!backend.fallback) {
        const back = await backend.get(timeoutMs);
        const same = back !== null && back.length === KEK_BYTES && timingSafeEqual(back, key);
        back?.fill(0);
        if (!same) throw new StateError("inconsistent", `${backend.name} did not return the KEK that was just stored`, backend.name);
      }
      const record: KeystoreMeta = { v: 1, backend: backend.name, kekId, createdAt: now.toISOString(), fallback: backend.fallback };
      writeMeta(o.dataDir, record, protection);
      return { state: "ready", kek: new Kek(key, kekId), backend: backend.name, fallback: backend.fallback, notice: backend.fallback ? FALLBACK_NOTICE : null, selection: { firstStart: true, how, nativeUnavailable }, migrationAvailable: false };
    } finally {
      key.fill(0);
    }
  };
  const useOperatorFile = async (how: SelectionHow): Promise<KeyStoreStatus> => {
    const { backend } = backendFor("operator-file", "");
    const key = await backend.get(timeoutMs);
    if (!key) throw new KeyStoreError("misconfigured", `${ENV_KEK_FILE} is empty`);
    const kekId = newKekId();
    writeMeta(o.dataDir, { v: 1, backend: "operator-file", kekId, createdAt: now.toISOString(), fallback: false }, protection);
    const kek = new Kek(key, kekId);
    key.fill(0);
    return { state: "ready", kek, backend: "operator-file", fallback: false, notice: null, selection: { firstStart: true, how, nativeUnavailable: null }, migrationAvailable: false };
  };
  const useFallback = (how: SelectionHow, nativeUnavailable: Selection["nativeUnavailable"]) => {
    const kekId = newKekId();
    return create(fallbackFileBackend(fallbackPath, kekId, protection), kekId, how, nativeUnavailable);
  };
  /** Native first start: null means "unavailable, fall back" (only when not explicit). */
  const tryNative = async (backend: KeyStoreBackend, isExplicit: boolean): Promise<KeyStoreStatus | { unavailable: { reason: string; detail: string } }> => {
    setBackend(backend.name);
    try {
      if ((await backend.probe(timeoutMs)) !== "available") throw new KeyStoreError("unavailable", `${backend.name} store cannot be constructed`);
      const existing = await backend.get(timeoutMs);
      if (existing !== null) {
        existing.fill(0);
        await orphanCheck(backend.name, () => backend.delete(timeoutMs));
      }
      return await create(backend, newKekId(), isExplicit ? "explicit" : "native", null);
    } catch (e) {
      // Timeouts are "locked" (a prompt may be waiting); explicit backends never fall back.
      if (isExplicit || !(e instanceof KeyStoreError) || e.code === "timeout") throw e;
      return { unavailable: { reason: e.code === "unavailable" ? "store_unavailable" : "first_write_failed", detail: e.message.slice(0, 200) } };
    }
  };

  if (explicit === "operator-file" || (!explicit && operatorPath)) return useOperatorFile(explicit ? "explicit" : "operator");
  if (explicit === "fallback-file") return useFallback("explicit", null);
  if (explicit) {
    const { backend } = backendFor(explicit, "");
    return (await tryNative(backend, true)) as KeyStoreStatus;
  }
  const n = native();
  if (!n.ok) return useFallback("fallback", { reason: n.reason, detail: n.detail });
  const r = await tryNative(n.backend, false);
  if ("unavailable" in r) return useFallback("fallback", r.unavailable);
  return r;
}
