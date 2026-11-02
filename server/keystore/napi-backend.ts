// Native KEK backend through @napi-rs/keyring 2.x (identity-model 7.3; Spike B, implementation plan 1.2).
//
// Loading rules settled by Spike B:
// - The binding is OPTIONAL and never imported statically: Paseo's plugin compiler (esbuild) cannot
//   bundle the `.node` file. It is loaded lazily with createRequire(<plugin dir>/package.json) and a
//   computed specifier that esbuild cannot see.
// - The plugin bundle has no usable __dirname, import.meta.url or cwd, so the plugin directory is
//   found through the daemon's config: $PASEO_HOME/config.json plugins["rooms"].path. `--id` installs
//   store the entry under another id, so a miss falls back to a scan of every plugins.*.path for a
//   package.json named "paseo-rooms". Any failure here means "native keyring unavailable": the
//   caller falls back (first start only) and reports why. It never stops the plugin.
// - Linux is ALWAYS pinned to Secret Service. The library's default store silently falls back to the
//   kernel keyutils store, which is lost at logout. keyutils is never used.
// - A missing platform package throws a plain Error at require time; a missing session bus throws at
//   AsyncEntry construction. Both are "unavailable".
// - Every call has a timeout (AbortSignal plus a timer, in case the binding ignores the signal). A
//   timeout counts as "locked".
//
// Untested (Spike B section 6): --id installs, a daemon started without PASEO_HOME, the
// desktop-managed daemon, macOS Keychain, Windows Credential Manager, musl and arm.
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import nodePath from "node:path";
import { KEK_BYTES } from "./sealed";
import { KeyStoreError, type KeyStoreBackend, type NativeBackendName, type ProbeResult } from "./types";

export const PLUGIN_ID = "rooms";
export const PLUGIN_PACKAGE_NAME = "paseo-rooms";
export const KEYRING_SERVICE = "paseo-rooms";
/** Pinned binding version; the loader accepts any 2.x (1.x returned null for a locked store). */
export const KEYRING_BINDING_VERSION = "2.1.2";
/** Linux store pin. Never "keyutils" and never the default store. */
export const LINUX_ENTRY_OPTIONS = Object.freeze({ linux: Object.freeze({ store: "secret-service" as const }) });

/** KeyStore account: `kek:` + the first 16 hex characters of sha256(canonicalHome) (identity-model 7.3). */
export function keyringAccount(canonicalHome: string): string {
  return `kek:${createHash("sha256").update(canonicalHome, "utf8").digest("hex").slice(0, 16)}`;
}

export function nativeBackendName(platform: NodeJS.Platform): NativeBackendName | null {
  if (platform === "linux") return "linux-secret-service";
  if (platform === "darwin") return "macos-keychain";
  if (platform === "win32") return "windows-credman";
  return null;
}

// ------------------------------------------------------------------------------------- discovery

export type DiscoveryFailure =
  | "config_missing"
  | "config_unreadable"
  | "not_registered"
  | "ambiguous"
  | "binding_missing"
  | "binding_invalid"
  | "binding_version";

export type DiscoveryResult = { ok: true; dir: string; how: string } | { ok: false; reason: DiscoveryFailure; detail: string };

export interface DiscoveryDeps {
  readFile: (p: string) => string;
}

const realDiscoveryDeps: DiscoveryDeps = { readFile: (p) => fs.readFileSync(p, "utf8") };

function packageNameAt(dir: string, deps: DiscoveryDeps): string | null {
  try {
    const name = (JSON.parse(deps.readFile(nodePath.join(dir, "package.json"))) as { name?: unknown }).name;
    return typeof name === "string" ? name : null;
  } catch {
    return null;
  }
}

/**
 * Finds this plugin's installed directory from the daemon config. Paths in `detail` are not logged by
 * callers as absolute paths (they can contain the user name); `how` names the config key only.
 */
export function discoverPluginDir(paseoHome: string, deps: DiscoveryDeps = realDiscoveryDeps): DiscoveryResult {
  const cfgPath = nodePath.join(paseoHome, "config.json");
  let text: string;
  try {
    text = deps.readFile(cfgPath);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    return { ok: false, reason: code === "ENOENT" ? "config_missing" : "config_unreadable", detail: `config.json ${code === "ENOENT" ? "not found" : `unreadable (${code ?? "error"})`}` };
  }
  let plugins: Record<string, unknown>;
  try {
    const cfg = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as { plugins?: unknown };
    plugins = cfg?.plugins && typeof cfg.plugins === "object" && !Array.isArray(cfg.plugins) ? (cfg.plugins as Record<string, unknown>) : {};
  } catch {
    return { ok: false, reason: "config_unreadable", detail: "config.json is not valid JSON" };
  }
  const pathOf = (id: string): string | null => {
    const p = (plugins[id] as { path?: unknown } | undefined)?.path;
    return typeof p === "string" && p.length > 0 ? p : null;
  };
  const own = pathOf(PLUGIN_ID);
  if (own && packageNameAt(own, deps) === PLUGIN_PACKAGE_NAME) return { ok: true, dir: own, how: `plugins.${PLUGIN_ID}.path` };
  // `paseo plugin install --id <other>`: scan every entry for our package name.
  const hits = Object.keys(plugins).filter((id) => {
    const p = pathOf(id);
    return p !== null && packageNameAt(p, deps) === PLUGIN_PACKAGE_NAME;
  });
  if (hits.length === 1) return { ok: true, dir: pathOf(hits[0])!, how: `plugins.<scan>.path (id ${hits[0].slice(0, 40)})` };
  if (hits.length > 1) return { ok: false, reason: "ambiguous", detail: `${hits.length} plugin entries point at a ${PLUGIN_PACKAGE_NAME} package` };
  return { ok: false, reason: "not_registered", detail: `no plugin entry in config.json points at a ${PLUGIN_PACKAGE_NAME} package` };
}

// --------------------------------------------------------------------------------------- binding

/** The subset of @napi-rs/keyring 2.x used here (index.d.ts of 2.1.2). */
export interface KeyringAsyncEntry {
  getSecret(signal?: AbortSignal | null): Promise<ArrayLike<number> | null>;
  setSecret(secret: Uint8Array, signal?: AbortSignal | null): Promise<void>;
  deleteCredential(signal?: AbortSignal | null): Promise<boolean>;
}
export interface KeyringBinding {
  AsyncEntry: new (service: string, account: string, options?: unknown) => KeyringAsyncEntry;
}

/** `require` rooted at a directory. Tests pass a fake; production uses createRequire. */
export type RequireFrom = (dir: string) => (specifier: string) => unknown;

const realRequireFrom: RequireFrom = (dir) => createRequire(nodePath.join(dir, "package.json"));

/** Computed so esbuild cannot see (and try to bundle) the native module. */
const BINDING_SPECIFIER = ["@napi-rs", "keyring"].join("/");

export type BindingResult = { ok: true; binding: KeyringBinding; how: string } | { ok: false; reason: DiscoveryFailure; detail: string };

function errSummary(e: unknown): string {
  const err = e as Error & { code?: unknown };
  const code = typeof err?.code === "string" ? ` ${err.code}` : "";
  return `${err?.name ?? "Error"}${code}: ${String(err?.message ?? e).split("\n")[0].slice(0, 120)}`;
}

/** Loads the optional binding from the plugin's own directory. Never throws. */
export function loadKeyringBinding(paseoHome: string, opts: { discovery?: DiscoveryDeps; requireFrom?: RequireFrom } = {}): BindingResult {
  const found = discoverPluginDir(paseoHome, opts.discovery);
  if (!found.ok) return found;
  let req: (s: string) => unknown;
  let mod: unknown;
  try {
    req = (opts.requireFrom ?? realRequireFrom)(found.dir);
    mod = req(BINDING_SPECIFIER);
  } catch (e) {
    return { ok: false, reason: "binding_missing", detail: `native keyring unavailable (${errSummary(e)})` };
  }
  if (typeof (mod as KeyringBinding | null)?.AsyncEntry !== "function") return { ok: false, reason: "binding_invalid", detail: "binding has no AsyncEntry" };
  try {
    const version = (req(`${BINDING_SPECIFIER}/package.json`) as { version?: unknown }).version;
    if (typeof version !== "string" || !version.startsWith("2.")) return { ok: false, reason: "binding_version", detail: `binding version ${String(version).slice(0, 20)} is not 2.x` };
  } catch {
    // package.json not resolvable (exports map): the AsyncEntry shape check above has to do.
  }
  return { ok: true, binding: mod as KeyringBinding, how: found.how };
}

// --------------------------------------------------------------------------------------- backend

/** Runs one keyring call with an AbortSignal and a hard timer. A timeout is "locked". */
export async function withTimeout<T>(what: string, timeoutMs: number, fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctl = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      ctl.abort();
      reject(new KeyStoreError("timeout", `Keyring ${what} timed out after ${timeoutMs} ms (locked, or waiting for an unlock prompt)`));
    }, timeoutMs);
    (timer as unknown as { unref?: () => void }).unref?.();
  });
  try {
    return await Promise.race([fn(ctl.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Backend over a loaded binding. Construction of the entry is the probe: it throws when the store is
 * unreachable (no session bus, no Secret Service provider) and is cached once it succeeds.
 */
export function napiBackend(binding: KeyringBinding, name: NativeBackendName, account: string): KeyStoreBackend {
  let entry: KeyringAsyncEntry | null = null;
  const getEntry = (): KeyringAsyncEntry => {
    if (entry) return entry;
    try {
      entry = new binding.AsyncEntry(KEYRING_SERVICE, account, LINUX_ENTRY_OPTIONS);
    } catch (e) {
      throw new KeyStoreError("unavailable", `Keyring store unavailable (${errSummary(e)})`);
    }
    return entry;
  };
  const failed = (what: string) => (e: unknown) => {
    if (e instanceof KeyStoreError) throw e;
    throw new KeyStoreError("locked", `Keyring ${what} failed (${errSummary(e)})`);
  };
  return {
    name,
    fallback: false,
    async probe(): Promise<ProbeResult> {
      try {
        getEntry();
        return "available";
      } catch {
        return "unavailable";
      }
    },
    async get(timeoutMs) {
      const e = getEntry();
      const raw = await withTimeout("read", timeoutMs, (signal) => e.getSecret(signal)).catch(failed("read"));
      if (raw === null || raw === undefined) return null;
      const kek = Buffer.from(raw as ArrayLike<number>);
      if (Array.isArray(raw)) raw.fill(0);
      else if (raw instanceof Uint8Array) raw.fill(0);
      if (kek.length !== KEK_BYTES) {
        kek.fill(0);
        throw new KeyStoreError("kek_invalid", `Keyring entry is not a ${KEK_BYTES}-byte KEK`);
      }
      return kek;
    },
    async put(kek, timeoutMs) {
      const e = getEntry();
      const copy = new Uint8Array(kek);
      try {
        await withTimeout("write", timeoutMs, (signal) => e.setSecret(copy, signal)).catch(failed("write"));
      } finally {
        copy.fill(0);
      }
    },
    async delete(timeoutMs) {
      const e = getEntry();
      return withTimeout("delete", timeoutMs, (signal) => e.deleteCredential(signal)).catch(failed("delete"));
    },
  };
}
