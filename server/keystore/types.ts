// KeyStore backend interface (identity-model 7.3). The plugin keeps exactly one secret outside its own
// files: the 32-byte KEK. Every backend is async and takes a timeout; a timeout is "locked".

export type NativeBackendName = "linux-secret-service" | "macos-keychain" | "windows-credman";
export type BackendName = NativeBackendName | `cli:${string}` | "fallback-file" | "operator-file";

export type ProbeResult = "available" | "locked" | "unavailable";

export interface KeyStoreBackend {
  readonly name: BackendName;
  /** True for the unprotected fallback file (raises the owner notice). */
  readonly fallback: boolean;
  probe(timeoutMs: number): Promise<ProbeResult>;
  /** The KEK, or null only for "no entry". Locked stores and OS errors throw KeyStoreError. */
  get(timeoutMs: number): Promise<Buffer | null>;
  put(kek: Uint8Array, timeoutMs: number): Promise<void>;
  delete(timeoutMs: number): Promise<boolean>;
}

export type KeyStoreErrorCode =
  /** The store cannot be reached at all (binding missing, no bus, constructor threw). */
  | "unavailable"
  /** Locked, or an OS error on a reachable store. */
  | "locked"
  /** No answer within the timeout (for example an unlock prompt nobody answers). Handled as locked. */
  | "timeout"
  /** The stored value is not a valid KEK. */
  | "kek_invalid"
  /** An operator setting is wrong (unknown backend name, bad KEK file). */
  | "misconfigured";

export class KeyStoreError extends Error {
  constructor(readonly code: KeyStoreErrorCode, message: string) {
    super(message);
    this.name = "KeyStoreError";
  }
}
