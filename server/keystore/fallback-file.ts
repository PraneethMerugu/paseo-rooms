// File backends (identity-model 7.5).
//
// fallback-file: keystore/kek.fallback inside plugin-data/rooms, owner-only, used when no keyring is
// available at first start. It protects nothing against a reader of the same files; the owner is told
// so (FALLBACK_NOTICE). The file names the kekId it belongs to, so a file copied from another
// installation, or left over from an earlier KEK, is refused instead of silently opening nothing.
//   kek.fallback = RJCS({ v: 1, typ: "kek-fallback", kekId, kek: b64u(32 bytes) })
// Windows DPAPI wrapping of this file (7.5 step 1) needs the PowerShell CLI backend: not done yet.
//
// operator-file: PASEO_ROOMS_KEK_FILE names a file of exactly 32 bytes supplied by the deployment
// (Docker or Kubernetes secret, systemd credential). Read-only to the plugin; same permission check.
import * as fs from "node:fs";
import { b64u, b64uDecode } from "../proto/b64u";
import { rjcsParse, rjcsText } from "../proto/rjcs";
import { writePrivateFile } from "../platform/durable";
import { ProtectionError, type FileProtection } from "../platform/file-protection";
import { KEK_BYTES, KEK_ID_RE } from "./sealed";
import { KeyStoreError, type KeyStoreBackend } from "./types";

export const FALLBACK_FILE = "kek.fallback";
export const FALLBACK_NOTICE = "Room keys are stored unprotected on disk. Anyone who can read this account's files or backups can read them.";

/** Typed refusal of an integrity-critical keystore file (corrupt, foreign or inconsistent). */
export class KeystoreFileError extends Error {
  readonly code = "keystore_inconsistent";
  constructor(message: string) {
    super(message);
    this.name = "KeystoreFileError";
  }
}

function errCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException)?.code;
}

/** Reads a file after the owner-only check; null if absent. */
function readProtected(path: string, protection: FileProtection): Buffer | null {
  try {
    fs.lstatSync(path);
  } catch (e) {
    if (errCode(e) === "ENOENT") return null;
    throw e;
  }
  const check = protection.verify(path);
  if (!check.ok) throw new ProtectionError(check.problems);
  return fs.readFileSync(path);
}

export function parseFallbackFile(bytes: Uint8Array): { kekId: string; kek: Buffer } {
  let v: unknown;
  try {
    v = rjcsParse(bytes);
  } catch {
    throw new KeystoreFileError("kek.fallback is malformed");
  }
  const o = v as Record<string, unknown>;
  const keys = o && typeof o === "object" && !Array.isArray(o) ? Object.keys(o).sort().join(",") : "";
  if (keys !== "kek,kekId,typ,v" || o.v !== 1 || o.typ !== "kek-fallback" || typeof o.kekId !== "string" || !KEK_ID_RE.test(o.kekId)) {
    throw new KeystoreFileError("kek.fallback is malformed");
  }
  try {
    return { kekId: o.kekId, kek: b64uDecode(o.kek as string, KEK_BYTES) };
  } catch {
    throw new KeystoreFileError("kek.fallback is malformed");
  }
}

/**
 * The fallback backend bound to one kekId: `get` refuses a file written for another KEK; `put` writes
 * the file for this kekId.
 */
export function fallbackFileBackend(path: string, kekId: string, protection: FileProtection): KeyStoreBackend {
  return {
    name: "fallback-file",
    fallback: true,
    async probe() {
      return "available";
    },
    async get() {
      const bytes = readProtected(path, protection);
      if (bytes === null) return null;
      try {
        const parsed = parseFallbackFile(bytes);
        if (parsed.kekId !== kekId) {
          parsed.kek.fill(0);
          throw new KeystoreFileError("kek.fallback belongs to another KEK than keystore/meta.json names");
        }
        return parsed.kek;
      } finally {
        bytes.fill(0);
      }
    },
    async put(kek) {
      if (kek.length !== KEK_BYTES) throw new KeyStoreError("kek_invalid", "KEK must be 32 bytes");
      writePrivateFile(path, rjcsText({ v: 1, typ: "kek-fallback", kekId, kek: b64u(kek) }), { protection });
    },
    async delete() {
      try {
        fs.unlinkSync(path);
        return true;
      } catch (e) {
        if (errCode(e) === "ENOENT") return false;
        throw e;
      }
    },
  };
}

/** Operator-provided KEK (PASEO_ROOMS_KEK_FILE). Exactly 32 raw bytes, owner-only. Never written by the plugin. */
export function operatorFileBackend(path: string, protection: FileProtection): KeyStoreBackend {
  return {
    name: "operator-file",
    fallback: false,
    async probe() {
      try {
        fs.lstatSync(path);
        return "available";
      } catch {
        return "unavailable";
      }
    },
    async get() {
      const bytes = readProtected(path, protection);
      if (bytes === null) throw new KeyStoreError("misconfigured", "PASEO_ROOMS_KEK_FILE names a file that does not exist");
      if (bytes.length !== KEK_BYTES) {
        bytes.fill(0);
        throw new KeyStoreError("misconfigured", `PASEO_ROOMS_KEK_FILE must hold exactly ${KEK_BYTES} bytes`);
      }
      return bytes;
    },
    async put() {
      throw new KeyStoreError("misconfigured", "The operator KEK file is read-only to the plugin");
    },
    async delete() {
      return false;
    },
  };
}
