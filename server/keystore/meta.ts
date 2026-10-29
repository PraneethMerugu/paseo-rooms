// keystore/meta.json (identity-model 7.1, 7.3, 7.5): the record of which backend holds the KEK and
// that a KEK exists. Integrity-critical: a malformed file is refused, never rewritten silently. It
// holds no secret.
import * as fs from "node:fs";
import nodePath from "node:path";
import { writePrivateFile } from "../platform/durable";
import { ProtectionError, type FileProtection } from "../platform/file-protection";
import { KeystoreFileError } from "./fallback-file";
import { KEK_ID_RE } from "./sealed";
import type { BackendName } from "./types";

export const KEYSTORE_DIR = "keystore";
export const META_FILE = "meta.json";
export const META_VERSION = 1;

export interface KeystoreMeta {
  v: 1;
  backend: BackendName;
  kekId: string;
  /** ISO 8601. */
  createdAt: string;
  /** True only for "fallback-file". */
  fallback: boolean;
}

const BACKEND_RE = /^(linux-secret-service|macos-keychain|windows-credman|fallback-file|operator-file|cli:[a-z0-9-]{1,32})$/;
const FIELDS = "backend,createdAt,fallback,kekId,v";

export function keystoreDir(dataDir: string): string {
  return nodePath.join(dataDir, KEYSTORE_DIR);
}

export function parseMeta(text: string): KeystoreMeta {
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as Record<string, unknown>;
  } catch {
    throw new KeystoreFileError("keystore/meta.json is not valid JSON");
  }
  const ok =
    !!o &&
    typeof o === "object" &&
    !Array.isArray(o) &&
    Object.keys(o).sort().join(",") === FIELDS &&
    o.v === META_VERSION &&
    typeof o.backend === "string" &&
    BACKEND_RE.test(o.backend) &&
    typeof o.kekId === "string" &&
    KEK_ID_RE.test(o.kekId) &&
    typeof o.createdAt === "string" &&
    !Number.isNaN(Date.parse(o.createdAt)) &&
    o.fallback === (o.backend === "fallback-file");
  if (!ok) throw new KeystoreFileError("keystore/meta.json is malformed");
  return o as unknown as KeystoreMeta;
}

/** Reads meta.json after the owner-only check. Null if absent. */
export function readMeta(dataDir: string, protection: FileProtection): KeystoreMeta | null {
  const path = nodePath.join(keystoreDir(dataDir), META_FILE);
  let text: string;
  try {
    fs.lstatSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
    throw e;
  }
  const check = protection.verify(path);
  if (!check.ok) throw new ProtectionError(check.problems);
  text = fs.readFileSync(path, "utf8");
  return parseMeta(text);
}

export function writeMeta(dataDir: string, meta: KeystoreMeta, protection: FileProtection): void {
  writePrivateFile(nodePath.join(keystoreDir(dataDir), META_FILE), `${JSON.stringify(meta, null, 2)}\n`, { protection });
}
