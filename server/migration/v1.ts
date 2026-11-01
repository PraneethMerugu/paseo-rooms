// Migration from M1 (identity v1) to identity v2 on first start (docs/specs/identity-v2/migration.md
// section 2; implementation plan I-15). M1 rooms are invalidated, not migrated:
//
//   2.1 detect: `gateway/state.json` with v 1, `gateway/host-key.json`, `member/device.json` or
//       `member/rooms.json` under plugin-data/rooms;
//   2.2 owner: no v1 lane endpoint exists any more (no v1 code path); `gateway/` moves to
//       `v1-archive-<UTC date>/gateway/` by rename (same filesystem), retried with backoff on win32
//       sharing violations; if it still fails, the data stays in place and the next start retries.
//       The v1 lane agents are left alone and listed (laneId, roomId, agentId, label, origin kind)
//       for "Agents from closed rooms";
//   2.3 member: `member/rooms.json` is read first (the v1 lane ids and registrations), the v1 files
//       of `member/` move to `v1-archive-<date>/member/`, and once a PaseoApi exists every
//       registration with source `plugin:rooms` and a v1 lane id as `sourceKey` is removed
//       (`hosts.remove`, retried with backoff until it succeeds);
//   2.4 the archive keeps plaintext v1 keys until the user deletes them (`deleteArchivedKeys`, an
//       explicit action in the Rooms UI): `host-key.json`, `state.json` and `device.json` are
//       unlinked, the room logs (`events.jsonl`) and `rooms.json` stay;
//   2.5 the one-time notice is shown until dismissed.
//
// Every step is recorded in `plugin-data/rooms/migration.json` (0600). Running it again does nothing
// once the record says done. If v2 data already sits in `member/` (`rooms/`, `settings.json`: a home
// that ran the development runtime next to M1), only the v1 entries move.
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import { readJsonFile, writePrivateFile } from "../platform/durable";

export const MIGRATION_FILE = "migration.json";
export const ARCHIVE_PREFIX = "v1-archive-";
/** Files unlinked from the archive by "Delete keys" (migration 2.4). */
export const ARCHIVED_KEY_FILES: readonly string[] = ["gateway/host-key.json", "gateway/state.json", "member/device.json"];
/** Entries of `member/` that belong to identity v2 and never move. */
const V2_MEMBER_ENTRIES = new Set(["rooms", "settings.json"]);
const RENAME_RETRY_CODES = new Set(["EPERM", "EACCES", "EBUSY"]);
/** Rename backoff (win32 sharing violations): about 6 s in total, then the next start retries. */
export const RENAME_BACKOFF_MS: readonly number[] = [50, 100, 200, 400, 800, 1600, 3000];
/** hosts.remove backoff; the last value repeats until it succeeds. */
export const HOSTS_BACKOFF_MS: readonly number[] = [1000, 2000, 4000, 8000, 16000, 32000, 60000];
/** Archive directory names: v1-archive-<UTC date>, optionally -2 to -99 (archiveName). */
export const ARCHIVE_NAME = /^v1-archive-\d{4}-\d{2}-\d{2}(-\d{1,2})?$/;
/** M1 ids (16 hex) are distinct from v2 ids (32 hex). */
const V1_LANE_ID = /^lane_[a-f0-9]{16}$/;

const StepState = z.enum(["none", "pending", "archived"]);
const OwnerLane = z.object({ laneId: z.string(), roomId: z.string(), agentId: z.string(), label: z.string(), origin: z.enum(["share", "fork"]) });
export type V1OwnerLane = z.infer<typeof OwnerLane>;
const MemberLane = z.object({ laneId: z.string(), registrationId: z.string().nullable() });

export const MigrationRecord = z.object({
  v: z.literal(1),
  typ: z.literal("rooms-migration"),
  from: z.literal("m1"),
  /** First detection, ISO time. */
  detectedAt: z.string(),
  /** Archive directory name under plugin-data/rooms (no path; joined into paths, so constrained). */
  archive: z.string().regex(ARCHIVE_NAME),
  gateway: StepState,
  member: StepState,
  /** Owner side: the v1 lanes and their agents (left alone, listed in the UI). */
  ownerLanes: z.array(OwnerLane),
  /** Member side: v1 lanes whose registrations are removed (2.3 step 2). */
  memberLanes: z.array(MemberLane),
  hosts: z.enum(["none", "pending", "done"]),
  hostsRemoved: z.number().int(),
  /** Set by "Delete keys" (2.4). */
  keysDeletedAt: z.string().nullable(),
  /** Set when the user dismissed the notice of 2.5. */
  noticeDismissedAt: z.string().nullable(),
  /** Start attempts that found the archive step pending (diagnostics). */
  attempts: z.number().int(),
});
export type MigrationRecord = z.infer<typeof MigrationRecord>;

export interface MigrationDeps {
  now?: () => Date;
  platform?: NodeJS.Platform;
  renameSync?: (from: string, to: string) => void;
  sleep?: (ms: number) => Promise<void>;
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

const defaults = (d: MigrationDeps = {}) => ({
  now: d.now ?? (() => new Date()),
  platform: d.platform ?? process.platform,
  renameSync: d.renameSync ?? fs.renameSync,
  sleep: d.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms))),
  log: d.log ?? (() => undefined),
});

export const migrationPath = (dataDir: string) => nodePath.join(dataDir, MIGRATION_FILE);

export function readMigration(dataDir: string): MigrationRecord | null {
  const raw = readJsonFile<unknown>(migrationPath(dataDir));
  if (raw === null) return null;
  const parsed = MigrationRecord.safeParse(raw);
  if (!parsed.success) throw new Error("migration.json is not readable; it was not changed");
  return parsed.data;
}

function writeMigration(dataDir: string, rec: MigrationRecord): void {
  writePrivateFile(migrationPath(dataDir), JSON.stringify(MigrationRecord.parse(rec), null, 2));
}

/** Section 2.1: v1 data that has not moved yet. */
export function detectV1(dataDir: string): { gateway: boolean; member: boolean } {
  const gw = nodePath.join(dataDir, "gateway");
  const state = readJsonFile<{ v?: unknown }>(nodePath.join(gw, "state.json"));
  const gateway = state?.v === 1 || fs.existsSync(nodePath.join(gw, "host-key.json"));
  const mem = nodePath.join(dataDir, "member");
  const member = fs.existsSync(nodePath.join(mem, "device.json")) || fs.existsSync(nodePath.join(mem, "rooms.json"));
  return { gateway, member };
}

function readOwnerLanes(dataDir: string): V1OwnerLane[] {
  const state = readJsonFile<{ lanes?: unknown }>(nodePath.join(dataDir, "gateway", "state.json"));
  if (!Array.isArray(state?.lanes)) return [];
  const out: V1OwnerLane[] = [];
  for (const l of state.lanes as Array<Record<string, unknown>>) {
    if (typeof l?.id !== "string" || typeof l.agentId !== "string") continue;
    const kind = (l.origin as { kind?: unknown } | undefined)?.kind === "fork" ? "fork" : "share";
    out.push({ laneId: l.id, roomId: typeof l.roomId === "string" ? l.roomId : "", agentId: l.agentId, label: typeof l.label === "string" ? l.label.slice(0, 80) : "Lane", origin: kind });
  }
  return out.slice(0, 1000);
}

function readMemberLanes(dataDir: string): Array<{ laneId: string; registrationId: string | null }> {
  const file = readJsonFile<{ rooms?: unknown }>(nodePath.join(dataDir, "member", "rooms.json"));
  if (!Array.isArray(file?.rooms)) return [];
  const out = new Map<string, string | null>();
  for (const r of file.rooms as Array<Record<string, unknown>>) {
    if (typeof r?.laneId !== "string" || !V1_LANE_ID.test(r.laneId)) continue;
    out.set(r.laneId, typeof r.registrationId === "string" ? r.registrationId : (out.get(r.laneId) ?? null));
  }
  return [...out].slice(0, 1000).map(([laneId, registrationId]) => ({ laneId, registrationId }));
}

function utcDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

type Part = "gateway" | "member";
const PARTS: readonly Part[] = ["gateway", "member"];

/**
 * A fresh archive name: v1-archive-<UTC date>, with -2, -3, ... when that one already holds ANY of
 * the parts about to move (V-4: checking one part let a second part land on an older archive).
 */
function archiveName(dataDir: string, d: Date, parts: readonly Part[]): string {
  const base = `${ARCHIVE_PREFIX}${utcDate(d)}`;
  for (let i = 1; i < 100; i++) {
    const name = i === 1 ? base : `${base}-${i}`;
    if (!parts.some((part) => fs.existsSync(nodePath.join(dataDir, name, part)))) return name;
  }
  throw new Error("too many v1 archives");
}

/** Entries of `member/` that are not identity v2 data (left behind by a partial member move). */
function v1MemberLeftovers(dataDir: string): string[] {
  const mem = nodePath.join(dataDir, "member");
  if (!fs.existsSync(mem)) return [];
  return fs.readdirSync(mem).filter((e) => !V2_MEMBER_ENTRIES.has(e));
}

function ensureOwnerDir(path: string): void {
  fs.mkdirSync(path, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(path, 0o700);
}

/** Rename with the win32 retry rule (migration 2.2 step 2). Returns false when it still fails. */
async function renameRetrying(from: string, to: string, d: ReturnType<typeof defaults>): Promise<boolean> {
  // Never replace something already archived (V-4): POSIX rename silently overwrites a file and
  // replaces an empty directory.
  if (fs.existsSync(to)) throw new Error(`v1 archive entry already exists: ${nodePath.basename(nodePath.dirname(to))}/${nodePath.basename(to)}`);
  for (let i = 0; ; i++) {
    try {
      d.renameSync(from, to);
      return true;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException)?.code ?? "";
      const retryable = d.platform === "win32" && RENAME_RETRY_CODES.has(code);
      if (!retryable) throw e;
      if (i >= RENAME_BACKOFF_MS.length) {
        d.log("v1_archive_rename_failed", { code });
        return false;
      }
      await d.sleep(RENAME_BACKOFF_MS[i]);
    }
  }
}

/** Moves one part; `member` moves entry by entry when v2 entries share the directory. */
async function archivePart(dataDir: string, archive: string, part: Part, d: ReturnType<typeof defaults>): Promise<boolean> {
  const src = nodePath.join(dataDir, part);
  if (!fs.existsSync(src)) return true;
  const destRoot = nodePath.join(dataDir, archive);
  ensureOwnerDir(destRoot);
  const dest = nodePath.join(destRoot, part);
  const entries = fs.readdirSync(src);
  // Entry by entry when v2 data shares `member/`, or when an earlier partial run already started
  // `<archive>/member/` (V-5): the remaining entries join it.
  const shared = part === "member" && (entries.some((e) => V2_MEMBER_ENTRIES.has(e)) || fs.existsSync(dest));
  if (!shared) return renameRetrying(src, dest, d);
  ensureOwnerDir(dest);
  for (const e of entries) {
    if (V2_MEMBER_ENTRIES.has(e)) continue;
    if (!(await renameRetrying(nodePath.join(src, e), nodePath.join(dest, e), d))) return false;
  }
  return true;
}

export interface MigrationResult {
  /** The record after this run, or null when this home never held v1 data. */
  record: MigrationRecord | null;
  /** True when this run changed the file system. */
  changed: boolean;
}

/**
 * Sections 2.1 to 2.3 (file part). Idempotent: with nothing left to move it returns the record as it
 * is. Throws only on unexpected I/O errors (not on win32 sharing violations, which leave the step
 * pending for the next start).
 */
export async function migrateV1(dataDir: string, deps: MigrationDeps = {}): Promise<MigrationResult> {
  const d = defaults(deps);
  const detected = detectV1(dataDir);
  let rec = readMigration(dataDir);
  // V-5: a record left "pending" by a crash or a partial move is reconciled with the disk first.
  let reconciled = false;
  if (rec) {
    const r = reconcilePending(dataDir, rec, detected);
    reconciled = r !== rec;
    rec = r;
  }
  // A member step still pending with v1 entries left in `member/` (device.json and rooms.json already
  // moved, so detectV1 no longer sees them) is not finished.
  const found = { gateway: detected.gateway, member: detected.member || (rec?.member === "pending" && v1MemberLeftovers(dataDir).length > 0) };
  if (!found.gateway && !found.member) {
    if (rec && reconciled) writeMigration(dataDir, rec);
    return { record: rec, changed: reconciled };
  }
  const now = d.now();
  const ownerLanes = found.gateway ? readOwnerLanes(dataDir) : [];
  const memberLanes = found.member ? readMemberLanes(dataDir) : [];
  const todo = PARTS.filter((p) => found[p]);
  if (!rec || (rec.gateway !== "pending" && rec.member !== "pending")) {
    // First detection, or v1 data written again after a downgrade (migration 4): a new archive.
    rec = {
      v: 1,
      typ: "rooms-migration",
      from: "m1",
      detectedAt: now.toISOString(),
      archive: archiveName(dataDir, now, todo),
      gateway: found.gateway ? "pending" : "none",
      member: found.member ? "pending" : "none",
      ownerLanes: mergeLanes(rec?.ownerLanes ?? [], ownerLanes),
      memberLanes: mergeMember(rec?.memberLanes ?? [], memberLanes),
      hosts: memberLanes.length || rec?.hosts === "pending" ? "pending" : (rec?.hosts ?? "none"),
      hostsRemoved: rec?.hostsRemoved ?? 0,
      keysDeletedAt: null,
      noticeDismissedAt: null,
      attempts: 0,
    };
  } else {
    rec = { ...rec, ownerLanes: mergeLanes(rec.ownerLanes, ownerLanes), memberLanes: mergeMember(rec.memberLanes, memberLanes) };
    if (memberLanes.length) rec.hosts = "pending";
    // A part found again that this archive already holds (V-4) waits: once nothing is pending, the
    // next start gives it a fresh archive name.
    for (const p of todo) {
      if (rec[p] === "pending") continue;
      if (fs.existsSync(nodePath.join(dataDir, rec.archive, p))) {
        found[p] = false;
        d.log("v1_archive_deferred", { part: p, archive: rec.archive });
      } else rec[p] = "pending";
    }
  }
  rec.attempts++;
  // Record what was read BEFORE anything moves (2.3 step 1), so a crash in between loses nothing.
  writeMigration(dataDir, rec);
  // The record is written after each part (V-5), so a crash after the first rename is visible.
  for (const p of PARTS) {
    if (!found[p]) continue;
    rec[p] = (await archivePart(dataDir, rec.archive, p, d)) ? "archived" : "pending";
    writeMigration(dataDir, rec);
  }
  d.log("v1_migration", { archive: rec.archive, gateway: rec.gateway, member: rec.member, ownerLanes: rec.ownerLanes.length, memberLanes: rec.memberLanes.length });
  return { record: rec, changed: true };
}

/**
 * V-5: a part recorded "pending" whose source holds no v1 data any more. It is "archived" when
 * `<archive>/<part>` exists (the rename happened, the record write did not), otherwise "none" (the
 * data is gone). Returns the same object when nothing changes.
 */
function reconcilePending(dataDir: string, rec: MigrationRecord, detected: { gateway: boolean; member: boolean }): MigrationRecord {
  let out = rec;
  for (const p of PARTS) {
    if (rec[p] !== "pending") continue;
    const left = p === "gateway" ? detected.gateway : detected.member || v1MemberLeftovers(dataDir).length > 0;
    if (left) continue;
    out = { ...out, [p]: fs.existsSync(nodePath.join(dataDir, rec.archive, p)) ? "archived" : "none" };
  }
  return out;
}

/**
 * Agent ids of M1 fork lanes (resume tripwire, C-iso2), read synchronously from every source that may
 * list them: migration.json, a v1 `gateway/state.json` not yet archived, and the `state.json` of each
 * archive (until "Delete keys" removes it). `complete` is false when migration.json or the live v1
 * state exists but cannot be read, so the caller can fail closed.
 */
export function v1ForkAgentIds(dataDir: string): { ids: Set<string>; complete: boolean } {
  const ids = new Set<string>();
  let complete = true;
  try {
    for (const l of readMigration(dataDir)?.ownerLanes ?? []) if (l.origin === "fork") ids.add(l.agentId);
  } catch {
    complete = false;
  }
  let roots: string[];
  try {
    roots = [dataDir, ...archives(dataDir).map((a) => nodePath.join(dataDir, a))];
  } catch {
    roots = [dataDir];
    complete = false;
  }
  for (const root of roots) {
    try {
      for (const l of readOwnerLanes(root)) if (l.origin === "fork") ids.add(l.agentId);
    } catch {
      if (root === dataDir) complete = false;
    }
  }
  return { ids, complete };
}

function mergeLanes(a: V1OwnerLane[], b: V1OwnerLane[]): V1OwnerLane[] {
  const m = new Map(a.map((l) => [l.laneId, l]));
  for (const l of b) m.set(l.laneId, l);
  return [...m.values()];
}

function mergeMember(a: MigrationRecord["memberLanes"], b: MigrationRecord["memberLanes"]): MigrationRecord["memberLanes"] {
  const m = new Map(a.map((l) => [l.laneId, l]));
  for (const l of b) m.set(l.laneId, { laneId: l.laneId, registrationId: l.registrationId ?? m.get(l.laneId)?.registrationId ?? null });
  return [...m.values()];
}

/** The part of Paseo's `hosts` API the member clean-up needs. */
export interface HostsRemoveApi {
  list(): Promise<{ hosts: Array<{ registrationId: string; source?: { id?: string; key?: string } | null }> }>;
  remove(registrationId: string): Promise<unknown>;
}

/**
 * Section 2.3 step 2, one attempt: removes every registration whose source is `plugin:<pluginId>`
 * and whose sourceKey is a recorded v1 lane id. Returns the number removed; throws on failure (the
 * caller retries with HOSTS_BACKOFF_MS). Marks the record done when none is left.
 */
export async function removeV1Registrations(dataDir: string, hosts: HostsRemoveApi, pluginId = "rooms"): Promise<number> {
  const rec = readMigration(dataDir);
  if (!rec || rec.hosts !== "pending") return 0;
  const lanes = new Set(rec.memberLanes.map((l) => l.laneId));
  const dir = await hosts.list();
  const stale = dir.hosts.filter((h) => h.source?.id === `plugin:${pluginId}` && typeof h.source.key === "string" && lanes.has(h.source.key));
  for (const h of stale) await hosts.remove(h.registrationId);
  const after = readMigration(dataDir) ?? rec;
  writeMigration(dataDir, { ...after, hosts: "done", hostsRemoved: after.hostsRemoved + stale.length });
  return stale.length;
}

/**
 * Section 2.4, only on the user's explicit action: unlinks the v1 key files from every archive and
 * keeps the logs. Returns the relative paths removed.
 */
export function deleteArchivedKeys(dataDir: string, now: () => Date = () => new Date()): string[] {
  const rec = readMigration(dataDir);
  if (!rec) throw new Error("There is no archive from the previous version of Rooms");
  const root = fs.realpathSync(dataDir);
  const removed: string[] = [];
  for (const archive of archives(dataDir)) {
    for (const rel of ARCHIVED_KEY_FILES) {
      const p = nodePath.join(dataDir, archive, rel);
      try {
        const st = fs.lstatSync(p);
        if (!st.isFile()) continue;
        // V-6: no symlink anywhere between the data folder and the file (for example
        // `<archive>/gateway -> elsewhere`): its directory must resolve to exactly where it should be.
        if (fs.realpathSync(nodePath.dirname(p)) !== nodePath.join(root, archive, nodePath.dirname(rel))) {
          throw new Error(`Not deleted: ${nodePath.posix.join(archive, rel)} is reached through a symbolic link`);
        }
        fs.unlinkSync(p);
        removed.push(nodePath.posix.join(archive, rel));
      } catch (e) {
        if ((e as NodeJS.ErrnoException)?.code !== "ENOENT") throw e;
      }
    }
  }
  writeMigration(dataDir, { ...rec, keysDeletedAt: now().toISOString() });
  return removed;
}

/** Archive directories under plugin-data/rooms. */
export function archives(dataDir: string): string[] {
  if (!fs.existsSync(dataDir)) return [];
  return fs.readdirSync(dataDir).filter((n) => ARCHIVE_NAME.test(n) && fs.lstatSync(nodePath.join(dataDir, n)).isDirectory());
}

/** Relative paths of v1 key files still present in the archives. */
export function archivedKeyFiles(dataDir: string): string[] {
  const out: string[] = [];
  for (const archive of archives(dataDir)) for (const rel of ARCHIVED_KEY_FILES) if (fs.existsSync(nodePath.join(dataDir, archive, rel))) out.push(nodePath.posix.join(archive, rel));
  return out;
}

export function dismissNotice(dataDir: string, now: () => Date = () => new Date()): void {
  const rec = readMigration(dataDir);
  if (!rec) return;
  writeMigration(dataDir, { ...rec, noticeDismissedAt: rec.noticeDismissedAt ?? now().toISOString() });
}
