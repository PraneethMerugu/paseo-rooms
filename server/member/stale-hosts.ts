// Routed lane hosts the member daemon could not remove (usability roadmap R3.1, R3.7).
//
// A member registers each lane of a room as a connected host in Paseo's hosts API. When access ends
// (removed, left, room closed), a lane closes, or the member's lane access is removed, the plugin
// removes that registration with `hosts.remove`: Paseo does not prune them, and a stale entry looks
// like a broken host. Paseo 0.13.2 lets only the registering source (`plugin:rooms`) remove its own
// hosts (the app can only disable them), so the plugin is the one that has to clean up.
//
// A removal that cannot be done now (no PaseoApi yet, or the call failed) is kept in
// `member/stale-hosts.json` (ids and labels only, no connection or grant), retried, and shown to the
// member with what to do. A registration that Paseo no longer knows counts as removed.
import * as fs from "node:fs";
import nodePath from "node:path";
import { z } from "zod";
import { writePrivateFile } from "../platform/durable";
import type { FileProtection } from "../platform/file-protection";

export const STALE_HOSTS_FILE = "stale-hosts.json";
export const staleHostsPath = (dataDir: string) => nodePath.join(dataDir, "member", STALE_HOSTS_FILE);
const MAX_ENTRIES = 256;

const StaleHost = z.strictObject({
  roomId: z.string().max(64),
  laneId: z.string().max(64),
  registrationId: z.string().min(1).max(200),
  label: z.string().max(200),
  /** Why the entry had to go: access ended, lane closed, lane access removed, the member left. */
  reason: z.enum(["access_ended", "lane_closed", "lane_removed", "left", "data_deleted"]),
  since: z.number().int(),
  /** Last failure: `no_api` (Paseo not reachable from the plugin yet) or an error code. */
  lastError: z.string().max(64).nullable(),
});
export type StaleHost = z.infer<typeof StaleHost>;
const StaleFile = z.strictObject({ v: z.literal(1), hosts: z.array(StaleHost).max(MAX_ENTRIES) });

/** The part of Paseo's hosts API removal needs. */
export interface HostsRemover {
  remove(registrationId: string): Promise<unknown>;
}

export function readStaleHosts(dataDir: string): StaleHost[] {
  try {
    const p = StaleFile.safeParse(JSON.parse(fs.readFileSync(staleHostsPath(dataDir), "utf8")));
    return p.success ? p.data.hosts : [];
  } catch {
    return [];
  }
}

export function writeStaleHosts(dataDir: string, hosts: readonly StaleHost[], protection?: FileProtection): void {
  const p = staleHostsPath(dataDir);
  if (hosts.length === 0) {
    fs.rmSync(p, { force: true });
    return;
  }
  writePrivateFile(p, JSON.stringify({ v: 1, hosts: hosts.slice(-MAX_ENTRIES) }, null, 2), protection ? { protection } : undefined);
}

/** True when Paseo says the registration does not exist (already removed by someone). */
export function isUnknownHost(e: unknown): boolean {
  const code = String((e as { code?: unknown })?.code ?? "");
  const msg = String((e as Error)?.message ?? "");
  return /not_found|unknown|host_unknown/i.test(code) || /not found|unknown host|no such host/i.test(msg);
}

/**
 * Removes each registration; returns the ids removed and the entries left (with `lastError`).
 * `hosts` null: nothing is attempted (`no_api`). Never throws.
 */
export async function removeHosts(hosts: HostsRemover | null, entries: readonly StaleHost[]): Promise<{ removed: string[]; remaining: StaleHost[] }> {
  const removed: string[] = [];
  const remaining: StaleHost[] = [];
  for (const h of entries) {
    if (!hosts) {
      remaining.push({ ...h, lastError: "no_api" });
      continue;
    }
    try {
      await hosts.remove(h.registrationId);
      removed.push(h.registrationId);
    } catch (e) {
      if (isUnknownHost(e)) removed.push(h.registrationId);
      else remaining.push({ ...h, lastError: String((e as { code?: unknown })?.code ?? (e as Error)?.name ?? "error").slice(0, 64) });
    }
  }
  return { removed, remaining };
}

/** Adds entries (one per registrationId; a newer entry replaces an older one). */
export function mergeStale(cur: readonly StaleHost[], add: readonly StaleHost[]): StaleHost[] {
  const ids = new Set(add.map((h) => h.registrationId));
  return [...cur.filter((h) => !ids.has(h.registrationId)), ...add];
}
