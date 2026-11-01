// Plugin RPC contracts that are not part of the room protocol: start-up, permissions, lane agents and
// the migration from M1. The room contracts are in shared/rpc-v2.ts. The M1 contracts (rooms.overview,
// rooms.create, rooms.join, ...) were removed at the identity v2 cut-over (I-15).
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

const Empty = z.object({});
const Ok = z.object({ ok: z.literal(true) });

export const roomsBootstrap = defineRpc({
  name: "rooms.bootstrap",
  input: Empty,
  /** `protocol`: always "v2" since the cut-over (kept for diagnostics). */
  output: z.object({ ok: z.literal(true), version: z.string(), dataDir: z.literal("plugin-data/rooms"), protocol: z.literal("v2").optional() }),
});

/** Problem found by the start-time file protection check (paths are relative to plugin-data/rooms). */
export const PermissionProblemView = z.object({ path: z.string(), code: z.string(), detail: z.string() });

/**
 * Explicit "Fix permissions" action (audit X-2). The start check never repairs silently: when it
 * fails, the plugin loads no keys and every other RPC returns the permission error until this runs.
 * Symlinks and foreign owners are never fixed; they stay in `problems`.
 */
export const roomsPermissionsFix = defineRpc({
  name: "rooms.permissions.fix",
  input: Empty,
  output: z.object({ ok: z.boolean(), problems: z.array(PermissionProblemView) }),
});

/** An open lane this daemon serves, by agent (owner side). */
export const LaneAgentView = z.object({
  agentId: z.string(),
  laneId: z.string(),
  roomId: z.string(),
  roomName: z.string(),
  /** Member links open on the lane endpoint now (one per member device). */
  connectedMembers: z.number().int().min(0),
});

/** Composer pill and the "Open room…" redirect: which agents are lanes right now. */
export const roomsLaneAgents = defineRpc({
  name: "rooms.lane.agents",
  input: Empty,
  output: z.object({ lanes: z.array(LaneAgentView) }),
});

/**
 * Migration 2.4: unlinks the v1 key files (`host-key.json`, `state.json`, `device.json`) from the
 * archive of the previous version. Only on the user's explicit action; the room logs stay.
 */
export const roomsMigrationDeleteKeys = defineRpc({
  name: "rooms.migration.keys.delete",
  /**
   * `expected`: the key files the dialog listed (relative paths). When given, the call is refused if
   * the files on disk differ, so what is deleted is what was shown (cut-over review V-9).
   */
  input: z.object({ confirm: z.literal(true), expected: z.array(z.string().max(200)).max(64).optional() }),
  output: z.object({ removed: z.array(z.string()) }),
});

/** Migration 2.5: the one-time upgrade notice was read. */
export const roomsMigrationDismiss = defineRpc({
  name: "rooms.migration.dismiss",
  input: Empty,
  output: Ok,
});
