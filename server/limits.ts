// Resource limits for lane endpoints (code review C-4, protocol review P-17).
// Defaults are safe for a watch-only lane. An owner can tune them in
// <data>/limits.json (same keys, partial). Every value is clamped to [min, max] below, so a bad file
// cannot disable a limit. The file is read once when the plugin starts.
import { join } from "node:path";
import { log } from "./log";
import { readJsonFile } from "./paths";

export interface ResourceLimits {
  /** Relay data connections per lane endpoint, including pre-authentication and control channels. */
  maxConnectionsPerLane: number;
  /** Accepted host links per member (all grants of one member) on one lane. */
  maxLinksPerMember: number;
  /** Routed sessions (each with its own upstream daemon socket) per host link. */
  maxRoutesPerLink: number;
  /** Routed sessions per member across all of that member's links on the lane. */
  maxRoutesPerMember: number;
  /** Routed sessions on one lane endpoint, all links (grants-v2 section 11: 256). */
  maxRoutesPerLane: number;
  /** Largest relay frame accepted from a member daemon, in bytes (ws maxPayload). */
  maxInboundFrameBytes: number;
  /** Largest routed viewer message (the JSON string inside hosts.route.frame), in characters. */
  maxRouteMessageChars: number;
  /** Largest frame accepted from the owner's own daemon on an upstream socket, in bytes. */
  maxUpstreamFrameBytes: number;
  /** Viewer messages queued while the upstream session is not ready; overflow closes the route. */
  maxPendingUpstreamFrames: number;
  /** Outstanding forwarded requests tracked per route; the oldest is dropped on overflow. */
  maxTrackedRequestsPerRoute: number;
  /** Upstream messages waiting to be filtered per route; overflow closes the route. */
  maxQueuedOutboundPerRoute: number;
  /** Inbound frames per second per link (token bucket refill rate). */
  linkFramesPerSecond: number;
  /** Token bucket size for inbound frames per link. */
  linkFrameBurst: number;
  /** Clamp for fetch_agent_timeline_request.limit (0 means "all" upstream). */
  maxTimelineLimit: number;
}

type Bound = { min: number; max: number; default: number };

export const LIMIT_BOUNDS: Record<keyof ResourceLimits, Bound> = {
  maxConnectionsPerLane: { min: 2, max: 512, default: 32 },
  maxLinksPerMember: { min: 1, max: 16, default: 2 },
  maxRoutesPerLink: { min: 1, max: 128, default: 16 },
  maxRoutesPerMember: { min: 1, max: 256, default: 32 },
  maxRoutesPerLane: { min: 1, max: 1024, default: 256 },
  maxInboundFrameBytes: { min: 64 * 1024, max: 16 * 1024 * 1024, default: 1024 * 1024 },
  maxRouteMessageChars: { min: 16 * 1024, max: 4 * 1024 * 1024, default: 256 * 1024 },
  maxUpstreamFrameBytes: { min: 1024 * 1024, max: 100 * 1024 * 1024, default: 32 * 1024 * 1024 },
  maxPendingUpstreamFrames: { min: 8, max: 1024, default: 64 },
  maxTrackedRequestsPerRoute: { min: 16, max: 4096, default: 256 },
  maxQueuedOutboundPerRoute: { min: 64, max: 16384, default: 2048 },
  linkFramesPerSecond: { min: 1, max: 1000, default: 50 },
  linkFrameBurst: { min: 10, max: 5000, default: 200 },
  maxTimelineLimit: { min: 50, max: 10_000, default: 1000 },
};

export const DEFAULT_LIMITS: ResourceLimits = Object.fromEntries(
  Object.entries(LIMIT_BOUNDS).map(([k, b]) => [k, b.default]),
) as unknown as ResourceLimits;

/** Merges a partial override into the defaults, clamping every value. Unknown keys are ignored. */
export function resolveLimits(override: unknown): ResourceLimits {
  const out: ResourceLimits = { ...DEFAULT_LIMITS };
  if (!override || typeof override !== "object") return out;
  for (const [k, b] of Object.entries(LIMIT_BOUNDS) as Array<[keyof ResourceLimits, Bound]>) {
    const v = (override as Record<string, unknown>)[k];
    if (typeof v === "number" && Number.isFinite(v)) out[k] = Math.min(b.max, Math.max(b.min, Math.floor(v)));
  }
  return out;
}

export function loadLimits(dataDir: string): ResourceLimits {
  try {
    const raw = readJsonFile<unknown>(join(dataDir, "limits.json"));
    const limits = resolveLimits(raw);
    if (raw) log("limits_loaded", { ...limits });
    return limits;
  } catch (e) {
    log("limits_invalid", { error: (e as Error).message?.slice(0, 200) });
    return { ...DEFAULT_LIMITS };
  }
}

/** Simple token bucket. */
export class TokenBucket {
  private tokens: number;
  private at: number;
  constructor(
    private readonly ratePerSecond: number,
    private readonly burst: number,
    private readonly now = () => Date.now(),
  ) {
    this.tokens = burst;
    this.at = now();
  }

  /** True when a token is available, without taking it. */
  peek(): boolean {
    const t = this.now();
    return Math.min(this.burst, this.tokens + ((t - this.at) / 1000) * this.ratePerSecond) >= 1;
  }

  take(): boolean {
    const t = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((t - this.at) / 1000) * this.ratePerSecond);
    this.at = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}
