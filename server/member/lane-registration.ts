// Lane host registration after admission (enrollment-v2.md section 8; C-10, C-12; implementation
// plan I-9). Ported from the M1 member's `register` (server/member/member.ts).
//
// - Runs only from journal state `admitted`, which is durable before the first hosts call, so a
//   failure never leaves the member without a local record.
// - Per lane: a grant (grants-v2 section 3; I-10 supplies `grantFor`), then `hosts.update` of the
//   registration with the same `sourceKey` (found in the journal or by `hosts.list`) or `hosts.add`.
//   Idempotent: a retry never creates a second registration.
// - Each registrationId is recorded in the journal as it succeeds; when every lane is registered the
//   journal moves to `registered`.
// - Failures retry with backoff 1 s, 2 s, 4 s ... 60 s. Only `error.name` and `error.code` are logged,
//   never the connection URI or the grant.
// - Armed from the journal at plugin start; only the hosts calls wait for a PaseoApi.
import { log } from "../log";

export const REGISTRATION_BACKOFF_MS: readonly number[] = [1000, 2000, 4000, 8000, 16000, 32000, 60000];

export type HostDirectoryEntry = { registrationId: string; source?: { id?: string; key?: string } | null };

/** The part of Paseo's `hosts` API this needs. */
export interface HostsApi {
  list(): Promise<{ hosts: HostDirectoryEntry[] }>;
  add(i: { connection: string; label: string; sourceKey: string; metadata: Record<string, string> }): Promise<{ registrationId: string }>;
  update(registrationId: string, patch: { connection: string; label: string; metadata: Record<string, string>; enabled: boolean }): Promise<{ registrationId: string }>;
}

export interface LaneRegistrationDeps {
  roomId: string;
  pluginId: string;
  /** Null until the plugin has a PaseoApi. */
  hosts(): HostsApi | null;
  /** Connection URI with a fresh grant for one lane (I-10). Never logged. */
  connectionFor(laneId: string): Promise<string>;
  label(laneId: string): string;
  /** Journal: one registration recorded. */
  record(laneId: string, registrationId: string): void;
  /** Journal: every lane registered. */
  done(): void;
  setTimer?(f: () => void, ms: number): unknown;
  clearTimer?(t: unknown): void;
}

export class LaneRegistrar {
  private readonly registered: Map<string, string>;
  private attempt = 0;
  private timer: unknown = null;
  private running = false;
  private stopped = false;
  status: "running" | "retrying" | "done" | "stopped" = "running";
  lastError: string | null = null;

  constructor(
    private readonly d: LaneRegistrationDeps,
    private readonly lanes: readonly string[],
    existing: Readonly<Record<string, string>>,
  ) {
    this.registered = new Map(Object.entries(existing));
  }

  start(): void {
    void this.run();
  }

  stop(): void {
    this.stopped = true;
    this.status = "stopped";
    if (this.timer !== null) (this.d.clearTimer ?? ((t) => clearTimeout(t as ReturnType<typeof setTimeout>)))(this.timer);
    this.timer = null;
  }

  /** One pass over the lanes not yet registered; schedules a retry on failure. */
  async run(): Promise<void> {
    if (this.running || this.stopped) return;
    this.running = true;
    this.timer = null;
    try {
      for (const laneId of this.lanes) {
        if (this.registered.has(laneId)) continue;
        const hosts = this.d.hosts();
        if (!hosts) throw Object.assign(new Error("no Paseo API yet"), { code: "no_api" });
        const registrationId = await this.register(hosts, laneId);
        this.registered.set(laneId, registrationId);
        this.d.record(laneId, registrationId);
      }
      this.attempt = 0;
      this.status = "done";
      this.lastError = null;
      this.d.done();
      log("lanes_registered", { roomId: this.d.roomId, lanes: this.lanes.length });
    } catch (err) {
      const e = err as { name?: string; code?: string };
      this.lastError = String(e?.code ?? e?.name ?? "error").slice(0, 64);
      const delay = REGISTRATION_BACKOFF_MS[Math.min(this.attempt, REGISTRATION_BACKOFF_MS.length - 1)];
      this.attempt++;
      this.status = "retrying";
      log("lane_registration_retry", { roomId: this.d.roomId, error: String(e?.name ?? "Error").slice(0, 64), code: e?.code ?? null, attempt: this.attempt, delayMs: delay });
      if (!this.stopped) this.timer = (this.d.setTimer ?? ((f, ms) => setTimeout(f, ms)))(() => void this.run(), delay);
    } finally {
      this.running = false;
    }
  }

  /** hosts.update of an existing registration with this sourceKey, else hosts.add. */
  private async register(hosts: HostsApi, laneId: string): Promise<string> {
    const connection = await this.d.connectionFor(laneId);
    const label = this.d.label(laneId);
    const metadata = { "rooms.roomId": this.d.roomId, "rooms.laneId": laneId, "rooms.role": "lane" };
    let registrationId = this.registered.get(laneId) ?? null;
    if (!registrationId) {
      const dir = await hosts.list();
      registrationId = dir.hosts.find((h) => h.source?.key === laneId && h.source?.id === `plugin:${this.d.pluginId}`)?.registrationId ?? null;
    }
    if (registrationId) return (await hosts.update(registrationId, { connection, label, metadata, enabled: true })).registrationId;
    return (await hosts.add({ connection, label, sourceKey: laneId, metadata })).registrationId;
  }
}
