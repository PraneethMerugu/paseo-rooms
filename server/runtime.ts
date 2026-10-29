// Process-wide runtime for the rooms plugin subprocess: one gateway (owner role) and one member role.
// The plugin's PaseoApi is only handed to handlers and hooks in Paseo 0.13.2, so it is captured on
// first contact (any RPC, lifecycle hook, or the client entry's bootstrap call).
import { dirname } from "node:path";
import type { PaseoApi } from "@getpaseo/client";
import { Gateway } from "./gateway/gateway";
import { log } from "./log";
import { loadLimits } from "./limits";
import { MemberRole } from "./member/member";
import { dataDir, logPath, resolvePaseoHome } from "./paths";
import { defaultProtection, ProtectionError, type FileProtection, type ProtectionProblem } from "./platform/file-protection";

const IO_PERMISSION_CODES = new Set(["EPERM", "EACCES"]);

/**
 * Start-up order (audit X-2): create or check plugin-data/rooms, verify the whole tree (owner-only,
 * no symlinks), and only then construct the roles, which read the key files. On failure no key is
 * loaded, every role RPC returns the typed ProtectionError, and `fixPermissions` (RPC
 * rooms.permissions.fix) is the only way forward. An EPERM or EACCES while constructing becomes the
 * same typed error instead of a raw exception that stops the plugin from loading.
 */
export class RoomsRuntime {
  readonly paseoHome = resolvePaseoHome();
  readonly dataDir = dataDir(this.paseoHome);
  private _gateway: Gateway | null = null;
  private _member: MemberRole | null = null;
  private startRequested = false;
  /** Set when the start check failed; cleared by a successful fixPermissions. */
  startupError: ProtectionError | null = null;
  paseo: PaseoApi | null = null;

  constructor(private readonly protection: FileProtection = defaultProtection()) {
    this.init();
  }

  get ready(): boolean {
    return this._gateway !== null && this._member !== null;
  }

  get gateway(): Gateway {
    if (!this._gateway) throw this.startupError ?? new Error("Rooms is not started");
    return this._gateway;
  }

  get member(): MemberRole {
    if (!this._member) throw this.startupError ?? new Error("Rooms is not started");
    return this._member;
  }

  private init(): void {
    let gateway: Gateway | null = null;
    try {
      this.protection.ensureDir(this.dataDir);
      const check = this.protection.verifyTree(this.dataDir);
      if (!check.ok) throw new ProtectionError(check.problems);
      const relay = process.env.PASEO_ROOMS_RELAY_ENDPOINT
        ? { endpoint: process.env.PASEO_ROOMS_RELAY_ENDPOINT, useTls: process.env.PASEO_ROOMS_RELAY_TLS !== "false" }
        : undefined;
      gateway = new Gateway(this.dataDir, this.paseoHome, relay, loadLimits(this.dataDir));
      this._member = new MemberRole(this.dataDir);
      this._gateway = gateway;
      this.startupError = null;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException)?.code;
      if (e instanceof ProtectionError) this.startupError = e;
      else if (code && IO_PERMISSION_CODES.has(code)) this.startupError = new ProtectionError([{ path: ".", code: "io", detail: `access denied (${code})` }]);
      else throw e;
      gateway?.host.dispose();
      this._gateway = null;
      this._member = null;
      log("permission_check_failed", { problems: this.startupError.problems.slice(0, 10) });
    }
  }

  start(): void {
    this.startRequested = true;
    if (!this.ready) return;
    this.gateway.start();
    this.member.start();
    log("runtime_started", { home: logPath(dirname(dirname(this.paseoHome)), this.paseoHome), memberRooms: this.member.rooms.length });
  }

  /** Explicit, user-requested repair, then a fresh start check. Never called automatically. */
  fixPermissions(): { ok: boolean; problems: ProtectionProblem[] } {
    if (this.ready) return { ok: true, problems: [] };
    const r = this.protection.fix(this.dataDir);
    log("permissions_fix", { ok: r.ok, problems: r.ok ? [] : r.problems.slice(0, 10) });
    if (!r.ok) {
      this.startupError = new ProtectionError(r.problems);
      return { ok: false, problems: r.problems };
    }
    this.init();
    if (!this.ready) return { ok: false, problems: this.startupError?.problems ?? [] };
    if (this.startRequested) this.start();
    if (this.paseo) this.member.attach(this.paseo);
    return { ok: true, problems: [] };
  }

  attach(paseo: PaseoApi): PaseoApi {
    if (!this.paseo) {
      this.paseo = paseo;
      log("paseo_attached", {});
    }
    this._member?.attach(paseo);
    return paseo;
  }

  async stop(): Promise<void> {
    if (this._member) await this._member.stop();
    if (this._gateway) {
      await this._gateway.stop();
      this._gateway.host.dispose();
    }
    log("runtime_stopped", {});
  }
}
