// Process-wide runtime for the rooms plugin subprocess: one gateway (owner role) and one member role.
// The plugin's PaseoApi is only handed to handlers and hooks in Paseo 0.13.2, so it is captured on
// first contact (any RPC, lifecycle hook, or the client entry's bootstrap call).
import type { PaseoApi } from "@getpaseo/client";
import { Gateway } from "./gateway/gateway";
import { log } from "./log";
import { loadLimits } from "./limits";
import { MemberRole } from "./member/member";
import { dataDir, ensurePrivateDir, resolvePaseoHome } from "./paths";

export class RoomsRuntime {
  readonly paseoHome = resolvePaseoHome();
  readonly dataDir = dataDir(this.paseoHome);
  readonly gateway: Gateway;
  readonly member: MemberRole;
  paseo: PaseoApi | null = null;

  constructor() {
    ensurePrivateDir(this.dataDir);
    const relay = process.env.PASEO_ROOMS_RELAY_ENDPOINT
      ? { endpoint: process.env.PASEO_ROOMS_RELAY_ENDPOINT, useTls: process.env.PASEO_ROOMS_RELAY_TLS !== "false" }
      : undefined;
    this.gateway = new Gateway(this.dataDir, this.paseoHome, relay, loadLimits(this.dataDir));
    this.member = new MemberRole(this.dataDir);
  }

  start(): void {
    this.gateway.start();
    this.member.start();
    log("runtime_started", { home: this.paseoHome.split("/").slice(-2).join("/"), memberRooms: this.member.rooms.length });
  }

  attach(paseo: PaseoApi): PaseoApi {
    if (!this.paseo) {
      this.paseo = paseo;
      log("paseo_attached", {});
    }
    this.member.attach(paseo);
    return paseo;
  }

  async stop(): Promise<void> {
    await this.member.stop();
    await this.gateway.stop();
    this.gateway.host.dispose();
    log("runtime_stopped", {});
  }
}
