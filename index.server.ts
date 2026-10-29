import type { PluginServerContext } from "@getpaseo/plugin/server";
import type { RpcInput, PluginRpcContract } from "@getpaseo/plugin";
import type { ZodType, input as ZodInput, output as ZodOutput } from "zod";
import type { PaseoApi } from "@getpaseo/client";
import { registerAgentGuard } from "./server/gateway/agent-guard";
import { log } from "./server/log";
import { RoomsRuntime } from "./server/runtime";
import {
  roomsBootstrap,
  roomsCreate,
  roomsInviteCreate,
  roomsInviteRevoke,
  roomsJoin,
  roomsLaneAgents,
  roomsLaneClose,
  roomsLaneCreate,
  roomsLaneErrors,
  roomsLeave,
  roomsLog,
  roomsMemberRevoke,
  roomsOverview,
  roomsPermissionsFix,
  roomsRotate,
  roomsSettingsSet,
} from "./shared/rpc";

const VERSION = "0.1.0";

export default function contribute(server: PluginServerContext) {
  const rt = new RoomsRuntime();
  rt.start();

  function handle<I extends ZodType, O extends ZodType>(
    contract: PluginRpcContract<I, O>,
    fn: (input: ZodOutput<I>, paseo: PaseoApi) => ZodInput<O> | Promise<ZodInput<O>>,
  ): void {
    server.handle(contract, async (input, context) => {
      const paseo = rt.attach(context.paseo);
      try {
        return await fn(input, paseo);
      } catch (e) {
        log("rpc_failed", { method: contract.name, error: (e as Error).message?.slice(0, 200) });
        throw e;
      }
    });
  }

  handle(roomsBootstrap, () => ({ ok: true as const, version: VERSION, dataDir: "plugin-data/rooms" as const }));
  handle(roomsPermissionsFix, () => rt.fixPermissions());
  handle(roomsOverview, async (_i, paseo) => ({ owned: await rt.gateway.overview(paseo), joined: rt.member.view() }));
  handle(roomsCreate, (i: RpcInput<typeof roomsCreate>, paseo) => rt.gateway.createRoom(paseo, i));
  handle(roomsLaneCreate, async (i, paseo) => ({ lane: await rt.gateway.createLane(paseo, i) }));
  handle(roomsLaneClose, (i) => {
    rt.gateway.closeLane(i.laneId);
    return { ok: true as const };
  });
  handle(roomsInviteCreate, (i) => {
    const { invite, code } = rt.gateway.host.createInvite(i);
    log("invite_created", { inviteId: invite.id, laneId: invite.laneId, expiresAt: invite.expiresAt, grantTtlSeconds: invite.grantTtlSeconds });
    return { inviteId: invite.id, code, expiresAt: invite.expiresAt };
  });
  handle(roomsInviteRevoke, (i) => {
    rt.gateway.host.revokeInvite(i.inviteId);
    return { ok: true as const };
  });
  handle(roomsMemberRevoke, (i) => {
    const t0 = Date.now();
    const cut = rt.gateway.revokeMember(i.memberId);
    log("member_revoked", { memberId: i.memberId, ...cut, ms: Date.now() - t0 });
    return { ok: true as const, ...cut };
  });
  handle(roomsLog, (i) => {
    const events = rt.gateway.host.events(i.roomId);
    const check = rt.gateway.host.verifyLog(i.roomId);
    return { events, verified: check.ok, error: check.ok ? null : `${check.reason} at seq ${check.seq}` };
  });
  handle(roomsLaneAgents, () => ({ lanes: rt.gateway.laneAgents() }));
  handle(roomsSettingsSet, (i) => {
    const settings = rt.gateway.setShowProjectName(i.roomId, i.showProjectName);
    log("room_settings_changed", { roomId: i.roomId, showProjectName: settings.showProjectName });
    return { settings };
  });
  handle(roomsLaneErrors, (i) => ({ errors: rt.gateway.laneErrors(i.laneId) }));
  handle(roomsJoin, async (i, paseo) => {
    const rec = await rt.member.join(paseo, i.code, i.label);
    return { joined: rt.member.view().find((r) => r.laneId === rec.laneId)! };
  });
  handle(roomsLeave, async (i) => {
    await rt.member.leave(i.laneId);
    return { ok: true as const };
  });
  handle(roomsRotate, async (i) => {
    const r = await rt.member.rotate(i.laneId, { force: i.force, reason: "manual" });
    const rec = rt.member.view().find((v) => v.laneId === i.laneId);
    return { ...r, grantExpiresAt: rec?.grantExpiresAt ?? null };
  });

  // While the start check has failed (rt.ready false), room agent creates are refused (fail closed).
  const removeGuard = registerAgentGuard(server, rt.dataDir, () => rt.ready);
  // Any lifecycle hook also hands us the PaseoApi; agent.session_open fires on every agent open/resume.
  // It is also the isolation tripwire for resumes (C-iso2): a fork lane agent whose stored config
  // lost the inert shadow is refused before its provider session opens.
  const removeOpen = server.before("agent.session_open", ({ request }, context) => {
    rt.attach(context.paseo);
    // Not ready: no lane is served, so no member can reach a room agent; the tripwire has nothing to guard.
    if (request.reason !== "create" && rt.ready) rt.gateway.assertRoomAgentIntact(request.agentId);
  });
  // C-13: a lane whose agent is archived closes at once (recorded as lane.closed, reason agent_archived).
  const removeArchived = server.on("agent.archived", (event, context) => {
    rt.attach(context.paseo);
    if (!rt.ready) return;
    const closed = rt.gateway.onAgentArchived(event.agent.id);
    if (closed) log("lanes_closed_for_archived_agent", { agentId: event.agent.id, lanes: closed });
  });

  return async () => {
    removeGuard();
    removeOpen();
    removeArchived();
    await rt.stop();
  };
}
