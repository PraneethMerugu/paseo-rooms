import type { PluginServerContext } from "@getpaseo/plugin/server";
import type { RpcInput, PluginRpcContract } from "@getpaseo/plugin";
import type { ZodType, input as ZodInput, output as ZodOutput } from "zod";
import type { PaseoApi } from "@getpaseo/client";
import { registerAgentGuard } from "./server/gateway/agent-guard";
import { log } from "./server/log";
import { RoomsRuntime } from "./server/runtime";
import { roomsProtocol, RoomsRuntimeV2 } from "./server/runtime-v2";
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
import {
  roomsV2InviteCreate,
  roomsV2InviteRevoke,
  roomsV2JoinAdmit,
  roomsV2JoinCancel,
  roomsV2JoinConfirm,
  roomsV2JoinDismiss,
  roomsV2JoinPreview,
  roomsV2JoinReject,
  roomsV2JoinStart,
  roomsV2LaneCreate,
  roomsV2LaneErrors,
  roomsV2MemberRemove,
  roomsV2MemberRole,
  roomsV2RoomConnect,
  roomsV2RoomCreate,
  roomsV2RoomDisconnect,
  roomsV2Status,
  roomsV2LinkCreate,
  roomsV2LinkConfirm,
  roomsV2DeviceVeto,
  roomsV2DeviceApprove,
  roomsV2ConflictResolve,
  roomsV2TestClockAdvance,
  roomsV2MlsSend,
  roomsV2MlsMessages,
  roomsV2DeviceRekey,
  roomsV2DeviceRemove,
  roomsV2HostKeyRotate,
  roomsV2HostKeyRevoke,
  roomsV2AdminKeyRotate,
  roomsV2AdminKeyRevoke,
  roomsV2EndpointRotate,
  roomsV2LaneRotate,
  roomsV2CloseProposed,
  roomsV2CloseConfirm,
  roomsV2RecoveryCreate,
  roomsV2RecoveryConfirm,
  roomsV2RecoveryAct,
  roomsV2AdminPrepare,
  type AdminActionKind,
  type AdminActionV2,
} from "./shared/rpc-v2";

const VERSION = "0.1.0";

export default function contribute(server: PluginServerContext) {
  // Development switch (decision D-2), read once at start. Unset: the M1 runtime, unchanged.
  if (roomsProtocol() === "v2") return contributeV2(server);
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

  handle(roomsBootstrap, () => ({ ok: true as const, version: VERSION, dataDir: "plugin-data/rooms" as const, protocol: "v1" as const }));
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

/**
 * Identity v2 development runtime (PASEO_ROOMS_PROTOCOL=v2; I-8 to I-15). Only the v2 RPCs are
 * registered; the M1 runtime, its RPCs and its hooks are not started.
 */
function contributeV2(server: PluginServerContext) {
  const rt = new RoomsRuntimeV2();
  void rt.start();
  log("protocol_v2_enabled", {});

  function handle<I extends ZodType, O extends ZodType>(contract: PluginRpcContract<I, O>, fn: (input: ZodOutput<I>) => ZodInput<O> | Promise<ZodInput<O>>): void {
    server.handle(contract, async (input, context) => {
      rt.attach(context?.paseo);
      try {
        return await fn(input);
      } catch (e) {
        log("rpc_failed", { method: contract.name, error: (e as Error).message?.slice(0, 200) });
        throw e;
      }
    });
  }

  /**
   * An interactive admin action (identity-model 5.3): the one-time token from `rooms.v2.admin.prepare`
   * is consumed for exactly this action before it runs; `stale_base` sends the UI back to its dialog.
   */
  function handleAdmin<I extends ZodType, O extends ZodType, K extends AdminActionKind>(
    contract: PluginRpcContract<I, O>,
    kind: K,
    fn: (input: ZodOutput<I>) => ZodInput<O> | Promise<ZodInput<O>>,
  ): void {
    handle(contract, async (input) => {
      const { confirmToken, ...params } = input as { confirmToken: string } & Record<string, unknown>;
      await rt.takeAdmin(confirmToken, { ...params, kind } as AdminActionV2);
      return fn(input);
    });
  }

  handle(roomsBootstrap, () => ({ ok: true as const, version: VERSION, dataDir: "plugin-data/rooms" as const, protocol: "v2" as const }));
  handle(roomsPermissionsFix, () => rt.fixPermissions());
  handle(roomsV2Status, async () => {
    await rt.start();
    return rt.status();
  });
  handle(roomsV2RoomCreate, (i) => rt.createRoom(i.recovery ?? "skip"));
  handle(roomsV2AdminPrepare, (i) => rt.prepareAdmin(i.action));
  // Owner: invites and join requests (enrollment-v2.md 2.1, 6.3).
  handleAdmin(roomsV2InviteCreate, "invite.create", ({ confirmToken: _t, ...i }) => rt.createInvite(i));
  handle(roomsV2InviteRevoke, async (i) => {
    await rt.revokeInvite(i.roomId, i.inviteId);
    return { ok: true as const };
  });
  handleAdmin(roomsV2JoinAdmit, "join.admit", (i) => rt.admitJoin(i.roomId, i.pendingId));
  handle(roomsV2JoinReject, async (i) => {
    await rt.rejectJoin(i.roomId, i.pendingId, i.reason);
    return { ok: true as const };
  });
  handleAdmin(roomsV2MemberRemove, "member.remove", (i) => rt.removeMember(i.roomId, i.memberId, i.compromise === true));
  handleAdmin(roomsV2MemberRole, "member.role", (i) => rt.changeRole(i.roomId, i.memberId, i.role));
  // Owner: lanes (grants-v2; I-10).
  handleAdmin(roomsV2LaneCreate, "lane.create", (i) => rt.createLane({ roomId: i.roomId, agentId: i.agentId, label: i.label }));
  handle(roomsV2LaneErrors, async (i) => ({ errors: await rt.laneErrors(i.roomId, i.laneId) }));
  // Member: preview, join, compare, confirm (2.3, 6.4).
  handle(roomsV2JoinPreview, (i) => rt.previewJoin(i.code));
  handle(roomsV2JoinStart, (i) => rt.startJoin(i));
  handle(roomsV2JoinConfirm, (i) => rt.confirmJoin(i.roomId, i.match));
  handle(roomsV2JoinCancel, async (i) => {
    await rt.cancelJoin(i.roomId);
    return { ok: true as const };
  });
  handle(roomsV2JoinDismiss, async (i) => {
    await rt.dismissJoin(i.roomId);
    return { ok: true as const };
  });
  handle(roomsV2RoomConnect, (i) => rt.connect(i.roomId));
  // Device links and holds (identity-model.md 6.3, 6.4; I-11).
  handle(roomsV2LinkCreate, (i) => rt.createLink(i.roomId, i.roomName));
  handle(roomsV2LinkConfirm, async (i) => {
    await rt.confirmLink(i.roomId, i.pendingId, i.match);
    return { ok: true as const };
  });
  handle(roomsV2DeviceVeto, (i) => rt.vetoDevice(i.roomId, i.ref));
  handleAdmin(roomsV2DeviceApprove, "device.approve", (i) => rt.approveDevice(i.roomId, i.ref));
  handleAdmin(roomsV2ConflictResolve, "device.conflict.resolve", (i) => rt.resolveConflict(i.roomId, i.memberId));
  handle(roomsV2MlsSend, (i) => rt.mlsSend(i.roomId, i.text));
  handle(roomsV2MlsMessages, (i) => rt.mlsMessages(i.roomId));
  // Rotation and recovery (I-12). Admin actions need the token of their confirmation dialog (I-14);
  // a member's own rekey and the recovery procedures (typed recovery code) do not.
  handle(roomsV2DeviceRekey, (i) => rt.requestRekey(i.roomId));
  handleAdmin(roomsV2DeviceRemove, "device.remove", (i) => rt.removeDevice(i.roomId, i.memberId, i.deviceId, i.compromise));
  handleAdmin(roomsV2HostKeyRotate, "host.key.rotate", (i) => rt.rotateHostKey(i.roomId));
  handleAdmin(roomsV2HostKeyRevoke, "host.key.revoke", (i) => rt.revokeHostKey(i.roomId, i.kid, i.fromSeq));
  handleAdmin(roomsV2AdminKeyRotate, "admin.key.rotate", (i) => rt.rotateAdminKey(i.roomId));
  handleAdmin(roomsV2AdminKeyRevoke, "admin.key.revoke", (i) => rt.revokeAdminKey(i.roomId, i.kid, i.fromSeq));
  handleAdmin(roomsV2EndpointRotate, "endpoint.rotate", (i) => rt.rotateEndpoint(i.roomId));
  handleAdmin(roomsV2LaneRotate, "lane.rotate", (i) => rt.rotateLane(i.roomId, i.laneId));
  handleAdmin(roomsV2CloseProposed, "room.close.propose", (i) => rt.proposeClose(i.roomId));
  handleAdmin(roomsV2CloseConfirm, "room.close.confirm", (i) => rt.confirmClose(i.roomId, i.proposal));
  handleAdmin(roomsV2RecoveryCreate, "recovery.create", (i) => rt.createRecoveryKey(i.roomId));
  handleAdmin(roomsV2RecoveryConfirm, "recovery.confirm", (i) => rt.confirmRecoveryKey(i.roomId, i.proposal));
  handle(roomsV2RecoveryAct, (i) => rt.recoveryAction(i.roomId, i.code, i.action));
  // TEST-ONLY: exists only on an e2e test home with PASEO_ROOMS_TEST_CLOCK=1 (server/platform/test-clock.ts).
  if (rt.clock.enabled) handle(roomsV2TestClockAdvance, (i) => rt.advanceTestClock(i.ms));
  handle(roomsV2RoomDisconnect, (i) => {
    rt.disconnect(i.roomId);
    return { ok: true as const };
  });

  return async () => {
    await rt.stop();
  };
}
