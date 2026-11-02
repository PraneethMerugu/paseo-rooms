import type { PluginServerContext } from "@getpaseo/plugin/server";
import type { PluginRpcContract } from "@getpaseo/plugin";
import type { ZodType, input as ZodInput, output as ZodOutput } from "zod";
import { registerAgentGuard } from "./server/gateway/agent-guard";
import { log } from "./server/log";
import { RoomsRuntimeV2 } from "./server/runtime-v2";
import { roomsBootstrap, roomsLaneAgents, roomsMigrationDeleteKeys, roomsMigrationDismiss, roomsPermissionsFix } from "./shared/rpc";
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
  roomsV2ChatList,
  roomsV2ChatRead,
  roomsV2ChatSend,
  roomsV2ChatUnread,
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
  roomsV2LaneClose,
  roomsV2RoomLeave,
  roomsV2HostsCleanup,
  roomsV2DataDelete,
  roomsV2RoomProfileSet,
  roomsV2MemberProfileSet,
  roomsV2AlertsAck,
  type AdminActionKind,
  type AdminActionV2,
} from "./shared/rpc-v2";

const VERSION = "0.1.0";

/**
 * Rooms (identity v2). Since the cut-over (I-15) this is the only runtime; M1 data found at start is
 * archived (server/migration/v1.ts).
 */
export default function contribute(server: PluginServerContext) {
  const rt = new RoomsRuntimeV2();
  void rt.start();

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
  handle(roomsLaneAgents, async () => {
    await rt.start();
    return { lanes: rt.laneAgents() };
  });
  // Migration from M1 (migration.md 2.4 and 2.5).
  handle(roomsMigrationDeleteKeys, (i) => {
    if (i.confirm !== true) throw new Error("Confirmation required");
    return rt.deleteV1Keys(i.expected);
  });
  handle(roomsMigrationDismiss, async () => {
    await rt.dismissMigrationNotice();
    return { ok: true as const };
  });
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
  // R3.3, R3.5: names over MLS (the host never sees them) and alert acknowledgements on this device.
  handle(roomsV2RoomProfileSet, (i) => rt.setRoomProfile(i.roomId, i.name, i.description));
  handle(roomsV2MemberProfileSet, (i) => rt.setMemberProfile(i.roomId, i.displayName));
  handle(roomsV2AlertsAck, (i) => rt.ackAlerts(i.roomId, i.alerts));
  handleAdmin(roomsV2DeviceApprove, "device.approve", (i) => rt.approveDevice(i.roomId, i.ref));
  handleAdmin(roomsV2ConflictResolve, "device.conflict.resolve", (i) => rt.resolveConflict(i.roomId, i.memberId));
  // R3.4: room chat, signed by the sending device inside MLS (mls-integration 5.2). It replaced the
  // development-only unsigned `rooms.v2.mls.send` and `rooms.v2.mls.messages`, which are gone.
  handle(roomsV2ChatSend, (i) => rt.chatSend(i.roomId, i.text));
  handle(roomsV2ChatList, (i) => rt.chatList(i.roomId, i.before, i.limit));
  handle(roomsV2ChatRead, (i) => rt.chatRead(i.roomId, i.seq));
  handle(roomsV2ChatUnread, () => rt.chatUnread());
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
  // R3.2, R3.1, R3.7, R2.6: close a lane (admin token), leave a room and delete all data (typed word
  // checked by the input schema; member actions, not admin statements), retry stale lane hosts.
  handleAdmin(roomsV2LaneClose, "lane.close", (i) => rt.closeLane(i.roomId, i.laneId));
  handle(roomsV2RoomLeave, (i) => rt.leaveRoom(i.roomId));
  handle(roomsV2HostsCleanup, () => rt.cleanUpStaleHosts());
  handle(roomsV2DataDelete, (i) => rt.deleteAllData({ deleteHosted: i.deleteHosted === true }));
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

  // Room agent guard (agent.create): any agent created with the PASEO_ROOMS_LANE env gets the inert
  // MCP shadow, and room agents for unverified providers are refused. Fail closed until the runtime is ready.
  const removeGuard = registerAgentGuard(server, rt.dataDir, () => rt.state === "ready");
  // Any lifecycle hook also hands us the PaseoApi. agent.session_open is the isolation tripwire on
  // resume (C-iso2) for room agents Rooms created (M1 fork lanes kept after the migration).
  const removeOpen = server.before("agent.session_open", ({ request }, context) => {
    rt.attach(context?.paseo);
    if (request.reason !== "create") rt.assertRoomAgentIntact(request.agentId);
  });
  // C-13: a lane whose agent is archived stops serving at once and is closed (lane.closed).
  const removeArchived = server.on("agent.archived", (event, context) => {
    rt.attach(context?.paseo);
    const closed = rt.onAgentArchived(event.agent.id);
    if (closed.length) log("lanes_closed_for_archived_agent", { agentId: event.agent.id, lanes: closed.length });
  });

  return async () => {
    removeGuard();
    removeOpen();
    removeArchived();
    await rt.stop();
  };
}
