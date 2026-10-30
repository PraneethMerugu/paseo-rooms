// Gateway side of the rooms control protocol v1 (docs/specs/rooms-control-protocol.md).
// One operation per relay channel: hello -> challenge -> proof -> result | error.
import { ControlHello, ControlProof, type ControlErrorCode, type ControlOp } from "../../shared/control";
import { randomToken } from "../crypto";
import { ControlFailure, HostStore } from "../host/host-store";
import { log } from "../log";
import type { LaneEndpoint } from "./lane-endpoint";

export interface ControlIo {
  first: unknown;
  send(frame: unknown): void;
  next(timeoutMs: number): Promise<unknown>;
  close(why: string): void;
}

const PROOF_TIMEOUT_MS = 15_000;

export async function handleControlChannel(endpoint: LaneEndpoint, io: ControlIo): Promise<void> {
  const host = endpoint.deps.host;
  const lane = endpoint.lane;
  if (!host) throw new Error("the control channel is served only by M1 lane endpoints");
  const fail = (code: ControlErrorCode, message: string, op: ControlOp | null) => {
    log("control_error", { laneId: lane.id, op, code });
    io.send({ type: "rooms.control.error", v: 1, code, message });
    io.close(`control_error:${code}`);
  };
  const hello = ControlHello.safeParse(io.first);
  if (!hello.success) {
    const v = (io.first as any)?.v;
    return fail(v !== 1 ? "unsupported_version" : "bad_frame", "Malformed control hello", null);
  }
  const { op, laneId, devicePublicKey } = hello.data;
  if (laneId !== lane.id) return fail("unknown_lane", "Unknown lane", op);
  const nonce = randomToken(32);
  io.send({ type: "rooms.control.challenge", v: 1, nonce, laneServerId: lane.serverId, hostKeyId: host.hostKey.keyId });
  const proofRaw = await io.next(PROOF_TIMEOUT_MS);
  const proof = ControlProof.safeParse(proofRaw);
  if (!proof.success) return fail("bad_frame", "Malformed or missing proof", op);
  const p = proof.data;
  const transcript = (tokenHash: string | null) =>
    HostStore.transcript({
      op,
      laneId: lane.id,
      laneServerId: lane.serverId,
      hostKeyId: host.hostKey.keyId,
      nonce,
      devicePublicKey,
      tokenHash,
      daemonServerId: p.daemonServerId ?? null,
      label: p.label ?? null,
    });
  const room = host.room(lane.roomId)!;
  const roomInfo = { roomId: room.id, roomName: room.name, laneId: lane.id, laneLabel: lane.label };
  try {
    if (op === "enroll") {
      if (!p.token) return fail("invalid_token", "Enrollment token missing", op);
      const res = host.enroll({
        laneId: lane.id,
        token: p.token,
        devicePublicKey,
        label: p.label ?? "Member",
        daemonServerId: p.daemonServerId ?? null,
        verifySignature: (tokenHash) => host.verifyDeviceSignature(devicePublicKey, transcript(tokenHash), p.sig),
      });
      log("control_enrolled", { laneId: lane.id, memberId: res.member.id, gid: res.claims.gid, exp: new Date(res.claims.exp * 1000).toISOString() });
      io.send({
        type: "rooms.control.result",
        v: 1,
        op,
        room: roomInfo,
        member: { id: res.member.id, label: res.member.label, role: res.member.role, status: res.member.status },
        grant: res.token,
        claims: res.claims,
        activeRoutes: 0,
      });
      return io.close("control_done");
    }
    if (p.token) return fail("bad_frame", "Token is only valid for enroll", op);
    const member = host.memberForDevice(lane.id, devicePublicKey);
    if (!host.verifyDeviceSignature(devicePublicKey, transcript(null), p.sig)) return fail("bad_signature", "Device signature is not valid", op);
    const memberView = { id: member.id, label: member.label, role: member.role, status: member.status };
    if (op === "status") {
      io.send({ type: "rooms.control.result", v: 1, op, room: roomInfo, member: memberView, activeRoutes: endpoint.activeRoutes(member.id) });
      return io.close("control_done");
    }
    if (op === "renew") {
      const res = host.renew(member);
      log("control_renewed", { laneId: lane.id, memberId: member.id, gid: res.claims.gid, exp: new Date(res.claims.exp * 1000).toISOString() });
      io.send({ type: "rooms.control.result", v: 1, op, room: roomInfo, member: memberView, grant: res.token, claims: res.claims, activeRoutes: endpoint.activeRoutes(member.id) });
      return io.close("control_done");
    }
    // leave
    host.leave(member);
    log("control_left", { laneId: lane.id, memberId: member.id });
    io.send({ type: "rooms.control.result", v: 1, op, room: roomInfo, member: { ...memberView, status: "left" }, activeRoutes: 0 });
    return io.close("control_done");
  } catch (e) {
    if (e instanceof ControlFailure) return fail(e.code, e.message, op);
    log("control_internal_error", { laneId: lane.id, op, error: (e as Error).message });
    return fail("internal", "Internal error", op);
  }
}

