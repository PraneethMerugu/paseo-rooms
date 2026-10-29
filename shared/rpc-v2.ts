// Plugin RPC contracts of the identity v2 development runtime (PASEO_ROOMS_PROTOCOL=v2, decision D-2).
// Registered only when the switch is set; they never ship. The `rooms.v2.dev.*` calls stand in for
// enrollment (I-9) so that sessions can be tested end to end: they carry public keys only.
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

const Empty = z.object({});
const Ok = z.object({ ok: z.literal(true) });
const RoomIdIn = z.object({ roomId: z.string().regex(/^room_[0-9a-f]{32}$/) });
const Head = z.object({ seq: z.number().int(), hash: z.string() });

export const OwnedRoomV2View = z.object({
  roomId: z.string(),
  serverId: z.string(),
  head: Head,
  endpoint: z.enum(["starting", "online", "offline", "closed"]),
  sessions: z.array(z.object({ memberId: z.string(), deviceId: z.string() })),
  members: z.number().int(),
});

export const JoinedRoomV2View = z.object({
  roomId: z.string(),
  memberId: z.string(),
  deviceId: z.string(),
  status: z.enum(["idle", "connecting", "open", "closed", "ended"]),
  head: Head,
  lastError: z.string().nullable(),
  endedReason: z.string().nullable(),
  alerts: z.array(z.object({ type: z.string(), seq: z.number().int() })),
});

export const roomsV2Status = defineRpc({
  name: "rooms.v2.status",
  input: Empty,
  output: z.object({
    protocol: z.literal("v2"),
    state: z.enum(["starting", "ready", "error"]),
    error: z.string().nullable(),
    keystore: z.object({ state: z.string(), backend: z.string().nullable(), fallback: z.boolean() }).nullable(),
    owned: z.array(OwnedRoomV2View),
    joined: z.array(JoinedRoomV2View),
  }),
});

export const roomsV2RoomCreate = defineRpc({
  name: "rooms.v2.room.create",
  input: Empty,
  output: z.object({ roomId: z.string(), serverId: z.string() }),
});

/** The room's signed genesis as RJCS text: public (it is in every invite). */
export const roomsV2DevDescriptor = defineRpc({
  name: "rooms.v2.dev.room.descriptor",
  input: RoomIdIn,
  output: z.object({ genesis: z.string() }),
});

/** Member daemon: new device keys for a room, sealed locally. Returns public keys only. */
export const roomsV2DevDevicePrepare = defineRpc({
  name: "rooms.v2.dev.device.prepare",
  input: z.object({ genesis: z.string().min(1).max(64 * 1024) }),
  output: z.object({ roomId: z.string(), memberId: z.string(), deviceId: z.string(), sig: z.string(), dh: z.string() }),
});

/** Owner daemon: a hand-made roster entry (member.admitted) for those public keys. Stands in for I-9. */
export const roomsV2DevMemberAdmit = defineRpc({
  name: "rooms.v2.dev.member.admit",
  input: RoomIdIn.extend({ memberId: z.string(), deviceId: z.string(), sig: z.string(), dh: z.string() }),
  output: z.object({ seq: z.number().int() }),
});

export const roomsV2DevMemberRemove = defineRpc({
  name: "rooms.v2.dev.member.remove",
  input: RoomIdIn.extend({ memberId: z.string() }),
  output: z.object({ seq: z.number().int() }),
});

/** Member daemon: open (or reopen) the room session and sync the log. */
export const roomsV2DevRoomConnect = defineRpc({
  name: "rooms.v2.dev.room.connect",
  input: RoomIdIn,
  output: z.object({ status: JoinedRoomV2View.shape.status, lastError: z.string().nullable() }),
});

export const roomsV2DevRoomDisconnect = defineRpc({
  name: "rooms.v2.dev.room.disconnect",
  input: RoomIdIn,
  output: Ok,
});
