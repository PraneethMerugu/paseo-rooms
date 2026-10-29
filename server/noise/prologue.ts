// Room endpoint Noise prologue (enrollment-v2.md section 3.3; signatures-and-encoding.md section 3.3):
//   prologue = "paseo-rooms/v2" || 0x00 || "noise-ik" || 0x00 || RJCS({ genesisHash, serverId })
// Both sides mix it into h before the first token, so a member that targets another room, another
// endpoint or another protocol version fails the handshake instead of negotiating (P-25).
// Not vendored: written for paseo-rooms.
import { b64u } from "../proto/b64u";
import { PROLOGUE_NOISE_IK, PROTOCOL_PREFIX } from "../proto/contexts";
import { isServerId } from "../proto/ids";
import { rjcs } from "../proto/rjcs";
import { createNoiseInitiator, createNoiseResponder, type NoiseHandshake, type NoiseKeyPair } from "./handshake-state";

export interface RoomEndpointBinding {
  /** 32-byte room genesis hash. */
  genesisHash: Uint8Array;
  /** Room endpoint serverId (`rme_...`). */
  serverId: string;
}

export function roomNoisePrologue(binding: RoomEndpointBinding): Uint8Array {
  if (binding.genesisHash.byteLength !== 32) throw new Error("noise prologue: genesisHash must be 32 bytes");
  if (!isServerId("roomEndpoint", binding.serverId)) throw new Error("noise prologue: bad room endpoint serverId");
  const genesisHash = b64u(binding.genesisHash);
  const encoder = new TextEncoder();
  return Buffer.concat([
    encoder.encode(PROTOCOL_PREFIX),
    Uint8Array.of(0),
    encoder.encode(PROLOGUE_NOISE_IK),
    Uint8Array.of(0),
    rjcs({ genesisHash, serverId: binding.serverId }),
  ]);
}

/** Member side: IK initiator bound to the room and endpoint it means to reach. */
export function createRoomIkInitiator(options: {
  binding: RoomEndpointBinding;
  endpointStatic: Uint8Array;
  deviceStatic: NoiseKeyPair;
  /** Test injection only. */
  ephemeral?: NoiseKeyPair;
}): NoiseHandshake {
  return createNoiseInitiator({
    pattern: "IK",
    prologue: roomNoisePrologue(options.binding),
    remoteStatic: options.endpointStatic,
    localStatic: options.deviceStatic,
    ephemeral: options.ephemeral,
  });
}

/** Endpoint side: IK responder bound to its own room and serverId. */
export function createRoomIkResponder(options: {
  binding: RoomEndpointBinding;
  endpointStatic: NoiseKeyPair;
  /** Test injection only. */
  ephemeral?: NoiseKeyPair;
}): NoiseHandshake {
  return createNoiseResponder({
    pattern: "IK",
    prologue: roomNoisePrologue(options.binding),
    localStatic: options.endpointStatic,
    ephemeral: options.ephemeral,
  });
}
