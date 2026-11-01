// Lane endpoint fixtures without a room (I-15: the M1 HostStore these tests used is gone). A
// TestAuthority issues opaque grant tokens per member and checks them like the grant service does:
// unknown or revoked tokens fail, a token for another lane is the wrong audience, an expired one
// fails. The lane's Noise key pair is a fresh X25519 pair.
import { randomBytes } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import type { EndpointLane, LaneGrantAuthority, LaneGrantCheck, LinkClaims } from "../../server/gateway/lane-endpoint";

let seq = 0;
const hex = (n: number) => randomBytes(n).toString("hex");

export function testLane(over: Partial<EndpointLane> = {}): EndpointLane {
  seq++;
  return {
    id: `lane_${hex(16)}`,
    roomId: `room_${hex(16)}`,
    label: "Live",
    origin: { kind: "share" },
    agentId: "agent-1",
    workspaceId: "wks_1",
    serverId: `rle_${hex(16)}`,
    relay: { endpoint: "relay.example:443", useTls: true },
    ...over,
  };
}

export class TestAuthority implements LaneGrantAuthority {
  private readonly secret = new Uint8Array(randomBytes(32));
  readonly publicKey = x25519.getPublicKey(this.secret);
  private readonly tokens = new Map<string, { laneId: string; claims: LinkClaims; revoked: boolean }>();

  /** A member with one grant for `laneId`, valid for `ttlS` seconds. */
  enroll(laneId: string, ttlS = 3600): { token: string; member: { id: string }; claims: LinkClaims } {
    const memberId = `mem_${hex(16)}`;
    const claims: LinkClaims = { sub: memberId, dev: hex(8), gid: `g_${hex(16)}`, exp: Math.floor(Date.now() / 1000) + ttlS };
    const token = `test.${hex(32)}`;
    this.tokens.set(token, { laneId, claims, revoked: false });
    return { token, member: { id: memberId }, claims };
  }

  revoke(token: string): void {
    const t = this.tokens.get(token);
    if (t) t.revoked = true;
  }

  check(token: string, laneId: string): LaneGrantCheck {
    const t = this.tokens.get(token);
    if (!t) return { ok: false, reason: "malformed" };
    if (t.laneId !== laneId) return { ok: false, reason: "wrong_audience", claims: t.claims };
    if (t.revoked) return { ok: false, reason: "revoked", claims: t.claims };
    if (t.claims.exp <= Math.floor(Date.now() / 1000)) return { ok: false, reason: "expired", claims: t.claims };
    return { ok: true, claims: t.claims };
  }

  keyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return { publicKey: this.publicKey, secretKey: new Uint8Array(this.secret) };
  }

  get publicKeyB64(): string {
    return Buffer.from(this.publicKey).toString("base64");
  }
}
