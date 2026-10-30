// Member side of key rotation (keys-rotation-recovery.md 4.1 and 4.6; implementation plan I-12).
//
// - Device rekey (4.1 steps 1 and 2): `rekeyRequest` builds the KeyChange for this device's next keys,
//   `newKeySig` by the next signing key, and `device.rekeyed` signed by the CURRENT signing key. The
//   runtime seals the next keys in the member journal before this is signed, opens its session with
//   the old DH key until the approval is in the log, then reconnects with the new one (the host closes
//   the old session with `superseded`). The MLS member publishes `rekey` KeyPackages and rejoins by
//   Welcome at its new leaf.
// - Endpoint rotation (4.6 steps 3 to 5): `movedTarget` reads a `moved` answer of a replaced endpoint.
//   The spec's answer carries only the signed entry; the host here adds the statement body, without
//   which a device that missed the rotation cannot learn the new endpoint (reported in the plan's
//   Follow-ups). What is checked here: the entry's hash and host signature under a host key this device
//   knows (when it knows the signer), the body's hash against the entry, and that the body is a strictly
//   valid `endpoint.rotated` of this room. The new session then fetches the whole log, and the entry is
//   an anchor there: a different entry at its seq is `fork` (room-client.ts), and the fold certifies the
//   endpoint. Without a persisted verified copy (I-8 follow-up), a restarted device knows only the
//   genesis host key, so a rotated host key leaves the hsig unchecked until that fold.
import { bodyHash, verifySignedEntry, type SignedEntry } from "../authority/entries";
import type { RoomState } from "../authority/state";
import { parseSignedStatement, type KeyChange, type SignedStatement, type StatementData } from "../authority/statements";
import { log } from "../log";
import { b64uDecode } from "../proto/b64u";
import { signDeviceStatement, signNewKey } from "../proto/device-link";
import { ed25519PrivateKeyFromSeed } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import type { KeyObject } from "node:crypto";
import { edKid } from "../authority/state";

/** `device.rekeyed` (4.1 step 2) for this device's next keys, signed by its current key. */
export function rekeyRequest(i: {
  roomId: string;
  deviceId: string;
  currentSig: string;
  currentKey: KeyObject;
  next: { sigSeed: Uint8Array; sig: string; dh: string };
  base: { seq: number; hash: string };
  ts: number;
}): { statement: SignedStatement; ref: string; change: KeyChange } {
  const change: KeyChange = { v: 2, typ: "key-change", roomId: i.roomId, subject: { kind: "device", id: i.deviceId }, old: edKid(i.currentSig), newSig: i.next.sig, newDh: i.next.dh };
  const newKeySig = signNewKey(ed25519PrivateKeyFromSeed(i.next.sigSeed), change);
  const data: StatementData<"device.rekeyed"> = { change, newKeySig };
  const statement = signDeviceStatement({ type: "device.rekeyed", roomId: i.roomId, kid: edKid(i.currentSig), key: i.currentKey, base: i.base, ts: i.ts, data });
  return { statement, ref: bodyHash(rjcs(statement)), change };
}

/** Where a rekey stands in this device's verified state. */
export function rekeyStatus(st: Readonly<RoomState>, memberId: string, deviceId: string, next: { sig: string; ref: string | null }): "approved" | "pending" | "ended" | "unsent" {
  const me = st.members[memberId]?.devices.find((d) => d.deviceId === deviceId);
  if (me?.sig === next.sig) return "approved";
  if (!next.ref) return "unsent";
  const p = st.pending[next.ref];
  if (!me || (p && p.status !== "pending")) return "ended";
  return "pending";
}

export type MovedTarget = { endpoint: { serverId: string; dh: string; relay: { host: string; port: number } }; anchor: SignedEntry; hsigChecked: boolean };

/** Reads and checks a `moved` answer (keys 4.6 step 4). Null when it does not hold together. */
export function movedTarget(fields: Record<string, unknown>, roomId: string, known: Readonly<RoomState> | null): MovedTarget | null {
  try {
    if (typeof fields.body !== "string") return null;
    const bodyBytes = new Uint8Array(Buffer.from(fields.body, "utf8"));
    const stmt = parseSignedStatement(rjcsParse(bodyBytes));
    if (stmt.body.type !== "endpoint.rotated" || stmt.body.roomId !== roomId) return null;
    const e = (fields.entry as SignedEntry | undefined)?.entry;
    if (!e || e.roomId !== roomId || e.type !== "endpoint.rotated" || e.cls !== "stmt" || e.bodyHash !== bodyHash(bodyBytes)) return null;
    let hsigChecked = false;
    const keys = known?.auth.hostKeys ?? [];
    if (keys.some((k) => k.kid === e.hostKid)) {
      // Throws on a bad hash or signature.
      verifySignedEntry(fields.entry, (kid, seq) => {
        const k = keys.find((x) => x.kid === kid && !x.revoked && (x.toSeq === null || seq <= x.toSeq));
        return k ? b64uDecode(k.pub, 32) : null;
      });
      hsigChecked = true;
    } else log("room_moved_hsig_unchecked", { roomId, seq: e.seq });
    const d = stmt.body.data as StatementData<"endpoint.rotated">;
    return { endpoint: { serverId: d.serverId, dh: d.dh.pub, relay: { host: d.relay.host, port: d.relay.port } }, anchor: fields.entry as SignedEntry, hsigChecked };
  } catch {
    return null;
  }
}
