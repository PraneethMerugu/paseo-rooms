// Room creation (identity-model.md sections 5.1, 5.2.1, 5.4, 7.1; implementation plan I-7).
// Not wired into the plugin until I-8: reached only by unit tests.
//
// createRoom generates, per room: the admin key, the host key, the room endpoint key (X25519, with a
// fresh `rme_` serverId), the creator's device keys and, unless the creator skips it, the recovery key.
// It builds and signs the genesis, writes the key files sealed under the KEK, then opens the room host
// and sequences the creator's `member.admitted` (method "creator") at seq 0.
//
// Recovery key (5.4): offered by default ("create"), skippable with one choice ("skip"), and then the
// dialog shows RECOVERY_SKIP_WARNING. When the policy sets `recoveryEscrow = "org"` it cannot be
// skipped; the escrow hand-off itself is outside this spec. The seed is returned once, as a printable
// code and as the text of a file to save, and is never written by the daemon.
//
// Files (identity-model 7.1), all owner-only:
//   admin/<roomId>/admin-key.sealed        admin key            (purpose admin-key:<roomId>)
//   host/<roomId>/keys.sealed              host + endpoint key  (purpose host-keys:<roomId>)
//   host/<roomId>/genesis.json             signed genesis, RJCS (public; its hash is pinned in keys.sealed)
//   member/rooms/<roomId>/keys.sealed      creator device keys  (purpose member-keys:<roomId>)
//   host/<roomId>/log/                     the room log (room-log-store.ts)
// Nothing here logs key material, the recovery code or file contents.
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import nodePath from "node:path";
import { verifyGenesis, type GenesisBody, type RoomGenesis } from "../authority/genesis";
import { Policy, Relay, type DeviceEntry } from "../authority/schema";
import type { Kek } from "../keystore/keystore";
import { RoomHost, writeGenesisFile, writeHostKeys, type OpenRoomHostOptions } from "../host/room-host";
import { hostRoomDir } from "../host/room-log-store";
import { log } from "../log";
import { b64u } from "../proto/b64u";
import { CTX_GENESIS } from "../proto/contexts";
import { newId, newServerId } from "../proto/ids";
import { ed25519PrivateKeyFromSeed, fingerprintOfKid, kid as kidOf, rawPublicKey, x25519PrivateKeyFromSecret } from "../proto/keys";
import { rjcs } from "../proto/rjcs";
import { sign } from "../proto/tbs";
import { adminDir, AdminSigner, writeAdminKey } from "./signer";

export const RECOVERY_SKIP_WARNING =
  "Without a recovery key, a room with one admin cannot be recovered if that admin's key is lost or stolen. Members would have to start a new room.";

/** Defaults decided on 2026-10-29 (identity-model 5.2.1). */
export function defaultPolicy(): Policy {
  return {
    minVersion: 2,
    sas: "sas6",
    deviceAddApproval: "same-person",
    rotateLaneOnRemove: "compromise",
    recoveryEscrow: "none",
    soleDeviceChange: "held",
    projectNames: "lane-owner",
    grantTtl: 43200,
    closeDelay: 86400,
  };
}

// ---- recovery code ----

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
export const RECOVERY_CODE_PREFIX = "prk2";

/**
 * Printable form of the 32-byte recovery seed: "prk2-" and 52 lowercase base32 characters in groups
 * of 4 (identity-model 5.4 fixes the content, not the spelling). A typo is caught when the code is
 * used: its public key must match `genesis.recovery`.
 */
export function encodeRecoveryCode(seed: Uint8Array): string {
  if (seed.length !== 32) throw new Error("recovery seed must be 32 bytes");
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of seed) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  out += BASE32[(acc << (5 - bits)) & 31];
  return `${RECOVERY_CODE_PREFIX}-${out.match(/.{1,4}/g)!.join("-")}`;
}

/** Inverse of encodeRecoveryCode; tolerant of case, spaces and hyphens. Throws on anything else. */
export function decodeRecoveryCode(code: string): Buffer {
  const text = code.toLowerCase().replace(/[\s-]/g, "");
  if (!text.startsWith(RECOVERY_CODE_PREFIX)) throw new Error("not a recovery code");
  const body = text.slice(RECOVERY_CODE_PREFIX.length);
  if (body.length !== 52) throw new Error("recovery code has the wrong length");
  const out: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const ch of body) {
    const v = BASE32.indexOf(ch);
    if (v < 0) throw new Error("recovery code has a character outside base32");
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  if (out.length !== 32 || acc !== 0) throw new Error("recovery code is not canonical");
  return Buffer.from(out);
}

export type RecoveryKeyOffer = {
  kid: string;
  fingerprint: string;
  /** Shown once. Not stored by the daemon. */
  code: string;
  /** Text of the file the dialog offers to save (JSON). Not written by the daemon. */
  fileText: string;
  fileName: string;
};

// ---- member device keys of the creator ----

export const memberKeysPurpose = (roomId: string) => `member-keys:${roomId}`;
export const memberKeysPath = (dataDir: string, roomId: string) => nodePath.join(dataDir, "member", "rooms", roomId, "keys.sealed");

// ---- createRoom ----

export type RecoveryChoice = "create" | "skip";

export class CreateRoomError extends Error {
  constructor(
    readonly code: "bad_relay" | "bad_policy" | "recovery_required",
    message: string,
  ) {
    super(message);
    this.name = "CreateRoomError";
  }
}

export interface CreateRoomOptions {
  dataDir: string;
  kek: Kek;
  /** The relay the room endpoint uses; `tls` must be true. */
  relay: { host: string; port: number; tls: true };
  /** Settings to change from the defaults (for example from an org policy). */
  policy?: Partial<Policy>;
  /** Default "create" (identity-model 5.4). */
  recovery?: RecoveryChoice;
  /** Clock in unix ms. */
  now?: () => number;
  lock?: OpenRoomHostOptions["lock"];
  protection?: OpenRoomHostOptions["protection"];
}

export interface CreatedRoom {
  roomId: string;
  genesisHash: string;
  genesis: RoomGenesis;
  memberId: string;
  deviceId: string;
  /** The open room host (holds the log lock; call close()). */
  host: RoomHost;
  signer: AdminSigner;
  recovery: RecoveryKeyOffer | null;
  /** Set when the creator skipped the recovery key: the text the dialog shows. */
  recoverySkippedWarning: string | null;
}

type Ed = { seed: Buffer; pub: Buffer; kid: string };
function newEd25519(): Ed {
  const seed = randomBytes(32);
  const pub = rawPublicKey(ed25519PrivateKeyFromSeed(seed));
  return { seed, pub, kid: kidOf("ed25519", pub) };
}
function newX25519(): Ed {
  const seed = randomBytes(32);
  const pub = rawPublicKey(x25519PrivateKeyFromSecret(seed));
  return { seed, pub, kid: kidOf("x25519", pub) };
}

export async function createRoom(o: CreateRoomOptions): Promise<CreatedRoom> {
  const now = o.now ?? Date.now;
  const relay = Relay.safeParse(o.relay);
  if (!relay.success) throw new CreateRoomError("bad_relay", "The relay needs a host, a port and tls: true");
  const policyParsed = Policy.safeParse({ ...defaultPolicy(), ...o.policy });
  if (!policyParsed.success) throw new CreateRoomError("bad_policy", "A policy setting is outside its allowed values");
  const policy = policyParsed.data;
  const choice = o.recovery ?? "create";
  if (choice === "skip" && policy.recoveryEscrow === "org") throw new CreateRoomError("recovery_required", "The organisation's policy requires a recovery key with an escrowed copy");

  const admin = newEd25519();
  const hostKey = newEd25519();
  const endpoint = newX25519();
  const devSig = newEd25519();
  const devDh = newX25519();
  const recovery = choice === "create" ? newEd25519() : null;
  const secrets = [admin, hostKey, endpoint, devSig, devDh, ...(recovery ? [recovery] : [])];
  const createdAt = Math.floor(now() / 1000);
  const memberId = newId("member");
  const deviceId = newId("device");
  const serverId = newServerId("roomEndpoint");

  const written: string[] = [];
  let host: RoomHost | null = null;
  try {
    const body: GenesisBody = {
      v: 2,
      typ: "room-genesis",
      createdAt,
      nonce: b64u(randomBytes(16)),
      admins: [{ alg: "ed25519", kid: admin.kid, pub: b64u(admin.pub) }],
      adminThreshold: 1,
      recovery: recovery ? { alg: "ed25519", kid: recovery.kid, pub: b64u(recovery.pub) } : null,
      host: { key: { alg: "ed25519", kid: hostKey.kid, pub: b64u(hostKey.pub) }, notBefore: createdAt, notAfter: null },
      endpoint: { serverId, dh: { alg: "x25519", kid: endpoint.kid, pub: b64u(endpoint.pub) }, relay: relay.data },
      policy,
    };
    const genesis: RoomGenesis = { body, kid: admin.kid, sig: b64u(sign(ed25519PrivateKeyFromSeed(admin.seed), CTX_GENESIS, rjcs(body))) };
    const v = verifyGenesis(genesis);
    const roomId = v.roomId;

    // Key files first, genesis last: a room directory without genesis.json is an interrupted creation.
    for (const dir of [hostRoomDir(o.dataDir, roomId), adminDir(o.dataDir, roomId), nodePath.dirname(memberKeysPath(o.dataDir, roomId))]) {
      if (fs.existsSync(dir)) throw new Error("room directory already exists");
      written.push(dir);
    }
    writeHostKeys(o.dataDir, o.kek, {
      v: 2,
      typ: "host-keys",
      roomId,
      genesisHash: v.genesisHash,
      hostKeys: [{ kid: hostKey.kid, seed: b64u(hostKey.seed) }],
      endpoint: { serverId, kid: endpoint.kid, secret: b64u(endpoint.seed) },
      lanes: {},
    });
    writeAdminKey(o.dataDir, o.kek, { v: 2, typ: "admin-key", roomId, genesisHash: v.genesisHash, memberId, kid: admin.kid, seed: b64u(admin.seed) });
    const memberPlain = Buffer.from(
      rjcs({ v: 2, typ: "member-keys", roomId, genesisHash: v.genesisHash, memberId, deviceId, sig: { kid: devSig.kid, seed: b64u(devSig.seed) }, dh: { kid: devDh.kid, secret: b64u(devDh.seed) } }),
    );
    try {
      o.kek.writeSealed(memberKeysPath(o.dataDir, roomId), memberKeysPurpose(roomId), memberPlain);
    } finally {
      memberPlain.fill(0);
    }
    writeGenesisFile(o.dataDir, genesis, roomId);

    host = await RoomHost.open({ dataDir: o.dataDir, kek: o.kek, roomId, now, lock: o.lock, protection: o.protection });
    const signer = AdminSigner.load({ dataDir: o.dataDir, kek: o.kek, roomId, now });
    // The create-room dialog is the confirmation of the creator's own admission.
    const device: DeviceEntry = { deviceId, kind: "person", sig: b64u(devSig.pub), dh: b64u(devDh.pub) };
    const prepared = signer.prepare({
      type: "member.admitted",
      data: { member: { memberId, role: "admin", lanes: [], devices: [device] }, confirmation: { method: "creator" } },
      base: { seq: -1, hash: v.genesisHash },
    });
    const stmt = signer.confirm(prepared.confirmToken);
    const res = host.submit(stmt);
    if (!res.ok) throw new Error(`the creator's admission was refused (${res.reason})`);
    signer.reconcile(host);

    const offer = recovery ? recoveryOffer(recovery, roomId, v.genesisHash) : null;
    log("room_created", { roomId, recovery: recovery ? "created" : "skipped", policy: { recoveryEscrow: policy.recoveryEscrow, deviceAddApproval: policy.deviceAddApproval } });
    return {
      roomId,
      genesisHash: v.genesisHash,
      genesis,
      memberId,
      deviceId,
      host,
      signer,
      recovery: offer,
      recoverySkippedWarning: recovery ? null : RECOVERY_SKIP_WARNING,
    };
  } catch (err) {
    host?.close();
    for (const dir of written) fs.rmSync(dir, { recursive: true, force: true });
    throw err;
  } finally {
    for (const s of secrets) s.seed.fill(0);
  }
}

function recoveryOffer(r: Ed, roomId: string, genesisHash: string): RecoveryKeyOffer {
  const code = encodeRecoveryCode(r.seed);
  const fileText = `${JSON.stringify({ v: 2, typ: "recovery-key", roomId, genesisHash, kid: r.kid, code }, null, 2)}\n`;
  return { kid: r.kid, fingerprint: fingerprintOfKid(r.kid), code, fileText, fileName: `paseo-room-recovery-${roomId}.json` };
}
