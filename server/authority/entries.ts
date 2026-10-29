// Log entries (room-log-v2.md section 3): `LogEntry`, `SignedEntry`, the chain check of one entry
// against its predecessor, body hashes, and the equivocation proof.
//   entryHash  = H("log-entry", RJCS(LogEntry))
//   SignedEntry = { entry, hash: b64u(entryHash), hsig: b64u(Sign(hostKey, "log-entry", RJCS(LogEntry))) }
//   bodyHash   = H("log-body", bodyBytes)
// Which host key is valid at a position is decided by the fold; this module takes a lookup.
import { z } from "zod";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_LOG_ENTRY, H_LOG_BODY, H_LOG_ENTRY } from "../proto/contexts";
import { verify } from "../proto/keys";
import { rjcs } from "../proto/rjcs";
import { H } from "../proto/tbs";
import { firstIssue, Hash32, Kid, nonNegInt, RoomId, Sig64 } from "./schema";

export const LogEntry = z.strictObject({
  v: z.literal(2),
  typ: z.literal("log-entry"),
  roomId: RoomId,
  seq: nonNegInt(),
  prev: Hash32,
  hts: nonNegInt(),
  epoch: nonNegInt().nullable(),
  cls: z.enum(["stmt", "mls"]),
  type: z.string().min(1).max(64),
  bodyHash: Hash32,
  hostKid: Kid,
});
export type LogEntry = z.infer<typeof LogEntry>;
export const SignedEntry = z.strictObject({ entry: LogEntry, hash: Hash32, hsig: Sig64 });
export type SignedEntry = z.infer<typeof SignedEntry>;

export const MLS_ENTRY_TYPES = ["mls.commit", "mls.app"] as const;

export type EntryReason = "bad_entry" | "wrong_room" | "seq_gap" | "prev_mismatch" | "hash_mismatch" | "unknown_host_key" | "bad_hsig" | "cls_mismatch";

export class EntryError extends Error {
  constructor(
    readonly reason: EntryReason,
    message: string,
  ) {
    super(message);
    this.name = "EntryError";
  }
}

export function entryHash(entry: LogEntry): string {
  return b64u(H(H_LOG_ENTRY, rjcs(entry)));
}

export function bodyHash(bodyBytes: Uint8Array): string {
  return b64u(H(H_LOG_BODY, bodyBytes));
}

/** Host key lookup: the raw public key of `hostKid` if that key may sign the entry at `seq`, else null. */
export type HostKeyAt = (hostKid: string, seq: number) => Uint8Array | null;

/** Schema, `hash` and `hsig` of one signed entry, without its place in a chain. */
export function verifySignedEntry(value: unknown, hostKeyAt: HostKeyAt): SignedEntry {
  const parsed = SignedEntry.safeParse(value);
  if (!parsed.success) throw new EntryError("bad_entry", firstIssue(parsed.error));
  const signed = value as SignedEntry;
  const e = signed.entry;
  const isMls = (MLS_ENTRY_TYPES as readonly string[]).includes(e.type);
  if (isMls !== (e.cls === "mls")) throw new EntryError("cls_mismatch", `cls ${e.cls} with type ${e.type}`);
  if (entryHash(e) !== signed.hash) throw new EntryError("hash_mismatch", `entry ${e.seq}: hash does not match`);
  const pub = hostKeyAt(e.hostKid, e.seq);
  if (!pub) throw new EntryError("unknown_host_key", `entry ${e.seq}: host key not valid at this position`);
  if (!verify(pub, CTX_LOG_ENTRY, rjcs(e), b64uDecode(signed.hsig, 64))) throw new EntryError("bad_hsig", `entry ${e.seq}: bad host signature`);
  return signed;
}

/**
 * Chain check of the entry that follows `prevHash` (the genesisHash for seq 0): room, seq, prev
 * link, hash and host signature.
 */
export function verifyChainedEntry(value: unknown, expect: { roomId: string; seq: number; prevHash: string }, hostKeyAt: HostKeyAt): SignedEntry {
  const signed = verifySignedEntry(value, hostKeyAt);
  const e = signed.entry;
  if (e.roomId !== expect.roomId) throw new EntryError("wrong_room", `entry ${e.seq}: roomId differs`);
  if (e.seq !== expect.seq) throw new EntryError("seq_gap", `expected seq ${expect.seq}, got ${e.seq}`);
  if (e.prev !== expect.prevHash) throw new EntryError("prev_mismatch", `entry ${e.seq}: prev does not link to the chain`);
  return signed;
}

/**
 * Equivocation proof (section 3): two signed entries with the same roomId and seq, different
 * hashes, each with a correct hash and a valid hsig under a host key valid at that position.
 * Anyone can check it without trusting the reporter.
 */
export function isEquivocationProof(a: unknown, b: unknown, hostKeyAt: HostKeyAt): boolean {
  try {
    const x = verifySignedEntry(a, hostKeyAt);
    const y = verifySignedEntry(b, hostKeyAt);
    return x.entry.roomId === y.entry.roomId && x.entry.seq === y.entry.seq && x.hash !== y.hash;
  } catch {
    return false;
  }
}
