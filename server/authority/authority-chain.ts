// Pre-admission authority chain (enrollment-v2.md 5.2 `enroll.pending.authority` and 5.5 step 3;
// implementation plan I-9). Pure: no I/O.
//
// Before the SAS is confirmed, a requester holds at most a (possibly stolen) invite. It must not see
// the roster, invites, lanes, grants or chat history, so `enroll.pending` carries only:
//   - the signed genesis (admins, recovery key, host key, endpoint, policy), and
//   - the log entries (signed entry + statement body) that change the room's authority KEYS since
//     then: AUTHORITY_CHAIN_TYPES below. No member, device, invite, enrollment, lane, grant, MLS,
//     policy or alert entry is included.
// `authority.seq` is the seq of the last included entry (-1 if none), not the log head.
//
// Why this suffices before admission. The SAS inputs (h, Nm, Nh, deviceDh, deviceSig, endpointDh,
// genesisHash, inviteId) come from the handshake, the two nonces, the member's own keys and the
// invite; none comes from the log. The endpoint key the member connects to is the one in the invite,
// and the IK handshake proves the host holds it. Comparing the SAS by voice binds that endpoint and
// genesis to the person the owner talks to (6.1); that comparison, not the log, is what defeats a
// substituted endpoint. What the chain adds is that the endpoint the member reached and the admin key
// it shows as the owner fingerprint (6.4) are certified from the genesis: every entry is host-signed
// by a host key valid at its position (genesis key, then keys installed by `host.key.rotated` from the
// next seq on), its body matches `bodyHash`, and its statement is signed by an admin or recovery key
// the genesis or an earlier chain entry certified (new keys need a valid `newKeySig`).
//
// Limits (stated, not hidden): entries are not hash-linked to each other here, so an omitted entry
// (for example a revocation) is not detectable before admission; removals and revocations are
// verified but do not narrow the key set. The full fold of room-log-v2.md section 5 runs over the
// complete log from `log.fetch` as soon as the device is admitted, and the member checks there that
// its admission is in the folded roster.
import { b64uDecode } from "../proto/b64u";
import { kid as kidOf } from "../proto/keys";
import { rjcsParse, RJCS_MAX_BYTES } from "../proto/rjcs";
import { bodyHash, verifySignedEntry, type SignedEntry } from "./entries";
import { verifyGenesis, type RoomGenesis } from "./genesis";
import { parseSignedStatement, verifyNewKeySig, verifyStatementSig, type KeyChange, type SignedStatement, type StatementType } from "./statements";

/** Entries that change which keys speak for the room: admins, recovery, host keys, the endpoint. */
export const AUTHORITY_CHAIN_TYPES: ReadonlySet<StatementType> = new Set<StatementType>([
  "admin.added",
  "admin.removed",
  "admin.key.rotated",
  "admin.key.revoked",
  "recovery.key.rotated",
  "host.key.rotated",
  "host.key.revoked",
  "endpoint.rotated",
]);

export type AuthorityChain = { seq: number; entries: SignedEntry[]; bodies: { seq: number; body: string }[] };

export class AuthorityChainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorityChainError";
  }
}

export type AuthorityChainResult = {
  endpoint: { serverId: string; dh: { alg: string; kid: string; pub: string }; relay: { host: string; port: number; tls: true } };
  /** kids of every admin key the chain certified (genesis admins first). */
  adminKids: string[];
  /**
   * Display only (the owner fingerprint, enrollment 6.4; R3.6): admin keys after applying the chain's
   * rotations, removals and revocations in order, genesis lineage first. Not a verification result:
   * an omitted entry is not detectable here (see the header).
   */
  currentAdminKids: string[];
};

/** Host side: the chain from the stored log records. */
export function authorityChainOf(records: readonly { signed: SignedEntry; body: Uint8Array }[], encode: (b: Uint8Array) => string): AuthorityChain {
  const picked = records.filter((r) => r.signed.entry.cls === "stmt" && AUTHORITY_CHAIN_TYPES.has(r.signed.entry.type as StatementType));
  return { seq: picked.at(-1)?.signed.entry.seq ?? -1, entries: picked.map((r) => r.signed), bodies: picked.map((r) => ({ seq: r.signed.entry.seq, body: encode(r.body) })) };
}

/** Member side: verifies the chain against the genesis (see the header). Throws AuthorityChainError. */
export function verifyAuthorityChain(genesisInput: RoomGenesis | unknown, chain: { seq: number; entries: unknown[]; bodies: { seq: number; body: string }[] }, decodeBody: (b: string) => Uint8Array): AuthorityChainResult {
  const g = verifyGenesis(genesisInput);
  const roomId = g.roomId;
  const signers = new Map<string, string>(); // kid -> pub: admin and recovery keys
  for (const a of g.genesis.body.admins) signers.set(a.kid, a.pub);
  if (g.genesis.body.recovery) signers.set(g.genesis.body.recovery.kid, g.genesis.body.recovery.pub);
  const adminKids = g.genesis.body.admins.map((a) => a.kid);
  const current = [...adminKids];
  const hostKeys: { kid: string; pub: string; fromSeq: number; toSeq: number | null }[] = [{ kid: g.genesis.body.host.key.kid, pub: g.genesis.body.host.key.pub, fromSeq: 0, toSeq: null }];
  let endpoint = structuredClone(g.genesis.body.endpoint) as AuthorityChainResult["endpoint"];
  const bodies = new Map(chain.bodies.map((b) => [b.seq, b.body]));
  if (bodies.size !== chain.bodies.length || chain.bodies.length !== chain.entries.length) throw new AuthorityChainError("bodies do not match entries");
  const hostKeyAt = (kid: string, seq: number) => {
    const k = hostKeys.find((h) => h.kid === kid && h.fromSeq <= seq && (h.toSeq === null || seq <= h.toSeq));
    return k ? b64uDecode(k.pub, 32) : null;
  };
  let last = -1;
  for (const value of chain.entries) {
    let signed: SignedEntry;
    try {
      signed = verifySignedEntry(value, hostKeyAt);
    } catch {
      throw new AuthorityChainError("an entry does not verify under a host key valid at its position");
    }
    const e = signed.entry;
    if (e.roomId !== roomId || e.cls !== "stmt" || e.seq <= last) throw new AuthorityChainError("entries out of order or of another room");
    if (!AUTHORITY_CHAIN_TYPES.has(e.type as StatementType)) throw new AuthorityChainError("an entry outside the authority chain");
    last = e.seq;
    const text = bodies.get(e.seq);
    if (text === undefined) throw new AuthorityChainError("missing body");
    const body = decodeBody(text);
    if (bodyHash(body) !== e.bodyHash) throw new AuthorityChainError("body does not match bodyHash");
    let stmt: SignedStatement;
    try {
      stmt = parseSignedStatement(rjcsParse(body, RJCS_MAX_BYTES));
    } catch {
      throw new AuthorityChainError("bad statement");
    }
    const sb = stmt.body;
    if (sb.type !== e.type || sb.roomId !== roomId) throw new AuthorityChainError("statement does not match its entry");
    if (sb.producer.kind !== "admin" && sb.producer.kind !== "recovery") throw new AuthorityChainError("authority statements are signed by admin or recovery keys");
    const pub = signers.get(sb.producer.kid);
    if (!pub || !verifyStatementSig(stmt, b64uDecode(pub, 32))) throw new AuthorityChainError("statement not signed by a certified key");
    const d = sb.data as { change?: KeyChange; newKeySig?: string; serverId?: string; dh?: AuthorityChainResult["endpoint"]["dh"]; relay?: AuthorityChainResult["endpoint"]["relay"] };
    if (d.change) {
      if (!d.newKeySig || !verifyNewKeySig(d.change, d.newKeySig)) throw new AuthorityChainError("new key signature does not verify");
      const newPub = d.change.newSig!;
      const newKid = kidOf("ed25519", b64uDecode(newPub, 32));
      if (sb.type === "host.key.rotated") {
        const cur = hostKeys.find((h) => h.toSeq === null)!;
        cur.toSeq = e.seq;
        hostKeys.push({ kid: newKid, pub: newPub, fromSeq: e.seq + 1, toSeq: null });
      } else {
        signers.set(newKid, newPub);
        if (sb.type !== "recovery.key.rotated") adminKids.push(newKid);
        if (sb.type === "admin.added") current.push(newKid);
        if (sb.type === "admin.key.rotated") {
          const i = current.indexOf(d.change.old ?? "");
          if (i >= 0) current[i] = newKid;
          else current.push(newKid);
        }
      }
    }
    if (sb.type === "admin.removed" || sb.type === "admin.key.revoked") {
      const gone = (sb.data as { kid?: string }).kid;
      const i = gone ? current.indexOf(gone) : -1;
      if (i >= 0) current.splice(i, 1);
    }
    if (sb.type === "endpoint.rotated" && d.serverId && d.dh && d.relay) endpoint = { serverId: d.serverId, dh: d.dh, relay: d.relay };
  }
  if (last !== chain.seq) throw new AuthorityChainError("authority.seq does not name the last entry");
  return { endpoint, adminKids, currentAdminKids: current };
}
