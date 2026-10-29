// Genesis verification (identity-model.md section 5.1). Creating a genesis is I-7 (server/admin).
//   genesisHash = H("genesis", RJCS(RoomGenesis)); roomId = "room_" + hex(genesisHash[0..16])
import { z } from "zod";
import { b64u, b64uDecode } from "../proto/b64u";
import { CTX_GENESIS, H_GENESIS } from "../proto/contexts";
import { roomIdOf } from "../proto/ids";
import { verify } from "../proto/keys";
import { rjcs, rjcsParse } from "../proto/rjcs";
import { H } from "../proto/tbs";
import { b64uBytes, firstIssue, KeyRef, Kid, nonNegInt, Policy, Relay, serverId, Sig64 } from "./schema";

const GenesisBody = z.strictObject({
  v: z.literal(2),
  typ: z.literal("room-genesis"),
  createdAt: nonNegInt(),
  nonce: b64uBytes(16),
  admins: z
    .array(KeyRef("ed25519"))
    .min(1)
    .max(8)
    .refine((a) => new Set(a.map((k) => k.pub)).size === a.length, "duplicate admin key"),
  adminThreshold: z.literal(1),
  recovery: KeyRef("ed25519").nullable(),
  host: z.strictObject({ key: KeyRef("ed25519"), notBefore: nonNegInt(), notAfter: z.null() }),
  endpoint: z.strictObject({ serverId: serverId("roomEndpoint"), dh: KeyRef("x25519"), relay: Relay }),
  policy: Policy,
});
const SignedGenesis = z.strictObject({ body: GenesisBody, kid: Kid, sig: Sig64 });

export type GenesisBody = z.infer<typeof GenesisBody>;
export type RoomGenesis = z.infer<typeof SignedGenesis>;
export type VerifiedGenesis = { genesis: RoomGenesis; genesisHash: string; roomId: string };

export class GenesisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GenesisError";
  }
}

/**
 * Verify a genesis given as RJCS bytes (strict parse) or as an already strict-parsed value:
 * schema, distinct keys, signature by one of the listed admins (with the listed key, M-5).
 */
export function verifyGenesis(input: Uint8Array | unknown): VerifiedGenesis {
  const value = input instanceof Uint8Array ? rjcsParse(input) : input;
  const parsed = SignedGenesis.safeParse(value);
  if (!parsed.success) throw new GenesisError(`genesis: ${firstIssue(parsed.error)}`);
  const g = parsed.data;
  const pubs = [...g.body.admins.map((a) => a.pub), g.body.host.key.pub, ...(g.body.recovery ? [g.body.recovery.pub] : [])];
  if (new Set(pubs).size !== pubs.length) throw new GenesisError("genesis: a key is used for two roles");
  // The spec fixes no order for `admins`; duplicates are refused above.
  const signer = g.body.admins.find((a) => a.kid === g.kid);
  if (!signer) throw new GenesisError("genesis: signer is not a listed admin");
  if (!verify(b64uDecode(signer.pub, 32), CTX_GENESIS, rjcs(g.body), b64uDecode(g.sig, 64))) throw new GenesisError("genesis: bad signature");
  const hash = H(H_GENESIS, rjcs(value));
  return { genesis: value as RoomGenesis, genesisHash: b64u(hash), roomId: roomIdOf(hash) };
}
