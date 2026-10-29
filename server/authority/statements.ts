// Statements of the room log (room-log-v2.md sections 2 and 4): the envelope, the strict `data`
// schema of every type in the catalogue, the producer kinds allowed for each type, and the
// signature check under context `stmt:<type>`. Which producer *key* is valid, and what a statement
// does, is decided by the fold (fold.ts), not here.
import { z } from "zod";
import { b64uDecode } from "../proto/b64u";
import { stmtContext } from "../proto/contexts";
import { verify } from "../proto/keys";
import { rjcs } from "../proto/rjcs";
import {
  AdmittedRosterEntry,
  DeviceEntry,
  DeviceId,
  Ed25519Pub,
  firstIssue,
  GrantId,
  Hash32,
  int,
  KeyRef,
  Kid,
  LaneId,
  LaneList,
  logPos,
  MemberId,
  nonNegInt,
  PendingId,
  POLICY_SETTINGS,
  Relay,
  Role,
  RoomId,
  ScopeId,
  serverId,
  Sig64,
  strictlySorted,
  X25519Pub,
  type PolicySetting,
} from "./schema";

export type ProducerKind = "admin" | "device" | "host" | "node" | "recovery";
const A: ProducerKind = "admin";
const D: ProducerKind = "device";
const H: ProducerKind = "host";
const N: ProducerKind = "node";
const R: ProducerKind = "recovery";

// ---- shared data parts ----

/** keys-rotation-recovery.md section 2. */
export const KeyChange = z.strictObject({
  v: z.literal(2),
  typ: z.literal("key-change"),
  roomId: RoomId,
  subject: z.strictObject({ kind: z.enum(["device", "admin", "recovery", "host", "lane", "node"]), id: z.string().min(1).max(64) }),
  old: Kid.nullable(),
  newSig: Ed25519Pub.nullable(),
  newDh: X25519Pub.nullable(),
});
export type KeyChange = z.infer<typeof KeyChange>;

const Ver = logPos();
const UnixS = nonNegInt();
const Offer = z.strictObject({ serverId: serverId("laneEndpoint"), dh: KeyRef("x25519"), relay: Relay });
// room-log-v2.md 4.2: the `.burned`, `.expired` and `.revoked` events carry `linkRef` in place of
// `inviteRef` for device links. Read here as "exactly one of the two".
const inviteOrLink = <T extends z.core.$ZodLooseShape>(extra: T) =>
  z.union([z.strictObject({ inviteRef: Hash32, ...extra }), z.strictObject({ linkRef: Hash32, ...extra })]);
const RefData = z.strictObject({ memberId: MemberId, ref: Hash32 });
const ApprovalData = z.strictObject({ memberId: MemberId, deviceId: DeviceId, ref: Hash32, mode: z.enum(["auto", "admin"]) });

const PolicyChange = z.strictObject({ setting: z.enum(Object.keys(POLICY_SETTINGS) as [PolicySetting, ...PolicySetting[]]), value: z.union([z.string(), int()]), ver: Ver });
const PolicyChanged = z
  .strictObject({ changes: z.array(PolicyChange).min(1).max(16) })
  .refine((d) => strictlySorted(d.changes, (c) => c.setting), "changes must be sorted by setting and unique")
  .refine((d) => d.changes.every((c) => POLICY_SETTINGS[c.setting].safeParse(c.value).success), "a setting has a value outside its range");

const Admitted = z
  .strictObject({
    member: AdmittedRosterEntry,
    confirmation: z.strictObject({ method: z.enum(["sas6", "creator", "sso-v1"]), inviteRef: Hash32.optional(), transcript: Hash32.optional() }),
  })
  .refine((d) => {
    const c = d.confirmation;
    if (c.method === "creator") return c.inviteRef === undefined && c.transcript === undefined;
    if (c.method === "sas6") return c.inviteRef !== undefined && c.transcript !== undefined;
    return true;
  }, "confirmation fields do not match its method");

// ---- the catalogue (room-log-v2.md section 4) ----

type Def = { producers: readonly ProducerKind[]; data: z.ZodType };

export const STATEMENT_TYPES = {
  // 4.1 authority
  "room.policy.changed": { producers: [A], data: PolicyChanged },
  "room.close.proposed": { producers: [A], data: z.strictObject({ exp: UnixS }) },
  "room.closed": { producers: [R, A], data: z.strictObject({ proposal: Hash32.nullable() }) },
  "admin.added": { producers: [A, R], data: z.strictObject({ change: KeyChange, newKeySig: Sig64 }) },
  "admin.removed": { producers: [A], data: z.strictObject({ kid: Kid }) },
  "admin.key.rotated": { producers: [A], data: z.strictObject({ change: KeyChange, newKeySig: Sig64 }) },
  "admin.key.revoked": { producers: [A, R], data: z.strictObject({ kid: Kid, fromSeq: nonNegInt() }) },
  "recovery.key.proposed": { producers: [A], data: z.strictObject({ change: KeyChange, newKeySig: Sig64, exp: UnixS }) },
  "recovery.key.rotated": { producers: [R, A], data: z.strictObject({ change: KeyChange, newKeySig: Sig64, proposal: Hash32.nullable() }) },
  "host.key.rotated": { producers: [A], data: z.strictObject({ change: KeyChange, newKeySig: Sig64, oldValidTo: UnixS }) },
  "host.key.revoked": { producers: [A], data: z.strictObject({ kid: Kid, fromSeq: nonNegInt() }) },
  "endpoint.rotated": { producers: [A], data: z.strictObject({ serverId: serverId("roomEndpoint"), dh: KeyRef("x25519"), relay: Relay, ver: Ver }) },
  "endpoint.evicted": { producers: [H], data: z.strictObject({ serverId: serverId("roomEndpoint"), count: nonNegInt(), windowS: nonNegInt() }) },
  "node.certified": { producers: [A], data: z.strictObject({ key: KeyRef("ed25519"), nodeRef: z.string().min(1).max(64) }) },
  // 4.2 invites and enrollment
  "invite.created": { producers: [A], data: z.strictObject({ inviteRef: Hash32, role: Role, lanes: LaneList, exp: UnixS }) },
  "invite.revoked": { producers: [A, D], data: inviteOrLink({}) },
  "invite.expired": { producers: [H], data: inviteOrLink({}) },
  "invite.burned": { producers: [H], data: inviteOrLink({ reason: z.enum(["attempts", "abandoned", "sas_mismatch"]) }) },
  "invite.contested": { producers: [H], data: z.strictObject({ inviteRef: Hash32, pendingId: PendingId }) },
  "enrollment.pending": { producers: [H], data: inviteOrLink({ pendingId: PendingId, deviceKid: Kid }) },
  "enrollment.closed": {
    producers: [H],
    // enrollment-v2.md section 5: the reasons of `enroll.closed`.
    data: z.strictObject({ pendingId: PendingId, reason: z.enum(["rejected", "timeout", "invite_revoked", "room_closed", "aborted", "vetoed"]) }),
  },
  "device.link.created": { producers: [D], data: z.strictObject({ memberId: MemberId, linkRef: Hash32, exp: UnixS }) },
  // 4.3 membership
  "member.admitted": { producers: [A], data: Admitted },
  "member.role.changed": { producers: [A], data: z.strictObject({ memberId: MemberId, role: Role, ver: Ver }) },
  "member.lanes.changed": { producers: [A], data: z.strictObject({ memberId: MemberId, lanes: LaneList, ver: Ver }) },
  "member.removed": { producers: [A], data: z.strictObject({ memberId: MemberId, reason: z.enum(["admin", "compromise"]) }) },
  "member.left": { producers: [D], data: z.strictObject({ memberId: MemberId }) },
  "member.device.replaced": {
    producers: [A],
    data: z.strictObject({
      memberId: MemberId,
      removed: z
        .array(DeviceId)
        .max(8)
        .refine((l) => new Set(l).size === l.length, "removed must be unique"),
      added: DeviceEntry,
      ver: Ver,
    }),
  },
  "device.added": {
    producers: [D],
    data: z.strictObject({
      memberId: MemberId,
      device: DeviceEntry,
      change: KeyChange,
      newKeySig: Sig64,
      addedBy: DeviceId,
      confirmation: z.strictObject({ method: z.literal("sas6"), linkRef: Hash32, transcript: Hash32 }),
    }),
  },
  "device.add.vetoed": { producers: [D], data: RefData },
  "device.add.approved": { producers: [A], data: ApprovalData },
  "device.removed": { producers: [A, D], data: z.strictObject({ memberId: MemberId, deviceId: DeviceId, reason: z.enum(["lost", "admin", "compromise", "self"]) }) },
  "device.rekeyed": { producers: [D], data: z.strictObject({ change: KeyChange, newKeySig: Sig64 }) },
  "device.rekey.vetoed": { producers: [D], data: RefData },
  "device.rekey.approved": { producers: [A], data: ApprovalData },
  "device.conflict.resolved": { producers: [A], data: z.strictObject({ memberId: MemberId, ver: Ver }) },
  "scope.membership.changed": {
    producers: [A],
    data: z.strictObject({
      scopeId: ScopeId,
      memberIds: z
        .array(MemberId)
        .max(4096)
        .refine((l) => strictlySorted(l, (x) => x), "memberIds must be sorted and unique"),
      ver: Ver,
    }),
  },
  "seat.added": { producers: [A, D], data: z.strictObject({ memberId: MemberId, device: DeviceEntry, agentRef: z.string().min(1).max(128) }) },
  "seat.removed": { producers: [A, D], data: z.strictObject({ deviceId: DeviceId }) },
  // 4.4 lanes and access
  "lane.created": { producers: [A], data: z.strictObject({ laneId: LaneId, owner: MemberId, offer: Offer, visibility: z.enum(["room", "team"]) }) },
  "lane.offer.rotated": { producers: [A], data: z.strictObject({ laneId: LaneId, offer: Offer, ver: Ver }) },
  "lane.names.changed": { producers: [D], data: z.strictObject({ laneId: LaneId, show: z.boolean(), ver: Ver }) },
  "lane.degraded": { producers: [H, N], data: z.strictObject({ laneId: LaneId, reason: z.enum(["agent_missing", "endpoint_failing"]) }) },
  "lane.closed": { producers: [A, H], data: z.strictObject({ laneId: LaneId }) },
  "grant.issued": { producers: [H], data: z.strictObject({ memberId: MemberId, deviceId: DeviceId, laneId: LaneId, gid: GrantId, exp: UnixS }) },
  "grant.revoked": {
    producers: [H],
    data: z.strictObject({ gid: GrantId, reason: z.enum(["superseded", "removed", "role_changed", "lane_closed", "host_key_revoked"]) }),
  },
  "grant.suspected_theft": {
    producers: [H],
    data: z.strictObject({ memberId: MemberId, deviceId: DeviceId, laneId: LaneId, gid: GrantId, reportedBy: z.enum(["endpoint", "member"]) }),
  },
  // 4.5 MLS (statement form only; mls.commit and mls.app are entries without a statement)
  "mls.stalled": { producers: [H], data: z.strictObject({ epoch: nonNegInt(), sinceMs: nonNegInt() }) },
  // 4.8 fence
  "producer.fence": { producers: [A, D], data: z.strictObject({}) },
} as const satisfies Record<string, Def>;

export type StatementType = keyof typeof STATEMENT_TYPES;
export const STATEMENT_TYPE_NAMES = Object.keys(STATEMENT_TYPES) as StatementType[];
export type StatementData<T extends StatementType> = z.infer<(typeof STATEMENT_TYPES)[T]["data"]>;

export function isStatementType(type: unknown): type is StatementType {
  return typeof type === "string" && Object.prototype.hasOwnProperty.call(STATEMENT_TYPES, type);
}

// ---- envelope (section 2) ----

const Producer = z.strictObject({ kind: z.enum(["admin", "device", "host", "node", "recovery"]), kid: Kid });
const Base = z.strictObject({ seq: logPos(), hash: Hash32 });

const StatementBodyEnvelope = z.strictObject({
  v: z.literal(2),
  typ: z.literal("stmt"),
  type: z.string(),
  roomId: RoomId,
  producer: Producer,
  base: Base,
  ts: nonNegInt(),
  data: z.unknown(),
});

export type StatementBody<T extends StatementType = StatementType> = {
  v: 2;
  typ: "stmt";
  type: T;
  roomId: string;
  producer: { kind: ProducerKind; kid: string };
  base: { seq: number; hash: string };
  ts: number;
  data: StatementData<T>;
};
export type SignedStatement = { body: StatementBody; sig: string };

export class StatementError extends Error {
  constructor(
    readonly reason: "unknown_type" | "bad_statement",
    message: string,
  ) {
    super(message);
    this.name = "StatementError";
  }
}

const SignedEnvelope = z.strictObject({ body: z.unknown(), sig: Sig64 });

/**
 * Strict schema check of a `SignedStatement` value (already strict-parsed from RJCS). An unknown
 * `type` gives `unknown_type`, so the member can say "This room uses a newer version of Rooms"
 * (signatures-and-encoding.md section 7 rule 7); everything else gives `bad_statement`.
 */
export function parseSignedStatement(value: unknown): SignedStatement {
  const outer = SignedEnvelope.safeParse(value);
  if (!outer.success) throw new StatementError("bad_statement", firstIssue(outer.error));
  const env = StatementBodyEnvelope.safeParse(outer.data.body);
  if (!env.success) throw new StatementError("bad_statement", firstIssue(env.error));
  const type = env.data.type;
  if (!isStatementType(type)) throw new StatementError("unknown_type", `unknown statement type ${JSON.stringify(type).slice(0, 80)}`);
  const def: Def = STATEMENT_TYPES[type];
  const data = def.data.safeParse(env.data.data);
  if (!data.success) throw new StatementError("bad_statement", `${type} data: ${firstIssue(data.error)}`);
  return value as SignedStatement;
}

export function producerKindAllowed(type: StatementType, kind: ProducerKind): boolean {
  return (STATEMENT_TYPES[type].producers as readonly ProducerKind[]).includes(kind);
}

/** Sign check under `stmt:<type>` over RJCS(body), with a key the verifier already holds (M-5). */
export function verifyStatementSig(stmt: SignedStatement, producerPub: Uint8Array): boolean {
  return verify(producerPub, stmtContext(stmt.body.type), rjcs(stmt.body), b64uDecode(stmt.sig, 64));
}

/** The `ref` or `proposal` a statement names, if any (room-log-v2.md section 5, ref rule). */
export function statementRef(body: StatementBody): string | null {
  const data = body.data as { ref?: unknown; proposal?: unknown };
  if (typeof data.ref === "string") return data.ref;
  if (typeof data.proposal === "string") return data.proposal;
  return null;
}
