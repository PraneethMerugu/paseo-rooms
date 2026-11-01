// Interactive admin confirmations (identity-model.md 5.3; room-log-v2.md 2 "After stale_base", R-9).
//
// `rooms.v2.admin.prepare` describes an interactive admin action from the current room state and
// returns a one-time token bound to (a) the exact action and (b) a `subject`: the current values the
// action depends on (a member's role and its field version, a pending request's status, the current
// host key, ...). The action RPC hands the token back; `take` recomputes the description and refuses
// with `stale_base` when the subject changed, so the dialog is shown again with the new value instead
// of signing over a concurrent change. Tokens live 5 minutes, are used once (also when refused), and
// are kept in memory only.
//
// This is a usability guard, not a security boundary (S-12): any same-user caller can call prepare.
import { randomBytes } from "node:crypto";
import { activeAdmins, versionKey, type RoomState } from "../authority/state";
import { lineageCount } from "../authority/lineage";
import type { AdminActionV2 } from "../../shared/rpc-v2";
import { INVITE_EXP_DEFAULT_S } from "../host/invites";

export const CONFIRM_TTL_MS = 5 * 60_000;
const MAX_TOKENS = 256;

export type AdminDescription = {
  title: string;
  details: string[];
  current: string | null;
  warning: string | null;
  typeToConfirm: string | null;
};
export type Described = AdminDescription & { subject: string };

export class ConfirmationError extends Error {
  constructor(
    readonly code: "bad_token" | "stale_base",
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ConfirmationError";
  }
}

/** The action with defaults filled in and set-valued fields sorted, as a canonical string. */
export function actionKey(a: AdminActionV2): string {
  const n: Record<string, unknown> = { ...a };
  if (a.kind === "member.remove") n.compromise = a.compromise === true;
  if (a.kind === "invite.create" && a.lanes) n.lanes = [...new Set(a.lanes)].sort();
  const keys = Object.keys(n)
    .filter((k) => n[k] !== undefined)
    .sort();
  return JSON.stringify(keys.map((k) => [k, n[k]]));
}

export class ConfirmationBook {
  readonly #tokens = new Map<string, { key: string; subject: string; exp: number }>();
  constructor(private readonly now: () => number = Date.now) {}

  prepare(action: AdminActionV2, d: Described): { confirmToken: string; expiresAt: number } {
    this.sweep();
    while (this.#tokens.size >= MAX_TOKENS) this.#tokens.delete(this.#tokens.keys().next().value!);
    const confirmToken = randomBytes(32).toString("base64url");
    const exp = this.now() + CONFIRM_TTL_MS;
    this.#tokens.set(confirmToken, { key: actionKey(action), subject: d.subject, exp });
    return { confirmToken, expiresAt: exp };
  }

  /** Consumes the token. Throws `bad_token` (unknown, used, expired or for another action) or `stale_base`. */
  take(confirmToken: string, action: AdminActionV2, now: () => Described): void {
    const t = this.#tokens.get(confirmToken);
    this.#tokens.delete(confirmToken);
    if (!t || t.exp < this.now()) throw new ConfirmationError("bad_token", "The confirmation expired or was already used. Open the dialog again.");
    if (t.key !== actionKey(action)) throw new ConfirmationError("bad_token", "The confirmation was for a different action.");
    const d = now();
    if (d.subject !== t.subject) throw new ConfirmationError("stale_base", d.current ? `This changed since you confirmed. ${d.current}` : "This changed since you confirmed.");
  }

  get size(): number {
    return this.#tokens.size;
  }

  private sweep(): void {
    const now = this.now();
    for (const [k, t] of this.#tokens) if (t.exp < now) this.#tokens.delete(k);
  }
}

// ------------------------------------------------------------------------------ descriptions

export type JoinRequestInfo = { pendingId: string; kind: "invite" | "link"; note: string; label: string; state: string; sas: string | null; contested: boolean; abandonedBefore: number; expiresAt: number };
export type LaneInfo = { laneId: string; label: string | null; status: string; agentId: string | null };

export interface DescribeContext {
  state: Readonly<RoomState>;
  /** Self-reported label of a member, if this daemon knows it. */
  label(memberId: string): string | null;
  lanes: LaneInfo[];
  joinRequest(pendingId: string): JoinRequestInfo | null;
  /** This daemon's admin key id, if it holds one. */
  ownAdminKid: string | null;
  ownMemberId: string | null;
}

/** First 8 characters after a type prefix (`mem_`, `dev_`, `lane_`, ...); key ids (base64url) have none. */
const short = (id: string) => id.replace(/^[a-z]{2,5}_(?=[0-9a-f]{32}$)/, "").slice(0, 8);
const fmtSas = (s: string) => (/^\d{6}$/.test(s) ? `${s.slice(0, 3)} ${s.slice(3)}` : s);
const fmtTime = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 16) + " UTC";

function who(ctx: DescribeContext, memberId: string): string {
  const l = ctx.label(memberId);
  return l ? `${l} (${short(memberId)})` : `member ${short(memberId)}`;
}

function laneName(ctx: DescribeContext, laneId: string): string {
  const l = ctx.lanes.find((x) => x.laneId === laneId);
  return l?.label ? `"${l.label}" (${short(laneId)})` : `lane ${short(laneId)}`;
}

function fail(message: string): never {
  throw new Error(message);
}

/**
 * The dialog text for an action and the subject its token is bound to. Throws when the action cannot
 * apply to the current state (unknown member, request no longer pending, ...).
 */
export function describeAdminAction(ctx: DescribeContext, a: AdminActionV2): Described {
  const st = ctx.state;
  const auth = st.auth;
  const base = { current: null, warning: null, typeToConfirm: null } as const;
  switch (a.kind) {
    case "invite.create": {
      const lanes = a.lanes ? [...new Set(a.lanes)].sort() : [];
      for (const l of lanes) if (auth.lanes[l]?.status !== "open") fail(`Lane ${short(l)} is not open`);
      return {
        ...base,
        title: "Create an invite",
        details: [
          ...(a.roomName ? [`Room name: ${a.roomName}`] : []),
          `Role: ${a.role ?? "watch"}`,
          lanes.length ? `Lanes: ${lanes.map((l) => laneName(ctx, l)).join(", ")}` : "Lanes: none",
          `Valid for ${Math.round((a.expS ?? INVITE_EXP_DEFAULT_S) / 60)} minutes, once.`,
          ...(a.note ? [`Your note: ${a.note}`] : []),
        ],
        warning: "The code is a secret until it is used. Send it privately; anyone with it can ask to join.",
        subject: JSON.stringify([auth.closed, lanes.map((l) => auth.lanes[l]?.status)]),
      };
    }
    case "join.admit": {
      const p = ctx.joinRequest(a.pendingId) ?? fail("Unknown join request");
      if (p.kind === "link") fail("Device links are approved by the member's own device, not admitted here");
      if (!p.sas) fail("The person has not revealed their code yet");
      return {
        ...base,
        title: `Admit "${p.label}"`,
        details: [`Invite note: ${p.note || "(none)"}`, `They call themselves: ${p.label} (self-reported).`, `Code: ${fmtSas(p.sas)}`],
        current: `Request state: ${p.state}`,
        warning: p.contested ? "Another device also tried to use this invite. It may have been copied. Compare the code carefully." : "Admit only if the person read you the same six digits by voice or in person.",
        subject: JSON.stringify([p.state, p.sas, p.contested]),
      };
    }
    case "member.remove": {
      const m = st.members[a.memberId] ?? fail("That member is not in the roster");
      if (a.memberId === ctx.ownMemberId) fail("You cannot remove yourself here");
      const pendingAdds = Object.values(st.pending).filter((p) => p.memberId === a.memberId && p.status === "pending");
      return {
        ...base,
        title: `Remove ${who(ctx, a.memberId)}`,
        details: [
          "Their sessions and lane links are cut now, and the removal is recorded in the room log.",
          a.compromise ? `Marked as misuse: the lanes they could use are rotated (${m.lanes.length || "all"} lane(s)).` : "Not marked as misuse: lanes are rotated only if the room policy says always.",
          ...(pendingAdds.length ? [`This also cancels ${pendingAdds.length} pending device request(s) of this member.`] : []),
        ],
        current: `Current role: ${m.role}, ${m.devices.length} device(s).`,
        typeToConfirm: "remove",
        subject: JSON.stringify([m.role, m.devices.map((d) => d.deviceId), auth.versions[versionKey.role(a.memberId)] ?? -1]),
      };
    }
    case "member.role": {
      const m = st.members[a.memberId] ?? fail("That member is not in the roster");
      if (m.role === a.role) fail(`The role is already ${a.role}`);
      return {
        ...base,
        title: `Change ${who(ctx, a.memberId)}'s role to ${a.role}`,
        details: ["Grants issued at the old role stop working at once.", "The change is recorded in the room log and every member sees it."],
        current: `Current role: ${m.role}.`,
        subject: JSON.stringify([m.role, auth.versions[versionKey.role(a.memberId)] ?? -1]),
      };
    }
    case "lane.create": {
      if (auth.closed) fail("The room is closed");
      return {
        ...base,
        title: `Share an agent as lane "${a.label ?? "Live"}"`,
        details: [`Agent ${short(a.agentId)} of this daemon. Members with this lane in their invite see it read-only.`, "The lane is recorded in the room log."],
        subject: JSON.stringify([auth.closed]),
      };
    }
    case "device.remove": {
      const m = st.members[a.memberId] ?? fail("That member is not in the roster");
      if (!m.devices.some((d) => d.deviceId === a.deviceId)) fail("That device is not active");
      const sole = m.devices.length === 1;
      const adding = Object.values(st.pending).filter((p) => p.requester === a.deviceId && p.kind === "add" && p.status === "pending");
      const ends = adding.map((p) => p.hts + (p.sole ? 72 : 24) * 3600_000);
      return {
        ...base,
        title: `Remove device ${short(a.deviceId)} of ${who(ctx, a.memberId)}`,
        details: [
          "The device's sessions and grants end now; the member's other devices stay.",
          a.compromise ? "Marked as compromised: the lanes this member could use are rotated." : "Not marked as compromised.",
          ...(adding.length ? [`Removing this device also cancels the device it is adding (joins at ${fmtTime(Math.min(...ends))}).`] : []),
        ],
        current: `${m.devices.length} active device(s).`,
        warning: sole ? "This is the member's only device: they keep their membership but cannot reach the room until an admin lets them back in." : null,
        typeToConfirm: "remove",
        subject: JSON.stringify([m.devices.map((d) => d.deviceId), adding.map((p) => p.seq)]),
      };
    }
    case "device.approve": {
      const p = st.pending[a.ref] ?? fail("Unknown device request");
      if (p.status !== "pending") fail(`The device request is ${p.status}`);
      return {
        ...base,
        title: p.kind === "add" ? `Approve a new device for ${who(ctx, p.memberId)}` : `Approve new keys for device ${short(p.deviceId)} of ${who(ctx, p.memberId)}`,
        details: [`Requested by device ${short(p.requester)} at ${fmtTime(p.hts)}.`, "Approving now skips the rest of the hold."],
        current: `Request status: ${p.status}.`,
        warning: p.sole
          ? `${who(ctx, p.memberId)} has only one device in this room, and it is ${p.kind === "add" ? "adding another" : "changing its keys"}. If they did not ask for this, remove the device instead.`
          : p.young
            ? "The requesting device joined less than 24 hours ago."
            : null,
        subject: JSON.stringify([p.status, p.seq]),
      };
    }
    case "device.conflict.resolve": {
      const c = st.conflicts[a.memberId];
      if (c === undefined) fail("That member has no open device conflict");
      return {
        ...base,
        title: `Resolve the device conflict of ${who(ctx, a.memberId)}`,
        details: ["Automatic device approvals resume for this member.", "Resolve only after you checked with the person which of their devices are theirs."],
        current: `Conflict opened at seq ${c}.`,
        subject: JSON.stringify([c, auth.versions[versionKey.conflict(a.memberId)] ?? -1]),
      };
    }
    case "host.key.rotate": {
      const cur = auth.hostKeys.find((h) => h.toSeq === null);
      return {
        ...base,
        title: "Rotate the host key",
        details: ["A new host key signs from now on. Grants signed by the old key stay valid for 24 hours.", "Every member sees a notice."],
        current: cur ? `Current host key: ${short(cur.kid)}.` : null,
        subject: JSON.stringify([cur?.kid ?? null]),
      };
    }
    case "host.key.revoke": {
      const h = auth.hostKeys.find((k) => k.kid === a.kid) ?? fail("Unknown host key");
      if (h.toSeq === null) fail("The current host key cannot be revoked; rotate it first");
      if (h.revoked) fail("That host key is already revoked");
      return {
        ...base,
        title: `Revoke host key ${short(a.kid)} from seq ${a.fromSeq}`,
        details: ["Entries it signed from that position are treated as suspect, and grants it signed stop working."],
        current: `Key used from seq ${h.fromSeq} to ${h.toSeq}.`,
        warning: "Use this only if the old host key may have been stolen.",
        typeToConfirm: "revoke",
        subject: JSON.stringify([h.toSeq, h.revoked]),
      };
    }
    case "admin.key.rotate": {
      if (!ctx.ownAdminKid) fail("No admin key for this room on this daemon");
      return {
        ...base,
        title: "Rotate this daemon's admin key",
        details: ["A new admin key replaces it; the old key signs the change.", "Every member sees a notice."],
        current: `Current admin key: ${short(ctx.ownAdminKid)}.`,
        subject: JSON.stringify([ctx.ownAdminKid]),
      };
    }
    case "admin.key.revoke": {
      const k = auth.admins.find((x) => x.kid === a.kid) ?? fail("Unknown admin key");
      if (k.kid === ctx.ownAdminKid) fail("Rotate your own key instead of revoking it");
      return {
        ...base,
        title: `Revoke admin key ${short(a.kid)} from seq ${a.fromSeq}`,
        details: ["Statements it signed from that position become suspect and have no effect.", "Every member sees a notice."],
        current: k.toSeq === null ? "The key is active." : `The key was active until seq ${k.toSeq}.`,
        warning: "Use this when another admin's key was lost or stolen.",
        typeToConfirm: "revoke",
        subject: JSON.stringify([k.toSeq, k.suspectFromSeq, activeAdmins(auth).length]),
      };
    }
    case "endpoint.rotate":
      return {
        ...base,
        title: "Rotate the room endpoint",
        details: ["Members reconnect to a new endpoint. The old one answers \"moved\" to active devices for 30 days."],
        current: `Current endpoint: ${short(auth.endpoint.serverId)}.`,
        subject: JSON.stringify([auth.endpoint.serverId, auth.versions[versionKey.endpoint()] ?? -1]),
      };
    case "lane.rotate": {
      const l = auth.lanes[a.laneId] ?? fail("Unknown lane");
      if (l.status === "closed") fail("The lane is closed");
      return {
        ...base,
        title: `Rotate lane ${laneName(ctx, a.laneId)}`,
        details: ["The old lane endpoint stops now; members' views reconnect with fresh grants."],
        current: `Current offer: ${short(l.offer.serverId)}.`,
        subject: JSON.stringify([l.offer.serverId, l.status]),
      };
    }
    case "room.close.propose": {
      if (auth.closed) fail("The room is already closed");
      // Keys 6.8: with one lineage no admin can confirm; the room is closed with the recovery key.
      if (lineageCount(auth) <= 1) fail(auth.recovery ? "This room has one admin lineage: close it with the recovery code" : "This room has one admin lineage: create a recovery key, then close the room with it");
      const open = Object.values(auth.pendingClose).filter((p) => !p.used).length;
      return {
        ...base,
        title: "Propose closing the room",
        details: [
          `An admin of another lineage must confirm, no earlier than ${Math.round(auth.policy.closeDelay / 3600)} h after the proposal. The proposal expires after at most 7 days.`,
          "Every member sees the proposal and the earliest time it can take effect.",
        ],
        current: open ? `${open} closing proposal(s) already open.` : null,
        warning: "A closed room cannot be reopened. Lanes stop and members lose access.",
        typeToConfirm: "close",
        subject: JSON.stringify([auth.closed, open]),
      };
    }
    case "room.close.confirm": {
      const p = auth.pendingClose[a.proposal] ?? fail("Unknown closing proposal");
      if (p.used) fail("That proposal was already used");
      return {
        ...base,
        title: "Close the room",
        details: [`Proposed by admin key ${short(p.kid)} at ${fmtTime(p.hts)}.`, "Every lane stops and every member loses access. This is final."],
        warning: "A closed room cannot be reopened.",
        typeToConfirm: "close",
        subject: JSON.stringify([auth.closed, p.used]),
      };
    }
    case "recovery.create": {
      if (auth.recovery) fail("This room already has a recovery key; rotate it with the recovery code");
      const single = lineageCount(auth) <= 1;
      return {
        ...base,
        title: "Create a recovery key",
        details: [
          "The recovery key can revoke and add admin keys and close the room. It is shown once, then never stored on this daemon.",
          single ? "It is installed at once. Every member sees a notice." : "This room has two or more admin lineages: an admin of another lineage must confirm it within 3 days.",
        ],
        current: "No recovery key yet.",
        subject: JSON.stringify([auth.recovery, single]),
      };
    }
    case "recovery.confirm": {
      const p = auth.pendingRecovery[a.proposal] ?? fail("Unknown recovery key proposal");
      if (p.used) fail("That proposal was already used");
      return {
        ...base,
        title: "Confirm another admin's recovery key",
        details: [`Proposed by admin key ${short(p.kid)}. The proposer holds the code; you do not see it.`],
        warning: "Confirm only if you talked to the admin who proposed it.",
        subject: JSON.stringify([p.used, auth.recovery?.kid ?? null]),
      };
    }
  }
}
