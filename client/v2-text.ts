// Texts of the v2 Rooms UI (I-14): alerts (room-log-v2 4.6 and 6.6, MLS alerts), keystore states
// (identity-model 7.3, 7.5) and the generic error text members see. Pure functions; no React.

export type Tone = "ok" | "warn" | "danger" | "muted";

/** Room-log 6.6 and MLS alerts as the member's room view shows them. Unknown types get a neutral text. */
export function alertText(type: string): { text: string; tone: Tone; stopsSending: boolean } {
  switch (type) {
    case "fork":
    case "truncation":
      return { text: "This room's history differs between members. The host may be misbehaving. Sending is stopped in this room; reading continues.", tone: "danger", stopsSending: true };
    case "invalid_entry":
      return { text: "This room's history contains an invalid entry. The host may be misbehaving. Later entries are not processed.", tone: "danger", stopsSending: true };
    case "withholding":
      return { text: "The host may be holding back room entries from this device.", tone: "warn", stopsSending: false };
    case "local_copy_corrupt":
      return { text: "This device's saved copy of the room history was damaged. It is being fetched again from the host and checked against what this device saw before.", tone: "warn", stopsSending: false };
    case "unverified_head_claim":
      return { text: "A device reported a different history without evidence. Admins were told.", tone: "muted", stopsSending: false };
    case "roster_mismatch":
      return { text: "The room group and the room's member list disagree. This device stopped updating the group; admins were sent the evidence.", tone: "danger", stopsSending: true };
    case "uncertified_key":
      return { text: "A key of this room was set by a revoked admin key. An admin must replace it.", tone: "warn", stopsSending: false };
    case "leaf_replaced_unrequested":
      return { text: "Someone used this device's identity to replace its membership. Ask an admin to remove this device.", tone: "danger", stopsSending: true };
    case "epoch_fork":
      return { text: "This device's view of the room group split from other members'. Sending is stopped in this group.", tone: "danger", stopsSending: true };
    case "epoch_anchor_mismatch":
      return { text: "Another member's device confirmed a different room group state.", tone: "warn", stopsSending: false };
    case "epoch_unconfirmed":
      return { text: "No other device has confirmed this device's room group state yet.", tone: "muted", stopsSending: false };
    case "state_rollback":
      return { text: "This device's room state is older than what the host last saw. It may be a restored copy; link the device again.", tone: "danger", stopsSending: true };
    case "welcome_refused":
      return { text: "This device could not join the room group from the invitation it received.", tone: "warn", stopsSending: false };
    case "chat_attribution_failed":
      return { text: "A chat message did not carry a valid signature of the device it came from, or was bound to another group state. It was not shown. Admins were told the sending device.", tone: "danger", stopsSending: false };
    case "host_fault":
      return { text: "The host sent the room group something invalid.", tone: "warn", stopsSending: false };
    default:
      return { text: `Security notice (${type.replace(/[^a-z_.-]/gi, "").slice(0, 40)}).`, tone: "warn", stopsSending: false };
  }
}

/** Identity-model 7.3 outcomes and 7.5: what the owner sees for the KeyStore state. */
export function keystoreText(state: string): { title: string; text: string; tone: Tone } | null {
  switch (state) {
    case "ready":
      return null;
    case "locked":
      return { title: "Keyring locked", text: "Rooms is stopped until you unlock your system keyring. Unlock it, then reload this screen.", tone: "warn" };
    case "kek_missing":
      return { title: "Room key missing from the keyring", text: "The keyring has no Rooms entry although one was created. Rooms does not create a new one silently, because every room's keys depend on it. Restore the entry or contact an admin of each room.", tone: "danger" };
    case "unavailable":
      return { title: "Keyring unavailable", text: "The keyring Rooms used before cannot be reached. Rooms does not fall back to another store on its own.", tone: "danger" };
    case "misconfigured":
      return { title: "Keystore misconfigured", text: "The configured keystore backend could not be used.", tone: "danger" };
    case "inconsistent":
      return { title: "Keystore inconsistent", text: "The keystore records do not match the files on disk.", tone: "danger" };
    case "permission_error":
      return { title: "Rooms files are not protected", text: "Rooms found files other accounts could read or change and loaded no keys.", tone: "danger" };
    default:
      return { title: "Keystore problem", text: state, tone: "danger" };
  }
}

/**
 * What a member sees for an error of their room session or lane. Only codes are mapped; free text
 * from the host is never shown, so a member never reads the owner's paths or project names.
 */
export function memberErrorText(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const code = /^[a-z][a-z0-9_]{1,40}/.exec(raw.trim())?.[0] ?? "";
  const known: Record<string, string> = {
    not_authorized: "This device is not authorized in the room (removed or rekeyed).",
    removed: "You were removed from this room.",
    left: "This device left the room.",
    room_closed: "The room is closed.",
    superseded: "Another session of this device replaced this one.",
    moved: "The room moved to a new endpoint; reconnecting.",
    busy: "The room is busy. Retrying.",
    timeout: "The room did not answer in time.",
    relay_unreachable: "The relay could not be reached.",
    grants_unavailable: "Access for this lane is not available yet.",
    persist_failed: "The room could not save a change.",
    fork: "History check failed (fork).",
    sas_mismatch: "The codes did not match, so the join stopped. Ask the owner for a new invite.",
    rejected: "The owner did not admit this device.",
    vetoed: "One of your devices said this was not you, so the link stopped.",
    abandoned: "The join was abandoned before it completed.",
    expired: "The code expired. Ask for a new one.",
    invite_in_use: "Another device is already using this code.",
    invite_burned: "This code can no longer be used. Ask for a new one.",
    truncation: "History check failed (truncation).",
  };
  return known[code] ?? "Connection problem. Try Reconnect; if it persists, tell the room owner.";
}

export function fmtSas(s: string | null): string {
  if (!s) return "------";
  return /^\d{6}$/.test(s) ? `${s.slice(0, 3)} ${s.slice(3)}` : s;
}

/** First 8 characters of an id, after its type prefix (`mem_`, `dev_`, `lane_`, `room_`) if it has one. */
export function shortId(id: string | null | undefined): string {
  if (!id) return "?";
  // Key ids are base64url and may contain "_"; only typed ids (`mem_` + 32 hex) have a prefix.
  return id.replace(/^[a-z]{2,5}_(?=[0-9a-f]{32}$)/, "").slice(0, 8);
}

/** Recovery code groups for display: "prk2-abcd-efgh-…" in lines of 4 groups. */
export function recoveryCodeLines(code: string): string[] {
  const [prefix, ...groups] = code.split("-");
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 4) lines.push(groups.slice(i, i + 4).join("-"));
  return [`${prefix}-`, ...lines];
}

/** The last group of a recovery code: typed back as proof the person saved it. */
export function recoveryCheckGroup(code: string): string {
  const groups = code.split("-");
  return groups[groups.length - 1] ?? "";
}

export const WINDOWS_DURABILITY =
  "On Windows, Rooms cannot flush a folder after replacing a file, so a power loss right after a change may undo that change. Linux and macOS flush the folder.";

/** An activity item as the status view carries it (shared/rpc-v2 ActivityV2Item). */
export type ActivityLike = { type: string; alert: boolean; memberId?: string; deviceId?: string; laneId?: string; value?: string; changes?: { setting: string; from: string; to: string }[]; sole?: boolean; marked?: number };

const POLICY_LABELS: Record<string, string> = {
  minVersion: "minimum Rooms version",
  sas: "join code check",
  deviceAddApproval: "who approves new devices",
  rotateLaneOnRemove: "lane keys after a removal",
  recoveryEscrow: "recovery escrow",
  soleDeviceChange: "changes from a member's only device",
  projectNames: "project names for viewers",
  grantTtl: "lane access lifetime (s)",
  closeDelay: "closing delay (s)",
};

/**
 * A display name next to its short member id (R3.3). Names are untrusted text chosen by each member:
 * the id is always shown, so a copied name does not pass for someone else.
 */
export function nameWithId(name: string | null | undefined, memberId: string | null | undefined): string {
  return name ? `${name} (${shortId(memberId)})` : `Member ${shortId(memberId)}`;
}

/** Room-log 4.6 notices (R3.5). `who` gives the person for a member id (name with id, or "You"). */
export function activityText(a: ActivityLike, who: (memberId: string | undefined) => string): { text: string; tone: Tone } {
  const p = who(a.memberId);
  const dev = a.deviceId ? `device ${shortId(a.deviceId)}` : "a device";
  const lane = a.laneId ? `lane ${shortId(a.laneId)}` : "a lane";
  const sole = a.sole ? " It came from their only device in this room." : "";
  const marked = a.marked ? ` ${a.marked} earlier entr${a.marked === 1 ? "y is" : "ies are"} now marked as having no effect.` : "";
  const t = (text: string, tone: Tone = "muted") => ({ text: text + marked, tone });
  switch (a.type) {
    case "member.admitted":
      return t(`${p} joined the room.`, "ok");
    case "member.removed":
      return t(`${p} was removed from the room.`, "warn");
    case "member.left":
      return t(`${p} left the room.`);
    case "member.role.changed":
      return t(`${p}'s role changed to ${a.value ?? "?"}.`, "warn");
    case "member.device.replaced":
      return t(`${p}'s devices were replaced by an admin (new ${dev}).`, "warn");
    case "device.added":
      return t(`${p} is adding ${dev}.${sole}`, "warn");
    case "device.add.approved":
      return t(`${p} added ${dev}.`, "ok");
    case "device.add.vetoed":
      return t(`A device of ${p} said "Not me" to ${dev}.`, "danger");
    case "device.removed":
      return t(`${p}'s ${dev} was removed.`, "warn");
    case "device.rekeyed":
      return t(`${p}'s ${dev} asked to change its keys.${sole}`, "warn");
    case "device.rekey.vetoed":
      return t(`A device of ${p} said "Not me" to the key change of ${dev}.`, "danger");
    case "device.rekey.approved":
      return t(`${p}'s ${dev} changed its keys.`);
    case "device.conflict.resolved":
      return t(`An admin resolved the device conflict of ${p}.`);
    case "device.leaf.repair.requested":
      return t(`${p}'s ${dev} asked to repair its membership in the room group.`);
    case "room.policy.changed": {
      const list = (a.changes ?? []).map((c) => `${POLICY_LABELS[c.setting] ?? c.setting}: ${c.from} to ${c.to}`).join("; ");
      return t(`Room settings changed${list ? `: ${list}` : ""}.`, "warn");
    }
    case "room.close.proposed":
      return t("An admin proposed closing this room.", "warn");
    case "room.closed":
      return t("The room was closed.", "warn");
    case "admin.added":
      return t("An admin key was added.", "warn");
    case "admin.removed":
      return t("An admin key was removed.", "warn");
    case "admin.key.rotated":
      return t("An admin rotated their key.");
    case "admin.key.revoked":
      return t("An admin key was revoked.", "danger");
    case "recovery.key.proposed":
      return t("A new recovery key was proposed.", "warn");
    case "recovery.key.rotated":
      return t("The room's recovery key changed.", "warn");
    case "host.key.rotated":
      return t("The host key was rotated.");
    case "host.key.revoked":
      return t("A host key was revoked.", "danger");
    case "endpoint.rotated":
      return t("The room endpoint key was rotated.");
    case "lane.offer.rotated":
      return t(`The key of ${lane} was rotated.`);
    case "lane.created":
      return t(`${lane[0].toUpperCase()}${lane.slice(1)} was shared${a.memberId ? ` by ${p}` : ""}.`, "ok");
    case "lane.closed":
      return t(`${lane[0].toUpperCase()}${lane.slice(1)} was closed.`);
    case "lane.names.changed":
      return t(`Project names in ${lane} are now ${a.value === "shown" ? "shown" : "hidden"}.`, "warn");
    case "lane.degraded":
      return t(`${lane[0].toUpperCase()}${lane.slice(1)} is not working (its agent or endpoint failed).`, "warn");
    case "grant.suspected-theft":
      return t("Lane access of a device was used from two places. It may be stolen.", "danger");
    case "endpoint.evicted":
      return t("The room endpoint was pushed off the relay repeatedly.", "danger");
    case "mls.stalled":
      return t("The room group stopped advancing.", "warn");
    case "uncertified_key":
      return t("A key of this room was set by a revoked admin key. An admin must replace it.", "warn");
    default:
      return t(`Room change (${a.type.replace(/[^a-z_.-]/gi, "").slice(0, 40)}).`);
  }
}
