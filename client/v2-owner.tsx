// Owner side of the v2 Rooms UI (I-14): join requests with the SAS (enrollment 6.3), device holds and
// conflicts (identity-model 6.3), members and devices, lanes and invites, keys, recovery and closure
// (keys-rotation-recovery 4, 6). Every admin statement goes through useAdminConfirm (token + dialog).
import type { PluginTheme } from "@getpaseo/plugin";
import { useRpc } from "@getpaseo/plugin/client";
import { copyText, Modal, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Pressable, Text, View } from "react-native";
import type { z } from "zod";
import {
  roomsV2AdminKeyRevoke,
  roomsV2AdminKeyRotate,
  roomsV2CloseConfirm,
  roomsV2CloseProposed,
  roomsV2ConflictResolve,
  roomsV2DeviceApprove,
  roomsV2DeviceRemove,
  roomsV2EndpointRotate,
  roomsV2HostKeyRevoke,
  roomsV2HostKeyRotate,
  roomsV2InviteCreate,
  roomsV2InviteRevoke,
  roomsV2JoinAdmit,
  roomsV2JoinReject,
  roomsV2LaneErrors,
  roomsV2LaneRotate,
  roomsV2MemberRemove,
  roomsV2MemberRole,
  roomsV2RecoveryAct,
  roomsV2RecoveryConfirm,
  roomsV2RecoveryCreate,
  type OwnedRoomV2View,
} from "../shared/rpc-v2";
import { Badge, Button, ConfirmButton, Dot, errorText, relativeTime, Section, Segmented, type Styles } from "./ui";
import { RecoveryCodeModal, SasDigits, useAdminConfirm, type RecoveryOffer } from "./v2-dialogs";
import { shortId } from "./v2-text";

export type OwnedV2 = z.infer<typeof OwnedRoomV2View>;
export const STATUS_V2_KEY = ["rooms", "v2", "status"] as const;

const ROLES = ["guest", "watch", "comment", "steer", "approve", "maintain", "admin"] as const;
type Role = (typeof ROLES)[number];
const iso = (ms: number) => new Date(ms).toISOString();
const when = (ms: number | null) => (ms === null ? "when an admin approves" : `${new Date(ms).toLocaleString()} (${relativeTime(iso(ms))})`);

function Chip({ theme, label, active, onPress, accessibilityLabel }: { theme: PluginTheme; label: string; active: boolean; onPress(): void; accessibilityLabel?: string }) {
  const c = theme.colors;
  return (
    <Pressable
      accessibilityRole="checkbox"
      accessibilityState={{ checked: active }}
      accessibilityLabel={accessibilityLabel ?? label}
      onPress={onPress}
      style={{ borderRadius: 999, borderWidth: 1, borderColor: active ? c.accent : c.border, backgroundColor: active ? c.surface2 : c.surface1, paddingHorizontal: 10, paddingVertical: 5 }}
    >
      <Text style={{ color: c.foreground, fontSize: 12, fontWeight: active ? "600" : "400" }}>{label}</Text>
    </Pressable>
  );
}

function Notice({ theme, styles, tone, children }: { theme: PluginTheme; styles: Styles; tone: "warn" | "danger" | "muted"; children: ReactNode }) {
  const c = theme.colors;
  const color = tone === "danger" ? c.statusDanger : tone === "warn" ? c.statusWarning : c.border;
  return <View style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: color, gap: 6 }]}>{children}</View>;
}

export function OwnedRoomCardV2({ view, theme, styles, compact }: { view: OwnedV2; theme: PluginTheme; styles: Styles; compact: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const admin = useAdminConfirm(theme, styles);
  const [tab, setTab] = useState<"members" | "lanes" | "keys">("members");
  const [recovery, setRecovery] = useState<RecoveryOffer | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
  const roomId = view.roomId;

  const rotateHost = useRpc(roomsV2HostKeyRotate);
  const rotateEndpoint = useRpc(roomsV2EndpointRotate);
  const rotateLane = useRpc(roomsV2LaneRotate);
  const removeDevice = useRpc(roomsV2DeviceRemove);
  const resolve = useRpc(roomsV2ConflictResolve);
  const approve = useRpc(roomsV2DeviceApprove);
  const confirmClose = useRpc(roomsV2CloseConfirm);
  const confirmRecovery = useRpc(roomsV2RecoveryConfirm);

  const actives = view.roster.filter((m) => m.devices.length > 0);
  const connected = actives.filter((m) => m.devices.some((d) => d.connected)).length;
  const labelOf = (memberId: string) => {
    const m = view.roster.find((x) => x.memberId === memberId);
    return m?.self ? "You" : m?.label ? `${m.label} (${shortId(memberId)})` : `Member ${shortId(memberId)}`;
  };
  const openJoins = view.joinRequests.filter((j) => j.state !== "admitted" && j.state !== "closed" && j.kind === "invite");
  const pendingDevices = view.deviceRequests.filter((d) => d.status === "pending");
  const ownKid = view.keys.adminKid;

  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <View style={{ flexShrink: 1, gap: 2 }}>
          <Text style={styles.h2}>Room {shortId(roomId)}</Text>
          <Text style={styles.small}>
            {view.members} member(s) · {connected} connected · log at seq {view.head.seq}
          </Text>
        </View>
        <Badge
          theme={theme}
          label={view.keys.closed ? "Closed" : view.endpoint === "online" ? "Online" : view.endpoint === "starting" ? "Starting" : view.endpoint === "closed" ? "Closed" : "Offline"}
          tone={view.keys.closed ? "muted" : view.endpoint === "online" ? "ok" : "warn"}
        />
      </View>

      {/* ---- alerts the owner must act on (room-log 4.6, 6.6; grants 6.4, 7.2) ---- */}
      {view.keys.closed ? (
        <Notice theme={theme} styles={styles} tone="muted">
          <Text style={styles.body}>This room is closed. Its lanes are stopped and members have no access. The agents stay on this daemon.</Text>
        </Notice>
      ) : null}
      {view.persistError ? (
        <Notice theme={theme} styles={styles} tone="danger">
          <Text style={styles.body}>
            {view.persistError === "room_stopped"
              ? "The room log could not be written, so the room stopped. Access stays cut in memory. Free disk space or fix permissions, then restart the daemon."
              : "Access was cut, but the change could not be saved. Rooms retries every 10 seconds; it is lost if the daemon restarts first. Free disk space or fix permissions."}
          </Text>
        </Notice>
      ) : null}
      {view.uncertified.map((u) => (
        <Notice key={`${u.subject}-${u.id}`} theme={theme} styles={styles} tone="warn">
          <Text style={styles.body}>
            A {u.subject === "host" ? "host key" : u.subject === "endpoint" ? "room endpoint key" : "lane offer"} of this room was set by a revoked admin key. Replace it.
          </Text>
          <View style={styles.row}>
            {u.subject === "host" ? (
              <Button theme={theme} label="Rotate host key" onPress={() => admin.open({ kind: "host.key.rotate", roomId }, (t) => rotateHost({ roomId, confirmToken: t }), { onDone: refresh, success: "Host key rotated" })} />
            ) : u.subject === "endpoint" ? (
              <Button theme={theme} label="Rotate endpoint" onPress={() => admin.open({ kind: "endpoint.rotate", roomId }, (t) => rotateEndpoint({ roomId, confirmToken: t }), { onDone: refresh, success: "Endpoint rotated" })} />
            ) : (
              <Button theme={theme} label="Rotate lane" onPress={() => admin.open({ kind: "lane.rotate", roomId, laneId: u.id }, (t) => rotateLane({ roomId, laneId: u.id, confirmToken: t }), { onDone: refresh, success: "Lane rotated" })} />
            )}
          </View>
        </Notice>
      ))}
      {view.compromisedDevices.map((deviceId) => {
        const m = view.roster.find((x) => x.devices.some((d) => d.deviceId === deviceId));
        return (
          <Notice key={deviceId} theme={theme} styles={styles} tone="danger">
            <Text style={styles.body}>
              Device {shortId(deviceId)}{m ? ` of ${labelOf(m.memberId)}` : ""} was used from two places twice within 7 days. Its access may be stolen.
            </Text>
            {m ? (
              <Button
                theme={theme}
                variant="danger"
                label="Remove device"
                onPress={() =>
                  admin.open({ kind: "device.remove", roomId, memberId: m.memberId, deviceId, compromise: true }, (t) => removeDevice({ roomId, memberId: m.memberId, deviceId, compromise: true, confirmToken: t }), {
                    onDone: refresh,
                    success: "Device removed",
                  })
                }
              />
            ) : null}
          </Notice>
        );
      })}
      {view.conflicts.map((memberId) => (
        <Notice key={memberId} theme={theme} styles={styles} tone="danger">
          <Text style={styles.body}>{labelOf(memberId)}'s devices disagree about a new device. One of them may be stolen. Automatic approvals are paused for this member.</Text>
          <Text style={styles.small}>Ask the person which devices are theirs, remove any that are not, then resolve.</Text>
          <Button
            theme={theme}
            label="Resolve conflict"
            onPress={() => admin.open({ kind: "device.conflict.resolve", roomId, memberId }, (t) => resolve({ roomId, memberId, confirmToken: t }), { onDone: refresh, success: "Conflict resolved" })}
          />
        </Notice>
      ))}
      {view.keys.closeProposals.map((p) => {
        const earliest = p.hts + view.policy.closeDelayS * 1000;
        const mine = p.kid === ownKid;
        return (
          <Notice key={p.ref} theme={theme} styles={styles} tone="warn">
            <Text style={styles.body}>
              {mine ? "You proposed closing this room." : `Admin key ${shortId(p.kid)} proposed closing this room.`} It can be confirmed from {when(earliest)}; the proposal expires {relativeTime(iso(p.exp * 1000))}.
            </Text>
            {!mine && view.lineages > 1 ? (
              <Button
                theme={theme}
                variant="danger"
                label="Confirm closing"
                disabled={Date.now() < earliest}
                onPress={() => admin.open({ kind: "room.close.confirm", roomId, proposal: p.ref }, (t) => confirmClose({ roomId, proposal: p.ref, confirmToken: t }), { onDone: refresh, success: "Room closed" })}
              />
            ) : (
              <Text style={styles.small}>{view.lineages > 1 ? "An admin of another lineage must confirm." : "A room with one admin lineage is closed with the recovery key (Keys tab)."}</Text>
            )}
          </Notice>
        );
      })}
      {(view.keys.recoveryProposals ?? []).map((p) => (
        <Notice key={p.ref} theme={theme} styles={styles} tone="warn">
          <Text style={styles.body}>
            {p.kid === ownKid ? "You proposed a recovery key. An admin of another lineage must confirm it" : `Admin key ${shortId(p.kid)} proposed a recovery key`}; the proposal expires {relativeTime(iso(p.exp * 1000))}.
          </Text>
          {p.kid !== ownKid ? (
            <Button
              theme={theme}
              label="Confirm recovery key"
              onPress={() => admin.open({ kind: "recovery.confirm", roomId, proposal: p.ref }, (t) => confirmRecovery({ roomId, proposal: p.ref, confirmToken: t }), { onDone: refresh, success: "Recovery key confirmed" })}
            />
          ) : null}
        </Notice>
      ))}

      {/* ---- join requests (enrollment 6.3) ---- */}
      {openJoins.map((j) => (
        <JoinRequestCard key={j.pendingId} roomId={roomId} j={j} theme={theme} styles={styles} admin={admin} refresh={refresh} />
      ))}

      {/* ---- held device adds and rekeys (identity-model 6.3) ---- */}
      {pendingDevices.map((d) => (
        <Notice key={d.ref} theme={theme} styles={styles} tone={d.sole || d.young ? "warn" : "muted"}>
          <Text style={styles.body}>
            {d.kind === "add" ? `${labelOf(d.memberId)} is adding a device; it joins ${when(d.effectiveAfter)}.` : `${labelOf(d.memberId)}'s device ${shortId(d.deviceId)} is changing its keys; effective ${when(d.effectiveAfter)}.`}
          </Text>
          {d.sole ? (
            <Text style={[styles.small, { color: theme.colors.statusWarning }]}>
              {labelOf(d.memberId)} has only one device in this room, and it is {d.kind === "add" ? "adding another" : "changing its keys"}. If they did not ask for this, remove the device.
            </Text>
          ) : null}
          {d.young ? <Text style={styles.small}>The requesting device joined less than 24 hours ago, so this needs an admin.</Text> : null}
          <View style={styles.row}>
            <Button
              theme={theme}
              label={d.effectiveAfter === null ? "Approve" : "Approve now"}
              onPress={() => admin.open({ kind: "device.approve", roomId, ref: d.ref }, (t) => approve({ roomId, ref: d.ref, confirmToken: t }), { onDone: refresh, success: "Approved" })}
            />
          </View>
        </Notice>
      ))}

      <Segmented<"members" | "lanes" | "keys">
        theme={theme}
        value={tab}
        onChange={setTab}
        options={[
          { value: "members", label: compact ? "Members" : `Members (${view.members})` },
          { value: "lanes", label: compact ? "Lanes" : "Lanes and invites" },
          { value: "keys", label: compact ? "Keys" : "Keys, recovery, closing" },
        ]}
      />
      {tab === "members" ? <MembersTab view={view} theme={theme} styles={styles} admin={admin} refresh={refresh} labelOf={labelOf} /> : null}
      {tab === "lanes" ? <LanesTab view={view} theme={theme} styles={styles} admin={admin} refresh={refresh} /> : null}
      {tab === "keys" ? <KeysTab view={view} theme={theme} styles={styles} admin={admin} refresh={refresh} onRecovery={setRecovery} /> : null}

      {admin.element}
      <RecoveryCodeModal
        theme={theme}
        styles={styles}
        offer={recovery}
        context={`Recovery key for room ${shortId(roomId)} (key ${shortId(recovery?.kid)}).`}
        onClosed={() => {
          setRecovery(null);
          toast.show("Recovery code dialog closed. The daemon does not keep a copy.");
        }}
      />
    </View>
  );
}

type AdminApi = ReturnType<typeof useAdminConfirm>;
type TabProps = { view: OwnedV2; theme: PluginTheme; styles: Styles; admin: AdminApi; refresh(): void };

function JoinRequestCard({ roomId, j, theme, styles, admin, refresh }: { roomId: string; j: OwnedV2["joinRequests"][number] } & Omit<TabProps, "view">) {
  const toast = useToast();
  const admit = useRpc(roomsV2JoinAdmit);
  const reject = useRpc(roomsV2JoinReject);
  const c = theme.colors;
  return (
    <View style={[styles.codeBox, { gap: 8, borderWidth: 1, borderColor: j.contested ? c.statusDanger : c.border }]} accessibilityLabel="Join request">
      <Text style={styles.h2}>Join request</Text>
      {j.contested ? <Text style={[styles.body, { color: c.statusDanger }]}>Another device also tried to use this invite. It may have been copied. Compare the code carefully.</Text> : null}
      <Text style={styles.body}>Someone used the invite {j.note ? `"${j.note}"` : "(no note)"}.</Text>
      <Text style={styles.body}>They call themselves: {j.label} (self-reported).</Text>
      <SasDigits theme={theme} sas={j.sas} />
      {!j.sas ? <Text style={styles.small}>Waiting for their device to reveal the code…</Text> : null}
      {j.abandonedBefore > 0 ? <Text style={[styles.small, { color: c.statusWarning }]}>{j.abandonedBefore} earlier attempt(s) on this invite were abandoned.</Text> : null}
      <Text style={styles.small}>Call or meet the person you invited and ask them to read their code. Admit only if it is the same. Do not compare codes in the chat or email where you sent the invite.</Text>
      <Text style={styles.small}>Expires {relativeTime(iso(j.expiresAt))}.</Text>
      <View style={styles.row}>
        <Button
          theme={theme}
          variant="primary"
          label="Admit"
          disabled={!j.sas}
          onPress={() => admin.open({ kind: "join.admit", roomId, pendingId: j.pendingId }, (t) => admit({ roomId, pendingId: j.pendingId, confirmToken: t }), { onDone: refresh, success: `Admitted ${j.label}` })}
        />
        <ConfirmButton
          theme={theme}
          label="Codes do not match"
          confirmLabel="Burn the invite"
          message="The invite stops working; nobody can join with it. Create a new invite after you talked to the person."
          onConfirm={() =>
            reject({ roomId, pendingId: j.pendingId, reason: "sas_mismatch" })
              .then(refresh)
              .catch((e) => toast.error(errorText(e)))
          }
        />
        <Button
          theme={theme}
          label="Cancel"
          onPress={() =>
            void reject({ roomId, pendingId: j.pendingId, reason: "cancel" })
              .then(refresh)
              .catch((e) => toast.error(errorText(e)))
          }
        />
      </View>
    </View>
  );
}

function MembersTab({ view, theme, styles, admin, refresh, labelOf }: TabProps & { labelOf(memberId: string): string }) {
  const setRole = useRpc(roomsV2MemberRole);
  const remove = useRpc(roomsV2MemberRemove);
  const removeDevice = useRpc(roomsV2DeviceRemove);
  const [roleFor, setRoleFor] = useState<string | null>(null);
  const roomId = view.roomId;
  return (
    <View style={{ gap: 10 }}>
      {view.roster.map((m) => (
        <View key={m.memberId} style={{ gap: 6 }}>
          <View style={styles.between}>
            <View style={{ flexShrink: 1, gap: 2 }}>
              <Text style={styles.body}>{labelOf(m.memberId)}</Text>
              <Text style={styles.small}>
                {m.role} · {m.lanes.length} lane(s) · {m.devices.length} device(s)
              </Text>
            </View>
            <Badge theme={theme} label={m.devices.some((d) => d.connected) ? "Connected" : m.devices.length ? "Not connected" : "No device"} tone={m.devices.some((d) => d.connected) ? "ok" : "muted"} />
          </View>
          {m.devices.map((d) => (
            <View key={d.deviceId} style={[styles.between, { paddingLeft: 12 }]}>
              <View style={[styles.row, { flexShrink: 1 }]}>
                <Dot color={d.connected ? theme.colors.statusSuccess : theme.colors.foregroundMuted} />
                <Text style={styles.small}>
                  Device {shortId(d.deviceId)} · {d.kind}
                  {d.since ? ` · since ${relativeTime(iso(d.since))}` : ""}
                </Text>
              </View>
              {!m.self ? (
                <View style={styles.row}>
                  <Button
                    theme={theme}
                    label="Remove device"
                    accessibilityLabel={`Remove device ${shortId(d.deviceId)}`}
                    onPress={() =>
                      admin.open({ kind: "device.remove", roomId, memberId: m.memberId, deviceId: d.deviceId, compromise: false }, (t) => removeDevice({ roomId, memberId: m.memberId, deviceId: d.deviceId, compromise: false, confirmToken: t }), {
                        onDone: refresh,
                        success: "Device removed",
                      })
                    }
                  />
                  <Button
                    theme={theme}
                    variant="danger"
                    label="Lost or stolen"
                    accessibilityLabel={`Remove device ${shortId(d.deviceId)} as compromised`}
                    onPress={() =>
                      admin.open({ kind: "device.remove", roomId, memberId: m.memberId, deviceId: d.deviceId, compromise: true }, (t) => removeDevice({ roomId, memberId: m.memberId, deviceId: d.deviceId, compromise: true, confirmToken: t }), {
                        onDone: refresh,
                        success: "Device removed; lanes rotated",
                      })
                    }
                  />
                </View>
              ) : null}
            </View>
          ))}
          {!m.self ? (
            <View style={styles.row}>
              <Button theme={theme} label={roleFor === m.memberId ? "Hide roles" : "Change role"} onPress={() => setRoleFor(roleFor === m.memberId ? null : m.memberId)} />
              <Button
                theme={theme}
                variant="danger"
                label="Remove"
                accessibilityLabel={`Remove ${labelOf(m.memberId)}`}
                onPress={() => admin.open({ kind: "member.remove", roomId, memberId: m.memberId, compromise: false }, (t) => remove({ roomId, memberId: m.memberId, compromise: false, confirmToken: t }), { onDone: refresh, success: "Member removed" })}
              />
              <Button
                theme={theme}
                variant="danger"
                label="Remove, suspect misuse"
                accessibilityLabel={`Remove ${labelOf(m.memberId)} and rotate their lanes`}
                onPress={() => admin.open({ kind: "member.remove", roomId, memberId: m.memberId, compromise: true }, (t) => remove({ roomId, memberId: m.memberId, compromise: true, confirmToken: t }), { onDone: refresh, success: "Member removed; lanes rotated" })}
              />
            </View>
          ) : null}
          {roleFor === m.memberId ? (
            <View style={styles.row}>
              {ROLES.map((r) => (
                <Chip
                  key={r}
                  theme={theme}
                  label={r}
                  active={m.role === r}
                  onPress={() => {
                    if (r === m.role) return;
                    admin.open({ kind: "member.role", roomId, memberId: m.memberId, role: r }, (t) => setRole({ roomId, memberId: m.memberId, role: r, confirmToken: t }), {
                      onDone: () => {
                        setRoleFor(null);
                        refresh();
                      },
                      success: `Role changed to ${r}`,
                    });
                  }}
                />
              ))}
            </View>
          ) : null}
          <View style={styles.divider} />
        </View>
      ))}
      <Text style={styles.small}>Names are what each person typed when they joined; they are not verified.</Text>
    </View>
  );
}

function LanesTab({ view, theme, styles, admin, refresh }: TabProps) {
  const toast = useToast();
  const createInvite = useRpc(roomsV2InviteCreate);
  const revokeInvite = useRpc(roomsV2InviteRevoke);
  const rotateLane = useRpc(roomsV2LaneRotate);
  const [role, setRole] = useState<Role>("watch");
  const [lanes, setLanes] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [roomName, setRoomName] = useState("");
  const [code, setCode] = useState<{ code: string; exp: number } | null>(null);
  const roomId = view.roomId;
  const open = view.lanes.filter((l) => l.status !== "closed");
  const toggle = (laneId: string) => setLanes((xs) => (xs.includes(laneId) ? xs.filter((x) => x !== laneId) : [...xs, laneId].sort()));
  const inviteInput = { roomId, role, lanes, ...(note.trim() ? { note: note.trim() } : {}), ...(roomName.trim() ? { roomName: roomName.trim() } : {}) };
  return (
    <View style={{ gap: 12 }}>
      <Section styles={styles} title="Lanes">
        {view.lanes.length === 0 ? <Text style={styles.muted}>No lanes. Open an agent, open the Command Center and choose "Open room…" to share it in this room.</Text> : null}
        {view.lanes.map((l) => (
          <View key={l.laneId} style={{ gap: 6 }}>
            <View style={styles.between}>
              <View style={{ flexShrink: 1, gap: 2 }}>
                <Text style={styles.body}>{l.label ?? `Lane ${shortId(l.laneId)}`}</Text>
                <Text style={styles.small}>
                  {l.status} · {l.links} link(s) · {l.routes} open view(s) · project names {l.showNames ? "shown" : "hidden"}
                </Text>
              </View>
              <Badge theme={theme} label={l.status === "closed" ? "Closed" : (l.endpoint ?? "offline")} tone={l.status === "closed" ? "muted" : l.endpoint === "online" ? "ok" : "warn"} />
            </View>
            {l.status !== "closed" ? (
              <View style={styles.row}>
                <Button
                  theme={theme}
                  label="Rotate lane"
                  onPress={() => admin.open({ kind: "lane.rotate", roomId, laneId: l.laneId }, (t) => rotateLane({ roomId, laneId: l.laneId, confirmToken: t }), { onDone: refresh, success: "Lane rotated" })}
                />
                <LaneErrorsV2 roomId={roomId} laneId={l.laneId} theme={theme} styles={styles} />
              </View>
            ) : null}
          </View>
        ))}
        <Text style={styles.small}>Closing a lane is not available in this build yet.</Text>
      </Section>

      <Section styles={styles} title="Invite someone">
        <Text style={styles.small}>Role</Text>
        <View style={styles.row}>
          {ROLES.map((r) => (
            <Chip key={r} theme={theme} label={r} active={role === r} onPress={() => setRole(r)} />
          ))}
        </View>
        {open.length ? <Text style={styles.small}>Lanes they can see</Text> : null}
        <View style={styles.row}>
          {open.map((l) => (
            <Chip key={l.laneId} theme={theme} label={l.label ?? shortId(l.laneId)} active={lanes.includes(l.laneId)} onPress={() => toggle(l.laneId)} />
          ))}
        </View>
        <TextInput accessibilityLabel="Note for you (who this invite is for)" placeholder="Who is it for? (only you see this)" placeholderTextColor={theme.colors.foregroundMuted} value={note} onChangeText={setNote} maxLength={80} style={styles.input} />
        <TextInput
          accessibilityLabel="Room name shown to the invited person"
          placeholder="Room name they see before joining (optional)"
          placeholderTextColor={theme.colors.foregroundMuted}
          value={roomName}
          onChangeText={setRoomName}
          maxLength={80}
          style={styles.input}
        />
        <View style={styles.row}>
          <Button
            theme={theme}
            variant="primary"
            label="Create invite"
            disabled={view.keys.closed}
            onPress={() =>
              admin.open({ kind: "invite.create", ...inviteInput }, (t) => createInvite({ ...inviteInput, confirmToken: t }), {
                onDone: (r) => {
                  setCode({ code: r.code, exp: r.exp });
                  refresh();
                },
              })
            }
          />
        </View>
        {code ? (
          <View style={[styles.codeBox, { gap: 6 }]}>
            <Text style={styles.small}>One-time invite code, valid {relativeTime(iso(code.exp * 1000))}. Send it privately. It is shown only now.</Text>
            <Text selectable numberOfLines={3} style={styles.mono}>
              {code.code}
            </Text>
            <Text style={styles.small}>Shown shortened. "Copy code" copies all of it. When they join, compare the six-digit code by voice.</Text>
            <View style={styles.row}>
              <Button theme={theme} variant="primary" label="Copy code" onPress={() => void copyText(code.code).then(() => toast.show("Invite code copied", { variant: "success" }), () => toast.error("Copy failed"))} />
              <Button theme={theme} label="Hide" onPress={() => setCode(null)} />
            </View>
          </View>
        ) : null}
      </Section>

      {view.invites.some((i) => i.state === "open" || i.state === "claimed") ? (
        <Section styles={styles} title="Open invites">
          {view.invites
            .filter((i) => i.state === "open" || i.state === "claimed")
            .map((i) => (
              <View key={i.inviteId} style={styles.between}>
                <View style={{ flexShrink: 1, gap: 2 }}>
                  <Text style={styles.body}>{i.note || "(no note)"}</Text>
                  <Text style={styles.small}>
                    {i.role} · {i.lanes.length} lane(s) · {i.state} · expires {relativeTime(iso(i.exp * 1000))}
                    {i.abandoned ? ` · ${i.abandoned} abandoned attempt(s)` : ""}
                  </Text>
                </View>
                <ConfirmButton
                  theme={theme}
                  variant="secondary"
                  label="Revoke invite"
                  confirmLabel="Revoke invite"
                  message="The code stops working. Anyone already admitted keeps access."
                  onConfirm={() =>
                    revokeInvite({ roomId, inviteId: i.inviteId })
                      .then(refresh)
                      .catch((e) => toast.error(errorText(e)))
                  }
                />
              </View>
            ))}
        </Section>
      ) : null}
    </View>
  );
}

/** Owner only: full error text of a lane (grants-v2 13.1). Members saw generic text with a reference. */
function LaneErrorsV2({ roomId, laneId, theme, styles }: { roomId: string; laneId: string; theme: PluginTheme; styles: Styles }) {
  const [open, setOpen] = useState(false);
  const fetchErrors = useRpc(roomsV2LaneErrors);
  const q = useQuery({ queryKey: ["rooms", "v2", "lane-errors", laneId], queryFn: () => fetchErrors({ roomId, laneId }), enabled: open, refetchInterval: open ? 5000 : false });
  return (
    <>
      <Button theme={theme} label={open ? "Hide errors" : "Recent errors"} onPress={() => setOpen((v) => !v)} />
      {open ? (
        <Modal title="Recent lane errors" open onOpenChange={(o) => setOpen(o)}>
          <Modal.Content>
            <View style={{ gap: 8 }}>
              <Text style={styles.small}>Only you see these. Members got generic text with the reference.</Text>
              {q.isError ? <Text style={styles.danger}>Could not load errors: {errorText(q.error)}</Text> : null}
              {q.data && q.data.errors.length === 0 ? <Text style={styles.small}>No errors since the lane started on this daemon.</Text> : null}
              {q.data?.errors.map((e, i) => (
                <View key={`${e.source}-${e.firstAt}-${i}`} style={{ gap: 2 }}>
                  <Text style={styles.small}>
                    {e.source} · {relativeTime(e.lastAt)}
                    {e.count > 1 ? ` · ${e.count} times` : ""}
                    {e.ref ? ` · ref ${e.ref}` : ""}
                  </Text>
                  <Text selectable numberOfLines={6} style={styles.mono}>
                    {e.message}
                  </Text>
                </View>
              ))}
            </View>
          </Modal.Content>
        </Modal>
      ) : null}
    </>
  );
}

function KeysTab({ view, theme, styles, admin, refresh, onRecovery }: TabProps & { onRecovery(o: RecoveryOffer): void }) {
  const rotateHost = useRpc(roomsV2HostKeyRotate);
  const revokeHost = useRpc(roomsV2HostKeyRevoke);
  const rotateAdmin = useRpc(roomsV2AdminKeyRotate);
  const revokeAdmin = useRpc(roomsV2AdminKeyRevoke);
  const rotateEndpoint = useRpc(roomsV2EndpointRotate);
  const createRecovery = useRpc(roomsV2RecoveryCreate);
  const propose = useRpc(roomsV2CloseProposed);
  const roomId = view.roomId;
  const k = view.keys;
  const retiredHost = k.hostKeys.filter((h) => h.toSeq !== null && !h.revoked);
  const otherAdmins = k.admins.filter((a) => a.kid !== k.adminKid);
  const [revokeFrom, setRevokeFrom] = useState<Record<string, string>>({});
  const fromSeqOf = (kid: string, dflt: number) => {
    const n = Number.parseInt(revokeFrom[kid] ?? String(dflt), 10);
    return Number.isFinite(n) && n >= 0 ? n : dflt;
  };
  return (
    <View style={{ gap: 12 }}>
      <Section styles={styles} title="Keys">
        <Text style={styles.small}>
          Host key {shortId(k.hostKid)} · your admin key {shortId(k.adminKid)} · {view.lineages} admin lineage(s) · endpoint {shortId(view.serverId)}
        </Text>
        <View style={styles.row}>
          <Button theme={theme} label="Rotate host key" onPress={() => admin.open({ kind: "host.key.rotate", roomId }, (t) => rotateHost({ roomId, confirmToken: t }), { onDone: refresh, success: "Host key rotated" })} />
          {k.adminKid ? <Button theme={theme} label="Rotate my admin key" onPress={() => admin.open({ kind: "admin.key.rotate", roomId }, (t) => rotateAdmin({ roomId, confirmToken: t }), { onDone: refresh, success: "Admin key rotated" })} /> : null}
          <Button theme={theme} label="Rotate endpoint" onPress={() => admin.open({ kind: "endpoint.rotate", roomId }, (t) => rotateEndpoint({ roomId, confirmToken: t }), { onDone: refresh, success: "Endpoint rotated" })} />
        </View>
        {retiredHost.map((h) => (
          <View key={h.kid} style={[styles.row, { justifyContent: "space-between" }]}>
            <Text style={styles.small}>
              Old host key {shortId(h.kid)} (seq {h.fromSeq} to {h.toSeq})
            </Text>
            <View style={styles.row}>
              <TextInput accessibilityLabel="Revoke from seq" value={revokeFrom[h.kid] ?? String(h.fromSeq)} onChangeText={(v) => setRevokeFrom((x) => ({ ...x, [h.kid]: v }))} keyboardType="number-pad" style={[styles.input, { width: 80 }]} />
              <Button
                theme={theme}
                variant="danger"
                label="Revoke"
                onPress={() => {
                  const fromSeq = fromSeqOf(h.kid, h.fromSeq);
                  admin.open({ kind: "host.key.revoke", roomId, kid: h.kid, fromSeq }, (t) => revokeHost({ roomId, kid: h.kid, fromSeq, confirmToken: t }), { onDone: refresh, success: "Host key revoked" });
                }}
              />
            </View>
          </View>
        ))}
        {otherAdmins.map((a) => (
          <View key={a.kid} style={[styles.row, { justifyContent: "space-between" }]}>
            <Text style={styles.small}>
              Admin key {shortId(a.kid)} (lineage {shortId(a.root)})
            </Text>
            <View style={styles.row}>
              <TextInput accessibilityLabel="Revoke from seq" value={revokeFrom[a.kid] ?? "0"} onChangeText={(v) => setRevokeFrom((x) => ({ ...x, [a.kid]: v }))} keyboardType="number-pad" style={[styles.input, { width: 80 }]} />
              <Button
                theme={theme}
                variant="danger"
                label="Revoke"
                onPress={() => {
                  const fromSeq = fromSeqOf(a.kid, 0);
                  admin.open({ kind: "admin.key.revoke", roomId, kid: a.kid, fromSeq }, (t) => revokeAdmin({ roomId, kid: a.kid, fromSeq, confirmToken: t }), { onDone: refresh, success: "Admin key revoked" });
                }}
              />
            </View>
          </View>
        ))}
      </Section>

      <Section styles={styles} title="Recovery key">
        {k.recoveryKid ? (
          <Text style={styles.small}>This room has a recovery key ({shortId(k.recoveryKid)}). Its holder can revoke admin keys, add an admin and close the room.</Text>
        ) : (
          <>
            <Text style={styles.small}>Without a recovery key, a room with one admin cannot be recovered if that admin's key is lost or stolen. Members would have to start a new room.</Text>
            <Button
              theme={theme}
              variant="primary"
              label="Create a recovery key"
              onPress={() =>
                admin.open({ kind: "recovery.create", roomId }, (t) => createRecovery({ roomId, confirmToken: t }), {
                  onDone: (r) => {
                    onRecovery(r.recovery);
                    refresh();
                  },
                })
              }
            />
          </>
        )}
        {k.recoveryKid ? <RecoveryActions view={view} theme={theme} styles={styles} refresh={refresh} onRecovery={onRecovery} /> : null}
      </Section>

      <Section styles={styles} title="Close the room">
        <Text style={styles.small}>Closing stops every lane and ends every member's access. It cannot be undone.</Text>
        {k.closed ? (
          <Text style={styles.small}>This room is closed.</Text>
        ) : view.lineages > 1 ? (
          <>
            <Text style={styles.small}>An admin of another lineage confirms, no earlier than the closing delay after the proposal. With the recovery code, the room closes at once.</Text>
            <View style={styles.row}>
              <Button theme={theme} variant="danger" label="Propose closing" onPress={() => admin.open({ kind: "room.close.propose", roomId }, (t) => propose({ roomId, confirmToken: t }), { onDone: refresh, success: "Closing proposed" })} />
              {k.recoveryKid ? <RecoveryActions view={view} theme={theme} styles={styles} refresh={refresh} onRecovery={onRecovery} initial="close" label="Close with the recovery code…" /> : null}
            </View>
          </>
        ) : k.recoveryKid ? (
          <>
            <Text style={styles.small}>This room has one admin lineage, so it is closed with the recovery code.</Text>
            <RecoveryActions view={view} theme={theme} styles={styles} refresh={refresh} onRecovery={onRecovery} initial="close" label="Close with the recovery code…" />
          </>
        ) : (
          <>
            <Text style={styles.small}>This room has one admin lineage and no recovery key. Create a recovery key to close this room, then close it with the code.</Text>
            <Button
              theme={theme}
              variant="danger"
              label="Create a recovery key to close this room"
              onPress={() =>
                admin.open({ kind: "recovery.create", roomId }, (t) => createRecovery({ roomId, confirmToken: t }), {
                  onDone: (r) => {
                    onRecovery(r.recovery);
                    refresh();
                  },
                })
              }
            />
          </>
        )}
      </Section>
    </View>
  );
}

/** Recovery procedures with the typed recovery code (keys 6.6, 6.8, 4.4): one action per typing. */
function RecoveryActions({
  view,
  theme,
  styles,
  refresh,
  onRecovery,
  initial = "rotate",
  label = "Use the recovery code…",
}: {
  view: OwnedV2;
  theme: PluginTheme;
  styles: Styles;
  refresh(): void;
  onRecovery(o: RecoveryOffer): void;
  initial?: "rotate" | "revoke_admin" | "close";
  label?: string;
}) {
  const act = useRpc(roomsV2RecoveryAct);
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<"rotate" | "revoke_admin" | "close">(initial);
  const [code, setCode] = useState("");
  const [kid, setKid] = useState(view.keys.admins.find((a) => a.kid !== view.keys.adminKid)?.kid ?? view.keys.adminKid ?? "");
  const [fromSeq, setFromSeq] = useState("0");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const word = kind === "close" ? "close" : kind === "revoke_admin" ? "revoke" : "rotate";
  const close = () => {
    if (busy) return;
    setOpen(false);
    setCode("");
    setTyped("");
    setError(null);
  };
  const run = () => {
    setBusy(true);
    setError(null);
    const n = Number.parseInt(fromSeq, 10);
    const action = kind === "revoke_admin" ? { kind, kid, fromSeq: Number.isFinite(n) && n >= 0 ? n : 0 } : { kind };
    void act({ roomId: view.roomId, code, action })
      .then((r) => {
        setOpen(false);
        setCode("");
        setTyped("");
        refresh();
        if (r.recovery) onRecovery(r.recovery);
        toast.show(kind === "close" ? "Room closed" : kind === "rotate" ? "Recovery key replaced" : r.freshAdminKid ? "Admin key revoked; this daemon holds a fresh admin key" : "Admin key revoked", { variant: "success" });
      })
      .catch((e) => setError(errorText(e)))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <Button theme={theme} variant={initial === "close" ? "danger" : "secondary"} label={label} onPress={() => setOpen(true)} />
      {open ? (
        <Modal title="Use the recovery code" open onOpenChange={(o) => (o ? undefined : close())}>
          <Modal.Content>
            <View style={{ gap: 10 }}>
              <Text style={styles.body}>The code is used for this one action and is not stored.</Text>
              <Segmented
                theme={theme}
                value={kind}
                onChange={(v) => {
                  setKind(v);
                  setTyped("");
                }}
                options={[
                  { value: "rotate", label: "Replace the recovery key", hint: "A new code is shown once" },
                  { value: "revoke_admin", label: "Revoke an admin key", hint: "Lost or stolen admin key" },
                  { value: "close", label: "Close the room", hint: "Final" },
                ]}
              />
              {kind === "revoke_admin" ? (
                <View style={{ gap: 6 }}>
                  <View style={styles.row}>
                    {view.keys.admins.map((a) => (
                      <Chip key={a.kid} theme={theme} label={`${shortId(a.kid)}${a.kid === view.keys.adminKid ? " (this daemon)" : ""}`} active={kid === a.kid} onPress={() => setKid(a.kid)} />
                    ))}
                  </View>
                  <Text style={styles.small}>Revoke from log position (statements from there on become suspect):</Text>
                  <TextInput accessibilityLabel="Revoke from seq" value={fromSeq} onChangeText={setFromSeq} keyboardType="number-pad" style={[styles.input, { width: 100 }]} />
                </View>
              ) : null}
              <TextInput
                accessibilityLabel="Recovery code"
                placeholder="prk2-…"
                placeholderTextColor={theme.colors.foregroundMuted}
                value={code}
                onChangeText={setCode}
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
                multiline={false}
                style={styles.input}
              />
              <Text style={styles.small}>Type "{word}" to confirm.</Text>
              <TextInput accessibilityLabel={`Type ${word} to confirm`} value={typed} onChangeText={setTyped} autoCapitalize="none" autoCorrect={false} style={styles.input} />
              {error ? <Text style={styles.danger}>{error}</Text> : null}
              <View style={styles.row}>
                <Button theme={theme} variant="danger" label="Confirm" busy={busy} disabled={typed.trim().toLowerCase() !== word || code.trim().length < 20 || (kind === "revoke_admin" && !kid)} onPress={run} />
                <Button theme={theme} label="Cancel" disabled={busy} onPress={close} />
              </View>
            </View>
          </Modal.Content>
        </Modal>
      ) : null}
    </>
  );
}
