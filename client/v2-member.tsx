// Member side of the v2 Rooms UI (I-14): join with a `prc2.`/`prl2.` code and compare the SAS
// (enrollment 2.3, 6.4), joined rooms with alerts (room-log 4.6, 6.6), the "Was this you?" veto,
// device links with the SAS on the confirming device (identity-model 6.3, 6.4) and the device's own
// rekey. Errors are shown as mapped codes only (memberErrorText), never as host-provided text.
import type { PluginTheme } from "@getpaseo/plugin";
import { useRpc } from "@getpaseo/plugin/client";
import { copyText, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Text, View } from "react-native";
import type { z } from "zod";
import {
  roomsV2DeviceRekey,
  roomsV2DeviceVeto,
  roomsV2JoinCancel,
  roomsV2JoinConfirm,
  roomsV2JoinDismiss,
  roomsV2JoinPreview,
  roomsV2JoinStart,
  roomsV2LinkConfirm,
  roomsV2LinkCreate,
  roomsV2RoomConnect,
  roomsV2RoomDisconnect,
  roomsV2RoomLeave,
  type JoinedRoomV2View,
  type JoiningV2View,
  type MlsV2View,
} from "../shared/rpc-v2";
import { Badge, Button, ConfirmButton, errorText, relativeTime, type Styles } from "./ui";
import { SasDigits, TypedConfirm } from "./v2-dialogs";
import { ActivityListV2, AlertNoticesV2, NameEditorV2 } from "./v2-activity";
import { ChatSectionV2 } from "./v2-chat";
import { STATUS_V2_KEY } from "./v2-owner";
import { memberErrorText, nameWithId, shortId } from "./v2-text";

type Joining = z.infer<typeof JoiningV2View>;
type Joined = z.infer<typeof JoinedRoomV2View>;
type Mls = z.infer<typeof MlsV2View>;
const iso = (ms: number) => new Date(ms).toISOString();

export const LOST_DEVICE_GUIDANCE =
  "If you lose this device, or it is stolen, tell an admin of each room as soon as you can, and at the latest within 3 days. The admin removes the device. That also cancels any device the thief tried to add, or any key change the thief requested for this device, because both wait 3 days when they come from your only device. After that, the admin can let you back in with a new invite.";

export function JoinFormV2({ theme, styles }: { theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const preview = useRpc(roomsV2JoinPreview);
  const start = useRpc(roomsV2JoinStart);
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const [trust, setTrust] = useState(false);
  const p = useMutation({ mutationFn: () => preview({ code: code.trim() }), onError: (e) => toast.error(errorText(e)) });
  const j = useMutation({
    mutationFn: () => start({ code: code.trim(), label: label.trim(), ...(trust ? { trustRelay: true } : {}) }),
    onSuccess: () => {
      setCode("");
      p.reset();
      setTrust(false);
      void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
    },
    onError: (e) => toast.error(errorText(e)),
  });
  const pv = p.data;
  const codeOk = /^(prc2|prl2)\./.test(code.trim());
  return (
    <View style={styles.card}>
      <Text style={styles.body}>Join with an invite or device link code</Text>
      <TextInput
        accessibilityLabel="Invite or link code"
        placeholder="prc2.… or prl2.…"
        placeholderTextColor={theme.colors.foregroundMuted}
        value={code}
        onChangeText={(v) => {
          setCode(v);
          if (p.data) p.reset();
        }}
        autoCapitalize="none"
        autoCorrect={false}
        multiline
        style={[styles.input, { minHeight: 56 }]}
      />
      {code.trim().startsWith("prc1.") ? <Text style={styles.small}>This is an invite from the earlier Rooms version. Ask the owner for a new invite.</Text> : null}
      {!pv ? (
        <View style={styles.row}>
          <Button theme={theme} variant="primary" label="Check code" busy={p.isPending} disabled={!codeOk} onPress={() => p.mutate()} />
          {code.trim() && !codeOk ? <Text style={styles.small}>Paste the whole code (it starts with prc2. or prl2.)</Text> : null}
        </View>
      ) : (
        <View style={{ gap: 8 }}>
          <View style={styles.codeBox}>
            <Text style={styles.body}>Room: {pv.roomName} (unverified until the codes match)</Text>
            <Text style={styles.small}>Room endpoint fingerprint: {pv.endpointFingerprint}</Text>
            <Text style={styles.small}>
              Relay: {pv.relay.host}:{pv.relay.port} {pv.relay.trusted ? "(trusted)" : "(not trusted yet)"} · code expires {relativeTime(iso(pv.exp * 1000))}
            </Text>
          </View>
          {!pv.relay.trusted ? (
            <View style={styles.row}>
              <Button theme={theme} label={trust ? "Relay trusted for this join" : "Trust this relay"} variant={trust ? "primary" : "secondary"} onPress={() => setTrust((v) => !v)} />
              <Text style={[styles.small, { flexShrink: 1 }]}>The relay carries encrypted room traffic. Trust it only if the owner told you to use it.</Text>
            </View>
          ) : null}
          <TextInput
            accessibilityLabel="Name for this device in the room"
            placeholder="Your name and device, e.g. Sam laptop"
            placeholderTextColor={theme.colors.foregroundMuted}
            value={label}
            onChangeText={setLabel}
            maxLength={80}
            style={styles.input}
          />
          <View style={styles.row}>
            <Button theme={theme} variant="primary" label="Join" busy={j.isPending} disabled={!label.trim() || (!pv.relay.trusted && !trust)} onPress={() => j.mutate()} />
            <Button theme={theme} label="Back" onPress={() => p.reset()} />
          </View>
        </View>
      )}
    </View>
  );
}

/** Enrollment 6.4 on the member's device (and on a new linked device, which reads the code from its other device). */
export function JoiningCardV2({ view, theme, styles }: { view: Joining; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useRpc(roomsV2JoinConfirm);
  const cancel = useRpc(roomsV2JoinCancel);
  const dismiss = useRpc(roomsV2JoinDismiss);
  const refresh = () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
  const fail = (e: unknown) => toast.error(errorText(e));
  const roomId = view.roomId;
  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <Text style={styles.h2}>{view.roomName}</Text>
        <Badge theme={theme} label={view.state} tone={view.state === "failed" ? "danger" : view.state === "registered" || view.state === "admitted" ? "ok" : "warn"} />
      </View>
      {view.state === "pending" ? (
        <>
          <Text style={styles.body}>Read this code to the room owner by voice or in person:</Text>
          <SasDigits theme={theme} sas={view.sas} />
          {view.ownerFingerprints.length ? (
            <View style={styles.codeBox}>
              <Text style={styles.small}>Owner fingerprint{view.ownerFingerprints.length > 1 ? "s (admin keys)" : " (admin key)"} (unverified until the codes match):</Text>
              {view.ownerFingerprints.slice(0, 3).map((f) => (
                <Text key={f} selectable style={styles.mono}>
                  {f}
                </Text>
              ))}
              {view.ownerFingerprints.length > 3 ? <Text style={styles.small}>and {view.ownerFingerprints.length - 3} more admin key(s).</Text> : null}
              <Text style={styles.small}>If the owner reads you the owner fingerprint shown on their room card, compare it too.</Text>
            </View>
          ) : null}
          {view.terms ? (
            <Text style={styles.small}>
              Role {view.terms.role}, {view.terms.lanes.length} lane(s), room "{view.roomName}" (unverified until the codes match).
            </Text>
          ) : null}
          <Text style={styles.small}>Press "Codes match" only after you heard the same six digits. For a device link, compare with the code on your other device.</Text>
          {view.expiresAt ? <Text style={styles.small}>Expires {relativeTime(iso(view.expiresAt))}.</Text> : null}
          <View style={styles.row}>
            <Button theme={theme} variant="primary" label="Codes match" disabled={!view.sas} onPress={() => void confirm({ roomId, match: true }).then(refresh, fail)} />
            <ConfirmButton
              theme={theme}
              label="Codes do not match"
              confirmLabel="They do not match"
              message="The join stops and the invite cannot be used again. Tell the owner by another channel."
              onConfirm={() => confirm({ roomId, match: false }).then(refresh, fail)}
            />
            <Button theme={theme} label="Cancel" onPress={() => void cancel({ roomId }).then(refresh, fail)} />
          </View>
        </>
      ) : view.state === "confirmed" ? (
        <Text style={styles.body}>Waiting for the owner to admit you…</Text>
      ) : view.state === "held" ? (
        <Text style={styles.body}>Your other device confirmed. This device joins after the waiting period unless one of your devices says "Not me", or when an admin approves it.</Text>
      ) : view.state === "keys" ? (
        <Text style={styles.small}>Connecting to the room…</Text>
      ) : view.state === "admitted" || view.state === "registered" ? (
        <Text style={styles.small}>Admitted. The room appears under "Rooms you joined".</Text>
      ) : null}
      {view.state === "failed" ? (
        <>
          <Text style={styles.body}>{view.failure ? (memberErrorText(view.failure) ?? "The join did not complete.") : "The join did not complete."}</Text>
          <Button theme={theme} label="Dismiss" onPress={() => void dismiss({ roomId }).then(refresh, fail)} />
        </>
      ) : null}
      {view.connection === "retrying" ? <Text style={styles.small}>Connection lost; retrying. {memberErrorText(view.lastError) ?? ""}</Text> : null}
    </View>
  );
}

export function JoinedCardV2({ view, mls, theme, styles }: { view: Joined; mls: Mls | undefined; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const connect = useRpc(roomsV2RoomConnect);
  const disconnect = useRpc(roomsV2RoomDisconnect);
  const veto = useRpc(roomsV2DeviceVeto);
  const rekey = useRpc(roomsV2DeviceRekey);
  const linkCreate = useRpc(roomsV2LinkCreate);
  const linkConfirm = useRpc(roomsV2LinkConfirm);
  const leave = useRpc(roomsV2RoomLeave);
  const [linkCode, setLinkCode] = useState<{ code: string; exp: number } | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
  const fail = (e: unknown) => toast.error(errorText(e));
  const roomId = view.roomId;
  const c = theme.colors;
  const alerts = [...view.alerts, ...(mls?.alerts ?? [])];
  const [showActivity, setShowActivity] = useState(false);
  const nameOf = new Map(view.names.map((n) => [n.memberId, n]));
  // R3.3: a name is untrusted text; the short member id always follows it, and look-alikes are flagged.
  const who = (memberId: string | undefined) => {
    if (!memberId) return "Someone";
    if (memberId === view.memberId) return "You";
    const n = nameOf.get(memberId);
    return `${nameWithId(n?.name, memberId)}${n?.collision ? " [same name as another member]" : ""}`;
  };
  const others = view.names.filter((n) => n.memberId !== view.memberId);
  const myRequests = view.deviceRequests.filter((d) => d.status === "pending");
  const ended = view.status === "ended";
  const statusLabel = ended ? (view.endedReason === "removed" ? "Removed" : view.endedReason === "room_closed" ? "Room closed" : "Ended") : view.status === "open" ? "Connected" : view.status === "connecting" ? "Connecting" : "Not connected";
  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <View style={{ flexShrink: 1, gap: 2 }}>
          <Text style={styles.h2}>{view.roomName ? `${view.roomName} (${shortId(roomId)})` : `Room ${shortId(roomId)}`}</Text>
          {view.roomDescription ? <Text style={styles.small}>{view.roomDescription}</Text> : null}
          <Text style={styles.small}>
            You are member {shortId(view.memberId)} · this device {shortId(view.deviceId)} · log at seq {view.head.seq}
          </Text>
        </View>
        <Badge theme={theme} label={statusLabel} tone={view.status === "open" ? "ok" : ended ? "muted" : "warn"} />
      </View>

      <AlertNoticesV2 roomId={roomId} alerts={alerts} sendingStopped={view.sendingStopped} theme={theme} styles={styles} />
      {view.conflict ? (
        <View style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: c.statusDanger }]}>
          <Text style={styles.body}>Your devices disagree about a new device. Automatic device approvals are paused until an admin resolves it. Tell an admin which devices are yours.</Text>
        </View>
      ) : null}
      {myRequests.map((d) => (
        <View key={d.ref} style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: c.statusWarning, gap: 6 }]}>
          <Text style={styles.body}>
            {d.kind === "add"
              ? `A new device (${shortId(d.deviceId)}) will join your membership in this room ${d.effectiveAfter ? `at ${new Date(d.effectiveAfter).toLocaleString()}` : "when an admin approves it"}. Was this you?`
              : `Device ${shortId(d.deviceId)} of yours is changing its keys${d.effectiveAfter ? `, effective ${new Date(d.effectiveAfter).toLocaleString()}` : ""}. Was this you?`}
          </Text>
          {d.sole ? <Text style={styles.small}>The request comes from your only device in this room.</Text> : null}
          <ConfirmButton
            theme={theme}
            label="Not me"
            confirmLabel="Stop it: not me"
            message="The request is cancelled and the room's admins are told your devices disagree. No device is removed; an admin decides."
            onConfirm={() =>
              veto({ roomId, ref: d.ref })
                .then(() => toast.show("Stopped. The admins were told.", { variant: "success" }))
                .then(refresh, fail)
            }
          />
        </View>
      ))}

      {view.lanes.map((l) => (
        <View key={l.laneId} style={styles.between}>
          <View style={{ flexShrink: 1, gap: 2 }}>
            <Text style={styles.body}>Lane {shortId(l.laneId)}</Text>
            <Text style={styles.small}>
              {l.hostStatus ?? "not registered"}
              {l.lastError ? ` · ${memberErrorText(l.lastError)}` : ""}
            </Text>
          </View>
          <Badge theme={theme} label={l.hostStatus === "online" ? "Online" : (l.hostStatus ?? "Waiting")} tone={l.hostStatus === "online" ? "ok" : "warn"} />
        </View>
      ))}
      {view.lanes.length ? <Text style={styles.small}>Each lane appears as a host under this daemon. It is read-only.</Text> : null}
      {view.lastError && !ended ? <Text style={styles.small}>{memberErrorText(view.lastError)}</Text> : null}
      {ended ? <Text style={styles.small}>This room no longer gives this device access. Rooms removes its lane hosts from this daemon's host list.</Text> : null}

      {!ended ? (
        <View style={styles.row}>
          {view.status === "open" ? (
            <Button theme={theme} label="Disconnect" onPress={() => void disconnect({ roomId }).then(refresh, fail)} />
          ) : (
            <Button theme={theme} label="Reconnect" onPress={() => void connect({ roomId }).then(refresh, fail)} />
          )}
          <Button
            theme={theme}
            label="Link another device"
            disabled={view.status !== "open"}
            onPress={() =>
              void linkCreate({ roomId })
                .then((r) => setLinkCode({ code: r.code, exp: r.exp }))
                .then(refresh, fail)
            }
          />
          {!view.rekey ? (
            <ConfirmButton
              theme={theme}
              variant="secondary"
              label="Replace this device's keys"
              confirmLabel="Request new keys"
              message="This device asks for new keys. Your other devices can say 'Not me'. The change waits 24 hours (72 hours if this is your only device) unless an admin approves it sooner."
              onConfirm={() =>
                rekey({ roomId })
                  .then(() => toast.show("Key change requested", { variant: "success" }))
                  .then(refresh, fail)
              }
            />
          ) : null}
        </View>
      ) : null}
      {view.rekey ? (
        <Text style={styles.small}>
          Key change requested {relativeTime(iso(view.rekey.requestedAt))}
          {view.rekey.published ? "; waiting for approval." : "; preparing."}
        </Text>
      ) : null}

      {linkCode ? (
        <View style={[styles.codeBox, { gap: 6 }]}>
          <Text style={styles.small}>Device link code, valid {relativeTime(iso(linkCode.exp * 1000))}. Use it on your new device only. It is shown only now.</Text>
          <Text selectable numberOfLines={3} style={styles.mono}>
            {linkCode.code}
          </Text>
          <View style={styles.row}>
            <Button theme={theme} variant="primary" label="Copy code" onPress={() => void copyText(linkCode.code).then(() => toast.show("Link code copied", { variant: "success" }), () => toast.error("Copy failed"))} />
            <Button theme={theme} label="Hide" onPress={() => setLinkCode(null)} />
          </View>
        </View>
      ) : null}
      {view.links.map((l) =>
        l.burned ? (
          <Text key={l.linkId} style={[styles.small, { color: c.statusWarning }]}>
            A device link was stopped ({l.burned === "sas_mismatch" ? "codes did not match" : "too many attempts"}). Create a new one if you still want to link a device.
          </Text>
        ) : l.pending && (l.pending.state === "open" || l.pending.state === "revealed") ? (
          <View key={l.linkId} style={[styles.codeBox, { gap: 6 }]}>
            <Text style={styles.body}>Linking "{l.pending.label}" (self-reported). Compare this code with the one on your new device:</Text>
            <SasDigits theme={theme} sas={l.pending.sas} />
            {l.pending.earlierAttempts > 0 ? (
              <Text style={[styles.small, { color: c.statusWarning }]}>{l.pending.earlierAttempts} earlier attempt(s) used this link. If you did not start them, press "Codes do not match".</Text>
            ) : null}
            <View style={styles.row}>
              <Button theme={theme} variant="primary" label="Codes match" disabled={!l.pending.sas} onPress={() => void linkConfirm({ roomId, pendingId: l.pending!.pendingId, match: true }).then(refresh, fail)} />
              <ConfirmButton
                theme={theme}
                label="Codes do not match"
                confirmLabel="Stop the link"
                message="The link stops and cannot be used again."
                onConfirm={() => linkConfirm({ roomId, pendingId: l.pending!.pendingId, match: false }).then(refresh, fail)}
              />
            </View>
          </View>
        ) : l.pending?.state === "confirmed" ? (
          <Text key={l.linkId} style={styles.small}>
            "{l.pending.label}" is confirmed and waits for the hold or an admin.
          </Text>
        ) : null,
      )}
      {!ended ? <NameEditorV2 roomId={roomId} kind="member" current={nameOf.get(view.memberId)?.name ?? null} theme={theme} styles={styles} /> : null}
      {others.length ? (
        <Text style={styles.small}>
          Members: {others.map((n) => who(n.memberId)).join(", ")}
        </Text>
      ) : null}
      {mls ? <ChatSectionV2 roomId={roomId} unread={mls.unread ?? 0} theme={theme} styles={styles} /> : null}
      <Button theme={theme} label={showActivity ? "Hide activity" : `Activity (${view.activity.length})`} onPress={() => setShowActivity((v) => !v)} />
      {showActivity ? <ActivityListV2 items={view.activity} who={who} theme={theme} styles={styles} /> : null}
      <Text style={styles.small}>{LOST_DEVICE_GUIDANCE}</Text>
      {view.hosted ? null : (
        <LeaveRoom
          theme={theme}
          styles={styles}
          ended={ended}
          devices={view.memberDevices ?? null}
          lanes={view.lanes.length}
          onConfirm={() =>
            leave({ roomId, confirm: "leave" }).then((r) => {
              toast.show(r.statement === "member.left" ? "You left the room" : r.statement === "device.removed" ? "This device left the room" : "Room removed from this device", { variant: "success" });
              if (r.hostsRemaining.length) toast.error(`${r.hostsRemaining.length} lane host(s) could not be removed yet. Rooms retries; see the notice at the top.`);
              refresh();
            })
          }
        />
      )}
    </View>
  );
}

/**
 * R3.1: Leave, with a typed confirmation. The text depends on how many active devices the member has
 * in the room: the only device signs `member.left`; one of several leaves alone (`device.removed`).
 */
function LeaveRoom(props: { theme: PluginTheme; styles: Styles; ended: boolean; devices: number | null; lanes: number; onConfirm(): Promise<unknown> }) {
  const { theme, styles, ended, devices, lanes } = props;
  const others = devices !== null && devices > 1 ? devices - 1 : 0;
  return (
    <View style={styles.row}>
      <TypedConfirm
        theme={theme}
        styles={styles}
        variant={ended ? "secondary" : "danger"}
        label={ended ? "Remove from this device" : others ? "Leave on this device" : "Leave room"}
        title={ended ? "Remove this room from this device" : others ? "Leave the room on this device" : "Leave the room"}
        word="leave"
        onConfirm={props.onConfirm}
      >
        {ended ? (
          <Text style={styles.body}>This device no longer has access. Its keys and saved copy of this room are deleted here.</Text>
        ) : others ? (
          <Text style={styles.body}>
            Only this device leaves. Your other {others} device(s) stay in the room. To leave the room entirely, leave on each device. The room log records that this device left.
          </Text>
        ) : (
          <Text style={styles.body}>You leave the room. Every member sees that you left. To come back you need a new invite.</Text>
        )}
        {!ended ? <Text style={styles.body}>{lanes ? `${lanes} lane host(s) are removed from this daemon's host list. ` : ""}This device's keys and saved copy of the room are deleted.</Text> : null}
      </TypedConfirm>
    </View>
  );
}
