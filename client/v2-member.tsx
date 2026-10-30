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
  type JoinedRoomV2View,
  type JoiningV2View,
  type MlsV2View,
} from "../shared/rpc-v2";
import { Badge, Button, ConfirmButton, errorText, relativeTime, type Styles } from "./ui";
import { SasDigits } from "./v2-dialogs";
import { STATUS_V2_KEY } from "./v2-owner";
import { alertText, memberErrorText, shortId } from "./v2-text";

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
  const [linkCode, setLinkCode] = useState<{ code: string; exp: number } | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
  const fail = (e: unknown) => toast.error(errorText(e));
  const roomId = view.roomId;
  const c = theme.colors;
  const alerts = [...view.alerts, ...(mls?.alerts ?? [])];
  const seen = new Set<string>();
  const uniqueAlerts = alerts.filter((a) => (seen.has(a.type) ? false : (seen.add(a.type), true)));
  const myRequests = view.deviceRequests.filter((d) => d.status === "pending");
  const ended = view.status === "ended";
  const statusLabel = ended ? (view.endedReason === "removed" ? "Removed" : view.endedReason === "room_closed" ? "Room closed" : "Ended") : view.status === "open" ? "Connected" : view.status === "connecting" ? "Connecting" : "Not connected";
  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <View style={{ flexShrink: 1, gap: 2 }}>
          <Text style={styles.h2}>Room {shortId(roomId)}</Text>
          <Text style={styles.small}>
            You are member {shortId(view.memberId)} · this device {shortId(view.deviceId)} · log at seq {view.head.seq}
          </Text>
        </View>
        <Badge theme={theme} label={statusLabel} tone={view.status === "open" ? "ok" : ended ? "muted" : "warn"} />
      </View>

      {uniqueAlerts.map((a) => {
        const t = alertText(a.type);
        return (
          <View key={a.type} style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: t.tone === "danger" ? c.statusDanger : t.tone === "warn" ? c.statusWarning : c.border }]}>
            <Text style={styles.body}>{t.text}</Text>
            <Text style={styles.small}>At log position {a.seq}.</Text>
          </View>
        );
      })}
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
      {ended ? <Text style={styles.small}>This room no longer gives this device access. A lane host entry may stay in your app's host list until you remove it.</Text> : null}

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
      <Text style={styles.small}>{LOST_DEVICE_GUIDANCE}</Text>
      <Text style={styles.small}>Leaving a room is not available in this build yet; ask an admin to remove you.</Text>
    </View>
  );
}
