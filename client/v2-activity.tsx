// Room names, alerts and activity in the v2 Rooms UI (usability roadmap R3.3, R3.5). Shared by the
// owner's and the member's room cards. Names are untrusted text: always shown with a short member id
// (nameWithId), and a name that looks like another member's is flagged. Activity items come from this
// device's verified fold; the texts are built here from ids and types (activityText).
import type { PluginTheme } from "@getpaseo/plugin";
import { useRpc } from "@getpaseo/plugin/client";
import { TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Text, View } from "react-native";
import type { z } from "zod";
import { roomsV2AlertsAck, roomsV2MemberProfileSet, roomsV2RoomProfileSet, type ActivityV2Item } from "../shared/rpc-v2";
import { Button, errorText, relativeTime, type Styles } from "./ui";
import { STATUS_V2_KEY } from "./v2-owner";
import { activityText, alertText } from "./v2-text";

type Activity = z.infer<typeof ActivityV2Item>;
const iso = (ms: number) => new Date(ms).toISOString();

/** Newest first; five shown until "Show all". */
export function ActivityListV2({ items, who, theme, styles }: { items: Activity[]; who(memberId: string | undefined): string; theme: PluginTheme; styles: Styles }) {
  const [all, setAll] = useState(false);
  if (items.length === 0) return <Text style={styles.small}>No activity yet on this device.</Text>;
  const c = theme.colors;
  const shown = all ? items : items.slice(0, 5);
  return (
    <View style={{ gap: 4 }}>
      {shown.map((a, i) => {
        const t = activityText(a, who);
        const color = t.tone === "danger" ? c.statusDanger : t.tone === "warn" ? c.statusWarning : t.tone === "ok" ? c.statusSuccess : c.border;
        return (
          <View key={`${a.seq}-${a.type}-${i}`} style={{ borderLeftWidth: 3, borderLeftColor: color, paddingLeft: 8, gap: 1 }}>
            <Text style={styles.body}>
              {a.alert ? "Alert: " : ""}
              {t.text}
            </Text>
            <Text style={styles.small}>
              {relativeTime(iso(a.hts))} · log position {a.seq}
            </Text>
          </View>
        );
      })}
      {items.length > 5 ? <Button theme={theme} label={all ? "Show fewer" : `Show all (${items.length})`} onPress={() => setAll((v) => !v)} /> : null}
      <Text style={styles.small}>Derived from the room history this device verified. Times are the host's.</Text>
    </View>
  );
}

/**
 * Alerts not yet acknowledged, one notice per type, with "Acknowledge" (R3.5). Acknowledging hides the
 * notice on this device; it does not resume sending where an alert stopped it.
 */
export function AlertNoticesV2({ roomId, alerts, sendingStopped, theme, styles }: { roomId: string; alerts: { type: string; seq: number; acked: boolean }[]; sendingStopped: boolean; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const ack = useRpc(roomsV2AlertsAck);
  const c = theme.colors;
  const open = alerts.filter((a) => !a.acked);
  const byType = new Map<string, { type: string; seq: number }[]>();
  for (const a of open) byType.set(a.type, [...(byType.get(a.type) ?? []), { type: a.type, seq: a.seq }]);
  const stoppedAcked = sendingStopped && !open.some((a) => alertText(a.type).stopsSending);
  return (
    <>
      {[...byType.entries()].map(([type, list]) => {
        const t = alertText(type);
        return (
          <View key={type} style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: t.tone === "danger" ? c.statusDanger : t.tone === "warn" ? c.statusWarning : c.border, gap: 6 }]}>
            <Text style={styles.body}>{t.text}</Text>
            <Text style={styles.small}>
              At log position {list.map((x) => x.seq).join(", ")}. The evidence is kept on this device.
              {t.stopsSending ? " Acknowledging hides this notice; sending stays stopped in this room." : ""}
            </Text>
            <View style={styles.row}>
              <Button
                theme={theme}
                label="Acknowledge"
                onPress={() =>
                  void ack({ roomId, alerts: list.slice(0, 64) })
                    .then(() => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY }))
                    .catch((e) => toast.error(errorText(e)))
                }
              />
            </View>
          </View>
        );
      })}
      {stoppedAcked ? <Text style={[styles.small, { color: c.statusWarning }]}>Sending is stopped in this room because of an acknowledged alert (see Activity). Ask an admin what to do.</Text> : null}
    </>
  );
}

/** Room name (admins) or this member's display name, sent inside the room group (the host never sees it). */
export function NameEditorV2({ roomId, kind, current, theme, styles }: { roomId: string; kind: "room" | "member"; current: string | null; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const setRoom = useRpc(roomsV2RoomProfileSet);
  const setMember = useRpc(roomsV2MemberProfileSet);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const max = kind === "room" ? 64 : 48;
  const label = kind === "room" ? "Room name" : "Your display name in this room";
  if (!editing) {
    return (
      <View style={styles.row}>
        <Text style={[styles.small, { flexShrink: 1 }]}>
          {label}: {current ?? "not set"}
        </Text>
        <Button
          theme={theme}
          label={current ? "Change" : "Set"}
          onPress={() => {
            setValue(current ?? "");
            setEditing(true);
          }}
        />
      </View>
    );
  }
  const save = () => {
    setBusy(true);
    const p = kind === "room" ? setRoom({ roomId, name: value.trim() }) : setMember({ roomId, displayName: value.trim() });
    void p
      .then(() => {
        setEditing(false);
        toast.show(kind === "room" ? "Room name sent to the room" : "Display name sent to the room", { variant: "success" });
        void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
      })
      .catch((e) => toast.error(errorText(e)))
      .finally(() => setBusy(false));
  };
  return (
    <View style={{ gap: 6 }}>
      <TextInput accessibilityLabel={label} placeholder={label} placeholderTextColor={theme.colors.foregroundMuted} value={value} onChangeText={setValue} maxLength={max} style={styles.input} />
      <Text style={styles.small}>
        {kind === "room" ? "Every member sees this name." : "Members see this name next to your member id."} It travels encrypted inside the room group; the host does not see it. Names are not checked: anyone can pick any name, so the id next to it is what identifies a person.
      </Text>
      <View style={styles.row}>
        <Button theme={theme} variant="primary" label="Save" busy={busy} disabled={!value.trim()} onPress={save} />
        <Button theme={theme} label="Cancel" onPress={() => setEditing(false)} />
      </View>
    </View>
  );
}
