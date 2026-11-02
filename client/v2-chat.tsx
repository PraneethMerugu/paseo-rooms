// Room chat in the v2 Rooms UI (usability roadmap R3.4, product M2). Shared by the owner's and the
// member's room cards. Messages come from this device's sealed chat store; each was signed by the
// sending device and checked against the leaf it decrypted from (mls-integration 5.2).
//
// Text is untrusted: rendered as plain React Native <Text>, never as markup. Only http and https
// links are recognised; opening one needs a second tap that shows the full address first. Names are
// untrusted too: the short member id always follows a name (nameWithId).
import type { PluginTheme } from "@getpaseo/plugin";
import { openExternalUrl, useRpc } from "@getpaseo/plugin/client";
import { TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Text, View } from "react-native";
import { roomsV2ChatList, roomsV2ChatRead, roomsV2ChatSend } from "../shared/rpc-v2";
import { Button, errorText, relativeTime, type Styles } from "./ui";
import { STATUS_V2_KEY } from "./v2-owner";
import { nameWithId, shortId } from "./v2-text";

export const CHAT_KEY = (roomId: string) => ["rooms", "v2", "chat", roomId] as const;
const TEXT_MAX = 4000;
/** The sender's clock is shown when it differs from the host's time by more than this. */
const CLOCK_NOTE_MS = 5 * 60_000;

/** Splits plain text into text and http(s) link parts. Anything else stays text. */
export function linkParts(text: string): { text: string; url: string | null }[] {
  const out: { text: string; url: string | null }[] = [];
  const re = /https?:\/\/[^\s<>"'`]+/gi;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const at = m.index ?? 0;
    // Trailing punctuation usually ends the sentence, not the address.
    const raw = m[0].replace(/[).,;:!?\]}]+$/, "");
    // Scheme http or https, a host of letters, digits, dots and hyphens (an optional port), no
    // credentials (`user@host` misleads about the destination), printable ASCII only.
    const url = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?([/?#][\x21-\x7e]*)?$/i.test(raw) ? raw : null;
    if (at > last) out.push({ text: text.slice(last, at), url: null });
    out.push({ text: raw, url });
    last = at + raw.length;
  }
  if (last < text.length) out.push({ text: text.slice(last), url: null });
  return out;
}

const cannotSendText = (why: string | null): string | null => {
  switch (why) {
    case null:
      return null;
    case "ended":
      return "This device no longer has access to the room.";
    case "no_group":
      return "This device is not in the room's encrypted group yet. Messages can be sent once it has joined.";
    case "unconfirmed":
      return "Waiting for another member's device to confirm this device's group state.";
    case "blocked":
    case "fork":
    case "truncation":
    case "invalid_entry":
      return "Sending is stopped in this room because of a security alert.";
    case "epoch_fork":
      return "Sending is stopped: this device's view of the room group split from other members'.";
    case "stalled":
      return "The room group is paused after a failed security check.";
    default:
      return "This device cannot send in this room right now.";
  }
};

/** The "Chat" toggle with the unread count, and the chat view when open. */
export function ChatSectionV2({ roomId, unread, theme, styles }: { roomId: string; unread: number; theme: PluginTheme; styles: Styles }) {
  const [open, setOpen] = useState(false);
  return (
    <View style={{ gap: 6 }}>
      <Button theme={theme} label={open ? "Hide chat" : unread > 0 ? `Chat (${unread} new)` : "Chat"} onPress={() => setOpen((v) => !v)} />
      {open ? <ChatViewV2 roomId={roomId} theme={theme} styles={styles} /> : null}
    </View>
  );
}

export function ChatViewV2({ roomId, theme, styles }: { roomId: string; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const list = useRpc(roomsV2ChatList);
  const send = useRpc(roomsV2ChatSend);
  const read = useRpc(roomsV2ChatRead);
  const [older, setOlder] = useState<Awaited<ReturnType<typeof list>>["messages"]>([]);
  const [olderMore, setOlderMore] = useState<boolean | null>(null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingLink, setPendingLink] = useState<string | null>(null);
  const q = useQuery({ queryKey: CHAT_KEY(roomId), queryFn: () => list({ roomId, limit: 50 }), refetchInterval: 3000 });
  const d = q.data;
  const c = theme.colors;
  const newest = d?.messages.length ? d.messages[d.messages.length - 1].seq : -1;
  // Viewing the chat marks what is shown as read on this device.
  useEffect(() => {
    if (!d || d.unread === 0 || newest < 0) return;
    void read({ roomId, seq: newest })
      .then(() => {
        void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
        void qc.invalidateQueries({ queryKey: CHAT_KEY(roomId) });
      })
      .catch(() => undefined);
  }, [roomId, newest, d?.unread]);
  const nameOf = new Map((d?.names ?? []).map((n) => [n.memberId, n]));
  const who = (memberId: string, own: boolean) => {
    if (own || memberId === d?.selfMemberId) return "You";
    const n = nameOf.get(memberId);
    return `${nameWithId(n?.name, memberId)}${n?.collision ? " [same name as another member]" : ""}`;
  };
  const shown = [...older.filter((o) => !d?.messages.some((m) => m.seq === o.seq)), ...(d?.messages ?? [])];
  const more = olderMore ?? d?.more ?? false;
  const loadOlder = () => {
    const first = shown[0]?.seq;
    if (first === undefined) return;
    void list({ roomId, before: first, limit: 50 })
      .then((r) => {
        setOlder((prev) => [...r.messages, ...prev]);
        setOlderMore(r.more);
      })
      .catch((e) => toast.error(errorText(e)));
  };
  const submit = () => {
    const text = draft.trim();
    if (!text) return;
    setBusy(true);
    void send({ roomId, text })
      .then(() => {
        setDraft("");
        void qc.invalidateQueries({ queryKey: CHAT_KEY(roomId) });
      })
      .catch((e) => toast.error(errorText(e)))
      .finally(() => setBusy(false));
  };
  const blocked = cannotSendText(d?.cannotSend ?? null);
  return (
    <View style={[styles.codeBox, { gap: 8 }]}>
      {q.isError ? <Text style={styles.danger}>Could not load the chat: {errorText(q.error)}</Text> : null}
      {more ? <Button theme={theme} label="Show older messages" onPress={loadOlder} /> : null}
      {d && shown.length === 0 ? <Text style={styles.small}>No messages yet. Messages are end-to-end encrypted for the room's members; the host cannot read them.</Text> : null}
      {shown.map((m) => {
        const late = Math.abs(m.ts - m.hts) > CLOCK_NOTE_MS;
        return (
          <View key={m.seq} style={{ borderLeftWidth: 3, borderLeftColor: m.own ? c.border : m.current ? c.statusSuccess : c.statusWarning, paddingLeft: 8, gap: 2 }}>
            <Text style={styles.small}>
              {who(m.memberId, m.own)} · device {shortId(m.deviceId)} · {relativeTime(new Date(m.hts).toISOString())}
              {late ? ` (sender's clock: ${new Date(m.ts).toLocaleString()})` : ""}
              {m.own ? "" : m.current ? " · signed by this device, verified" : " · verified; this device has since left the room"}
            </Text>
            <Text style={styles.body} selectable>
              {linkParts(m.text).map((p, i) =>
                p.url ? (
                  <Text key={i} style={{ color: c.accent, textDecorationLine: "underline" }} accessibilityRole="link" onPress={() => setPendingLink(p.url)}>
                    {p.text}
                  </Text>
                ) : (
                  <Text key={i}>{p.text}</Text>
                ),
              )}
            </Text>
          </View>
        );
      })}
      {pendingLink ? (
        <View style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: c.statusWarning, gap: 6 }]}>
          <Text style={styles.body}>Open this address from a chat message? Check it first: anyone in the room can post a link.</Text>
          <Text style={styles.mono} selectable>
            {pendingLink}
          </Text>
          <View style={styles.row}>
            <Button
              theme={theme}
              variant="primary"
              label="Open"
              onPress={() => {
                const url = pendingLink;
                setPendingLink(null);
                void openExternalUrl(url).catch((e) => toast.error(errorText(e)));
              }}
            />
            <Button theme={theme} label="Cancel" onPress={() => setPendingLink(null)} />
          </View>
        </View>
      ) : null}
      {blocked ? <Text style={[styles.small, { color: c.statusWarning }]}>{blocked}</Text> : null}
      <TextInput
        accessibilityLabel="Message"
        placeholder="Message the room"
        placeholderTextColor={c.foregroundMuted}
        value={draft}
        onChangeText={setDraft}
        maxLength={TEXT_MAX}
        multiline
        editable={!blocked}
        style={[styles.input, { minHeight: 40 }]}
      />
      <View style={styles.row}>
        <Button theme={theme} variant="primary" label="Send" busy={busy} disabled={!draft.trim() || !!blocked} onPress={submit} />
        <Text style={styles.small}>Plain text. Encrypted for the room's current members only.</Text>
      </View>
    </View>
  );
}
