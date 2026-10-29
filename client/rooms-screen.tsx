// Rooms screen: rooms you own (lanes, members, invites, revoke) and rooms you joined (join by code).
import type { PluginTheme } from "@getpaseo/plugin";
import type { PluginScreenProps } from "@getpaseo/plugin/client";
import { useRpc } from "@getpaseo/plugin/client";
import { copyText, ScrollView, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Text, View } from "react-native";
import {
  roomsInviteCreate,
  roomsInviteRevoke,
  roomsJoin,
  roomsLaneClose,
  roomsLaneErrors,
  roomsLeave,
  roomsMemberRevoke,
  roomsOverview,
  roomsRotate,
  roomsSettingsSet,
  type JoinedRoomView,
  type OwnedRoomView,
} from "../shared/rpc";
import { Badge, Button, commandCenterHint, ConfirmButton, errorText, relativeTime, Section, useStyles, type Styles } from "./ui";

export const OVERVIEW_KEY = ["rooms", "overview"] as const;

export function RoomsScreen({ theme, layout, navigation }: PluginScreenProps) {
  const styles = useStyles(theme, layout.compact);
  const overview = useRpc(roomsOverview);
  const q = useQuery({ queryKey: OVERVIEW_KEY, queryFn: () => overview({}), refetchInterval: 5000 });
  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <View style={{ gap: 4 }}>
        <Text accessibilityRole="header" style={styles.h1}>
          Rooms
        </Text>
        <Text style={styles.muted}>Share a live or forked agent read-only with people who run Paseo. Members see it as a host under their own daemon.</Text>
      </View>
      {q.isError ? <Text style={styles.danger}>Could not load rooms: {errorText(q.error)}</Text> : null}
      <Section styles={styles} title="Rooms you own">
        {q.data && q.data.owned.length === 0 ? (
          <Text style={styles.muted}>No rooms yet. Open an agent, {commandCenterHint(layout.compact)} and choose "Open room…".</Text>
        ) : null}
        {q.data?.owned.map((r) => (
          <OwnedRoomCard key={r.room.id} view={r} theme={theme} styles={styles} openAgent={(agentId) => navigation?.openAgent({ agentId })} />
        ))}
      </Section>
      <Section styles={styles} title="Rooms you joined">
        <JoinForm theme={theme} styles={styles} />
        {q.data?.joined.map((j) => <JoinedRoomCard key={j.laneId} view={j} theme={theme} styles={styles} />)}
      </Section>
    </ScrollView>
  );
}

function OwnedRoomCard({ view, theme, styles, openAgent }: { view: OwnedRoomView; theme: PluginTheme; styles: Styles; openAgent(agentId: string): void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const createInvite = useRpc(roomsInviteCreate);
  const revokeInvite = useRpc(roomsInviteRevoke);
  const revokeMember = useRpc(roomsMemberRevoke);
  const closeLane = useRpc(roomsLaneClose);
  const [invite, setInvite] = useState<{ code: string; expiresAt: string; laneId: string } | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW_KEY });
  const inviteM = useMutation({
    mutationFn: (laneId: string) => createInvite({ laneId }),
    onSuccess: (r, laneId) => {
      setInvite({ code: r.code, expiresAt: r.expiresAt, laneId });
      void refresh();
    },
    onError: (e) => toast.error(errorText(e)),
  });
  const revokeM = useMutation({
    mutationFn: (memberId: string) => revokeMember({ memberId }),
    onSuccess: (r) => {
      toast.show(r.cutLinks ? `Revoked. Cut ${r.cutLinks} live link(s).` : "Revoked.", { variant: "success" });
      void refresh();
    },
    onError: (e) => toast.error(errorText(e)),
  });
  const actives = view.members.filter((m) => m.status === "active");
  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <Text style={styles.h2}>{view.room.name}</Text>
        <Badge
          theme={theme}
          label={actives.length ? `${actives.filter((m) => m.connected).length} of ${actives.length} connected` : "No members yet"}
          tone={actives.some((m) => m.connected) ? "ok" : "muted"}
        />
      </View>
      {view.lanes.map((l) => (
        <View key={l.lane.id} style={{ gap: 6 }}>
          <View style={styles.between}>
            <View style={{ flexShrink: 1, gap: 2 }}>
              <Text style={styles.body}>
                {l.lane.label} · {l.lane.origin.kind === "fork" ? "fork" : "live share"}
              </Text>
              <Text style={styles.small} numberOfLines={1}>
                {l.agentTitle ?? l.lane.agentId.slice(0, 8)} · {l.activeRoutes} open view(s)
              </Text>
            </View>
            <Badge
              theme={theme}
              label={l.endpoint === "online" ? "Online" : l.endpoint === "closed" ? "Closed" : l.endpoint === "starting" ? "Starting" : "Offline"}
              tone={l.endpoint === "online" ? "ok" : l.endpoint === "closed" ? "muted" : "warn"}
            />
          </View>
          {l.lane.status === "open" ? <LaneErrors laneId={l.lane.id} theme={theme} styles={styles} /> : null}
          {l.lane.status === "open" ? (
            <View style={styles.row}>
              <Button theme={theme} variant="primary" label="Create invite" busy={inviteM.isPending && inviteM.variables === l.lane.id} onPress={() => inviteM.mutate(l.lane.id)} />
              <Button theme={theme} label="Open agent" onPress={() => openAgent(l.lane.agentId)} />
              <ConfirmButton
                theme={theme}
                label="Close lane"
                confirmLabel="Close lane"
                message="Closing ends every member's view of this agent now and revokes unused invites. It cannot be reopened."
                onConfirm={() =>
                  closeLane({ laneId: l.lane.id })
                    .then(refresh)
                    .catch((e) => toast.error(errorText(e)))
                }
              />
            </View>
          ) : null}
          {invite && invite.laneId === l.lane.id ? (
            <View style={[styles.codeBox, { gap: 6 }]}>
              <Text style={styles.small}>One-time invite code, valid {relativeTime(invite.expiresAt)}. Send it privately; anyone with it can join once.</Text>
              <Text selectable numberOfLines={3} style={styles.mono}>
                {invite.code}
              </Text>
              <Text style={styles.small}>Shown shortened. "Copy code" copies all of it.</Text>
              <View style={styles.row}>
                <Button
                  theme={theme}
                  variant="primary"
                  label="Copy code"
                  onPress={() => void copyText(invite.code).then(() => toast.show("Invite code copied", { variant: "success" }))}
                />
                <Button theme={theme} label="Hide" onPress={() => setInvite(null)} />
              </View>
            </View>
          ) : null}
        </View>
      ))}
      <ProjectNameSetting view={view} theme={theme} styles={styles} />
      {view.members.length ? <View style={styles.divider} /> : null}
      {view.members.map((m) => (
        <View key={m.id} style={styles.between}>
          <View style={{ flexShrink: 1, gap: 2 }}>
            <Text style={styles.body}>{m.label}</Text>
            <Text style={styles.small}>
              {m.status === "active"
                ? `${m.connected ? "connected" : "not connected"} · access expires ${relativeTime(m.grantExpiresAt)} unless renewed`
                : `${m.status} ${relativeTime(m.endedAt)}`}
            </Text>
          </View>
          {m.status === "active" ? (
            <ConfirmButton
              theme={theme}
              label="Revoke"
              confirmLabel="Revoke access"
              message={`${m.label} loses access now and their open view is cut.`}
              accessibilityLabel={`Revoke ${m.label}`}
              onConfirm={() => revokeM.mutateAsync(m.id).catch(() => undefined)}
            />
          ) : (
            <Badge theme={theme} label={m.status} tone="muted" />
          )}
        </View>
      ))}
      {view.invites.some((i) => i.status === "open") ? <View style={styles.divider} /> : null}
      {view.invites
        .filter((i) => i.status === "open")
        .map((i) => (
          <View key={i.id} style={styles.between}>
            <Text style={styles.small}>Unused invite, expires {relativeTime(i.expiresAt)}</Text>
            <ConfirmButton
              theme={theme}
              variant="secondary"
              label="Revoke invite"
              confirmLabel="Revoke invite"
              message="The code stops working. Anyone who already joined keeps access."
              onConfirm={() =>
                revokeInvite({ inviteId: i.id })
                  .then(refresh)
                  .catch((e) => toast.error(errorText(e)))
              }
            />
          </View>
        ))}
    </View>
  );
}

function JoinForm({ theme, styles }: { theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const join = useRpc(roomsJoin);
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const m = useMutation({
    mutationFn: () => join({ code: code.trim(), ...(label.trim() ? { label: label.trim() } : {}) }),
    onSuccess: (r) => {
      setCode("");
      toast.show(`Joined ${r.joined.roomName}. The lane appears as a host under this daemon.`, { variant: "success" });
      void qc.invalidateQueries({ queryKey: OVERVIEW_KEY });
    },
    onError: (e) => toast.error(errorText(e)),
  });
  return (
    <View style={styles.card}>
      <Text style={styles.body}>Join with an invite code</Text>
      <TextInput
        accessibilityLabel="Invite code"
        placeholder="prc1.…"
        placeholderTextColor={theme.colors.foregroundMuted}
        value={code}
        onChangeText={setCode}
        autoCapitalize="none"
        autoCorrect={false}
        secureTextEntry={false}
        multiline
        style={[styles.input, { minHeight: 56 }]}
      />
      <TextInput
        accessibilityLabel="Your name in the room"
        placeholder="Your name in the room (optional)"
        placeholderTextColor={theme.colors.foregroundMuted}
        value={label}
        onChangeText={setLabel}
        style={styles.input}
      />
      <View style={styles.row}>
        <Button theme={theme} variant="primary" label="Join room" busy={m.isPending} disabled={code.trim().length < 20} onPress={() => m.mutate()} />
        {code.trim().length > 0 && code.trim().length < 20 ? <Text style={styles.small}>Paste the whole code (it starts with prc1.)</Text> : null}
      </View>
    </View>
  );
}

function JoinedRoomCard({ view, theme, styles }: { view: JoinedRoomView; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const leave = useRpc(roomsLeave);
  const rotate = useRpc(roomsRotate);
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW_KEY });
  const tone = view.status !== "active" ? "muted" : view.hostStatus === "online" ? "ok" : view.hostStatus === "error" ? "danger" : "warn";
  const label =
    view.status !== "active" ? view.status : view.hostStatus === "online" ? "Connected" : view.hostStatus === "error" ? (view.hostError ?? "Error") : (view.hostStatus ?? "Waiting");
  return (
    <View style={styles.card}>
      <View style={styles.between}>
        <View style={{ flexShrink: 1, gap: 2 }}>
          <Text style={styles.h2}>{view.roomName}</Text>
          <Text style={styles.small}>
            {view.laneLabel} · joined {relativeTime(view.joinedAt)}
            {view.grantExpiresAt ? ` · access renews automatically, expires ${relativeTime(view.grantExpiresAt)}` : ""}
          </Text>
        </View>
        <Badge theme={theme} label={label} tone={tone} />
      </View>
      {view.status === "active" ? (
        <>
          <Text style={styles.small}>Find it in the host list as "{view.roomName} · {view.laneLabel}". It is read-only.</Text>
          <View style={styles.row}>
            <Button
              theme={theme}
              label="Reconnect"
              onPress={() =>
                void rotate({ laneId: view.laneId, force: true })
                  .then((r) => toast.show(r.rotated ? "Reconnected with fresh access" : `Not reconnected: ${r.reason}`))
                  .then(refresh)
                  .catch((e) => toast.error(errorText(e)))
              }
            />
            <ConfirmButton
              theme={theme}
              label="Leave"
              confirmLabel="Leave room"
              message="You stop seeing this agent. Rejoining needs a new invite from the owner."
              onConfirm={() =>
                leave({ laneId: view.laneId })
                  .then(refresh)
                  .catch((e) => toast.error(errorText(e)))
              }
            />
          </View>
        </>
      ) : view.status === "revoked" ? (
        <Text style={styles.small}>The owner revoked your access. The host entry may stay in your app list until you remove it (Paseo does not prune routed hosts yet).</Text>
      ) : view.status === "left" ? (
        <Text style={styles.small}>You left this room. The host entry may stay in your app list until you remove it (Paseo does not prune routed hosts yet).</Text>
      ) : null}
    </View>
  );
}

/** Owner-only room setting: members see a neutral name unless the owner opts in. */
function ProjectNameSetting({ view, theme, styles }: { view: OwnedRoomView; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const setSettings = useRpc(roomsSettingsSet);
  const shown = view.settings.showProjectName;
  const apply = (show: boolean) =>
    setSettings({ roomId: view.room.id, showProjectName: show })
      .then(() => qc.invalidateQueries({ queryKey: OVERVIEW_KEY }))
      .catch((e) => toast.error(errorText(e)));
  return (
    <View style={{ gap: 6 }}>
      <View style={styles.between}>
        <View style={{ flexShrink: 1, gap: 2 }}>
          <Text style={styles.body}>Show project name to members</Text>
          <Text style={styles.small}>
            {shown ? "Members see the project and folder names." : `Members see "${view.room.name} · <lane name>" instead of the project name, and hashed folder names.`}
          </Text>
        </View>
        <Badge theme={theme} label={shown ? "Shown" : "Hidden"} tone={shown ? "warn" : "muted"} />
      </View>
      <View style={styles.row}>
        {shown ? (
          <ConfirmButton
            theme={theme}
            variant="secondary"
            label="Hide project name"
            confirmLabel="Hide"
            message="Members see the neutral name from now on, including views that are open. Names they already saw are not recalled. The change is recorded in the room log."
            onConfirm={() => apply(false)}
          />
        ) : (
          <ConfirmButton
            theme={theme}
            variant="secondary"
            label="Show project name"
            confirmLabel="Show to members"
            message="Members will see the project's display name (for a git project this can be owner/repo), a workspace named after it, and the real folder names in paths (not the full paths). It applies to open views now and is recorded in the room log."
            onConfirm={() => apply(true)}
          />
        )}
      </View>
    </View>
  );
}

/** Owner-only: full text of the errors this lane's members saw as generic text. Read from this daemon. */
function LaneErrors({ laneId, theme, styles }: { laneId: string; theme: PluginTheme; styles: Styles }) {
  const [open, setOpen] = useState(false);
  const fetchErrors = useRpc(roomsLaneErrors);
  const q = useQuery({ queryKey: ["rooms", "lane-errors", laneId], queryFn: () => fetchErrors({ laneId }), enabled: open, refetchInterval: open ? 5000 : false });
  const count = q.data?.errors.length ?? 0;
  return (
    <View style={{ gap: 6 }}>
      <View style={styles.row}>
        <Button
          theme={theme}
          label={open ? "Hide recent errors" : "Recent errors"}
          accessibilityLabel={open ? "Hide recent errors for this lane" : "Show recent errors for this lane"}
          onPress={() => setOpen((v) => !v)}
        />
        {open ? <Text style={styles.small}>Only you see these. Members got generic text.</Text> : null}
      </View>
      {open ? (
        <View style={[styles.codeBox, { gap: 8 }]}>
          {q.isError ? <Text style={styles.danger}>Could not load errors: {errorText(q.error)}</Text> : null}
          {q.isLoading ? <Text style={styles.small}>Loading…</Text> : null}
          {q.data && count === 0 ? <Text style={styles.small}>No errors since the lane started on this daemon.</Text> : null}
          {q.data?.errors.map((e, i) => (
            <View key={`${e.source}-${e.firstAt}-${i}`} style={{ gap: 2 }}>
              <Text style={styles.small} numberOfLines={1}>
                {e.source} · {relativeTime(e.lastAt)}
                {e.count > 1 ? ` · ${e.count} times` : ""}
              </Text>
              <Text selectable numberOfLines={6} style={styles.mono}>
                {e.message}
              </Text>
            </View>
          ))}
        </View>
      ) : null}
    </View>
  );
}
