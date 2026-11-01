// Rooms screen (identity v2; I-14, the only screen since the I-15 cut-over). Talks to the daemon
// through rooms.v2.* RPCs, plus the migration notices of migration.md 2.3 to 2.5 (rooms.migration.*).
import type { PluginTheme } from "@getpaseo/plugin";
import type { PluginScreenProps } from "@getpaseo/plugin/client";
import { useAgent, useRpc } from "@getpaseo/plugin/client";
import { Modal, ScrollView, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Text, View } from "react-native";
import { roomsMigrationDeleteKeys, roomsMigrationDismiss, roomsPermissionsFix } from "../shared/rpc";
import { roomsV2DataDelete, roomsV2HostsCleanup, roomsV2LaneCreate, roomsV2RoomCreate, roomsV2Status } from "../shared/rpc-v2";
import { Button, commandCenterHint, errorText, Section, Segmented, useStyles, type Styles } from "./ui";
import { RecoveryCodeModal, TypedConfirm, useAdminConfirm, type RecoveryOffer } from "./v2-dialogs";
import { JoinedCardV2, JoinFormV2, JoiningCardV2 } from "./v2-member";
import { OwnedRoomCardV2, STATUS_V2_KEY, type OwnedV2 } from "./v2-owner";
import { keystoreText, shortId, WINDOWS_DURABILITY } from "./v2-text";

function useStatusV2() {
  const status = useRpc(roomsV2Status);
  return useQuery({ queryKey: STATUS_V2_KEY, queryFn: () => status({}), refetchInterval: 3000 });
}

export function RoomsV2Screen({ theme, layout, navigation }: PluginScreenProps) {
  const styles = useStyles(theme, layout.compact);
  const q = useStatusV2();
  const s = q.data;
  const closedAgents = [
    ...(s?.owned ?? []).flatMap((r) => r.lanes.filter((l) => l.agentId && (r.keys.closed || l.status === "closed")).map((l) => ({ roomId: r.roomId, laneId: l.laneId, agentId: l.agentId!, label: l.label, old: false }))),
    // Migration 2.2 step 3: lane agents of the previous version (M1), left on this daemon.
    ...(s?.migration?.lanes ?? []).map((l) => ({ roomId: l.roomId, laneId: l.laneId, agentId: l.agentId, label: l.label as string | null, old: true })),
  ].filter((a, i, all) => all.findIndex((b) => b.agentId === a.agentId) === i);
  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <View style={{ gap: 4 }}>
        <View style={styles.between}>
          <Text accessibilityRole="header" style={styles.h1}>
            Rooms
          </Text>
        </View>
        <Text style={styles.muted}>Share an agent read-only with people who run Paseo. Joins are confirmed by comparing a six-digit code by voice.</Text>
      </View>
      {q.isError ? <Text style={styles.danger}>Could not load rooms: {errorText(q.error)}</Text> : null}
      {s ? <RuntimeNotices s={s} theme={theme} styles={styles} /> : null}
      {s?.migration ? <MigrationNotices m={s.migration} theme={theme} styles={styles} /> : null}

      <Section styles={styles} title="Rooms you own" trailing={s?.state === "ready" ? <CreateRoomButton theme={theme} styles={styles} /> : null}>
        {s && s.owned.length === 0 ? <Text style={styles.muted}>No rooms yet. Create one, then share an agent: open the agent, {commandCenterHint(layout.compact)} and choose "Open room…".</Text> : null}
        {s?.owned.map((r) => <OwnedRoomCardV2 key={r.roomId} view={r} theme={theme} styles={styles} compact={layout.compact} />)}
      </Section>

      <Section styles={styles} title="Rooms you joined">
        {s?.state === "ready" ? <JoinFormV2 theme={theme} styles={styles} /> : null}
        {s?.joining
          .filter((j) => !((j.state === "admitted" || j.state === "registered") && s.joined.some((x) => x.roomId === j.roomId)))
          .map((j) => <JoiningCardV2 key={j.roomId} view={j} theme={theme} styles={styles} />)}
        {s?.joined.map((j) => <JoinedCardV2 key={j.roomId} view={j} mls={s.mls.find((m) => m.roomId === j.roomId)} theme={theme} styles={styles} />)}
      </Section>

      {closedAgents.length ? (
        <Section styles={styles} title="Agents from closed rooms">
          <Text style={styles.small}>These agents stay on this daemon after their room or lane closed. Members can no longer see them. Archive them in Paseo when you no longer need them.</Text>
          {closedAgents.map((a) => (
            <View key={`${a.roomId}-${a.laneId}`} style={styles.between}>
              <Text style={styles.body}>
                {a.label ?? `Lane ${shortId(a.laneId)}`} · {a.old ? "previous version" : `room ${shortId(a.roomId)}`}
              </Text>
              <Button theme={theme} label="Open agent" onPress={() => navigation?.openAgent({ agentId: a.agentId })} />
            </View>
          ))}
        </Section>
      ) : null}

      {s ? <About s={s} theme={theme} styles={styles} /> : null}
      {s?.state === "ready" || s?.error === "data_deleted" ? <DeleteAllData s={s} theme={theme} styles={styles} /> : null}
    </ScrollView>
  );
}

type Status = NonNullable<ReturnType<typeof useStatusV2>["data"]>;

function RuntimeNotices({ s, theme, styles }: { s: Status; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const fix = useRpc(roomsPermissionsFix);
  const [busy, setBusy] = useState(false);
  const c = theme.colors;
  const ks = s.keystore;
  const ksText = ks ? keystoreText(ks.state) : null;
  const box = (tone: "warn" | "danger") => [styles.codeBox, { borderLeftWidth: 3, borderLeftColor: tone === "danger" ? c.statusDanger : c.statusWarning, gap: 6 }];
  return (
    <>
      {s.state === "starting" ? <Text style={styles.muted}>Starting Rooms…</Text> : null}
      {ks?.state === "ready" && ks.fallback ? (
        <View style={box("warn")}>
          <Text style={styles.body}>{ks.notice ?? "Room keys are stored unprotected on disk. Anyone who can read this account's files or backups can read them."}</Text>
          <Text style={styles.small}>No system keyring was available when Rooms first started. Rooms moves the keys into a keyring once one is available.</Text>
        </View>
      ) : null}
      {ksText ? (
        <View style={box(ksText.tone === "danger" ? "danger" : "warn")}>
          <Text style={styles.h2}>{ksText.title}</Text>
          <Text style={styles.body}>{ksText.text}</Text>
        </View>
      ) : null}
      {s.permissionProblems?.length ? (
        <View style={box("danger")}>
          <Text style={styles.h2}>Rooms files are not protected</Text>
          <Text style={styles.body}>Rooms loaded no keys. "Fix permissions" makes these files readable by your account only. Links and files owned by another account are never changed; fix those by hand.</Text>
          {s.permissionProblems.slice(0, 6).map((p, i) => (
            <Text key={i} style={styles.mono}>
              {p.path}: {p.detail}
            </Text>
          ))}
          <Button
            theme={theme}
            variant="primary"
            label="Fix permissions"
            busy={busy}
            onPress={() => {
              setBusy(true);
              void fix({})
                .then((r) => (r.ok ? toast.show("Permissions fixed. Rooms started.", { variant: "success" }) : toast.error(`${r.problems.length} problem(s) remain; fix them by hand.`)))
                .catch((e) => toast.error(errorText(e)))
                .finally(() => {
                  setBusy(false);
                  void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
                });
            }}
          />
        </View>
      ) : null}
      {s.staleHosts?.length ? <StaleHostsNotice s={s} theme={theme} styles={styles} /> : null}
      {s.state === "error" && s.error === "data_deleted" ? (
        <View style={box("warn")}>
          <Text style={styles.body}>Rooms data and keys were deleted on this daemon. Rooms stays stopped until the daemon restarts; it then starts empty. To uninstall, remove the plugin now.</Text>
        </View>
      ) : s.state === "error" && !s.permissionProblems?.length && !ksText ? (
        <View style={box("danger")}>
          <Text style={styles.body}>Rooms could not start: {s.error ?? "unknown error"}</Text>
        </View>
      ) : null}
    </>
  );
}

/**
 * Migration from M1 (migration.md 2.3 step 4, 2.4, 2.5): the one-time upgrade notice, and the archive
 * of v1 keys with "Delete keys", which needs the user's confirmation and keeps the room logs.
 */
function MigrationNotices({ m, theme, styles }: { m: NonNullable<Status["migration"]>; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const dismiss = useRpc(roomsMigrationDismiss);
  const deleteKeys = useRpc(roomsMigrationDeleteKeys);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const c = theme.colors;
  const box = [styles.codeBox, { borderLeftWidth: 3, borderLeftColor: c.statusWarning, gap: 6 }];
  const refresh = () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
  return (
    <>
      {m.notice ? (
        <View style={box}>
          <Text style={styles.h2}>Rooms was upgraded</Text>
          <Text style={styles.body}>Rooms from the previous version were closed during the upgrade. Create a new room and send new invites. Invite codes starting with prc1. no longer work.</Text>
          {m.hosts !== "none" ? (
            <Text style={styles.small}>
              {m.hosts === "done" ? "The lanes you had joined were removed from this daemon's hosts." : "Removing the lanes you had joined from this daemon's hosts…"} Paseo may still list old entries for them until it refreshes.
            </Text>
          ) : null}
          {m.gateway === "pending" || m.member === "pending" ? <Text style={styles.small}>Some files of the previous version could not be moved yet. Rooms tries again at the next start.</Text> : null}
          <View style={styles.row}>
            <Button theme={theme} label="OK" onPress={() => void dismiss({}).then(refresh).catch((e) => toast.error(errorText(e)))} />
          </View>
        </View>
      ) : null}
      {m.keyFiles.length ? (
        <View style={box}>
          <Text style={styles.body}>Keys from the previous version of Rooms are stored unprotected in plugin-data/rooms/{m.archive}. They no longer work. Delete them?</Text>
          <Text style={styles.small}>The room logs of the previous version stay in that folder.</Text>
          <View style={styles.row}>
            <Button theme={theme} variant="primary" label="Delete keys" onPress={() => setConfirm(true)} />
          </View>
        </View>
      ) : null}
      {confirm ? (
        <Modal title="Delete old keys" open onOpenChange={(o) => (busy ? undefined : setConfirm(o))}>
          <Modal.Content>
            <View style={{ gap: 10 }}>
              <Text style={styles.body}>This deletes {m.keyFiles.length} file(s) with keys of the previous version. It cannot be undone. The room logs are kept.</Text>
              {m.keyFiles.slice(0, 6).map((f) => (
                <Text key={f} style={styles.mono}>
                  {f}
                </Text>
              ))}
              <View style={styles.row}>
                <Button
                  theme={theme}
                  variant="primary"
                  label="Delete"
                  busy={busy}
                  onPress={() => {
                    setBusy(true);
                    void deleteKeys({ confirm: true, expected: m.keyFiles })
                      .then((r) => {
                        toast.show(`Deleted ${r.removed.length} file(s)`, { variant: "success" });
                        setConfirm(false);
                      })
                      .catch((e) => toast.error(errorText(e)))
                      .finally(() => {
                        setBusy(false);
                        refresh();
                      });
                  }}
                />
                <Button theme={theme} label="Cancel" disabled={busy} onPress={() => setConfirm(false)} />
              </View>
            </View>
          </Modal.Content>
        </Modal>
      ) : null}
    </>
  );
}

/** Identity-model 5.4: the create dialog preselects the recovery key and says what skipping costs. */
function CreateRoomButton({ theme, styles }: { theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const create = useRpc(roomsV2RoomCreate);
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<"create" | "skip">("create");
  const [busy, setBusy] = useState(false);
  const [offer, setOffer] = useState<{ offer: RecoveryOffer; roomId: string } | null>(null);
  return (
    <>
      <Button theme={theme} variant="primary" label="Create room" onPress={() => setOpen(true)} />
      {open ? (
        <Modal title="Create a room" open onOpenChange={(o) => (busy ? undefined : setOpen(o))}>
          <Modal.Content>
            <View style={{ gap: 10 }}>
              <Text style={styles.body}>This daemon becomes the room's host and its first admin.</Text>
              <Segmented<"create" | "skip">
                theme={theme}
                value={choice}
                onChange={setChoice}
                options={[
                  { value: "create", label: "Create a recovery key", hint: "Recommended. Shown once; you save it." },
                  { value: "skip", label: "Skip", hint: "No recovery if your admin key is lost" },
                ]}
              />
              {choice === "skip" ? (
                <Text style={[styles.small, { color: theme.colors.statusWarning }]}>
                  Without a recovery key, a room with one admin cannot be recovered if that admin's key is lost or stolen. Members would have to start a new room.
                </Text>
              ) : null}
              <View style={styles.row}>
                <Button
                  theme={theme}
                  variant="primary"
                  label="Create room"
                  busy={busy}
                  onPress={() => {
                    setBusy(true);
                    void create({ recovery: choice })
                      .then((r) => {
                        setOpen(false);
                        if (r.recovery) setOffer({ offer: r.recovery, roomId: r.roomId });
                        toast.show(`Room ${shortId(r.roomId)} created`, { variant: "success" });
                        void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
                      })
                      .catch((e) => toast.error(errorText(e)))
                      .finally(() => setBusy(false));
                  }}
                />
                <Button theme={theme} label="Cancel" disabled={busy} onPress={() => setOpen(false)} />
              </View>
            </View>
          </Modal.Content>
        </Modal>
      ) : null}
      <RecoveryCodeModal theme={theme} styles={styles} offer={offer?.offer ?? null} context={`Recovery key for room ${shortId(offer?.roomId)}.`} onClosed={() => setOffer(null)} />
    </>
  );
}

/** R3.7: routed lane hosts the plugin could not remove from this daemon's host list. */
function StaleHostsNotice({ s, theme, styles }: { s: Status; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const toast = useToast();
  const cleanup = useRpc(roomsV2HostsCleanup);
  const [busy, setBusy] = useState(false);
  const hosts = s.staleHosts ?? [];
  return (
    <View style={[styles.codeBox, { borderLeftWidth: 3, borderLeftColor: theme.colors.statusWarning, gap: 6 }]}>
      <Text style={styles.body}>
        {hosts.length} lane host(s) from rooms you left or lanes that closed are still in this daemon's host list. They no longer connect. Rooms retries removing them.
      </Text>
      {hosts.slice(0, 6).map((h) => (
        <Text key={h.registrationId} style={styles.small}>
          {h.label} · {h.reason.replace(/_/g, " ")}
          {h.lastError === "no_api" ? " · Paseo was not reachable from Rooms yet" : h.lastError ? ` · ${h.lastError}` : ""}
        </Text>
      ))}
      <Text style={styles.small}>If they stay, disable them in Paseo's host list. Paseo lets only Rooms itself delete them, so remove them here before you remove the plugin.</Text>
      <Button
        theme={theme}
        label="Retry now"
        busy={busy}
        onPress={() => {
          setBusy(true);
          void cleanup({})
            .then((r) => (r.remaining.length ? toast.error(`${r.remaining.length} host(s) could not be removed yet.`) : toast.show("Lane hosts removed", { variant: "success" })))
            .catch((e) => toast.error(errorText(e)))
            .finally(() => {
              setBusy(false);
              void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
            });
        }}
      />
    </View>
  );
}

/**
 * R2.6 "Leave all rooms and delete keys": the typed confirmation lists what happens. Hosted rooms need
 * an extra choice, because they stop for good and their members lose access.
 */
function DeleteAllData({ s, theme, styles }: { s: Status; theme: PluginTheme; styles: Styles }) {
  const qc = useQueryClient();
  const del = useRpc(roomsV2DataDelete);
  const [open, setOpen] = useState(false);
  const [hostedToo, setHostedToo] = useState(false);
  const [result, setResult] = useState<Awaited<ReturnType<typeof del>> | null>(null);
  const joined = s.joined.length + s.joining.filter((j) => !s.joined.some((x) => x.roomId === j.roomId)).length;
  const hosted = s.owned.length;
  const backend = s.keystore?.backend ?? "unknown";
  return (
    <Section styles={styles} title="Remove Rooms from this daemon" trailing={<Button theme={theme} label={open ? "Hide" : "Show"} onPress={() => setOpen((v) => !v)} />}>
      {open && s.state === "ready" ? (
        <View style={{ gap: 8 }}>
          <Text style={styles.small}>
            Before you remove the plugin, leave your rooms and delete the keys here. Removing the plugin alone leaves the room keys, the keyring entry and the lane hosts behind (see the README).
          </Text>
          {hosted > 0 ? (
            <View style={styles.row}>
              <Button theme={theme} variant={hostedToo ? "danger" : "secondary"} label={hostedToo ? `Also delete ${hosted} hosted room(s): yes` : `Also delete ${hosted} hosted room(s)`} onPress={() => setHostedToo((v) => !v)} />
              <Text style={[styles.small, { flexShrink: 1 }]}>Required while this daemon hosts rooms.</Text>
            </View>
          ) : null}
          <TypedConfirm
            theme={theme}
            styles={styles}
            label="Leave all rooms and delete keys"
            title="Leave all rooms and delete keys"
            word="delete"
            onConfirm={() =>
              del({ confirm: "delete", ...(hostedToo ? { deleteHosted: true } : {}) }).then((r) => {
                setResult(r);
                void qc.invalidateQueries({ queryKey: STATUS_V2_KEY });
              })
            }
          >
            <Text style={styles.body}>This daemon leaves {joined} joined room(s). Each owner sees that you left. Rooms that cannot be reached now are only forgotten here; their owners still list you.</Text>
            <Text style={styles.body}>Every lane host Rooms added to this daemon's host list is removed.</Text>
            <Text style={styles.body}>The room key in {backend} and every Rooms file on this daemon are deleted. This cannot be undone.</Text>
            {hosted > 0 ? (
              <Text style={[styles.body, { color: theme.colors.statusDanger }]}>
                {hostedToo ? `${hosted} room(s) hosted here stop for good. Their members lose access and the rooms cannot be recovered.` : `This daemon hosts ${hosted} room(s). Choose "Also delete hosted rooms" first, or the request is refused.`}
              </Text>
            ) : null}
          </TypedConfirm>
        </View>
      ) : null}
      {result ? (
        <View style={[styles.codeBox, { gap: 4 }]}>
          <Text style={styles.body}>
            Left {result.left.filter((l) => l.statement).length} room(s), forgot {result.left.filter((l) => !l.statement).length}. Removed {result.hostsRemoved} lane host(s).
          </Text>
          {result.hostsRemaining.length ? <Text style={styles.small}>{result.hostsRemaining.length} lane host(s) could not be removed. Disable them in Paseo's host list.</Text> : null}
          <Text style={styles.small}>
            Room key: {result.keystore.kek}
            {result.keystore.message ? ` (${result.keystore.message})` : ""}. Rooms files deleted: {result.dataDeleted ? "yes" : "no"}.
          </Text>
        </View>
      ) : null}
    </Section>
  );
}

function About({ s, theme, styles }: { s: Status; theme: PluginTheme; styles: Styles }) {
  const [open, setOpen] = useState(false);
  return (
    <Section styles={styles} title="About" trailing={<Button theme={theme} label={open ? "Hide" : "Show"} onPress={() => setOpen((v) => !v)} />}>
      {open ? (
        <View style={[styles.codeBox, { gap: 6 }]}>
          <Text style={styles.small}>Protocol: Rooms identity v2. Room keys stay on this daemon; this app holds none.</Text>
          <Text style={styles.small}>
            Key storage: {s.keystore?.backend ?? "not open"}
            {s.keystore?.fallback ? " (unprotected file)" : ""}. Daemon OS: {s.platform ?? "unknown"}.
          </Text>
          <Text style={styles.small}>Changes are written to a temporary file, flushed, renamed over the old file, and the folder is flushed.</Text>
          {s.platform === "win32" ? <Text style={[styles.small, { color: theme.colors.statusWarning }]}>{WINDOWS_DURABILITY}</Text> : <Text style={styles.small}>{WINDOWS_DURABILITY}</Text>}
          <Text style={styles.small}>The confirmation dialogs prevent accidental admin actions. They do not stop other programs running as your account, which can call the same functions.</Text>
        </View>
      ) : null}
    </Section>
  );
}

/** "Open room…" under v2: share this agent as a lane of a room this daemon owns (lane.created, confirmed). */
export function OpenRoomV2Screen({ theme, layout, params }: PluginScreenProps) {
  const styles = useStyles(theme, layout.compact);
  const agentId = params.agentId ?? "";
  const title = useAgent(agentId, (a) => a.title);
  const q = useStatusV2();
  const qc = useQueryClient();
  const createLane = useRpc(roomsV2LaneCreate);
  const admin = useAdminConfirm(theme, styles);
  const [label, setLabel] = useState("");
  const [roomId, setRoomId] = useState<string | null>(null);
  const rooms: OwnedV2[] = (q.data?.owned ?? []).filter((r) => !r.keys.closed && r.keys.adminKid);
  const chosen = roomId ?? rooms[0]?.roomId ?? null;
  const already = (q.data?.owned ?? []).some((r) => r.lanes.some((l) => l.agentId === agentId && l.status !== "closed"));
  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <Text accessibilityRole="header" style={styles.h1}>
        Share in a room
      </Text>
      <Text style={styles.muted}>Agent: {title ?? shortId(agentId)}. Members see it read-only, live. Rooms shares this agent as it is; it does not fork it.</Text>
      {already ? <Text style={styles.body}>This agent is already shared in a room.</Text> : null}
      {rooms.length === 0 ? <Text style={styles.body}>You own no open room. Create one on the Rooms screen first.</Text> : null}
      {rooms.length > 1 ? (
        <Segmented theme={theme} value={chosen ?? ""} onChange={setRoomId} options={rooms.map((r) => ({ value: r.roomId, label: `Room ${shortId(r.roomId)}`, hint: `${r.members} member(s)` }))} />
      ) : null}
      <TextInput accessibilityLabel="Lane name members see" placeholder="Lane name members see (default: Live)" placeholderTextColor={theme.colors.foregroundMuted} value={label} onChangeText={setLabel} maxLength={80} style={styles.input} />
      <View style={styles.row}>
        <Button
          theme={theme}
          variant="primary"
          label="Share"
          disabled={!chosen || !agentId || already}
          onPress={() => {
            if (!chosen) return;
            const input = { roomId: chosen, agentId, ...(label.trim() ? { label: label.trim() } : {}) };
            admin.open({ kind: "lane.create", ...input }, (t) => createLane({ ...input, confirmToken: t }), {
              success: "Shared. Invite people from the Rooms screen.",
              onDone: () => void qc.invalidateQueries({ queryKey: STATUS_V2_KEY }),
            });
          }}
        />
      </View>
      {admin.element}
    </ScrollView>
  );
}
