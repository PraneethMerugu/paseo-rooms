// "Open room…" screen for one agent: room name, lane origin (fork by default, or share live), create.
import type { PluginScreenProps } from "@getpaseo/plugin/client";
import { useAgent, useRpc } from "@getpaseo/plugin/client";
import { copyText, ScrollView, TextInput, useToast } from "@getpaseo/plugin/client/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Text, View } from "react-native";
import { isForkVerifiedProvider } from "../shared/policy";
import { roomsCreate, roomsInviteCreate, roomsLaneAgents } from "../shared/rpc";
import { OVERVIEW_KEY } from "./rooms-screen";
import { Button, commandCenterHint, errorText, relativeTime, Segmented, useStyles } from "./ui";

type Origin = "fork" | "share";

export function OpenRoomScreen({ theme, layout, params }: PluginScreenProps) {
  const styles = useStyles(theme, layout.compact);
  const agentId = params.agentId ?? "";
  const title = useAgent(agentId, (a) => a.title);
  const provider = useAgent(agentId, (a) => a.provider);
  const create = useRpc(roomsCreate);
  const createInvite = useRpc(roomsInviteCreate);
  const laneAgents = useRpc(roomsLaneAgents);
  const lanes = useQuery({ queryKey: ["rooms", "lane-agents"], queryFn: () => laneAgents({}), enabled: !!agentId });
  const laneOfAgent = lanes.data?.lanes.find((l) => l.agentId === agentId) ?? null;
  const forkAllowed = !provider || isForkVerifiedProvider(String(provider));
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [originChoice, setOrigin] = useState<Origin>("fork");
  const [instruction, setInstruction] = useState("");
  const [invite, setInvite] = useState<{ code: string; expiresAt: string } | null>(null);
  const origin: Origin = forkAllowed ? originChoice : "share";
  const roomName = name.trim() || (title ? `${title}` : "Room");
  const m = useMutation({
    mutationFn: () =>
      create({ name: roomName.slice(0, 80), agentId, origin, ...(origin === "fork" && instruction.trim() ? { instruction: instruction.trim() } : {}) }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: OVERVIEW_KEY }),
    onError: (e) => toast.error(errorText(e)),
  });
  const inviteM = useMutation({
    mutationFn: (laneId: string) => createInvite({ laneId }),
    onSuccess: (r) => setInvite({ code: r.code, expiresAt: r.expiresAt }),
    onError: (e) => toast.error(errorText(e)),
  });

  if (!agentId) {
    return (
      <View style={[styles.screen, styles.content]}>
        <Text style={styles.body}>Open this from an agent: {commandCenterHint(layout.compact)} in an agent and choose "Open room…".</Text>
      </View>
    );
  }
  if (laneOfAgent && !m.data) {
    return (
      <View style={[styles.screen, styles.content]}>
        <Text style={styles.body}>
          This agent is already shared as a lane of the room "{laneOfAgent.roomName}". Manage it under Rooms in the sidebar.
        </Text>
      </View>
    );
  }
  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <View style={{ gap: 4 }}>
        <Text accessibilityRole="header" style={styles.h1}>
          Open a room
        </Text>
        <Text style={styles.muted} numberOfLines={2}>
          From {title ?? agentId.slice(0, 8)}
          {provider ? ` · ${provider}` : ""}. Members get read-only access to one agent; nothing else on this machine is visible to them.
        </Text>
      </View>
      {!m.data ? (
        <View style={styles.card}>
          <Text style={styles.body}>Room name</Text>
          <TextInput
            accessibilityLabel="Room name"
            placeholder={title ?? "Room"}
            placeholderTextColor={theme.colors.foregroundMuted}
            value={name}
            onChangeText={setName}
            maxLength={80}
            style={styles.input}
          />
          <Text style={styles.body}>What members see</Text>
          <Segmented<Origin>
            theme={theme}
            value={origin}
            onChange={setOrigin}
            options={
              forkAllowed
                ? [
                    { value: "fork", label: "Fork (recommended)", hint: "A new agent seeded with this conversation's messages, without Paseo control tools." },
                    { value: "share", label: "Share live", hint: "This agent itself, read-only, as it works." },
                  ]
                : [{ value: "share", label: "Share live", hint: "This agent itself, read-only, as it works." }]
            }
          />
          {!forkAllowed ? (
            <Text style={styles.small}>Fork is not available for {String(provider)}: only providers verified to run without Paseo control tools can be forked into a room.</Text>
          ) : null}
          {origin === "fork" ? (
            <>
              <Text style={styles.body}>First instruction for the fork (optional)</Text>
              <TextInput
                accessibilityLabel="First instruction for the fork"
                placeholder="Defaults to: confirm you are ready and wait"
                placeholderTextColor={theme.colors.foregroundMuted}
                value={instruction}
                onChangeText={setInstruction}
                multiline
                style={[styles.input, { minHeight: 64 }]}
              />
              <Text style={styles.small}>Starting the fork runs one turn on your provider account.</Text>
            </>
          ) : null}
          <View style={styles.row}>
            <Button theme={theme} variant="primary" label="Create room" busy={m.isPending} onPress={() => m.mutate()} />
          </View>
        </View>
      ) : (
        <View style={styles.card}>
          <Text style={styles.h2}>{m.data.room.name} is open</Text>
          <Text style={styles.small}>
            Lane "{m.data.lane.label}" ({m.data.lane.origin.kind === "fork" ? "fork" : "live share"}). Manage it under Rooms in the sidebar.
          </Text>
          {invite ? (
            <View style={[styles.codeBox, { gap: 6 }]}>
              <Text style={styles.small}>One-time invite code, valid {relativeTime(invite.expiresAt)}. Send it privately.</Text>
              <Text selectable numberOfLines={3} style={styles.mono}>
                {invite.code}
              </Text>
              <View style={styles.row}>
                <Button theme={theme} variant="primary" label="Copy code" onPress={() => void copyText(invite.code).then(() => toast.show("Invite code copied", { variant: "success" }))} />
              </View>
            </View>
          ) : (
            <View style={styles.row}>
              <Button theme={theme} variant="primary" label="Create invite" busy={inviteM.isPending} onPress={() => inviteM.mutate(m.data.lane.id)} />
            </View>
          )}
        </View>
      )}
    </ScrollView>
  );
}
