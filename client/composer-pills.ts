// "● Room · N connected" pill on agents that are room lanes (owner side).
import type { PluginButtonRegistration, PluginClientContext } from "@getpaseo/plugin/client";
import { roomsLaneAgents } from "../shared/rpc";

const REFRESH_MS = 10_000;

export function contributeLanePills(client: PluginClientContext): () => void {
  const lifetime = new AbortController();
  const pills = new Map<string, { reg: PluginButtonRegistration; label: string }>();
  const workspaces = new Map<string, string>();
  let lanes = new Map<string, { roomName: string; connected: number }>();

  const sync = () => {
    if (lifetime.signal.aborted) return;
    for (const [agentId, pill] of pills)
      if (!lanes.has(agentId) || !workspaces.has(agentId)) {
        pill.reg.remove();
        pills.delete(agentId);
      }
    for (const [agentId, lane] of lanes) {
      const workspaceId = workspaces.get(agentId);
      if (!workspaceId) continue;
      const label = `● Room · ${lane.connected} connected`;
      const existing = pills.get(agentId);
      if (existing) {
        if (existing.label !== label) {
          existing.reg.update({ label, title: `${lane.roomName}: ${lane.connected} member(s) connected` });
          existing.label = label;
        }
        continue;
      }
      const reg = client.addComposerPill({
        id: "room-lane",
        workspaceId,
        agentId,
        button: {
          title: `${lane.roomName}: ${lane.connected} member(s) connected`,
          icon: "Users",
          label,
          behavior: { kind: "action", onPress: () => client.openScreen({ screenId: "rooms" }) },
        },
      });
      pills.set(agentId, { reg, label });
    }
  };

  const refreshLanes = async () => {
    try {
      const r = await client.rpc(roomsLaneAgents, {});
      lanes = new Map(r.lanes.map((l) => [l.agentId, { roomName: l.roomName, connected: l.connectedMembers }]));
      sync();
    } catch {
      // Host without the plugin running, or offline: show no pills.
    }
  };

  void client.paseo.agents
    .list({ subscribe: {}, signal: lifetime.signal })
    .then(({ subscription }) => {
      subscription.subscribe({
        snapshot: ({ entries }) => {
          workspaces.clear();
          for (const { agent } of entries) if (agent.workspaceId) workspaces.set(agent.id, agent.workspaceId);
          void refreshLanes();
        },
        update: (message) => {
          if (message.type !== "agent_update") return;
          const u = message.payload;
          if (u.kind === "upsert") {
            if (u.agent.workspaceId) workspaces.set(u.agent.id, u.agent.workspaceId);
            if (!lanes.has(u.agent.id)) void refreshLanes();
          } else workspaces.delete(u.agentId);
          sync();
        },
      });
      return undefined;
    })
    .catch(() => undefined);
  const timer = setInterval(() => void refreshLanes(), REFRESH_MS);

  return () => {
    lifetime.abort();
    clearInterval(timer);
    for (const p of pills.values()) p.reg.remove();
    pills.clear();
  };
}
