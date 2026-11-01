import type { PluginClientContext, PluginSidebarItemProps } from "@getpaseo/plugin/client";
import { SidebarRow } from "@getpaseo/plugin/client/ui";
import { contributeLanePills } from "./client/composer-pills";
import { OpenRoomV2Screen, RoomsV2Screen } from "./client/v2-screen";
import { roomsBootstrap, roomsLaneAgents } from "./shared/rpc";

function RoomsSidebarItem({ currentScreen, openScreen }: PluginSidebarItemProps) {
  return <SidebarRow icon="Users" label="Rooms" active={currentScreen?.screenId === "rooms"} onPress={() => openScreen({ screenId: "rooms" })} />;
}

export default function contribute(client: PluginClientContext) {
  // Hands the daemon-side plugin its PaseoApi early (lane registration and the M1 clean-up need it).
  void client.rpc(roomsBootstrap, {}).catch(() => undefined);
  client.addScreen({ id: "rooms", title: "Rooms", Component: RoomsV2Screen });
  client.addScreen({ id: "open-room", title: "Open room", Component: OpenRoomV2Screen });
  client.addSidebarHeaderItem({ id: "rooms", title: "Rooms", Component: RoomsSidebarItem });
  client.addCommandCenterItem({
    id: "open-room",
    title: "Open room…",
    icon: "Users",
    context: "agent",
    keywords: ["room", "share", "invite", "collaborate"],
    // The 0.13.2 Command Center has no per-agent visibility predicate, so the item cannot be hidden on
    // agents that already are lanes; selecting it there opens Rooms instead of the share screen.
    async onSelect({ agent, openScreen, rpc }) {
      const lanes = await rpc(roomsLaneAgents, {}).catch(() => null);
      if (lanes?.lanes.some((l) => l.agentId === agent.id)) openScreen({ screenId: "rooms" });
      else openScreen({ screenId: "open-room", params: { agentId: agent.id } });
    },
  });
  const removePills = contributeLanePills(client);
  return () => removePills();
}
