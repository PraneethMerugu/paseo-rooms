import type { PluginClientContext, PluginSidebarItemProps } from "@getpaseo/plugin/client";
import { SidebarRow } from "@getpaseo/plugin/client/ui";
import { contributeLanePills } from "./client/composer-pills";
import { OpenRoomScreen } from "./client/open-room-screen";
import { RoomsScreen } from "./client/rooms-screen";
import { roomsBootstrap, roomsLaneAgents } from "./shared/rpc";

function RoomsSidebarItem({ currentScreen, openScreen }: PluginSidebarItemProps) {
  return <SidebarRow icon="Users" label="Rooms" active={currentScreen?.screenId === "rooms"} onPress={() => openScreen({ screenId: "rooms" })} />;
}

export default function contribute(client: PluginClientContext) {
  // Hands the daemon-side plugin its PaseoApi early (member host observation starts on first contact).
  void client.rpc(roomsBootstrap, {}).catch(() => undefined);
  client.addScreen({ id: "rooms", title: "Rooms", Component: RoomsScreen });
  client.addScreen({ id: "open-room", title: "Open room", Component: OpenRoomScreen });
  client.addSidebarHeaderItem({ id: "rooms", title: "Rooms", Component: RoomsSidebarItem });
  client.addCommandCenterItem({
    id: "open-room",
    title: "Open room…",
    icon: "Users",
    context: "agent",
    keywords: ["room", "share", "invite", "fork", "collaborate"],
    // The 0.13.2 Command Center has no per-agent visibility predicate, so the item cannot be hidden on
    // agents that already are lanes; selecting it there opens Rooms instead of the create screen.
    async onSelect({ agent, openScreen, rpc }) {
      const lanes = await rpc(roomsLaneAgents, {}).catch(() => null);
      if (lanes?.lanes.some((l) => l.agentId === agent.id)) openScreen({ screenId: "rooms" });
      else openScreen({ screenId: "open-room", params: { agentId: agent.id } });
    },
  });
  const removePills = contributeLanePills(client);
  return () => removePills();
}
