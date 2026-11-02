import type { PluginClientContext, PluginSidebarItemProps } from "@getpaseo/plugin/client";
import { useRpc } from "@getpaseo/plugin/client";
import { SidebarRow } from "@getpaseo/plugin/client/ui";
import { useEffect, useState } from "react";
import { Text, View } from "react-native";
import { contributeLanePills } from "./client/composer-pills";
import { OpenRoomV2Screen, RoomsV2Screen } from "./client/v2-screen";
import { roomsBootstrap, roomsLaneAgents } from "./shared/rpc";
import { roomsV2ChatUnread } from "./shared/rpc-v2";

/** R3.4: unread chat messages of every room on this daemon (counts only), polled every 5 s. */
function useChatUnread(): number {
  const unread = useRpc(roomsV2ChatUnread);
  const [total, setTotal] = useState(0);
  useEffect(() => {
    let live = true;
    const tick = () =>
      void unread({})
        .then((r) => live && setTotal(r.total))
        .catch(() => live && setTotal(0));
    tick();
    const t = setInterval(tick, 5000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  return total;
}

function RoomsSidebarItem({ currentScreen, openScreen, theme }: PluginSidebarItemProps) {
  const unread = useChatUnread();
  const badge =
    unread > 0 ? (
      <View accessibilityLabel={`${unread} unread chat messages`} style={{ minWidth: 18, paddingHorizontal: 5, borderRadius: 9, backgroundColor: theme.colors.accent, alignItems: "center" }}>
        <Text style={{ color: theme.colors.accentForeground, fontSize: 11, fontWeight: "600" }}>{unread > 99 ? "99+" : String(unread)}</Text>
      </View>
    ) : undefined;
  return <SidebarRow icon="Users" label="Rooms" active={currentScreen?.screenId === "rooms"} onPress={() => openScreen({ screenId: "rooms" })} trailing={badge} />;
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
