// Which Rooms runtime the daemon started: "v1" (M1, the default) or "v2" (identity v2 development
// runtime, PASEO_ROOMS_PROTOCOL=v2). Older daemons do not report it, and any failure means M1, so the
// v2 UI appears only when the daemon says so (I-14).
import { useRpc } from "@getpaseo/plugin/client";
import { useQuery } from "@tanstack/react-query";
import { roomsBootstrap } from "../shared/rpc";

export function useRoomsProtocol(): "v1" | "v2" | null {
  const bootstrap = useRpc(roomsBootstrap);
  const q = useQuery({ queryKey: ["rooms", "protocol"], queryFn: () => bootstrap({}), staleTime: 60_000, retry: 1 });
  if (q.isPending) return null;
  return q.data?.protocol === "v2" ? "v2" : "v1";
}
