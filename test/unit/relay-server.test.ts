// The relay code extracted from the M1 lane endpoint (server/transport/relay-server.ts, I-8) still
// carries the lane's Noise NK channel: a client reaches a LaneConnection through the fake relay and
// completes Paseo's protected handshake. Loopback only; no daemon (the first frame is refused).
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { openClientSecureChannel, type Transport } from "@getpaseo/relay/e2ee";
import { LaneEndpoint } from "../../server/gateway/lane-endpoint";
import { HostStore } from "../../server/host/host-store";
import { parseRelayNotice, relayClientUrl, relayServerUrl } from "../../server/transport/relay-server";
import { startFakeRelay, until } from "./fake-relay";
import { tempDir } from "./helpers";

test("relay URLs and notices keep the M1 shapes", () => {
  const relay = { endpoint: "relay.example:443", useTls: true };
  assert.equal(relayServerUrl(relay, "srv"), "wss://relay.example/ws?serverId=srv&role=server&v=2");
  assert.equal(relayServerUrl(relay, "srv", "c1"), "wss://relay.example/ws?serverId=srv&role=server&v=2&connectionId=c1");
  assert.equal(relayClientUrl({ endpoint: "127.0.0.1:6923", useTls: false }, "srv"), "ws://127.0.0.1:6923/ws?serverId=srv&role=client&v=2");
  assert.deepEqual(parseRelayNotice({ type: "sync", connectionIds: ["a", "b"] }), { disconnected: null, announced: ["a", "b"] });
  assert.deepEqual(parseRelayNotice({ type: "connected", connectionId: "a" }), { disconnected: null, announced: ["a"] });
  assert.deepEqual(parseRelayNotice({ type: "disconnected", connectionId: "a" }), { disconnected: "a", announced: [] });
  assert.deepEqual(parseRelayNotice({ type: "sync", connectionIds: "x" }), { disconnected: null, announced: [] });
});

test("lane endpoint over the extracted relay connection: NK handshake through the fake relay", async () => {
  const relay = await startFakeRelay();
  const tmp = tempDir();
  const host = new HostStore(tmp.dir, { endpoint: relay.endpoint, useTls: false });
  try {
    const room = host.createRoom("Lab");
    const lane = host.createLane({ roomId: room.id, label: "Live", origin: { kind: "share", agentId: "agent-1" }, agentId: "agent-1", workspaceId: "wks_1" });
    const ep = new LaneEndpoint(lane, { host, paseoHome: tmp.dir });
    assert.equal(ep.relayUrl("c1"), `ws://${relay.endpoint}/ws?serverId=${lane.serverId}&role=server&v=2&connectionId=c1`);

    // A member daemon connects as a client; the relay names the connection; the endpoint is told.
    const ws = new WebSocket(relayClientUrl({ endpoint: relay.endpoint, useTls: false }, lane.serverId), { perMessageDeflate: false });
    await new Promise<void>((r) => ws.once("open", () => r()));
    const connectionId = await until("client connection", () => relay.clientConnections(lane.serverId)[0]);
    const transport: Transport = { send: (d) => void ws.send(d), close: (c, r) => ws.close(c, r), onmessage: null, onclose: null, onerror: null };
    ws.on("message", (d, isBinary) => transport.onmessage?.({ data: isBinary ? new Uint8Array(d as Buffer).slice().buffer : (d as Buffer).toString("utf8"), isBinary }));
    ws.on("close", (c, r) => transport.onclose?.(c, r.toString()));
    const channelP = openClientSecureChannel(transport, { daemonPublicKeyB64: host.laneKeys(lane.id)!.publicKeyB64, minimumMode: "protected" });
    ep.onRelayControl({ type: "connected", connectionId });
    const channel = await channelP;
    const conn = ep.connections.get(connectionId)!;
    await until("server side channel", () => conn.channel);

    // An unexpected first frame closes the connection, as in M1.
    const closed = new Promise<void>((r) => ws.once("close", () => r()));
    await channel.send(JSON.stringify({ type: "nonsense" }));
    await closed;
    await until("connection removed", () => !ep.connections.has(connectionId));
    await ep.stop();
  } finally {
    host.dispose();
    await relay.close();
    tmp.cleanup();
  }
});
