// Member side of the rooms control protocol v1. Opens a protected relay channel to the lane
// endpoint (Noise NK to the lane key pinned in the invite), proves possession of the device key,
// and returns the gateway's result. Never logs tokens, grants or signatures.
import WebSocket from "ws";
import { openClientSecureChannel, type SecureChannel, type Transport } from "@getpaseo/relay/e2ee";
import { buildRelayWebSocketUrl } from "@getpaseo/protocol/daemon-endpoints";
import { ControlChallenge, ControlError, ControlResult, type ControlOp } from "../../shared/control";
import type { InvitePayload } from "../../shared/schemas";
import { sha256Hex, signEd25519, type StoredEd25519Key } from "../crypto";
import { verifyGrant } from "../grants";
import { HostStore } from "../host/host-store";

export type LaneOffer = InvitePayload["offer"];
export type PinnedHost = InvitePayload["host"];

export class ControlClientError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

export interface ControlRequest {
  op: ControlOp;
  laneId: string;
  offer: LaneOffer;
  host: PinnedHost;
  device: StoredEd25519Key;
  token?: string;
  label?: string;
  daemonServerId?: string | null;
  timeoutMs?: number;
}

export type ControlResultFrame = ReturnType<typeof ControlResult.parse>;

function describeSocketError(e: unknown): string {
  const err = e as { message?: string; code?: string; errors?: Array<{ code?: string; message?: string }> };
  const inner = err?.errors?.map((x) => x.code ?? x.message).filter(Boolean).join(", ");
  return [err?.message, err?.code, inner].filter((x) => x && String(x).trim()).join(" ") || "relay connection failed";
}

/** Retries only failures that happened before the relay socket opened (nothing was sent). */
export async function controlRequest(req: ControlRequest): Promise<ControlResultFrame> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await controlRequestOnce(req);
    } catch (e) {
      lastError = e;
      if (!(e instanceof ControlClientError) || e.code !== "connect") throw e;
      await new Promise((r) => setTimeout(r, 750 * (attempt + 1)));
    }
  }
  throw lastError;
}

async function controlRequestOnce(req: ControlRequest): Promise<ControlResultFrame> {
  const url = buildRelayWebSocketUrl({
    endpoint: req.offer.relay.endpoint,
    useTls: req.offer.relay.useTls,
    serverId: req.offer.serverId,
    role: "client",
    version: "2",
  });
  const ws = new WebSocket(url, { perMessageDeflate: false });
  const timeoutMs = req.timeoutMs ?? 20_000;
  try {
    return await new Promise<ControlResultFrame>((resolve, reject) => {
      const timer = setTimeout(() => reject(new ControlClientError("timeout", "Lane endpoint did not answer (is the owner's daemon online?)")), timeoutMs);
      const done = (fn: () => void) => {
        clearTimeout(timer);
        fn();
      };
      let channelP: Promise<SecureChannel> | null = null;
      let opened = false;
      let stage: "challenge" | "result" = "challenge";
      const transport: Transport = {
        send: (data) => new Promise<void>((res, rej) => ws.send(data, (e) => (e ? rej(e) : res()))),
        close: (c, r) => ws.close(c, r),
        onmessage: null,
        onclose: null,
        onerror: null,
      };
      ws.on("message", (data, isBinary) =>
        transport.onmessage?.({ data: isBinary ? new Uint8Array(data as Buffer).slice().buffer : (data as Buffer).toString("utf8"), isBinary }),
      );
      ws.on("close", (c, r) => {
        transport.onclose?.(c, r.toString());
        done(() => reject(new ControlClientError(opened ? "closed" : "connect", `Lane channel closed (${c})`)));
      });
      ws.on("error", (e) => {
        transport.onerror?.(e);
        done(() => reject(new ControlClientError(opened ? "network" : "connect", `Could not reach the lane: ${describeSocketError(e)}`)));
      });
      const send = (obj: unknown) => void channelP?.then((ch) => ch.send(JSON.stringify(obj))).catch(() => undefined);
      ws.once("open", () => {
        opened = true;
        channelP = openClientSecureChannel(transport, {
          daemonPublicKeyB64: req.offer.publicKeyB64,
          minimumMode: "protected",
          events: {
            onopen: () =>
              send({ type: "rooms.control.hello", v: 1, op: req.op, laneId: req.laneId, devicePublicKey: req.device.publicKey }),
            onmessage: (data) => {
              if (typeof data !== "string") return;
              let msg: unknown;
              try {
                msg = JSON.parse(data);
              } catch {
                return;
              }
              const err = ControlError.safeParse(msg);
              if (err.success) return done(() => reject(new ControlClientError(err.data.code, err.data.message)));
              if (stage === "challenge") {
                const ch = ControlChallenge.safeParse(msg);
                if (!ch.success) return done(() => reject(new ControlClientError("bad_frame", "Unexpected frame from lane")));
                if (ch.data.laneServerId !== req.offer.serverId || ch.data.hostKeyId !== req.host.keyId)
                  return done(() => reject(new ControlClientError("identity_mismatch", "Lane or host identity does not match the pinned invite")));
                const tokenHash = req.token ? sha256Hex(req.token) : null;
                const transcript = HostStore.transcript({
                  op: req.op,
                  laneId: req.laneId,
                  laneServerId: ch.data.laneServerId,
                  hostKeyId: ch.data.hostKeyId,
                  nonce: ch.data.nonce,
                  devicePublicKey: req.device.publicKey,
                  tokenHash,
                  daemonServerId: req.daemonServerId ?? null,
                  label: req.label ?? null,
                });
                stage = "result";
                send({
                  type: "rooms.control.proof",
                  v: 1,
                  sig: signEd25519(req.device, transcript),
                  ...(req.token ? { token: req.token } : {}),
                  ...(req.label ? { label: req.label } : {}),
                  ...(req.daemonServerId !== undefined ? { daemonServerId: req.daemonServerId } : {}),
                });
                return;
              }
              const res = ControlResult.safeParse(msg);
              if (!res.success) return done(() => reject(new ControlClientError("bad_frame", "Malformed result from lane")));
              if (res.data.grant) {
                const check = verifyGrant(res.data.grant, {
                  hostPublicKey: req.host.publicKey,
                  hostKeyId: req.host.keyId,
                  laneId: req.laneId,
                  laneServerId: req.offer.serverId,
                });
                if (!check.ok) return done(() => reject(new ControlClientError("bad_grant", `Grant from lane failed verification (${check.reason})`)));
                if (check.claims.dev !== req.device.keyId) return done(() => reject(new ControlClientError("bad_grant", "Grant is bound to another device")));
              }
              done(() => resolve(res.data));
            },
            onclose: () => undefined,
            onerror: () => undefined,
          },
        });
        channelP.catch((e) => done(() => reject(new ControlClientError("handshake", (e as Error).message))));
      });
    });
  } finally {
    try {
      ws.close();
    } catch {}
  }
}
