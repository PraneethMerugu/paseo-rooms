// Member side of room sessions (implementation plan I-8; enrollment-v2.md 3.3 to 3.6, 4.1;
// room-log-v2.md 6 and 8.3).
//
// - Connects to the relay as a client for the room endpoint's serverId, runs Noise IK as the
//   initiator with the room prologue and the endpoint static from the signed authority state, and
//   sends `session.hello` at once (this first transport message is the key confirmation, S-10).
// - Keeps a verified copy of the log: every entry goes through the same fold as the host's
//   (server/authority/fold.ts), so a bad hash, link, host signature or statement stops processing
//   with `invalid_entry`.
// - Head comparison (room-log-v2 6.1, 6.4): a host head below the highest signed entry this member
//   verified is `truncation`; a different signed entry at a seq it already holds is `fork` with the
//   two entries as the equivocation proof. Then `log.fetch` to the head and `log.subscribe`.
// - Gossip checks of 6.3 (`checkPeerHead`): `fork` only with proof, else `unverified_head_claim`
//   attributed to the sender; `withholding` with proof when the host does not serve an entry it
//   signed. Peer evidence (MLS `log.evidence.request`, I-13) is supplied by the caller.
// - Section 3.5 timers: ping after 30 s of silence, close after 90 s, reconnect before 12 h.
//
// Not here: persistence of the verified copy and receipts (the member journal, I-9), MLS gossip
// transport (I-13), and the UI for alerts (I-14). Alerts are kept in memory and passed to `onAlert`.
import WebSocket from "ws";
import { z } from "zod";
import { isEquivocationProof, SignedEntry as SignedEntrySchema, verifySignedEntry, type SignedEntry } from "../authority/entries";
import { FoldError, RoomLogFold } from "../authority/fold";
import { verifyGenesis, type RoomGenesis } from "../authority/genesis";
import { log } from "../log";
import { NOISE_MAX_MESSAGE_BYTES } from "../noise/cipher-state";
import type { NoiseHandshake, NoiseKeyPair } from "../noise/handshake-state";
import { createRoomIkInitiator, type RoomEndpointBinding } from "../noise/prologue";
import { b64uDecode, b64uDecodeVar } from "../proto/b64u";
import type { Frame } from "../transport/records";
import { relayClientUrl, type RelayAddress } from "../transport/relay-server";
import {
  IK_MESSAGE2_BYTES,
  LOG_FETCH_MAX,
  NON_CLOSING_ERRORS,
  resolveTimings,
  SessionClock,
  SessionCrypto,
  type AccessEndedReason,
  type RoomErrorCode,
  type RoomSessionTimings,
} from "../transport/room-session";
import { RJCS_MAX_FRAME_BYTES } from "../proto/rjcs";

export type RoomAlertType = "fork" | "truncation" | "withholding" | "unverified_head_claim" | "invalid_entry";

export type RoomAlert = {
  type: RoomAlertType;
  roomId: string;
  seq: number;
  at: number;
  /** fork: the two signed entries (an equivocation proof). truncation: maxSignedHead. withholding: the peer's signed entry. */
  proof: SignedEntry[];
  /** unverified_head_claim and peer-sourced alerts: who made the claim. */
  peer?: { memberId: string; deviceId: string };
  /** invalid_entry: the fold reason. */
  reason?: string;
};

export type PeerHeadResult = "consistent" | "fork" | "withholding" | "unverified_head_claim";

export type RoomClientStatus = "idle" | "connecting" | "open" | "closed" | "ended";

export class RoomSessionError extends Error {
  constructor(
    readonly code: RoomErrorCode | "closed" | "handshake_failed" | "timeout",
    readonly fields: Record<string, unknown> = {},
  ) {
    super(`room session: ${code}`);
    this.name = "RoomSessionError";
  }
}

export interface RoomClientOptions {
  /** The room's signed genesis (from the invite; verified here). */
  genesis: RoomGenesis | Uint8Array;
  /** This device's X25519 key pair (the roster's `dh`). */
  device: NoiseKeyPair;
  /** Where the relay is reached. */
  relay: RelayAddress;
  timings?: Partial<RoomSessionTimings>;
  /** Waiting time for peer evidence in gossip checks (6.3: 30 s). */
  evidenceTimeoutMs?: number;
  now?: () => number;
  onAlert?(alert: RoomAlert): void;
  /** Test only: bind the handshake to something else than this room (wrong prologue). */
  bindingOverride?: RoomEndpointBinding;
  /** Test only: inject the first handshake message's ephemeral. */
  ephemeral?: NoiseKeyPair;
}

const HelloOk = z.object({
  t: z.literal("session.hello.ok"),
  serverTime: z.number().int(),
  minVersion: z.number().int(),
  memberId: z.string(),
  deviceId: z.string(),
  head: z.object({ seq: z.number().int().min(0), hash: z.string(), hsig: z.string() }).nullable(),
  lastAck: z.unknown(),
});
export type HelloOk = z.infer<typeof HelloOk>;

const EntriesReply = z.object({
  entries: z.array(z.unknown()).max(LOG_FETCH_MAX),
  bodies: z.array(z.object({ seq: z.number().int().min(0), body: z.string() })).max(LOG_FETCH_MAX),
  head: z.unknown(),
});

type Pending = { resolve(frame: Frame): void; reject(err: Error): void; timer: ReturnType<typeof setTimeout> };

export class RoomClient {
  readonly roomId: string;
  readonly genesisHash: string;
  readonly timings: RoomSessionTimings;
  status: RoomClientStatus = "idle";
  /** Last error code from the host, if any. */
  lastError: RoomErrorCode | "handshake_failed" | "closed" | null = null;
  endedReason: AccessEndedReason | null = null;
  /** Extra fields of the last closing error (section 10). */
  lastErrorFields: Record<string, unknown> = {};
  hello: HelloOk | null = null;
  readonly alerts: RoomAlert[] = [];
  /** Set by fork, truncation and invalid_entry: stop sending application messages, keep reading (6.6). */
  sendingStopped = false;
  private readonly fold: RoomLogFold;
  private readonly chain: SignedEntry[] = [];
  /** No further entries are processed after an invalid one (6.6). */
  private processingStopped = false;
  private ws: WebSocket | null = null;
  private crypto: SessionCrypto | null = null;
  private clock: SessionClock | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private syncing: Promise<void> = Promise.resolve();
  private readonly now: () => number;

  constructor(private readonly o: RoomClientOptions) {
    const v = verifyGenesis(o.genesis);
    this.roomId = v.roomId;
    this.genesisHash = v.genesisHash;
    this.fold = RoomLogFold.fromGenesis(v.genesis);
    this.timings = resolveTimings(o.timings);
    this.now = o.now ?? Date.now;
  }

  /** Own verified head: `{-1, genesisHash}` before the first entry. */
  get head(): { seq: number; hash: string } {
    return this.fold.head;
  }

  /** Highest signed entry this member verified. */
  get maxSignedHead(): SignedEntry | null {
    return this.chain.at(-1) ?? null;
  }

  get state() {
    return this.fold.state;
  }

  entry(seq: number): SignedEntry | undefined {
    return this.chain[seq];
  }

  /** Handshake only (pre-auth operations, I-9). Rejects with RoomSessionError. */
  async open(): Promise<void> {
    if (this.status === "connecting" || this.status === "open") throw new Error("room client already connected");
    this.status = "connecting";
    this.lastError = null;
    this.lastErrorFields = {};
    try {
      await this.handshake();
    } catch (err) {
      this.close();
      throw err;
    }
  }

  /** Opens the session, compares heads, syncs the log and subscribes. Rejects with RoomSessionError. */
  async connect(): Promise<HelloOk> {
    if (this.status === "connecting" || this.status === "open") throw new Error("room client already connected");
    this.status = "connecting";
    this.lastError = null;
    this.lastErrorFields = {};
    try {
      await this.handshake();
      const hello = HelloOk.parse(await this.request({ t: "session.hello", v: 2, known: { logSeq: this.head.seq, logHash: this.head.hash } }));
      this.hello = hello;
      this.status = "open";
      await this.compareHead(hello.head);
      await this.sync();
      await this.request({ t: "log.subscribe", fromSeq: this.head.seq + 1 });
      log("room_client_open", { roomId: this.roomId, head: this.head.seq, deviceId: hello.deviceId });
      return hello;
    } catch (err) {
      this.close();
      if (err instanceof RoomSessionError) {
        if (err.code === "access_ended") this.status = "ended";
        throw err;
      }
      throw err instanceof z.ZodError ? new RoomSessionError("bad_frame") : err;
    }
  }

  close(): void {
    this.clock?.stop();
    this.clock = null;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new RoomSessionError(this.lastError ?? "closed", this.lastErrorFields));
    }
    this.pending.clear();
    try {
      this.ws?.close(1000, "closed");
    } catch {}
    this.ws = null;
    this.crypto = null;
    if (this.status !== "ended") this.status = "closed";
  }

  /** One request frame; resolves with the reply, rejects with RoomSessionError on `error`. */
  request(frame: Omit<Frame, "id">, timeoutMs = 30_000): Promise<Frame> {
    if (!this.crypto) return Promise.reject(new RoomSessionError("closed"));
    const id = this.nextId++;
    return new Promise<Frame>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new RoomSessionError("timeout"));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.send({ ...frame, id } as Frame);
    });
  }

  /** `log.fetch` of one range, entries verified only as signed entries (not folded). */
  async fetch(fromSeq: number, toSeq?: number, limit = LOG_FETCH_MAX): Promise<{ entries: unknown[]; bodies: Map<number, Uint8Array>; head: unknown }> {
    const reply = EntriesReply.parse(await this.request({ t: "log.fetch", fromSeq, ...(toSeq === undefined ? {} : { toSeq }), limit, bodies: "stmt" }));
    const bodies = new Map<number, Uint8Array>();
    for (const b of reply.bodies) bodies.set(b.seq, new Uint8Array(b64uDecodeVar(b.body, RJCS_MAX_FRAME_BYTES)));
    return { entries: reply.entries, bodies, head: reply.head };
  }

  /** Fetches from the own head to the host's head and folds every entry. */
  sync(): Promise<void> {
    const run = this.syncing.then(() => this.syncNow());
    this.syncing = run.catch(() => undefined);
    return run;
  }

  /**
   * Section 6.3: a head `(s, h_s)` gossiped by peer P. `evidence` asks P for its signed entry at `s`
   * (MLS `log.evidence.request`, I-13); it may resolve null. Returns the outcome; alerts are raised.
   */
  async checkPeerHead(peer: { memberId: string; deviceId: string }, s: number, hs: string, evidence?: () => Promise<unknown | null>): Promise<PeerHeadResult> {
    const own = this.head.seq;
    if (s <= own) {
      const mine = this.chain[s];
      if (mine.hash === hs) return "consistent";
      // Ask the host for its entry at s, and P for its signed entry.
      const fromHost = await this.fetch(s, s, 1).catch(() => null);
      const hostEntry = fromHost?.entries[0];
      if (hostEntry && this.validAt(hostEntry, s) && (hostEntry as SignedEntry).hash === hs) return this.raiseFork(s, mine, hostEntry as SignedEntry, peer);
      const peerEntry = await this.askPeer(evidence);
      if (peerEntry && this.validAt(peerEntry, s) && (peerEntry as SignedEntry).hash === hs) return this.raiseFork(s, mine, peerEntry as SignedEntry, peer);
      return this.raiseUnverified(s, peer);
    }
    await this.sync().catch(() => undefined);
    const at = this.chain[s];
    if (at && at.hash === hs) return "consistent";
    const peerEntry = await this.askPeer(evidence);
    if (peerEntry && this.validAt(peerEntry, s) && (peerEntry as SignedEntry).hash === hs) {
      if (at) return this.raiseFork(s, at, peerEntry as SignedEntry, peer);
      // The host signed an entry at s that it does not serve.
      this.raise({ type: "withholding", roomId: this.roomId, seq: s, at: this.now(), proof: [peerEntry as SignedEntry], peer });
      return "withholding";
    }
    return this.raiseUnverified(s, peer);
  }

  // ------------------------------------------------------------------------------- internals

  private handshake(): Promise<void> {
    const auth = this.fold.state.auth.endpoint;
    const binding: RoomEndpointBinding = this.o.bindingOverride ?? { genesisHash: b64uDecode(this.genesisHash, 32), serverId: auth.serverId };
    let hs: NoiseHandshake;
    try {
      hs = createRoomIkInitiator({ binding, endpointStatic: b64uDecode(auth.dh.pub, 32), deviceStatic: this.o.device, ephemeral: this.o.ephemeral });
    } catch {
      return Promise.reject(new RoomSessionError("handshake_failed"));
    }
    const ws = new WebSocket(relayClientUrl(this.o.relay, auth.serverId), { perMessageDeflate: false, maxPayload: NOISE_MAX_MESSAGE_BYTES });
    this.ws = ws;
    return new Promise<void>((resolve, reject) => {
      let done = false;
      const finish = (err?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (err) {
          this.lastError = "handshake_failed";
          reject(err);
        } else resolve();
      };
      const timer = setTimeout(() => finish(new RoomSessionError("handshake_failed", { why: "timeout" })), this.timings.handshakeTimeoutMs);
      ws.on("open", () => {
        try {
          ws.send(hs.writeMessage(new Uint8Array(0)), { binary: true });
        } catch {
          finish(new RoomSessionError("handshake_failed"));
        }
      });
      ws.on("message", (data, isBinary) => {
        const bytes = new Uint8Array(Array.isArray(data) ? Buffer.concat(data) : (data as Buffer));
        if (!this.crypto) {
          if (!isBinary || bytes.byteLength !== IK_MESSAGE2_BYTES) return finish(new RoomSessionError("handshake_failed"));
          try {
            hs.readMessage(bytes);
            const keys = hs.split();
            this.crypto = new SessionCrypto(keys.send, keys.receive);
          } catch {
            return finish(new RoomSessionError("handshake_failed"));
          }
          this.clock = new SessionClock(this.timings, this.now, {
            onPing: () => this.send({ t: "ping" }),
            onIdle: () => this.drop("closed"),
            onExpire: () => this.drop("closed"),
          });
          return finish();
        }
        if (!isBinary) return this.drop("bad_frame");
        this.onTransport(bytes);
      });
      ws.on("close", () => {
        finish(new RoomSessionError("handshake_failed", { why: "closed" }));
        this.drop(this.lastError ?? "closed");
      });
      ws.on("error", () => undefined);
    });
  }

  private onTransport(bytes: Uint8Array): void {
    let frame: Frame | null;
    try {
      frame = this.crypto!.open(bytes);
    } catch {
      return this.drop("bad_frame");
    }
    this.clock?.received();
    if (!frame) return;
    if (frame.t === "ping") return this.send({ t: "pong" });
    if (frame.t === "pong") return;
    if (frame.t === "error") return this.onError(frame);
    if (frame.t === "log.entries") {
      void this.onPush(frame).catch((e) => log("room_client_push_failed", { roomId: this.roomId, error: String((e as Error).message).slice(0, 200) }));
      return;
    }
    if (isReply(frame)) {
      const p = this.pending.get(frame.re!);
      if (!p) return;
      this.pending.delete(frame.re!);
      clearTimeout(p.timer);
      p.resolve(frame);
    }
  }

  private onError(frame: Frame): void {
    const code = frame.code as RoomErrorCode;
    const { t: _t, re, code: _c, ...fields } = frame;
    if (code === "access_ended") {
      this.endedReason = (fields.reason as AccessEndedReason) ?? null;
      this.status = "ended";
    }
    const err = new RoomSessionError(code, fields as Record<string, unknown>);
    const p = re === undefined ? undefined : this.pending.get(re);
    if (p) {
      this.pending.delete(re!);
      clearTimeout(p.timer);
      p.reject(err);
    }
    if (!NON_CLOSING_ERRORS.has(code)) {
      this.lastError = code;
      this.lastErrorFields = fields as Record<string, unknown>;
      log("room_client_error", { roomId: this.roomId, code, ...(code === "access_ended" ? { reason: this.endedReason } : {}) });
      this.drop(code);
    }
  }

  private drop(code: RoomErrorCode | "closed" | "handshake_failed"): void {
    if (code !== "closed") this.lastError = code;
    if (this.ws || this.crypto) this.close();
  }

  private send(frame: Frame): void {
    if (!this.crypto || this.ws?.readyState !== WebSocket.OPEN) return;
    for (const m of this.crypto.seal(frame)) this.ws.send(m, { binary: true });
  }

  /** Section 6.1 and 6.4 on the host's head from session.hello. */
  private async compareHead(head: HelloOk["head"]): Promise<void> {
    const max = this.maxSignedHead;
    if (head === null) {
      if (max) this.raise({ type: "truncation", roomId: this.roomId, seq: max.entry.seq, at: this.now(), proof: [max] });
      return;
    }
    if (max && head.seq < max.entry.seq) this.raise({ type: "truncation", roomId: this.roomId, seq: max.entry.seq, at: this.now(), proof: [max] });
    const mine = this.chain[head.seq];
    if (mine && mine.hash !== head.hash) {
      const got = await this.fetch(head.seq, head.seq, 1).catch(() => null);
      const theirs = got?.entries[0];
      if (theirs && this.validAt(theirs, head.seq) && (theirs as SignedEntry).hash !== mine.hash) this.raiseFork(head.seq, mine, theirs as SignedEntry);
    }
  }

  private async syncNow(): Promise<void> {
    for (let guard = 0; guard < 100_000 && !this.processingStopped; guard++) {
      const own = this.head.seq;
      // Overlap one entry: the host's chain must still contain our head (6.4).
      const from = Math.max(0, own);
      const page = await this.fetch(from, undefined, LOG_FETCH_MAX);
      const hostHead = this.parseHead(page.head);
      const max = this.maxSignedHead;
      if (max && (hostHead === null || hostHead.entry.seq < max.entry.seq)) {
        this.raise({ type: "truncation", roomId: this.roomId, seq: max.entry.seq, at: this.now(), proof: [max] });
        return;
      }
      let entries = page.entries;
      if (own >= 0) {
        const first = entries[0];
        if (!first) return this.raise({ type: "truncation", roomId: this.roomId, seq: own, at: this.now(), proof: [this.chain[own]] });
        if ((first as SignedEntry).hash !== this.chain[own].hash) {
          if (this.validAt(first, own)) this.raiseFork(own, this.chain[own], first as SignedEntry);
          else this.raise({ type: "truncation", roomId: this.roomId, seq: own, at: this.now(), proof: [this.chain[own]] });
          return;
        }
        entries = entries.slice(1);
      }
      this.ingest(entries, page.bodies);
      if (entries.length === 0 || hostHead === null || this.head.seq >= hostHead.entry.seq) return;
    }
  }

  private async onPush(frame: Frame): Promise<void> {
    const reply = EntriesReply.parse(frame);
    const bodies = new Map<number, Uint8Array>();
    for (const b of reply.bodies) bodies.set(b.seq, new Uint8Array(b64uDecodeVar(b.body, RJCS_MAX_FRAME_BYTES)));
    await this.syncing;
    const first = reply.entries[0] as SignedEntry | undefined;
    if (!first) return;
    const seq = (first as { entry?: { seq?: number } }).entry?.seq ?? -1;
    if (seq > this.head.seq + 1) return void (await this.sync());
    const fresh: unknown[] = [];
    for (const e of reply.entries) {
      const s = (e as { entry?: { seq?: number } }).entry?.seq ?? -1;
      if (s <= this.head.seq) {
        const mine = this.chain[s];
        if (mine && (e as SignedEntry).hash !== mine.hash && this.validAt(e, s)) this.raiseFork(s, mine, e as SignedEntry);
        continue;
      }
      fresh.push(e);
    }
    this.ingest(fresh, bodies);
  }

  /** Folds entries in order; the first that fails raises `invalid_entry` and stops processing. */
  private ingest(entries: unknown[], bodies: Map<number, Uint8Array>): void {
    for (const e of entries) {
      if (this.processingStopped) return;
      const seq = this.head.seq + 1;
      try {
        this.fold.append(e, bodies.get(seq));
      } catch (err) {
        if (!(err instanceof FoldError)) throw err;
        this.processingStopped = true;
        this.raise({ type: "invalid_entry", roomId: this.roomId, seq, at: this.now(), proof: [], reason: err.reason });
        return;
      }
      this.chain.push(SignedEntrySchema.parse(e));
    }
  }

  private parseHead(value: unknown): SignedEntry | null {
    const p = SignedEntrySchema.safeParse(value);
    return p.success ? p.data : null;
  }

  /** A signed entry with a correct hash and a valid hsig by a host key valid at `seq` (own fold's view). */
  private validAt(value: unknown, seq: number): boolean {
    try {
      return verifySignedEntry(value, this.fold.hostKeyAt).entry.seq === seq;
    } catch {
      return false;
    }
  }

  private async askPeer(evidence?: () => Promise<unknown | null>): Promise<unknown | null> {
    if (!evidence) return null;
    const timeout = this.o.evidenceTimeoutMs ?? 30_000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([evidence().catch(() => null), new Promise<null>((r) => (timer = setTimeout(() => r(null), timeout)))]);
    } finally {
      clearTimeout(timer);
    }
  }

  private raiseFork(seq: number, a: SignedEntry, b: SignedEntry, peer?: { memberId: string; deviceId: string }): PeerHeadResult {
    if (!isEquivocationProof(a, b, this.fold.hostKeyAt)) return "unverified_head_claim";
    this.raise({ type: "fork", roomId: this.roomId, seq, at: this.now(), proof: [a, b], ...(peer ? { peer } : {}) });
    return "fork";
  }

  private raiseUnverified(seq: number, peer: { memberId: string; deviceId: string }): PeerHeadResult {
    this.raise({ type: "unverified_head_claim", roomId: this.roomId, seq, at: this.now(), proof: [], peer });
    return "unverified_head_claim";
  }

  private raise(a: RoomAlert): void {
    if (a.type === "fork" || a.type === "truncation" || a.type === "invalid_entry") this.sendingStopped = true;
    this.alerts.push(a);
    log("room_alert", { roomId: this.roomId, type: a.type, seq: a.seq, ...(a.peer ? { peerDevice: a.peer.deviceId } : {}) });
    this.o.onAlert?.(a);
  }
}

function isReply(frame: Frame): boolean {
  return typeof frame.re === "number" && frame.t.endsWith(".ok");
}
