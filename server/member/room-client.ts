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
// - Pre-admission anchors (enrollment 5.7; round 9, item 3): the signed entries the host showed this
//   device before admission (authority chain, `enroll.held`, `enroll.admitted`) must appear in the
//   fetched log at the same seq with the same hash. A different entry there is `fork` (the two
//   host-signed entries are the equivocation proof); an anchor beyond the host's head once synced is
//   `truncation`. The alert's `reason` names the anchor's source.
// - Section 3.5 timers: ping after 30 s of silence, close after 90 s, reconnect before 12 h.
//
// - Enrollment (I-9) uses the same client before the member has the genesis: `target` names the
//   room and endpoint from the invite; then only `open` and `request` are available, and the
//   session's handshake hash is `handshakeHash`. Frames the host pushes outside a reply
//   (`enroll.admitted`, `enroll.closed`) go to `onPush`.
//
// - `onIngest` hands every accepted entry, with the fold state before and after it, to the MLS member
//   (I-13), which fetches MLS bodies itself with `msg.fetch`.
//
// - Persistence (room-log-v2.md 6.1 and 8.2; roadmap R2.1): with a `store`, the verified chain, its
//   statement bodies, `maxSignedHead`, the receipts of this device's own statements and the alerts that
//   stop sending survive a restart. On construction the stored chain is re-folded from the genesis (every
//   hash, link, hsig and statement checked again); `log.fetch` then resumes from its head. A stored
//   `maxSignedHead` beyond the re-folded chain, and every stored receipt, become anchors: the host's
//   chain must reach them with the same hash (`fork` otherwise, with the two host-signed entries) and
//   its head must not be below them (`truncation`). Local damage (a file that does not open, a chain that
//   does not fold, a head record that disagrees with the chain) raises `local_copy_corrupt`, drops the
//   stored chain and re-verifies everything the host serves against the anchors that are left; two
//   host-signed stored entries at one seq are a `fork`, not damage.
//
// Not here: MLS gossip of log heads
// (`logHead` is sent in every MLS message's authenticated data, but `checkPeerHead` is not yet fed from
// it), and the UI for alerts (I-14). Alerts are kept in memory and passed to `onAlert`.
import WebSocket from "ws";
import { z } from "zod";
import { isEquivocationProof, SignedEntry as SignedEntrySchema, verifySignedEntry, type SignedEntry } from "../authority/entries";
import { FoldError, RoomLogFold, type RoomState } from "../authority/fold";
import { verifyGenesis, type RoomGenesis } from "../authority/genesis";
import { log } from "../log";
import type { LogCopyStore, StoredAlert } from "./log-copy";
import { NOISE_MAX_MESSAGE_BYTES } from "../noise/cipher-state";
import type { NoiseHandshake, NoiseKeyPair } from "../noise/handshake-state";
import { createRoomIkInitiator, type RoomEndpointBinding } from "../noise/prologue";
import { b64u, b64uDecode, b64uDecodeVar } from "../proto/b64u";
import { roomIdOf } from "../proto/ids";
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

export type RoomAlertType = "fork" | "truncation" | "withholding" | "unverified_head_claim" | "invalid_entry" | "local_copy_corrupt";

export type RoomAlert = {
  type: RoomAlertType;
  roomId: string;
  seq: number;
  at: number;
  /** fork: the two signed entries (an equivocation proof). truncation: maxSignedHead. withholding: the peer's signed entry. */
  proof: SignedEntry[];
  /** unverified_head_claim and peer-sourced alerts: who made the claim. */
  peer?: { memberId: string; deviceId: string };
  /**
   * invalid_entry: the fold reason. fork and truncation from an anchor: `<kind>:<source>` (kinds
   * `pre_admission`, `stored`, `receipt`). local_copy_corrupt: what was damaged.
   */
  reason?: string;
  /** Loaded from the stored copy (raised before a restart). */
  restored?: true;
};

/** A host-signed entry the fetched chain must contain at its seq with the same hash. */
export type RoomAnchor = { source: string; signed: SignedEntry; kind?: "pre_admission" | "stored" | "receipt" };

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
  /** The room's signed genesis (verified here). Absent only while enrolling (`target`). */
  genesis?: RoomGenesis | Uint8Array;
  /** Enrollment before the genesis is known: the room and endpoint named by the invite. */
  target?: { genesisHash: string; endpoint: { serverId: string; dh: { pub: string } } };
  /** Frames the host pushes outside a reply (enrollment). */
  onPush?(frame: Frame): void;
  /** This device's X25519 key pair (the roster's `dh`). */
  device: NoiseKeyPair;
  /** Where the relay is reached. */
  relay: RelayAddress;
  timings?: Partial<RoomSessionTimings>;
  /** Waiting time for peer evidence in gossip checks (6.3: 30 s). */
  evidenceTimeoutMs?: number;
  now?: () => number;
  onAlert?(alert: RoomAlert): void;
  /** Every entry the fold accepted, with the fold state before and after it (the MLS member, I-13). */
  onIngest?(signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): void;
  /**
   * The room endpoint to reach when it is newer than the genesis one (keys 4.6): the last endpoint this
   * device verified, or the one a `moved` answer named. The fetched log must then certify it.
   */
  endpoint?: { serverId: string; dh: { pub: string } };
  /** Signed entries received before admission, checked against the fetched log (enrollment 5.7). */
  anchors?: readonly RoomAnchor[];
  /** The verified copy at rest (server/member/log-copy.ts). Without it nothing survives a restart. */
  store?: LogCopyStore;
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
  private fold: RoomLogFold | null;
  /** Handshake hash `h` of the current session (b64u), set once the handshake completed. */
  handshakeHash: string | null = null;
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
  /** Pre-admission, stored and receipt anchors by seq; removed once checked. */
  private readonly anchors = new Map<number, RoomAnchor[]>();
  /** A stored `maxSignedHead` beyond the chain (restart, or a host that has not served it again yet). */
  private storedMax: SignedEntry | null = null;
  /** Statement bodies of the chain (kept only with a store, for the copy at rest). */
  private readonly bodies = new Map<number, Uint8Array>();
  /** Restored entries not yet handed to `onIngest` (done once the session is open, as before). */
  private replay: { signed: SignedEntry; before: Readonly<RoomState>; after: Readonly<RoomState> }[] = [];
  /** Damage found in the stored copy, if any. */
  restoreProblems: string[] = [];

  constructor(private readonly o: RoomClientOptions) {
    if (o.genesis) {
      const v = verifyGenesis(o.genesis);
      this.roomId = v.roomId;
      this.genesisHash = v.genesisHash;
      this.fold = RoomLogFold.fromGenesis(v.genesis);
    } else if (o.target) {
      this.genesisHash = o.target.genesisHash;
      this.roomId = roomIdOf(b64uDecode(o.target.genesisHash, 32));
      this.fold = null;
    } else throw new Error("room client needs a genesis or an enrollment target");
    this.timings = resolveTimings(o.timings);
    this.now = o.now ?? Date.now;
    for (const a of o.anchors ?? []) this.addAnchor(a);
    if (o.store && this.fold) this.restore(o.store);
  }

  /** Pre-admission anchors not yet matched against the fetched log. */
  get uncheckedAnchors(): number {
    return this.anchors.size;
  }

  /** Own verified head: `{-1, genesisHash}` before the first entry. */
  get head(): { seq: number; hash: string } {
    return this.fold ? this.fold.head : { seq: -1, hash: this.genesisHash };
  }

  /** Highest signed entry this member verified (in this process or, with a store, before a restart). */
  get maxSignedHead(): SignedEntry | null {
    const tail = this.chain.at(-1) ?? null;
    return this.storedMax && (!tail || this.storedMax.entry.seq > tail.entry.seq) ? this.storedMax : tail;
  }

  get state() {
    return this.requireFold().state;
  }

  private requireFold(): RoomLogFold {
    if (!this.fold) throw new Error("room client: no genesis yet (enrollment session)");
    return this.fold;
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
      this.status = "open";
    } catch (err) {
      this.close();
      throw err;
    }
  }

  /** Opens the session, compares heads, syncs the log and subscribes. Rejects with RoomSessionError. */
  async connect(): Promise<HelloOk> {
    if (this.status === "connecting" || this.status === "open") throw new Error("room client already connected");
    this.requireFold();
    this.status = "connecting";
    this.lastError = null;
    this.lastErrorFields = {};
    try {
      await this.handshake();
      const hello = HelloOk.parse(await this.request({ t: "session.hello", v: 2, known: { logSeq: this.head.seq, logHash: this.head.hash } }));
      this.hello = hello;
      this.status = "open";
      await this.compareHead(hello.head);
      this.replayRestored();
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
    const sent = this.requestRaw(frame, timeoutMs);
    // Room-log 6.4 "own statements": keep the receipt until the chain contains it.
    return frame.t === "stmt.submit" ? sent.then((reply) => (this.noteReceipt(reply.receipt), reply)) : sent;
  }

  /**
   * A receipt for one of this device's statements. One at or below the own head must be the chain's
   * entry (`fork` with proof otherwise); one beyond it becomes an anchor kept at rest until it is seen.
   */
  noteReceipt(value: unknown): void {
    const p = SignedEntrySchema.safeParse(value);
    if (!p.success || !this.fold || this.processingStopped) return;
    const r = p.data;
    const seq = r.entry.seq;
    if (!this.validAt(r, seq)) return;
    if (seq <= this.head.seq) {
      if (this.chain[seq].hash !== r.hash) this.raiseFork(seq, this.chain[seq], r);
      return;
    }
    this.addAnchor({ kind: "receipt", source: "own_statement", signed: r });
    this.persist();
  }

  private requestRaw(frame: Omit<Frame, "id">, timeoutMs: number): Promise<Frame> {
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
    const auth = this.o.endpoint ?? (this.fold ? this.fold.state.auth.endpoint : this.o.target!.endpoint);
    this.handshakeHash = null;
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
            this.handshakeHash = b64u(hs.handshakeHash());
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
      return;
    }
    if (frame.re === undefined) this.o.onPush?.(frame);
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
      const atHostHead = hostHead === null || this.head.seq >= hostHead.entry.seq;
      if (atHostHead && !this.processingStopped) this.checkAnchorsBeyondHead();
      if (entries.length === 0 || atHostHead) return;
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
    let appended = false;
    for (const e of entries) {
      if (this.processingStopped) return;
      const seq = this.head.seq + 1;
      const before = this.requireFold().state;
      try {
        this.requireFold().append(e, bodies.get(seq));
      } catch (err) {
        if (!(err instanceof FoldError)) throw err;
        this.processingStopped = true;
        this.raise({ type: "invalid_entry", roomId: this.roomId, seq, at: this.now(), proof: [], reason: err.reason });
        break;
      }
      const signed = SignedEntrySchema.parse(e);
      this.chain.push(signed);
      const body = bodies.get(seq);
      if (this.o.store && body) this.bodies.set(seq, body);
      this.checkAnchors(signed);
      this.hook(signed, before, this.requireFold().state);
      appended = true;
    }
    if (appended) this.persist();
  }

  private hook(signed: SignedEntry, before: Readonly<RoomState>, after: Readonly<RoomState>): void {
    try {
      this.o.onIngest?.(signed, before, after);
    } catch (err) {
      log("room_client_ingest_hook_failed", { roomId: this.roomId, error: String((err as Error)?.message ?? err).slice(0, 160) });
    }
  }

  /** Hands the restored entries to `onIngest` once, in order, before new entries (same order as a refetch). */
  private replayRestored(): void {
    const list = this.replay;
    this.replay = [];
    for (const r of list) this.hook(r.signed, r.before, r.after);
  }

  // ----------------------------------------------------------------------------- copy at rest

  private addAnchor(a: RoomAnchor): void {
    const list = this.anchors.get(a.signed.entry.seq) ?? [];
    if (list.some((x) => x.signed.hash === a.signed.hash && (x.kind ?? "pre_admission") === (a.kind ?? "pre_admission"))) return;
    list.push(a);
    this.anchors.set(a.signed.entry.seq, list);
  }

  /** Room-log 8.2 "On start": re-verify the stored chain and fold; local damage is re-checked against the host. */
  private restore(store: LogCopyStore): void {
    const fold = this.requireFold();
    const copy = store.load();
    const problems = [...copy.problems];
    let discard = problems.some((p) => p.startsWith("segment_"));
    const replay: typeof this.replay = [];
    for (const { signed, body } of copy.entries) {
      const before = fold.state;
      try {
        fold.append(signed, body);
      } catch (err) {
        if (!(err instanceof FoldError)) throw err;
        problems.push(`stored_chain_invalid:${signed.entry.seq}`);
        discard = true;
        break;
      }
      this.chain.push(signed);
      if (body) this.bodies.set(signed.entry.seq, body);
      replay.push({ signed, before, after: fold.state });
    }
    const max = copy.maxSignedHead;
    if (!discard && max && max.entry.seq <= this.head.seq && this.chain[max.entry.seq].hash !== max.hash) {
      // Two different entries at one seq, both stored by this device. Both host-signed: the host
      // equivocated (keep the chain, raise fork). Otherwise local damage.
      if (isEquivocationProof(this.chain[max.entry.seq], max, fold.hostKeyAt)) {
        this.raise({ type: "fork", roomId: this.roomId, seq: max.entry.seq, at: this.now(), proof: [this.chain[max.entry.seq], max], reason: "stored:max_signed_head" });
      } else {
        problems.push("stored_head_mismatch");
        discard = true;
      }
    }
    for (const a of copy.alerts) this.raise({ ...a, roomId: this.roomId, restored: true }, false);
    if (discard) {
      // The chain at rest is not used. What stays authentic (the sealed head record, the journal's
      // pre-admission anchors) is checked against what the host serves; nothing is taken on trust.
      this.chain.length = 0;
      this.bodies.clear();
      const fresh = RoomLogFold.fromGenesis(this.o.genesis!);
      this.fold = fresh;
      replay.length = 0;
      try {
        store.discardChain();
      } catch (err) {
        log("member_log_copy_discard_failed", { roomId: this.roomId, error: String((err as Error)?.message ?? err).slice(0, 160) });
      }
    }
    this.replay = replay;
    if (max && max.entry.seq > this.head.seq) {
      this.storedMax = max;
      this.addAnchor({ kind: "stored", source: "max_signed_head", signed: max });
    }
    for (const r of copy.receipts) {
      if (r.entry.seq > this.head.seq) this.addAnchor({ kind: "receipt", source: "own_statement", signed: r });
      else if (this.chain[r.entry.seq].hash !== r.hash) this.raiseFork(r.entry.seq, this.chain[r.entry.seq], r);
    }
    this.restoreProblems = problems;
    if (problems.length) this.raise({ type: "local_copy_corrupt", roomId: this.roomId, seq: this.maxSignedHead?.entry.seq ?? -1, at: this.now(), proof: [], reason: problems.join(",").slice(0, 200) });
    log("member_log_copy_loaded", { roomId: this.roomId, entries: this.chain.length, maxSignedHead: this.maxSignedHead?.entry.seq ?? -1, receipts: copy.receipts.length, problems: problems.length });
  }

  /** Writes the copy at rest; a failed write is logged and the session goes on (detection then lasts this process). */
  private persist(): void {
    const store = this.o.store;
    if (!store || !this.fold) return;
    try {
      store.save({
        chain: this.chain,
        bodyAt: (seq) => this.bodies.get(seq),
        maxSignedHead: this.maxSignedHead,
        receipts: [...this.anchors.values()].flat().filter((a) => a.kind === "receipt").map((a) => a.signed),
        alerts: this.alerts.filter((a): a is RoomAlert & { type: StoredAlert["type"] } => STORED_ALERTS.has(a.type)).map(({ type, seq, at, proof, peer, reason }) => ({ type, seq, at, proof, ...(peer ? { peer } : {}), ...(reason ? { reason: reason.slice(0, 200) } : {}) })),
      });
    } catch (err) {
      log("member_log_copy_write_failed", { roomId: this.roomId, error: String((err as Error)?.message ?? err).slice(0, 160) });
    }
  }

  private parseHead(value: unknown): SignedEntry | null {
    const p = SignedEntrySchema.safeParse(value);
    return p.success ? p.data : null;
  }

  /** A signed entry with a correct hash and a valid hsig by a host key valid at `seq` (own fold's view). */
  private validAt(value: unknown, seq: number): boolean {
    try {
      return verifySignedEntry(value, this.requireFold().hostKeyAt).entry.seq === seq;
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
    if (!isEquivocationProof(a, b, this.requireFold().hostKeyAt)) return "unverified_head_claim";
    this.raise({ type: "fork", roomId: this.roomId, seq, at: this.now(), proof: [a, b], ...(peer ? { peer } : {}) });
    return "fork";
  }

  /** Enrollment 5.7: the fetched entry at an anchor's seq must be the anchor itself. */
  private checkAnchors(signed: SignedEntry): void {
    const list = this.anchors.get(signed.entry.seq);
    if (!list) return;
    this.anchors.delete(signed.entry.seq);
    for (const a of list) {
      if (a.signed.hash === signed.hash) continue;
      // Both are host-signed entries at one seq: an equivocation proof when both verify under the
      // fold's host key for that seq. Otherwise still a fork, but the proof does not stand alone.
      const proven = isEquivocationProof(a.signed, signed, this.requireFold().hostKeyAt);
      this.raise({ type: "fork", roomId: this.roomId, seq: signed.entry.seq, at: this.now(), proof: [a.signed, signed], reason: `${a.kind ?? "pre_admission"}${proven ? "" : "_unproven"}:${a.source}` });
    }
  }

  /** At the host's head: an anchor past it is an entry the host signed and no longer serves. */
  private checkAnchorsBeyondHead(): void {
    for (const [seq, list] of [...this.anchors]) {
      if (seq <= this.head.seq) continue;
      this.anchors.delete(seq);
      for (const a of list) this.raise({ type: "truncation", roomId: this.roomId, seq, at: this.now(), proof: [a.signed], reason: `${a.kind ?? "pre_admission"}:${a.source}` });
    }
    this.persist();
  }

  /**
   * Same alert already raised (a restored one, or the same check again after a reconnect). Claims
   * without evidence are all kept: repeated claims from one device are what admins look at (6.3).
   */
  private known(a: RoomAlert): boolean {
    if (a.type === "unverified_head_claim") return false;
    const key = alertKey(a);
    return this.alerts.some((x) => alertKey(x) === key);
  }

  private raiseUnverified(seq: number, peer: { memberId: string; deviceId: string }): PeerHeadResult {
    this.raise({ type: "unverified_head_claim", roomId: this.roomId, seq, at: this.now(), proof: [], peer });
    return "unverified_head_claim";
  }

  private raise(a: RoomAlert, notify = true): void {
    if (a.type === "fork" || a.type === "truncation" || a.type === "invalid_entry") this.sendingStopped = true;
    if (this.known(a)) return;
    this.alerts.push(a);
    if (!notify) return;
    log("room_alert", { roomId: this.roomId, type: a.type, seq: a.seq, ...(a.peer ? { peerDevice: a.peer.deviceId } : {}), ...(a.type === "local_copy_corrupt" ? { reason: a.reason } : {}) });
    this.o.onAlert?.(a);
    if (STORED_ALERTS.has(a.type)) this.persist();
  }
}

const STORED_ALERTS = new Set<RoomAlertType>(["fork", "truncation", "invalid_entry", "withholding"]);

function alertKey(a: RoomAlert): string {
  return [a.type, a.seq, a.reason ?? "", a.peer?.deviceId ?? "", ...a.proof.map((p) => p.hash)].join("|");
}

function isReply(frame: Frame): boolean {
  // `.ok` replies, and `enroll.pending`, the reply to `enroll.request` (enrollment-v2.md 5.2).
  return typeof frame.re === "number" && (frame.t.endsWith(".ok") || frame.t === "enroll.pending");
}
