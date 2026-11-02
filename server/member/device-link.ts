// The confirming device's side of a device link (identity-model.md 6.3, 6.4; enrollment-v2.md 5.4,
// 6.2; hardening plan decisions round 4, re-review R-2; review S-13; implementation plan I-11).
//
// Device A (an active device of the member) creates a link, shows its `prl2.` code, answers the
// host's `link.request` with its own nonce Nc, computes the SAS itself from inputs it pinned, and on
// "Codes match" signs `device.added` for the new device B.
//
// - The host never chooses the SAS nonce: A pins `(pendingId, h, sasCommit, deviceSig, deviceDh)`
//   from the request, then chooses Nc, writes pin and counters to its sealed state (fsync) and only
//   then sends `link.nonce`. The SAS uses the pinned `h` and commitment and A's own Nc.
// - A counts for itself and never relies on the host's counters (R-2): 1 Nc per pendingId (a
//   byte-identical re-push gets the same Nc; a changed one burns the link), 1 open pending per link
//   (open from `link.nonce` until `link.closed`, A's own confirm or abort, or 15 minutes on A's
//   clock; a request meanwhile gets no answer and does not count), 3 Nc per link in total (a further
//   request burns the link: `link.abort {reason:"attempts"}`, no nonce). The counters, the burned
//   flag and the pins live in `member/rooms/<roomId>/state.sealed` (section `links`), so a restart
//   does not reset them.
// - "Codes do not match" sends `link.abort sas_mismatch` and burns the link locally, whatever the
//   host does.
//
// The token is never stored: it is in the code shown once. Nothing here logs keys, nonces, the token,
// the token key, the code or the SAS.
import { randomBytes, type KeyObject } from "node:crypto";
import { z } from "zod";
import { b64uBytes, entityId, Hash32, nonNegInt, Sig64 } from "../authority/schema";
import { verifyNewKeySig, type StatementData, type StatementType } from "../authority/statements";
import { log } from "../log";
import { b64u, b64uDecode } from "../proto/b64u";
import { deviceAddedData, encodeLink, LINK_EXP_MAX_S, newDeviceKeyChange, signDeviceStatement } from "../proto/device-link";
import { computeSas, isValidLabel, sasCommitOf, tokenKeyOf, verifyEnrollSig, type EnrollSigned } from "../proto/enroll";
import { isId, linkRef, newId } from "../proto/ids";
import type { Frame } from "../transport/records";

/** R-2 limits, counted by the confirming device. */
export const LINK_LIMITS = { noncesPerLink: 3, openPendingTtlMs: 15 * 60 * 1000 } as const;
/** A request for a link whose exp passed by more than this is not answered. */
const EXP_GRACE_MS = 60_000;
const MAX_LINKS = 64;

const PinState = z.enum(["open", "revealed", "confirmed", "aborted", "closed"]);
const Pin = z.strictObject({
  pendingId: entityId("pending"),
  deviceId: entityId("device"),
  h: Hash32,
  sasCommit: Hash32,
  deviceSig: b64uBytes(32),
  deviceDh: b64uBytes(32),
  label: z.string().max(400),
  nc: Hash32,
  /** A's clock when it chose Nc (unix ms). */
  at: nonNegInt(),
  state: PinState,
  nm: Hash32.nullable(),
  newKeySig: Sig64.nullable(),
  sas: z.string().regex(/^[0-9]{6}$/).nullable(),
  transcript: Hash32.nullable(),
});
type Pin = z.infer<typeof Pin>;

const LocalLink = z.strictObject({
  linkId: entityId("link"),
  /** unix s */
  exp: nonNegInt(),
  createdAt: nonNegInt(),
  /** Nc values sent for this link (at most 3). */
  nonces: nonNegInt().max(LINK_LIMITS.noncesPerLink),
  burned: z.enum(["sas_mismatch", "attempts"]).nullable(),
  /** The entry that logged `device.link.created` (a base for A's later statements). */
  receipt: z.strictObject({ seq: nonNegInt(), hash: Hash32 }).nullable(),
  pins: z.array(Pin).max(LINK_LIMITS.noncesPerLink),
});
type LocalLink = z.infer<typeof LocalLink>;

const LinkState = z.strictObject({ v: z.literal(2), typ: z.literal("device-links"), links: z.array(LocalLink).max(MAX_LINKS) });
type LinkState = z.infer<typeof LinkState>;

const B32 = b64uBytes(32);
const LinkRequestPush = z.strictObject({
  t: z.literal("link.request"),
  pendingId: entityId("pending"),
  linkId: entityId("link"),
  deviceId: entityId("device"),
  request: z.strictObject({
    v: z.literal(2),
    typ: z.literal("enroll-request"),
    h: B32,
    genesisHash: B32,
    linkId: entityId("link"),
    deviceSig: B32,
    deviceDh: B32,
    label: z.string().max(400),
    sasCommit: B32,
  }),
  sig: Sig64,
});
const LinkRevealPush = z.strictObject({ t: z.literal("link.reveal"), pendingId: entityId("pending"), Nm: B32, newKeySig: Sig64 });
const LinkClosedPush = z.strictObject({ t: z.literal("link.closed"), linkId: entityId("link"), pendingId: entityId("pending"), reason: z.string().max(32) });

/** The room session A uses (server/member/room-client.ts). */
export interface LinkSession {
  readonly head: { seq: number; hash: string };
  request(frame: Omit<Frame, "id">, timeoutMs?: number): Promise<Frame>;
}

export interface DeviceLinkerOptions {
  roomId: string;
  genesisHash: string;
  memberId: string;
  deviceId: string;
  /** Kid of this device's signing key. */
  sigKid: string;
  /** This device's signing key, loaded from its sealed key file on demand. */
  sigKey(): KeyObject;
  /** The room endpoint from this device's verified authority state. */
  endpoint(): { serverId: string; dh: { alg: "x25519"; kid: string; pub: string }; relay: { host: string; port: number; tls: true } };
  /** The open room session, or null. */
  session(): LinkSession | null;
  /** The `links` section of the sealed member state (read and durable write). */
  store: { read(): unknown; write(state: unknown): void };
  now?: () => number;
  random?: (n: number) => Buffer;
  onChange?(): void;
}

export class DeviceLinkError extends Error {
  constructor(
    readonly code: "no_session" | "unknown_pending" | "not_revealed" | "burned" | "too_many_links" | "refused",
    message: string,
  ) {
    super(message);
    this.name = "DeviceLinkError";
  }
}

export type LinkView = {
  linkId: string;
  exp: number;
  /** Nc values sent (attempts that reached the SAS on this device). */
  attempts: number;
  burned: "sas_mismatch" | "attempts" | null;
  pending: {
    pendingId: string;
    deviceId: string;
    /** Self-reported by the new device. */
    label: string;
    state: z.infer<typeof PinState>;
    /** "186 565" once B revealed; computed by this device. */
    sas: string | null;
    /** "N earlier attempts on this link" (6.4). */
    earlierAttempts: number;
  } | null;
};

export class DeviceLinker {
  private st: LinkState;
  private readonly now: () => number;
  private readonly random: (n: number) => Buffer;

  constructor(private readonly o: DeviceLinkerOptions) {
    this.now = o.now ?? Date.now;
    this.random = o.random ?? randomBytes;
    const raw = o.store.read();
    if (raw === undefined) this.st = { v: 2, typ: "device-links", links: [] };
    else {
      const parsed = LinkState.safeParse(raw);
      if (!parsed.success) throw new Error("device link state is invalid");
      this.st = parsed.data;
    }
  }

  get roomId(): string {
    return this.o.roomId;
  }

  view(): LinkView[] {
    return this.st.links.map((l) => {
      const pin = l.pins.at(-1) ?? null;
      return {
        linkId: l.linkId,
        exp: l.exp,
        attempts: l.nonces,
        burned: l.burned,
        pending: pin && {
          pendingId: pin.pendingId,
          deviceId: pin.deviceId,
          label: pin.label,
          state: pin.state,
          sas: pin.sas ? `${pin.sas.slice(0, 3)} ${pin.sas.slice(3)}` : null,
          earlierAttempts: l.nonces - 1,
        },
      };
    });
  }

  /** "Link another device" (6.4, creating a link): returns the `prl2.` code once. */
  async create(i: { roomName?: string } = {}): Promise<{ code: string; linkId: string; exp: number }> {
    const session = this.o.session();
    if (!session) throw new DeviceLinkError("no_session", "The room is not connected");
    const now = this.now();
    // Old links that can no longer be used make room; a link with a confirmed add stays.
    const live = this.st.links.filter((l) => l.exp * 1000 + EXP_GRACE_MS + LINK_LIMITS.openPendingTtlMs > now || l.pins.some((p) => p.state === "confirmed"));
    if (live.length >= MAX_LINKS) throw new DeviceLinkError("too_many_links", "Too many device links in this room");
    const token = this.random(32);
    try {
      const linkId = newId("link");
      const exp = Math.floor(now / 1000) + LINK_EXP_MAX_S;
      const statement = signDeviceStatement({
        type: "device.link.created",
        roomId: this.o.roomId,
        kid: this.o.sigKid,
        key: this.o.sigKey(),
        base: session.head,
        ts: now,
        data: { memberId: this.o.memberId, linkRef: linkRef(linkId), exp },
      });
      // Counters exist before the host can push anything for this link.
      this.persist({ ...this.st, links: [...live, { linkId, exp, createdAt: now, nonces: 0, burned: null, receipt: null, pins: [] }] });
      const reply = await session.request({ t: "device.link.create", linkId, tokenKey: b64u(tokenKeyOf(token, "link")), exp, statement });
      const r = (reply.receipt as { entry?: { seq?: unknown }; hash?: unknown } | undefined) ?? {};
      if (typeof r.entry?.seq === "number" && typeof r.hash === "string") this.patchLink(linkId, { receipt: { seq: r.entry.seq, hash: r.hash } });
      const ep = this.o.endpoint();
      const code = encodeLink({
        v: 2,
        typ: "device-link",
        roomId: this.o.roomId,
        genesisHash: this.o.genesisHash,
        roomName: (i.roomName ?? "Room").slice(0, 80),
        endpoint: { serverId: ep.serverId, dh: { alg: "x25519", kid: ep.dh.kid, pub: ep.dh.pub }, relay: { host: ep.relay.host, port: ep.relay.port, tls: true } },
        linkId,
        token: b64u(token),
        exp,
        sas: "sas6",
      });
      log("link_code_created", { roomId: this.o.roomId, linkRef: linkRef(linkId), exp });
      return { code, linkId, exp };
    } finally {
      token.fill(0);
    }
  }

  /** Session pushes for this device's links. Returns true when the frame was a link frame. */
  onPush(frame: Frame): boolean {
    if (frame.t === "link.request") void this.onRequest(frame);
    else if (frame.t === "link.reveal") void this.onReveal(frame);
    else if (frame.t === "link.closed") this.onClosed(frame);
    else return false;
    return true;
  }

  /** "Codes match" (true): sign `device.added` for B and send `link.confirm`. "Codes do not match": burn. */
  async confirm(pendingId: string, match: boolean): Promise<void> {
    const found = this.findPin(pendingId);
    if (!found) throw new DeviceLinkError("unknown_pending", "Unknown link request");
    const { link, pin } = found;
    if (pin.state !== "revealed") throw new DeviceLinkError("not_revealed", `The link request is ${pin.state}`);
    const session = this.o.session();
    if (!match) {
      // Burned locally first, whatever the host does (6.4 step 6).
      this.patchLink(link.linkId, { burned: "sas_mismatch" }, pendingId, { state: "aborted" });
      log("link_sas_mismatch", { roomId: this.o.roomId, pendingId });
      await session?.request({ t: "link.abort", linkId: link.linkId, pendingId, reason: "sas_mismatch" }).catch(() => undefined);
      return;
    }
    if (!session) throw new DeviceLinkError("no_session", "The room is not connected");
    const base = link.receipt && link.receipt.seq > session.head.seq ? link.receipt : session.head;
    const statement = signDeviceStatement({
      type: "device.added",
      roomId: this.o.roomId,
      kid: this.o.sigKid,
      key: this.o.sigKey(),
      base,
      ts: this.now(),
      data: deviceAddedData({
        roomId: this.o.roomId,
        memberId: this.o.memberId,
        deviceId: pin.deviceId,
        deviceSig: pin.deviceSig,
        deviceDh: pin.deviceDh,
        newKeySig: pin.newKeySig!,
        addedBy: this.o.deviceId,
        linkId: link.linkId,
        transcript: pin.transcript!,
      }),
    });
    this.patchLink(link.linkId, {}, pendingId, { state: "confirmed" });
    log("link_codes_match", { roomId: this.o.roomId, pendingId });
    await session.request({ t: "link.confirm", pendingId, statement });
  }

  /** A device statement of this member's own (for example `device.add.vetoed`), submitted on the session. */
  async submitOwn<T extends StatementType>(type: T, data: StatementData<T>): Promise<{ seq: number }> {
    const session = this.o.session();
    if (!session) throw new DeviceLinkError("no_session", "The room is not connected");
    const statement = signDeviceStatement({ type, roomId: this.o.roomId, kid: this.o.sigKid, key: this.o.sigKey(), base: session.head, ts: this.now(), data });
    const reply = await session.request({ t: "stmt.submit", statement });
    const seq = (reply.receipt as { entry?: { seq?: number } } | undefined)?.entry?.seq;
    return { seq: typeof seq === "number" ? seq : -1 };
  }

  // ------------------------------------------------------------------------------- internals

  /** 6.4 step 2 and 3, with A's own limits (R-2). Pins and counters are durable before `link.nonce`. */
  private async onRequest(frame: Frame): Promise<void> {
    const f = LinkRequestPush.safeParse(frame);
    if (!f.success) return void log("link_request_ignored", { roomId: this.o.roomId, why: "bad_frame" });
    const r = f.data;
    const link = this.st.links.find((l) => l.linkId === r.linkId);
    const why = (w: string) => log("link_request_ignored", { roomId: this.o.roomId, pendingId: r.pendingId, why: w });
    if (!link) return why("not_own_link");
    if (link.burned) return why("burned");
    const req = r.request as EnrollSigned;
    const valid =
      r.request.linkId === link.linkId &&
      req.genesisHash === this.o.genesisHash &&
      req.deviceSig !== req.deviceDh &&
      isValidLabel(req.label) &&
      verifyEnrollSig(req, r.sig);
    if (!valid) return why("bad_request");
    const now = this.now();
    const pin = link.pins.find((p) => p.pendingId === r.pendingId);
    if (pin) {
      const same = pin.h === req.h && pin.sasCommit === req.sasCommit && pin.deviceSig === req.deviceSig && pin.deviceDh === req.deviceDh && pin.deviceId === r.deviceId;
      if (!same) return this.burn(link, r.pendingId, "changed_request");
      // A lost reply: the same pinned Nc again, never a new one.
      if (pin.state === "open" || pin.state === "revealed") await this.send({ t: "link.nonce", pendingId: pin.pendingId, Nc: pin.nc });
      return;
    }
    if (now > link.exp * 1000 + EXP_GRACE_MS) return why("expired");
    const open = link.pins.find((p) => (p.state === "open" || p.state === "revealed") && now - p.at < LINK_LIMITS.openPendingTtlMs);
    if (open) return why("another_open");
    if (link.nonces >= LINK_LIMITS.noncesPerLink) return this.burn(link, r.pendingId, "attempts");
    const nc = this.random(32);
    const next: Pin = {
      pendingId: r.pendingId,
      deviceId: r.deviceId,
      h: req.h,
      sasCommit: req.sasCommit,
      deviceSig: req.deviceSig,
      deviceDh: req.deviceDh,
      label: req.label,
      nc: b64u(nc),
      at: now,
      state: "open",
      nm: null,
      newKeySig: null,
      sas: null,
      transcript: null,
    };
    nc.fill(0);
    // Earlier pins that timed out are closed; the new pin and the count are written before the send.
    const pins = link.pins.map((p) => (p.state === "open" || p.state === "revealed" ? { ...p, state: "closed" as const } : p));
    this.persist(this.replaceLink({ ...link, nonces: link.nonces + 1, pins: [...pins, next] }));
    log("link_nonce_sent", { roomId: this.o.roomId, pendingId: r.pendingId, attempt: link.nonces + 1 });
    this.o.onChange?.();
    await this.send({ t: "link.nonce", pendingId: r.pendingId, Nc: next.nc });
  }

  /** 6.4 step 5: A checks the commitment, verifies B's newKeySig and computes the SAS itself. */
  private async onReveal(frame: Frame): Promise<void> {
    const f = LinkRevealPush.safeParse(frame);
    if (!f.success) return void log("link_reveal_ignored", { roomId: this.o.roomId, why: "bad_frame" });
    const found = this.findPin(f.data.pendingId);
    if (!found || found.link.burned) return void log("link_reveal_ignored", { roomId: this.o.roomId, why: "unknown_pending" });
    const { link, pin } = found;
    if (pin.state === "revealed" && pin.nm === f.data.Nm && pin.newKeySig === f.data.newKeySig) return;
    if (pin.state !== "open") return void log("link_reveal_ignored", { roomId: this.o.roomId, why: `pin_${pin.state}` });
    const nm = b64uDecode(f.data.Nm, 32);
    const commitOk = sasCommitOf(nm) === pin.sasCommit;
    const keyOk = verifyNewKeySig(newDeviceKeyChange(this.o.roomId, pin.deviceId, pin.deviceSig, pin.deviceDh), f.data.newKeySig);
    if (!commitOk || !keyOk) {
      this.patchLink(link.linkId, {}, pin.pendingId, { state: "aborted" });
      log("link_reveal_refused", { roomId: this.o.roomId, pendingId: pin.pendingId, why: commitOk ? "new_key_sig" : "commitment" });
      await this.send({ t: "link.abort", linkId: link.linkId, pendingId: pin.pendingId, reason: "cancelled" });
      return;
    }
    const sas = computeSas({
      h: b64uDecode(pin.h, 32),
      nm,
      nh: b64uDecode(pin.nc, 32),
      deviceDh: pin.deviceDh,
      deviceSig: pin.deviceSig,
      endpointDh: this.o.endpoint().dh.pub,
      genesisHash: this.o.genesisHash,
      target: { linkId: link.linkId },
    });
    this.patchLink(link.linkId, {}, pin.pendingId, { state: "revealed", nm: f.data.Nm, newKeySig: f.data.newKeySig, sas: sas.digits, transcript: sas.transcript });
    log("link_sas_shown", { roomId: this.o.roomId, pendingId: pin.pendingId });
    this.o.onChange?.();
  }

  private onClosed(frame: Frame): void {
    const f = LinkClosedPush.safeParse(frame);
    if (!f.success) return;
    const found = this.findPin(f.data.pendingId);
    if (!found || found.link.linkId !== f.data.linkId) return;
    if (found.pin.state === "open" || found.pin.state === "revealed") this.patchLink(found.link.linkId, {}, found.pin.pendingId, { state: "closed" });
    log("link_pending_closed", { roomId: this.o.roomId, pendingId: f.data.pendingId, reason: f.data.reason.replace(/[^a-z_]/g, "").slice(0, 24) });
    this.o.onChange?.();
  }

  /** The link is burned on this device; the host is told once. */
  private async burn(link: LocalLink, pendingId: string, why: string): Promise<void> {
    if (!link.burned) {
      this.persist(this.replaceLink({ ...link, burned: "attempts", pins: link.pins.map((p) => (p.state === "open" || p.state === "revealed" ? { ...p, state: "aborted" as const } : p)) }));
      log("link_burned_locally", { roomId: this.o.roomId, pendingId, why });
      this.o.onChange?.();
      await this.send({ t: "link.abort", linkId: link.linkId, pendingId, reason: "attempts" });
    }
  }

  private async send(frame: Omit<Frame, "id">): Promise<void> {
    const session = this.o.session();
    if (!session) return;
    try {
      await session.request(frame);
    } catch (e) {
      log("link_send_failed", { roomId: this.o.roomId, op: String(frame.t).slice(0, 24), code: (e as { code?: string }).code ?? "error" });
    }
  }

  private findPin(pendingId: string): { link: LocalLink; pin: Pin } | null {
    if (!isId("pending", pendingId)) return null;
    for (const link of this.st.links) {
      const pin = link.pins.find((p) => p.pendingId === pendingId);
      if (pin) return { link, pin };
    }
    return null;
  }

  private replaceLink(next: LocalLink): LinkState {
    return { ...this.st, links: this.st.links.map((l) => (l.linkId === next.linkId ? next : l)) };
  }

  private patchLink(linkId: string, patch: Partial<LocalLink>, pendingId?: string, pinPatch?: Partial<Pin>): void {
    const link = this.st.links.find((l) => l.linkId === linkId);
    if (!link) return;
    const pins = pendingId && pinPatch ? link.pins.map((p) => (p.pendingId === pendingId ? { ...p, ...pinPatch } : p)) : link.pins;
    this.persist(this.replaceLink({ ...link, ...patch, pins }));
  }

  /** Durable write first (sealed, fsync); memory follows only after it succeeded. */
  private persist(next: LinkState): void {
    const parsed = LinkState.parse(next);
    this.o.store.write(parsed);
    this.st = parsed;
  }
}
