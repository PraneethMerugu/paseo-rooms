// MLS adapter (mls-integration.md sections 1, 2, 8; implementation plan I-13). The ONLY module that
// imports ts-mls; everything else in the plugin goes through it, so the ts-mls 2.0 migration stays here.
//
// - ts-mls is pinned at exactly 1.6.4 (floor 1.6.4: the removal check fails on 1.6.2). Public API only:
//   no fork of createCommit, no import through the `./*.js` subpath exports. The client config is
//   built from the public `default*Config` exports (section 1 names `ts-mls/clientConfig.js`, a subpath;
//   the public index has the same parts), with our authentication service and the key retention of 8.3.
// - Suite 1 only (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`); anything else is refused.
// - `decodeState` takes the client config as a required argument: ts-mls does not serialize it and a
//   decoded state without it silently uses the accept-all authentication service (spike surprise 3).
// - Two values ts-mls 1.6.4 does not return through its public API are derived here from public
//   types and encoders: the KeyPackageRef (RFC 9420 5.2, RefHash over the encoded KeyPackage), the
//   KeyPackage signature check (SignWithLabel over KeyPackageTBS, the encoding minus its trailing
//   signature), and the sender of an application message (the leaf whose application ratchet the
//   message advanced in the public `secretTree`). Unit tests compare the first two with the library's
//   internal functions.
// Nothing here logs; no key material leaves this module except inside encoded state for sealing.
import { createHash } from "node:crypto";
import * as tsmls from "ts-mls";
import { verifyEd25519 } from "../proto/keys";

export type MlsLib = typeof tsmls;
export type MlsState = tsmls.ClientState;
export type MlsKeyPackage = tsmls.KeyPackage;
export type MlsPrivateKeyPackage = tsmls.PrivateKeyPackage;
export type MlsCredential = tsmls.Credential;
export type MlsClientConfig = tsmls.ClientConfig;

export const MLS_SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
/** `paseo_room_authority` GroupContext extension (section 2.3), private-use range. */
export const AUTHORITY_EXTENSION_TYPE = 0xf0a1;
/** Section 8.3. */
export const KEY_RETENTION = { retainKeysForEpochs: 2, retainKeysForGenerations: 64, maximumForwardRatchetSteps: 1000 } as const;
/** Section 6.2: the host refuses larger commits; also the cap for application messages here. */
export const MLS_MESSAGE_MAX_BYTES = 1024 * 1024;

const KP_REF_LABEL = "MLS 1.0 KeyPackage Reference";
const KP_TBS_LABEL = "MLS 1.0 KeyPackageTBS";
/** MLSMessage header: version (uint16) and wire format (uint16). */
const MLS_MESSAGE_HEADER = 4;

export type AuthServiceLike = { validateCredential(credential: MlsCredential, signaturePublicKey: Uint8Array): Promise<boolean> };

/** A leaf of the ratchet tree, as the roster rule reads it. */
export type LeafView = { leafIndex: number; identity: Uint8Array; signaturePublicKey: Uint8Array; credentialType: string; hpkePublicKey: Uint8Array };

/** Proposals of an incoming commit, normalized (the IncomingMessageCallback sees only these). */
export type ProposalView =
  | { type: "add"; identity: Uint8Array | null; signaturePublicKey: Uint8Array; ref: string }
  | { type: "remove"; leafIndex: number }
  | { type: "group_context_extensions"; extensions: { type: number; data: Uint8Array }[] }
  | { type: "reinit" }
  | { type: "other"; name: string };

export type IncomingView = { kind: "commit"; senderLeafIndex: number | undefined; proposals: ProposalView[] } | { kind: "proposal" };

/** What the host and members read from an MLSMessage without group state (Spike A case (e)). */
export type MessagePeek =
  | { wireformat: "mls_private_message"; groupId: Uint8Array; epoch: number; contentType: "application" | "proposal" | "commit"; authenticatedData: Uint8Array }
  | { wireformat: "mls_welcome"; suite: string; refs: string[] }
  | { wireformat: "mls_key_package" }
  | { wireformat: "other"; name: string };

export type KeyPackageInfo = {
  keyPackage: MlsKeyPackage;
  ref: string;
  suite: string;
  version: string;
  credentialType: string;
  identity: Uint8Array | null;
  signaturePublicKey: Uint8Array;
  capabilityExtensions: number[];
  notBefore: number;
  notAfter: number;
  signatureValid: boolean;
};

export type ProcessResult =
  | { kind: "application"; plaintext: Uint8Array; newState: MlsState; senderLeafIndex: number | null }
  | { kind: "commit"; accepted: true; newState: MlsState; senderLeafIndex: number | undefined }
  | { kind: "commit"; accepted: false }
  | { kind: "proposal"; accepted: boolean };

export class MlsAdapterError extends Error {
  constructor(
    readonly code: "bad_message" | "wrong_suite" | "not_active" | "bad_key_package",
    message: string,
  ) {
    super(message);
    this.name = "MlsAdapterError";
  }
}

const b64u = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64url");

/** QUIC-style variable-length integer of RFC 9420 section 2.1.2. */
function varint(n: number): Buffer {
  if (n < 64) return Buffer.from([n]);
  if (n < 16384) return Buffer.from([0x40 | (n >> 8), n & 0xff]);
  if (n < 2 ** 30) return Buffer.from([0x80 | (n >>> 24), (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  throw new Error("varint: too large");
}
const opaque = (b: Uint8Array) => Buffer.concat([varint(b.length), b]);

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

export class MlsAdapter {
  private constructor(
    private readonly lib: MlsLib,
    readonly cs: tsmls.CiphersuiteImpl,
  ) {}

  /** The library defaults to the pinned ts-mls; a test passes another version for the positive control. */
  static async create(lib: MlsLib = tsmls): Promise<MlsAdapter> {
    const cs = await lib.getCiphersuiteImpl(lib.getCiphersuiteFromName(MLS_SUITE));
    return new MlsAdapter(lib, cs);
  }

  /** Client config of section 1 and 8.3 around one authentication service. */
  config(authService: AuthServiceLike): MlsClientConfig {
    const l = this.lib;
    return {
      keyRetentionConfig: { ...KEY_RETENTION },
      lifetimeConfig: l.defaultLifetimeConfig,
      keyPackageEqualityConfig: l.defaultKeyPackageEqualityConfig,
      paddingConfig: l.defaultPaddingConfig,
      authService,
    };
  }

  /** A new leaf signature key pair (separate from the device signing key, section 3). */
  async newLeafSigner(): Promise<{ publicKey: Uint8Array; signKey: Uint8Array }> {
    const kp = await this.cs.signature.keygen();
    return { publicKey: kp.publicKey, signKey: kp.signKey };
  }

  capabilities(): tsmls.Capabilities {
    const caps = this.lib.defaultCapabilities();
    return { ...caps, extensions: [...new Set([...caps.extensions, AUTHORITY_EXTENSION_TYPE])] };
  }

  /** A KeyPackage for a basic credential; lifetime in unix seconds. */
  async keyPackage(identity: Uint8Array, signer: { publicKey: Uint8Array; signKey: Uint8Array }, lifetime: { notBefore: number; notAfter: number }): Promise<{ publicPackage: MlsKeyPackage; privatePackage: MlsPrivateKeyPackage; bytes: Uint8Array; ref: string }> {
    const cred: MlsCredential = { credentialType: "basic", identity };
    const r = await this.lib.generateKeyPackageWithKey(cred, this.capabilities(), { notBefore: BigInt(lifetime.notBefore), notAfter: BigInt(lifetime.notAfter) }, [], signer, this.cs);
    const bytes = this.encodeKeyPackage(r.publicPackage);
    return { publicPackage: r.publicPackage, privatePackage: r.privatePackage, bytes, ref: this.keyPackageRefOf(bytes) };
  }

  encodeKeyPackage(kp: MlsKeyPackage): Uint8Array {
    return this.lib.encodeMlsMessage({ version: "mls10", wireformat: "mls_key_package", keyPackage: kp } as tsmls.MLSMessage);
  }

  /** RFC 9420 5.2: RefHash("MLS 1.0 KeyPackage Reference", KeyPackage), b64u. `msgBytes` is the MLSMessage. */
  keyPackageRefOf(msgBytes: Uint8Array): string {
    const kpBytes = msgBytes.subarray(MLS_MESSAGE_HEADER);
    return b64u(createHash("sha256").update(opaque(Buffer.from(KP_REF_LABEL, "ascii"))).update(opaque(kpBytes)).digest());
  }

  /** Strict decode of a published KeyPackage (an MLSMessage of wire format mls_key_package). */
  decodeKeyPackage(msgBytes: Uint8Array): KeyPackageInfo {
    const m = this.decode(msgBytes);
    if (m.wireformat !== "mls_key_package") throw new MlsAdapterError("bad_key_package", "not a KeyPackage message");
    const kp = (m as tsmls.MlsKeyPackage).keyPackage;
    const leaf = kp.leafNode;
    const kpBytes = msgBytes.subarray(MLS_MESSAGE_HEADER);
    // KeyPackage = KeyPackageTBS || signature<V>; for Ed25519 the signature is 64 bytes, prefix 1 byte.
    const sigLen = kp.signature.length;
    const tbs = kpBytes.subarray(0, kpBytes.length - varint(sigLen).length - sigLen);
    const signContent = Buffer.concat([opaque(Buffer.from(KP_TBS_LABEL, "ascii")), opaque(tbs)]);
    const signatureValid = kp.cipherSuite === MLS_SUITE && verifyEd25519(leaf.signaturePublicKey, signContent, kp.signature);
    return {
      keyPackage: kp,
      ref: this.keyPackageRefOf(msgBytes),
      suite: kp.cipherSuite,
      version: kp.version,
      credentialType: leaf.credential.credentialType,
      identity: leaf.credential.credentialType === "basic" ? leaf.credential.identity : null,
      signaturePublicKey: leaf.signaturePublicKey,
      capabilityExtensions: [...leaf.capabilities.extensions],
      notBefore: leaf.leafNodeSource === "key_package" ? Number(leaf.lifetime.notBefore) : 0,
      notAfter: leaf.leafNodeSource === "key_package" ? Number(leaf.lifetime.notAfter) : 0,
      signatureValid,
    };
  }

  /** Creates the group with this device's leaf only, and the authority extension (section 2.3). */
  async createGroup(groupId: Uint8Array, kp: { publicPackage: MlsKeyPackage; privatePackage: MlsPrivateKeyPackage }, authority: Uint8Array, config: MlsClientConfig): Promise<MlsState> {
    return this.lib.createGroup(groupId, kp.publicPackage, kp.privatePackage, [{ extensionType: AUTHORITY_EXTENSION_TYPE, extensionData: authority }], this.cs, config);
  }

  /**
   * A commit (PrivateMessage) with the given Adds, Removes and extension change, carrying `aad`. The
   * Welcome has the ratchet tree in its GroupInfo extension.
   */
  async commit(state: MlsState, c: { adds?: MlsKeyPackage[]; removes?: number[]; authority?: Uint8Array }, aad: Uint8Array): Promise<{ newState: MlsState; commit: Uint8Array; welcome: Uint8Array | null }> {
    const proposals: tsmls.Proposal[] = [
      ...(c.removes ?? []).map((leafIndex) => ({ proposalType: "remove" as const, remove: { removed: leafIndex } })),
      ...(c.adds ?? []).map((keyPackage) => ({ proposalType: "add" as const, add: { keyPackage } })),
      ...(c.authority ? [{ proposalType: "group_context_extensions" as const, groupContextExtensions: { extensions: [{ extensionType: AUTHORITY_EXTENSION_TYPE, extensionData: c.authority }] } }] : []),
    ];
    const r = await this.lib.createCommit({ state, cipherSuite: this.cs }, { extraProposals: proposals, ratchetTreeExtension: true, wireAsPublicMessage: false, authenticatedData: aad });
    return {
      newState: r.newState,
      commit: this.lib.encodeMlsMessage(r.commit),
      welcome: r.welcome ? this.lib.encodeMlsMessage({ version: "mls10", wireformat: "mls_welcome", welcome: r.welcome } as tsmls.MLSMessage) : null,
    };
  }

  /** An application message (PrivateMessage) carrying `aad`. */
  async encrypt(state: MlsState, plaintext: Uint8Array, aad: Uint8Array): Promise<{ newState: MlsState; message: Uint8Array }> {
    const r = await this.lib.createApplicationMessage(state, plaintext, this.cs, aad);
    return { newState: r.newState, message: this.lib.encodeMlsMessage({ version: "mls10", wireformat: "mls_private_message", privateMessage: r.privateMessage } as tsmls.MLSMessage) };
  }

  /**
   * Processes a PrivateMessage. `decide` sees commits (and proposals) in normalized form and returns
   * accept or reject; a rejected commit leaves the caller's state as it was (the caller discards).
   */
  async process(state: MlsState, bytes: Uint8Array, decide: (incoming: IncomingView) => boolean): Promise<ProcessResult> {
    const m = this.decode(bytes);
    if (m.wireformat !== "mls_private_message") throw new MlsAdapterError("bad_message", `unexpected wire format ${m.wireformat}`);
    const pm = (m as tsmls.MlsPrivateMessage).privateMessage;
    let accepted = true;
    let sender: number | undefined;
    const callback: tsmls.IncomingMessageCallback = (incoming) => {
      if (incoming.kind === "proposal") {
        accepted = decide({ kind: "proposal" });
        return accepted ? "accept" : "reject";
      }
      sender = incoming.senderLeafIndex === undefined ? undefined : Number(incoming.senderLeafIndex);
      let ok: boolean;
      try {
        ok = decide({ kind: "commit", senderLeafIndex: sender, proposals: incoming.proposals.map((p) => this.viewProposal(p.proposal)) });
      } catch {
        ok = false;
      }
      accepted = ok;
      return ok ? "accept" : "reject";
    };
    const before = state.secretTree;
    const beforeHist = pm.epoch < state.groupContext.epoch ? state.historicalReceiverData.get(pm.epoch)?.secretTree : undefined;
    const r = await this.lib.processPrivateMessage(state, pm, this.lib.makePskIndex(state, {}), this.cs, callback);
    if (r.kind === "applicationMessage") {
      const afterTree = pm.epoch < state.groupContext.epoch ? r.newState.historicalReceiverData.get(pm.epoch)?.secretTree : r.newState.secretTree;
      return { kind: "application", plaintext: r.message, newState: r.newState, senderLeafIndex: changedLeaf(beforeHist ?? before, afterTree) };
    }
    if (pm.contentType === "proposal") return { kind: "proposal", accepted: false };
    if (!accepted || r.actionTaken === "reject") return { kind: "commit", accepted: false };
    return { kind: "commit", accepted: true, newState: r.newState, senderLeafIndex: sender };
  }

  /** Joins from a Welcome (ratchet tree from the GroupInfo extension). */
  async join(welcome: Uint8Array, kp: { publicPackage: MlsKeyPackage; privatePackage: MlsPrivateKeyPackage }, config: MlsClientConfig): Promise<MlsState> {
    const m = this.decode(welcome);
    if (m.wireformat !== "mls_welcome") throw new MlsAdapterError("bad_message", "not a Welcome");
    const w = (m as tsmls.MlsWelcome).welcome;
    if (w.cipherSuite !== MLS_SUITE) throw new MlsAdapterError("wrong_suite", "Welcome of another suite");
    return this.lib.joinGroup(w, kp.publicPackage, kp.privatePackage, this.lib.emptyPskIndex, this.cs, undefined, undefined, config);
  }

  /** Reads an MLSMessage without group state: wire format, group, epoch, content type, AAD, Welcome refs. */
  peek(bytes: Uint8Array): MessagePeek {
    const m = this.decode(bytes);
    if (m.wireformat === "mls_private_message") {
      const pm = (m as tsmls.MlsPrivateMessage).privateMessage;
      return { wireformat: "mls_private_message", groupId: pm.groupId, epoch: Number(pm.epoch), contentType: pm.contentType as "application" | "proposal" | "commit", authenticatedData: pm.authenticatedData };
    }
    if (m.wireformat === "mls_welcome") {
      const w = (m as tsmls.MlsWelcome).welcome;
      return { wireformat: "mls_welcome", suite: w.cipherSuite, refs: w.secrets.map((s) => b64u(s.newMember)) };
    }
    if (m.wireformat === "mls_key_package") return { wireformat: "mls_key_package" };
    return { wireformat: "other", name: String(m.wireformat) };
  }

  encodeState(state: MlsState): Uint8Array {
    return this.lib.encodeGroupState(state);
  }

  /** The config is required: a state is never returned without our authentication service. */
  decodeState(bytes: Uint8Array, config: MlsClientConfig): MlsState {
    if (!config?.authService) throw new Error("decodeState: a client config with an authentication service is required");
    const r = this.lib.decodeGroupState(bytes, 0);
    if (!r) throw new MlsAdapterError("bad_message", "group state does not decode");
    return { ...r[0], clientConfig: config } as MlsState;
  }

  /** Re-attaches a config to a state in memory (for example a forked copy in tests). */
  withConfig(state: MlsState, config: MlsClientConfig): MlsState {
    return { ...state, clientConfig: config };
  }

  leaves(state: MlsState): LeafView[] {
    const out: LeafView[] = [];
    state.ratchetTree.forEach((n, i) => {
      if (n && n.nodeType === "leaf") {
        const c = n.leaf.credential;
        out.push({ leafIndex: i / 2, identity: c.credentialType === "basic" ? c.identity : new Uint8Array(0), credentialType: c.credentialType, signaturePublicKey: n.leaf.signaturePublicKey, hpkePublicKey: n.leaf.hpkePublicKey });
      }
    });
    return out;
  }

  ownLeafIndex(state: MlsState): number {
    return Number(state.privatePath.leafIndex);
  }

  epoch(state: MlsState): number {
    return Number(state.groupContext.epoch);
  }

  groupId(state: MlsState): Uint8Array {
    return state.groupContext.groupId;
  }

  /** RFC 9420 8.7 epoch_authenticator, a public field of the public ClientState (MLS test 13). */
  epochAuthenticator(state: MlsState): Uint8Array {
    return state.keySchedule.epochAuthenticator;
  }

  isActive(state: MlsState): boolean {
    return state.groupActiveState.kind === "active";
  }

  authorityExtension(state: MlsState): Uint8Array | null {
    const e = state.groupContext.extensions.find((x) => (typeof x.extensionType === "number" ? x.extensionType : -1) === AUTHORITY_EXTENSION_TYPE);
    return e ? e.extensionData : null;
  }

  // ---- internals ----

  private decode(bytes: Uint8Array): tsmls.MLSMessage {
    let r: [tsmls.MLSMessage, number] | undefined;
    try {
      r = this.lib.decodeMlsMessage(bytes, 0);
    } catch {
      r = undefined;
    }
    if (!r || r[1] !== bytes.length) throw new MlsAdapterError("bad_message", "not a strict MLSMessage");
    if (r[0].version !== "mls10") throw new MlsAdapterError("bad_message", "unsupported MLS version");
    return r[0];
  }

  private viewProposal(p: tsmls.Proposal): ProposalView {
    switch (p.proposalType) {
      case "add": {
        const leaf = p.add.keyPackage.leafNode;
        const bytes = this.encodeKeyPackage(p.add.keyPackage);
        return { type: "add", identity: leaf.credential.credentialType === "basic" ? leaf.credential.identity : null, signaturePublicKey: leaf.signaturePublicKey, ref: this.keyPackageRefOf(bytes) };
      }
      case "remove":
        return { type: "remove", leafIndex: Number(p.remove.removed) };
      case "group_context_extensions":
        return { type: "group_context_extensions", extensions: p.groupContextExtensions.extensions.map((e) => ({ type: typeof e.extensionType === "number" ? e.extensionType : -1, data: e.extensionData })) };
      case "reinit":
        return { type: "reinit" };
      default:
        return { type: "other", name: String(p.proposalType) };
    }
  }
}

/** The one leaf whose application ratchet changed between two secret trees, or null. */
function changedLeaf(before: tsmls.SecretTree | undefined, after: tsmls.SecretTree | undefined): number | null {
  if (!before || !after) return null;
  const found: number[] = [];
  for (let i = 0; i < Math.max(before.length, after.length); i += 2) {
    const a = before[i]?.application;
    const b = after[i]?.application;
    if (!a && !b) continue;
    if (!a || !b || a.generation !== b.generation || !bytesEqual(a.secret, b.secret) || Object.keys(a.unusedGenerations).join() !== Object.keys(b.unusedGenerations).join()) found.push(i / 2);
  }
  return found.length === 1 ? found[0] : null;
}

let shared: Promise<MlsAdapter> | null = null;
/** The adapter over the pinned ts-mls, created once. */
export function mlsAdapter(): Promise<MlsAdapter> {
  shared ??= MlsAdapter.create();
  return shared;
}
