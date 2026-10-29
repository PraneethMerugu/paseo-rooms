// Derived from Paseo (github.com/getpaseo/paseo), packages/relay/src/noise/index.ts
// at commit 1467121b16742c2ce57320748d70d365aaf861c6. Copyright (c) 2025-present Mohamed Boudra.
// Licensed under the Apache License, Version 2.0 (repository root LICENSE; copy in ./LICENSE).
// CHANGED by paseo-rooms (identity v2, milestone I-4; see ./NOTICE.md):
//   - a pattern table with NK and IK replaces the NK-only token list; tokens s, se, ss added;
//   - `pattern` is a required option; IK initiators take `localStatic`;
//   - `remoteStatic()` exposes the initiator static learned by an IK responder, only after the
//     message carrying it has been fully authenticated;
//   - any failed write or read poisons the handshake (later calls throw) and zeroes the ephemeral;
//   - key pairs are length-checked; `handshakeMessageBytes()` added for transport size checks.
// Upstream names, error texts and the token-by-token structure are kept for diffing.
/**
 * Conforming Noise_NK_25519_ChaChaPoly_SHA256 and Noise_IK_25519_ChaChaPoly_SHA256
 * (Noise Protocol Framework rev 34).
 *
 * The pattern is executed token by token from its definition, so the vector
 * tests exercise the same code path as production.
 *
 *   NK:                     IK:
 *     <- s                    <- s
 *     ...                     ...
 *     -> e, es                -> e, es, s, ss
 *     <- e, ee                <- e, ee, se
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { CipherState, NoiseProtocolError, NOISE_MAX_MESSAGE_BYTES, NOISE_TAG_BYTES } from "./cipher-state.js";
import { SymmetricState, concat } from "./symmetric-state.js";

export {
  CipherState,
  NoiseProtocolError,
  NOISE_MAX_MESSAGE_BYTES,
  NOISE_TAG_BYTES,
} from "./cipher-state.js";

export type NoisePattern = "NK" | "IK";
export const NOISE_NK_PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_SHA256";
export const NOISE_IK_PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_SHA256";
const PROTOCOL_NAMES: Record<NoisePattern, string> = { NK: NOISE_NK_PROTOCOL_NAME, IK: NOISE_IK_PROTOCOL_NAME };
export const DH_BYTES = 32;

export interface NoiseKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface NoiseInitiatorOptions {
  pattern: NoisePattern;
  /** Responder's static public key, trusted out of band. */
  remoteStatic: Uint8Array;
  /** Initiator's static key pair. Required for IK, refused for NK. */
  localStatic?: NoiseKeyPair;
  prologue: Uint8Array;
  /** Test injection only; production generates a fresh ephemeral. */
  ephemeral?: NoiseKeyPair;
}

export interface NoiseResponderOptions {
  pattern: NoisePattern;
  localStatic: NoiseKeyPair;
  prologue: Uint8Array;
  /** Test injection only; production generates a fresh ephemeral. */
  ephemeral?: NoiseKeyPair;
}

export interface TransportKeys {
  /** Initiator → responder. */
  send: CipherState;
  /** Responder → initiator. */
  receive: CipherState;
}

export interface NoiseHandshake {
  /** Builds the next handshake message this side is due to write. */
  writeMessage(payload: Uint8Array): Uint8Array;
  /** Consumes the next handshake message this side is due to read; returns its payload. */
  readMessage(message: Uint8Array): Uint8Array;
  /** True once both handshake messages have been processed. */
  isComplete(): boolean;
  handshakeHash(): Uint8Array;
  /**
   * The peer's static public key: the pre-shared responder key for an initiator; for an IK
   * responder, the initiator static, available only after message 1 authenticated in full.
   * Null for an NK responder.
   */
  remoteStatic(): Uint8Array | null;
  /** Derives transport keys, oriented for this side. Ends the handshake state. */
  split(): { send: CipherState; receive: CipherState };
}

type Token = "e" | "s" | "es" | "se" | "ss" | "ee";
const PATTERNS: Record<NoisePattern, ReadonlyArray<ReadonlyArray<Token>>> = {
  NK: [
    ["e", "es"],
    ["e", "ee"],
  ],
  IK: [
    ["e", "es", "s", "ss"],
    ["e", "ee", "se"],
  ],
};

/** Size of handshake message `index` (0 or 1) of `pattern` with a payload of `payloadBytes`. */
export function handshakeMessageBytes(pattern: NoisePattern, index: 0 | 1, payloadBytes = 0): number {
  let size = payloadBytes + NOISE_TAG_BYTES; // every handshake message here is written after a mixKey
  for (const token of PATTERNS[pattern][index]) {
    if (token === "e") size += DH_BYTES;
    if (token === "s") size += DH_BYTES + NOISE_TAG_BYTES;
  }
  return size;
}

export function generateNoiseKeyPair(): NoiseKeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

export function createNoiseInitiator(options: NoiseInitiatorOptions): NoiseHandshake {
  requirePattern(options.pattern);
  requireKeyLength(options.remoteStatic, "remote static key");
  const s = options.localStatic ?? null;
  if (options.pattern === "IK" && !s) throw new NoiseProtocolError("IK initiator needs a local static key");
  if (options.pattern === "NK" && s) throw new NoiseProtocolError("NK initiator has no local static key");
  if (s) requireKeyPair(s, "local static");
  if (options.ephemeral) requireKeyPair(options.ephemeral, "ephemeral");
  return new HandshakeState({
    pattern: options.pattern,
    initiator: true,
    prologue: options.prologue,
    s,
    rs: options.remoteStatic,
    ephemeral: options.ephemeral ?? null,
  });
}

export function createNoiseResponder(options: NoiseResponderOptions): NoiseHandshake {
  requirePattern(options.pattern);
  requireKeyPair(options.localStatic, "local static");
  if (options.ephemeral) requireKeyPair(options.ephemeral, "ephemeral");
  return new HandshakeState({
    pattern: options.pattern,
    initiator: false,
    prologue: options.prologue,
    s: options.localStatic,
    rs: null,
    ephemeral: options.ephemeral ?? null,
  });
}

class HandshakeState implements NoiseHandshake {
  private readonly symmetric: SymmetricState;
  private readonly messages: ReadonlyArray<ReadonlyArray<Token>>;
  private readonly initiator: boolean;
  private readonly s: NoiseKeyPair | null;
  private e: NoiseKeyPair | null;
  private rs: Uint8Array | null;
  private rsVisible: boolean;
  private re: Uint8Array | null = null;
  private messageIndex = 0;
  private finished = false;
  private failed = false;

  constructor(params: {
    pattern: NoisePattern;
    initiator: boolean;
    prologue: Uint8Array;
    s: NoiseKeyPair | null;
    rs: Uint8Array | null;
    ephemeral: NoiseKeyPair | null;
  }) {
    this.symmetric = new SymmetricState(PROTOCOL_NAMES[params.pattern]);
    this.messages = PATTERNS[params.pattern];
    this.initiator = params.initiator;
    this.s = params.s;
    this.rs = params.rs;
    this.rsVisible = params.rs !== null;
    this.e = params.ephemeral;
    this.symmetric.mixHash(params.prologue);
    // Pre-message "<- s" (NK and IK): the responder's static public key.
    const preMessageStatic = this.initiator ? this.rs : this.s?.publicKey;
    if (!preMessageStatic) throw new NoiseProtocolError("missing responder static key");
    this.symmetric.mixHash(preMessageStatic);
  }

  writeMessage(payload: Uint8Array): Uint8Array {
    return this.guard(() => {
      const tokens = this.nextTokens(this.initiator);
      const parts: Uint8Array[] = [];
      for (const token of tokens) {
        switch (token) {
          case "e": {
            if (!this.e) this.e = generateNoiseKeyPair();
            parts.push(this.e.publicKey);
            this.symmetric.mixHash(this.e.publicKey);
            break;
          }
          case "s": {
            if (!this.s) throw new NoiseProtocolError("missing DH key");
            parts.push(this.symmetric.encryptAndHash(this.s.publicKey));
            break;
          }
          default:
            this.mixToken(token);
        }
      }
      parts.push(this.symmetric.encryptAndHash(payload));
      const message = concat(...parts);
      if (message.byteLength > NOISE_MAX_MESSAGE_BYTES) {
        throw new NoiseProtocolError("handshake message too large");
      }
      this.advance();
      return message;
    });
  }

  readMessage(message: Uint8Array): Uint8Array {
    return this.guard(() => {
      if (message.byteLength > NOISE_MAX_MESSAGE_BYTES) {
        throw new NoiseProtocolError("handshake message too large");
      }
      const tokens = this.nextTokens(!this.initiator);
      let offset = 0;
      const take = (length: number): Uint8Array => {
        if (message.byteLength < offset + length) {
          throw new NoiseProtocolError("handshake message truncated");
        }
        const out = message.slice(offset, offset + length);
        offset += length;
        return out;
      };
      for (const token of tokens) {
        switch (token) {
          case "e": {
            this.re = take(DH_BYTES);
            this.symmetric.mixHash(this.re);
            break;
          }
          case "s": {
            // Noise section 7.3: encrypted under the key from `es` when one is set.
            const length = this.symmetric.cipher.hasKey() ? DH_BYTES + NOISE_TAG_BYTES : DH_BYTES;
            this.rs = this.symmetric.decryptAndHash(take(length));
            break;
          }
          default:
            this.mixToken(token);
        }
      }
      const payload = this.symmetric.decryptAndHash(message.slice(offset));
      this.advance();
      // The remote static becomes visible only once the whole message, payload tag included, authenticated.
      if (this.rs) this.rsVisible = true;
      return payload;
    });
  }

  isComplete(): boolean {
    return this.messageIndex >= this.messages.length;
  }

  handshakeHash(): Uint8Array {
    return this.symmetric.handshakeHash();
  }

  remoteStatic(): Uint8Array | null {
    return this.rsVisible && this.rs ? this.rs.slice() : null;
  }

  split(): { send: CipherState; receive: CipherState } {
    if (this.failed) throw new NoiseProtocolError("handshake failed");
    if (!this.isComplete()) throw new NoiseProtocolError("handshake incomplete");
    if (this.finished) throw new NoiseProtocolError("handshake already split");
    this.finished = true;
    const [c1, c2] = this.symmetric.split();
    this.e?.secretKey.fill(0);
    this.e = null;
    return this.initiator ? { send: c1, receive: c2 } : { send: c2, receive: c1 };
  }

  private guard<T>(step: () => T): T {
    if (this.failed) throw new NoiseProtocolError("handshake failed");
    try {
      return step();
    } catch (error) {
      this.failed = true;
      this.e?.secretKey.fill(0);
      throw error;
    }
  }

  private nextTokens(expectedWriterIsInitiator: boolean): ReadonlyArray<Token> {
    if (this.isComplete() || this.finished) throw new NoiseProtocolError("handshake complete");
    const writerIsInitiator = this.messageIndex % 2 === 0;
    if (writerIsInitiator !== expectedWriterIsInitiator) {
      throw new NoiseProtocolError("handshake message out of turn");
    }
    return this.messages[this.messageIndex];
  }

  private advance(): void {
    this.messageIndex += 1;
  }

  /** Noise rev 34 section 7: the first letter names the initiator's key, the second the responder's. */
  private mixToken(token: "es" | "se" | "ss" | "ee"): void {
    switch (token) {
      case "es":
        return this.mixDh(this.initiator ? this.e : this.s, this.initiator ? this.rs : this.re);
      case "se":
        return this.mixDh(this.initiator ? this.s : this.e, this.initiator ? this.re : this.rs);
      case "ss":
        return this.mixDh(this.s, this.rs);
      case "ee":
        return this.mixDh(this.e, this.re);
    }
  }

  private mixDh(local: NoiseKeyPair | null, remote: Uint8Array | null): void {
    if (!local || !remote) throw new NoiseProtocolError("missing DH key");
    let shared: Uint8Array;
    try {
      shared = x25519.getSharedSecret(local.secretKey, remote);
    } catch {
      throw new NoiseProtocolError("invalid DH public key");
    }
    if (isAllZero(shared)) throw new NoiseProtocolError("invalid DH public key");
    this.symmetric.mixKey(shared);
    shared.fill(0);
  }
}

function requirePattern(pattern: unknown): asserts pattern is NoisePattern {
  if (pattern !== "NK" && pattern !== "IK") throw new NoiseProtocolError("unsupported handshake pattern");
}

function requireKeyLength(key: Uint8Array, label: string): void {
  if (key.byteLength !== DH_BYTES) throw new NoiseProtocolError(`${label} must be 32 bytes`);
}

function requireKeyPair(pair: NoiseKeyPair, label: string): void {
  requireKeyLength(pair.publicKey, `${label} public key`);
  requireKeyLength(pair.secretKey, `${label} secret key`);
}

function isAllZero(bytes: Uint8Array): boolean {
  let acc = 0;
  for (const byte of bytes) acc |= byte;
  return acc === 0;
}
