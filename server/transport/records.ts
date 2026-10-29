// Records and frames inside a room endpoint Noise session (enrollment-v2.md sections 3.4 and 3.6).
//   Record = flags (1 byte) || fragment      flags: 0x00 = last fragment, 0x01 = more follow
// After Split() every WebSocket message is one Noise transport message (<= 65 535 bytes), whose
// plaintext is one record. A frame is the concatenation of its fragments, at most 4 MiB, and is
// one strict RJCS object { t, id?, re?, ... }. Fragments of different frames do not interleave.
// Any error (bad flags, empty fragment, oversized frame, bad AEAD tag, non-canonical RJCS, bad
// envelope) is fatal: the reader stays failed and the caller closes the session.
// Pure JS; nothing here logs frame contents.
import { NOISE_MAX_MESSAGE_BYTES, NOISE_TAG_BYTES, type CipherState } from "../noise/handshake-state";
import { rjcs, rjcsParse, RJCS_MAX_FRAME_BYTES, type RjcsValue } from "../proto/rjcs";

export const RECORD_FLAG_LAST = 0x00;
export const RECORD_FLAG_MORE = 0x01;
/** Largest record plaintext: one Noise transport message minus its tag. */
export const RECORD_MAX_BYTES = NOISE_MAX_MESSAGE_BYTES - NOISE_TAG_BYTES;
/** Largest fragment: a record minus its flags byte. */
export const FRAGMENT_MAX_BYTES = RECORD_MAX_BYTES - 1;
/** Largest frame (section 3.4). */
export const FRAME_MAX_BYTES = RJCS_MAX_FRAME_BYTES;
/** Request ids are 1..2^31 (section 3.6). */
export const FRAME_ID_MAX = 2 ** 31;

export type Frame = { t: string; id?: number; re?: number; [key: string]: RjcsValue | undefined };

export class RecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecordError";
  }
}

/** Envelope check of section 3.6: an object with a non-empty string `t`; `id` and `re` in 1..2^31. */
export function checkFrameEnvelope(value: unknown): Frame {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new RecordError("frame: not an object");
  const frame = value as Record<string, unknown>;
  if (typeof frame.t !== "string" || frame.t.length === 0) throw new RecordError("frame: bad t");
  for (const key of ["id", "re"] as const) {
    if (key in frame && !isFrameId(frame[key])) throw new RecordError(`frame: bad ${key}`);
  }
  return frame as Frame;
}

function isFrameId(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= FRAME_ID_MAX;
}

/** Encodes one frame as RJCS and splits it into records of at most `fragmentBytes` + 1 bytes. */
export function frameToRecords(frame: Frame, fragmentBytes = FRAGMENT_MAX_BYTES): Uint8Array[] {
  if (!Number.isSafeInteger(fragmentBytes) || fragmentBytes < 1 || fragmentBytes > FRAGMENT_MAX_BYTES) {
    throw new RecordError("records: bad fragment size");
  }
  checkFrameEnvelope(frame);
  let bytes: Uint8Array;
  try {
    bytes = rjcs(frame, FRAME_MAX_BYTES);
  } catch {
    throw new RecordError("frame: not encodable or too large");
  }
  const records: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.byteLength; offset += fragmentBytes) {
    const fragment = bytes.subarray(offset, offset + fragmentBytes);
    const last = offset + fragmentBytes >= bytes.byteLength;
    const record = new Uint8Array(1 + fragment.byteLength);
    record[0] = last ? RECORD_FLAG_LAST : RECORD_FLAG_MORE;
    record.set(fragment, 1);
    records.push(record);
  }
  return records;
}

/** Reassembles records into frames. Returns a frame when its last fragment arrives, else null. */
export class FrameAssembler {
  private parts: Uint8Array[] = [];
  private size = 0;
  private failed = false;

  push(record: Uint8Array): Frame | null {
    if (this.failed) throw new RecordError("records: reader failed");
    try {
      return this.accept(record);
    } catch (error) {
      this.failed = true;
      this.parts = [];
      throw error instanceof RecordError ? error : new RecordError("frame: not canonical RJCS");
    }
  }

  /** True while a frame is partly received. */
  pending(): boolean {
    return this.parts.length > 0;
  }

  private accept(record: Uint8Array): Frame | null {
    if (record.byteLength > RECORD_MAX_BYTES) throw new RecordError("records: record too large");
    if (record.byteLength < 2) throw new RecordError("records: empty fragment");
    const flags = record[0];
    if (flags !== RECORD_FLAG_LAST && flags !== RECORD_FLAG_MORE) throw new RecordError("records: bad flags");
    this.size += record.byteLength - 1;
    if (this.size > FRAME_MAX_BYTES) throw new RecordError("records: frame too large");
    this.parts.push(record.slice(1));
    if (flags === RECORD_FLAG_MORE) return null;
    const bytes = new Uint8Array(this.size);
    let offset = 0;
    for (const part of this.parts) {
      bytes.set(part, offset);
      offset += part.byteLength;
    }
    this.parts = [];
    this.size = 0;
    return checkFrameEnvelope(rjcsParse(bytes, FRAME_MAX_BYTES));
  }
}

const EMPTY_AD = new Uint8Array(0);

/** Encrypts one frame into Noise transport messages (empty associated data, as Paseo's relay). */
export function sealFrame(send: CipherState, frame: Frame, fragmentBytes = FRAGMENT_MAX_BYTES): Uint8Array[] {
  return frameToRecords(frame, fragmentBytes).map((record) => send.encryptWithAd(EMPTY_AD, record));
}

/** Decrypts transport messages and reassembles frames. Any failure is fatal for the session. */
export class FrameOpener {
  private readonly assembler = new FrameAssembler();
  private failed = false;

  constructor(private readonly receive: CipherState) {}

  open(message: Uint8Array): Frame | null {
    if (this.failed) throw new RecordError("records: reader failed");
    if (message.byteLength > NOISE_MAX_MESSAGE_BYTES) {
      this.failed = true;
      throw new RecordError("records: transport message too large");
    }
    let record: Uint8Array;
    try {
      record = this.receive.decryptWithAd(EMPTY_AD, message);
    } catch {
      this.failed = true;
      throw new RecordError("records: authentication failed");
    }
    try {
      return this.assembler.push(record);
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }
}
