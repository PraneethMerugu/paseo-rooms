// The member's MLS record at rest (mls-integration.md 8.1): one sealed file per device and group under
// the member's room directory, bound to its purpose. A failed write throws, so the member never
// acknowledges a state it did not write (8.2).
import nodePath from "node:path";
import type { Kek } from "../keystore/keystore";
import { rjcs, rjcsParse } from "../proto/rjcs";
import type { MemberRecord, MlsStore } from "./member";

export const mlsStatePath = (dataDir: string, roomId: string, deviceId: string) => nodePath.join(dataDir, "member", "rooms", roomId, `mls-${deviceId}.sealed`);
export const mlsStatePurpose = (roomId: string, deviceId: string) => `mls-state:${roomId}:${deviceId}`;

export class SealedMlsStore implements MlsStore {
  constructor(
    private readonly o: { dataDir: string; kek: Kek; roomId: string; deviceId: string },
  ) {}

  read(): MemberRecord | null {
    const plain = this.o.kek.readSealed(mlsStatePath(this.o.dataDir, this.o.roomId, this.o.deviceId), mlsStatePurpose(this.o.roomId, this.o.deviceId));
    if (!plain) return null;
    try {
      return rjcsParse(plain) as MemberRecord;
    } finally {
      plain.fill(0);
    }
  }

  write(r: MemberRecord): void {
    const plain = Buffer.from(rjcs(r, 16 * 1024 * 1024));
    try {
      this.o.kek.writeSealed(mlsStatePath(this.o.dataDir, this.o.roomId, this.o.deviceId), mlsStatePurpose(this.o.roomId, this.o.deviceId), plain);
    } finally {
      plain.fill(0);
    }
  }
}
