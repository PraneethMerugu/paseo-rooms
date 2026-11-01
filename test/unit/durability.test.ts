// D: durable writes (grants-v2 7.3), log clipping and limiting (C-5).
//
// The M1 parts of this file were removed at the identity v2 cut-over (I-15), with the code they tested;
// their v2 counterparts: revocation enforce-then-persist (P-13) and the grant allowlist (P-12/C-9) in
// v2-grants.test.ts (sections 4, 7.1/7.2, 8); the torn room log (C-11) in v2-room-host.test.ts; member
// rotation timers after a restart (C-12) in v2-grants.test.ts ("scheduler"); archived-agent lane
// closure (C-13) in v2-grants.test.ts.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { clip, LogLimiter } from "../../server/log";
import { writePrivateFile } from "../../server/platform/durable";
import { defaultProtection } from "../../server/platform/file-protection";
import { tempDir } from "./helpers";

test("durable writes leave no temp files and keep 0600", () => {
  const tmp = tempDir();
  try {
    const p = join(tmp.dir, "x", "state.json");
    writePrivateFile(p, "{}");
    writePrivateFile(p, '{"a":1}');
    assert.equal(readFileSync(p, "utf8"), '{"a":1}');
    assert.deepEqual(readdirSync(join(tmp.dir, "x")), ["state.json"]);
    assert.deepEqual(defaultProtection().verify(p), { ok: true });
  } finally {
    tmp.cleanup();
  }
});

test("C-5: peer strings are clipped and deny logs are limited per source", () => {
  assert.equal(clip("a\nb\u0000c"), "a?b?c");
  assert.match(clip("x".repeat(500))!, /…\(500\)$/);
  let t = 0;
  const lim = new LogLimiter(3, 60, 10, () => t);
  const written = Array.from({ length: 10 }, () => lim.log("k", "test_event", {})).filter(Boolean).length;
  assert.equal(written, 3);
  t += 1000; // one token per second at 60/min
  assert.equal(lim.log("k", "test_event", {}), true);
  assert.equal(lim.log("other", "test_event", {}), true, "buckets are per key");
});

test("a failed durable write leaves the previous file intact", () => {
  const tmp = tempDir();
  try {
    const dir = join(tmp.dir, "d");
    writePrivateFile(join(dir, "f.json"), "1");
    mkdirSync(join(dir, "g.json", "blocker"), { recursive: true });
    assert.throws(() => writePrivateFile(join(dir, "g.json"), "2"));
    assert.equal(readFileSync(join(dir, "f.json"), "utf8"), "1");
    assert.ok(existsSync(join(dir, "f.json")));
  } finally {
    tmp.cleanup();
  }
});
