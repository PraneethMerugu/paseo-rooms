// Generates server/room-profile/generated.ts. Fails if any protocol type is unclassified or stale, or
// if any field of a forwarded message or gateway-built object is unreviewed or stale.
import { writeFileSync } from "node:fs";
import { coverage, fieldCoverage, GENERATED_PATH, protocolTypes, readClassification, readFieldPolicy, renderGenerated } from "./room-profile-lib";

const types = protocolTypes();
const rows = readClassification();
const fieldRows = readFieldPolicy();
const report = coverage(rows, types);
const fields = fieldCoverage(fieldRows, rows);
const problems = [
  ...report.unclassified.inbound.map((t) => `unclassified inbound: ${t}`),
  ...report.unclassified.outbound.map((t) => `unclassified outbound: ${t}`),
  ...report.stale.inbound.map((t) => `stale inbound (not in protocol): ${t}`),
  ...report.stale.outbound.map((t) => `stale outbound (not in protocol): ${t}`),
  ...report.duplicates.map((t) => `duplicate: ${t}`),
  ...fields.unclassified.map((f) => `unreviewed field: ${f}`),
  ...fields.stale.map((f) => `stale field (not in protocol): ${f}`),
  ...fields.duplicates.map((f) => `duplicate field: ${f}`),
  ...fields.missingObjects.map((o) => `allowed type or object without a field table: ${o}`),
  ...fields.missingNested.map((o) => `nested field without a table: ${o}`),
];
if (problems.length) {
  console.error(problems.join("\n"));
  console.error(`\n${problems.length} problem(s). Classify every type in profile/classification.csv and every field in profile/fields.csv (unclear => deny/drop).`);
  process.exit(1);
}
writeFileSync(GENERATED_PATH, renderGenerated(rows, types.version, fieldRows));
console.log(JSON.stringify({ wrote: GENERATED_PATH, protocol: types.version, inbound: types.inbound.length, outbound: types.outbound.length, fieldObjects: new Set(fieldRows.map((r) => r.object)).size, fields: fieldRows.length }));
