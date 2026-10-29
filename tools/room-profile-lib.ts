// Shared by tools/gen-room-profile.ts and the conformance test: protocol type enumeration,
// classification CSV parsing and the generated module text. Not part of the plugin bundle.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as messages from "@getpaseo/protocol/messages";
import { CLIENT_CAPS } from "@getpaseo/protocol/client-capabilities";

export const PLUGIN_DIR = join(import.meta.dirname, "..");
export const CSV_PATH = join(PLUGIN_DIR, "profile", "classification.csv");
export const GENERATED_PATH = join(PLUGIN_DIR, "server", "room-profile", "generated.ts");
export const FIELDS_CSV_PATH = join(PLUGIN_DIR, "profile", "fields.csv");

export type Direction = "inbound" | "outbound";
export type M1Action = "forward" | "gateway" | "deny";
export interface ClassificationRow {
  type: string;
  direction: Direction;
  daemonPermission: string;
  futureRole: string;
  m1Watch: M1Action;
  reason: string;
}

const def = (s: any): any => s?._zod?.def ?? s?.def ?? {};

/** Every `type` literal of the session message unions in the installed @getpaseo/protocol. */
export function protocolTypes(): { inbound: string[]; outbound: string[]; version: string } {
  const list = (schema: any): string[] =>
    def(schema).options.map((o: any) => def((def(o).shape ?? o.shape).type).values[0] as string);
  const pkg = JSON.parse(readFileSync(join(PLUGIN_DIR, "node_modules", "@getpaseo", "protocol", "package.json"), "utf8"));
  return {
    inbound: list((messages as any).SessionInboundMessageSchema).sort(),
    outbound: list((messages as any).SessionOutboundMessageSchema).sort(),
    version: pkg.version as string,
  };
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

export function readClassification(path = CSV_PATH): ClassificationRow[] {
  const lines = readFileSync(path, "utf8").split(/\r?\n/).filter((l) => l.trim());
  const header = parseCsvLine(lines[0]);
  const expected = ["type", "direction", "daemon_permission", "future_role", "m1_watch", "binding_or_reason"];
  if (header.join(",") !== expected.join(",")) throw new Error(`classification header must be ${expected.join(",")}`);
  return lines.slice(1).map((line, i) => {
    const c = parseCsvLine(line);
    if (c.length !== 6) throw new Error(`classification row ${i + 2}: expected 6 columns, got ${c.length}`);
    const [type, direction, daemonPermission, futureRole, m1Watch, reason] = c;
    if (direction !== "inbound" && direction !== "outbound") throw new Error(`row ${i + 2}: bad direction ${direction}`);
    if (!["forward", "gateway", "deny"].includes(m1Watch)) throw new Error(`row ${i + 2}: bad m1_watch ${m1Watch}`);
    if (!["watch", "steer", "approve", "owner", "never"].includes(futureRole)) throw new Error(`row ${i + 2}: bad future_role ${futureRole}`);
    if (m1Watch !== "deny" && futureRole !== "watch") throw new Error(`row ${i + 2}: ${type} allowed in M1 but future_role is ${futureRole}`);
    return { type, direction, daemonPermission, futureRole, m1Watch: m1Watch as M1Action, reason };
  });
}

export interface CoverageReport {
  unclassified: { inbound: string[]; outbound: string[] };
  stale: { inbound: string[]; outbound: string[] };
  duplicates: string[];
}

export function coverage(rows: ClassificationRow[], types = protocolTypes()): CoverageReport {
  const keyed = new Map<string, number>();
  for (const r of rows) keyed.set(`${r.direction}:${r.type}`, (keyed.get(`${r.direction}:${r.type}`) ?? 0) + 1);
  const has = (d: Direction, t: string) => keyed.has(`${d}:${t}`);
  const inProto = (d: Direction, t: string) => (d === "inbound" ? types.inbound : types.outbound).includes(t);
  return {
    unclassified: {
      inbound: types.inbound.filter((t) => !has("inbound", t)),
      outbound: types.outbound.filter((t) => !has("outbound", t)),
    },
    stale: {
      inbound: rows.filter((r) => r.direction === "inbound" && !inProto("inbound", r.type)).map((r) => r.type),
      outbound: rows.filter((r) => r.direction === "outbound" && !inProto("outbound", r.type)).map((r) => r.type),
    },
    duplicates: [...keyed.entries()].filter(([, n]) => n > 1).map(([k]) => k),
  };
}

// ------------------------------------------------------------------------------------------------
// Field-level review (B2): every field of every forwarded message and gateway-built object.

export type FieldAction = "keep" | "drop" | "redact" | "nested" | "gateway" | "force";
export interface FieldRow {
  object: string;
  field: string;
  action: FieldAction;
  reason: string;
}

const FIELD_ACTIONS: readonly FieldAction[] = ["keep", "drop", "redact", "nested", "gateway", "force"];

export function readFieldPolicy(path = FIELDS_CSV_PATH): FieldRow[] {
  const lines = readFileSync(path, "utf8").split(/\r?\n/).filter((l) => l.trim());
  const header = parseCsvLine(lines[0]);
  if (header.join(",") !== "object,field,action,reason") throw new Error("fields.csv header must be object,field,action,reason");
  return lines.slice(1).map((line, i) => {
    const c = parseCsvLine(line);
    if (c.length !== 4) throw new Error(`fields.csv row ${i + 2}: expected 4 columns, got ${c.length}`);
    const [object, field, action, reason] = c;
    if (!FIELD_ACTIONS.includes(action as FieldAction)) throw new Error(`fields.csv row ${i + 2}: bad action ${action}`);
    if (action === "force" && object !== "hello.capabilities") throw new Error(`fields.csv row ${i + 2}: force is only valid for hello.capabilities`);
    return { object, field, action: action as FieldAction, reason };
  });
}

function unwrap(schema: any): any {
  let s = schema;
  for (let i = 0; i < 32; i++) {
    const d = def(s);
    if (["optional", "nullable", "default", "catch", "readonly", "nonoptional", "prefault"].includes(d.type)) s = d.innerType;
    else if (d.type === "pipe") s = d.in;
    else if (d.type === "lazy") s = d.getter();
    else if (d.type === "array") s = d.element;
    else return s;
  }
  return s;
}

function shapeKeys(schema: any): string[] {
  const s = unwrap(schema);
  const d = def(s);
  if (d.type === "object") return Object.keys(d.shape);
  if (d.type === "union") return [...new Set<string>(d.options.flatMap((o: any) => shapeKeys(o)))];
  throw new Error(`not an object schema (${d.type})`);
}

function child(schema: any, key: string): any {
  const s = unwrap(schema);
  const d = def(s);
  if (d.type === "object") {
    if (!(key in d.shape)) throw new Error(`no field ${key}`);
    return d.shape[key];
  }
  if (d.type === "union") {
    for (const o of d.options) {
      const od = def(unwrap(o));
      if (od.type === "object" && key in od.shape) return od.shape[key];
    }
  }
  throw new Error(`no field ${key}`);
}

function unionOption(union: any, type: string): any {
  const opt = def(union).options.find((o: any) => def(def(o).shape?.type ?? def(o.shape?.type)).values?.[0] === type);
  if (!opt) throw new Error(`protocol has no message type ${type}`);
  return opt;
}

/** Protocol schema for one reviewed object name (see profile/fields.csv). */
export function fieldObjectSchema(object: string): any {
  const M = messages as any;
  const [head, ...path] = object.split(".");
  // Message type names contain dots, so split the "in:"/"out:" type off by matching known types.
  let base: any;
  let rest: string[] = path;
  if (head.startsWith("in:") || head.startsWith("out:")) {
    const dir = head.startsWith("in:") ? "in" : "out";
    const union = dir === "in" ? M.SessionInboundMessageSchema : M.SessionOutboundMessageSchema;
    const full = object.slice(dir.length + 1);
    const types: string[] = def(union).options.map((o: any) => def(def(o).shape.type).values[0]);
    const type = types.filter((t) => full === t || full.startsWith(`${t}.`)).sort((a, b) => b.length - a.length)[0];
    if (!type) throw new Error(`protocol has no message type for ${object}`);
    rest = full === type ? [] : full.slice(type.length + 1).split(".");
    base = unionOption(union, type);
    if (dir === "out") base = child(base, "payload");
  } else if (head === "hello") base = M.WSHelloMessageSchema;
  else if (head === "AgentSnapshot") base = M.AgentSnapshotPayloadSchema;
  else if (head === "WorkspaceDescriptor") base = M.WorkspaceDescriptorPayloadSchema;
  else if (head === "ProjectPlacement") base = M.ProjectPlacementPayloadSchema;
  else if (head === "AgentListEntry") base = child(child(unionOption(M.SessionOutboundMessageSchema, "fetch_agents_response"), "payload"), "entries");
  else throw new Error(`unknown reviewed object ${object}`);
  for (const k of rest) base = child(base, k);
  return base;
}

/** Field names the installed protocol defines for one reviewed object. */
export function protocolFields(object: string): string[] {
  const keys = shapeKeys(fieldObjectSchema(object));
  // capabilities is .passthrough(): CLIENT_CAPS lists the wire names that are not in the shape.
  if (object === "hello.capabilities") return [...new Set([...keys, ...Object.values(CLIENT_CAPS)])].sort();
  return keys.sort();
}

export interface FieldCoverage {
  unclassified: string[];
  stale: string[];
  duplicates: string[];
  missingObjects: string[];
  missingNested: string[];
}

/**
 * Field-level conformance: every field of every reviewed object is classified exactly once, every
 * allowed message type has a reviewed object, and every "nested" field has its own table.
 */
export function fieldCoverage(fieldRows: FieldRow[], classification: ClassificationRow[]): FieldCoverage {
  const byObject = new Map<string, FieldRow[]>();
  const seen = new Map<string, number>();
  for (const r of fieldRows) {
    byObject.set(r.object, [...(byObject.get(r.object) ?? []), r]);
    const k = `${r.object}#${r.field}`;
    seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  const unclassified: string[] = [];
  const stale: string[] = [];
  for (const [object, rows] of byObject) {
    let proto: string[];
    try {
      proto = protocolFields(object);
    } catch (e) {
      stale.push(`${object} (${(e as Error).message})`);
      continue;
    }
    const mine = new Set(rows.map((r) => r.field));
    for (const f of proto) if (!mine.has(f)) unclassified.push(`${object}#${f}`);
    for (const f of mine) if (!proto.includes(f)) stale.push(`${object}#${f}`);
  }
  const required = [
    "hello",
    "AgentSnapshot",
    "WorkspaceDescriptor",
    "ProjectPlacement",
    "AgentListEntry",
    ...classification.filter((r) => r.m1Watch !== "deny" && r.direction === "inbound").map((r) => `in:${r.type}`),
    ...classification.filter((r) => r.m1Watch !== "deny" && r.direction === "outbound" && r.type !== "status").map((r) => `out:${r.type}`),
  ];
  return {
    unclassified: unclassified.sort(),
    stale: stale.sort(),
    duplicates: [...seen.entries()].filter(([, n]) => n > 1).map(([k]) => k),
    missingObjects: required.filter((o) => !byObject.has(o)),
    missingNested: fieldRows.filter((r) => r.action === "nested" && !byObject.has(`${r.object}.${r.field}`)).map((r) => `${r.object}.${r.field}`),
  };
}

export function renderGenerated(rows: ClassificationRow[], protocolVersion: string, fieldRows: FieldRow[] = readFieldPolicy()): string {
  const pick = (d: Direction) =>
    rows
      .filter((r) => r.direction === d)
      .sort((a, b) => (a.type < b.type ? -1 : 1))
      .map((r) => `  ${JSON.stringify(r.type)}: ${JSON.stringify(r.m1Watch)},`)
      .join("\n");
  const prompting = rows
    .filter((r) => r.direction === "inbound" && (r.futureRole === "steer" || r.futureRole === "approve"))
    .map((r) => r.type)
    .sort()
    .map((t) => `  ${JSON.stringify(t)},`)
    .join("\n");
  const objects = [...new Set(fieldRows.map((r) => r.object))].sort();
  const fields = objects
    .map((o) => {
      const entries = fieldRows
        .filter((r) => r.object === o)
        .sort((a, b) => (a.field < b.field ? -1 : 1))
        .map((r) => `    ${JSON.stringify(r.field)}: ${JSON.stringify(r.action)},`)
        .join("\n");
      return `  ${JSON.stringify(o)}: {\n${entries}\n  },`;
    })
    .join("\n");
  return `// GENERATED by tools/gen-room-profile.ts from profile/classification.csv and profile/fields.csv. Do not edit.
// Protocol: @getpaseo/protocol ${protocolVersion}. Regenerate with \`npm run gen:profile\`.
// Values are the Milestone 1 watch-role action: "forward" (exact-id binding in filter.ts),
// "gateway" (answered or rewritten by the gateway) or "deny" (immediate rpc_error / drop).

export const ROOM_PROFILE_PROTOCOL_VERSION = ${JSON.stringify(protocolVersion)};

export type RoomProfileAction = "forward" | "gateway" | "deny";

export const INBOUND_WATCH: Readonly<Record<string, RoomProfileAction>> = {
${pick("inbound")}
};

export const OUTBOUND_WATCH: Readonly<Record<string, RoomProfileAction>> = {
${pick("outbound")}
};

/**
 * Inbound types whose future role is steer or approve (they prompt or drive the agent). Lanes run as
 * the owner's OS user in M1, so these stay denied whatever the table says (see filter.ts).
 */
export const PROMPTING_INBOUND: ReadonlySet<string> = new Set([
${prompting}
]);

export type FieldAction = "keep" | "drop" | "redact" | "nested" | "gateway" | "force";

/** Field-level policy from profile/fields.csv. Fields not listed are dropped. */
export const FIELD_POLICY: Readonly<Record<string, Readonly<Record<string, FieldAction>>>> = {
${fields}
};
`;
}
