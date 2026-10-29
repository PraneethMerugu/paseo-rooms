// Samples /proc/*/cmdline every 100 ms and records, per label, how many processes matched a
// substring. Prints only counts (command lines can hold credentials such as MCP bearer tokens).
//   proc-sampler <outFile> <seconds> <label>=<substring> ...
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const [out, secondsArg, ...specs] = process.argv.slice(2);
const patterns = specs.map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)] as const);
const max: Record<string, number> = Object.fromEntries(patterns.map(([l]) => [l, 0]));
const deadline = Date.now() + Number(secondsArg) * 1000;
function sample() {
  const counts: Record<string, number> = Object.fromEntries(patterns.map(([l]) => [l, 0]));
  for (const pid of readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(pid) || pid === String(process.pid)) continue;
    let cmd = "";
    try {
      cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8");
    } catch {
      continue;
    }
    for (const [l, sub] of patterns) if (cmd.includes(sub)) counts[l]++;
  }
  for (const [l] of patterns) max[l] = Math.max(max[l], counts[l]);
  writeFileSync(out, JSON.stringify(max));
}
const stop = () => {
  sample();
  process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
const timer = setInterval(() => {
  sample();
  if (Date.now() > deadline) {
    clearInterval(timer);
    process.exit(0);
  }
}, 100);
