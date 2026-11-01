// Scans test homes and logs for secrets seen during the e2e run. Prints counts and paths only.
//   secret-scan <secretsFile> <dir>...
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const [secretsFile, ...dirs] = process.argv.slice(2);
const secrets = readFileSync(secretsFile, "utf8")
  .split("\n")
  .map((s) => s.trim())
  .filter((s) => s.length >= 20);
const hits: Record<string, number> = {};
const expected: Record<string, number> = {};
let scanned = 0;
function walk(dir: string): void {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "node_modules" || name === "models") continue;
      walk(p);
    } else if (st.isFile() && st.size < 50 * 1024 * 1024 && p !== secretsFile) {
      scanned++;
      const text = readFileSync(p, "utf8");
      const n = secrets.filter((s) => text.includes(s)).length;
      if (!n) continue;
      // The member daemon's own hosts.json stores the current grant by design (0600).
      if (name === "hosts.json") expected[relative(process.cwd(), p)] = n;
      else hits[relative(process.cwd(), p)] = n;
    }
  }
}
for (const d of dirs) walk(d);
console.log(JSON.stringify({ secretsTracked: secrets.length, filesScanned: scanned, unexpectedFilesWithSecrets: hits, expectedHostsJson: expected }));
process.exit(Object.keys(hits).length ? 1 : 0);
