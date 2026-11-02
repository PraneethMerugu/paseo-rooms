// Checks that repository paths named in the Markdown docs exist. Run from the repository root:
//   node tools/check-doc-paths.mjs
// It checks (1) relative Markdown links and (2) code spans that look like repository paths, for
// example `docs/design/specs/identity-v2/README.md` or `server/limits.ts`. A code span resolves
// against the repository root, then against the Markdown file's own directory. Globs, placeholders
// (<...>), home paths (~) and git-ignored locations are skipped. Exits 1 if anything is missing.
// The records under docs/ describe the code as it was when they were written, and
// server/noise/NOTICE.md names upstream Paseo files, so there only links and `docs/...` references
// are checked.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const root = process.cwd();
const tracked = execFileSync("git", ["ls-files", "-co", "--exclude-standard"], { encoding: "utf8" })
  .split("\n")
  .filter((f) => f.endsWith(".md") && !f.includes("node_modules/"));

const TOP = /^(docs|server|client|shared|test|tools|profile|ui-check)\/|^(index\.(server|client)\.tsx?|package\.json|paseo-plugin\.json|tsconfig[\w.]*\.json|[A-Z]+\.md)$/;
const IGNORED = /^(test\/m1-evidence|\.test-homes|node_modules)(\/|$)|\/(logs|\.homes|\.test-homes)(\/|$)/;

function exists(p, fromDir) {
  return [join(root, p), join(fromDir, p)].some((c) => existsSync(c));
}

const missing = [];
for (const file of tracked) {
  const text = readFileSync(file, "utf8");
  const fromDir = resolve(root, dirname(file));
  const historical = /^docs\/|^server\/noise\//.test(file);
  text.split("\n").forEach((line, i) => {
    for (const m of line.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = m[1].split("#")[0];
      if (!target || /^[a-z]+:/i.test(target) || !/^[\w./-]+$/.test(target)) continue;
      if (!existsSync(join(fromDir, target))) missing.push(`${file}:${i + 1}: link ${m[1]}`);
    }
    for (const m of line.matchAll(/`([^`\s]+)`/g)) {
      let p = m[1].replace(/[:#].*$/, "").replace(/[),.;]+$/, "");
      if (/[*<>~$]|^\.\.?\//.test(p) && !/^\.\.?\/[\w.-]/.test(p)) continue;
      if (/[*<>~${}]/.test(p)) continue;
      const looksLikePath = historical
        ? p.startsWith("docs/")
        : TOP.test(p) || (/\.(md|ts|tsx|sh|mjs|json|csv)$/.test(p) && p.includes("/"));
      if (!looksLikePath || IGNORED.test(p)) continue;
      if (!exists(p, fromDir)) missing.push(`${file}:${i + 1}: \`${m[1]}\``);
    }
  });
}

if (missing.length) {
  console.log(missing.join("\n"));
  console.log(`\n${missing.length} path reference(s) not found`);
  process.exit(1);
}
console.log(`ok: ${tracked.length} Markdown files, every repository path found`);
