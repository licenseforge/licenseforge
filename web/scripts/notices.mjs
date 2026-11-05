// Writes dist/THIRD_PARTY_NOTICES.txt: every production npm package in the
// lockfile (the ones the bundle can contain; dev tools are left out) with its
// license and the license files it ships. Run after `vite build`. Fails if a
// package has no license at all, so nothing ships unattributed.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const out = [
  "Third-party software in the LicenseForge dashboard bundle.",
  "Generated from web/package-lock.json (production dependencies).",
  "",
];
let count = 0;
for (const [path, p] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
  if (!path.startsWith("node_modules/") || p.dev || p.devOptional) continue;
  const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  const files = readdirSync(path).filter((f) => /^(licen[cs]e|copying|notice)/i.test(f));
  if (!p.license && files.length === 0) throw new Error(`${name}@${p.version}: no license`);
  out.push("=".repeat(72), `${name} ${p.version}`, `License: ${p.license ?? "see below"}`, "");
  for (const f of files) out.push(readFileSync(join(path, f), "utf8").trim(), "");
  count++;
}
writeFileSync("dist/THIRD_PARTY_NOTICES.txt", out.join("\n"));
console.log(`dist/THIRD_PARTY_NOTICES.txt: ${count} packages`);
