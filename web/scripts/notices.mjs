// Writes dist/THIRD_PARTY_NOTICES.txt: every npm package the bundle can
// contain (the lockfile's production dependencies, plus BUNDLED_DEV) with its
// license and the license files it ships. A package without license files gets
// the standard text of its license from licenses/ (SPDX license-list-data
// v3.29.0); a license outside that set fails the build, so nothing ships
// unattributed. Run after `vite build`.
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// devDependencies whose output is in the bundle: Tailwind's generated CSS.
// Keep in sync with BUNDLED_DEV in .github/workflows/release.yml (SBOM).
export const BUNDLED_DEV = new Set(["tailwindcss"]);

const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const vendored = new URL("licenses/", import.meta.url);
const out = [
  "Third-party software in the LicenseForge dashboard bundle.",
  "Generated from web/package-lock.json (production dependencies and bundled build output).",
  "",
];
let count = 0;
for (const [path, p] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
  if (!path.startsWith("node_modules/")) continue;
  const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  if ((p.dev || p.devOptional) && !BUNDLED_DEV.has(name)) continue;
  out.push("=".repeat(72), `${name} ${p.version}`, `License: ${p.license ?? "see below"}`, "");
  const files = readdirSync(path).filter((f) => /^(licen[cs]e|copying|notice)/i.test(f));
  for (const f of files) out.push(readFileSync(join(path, f), "utf8").trim(), "");
  if (files.length === 0) {
    const text = new URL(`${p.license}.txt`, vendored);
    if (!p.license || !existsSync(text)) throw new Error(`${name}@${p.version}: no license file and no vendored text for ${p.license}`);
    out.push(`(No license file in the package; the standard ${p.license} text follows.)`, readFileSync(text, "utf8").trim(), "");
  }
  count++;
}
for (const name of BUNDLED_DEV) {
  if (!lock.packages[`node_modules/${name}`]) throw new Error(`BUNDLED_DEV ${name} is not in the lockfile`);
}
writeFileSync("dist/THIRD_PARTY_NOTICES.txt", out.join("\n"));
console.log(`dist/THIRD_PARTY_NOTICES.txt: ${count} packages`);
