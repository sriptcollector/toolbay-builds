#!/usr/bin/env node
// Write toolbay.json (schema 1, the format the Toolbay hub installs from) for one build.
// Usage: node manifest.mjs <plan.json> <artifacts dir> <release download base url> <out file>
// Each platform entry gets a direct `url`, so the hub can install from this file alone.
import fs from "node:fs";
import path from "node:path";

const [planPath, dir, base, outFile] = process.argv.slice(2);
const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
const platforms = {};
for (const f of fs.readdirSync(dir).filter((f) => /^entry-.*\.json$/.test(f))) {
  const { platform, entry } = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  platforms[platform] = { ...entry, url: `${base}/${encodeURIComponent(entry.asset)}` };
}
if (!Object.keys(platforms).length) {
  console.error("no platform builds to publish");
  process.exit(1);
}
const manifest = {
  schema: 1,
  id: plan.slug,
  name: plan.name,
  version: plan.version,
  // Not "repo": the hub would then look for updates in the source repo's own releases.
  sourceRepo: process.env.SOURCE_REPO || "",
  commit: process.env.SOURCE_SHA || "",
  ...(plan.identifier ? { identifier: plan.identifier } : { identifier: `ai.toolbay.app.${plan.slug.replace(/[^a-z0-9]/g, "")}` }),
  platforms,
  files: [],
  launch: { args: [] },
  builtBy: "toolbay-builds",
};
fs.writeFileSync(outFile, JSON.stringify(manifest, null, 2));
console.log(JSON.stringify(manifest, null, 2));
