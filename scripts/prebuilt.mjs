#!/usr/bin/env node
// Official release installers: for apps Toolbay can't (or shouldn't) rebuild from source, use the
// maintainers' own latest release, so the app is exactly what they ship. Picks one Windows and one
// Mac download the Toolbay hub can install silently. Nothing is re-hosted: the manifest points at
// the original GitHub release files, pinned by size and sha256.
// Usage: node prebuilt.mjs <owner/repo> <plan.json in/out>    Env: GH_TOKEN
import fs from "node:fs";

const [repo, planPath] = process.argv.slice(2);
const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || "";

const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
  headers: { Accept: "application/vnd.github+json", "User-Agent": "toolbay-builds", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
});
if (!res.ok) {
  console.log("no release to use");
  process.exit(0);
}
const rel = await res.json();
const assets = (rel.assets || []).map((a) => ({ name: a.name, url: a.browser_download_url, size: a.size }));
const n = (a) => a.name.toLowerCase();
const not = /(arm64|aarch64|armv7|ia32|x86[-_.]?32|i386|win32[-_.]|\.blockmap|\.sig$|\.sha|debug|symbols|portable-?arm)/i;

// Windows: an installer the hub can run silently (NSIS, checked after download), else a portable zip.
const winExe = assets.filter((a) => /\.exe$/i.test(a.name) && !not.test(a.name) && /(setup|install|win|x64|amd64|x86_64)/i.test(a.name));
const winZip = assets.filter((a) => /\.zip$/i.test(a.name) && /(win|windows)/i.test(a.name) && !not.test(a.name) && !/(mac|darwin|osx|linux)/i.test(a.name));
const pickWin = [...winExe.sort((a, b) => Number(/setup|install/i.test(n(b))) - Number(/setup|install/i.test(n(a)))), ...winZip];
// Mac: a dmg (Apple silicon or universal first), else a mac zip.
const macDmg = assets.filter((a) => /\.dmg$/i.test(a.name) && !/(x64|x86_64|intel)(?!.*universal)/i.test(a.name));
const macDmgAny = assets.filter((a) => /\.dmg$/i.test(a.name));
const macZip = assets.filter((a) => /\.zip$/i.test(a.name) && /(mac|darwin|osx)/i.test(a.name) && !/(x64|x86_64|intel)/i.test(a.name));
const pickMac = [...macDmg.sort((a, b) => Number(/arm64|aarch64|universal/i.test(n(b))) - Number(/arm64|aarch64|universal/i.test(n(a)))), ...macDmgAny, ...macZip];

const prebuilt = {
  tag: rel.tag_name,
  version: String(rel.tag_name || "").replace(/^[vV]/, "").match(/^\d+(\.\d+){0,2}/)?.[0] || plan.version,
  publishedAt: rel.published_at,
  windows: pickWin.slice(0, 3),
  mac: pickMac.slice(0, 2),
};
if (!prebuilt.windows.length && !prebuilt.mac.length) {
  console.log("the latest release has no Windows or Mac download Toolbay can use");
  process.exit(0);
}
plan.prebuilt = prebuilt;
plan.version = prebuilt.version || plan.version;
plan.platforms = [prebuilt.windows.length ? "windows-x86_64" : null, prebuilt.mac.length ? "darwin-aarch64" : null].filter(Boolean);
// A project Toolbay can't build from source is fine when the makers ship installers.
if (!plan.supported) {
  plan.supported = true;
  plan.kind = "release";
  plan.reason = undefined;
}
fs.writeFileSync(planPath, JSON.stringify(plan, null, 2));
console.log(JSON.stringify(prebuilt, null, 2));
