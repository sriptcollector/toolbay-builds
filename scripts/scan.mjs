#!/usr/bin/env node
// Toolbay's privacy and security check for one repo, run before anything is built.
// Usage: node scan.mjs <src dir> <plan.json> <out privacy.json>
// Inputs (optional, produced by the workflow before this runs):
//   $LICENSE_SPDX           SPDX id GitHub detected for the repo
//   gitleaks.json           secret scan (gitleaks dir --report-format json)
//   osv.json                dependency audit (osv-scanner --format json)
//   clamav.txt              malware scan (clamscan -r --infected)
// Writes {status, blocked, summary, license, checks:[{id,label,status,summary,details[]}], endpoints[]}
//   status: "passed" (nothing serious) | "failed" (do not list) ; blocked: build must not run.
import fs from "node:fs";
import path from "node:path";

const [srcArg, planPath, outPath] = process.argv.slice(2);
const src = path.resolve(srcArg);
const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
const readJson = (f) => {
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;
  }
};

// OSI-approved licenses (SPDX ids), the common ones GitHub detects.
const OSI = new Set([
  "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "0BSD", "ISC", "Zlib",
  "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
  "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
  "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2",
  "Artistic-2.0", "BSL-1.0", "ECL-2.0", "OSL-3.0", "AFL-3.0", "MS-PL", "MS-RL", "UPL-1.0", "NCSA", "PostgreSQL",
  "Unlicense", "CECILL-2.1", "LiLiQ-P-1.1", "MulanPSL-2.0", "WTFPL",
]);
// Not OSI-approved but sometimes mistaken for open source.
const NOT_OSI = { "CC-BY-NC-4.0": "a non-commercial Creative Commons license", "BUSL-1.1": "the Business Source License", "SSPL-1.0": "the Server Side Public License", "Elastic-2.0": "the Elastic License", "Commons-Clause": "the Commons Clause" };

const checks = [];
const add = (id, label, status, summary, details = []) => checks.push({ id, label, status, summary, details });

// ---- license
let spdx = (process.env.LICENSE_SPDX || "").trim();
if (!spdx || spdx === "NOASSERTION") {
  // GitHub couldn't tell; look at the file ourselves for the common texts.
  const f = plan.licenseFile && fs.readFileSync(path.join(src, plan.licenseFile), "utf8").slice(0, 4000);
  if (f) {
    if (/MIT License|Permission is hereby granted, free of charge/i.test(f)) spdx = "MIT";
    else if (/Apache License,?\s+Version 2\.0/i.test(f)) spdx = "Apache-2.0";
    else if (/GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3/i.test(f)) spdx = "AGPL-3.0";
    else if (/GNU LESSER GENERAL PUBLIC LICENSE/i.test(f)) spdx = /Version 3/i.test(f) ? "LGPL-3.0" : "LGPL-2.1";
    else if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(f)) spdx = "GPL-3.0";
    else if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(f)) spdx = "GPL-2.0";
    else if (/Mozilla Public License,?\s+(v\.|Version) 2\.0/i.test(f)) spdx = "MPL-2.0";
    else if (/Redistribution and use in source and binary forms/i.test(f)) spdx = /Neither the name/i.test(f) ? "BSD-3-Clause" : "BSD-2-Clause";
    else if (/This is free and unencumbered software released into the public domain/i.test(f)) spdx = "Unlicense";
    else if (/ISC License/i.test(f)) spdx = "ISC";
  }
}
let licenseOk = OSI.has(spdx);
if (licenseOk) add("license", "Open-source license", "passed", `${spdx}, an OSI-approved open-source license.`);
else if (NOT_OSI[spdx]) add("license", "Open-source license", "failed", `This project uses ${NOT_OSI[spdx]}, which isn't an approved open-source license. Toolbay only lists open-source software.`);
else if (!spdx) add("license", "Open-source license", "failed", "This project has no license file, so it isn't open source yet. Add a LICENSE file (MIT or Apache-2.0 are common) and try again.");
else add("license", "Open-source license", "failed", `Toolbay couldn't confirm "${spdx}" is an OSI-approved open-source license. Use a standard license file (MIT, Apache-2.0, GPL-3.0) and try again.`);

// ---- walk the source once
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "out", "target", ".next", "vendor", "__pycache__", ".venv", "venv"]);
const TEXT_EXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro|html?|css|json|rs|py|toml|ya?ml|go|swift|kt|java|rb|php|sh|ps1|md|txt|env|cfg|ini)$/i;
const BIN_EXT = /\.(exe|dll|so|dylib|bin|msi|scr|bat|cmd|vbs|jar|apk)$/i;
const files = [];
const binaries = [];
(function walk(dir, depth = 0) {
  if (depth > 12) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walk(p, depth + 1);
    } else if (e.isFile()) {
      const rel = path.relative(src, p).replace(/\\/g, "/");
      if (BIN_EXT.test(e.name)) binaries.push(rel);
      else if (TEXT_EXT.test(e.name) && fs.statSync(p).size < 1_500_000) files.push(rel);
    }
  }
})(src);

// ---- network endpoints the code talks to
const hosts = new Map();
const IGNORE_HOSTS = /(^|\.)(w3\.org|schema\.org|json-schema\.org|example\.(com|org)|localhost|127\.0\.0\.1|0\.0\.0\.0|github\.com|githubusercontent\.com|shields\.io|npmjs\.(com|org)|mozilla\.org|wikipedia\.org|apache\.org|opensource\.org|gnu\.org|creativecommons\.org|tauri\.app|reactjs\.org|react\.dev|vitejs\.dev|semver\.org|purl\.org|xmlns\.com|ogp\.me|svgjs\.dev)$/i;
const NET_CALL = /\b(fetch|axios|XMLHttpRequest|WebSocket|EventSource|requests\.(get|post)|urllib|httpx|reqwest|navigator\.sendBeacon)\b/;
const TRACKERS = /(google-analytics\.com|googletagmanager\.com|segment\.(io|com)|mixpanel\.com|amplitude\.com|hotjar\.com|sentry\.io|posthog\.com|plausible\.io|clarity\.ms|facebook\.net|doubleclick\.net|datadoghq\.com|fullstory\.com|logrocket\.com)/i;
let netCalls = 0;
for (const rel of files) {
  if (/(^|\/)(LICENSE|CHANGELOG|README)|\.md$|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock/i.test(rel)) continue;
  const text = fs.readFileSync(path.join(src, rel), "utf8");
  if (NET_CALL.test(text)) netCalls++;
  for (const m of text.matchAll(/\b(?:https?|wss?):\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)) {
    const h = m[1].toLowerCase();
    if (IGNORE_HOSTS.test(h)) continue;
    const entry = hosts.get(h) || { host: h, files: new Set(), tracker: TRACKERS.test(h) };
    entry.files.add(rel);
    hosts.set(h, entry);
  }
}
const endpoints = [...hosts.values()]
  .map((e) => ({ host: e.host, tracker: e.tracker, files: [...e.files].slice(0, 5), count: e.files.size }))
  .sort((a, b) => Number(b.tracker) - Number(a.tracker) || b.count - a.count)
  .slice(0, 60);
const trackers = endpoints.filter((e) => e.tracker);
if (!endpoints.length) add("network", "Internet connections", "passed", "No internet addresses found in the code. It should work offline.");
else
  add(
    "network",
    "Internet connections",
    trackers.length ? "warning" : "passed",
    trackers.length
      ? `Talks to ${endpoints.length} internet address${endpoints.length > 1 ? "es" : ""}, including ${trackers.length} analytics or tracking service${trackers.length > 1 ? "s" : ""} (${trackers.map((t) => t.host).join(", ")}).`
      : `Talks to ${endpoints.length} internet address${endpoints.length > 1 ? "es" : ""} (${endpoints.slice(0, 4).map((e) => e.host).join(", ")}${endpoints.length > 4 ? ", …" : ""}). No known trackers.`,
    endpoints.map((e) => `${e.host}${e.tracker ? " (analytics/tracking)" : ""} — ${e.files.join(", ")}`),
  );

// ---- permissions the app asks for
const perms = [];
const risky = [];
if (plan.kind === "tauri") {
  const capDir = path.join(src, plan.tauri.dir, "capabilities");
  const capFiles = fs.existsSync(capDir) ? fs.readdirSync(capDir).filter((f) => /\.(json|toml)$/.test(f)) : [];
  for (const f of capFiles) {
    const c = readJson(path.join(capDir, f));
    for (const p of c?.permissions || []) {
      const id = typeof p === "string" ? p : p.identifier;
      if (id) perms.push(id);
    }
  }
  const conf = readJson(path.join(src, plan.tauri.dir, "tauri.conf.json")) || {};
  for (const p of conf.tauri?.allowlist ? Object.entries(conf.tauri.allowlist).filter(([, v]) => v === true || v?.all) .map(([k]) => `${k}:all`) : []) perms.push(p);
  for (const p of perms) if (/^(shell:|fs:(allow-)?(write|remove|.*all)|process:|http:default|global-shortcut|autostart|clipboard-manager:allow-read)/.test(p) || /:all$/.test(p)) risky.push(p);
}
if (plan.kind === "electron") {
  for (const rel of files.filter((f) => /\.(m?[jt]s|cjs)$/.test(f))) {
    const t = fs.readFileSync(path.join(src, rel), "utf8");
    if (/nodeIntegration\s*:\s*true/.test(t)) risky.push(`nodeIntegration: true (${rel})`);
    if (/contextIsolation\s*:\s*false/.test(t)) risky.push(`contextIsolation: false (${rel})`);
    if (/webSecurity\s*:\s*false/.test(t)) risky.push(`webSecurity: false (${rel})`);
  }
}
const pkg = readJson(path.join(src, "package.json"));
for (const s of ["preinstall", "install", "postinstall"]) if (pkg?.scripts?.[s]) risky.push(`runs a script when installed: ${s} = "${pkg.scripts[s].slice(0, 120)}"`);
let shellUse = 0;
for (const rel of files.filter((f) => /\.(py|m?[jt]sx?|cjs|rs)$/.test(f))) {
  const t = fs.readFileSync(path.join(src, rel), "utf8");
  if (/\b(child_process|os\.system|subprocess\.|std::process::Command|Command::new)\b/.test(t)) shellUse++;
}
if (shellUse) perms.push(`starts other programs (${shellUse} file${shellUse > 1 ? "s" : ""})`);
const web = ["static-web", "vite-web", "web", "next-static"].includes(plan.kind);
if (web) add("permissions", "What it can access", "passed", "Runs as a web page in its own window. It can't read your files or start programs.");
else
  add(
    "permissions",
    "What it can access",
    risky.length ? "warning" : "passed",
    risky.length ? `Asks for ${risky.length} sensitive permission${risky.length > 1 ? "s" : ""} (for example ${risky[0]}). An admin reviews these before it's listed.` : perms.length ? `Asks for ${perms.length} standard permission${perms.length > 1 ? "s" : ""}.` : "Asks for no special permissions.",
    [...risky.map((r) => `sensitive: ${r}`), ...perms.filter((p) => !risky.includes(p)).slice(0, 40)],
  );

// ---- secrets committed to the repo
const leaks = (readJson("gitleaks.json") || []).filter((l) => !/test|example|sample|mock|fixture/i.test(l.File || ""));
if (!leaks.length) add("secrets", "Leaked passwords or keys", "passed", "No passwords, API keys or tokens found in the code.");
else
  add(
    "secrets",
    "Leaked passwords or keys",
    "warning",
    `Found ${leaks.length} thing${leaks.length > 1 ? "s" : ""} that look${leaks.length > 1 ? "" : "s"} like a password or key in the code. The owner should remove and replace ${leaks.length > 1 ? "them" : "it"}.`,
    leaks.slice(0, 20).map((l) => `${l.Description || l.RuleID} in ${l.File}:${l.StartLine}`),
  );

// ---- malware
const clam = fs.existsSync("clamav.txt") ? fs.readFileSync("clamav.txt", "utf8") : null;
const infected = clam ? [...clam.matchAll(/^(.+?):\s+(.+)\s+FOUND$/gm)].map((m) => `${path.relative(src, m[1]).replace(/\\/g, "/")}: ${m[2]}`) : [];
const obfuscated = files.filter((rel) => {
  if (!/\.(m?js|cjs)$/.test(rel) || /\.min\.js$/.test(rel)) return false;
  const t = fs.readFileSync(path.join(src, rel), "utf8");
  return /eval\(\s*(atob|Buffer\.from|unescape|String\.fromCharCode)\(/.test(t) || /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){200,}/i.test(t);
});
if (infected.length) add("malware", "Known malware", "failed", `The virus scanner flagged ${infected.length} file${infected.length > 1 ? "s" : ""}. Toolbay won't build this project.`, infected);
else if (obfuscated.length) add("malware", "Known malware", "warning", "No known malware, but some code is deliberately hidden (obfuscated). An admin will look at it.", obfuscated.slice(0, 20));
else add("malware", "Known malware", clam === null ? "warning" : "passed", clam === null ? "The virus scan didn't run." : "No known malware found.", binaries.length ? binaries.slice(0, 20).map((b) => `includes a program file: ${b}`) : []);

// ---- dependencies with known vulnerabilities
const osv = readJson("osv.json");
const vulns = [];
for (const r of osv?.results || []) for (const p of r.packages || []) for (const g of p.groups || p.vulnerabilities || []) {
  const sev = Number(g.max_severity || 0);
  vulns.push({ pkg: `${p.package?.name}@${p.package?.version}`, id: (g.ids || [g.id])[0], sev });
}
const critical = vulns.filter((v) => v.sev >= 9);
const high = vulns.filter((v) => v.sev >= 7 && v.sev < 9);
if (!osv) add("dependencies", "Outdated or unsafe libraries", "warning", "The library check didn't run.");
else if (!vulns.length) add("dependencies", "Outdated or unsafe libraries", "passed", "No libraries with known security problems.");
else
  add(
    "dependencies",
    "Outdated or unsafe libraries",
    critical.length ? "warning" : "passed",
    `${vulns.length} librar${vulns.length > 1 ? "ies have" : "y has"} a known security problem${critical.length ? `, ${critical.length} critical` : ""}${high.length ? `, ${high.length} high` : ""}.${critical.length ? " An admin reviews these before it's listed." : ""}`,
    [...critical, ...high, ...vulns.filter((v) => v.sev < 7)].slice(0, 40).map((v) => `${v.pkg}: ${v.id}${v.sev ? ` (severity ${v.sev})` : ""}`),
  );

const failed = checks.filter((c) => c.status === "failed");
const warnings = checks.filter((c) => c.status === "warning");
const blocked = !licenseOk || infected.length > 0 || !plan.supported;
const status = failed.length ? "failed" : "passed";
const summary = failed.length
  ? failed.map((c) => c.summary).join(" ")
  : warnings.length
    ? `Passed with ${warnings.length} thing${warnings.length > 1 ? "s" : ""} to review: ${warnings.map((w) => w.label.toLowerCase()).join(", ")}.`
    : "Passed: open-source license, no leaked keys, no known malware, no unsafe libraries found.";
const result = { status, blocked, summary, license: spdx || null, checkedAt: new Date().toISOString(), checks, endpoints };
fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
console.log(summary);
for (const c of checks) console.log(`- [${c.status}] ${c.label}: ${c.summary}`);
