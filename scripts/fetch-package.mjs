#!/usr/bin/env node
// Download an uploaded Toolbay package (the .zip of an app's source) and unpack it safely.
// Usage: node fetch-package.mjs <dest dir>
// Env: SOURCE_URL (https://toolbay.ai/api/v1/packages/<BUILD_ID>/source), SOURCE_SHA256, BUILD_ID,
//      WEBHOOK_SECRET (signs the download link; the same secret that signs build webhooks).
// The sha256 was taken by toolbay.ai at upload time, so the code built here is exactly the code
// that was scanned there. Fails on any mismatch, unsafe path, link, or zip bomb.
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const dest = path.resolve(process.argv[2] || "src");
const { SOURCE_URL = "", SOURCE_SHA256 = "", BUILD_ID = "", WEBHOOK_SECRET = "" } = process.env;
const fail = (m) => {
  console.error(`::error::${m}`);
  process.exit(1);
};

const url = new URL(SOURCE_URL);
if (url.protocol !== "https:" && url.hostname !== "localhost") fail("source_url must be https");
if (url.pathname !== `/api/v1/packages/${BUILD_ID}/source`) fail("source_url doesn't match this build");
if (!/^[0-9a-f]{64}$/.test(SOURCE_SHA256)) fail("source_sha256 must be 64 hex characters");
if (WEBHOOK_SECRET) {
  const sig = crypto.createHmac("sha256", WEBHOOK_SECRET).update(`package-source:${BUILD_ID}`).digest("hex").slice(0, 40);
  url.searchParams.set("sig", sig);
}

const res = await fetch(url, { redirect: "error" });
if (!res.ok) fail(`couldn't download the package (${res.status})`);
const zip = Buffer.from(await res.arrayBuffer());
const got = crypto.createHash("sha256").update(zip).digest("hex");
if (got !== SOURCE_SHA256) fail(`package hash mismatch: expected ${SOURCE_SHA256}, got ${got}`);
const zipPath = path.resolve("source.zip");
fs.writeFileSync(zipPath, zip);

// List entries first: no absolute paths, no .., no symlinks, bounded size.
const listing = execFileSync("zipinfo", ["-l", zipPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).split("\n");
let total = 0;
let count = 0;
for (const line of listing) {
  const m = line.match(/^([-dl?][rwxsStT-]{9}|[-dl?]\S*)\s+\S+\s+\S+\s+(\d+)\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$/);
  if (!m) continue;
  const [, mode, size, , raw] = m;
  const name = raw.replace(/\\/g, "/"); // older Windows zips use backslashes
  count++;
  total += Number(size);
  if (mode.startsWith("l")) fail(`the package contains a link (${name}), which isn't allowed`);
  if (name.startsWith("/") || /(^|\/)\.\.(\/|$)/.test(name) || /^[a-z]:/i.test(name)) fail(`unsafe path in the package: ${name}`);
}
if (!count) fail("the package is empty or isn't a zip");
if (count > 25000) fail("the package has too many files");
if (total > 600 * 1024 * 1024) fail("the package unpacks to more than 600 MB");

fs.rmSync(dest, { recursive: true, force: true });
fs.mkdirSync(dest, { recursive: true });
execFileSync("unzip", ["-q", "-o", zipPath, "-d", dest], { stdio: "inherit" });
for (const junk of ["__MACOSX", ".DS_Store"]) fs.rmSync(path.join(dest, junk), { recursive: true, force: true });

// One wrapper folder (my-app/…) is the root.
const top = fs.readdirSync(dest);
if (top.length === 1 && !fs.existsSync(path.join(dest, "toolbay.json")) && fs.statSync(path.join(dest, top[0])).isDirectory()) {
  const inner = path.join(dest, top[0]);
  const tmp = `${dest}.tmp`;
  fs.renameSync(inner, tmp);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.renameSync(tmp, dest);
}
if (!fs.existsSync(path.join(dest, "toolbay.json"))) fail("the package has no toolbay.json at the top");
console.log(`Unpacked ${count} files (${(total / 1048576).toFixed(1)} MB), sha256 ${got}`);
