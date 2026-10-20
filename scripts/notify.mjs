#!/usr/bin/env node
// Tell toolbay.ai how a build is going. Signed with HMAC-SHA256 so the site knows it's us.
// Usage: node notify.mjs <status> <step> [json file to merge into the body]
// Env: CALLBACK_URL, WEBHOOK_SECRET, BUILD_ID, RUN_URL. Missing URL or secret = no-op.
import crypto from "node:crypto";
import fs from "node:fs";

const [status, step, extraFile] = process.argv.slice(2);
const url = process.env.CALLBACK_URL;
const secret = process.env.WEBHOOK_SECRET;
if (!url || !secret || !/^https:\/\//.test(url)) {
  console.log(`(not notifying: ${!url ? "no callback url" : !secret ? "no secret" : "callback must be https"}) ${status} / ${step}`);
  process.exit(0);
}
let extra = {};
if (extraFile && fs.existsSync(extraFile)) extra = JSON.parse(fs.readFileSync(extraFile, "utf8"));
const body = JSON.stringify({ buildId: process.env.BUILD_ID, status, step, runUrl: process.env.RUN_URL, at: new Date().toISOString(), ...extra });
const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
for (let attempt = 1; attempt <= 3; attempt++) {
  try {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-Toolbay-Signature": `sha256=${sig}` }, body });
    console.log(`notified ${status} / ${step}: HTTP ${res.status}`);
    if (res.ok || res.status < 500) break;
  } catch (e) {
    console.log(`notify attempt ${attempt} failed: ${e.message}`);
  }
  await new Promise((r) => setTimeout(r, attempt * 2000));
}
