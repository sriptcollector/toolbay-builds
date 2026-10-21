#!/usr/bin/env node
// Toolbay's PC scan worker: the AI security review of uploaded packages, run on Orion's computer
// with Claude Code instead of an API key. A scheduled task in the Claude desktop app runs:
//
//   node worker/scan-worker.mjs fetch          pull waiting packages, unpack each into its own empty
//                                              sandbox, run the local deterministic checks, print jobs
//   (the task's read-only reviewer agents read each sandbox and write <job>/verdict.json)
//   node worker/scan-worker.mjs post <id>      send the verdict back to toolbay.ai
//   node worker/scan-worker.mjs clean          delete finished sandboxes
//
// Nothing in a package is ever executed here: unzip, read, pattern checks. Builds happen in CI.
// Config: %USERPROFILE%\.toolbay\scan-worker.json {"url": "https://toolbay.ai", "token": "tb_live_…"}
//   or {"url", "secret"} (TOOLBAY_WEBHOOK_SECRET, HMAC). Env TOOLBAY_URL / TOOLBAY_TOKEN override.
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const scripts = path.join(here, "..", "scripts");
const ROOT = process.env.TOOLBAY_SCAN_DIR || (process.platform === "win32" ? "C:\\tb-scan\\jobs" : path.join(os.tmpdir(), "tb-scan"));
const cfgFile = path.join(os.homedir(), ".toolbay", "scan-worker.json");
const cfg = fs.existsSync(cfgFile) ? JSON.parse(fs.readFileSync(cfgFile, "utf8")) : {};
const BASE = (process.env.TOOLBAY_URL || cfg.url || "https://toolbay.ai").replace(/\/+$/, "");
const TOKEN = process.env.TOOLBAY_TOKEN || cfg.token || "";
const SECRET = process.env.TOOLBAY_WORKER_SECRET || cfg.secret || "";
const TAR = process.platform === "win32" ? path.join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe") : "tar";

const MAX_FILES = 25_000;
const MAX_UNPACKED = 600 * 1024 * 1024;
// Files an AI coding tool would treat as instructions: renamed so the reviewer sees them only as data.
const AGENT_FILES = /^(CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md|\.claude|\.mcp\.json|\.cursor|\.cursorrules|\.windsurfrules|\.github\/copilot-instructions\.md)$/i;

function headers(method, p) {
  if (TOKEN) return { Authorization: `Bearer ${TOKEN}` };
  if (SECRET) {
    const ts = Math.floor(Date.now() / 1000);
    return { "X-Toolbay-Worker": `${ts}.${crypto.createHmac("sha256", SECRET).update(`${method} ${p} ${ts}`).digest("hex")}` };
  }
  throw new Error(`No credentials: put {"url","token"} in ${cfgFile}`);
}

async function api(method, p, body) {
  const res = await fetch(BASE + p, {
    method,
    headers: { ...headers(method, p), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(120_000),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { error: text.slice(0, 300) };
  }
  if (!res.ok) throw new Error(`${method} ${p}: HTTP ${res.status} ${data.error || ""}`);
  return data;
}

function unpack(zip, dest) {
  // List first (bsdtar shows links as "l…"): refuse links, absolute paths, .., bombs.
  const list = execFileSync(TAR, ["-tvf", zip], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).split(/\r?\n/).filter(Boolean);
  if (!list.length) throw new Error("empty or not a zip");
  if (list.length > MAX_FILES) throw new Error("too many files");
  let total = 0;
  for (const line of list) {
    const m = line.match(/^(\S)\S*\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$/);
    if (!m) continue;
    const [, type, size, raw] = m;
    const name = raw.replace(/\\/g, "/");
    if (type === "l" || / -> /.test(name)) throw new Error(`link in package: ${name}`);
    if (name.startsWith("/") || /(^|\/)\.\.(\/|$)/.test(name) || /^[a-z]:/i.test(name)) throw new Error(`unsafe path: ${name}`);
    total += Number(size);
  }
  if (total > MAX_UNPACKED) throw new Error("unpacks to more than 600 MB");
  fs.mkdirSync(dest, { recursive: true });
  execFileSync(TAR, ["-xf", zip, "-C", dest], { stdio: "pipe" });
  for (const junk of ["__MACOSX", ".DS_Store"]) fs.rmSync(path.join(dest, junk), { recursive: true, force: true });
  const top = fs.readdirSync(dest);
  if (top.length === 1 && !fs.existsSync(path.join(dest, "toolbay.json")) && fs.statSync(path.join(dest, top[0])).isDirectory()) {
    const tmp = `${dest}.tmp`;
    fs.renameSync(path.join(dest, top[0]), tmp);
    fs.rmSync(dest, { recursive: true, force: true });
    fs.renameSync(tmp, dest);
  }
}

function walk(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (!/^(node_modules|\.git|target|dist|build)$/.test(e.name)) walk(p, base, out);
    } else out.push(path.relative(base, p).replace(/\\/g, "/"));
  }
  return out;
}

function neutralize(src) {
  const renamed = [];
  for (const rel of [...walk(src), ...fs.readdirSync(src)]) {
    const leaf = rel.split("/").pop();
    if (!AGENT_FILES.test(rel) && !AGENT_FILES.test(leaf)) continue;
    const from = path.join(src, rel);
    if (!fs.existsSync(from)) continue;
    fs.renameSync(from, `${from}.untrusted`);
    renamed.push(rel);
  }
  return renamed;
}

/** Riskiest first, like src/lib/ai-scan.ts on the site. */
function rank(rel, text) {
  let s = 0;
  if (/(^|\/)(package\.json|build\.rs|Cargo\.toml|tauri\.conf\.json5?|electron-builder\.(json|ya?ml)|vite\.config\.\w+|setup\.py|pyproject\.toml)$/i.test(rel)) s += 100;
  if (/(^|\/)(main|index|preload|lib|app|background|server)\.(m?[jt]sx?|rs|py)$/i.test(rel)) s += 40;
  if (/\b(fetch|axios|XMLHttpRequest|WebSocket|https?\.request|reqwest|requests\.|child_process|exec\(|spawn\(|Command::new|subprocess|eval\(|new Function|atob\(|Buffer\.from\([^)]*base64)/.test(text)) s += 60;
  if (/homedir|AppData|Library\/Application Support|\.ssh|\.aws|Login Data|Cookies|keychain|wallet/i.test(text)) s += 80;
  if (/\.(md|txt|lock|svg|css)$/i.test(rel)) s -= 50;
  return s;
}

async function fetchJobs() {
  fs.mkdirSync(ROOT, { recursive: true });
  const { jobs } = await api("GET", "/api/v1/admin/scan-queue");
  const ready = [];
  for (const j of jobs) {
    const dir = path.join(ROOT, j.id);
    const started = Date.now();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    try {
      const res = await fetch(j.sourceUrl, { redirect: "error", signal: AbortSignal.timeout(120_000) });
      if (!res.ok) throw new Error(`download failed (HTTP ${res.status})`);
      const zip = Buffer.from(await res.arrayBuffer());
      const sha = crypto.createHash("sha256").update(zip).digest("hex");
      if (sha !== j.sha256) throw new Error(`hash mismatch (${sha})`);
      fs.writeFileSync(path.join(dir, "source.zip"), zip);
      const src = path.join(dir, "src");
      unpack(path.join(dir, "source.zip"), src);
      // Local deterministic checks (the same scripts CI uses), before anything is renamed.
      const env = { ...process.env, SOURCE_REPO: `package/${j.id}/x` };
      fs.writeFileSync(path.join(dir, "plan.json"), execFileSync(process.execPath, [path.join(scripts, "detect.mjs"), src], { env, encoding: "utf8" }));
      execFileSync(process.execPath, [path.join(scripts, "scan.mjs"), src, path.join(dir, "plan.json"), path.join(dir, "local.json")], { cwd: dir, env, stdio: "pipe" });
      const local = JSON.parse(fs.readFileSync(path.join(dir, "local.json"), "utf8"));
      const renamed = neutralize(src);
      const files = walk(src)
        .filter((f) => !/\.(png|jpe?g|gif|webp|ico|icns|woff2?|ttf|otf|mp[34]|wav|zip)$/i.test(f))
        .map((f) => {
          const full = path.join(src, f);
          const size = fs.statSync(full).size;
          const text = size < 2_000_000 ? fs.readFileSync(full, "utf8") : "";
          return { f, size, score: rank(f, text) };
        })
        .sort((a, b) => b.score - a.score || a.size - b.size);
      const job = {
        id: j.id,
        name: j.name,
        version: j.version,
        sha256: j.sha256,
        dir: src,
        started,
        files: files.length,
        sourceBytes: files.reduce((n, x) => n + x.size, 0),
        reviewOrder: files.slice(0, 60).map((x) => x.f),
        codeFiles: files.filter((x) => /\.(m?[jt]sx?|cjs|cts|mts|vue|svelte|astro|html?|rs|py|go|rb|php|java|kt|swift|c|cc|cpp|h|cs|sh|ps1|bat|cmd)$|(^|\/)(package\.json|build\.rs|Cargo\.toml|tauri\.conf\.json)$/i.test(x.f)).map((x) => x.f),
        renamedAgentFiles: renamed,
        localChecks: local.checks.map(({ id, label, status, summary }) => ({ id, label, status, summary })),
        localFailed: local.checks.filter((c) => c.status === "failed").map((c) => `${c.label}: ${c.summary} ${c.details.slice(0, 3).join("; ")}`),
      };
      fs.writeFileSync(path.join(dir, "job.json"), JSON.stringify(job, null, 2));
      ready.push(job);
    } catch (e) {
      // Can't unpack or verify: report it as an error so the package is held for a person.
      await api("POST", `/api/v1/admin/scan-results/${j.id}`, {
        status: "error", verdict: null, summary: `The PC security check couldn't open this package: ${e.message}`.slice(0, 500),
        findings: [], coverage: 0, models: [], sha256: j.sha256, durationMs: Date.now() - started,
      }).catch(() => {});
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  process.stdout.write(JSON.stringify({ jobs: ready.map(({ id, name, dir, files, sourceBytes, reviewOrder, localFailed }) => ({ id, name, dir, files, sourceBytes, reviewOrder: reviewOrder.slice(0, 25), localFailed })) }, null, 2) + "\n");
}

const SECRETISH = /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|tb_live_[A-Za-z0-9_-]{10,}|xox[abp]-[A-Za-z0-9-]{10,})/g;
const redact = (s) => String(s ?? "").replace(SECRETISH, "[redacted]");

function readVerdict(file) {
  if (!fs.existsSync(file)) return null;
  const raw = fs.readFileSync(file, "utf8");
  const m = raw.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]);
  } catch {
    return null;
  }
}

const SEVERITIES = ["low", "medium", "high", "critical"];
const CATEGORIES = ["malware", "backdoor", "credential_theft", "hidden_network", "data_exfiltration", "obfuscation", "crypto_miner", "security_md_mismatch", "dangerous_permission", "unsafe_build_script", "other"];
function cleanFindings(list, confirmedBy) {
  return (Array.isArray(list) ? list : []).slice(0, 40).map((f) => ({
    severity: SEVERITIES.includes(f?.severity) ? f.severity : "high",
    category: CATEGORIES.includes(f?.category) ? f.category : "other",
    file: redact(f?.file).slice(0, 300),
    evidence: redact(f?.evidence).slice(0, 300),
    explanation: redact(f?.explanation).slice(0, 600),
    ...(confirmedBy ? { confirmedBy } : {}),
  }));
}

async function post(id) {
  const dir = path.join(ROOT, id);
  const job = JSON.parse(fs.readFileSync(path.join(dir, "job.json"), "utf8"));
  const bulk = readVerdict(path.join(dir, "verdict-sonnet.json"));
  const final = readVerdict(path.join(dir, "verdict-opus.json"));
  const notes = [];
  if (job.renamedAgentFiles.length) notes.push(`Ignored AI-instruction files in the package: ${job.renamedAgentFiles.join(", ")}.`);
  let body;
  if (!bulk) {
    body = { status: "error", verdict: null, summary: "The AI reviewer gave no readable answer, so this upload waits for a person.", findings: [], coverage: 0, models: [] };
  } else {
    const use = final ?? bulk;
    const verdict = ["clean", "suspicious", "malicious"].includes(use.verdict) ? use.verdict : "suspicious";
    const findings = cleanFindings(use.findings, final ? "claude-opus-5-5" : undefined);
    // Coverage = share of the code files the reviewer says it read.
    const read = new Set((Array.isArray(bulk.files_reviewed) ? bulk.files_reviewed : []).map((f) => String(f).replace(/\\/g, "/").replace(/^\.\//, "")));
    const coverage = job.codeFiles.length ? job.codeFiles.filter((f) => read.has(f)).length / job.codeFiles.length : 1;
    if (coverage < 1) notes.push(`The AI read ${Math.round(coverage * 100)}% of the code files (riskiest first).`);
    const flaggedBulk = bulk.verdict !== "clean" || cleanFindings(bulk.findings).some((f) => f.severity !== "low");
    if (flaggedBulk && !final) notes.push("The first review flagged something and there was no second opinion; holding for a person.");
    const clean = verdict === "clean" && !findings.some((f) => f.severity === "high" || f.severity === "critical") && !(flaggedBulk && !final) && !job.localFailed.length;
    body = {
      status: clean ? "clean" : "flagged",
      verdict,
      summary: redact(use.summary).slice(0, 1500) || (clean ? "The AI review read the code and found nothing harmful or hidden." : "The AI review flagged this package."),
      findings,
      securityMdMismatches: (Array.isArray(bulk.security_md_mismatches) ? bulk.security_md_mismatches : []).slice(0, 20).map((x) => redact(x).slice(0, 400)),
      escalated: !!final,
      coverage,
      models: ["claude-sonnet-5-5", ...(final ? ["claude-opus-5-5"] : [])],
    };
  }
  body = {
    ...body,
    costUsd: 0, // runs on Orion's Claude subscription through Claude Code
    notes: [...notes, ...job.localFailed.map((x) => `Local check failed: ${x}`.slice(0, 480))].slice(0, 20),
    sha256: job.sha256,
    durationMs: Date.now() - job.started,
    localChecks: job.localChecks,
  };
  const out = await api("POST", `/api/v1/admin/scan-results/${id}`, body);
  fs.writeFileSync(path.join(dir, "posted.json"), JSON.stringify({ ...out, status: body.status, durationMs: body.durationMs }, null, 2));
  console.log(JSON.stringify({ id, status: body.status, verdict: body.verdict, published: out.published, reasons: out.reasons, seconds: Math.round(body.durationMs / 1000) }));
}

function clean() {
  if (!fs.existsSync(ROOT)) return;
  for (const id of fs.readdirSync(ROOT)) {
    const dir = path.join(ROOT, id);
    const done = fs.existsSync(path.join(dir, "posted.json"));
    const old = Date.now() - fs.statSync(dir).mtimeMs > 6 * 3600_000;
    if (done || old) fs.rmSync(dir, { recursive: true, force: true });
  }
}

const [cmd, arg] = process.argv.slice(2);
try {
  if (cmd === "fetch") await fetchJobs();
  else if (cmd === "post" && /^p[a-z0-9]{8,40}$/.test(arg || "")) await post(arg);
  else if (cmd === "clean") clean();
  else {
    console.error("usage: scan-worker.mjs fetch | post <id> | clean");
    process.exit(2);
  }
} catch (e) {
  console.error(`scan-worker: ${e.message}`);
  process.exit(1);
}
