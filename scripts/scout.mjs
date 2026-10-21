#!/usr/bin/env node
// Tool scout: find good free, open-source desktop apps people would want, and send them to
// toolbay.ai's "Scouted" review queue as draft listings. Toolbay then builds and checks each one
// (privacy check + compatibility check) and Orion approves or rejects it. Nothing is published
// automatically, and the original maintainers are always the credited authors.
//
// Env: GITHUB_TOKEN (search), SCOUT_URL (https://toolbay.ai/api/v1/scout), WEBHOOK_SECRET,
//      SCOUT_MAX (default 5: how many the site may add today), DRY_RUN=1 (print only).
import crypto from "node:crypto";

const TOKEN = process.env.GITHUB_TOKEN || "";
const MAX = Number(process.env.SCOUT_MAX || 5);
const DRY = process.env.DRY_RUN === "1";
const now = Date.now();
const day = 86_400_000;
const since = (days) => new Date(now - days * day).toISOString().slice(0, 10);

const OSI = new Set([
  "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Zlib", "MPL-2.0", "GPL-2.0", "GPL-3.0",
  "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "EPL-2.0", "Unlicense", "Artistic-2.0", "BSL-1.0", "EUPL-1.2", "MIT-0",
]);

// Not consumer desktop apps: libraries, dev tooling, servers, lists.
const NOT_APPS = /(^|-)(cli|library|lib|framework|sdk|api|devtools?|developer-tools|compiler|boilerplate|template|starter|awesome|awesome-list|vscode-extension|neovim|vim|plugin|server|self-hosted|docker|kubernetes|k8s|database|blockchain|crypto|web3|terminal|terminal-emulator|shell|ssh|git|gist|programming-language|ide|linter|testing|proxy|vpn|v2ray|xray|clash|mihomo|shadowsocks|sing-box|trojan|cheat|crack|claude-code|codex)($|-)/;
// Not for everyday people: dev tools, network proxy clients, command-line programs.
const NOT_APP_WORDS = /\b(framework|library|sdk|boilerplate|starter kit|template|awesome list|curated list|bindings|for developers|developers?|programmers?|cli|command[- ]line|terminal|ssh|proxy|vpn|v2ray|clash|claude code|codex|api keys?|coreutils|ls)\b/i;

// Paid products people look for free alternatives to: name -> company.
const PAID = {
  notion: ["Notion", "Notion Labs"], evernote: ["Evernote", "Evernote"], photoshop: ["Photoshop", "Adobe"],
  lightroom: ["Lightroom", "Adobe"], illustrator: ["Illustrator", "Adobe"], premiere: ["Premiere Pro", "Adobe"],
  "after effects": ["After Effects", "Adobe"], figma: ["Figma", "Figma"], sketch: ["Sketch", "Sketch B.V."],
  postman: ["Postman", "Postman"], slack: ["Slack", "Salesforce"], todoist: ["Todoist", "Doist"],
  trello: ["Trello", "Atlassian"], "1password": ["1Password", "AgileBits"], lastpass: ["LastPass", "LastPass"],
  grammarly: ["Grammarly", "Grammarly"], loom: ["Loom", "Atlassian"], "wispr flow": ["Wispr Flow", "Wispr"],
  cleanmymac: ["CleanMyMac", "MacPaw"], bartender: ["Bartender", "Surtees Studios"], alfred: ["Alfred", "Running with Crayons"],
  "microsoft office": ["Microsoft Office", "Microsoft"], "ms office": ["Microsoft Office", "Microsoft"],
  onenote: ["OneNote", "Microsoft"], "adobe acrobat": ["Adobe Acrobat", "Adobe"], acrobat: ["Adobe Acrobat", "Adobe"],
  "final cut": ["Final Cut Pro", "Apple"], camtasia: ["Camtasia", "TechSmith"], snagit: ["Snagit", "TechSmith"],
  teamviewer: ["TeamViewer", "TeamViewer"], anydesk: ["AnyDesk", "AnyDesk"], dropbox: ["Dropbox", "Dropbox"],
  "google keep": ["Google Keep", "Google"], "google photos": ["Google Photos", "Google"], spotify: ["Spotify", "Spotify"],
  airtable: ["Airtable", "Airtable"], miro: ["Miro", "Miro"], "adobe xd": ["Adobe XD", "Adobe"], audition: ["Audition", "Adobe"],
  "logic pro": ["Logic Pro", "Apple"], "ableton": ["Ableton Live", "Ableton"], "fl studio": ["FL Studio", "Image-Line"],
  "magnet": ["Magnet", "CrowdCafé"], "screenflow": ["ScreenFlow", "Telestream"], "cleanshot": ["CleanShot X", "MTW"],
  "raycast": ["Raycast", "Raycast"], "things": ["Things", "Cultured Code"], "bear": ["Bear", "Shiny Frog"],
  "ulysses": ["Ulysses", "Ulysses GmbH"], "scrivener": ["Scrivener", "Literature & Latte"], "parallels": ["Parallels", "Parallels"],
};

const QUERIES = [
  `topic:desktop-app stars:>800 pushed:>${since(180)} archived:false`,
  `topic:electron-app stars:>800 pushed:>${since(180)} archived:false`,
  `topic:tauri-app stars:>400 pushed:>${since(180)} archived:false`,
  `topic:windows-app stars:>500 pushed:>${since(180)} archived:false`,
  `topic:macos-app stars:>800 pushed:>${since(180)} archived:false`,
  `"alternative to" in:description stars:>1500 pushed:>${since(180)} archived:false`,
  `"open source alternative" in:description stars:>1500 pushed:>${since(180)} archived:false`,
];

async function gh(path) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(`https://api.github.com${path}`, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "toolbay-scout",
        ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
      },
    });
    if (res.status === 403 || res.status === 429) {
      await new Promise((r) => setTimeout(r, 15_000));
      continue;
    }
    if (!res.ok) return null;
    return res.json();
  }
  return null;
}

async function ghText(path) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: { Accept: "application/vnd.github.raw", "User-Agent": "toolbay-scout", ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}) },
  });
  return res.ok ? res.text() : "";
}

function plain(md) {
  return md
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)/g, "") // linked images (badges)
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "") // images
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1") // links -> their text
    .replace(/\[([^\]]+)\]\[[^\]]*\]/g, "$1") // reference links
    .replace(/^\s*\[[^\]]+\]:\s*\S+.*$/gm, "") // link definitions
    .replace(/https?:\/\/\S+/g, "")
    .replace(/\[\s*\]|\(\s*\)/g, "")
    .replace(/[*_`>#|]+/g, " ")
    .replace(/:[a-z_]+:/g, "")
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu, "")
    .replace(/\s+/g, " ")
    .replace(/\s+([.,;:!?])/g, "$1")
    .trim();
}

/** A paragraph that reads like a description: real sentences, not badges, links, tables or warnings. */
function readable(p) {
  if (p.length < 60) return false;
  if (/^(table of contents|contents|install|installation|build|building|license|caution|warning|note|important|disclaimer|download|screenshots?)\b/i.test(p)) return false;
  if (/shields\.io|badge|discord|sponsor|donate|translat/i.test(p)) return false;
  const words = p.split(/\s+/);
  const letters = (p.match(/[A-Za-z]/g) || []).length;
  return words.length >= 10 && letters / p.length > 0.7 && /[a-z]{3,} [a-z]{3,}/.test(p);
}

/** First real paragraph of the README, in plain words. */
function readmeIntro(md) {
  // Skip GitHub alert blocks ("> [!CAUTION] ...", disclaimers) before reading paragraphs.
  const para = md.split(/\n\s*\n/).filter((p) => !/^\s*>\s*\[!\w+\]/.test(p)).map(plain).find(readable) || "";
  if (para.length <= 600) return para;
  const cut = para.slice(0, 600);
  return cut.slice(0, Math.max(cut.lastIndexOf(". ") + 1, 300)).trim();
}

/** Screenshot-looking images from the README (absolute URLs, no badges or logos). */
function readmeShots(md, repo, branch) {
  const urls = [
    ...[...md.matchAll(/!\[[^\]]*\]\(([^)\s]+)/g)].map((m) => m[1]),
    ...[...md.matchAll(/<img[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]),
  ];
  const out = [];
  for (let u of urls) {
    if (/badge|shields\.io|logo|icon|sponsor|avatar|contrib|star-history|readme-stats|ytimg|youtube|\.svg(\?|$)/i.test(u)) continue;
    if (!/\.(png|jpe?g|gif|webp)(\?|$)/i.test(u) && !/user-attachments|githubusercontent/.test(u)) continue;
    if (!/^https?:/.test(u)) u = `https://raw.githubusercontent.com/${repo}/${branch}/${u.replace(/^\.?\//, "")}`;
    u = u.replace(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/blob\//, "https://raw.githubusercontent.com/$1/");
    if (!out.includes(u)) out.push(u);
    if (out.length >= 4) break;
  }
  return out;
}

function inspiredBy(text) {
  const t = text.toLowerCase();
  const m = t.match(/(?:alternative|replacement) (?:to|for) ([a-z0-9 .+'-]{2,30})/);
  const keys = Object.keys(PAID).sort((a, b) => b.length - a.length);
  const pick = (s) => keys.find((k) => new RegExp(`\\b${k.replace(/[.+]/g, "\\$&")}\\b`).test(s));
  const k = (m && pick(m[1])) || null;
  return k ? { name: PAID[k][0], company: PAID[k][1] } : null;
}

function title(name) {
  return name.replace(/[-_]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

async function candidate(r) {
  const repo = r.full_name;
  if (r.fork || r.archived || r.is_template || r.disabled) return null;
  const spdx = r.license?.spdx_id;
  if (!OSI.has(spdx)) return null;
  const topics = r.topics || [];
  if (topics.some((t) => NOT_APPS.test(t)) || NOT_APP_WORDS.test(r.description || "")) return null;

  const rel = await gh(`/repos/${repo}/releases/latest`);
  const assets = (rel?.assets || []).map((a) => a.name.toLowerCase());
  const installers = assets.filter((n) => /\.(exe|msi|dmg|appimage|deb|rpm)$|mac.*\.zip$|win.*\.zip$/.test(n));
  const buildable = topics.some((t) => /^(tauri|electron)(-app)?$/.test(t));
  const freshRelease = rel?.published_at && now - Date.parse(rel.published_at) < 365 * day;
  if (!(installers.length || buildable) || !freshRelease) return null;
  if (!installers.some((n) => /\.(exe|msi)$|win/.test(n)) && !buildable) return null; // Toolbay starts with Windows

  const md = await ghText(`/repos/${repo}/readme`);
  const owner = await gh(`/users/${r.owner.login}`);
  const contributors = (await gh(`/repos/${repo}/contributors?per_page=3`)) || [];
  const text = `${r.description || ""} ${topics.join(" ")} ${md.slice(0, 3000)}`;
  const insp = inspiredBy(text);
  const score =
    Math.log10(Math.max(r.stargazers_count, 1)) * 10 +
    Math.max(0, 10 - (now - Date.parse(r.pushed_at)) / (18 * day)) +
    (installers.length ? 5 : 0) +
    (insp ? 8 : 0);
  return {
    repo,
    repoUrl: r.html_url,
    score: Math.round(score * 10) / 10,
    stars: r.stargazers_count,
    license: spdx,
    pushedAt: r.pushed_at,
    lastRelease: rel?.tag_name || null,
    installers: installers.slice(0, 6),
    draft: {
      name: title(r.name),
      tagline: plain(r.description || "").slice(0, 140),
      description: readmeIntro(md) || plain(r.description || ""),
      screenshots: readmeShots(md, repo, r.default_branch),
      homepage: r.homepage || null,
      inspiredBy: insp,
      credit: {
        name: owner?.name || r.owner.login,
        login: r.owner.login,
        url: r.owner.html_url,
        maintainers: contributors.filter((c) => c.type === "User").map((c) => ({ login: c.login, url: c.html_url })),
      },
    },
  };
}

const seen = new Set();
const found = [];
// SCOUT_ONLY=owner/a,owner/b: just draft these (for checking drafts), no search.
if (process.env.SCOUT_ONLY) {
  for (const full of process.env.SCOUT_ONLY.split(",")) {
    const r = await gh(`/repos/${full.trim()}`);
    const c = r && (await candidate(r).catch((e) => (console.log(full, e.message), null)));
    console.log(JSON.stringify(c ? { repo: c.repo, ...c.draft } : { repo: full, skipped: true }, null, 2));
  }
  process.exit(0);
}
for (const q of QUERIES) {
  const res = await gh(`/search/repositories?q=${encodeURIComponent(q)}&sort=stars&order=desc&per_page=30`);
  for (const r of res?.items || []) {
    if (seen.has(r.full_name)) continue;
    seen.add(r.full_name);
    const c = await candidate(r).catch(() => null);
    if (c) found.push(c);
  }
}
found.sort((a, b) => b.score - a.score);
// Send extra so the site can skip ones it already has and still reach its daily cap.
const send = found.slice(0, MAX * 4);
console.log(`checked ${seen.size} repos, ${found.length} look like consumer desktop apps; sending ${send.length}`);
for (const c of send) console.log(`- ${c.score}  ${c.repo}  ★${c.stars}  ${c.license}${c.draft.inspiredBy ? `  (free alternative to ${c.draft.inspiredBy.name})` : ""}`);

if (DRY || !process.env.SCOUT_URL || !process.env.WEBHOOK_SECRET) {
  console.log(DRY ? "(dry run, nothing sent)" : "(no SCOUT_URL/WEBHOOK_SECRET, nothing sent)");
  process.exit(0);
}
const body = JSON.stringify({ max: MAX, candidates: send, at: new Date().toISOString() });
const sig = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update(body).digest("hex");
const res = await fetch(process.env.SCOUT_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Toolbay-Signature": `sha256=${sig}` },
  body,
});
console.log(`toolbay.ai: HTTP ${res.status} ${await res.text()}`);
if (!res.ok) process.exit(1);
