#!/usr/bin/env node
// Classify a checked-out repo: what kind of project is it, and how do we build it?
// Usage: node detect.mjs <repo dir>  -> prints JSON (see `plan` below).
//
// kinds:
//   tauri        existing Tauri app; built with its own `tauri build`
//   electron     existing Electron app; built with electron-builder
//   vite-web     Vite (React/Vue/Svelte/...) web app; static build wrapped in the Toolbay runner
//   next-static  Next.js with `output: "export"`; static build wrapped in the runner
//   next-server  Next.js that needs its server; bundled with Node and run by the runner
//   web          other Node web app with a build script producing a static folder
//   static-web   plain HTML/CSS/JS, no build step
//   python-cli   Python command-line tool or script; bundled Python + launcher window
//   node-cli     Node command-line tool; bundled Node + launcher window
//   unsupported  anything else, with a plain-words reason
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2] || ".");
// The workflow checks the repo out as "src"; name things after the real repo.
const repoName = (process.env.SOURCE_REPO || "").split("/")[1] || path.basename(root);
const exists = (p) => fs.existsSync(path.join(root, p));
const read = (p) => {
  try {
    return fs.readFileSync(path.join(root, p), "utf8");
  } catch {
    return null;
  }
};
const json = (p) => {
  const t = read(p);
  if (t == null) return null;
  try {
    return JSON.parse(t);
  } catch {
    // JSON5-ish (tauri.conf.json5, comments): strip comments and trailing commas.
    try {
      return JSON.parse(t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "").replace(/,\s*([}\]])/g, "$1"));
    } catch {
      return null;
    }
  }
};
const ls = (p = ".") => {
  try {
    return fs.readdirSync(path.join(root, p));
  } catch {
    return [];
  }
};

function packageManager(dir = ".") {
  const has = (f) => exists(path.join(dir, f));
  if (has("pnpm-lock.yaml")) return "pnpm";
  if (has("yarn.lock")) return "yarn";
  if (has("bun.lockb") || has("bun.lock")) return "bun";
  return "npm";
}

function runScript(pm, script) {
  return pm === "npm" ? `npm run ${script}` : `${pm} run ${script}`;
}

function installCmd(pm, dir = ".") {
  const has = (f) => exists(path.join(dir, f));
  switch (pm) {
    case "pnpm":
      return "pnpm install --frozen-lockfile=false";
    case "yarn":
      return "yarn install";
    case "bun":
      return "bun install";
    default:
      return has("package-lock.json") ? "npm ci --no-audit --no-fund" : "npm install --no-audit --no-fund";
  }
}

const deps = (pkg) => ({ ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) });

function slugify(s) {
  return (
    String(s || "")
      .toLowerCase()
      .replace(/^@[^/]+\//, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48) || "app"
  );
}

function titleCase(s) {
  return String(s || "App")
    .replace(/^@[^/]+\//, "")
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

/** Find an icon the project already ships, best first. */
function findIcon(extra = []) {
  const candidates = [
    ...extra,
    "src-tauri/icons/icon.png",
    "src-tauri/icons/128x128@2x.png",
    "build/icon.png",
    "assets/icon.png",
    "resources/icon.png",
    "public/icon.png",
    "public/logo.png",
    "public/logo512.png",
    "public/android-chrome-512x512.png",
    "public/apple-touch-icon.png",
    "public/favicon.png",
    "icon.png",
    "logo.png",
    "favicon.png",
    "public/favicon.ico",
    "favicon.ico",
  ];
  return candidates.find((c) => c && exists(c)) || null;
}

function licenseFile() {
  return ls().find((f) => /^(licen[sc]e|copying)(\.(md|txt))?$/i.test(f)) || null;
}

function base() {
  const pkg = json("package.json");
  const name = pkg?.productName || pkg?.build?.productName || pkg?.name || repoName;
  return {
    name: titleCase(name),
    slug: slugify(pkg?.name || repoName),
    version: /^\d+\.\d+\.\d+/.test(pkg?.version || "") && !/^0\.0\.0/.test(pkg.version) ? pkg.version : "1.0.0",
    description: pkg?.description || "",
    licenseFile: licenseFile(),
    icon: findIcon(),
  };
}

function unsupported(reason) {
  return { ...base(), kind: "unsupported", supported: false, reason };
}

function detect() {
  // ---- Tauri
  const tauriDirs = ["src-tauri", ...ls().filter((d) => fs.existsSync(path.join(root, d, "src-tauri")))
    .map((d) => `${d}/src-tauri`)];
  for (const dir of tauriDirs) {
    const confName = ["tauri.conf.json", "tauri.conf.json5", "Tauri.toml"].find((f) => exists(`${dir}/${f}`));
    if (!confName) continue;
    const conf = confName.endsWith(".toml") ? {} : json(`${dir}/${confName}`) || {};
    const appDir = path.posix.dirname(dir) === "." ? "." : path.posix.dirname(dir);
    const pkg = json(path.posix.join(appDir, "package.json"));
    const cargo = read(`${dir}/Cargo.toml`) || "";
    const v2 = /^\s*tauri\s*=\s*(\{[^}]*version\s*=\s*)?"[\^~=]?2/m.test(cargo) || "$schema" in conf && /config\/2/.test(conf.$schema) || "app" in conf || "bundle" in conf && !("tauri" in conf);
    const productName = conf.productName || conf.package?.productName || pkg?.productName || pkg?.name;
    const pm = packageManager(appDir);
    const d = deps(pkg);
    return {
      ...base(),
      name: titleCase(productName || repoName),
      version: conf.version && /^\d/.test(conf.version) ? conf.version : conf.package?.version || base().version,
      identifier: conf.identifier || conf.tauri?.bundle?.identifier || null,
      kind: "tauri",
      supported: true,
      tauri: { major: v2 ? 2 : 1, dir, appDir, cli: d["@tauri-apps/cli"] || null, hasPackageJson: !!pkg },
      packageManager: pm,
      install: pkg ? installCmd(pm, appDir) : null,
      icon: findIcon([`${dir}/icons/icon.png`, `${dir}/icons/128x128@2x.png`]),
      platforms: ["windows-x86_64", "darwin-aarch64"],
    };
  }

  const pkg = json("package.json");
  const d = deps(pkg);
  const scripts = pkg?.scripts || {};
  const pm = packageManager();

  // ---- monorepo with no app at the root
  if (pkg?.workspaces && !scripts.build && !d.electron && !d.vite && !d.next) {
    return unsupported(
      "This repo holds several projects in one (a monorepo), and Toolbay can't tell which one is the app yet.",
    );
  }

  // ---- Electron
  if (d.electron) {
    const builder = d["electron-builder"] ? "electron-builder" : d["@electron-forge/cli"] ? "forge" : "electron-builder";
    return {
      ...base(),
      kind: "electron",
      supported: true,
      packageManager: pm,
      install: installCmd(pm),
      build: scripts.build ? runScript(pm, "build") : null,
      electron: { builder, main: pkg.main || null },
      icon: findIcon(["build/icon.png", "build/icons/512x512.png"]),
      platforms: ["windows-x86_64", "darwin-aarch64"],
    };
  }

  // ---- Next.js
  if (d.next) {
    const conf = ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"].map(read).find(Boolean) || "";
    const exported = /output\s*:\s*["'`]export["'`]/.test(conf) || /next export/.test(scripts.build || "") ||
      /next export/.test(scripts.export || "");
    if (exported) {
      return {
        ...base(), kind: "next-static", supported: true, packageManager: pm, install: installCmd(pm),
        build: scripts.export && !/output/.test(conf) ? `${runScript(pm, "build")} && ${runScript(pm, "export")}` : runScript(pm, "build"),
        outDir: (conf.match(/distDir\s*:\s*["'`]([^"'`]+)/)?.[1]) || "out",
        platforms: ["windows-x86_64", "darwin-aarch64"],
      };
    }
    return {
      ...base(), kind: "next-server", supported: true, packageManager: pm, install: installCmd(pm),
      build: scripts.build ? runScript(pm, "build") : "npx next build",
      start: ["node", "node_modules/next/dist/bin/next", "start", "-p", "{port}", "-H", "127.0.0.1"],
      standalone: /output\s*:\s*["'`]standalone["'`]/.test(conf),
      note: "Runs its own local server inside the app (Next.js with server features).",
      platforms: ["windows-x86_64", "darwin-aarch64"],
    };
  }

  // ---- Vite and other built web apps
  const webDeps = ["vite", "react-scripts", "@vue/cli-service", "parcel", "webpack", "@sveltejs/kit", "astro", "@angular/cli", "gatsby", "svelte", "vue", "react", "preact", "solid-js", "lit"];
  const isWeb = webDeps.some((x) => d[x]) && (exists("index.html") || exists("public/index.html") || exists("src/index.html") || scripts.build);
  if (pkg && isWeb && scripts.build && !pkg.bin) {
    const viteConf = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.mts"].map(read).find(Boolean) || "";
    let outDir = viteConf.match(/outDir\s*:\s*["'`]([^"'`]+)/)?.[1];
    if (!outDir) {
      if (d["react-scripts"]) outDir = "build";
      else if (d["@sveltejs/kit"]) outDir = "build";
      else if (d.gatsby) outDir = "public";
      else if (d["@angular/cli"]) outDir = "dist";
      else outDir = "dist";
    }
    if (d["@sveltejs/kit"] && !d["@sveltejs/adapter-static"]) {
      return unsupported("This SvelteKit app needs a server and isn't set up for a static build (adapter-static), so Toolbay can't package it yet.");
    }
    return {
      ...base(),
      kind: d.vite ? "vite-web" : "web",
      supported: true,
      packageManager: pm,
      install: installCmd(pm),
      build: runScript(pm, "build"),
      outDir,
      // Relative asset paths so the build works from the app's own folder.
      viteBase: d.vite ? true : false,
      platforms: ["windows-x86_64", "darwin-aarch64"],
    };
  }

  // ---- Node CLI
  if (pkg && (pkg.bin || (pkg.main && !exists("index.html") && /cli|command|tool/i.test(`${pkg.description} ${(pkg.keywords || []).join(" ")}`)))) {
    const bin = typeof pkg.bin === "string" ? pkg.bin : pkg.bin ? Object.values(pkg.bin)[0] : pkg.main;
    return {
      ...base(), kind: "node-cli", supported: true, packageManager: pm, install: installCmd(pm),
      build: scripts.build ? runScript(pm, "build") : null,
      entry: bin,
      platforms: ["windows-x86_64", "darwin-aarch64"],
    };
  }

  // ---- static site (no build)
  const staticRoots = [".", "docs", "public", "site", "www", "src"];
  for (const r of staticRoots) {
    if (exists(path.join(r, "index.html")) && (!pkg || !scripts.build)) {
      return { ...base(), kind: "static-web", supported: true, outDir: r, icon: findIcon([path.join(r, "favicon.png"), path.join(r, "favicon.ico")]), platforms: ["windows-x86_64", "darwin-aarch64"] };
    }
  }

  // ---- Python
  const py = ls().filter((f) => f.endsWith(".py"));
  const pyproject = read("pyproject.toml");
  if (pyproject || exists("setup.py") || exists("setup.cfg") || py.length) {
    const scriptsSection = pyproject?.match(/\[project\.scripts\]([\s\S]*?)(\n\[|$)/)?.[1] || "";
    const entry = scriptsSection.match(/^\s*["']?([\w.-]+)["']?\s*=\s*["']([\w.]+):(\w+)["']/m);
    const mainPy = ["main.py", "app.py", "cli.py", "run.py", "__main__.py", `${repoName}.py`].find((f) => py.includes(f)) || (py.length === 1 ? py[0] : null);
    const gui = /tkinter|PySide|PyQt|customtkinter|flet|kivy|pygame/.test(py.map((f) => read(f) || "").join("\n") + (read("requirements.txt") || "") + (pyproject || ""));
    if (!entry && !mainPy && !pyproject && !exists("setup.py")) {
      return unsupported("Toolbay found Python files but no clear way to start the program (no main.py or entry point).");
    }
    return {
      ...base(),
      name: titleCase(pyproject?.match(/^name\s*=\s*["']([^"']+)/m)?.[1] || repoName),
      slug: slugify(pyproject?.match(/^name\s*=\s*["']([^"']+)/m)?.[1] || repoName),
      description: pyproject?.match(/^description\s*=\s*["']([^"']+)/m)?.[1] || "",
      kind: "python-cli",
      supported: true,
      python: {
        installable: !!(pyproject || exists("setup.py")),
        requirements: exists("requirements.txt") ? "requirements.txt" : null,
        entry: entry ? { module: entry[2], func: entry[3], name: entry[1] } : null,
        script: mainPy,
        gui,
      },
      platforms: ["windows-x86_64"],
    };
  }

  // ---- other languages
  if (exists("Cargo.toml")) return unsupported("This is a Rust program without a Tauri window. Toolbay can't package plain Rust programs yet.");
  if (exists("go.mod")) return unsupported("This is a Go program. Toolbay can't package Go programs yet.");
  if (ls().some((f) => /\.(sln|csproj)$/.test(f))) return unsupported("This is a .NET program. Toolbay can't package .NET programs yet.");
  if (exists("CMakeLists.txt") || exists("Makefile")) return unsupported("This is a C/C++ project. Toolbay can't package those yet.");
  if (exists("pubspec.yaml")) return unsupported("This is a Flutter app. Toolbay can't package Flutter apps yet.");
  if (exists("Package.swift") || ls().some((f) => f.endsWith(".xcodeproj"))) return unsupported("This is an Apple-only app (Swift/Xcode). Toolbay can't package those yet.");
  if (pkg) return unsupported("Toolbay couldn't find an app to open in this project (no web page, window, or command to run).");
  return unsupported("Toolbay couldn't recognise this project. It supports web apps, Tauri and Electron apps, and Python or Node command-line tools.");
}

const plan = detect();
process.stdout.write(JSON.stringify(plan, null, 2) + "\n");
