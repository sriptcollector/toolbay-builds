#!/usr/bin/env node
// Build one project for this computer and package it for the Toolbay hub.
// Usage: node package.mjs <plan.json> <src dir> <runner dir> <out dir>
//   runner dir: the unpacked Toolbay runner for this OS (toolbay-runner.exe, or "Toolbay App.app").
// Writes <out>/<asset> and <out>/entry.json (the toolbay.json platform entry, minus url).
// On failure writes <out>/error.json {message, detail} with a plain-words message and exits 1.
import { execFileSync, execSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const [planPath, srcArg, runnerArg, outArg] = process.argv.slice(2);
const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
const src = path.resolve(srcArg);
const runnerDir = path.resolve(runnerArg);
const out = path.resolve(outArg);
const isWin = process.platform === "win32";
const isMac = process.platform === "darwin";
const platformKey = `${isWin ? "windows" : isMac ? "darwin" : "linux"}-${process.arch === "arm64" ? "aarch64" : "x86_64"}`;
const work = path.join(os.tmpdir(), "tb-pkg");
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
fs.mkdirSync(out, { recursive: true });

class Friendly extends Error {
  constructor(message, detail) {
    super(message);
    this.detail = detail;
  }
}

function sh(cmd, cwd = src, env = {}) {
  console.log(`\n$ ${cmd}   (in ${path.relative(process.cwd(), cwd) || "."})`);
  const r = spawnSync(cmd, { cwd, shell: true, stdio: "inherit", env: { ...process.env, CI: "true", npm_config_engine_strict: "false", ...env } });
  if (r.status !== 0) throw new Error(`Command failed (${r.status}): ${cmd}`);
}

function step(name, friendly, fn) {
  console.log(`\n::group::${name}`);
  try {
    return fn();
  } catch (e) {
    if (e instanceof Friendly) throw e;
    throw new Friendly(friendly, String(e?.message || e));
  } finally {
    console.log("::endgroup::");
  }
}

function copyDir(from, to) {
  fs.cpSync(from, to, { recursive: true, dereference: false, filter: (p) => !/[\\/]\.git([\\/]|$)/.test(p) });
}

function zipDir(dir, zipPath) {
  fs.rmSync(zipPath, { force: true });
  if (isWin) {
    // tar on Windows 10+ is bsdtar and writes real zips with -a.
    const tar = path.join(process.env.SystemRoot || "C:/Windows", "System32", "tar.exe");
    execFileSync(tar, ["-a", "-c", "-f", zipPath, "-C", dir, ...fs.readdirSync(dir)], { stdio: "inherit" });
  } else {
    execSync(`cd "${dir}" && zip -qry "${zipPath}" .`, { stdio: "inherit", shell: "/bin/bash" });
  }
}

/** Unpack a .zip/.tar.gz with the system tar (bsdtar on Windows; Git's GNU tar can't read C:\ paths). */
function untar(file, dest) {
  const tar = isWin ? path.join(process.env.SystemRoot || "C:/Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-x", "-f", file, "-C", dest], { stdio: "inherit" });
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const safeName = (plan.name || "App").replace(/[^\w .()-]/g, "").trim() || "App";
const assetBase = `${plan.slug}-${plan.version}-${platformKey}`;

function installDeps(dir = src) {
  if (!plan.install) return;
  const pm = plan.packageManager;
  if (pm === "pnpm" || pm === "yarn") sh("corepack enable", dir);
  if (pm === "bun") sh("npm i -g bun", dir);
  try {
    sh(plan.install, dir);
  } catch (e) {
    if (pm === "npm" && /npm ci/.test(plan.install)) sh("npm install --no-audit --no-fund --legacy-peer-deps", dir);
    else throw e;
  }
}

/** An .ico holding one PNG (Windows Vista+ reads these), from a PNG or an existing .ico. */
function toIco(file) {
  const buf = fs.readFileSync(file);
  if (buf.readUInt16LE(0) === 0 && buf.readUInt16LE(2) === 1) return buf; // already a real .ico
  if (buf.subarray(1, 4).toString() !== "PNG") throw new Error("icon is not a PNG or ICO");
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  const head = Buffer.alloc(22);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(1, 4);
  head.writeUInt8(w >= 256 ? 0 : w, 6); head.writeUInt8(h >= 256 ? 0 : h, 7);
  head.writeUInt16LE(1, 10); head.writeUInt16LE(32, 12);
  head.writeUInt32LE(buf.length, 14); head.writeUInt32LE(22, 18);
  return Buffer.concat([head, buf]);
}

/** Stamp the project's own icon and name on the runner program (Windows). */
function setWindowsIcon(exe) {
  if (!isWin || !plan.icon) return;
  try {
    const tools = path.join(work, "icon-tools");
    fs.mkdirSync(tools, { recursive: true });
    execSync("npm init -y >NUL && npm i --no-audit --no-fund rcedit@4", { cwd: tools, stdio: "inherit", shell: "cmd.exe" });
    const ico = path.join(work, "icon.ico");
    fs.writeFileSync(ico, toIco(path.join(src, plan.icon)));
    execSync(`node -e "(require('rcedit').rcedit||require('rcedit'))(process.argv[1],{icon:process.argv[2],'version-string':{ProductName:process.argv[3],FileDescription:process.argv[3]}}).then(()=>console.log('icon set'))" "${exe}" "${ico}" "${safeName}"`, { cwd: tools, stdio: "inherit" });
  } catch (e) {
    console.log(`(icon not applied: ${String(e.message).split(String.fromCharCode(10))[0]})`);
  }
}

/**
 * Wrap a payload folder (www/, app/, runtimes) with the Toolbay runner.
 * Windows: <slug>.exe + toolbay/   macOS: <Name>.app with toolbay/ in Resources.
 */
function wrap(payloadFn, appJson) {
  const stage = path.join(work, "stage");
  fs.rmSync(stage, { recursive: true, force: true });
  fs.mkdirSync(stage, { recursive: true });
  let payload, entry;
  if (isWin) {
    const exeName = `${plan.slug}.exe`;
    fs.copyFileSync(path.join(runnerDir, "toolbay-runner.exe"), path.join(stage, exeName));
    setWindowsIcon(path.join(stage, exeName));
    payload = path.join(stage, "toolbay");
    entry = { kind: "zip", exe: exeName };
  } else {
    const appName = `${safeName}.app`;
    const appDir = path.join(stage, appName);
    execSync(`ditto "${path.join(runnerDir, "Toolbay App.app")}" "${appDir}"`);
    payload = path.join(appDir, "Contents", "Resources", "toolbay");
    entry = { kind: "zip", exe: appName, app: appName };
  }
  fs.mkdirSync(payload, { recursive: true });
  payloadFn(payload);
  fs.writeFileSync(
    path.join(payload, "app.json"),
    JSON.stringify({ id: plan.slug, name: plan.name, description: plan.description || "", ...appJson }, null, 2),
  );
  if (isMac) {
    const appDir = path.join(stage, `${safeName}.app`);
    const plist = path.join(appDir, "Contents", "Info.plist");
    const id = `ai.toolbay.app.${plan.slug.replace(/[^a-z0-9]/g, "")}`;
    for (const [k, v] of [["CFBundleIdentifier", id], ["CFBundleName", safeName], ["CFBundleDisplayName", safeName]]) {
      execSync(`/usr/libexec/PlistBuddy -c "Set :${k} ${v}" "${plist}" || /usr/libexec/PlistBuddy -c "Add :${k} string ${v}" "${plist}"`, { shell: "/bin/bash" });
    }
    // Re-sign ad hoc after editing the bundle so macOS will open it.
    execSync(`codesign --force --deep -s - "${appDir}"`, { stdio: "inherit" });
  }
  const asset = `${assetBase}.zip`;
  zipDir(stage, path.join(out, asset));
  return { ...entry, asset };
}

function findStatic(dirs) {
  for (const d of dirs) {
    const p = path.join(src, d);
    if (fs.existsSync(path.join(p, "index.html"))) return p;
  }
  return null;
}

const STATIC_SKIP = /(^|[\\/])(node_modules|\.git|\.github|test|tests|__tests__|\.vscode)([\\/]|$)/;

function packageStatic(root) {
  return wrap(
    (payload) => {
      fs.cpSync(root, path.join(payload, "www"), { recursive: true, filter: (p) => !STATIC_SKIP.test(path.relative(root, p)) });
    },
    { mode: "static", root: "www", spa: true, width: plan.width || 1200, height: plan.height || 820 },
  );
}

// ---------------------------------------------------------------- runtimes

async function fetchTo(url, file) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download ${url}: ${res.status}`);
  fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
}

/** Official Node.js for this OS, unpacked into <dest> so node(.exe) sits at <dest>/node(.exe). */
async function bundleNode(dest) {
  const ver = process.version; // the same Node the build used
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  if (isWin) {
    const zip = path.join(work, "node.zip");
    await fetchTo(`https://nodejs.org/dist/${ver}/node-${ver}-win-${arch}.zip`, zip);
    untar(zip, work);
    fs.mkdirSync(dest, { recursive: true });
    fs.copyFileSync(path.join(work, `node-${ver}-win-${arch}`, "node.exe"), path.join(dest, "node.exe"));
  } else {
    const tgz = path.join(work, "node.tgz");
    await fetchTo(`https://nodejs.org/dist/${ver}/node-${ver}-darwin-${arch}.tar.gz`, tgz);
    untar(tgz, work);
    fs.mkdirSync(dest, { recursive: true });
    fs.copyFileSync(path.join(work, `node-${ver}-darwin-${arch}`, "bin", "node"), path.join(dest, "node"));
    fs.chmodSync(path.join(dest, "node"), 0o755);
  }
}

/** Relocatable CPython (python-build-standalone, includes tkinter) unpacked to <dest>. */
async function bundlePython(dest) {
  const rel = await (await fetch("https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest", {
    headers: process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {},
  })).json();
  const triple = isWin ? "x86_64-pc-windows-msvc" : process.arch === "arm64" ? "aarch64-apple-darwin" : "x86_64-apple-darwin";
  const asset = rel.assets.find((a) => new RegExp(`^cpython-3\\.12\\.\\d+\\+\\d+-${triple}-install_only\\.tar\\.gz$`).test(a.name));
  if (!asset) throw new Error("no python build found");
  const tgz = path.join(work, "python.tgz");
  await fetchTo(asset.browser_download_url, tgz);
  untar(tgz, work);
  fs.renameSync(path.join(work, "python"), dest);
  return isWin ? path.join(dest, "python.exe") : path.join(dest, "bin", "python3");
}

// ---------------------------------------------------------------- kinds

async function build() {
  switch (plan.kind) {
    case "static-web": {
      const root = path.join(src, plan.outDir || ".");
      return step("Package the web app", "Toolbay couldn't package this web page.", () => packageStatic(root));
    }

    case "vite-web":
    case "web":
    case "next-static": {
      step("Install dependencies", "Installing the project's dependencies failed. The project may need extra setup that Toolbay can't do automatically.", () => installDeps());
      step("Build the web app", "The project's own build step failed, so there was nothing to package.", () =>
        sh(plan.build, src, plan.kind === "vite-web" ? {} : { NEXT_TELEMETRY_DISABLED: "1" }),
      );
      const root = findStatic([plan.outDir, "dist", "build", "out", "public", "dist/browser", `dist/${plan.slug}`, `dist/${plan.slug}/browser`].filter(Boolean));
      if (!root) throw new Friendly("The build finished but Toolbay couldn't find the finished web page (no index.html in dist, build or out).");
      return step("Package the web app", "Toolbay couldn't package the finished web app.", () => packageStatic(root));
    }

    case "next-server": {
      step("Install dependencies", "Installing the project's dependencies failed.", () => installDeps());
      step("Build the web app", "The project's own build step failed, so there was nothing to package.", () =>
        sh(plan.build, src, { NEXT_TELEMETRY_DISABLED: "1" }),
      );
      const standalone = path.join(src, ".next", "standalone");
      const useStandalone = fs.existsSync(path.join(standalone, "server.js"));
      const entry = await (async () => {
        const nodeDir = path.join(work, "node-rt");
        await bundleNode(nodeDir);
        return wrap(
          (payload) => {
            const app = path.join(payload, "app");
            if (useStandalone) {
              copyDir(standalone, app);
              if (fs.existsSync(path.join(src, ".next", "static"))) copyDir(path.join(src, ".next", "static"), path.join(app, ".next", "static"));
              if (fs.existsSync(path.join(src, "public"))) copyDir(path.join(src, "public"), path.join(app, "public"));
            } else {
              copyDir(src, app);
            }
            copyDir(nodeDir, path.join(payload, "node"));
          },
          {
            mode: "server",
            command: useStandalone ? [isWin ? "node/node.exe" : "node/node", "server.js"] : [isWin ? "node/node.exe" : "node/node", "node_modules/next/dist/bin/next", "start", "-p", "{port}", "-H", "127.0.0.1"],
            cwd: "app",
            env: { NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1" },
            url: "http://127.0.0.1:{port}/",
            width: 1280,
            height: 840,
          },
        );
      })();
      return entry;
    }

    case "node-cli": {
      step("Install dependencies", "Installing the project's dependencies failed.", () => installDeps());
      if (plan.build) step("Build the tool", "The project's own build step failed.", () => sh(plan.build));
      const nodeDir = path.join(work, "node-rt");
      await bundleNode(nodeDir);
      return wrap(
        (payload) => {
          copyDir(src, path.join(payload, "app"));
          copyDir(nodeDir, path.join(payload, "node"));
        },
        { mode: "cli", command: [isWin ? "node/node.exe" : "node/node", plan.entry], cwd: "app", argsHint: "Options, e.g. --help", examples: ["--help"], width: 900, height: 640 },
      );
    }

    case "python-cli": {
      const pyDir = path.join(work, "python");
      const py = await bundlePython(pyDir).catch((e) => {
        throw new Friendly("Toolbay couldn't download Python for this tool. Try again in a few minutes.", String(e));
      });
      step("Install the tool", "Installing this Python project's requirements failed.", () => {
        if (plan.python.requirements) sh(`"${py}" -m pip install --no-warn-script-location -r ${plan.python.requirements}`);
        if (plan.python.installable) sh(`"${py}" -m pip install --no-warn-script-location .`);
      });
      const pyRel = isWin ? "python/python.exe" : "python/bin/python3";
      let command;
      if (plan.python.entry) command = [pyRel, "-c", `import sys; from ${plan.python.entry.module} import ${plan.python.entry.func} as m; sys.argv[0]='${plan.python.entry.name}'; sys.exit(m())`];
      else command = [pyRel, `app/${plan.python.script}`];
      return wrap(
        (payload) => {
          copyDir(pyDir, path.join(payload, "python"));
          copyDir(src, path.join(payload, "app"));
        },
        plan.python.gui
          ? { mode: "process", command, cwd: "app" }
          : { mode: "cli", command, cwd: "app", argsHint: "Options, e.g. --help", examples: ["--help"], width: 900, height: 640 },
      );
    }

    case "tauri": {
      const t = plan.tauri;
      const appDir = path.join(src, t.appDir);
      if (t.hasPackageJson) step("Install dependencies", "Installing the app's dependencies failed.", () => installDeps(appDir));
      const cli = t.cli ? (plan.packageManager === "npm" ? "npx tauri" : `${plan.packageManager} tauri`) : `npx -y @tauri-apps/cli@${t.major}`;
      // Turn off the app's own auto-updater signing; Toolbay ships updates instead.
      const override = t.major === 2 ? { bundle: { createUpdaterArtifacts: false } } : { tauri: { updater: { active: false } } };
      const cfgFile = path.join(work, "tb-override.json");
      fs.writeFileSync(cfgFile, JSON.stringify(override));
      const bundles = isWin ? "nsis" : "app";
      step("Build the app", "The app's own build failed on Toolbay's build machine. It may need tools or settings Toolbay doesn't have.", () =>
        sh(`${cli} build --bundles ${bundles} --config "${cfgFile}"`, appDir, { TAURI_SIGNING_PRIVATE_KEY: "", TAURI_PRIVATE_KEY: "" }),
      );
      const targetRoots = [path.join(src, t.dir, "target"), path.join(src, "target")];
      const bundleDir = targetRoots.map((r) => path.join(r, "release", "bundle")).find((p) => fs.existsSync(p));
      if (!bundleDir) throw new Friendly("The app built, but Toolbay couldn't find the finished installer.");
      if (isWin) {
        const dir = path.join(bundleDir, "nsis");
        const exe = fs.readdirSync(dir).find((f) => f.endsWith("-setup.exe"));
        if (!exe) throw new Friendly("The app built, but Toolbay couldn't find the Windows installer.");
        const asset = `${assetBase}-setup.exe`;
        fs.copyFileSync(path.join(dir, exe), path.join(out, asset));
        const mainExe = `${(plan.cargoBin || "").trim()}`;
        return { kind: "nsis", asset, silentArgs: ["/S"], ...(mainExe ? { exe: mainExe } : {}) };
      }
      const dir = path.join(bundleDir, "macos");
      const app = fs.readdirSync(dir).find((f) => f.endsWith(".app"));
      if (!app) throw new Friendly("The app built, but Toolbay couldn't find the Mac app.");
      execSync(`codesign --force --deep -s - "${path.join(dir, app)}"`, { stdio: "inherit" });
      const stage = path.join(work, "stage");
      fs.mkdirSync(stage, { recursive: true });
      execSync(`ditto "${path.join(dir, app)}" "${path.join(stage, app)}"`);
      const asset = `${assetBase}.zip`;
      zipDir(stage, path.join(out, asset));
      return { kind: "zip", asset, exe: app, app };
    }

    case "electron": {
      step("Install dependencies", "Installing the app's dependencies failed.", () => installDeps());
      if (plan.build) step("Build the app", "The app's own build step failed.", () => sh(plan.build));
      const target = isWin ? "--win nsis --x64" : "--mac zip --arm64";
      step("Package the app", "Packaging this Electron app failed. It may need its own packaging setup.", () =>
        sh(`${plan.electron?.hasBuilder ? "npx electron-builder" : "npx -y electron-builder@25"} ${target} --publish never -c.directories.output=tb-dist -c.nsis.oneClick=true -c.nsis.perMachine=false -c.nsis.allowToChangeInstallationDirectory=false`, src, { CSC_IDENTITY_AUTO_DISCOVERY: "false" }),
      );
      const dist = path.join(src, "tb-dist");
      if (isWin) {
        const exe = fs.readdirSync(dist).find((f) => /setup.*\.exe$/i.test(f) || /\.exe$/i.test(f));
        if (!exe) throw new Friendly("The app built, but Toolbay couldn't find the Windows installer.");
        const asset = `${assetBase}-setup.exe`;
        fs.copyFileSync(path.join(dist, exe), path.join(out, asset));
        const product = plan.electron?.productName;
        return {
          kind: "nsis",
          asset,
          silentArgs: ["/S", "/currentuser"],
          ...(product ? { exe: `${product}.exe`, uninstaller: `Uninstall ${product}.exe` } : {}),
        };
      }
      const zip = fs.readdirSync(dist).find((f) => f.endsWith(".zip"));
      if (!zip) throw new Friendly("The app built, but Toolbay couldn't find the Mac app.");
      const asset = `${assetBase}.zip`;
      fs.copyFileSync(path.join(dist, zip), path.join(out, asset));
      return { kind: "zip", asset };
    }

    default:
      throw new Friendly(plan.reason || "Toolbay can't turn this kind of project into an app yet.");
  }
}

try {
  const entry = await build();
  const file = path.join(out, entry.asset);
  entry.size = fs.statSync(file).size;
  entry.sha256 = sha256(file);
  fs.writeFileSync(path.join(out, `entry-${platformKey}.json`), JSON.stringify({ platform: platformKey, entry }, null, 2));
  console.log(`\nPackaged ${entry.asset} (${(entry.size / 1048576).toFixed(1)} MB) for ${platformKey}`);
} catch (e) {
  const message = e instanceof Friendly ? e.message : "Something went wrong while packaging this project.";
  const detail = e?.detail || String(e?.stack || e);
  console.error(`\n${message}\n${detail}`);
  fs.writeFileSync(path.join(out, `error-${platformKey}.json`), JSON.stringify({ platform: platformKey, message, detail: detail.slice(-4000) }, null, 2));
  process.exit(1);
}
