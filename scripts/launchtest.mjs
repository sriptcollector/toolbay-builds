#!/usr/bin/env node
// Compatibility check: install the freshly built app the way the Toolbay hub does,
// open it, see that it stays up, take a screenshot, close it, uninstall it.
// Usage: node launchtest.mjs <out dir>   (reads out/entry-<platform>.json from package.mjs)
// Writes out/compat-<platform>.json and out/screenshot-<platform>.png (when it opened).
// A build that doesn't open is moved aside (entry -> blocked-entry) so it isn't published.
import { execFileSync, execSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const out = path.resolve(process.argv[2] || "out");
const isWin = process.platform === "win32";
const entryFile = fs.readdirSync(out).find((f) => /^entry-.*\.json$/.test(f));
if (!entryFile) {
  console.log("nothing to test (no build for this computer)");
  process.exit(0);
}
const { platform, entry } = JSON.parse(fs.readFileSync(path.join(out, entryFile), "utf8"));
const OPEN_WAIT_MS = 15_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();

const result = {
  platform,
  os: "",
  osVersion: "",
  arch: process.arch === "arm64" ? "arm64" : "x64",
  installs: false,
  opens: false,
  closes: false,
  closeForced: false,
  uninstalls: null,
  seconds: 0,
  note: "",
  ok: false,
  testedAt: new Date().toISOString(),
};

function osInfo() {
  try {
    if (isWin) {
      const s = execSync(`powershell -NoProfile -Command "$o=Get-CimInstance Win32_OperatingSystem; $o.Caption + '|' + $o.Version"`).toString().trim();
      [result.os, result.osVersion] = s.split("|");
    } else {
      result.os = `macOS ${execSync("sw_vers -productVersion").toString().trim()}`;
      result.osVersion = execSync("sw_vers -buildVersion").toString().trim();
    }
  } catch {
    result.os = os.type();
    result.osVersion = os.release();
  }
}

const tar = isWin ? path.join(process.env.SystemRoot || "C:/Windows", "System32", "tar.exe") : "tar";
const work = fs.mkdtempSync(path.join(os.tmpdir(), "tb-launch-"));
const installDir = path.join(work, "Toolbay Tools", "app"); // a space, like the hub's real folder

function shallowestExe(dir) {
  const found = [];
  const walk = (d, depth) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      const n = e.name.toLowerCase();
      if ((n.endsWith(".exe") || n.endsWith(".app")) && !n.includes("unins")) found.push(p);
      else if (e.isDirectory() && depth < 3) walk(p, depth + 1);
    }
  };
  walk(dir, 0);
  return found.sort((a, b) => a.split(path.sep).length - b.split(path.sep).length)[0];
}

function install() {
  const pkg = entry.localPath || path.join(out, entry.asset);
  fs.mkdirSync(installDir, { recursive: true });
  if (entry.kind === "zip") {
    if (isWin) execFileSync(tar, ["-x", "-f", pkg, "-C", installDir]);
    else execSync(`ditto -x -k "${pkg}" "${installDir}"`);
  } else if (entry.kind === "dmg" && !isWin) {
    const mnt = path.join(work, "mnt");
    fs.mkdirSync(mnt, { recursive: true });
    execSync(`hdiutil attach -nobrowse -readonly -mountpoint "${mnt}" "${pkg}"`, { stdio: "inherit" });
    const app = fs.readdirSync(mnt).find((f) => f.endsWith(".app"));
    if (app) execSync(`ditto "${path.join(mnt, app)}" "${path.join(installDir, app)}"`);
    execSync(`hdiutil detach -quiet "${mnt}"`);
    if (!app) throw new Error("the disk image has no app in it");
  } else if (entry.kind === "exe" && isWin) {
    fs.copyFileSync(pkg, path.join(installDir, entry.exe || path.basename(pkg)));
  } else if (entry.kind === "nsis" && isWin) {
    // Exactly like the hub: silent args, then /D= raw and unquoted (the path has a space).
    const args = [...(entry.silentArgs?.length ? entry.silentArgs : ["/S"]), `/D=${installDir}`].join(" ");
    execSync(`"${pkg}" ${args}`, { stdio: "inherit", timeout: 180_000 });
  } else {
    throw new Error(`can't test a ${entry.kind} package on this computer`);
  }
  const target = entry.exe ? path.join(installDir, entry.exe) : shallowestExe(installDir);
  if (!target || !fs.existsSync(target)) throw new Error("installed, but the program isn't where the package says");
  result.installs = true;
  return target;
}

function running(imageOrApp) {
  try {
    if (isWin) {
      const out = execSync(`tasklist /FI "IMAGENAME eq ${path.basename(imageOrApp)}" /NH`).toString();
      return out.toLowerCase().includes(path.basename(imageOrApp).toLowerCase());
    }
    execSync(`pgrep -f "${imageOrApp}/Contents/MacOS/"`);
    return true;
  } catch {
    return false;
  }
}

function screenshot(file) {
  try {
    if (isWin) {
      const ps = `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); $bmp.Save('${file}',[System.Drawing.Imaging.ImageFormat]::Png)`;
      execFileSync("powershell", ["-NoProfile", "-Command", ps], { timeout: 30_000 });
    } else {
      execSync(`screencapture -x "${file}"`, { timeout: 30_000 });
    }
    return fs.existsSync(file);
  } catch (e) {
    console.log(`(no screenshot: ${e.message.split("\n")[0]})`);
    return false;
  }
}

async function main() {
  osInfo();
  const program = install();
  console.log(`installed: ${program}`);

  let exitCode = null;
  if (isWin) {
    const child = spawn(program, ["--from-toolbay"], { cwd: path.dirname(program), detached: true, stdio: "ignore", env: { ...process.env, TOOLBAY_HUB: "1" } });
    child.on("exit", (c) => (exitCode = c));
    child.unref();
  } else {
    execSync(`open -n -a "${program}" --args --from-toolbay`);
  }
  await sleep(OPEN_WAIT_MS);
  result.opens = running(program);
  if (!result.opens) {
    result.note =
      exitCode && exitCode !== 0
        ? `It closed by itself right after opening (exit code ${exitCode}).`
        : "It didn't stay open on the test computer.";
  } else {
    screenshot(path.join(out, `screenshot-${platform}.png`));
  }

  // Close politely first, like a person clicking X; force only if it ignores that.
  if (result.opens) {
    try {
      // Like clicking the window's X (taskkill without /F fails on the webview helper processes).
      if (isWin)
        execFileSync("powershell", ["-NoProfile", "-Command", `Get-Process -Name '${path.basename(program, ".exe")}' -ErrorAction SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }`], { stdio: "ignore" });
      else execSync(`osascript -e 'tell application "${program}" to quit'`, { stdio: "ignore" });
    } catch {}
    for (let i = 0; i < 10 && running(program); i++) await sleep(1000);
    result.closes = !running(program);
    if (!result.closes) {
      result.closeForced = true;
      try {
        if (isWin) execSync(`taskkill /IM "${path.basename(program)}" /T /F`, { stdio: "ignore" });
        else execSync(`pkill -f "${program}/Contents/MacOS/"`, { stdio: "ignore" });
      } catch {}
    }
  }

  if (entry.kind === "nsis") {
    const un = [entry.uninstaller, "uninstall.exe", "Uninstall.exe"].filter(Boolean).map((u) => path.join(installDir, u)).find((p) => fs.existsSync(p));
    if (un) {
      try {
        execSync(`"${un}" /S`, { timeout: 120_000 });
        await sleep(3000);
        result.uninstalls = !fs.existsSync(program);
      } catch {
        result.uninstalls = false;
      }
    }
  }
  result.ok = result.installs && result.opens;
}

try {
  await main();
} catch (e) {
  result.note = result.installs ? `It didn't open: ${e.message}` : `It didn't install: ${e.message}`;
}
result.seconds = Math.round((Date.now() - t0) / 1000);
fs.writeFileSync(path.join(out, `compat-${platform}.json`), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
if (!result.ok) {
  // Don't publish a build that doesn't open; keep it for the build log.
  fs.renameSync(path.join(out, entryFile), path.join(out, `blocked-${entryFile}`));
  fs.writeFileSync(
    path.join(out, `error-${platform}.json`),
    JSON.stringify({ platform, message: `It built, but on a test computer: ${result.note}`, detail: result.note }, null, 2),
  );
}
