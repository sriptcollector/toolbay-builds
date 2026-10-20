# toolbay-builds

Turns a GitHub repo into a Toolbay desktop app. toolbay.ai starts a run of
[`build.yml`](.github/workflows/build.yml) for each project someone uploads; every finished build is a
release here (`b-<build id>`) holding the app files and a `toolbay.json` the Toolbay hub installs from.

| Project type | How it becomes an app |
| --- | --- |
| Tauri app | its own `tauri build` (Windows installer, Mac app) |
| Electron app | electron-builder |
| Vite / React / Vue / plain web app, Next.js static export | the web build is opened by the Toolbay runner in its own window |
| Next.js with a server | bundled with Node; the runner starts the server and opens it |
| Python or Node command-line tool | bundled with its runtime; the runner shows a simple launcher window (options, Run, output) |
| Python app with its own window (Tk, Qt) | bundled with Python; the runner starts it |

Before anything runs, the inspect job checks for an OSI open-source license, leaked keys (gitleaks),
known vulnerable libraries (osv-scanner), malware (ClamAV), what the app talks to on the internet and
what permissions it asks for. That report is the tool's privacy check on Toolbay.

- `runner/`: the Toolbay runner (Tauri 2), released as `runner-v1` by [`runner.yml`](.github/workflows/runner.yml).
- `scripts/detect.mjs`: classifies a repo. `scripts/scan.mjs`: the privacy and security check.
  `scripts/package.mjs`: builds and packages. `scripts/manifest.mjs`: writes `toolbay.json`.
  `scripts/notify.mjs`: reports progress to toolbay.ai (HMAC-signed with `TOOLBAY_WEBHOOK_SECRET`).

Run one by hand:

```bash
gh workflow run build.yml -R sriptcollector/toolbay-builds -f build_id=test1 -f repo=gabrielecirulli/2048 -f sha=<full commit sha>
```

MIT licensed. Apps built here keep their own licenses.
