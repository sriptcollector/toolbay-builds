# Toolbay PC scan worker

The AI security review of uploaded packages, run on Orion's PC with Claude Code (his normal Claude
login, no API key). It's started by the Claude desktop app's scheduled task `toolbay-security-scan`.

1. `node worker/scan-worker.mjs fetch` pulls waiting packages from toolbay.ai
   (GET /api/v1/admin/scan-queue). Each package is downloaded, checked against its sha256 and
   unpacked into its own empty folder `C:\tb-scan\jobs\<id>\src`. Links, `..` and bombs are
   refused. Then it runs the same pattern checks as CI (scripts/detect.mjs + scan.mjs). Files that
   AI tools treat as instructions (CLAUDE.md, AGENTS.md, .claude/, .mcp.json…) are renamed
   `*.untrusted`.
2. The task gives each sandbox to the reviewer agent `toolbay-security-reviewer` (Sonnet, tools
   Read/Grep/Glob only). Anything flagged goes to `toolbay-security-reviewer-opus` for a second
   opinion. Their JSON replies are saved as `verdict-sonnet.json` / `verdict-opus.json`.
3. `node worker/scan-worker.mjs post <id>` sends the verdict to POST /api/v1/admin/scan-results/:id.
   Secrets are redacted, and the verdict is pinned to the sha256. Unreadable answers, a missing
   second opinion or a failed local check are never "clean".
4. `node worker/scan-worker.mjs clean` deletes finished sandboxes.

Nothing in a package is ever executed here. Builds happen in CI.

Setup on the PC:
- Copy `worker/agents/*.md` to `%USERPROFILE%\.claude\agents\`.
- Create `%USERPROFILE%\.toolbay\scan-worker.json` containing `{"url": "https://toolbay.ai", "token": "tb_live_…"}`. The token must be an API token of the owner account. Or use `{"url", "secret"}`, where the secret is the same value as TOOLBAY_WEBHOOK_SECRET on Railway.
