# pac-scan

Offline security scanner for **Power Apps Code Apps** (React + Vite).

Catches CSP and DLP policy violations **at build time** — before they surface as silent runtime failures inside the Power Apps Player sandbox.

---

## Prerequisites

- **Node.js 18+**
- **[pac CLI](https://learn.microsoft.com/power-platform/developer/cli/introduction)** — required only for `pac-scan fetch`. All other commands are fully offline.

---

## Why it exists

Power Apps Code Apps run inside the Power Apps Player, a tightly sandboxed iframe governed by two policy layers:

| Layer | What it enforces |
|---|---|
| **DLP policies** | Which connectors an app may use. An admin can block a connector at any time — your app stops working with no build-time warning. |
| **CSP directives** | Which domains `fetch()` / XHR can reach, which script sources are allowed, and which domains may embed the player. |

Both layers are configured by Power Platform admins, not developers. pac-scan bridges that gap: it pulls a snapshot of the live policies once, then every subsequent scan runs completely offline — no network, no telemetry, no data leaving the boundary.

---

## Quick start

```bash
# 1. Install
npm install --save-dev pac-scan

# 2. Authenticate pac CLI (one-time)
pac auth create

# 3. Pull live policies
npx pac-scan fetch --env prod

# 4. Scan
npx pac-scan run --env prod
```

---

## CLI commands

### `pac-scan fetch`

Pulls live DLP and CSP policies from Power Platform and writes a snapshot to `.pac-scan/current/<env>.json`.

```bash
pac-scan fetch --env prod
pac-scan fetch --env dev --environment-id 00000000-0000-0000-0000-000000000000
pac-scan fetch --env uat --verbose
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--env <env>` | `default_environment` from config | Target environment name |
| `--environment-id <guid>` | auto-detected | Override Power Platform environment GUID |
| `--config <path>` | auto-detected | Path to `pac-scan.config.yaml` |
| `--verbose` | false | Print detailed fetch progress |

Requires the [pac CLI](https://learn.microsoft.com/power-platform/developer/cli/introduction) to be installed and authenticated (`pac auth create`).

---

### `pac-scan run`

Scans source files against the saved snapshot. Runs fully offline.

```bash
pac-scan run --env prod
pac-scan run --env dev --fail-on CRITICAL
pac-scan run --env uat --output ./reports --format json
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--env <env>` | `default_environment` from config | Target environment |
| `--fail-on <severity>` | from `fail_on_severity` in config | Override failure threshold |
| `--path <dir>` | `cwd` | Root directory to scan |
| `--output <dir>` | `cwd` | Directory to write the JSON report |
| `--format terminal\|json` | `terminal` | Output format |
| `--verbose` | false | Print each file as it is scanned |

Exit code 0 = PASS, exit code 1 = FAIL or error.

---

### `pac-scan diff`

Compares two snapshots for the same environment, showing policy changes between dates. Useful for answering "why did my scan start failing after the admin changed the DLP policy?"

```bash
pac-scan diff --env prod --from 2026-05-01 --to 2026-05-05
pac-scan diff --env prod --from 2026-05-01 --to 2026-05-05 --format json
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--env <env>` | required | Environment to compare |
| `--from <date>` | required | Base date (`YYYY-MM-DD`) — finds nearest snapshot |
| `--to <date>` | required | Head date (`YYYY-MM-DD`) — finds nearest snapshot |
| `--format terminal\|json` | `terminal` | Output format |
| `--config <path>` | auto-detected | Path to config |

---

### `pac-scan policy`

Displays a formatted view of the current policy snapshot — DLP policies, connector risk tiers, endpoint filter URLs, and CSP directives.

```bash
pac-scan policy --env prod
pac-scan policy --env dev --format json
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--env <env>` | `default_environment` from config | Target environment |
| `--format terminal\|json` | `terminal` | Output format |
| `--config <path>` | auto-detected | Path to config |

---

### `pac-scan validate`

Checks that your setup is complete and correct. Run this first when setting up a new project or debugging unexpected failures.

```bash
pac-scan validate
pac-scan validate --env dev
```

Checks:

- Config file exists and is syntactically valid
- All configured snapshot files exist on disk
- pac CLI is installed on PATH
- pac CLI has at least one authenticated profile

---

## Configuration: `pac-scan.config.yaml`

Place this file in your project root (pac-scan searches upward from `cwd` to find it):

```yaml
default_environment: prod

environments:
  dev:
    dlp_snapshot:  .pac-scan/current/dev.json
    csp_snapshot:  .pac-scan/current/dev.json
    environment_url: https://org-dev.crm.dynamics.com/
    # environment_id: 00000000-0000-0000-0000-000000000000  # optional GUID override
  uat:
    dlp_snapshot:  .pac-scan/current/uat.json
    csp_snapshot:  .pac-scan/current/uat.json
    environment_url: https://org-uat.crm.dynamics.com/
  prod:
    dlp_snapshot:  .pac-scan/current/prod.json
    csp_snapshot:  .pac-scan/current/prod.json
    environment_url: https://org.crm.dynamics.com/

# Minimum severity that fails the build, per environment
fail_on_severity:
  dev:  CRITICAL
  uat:  HIGH
  prod: MEDIUM

# Source files to scan
scan_paths:      [src]
scan_extensions: [.ts, .tsx, .js, .jsx]
```

---

## Git hook

Blocks commits when any finding meets the `dev` threshold (CRITICAL by default).

```bash
# Install (cross-platform, prompts before overwriting)
npm run install-hooks

# Or manually on Unix/macOS
bash scripts/install-hooks.sh

# Or on Windows (PowerShell)
.\scripts\install-hooks.ps1
```

To skip in an emergency: `git commit --no-verify`

---

## Azure DevOps pipeline

See [examples/azure-devops-pipeline.yml](examples/azure-devops-pipeline.yml) for the full 4-stage pipeline.

Quick reference — add these two tasks to any existing pipeline:

```yaml
- script: npm install -g pac-scan
  displayName: 'Install pac-scan'

- task: PACSecurityScan@1
  displayName: 'Run Security Scan'
  inputs:
    command: run
    environment: prod
    failOnSeverity: HIGH
    outputPath: $(Build.ArtifactStagingDirectory)/scan-report.json
```

The `PACSecurityScan@1` task lives in `azure-devops-task/`. Build it (`npm run build` in that folder) and upload the extension to your Azure DevOps organisation.

---

## GitHub Actions

See [examples/github-actions-workflow.yml](examples/github-actions-workflow.yml) for the full 5-job workflow.

Quick reference — add this step to any job:

```yaml
- uses: your-org/pac-scan-action@v1
  id: scan
  with:
    command: run
    environment: prod
    fail-on-severity: HIGH
    output-path: ./pac-scan-report.json
```

The action lives in `github-action/`. Push it as its own GitHub repository and reference it by org/repo@tag.

---

## The 5 rules

### PAC001 — Hardcoded secrets (CRITICAL)

Detects API keys, bearer tokens, client secrets, tenant/application GUIDs, Azure storage account keys, and private key headers hardcoded in source files.

**Why it matters:** The Power Apps Player may cache app bundles in browser storage, and Code Apps are sometimes deployed to shared tenants. A leaked key is a leaked key.

**Exclusions:** Test files (`*.test.ts`, `*.spec.ts`), lines referencing environment variables (`process.env.`, `import.meta.env.`, `EnvVar(`, `getEnvironmentVariable(`), and comment lines are not flagged.

**Fix:** Use `@microsoft/powerplatform-envvar` to read environment variables at runtime. Never put credentials in source.

---

### PAC002 — Raw fetch to non-allowlisted domain (HIGH / MEDIUM)

Detects `fetch()`, `axios.*()`, and `XMLHttpRequest.open()` calls pointing to domains not present in the snapshot's `connect_src` list or connector endpoint filters.

| Severity | When |
|---|---|
| HIGH | Static URL that is demonstrably not allowlisted |
| MEDIUM | Dynamic URL (variable or template literal with interpolation) |

**Why it matters:** The Power Apps Player CSP blocks `fetch()` to any domain not in `connect-src`. The call fails silently with a network error at runtime — not a helpful error.

**Fix:** Add the domain to the DLP policy's endpoint filter in Power Platform admin, then run `pac-scan fetch` to refresh the snapshot.

---

### PAC003 — DLP connector violations (CRITICAL / HIGH / MEDIUM)

Detects imports, `connectorName:` assignments, and `useConnector()` calls for connectors classified as blocked or non-business in the environment's DLP policies.

| Severity | Classification |
|---|---|
| CRITICAL | Connector is in the **blocked** list |
| HIGH | Connector is in the **non-business** list |
| MEDIUM | Connector not found in the snapshot at all |

**Why it matters:** A blocked connector call raises an error at runtime in the Power Apps Player. There is no fallback.

---

### PAC004 — CSP violations (HIGH / MEDIUM)

Detects patterns the Power Apps Player CSP will reject:

- `eval()`, `new Function(string)`, `setTimeout(string, ...)` — violates `script-src`
- `innerHTML` with `<script` — XSS risk and CSP violation
- `dangerouslySetInnerHTML` — same
- `<iframe src="https://external-domain">` — violates `frame-ancestors`
- `vite.config` CSP header containing `'unsafe-inline'`, `'unsafe-eval'`, `*`, or `data:` — permissive CSP leaks out

**Fix:** Replace `eval()` with a JSON parser or a proper expression library. Replace string-based `setTimeout` with an arrow function. Use `textContent` instead of `innerHTML` for dynamic content.

---

### PAC005 — Vulnerable dependencies (CRITICAL / HIGH)

Runs `npm audit --json` in the project directory and surfaces critical and high severity advisories as findings.

**Why it matters:** Code Apps are deployed as static bundles. Vulnerable dependencies in the bundle are as exploitable as in any web app.

**Graceful degradation:** If npm is not found, `package.json` is missing, or the audit times out, PAC005 emits an INFO finding and exits cleanly — it never blocks a scan.

---

## How to read the report

### Terminal output

```
┌─────────────────────────────────────────────────────┐
│  pac-scan  v1.0.0   env: prod   2026-05-06 14:32:01 │
└─────────────────────────────────────────────────────┘

  environment    prod
  snapshot age   2h 14m
  files scanned  47
  rules run      5

❌ [PAC001] CRITICAL  src/services/api.ts:12:17
   Hardcoded secret: "apiKey" pattern matched
   Fix: Use @microsoft/powerplatform-envvar
   ─────────────────────────────────────────
   11 | const config = {
 > 12 |   apiKey: "sk-live-abc123def456ghi789",
   13 |   endpoint: "https://api.example.com",
```

### JSON report

Written to the output directory as `pac-scan-report-<env>-<YYYYMMDD-HHmmss>.json`.

Key fields:

```jsonc
{
  "scan_id":            "uuid",          // unique per run
  "result":             "PASS | FAIL",
  "snapshot_age_hours": 2.2,             // hours since fetch
  "snapshot_warned":    false,           // true when > 24 hours
  "summary": {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   2
  },
  "findings": [
    {
      "rule_id":     "PAC001",
      "severity":    "CRITICAL",
      "file":        "src/services/api.ts",
      "line":        12,
      "column":      10,
      "message":     "Hardcoded secret: ...",
      "remediation": "Use @microsoft/powerplatform-envvar",
      "code_snippet": "..."
    }
  ]
}
```

---

## Troubleshooting

### "pac CLI not found"

pac-scan calls the Microsoft `pac` CLI for the `fetch` command (only). The `run`, `diff`, `policy`, and `validate` commands are fully offline.

**Fix:**
```bash
npm install -g @microsoft/powerplatform-cli
pac auth create
```

Verify: `pac --version`

---

### "No snapshot found for env"

The `fetch` command has not been run yet for this environment, or the snapshot was written to a different path.

**Fix:**
```bash
pac-scan fetch --env <env>
```

The snapshot is saved to `.pac-scan/current/<env>.json`. Commit the `snapshots/` directory to version control so CI agents have access without a live `fetch` step.

---

### "Snapshot is stale"

The snapshot is more than 24 hours old. This is a warning, not an error — the scan still runs.

**Fix:**
```bash
pac-scan fetch --env <env>
```

For CI/CD, include a dedicated fetch job (or step) that runs before the scan job and uploads the snapshot as a pipeline artifact. See the example pipelines in `examples/`.

---

## VS Code extension

The `vscode-extension/` folder contains a full VS Code extension that:

- **Activates** automatically when a workspace contains `pac-scan.config.yaml`
- **Squiggles** findings inline (red for CRITICAL/HIGH, yellow for MEDIUM)
- Shows a **Results panel** (webview) grouped by file — click any finding to jump to it
- **Status bar** item shows live state: `$(shield) PAC Scan` → `$(sync~spin) PAC: Scanning…` → `$(pass-filled) PAC: Clean` / `$(error) PAC: N issues`

**Commands available in the Command Palette:**

| Command | Description |
|---|---|
| `PAC: Run Security Scan` | Runs a full scan on the workspace |
| `PAC: Scan This File` | Context menu on `.ts` / `.tsx` files |
| `PAC: Refresh Policy Snapshot` | Runs `pac-scan fetch` for the current env |
| `PAC: Show Last Report` | Opens the results webview panel |

**Setting:**

```jsonc
// .vscode/settings.json
{
  "pac-scan.environment": "dev"   // override default_environment from config
}
```

**To build and install locally:**
```bash
cd vscode-extension
npm install
npm run build
# Then in VS Code: Extensions → Install from VSIX (after packaging with vsce)
```

---

## Repository structure

```
powerapps-codeapps-pac-scan/
├── src/
│   ├── cli.ts                    ← entry point (all 5 commands registered)
│   ├── commands/                 ← fetch, run, diff, policy, validate
│   ├── rules/                    ← PAC001–PAC005 scan rules
│   ├── scanner/                  ← file walker + scan orchestrator
│   ├── reporter/                 ← terminal + JSON report writers
│   ├── snapshot/                 ← schema + loader
│   └── config/                   ← config loader (yaml + validation)
├── vscode-extension/             ← VS Code extension (diagnostics + webview)
├── azure-devops-task/            ← Azure Pipelines task (PACSecurityScan@1)
├── github-action/                ← GitHub Actions action
├── scripts/                      ← git hook installers (bash / PS / Node)
├── examples/                     ← complete pipeline YAML examples
├── .pac-scan/                    ← snapshot storage (commit this directory)
│   ├── current/<env>.json        ← latest snapshot per environment
│   └── snapshots/<env>/          ← full history (used by diff)
└── pac-scan.config.yaml          ← project configuration
```

---

## Contributing / dev setup

```bash
# Install root dependencies
npm install

# Build the CLI
npm run build

# Run the CLI from source
node dist/cli.js --help

# Build the VS Code extension
cd vscode-extension && npm install && npm run build

# Build the Azure DevOps task
cd azure-devops-task && npm install && npm run build

# Build the GitHub Action
cd github-action && npm install && npm run build
```

---

## License

MIT
