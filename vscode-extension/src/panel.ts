import * as vscode from 'vscode';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import type { JsonReport, Finding } from './scanner';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateNonce(): string {
  return randomBytes(16).toString('hex');
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatAge(isoTimestamp: string): string {
  const diffMs = Date.now() - new Date(isoTimestamp).getTime();
  const hours = diffMs / 3_600_000;
  if (hours < 1) return `${Math.round(diffMs / 60_000)}m ago`;
  if (hours < 48) {
    const h = Math.floor(hours);
    const m = Math.round((hours - h) * 60);
    return m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
  }
  return `${Math.round(hours / 24)}d ago`;
}

// ---------------------------------------------------------------------------
// Panel class
// ---------------------------------------------------------------------------

export class PacScanPanel {
  public static currentPanel: PacScanPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _workspaceRoot: string;
  private _disposables: vscode.Disposable[] = [];
  private _nonce: string;

  private constructor(panel: vscode.WebviewPanel, workspaceRoot: string) {
    this._panel = panel;
    this._workspaceRoot = workspaceRoot;
    this._nonce = generateNonce();

    this._panel.webview.html = this._buildShellHtml();

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(
      (message: { command: string; file?: string; line?: number; column?: number }) => {
        switch (message.command) {
          case 'openFile':
            if (message.file !== undefined) {
              this._openFile(message.file, message.line ?? 1, message.column ?? 1);
            }
            break;
          case 'runScan':
            vscode.commands.executeCommand('pac-scan.runScan');
            break;
          case 'fetchSnapshot':
            vscode.commands.executeCommand('pac-scan.fetchSnapshot');
            break;
        }
      },
      null,
      this._disposables,
    );
  }

  // ---------------------------------------------------------------------------
  // Public factory / API
  // ---------------------------------------------------------------------------

  public static show(
    _context: vscode.ExtensionContext,
    workspaceRoot: string,
  ): PacScanPanel {
    const column =
      vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.Beside;

    if (PacScanPanel.currentPanel) {
      PacScanPanel.currentPanel._panel.reveal(column);
      return PacScanPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'pacScanResults',
      'PAC Scan Results',
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [],
      },
    );

    PacScanPanel.currentPanel = new PacScanPanel(panel, workspaceRoot);
    return PacScanPanel.currentPanel;
  }

  /** Posts the full report to the webview for rendering. */
  public update(report: JsonReport | null): void {
    this._panel.webview.postMessage({ type: 'update', report });
  }

  /** Toggles the scanning overlay. */
  public setScanning(scanning: boolean): void {
    this._panel.webview.postMessage({ type: 'scanning', scanning });
  }

  public dispose(): void {
    PacScanPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const d = this._disposables.pop();
      if (d) d.dispose();
    }
  }

  // ---------------------------------------------------------------------------
  // File opener
  // ---------------------------------------------------------------------------

  private async _openFile(file: string, line: number, col: number): Promise<void> {
    const absPath = path.isAbsolute(file) ? file : path.join(this._workspaceRoot, file);
    try {
      const uri = vscode.Uri.file(absPath);
      const doc = await vscode.workspace.openTextDocument(uri);
      const lineIdx = Math.max(0, line - 1);
      const colIdx  = Math.max(0, col - 1);
      const range   = new vscode.Range(lineIdx, colIdx, lineIdx, colIdx);
      await vscode.window.showTextDocument(doc, { selection: range, preserveFocus: false });
    } catch {
      vscode.window.showErrorMessage(`PAC Scan: Could not open file: ${file}`);
    }
  }

  // ---------------------------------------------------------------------------
  // HTML generation
  // ---------------------------------------------------------------------------

  private _buildShellHtml(): string {
    const nonce = this._nonce;

    /* ---------- styles (VS Code CSS variables for full theme support) --------- */
    const css = `
      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        background: var(--vscode-editor-background);
        color: var(--vscode-editor-foreground);
        font-family: var(--vscode-font-family);
        font-size: var(--vscode-font-size);
        line-height: 1.5;
      }

      /* ── Toolbar ─────────────────────────────────────────────────────────── */
      .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 16px;
        border-bottom: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
        position: sticky;
        top: 0;
        z-index: 10;
      }
      .toolbar-title {
        font-weight: 600;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .toolbar-env {
        font-size: 11px;
        padding: 1px 6px;
        border-radius: 3px;
        background: var(--vscode-badge-background);
        color: var(--vscode-badge-foreground);
        font-weight: 400;
      }
      .toolbar-actions { display: flex; gap: 6px; }

      /* ── Buttons ─────────────────────────────────────────────────────────── */
      button {
        padding: 4px 10px;
        background: var(--vscode-button-background);
        color: var(--vscode-button-foreground);
        border: none;
        border-radius: 2px;
        cursor: pointer;
        font-size: 12px;
        font-family: inherit;
      }
      button:hover { background: var(--vscode-button-hoverBackground); }
      button.secondary {
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
      }
      button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }

      /* ── Scanning overlay ─────────────────────────────────────────────────── */
      #scanning-bar {
        display: none;
        padding: 6px 16px;
        font-size: 12px;
        color: var(--vscode-descriptionForeground);
        background: var(--vscode-editorWidget-background);
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      #scanning-bar.visible { display: block; }

      /* ── Content area ─────────────────────────────────────────────────────── */
      #root { padding: 16px; }
      .placeholder {
        padding: 32px;
        text-align: center;
        color: var(--vscode-descriptionForeground);
      }

      /* ── Summary banner ───────────────────────────────────────────────────── */
      .summary {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 12px 14px;
        border-radius: 4px;
        margin-bottom: 16px;
        border-left: 4px solid var(--vscode-panel-border);
      }
      .summary.pass { border-left-color: var(--vscode-testing-iconPassed); }
      .summary.fail { border-left-color: var(--vscode-editorError-foreground); }

      .result-badge {
        font-size: 14px;
        font-weight: 600;
      }
      .result-badge.pass { color: var(--vscode-testing-iconPassed); }
      .result-badge.fail { color: var(--vscode-editorError-foreground); }

      .counts {
        display: flex;
        gap: 12px;
        font-size: 12px;
        flex-wrap: wrap;
      }
      .count-item { display: flex; align-items: center; gap: 4px; }
      .count-item .num { font-weight: 600; font-size: 14px; }
      .sev-critical .num { color: var(--vscode-editorError-foreground); }
      .sev-high .num     { color: var(--vscode-editorError-foreground); }
      .sev-medium .num   { color: var(--vscode-editorWarning-foreground); }
      .sev-low .num      { color: var(--vscode-descriptionForeground); }

      .meta { font-size: 11px; color: var(--vscode-descriptionForeground); }

      /* ── No findings ──────────────────────────────────────────────────────── */
      .no-findings {
        padding: 24px;
        text-align: center;
        color: var(--vscode-testing-iconPassed);
        font-size: 13px;
      }

      /* ── File group ───────────────────────────────────────────────────────── */
      .file-group { margin-bottom: 12px; }
      .file-header {
        font-size: 11px;
        font-weight: 600;
        color: var(--vscode-descriptionForeground);
        padding: 4px 0 4px 4px;
        border-bottom: 1px solid var(--vscode-panel-border);
        margin-bottom: 2px;
        font-family: var(--vscode-editor-font-family, monospace);
      }

      /* ── Finding row ──────────────────────────────────────────────────────── */
      .finding {
        display: grid;
        grid-template-columns: 80px 60px 1fr auto;
        gap: 6px;
        align-items: start;
        padding: 6px 8px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 12px;
        margin-bottom: 2px;
      }
      .finding:hover { background: var(--vscode-list-hoverBackground); }
      .finding .sev-badge {
        padding: 1px 5px;
        border-radius: 2px;
        font-size: 10px;
        font-weight: 600;
        text-align: center;
        letter-spacing: 0.5px;
      }
      .finding .sev-badge.critical,
      .finding .sev-badge.high {
        background: var(--vscode-inputValidation-errorBackground);
        color: var(--vscode-editorError-foreground);
        border: 1px solid var(--vscode-editorError-foreground);
      }
      .finding .sev-badge.medium {
        background: var(--vscode-inputValidation-warningBackground);
        color: var(--vscode-editorWarning-foreground);
        border: 1px solid var(--vscode-editorWarning-foreground);
      }
      .finding .sev-badge.low,
      .finding .sev-badge.info {
        color: var(--vscode-descriptionForeground);
        border: 1px solid var(--vscode-panel-border);
      }
      .finding .rule-id {
        font-family: var(--vscode-editor-font-family, monospace);
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
        padding-top: 2px;
      }
      .finding .msg { color: var(--vscode-editor-foreground); }
      .finding .loc {
        font-family: var(--vscode-editor-font-family, monospace);
        font-size: 10px;
        color: var(--vscode-descriptionForeground);
        white-space: nowrap;
        text-align: right;
      }
    `;

    /* ---------- webview script ------------------------------------------------ */
    const script = `
      const vscode = acquireVsCodeApi();

      document.getElementById('btn-run').addEventListener('click', () => {
        vscode.postMessage({ command: 'runScan' });
      });
      document.getElementById('btn-fetch').addEventListener('click', () => {
        vscode.postMessage({ command: 'fetchSnapshot' });
      });

      window.addEventListener('message', (event) => {
        const msg = event.data;
        if (msg.type === 'update') renderReport(msg.report);
        if (msg.type === 'scanning') {
          document.getElementById('scanning-bar').classList.toggle('visible', msg.scanning);
        }
      });

      function esc(s) {
        return String(s)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }

      function fmtAge(iso) {
        const ms = Date.now() - new Date(iso).getTime();
        const h  = ms / 3600000;
        if (h < 1) return Math.round(ms / 60000) + 'm ago';
        const hh = Math.floor(h), mm = Math.round((h - hh) * 60);
        if (h < 48) return hh + 'h' + (mm > 0 ? ' ' + mm + 'm' : '') + ' ago';
        return Math.round(h / 24) + 'd ago';
      }

      function renderReport(report) {
        const root = document.getElementById('root');
        if (!report) {
          root.innerHTML = '<p class="placeholder">No scan results yet. Click ▶ Run Scan to start.</p>';
          return;
        }

        const { result, summary, findings, environment, timestamp, snapshot_age_hours } = report;
        const isPass = result === 'PASS';

        const staleWarn = snapshot_age_hours >= 24
          ? '<span style="color:var(--vscode-editorWarning-foreground)"> ⚠ Snapshot is ' + Math.round(snapshot_age_hours) + 'h old</span>'
          : '';

        let html = \`
          <div class="summary \${isPass ? 'pass' : 'fail'}">
            <div class="result-badge \${isPass ? 'pass' : 'fail'}">\${isPass ? '✅ PASS — safe to deploy' : '❌ FAIL — security issues found'}</div>
            <div class="counts">
              <span class="count-item sev-critical"><span class="num">\${summary.critical}</span> CRITICAL</span>
              <span class="count-item sev-high"><span class="num">\${summary.high}</span> HIGH</span>
              <span class="count-item sev-medium"><span class="num">\${summary.medium}</span> MEDIUM</span>
              <span class="count-item sev-low"><span class="num">\${summary.low}</span> LOW</span>
            </div>
            <div class="meta">
              \${summary.files_scanned} files · \${summary.rules_run} rules ·
              scanned \${fmtAge(timestamp)}\${staleWarn}
            </div>
          </div>
        \`;

        if (findings.length === 0) {
          html += '<p class="no-findings">✅ No findings — code is clear of known issues</p>';
        } else {
          // Group by file
          const byFile = {};
          for (const f of findings) {
            if (!byFile[f.file]) byFile[f.file] = [];
            byFile[f.file].push(f);
          }

          for (const [file, ffindings] of Object.entries(byFile)) {
            html += \`<div class="file-group"><div class="file-header">\${esc(file)}</div>\`;
            for (const f of ffindings) {
              const sev = f.severity.toLowerCase();
              const loc = f.line > 0 ? \`:\${f.line}:\${f.column}\` : '';
              html += \`
                <div class="finding"
                     data-file="\${esc(f.file)}"
                     data-line="\${f.line}"
                     data-col="\${f.column}">
                  <span class="sev-badge \${sev}">\${f.severity}</span>
                  <span class="rule-id">\${esc(f.rule_id)}</span>
                  <span class="msg">\${esc(f.message)}</span>
                  <span class="loc">\${esc(loc)}</span>
                </div>
              \`;
            }
            html += '</div>';
          }
        }

        root.innerHTML = html;

        // Attach click handlers for opening files
        root.querySelectorAll('.finding').forEach(el => {
          el.addEventListener('click', () => {
            vscode.postMessage({
              command: 'openFile',
              file:   el.dataset.file,
              line:   parseInt(el.dataset.line, 10),
              column: parseInt(el.dataset.col, 10),
            });
          });
        });
      }
    `;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <title>PAC Scan</title>
  <style nonce="${nonce}">${css}</style>
</head>
<body>
  <div class="toolbar">
    <div class="toolbar-title">
      🛡️ PAC Scan
    </div>
    <div class="toolbar-actions">
      <button id="btn-run">▶ Run Scan</button>
      <button id="btn-fetch" class="secondary">⟳ Refresh Snapshot</button>
    </div>
  </div>
  <div id="scanning-bar">⟳&nbsp; Scanning — please wait...</div>
  <div id="root">
    <p class="placeholder">Click ▶ Run Scan to start.</p>
  </div>
  <script nonce="${nonce}">${script}</script>
</body>
</html>`;
  }
}
