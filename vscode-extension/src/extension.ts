import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ChildProcess } from 'node:child_process';
import {
  runScan,
  runFetch,
  readDefaultEnv,
  snapshotExists,
  getReportDir,
  type JsonReport,
} from './scanner';
import { PacScanDiagnostics } from './diagnostics';
import { PacScanPanel } from './panel';

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) return;
  const workspaceRoot: string = workspaceFolder.uri.fsPath;

  // Verify the workspace actually has a pac-scan config (belt-and-suspenders —
  // activation events already guard this, but be safe).
  const cfgPath = path.join(workspaceRoot, 'pac-scan.config.yaml');
  if (!fs.existsSync(cfgPath)) return;

  // ── Shared resources ───────────────────────────────────────────────────────
  const outputChannel = vscode.window.createOutputChannel('PAC Scan');
  const diagnostics   = new PacScanDiagnostics();
  const reportDir     = getReportDir();

  // Status bar item (left side, low priority so it doesn't crowd the bar)
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, -100);
  statusBar.command = 'pac-scan.showReport';
  statusBar.show();

  context.subscriptions.push(outputChannel, diagnostics, statusBar);

  // ── State ─────────────────────────────────────────────────────────────────
  let isScanning     = false;
  let activeProc: ChildProcess | undefined;
  let lastReport: JsonReport | null = null;

  // ── Status bar helpers ─────────────────────────────────────────────────────
  type BarState = 'idle' | 'scanning' | 'clean' | 'issues' | 'no-snapshot';

  function setStatusBar(state: BarState, count?: number): void {
    switch (state) {
      case 'idle':
        statusBar.text        = '$(shield) PAC Scan';
        statusBar.backgroundColor = undefined;
        statusBar.tooltip     = 'PAC Scan: Click to run a scan';
        break;
      case 'scanning':
        statusBar.text        = '$(sync~spin) PAC: Scanning\u2026';
        statusBar.backgroundColor = undefined;
        statusBar.tooltip     = 'PAC Scan: Scan in progress\u2026';
        break;
      case 'clean':
        statusBar.text        = '$(pass-filled) PAC: Clean';
        statusBar.backgroundColor = undefined;
        statusBar.tooltip     = 'PAC Scan: No security issues found \u2014 click to view report';
        break;
      case 'issues':
        statusBar.text        = `$(error) PAC: ${count} issue${count !== 1 ? 's' : ''}`;
        statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        statusBar.tooltip     = 'PAC Scan: Security issues found \u2014 click to view report';
        break;
      case 'no-snapshot':
        statusBar.text        = '$(warning) PAC: No snapshot';
        statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        statusBar.tooltip     = 'PAC Scan: No policy snapshot \u2014 run: pac-scan fetch --env <env>';
        break;
    }
  }

  // ── Environment resolution ─────────────────────────────────────────────────
  function resolveEnv(): string {
    return (
      vscode.workspace.getConfiguration('pac-scan').get<string>('environment') ||
      readDefaultEnv(workspaceRoot)
    );
  }

  // ── Check snapshot on startup ──────────────────────────────────────────────
  const initialEnv = resolveEnv();
  if (!snapshotExists(workspaceRoot, initialEnv)) {
    setStatusBar('no-snapshot');
  } else {
    setStatusBar('idle');
  }

  // ── Core scan executor ─────────────────────────────────────────────────────
  async function executeScan(): Promise<void> {
    if (isScanning) {
      vscode.window.showInformationMessage('PAC Scan is already running.');
      return;
    }

    isScanning = true;
    setStatusBar('scanning');

    const panel = PacScanPanel.currentPanel;
    panel?.setScanning(true);
    outputChannel.show(/* preserveFocus */ true);

    const env = resolveEnv();

    await new Promise<void>((resolve) => {
      activeProc = runScan(
        { workspaceRoot, env, reportDir, outputChannel },
        (report, exitCode) => {
          isScanning  = false;
          activeProc  = undefined;
          lastReport  = report;

          if (report) {
            diagnostics.update(report, workspaceRoot);
            panel?.update(report);

            if (report.result === 'FAIL') {
              setStatusBar('issues', report.findings.length);
              // Show a non-modal notification for CI-style workflows
              vscode.window.showWarningMessage(
                `PAC Scan: ${report.findings.length} issue(s) found in ${report.environment}.`,
                'View Report',
              ).then((choice) => {
                if (choice === 'View Report') {
                  vscode.commands.executeCommand('pac-scan.showReport');
                }
              });
            } else {
              setStatusBar('clean');
            }
          } else {
            setStatusBar('idle');
            vscode.window.showErrorMessage(
              `PAC Scan failed (exit ${exitCode}). Check the PAC Scan output channel for details.`,
              'Show Output',
            ).then((choice) => {
              if (choice === 'Show Output') outputChannel.show();
            });
          }

          panel?.setScanning(false);
          resolve();
        },
      );
    });
  }

  // ── Commands ───────────────────────────────────────────────────────────────
  context.subscriptions.push(

    vscode.commands.registerCommand('pac-scan.runScan', executeScan),

    // "Scan This File" runs the full project scan — scanning a single file
    // in isolation would miss cross-file violations and DLP connector refs.
    // Diagnostics are still scoped to individual files via the collection.
    vscode.commands.registerCommand('pac-scan.runScanFile', executeScan),

    vscode.commands.registerCommand('pac-scan.fetchSnapshot', async () => {
      if (isScanning) {
        vscode.window.showInformationMessage('PAC Scan is running. Please wait.');
        return;
      }

      outputChannel.show(true);
      const env = resolveEnv();
      setStatusBar('scanning');

      await new Promise<void>((resolve) => {
        runFetch(workspaceRoot, env, outputChannel, (exitCode) => {
          if (exitCode === 0) {
            vscode.window.showInformationMessage(
              `PAC Scan: Snapshot refreshed for environment "${env}"`,
            );
            setStatusBar('idle');
          } else {
            vscode.window.showErrorMessage(
              `PAC Scan: Snapshot fetch failed. Check the PAC Scan output channel.`,
              'Show Output',
            ).then((c) => { if (c === 'Show Output') outputChannel.show(); });
            setStatusBar('no-snapshot');
          }
          resolve();
        });
      });
    }),

    vscode.commands.registerCommand('pac-scan.showReport', () => {
      const panel = PacScanPanel.show(context, workspaceRoot);
      if (lastReport) panel.update(lastReport);
    }),
  );
}

export function deactivate(): void {
  // VS Code disposes all context.subscriptions automatically.
  // Child processes are cleaned up by the OS when the extension host exits.
}
