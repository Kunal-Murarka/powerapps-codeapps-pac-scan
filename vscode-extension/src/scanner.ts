import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn, ChildProcess } from 'node:child_process';

// ---------------------------------------------------------------------------
// Report type definitions (mirrors JsonReport from the pac-scan CLI)
// ---------------------------------------------------------------------------

export interface Finding {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  file: string;
  line: number;
  column: number;
  message: string;
  remediation: string;
  code_snippet: string;
}

export interface RuleSummary {
  findings: number;
  status: 'PASS' | 'FAIL';
}

export interface JsonReport {
  scan_id: string;
  tool: string;
  version: string;
  timestamp: string;
  environment: string;
  environment_id: string;
  snapshot_age_hours: number;
  snapshot_warned: boolean;
  result: 'PASS' | 'FAIL';
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    files_scanned: number;
    rules_run: number;
  };
  findings: Finding[];
  rules_summary: Record<string, RuleSummary>;
}

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

/**
 * Finds the pac-scan CLI binary.
 * Checks the project-local node_modules/.bin first, then falls back to
 * whatever is on PATH (globally installed or npx-resolved).
 */
export function findPacScanBin(workspaceRoot: string): string {
  const isWindows = process.platform === 'win32';
  const ext = isWindows ? '.cmd' : '';

  // 1. Local node_modules/.bin/pac-scan (preferred — version is pinned)
  const local = path.join(workspaceRoot, 'node_modules', '.bin', `pac-scan${ext}`);
  if (fs.existsSync(local)) return local;

  // 2. Global / PATH
  return `pac-scan${ext}`;
}

// ---------------------------------------------------------------------------
// Config reading (YAML scalar extract — avoids js-yaml dependency)
// ---------------------------------------------------------------------------

/**
 * Reads `default_environment` from pac-scan.config.yaml using a simple regex.
 * Avoids pulling js-yaml into the extension bundle.
 */
export function readDefaultEnv(workspaceRoot: string): string {
  const cfgPath = path.join(workspaceRoot, 'pac-scan.config.yaml');
  if (!fs.existsSync(cfgPath)) return 'prod';
  try {
    const content = fs.readFileSync(cfgPath, 'utf-8');
    const m = content.match(/^default_environment:\s*([\w-]+)/m);
    return m?.[1] ?? 'prod';
  } catch {
    return 'prod';
  }
}

/**
 * Checks whether the snapshot file for `env` exists.
 */
export function snapshotExists(workspaceRoot: string, env: string): boolean {
  const p = path.join(workspaceRoot, '.pac-scan', 'current', `${env}.json`);
  return fs.existsSync(p);
}

// ---------------------------------------------------------------------------
// Scan runner
// ---------------------------------------------------------------------------

export interface ScanOptions {
  workspaceRoot: string;
  env: string;
  /** Directory where the JSON report will be written. */
  reportDir: string;
  outputChannel: vscode.OutputChannel;
}

/**
 * Spawns `pac-scan run --env <env> --output <reportDir>` and calls
 * `onComplete` when the process exits.
 *
 * Returns the ChildProcess so the caller can kill it on cancellation.
 */
export function runScan(
  opts: ScanOptions,
  onComplete: (report: JsonReport | null, exitCode: number) => void,
): ChildProcess {
  const { workspaceRoot, env, reportDir, outputChannel } = opts;
  const bin = findPacScanBin(workspaceRoot);
  const args = ['run', '--env', env, '--output', reportDir];

  outputChannel.appendLine('');
  outputChannel.appendLine(`[pac-scan] ${new Date().toLocaleTimeString()} — Starting scan`);
  outputChannel.appendLine(`[pac-scan] env: ${env}   binary: ${bin}`);
  outputChannel.appendLine('─'.repeat(60));

  const proc = spawn(bin, args, {
    cwd: workspaceRoot,
    // shell:true is needed on Windows to execute .cmd wrappers
    shell: process.platform === 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proc.stdout?.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));
  proc.stderr?.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));

  proc.on('error', (err) => {
    outputChannel.appendLine(`[pac-scan] Process error: ${err.message}`);
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      outputChannel.appendLine('[pac-scan] pac-scan CLI not found.');
      outputChannel.appendLine('[pac-scan] Install it: npm install --save-dev pac-scan');
      vscode.window.showErrorMessage(
        'pac-scan CLI not found. Run: npm install --save-dev pac-scan',
        'Open Terminal',
      ).then((choice) => {
        if (choice === 'Open Terminal') {
          vscode.commands.executeCommand('workbench.action.terminal.new');
        }
      });
    }
    onComplete(null, 1);
  });

  proc.on('close', (exitCode: number | null) => {
    outputChannel.appendLine('─'.repeat(60));

    // Find the most recently written report in the output directory
    let report: JsonReport | null = null;
    try {
      const files = fs.readdirSync(reportDir)
        .filter(f => f.startsWith('pac-scan-report-') && f.endsWith('.json'))
        .sort();

      if (files.length > 0) {
        const latest = path.join(reportDir, files[files.length - 1]);
        report = JSON.parse(fs.readFileSync(latest, 'utf-8')) as JsonReport;
      }
    } catch {
      // report stays null — the error message will be shown by the caller
    }

    onComplete(report, exitCode ?? 1);
  });

  return proc;
}

// ---------------------------------------------------------------------------
// Fetch runner
// ---------------------------------------------------------------------------

/**
 * Spawns `pac-scan fetch --env <env>` and calls `onComplete` when done.
 * Returns the ChildProcess for cancellation support.
 */
export function runFetch(
  workspaceRoot: string,
  env: string,
  outputChannel: vscode.OutputChannel,
  onComplete: (exitCode: number) => void,
): ChildProcess {
  const bin = findPacScanBin(workspaceRoot);
  const args = ['fetch', '--env', env];

  outputChannel.appendLine('');
  outputChannel.appendLine(`[pac-scan] ${new Date().toLocaleTimeString()} — Fetching snapshot`);
  outputChannel.appendLine(`[pac-scan] env: ${env}   binary: ${bin}`);
  outputChannel.appendLine('─'.repeat(60));

  const proc = spawn(bin, args, {
    cwd: workspaceRoot,
    shell: process.platform === 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proc.stdout?.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));
  proc.stderr?.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));

  proc.on('error', (err) => {
    outputChannel.appendLine(`[pac-scan] Process error: ${err.message}`);
    onComplete(1);
  });

  proc.on('close', (exitCode: number | null) => {
    outputChannel.appendLine('─'.repeat(60));
    onComplete(exitCode ?? 1);
  });

  return proc;
}

// ---------------------------------------------------------------------------
// Shared temp directory for report output
// ---------------------------------------------------------------------------

export function getReportDir(): string {
  const dir = path.join(os.tmpdir(), 'pac-scan-vscode');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}
