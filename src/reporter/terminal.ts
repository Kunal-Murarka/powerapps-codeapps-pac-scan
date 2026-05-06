import chalk from 'chalk';
import type { Finding } from '../rules/base.js';
import type { EnvironmentSnapshot, Severity } from '../snapshot/schema.js';
import type { ScanResult } from '../scanner/index.js';
import { ALL_RULES } from '../scanner/index.js';



// ---------------------------------------------------------------------------
// Severity styling
// ---------------------------------------------------------------------------

function severityLabel(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL': return chalk.bgRed.white.bold(` ${sev} `);
    case 'HIGH':     return chalk.red.bold(sev);
    case 'MEDIUM':   return chalk.yellow.bold(sev);
    case 'LOW':      return chalk.dim(sev);
    case 'INFO':     return chalk.blue(sev);
    default:         return sev;
  }
}

function severityIcon(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL': return chalk.red('❌');
    case 'HIGH':     return chalk.red('⚠ ');
    case 'MEDIUM':   return chalk.yellow('⚡');
    case 'LOW':      return chalk.dim('ℹ ');
    case 'INFO':     return chalk.blue('ℹ ');
    default:         return '  ';
  }
}

function severityCount(findings: Finding[], sev: Severity): number {
  return findings.filter(f => f.severity === sev).length;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hRule(width = 60): string {
  return chalk.dim('─'.repeat(width));
}

function snapshotAgeFmt(snapshot: EnvironmentSnapshot): { text: string; stale: boolean } {
  const ms = Date.now() - new Date(snapshot.fetched_at).getTime();
  const hours = ms / 3_600_000;
  const stale = hours >= 24;

  let text: string;
  if (hours < 1) {
    const mins = Math.round(ms / 60_000);
    text = `${mins}m ago`;
  } else if (hours < 48) {
    const h = Math.floor(hours);
    const m = Math.round((hours - h) * 60);
    text = m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
  } else {
    text = `${Math.round(hours / 24)}d ago`;
  }

  return { text, stale };
}

// ---------------------------------------------------------------------------
// Finding block renderer
// ---------------------------------------------------------------------------

function renderFinding(f: Finding): void {
  const location = f.line > 0 ? `${f.file}:${f.line}` : f.file;
  const ruleId = chalk.dim(f.rule_id);

  console.log(`${severityIcon(f.severity)} ${severityLabel(f.severity).padEnd(12)}  ${ruleId}  ${chalk.bold(location)}`);
  console.log(`   ${f.message}`);

  if (f.remediation) {
    const firstLine = f.remediation.split('\n')[0];
    console.log(`   ${chalk.dim('→')} ${chalk.cyan(firstLine)}`);
  }

  if (f.code_snippet) {
    console.log('');
    for (const line of f.code_snippet.split('\n')) {
      // Highlight the '>' marker line
      if (line.startsWith('> ')) {
        console.log('   ' + chalk.yellow(line) + chalk.dim('    ← HERE'));
      } else {
        console.log('   ' + chalk.dim(line));
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface TerminalReportOptions {
  scanResult: ScanResult;
  snapshot: EnvironmentSnapshot;
  threshold: Severity;
  reportPath: string;
}

export function printTerminalReport(opts: TerminalReportOptions): void {
  const { scanResult, snapshot, threshold, reportPath } = opts;
  const { findings, rulesSummary, filesScanned, rulesRun, thresholdBreached } = scanResult;

  // ── Header ───────────────────────────────────────────────────────────────
  console.log('');
  console.log(chalk.bold.cyan('┌─────────────────────────────────────────────┐'));
  console.log(chalk.bold.cyan('│') + chalk.bold('  pac-scan  │  Power Apps Code App Scanner   ') + chalk.bold.cyan('│'));
  console.log(chalk.bold.cyan('└─────────────────────────────────────────────┘'));
  console.log('');

  // ── Meta ─────────────────────────────────────────────────────────────────
  const ageInfo = snapshotAgeFmt(snapshot);
  const ageText = ageInfo.stale
    ? chalk.yellow(`${ageInfo.text}  ⚠  Snapshot is stale — run: pac-scan fetch --env ${snapshot.environment}`)
    : chalk.dim(ageInfo.text);

  const COL = 16;
  console.log(`  ${chalk.bold('Environment:'.padEnd(COL))}${snapshot.environment}`);
  console.log(`  ${chalk.bold('Snapshot age:'.padEnd(COL))}${ageText}`);
  console.log(`  ${chalk.bold('Files scanned:'.padEnd(COL))}${filesScanned}`);
  console.log(`  ${chalk.bold('Rules run:'.padEnd(COL))}${rulesRun}`);
  console.log('');

  // ── Findings ─────────────────────────────────────────────────────────────
  if (findings.length === 0) {
    console.log(chalk.green('  ✅  No findings.'));
    console.log('');
  } else {
    console.log(chalk.bold('FINDINGS:'));
    console.log(hRule());

    for (const f of findings) {
      renderFinding(f);
      console.log(hRule());
    }
  }

  // ── Summary counts ───────────────────────────────────────────────────────
  const critical = severityCount(findings, 'CRITICAL');
  const high     = severityCount(findings, 'HIGH');
  const medium   = severityCount(findings, 'MEDIUM');
  const low      = severityCount(findings, 'LOW');

  console.log(chalk.bold('SUMMARY:'));
  console.log(
    `  ${severityIcon('CRITICAL')} ${chalk.red.bold('CRITICAL')}  ${String(critical).padEnd(5)}` +
    `  ${severityIcon('HIGH')} ${chalk.red('HIGH')}      ${String(high).padEnd(5)}`
  );
  console.log(
    `  ${severityIcon('MEDIUM')} ${chalk.yellow('MEDIUM')}    ${String(medium).padEnd(5)}` +
    `  ${severityIcon('LOW')} ${chalk.dim('LOW')}       ${low}`
  );
  console.log('');

  // ── Rule-by-rule pass/fail ────────────────────────────────────────────────
  console.log(chalk.bold('RULES:'));
  for (const rule of ALL_RULES) {
    const summary = rulesSummary[rule.id];
    if (!summary) continue;
    const icon  = summary.status === 'PASS' ? chalk.green('✓') : chalk.red('✗');
    const label = summary.status === 'PASS' ? chalk.green('PASS') : chalk.red('FAIL');
    const count = summary.findings > 0 ? chalk.dim(` (${summary.findings} finding${summary.findings !== 1 ? 's' : ''})`) : '';
    console.log(`  ${icon} ${chalk.bold(rule.id)}  ${label}${count}  ${chalk.dim(rule.name)}`);
  }
  console.log('');

  // ── Result banner ─────────────────────────────────────────────────────────
  if (thresholdBreached) {
    const threshLabel = `${threshold}+`;
    console.log(chalk.red.bold(`RESULT: ██ FAIL — deployment blocked (${snapshot.environment} threshold: ${threshLabel})`));
  } else {
    console.log(chalk.green.bold('RESULT: ✅ PASS — safe to deploy'));
  }
  console.log('');

  // ── Report path ───────────────────────────────────────────────────────────
  console.log(`  ${chalk.dim('Report saved:')} ${reportPath}`);
  console.log('');
}

