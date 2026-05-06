import { Command } from 'commander';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import chalk from 'chalk';
import { loadConfig } from '../config/loader.js';
import { loadSnapshot } from '../snapshot/loader.js';
import { walkFiles } from '../scanner/file-walker.js';
import { runScan } from '../scanner/index.js';
import { writeJsonReport } from '../reporter/json.js';
import { printTerminalReport } from '../reporter/terminal.js';
import type { Severity } from '../snapshot/schema.js';

// ---------------------------------------------------------------------------
// Read package version at runtime (avoids hard-coding)
// ---------------------------------------------------------------------------

function getPackageVersion(): string {
  try {
    // Use createRequire to load JSON in an ESM context
    const require = createRequire(import.meta.url);
    // Walk up from dist/ to find package.json
    const pkg = require('../../package.json') as { version: string };
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

// ---------------------------------------------------------------------------
// Severity validation
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = new Set<string>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

function parseSeverity(raw: string, flag: string): Severity {
  const upper = raw.toUpperCase();
  if (!VALID_SEVERITIES.has(upper)) {
    throw new Error(
      `Invalid value for ${flag}: "${raw}". Must be one of: CRITICAL | HIGH | MEDIUM | LOW | INFO`
    );
  }
  return upper as Severity;
}

// ---------------------------------------------------------------------------
// Options type
// ---------------------------------------------------------------------------

interface RunOptions {
  env?: string;
  failOn?: string;
  path?: string;
  output?: string;
  config?: string;
  format: string;
  verbose: boolean;
}

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

export function runCommand(): Command {
  return new Command('run')
    .description(
      'Scan project source files against DLP and CSP policies from the snapshot.\n' +
      'Exits non-zero when findings meet or exceed the configured fail_on_severity threshold.\n' +
      'Runs fully offline — no network calls.'
    )
    .option('-e, --env <environment>', 'Target environment (defaults to config default_environment)')
    .option('--fail-on <severity>', 'Override the fail threshold: CRITICAL | HIGH | MEDIUM | LOW')
    .option('--path <directory>', 'Root directory of the project to scan (defaults to cwd)')
    .option('--output <directory>', 'Directory to write the JSON report into (defaults to cwd)')
    .option('--config <path>', 'Path to pac-scan.config.yaml (auto-detected when omitted)')
    .option('-f, --format <format>', 'Output format: terminal | json', 'terminal')
    .option('--verbose', 'Print each file as it is scanned', false)
    .action(async (options: RunOptions) => {
      try {
        await runScanCommand(options);
      } catch (err) {
        console.error(chalk.red(`\n✗ ${(err as Error).message}`));
        process.exit(1);
      }
    });
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

async function runScanCommand(options: RunOptions): Promise<void> {
  const {
    failOn,
    output,
    config: configPath,
    format,
    verbose,
  } = options;

  if (format !== 'terminal' && format !== 'json') {
    throw new Error(`Unknown format "${format}". Use: terminal | json`);
  }

  // ── 1. Load config ────────────────────────────────────────────────────────
  const cfg = loadConfig(configPath);
  const env = options.env ?? cfg.default_environment;

  if (!(env in cfg.environments)) {
    const known = Object.keys(cfg.environments).join(', ');
    throw new Error(`Environment "${env}" not found in config. Defined environments: ${known}`);
  }

  // ── 2. Resolve threshold ─────────────────────────────────────────────────
  let threshold: Severity;
  if (failOn) {
    threshold = parseSeverity(failOn, '--fail-on');
  } else if (cfg.fail_on_severity[env]) {
    threshold = cfg.fail_on_severity[env];
  } else {
    // Sensible default: match prod strictness
    threshold = 'MEDIUM';
  }

  // ── 3. Load snapshot ──────────────────────────────────────────────────────
  const snapshotPath = cfg.environments[env].dlp_snapshot;
  const snapshot = loadSnapshot(snapshotPath, env);

  // ── 4. Resolve project directory ──────────────────────────────────────────
  const projectDir = resolve(options.path ?? process.cwd());

  if (verbose) {
    console.log(chalk.dim(`  Scanning: ${projectDir}`));
    console.log(chalk.dim(`  Environment: ${env}  Threshold: ${threshold}`));
    console.log(chalk.dim(`  Snapshot: ${snapshotPath} (${snapshot.connectors.length} connectors, ${snapshot.dlp_policies.length} DLP policies)`));
  }

  // ── 5. Walk files ─────────────────────────────────────────────────────────
  if (verbose) process.stdout.write(chalk.dim('  Walking files...'));

  const files = await walkFiles({
    projectDir,
    scanPaths: cfg.scan_paths,
    extensions: cfg.scan_extensions,
    excludePatterns: cfg.exclude_patterns,
    includeConfigFiles: true,
  });

  if (verbose) {
    process.stdout.write(chalk.green(` ✓ ${files.length} files\n`));
    for (const f of files) console.log(chalk.dim(`    ${f.path}`));
  }

  // ── 6. Run all rules ──────────────────────────────────────────────────────
  if (verbose) process.stdout.write(chalk.dim('  Running rules...'));

  const scanResult = runScan({ files, snapshot, threshold });

  if (verbose) {
    process.stdout.write(chalk.green(` ✓ ${scanResult.findings.length} finding(s)\n`));
  }

  // ── 7. Write JSON report (always) ─────────────────────────────────────────
  const version = getPackageVersion();
  const outputDir = output ?? process.cwd();
  const reportPath = writeJsonReport({ scanResult, snapshot, version, outputDir });

  // ── 8. Produce output ─────────────────────────────────────────────────────
  if (format === 'json') {
    // JSON-only mode: emit the report to stdout and skip the terminal banner
    const { readFileSync } = await import('node:fs');
    process.stdout.write(readFileSync(reportPath, 'utf-8'));
    process.stdout.write('\n');
  } else {
    printTerminalReport({ scanResult, snapshot, threshold, reportPath });
  }

  // ── 9. Exit code ──────────────────────────────────────────────────────────
  if (scanResult.thresholdBreached) {
    process.exit(1);
  }
}

