import { Command } from 'commander';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';
import chalk from 'chalk';
import { loadConfig } from '../config/loader.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

interface ValidateOptions {
  env?: string;
  config?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ok(label: string, detail?: string): void {
  const suffix = detail ? chalk.dim(`  (${detail})`) : '';
  console.log(`  ${chalk.green('✅')} ${label}${suffix}`);
}

function fail(label: string, detail?: string): void {
  const suffix = detail ? `\n     ${chalk.dim(detail)}` : '';
  console.log(`  ${chalk.red('❌')} ${chalk.red(label)}${suffix}`);
}

function warn(label: string, detail?: string): void {
  const suffix = detail ? `\n     ${chalk.dim(detail)}` : '';
  console.log(`  ${chalk.yellow('⚠ ')} ${chalk.yellow(label)}${suffix}`);
}

function section(title: string): void {
  console.log('');
  console.log(chalk.bold.cyan(`  ${title}`));
  console.log('  ' + '─'.repeat(58));
}

// ---------------------------------------------------------------------------
// Check functions
// ---------------------------------------------------------------------------

function checkPacCli(): boolean {
  try {
    execSync('pac --version', { stdio: 'pipe', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

function checkPacAuth(): { authenticated: boolean; user: string } {
  try {
    const out = execSync('pac auth list', { stdio: 'pipe', timeout: 10_000 }).toString();
    // Look for a line with an asterisk (active profile) or any profile at all
    const hasActive = out.includes('*') || /connected|authenticated/i.test(out);
    if (hasActive) {
      const m = out.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      return { authenticated: true, user: m?.[0] ?? 'unknown' };
    }
    return { authenticated: false, user: '' };
  } catch {
    return { authenticated: false, user: '' };
  }
}

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

export function validateCommand(): Command {
  return new Command('validate')
    .description(
      'Verify that pac-scan is fully configured and ready to run.\n' +
      'Checks config file, snapshot files, pac CLI installation, and authentication.\n' +
      'Run this first when setting up a new project.'
    )
    .option('-e, --env <environment>', 'Specific environment to validate (validates all when omitted)')
    .option('--config <path>', 'Path to pac-scan.config.yaml (auto-detected when omitted)')
    .action(async (options: ValidateOptions) => {
      try {
        await runValidate(options);
      } catch (err) {
        console.error(chalk.red('\nError:'), (err as Error).message);
        process.exit(1);
      }
    });
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

async function runValidate(options: ValidateOptions): Promise<void> {
  const { env, config } = options;

  console.log('');
  console.log(chalk.bold('  pac-scan validate'));
  console.log('');

  let allPassed = true;

  // ── 1. Config file ──────────────────────────────────────────────────────
  section('Configuration file');

  let cfg;
  let configPath = '';
  try {
    cfg = loadConfig(config);
    // Recover the resolved path for display
    try {
      configPath = config
        ? resolve(config)
        : findConfigPath(process.cwd());
    } catch {
      configPath = '(auto-detected)';
    }
    ok('pac-scan.config.yaml found and valid', configPath);
  } catch (err) {
    fail('pac-scan.config.yaml', (err as Error).message);
    allPassed = false;
    // Cannot continue without config
    printResult(allPassed);
    process.exit(1);
    return;
  }

  ok(`default_environment: ${cfg.default_environment}`);

  const envsToCheck = env
    ? [env]
    : Object.keys(cfg.environments);

  if (env && !cfg.environments[env]) {
    fail(`Environment "${env}" not found in config`, `Available: ${Object.keys(cfg.environments).join(', ')}`);
    allPassed = false;
  }

  // ── 2. Snapshot files ────────────────────────────────────────────────────
  section('Snapshot files');

  for (const envName of envsToCheck) {
    if (!cfg.environments[envName]) continue;

    const snapshotPath = resolve(process.cwd(), '.pac-scan', 'current', `${envName}.json`);

    if (existsSync(snapshotPath)) {
      let ageHours = -1;
      try {
        const snap = JSON.parse(
          readFileSync(snapshotPath, 'utf-8')
        ) as { fetched_at: string };
        ageHours = (Date.now() - new Date(snap.fetched_at).getTime()) / 3_600_000;
      } catch { /* ignore */ }

      if (ageHours >= 0 && ageHours >= 24) {
        warn(
          `${envName}: snapshot is ${Math.round(ageHours)}h old`,
          `Run: pac-scan fetch --env ${envName}`,
        );
      } else {
        const ageStr = ageHours >= 0 ? `${Math.round(ageHours * 10) / 10}h old` : 'age unknown';
        ok(`${envName}: snapshot found`, ageStr);
      }
    } else {
      fail(
        `${envName}: no snapshot found`,
        `Run: pac-scan fetch --env ${envName}`,
      );
      allPassed = false;
    }
  }

  // ── 3. pac CLI ───────────────────────────────────────────────────────────
  section('pac CLI (required for fetch only)');

  const pacInstalled = checkPacCli();
  if (pacInstalled) {
    ok('pac CLI found on PATH');

    const auth = checkPacAuth();
    if (auth.authenticated) {
      ok(`Authenticated`, auth.user);
    } else {
      warn(
        'No active pac auth profile found',
        'Run: pac auth create  (only needed for pac-scan fetch)',
      );
    }
  } else {
    warn(
      'pac CLI not found on PATH',
      'Only required for: pac-scan fetch\n' +
      '     Install: npm install -g @microsoft/powerplatform-cli',
    );
  }

  // ── Result ───────────────────────────────────────────────────────────────
  printResult(allPassed);

  if (!allPassed) process.exit(1);
}

function printResult(allPassed: boolean): void {
  console.log('');
  console.log('  ' + '─'.repeat(58));
  if (allPassed) {
    console.log(`  ${chalk.green.bold('✅ All checks passed — pac-scan is ready to run.')}`);
  } else {
    console.log(`  ${chalk.red.bold('❌ Some checks failed — see issues above.')}`);
  }
  console.log('');
}

/** Walks up from startDir to find pac-scan.config.yaml — mirrors config/loader.ts */
function findConfigPath(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 10; i++) {
    const candidate = join(dir, 'pac-scan.config.yaml');
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('pac-scan.config.yaml not found');
}
