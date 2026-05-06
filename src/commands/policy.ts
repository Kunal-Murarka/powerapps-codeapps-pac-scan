import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../config/loader.js';
import { loadSnapshot } from '../snapshot/loader.js';
import type { EnvironmentSnapshot, DlpPolicy, ConnectorEntry } from '../snapshot/schema.js';

// ---------------------------------------------------------------------------
// Terminal rendering helpers
// ---------------------------------------------------------------------------

/** Renders a horizontal rule using box-drawing characters. */
function rule(label: string, width = 72): string {
  const bar = '═'.repeat(Math.max(0, width - label.length - 4));
  return chalk.bold.cyan(`══ ${label} ${bar}`);
}

/** Right-pads `s` to `width` characters. */
function pad(s: string, width: number): string {
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

/** Truncates `s` to `maxLen` characters with ellipsis. */
function trunc(s: string, maxLen: number): string {
  return s.length <= maxLen ? s : `${s.slice(0, maxLen - 1)}…`;
}

/** Applies a chalk colour to a risk tier label. */
function colourRisk(tier: string): string {
  switch (tier) {
    case 'HIGH':   return chalk.red(pad(tier, 6));
    case 'MEDIUM': return chalk.yellow(pad(tier, 6));
    default:       return chalk.green(pad(tier, 6));
  }
}

/** Applies a chalk colour to a connector group classification label. */
function colourGroup(group: string): string {
  if (group === 'Blocked')      return chalk.red(group);
  if (group === 'Non-Business') return chalk.yellow(group);
  return chalk.green(group);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function printHeader(snapshot: EnvironmentSnapshot): void {
  const fetchedAt = new Date(snapshot.fetched_at)
    .toISOString()
    .replace('T', ' ')
    .replace(/\.\d+Z$/, ' UTC');

  console.log('');
  console.log(rule(`Policy view — ${snapshot.environment.toUpperCase()}`));
  console.log(`  ${chalk.bold('Environment:')}    ${snapshot.environment}`);
  console.log(`  ${chalk.bold('Environment ID:')} ${snapshot.environment_id}`);
  console.log(`  ${chalk.bold('Fetched at:')}     ${fetchedAt}`);
  console.log('');
}

// ---------------------------------------------------------------------------
// DLP policy table
// ---------------------------------------------------------------------------

function printDlpPolicies(policies: DlpPolicy[]): void {
  console.log(rule(`DLP Policies (${policies.length})`));

  if (policies.length === 0) {
    console.log(chalk.dim('  No DLP policies in snapshot. Run: pac-scan fetch --env <env>'));
    console.log('');
    return;
  }

  const COL_NAME    = 40;
  const COL_BUS     = 10;
  const COL_NONBUS  = 13;
  const COL_BLOCKED = 8;

  // Table header
  console.log(
    `  ${chalk.bold(pad('Policy Name', COL_NAME))}` +
    `  ${chalk.bold(pad('Business', COL_BUS))}` +
    `  ${chalk.bold(pad('Non-Business', COL_NONBUS))}` +
    `  ${chalk.bold('Blocked')}`
  );
  console.log('  ' + '─'.repeat(COL_NAME + COL_BUS + COL_NONBUS + COL_BLOCKED + 6));

  for (const p of policies) {
    const bus     = p.connectors.business.length;
    const nonBus  = p.connectors.non_business.length;
    const blocked = p.connectors.blocked.length;

    console.log(
      `  ${pad(trunc(p.name, COL_NAME), COL_NAME)}` +
      `  ${chalk.green(pad(String(bus), COL_BUS))}` +
      `  ${chalk.yellow(pad(String(nonBus), COL_NONBUS))}` +
      `  ${chalk.red(String(blocked))}`
    );
  }
  console.log('');

  // Blocked connector detail
  const allBlocked = [...new Set(policies.flatMap(p => p.connectors.blocked))].sort();
  if (allBlocked.length > 0) {
    console.log(`  ${chalk.red.bold('Blocked connectors')} (${allBlocked.length}):`);
    for (const name of allBlocked) {
      console.log(`    ${chalk.red('✗')} ${name}`);
    }
    console.log('');
  }

  // Non-business connector detail
  const allNonBus = [...new Set(policies.flatMap(p => p.connectors.non_business))].sort();
  if (allNonBus.length > 0) {
    console.log(`  ${chalk.yellow.bold('Non-business connectors')} (${allNonBus.length}):`);
    for (const name of allNonBus) {
      const inBlocked = allBlocked.includes(name);
      console.log(`    ${chalk.yellow('⚠')} ${name}${inBlocked ? chalk.dim(' (also blocked)') : ''}`);
    }
    console.log('');
  }

  // Build a full cross-policy view grouped by connector name
  console.log(rule('Connector classification per policy'));
  for (const p of policies) {
    console.log(`  ${chalk.bold(p.name)}`);
    const groups: [string, string[]][] = [
      ['Business',     p.connectors.business],
      ['Non-Business', p.connectors.non_business],
      ['Blocked',      p.connectors.blocked],
    ];
    for (const [groupName, connectors] of groups) {
      if (connectors.length === 0) continue;
      console.log(`    ${colourGroup(groupName)} (${connectors.length}): ${connectors.slice(0, 6).join(', ')}${connectors.length > 6 ? ` … +${connectors.length - 6} more` : ''}`);
    }
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Connector table
// ---------------------------------------------------------------------------

function printConnectors(connectors: ConnectorEntry[]): void {
  console.log(rule(`Connectors (${connectors.length} total)`));

  if (connectors.length === 0) {
    console.log(chalk.dim('  No connectors in snapshot.'));
    console.log('');
    return;
  }

  // Sort: HIGH → MEDIUM → LOW, then alphabetically within tier
  const tierOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const sorted = [...connectors].sort((a, b) => {
    const tierDiff = (tierOrder[a.risk_tier] ?? 3) - (tierOrder[b.risk_tier] ?? 3);
    return tierDiff !== 0 ? tierDiff : a.name.localeCompare(b.name);
  });

  const COL_NAME    = 42;
  const COL_ENABLED = 8;
  const COL_RISK    = 8;

  console.log(
    `  ${chalk.bold(pad('Connector', COL_NAME))}` +
    `  ${chalk.bold(pad('Enabled', COL_ENABLED))}` +
    `  ${chalk.bold('Risk')}`
  );
  console.log('  ' + '─'.repeat(COL_NAME + COL_ENABLED + COL_RISK + 4));

  for (const c of sorted) {
    const enabledStr = c.enabled ? chalk.green('yes') : chalk.red('no');
    console.log(
      `  ${pad(trunc(c.name, COL_NAME), COL_NAME)}` +
      `  ${pad(enabledStr, COL_ENABLED + 10)}` +  // +10 for chalk escape codes
      `  ${colourRisk(c.risk_tier)}`
    );

    if (c.endpoint_filter_urls.length > 0) {
      for (const url of c.endpoint_filter_urls) {
        console.log(`    ${chalk.dim('→')} ${url}`);
      }
    }
    if (c.allowed_actions.length > 0) {
      console.log(`    ${chalk.dim('actions:')} ${c.allowed_actions.join(', ')}`);
    }
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// CSP directives
// ---------------------------------------------------------------------------

function printCsp(snapshot: EnvironmentSnapshot): void {
  const { csp } = snapshot;

  console.log(rule('CSP Directives (Power Apps Player sandbox)'));

  const printDirective = (name: string, values: string[], colour: (s: string) => string) => {
    if (values.length === 0) {
      console.log(`  ${chalk.bold(name + ':')} ${chalk.dim('(none)')}`);
      return;
    }
    console.log(`  ${chalk.bold(name + ':')}`);
    for (const v of values) {
      console.log(`    ${colour('•')} ${v}`);
    }
  };

  printDirective('connect-src',    csp.connect_src,    chalk.cyan);
  printDirective('script-src',     csp.script_src,     chalk.cyan);
  printDirective('frame-ancestors', csp.frame_ancestors, chalk.cyan);
  console.log('');
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

function printJson(snapshot: EnvironmentSnapshot): void {
  console.log(JSON.stringify(snapshot, null, 2));
}

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

interface PolicyOptions {
  env?: string;
  format: string;
  config?: string;
}

export function policyCommand(): Command {
  return new Command('policy')
    .description(
      'Display the effective DLP and CSP policy for an environment snapshot.\n' +
      'Reads .pac-scan/current/<env>.json — fully offline, no network calls.'
    )
    .option('-e, --env <environment>', 'Target environment (defaults to config default_environment)')
    .option(
      '-f, --format <format>',
      'Output format: terminal | json',
      'terminal'
    )
    .option('--config <path>', 'Path to pac-scan.config.yaml (auto-detected when omitted)')
    .action(async (options: PolicyOptions) => {
      try {
        await runPolicy(options);
      } catch (err) {
        console.error(chalk.red(`\n✗ ${(err as Error).message}`));
        process.exit(1);
      }
    });
}

async function runPolicy(options: PolicyOptions): Promise<void> {
  const { format, config: configPath } = options;

  if (format !== 'terminal' && format !== 'json') {
    throw new Error(`Unknown format "${format}". Use: terminal | json`);
  }

  const cfg = loadConfig(configPath);
  const env = options.env ?? cfg.default_environment;

  if (!(env in cfg.environments)) {
    const known = Object.keys(cfg.environments).join(', ');
    throw new Error(`Environment "${env}" not found in config. Defined environments: ${known}`);
  }

  const snapshotPath = cfg.environments[env].dlp_snapshot;
  const snapshot = loadSnapshot(snapshotPath, env);

  if (format === 'json') {
    printJson(snapshot);
    return;
  }

  // Terminal format
  printHeader(snapshot);
  printDlpPolicies(snapshot.dlp_policies);
  printConnectors(snapshot.connectors);
  printCsp(snapshot);
}
