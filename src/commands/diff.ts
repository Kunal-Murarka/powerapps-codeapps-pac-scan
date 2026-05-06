import { Command } from 'commander';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import chalk from 'chalk';
import { loadConfig } from '../config/loader.js';
import type { EnvironmentSnapshot, CspPolicy } from '../snapshot/schema.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

interface DiffOptions {
  env: string;
  from: string;
  to: string;
  format: string;
  config?: string;
}

// ---------------------------------------------------------------------------
// Diff result shape
// ---------------------------------------------------------------------------

interface ConnectorChange {
  name: string;
  changeType:
    | 'added_to_blocked'
    | 'removed_from_blocked'
    | 'added_to_non_business'
    | 'removed_from_non_business'
    | 'added_to_business'
    | 'removed_from_business';
}

interface EndpointChange {
  connector: string;
  url: string;
  changeType: 'added' | 'removed';
}

interface CspChange {
  directive: 'connect_src' | 'script_src' | 'frame_ancestors';
  value: string;
  changeType: 'added' | 'removed';
}

interface SnapshotDiff {
  base: { path: string; fetched_at: string };
  head: { path: string; fetched_at: string };
  connectorChanges: ConnectorChange[];
  endpointChanges: EndpointChange[];
  cspChanges: CspChange[];
}

// ---------------------------------------------------------------------------
// Snapshot discovery
// ---------------------------------------------------------------------------

const SNAPSHOT_DATE_RE = /^(\d{4}-\d{2}-\d{2})-\d{6}\.json$/;

/**
 * Finds the snapshot file closest to (and not after) the given date string
 * (YYYY-MM-DD) in `.pac-scan/snapshots/<env>/`.
 * Falls back to `.pac-scan/current/<env>.json` when no dated history exists.
 */
function findSnapshotForDate(workspaceRoot: string, env: string, dateStr: string): string {
  const snapshotDir = resolve(workspaceRoot, '.pac-scan', 'snapshots', env);

  if (existsSync(snapshotDir)) {
    const files = readdirSync(snapshotDir)
      .filter(f => SNAPSHOT_DATE_RE.test(f))
      .sort(); // lexicographic = chronological for YYYY-MM-DD-HHmmss

    const candidates = files.filter(f => {
      const m = SNAPSHOT_DATE_RE.exec(f);
      return m !== null && m[1] <= dateStr;
    });

    if (candidates.length > 0) {
      return join(snapshotDir, candidates[candidates.length - 1]);
    }
  }

  const current = resolve(workspaceRoot, '.pac-scan', 'current', `${env}.json`);
  if (existsSync(current)) return current;

  throw new Error(
    `No snapshot found for env "${env}" on or before ${dateStr}.\n` +
    `Run: pac-scan fetch --env ${env}\n` +
    `Snapshots are stored in: .pac-scan/snapshots/${env}/`,
  );
}

function loadSnapshotFile(filePath: string): EnvironmentSnapshot {
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8')) as EnvironmentSnapshot;
  } catch (err) {
    throw new Error(`Failed to read snapshot at ${filePath}: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Diffing logic
// ---------------------------------------------------------------------------

function diffConnectors(base: EnvironmentSnapshot, head: EnvironmentSnapshot): ConnectorChange[] {
  const changes: ConnectorChange[] = [];

  const baseBlocked     = new Set(base.dlp_policies.flatMap(p => p.connectors.blocked));
  const headBlocked     = new Set(head.dlp_policies.flatMap(p => p.connectors.blocked));
  const baseNonBusiness = new Set(base.dlp_policies.flatMap(p => p.connectors.non_business));
  const headNonBusiness = new Set(head.dlp_policies.flatMap(p => p.connectors.non_business));
  const baseBusiness    = new Set(base.dlp_policies.flatMap(p => p.connectors.business));
  const headBusiness    = new Set(head.dlp_policies.flatMap(p => p.connectors.business));

  for (const name of headBlocked)     if (!baseBlocked.has(name))     changes.push({ name, changeType: 'added_to_blocked' });
  for (const name of baseBlocked)     if (!headBlocked.has(name))     changes.push({ name, changeType: 'removed_from_blocked' });
  for (const name of headNonBusiness) if (!baseNonBusiness.has(name)) changes.push({ name, changeType: 'added_to_non_business' });
  for (const name of baseNonBusiness) if (!headNonBusiness.has(name)) changes.push({ name, changeType: 'removed_from_non_business' });
  for (const name of headBusiness)    if (!baseBusiness.has(name))    changes.push({ name, changeType: 'added_to_business' });
  for (const name of baseBusiness)    if (!headBusiness.has(name))    changes.push({ name, changeType: 'removed_from_business' });

  return changes;
}

function diffEndpoints(base: EnvironmentSnapshot, head: EnvironmentSnapshot): EndpointChange[] {
  const changes: EndpointChange[] = [];

  const baseMap = new Map<string, Set<string>>();
  for (const c of base.connectors) baseMap.set(c.name, new Set(c.endpoint_filter_urls));
  const headMap = new Map<string, Set<string>>();
  for (const c of head.connectors) headMap.set(c.name, new Set(c.endpoint_filter_urls));

  for (const [name, headUrls] of headMap) {
    const baseUrls = baseMap.get(name) ?? new Set<string>();
    for (const url of headUrls) if (!baseUrls.has(url)) changes.push({ connector: name, url, changeType: 'added' });
    for (const url of baseUrls) if (!headUrls.has(url)) changes.push({ connector: name, url, changeType: 'removed' });
  }
  for (const [name, baseUrls] of baseMap) {
    if (!headMap.has(name)) {
      for (const url of baseUrls) changes.push({ connector: name, url, changeType: 'removed' });
    }
  }

  return changes;
}

function diffCsp(base: EnvironmentSnapshot, head: EnvironmentSnapshot): CspChange[] {
  const changes: CspChange[] = [];
  const directives: Array<keyof CspPolicy> = ['connect_src', 'script_src', 'frame_ancestors'];

  for (const directive of directives) {
    const baseVals = new Set(base.csp[directive]);
    const headVals = new Set(head.csp[directive]);
    for (const v of headVals) if (!baseVals.has(v)) changes.push({ directive, value: v, changeType: 'added' });
    for (const v of baseVals) if (!headVals.has(v)) changes.push({ directive, value: v, changeType: 'removed' });
  }

  return changes;
}

// ---------------------------------------------------------------------------
// Terminal renderer
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

function printDiff(diff: SnapshotDiff): void {
  const { base, head, connectorChanges, endpointChanges, cspChanges } = diff;

  console.log('');
  console.log(chalk.bold('┌─ pac-scan diff ───────────────────────────────────────────────┐'));
  console.log(chalk.bold('│') + ` Base : ${formatDate(base.fetched_at).padEnd(56)}` + chalk.bold('│'));
  console.log(chalk.bold('│') + `        ${base.path.slice(-56).padEnd(56)}` + chalk.bold('│'));
  console.log(chalk.bold('│') + ` Head : ${formatDate(head.fetched_at).padEnd(56)}` + chalk.bold('│'));
  console.log(chalk.bold('│') + `        ${head.path.slice(-56).padEnd(56)}` + chalk.bold('│'));
  console.log(chalk.bold('└───────────────────────────────────────────────────────────────┘'));
  console.log('');

  const totalChanges = connectorChanges.length + endpointChanges.length + cspChanges.length;

  if (totalChanges === 0) {
    console.log(chalk.green('  ✅ No policy changes between these two snapshots.'));
    return;
  }

  // ── DLP connector changes ───────────────────────────────────────────────
  if (connectorChanges.length > 0) {
    console.log(chalk.bold.cyan('  DLP Connector Changes'));
    console.log('  ' + '─'.repeat(60));

    const LABELS: Record<ConnectorChange['changeType'], [string, (s: string) => string]> = {
      added_to_blocked:          ['+ BLOCKED',        (s) => chalk.red.bold(s)],
      removed_from_blocked:      ['- unblocked',      (s) => chalk.green(s)],
      added_to_non_business:     ['+ NON-BUSINESS',   (s) => chalk.yellow.bold(s)],
      removed_from_non_business: ['- non-business ✓', (s) => chalk.green(s)],
      added_to_business:         ['+ business ✓',     (s) => chalk.green(s)],
      removed_from_business:     ['- removed',        (s) => chalk.dim(s)],
    };

    for (const change of connectorChanges) {
      const [label, color] = LABELS[change.changeType];
      console.log(`  ${color(label.padEnd(20))} ${change.name}`);
    }
    console.log('');
  }

  // ── Endpoint filter URL changes ────────────────────────────────────────
  if (endpointChanges.length > 0) {
    console.log(chalk.bold.cyan('  Endpoint Filter URL Changes'));
    console.log('  ' + '─'.repeat(60));

    for (const change of endpointChanges) {
      const icon = change.changeType === 'added' ? chalk.green('+') : chalk.red('-');
      console.log(`  ${icon}  ${chalk.dim(change.connector)}  ${change.url}`);
    }
    console.log('');
  }

  // ── CSP directive changes ──────────────────────────────────────────────
  if (cspChanges.length > 0) {
    console.log(chalk.bold.cyan('  CSP Directive Changes'));
    console.log('  ' + '─'.repeat(60));

    for (const change of cspChanges) {
      const icon = change.changeType === 'added' ? chalk.green('+') : chalk.red('-');
      console.log(`  ${icon}  ${chalk.dim(change.directive).padEnd(26)} ${change.value}`);
    }
    console.log('');
  }

  console.log(chalk.dim(`  Total changes: ${totalChanges}`));

  const newlyBlocked = connectorChanges.filter(c => c.changeType === 'added_to_blocked');
  if (newlyBlocked.length > 0) {
    console.log('');
    console.log(chalk.red.bold(`  ⚠  ${newlyBlocked.length} connector(s) added to the BLOCKED list.`));
    console.log(chalk.red('     PAC003 violations will now appear in scans that previously passed.'));
    for (const c of newlyBlocked) console.log(chalk.red(`     • ${c.name}`));
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

export function diffCommand(): Command {
  return new Command('diff')
    .description(
      'Compare DLP/CSP policy snapshots for an environment between two dates.\n' +
      'Shows connectors added/removed from blocked list, endpoint filter changes,\n' +
      'and CSP directive changes. Useful for tracing why a scan started failing.'
    )
    .requiredOption('-e, --env <environment>', 'Environment to compare (e.g. prod)')
    .requiredOption('--from <date>', 'Base date YYYY-MM-DD — finds nearest snapshot on or before this date')
    .requiredOption('--to <date>',   'Head date YYYY-MM-DD — finds nearest snapshot on or before this date')
    .option('-f, --format <format>', 'Output format: terminal | json', 'terminal')
    .option('--config <path>', 'Path to pac-scan.config.yaml (auto-detected when omitted)')
    .action(async (options: DiffOptions) => {
      try {
        await runDiff(options);
      } catch (err) {
        console.error(chalk.red('Error:'), (err as Error).message);
        process.exit(1);
      }
    });
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

async function runDiff(options: DiffOptions): Promise<void> {
  const { env, from, to, format, config } = options;

  const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
  if (!DATE_RE.test(from)) throw new Error(`--from must be YYYY-MM-DD, got: "${from}"`);
  if (!DATE_RE.test(to))   throw new Error(`--to must be YYYY-MM-DD, got: "${to}"`);

  const cfg = loadConfig(config);
  const workspaceRoot = resolve(process.cwd());

  if (!cfg.environments[env]) {
    throw new Error(
      `Environment "${env}" not found in config.\n` +
      `Available: ${Object.keys(cfg.environments).join(', ')}`,
    );
  }

  const basePath = findSnapshotForDate(workspaceRoot, env, from);
  const headPath = findSnapshotForDate(workspaceRoot, env, to);

  if (basePath === headPath) {
    console.log(chalk.yellow(`Both dates resolve to the same snapshot:\n  ${basePath}`));
    console.log(chalk.dim('No diff to display.'));
    return;
  }

  const baseSnap = loadSnapshotFile(basePath);
  const headSnap = loadSnapshotFile(headPath);

  const diff: SnapshotDiff = {
    base: { path: basePath, fetched_at: baseSnap.fetched_at },
    head: { path: headPath, fetched_at: headSnap.fetched_at },
    connectorChanges: diffConnectors(baseSnap, headSnap),
    endpointChanges:  diffEndpoints(baseSnap, headSnap),
    cspChanges:       diffCsp(baseSnap, headSnap),
  };

  if (format === 'json') {
    process.stdout.write(JSON.stringify(diff, null, 2) + '\n');
  } else {
    printDiff(diff);
  }
}
