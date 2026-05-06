import { Command } from 'commander';
import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, copyFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import chalk from 'chalk';
import { loadConfig } from '../config/loader.js';
import type {
  EnvironmentSnapshot,
  DlpPolicy,
  ConnectorEntry,
  ConnectorRiskTier,
  CspPolicy,
} from '../snapshot/schema.js';

// ---------------------------------------------------------------------------
// Types mirroring pac CLI JSON output shapes
// ---------------------------------------------------------------------------

interface PacAuthProfile {
  Active?: boolean;
  active?: boolean;
  ConnectedAs?: string;
  connectedAs?: string;
  ConnectedUser?: string;
  UserEmail?: string;
  Kind?: string;
}

interface PacOrgEntry {
  EnvironmentId?: string;
  environmentId?: string;
  FriendlyName?: string;
  friendlyName?: string;
  DisplayName?: string;
  Url?: string;
  url?: string;
  EnvironmentUrl?: string;
}

interface PacDlpRawConnector {
  id?: string;
  name?: string;
  connectorId?: string;
}

interface PacDlpConnectorGroup {
  classification?: string;
  connectors?: PacDlpRawConnector[];
}

interface PacDlpEndpointRule {
  order?: number;
  behavior?: string;
  endpoint?: string;
}

interface PacDlpRawPolicy {
  name?: string;
  policyName?: string;
  displayName?: string;
  connectorGroups?: PacDlpConnectorGroup[];
  connectorSettings?: Array<{
    connectorId?: string;
    endpointRules?: PacDlpEndpointRule[];
  }>;
}

interface PacRawConnector {
  connectorId?: string;
  name?: string;
  displayName?: string;
  publisher?: string;
  tier?: string;
  enabled?: boolean;
}

interface PacAdminConnector {
  connectorId?: string;
  name?: string;
  endpointRules?: PacDlpEndpointRule[];
  allowedHttpActions?: string[];
}

// ---------------------------------------------------------------------------
// pac CLI runner
// ---------------------------------------------------------------------------

/**
 * Invokes `pac <args>` and returns stdout as a string.
 * Throws a structured error that includes stderr so the user sees exactly
 * what pac said when it failed.
 */
function runPac(args: string, verbose: boolean, label: string): string {
  if (verbose) {
    console.log(chalk.dim(`  → pac ${args}`));
  }
  try {
    return execSync(`pac ${args}`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    const e = err as { status?: number; stderr?: string; stdout?: string; code?: string };
    if (e.code === 'ENOENT') {
      throw new Error(
        'pac CLI not found. Install from: https://aka.ms/PowerAppsCLI\n' +
        '  Then authenticate: pac auth create --kind User'
      );
    }
    const detail = (e.stderr ?? e.stdout ?? '').trim();
    throw new Error(`pac ${label} failed (exit ${e.status ?? '?'}):\n  ${detail || String(err)}`);
  }
}

/**
 * Verifies pac CLI is reachable and returns the version string.
 * Throws the canonical "pac CLI not found" message on ENOENT.
 */
function checkPacCli(): void {
  try {
    execSync('pac --version', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === 'ENOENT') {
      throw new Error(
        'pac CLI not found. Install from: https://aka.ms/PowerAppsCLI\n' +
        '  Then authenticate: pac auth create --kind User'
      );
    }
    // pac returned non-zero but is present — unusual, surface the error
    throw new Error(`pac CLI check failed: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// JSON extraction helper
// ---------------------------------------------------------------------------

/**
 * Locates the first `[` or `{` in `text` and attempts JSON.parse from there.
 * Returns `null` on failure so callers can fall back to text parsing.
 *
 * pac CLI may emit ANSI colour codes or progress lines before the JSON body;
 * this handles that gracefully.
 */
function tryParseJson<T>(text: string): T | null {
  const bracketIdx = text.indexOf('[');
  const braceIdx = text.indexOf('{');
  const start =
    bracketIdx === -1 ? braceIdx :
    braceIdx   === -1 ? bracketIdx :
    Math.min(bracketIdx, braceIdx);
  if (start === -1) return null;
  try {
    return JSON.parse(text.slice(start)) as T;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Auth verification
// ---------------------------------------------------------------------------

function verifyAuth(verbose: boolean): string {
  const output = runPac('auth list', verbose, 'auth list');

  // Try JSON first (newer pac CLI versions)
  const profiles = tryParseJson<PacAuthProfile[]>(output);
  if (Array.isArray(profiles)) {
    const active = profiles.find(p => p.Active === true || p.active === true);
    if (active) {
      return active.ConnectedAs ?? active.connectedAs ?? active.ConnectedUser ?? active.UserEmail ?? 'unknown';
    }
  }

  // Fall back: tabular text. Active profile is marked with '*'.
  for (const line of output.split('\n')) {
    if (line.includes('*')) {
      // Split on runs of 2+ spaces — pac CLI uses space-aligned columns
      const cols = line.trim().split(/\s{2,}/);
      for (const col of cols) {
        if (col.includes('@') && col.includes('.')) return col.trim();
      }
    }
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// Environment ID resolution
// ---------------------------------------------------------------------------

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function resolveEnvironmentId(
  envName: string,
  envUrl: string | undefined,
  envIdFromConfig: string | undefined,
  override: string | undefined,
  verbose: boolean,
): string {
  // 1. CLI flag takes priority
  if (override) {
    if (!GUID_RE.test(override)) {
      throw new Error(`--environment-id "${override}" is not a valid GUID`);
    }
    return override;
  }

  // 2. Config-cached ID
  if (envIdFromConfig && GUID_RE.test(envIdFromConfig)) {
    if (verbose) console.log(chalk.dim(`  Using cached environment_id from config`));
    return envIdFromConfig;
  }

  // 3. Resolve via pac org list
  const output = runPac('org list', verbose, 'org list');

  // Try JSON
  const parsed =
    tryParseJson<PacOrgEntry[]>(output) ??
    tryParseJson<{ value: PacOrgEntry[] }>(output)?.value ??
    null;

  if (Array.isArray(parsed)) {
    for (const entry of parsed) {
      const id = entry.EnvironmentId ?? entry.environmentId;
      const name = (entry.FriendlyName ?? entry.friendlyName ?? entry.DisplayName ?? '').toLowerCase();
      const url = normaliseUrl(entry.Url ?? entry.url ?? entry.EnvironmentUrl ?? '');
      if (!id) continue;
      if (
        name === envName.toLowerCase() ||
        (envUrl && url === normaliseUrl(envUrl))
      ) {
        return id;
      }
    }
  }

  // Fall back: text table — find a GUID on a line that mentions the env name / URL
  for (const line of output.split('\n')) {
    const lower = line.toLowerCase();
    const matchesName = lower.includes(envName.toLowerCase());
    const matchesUrl = envUrl && lower.includes(normaliseUrl(envUrl));
    if (matchesName || matchesUrl) {
      const guidMatch = line.match(GUID_RE);
      if (guidMatch) return guidMatch[0];
    }
  }

  throw new Error(
    `Could not resolve environment ID for "${envName}".\n` +
    `  Options:\n` +
    `  • Add environment_url to pac-scan.config.yaml matching the pac org list output\n` +
    `  • Or pass: pac-scan fetch --env ${envName} --environment-id <guid>\n` +
    `\n  pac org list output (truncated):\n${indentLines(output.split('\n').slice(0, 8).join('\n'), 4)}`
  );
}

// ---------------------------------------------------------------------------
// DLP policy fetching and parsing
// ---------------------------------------------------------------------------

function fetchDlpPolicies(envId: string, verbose: boolean): DlpPolicy[] {
  let output: string;
  try {
    output = runPac(`admin list-dlp-policy --environment ${envId}`, verbose, 'admin list-dlp-policy');
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('not found') || msg.includes('ENOENT')) throw err;
    // Admin command failed (likely permissions) — warn and continue
    console.warn(chalk.yellow(`  ⚠ DLP policy fetch failed (requires admin role): ${firstLine(msg)}`));
    console.warn(chalk.yellow(`    Storing empty DLP policies. Grant admin access and re-run.`));
    return [];
  }

  const raw =
    tryParseJson<PacDlpRawPolicy[]>(output) ??
    tryParseJson<{ policies: PacDlpRawPolicy[] }>(output)?.policies ??
    tryParseJson<{ value: PacDlpRawPolicy[] }>(output)?.value ??
    null;

  if (!Array.isArray(raw)) {
    console.warn(chalk.yellow(`  ⚠ Could not parse DLP policy output — storing empty policies`));
    return [];
  }

  return raw.map((p): DlpPolicy => {
    const groups = p.connectorGroups ?? [];
    const business: string[] = [];
    const non_business: string[] = [];
    const blocked: string[] = [];

    for (const group of groups) {
      const cls = (group.classification ?? '').toLowerCase().replace(/[-_]/g, '');
      const names = (group.connectors ?? []).map(c => extractConnectorName(c.id ?? c.connectorId ?? c.name ?? ''));

      if (cls === 'business') business.push(...names);
      else if (cls === 'nonbusiness') non_business.push(...names);
      else if (cls === 'blocked') blocked.push(...names);
    }

    return {
      policy_id: p.name ?? p.policyName ?? crypto.randomUUID(),
      name: p.displayName ?? p.name ?? 'Unnamed Policy',
      connectors: { business, non_business, blocked },
    };
  });
}

// ---------------------------------------------------------------------------
// Connector fetching and parsing
// ---------------------------------------------------------------------------

/**
 * Builds a name → risk_tier lookup from DLP policies.
 * Blocked connectors are HIGH, non-business are MEDIUM, business are LOW.
 */
function buildDlpClassificationMap(policies: DlpPolicy[]): Map<string, ConnectorRiskTier> {
  const map = new Map<string, ConnectorRiskTier>();
  for (const policy of policies) {
    for (const name of policy.connectors.blocked)      map.set(name, 'HIGH');
    for (const name of policy.connectors.non_business) { if (!map.has(name)) map.set(name, 'MEDIUM'); }
    for (const name of policy.connectors.business)     { if (!map.has(name)) map.set(name, 'LOW');    }
  }
  return map;
}

/** Synthesises a connector list purely from DLP policy data when pac connector list fails. */
function buildConnectorsFromDlp(policies: DlpPolicy[]): ConnectorEntry[] {
  const map = new Map<string, ConnectorEntry>();
  const add = (name: string, entry: ConnectorEntry) => { if (!map.has(name)) map.set(name, entry); };

  for (const p of policies) {
    for (const name of p.connectors.blocked)      add(name, { name, enabled: false, risk_tier: 'HIGH',   allowed_actions: [], endpoint_filter_urls: [] });
    for (const name of p.connectors.non_business) add(name, { name, enabled: true,  risk_tier: 'MEDIUM', allowed_actions: [], endpoint_filter_urls: [] });
    for (const name of p.connectors.business)     add(name, { name, enabled: true,  risk_tier: 'LOW',    allowed_actions: [], endpoint_filter_urls: [] });
  }
  return [...map.values()];
}

function fetchConnectors(envId: string, dlpPolicies: DlpPolicy[], verbose: boolean): ConnectorEntry[] {
  let output: string;
  try {
    output = runPac(`connector list --environment ${envId}`, verbose, 'connector list');
  } catch {
    // Fall back to DLP-derived connector list
    console.warn(chalk.yellow(`  ⚠ pac connector list failed — deriving connector list from DLP policies`));
    return buildConnectorsFromDlp(dlpPolicies);
  }

  const raw =
    tryParseJson<PacRawConnector[]>(output) ??
    tryParseJson<{ value: PacRawConnector[] }>(output)?.value ??
    null;

  if (!Array.isArray(raw) || raw.length === 0) {
    console.warn(chalk.yellow(`  ⚠ No connectors returned — deriving from DLP policies`));
    return buildConnectorsFromDlp(dlpPolicies);
  }

  const classMap = buildDlpClassificationMap(dlpPolicies);

  return raw.map((c): ConnectorEntry => {
    const name = extractConnectorName(c.connectorId ?? c.name ?? '');
    const risk_tier = classMap.get(name) ?? 'LOW';
    return {
      name,
      enabled: c.enabled !== false,
      risk_tier,
      allowed_actions: [],
      endpoint_filter_urls: [],
    };
  });
}

// ---------------------------------------------------------------------------
// Endpoint filter fetching
// ---------------------------------------------------------------------------

function fetchEndpointFilters(
  envId: string,
  connectors: ConnectorEntry[],
  verbose: boolean,
): ConnectorEntry[] {
  let output: string;
  try {
    output = runPac(`admin connector list --environment ${envId}`, verbose, 'admin connector list');
  } catch {
    // This command may not exist in all pac CLI versions — silently skip
    if (verbose) console.log(chalk.dim(`  pac admin connector list not available — skipping endpoint filters`));
    return connectors;
  }

  const raw = tryParseJson<PacAdminConnector[]>(output) ?? null;
  if (!Array.isArray(raw)) return connectors;

  const filterMap = new Map<string, { urls: string[]; actions: string[] }>();
  for (const item of raw) {
    const name = extractConnectorName(item.connectorId ?? item.name ?? '');
    if (!name) continue;
    const urls = (item.endpointRules ?? [])
      .filter(r => (r.behavior ?? '').toLowerCase() === 'allow' && r.endpoint)
      .map(r => r.endpoint as string);
    const actions = item.allowedHttpActions ?? [];
    filterMap.set(name, { urls, actions });
  }

  return connectors.map(c => {
    const extra = filterMap.get(c.name);
    if (!extra) return c;
    return {
      ...c,
      endpoint_filter_urls: extra.urls.length > 0 ? extra.urls : c.endpoint_filter_urls,
      allowed_actions:      extra.actions.length > 0 ? extra.actions : c.allowed_actions,
    };
  });
}

// ---------------------------------------------------------------------------
// CSP derivation
// ---------------------------------------------------------------------------

/**
 * Derives a best-effort CSP snapshot from connector endpoint filter URLs
 * plus the known Power Apps Player defaults for Code Apps.
 */
function buildCsp(connectors: ConnectorEntry[]): CspPolicy {
  const connectSrc = new Set<string>([
    'https://*.microsoft.com',
    'https://*.microsoftonline.com',
    'https://*.dynamics.com',
    'https://*.powerapps.com',
    'https://*.azure.com',
  ]);

  for (const c of connectors) {
    for (const url of c.endpoint_filter_urls) {
      connectSrc.add(url);
    }
  }

  return {
    connect_src: [...connectSrc].sort(),
    // Code Apps bundle their own scripts — 'self' is the effective source
    script_src: ["'self'"],
    // Power Apps Player embeds in SharePoint, Teams, and standalone Power Apps
    frame_ancestors: [
      'https://*.sharepoint.com',
      'https://teams.microsoft.com',
      'https://*.powerapps.com',
    ],
  };
}

// ---------------------------------------------------------------------------
// Snapshot storage
// ---------------------------------------------------------------------------

/** Formats a Date as YYYY-MM-DD-HHmmss for use in filenames. */
function formatTimestamp(d: Date): string {
  const pad2 = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}` +
    `-${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}`
  );
}

function saveSnapshot(snapshot: EnvironmentSnapshot, env: string): { snapshotFile: string; currentFile: string } {
  const ts = formatTimestamp(new Date(snapshot.fetched_at));
  const snapshotsDir = resolve('.pac-scan', 'snapshots', env);
  const currentDir   = resolve('.pac-scan', 'current');

  mkdirSync(snapshotsDir, { recursive: true });
  mkdirSync(currentDir,   { recursive: true });

  const snapshotFile = join(snapshotsDir, `${ts}.json`);
  const currentFile  = join(currentDir,   `${env}.json`);

  const json = JSON.stringify(snapshot, null, 2);
  writeFileSync(snapshotFile, json, 'utf8');
  // Windows has no reliable symlink support without admin rights — copy instead
  copyFileSync(snapshotFile, currentFile);

  return { snapshotFile, currentFile };
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

function printSummary(snapshot: EnvironmentSnapshot, currentFile: string): void {
  const blockedCount   = snapshot.connectors.filter(c => c.risk_tier === 'HIGH').length;
  const highRiskCount  = snapshot.connectors.filter(c => c.risk_tier === 'HIGH' || c.risk_tier === 'MEDIUM').length;
  const endpointUrls   = snapshot.connectors.flatMap(c => c.endpoint_filter_urls);
  const uniqueUrls     = new Set(endpointUrls).size;

  const fetchedAt = new Date(snapshot.fetched_at)
    .toISOString()
    .replace('T', ' ')
    .replace(/\.\d+Z$/, ' UTC');

  const rows: [string, string][] = [
    ['Environment:',   snapshot.environment],
    ['Fetched at:',    fetchedAt],
    ['DLP Policies:',  `${snapshot.dlp_policies.length} found`],
    ['Connectors:',    `${snapshot.connectors.length} total, ${blockedCount} blocked, ${highRiskCount} high-risk`],
    ['HTTP Endpoints:', `${uniqueUrls} filter URL${uniqueUrls !== 1 ? 's' : ''}`],
    ['Snapshot:',      currentFile],
  ];

  const colWidth = Math.max(...rows.map(([k]) => k.length)) + 2;

  console.log('');
  for (const [key, value] of rows) {
    console.log(`  ${chalk.bold(key.padEnd(colWidth))}${value}`);
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// Small utility helpers
// ---------------------------------------------------------------------------

/** Strips trailing slashes and lowercases a URL for comparison. */
function normaliseUrl(url: string): string {
  return url.replace(/\/+$/, '').toLowerCase();
}

/** Extracts the final path segment of a connector ID or name. */
function extractConnectorName(id: string): string {
  const parts = id.split('/');
  return (parts[parts.length - 1] ?? id).trim();
}

function firstLine(s: string): string {
  return s.split('\n')[0] ?? s;
}

function indentLines(s: string, spaces: number): string {
  const prefix = ' '.repeat(spaces);
  return s.split('\n').map(l => prefix + l).join('\n');
}

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

interface FetchOptions {
  env: string;
  environmentId?: string;
  config?: string;
  verbose: boolean;
}

export function fetchCommand(): Command {
  return new Command('fetch')
    .description(
      'Fetch DLP and CSP policy snapshot from a Power Platform environment.\n' +
      'Requires pac CLI to be installed and authenticated (pac auth list).\n' +
      'All subsequent commands (run, diff, policy) work fully offline from this snapshot.'
    )
    .requiredOption('-e, --env <environment>', 'Target environment name defined in pac-scan.config.yaml')
    .option(
      '--environment-id <guid>',
      'Override the Power Platform environment GUID (skips pac org list look-up)'
    )
    .option('--config <path>', 'Path to pac-scan.config.yaml (auto-detected when omitted)')
    .option('--verbose', 'Show pac CLI commands as they run', false)
    .action(async (options: FetchOptions) => {
      try {
        await runFetch(options);
      } catch (err) {
        console.error(chalk.red(`\n✗ ${(err as Error).message}`));
        process.exit(1);
      }
    });
}

async function runFetch(options: FetchOptions): Promise<void> {
  const { env, environmentId: envIdOverride, config: configPath, verbose } = options;

  // Validate env name — only allow word chars and dashes to prevent path traversal
  if (!/^[\w-]+$/.test(env)) {
    throw new Error(`Environment name "${env}" contains invalid characters`);
  }

  // ── Load config ────────────────────────────────────────────────────────────
  const cfg = loadConfig(configPath);

  if (!(env in cfg.environments)) {
    const known = Object.keys(cfg.environments).join(', ');
    throw new Error(`Environment "${env}" not found in config. Defined environments: ${known}`);
  }

  const envCfg = cfg.environments[env];

  // ── Step 0: Verify pac CLI is present ─────────────────────────────────────
  process.stdout.write(chalk.dim('  Checking pac CLI...'));
  checkPacCli();
  process.stdout.write(chalk.green(' ✓\n'));

  // ── Step 1: Verify authentication ─────────────────────────────────────────
  process.stdout.write(chalk.dim('  Verifying authentication...'));
  const connectedAs = verifyAuth(verbose);
  process.stdout.write(chalk.green(` ✓ Authenticated as: ${connectedAs}\n`));

  // ── Step 2: Resolve environment GUID ──────────────────────────────────────
  process.stdout.write(chalk.dim(`  Resolving environment ID for "${env}"...`));
  const environmentId = resolveEnvironmentId(
    env,
    envCfg.environment_url,
    envCfg.environment_id,
    envIdOverride,
    verbose,
  );
  process.stdout.write(chalk.green(` ✓ ${environmentId}\n`));

  // ── Step 3: Fetch DLP policies ────────────────────────────────────────────
  process.stdout.write(chalk.dim('  Fetching DLP policies...'));
  const dlpPolicies = fetchDlpPolicies(environmentId, verbose);
  process.stdout.write(chalk.green(` ✓ ${dlpPolicies.length} polic${dlpPolicies.length === 1 ? 'y' : 'ies'} found\n`));

  // ── Step 4: Fetch connector list ──────────────────────────────────────────
  process.stdout.write(chalk.dim('  Fetching connector list...'));
  let connectors = fetchConnectors(environmentId, dlpPolicies, verbose);
  process.stdout.write(chalk.green(` ✓ ${connectors.length} connectors\n`));

  // ── Step 5: Fetch endpoint filter configurations ──────────────────────────
  process.stdout.write(chalk.dim('  Fetching endpoint filter configurations...'));
  connectors = fetchEndpointFilters(environmentId, connectors, verbose);
  const filterCount = connectors.filter(c => c.endpoint_filter_urls.length > 0).length;
  process.stdout.write(chalk.green(` ✓ ${filterCount} connectors with endpoint rules\n`));

  // ── Build snapshot ─────────────────────────────────────────────────────────
  const now = new Date();
  const snapshot: EnvironmentSnapshot = {
    fetched_at: now.toISOString(),
    environment: env,
    environment_id: environmentId,
    dlp_policies: dlpPolicies,
    connectors,
    csp: buildCsp(connectors),
  };

  // ── Save snapshot ──────────────────────────────────────────────────────────
  const { snapshotFile, currentFile } = saveSnapshot(snapshot, env);
  console.log(chalk.green(`  ✓ Snapshot saved: ${snapshotFile}`));

  // ── Summary ────────────────────────────────────────────────────────────────
  printSummary(snapshot, currentFile);
}
