import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScanRule, ScannedFile, Finding } from './base.js';
import type { EnvironmentSnapshot, Severity } from '../snapshot/schema.js';

export const PAC005_ID = 'PAC005' as const;
export const PAC005_NAME = 'Vulnerable npm dependency';

const AUDIT_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// npm audit JSON shapes
// ---------------------------------------------------------------------------

// npm audit --json output differs between npm v6 and v7+. We handle both.

// npm v7+ shape
interface NpmAuditV7 {
  vulnerabilities?: Record<string, NpmVulnV7>;
  metadata?: { vulnerabilities?: { total?: number } };
}

interface NpmVulnV7 {
  name?: string;
  severity?: string;      // 'critical' | 'high' | 'moderate' | 'low' | 'info'
  via?: Array<ViaRef | string>;
  fixAvailable?: boolean | { name?: string; version?: string };
  range?: string;
  nodes?: string[];
}

interface ViaRef {
  title?: string;
  url?: string;
  severity?: string;
}

// npm v6 shape
interface NpmAuditV6 {
  advisories?: Record<string, NpmAdvisoryV6>;
  metadata?: { vulnerabilities?: { critical?: number; high?: number; moderate?: number; low?: number } };
}

interface NpmAdvisoryV6 {
  module_name?: string;
  severity?: string;
  title?: string;
  recommendation?: string;
  findings?: Array<{ version?: string }>;
  references?: string;
  url?: string;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/**
 * Maps npm audit severity to PAC severity.
 * Returns null when the finding should be suppressed (npm 'low' / 'info').
 */
function mapSeverity(npmSeverity: string): Severity | null {
  switch (npmSeverity.toLowerCase()) {
    case 'critical': return 'CRITICAL';
    case 'high':     return 'HIGH';
    case 'moderate': return 'MEDIUM';
    default:         return null;   // low, info — ignored
  }
}

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

interface AuditFinding {
  packageName: string;
  installedVersion: string;
  npmSeverity: string;
  title: string;
  fixVersion: string | null;
  url: string | null;
}

// ---------------------------------------------------------------------------
// npm audit runner
// ---------------------------------------------------------------------------

interface AuditResult {
  findings: AuditFinding[];
  warnings: string[];
}

function runNpmAudit(projectDir: string): AuditResult {
  const warnings: string[] = [];

  // 1. Check package.json exists
  if (!existsSync(resolve(projectDir, 'package.json'))) {
    warnings.push(`PAC005: package.json not found in ${projectDir} — skipping dependency audit`);
    return { findings: [], warnings };
  }

  // 2. Check npm is available
  try {
    execSync('npm --version', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch {
    warnings.push('PAC005: npm not found — skipping dependency audit');
    return { findings: [], warnings };
  }

  // 3. Run npm audit --json
  let stdout = '';
  try {
    stdout = execSync('npm audit --json', {
      cwd: projectDir,
      encoding: 'utf8',
      timeout: AUDIT_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    const e = err as { signal?: string; stdout?: string; stderr?: string; status?: number };

    // ETIMEDOUT signal means we hit our timeout
    if (e.signal === 'SIGTERM') {
      warnings.push(
        `PAC005: npm audit timed out after ${AUDIT_TIMEOUT_MS / 1000}s — skipping dependency audit`
      );
      return { findings: [], warnings };
    }

    // npm audit exits with status 1 when vulnerabilities are found — that is
    // expected, and stdout still contains valid JSON.
    stdout = e.stdout ?? '';
    if (!stdout) {
      warnings.push(`PAC005: npm audit produced no output — ${e.stderr ?? 'unknown error'}`);
      return { findings: [], warnings };
    }
  }

  // 4. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    warnings.push('PAC005: Could not parse npm audit JSON output — skipping dependency audit');
    return { findings: [], warnings };
  }

  const raw = parsed as Record<string, unknown>;

  // 5. Detect npm v7+ vs v6 format by shape
  if (raw['vulnerabilities'] !== undefined) {
    return { findings: parseV7(raw as NpmAuditV7), warnings };
  }
  if (raw['advisories'] !== undefined) {
    return { findings: parseV6(raw as NpmAuditV6), warnings };
  }

  // Audit ran but produced an unrecognised format
  warnings.push('PAC005: Unrecognised npm audit output format — skipping dependency audit');
  return { findings: [], warnings };
}

// ---------------------------------------------------------------------------
// npm v7+ parser
// ---------------------------------------------------------------------------

function parseV7(audit: NpmAuditV7): AuditFinding[] {
  const results: AuditFinding[] = [];

  for (const [pkgName, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
    const severity = vuln.severity ?? 'unknown';
    if (mapSeverity(severity) === null) continue;

    // Extract title from via[] — the first direct advisory title
    let title = 'Vulnerability';
    let url: string | null = null;
    for (const v of vuln.via ?? []) {
      if (typeof v === 'object' && v.title) {
        title = v.title;
        url = v.url ?? null;
        break;
      }
    }

    let fixVersion: string | null = null;
    const fix = vuln.fixAvailable;
    if (fix && typeof fix === 'object' && fix.version) {
      fixVersion = fix.version;
    }

    results.push({
      packageName: pkgName,
      installedVersion: vuln.range ?? 'unknown',
      npmSeverity: severity,
      title,
      fixVersion,
      url,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// npm v6 parser
// ---------------------------------------------------------------------------

function parseV6(audit: NpmAuditV6): AuditFinding[] {
  const results: AuditFinding[] = [];

  for (const advisory of Object.values(audit.advisories ?? {})) {
    const severity = advisory.severity ?? 'unknown';
    if (mapSeverity(severity) === null) continue;

    const installedVersion =
      advisory.findings?.[0]?.version ?? 'unknown';

    results.push({
      packageName: advisory.module_name ?? 'unknown',
      installedVersion,
      npmSeverity: severity,
      title: advisory.title ?? 'Vulnerability',
      fixVersion: null,   // v6 doesn't give a fixed version directly
      url: advisory.url ?? null,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/**
 * Returns the directory that contains the project being scanned.
 * We heuristically find the first package.json in the scanned file list's
 * common ancestor, or fall back to process.cwd().
 */
function inferProjectDir(files: ScannedFile[]): string {
  if (files.length === 0) return process.cwd();

  // Find a package.json in the scanned files list
  const pkgFile = files.find(f => f.path === 'package.json' || f.path.endsWith('/package.json'));
  if (pkgFile) {
    // path is relative — resolve from cwd
    const abs = resolve(process.cwd(), pkgFile.path);
    return abs.replace(/[\\/]package\.json$/, '') || process.cwd();
  }

  return process.cwd();
}

const pac005: ScanRule = {
  id: PAC005_ID,
  name: PAC005_NAME,
  severity: 'HIGH',   // default severity; actual per-finding is mapped from npm

  run(files: ScannedFile[], _snapshot: EnvironmentSnapshot): Finding[] {
    const findings: Finding[] = [];
    const projectDir = inferProjectDir(files);
    const { findings: auditFindings, warnings } = runNpmAudit(projectDir);

    // Surface warnings as INFO-level whole-report findings
    for (const w of warnings) {
      findings.push({
        rule_id: PAC005_ID,
        severity: 'INFO',
        file: 'package.json',
        line: 0,
        column: 0,
        message: w,
        remediation: '',
        code_snippet: '',
      });
    }

    for (const af of auditFindings) {
      const severity = mapSeverity(af.npmSeverity);
      if (severity === null) continue;   // shouldn't happen — filtered in parsers

      const fixNote = af.fixVersion
        ? `Run: npm audit fix  or upgrade to: ${af.fixVersion}`
        : `Run: npm audit fix --force  (review breaking changes carefully)`;

      const urlNote = af.url ? `\nAdvisory: ${af.url}` : '';

      findings.push({
        rule_id: PAC005_ID,
        severity,
        file: 'package.json',
        line: 0,
        column: 0,
        message:
          `"${af.packageName}" (${af.installedVersion}) has ${af.npmSeverity} vulnerability: ${af.title}`,
        remediation: fixNote + urlNote,
        code_snippet: `"${af.packageName}": "${af.installedVersion}"`,
      });
    }

    return findings;
  },
};

export default pac005;
