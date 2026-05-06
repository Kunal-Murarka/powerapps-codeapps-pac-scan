import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import type { Finding } from '../rules/base.js';
import type { EnvironmentSnapshot, Severity } from '../snapshot/schema.js';
import type { ScanResult, RuleSummary } from '../scanner/index.js';

// ---------------------------------------------------------------------------
// Report schema
// ---------------------------------------------------------------------------

export interface JsonReport {
  scan_id: string;
  tool: string;
  version: string;
  timestamp: string;
  environment: string;
  environment_id: string;
  snapshot_age_hours: number;
  /** true when the snapshot is more than 24 hours old — a stale snapshot warning. */
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
// Helpers
// ---------------------------------------------------------------------------

/** Generates a simple UUID-v4 (crypto.randomUUID available in Node 15+). */
function newScanId(): string {
  return crypto.randomUUID();
}

function countBySeverity(findings: Finding[], sev: Severity): number {
  return findings.filter(f => f.severity === sev).length;
}

function snapshotAgeHours(snapshot: EnvironmentSnapshot): number {
  const fetchedAt = new Date(snapshot.fetched_at).getTime();
  const now = Date.now();
  return Math.round(((now - fetchedAt) / 3_600_000) * 10) / 10;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface JsonReportOptions {
  scanResult: ScanResult;
  snapshot: EnvironmentSnapshot;
  version: string;
  /** Directory to write the report into. Defaults to process.cwd(). */
  outputDir?: string;
}

/**
 * Builds the JSON report object and writes it to disk.
 * Returns the absolute path of the written file.
 */
export function writeJsonReport(opts: JsonReportOptions): string {
  const { scanResult, snapshot, version, outputDir = process.cwd() } = opts;

  const now = new Date();
  const timestamp = now.toISOString();

  // Filename: pac-scan-report-<env>-<YYYYMMDD-HHmmss>.json
  const pad2 = (n: number) => String(n).padStart(2, '0');
  const datePart =
    `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}` +
    `-${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}`;
  const filename = `pac-scan-report-${snapshot.environment}-${datePart}.json`;

  const report: JsonReport = {
    scan_id: newScanId(),
    tool: 'pac-scan',
    version,
    timestamp,
    environment: snapshot.environment,
    environment_id: snapshot.environment_id,
    snapshot_age_hours: snapshotAgeHours(snapshot),
    snapshot_warned: snapshotAgeHours(snapshot) >= 24,
    result: scanResult.thresholdBreached ? 'FAIL' : 'PASS',
    summary: {
      total: scanResult.findings.length,
      critical: countBySeverity(scanResult.findings, 'CRITICAL'),
      high:     countBySeverity(scanResult.findings, 'HIGH'),
      medium:   countBySeverity(scanResult.findings, 'MEDIUM'),
      low:      countBySeverity(scanResult.findings, 'LOW'),
      info:     countBySeverity(scanResult.findings, 'INFO'),
      files_scanned: scanResult.filesScanned,
      rules_run:     scanResult.rulesRun,
    },
    findings: scanResult.findings,
    rules_summary: scanResult.rulesSummary,
  };

  mkdirSync(resolve(outputDir), { recursive: true });
  const filePath = join(resolve(outputDir), filename);
  writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');

  return filePath;
}

