import type { ScannedFile, Finding, ScanRule } from '../rules/base.js';
import type { EnvironmentSnapshot, Severity } from '../snapshot/schema.js';
import pac001 from '../rules/PAC001-secrets.js';
import pac002 from '../rules/PAC002-fetch.js';
import pac003 from '../rules/PAC003-dlp.js';
import pac004 from '../rules/PAC004-csp.js';
import pac005 from '../rules/PAC005-dependencies.js';

export const ALL_RULES: ScanRule[] = [pac001, pac002, pac003, pac004, pac005];

// ---------------------------------------------------------------------------
// Severity ordering — higher index = more severe
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Returns true when `finding.severity` is >= `threshold`. */
export function meetsThreshold(findingSeverity: Severity, threshold: Severity): boolean {
  return severityRank(findingSeverity) >= severityRank(threshold);
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

export interface RuleSummary {
  findings: number;
  status: 'PASS' | 'FAIL';
}

export interface ScanResult {
  findings: Finding[];
  rulesSummary: Record<string, RuleSummary>;
  filesScanned: number;
  rulesRun: number;
  /** True when any finding meets or exceeds the threshold severity. */
  thresholdBreached: boolean;
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

export interface ScannerOptions {
  files: ScannedFile[];
  snapshot: EnvironmentSnapshot;
  threshold: Severity;
  /** Subset of rules to run. Defaults to ALL_RULES. */
  rules?: ScanRule[];
}

/**
 * Runs all rules against the provided files and returns the aggregated result.
 * Never throws — rule errors are caught per-rule and surfaced as LOW findings.
 */
export function runScan(opts: ScannerOptions): ScanResult {
  const { files, snapshot, threshold, rules = ALL_RULES } = opts;

  const allFindings: Finding[] = [];
  const rulesSummary: Record<string, RuleSummary> = {};
  let thresholdBreached = false;

  for (const rule of rules) {
    let ruleFindings: Finding[] = [];
    try {
      ruleFindings = rule.run(files, snapshot);
    } catch (err) {
      // Rule crashed entirely — produce a single LOW meta-finding
      ruleFindings = [{
        rule_id: rule.id,
        severity: 'LOW',
        file: '<scanner>',
        line: 0,
        column: 0,
        message: `Rule ${rule.id} threw an unexpected error: ${(err as Error).message}`,
        remediation: '',
        code_snippet: '',
      }];
    }

    allFindings.push(...ruleFindings);

    const breachingFindings = ruleFindings.filter(f => meetsThreshold(f.severity, threshold));
    if (breachingFindings.length > 0) thresholdBreached = true;

    rulesSummary[rule.id] = {
      findings: ruleFindings.length,
      status: breachingFindings.length > 0 ? 'FAIL' : 'PASS',
    };
  }

  // Sort findings: severity DESC, then file + line ASC
  allFindings.sort((a, b) => {
    const sevDiff = severityRank(b.severity) - severityRank(a.severity);
    if (sevDiff !== 0) return sevDiff;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  return {
    findings: allFindings,
    rulesSummary,
    filesScanned: files.length,
    rulesRun: rules.length,
    thresholdBreached,
  };
}

