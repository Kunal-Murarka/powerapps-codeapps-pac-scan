import type { ScanRule, ScannedFile, Finding } from './base.js';
import { buildSnippet, makeParseErrorFinding, checkCommentState } from './base.js';
import type { EnvironmentSnapshot } from '../snapshot/schema.js';

export const PAC001_ID = 'PAC001' as const;
export const PAC001_NAME = 'Hardcoded secrets';

const SEVERITY = 'CRITICAL' as const;

const REMEDIATION =
  "Move this value to a Power Platform environment variable. " +
  "Access it via: import { getEnvironmentVariable } from '@microsoft/powerplatform-envvar'";

// ---------------------------------------------------------------------------
// Exclusion rules
// ---------------------------------------------------------------------------

/** Files matching these suffixes are never scanned by PAC001. */
const EXCLUDED_SUFFIXES = ['.test.ts', '.spec.ts', '.test.tsx', '.spec.tsx', '.mock.ts'];

/**
 * If any of these substrings appear on a line the line is considered safe —
 * the value is read from an environment variable, not hardcoded.
 */
const SAFE_SUBSTRINGS = [
  'process.env.',
  'import.meta.env.',
  'EnvVar(',
  'getEnvironmentVariable(',
];

// ---------------------------------------------------------------------------
// Secret detection patterns
// ---------------------------------------------------------------------------

interface SecretPattern {
  /** Regex source without flags. Will be compiled with 'g' (+ 'i' when flagged). */
  source: string;
  /** Extra flags to add beyond 'g'. Typically 'i' for case-insensitive matches. */
  flags: string;
  label: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // Generic API key assignments:  apiKey = "...", api_key: "...", API-KEY = "..."
  {
    source: String.raw`api[_\-]?key\s*[:=]\s*["'][a-zA-Z0-9]{16,}`,
    flags: 'i',
    label: 'API key',
  },
  {
    source: String.raw`apikey\s*[:=]\s*["'][a-zA-Z0-9]{16,}`,
    flags: 'i',
    label: 'API key',
  },

  // Authorization headers with Bearer token
  {
    source: String.raw`Authorization\s*[:=]\s*["']Bearer\s+[a-zA-Z0-9+/=]{20,}`,
    flags: 'i',
    label: 'Bearer token in Authorization header',
  },
  {
    source: String.raw`bearer\s+[a-zA-Z0-9+/=]{20,}`,
    flags: 'i',
    label: 'Bearer token',
  },

  // Power Platform: client secrets and application/tenant IDs
  {
    source: String.raw`client[_\-]?secret\s*[:=]\s*["'][^"']{8,}`,
    flags: 'i',
    label: 'Client secret',
  },
  {
    source: String.raw`clientSecret\s*[:=]\s*["'][^"']{8,}`,
    flags: 'i',
    label: 'Client secret',
  },
  {
    // GUID format: 8-4-4-4-12 hex chars separated by hyphens = 36 chars
    source: String.raw`tenant[_\-]?id\s*[:=]\s*["'][0-9a-f\-]{36}`,
    flags: 'i',
    label: 'Tenant ID',
  },
  {
    source: String.raw`application[_\-]?id\s*[:=]\s*["'][0-9a-f\-]{36}`,
    flags: 'i',
    label: 'Application ID',
  },

  // Azure connection string fragments
  {
    source: String.raw`AccountKey=[a-zA-Z0-9+/=]{20,}`,
    flags: '',
    label: 'Azure Storage account key',
  },
  {
    source: String.raw`SharedAccessKey=[a-zA-Z0-9+/=]{20,}`,
    flags: '',
    label: 'Azure SAS key',
  },

  // Private key PEM headers
  {
    source: String.raw`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`,
    flags: '',
    label: 'Private key',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isExcludedFile(filePath: string): boolean {
  return EXCLUDED_SUFFIXES.some(s => filePath.endsWith(s));
}

function isSafeLine(line: string): boolean {
  return SAFE_SUBSTRINGS.some(sub => line.includes(sub));
}

// ---------------------------------------------------------------------------
// Rule implementation
// ---------------------------------------------------------------------------

const pac001: ScanRule = {
  id: PAC001_ID,
  name: PAC001_NAME,
  severity: SEVERITY,

  run(files: ScannedFile[], _snapshot: EnvironmentSnapshot): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      try {
        if (isExcludedFile(file.path)) continue;

        let inBlockComment = false;
        // Deduplicate: skip if another pattern already reported the same position
        const reportedPositions = new Set<string>();

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];

          // Skip comment lines and track block comment state
          const [skip, nextState] = checkCommentState(line, inBlockComment);
          inBlockComment = nextState;
          if (skip) continue;

          // Skip lines that access values from env vars (safe patterns)
          if (isSafeLine(line)) continue;

          // Test each secret pattern — report first match per pattern per line,
          // but only if that (line, column) hasn't already been reported by
          // a different pattern (avoids duplicate findings for overlapping regexes).
          for (const { source, flags, label } of SECRET_PATTERNS) {
            const re = new RegExp(source, flags ? `${flags}g` : 'g');
            const match = re.exec(line);
            if (match !== null) {
              const posKey = `${i + 1}:${match.index + 1}`;
              if (reportedPositions.has(posKey)) continue;
              reportedPositions.add(posKey);

              findings.push({
                rule_id: PAC001_ID,
                severity: SEVERITY,
                file: file.path,
                line: i + 1,
                column: match.index + 1,
                message: `Hardcoded ${label} detected`,
                remediation: REMEDIATION,
                code_snippet: buildSnippet(file.lines, i),
              });
            }
          }
        }
      } catch (err) {
        findings.push(makeParseErrorFinding(PAC001_ID, file.path, err));
      }
    }

    return findings;
  },
};

export default pac001;
