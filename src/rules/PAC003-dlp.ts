import type { ScanRule, ScannedFile, Finding } from './base.js';
import { buildSnippet, makeParseErrorFinding, checkCommentState } from './base.js';
import type { EnvironmentSnapshot, DlpPolicy } from '../snapshot/schema.js';

export const PAC003_ID = 'PAC003' as const;
export const PAC003_NAME = 'DLP connector violation';

// ---------------------------------------------------------------------------
// Connector reference patterns
// ---------------------------------------------------------------------------

/**
 * Captures the npm package import style:
 *   import { ... } from "@microsoft/powerplatform-connector-sharepointonline"
 * Capture group 1: everything after the final '-' (the connector name fragment).
 * We normalise further in code.
 */
const RE_IMPORT = /from\s+["']@microsoft\/powerplatform-connector-([a-z0-9_-]+)["']/gi;

/**
 * Captures property assignment / object-literal style:
 *   connectorName: "shared_twitter"
 *   connector: "shared_dropbox"
 * Capture group 1: the raw value including potential "shared_" prefix.
 */
const RE_PROP = /\bconnector(?:Name)?\s*[:=]\s*["']([a-z0-9_-]+)["']/gi;

/**
 * Captures the useConnector hook:
 *   useConnector("shared_gmail")
 *   useConnector('shared_googlesheets')
 * Capture group 1: the raw connector string.
 */
const RE_HOOK = /\buseConnector\s*\(\s*["']([a-z0-9_-]+)["']\s*\)/gi;

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

/** Strips the "shared_" prefix and lowercases. */
function normalise(raw: string): string {
  return raw.toLowerCase().replace(/^shared_/, '');
}

// ---------------------------------------------------------------------------
// DLP classification index
// ---------------------------------------------------------------------------

type DlpClass = 'blocked' | 'non_business' | 'business' | 'unlisted';

interface ClassResult {
  cls: DlpClass;
  /** The first policy that classified this connector (for remediation text). */
  policy: DlpPolicy | null;
}

function buildClassIndex(policies: DlpPolicy[]): Map<string, ClassResult> {
  const idx = new Map<string, ClassResult>();

  for (const policy of policies) {
    for (const name of policy.connectors.blocked) {
      const key = normalise(name);
      if (!idx.has(key) || idx.get(key)!.cls !== 'blocked') {
        idx.set(key, { cls: 'blocked', policy });
      }
    }
    for (const name of policy.connectors.non_business) {
      const key = normalise(name);
      if (!idx.has(key)) idx.set(key, { cls: 'non_business', policy });
    }
    for (const name of policy.connectors.business) {
      const key = normalise(name);
      if (!idx.has(key)) idx.set(key, { cls: 'business', policy });
    }
  }

  return idx;
}

// ---------------------------------------------------------------------------
// Finding factory
// ---------------------------------------------------------------------------

function makeFinding(
  file: ScannedFile,
  lineIdx: number,
  col: number,
  rawName: string,
  result: ClassResult,
): Finding {
  const normName = normalise(rawName);
  const policyName = result.policy?.name ?? 'unknown policy';

  let severity: Finding['severity'];
  let message: string;
  let remediation: string;

  switch (result.cls) {
    case 'blocked':
      severity = 'CRITICAL';
      message = `Connector "${normName}" is explicitly blocked by DLP policy "${policyName}"`;
      remediation =
        `Connector ${normName} is explicitly blocked by DLP policy ${policyName}. ` +
        `Remove this connector reference.`;
      break;
    case 'non_business':
      severity = 'HIGH';
      message = `Connector "${normName}" is in the non-business tier of DLP policy "${policyName}"`;
      remediation =
        `Connector ${normName} is in the non-business tier of DLP policy ${policyName}. ` +
        `It cannot be used alongside business connectors in the same app.`;
      break;
    default:
      severity = 'MEDIUM';
      message = `Connector "${normName}" is not listed in any DLP policy — it may be blocked at runtime`;
      remediation =
        `Connector ${normName} is not classified in any DLP policy. ` +
        `Verify it is allowed in your target environment before deploying.`;
  }

  return {
    rule_id: PAC003_ID,
    severity,
    file: file.path,
    line: lineIdx + 1,
    column: col,
    message,
    remediation,
    code_snippet: buildSnippet(file.lines, lineIdx),
  };
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

const pac003: ScanRule = {
  id: PAC003_ID,
  name: PAC003_NAME,
  severity: 'HIGH',

  run(files: ScannedFile[], snapshot: EnvironmentSnapshot): Finding[] {
    const findings: Finding[] = [];

    // Nothing to check if no DLP policies in snapshot
    if (snapshot.dlp_policies.length === 0) return findings;

    const classIdx = buildClassIndex(snapshot.dlp_policies);

    for (const file of files) {
      try {
        let inBlockComment = false;

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];

          const [skip, nextState] = checkCommentState(line, inBlockComment);
          inBlockComment = nextState;
          if (skip) continue;

          // Deduplicate per (line, column) to avoid double-reporting when
          // a connector name appears in two patterns on the same line
          const reported = new Set<string>();

          const scanMatch = (re: RegExp, groupIdx: number) => {
            for (const match of line.matchAll(re)) {
              const raw = match[groupIdx];
              if (!raw) continue;
              const col = (match.index ?? 0) + 1;
              const posKey = `${i}:${col}`;
              if (reported.has(posKey)) continue;

              const normName = normalise(raw);
              const result: ClassResult = classIdx.get(normName) ?? { cls: 'unlisted', policy: null };

              // Only report blocked and non_business (high signal).
              // Unlisted (MEDIUM) is intentionally included too.
              if (result.cls === 'business') continue;

              reported.add(posKey);
              findings.push(makeFinding(file, i, col, raw, result));
            }
          };

          // Reset lastIndex because we reuse the global regexes per-line
          RE_IMPORT.lastIndex = 0;
          RE_PROP.lastIndex = 0;
          RE_HOOK.lastIndex = 0;

          scanMatch(RE_IMPORT, 1);
          scanMatch(RE_PROP, 1);
          scanMatch(RE_HOOK, 1);
        }
      } catch (err) {
        findings.push(makeParseErrorFinding(PAC003_ID, file.path, err));
      }
    }

    return findings;
  },
};

export default pac003;
