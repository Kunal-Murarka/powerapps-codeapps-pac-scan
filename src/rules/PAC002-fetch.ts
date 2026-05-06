import type { ScanRule, ScannedFile, Finding } from './base.js';
import { buildSnippet, makeParseErrorFinding, checkCommentState } from './base.js';
import type { EnvironmentSnapshot } from '../snapshot/schema.js';

export const PAC002_ID = 'PAC002' as const;
export const PAC002_NAME = 'Raw fetch to non-whitelisted domain';

const SEVERITY_STATIC  = 'HIGH'   as const;
const SEVERITY_DYNAMIC = 'MEDIUM' as const;

const REMEDIATION =
  "Direct network calls bypass Power Platform DLP enforcement. " +
  "Use a registered Power Platform connector instead, or add " +
  "this domain to your environment's HTTP connector endpoint filter URLs.";

// ---------------------------------------------------------------------------
// Exclusion rules
// ---------------------------------------------------------------------------

const EXCLUDED_SUFFIXES = ['.test.ts', '.spec.ts', '.test.tsx', '.spec.tsx'];

const LOCALHOST_NAMES = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

/**
 * Patterns that detect a network call containing a hard-coded URL string
 * literal. Capture group 1 is always the URL itself.
 *
 * Rules:
 *  - fetch("url") / fetch('url')
 *  - fetch(`url`)  — plain backtick template with no ${…} interpolation
 *  - axios.<method>("url") / axios.<method>('url')
 *  - axios.<method>(`url`) — plain backtick
 *  - xhr.open("METHOD", "url")
 */
interface StaticPattern {
  source: string;
  label: string;
}

// Note: backtick (`) inside a regex literal is a plain character — no escaping needed.
// Character class [^`\s$] = not-backtick, not-whitespace, not-dollar-sign.
const STATIC_PATTERNS: StaticPattern[] = [
  // fetch("https://...") or fetch('https://...')
  {
    source: String.raw`\bfetch\s*\(\s*["'](https?://[^"'\s]+)["']`,
    label: 'fetch()',
  },
  // fetch(`https://...`) — no interpolation (no ${ present before closing `)
  {
    source: String.raw`\bfetch\s*\(\s*` + '`' + String.raw`(https?://[^` + '`' + String.raw`\s$][^` + '`' + String.raw`$]*)` + '`',
    label: 'fetch()',
  },
  // axios.get/post/put/patch/delete/head/request("https://...")
  {
    source: String.raw`\baxios\s*\.\s*\w+\s*\(\s*["'](https?://[^"'\s]+)["']`,
    label: 'axios',
  },
  // axios.method(`https://...`) — no interpolation
  {
    source: String.raw`\baxios\s*\.\s*\w+\s*\(\s*` + '`' + String.raw`(https?://[^` + '`' + String.raw`\s$][^` + '`' + String.raw`$]*)` + '`',
    label: 'axios',
  },
  // new XMLHttpRequest() ... xhr.open("GET", "https://...")
  {
    source: String.raw`\.open\s*\(\s*["']\w+["']\s*,\s*["'](https?://[^"'\s]+)["']`,
    label: 'XMLHttpRequest.open()',
  },
];

/**
 * Patterns that detect a network call whose URL argument is a variable or
 * interpolated template literal (i.e. we cannot statically evaluate the URL).
 * These produce MEDIUM-severity findings with a "verify" message.
 */
interface DynamicPattern {
  source: string;
  label: string;
}

const DYNAMIC_PATTERNS: DynamicPattern[] = [
  // fetch(variable) — argument is an identifier, not a string/template literal
  // Exclude: starts with quote, backtick, or the 'new' keyword
  {
    source: String.raw`\bfetch\s*\(\s*(?!["'` + '`' + String.raw`]|new[\s(])([\w$][\w$.]*)`,
    label: 'fetch()',
  },
  // fetch(`...${...}`) — template literal with interpolation
  {
    source: String.raw`\bfetch\s*\(\s*` + '`' + '[^`]*\\${',
    label: 'fetch()',
  },
  // axios.method(variable)
  {
    source: String.raw`\baxios\s*\.\s*\w+\s*\(\s*(?!["'` + '`' + String.raw`]|new[\s(])([\w$][\w$.]*)`,
    label: 'axios',
  },
  // axios.method(`...${...}`)
  {
    source: String.raw`\baxios\s*\.\s*\w+\s*\(\s*` + '`' + '[^`]*\\${',
    label: 'axios',
  },
];

// ---------------------------------------------------------------------------
// Domain / allowlist helpers
// ---------------------------------------------------------------------------

function extractHostname(rawUrl: string): string | null {
  // Ensure URL has a scheme so URL() can parse it
  const withScheme = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
  try {
    return new URL(withScheme).hostname.toLowerCase();
  } catch {
    // Fall back to a simple regex extraction
    const m = rawUrl.match(/^https?:\/\/([^/?#\s]+)/i);
    return m ? m[1].toLowerCase() : null;
  }
}

/**
 * Returns true when `hostname` is matched by one of `allowedPatterns`.
 *
 * Pattern formats accepted:
 *  - `https://*.microsoft.com`  (wildcard subdomain)
 *  - `*.microsoft.com`          (wildcard without scheme)
 *  - `api.microsoft.com`        (exact hostname)
 *  - `https://api.microsoft.com` (exact with scheme)
 */
function isAllowedDomain(hostname: string, allowedPatterns: string[]): boolean {
  for (const raw of allowedPatterns) {
    if (!raw) continue;

    // Strip scheme and trailing path to get the host pattern
    const hostPart = raw
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .toLowerCase();

    if (!hostPart) continue;

    if (hostPart.startsWith('*.')) {
      // *.microsoft.com → match microsoft.com itself and any subdomain
      const base = hostPart.slice(2); // 'microsoft.com'
      if (hostname === base || hostname.endsWith(`.${base}`)) return true;
    } else {
      if (hostname === hostPart) return true;
    }
  }
  return false;
}

function isLocalhost(hostname: string): boolean {
  return LOCALHOST_NAMES.has(hostname) || hostname.endsWith('.localhost');
}

// ---------------------------------------------------------------------------
// Allowlist builder
// ---------------------------------------------------------------------------

/**
 * Builds the combined URL allowlist from the snapshot:
 *  - CSP connect-src directives
 *  - Per-connector endpoint filter URLs
 */
function buildAllowlist(snapshot: EnvironmentSnapshot): string[] {
  return [
    ...snapshot.csp.connect_src,
    ...snapshot.connectors.flatMap(c => c.endpoint_filter_urls),
  ];
}

// ---------------------------------------------------------------------------
// Rule implementation
// ---------------------------------------------------------------------------

const pac002: ScanRule = {
  id: PAC002_ID,
  name: PAC002_NAME,
  severity: SEVERITY_STATIC,

  run(files: ScannedFile[], snapshot: EnvironmentSnapshot): Finding[] {
    const findings: Finding[] = [];
    const allowlist = buildAllowlist(snapshot);

    for (const file of files) {
      try {
        if (EXCLUDED_SUFFIXES.some(s => file.path.endsWith(s))) continue;

        let inBlockComment = false;

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];

          // Skip comment lines, track block comment state
          const [skip, nextState] = checkCommentState(line, inBlockComment);
          inBlockComment = nextState;
          if (skip) continue;

          // ── Static URL patterns ──────────────────────────────────────────
          for (const { source, label } of STATIC_PATTERNS) {
            const re = new RegExp(source, 'gi');
            for (const match of line.matchAll(re)) {
              const url = match[1];
              if (!url) continue;

              // Skip relative URLs (shouldn't happen given the regex, but be safe)
              if (!url.startsWith('http')) continue;

              const hostname = extractHostname(url);
              if (!hostname) continue;
              if (isLocalhost(hostname)) continue;

              if (!isAllowedDomain(hostname, allowlist)) {
                findings.push({
                  rule_id: PAC002_ID,
                  severity: SEVERITY_STATIC,
                  file: file.path,
                  line: i + 1,
                  column: (match.index ?? 0) + 1,
                  message:
                    `${label} call to non-whitelisted domain: ${hostname} ` +
                    `— not in csp.connect_src or connector endpoint_filter_urls`,
                  remediation: REMEDIATION,
                  code_snippet: buildSnippet(file.lines, i),
                });
              }
            }
          }

          // ── Dynamic URL patterns ─────────────────────────────────────────
          for (const { source, label } of DYNAMIC_PATTERNS) {
            const re = new RegExp(source, 'gi');
            for (const match of line.matchAll(re)) {
              findings.push({
                rule_id: PAC002_ID,
                severity: SEVERITY_DYNAMIC,
                file: file.path,
                line: i + 1,
                column: (match.index ?? 0) + 1,
                message:
                  `Dynamic URL in ${label} — verify it resolves to a whitelisted domain`,
                remediation: REMEDIATION,
                code_snippet: buildSnippet(file.lines, i),
              });
            }
          }
        }
      } catch (err) {
        findings.push(makeParseErrorFinding(PAC002_ID, file.path, err));
      }
    }

    return findings;
  },
};

export default pac002;
