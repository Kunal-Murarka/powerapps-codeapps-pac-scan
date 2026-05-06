import type { ScanRule, ScannedFile, Finding } from './base.js';
import { buildSnippet, makeParseErrorFinding, checkCommentState } from './base.js';
import type { EnvironmentSnapshot } from '../snapshot/schema.js';

export const PAC004_ID = 'PAC004' as const;
export const PAC004_NAME = 'CSP policy violation';

const REMEDIATION =
  "This pattern violates the Content Security Policy enforced by your Power Platform " +
  "managed environment. The app will fail silently at runtime. " +
  "Use Power Platform approved patterns instead.";

// ---------------------------------------------------------------------------
// A) Source-code patterns — eval / dynamic script injection
// ---------------------------------------------------------------------------

interface CodePattern {
  source: string;
  flags: string;
  message: string;
}

const CODE_PATTERNS: CodePattern[] = [
  // document.createElement('script') or document.createElement("script")
  {
    source: String.raw`document\.createElement\s*\(\s*["'` + '`' + String.raw`]script["'` + '`' + String.raw`]\s*\)`,
    flags: 'i',
    message: "Dynamic script element creation violates CSP 'unsafe-inline' restriction",
  },
  // eval(...)
  {
    source: String.raw`\beval\s*\(`,
    flags: '',
    message: "eval() violates CSP 'unsafe-eval' restriction",
  },
  // new Function(...)
  {
    source: String.raw`\bnew\s+Function\s*\(`,
    flags: '',
    message: "new Function() violates CSP 'unsafe-eval' restriction",
  },
  // innerHTML = "..." where the value contains "<script"
  {
    source: String.raw`\.innerHTML\s*[+]?=\s*["'` + '`' + String.raw`][^"'` + '`' + String.raw`]*<script`,
    flags: 'i',
    message: "innerHTML assignment with <script> content violates CSP 'unsafe-inline' restriction",
  },
  // dangerouslySetInnerHTML={{ __html: "...script..." }}
  {
    source: String.raw`dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:`,
    flags: '',
    message: "dangerouslySetInnerHTML may inject inline scripts — verify content does not contain <script> tags",
  },
  // setTimeout/setInterval with a string argument (treated as eval)
  {
    source: String.raw`\bset(?:Timeout|Interval)\s*\(\s*["']`,
    flags: '',
    message: "Passing a string to setTimeout/setInterval uses implicit eval — violates CSP 'unsafe-eval'",
  },
];

// ---------------------------------------------------------------------------
// B) iframe src extraction
// ---------------------------------------------------------------------------

// Extracts the src value from <iframe src="..."> or <IFrame src="...">
const RE_IFRAME_SRC_STRING = /<iframe[^>]+\bsrc\s*=\s*["'](https?:\/\/[^"'\s]+)["']/gi;

// ---------------------------------------------------------------------------
// C) vite.config CSP header parsing
// ---------------------------------------------------------------------------

// Three quote-specific regexes so the character class never prematurely
// terminates on interior quotes (e.g. 'self' inside a double-quoted value).
const RE_VITE_CSP_DQ = /['"]Content-Security-Policy['"]\s*:\s*"([^"]+)"/gi;
const RE_VITE_CSP_SQ = /['"]Content-Security-Policy['"]\s*:\s*'([^']+)'/gi;
const RE_VITE_CSP_BT = /['"]Content-Security-Policy['"]\s*:\s*`([^`]+)`/gi;

// ---------------------------------------------------------------------------
// Domain allowlist helpers (shared with PAC002 logic, inlined here)
// ---------------------------------------------------------------------------

function extractHostname(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    const m = rawUrl.match(/^https?:\/\/([^/?#\s]+)/i);
    return m ? m[1].toLowerCase() : null;
  }
}

function isAllowedFrameAncestor(hostname: string, patterns: string[]): boolean {
  for (const raw of patterns) {
    const hostPart = raw
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .toLowerCase();
    if (!hostPart) continue;
    if (hostPart.startsWith('*.')) {
      const base = hostPart.slice(2);
      if (hostname === base || hostname.endsWith(`.${base}`)) return true;
    } else {
      if (hostname === hostPart) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// D) vite.config directive comparison
// ---------------------------------------------------------------------------

/**
 * Parses a CSP header string into a map of directive → value tokens.
 * e.g. "default-src 'self'; script-src 'self' 'unsafe-inline'"
 * → { 'default-src': ["'self'"], 'script-src': ["'self'", "'unsafe-inline'"] }
 */
function parseCspHeader(header: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const clause of header.split(';')) {
    const parts = clause.trim().split(/\s+/);
    if (parts.length < 1 || !parts[0]) continue;
    map.set(parts[0].toLowerCase(), parts.slice(1));
  }
  return map;
}

const PERMISSIVE_TOKENS = new Set([
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'unsafe-hashes'",
  'data:',
  '*',
  'http:',
  'https:',
]);

/**
 * Returns true when the vite CSP directive is more permissive than allowed.
 * "More permissive" = contains a token the snapshot directive does not allow,
 * or contains a wildcard/unsafe token.
 */
function isMorePermissive(viteSrcTokens: string[], snapshotTokens: string[]): boolean {
  const snapshotSet = new Set(snapshotTokens.map(t => t.toLowerCase()));
  for (const tok of viteSrcTokens) {
    const lower = tok.toLowerCase();
    if (PERMISSIVE_TOKENS.has(lower) && !snapshotSet.has(lower)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

const VITE_CONFIG_NAMES = new Set(['vite.config.ts', 'vite.config.js', 'vite.config.mts', 'vite.config.mjs']);
const HTML_NAMES = new Set(['index.html']);

const pac004: ScanRule = {
  id: PAC004_ID,
  name: PAC004_NAME,
  severity: 'MEDIUM',

  run(files: ScannedFile[], snapshot: EnvironmentSnapshot): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      // Determine what kind of file this is
      const basename = file.path.split(/[\\/]/).pop() ?? '';
      const isViteConfig = VITE_CONFIG_NAMES.has(basename);
      const isHtml = HTML_NAMES.has(basename) || file.path.endsWith('.html');
      const isSourceFile = !isViteConfig && !isHtml;

      try {
        // ── A) Scan source files for eval / dynamic script patterns ────────
        if (isSourceFile) {
          let inBlockComment = false;

          for (let i = 0; i < file.lines.length; i++) {
            const line = file.lines[i];
            const [skip, nextState] = checkCommentState(line, inBlockComment);
            inBlockComment = nextState;
            if (skip) continue;

            const reported = new Set<string>();

            for (const { source, flags, message } of CODE_PATTERNS) {
              const re = new RegExp(source, flags ? `${flags}g` : 'g');
              for (const match of line.matchAll(re)) {
                const col = (match.index ?? 0) + 1;
                const posKey = `${i}:${col}`;
                if (reported.has(posKey)) continue;
                reported.add(posKey);

                findings.push({
                  rule_id: PAC004_ID,
                  severity: 'HIGH',
                  file: file.path,
                  line: i + 1,
                  column: col,
                  message,
                  remediation: REMEDIATION,
                  code_snippet: buildSnippet(file.lines, i),
                });
              }
            }
          }
        }

        // ── B) HTML: iframe src domain checks ──────────────────────────────
        if (isHtml) {
          for (let i = 0; i < file.lines.length; i++) {
            const line = file.lines[i];
            RE_IFRAME_SRC_STRING.lastIndex = 0;
            for (const match of line.matchAll(RE_IFRAME_SRC_STRING)) {
              const url = match[1];
              if (!url) continue;
              const hostname = extractHostname(url);
              if (!hostname) continue;

              if (!isAllowedFrameAncestor(hostname, snapshot.csp.frame_ancestors)) {
                findings.push({
                  rule_id: PAC004_ID,
                  severity: 'HIGH',
                  file: file.path,
                  line: i + 1,
                  column: (match.index ?? 0) + 1,
                  message:
                    `iframe src domain "${hostname}" is not in snapshot csp.frame_ancestors`,
                  remediation: REMEDIATION,
                  code_snippet: buildSnippet(file.lines, i),
                });
              }
            }
          }
        }

        // ── C) vite.config: CSP header directive comparison ─────────────────
        if (isViteConfig) {
          // Map snapshot CSP directives for comparison
          const snapshotDirectives = new Map<string, string[]>([
            ['connect-src', snapshot.csp.connect_src],
            ['script-src',  snapshot.csp.script_src],
            ['frame-ancestors', snapshot.csp.frame_ancestors],
          ]);

          const viteREs = [RE_VITE_CSP_DQ, RE_VITE_CSP_SQ, RE_VITE_CSP_BT];

          for (let i = 0; i < file.lines.length; i++) {
            const line = file.lines[i];

            for (const re of viteREs) {
              re.lastIndex = 0;
              for (const match of line.matchAll(re)) {
                const cspValue = match[1];
                if (!cspValue) continue;
                const viteParsed = parseCspHeader(cspValue);

                for (const [directive, snapshotTokens] of snapshotDirectives) {
                  const viteTokens = viteParsed.get(directive);
                  if (!viteTokens) continue;

                  if (isMorePermissive(viteTokens, snapshotTokens)) {
                    findings.push({
                      rule_id: PAC004_ID,
                      severity: 'MEDIUM',
                      file: file.path,
                      line: i + 1,
                      column: (match.index ?? 0) + 1,
                      message:
                        `vite.config CSP directive "${directive}" is more permissive than ` +
                        `snapshot allows — your local dev CSP will not match the managed environment`,
                      remediation: REMEDIATION,
                      code_snippet: buildSnippet(file.lines, i),
                    });
                  }
                }
              }
            }
          }
        }
      } catch (err) {
        findings.push(makeParseErrorFinding(PAC004_ID, file.path, err));
      }
    }

    return findings;
  },
};

export default pac004;
