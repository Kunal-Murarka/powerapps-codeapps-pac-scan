import type { Severity, EnvironmentSnapshot } from '../snapshot/schema.js';

/**
 * A source file to be scanned, pre-loaded by the file walker.
 */
export interface ScannedFile {
  /** Path relative to the project root (e.g. `src/components/App.tsx`). */
  path: string;
  /** Raw file content as a UTF-8 string (line endings normalised to \n). */
  content: string;
  /** `content` split on `\n` — no trailing `\r` on each element. */
  lines: string[];
}

/**
 * A single scan finding produced by a rule.
 */
export interface Finding {
  rule_id: string;
  severity: Severity;
  /** Relative file path from project root. */
  file: string;
  /** 1-based line number. 0 = whole-file finding (e.g. parse error). */
  line: number;
  /** 1-based column number. 0 = whole-file finding. */
  column: number;
  message: string;
  remediation: string;
  /**
   * The offending line plus one line of context before and after,
   * formatted like:
   *   42 | const prev = ...;
   * > 43 | const apiKey = "abc...";
   *   44 | doSomething(apiKey);
   */
  code_snippet: string;
}

/**
 * Contract every scan rule must implement.
 */
export interface ScanRule {
  id: string;
  name: string;
  severity: Severity;
  run(files: ScannedFile[], snapshot: EnvironmentSnapshot): Finding[];
}

// ---------------------------------------------------------------------------
// Shared helpers used by rule implementations
// ---------------------------------------------------------------------------

/**
 * Builds a 3-line code snippet centred on `lineIdx` (0-based).
 */
export function buildSnippet(lines: string[], lineIdx: number): string {
  const num = lineIdx + 1;
  const parts: string[] = [];
  if (lineIdx > 0)
    parts.push(`  ${num - 1} | ${lines[lineIdx - 1]}`);
  parts.push(`> ${num} | ${lines[lineIdx]}`);
  if (lineIdx < lines.length - 1)
    parts.push(`  ${num + 1} | ${lines[lineIdx + 1]}`);
  return parts.join('\n');
}

/**
 * Creates a LOW-severity whole-file finding for unexpected parse/runtime errors.
 */
export function makeParseErrorFinding(
  ruleId: string,
  filePath: string,
  err: unknown,
): Finding {
  return {
    rule_id: ruleId,
    severity: 'LOW',
    file: filePath,
    line: 0,
    column: 0,
    message: `File could not be parsed: ${(err as Error).message ?? String(err)}`,
    remediation: '',
    code_snippet: '',
  };
}

/**
 * Returns true when `line` is inside a block comment or is a single-line
 * comment line. Updates `inBlockComment` state and returns it.
 *
 * Call this before checking any patterns; if it returns true, skip the line.
 *
 * @param line              The raw source line.
 * @param inBlockCommentIn  Whether we entered this line inside a `/ * … * /` block.
 * @returns `[skip, newInBlockComment]`
 */
export function checkCommentState(
  line: string,
  inBlockCommentIn: boolean,
): [skip: boolean, newState: boolean] {
  let inBlock = inBlockCommentIn;

  if (inBlock) {
    if (line.includes('*/')) inBlock = false;
    return [true, inBlock];
  }

  // Opening a block comment on this line — skip the whole line
  const openIdx = line.indexOf('/*');
  if (openIdx !== -1) {
    const closeIdx = line.indexOf('*/', openIdx + 2);
    if (closeIdx === -1) inBlock = true; // extends past this line
    return [true, inBlock];
  }

  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
    return [true, inBlock];
  }

  return [false, inBlock];
}
