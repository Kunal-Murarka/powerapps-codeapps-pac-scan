import { readFileSync, existsSync } from 'node:fs';
import { resolve, relative, join } from 'node:path';
import { glob } from 'glob';
import type { ScannedFile } from '../rules/base.js';

// ---------------------------------------------------------------------------
// .gitignore helper (best-effort, offline)
// ---------------------------------------------------------------------------

/**
 * Reads `.gitignore` from `projectDir` and returns a Set of normalised
 * patterns. We do a very lightweight parse — enough to skip common patterns
 * like `node_modules/`, `dist/`, etc. The glob `ignore` option handles
 * most of the heavy lifting.
 */
function readGitignorePatterns(projectDir: string): string[] {
  const gitignorePath = join(projectDir, '.gitignore');
  if (!existsSync(gitignorePath)) return [];

  try {
    const content = readFileSync(gitignorePath, 'utf-8');
    return content
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface FileWalkerOptions {
  /** Absolute path to the root of the project being scanned. */
  projectDir: string;
  /** Sub-directories to scan, relative to projectDir (e.g. ['src']). */
  scanPaths: string[];
  /** File extensions to include (e.g. ['.ts', '.tsx', '.js', '.jsx']). */
  extensions: string[];
  /** Glob patterns to exclude (relative to projectDir). */
  excludePatterns: string[];
  /** Whether to also include index.html and vite.config.* files. */
  includeConfigFiles?: boolean;
}

/**
 * Walks the project directory and returns all matching source files,
 * pre-loaded with their content and split into lines.
 *
 * Never throws — files that fail to read are silently skipped
 * (the scanner will not produce findings for them).
 */
export async function walkFiles(opts: FileWalkerOptions): Promise<ScannedFile[]> {
  const {
    projectDir,
    scanPaths,
    extensions,
    excludePatterns,
    includeConfigFiles = true,
  } = opts;

  const gitignorePatterns = readGitignorePatterns(projectDir);

  // Build glob patterns: one pattern per scan-path × extension
  const extGlob = extensions.length === 1
    ? extensions[0].replace(/^\./, '')
    : `{${extensions.map(e => e.replace(/^\./, '')).join(',')}}`;

  const patterns = scanPaths.map(p => `${p}/**/*.${extGlob}`);

  // Also always scan package.json (for PAC005) and config files (PAC004)
  if (includeConfigFiles) {
    patterns.push('package.json');
    patterns.push('index.html');
    patterns.push('vite.config.{ts,js,mts,mjs}');
  }

  const ignore = [
    ...excludePatterns,
    ...gitignorePatterns,
    // Always exclude these regardless of config
    '**/node_modules/**',
    '**/dist/**',
    '**/.pac-scan/**',
  ];

  let relativePaths: string[] = [];
  try {
    relativePaths = await glob(patterns, {
      cwd: projectDir,
      ignore,
      nodir: true,
      posix: true,   // use forward slashes on all platforms
    });
  } catch {
    // glob failure is non-fatal; return empty
    return [];
  }

  // Sort for deterministic ordering (important for reproducible reports)
  relativePaths.sort();

  const files: ScannedFile[] = [];

  for (const relPath of relativePaths) {
    const absPath = resolve(projectDir, relPath);
    // Use the path relative to projectDir for display and deduplication
    const displayPath = relative(projectDir, absPath).replace(/\\/g, '/');

    try {
      const raw = readFileSync(absPath, 'utf-8');
      const content = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      files.push({
        path: displayPath,
        content,
        lines: content.split('\n'),
      });
    } catch {
      // Unreadable file — skip silently
    }
  }

  return files;
}

