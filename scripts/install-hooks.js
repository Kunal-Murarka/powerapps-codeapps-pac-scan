#!/usr/bin/env node
/**
 * install-hooks.js — Cross-platform Node.js installer for the pac-scan
 * pre-commit git hook.
 *
 * Usage:
 *   node scripts/install-hooks.js
 *   npm run install-hooks
 *
 * Works on Windows, macOS, and Linux.
 * Writes the hook with LF line endings so sh.exe on Windows can execute it.
 */

import { existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createInterface } from 'node:readline';

const GIT_DIR  = resolve('.git');
const HOOK_DIR  = join(GIT_DIR, 'hooks');
const HOOK_FILE = join(HOOK_DIR, 'pre-commit');

// ---------------------------------------------------------------------------
// Validate we are inside a git repository
// ---------------------------------------------------------------------------
if (!existsSync(GIT_DIR)) {
  console.error('Error: No .git directory found.');
  console.error('       Run this script from the root of a git repository.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Hook file content — MUST use LF line endings (sh.exe on Windows requires it)
// ---------------------------------------------------------------------------
const HOOK_CONTENT = [
  '#!/bin/sh',
  'echo "🔍 pac-scan: Running Power Apps security scan..."',
  '',
  'pac-scan run --env dev --output .pac-scan/last-commit-reports',
  '',
  'EXIT_CODE=$?',
  '',
  'if [ $EXIT_CODE -ne 0 ]; then',
  '  echo ""',
  '  echo "❌ pac-scan FAILED — commit blocked"',
  '  echo "   Fix the issues above, then commit again."',
  '  echo "   Full report: .pac-scan/last-commit-reports/"',
  '  echo ""',
  '  exit 1',
  'fi',
  '',
  'echo "✅ pac-scan PASSED — proceeding with commit"',
  'exit 0',
  '',
].join('\n');   // LF only — intentional

// ---------------------------------------------------------------------------
// Install (optionally prompting before overwrite)
// ---------------------------------------------------------------------------
async function install() {
  if (existsSync(HOOK_FILE)) {
    const overwrite = await prompt('⚠  Pre-commit hook already exists. Overwrite? [y/N] ');
    if (!/^[yY]/.test(overwrite)) {
      console.log('   Aborted.');
      return;
    }
  }

  mkdirSync(HOOK_DIR, { recursive: true });
  writeFileSync(HOOK_FILE, HOOK_CONTENT, { encoding: 'utf-8' });

  // Make executable on Unix/macOS — no-op on Windows (git handles it)
  if (process.platform !== 'win32') {
    try { chmodSync(HOOK_FILE, 0o755); } catch { /* ignore */ }
  }

  console.log(`✅ pac-scan pre-commit hook installed at: ${HOOK_FILE}`);
  console.log('');
  console.log('   The hook runs: pac-scan run --env dev');
  console.log('   To skip (emergency only): git commit --no-verify');
}

function prompt(question) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => { rl.close(); resolve(answer); });
  });
}

install().catch((err) => {
  console.error('Error:', err.message ?? err);
  process.exit(1);
});
