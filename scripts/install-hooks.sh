#!/usr/bin/env bash
# install-hooks.sh — Installs the pac-scan pre-commit git hook (Unix/macOS)
#
# Usage:
#   bash scripts/install-hooks.sh
#
# Run from the root of the repository that contains the Power Apps Code App.
# The hook calls "pac-scan run --env dev" before every commit.

set -e

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [ ! -d ".git" ]; then
  echo "Error: No .git directory found."
  echo "       Run this script from the root of a git repository."
  exit 1
fi

if [ -f "$HOOK_FILE" ]; then
  echo "⚠  Pre-commit hook already exists at: $HOOK_FILE"
  read -r -p "   Overwrite? [y/N] " confirm
  case "$confirm" in
    [yY][eE][sS]|[yY]) ;;
    *) echo "   Aborted."; exit 0 ;;
  esac
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK_FILE" << 'HOOK_CONTENT'
#!/bin/sh
echo "🔍 pac-scan: Running Power Apps security scan..."

pac-scan run --env dev --output .pac-scan/last-commit-reports

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ pac-scan FAILED — commit blocked"
  echo "   Fix the issues above, then commit again."
  echo "   Full report: .pac-scan/last-commit-reports/"
  echo ""
  exit 1
fi

echo "✅ pac-scan PASSED — proceeding with commit"
exit 0
HOOK_CONTENT

chmod +x "$HOOK_FILE"

echo "✅ pac-scan pre-commit hook installed at: $HOOK_FILE"
echo ""
echo "   The hook runs: pac-scan run --env dev"
echo "   To skip (emergency only): git commit --no-verify"
