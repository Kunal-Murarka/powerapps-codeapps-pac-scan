#!/usr/bin/env node
/**
 * pac-scan — Security scanner for Power Apps Code Apps (React+Vite).
 *
 * Catches CSP and DLP policy violations at build time so they are never
 * discovered at runtime inside the Power Apps Player sandbox.
 *
 * All analysis runs fully OFFLINE — no external network calls, no telemetry,
 * no data leaves the enterprise boundary.
 */
import { Command } from 'commander';
import { fetchCommand } from './commands/fetch.js';
import { runCommand } from './commands/run.js';
import { diffCommand } from './commands/diff.js';
import { policyCommand } from './commands/policy.js';
import { validateCommand } from './commands/validate.js';

const program = new Command();

program
  .name('pac-scan')
  .description(
    'Offline security scanner for Power Apps Code Apps.\n' +
    'Detects CSP and DLP violations before they reach the Power Apps Player sandbox.'
  )
  .version('0.1.0');

program.addCommand(fetchCommand());
program.addCommand(runCommand());
program.addCommand(diffCommand());
program.addCommand(policyCommand());
program.addCommand(validateCommand());

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error('Fatal:', (err as Error).message ?? err);
  process.exit(1);
});
