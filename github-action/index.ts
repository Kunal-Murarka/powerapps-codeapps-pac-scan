import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as path from 'node:path';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
  try {
    const command        = core.getInput('command')           || 'run';
    const environment    = core.getInput('environment')       || 'prod';
    const failOnSeverity = core.getInput('fail-on-severity')  || 'HIGH';
    const outputPath     = core.getInput('output-path')       || './pac-scan-report.json';

    // Resolve and publish the report path before the scan runs — so it's
    // always available even when the step exits with a failure code.
    const resolvedReportPath = path.resolve(outputPath);
    core.setOutput('report-path', resolvedReportPath);

    // Build CLI arguments
    const args: string[] = [command, '--env', environment];

    if (command === 'run') {
      args.push('--fail-on', failOnSeverity);
      args.push('--output', outputPath);
    }

    core.info(`Running: pac-scan ${args.join(' ')}`);

    // exec streams stdout/stderr to the Actions log automatically.
    // ignoreReturnCode: true lets us handle the exit code manually so we
    // can set the 'result' output before failing the step.
    const exitCode = await exec.exec('pac-scan', args, {
      ignoreReturnCode: true,
    });

    if (command === 'run') {
      const result = exitCode === 0 ? 'PASS' : 'FAIL';
      core.setOutput('result', result);

      if (exitCode !== 0) {
        core.setFailed(
          `pac-scan found security violations (exit code ${exitCode}). ` +
          `Review the report at: ${resolvedReportPath}`,
        );
      } else {
        core.info('pac-scan passed — no violations at or above the threshold.');
      }
    } else {
      // fetch command
      core.setOutput('result', exitCode === 0 ? 'PASS' : 'FAIL');

      if (exitCode !== 0) {
        core.setFailed(
          'pac-scan fetch failed. ' +
          'Ensure the pac CLI is installed and the agent is authenticated to Power Platform.',
        );
      } else {
        core.info('Policy snapshot fetched successfully.');
      }
    }
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
}

run();
