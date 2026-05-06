import * as task from 'azure-pipelines-task-lib/task';
import { spawn } from 'node:child_process';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
  try {
    const command        = task.getInput('command', true)       ?? 'run';
    const environment    = task.getInput('environment', true)   ?? 'prod';
    const failOnSeverity = task.getInput('failOnSeverity')      ?? 'HIGH';
    const outputPath     = task.getInput('outputPath')          ??
      (process.env['BUILD_ARTIFACTSTAGINGDIRECTORY'] ?? '.');

    // Publish the variable early so downstream tasks can reference it even
    // if the scan step itself fails (condition: always()).
    task.setVariable('PacScanReportPath', outputPath);

    // Build CLI arguments
    const args: string[] = [command, '--env', environment];

    if (command === 'run') {
      args.push('--fail-on', failOnSeverity);
      args.push('--output', outputPath);
    }

    task.debug(`Running: pac-scan ${args.join(' ')}`);

    const exitCode = await spawnAsync('pac-scan', args);

    if (exitCode === 0) {
      task.setResult(task.TaskResult.Succeeded, 'pac-scan passed');
    } else {
      task.setResult(
        task.TaskResult.Failed,
        `pac-scan found security violations — see report at: ${outputPath}`,
      );
    }
  } catch (err) {
    task.setResult(
      task.TaskResult.Failed,
      err instanceof Error ? err.message : String(err),
    );
  }
}

// ---------------------------------------------------------------------------
// Process spawner — streams stdout/stderr directly to the pipeline console
// ---------------------------------------------------------------------------

function spawnAsync(bin: string, args: string[]): Promise<number> {
  return new Promise((resolve) => {
    const proc = spawn(bin, args, {
      // shell:true is required on Windows agents to execute .cmd wrappers
      shell: process.platform === 'win32',
      // 'inherit' passes stdout/stderr straight to the Azure Pipelines log
      stdio: 'inherit',
    });

    proc.on('error', (err) => {
      const isNotFound = (err as NodeJS.ErrnoException).code === 'ENOENT';
      if (isNotFound) {
        task.error(
          'pac-scan CLI not found on PATH.\n' +
          'Add a step before this task to install it:\n' +
          '  script: npm install -g pac-scan',
        );
      } else {
        task.error(err.message);
      }
      resolve(1);
    });

    proc.on('close', (code) => resolve(code ?? 1));
  });
}

run();
