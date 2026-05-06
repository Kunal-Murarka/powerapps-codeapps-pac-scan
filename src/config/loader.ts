import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import type { PacScanConfig, EnvironmentConfig, Severity } from '../snapshot/schema.js';

const VALID_SEVERITIES = new Set<string>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const CONFIG_FILENAME = 'pac-scan.config.yaml';

/**
 * Resolves the config file path, searching upward from `cwd` when no
 * explicit path is provided (similar to how tsconfig.json is located).
 */
function findConfigFile(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 10; i++) {
    const candidate = resolve(dir, CONFIG_FILENAME);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break; // reached filesystem root
    dir = parent;
  }
  throw new Error(
    `${CONFIG_FILENAME} not found. ` +
    `Create one in the repository root (searched from: ${startDir})`
  );
}

/**
 * Asserts that `value` is a non-null plain object and narrows the type.
 * Throws a descriptive error when the assertion fails.
 */
function assertObject(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid config: "${path}" must be a mapping object, got ${JSON.stringify(value)}`);
  }
  return value as Record<string, unknown>;
}

/**
 * Asserts that `value` is a non-empty string.
 */
function assertString(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Invalid config: "${path}" must be a non-empty string, got ${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * Asserts that `value` is a string array (may be empty).
 */
function assertStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) {
    throw new Error(`Invalid config: "${path}" must be an array of strings, got ${JSON.stringify(value)}`);
  }
  return value as string[];
}

/**
 * Validates and returns the parsed environments map.
 */
function parseEnvironments(raw: unknown): Record<string, EnvironmentConfig> {
  const envMap = assertObject(raw, 'environments');
  const result: Record<string, EnvironmentConfig> = {};

  for (const [envName, envRaw] of Object.entries(envMap)) {
    const envObj = assertObject(envRaw, `environments.${envName}`);

    const dlp_snapshot = assertString(
      envObj['dlp_snapshot'],
      `environments.${envName}.dlp_snapshot`
    );
    const csp_snapshot = assertString(
      envObj['csp_snapshot'],
      `environments.${envName}.csp_snapshot`
    );

    const environment_url = typeof envObj['environment_url'] === 'string'
      ? envObj['environment_url']
      : undefined;
    const environment_id = typeof envObj['environment_id'] === 'string'
      ? envObj['environment_id']
      : undefined;

    result[envName] = { dlp_snapshot, csp_snapshot, environment_url, environment_id };
  }

  if (Object.keys(result).length === 0) {
    throw new Error('Invalid config: "environments" must contain at least one entry');
  }

  return result;
}

/**
 * Validates and returns the fail_on_severity map.
 */
function parseFailOnSeverity(raw: unknown): Record<string, Severity> {
  const sevMap = assertObject(raw, 'fail_on_severity');
  const result: Record<string, Severity> = {};

  for (const [envName, sevRaw] of Object.entries(sevMap)) {
    const sev = assertString(sevRaw, `fail_on_severity.${envName}`).toUpperCase();
    if (!VALID_SEVERITIES.has(sev)) {
      throw new Error(
        `Invalid config: "fail_on_severity.${envName}" must be one of ` +
        `${[...VALID_SEVERITIES].join(' | ')}, got "${sev}"`
      );
    }
    result[envName] = sev as Severity;
  }

  return result;
}

/**
 * Loads and validates pac-scan.config.yaml.
 *
 * @param configPath - Explicit path to the config file. When omitted the
 *   function searches upward from `process.cwd()`.
 * @returns Validated {@link PacScanConfig} object.
 * @throws When the config file is missing, unreadable, or has invalid fields.
 */
export function loadConfig(configPath?: string): PacScanConfig {
  const resolvedPath = configPath
    ? resolve(configPath)
    : findConfigFile(process.cwd());

  let raw: unknown;
  try {
    const content = readFileSync(resolvedPath, 'utf-8');
    raw = yaml.load(content);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`Config file not found: ${resolvedPath}`);
    }
    throw new Error(`Failed to parse ${resolvedPath}: ${(err as Error).message}`);
  }

  const doc = assertObject(raw, '<root>');

  const environments = parseEnvironments(doc['environments']);
  const default_environment = assertString(doc['default_environment'], 'default_environment');

  if (!(default_environment in environments)) {
    throw new Error(
      `Invalid config: "default_environment" is "${default_environment}" ` +
      `but that environment is not defined under "environments"`
    );
  }

  const fail_on_severity = parseFailOnSeverity(doc['fail_on_severity']);

  // Optional fields with defaults
  const scan_paths: string[] = doc['scan_paths'] !== undefined
    ? assertStringArray(doc['scan_paths'], 'scan_paths')
    : ['src'];

  const scan_extensions: string[] = doc['scan_extensions'] !== undefined
    ? assertStringArray(doc['scan_extensions'], 'scan_extensions')
    : ['.ts', '.tsx', '.js', '.jsx'];

  const exclude_patterns: string[] = doc['exclude_patterns'] !== undefined
    ? assertStringArray(doc['exclude_patterns'], 'exclude_patterns')
    : ['**/node_modules/**', '**/dist/**'];

  return {
    environments,
    default_environment,
    fail_on_severity,
    scan_paths,
    scan_extensions,
    exclude_patterns,
  };
}
