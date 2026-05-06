import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type {
  EnvironmentSnapshot,
  DlpPolicy,
  ConnectorEntry,
  CspPolicy,
} from './schema.js';

// ---------------------------------------------------------------------------
// Internal validation helpers
// ---------------------------------------------------------------------------

function assertField<T>(
  obj: Record<string, unknown>,
  key: string,
  context: string,
  check: (v: unknown) => v is T,
  typeName: string
): T {
  const value = obj[key];
  if (!check(value)) {
    throw new Error(
      `Snapshot validation error at "${context}.${key}": ` +
      `expected ${typeName}, got ${JSON.stringify(value)}`
    );
  }
  return value;
}

function isString(v: unknown): v is string {
  return typeof v === 'string';
}

function isBoolean(v: unknown): v is boolean {
  return typeof v === 'boolean';
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((i) => typeof i === 'string');
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Sub-object validators
// ---------------------------------------------------------------------------

function validateCsp(raw: unknown, path: string): CspPolicy {
  if (!isPlainObject(raw)) {
    throw new Error(`Snapshot validation error at "${path}": expected an object`);
  }

  return {
    connect_src: assertField(raw, 'connect_src', path, isStringArray, 'string[]'),
    script_src: assertField(raw, 'script_src', path, isStringArray, 'string[]'),
    frame_ancestors: assertField(raw, 'frame_ancestors', path, isStringArray, 'string[]'),
  };
}

function validateConnector(raw: unknown, index: number): ConnectorEntry {
  const path = `connectors[${index}]`;
  if (!isPlainObject(raw)) {
    throw new Error(`Snapshot validation error at "${path}": expected an object`);
  }

  const name = assertField(raw, 'name', path, isString, 'string');
  const enabled = assertField(raw, 'enabled', path, isBoolean, 'boolean');
  const risk_tier = assertField(raw, 'risk_tier', path, isString, 'string');

  if (!['HIGH', 'MEDIUM', 'LOW'].includes(risk_tier)) {
    throw new Error(
      `Snapshot validation error at "${path}.risk_tier": ` +
      `must be HIGH | MEDIUM | LOW, got "${risk_tier}"`
    );
  }

  return {
    name,
    enabled,
    risk_tier: risk_tier as ConnectorEntry['risk_tier'],
    allowed_actions: assertField(raw, 'allowed_actions', path, isStringArray, 'string[]'),
    endpoint_filter_urls: assertField(raw, 'endpoint_filter_urls', path, isStringArray, 'string[]'),
  };
}

function validateDlpPolicy(raw: unknown, index: number): DlpPolicy {
  const path = `dlp_policies[${index}]`;
  if (!isPlainObject(raw)) {
    throw new Error(`Snapshot validation error at "${path}": expected an object`);
  }

  const connectorsRaw = raw['connectors'];
  if (!isPlainObject(connectorsRaw)) {
    throw new Error(`Snapshot validation error at "${path}.connectors": expected an object`);
  }

  return {
    policy_id: assertField(raw, 'policy_id', path, isString, 'string'),
    name: assertField(raw, 'name', path, isString, 'string'),
    connectors: {
      business: assertField(connectorsRaw, 'business', `${path}.connectors`, isStringArray, 'string[]'),
      non_business: assertField(connectorsRaw, 'non_business', `${path}.connectors`, isStringArray, 'string[]'),
      blocked: assertField(connectorsRaw, 'blocked', `${path}.connectors`, isStringArray, 'string[]'),
    },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Loads and validates the environment snapshot JSON for the given environment.
 *
 * @param snapshotPath - Resolved path to the snapshot file (from config).
 * @param env          - Short environment name used for error messages.
 * @returns Validated {@link EnvironmentSnapshot}.
 * @throws When the snapshot file is absent or fails schema validation.
 */
export function loadSnapshot(snapshotPath: string, env: string): EnvironmentSnapshot {
  const resolvedPath = resolve(snapshotPath);

  if (!existsSync(resolvedPath)) {
    throw new Error(
      `No snapshot found for env "${env}". Run: pac-scan fetch --env ${env}\n` +
      `  (looked for: ${resolvedPath})`
    );
  }

  let raw: unknown;
  try {
    const content = readFileSync(resolvedPath, 'utf-8');
    raw = JSON.parse(content);
  } catch (err) {
    throw new Error(
      `Failed to read snapshot for env "${env}" at ${resolvedPath}: ` +
      (err as Error).message
    );
  }

  if (!isPlainObject(raw)) {
    throw new Error(`Snapshot file for env "${env}" must contain a JSON object`);
  }

  // Validate top-level required scalar fields
  const fetched_at = assertField(raw, 'fetched_at', '<root>', isString, 'string');
  const environment = assertField(raw, 'environment', '<root>', isString, 'string');
  const environment_id = assertField(raw, 'environment_id', '<root>', isString, 'string');

  // Validate arrays
  const dlpPoliciesRaw = raw['dlp_policies'];
  if (!Array.isArray(dlpPoliciesRaw)) {
    throw new Error(`Snapshot validation error at "dlp_policies": expected an array`);
  }

  const connectorsRaw = raw['connectors'];
  if (!Array.isArray(connectorsRaw)) {
    throw new Error(`Snapshot validation error at "connectors": expected an array`);
  }

  const dlp_policies = dlpPoliciesRaw.map((item, i) => validateDlpPolicy(item, i));
  const connectors = connectorsRaw.map((item, i) => validateConnector(item, i));
  const csp = validateCsp(raw['csp'], 'csp');

  return {
    fetched_at,
    environment,
    environment_id,
    dlp_policies,
    connectors,
    csp,
  };
}
