/**
 * TypeScript interfaces for pac-scan environment snapshots.
 *
 * A snapshot captures the live DLP policies and CSP configuration for a
 * single Power Platform environment at a point in time. It is produced by
 * `pac-scan fetch --env <env>` and consumed by `pac-scan run` to evaluate
 * source-code rules offline — no network calls at scan time.
 */

// ---------------------------------------------------------------------------
// DLP policy types
// ---------------------------------------------------------------------------

/** Connector groupings as defined by the DLP policy in Power Platform. */
export interface DlpConnectorGroups {
  /** Connectors classified as Business data — allowed in business apps. */
  business: string[];
  /** Connectors classified as Non-business — restricted from business apps. */
  non_business: string[];
  /** Connectors that are completely blocked for all apps. */
  blocked: string[];
}

/** A single DLP policy retrieved from the Power Platform environment. */
export interface DlpPolicy {
  /** Unique identifier of the policy (GUID). */
  policy_id: string;
  /** Human-readable policy name. */
  name: string;
  /** Connector classification buckets for this policy. */
  connectors: DlpConnectorGroups;
}

// ---------------------------------------------------------------------------
// Connector types
// ---------------------------------------------------------------------------

/** Risk tier for a connector — used by PAC003 / PAC005 rules. */
export type ConnectorRiskTier = 'HIGH' | 'MEDIUM' | 'LOW';

/** Metadata for a single connector available in the environment. */
export interface ConnectorEntry {
  /** Connector logical name (e.g. `shared_http`, `shared_sharepointonline`). */
  name: string;
  /** Whether the connector is currently enabled in this environment. */
  enabled: boolean;
  /** Risk classification for the connector. */
  risk_tier: ConnectorRiskTier;
  /** Actions the policy allows for this connector (e.g. `GetItem`, `PostMessage`). */
  allowed_actions: string[];
  /**
   * Allowlisted endpoint URL patterns for connectors that support
   * endpoint filtering (e.g. `https://*.microsoft.com`).
   */
  endpoint_filter_urls: string[];
}

// ---------------------------------------------------------------------------
// CSP types
// ---------------------------------------------------------------------------

/**
 * Content Security Policy directives as enforced by the Power Apps Player
 * sandbox for Code Apps running in this environment.
 */
export interface CspPolicy {
  /** Allowed origins for `fetch()` / XHR (`connect-src` directive). */
  connect_src: string[];
  /** Allowed script sources (`script-src` directive). */
  script_src: string[];
  /** Allowed frame embedders (`frame-ancestors` directive). */
  frame_ancestors: string[];
}

// ---------------------------------------------------------------------------
// Top-level snapshot
// ---------------------------------------------------------------------------

/**
 * Root snapshot object written to `.pac-scan/current/<env>.json` by
 * `pac-scan fetch --env <env>`.
 */
export interface EnvironmentSnapshot {
  /** ISO-8601 timestamp of when this snapshot was captured. */
  fetched_at: string;
  /** Short environment name (e.g. `dev`, `uat`, `prod`). */
  environment: string;
  /** Power Platform environment GUID. */
  environment_id: string;
  /** All DLP policies active in the environment. */
  dlp_policies: DlpPolicy[];
  /** Connector catalogue with metadata and endpoint filters. */
  connectors: ConnectorEntry[];
  /** CSP directives enforced by the Power Apps Player for this environment. */
  csp: CspPolicy;
}

// ---------------------------------------------------------------------------
// Config types (referenced by config/loader.ts)
// ---------------------------------------------------------------------------

/** Severity level used in `fail_on_severity` config and rule findings. */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Per-environment pointers to snapshot files. */
export interface EnvironmentConfig {
  dlp_snapshot: string;
  csp_snapshot: string;
  /** Power Platform environment URL (e.g. https://orgname.crm.dynamics.com/). Used to auto-resolve environment_id. */
  environment_url?: string;
  /** Power Platform environment GUID. When set, skips pac org list look-up. */
  environment_id?: string;
}

/** Parsed and validated pac-scan.config.yaml contents. */
export interface PacScanConfig {
  environments: Record<string, EnvironmentConfig>;
  default_environment: string;
  fail_on_severity: Record<string, Severity>;
  scan_paths: string[];
  scan_extensions: string[];
  exclude_patterns: string[];
}
