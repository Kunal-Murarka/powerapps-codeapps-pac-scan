import { describe, it, expect } from 'vitest';
import type { ScannedFile } from '../src/rules/base.js';
import type { EnvironmentSnapshot } from '../src/snapshot/schema.js';
import pac001 from '../src/rules/PAC001-secrets.js';
import pac002 from '../src/rules/PAC002-fetch.js';
import pac003 from '../src/rules/PAC003-dlp.js';
import pac004 from '../src/rules/PAC004-csp.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeFile(path: string, content: string): ScannedFile {
  const lines = content.split('\n');
  return { path, content, lines };
}

function makeSnapshot(overrides: Partial<EnvironmentSnapshot> = {}): EnvironmentSnapshot {
  return {
    fetched_at: '2026-05-06T00:00:00Z',
    environment: 'prod',
    environment_id: '00000000-0000-0000-0000-000000000000',
    dlp_policies: [],
    connectors: [],
    csp: {
      connect_src: ["'self'", 'https://*.microsoft.com'],
      script_src: ["'self'"],
      frame_ancestors: ["'self'", 'https://*.powerapps.com'],
    },
    ...overrides,
  };
}

// ===========================================================================
// PAC001 — Hardcoded secrets
// ===========================================================================

describe('PAC001 — Hardcoded secrets', () => {
  const snapshot = makeSnapshot();

  it('detects hardcoded API key', () => {
    const file = makeFile('src/api.ts', `const config = { apiKey: "skliveabc123def456ghi7890" };`);
    const findings = pac001.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule_id).toBe('PAC001');
    expect(findings[0].severity).toBe('CRITICAL');
  });

  it('detects Bearer token', () => {
    const file = makeFile('src/auth.ts', `const header = { Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefgh" };`);
    const findings = pac001.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('Bearer');
  });

  it('detects client secret', () => {
    const file = makeFile('src/config.ts', `const clientSecret = "my-super-secret-value-1234";`);
    const findings = pac001.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('Client secret');
  });

  it('detects Azure Storage account key', () => {
    const file = makeFile('src/storage.ts', `const conn = "AccountKey=abcdefghijklmnopqrstuvwxyz1234567890ABCD+E=";`);
    const findings = pac001.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('Azure Storage');
  });

  it('detects private key PEM header', () => {
    const file = makeFile('src/cert.ts', `const pem = "-----BEGIN PRIVATE KEY-----";`);
    const findings = pac001.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('Private key');
  });

  it('skips environment variable references', () => {
    const file = makeFile('src/safe.ts', `const key = process.env.API_KEY;`);
    const findings = pac001.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('skips import.meta.env references', () => {
    const file = makeFile('src/safe2.ts', `const apiKey = import.meta.env.VITE_API_KEY;`);
    const findings = pac001.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('skips test files', () => {
    const file = makeFile('src/api.test.ts', `const apiKey = "sk_live_abc123def456ghi7890";`);
    const findings = pac001.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('skips comment lines', () => {
    const file = makeFile('src/api.ts', `// apiKey: "sk_live_abc123def456ghi7890"`);
    const findings = pac001.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('skips block comments', () => {
    const file = makeFile('src/api.ts', [
      '/*',
      ' * apiKey: "sk_live_abc123def456ghi7890"',
      ' */',
    ].join('\n'));
    const findings = pac001.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('does not duplicate findings for overlapping patterns', () => {
    const file = makeFile('src/api.ts', `const api_key = "abcdefghijklmnop1234";`);
    const findings = pac001.run([file], snapshot);
    // Should produce exactly 1, not 2 (api_key and apikey patterns overlap)
    expect(findings).toHaveLength(1);
  });
});

// ===========================================================================
// PAC002 — Raw fetch to non-allowlisted domain
// ===========================================================================

describe('PAC002 — Raw fetch to non-allowlisted domain', () => {
  const snapshot = makeSnapshot();

  it('flags fetch to non-allowlisted domain', () => {
    const file = makeFile('src/data.ts', `const res = await fetch("https://evil.example.com/api");`);
    const findings = pac002.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule_id).toBe('PAC002');
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].message).toContain('evil.example.com');
  });

  it('allows fetch to allowlisted domain (*.microsoft.com)', () => {
    const file = makeFile('src/data.ts', `const res = await fetch("https://graph.microsoft.com/v1.0/me");`);
    const findings = pac002.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('allows fetch to localhost', () => {
    const file = makeFile('src/dev.ts', `fetch("http://localhost:3000/api");`);
    const findings = pac002.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('flags axios calls to non-allowlisted domain', () => {
    const file = makeFile('src/client.ts', `axios.get("https://unknown-api.io/data");`);
    const findings = pac002.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('HIGH');
  });

  it('flags dynamic URL in fetch as MEDIUM', () => {
    const file = makeFile('src/dynamic.ts', `const res = await fetch(apiUrl);`);
    const findings = pac002.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('MEDIUM');
  });

  it('flags template literal with interpolation as MEDIUM', () => {
    const file = makeFile('src/dynamic2.ts', 'const res = await fetch(`https://api.example.com/${path}`);');
    const findings = pac002.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some(f => f.severity === 'MEDIUM')).toBe(true);
  });

  it('skips test files', () => {
    const file = makeFile('src/data.spec.ts', `fetch("https://evil.example.com/api");`);
    const findings = pac002.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('uses connector endpoint_filter_urls in allowlist', () => {
    const snap = makeSnapshot({
      connectors: [{
        name: 'shared_http',
        enabled: true,
        risk_tier: 'MEDIUM',
        allowed_actions: ['GetItem'],
        endpoint_filter_urls: ['https://custom-api.contoso.com'],
      }],
    });
    const file = makeFile('src/data.ts', `fetch("https://custom-api.contoso.com/items");`);
    const findings = pac002.run([file], snap);
    expect(findings).toHaveLength(0);
  });
});

// ===========================================================================
// PAC003 — DLP connector violations
// ===========================================================================

describe('PAC003 — DLP connector violations', () => {
  const snapshot = makeSnapshot({
    dlp_policies: [{
      policy_id: 'pol-1',
      name: 'Default Policy',
      connectors: {
        business: ['shared_sharepointonline'],
        non_business: ['shared_twitter'],
        blocked: ['shared_gmail'],
      },
    }],
  });

  it('flags blocked connector as CRITICAL', () => {
    const file = makeFile('src/mail.ts', `import { send } from "@microsoft/powerplatform-connector-gmail";`);
    const findings = pac003.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].message).toContain('blocked');
  });

  it('flags non-business connector as HIGH', () => {
    const file = makeFile('src/social.ts', `const connectorName = "shared_twitter";`);
    const findings = pac003.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].message).toContain('non-business');
  });

  it('allows business connector with no finding', () => {
    const file = makeFile('src/sp.ts', `import { getList } from "@microsoft/powerplatform-connector-sharepointonline";`);
    const findings = pac003.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('flags useConnector hook with blocked connector', () => {
    const file = makeFile('src/hook.ts', `const conn = useConnector("shared_gmail");`);
    const findings = pac003.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('CRITICAL');
  });

  it('flags unlisted connector as MEDIUM', () => {
    const file = makeFile('src/unknown.ts', `const connectorName = "shared_unknownservice";`);
    const findings = pac003.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('MEDIUM');
  });

  it('produces no findings when no DLP policies exist', () => {
    const emptySnap = makeSnapshot({ dlp_policies: [] });
    const file = makeFile('src/mail.ts', `import { send } from "@microsoft/powerplatform-connector-gmail";`);
    const findings = pac003.run([file], emptySnap);
    expect(findings).toHaveLength(0);
  });
});

// ===========================================================================
// PAC004 — CSP violations
// ===========================================================================

describe('PAC004 — CSP violations', () => {
  const snapshot = makeSnapshot();

  it('flags eval()', () => {
    const file = makeFile('src/unsafe.ts', `const result = eval("2 + 2");`);
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].message).toContain('eval()');
  });

  it('flags new Function()', () => {
    const file = makeFile('src/unsafe.ts', `const fn = new Function("return 42");`);
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('Function()');
  });

  it('flags setTimeout with string argument', () => {
    const file = makeFile('src/timer.ts', `setTimeout("doSomething()", 1000);`);
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('setTimeout');
  });

  it('flags dangerouslySetInnerHTML', () => {
    const file = makeFile('src/App.tsx', `<div dangerouslySetInnerHTML={{ __html: content }} />`);
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('dangerouslySetInnerHTML');
  });

  it('flags iframe with non-allowlisted src', () => {
    const file = makeFile('public/index.html', `<iframe src="https://evil.example.com/embed"></iframe>`);
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('evil.example.com');
  });

  it('allows iframe with allowlisted src', () => {
    const file = makeFile('public/index.html', `<iframe src="https://apps.powerapps.com/embed"></iframe>`);
    const findings = pac004.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('flags permissive CSP in vite.config.ts', () => {
    const file = makeFile('vite.config.ts', [
      'export default defineConfig({',
      '  server: {',
      '    headers: {',
      `      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-eval'"`,
      '    }',
      '  }',
      '});',
    ].join('\n'));
    const findings = pac004.run([file], snapshot);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].message).toContain('more permissive');
  });

  it('allows safe vite.config CSP that matches snapshot', () => {
    const file = makeFile('vite.config.ts', [
      'export default defineConfig({',
      '  server: {',
      '    headers: {',
      `      "Content-Security-Policy": "default-src 'self'; script-src 'self'"`,
      '    }',
      '  }',
      '});',
    ].join('\n'));
    const findings = pac004.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });

  it('skips comment lines', () => {
    const file = makeFile('src/safe.ts', `// eval("this is a comment")`);
    const findings = pac004.run([file], snapshot);
    expect(findings).toHaveLength(0);
  });
});

// ===========================================================================
// PAC005 — Vulnerable dependencies (structural test only)
// ===========================================================================

describe('PAC005 — Vulnerable dependencies', () => {
  // PAC005 calls npm audit externally, so we test its structural contract only

  it('exports the correct rule metadata', async () => {
    const pac005 = (await import('../src/rules/PAC005-dependencies.js')).default;
    expect(pac005.id).toBe('PAC005');
    expect(pac005.name).toBe('Vulnerable npm dependency');
    expect(pac005.severity).toBe('HIGH');
    expect(typeof pac005.run).toBe('function');
  });

  it('gracefully handles missing package.json', async () => {
    const pac005 = (await import('../src/rules/PAC005-dependencies.js')).default;
    // Pass no files (inferProjectDir will fall back to cwd which has a package.json,
    // so we test that it doesn't throw)
    const findings = pac005.run([], makeSnapshot());
    // Should not throw, may or may not have findings depending on real npm audit
    expect(Array.isArray(findings)).toBe(true);
  });
});
