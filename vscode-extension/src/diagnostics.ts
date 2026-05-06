import * as vscode from 'vscode';
import * as path from 'node:path';
import type { JsonReport } from './scanner';

// ---------------------------------------------------------------------------
// Severity → VS Code DiagnosticSeverity mapping
// ---------------------------------------------------------------------------

function mapSeverity(sev: string): vscode.DiagnosticSeverity {
  switch (sev) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
    case 'INFO':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ---------------------------------------------------------------------------
// Diagnostics manager
// ---------------------------------------------------------------------------

export class PacScanDiagnostics {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('pac-scan');
  }

  /**
   * Replaces all diagnostics with findings from `report`.
   * Findings with line === 0 (whole-file / meta-findings) are skipped —
   * they appear in the panel but cannot be squiggled.
   */
  update(report: JsonReport, workspaceRoot: string): void {
    this.collection.clear();

    // Group findings by absolute file URI
    const byUri = new Map<string, vscode.Diagnostic[]>();

    for (const finding of report.findings) {
      if (finding.line <= 0) continue; // no specific location — skip squiggle

      // Resolve relative path (e.g. "src/App.tsx") to absolute
      const absPath = path.isAbsolute(finding.file)
        ? finding.file
        : path.join(workspaceRoot, finding.file);

      const uri = vscode.Uri.file(absPath);
      const key = uri.toString();

      // VS Code ranges are 0-based; findings are 1-based
      const line = Math.max(0, finding.line - 1);
      const col  = Math.max(0, finding.column - 1);
      const range = new vscode.Range(line, col, line, col + 1);

      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.rule_id}] ${finding.message}`,
        mapSeverity(finding.severity),
      );
      diagnostic.source = 'pac-scan';
      diagnostic.code = {
        value: finding.rule_id,
        target: vscode.Uri.parse(`https://aka.ms/pac-scan-rules#${finding.rule_id.toLowerCase()}`),
      };

      // Attach remediation as a related information hint
      if (finding.remediation) {
        const relatedLoc = new vscode.Location(uri, range);
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(relatedLoc, finding.remediation),
        ];
      }

      if (!byUri.has(key)) byUri.set(key, []);
      byUri.get(key)!.push(diagnostic);
    }

    // Bulk-set diagnostics per file
    for (const [uriStr, diags] of byUri) {
      this.collection.set(vscode.Uri.parse(uriStr), diags);
    }
  }

  clear(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }
}
