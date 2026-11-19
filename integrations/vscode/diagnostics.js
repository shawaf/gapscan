'use strict';
// Pure mapping from GapScan's findings JSON to editor diagnostics. No VS Code API in here, so it
// can be tested with plain Node (`node --test integrations/vscode`).

const SEVERITY = { critical: 0, high: 0, medium: 1, low: 2, info: 3 }; // 0 Error 1 Warning 2 Info 3 Hint

function findingsToDiagnostics(scan) {
  const byFile = new Map();
  for (const f of (scan && scan.findings) || []) {
    if (!f.file || !f.start_line) continue;
    const startLine = Math.max(0, f.start_line - 1);
    const endLine = Math.max(startLine, (f.end_line || f.start_line) - 1);
    const flow = Array.isArray(f.raw && f.raw.taint_path) ? '\nFlow: ' + f.raw.taint_path.join(' -> ') : '';
    const diag = {
      startLine, endLine,
      severity: SEVERITY[f.severity] ?? 1,
      message: `${f.title}${f.cwe && f.cwe.length ? ' (' + f.cwe.join(', ') + ')' : ''}${flow}`,
      source: 'GapScan',
      code: f.rule_id,
      findingId: f.id,
    };
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(diag);
  }
  return byFile;
}

module.exports = { findingsToDiagnostics, SEVERITY };
