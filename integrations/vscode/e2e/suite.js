'use strict';
// Runs inside VS Code (extension host). Exported `run` is what @vscode/test-electron calls.
const assert = require('assert');
const path = require('path');
const vscode = require('vscode');

async function waitFor(check, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = check();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('timed out');
}

exports.run = async function run() {
  const ext = vscode.extensions.all.find((e) => e.packageJSON.name === 'gapscan');
  assert.ok(ext, 'extension loaded');
  await waitFor(() => ext.isActive, 30000); // activates on startup, so scan-on-save works at once
  const cmds = await vscode.commands.getCommands(true);
  assert.ok(cmds.includes('gapscan.scanWorkspace') && cmds.includes('gapscan.clear'));

  const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const appPy = vscode.Uri.file(path.join(root, 'app.py'));
  await vscode.commands.executeCommand('gapscan.scanWorkspace');
  const diags = await waitFor(() => {
    const d = vscode.languages.getDiagnostics(appPy).filter((x) => x.source === 'GapScan');
    return d.length ? d : null;
  }, 10 * 60 * 1000);

  const sqli = diags.find((d) => d.range.start.line === 15 && /CWE-89/.test(d.message));
  assert.ok(sqli, 'SQL injection on line 16: ' + diags.map((d) => `${d.range.start.line + 1} ${d.message}`).join(' | '));
  assert.strictEqual(sqli.severity, vscode.DiagnosticSeverity.Error);
  assert.ok(diags.some((d) => d.range.start.line === 22 && /CWE-78/.test(d.message)), 'command injection on line 23');
  assert.ok(diags.every((d) => typeof d.code === 'string' && d.code.length > 0), 'every problem names its rule');
  console.log(`GapScan e2e: ${diags.length} problems in app.py`);

  await vscode.commands.executeCommand('gapscan.clear');
  assert.strictEqual(vscode.languages.getDiagnostics(appPy).filter((x) => x.source === 'GapScan').length, 0);
};
