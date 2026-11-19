'use strict';
// GapScan for VS Code: runs the local `gapscan` CLI and shows its findings as problems.
// Everything is local: the CLI is the same offline engine, nothing is sent anywhere.
const vscode = require('vscode');
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { findingsToDiagnostics } = require('./diagnostics');

let collection;
let running = false;

function scan(folder, output) {
  if (running) return;
  running = true;
  const cfg = vscode.workspace.getConfiguration('gapscan');
  const exe = cfg.get('executable') || 'gapscan';
  // A private directory per scan: a fixed name in the shared temp folder could be pre-created or
  // symlinked by another local user.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gapscan-'));
  const out = path.join(dir, 'findings.json');
  output.appendLine(`> ${exe} scan ${folder}`);
  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: 'GapScan: scanning' },
    () =>
      new Promise((resolve) => {
        execFile(exe, ['scan', folder, '-o', out], { timeout: 10 * 60 * 1000, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
          running = false;
          output.appendLine(String(stdout || '') + String(stderr || ''));
          try {
            if (err) {
              vscode.window.showErrorMessage(`GapScan failed: ${String(err.message).slice(0, 200)}`);
            } else {
              show(folder, JSON.parse(fs.readFileSync(out, 'utf8')));
            }
          } catch (e) {
            vscode.window.showErrorMessage(`GapScan: could not read results (${e.message})`);
          } finally {
            fs.rmSync(dir, { recursive: true, force: true });
            resolve();
          }
        });
      })
  );
}

function show(folder, scanResult) {
  collection.clear();
  let total = 0;
  for (const [file, diags] of findingsToDiagnostics(scanResult)) {
    const uri = vscode.Uri.file(path.join(folder, file));
    collection.set(uri, diags.map((d) => {
      const x = new vscode.Diagnostic(new vscode.Range(d.startLine, 0, d.endLine, Number.MAX_SAFE_INTEGER), d.message, d.severity);
      x.source = d.source; x.code = d.code;
      return x;
    }));
    total += diags.length;
  }
  vscode.window.setStatusBarMessage(`GapScan: ${total} finding(s)`, 8000);
}

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('gapscan');
  const output = vscode.window.createOutputChannel('GapScan');
  context.subscriptions.push(collection, output,
    vscode.commands.registerCommand('gapscan.scanWorkspace', () => {
      const f = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (!f) return vscode.window.showWarningMessage('Open a folder first.');
      scan(f.uri.fsPath, output);
    }),
    vscode.commands.registerCommand('gapscan.clear', () => collection.clear()),
    vscode.workspace.onDidSaveTextDocument(() => {
      if (!vscode.workspace.getConfiguration('gapscan').get('scanOnSave')) return;
      const f = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (f) scan(f.uri.fsPath, output);
    }));
}

function deactivate() {}
module.exports = { activate, deactivate };
