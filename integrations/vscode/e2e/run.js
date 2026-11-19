'use strict';
// End-to-end: starts a real VS Code with this extension and the vulnerable fixture as workspace,
// runs "GapScan: Scan workspace" against the real CLI and checks the problems it shows.
//   npm install && GAPSCAN_EXE=/path/to/gapscan xvfb-run -a npm run e2e
const fs = require('fs');
const os = require('os');
const path = require('path');
const { runTests } = require('@vscode/test-electron');

async function main() {
  const ext = path.resolve(__dirname, '..');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gapscan-e2e-'));
  fs.cpSync(path.resolve(ext, '../../eval/fixtures/vuln-app'), work, { recursive: true });
  fs.mkdirSync(path.join(work, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(work, '.vscode', 'settings.json'),
    JSON.stringify({ 'gapscan.executable': process.env.GAPSCAN_EXE || 'gapscan' }));
  try {
    await runTests({
      version: process.env.VSCODE_VERSION || 'stable',
      extensionDevelopmentPath: ext,
      extensionTestsPath: path.join(__dirname, 'suite.js'),
      launchArgs: [work, '--disable-extensions', '--disable-workspace-trust'],
    });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
