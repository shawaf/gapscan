'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { findingsToDiagnostics } = require('./diagnostics');

test('maps findings to per-file diagnostics with severity and flow', () => {
  const scan = { findings: [
    { id: 'a', file: 'app.py', start_line: 9, end_line: 9, severity: 'critical', title: 'OS command injection', cwe: ['CWE-78'], rule_id: 'gapscan.taint.cmd', raw: { taint_path: ['source at app.py:8', 'sink at app.py:9'] } },
    { id: 'b', file: 'app.py', start_line: 3, severity: 'low', title: 'Weak hash', cwe: [], rule_id: 'md5', raw: {} },
    { id: 'c', file: null, start_line: null, severity: 'high', title: 'no location', raw: {} },
  ] };
  const m = findingsToDiagnostics(scan);
  assert.deepStrictEqual([...m.keys()], ['app.py']);
  const [first, second] = m.get('app.py');
  assert.strictEqual(first.startLine, 8);
  assert.strictEqual(first.severity, 0);
  assert.match(first.message, /CWE-78/);
  assert.match(first.message, /Flow: source at app.py:8 -> sink at app.py:9/);
  assert.strictEqual(second.severity, 2);
  assert.strictEqual(second.endLine, 2);
});

test('empty or missing input gives no diagnostics', () => {
  assert.strictEqual(findingsToDiagnostics({}).size, 0);
  assert.strictEqual(findingsToDiagnostics(null).size, 0);
});
