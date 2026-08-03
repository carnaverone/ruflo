import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  auditPluginMemoryProvenance,
  auditSource,
  findObjectEnd,
} from '../audit-plugin-memory-provenance.mjs';

test('findObjectEnd ignores braces in strings, templates, and comments', () => {
  const source = `{
    content: "brace } inside string",
    template: \`value { still text }\`,
    // }
    nested: { ok: true },
    /* { } */
  } trailing`;
  const end = findObjectEnd(source, 0);
  assert.equal(source[end], '}');
  assert.equal(source.slice(end + 1).trim(), 'trailing');
});

test('auditSource accepts explicit canonical provenance', () => {
  const findings = auditSource(`
    await this.memory.store({
      namespace: 'qe/patterns',
      content: JSON.stringify(pattern),
      provenance_type: 'agent_output',
      metadata: { nested: { value: '}' } },
    });
  `, 'plugin.ts');
  assert.deepEqual(findings, []);
});

test('auditSource reports missing provenance with line number', () => {
  const findings = auditSource(`
    const before = true;
    await this.memory.store({
      namespace: 'qe/patterns',
      content: 'value',
    });
  `, 'plugin.ts');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].code, 'MISSING_PROVENANCE_TYPE');
  assert.equal(findings[0].line, 3);
});

test('repository audit scans plugin source and excludes tests', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'ruflo-plugin-provenance-'));
  try {
    const src = path.join(root, 'example', 'src');
    const tests = path.join(root, 'example', '__tests__');
    mkdirSync(src, { recursive: true });
    mkdirSync(tests, { recursive: true });

    writeFileSync(path.join(src, 'good.ts'), `
      memory.store({ content: 'ok', provenance_type: 'tool_result' });
    `);
    writeFileSync(path.join(src, 'bad.ts'), `
      this.memory.store({ content: 'missing' });
    `);
    writeFileSync(path.join(tests, 'fixture.test.ts'), `
      this.memory.store({ content: 'test fixture without provenance' });
    `);

    const result = auditPluginMemoryProvenance(root);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].code, 'MISSING_PROVENANCE_TYPE');
    assert.match(result.findings[0].file, /bad\.ts$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
