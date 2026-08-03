#!/usr/bin/env node
/**
 * Audit direct plugin memory writes and require explicit ADR-323 provenance.
 *
 * This intentionally scans only source files under v3/plugins/*/src. Test
 * fixtures and generated output are excluded. The accepted call shape is a
 * direct object literal passed to `memory.store({ ... })` or
 * `this.memory.store({ ... })`; each such object must declare
 * `provenance_type` explicitly so provenance cannot silently default to
 * `unknown`.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.dirname(SCRIPT_DIR);
const DEFAULT_PLUGIN_ROOT = path.join(REPO_ROOT, 'v3', 'plugins');
const SOURCE_SUFFIXES = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs']);
const MEMORY_STORE_RE = /\b(?:this\.)?memory\.store\s*\(\s*\{/g;

function walk(directory, output = []) {
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return output;
  }

  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'coverage') continue;
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(target, output);
    else if (entry.isFile() && SOURCE_SUFFIXES.has(path.extname(entry.name))) output.push(target);
  }
  return output;
}

function lineNumber(source, offset) {
  return source.slice(0, offset).split('\n').length;
}

/**
 * Find the closing brace for an object literal while ignoring braces inside
 * strings, templates, and comments. Returns -1 for malformed input.
 */
export function findObjectEnd(source, objectStart) {
  let depth = 0;
  let state = 'code';
  let escaped = false;

  for (let index = objectStart; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (state === 'line-comment') {
      if (char === '\n') state = 'code';
      continue;
    }
    if (state === 'block-comment') {
      if (char === '*' && next === '/') {
        state = 'code';
        index += 1;
      }
      continue;
    }
    if (state === 'single' || state === 'double' || state === 'template') {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (
        (state === 'single' && char === "'")
        || (state === 'double' && char === '"')
        || (state === 'template' && char === '`')
      ) {
        state = 'code';
      }
      continue;
    }

    if (char === '/' && next === '/') {
      state = 'line-comment';
      index += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      state = 'block-comment';
      index += 1;
      continue;
    }
    if (char === "'") {
      state = 'single';
      continue;
    }
    if (char === '"') {
      state = 'double';
      continue;
    }
    if (char === '`') {
      state = 'template';
      continue;
    }
    if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return index;
      if (depth < 0) return -1;
    }
  }

  return -1;
}

export function auditSource(source, file = '<memory>') {
  const findings = [];
  MEMORY_STORE_RE.lastIndex = 0;

  for (let match = MEMORY_STORE_RE.exec(source); match; match = MEMORY_STORE_RE.exec(source)) {
    const objectStart = source.indexOf('{', match.index);
    const objectEnd = findObjectEnd(source, objectStart);
    if (objectEnd < 0) {
      findings.push({
        file,
        line: lineNumber(source, match.index),
        code: 'UNTERMINATED_STORE_OBJECT',
        detail: 'Unable to determine the end of memory.store object literal',
      });
      continue;
    }

    const objectSource = source.slice(objectStart, objectEnd + 1);
    if (!/\bprovenance_type\s*:/.test(objectSource)) {
      findings.push({
        file,
        line: lineNumber(source, match.index),
        code: 'MISSING_PROVENANCE_TYPE',
        detail: 'Direct plugin memory.store object must declare provenance_type',
      });
    }

    MEMORY_STORE_RE.lastIndex = objectEnd + 1;
  }

  return findings;
}

export function auditPluginMemoryProvenance(pluginRoot = DEFAULT_PLUGIN_ROOT) {
  const findings = [];
  const files = walk(pluginRoot).filter((file) => {
    const normalized = file.split(path.sep).join('/');
    return normalized.includes('/src/') && !normalized.includes('/__tests__/') && !/\.(?:test|spec)\.[^.]+$/.test(normalized);
  });

  for (const file of files) {
    let source;
    try {
      if (!statSync(file).isFile()) continue;
      source = readFileSync(file, 'utf8');
    } catch (error) {
      findings.push({
        file: path.relative(REPO_ROOT, file),
        line: 1,
        code: 'READ_ERROR',
        detail: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    findings.push(...auditSource(source, path.relative(REPO_ROOT, file)));
  }

  return { filesScanned: files.length, findings };
}

function main() {
  const json = process.argv.includes('--format=json') || process.argv.includes('--json');
  const result = auditPluginMemoryProvenance();

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.findings.length === 0) {
    console.log(`Plugin memory provenance audit passed (${result.filesScanned} source files scanned)`);
  } else {
    console.error(`Plugin memory provenance audit failed (${result.findings.length} finding(s))`);
    for (const finding of result.findings) {
      console.error(`- ${finding.file}:${finding.line} ${finding.code}: ${finding.detail}`);
    }
  }

  process.exitCode = result.findings.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
