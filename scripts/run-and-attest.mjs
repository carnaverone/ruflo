#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import {
  createExecutionAttestation,
  digestArgv,
} from './lib/execution-attestation.mjs';

const MAX_KEY_BYTES = 16 * 1024;
const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

function usage(message) {
  if (message) console.error(message);
  console.error(
    'usage: node scripts/run-and-attest.mjs --private-key <key.pem> ' +
    '--source-commit <sha> --output <attestation.json> [--claim-id <id>] -- <command> [args...]',
  );
  process.exit(2);
}

function readPrivateKey(path) {
  const resolved = resolve(path);
  const stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('private key must be a regular non-symlink file');
  if (stat.size > MAX_KEY_BYTES) throw new Error(`private key exceeds ${MAX_KEY_BYTES} bytes`);
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new Error('private key permissions must not grant group or world access');
  }
  return readFileSync(resolved, 'utf8');
}

function parseArgs(argv) {
  const separator = argv.indexOf('--');
  if (separator < 0) usage('missing -- command separator');
  const options = argv.slice(0, separator);
  const command = argv.slice(separator + 1);
  if (command.length === 0) usage('missing command');

  const parsed = { command };
  for (let index = 0; index < options.length; index += 1) {
    const option = options[index];
    const value = options[index + 1];
    if (!['--private-key', '--source-commit', '--output', '--claim-id'].includes(option) || value === undefined) {
      usage(`invalid option: ${option}`);
    }
    index += 1;
    if (option === '--private-key') parsed.privateKey = value;
    if (option === '--source-commit') parsed.sourceCommit = value.toLowerCase();
    if (option === '--output') parsed.output = value;
    if (option === '--claim-id') parsed.claimId = value;
  }

  parsed.sourceCommit ??= process.env.GITHUB_SHA?.toLowerCase();
  if (!parsed.privateKey) usage('missing --private-key');
  if (!parsed.output) usage('missing --output');
  if (!parsed.sourceCommit || !COMMIT_RE.test(parsed.sourceCommit)) usage('missing or invalid --source-commit');
  return parsed;
}

const args = parseArgs(process.argv.slice(2));
let privateKey;
try {
  privateKey = readPrivateKey(args.privateKey);
} catch (error) {
  usage(error instanceof Error ? error.message : String(error));
}

const startedAt = new Date().toISOString();
const stdoutHash = createHash('sha256');
const stderrHash = createHash('sha256');
let spawnFailed = false;

const child = spawn(args.command[0], args.command.slice(1), {
  shell: false,
  stdio: ['inherit', 'pipe', 'pipe'],
  windowsHide: true,
});

function forwardAndHash(stream, destination, hash) {
  stream.on('data', (chunk) => {
    hash.update(chunk);
    if (!destination.write(chunk)) {
      stream.pause();
      destination.once('drain', () => stream.resume());
    }
  });
}

forwardAndHash(child.stdout, process.stdout, stdoutHash);
forwardAndHash(child.stderr, process.stderr, stderrHash);
child.on('error', (error) => {
  spawnFailed = true;
  console.error(`run-and-attest: command could not be started: ${error.message}`);
  process.exitCode = 2;
});
child.on('close', (code, signal) => {
  if (spawnFailed) return;
  const completedAt = new Date().toISOString();
  const exitCode = Number.isInteger(code) ? code : 128;
  try {
    const attestation = createExecutionAttestation({
      commandDigest: digestArgv(args.command),
      stdoutDigest: `sha256:${stdoutHash.digest('hex')}`,
      stderrDigest: `sha256:${stderrHash.digest('hex')}`,
      exitCode,
      signal: signal ?? null,
      sourceCommit: args.sourceCommit,
      startedAt,
      completedAt,
      ...(args.claimId ? { claimId: args.claimId } : {}),
    }, privateKey);
    writeFileSync(resolve(args.output), `${JSON.stringify(attestation, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    process.exitCode = exitCode;
  } catch (error) {
    console.error(`run-and-attest: failed to write attestation: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  }
});
