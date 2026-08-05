import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { scanFile } from '../src/scanner.js';
import type { VulnerabilityPair } from '../src/types.js';

const pairs: VulnerabilityPair[] = [
  {
    name: 'keyv',
    version: '6.0.0',
    incidents: ['test-incident'],
  },
];

test('finds compromised versions in malformed npm lockfiles', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-scanner-'));
  const lockfile = path.join(directory, 'package-lock.json');

  try {
    await writeFile(
      lockfile,
      '{\n  "packages": {\n    "node_modules/keyv": {\n      "version": "6.0.0"\n',
      'utf8',
    );

    const result = await scanFile(lockfile, pairs);
    assert.equal(result.matches.length, 1);
    assert.equal(result.matches[0]?.pair.name, 'keyv');
    assert.match(result.kind, /text fallback/);
    assert.match(result.fallbackWarning ?? '', /scanned with tolerant text fallback/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('does not produce near-version or near-name false positives', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-scanner-'));
  const lockfile = path.join(directory, 'yarn.lock');

  try {
    await writeFile(lockfile, 'not-keyv@6.0.0:\n\nkeyv@6.0.1:\n', 'utf8');
    const result = await scanFile(lockfile, pairs);
    assert.deepEqual(result.matches, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
