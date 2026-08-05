import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadManifest } from '../src/manifest.js';
import { scanFile } from '../src/scanner.js';
import type { VulnerabilityPair } from '../src/types.js';

const manifest = fileURLToPath(new URL('../data/compromised-npm-packages.json', import.meta.url));

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

test('finds every package/version named in the Aikido Keyv compromise report', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-scanner-'));
  const lockfile = path.join(directory, 'package-lock.json');
  const reportedPairs = [
    ['keyv', '6.0.0'],
    ['flat-cache', '6.1.24'],
    ['file-entry-cache', '11.1.6'],
    ['cacheable-request', '13.0.20'],
    ['cacheable', '2.5.1'],
    ['@cacheable/memory', '2.2.1'],
    ['cache-manager', '7.2.10'],
    ['@cacheable/node-cache', '3.1.2'],
    ['@cacheable/utils', '2.5.1'],
    ['@cacheable/net', '2.1.1'],
    ['ecto', '5.0.1'],
    ['@deliveroo/reevent', '1.0.1'],
    ['@or-sdk/invitations', '1.4.9'],
    ['@picsart/ai-sdk', '3.32.2'],
    ['@qlik/embed-runtime', '1.6.4'],
    ['picasso.js', '2.11.6'],
  ] as const;

  try {
    await writeFile(
      lockfile,
      JSON.stringify({
        lockfileVersion: 3,
        packages: Object.fromEntries(
          reportedPairs.map(([name, version]) => [`node_modules/${name}`, { version }]),
        ),
      }),
      'utf8',
    );

    const result = await scanFile(lockfile, await loadManifest(manifest));
    assert.deepEqual(
      result.matches.map(({ pair }) => [pair.name, pair.version]),
      reportedPairs,
    );
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
