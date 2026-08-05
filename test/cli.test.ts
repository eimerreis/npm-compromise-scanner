import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runCli, type CliIo } from '../src/cli.js';

const manifest = fileURLToPath(new URL('../data/compromised-npm-packages.json', import.meta.url));

test('shows first-time setup help', async () => {
  const output: string[] = [];

  assert.equal(await runCli(['help', 'init'], captureIo(output)), 0);
  assert.match(output.join('\n'), /Create a Workspace Manifest/);
  assert.match(output.join('\n'), /Advisory source URL/);
});

test('creates a Workspace Manifest from interactive input', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-cli-'));
  const output = path.join(directory, 'npm-compromise-scanner.json');
  const responses = [
    'https://example.com/advisories/example-compromise',
    'keyv',
    '6.0.0, 6.0.1',
    'y',
    '@cacheable/memory',
    '2.2.1',
    'n',
  ];
  const outputLines: string[] = [];

  try {
    const status = await runCli(
      ['init', '--output', output],
      {
        ...captureIo(outputLines),
        prompt: async () => responses.shift() ?? '',
      },
    );

    assert.equal(status, 0);
    assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), {
      schemaVersion: 1,
      incidents: [
        {
          id: 'custom-example-compromise',
          source: 'https://example.com/advisories/example-compromise',
          packages: [
            { name: 'keyv', versions: ['6.0.0', '6.0.1'] },
            { name: '@cacheable/memory', versions: ['2.2.1'] },
          ],
        },
      ],
    });
    assert.ok(outputLines.some((line) => line.includes('Created workspace manifest')));

    assert.equal(await runCli(['init', '--output', output], captureIo([])), 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('creates a Workspace Manifest non-interactively for coding agents', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-cli-'));
  const output = path.join(directory, 'agent-manifest.json');

  try {
    assert.equal(
      await runCli(
        [
          'init',
          '--output',
          output,
          '--source',
          'https://example.com/advisories/keyv-compromise',
          '--package',
          'keyv@6.0.0',
          '--package',
          '@cacheable/memory@2.2.1',
          '--package',
          'keyv@6.0.0',
        ],
        captureIo([]),
      ),
      0,
    );

    const created = JSON.parse(await readFile(output, 'utf8'));
    assert.deepEqual(created.incidents[0].packages, [
      { name: 'keyv', versions: ['6.0.0'] },
      { name: '@cacheable/memory', versions: ['2.2.1'] },
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('uses the Workspace Manifest by default', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-cli-'));
  const originalDirectory = process.cwd();
  const output: string[] = [];

  try {
    await writeFile(
      path.join(directory, 'npm-compromise-scanner.json'),
      JSON.stringify({
        schemaVersion: 1,
        incidents: [
          {
            id: 'custom-keyv-report',
            source: 'https://example.com/advisories/keyv-report',
            packages: [{ name: 'keyv', versions: ['6.0.0'] }],
          },
        ],
      }),
      'utf8',
    );
    await writeFile(
      path.join(directory, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }),
      'utf8',
    );

    process.chdir(directory);
    assert.equal(await runCli(['--root', directory, '--no-cache'], captureIo(output)), 1);
    assert.ok(output.some((line) => line.includes('custom-keyv-report')));
  } finally {
    process.chdir(originalDirectory);
    await rm(directory, { recursive: true, force: true });
  }
});

test('scans cached candidates while refreshing discovery', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-cli-'));
  const root = path.join(directory, 'root');
  const lockfile = path.join(root, 'package-lock.json');
  const cacheFile = path.join(directory, 'cache', 'inventory.json');
  const firstOutput: string[] = [];
  const secondOutput: string[] = [];

  try {
    await import('node:fs/promises').then(({ mkdir }) => mkdir(root, { recursive: true }));
    await writeFile(
      lockfile,
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.1' } } }),
      'utf8',
    );

    const firstStatus = await runCli(cliArguments(root, cacheFile), captureIo(firstOutput));
    assert.equal(firstStatus, 0);
    assert.ok(firstOutput.some((line) => line.includes('No cached candidate files')));

    await writeFile(
      lockfile,
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }),
      'utf8',
    );

    const secondStatus = await runCli(cliArguments(root, cacheFile), captureIo(secondOutput));
    assert.equal(secondStatus, 1);
    assert.ok(secondOutput.some((line) => line.includes('Scanning 1 cached candidate file')));
    assert.ok(secondOutput.some((line) => line.includes('keyv@6.0.0')));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function cliArguments(root: string, cacheFile: string): string[] {
  return ['--root', root, '--cache-file', cacheFile, '--manifest', manifest];
}

function captureIo(output: string[]): CliIo {
  return {
    stdout: (message) => output.push(message),
    stderr: (message) => output.push(message),
  };
}
