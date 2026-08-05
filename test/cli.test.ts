import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runCli, type CliIo } from '../src/cli.js';

const manifest = fileURLToPath(new URL('../data/compromised-npm-packages.json', import.meta.url));

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
