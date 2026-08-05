import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { readCachedFiles, writeCachedFiles } from '../src/cache.js';

test('stores separate sorted candidate inventories per scan root', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-cache-'));
  const cacheFile = path.join(directory, 'inventory.json');
  const firstRoot = path.join(directory, 'first');
  const secondRoot = path.join(directory, 'second');

  try {
    await writeCachedFiles(cacheFile, firstRoot, ['/z/package.json', '/a/yarn.lock', '/z/package.json']);
    await writeCachedFiles(cacheFile, secondRoot, ['/b/pnpm-lock.yaml']);

    assert.deepEqual(await readCachedFiles(cacheFile, firstRoot), ['/a/yarn.lock', '/z/package.json']);
    assert.deepEqual(await readCachedFiles(cacheFile, secondRoot), ['/b/pnpm-lock.yaml']);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
