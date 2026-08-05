import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { discoverCandidateFiles } from '../src/discovery.js';

test('discovers supported files and prunes dependency and VCS directories', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'npm-compromise-discovery-'));

  try {
    await mkdir(path.join(root, 'project', 'node_modules', 'ignored'), { recursive: true });
    await mkdir(path.join(root, 'project', '.git'), { recursive: true });
    await writeFile(path.join(root, 'project', 'package-lock.json'), '{}', 'utf8');
    await writeFile(path.join(root, 'project', 'node_modules', 'ignored', 'package.json'), '{}', 'utf8');
    await writeFile(path.join(root, 'project', '.git', 'package.json'), '{}', 'utf8');

    const result = await discoverCandidateFiles(root);
    assert.deepEqual(result.files, [path.join(root, 'project', 'package-lock.json')]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
