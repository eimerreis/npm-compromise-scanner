import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

type RootCache = {
  updatedAt: string;
  files: string[];
};

type InventoryCache = {
  schemaVersion: 1;
  roots: Record<string, RootCache>;
};

export function defaultCacheFile(): string {
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Caches', 'npm-compromise-scanner', 'inventory.json');
  }

  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA ?? process.env.APPDATA ?? os.tmpdir();
    return path.join(base, 'npm-compromise-scanner', 'cache', 'inventory.json');
  }

  const base = process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache');
  return path.join(base, 'npm-compromise-scanner', 'inventory.json');
}

export async function readCachedFiles(cacheFile: string, root: string): Promise<string[]> {
  const cache = await readCache(cacheFile);
  return cache.roots[rootKey(root)]?.files ?? [];
}

export async function writeCachedFiles(cacheFile: string, root: string, files: string[]): Promise<void> {
  const cache = await readCache(cacheFile);
  cache.roots[rootKey(root)] = {
    updatedAt: new Date().toISOString(),
    files: [...new Set(files)].sort(),
  };

  await mkdir(path.dirname(cacheFile), { recursive: true });
  const temporaryFile = `${cacheFile}.${process.pid}.tmp`;
  await writeFile(temporaryFile, `${JSON.stringify(cache, null, 2)}\n`, 'utf8');

  try {
    await rename(temporaryFile, cacheFile);
  } catch (error) {
    if (!isReplacementError(error)) throw error;
    await rm(cacheFile, { force: true });
    await rename(temporaryFile, cacheFile);
  }
}

export async function clearCache(cacheFile: string): Promise<void> {
  await rm(cacheFile, { force: true });
}

async function readCache(cacheFile: string): Promise<InventoryCache> {
  try {
    const value: unknown = JSON.parse(await readFile(cacheFile, 'utf8'));
    if (!isRecord(value) || value.schemaVersion !== 1 || !isRecord(value.roots)) return emptyCache();

    const roots: Record<string, RootCache> = {};
    for (const [root, entry] of Object.entries(value.roots)) {
      if (
        isRecord(entry) &&
        typeof entry.updatedAt === 'string' &&
        Array.isArray(entry.files) &&
        entry.files.every((file) => typeof file === 'string')
      ) {
        roots[root] = { updatedAt: entry.updatedAt, files: entry.files };
      }
    }
    return { schemaVersion: 1, roots };
  } catch {
    return emptyCache();
  }
}

function rootKey(root: string): string {
  const resolved = path.resolve(root);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function emptyCache(): InventoryCache {
  return { schemaVersion: 1, roots: {} };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isReplacementError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && (error.code === 'EEXIST' || error.code === 'EPERM');
}
