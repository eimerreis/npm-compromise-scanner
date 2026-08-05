import { readdir } from 'node:fs/promises';
import path from 'node:path';

export const candidateFileNames = new Set([
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
]);

const globallySkippedDirectories = new Set([
  '.git',
  '.Trash',
  '.Trashes',
  '.Spotlight-V100',
  '.fseventsd',
  'node_modules',
]);

export type DiscoveryResult = {
  files: string[];
  scannedDirectories: number;
  unreadableDirectories: number;
};

export async function discoverCandidateFiles(
  root: string,
  onProgress?: (scannedDirectories: number) => void,
): Promise<DiscoveryResult> {
  const directories = [path.resolve(root)];
  const files: string[] = [];
  let cursor = 0;
  let scannedDirectories = 0;
  let unreadableDirectories = 0;

  while (cursor < directories.length) {
    const batch = directories.slice(cursor, cursor + 32);
    cursor += batch.length;

    await Promise.all(
      batch.map(async (directory) => {
        let entries;
        try {
          entries = await readdir(directory, { withFileTypes: true });
        } catch {
          unreadableDirectories += 1;
          return;
        }

        scannedDirectories += 1;
        if (scannedDirectories % 250 === 0) onProgress?.(scannedDirectories);

        for (const entry of entries) {
          const fullPath = path.join(directory, entry.name);
          if (entry.isDirectory()) {
            if (!shouldSkipDirectory(fullPath, entry.name)) directories.push(fullPath);
          } else if (entry.isFile() && candidateFileNames.has(entry.name)) {
            files.push(fullPath);
          }
        }
      }),
    );
  }

  files.sort();
  return { files, scannedDirectories, unreadableDirectories };
}

function shouldSkipDirectory(fullPath: string, name: string): boolean {
  if (globallySkippedDirectories.has(name)) return true;

  if (process.platform === 'darwin') {
    if (isWithinAny(fullPath, ['/System', '/dev', '/private/tmp', '/private/var/tmp', '/private/var/folders'])) {
      return true;
    }
    if (fullPath.endsWith(path.join('Library', 'Caches'))) return true;
    if (fullPath.endsWith(path.join('Library', 'Developer', 'CoreSimulator'))) return true;
  }

  if (process.platform === 'linux' && isWithinAny(fullPath, ['/dev', '/proc', '/sys', '/run'])) return true;

  if (process.platform === 'win32' && (name === '$Recycle.Bin' || name === 'System Volume Information')) {
    return true;
  }

  return false;
}

function isWithinAny(candidate: string, roots: string[]): boolean {
  return roots.some((root) => candidate === root || candidate.startsWith(`${root}${path.sep}`));
}
