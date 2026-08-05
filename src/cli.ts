import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { clearCache, defaultCacheFile, readCachedFiles, writeCachedFiles } from './cache.js';
import { discoverCandidateFiles } from './discovery.js';
import { loadManifest } from './manifest.js';
import { scanFiles } from './scanner.js';
import type { FileScanResult } from './types.js';

const packageMetadata: unknown = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const packageVersion =
  typeof packageMetadata === 'object' &&
  packageMetadata !== null &&
  'version' in packageMetadata &&
  typeof packageMetadata.version === 'string'
    ? packageMetadata.version
    : 'unknown';
const defaultManifest = fileURLToPath(new URL('../data/compromised-npm-packages.json', import.meta.url));

type CliOptions = {
  root: string;
  manifest: string;
  cacheFile: string;
  useCache: boolean;
  clearCache: boolean;
};

export type CliIo = {
  stdout: (message: string) => void;
  stderr: (message: string) => void;
};

const processIo: CliIo = {
  stdout: (message) => console.log(message),
  stderr: (message) => console.error(message),
};

export async function runCli(argv: string[], io: CliIo = processIo): Promise<number> {
  let options: CliOptions;
  try {
    const parsed = parseArguments(argv);
    if (parsed.action === 'help') {
      io.stdout(helpText());
      return 0;
    }
    if (parsed.action === 'version') {
      io.stdout(packageVersion);
      return 0;
    }
    options = parsed.options;
  } catch (error) {
    io.stderr(`Input error: ${errorMessage(error)}`);
    io.stderr('Run npm-compromise-scan --help for usage.');
    return 2;
  }

  let pairs;
  try {
    pairs = await loadManifest(options.manifest);
  } catch (error) {
    io.stderr(`Configuration error: ${errorMessage(error)}`);
    return 2;
  }

  if (options.clearCache) {
    await clearCache(options.cacheFile);
    io.stdout(`Cleared cache: ${options.cacheFile}`);
  }

  phase(io, `Scanning ${options.root}`);
  const startedAt = performance.now();
  const cachePromise = options.useCache ? readCachedFiles(options.cacheFile, options.root) : Promise.resolve([]);
  const discoveryPromise = discoverCandidateFiles(options.root);
  const cachedFiles = await cachePromise;
  const allResults: FileScanResult[] = [];

  if (cachedFiles.length > 0) {
    io.stdout(`Scanning ${cachedFiles.length} cached candidate file(s) while filesystem discovery runs...`);
    const cachedResults = await scanFiles(cachedFiles, pairs);
    allResults.push(...cachedResults);
    printScanResults(cachedResults, io);
  } else {
    io.stdout('No cached candidate files; filesystem discovery is running...');
  }

  const discovery = await discoveryPromise;
  const cachedSet = new Set(cachedFiles);
  const newlyDiscoveredFiles = discovery.files.filter((file) => !cachedSet.has(file));
  io.stdout(
    `Discovery found ${discovery.files.length} candidate file(s) in ${discovery.scannedDirectories} directories` +
      `${discovery.unreadableDirectories > 0 ? `; ${discovery.unreadableDirectories} directories were inaccessible` : ''}.`,
  );

  if (newlyDiscoveredFiles.length > 0) {
    io.stdout(`Scanning ${newlyDiscoveredFiles.length} newly discovered candidate file(s)...`);
    const discoveredResults = await scanFiles(newlyDiscoveredFiles, pairs);
    allResults.push(...discoveredResults);
    printScanResults(discoveredResults, io);
  }

  if (options.useCache) {
    try {
      await writeCachedFiles(options.cacheFile, options.root, discovery.files);
      io.stdout(`Updated candidate cache: ${options.cacheFile}`);
    } catch (error) {
      io.stderr(`[WARN] Could not update cache: ${errorMessage(error)}`);
    }
  }

  const matches = allResults.filter((result) => result.matches.length > 0);
  const unreadableFiles = allResults.filter((result) => result.error);
  const missingCachedFiles = allResults.filter((result) => result.missing).length;
  const fallbackFiles = allResults.filter((result) => result.fallbackWarning).length;
  const elapsedSeconds = ((performance.now() - startedAt) / 1_000).toFixed(2);

  io.stdout('');
  io.stdout(`Configured package/version pairs: ${pairs.length}`);
  if (fallbackFiles > 0) io.stdout(`Fallbacks: ${fallbackFiles} malformed JSON file(s) scanned as text.`);
  if (missingCachedFiles > 0) io.stdout(`Removed ${missingCachedFiles} stale path(s) from the refreshed cache.`);
  if (unreadableFiles.length > 0) io.stdout(`Warnings: ${unreadableFiles.length} file(s) could not be scanned.`);
  io.stdout(`Completed in ${elapsedSeconds}s.`);

  if (matches.length > 0) {
    io.stdout(`Found configured compromised package versions in ${matches.length} file(s).`);
    return 1;
  }

  if (unreadableFiles.length > 0) {
    io.stdout('Scan incomplete; no clean result can be reported.');
    return 2;
  }

  io.stdout('No configured compromised package versions found.');
  return 0;
}

function printScanResults(results: FileScanResult[], io: CliIo): void {
  for (const result of results) {
    if (result.fallbackWarning) io.stderr(`[WARN] ${result.file}: ${result.fallbackWarning}`);
    if (result.error) io.stderr(`[WARN] ${result.file}: ${result.error}`);
    if (result.matches.length === 0) continue;

    io.stdout('');
    io.stdout(`[MATCH][${result.kind}] ${result.file}`);
    for (const match of result.matches) {
      io.stdout(`  ${match.pair.name}@${match.pair.version} (${match.pair.incidents.join(', ')})`);
      io.stdout(`    ${match.evidence}`);
    }
  }
}

function parseArguments(
  argv: string[],
): { action: 'scan'; options: CliOptions } | { action: 'help' } | { action: 'version' } {
  const options: CliOptions = {
    root: defaultScanRoot(),
    manifest: defaultManifest,
    cacheFile: defaultCacheFile(),
    useCache: true,
    clearCache: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') return { action: 'help' };
    if (argument === '-v' || argument === '--version') return { action: 'version' };
    if (argument === '--no-cache') {
      options.useCache = false;
      continue;
    }
    if (argument === '--clear-cache') {
      options.clearCache = true;
      continue;
    }

    if (argument === '--root' || argument === '--manifest' || argument === '--cache-file') {
      const value = argv[index + 1];
      if (!value) throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === '--root') options.root = path.resolve(value);
      if (argument === '--manifest') options.manifest = path.resolve(value);
      if (argument === '--cache-file') options.cacheFile = path.resolve(value);
      continue;
    }

    throw new Error(`Unknown argument: ${argument}`);
  }

  return { action: 'scan', options };
}

function defaultScanRoot(): string {
  if (process.platform === 'win32') {
    return process.env.SystemDrive ? `${process.env.SystemDrive}${path.sep}` : path.parse(process.cwd()).root;
  }
  return path.parse(process.cwd()).root;
}

function phase(io: CliIo, message: string): void {
  const timestamp = new Date().toLocaleTimeString('en-GB', { hour12: false });
  io.stdout(`\n[${timestamp}] ${message}`);
}

function helpText(): string {
  return `Usage: npm-compromise-scan [options]

Scans package manifests and npm, Yarn, pnpm, and Bun lockfiles for exact
package/version pairs from a vulnerability manifest.

Options:
  --root <path>        Scan root (default: current system drive/root)
  --manifest <path>    Custom vulnerability manifest
  --cache-file <path>  Custom candidate inventory cache
  --no-cache           Disable reading and writing the inventory cache
  --clear-cache        Clear the inventory cache before scanning
  -h, --help           Show help
  -v, --version        Show version

Exit codes:
  0  No configured compromised versions found
  1  At least one configured compromised version found
  2  Invalid input or an incomplete scan`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
