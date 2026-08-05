import { existsSync, readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { clearCache, defaultCacheFile, readCachedFiles, writeCachedFiles } from './cache.js';
import { discoverCandidateFiles } from './discovery.js';
import { loadManifest } from './manifest.js';
import { scanFiles } from './scanner.js';
import type { FileScanResult, VulnerabilityManifest } from './types.js';

const packageMetadata: unknown = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const packageVersion =
  typeof packageMetadata === 'object' &&
  packageMetadata !== null &&
  'version' in packageMetadata &&
  typeof packageMetadata.version === 'string'
    ? packageMetadata.version
    : 'unknown';
const bundledManifest = fileURLToPath(new URL('../data/compromised-npm-packages.json', import.meta.url));
const workspaceManifestFilename = 'npm-compromise-scanner.json';

type ScanOptions = {
  root: string;
  manifest?: string;
  cacheFile: string;
  useCache: boolean;
  clearCache: boolean;
};

type InitOptions = {
  output: string;
  force: boolean;
  source?: string;
  packageSpecs: string[];
};

type PackageEntry = VulnerabilityManifest['incidents'][number]['packages'][number];

export type CliIo = {
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  prompt?: (message: string) => Promise<string>;
};

const processIo: CliIo = {
  stdout: (message) => console.log(message),
  stderr: (message) => console.error(message),
};

export async function runCli(argv: string[], io: CliIo = processIo): Promise<number> {
  let parsed: ReturnType<typeof parseArguments>;
  try {
    parsed = parseArguments(argv);
  } catch (error) {
    io.stderr(`Input error: ${errorMessage(error)}`);
    io.stderr('Run npm-compromise-scan --help for usage.');
    return 2;
  }

  if (parsed.action === 'help') {
    io.stdout(helpText(parsed.topic));
    return 0;
  }
  if (parsed.action === 'version') {
    io.stdout(packageVersion);
    return 0;
  }
  if (parsed.action === 'init') return runInit(parsed.options, io);

  return runScan(parsed.options, io);
}

async function runScan(options: ScanOptions, io: CliIo): Promise<number> {
  const manifest = options.manifest ?? defaultManifest();
  let pairs;
  try {
    pairs = await loadManifest(manifest);
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

async function runInit(options: InitOptions, io: CliIo): Promise<number> {
  if (existsSync(options.output) && !options.force) {
    io.stderr(`Configuration error: ${options.output} already exists. Use init --force to overwrite it.`);
    return 2;
  }
  const terminalPrompt = options.source || io.prompt ? undefined : createTerminalPrompt();
  const interactiveIo = { prompt: io.prompt ?? terminalPrompt?.prompt };

  try {
    const source = options.source ?? (await askForSourceUrl(requirePrompt(interactiveIo)));
    if (!incidentSlug(source)) throw new Error('A source URL with a path slug is required');
    const packages = options.source ? packagesFromSpecs(options.packageSpecs) : await askForPackages(requirePrompt(interactiveIo));
    const manifest: VulnerabilityManifest = {
      schemaVersion: 1,
      incidents: [
        {
          id: `custom-${incidentSlug(source)}`,
          source,
          packages,
        },
      ],
    };

    await mkdir(path.dirname(options.output), { recursive: true });
    await writeFile(options.output, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    io.stdout(`Created workspace manifest: ${options.output}`);
    io.stdout(`Scan with: npm-compromise-scan --manifest ${options.output}`);
    return 0;
  } catch (error) {
    const signal = terminalPrompt?.interrupted();
    if (signal) {
      io.stderr(`Interactive setup cancelled by ${signal}.`);
      return signal === 'SIGINT' ? 130 : 143;
    }
    io.stderr(`Input error: ${errorMessage(error)}`);
    return 2;
  } finally {
    terminalPrompt?.close();
  }
}

type TerminalPrompt = {
  prompt: (message: string) => Promise<string>;
  close: () => void;
  interrupted: () => NodeJS.Signals | undefined;
};

function createTerminalPrompt(): TerminalPrompt {
  const readline = createInterface({ input: process.stdin });
  const lines: string[] = [];
  let waitForLine: (() => void) | undefined;
  let closed = false;
  let signal: NodeJS.Signals | undefined;
  const wake = () => {
    waitForLine?.();
    waitForLine = undefined;
  };
  const interrupt = (receivedSignal: NodeJS.Signals) => {
    signal = receivedSignal;
    closed = true;
    readline.close();
    wake();
  };
  const onSigint = () => interrupt('SIGINT');
  const onSigterm = () => interrupt('SIGTERM');

  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  readline.on('line', (line) => {
    lines.push(line);
    wake();
  });
  readline.on('close', () => {
    closed = true;
    wake();
  });

  return {
    prompt: async (message) => {
      process.stdout.write(message);
      while (lines.length === 0 && !closed) {
        await new Promise<void>((resolve) => {
          waitForLine = resolve;
        });
      }
      return lines.shift() ?? '';
    },
    close: () => {
      process.off('SIGINT', onSigint);
      process.off('SIGTERM', onSigterm);
      readline.close();
    },
    interrupted: () => signal,
  };
}

function requirePrompt(io: Pick<CliIo, 'prompt'>): Required<Pick<CliIo, 'prompt'>> {
  if (!io.prompt) throw new Error('Interactive input is unavailable');
  return { prompt: io.prompt };
}

function packagesFromSpecs(specs: string[]): PackageEntry[] {
  const packages = new Map<string, string[]>();

  for (const spec of specs) {
    const separator = spec.lastIndexOf('@');
    const name = spec.slice(0, separator);
    const version = spec.slice(separator + 1);
    if (separator <= 0 || !name || !version) {
      throw new Error(`--package must use package@exact-version: ${spec}`);
    }
    const versions = packages.get(name) ?? [];
    if (!versions.includes(version)) versions.push(version);
    packages.set(name, versions);
  }

  if (packages.size === 0) throw new Error('At least one --package is required with --source');
  return [...packages].map(([name, versions]) => ({ name, versions }));
}

async function askForSourceUrl(io: Required<Pick<CliIo, 'prompt'>>): Promise<string> {
  const source = (await io.prompt('Advisory source URL: ')).trim();
  const slug = incidentSlug(source);
  if (!slug) throw new Error('A source URL with a path slug is required');
  return source;
}

async function askForPackages(
  io: Required<Pick<CliIo, 'prompt'>>,
): Promise<PackageEntry[]> {
  const packages: PackageEntry[] = [];

  do {
    const name = (await io.prompt('Compromised package name: ')).trim();
    if (!name) throw new Error('A package name is required');

    const versions = (await io.prompt('Exact compromised version(s), comma-separated: '))
      .split(',')
      .map((version) => version.trim())
      .filter(Boolean);
    if (versions.length === 0) throw new Error('At least one exact version is required');
    packages.push({ name, versions: [...new Set(versions)] });
  } while (/^y(es)?$/i.test((await io.prompt('Add another package? [y/N]: ')).trim()));

  return packages;
}

function defaultManifest(): string {
  const workspaceManifest = path.resolve(workspaceManifestFilename);
  return existsSync(workspaceManifest) ? workspaceManifest : bundledManifest;
}

function incidentSlug(source: string): string {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return '';
  }

  const segment = url.pathname.split('/').filter(Boolean).at(-1);
  return segment?.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') ?? '';
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
):
  | { action: 'scan'; options: ScanOptions }
  | { action: 'init'; options: InitOptions }
  | { action: 'help'; topic?: 'init' }
  | { action: 'version' } {
  if (argv[0] === 'init') return parseInitArguments(argv.slice(1));
  if (argv[0] === 'help') {
    if (argv.length === 1) return { action: 'help' };
    if (argv.length === 2 && argv[1] === 'init') return { action: 'help', topic: 'init' };
    throw new Error(`Unknown help topic: ${argv[1] ?? ''}`);
  }
  if (argv.includes('-h') || argv.includes('--help')) return { action: 'help' };
  if (argv.includes('-v') || argv.includes('--version')) return { action: 'version' };

  const options: ScanOptions = {
    root: defaultScanRoot(),
    cacheFile: defaultCacheFile(),
    useCache: true,
    clearCache: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
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

function parseInitArguments(
  argv: string[],
): { action: 'init'; options: InitOptions } | { action: 'help'; topic?: 'init' } {
  if (argv.includes('-h') || argv.includes('--help')) return { action: 'help', topic: 'init' };
  const options: InitOptions = { output: path.resolve(workspaceManifestFilename), force: false, packageSpecs: [] };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--force') {
      options.force = true;
      continue;
    }
    if (argument === '--output' || argument === '--source' || argument === '--package') {
      const value = argv[index + 1];
      if (!value) throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === '--output') options.output = path.resolve(value);
      if (argument === '--source') options.source = value;
      if (argument === '--package') options.packageSpecs.push(value);
      continue;
    }
    throw new Error(`Unknown init argument: ${argument}`);
  }

  if ((options.source === undefined) !== (options.packageSpecs.length === 0)) {
    throw new Error('Use --source and at least one --package together');
  }

  return { action: 'init', options };
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

function helpText(topic?: 'init'): string {
  if (topic === 'init') {
    return `Usage: npm-compromise-scan init [options]

Create a Workspace Manifest for package/version pairs from an advisory.

Prompts:
  Advisory source URL     Required; used to derive the incident ID
  Compromised package     Package name to match
  Exact version(s)        One or more comma-separated versions

Options:
  --output <path>      Output file (default: ./${workspaceManifestFilename})
  --force              Overwrite an existing output file
  --source <url>       Create non-interactively from this advisory URL
  --package <name@version>
                        Add an exact compromised version; repeat as needed

Examples:
  npm-compromise-scan init
  npm-compromise-scan init --source https://example.com/advisory \\
    --package keyv@6.0.0 --package @cacheable/memory@2.2.1
  npm-compromise-scan --root ./my-project

The scan uses ./${workspaceManifestFilename} in the current directory unless
--manifest <path> is provided.`;
  }

  return `Usage: npm-compromise-scan [options]
       npm-compromise-scan init [options]

Scans package manifests and npm, Yarn, pnpm, and Bun lockfiles for exact
package/version pairs from a vulnerability manifest.

Scan options:
  --root <path>        Scan root (default: current system drive/root)
  --manifest <path>    Custom vulnerability manifest
  --cache-file <path>  Custom candidate inventory cache
  --no-cache           Disable reading and writing the inventory cache
  --clear-cache        Clear the inventory cache before scanning

Init options:
  --output <path>      Workspace Manifest output (default: ./${workspaceManifestFilename})
  --force              Overwrite an existing output file

Without --manifest, a ./${workspaceManifestFilename} in the current directory
replaces the bundled manifest.

Getting started:
  npm-compromise-scan help init   Create a Workspace Manifest interactively
  npm-compromise-scan init        Create it now
  npm-compromise-scan --root .    Scan the current project

General options:
  help [init]          Show general or init-specific help
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
