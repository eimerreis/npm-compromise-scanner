import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pairKey } from './manifest.js';
import type { FileScanResult, Match, VulnerabilityPair } from './types.js';

type JsonRecord = Record<string, unknown>;

export async function scanFiles(
  files: string[],
  pairs: VulnerabilityPair[],
  concurrency = 32,
): Promise<FileScanResult[]> {
  const results = new Array<FileScanResult>(files.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < files.length) {
      const index = nextIndex;
      nextIndex += 1;
      const file = files[index];
      if (file) results[index] = await scanFile(file, pairs);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, files.length) }, worker));
  return results;
}

export async function scanFile(file: string, pairs: VulnerabilityPair[]): Promise<FileScanResult> {
  const base = path.basename(file);
  const jsonFile = base === 'package.json' || base === 'package-lock.json' || base === 'npm-shrinkwrap.json';
  const kind = base === 'package.json' ? 'manifest exact' : 'resolved';

  try {
    if (!jsonFile) return { file, kind, matches: await scanTextLock(file, pairs) };

    try {
      const matches =
        base === 'package.json'
          ? scanPackageManifest(await readJson(file), pairs)
          : scanPackageLock(await readJson(file), pairs);
      return { file, kind, matches };
    } catch (error) {
      const matches = await scanMalformedJson(file, pairs);
      return {
        file,
        kind: `${kind} text fallback`,
        matches,
        fallbackWarning: `${errorMessage(error)}; scanned with tolerant text fallback`,
      };
    }
  } catch (error) {
    if (isMissingFile(error)) return { file, kind, matches: [], missing: true };
    return { file, kind, matches: [], error: errorMessage(error) };
  }
}

async function readJson(file: string): Promise<JsonRecord> {
  const value: unknown = JSON.parse(await readFile(file, 'utf8'));
  if (!isRecord(value)) throw new Error('JSON root is not an object');
  return value;
}

function scanPackageLock(lock: JsonRecord, pairs: VulnerabilityPair[]): Match[] {
  const pairMap = createPairMap(pairs);
  const matches = new Map<string, Match>();

  if (isRecord(lock.packages)) {
    for (const [packagePath, packageData] of Object.entries(lock.packages)) {
      if (!isRecord(packageData)) continue;
      const name = packagePath === '' ? stringValue(lock.name) : packageNameFromPath(packagePath);
      addPair(matches, pairMap, name, stringValue(packageData.version), packagePath || `${name}`);
    }
  }

  scanDependencyTree(lock.dependencies, matches, pairMap);
  return [...matches.values()];
}

function scanDependencyTree(
  dependencies: unknown,
  matches: Map<string, Match>,
  pairMap: Map<string, VulnerabilityPair>,
  prefix = '',
): void {
  if (!isRecord(dependencies)) return;

  for (const [name, dependency] of Object.entries(dependencies)) {
    if (!isRecord(dependency)) continue;
    const version = stringValue(dependency.version);
    addPair(matches, pairMap, name, version, `${prefix}${name}@${version}`);
    scanDependencyTree(dependency.dependencies, matches, pairMap, `${prefix}${name} > `);
  }
}

function scanPackageManifest(packageJson: JsonRecord, pairs: VulnerabilityPair[]): Match[] {
  const pairMap = createPairMap(pairs);
  const matches = new Map<string, Match>();
  const packageName = stringValue(packageJson.name);
  const packageVersion = stringValue(packageJson.version);
  addPair(matches, pairMap, packageName, packageVersion, `${packageName}@${packageVersion}`);

  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = packageJson[field];
    if (!isRecord(dependencies)) continue;

    for (const [name, value] of Object.entries(dependencies)) {
      const requestedVersion = stringValue(value);
      if (!requestedVersion) continue;
      addPair(matches, pairMap, name, requestedVersion, `${field}.${name} = ${requestedVersion}`);

      const aliasMatch = requestedVersion.match(/^npm:(@?[^@]+(?:\/[^@]+)?)@(.+)$/);
      if (aliasMatch?.[1] && aliasMatch[2]) {
        addPair(matches, pairMap, aliasMatch[1], aliasMatch[2], `${field}.${name} = ${requestedVersion}`);
      }
    }
  }

  return [...matches.values()];
}

async function scanTextLock(file: string, pairs: VulnerabilityPair[]): Promise<Match[]> {
  const content = (await readFile(file)).toString('utf8');
  const lines = content.split(/\r?\n/);
  const blocks = content.split(/\r?\n\s*\r?\n/);
  const matches = new Map<string, Match>();

  for (const pair of pairs) {
    const nameRegex = packagePattern(pair.name);
    const versionRegex = versionPattern(pair.version);
    let evidence: string | undefined;

    for (const [index, line] of lines.entries()) {
      if (nameRegex.test(line) && versionRegex.test(line)) {
        evidence = `line ${index + 1}: ${line.trim()}`;
        break;
      }
    }

    if (!evidence) {
      for (const block of blocks) {
        const blockLines = block.split(/\r?\n/);
        const header = blockLines[0] ?? '';
        const versionLine = blockLines.find((line) => /^\s*version\s*[: ]/.test(line));
        if (versionLine && nameRegex.test(header) && versionRegex.test(versionLine)) {
          evidence = `${header.trim()} | ${versionLine.trim()}`;
          break;
        }
      }
    }

    if (evidence) matches.set(pairKey(pair.name, pair.version), { pair, evidence });
  }

  return [...matches.values()];
}

async function scanMalformedJson(file: string, pairs: VulnerabilityPair[]): Promise<Match[]> {
  const content = await readFile(file, 'utf8');
  const matches = new Map<string, Match>();

  for (const pair of pairs) {
    const name = escapeRegex(pair.name);
    const version = escapeRegex(pair.version);
    const declaration = new RegExp(`"${name}"\\s*:\\s*"${version}"`);
    const packageEntry = new RegExp(
      `"(?:[^"\\r\\n]*/)?(?:node_modules/)?${name}"\\s*:\\s*\\{\\s*"version"\\s*:\\s*"${version}"`,
    );
    const packageMetadata = new RegExp(
      `"name"\\s*:\\s*"${name}"[\\s\\S]{0,500}?"version"\\s*:\\s*"${version}"`,
    );

    if (declaration.test(content) || packageEntry.test(content) || packageMetadata.test(content)) {
      matches.set(pairKey(pair.name, pair.version), {
        pair,
        evidence: 'matched by tolerant text fallback after JSON parse failure',
      });
    }
  }

  return [...matches.values()];
}

function addPair(
  matches: Map<string, Match>,
  pairs: Map<string, VulnerabilityPair>,
  name: string | undefined,
  version: string | undefined,
  evidence: string,
): void {
  if (!name || !version) return;
  const key = pairKey(name, version);
  const pair = pairs.get(key);
  if (pair && !matches.has(key)) matches.set(key, { pair, evidence });
}

function createPairMap(pairs: VulnerabilityPair[]): Map<string, VulnerabilityPair> {
  return new Map(pairs.map((pair) => [pairKey(pair.name, pair.version), pair]));
}

function packageNameFromPath(packagePath: string): string | undefined {
  return packagePath.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/)?.[1];
}

function packagePattern(name: string): RegExp {
  return new RegExp(`(^|[^A-Za-z0-9._@/-])${escapeRegex(name)}(?=$|[@/:"'\\s])`);
}

function versionPattern(version: string): RegExp {
  return new RegExp(`(^|[^0-9A-Za-z.-])${escapeRegex(version)}(?=$|[^0-9A-Za-z.-])`);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
