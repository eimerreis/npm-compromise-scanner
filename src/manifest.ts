import { readFile } from 'node:fs/promises';
import type { VulnerabilityManifest, VulnerabilityPair } from './types.js';

export async function loadManifest(file: string): Promise<VulnerabilityPair[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot parse manifest ${file}: ${errorMessage(error)}`);
  }

  validateManifest(parsed);
  const pairs = new Map<string, VulnerabilityPair>();

  for (const incident of parsed.incidents) {
    for (const packageEntry of incident.packages) {
      for (const version of packageEntry.versions) {
        const key = pairKey(packageEntry.name, version);
        const pair = pairs.get(key) ?? {
          name: packageEntry.name,
          version,
          incidents: [],
        };
        pair.incidents.push(incident.id);
        pairs.set(key, pair);
      }
    }
  }

  if (pairs.size === 0) throw new Error('Manifest does not contain any package versions');
  return [...pairs.values()];
}

export function pairKey(name: string, version: string): string {
  return `${name}\0${version}`;
}

function validateManifest(value: unknown): asserts value is VulnerabilityManifest {
  if (!isRecord(value) || value.schemaVersion !== 1 || !Array.isArray(value.incidents)) {
    throw new Error('Manifest must contain schemaVersion 1 and an incidents array');
  }

  for (const [incidentIndex, incident] of value.incidents.entries()) {
    if (!isRecord(incident) || typeof incident.id !== 'string' || !Array.isArray(incident.packages)) {
      throw new Error(`Incident ${incidentIndex + 1} must have an id and packages array`);
    }

    for (const [packageIndex, packageEntry] of incident.packages.entries()) {
      if (
        !isRecord(packageEntry) ||
        typeof packageEntry.name !== 'string' ||
        !Array.isArray(packageEntry.versions) ||
        !packageEntry.versions.every((version) => typeof version === 'string' && version.length > 0)
      ) {
        throw new Error(
          `Package ${packageIndex + 1} in incident ${incident.id} must have a name and non-empty string versions`,
        );
      }
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
