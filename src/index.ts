export { clearCache, defaultCacheFile, readCachedFiles, writeCachedFiles } from './cache.js';
export { runCli } from './cli.js';
export { discoverCandidateFiles } from './discovery.js';
export { loadManifest } from './manifest.js';
export { scanFile, scanFiles } from './scanner.js';
export type { FileScanResult, Match, VulnerabilityManifest, VulnerabilityPair } from './types.js';
