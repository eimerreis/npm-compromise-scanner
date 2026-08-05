export type Incident = {
  id: string;
  published?: string;
  source?: string;
  packages: Array<{
    name: string;
    versions: string[];
  }>;
};

export type VulnerabilityManifest = {
  schemaVersion: 1;
  incidents: Incident[];
};

export type VulnerabilityPair = {
  name: string;
  version: string;
  incidents: string[];
};

export type Match = {
  pair: VulnerabilityPair;
  evidence: string;
};

export type FileScanResult = {
  file: string;
  kind: string;
  matches: Match[];
  fallbackWarning?: string;
  missing?: boolean;
  error?: string;
};
