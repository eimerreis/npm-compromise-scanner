# @eimerreis/npm-compromise-scanner

Cross-platform CLI that scans package manifests and npm, Yarn, pnpm, and Bun lockfiles for exact package/version pairs associated with npm supply-chain incidents.

## Usage

```bash
npx @eimerreis/npm-compromise-scanner
```

The default scan root is `/` on macOS/Linux and the system drive on Windows. Full-machine scans may require an elevated shell.

```bash
sudo npx @eimerreis/npm-compromise-scanner
```

Options:

```text
--root <path>        Scan a specific root
--manifest <path>    Use a custom vulnerability manifest
--cache-file <path>  Use a custom candidate inventory cache
--no-cache           Disable the candidate inventory cache
--clear-cache        Clear the cache before scanning
-h, --help           Show help
-v, --version        Show version
```

## Candidate cache

The first run discovers package manifests and lockfiles across the selected root and stores only their paths in the OS cache directory. Later runs scan those cached paths immediately while refreshing the filesystem inventory in parallel. Newly discovered files are scanned after discovery, and stale paths are removed from the cache.

Default cache locations:

```text
macOS    ~/Library/Caches/npm-compromise-scanner/inventory.json
Linux    $XDG_CACHE_HOME/npm-compromise-scanner/inventory.json
         or ~/.cache/npm-compromise-scanner/inventory.json
Windows  %LOCALAPPDATA%\npm-compromise-scanner\cache\inventory.json
```

## Workspace Manifest

Create a local manifest interactively:

```bash
npm-compromise-scan init
```

This writes `./npm-compromise-scanner.json`. A scan run from that directory uses it instead of the bundled manifest. Use `--output <path>` to choose another location, and `--force` to replace an existing output file.

Coding agents and scripts can create the same manifest without prompts after extracting exact pairs from an advisory:

```bash
npm-compromise-scan init \
  --source https://example.com/advisory \
  --package keyv@6.0.0 \
  --package @cacheable/memory@2.2.1
```

Repeat `--package` for each affected pair. Scoped packages are supported.

```bash
npm-compromise-scan --manifest ./other-manifest.json
```

An explicit `--manifest` always takes precedence over the Workspace Manifest.

## Custom manifest

```json
{
  "schemaVersion": 1,
  "incidents": [
    {
      "id": "incident-id",
      "source": "https://example.com/advisory",
      "packages": [
        {
          "name": "package-name",
          "versions": ["1.2.3"]
        }
      ]
    }
  ]
}
```

## Exit codes

```text
0  No configured compromised versions found
1  At least one configured compromised version found
2  Invalid input or an incomplete scan
```

## Development

The package uses Node.js at runtime, `tsx` for TypeScript development/tests, and `tsc` for publishing JavaScript. Bun is not required.

```bash
npm install
npm test
npm run check
npm run build
npm run dev -- --root /path/to/scan
```

## Releasing

Record the release intent and push it to `main`:

```bash
npm run changeset
git add .changeset
git commit -m "chore: add release changeset"
git push
```

The release workflow verifies the package, applies the pending changeset, publishes through npm trusted publishing, commits the version update, and creates the corresponding GitHub release.
