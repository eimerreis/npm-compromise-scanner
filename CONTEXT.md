# npm Compromise Scanner

The scanner identifies exact npm package/version pairs associated with supply-chain incidents.

## Language

**Workspace Manifest**:
A vulnerability manifest stored in the current working directory. When present, it replaces the Bundled Manifest for default scans.
_Avoid_: config file, local manifest

**Bundled Manifest**:
The vulnerability manifest shipped with the scanner package.
_Avoid_: default config, built-in config

**Incident ID**:
A machine-readable identifier derived from the required source URL's final path segment for an incident in a Workspace Manifest.
_Avoid_: user-entered incident name, incident label

**Source URL**:
The required advisory URL that makes a Workspace Manifest incident traceable to its report.
_Avoid_: reference link, optional source
