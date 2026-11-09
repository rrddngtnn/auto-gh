# Security policy

`auto-gh` provisions DNS records, directory user credentials, and inbound catch-all verification messages. Treat any issue touching credential storage or authentication handling as sensitive.

## Reporting a vulnerability

Please report security issues **privately**, not through public issues or pull requests.

- Open a private vulnerability report via the repository's GitHub Security Advisories tab, or
- Contact the maintainer through the address listed on the repository profile.

Include: affected component, a minimal reproduction, and the impact you observed. You will receive an acknowledgement; please allow a reasonable window for a fix before any public disclosure.

## Handling of secrets

- Generated seat passwords, exported Admin Console CSV files (`csv_out/`), and local SQLite databases (`*.db`, `*.sqlite`) contain credential material and are gitignored by default.
- `.env` is gitignored. Only `.env.example` (containing loopback and `.test` placeholder values) is tracked.
- The pre-publish hygiene gate (`scripts/public-hygiene-gate.py`) scans tracked files, filenames, and reachable commit history for leaked credentials, private keys, non-RFC5737 IPv4 addresses, and operator-specific identifiers. Run it before pushing to any public remote.

## Scope

In scope: credential disclosure, SQL injection in state persistence, path traversal in CSV export or MIME ingestion, and leakage of stored tokens.

Out of scope: issues that require a pre-compromised host or physical access to the deployment.
