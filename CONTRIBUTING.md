# Contributing to auto-gh

Thanks for helping. This is a Python monorepo with five decoupled packages under `packages/`:
`dns_zone`, `directory_seats`, `catchall_mail`, `seat_allocator`, and `gsuite_seatpool`.

## Setup

Use Python 3.10 or newer. Work from the repository root. Do not use production credentials, real domains, or live infrastructure data for development or tests.

```bash
python3 -m pip install -e ".[dev]"
```

Or run directly against the source tree:

```bash
export PYTHONPATH=packages
```

## Build & test

```bash
# Run the offline unit and integration suite (pytest)
make test

# Run the pre-publish hygiene gate against the working tree and git history
python3 scripts/public-hygiene-gate.py --repo-root .

# Inspect runtime environment and optional dependencies
make doctor
```

All tests must execute 100% offline against the in-memory FastAPI mock server (`packages/gsuite_seatpool/mock_server.py`) and temporary SQLite databases. Never write tests that issue live external network requests.

Keep changes minimal and focused. Prefer the Python standard library and existing helpers over new dependencies. Explain the motivation and validation in your pull request, link relevant issues, and add tests for behavior changes. Follow the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. One logical change per commit. Do not include internal planning markers (`Wave`, `Phase`, `Task`, `ADR`, `SDD`, `YAGNI`) in commit messages or comments.

## Before you push to a public remote

Run the pre-publish hygiene gate from the repository root and inspect its full report:

```bash
python3 scripts/public-hygiene-gate.py --repo-root .
```

The gate scans Git-tracked files, filenames, and commit history for leaked operator identifiers, live infrastructure facts, credential material, non-English strings, and internal planning markers.
