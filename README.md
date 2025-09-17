# Shai-Halud Dependency Scanner

`scan_shai_halud.py` inspects Node.js projects for packages compromised in the
Shai-Halud npm supply-chain incident. It supports lockfile inspection for
pnpm, npm, and Yarn v1 projects and falls back to CLI inspection when
lockfiles are absent or unreadable.

## How it works

1. Parse the affected package CSV (headers: `Package`, `Versions`) and build a
   mapping of exact package versions to flag.
2. Inspect the current project directory, prioritising lockfiles in the order:
   `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`.
3. If no supported lockfile can be parsed, run a single package manager command
   (`npm ls`, `pnpm list`, or `yarn list`) and parse its JSON output.
4. Compare resolved dependency versions against the CSV and report any matches.

The scanner never installs packages and operates on existing metadata only.

## Usage

```
python scan_shai_halud.py --csv affected.csv --format table
```

```
python scan_shai_halud.py --csv affected.csv --dir ../my-repo --format json --output report.json
```

### Arguments

- `--csv` (required): Path to the affected package CSV file.
- `--dir`: Project root to scan (default: current directory).
- `--format`: Output format, either `table` (default) or `json`.
- `--output`: Write report to a file instead of stdout.
- `--max-depth`: Limit recursion depth for CLI fallback commands (if supported).
- `--verbose`: Print diagnostics about detection strategy and fallbacks.

### Exit codes

- `0` – no flagged packages detected.
- `2` – one or more flagged packages detected (CI should treat as failure).
- `1` – execution error (CSV unreadable, failed lockfile parse, command error).

## Fixtures & Tests

The `tests/fixtures` directory contains minimal lockfiles and a sample CSV for
quick manual validation. Run the unit tests with:

```
python -m unittest discover tests
```
