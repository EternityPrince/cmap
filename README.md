# cmaper

`cmaper` is a snapshot-first network survey CLI in C with:

- scan execution (`nmap` discovery + detail)
- XML artifacts per session
- SQLite persistent history
- analytics modes (`sessions`, `session`, `diff`, `timeline`, `devices`, `device`, `posture`)
- output layer (`terminal`, `markdown`, `json`, `file:<path>`, `clipboard`)

## Build

```sh
make clean
make -j4
```

Alternative:

```sh
cmake -S . -B build
cmake --build build
```

## Quick Start

```sh
./build/cmaper --help
./build/cmaper --version
./build/cmaper check
./build/cmaper scan --target 10.0.0.0/24 --profile mid
./build/cmaper sessions --limit 20
```

## Output Layer

Global output controls:

- `--format terminal|markdown|json`
- `--view compact|full`
- `--output terminal|clipboard|file:<path>`

Examples:

```sh
./build/cmaper sessions --format markdown
./build/cmaper diff <old> <new> --view full
./build/cmaper devices <session> --format json --output file:/tmp/devices.json
./build/cmaper posture <session> --output clipboard
```

Notes:

- ANSI styling is used only for TTY terminal output.
- File and clipboard outputs are plain text/markdown/json without ANSI escapes.
- Clipboard copy failure is non-fatal (report is printed to stdout fallback).

## Delete Flows

- `delete-session <session-id>`
- `delete-all-sessions`

Safety behavior:

- interactive TTY is required
- user must type exactly `y` to confirm
- after delete, metadata rebuild/orphan cleanup runs for devices/networks

## Install Scripts

```sh
./scripts/install.sh
./scripts/uninstall.sh
./scripts/reinstall.sh
./scripts/reinstall.sh --backup
```

Optional for backup location override:

```sh
CMAPER_BACKUP_DIR=/tmp/cmaper-backups ./scripts/reinstall.sh --backup
```

Install to custom directories and expose command as `cmap`:

```sh
./scripts/install.sh \
  --install-root /opt/cmaper \
  --bin-dir /usr/local/bin \
  --data-dir /var/lib/cmaper \
  --cmd-name cmap
```

Termux scaffold:

```sh
./scripts/termux/install.sh
```

## Environment Variables

- `NMAPER_NMAP_BIN`
- `NMAPER_NMAP_SCRIPTS_DIR`
- `NMAPER_DB_PATH`
- `NMAPER_XML_OUTPUT_DIR`
- `NMAPER_DATA_DIR`

(`CMAPER_*` compatibility aliases are supported for runtime path variables.)

## E2E Fake Nmap Scenario

Run deterministic end-to-end flow (2 scans + sessions/diff/devices/timeline/posture):

```sh
tests/e2e/run_fake_nmap_scenario.sh
```

Keep artifacts:

```sh
tests/e2e/run_fake_nmap_scenario.sh --keep
```
