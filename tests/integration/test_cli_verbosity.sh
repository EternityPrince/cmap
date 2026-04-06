#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN=${CMAPER_BIN:-"$REPO_ROOT/build/cmaper"}

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN. Build project first." >&2
    exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}/cmaper-itest-cli-verbosity-$$
mkdir -p "$TMP_ROOT/data" "$TMP_ROOT/scripts"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

export NMAPER_DATA_DIR="$TMP_ROOT/data"
export NMAPER_DB_PATH="$TMP_ROOT/data/cmaper.db"
export NMAPER_XML_OUTPUT_DIR="$TMP_ROOT/data/xml"
export NMAPER_NMAP_BIN="$SCRIPT_DIR/../e2e/fake-nmap.sh"
export NMAPER_NMAP_SCRIPTS_DIR="$TMP_ROOT/scripts"

"$BIN" check >/dev/null 2>"$TMP_ROOT/default.err" || true
"$BIN" -v check >/dev/null 2>"$TMP_ROOT/verbose.err" || true
"$BIN" -q check >/dev/null 2>"$TMP_ROOT/quiet.err" || true

if grep -q "\\[PHASE\\]" "$TMP_ROOT/default.err"; then
    echo "Default log level unexpectedly includes [PHASE]" >&2
    cat "$TMP_ROOT/default.err" >&2
    exit 1
fi

if ! grep -q "\\[PHASE\\]" "$TMP_ROOT/verbose.err"; then
    echo "Verbose mode should include [PHASE] logs" >&2
    cat "$TMP_ROOT/verbose.err" >&2
    exit 1
fi

if grep -q "\\[WAIT\\]" "$TMP_ROOT/quiet.err"; then
    echo "Quiet mode should hide [WAIT] logs" >&2
    cat "$TMP_ROOT/quiet.err" >&2
    exit 1
fi

echo "test_cli_verbosity: ok"
