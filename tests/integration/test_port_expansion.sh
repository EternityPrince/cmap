#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN=${CMAPER_BIN:-"$REPO_ROOT/build/cmaper"}

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN. Build project first." >&2
    exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}/cmaper-itest-port-expansion-$$
mkdir -p "$TMP_ROOT/data" "$TMP_ROOT/scripts" "$TMP_ROOT/out"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

export NMAPER_DATA_DIR="$TMP_ROOT/data"
export NMAPER_DB_PATH="$TMP_ROOT/data/cmaper.db"
export NMAPER_XML_OUTPUT_DIR="$TMP_ROOT/data/xml"
export NMAPER_NMAP_BIN="$SCRIPT_DIR/fake-nmap-probe-expand.sh"
export NMAPER_NMAP_SCRIPTS_DIR="$TMP_ROOT/scripts"

run_quiet() {
    "$BIN" -q -q -q -q "$@"
}

run_quiet scan --target 10.0.0.0/24 --profile mid --no-ping >"$TMP_ROOT/out/scan.txt"

run_quiet sessions --limit 1 >"$TMP_ROOT/out/sessions.txt"
SESSION_ID=$(awk '/^  session-/{print $1}' "$TMP_ROOT/out/sessions.txt" | sed -n '1p')

if [ -z "$SESSION_ID" ]; then
    echo "Failed to resolve latest session id" >&2
    cat "$TMP_ROOT/out/sessions.txt" >&2
    exit 1
fi

run_quiet session --session "$SESSION_ID" --format json >"$TMP_ROOT/out/session.json"

if ! grep -q '"primary_ip":"10.0.0.10"' "$TMP_ROOT/out/session.json"; then
    echo "Expected host 10.0.0.10 in session json" >&2
    cat "$TMP_ROOT/out/session.json" >&2
    exit 1
fi

if ! grep -q '"open_tcp_ports":2' "$TMP_ROOT/out/session.json"; then
    echo "Expected expanded open tcp port count (=2) in session json" >&2
    cat "$TMP_ROOT/out/session.json" >&2
    exit 1
fi

echo "test_port_expansion: ok"
