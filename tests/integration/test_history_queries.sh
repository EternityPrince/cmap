#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN=${CMAPER_BIN:-"$REPO_ROOT/build/cmaper"}

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN. Build project first." >&2
    exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}/cmaper-itest-history-$$
mkdir -p "$TMP_ROOT/data" "$TMP_ROOT/scripts" "$TMP_ROOT/out"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

export NMAPER_DATA_DIR="$TMP_ROOT/data"
export NMAPER_DB_PATH="$TMP_ROOT/data/cmaper.db"
export NMAPER_XML_OUTPUT_DIR="$TMP_ROOT/data/xml"
export NMAPER_NMAP_BIN="$SCRIPT_DIR/../e2e/fake-nmap.sh"
export NMAPER_NMAP_SCRIPTS_DIR="$TMP_ROOT/scripts"

run_quiet() {
    "$BIN" -q -q -q -q "$@"
}

assert_contains() {
    file=$1
    pattern=$2
    if ! grep -q "$pattern" "$file"; then
        echo "Expected pattern '$pattern' in $file" >&2
        cat "$file" >&2
        exit 1
    fi
}

CMAPER_FAKE_ROUND=1 run_quiet scan --target 10.0.0.0/24 --profile mid --no-ping >"$TMP_ROOT/out/scan1.txt"
CMAPER_FAKE_ROUND=2 run_quiet scan --target 10.0.0.0/24 --profile mid --no-ping >"$TMP_ROOT/out/scan2.txt"

run_quiet sessions --limit 2 >"$TMP_ROOT/out/sessions.txt"
SESSION_NEW=$(awk '/^  session-/{print $1}' "$TMP_ROOT/out/sessions.txt" | sed -n '1p')
SESSION_OLD=$(awk '/^  session-/{print $1}' "$TMP_ROOT/out/sessions.txt" | sed -n '2p')

if [ -z "$SESSION_NEW" ] || [ -z "$SESSION_OLD" ]; then
    echo "Failed to extract session ids from sessions output" >&2
    cat "$TMP_ROOT/out/sessions.txt" >&2
    exit 1
fi

run_quiet sessions --limit 2 --format json >"$TMP_ROOT/out/sessions.json"
assert_contains "$TMP_ROOT/out/sessions.json" "$SESSION_NEW"

run_quiet session --session "$SESSION_NEW" --format json >"$TMP_ROOT/out/session.json"
assert_contains "$TMP_ROOT/out/session.json" "\"hosts\""

run_quiet diff --from "$SESSION_OLD" --to "$SESSION_NEW" --format json >"$TMP_ROOT/out/diff.json"
assert_contains "$TMP_ROOT/out/diff.json" "$SESSION_OLD"
assert_contains "$TMP_ROOT/out/diff.json" "$SESSION_NEW"
assert_contains "$TMP_ROOT/out/diff.json" "\"alerts\""

run_quiet devices --session "$SESSION_NEW" --format json >"$TMP_ROOT/out/devices.json"
assert_contains "$TMP_ROOT/out/devices.json" "$SESSION_NEW"
assert_contains "$TMP_ROOT/out/devices.json" "\"items\""

run_quiet timeline --session "$SESSION_NEW" --format json >"$TMP_ROOT/out/timeline.json"
assert_contains "$TMP_ROOT/out/timeline.json" "$SESSION_NEW"
assert_contains "$TMP_ROOT/out/timeline.json" "\"items\""

run_quiet posture --session "$SESSION_NEW" --format json >"$TMP_ROOT/out/posture.json"
assert_contains "$TMP_ROOT/out/posture.json" "$SESSION_NEW"
assert_contains "$TMP_ROOT/out/posture.json" "\"alerts\""

echo "test_history_queries: ok"
