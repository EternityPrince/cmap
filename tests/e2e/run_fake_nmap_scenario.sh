#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN="$REPO_ROOT/build/cmaper"
KEEP=0

for arg in "$@"; do
    case "$arg" in
        --keep)
            KEEP=1
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--keep]" >&2
            exit 2
            ;;
    esac
done

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN. Run 'make' first." >&2
    exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}/cmaper-e2e-$$
mkdir -p "$TMP_ROOT"

cleanup() {
    if [ "$KEEP" -eq 0 ]; then
        rm -rf "$TMP_ROOT"
    else
        echo "E2E artifacts kept at: $TMP_ROOT"
    fi
}
trap cleanup EXIT INT TERM

DATA_DIR="$TMP_ROOT/data"
SCRIPTS_DIR="$TMP_ROOT/nmap-scripts"
OUT_DIR="$TMP_ROOT/out"
mkdir -p "$DATA_DIR" "$SCRIPTS_DIR" "$OUT_DIR"

export NMAPER_DATA_DIR="$DATA_DIR"
export NMAPER_DB_PATH="$DATA_DIR/cmaper.db"
export NMAPER_XML_OUTPUT_DIR="$DATA_DIR/xml"
export NMAPER_NMAP_BIN="$SCRIPT_DIR/fake-nmap.sh"
export NMAPER_NMAP_SCRIPTS_DIR="$SCRIPTS_DIR"

run_quiet() {
    "$BIN" -q -q -q -q "$@"
}

echo "== fake-nmap round 1 =="
CMAPER_FAKE_ROUND=1 run_quiet scan --target 10.0.0.0/24 --profile mid --no-ping > "$OUT_DIR/scan-round1.txt"
cat "$OUT_DIR/scan-round1.txt"

echo "== fake-nmap round 2 =="
CMAPER_FAKE_ROUND=2 run_quiet scan --target 10.0.0.0/24 --profile mid --no-ping > "$OUT_DIR/scan-round2.txt"
cat "$OUT_DIR/scan-round2.txt"

SESSIONS_TXT="$OUT_DIR/sessions.txt"
run_quiet sessions --limit 2 > "$SESSIONS_TXT"
cat "$SESSIONS_TXT"

SESSION_NEW=$(awk '/^  session-/{print $1}' "$SESSIONS_TXT" | sed -n '1p')
SESSION_OLD=$(awk '/^  session-/{print $1}' "$SESSIONS_TXT" | sed -n '2p')

if [ "$SESSION_NEW" = "" ] || [ "$SESSION_OLD" = "" ]; then
    echo "Failed to resolve last two sessions from sessions output" >&2
    exit 1
fi

echo "Resolved sessions:"
echo "  old: $SESSION_OLD"
echo "  new: $SESSION_NEW"

echo "== diff =="
run_quiet diff --from "$SESSION_OLD" --to "$SESSION_NEW" > "$OUT_DIR/diff.txt"
cat "$OUT_DIR/diff.txt"

echo "== devices =="
run_quiet devices --session "$SESSION_NEW" > "$OUT_DIR/devices.txt"
cat "$OUT_DIR/devices.txt"

echo "== timeline =="
run_quiet timeline --session "$SESSION_NEW" > "$OUT_DIR/timeline.txt"
cat "$OUT_DIR/timeline.txt"

echo "== posture =="
run_quiet posture --session "$SESSION_NEW" > "$OUT_DIR/posture.txt"
cat "$OUT_DIR/posture.txt"

run_quiet diff --from "$SESSION_OLD" --to "$SESSION_NEW" --format json > "$OUT_DIR/diff.json"
run_quiet devices --session "$SESSION_NEW" --format json > "$OUT_DIR/devices.json"
run_quiet timeline --session "$SESSION_NEW" --format json > "$OUT_DIR/timeline.json"

echo "JSON artifacts:"
echo "  $OUT_DIR/diff.json"
echo "  $OUT_DIR/devices.json"
echo "  $OUT_DIR/timeline.json"

echo "E2E fake-nmap scenario completed."
