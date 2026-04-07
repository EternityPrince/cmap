#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN=${CMAPER_BIN:-"$REPO_ROOT/build/cmaper"}

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN. Build project first." >&2
    exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}/cmaper-itest-cli-parser-$$
mkdir -p "$TMP_ROOT"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

assert_fails_with() {
    phrase=$1
    shift

    if "$@" >"$TMP_ROOT/out.txt" 2>"$TMP_ROOT/err.txt"; then
        echo "Expected command to fail: $*" >&2
        exit 1
    fi

    if ! grep -qi "$phrase" "$TMP_ROOT/err.txt"; then
        echo "Expected stderr to contain '$phrase' for command: $*" >&2
        cat "$TMP_ROOT/err.txt" >&2
        exit 1
    fi
}

assert_fails_with "requires a value" \
    "$BIN" scan --target 10.0.0.0/24 --profile

assert_fails_with "not valid for mode 'sessions'" \
    "$BIN" sessions --target 10.0.0.0/24

assert_fails_with "cannot be used together" \
    "$BIN" scan --target 10.0.0.0/24 --all-ports --no-all-ports

assert_fails_with "not valid for mode 'sessions'" \
    "$BIN" sessions --window 30d

assert_fails_with "not valid for mode 'sessions'" \
    "$BIN" sessions --changes-only

assert_fails_with "invalid value for '--window'" \
    "$BIN" device --session s --device d --window abc

assert_fails_with "must be a positive day count" \
    "$BIN" device --session s --device d --window 0d

echo "test_cli_parser: ok"
