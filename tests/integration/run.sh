#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

"$SCRIPT_DIR/test_cli_parser.sh"
"$SCRIPT_DIR/test_cli_verbosity.sh"
"$SCRIPT_DIR/test_history_queries.sh"
"$SCRIPT_DIR/test_port_expansion.sh"
"$SCRIPT_DIR/test_hostname_inference.sh"

echo "integration tests: ok"
