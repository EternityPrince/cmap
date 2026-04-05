#!/bin/sh
set -eu

if [ "${HOME:-}" = "" ]; then
    echo "HOME is not set; cannot resolve uninstall paths" >&2
    exit 1
fi

INSTALL_ROOT=${CMAPER_INSTALL_ROOT:-"$HOME/.local/share/cmaper"}
BIN_DIR=${CMAPER_BIN_DIR:-"$HOME/.local/bin"}
DATA_DIR=${CMAPER_DATA_DIR:-"$HOME/.local/share/cmaper/data"}
CMD_NAME=${CMAPER_CMD_NAME:-"cmap"}
PURGE_DATA=0

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --purge-data             Remove runtime data directory
  --install-root <path>    Install root directory (default: $INSTALL_ROOT)
  --bin-dir <path>         Launcher directory (default: $BIN_DIR)
  --data-dir <path>        Runtime data directory (default: $DATA_DIR)
  --cmd-name <name>        Main terminal command name (default: $CMD_NAME)
  -h, --help               Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge-data)
            PURGE_DATA=1
            ;;
        --install-root)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Option '--install-root' requires a value." >&2
                usage >&2
                exit 2
            fi
            INSTALL_ROOT="$1"
            ;;
        --bin-dir)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Option '--bin-dir' requires a value." >&2
                usage >&2
                exit 2
            fi
            BIN_DIR="$1"
            ;;
        --data-dir)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Option '--data-dir' requires a value." >&2
                usage >&2
                exit 2
            fi
            DATA_DIR="$1"
            ;;
        --cmd-name)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Option '--cmd-name' requires a value." >&2
                usage >&2
                exit 2
            fi
            CMD_NAME="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$CMD_NAME" = "" ]; then
    echo "Command name cannot be empty." >&2
    exit 2
fi

safe_rm_rf() {
    path="$1"
    if [ "$path" = "" ] || [ "$path" = "/" ]; then
        echo "Refusing to remove unsafe path: '$path'" >&2
        exit 1
    fi
    rm -rf "$path"
}

LAUNCHER="$BIN_DIR/$CMD_NAME"
LEGACY_LAUNCHER="$BIN_DIR/cmaper"

if [ -f "$LAUNCHER" ]; then
    rm -f "$LAUNCHER"
    echo "Removed launcher: $LAUNCHER"
fi
if [ "$LEGACY_LAUNCHER" != "$LAUNCHER" ] && [ -f "$LEGACY_LAUNCHER" ]; then
    rm -f "$LEGACY_LAUNCHER"
    echo "Removed compatibility launcher: $LEGACY_LAUNCHER"
fi

if [ -d "$INSTALL_ROOT" ]; then
    safe_rm_rf "$INSTALL_ROOT"
    echo "Removed install root: $INSTALL_ROOT"
fi

if [ "$PURGE_DATA" -eq 1 ] && [ -d "$DATA_DIR" ]; then
    safe_rm_rf "$DATA_DIR"
    echo "Purged data dir: $DATA_DIR"
fi

echo "Uninstall complete."
