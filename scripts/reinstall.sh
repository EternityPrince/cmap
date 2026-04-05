#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "${HOME:-}" = "" ]; then
    echo "HOME is not set; cannot resolve reinstall paths" >&2
    exit 1
fi

INSTALL_ROOT=${CMAPER_INSTALL_ROOT:-"$HOME/.local/share/cmaper"}
BIN_DIR=${CMAPER_BIN_DIR:-"$HOME/.local/bin"}
DATA_DIR=${CMAPER_DATA_DIR:-"$HOME/.local/share/cmaper/data"}
BACKUP_DIR=${CMAPER_BACKUP_DIR:-"$HOME/.local/share/cmaper/backups"}
CMD_NAME=${CMAPER_CMD_NAME:-"cmap"}
BACKUP=0
SKIP_BUILD=0

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --backup                 Backup install/data before reinstall
  --skip-build             Reuse existing build/cmaper
  --install-root <path>    Install root directory (default: $INSTALL_ROOT)
  --bin-dir <path>         Launcher directory (default: $BIN_DIR)
  --data-dir <path>        Runtime data directory (default: $DATA_DIR)
  --backup-dir <path>      Backup root directory (default: $BACKUP_DIR)
  --cmd-name <name>        Main terminal command name (default: $CMD_NAME)
  -h, --help               Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --backup)
            BACKUP=1
            ;;
        --skip-build)
            SKIP_BUILD=1
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
        --backup-dir)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Option '--backup-dir' requires a value." >&2
                usage >&2
                exit 2
            fi
            BACKUP_DIR="$1"
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

if [ "$BACKUP" -eq 1 ]; then
    TS=$(date +"%Y%m%d-%H%M%S")
    BACKUP_ROOT="$BACKUP_DIR/$TS"
    mkdir -p "$BACKUP_ROOT"

    if [ -d "$INSTALL_ROOT" ]; then
        cp -R "$INSTALL_ROOT" "$BACKUP_ROOT/install-root"
    fi
    if [ -d "$DATA_DIR" ]; then
        cp -R "$DATA_DIR" "$BACKUP_ROOT/data-dir"
    fi

    echo "Backup created: $BACKUP_ROOT"
fi

CMAPER_INSTALL_ROOT="$INSTALL_ROOT" \
CMAPER_BIN_DIR="$BIN_DIR" \
CMAPER_DATA_DIR="$DATA_DIR" \
CMAPER_CMD_NAME="$CMD_NAME" \
"$SCRIPT_DIR/uninstall.sh"

if [ "$SKIP_BUILD" -eq 1 ]; then
    CMAPER_INSTALL_ROOT="$INSTALL_ROOT" \
    CMAPER_BIN_DIR="$BIN_DIR" \
    CMAPER_DATA_DIR="$DATA_DIR" \
    CMAPER_CMD_NAME="$CMD_NAME" \
    "$SCRIPT_DIR/install.sh" --skip-build
else
    CMAPER_INSTALL_ROOT="$INSTALL_ROOT" \
    CMAPER_BIN_DIR="$BIN_DIR" \
    CMAPER_DATA_DIR="$DATA_DIR" \
    CMAPER_CMD_NAME="$CMD_NAME" \
    "$SCRIPT_DIR/install.sh"
fi
