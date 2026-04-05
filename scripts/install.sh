#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if [ "${HOME:-}" = "" ]; then
    echo "HOME is not set; cannot resolve install paths" >&2
    exit 1
fi

INSTALL_ROOT=${CMAPER_INSTALL_ROOT:-"$HOME/.local/share/cmaper"}
BIN_DIR=${CMAPER_BIN_DIR:-"$HOME/.local/bin"}
DATA_DIR=${CMAPER_DATA_DIR:-"$HOME/.local/share/cmaper/data"}
CMD_NAME=${CMAPER_CMD_NAME:-"cmap"}
SKIP_BUILD=0

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --skip-build             Reuse existing build/cmaper
  --install-root <path>    Install root directory (default: $INSTALL_ROOT)
  --bin-dir <path>         Launcher directory (default: $BIN_DIR)
  --data-dir <path>        Runtime data directory (default: $DATA_DIR)
  --cmd-name <name>        Main terminal command name (default: $CMD_NAME)
  -h, --help               Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
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

if [ "$SKIP_BUILD" -eq 0 ]; then
    make -C "$REPO_ROOT"
fi

BINARY_SRC="$REPO_ROOT/build/cmaper"
if [ ! -x "$BINARY_SRC" ]; then
    echo "Binary not found at $BINARY_SRC. Run 'make' first." >&2
    exit 1
fi

mkdir -p "$INSTALL_ROOT/bin" "$BIN_DIR" "$DATA_DIR"

BINARY_DST="$INSTALL_ROOT/bin/cmaper-bin"
LAUNCHER="$BIN_DIR/$CMD_NAME"
LEGACY_LAUNCHER="$BIN_DIR/cmaper"

cp "$BINARY_SRC" "$BINARY_DST"
chmod 755 "$BINARY_DST"

write_launcher() {
    launcher_path="$1"
    launcher_name="$2"

    cat > "$launcher_path" <<EOF
#!/bin/sh
set -eu

INSTALL_ROOT="$INSTALL_ROOT"
DATA_DIR_DEFAULT="$DATA_DIR"
PROGRAM_NAME_DEFAULT="$launcher_name"

export NMAPER_DATA_DIR="\${NMAPER_DATA_DIR:-\$DATA_DIR_DEFAULT}"
export NMAPER_DB_PATH="\${NMAPER_DB_PATH:-\$NMAPER_DATA_DIR/cmaper.db}"
export NMAPER_XML_OUTPUT_DIR="\${NMAPER_XML_OUTPUT_DIR:-\$NMAPER_DATA_DIR/xml}"
export CMAPER_PROGRAM_NAME="\${CMAPER_PROGRAM_NAME:-\$PROGRAM_NAME_DEFAULT}"

exec "\$INSTALL_ROOT/bin/cmaper-bin" "\$@"
EOF
    chmod 755 "$launcher_path"
}

write_launcher "$LAUNCHER" "$CMD_NAME"
if [ "$LEGACY_LAUNCHER" != "$LAUNCHER" ]; then
    write_launcher "$LEGACY_LAUNCHER" "cmaper"
fi

cat <<EOF
Installed cmaper:
  binary:   $BINARY_DST
  launcher: $LAUNCHER
  compat:   $LEGACY_LAUNCHER
  data:     $DATA_DIR

Add $BIN_DIR to PATH if needed.
Run: $CMD_NAME --help
EOF
