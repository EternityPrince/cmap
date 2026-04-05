#!/data/data/com.termux/files/usr/bin/sh
set -eu

if command -v pkg >/dev/null 2>&1; then
    pkg update -y
    pkg install -y clang make libxml2 sqlite
fi

echo "Termux scaffold ready."
echo "Run from repo root:"
echo "  make"
echo "  ./scripts/install.sh"
