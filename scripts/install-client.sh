#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_URL="${ARCHIVE_URL:-https://github.com/thevibethinker/zobius-protocol/archive/refs/heads/main.tar.gz}"
INSTALL_DIR="${INSTALL_DIR:-/home/workspace/Skills/zobius-client}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive_path="$tmp_dir/zobius-protocol.tar.gz"
extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"

curl -fsSL "$ARCHIVE_URL" -o "$archive_path"
tar -xzf "$archive_path" -C "$extract_dir"

src_dir="$(find "$extract_dir" -maxdepth 2 -type d -path "*/client" | head -n 1)"
if [[ -z "$src_dir" ]]; then
  echo "Could not locate client directory in downloaded archive."
  exit 1
fi

mkdir -p "$(dirname "$INSTALL_DIR")"
rm -rf "$INSTALL_DIR"
cp -R "$src_dir" "$INSTALL_DIR"

echo "Installed Zobius client to: $INSTALL_DIR"
echo "Next: set ZO2ZO_BRIDGE_URL_<HANDLE> and ZO2ZO_BRIDGE_TOKEN_<HANDLE> in Settings > Advanced."
