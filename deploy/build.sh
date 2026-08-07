#!/usr/bin/env bash
# Build the release binary only. Run deploy/upload.sh separately to ship it.
#
# Usage:
#   ./deploy/build.sh
#
# Requirements: cargo. Prefers cargo-zigbuild (reliable Linux cross-compiles from
# macOS), then `cross`, and falls back to plain cargo for the target.
set -euo pipefail
cd "$(dirname "$0")/.."
source deploy/common.sh

echo "==> Building release binary ($BIN_TARGET)"
if command -v cargo-zigbuild >/dev/null 2>&1; then
  cargo zigbuild --release --target "$BIN_TARGET" -p sso-server
elif command -v cross >/dev/null 2>&1; then
  cross build --release --target "$BIN_TARGET" -p sso-server
else
  echo "    (using cargo; install cargo-zigbuild or cross for reliable Linux cross-compiles from macOS)"
  cargo build --release --target "$BIN_TARGET" -p sso-server
fi

if [ ! -f "$BIN" ]; then
  echo "error: expected binary at $BIN but it was not produced" >&2
  exit 1
fi
echo "==> Built: $BIN"
echo "==> Now run: ./deploy/upload.sh"
