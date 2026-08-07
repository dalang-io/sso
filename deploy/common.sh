#!/usr/bin/env bash
# Shared defaults for build.sh / upload.sh. Source this from both.
set -euo pipefail

# Production hosts (from project setup). Override with SSO_HOST.
SSO_HOST="${SSO_HOST:-root@163.128.55.121}"
REMOTE_DIR="${REMOTE_DIR:-/opt/dalang-sso}"
BIN_TARGET="${BIN_TARGET:-x86_64-unknown-linux-gnu}"

# Resolve the release binary, honoring CARGO_TARGET_DIR if set.
if [ -f "target/${BIN_TARGET}/release/sso" ]; then
  BIN="target/${BIN_TARGET}/release/sso"
else
  BIN="${CARGO_TARGET_DIR:-target}/${BIN_TARGET}/release/sso"
fi
