#!/usr/bin/env bash
# Build a release binary and deploy Dalang SSO to a production host.
#
# Usage:
#   ./deploy/deploy.sh                 # deploys to the default host below
#   SSO_HOST=root@2001:df6:d2c0:4::121 ./deploy/deploy.sh   # IPv6
#
# Requirements on your machine: cargo, ssh, rsync. The remote must be reachable
# over SSH as root (or a sudo-capable user).
set -euo pipefail

# Production hosts (from project setup). Override with SSO_HOST.
SSO_HOST="${SSO_HOST:-root@163.128.55.121}"
REMOTE_DIR="/opt/dalang-sso"
BIN_TARGET="${BIN_TARGET:-x86_64-unknown-linux-gnu}"

cd "$(dirname "$0")/.."

echo "==> Building release binary ($BIN_TARGET)"
if command -v cross >/dev/null 2>&1; then
  cross build --release --target "$BIN_TARGET" -p sso-server
else
  echo "    (using cargo; install 'cross' for reliable Linux cross-compiles from macOS)"
  cargo build --release --target "$BIN_TARGET" -p sso-server
fi
BIN="target/${BIN_TARGET}/release/sso"

echo "==> Preparing remote $SSO_HOST:$REMOTE_DIR"
ssh "$SSO_HOST" "mkdir -p $REMOTE_DIR/data"

echo "==> Uploading binary + unit file"
rsync -avz "$BIN" "$SSO_HOST:$REMOTE_DIR/sso.new"
rsync -avz deploy/sso.service "$SSO_HOST:/etc/systemd/system/sso.service"

# .env is uploaded only if it does not already exist remotely (never overwrite prod secrets).
if ! ssh "$SSO_HOST" "test -f $REMOTE_DIR/.env"; then
  echo "==> No remote .env found — uploading .env.example as a starting point"
  echo "    EDIT $REMOTE_DIR/.env on the server and set real secrets before first start!"
  rsync -avz .env.example "$SSO_HOST:$REMOTE_DIR/.env"
fi

echo "==> Activating"
ssh "$SSO_HOST" "
  set -e
  mv $REMOTE_DIR/sso.new $REMOTE_DIR/sso
  chmod +x $REMOTE_DIR/sso
  systemctl daemon-reload
  systemctl enable sso
  systemctl restart sso
  sleep 1
  systemctl --no-pager --lines=15 status sso || true
"
echo "==> Done. Health: curl http://<host>:8080/health (proxy it behind TLS — see docs/DEPLOY.md)"
