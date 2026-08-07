#!/usr/bin/env bash
# Upload an already-built binary and (re)start the production service.
# Run deploy/build.sh first (or download a prebuilt release binary).
#
# Usage:
#   ./deploy/upload.sh
#   SSO_HOST=root@2001:df6:d2c0:4::121 ./deploy/upload.sh   # IPv6
#
# Requirements: ssh, and rsync OR scp. The remote must be reachable over SSH as
# root. `.env` is never overwritten; on first deploy `.env.example` is seeded.
set -euo pipefail
cd "$(dirname "$0")/.."
source deploy/common.sh

if [ ! -f "$BIN" ]; then
  echo "error: binary not found at $BIN — run ./deploy/build.sh first" >&2
  exit 1
fi

echo "==> Preparing remote $SSO_HOST:$REMOTE_DIR"
ssh "$SSO_HOST" "mkdir -p $REMOTE_DIR/data"

echo "==> Uploading binary + unit file"
if command -v rsync >/dev/null 2>&1 && ssh "$SSO_HOST" 'command -v rsync' >/dev/null 2>&1; then
  rsync -avz "$BIN" "$SSO_HOST:$REMOTE_DIR/sso.new"
  rsync -avz deploy/sso.service "$SSO_HOST:/etc/systemd/system/sso.service"
else
  echo "    (rsync unavailable on a side — using scp)"
  scp "$BIN" "$SSO_HOST:$REMOTE_DIR/sso.new"
  scp deploy/sso.service "$SSO_HOST:/etc/systemd/system/sso.service"
fi

# .env is uploaded only if it does not already exist remotely (never overwrite prod secrets).
if ! ssh "$SSO_HOST" "test -f $REMOTE_DIR/.env"; then
  echo "==> No remote .env found — uploading .env.example as a starting point"
  echo "    EDIT $REMOTE_DIR/.env on the server and set real secrets before first start!"
  scp .env.example "$SSO_HOST:$REMOTE_DIR/.env"
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
