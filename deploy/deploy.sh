#!/usr/bin/env bash
# Build and deploy Dalang SSO in one command (convenience). For finer control,
# or to avoid a single long-running step, run deploy/build.sh and
# deploy/upload.sh separately.
#
# Usage:
#   ./deploy/deploy.sh                 # builds + uploads to the default host
#   SSO_HOST=root@2001:df6:d2c0:4::121 ./deploy/deploy.sh   # IPv6
set -euo pipefail
base="$(dirname "$0")"
"$base/build.sh"
"$base/upload.sh"
