#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-mage-buildenv}"
REPO_ROOT="${REPO_ROOT:-/work}"

sudo docker exec "$CONTAINER_NAME" bash -lc "
  set -euo pipefail
  if [[ ! -e /dev/sgx && -e /dev/sgx_enclave ]]; then
    ln -s /dev/sgx_enclave /dev/sgx
  fi
  if [[ -e /dev/isgx ]]; then
    rm -f /dev/isgx
  fi
  if ! python3 - <<'PY' >/dev/null 2>&1
import grpc
parts = tuple(int(part) for part in grpc.__version__.split('.')[:2])
raise SystemExit(0 if parts >= (1, 48) else 1)
PY
  then
    apt-get update >/dev/null
    apt-get install -y python3-pip >/dev/null
    python3 -m pip install --no-cache-dir 'grpcio>=1.48,<2' >/dev/null
  fi
  cd '$REPO_ROOT'
  RESULTS_DIR='${RESULTS_DIR:-$REPO_ROOT/results/quote_fabric_benchmark}' \
  COLLATERAL_CACHE_DIR='${COLLATERAL_CACHE_DIR:-$REPO_ROOT/collateral_cache}' \
  PARTIES_LIST='${PARTIES_LIST:-2 4 6 8}' \
  ROUNDS='${ROUNDS:-5}' \
  TIMEOUT_SEC='${TIMEOUT_SEC:-90}' \
  FMSPC='${FMSPC:-00606A000000}' \
  PCK_CA='${PCK_CA:-platform}' \
  REBUILD='${REBUILD:-0}' \
  WARMUP_QUOTE='${WARMUP_QUOTE:-0}' \
  FABRIC_HOST='${FABRIC_HOST:-127.0.0.1}' \
  FABRIC_BASE_PORT='${FABRIC_BASE_PORT:-50051}' \
  FABRIC_POLL_INTERVAL='${FABRIC_POLL_INTERVAL:-0.05}' \
  bash scripts/run_mage_fabric_quote_benchmark.sh
"
