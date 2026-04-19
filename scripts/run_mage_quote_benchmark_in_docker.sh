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
  cd '$REPO_ROOT'
  RESULTS_DIR='${RESULTS_DIR:-$REPO_ROOT/results/quote_benchmark}' \
  COLLATERAL_CACHE_DIR='${COLLATERAL_CACHE_DIR:-$REPO_ROOT/collateral_cache}' \
  PARTIES_LIST='${PARTIES_LIST:-2 4 6 8}' \
  ROUNDS='${ROUNDS:-5}' \
  TIMEOUT_SEC='${TIMEOUT_SEC:-90}' \
  FMSPC='${FMSPC:-00606A000000}' \
  PCK_CA='${PCK_CA:-platform}' \
  REBUILD='${REBUILD:-0}' \
  WARMUP_QUOTE='${WARMUP_QUOTE:-0}' \
  bash scripts/run_mage_quote_benchmark.sh
"
