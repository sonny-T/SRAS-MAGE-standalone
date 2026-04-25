#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE_DIR="$ROOT/SampleCode/MutualAttestationQuoteFabricBenchmark"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/results/quote_fabric_benchmark}"
COLLATERAL_CACHE_DIR="${COLLATERAL_CACHE_DIR:-$ROOT/collateral_cache}"
PARTIES_LIST="${PARTIES_LIST:-2 4 6 8}"
ROUNDS="${ROUNDS:-5}"
TIMEOUT_SEC="${TIMEOUT_SEC:-90}"
FMSPC="${FMSPC:-00606A000000}"
PCK_CA="${PCK_CA:-platform}"
REBUILD="${REBUILD:-0}"
WARMUP_QUOTE="${WARMUP_QUOTE:-0}"
FABRIC_HOST="${FABRIC_HOST:-127.0.0.1}"
FABRIC_BASE_PORT="${FABRIC_BASE_PORT:-50051}"
FABRIC_POLL_INTERVAL="${FABRIC_POLL_INTERVAL:-0.05}"
MAGE_SDK_DIR="${MAGE_SDK_DIR:-$ROOT/linux/installer/common/sdk/output/package}"
PRIMARY_REPO_ROOT="${PRIMARY_REPO_ROOT:-$ROOT}"
PSW_BUILD_DIR="${PSW_BUILD_DIR:-$PRIMARY_REPO_ROOT/build/linux}"
PSW_RUNTIME_DIR="${PSW_RUNTIME_DIR:-$ROOT/.runtime-lib}"

mkdir -p "$PSW_RUNTIME_DIR"
ln -sf "$PSW_BUILD_DIR/libsgx_urts.so" "$PSW_RUNTIME_DIR/libsgx_urts.so"
ln -sf "$PSW_BUILD_DIR/libsgx_urts.so" "$PSW_RUNTIME_DIR/libsgx_urts.so.2"
ln -sf "$PSW_BUILD_DIR/libsgx_uae_service.so" "$PSW_RUNTIME_DIR/libsgx_uae_service.so"
ln -sf "$PSW_BUILD_DIR/libsgx_enclave_common.so" "$PSW_RUNTIME_DIR/libsgx_enclave_common.so"
ln -sf "$PSW_BUILD_DIR/libsgx_enclave_common.so" "$PSW_RUNTIME_DIR/libsgx_enclave_common.so.1"

export LD_LIBRARY_PATH="$PSW_RUNTIME_DIR:$PSW_BUILD_DIR:$MAGE_SDK_DIR/lib64:/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p "$RESULTS_DIR" "$COLLATERAL_CACHE_DIR"
export COLLATERAL_CACHE_DIR
export WARMUP_QUOTE
echo "[config] results=$RESULTS_DIR collateral_cache=$COLLATERAL_CACHE_DIR parties=\"$PARTIES_LIST\" rounds=$ROUNDS rebuild=$REBUILD warmup_quote=$WARMUP_QUOTE fabric=${FABRIC_HOST}:${FABRIC_BASE_PORT}+i-1 fabric_poll_interval=$FABRIC_POLL_INTERVAL"

ensure_built_for_parties() {
  local parties="$1"
  local missing=0

  if [[ ! -x "$SAMPLE_DIR/app" ]]; then
    echo "missing benchmark app: $SAMPLE_DIR/app" >&2
    missing=1
  fi
  if [[ ! -x "$SAMPLE_DIR/quote_helper" ]]; then
    echo "missing quote helper: $SAMPLE_DIR/quote_helper" >&2
    missing=1
  fi
  for party_id in $(seq 1 "$parties"); do
    if [[ ! -f "$SAMPLE_DIR/libenclave${party_id}.so" ]]; then
      echo "missing signed enclave: $SAMPLE_DIR/libenclave${party_id}.so" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "build artifacts are missing for PARTIES=$parties; rerun with REBUILD=1" >&2
    exit 1
  fi
}

if [[ "$REBUILD" == "1" ]]; then
  echo "[build] rebuilding MAGE PSW runtime"
  make -C "$PRIMARY_REPO_ROOT/psw/urts/linux" -j4 >/dev/null
else
  echo "[build] skipped; using existing build artifacts"
fi

for parties in $PARTIES_LIST; do
  if [[ "$REBUILD" == "1" ]]; then
    echo "[build] building benchmark artifacts for parties=$parties"
    pushd "$SAMPLE_DIR" >/dev/null
    make clean >/dev/null 2>&1 || true
    make SGX_MODE=HW PARTIES="$parties" SGX_SDK="$MAGE_SDK_DIR" PSW_LIB_ROOT="$PSW_BUILD_DIR"
    popd >/dev/null
  else
    echo "[build] checking existing benchmark artifacts for parties=$parties"
    ensure_built_for_parties "$parties"
  fi

  parties_root="$RESULTS_DIR/n${parties}"
  rm -rf "$parties_root"
  mkdir -p "$parties_root"
  for run in $(seq 1 "$ROUNDS"); do
    run_dir="$parties_root/run${run}"
    fabric_run_id="mage_n${parties}_run${run}_$(date +%s%N)"
    echo "[run] parties=$parties run=$run preparing $run_dir"
    rm -rf "$run_dir"
    mkdir -p "$run_dir"
    pids=()
    for party_id in $(seq 1 "$parties"); do
      echo "[run] parties=$parties run=$run starting party=$party_id"
      party_quote_dir="$run_dir/quotes_party_${party_id}"
      mkdir -p "$party_quote_dir"
      (
        cd "$SAMPLE_DIR"
        fabric_port=$((FABRIC_BASE_PORT + party_id - 1))
        ./app \
          --party-id "$party_id" \
          --parties "$parties" \
          --quote-dir "$party_quote_dir" \
          --result-dir "$run_dir" \
          --timeout-sec "$TIMEOUT_SEC" \
          --fmspc "$FMSPC" \
          --pck-ca "$PCK_CA" \
          --helper ./quote_helper \
          --fabric-helper ./fabric_quote_helper.py \
          --fabric-proto-dir ./rpe_conn \
          --fabric-run-id "$fabric_run_id" \
          --fabric-poll-interval "$FABRIC_POLL_INTERVAL" \
          --fabric-address "${FABRIC_HOST}:${fabric_port}"
      ) >"$run_dir/party_${party_id}.log" 2>&1 &
      pids+=("$!")
    done

    echo "[run] parties=$parties run=$run waiting for ${#pids[@]} parties"
    failed=0
    for pid in "${pids[@]}"; do
      if ! wait "$pid"; then
        failed=1
      fi
    done
    if [[ "$failed" -ne 0 ]]; then
      echo "run failed: parties=$parties run=$run" >&2
      exit 1
    fi
    echo "[run] parties=$parties run=$run finished"
  done
done

QUOTE_EXCHANGE_LABEL=fabric_quote_exchange_ms python3 "$ROOT/scripts/collect_mage_quote_benchmark.py" "$RESULTS_DIR"
echo "[summary] $RESULTS_DIR/mage_quote_benchmark_summary.txt"
cat "$RESULTS_DIR/mage_quote_benchmark_summary.txt"
