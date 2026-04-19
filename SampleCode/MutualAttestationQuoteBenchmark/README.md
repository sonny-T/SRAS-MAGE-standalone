# MAGE Quote Benchmark

This benchmark measures initial multi-party trust establishment for MAGE-style
identity derivation using SGX/DCAP Quotes.

Each party is an app process with one enclave instance. The party generates a
local Quote, waits until all parties have published their Quotes, verifies every
Quote with DCAP, and checks the verified MRENCLAVE against the MAGE-derived
expected identity set inside the enclave.

## Recommended Command

Run the warmed-path benchmark for N = 2, 4, 6, 8 with five rounds:

```bash
REBUILD=1 WARMUP_QUOTE=1 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_quote_benchmark_in_docker.sh
```

Use `REBUILD=1` after source changes or when the requested party count requires
new signed enclave binaries. For repeated measurements with existing artifacts,
use `REBUILD=0` or omit it.

## Warmup Mode

`WARMUP_QUOTE=1` performs one Quote-generation warmup before the measured
authentication interval starts. The warmup initializes the helper process,
DCAP/QE target info, and Quote-size state. The warmup time is recorded but
excluded from the end-to-end authentication latency.

Cold-path measurement:

```bash
PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_quote_benchmark_in_docker.sh
```

Warmed-path measurement:

```bash
WARMUP_QUOTE=1 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_quote_benchmark_in_docker.sh
```

## Output Files

The default output directory is:

```text
results/quote_benchmark/
```

Important files:

```text
results/quote_benchmark/mage_quote_benchmark_summary.txt
results/quote_benchmark/mage_quote_benchmark_summary.csv
results/quote_benchmark/mage_quote_benchmark_summary.json
results/quote_benchmark/n<N>/run<R>/party_<P>.json
results/quote_benchmark/n<N>/run<R>/party_<P>.log
```

The benchmark also uses a local collateral cache:

```text
collateral_cache/
```

Delete this directory to force a cold collateral fetch.

## Summary Fields

`auth_latency_ms` is the system-level N-party end-to-end latency excluding
warmup:

```text
max(all_party_auth_end) - min(all_party_auth_start)
```

`avg_per_party_auth_ms` is the average local authentication duration across
parties:

```text
avg(party_i_auth_end - party_i_auth_start)
```

Use `auth_latency_ms` for the main N-party trust-establishment latency.

Included per-party stages:

```text
quote_generation_ms
wait_all_quotes_ms
quote_verification_total_ms
mage_identity_derivation_total_ms
```

Per-quote breakdown:

```text
quote_verify_ms
collateral_ms
qv_verify_ms
mage_identity_derivation_ms
```

Excluded warmup:

```text
warmup_quote_ms
```

## Regenerating Reports

If raw JSON files already exist, regenerate the summary without rerunning SGX:

```bash
python3 scripts/collect_mage_quote_benchmark.py results/quote_benchmark
```
