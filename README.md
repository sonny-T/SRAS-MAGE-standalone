# MAGE Quote Benchmark Reproduction

This repository now contains two benchmark variants for reproducing the MAGE
multi-party trust-establishment measurements without relying on ad hoc local
build artifacts.

## Included Components

- `SampleCode/MutualAttestationQuoteBenchmark`
  - Baseline benchmark that exchanges Quotes through per-run local directories
  - Measures Quote generation, Quote exchange, DCAP verification, and MAGE
    identity derivation
- `SampleCode/MutualAttestationQuoteFabricBenchmark`
  - Fabric-network variant that exchanges Quotes through the SRAS Fabric client
    gRPC interface
- `scripts/run_mage_quote_benchmark.sh`
- `scripts/run_mage_quote_benchmark_in_docker.sh`
- `scripts/run_mage_fabric_quote_benchmark.sh`
- `scripts/run_mage_fabric_quote_benchmark_in_docker.sh`
- `scripts/collect_mage_quote_benchmark.py`

## What Is Intentionally Not Committed

The benchmarks generate several files locally during build and execution. These
are reproducible outputs and should not be committed:

- `app`
- `quote_helper`
- `enclave.so`
- `libenclave*.so`
- `mage.bin`
- `genmage.out`
- `App/Enclave_u.*`
- `Enclave/Enclave_t.*`
- `*.o`
- `results/`
- `collateral_cache/`

The repository `.gitignore` has been updated so these files stay out of future
commits.

## Benchmark 1: Local Quote Exchange

Run the warmed-path benchmark for `N=2,4,6,8` inside the `mage-buildenv`
container:

```bash
REBUILD=1 WARMUP_QUOTE=1 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_quote_benchmark_in_docker.sh
```

For repeated runs with existing artifacts:

```bash
REBUILD=0 WARMUP_QUOTE=1 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_quote_benchmark_in_docker.sh
```

Outputs are written to:

```text
results/quote_benchmark/
```

## Benchmark 2: Fabric Quote Exchange

Start the SRAS Fabric network and one Fabric client per party first. Then run:

```bash
REBUILD=1 WARMUP_QUOTE=1 FABRIC_HOST=172.17.0.1 FABRIC_BASE_PORT=50051 FABRIC_POLL_INTERVAL=0.05 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_fabric_quote_benchmark_in_docker.sh
```

For repeated runs:

```bash
REBUILD=0 WARMUP_QUOTE=1 FABRIC_HOST=172.17.0.1 FABRIC_BASE_PORT=50051 FABRIC_POLL_INTERVAL=0.05 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_fabric_quote_benchmark_in_docker.sh
```

Outputs are written to:

```text
results/quote_fabric_benchmark/
```

## Regenerating Reports

If raw per-run JSON files already exist, regenerate the report without rerunning
the benchmark:

```bash
python3 scripts/collect_mage_quote_benchmark.py results/quote_benchmark
python3 scripts/collect_mage_quote_benchmark.py results/quote_fabric_benchmark
```

The Fabric benchmark can relabel the exchange column through:

```bash
QUOTE_EXCHANGE_LABEL=fabric_quote_exchange_ms python3 scripts/collect_mage_quote_benchmark.py results/quote_fabric_benchmark
```

## Verification

The current benchmark helper and collector checks can be rerun with:

```bash
python3 -m pytest tests/test_collect_mage_quote_benchmark.py tests/test_fabric_quote_helper.py
python3 -m py_compile SampleCode/MutualAttestationQuoteFabricBenchmark/fabric_quote_helper.py scripts/collect_mage_quote_benchmark.py
bash -n scripts/run_mage_quote_benchmark.sh
bash -n scripts/run_mage_quote_benchmark_in_docker.sh
bash -n scripts/run_mage_fabric_quote_benchmark.sh
bash -n scripts/run_mage_fabric_quote_benchmark_in_docker.sh
```
