# MAGE Fabric Quote Benchmark

This benchmark is the Fabric-network variant of
`SampleCode/MutualAttestationQuoteBenchmark`.

It keeps the same local MAGE workflow:

```text
Quote generation -> DCAP Quote verification -> MAGE identity derivation
```

The difference is the Quote exchange stage. Instead of sharing Quote files
through a local directory, each party uploads and queries Quotes through an
SRAS Fabric client using the existing `RpeService` gRPC interface:

```text
SendQuote(RpeIdAndQuote)
QueryQuoteByIds(RpeIds)
```

## Prerequisites

Start the SRAS Fabric network and one Fabric client per party before running
this benchmark. The runner assumes this port mapping:

```text
party 1 -> FABRIC_HOST:FABRIC_BASE_PORT
party 2 -> FABRIC_HOST:FABRIC_BASE_PORT+1
party i -> FABRIC_HOST:FABRIC_BASE_PORT+i-1
```

The default is:

```text
FABRIC_HOST=127.0.0.1
FABRIC_BASE_PORT=50051
```

When the benchmark runs inside `mage-buildenv` and the SRAS Fabric clients run
on the host, use the Docker bridge address:

```text
FABRIC_HOST=172.17.0.1
```

The container must use a Python gRPC runtime newer than the old Ubuntu
`python3-grpcio` package. The Docker runner checks this and installs
`grpcio>=1.48` with `pip` when needed.

Quote polling defaults to `FABRIC_POLL_INTERVAL=0.05`, so the measured Fabric
exchange time is not inflated by the original one-second polling sleep.

## Start SRAS Fabric

From the SRAS repository, start the Fabric network:

```bash
cd /home/ecs-user/SRAS/fabric_service/fabric_network
mkdir -p /tmp/sras-docker-wrapper
printf '#!/usr/bin/env bash\nexec sudo env HLF_VERSION="${HLF_VERSION:-1.4.12}" docker "$@"\n' > /tmp/sras-docker-wrapper/docker
chmod +x /tmp/sras-docker-wrapper/docker
PATH=/tmp/sras-docker-wrapper:$PATH bash fabric-network.sh start
```

Then start one Fabric client per party:

```bash
cd /home/ecs-user/SRAS
python3 performance/start_multi_faric.py --num-parties 2 --wait 0
```

Check that the clients are listening:

```bash
ss -ltnp
```

For `N=2`, ports `50051` and `50052` should be present.

## Run

```bash
REBUILD=1 WARMUP_QUOTE=1 FABRIC_HOST=172.17.0.1 FABRIC_BASE_PORT=50051 FABRIC_POLL_INTERVAL=0.05 PARTIES_LIST="2 4 6 8" ROUNDS=5 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_fabric_quote_benchmark_in_docker.sh
```

For repeated runs without rebuilding:

```bash
WARMUP_QUOTE=1 FABRIC_HOST=172.17.0.1 FABRIC_BASE_PORT=50051 FABRIC_POLL_INTERVAL=0.05 PARTIES_LIST="2" ROUNDS=1 FMSPC=00606A000000 PCK_CA=platform bash scripts/run_mage_fabric_quote_benchmark_in_docker.sh
```

Each benchmark round uses a unique Fabric `rpeId` prefix, so repeated runs do
not read stale Quote values already stored in the Fabric ledger.

## Output

The default output directory is:

```text
results/quote_fabric_benchmark/
```

Important files:

```text
results/quote_fabric_benchmark/mage_quote_benchmark_summary.txt
results/quote_fabric_benchmark/mage_quote_benchmark_summary.csv
results/quote_fabric_benchmark/mage_quote_benchmark_summary.json
results/quote_fabric_benchmark/n<N>/run<R>/party_<P>.json
results/quote_fabric_benchmark/n<N>/run<R>/party_<P>.log
```

In the text summary, `fabric_quote_exchange_ms` is the measured Fabric Quote
exchange stage:

```text
SendQuote + QueryQuoteByIds until all requested Quotes are returned
```

`auth_latency_ms` remains the system-level N-party trust-establishment latency
excluding warmup.
