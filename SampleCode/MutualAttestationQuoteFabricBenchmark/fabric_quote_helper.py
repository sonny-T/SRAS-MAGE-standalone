#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import importlib
import json
import os
import sys
import time
from pathlib import Path

import grpc


def log(message: str) -> None:
    print(f"[fabric-helper] {message}", file=sys.stderr, flush=True)


def now_ms() -> float:
    return time.monotonic() * 1000.0


def _import_rpe_modules(proto_dir: str):
    proto_path = Path(proto_dir).resolve()
    sys.path.insert(0, str(proto_path.parent))
    package_name = proto_path.name
    rpe_pb2 = importlib.import_module(f"{package_name}.rpe_pb2")
    rpe_pb2_grpc = importlib.import_module(f"{package_name}.rpe_pb2_grpc")

    return rpe_pb2, rpe_pb2_grpc


def party_rpe_ids(parties: int, run_id: str) -> list[str]:
    prefix = f"{run_id}_" if run_id else ""
    return [f"{prefix}party_{idx}" for idx in range(1, parties + 1)]


def quote_file_id(rpe_id: str, run_id: str) -> str:
    prefix = f"{run_id}_" if run_id else ""
    if prefix and rpe_id.startswith(prefix):
        return rpe_id[len(prefix):]
    return rpe_id


def _quote_path(quote_dir: Path, rpe_id: str) -> Path:
    # Keep file names compatible with the C++ verifier: party_N.quote.
    return quote_dir / f"{rpe_id}.quote"


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, path)


def exchange_quotes(args: argparse.Namespace) -> int:
    exchange_start_ms = now_ms()
    rpe_pb2, rpe_pb2_grpc = _import_rpe_modules(args.proto_dir)
    quote_dir = Path(args.quote_dir)
    local_quote = Path(args.local_quote)
    rpe_ids = party_rpe_ids(args.parties, args.run_id)
    local_rpe_id = f"{args.run_id + '_' if args.run_id else ''}party_{args.party_id}"

    quote_bytes = local_quote.read_bytes()
    encoded_quote = base64.b64encode(quote_bytes).decode("ascii")

    channel_start_ms = now_ms()
    channel = grpc.insecure_channel(args.address)
    log(f"waiting for gRPC channel ready: address={args.address}")
    grpc.channel_ready_future(channel).result(timeout=args.rpc_timeout)
    log(f"gRPC channel ready: duration_ms={now_ms() - channel_start_ms:.3f}")
    stub = rpe_pb2_grpc.RpeServiceStub(channel)

    send_start_ms = now_ms()
    log(f"SendQuote start: rpe_id={local_rpe_id} quote_bytes={len(quote_bytes)}")
    send_response = stub.SendQuote(
        rpe_pb2.RpeIdAndQuote(rpeId=local_rpe_id, base64EncodedQuote=encoded_quote),
        timeout=args.rpc_timeout,
    )
    log(f"SendQuote done: status={send_response.status} duration_ms={now_ms() - send_start_ms:.3f}")
    if send_response.status != 0:
        print(f"SendQuote failed: {send_response.content}", file=sys.stderr)
        return 1

    deadline = time.time() + args.timeout
    last_error = ""
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        try:
            query_start_ms = now_ms()
            log(f"QueryQuoteByIds start: attempt={attempts} ids={','.join(rpe_ids)}")
            response = stub.QueryQuoteByIds(
                rpe_pb2.RpeIds(rpeIds=",".join(rpe_ids)),
                timeout=args.rpc_timeout,
            )
            query_duration_ms = now_ms() - query_start_ms
            log(
                f"QueryQuoteByIds done: attempt={attempts} status={response.status} "
                f"duration_ms={query_duration_ms:.3f} content_bytes={len(response.content)}"
            )
            if response.status == 0:
                quote_map = json.loads(response.content or "{}")
                available = [rpe_id for rpe_id in rpe_ids if rpe_id in quote_map and quote_map[rpe_id]]
                missing = [rpe_id for rpe_id in rpe_ids if rpe_id not in quote_map or not quote_map[rpe_id]]
                log(
                    f"QueryQuoteByIds parsed: attempt={attempts} got={len(available)}/{len(rpe_ids)} "
                    f"missing={','.join(missing) if missing else '-'}"
                )
                if all(rpe_id in quote_map and quote_map[rpe_id] for rpe_id in rpe_ids):
                    for rpe_id in rpe_ids:
                        write_bytes_atomic(
                            _quote_path(quote_dir, quote_file_id(rpe_id, args.run_id)),
                            base64.b64decode(quote_map[rpe_id]),
                        )
                    log(
                        f"exchange complete: attempts={attempts} "
                        f"total_duration_ms={now_ms() - exchange_start_ms:.3f}"
                    )
                    return 0
                last_error = f"only got {len(quote_map)}/{len(rpe_ids)} quotes"
            else:
                last_error = response.content
        except Exception as exc:  # Fabric clients may be temporarily behind.
            last_error = str(exc)
            log(f"QueryQuoteByIds exception: attempt={attempts} error={last_error}")
        time.sleep(args.poll_interval)

    print(f"QueryQuoteByIds timed out: {last_error}", file=sys.stderr)
    return 2


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_proto_dir = str(Path(__file__).resolve().parent / "rpe_conn")
    parser = argparse.ArgumentParser(description="Exchange MAGE quotes through SRAS Fabric client gRPC")
    parser.add_argument("--address", required=True, help="Fabric client gRPC address, e.g. 127.0.0.1:50051")
    parser.add_argument("--party-id", required=True, type=int)
    parser.add_argument("--parties", required=True, type=int)
    parser.add_argument("--quote-dir", required=True)
    parser.add_argument("--local-quote", required=True)
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional per-run prefix for Fabric rpeId keys to avoid reading stale ledger quotes",
    )
    parser.add_argument(
        "--proto-dir",
        default=default_proto_dir,
        help="Directory containing rpe_pb2.py and rpe_pb2_grpc.py",
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--rpc-timeout", type=float, default=30.0)
    parser.add_argument("--poll-interval", type=float, default=0.05)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    return exchange_quotes(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
