#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path


def load_run_records(root: Path) -> list[dict[str, int | str]]:
    rows: list[dict[str, int | str]] = []
    for run_dir in sorted(path for path in root.rglob("*") if path.is_dir() and path.name.startswith("run")):
        party_files = sorted(
            party_file
            for party_file in run_dir.glob("party_*.json")
            if not party_file.name.endswith(".verify.json")
        )
        if not party_files:
            continue

        parties = None
        starts: list[int] = []
        ends: list[int] = []
        durations: list[int] = []
        statuses: list[str] = []
        warmup_quote_values: list[float] = []
        quote_generation_values: list[float] = []
        quote_qe_target_info_values: list[float] = []
        quote_get_quote_values: list[float] = []
        wait_all_quotes_values: list[float] = []
        quote_verification_total_values: list[float] = []
        identity_check_total_values: list[float] = []
        quote_verify_peer_values: list[float] = []
        verify_collateral_values: list[float] = []
        verify_qv_values: list[float] = []
        identity_check_peer_values: list[float] = []
        for party_file in party_files:
            payload = json.loads(party_file.read_text(encoding="utf-8"))
            party_count = int(payload["parties"])
            parties = party_count if parties is None else parties
            if parties != party_count:
                raise ValueError(f"inconsistent parties in {run_dir}")
            starts.append(int(payload["auth_start_ns"]))
            ends.append(int(payload["auth_end_ns"]))
            durations.append(int(payload["auth_duration_us"]))
            statuses.append(str(payload["status"]))
            timing_ms = payload.get("timing_ms", {})
            warmup_quote_values.append(float(timing_ms.get("warmup_quote", 0.0)))
            quote_generation_values.append(float(timing_ms.get("quote_generation", 0.0)))
            quote_qe_target_info_values.append(float(timing_ms.get("quote_qe_target_info", 0.0)))
            quote_get_quote_values.append(float(timing_ms.get("quote_get_quote", 0.0)))
            wait_all_quotes_values.append(float(timing_ms.get("wait_all_quotes", 0.0)))
            quote_verification_total_values.append(float(timing_ms.get("quote_verification_total", 0.0)))
            identity_check_total_values.append(float(timing_ms.get("identity_check_total", 0.0)))
            for peer_timing in payload.get("peer_timings", []):
                quote_verify_peer_values.append(float(peer_timing.get("quote_verify_ms", 0.0)))
                verify_collateral_values.append(float(peer_timing.get("verify_collateral_ms", 0.0)))
                verify_qv_values.append(float(peer_timing.get("verify_qv_verify_ms", 0.0)))
                identity_check_peer_values.append(float(peer_timing.get("identity_check_ms", 0.0)))

        if parties is None:
            continue
        if any(status != "ok" for status in statuses):
            raise ValueError(f"non-ok party status found in {run_dir}")

        latency_us = (max(ends) - min(starts)) // 1000
        rows.append(
            {
                "parties": parties,
                "run": run_dir.name,
                "trust_establishment_latency_us": latency_us,
                "trust_establishment_latency_ms": latency_us / 1000.0,
                "per_party_auth_avg_us": sum(durations) // len(durations),
                "per_party_auth_avg_ms": (sum(durations) // len(durations)) / 1000.0,
                "warmup_quote_avg_ms": sum(warmup_quote_values) / len(warmup_quote_values),
                "quote_generation_avg_ms": sum(quote_generation_values) / len(quote_generation_values),
                "quote_qe_target_info_avg_ms": sum(quote_qe_target_info_values) / len(quote_qe_target_info_values),
                "quote_get_quote_avg_ms": sum(quote_get_quote_values) / len(quote_get_quote_values),
                "wait_all_quotes_avg_ms": sum(wait_all_quotes_values) / len(wait_all_quotes_values),
                "quote_verification_total_avg_ms": (
                    sum(quote_verification_total_values) / len(quote_verification_total_values)
                ),
                "identity_derivation_total_avg_ms": (
                    sum(identity_check_total_values) / len(identity_check_total_values)
                ),
                "quote_verify_per_quote_avg_ms": (
                    sum(quote_verify_peer_values) / len(quote_verify_peer_values) if quote_verify_peer_values else 0.0
                ),
                "verify_collateral_per_quote_avg_ms": (
                    sum(verify_collateral_values) / len(verify_collateral_values) if verify_collateral_values else 0.0
                ),
                "verify_qv_per_quote_avg_ms": (
                    sum(verify_qv_values) / len(verify_qv_values) if verify_qv_values else 0.0
                ),
                "identity_check_per_quote_avg_ms": (
                    sum(identity_check_peer_values) / len(identity_check_peer_values)
                    if identity_check_peer_values
                    else 0.0
                ),
            }
        )
    if not rows:
        raise FileNotFoundError(f"no run directories with party_*.json found in {root}")
    return rows


def aggregate(rows: list[dict[str, int | str]]) -> list[dict[str, int | float]]:
    grouped: dict[int, list[dict[str, int | str]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["parties"])].append(row)

    summary: list[dict[str, int | float]] = []
    for parties in sorted(grouped):
        party_rows = grouped[parties]
        trust_values = [float(row["trust_establishment_latency_ms"]) for row in party_rows]
        per_party_values = [float(row["per_party_auth_avg_ms"]) for row in party_rows]
        warmup_quote_values = [float(row["warmup_quote_avg_ms"]) for row in party_rows]
        quote_generation_values = [float(row["quote_generation_avg_ms"]) for row in party_rows]
        quote_qe_target_info_values = [float(row["quote_qe_target_info_avg_ms"]) for row in party_rows]
        quote_get_quote_values = [float(row["quote_get_quote_avg_ms"]) for row in party_rows]
        wait_all_quotes_values = [float(row["wait_all_quotes_avg_ms"]) for row in party_rows]
        quote_verification_total_values = [float(row["quote_verification_total_avg_ms"]) for row in party_rows]
        identity_derivation_total_values = [float(row["identity_derivation_total_avg_ms"]) for row in party_rows]
        quote_verify_peer_values = [float(row["quote_verify_per_quote_avg_ms"]) for row in party_rows]
        verify_collateral_values = [float(row["verify_collateral_per_quote_avg_ms"]) for row in party_rows]
        verify_qv_values = [float(row["verify_qv_per_quote_avg_ms"]) for row in party_rows]
        identity_check_peer_values = [float(row["identity_check_per_quote_avg_ms"]) for row in party_rows]
        summary.append(
            {
                "parties": parties,
                "runs": len(party_rows),
                "avg_trust_establishment_latency_ms": sum(trust_values) / len(trust_values),
                "avg_per_party_auth_ms": sum(per_party_values) / len(per_party_values),
                "avg_warmup_quote_ms": sum(warmup_quote_values) / len(warmup_quote_values),
                "avg_quote_generation_ms": sum(quote_generation_values) / len(quote_generation_values),
                "avg_quote_qe_target_info_ms": (
                    sum(quote_qe_target_info_values) / len(quote_qe_target_info_values)
                ),
                "avg_quote_get_quote_ms": sum(quote_get_quote_values) / len(quote_get_quote_values),
                "avg_wait_all_quotes_ms": sum(wait_all_quotes_values) / len(wait_all_quotes_values),
                "avg_quote_verification_total_ms": (
                    sum(quote_verification_total_values) / len(quote_verification_total_values)
                ),
                "avg_identity_derivation_total_ms": (
                    sum(identity_derivation_total_values) / len(identity_derivation_total_values)
                ),
                "avg_quote_verify_per_quote_ms": sum(quote_verify_peer_values) / len(quote_verify_peer_values),
                "avg_verify_collateral_per_quote_ms": (
                    sum(verify_collateral_values) / len(verify_collateral_values)
                ),
                "avg_verify_qv_per_quote_ms": sum(verify_qv_values) / len(verify_qv_values),
                "avg_identity_check_per_quote_ms": (
                    sum(identity_check_peer_values) / len(identity_check_peer_values)
                ),
            }
        )
    return summary


def write_outputs(root: Path, summary: list[dict[str, int | float]]) -> None:
    quote_exchange_label = os.environ.get("QUOTE_EXCHANGE_LABEL", "wait_all_quotes_ms")
    json_path = root / "mage_quote_benchmark_summary.json"
    csv_path = root / "mage_quote_benchmark_summary.csv"
    txt_path = root / "mage_quote_benchmark_summary.txt"

    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "parties",
                "runs",
                "avg_trust_establishment_latency_ms",
                "avg_per_party_auth_ms",
                "avg_warmup_quote_ms",
                "avg_quote_generation_ms",
                "avg_quote_qe_target_info_ms",
                "avg_quote_get_quote_ms",
                "avg_wait_all_quotes_ms",
                "avg_quote_verification_total_ms",
                "avg_identity_derivation_total_ms",
                "avg_quote_verify_per_quote_ms",
                "avg_verify_collateral_per_quote_ms",
                "avg_verify_qv_per_quote_ms",
                "avg_identity_check_per_quote_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(summary)

    lines = [
        "MAGE Quote Benchmark Summary",
        "==========================",
        "",
    ]
    for row in summary:
        lines.extend(
            [
                f"N={row['parties']} (runs={row['runs']})",
                "  End-to-end latency, excluding warmup:",
                f"    auth_latency_ms: {row['avg_trust_establishment_latency_ms']:.3f}",
                f"    avg_per_party_auth_ms: {row['avg_per_party_auth_ms']:.3f}",
                "  Included per-party stages, excluding warmup:",
                f"    quote_generation_ms: {row['avg_quote_generation_ms']:.3f}",
                f"    {quote_exchange_label}: {row['avg_wait_all_quotes_ms']:.3f}",
                f"    quote_verification_total_ms: {row['avg_quote_verification_total_ms']:.3f}",
                f"    mage_identity_derivation_total_ms: {row['avg_identity_derivation_total_ms']:.3f}",
                "  Quote generation breakdown:",
                f"    qe_target_info_ms: {row['avg_quote_qe_target_info_ms']:.3f}",
                f"    qe_get_quote_ms: {row['avg_quote_get_quote_ms']:.3f}",
                "  Per-quote verification and identity breakdown:",
                f"    quote_verify_ms: {row['avg_quote_verify_per_quote_ms']:.3f}",
                f"    collateral_ms: {row['avg_verify_collateral_per_quote_ms']:.3f}",
                f"    qv_verify_ms: {row['avg_verify_qv_per_quote_ms']:.3f}",
                f"    mage_identity_derivation_ms: {row['avg_identity_check_per_quote_ms']:.3f}",
                "  Excluded warmup:",
                f"    warmup_quote_ms: {row['avg_warmup_quote_ms']:.3f}",
                "",
            ]
        )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) == 2 else Path(__file__).resolve().parents[1] / "results"
    if len(argv) > 2:
        print(f"usage: {argv[0]} [results-root]", file=sys.stderr)
        return 2
    rows = load_run_records(root)
    summary = aggregate(rows)
    write_outputs(root, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
