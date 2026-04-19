import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from collect_mage_quote_benchmark import aggregate, load_run_records, write_outputs


def test_collects_warmup_quote_average(tmp_path: Path) -> None:
    run_dir = tmp_path / "n2" / "run1"
    run_dir.mkdir(parents=True)
    base_payload = {
        "parties": 2,
        "auth_start_ns": 1000,
        "auth_end_ns": 2000,
        "auth_duration_us": 1,
        "status": "ok",
        "timing_ms": {
            "warmup_quote": 10.0,
            "quote_generation": 20.0,
            "quote_qe_target_info": 0.0,
            "quote_get_quote": 15.0,
            "wait_all_quotes": 0.0,
            "quote_verification_total": 1.0,
        },
        "peer_timings": [
            {
                "quote_verify_ms": 1.0,
                "verify_collateral_ms": 0.0,
                "verify_qv_verify_ms": 1.0,
                "identity_check_ms": 0.1,
            }
        ],
    }
    for party_id in (1, 2):
        payload = dict(base_payload)
        payload["party_id"] = party_id
        (run_dir / f"party_{party_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    rows = load_run_records(tmp_path)
    summary = aggregate(rows)

    assert summary[0]["avg_warmup_quote_ms"] == 10.0


def test_report_labels_exclude_warmup_and_break_down_auth_latency(tmp_path: Path) -> None:
    summary = [
        {
            "parties": 2,
            "runs": 1,
            "avg_trust_establishment_latency_ms": 100.0,
            "avg_per_party_auth_ms": 90.0,
            "avg_warmup_quote_ms": 10.0,
            "avg_quote_generation_ms": 20.0,
            "avg_quote_qe_target_info_ms": 0.0,
            "avg_quote_get_quote_ms": 15.0,
            "avg_wait_all_quotes_ms": 3.0,
            "avg_quote_verification_total_ms": 4.0,
            "avg_identity_derivation_total_ms": 0.5,
            "avg_quote_verify_per_quote_ms": 2.0,
            "avg_verify_collateral_per_quote_ms": 0.0,
            "avg_verify_qv_per_quote_ms": 2.0,
            "avg_identity_check_per_quote_ms": 0.25,
        }
    ]

    write_outputs(tmp_path, summary)
    report = (tmp_path / "mage_quote_benchmark_summary.txt").read_text(encoding="utf-8")

    assert "N=2 (runs=1)" in report
    assert "End-to-end latency, excluding warmup:" in report
    assert "  auth_latency_ms: 100.000" in report
    assert "Included per-party stages, excluding warmup:" in report
    assert "  quote_generation_ms: 20.000" in report
    assert "  quote_verification_total_ms: 4.000" in report
    assert "  mage_identity_derivation_total_ms: 0.500" in report
    assert "Excluded warmup:" in report
    assert "  warmup_quote_ms: 10.000" in report
