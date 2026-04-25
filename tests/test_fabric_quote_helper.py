import sys
from pathlib import Path


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "SampleCode" / "MutualAttestationQuoteFabricBenchmark"),
)

from fabric_quote_helper import _import_rpe_modules, party_rpe_ids, write_bytes_atomic


def test_fabric_rpe_ids_include_run_id_prefix() -> None:
    assert party_rpe_ids(3, "mage_n3_run1") == [
        "mage_n3_run1_party_1",
        "mage_n3_run1_party_2",
        "mage_n3_run1_party_3",
    ]


def test_imports_packaged_rpe_proto_modules() -> None:
    proto_dir = (
        Path(__file__).resolve().parents[1]
        / "SampleCode"
        / "MutualAttestationQuoteFabricBenchmark"
        / "rpe_conn"
    )

    rpe_pb2, rpe_pb2_grpc = _import_rpe_modules(str(proto_dir))

    assert hasattr(rpe_pb2, "RpeIds")
    assert hasattr(rpe_pb2_grpc, "RpeServiceStub")


def test_atomic_quote_write_replaces_existing_file(tmp_path: Path) -> None:
    quote_path = tmp_path / "party_2.quote"
    quote_path.write_bytes(b"old")

    write_bytes_atomic(quote_path, b"new-quote")

    assert quote_path.read_bytes() == b"new-quote"
    assert not list(tmp_path.glob(".*.tmp"))
