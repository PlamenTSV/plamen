"""Pure receipt-codec parity, not report or model-execution acceptance."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

import report_index_summary_authority as authority
from plamen_validators import derive_report_index_summary_master_parity
from test_report_index_summary_parity_successor_a0_a1 import _index_bytes


def _case():
    derivation = derive_report_index_summary_master_parity(_index_bytes())
    assert derivation.repair_required
    contract = SimpleNamespace(key="sc/core/evm/codex/report_index/summary_parity", digest="c" * 64)
    model_key = "sc/core/evm/codex/report_index/model"
    receipt = authority._build_summary_parity_receipt(
        derivation, contract=contract, run_id="receipt-codec-test",
        model_work_unit_key=model_key,
    )
    kwargs = dict(
        contract=contract, run_id="receipt-codec-test", model_work_unit_key=model_key,
        prestate={"sha256": derivation.before_sha256, "size": len(derivation.input_bytes),
                  "predecessor_owner_key": model_key, "status": "ACTIVE_REGISTERED_PREDECESSOR"},
        current=derivation.output_bytes, before_derivation=derivation,
    )
    return receipt, kwargs


def test_receipt_codec_roundtrip_and_pure_derivation(tmp_path):
    receipt, kwargs = _case()
    raw = authority._summary_parity_receipt_bytes(receipt)
    target = tmp_path / "receipt.json"
    target.write_bytes(raw)
    assert authority._read_summary_parity_receipt(target) == (receipt, raw)
    assert authority._validate_summary_parity_receipt(receipt, **kwargs) == []


@pytest.mark.parametrize("field", (
    "schema_version", "run_id", "model_work_unit_key", "contract_digest",
    "before_sha256", "after_sha256", "master_section_sha256", "outside_summary_sha256",
))
def test_self_consistent_receipt_tamper_does_not_match_original_derivation(field):
    receipt, kwargs = _case()
    receipt[field] = "changed"
    receipt["receipt_digest"] = authority._summary_parity_receipt_digest(receipt)
    assert authority._validate_summary_parity_receipt(receipt, **kwargs)


def test_predecessor_mismatch_is_rejected():
    receipt, kwargs = _case()
    kwargs = deepcopy(kwargs)
    kwargs["prestate"]["predecessor_owner_key"] = "unrelated-owner"
    assert authority._validate_summary_parity_receipt(receipt, **kwargs)


def test_noncanonical_receipt_bytes_are_rejected(tmp_path):
    receipt, _ = _case()
    target = tmp_path / "receipt.json"
    target.write_bytes(authority._summary_parity_receipt_bytes(receipt) + b"\n")
    with pytest.raises(ValueError, match="non-canonical"):
        authority._read_summary_parity_receipt(target)


def test_driver_uses_the_shared_receipt_checks():
    import plamen_driver as driver
    for name in (
        "_summary_parity_receipt_digest", "_summary_parity_receipt_bytes",
        "_build_summary_parity_receipt", "_read_summary_parity_receipt",
        "_validate_summary_parity_receipt",
    ):
        assert getattr(driver, name) is getattr(authority, name)
