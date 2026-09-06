"""P0-AM contracts for phase-independent checkpoint runtime debt."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from plamen_types import Checkpoint


DEBT_A = "AUXILIARY_WRITABLE_ROOT_RECONCILIATION"
DEBT_B = "STARTUP_EXTERNAL_STATE_REPAIR"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _write_checkpoint(scratchpad: Path, **updates: object) -> None:
    payload: dict[str, object] = {
        "completed": [],
        "degraded": [],
        "rate_limited_at": None,
    }
    payload.update(updates)
    (scratchpad / "_v2_checkpoint.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )


def test_legacy_checkpoint_loads_without_runtime_debt(tmp_path: Path) -> None:
    _write_checkpoint(tmp_path, completed=["recon"])

    checkpoint = Checkpoint.load(tmp_path)

    assert checkpoint.runtime_debts == {}
    checkpoint.save(tmp_path)
    payload = json.loads((tmp_path / "_v2_checkpoint.json").read_text("utf-8"))
    assert "runtime_debts" not in payload


def test_runtime_debts_round_trip_in_stable_key_order(tmp_path: Path) -> None:
    checkpoint = Checkpoint()
    checkpoint.record_runtime_debt(DEBT_B, DIGEST_B)
    checkpoint.record_runtime_debt(DEBT_A, DIGEST_A)

    checkpoint.save(tmp_path)

    payload = json.loads((tmp_path / "_v2_checkpoint.json").read_text("utf-8"))
    assert list(payload["runtime_debts"]) == [DEBT_A, DEBT_B]
    assert Checkpoint.load(tmp_path).runtime_debts == {
        DEBT_A: DIGEST_A,
        DEBT_B: DIGEST_B,
    }


def test_record_and_exact_clear_are_idempotent_and_preserve_siblings() -> None:
    checkpoint = Checkpoint()
    checkpoint.record_runtime_debt(DEBT_A, DIGEST_A)
    checkpoint.record_runtime_debt(DEBT_B, DIGEST_B)
    checkpoint.record_runtime_debt(DEBT_A, DIGEST_A)

    assert checkpoint.clear_runtime_debt(DEBT_A, DIGEST_C) is False
    assert checkpoint.runtime_debts == {
        DEBT_A: DIGEST_A,
        DEBT_B: DIGEST_B,
    }

    checkpoint.record_runtime_debt(DEBT_A, DIGEST_C)
    assert checkpoint.clear_runtime_debt(DEBT_A, DIGEST_A) is False
    assert checkpoint.clear_runtime_debt(DEBT_A, DIGEST_C) is True
    assert checkpoint.clear_runtime_debt(DEBT_A, DIGEST_C) is False
    assert checkpoint.runtime_debts == {DEBT_B: DIGEST_B}


@pytest.mark.parametrize(
    "debt_id",
    [
        "",
        "lowercase",
        "9LEADING_DIGIT",
        "_LEADING_UNDERSCORE",
        "HAS SPACE",
        "HAS/SLASH",
        "A" * 129,
        7,
        None,
    ],
)
def test_record_rejects_noncanonical_runtime_debt_ids(debt_id: object) -> None:
    with pytest.raises(ValueError, match="runtime debt ID"):
        Checkpoint().record_runtime_debt(debt_id, DIGEST_A)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "a" * 63,
        "A" * 64,
        "g" * 64,
        7,
        None,
    ],
)
def test_record_rejects_malformed_receipt_digests(digest: object) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        Checkpoint().record_runtime_debt(DEBT_A, digest)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "runtime_debts",
    [
        [],
        {DEBT_A: "a" * 63},
        {"lowercase": DIGEST_A},
        {7: DIGEST_A},
    ],
)
def test_load_rejects_malformed_runtime_debt_state(
    tmp_path: Path,
    runtime_debts: object,
) -> None:
    _write_checkpoint(tmp_path, runtime_debts=runtime_debts)

    with pytest.raises(RuntimeError, match="runtime_debts"):
        Checkpoint.load(tmp_path)


@pytest.mark.parametrize(
    "runtime_debts",
    [
        [],
        {DEBT_A: "a" * 63},
        {"lowercase": DIGEST_A},
        {7: DIGEST_A},
    ],
)
def test_save_rejects_malformed_runtime_debt_state(
    tmp_path: Path,
    runtime_debts: object,
) -> None:
    checkpoint = Checkpoint()
    checkpoint.runtime_debts = runtime_debts  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="runtime_debts"):
        checkpoint.save(tmp_path)

    assert not (tmp_path / "_v2_checkpoint.json").exists()


def test_runtime_debt_is_not_phase_state_or_completion_authority() -> None:
    checkpoint = Checkpoint(
        completed=["recon"],
        degraded=["recon"],
        rate_limited_at="recon",
        runtime_debts={DEBT_A: DIGEST_A},
    )

    checkpoint.mark_completed("recon")

    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == []
    assert checkpoint.rate_limited_at is None
    assert checkpoint.runtime_debts == {DEBT_A: DIGEST_A}
    assert checkpoint.validate_phase_names({"recon"}) == []
    assert checkpoint.validate_phase_names(set()) == [
        "completed:recon",
    ]


def test_runtime_debt_serialization_is_insertion_order_independent(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    left = Checkpoint(runtime_debts={DEBT_B: DIGEST_B, DEBT_A: DIGEST_A})
    right = Checkpoint(runtime_debts={DEBT_A: DIGEST_A, DEBT_B: DIGEST_B})

    left.save(first)
    right.save(second)

    assert (first / "_v2_checkpoint.json").read_bytes() == (
        second / "_v2_checkpoint.json"
    ).read_bytes()


def test_exact_clear_validates_identity_and_digest_before_mutation() -> None:
    checkpoint = Checkpoint(runtime_debts={DEBT_A: DIGEST_A})

    with pytest.raises(ValueError, match="runtime debt ID"):
        checkpoint.clear_runtime_debt("lowercase", DIGEST_A)
    with pytest.raises(ValueError, match="SHA-256"):
        checkpoint.clear_runtime_debt(DEBT_A, "a" * 63)

    assert checkpoint.runtime_debts == {DEBT_A: DIGEST_A}
