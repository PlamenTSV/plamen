from __future__ import annotations

from plamen_driver import _checkpoint_delivery_payload
from plamen_types import Checkpoint


def test_checkpoint_delivery_payload_mirrors_runtime_debts():
    debt_digest = "a" * 64
    checkpoint = Checkpoint(
        runtime_debts={
            "auxiliary_writable_root_recovery": debt_digest,
        }
    )
    assert _checkpoint_delivery_payload(checkpoint)["runtime_debts"] == {
        "auxiliary_writable_root_recovery": debt_digest,
    }


def test_checkpoint_delivery_payload_omits_empty_runtime_debts_like_save():
    assert "runtime_debts" not in _checkpoint_delivery_payload(Checkpoint())
