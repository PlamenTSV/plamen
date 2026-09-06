from __future__ import annotations

import worker_execution_receipts as W


def _serialized() -> dict[str, object]:
    return {
        "platform": "WINDOWS",
        "exhaustive_descendant_termination_authority": True,
        "exhaustive_write_confinement_authority": False,
        "write_confinement": (
            "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
        ),
        "serialized_low_integrity_stage_authority": True,
        "medium_integrity_source_and_canonical_protection": True,
        "write_confinement_limitation": (
            "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
        ),
        "low_integrity_lease": {
            "protocol": "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1",
            "lock_path": "C:/lease/execution.lock",
            "state_path": "C:/lease/state.json",
            "identity_sha256": "a" * 64,
            "scope": "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE",
            "crash_recovery": "OS_BYTE_RANGE_UNLOCK_PLUS_STALE_ROOT_RELABEL",
            "namespace_authority": "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA",
            "namespace_limitation": (
                "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
            ),
        },
    }


def test_transaction_accepts_honest_serialized_plamen_stage_authority() -> None:
    assert (
        W._transaction_write_authority(_serialized())
        == "SERIALIZED_PLAMEN_STAGE"
    )


def test_serialized_authority_is_strictly_conjunctive() -> None:
    for missing in (
        "serialized_low_integrity_stage_authority",
        "medium_integrity_source_and_canonical_protection",
        "low_integrity_lease",
    ):
        value = _serialized()
        value.pop(missing)
        assert W._transaction_write_authority(value) is None
    value = _serialized()
    value["low_integrity_lease"] = {
        **value["low_integrity_lease"],  # type: ignore[arg-type]
        "protocol": "forged",
    }
    assert W._transaction_write_authority(value) is None


def test_exhaustive_authority_remains_preferred() -> None:
    assert (
        W._transaction_write_authority(
            {
                "platform": "LINUX",
                "exhaustive_write_confinement_authority": True,
            }
        )
        == "EXHAUSTIVE"
    )
