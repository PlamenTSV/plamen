"""V4 authority-lineage regressions for persisted PhaseIO ledger records.

The V3 scalar repair made nested byte counts exact, but a caller could still
coherently replace every mutable copy of a producer authority and recompute
all ordinary digests.  These fixtures preserve the *consumer-captured*
producer receipt while replacing the producer-side projections.  A mutable
producer is never allowed to rewrite the immutable receipt already captured
by its consumer.

Every mutation publishes a matching canonical output-authority CAS object,
updates the journal and commit receipt, and removes the superseded CAS object.
The rejection therefore cannot be caused by a stale digest or duplicate CAS.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest

import artifact_ledger as AL
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "12345678-1234-4234-8234-123456789abc"


def _fixture(
    tmp_path: Path,
) -> tuple[Path, PhaseIOContract, LaunchSpec, dict[str, Any]]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    key = "sc/core/evm/claude/fixture/ledger_v4"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="fixture",
        work_unit_id="ledger_v4",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output.md",
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    AL.record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    (scratchpad / "output.md").write_bytes(b"x")
    AL.record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    ledger = AL.read_artifact_ledger(scratchpad)
    frozen = AL._input_binding_record(
        scratchpad,
        tmp_path,
        contract.outputs[0].identity,
        "IMMUTABLE",
        ledger,
    )
    assert frozen["status"] == "ACTIVE"
    assert frozen["producer_commit_receipt_digest"] == (
        ledger["work_units"][contract.key]["commit_authority"][
            "receipt_digest"
        ]
    )
    return scratchpad, contract, launch, frozen


def _publish_resealed_authority(
    scratchpad: Path,
    contract: PhaseIOContract,
    mutate: Callable[[
        dict[str, Any], dict[str, Any], dict[str, Any], str
    ], None],
) -> dict[str, Any]:
    journal_path = scratchpad / AL._OUTPUT_AUTHORITY_LEDGER_NAME
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert len(journal["authorities"]) == 1
    old_key, authority = next(iter(journal["authorities"].items()))
    old_digest = str(authority["authority_digest"])
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    identity = contract.outputs[0].identity

    mutate(authority, ledger, unit, identity)
    unsigned = {
        key: value
        for key, value in authority.items()
        if key != "authority_digest"
    }
    new_digest = AL._canonical_json_digest(unsigned)
    authority["authority_digest"] = new_digest
    new_key = str(authority["authority_key"])
    journal["authorities"] = {new_key: authority}
    journal_path.write_text(
        json.dumps(journal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    cas_root = scratchpad / AL._OUTPUT_AUTHORITY_CAS_DIRECTORY
    (cas_root / f"{new_digest}.json").write_bytes(
        AL._canonical_json_bytes(unsigned)
    )
    old_path = cas_root / f"{old_digest}.json"
    if old_digest != new_digest and old_path.exists():
        old_path.unlink()

    commit = unit["commit_authority"]
    commit["output_authority_key"] = new_key
    commit["output_authority_digest"] = new_digest
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    return ledger


def _mutate_source(
    authority: dict[str, Any],
    _ledger: dict[str, Any],
    unit: dict[str, Any],
    _identity: str,
) -> None:
    authority["source"] = "VALIDATED_EXPECTED_OUTPUT_RECORDS"
    unit["commit_authority"]["output_authority_source"] = authority["source"]


def _mutate_actor(
    authority: dict[str, Any],
    _ledger: dict[str, Any],
    unit: dict[str, Any],
    _identity: str,
) -> None:
    authority["actor"] = "MODEL"
    unit["commit_authority"]["output_authority_actor"] = "MODEL"


def _mutate_source_actor(
    authority: dict[str, Any],
    ledger: dict[str, Any],
    unit: dict[str, Any],
    identity: str,
) -> None:
    _mutate_source(authority, ledger, unit, identity)
    _mutate_actor(authority, ledger, unit, identity)


def _mutate_legacy_fallback(
    authority: dict[str, Any],
    _ledger: dict[str, Any],
    unit: dict[str, Any],
    _identity: str,
) -> None:
    authority["source"] = "WORKER_TRANSACTION_CAS"
    authority["actor"] = "MODEL"
    unit["commit_authority"].pop("output_authority_source", None)
    unit["commit_authority"].pop("output_authority_actor", None)


def _mutate_attempt(
    authority: dict[str, Any],
    _ledger: dict[str, Any],
    unit: dict[str, Any],
    _identity: str,
) -> None:
    authority["attempt_ordinal"] = 2
    authority["authority_key"] = AL._output_authority_key(
        run_id=RUN_ID,
        work_unit_key=unit["work_unit_key"],
        attempt_ordinal=2,
    )
    unit["commit_authority"]["attempt_ordinal"] = 2


def _mutate_input_digest(
    authority: dict[str, Any],
    _ledger: dict[str, Any],
    unit: dict[str, Any],
    _identity: str,
) -> None:
    replacement = hashlib.sha256(b"replacement-input-set").hexdigest()
    authority["input_set_digest"] = replacement
    unit["input_set_digest"] = replacement
    unit["commit_authority"]["input_set_digest"] = replacement


def _mutate_hash(
    authority: dict[str, Any],
    ledger: dict[str, Any],
    unit: dict[str, Any],
    identity: str,
) -> None:
    replacement = hashlib.sha256(b"replacement-output").hexdigest()
    authority["expected_output_records"][identity]["sha256"] = replacement
    authority["observed_outputs"][identity]["sha256"] = replacement
    unit["artifacts"][identity]["sha256"] = replacement
    unit["commit_authority"]["expected_output_records"][identity][
        "sha256"
    ] = replacement
    ledger["artifact_bindings"][identity]["sha256"] = replacement
    ledger["artifacts"]["output.md"]["sha256"] = replacement


def _mutate_size(
    authority: dict[str, Any],
    ledger: dict[str, Any],
    unit: dict[str, Any],
    identity: str,
) -> None:
    authority["expected_output_records"][identity]["size"] = 2
    authority["observed_outputs"][identity]["size"] = 2
    unit["artifacts"][identity]["size"] = 2
    unit["commit_authority"]["expected_output_records"][identity]["size"] = 2
    ledger["artifact_bindings"][identity]["size"] = 2
    ledger["artifacts"]["output.md"]["size"] = 2


def _mutate_physical_identity(
    authority: dict[str, Any],
    ledger: dict[str, Any],
    unit: dict[str, Any],
    identity: str,
) -> None:
    replacement = "file:replacement:identity"
    authority["observed_outputs"][identity][
        "physical_identity"
    ] = replacement
    unit["artifacts"][identity]["physical_identity"] = replacement
    ledger["artifact_bindings"][identity][
        "physical_identity"
    ] = replacement


ACCEPTED_INVALID_MUTATIONS = (
    ("source", _mutate_source),
    ("actor", _mutate_actor),
    ("source_actor", _mutate_source_actor),
    ("legacy_fallback", _mutate_legacy_fallback),
    ("attempt", _mutate_attempt),
    ("input_digest", _mutate_input_digest),
    ("artifact_hash", _mutate_hash),
    ("artifact_size", _mutate_size),
    ("physical_identity", _mutate_physical_identity),
)


@pytest.mark.parametrize(
    ("case", "mutate"),
    ACCEPTED_INVALID_MUTATIONS,
    ids=[row[0] for row in ACCEPTED_INVALID_MUTATIONS],
)
def test_v4_coherent_producer_reseal_cannot_rewrite_frozen_consumer_authority(
    tmp_path: Path,
    case: str,
    mutate: Callable[[dict[str, Any], dict[str, Any], dict[str, Any], str], None],
) -> None:
    scratchpad, contract, _launch, frozen = _fixture(tmp_path)
    ledger = _publish_resealed_authority(scratchpad, contract, mutate)
    # Coherently replace byte fields in the source record where applicable,
    # while preserving its independently captured producer receipt.
    binding = copy.deepcopy(frozen)
    current = ledger["artifact_bindings"][contract.outputs[0].identity]
    binding["sha256"] = current["sha256"]
    binding["size"] = current["size"]
    assert binding["producer_commit_receipt_digest"] != (
        ledger["work_units"][contract.key]["commit_authority"][
            "receipt_digest"
        ]
    ), case

    issues = AL.semantic_input_producer_authority_issues(
        ledger, binding, run_id=RUN_ID
    )
    assert issues, case
    with pytest.raises(AL.ArtifactLedgerError):
        AL.semantic_import_authority_from_snapshot(
            ledger,
            None,
            contract.outputs[0].identity,
            binding,
            run_id=RUN_ID,
        )


def _final_mutation(
    name: str,
) -> Callable[[dict[str, Any], dict[str, Any], dict[str, Any], str], None]:
    def mutate(
        authority: dict[str, Any],
        _ledger: dict[str, Any],
        unit: dict[str, Any],
        identity: str,
    ) -> None:
        commit = unit["commit_authority"]
        if name == "omit_source_hint":
            commit.pop("output_authority_source", None)
        elif name == "omit_actor_hint":
            commit.pop("output_authority_actor", None)
        elif name == "invalid_source_hint":
            commit["output_authority_source"] = "INVALID_SOURCE"
        elif name == "invalid_actor_hint":
            commit["output_authority_actor"] = "INVALID_ACTOR"
        elif name == "source_hint_only_swap":
            commit["output_authority_source"] = (
                "VALIDATED_EXPECTED_OUTPUT_RECORDS"
            )
        elif name == "actor_hint_only_swap":
            commit["output_authority_actor"] = "MODEL"
        elif name == "coherent_invalid_source":
            authority["source"] = "INVALID_SOURCE"
            commit["output_authority_source"] = "INVALID_SOURCE"
        elif name == "coherent_invalid_actor":
            authority["actor"] = "INVALID_ACTOR"
            commit["output_authority_actor"] = "INVALID_ACTOR"
        elif name == "observed_absent_with_bytes":
            authority["observed_outputs"][identity]["status"] = "ABSENT"
        elif name == "derived_key_substitution":
            authority["authority_key"] = "f" * 64
        elif name == "active_reason_code":
            authority["reason_codes"] = ["INVENTED_REASON"]
        else:  # pragma: no cover - fixture author error
            raise AssertionError(name)

    return mutate


FINAL_DIVERGENCE_CASES = (
    "omit_source_hint",
    "omit_actor_hint",
    "invalid_source_hint",
    "invalid_actor_hint",
    "source_hint_only_swap",
    "actor_hint_only_swap",
    "coherent_invalid_source",
    "coherent_invalid_actor",
    "observed_absent_with_bytes",
    "derived_key_substitution",
    "active_reason_code",
)


@pytest.mark.parametrize("case", FINAL_DIVERGENCE_CASES)
def test_v4_final_validator_agrees_with_active_producer_validator(
    tmp_path: Path,
    case: str,
) -> None:
    scratchpad, contract, launch, _frozen = _fixture(tmp_path)
    ledger = _publish_resealed_authority(
        scratchpad, contract, _final_mutation(case)
    )
    unit = ledger["work_units"][contract.key]
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) is False
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    ), case


def test_v4_exact_repair_fixture_reaches_postrepair_tamper_boundary(
    tmp_path: Path,
) -> None:
    # This is intentionally the production-backed integration setup whose V3
    # run stopped before any scalar/history tamper.  Importing the established
    # fixture avoids replacing the real driver/transaction boundary with a
    # mock that could conceal the recovery regression.
    from test_semantic_dedup_repair_fault_matrix import (
        _driver_repaired_fixture,
        _repair_unit,
    )

    _project, _scratchpad, _config, _expected, repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    assert repaired["safe_to_consume"] is True
    assert repaired["repaired"] is True
    _key, unit = _repair_unit(AL.read_artifact_ledger(_scratchpad))
    assert unit["committed_output_repair_history"][-1]["state"] == (
        "REPAIRED_ACTIVE"
    )
