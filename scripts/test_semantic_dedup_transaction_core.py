from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from semantic_dedup_transaction import (
    ABSORBED_MAP,
    APPLIED_RECEIPT,
    ATTESTATION_SCHEMA,
    DEDUPED_INVENTORY,
    FAILPOINTS,
    INVENTORY,
    OUTPUTS,
    PENDING,
    RECORDS,
    ROOT,
    SemanticDedupAuthorityCallbacks,
    SemanticDedupTransactionError,
    apply_semantic_dedup_transaction,
    capture_semantic_dedup_inputs,
    capture_semantic_dedup_output_prestate,
    recover_semantic_dedup_transaction,
)


RUN = "run-semantic-dedup-1"
PHASE = "semantic_dedup"
PROPOSAL = "dedup_decisions.md"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _records(inventory: bytes, marker: str) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "plamen.finding_records.v2",
                "source": INVENTORY,
                "source_sha256": _sha(inventory),
                "records": [{"inventory_id": marker}],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


class _Authority:
    def __init__(self, root: Path, expected_outputs: dict[str, bytes]):
        self.root = root
        self.expected_outputs = expected_outputs
        self.calls: list[str] = []

    def _row(self, request: Any, action: str) -> dict[str, Any]:
        self.calls.append(action)
        if action == "PHASEIO_COMMIT":
            # This is the actual RMW output commit, not a staging precommit.
            for relative, raw in self.expected_outputs.items():
                assert (self.root / relative).read_bytes() == raw
        kind = (
            "PHASE_IO"
            if action.startswith("PHASEIO_")
            else "SEMANTIC_MUTATION"
        )
        status = {
            "PHASEIO_ARM": "ARMED",
            "PHASEIO_COMMIT": "COMMITTED",
            "MUTATION_ARM": "ARMED",
            "MUTATION_FINALIZE": "FINALIZED",
        }[action]
        digest = _sha(
            f"{action}:{request.run_id}:{request.phase}:"
            f"{request.generation_digest}".encode()
        )
        return {
            "schema_version": ATTESTATION_SCHEMA,
            "run_id": request.run_id,
            "phase": request.phase,
            "generation_digest": request.generation_digest,
            "action": action,
            "authority_kind": kind,
            "status": status,
            "authority_id": f"test:{action.lower()}",
            "authority_digest": digest,
        }

    def callbacks(self) -> SemanticDedupAuthorityCallbacks:
        return SemanticDedupAuthorityCallbacks(
            phaseio_arm=lambda request: self._row(request, "PHASEIO_ARM"),
            phaseio_commit=lambda request: self._row(
                request, "PHASEIO_COMMIT"
            ),
            mutation_arm=lambda request: self._row(
                request, "MUTATION_ARM"
            ),
            mutation_finalize=lambda request: self._row(
                request, "MUTATION_FINALIZE"
            ),
        )


def _fixture(
    root: Path,
    *,
    existing_sidecars: bool = False,
) -> tuple[dict[str, Any], _Authority]:
    before_inventory = b"## [INV-001] old\n"
    before_records = _records(before_inventory, "INV-001")
    proposal = b"KEEP: INV-001\n"
    (root / INVENTORY).write_bytes(before_inventory)
    (root / RECORDS).write_bytes(before_records)
    (root / PROPOSAL).write_bytes(proposal)
    if existing_sidecars:
        (root / APPLIED_RECEIPT).write_bytes(b'{"old":true}\n')
        (root / ABSORBED_MAP).write_bytes(b"# old map\n")
        (root / DEDUPED_INVENTORY).write_bytes(before_inventory)

    # The canonical pair is a read-modify-write target.  It is authenticated
    # exclusively through the five-output prestate contract, never duplicated
    # as a read-only exact input.
    exact = (PROPOSAL,)
    expected_inputs = capture_semantic_dedup_inputs(root, exact)
    output_prestate = capture_semantic_dedup_output_prestate(root)
    post_inventory = b"## [INV-001] retained with full fields\n"
    post_records = _records(post_inventory, "INV-001")
    sidecars = {
        APPLIED_RECEIPT: b'{"schema_version":"test.applied.v1"}\n',
        ABSORBED_MAP: b"# absorbed aliases\n\nNone.\n",
        DEDUPED_INVENTORY: post_inventory,
    }
    outputs = {
        INVENTORY: post_inventory,
        RECORDS: post_records,
        **sidecars,
    }
    authority = _Authority(root, outputs)
    kwargs = {
        "scratchpad": root,
        "run_id": RUN,
        "phase": PHASE,
        "post_inventory": post_inventory,
        "post_records": post_records,
        "exact_inputs": exact,
        "proposal_inputs": (PROPOSAL,),
        "expected_inputs": expected_inputs,
        "expected_output_prestate": output_prestate,
        "staged_sidecars": sidecars,
        "authority_binding": {
            "run_id": RUN,
            "phase": PHASE,
            "work_unit_key": "l1/core/evm/claude/semantic_dedup/prequeue_apply",
            "contract_digest": "a" * 64,
        },
        "authority": authority.callbacks(),
    }
    return kwargs, authority


def _generation(root: Path) -> Path:
    generations = list((root / ROOT).glob("g_*"))
    assert len(generations) == 1
    return generations[0]


def test_success_is_five_output_committed_and_byte_idempotent(
    tmp_path: Path,
) -> None:
    kwargs, authority = _fixture(tmp_path)
    result = apply_semantic_dedup_transaction(**kwargs)

    assert result.state == "COMMITTED"
    assert result.safe_to_consume is True
    assert result.recovered is False
    assert not (tmp_path / PENDING).exists()
    for relative, raw in authority.expected_outputs.items():
        assert (tmp_path / relative).read_bytes() == raw
    generation = _generation(tmp_path)
    intent = json.loads((generation / "i.json").read_text())
    assert intent["publication_order"] == list(OUTPUTS)
    assert set(intent["outputs"]) == set(OUTPUTS)
    assert {row["path"] for row in intent["staged_sidecars"]} == {
        APPLIED_RECEIPT,
        ABSORBED_MAP,
        DEDUPED_INVENTORY,
    }
    assert all(
        intent["outputs"][row["path"]]["before"]["status"] == "MISSING"
        for row in intent["staged_sidecars"]
    )
    assert (tmp_path / ROOT / f"c_{result.generation_digest}.json").is_file()
    assert authority.calls.index("PHASEIO_COMMIT") > authority.calls.index(
        "MUTATION_ARM"
    )

    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    replay = apply_semantic_dedup_transaction(**kwargs)
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert replay.state == "COMMITTED"
    assert replay.recovered is True
    assert before == after


@pytest.mark.parametrize("failpoint", FAILPOINTS)
def test_every_fault_boundary_replays_without_early_commit(
    tmp_path: Path,
    failpoint: str,
) -> None:
    kwargs, authority = _fixture(tmp_path)
    fired = False

    def fault(name: str) -> None:
        nonlocal fired
        if name == failpoint and not fired:
            fired = True
            raise RuntimeError(f"fault:{name}")

    with pytest.raises(RuntimeError, match="fault:"):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    assert fired
    # The fake PHASEIO_COMMIT callback itself asserts all five exact outputs.
    result = apply_semantic_dedup_transaction(**kwargs)
    assert result.state == "COMMITTED"
    assert result.safe_to_consume is True
    for relative, raw in authority.expected_outputs.items():
        assert (tmp_path / relative).read_bytes() == raw


def test_present_sidecar_preimages_are_durable_and_recoverable(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path, existing_sidecars=True)

    def fault(name: str) -> None:
        if name == "AFTER_APPLIED_RECEIPT_REPLACED":
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    generation = _generation(tmp_path)
    intent = json.loads((generation / "i.json").read_text())
    assert all(
        intent["outputs"][row["path"]]["before"]["status"] == "PRESENT"
        and intent["outputs"][row["path"]]["before"]["payload"].startswith(
            "x/"
        )
        for row in intent["staged_sidecars"]
    )
    result = recover_semantic_dedup_transaction(
        scratchpad=tmp_path,
        run_id=RUN,
        phase=PHASE,
        authority_binding=kwargs["authority_binding"],
        authority=kwargs["authority"],
    )
    assert result is not None and result.state == "COMMITTED"


def test_foreign_canonical_state_is_never_overwritten_or_certified(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)
    foreign = b"FOREIGN\n"

    def fault(name: str) -> None:
        if name == "AFTER_INVENTORY_REPLACED":
            (tmp_path / INVENTORY).write_bytes(foreign)
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    with pytest.raises(SemanticDedupTransactionError, match="third state"):
        apply_semantic_dedup_transaction(**kwargs)
    assert (tmp_path / INVENTORY).read_bytes() == foreign
    assert (tmp_path / PENDING).is_file()


def test_foreign_sidecar_state_is_never_overwritten_or_certified(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)
    foreign = b"FOREIGN SIDECAR\n"

    def fault(name: str) -> None:
        if name == "AFTER_ABSORBED_MAP_REPLACED":
            (tmp_path / ABSORBED_MAP).write_bytes(foreign)
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    with pytest.raises(SemanticDedupTransactionError, match="third state"):
        apply_semantic_dedup_transaction(**kwargs)
    assert (tmp_path / ABSORBED_MAP).read_bytes() == foreign


def test_input_drift_after_generation_is_not_admitted(
    tmp_path: Path,
) -> None:
    kwargs, authority = _fixture(tmp_path)

    def fault(name: str) -> None:
        if name == "AFTER_GENERATION_DURABLE":
            (tmp_path / PROPOSAL).write_bytes(b"changed proposal\n")
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    with pytest.raises(SemanticDedupTransactionError, match="input changed"):
        apply_semantic_dedup_transaction(**kwargs)
    assert "PHASEIO_COMMIT" not in authority.calls
    assert not (tmp_path / PENDING).exists()


def test_input_drift_after_staged_pending_blocks_before_publication(
    tmp_path: Path,
) -> None:
    kwargs, authority = _fixture(tmp_path)

    def fault(name: str) -> None:
        if name == "AFTER_PENDING_STAGED_DURABLE":
            (tmp_path / PROPOSAL).write_bytes(b"changed proposal\n")
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    with pytest.raises(SemanticDedupTransactionError, match="input changed"):
        recover_semantic_dedup_transaction(
            scratchpad=tmp_path,
            run_id=RUN,
            phase=PHASE,
            authority_binding=kwargs["authority_binding"],
            authority=kwargs["authority"],
        )
    assert "PHASEIO_COMMIT" not in authority.calls
    assert (tmp_path / INVENTORY).read_bytes().startswith(b"## [INV-001] old")


def test_output_prestate_drift_blocks_before_phaseio_arm(tmp_path: Path) -> None:
    kwargs, authority = _fixture(tmp_path)
    (tmp_path / ABSORBED_MAP).write_bytes(b"appeared after snapshot\n")
    with pytest.raises(
        SemanticDedupTransactionError, match="appeared after prestate"
    ):
        apply_semantic_dedup_transaction(**kwargs)
    assert authority.calls == []
    assert not (tmp_path / ROOT).exists()


def test_post_verify_tamper_never_reaches_phaseio_commit(tmp_path: Path) -> None:
    kwargs, authority = _fixture(tmp_path)
    foreign = b"changed after verification\n"

    def fault(name: str) -> None:
        if name == "AFTER_PAIR_VERIFIED":
            (tmp_path / ABSORBED_MAP).write_bytes(foreign)

    with pytest.raises(SemanticDedupTransactionError, match="before PhaseIO"):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    assert "PHASEIO_COMMIT" not in authority.calls
    assert (tmp_path / ABSORBED_MAP).read_bytes() == foreign
    assert (tmp_path / PENDING).is_file()


def test_wrong_external_attestation_never_grants_commit(tmp_path: Path) -> None:
    kwargs, authority = _fixture(tmp_path)

    def wrong(request: Any) -> dict[str, Any]:
        row = authority._row(request, "PHASEIO_ARM")
        row["generation_digest"] = "0" * 64
        return row

    callbacks = SemanticDedupAuthorityCallbacks(
        phaseio_arm=wrong,
        phaseio_commit=kwargs["authority"].phaseio_commit,
        mutation_arm=kwargs["authority"].mutation_arm,
        mutation_finalize=kwargs["authority"].mutation_finalize,
    )
    with pytest.raises(SemanticDedupTransactionError, match="not exact"):
        apply_semantic_dedup_transaction(
            **{**kwargs, "authority": callbacks}
        )
    assert "PHASEIO_COMMIT" not in authority.calls
    assert not (tmp_path / PENDING).exists()


def test_wrong_run_phase_or_authority_binding_cannot_recover(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)

    def fault(name: str) -> None:
        if name == "AFTER_PENDING_STAGED_DURABLE":
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    with pytest.raises(SemanticDedupTransactionError):
        recover_semantic_dedup_transaction(
            scratchpad=tmp_path,
            run_id="another-run",
            phase=PHASE,
            authority_binding={
                **kwargs["authority_binding"],
                "run_id": "another-run",
            },
            authority=kwargs["authority"],
        )
    with pytest.raises(SemanticDedupTransactionError):
        recover_semantic_dedup_transaction(
            scratchpad=tmp_path,
            run_id=RUN,
            phase=PHASE,
            authority_binding={
                **kwargs["authority_binding"],
                "contract_digest": "b" * 64,
            },
            authority=kwargs["authority"],
        )


def test_tampered_intent_pending_and_receipt_fail_closed(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)

    def fault(name: str) -> None:
        if name == "AFTER_PENDING_STAGED_DURABLE":
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        apply_semantic_dedup_transaction(**kwargs, fault_hook=fault)
    generation = _generation(tmp_path)
    intent_path = generation / "i.json"
    original_intent = intent_path.read_bytes()
    intent_path.write_bytes(original_intent + b" ")
    with pytest.raises(SemanticDedupTransactionError):
        apply_semantic_dedup_transaction(**kwargs)
    intent_path.write_bytes(original_intent)

    pending_path = tmp_path / PENDING
    original_pending = pending_path.read_bytes()
    pending_path.write_bytes(original_pending + b" ")
    with pytest.raises(SemanticDedupTransactionError):
        apply_semantic_dedup_transaction(**kwargs)
    pending_path.write_bytes(original_pending)
    result = apply_semantic_dedup_transaction(**kwargs)

    receipt = tmp_path / ROOT / f"c_{result.generation_digest}.json"
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(SemanticDedupTransactionError):
        apply_semantic_dedup_transaction(**kwargs)


def test_invalid_post_records_and_incomplete_sidecars_rejected_before_arm(
    tmp_path: Path,
) -> None:
    kwargs, authority = _fixture(tmp_path)
    with pytest.raises(SemanticDedupTransactionError, match="does not bind"):
        apply_semantic_dedup_transaction(
            **{**kwargs, "post_records": b'{"records":[]}\n'}
        )
    sidecars = dict(kwargs["staged_sidecars"])
    sidecars.pop(ABSORBED_MAP)
    with pytest.raises(SemanticDedupTransactionError, match="exact three"):
        apply_semantic_dedup_transaction(
            **{**kwargs, "staged_sidecars": sidecars}
        )
    assert authority.calls == []


def test_one_run_phase_cannot_silently_start_a_second_generation(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)
    apply_semantic_dedup_transaction(**kwargs)

    new_inventory = b"## [INV-001] changed again\n"
    new_records = _records(new_inventory, "INV-001")
    next_kwargs = {
        **kwargs,
        "post_inventory": new_inventory,
        "post_records": new_records,
        "expected_inputs": capture_semantic_dedup_inputs(
            tmp_path, kwargs["exact_inputs"]
        ),
        "expected_output_prestate": capture_semantic_dedup_output_prestate(
            tmp_path
        ),
        "staged_sidecars": {
            **kwargs["staged_sidecars"],
            DEDUPED_INVENTORY: new_inventory,
        },
    }
    next_kwargs["authority"] = _Authority(
        tmp_path,
        {
            INVENTORY: new_inventory,
            RECORDS: new_records,
            **next_kwargs["staged_sidecars"],
        },
    ).callbacks()
    with pytest.raises(SemanticDedupTransactionError, match="another generation"):
        apply_semantic_dedup_transaction(**next_kwargs)


def test_cross_platform_safe_paths_and_short_private_names(
    tmp_path: Path,
) -> None:
    kwargs, _ = _fixture(tmp_path)
    result = apply_semantic_dedup_transaction(**kwargs)
    relatives = [
        path.relative_to(tmp_path).as_posix()
        for path in (tmp_path / ROOT).rglob("*")
    ]
    assert all("\\" not in relative and ".." not in relative for relative in relatives)
    assert max(len(relative) for relative in relatives) < 100
    assert result.generation_digest in _generation(tmp_path).name


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows symlink creation requires host policy privileges",
)
def test_symlink_source_and_private_root_are_rejected(tmp_path: Path) -> None:
    kwargs, _ = _fixture(tmp_path)
    target = tmp_path / "proposal.real"
    target.write_bytes((tmp_path / PROPOSAL).read_bytes())
    (tmp_path / PROPOSAL).unlink()
    (tmp_path / PROPOSAL).symlink_to(target)
    with pytest.raises(SemanticDedupTransactionError):
        apply_semantic_dedup_transaction(**kwargs)
