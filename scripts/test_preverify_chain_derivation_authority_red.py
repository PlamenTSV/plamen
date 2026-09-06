"""Fixture-first RED contracts for chain derivation authority.

The atomic pair and chain-candidate delta are semantic providers, not merely
content-addressed storage.  Their receipts therefore require stable versioned
algorithms, checked-in conformance vectors, and outputs that can be rederived
from authenticated source bytes.  A hash of the current Python file is not an
algorithm identity and a self-consistent output digest is not source replay.

These tests intentionally avoid prescribing where an authenticated capability
is resolved.  They pin only the deterministic provider and receipt boundary.
No audit, model, network request, or non-temporary artifact is launched.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

import chain_candidate_inventory_union as DELTA
import preverify_chain_pair_projection as PAIR
import preverify_frozen_projection as FROZEN
import test_preverify_chain_candidate_delta as DELTA_FIXTURE
import test_preverify_chain_pair_projection as PAIR_FIXTURE


_PAIR_PUBLIC_CONTRACT = (
    "PAIR_DERIVATION_ALGORITHM",
    "PAIR_DERIVATION_CONFORMANCE_SHA256",
    "derive_preverify_chain_pair_relation",
    "derive_preverify_chain_pair_derivation_conformance_sha256",
    "validate_preverify_chain_pair_derivation_conformance",
)
_DELTA_PUBLIC_CONTRACT = (
    "DELTA_DERIVATION_ALGORITHM",
    "DELTA_DERIVATION_CONFORMANCE_SHA256",
    "derive_preverify_chain_candidate_payload",
    "derive_preverify_chain_candidate_derivation_conformance_sha256",
    "validate_preverify_chain_candidate_derivation_conformance",
)


def _required(module: Any, name: str) -> Any:
    assert hasattr(module, name), (
        f"{module.__name__} must expose the versioned derivation contract "
        f"{name}"
    )
    return getattr(module, name)


@pytest.mark.parametrize(
    ("module", "contract"),
    (
        (PAIR, _PAIR_PUBLIC_CONTRACT),
        (DELTA, _DELTA_PUBLIC_CONTRACT),
    ),
    ids=("pair", "candidate-delta"),
)
def test_chain_provider_exposes_versioned_derivation_contract(
    module: Any,
    contract: tuple[str, ...],
) -> None:
    missing = [name for name in contract if not hasattr(module, name)]
    assert missing == [], (
        f"{module.__name__} has no replayable derivation authority: "
        + ", ".join(missing)
    )
    for name in contract:
        value = getattr(module, name)
        if name.startswith(("derive_", "validate_")):
            assert callable(value), f"{module.__name__}.{name} is not callable"
        else:
            assert isinstance(value, str) and value.strip(), (
                f"{module.__name__}.{name} is not a stable identifier/digest"
            )


@pytest.mark.parametrize(
    (
        "module",
        "algorithm_name",
        "digest_name",
        "derive_digest_name",
        "validate_name",
        "algorithm_suffix",
    ),
    (
        (
            PAIR,
            "PAIR_DERIVATION_ALGORITHM",
            "PAIR_DERIVATION_CONFORMANCE_SHA256",
            "derive_preverify_chain_pair_derivation_conformance_sha256",
            "validate_preverify_chain_pair_derivation_conformance",
            ".v2",
        ),
        (
            DELTA,
            "DELTA_DERIVATION_ALGORITHM",
            "DELTA_DERIVATION_CONFORMANCE_SHA256",
            "derive_preverify_chain_candidate_derivation_conformance_sha256",
            "validate_preverify_chain_candidate_derivation_conformance",
            ".v1",
        ),
    ),
    ids=("pair", "candidate-delta"),
)
def test_checked_in_conformance_digest_matches_executable_algorithm(
    module: Any,
    algorithm_name: str,
    digest_name: str,
    derive_digest_name: str,
    validate_name: str,
    algorithm_suffix: str,
) -> None:
    algorithm = _required(module, algorithm_name)
    expected = _required(module, digest_name)
    derive_digest = _required(module, derive_digest_name)
    validate = _required(module, validate_name)

    assert isinstance(algorithm, str) and algorithm.endswith(algorithm_suffix)
    assert isinstance(expected, str) and len(expected) == 64
    assert derive_digest() == expected
    validate()


def test_pair_v2_accepts_only_an_explicit_typed_zero_relation() -> None:
    hypotheses = (
        b"# Hypotheses\n\n"
        b"<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
        b"| Hypothesis | Constituents |\n"
        b"|---|---|\n"
    )
    mapping = (
        b"# Finding Mapping\n\n"
        b"<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"|---|---|\n"
    )
    exact = PAIR.derive_preverify_chain_pair_relation(hypotheses, mapping)
    assert exact["state"] == "EXACT"
    assert exact["relation_edge_count"] == 0
    assert exact["hypotheses_parser"] == {
        "recognized_tables": 1,
        "candidate_rows": 0,
        "parsed_rows": 0,
        "complete": True,
    }
    assert exact["mapping_parser"]["complete"] is True

    missing_marker = PAIR.derive_preverify_chain_pair_relation(
        hypotheses.replace(b"<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n", b""),
        mapping,
    )
    assert missing_marker["state"] == "AMBIGUOUS"

    mismatched_marker = PAIR.derive_preverify_chain_pair_relation(
        hypotheses.replace(b"COUNT: 0", b"COUNT: 1"),
        mapping,
    )
    assert mismatched_marker["state"] == "AMBIGUOUS"


@pytest.mark.parametrize(
    ("module", "derive_name", "validate_name", "error_type"),
    (
        (
            PAIR,
            "derive_preverify_chain_pair_relation",
            "validate_preverify_chain_pair_derivation_conformance",
            PAIR.PreverifyChainPairProjectionError,
        ),
        (
            DELTA,
            "derive_preverify_chain_candidate_payload",
            "validate_preverify_chain_candidate_derivation_conformance",
            DELTA.ChainCandidateDeltaError,
        ),
    ),
    ids=("pair", "candidate-delta"),
)
def test_executable_drift_under_unchanged_algorithm_id_fails_conformance(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    derive_name: str,
    validate_name: str,
    error_type: type[Exception],
) -> None:
    _required(module, derive_name)
    validate = _required(module, validate_name)

    def drifted_derivation(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        return {"fixture_only_executable_drift": True}

    monkeypatch.setattr(module, derive_name, drifted_derivation)
    with pytest.raises(
        error_type,
        match="algorithm|conformance|digest|version",
    ):
        validate()


def _changed_provider_file(
    tmp_path: Path,
    module: Any,
    change: str,
) -> Path:
    original = Path(str(module.__file__)).read_bytes()
    if change == "comment":
        changed = original + b"\n# fixture-only nonsemantic comment\n"
    else:
        changed = (
            original.replace(b"\r\n", b"\n")
            if b"\r\n" in original
            else original.replace(b"\n", b"\r\n")
        )
    assert changed != original
    alternate = tmp_path / f"{module.__name__}-{change}.py"
    alternate.write_bytes(changed)
    return alternate


@pytest.mark.parametrize("change", ("comment", "crlf"))
def test_pair_generation_ignores_nonsemantic_provider_file_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    root, project = PAIR_FIXTURE._seed(tmp_path)
    first = PAIR_FIXTURE._prepare(root, project)
    monkeypatch.setattr(
        PAIR,
        "__file__",
        str(_changed_provider_file(tmp_path, PAIR, change)),
    )

    replay = PAIR_FIXTURE._prepare(root, project)

    assert replay["generation_digest"] == first["generation_digest"]
    assert replay["receipt_path"] == first["receipt_path"]


@pytest.mark.parametrize("change", ("comment", "crlf"))
def test_delta_generation_ignores_nonsemantic_provider_file_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    project, root, pair, _before = (
        DELTA_FIXTURE._accepted_delta_sources(tmp_path, monkeypatch)
    )
    kwargs = {
        "scratchpad": root,
        "project_root": project,
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase_name": "sc_verify_queue",
        "run_id": DELTA_FIXTURE.CHAIN_FIXTURE.RUN_ID,
        "chain_pair_projection": pair,
    }
    first = DELTA.prepare_preverify_chain_candidate_delta(**kwargs)
    monkeypatch.setattr(
        DELTA,
        "__file__",
        str(_changed_provider_file(tmp_path, DELTA, change)),
    )

    replay = DELTA.prepare_preverify_chain_candidate_delta(**kwargs)

    assert replay["generation_digest"] == first["generation_digest"]
    assert replay["candidate_path"] == first["candidate_path"]
    assert replay["receipt_path"] == first["receipt_path"]


def test_pair_receipt_binds_algorithm_not_python_file(
    tmp_path: Path,
) -> None:
    root, project = PAIR_FIXTURE._seed(tmp_path)
    result = PAIR_FIXTURE._prepare(root, project)
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )

    algorithm = _required(PAIR, "PAIR_DERIVATION_ALGORITHM")
    conformance = _required(
        PAIR,
        "PAIR_DERIVATION_CONFORMANCE_SHA256",
    )
    assert "provider_code_sha256" not in receipt
    assert receipt["derivation_algorithm"] == algorithm
    assert receipt["derivation_conformance_sha256"] == conformance


def test_delta_payload_and_receipt_bind_algorithm_not_python_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, root, pair, _before = (
        DELTA_FIXTURE._accepted_delta_sources(tmp_path, monkeypatch)
    )
    result = DELTA.prepare_preverify_chain_candidate_delta(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=DELTA_FIXTURE.CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )
    payload = json.loads(
        (root / result["candidate_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )

    algorithm = _required(DELTA, "DELTA_DERIVATION_ALGORITHM")
    conformance = _required(
        DELTA,
        "DELTA_DERIVATION_CONFORMANCE_SHA256",
    )
    for artifact in (payload, receipt):
        assert "provider_code_sha256" not in artifact
        assert artifact["derivation_algorithm"] == algorithm
        assert artifact["derivation_conformance_sha256"] == conformance


def test_coherent_forged_candidate_is_rejected_by_source_rederivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-digests cannot authorize semantics absent from source preimages.

    The existing fixture seam changes the writer's executable derivation while
    preserving its ordinary payload/receipt/PhaseIO path.  A correct provider
    rejects the unchanged algorithm ID through conformance before publication,
    or the frozen consumer independently rederives and rejects the candidate.
    """

    project, root, pair, _before = (
        DELTA_FIXTURE._accepted_delta_sources(tmp_path, monkeypatch)
    )
    original: Callable[..., tuple[dict[str, Any], list[dict[str, Any]]]] = (
        DELTA._derive_delta_payload
    )

    def forged(
        *args: Any,
        **kwargs: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        payload, debt = original(*args, **kwargs)
        changed = deepcopy(payload)
        row = changed["candidates"][0]
        row["description"] = (
            "Fixture-invented semantics absent from authenticated sources."
        )
        row["inventory_block"] = str(row["inventory_block"]).replace(
            "A generic chain-discovered precondition path.",
            "Fixture-invented semantics absent from authenticated sources.",
        )
        changed.pop("candidate_digest", None)
        changed["candidate_digest"] = DELTA._digest(changed)
        return changed, deepcopy(debt)

    monkeypatch.setattr(DELTA, "_derive_delta_payload", forged)

    with pytest.raises(
        FROZEN.PreverifyFrozenProjectionError,
        match="algorithm|conformance|derive|replay|source|candidate delta",
    ):
        FROZEN.prepare_preverify_frozen_projection(
            scratchpad=root,
            project_root=project,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase_name="sc_verify_queue",
            run_id=DELTA_FIXTURE.CHAIN_FIXTURE.RUN_ID,
            chain_pair_projection=pair,
        )
