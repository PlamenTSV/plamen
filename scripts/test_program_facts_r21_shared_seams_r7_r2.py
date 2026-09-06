from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

import pytest

import artifact_ledger
import phase_io_contracts
import program_facts_positive_composer
from artifact_ledger import (
    ArtifactLedgerError,
    LEDGER_NAME,
    read_artifact_ledger,
)
from program_facts_v2_contracts import ProgramFactsTypeError
from review_fixtures.program_facts_r2_1_b0_red_support import (
    PUBLIC_IDENTITIES,
    canonical_bytes,
    logical_output_bytes,
    require_accepts,
    require_callable,
)
from test_program_facts_r21_3_test_composer_b0_red import (
    _authority_vector,
    _candidate_mapping,
    _candidate_validation_kwargs,
    _sealed_inputs,
)
from test_program_facts_r21_shared_seams_r7 import (
    LEDGER_CALLABLE,
    PHASEIO_CALLABLE,
    _active_prestate,
    _assert_selection_store,
    _commit_kwargs,
    _committer,
    _ledger_bytes,
    _phaseio_validator,
    _publication_vector,
    _selection_digest,
    _tree_bytes,
)


_GENERIC_LEDGER_KEYS = {
    "version",
    "artifacts",
    "artifact_bindings",
    "work_units",
}
_PROGRAM_FACTS_LEDGER_KEYS = {
    "program_facts_v2_generation_selections",
    "program_facts_v2_active_selection",
}


class _NestedFlip(Mapping[str, object]):
    def __init__(self) -> None:
        self.reads = 0

    def __getitem__(self, key: str) -> object:
        if key != "tag":
            raise KeyError(key)
        self.reads += 1
        return "first" if self.reads == 1 else "second"

    def __iter__(self) -> Iterator[str]:
        return iter(("tag",))

    def __len__(self) -> int:
        return 1


class _OuterFlip(Mapping[str, object]):
    def __init__(
        self,
        payload: Mapping[str, object],
        nested: _NestedFlip,
    ) -> None:
        self._payload = dict(payload)
        self._payload["facts"] = [nested]
        self.variant_reads = 0

    def __getitem__(self, key: str) -> object:
        if key == "selected_variant_ids":
            self.variant_reads += 1
            return (
                ["variant-a"]
                if self.variant_reads == 1
                else ["variant-b"]
            )
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


def _recursively_plain(value: Any) -> bool:
    if isinstance(value, Mapping):
        return type(value) is dict and all(
            _recursively_plain(key) and _recursively_plain(child)
            for key, child in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return type(value) is list and all(
            _recursively_plain(child) for child in value
        )
    return True


def _exact_signature_rows(
    callable_: Callable[..., Any],
) -> list[tuple[str, inspect._ParameterKind, Any, str]]:
    rows = []
    for parameter in inspect.signature(callable_).parameters.values():
        annotation = (
            ""
            if parameter.annotation is inspect.Parameter.empty
            else str(parameter.annotation)
        )
        rows.append(
            (
                parameter.name,
                parameter.kind,
                parameter.default,
                annotation,
            )
        )
    return rows


def _phaseio_core_vector(law: str):
    composer = require_callable(
        "program_facts_positive_composer",
        "compose_program_facts_v2_production",
        law,
    )
    core_validator = require_callable(
        "program_facts_positive_composer",
        "validate_production_composition_candidate",
        law,
    )
    inputs = _sealed_inputs()
    inputs["facts"] = [{"tag": "first"}]
    _environment, permit, authority = _authority_vector()
    candidate = require_accepts(
        composer,
        law,
        inputs,
        permit,
        **authority,
    )
    require_accepts(
        core_validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            inputs,
            permit,
            authority,
        ),
    )
    return _candidate_mapping(candidate), inputs, permit, authority


def _raw_ledger_document() -> dict[str, Any]:
    return {
        "version": 2,
        "artifacts": {},
        "artifact_bindings": {},
        "work_units": {},
    }


def _write_raw_ledger(root: Path, document: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            dict(document),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")
    (root / LEDGER_NAME).write_bytes(payload)


def _valid_selection_state(
    vector: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    selection = deepcopy(vector["selection"])
    digest = _selection_digest(selection)
    history = {
        selection["generation_id"]: {
            "selection_digest": digest,
            "selection_record": selection,
        }
    }
    pointer = {
        "state": "PRESENT",
        "generation_id": selection["generation_id"],
        "selection_digest": digest,
    }
    return history, pointer


def _path_key(path: os.PathLike[str] | str) -> str:
    return os.path.normcase(
        os.path.abspath(os.fspath(path))
    )


def test_shared_r2_phaseio_signature_and_export_are_exact() -> None:
    law = "PF-SHARED-R7-R2/phaseio-exact-signature-export"
    _phaseio_core_vector(law)
    target = _phaseio_validator(law)
    expected = [
        (
            "candidate",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.empty,
            "object",
        ),
        *[
            (
                name,
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.empty,
                annotation,
            )
            for name, annotation in (
                (
                    "sealed_composition_inputs",
                    "Mapping[str, Any]",
                ),
                (
                    "activation_permit_document",
                    "Mapping[str, Any]",
                ),
                ("provider_environment", "Mapping[str, Any]"),
                ("expected_run_id", "str"),
                ("expected_run_generation", "int"),
                (
                    "expected_execution_authority_digest",
                    "str",
                ),
                (
                    "expected_composition_authority_digest",
                    "str",
                ),
                (
                    "expected_methodology_package_digest",
                    "str",
                ),
                (
                    "expected_provider_environment_digest",
                    "str",
                ),
                (
                    "expected_provider_package_digest",
                    "str",
                ),
                (
                    "expected_native_host_receipt_digest",
                    "str",
                ),
                (
                    "expected_independent_review_receipts",
                    "Mapping[str, str]",
                ),
                ("expected_issuer_policy_digest", "str"),
                ("expected_issuer_id", "str"),
                ("expected_release_id", "str"),
                (
                    "expected_activation_decision_digest",
                    "str",
                ),
            )
        ],
    ]
    assert _exact_signature_rows(target) == expected
    assert str(inspect.signature(target).return_annotation) == "dict[str, Any]"
    assert phase_io_contracts.__all__.count(PHASEIO_CALLABLE) == 1


def test_shared_r2_phaseio_owns_recursive_snapshot_before_core_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7-R2/phaseio-owned-recursive-snapshot"
    candidate, ordinary_inputs, permit, authority = _phaseio_core_vector(law)
    nested = _NestedFlip()
    original_carrier = _OuterFlip(ordinary_inputs, nested)
    target = _phaseio_validator(law)
    original_snapshot = (
        program_facts_positive_composer
        .snapshot_sealed_composition_inputs_v1
    )
    original_validator = (
        program_facts_positive_composer
        .validate_production_composition_candidate
    )
    original_snapshot_calls = 0
    validator_calls = 0
    phase_snapshot: dict[str, Any] | None = None

    def snapshot_spy(value: Mapping[str, Any]) -> dict[str, Any]:
        nonlocal original_snapshot_calls, phase_snapshot
        result = original_snapshot(value)
        if value is original_carrier:
            original_snapshot_calls += 1
            phase_snapshot = result
        return result

    def validator_spy(
        value: object,
        **kwargs: Any,
    ) -> dict[str, Any]:
        nonlocal validator_calls
        validator_calls += 1
        supplied = kwargs["sealed_composition_inputs"]
        assert supplied is phase_snapshot
        assert supplied is not original_carrier
        assert _recursively_plain(supplied)
        return original_validator(value, **kwargs)

    monkeypatch.setattr(
        program_facts_positive_composer,
        "snapshot_sealed_composition_inputs_v1",
        snapshot_spy,
    )
    monkeypatch.setattr(
        program_facts_positive_composer,
        "validate_production_composition_candidate",
        validator_spy,
    )
    monkeypatch.setattr(
        phase_io_contracts,
        "snapshot_sealed_composition_inputs_v1",
        snapshot_spy,
        raising=False,
    )
    monkeypatch.setattr(
        phase_io_contracts,
        "validate_production_composition_candidate",
        validator_spy,
        raising=False,
    )
    observed = require_accepts(
        target,
        law,
        candidate,
        **_candidate_validation_kwargs(
            original_carrier,
            permit,
            authority,
        ),
    )
    assert _candidate_mapping(observed) == candidate
    assert original_snapshot_calls == 1
    assert validator_calls == 1
    assert original_carrier.variant_reads == 1
    assert nested.reads == 1


def test_shared_r2_phaseio_owned_root_caller_and_process_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7-R2/phaseio-bounded-side-effect-census"
    candidate, inputs, permit, authority = _phaseio_core_vector(law)
    kwargs = _candidate_validation_kwargs(inputs, permit, authority)
    target = _phaseio_validator(law)
    owned_root = tmp_path / "phaseio-owned-root"
    owned_root.mkdir()
    (owned_root / "sentinel").write_bytes(b"unchanged")
    monkeypatch.chdir(owned_root)
    before_objects = deepcopy(
        {
            "candidate": candidate,
            "inputs": inputs,
            "permit": permit,
            "authority": authority,
            "kwargs": kwargs,
        }
    )
    before_tree = _tree_bytes(owned_root)
    before_ledger = _ledger_bytes(owned_root)
    before_environment = dict(os.environ)
    before_modules = frozenset(sys.modules)
    before_cwd = os.getcwd()
    require_accepts(target, law, candidate, **kwargs)
    rejected = deepcopy(candidate)
    rejected["candidate_digest"] = "f" * 64
    with pytest.raises(ProgramFactsTypeError):
        target(rejected, **kwargs)
    assert {
        "candidate": candidate,
        "inputs": inputs,
        "permit": permit,
        "authority": authority,
        "kwargs": kwargs,
    } == before_objects
    assert _tree_bytes(owned_root) == before_tree
    assert _ledger_bytes(owned_root) == before_ledger
    assert dict(os.environ) == before_environment
    assert frozenset(sys.modules) == before_modules
    assert os.getcwd() == before_cwd


def test_shared_r2_ledger_signature_and_export_are_exact(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7-R2/ledger-exact-signature-export"
    root = tmp_path / ".scratchpad"
    _publication_vector(root, law)
    target = _committer(law)
    expected = [
        (
            "selection_record",
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.empty,
            "Mapping[str, Any]",
        ),
        (
            "arm_path",
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.empty,
            "Path",
        ),
        (
            "generation_manifest_path",
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.empty,
            "Path",
        ),
        (
            "logical_output_paths",
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.empty,
            "Mapping[str, Path]",
        ),
    ]
    assert _exact_signature_rows(target) == expected
    assert str(inspect.signature(target).return_annotation) == "dict[str, Any]"
    assert artifact_ledger.__all__.count(LEDGER_CALLABLE) == 1


@pytest.mark.parametrize(
    "target_name",
    ("arm", "manifest", *PUBLIC_IDENTITIES),
)
def test_shared_r2_idempotent_replay_reopens_each_of_all_five_files(
    tmp_path: Path,
    target_name: str,
) -> None:
    law = f"PF-SHARED-R7-R2/idempotent-reopen-{target_name}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    committer = _committer(law)
    require_accepts(committer, law, **_commit_kwargs(vector))
    if target_name == "arm":
        target = vector["arm_path"]
    elif target_name == "manifest":
        target = vector["manifest_path"]
    else:
        target = vector["output_paths"][target_name]
    target.write_bytes(target.read_bytes() + b"tampered")
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(vector))
    assert _ledger_bytes(root) == before_ledger


def test_shared_r2_successor_preserves_exact_prior_row_and_pointer_cas(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7-R2/successor-preserves-immutable-history"
    root = tmp_path / ".scratchpad"
    first = _publication_vector(root, law)
    committer = _committer(law)
    first_result = require_accepts(
        committer,
        law,
        **_commit_kwargs(first),
    )
    first_ledger = read_artifact_ledger(root)
    first_row = deepcopy(
        first_ledger["program_facts_v2_generation_selections"][
            first["selection"]["generation_id"]
        ]
    )
    first_row_bytes = canonical_bytes(first_row)
    successor = _publication_vector(
        root,
        law,
        prior_active=_active_prestate(first_result),
    )
    successor_result = require_accepts(
        committer,
        law,
        **_commit_kwargs(successor),
    )
    ledger = read_artifact_ledger(root)
    history = ledger["program_facts_v2_generation_selections"]
    assert set(history) == {
        first["selection"]["generation_id"],
        successor["selection"]["generation_id"],
    }
    assert history[first["selection"]["generation_id"]] == first_row
    assert (
        canonical_bytes(history[first["selection"]["generation_id"]])
        == first_row_bytes
    )
    assert history[successor["selection"]["generation_id"]] == {
        "selection_digest": _selection_digest(successor["selection"]),
        "selection_record": successor["selection"],
    }
    assert ledger["program_facts_v2_active_selection"] == {
        "state": "PRESENT",
        "generation_id": successor_result["generation_id"],
        "selection_digest": successor_result["selection_digest"],
    }
    assert set(ledger) == _GENERIC_LEDGER_KEYS | _PROGRAM_FACTS_LEDGER_KEYS


def test_shared_r2_reader_normalizes_only_exact_absent_selection_state(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7-R2/reader-exact-absent-default"
    root = tmp_path / ".scratchpad"
    _publication_vector(root, law)
    _committer(law)
    ledger = read_artifact_ledger(root)
    assert ledger["program_facts_v2_generation_selections"] == {}
    assert ledger["program_facts_v2_active_selection"] == {
        "state": "ABSENT"
    }
    assert set(ledger) == _GENERIC_LEDGER_KEYS | _PROGRAM_FACTS_LEDGER_KEYS


_MALFORMED_READER_STATES = (
    "pointer_only",
    "history_only",
    "pointer_row_mismatch",
    "malformed_digest",
    "unknown_row_key",
    "unknown_selection_record_shape",
    "unknown_program_facts_top_level",
)


@pytest.mark.parametrize("malformed_state", _MALFORMED_READER_STATES)
def test_shared_r2_reader_fails_closed_on_malformed_selection_state(
    tmp_path: Path,
    malformed_state: str,
) -> None:
    law = f"PF-SHARED-R7-R2/reader-malformed-{malformed_state}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    _committer(law)
    history, pointer = _valid_selection_state(vector)
    document = _raw_ledger_document()
    if malformed_state != "pointer_only":
        document["program_facts_v2_generation_selections"] = history
    if malformed_state != "history_only":
        document["program_facts_v2_active_selection"] = pointer
    generation_id = vector["selection"]["generation_id"]
    if malformed_state == "pointer_row_mismatch":
        document["program_facts_v2_active_selection"] = {
            **pointer,
            "selection_digest": "f" * 64,
        }
    elif malformed_state == "malformed_digest":
        document["program_facts_v2_generation_selections"][
            generation_id
        ]["selection_digest"] = "not-a-digest"
    elif malformed_state == "unknown_row_key":
        document["program_facts_v2_generation_selections"][
            generation_id
        ]["extra"] = "forbidden"
    elif malformed_state == "unknown_selection_record_shape":
        record = document[
            "program_facts_v2_generation_selections"
        ][generation_id]["selection_record"]
        record["extra"] = "forbidden"
        new_digest = hashlib.sha256(canonical_bytes(record)).hexdigest()
        document["program_facts_v2_generation_selections"][
            generation_id
        ]["selection_digest"] = new_digest
        document["program_facts_v2_active_selection"][
            "selection_digest"
        ] = new_digest
    elif malformed_state == "unknown_program_facts_top_level":
        document["program_facts_v2_unknown"] = {}
    _write_raw_ledger(root, document)
    before = (root / LEDGER_NAME).read_bytes()
    with pytest.raises(ArtifactLedgerError):
        read_artifact_ledger(root)
    assert (root / LEDGER_NAME).read_bytes() == before


@pytest.mark.parametrize("target_name", ("arm", PUBLIC_IDENTITIES[0]))
def test_shared_r2_replacement_during_stable_read_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
) -> None:
    law = f"PF-SHARED-R7-R2/stable-read-race-{target_name}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    target = (
        vector["arm_path"]
        if target_name == "arm"
        else vector["output_paths"][target_name]
    )
    committer = _committer(law)
    original_chain = artifact_ledger._lexical_no_follow_chain
    target_key = _path_key(target)
    target_chain_reads = 0

    def racing_chain(path: Path):
        nonlocal target_chain_reads
        if _path_key(path) == target_key:
            target_chain_reads += 1
            if target_chain_reads == 2:
                replacement = target.with_name(f"{target.name}.raced")
                replacement.write_bytes(target.read_bytes() + b"raced")
                os.replace(replacement, target)
        return original_chain(path)

    monkeypatch.setattr(
        artifact_ledger,
        "_lexical_no_follow_chain",
        racing_chain,
    )
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(vector))
    assert target_chain_reads >= 2
    assert _ledger_bytes(root) == before_ledger


def test_shared_r2_extra_complete_unselected_generation_is_never_discovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7-R2/unselected-generation-no-discovery"
    root = tmp_path / ".scratchpad"
    selected = _publication_vector(root, law)
    extra_prior = {
        "state": "PRESENT",
        "generation_id": "pfg-" + ("f" * 32),
        "selection_digest": "f" * 64,
    }
    extra = _publication_vector(
        root,
        law,
        prior_active=extra_prior,
    )
    assert (
        selected["selection"]["generation_id"]
        != extra["selection"]["generation_id"]
    )
    extra_tree = {
        path: path.read_bytes()
        for path in (
            extra["arm_path"],
            extra["manifest_path"],
            *tuple(extra["output_paths"].values()),
        )
    }
    future = 2_000_000_000
    for path in extra_tree:
        os.utime(path, (future, future))
    committer = _committer(law)
    generation_root = root / ".program_facts_public_generations"
    transaction_root = root / ".program_facts_publication_transactions"
    forbidden_roots = {
        _path_key(generation_root),
        _path_key(transaction_root),
    }
    discoveries: list[str] = []
    original_iterdir = Path.iterdir
    original_glob = Path.glob
    original_rglob = Path.rglob
    original_listdir = os.listdir
    original_scandir = os.scandir

    def record_path_discovery(
        operation: str,
        path: os.PathLike[str] | str,
    ) -> None:
        if _path_key(path) in forbidden_roots:
            discoveries.append(operation)
            raise AssertionError(
                f"unselected generation discovery via {operation}"
            )

    def guarded_iterdir(path: Path):
        record_path_discovery("Path.iterdir", path)
        return original_iterdir(path)

    def guarded_glob(path: Path, pattern: str):
        record_path_discovery("Path.glob", path)
        return original_glob(path, pattern)

    def guarded_rglob(path: Path, pattern: str):
        record_path_discovery("Path.rglob", path)
        return original_rglob(path, pattern)

    def guarded_listdir(path: Any = "."):
        if not isinstance(path, int):
            record_path_discovery("os.listdir", path)
        return original_listdir(path)

    def guarded_scandir(path: Any = "."):
        if not isinstance(path, int):
            record_path_discovery("os.scandir", path)
        return original_scandir(path)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)
    monkeypatch.setattr(Path, "glob", guarded_glob)
    monkeypatch.setattr(Path, "rglob", guarded_rglob)
    monkeypatch.setattr(os, "listdir", guarded_listdir)
    monkeypatch.setattr(os, "scandir", guarded_scandir)
    result = require_accepts(
        committer,
        law,
        **_commit_kwargs(selected),
    )
    assert result["generation_id"] == selected["selection"]["generation_id"]
    assert not discoveries
    ledger = _assert_selection_store(
        root,
        selection=selected["selection"],
        expected_history_count=1,
    )
    assert extra["selection"]["generation_id"] not in ledger[
        "program_facts_v2_generation_selections"
    ]
    assert {
        path: path.read_bytes() for path in extra_tree
    } == extra_tree


def _create_directory_reparse(
    link: Path,
    target: Path,
) -> tuple[bool, str]:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        return (
            completed.returncode == 0,
            (completed.stderr or completed.stdout).strip(),
        )
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        return False, str(exc)
    return True, ""


def test_shared_r2_parent_directory_reparse_is_rejected(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7-R2/parent-directory-reparse"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    committer = _committer(law)
    generation_directory = vector["manifest_path"].parent
    backing = root / "_reparse_backing_generation"
    generation_directory.replace(backing)
    created, detail = _create_directory_reparse(
        generation_directory,
        backing,
    )
    if not created:
        backing.replace(generation_directory)
        pytest.skip(f"directory reparse unavailable: {detail}")
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(vector))
    assert _ledger_bytes(root) == before_ledger


@pytest.mark.parametrize("failure_boundary", ("pre_replace", "post_replace"))
def test_shared_r2_successor_failure_keeps_complete_prior_or_postimage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_boundary: str,
) -> None:
    law = f"PF-SHARED-R7-R2/successor-failure-{failure_boundary}"
    root = tmp_path / ".scratchpad"
    first = _publication_vector(root, law)
    committer = _committer(law)
    first_result = require_accepts(
        committer,
        law,
        **_commit_kwargs(first),
    )
    prior_ledger_bytes = _ledger_bytes(root)
    prior_ledger = deepcopy(read_artifact_ledger(root))
    first_row = deepcopy(
        prior_ledger["program_facts_v2_generation_selections"][
            first["selection"]["generation_id"]
        ]
    )
    successor = _publication_vector(
        root,
        law,
        prior_active=_active_prestate(first_result),
    )
    evidence_files = (
        first["arm_path"],
        first["manifest_path"],
        *tuple(first["output_paths"].values()),
        successor["arm_path"],
        successor["manifest_path"],
        *tuple(successor["output_paths"].values()),
    )
    evidence_before = {path: path.read_bytes() for path in evidence_files}
    original_write = artifact_ledger.write_artifact_ledger

    if failure_boundary == "pre_replace":
        def injected_write(
            _root: Path,
            _ledger: dict[str, Any],
        ) -> None:
            raise ArtifactLedgerError("injected successor pre-replace failure")
    else:
        def injected_write(
            target_root: Path,
            ledger: dict[str, Any],
        ) -> None:
            original_write(target_root, ledger)
            raise ArtifactLedgerError("injected successor post-replace failure")

    monkeypatch.setattr(
        artifact_ledger,
        "write_artifact_ledger",
        injected_write,
    )
    try:
        committer(**_commit_kwargs(successor))
    except ArtifactLedgerError:
        pass
    if failure_boundary == "pre_replace":
        assert _ledger_bytes(root) == prior_ledger_bytes
        assert read_artifact_ledger(root) == prior_ledger
    else:
        ledger = read_artifact_ledger(root)
        history = ledger["program_facts_v2_generation_selections"]
        assert set(history) == {
            first["selection"]["generation_id"],
            successor["selection"]["generation_id"],
        }
        assert history[first["selection"]["generation_id"]] == first_row
        assert history[successor["selection"]["generation_id"]] == {
            "selection_digest": _selection_digest(successor["selection"]),
            "selection_record": successor["selection"],
        }
        assert ledger["program_facts_v2_active_selection"] == {
            "state": "PRESENT",
            "generation_id": successor["selection"]["generation_id"],
            "selection_digest": _selection_digest(successor["selection"]),
        }
    assert {path: path.read_bytes() for path in evidence_files} == evidence_before
