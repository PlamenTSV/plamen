"""Focused regression for generic/typed artifact-state coexistence.

This suite deliberately uses minimal ledger fixtures.  It must not build an
audit snapshot or enumerate the runtime Python/Slither distribution.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import artifact_ledger as AL
import plamen_validators as PV


RUN_ID = "4ebffb67-6137-4cd5-9c2e-e53427603116"
CONTRACT_DIGEST = "c" * 64
LAUNCH_DIGEST = "d" * 64

INSTANTIATE_AFFECTED = (
    "attack_surface.md",
    "contract_inventory.md",
    "design_context.md",
    "detected_patterns.md",
    "function_list.md",
    "recon_summary.md",
    "skill_selection_catalog.json",
    "state_variables.md",
    "template_recommendations.md",
)
EXTERNAL_DEPENDENCY_CONTROL = "external_dependency_research.md"
GENERIC_ONLY_CONTROLS = (
    "build_status.md",
    "emit_list.md",
    "setter_list.md",
)
TYPED_AUTHORITY_FIELDS = (
    "owner_key",
    "run_id",
    "contract_digest",
    "launch_digest",
    "authority_level",
)


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_row_bytes(row: dict[str, Any]) -> bytes:
    return json.dumps(
        row,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _write_state(scratchpad: Path, state: dict[str, Any]) -> None:
    (scratchpad / "_artifact_state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _read_state(scratchpad: Path) -> dict[str, Any]:
    return json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )


def _materialize(scratchpad: Path, name: str) -> bytes:
    raw = f"fixture bytes for {name}\n".encode("utf-8")
    (scratchpad / name).write_bytes(raw)
    return raw


def _typed_legacy_row(
    scratchpad: Path,
    name: str,
    raw: bytes,
    *,
    ordinal: int,
) -> dict[str, Any]:
    metadata = (scratchpad / name).stat()
    return {
        "path": name,
        "owner_phase": "recon",
        "owner_key": (
            "sc/light/evm/claude/recon/"
            f"typed-producer-{ordinal:02d}"
        ),
        "run_id": RUN_ID,
        "contract_digest": CONTRACT_DIGEST,
        "launch_digest": LAUNCH_DIGEST,
        "authority_level": "ACTIVE_AUTHORITY",
        "status": "ACTIVE",
        "mtime_ns": metadata.st_mtime_ns,
        "size": len(raw),
        "sha256": _raw_sha256(raw),
        "updated_at": f"2026-08-26T00:00:{ordinal:02d}+00:00",
        # A distinctive typed extension proves that the generic recorder does
        # not rebuild a merely equivalent subset of the row.
        "typed_fixture_ordinal": ordinal,
    }


def _minimal_state(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": AL.LEDGER_VERSION,
        "artifacts": artifacts,
        "artifact_bindings": {},
        "work_units": {},
    }


def test_generic_recon_recording_preserves_all_typed_rows_exactly(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()

    typed_names = (*INSTANTIATE_AFFECTED, EXTERNAL_DEPENDENCY_CONTROL)
    typed_rows: dict[str, dict[str, Any]] = {}
    for ordinal, name in enumerate(typed_names, 1):
        raw = _materialize(scratchpad, name)
        typed_rows[name] = _typed_legacy_row(
            scratchpad, name, raw, ordinal=ordinal
        )

    # These files are materialized but genuinely absent from the ledger.  The
    # compatibility recorder must still do its ordinary ownership job for
    # them while leaving every typed row untouched.
    generic_raw = {
        name: _materialize(scratchpad, name)
        for name in GENERIC_ONLY_CONTROLS
    }
    _write_state(scratchpad, _minimal_state(typed_rows))

    before = _read_state(scratchpad)
    before_rows = {
        name: _canonical_row_bytes(before["artifacts"][name])
        for name in typed_names
    }
    before_authority = {
        name: tuple(
            before["artifacts"][name][field]
            for field in TYPED_AUTHORITY_FIELDS
        )
        for name in typed_names
    }

    materialized = PV._record_phase_artifact_state(
        scratchpad,
        str(tmp_path),
        [],
        "recon",
        "sc",
    )
    after = _read_state(scratchpad)

    # All nine formerly rejected instantiate inputs, including the
    # DRIVER-produced skill-selection catalog, retain their complete typed
    # authority.  The external dependency is a non-recon-owned control and is
    # unchanged as well.
    assert set(INSTANTIATE_AFFECTED).issubset(materialized)
    assert EXTERNAL_DEPENDENCY_CONTROL not in materialized
    for name in typed_names:
        assert after["artifacts"][name] == before["artifacts"][name]
        assert _canonical_row_bytes(after["artifacts"][name]) == before_rows[name]
        assert tuple(
            after["artifacts"][name][field]
            for field in TYPED_AUTHORITY_FIELDS
        ) == before_authority[name]

    for name, raw in generic_raw.items():
        row = after["artifacts"][name]
        assert name in materialized
        assert row["path"] == name
        assert row["owner_phase"] == "recon"
        assert row["status"] == "ACTIVE"
        assert row["size"] == len(raw)
        assert row["sha256"] == _raw_sha256(raw)
        assert not set(TYPED_AUTHORITY_FIELDS).intersection(row)


def test_each_typed_authority_marker_prevents_generic_reblessing(
    tmp_path: Path,
) -> None:
    """Partial/tampered typed rows remain debt instead of being repaired."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    names = (
        *GENERIC_ONLY_CONTROLS,
        "attack_surface.md",
        "contract_inventory.md",
    )
    rows: dict[str, dict[str, Any]] = {}
    for name, field in zip(names, TYPED_AUTHORITY_FIELDS, strict=True):
        raw = _materialize(scratchpad, name)
        rows[name] = {
            "path": name,
            "status": "ACTIVE",
            "size": len(raw),
            "sha256": _raw_sha256(raw),
            field: f"partial-{field}",
        }
    _write_state(scratchpad, _minimal_state(rows))
    before = _read_state(scratchpad)["artifacts"]

    PV._record_phase_artifact_state(
        scratchpad,
        str(tmp_path),
        [],
        "recon",
        "sc",
    )
    after = _read_state(scratchpad)["artifacts"]

    assert after == before


def test_ownerless_generic_row_remains_rejected_by_semantic_consumer(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    name = "attack_surface.md"
    identity = f"scratchpad:{name}"
    raw = _materialize(scratchpad, name)
    digest = _raw_sha256(raw)
    owner = "sc/light/evm/claude/recon/fixture-producer"

    authoritative = {
        "identity": identity,
        "owner_key": owner,
        "run_id": RUN_ID,
        "contract_digest": CONTRACT_DIGEST,
        "launch_digest": LAUNCH_DIGEST,
        "writer": "MODEL",
        "status": "ACTIVE",
        "size": len(raw),
        "sha256": digest,
    }
    # The legacy projection has exact bytes but no typed provenance.  Generic
    # recording may refresh this compatibility row; it must not mint producer
    # authority for it.
    ownerless = {
        "path": name,
        "owner_phase": "recon",
        "status": "ACTIVE",
        "size": len(raw),
        "sha256": digest,
        "mtime_ns": (scratchpad / name).stat().st_mtime_ns,
        "updated_at": "2026-08-26T00:00:00+00:00",
    }
    state = _minimal_state({name: ownerless})
    state["artifact_bindings"][identity] = dict(authoritative)
    state["work_units"][owner] = {
        "run_id": RUN_ID,
        "contract_digest": CONTRACT_DIGEST,
        "launch_digest": LAUNCH_DIGEST,
        "artifacts": {identity: dict(authoritative)},
    }
    _write_state(scratchpad, state)

    PV._record_phase_artifact_state(
        scratchpad,
        str(tmp_path),
        [],
        "recon",
        "sc",
    )
    after = _read_state(scratchpad)
    legacy = after["artifacts"][name]
    assert not set(TYPED_AUTHORITY_FIELDS).intersection(legacy)

    # Isolate the exact legacy-provenance predicate: the producer work unit's
    # commit receipt is assumed valid, so rejection can only come from the
    # owner-less legacy projection under test.  `_input_binding_record` is the
    # semantic consumer used when instantiate binds its exact denominator.
    monkeypatch.setattr(
        AL,
        "_active_commit_receipt_is_valid",
        lambda *args, **kwargs: True,
    )
    record = AL._input_binding_record(
        scratchpad,
        tmp_path,
        identity,
        "IMMUTABLE",
        after,
    )
    assert record["status"] == "PRODUCER_AUTHORITY_MISMATCH"
    assert not AL._producer_authority_is_active(
        after,
        after["artifact_bindings"][identity],
        identity=identity,
        run_id=RUN_ID,
    )


def test_suite_does_not_import_or_invoke_audit_snapshot() -> None:
    """Guard the focused suite against the 1,092-member snapshot replay."""

    import ast

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    forbidden_imports = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Import)
            and any(alias.name == "audit_snapshot" for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.module == "audit_snapshot"
        )
    ]
    forbidden_runtime_names = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "audit_snapshot"
    ]
    assert forbidden_imports == []
    assert forbidden_runtime_names == []
