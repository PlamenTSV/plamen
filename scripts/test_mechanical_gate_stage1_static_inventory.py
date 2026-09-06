from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

import mechanical_gate_inventory as inventory_module
from mechanical_gate_inventory import (
    ActivationInventoryError,
    activation_inventory_digest,
    compute_decision_code_digest,
    compute_source_tree_digest,
    validate_activation_parity,
)
from mechanical_gate_registry import (
    DECISION_CODE_DIGEST_ALGORITHM,
    GateActivation,
    load_mechanical_gate_registry,
    strict_json_loads,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "rules" / "mechanical-gate-registry.json"
INVENTORY_PATH = (
    ROOT / "rules" / "mechanical-gate-activation-baseline.v1.json"
)
REFRESH_MANIFEST_PATH = (
    ROOT
    / "rules"
    / "mechanical-gate-migration-edits.activation-refresh.v1.json"
)


def test_generated_stage1_inventory_is_non_authoritative_and_exact() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    inventory = strict_json_loads(INVENTORY_PATH.read_bytes())
    assert inventory["runtime_authority_granted"] is False
    expected_activation_count = sum(
        len(record.activations)
        for record in registry.gate_records
        if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED"
    )
    assert len(inventory["activations"]) == expected_activation_count
    assert all(
        row["runtime_state"] == "LEGACY_NOT_MIGRATED"
        and row["literal_runtime_registration_present"] is False
        for row in inventory["activations"]
    )
    assert {
        row["gate_id"] for row in inventory["activations"]
    } == set(registry.migration["baseline_gate_ids"])


def test_inventory_bytes_tree_generator_and_registry_are_digest_bound() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    raw = INVENTORY_PATH.read_bytes()
    inventory = strict_json_loads(raw)
    refresh = strict_json_loads(REFRESH_MANIFEST_PATH.read_bytes())
    inventory_digest = activation_inventory_digest(inventory)
    assert hashlib.sha256(raw).hexdigest() == (
        refresh["refreshed_authority"]["baseline_sha256"]
    )
    assert inventory_digest == (
        registry.activation_inventory["manifest_sha256"]
    )
    assert inventory_digest == (
        refresh["refreshed_authority"]["baseline_inventory_sha256"]
    )
    assert inventory["source_tree_digest"] == (
        registry.migration["source_tree_digest"]
    )
    assert inventory["source_tree_digest"] == (
        registry.activation_inventory["source_tree_digest"]
    )
    assert inventory["generator_version"] == (
        registry.activation_inventory["generator_version"]
    )
    assert inventory["generator_digest"] == (
        registry.activation_inventory["generator_digest"]
    )


def test_static_legacy_activation_parity_recomputes_from_source() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    inventory = strict_json_loads(INVENTORY_PATH.read_bytes())
    receipt = validate_activation_parity(
        registry,
        inventory,
        source_root=ROOT,
    )
    assert receipt["valid"] is True
    assert receipt["activation_count"] == sum(
        len(record.activations)
        for record in registry.gate_records
        if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED"
    )
    assert receipt["runtime_authority_granted"] is False


def test_unrelated_rebinding_does_not_poison_exact_decision_closure(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    source = scripts / "gate.py"
    source.write_text(
        "UNRELATED = 1\n"
        "UNRELATED = 2\n"
        "BOUND = 3\n"
        "def _impl():\n"
        "    return BOUND\n"
        "def wrapper():\n"
        "    return _impl()\n",
        encoding="utf-8",
    )
    activation = GateActivation(
        activation_id="fixture.legacy.rebinding",
        module="scripts/gate.py",
        wrapper_symbol="wrapper",
        implementation_symbols=("_impl",),
        hook_id="fixture.legacy.rebinding",
        phases=("RECON",),
        pipelines=("SC",),
        modes=("THOROUGH",),
        ecosystems=("EVM",),
        backends=("CLAUDE",),
        runtime_state="LEGACY_NOT_MIGRATED",
        code_digest_algorithm=DECISION_CODE_DIGEST_ALGORITHM,
        code_digest="0" * 64,
    )
    before = compute_decision_code_digest(tmp_path, activation)
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "UNRELATED = 1", "UNRELATED = 4"
        ),
        encoding="utf-8",
    )
    assert compute_decision_code_digest(tmp_path, activation) == before


@pytest.mark.parametrize("mutation", ("add", "remove", "replace"))
def test_source_snapshot_rejects_moving_tree_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    first = scripts / "a.py"
    first.write_text("VALUE = 1\n", encoding="utf-8")
    removable = scripts / "z.py"
    removable.write_text("VALUE = 2\n", encoding="utf-8")
    original = inventory_module._read_source_entry
    fired = False

    def mutate_after_read(root: Path, path: Path):
        nonlocal fired
        entry = original(root, path)
        if not fired:
            fired = True
            if mutation == "add":
                (scripts / "late.py").write_text(
                    "VALUE = 3\n", encoding="utf-8"
                )
            elif mutation == "remove":
                removable.unlink()
            else:
                path.write_text("VALUE = 999\n", encoding="utf-8")
        return entry

    monkeypatch.setattr(
        inventory_module,
        "_read_source_entry",
        mutate_after_read,
    )
    with pytest.raises(ActivationInventoryError):
        compute_source_tree_digest(
            tmp_path,
            production_roots=("scripts",),
        )


def test_portable_mode_normalization_preserves_real_digest_sensitivity() -> None:
    entry = inventory_module._SourceEntry(
        relative_path="scripts/gate.py",
        path=Path("scripts/gate.py"),
        raw=b"VALUE = 1\n",
        mode=0o666,
        device=1,
        inode=2,
        size=10,
        modified_ns=3,
        changed_ns=4,
    )
    windows = inventory_module._SourceSnapshot(
        root=Path("."),
        entries=(entry,),
    )
    linux = inventory_module._SourceSnapshot(
        root=Path("."),
        entries=(replace(entry, mode=0o644),),
    )
    executable = inventory_module._SourceSnapshot(
        root=Path("."),
        entries=(replace(entry, mode=0o755),),
    )
    renamed = inventory_module._SourceSnapshot(
        root=Path("."),
        entries=(
            replace(entry, relative_path="scripts/renamed.py"),
        ),
    )
    changed = inventory_module._SourceSnapshot(
        root=Path("."),
        entries=(
            replace(entry, raw=b"VALUE = 2\n"),
        ),
    )
    digest = inventory_module._source_tree_digest_from_snapshot
    assert digest(windows) == digest(linux)
    assert digest(windows) != digest(executable)
    assert digest(windows) != digest(renamed)
    assert digest(windows) != digest(changed)


def test_source_snapshot_rejects_non_regular_python_path(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "unsafe.py").mkdir()
    with pytest.raises(ActivationInventoryError):
        compute_source_tree_digest(
            tmp_path,
            production_roots=("scripts",),
        )
