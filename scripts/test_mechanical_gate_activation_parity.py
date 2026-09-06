from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from mechanical_gate_inventory import (
    ActivationInventoryError,
    activation_inventory_digest,
    build_activation_inventory,
    compute_decision_code_digest,
    compute_legacy_module_code_digest,
    compute_source_tree_digest,
    discover_literal_activations,
    validate_activation_parity,
    validate_no_direct_call_bypass,
)
from mechanical_gate_registry import (
    LEGACY_MODULE_CODE_DIGEST_ALGORITHM,
    MechanicalGateRegistryError,
    strict_json_loads,
    validate_mechanical_gate_registry,
)
from test_mechanical_gate_registry_schema import (
    ACTIVATION_ID,
    GATE_ID,
    valid_registry_payload,
)


SOURCE = """\
from mechanical_gate_runtime import evaluate_registered_gate

_THRESHOLD = 3

def _fixture_guard_impl(context):
    return bool(context and len(context) >= _THRESHOLD)

def run_fixture_guard(context):
    return evaluate_registered_gate(
        "fixture.integrity_guard",
        activation_id="fixture.integrity_guard.recon",
        context=context,
        evaluator=_fixture_guard_impl,
    )

def main():
    return run_fixture_guard("fixture")

if __name__ == "__main__":
    main()
"""


def _write_source(root: Path, source: str = SOURCE) -> Path:
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    path = scripts / "gate_fixture.py"
    path.write_text(source, encoding="utf-8", newline="\n")
    return path


def _bound_registry_and_inventory(
    root: Path,
    source: str = SOURCE,
):
    _write_source(root, source)
    payload = valid_registry_payload()
    tree_digest = compute_source_tree_digest(
        root,
        production_roots=("scripts",),
        production_excludes=("scripts/test_*.py", "scripts/conftest.py"),
    )
    payload["migration"]["source_tree_digest"] = tree_digest
    payload["activation_inventory"]["source_tree_digest"] = tree_digest
    initial = validate_mechanical_gate_registry(payload)
    code_digest = compute_decision_code_digest(
        root, initial.gate_records[0].activations[0]
    )
    payload["gate_records"][0]["activations"][0][
        "code_digest"
    ] = code_digest
    registry = validate_mechanical_gate_registry(payload)
    inventory = build_activation_inventory(root, registry)
    payload["activation_inventory"]["manifest_sha256"] = (
        activation_inventory_digest(inventory)
    )
    payload["activation_inventory"]["generator_digest"] = inventory[
        "generator_digest"
    ]
    payload["activation_inventory"]["generator_version"] = inventory[
        "generator_version"
    ]
    registry = validate_mechanical_gate_registry(payload)
    inventory = build_activation_inventory(root, registry)
    return registry, inventory


def test_literal_discovery_and_fixture_inventory_are_deterministic(
    tmp_path: Path,
) -> None:
    registry, inventory = _bound_registry_and_inventory(tmp_path)
    rows = discover_literal_activations(
        tmp_path,
        production_roots=registry.registry_scope["production_roots"],
        production_excludes=registry.registry_scope[
            "production_excludes"
        ],
    )
    assert [(row.gate_id, row.activation_id) for row in rows] == [
        (GATE_ID, ACTIVATION_ID)
    ]
    assert build_activation_inventory(tmp_path, registry) == inventory
    assert validate_activation_parity(
        registry, inventory, source_root=tmp_path
    )["valid"] is True


def test_comments_and_locations_do_not_change_decision_closure_digest(
    tmp_path: Path,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    before = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    path = tmp_path / "scripts" / "gate_fixture.py"
    path.write_text(
        "\n\n# location-only change\n" + SOURCE.replace(
            "return bool(", "return bool(  # decision comment\n        "
        ),
        encoding="utf-8",
    )
    after = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    assert before == after


def test_transitive_constant_or_implementation_drift_changes_digest(
    tmp_path: Path,
) -> None:
    registry, inventory = _bound_registry_and_inventory(tmp_path)
    path = tmp_path / "scripts" / "gate_fixture.py"
    path.write_text(SOURCE.replace("_THRESHOLD = 3", "_THRESHOLD = 4"))
    changed = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    assert changed != inventory["activations"][0]["code_digest"]
    with pytest.raises(ActivationInventoryError):
        validate_activation_parity(
            registry, inventory, source_root=tmp_path
        )


@pytest.mark.parametrize(
    "replacement",
    (
        'gate_name,\n        activation_id="fixture.integrity_guard.recon"',
        '"fixture.integrity_guard",\n        activation_id=activation_name',
        '"fixture." + "integrity_guard",\n        activation_id="fixture.integrity_guard.recon"',
        'f"fixture.integrity_guard",\n        activation_id="fixture.integrity_guard.recon"',
    ),
)
def test_dynamic_or_computed_decision_ids_are_rejected(
    tmp_path: Path, replacement: str
) -> None:
    source = SOURCE.replace(
        '"fixture.integrity_guard",\n'
        '        activation_id="fixture.integrity_guard.recon"',
        replacement,
    )
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


def test_local_api_lookalike_is_not_a_registered_activation(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "from mechanical_gate_runtime import evaluate_registered_gate",
        (
            "def evaluate_registered_gate("
            "gate_id, *, activation_id, context, evaluator):\n"
            "    return evaluator(context)"
        ),
    )
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


@pytest.mark.parametrize(
    "source",
    (
        SOURCE.replace(
            "from mechanical_gate_runtime import evaluate_registered_gate",
            (
                "from mechanical_gate_runtime import evaluate_registered_gate\n"
                "evaluate_registered_gate = lambda *args, **kwargs: True"
            ),
        ),
        SOURCE.replace(
            "def run_fixture_guard(context):",
            (
                "def run_fixture_guard("
                "context, evaluate_registered_gate=lambda *args, **kwargs: True):"
            ),
        ),
        SOURCE.replace(
            "from mechanical_gate_runtime import evaluate_registered_gate",
            "import mechanical_gate_runtime",
        )
        .replace(
            "def run_fixture_guard(context):",
            "def run_fixture_guard(context, mechanical_gate_runtime=None):",
        )
        .replace(
            "return evaluate_registered_gate(",
            "return mechanical_gate_runtime.evaluate_registered_gate(",
        ),
    ),
)
def test_imported_gate_api_cannot_be_shadowed_by_a_local_binding(
    tmp_path: Path,
    source: str,
) -> None:
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path,
            production_roots=("scripts",),
            production_excludes=(),
        )


def test_evaluator_symbol_must_equal_declared_implementation(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "evaluator=_fixture_guard_impl",
        "evaluator=_other_guard_impl",
    ).replace(
        "def run_fixture_guard(context):",
        "def _other_guard_impl(context):\n"
        "    return True\n\n"
        "def run_fixture_guard(context):",
    )
    _write_source(tmp_path, source)
    payload = valid_registry_payload()
    registry = validate_mechanical_gate_registry(payload)
    with pytest.raises(ActivationInventoryError):
        build_activation_inventory(tmp_path, registry)


@pytest.mark.parametrize(
    "call_expression",
    (
        "getattr(__import__('mechanical_gate_runtime'), "
        "'evaluate_registered_gate')",
        "globals()['evaluate_registered_gate']",
        "globals()['evaluate_' + 'registered_gate']",
        "vars()['evaluate_' + 'registered_gate']",
        "globals()[f\"{'evaluate_'}registered_gate\"]",
        (
            "globals()['%s%s' % "
            "('evaluate_', 'registered_gate')]"
        ),
        (
            "__import__('mechanical_gate_runtime').__dict__"
            "['evaluate_' + 'registered_gate']"
        ),
        (
            "getattr(__import__('mechanical_gate_runtime'), "
            "'evaluate_{}'.format('registered_gate'))"
        ),
        "(lambda: evaluate_registered_gate)()",
    ),
)
def test_computed_reflection_or_dispatch_cannot_hide_gate_api(
    tmp_path: Path,
    call_expression: str,
) -> None:
    source = SOURCE.replace(
        "return evaluate_registered_gate(",
        f"return {call_expression}(",
    )
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


@pytest.mark.parametrize(
    "body",
    (
        (
            "def hidden(context, dynamic_name):\n"
            "    return invoke(\n"
            "        getattr(mechanical_gate_runtime, dynamic_name), context\n"
            "    )\n"
        ),
        (
            "def hidden(context, dynamic_name):\n"
            "    callbacks = (\n"
            "        getattr(mechanical_gate_runtime, dynamic_name),\n"
            "    )\n"
            "    return callbacks[0](context)\n"
        ),
        (
            "def hidden(context, dynamic_name):\n"
            "    runtime = __import__('mechanical_gate_runtime')\n"
            "    holder = (runtime,)\n"
            "    return invoke(getattr(holder[0], dynamic_name), context)\n"
        ),
    ),
)
def test_runtime_module_authority_cannot_escape_through_callback(
    tmp_path: Path,
    body: str,
) -> None:
    source = SOURCE.replace(
        "from mechanical_gate_runtime import evaluate_registered_gate",
        "import mechanical_gate_runtime\n"
        "from mechanical_gate_runtime import evaluate_registered_gate",
    )
    source += "\n\ndef invoke(callback, value):\n    return callback(value)\n"
    source += body
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


def test_concatenated_reflection_cannot_hide_unregistered_activation(
    tmp_path: Path,
) -> None:
    hidden = SOURCE + """\

def hidden_gate(context):
    return getattr(
        __import__("mechanical_gate_runtime"),
        "evaluate_" + "registered_gate",
    )(
        "hidden.uninventoried_gate",
        activation_id="hidden.uninventoried_gate.recon",
        context=context,
        evaluator=lambda value: True,
    )
"""
    _write_source(tmp_path, hidden)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


def test_variable_held_reflection_cannot_hide_unregistered_activation(
    tmp_path: Path,
) -> None:
    hidden = SOURCE.replace(
        "def run_fixture_guard(context):",
        "_GATE_API = 'evaluate_' + 'registered_gate'\n\n"
        "def run_fixture_guard(context):",
    ).replace(
        "return evaluate_registered_gate(",
        "return globals()[_GATE_API](",
    )
    _write_source(tmp_path, hidden)
    with pytest.raises(
        ActivationInventoryError,
        match="dynamic namespace subscript|namespace authority",
    ):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


@pytest.mark.parametrize("shape", ("nested", "class"))
def test_nested_or_class_same_leaf_wrapper_is_rejected(
    tmp_path: Path,
    shape: str,
) -> None:
    if shape == "nested":
        source = SOURCE.replace(
            "def run_fixture_guard(context):",
            "def outer():\n    def run_fixture_guard(context):",
        ).replace(
            "\ndef main():",
            "\n    return run_fixture_guard\n\ndef main():",
        )
    else:
        source = SOURCE.replace(
            "def run_fixture_guard(context):",
            "class Hidden:\n    def run_fixture_guard(self, context):",
        )
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


def test_literal_activation_missing_registry_and_registry_missing_code(
    tmp_path: Path,
) -> None:
    registry, inventory = _bound_registry_and_inventory(tmp_path)
    unknown = SOURCE.replace(
        '"fixture.integrity_guard"',
        '"fixture.unknown_guard"',
    ).replace(
        '"fixture.integrity_guard.recon"',
        '"fixture.unknown_guard.recon"',
    )
    (tmp_path / "scripts" / "gate_fixture.py").write_text(unknown)
    with pytest.raises(ActivationInventoryError):
        validate_activation_parity(
            registry, inventory, source_root=tmp_path
        )

    (tmp_path / "scripts" / "gate_fixture.py").write_text(
        SOURCE.replace("evaluate_registered_gate(", "not_a_gate(")
    )
    with pytest.raises(ActivationInventoryError):
        validate_activation_parity(
            registry, inventory, source_root=tmp_path
        )


def test_direct_implementation_call_outside_wrapper_is_a_bypass(
    tmp_path: Path,
) -> None:
    source = SOURCE + """\

def unrelated_entry(context):
    return _fixture_guard_impl(context)
"""
    registry, _ = _bound_registry_and_inventory(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    "module_name",
    ("scripts.helper", "helper"),
)
def test_cross_module_import_cannot_bypass_registered_implementation(
    tmp_path: Path,
    module_name: str,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "helper.py").write_text(
        "_THRESHOLD = 3\n"
        "def _fixture_guard_impl(context):\n"
        "    return bool(context and len(context) >= _THRESHOLD)\n",
        encoding="utf-8",
    )
    imported_source = f"""\
from mechanical_gate_runtime import evaluate_registered_gate
from {module_name} import _fixture_guard_impl

def run_fixture_guard(context):
    return evaluate_registered_gate(
        "fixture.integrity_guard",
        activation_id="fixture.integrity_guard.recon",
        context=context,
        evaluator=_fixture_guard_impl,
    )

if __name__ == "__main__":
    run_fixture_guard("fixture")
"""
    registry, _ = _bound_registry_and_inventory(
        tmp_path, imported_source
    )
    (scripts / "bypass.py").write_text(
        f"from {module_name} import _fixture_guard_impl\n"
        "def unrelated_entry(context):\n"
        "    return _fixture_guard_impl(context)\n",
        encoding="utf-8",
    )
    with pytest.raises(ActivationInventoryError):
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    "source_suffix",
    (
        "\nfrom mechanical_gate_runtime import *\n",
        "\n_GATE_CALL = evaluate_registered_gate\n",
        (
            "\n_ALIAS = _fixture_guard_impl\n"
            "def unrelated_entry(context):\n"
            "    return _ALIAS(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return getattr(globals(), '_fixture_guard_impl')(context)\n"
        ),
    ),
)
def test_star_import_callback_table_and_reflection_bypass_are_rejected(
    tmp_path: Path,
    source_suffix: str,
) -> None:
    with pytest.raises(ActivationInventoryError):
        registry, _ = _bound_registry_and_inventory(
            tmp_path, SOURCE + source_suffix
        )
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    "source_suffix",
    (
        (
            "\ndef unrelated_entry(context):\n"
            "    return globals()['_fixture_guard_impl'](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return globals()['_fixture_' + 'guard_impl'](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return vars()['_' + 'fixture_guard_impl'](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return globals()['{}'.format("
            "'_fixture_guard_impl')](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return globals()[''.join(("
            "'_fixture_', 'guard_impl'))](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return getattr(__import__(__name__), "
            "'{}'.format('_fixture_guard_impl'))(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return globals()[f\"{'_fixture_'}guard_impl\"]"
            "(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    return globals()[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    namespace = globals()\n"
            "    return namespace[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    return globals().get(key)(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    namespace = globals\n"
            "    return namespace()[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    namespace = (globals(),)[0]\n"
            "    return namespace[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    factory = (globals,)[0]\n"
            "    return factory()[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    namespace = globals().copy()\n"
            "    return namespace[key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    lookup = globals().get\n"
            "    return lookup(key)(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    lookup = globals().__getitem__\n"
            "    return lookup(key)(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    holder = {'ns': globals()}\n"
            "    return holder['ns'][key](context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    invoke = lambda namespace: namespace[key](context)\n"
            "    return invoke(globals())\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    import operator\n"
            "    key = '_fixture_' + 'guard_impl'\n"
            "    return operator.getitem(globals(), key)(context)\n"
        ),
        (
            "\ndef unrelated_entry(context):\n"
            "    return getattr(__import__(__name__), "
            "'Xfixture_guard_impl'.replace('X', '_'))(context)\n"
        ),
    ),
)
def test_dictionary_reflection_cannot_bypass_implementation_owner(
    tmp_path: Path,
    source_suffix: str,
) -> None:
    with pytest.raises(ActivationInventoryError):
        registry, _ = _bound_registry_and_inventory(
            tmp_path, SOURCE + source_suffix
        )
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    "import_line",
    (
        "from scripts import gate_fixture as gf",
        "from scripts import gate_fixture",
    ),
)
def test_package_module_importfrom_cannot_bypass_implementation_owner(
    tmp_path: Path,
    import_line: str,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    local = "gf" if " as gf" in import_line else "gate_fixture"
    (tmp_path / "scripts" / "bypass.py").write_text(
        f"{import_line}\n"
        "def unrelated_entry(context):\n"
        f"    return {local}._fixture_guard_impl(context)\n",
        encoding="utf-8",
    )
    with pytest.raises(ActivationInventoryError, match="bypasses"):
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    "body",
    (
        (
            "_IMPL = gf._fixture_guard_impl\n"
            "def unrelated_entry(context):\n"
            "    return _IMPL(context)\n"
        ),
        (
            "_MODULE = gf\n"
            "def unrelated_entry(context):\n"
            "    return _MODULE._fixture_guard_impl(context)\n"
        ),
        (
            "_INVOKE = lambda callback, value: callback(value)\n"
            "def unrelated_entry(context):\n"
            "    return _INVOKE(gf._fixture_guard_impl, context)\n"
        ),
        (
            "def unrelated_entry(context, dynamic_name):\n"
            "    namespace = gf.__dict__\n"
            "    return namespace[dynamic_name](context)\n"
        ),
        (
            "def unrelated_entry(context, dynamic_name):\n"
            "    return gf.__dict__.get(dynamic_name)(context)\n"
        ),
        (
            "_INVOKE = lambda callback, value: callback(value)\n"
            "def unrelated_entry(context, dynamic_name):\n"
            "    return _INVOKE(getattr(gf, dynamic_name), context)\n"
        ),
        (
            "def unrelated_entry(context, dynamic_name):\n"
            "    callbacks = (getattr(gf, dynamic_name),)\n"
            "    return callbacks[0](context)\n"
        ),
    ),
)
def test_package_module_implementation_cannot_escape_by_indirection(
    tmp_path: Path,
    body: str,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    (tmp_path / "scripts" / "bypass.py").write_text(
        "from scripts import gate_fixture as gf\n" + body,
        encoding="utf-8",
    )
    with pytest.raises(
        ActivationInventoryError,
        match=(
            "implementation reference|implementation module|"
            "namespace authority|namespace lookup"
        ),
    ):
        validate_no_direct_call_bypass(tmp_path, registry)


@pytest.mark.parametrize(
    ("import_line", "reference"),
    (
        ("from scripts import gate_fixture as gf", "gf"),
        ("import scripts.gate_fixture", "scripts.gate_fixture"),
    ),
)
def test_owner_module_constant_nonimplementation_getattr_is_allowed(
    tmp_path: Path,
    import_line: str,
    reference: str,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    (tmp_path / "scripts" / "benign.py").write_text(
        f"{import_line}\n"
        "def read_constant():\n"
        f"    return getattr({reference}, '_THRESHOLD')\n",
        encoding="utf-8",
    )
    validate_no_direct_call_bypass(tmp_path, registry)


def test_bare_annotation_is_not_treated_as_namespace_authority(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "_THRESHOLD = 3",
        "_DECLARED_ONLY: object\n_THRESHOLD = 3",
    )
    registry, inventory = _bound_registry_and_inventory(tmp_path, source)
    validate_activation_parity(
        registry, inventory, source_root=tmp_path
    )


def test_dotted_import_module_cannot_escape_implementation_owner(
    tmp_path: Path,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    (tmp_path / "scripts" / "bypass.py").write_text(
        "import scripts.gate_fixture\n"
        "def unrelated_entry(context, dynamic_name):\n"
        "    module = scripts.gate_fixture\n"
        "    return getattr(module, dynamic_name)(context)\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ActivationInventoryError,
        match="implementation module|callable reflection",
    ):
        validate_no_direct_call_bypass(tmp_path, registry)


def test_dotted_import_dynamic_getattr_callback_is_rejected(
    tmp_path: Path,
) -> None:
    registry, _ = _bound_registry_and_inventory(tmp_path)
    (tmp_path / "scripts" / "bypass.py").write_text(
        "import scripts.gate_fixture\n"
        "def invoke(callback, value):\n"
        "    return callback(value)\n"
        "def unrelated_entry(context, dynamic_name):\n"
        "    return invoke(\n"
        "        getattr(scripts.gate_fixture, dynamic_name), context\n"
        "    )\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ActivationInventoryError,
        match="implementation module",
    ):
        validate_no_direct_call_bypass(tmp_path, registry)


def test_selector_drift_in_generated_inventory_is_rejected(
    tmp_path: Path,
) -> None:
    registry, inventory = _bound_registry_and_inventory(tmp_path)
    drifted = copy.deepcopy(inventory)
    drifted["activations"][0]["modes"] = ["CORE"]
    with pytest.raises(ActivationInventoryError):
        validate_activation_parity(
            registry, drifted, source_root=tmp_path
        )


def test_source_tree_digest_binds_relative_name_mode_size_and_bytes(
    tmp_path: Path,
) -> None:
    _write_source(tmp_path)
    first = compute_source_tree_digest(
        tmp_path, production_roots=("scripts",)
    )
    source_path = tmp_path / "scripts" / "gate_fixture.py"
    renamed = source_path.with_name("gate_fixture_renamed.py")
    source_path.rename(renamed)
    second = compute_source_tree_digest(
        tmp_path, production_roots=("scripts",)
    )
    assert first != second


def test_dead_private_wrapper_is_not_counted_live(tmp_path: Path) -> None:
    source = SOURCE.replace(
        "def run_fixture_guard(context):",
        "def _dead_fixture_guard(context):",
    )
    _write_source(tmp_path, source)
    payload = valid_registry_payload()
    payload["gate_records"][0]["activations"][0][
        "wrapper_symbol"
    ] = "_dead_fixture_guard"
    registry = validate_mechanical_gate_registry(payload)
    with pytest.raises(ActivationInventoryError):
        build_activation_inventory(tmp_path, registry)


def test_dead_public_wrapper_and_dead_caller_chain_are_rejected(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "def main():\n    return run_fixture_guard(\"fixture\")",
        "def dead_caller():\n    return run_fixture_guard(\"fixture\")\n"
        "\ndef main():\n    return \"no gate\"",
    )
    _write_source(tmp_path, source)
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    with pytest.raises(ActivationInventoryError):
        build_activation_inventory(tmp_path, registry)


def test_dead_legacy_declared_owner_is_not_counted_live(
    tmp_path: Path,
) -> None:
    source = (
        "def dead_impl(context):\n"
        "    return bool(context)\n"
        "def dead_wrapper(context):\n"
        "    return dead_impl(context)\n"
        "def main():\n"
        "    return 'no gate'\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )
    _write_source(tmp_path, source)
    payload = valid_registry_payload()
    activation = payload["gate_records"][0]["activations"][0]
    activation["wrapper_symbol"] = "dead_wrapper"
    activation["implementation_symbols"] = ["dead_impl"]
    activation["runtime_state"] = "LEGACY_NOT_MIGRATED"
    activation["code_digest_algorithm"] = (
        LEGACY_MODULE_CODE_DIGEST_ALGORITHM
    )
    payload["gate_records"][0]["input_contracts"] = []
    payload["gate_records"][0]["output_contracts"] = []
    tree_digest = compute_source_tree_digest(
        tmp_path,
        production_roots=("scripts",),
        production_excludes=(
            "scripts/test_*.py",
            "scripts/conftest.py",
        ),
    )
    payload["migration"]["source_tree_digest"] = tree_digest
    payload["activation_inventory"]["source_tree_digest"] = tree_digest
    provisional = validate_mechanical_gate_registry(payload)
    activation["code_digest"] = compute_legacy_module_code_digest(
        tmp_path,
        provisional.gate_records[0].activations[0],
        production_roots=("scripts",),
        production_excludes=(
            "scripts/test_*.py",
            "scripts/conftest.py",
        ),
    )
    registry = validate_mechanical_gate_registry(payload)
    with pytest.raises(
        ActivationInventoryError,
        match="statically unreachable",
    ):
        build_activation_inventory(tmp_path, registry)


@pytest.mark.parametrize(
    "source",
    (
        (
            "import importlib\n"
            "def legacy_impl(context):\n"
            "    return bool(context)\n"
            "def legacy_wrapper(context):\n"
            "    return legacy_impl(context)\n"
            "def main(module_name):\n"
            "    module = importlib.import_module(module_name)\n"
            "    return module.legacy_wrapper('x')\n"
            "if __name__ == '__main__':\n"
            "    main('gate_fixture')\n"
        ),
        (
            "def legacy_impl(context):\n"
            "    return bool(context)\n"
            "def legacy_wrapper(context):\n"
            "    return legacy_impl(context)\n"
            "def main(key):\n"
            "    callbacks = {'gate': legacy_wrapper}\n"
            "    return callbacks[key]('x')\n"
            "if __name__ == '__main__':\n"
            "    main('gate')\n"
        ),
    ),
)
def test_legacy_liveness_cannot_be_invented_by_dynamic_dispatch(
    tmp_path: Path,
    source: str,
) -> None:
    _write_source(tmp_path, source)
    payload = valid_registry_payload()
    activation = payload["gate_records"][0]["activations"][0]
    activation["wrapper_symbol"] = "legacy_wrapper"
    activation["implementation_symbols"] = ["legacy_impl"]
    activation["runtime_state"] = "LEGACY_NOT_MIGRATED"
    activation["code_digest_algorithm"] = (
        LEGACY_MODULE_CODE_DIGEST_ALGORITHM
    )
    payload["gate_records"][0]["input_contracts"] = []
    payload["gate_records"][0]["output_contracts"] = []
    tree_digest = compute_source_tree_digest(
        tmp_path,
        production_roots=("scripts",),
        production_excludes=(
            "scripts/test_*.py",
            "scripts/conftest.py",
        ),
    )
    payload["migration"]["source_tree_digest"] = tree_digest
    payload["activation_inventory"]["source_tree_digest"] = tree_digest
    provisional = validate_mechanical_gate_registry(payload)
    activation["code_digest"] = compute_legacy_module_code_digest(
        tmp_path,
        provisional.gate_records[0].activations[0],
        production_roots=("scripts",),
        production_excludes=(
            "scripts/test_*.py",
            "scripts/conftest.py",
        ),
    )
    registry = validate_mechanical_gate_registry(payload)
    with pytest.raises(
        ActivationInventoryError,
        match="statically unreachable",
    ):
        build_activation_inventory(tmp_path, registry)


@pytest.mark.parametrize(
    "source",
    (
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if False:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "while False:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "main() if False else None",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if []:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if ():\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if 1 - 1:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if 0 == 1:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "[] and main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if {*()}:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if [*()]:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if (*(),):\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            "if {**{}}:\n    main()",
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            'if [*""]:\n    main()',
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            'if (*b"",):\n    main()',
        ),
        SOURCE.replace(
            'if __name__ == "__main__":\n    main()',
            'if {*""}:\n    main()',
        ),
        SOURCE.replace(
            "def run_fixture_guard(context):\n"
            "    return evaluate_registered_gate(",
            "def run_fixture_guard(context):\n"
            "    if False:\n"
            "        return evaluate_registered_gate(",
        ).replace(
            "\n\ndef main():",
            "\n    return True\n\n\ndef main():",
        ),
        SOURCE.replace(
            "def run_fixture_guard(context):",
            "def definition_time_gate(\n"
            "    result=evaluate_registered_gate(\n"
            '        "fixture.integrity_guard",\n'
            '        activation_id="fixture.integrity_guard.recon",\n'
            "        context={},\n"
            "        evaluator=_fixture_guard_impl,\n"
            "    ),\n"
            "):\n"
            "    return result\n\n"
            "def run_fixture_guard(context):",
        ),
    ),
)
def test_dead_path_and_definition_time_calls_are_not_runtime_liveness(
    tmp_path: Path,
    source: str,
) -> None:
    with pytest.raises(
        ActivationInventoryError,
        match=(
            "top-level wrapper|statically unreachable|activation parity"
        ),
    ):
        registry, inventory = _bound_registry_and_inventory(tmp_path, source)
        validate_activation_parity(
            registry, inventory, source_root=tmp_path
        )


def test_reachable_helper_is_bound_and_ambiguous_callback_is_rejected(
    tmp_path: Path,
) -> None:
    helper_source = SOURCE.replace(
        "def _fixture_guard_impl(context):\n"
        "    return bool(context and len(context) >= _THRESHOLD)",
        "def _helper(context):\n"
        "    return len(context) >= _THRESHOLD\n\n"
        "def _fixture_guard_impl(context):\n"
        "    return bool(context and _helper(context))",
    )
    registry, _ = _bound_registry_and_inventory(tmp_path, helper_source)
    before = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    path = tmp_path / "scripts" / "gate_fixture.py"
    path.write_text(helper_source.replace("return len(context)", "return 1 + len(context)"))
    after = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    assert before != after

    ambiguous = SOURCE.replace(
        "def _fixture_guard_impl(context):",
        "def _fixture_guard_impl(context, callback=lambda value: value):",
    ).replace(
        "return bool(context and len(context) >= _THRESHOLD)",
        "return callback(context)",
    )
    _write_source(tmp_path / "ambiguous", ambiguous)
    payload = valid_registry_payload()
    registry = validate_mechanical_gate_registry(payload)
    with pytest.raises(ActivationInventoryError):
        compute_decision_code_digest(
            tmp_path / "ambiguous",
            registry.gate_records[0].activations[0],
        )


def test_dotted_import_helper_drift_changes_decision_closure_digest(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "scripts"
    package = scripts / "pkg"
    package.mkdir(parents=True)
    (scripts / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    helper = package / "helper.py"
    helper.write_text(
        "def helper(context):\n"
        "    return bool(context)\n",
        encoding="utf-8",
    )
    source = SOURCE.replace(
        "from mechanical_gate_runtime import evaluate_registered_gate",
        "from mechanical_gate_runtime import evaluate_registered_gate\n"
        "import scripts.pkg.helper",
    ).replace(
        "return bool(context and len(context) >= _THRESHOLD)",
        "return scripts.pkg.helper.helper(context)",
    )
    registry, _ = _bound_registry_and_inventory(tmp_path, source)
    before = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    helper.write_text(
        "def helper(context):\n"
        "    return False\n",
        encoding="utf-8",
    )
    after = compute_decision_code_digest(
        tmp_path, registry.gate_records[0].activations[0]
    )
    assert before != after


def test_two_registered_decisions_hidden_in_one_wrapper_are_rejected(
    tmp_path: Path,
) -> None:
    source = SOURCE.replace(
        "return evaluate_registered_gate(",
        (
            "evaluate_registered_gate(\n"
            '        "fixture.second_guard",\n'
            '        activation_id="fixture.second_guard.recon",\n'
            "        context=context,\n"
            "        evaluator=_fixture_guard_impl,\n"
            "    )\n"
            "    return evaluate_registered_gate("
        ),
    )
    _write_source(tmp_path, source)
    with pytest.raises(ActivationInventoryError):
        discover_literal_activations(
            tmp_path, production_roots=("scripts",)
        )


def test_inventory_digest_is_closed_and_tamper_evident(
    tmp_path: Path,
) -> None:
    _, inventory = _bound_registry_and_inventory(tmp_path)
    before = activation_inventory_digest(inventory)
    tampered = copy.deepcopy(inventory)
    tampered["activations"][0]["source_line"] += 1
    assert activation_inventory_digest(tampered) != before
    tampered["unexpected"] = True
    with pytest.raises(ActivationInventoryError):
        activation_inventory_digest(tampered)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("gate_id", 7),
        ("activation_id", "BAD"),
        ("module", r"scripts\gate_fixture.py"),
        ("wrapper_symbol", 7),
        ("implementation_symbols", "_fixture_guard_impl"),
        ("source_line", 0),
        ("phases", "RECON"),
        ("runtime_state", "ACTIVE"),
        ("code_digest", "bad"),
        ("source_tree_digest", "bad"),
    ),
)
def test_inventory_rows_are_strictly_typed_and_closed(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    _, inventory = _bound_registry_and_inventory(tmp_path)
    malformed = copy.deepcopy(inventory)
    malformed["activations"][0][field] = value
    with pytest.raises(ActivationInventoryError):
        activation_inventory_digest(malformed)


def test_inventory_row_tree_digest_must_equal_top_level(
    tmp_path: Path,
) -> None:
    _, inventory = _bound_registry_and_inventory(tmp_path)
    malformed = copy.deepcopy(inventory)
    malformed["activations"][0]["source_tree_digest"] = "b" * 64
    with pytest.raises(ActivationInventoryError):
        activation_inventory_digest(malformed)


def test_parity_normalizes_hostile_inventory_types_to_domain_errors(
    tmp_path: Path,
) -> None:
    registry, inventory = _bound_registry_and_inventory(tmp_path)
    malformed = copy.deepcopy(inventory)
    malformed["activations"][0]["lifecycle_state"] = []
    with pytest.raises(ActivationInventoryError):
        validate_activation_parity(
            registry, malformed, source_root=tmp_path
        )


def test_source_root_alias_and_module_path_casefold_collision_are_rejected(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    _write_source(real)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(ActivationInventoryError):
            compute_source_tree_digest(
                alias, production_roots=("scripts",)
            )

    payload = valid_registry_payload()
    second = copy.deepcopy(payload["gate_records"][0])
    second["gate_id"] = "fixture.second_guard"
    second["execution_order"] = 11
    second["activations"][0]["activation_id"] = (
        "fixture.second_guard.recon"
    )
    second["activations"][0]["module"] = "Scripts/GATE_FIXTURE.py"
    for output in second["output_contracts"]:
        output["artifact_identity"] = str(
            output["artifact_identity"]
        ).replace(GATE_ID, "fixture.second_guard")
    payload["gate_records"].append(second)
    payload["migration"]["baseline_gate_ids"] = [
        GATE_ID,
        "fixture.second_guard",
    ]
    payload["migration"]["baseline_live_gate_count"] = 2
    payload["seam_budgets"][0]["baseline_gate_ids"] = [
        GATE_ID,
        "fixture.second_guard",
    ]
    payload["seam_budgets"][0]["active_gate_count"] = 2
    payload["seam_budgets"][0]["post_change_gate_count"] = 2
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


ROOT = Path(__file__).resolve().parents[1]
REFRESH_MANIFEST_PATH = (
    ROOT
    / "rules"
    / "mechanical-gate-migration-edits.activation-refresh.v1.json"
)
CANONICAL_REGISTRY_PATH = ROOT / "rules" / "mechanical-gate-registry.json"
CANONICAL_BASELINE_PATH = (
    ROOT / "rules" / "mechanical-gate-activation-baseline.v1.json"
)
REVIEWED_REGISTRY_SHA256 = (
    "be7b834e5d7ed171bd6081c2f7a8afa160cb660e9bec4ee5d13ef6dc4239d565"
)
REVIEWED_BASELINE_SHA256 = (
    "7d2c08c7691532577e3685aadaaa621669f2cc9ab3f5b6d771e389cb7d9d6a85"
)
REVIEWED_BASELINE_INVENTORY_SHA256 = (
    "7d2c08c7691532577e3685aadaaa621669f2cc9ab3f5b6d771e389cb7d9d6a85"
)
REVIEWED_SEMANTIC_PROJECTION_SHA256 = (
    "428938c62ab2cfda0653c76e93ec75920aa8deaa4ed439817a3af6137e6d1449"
)


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _registry_semantic_projection(payload: dict[str, object]) -> str:
    projected = copy.deepcopy(payload)
    projected["migration"]["source_tree_digest"] = "<SOURCE_TREE_DIGEST>"
    projected["activation_inventory"]["source_tree_digest"] = (
        "<SOURCE_TREE_DIGEST>"
    )
    projected["activation_inventory"]["manifest_sha256"] = (
        "<MANIFEST_SHA256>"
    )
    for gate in projected["gate_records"]:
        for activation in gate["activations"]:
            activation["code_digest"] = "<CODE_DIGEST>"
    return _canonical_json_sha256(projected)


def test_governed_refresh_is_closed_to_source_binding_fields() -> None:
    manifest = strict_json_loads(REFRESH_MANIFEST_PATH.read_bytes())
    assert set(manifest) == {
        "schema_version",
        "status",
        "reviewed_registry_preimage",
        "baseline_preimage",
        "refreshed_authority",
        "allowed_registry_delta_fields",
        "activation_identity_sha256",
        "activation_count",
        "missing_identities",
        "new_identities",
        "non_source_bound_semantic_deltas",
        "source_bound_delta_counts",
        "source_bound_deltas",
    }
    assert manifest["schema_version"] == (
        "plamen.mechanical_gate_activation_refresh.v1"
    )
    assert manifest["status"] == "AWAITING_INDEPENDENT_REVIEW"
    assert manifest["reviewed_registry_preimage"] == {
        "path": "rules/mechanical-gate-registry.json",
        "sha256": REVIEWED_REGISTRY_SHA256,
        "semantic_projection_sha256": (
            REVIEWED_SEMANTIC_PROJECTION_SHA256
        ),
    }
    assert manifest["baseline_preimage"] == {
        "path": "rules/mechanical-gate-activation-baseline.v1.json",
        "sha256": REVIEWED_BASELINE_SHA256,
        "source_tree_digest": (
            "a1059a20e203fa2797e322404cd9a155fc84941bb70195d7042104987f3483cf"
        ),
    }
    assert manifest["allowed_registry_delta_fields"] == [
        "migration.source_tree_digest",
        "activation_inventory.manifest_sha256",
        "activation_inventory.source_tree_digest",
        "gate_records[*].activations[*].code_digest",
    ]
    assert manifest["missing_identities"] == []
    assert manifest["new_identities"] == []
    assert manifest["non_source_bound_semantic_deltas"] == []
    assert manifest["source_bound_delta_counts"] == {
        "code_digest": 24,
        "source_line": 12,
        "source_tree_digest": 63,
    }

    registry_raw = CANONICAL_REGISTRY_PATH.read_bytes()
    baseline_raw = CANONICAL_BASELINE_PATH.read_bytes()
    registry = strict_json_loads(registry_raw)
    baseline = strict_json_loads(baseline_raw)
    refreshed = manifest["refreshed_authority"]
    assert hashlib.sha256(registry_raw).hexdigest() == refreshed[
        "registry_sha256"
    ]
    assert hashlib.sha256(baseline_raw).hexdigest() == refreshed[
        "baseline_sha256"
    ]
    assert activation_inventory_digest(baseline) == refreshed[
        "baseline_inventory_sha256"
    ]
    assert baseline["source_tree_digest"] == refreshed[
        "source_tree_digest"
    ]
    assert registry["migration"]["source_tree_digest"] == refreshed[
        "source_tree_digest"
    ]
    assert registry["activation_inventory"]["source_tree_digest"] == (
        refreshed["source_tree_digest"]
    )
    assert registry["activation_inventory"]["manifest_sha256"] == (
        refreshed["baseline_inventory_sha256"]
    )
    assert baseline["generator_version"] == refreshed[
        "generator_version"
    ]
    assert baseline["generator_digest"] == refreshed["generator_digest"]
    assert _registry_semantic_projection(registry) == (
        REVIEWED_SEMANTIC_PROJECTION_SHA256
    )

    identities = sorted(
        (row["gate_id"], row["activation_id"])
        for row in baseline["activations"]
    )
    assert len(identities) == manifest["activation_count"] == 63
    assert _canonical_json_sha256(identities) == manifest[
        "activation_identity_sha256"
    ]
    baseline_by_identity = {
        (row["gate_id"], row["activation_id"]): row
        for row in baseline["activations"]
    }
    registry_by_identity = {
        (gate["gate_id"], activation["activation_id"]): activation
        for gate in registry["gate_records"]
        for activation in gate["activations"]
    }
    observed_counts = {
        "code_digest": 0,
        "source_line": 0,
        "source_tree_digest": 0,
    }
    assert len(manifest["source_bound_deltas"]) == 63
    for delta in manifest["source_bound_deltas"]:
        assert set(delta) == {
            "gate_id",
            "activation_id",
            "changed_fields",
            "before",
            "after",
        }
        identity = (delta["gate_id"], delta["activation_id"])
        assert identity in baseline_by_identity
        assert identity in registry_by_identity
        assert set(delta["changed_fields"]) <= set(observed_counts)
        assert "source_tree_digest" in delta["changed_fields"]
        for field in delta["changed_fields"]:
            observed_counts[field] += 1
            assert baseline_by_identity[identity][field] == delta["after"][
                field
            ]
        assert registry_by_identity[identity]["code_digest"] == (
            baseline_by_identity[identity]["code_digest"]
        )
    assert observed_counts == manifest["source_bound_delta_counts"]
    assert sum(
        "code_digest" not in delta["changed_fields"]
        for delta in manifest["source_bound_deltas"]
    ) == 39

    predecessor_baseline = copy.deepcopy(baseline)
    predecessor_baseline["source_tree_digest"] = manifest[
        "baseline_preimage"
    ]["source_tree_digest"]
    predecessor_baseline_by_identity = {
        (row["gate_id"], row["activation_id"]): row
        for row in predecessor_baseline["activations"]
    }
    for delta in manifest["source_bound_deltas"]:
        predecessor = predecessor_baseline_by_identity[
            (delta["gate_id"], delta["activation_id"])
        ]
        for field, value in delta["before"].items():
            predecessor[field] = value
    assert activation_inventory_digest(predecessor_baseline) == (
        REVIEWED_BASELINE_INVENTORY_SHA256
    )

    predecessor_registry = copy.deepcopy(registry)
    predecessor_tree = manifest["baseline_preimage"][
        "source_tree_digest"
    ]
    predecessor_registry["migration"]["source_tree_digest"] = (
        predecessor_tree
    )
    predecessor_registry["activation_inventory"][
        "source_tree_digest"
    ] = predecessor_tree
    predecessor_registry["activation_inventory"]["manifest_sha256"] = (
        REVIEWED_BASELINE_INVENTORY_SHA256
    )
    predecessor_registry_by_identity = {
        (gate["gate_id"], activation["activation_id"]): activation
        for gate in predecessor_registry["gate_records"]
        for activation in gate["activations"]
    }
    for delta in manifest["source_bound_deltas"]:
        if "code_digest" not in delta["before"]:
            continue
        predecessor_registry_by_identity[
            (delta["gate_id"], delta["activation_id"])
        ]["code_digest"] = delta["before"]["code_digest"]
    predecessor_registry_raw = (
        json.dumps(
            predecessor_registry,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    assert hashlib.sha256(predecessor_registry_raw).hexdigest() == (
        REVIEWED_REGISTRY_SHA256
    )


def test_governed_refresh_projection_rejects_selector_mutation() -> None:
    manifest = strict_json_loads(REFRESH_MANIFEST_PATH.read_bytes())
    registry = strict_json_loads(CANONICAL_REGISTRY_PATH.read_bytes())
    expected = manifest["reviewed_registry_preimage"][
        "semantic_projection_sha256"
    ]
    assert _registry_semantic_projection(registry) == expected

    semantic_mutation = copy.deepcopy(registry)
    semantic_mutation["gate_records"][0]["activations"][0]["modes"] = [
        "THOROUGH"
    ]
    assert _registry_semantic_projection(semantic_mutation) != expected

    allowed_binding_mutation = copy.deepcopy(registry)
    allowed_binding_mutation["gate_records"][0]["activations"][0][
        "code_digest"
    ] = "f" * 64
    assert _registry_semantic_projection(allowed_binding_mutation) == expected
