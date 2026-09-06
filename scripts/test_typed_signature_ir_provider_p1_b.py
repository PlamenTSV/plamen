"""Provider-derived function signature/type IR acceptance fixtures.

The fixtures are deliberately ecosystem-generic and contain no benchmark or
protocol names.  Provider/compiler facts are authoritative for enumeration;
source regex is an explicitly weaker, visible fallback.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _tir():
    return importlib.import_module("enumeration_type_ir")


def _eg():
    return importlib.import_module("enumeration_gate")


def _rp():
    return importlib.import_module("recon_prepass")


def test_provider_signature_preserves_generic_receiver_visibility_and_mutability():
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="apply",
        bare_name="apply",
        provider_symbol="rust-analyzer cargo unit 1.0 crate::Store#apply().",
        raw_signature=(
            "pub(crate) async fn apply<'a, T: Clone>("
            "&'a mut self, item: T, limit: u64) -> Result<T, Error>"
        ),
        source_path=r"src\store.rs",
        source_line=9,
        source_sha256="a" * 64,
        kind="Method",
    )

    assert fact["authority"] == "COMPILER_PROVIDER"
    assert fact["source_binding"]["path"] == "src/store.rs"
    assert fact["visibility"] == "pub(crate)"
    assert fact["mutability"] == "MUTABLE_RECEIVER"
    assert fact["receiver"] == "&'a mut self"
    assert fact["generics"] == "<'a, T: Clone>"
    assert fact["returns"] == "Result<T, Error>"
    assert [row["name"] for row in fact["parameter_facts"]] == ["item", "limit"]
    assert [row["raw_type"] for row in fact["parameter_facts"]] == ["T", "u64"]
    assert all(row["authority"] == "COMPILER_PROVIDER" for row in fact["parameter_facts"])


def test_go_provider_signature_preserves_receiver_and_exported_visibility():
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem="go",
        provider="scip-go",
        function_identity="Apply",
        bare_name="Apply",
        provider_symbol="scip-go gomod example.invalid/unit Store#Apply().",
        raw_signature="func (s *Store[T]) Apply(value T, limit uint64) error",
        source_path="pkg\\store.go",
        source_line=13,
        source_sha256="b" * 64,
        kind="Method",
    )
    assert fact["receiver"] == "s *Store[T]"
    assert fact["visibility"] == "EXPORTED"
    assert fact["generics"] == ""
    assert fact["returns"] == "error"
    assert [row["name"] for row in fact["parameter_facts"]] == ["value", "limit"]


def test_go_provider_resolves_grouped_parameter_names_without_regex_guessing():
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem="go",
        provider="scip-go",
        function_identity="Apply",
        bare_name="Apply",
        provider_symbol="symbol Apply().",
        raw_signature="func Apply(first, second uint64)",
        source_path="pkg/module.go",
        source_line=2,
        source_sha256="b" * 64,
        kind="Function",
    )
    assert [(row["name"], row["raw_type"]) for row in fact["parameter_facts"]] == [
        ("first", "uint64"),
        ("second", "uint64"),
    ]
    assert all(row["fidelity"] == "PROVIDER_SIGNATURE" for row in fact["parameter_facts"])


@pytest.mark.parametrize(
    ("ecosystem", "signature", "expected"),
    [
        (
            "rust",
            "pub fn apply<F: Fn(u64) -> bool>(value: u64, check: F)",
            [("value", "u64"), ("check", "F")],
        ),
        (
            "go",
            "func Apply[T interface{ Check(uint64) bool }](value uint64, check T)",
            [("value", "uint64"), ("check", "T")],
        ),
    ],
)
def test_provider_signature_skips_callable_generic_constraints_before_parameters(
    ecosystem: str, signature: str, expected: list[tuple[str, str]],
):
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem=ecosystem,
        provider=f"scip-{ecosystem}",
        function_identity="Apply" if ecosystem == "go" else "apply",
        bare_name="Apply" if ecosystem == "go" else "apply",
        provider_symbol="provider symbol",
        raw_signature=signature,
        source_path="src/module.go" if ecosystem == "go" else "src/module.rs",
        source_line=7,
        source_sha256="7" * 64,
        kind="Function",
    )

    assert fact["parse_status"] == "EXACT"
    assert [
        (row["name"], row["raw_type"]) for row in fact["parameter_facts"]
    ] == expected


def test_signature_path_and_digest_are_stable_across_os_separator_forms():
    provider = _tir()
    kwargs = dict(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="read",
        bare_name="read",
        provider_symbol="symbol read().",
        raw_signature="pub fn read(key: &[u8]) -> Option<u64>",
        source_line=4,
        source_sha256="c" * 64,
        kind="Function",
    )
    windows = provider.build_function_signature_fact(
        source_path=r".\src\module.rs", **kwargs
    )
    posix = provider.build_function_signature_fact(
        source_path="src/module.rs", **kwargs
    )
    assert windows == posix


class _Occurrence:
    def __init__(self, path: str, line: int):
        self.relative_path = path
        self.start_line = line


class _Info:
    def __init__(self, signature: str, kind: str = "Function"):
        self.signature = signature
        self.kind = kind


class _OverloadedReader:
    def __init__(self, _index_path):
        self._definitions = {
            "rust-analyzer cargo unit 1.0 crate::left#apply().": _Occurrence("src/lib.rs", 0),
            "rust-analyzer cargo unit 1.0 crate::right#apply().": _Occurrence("src/lib.rs", 4),
            "rust-analyzer cargo unit 1.0 crate::one().": _Occurrence("src/lib.rs", 8),
            "rust-analyzer cargo unit 1.0 crate::two().": _Occurrence("src/lib.rs", 9),
            "rust-analyzer cargo unit 1.0 crate::three().": _Occurrence("src/lib.rs", 10),
        }
        self._references = {key: [] for key in self._definitions}
        self._symbol_info = {
            "rust-analyzer cargo unit 1.0 crate::left#apply().": _Info(
                "pub fn apply(value: u64)"
            ),
            "rust-analyzer cargo unit 1.0 crate::right#apply().": _Info(
                "pub fn apply(value: Address)"
            ),
            "rust-analyzer cargo unit 1.0 crate::one().": _Info("fn one()"),
            "rust-analyzer cargo unit 1.0 crate::two().": _Info("fn two()"),
            "rust-analyzer cargo unit 1.0 crate::three().": _Info("fn three()"),
        }

    @staticmethod
    def _extract_name_from_symbol(symbol: str) -> str:
        if "apply" in symbol:
            return "apply"
        return symbol.rsplit("::", 1)[-1].split("(", 1)[0]

    def stats(self):
        return {"definitions": 5, "documents": 1}


def test_scip_overloaded_same_name_functions_remain_distinct_and_bound(tmp_path: Path):
    rp = _rp()
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    (project / "src").mkdir(parents=True)
    source = (
        "pub fn apply(value: u64) {}\n\n\n\n"
        "pub fn apply(value: Address) {}\n\n\n\n"
        "fn one() {}\nfn two() {}\nfn three() {}\n"
    )
    (project / "src" / "lib.rs").write_text(source, encoding="utf-8")
    index = scratch / "scip_rust.index"
    index.write_bytes(b"x" * 200)

    fake_package = types.ModuleType("plamen_l1")
    fake_reader = types.ModuleType("plamen_l1.scip_reader")
    fake_reader.ScipReader = _OverloadedReader
    fake_package.scip_reader = fake_reader
    with mock.patch.dict(
        sys.modules,
        {"plamen_l1": fake_package, "plamen_l1.scip_reader": fake_reader},
    ), mock.patch.object(
        rp,
        "_capture_python_provider_authority",
        return_value={
            "schema": "plamen.runtime-tool-identity.v2",
            "tool_id": "protobuf",
            "identity_kind": "python_distribution",
            "authority_status": "MATCH",
            "deterministic_provider_authority": True,
            "authority_digest": "b" * 64,
        },
    ), mock.patch.object(
        rp,
        "_provider_authority_replays",
        return_value=True,
    ):
        assert rp._scip_to_graph_artifacts(
            scratch, index, project, ecosystem="rust"
        ).startswith("WRITTEN:")

    graph = json.loads(
        (scratch / "_mechanical_graph.json").read_text(encoding="utf-8")
    )
    apply_rows = [
        (identity, row)
        for identity, row in graph["functions"].items()
        if row["bare"] == "apply"
    ]
    assert len(apply_rows) == 2
    assert len({identity for identity, _row in apply_rows}) == 2
    assert {row["loc"] for _identity, row in apply_rows} == {
        "src/lib.rs:L1",
        "src/lib.rs:L5",
    }
    assert {
        row["signature_fact"]["canonical_signature"]
        for _identity, row in apply_rows
    } == {"pub fn apply(value: u64)", "pub fn apply(value: Address)"}
    assert all(
        row["signature_fact"]["source_binding"]["source_sha256"]
        == hashlib.sha256(source.encode("utf-8")).hexdigest()
        for _identity, row in apply_rows
    )
    summary = (scratch / "function_summary.md").read_text(encoding="utf-8")
    assert "Provider Signature" in summary
    assert "pub fn apply(value: u64)" in summary
    assert "pub fn apply(value: Address)" in summary


class _SolidityMapping:
    def __init__(self, path: str, line: int):
        self.filename = types.SimpleNamespace(short=path)
        self.lines = [line]


class _SolidityParameter:
    def __init__(self, name: str, type_name: str):
        self.name = name
        self.type = type_name


class _SolidityFunction:
    def __init__(self, contract, type_name: str, line: int):
        self.name = "apply"
        self.contract = contract
        self.source_mapping = _SolidityMapping("src/Module.sol", line)
        self.parameters = [_SolidityParameter("value", type_name)]
        self.returns = []
        self.full_name = f"apply({type_name})"
        self.canonical_name = f"Module.apply({type_name})"
        self.solidity_signature = f"apply({type_name})"
        self.visibility = "external"
        self.payable = False
        self.pure = False
        self.view = False
        self.state_variables_read = []
        self.state_variables_written = []
        self.internal_calls = []
        self.high_level_calls = []
        self.nodes = []


class _SolidityContract:
    def __init__(self):
        self.name = "Module"
        self.is_interface = False
        self.state_variables_declared = []
        self.functions_declared = []


def test_slither_overloads_and_compiler_type_fields_survive(tmp_path: Path):
    rp = _rp()
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    source = (
        "contract Module {\n"
        " function apply(uint256 value) external {}\n"
        " function apply(address value) external {}\n"
        "}\n"
    )
    (project / "src" / "Module.sol").write_text(source, encoding="utf-8")
    contract = _SolidityContract()
    contract.functions_declared = [
        _SolidityFunction(contract, "uint256", 2),
        _SolidityFunction(contract, "address", 3),
    ]
    fake_module = types.ModuleType("slither")

    class _Slither:
        def __init__(self, _target):
            self.contracts = [contract]

    fake_module.Slither = _Slither
    fake_module.__file__ = __file__
    authority = {
        "schema": "plamen.runtime-tool-identity.v2",
        "tool_id": "slither",
        "identity_kind": "python_distribution",
        "module_origin": __file__,
        "authority_status": "MATCH",
        "deterministic_provider_authority": True,
        "authority_digest": "a" * 64,
    }
    with mock.patch.dict(sys.modules, {"slither": fake_module}), mock.patch.object(
        rp,
        "_capture_python_provider_authority",
        return_value=authority,
    ), mock.patch.object(
        rp,
        "_provider_authority_replays",
        return_value=True,
    ):
        assert rp._bake_evm_slither_graph(scratch, project) == "WRITTEN"

    graph = json.loads(
        (scratch / "_mechanical_graph.json").read_text(encoding="utf-8")
    )
    rows = [row for row in graph["functions"].values() if row["bare"] == "apply"]
    assert len(rows) == 2
    assert {row["signature_fact"]["raw_parameters"] for row in rows} == {
        "uint256 value",
        "address value",
    }
    assert {row["signature_fact"]["visibility"] for row in rows} == {"external"}
    assert {row["signature_fact"]["mutability"] for row in rows} == {"nonpayable"}
    assert {
        row["signature_fact"]["parameter_facts"][0]["family"] for row in rows
    } == {"unsigned_integer", "address_identity"}
    assert all(
        row["signature_fact"]["authority"] == "COMPILER_PROVIDER" for row in rows
    )


def test_function_summary_consumer_reduces_typed_identities_to_bare_names(
    tmp_path: Path,
):
    eg = _eg()
    (tmp_path / "function_summary.md").write_text(
        "| Function | Callers | Provider Signature |\n"
        "|---|---|---|\n"
        "| `Module.apply(uint256)` | 3 | `apply(uint256)` |\n"
        "| `apply@src/module.rs:L7#ABCDEF` | 2 | `fn apply()` |\n",
        encoding="utf-8",
    )
    assert eg._load_function_summary(tmp_path) == {"apply": {"callers": 3}}


def test_hot_axis_evidence_for_one_overload_does_not_clear_its_sibling(
    tmp_path: Path,
):
    eg = _eg()
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    (project / "src" / "Module.sol").write_text(
        "function apply(uint256 value) external {}\n"
        "function apply(address value) external {}\n",
        encoding="utf-8",
    )
    first = "Module.apply(uint256)"
    second = "Module.apply(address)"
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "source": "slither",
                "functions": {
                    first: {
                        "bare": "apply",
                        "loc": "src/Module.sol:L1",
                        "callers": ["caller-a", "caller-b"],
                    },
                    second: {
                        "bare": "apply",
                        "loc": "src/Module.sol:L2",
                        "callers": ["caller-a", "caller-b"],
                    },
                },
                "var_refs": {},
            }
        ),
        encoding="utf-8",
    )
    (scratch / "findings_inventory.md").write_text(
        "### Finding [INV-001]: First overload boundary\n"
        "**Location**: `src/Module.sol:L1`\n"
        "**Description**: [BOUNDARY: value = 0] The first overload was examined.\n"
        "**Impact**: A state transition diverges.\n",
        encoding="utf-8",
    )

    eg.compute_axis_coverage_gaps(scratch)
    matrix = json.loads(
        (scratch / "_hot_function_axes.json").read_text(encoding="utf-8")
    )["matrix"]
    by_location = {row["loc"]: row for row in matrix}
    assert by_location["src/Module.sol:L1"]["cells"]["boundary"] == "EXAMINED"
    assert by_location["src/Module.sol:L2"]["cells"]["boundary"] == "GAP"


def _write_confirmed_inventory(scratch: Path, location: str) -> None:
    (scratch / "findings_inventory.md").write_text(
        "# Inventory\n\n"
        "### Finding [INV-001]: Boundary behavior\n"
        "**Severity**: Medium\n"
        f"**Location**: `{location}`\n"
        "**Verdict**: CONFIRMED\n"
        "**Source IDs**: SRC-1\n"
        "**Description**: No boundary class is discussed.\n"
        "**Impact**: A reachable transition may diverge.\n",
        encoding="utf-8",
    )


def test_boundary_consumer_prefers_bound_provider_fact_and_exposes_disagreement(
    tmp_path: Path,
):
    provider = _tir()
    eg = _eg()
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    source = "pub fn apply(value: u64) {}\n"
    path = project / "src" / "module.rs"
    path.write_text(source, encoding="utf-8")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    fact = provider.build_function_signature_fact(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="apply",
        bare_name="apply",
        provider_symbol="symbol apply().",
        raw_signature="pub fn apply(value: Address)",
        source_path="src/module.rs",
        source_line=1,
        source_sha256=digest,
        kind="Function",
    )
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "source": "scip",
                "functions": {
                    "apply": {
                        "bare": "apply",
                        "loc": "src/module.rs:L1",
                        "callers": [],
                        "signature_fact": fact,
                    }
                },
                "var_refs": {},
            }
        ),
        encoding="utf-8",
    )
    _write_confirmed_inventory(scratch, "src/module.rs:L1")

    candidates = eg.compute_boundary_input_candidates(scratch)
    assert {row["type_family"] for row in candidates} == {"address_identity"}
    obligations = json.loads(
        (scratch / "_boundary_input_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert {row["type_authority"] for row in obligations} == {"COMPILER_PROVIDER"}
    shortfalls = json.loads(
        (scratch / "_coverage_shortfalls.json").read_text(encoding="utf-8")
    )["shortfalls"]
    assert any(row["kind"] == "PROVIDER_REGEX_DISAGREEMENT" for row in shortfalls)


def test_ambiguous_regex_is_unknown_and_missing_provider_degrades_haltlessly(
    tmp_path: Path,
):
    provider = _tir()
    selection = provider.select_function_parameter_ir(
        ecosystem="go",
        provider_fact=None,
        fallback_raw_parameters="first, second uint64",
        type_facts={},
        source_path="pkg/module.go",
        source_line=2,
        source_sha256="d" * 64,
    )
    assert selection["authority"] == "REGEX_FALLBACK"
    assert selection["parameters"][0]["family"] == "unknown"
    assert selection["parameters"][0]["fidelity"] == "REGEX_AMBIGUOUS_UNKNOWN"
    assert selection["parameters"][1]["fidelity"] == "REGEX_FALLBACK"
    assert any(row["kind"] == "PROVIDER_SIGNATURE_UNAVAILABLE" for row in selection["debts"])


def test_stale_provider_binding_does_not_override_current_source():
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="apply",
        bare_name="apply",
        provider_symbol="symbol apply().",
        raw_signature="pub fn apply(value: Address)",
        source_path="src/module.rs",
        source_line=1,
        source_sha256="e" * 64,
        kind="Function",
    )
    selection = provider.select_function_parameter_ir(
        ecosystem="rust",
        provider_fact=fact,
        fallback_raw_parameters="value: u64",
        type_facts={},
        source_path="src/module.rs",
        source_line=1,
        source_sha256="f" * 64,
    )
    assert selection["authority"] == "REGEX_FALLBACK"
    assert selection["parameters"][0]["family"] == "unsigned_integer"
    assert any(row["kind"] == "PROVIDER_SOURCE_BINDING_MISMATCH" for row in selection["debts"])


def test_tampered_provider_signature_fails_to_regex_fallback():
    provider = _tir()
    fact = provider.build_function_signature_fact(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="apply",
        bare_name="apply",
        provider_symbol="symbol apply().",
        raw_signature="pub fn apply(value: Address)",
        source_path="src/module.rs",
        source_line=1,
        source_sha256="a" * 64,
        kind="Function",
    )
    fact["raw_parameters"] = "value: u64"
    selection = provider.select_function_parameter_ir(
        ecosystem="rust",
        provider_fact=fact,
        fallback_raw_parameters="value: u64",
        type_facts={},
        source_path="src/module.rs",
        source_line=1,
        source_sha256="a" * 64,
    )
    assert selection["authority"] == "REGEX_FALLBACK"
    assert selection["parameters"][0]["family"] == "unsigned_integer"
    assert any(row["kind"] == "PROVIDER_SIGNATURE_INVALID" for row in selection["debts"])


@pytest.mark.parametrize(
    ("baker", "relative_path", "source"),
    [
        ("_bake_rust_source_graph", "src/module.rs", "pub fn apply(value: u64) {}\n"),
        ("_bake_go_source_graph", "pkg/module.go", "package unit\nfunc Apply(value uint64) {}\n"),
        (
            "_bake_move_graph",
            "sources/module.move",
            "module 0x1::module { public fun apply(value: u64) {} }\n",
        ),
        (
            "_bake_evm_source_graph",
            "src/Module.sol",
            "contract Module {\n function apply(uint256 value) external {}\n}\n",
        ),
    ],
)
def test_source_only_ecosystem_providers_are_explicit_regex_fallback(
    tmp_path: Path, baker: str, relative_path: str, source: str,
):
    rp = _rp()
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    target = project / relative_path
    target.parent.mkdir(parents=True)
    scratch.mkdir()
    target.write_text(source, encoding="utf-8")
    assert getattr(rp, baker)(scratch, project) == "WRITTEN"
    graph = json.loads(
        (scratch / "_mechanical_graph.json").read_text(encoding="utf-8")
    )
    assert graph["functions"]
    assert graph["function_signatures"]
    for identity, row in graph["functions"].items():
        fact = row["signature_fact"]
        assert fact == graph["function_signatures"][identity]
        assert fact["authority"] == "REGEX_FALLBACK"
        assert fact["parse_status"] == "UNKNOWN"
        assert "\\" not in fact["source_binding"]["path"]


def test_fresh_scip_index_does_not_reuse_pre_signature_schema_graph(tmp_path: Path):
    rp = _rp()
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    project.mkdir()
    scratch.mkdir()
    (project / "lib.rs").write_text("pub fn read() {}\n", encoding="utf-8")
    index = scratch / "scip_rust.index"
    index.write_bytes(b"x" * 200)
    for name in (
        "caller_map.md", "callee_map.md", "state_write_map.md", "function_summary.md"
    ):
        (scratch / name).write_text("current", encoding="utf-8")
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps({"source": "scip", "functions": {}, "var_refs": {}}),
        encoding="utf-8",
    )
    assert not rp._scip_bake_is_fresh(scratch, project, index, (".rs",))


def test_scip_cache_rejects_source_hash_drift_even_when_mtime_is_older(
    tmp_path: Path,
):
    """A checkout can preserve/restore mtimes; source bytes remain authoritative."""
    provider = _tir()
    rp = _rp()
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    source_path = project / "src" / "lib.rs"
    old_source = "pub fn read(value: u64) {}\n"
    new_source = "pub fn read(value: Address) {}\n"
    source_path.write_text(new_source, encoding="utf-8")
    fact = provider.build_function_signature_fact(
        ecosystem="rust",
        provider="scip-rust",
        function_identity="read",
        bare_name="read",
        provider_symbol="symbol read().",
        raw_signature="pub fn read(value: u64)",
        source_path="src/lib.rs",
        source_line=1,
        source_sha256=hashlib.sha256(old_source.encode("utf-8")).hexdigest(),
        kind="Function",
    )
    graph = {
        "function_signature_schema": provider.FUNCTION_SIGNATURE_SCHEMA,
        "functions": {"read": {"bare": "read", "signature_fact": fact}},
        "function_signatures": {"read": fact},
    }
    index = scratch / "scip_rust.index"
    index.write_bytes(b"x" * 200)
    index_time = index.stat().st_mtime
    for name in (
        "caller_map.md", "callee_map.md", "state_write_map.md", "function_summary.md"
    ):
        path = scratch / name
        path.write_text("current", encoding="utf-8")
        os.utime(path, (index_time + 2, index_time + 2))
    graph_path = scratch / "_mechanical_graph.json"
    graph_path.write_text(json.dumps(graph), encoding="utf-8")
    os.utime(graph_path, (index_time + 2, index_time + 2))
    os.utime(source_path, (index_time - 2, index_time - 2))

    assert not rp._scip_bake_is_fresh(scratch, project, index, (".rs",))
