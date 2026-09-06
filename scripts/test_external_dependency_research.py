"""Fix B / Hook 1 — External-Dependency Research ledger + generic detection.

Covers the recon-owned prerequisites for the external-dependency research
mandate (Plan: "structured-toasting-parasol.md" Fix B):

1. Gate V prereq: `_mechanical_graph.json` now carries a "callees" key
   (previously computed in memory but never serialized) for the EVM/Slither
   graph writer, verified end-to-end for a fixture with a known call edge.
2. A GENERIC (non-brand) structural detector sets EXTERNAL_DEPENDENCY /
   NAMED_EXTERNAL_PROTOCOL for an unvendored, non-stdlib interface whose
   return value is consumed — and does NOT fire for a vendored/stdlib
   import or an in-repo-implemented interface.
3. `external_dependency_research.md` is always created (header-only when
   detection is empty) so a depth-phase worker (no live web tools) never
   sees a missing file.
4. A `FETCH_FAILED` row written by recon (LLM-enriched content) round-trips
   across a pre-pass re-run — never silently dropped/overwritten.

Every positive-harvest test asserts a NON-EMPTY landing (a synthetic
EXTERNAL_DEPENDENCY flag / ledger row / callees entry actually appears),
never merely "does not crash" — per the ID-regex-catalog lesson that an
over-loose gate with an empty harvest is worse than none.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import types
from pathlib import Path


def _rp():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("recon_prepass")


def _proj(tmp_path: Path):
    """<root> project dir plus a sibling `.scratchpad` the pre-pass writes to."""
    root = tmp_path / "proj"
    sp = root / ".scratchpad"
    sp.mkdir(parents=True)
    return root, sp


def _sol(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + body,
                 encoding="utf-8")
    return p


# ─────────────────────────────────────────────────────────────────────────────
# 1. Generic (non-brand) EXTERNAL_DEPENDENCY detection
# ─────────────────────────────────────────────────────────────────────────────

def test_generic_nonbranded_dep_with_consumed_return_sets_external_dependency(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    # A wholly synthetic, non-brand interface name — never vendored in-repo,
    # not a recognized ERC/EIP-standard or OZ/solmate/solady utility — whose
    # return value is consumed (assigned to a local).
    _sol(root, "Gateway.sol",
         "interface IZphyrGateway {\n"
         "    function relay(bytes calldata payload) external returns (uint256);\n"
         "}\n\n"
         "contract Gateway {\n"
         "    address public target;\n"
         "    function forward(bytes calldata payload) external {\n"
         "        uint256 result = IZphyrGateway(target).relay(payload);\n"
         "        require(result > 0, \"bad\");\n"
         "    }\n"
         "}\n")

    markers = rp._detect_external_dependency_markers(root)
    names = [n for n, _loc in markers]
    assert "IZphyrGateway" in names, markers

    status = rp._seed_external_dependency_flag(sp, root)
    assert status.startswith("DETECTED:"), status
    assert "EXTERNAL_DEPENDENCY" in status
    assert "NAMED_EXTERNAL_PROTOCOL" in status

    dp = (sp / "detected_patterns.md").read_text(encoding="utf-8")
    assert "EXTERNAL_DEPENDENCY" in dp
    assert "IZphyrGateway" in dp

    tr = sp / "template_recommendations.md"
    # Stub template_recommendations.md carrying the INTEGRATION_HAZARD_RESEARCH
    # row, as the real pre-pass writer would produce it.
    tr.write_text(
        rp._PREPASS_MARKER + "\n"
        "| | `INTEGRATION_HAZARD_RESEARCH` | NAMED_EXTERNAL_PROTOCOL flag | NO | - | |\n",
        encoding="utf-8",
    )
    # Re-run: the seed call flips the row (order-independent — call again).
    rp._seed_external_dependency_flag(sp, root)
    flipped = tr.read_text(encoding="utf-8")
    assert "YES" in flipped
    assert "IZphyrGateway" in flipped


def test_vendored_stdlib_import_does_not_set_external_dependency(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    # IERC20 is a recognized ERC-standard interface name (allowlisted) — even
    # though there's no in-repo implementation, this must NOT fire.
    _sol(root, "Vault.sol",
         "interface IERC20 {\n"
         "    function transfer(address to, uint256 amount) external returns (bool);\n"
         "}\n\n"
         "contract Vault {\n"
         "    address public token;\n"
         "    function sweep(address to, uint256 amount) external {\n"
         "        bool ok = IERC20(token).transfer(to, amount);\n"
         "        require(ok, \"fail\");\n"
         "    }\n"
         "}\n")

    markers = rp._detect_external_dependency_markers(root)
    names = [n for n, _loc in markers]
    assert "IERC20" not in names, markers

    status = rp._seed_external_dependency_flag(sp, root)
    assert status == "NOT_DETECTED", status


def test_in_repo_implemented_interface_does_not_set_external_dependency(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    # A non-standard interface name, but WITH a real vendored `contract`
    # implementation in-repo — the "implementation IS vendored" exclusion.
    _sol(root, "Router.sol",
         "interface ICustomRouter {\n"
         "    function swap(uint256 amountIn) external returns (uint256);\n"
         "}\n\n"
         "contract ICustomRouter_Impl {\n"
         "    function noop() external {}\n"
         "}\n\n"
         "contract ICustomRouter {\n"
         "    function swap(uint256 amountIn) external returns (uint256) { return amountIn; }\n"
         "}\n\n"
         "contract Caller {\n"
         "    address public router;\n"
         "    function go(uint256 amt) external {\n"
         "        uint256 out = ICustomRouter(router).swap(amt);\n"
         "    }\n"
         "}\n")

    markers = rp._detect_external_dependency_markers(root)
    names = [n for n, _loc in markers]
    assert "ICustomRouter" not in names, markers


def test_external_dependency_detector_never_raises_on_garbage(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    _sol(root, "Broken.sol", "interface I{ this is not valid solidity {{{ ")
    # Must degrade to a (possibly empty) list, never raise.
    markers = rp._detect_external_dependency_markers(root)
    assert isinstance(markers, list)
    status = rp._seed_external_dependency_flag(sp, root)
    assert status in ("NOT_DETECTED",) or status.startswith("DETECTED:") or status.startswith("FAILED:")


# ─────────────────────────────────────────────────────────────────────────────
# 2. external_dependency_research.md ledger: stub creation + FETCH_FAILED
#    round-trip (never dropped)
# ─────────────────────────────────────────────────────────────────────────────

def test_ledger_created_with_header_when_detection_empty(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    status = rp._write_external_dependency_research_stub(sp)
    assert status == "STUB", status
    ledger = sp / "external_dependency_research.md"
    assert ledger.exists()
    text = ledger.read_text(encoding="utf-8")
    assert "External Dependency Research Ledger" in text
    assert "| Dependency | Integration Surface" in text
    assert "Conformance" in text
    assert "Fetch Status" in text


def test_fetch_failed_row_round_trips_never_dropped(tmp_path: Path):
    rp = _rp()
    root, sp = _proj(tmp_path)
    # First: the pre-pass writes the stub (as run_recon_prepass would, before
    # the recon LLM enriches it).
    rp._write_external_dependency_research_stub(sp)

    # Recon LLM enriches the file: the marker header is REPLACED with real
    # content (no _PREPASS_MARKER first line) that includes a carried-forward
    # FETCH_FAILED row — exactly the "never silently dropped" contract.
    enriched = (
        "# External Dependency Research Ledger\n\n"
        "| Dependency | Integration Surface | Assumed Behavior | Real Behavior | "
        "Source | Conformance | Fetch Status |\n"
        "|------------|----------------------|-------------------|-----------------|"
        "--------|-------------|---------------|\n"
        "| IZphyrGateway | Gateway.sol:L8 | relay() always succeeds | UNKNOWN | "
        "n/a | CHECK | FETCH_FAILED:network_unreachable |\n"
    )
    ledger = sp / "external_dependency_research.md"
    ledger.write_text(enriched, encoding="utf-8")

    # Simulate a pre-pass RE-RUN (e.g. resume after a crash). The stub writer
    # MUST NOT clobber the LLM-enriched content — same marker-preserving
    # contract every other `_write_*_stub` helper already relies on.
    status = rp._write_external_dependency_research_stub(sp)
    assert status == "STUB", status  # helper reports success regardless of preservation

    after = ledger.read_text(encoding="utf-8")
    assert "FETCH_FAILED:network_unreachable" in after, after
    assert "IZphyrGateway" in after


# ─────────────────────────────────────────────────────────────────────────────
# 3. Gate V prereq: _mechanical_graph.json now carries "callees"
# ─────────────────────────────────────────────────────────────────────────────

class _FakeSourceMapping:
    def __init__(self, path: str, line: int):
        self.filename = types.SimpleNamespace(short=path)
        self.lines = [line]


class _FakeFunction:
    def __init__(self, name: str, contract: "_FakeContract", path: str, line: int):
        self.name = name
        self.contract = contract
        self.source_mapping = _FakeSourceMapping(path, line)
        self.state_variables_read = []
        self.state_variables_written = []
        self.internal_calls = []
        self.high_level_calls = []


class _FakeContract:
    def __init__(self, name: str):
        self.name = name
        self.is_interface = False
        self.functions_declared = []


class _FakeSlitherInstance:
    def __init__(self, contracts):
        self.contracts = contracts


def _install_fake_slither_module(monkeypatch, contracts):
    """Install a fake `slither` module in sys.modules so `from slither import
    Slither` (a lazy, function-local import in `_bake_evm_slither_graph`)
    resolves to a Slither() that returns `contracts` with zero compiler/solc
    dependency. Restored automatically by the `monkeypatch` fixture."""
    fake_module = types.ModuleType("slither")
    fake_module.__file__ = __file__

    class _FakeSlitherClass:
        def __init__(self, _target):
            self.contracts = contracts

    fake_module.Slither = _FakeSlitherClass
    monkeypatch.setitem(sys.modules, "slither", fake_module)
    rp = _rp()
    monkeypatch.setattr(
        rp,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: {
            "schema": "plamen.runtime-tool-identity.v2",
            "tool_id": "slither",
            "identity_kind": "python_distribution",
            "module_origin": __file__,
            "authority_status": "MATCH",
            "deterministic_provider_authority": True,
            "authority_digest": "a" * 64,
        },
    )
    monkeypatch.setattr(
        rp,
        "_provider_authority_replays",
        lambda *_args, **_kwargs: True,
    )


def test_mechanical_graph_json_has_nonempty_callees_for_known_call_edge(tmp_path, monkeypatch):
    rp = _rp()
    root, sp = _proj(tmp_path)
    # Need at least one real .sol file on disk (the function checks
    # `any(proj.rglob("*.sol"))` before invoking Slither).
    _sol(root, "Vault.sol",
         "contract Vault {\n"
         "  function withdraw() external { deposit(); }\n"
         "  function deposit() internal {}\n"
         "}\n")

    vault = _FakeContract("Vault")
    fn_withdraw = _FakeFunction("withdraw", vault, "Vault.sol", 2)
    fn_deposit = _FakeFunction("deposit", vault, "Vault.sol", 3)
    # `withdraw` internally calls `deposit` — a known call edge. The real
    # code does `getattr(ic, "function", ic)`, so a bare function object in
    # `internal_calls` (no `.function` wrapper) resolves to itself.
    fn_withdraw.internal_calls = [fn_deposit]
    vault.functions_declared = [fn_withdraw, fn_deposit]

    _install_fake_slither_module(monkeypatch, [vault])

    status = rp._bake_evm_slither_graph(sp, root)
    assert status == "WRITTEN", status

    graph_path = sp / "_mechanical_graph.json"
    assert graph_path.exists()
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    functions = graph["functions"]
    assert "Vault.withdraw" in functions
    fn_entry = functions["Vault.withdraw"]
    assert "callees" in fn_entry, fn_entry
    assert fn_entry["callees"] == ["deposit"], fn_entry
    # `callers` (pre-existing behavior) must still be populated on the callee.
    assert functions["Vault.deposit"]["callers"] == ["withdraw"], functions["Vault.deposit"]


def test_slither_graph_excludes_preserved_medusa_harness(tmp_path, monkeypatch):
    rp = _rp()
    root, sp = _proj(tmp_path)
    _sol(root, "Vault.sol", "contract Vault { function deposit() external {} }\n")
    _sol(
        root,
        ".medusa-tests/LegacyHarness.sol",
        "contract LegacyHarness { function primedExploit() external {} }\n",
    )

    vault = _FakeContract("Vault")
    vault.functions_declared = [_FakeFunction("deposit", vault, "Vault.sol", 1)]
    harness = _FakeContract("LegacyHarness")
    harness.functions_declared = [
        _FakeFunction(
            "primedExploit", harness, ".medusa-tests/LegacyHarness.sol", 1
        )
    ]
    _install_fake_slither_module(monkeypatch, [vault, harness])

    before = (root / ".medusa-tests" / "LegacyHarness.sol").read_bytes()
    status = rp._bake_evm_slither_graph(sp, root)
    assert status == "WRITTEN", status
    graph = json.loads(
        (sp / "_mechanical_graph.json").read_text(encoding="utf-8")
    )
    assert "Vault.deposit" in graph["functions"]
    assert not any(
        "LegacyHarness" in identity or row.get("bare") == "primedExploit"
        for identity, row in graph["functions"].items()
    )
    assert (root / ".medusa-tests" / "LegacyHarness.sol").read_bytes() == before


def test_scip_graph_writer_source_still_serializes_callees():
    """Regression guard (no SCIP toolchain dependency): the SCIP renderer
    must keep serializing `"callees"` into the functions dict it writes to
    `_mechanical_graph.json` — a static source check so this doesn't silently
    regress if the function body is edited without a SCIP-index fixture."""
    rp = _rp()
    src = Path(rp.__file__).read_text(encoding="utf-8")
    # The public wrapper now stages and atomically publishes the graph set;
    # serialization remains in the pure implementation it invokes.  Inspect
    # that implementation rather than accidentally testing wrapper layout.
    start = src.index("def _scip_to_graph_artifacts_impl(")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert '"callees": sorted(callees.get(fn, []))' in body, (
        "_scip_to_graph_artifacts_impl no longer serializes callees into "
        "_mechanical_graph.json"
    )


def test_mechanical_graph_json_docstring_documents_callees():
    rp = _rp()
    doc = rp._write_mechanical_graph_json.__doc__ or ""
    assert "callees" in doc
