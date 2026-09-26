from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import recon_prepass as recon
from enumeration_type_ir import validate_function_signature_fact


def test_opengrep_compat_lane_publishes_findings_but_retains_debt(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "Contract.sol"
    rules = tmp_path / "rules"
    scratch.mkdir()
    source.parent.mkdir(parents=True)
    source.write_text("contract Contract {}\n", encoding="ascii")
    (rules / "solidity" / "security").mkdir(parents=True)
    (rules / "solidity" / "rule.yaml").write_text("rules: []\n", encoding="ascii")
    (rules / "solidity" / "security" / "rule.yaml").write_text(
        "rules: []\n", encoding="ascii"
    )
    scanner = Path("/usr/bin/true").resolve(strict=True)
    seen: dict[str, object] = {}

    monkeypatch.setattr(recon.shutil, "which", lambda name: os.fspath(scanner))
    monkeypatch.setattr(
        recon,
        "_ensure_opengrep_rules",
        lambda: {"opengrep-rules": rules, "decurity-rules": rules},
    )
    monkeypatch.setattr(
        recon,
        "replay_evm_analysis_workspace_execution_closure",
        lambda receipt: receipt,
    )

    def execute(**kwargs):
        seen.update(kwargs)
        stage = Path(kwargs["stage"])
        terminal = {
            "returncode": 0,
            "status": "COMPLETED",
            "actual_tool_started": True,
            "actual_tool_completion_observed": True,
        }
        (stage / "results.sarif").write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "OpenGrep", "rules": []}},
                "results": [{
                    "ruleId": "solidity.test-rule",
                    "level": "warning",
                    "message": {"text": "review candidate"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": os.fspath(source)},
                        "region": {"startLine": 1},
                    }}],
                }],
            }],
        }), encoding="utf-8")
        return {
            "schema": "plamen.compat-static-analysis-execution.v1",
            "authority_tier": "OBSERVATIONAL_REDUCED_ISOLATION",
            "can_certify_clean": False,
            "tool_id": "opengrep",
            "workspace_receipt_sha256": "1" * 64,
            "policy_sha256": "2" * 64,
            "request_sha256": "3" * 64,
            "terminal_sha256": hashlib.sha256(json.dumps(
                terminal, ensure_ascii=True, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "terminal": terminal,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(recon, "execute_compat_static_analysis", execute)
    status = recon._run_opengrep_scan(
        scratch,
        project,
        "evm",
        workspace_authority={"receipt_sha256": "1" * 64},
        posix_compat_session_authority=object(),
    )

    assert status.startswith("FAILED:EXECUTED_OBSERVATIONAL_REDUCED_ISOLATION")
    assert (scratch / "opengrep_results.sarif").is_file()
    assert (scratch / "opengrep_findings.md").is_file()
    assert (scratch / "opengrep_observational_positive.v1.json").is_file()
    assert seen["tool_id"] == "opengrep"
    assert seen["expected_outputs"] == ("results.sarif",)
    command = list(seen["argv"])
    assert os.fspath(source.resolve()) in command
    assert any(os.fspath(rules.resolve()) in item for item in command)


def test_slither_compat_lane_builds_precise_graph_without_native_authority(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    managed = tmp_path / "managed" / "bin"
    scratch.mkdir()
    project.mkdir()
    managed.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Contract.sol").write_text(
        "contract C { function f() external {} }\n", encoding="ascii"
    )
    fake_python = managed / "python3.12"
    fake_slither = managed / "slither"
    fake_python.write_text("python", encoding="ascii")
    fake_slither.write_text("slither", encoding="ascii")
    fake_slither.chmod(0o755)
    evidence = {
        "schema": "plamen.compat-static-analysis-execution.v1",
        "authority_tier": "OBSERVATIONAL_REDUCED_ISOLATION",
        "can_certify_clean": False,
        "terminal": {"returncode": 0, "status": "COMPLETED"},
        "stdout": "",
        "stderr": "",
    }
    seen: dict[str, object] = {}

    monkeypatch.setattr(recon.sys, "executable", os.fspath(fake_python))
    selected_solc = tmp_path / "managed" / "solc"
    selected_solc.write_text("solc", encoding="ascii")
    selected_solc.chmod(0o755)
    monkeypatch.setattr(
        recon,
        "resolve_compat_foundry_solc",
        lambda **_kwargs: selected_solc,
    )

    def execute(**kwargs):
        seen.update(kwargs)
        Path(kwargs["stage"], "slither-printers.json").write_text(
            "{}", encoding="ascii"
        )
        return evidence

    monkeypatch.setattr(recon, "execute_compat_static_analysis", execute)
    monkeypatch.setattr(
        recon,
        "_slither_cli_function_rows",
        lambda _value: [{
            "contract": "C",
            "name": "f()",
            "bare": "f",
            "visibility": "external",
            "modifiers": (),
            "reads": (),
            "writes": (),
            "internal_calls": (),
            "external_calls": (),
            "cyclomatic_complexity": 1,
        }],
    )

    def source_graph(stage: Path, _project: Path) -> str:
        Path(stage, "_mechanical_graph.json").write_text(json.dumps({
            "source": "evm-source",
            "functions": {
                "src/Contract.sol::C.f@L1": {
                    "bare": "f", "loc": "src/Contract.sol:L1",
                    "signature_fact": {},
                },
            },
            "var_refs": {},
        }), encoding="utf-8")
        return "WRITTEN"

    monkeypatch.setattr(recon, "_bake_evm_source_graph", source_graph)
    workspace = {
        "build_root": {"absolute_path": os.fspath(project.resolve())},
    }
    status, returned = recon._bake_evm_slither_native_graph(
        scratch,
        project,
        workspace_authority=workspace,
        session_tool_authority=None,
        native_runtime_authority=None,
        posix_compat_session_authority=object(),
    )

    assert status == "WRITTEN"
    assert returned == evidence
    assert seen["tool_id"] == "slither"
    assert seen["expected_outputs"] == ("slither-printers.json",)
    assert seen["auxiliary_executables"] == {"solc": selected_solc}
    assert seen["environment"]["FOUNDRY_SOLC"] == os.fspath(selected_solc)
    assert "--no-fail" in seen["argv"]
    graph = json.loads((scratch / "_mechanical_graph.json").read_text())
    row = graph["functions"]["src/Contract.sol::C.f@L1"]
    assert row["slither_cli_bound"] is True
    fact = row["signature_fact"]
    assert fact["provider"] == "slither-cli"
    assert fact["authority"] == "COMPILER_PROVIDER"
    assert fact["canonical_signature"] == "f()"
    assert fact["source_binding"]["status"] == "EXACT"
    assert validate_function_signature_fact(fact) == []
    assert "cyclomatic_complexity" not in fact
    assert row["cyclomatic_complexity"] == 1
    assert recon._graph_artifact_evidence(scratch)


def test_slither_fail_soft_diagnostic_is_typed_partial_debt() -> None:
    assert recon._slither_compat_analysis_limitation(
        "ERROR:SlitherSolcParsing: Failed to generate IR for C.f"
    ) == "SLITHER_FAIL_SOFT_IR_OR_PARSE_DEBT"
    assert recon._slither_compat_analysis_limitation("ordinary warning") is None


def test_evm_graph_publishes_partial_slither_rows_instead_of_discarding(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    observed: list[str] = []

    monkeypatch.setattr(recon, "_maybe_warn_via_ir_build", lambda _project: None)
    monkeypatch.setattr(
        recon,
        "_bake_evm_slither_native_graph",
        lambda *_args, **_kwargs: (
            "WRITTEN:PARTIAL:SLITHER_FAIL_SOFT_IR_OR_PARSE_DEBT",
            {"schema": "fixture-observational-evidence"},
        ),
    )
    monkeypatch.setattr(
        recon,
        "_bind_workspace_graph_reference",
        lambda *_args, **_kwargs: observed.append("bound"),
    )
    monkeypatch.setattr(
        recon,
        "_validate_and_publish_graph_artifact_set",
        lambda *_args, **_kwargs: ("WRITTEN", {}),
    )
    monkeypatch.setattr(
        recon,
        "_record_precise_graph_outcome",
        lambda *_args, **_kwargs: observed.append("recorded"),
    )

    result = recon._bake_evm_graph(
        scratch,
        project,
        workspace_authority={"tools": []},
        posix_compat_session_authority=object(),
    )

    assert result == (
        "WRITTEN:slither "
        "(WRITTEN:PARTIAL:SLITHER_FAIL_SOFT_IR_OR_PARSE_DEBT)"
    )
    assert observed == ["bound", "recorded"]
