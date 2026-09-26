"""RED integration contract for driver-owned strict V3 completion receipts.

The receipt producer and independent verifier are already strict.  The driver
must invoke that authority for every clean SC Thorough terminal path.  A POSIX
compatibility transport is not exempt: reduced execution isolation and audit
evidence closure are separate concerns.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import audit_completion_receipt as C
import e2e_acceptance_verifier as V
import test_audit_completion_receipt as P
import test_e2e_acceptance_verifier as F


DRIVER_PATH = Path(__file__).with_name("plamen_driver.py")


def _load_driver_terminal_policy(
    *, platform_name: str, posix_compat: bool,
):
    """Load only the two source-owned pure terminal policy functions.

    Full driver import intentionally activates the generated runtime-closure
    manifest.  This RED test itself changes the scripts path denominator, so
    importing the whole runtime before that manifest is regenerated would
    test packaging drift instead of the receipt hook under review.
    """

    parsed = ast.parse(DRIVER_PATH.read_text(encoding="utf-8"))
    wanted = {"_pipeline_terminal_exit_code", "_completion_receipt_required"}
    functions = [
        node for node in parsed.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in wanted
    ]
    assert {node.name for node in functions} == wanted
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations")],
                level=0,
            ),
            *functions,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace = {
        "Any": Any,
        "Mapping": Mapping,
        "EXIT_SUCCESS": 0,
        "EXIT_DEGRADED": 2,
        "os": SimpleNamespace(name="nt" if platform_name == "win32" else "posix"),
        "sys": SimpleNamespace(platform=platform_name),
        "_posix_v2_compat_process_active": lambda: posix_compat,
    }
    exec(compile(module, str(DRIVER_PATH), "exec"), namespace)
    return (
        namespace["_pipeline_terminal_exit_code"],
        namespace["_completion_receipt_required"],
    )


def _expanded_two_shard_plan() -> list[str]:
    result: list[str] = []
    for phase in C.SC_THOROUGH_PHASES:
        if phase == "report_body_writer_critical_high":
            result.extend(
                (
                    "report_body_writer_critical_high_a",
                    "report_body_writer_critical_high_b",
                )
            )
        elif phase == "report_critical_high":
            result.extend(("report_critical_high_a", "report_critical_high_b"))
        else:
            result.append(phase)
    return result


def _install_realized_plan(paths: dict[str, Path]) -> None:
    checkpoint = json.loads(paths["checkpoint"].read_text(encoding="utf-8"))
    phases = _expanded_two_shard_plan()
    old_commits = checkpoint["phase_commits"]
    commits: dict[str, dict] = {}
    for phase in phases:
        base = phase
        if phase.startswith("report_body_writer_critical_high_"):
            base = "report_body_writer_critical_high"
        elif phase in {"report_critical_high_a", "report_critical_high_b"}:
            base = "report_critical_high"
        row = dict(old_commits[base])
        row["phase_name"] = phase
        commits[phase] = row
    checkpoint["config"]["_active_phase_names"] = phases
    checkpoint["completed"] = phases
    checkpoint["phase_commits"] = commits
    F._write_json(paths["checkpoint"], checkpoint)


def _driver_config(
    paths: dict[str, Path], identity: C.ExpectedCompletionIdentity,
) -> dict:
    config = json.loads(paths["config"].read_text(encoding="utf-8"))
    config["_audit_completion_identity"] = {
        field: str(getattr(identity, field))
        for field in identity.__dataclass_fields__
    }
    return config


def _run_current_driver_terminal_hook(
    *, paths: dict[str, Path], config: dict,
    terminal_exit_code, completion_receipt_required,
    runtime_debts: Mapping[str, Any] | None = None,
) -> int:
    """Execute the exact receipt decision currently embedded in run_pipeline."""

    checkpoint = SimpleNamespace(
        degraded=[], runtime_debts=dict(runtime_debts or {}),
    )
    exit_code = terminal_exit_code(checkpoint)
    if exit_code == 0 and completion_receipt_required(config):
        C.publish_from_driver_terminal_state(
            scratchpad=paths["scratchpad"],
            config=config,
            terminal_exit_code=exit_code,
        )
    return exit_code


def _assert_strict_terminal_acceptance(paths: dict[str, Path]) -> None:
    receipt_path = paths["scratchpad"] / C.RECEIPT_NAME
    assert receipt_path.is_file(), (
        "a clean SC Thorough driver terminal path returned success without "
        "publishing strict V3 completion authority"
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema_version"] == C.DRIVER_TERMINAL_SCHEMA
    assert receipt["realized_phase_plan_sha256"] == C.phase_names_sha256(
        _expanded_two_shard_plan()
    )
    assert C.validate_terminal_closure(receipt["terminal_closure"])
    verdict = V.verify_sc_thorough_e2e(
        scratchpad=paths["scratchpad"],
        config_path=paths["config"],
        project_root=paths["project"],
        expected_identity_path=paths["identity"],
    )
    assert verdict.accepted is True, [
        (issue.code, issue.detail) for issue in verdict.issues
    ]


@pytest.mark.parametrize("platform_name", ("darwin", "linux", "win32"))
def test_every_native_clean_terminal_path_publishes_strict_v3_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    paths, identity = P._producer_fixture(tmp_path, monkeypatch)
    _install_realized_plan(paths)
    config = _driver_config(paths, identity)
    exit_policy, receipt_policy = _load_driver_terminal_policy(
        platform_name=platform_name, posix_compat=False,
    )

    assert _run_current_driver_terminal_hook(
        paths=paths,
        config=config,
        terminal_exit_code=exit_policy,
        completion_receipt_required=receipt_policy,
    ) == 0
    _assert_strict_terminal_acceptance(paths)


def test_posix_compat_clean_terminal_requires_authenticated_closure_too(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compatibility transport does not weaken terminal evidence authority."""

    paths, identity = P._producer_fixture(tmp_path, monkeypatch)
    _install_realized_plan(paths)
    config = _driver_config(paths, identity)
    exit_policy, receipt_policy = _load_driver_terminal_policy(
        platform_name="darwin", posix_compat=True,
    )

    assert _run_current_driver_terminal_hook(
        paths=paths,
        config=config,
        terminal_exit_code=exit_policy,
        completion_receipt_required=receipt_policy,
    ) == 0
    _assert_strict_terminal_acceptance(paths)


def test_posix_compat_runtime_debt_stays_degraded_and_non_accepting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, identity = P._producer_fixture(tmp_path, monkeypatch)
    _install_realized_plan(paths)
    config = _driver_config(paths, identity)
    exit_policy, receipt_policy = _load_driver_terminal_policy(
        platform_name="darwin", posix_compat=True,
    )

    assert _run_current_driver_terminal_hook(
        paths=paths,
        config=config,
        terminal_exit_code=exit_policy,
        completion_receipt_required=receipt_policy,
        runtime_debts={"POSIX_COMPAT_RUNTIME_DEBT": ["unresolved"]},
    ) == 2
    assert not (paths["scratchpad"] / C.RECEIPT_NAME).exists()

    verdict = V.verify_sc_thorough_e2e(
        scratchpad=paths["scratchpad"],
        config_path=paths["config"],
        project_root=paths["project"],
        expected_identity_path=paths["identity"],
    )
    assert verdict.accepted is False
    assert "DRIVER_TERMINAL_RECEIPT_MISSING_OR_INVALID" in {
        issue.code for issue in verdict.issues
    }
