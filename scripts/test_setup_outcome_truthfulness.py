"""The interactive setup command reports selected-action outcomes truthfully."""

from __future__ import annotations

import inspect
import io
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from test_cli_release_readiness import _load_front


class _TTY(io.StringIO):
    def isatty(self):
        return True


def _setup_fixture(monkeypatch, *, selected, recipes=None):
    front = _load_front()
    output = _TTY()
    monkeypatch.setattr(front.sys, "stdin", _TTY())
    monkeypatch.setattr(front.sys, "stdout", output)
    monkeypatch.setattr(front, "run_install", lambda: 0)
    monkeypatch.setattr(front, "_toolchain_runtime_required_missing", lambda _root: [])
    monkeypatch.setattr(front, "check_dependencies", lambda: True)
    monkeypatch.setattr(front, "_locked_toolchain_identity_report", lambda: [])
    monkeypatch.setattr(front, "_rag_needs_build", lambda: False)
    monkeypatch.setattr(front, "_probe_rag_db", lambda: 500)
    monkeypatch.setattr(front, "_find_codex_bin", lambda: None)
    monkeypatch.setattr(front, "_dependency_backend_paths", lambda: {})
    monkeypatch.setattr(front, "_drain_stdin", lambda: None)
    monkeypatch.setattr(front.console, "print", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(front, "_INSTALL_RECIPES", recipes or {})
    monkeypatch.setattr(
        front.inquirer,
        "checkbox",
        lambda **_kwargs: SimpleNamespace(execute=lambda: list(selected)),
    )
    return front, output


def _recipe(*, commands=None, requires=None, provides=None):
    return (
        "fixture tool",
        lambda: False,
        lambda: list(commands or []),
        list(provides or ["fixture-bin"]),
        "instant",
        [],
        requires,
    )


@pytest.mark.parametrize("selected", ([], ["__skip__"]))
def test_setup_skip_is_success_without_selected_effects(monkeypatch, selected):
    front, _output = _setup_fixture(monkeypatch, selected=selected)
    called = []
    monkeypatch.setattr(front, "_run_install_cmd", lambda *_a, **_k: called.append(True))

    assert front.run_setup() == 0
    assert called == []


def test_invalid_toolchain_controls_fail_before_prompt(monkeypatch):
    front, output = _setup_fixture(monkeypatch, selected=[])
    prompted = []
    monkeypatch.setattr(
        front,
        "_locked_toolchain_identity_report",
        lambda: (_ for _ in ()).throw(RuntimeError("fixture control mismatch")),
    )
    monkeypatch.setattr(
        front.inquirer,
        "checkbox",
        lambda **_kwargs: prompted.append(True),
    )

    assert front.run_setup() == 1
    assert prompted == []
    assert "Toolchain controls are invalid" in output.getvalue()
    assert "All tools installed" not in output.getvalue()


@pytest.mark.parametrize("install_result, expected", ((None, 1), (7, 7)))
def test_base_install_status_is_never_coerced_to_success(
    monkeypatch, install_result, expected
):
    front, _output = _setup_fixture(monkeypatch, selected=[])
    monkeypatch.setattr(front, "run_install", lambda: install_result)

    assert front.run_setup() == expected


@pytest.mark.parametrize("failure", ("manual", "rejected", "prerequisite", "command"))
def test_selected_recipe_failure_returns_nonzero(monkeypatch, failure):
    commands = [] if failure == "manual" else ["fixture install --version 1.0.0"]
    requires = "fixture-prerequisite" if failure == "prerequisite" else None
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Fixture"],
        recipes={"Fixture": [_recipe(commands=commands, requires=requires)]},
    )
    monkeypatch.setattr(
        front,
        "_toolchain_acquisition_rejection",
        lambda _command: "fixture rejected" if failure == "rejected" else None,
    )
    monkeypatch.setattr(
        front,
        "_ensure_prereq",
        lambda *_args: failure != "prerequisite",
    )
    commands_run = []
    monkeypatch.setattr(
        front,
        "_run_install_cmd",
        lambda command, **_kwargs: commands_run.append(command) or failure != "command",
    )
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (True, "ok"))

    assert front.run_setup() == 1
    assert "Setup incomplete" in output.getvalue()
    assert "fixture tool" in output.getvalue()
    if failure in {"manual", "rejected", "prerequisite"}:
        assert commands_run == []
    else:
        assert commands_run == commands


def test_failed_post_install_probe_returns_nonzero(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Fixture"],
        recipes={"Fixture": [_recipe(commands=["fixture install --version 1.0.0"])]},
    )
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_run_install_cmd", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (False, "broken"))

    assert front.run_setup() == 1
    assert "install postcondition failed" in output.getvalue()
    assert "Setup incomplete" in output.getvalue()


def test_locked_identity_postcondition_mismatch_returns_nonzero(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Fixture"],
        recipes={
            "Fixture": [
                _recipe(
                    commands=["fixture install --version 1.0.0"],
                    provides=["scip-go"],
                )
            ]
        },
    )
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_run_install_cmd", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(front, "_locked_identity_is_current", lambda _identity: False)

    assert front.run_setup() == 1
    assert "postcondition does not match" in output.getvalue()
    assert "Setup incomplete" in output.getvalue()


def test_adapter_and_incomplete_rag_failures_are_aggregated(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["__codex__", "__rag__"],
    )
    monkeypatch.setattr(front, "_find_codex_bin", lambda: "/fixture/codex")
    monkeypatch.setattr(
        front, "_dependency_backend_paths", lambda: {"codex": "/fixture/codex"}
    )
    monkeypatch.setattr(front, "_install_codex_adapter", lambda *_a, **_k: False)
    monkeypatch.setattr(front, "_build_rag_db", lambda _write: True)
    rag_checks = iter((True, True))
    monkeypatch.setattr(front, "_rag_needs_build", lambda: next(rag_checks))

    assert front.run_setup() == 1
    assert "Codex adapter, RAG DB" in output.getvalue()


def test_false_rag_builder_result_returns_nonzero(monkeypatch):
    front, output = _setup_fixture(monkeypatch, selected=["__rag__"])
    monkeypatch.setattr(front, "_build_rag_db", lambda _write: False)

    assert front.run_setup() == 1
    assert "RAG DB" in output.getvalue()


def test_setup_continues_after_failure_and_aggregates_outcomes(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["First", "Second"],
        recipes={
            "First": [_recipe(commands=["first --version 1.0.0"])],
            "Second": [_recipe(commands=["second --version 1.0.0"])],
        },
    )
    commands_run = []
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_SETUP_PINNED_TOOL_VERSIONS", {})
    monkeypatch.setattr(
        front,
        "_run_install_cmd",
        lambda command, **_kwargs: commands_run.append(command) or command.startswith("second"),
    )
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (True, "ok"))

    assert front.run_setup() == 1
    assert commands_run == ["first --version 1.0.0", "second --version 1.0.0"]
    assert "Setup incomplete" in output.getvalue()
    assert "fixture tool" in output.getvalue()


def test_duplicate_recipe_selected_through_two_groups_runs_once(monkeypatch):
    duplicate = _recipe(
        commands=["cargo install cargo-fuzz --version 0.13.2 --locked"],
        provides=["cargo-fuzz"],
    )
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Soroban", "L1 (Rust)"],
        recipes={"Soroban": [duplicate], "L1 (Rust)": [duplicate]},
    )
    commands_run = []
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_SETUP_PINNED_TOOL_VERSIONS", {})
    monkeypatch.setattr(front, "_cargo_fuzz_nightly_is_current", lambda: True)
    monkeypatch.setattr(
        front,
        "_run_install_cmd",
        lambda command, **_kwargs: commands_run.append(command) or True,
    )
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (True, "ok"))

    assert front.run_setup() == 0
    assert commands_run == [
        "cargo install cargo-fuzz --version 0.13.2 --locked"
    ]
    assert "already evaluated through another selected toolchain group" in output.getvalue()


def test_successful_selected_recipe_returns_zero(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Fixture"],
        recipes={"Fixture": [_recipe(commands=["fixture install --version 1.0.0"])]},
    )
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_run_install_cmd", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (True, "ok"))

    assert front.run_setup() == 0
    assert "done" in output.getvalue()
    assert "Setup incomplete" not in output.getvalue()


def test_failed_final_required_dependency_recheck_returns_nonzero(monkeypatch):
    front, output = _setup_fixture(
        monkeypatch,
        selected=["Fixture"],
        recipes={"Fixture": [_recipe(commands=["fixture install --version 1.0.0"])]},
    )
    dependency_checks = iter((True, False))
    monkeypatch.setattr(front, "check_dependencies", lambda: next(dependency_checks))
    monkeypatch.setattr(front, "_toolchain_acquisition_rejection", lambda _command: None)
    monkeypatch.setattr(front, "_run_install_cmd", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(front, "_probe_tool_runtime", lambda *_args: (True, "ok"))

    assert front.run_setup() == 1
    assert "required dependencies" in output.getvalue()


def test_explicit_setup_dispatch_does_not_coerce_missing_status_to_success():
    source = inspect.getsource(_load_front().main)
    assert "SystemExit(run_setup())" in source
    assert "SystemExit(run_setup() or 0)" not in source


def _rag_builder_fixture(monkeypatch, *, outcomes, count):
    front = _load_front()
    writes = []
    commands = []
    remaining = iter(outcomes)
    monkeypatch.setitem(sys.modules, "chromadb", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace())
    monkeypatch.setattr(
        front.os.path,
        "isdir",
        lambda value: str(value).endswith(
            front.os.path.join("custom-mcp", "unified-vuln-db")
        ),
    )
    monkeypatch.setattr(
        front,
        "_managed_runtime_python",
        lambda: SimpleNamespace(resolve=lambda strict: Path("/fixture/python")),
    )
    monkeypatch.setattr(front, "_is_fanless_mac", lambda: False)
    monkeypatch.setattr(front, "_probe_rag_db", lambda: count)

    def run(command, **_kwargs):
        commands.append(command)
        return next(remaining)

    monkeypatch.setattr(front, "_run_install_cmd", run)
    return front, writes, commands


def test_rag_builder_reports_failure_when_one_requested_source_fails(
    monkeypatch,
):
    front, writes, commands = _rag_builder_fixture(
        monkeypatch,
        outcomes=(False, True, True, True),
        count=750,
    )

    assert 750 >= front._RAG_MIN_ENTRIES
    assert front._build_rag_db(writes.append) is False
    assert len(commands) == 4
    assert "failed — continuing with partial data" in "".join(writes)
    assert "RAG database incomplete" in "".join(writes)


def test_rag_builder_rejects_low_count_after_all_steps_succeed(monkeypatch):
    front, writes, commands = _rag_builder_fixture(
        monkeypatch,
        outcomes=(True, True, True, True),
        count=499,
    )

    assert front._RAG_MIN_ENTRIES == 500
    assert front._build_rag_db(writes.append) is False
    assert len(commands) == 4
    assert "RAG database incomplete" in "".join(writes)


def test_rag_builder_accepts_complete_count_when_all_steps_succeed(monkeypatch):
    front, writes, commands = _rag_builder_fixture(
        monkeypatch,
        outcomes=(True, True, True, True),
        count=500,
    )

    assert front._build_rag_db(writes.append) is True
    assert len(commands) == 4
    assert "RAG database: 500 entries indexed" in "".join(writes)
    assert "RAG database incomplete" not in "".join(writes)


def test_rag_builder_accepts_a_successful_bounded_retry(monkeypatch):
    front, writes, commands = _rag_builder_fixture(
        monkeypatch,
        outcomes=(True, False, True, True, True),
        count=500,
    )

    assert front._build_rag_db(writes.append) is True
    assert len(commands) == 5
    assert "retry 1/1" in "".join(writes)
    assert "failed — continuing with partial data" not in "".join(writes)
