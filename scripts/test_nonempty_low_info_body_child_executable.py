"""Focused executable-boundary tests for the deterministic low/info child.

These tests exercise only the fixture executable against the exact routing
document shape emitted by ``posix_v2_compat_runtime``.  They prove closed
attempt selection and route-byte validation, not MODEL or PhaseIO authority;
the genuine same-run integration owns those claims.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from test_nonempty_low_info_body_child import (
    _ATTEMPT_PROMPTS,
    _body_child_source,
)


pytestmark = [
    pytest.mark.posix_only,
    pytest.mark.skipif(
        os.name != "posix", reason="fixture executable requires POSIX",
    ),
]


def _routing(
    *, input_path: Path, output_path: Path,
    output_identity: str = "scratchpad:report_low_info.md",
) -> dict[str, object]:
    raw = input_path.read_bytes()
    return {
        "schema": "plamen.posix_v2_codex_local_phaseio.v1",
        "project_source_root": str(input_path.parent),
        "project_source_access": "READ_ONLY_BY_INSTRUCTION",
        "codex_working_directory": str(input_path.parent),
        "input_routes": [{
            "identity": "scratchpad:report_evidence_records.json",
            "path": str(input_path),
            "class": "IMMUTABLE",
            "binding_status": "ACTIVE",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }],
        "output_routes": [{
            "identity": output_identity,
            "path": str(output_path),
            "canonical_path": str(output_path.parent / "canonical.md"),
            "write_mode": "CREATE",
            "prestate_status": "ABSENT",
            "prestate_existed": False,
            "prestate_sha256": "",
            "prestate_size": 0,
        }],
    }


def _provider_prompt(request: str, routing: dict[str, object]) -> str:
    return (
        request.rstrip()
        + "\n\n# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\n\n"
        + "```json\n"
        + json.dumps(routing, sort_keys=True, separators=(",", ":"))
        + "\n```\n"
    )


def _binary(tmp_path: Path) -> tuple[Path, tuple[bytes, int, int]]:
    binary = tmp_path / "fixture-codex-low-info"
    binary.write_bytes(_body_child_source(
        model="fixture-model",
        body="attempt-one\n",
        retry_body="attempt-two\n",
    ))
    binary.chmod(0o755)
    observed = os.lstat(binary)
    assert stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
    return binary, (binary.read_bytes(), observed.st_ino, observed.st_mtime_ns)


def _execute(binary: Path, prompt: str, transcript: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary), "exec", "-o", str(transcript)],
        input=prompt,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )


def test_one_immutable_executable_selects_both_exact_prompt_attempts(
    tmp_path: Path,
) -> None:
    binary, binary_state = _binary(tmp_path)
    bound = tmp_path / "bound.json"
    bound.write_bytes(b'{"bound":true}\n')

    for attempt, expected in ((1, "attempt-one\n"), (2, "attempt-two\n")):
        staged = tmp_path / f"attempt-{attempt}" / "report_low_info.md"
        staged.parent.mkdir()
        transcript = tmp_path / f"attempt-{attempt}.last-message"
        routing = _routing(input_path=bound, output_path=staged)
        assert "work_unit_key" not in routing
        result = _execute(
            binary,
            _provider_prompt(_ATTEMPT_PROMPTS[attempt], routing),
            transcript,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert staged.read_text(encoding="utf-8") == expected
        assert transcript.read_text(encoding="utf-8") == "complete\n"
        observed = os.lstat(binary)
        assert (
            binary.read_bytes(), observed.st_ino, observed.st_mtime_ns,
        ) == binary_state


@pytest.mark.parametrize(
    "prompt_request",
    (
        "Render the already-bound deterministic low/info evidence fixture.\n",
        "Render the already-bound deterministic low/info evidence fixture attempt 3.\n",
        "Render the already-bound deterministic low/info evidence fixture attempt 1. extra\n",
    ),
)
def test_missing_or_invalid_attempt_is_rejected(
    tmp_path: Path, prompt_request: str,
) -> None:
    binary, _state = _binary(tmp_path)
    bound = tmp_path / "bound.json"
    bound.write_bytes(b'{"bound":true}\n')
    staged = tmp_path / "stage" / "report_low_info.md"
    staged.parent.mkdir()
    result = _execute(
        binary,
        _provider_prompt(prompt_request, _routing(input_path=bound, output_path=staged)),
        tmp_path / "last-message",
    )
    assert result.returncode != 0
    assert not staged.exists()


def test_changed_bound_input_is_rejected_before_output(
    tmp_path: Path,
) -> None:
    binary, _state = _binary(tmp_path)
    bound = tmp_path / "bound.json"
    bound.write_bytes(b'{"bound":true}\n')
    staged = tmp_path / "stage" / "report_low_info.md"
    staged.parent.mkdir()
    routing = _routing(input_path=bound, output_path=staged)
    bound.write_bytes(b'{"bound":null}\n')
    result = _execute(
        binary,
        _provider_prompt(_ATTEMPT_PROMPTS[1], routing),
        tmp_path / "last-message",
    )
    assert result.returncode != 0
    assert "digest differs" in result.stderr
    assert not staged.exists()


def test_wrong_output_identity_is_rejected(
    tmp_path: Path,
) -> None:
    binary, _state = _binary(tmp_path)
    bound = tmp_path / "bound.json"
    bound.write_bytes(b'{"bound":true}\n')
    staged = tmp_path / "stage" / "report_low_info.md"
    staged.parent.mkdir()
    routing = _routing(
        input_path=bound,
        output_path=staged,
        output_identity="scratchpad:report_medium.md",
    )
    result = _execute(
        binary,
        _provider_prompt(_ATTEMPT_PROMPTS[1], routing),
        tmp_path / "last-message",
    )
    assert result.returncode != 0
    assert "output identity differs" in result.stderr
    assert not staged.exists()
