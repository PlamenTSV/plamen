"""Execute the local tail fixtures against the actual routing JSON shape.

These are fixture-wire tests, not MODEL authority or full audit tests.
The production routing payload deliberately has no work_unit_key field.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from test_nonempty_report_tail_children import _tail_child_source


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX fixture child")


def _execute(tmp_path: Path, *, phase: str, damage: str = ""):
    binary = tmp_path / "fixture-codex"
    binary.write_bytes(_tail_child_source(model="fixture-model"))
    binary.chmod(0o755)
    report = "# Report\n\n### [H-01] First\n\nBody.\n\n### [L-02] Second\n\nBody.\n"
    inputs = {"project:AUDIT_REPORT.md": report}
    if phase == "report_dedup_agent":
        inputs.update({
            "scratchpad:report_index.md": "# Index\n",
            "scratchpad:finding_mapping.md": "# Mapping\n",
            "scratchpad:report_dedup_candidate_pairs.md": "# Pairs\n",
            "scratchpad:report_dedup_candidate_pairs.json": json.dumps({
                "schema_version": "plamen.report_dedup_candidate_pairs.v1",
                "status": "COMPLETE",
                "total_pairs": 1,
                "pairs": [{"report_ids": ["H-01", "L-02"],
                           "pair_key": "H-01~L-02"}],
            }),
        })
        output_identity = "scratchpad:report_dedup_agent_decisions.md"
    else:
        output_identity = "scratchpad:disposition.md"
    routes = []
    for index, (identity, content) in enumerate(inputs.items()):
        path = tmp_path / f"input-{index}"
        raw = content.encode("utf-8")
        path.write_bytes(raw)
        routes.append({
            "identity": identity, "path": str(path), "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "class": "IMMUTABLE", "binding_status": "ACTIVE",
        })
    output = tmp_path / "staged-output.md"
    routing = {
        "schema": "plamen.posix_v2_codex_local_phaseio.v1",
        "codex_working_directory": str(tmp_path),
        "project_source_root": str(tmp_path),
        "project_source_access": "READ_ONLY_BY_INSTRUCTION",
        "input_routes": routes,
        "output_routes": [{
            "identity": output_identity,
            "path": str(output), "canonical_path": str(tmp_path / "canonical.md"),
            "prestate_existed": False, "prestate_status": "ABSENT",
            "prestate_sha256": "", "prestate_size": 0, "write_mode": "REPLACE",
        }],
    }
    assert "work_unit_key" not in routing
    if damage == "input":
        Path(routes[0]["path"]).write_bytes(b"changed input\n")
    elif damage == "duplicate":
        routes.append(dict(routes[0]))
    elif damage == "output":
        routing["output_routes"][0]["identity"] = "scratchpad:unregistered.md"
    prompt = (
        "Render the bound proposal. Example only:\n```json\n[\"not routing\"]\n```\n"
        "\n# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\n\n```json\n"
        + json.dumps(routing) + "\n```\n"
    )
    result = subprocess.run(
        [str(binary), "-o", str(tmp_path / "final-message")],
        input=prompt, text=True, capture_output=True, timeout=10, check=False,
    )
    return result, output


@pytest.mark.parametrize("phase", ("report_dedup_agent", "report_disposition"))
def test_tail_child_uses_registered_output_route_without_work_unit_key(tmp_path, phase):
    result, output = _execute(tmp_path, phase=phase)
    assert result.returncode == 0, result.stderr
    rendered = output.read_text(encoding="utf-8")
    if phase == "report_dedup_agent":
        assert "| H-01, L-02 |" in rendered
    else:
        assert "| H-01 | BODY |" in rendered
        assert "| L-02 | BODY |" in rendered


@pytest.mark.parametrize("damage", ("input", "duplicate", "output"))
def test_tail_child_rejects_changed_or_unregistered_routes(tmp_path, damage):
    result, output = _execute(tmp_path, phase="report_disposition", damage=damage)
    assert result.returncode != 0
    assert not output.exists()
