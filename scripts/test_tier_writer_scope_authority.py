"""The tier-writer template may only name inputs the driver registers.

`report_index.md` is deliberately NOT a body-writer input: it lists every
finding across all shards, so the contract gives each writer its own rendered
manifest instead.  The template nevertheless instructed the worker to read it
as a fallback, which the pre-launch consistency checker denies -- and the
driver fails closed when a manifest is absent, so the fallback could never be
executed anyway.  A denied launch means the tier body is never written.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import claude_worker_prompt_consistency as C  # noqa: E402

_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "prompts" / "shared" / "v2" / "phase6b-tier-writers.md"
)
PROJECT = "/audit/p"
SCRATCHPAD = PROJECT + "/.scratchpad"
INPUTS = (
    "scratchpad:body_manifests/report_medium.json",
    "scratchpad:report_evidence_manifests/report_medium.json",
    "scratchpad:verify_H-1.md",
    "scratchpad:verify_core.md",
    "scratchpad:findings_inventory.md",
)
OUTPUTS = ("scratchpad:report_medium.md",)


def _issues(text: str):
    return C.validate_claude_worker_prompt_consistency(
        text,
        phase_io_inputs=INPUTS,
        phase_io_outputs=OUTPUTS,
        policy_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        safe_search_roots=(),
        project_root=PROJECT,
        scratchpad_root=SCRATCHPAD,
    )


def _scope_line() -> str:
    for line in _TEMPLATE.read_text(encoding="utf-8").splitlines():
        if line.startswith("SCOPE: Write ONLY the exact driver-assigned tier"):
            return line
    raise AssertionError("tier-writer SCOPE line not found")


def test_scope_line_names_no_unregistered_artifact() -> None:
    issues = _issues(_scope_line())
    assert issues == (), [
        (issue.code, issue.subject) for issue in issues
    ]


def test_scope_block_has_no_forbidden_report_index_fallback() -> None:
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "fall back to `report_index.md`" not in text
    assert "or report_index.md if no manifest" not in text


def test_the_removed_fallback_really_was_a_denial() -> None:
    """Negative control: the old line denies the launch."""
    old = (
        "SCOPE: Write ONLY the exact driver-assigned tier output file named in "
        "the phase override. If NO manifest was provided, fall back to "
        "`report_index.md` for your tier assignments."
    )
    codes = {issue.code for issue in _issues(old)}
    assert codes, "the removed fallback must have been a denial"
    assert codes <= {"UNREGISTERED_ARTIFACT_READ", "UNREGISTERED_OUTPUT_WRITE"}


def test_registered_manifest_reads_are_accepted() -> None:
    line = (
        "Read `body_manifests/report_medium.json` and "
        "`report_evidence_manifests/report_medium.json` before writing.\n"
    )
    assert _issues(line) == ()
