"""Bounded web research must admit every REVIEWED launch mode, and only those.

This single hardcoded string disabled ALL bounded web research, silently, for
months. `_validate_web_event_context` required the hook event's
`permission_mode` to equal the authority's, and the authority hardcoded
`"default"`. From Claude CLI 2.1.273 the bounded-web lane reports `"dontAsk"`,
so every WebSearch raised before the evaluator ever ran, surfacing only as
`PLAMEN_TOOL_POLICY_DENY:ClaudePhaseToolPolicyError`.

The damage was not the denial, it was the MISATTRIBUTION. Across DODO runs 35,
36 and 37 the symptom read `dependency parity: researched=0 unresolved=25` and
was charged to the worker. Run36 disproved that: the worker issued all 7
authorized query groups verbatim with ZERO `WEB_QUERY_UNREGISTERED`, and still
researched nothing. No web receipt of any kind -- not even a denial row -- was
ever written in any run.

The restricted-FILESYSTEM lane in `claude_stream_json_evidence` already
accepted {"default", "dontAsk"}; only the web lane was missed. This is the
completion of that reviewed decision, not a new relaxation -- which is exactly
why the negative controls below matter more than the positive one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import claude_phase_tool_policy as P  # noqa: E402
from dependency_obligations import _stable_id  # noqa: E402

# An obligation_id is a DIGEST of its own row, not a label. Inventing one is
# rejected as "does not match its semantic row" -- correctly.
_KIND = "source-import"
_DEP = "@openzeppelin/contracts"
_LOCUS = "contracts/A.sol:L1"


def _authority():
    return P.build_dependency_research_network_authority({
        "schema": "plamen.external-dependency-obligations.v1",
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": [{
            "obligation_id": _stable_id(_KIND, _DEP, _LOCUS),
            "dependency": _DEP,
            "kind": _KIND,
            "research_question": "Determine the externally defined semantics.",
            "source_location": _LOCUS,
            "declaration_evidence": 'import "@openzeppelin/contracts/x.sol";',
        }],
        "observed_count": 1,
        "retained_count": 1,
        "overflow_ids": [],
        "truncated": False,
    })


def _policy(tmp_path: Path) -> Path:
    """Build via the PRODUCT builder.

    A hand-rolled policy is rejected ("policy digest mismatch") because the
    manifest is self-binding. Reaching for the real builder is also the point:
    the test then exercises the same bytes a live phase would.
    """
    (tmp_path / "r").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    manifest = P.build_policy_manifest(
        run_id="test-run",
        phase="recon",
        attempt=1,
        expected_cwd=tmp_path,
        project_root=tmp_path,
        scratchpad_root=tmp_path,
        methodology_read_roots=[],
        exact_read_files=[],
        exact_write_files=[],
        forbidden_read_files=[],
        receipt_directory=tmp_path / "r",
        network_authority=_authority(),
    )
    path = tmp_path / "p.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _event(tmp_path: Path, mode: str) -> bytes:
    query = str(_authority()["obligations"][0]["query"])
    return json.dumps({
        "session_id": "s1",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": str(tmp_path),
        "permission_mode": mode,
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {"query": query},
        "tool_use_id": "toolu_01AAAAAAAAAAAAAAAAAAAA",
    }).encode("utf-8")


@pytest.mark.parametrize("mode", ["default", "dontAsk"])
def test_every_reviewed_mode_is_admitted(tmp_path: Path, mode: str) -> None:
    """`dontAsk` is what the live CLI actually reports for this lane."""
    code, out = P.run_hook(_policy(tmp_path), _event(tmp_path, mode))
    assert code == 0, f"{mode} was refused: {out}"
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "BOUNDED_WEB"


# --------------------------------------------------------------------------
# Negative controls. Widening a security predicate is only safe if the modes
# that must stay out, stay out.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [
    "bypassPermissions", "acceptEdits", "auto", "plan", "", "DEFAULT",
    "dontask", None,
])
def test_unreviewed_modes_are_refused(tmp_path: Path, mode) -> None:
    code, out = P.run_hook(_policy(tmp_path), _event(tmp_path, mode))
    assert code == 2, f"{mode!r} was admitted to the bounded-web lane: {out}"
    assert out["error"].startswith("PLAMEN_TOOL_POLICY_DENY")


def test_reviewed_set_is_exactly_two_modes() -> None:
    """A future edit must not quietly add `bypassPermissions` here."""
    assert P.REVIEWED_WEB_PERMISSION_MODES == ("default", "dontAsk")


def test_authority_cannot_smuggle_an_unreviewed_mode() -> None:
    """A tampered policy must not widen the lane by rewriting the authority."""
    authority = dict(_authority())
    authority["permission_mode"] = "bypassPermissions"
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P.validate_dependency_research_network_authority(authority)


def test_failure_detail_is_recorded_out_of_band(tmp_path: Path) -> None:
    """The diagnostic that actually found this bug must keep working.

    Seven identical content-free denials in run37 named the cause in one line
    once the detail was persisted. Without it this cost an afternoon and was
    still misdiagnosed.
    """
    policy_path = _policy(tmp_path)
    code, out = P.run_hook(policy_path, _event(tmp_path, "bypassPermissions"))
    assert code == 2
    # The model-visible payload stays content-free.
    assert out == {"error": "PLAMEN_TOOL_POLICY_DENY:ClaudePhaseToolPolicyError"}
    log = tmp_path / "r" / "_hook_exceptions.log"
    assert log.is_file(), "no out-of-band diagnostic was written"
    row = json.loads(log.read_text("utf-8").splitlines()[-1])
    assert "permission mode is invalid" in row["detail"]
    assert row["phase"] == "recon"
    assert "ClaudePhaseToolPolicyError" in row["traceback"]
