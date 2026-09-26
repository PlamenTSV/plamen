"""The auxiliary model performs the web searches -- that is not a violation.

DODO run41 recon `R-EXT` did 16 WebSearches and 7 WebFetches, then authored a
complete 25-obligation research artifact: 13 rows RESEARCHED with real sources,
`PLAMEN_STATUS: COMPLETE` at EOF, `"subtype":"success"` from the CLI. The driver
discarded ALL of it and published `researched=0 unresolved=25`.

Cause: `posix_v2_compat_claude` required the auxiliary usage row to carry
`webSearchRequests == 0`. But the provider EXECUTES WebSearch on the auxiliary
model, so the measured usage was the exact inverse of the assumption:

    claude-sonnet-5      (armed)     webSearchRequests = 0
    claude-haiku-4-5     (auxiliary) webSearchRequests = 16

Every Claude-backend worker that searched at all therefore failed
MODEL_DENOMINATOR_MISMATCH and had its output thrown away. That is why
dependency parity read `researched=0` on every run from 35 onward.

The invariant the gate genuinely owns is AUTHORSHIP, and it is enforced exactly
and separately: every `assistant` event must carry the armed model. These tests
pin the fix in BOTH directions -- the real payload is admitted, and none of the
authorship or provenance guarantees were weakened to do it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import posix_v2_compat_claude as C  # noqa: E402

_RUN41 = json.loads(
    (_SCRIPTS / "_fixtures_run41_model_usage.json").read_text("utf-8")
)
_ARMED = "claude-sonnet-5"
_AUX = "claude-haiku-4-5-20251001"


def test_fixture_is_the_measured_inversion() -> None:
    """Guard the premise: if this stops holding, the fix needs rethinking."""
    assert _RUN41[_ARMED]["webSearchRequests"] == 0
    assert _RUN41[_AUX]["webSearchRequests"] == 16
    assert _RUN41[_AUX]["canonicalModel"] == "claude-haiku-4-5"


def test_auxiliary_is_a_recognised_usage_model() -> None:
    assert _AUX in C._ALLOWED_AUXILIARY_USAGE_MODELS


@pytest.mark.parametrize("source", ["validate", "replay"])
def test_neither_path_still_requires_zero_auxiliary_searches(
    source: str,
) -> None:
    """Both call sites must agree, or resume rejects what ran fine live.

    Read the source rather than the behaviour: these two predicates live in
    different functions with different failure codes, and an earlier fix that
    touched only one would have made every RESUME fail on a completion the live
    run had already admitted.
    """
    text = (_SCRIPTS / "posix_v2_compat_claude.py").read_text("utf-8")
    assert text.count('row.get("webSearchRequests") != 0') == 0, (
        "an auxiliary usage row is still required to have zero web searches; "
        "any worker that searches will be discarded"
    )
    # The surviving guard on that row is provenance, which must NOT have gone.
    assert text.count('row.get("canonicalModel") != "claude-haiku-4-5"') == 2, (
        f"{source}: auxiliary canonical-model provenance guard was lost"
    )


def test_authorship_guard_is_untouched() -> None:
    """The real invariant. Removing this would make the fix unsafe."""
    text = (_SCRIPTS / "posix_v2_compat_claude.py").read_text("utf-8")
    assert 'message.get("model") != projection["model"]' in text, (
        "assistant-event authorship binding is gone; the auxiliary allowance "
        "is only safe because authorship is enforced exactly, elsewhere"
    )
    assert "assistant model differs from armed model" in text


def test_unknown_auxiliary_model_is_still_rejected() -> None:
    """The allowance is for ONE sanctioned helper, not any model."""
    assert "claude-opus-5" not in C._ALLOWED_AUXILIARY_USAGE_MODELS
    assert len(C._ALLOWED_AUXILIARY_USAGE_MODELS) == 1


def test_provider_and_metric_guards_are_untouched() -> None:
    text = (_SCRIPTS / "posix_v2_compat_claude.py").read_text("utf-8")
    assert 'row.get("provider") != "firstParty"' in text
    assert "model usage metric is invalid" in text
    assert "model usage cost is invalid" in text
    # webSearchRequests is still RANGE-checked as a non-negative int; only the
    # exact-zero equality went away.
    assert '"cacheCreationInputTokens", "webSearchRequests",' in text


def test_primary_usage_provenance_guard_is_untouched() -> None:
    text = (_SCRIPTS / "posix_v2_compat_claude.py").read_text("utf-8")
    assert "primary usage provenance changed" in text
