"""The WebSearch response contract, pinned to responses a real run produced.

`_web_response_sources` modelled a WebSearch response as
`[block] * searchCount + [summary]` and indexed it positionally
(`results[searchCount]`, `results[:searchCount]`). That is only true when
`searchCount == 1`.

The real shape INTERLEAVES one `{tool_use_id, content}` block per provider
search with the assistant's text between them, the final string being the
summary. DODO run38 -- the first run in which any WebSearch was ever admitted,
after the permission-mode fix -- returned:

    searchCount=3 -> 6 results   [dict, str, dict, str, dict, str]   REJECTED
    searchCount=3 -> 5 results   [dict, str, dict, dict, str]        REJECTED
    searchCount=1 -> 2 results   [dict, str]                         accepted

Five of seven searches died as "WebSearch response is malformed", every
dependent WebFetch was then denied `WEB_PRIOR_DENIAL`, and dependency parity
reported `researched=0 unresolved=25` -- the same symptom that had been charged
to the worker for months.

Note the 5-result case: interleaving is not strictly regular (a search can
return no interstitial text), so a "results == 2*count" rule would be just as
wrong as the original. The contract asserts what actually matters instead:
exactly `count` result blocks, and at least one non-empty summary string.

The fixture is the verbatim capture from run38's R-EXT worker, not a
hand-written shape. Hand-written fixtures are exactly how the original contract
came to be wrong.
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

_FIXTURE = _SCRIPTS / "_fixtures_run38_websearch.json"


def _responses() -> list[dict]:
    return json.loads(_FIXTURE.read_text("utf-8"))


def _policy() -> dict:
    authority = P.build_dependency_research_network_authority({
        "schema": "plamen.external-dependency-obligations.v1",
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": [{
            "obligation_id": _stable_id(
                "source-import", "@openzeppelin/contracts", "contracts/A.sol:L1"
            ),
            "dependency": "@openzeppelin/contracts",
            "kind": "source-import",
            "research_question": "Determine the externally defined semantics.",
            "source_location": "contracts/A.sol:L1",
            "declaration_evidence": 'import "@openzeppelin/contracts/x.sol";',
        }],
        "observed_count": 1,
        "retained_count": 1,
        "overflow_ids": [],
        "truncated": False,
    })
    return {
        "network_authority": authority,
        "external_network_policy": "BOUNDED_RECEIPTS",
    }


def _event(response: dict) -> dict:
    return {
        "tool_name": "WebSearch",
        "tool_input": {"query": response["query"]},
        "tool_response": response,
    }


def test_fixture_still_exercises_the_multi_search_shape() -> None:
    """Guard the fixture itself: a count==1-only corpus proves nothing."""
    counts = {int(r["searchCount"]) for r in _responses()}
    assert counts - {1}, (
        "fixture lost its multi-search responses; the regression it guards "
        "only appears when searchCount > 1"
    )
    assert any(
        len(r["results"]) != 2 * int(r["searchCount"]) for r in _responses()
    ), "fixture lost the irregular-interleaving case"


@pytest.mark.parametrize("index", range(7))
def test_every_real_response_is_accepted(index: int) -> None:
    responses = _responses()
    response = responses[index]
    urls, _redirects, digest = P._web_response_sources(
        _event(response), _policy()
    )
    assert urls, f"response {index} yielded no source URLs"
    assert digest


def test_all_seven_accepted_and_urls_harvested() -> None:
    """Before the fix this was 2/7 and dependency research was inert."""
    policy = _policy()
    total = 0
    for response in _responses():
        urls, _r, _d = P._web_response_sources(_event(response), policy)
        total += len(urls)
    assert total > 100, f"only {total} URLs harvested across 7 real searches"


# --------------------------------------------------------------------------
# Negative controls: widening the shape must not admit a malformed response.
# --------------------------------------------------------------------------

def _mutate(**over):
    response = dict(_responses()[0])
    response.update(over)
    return response


def test_block_count_must_equal_search_count() -> None:
    """The count is the security-relevant number; it must still be enforced."""
    response = _responses()[0]
    trimmed = dict(response)
    trimmed["results"] = [
        row for row in response["results"] if not isinstance(row, dict)
    ][:1] + [
        row for row in response["results"] if isinstance(row, dict)
    ][:1]
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P._web_response_sources(_event(trimmed), _policy())


def test_a_response_with_no_summary_is_refused() -> None:
    response = _responses()[0]
    blocks_only = dict(response)
    blocks_only["results"] = [
        row for row in response["results"] if isinstance(row, dict)
    ]
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P._web_response_sources(_event(blocks_only), _policy())


def test_an_unexpected_result_element_type_is_refused() -> None:
    """Partitioning by type must not silently ignore a third kind."""
    response = _responses()[0]
    poisoned = dict(response)
    poisoned["results"] = list(response["results"]) + [12345]
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P._web_response_sources(_event(poisoned), _policy())


@pytest.mark.parametrize("over", [
    {"searchCount": 0},
    {"searchCount": -1},
    {"searchCount": True},
    {"durationSeconds": -1},
    {"durationSeconds": "14.1"},
    {"results": "not-a-list"},
])
def test_malformed_envelopes_are_still_refused(over) -> None:
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P._web_response_sources(_event(_mutate(**over)), _policy())


def test_query_mismatch_is_still_refused() -> None:
    """The response must answer the query the gate authorized."""
    response = _responses()[0]
    event = _event(response)
    event["tool_input"] = {"query": "some other query entirely"}
    with pytest.raises(P.ClaudePhaseToolPolicyError):
        P._web_response_sources(event, _policy())

def test_non_finite_duration_cannot_reach_the_contract() -> None:
    """`inf` is refused upstream, by the encoder, not by this predicate.

    A real `tool_response` is parsed FROM JSON and therefore cannot carry a
    non-finite float at all; `canonical_json_bytes` raises before the
    finiteness check ever runs. Asserting `ClaudePhaseToolPolicyError` here
    would be testing a path no live event can take -- worth stating once
    rather than leaving a fixture that looks like coverage.
    """
    with pytest.raises(ValueError):
        P._web_response_sources(
            _event(_mutate(durationSeconds=float("inf"))), _policy()
        )
