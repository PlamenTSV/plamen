from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

import codex_dependency_research as C
import plamen_driver as D
import rooted_path_io as rooted_io
from phase_io_contracts import resolve_phase_io_contract


URL = "https://docs.vendor.com/protocol"


def _obligation_row(
    *,
    dependency: str = "vendor/package",
    kind: str = "solidity-import",
    source_location: str = "src/A.sol:L1",
    research_question: str = "What behavior is relied on?",
) -> dict[str, str]:
    obligation_id = "DEP-" + hashlib.sha256(
        (
            kind + "\0" + dependency.casefold() + "\0"
            + source_location.casefold()
        ).encode("utf-8")
    ).hexdigest()[:12].upper()
    return {
        "obligation_id": obligation_id,
        "dependency": dependency,
        "kind": kind,
        "source_location": source_location,
        "declaration_evidence": f"declares {dependency}",
        "research_question": research_question,
    }


SINGLE_ROW = _obligation_row()
SINGLE_ID = SINGLE_ROW["obligation_id"]


def _envelope(rows: list[dict[str, str]] | None = None) -> dict[str, object]:
    admitted = sorted(rows or [SINGLE_ROW], key=lambda row: row["obligation_id"])
    return {
        "schema": "plamen.external-dependency-obligations.v1",
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": admitted,
        "observed_count": len(admitted),
        "retained_count": len(admitted),
        "truncated": False,
        "overflow_ids": [],
    }


SINGLE_QUERY = C.compile_model_visible_projection(_envelope())["query_groups"][0][
    "query"
]


def _report(url: str = URL, *, obligation_id: str = SINGLE_ID) -> bytes:
    return (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | "
        "Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| {obligation_id} | vendor/package | src/A.sol:L1 | atomic | documented | {url} | "
        "CONFORMS | RESEARCHED |\n"
    ).encode()


def _unresolved_report(status: str) -> bytes:
    return (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | "
        "Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| {SINGLE_ID} | vendor/package | src/A.sol:L1 | atomic | inconclusive |  | "
        f"UNKNOWN | {status} |\n"
    ).encode()


def _provider_evidence(
    root: Path,
    *,
    event_url: str = URL,
    event_items: list[dict[str, object]] | None = None,
    event_records: list[dict[str, object]] | None = None,
    obligations: dict[str, object] | None = None,
) -> dict[str, str]:
    attempt_dir = root / ".worker_transactions" / "recon" / "dependency_research" / "attempts" / ("attempt-" + "a" * 24)
    provider_dir = root / ".worker_execution_receipts" / "wt-test"
    attempt_dir.mkdir(parents=True)
    (provider_dir / "blobs").mkdir(parents=True)
    envelope = obligations or _envelope()
    query = C.compile_model_visible_projection(envelope)["query_groups"][0][
        "query"
    ]
    items = event_items if event_items is not None else [
        {
            "type": "web_search",
            "query": query,
            "action": {"type": "search", "query": query},
        },
        {
            "type": "web_search",
            "query": event_url,
            "action": {"type": "open_page", "url": event_url},
        },
    ]
    if event_records is not None and event_items is not None:
        raise ValueError("test fixture must select items or full event records")
    records = event_records
    if records is None:
        records = []
        for index, raw_item in enumerate(items, 1):
            item = dict(raw_item)
            item.setdefault(
                "id", f"exec-00000000-0000-4000-8000-{index:012d}"
            )
            records.append({"type": "item.completed", "item": item})
    stdout = "".join(json.dumps(event) + "\n" for event in records).encode()
    stdout_sha = hashlib.sha256(stdout).hexdigest()
    (provider_dir / "blobs" / "stdout.bin").write_bytes(stdout)
    provider = {
        "stdout_blob": {
            "relative_path": "blobs/stdout.bin",
            "sha256": stdout_sha,
            "size": len(stdout),
        },
        "stream_observation": {"stdout_overflow": False},
    }
    (provider_dir / "completion.json").write_text(json.dumps(provider), encoding="utf-8")
    attempt = {
        "provider_completion_relative_path": (
            ".worker_execution_receipts/wt-test/completion.json"
        )
    }
    completion = attempt_dir / "completion.json"
    completion.write_text(json.dumps(attempt), encoding="utf-8")
    obligations = root / "external_dependency_obligations.json"
    obligations.write_text(
        json.dumps(envelope),
        encoding="utf-8",
    )
    return {
        "schema": C.CONTEXT_SCHEMA,
        "scratchpad_root": str(root),
        "attempt_completion": str(completion),
        "obligations_path": str(obligations),
        "research_output": "recon_external_dependency_research.md",
    }


def test_staged_gate_joins_researched_url_to_typed_codex_event(tmp_path: Path):
    context = _provider_evidence(tmp_path)
    assert C.staged_codex_dependency_research_validator(
        {"scratchpad:recon_external_dependency_research.md": _report()},
        context,
    ) == []


def test_staged_gate_rejects_unreceipted_source(tmp_path: Path):
    context = _provider_evidence(
        tmp_path, event_url="https://docs.example.com/different"
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    )
    assert issues and "literal open evidence differs" in issues[0]


def test_staged_gate_rejects_search_query_that_only_names_claimed_url(
    tmp_path: Path,
) -> None:
    context = _provider_evidence(
        tmp_path,
        event_items=[
            {
                "type": "web_search",
                "query": SINGLE_QUERY,
                "action": {"type": "search", "query": SINGLE_QUERY},
            },
        ],
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    )
    assert issues and "literal open evidence differs" in issues[0]


def test_staged_gate_rejects_current_codex_opaque_ref_open_shape(
    tmp_path: Path,
) -> None:
    context = _provider_evidence(
        tmp_path,
        event_items=[
            {
                "type": "web_search",
                "query": SINGLE_QUERY,
                "action": {
                    "type": "search",
                    "query": SINGLE_QUERY,
                },
            },
            {
                "type": "web_search",
                "query": "",
                "action": {"type": "other"},
            },
        ],
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    )
    assert issues and "exact literal-open lifecycle" in issues[0]


def test_staged_gate_rejects_batched_queries_field(tmp_path: Path) -> None:
    context = _provider_evidence(
        tmp_path,
        event_items=[
            {
                "type": "web_search",
                "action": {
                    "type": "search",
                    "query": SINGLE_QUERY,
                    "queries": [SINGLE_QUERY, "injected query"],
                },
            },
            {
                "type": "web_search",
                "action": {"type": "open_page", "url": URL},
            },
        ],
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    )
    assert issues and "action shape is unsupported" in issues[0]


def test_staged_gate_rejects_incomplete_failed_and_duplicate_web_items(
    tmp_path: Path,
) -> None:
    search = {
        "type": "web_search",
        "id": "exec-00000000-0000-4000-8000-000000000001",
        "action": {"type": "search", "query": SINGLE_QUERY},
    }
    open_item = {
        "type": "web_search",
        "id": "exec-00000000-0000-4000-8000-000000000002",
        "action": {"type": "open_page", "url": URL},
    }
    cases = {
        "started_only": [{"type": "item.started", "item": search}],
        "failed_status": [{
            "type": "item.completed",
            "item": {**search, "status": "failed"},
        }],
        "failed_event_status": [{
            "type": "item.completed",
            "status": "failed",
            "item": search,
        }],
        "duplicate_ids": [
            {"type": "item.completed", "item": search},
            {
                "type": "item.completed",
                "item": {**open_item, "id": search["id"]},
            },
        ],
    }
    for name, records in cases.items():
        context = _provider_evidence(
            tmp_path / name,
            event_records=records,
        )
        issues = C.staged_codex_dependency_research_validator(
            {"recon_external_dependency_research.md": _report()}, context
        )
        assert issues, name


def test_staged_gate_accepts_matched_started_then_completed_web_items(
    tmp_path: Path,
) -> None:
    search_started = {
        "type": "web_search",
        "id": "item_1",
        "status": "in_progress",
    }
    search_completed = {
        "type": "web_search",
        "item_id": "item_1",
        "id": "exec-00000000-0000-4000-8000-000000000001",
        "status": "completed",
        "action": {"type": "search", "query": SINGLE_QUERY},
    }
    open_item = {
        "type": "web_search",
        "id": "exec-00000000-0000-4000-8000-000000000002",
        "status": "completed",
        "action": {"type": "open_page", "url": URL},
    }
    context = _provider_evidence(
        tmp_path,
        event_records=[
            {"type": "item.started", "item": search_started},
            {"type": "item.completed", "item": search_completed},
            {"type": "item.completed", "item": open_item},
        ],
    )
    assert C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    ) == []


def test_run18_other_action_literal_open_replays_exact_completed_lifecycle(
    tmp_path: Path,
) -> None:
    search_exec = "exec-00000000-0000-4000-8000-000000000011"
    open_exec = "exec-00000000-0000-4000-8000-000000000012"
    context = _provider_evidence(
        tmp_path,
        event_records=[
            {
                "type": "item.started",
                "item": {
                    "item_id": "item_11",
                    "type": "web_search",
                    "id": search_exec,
                    "query": "",
                    "action": {"type": "other"},
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "item_id": "item_11",
                    "type": "web_search",
                    "id": search_exec,
                    "query": SINGLE_QUERY,
                    "action": {"type": "search", "query": SINGLE_QUERY},
                },
            },
            {
                "type": "item.started",
                "item": {
                    "item_id": "item_12",
                    "type": "web_search",
                    "id": open_exec,
                    "query": "",
                    "action": {"type": "other"},
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "item_id": "item_12",
                    "type": "web_search",
                    "id": open_exec,
                    "query": URL,
                    "action": {"type": "other"},
                },
            },
        ],
    )
    assert C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    ) == []


def test_other_action_open_requires_exact_paired_literal_shape(
    tmp_path: Path,
) -> None:
    open_exec = "exec-00000000-0000-4000-8000-000000000022"
    exact_started = {
        "type": "item.started",
        "item": {
            "item_id": "item_22",
            "type": "web_search",
            "id": open_exec,
            "query": "",
            "action": {"type": "other"},
        },
    }
    exact_completed = {
        "type": "item.completed",
        "item": {
            "item_id": "item_22",
            "type": "web_search",
            "id": open_exec,
            "query": URL,
            "action": {"type": "other"},
        },
    }
    search = {
        "type": "item.completed",
        "item": {
            "type": "web_search",
            "id": "exec-00000000-0000-4000-8000-000000000021",
            "action": {"type": "search", "query": SINGLE_QUERY},
        },
    }
    cases = {
        "no_started": [search, exact_completed],
        "opaque_query": [
            search,
            exact_started,
            {
                **exact_completed,
                "item": {**exact_completed["item"], "query": "turn0search0"},
            },
        ],
        "extra_action_member": [
            search,
            exact_started,
            {
                **exact_completed,
                "item": {
                    **exact_completed["item"],
                    "action": {"type": "other", "url": URL},
                },
            },
        ],
        "extra_item_member": [
            search,
            exact_started,
            {
                **exact_completed,
                "item": {**exact_completed["item"], "status": "completed"},
            },
        ],
    }
    for name, records in cases.items():
        context = _provider_evidence(tmp_path / name, event_records=records)
        issues = C.staged_codex_dependency_research_validator(
            {"recon_external_dependency_research.md": _report()}, context
        )
        assert issues, name


def test_literal_open_may_end_in_honest_unresolved_disposition(
    tmp_path: Path,
) -> None:
    for status in ("NEEDS_DEPENDENCY_RESEARCH", "FETCH_FAILED"):
        context = _provider_evidence(tmp_path / status.lower())
        assert C.staged_codex_dependency_research_validator(
            {"recon_external_dependency_research.md": _unresolved_report(status)},
            context,
        ) == []


def test_invented_or_mismatched_source_cannot_use_unrelated_open(
    tmp_path: Path,
) -> None:
    context = _provider_evidence(
        tmp_path,
        event_url="https://docs.example.com/different",
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report(URL)}, context
    )
    assert issues and "literal open evidence differs" in issues[0]


def test_run19_unrelated_temporal_proxy_cannot_claim_dodo_research(
    tmp_path: Path,
) -> None:
    row = _obligation_row(
        dependency="IDODORouteProxy",
        source_location="contracts/interfaces/IDODORouteProxy.sol:L4",
    )
    envelope = _envelope([row])
    unrelated = "https://github.com/temporalio/temporal-proxy"
    context = _provider_evidence(
        tmp_path,
        event_url=unrelated,
        obligations=envelope,
    )
    report = (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | "
        "Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| {row['obligation_id']} | IDODORouteProxy | "
        "contracts/interfaces/IDODORouteProxy.sol:L4 | routing proxy | "
        "The opened result is an unrelated Temporal proxy. | "
        f"{unrelated} | DODO behavior not established. | RESEARCHED |\n"
    ).encode()

    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": report}, context
    )
    assert issues and "source is not identity-relevant" in issues[0]
    with pytest.raises(ValueError, match="not identity-relevant"):
        C.claimed_researched_sources(report)


def test_dependency_source_relevance_requires_owner_or_project_anchor() -> None:
    assert C._source_is_dependency_relevant(
        "IDODORouteProxy",
        "https://docs.dodoex.io/developer/contracts/dodo-route-proxy",
    )
    assert C._source_is_dependency_relevant(
        "@uniswap/v2-core",
        "https://developers.uniswap.org/docs/protocols/v2/concepts/architecture",
    )
    assert C._source_is_dependency_relevant(
        "@zetachain/protocol-contracts",
        "https://github.com/zeta-chain/protocol-contracts",
    )
    assert not C._source_is_dependency_relevant(
        "IDODORouteProxy",
        "https://github.com/temporalio/temporal-proxy",
    )


def test_report_cannot_rename_projected_dependency_to_launder_source(
    tmp_path: Path,
) -> None:
    context = _provider_evidence(tmp_path)
    report = _report().replace(b"vendor/package", b"vendor-renamed")
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": report}, context
    )
    assert issues and "row differs from its projected identity" in issues[0]


def test_run19_uniswap_fetch_uses_neutral_accept_to_avoid_downgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, str]] = []

    class Response:
        status = 200

        @staticmethod
        def getheader(name: str) -> str | None:
            return "text/html" if name == "Content-Type" else None

        @staticmethod
        def read(_limit: int) -> bytes:
            return b"uniswap-v2-architecture"

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, _method: str, _path: str, *, headers: dict[str, str]):
            requests.append(dict(headers))

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(C, "_PinnedHTTPSConnection", Connection)
    monkeypatch.setattr(C, "_public_addresses", lambda _host: ["93.184.216.34"])
    url = "https://developers.uniswap.org/docs/protocols/v2/concepts/architecture"
    result = C._fetch_https(url)
    assert result["status"] == "FETCHED"
    assert requests == [{
        "Host": "developers.uniswap.org",
        "User-Agent": "Plamen-Dependency-Research/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }]


def test_https_downgrade_redirect_remains_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 303

        @staticmethod
        def getheader(name: str) -> str | None:
            if name == "Location":
                return "http://developers.uniswap.org/llms.mdx/docs/protocols/v2"
            return None

        @staticmethod
        def read(_limit: int) -> bytes:
            return b""

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        @staticmethod
        def request(*_args, **_kwargs) -> None:
            pass

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(C, "_PinnedHTTPSConnection", Connection)
    monkeypatch.setattr(C, "_public_addresses", lambda _host: ["93.184.216.34"])
    with pytest.raises(ValueError, match="REDIRECT_URL_POLICY"):
        C._fetch_https(
            "https://developers.uniswap.org/docs/protocols/v2/concepts/architecture"
        )


def test_dependency_bounds_make_fetch_prompt_compositional() -> None:
    accepted = _obligation_row(
        dependency="d" * 296,
        kind="k" * 80,
    )
    projection = C.compile_model_visible_projection(_envelope([accepted]))
    assert projection["obligation_count"] == 1

    rejected = _obligation_row(
        dependency="d" * 297,
        kind="k" * 80,
    )
    try:
        C.compile_model_visible_projection(_envelope([rejected]))
    except ValueError:
        pass
    else:
        raise AssertionError("non-compositional dependency bound was accepted")


def _run17_envelope() -> dict[str, object]:
    rows = [
        _obligation_row(
            dependency=f"vendor/group-{index % 7}",
            kind=f"dependency-kind-{index % 7}",
            source_location=f"src/Integration{index:02d}.sol:L{index + 1}",
            research_question=f"What is the group {index % 7} guarantee?",
        )
        for index in range(25)
    ]
    return _envelope(rows)


def _run17_report(
    envelope: dict[str, object],
    *,
    unresolved: bool = False,
    limit: int | None = None,
) -> bytes:
    projection = C.compile_model_visible_projection(envelope)
    group_by_id = {
        obligation_id: index
        for index, group in enumerate(projection["query_groups"])
        for obligation_id in group["obligation_ids"]
    }
    rows = list(projection["obligations"])
    if limit is not None:
        rows = rows[:limit]
    body = []
    for row in rows:
        group_index = group_by_id[row["obligation_id"]]
        source = "" if unresolved else f"https://docs.vendor.com/group-{group_index}"
        status = "NEEDS_DEPENDENCY_RESEARCH" if unresolved else "RESEARCHED"
        body.append(
            f"| {row['obligation_id']} | {row['dependency']} | "
            f"{row['source_location']} | assumed | observed | {source} | "
            f"UNKNOWN | {status} |"
        )
    return (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | "
        "Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        + "\n".join(body)
        + ("\n" if body else "")
    ).encode()


def _run17_events(
    envelope: dict[str, object],
    *,
    include_opens: bool = True,
) -> list[dict[str, object]]:
    projection = C.compile_model_visible_projection(envelope)
    events: list[dict[str, object]] = []
    for index, group in enumerate(projection["query_groups"]):
        query = group["query"]
        events.append({
            "type": "web_search",
            "action": {"type": "search", "query": query},
        })
        if include_opens:
            events.append({
                "type": "web_search",
                "action": {
                    "type": "open_page",
                    "url": f"https://docs.vendor.com/group-{index}",
                },
            })
    return events


def test_run17_projection_has_25_unique_rows_and_seven_exact_groups() -> None:
    envelope = _run17_envelope()
    projection = C.compile_model_visible_projection(envelope)
    rendered = C.render_model_visible_projection(projection)
    ids = [row["obligation_id"] for row in projection["obligations"]]
    grouped_ids = [
        obligation_id
        for group in projection["query_groups"]
        for obligation_id in group["obligation_ids"]
    ]

    assert projection["obligation_count"] == 25
    assert projection["query_group_count"] == 7
    assert len(ids) == len(set(ids)) == 25
    assert sorted(grouped_ids) == ids
    assert len(grouped_ids) == len(set(grouped_ids)) == 25
    assert [group["query"] for group in projection["query_groups"]] == sorted(
        group["query"] for group in projection["query_groups"]
    )
    assert all(rendered.count(obligation_id) >= 1 for obligation_id in ids)
    assert all(group["query"] in rendered for group in projection["query_groups"])


def test_projection_rejects_count_duplicate_and_group_mismatch() -> None:
    projection = C.compile_model_visible_projection(_run17_envelope())
    mutations = []

    count = {**projection, "obligation_count": 24}
    count["projection_digest"] = C._projection_digest(count)
    mutations.append(count)

    duplicate = json.loads(json.dumps(projection))
    duplicate["obligations"][1] = duplicate["obligations"][0]
    duplicate["projection_digest"] = C._projection_digest(duplicate)
    mutations.append(duplicate)

    group = json.loads(json.dumps(projection))
    group["query_groups"][0]["obligation_ids"].pop()
    group["projection_digest"] = C._projection_digest(group)
    mutations.append(group)

    for malformed in mutations:
        try:
            C.validate_model_visible_projection(malformed)
        except ValueError:
            continue
        raise AssertionError("malformed model-visible projection was accepted")

    envelope = _run17_envelope()
    envelope["retained_count"] = 24
    try:
        C.compile_model_visible_projection(envelope)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed obligation count was accepted")


def test_run17_full_report_and_exact_seven_searches_pass(tmp_path: Path) -> None:
    envelope = _run17_envelope()
    context = _provider_evidence(
        tmp_path,
        event_items=_run17_events(envelope),
        obligations=envelope,
    )
    assert C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _run17_report(envelope)},
        context,
    ) == []


def test_run17_unresolved_report_still_requires_all_seven_searches(
    tmp_path: Path,
) -> None:
    envelope = _run17_envelope()
    searches = _run17_events(envelope, include_opens=False)
    context = _provider_evidence(
        tmp_path,
        event_items=searches,
        obligations=envelope,
    )
    report = _run17_report(envelope, unresolved=True)
    assert C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": report}, context
    ) == []

    missing_context = _provider_evidence(
        tmp_path / "missing",
        event_items=searches[:-1],
        obligations=envelope,
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": report}, missing_context
    )
    assert issues and "search denominator differs" in issues[0]


def test_run17_header_only_and_partial_reports_reject(tmp_path: Path) -> None:
    envelope = _run17_envelope()
    events = _run17_events(envelope)
    context = _provider_evidence(
        tmp_path,
        event_items=events,
        obligations=envelope,
    )
    for limit in (0, 24):
        issues = C.staged_codex_dependency_research_validator(
            {
                "recon_external_dependency_research.md": _run17_report(
                    envelope, limit=limit
                )
            },
            context,
        )
        assert issues and "omits obligation rows" in issues[0]
        assert "expected=25" in issues[0]
        assert f"observed={limit}" in issues[0]


def test_run17_missing_duplicate_extra_unregistered_and_out_of_order_reject(
    tmp_path: Path,
) -> None:
    envelope = _run17_envelope()
    canonical = _run17_events(envelope)
    cases = {
        "zero": [],
        "missing": canonical[:-2],
        "duplicate": [canonical[0], *canonical],
        "extra": [
            *canonical,
            {
                "type": "web_search",
                "action": {"type": "search", "query": "unregistered query"},
            },
        ],
        "unregistered": [
            *canonical[:-1],
            {"type": "web_search", "action": {"type": "other"}},
        ],
        "out_of_order": [canonical[2], canonical[3], canonical[0], canonical[1], *canonical[4:]],
    }
    report = _run17_report(envelope)
    for name, events in cases.items():
        context = _provider_evidence(
            tmp_path / name,
            event_items=events,
            obligations=envelope,
        )
        issues = C.staged_codex_dependency_research_validator(
            {"recon_external_dependency_research.md": report}, context
        )
        assert issues, name


def test_provider_receipt_allows_bounded_windows_visibility_delay(tmp_path: Path):
    context = _provider_evidence(tmp_path)
    completion = json.loads(Path(context["attempt_completion"]).read_text())
    provider = tmp_path / completion["provider_completion_relative_path"]
    raw = provider.read_bytes()
    provider.unlink()

    def publish() -> None:
        time.sleep(0.05)
        provider.write_bytes(raw)

    thread = threading.Thread(target=publish)
    thread.start()
    try:
        assert C._provider_stdout(context)
    finally:
        thread.join(timeout=1.0)


def test_provider_stdout_reads_extended_length_receipt_paths(tmp_path: Path):
    root = tmp_path / "scratch"
    rooted_io.ensure_directory(root)
    long_parts = [(letter * 80) for letter in ("a", "b", "c")]
    attempt_relative = Path(
        ".worker_transactions", *long_parts, "completion.json"
    )
    provider_relative = Path(
        ".worker_execution_receipts", *long_parts, "completion.json"
    )
    blob_relative = Path(
        ".worker_execution_receipts", *long_parts, "blobs", "stdout.bin"
    )
    attempt_path = root / attempt_relative
    provider_path = root / provider_relative
    blob_path = root / blob_relative
    rooted_io.ensure_directory(attempt_path.parent)
    rooted_io.ensure_directory(blob_path.parent)
    stdout = (
        json.dumps({
            "type": "item.completed",
            "item": {
                "type": "web_search",
                "action": {"type": "open_page", "url": URL},
            },
        }) + "\n"
    ).encode()
    rooted_io.durable_write_once_bytes(blob_path, stdout)
    rooted_io.durable_write_once_bytes(
        provider_path,
        json.dumps({
            "stdout_blob": {
                "relative_path": "blobs/stdout.bin",
                "sha256": hashlib.sha256(stdout).hexdigest(),
                "size": len(stdout),
            },
            "stream_observation": {"stdout_overflow": False},
        }).encode(),
    )
    rooted_io.durable_write_once_bytes(
        attempt_path,
        json.dumps({
            "provider_completion_relative_path": provider_relative.as_posix(),
        }).encode(),
    )
    assert len(str(provider_path)) > 260
    assert C._provider_stdout({
        "scratchpad_root": str(root),
        "attempt_completion": str(attempt_path),
    }) == stdout


def test_fetch_receipt_validation_is_exact_and_compare_only(tmp_path: Path):
    report = tmp_path / "recon_external_dependency_research.md"
    report.write_bytes(_report())
    payload = {
        "schema_version": C.FETCH_RECEIPT_SCHEMA,
        "observed_at": "2026-09-06T00:00:00+00:00",
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "entries": [{
            "status": "FETCHED",
            "requested_url": URL,
            "final_url": URL,
            "redirects": [],
            "resolved_addresses": ["93.184.216.34"],
            "http_status": 200,
            "content_type": "text/html",
            "content_sha256": "b" * 64,
            "content_size": 123,
            "error_code": "",
            "obligation_ids": [SINGLE_ID],
        }],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["payload_digest"] = hashlib.sha256(canonical).hexdigest()
    receipt = tmp_path / C.FETCH_RECEIPT_FILE
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    before = receipt.read_bytes()
    assert C.validate_fetch_receipt(report, receipt) == []
    assert receipt.read_bytes() == before


def test_codex_dependency_fetch_phaseio_and_search_flag_order():
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="codex_dependency_fetch",
        exact_inputs=("recon_external_dependency_research.md",),
        exact_outputs=(C.FETCH_RECEIPT_FILE,),
        exact_writer="DRIVER",
    )
    assert contract.model_invoked is False
    command = D._build_codex_cmd("test-model", live_search=True)
    assert command[1:3] == ["--search", "exec"]
    assert "--search" not in D._build_codex_cmd("test-model")
