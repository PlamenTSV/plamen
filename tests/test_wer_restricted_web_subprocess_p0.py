from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
from typing import Callable

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import test_claude_provider_preparation as PROVIDER_FIXTURES  # noqa: E402
import test_wer_claude_runtime_lifecycle_p0_am as FIXTURES  # noqa: E402
import claude_phase_tool_policy as HOOK_POLICY  # noqa: E402
import worker_execution_receipts as WER  # noqa: E402


_WEB_CAPABILITY = "vendor-restricted-web-analysis"
_OBLIGATIONS = ({
    "obligation_id": "DEP-98C0701965F5",
    "dependency": "@openzeppelin/contracts",
    "kind": "source-import",
    "source_location": "src/Vault.sol:L7",
    "declaration_evidence": (
        'import "@openzeppelin/contracts/token/ERC20.sol";'
    ),
    "research_question": "Determine externally defined failure behavior.",
},)


def _build_rext_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    capabilities: tuple[str, ...] = (_WEB_CAPABILITY,),
    permission_mode: str = "default",
    builtin_tools: tuple[str, ...] = tuple(WER._RESTRICTED_CLAUDE_WEB_TOOLS),
    mutate_settings: Callable[[Path], None] | None = None,
) -> FIXTURES.RuntimeCase:
    private_python = tmp_path / "provider-python.exe"
    shutil.copy2(sys.executable, private_python)
    assert private_python.stat().st_nlink == 1
    monkeypatch.setattr(FIXTURES.sys, "executable", str(private_python))
    monkeypatch.setattr(
        FIXTURES.A,
        "_default_runtime_namespace",
        lambda: FIXTURES._fixture_runtime_namespace(tmp_path),
    )
    PROVIDER_FIXTURES._install_observers(monkeypatch, private_python)
    monkeypatch.setattr(
        FIXTURES.P,
        "observe_claude_executable",
        lambda **_kwargs: FIXTURES._executable_observation(
            private_python,
            version="2.1.252",
        ),
    )

    original_policy_writer = FIXTURES.Q.write_policy_bundle
    original_intent_compiler = (
        FIXTURES.P.compile_claude_provider_semantic_intent
    )
    original_tool_compiler = FIXTURES.P.compile_claude_phase_tool_policy

    def write_rext_policy(**kwargs: object) -> object:
        result = original_policy_writer(
            **kwargs,
            network_authority=(
                FIXTURES.Q.build_dependency_research_network_authority(
                    _OBLIGATIONS
                )
            ),
        )
        if mutate_settings is not None:
            mutate_settings(Path(str(kwargs["settings_path"])))
        return result

    def compile_rext_intent(**kwargs: object) -> object:
        kwargs["phase"] = "recon_external_dependency_research"
        kwargs["required_capabilities"] = capabilities
        return original_intent_compiler(**kwargs)

    def compile_rext_tools(**kwargs: object) -> object:
        kwargs.update({
            "phase": "recon_external_dependency_research",
            "permission_mode": permission_mode,
            "builtin_tools": builtin_tools,
            "forbidden_tools": tuple(sorted(
                WER._RESTRICTED_CLAUDE_WEB_FORBIDDEN_TOOLS
            )),
        })
        return original_tool_compiler(**kwargs)

    monkeypatch.setattr(
        FIXTURES.Q,
        "write_policy_bundle",
        write_rext_policy,
    )
    monkeypatch.setattr(
        FIXTURES.P,
        "compile_claude_provider_semantic_intent",
        compile_rext_intent,
    )
    monkeypatch.setattr(
        FIXTURES.P,
        "compile_claude_phase_tool_policy",
        compile_rext_tools,
    )
    return FIXTURES._case(
        tmp_path,
        label="rext-bounded-web",
        restricted=True,
    )


def _exercise_receipt_bound_redirect(
    case: FIXTURES.RuntimeCase, *, successor_outcome: str = "success",
    session_id: str | None = None,
) -> None:
    policy_path = case.root / "restricted-policy-rext-bounded-web.json"
    policy = HOOK_POLICY.load_policy(policy_path)
    row = policy["network_authority"]["obligations"][0]
    query = row["query"]
    original = (
        "https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-01"
    )
    successor = (
        "https://developers.uniswap.org/contracts/v2/reference/smart-contracts/router-01"
    )

    def event(name: str, tool: str, tool_input: dict[str, str], use: str, **extra: object):
        return {
            "session_id": case.session_id if session_id is None else session_id,
            "tool_use_id": use,
            "cwd": str(case.root),
            "permission_mode": "default",
            "hook_event_name": name,
            "tool_name": tool,
            "tool_input": tool_input,
            **extra,
        }

    search_input = {"query": query}
    assert HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PreToolUse", "WebSearch", search_input, "wer-search",
        )).encode(),
    )[0] == 0
    search_response = {
        "query": query,
        "results": [
            {
                "tool_use_id": "srv-search-1",
                "content": [{"title": "Router docs", "url": original}],
            },
            {
                "tool_use_id": "srv-search-2",
                "content": [{"title": "Router source", "url": "https://github.com/Uniswap/v2-periphery"}],
            },
            "Aggregate search results",
        ],
        "durationSeconds": 0.2,
        "searchCount": 2,
    }
    assert HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PostToolUse", "WebSearch", search_input, "wer-search",
            tool_response=search_response,
        )).encode(),
    ) == (0, {})

    fetch_proposed = {
        "url": original,
        "prompt": "Extract router guarantees and failure behavior.",
    }
    fetch_pre = HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PreToolUse", "WebFetch", fetch_proposed, "wer-redirect",
        )).encode(),
    )
    assert fetch_pre[0] == 0
    fetch_input = fetch_pre[1]["hookSpecificOutput"]["updatedInput"]
    assert fetch_input == {"url": original, "prompt": row["fetch_prompt"]}
    redirect_result = (
        "REDIRECT DETECTED: The URL redirects to a location that was not fetched automatically.\n\n"
        f"Original URL: {original}\n"
        "Redirect URL (from the server's Location header — server-supplied, not verified): "
        f"{successor}\n"
        "Status: 301 Moved Permanently\n\n"
        "To complete your request, I need to fetch content from the redirected URL. "
        "Please use WebFetch again with these parameters:\n"
        f'- url: "{successor}"\n'
        f'- prompt: "{row["fetch_prompt"]}"'
    )
    assert HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PostToolUse", "WebFetch", fetch_input, "wer-redirect",
            tool_response={
                "bytes": len(redirect_result.encode()), "code": 301,
                "codeText": "Moved Permanently", "durationMs": 5,
                "result": redirect_result, "url": original,
            },
        )).encode(),
    ) == (0, {})

    # This is the exact proposal emitted in Claude 2.1.252's authenticated
    # redirect envelope.  The hook resolves it to the same opaque group and
    # returns the canonical whole-object updatedInput again.
    successor_proposed = {"url": successor, "prompt": row["fetch_prompt"]}
    successor_pre = HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PreToolUse", "WebFetch", successor_proposed, "wer-successor",
        )).encode(),
    )
    assert successor_pre[0] == 0
    successor_input = successor_pre[1]["hookSpecificOutput"]["updatedInput"]
    assert successor_input == {
        "url": successor, "prompt": row["fetch_prompt"],
    }
    if successor_outcome == "missing_post":
        return
    if successor_outcome == "second_redirect":
        provider_original = "https://developers.uniswap.org/docs/protocols/v2/overview"
        insecure_successor = "http://developers.uniswap.org/llms.mdx/docs/protocols/v2/overview"
        second_result = (
            "REDIRECT DETECTED: The URL redirects to a location that was not fetched automatically.\n\n"
            f"Original URL: {provider_original}\n"
            "Redirect URL (from the server's Location header — server-supplied, not verified): "
            f"{insecure_successor}\n"
            "Status: 303 See Other\n\n"
            "To complete your request, I need to fetch content from the redirected URL. "
            "Please use WebFetch again with these parameters:\n"
            f'- url: "{insecure_successor}"\n'
            f'- prompt: "{row["fetch_prompt"]}"'
        )
        assert HOOK_POLICY.run_hook(
            policy_path,
            json.dumps(event(
                "PostToolUse", "WebFetch", successor_input, "wer-successor",
                tool_response={
                    "bytes": len(second_result.encode()), "code": 303,
                    "codeText": "See Other", "durationMs": 5,
                    "result": second_result, "url": successor,
                },
            )).encode(),
        )[0] == 2
        return
    assert successor_outcome == "success"
    assert HOOK_POLICY.run_hook(
        policy_path,
        json.dumps(event(
            "PostToolUse", "WebFetch", successor_input, "wer-successor",
            tool_response={
                "bytes": 12, "code": 200, "codeText": "OK",
                "durationMs": 5, "result": "Router facts", "url": successor,
            },
        )).encode(),
    ) == (0, {})


def test_rext_wer_subprocess_commits_and_terminal_receipt_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _build_rext_case(tmp_path, monkeypatch)
    _exercise_receipt_bound_redirect(case)
    captures = FIXTURES._install_fake_cli(monkeypatch, (case,))

    completed = WER.run_observed_worker(**case.wer_kwargs())
    receipt = WER.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=FIXTURES._strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    boundary = arm["process_intent"]["restricted_stage_boundary"]

    assert len(captures) == 1
    argv = captures[0]["argv"]
    assert argv.count("--allowedTools") == 1
    assert argv[argv.index("--allowedTools") + 1].split(",") == list(
        WER._RESTRICTED_CLAUDE_WEB_ALLOWED_TOOLS
    )
    assert argv[argv.index("--permission-mode") + 1] == "default"
    assert captures[0]["env"]["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    headless = arm["process_intent"]["provider_stdout_evidence"][
        "command_contract"
    ]["headless_profile"]
    assert headless["permission_mode"] == "default"
    hook_policy = json.loads(Path(
        headless["settings"]["hook_policy"]["path"]
    ).read_text(encoding="utf-8"))
    assert hook_policy["external_network_policy"] == "BOUNDED_RECEIPTS"
    assert hook_policy["network_authority"]["permission_mode"] == "default"
    assert not ({"Edit", "Write", "WebFetch", "WebSearch"} & set(
        argv[argv.index("--allowedTools") + 1].split(",")
    ))
    assert FIXTURES._find_values(receipt, "completion_authority") == [True]
    assert FIXTURES._find_values(receipt, "closure_mode") == [
        "NORMAL_COMPLETION"
    ]
    assert boundary["permission_rules"] == sorted({
        "Glob",
        "Grep",
        "Read",
        *FIXTURES.Q.exact_edit_permission_rules((
            tmp_path / case.output_scope / "result.json",
        )),
    })
    assert "WebFetch" not in boundary["permission_rules"]
    assert "WebSearch" not in boundary["permission_rules"]


@pytest.mark.parametrize(
    ("successor_outcome", "error"),
    (
        ("missing_post", "PRE closure cardinality mismatch"),
    ),
)
def test_rext_wer_rejects_unclosed_or_second_redirect_receipt_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    successor_outcome: str,
    error: str,
) -> None:
    case = _build_rext_case(tmp_path, monkeypatch)
    _exercise_receipt_bound_redirect(
        case, successor_outcome=successor_outcome,
    )
    FIXTURES._install_fake_cli(monkeypatch, (case,))
    with pytest.raises(
        (WER.WorkerExecutionError, WER.WorkerExecutionIncomplete),
        match=error,
    ):
        WER.run_observed_worker(**case.wer_kwargs())
    assert not list(
        tmp_path.glob(".worker_execution_receipts/*/completion_*.json")
    )


def test_rext_wer_accepts_closed_fetch_rejection_for_staged_partial_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _build_rext_case(tmp_path, monkeypatch)
    _exercise_receipt_bound_redirect(
        case, successor_outcome="second_redirect",
    )
    FIXTURES._install_fake_cli(monkeypatch, (case,))
    completed = WER.run_observed_worker(**case.wer_kwargs())
    receipt = WER.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=FIXTURES._strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    lifecycle = receipt["process_observation"][
        "bounded_web_receipt_lifecycle"
    ]
    assert lifecycle["receipt_count"] == 6


def test_rext_terminal_replay_rejects_post_completion_receipt_set_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _build_rext_case(tmp_path, monkeypatch)
    _exercise_receipt_bound_redirect(case)
    FIXTURES._install_fake_cli(monkeypatch, (case,))
    completed = WER.run_observed_worker(**case.wer_kwargs())
    policy = HOOK_POLICY.load_policy(
        case.root / "restricted-policy-rext-bounded-web.json"
    )
    receipt_root = Path(policy["receipt_directory"])
    existing = sorted(receipt_root.glob("web-*.json"))[0]
    shutil.copy2(existing, receipt_root / ("web-" + "f" * 64 + ".json"))
    with pytest.raises(
        WER.WorkerExecutionError,
        match="bounded-web receipt lifecycle is incomplete",
    ):
        WER.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=FIXTURES._strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_rext_wer_rejects_balanced_foreign_session_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _build_rext_case(tmp_path, monkeypatch)
    _exercise_receipt_bound_redirect(
        case, session_id="foreign-provider-session",
    )
    FIXTURES._install_fake_cli(monkeypatch, (case,))
    with pytest.raises(
        (WER.WorkerExecutionError, WER.WorkerExecutionIncomplete),
        match="foreign provider session",
    ):
        WER.run_observed_worker(**case.wer_kwargs())
    assert not list(
        tmp_path.glob(".worker_execution_receipts/*/completion_*.json")
    )


def _remove_post_failure_hook(settings_path: Path) -> None:
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["hooks"].pop("PostToolUseFailure")
    settings_path.write_bytes(FIXTURES.Q.canonical_json_bytes(settings))


@pytest.mark.parametrize(
    ("mutation", "kwargs"),
    (
        (
            "capability",
            {"capabilities": (_WEB_CAPABILITY, "vendor-restricted-unknown")},
        ),
        ("permission", {"permission_mode": "dontAsk"}),
        (
            "tools",
            {"builtin_tools": tuple(WER._RESTRICTED_CLAUDE_TOOLS)},
        ),
        ("hooks", {"mutate_settings": _remove_post_failure_hook}),
    ),
)
def test_rext_mutations_fail_before_completion_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    kwargs: dict[str, object],
) -> None:
    if mutation in {"capability", "hooks"}:
        case = _build_rext_case(tmp_path, monkeypatch, **kwargs)
        FIXTURES._install_fake_cli(monkeypatch, (case,))
        with pytest.raises(
            WER.WorkerExecutionError,
            match=(
                "restricted Claude capability denominator is unsupported"
                if mutation == "capability"
                else "runtime materialization failed|settings capability denominator"
            ),
        ):
            WER.run_observed_worker(**case.wer_kwargs())
    else:
        with pytest.raises(Exception, match="capability debt|package carries"):
            _build_rext_case(tmp_path, monkeypatch, **kwargs)
    assert not list(
        tmp_path.glob(".worker_execution_receipts/*/completion_*.json")
    )
