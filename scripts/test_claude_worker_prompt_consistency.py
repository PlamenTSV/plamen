from __future__ import annotations

import pytest

import claude_worker_prompt_consistency as C


PROJECT = r"C:\audit workspace\protocol"
SCRATCHPAD = PROJECT + r"\.scratchpad"
INPUTS = (
    "scratchpad:recon_summary.md",
    "scratchpad:contract_inventory.md",
    "scratchpad:retry_plan.json",
    PROJECT + r"\foundry.toml",
)
OUTPUTS = ("scratchpad:assigned_findings.md",)
TOOLS = ("Edit", "Glob", "Grep", "Read", "Write")
SAFE_ROOTS = (
    PROJECT + r"\contracts",
    PROJECT + r"\test",
)


def _issues(prompt: str, **overrides):
    authority = {
        "phase_io_inputs": INPUTS,
        "phase_io_outputs": OUTPUTS,
        "policy_tools": TOOLS,
        "safe_search_roots": SAFE_ROOTS,
        "project_root": PROJECT,
        "scratchpad_root": SCRATCHPAD,
    }
    authority.update(overrides)
    return C.validate_claude_worker_prompt_consistency(prompt, **authority)


def _codes(prompt: str, **overrides) -> set[str]:
    return {issue.code for issue in _issues(prompt, **overrides)}


def test_valid_restricted_leaf_prompt_has_no_issues() -> None:
    prompt = r"""
# Worker assignment

- Read `scratchpad:recon_summary.md` and `contract_inventory.md`.
- Search `contracts` with Glob and `test` with Grep.
- Write only to `scratchpad:assigned_findings.md`.
- Use Read, Glob, Grep, and Write as needed.

Never search PROJECT_ROOT, the scratchpad root, `.`, or a parent directory.
Do not use Bash, PowerShell, Agent, Task, WebSearch, WebFetch, or MCP.
The PhaseIO JSON mentions "scratchpad:retry_plan.json" as a registered input.
"""
    assert _issues(prompt) == ()


def test_r44_foundry_parent_directive_is_rejected() -> None:
    prompt = (
        "If PROJECT_ROOT is a source subdirectory, you may move one or two "
        "parents up only to the nearest directory containing `foundry.toml`."
    )
    issues = _issues(prompt)
    assert {issue.code for issue in issues} == {
        "UNSAFE_PARENT_SEARCH_DIRECTIVE",
        "UNSAFE_PROJECT_SEARCH_DIRECTIVE",
    }
    assert all(issue.line == 1 for issue in issues)


@pytest.mark.parametrize(
    ("prompt", "code"),
    [
        ("Search PROJECT_ROOT recursively for Solidity files.",
         "UNSAFE_PROJECT_SEARCH_DIRECTIVE"),
        ("Scan the repository root before analysis.",
         "UNSAFE_PROJECT_SEARCH_DIRECTIVE"),
        ("Use Glob with path `.` to find `foundry.toml`.",
         "UNSAFE_PROJECT_SEARCH_DIRECTIVE"),
        ("Grep `.scratchpad` for prior reports.",
         "UNSAFE_SCRATCHPAD_SEARCH_DIRECTIVE"),
        ("Walk `..\\sibling` to locate dependencies.",
         "UNSAFE_PARENT_SEARCH_DIRECTIVE"),
    ],
)
def test_explicit_unsafe_search_directives(prompt: str, code: str) -> None:
    assert code in _codes(prompt)


def test_non_safe_concrete_search_root_is_rejected() -> None:
    issues = _issues("Search `scripts` for deployment helpers.")
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNSAFE_SEARCH_ROOT_DIRECTIVE", "scripts")
    ]


def test_windows_safe_roots_are_case_and_separator_stable() -> None:
    prompt = (
        r"Search `c:/AUDIT WORKSPACE/protocol/contracts` for contracts." "\n"
        r"Use Grep on `C:\audit workspace\protocol\test`."
    )
    assert _issues(prompt) == ()


def test_unresolved_claude_methodology_path_is_always_detected() -> None:
    issues = _issues(
        "Do not read `~/.claude/agents/depth-token-flow.md`; use the Codex path."
    )
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNRESOLVED_CLAUDE_PATH", "~/.claude")
    ]


def test_named_artifact_read_must_be_registered() -> None:
    prompt = (
        "Read `scratchpad:recon_summary.md`.\n"
        "Review `scratchpad:secret_ground_truth.md`.\n"
        "Use Read to open `scratchpad:raw_inventory.json`."
    )
    issues = _issues(prompt)
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "scratchpad:secret_ground_truth.md"),
        ("UNREGISTERED_ARTIFACT_READ", "scratchpad:raw_inventory.json"),
    ]


def test_project_root_anaphoric_artifact_read_requires_exact_project_input() -> None:
    issues = _issues(
        "`impact_map.md` is present in PROJECT_ROOT. Read it.",
        phase_io_inputs=INPUTS + ("scratchpad:impact_map.md",),
    )
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "impact_map.md")
    ]


def test_project_root_anaphoric_artifact_read_across_adjacent_lines_is_checked() -> None:
    issues = _issues(
        "`impact_map.md` is present in PROJECT_ROOT.\nRead it.",
        phase_io_inputs=INPUTS + ("scratchpad:impact_map.md",),
    )
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "impact_map.md")
    ]


@pytest.mark.parametrize(
    "registered",
    (
        PROJECT + r"\impact_map.md",
        "project:impact_map.md",
    ),
)
def test_project_root_anaphoric_artifact_read_accepts_exact_project_input(
    registered: str,
) -> None:
    assert _issues(
        "`impact_map.md` is present in PROJECT_ROOT. Read it.",
        phase_io_inputs=INPUTS + (registered,),
    ) == ()


def test_direct_project_root_artifact_read_requires_exact_project_input() -> None:
    issues = _issues(
        "Read `impact_map.md` from PROJECT_ROOT.",
        phase_io_inputs=INPUTS + ("scratchpad:impact_map.md",),
    )
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "impact_map.md")
    ]


def test_negated_or_descriptive_project_artifact_prose_is_not_a_directive() -> None:
    inputs = INPUTS + ("scratchpad:impact_map.md",)
    assert _issues(
        "`impact_map.md` is present in PROJECT_ROOT. Do not read it.",
        phase_io_inputs=inputs,
    ) == ()
    assert _issues(
        "`impact_map.md` is present in PROJECT_ROOT for operator review.",
        phase_io_inputs=inputs,
    ) == ()


def test_windows_project_root_anaphora_accepts_registered_path_with_spaces() -> None:
    assert _issues(
        "`impact_map.md` is present in PROJECT_ROOT. Read it.",
        phase_io_inputs=INPUTS + (PROJECT + r"\impact_map.md",),
    ) == ()


def test_posix_project_root_anaphora_accepts_exact_registered_path() -> None:
    project = "/audit workspace/protocol"
    assert _issues(
        "`impact_map.md` is present in PROJECT_ROOT. Read it.",
        project_root=project,
        scratchpad_root=project + "/.scratchpad",
        phase_io_inputs=(project + "/impact_map.md",),
        phase_io_outputs=(project + "/.scratchpad/assigned_findings.md",),
        safe_search_roots=(project + "/contracts",),
    ) == ()


def test_registered_windows_input_and_unique_basename_are_accepted() -> None:
    prompt = (
        r"Open `C:\AUDIT WORKSPACE\PROTOCOL\.scratchpad\retry_plan.json`." "\n"
        "Consume `contract_inventory.md`."
    )
    assert _issues(prompt) == ()


def test_ambiguous_bare_basename_is_not_admitted() -> None:
    inputs = INPUTS + (PROJECT + r"\docs\contract_inventory.md",)
    issues = _issues("Read `contract_inventory.md`.", phase_io_inputs=inputs)
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "contract_inventory.md")
    ]


def test_posix_bare_artifact_case_remains_sensitive() -> None:
    issues = _issues(
        "Read `RECON_SUMMARY.md`.",
        project_root="/audit/protocol",
        scratchpad_root="/audit/protocol/.scratchpad",
        phase_io_inputs=("scratchpad:recon_summary.md",),
        phase_io_outputs=("scratchpad:assigned_findings.md",),
        safe_search_roots=("/audit/protocol/contracts",),
    )
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "RECON_SUMMARY.md")
    ]


def test_contextual_read_list_is_checked() -> None:
    prompt = """
Read these artifacts:
- `scratchpad:recon_summary.md`
- `scratchpad:not_registered.json`
"""
    assert [(issue.code, issue.subject) for issue in _issues(prompt)] == [
        ("UNREGISTERED_ARTIFACT_READ", "scratchpad:not_registered.json")
    ]


def test_alternate_and_unregistered_output_writes_are_rejected() -> None:
    prompt = (
        "Write only to `scratchpad:assigned_findings.md`, then append "
        "`scratchpad:violations.md`.\n"
        "Create an additional output artifact."
    )
    issues = _issues(prompt)
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_OUTPUT_WRITE", "scratchpad:violations.md"),
        ("ALTERNATE_OUTPUT_WRITE", "additional output"),
    ]


def test_sequenced_write_directive_is_checked() -> None:
    issues = _issues("Then append `scratchpad:late_summary.md`.")
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_OUTPUT_WRITE", "scratchpad:late_summary.md")
    ]


def test_contextual_write_list_and_windows_output() -> None:
    prompt = (
        "Write to:\n"
        r"- `C:\audit workspace\protocol\.scratchpad\assigned_findings.md`"
    )
    assert _issues(prompt) == ()


@pytest.mark.parametrize(
    ("prompt", "code", "subject"),
    [
        ("Spawn four breadth agents.", "DENIED_COORDINATOR_INSTRUCTION", "Agent"),
        ("Use the Task tool to delegate analysis.",
         "DENIED_COORDINATOR_INSTRUCTION", "Task"),
        ("Run `forge test` in the shell.", "DENIED_TOOL_INSTRUCTION", "shell"),
        ("Execute the static tools before writing.",
         "DENIED_TOOL_INSTRUCTION", "shell"),
        ("Use PowerShell to inspect the tree.", "DENIED_TOOL_INSTRUCTION", "shell"),
        ("Call WebSearch for current documentation.",
         "DENIED_TOOL_INSTRUCTION", "WebSearch"),
        ("Invoke an MCP server for precedent research.",
         "DENIED_TOOL_INSTRUCTION", "MCP"),
        ("**MANDATORY**: Use Slither (`list_functions` + `analyze_modifiers`).",
         "DENIED_TOOL_INSTRUCTION", "shell"),
    ],
)
def test_denied_coordinator_and_tool_directives(
    prompt: str, code: str, subject: str
) -> None:
    assert (code, subject) in {
        (issue.code, issue.subject) for issue in _issues(prompt)
    }


def test_policy_admitted_web_tool_instruction_is_valid() -> None:
    assert _issues(
        "Call WebSearch with the exact authorized query.",
        policy_tools=TOOLS + ("WebSearch", "WebFetch"),
    ) == ()


def test_negated_and_descriptive_tool_prose_does_not_false_positive() -> None:
    prompt = """
Do not spawn agents or use the Task tool.
Never run Bash, PowerShell, shell commands, WebSearch, WebFetch, or MCP.
The provider tool denominator contains Read, Write, Edit, Glob, and Grep.
The coordinator, not this worker, performs downstream orchestration.
"""
    assert _issues(prompt) == ()


@pytest.mark.parametrize(
    ("phase_shape", "prompt", "expected"),
    [
        (
            "breadth",
            "Read `scratchpad:recon_summary.md` and `scratchpad:raw_recon.md`.",
            "UNREGISTERED_ARTIFACT_READ",
        ),
        (
            "rescan",
            "Search PROJECT_ROOT again for blind spots.",
            "UNSAFE_PROJECT_SEARCH_DIRECTIVE",
        ),
        (
            "depth",
            "Spawn depth agents with the Agent tool, then aggregate their work.",
            "DENIED_COORDINATOR_INSTRUCTION",
        ),
        (
            "integration-hazard",
            "SCOPE: Write ONLY to `scratchpad:assigned_findings.md` and also "
            "`scratchpad:integration_summary.md`.",
            "UNREGISTERED_OUTPUT_WRITE",
        ),
    ],
)
def test_phase_family_hazard_shapes(
    phase_shape: str, prompt: str, expected: str
) -> None:
    del phase_shape
    assert expected in _codes(prompt)


def test_raising_api_exposes_structured_issues() -> None:
    with pytest.raises(C.ClaudeWorkerPromptConsistencyError) as caught:
        C.require_claude_worker_prompt_consistency(
            "Read `scratchpad:unregistered.md`.",
            phase_io_inputs=INPUTS,
            phase_io_outputs=OUTPUTS,
            policy_tools=TOOLS,
            safe_search_roots=SAFE_ROOTS,
            project_root=PROJECT,
            scratchpad_root=SCRATCHPAD,
        )
    assert caught.value.issues[0].code == "UNREGISTERED_ARTIFACT_READ"


def test_invalid_api_inputs_fail_before_analysis() -> None:
    with pytest.raises(TypeError):
        _issues("Read `x.md`.", phase_io_inputs="scratchpad:x.md")
    with pytest.raises(ValueError):
        _issues("")
    with pytest.raises(ValueError):
        _issues("x\x00y")


def test_mixed_clause_negation_is_clause_local() -> None:
    prompts = {
        "Do not read `scratchpad:recon_summary.md`; read `scratchpad:secret.md`.":
            "UNREGISTERED_ARTIFACT_READ",
        "Do not read `scratchpad:recon_summary.md`, then read `scratchpad:secret.md`.":
            "UNREGISTERED_ARTIFACT_READ",
        "Do not write `scratchpad:assigned_findings.md`; write `scratchpad:other.md`.":
            "UNREGISTERED_OUTPUT_WRITE",
        "Do not search `contracts`; search PROJECT_ROOT recursively.":
            "UNSAFE_PROJECT_SEARCH_DIRECTIVE",
        "Do not spawn agents; then spawn one agent.":
            "DENIED_COORDINATOR_INSTRUCTION",
        "Do not call WebSearch; call WebFetch.":
            "DENIED_TOOL_INSTRUCTION",
    }
    for prompt, expected in prompts.items():
        assert expected in _codes(prompt), prompt


def test_later_negated_clause_does_not_taint_prior_allowed_clause() -> None:
    assert _issues(
        "Write only `scratchpad:assigned_findings.md`; "
        "do not write `scratchpad:other.md`."
    ) == ()
    assert _issues("Search `contracts`; never search PROJECT_ROOT.") == ()
    assert _issues("Read `scratchpad:recon_summary.md` and do not read `secret.md`.") == ()


@pytest.mark.parametrize(
    "prompt",
    [
        "<!-- Read `scratchpad:secret.md`. -->",
        "> Read `scratchpad:secret.md`.",
        "Example: Read `scratchpad:secret.md`.",
        "Bad example — Read `scratchpad:secret.md`.",
        "Example: `Read scratchpad:secret.md`",
        "Example only:\n```\nRead `scratchpad:secret.md`.\n```",
    ],
)
def test_model_visible_comments_blockquotes_and_examples_are_checked(prompt: str) -> None:
    assert "UNREGISTERED_ARTIFACT_READ" in _codes(prompt)


def test_negated_model_visible_example_remains_non_directive() -> None:
    assert _issues("Example: Do not read `scratchpad:secret.md`.") == ()


@pytest.mark.parametrize(
    "prompt",
    [
        "The worker must read `scratchpad:secret.md` before analysis.",
        "This agent is required to inspect `scratchpad:secret.md`.",
        "Each auditor should review `scratchpad:secret.md`.",
    ],
)
def test_explicit_subject_modal_directives_are_checked(prompt: str) -> None:
    assert "UNREGISTERED_ARTIFACT_READ" in _codes(prompt)


@pytest.mark.parametrize(
    ("prompt", "expected"),
    [
        ("Read the following files\n- `scratchpad:secret.md`",
         "UNREGISTERED_ARTIFACT_READ"),
        ("Files to read:\n1. `scratchpad:secret.md`",
         "UNREGISTERED_ARTIFACT_READ"),
        ("Input artifacts:\n* `scratchpad:secret.md`",
         "UNREGISTERED_ARTIFACT_READ"),
        ("Write these outputs\n- `scratchpad:other.md`",
         "UNREGISTERED_OUTPUT_WRITE"),
        ("Output files:\n- `scratchpad:other.md`",
         "UNREGISTERED_OUTPUT_WRITE"),
    ],
)
def test_non_colon_and_reverse_multiline_directive_lists(
    prompt: str, expected: str
) -> None:
    assert expected in _codes(prompt)


def test_bare_artifact_search_is_a_registered_input_read() -> None:
    assert _issues("Search `recon_summary.md` for a marker.") == ()
    issues = _issues("Search `secret.md` for a marker.")
    assert [(issue.code, issue.subject) for issue in issues] == [
        ("UNREGISTERED_ARTIFACT_READ", "secret.md")
    ]


def test_unquoted_posix_search_roots_are_checked() -> None:
    authority = {
        "project_root": "/audit/protocol",
        "scratchpad_root": "/audit/protocol/.scratchpad",
        "phase_io_inputs": ("scratchpad:recon_summary.md",),
        "phase_io_outputs": ("scratchpad:assigned_findings.md",),
        "safe_search_roots": ("/audit/protocol/contracts",),
    }
    assert _issues("Search /audit/protocol/contracts for sources.", **authority) == ()
    assert "UNSAFE_SEARCH_ROOT_DIRECTIVE" in _codes(
        "Search /audit/protocol/scripts for helpers.", **authority
    )
    assert "UNSAFE_SEARCH_ROOT_DIRECTIVE" in _codes(
        "Search /etc for configuration.", **authority
    )


def test_unquoted_registered_paths_with_spaces_do_not_false_positive() -> None:
    windows = (
        r"Read C:\audit workspace\protocol\.scratchpad\recon_summary.md." "\n"
        r"Search C:\audit workspace\protocol\contracts for sources." "\n"
        r"Write C:\audit workspace\protocol\.scratchpad\assigned_findings.md."
    )
    assert _issues(windows) == ()

    posix_project = "/audit workspace/protocol"
    posix = (
        "Read /audit workspace/protocol/.scratchpad/recon_summary.md.\n"
        "Search /audit workspace/protocol/contracts for sources.\n"
        "Write /audit workspace/protocol/.scratchpad/assigned_findings.md."
    )
    assert _issues(
        posix,
        project_root=posix_project,
        scratchpad_root=posix_project + "/.scratchpad",
        phase_io_inputs=("scratchpad:recon_summary.md",),
        phase_io_outputs=("scratchpad:assigned_findings.md",),
        safe_search_roots=(posix_project + "/contracts",),
    ) == ()


@pytest.mark.parametrize(
    "prompt",
    [
        "Run git diff against upstream.",
        "Use cmd.exe to inspect files.",
        "Run python helper.py.",
        "Execute bash audit.sh.",
    ],
)
def test_explicit_shell_command_instructions_are_denied(prompt: str) -> None:
    assert ("DENIED_TOOL_INSTRUCTION", "shell") in {
        (issue.code, issue.subject) for issue in _issues(prompt)
    }


@pytest.mark.parametrize(
    "prompt",
    [
        "Review of `secret.md` is out of scope.",
        "Read access to `secret.md` is denied.",
        "Search results from PROJECT_ROOT are unavailable.",
        "Write permission for `scratchpad:other.md` is denied.",
        "Use of Bash is prohibited.",
    ],
)
def test_nominal_descriptive_prose_does_not_false_positive(prompt: str) -> None:
    assert _issues(prompt) == ()
