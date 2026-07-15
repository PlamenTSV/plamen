"""Plamen V2 driver — slim orchestrator.

Imports all public names from the 4 sub-modules so existing test files
that do `import plamen_driver as D` continue to work unchanged.
"""
from __future__ import annotations

import concurrent.futures
import atexit
from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from plamen_types import *  # noqa: F403,F401
from plamen_parsers import *  # noqa: F403,F401
from plamen_validators import *  # noqa: F403,F401
from plamen_mechanical import *  # noqa: F403,F401
from plamen_prompt import *  # noqa: F403,F401
# Explicit imports for underscore-prefixed dedup helpers that are NOT in the
# source modules' __all__ (so `import *` above does not bring them in). The
# driver's dedup multi-round orchestration + absorbed-map propagation depend on
# these; importing them by name keeps the dependency robust regardless of the
# producer modules' __all__ contents.
from plamen_parsers import _dedup_live_pair_cap  # noqa: F401
# Dedup redesign (in-context clustering blocks): the block builder is the new
# live LLM-input producer. It is exported in plamen_parsers.__all__, but import
# it by name too (mirrors the _dedup_live_pair_cap robustness pattern) so the
# phase wiring below is insulated from __all__ drift.
from plamen_parsers import _compute_dedup_candidate_blocks  # noqa: F401
from plamen_parsers import _compute_report_dedup_candidate_pairs  # noqa: F401
from plamen_mechanical import _extract_dedup_absorbed_ids  # noqa: F401
import plamen_display as display
from pty_exec import (
    SUBPROCESS_ISOLATION_PAYLOAD,
    _CONTEXT_THRASH_LOOP_S,
    ClaudePtySession,
    append_claude_pty_prompt_arg,
    event_is_overloaded,
    event_is_rate_limited,
    parse_transcript_agentids,
    parse_transcript_usage,
    text_shows_overloaded,
    text_shows_rate_limit,
    transcript_shows_compaction,
)
from preflight_pty_transports import (
    should_run_preflight,
)


def _run_opengrep_scan(scratch: Path, proj: Path, lang: str) -> str:
    """Lazy wrapper so driver helper introspection sees the opengrep runner."""
    from recon_prepass import _run_opengrep_scan as _scan

    return _scan(scratch, proj, lang)


def _run_sec3_xray(scratch: Path, proj: Path) -> str:
    """Lazy wrapper so driver helper introspection sees the Sec3 X-Ray runner
    (RECON-1: invoked from the pre-breadth hook, not startup)."""
    from recon_prepass import _run_sec3_xray as _scan

    return _scan(scratch, proj)


def _run_dependency_audit_l1(scratch: Path, proj: Path, language: str) -> str:
    """Lazy wrapper so driver helper introspection sees the L1 dependency-
    vulnerability scan runner (Wave-2 A5: govulncheck / cargo audit, invoked
    from the pre-breadth hook, not startup)."""
    from recon_prepass import _run_dependency_audit_l1 as _scan

    return _scan(scratch, proj, language)

# Rate-limit detection: JSON-first (structured), text-fallback (unstructured).
#
# BACKGROUND: Plain-text regex on the stdio log tail was the source of a
# $120 false-positive loop — Claude's own hallucinated prose about quota
# exhaustion post-compaction matched the regex and caused the driver to
# pause the pipeline when no API error had actually occurred.
#
# FIX: `claude -p --output-format json` writes a structured envelope as the
# final stdout chunk. Parse that envelope and trust its fields:
#   - `is_error: true` AND `api_error_status in (429, 529)` → rate limit
#   - `stop_reason: "rate_limited"` / similar → rate limit
# Only fall back to text regex if the envelope is unparseable (subprocess
# crashed before writing JSON). And in fallback, require the error signal
# to co-occur with an HTTP-style status or API error prefix — strings
# inside LLM prose don't have those.
_API_RATE_LIMIT_STATUSES = {429, 529}  # 429 Too Many Requests, 529 Overloaded

# When a provider advises a reset window FURTHER out than this, a capped
# spin-wait (min(estimate, 3600)) + retry would burn a retry re-hitting the same
# cap. This is the Codex/ChatGPT DAILY usage-cap case (resets hours out with an
# absolute "try again at <time>"). Above the threshold we preserve state and
# pause for resume immediately instead. Anthropic 429/529 advise minutes-scale
# `retry-after` windows and stay below it, so this never misfires on them.
_RATE_LIMIT_RESUME_THRESHOLD_S = int(
    os.environ.get("PLAMEN_RATE_LIMIT_RESUME_THRESHOLD_S", "1800") or 1800
)

# Codex-only extended retry budget. The Codex CLI is a single-pass executor
# that frequently under-covers a discovery/synthesis phase on the first run
# and recovers when re-prompted with a delta retry hint. Claude (and every
# other phase) keep the standard "retry-once-then-degrade" 2-attempt budget;
# ONLY these RECOVERING content phases get up to 3 attempts, and ONLY when the
# active backend is Codex. This hedges the 2nd-flake degrade/halt for Codex
# without weakening any recall/silent-drop protection (the extra attempt only
# RE-RUNS the same gated phase; it never relaxes a gate).
_CODEX_EXTRA_RETRY_MAX_ATTEMPTS = 3
_CODEX_EXTRA_RETRY_PHASES = (
    "recon",
    "breadth",
    "rescan",
    "inventory",
)


def _is_codex_extra_retry_phase(phase_name: str) -> bool:
    """True for the RECOVERING content phases eligible for the extended hinted
    retry budget (all backends): recon, breadth, rescan (incl. its per-contract
    sub-step), inventory, and inventory_chunk_*.

    These single-pass discovery phases under-cover on a fresh attempt (sonnet
    recon skipping module enumeration; codex single-subprocess leaving a rescan
    shard empty) and recover when re-prompted with the gate's exact missing-list
    hint. Phase-scoped on purpose — verify/report/skeptic/chain/depth and all
    other phases are excluded so their existing budgets stay UNCHANGED.
    """
    if not phase_name:
        return False
    if phase_name in _CODEX_EXTRA_RETRY_PHASES:
        return True
    return phase_name.startswith("inventory_chunk_")


def _record_recon_uncovered_in_scope_leftover(scratchpad, coverage_issues) -> int:
    """L1 recall-preservation: append recon-uncited >=10-file modules to
    scope_leftover.md, flagged as auto-recorded, so they are VISIBLE to the
    human reviewer and downstream depth instead of being silently dropped.

    Used when the L1 recon-coverage check is downgraded to non-blocking: L1
    recon (even opus-4.8) repeatedly leaves a few low-interest infra crates
    (tooling/tui/database/utils) uncited across retries and context compacts on
    the large recon, so retrying never fixes it and only burns attempts. Rather
    than halt/retry, we record the gap. Returns count recorded.
    """
    try:
        from pathlib import Path as _P
        p = _P(scratchpad) / "scope_leftover.md"
        existing = p.read_text(encoding="utf-8") if p.exists() else ""
        if "AUTO-RECORDED: recon-uncovered" in existing:
            return 0  # idempotent: already recorded this run
        block = [
            "",
            "## AUTO-RECORDED: recon-uncovered modules (review for depth coverage)",
            "These >=10-file modules were neither cited nor acknowledged by recon",
            "across its attempts. Recorded here (NOT silently dropped) so a human",
            "and the depth phase can review them:",
        ]
        for issue in coverage_issues:
            block.append(
                f"- ACKNOWLEDGED: {issue} -- auto-recorded (recon did not classify)"
            )
        p.write_text(existing.rstrip() + "\n" + "\n".join(block) + "\n", encoding="utf-8")
        return len(coverage_issues)
    except Exception as e:
        log.warning(f"[recon] could not auto-record uncovered modules: {e!r}")
        return 0


def _codex_max_attempts_for_phase(cli_backend: str | None, phase_name: str) -> int:
    """Return the max attempt budget for a phase.

    RECOVERING content phases (recon/breadth/inventory/inventory_chunk_*) get
    3 attempts on EVERY backend — not just Codex. These phases under-cover on a
    single pass (sonnet recon skipping the enumerate-every-module step; codex's
    single-subprocess under-fan-out) and the retry loop feeds the gate's exact
    missing-list back as a HINT, so the 3rd (hinted) attempt near-always
    recovers instead of halting a critical phase. Every other phase
    (verify/report/skeptic/chain/depth/…) keeps the unchanged 2-attempt
    retry-once-then-degrade default. The extra attempt only RE-RUNS the same
    gated phase with a hint — it never relaxes a gate, so it cannot drop a
    finding. (cli_backend retained for signature/call-site stability.)
    """
    if _is_codex_extra_retry_phase(phase_name):
        return _CODEX_EXTRA_RETRY_MAX_ATTEMPTS
    return 2


class _PtyStop(Exception):
    def __init__(self, rc: int):
        super().__init__(rc)
        self.rc = rc


class _PtyEarlyComplete(_PtyStop):
    """Clean-stop sentinel: the worker's own artifact is finished, correctly
    owned (PLAMEN_ARTIFACT / EXPECTED_OUTPUT markers match the assigned row),
    carries the PLAMEN_STATUS COMPLETE marker, and the worker has gone
    disk-idle for the early-complete grace window. Distinct from a containment
    stop so the caller can resolve the row via the normal status computation
    (status 'complete') rather than the 'containment' label. Path-independent
    defense-in-depth: even if transcript-path resolution ever fails again, a
    genuinely-finished, correctly-owned worker frees its slot instead of
    pinning to the full timeout. NEVER fires on an unfinished or mis-owned
    worker (missing marker => not complete; ownership mismatch => not
    complete)."""

    def __init__(self) -> None:
        super().__init__(0)


def _format_ai_model_summary(config: dict, active_phases: list[Phase], mode: str) -> str:
    """Return a concise runtime/model summary for the startup banner."""
    backend = (config.get("cli_backend") or "claude").strip().lower()
    backend_label = "Codex CLI" if backend == "codex" else "Claude Code"

    models: list[str] = []
    for phase in active_phases:
        try:
            model = phase_model(phase, mode, config)
        except Exception:
            model = (getattr(phase, "model", "") or "sonnet").strip()
        if model and model not in models:
            models.append(model)

    if not models:
        return backend_label
    if len(models) == 1:
        model_text = models[0]
    elif len(models) <= 3:
        model_text = ", ".join(models)
    else:
        model_text = ", ".join(models[:3]) + f" +{len(models) - 3} more"
    return f"{backend_label} / {model_text}"


_PARENT_CLAUDE_IDENTITY_ENV_KEYS = frozenset({
    "CLAUDECODE",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_EXECPATH",
    "CLAUDE_CODE_CHILD_SESSION",
    "AI_AGENT",
})

# Every env var with this prefix is parent-Claude-Code session/runtime identity
# and must NEVER leak into a fresh child `claude` worker. Enumerating the exact
# set is fragile -- new identity vars appear across Claude Code releases and a
# single missed one makes nested workers misbehave. Observed on v2.1.175:
# `CLAUDE_CODE_CHILD_SESSION=1` was inherited (not in the old explicit set), and
# nested PTY workers then wrote only a 1-line `ai-title` STUB transcript instead
# of the real end_turn-bearing conversation, so the driver's completion poll
# never saw end_turn and the phase hung to its full timeout. Stripping by prefix
# is future-proof against the next such variable.
_PARENT_CLAUDE_IDENTITY_ENV_PREFIXES = ("CLAUDE_CODE_",)


def _filtered_child_subprocess_environ(
    source_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return a subprocess env that cannot inherit a parent Claude session.

    Launching Plamen from inside `/plamen` (or from any Claude Code session, e.g.
    a Bash tool call) means the driver itself runs under Claude Code. Child
    `claude` subprocesses must start as fresh, standalone sessions; if they
    inherit Claude Code identity variables, Claude may detect a nested active
    session and either exit rc=0 without doing any phase work OR write only a
    1-line `ai-title` stub transcript (v2.1.175) -- both break the driver, which
    detects completion from the session's on-disk transcript.

    Strips both the explicit identity keys and ANYTHING under the
    `CLAUDE_CODE_` prefix so a newly-added identity variable cannot reintroduce
    the nested-session footgun.
    """
    env = dict(os.environ if source_env is None else source_env)
    for key in list(env.keys()):
        if key in _PARENT_CLAUDE_IDENTITY_ENV_KEYS or key.startswith(
            _PARENT_CLAUDE_IDENTITY_ENV_PREFIXES
        ):
            env.pop(key, None)
    return env


# Text-fallback regex: only triggers when an HTTP status or structured
# error prefix is present. Claude's own prose like "quota exhausted until
# Apr 23" won't match because no 429/status-code is adjacent.
#
# Covers both 429 (rate_limit_error) and 529 (overloaded_error). The text
# fallback path fires ONLY when the JSON envelope is unparseable (crash
# before envelope). In that mode we MUST still catch overload pauses, not
# just rate limits — Anthropic returns 529 during provider-wide overload
# and the retry semantics are the same.
_STRUCTURED_RATE_LIMIT_RE = re.compile(
    r"\b(?:"
    r"429\s*(?:too\s+many\s+requests|status|http|error|rate)"
    r"|529\s*(?:overloaded|status|http|error)"
    r"|status[_ ]?code[=:\s]+(?:429|529)"
    r"|api[_ ]?error[_ ]?status[=:\s\"]+(?:429|529)"
    r"|\"type\"\s*:\s*\"rate_limit_error\""
    r"|\"type\"\s*:\s*\"overloaded_error\""
    r"|\"error\"\s*:\s*\{\s*\"type\"\s*:\s*\"(?:rate_limit|overloaded)"
    r"|anthropic.*(?:429|529)"
    r")\b",
    re.IGNORECASE,
)


# ── Codex backend constants ───────────────────────────────────────────────

_CODEX_PREAMBLE_SINGLE_AGENT = """\
## Agent Spawning (IMPORTANT)

You are running inside `codex exec` as a SINGLE-TURN non-interactive subprocess.
This phase runs as a SINGLE AGENT — do NOT use `spawn_agent`. Execute all
analysis directly in this session.

When instructions say "spawn agent" or "use Task tool" or "use Agent tool":
- If the instruction is about a PARALLEL sub-agent within your phase: perform
  the analysis yourself sequentially instead. You ARE the agent.
- If the instruction is outside this assigned phase: STOP. Do not proceed.
  The driver owns all other subprocess boundaries.

When instructions contain `Task(subagent_type=..., prompt="...")` blocks, treat
the PROMPT CONTENT inside those blocks as YOUR OWN analysis instructions.
Execute the analysis described in the prompt text directly.

## Model Tier Mapping

- `model="opus"` → `gpt-5.5`
- `model="sonnet"` → `gpt-5.4`
- `model="haiku"` → `gpt-5.4-mini`
- `subagent_type="general-purpose"` → you (single agent, perform the work)
- `subagent_type="security-analyzer"` → you (single agent, perform the work)

## Network & MCP

Network access IS available (the driver runs under the bypass sandbox), so
WebSearch / web-fetch ARE usable. The bundled MCP tools (slither,
unified-vuln-db, solana-fender) are NOT loaded on Codex (the driver passes
`--ignore-user-config`). When instructions reference an MCP tool, use the
documented fallback: prefer WebSearch (e.g. `site:solodit.xyz <pattern>`) for
RAG / historical-precedent steps, and direct code analysis otherwise. Do not
silently skip RAG — use the web fallback so axis-4 scoring is not zeroed.
"""

_CODEX_PREAMBLE_MULTI_AGENT = """\
## Agent Spawning — MULTI-AGENT MODE (IMPORTANT)

You are running inside `codex exec` as the ORCHESTRATOR for this phase.
You MUST use `spawn_agent` to run analysis work in PARALLEL sub-agents.

### How to spawn sub-agents

When the methodology says `Task(subagent_type=..., prompt="...")` or
instructs you to "spawn agents" or "use the Task tool":

1. Use `spawn_agent` with the prompt content from the Task block.
   Each `spawn_agent` call creates a child agent that runs independently.
2. Spawn ALL independent agents in rapid succession (do not wait between
   spawns). Codex runs up to 6 agents concurrently.
3. After all agents are spawned, use `wait_agent` to block until each
   agent reaches its final status.
4. If an agent's output is needed before spawning a dependent agent,
   `wait_agent` on it first, then spawn the dependent one.

### Translation rules

| Claude Code | Codex equivalent |
|-------------|-----------------|
| `Task(subagent_type="general-purpose", model="sonnet", prompt="...")` | `spawn_agent(prompt="...")` |
| `Task(subagent_type="security-analyzer", prompt="...")` | `spawn_agent(prompt="...")` |
| `Task(subagent_type="depth-token-flow", prompt="...")` | `spawn_agent(prompt="...")` |
| Await agent results | `wait_agent(agent_id)` |
| Send follow-up to agent | `send_input(agent_id, message)` |

### Critical rules

- Sub-agents SHARE your working directory and scratchpad. Each agent
  MUST write to its own designated output file to avoid conflicts.
- Sub-agents inherit your sandbox policy and model. You cannot override
  the model per sub-agent — all children run your model.
- Do NOT spawn agents for SUBSEQUENT pipeline phases. Only spawn agents
  for work within YOUR assigned phase sections.
- If the methodology describes an ORCHESTRATOR SPLIT DIRECTIVE table
  with agent assignments, follow it: spawn one agent per assignment
  with the corresponding task scope.
- Maximum 6 concurrent agents. If the methodology calls for more,
  batch them: spawn 6, wait for completion, then spawn the next batch.
- If a sub-agent fails or times out, log the failure and continue with
  remaining agents. Do not halt the phase.

## Model Tier Mapping

- `model="opus"` → `gpt-5.5` (parent model — children inherit this)
- `model="sonnet"` → `gpt-5.4`
- `model="haiku"` → `gpt-5.4-mini`
- NOTE: All sub-agents run YOUR model. Model specifications in Task
  blocks (e.g., `model="sonnet"`) are informational only — they cannot
  be overridden per sub-agent in Codex.

## Network & MCP

Network access IS available (the driver runs under the bypass sandbox), so
WebSearch / web-fetch ARE usable. The bundled MCP tools (slither,
unified-vuln-db, solana-fender) are NOT loaded on Codex (the driver passes
`--ignore-user-config`). When instructions reference an MCP tool, use the
documented fallback: prefer WebSearch (e.g. `site:solodit.xyz <pattern>`) for
RAG / historical-precedent steps, and direct code analysis otherwise. Do not
silently skip RAG — use the web fallback so axis-4 scoring is not zeroed.
"""

# Re-export from plamen_types for local use. Phases where the LLM should
# use spawn_agent for parallel sub-agents instead of sequential execution.
_CODEX_MULTI_AGENT_PHASES = CODEX_MULTI_AGENT_PHASES

_CODEX_TOOL_POSIX = """\
## Tool Translation (Codex Runtime — POSIX)

When instructions reference Claude Code tools, use these Codex equivalents:
- "Read tool" / "Read file" → `shell` tool: `cat -n <file>`
- "Write tool" / "Write file" / create a new file →
    `shell` tool with heredoc:
    ```
    cat > path/to/file.md <<'PLAMEN_EOF'
    file content here
    PLAMEN_EOF
    ```
- "Edit tool" / modify existing file → `apply_patch` tool (unified diff)
- "Grep tool" → `shell` tool: `grep -rn 'pattern' path/` or `rg 'pattern'`
- "Glob tool" → `shell` tool: `find . -name '*.rs'` or `fd -e rs`
- "Bash tool" → `shell` tool
"""

_CODEX_TOOL_WINDOWS = """\
## Tool Translation (Codex Runtime — Windows / PowerShell)

When instructions reference Claude Code tools, use these Codex equivalents:
- "Read tool" / "Read file" → `shell` tool: `Get-Content <file>` or `type <file>`
- "Write tool" / "Write file" / create a new file →
    `shell` tool with PowerShell here-string:
    ```powershell
    @"
    file content here
    "@ | Out-File -FilePath "path/to/file.md" -Encoding utf8
    ```
    Or for short content: `Set-Content -Path "file.md" -Value "content"`
- "Edit tool" / modify existing file → `apply_patch` tool (unified diff)
- "Grep tool" → `shell` tool: `Select-String -Path "*.rs" -Pattern "pattern" -Recurse`
    or `rg 'pattern'` (if ripgrep installed)
- "Glob tool" → `shell` tool: `Get-ChildItem -Recurse -Filter "*.rs"`
- "Bash tool" → `shell` tool (PowerShell)

IMPORTANT: This is a Windows PowerShell environment. Do NOT use Unix commands
like `cat`, `grep`, `find`, `sed`, `awk`. Use PowerShell equivalents above.
"""


def _codex_tool_preamble(*, multi_agent: bool = False) -> str:
    """Return platform-appropriate Codex tool preamble with agent mode section.

    multi_agent=True selects the spawn_agent-based preamble for orchestrator
    phases (breadth, depth, rescan, recon). False selects the single-agent
    preamble for reducer/formatter phases.
    """
    tool_section = (
        _CODEX_TOOL_WINDOWS if sys.platform == "win32" else _CODEX_TOOL_POSIX
    )
    agent_section = (
        _CODEX_PREAMBLE_MULTI_AGENT if multi_agent
        else _CODEX_PREAMBLE_SINGLE_AGENT
    )
    return tool_section + "\n" + agent_section

_CODEX_PRICING: dict[str, tuple[float, float]] = {
    # model: (input_per_1M_tokens, output_per_1M_tokens)
    "gpt-5.5":      (5.00, 30.00),
    "gpt-5.4":      (2.50, 15.00),
    "gpt-5.4-mini": (0.75,  4.50),
    "gpt-5.4-nano": (0.20,  1.25),
    "o3":           (2.00,  8.00),
    "o4-mini":      (1.10,  4.40),
    "gpt-4.1":      (2.00,  8.00),
    "gpt-4.1-mini": (0.40,  1.60),
    "gpt-4.1-nano": (0.10,  0.40),
}

_CODEX_RATE_LIMIT_RE = re.compile(
    r"(?:"
    r"rate_limit_exceeded"
    r"|rate_limit_error"
    r"|usage_limit_reached"
    r"|insufficient_quota"
    r"|billing_hard_limit_reached"
    r"|tokens_usage_based"
    r"|Too Many Requests"
    r"|\"type\"\s*:\s*\"rate_limit"
    r"|\"type\"\s*:\s*\"usage_limit"
    r"|\"code\"\s*:\s*\"rate_limit"
    r"|status[=:\s]+429"
    r"|HTTP\s+429"
    r"|Error:\s*429"
    r"|selected\s+model\s+is\s+at\s+capacity"
    r"|model\s+is\s+at\s+capacity"
    # Codex/ChatGPT usage-cap errors are NATURAL LANGUAGE, not structured
    # tokens: e.g. {"type":"error","message":"You've hit your usage limit.
    # Visit https://chatgpt.com/codex/settings/usage to purchase more credits
    # or try again at 5:46 PM."}. These MUST be treated as a rate-limit pause
    # (auto-wait + preserve state), NOT a phase failure -> retry -> halt.
    r"|purchase\s+more\s+credits"
    r"|chatgpt\.com/codex/settings/usage"
    r"|(?:reached|hit)\s+your\s+(?:usage|rate|monthly)\s+limit"
    r")",
    re.IGNORECASE,
)


def _codex_depth_artifact_checklist(pipeline: str, mode: str) -> str:
    """Return a mandatory artifact checklist for the Codex depth phase.

    gpt-5.5 reliably spawns 1-2 sub-agents from the generic multi-agent
    preamble but misses the full set of Thorough-only sub-steps
    (confidence scoring, DST, perturbation, skill checklist). This
    checklist makes the complete spawn plan explicit and unmissable.
    """
    is_thorough = mode == "thorough"
    if pipeline == "l1":
        lines = [
            "## MANDATORY DEPTH ARTIFACT CHECKLIST (Codex — HARD GATE)",
            "",
            "The post-phase gate WILL FAIL unless ALL artifacts below exist",
            "and are ≥200 bytes. You must spawn_agent for each group.",
            "",
            "### Batch 1: Core depth agents (spawn ALL 5 in parallel)",
            "",
            "| # | spawn_agent prompt scope | Output file | Required |",
            "|---|-------------------------|-------------|----------|",
            "| 1 | depth-consensus-invariant (consensus safety, fork choice, BLS, validator lifecycle) | depth_consensus_invariant_findings.md | YES |",
            "| 2 | depth-network-surface (p2p DoS, mempool, RPC, eclipse) | depth_network_surface_findings.md | YES |",
            "| 3 | depth-state-trace (state sync, pruning, execution hardening) | depth_state_trace_findings.md | YES |",
            "| 4 | depth-external (dependency audit, cross-environment drift) | depth_external_findings.md | YES |",
            "| 5 | depth-edge-case (boundary conditions, zero-state) | depth_edge_case_findings.md | YES |",
            "",
            "After spawning all 5, use wait_agent on each.",
            "",
            "### CRITICAL: Post-wait output verification",
            "",
            "After EACH wait_agent completes, verify the output file exists",
            "and is ≥200 bytes. Codex agents can report DONE with 0-byte",
            "output (thread limit, content filter, or silent failure). For",
            "each 0-byte or missing file:",
            "1. Close the completed (failed) agent with close_agent",
            "2. Spawn a NEW agent for that role with the same prompt",
            "3. Wait and re-verify",
            "Do NOT proceed to Batch 2 until all Batch 1 files are ≥200 bytes.",
        ]
        if is_thorough:
            lines.extend([
                "",
                "### Batch 2: Thorough-only sub-steps (after Batch 1 completes)",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 6 | Confidence scoring (4-axis per phase4-confidence-scoring.md) | confidence_scores.md | YES |",
                "| 7 | Design Stress Testing (design limits, parameter extremes) | design_stress_findings.md | YES |",
                "",
                "### Batch 3: After confidence scores exist",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 8 | DA iteration 2 (Devil's Advocate on UNCERTAIN findings) | depth_iter2_*_findings.md | IF uncertain Medium+ |",
                "",
                "### Batch 4: Final parallel pair",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 9 | Perturbation (DIRECTION_FLIP, TIMING_SHIFT, ACTOR_SWAP) | perturbation_findings.md | YES |",
                "| 10 | Skill Execution Checklist (verify skill steps executed) | skill_execution_gaps.md | YES |",
                "",
                "### Execution sequence",
                "",
                "```",
                "Batch 1: spawn agents 1-5 in parallel → wait_agent all",
                "Batch 2: spawn agents 6-7 in parallel → wait_agent all",
                "Batch 3: if uncertain Medium+ in confidence_scores.md → spawn agent 8 → wait_agent",
                "Batch 4: spawn agents 9-10 in parallel → wait_agent all",
                "Finally: write never_cut_checkpoint.md + depth_exit.md",
                "```",
                "",
                "FAILURE MODE: If you return after Batch 1 without spawning",
                "Batches 2-4, the gate rejects your output and forces a retry.",
                "Complete ALL batches before returning.",
            ])
        elif mode == "core":
            lines.extend([
                "",
                "### Batch 2: Core confidence scoring (after Batch 1 completes)",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 6 | Confidence scoring (2-axis: Evidence x 0.5 + Analysis Quality x 0.5) | confidence_scores.md | YES |",
                "",
                "```",
                "Batch 1: spawn agents 1-5 in parallel → wait_agent all",
                "Batch 2: spawn agent 6 → wait_agent",
                "Finally: write never_cut_checkpoint.md + depth_exit.md",
                "```",
            ])
        else:
            # Light mode: depth agents only, no confidence scoring
            lines.extend([
                "",
                "Light mode: only Batch 1 is required. Write",
                "never_cut_checkpoint.md + depth_exit.md after all 5 complete.",
            ])
    else:
        # SC pipeline
        lines = [
            "## MANDATORY DEPTH ARTIFACT CHECKLIST (Codex — HARD GATE)",
            "",
            "The post-phase gate WILL FAIL unless ALL artifacts below exist",
            "and are ≥200 bytes. You must spawn_agent for each group.",
            "",
            "### Batch 1: Core depth agents (spawn ALL 4 in parallel)",
            "",
            "| # | spawn_agent prompt scope | Output file | Required |",
            "|---|-------------------------|-------------|----------|",
            "| 1 | depth-token-flow (token entry/exit, donation attacks) | depth_token_flow_findings.md | YES |",
            "| 2 | depth-state-trace (cross-function state mutation) | depth_state_trace_findings.md | YES |",
            "| 3 | depth-edge-case (zero-state, dust, boundary) | depth_edge_case_findings.md | YES |",
            "| 4 | depth-external (external calls, MEV, cross-chain) | depth_external_findings.md | YES |",
            "",
            "After spawning all 4, use wait_agent on each.",
            "",
            "### CRITICAL: Post-wait output verification",
            "",
            "After EACH wait_agent completes, verify the output file exists",
            "and is ≥200 bytes. Codex agents can report DONE with 0-byte",
            "output (thread limit, content filter, or silent failure). For",
            "each 0-byte or missing file:",
            "1. Close the completed (failed) agent with close_agent",
            "2. Spawn a NEW agent for that role with the same prompt",
            "3. Wait and re-verify",
            "Do NOT proceed to Batch 2 until all Batch 1 files are ≥200 bytes.",
        ]
        if is_thorough:
            lines.extend([
                "",
                "### Batch 2: Thorough-only sub-steps (after Batch 1 completes)",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 5 | Confidence scoring (4-axis per phase4-confidence-scoring.md) | confidence_scores.md | YES |",
                "| 6 | Design Stress Testing (design limits, parameter extremes) | design_stress_findings.md | YES |",
                "",
                "### Batch 3: After confidence scores exist",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 7 | DA iteration 2 (Devil's Advocate on UNCERTAIN findings) | depth_iter2_*_findings.md | IF uncertain Medium+ |",
                "",
                "### Batch 4: Final parallel pair",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 8 | Perturbation (DIRECTION_FLIP, TIMING_SHIFT, ACTOR_SWAP) | perturbation_findings.md | YES |",
                "| 9 | Skill Execution Checklist (verify skill steps executed) | skill_execution_gaps.md | YES |",
                "",
                "### Execution sequence",
                "",
                "```",
                "Batch 1: spawn agents 1-4 in parallel → wait_agent all",
                "Batch 2: spawn agents 5-6 in parallel → wait_agent all",
                "Batch 3: if uncertain Medium+ in confidence_scores.md → spawn agent 7 → wait_agent",
                "Batch 4: spawn agents 8-9 in parallel → wait_agent all",
                "Finally: write never_cut_checkpoint.md + depth_exit.md",
                "```",
                "",
                "FAILURE MODE: If you return after Batch 1 without spawning",
                "Batches 2-4, the gate rejects your output and forces a retry.",
                "Complete ALL batches before returning.",
            ])
        elif mode in ("core", ""):
            # SC Core mode: 4 depth agents + 4 scanners + validation sweep +
            # confidence scoring (2-axis) per AUDIT MODES table.
            lines.extend([
                "",
                "### Batch 2: Core sub-steps (after Batch 1 completes)",
                "",
                "| # | spawn_agent prompt scope | Output file | Required |",
                "|---|-------------------------|-------------|----------|",
                "| 5 | Blind Spot Scanner A (systematic checks) | blind_spot_a_findings.md | YES |",
                "| 6 | Blind Spot Scanner B (systematic checks) | blind_spot_b_findings.md | YES |",
                "| 7 | Blind Spot Scanner C (systematic checks) | blind_spot_c_findings.md | YES |",
                "| 8 | Validation Sweep (cross-agent consistency) | validation_sweep_findings.md | YES |",
                "| 9 | Confidence scoring (2-axis: Evidence x 0.5 + Analysis Quality x 0.5) | confidence_scores.md | YES |",
                "",
                "```",
                "Batch 1: spawn agents 1-4 in parallel → wait_agent all",
                "Batch 2: spawn agents 5-9 in parallel → wait_agent all",
                "Finally: write never_cut_checkpoint.md + depth_exit.md",
                "```",
            ])
    lines.append("")
    return "\n".join(lines)


def _codex_mandatory_secondary_names(
    phase_name: str, pipeline: str, mode: str, scratchpad: Optional[Path]
) -> list[str]:
    """Return a phase's mandatory pre-created SECONDARY artifact filenames.

    Scalar-arg sibling of `_codex_secondary_artifact_targets` (which needs a
    Phase object) so prompt-construction code can call it. Single source of
    truth for both (a) the pre-created-fill directive and (b) the Codex depth
    Expected-Output-Contract widening. Derives names from the same canonical
    sources (`sc_never_cut_groups` / `l1_never_cut_groups`,
    `_required_niche_worker_jobs`, `_recon_worker_jobs`); for `[A|B]`
    alternations only the first representative is returned.
    """
    pipeline = (pipeline or "sc").lower()
    mode = (mode or "core").lower()
    names: list[str] = []
    if phase_name == "depth":
        try:
            groups = (
                l1_never_cut_groups(mode)
                if pipeline == "l1"
                else sc_never_cut_groups(mode)
            )
        except Exception:
            groups = []
        for group in groups:
            if group:
                names.append(group[0])
        if scratchpad is not None:
            try:
                for job in _required_niche_worker_jobs(scratchpad):
                    out = job.get("output")
                    if out:
                        names.append(out)
            except Exception:
                pass
    elif phase_name == "recon":
        try:
            for job in _recon_worker_jobs({"mode": mode, "pipeline": pipeline}):
                out = job.get("output")
                if out:
                    names.append(out)
        except Exception:
            pass
    seen: set = set()
    return [n for n in names if n and not (n in seen or seen.add(n))]


def _codex_widen_depth_output_contract(
    prompt_text: str, secondary_names: list[str]
) -> str:
    """Codex-only: add the mandatory secondary artifacts to the depth phase's
    EXPECTED OUTPUT FILES (HARD CONTRACT) section.

    The base depth prompt's `OUTPUT ALLOWLIST (HARD)` and `PHASE ISOLATION
    CONTRACT` both derive their allowed/writable set from "this phase's Expected
    Output Contract" — which lists only `depth_*_findings.md` (the core glob from
    `phase.expected_artifacts`). On Codex (single-turn, full base prompt) the
    model reads that allowlist literally, treats the never-cut scanners /
    validation / confidence / niche artifacts as "an output file outside this
    allowlist", and refuses to write them — failing the never-cut gate even
    though it precreated them and the checklist asked for them. By listing the
    secondaries INSIDE the Expected Output Contract, both downstream HARD
    references include them and the contradiction is gone.

    Claude PTY never reaches this: its depth prompt is replaced by the
    worker-pool stub (one allowlisted worker per artifact). This function runs
    only inside `_translate_prompt_for_codex` (`if backend == "codex"`), so it
    cannot affect a Claude run. Skips gracefully (returns input unchanged) if
    the anchor header is absent or there are no secondaries — never corrupts.
    """
    if not secondary_names:
        return prompt_text
    header = (
        "## EXPECTED OUTPUT FILES (HARD CONTRACT -- GATE WILL FAIL IF VIOLATED)"
    )
    if header not in prompt_text:
        return prompt_text  # base prompt shape changed — skip, do not corrupt
    block_lines = [
        "",
        "### Mandatory secondary outputs (part of THIS contract and your allowlist)",
        "",
        "The artifacts below are PART of this phase's Expected Output Contract "
        "and your OUTPUT ALLOWLIST — NOT 'outside the allowlist'. They are "
        "pre-created EMPTY on disk (apply_patch can modify them; they already "
        "exist). You MUST fill EACH with real first-pass content this phase. The "
        "post-phase never-cut gate FAILS the phase if any is missing or empty, "
        "so these are mandatory, not optional:",
        "",
    ]
    block_lines += [f"- `{n}`" for n in secondary_names]
    block = "\n".join(block_lines) + "\n"
    return prompt_text.replace(header, header + "\n" + block, 1)


def _codex_precreated_fill_directive(
    phase_name: str, pipeline: str, mode: str, scratchpad: Optional[Path]
) -> str:
    """Codex-only directive naming the pre-created secondary files to fill.

    `_precreate_codex_artifacts` seeds empty files for the phase's mandatory
    secondary artifacts (never-cut scanners/validation/confidence, triggered
    niches, recon shards) because Codex's apply_patch cannot create new files.
    This tells the model those EMPTY files already exist on disk and MUST be
    filled with real content this phase — an empty seed still fails the
    never-cut/stub gate, so leaving them blank degrades the phase.

    Derives the same filenames as `_codex_secondary_artifact_targets` from the
    existing sources so the prompt and the seeding stay in sync.
    """
    deduped = _codex_mandatory_secondary_names(
        phase_name, pipeline, mode, scratchpad
    )
    if not deduped:
        return ""

    lines = [
        "## PRE-CREATED SECONDARY ARTIFACTS (Codex — MUST FILL)",
        "",
        "The following files have already been created EMPTY on disk so your",
        "apply_patch tool has valid targets (apply_patch cannot create new",
        "files). You MUST fill EACH with real first-pass content this phase.",
        "An empty file still FAILS the mandatory artifact gate, so leaving any",
        "of these blank degrades the phase:",
        "",
    ]
    lines += [f"- {n}" for n in deduped]
    lines.append("")
    return "\n".join(lines)


def _translate_prompt_for_codex(prompt_text: str, *,
                               phase_name: str = "",
                               pipeline: str = "",
                               mode: str = "",
                               scratchpad: Optional[Path] = None) -> str:
    """Translate Claude-specific prompt content for Codex runtime.

    Path translation: only rewrite ~/.claude/ → ~/.codex/plamen/ when the
    target directory actually exists on disk.  Otherwise keep ~/.claude/ as-is
    — the Codex sandbox can read the entire filesystem, so the original paths
    resolve fine.

    Also strips Claude-specific references that create noise or contradiction
    in a Codex subprocess (MCP timeout mentions, AskUserQuestion references,
    "Task tool" phrasing).

    Multi-agent phases (breadth, depth, rescan, recon) get the spawn_agent
    preamble instead of the single-agent preamble, enabling parallel sub-agent
    execution within the phase.

    For the depth phase, injects a mandatory artifact checklist with an
    explicit spawn plan so gpt-5.5 produces all required artifacts on
    attempt 1 (v2.6.2).
    """
    codex_home = Path.home() / ".codex" / "plamen"
    if not codex_home.is_dir():
        raise RuntimeError(
            f"Codex backend is active but {codex_home} does not exist. "
            f"Create it as a symlink to your Plamen install "
            f"(e.g., mklink /D \"{codex_home}\" \"{Path.home() / '.claude'}\")"
        )
    # Rewrite every ~/.claude reference to the Codex methodology mirror, covering
    # ALL forms the prompts / methodology files can carry, on every platform:
    #   ~/.claude/ , $HOME/.claude/ , <expanded-home>/.claude(/) , and the
    #   no-trailing-slash variants (sys.path.insert('~/.claude'), --add-dir ~/.claude).
    translated = prompt_text.replace("~/.claude/", "~/.codex/plamen/")
    translated = translated.replace("$HOME/.claude/", "~/.codex/plamen/")
    home_fwd = str(Path.home()).replace("\\", "/")
    translated = translated.replace(f"{home_fwd}/.claude/", "~/.codex/plamen/")
    if "\\" in str(Path.home()):
        translated = translated.replace(
            f"{str(Path.home())}\\.claude\\", "~/.codex/plamen/"
        )
    translated = translated.replace("$HOME/.claude", "~/.codex/plamen")
    translated = re.sub(r"~/\.claude(?![\w./])", "~/.codex/plamen", translated)

    translated = translated.replace("claude -p subprocess", "codex exec subprocess")
    translated = translated.replace("Claude Code's MCP timeout is 300s", "MCP tools are unavailable in this runtime")
    translated = translated.replace(
        "Claude Code's tool timeout is set to 300s (5 min) via MCP_TOOL_TIMEOUT in settings.json to accommodate ChromaDB cold start.",
        "MCP tools are unavailable in this runtime.",
    )
    translated = re.sub(
        r"do NOT call AskUserQuestion\b",
        "do NOT ask the user questions",
        translated,
    )
    is_multi = phase_name in _CODEX_MULTI_AGENT_PHASES
    if is_multi:
        # Multi-agent phases: rewrite Task tool references to spawn_agent.
        # Keep Task() block structure intact — the preamble tells the model
        # how to translate them to spawn_agent calls.
        translated = re.sub(
            r"\buse the Task tool\b",
            "use spawn_agent",
            translated,
            flags=re.IGNORECASE,
        )
    else:
        # Single-agent phases: tell model to execute directly.
        translated = re.sub(
            r"\buse the Task tool\b",
            "execute the analysis directly",
            translated,
            flags=re.IGNORECASE,
        )

    preamble = _codex_tool_preamble(multi_agent=is_multi)

    # v2.6.2: inject mandatory artifact checklist for depth phase.
    # gpt-5.5 reliably spawns the core depth agents but misses Thorough
    # sub-steps (confidence scoring, DST, perturbation, skill checklist)
    # without an explicit spawn plan.
    depth_checklist = ""
    if phase_name == "depth" and is_multi:
        depth_checklist = _codex_depth_artifact_checklist(
            pipeline or "sc", mode or "core"
        ) + "\n"

    # Codex-only: name the pre-created secondary artifact files (seeded by
    # _precreate_codex_artifacts) the model must fill this phase.
    fill_directive = _codex_precreated_fill_directive(
        phase_name, pipeline or "sc", mode or "core", scratchpad
    )
    if fill_directive:
        fill_directive += "\n"

    # Codex-only: the base depth prompt's OUTPUT ALLOWLIST (HARD) and PHASE
    # ISOLATION CONTRACT derive their allowed set from the Expected Output
    # Contract, which lists only the depth_*_findings.md core glob. The model
    # then refuses the never-cut secondaries (blind-spot scanners, validation
    # sweep, confidence, niche) as "outside the allowlist". List those inside
    # the Expected Output Contract so the allowlist includes them. Depth only;
    # core depth_* reps are already covered by the glob, so drop them here.
    if phase_name == "depth":
        _secondary = [
            n
            for n in _codex_mandatory_secondary_names(
                phase_name, pipeline or "sc", mode or "core", scratchpad
            )
            if not (n.startswith("depth_") and n.endswith("_findings.md"))
        ]
        translated = _codex_widen_depth_output_contract(translated, _secondary)

    return preamble + "\n" + depth_checklist + fill_directive + translated


_CODEX_CONTEXT_LIMITS: dict[str, int] = {
    # Conservative token limits per model (chars ÷ 4 ≈ tokens).
    # Codex hard-errors on exceed (not silent truncation).
    # GPT-5.5: 1M context window (opus-tier, $5/$30 per 1M tokens)
    "gpt-5.5": 800_000,
    # GPT-5.4: 1M context (previous frontier, $2.50/$15)
    "gpt-5.4": 800_000,
    # GPT-5.4-mini: 400K context (sonnet-tier, $0.75/$4.50)
    "gpt-5.4-mini": 320_000,
    # GPT-5.4-nano: 400K context (haiku-tier, $0.20/$1.25)
    "gpt-5.4-nano": 320_000,
    # Legacy (deprecated Feb 2026, API sunset Oct 2026)
    "o3": 200_000,
    "o4-mini": 200_000,
    "gpt-4.1": 1_000_000,
    "gpt-4.1-mini": 1_000_000,
    "gpt-4.1-nano": 1_000_000,
}


def _codex_prompt_fits(prompt: str, model: str) -> bool:
    """Check if prompt likely fits the model's context window.

    Returns True if safe, False if prompt is dangerously large.
    Uses ~4 chars/token heuristic with a 20% safety margin for
    tool outputs and response tokens.
    """
    limit = _CODEX_CONTEXT_LIMITS.get(model, 272_000)
    # Reserve 20% for response + tool outputs
    effective_limit = int(limit * 0.80)
    estimated_tokens = len(prompt) // 4
    return estimated_tokens <= effective_limit


def _codex_auth_available() -> bool:
    """Check if Codex authentication is available (OAuth or API key).

    Without auth, `codex exec` will attempt interactive browser login,
    hanging indefinitely in a subprocess with no TTY.
    """
    if os.environ.get("CODEX_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return True
    auth_path = Path.home() / ".codex" / "auth.json"
    return auth_path.exists()


def _backend_available(backend: str) -> bool:
    """Check whether *backend* is installed and authenticated.

    Reuses the existing Codex availability gate (binary + OAuth/API-key
    auth). Claude is the driver's unconditional default backend -- its own
    spawn path already surfaces a missing binary/auth failure directly, so
    it has no separate pre-check here (matches every other `cli_backend`
    read site, which treats "claude" as always selectable).
    """
    backend = (backend or "").strip().lower()
    if backend == "codex":
        return bool(CODEX_BIN) and _codex_auth_available()
    return True


def _effective_backend(config: dict, phase: "Phase") -> str:
    """Resolve the CLI backend to use for *phase*.

    Cross-vendor override (Wave-4 M1): `config["phase_backend_overrides"]`
    is an optional `{phase_name: backend}` map. When it names a backend for
    *phase* that differs from `config["cli_backend"]` AND that backend is
    actually available/authenticated, use it. Otherwise (no override, same
    backend, or override backend unavailable) fall back to
    `config["cli_backend"]` -- NEVER raises and NEVER fails the phase.

    With no `phase_backend_overrides` key (or none for this phase's name),
    this returns exactly `config.get("cli_backend", "claude")` -- the
    pre-existing default-path behavior is unchanged.
    """
    default_backend = (config.get("cli_backend") or "claude").strip().lower()
    overrides = config.get("phase_backend_overrides") or {}
    phase_name = getattr(phase, "name", phase)
    override = overrides.get(phase_name) if isinstance(overrides, dict) else None
    if not override:
        return default_backend
    override = str(override).strip().lower()
    if override == default_backend:
        return default_backend
    if _backend_available(override):
        return override
    log.warning(
        f"[{phase_name}] phase_backend_overrides requested backend "
        f"{override!r} but it is not available/authenticated -- falling "
        f"back to the configured cli_backend {default_backend!r}."
    )
    return default_backend


def _codex_auth_is_chatgpt() -> bool:
    """Return True if Codex is authenticated via ChatGPT OAuth (not API key).

    ChatGPT-auth accounts cannot use `--model` flag — the server rejects ALL
    explicit model names with "not supported when using Codex with a ChatGPT
    account". The account's subscription tier determines the default model
    automatically (Pro → GPT-5, Plus → GPT-4.1, etc).
    """
    if os.environ.get("CODEX_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return False
    auth_path = Path.home() / ".codex" / "auth.json"
    if not auth_path.exists():
        return False
    try:
        data = json.loads(auth_path.read_text(encoding="utf-8"))
        return data.get("auth_mode") == "chatgpt"
    except Exception:
        return False


def _codex_robustness_overrides() -> list[str]:
    """Inline `-c` config overrides applied to every `codex exec` invocation.

    Both codex command builders pass `--ignore-user-config` (so config.toml is
    NOT read live); these research-backed settings must therefore be inline:

    - `model_auto_compact_token_limit=220000` — force early history compaction
      instead of the bogus "context window exceeded (~N tokens)" PERMANENT
      failure caused by the token-counter corruption bug (openai/codex #16068,
      #19409). NEVER set `model_context_window` (the trigger for that bug).
    - `service_tier="flex"` — a built-in tier value so `spawn_agent` can resolve
      the child model. Without a valid tier, sub-agent spawning fails with
      "could not resolve the child model for service tier validation" (#27297),
      which degrades the fan-out-heavy recon phase. Only `flex`/`fast` are valid
      on older parsers; `default`/`priority` are rejected.

    Uses the same proven `-c key=value` form already used for
    `model_reasoning_effort`. If a future codex version rejects either key it
    surfaces as a config error; the context-exceeded handler now degrades the
    phase and continues rather than perma-failing the run.
    """
    return [
        "-c", "model_auto_compact_token_limit=220000",
        "-c", 'service_tier="flex"',
    ]


def _build_codex_cmd(effective_model: str, *, needs_mcp: bool = False,
                     output_last_message: str = "",
                     writable_dirs: list[str] | None = None) -> list[str]:
    """Build the codex exec command array for a phase subprocess.

    Uses --dangerously-bypass-approvals-and-sandbox to skip Codex's built-in
    approval prompts and sandbox restrictions. Without this flag, `codex exec`
    auto-rejects all tool calls (apply_patch, shell) with "rejected by user
    approval settings" — making zero artifact writes possible. This is
    Codex's equivalent of Claude Code's --dangerously-skip-permissions.

    The Plamen driver already controls the subprocess lifecycle, timeout, and
    output validation — the external orchestration IS the sandbox.

    --skip-git-repo-check: audit targets may not be git repos (extracted archives).
    --output-last-message: writes final agent message to a file for reliable extraction.
    --add-dir: retained for documentation; harmless with bypass active.

    ChatGPT-auth accounts cannot use --model flag at all — the server rejects
    every explicit model name with "not supported when using Codex with a
    ChatGPT account". The subscription tier (Free/Plus/Pro) determines the
    default model automatically. Only API-key auth supports --model.
    """
    cmd = [CODEX_BIN, "exec"]
    # ChatGPT-auth accounts may reject --model depending on plan/token state.
    # Always try with --model first; the caller retries without it on failure
    # (see _detect_codex_model_rejection).
    cmd.extend(["--model", effective_model])
    cmd.extend([
        "--json",
        "--ephemeral",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
    ])
    cmd.extend(_codex_robustness_overrides())
    if writable_dirs:
        for d in writable_dirs:
            cmd.extend(["--add-dir", d])
    if output_last_message:
        cmd.extend(["--output-last-message", output_last_message])
    if effective_model in ("o3", "o4-mini"):
        cmd.extend(["-c", 'model_reasoning_effort="high"'])
    cmd.append("-")  # read prompt from stdin
    return cmd


def _detect_codex_model_rejection(log_path: Path) -> bool:
    """Detect if Codex rejected the --model flag (ChatGPT account restriction).

    ChatGPT-auth accounts may reject explicit --model depending on plan state
    or token freshness. When detected, the driver retries without --model,
    letting the subscription tier determine the default model automatically.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "not supported when using Codex with a ChatGPT account" in text


def _detect_codex_model_not_available(log_path: Path) -> bool:
    """Detect if Codex failed because the requested model isn't on the user's plan.

    API-key accounts that lack access to a specific model (e.g., gpt-5.5
    requires a higher-tier plan) get a 404 "model not found" or 403 "access
    denied" that is distinct from a credential failure. This must be checked
    BEFORE _detect_codex_auth_error, which would otherwise misclassify it as
    a permanent auth failure instead of a recoverable model-downgrade scenario.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(
        r"(?:model.*(?:not\s+found|does\s+not\s+exist|not\s+available)"
        r"|(?:not\s+found|does\s+not\s+exist).*model"
        r"|access.*denied.*model|model.*access.*denied"
        r"|you\s+do\s+not\s+have\s+access.*model"
        r"|insufficient.*(?:plan|tier|quota).*model"
        r"|status[=:\s]+404.*model|model.*status[=:\s]+404"
        r"|The\s+model\s+`[^`]+`\s+does\s+not\s+exist)",
        text, re.IGNORECASE,
    ))


def _detect_codex_model_capacity(log_path: Path) -> bool:
    """Detect transient Codex/OpenAI selected-model capacity failures."""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(
        r"(?:selected\s+model\s+is\s+at\s+capacity|model\s+is\s+at\s+capacity)",
        text,
        re.IGNORECASE,
    ))


def _codex_next_fallback_model(current_model: str, attempted: list[str] | None = None) -> Optional[str]:
    """Return the next configured Codex fallback model after a capacity miss."""
    attempted_set = {m for m in (attempted or []) if m}
    attempted_set.add(current_model)
    for candidate in _CODEX_FALLBACK_MODEL_ORDER:
        if candidate and candidate not in attempted_set:
            return candidate
    return None


def _build_codex_cmd_no_model(*, needs_mcp: bool = False,
                              output_last_message: str = "",
                              writable_dirs: list[str] | None = None) -> list[str]:
    """Build codex exec command WITHOUT --model flag (ChatGPT-auth fallback).

    Uses --dangerously-bypass-approvals-and-sandbox for same reason as
    _build_codex_cmd — without it, all tool calls are auto-rejected.
    """
    cmd = [
        CODEX_BIN, "exec",
        "--json",
        "--ephemeral",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
    ]
    cmd.extend(_codex_robustness_overrides())
    if writable_dirs:
        for d in writable_dirs:
            cmd.extend(["--add-dir", d])
    if output_last_message:
        cmd.extend(["--output-last-message", output_last_message])
    cmd.append("-")
    return cmd


def _detect_codex_cli_crash(log_path: Path) -> bool:
    """Detect if Codex subprocess crashed due to invalid CLI arguments.

    CLI argument errors (e.g., --disallowedTools not recognized) are permanent
    failures — retrying with identical args is pointless. The driver should
    surface the error instead of burning retry budget.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(
        r"(?:unexpected argument|unrecognized option|Usage: codex exec"
        r"|error:.*found\b.*tip:)",
        text, re.IGNORECASE,
    ))


def _detect_codex_auth_error(log_path: Path) -> bool:
    """Check if a Codex subprocess failed due to authentication issues.

    Auth errors (401/403, token expiry) should NOT trigger rate-limit pause
    logic — they need re-authentication, not backoff.

    IMPORTANT: Call _detect_codex_model_not_available BEFORE this function.
    Model-not-available (404/403 for missing model access) would otherwise
    match the 401/403 patterns here and cause a permanent halt instead of
    a graceful model downgrade.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # Exclude model/capacity/rate-limit patterns from auth classification.
    # Codex JSON logs include the full audit prompt and model transcript, so
    # words like "Unauthorized" commonly appear as vulnerability text. Auth
    # matching must be anchored to actual provider/CLI error fields.
    if _detect_codex_model_not_available(log_path) or _CODEX_RATE_LIMIT_RE.search(text):
        return False
    return bool(re.search(
        r"(?:status[=:\s]+401|HTTP\s+401"
        r"|(?:\"(?:type|code|message)\"\s*:\s*\"[^\"]*(?:unauthorized|invalid_api_key|authentication|auth)[^\"]*\")"
        r"|(?:error|api error|provider error|codex error)[^\r\n]{0,160}(?:unauthorized|invalid_api_key|token[^\r\n]{0,40}expired|authentication[^\r\n]{0,40}failed|auth[^\r\n]{0,40}error))",
        text, re.IGNORECASE,
    ))


def _detect_codex_rate_limit(log_path: Path, returncode: int) -> bool:
    """Check if a Codex subprocess failed due to rate limiting.

    Checks JSONL output regardless of returncode because Codex may report
    usage_limit_reached in the event stream with rc=0 (graceful stop).

    Returns False for auth errors (401) — those need re-auth, not backoff.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # Auth errors are NOT rate limits — discriminate early
    if _detect_codex_auth_error(log_path):
        return False
    if returncode == 0:
        # On success, only check for plan-cap exhaustion (not transient 429s).
        # Codex can graceful-stop (rc=0) with the usage cap in-stream, and that
        # message is NATURAL LANGUAGE — so match the plan-cap phrases too, not
        # just the structured tokens.
        return bool(re.search(
            r"usage_limit_reached|billing_hard_limit_reached|insufficient_quota"
            r"|purchase\s+more\s+credits"
            r"|chatgpt\.com/codex/settings/usage"
            r"|(?:reached|hit)\s+your\s+(?:usage|rate|monthly)\s+limit",
            text, re.IGNORECASE))
    return bool(_CODEX_RATE_LIMIT_RE.search(text))


def _detect_codex_context_exceeded(log_path: Path) -> bool:
    """Check if a Codex subprocess failed because prompt exceeded context window.

    Codex hard-errors (not truncates) when input exceeds the model's context.
    This needs different handling than rate limits: shrink prompt or use bigger model.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(
        r"exceeds.*context.window|context_length_exceeded|max_tokens_exceeded"
        r"|maximum context length",
        text, re.IGNORECASE,
    ))


def _detect_codex_content_filter(log_path: Path) -> bool:
    """Detect if a Codex subprocess was killed by OpenAI's content safety filter.

    The safety filter flags security audit prompts as "cybersecurity risk" and
    terminates the turn before any subagent work can proceed.  The error is
    nondeterministic — a retry with a slightly different prompt shape (e.g. the
    retry hint prepended) often passes.  Treated as transient: the driver gets
    one bonus retry that does NOT consume the normal retry budget.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(
        r"flagged for (?:possible )?cybersecurity risk"
        r"|Trusted Access for Cyber",
        text, re.IGNORECASE,
    ))


def _codex_secondary_artifact_targets(
    phase: "Phase", scratchpad: Path, config: Optional[dict] = None
) -> list[str]:
    """Return the phase's mandatory first-pass SECONDARY artifact filenames.

    `phase.expected_artifacts` only declares the glob of CORE outputs (e.g.
    `depth_*_findings.md` → the 4/5 core depth findings). The never-cut gate
    additionally requires the blind-spot scanners, validation sweep, confidence
    scores, and triggered niche outputs (and recon's worker shards). Codex's
    apply_patch cannot create new files, so unless those are pre-seeded the
    model has no target to fill and the never-cut gate degrades the phase.

    This derives the secondary filenames from EXISTING single-sources-of-truth
    (`sc_never_cut_groups` / `l1_never_cut_groups`, `_required_niche_worker_jobs`,
    `_recon_worker_jobs`) rather than a hardcoded parallel list. For never-cut
    `[A|B]` alternations only the FIRST representative is seeded (one valid
    target is enough; the gate accepts either). Only TRIGGERED niches (from the
    manifest) are seeded, never all possible.
    """
    cfg = config or {}
    mode = str(cfg.get("mode") or "core").lower()
    pipeline = str(cfg.get("pipeline") or "sc").lower()
    targets: list[str] = []

    if phase.name == "depth":
        try:
            groups = (
                l1_never_cut_groups(mode)
                if pipeline == "l1"
                else sc_never_cut_groups(mode)
            )
        except Exception:
            groups = []
        for group in groups:
            # `group` is a list of alternations ([A|B]); seed ONE representative.
            if group:
                targets.append(group[0])
        # Triggered niche outputs from the instantiate manifest (manifest-driven,
        # only required/triggered rows return).
        try:
            for job in _required_niche_worker_jobs(scratchpad):
                out = job.get("output")
                if out:
                    targets.append(out)
        except Exception:
            pass
    elif phase.name == "recon":
        try:
            for job in _recon_worker_jobs(cfg):
                out = job.get("output")
                if out:
                    targets.append(out)
        except Exception:
            pass

    # De-dupe while preserving order; drop any that overlap a core glob target
    # already covered by expected_artifacts handling (those are seeded anyway).
    seen: set = set()
    deduped: list[str] = []
    for name in targets:
        if name and name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _precreate_codex_artifacts(
    phase: "Phase", scratchpad: Path, config: Optional[dict] = None
) -> None:
    """Seed empty files for expected artifacts so apply_patch has targets.

    Codex's apply_patch tool cannot create new files — it only modifies
    existing ones. By pre-creating each expected artifact as an empty file,
    the model can use apply_patch to write content into them. Files that
    already have content (from a prior attempt or phase) are left untouched.
    Glob patterns with wildcards are expanded to a single representative
    filename using the phase's example_tokens if available.

    In addition to `phase.expected_artifacts` (the CORE outputs), this also
    seeds the phase's mandatory first-pass SECONDARY artifacts — the never-cut
    scanners/validation/confidence files, triggered niche outputs, and recon
    worker shards — so Codex can fill the full first-pass set rather than only
    the core glob. Secondary names are derived from existing sources (see
    `_codex_secondary_artifact_targets`); seeding is additive and an unfilled
    empty seed still fails the stub/never-cut gate (no false-pass).
    """
    def _seed(concrete: str) -> None:
        target = scratchpad / concrete
        if not target.exists():
            try:
                target.write_text("", encoding="utf-8")
            except OSError:
                pass

    for pattern in phase.expected_artifacts:
        if "*" in pattern or "?" in pattern:
            if phase.example_tokens:
                for token in phase.example_tokens:
                    _seed(pattern.replace("*", token, 1))
        else:
            _seed(pattern)

    for name in _codex_secondary_artifact_targets(phase, scratchpad, config):
        _seed(name)


def _update_depth_alias_markers(path: Path, expected_name: str) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    new = re.sub(
        r"<!--\s*PLAMEN_ARTIFACT:\s*[^>]+-->",
        f"<!-- PLAMEN_ARTIFACT: {expected_name} -->",
        text,
        count=1,
    )
    new = re.sub(
        r"<!--\s*EXPECTED_OUTPUT:\s*[^>]+-->",
        f"<!-- EXPECTED_OUTPUT: {expected_name} -->",
        new,
        count=1,
    )
    if new != text:
        try:
            path.write_text(new, encoding="utf-8")
        except OSError:
            pass


def _canonicalize_depth_iter_filenames(scratchpad: Path) -> list[str]:
    """Rename non-canonical iter2/iter3 outputs to the canonical _findings.md form.

    The driver's depth manifest instructs the LLM to write
    `depth_iter2_*_findings.md` (and `depth_iter3_*_findings.md`), but the
    orchestrator routinely drops the `_findings` segment and emits
    `depth_iter2_state_trace.md`, `depth_iter3_targeted.md`, etc. Multiple
    downstream consumers (inventory parsers, validators, never-cut gate)
    glob for the strict suffix and miss these files, causing false-fail
    retries that re-spend the entire opus depth phase.

    Same class as v2.3.4's `depth_perturbation_findings.md` →
    `perturbation_findings.md` canonicalization. Idempotent and safe to
    re-run — if the canonical name already exists we skip to avoid
    clobbering.

    Returns the list of (source, target) pairs renamed for logging.
    """
    renamed: list[str] = []

    # Devil's-Advocate coordinators often write `da_iter2_*` / `da_iter3_*`
    # without the depth prefix. Canonicalize those first so the downstream
    # `depth_*_findings.md` gate sees them before spending a full retry.
    da_token_re = re.compile(r"^da[_-]?iter(?:ation)?[_-]?([23])[_-]?(.*)$", re.IGNORECASE)
    for src in sorted(scratchpad.glob("da_iter*.md")) + sorted(scratchpad.glob("da-iter*.md")):
        m = da_token_re.match(src.stem)
        if not m:
            continue
        n = m.group(1)
        role = re.sub(r"_?findings$", "", m.group(2), flags=re.IGNORECASE)
        role = re.sub(r"[_\-]+", "_", role).strip("_-")
        if role:
            target_name = f"depth_da_iter{n}_{role}_findings.md"
        else:
            target_name = f"depth_da_iter{n}_findings.md"
        target = src.with_name(target_name)
        if target.exists():
            continue
        try:
            src.rename(target)
            _update_depth_alias_markers(target, target_name)
            renamed.append(f"{src.name} -> {target.name}")
        except OSError:
            pass

    # The orchestrator is reliably TRYING to write depth iteration-2/3
    # findings, but the token order and spelling drift. Observed and
    # plausible variants — all semantically "depth iteration N findings
    # for <role>":
    #   depth_iter2_state_trace.md                (canonical prefix, no _findings)
    #   depth_iter2_state_trace_findings.md       (fully canonical — skip)
    #   depth_state_trace_iteration2_findings.md  (role-first, spelled out)
    #   depth_iteration2_state_trace_findings.md  (prefix, spelled out)
    #   depth_state_trace_iter2.md                (role-first, abbreviated)
    #   depth_state_trace_iter_2_findings.md      (underscore before digit)
    # ...with `iter` or `iteration`, an optional `_`/`-` before the digit,
    # and the role segment in either position. Canonical target for ALL:
    #   depth_iter{N}_{role}_findings.md
    #
    # Rather than enumerate variants (a losing game — the LLM keeps finding
    # new orderings), DECOMPOSE each `depth_*.md` filename: locate the
    # iteration token, lift N, treat everything else as the role, rebuild
    # canonically. A false "no iter2 artifacts" retry re-spends the whole
    # opus depth phase (~$4 observed on a prior audit) — same class as
    # v2.3.4's perturbation_findings canonicalization.
    #
    # `depth_da_*` / `depth_da3_*` are a SEPARATE recognized Devil's-Advocate
    # iteration form and must be left untouched.
    iter_token_re = re.compile(r"iter(?:ation)?[_-]?([23])", re.IGNORECASE)
    for src in sorted(scratchpad.glob("depth_*.md")):
        if src.name.lower().startswith(("depth_da_", "depth_da3_")):
            continue  # recognized DA form — not an iter-prefixed file
        stem = src.stem
        if not stem.startswith("depth_"):
            continue
        body = stem[len("depth_"):]
        m = iter_token_re.search(body)
        if not m:
            continue  # no iteration token → iter1 base file or non-iter file
        n = m.group(1)
        # Role = everything except the iteration token and the _findings
        # suffix, with separators collapsed.
        role = body[:m.start()] + body[m.end():]
        role = re.sub(r"_?findings", "", role, flags=re.IGNORECASE)
        role = re.sub(r"[_\-]+", "_", role).strip("_-")
        if not role:
            continue  # can't canonicalize without a role segment
        target_name = f"depth_iter{n}_{role}_findings.md"
        if src.name == target_name:
            continue  # already canonical
        target = src.with_name(target_name)
        if target.exists():
            continue  # don't clobber existing canonical
        try:
            src.rename(target)
            _update_depth_alias_markers(target, target_name)
            renamed.append(f"{src.name} -> {target.name}")
        except OSError:
            # Best-effort: any FS error and we leave the file alone.
            # The iter2 gate's tolerant glob is the defense-in-depth path.
            pass
    return renamed


# S1.3 — mechanical confidence scoring (driver-owned). Evidence-source tag
# scores per ~/.plamen/rules/phase4-confidence-scoring.md, extended with the
# PoC/proof tags depth findings actually carry.
_EVIDENCE_TAG_SCORE = {
    "[PROD-ONCHAIN]": 1.0, "[MEDUSA-PASS]": 1.0, "[POC-PASS]": 1.0,
    "[PROD-SOURCE]": 0.9, "[PROD-FORK]": 0.9, "[FUZZ-PASS]": 0.9,
    "[NON-DET-PASS]": 0.9, "[CONFORMANCE-PASS]": 0.9, "[DIFF-PASS]": 0.9,
    "[CODE]": 0.8, "[CODE-TRACE]": 0.8, "[LSP-TRACE]": 0.7,
    "[DOC]": 0.4, "[MOCK]": 0.2, "[POC-FAIL]": 0.15, "[EXT-UNV]": 0.1,
}
# Ship A (fixes SW07-4): single source of truth in plamen_types. The former
# local copy dropped NON-DET/ASYMMETRIC/MEDUSA-PASS/etc., so L1 + network depth
# findings scored lower than identical SC findings in the confidence ranking.
_DEPTH_EVIDENCE_TAG_RE = DEPTH_EVIDENCE_TAG_RE
# F2.0: permissive bracket-content capture. The old `[A-Z]{1,8}-\d+[A-Z\d-]*`
# rejected blind-spot IDs of shape `BLIND-A-1` (the `\d+` immediately after
# the first hyphen rejects the `A-` letter segment) — in a prior run this matched
# 0/14 blind-spot findings, silently under-scoring real findings in
# confidence. The `## Finding [...]` syntax is itself the source-of-truth
# contract: whatever the agent put in the brackets is the ID.
# Ship D (fixes SW07-3/5): single source of truth in plamen_types. The former
# local copy was H2-ONLY, so the confidence synthesizer saw ZERO findings on
# the prompt-mandated H3 `### Finding [ID]` depth blocks and wrote a
# "(no findings produced)" placeholder confidence_scores.md.
_FINDING_HEADING_RE = FINDING_BLOCK_HEADING_RE


def _iter_finding_blocks(text: str):
    """Yield (finding_id, block_text) for each `## Finding [ID]` section.

    F2.0: id is the raw bracket content; callers dedupe on the normalized
    form (with raw-uppercase fallback for new/unrecognized prefixes) to
    avoid raw-vs-normalized double-counting.
    """
    matches = list(_FINDING_HEADING_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        yield m.group(1).strip(), text[start:end]


def _compute_depth_confidence(scratchpad: Path, mode: str) -> int:
    """S1.3: write a real, per-finding confidence_scores.md (driver-owned).

    Replaces the uniform-0.5 stub. Three axes are scored mechanically from
    each finding's text per phase4-confidence-scoring.md; the RAG axis is held
    at a 0.30 PENDING floor because rag_sweep (Phase 4b.5) runs after depth —
    final scoring incorporates RAG later. Differentiated composites pass
    `_validate_confidence_scores_quality`. The 8-column table format is
    byte-compatible with the prior synth (no downstream parser change).
    Returns the finding-row count.
    """
    finding_files = sorted(
        list(scratchpad.glob("depth_*_findings.md"))
        + list(scratchpad.glob("blind_spot_*_findings.md"))
        + list(scratchpad.glob("niche_*_findings.md"))
        + list(scratchpad.glob("validation_sweep_findings.md"))
        + list(scratchpad.glob("scanner_*_findings.md"))
        + list(scratchpad.glob("design_stress_findings.md"))
        + list(scratchpad.glob("perturbation_findings.md"))
    )
    seen: set[str] = set()
    rows: list[str] = []
    for fpath in finding_files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for raw_id, block in _iter_finding_blocks(text):
            # F2.0: dedupe on the NORMALIZED form (with raw-uppercase
            # fallback for new/unrecognized prefixes) so the same finding
            # surfacing in two formats does not produce two rows.
            norm_id = _normalize_finding_id(raw_id)
            key = norm_id or raw_id.upper()
            if key in seen:
                continue
            seen.add(key)
            display_id = norm_id or raw_id
            tag_scores = [s for t, s in _EVIDENCE_TAG_SCORE.items() if t in block]
            evidence = max(tag_scores) if tag_scores else 0.5
            dtags = len(_DEPTH_EVIDENCE_TAG_RE.findall(block))
            quality = (
                1.0 if dtags >= 3 else
                0.7 if dtags == 2 else
                0.4 if dtags == 1 else 0.1
            )
            consensus = 1.0   # single-domain conservative default (spec)
            rag = 0.3         # RAG_PENDING — rag_sweep runs after depth
            composite = round(
                evidence * 0.25 + consensus * 0.25
                + quality * 0.3 + rag * 0.2,
                2,
            )
            classification = (
                "CONFIDENT" if composite >= 0.7 else
                "UNCERTAIN" if composite >= 0.4 else "LOW_CONFIDENCE"
            )
            rows.append(
                f"| {display_id} | {evidence:.2f} | {consensus:.2f} | {quality:.2f} "
                f"| {rag:.2f} | {composite:.2f} | {classification} "
                f"| {fpath.name} |"
            )
    lines = [
        "# Confidence Scores (driver-computed)",
        "",
        "> **Status**: DRIVER-COMPUTED — per-finding mechanical scoring. "
        "Evidence/Consensus/Quality derived from finding text; the RAG axis "
        "is held at a 0.30 PENDING floor (rag_sweep runs after depth; final "
        "scoring incorporates RAG).",
        "",
        "| Finding ID | Evidence | Consensus | Quality | RAG | Composite "
        "| Classification | Source |",
        "|------------|----------|-----------|---------|-----|-----------"
        "|----------------|--------|",
    ]
    lines.extend(rows)
    if not rows:
        lines.append("| - | - | - | - | - | - | - | (no findings produced) |")
    try:
        (scratchpad / "confidence_scores.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except OSError:
        pass
    return len(rows)


def _synthesize_depth_lifecycle_artifacts(
    scratchpad: Path, pipeline: str, *, force: bool = False,
    mode: str = "core",
) -> list[str]:
    """Auto-generate never_cut_checkpoint.md and depth_exit.md from disk state.

    Codex/GPT models reliably produce finding files but frequently omit the
    lifecycle metadata artifacts the gate requires, or write them in a format
    the validator rejects.  These are mechanically derivable from what's on
    disk — no LLM reasoning needed.

    When *force* is True (Codex backend), always overwrite — the driver's
    mechanical version is more reliable than whatever the LLM wrote.

    v2.6.3: mode-aware — Thorough-only roles (design-stress, perturbation,
    skill-execution-checklist) are only included when mode == "thorough".

    Returns list of files synthesized (for logging).
    """
    synthesized: list[str] = []

    # F2.a: rebuild order matters. confidence_scores.md must be recomputed
    # BEFORE never_cut_checkpoint.md and depth_exit.md, because the latter
    # two read confidence's existence/size to mark `confidence-scoring`
    # status. Original order rebuilt the checkpoint with stale/missing
    # confidence info, then recomputed confidence — so the checkpoint
    # recorded `SKIPPED NO_APPLICABLE_FLAG` despite real findings.

    # --- confidence_scores.md (S1.3 — driver-owned mechanical scoring) ---
    # Compute real per-finding scores when the file is missing or a stub
    # (a SYNTHESIZED placeholder, uniform composites, near-empty, or — per
    # F2.b — a DRIVER-COMPUTED `(no findings produced)` placeholder when
    # real depth findings now exist on disk). A substantive LLM-written
    # confidence file is left untouched.
    cs = scratchpad / "confidence_scores.md"
    cs_missing = not cs.exists() or cs.stat().st_size < 100
    cs_stub = (not cs_missing) and bool(_depth_artifact_is_stub(cs))
    if cs_missing or cs_stub or force:
        _compute_depth_confidence(scratchpad, mode)
        if cs.exists():
            synthesized.append("confidence_scores.md")

    # --- never_cut_checkpoint.md ---
    # F2.a: ALWAYS rebuild. Purely mechanical 9-line status derived from
    # on-disk findings; previously guarded by `if force or not ncc.exists()`
    # which left the file frozen at the attempt-1 all-SKIPPED snapshot even
    # after attempt 2 produced real findings.
    ncc = scratchpad / "never_cut_checkpoint.md"
    if pipeline == "l1":
        role_file_map = {
            "depth-consensus-invariant": "depth_consensus_invariant_findings.md",
            "depth-network-surface": "depth_network_surface_findings.md",
            "depth-state-trace": "depth_state_trace_findings.md",
            "depth-external": "depth_external_findings.md",
            "depth-edge-case": "depth_edge_case_findings.md",
            "confidence-scoring": "confidence_scores.md",
        }
    else:
        role_file_map = {
            "depth-token-flow": "depth_token_flow_findings.md",
            "depth-state-trace": "depth_state_trace_findings.md",
            "depth-edge-case": "depth_edge_case_findings.md",
            "depth-external": "depth_external_findings.md",
            "confidence-scoring": "confidence_scores.md",
        }
    if mode == "thorough":
        role_file_map.update({
            "design-stress": "design_stress_findings.md",
            "perturbation": "perturbation_findings.md",
            "skill-execution-checklist": "skill_execution_gaps.md",
        })
    ncc_lines = ["# Never-Cut Checkpoint (auto-synthesized by driver)\n"]
    for role, filename in role_file_map.items():
        fpath = scratchpad / filename
        alias = f"depth_{filename}" if not filename.startswith("depth_") else None
        exists = fpath.exists() and fpath.stat().st_size > 0
        if not exists and alias:
            alias_p = scratchpad / alias
            if alias_p.exists() and alias_p.stat().st_size > 0:
                exists = True
                fpath = alias_p
        # v2.0.3 (A3 / Codex Claim 7): substance-aware status. A header-only
        # 29-byte file produced by an orphaned background agent must NOT be
        # reported as SPAWNED — that hides the orphan from downstream
        # diagnostics. Mirror the gate's substance check.
        if exists:
            stub_reason = _depth_artifact_is_stub(fpath)
            if stub_reason:
                status = f"STUB ({stub_reason})"
            else:
                status = "SPAWNED"
        else:
            status = "SKIPPED NO_APPLICABLE_FLAG"
        ncc_lines.append(f"- {role}: {status}")
    try:
        ncc.write_text("\n".join(ncc_lines) + "\n", encoding="utf-8")
        synthesized.append("never_cut_checkpoint.md")
    except OSError:
        pass

    # --- depth_exit.md ---
    # F2.a + F2.c: ALWAYS rebuild the structured header; preserve genuine
    # LLM body content under `## Original LLM depth exit (preserved)`, but
    # FIRST strip any prior driver-generated wrapper from the existing
    # file so the preservation does not nest itself recursively across
    # repeated calls. Without this strip, each call would wrap the prior
    # call's full file (including its own header) as "original LLM body",
    # bloating the file unboundedly across attempts/repairs.
    dep = scratchpad / "depth_exit.md"
    dep_existing_text = ""
    if dep.exists() and not force:
        try:
            dep_existing_text = dep.read_text(encoding="utf-8", errors="replace")
        except Exception:
            dep_existing_text = ""
    # Strip prior driver wrapper.
    llm_only = dep_existing_text
    if llm_only:
        # If there's a previously-preserved LLM block, keep only what's
        # below the `## Original LLM depth exit (preserved)` marker.
        m = re.search(
            r"(?ms)^##\s+Original\s+LLM\s+depth\s+exit\s+\(preserved\)\s*\n+",
            llm_only,
        )
        if m:
            llm_only = llm_only[m.end():]
        # Or if no marker but the text starts with the driver header, the
        # whole file is a prior driver wrapper with no real LLM body.
        elif re.match(
            r"\s*#\s+Depth\s+Exit\s+\(auto-synthesized", llm_only
        ):
            llm_only = ""
    # v2.0.3 (A3): split depth files into substantive vs stub.
    # depth_exit.md must NOT list stub files under "completed roles" —
    # that produces a misleading exit rationale when orphan-background
    # leaves header-only files on disk.
    depth_files = list(scratchpad.glob("depth_*_findings.md"))
    completed: list[str] = []
    stub_paths: list[str] = []
    for f in depth_files:
        if f.stat().st_size == 0:
            continue
        if _depth_artifact_is_stub(f):
            stub_paths.append(f.name)
        else:
            completed.append(f.name)
    dep_lines = [
        "# Depth Exit (auto-synthesized by driver)\n",
        "- criterion: 1",
        "- rationale: Substance-aware exit (v2.0.3). Stub files are listed "
        "separately and NOT counted as completion.",
        "- explored_paths:",
    ]
    for name in completed:
        dep_lines.append(f"  - {name}")
    if not completed:
        dep_lines.append("  - (no substantive depth findings files found)")
    if stub_paths:
        dep_lines.append("- stub_paths (NOT counted as completion):")
        for name in stub_paths:
            dep_lines.append(f"  - {name}")
    if llm_only.strip() and not force:
        dep_lines.append("\n---\n")
        dep_lines.append("## Original LLM depth exit (preserved)\n")
        # rstrip to stabilize across repeated calls — without it, each
        # iteration's `"\n".join` would accumulate a trailing newline.
        dep_lines.append(llm_only.rstrip())
    try:
        dep.write_text("\n".join(dep_lines) + "\n", encoding="utf-8")
        synthesized.append("depth_exit.md")
    except OSError:
        pass

    return synthesized


def _estimate_codex_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost from Codex token counts."""
    inp_rate, out_rate = _CODEX_PRICING.get(model, (2.00, 8.00))
    return (input_tokens * inp_rate + output_tokens * out_rate) / 1_000_000


def _parse_codex_output(log_path: Path, model: str = "") -> dict:
    """Parse streaming JSONL from Codex subprocess output log.

    Codex --json emits one JSON event per line:
      - type=turn.completed → usage {input_tokens, output_tokens, ...}
      - type=item.completed + item.type=agent_message → output text
      - type=turn.failed / type=error → error info
    We accumulate usage across all turn.completed events.
    Model must be passed in since JSONL events don't include it.
    """
    result: dict[str, Any] = {"output": "", "cost_usd": 0.0, "duration_ms": 0,
                              "tokens": 0, "model": model}
    total_input = 0
    total_output = 0
    output_parts: list[str] = []
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = event.get("type", "")
            if etype == "error":
                result["error"] = event.get("message", "unknown_error")
                return result
            if etype == "turn.failed":
                err = event.get("error") or {}
                result["error"] = err.get("message", "turn_failed")
                return result
            if etype == "turn.completed":
                usage = event.get("usage") or {}
                total_input += usage.get("input_tokens", 0)
                total_output += usage.get("output_tokens", 0)
            if etype == "item.completed":
                item = event.get("item") or {}
                if item.get("type") == "agent_message":
                    msg = item.get("text", "")
                    if msg:
                        output_parts.append(msg)
    except OSError:
        pass
    result["output"] = "\n".join(output_parts)
    result["tokens"] = total_input + total_output
    result["input_tokens"] = total_input
    result["output_tokens"] = total_output
    result["cost_usd"] = _estimate_codex_cost(model, total_input, total_output)
    return result


# ── Process management ────────────────────────────────────────────────────

def _terminate_process_tree(proc: subprocess.Popen, grace_s: float = 5.0) -> None:
    """Terminate a phase subprocess and its children best-effort."""
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(1.0, grace_s + 0.5),
                check=False,
            )
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=grace_s)
        except Exception:
            pass
        return

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=grace_s)
        return
    except Exception:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=grace_s)
    except Exception:
        pass


_HALT_TERMINATE_GRACE_S = 2.0
_ACTIVE_WORKER_SESSIONS: set[Any] = set()
_ACTIVE_WORKER_SESSIONS_LOCK = threading.Lock()


class _NonBlockingWorkerPool(concurrent.futures.ThreadPoolExecutor):
    """ThreadPoolExecutor whose context-manager exit never waits.

    The stdlib ThreadPoolExecutor `with` block always calls
    `shutdown(wait=True)` in `__exit__`. That defeats Plamen's Esc/rate-limit
    fast path: even after active PTYs are terminated and queued futures are
    cancelled, the context manager can sit on still-unwinding worker threads.
    Worker pool loops already collect every required result before normal exit,
    so non-blocking context exit is the correct behavior for abnormal exits.
    """

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        try:
            self.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self.shutdown(wait=False)
        return False


def _register_active_worker_session(session: Any) -> None:
    try:
        with _ACTIVE_WORKER_SESSIONS_LOCK:
            _ACTIVE_WORKER_SESSIONS.add(session)
    except Exception:
        pass


def _unregister_active_worker_session(session: Any) -> None:
    try:
        with _ACTIVE_WORKER_SESSIONS_LOCK:
            _ACTIVE_WORKER_SESSIONS.discard(session)
    except Exception:
        pass


def _terminate_active_worker_sessions(grace_s: float = _HALT_TERMINATE_GRACE_S) -> None:
    try:
        with _ACTIVE_WORKER_SESSIONS_LOCK:
            sessions = list(_ACTIVE_WORKER_SESSIONS)
    except Exception:
        sessions = []
    for session in sessions:
        try:
            session.terminate(grace_s=grace_s)
        except Exception:
            pass


def _cancel_pending_worker_futures(
    pending_futs: set[concurrent.futures.Future],
    executor: concurrent.futures.ThreadPoolExecutor,
) -> None:
    """Fast Esc path: cancel queued workers and terminate active PTYs."""
    _terminate_active_worker_sessions()
    for fut in list(pending_futs):
        fut.cancel()
    try:
        executor.shutdown(wait=False, cancel_futures=True)
    except TypeError:
        executor.shutdown(wait=False)
    except Exception:
        pass


def _hard_exit_after_user_stop(exit_code: int = 0) -> None:
    """Exit after explicit user stop without waiting on worker threads.

    Worker-pool cancellation is deliberately non-blocking, but Python will
    still keep non-daemon executor threads alive during normal interpreter
    shutdown. On Windows this can leave the driver resident after the UI says
    "Stopped" while Claude children keep running. Once the user has chosen
    stop and keep/purge, terminate registered child PTYs, release the run
    lock, and bypass normal shutdown.
    """
    try:
        display.graceful_stop.finalizing = True
        display.pause_toggle._suspended = True
        restore = getattr(display.pause_toggle, "restore_terminal", None)
        if callable(restore):
            restore()
    except Exception:
        pass
    try:
        _terminate_active_worker_sessions(grace_s=_HALT_TERMINATE_GRACE_S)
    except Exception:
        pass
    try:
        _release_run_lock()
    except Exception:
        pass
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(exit_code)


def _backfill_legacy_unmarked_completed_phase(
    scratchpad: Path, phase: Phase
) -> list[str]:
    """Backfill the COMPLETE marker for an ALREADY-CHECKPOINTED supervised
    phase whose only gate failure is a content-valid artifact that lost its
    status marker (e.g. a worker whose final marker write was dropped by
    context compaction).

    On a fresh-audit scratchpad a marker-less artifact is classified
    IN_PROGRESS purely because the marker is absent, BEFORE its content is
    judged. For a phase already in ``checkpoint.completed`` that is a false
    rewind trigger: the phase finished, only the process signal is missing.

    This backfills ``<!-- PLAMEN_STATUS: COMPLETE -->`` for each such file
    ONLY when its CONTENT passes the same structural completeness gate the
    fresh-audit path uses. Returns the list of files marked. It is a strict
    no-op (returns ``[]``) when ANY expected row is genuinely incomplete
    (missing / stub / marked-but-IN_PROGRESS / structural_fail) so a real
    rewind still proceeds, and only acts on the supervised phases that carry
    legacy-unmarked classification (breadth, depth).
    """
    if phase.name == "breadth":
        rows = compute_breadth_row_statuses(scratchpad, phase)
    elif phase.name == "depth":
        rows = compute_depth_row_statuses(scratchpad, phase)
    else:
        return []
    if not rows:
        return []
    legacy_candidates: list[str] = []
    for row in rows:
        status = row.get("status")
        if status == "complete":
            continue
        reasons = row.get("reasons") or []
        # Only marker-less-on-fresh-audit rows are eligible. Any other
        # non-complete status (missing/stub/structural_fail, or a
        # marked-but-IN_PROGRESS file) is a genuine hole -> abort backfill.
        if status == "in_progress" and "legacy-unmarked on fresh audit" in reasons:
            legacy_candidates.append(str(row.get("name", "")))
        else:
            return []
    backfilled: list[str] = []
    for name in legacy_candidates:
        path = scratchpad / name
        ok, _why = _structural_completeness_ok(
            path,
            required_headings=(),
            placeholder_strings=("TODO", "FILL_ME", "<placeholder>"),
        )
        if not ok:
            # Content does not actually pass -> do not mask a real hole.
            return []
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write("\n<!-- PLAMEN_STATUS: COMPLETE -->\n")
            backfilled.append(name)
        except Exception as exc:  # pragma: no cover - I/O failure path
            log.warning(
                "[resume] marker backfill failed for %s: %r", name, exc
            )
            return []
    return backfilled


def _reconcile_completed_checkpoint_artifacts(
    scratchpad: Path,
    project_root: str,
    checkpoint: Checkpoint,
    phases: list[Phase],
    mode: str,
) -> list[str]:
    """Rewind completed checkpoint entries whose artifacts no longer pass.

    Resume safety is a contract between `_v2_checkpoint.json` and the current
    phase graph. A completed phase is only skippable if its active artifact
    gate still passes. When an earlier completed phase is invalid, every
    downstream completed phase is also unsafe because it may have consumed the
    stale or missing output.
    """
    active = [phase for phase in phases if mode in phase.modes]
    active_names = {phase.name for phase in active}
    unknown = checkpoint.validate_phase_names(active_names)
    if unknown:
        raise RuntimeError(
            "checkpoint references phases outside the active graph: "
            + ", ".join(sorted(unknown))
        )

    first_invalid_idx: int | None = None
    first_missing: list[str] = []
    completed_names = set(checkpoint.completed or [])
    first_hole_idx: int | None = None
    for idx, phase in enumerate(active):
        if phase.name not in completed_names:
            if first_hole_idx is None:
                first_hole_idx = idx
            continue
        if first_hole_idx is not None:
            first_invalid_idx = first_hole_idx
            first_missing = [
                "checkpoint completion is not prefix-closed: "
                f"{phase.name} is completed after incomplete phase "
                f"{active[first_hole_idx].name}"
            ]
            log.warning("[resume] %s", first_missing[0])
            break

    for idx, phase in enumerate(active):
        if first_invalid_idx is not None:
            break
        if phase.name not in checkpoint.completed:
            continue
        missing = _resume_phase_contract_issues(
            scratchpad, project_root, phase, mode
        )
        if missing and scratchpad_is_fresh_audit(scratchpad):
            # A completed-and-checkpointed phase must NOT be rewound merely
            # because a content-valid artifact lost its COMPLETE marker.
            # Backfill the marker for legacy-unmarked content-valid rows,
            # then re-validate. Genuine holes leave `missing` non-empty.
            backfilled = _backfill_legacy_unmarked_completed_phase(
                scratchpad, phase
            )
            if backfilled:
                missing = _resume_phase_contract_issues(
                    scratchpad, project_root, phase, mode
                )
                if not missing:
                    log.info(
                        "[resume] completed phase %s: backfilled COMPLETE "
                        "marker for content-valid artifact(s) instead of "
                        "rewinding: %s",
                        phase.name,
                        ", ".join(backfilled),
                    )
        if missing:
            first_invalid_idx = idx
            first_missing = list(missing)
            log.warning(
                "[resume] completed phase %s failed contract reconciliation: %s",
                phase.name,
                ", ".join(first_missing),
            )
            break

    if first_invalid_idx is None:
        return []

    rewind_names = {phase.name for phase in active[first_invalid_idx:]}
    removed = [name for name in checkpoint.completed if name in rewind_names]
    removed_degraded = [name for name in checkpoint.degraded if name in rewind_names]
    checkpoint.completed = [name for name in checkpoint.completed if name not in rewind_names]
    checkpoint.degraded = [name for name in checkpoint.degraded if name not in rewind_names]
    for name in removed_degraded:
        checkpoint.clear_degraded_sentinel(scratchpad, name)
    if checkpoint.rate_limited_at in rewind_names:
        checkpoint.rate_limited_at = None
    return removed


def _resume_phase_contract_issues(
    scratchpad: Path,
    project_root: str,
    phase: Phase,
    mode: str = "core",
) -> list[str]:
    """Side-effect-free subset of phase completion contracts for resume."""
    issues: list[str] = []
    if (
        phase.expected_artifacts
        or getattr(phase, "any_of", None)
        or phase.name in L1_VERIFY_PHASE_NAMES
        or phase.name in SC_VERIFY_PHASE_NAMES
    ):
        passed, missing = gate_passes(scratchpad, project_root, phase)
        if not passed:
            issues.extend(missing)

    if phase.name == "inventory":
        # v2.8.6: skip parity on resume — inventory is modified by downstream
        # phases (depth promotion, dedup) so the merge receipt is stale. The
        # parity check was already enforced when the inventory was first created.
        # Only run the structure check (headings/format) on resume.
        issues.extend(_validate_inventory_structure(scratchpad))
    elif phase.name == "recon" and "build_status.md" in set(phase.expected_artifacts):
        hard, _soft = _validate_recon_content_structure(scratchpad)
        issues.extend(hard)
    elif phase.name == "instantiate":
        issues.extend(_validate_spawn_manifest_schema(scratchpad, mode))
    elif phase.name in (
        "inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"
    ):
        issues.extend(_validate_inventory_chunk_structure(scratchpad, phase.name))
    elif phase.name in ("verify_queue", "sc_verify_queue"):
        issues.extend(_validate_verification_queue_inventory_parity(scratchpad))
        if phase.name == "sc_verify_queue" and mode != "thorough":
            low_info = [
                r.get("finding id", "")
                for r in parse_verification_queue_rows(scratchpad)
                if _severity_bucket(r.get("severity", "")) in {"low", "info"}
            ]
            if low_info:
                issues.append(
                    "SC verification queue contains Low/Info active row(s) "
                    f"in {mode} mode: {', '.join(low_info[:8])}"
                )
    elif phase.name == "report_index":
        issues.extend(_validate_report_index_inputs(scratchpad))
        issues.extend(_check_index_completeness(
            scratchpad, project_root, write_retry_hint=False
        ))
        issues.extend(_validate_report_coverage_accounting(scratchpad))
    elif phase.name in ("verify_aggregate", "sc_verify_aggregate"):
        issues.extend(_validate_verify_files_for_queue(scratchpad))
        issues.extend(_validate_verify_evidence_tags(scratchpad))
    elif phase.name == "skeptic":
        issues.extend(_validate_skeptic_full_ch_coverage(scratchpad))
    elif phase.name == "report_assemble":
        # RESUME-2: the resume reconcile probe must be side-effect-free. The full
        # _run_report_quality_gate writes AUDIT_REPORT.md + report_quality.md and
        # applies prose checks -- it belongs only on the live post-assembly path.
        # Here use a content-only presence/structure check plus the mechanical
        # degraded-sentinel check (meaningful on a genuine resume).
        issues.extend(_report_assemble_content_only_issues(project_root))
        issues.extend(_validate_assemble_not_degraded(scratchpad))
    elif (
        phase.name in (
            "report_critical_high", "report_medium", "report_low_info",
            "report_body_writer_critical_high",
            "report_body_writer_medium",
            "report_body_writer_low_info",
        )
        or re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name)
        or re.match(r"^report_body_writer_(critical_high|medium|low_info)_[a-z]$", phase.name)
    ):
        check_phase_name = phase.name.replace("report_body_writer_", "report_")
        issues.extend(_validate_tier_body_against_manifest(scratchpad, check_phase_name))

    return issues


def _phase_content_gate_issues(
    phase: Phase,
    config: dict,
    scratchpad: Path,
    project_root: str,
) -> list[str]:
    """Side-effect-free CONTENT re-validation for a phase, mirroring the
    resume-skip decision.

    Returns the list of content/disk issues (empty == artifacts on disk are
    content-valid). This is the same gate the resume loop uses to decide
    whether a completed phase can be skipped, so the degrade/halt path can
    re-check content before forcing a CRITICAL halt (FC4 safety net). It is
    DELIBERATELY content-only: it does not re-run prose/quality retry-hint
    generation, only the validators that prove the artifacts are usable.
    """
    mode = config.get("mode", "core")
    if phase.name in L1_VERIFY_PHASE_NAMES or phase.name in SC_VERIFY_PHASE_NAMES:
        return list(_validate_verify_completion(scratchpad, phase.name, mode=mode))
    if phase.name == "attention_repair":
        hard, _soft = _validate_attention_repair(scratchpad, mode)
        return list(hard)
    if phase.name == "exploration_skeptic":
        # Soft, additive phase: validator only ever returns [], so this is
        # always content-valid on resume — prevents a false resume-halt.
        # M1: the committed-invariant soft validator runs alongside (also
        # always returns []); it only writes a `.ci_gap` sentinel for visibility.
        _validate_invariant_commitment(scratchpad, mode)
        return list(_validate_exploration_skeptic(scratchpad, mode))
    if phase.name == "enumgap_exploration":
        # Soft, additive phase (validator always returns []) — content-valid on
        # resume so it never causes a false resume-halt.
        return list(_validate_enumgap_exploration(scratchpad, mode))
    if phase.name == "axis_coverage":
        # Soft, additive phase (M2 validator always returns []) — content-valid on
        # resume so it never causes a false resume-halt.
        return list(_validate_axis_coverage(scratchpad, mode))
    if phase.name == "report_assemble":
        # RESUME-3: the FC4 content re-check must be SIDE-EFFECT-FREE and
        # content-only. Do NOT run _run_report_quality_gate here (it writes
        # AUDIT_REPORT.md + report_quality.md and applies prose checks), and do
        # NOT consult the {phase}.degraded sentinel the driver just wrote one
        # branch earlier (it is not independent evidence). Only verify the
        # delivered report is present and structurally non-stub.
        return _report_assemble_content_only_issues(project_root)
    return list(_resume_phase_contract_issues(scratchpad, project_root, phase, mode))


def _report_assemble_content_only_issues(project_root: str) -> list[str]:
    """Mechanical, side-effect-free presence/structure check for the delivered
    AUDIT_REPORT.md. Returns [] when the report exists and is non-stub.

    Used by RESUME-2 (resume reconcile) and RESUME-3 (FC4 degrade re-check) so a
    content-valid report is never rewound/halted by the side-effecting prose
    quality gate. The full _run_report_quality_gate still runs on the live
    post-assembly path where its self-heal writes belong.
    """
    issues: list[str] = []
    report = Path(project_root) / "AUDIT_REPORT.md"
    if not report.exists():
        return ["AUDIT_REPORT.md missing"]
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [f"AUDIT_REPORT.md unreadable ({exc})"]
    if len(text) < 500:
        issues.append("AUDIT_REPORT.md is a stub (<500 bytes)")
    # Structurally non-stub: at least one finding section OR an explicit
    # Summary / severity section heading (a clean no-findings report is valid).
    if not (
        re.search(r"(?im)^###\s+\[?[CHMLI]-\d", text)
        or re.search(r"(?im)^##\s+(?:Summary|Critical|High|Medium|Low|Informational)\b", text)
    ):
        issues.append("AUDIT_REPORT.md has no finding sections or severity/summary headings")
    return issues


def _fc4_autocomplete_if_content_valid(
    phase: Phase, config: dict, scratchpad: Path, checkpoint: Checkpoint,
) -> "list[str] | None":
    """FC4 safety net (shared by every CRITICAL-degrade branch): before halting,
    re-validate artifacts with the side-effect-free CONTENT gate the resume path
    uses. If content-valid, auto-complete the phase (clear retry hint + degraded
    sentinel, mark completed) and return None so the caller `continue`s instead
    of halting. Returns the remaining content issues when content genuinely fails.
    """
    content_issues = _phase_content_gate_issues(
        phase, config, scratchpad, config["project_root"]
    )
    if content_issues:
        return list(content_issues)
    log.warning(
        f"[{phase.name}] degraded on retry-hint/quality gate but artifacts pass "
        f"the content gate on re-check - auto-completing instead of halting (FC4)"
    )
    _clear_retry_hint(scratchpad, phase.name)
    _cleanup_quarantine_backups(scratchpad, phase)
    if phase.name in checkpoint.degraded:
        checkpoint.degraded.remove(phase.name)
    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
    checkpoint.mark_completed(phase.name)
    if checkpoint.rate_limited_at == phase.name:
        checkpoint.rate_limited_at = None
    checkpoint.save(scratchpad)
    return None


def _inventory_has_usable_findings(scratchpad: Path, min_blocks: int = 3) -> bool:
    """True when findings_inventory.md holds enough parseable finding blocks to
    feed downstream phases (chain/verify/report).

    Used by the inventory degrade-and-continue branch: a STRUCTURE /
    field-completeness gate failure on an inventory that nonetheless contains
    >= `min_blocks` usable finding blocks is a quality shortfall, not a
    catastrophe — downstream phases can still operate. A missing/near-empty
    inventory (0 blocks) still funnels to the critical-halt path.
    """
    inv_path = scratchpad / "findings_inventory.md"
    try:
        if not inv_path.exists():
            return False
        text = inv_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if len(text.strip()) < 500:
        return False
    try:
        return len(_inventory_blocks(text)) >= min_blocks
    except Exception:
        return False


def _inventory_degrade_floor_ok(scratchpad: Path) -> bool:
    """B2 verify graceful fallback: decide the inventory degrade branch.

    Returns True (degrade-and-continue, NEVER terminal halt) when either:

      * the inventory already holds usable finding blocks, OR
      * the B1 floor can reconstruct a structurally valid inventory from the
        completed breadth/depth/chunk artifacts. The floor is honest: it only
        carries forward findings that actually exist (never fabricates), and a
        genuinely empty audit (0 findings anywhere) still yields a valid empty
        inventory, not a crash.

    `ensure_findings_inventory_floor` is a NO-OP when a real inventory already
    exists, so calling it here cannot clobber a good inventory or invent
    findings. The only path that should NOT reach this branch is one where the
    floor itself raised — in which case we return False and let the caller fall
    through to the critical-halt diagnostics so the failure is surfaced, not
    silently swallowed.
    """
    if _inventory_has_usable_findings(scratchpad):
        return True
    try:
        n_findings, n_sources = ensure_findings_inventory_floor(scratchpad)
    except Exception as exc:
        log.error(f"[inventory] floor reconstruction raised: {exc}")
        return False
    inv_path = scratchpad / "findings_inventory.md"
    if not inv_path.exists():
        # Floor must always write a file (even the empty path); absence means an
        # unexpected failure — surface it via the critical-halt path.
        return False
    if n_findings > 0:
        log.warning(
            f"[inventory] degraded with no usable inventory on disk; floor "
            f"reconstructed {n_findings} finding(s) from {n_sources} source "
            "artifact(s) -- degrading and continuing (verification proceeds on "
            "the honest reconstructed inventory)"
        )
    else:
        log.warning(
            f"[inventory] degraded and {n_sources} source artifact(s) yielded "
            "0 findings (genuinely empty audit); wrote a valid empty inventory "
            "-- degrading and continuing"
        )
    return True


_BODY_CONTENT_RETRY_CAP = 2


def _body_content_retry_path(scratchpad: Path, phase_name: str) -> Path:
    return scratchpad / f".{phase_name}.content_retry"


def _body_content_retry_exhausted(scratchpad: Path, phase_name: str) -> bool:
    """Bucket 3: True once the bounded productive content-retry budget for a
    body-writer phase is spent, so content shortfall stops triggering retries
    and the phase WARN-ships its current (best-effort) sections."""
    try:
        return int(_body_content_retry_path(scratchpad, phase_name).read_text(encoding="utf-8")) >= _BODY_CONTENT_RETRY_CAP
    except Exception:
        return False


def _bump_body_content_retry(scratchpad: Path, phase_name: str) -> None:
    p = _body_content_retry_path(scratchpad, phase_name)
    try:
        n = int(p.read_text(encoding="utf-8"))
    except Exception:
        n = 0
    try:
        p.write_text(str(n + 1), encoding="utf-8")
    except Exception:
        pass


def _body_content_retry_hint(phase_name: str, content_short: list) -> str:
    """Delta-injected (convergent) retry hint: names the specific thin sections
    so the body-writer enriches THEM, never an identical re-prompt (LLM-8)."""
    return (
        f"## Body content quality retry for {phase_name}\n\n"
        "The previous attempt shipped section(s) with a thin or missing "
        "**Impact** or **PoC Result**. Enrich ONLY the sections listed below with "
        "concrete, specific detail tied to the verifier evidence (or, for a "
        "genuinely minor Low/Info one-liner with no security nuance, move it to "
        "the `## Quality Observations` megasection). Do NOT pad with boilerplate "
        "and do NOT alter any other section.\n\n"
        "Sections needing enrichment:\n"
        + "\n".join(f"- {c}" for c in content_short[:20])
        + "\n"
    )


def _record_phase_cost(scratchpad: Path, phase_name: str, model: str,
                       attempt: int, stdio_log: Path, duration_s: float,
                       backend: str = "claude") -> None:
    """Parse the claude -p JSON envelope for cost + append to a ledger.

    Pure observability. Does not affect pipeline decisions. Envelope
    fields captured when present: total_cost_usd, num_turns, duration_ms,
    stop_reason, is_error.
    """
    ledger_path = scratchpad / "_v2_cost_ledger.md"
    try:
        if not stdio_log.exists():
            return
        with stdio_log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 32768))
            tail = f.read().decode("utf-8", errors="replace")
        fields: dict[str, Any] = {}
        if backend == "codex":
            parsed = _parse_codex_output(stdio_log, model=model)
            fields["total_cost_usd"] = f"{parsed.get('cost_usd', 0):.4f}"
            fields["stop_reason"] = "error" if parsed.get("error") else "end"
            fields["is_error"] = bool(parsed.get("error"))
            # _parse_codex_output accumulates input/output tokens separately
            # from turn.completed usage dicts in the JSONL stream.
            fields["input_tokens"] = parsed.get("input_tokens", 0) or "?"
            fields["output_tokens"] = parsed.get("output_tokens", 0) or "?"
            # Count turns from JSONL
            num_turns = 0
            try:
                for line in tail.splitlines():
                    if '"turn.completed"' in line:
                        num_turns += 1
            except Exception:
                pass
            fields["num_turns"] = num_turns or 1
        elif backend == "claude-pty":
            fields.update(parse_transcript_usage(stdio_log))
        else:
            envelope = _extract_json_envelope(tail)
            if envelope:
                for key in ("total_cost_usd", "num_turns", "stop_reason",
                            "is_error", "api_error_status"):
                    if key in envelope:
                        fields[key] = envelope[key]
                # Cache metrics — essential for measuring whether prompt caching
                # is already helping us (cache_read = cheap hits at 0.1x input
                # price; cache_creation = one-time writes at 1.25x input).
                # claude-cli exposes these via the `usage` field in the JSON
                # envelope (Anthropic API convention).
                usage = envelope.get("usage") or {}
                if isinstance(usage, dict):
                    for key in ("input_tokens", "output_tokens",
                                "cache_read_input_tokens",
                                "cache_creation_input_tokens"):
                        if key in usage:
                            fields[key] = usage[key]
        # First write: create header row with cache columns
        if not ledger_path.exists():
            ledger_path.write_text(
                "# Phase Cost Ledger\n\n"
                "Cache columns explain where money went:\n"
                "- InTok = raw input tokens billed at 1x\n"
                "- OutTok = output tokens billed at 5x (sonnet)\n"
                "- CacheRd = input tokens served from cache at 0.1x (savings)\n"
                "- CacheWr = input tokens written to cache at 1.25x (one-time)\n"
                "- TotalInTok = InTok + CacheRd + CacheWr (Anthropic long-context threshold: 200k)\n"
                "- LongCtx = ⚠️ when TotalInTok > 200k (long-context pricing tier applies)\n"
                "- High CacheRd / TotalInTok ratio = good cache reuse\n\n"
                "| Phase | Attempt | Model | Dur(s) | Cost(USD) | Turns | "
                "InTok | OutTok | CacheRd | CacheWr | TotalInTok | LongCtx | "
                "CacheHit% | StopReason | Err |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
                encoding="utf-8",
            )
        cost = fields.get("total_cost_usd", "?")
        turns = fields.get("num_turns", "?")
        stop = fields.get("stop_reason", "?")
        err = fields.get("is_error", False)
        api_err = fields.get("api_error_status")
        err_s = f"{api_err}" if api_err else ("true" if err else "")
        in_tok = fields.get("input_tokens", "?")
        out_tok = fields.get("output_tokens", "?")
        cache_rd = fields.get("cache_read_input_tokens", 0)
        cache_wr = fields.get("cache_creation_input_tokens", 0)
        # Compute total input tokens (InTok + CacheRd + CacheWr) — this is
        # what Anthropic compares against the 200k long-context threshold.
        try:
            total_in = int(in_tok) + int(cache_rd) + int(cache_wr)
            long_ctx = "⚠️" if total_in > 200000 else ""
            total_in_s = str(total_in)
        except Exception:
            total_in = None
            long_ctx = ""
            total_in_s = "?"
        # Compute cache hit % against TotalInTok denominator (matches the
        # header doc and is the meaningful reuse ratio).
        try:
            if total_in is not None and total_in > 0:
                cache_hit_pct = f"{100.0 * int(cache_rd) / total_in:.0f}%"
            else:
                cache_hit_pct = "?"
        except Exception:
            cache_hit_pct = "?"
        with ledger_path.open("a", encoding="utf-8") as f:
            f.write(
                f"| {phase_name} | {attempt} | {model} | "
                f"{duration_s:.0f} | {cost} | {turns} | "
                f"{in_tok} | {out_tok} | {cache_rd} | {cache_wr} | "
                f"{total_in_s} | {long_ctx} | "
                f"{cache_hit_pct} | {stop} | {err_s} |\n"
            )
    except Exception:
        # Telemetry must never break the pipeline.
        pass


def _restore_tier_body_from_overflow(scratchpad: Path, phase_name: str) -> bool:
    """Recover a valid tier body quarantined by an older containment pass."""
    if not re.match(r"^report_(critical_high|medium|low_info)(?:_[a-z])?$", phase_name):
        return False
    dest = scratchpad / f"{phase_name}.md"
    overflow = scratchpad / "_overflow"
    if not overflow.exists():
        return False
    candidates = sorted(
        overflow.glob(f"**/{phase_name}.md"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    for src in candidates:
        try:
            if not src.exists() or src.stat().st_size <= 100:
                continue
            shutil.copy2(src, dest)
            if _validate_tier_body_against_manifest(scratchpad, phase_name):
                dest.unlink(missing_ok=True)
                continue
            return True
        except Exception as exc:
            log.warning(f"[{phase_name}] overflow restore failed for {src}: {exc!r}")
    return False


def _extract_json_envelope(tail_text: str) -> Optional[dict]:
    """Find the outermost JSON object in the tail and parse it.

    `claude -p --output-format json` writes a single JSON object to stdout.
    It is the last complete JSON in the log. Walk backward to find it.
    """
    # Scan backward for `{` then try to json.loads progressively.
    # Practical heuristic: the envelope is at the very end (or very near it)
    # and is well-formed. Try the last 64KB first.
    for end_marker in ("\n}\n", "}\n", "}"):
        idx = tail_text.rfind(end_marker)
        if idx == -1:
            continue
        # Find matching opening brace
        depth = 0
        for i in range(idx, -1, -1):
            ch = tail_text[i]
            if ch == "}":
                depth += 1
            elif ch == "{":
                depth -= 1
                if depth == 0:
                    candidate = tail_text[i:idx + len(end_marker)]
                    try:
                        return json.loads(candidate)
                    except Exception:
                        break
    return None


def _detect_rate_limit_jsonl_tail(tail_text: str) -> bool:
    """Detect rate limits in Claude Code session JSONL events."""
    for line in tail_text.splitlines()[-200:]:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if isinstance(event, dict) and event_is_rate_limited(event):
            return True
    return False


def detect_rate_limit(stdio_log: Path, tail_bytes: int = 65536) -> bool:
    """Return True iff an actual API rate limit is detected.

    Strategy:
    1. Read the last ~64KB of the stdio log.
    2. Try to parse a JSON envelope. If found, check structured fields
       (`is_error`, `api_error_status`, error `type`).
    3. If no JSON envelope (crash pre-envelope), fall back to a STRUCTURED
       text regex that requires an HTTP status or API error prefix. Plain
       LLM prose no longer triggers.
    """
    if not stdio_log.exists():
        return False
    try:
        with stdio_log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return False

    if "PLAMEN_RATE_LIMIT_DETECTED=1" in tail:
        return True

    envelope = _extract_json_envelope(tail)
    if envelope is not None:
        # Structured path: trust only fields, ignore prose.
        if event_is_rate_limited(envelope):
            return True
        if envelope.get("is_error") is True:
            status = envelope.get("api_error_status")
            try:
                status_code = int(status)
            except Exception:
                status_code = None
            if status_code in _API_RATE_LIMIT_STATUSES:
                return True
            err = envelope.get("error") or {}
            if isinstance(err, dict):
                err_type = (err.get("type") or "").lower()
                if "rate_limit" in err_type or "overloaded" in err_type:
                    return True
        stop_reason = (envelope.get("stop_reason") or "").lower()
        if stop_reason in ("rate_limited", "rate_limit", "overloaded"):
            return True
        terminal_reason = (envelope.get("terminal_reason") or "").lower()
        if "rate" in terminal_reason and "limit" in terminal_reason:
            return True
        # Envelope parsed cleanly, no structured rate-limit signal → NOT
        # rate-limited. Do NOT fall through to text regex — that's the
        # false-positive path.
        if _detect_rate_limit_jsonl_tail(tail):
            return True
        return False

    # Envelope not parseable (subprocess likely crashed pre-envelope).
    # Use strict text regex: requires structured error prefix.
    if _detect_rate_limit_jsonl_tail(tail):
        return True
    if text_shows_rate_limit(tail):
        return True
    return bool(_STRUCTURED_RATE_LIMIT_RE.search(tail))


_NOT_LOGGED_IN_RE = re.compile(
    r"not\s+logged\s+in|/login|please\s+log\s+in|"
    r"run\s+`?claude`?\s+(?:interactively\s+)?to\s+(?:log\s*in|authenticate)",
    re.IGNORECASE,
)


def detect_not_logged_in(stdio_log: Path, tail_bytes: int = 65536) -> bool:
    """Return True iff the `claude` CLI emitted an authentication error (v2.0.1).

    An unauthenticated `claude -p` returns rc=0 (or rc!=0 on newer builds) with a
    "Not logged in" / "/login" message; without this the driver retries the same
    unauthenticated CLI and degrades the phase, masking the real cause.
    """
    if not stdio_log.exists():
        return False
    try:
        with stdio_log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return False
    return bool(_NOT_LOGGED_IN_RE.search(tail))


# ── 529 overload (transient provider overload) ──────────────────────────────
#
# A 529 / `overloaded_error` is Anthropic being temporarily overloaded
# provider-wide. It is NOT the user's account rate/usage cap (429 / "weekly
# limit"). `detect_rate_limit` returns True for BOTH (the structured paths and
# the regexes cover 429+529 alike). `detect_overloaded` narrows to the 529
# class so the depth-retry path can give transient overloads short-backoff
# retries BEFORE ever surfacing the usage-cap pause panel. Genuine 429s skip
# this path entirely and keep their existing long-wait + pause behavior.

# Short exponential backoff schedule for transient 529 overloads (seconds).
# Capped at ~3 min per the design; >=4 attempts before any pause is surfaced.
_OVERLOAD_BACKOFF_SCHEDULE_S = (30, 60, 120, 180)


def _detect_overloaded_jsonl_tail(tail_text: str) -> bool:
    """Detect 529/overloaded signals in Claude Code session JSONL events."""
    for line in tail_text.splitlines()[-200:]:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if isinstance(event, dict) and event_is_overloaded(event):
            return True
    return False


def detect_overloaded(stdio_log: Path, tail_bytes: int = 65536) -> bool:
    """Return True iff a transient 529 / `overloaded_error` is detected.

    Strict subset of `detect_rate_limit`: matches ONLY the 529/overload class,
    never the 429 usage-cap class. Same envelope-first/text-fallback strategy.
    """
    if not stdio_log.exists():
        return False
    try:
        with stdio_log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return False

    envelope = _extract_json_envelope(tail)
    if envelope is not None:
        # Structured path: trust only fields.
        if event_is_overloaded(envelope):
            return True
        if envelope.get("is_error") is True:
            status = envelope.get("api_error_status")
            try:
                status_code = int(status)
            except Exception:
                status_code = None
            if status_code == 529:
                return True
            err = envelope.get("error") or {}
            if isinstance(err, dict):
                err_type = (err.get("type") or "").lower()
                if "overloaded" in err_type:
                    return True
        stop_reason = (envelope.get("stop_reason") or "").lower()
        if stop_reason == "overloaded":
            return True
        if _detect_overloaded_jsonl_tail(tail):
            return True
        return False

    # Envelope not parseable.
    if _detect_overloaded_jsonl_tail(tail):
        return True
    return bool(text_shows_overloaded(tail))


def overload_backoff_plan(
    attempts_so_far: int,
    *,
    max_attempts: int = len(_OVERLOAD_BACKOFF_SCHEDULE_S),
    schedule: tuple[int, ...] = _OVERLOAD_BACKOFF_SCHEDULE_S,
) -> tuple[bool, int]:
    """Pure decision helper for 529 overload handling (unit-testable).

    `attempts_so_far` = number of short-backoff overload retries ALREADY made
    for this phase (0 before the first retry).

    Returns ``(should_retry, wait_seconds)``:
    - If more overload retries remain → ``(True, <backoff for this attempt>)``.
    - If the overload budget is exhausted → ``(False, 0)`` and the caller MUST
      fall back to the existing pause-for-resume path (haltless floor).
    """
    if attempts_so_far < 0:
        attempts_so_far = 0
    if attempts_so_far >= max_attempts:
        return False, 0
    idx = min(attempts_so_far, len(schedule) - 1)
    return True, schedule[idx]


def _overload_sleep_seconds(wait_s: int) -> int:
    """Resolve the actual sleep length for a 529 backoff step.

    In tests the env var PLAMEN_OVERLOAD_BACKOFF_TEST_S forces a short sleep so
    real wall-clock backoff never runs in the suite. Production uses the real
    schedule value.
    """
    override = os.environ.get("PLAMEN_OVERLOAD_BACKOFF_TEST_S")
    if override:
        try:
            return max(0, int(override))
        except Exception:
            return 0
    return max(0, int(wait_s))


def _append_rate_limit_sentinel(
    stdio_log: Path,
    *,
    phase_name: str,
    source: str,
) -> None:
    """Stamp a phase log with a structured rate-limit marker.

    Worker-pool phases can detect rate limits inside child PTYs even when the
    child transcript tail does not include a parseable Anthropic JSON envelope.
    The outer retry loop only inspects the aggregate `_stdio_<phase>.log`, so
    every internal rate-limit rc must be surfaced there in a structured form.
    """
    try:
        with stdio_log.open("a", encoding="utf-8", errors="replace") as f:
            f.write(
                "\nPLAMEN_RATE_LIMIT_DETECTED=1 "
                "api_error_status=429 "
                "type=rate_limit_error "
                f"phase={phase_name} "
                f"source={source}\n"
            )
    except Exception:
        pass


# v2.0.3 (A2): orphaned-background-agent detection. The LLM uses Task with
# run_in_background:true on multiple agents, then end_turn — agents are
# killed when the subprocess exits, leaving WRITE-THEN-VERIFY reservation
# headers on disk. Detection runs post-subprocess; writes a diagnostic file
# that the retry-hint dispatcher (A4) consumes. Does NOT affect gate
# pass/fail (substance gate from Stage 1.5 is the authority).
_PLAMEN_STUB_HEADER_RE = re.compile(
    r"\A\s*#+\s+[^\n]{1,80}\s*\n?\s*\Z",
    re.MULTILINE,
)


def _is_header_only_stub(path: Path, max_bytes: int = 120) -> bool:
    """True iff `path` is a header-only file (≤120 bytes containing only a
    single markdown heading). This is the orphan-background fingerprint:
    the WRITE-THEN-VERIFY reservation header reached disk; full content
    never did.
    """
    try:
        size = path.stat().st_size
        if size == 0 or size > max_bytes:
            return False
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(_PLAMEN_STUB_HEADER_RE.match(content))


def _resolve_never_cut_targets(scratchpad: Path, phase_name: str,
                                 mode: str, pipeline: str) -> list[str]:
    """Return the flat list of canonical artifact filenames that the phase
    is expected to produce per the never-cut groups (any-of groups are
    collapsed to the first canonical name). Used by the orphan detector to
    enumerate which files to scan for stub fingerprints — works around
    `Phase.expected_artifacts=["depth_*_findings.md"]` (a glob, not an
    enumeration) per Codex Round-1 Claim 5.
    """
    if phase_name != "depth":
        return []
    try:
        if pipeline == "l1":
            groups = l1_never_cut_groups(mode)
        else:
            groups = sc_never_cut_groups(mode)
    except Exception:
        return []
    # any-of group: pick the first canonical name (e.g.
    # ["validation_sweep_findings.md", "scanner_validation_findings.md"]
    # collapses to "validation_sweep_findings.md").
    return [group[0] for group in groups if group]


def _slugify_cwd_for_transcript(project_root: str) -> str:
    """v2.0.5 (B1): convert a project root path to the Claude Code
    transcript directory slug. Claude Code stores per-session transcript
    JSONL files at `~/.claude/projects/{slug}/{session_id}.jsonl` where
    the slug replaces path separators, the drive colon, AND spaces with
    dashes (verified empirically against
    `~/.claude/projects/D--Programming-Web3-Contests-Example-Protocol-...`).

    Example: ``D:\\Programming\\X Audit\\repo`` →
    ``D--Programming-X-Audit-repo``.
    """
    s = str(project_root)
    # Drive letter + colon → drive letter + double-dash
    s = re.sub(r"^([A-Za-z]):", r"\1-", s)
    # Path separators (\, /) AND whitespace → dash
    s = re.sub(r"[\\/\s]+", "-", s)
    return s


def _find_transcript_jsonl(project_root: str) -> Optional[Path]:
    """v2.0.5 (B1): locate the most recent Claude Code transcript JSONL
    for the given project root. Returns None if not discoverable.

    Multiple session files may exist per project (one per `claude -p`
    invocation). The most recent file by mtime is the one corresponding
    to the just-finished subprocess.
    """
    slug = _slugify_cwd_for_transcript(project_root)
    candidates = (
        Path.home() / ".claude" / "projects" / slug,
        plamen_home().parent / "projects" / slug,
    )
    for parent in candidates:
        if not parent.is_dir():
            continue
        files = sorted(parent.glob("*.jsonl"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            return files[0]
    return None


# v2.0.5 (B1): Claude Code's Task tool surfaces as either name="Task"
# (older transcripts) or name="Agent" (newer Claude Code releases).
# Both must be scanned for the orphan fingerprint.
_TRANSCRIPT_TASK_NAMES = ("Task", "Agent")


def _walk_transcript_tool_uses(obj: Any, out: list[dict]) -> None:
    """v2.0.5 (B1): iterative walk over a parsed JSONL entry collecting
    every nested `tool_use` whose name is in `_TRANSCRIPT_TASK_NAMES`
    (Task | Agent). Mutates `out` in place — module-level so the
    structural-integrity test doesn't flag a nested closure.
    """
    stack: list[Any] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if (cur.get("type") == "tool_use"
                    and cur.get("name") in _TRANSCRIPT_TASK_NAMES):
                inp = cur.get("input") or {}
                if isinstance(inp, dict):
                    out.append({
                        "id": cur.get("id", ""),
                        "subagent_type": inp.get("subagent_type", ""),
                        "description": (inp.get("description") or "")[:120],
                        "run_in_background": bool(inp.get("run_in_background")),
                    })
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def _scan_transcript_for_background_orphan(
    transcript_path: Path,
) -> Optional[dict]:
    """v2.0.5 (B1): definitive-evidence path for orphan-background
    detection. Parse a Claude Code session JSONL and look for ≥2
    tool_use calls (name ∈ {Task, Agent}) with run_in_background:true
    followed by stop_reason=end_turn without a subsequent collection.

    Returns a partial dict with structured evidence, or None.
    """
    if not transcript_path.is_file():
        return None
    all_calls: list[dict] = []
    last_stop_reason: Optional[str] = None
    try:
        with transcript_path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                _walk_transcript_tool_uses(obj, all_calls)
                if obj.get("type") == "assistant":
                    sr = (obj.get("message") or {}).get("stop_reason")
                    if sr:
                        last_stop_reason = sr
    except OSError:
        return None

    bg_calls = [c for c in all_calls if c["run_in_background"]]
    if len(bg_calls) < 2:
        return None
    if last_stop_reason != "end_turn":
        # Crash/rate-limit/different terminal — not the orphan signature.
        return None
    return {
        "transcript_path": str(transcript_path),
        "task_count_background": len(bg_calls),
        "turn_ended_at": last_stop_reason,
        "agent_ids": [c["id"] for c in bg_calls],
        "subagent_types": [c["subagent_type"] for c in bg_calls],
    }


def detect_background_orphan(
    stdio_log: Path,
    scratchpad: Path,
    phase_name: str,
    mode: str,
    pipeline: str,
    rc: int,
    *,
    backend: str = "claude",
    project_root: Optional[str] = None,
) -> Optional[dict]:
    """Detect the orphaned-background-agent pattern after a subprocess exits.

    Returns a diagnostic dict if the pattern is detected and writes it to
    `{scratchpad}/_diagnostic_orphan_{phase_name}.json`. Returns None
    otherwise.

    Detection priority (Codex Round-2 Claim 10):
      - **Definitive evidence:** transcript JSONL proves ≥2 Task calls
        with `run_in_background:true` followed by `end_turn` without
        subsequent collection AND ≥2 expected files are header-only stubs
        → emit diagnostic REGARDLESS of rc.
      - **Heuristic path:** transcript unavailable / unparseable; `rc == 0`
        AND ≥2 expected files are header-only stubs → emit with
        `evidence:"heuristic"`.
      - Otherwise → return None (silent).
    """
    targets = _resolve_never_cut_targets(scratchpad, phase_name, mode, pipeline)
    if not targets:
        return None
    stub_files = [t for t in targets if _is_header_only_stub(scratchpad / t)]
    if len(stub_files) < 2:
        return None

    # v2.0.5 (B1): definitive-evidence path via transcript JSONL.
    # Works regardless of rc (per Codex Round-2 Claim 10) — the LLM's
    # documented behavior is the diagnosis; rc quirks must not suppress.
    transcript_evidence: Optional[dict] = None
    if backend == "claude" and project_root:
        transcript_path = _find_transcript_jsonl(project_root)
        if transcript_path is not None:
            transcript_evidence = _scan_transcript_for_background_orphan(
                transcript_path
            )

    if transcript_evidence:
        diag = {
            "phase": phase_name,
            "evidence": "transcript_jsonl",
            "rc": rc,
            "backend": backend,
            "stub_files": stub_files,
            "stub_count": len(stub_files),
            "fingerprint": "tool_use_run_in_background_then_end_turn",
            "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **transcript_evidence,
        }
    else:
        # Heuristic path: rc==0 required (orphan is a clean exit). If the
        # subprocess crashed or timed out, the cause is different.
        if rc != 0:
            return None
        diag = {
            "phase": phase_name,
            "evidence": "heuristic",
            "rc": rc,
            "backend": backend,
            "stub_files": stub_files,
            "stub_count": len(stub_files),
            "fingerprint": "header_only_files_with_clean_rc",
            "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    try:
        out = scratchpad / f"_diagnostic_orphan_{phase_name}.json"
        out.write_text(json.dumps(diag, indent=2), encoding="utf-8")
    except OSError:
        pass
    return diag


_INVENTORY_CHUNK_RE = re.compile(r"^findings_inventory_chunk_([a-z])\.md$")


def _is_valid_inventory_chunk_output(path: Path) -> bool:
    """v2.0.4 (A'2): lightweight side-effect-free validator for an
    inventory chunk artifact. Replicates the substantive checks of the
    inventory_chunk_* gate WITHOUT calling _run_phase_validators (which
    has side effects per Codex Round-2 Claim 11).

    Inventory chunk gate requirements (derived from
    phase4a-inventory-prompt body lines 200-208 and the prompt-builder
    inventory_scope_directive at plamen_prompt.py:2206-2280):

      - file size >= 200 bytes (gate min_artifact_bytes)
      - contains at least one `### Finding [CC-` heading (the
        chunk-row contract; CC-N IDs are mandatory per the prompt body)
      - contains at least one `**Impact**:` line (checklist requirement
        — every CC block must list the impact)
      - contains at least one `**Source IDs**:` reference (cross-phase
        parity contract — downstream merge maps CC IDs back to upstream)

    Returns True iff all four hold. No side effects. The general
    `_run_phase_validators` belongs to Phase C with a `dry_run=True`
    extraction; A' uses this lightweight check.
    """
    try:
        if path.stat().st_size < 200:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # CC-N chunk-row heading (mandatory). Tolerant `#{2,4}` + optional `:` after
    # the bracketed ID so `### Finding [CC-1]` and `#### Finding [CC-1]: title`
    # both match (strict superset of the old `^###\s+Finding\s+\[CC-`).
    if not re.search(r"(?im)^\s*#{2,6}\s+Finding\s+\[CC-", _llm_norm(text)):
        return False
    # Impact + Source-ID presence via the shared tolerant extractor: accepts
    # bold/bullet/plain/table-cell renderings, `:`/`-`/`=`/em-dash separators,
    # and the `Source ID` singular alias — fixing the futile chain-chunk retries
    # the old literal `^**Impact**:` / `^**Source IDs**:` regexes caused on
    # complete-but-differently-rendered chunks.
    impact_val, _ = _field_anywhere(text, ("Impact",), table_ok=True)
    if not impact_val:
        return False
    src_val, _ = _field_anywhere(
        text, ("Source IDs", "Source ID", "Source Finding IDs"), table_ok=True
    )
    if not src_val:
        return False
    return True


def _record_artifact_adoption(
    scratchpad: Path,
    project_root: str,
    name: str,
    *,
    owning_phase: str,
    adopted_from: str,
) -> None:
    """v2.0.4 (A'2): record adoption provenance in `_artifact_state.json`.

    Extends the existing `_artifact_record` schema (validators.py:1321)
    with three optional fields:
      - `adopted_from`: the phase that physically produced the file
      - `adopted_at`: ISO timestamp of adoption
      - `adoption_owning_phase`: the phase whose expected_artifact this is

    Backward-compatible: artifacts without these fields are normal
    phase-owned outputs.
    """
    try:
        state = _read_artifact_state(scratchpad)
    except Exception as e:
        log.debug(f"[adoption] could not read artifact state: {e}")
        return
    artifacts = state.setdefault("artifacts", {})
    record = _artifact_record(
        scratchpad, project_root, name,
        owner_phase=owning_phase, status="ACTIVE",
    )
    if record is None:
        return
    record["adopted_from"] = adopted_from
    record["adopted_at"] = datetime.now(timezone.utc).isoformat()
    record["adoption_owning_phase"] = owning_phase
    artifacts[name] = record
    try:
        _write_artifact_state(scratchpad, state)
    except Exception as e:
        log.debug(f"[adoption] could not write artifact state: {e}")


def _try_adopt_inventory_sibling(
    scratchpad: Path,
    project_root: str,
    current_phase_name: str,
    foreign_name: str,
) -> bool:
    """v2.0.4 (A'2): attempt to adopt a sibling inventory_chunk output.

    Adoption semantics (Phase A' tactical, inventory-scoped):
      - The foreign artifact must be a sibling chunk's expected output
        (e.g., chunk_a is running and the foreign file is
        findings_inventory_chunk_b.md).
      - The foreign file's content must pass the lightweight inventory
        chunk validator (no side effects, no recursion into the general
        phase validator per Codex Round-2 Claim 11).
      - On success: the file STAYS in the scratchpad root at its
        expected name. Provenance is recorded in `_artifact_state.json`.
        The downstream chunk_b phase will execute, but its subprocess
        will see the existing substantive file via the resumption
        protocol and exit immediately without re-deriving.
      - Phase C will generalize this with full skip-by-adoption via
        the declarative `Phase.adoptable_outputs` contract and
        `_run_phase_validators_readonly`.

    Returns True iff the adoption is accepted. False → caller should
    quarantine instead.
    """
    m = _INVENTORY_CHUNK_RE.match(foreign_name)
    if not m:
        return False
    owning_chunk_letter = m.group(1)
    owning_phase_name = f"inventory_chunk_{owning_chunk_letter}"
    if owning_phase_name == current_phase_name:
        return False  # not a sibling — it's our own output
    foreign_path = scratchpad / foreign_name
    if not foreign_path.exists():
        return False
    if not _is_valid_inventory_chunk_output(foreign_path):
        log.warning(
            f"[{current_phase_name}] cannot adopt {foreign_name}: "
            f"failed inventory chunk validator (size/CC-heading/"
            f"Impact/Source IDs missing). Will quarantine instead."
        )
        return False
    _record_artifact_adoption(
        scratchpad, project_root, foreign_name,
        owning_phase=owning_phase_name,
        adopted_from=current_phase_name,
    )
    log.warning(
        f"[{current_phase_name}] adopted {foreign_name} for "
        f"{owning_phase_name} (validator passed; provenance recorded). "
        f"{owning_phase_name} subprocess will exit via resumption protocol."
    )
    return True


def _archive_orphan_stubs(
    scratchpad: Path, phase_name: str, diag: dict
) -> Optional[Path]:
    """v2.0.3 (A4): move orphan-background stub files out of the scratchpad
    into `_overflow/{phase_name}/orphan_stubs/{timestamp}/` along with a
    manifest. Returns the archive directory path or None on failure.

    Rationale: the retry attempt should treat orphan stubs as MISSING, not
    as partial work. Moving them out of the scratchpad root ensures the
    resumption-protocol substantive-content check sees them as absent.
    The archive also provides a concrete regression fixture for tests.
    """
    stubs = diag.get("stub_files") or []
    if not stubs:
        return None
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive_dir = scratchpad / "_overflow" / phase_name / "orphan_stubs" / ts
    try:
        archive_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    moved: list[str] = []
    for name in stubs:
        src = scratchpad / name
        if not src.exists():
            continue
        try:
            dst = archive_dir / name
            src.rename(dst)
            moved.append(name)
        except OSError as e:
            log.debug(f"[{phase_name}] could not archive stub {name}: {e}")
    try:
        manifest = archive_dir / "manifest.txt"
        manifest.write_text(
            f"# Orphan-background stub archive ({phase_name})\n"
            f"# Detected at: {diag.get('detected_at','unknown')}\n"
            f"# Evidence: {diag.get('evidence','unknown')}\n"
            f"# rc: {diag.get('rc','unknown')}\n"
            f"# Backend: {diag.get('backend','unknown')}\n"
            f"# Fingerprint: {diag.get('fingerprint','unknown')}\n"
            f"# Stub files archived:\n"
            + "".join(f"#   - {m}\n" for m in moved),
            encoding="utf-8",
        )
    except OSError:
        pass
    return archive_dir


_VERIFY_HINT_ID_RE = re.compile(
    r"\b(?:INV|H|M|L|C|MED|LOW|INFO|CH|DCOV|SLITHER|DEPTH-[A-Z]+)-\d+\b",
    re.IGNORECASE,
)


_SEMANTIC_DEDUP_PASSTHROUGH_PREFIX = (
    "semantic dedup: PASSTHROUGH unchanged despite live candidate pairs"
)


def _semantic_dedup_pair_count(scratchpad: Path) -> int:
    pairs_file = scratchpad / "dedup_candidate_pairs.md"
    if not pairs_file.exists():
        return 0
    try:
        pair_text = pairs_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    return sum(
        1
        for line in pair_text.splitlines()
        if line.lstrip().startswith("|")
        and not re.match(r"\s*\|\s*-+", line)
        and "Finding A" not in line
    )


def _semantic_dedup_passthrough_issue(scratchpad: Path) -> Optional[str]:
    pair_rows = _semantic_dedup_pair_count(scratchpad)
    if pair_rows <= 0:
        return None
    decisions = scratchpad / "dedup_decisions.md"
    if not decisions.exists():
        return None
    try:
        dec_text = decisions.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    if re.search(r"(?im)^\s*\*?\*?Status\*?\*?\s*:\s*PASSTHROUGH\b", dec_text):
        return (
            f"{_SEMANTIC_DEDUP_PASSTHROUGH_PREFIX} "
            f"({pair_rows} candidate pair(s)); subprocess preserved the "
            "pre-run safety net instead of evaluating merge/keep decisions"
        )
    return None


def _is_semantic_dedup_passthrough_failure(missing: list[Any]) -> bool:
    return any(
        str(item).startswith(_SEMANTIC_DEDUP_PASSTHROUGH_PREFIX)
        for item in missing
    )


# FIX (#5): phases whose disk gate can pass on a driver pre-written
# scaffold/placeholder rather than real completed work. The zombie-phase
# early-complete (in `_pty_poll`) must NEVER fire for these — the existing
# continuation-budget / timeout path owns them. chain_agent2 / chain_iter2 are
# deliberately NOT here: they write real synthesis artifacts with no scaffold,
# so they are exactly the idle-zombie case the recovery is meant to rescue
# (chain_agent2 once blocked the full ~90-min LOC-scaled timeout after writing
# all three of its artifacts).
_ZOMBIE_SCAFFOLD_EXCLUDED_NAMES = frozenset({
    "sc_semantic_dedup", "semantic_dedup",   # PASSTHROUGH scaffold
    "chain",                                  # chain Agent 1 — MECHANICAL_BASELINE
})
_ZOMBIE_SCAFFOLD_EXCLUDED_PREFIXES = (
    "report_critical_high", "report_medium", "report_low_info",  # placeholder pre-writes
)


def _zombie_phase_is_scaffold_excluded(phase: Any) -> bool:
    """True when `phase` may pass its gate on a pre-written scaffold/placeholder
    and therefore must not be early-completed by zombie-phase recovery."""
    name = getattr(phase, "name", "") or ""
    if name in _ZOMBIE_SCAFFOLD_EXCLUDED_NAMES:
        return True
    if getattr(phase, "appends_existing_artifact", False):
        return True
    return any(name.startswith(pfx) for pfx in _ZOMBIE_SCAFFOLD_EXCLUDED_PREFIXES)


def _dedup_passthrough_should_continue(
    phase_name: str, attempt: int, budget: int, scratchpad: Path
) -> bool:
    """True when the in-session continuation loop should spend a turn driving
    a fresh missing-only continuation for a semantic-dedup phase instead of
    accepting the gate's pass.

    The gate "passes" the moment the driver's crash-safety PASSTHROUGH
    scaffold exists on disk — so a subprocess that compacted mid-write and
    never overwrote the scaffold looks complete and the continuation budget
    is never used. This predicate fires ONLY when ALL hold:

      - the phase is the semantic-dedup phase (SC or L1),
      - continuation budget remains (attempt <= budget), and
      - dedup_decisions.md still carries Status: PASSTHROUGH while
        dedup_candidate_pairs.md has live candidate rows
        (``_semantic_dedup_passthrough_issue`` is the single source of truth).

    When it returns False on a dedup phase because the budget is spent, the
    caller accepts the passthrough floor (returns 0) — it MUST NOT escalate to
    a whole-phase-retry sentinel, because this phase is critical=True and that
    would cascade to a critical halt. Recall is preserved downstream by the
    mechanical passthrough disposition, supplemental dedup, and the
    Python-native report_dedup pass.
    """
    if phase_name not in ("semantic_dedup", "sc_semantic_dedup"):
        return False
    if attempt > budget:
        return False
    return bool(_semantic_dedup_passthrough_issue(scratchpad))


# Regex for the LLM/mechanical absorbed->survivor relationship rows in
# dedup_decisions.md. Two formats are recognized (mirrors
# _extract_dedup_absorbed_ids, but captures BOTH endpoints so the survivor can
# be propagated into finding_mapping):
#   1. LLM semantic dedup status row:
#        | INV-013 | MERGED into INV-014 | <coupled-content> | <notes> |
#   2. Mechanical fallback/supplement:
#        | MECHANICAL_MERGE | INV-013 | INV-014 | <signal> |
#        | MECHANICAL_SUPPLEMENT | INV-013 | INV-014 | <signal> |
_DEDUP_MERGED_INTO_RE = re.compile(
    r"^\|\s*([A-Za-z]+-\d+)\s*\|\s*MERGED\s+into\s+([A-Za-z]+-\d+)\b"
    r"(?:\s*\|\s*([^|]*))?",
    re.MULTILINE | re.IGNORECASE,
)
_DEDUP_MECHANICAL_ROW_RE = re.compile(
    r"^\|\s*MECHANICAL_(?:MERGE|SUPPLEMENT)\s*\|\s*([A-Za-z]+-\d+)\s*\|\s*"
    r"([A-Za-z]+-\d+)\s*\|\s*([^|]*)",
    re.MULTILINE | re.IGNORECASE,
)


def _dedup_absorbed_survivor_mapping(
    scratchpad: Path,
) -> dict[str, dict[str, str]]:
    """Return ``{absorbed_id: {"survivor": id, "coupled": text}}`` from dedup.

    Parses ``dedup_decisions.md`` for both the LLM ``MERGED into`` status rows
    and the mechanical ``MECHANICAL_MERGE/SUPPLEMENT`` rows. Captures the
    survivor AND the coupled-content / signal cell so the absorbed finding's
    distinct content can be recorded alongside the constituent mapping. This is
    additive bookkeeping — it never drops a finding; it only records which
    survivor a previously-absorbed finding was consolidated into so the
    tier-writer Rule 10 coupling path (read finding_mapping.md, pull each source
    finding's distinct root cause into the report finding) reaches the absorbed
    lineage.
    """
    path = scratchpad / "dedup_decisions.md"
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    mapping: dict[str, dict[str, str]] = {}

    def _norm(token: str) -> str:
        return str(token or "").strip().strip("[]").upper()

    for m in _DEDUP_MERGED_INTO_RE.finditer(text):
        absorbed = _norm(m.group(1))
        survivor = _norm(m.group(2))
        coupled = re.sub(r"\s+", " ", (m.group(3) or "").strip())
        if absorbed and survivor and absorbed != survivor:
            # First writer wins (a finding is absorbed into one survivor only).
            mapping.setdefault(
                absorbed, {"survivor": survivor, "coupled": coupled}
            )
    for m in _DEDUP_MECHANICAL_ROW_RE.finditer(text):
        absorbed = _norm(m.group(1))
        survivor = _norm(m.group(2))
        coupled = re.sub(r"\s+", " ", (m.group(3) or "").strip())
        if absorbed and survivor and absorbed != survivor:
            mapping.setdefault(
                absorbed, {"survivor": survivor, "coupled": coupled}
            )
    return mapping


def _write_dedup_absorbed_map(
    scratchpad: Path,
    mapping: dict[str, dict[str, str]],
) -> int:
    """Write the driver-owned ``dedup_absorbed_map.md`` sidecar.

    Chain Agent 1 reads this file (see prompts/shared/v2/phase4c-chain-agent1.md
    Inputs) and the mechanical chain baseline folds it into Constituent
    Findings. Each row records an absorbed ID, its survivor, and the absorbed
    finding's distinct coupled content so no attack path / route / impact is
    lost when the survivor is consolidated. Returns the number of rows written.
    """
    scratchpad = Path(scratchpad)
    lines = [
        "# Dedup Absorbed Map",
        "",
        "**Status**: DRIVER_PROPAGATION",
        "",
        "Driver-written record of semantic-dedup merges. Each row is an "
        "`Absorbed ID -> Survivor ID` consolidation. Chain Agent 1 MUST record "
        "every Absorbed ID as a Constituent Finding of its Survivor's "
        "hypothesis and preserve the absorbed finding's distinct attack path / "
        "route / call-site / impact in the survivor hypothesis description so "
        "the tier-writer Rule 10 path couples both with ZERO DATA LOSS. Do NOT "
        "re-create an Absorbed ID as its own standalone hypothesis.",
        "",
        "| Absorbed ID | Survivor ID | Coupled Distinct Content |",
        "|-------------|-------------|--------------------------|",
    ]
    n = 0
    for absorbed in sorted(mapping):
        info = mapping[absorbed]
        survivor = info.get("survivor", "")
        coupled = (info.get("coupled") or "").replace("|", "/").strip()
        if not survivor:
            continue
        lines.append(f"| {absorbed} | {survivor} | {coupled} |")
        n += 1
    if n == 0:
        lines.append("| (none) | (none) | no dedup merges recorded |")
    (scratchpad / "dedup_absorbed_map.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return n


# Column 1 = source finding ID, column 2 = mapped hypothesis ID. The hypothesis
# column is NOT restricted to ``H-``/``CH-`` — real pipelines emit severity-
# prefixed hypothesis IDs (``HC-01``, ``HH-01``, ``HM-01``, ``HL-``, ``HI-``,
# ``CH-``). Accepting any ``<PREFIX>-<num>`` token here is RECALL-SAFE for the
# coverage seed: it only ever ADDS the column-1 source IDs to the superset (a
# narrower pattern silently dropped every INV-* source ID whenever the
# hypothesis prefix was multi-letter, which is the common case).
# Finding-mapping rows are `| <source-id> | <hypothesis-id> |`. IDs span many
# formats across modes: SC `INV-041`/`H-22`/`CH-1`/`HL-05`, and L1
# severity-encoded `H-C01`/`H-M27`/`L1-H-12`. A `[A-Za-z]+-\d+` pattern silently
# DROPS the severity-encoded L1 forms (digits not immediately after the dash) →
# coverage-seed under-counts an L1 report. Match the general ID shape instead:
# starts with a letter, contains at least one dash, ends with a digit (so any
# letter/number-segmented ID is captured), per feedback_id_regex_catalog
# (catalog ALL formats; permissive capture, not prefix enumeration).
_FINDING_MAPPING_ROW_RE = re.compile(
    r"^\|\s*([A-Za-z][A-Za-z0-9-]*\d)\s*\|\s*([A-Za-z][A-Za-z0-9-]*\d)\s*\|",
    re.MULTILINE,
)


def _write_report_index_coverage_seed(scratchpad: Path) -> int:
    """Write the driver-owned ``report_index_coverage_seed.md``.

    This is the mechanical completeness backbone for the report_index phase. It
    enumerates EVERY finding/hypothesis ID from BOUNDED, driver-written ledgers
    (the verification queue + computed severities, the dedup absorbed->survivor
    map, and finding_mapping) so the Index Agent never has to re-derive the ID
    set by bulk-reading the 100K+ ``findings_inventory.md`` — the exact context
    -collapse trigger this artifact exists to remove.

    Recall-safety: the seed is a SUPERSET — it lists every ID present in any of
    the bounded sources. Coverage/completeness is still enforced by the existing
    Step 6a.1 gate (``hypothesis_count == report_ids + excluded + consolidated``)
    and STEP 5.5 ledger, which now run over a bounded ID list rather than over
    finding prose. Returns the number of seed rows written.
    """
    scratchpad = Path(scratchpad)

    # 1. Per-finding expected severity from the bounded verification queue.
    try:
        sev_map = _expected_report_index_severities(scratchpad)
    except Exception:
        sev_map = {}

    # 2. Per-finding verdict + mapped hypothesis from the verification queue.
    #    Also capture the raw queue Severity column as a routing fallback: the
    #    severity-matrix sev_map can return a conservative default (Low) when a
    #    verify file is missing, but the queue Severity is the always-present
    #    bounded signal. Tier-shard routing prefers the matrix severity when set
    #    and falls back to the queue severity so shards stay accurately partitioned.
    verdict_map: dict[str, str] = {}
    queue_sev_map: dict[str, str] = {}
    try:
        for row in parse_verification_queue_rows(scratchpad):
            fid = (row.get("finding id") or "").strip().upper()
            if not fid:
                continue
            verdict_map[fid] = (
                row.get("verdict")
                or row.get("status")
                or row.get("preferred verification")
                or ""
            ).strip()
            qsev = (row.get("severity") or "").strip()
            if qsev:
                queue_sev_map[fid] = qsev
    except Exception:
        pass

    # 3. finding_id -> hypothesis_id from finding_mapping.md (bounded).
    hyp_map: dict[str, str] = {}
    try:
        fm_path = scratchpad / "finding_mapping.md"
        if fm_path.is_file():
            fm_text = fm_path.read_text(encoding="utf-8", errors="replace")
            for m in _FINDING_MAPPING_ROW_RE.finditer(fm_text):
                hyp_map.setdefault(
                    m.group(1).strip().upper(), m.group(2).strip().upper()
                )
    except Exception:
        pass

    # 4. absorbed -> survivor relations from the dedup decisions (bounded).
    try:
        absorbed_map = _dedup_absorbed_survivor_mapping(scratchpad)
    except Exception:
        absorbed_map = {}

    # 5. Force-include justified High/Critical chains (and their constituents)
    #    REGARDLESS of mode. A chain upgraded ABOVE its constituents (e.g.
    #    PARTIAL/Low → High via a justified Combined-Impact) would otherwise
    #    never be promoted to the verify queue / body in any mode. Purely
    #    additive to the seed superset — ADD-only, never demotes/drops.
    try:
        forced_chains = _forced_chain_seed_rows(scratchpad)
    except Exception:
        forced_chains = {}

    # Union of every ID that appears in any bounded source. This is the
    # authoritative completeness set — a SUPERSET, never a filtered subset.
    all_ids: set[str] = set()
    all_ids.update(sev_map.keys())
    all_ids.update(verdict_map.keys())
    all_ids.update(hyp_map.keys())
    for absorbed, info in absorbed_map.items():
        all_ids.add(absorbed)
        surv = (info or {}).get("survivor", "")
        if surv:
            all_ids.add(surv.upper())
    for cid, info in forced_chains.items():
        all_ids.add(cid)
        # Record the chain's upgraded severity in the seed (only when the
        # severity-matrix sev_map did not already carry a value for it).
        sev_map.setdefault(cid, str((info or {}).get("severity", "")))
        for con in (info or {}).get("constituents", []) or []:
            all_ids.add(con)

    lines = [
        "# Report Index Coverage Seed",
        "",
        "**Status**: DRIVER_ENUMERATED",
        "",
        "Driver-enumerated ID list of EVERY finding/hypothesis from bounded "
        "ledgers (verification queue, severity binding, finding_mapping, dedup "
        "absorbed map). The Index Agent MUST account for every ID below in the "
        "Master Finding Index or the Excluded Findings / Consolidation Map. "
        "This is the mechanical completeness backbone — enumerate the full ID "
        "set from HERE, not by bulk-reading findings_inventory.md.",
        "",
        "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |",
        "|----------------|-------------------|---------|-------------------|----------------|",
    ]
    n = 0
    for fid in sorted(all_ids, key=lambda x: x.upper()):
        sev = sev_map.get(fid, "")
        verdict = verdict_map.get(fid, "")
        hyp = hyp_map.get(fid, "")
        relation = ""
        if fid in absorbed_map:
            surv = (absorbed_map[fid] or {}).get("survivor", "")
            relation = f"ABSORBED into {surv}" if surv else ""
        else:
            absorbed_into_this = [
                a for a, info in absorbed_map.items()
                if (info or {}).get("survivor", "").upper() == fid
            ]
            if absorbed_into_this:
                relation = "SURVIVOR of " + ",".join(sorted(absorbed_into_this))
        lines.append(
            f"| {fid} | {sev} | {verdict} | {hyp} | {relation} |"
        )
        n += 1
    if n == 0:
        lines.append("| (none) | | | | no bounded IDs found |")
    (scratchpad / "report_index_coverage_seed.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    # R3/R4 (TASK C): tier-shard the coverage seed so the report_index LLM can
    # process one tier-batch at a time and NEVER hold the whole working set in
    # a single turn (the context-collapse trigger that froze a prior run ~27min).
    # Completeness stays guaranteed mechanically because every seed row lands in
    # exactly one tier shard (full seed == union of shards, zero drops) and the
    # post-phase reconciliation gate (_check_index_completeness) validates the
    # merged report_index.md against the FULL seed superset.
    try:
        _write_report_index_seed_shards(
            scratchpad,
            seed_rows=[
                {
                    "id": fid,
                    "severity": sev_map.get(fid, ""),
                    # Routing severity: take the MORE-SEVERE of the matrix sev_map
                    # and the raw queue Severity. The matrix defaults to Low when
                    # a verify file is absent; the queue Severity is the always-
                    # present bounded signal. Routing UP never drops a finding
                    # (the gate reconciles the full seed regardless of tier), so
                    # using the max keeps a Critical/High finding in its tier even
                    # if the matrix conservatively reported Low.
                    "route_severity": _more_severe_label(
                        sev_map.get(fid, ""), queue_sev_map.get(fid, "")
                    ),
                    "verdict": verdict_map.get(fid, ""),
                    "hyp": hyp_map.get(fid, ""),
                    "absorbed_map": absorbed_map,
                }
                for fid in sorted(all_ids, key=lambda x: x.upper())
            ],
        )
    except Exception as exc:  # best-effort: shards are a convenience layer
        log.warning(f"[report_index] seed-shard partition skipped: {exc!r}")
    return n


# Coverage-seed tier shards. Each shard is a BOUNDED subset of
# report_index_coverage_seed.md restricted to one report tier-batch, so the
# Index Agent processes STEP 1.5 consolidation + STEP 5/5.5 coverage over a
# small ID list per turn instead of the full set. The driver owns the
# partition (severity -> tier) and the post-phase reconciliation, so the LLM
# can never let a finding fall between shards.
_REPORT_INDEX_TIER_SHARDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("critical_high", ("Critical", "High")),
    ("medium", ("Medium",)),
    ("low_info", ("Low", "Informational", "Info")),
)


def _more_severe_label(a: str, b: str) -> str:
    """Return whichever severity label is MORE severe (recall-safe routing).

    Used to pick a tier-shard routing severity from two bounded signals (the
    severity-matrix map and the raw queue Severity). Routing a finding to a
    higher tier never drops it — the completeness gate reconciles the full seed
    regardless of which shard a row landed in — so taking the max keeps a
    Critical/High finding in its tier even when one signal is conservative.
    """
    ra, rb = severity_rank(a), severity_rank(b)
    if rb > ra:
        return b
    return a or b


def _report_index_tier_for_severity(severity: str) -> str:
    """Map an expected severity string to its coverage-seed tier-shard key.

    Unknown / blank severities route to ``low_info`` so an under-classified row
    is never dropped from the shard partition — it still gets exactly one
    disposition and the reconciliation gate over the full seed catches drift.
    """
    sev = (severity or "").strip().lower()
    for tier, names in _REPORT_INDEX_TIER_SHARDS:
        if any(sev == n.lower() for n in names):
            return tier
    return "low_info"


def _write_report_index_seed_shards(
    scratchpad: Path, seed_rows: list[dict]
) -> dict[str, int]:
    """Partition the coverage seed into per-tier shard files.

    Returns {tier_key: row_count}. Every seed row lands in exactly ONE shard
    (partition, not overlap), so ``union(shards) == full seed`` mechanically.
    The Index Agent reads one shard per turn; the driver assembles the merged
    report_index.md and reconciles it against the FULL seed afterward.
    """
    scratchpad = Path(scratchpad)
    buckets: dict[str, list[dict]] = {t: [] for t, _ in _REPORT_INDEX_TIER_SHARDS}
    for row in seed_rows:
        route_sev = row.get("route_severity") or row.get("severity", "")
        tier = _report_index_tier_for_severity(route_sev)
        buckets[tier].append(row)

    counts: dict[str, int] = {}
    for tier, _names in _REPORT_INDEX_TIER_SHARDS:
        rows = buckets[tier]
        lines = [
            f"# Report Index Coverage Seed — Tier Shard: {tier}",
            "",
            "**Status**: DRIVER_ENUMERATED",
            "",
            "Bounded per-tier slice of report_index_coverage_seed.md. Process "
            "this shard's IDs in ONE turn: run STEP 1.5 consolidation and STEP "
            "5/5.5 coverage over THESE IDs only, then move to the next tier "
            "shard. Do NOT hold every tier's working set at once — that is the "
            "context-collapse trigger this partition removes. Every ID below "
            "MUST receive exactly one disposition (report ID, exclusion, or "
            "consolidation) in report_index.md.",
            "",
            "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |",
            "|----------------|-------------------|---------|-------------------|----------------|",
        ]
        for row in rows:
            fid = row["id"]
            absorbed_map = row.get("absorbed_map") or {}
            relation = ""
            if fid in absorbed_map:
                surv = (absorbed_map[fid] or {}).get("survivor", "")
                relation = f"ABSORBED into {surv}" if surv else ""
            else:
                absorbed_into_this = [
                    a for a, info in absorbed_map.items()
                    if (info or {}).get("survivor", "").upper() == fid.upper()
                ]
                if absorbed_into_this:
                    relation = "SURVIVOR of " + ",".join(sorted(absorbed_into_this))
            lines.append(
                f"| {fid} | {row.get('severity', '')} | {row.get('verdict', '')} "
                f"| {row.get('hyp', '')} | {relation} |"
            )
        if not rows:
            lines.append("| (none) | | | | no IDs in this tier |")
        (scratchpad / f"report_index_seed_{tier}.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        counts[tier] = len(rows)
    return counts


def _run_gate_v_for_phase(phase_name: str, scratchpad: Path) -> dict:
    """Gate V (Fix A, recall) driver entry: 3-axis Variant-Family Coverage.

    Axis 1 (co-reference) is the existing G1/G2 gate (`run_enumeration_gate`,
    called separately, immediately before this) — UNCHANGED. Axes 2
    (boundary-input) and 3 (symmetric-operation), reached via
    `enumeration_gate.compute_variant_gaps`, are additive derivers over the
    same `_mechanical_graph.json` + `chain_candidate_pairs.md` data, emitted
    through the SAME append-only, idempotent inventory path. Unconditional
    (not Thorough-only, not confidence-gated) — a confidently-wrong agent is
    exactly the failure mode this closes.

    Never raises; a no-op (returns `{"emitted": 0}`) when the graph or the
    chain-candidate-pairs file is absent, mirroring `enumeration_gate`'s own
    no-op contract. Wired into `_run_phase_validators`'s L1 and SC
    depth-phase post-processing branches, immediately after
    `run_enumeration_gate`.
    """
    try:
        import enumeration_gate as _eg
        res = _eg.compute_variant_gaps(scratchpad)
    except Exception as exc:
        log.warning(
            f"[{phase_name}] variant gate skipped (non-blocking): {exc}"
        )
        return {"emitted": 0}
    if res.get("emitted"):
        log.info(
            f"[{phase_name}] variant gate: emitted {res['emitted']} "
            f"VARGAP candidate(s) (axis2/boundary="
            f"{res.get('axis2_emitted', 0)}, axis3/symmetric="
            f"{res.get('axis3_emitted', 0)}) for verification"
        )
    return res


# ─────────────────────────────────────────────────────────────────────────
# Gate P (Fix C, recall): coverage-seed backfill for promotion-gate output.
#
# `route_promotion_orphans` (plamen_mechanical.py) appends BODY-disposed
# orphans to `findings_inventory.md` as fresh `INV-NNN` NEEDS_VERIFICATION
# candidates AFTER `report_index_coverage_seed.md` has already been written
# (Gate P reconciles against the seed, so it must run after the seed exists —
# see `compute_promotion_orphans`'s no-op-when-seed-absent contract). Left
# alone, those new IDs would be invisible to the Index Agent's STEP 5
# completeness check, which is told to enumerate from the bounded seed/shards
# rather than bulk-reading `findings_inventory.md`.
#
# This helper closes that gap the same way the rest of the coverage-seed
# machinery does: a pure ADDITIVE, idempotent superset append — never
# rewrites or removes an existing row, never touches severity/verdict of any
# other finding. It is a convenience backfill only: even if it fails or is
# skipped, the PROMOGAP findings still physically exist in
# `findings_inventory.md` and are not lost (recall-safe by construction).
# ─────────────────────────────────────────────────────────────────────────

_PROMOGAP_SECTION_RE = re.compile(
    r"##\s*Promotion-Completeness Candidates \(PROMOGAP\)(.*?)(?=\n##\s|\Z)",
    re.DOTALL,
)
_PROMOGAP_BLOCK_RE = re.compile(
    r"###\s*Finding\s*\[(INV-\d+)\][^\n]*\n"
    r"\*\*Severity\*\*:\s*([^\n]*)\n"
    r".*?\*\*Verdict\*\*:\s*([^\n]*)",
    re.DOTALL,
)


def _append_promogap_ids_to_coverage_seed(scratchpad: Path) -> int:
    """Additively backfill newly-emitted PROMOGAP IDs into the coverage seed.

    Scans the `## Promotion-Completeness Candidates (PROMOGAP)` section of
    `findings_inventory.md` (bounded — only that section, never the full
    100K+ file) for `### Finding [INV-NNN]:` blocks, and appends one seed row
    per ID not already present in `report_index_coverage_seed.md` (both the
    flat file and its matching tier shard). Idempotent: a second call with no
    new PROMOGAP IDs appends nothing. Never raises; any failure degrades to
    "no backfill" — the findings remain in `findings_inventory.md` regardless.
    Returns the number of IDs newly added to the seed.
    """
    scratchpad = Path(scratchpad)
    inv_path = scratchpad / "findings_inventory.md"
    seed_path = scratchpad / "report_index_coverage_seed.md"
    if not inv_path.exists() or not seed_path.exists():
        return 0
    try:
        inv_text = inv_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    sect_m = _PROMOGAP_SECTION_RE.search(inv_text)
    if not sect_m:
        return 0
    section = sect_m.group(1)

    try:
        seed_text = seed_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    existing_ids = {m.group(0).upper() for m in re.finditer(r"\bINV-\d+\b", seed_text)}

    new_rows: list[tuple[str, str, str]] = []  # (id, severity, tier)
    for m in _PROMOGAP_BLOCK_RE.finditer(section):
        fid = m.group(1).strip().upper()
        if fid in existing_ids:
            continue
        existing_ids.add(fid)
        sev = m.group(2).strip() or "Medium"
        tier = _report_index_tier_for_severity(sev)
        new_rows.append((fid, sev, tier))

    if not new_rows:
        return 0

    try:
        seed_lines = seed_text.rstrip("\n").split("\n")
        # Drop a lone "no bounded IDs found" placeholder row before appending
        # real rows so the seed table stays well-formed.
        seed_lines = [
            ln for ln in seed_lines
            if "no bounded IDs found" not in ln
        ]
        for fid, sev, _tier in new_rows:
            seed_lines.append(f"| {fid} | {sev} | NEEDS_VERIFICATION | | |")
        seed_path.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
    except Exception:
        return 0

    # Best-effort: also backfill the matching tier-shard file so the Index
    # Agent's per-tier-batch pass sees the row too. A failure here only loses
    # the tier-shard convenience copy; the flat seed above is the primary
    # completeness source and already carries the row.
    by_tier: dict[str, list[tuple[str, str]]] = {}
    for fid, sev, tier in new_rows:
        by_tier.setdefault(tier, []).append((fid, sev))
    for tier, rows in by_tier.items():
        shard_path = scratchpad / f"report_index_seed_{tier}.md"
        if not shard_path.exists():
            continue
        try:
            shard_text = shard_path.read_text(encoding="utf-8", errors="replace")
            shard_lines = shard_text.rstrip("\n").split("\n")
            shard_lines = [
                ln for ln in shard_lines if "no IDs in this tier" not in ln
            ]
            for fid, sev in rows:
                shard_lines.append(f"| {fid} | {sev} | NEEDS_VERIFICATION | | |")
            shard_path.write_text("\n".join(shard_lines) + "\n", encoding="utf-8")
        except Exception:
            continue

    return len(new_rows)


def _run_gate_p_for_report_index(scratchpad: Path) -> dict:
    """Gate P (Fix C, recall) driver entry: content-shaped Promotion
    Completeness (Class C pipeline-loss).

    Calls `compute_promotion_orphans` + `route_promotion_orphans`
    (plamen_mechanical.py) and, when any orphan was routed to the report
    BODY, additively backfills its ID into `report_index_coverage_seed.md`
    so the Index Agent's completeness check still finds it. Never raises —
    any failure logs a warning and returns the zeroed result shape (mirrors
    `route_promotion_orphans`'s own graph/ledger-absent no-op contract).

    Wired into `main()`'s shared `report_index` pre-hook, immediately after
    `_write_report_index_coverage_seed` (Gate P reconciles against that
    seed, so it must run after the seed exists) and before the LLM Index
    Agent spawns — i.e. "before report" per the design.
    """
    scratchpad = Path(scratchpad)
    zero_result = {
        "harvested": 0, "body_candidates": 0, "appendix_c": 0,
        "appendix_a": 0, "emitted_to_inventory": 0,
    }
    try:
        orphans = compute_promotion_orphans(scratchpad)
        result = route_promotion_orphans(scratchpad, orphans)
    except Exception as exc:
        log.warning(
            f"[report_index] promotion gate skipped (non-blocking): {exc}"
        )
        return zero_result
    if result.get("harvested"):
        log.info(
            f"[report_index] promotion gate: harvested "
            f"{result['harvested']} orphan(s) -> "
            f"{result.get('emitted_to_inventory', 0)} to body "
            f"(NEEDS_VERIFICATION), {result.get('appendix_c', 0)} "
            f"to Appendix C, {result.get('appendix_a', 0)} to "
            "Appendix A (see promotion_orphans.md / promotion_routing.md)"
        )
    if result.get("emitted_to_inventory"):
        try:
            backfilled = _append_promogap_ids_to_coverage_seed(scratchpad)
            if backfilled:
                log.info(
                    f"[report_index] backfilled {backfilled} PROMOGAP "
                    "ID(s) into report_index_coverage_seed.md"
                )
        except Exception as exc:
            log.warning(
                "[report_index] PROMOGAP coverage-seed backfill failed "
                f"(non-blocking): {exc!r}"
            )
    return result


# ─────────────────────────────────────────────────────────────────────────
# Hook-4 (Fix B, recall): haltless WARN gate for uncited external-dependency
# research assumptions.
#
# Mirrors the existing report_index/verify completeness asserts: a pure
# telemetry scan that never blocks a phase, never mutates a finding's
# severity or disposition, and degrades to a no-op when its source artifacts
# are absent. Reads `findings_inventory.md` + `verify_*.md` for findings
# whose severity leans on an `[EXTERNAL-ASSUMPTION: ...]` tag (R10 burden-
# inversion) or whose Location falls inside a `file:line` recorded in
# `external_dependency_research.md`'s Integration Surface column (Hook 1's
# recon-baked research ledger), and flags any such finding that lacks a
# matching `[EXT-CITED: ...]` reference or a `NEEDS_DEPENDENCY_RESEARCH`
# escalation line. Writes `external_research_gaps.md`.
# ─────────────────────────────────────────────────────────────────────────

_ERG_FINDING_BLOCK_RE = re.compile(
    r"(?:^|\n)#{2,3}\s*Finding\s*\[([A-Za-z0-9\-]+)\][^\n]*\n"
    r"(.*?)(?=\n#{2,3}\s*Finding\s*\[|\Z)",
    re.DOTALL,
)
_ERG_LOCATION_RE = re.compile(r"\*\*Location\*\*:\s*`?([^`\n]+?)`?\s*(?:\n|$)")
_ERG_SURFACE_ROW_RE = re.compile(
    r"^\|\s*`?([^|`]+?)`?\s*\|\s*([^|]+?)\s*\|", re.MULTILINE
)
_ERG_LOC_TOKEN_RE = re.compile(r"[\w./\\-]+\.[A-Za-z]+:L?\d+")


def _external_dependency_research_surfaces(
    scratchpad: Path,
) -> list[tuple[str, str]]:
    """Parse `external_dependency_research.md`'s Integration Surface column.

    Returns a list of (dependency, file:line) pairs, one per surface token
    found in each ledger row. Never raises; returns [] when the ledger is
    absent or unparseable (recall-neutral no-op — Hook-4 simply has nothing
    to cross-reference for the location axis, the [EXTERNAL-ASSUMPTION] tag
    axis still runs independently).
    """
    scratchpad = Path(scratchpad)
    path = scratchpad / "external_dependency_research.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    for m in _ERG_SURFACE_ROW_RE.finditer(text):
        dep = m.group(1).strip()
        if not dep or dep.lower() in (
            "dependency", "---", "name/namespace", "-", ""
        ):
            continue
        surfaces_cell = m.group(2)
        for loc in _ERG_LOC_TOKEN_RE.findall(surfaces_cell):
            out.append((dep, loc))
    return out


def _check_external_research_citation_gaps(scratchpad: Path) -> int:
    """Hook-4 driver entry: scan for uncited external-assumption findings.

    Never raises. Idempotent (rewrites the ledger from current state each
    call, so resume never accumulates duplicate rows). Returns the number of
    gap rows written to `external_research_gaps.md`.
    """
    scratchpad = Path(scratchpad)
    try:
        surfaces = _external_dependency_research_surfaces(scratchpad)
    except Exception:
        surfaces = []

    sources: list[tuple[str, str]] = []  # (source_label, text)
    inv_path = scratchpad / "findings_inventory.md"
    if inv_path.exists():
        try:
            sources.append(
                ("findings_inventory.md",
                 inv_path.read_text(encoding="utf-8", errors="replace"))
            )
        except Exception:
            pass
    try:
        for vf in sorted(scratchpad.glob("verify_*.md")):
            try:
                sources.append(
                    (vf.name, vf.read_text(encoding="utf-8", errors="replace"))
                )
            except Exception:
                continue
    except Exception:
        pass

    gap_rows: list[tuple[str, str, str, str]] = []  # fid, dep, location, reason
    seen_keys: set[tuple[str, str]] = set()
    for source_label, text in sources:
        try:
            for m in _ERG_FINDING_BLOCK_RE.finditer(text):
                fid = m.group(1).strip()
                block = m.group(2)
                has_assumption = "[EXTERNAL-ASSUMPTION" in block
                loc_m = _ERG_LOCATION_RE.search(block)
                loc = loc_m.group(1).strip() if loc_m else ""
                matched_dep = ""
                if loc:
                    for dep, surf in surfaces:
                        if surf and surf in loc:
                            matched_dep = dep
                            break
                if not has_assumption and not matched_dep:
                    continue
                if "[EXT-CITED" in block or "NEEDS_DEPENDENCY_RESEARCH" in block:
                    continue
                key = (fid, loc or source_label)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                reason = (
                    "uncited [EXTERNAL-ASSUMPTION] tag" if has_assumption
                    else "location within a researched external-dependency "
                         "integration surface, uncited"
                )
                gap_rows.append((fid, matched_dep or "(unnamed)", loc or "-", reason))
        except Exception:
            continue

    lines = [
        "# External-Dependency Research Gaps",
        "",
        "Hook-4 (Fix B) haltless WARN gate. Findings listed below either carry "
        "an `[EXTERNAL-ASSUMPTION: ...]` tag or sit at a location inside a "
        "researched external-dependency integration surface, WITHOUT a "
        "matching `[EXT-CITED: ...]` citation or `NEEDS_DEPENDENCY_RESEARCH` "
        "escalation. This never changes a finding's severity or disposition "
        "— it is an advisory flag only: recommend manual verification of the "
        "assumed external behavior before relying on the reported severity.",
        "",
        "| Finding ID | Dependency | Integration Surface | Reason |",
        "|------------|------------|----------------------|--------|",
    ]
    for fid, dep, loc, reason in gap_rows:
        lines.append(f"| {fid} | {dep} | `{loc}` | {reason} |")
    if not gap_rows:
        lines.append("| (none) | | | no uncited external-assumption findings |")
    try:
        (scratchpad / "external_research_gaps.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except Exception:
        pass
    return len(gap_rows)


def _append_external_research_appendix_note(
    scratchpad: Path, project_root: Path
) -> int:
    """Surface Hook-4's gap ledger as an Appendix note on the assembled report.

    Reuses the report_floor phase's existing role as the driver-owned,
    post-assembly `AUDIT_REPORT.md` mutator (the same mechanism that relocates
    Appendix C content via the material-harm floor) rather than inventing a
    new report-generation path. Advisory-only: never changes a finding's
    severity, verdict, or body/appendix disposition — it only appends a note.
    Idempotent (checks for its own heading before appending). Never raises;
    a missing ledger, missing report, or any I/O failure is a silent no-op.
    Returns the number of gap rows surfaced (0 if none / no-op).
    """
    scratchpad = Path(scratchpad)
    project_root = Path(project_root)
    ledger_path = scratchpad / "external_research_gaps.md"
    report_path = project_root / "AUDIT_REPORT.md"
    if not ledger_path.exists() or not report_path.exists():
        return 0
    try:
        ledger_text = ledger_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    rows = re.findall(
        r"^\|\s*([A-Za-z0-9\-]+)\s*\|.*\|$", ledger_text, re.MULTILINE
    )
    # Exclude the "(none)" sentinel row and markdown table divider rows
    # (`|---|---|...|` — the capture group is all hyphens, which otherwise
    # false-matches `[A-Za-z0-9\-]+` and would make every EMPTY ledger look
    # non-empty).
    rows = [
        r for r in rows
        if r and r != "(none)" and not re.fullmatch(r"-+", r)
    ]
    if not rows:
        return 0
    try:
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    heading = "## Appendix D: External-Dependency Research Gaps (Advisory)"
    if heading in report_text:
        return 0
    note = (
        f"\n\n{heading}\n\n"
        "The following findings rely on an assumed worst-case external-"
        "dependency behavior (per R10) without a citation to researched "
        "real-world dependency semantics. This is an advisory note only — it "
        "does not change any finding's reported severity or disposition. "
        "Recommend manual verification of the named external dependency's "
        "actual behavior before relying on the assumed-worst-case severity.\n\n"
        f"Affected finding(s): {', '.join(sorted(set(rows)))}\n"
    )
    try:
        report_path.write_text(report_text.rstrip("\n") + note, encoding="utf-8")
    except Exception:
        return 0
    return len(rows)


def _propagate_dedup_absorbed_to_finding_mapping(scratchpad: Path) -> int:
    """Record dedup-absorbed IDs as constituents of their survivor's hypothesis.

    Runs at the dedup post-swap boundary. Two coupling paths, both additive
    (never drops a finding):

    1. ALWAYS writes the driver-owned ``dedup_absorbed_map.md`` sidecar that
       Chain Agent 1 reads and the mechanical chain baseline folds in. This
       guarantees the coupling reaches the report even when chain has not run
       yet at dedup time (the normal SC/L1 ordering: dedup -> chain).
    2. When ``finding_mapping.md`` ALREADY exists (resume after chain, or a
       prior run), it additionally records every absorbed ID as a constituent
       row of its survivor's hypothesis IN-PLACE, so the coupling survives even
       if chain consolidated differently than the dedup survivor mapping.

    Returns the number of absorbed->survivor relationships propagated.
    """
    scratchpad = Path(scratchpad)
    mapping = _dedup_absorbed_survivor_mapping(scratchpad)
    # Always (re)write the sidecar — even an empty one is a clear signal to the
    # chain baseline that propagation ran and there were no merges.
    _write_dedup_absorbed_map(scratchpad, mapping)
    if not mapping:
        return 0

    fm_path = scratchpad / "finding_mapping.md"
    if not fm_path.is_file():
        # Chain has not run yet (normal ordering). The sidecar is the bridge;
        # the chain baseline / Chain Agent 1 will fold it in. Nothing to edit
        # in-place yet.
        return len(mapping)

    try:
        fm_text = fm_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return len(mapping)

    # Build survivor_id -> hypothesis_id from existing finding_mapping rows:
    #   | <finding_id> | <hypothesis_id> | <status> | <notes> |
    # Both columns use the widened / unified ID shapes so severity-encoded L1
    # hypothesis IDs (H-C01, HC-01, L1-H-12) and multi-segment finding IDs are
    # not silently skipped — the same ID-format-too-narrow drop class fixed for
    # the AXIS/CI promoters. Column 2 reuses _ID_HYPO_ALTS (no capture groups).
    row_re = re.compile(
        r"^\|\s*([A-Za-z0-9]+(?:-[A-Za-z0-9]+)+)\s*\|\s*(" + _ID_HYPO_ALTS + r")\s*\|",
        re.MULTILINE,
    )
    survivor_to_hyp: dict[str, str] = {}
    existing_finding_ids: set[str] = set()
    for m in row_re.finditer(fm_text):
        fid = m.group(1).strip().upper()
        hid = m.group(2).strip().upper()
        existing_finding_ids.add(fid)
        survivor_to_hyp.setdefault(fid, hid)

    new_rows: list[str] = []
    propagated = 0
    for absorbed, info in sorted(mapping.items()):
        survivor = info.get("survivor", "")
        if not survivor:
            continue
        if absorbed in existing_finding_ids:
            # Already mapped (e.g., chain re-added it); leave as-is.
            continue
        hid = survivor_to_hyp.get(survivor)
        if not hid:
            # Survivor itself isn't in finding_mapping (chain dropped/renamed
            # it). Fall back to a self-hypothesis row so the absorbed lineage
            # is still recorded — never silently drop.
            hid = survivor_to_hyp.get(survivor.upper()) or "H-DEDUP"
        coupled = (info.get("coupled") or "").replace("|", "/").strip()
        note = (
            f"DEDUP_CONSTITUENT of {survivor}"
            + (f"; coupled: {coupled}" if coupled else "")
        )
        new_rows.append(
            f"| {absorbed} | {hid} | DEDUP_ABSORBED | {note} |"
        )
        propagated += 1

    if new_rows:
        addition = (
            "\n<!-- dedup-absorbed constituents propagated by driver -->\n"
            + "\n".join(new_rows)
            + "\n"
        )
        fm_path.write_text(fm_text.rstrip("\n") + "\n" + addition, encoding="utf-8")
    return propagated


def _build_dedup_round_exclusion_block(scratchpad: Path) -> str:
    """Build the ``## Already-decided exclusion list`` carry-forward block.

    Reads decisions already recorded in ``dedup_decisions.md`` (from prior
    rounds) and lists every pair/ID already decided so the next round does NOT
    re-decide them. Per-pair judgment is preserved (each pair is decided exactly
    once); this only prevents oscillation/double-deciding across rounds.
    """
    decided_ids: set[str] = set()
    mapping = _dedup_absorbed_survivor_mapping(scratchpad)
    for absorbed, info in mapping.items():
        decided_ids.add(absorbed)
        if info.get("survivor"):
            decided_ids.add(info["survivor"])
    # Also harvest any explicitly-decided IDs (KEEP SEPARATE / GROUP / PASS)
    # from the decisions status table so they are not re-evaluated.
    dec_path = scratchpad / "dedup_decisions.md"
    if dec_path.is_file():
        try:
            dec_text = dec_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            dec_text = ""
        for m in re.finditer(
            r"^\|\s*([A-Za-z]+-\d+)\s*\|\s*"
            r"(?:KEEP\s+SEPARATE|GROUP|PASS|MERGED\b)",
            dec_text,
            re.MULTILINE | re.IGNORECASE,
        ):
            decided_ids.add(m.group(1).strip().upper())
    if not decided_ids:
        return ""
    lines = [
        "## Already-decided exclusion list",
        "",
        "These finding IDs were decided in a prior dedup round. Do NOT "
        "re-decide any pair that consists solely of IDs listed here — their "
        "decisions are already recorded in dedup_decisions.md. Evaluate only "
        "this round's candidate rows.",
        "",
    ]
    lines += [f"- {fid}" for fid in sorted(decided_ids)]
    lines += ["", "---", ""]
    return "\n".join(lines) + "\n"


def _stage_dedup_round_packet(scratchpad: Path, round_n: int) -> Optional[Path]:
    """Stage round-N's live packet for the dedup subprocess.

    Copies ``dedup_candidate_pairs_round{N}.md`` into the canonical live file
    ``dedup_candidate_pairs.md`` (which the subprocess reads) with the
    carry-forward ``## Already-decided exclusion list`` block prepended, and
    likewise stages the matching focus inventory. Returns the staged live path
    or None if the round file is absent.

    This is the bounded-OUTPUT mechanism: each round's subprocess sees only
    <=`_DEDUP_ROUND_CHUNK` candidate rows, but every pair is still per-pair
    LLM-judged. No merge is ever applied mechanically here.
    """
    scratchpad = Path(scratchpad)
    round_pairs = scratchpad / f"dedup_candidate_pairs_round{round_n}.md"
    if not round_pairs.is_file():
        return None
    try:
        body = round_pairs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    exclusion = _build_dedup_round_exclusion_block(scratchpad)
    live = scratchpad / "dedup_candidate_pairs.md"
    live.write_text(exclusion + body, encoding="utf-8")
    # Stage the matching focus inventory if present.
    round_focus = scratchpad / f"dedup_focus_inventory_round{round_n}.md"
    if round_focus.is_file():
        try:
            shutil.copy2(round_focus, scratchpad / "dedup_focus_inventory.md")
        except Exception:
            pass
    return live


def _dedup_round_files(scratchpad: Path) -> list[Path]:
    """Return the sorted list of per-round candidate-pair packets, if any."""
    scratchpad = Path(scratchpad)
    files = sorted(
        scratchpad.glob("dedup_candidate_pairs_round*.md"),
        key=lambda p: _dedup_round_index(p.name),
    )
    return files


def _dedup_round_index(name: str) -> int:
    m = re.search(r"round(\d+)\.md$", name)
    return int(m.group(1)) if m else 0


def _run_verify_recovery_shard(
    config: dict,
    missing: list[tuple[str, dict]],
) -> list[str]:
    """Run a one-shot recovery verification subprocess for dropped findings.

    v2.6.8: Before mechanical stubbing, attempt real verification for
    findings that verify shards failed to cover. Writes a recovery
    manifest, reads the standalone verification prompt, applies
    pruning, wraps with a recovery directive, and runs a subprocess.

    Returns the list of finding IDs that are STILL missing after recovery
    (i.e. the recovery shard also failed to produce them).
    """
    scratchpad = Path(config["scratchpad"])
    pipeline = config.get("pipeline", "sc")
    is_l1 = pipeline == "l1"

    # Write recovery manifest.
    recovery_rows = [row for _, row in missing]
    manifest_path = scratchpad / "verification_queue_recovery.md"
    _write_queue_subset_manifest(manifest_path, recovery_rows)

    # Build the recovery prompt from the standalone verification template.
    standalone_name = (
        "phase5-verification-l1.md" if is_l1
        else "phase5-verification-sc.md"
    )
    standalone_path = plamen_home() / "prompts" / "shared" / "v2" / standalone_name
    if not standalone_path.exists():
        log.warning(
            f"[verify_recovery] standalone prompt not found: {standalone_path} "
            f"— skipping recovery, will stub {len(missing)} findings"
        )
        return [fid for fid, _ in missing]

    try:
        base_prompt = standalone_path.read_text(encoding="utf-8")
    except Exception as e:
        log.warning(f"[verify_recovery] failed to read {standalone_path}: {e}")
        return [fid for fid, _ in missing]

    if is_l1:
        base_prompt = _prune_l1_verify_shard_prompt(base_prompt)
    else:
        base_prompt = _prune_sc_verify_shard_prompt(base_prompt)

    # Build the checklist of IDs the recovery shard must produce.
    id_checklist = []
    for fid, row in missing:
        title = re.sub(r"\s+", " ", row.get("title", "")).strip()
        sev = (row.get("severity") or "Medium").strip()
        id_checklist.append(f"- {fid} -> verify_{fid}.md | {sev} | {title[:120]}")
    checklist_block = "\n".join(id_checklist)

    # Wrap with recovery-specific directive.
    recovery_directive = (
        "# RECOVERY VERIFICATION SHARD\n\n"
        "You are a recovery verifier. The primary verify shards ran but "
        "failed to produce verify files for the findings below. Your job "
        "is to verify ONLY these findings. Do not produce output for "
        "findings not listed here.\n\n"
        f"## Recovery Manifest\n\n"
        f"Read the recovery manifest at: verification_queue_recovery.md\n\n"
        f"## Assigned Findings ({len(missing)} total)\n\n"
        f"{checklist_block}\n\n"
        f"## Instructions\n\n"
        f"For each finding above, create a verify_<ID>.md file following "
        f"the standard verification methodology below. Prioritize "
        f"Critical/High findings. If you run out of context budget, "
        f"produce as many verify files as possible in severity order.\n\n"
        f"---\n\n"
    )
    full_prompt = recovery_directive + base_prompt

    # Resolve model and timeout.
    effective_model = "sonnet"
    mode = config.get("mode", "core")
    if mode == "light":
        effective_model = "sonnet"
    timeout = scale_timeout(
        1800, config["project_root"], config["language"],
        mode=mode, hypothesis_count=len(missing),
    )

    # Write snapshot.
    snap = scratchpad / "_prompt_verify_recovery.attempt1.md"
    try:
        snap.write_text(full_prompt, encoding="utf-8")
    except Exception as e:
        log.warning(f"[verify_recovery] snapshot write failed: {e}")
        return [fid for fid, _ in missing]

    # Build subprocess command. Mirrors run_phase flags so verify-
    # recovery shards benefit from the same cache-reuse improvements.
    cmd = [
        CLAUDE_BIN, "-p",
        "--model", effective_model,
        "--output-format", "json",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
        "--exclude-dynamic-system-prompt-sections",
        "--add-dir", config["project_root"],
        "--add-dir", plamen_home().as_posix(),
    ]

    # Subprocess isolation (same as run_phase). Resolve to ABSOLUTE — the worker
    # runs with cwd=project_root and a relative `--settings` arg would resolve
    # against the worker cwd, "Settings file not found", every worker dies.
    isolation_path = (scratchpad / "_subprocess_isolation.json").resolve()
    isolation_ok = False
    try:
        isolation_payload = SUBPROCESS_ISOLATION_PAYLOAD
        if (
            not isolation_path.exists()
            or isolation_path.read_text(encoding="utf-8").strip()
            != isolation_payload
        ):
            isolation_path.write_text(isolation_payload, encoding="utf-8")
        isolation_ok = True
    except Exception:
        pass
    cmd.extend(["--disallowedTools", "mcp__*"])
    if isolation_ok:
        iso = isolation_path.as_posix()
        cmd.extend([
            "--settings", iso,
            "--strict-mcp-config", "--mcp-config", iso,
        ])

    # Subprocess env. Mirrors `run_phase`'s env composition — tool output
    # caps + context-editing beta — so verify-recovery shards benefit
    # from the same cost-cutting that main verify shards do. Recovery
    # shards run security-verifier (opus), making them prime candidates.
    _existing_beta_rec = os.environ.get("ANTHROPIC_BETA", "").strip()
    _our_beta_rec = "context-management-2025-06-27"
    _merged_beta_rec = (
        _existing_beta_rec + "," + _our_beta_rec
        if _existing_beta_rec and _our_beta_rec not in _existing_beta_rec
        else _our_beta_rec
    )
    subprocess_env = {
        **_filtered_child_subprocess_environ(),
        "ANTHROPIC_DISABLE_AUTOUPDATE": "1",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": PLAMEN_OPUS_MODEL,
        "PLAMEN_SCRATCHPAD": str(scratchpad),
        "BASH_MAX_OUTPUT_LENGTH": os.environ.get(
            "BASH_MAX_OUTPUT_LENGTH", "30000"
        ),
        "MAX_MCP_OUTPUT_TOKENS": os.environ.get(
            "MAX_MCP_OUTPUT_TOKENS", "8000"
        ),
        "ANTHROPIC_BETA": _merged_beta_rec,
    }

    # Platform-specific Popen kwargs.
    popen_kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        popen_kwargs["start_new_session"] = True

    log_path = scratchpad / "_stdio_verify_recovery.attempt1.log"
    start = time.monotonic()

    log.info(
        f"[verify_recovery] spawning recovery shard for {len(missing)} "
        f"findings (timeout={timeout}s, model={effective_model})"
    )

    with log_path.open("w", encoding="utf-8", errors="replace") as out, \
            snap.open("rb") as stdin_file:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_file, stdout=out, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                cwd=config["project_root"],
                env=subprocess_env,
                **popen_kwargs,
            )
        except Exception as e:
            log.warning(f"[verify_recovery] Popen failed: {e}")
            return [fid for fid, _ in missing]

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc, grace_s=10)
            log.warning(
                f"[verify_recovery] timed out after {timeout}s"
            )

    elapsed = time.monotonic() - start
    log.info(f"[verify_recovery] completed in {elapsed:.0f}s")

    # Check which findings are still missing after recovery.
    still_missing = []
    recovered = []
    for fid, row in missing:
        if _verify_file_present_for_id(scratchpad, fid, min_bytes=100):
            recovered.append(fid)
        else:
            still_missing.append(fid)

    if recovered:
        log.info(
            f"[verify_recovery] recovered {len(recovered)}/{len(missing)} "
            f"verify files: {recovered[:8]}"
            + (f" (+{len(recovered) - 8} more)" if len(recovered) > 8 else "")
        )
    if still_missing:
        log.warning(
            f"[verify_recovery] {len(still_missing)} findings still missing "
            f"after recovery: {still_missing[:8]}"
            + (f" (+{len(still_missing) - 8} more)" if len(still_missing) > 8 else "")
        )

    return still_missing


def _clear_stale_verify_retry_hint_after_reshard(
    scratchpad: Path,
    phase_name: str,
    assigned_rows: list[dict[str, str]],
) -> bool:
    """Drop verify retry hints whose IDs no longer belong to this shard.

    Verify shard manifests are regenerated on resume. After a shard-splitting
    fix, a prior retry hint can point at IDs that moved to a later shard; if
    injected, it steers the subprocess outside its current manifest.
    """
    if not assigned_rows:
        return False
    try:
        hint = _read_retry_hint(scratchpad, phase_name)
    except Exception:
        return False
    if not hint:
        return False

    assigned_ids = {
        str(row.get("finding id") or row.get("Finding ID") or "").strip().upper()
        for row in assigned_rows
    }
    assigned_ids.discard("")
    mentioned_ids = {m.group(0).upper() for m in _VERIFY_HINT_ID_RE.finditer(hint)}
    if mentioned_ids and assigned_ids and not mentioned_ids.issubset(assigned_ids):
        _clear_retry_hint(scratchpad, phase_name)
        log.info(
            f"[{phase_name}] cleared stale retry hint after verify re-shard; "
            f"hint_ids={sorted(mentioned_ids)[:8]} assigned_ids={sorted(assigned_ids)[:8]}"
        )
        return True
    return False


_HEARTBEAT_INTERVAL = 0.1  # seconds between proc.wait polls (governs spinner fps ~10)
_HEARTBEAT_DISPLAY_INTERVAL = 15  # seconds between heartbeat display lines
_ARTIFACT_SCAN_INTERVAL = 3  # seconds between scratchpad scans (avoid thrashing iterdir)
_EARLY_COMPLETE_IDLE_GRACE_SECONDS = int(os.environ.get(
    "PLAMEN_EARLY_COMPLETE_IDLE_SECONDS", "600"
))


_RUNAWAY_TOOL_RESULT_BYTES = 500_000
_TOOL_RESULT_SCAN_INTERVAL_S = 60.0


def _claude_project_dir_name(path) -> str:
    """Encode an absolute cwd the way Claude Code names its
    ``~/.claude/projects/<dir>`` session directory.

    Verified against on-disk dirs: ``D:\\Programming\\...\\repo`` ->
    ``D--Programming-...-repo``. Every non-alphanumeric char maps to a single
    ``-`` WITHOUT collapsing runs (``D:\\`` -> ``D--``).
    """
    return re.sub(r"[^A-Za-z0-9]", "-", os.path.abspath(str(path)))


def _scan_claude_tool_results_for_runaways(
    start_time: float, already_warned: set[str], scratchpad: Path
) -> list[tuple[str, int]]:
    """Detect single tool-result blobs exceeding the runaway threshold.

    A subagent that issues a Bash/Glob/Read against a huge directory (e.g.
    %TEMP%, $HOME, ~/.cache) can dump multi-MB results into the claude session's
    tool-results dir, which blocks the coordinator and produces no audit value.

    SCOPED to THE CURRENT RUN only. Claude keys its project dir by the
    coordinator's cwd, which is this run's PROJECT_ROOT == ``scratchpad.parent``.
    Earlier this scanned EVERY dir under ``~/.claude/projects/`` filtered only by
    mtime, so a *concurrent* audit (or a Codex run, which writes its sessions
    elsewhere entirely) would surface another run's huge tool-result and
    misattribute it to THIS phase ("a subagent likely read outside
    PROJECT_ROOT -- coordinator may stall"). Scoping to the current run's own
    project dir kills that cross-run false positive: on a Codex run the current
    run's Claude project dir has no fresh blobs (Codex doesn't write there), and
    a sibling Claude run's blobs live under a DIFFERENT encoded dir that is no
    longer scanned. If the current run's project dir can't be located, there are
    no current-run tool-results to police -- scanning others is pure
    false-positive risk with zero benefit, so return nothing.

    Returns list of (path, size) for newly-detected runaways. Mutates
    already_warned so each path is reported once.
    """
    try:
        projects = Path.home() / ".claude" / "projects"
        if not projects.is_dir():
            return []
    except Exception:
        return []
    try:
        target_norm = _claude_project_dir_name(Path(scratchpad).parent).casefold()
    except Exception:
        return []
    out: list[tuple[str, int]] = []
    try:
        for proj_dir in projects.iterdir():
            if not proj_dir.is_dir():
                continue
            # Only THIS run's project dir (cwd-keyed). casefold tolerates
            # drive-letter case differences on Windows.
            if proj_dir.name.casefold() != target_norm:
                continue
            for sess in proj_dir.iterdir():
                if not sess.is_dir():
                    continue
                tr = sess / "tool-results"
                if not tr.is_dir():
                    continue
                try:
                    for f in tr.iterdir():
                        if not f.is_file():
                            continue
                        try:
                            st = f.stat()
                            if st.st_mtime < start_time:
                                continue
                            if st.st_size < _RUNAWAY_TOOL_RESULT_BYTES:
                                continue
                        except OSError:
                            continue
                        key = str(f)
                        if key in already_warned:
                            continue
                        already_warned.add(key)
                        out.append((key, st.st_size))
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _breadth_manifest_complete_reason(scratchpad: Path, phase: Phase) -> Optional[str]:
    """Return a reason when every manifest-declared breadth output is substantial."""
    outputs = parse_breadth_manifest_outputs(scratchpad) or []
    if not outputs:
        return None
    missing: list[str] = []
    for name in outputs:
        path = scratchpad / name
        if not path.exists():
            missing.append(name)
            continue
        try:
            if path.stat().st_size < phase.min_artifact_bytes:
                missing.append(f"{name} (stub)")
        except OSError:
            missing.append(name)
    if missing:
        return None
    return (
        f"all {len(outputs)} manifest breadth outputs are present and "
        f">= {phase.min_artifact_bytes} bytes"
    )


def _run_early_complete_check(checker: Callable[[], Optional[str]]) -> Optional[str]:
    return checker.__call__()


def _scratchpad_activity_signature(scratchpad: Path) -> tuple[tuple[str, int, int], ...]:
    entries: list[tuple[str, int, int]] = []
    try:
        for p in scratchpad.rglob("*"):
            try:
                if not p.is_file():
                    continue
                rel = p.relative_to(scratchpad).as_posix()
                if rel.startswith("_"):
                    continue
                st = p.stat()
                entries.append((rel, st.st_size, st.st_mtime_ns))
            except OSError:
                continue
    except OSError:
        pass
    return tuple(sorted(entries))


def _wait_with_heartbeat(
    proc: subprocess.Popen,
    timeout: float,
    scratchpad: Path,
    phase_name: str,
    start_time: float,
    protected_patterns: tuple[str, ...] = (),
    early_complete: Optional[Callable[[], Optional[str]]] = None,
) -> int:
    """Poll proc every _HEARTBEAT_INTERVAL (3s), printing artifact progress.

    Short poll interval ensures halt responds within ~3 seconds.
    Display output is throttled to _HEARTBEAT_DISPLAY_INTERVAL (15s).

    Returns:
      >=0  normal subprocess exit code
      -2   timeout (caller should also check subprocess.TimeoutExpired)
      -3   user pressed Esc (halt) — subprocess terminated, driver stays alive

    Raises subprocess.TimeoutExpired if the process exceeds *timeout*.
    """
    deadline = start_time + timeout
    known_artifacts: set[str] = set()
    known_artifact_stats: dict[str, tuple[int, int]] = {}
    try:
        for p in scratchpad.iterdir():
            if not p.name.startswith("_"):
                known_artifacts.add(p.name)
                try:
                    st = p.stat()
                    known_artifact_stats[p.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    pass
        scip_dir = scratchpad / "scip"
        if scip_dir.is_dir():
            for p in scip_dir.iterdir():
                known_artifacts.add(f"scip/{p.name}")
    except Exception:
        pass

    tool_calls_file = scratchpad / "tool_calls.jsonl"
    last_tc_size = tool_calls_file.stat().st_size if tool_calls_file.exists() else 0
    last_activity_tc_size = last_tc_size
    last_activity_signature = _scratchpad_activity_signature(scratchpad)
    last_display_time = time.time()
    last_scan_time = time.time()
    last_tool_result_scan_time = time.time()
    tool_result_warned: set[str] = set()
    early_complete_since: Optional[float] = None
    early_complete_last_activity: Optional[float] = None
    early_complete_reason: Optional[str] = None
    _ALIVE_INTERVAL = 300

    # Accumulate new artifacts between display ticks
    pending_artifacts: list[str] = []

    while True:
        try:
            rc = proc.wait(timeout=_HEARTBEAT_INTERVAL)
            # Process exited — flush any pending artifacts
            display._clear_spinner()
            if pending_artifacts:
                elapsed = int(time.time() - start_time)
                display.print_phase_heartbeat(phase_name, elapsed, new_artifacts=pending_artifacts)
            return rc
        except subprocess.TimeoutExpired:
            pass
        except KeyboardInterrupt:
            display._clear_spinner()
            _terminate_process_tree(proc, grace_s=10)
            raise

        # Esc halt: terminate subprocess, return -3 so driver can offer resume
        if display.graceful_stop.requested:
            display._clear_spinner()
            _terminate_process_tree(proc, grace_s=_HALT_TERMINATE_GRACE_S)
            return -3

        now = time.time()

        if now > deadline:
            display._clear_spinner()
            raise subprocess.TimeoutExpired(proc.args, timeout)

        elapsed = int(now - start_time)

        # Spin the inline indicator every poll (~4fps)
        display.spin(elapsed)

        # Scan for new artifacts at a slower cadence (every 3s)
        if now - last_scan_time >= _ARTIFACT_SCAN_INTERVAL:
            last_scan_time = now
            observed_activity = False
            try:
                for p in scratchpad.iterdir():
                    if not p.name.startswith("_") and p.name in known_artifacts:
                        try:
                            st = p.stat()
                            sig = (st.st_size, st.st_mtime_ns)
                        except OSError:
                            sig = (0, 0)
                        if known_artifact_stats.get(p.name) != sig:
                            known_artifact_stats[p.name] = sig
                            if protected_patterns and _matches_any_pattern(
                                p.name, list(protected_patterns)
                            ):
                                display._clear_spinner()
                                log.error(
                                    f"[{phase_name}] live containment abort: "
                                    f"protected downstream artifact changed: {p.name}"
                                )
                                _terminate_process_tree(proc, grace_s=_HALT_TERMINATE_GRACE_S)
                                return -4
                        continue
                    if not p.name.startswith("_") and p.name not in known_artifacts:
                        pending_artifacts.append(p.name)
                        known_artifacts.add(p.name)
                        try:
                            st = p.stat()
                            known_artifact_stats[p.name] = (st.st_size, st.st_mtime_ns)
                        except OSError:
                            known_artifact_stats[p.name] = (0, 0)
                        if protected_patterns and _matches_any_pattern(
                            p.name, list(protected_patterns)
                        ):
                            # F7: depth's chain/synthesis writes are benign
                            # post-completion overruns — quarantine post-run
                            # rather than killing the subprocess mid-run.
                            if (
                                phase_name == "depth"
                                and _is_benign_depth_foreign_artifact(p.name)
                            ):
                                log.warning(
                                    f"[{phase_name}] foreign-artifact leak "
                                    f"(benign, will quarantine post-run): "
                                    f"{p.name}"
                                )
                            else:
                                display._clear_spinner()
                                log.error(
                                    f"[{phase_name}] live containment abort: "
                                    f"protected downstream artifact appeared: {p.name}"
                                )
                                _terminate_process_tree(proc, grace_s=_HALT_TERMINATE_GRACE_S)
                                return -4
                scip_dir = scratchpad / "scip"
                if scip_dir.is_dir():
                    for p in scip_dir.iterdir():
                        key = f"scip/{p.name}"
                        if key not in known_artifacts:
                            pending_artifacts.append(key)
                            known_artifacts.add(key)
            except Exception:
                pass

            cur_activity_signature = _scratchpad_activity_signature(scratchpad)
            cur_activity_tc_size = (
                tool_calls_file.stat().st_size if tool_calls_file.exists() else 0
            )
            if (
                cur_activity_signature != last_activity_signature
                or cur_activity_tc_size > last_activity_tc_size
            ):
                observed_activity = True
                last_activity_signature = cur_activity_signature
                last_activity_tc_size = cur_activity_tc_size

            # Runaway tool-result watchdog: a subagent that lists a huge
            # out-of-scope directory (e.g. system temp, home dir) can dump
            # multi-MB results that block the coordinator and produce no
            # audit value. Warn so the operator can halt early.
            if now - last_tool_result_scan_time >= _TOOL_RESULT_SCAN_INTERVAL_S:
                last_tool_result_scan_time = now
                for path, size in _scan_claude_tool_results_for_runaways(
                    start_time, tool_result_warned, scratchpad
                ):
                    log.warning(
                        f"[{phase_name}] runaway tool result detected: "
                        f"{size / 1024:.0f} KB at {path} -- a subagent likely "
                        f"read outside PROJECT_ROOT/SCRATCHPAD. Coordinator "
                        f"may stall waiting for that subagent."
                    )

            if early_complete:
                try:
                    reason = _run_early_complete_check(early_complete)
                except Exception as exc:
                    log.debug(f"[{phase_name}] early completion check skipped: {exc}")
                    reason = None
                if reason:
                    if early_complete_since is None:
                        early_complete_since = now
                        early_complete_last_activity = now
                        early_complete_reason = reason
                        log.info(
                            f"[{phase_name}] manifest complete: {reason}; "
                            "waiting for subprocess to go idle before cutover"
                        )
                    elif observed_activity:
                        early_complete_last_activity = now
                    idle_for = now - (early_complete_last_activity or now)
                    if idle_for >= _EARLY_COMPLETE_IDLE_GRACE_SECONDS:
                        display._clear_spinner()
                        log.info(
                            f"[{phase_name}] early completion after idle grace: "
                            f"{early_complete_reason or reason}; no scratchpad/tool "
                            f"activity for {int(idle_for)}s"
                        )
                        _terminate_process_tree(proc, grace_s=_HALT_TERMINATE_GRACE_S)
                        return 0
                else:
                    early_complete_since = None
                    early_complete_last_activity = None
                    early_complete_reason = None

        since_display = now - last_display_time

        # Show new artifacts immediately (spinner line → artifact line)
        if pending_artifacts and since_display >= _ARTIFACT_SCAN_INTERVAL:
            names = ", ".join(pending_artifacts[:4])
            extra = f" +{len(pending_artifacts) - 4} more" if len(pending_artifacts) > 4 else ""
            display.print_phase_heartbeat(phase_name, elapsed, new_artifacts=pending_artifacts)
            mins, secs = divmod(elapsed, 60)
            log.info(f"[{phase_name}] {mins}:{secs:02d} | +{names}{extra}")
            pending_artifacts = []
            last_display_time = now
        elif not pending_artifacts and since_display >= _ALIVE_INTERVAL:
            mins, secs = divmod(elapsed, 60)
            cur_tc_size = tool_calls_file.stat().st_size if tool_calls_file.exists() else 0
            if cur_tc_size > last_tc_size:
                delta_kb = (cur_tc_size - last_tc_size) / 1024
                display.print_phase_heartbeat(phase_name, elapsed, tool_calls_delta_kb=delta_kb)
                log.info(f"[{phase_name}] {mins}:{secs:02d} | working (+{delta_kb:.0f}KB tool calls)")
                last_tc_size = cur_tc_size
            else:
                display.print_phase_heartbeat(phase_name, elapsed)
                log.info(f"[{phase_name}] {mins}:{secs:02d} | waiting")
            last_display_time = now


class _PhaseHeartbeatThread:
    """Context manager that pulses a live terminal heartbeat while a long
    *synchronous, in-process* step runs — e.g. the recon mechanical prepass
    (Slither/graph bake, build/dep-install) which can block 1-3+ minutes with
    zero output and look like a dead launch (the chronic 0-byte-stdio class).

    It reuses ``display.print_phase_heartbeat`` so the pulse line matches the
    worker-phase loops, and mirrors their new-artifact computation (set diff of
    files in ``scratchpad`` since start).

    A daemon thread does the pulsing; ``__exit__`` always sets the stop Event
    and joins with a small timeout in a ``finally``-equivalent path, so the
    thread can never leak. Degrades to a complete no-op when ``display`` is
    None / lacks ``print_phase_heartbeat`` — it never raises into the caller.
    """

    def __init__(self, display_mod, phase_name, scratchpad, interval=12):
        self._display = display_mod
        self._phase_name = phase_name
        try:
            self._scratch = Path(scratchpad) if scratchpad else None
        except Exception:
            self._scratch = None
        try:
            self._interval = max(1, int(interval or 12))
        except Exception:
            self._interval = 12
        self._stop = threading.Event()
        self._thread = None
        self._start_mono = None
        self._baseline: set[str] = set()
        # Only pulse when there is a usable display sink. The module-level
        # display already degrades to stderr when Rich is unavailable, but a
        # caller may pass None (non-interactive / no display) — then no-op.
        self._enabled = bool(
            self._display is not None
            and hasattr(self._display, "print_phase_heartbeat")
        )

    def _snapshot(self) -> set[str]:
        if self._scratch is None:
            return set()
        try:
            return {p.name for p in self._scratch.iterdir() if p.is_file()}
        except Exception:
            return set()

    def _run(self):
        # wait() returns True only when the stop Event is set; on timeout it
        # returns False. So this pulses every `interval` seconds (NOT at t=0 —
        # the up-front status line covers the immediate notice) until stopped.
        while not self._stop.wait(self._interval):
            try:
                elapsed = int(time.monotonic() - (self._start_mono or time.monotonic()))
                new = sorted(self._snapshot() - self._baseline)
                if new:
                    self._display.print_phase_heartbeat(
                        self._phase_name, elapsed, new_artifacts=new)
                else:
                    self._display.print_phase_heartbeat(self._phase_name, elapsed)
            except Exception:
                # The heartbeat is pure UX; never let it crash the run.
                pass

    def __enter__(self):
        if not self._enabled:
            return self
        try:
            self._start_mono = time.monotonic()
            self._baseline = self._snapshot()
            self._thread = threading.Thread(
                target=self._run,
                name=f"heartbeat-{self._phase_name}",
                daemon=True,
            )
            self._thread.start()
        except Exception:
            self._thread = None
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._stop.set()
            t = self._thread
            if t is not None and t.is_alive():
                t.join(timeout=2.0)
        except Exception:
            pass
        # Never suppress an exception raised inside the wrapped step.
        return False


def _phase_heartbeat_thread(display_mod, phase_name, scratchpad, interval=12):
    """Return a context manager that pulses a live heartbeat around a long
    synchronous in-process step. See :class:`_PhaseHeartbeatThread`."""
    return _PhaseHeartbeatThread(display_mod, phase_name, scratchpad, interval)


# ===========================================================================
# Artifact-gated PTY supervision (Ship 6 of the supervision plan)
# ===========================================================================

# Row-aware phases. These have structured per-output status helpers, so
# missing-only repair can name exactly which spawned worker rows are incomplete.
# Other Claude PTY phases still participate in the disposable gate-repair loop
# when run_phase() sees concrete expected_artifacts / any_of / dynamic verify
# gates; they use the generic gate_missing repair prompt instead of row status.
#
# Adding a phase here REQUIRES a structured per-row status helper in
# `compute_phase_row_statuses` AND a prompt that emits PLAMEN markers.
PTY_SUPERVISED_PHASES: frozenset[str] = frozenset({"breadth", "depth"})


def _pty_supervision_cache_dir() -> Path:
    """Cache directory for the empirical preflight (Ship 4).

    Lives under ``plamen_home()/cache`` so it survives across audits
    on the same machine without polluting per-project scratchpads.
    """
    return plamen_home() / "cache"


def _row_id_from_artifact_name(name: str) -> str:
    """Derive a human/agent row id from a spawned-worker artifact
    filename. Strips the family prefix (``analysis_`` for breadth,
    ``depth_`` for depth) and the suffix (``_findings.md`` or ``.md``).

      analysis_access_control.md   -> access_control
      depth_token_flow_findings.md -> token_flow

    Used only as a fallback when no transcript-derived AGENT_ROW handle
    is available for the row.
    """
    base = name
    for suffix in ("_findings.md", ".md"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    for prefix in ("analysis_", "depth_"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            break
    return base


def _build_continuation_message(
    *,
    phase_name: str,
    row_statuses: list[dict[str, Any]],
    handles_by_row: dict[str, dict[str, str]],
    agentid_resume_supported: bool,
    gate_missing: list[str] | None = None,
) -> str:
    """Build the user-message text that the supervision loop sends to
    the coordinator after a failed in-session gate check.

    The message lists ONLY rows whose status is NOT ``complete`` --
    rows that already passed structural completeness are never re-run.
    Each row carries its current status, expected output filename,
    and (if ``agentid_resume_supported`` and a handle is known) the
    ``agentId`` for SendMessage-style resume; otherwise the handle
    column is dropped and the coordinator is told to respawn.

    ``row_statuses`` is the output of
    ``compute_phase_row_statuses(scratchpad, phase)``. ``handles_by_row`` is
    the output of ``parse_transcript_agentids(transcript_path)``.

    ``gate_missing`` is included as a footer for forensics when the structured
    row list is empty. Production recovery no longer sends this message into a
    live PTY, but tests keep it as the row-scoping contract.
    """
    incomplete: list[dict[str, Any]] = [
        r for r in (row_statuses or [])
        if r.get("status") and r["status"] != "complete"
    ]

    lines: list[str] = []
    lines.append(
        f"The driver's artifact-complete gate did not pass for phase "
        f"`{phase_name}`."
    )
    lines.append("")

    if incomplete:
        if agentid_resume_supported:
            lines.append(
                "Incomplete manifest artifacts (act ONLY on these; do NOT "
                "re-spawn rows whose file already contains "
                "`<!-- PLAMEN_STATUS: COMPLETE -->`):"
            )
            lines.append("")
            lines.append("| Row | Expected Output | Status | Handle (if known) |")
            lines.append("| --- | --- | --- | --- |")
            for r in incomplete:
                name = r["name"]
                # Derive a row id from the filename: analysis_<focus>.md -> focus
                # (matches the AGENT_ROW marker in the dispatch prompt). Falls
                # back to filename when handle lookup is unavailable.
                handle_entry = None
                for h in handles_by_row.values():
                    if h.get("expected_output") == name:
                        handle_entry = h
                        break
                row_id = (
                    handle_entry.get("agent_id")
                    if handle_entry
                    else _row_id_from_artifact_name(name)
                )
                handle = handle_entry.get("handle") if handle_entry else ""
                handle_cell = handle if handle else "(no handle; respawn required)"
                lines.append(
                    f"| {row_id} | {name} | {r['status'].upper()} | {handle_cell} |"
                )
            lines.append("")
            lines.append(
                "For each row above:\n"
                "1. If the row has a non-empty Handle AND status is "
                "IN_PROGRESS, attempt `SendMessage` to that handle asking "
                "it to finish writing the assigned file and emit "
                "`<!-- PLAMEN_STATUS: COMPLETE -->` at the end.\n"
                "2. If SendMessage is unsupported or fails, OR status is "
                "MISSING / STUB / STRUCTURAL_FAIL / LEGACY_UNMARKED, "
                "re-spawn ONLY that row using the §Subagent Prompt "
                "Template. Re-spawned subagents MUST include "
                "`AGENT_ROW: <row>` and `EXPECTED_OUTPUT: <filename>` "
                "lines in their dispatch prompt (per template).\n"
                "3. Do NOT re-run rows whose file already contains "
                "`<!-- PLAMEN_STATUS: COMPLETE -->`."
            )
        else:
            lines.append(
                "Incomplete manifest artifacts (act ONLY on these; do NOT "
                "re-spawn rows whose file already contains "
                "`<!-- PLAMEN_STATUS: COMPLETE -->`):"
            )
            lines.append("")
            lines.append("| Row | Expected Output | Status |")
            lines.append("| --- | --- | --- |")
            for r in incomplete:
                name = r["name"]
                row_id = _row_id_from_artifact_name(name)
                # Prefer the transcript-derived agent_id when available.
                for h in handles_by_row.values():
                    if h.get("expected_output") == name:
                        row_id = h.get("agent_id") or row_id
                        break
                lines.append(
                    f"| {row_id} | {name} | {r['status'].upper()} |"
                )
            lines.append("")
            lines.append(
                "Re-spawn ONLY the rows above using the §Subagent Prompt "
                "Template. Respawn is the only available continuation "
                "path on this Claude Code version (the driver's preflight "
                "disabled handle-based resume). Re-spawned subagents "
                "MUST include `AGENT_ROW: <row>` and "
                "`EXPECTED_OUTPUT: <filename>` lines in their dispatch "
                "prompt. Do NOT re-run rows whose file already contains "
                "`<!-- PLAMEN_STATUS: COMPLETE -->`."
            )
    else:
        # No structured detail available (e.g. supervision wired into a
        # phase whose row-status helper isn't shipped yet). Fall back to
        # the gate's aggregated failure detail.
        lines.append(
            "Structured per-row status is not available for this phase. "
            "Gate detail:"
        )
        lines.append("")
        for item in (gate_missing or []):
            lines.append(f"- {item}")
        lines.append("")
        lines.append(
            "Re-run the phase's completion loop until every expected "
            "artifact contains `<!-- PLAMEN_STATUS: COMPLETE -->`."
        )

    lines.append("")
    lines.append(
        "Return `DONE` only when every listed artifact contains "
        "`<!-- PLAMEN_STATUS: COMPLETE -->`."
    )
    return "\n".join(lines)


def _argv_bootstrap_instruction(snap_path: Any) -> str:
    """Single source of truth for the positional bootstrap instruction baked
    into a PTY argv when ``PLAMEN_BOOTSTRAP_IN_ARGV=1``. Production (run_phase)
    and the Ship 8.16 respawn rewrite MUST emit byte-identical text so the
    model treats a continuation respawn exactly like a first launch -- the only
    difference being WHICH prompt file it is told to execute.
    """
    return (
        "Read and fully execute every instruction in "
        f"{Path(snap_path).as_posix()}. When done, output your one-line "
        "DONE summary."
    )


def _rewrite_argv_positional_prompt(
    argv: list[str], snapshot: Path
) -> list[str]:
    """Ship 8.16: point a respawn's argv at the continuation/missing-only
    SNAPSHOT instead of the original phase prompt.

    When the prompt is delivered via argv (``PLAMEN_BOOTSTRAP_IN_ARGV=1``, the
    default PTY transport), the positional prompt is the final argv element, and
    ``send_bootstrap`` is a no-op. Both
    ``_respawn_via_resume`` and ``_respawn_missing_only`` previously preserved
    that ORIGINAL positional verbatim, so the model re-ran the full phase
    prompt instead of the compact continuation (codex #1 / T1+T1b -- the Ship
    8.11/8.12 synthetic proof never asserted argv delivery).

    Returns a NEW argv with the positional rewritten to execute ``snapshot``.
    If the argv carries no positional prompt (headless mode),
    it is returned unchanged -- there ``send_bootstrap`` delivers the snapshot
    via ``prompt_path`` and no argv rewrite is needed.
    """
    out = list(argv)
    if out and str(out[-1]).startswith(
        "Read and fully execute every instruction in "
    ):
        out[-1] = _argv_bootstrap_instruction(snapshot)
        return out
    for i in range(len(out) - 1, -1, -1):
        if out[i] == "--":
            if i + 1 < len(out):
                out[i + 1] = _argv_bootstrap_instruction(snapshot)
            return out
    return out


def _build_resume_cmd_and_snapshot(
    *,
    session_id: str,
    continuation: str,
    base_cmd: list[str],
    prompt_path: Path,
    now_ts: int | None = None,
) -> tuple[list[str], Path]:
    """Construct the argv and continuation-snapshot path for a
    ``claude --resume <session_id>`` respawn.

    Pure helper: no spawn, no PTY, no subprocess. Returns
    ``(resume_cmd, continuation_snapshot_path)``. The continuation
    message is written to a sibling of ``prompt_path`` named
    ``<original-stem>.continuation.<unix_ts>.md`` so each respawn gets
    its own forensic record.

    The resume command strips any ``--session-id <uuid>`` pair from
    ``base_cmd`` (``--session-id`` and ``--resume`` are mutually
    exclusive in the Claude Code CLI) and inserts
    ``--resume <session_id>`` immediately after the program name.
    Other flags are preserved verbatim and in order.

    Ship 6 of the artifact-complete PTY supervision plan.
    """
    resume_cmd: list[str] = []
    skip_next = False
    for tok in base_cmd:
        if skip_next:
            skip_next = False
            continue
        if tok == "--session-id":
            skip_next = True
            continue
        resume_cmd.append(tok)
    if not resume_cmd:
        # Defensive: an empty base_cmd shouldn't happen; the caller
        # builds it from CLAUDE_BIN + flags. If it does, propagate
        # the failure rather than producing a bogus claude command.
        raise ValueError(
            "_build_resume_cmd_and_snapshot: base_cmd is empty after "
            "stripping --session-id"
        )
    # Insert --resume right after the program name (consistent CLI ordering).
    resume_cmd = [resume_cmd[0], "--resume", session_id] + resume_cmd[1:]

    ts = now_ts if now_ts is not None else int(time.time())
    snapshot = prompt_path.with_name(
        f"{prompt_path.stem}.continuation.{ts}{prompt_path.suffix}"
    )
    snapshot.write_text(continuation, encoding="utf-8")

    return resume_cmd, snapshot


def _respawn_via_resume(
    *,
    session_id: str,
    continuation: str,
    base_cmd: list[str],
    cwd: str,
    env: dict[str, str],
    log_file: Any,
    prompt_path: Path,
) -> ClaudePtySession:
    """Spawn a NEW ``ClaudePtySession`` resuming the same Claude
    session by ID. Writes the continuation message to a fresh
    snapshot file used as the new session's bootstrap prompt.

    Returns the new (spawned + bootstrapped) session. The caller is
    responsible for terminating this session in its existing
    ``finally`` block. The supervision loop replaces its in-scope
    ``session`` variable with this return value before continuing the
    loop, so the outer terminator targets the live session.
    """
    resume_cmd, snapshot = _build_resume_cmd_and_snapshot(
        session_id=session_id,
        continuation=continuation,
        base_cmd=base_cmd,
        prompt_path=prompt_path,
    )
    # Ship 8.16: point the argv positional prompt at the continuation snapshot.
    # Without this, PLAMEN_BOOTSTRAP_IN_ARGV makes the resumed session re-run
    # the ORIGINAL phase prompt (send_bootstrap is suppressed in argv mode).
    resume_cmd = _rewrite_argv_positional_prompt(resume_cmd, snapshot)
    new_session = ClaudePtySession(
        resume_cmd,
        cwd=cwd,
        env=env,
        session_id=session_id,
        prompt_path=snapshot,
        log_file=log_file,
    )
    new_session.spawn()
    new_session.send_bootstrap()
    return new_session


# ---------------------------------------------------------------------------
# Ship 8.11/8.12: missing-only continuation subprocess
# ---------------------------------------------------------------------------


def _build_fresh_session_cmd(
    base_cmd: list[str], new_session_id: str
) -> list[str]:
    """Minimal shared PTY-argv builder (Correction 1): return ``base_cmd``
    with the ``--session-id`` value replaced by ``new_session_id``.

    ``base_cmd`` is the production interactive-PTY command the driver built
    in ``run_phase`` -- it already carries the exact production flags
    (model, both ``--add-dir``, and the isolation set
    ``--disallowedTools mcp__* --settings <iso> --strict-mcp-config
    --mcp-config <iso>``). Transforming it (rather than reconstructing)
    GUARANTEES the missing-only subprocess uses an identical command shape
    with ZERO drift. Ship 8.10 will extract a from-scratch constructor for
    the preflight (which has no base_cmd to transform) and may converge
    both onto one builder then.
    """
    out = list(base_cmd)
    for i, tok in enumerate(out):
        if tok == "--session-id" and i + 1 < len(out):
            out[i + 1] = new_session_id
            return out
    # Defensive: a PTY base_cmd should always carry --session-id. If it
    # somehow does not, insert one right after the program name.
    if out:
        return [out[0], "--session-id", new_session_id] + out[1:]
    return ["--session-id", new_session_id]


def _build_missing_only_prompt(
    phase: Phase,
    scratchpad: Path,
    row_statuses: list[dict[str, Any]],
    prompt_path: Path,
    gate_missing: list[Any] | None = None,
    now_ts: int | None = None,
) -> Path:
    """Write a COMPACT missing-only continuation bootstrap prompt to a
    snapshot sibling of ``prompt_path``; return its path.

    Correction 2: the prompt carries FULL row metadata pointers so the
    missing-only subprocess reconstructs the same-quality agent prompts --
    not shallow generic files. It points to ``spawn_manifest.md``, lists
    the incomplete expected outputs, names the Subagent Prompt Template
    file (read on demand via ``--add-dir plamen_home`` -- NOT inlined, so
    the base prompt stays ~1-2 KB and compaction-resistant), names the
    per-row opengrep shard path convention, and forbids touching COMPLETE
    files. Completion is disk-derived (Ship 8.8 rule).
    """
    incomplete = [
        r for r in (row_statuses or [])
        if r.get("status") and r["status"] != "complete"
    ]
    template = (
        plamen_home() / "prompts" / "shared" / "v2"
        / ("phase4b-depth.md" if phase.name == "depth" else "phase3-breadth.md")
    )
    lines: list[str] = []
    lines.append(f"# MISSING-ONLY CONTINUATION (phase: {phase.name})")
    lines.append("")

    if phase.name not in {"breadth", "depth"}:
        if phase.name in L1_VERIFY_PHASE_NAMES or phase.name in SC_VERIFY_PHASE_NAMES:
            lines.append(
                "A prior verifier shard turn ended with the Python driver's "
                "disk gate still failing. Your ONLY job this turn is to "
                "write the missing verifier files listed below. Do not "
                "rewrite verifier files that already exist and are not "
                "listed here."
            )
            lines.append("")
            lines.append("## Missing Verifier Rows")
            lines.append("")
            lines.append("| Finding ID | Expected Output | Severity | Title |")
            lines.append("| --- | --- | --- | --- |")
            missing_rows = [
                r for r in incomplete
                if str(r.get("status") or "") != "complete"
            ]
            for r in missing_rows:
                row = r.get("row") if isinstance(r.get("row"), dict) else {}
                fid = str(r.get("finding_id") or row.get("finding id") or "").strip()
                severity = str(row.get("severity") or "").replace("|", "/")
                title = str(row.get("title") or "").replace("|", "/")
                lines.append(
                    f"| {fid or '(unknown)'} | {r.get('name')} | "
                    f"{severity or '-'} | {title or '-'} |"
                )
            lines.append("")
            if gate_missing:
                lines.append("## Gate Failure Detail")
                lines.append("")
                for item in gate_missing:
                    lines.append(f"- {item}")
                lines.append("")
            lines.append("## Verification Method")
            lines.append("")
            lines.append(
                f"1. Read the original verifier shard prompt snapshot at "
                f"`{prompt_path.as_posix()}` for the exact verification "
                "methodology, verdict schema, evidence tags, and shard "
                "manifest path."
            )
            lines.append(
                "2. Verify ONLY the Missing Verifier Rows above. Preserve "
                "every existing `verify_*.md` file that is not listed above."
            )
            lines.append(
                "3. For each missing row, write exactly the expected output "
                "`verify_<finding_id>.md` with the canonical verifier fields: "
                "Finding ID, Severity, Verdict, Evidence Tag, Preferred Tag, "
                "and concise evidence/reasoning."
            )
            lines.append(
                "4. Do not advance to later pipeline phases and do not create "
                "report, aggregate, skeptic, or crossbatch artifacts."
            )
            lines.append("")
            lines.append("## Completion")
            lines.append("")
            lines.append(
                "Before emitting DONE, verify on disk that every expected "
                "output in the table exists and is substantive. Then emit: "
                f"`DONE: {phase.name} missing verifier rows complete`."
            )
            lines.append("")
            ts = now_ts if now_ts is not None else int(time.time())
            snapshot = prompt_path.with_name(
                f"{prompt_path.stem}.missing_only.{ts}{prompt_path.suffix}"
            )
            snapshot.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return snapshot

        lines.append(
            "A prior coordinator turn for this phase ended with the Python "
            "driver's disk gate still failing. Your ONLY job this turn is to "
            "repair the listed gate failures for this same phase. Do not "
            "create any artifact outside the listed expected outputs."
        )
        lines.append("")
        lines.append("## Gate failure detail")
        lines.append("")
        detail = [str(x) for x in (gate_missing or [])]
        if detail:
            for item in detail:
                lines.append(f"- {item}")
        else:
            lines.append("- gate failed without structured detail; inspect expected outputs")
        lines.append("")
        lines.append("## Expected artifact contract")
        lines.append("")
        expected = list(getattr(phase, "expected_artifacts", None) or [])
        if expected:
            for item in expected:
                lines.append(f"- `{item}`")
        else:
            lines.append(
                "- dynamic expected artifacts; inspect the original phase "
                "prompt and relevant manifests"
            )
        any_of = list(getattr(phase, "any_of", None) or [])
        if any_of:
            lines.append("")
            lines.append("Any-of alternatives:")
            for item in any_of:
                lines.append(f"- `{item}`")
        lines.append("")
        lines.append("## Repair method")
        lines.append("")
        lines.append(
            f"1. Read the original phase prompt snapshot at "
            f"`{prompt_path.as_posix()}` only for methodology needed to "
            "repair the gate failures above."
        )
        lines.append(
            "2. Treat disk artifacts as the source of truth. Preserve any "
            "artifact that is already complete and not explicitly listed as "
            "invalid."
        )
        lines.append(
            "3. Repair only missing, stub, structurally invalid, or "
            "gate-failing artifacts for this phase. Do not write any artifact "
            "outside this phase's expected output contract."
        )
        if getattr(phase, "appends_existing_artifact", False):
            lines.append(
                "4. This phase appends/enriches an existing artifact. Preserve "
                "existing content and add only the missing phase-owned section "
                "or repair requested by the gate."
            )
        else:
            lines.append(
                "4. If a failed artifact exists but is invalid, rewrite that "
                "artifact only; do not rewrite unrelated complete outputs."
            )
        lines.append("")
        lines.append("## Completion")
        lines.append("")
        lines.append(
            "Before emitting DONE, verify on disk that the failed artifact(s) "
            "now exist, are substantive, satisfy the phase-specific format, "
            "and contain no unresolved placeholder text. Then emit: "
            f"`DONE: {phase.name} gate repair complete`."
        )
        lines.append("")
        ts = now_ts if now_ts is not None else int(time.time())
        snapshot = prompt_path.with_name(
            f"{prompt_path.stem}.missing_only.{ts}{prompt_path.suffix}"
        )
        snapshot.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return snapshot

    if phase.name == "depth":
        lines.append(
            "A prior depth coordinator turn ended with one or more depth role "
            "artifacts incomplete. Your ONLY job this turn is to complete the "
            "depth rows listed below. Do NOT use any breadth manifest; "
            "depth rows are defined by this phase's role/output contract and "
            "the original depth prompt snapshot."
        )
        lines.append("")
        lines.append("## Incomplete Depth Rows")
        lines.append("")
        lines.append("| Role | Expected Output | Status |")
        lines.append("| --- | --- | --- |")
        for r in incomplete:
            name = str(r.get("name") or "")
            role = name
            if role.startswith("depth_"):
                role = role[len("depth_"):]
            if role.endswith("_findings.md"):
                role = role[: -len("_findings.md")]
            lines.append(f"| {role or '(unknown)'} | {name} | {str(r.get('status','')).upper()} |")
        if gate_missing:
            lines.append("")
            lines.append("Gate detail:")
            for item in gate_missing:
                lines.append(f"- {item}")
        lines.append("")
        lines.append("## Methodology")
        lines.append("")
        lines.append(
            f"1. Read the original depth prompt snapshot at "
            f"`{prompt_path.as_posix()}` for the exact methodology, mode "
            "requirements, language templates, semantic proof blocks, graph "
            "artifact obligations, and marker contract."
        )
        lines.append(
            f"2. Read `{template.as_posix()}` only as the shared depth "
            "methodology reference. Do not follow breadth coordinator "
            "instructions; do not read breadth manifests; do not use "
            "breadth static-analysis shard conventions."
        )
        lines.append(
            "3. Repair ONLY the expected output files listed above. Preserve "
            "every depth file that already has final "
            "`<!-- PLAMEN_STATUS: COMPLETE -->` and is not listed here."
        )
        lines.append(
            "4. If you need to spawn Task agents, spawn only the listed depth "
            "roles, wait for them to finish, and verify their files on disk. "
            "Each Task prompt must include `AGENT_ROW`, `EXPECTED_OUTPUT`, "
            "the IN_PROGRESS-first marker write, the depth role methodology, "
            "and the SCOPE line that forbids other outputs."
        )
        lines.append("")
        lines.append("## Completion")
        lines.append("")
        lines.append(
            "Before emitting DONE, verify ON DISK that every listed depth "
            "artifact exists, is substantive, has a final COMPLETE marker, "
            "and contains either `### Finding [` / `## Finding [` blocks or "
            "a `## No Findings` rationale. Then emit: "
            "`DONE: missing depth rows completed`."
        )
        lines.append("")
        ts = now_ts if now_ts is not None else int(time.time())
        snapshot = prompt_path.with_name(
            f"{prompt_path.stem}.missing_only.{ts}{prompt_path.suffix}"
        )
        snapshot.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return snapshot

    lines.append(
        "A prior coordinator turn for this phase ended (possibly after a "
        "context compaction) with some manifest outputs incomplete. Your "
        "ONLY job this turn: complete the incomplete rows listed below. Do "
        "NOT touch any file that already contains "
        "`<!-- PLAMEN_STATUS: COMPLETE -->` -- those rows are done."
    )
    lines.append("")
    lines.append("## Incomplete rows (the ONLY work for this turn)")
    lines.append("")
    lines.append("| Expected Output | Status |")
    lines.append("| --- | --- |")
    for r in incomplete:
        lines.append(f"| {r['name']} | {str(r.get('status','')).upper()} |")
    lines.append("")
    lines.append("## How to run each incomplete row (FULL methodology, not a shortcut)")
    lines.append("")
    lines.append(
        f"1. Read `{(scratchpad / 'spawn_manifest.md').as_posix()}`. For each "
        "incomplete Expected Output above, find its manifest row: Agent ID, "
        "Focus Area, and skill/template binding."
    )
    lines.append(
        f"2. Read the Subagent Prompt Template in `{template.as_posix()}` and "
        "construct each subagent's Task() prompt EXACTLY per that template "
        "(same recon reads, same methodology, same PLAMEN marker contract). "
        "Do not summarize or weaken it."
    )
    lines.append(
        "3. Each subagent's assigned opengrep obligation shard, if present, is "
        f"at `{scratchpad.as_posix()}/opengrep_obligations_<agent_id>_"
        "<focus_area_slug>.md` (telemetry; not a completeness gate)."
    )
    if phase.name == "breadth":
        lines.append(
            "4. Spawn ONLY the incomplete rows above, as background Task calls "
            "in a single assistant message (`run_in_background: true` for each "
            "Task), then keep this coordinator alive and monitor/collect until "
            "disk verification passes. Do NOT re-spawn or overwrite rows "
            "already COMPLETE on disk."
        )
    else:
        lines.append(
            "4. Spawn ONLY the incomplete rows above, as foreground Task calls "
            "in a single message. Do NOT re-spawn or overwrite rows already "
            "COMPLETE on disk."
        )
    lines.append("")
    lines.append("## Completion (disk-derived; never trust memory or a compaction summary)")
    lines.append("")
    lines.append(
        "Before emitting DONE, verify ON DISK that EVERY incomplete row above "
        "now exists with a final `<!-- PLAMEN_STATUS: COMPLETE -->` and either "
        "a `## Finding [` block or a `## No Findings` rationale. Use targeted "
        "grep / file checks, NOT full-body reads. Only then emit: "
        f"`DONE: <N> missing {phase.name} rows completed`."
    )
    lines.append("")
    ts = now_ts if now_ts is not None else int(time.time())
    snapshot = prompt_path.with_name(
        f"{prompt_path.stem}.missing_only.{ts}{prompt_path.suffix}"
    )
    snapshot.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return snapshot


def _respawn_missing_only(
    *,
    phase: Phase,
    scratchpad: Path,
    row_statuses: list[dict[str, Any]],
    base_cmd: list[str],
    cwd: str,
    env: dict[str, str],
    log_file: Any,
    prompt_path: Path,
    gate_missing: list[Any] | None = None,
) -> ClaudePtySession:
    """Spawn a FRESH PTY session (new uuid, NOT --resume) with a compact
    missing-only continuation prompt. Returns the new (spawned +
    bootstrapped) session.

    Ship 8.11: this is the third continuation transport, available even
    when preflight reports live=False AND resume=False. It runs the SAME
    missing agents a whole-phase retry would, with a smaller base prompt
    and without re-running already-COMPLETE rows -- so cost is <= a full
    retry, and on success it avoids the full retry entirely.
    """
    new_session_id = str(uuid.uuid4())
    fresh_cmd = _build_fresh_session_cmd(base_cmd, new_session_id)
    snapshot = _build_missing_only_prompt(
        phase, scratchpad, row_statuses, prompt_path,
        gate_missing=gate_missing,
    )
    # Ship 8.16: point the argv positional prompt at the compact missing-only
    # snapshot. Without this, PLAMEN_BOOTSTRAP_IN_ARGV makes the fresh session
    # re-run the ORIGINAL full phase prompt (send_bootstrap is suppressed in
    # argv mode) -- defeating the entire missing-only optimization.
    fresh_cmd = _rewrite_argv_positional_prompt(fresh_cmd, snapshot)
    new_session = ClaudePtySession(
        fresh_cmd,
        cwd=cwd,
        env=env,
        session_id=new_session_id,
        prompt_path=snapshot,
        log_file=log_file,
    )
    new_session.spawn()
    new_session.send_bootstrap()
    return new_session


def _write_continuation_record(
    scratchpad: Path,
    phase_name: str,
    attempt: int,
    continuation: str,
    gate_missing: list[str],
) -> None:
    """Persist a forensic record of an in-session continuation. The
    file is best-effort -- write failures are logged at debug level
    and do not affect the supervision loop. One file per attempt
    keeps the audit trail straightforward; the supervision loop
    appends a new one for each iteration.
    """
    try:
        path = scratchpad / f"_continuation_{phase_name}_{attempt}.md"
        body = []
        body.append(f"# Continuation record: {phase_name} attempt {attempt}")
        body.append("")
        body.append("## Gate failure detail")
        body.append("")
        for item in (gate_missing or []):
            body.append(f"- {item}")
        body.append("")
        body.append("## Continuation message sent to coordinator")
        body.append("")
        body.append(continuation)
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
    except Exception as exc:
        log.debug(
            f"[{phase_name}] continuation record write failed: {exc}"
        )


def _run_supervised_pty_loop(
    *,
    session: ClaudePtySession,
    scratchpad: Path,
    project_root: str,
    phase: Phase,
    config: dict,
    preflight: dict,
    timeout: float,
    quiescence_s: float,
    on_poll: Any,
    base_cmd: list[str],
    cwd: str,
    env: dict[str, str],
    log_file: Any,
    prompt_path: Path,
    phase_started_at: float | None = None,
) -> tuple[int, ClaudePtySession]:
    """Drive the artifact-complete supervision loop for a single phase.

    Returns ``(rc, final_session)``. ``final_session`` may differ from
    the input ``session`` because incomplete phases are recovered by
    terminating the old coordinator and spawning a fresh missing-only
    interactive Claude session.

    Production policy: no live PTY continuation and no ``--resume``. A
    Claude PTY is a disposable phase worker; disk artifacts are the durable
    state. If the gate rejects a turn, the driver computes incomplete rows
    from disk and starts a new missing-only session scoped to those rows.

    rc semantics:

      - ``0``  -- disk gate passed (artifacts are COMPLETE +
        structurally OK).
      - ``1``  -- rate-limited (the existing rate-limit retry logic
        in the outer loop handles backoff).
      - ``-2`` -- whole-phase retry sentinel: budget exhausted, no
        structured row status available, hang (no end_turn within
        ``timeout``), old PTY refused to terminate, or missing-only
        respawn failed. The outer driver retries the phase from scratch;
        COMPLETE rows on disk are skipped by the phase prompt's
        disk-verification loop, so progress is preserved.

    The ``_PtyStop`` foreign-artifact containment exception raised by
    ``on_poll`` propagates out of this function unchanged -- the
    caller's existing except-handler converts it to ``rc = stop.rc``.
    """
    budget = int(config.get("pty_continuation_budget", 3))
    attempt = 0

    # Ship 8.13: emit the auto-compaction telemetry at most ONCE per phase
    # run. It is INFO, not WARNING: disk gates remain authoritative.
    compaction_warned = False

    while True:
        attempt += 1
        state = session.wait_for_turn_complete(
            timeout,
            quiescence_s=quiescence_s,
            on_poll=on_poll,
        )

        if state.rate_limited:
            return 1, session

        # Ship 8.17: context-overflow / autocompact-thrash fast-fail. The wait
        # loop returned early (instead of burning the full deadline) because
        # the turn was emitting compaction churn with zero forward progress for
        # >= _CONTEXT_THRASH_LOOP_S. This is NOT a new halt: we simply let the
        # existing gate + missing-only / whole-phase recovery below take over
        # immediately, exactly as on a timeout. If the gate happens to have
        # passed (work landed on disk before thrash), the gate_passed branch
        # below returns 0 unchanged. Diagnostic WARNING, emitted at most once.
        if getattr(state, "context_thrash", False):
            log.warning(
                f"[{phase.name}] context-overflow thrash detected after "
                f"~{int(_CONTEXT_THRASH_LOOP_S)}s with no new productive "
                f"output; abandoning this turn and recovering missing rows "
                f"instead of waiting the full {timeout}s timeout"
            )

        # Run the in-session gate.
        try:
            gate_passed, gate_missing = gate_passes(
                scratchpad, project_root, phase
            )
        except Exception as exc:
            log.error(
                f"[{phase.name}] supervised gate check failed: {exc}; "
                f"falling back to whole-phase retry"
            )
            return -2, session

        if gate_passed:
            # Semantic-dedup compaction-continue. The driver pre-writes a
            # crash-safety PASSTHROUGH scaffold (dedup_decisions.md +
            # findings_inventory_deduped.md) BEFORE this subprocess so a
            # timeout never loses findings. That scaffold satisfies the
            # generic artifact gate from turn 1 — so without this guard the
            # loop returns 0 immediately and NEVER spends its continuation
            # budget, even when the subprocess compacted mid-write and left
            # the scaffold unchanged while live candidate pairs remain. That
            # is the exact "passes on the safety net, never actually dedups"
            # no-op. Treat an unchanged PASSTHROUGH + live pairs the same as
            # any other incomplete artifact: drive a FRESH missing-only
            # continuation (clean context, immune to the prior compaction)
            # up to the same budget breadth/depth use. When the budget is
            # spent, ACCEPT the passthrough floor (return 0) — never -2 —
            # because this phase is critical=True and a -2 would cascade to
            # whole-phase retries and ultimately a critical halt. The
            # mechanical passthrough disposition + supplemental dedup +
            # the Python-native report_dedup remain the recall-safe net.
            if _dedup_passthrough_should_continue(
                phase.name, attempt, budget, scratchpad
            ):
                log.info(
                    f"[{phase.name}] gate passes on the pre-written "
                    f"PASSTHROUGH scaffold but live candidate pairs remain "
                    f"(attempt {attempt}/{budget}); driving a fresh "
                    f"missing-only continuation instead of accepting the "
                    f"no-op (compaction-continue, same as breadth/depth)."
                )
                gate_passed = False
                if not gate_missing:
                    gate_missing = [
                        "dedup_decisions.md still carries Status: PASSTHROUGH "
                        "while dedup_candidate_pairs.md has live rows — "
                        "evaluate every candidate pair and OVERWRITE the "
                        "passthrough with real MERGE / KEEP SEPARATE decisions"
                    ]
            else:
                return 0, session

        # Ship 8.13: DONE-then-gate-miss telemetry. When the turn reached
        # end_turn (state.complete -> the coordinator emitted DONE) yet the
        # disk gate REJECTED it, and the transcript shows an auto-compaction
        # fingerprint, this is the verified premature-DONE signature from a prior run.
        # Diagnostic ONLY -- it never gates the phase and never alters
        # control flow (the missing-only / live / resume continuation below
        # handles recovery regardless). Emitted at most once per phase run.
        if state.complete and not compaction_warned:
            try:
                if transcript_shows_compaction(session.transcript_path):
                    log.info(
                        f"[{phase.name}] coordinator emitted DONE after "
                        f"Claude context compaction, but disk gate rejected "
                        f"completion; continuing missing rows. This is not "
                        f"a phase failure."
                    )
                    compaction_warned = True
            except Exception:
                pass

        process_exited = not session.is_alive()

        # Build the repair scope from disk. Breadth/depth return structured
        # per-row status; all other gate-backed phases return [] and fall
        # back to gate_missing detail for the generic artifact repair prompt.
        try:
            row_statuses = compute_phase_row_statuses(scratchpad, phase)
        except Exception as exc:
            log.warning(
                f"[{phase.name}] compute_phase_row_statuses failed: {exc}"
            )
            row_statuses = []

        incomplete_count = sum(
            1 for r in row_statuses
            if r.get("status") and r["status"] != "complete"
        )
        if incomplete_count <= 0 and gate_missing:
            incomplete_count = len(gate_missing)
        if incomplete_count <= 0:
            log.warning(
                f"[{phase.name}] gate failed but no structured incomplete "
                "rows were available; falling back to whole-phase retry"
            )
            return -2, session

        timed_out_without_end = not state.complete and not process_exited
        is_verify_shard = (
            phase.name in L1_VERIFY_PHASE_NAMES
            or phase.name in SC_VERIFY_PHASE_NAMES
        )
        if timed_out_without_end and not is_verify_shard:
            log.warning(
                f"[{phase.name}] PTY turn at attempt {attempt} did not "
                f"reach end_turn within {timeout}s; falling back to "
                f"whole-phase retry"
            )
            return -2, session

        if attempt > budget:
            log.warning(
                f"[{phase.name}] in-session continuation budget ({budget}) "
                f"exhausted; falling back to whole-phase retry"
            )
            return -2, session
        if timed_out_without_end:
            log.warning(
                f"[{phase.name}] PTY turn at attempt {attempt} did not "
                f"reach end_turn within {timeout}s; starting missing-only "
                f"verifier recovery for {incomplete_count} incomplete row(s)"
            )

        # Permanent subscription-preserving policy: never try to keep
        # driving the same interactive PTY, and never depend on --resume /
        # transcript handles. The old coordinator is disposable; the durable
        # state is the set of files on disk. Each recovery turn starts a
        # fresh Claude interactive session with a compact missing-only prompt.
        log.info(
            f"[{phase.name}] continuation #{attempt} via fresh missing-only "
            f"PTY ({incomplete_count} incomplete rows)"
        )
        try:
            display.print_phase_heartbeat(
                phase.name,
                int(time.time() - phase_started_at) if phase_started_at else 0,
                status=(
                    f"gate repair: fresh PTY for {incomplete_count} "
                    "incomplete artifact(s)"
                ),
            )
        except Exception:
            pass
        # Old-PTY termination guarantee + defined refusal (Correction 3):
        # never spawn a second coordinator into the same scratchpad while the
        # old one is alive.
        try:
            session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
        except Exception:
            pass
        _term_deadline = time.time() + 5.0
        while session.is_alive() and time.time() < _term_deadline:
            time.sleep(0.2)
        if session.is_alive():
            log.error(
                f"[{phase.name}] old PTY refused to terminate before "
                f"missing-only continuation; refusing to spawn a second "
                f"coordinator into the same scratchpad -- falling back to "
                f"whole-phase retry"
            )
            return -2, session
        try:
            session = _respawn_missing_only(
                phase=phase,
                scratchpad=scratchpad,
                row_statuses=row_statuses,
                base_cmd=base_cmd,
                cwd=cwd,
                env=env,
                log_file=log_file,
                prompt_path=prompt_path,
                gate_missing=gate_missing,
            )
        except Exception as exc:
            log.error(
                f"[{phase.name}] missing-only respawn failed: {exc}; "
                f"falling back to whole-phase retry"
            )
            return -2, session
        continue


# ===========================================================================
# Python-scheduled recon worker PTYs
# ===========================================================================

_RECON_WORKER_CONCURRENCY = 4


def _should_use_recon_worker_pool(config: dict, scratchpad: Path) -> bool:
    """Return True when recon should run as driver-owned PTY workers."""
    if os.environ.get("PLAMEN_DISABLE_RECON_WORKER_POOL") == "1":
        return False
    if config.get("pipeline") != "sc":
        return False
    # Keep Codex and headless Claude on their existing paths until they are
    # separately validated; this pool solves the Claude PTY coordinator leak.
    return True


def _recon_worker_jobs(config: dict) -> list[dict[str, str]]:
    """Return mode-scaled recon role shards.

    Light keeps two broader Sonnet shards to control cost. Core/Thorough use
    the documented four recon roles without a recon coordinator.
    """
    mode = str(config.get("mode") or "core").lower()
    if mode == "light":
        return [
            {
                "agent_id": "R1",
                "role": "context_static",
                "output": "recon_build_static.md",
                "focus": (
                    "Build/static compile status plus compact design/trust "
                    "context needed for downstream analysis."
                ),
            },
            {
                "agent_id": "R2",
                "role": "inventory_templates",
                "output": "recon_inventory_surface.md",
                "focus": (
                    "Contract inventory, attack surface, event/setter maps, "
                    "detected patterns, and template recommendations."
                ),
            },
        ]
    return [
        {
            "agent_id": "R1",
            "role": "build_static",
            "output": "recon_build_static.md",
            "focus": "Build environment, compile health, static availability, tooling gaps.",
        },
        {
            "agent_id": "R2",
            "role": "design_context",
            "output": "recon_design_context.md",
            "focus": "Protocol purpose, trust boundaries, dependencies, operational implications, invariants.",
        },
        {
            "agent_id": "R3",
            "role": "inventory_surface",
            "output": "recon_inventory_surface.md",
            "focus": "Contracts, functions, state variables, external/public entry points, setters, events.",
        },
        {
            "agent_id": "R4",
            "role": "templates_patterns",
            "output": "recon_templates_patterns.md",
            "focus": "Detected risk patterns, required skills/templates, niche triggers, downstream recommendation matrix.",
        },
    ]


def _build_recon_worker_prompt(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    attempt: int,
    retry_reasons: list[str] | None = None,
) -> str:
    output = job["output"]
    role = job["role"]
    agent_id = job["agent_id"]
    focus = job["focus"]
    methodology = (
        plamen_home()
        / "prompts"
        / str(config.get("language") or "evm")
        / "v2"
        / "phase1-recon-prompt.md"
    ).as_posix()
    retry_block = ""
    if retry_reasons:
        retry_block = (
            "\n## Previous Gate Failure\n\n"
            + "\n".join(f"- {r}" for r in retry_reasons)
            + "\n"
        )
    role_guidance = {
        "build_static": (
            "Establish whether the project can compile and record bounded "
            "build-repair evidence. You may run build-environment and compile "
            "commands only under the Command Boundary below. Do not run tests, "
            "PoCs, fuzzers, Medusa, Echidna, Halmos, Slither detector passes, "
            "or verification-specific commands. Do not write build_status.md "
            "directly."
        ),
        "design_context": (
            "Summarize protocol purpose, trust boundaries, external dependencies, "
            "key invariants, and operational implications. Do not write "
            "design_context.md directly."
        ),
        "inventory_surface": (
            "The mechanical pre-pass ALREADY wrote the FULL contract/function/"
            "state enumeration to contract_inventory.md, function_list.md, and "
            "state_variables.md (see the readable-inputs list below). Those files "
            "are authoritative and are preserved at the top of the canonical "
            "artifacts. DO NOT re-enumerate contracts, functions, or state "
            "variables from source. Produce ONLY the narrative layer on top of "
            "the mechanical enumeration: (1) externally-reachable entry points "
            "with their access level (public / admin / role / contract-only), "
            "(2) attack-surface grouping (asset movement, accounting, privileged "
            "setters, external-call sinks), and (3) trust boundaries — which "
            "actors reach which entry points. "
            "Then a MANDATORY '## Enumeration Gaps' subsection: scan source for "
            "and FLAG with file:line any GENERIC mechanism a regex/Slither pass "
            "can miss — inline assembly, proxy/delegatecall/callcode targets, "
            "dynamic dispatch (function pointers / selector-routed calls), "
            "fallback()/receive(), and raw low-level .call/.staticcall/"
            ".delegatecall — or write 'none found' with what was checked. "
            "Do not write canonical inventory files directly."
        ),
        "templates_patterns": (
            "Derive risk-pattern flags and template/skill/niche recommendations "
            "FROM the mechanical enumeration (contract_inventory.md, "
            "function_list.md, state_variables.md) plus the inventory_surface "
            "attack-surface narrative when present — do NOT re-enumerate from "
            "source. "
            "Derive detected risk patterns and the template/skill/niche "
            "recommendation matrix. This is recommendation data only; do not "
            "create any roster or later-phase coordination artifact."
        ),
        "context_static": (
            "Merged light-mode role: establish whether the project can compile "
            "under the Command Boundary below, then summarize compact design "
            "context, trust boundaries, key invariants, and operational "
            "implications. Do not run tests, PoCs, fuzzers, Medusa, Echidna, "
            "Halmos, Slither detector passes, or verification-specific commands."
        ),
        "inventory_templates": (
            "Merged light-mode role. The mechanical pre-pass ALREADY wrote the "
            "FULL contract/function/state enumeration to contract_inventory.md, "
            "function_list.md, and state_variables.md (see the readable-inputs "
            "list below); those files are authoritative and preserved at the top "
            "of the canonical artifacts. DO NOT re-enumerate from source. Build "
            "ON TOP of the mechanical enumeration: attack surface (entry points "
            "with access level, asset/accounting/privileged-setter/external-call "
            "grouping, trust boundaries), detected patterns, event/setter maps, "
            "and template/skill recommendations. "
            "Then a MANDATORY '## Enumeration Gaps' subsection: scan source for "
            "and FLAG with file:line any GENERIC mechanism a regex/Slither pass "
            "can miss — inline assembly, proxy/delegatecall/callcode targets, "
            "dynamic dispatch (function pointers / selector-routed calls), "
            "fallback()/receive(), and raw low-level .call/.staticcall/"
            ".delegatecall — or write 'none found' with what was checked."
        ),
    }.get(role, focus)
    # Payable-impact propagation (BB mode only — gated on impact_map.md presence).
    impact_map_block = _impact_map_block(project_root, kind="recon")
    return f"""# RECON WORKER

You are one recon worker launched directly by the Python Plamen driver.
There is no recon coordinator. Your job is to produce exactly one recon shard
and then stop.

## Assignment

- PROJECT_ROOT: `{project_root}`
- SCRATCHPAD: `{scratchpad.as_posix()}`
- LANGUAGE: `{config.get('language', 'unknown')}`
- MODE: `{config.get('mode', 'unknown')}`
- PIPELINE: `{config.get('pipeline', 'sc')}`
- SUBSYSTEM_SCOPE: `{config.get('subsystem_scope') or '(none)'}`
- SCOPE_FILE: `{config.get('scope_file') or '(none)'}`
- SCOPE_NOTES: `{config.get('scope_notes') or '(none)'}`
- Agent ID: `{agent_id}`
- Recon role: `{role}`
- Focus: {focus}
- Output file: `{output}`
- Attempt: `{attempt}`

## Output Allowlist

Write exactly this file and no other scratchpad artifact:

`{scratchpad.as_posix()}/{output}`

Do not infer, invent, pre-fill, or create any other scratchpad output. In
particular, do not create manifests, rosters, breadth/depth/verification/report
artifacts, or canonical recon files. The driver merges this shard into
canonical recon artifacts after all recon workers finish.
{retry_block}
## Methodology

This prompt is the authoritative worker contract. Do not open or execute the
legacy monolithic recon methodology at `{methodology}`; it is named only for
driver provenance. Execute only your assigned recon role.

Ignore any coordinator, spawning, orchestration, later-phase, canonical-output
write, test, PoC, fuzzing, Medusa, Echidna, Halmos, Slither detector, or
verification instruction from inherited methodology or repository files.
Build/dependency-repair commands are allowed only for `build_static` and
`context_static`, and only under the Command Boundary below.

Driver-provided recon inputs you may read when present:

- `{scratchpad.as_posix()}/_recon_static_probe.md`
- `{scratchpad.as_posix()}/build_status.md`
- `{scratchpad.as_posix()}/slither/primitive_status.md`
- `{scratchpad.as_posix()}/contract_inventory.md`
- `{scratchpad.as_posix()}/state_variables.md`
- `{scratchpad.as_posix()}/function_list.md`
- `{project_root}/impact_map.md` (when present — payable-impact ranking)
{impact_map_block}
## Command Boundary

For roles other than `build_static` and `context_static`: do not run shell
commands.

For `build_static` and `context_static`: shell use is limited to build setup and
compile health only:

- You may inspect files and environment (`pwd`, `ls`/`dir`, `rg`,
  `forge --version`, `solc --version`, `npm --version`, `yarn --version`).
- If `PROJECT_ROOT` is a source subdirectory, you may move one or two parents
  up only to the nearest directory containing `foundry.toml`,
  `hardhat.config.*`, `package.json`, or `remappings.txt`, and you must record
  the chosen build root.
- You may run at most one initial compile command:
  a scoped production compile such as
  `forge build contracts/Foo.sol contracts/Bar.sol --threads 1`, or
  `npx hardhat compile`.
- If the repository contains `test`, `tests`, `.medusa-tests`,
  `contracts/.medusa-tests`, fuzz, invariant, or verification directories,
  do not run a bare full-project `forge build`; compile explicit production
  contract paths only.
- Compile commands may run longer than the shell UI's short display timeout.
  If a compile command times out or continues in the background, do not start
  another compile. Check existing artifact/build-info timestamps if available,
  then write the shard with `TIMED_OUT_OR_BACKGROUND` status and the evidence
  you have.
- If that compile fails, you may make at most two targeted build-repair
  attempts for missing dependencies, remappings, compiler-version mismatch, or
  Foundry/Hardhat config issues, and after each repair run one compile command.
- You may run `git submodule update --init --recursive` at most once only when
  the compile error shows missing repository dependencies.
- You may run `forge install ... --no-git`, `npm install`, or `yarn install` at
  most once only when the compile error shows a missing dependency required for
  compilation.
- You may run `slither --version` only as an availability probe. Do not run
  `slither <target>`, detector groups, human-summary, call-graph generation, or
  any command that invokes `crytic-compile` from recon.
- You must not run any command matching: `forge test`, `npx hardhat test`,
  `medusa`, `echidna`, `halmos`, `invariant`, `fuzz`, `Verify*.t.sol`,
  `.medusa-tests`, `test/Verify`, or later-phase verification/PoC commands.
- Do not inspect or execute test, fuzz, invariant, `.medusa-tests`, or
  verification directories/configs during recon. Only record compile/build
  readiness and static-tool availability.
- If build setup is still failing after the bounded attempts, stop repairing,
  write the shard with the exact failing command, error tail, attempted fixes,
  and remaining blocker. Later verification can consume that status instead of
  recon retrying indefinitely.

Role-specific task:

{role_guidance}

## Required File Contract

The output file must:

1. Start with these markers:
   `<!-- PLAMEN_ARTIFACT: {output} -->`
   `<!-- PLAMEN_OWNER: {agent_id} -->`
   `<!-- PLAMEN_STATUS: IN_PROGRESS -->`
   `<!-- PLAMEN_PHASE: recon -->`
   `<!-- PLAMEN_VERSION: 1 -->`
   `<!-- RECON_ROLE: {role} -->`
   `<!-- EXPECTED_OUTPUT: {output} -->`
2. Contain substantive role-specific recon data with concrete file/path or
   command evidence where applicable.
3. Include a `## Canonical Merge Hints` section listing which canonical recon
   artifacts your shard should inform.
4. End with `<!-- PLAMEN_STATUS: COMPLETE -->` only after the shard is fully
   written and verified on disk.

When done, return exactly one line:

`DONE: {output} complete`
"""


def _recon_worker_complete(
    scratchpad: Path,
    output: str,
    job: dict[str, str] | None = None,
) -> tuple[bool, list[str]]:
    p = scratchpad / output
    reasons: list[str] = []
    if not p.exists():
        return False, ["missing"]
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return False, [f"unreadable: {exc}"]
    if p.stat().st_size < 400:
        reasons.append("stub or too small")
    if f"PLAMEN_ARTIFACT: {output}" not in text:
        reasons.append(f"missing marker PLAMEN_ARTIFACT: {output}")
    if "PLAMEN_PHASE: recon" not in text:
        reasons.append("missing marker PLAMEN_PHASE: recon")
    if "PLAMEN_STATUS: COMPLETE" not in text:
        reasons.append("missing COMPLETE marker")
    if job is not None:
        expected_owner = str(job.get("agent_id") or "")
        expected_role = str(job.get("role") or "")
        if expected_owner and f"PLAMEN_OWNER: {expected_owner}" not in text:
            reasons.append(f"missing marker PLAMEN_OWNER: {expected_owner}")
        if expected_role and f"RECON_ROLE: {expected_role}" not in text:
            reasons.append(f"missing marker RECON_ROLE: {expected_role}")
        if f"EXPECTED_OUTPUT: {output}" not in text:
            reasons.append(f"missing marker EXPECTED_OUTPUT: {output}")
    return not reasons, reasons


def _install_recon_command_guard(scratchpad: Path, env: dict[str, str]) -> dict[str, str]:
    """Prepend recon-only command wrappers that block later-phase fanout.

    Prompt boundaries are necessary but not sufficient when Claude runs with
    Bash permissions. Recon build repair needs `forge build` / dependency setup,
    while `forge test`, fuzzers, Medusa, and Slither target analysis belong to
    later phases. These wrappers make that boundary deterministic for common
    EVM tool commands without blocking normal file-inspection tools.
    """
    guarded = dict(env)
    guard_dir = scratchpad / "_recon_command_guard"
    try:
        guard_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return guarded

    def _real(name: str) -> str:
        value = shutil.which(name, path=env.get("PATH") or os.environ.get("PATH"))
        return Path(value).as_posix() if value else ""

    reals = {
        "forge": _real("forge"),
        "npx": _real("npx"),
        "npm": _real("npm"),
        "yarn": _real("yarn"),
        "git": _real("git"),
        "slither": _real("slither"),
    }
    for key, value in reals.items():
        if value:
            guarded[f"PLAMEN_REAL_{key.upper()}"] = value

    scripts: dict[str, str] = {
        "forge": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_FORGE:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real forge not found" >&2; exit 127; fi
sub="${1:-}"
case "$sub" in
  build)
    has_path=0
    for arg in "${@:2}"; do
      case "$arg" in
        -*|[0-9]*) ;;
        *.sol|contracts/*|src/*) has_path=1 ;;
      esac
    done
    if [[ "$has_path" == "0" && ( -d "test" || -d "tests" || -d ".medusa-tests" || -d "contracts/.medusa-tests" ) ]]; then
      echo "PLAMEN_RECON_COMMAND_BLOCKED: bare forge build would include test/fuzz surfaces; pass explicit production contract paths during recon" >&2
      exit 126
    fi
    guard_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    lock_dir="${PLAMEN_RECON_BUILD_LOCK:-$guard_root/forge_build.lock}"
    if ! mkdir "$lock_dir" 2>/dev/null; then
      echo "PLAMEN_RECON_COMMAND_BLOCKED: concurrent forge build already running or previous recon build timed out; recon must not stack compiler processes" >&2
      exit 126
    fi
    trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT INT TERM
    "$real" "$@"
    ;;
  install|remappings|config|clean|--version|-V|--help|-h)
    exec "$real" "$@"
    ;;
  test|coverage|snapshot|script|create|verify-contract)
    echo "PLAMEN_RECON_COMMAND_BLOCKED: forge $sub is a later-phase verification/test command; recon may only repair compilation" >&2
    exit 126
    ;;
  *)
    echo "PLAMEN_RECON_COMMAND_BLOCKED: forge $sub is outside recon build-repair allowlist" >&2
    exit 126
    ;;
esac
''',
        "npx": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_NPX:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real npx not found" >&2; exit 127; fi
args=" $* "
if [[ "$args" == *" test"* || "$args" == *" forge test"* || "$args" == *" hardhat test"* ]]; then
  echo "PLAMEN_RECON_COMMAND_BLOCKED: npx test/verification commands are not allowed during recon" >&2
  exit 126
fi
if [[ "${1:-}" == "hardhat" && ( "${2:-}" == "compile" || "${2:-}" == "clean" || "${2:-}" == "--version" ) ]]; then
  exec "$real" "$@"
fi
echo "PLAMEN_RECON_COMMAND_BLOCKED: npx is limited to hardhat compile/clean/version during recon" >&2
exit 126
''',
        "npm": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_NPM:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real npm not found" >&2; exit 127; fi
case "${1:-}" in
  install|ci|--version|-v) exec "$real" "$@" ;;
  *) echo "PLAMEN_RECON_COMMAND_BLOCKED: npm is limited to install/ci/version during recon" >&2; exit 126 ;;
esac
''',
        "yarn": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_YARN:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real yarn not found" >&2; exit 127; fi
case "${1:-}" in
  install|--version|-v) exec "$real" "$@" ;;
  *) echo "PLAMEN_RECON_COMMAND_BLOCKED: yarn is limited to install/version during recon" >&2; exit 126 ;;
esac
''',
        "git": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_GIT:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real git not found" >&2; exit 127; fi
if [[ "${1:-}" == "submodule" && "${2:-}" == "update" ]]; then exec "$real" "$@"; fi
if [[ "${1:-}" == "rev-list" || "${1:-}" == "status" ]]; then exec "$real" "$@"; fi
echo "PLAMEN_RECON_COMMAND_BLOCKED: git is limited to submodule update/status/rev-list during recon" >&2
exit 126
''',
        "slither": r'''#!/usr/bin/env bash
set -euo pipefail
real="${PLAMEN_REAL_SLITHER:-}"
if [[ -z "$real" ]]; then echo "PLAMEN_RECON_COMMAND_BLOCKED: real slither not found" >&2; exit 127; fi
case "${1:-}" in
  --version|-V|version) exec "$real" "$@" ;;
  *) echo "PLAMEN_RECON_COMMAND_BLOCKED: slither target/detector runs are not allowed during recon worker build repair" >&2; exit 126 ;;
esac
''',
    }
    deny_all = r'''#!/usr/bin/env bash
echo "PLAMEN_RECON_COMMAND_BLOCKED: this fuzzer/verification command is not allowed during recon" >&2
exit 126
'''
    for name in ("medusa", "echidna", "halmos"):
        scripts[name] = deny_all

    for name, body in scripts.items():
        try:
            path = guard_dir / name
            path.write_text(body, encoding="utf-8", newline="\n")
            try:
                path.chmod(0o755)
            except Exception:
                pass
        except Exception:
            pass

    old_path = guarded.get("PATH") or os.environ.get("PATH") or ""
    guarded["PATH"] = str(guard_dir) + os.pathsep + old_path
    guarded["PLAMEN_RECON_COMMAND_GUARD"] = str(guard_dir)
    return guarded


def _run_single_recon_worker_pty(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
    retry_reasons: list[str] | None = None,
    allowed_outputs: list[str] | None = None,
    protected_input_names: set[str] | None = None,
) -> dict[str, Any]:
    output = job["output"]
    allowed_output_set = set(allowed_outputs or [output])
    protected_input_set = set(protected_input_names or set())
    session_id = str(uuid.uuid4())
    prompt = _build_recon_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        attempt=attempt,
        retry_reasons=retry_reasons,
    )
    snap = scratchpad / (
        f"_prompt_recon_worker_{Path(output).stem}.attempt{attempt}.md"
    )
    snap.write_text(prompt, encoding="utf-8")
    cmd = _build_fresh_session_cmd(base_cmd, session_id)
    cmd = _rewrite_argv_positional_prompt(cmd, snap)
    worker_env = _install_recon_command_guard(scratchpad, env)
    log_path = scratchpad / (
        f"_stdio_recon_worker_{Path(output).stem}.attempt{attempt}.log"
    )
    known_stats: dict[str, tuple[int, int]] = {}
    try:
        for p in scratchpad.iterdir():
            if p.is_file() and not p.name.startswith("_"):
                try:
                    st = p.stat()
                    known_stats[p.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    known_stats[p.name] = (0, 0)
    except Exception:
        known_stats = {}

    def _worker_poll(_now: float, _state: Any) -> None:
        try:
            for p in scratchpad.iterdir():
                if p.name.startswith("_") or not p.is_file():
                    continue
                known_names = set(known_stats)
                try:
                    st = p.stat()
                    sig = (st.st_size, st.st_mtime_ns)
                except OSError:
                    sig = (0, 0)
                old_sig = known_stats.get(p.name)
                known_stats[p.name] = sig
                if _worker_artifact_name_allowed(p.name, allowed_output_set):
                    continue
                if old_sig == sig:
                    continue
                if p.name in protected_input_set:
                    continue
                if _worker_artifact_is_benign_duplicate_copy(p.name, known_names):
                    moved = _quarantine_worker_duplicate_copy(
                        scratchpad=scratchpad,
                        path=p,
                        phase_name="recon",
                        worker_output=output,
                    )
                    if moved is not None:
                        log.info(
                            "[recon] worker %s quarantined benign duplicate "
                            "scratchpad copy: %s -> %s",
                            output,
                            p.name,
                            moved.relative_to(scratchpad).as_posix(),
                        )
                    continue
                log.error(
                    "[recon] worker %s wrote or modified out-of-scope artifact: %s",
                    output,
                    p.name,
                )
                raise _PtyStop(-4)
        except _PtyStop:
            raise
        except Exception:
            pass

    with log_path.open("w", encoding="utf-8", errors="replace") as out:
        session = ClaudePtySession(
            cmd,
            cwd=project_root,
            env=worker_env,
            session_id=session_id,
            prompt_path=snap,
            log_file=out,
        )
        _register_active_worker_session(session)
        try:
            out.write(f"CLAUDE_TRANSCRIPT={session.transcript_path}\n")
            out.flush()
            session.spawn()
            session.send_bootstrap()
            state = session.wait_for_turn_complete(
                timeout,
                quiescence_s=quiescence_s,
                on_poll=_worker_poll,
            )
            if state.rate_limited:
                # A transient 529/overloaded is provider-wide, NOT a 429
                # account/usage cap. It must NOT escalate to the phase-level
                # usage-cap pause that stops the whole worker pool — Claude
                # Code's own retry loop (exp backoff, up to 10x) usually
                # self-recovers it. Classify it as a retriable worker failure
                # so the gate re-spawns just this one worker. Mirrors the
                # single-subprocess overload path (detect_overloaded backoff).
                if getattr(state, "overloaded", False):
                    return {"output": output, "rc": 1, "status": "overloaded",
                            "reasons": ["transient 529 overloaded -- retriable"]}
                return {"output": output, "rc": 1, "status": "rate_limited"}
            ok, reasons = _recon_worker_complete(scratchpad, output, job)
            return {
                "output": output,
                "rc": 0 if ok else -2,
                "status": "complete" if ok else "incomplete",
                "reasons": reasons,
                "log": str(log_path),
            }
        except _PtyStop as stop:
            return {
                "output": output,
                "rc": stop.rc,
                "status": "containment",
                "reasons": ["worker wrote protected out-of-scope artifact"],
                "log": str(log_path),
            }
        except Exception as exc:
            return {
                "output": output,
                "rc": EXIT_ERROR,
                "status": "error",
                "reasons": [str(exc)],
                "log": str(log_path),
            }
        finally:
            _unregister_active_worker_session(session)
            try:
                session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
            except Exception:
                pass
            try:
                if session.transcript_path.exists():
                    out.write("\n\n# Claude session transcript tail\n")
                    with session.transcript_path.open("rb") as tf:
                        tf.seek(0, 2)
                        size = tf.tell()
                        tf.seek(max(0, size - 65536))
                        out.write(tf.read().decode("utf-8", errors="replace"))
                    out.flush()
            except Exception:
                pass


def _run_recon_worker_pool_pty(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
) -> int:
    jobs = _recon_worker_jobs(config)
    if not jobs:
        log.warning("[recon] worker-pool unavailable: no jobs")
        return -2
    concurrency = min(_RECON_WORKER_CONCURRENCY, max(1, len(jobs)))
    pool_started = time.time()
    retry_reasons_by_output: dict[str, list[str]] = {}
    try:
        (scratchpad / "_recon_worker_pool_contract.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "phase": "recon",
                    "pipeline": config.get("pipeline", "sc"),
                    "mode": config.get("mode", "core"),
                    "outputs": [str(job.get("output") or "") for job in jobs],
                    "jobs": jobs,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning(f"[recon] could not write worker-pool contract marker: {exc}")

    budget = 2
    for pool_attempt in range(1, budget + 1):
        open_jobs = []
        for job in jobs:
            ok, _reasons = _recon_worker_complete(scratchpad, job["output"], job)
            if not ok:
                open_jobs.append(job)
        if not open_jobs:
            try:
                _merge_recon_worker_shards(scratchpad, config)
            except Exception as exc:
                log.warning(f"[recon] worker-shard merge failed: {exc!r}")
                return -2
            passed, missing = gate_passes(scratchpad, project_root, phase)
            if passed:
                return 0
            log.warning(f"[recon] worker-pool canonical gate failed: {missing}")
            return -2
        log.info(
            f"[recon] worker PTY pool attempt {pool_attempt}: "
            f"{len(open_jobs)} open shard(s), concurrency={concurrency}"
        )
        pool_allowed_outputs = [str(job["output"]) for job in open_jobs]
        input_snapshot = _snapshot_worker_input_artifacts(
            scratchpad,
            set(pool_allowed_outputs),
        )
        protected_input_names = set(input_snapshot)
        display.print_phase_heartbeat(
            "recon",
            int(time.time() - pool_started),
            status=_format_worker_pool_progress_status(
                complete=len(jobs) - len(open_jobs),
                total=len(jobs),
                active_outputs=[j["output"] for j in open_jobs[:concurrency]],
                queued=max(0, len(open_jobs) - concurrency),
                phase_label="recon",
            ),
        )
        results: list[dict[str, Any]] = []
        try:
            with _NonBlockingWorkerPool(
                max_workers=concurrency,
                thread_name_prefix="plamen-recon-worker",
            ) as executor:
                fut_to_job = {
                    executor.submit(
                        _run_single_recon_worker_pty,
                        job=job,
                        scratchpad=scratchpad,
                        project_root=project_root,
                        config=config,
                        base_cmd=base_cmd,
                        env=env,
                        # full scaled budget per worker (parity with breadth/
                        # rescan/depth); the 2400 cap starved workers below
                        # scale_timeout on large repos.
                        timeout=max(900, timeout),
                        quiescence_s=quiescence_s,
                        attempt=pool_attempt,
                        retry_reasons=retry_reasons_by_output.get(job["output"]),
                        allowed_outputs=pool_allowed_outputs,
                        protected_input_names=protected_input_names,
                    ): job
                    for job in open_jobs
                }
                pending_futs: set[concurrent.futures.Future] = set(fut_to_job)
                last_progress = time.time()
                while pending_futs:
                    done, pending_futs = concurrent.futures.wait(
                        pending_futs,
                        timeout=_WORKER_POOL_UI_POLL_S,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    now = time.time()
                    elapsed = int(now - pool_started)
                    display.spin(elapsed)
                    if display.graceful_stop.requested:
                        _cancel_pending_worker_futures(pending_futs, executor)
                        raise _PtyStop(-3)
                    for fut in done:
                        result = fut.result()
                        results.append(result)
                        output = result.get("output", "(unknown)")
                        status = result.get("status")
                        log.info(f"[recon] worker {output}: {status}")
                        display.print_phase_heartbeat(
                            "recon",
                            elapsed,
                            status=f"worker {output}: {status}",
                        )
                        if result.get("status") == "rate_limited":
                            log.warning(
                                "[recon] worker %s hit rate limit; stopping "
                                "remaining workers and surfacing phase-level "
                                "rate-limit pause",
                                output,
                            )
                            _cancel_pending_worker_futures(pending_futs, executor)
                            return 1
                        last_progress = now
                    if pending_futs and now - last_progress >= _WORKER_POOL_HEARTBEAT_S:
                        display.print_phase_heartbeat(
                            "recon",
                            elapsed,
                            status=(
                                f"recon worker pool active: {len(pending_futs)} "
                                "worker(s) still running"
                            ),
                        )
                        last_progress = now
        finally:
            restored_inputs = _restore_worker_input_artifacts(
                scratchpad,
                input_snapshot,
            )
            if restored_inputs:
                log.info(
                    "[recon] restored %d pre-existing scratchpad input "
                    "artifact(s) modified during worker batch: %s",
                    len(restored_inputs),
                    restored_inputs[:10],
                )
        if any(r.get("status") == "rate_limited" for r in results):
            return 1
        if any(r.get("rc") == -4 for r in results):
            log.error("[recon] worker-pool containment violation")
            return -4
        remaining_jobs = []
        for job in jobs:
            ok, _reasons = _recon_worker_complete(scratchpad, job["output"], job)
            if not ok:
                remaining_jobs.append(job)
        if not remaining_jobs:
            try:
                _merge_recon_worker_shards(scratchpad, config)
            except Exception as exc:
                log.warning(f"[recon] worker-shard merge failed: {exc!r}")
                return -2
            passed, missing = gate_passes(scratchpad, project_root, phase)
            if passed:
                return 0
            log.warning(f"[recon] worker-pool canonical gate failed: {missing}")
            return -2
        retry_reasons_by_output = {
            str(r.get("output")): [
                f"status={r.get('status')}",
                *[str(x) for x in (r.get("reasons") or [])],
            ]
            for r in results
            if r.get("status") != "complete"
        }
    log.warning("[recon] worker-pool retry budget exhausted")
    # Haltless tail: rather than discarding the work of every worker that DID
    # reach COMPLETE, merge the completed shards and see whether the canonical
    # gate is satisfied. A partial merge never overwrites a complete mechanical
    # artifact (the >=100B merge branch preserves the mechanical body at top and
    # appends the shard as a Recon Worker Addendum).
    completed_jobs = []
    remaining_jobs = []
    for job in jobs:
        ok, _reasons = _recon_worker_complete(scratchpad, job["output"], job)
        if ok:
            completed_jobs.append(job)
        else:
            remaining_jobs.append(job)
    try:
        _merge_recon_worker_shards(scratchpad, config)
    except Exception as exc:
        log.warning(f"[recon] partial-merge failed: {exc!r}")
        return -2
    passed, missing = gate_passes(scratchpad, project_root, phase)
    if passed:
        log.info(
            "[recon] partial-merge over %d/%d completed shards passed canonical "
            "gate; continuing haltless",
            len(completed_jobs),
            len(jobs),
        )
        return 0
    degraded, _new_missing = _try_recon_prepass_marker_degrade(
        scratchpad, config, list(missing)
    )
    if degraded:
        return 0
    log.warning(
        "[recon] partial-merge over %d/%d completed shards did not satisfy "
        "the canonical gate: %s",
        len(completed_jobs),
        len(jobs),
        missing,
    )
    return -2


# ===========================================================================
# Python-scheduled breadth worker PTYs
# ===========================================================================

_BREADTH_WORKER_CONCURRENCY = 3

_L1_BREADTH_LAYERS: tuple[dict[str, Any], ...] = (
    {
        "layer": "network",
        "flags": ("P2P",),
        "skills": "p2p-dos-and-eclipse, go-concurrency-safety / rust-unsafe-audit",
        "difficulty": "HIGH",
    },
    {
        "layer": "mempool",
        "flags": ("MEMPOOL",),
        "skills": "mempool-asymmetric-dos, go-concurrency-safety / rust-unsafe-audit",
        "difficulty": "MEDIUM",
    },
    {
        "layer": "consensus",
        "flags": ("CONSENSUS",),
        "skills": "consensus-safety-invariants, fork-choice, validator lifecycle, hardfork activation",
        "difficulty": "HIGH",
    },
    {
        "layer": "execution",
        "flags": ("EXECUTION",),
        "skills": "execution-client-hardening, cross-environment-semantic-drift when detected",
        "difficulty": "MEDIUM",
    },
    {
        "layer": "crypto",
        "flags": ("BLS", "CRYPTO"),
        "skills": "bls-aggregation-audit, dependency-audit-nodeclient",
        "difficulty": "MEDIUM",
    },
    {
        "layer": "storage",
        "flags": ("STATE_SYNC", "STORAGE"),
        "skills": "state-sync-pruning, go-concurrency-safety / rust-unsafe-audit",
        "difficulty": "LOW-MEDIUM",
    },
    {
        "layer": "rpc",
        "flags": ("RPC",),
        "skills": "rpc-surface-audit",
        "difficulty": "LOW",
    },
    {
        "layer": "cross_chain",
        "flags": ("LIGHT_CLIENT", "CROSS_CHAIN"),
        "skills": "light-client-proof-verification",
        "difficulty": "HIGH",
    },
    {
        "layer": "difficulty",
        "flags": ("DIFFICULTY",),
        "skills": "consensus-safety-invariants for fixed-point / parameter audit",
        "difficulty": "MEDIUM",
    },
    {
        "layer": "cosmos",
        "flags": ("COSMOS_SDK",),
        "skills": "cosmos-sdk-module-safety, cosmos-ibc-security",
        "difficulty": "HIGH",
    },
)


def _breadth_manifest_jobs(scratchpad: Path) -> list[dict[str, str]]:
    """Return one concrete worker job per breadth manifest output."""
    outputs = parse_breadth_manifest_outputs(scratchpad) or []
    agents = parse_breadth_manifest_agents(scratchpad) or []
    jobs: list[dict[str, str]] = []
    for idx, name in enumerate(outputs):
        agent = agents[idx] if idx < len(agents) else {}
        stem = name
        if stem.startswith("analysis_"):
            stem = stem[len("analysis_"):]
        if stem.endswith(".md"):
            stem = stem[:-3]
        focus = agent.get("focus_area") or stem
        agent_id = agent.get("agent_id") or f"B{idx + 1}"
        jobs.append({
            "agent_id": str(agent_id),
            "focus_area": str(focus),
            "output": str(name),
        })
    return jobs


def _truthy_l1_flag(text: str, flag: str) -> bool:
    flag_re = re.escape(flag)
    patterns = (
        rf"\b{flag_re}\b\s*[:=|]\s*(?:true|yes|present|detected|enabled|1)\b",
        rf"\b{flag_re}\b[^\n\r]{{0,80}}(?:true|yes|present|detected|enabled)",
        rf"(?:true|yes|present|detected|enabled)[^\n\r]{{0,80}}\b{flag_re}\b",
    )
    false_re = re.compile(
        rf"\b{flag_re}\b\s*[:=|]\s*(?:false|no|absent|none|disabled|0)\b",
        re.IGNORECASE,
    )
    if false_re.search(text or ""):
        return False
    return any(re.search(p, text or "", re.IGNORECASE) for p in patterns)


def _false_l1_flag(text: str, flag: str) -> bool:
    return bool(
        re.search(
            rf"\b{re.escape(flag)}\b\s*[:=|]\s*(?:false|no|absent|none|disabled|0)\b",
            text or "",
            re.IGNORECASE,
        )
    )


def _l1_breadth_active_layer_defs(scratchpad: Path) -> list[dict[str, Any]]:
    blobs: list[str] = []
    for name in (
        "recon_summary.md",
        "subsystem_map.md",
        "attack_surface.md",
        "trust_boundaries.md",
        "template_recommendations.md",
    ):
        p = scratchpad / name
        try:
            if p.exists():
                blobs.append(p.read_text(encoding="utf-8", errors="replace")[:200_000])
        except Exception:
            pass
    text = "\n".join(blobs)
    active: list[dict[str, Any]] = []
    for layer in _L1_BREADTH_LAYERS:
        flags = tuple(str(f) for f in layer.get("flags") or ())
        if any(_truthy_l1_flag(text, f) for f in flags):
            active.append(layer)
            continue
        if flags and all(_false_l1_flag(text, f) for f in flags):
            continue
        layer_name = str(layer["layer"]).replace("_", "[-_ ]?")
        if re.search(rf"\b{layer_name}\b", text, re.IGNORECASE):
            active.append(layer)
    if not active:
        # Conservative fallback: if recon used an unexpected flag format, keep
        # recall by covering every L1 layer rather than passing a small quorum.
        active = list(_L1_BREADTH_LAYERS)
    return active


def _l1_breadth_group_has_high_difficulty(job: list[dict[str, Any]]) -> bool:
    return any(str(x.get("difficulty")) == "HIGH" for x in job)


def _merge_l1_breadth_layers(
    layers: list[dict[str, Any]],
    mode: str,
) -> list[list[dict[str, Any]]]:
    # Soft caps mirror the audit-mode intent. HIGH layers are never merged
    # with another HIGH layer; if the target cap cannot be met without doing
    # that, preserve quality and exceed the cap.
    target = {"light": 3, "core": 5, "thorough": 7}.get(
        (mode or "core").lower(),
        5,
    )
    jobs = [[layer] for layer in layers]

    while len(jobs) > target:
        merge_idx: tuple[int, int] | None = None
        for i in range(len(jobs)):
            if len(jobs[i]) >= 3:
                continue
            for j in range(i + 1, len(jobs)):
                if len(jobs[i]) + len(jobs[j]) > 3:
                    continue
                if (
                    _l1_breadth_group_has_high_difficulty(jobs[i])
                    and _l1_breadth_group_has_high_difficulty(jobs[j])
                ):
                    continue
                merge_idx = (i, j)
                break
            if merge_idx:
                break
        if not merge_idx:
            break
        i, j = merge_idx
        jobs[i] = jobs[i] + jobs[j]
        del jobs[j]
    return jobs


def _l1_breadth_jobs(scratchpad: Path, config: dict) -> list[dict[str, str]]:
    layer_defs = _l1_breadth_active_layer_defs(scratchpad)
    merged = _merge_l1_breadth_layers(layer_defs, str(config.get("mode", "core")))
    jobs: list[dict[str, str]] = []
    for idx, group in enumerate(merged, start=1):
        names = [str(layer["layer"]) for layer in group]
        primary = names[0]
        output = f"analysis_layer_{primary}.md"
        focus = ", ".join(names)
        skills = "; ".join(str(layer.get("skills") or "") for layer in group)
        difficulty = "/".join(str(layer.get("difficulty") or "") for layer in group)
        jobs.append({
            "agent_id": f"L1B{idx}",
            "focus_area": focus,
            "output": output,
            "layers": ",".join(names),
            "skills": skills,
            "difficulty": difficulty,
        })
    return jobs


def _breadth_worker_jobs(scratchpad: Path, config: dict) -> list[dict[str, str]]:
    if (config.get("pipeline") or "sc") == "l1":
        return _l1_breadth_jobs(scratchpad, config)
    return _breadth_manifest_jobs(scratchpad)


def _breadth_open_jobs(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
) -> list[dict[str, str]]:
    statuses = {
        r.get("name"): r.get("status")
        for r in compute_breadth_row_statuses(scratchpad, phase)
    }
    return [
        job for job in jobs
        if statuses.get(job["output"]) not in ("complete", "legacy_unmarked")
    ]


def _should_use_breadth_worker_pool(config: dict, scratchpad: Path) -> bool:
    """Return True when breadth can be scheduled as driver-owned workers."""
    if (config.get("pipeline") or "sc") == "l1":
        try:
            return bool(_l1_breadth_jobs(scratchpad, config))
        except Exception:
            return False
    manifest = scratchpad / "spawn_manifest.md"
    if not manifest.exists():
        return False
    try:
        return bool(parse_breadth_manifest_outputs(scratchpad))
    except Exception:
        return False


# FIX (recall #1): condensed Rule-13 anti-normalization + a mandate to
# PROMOTE matrix-cell divergences to findings. Surfaced to every SC breadth
# worker (the rule otherwise lives only in generic-security-rules.md, which the
# breadth prompt never reads). Kept short on purpose — the 5-Question core +
# the promotion mandate, not the full 38-line rule block — so it sharpens
# recall without diluting attention.
_BREADTH_ANTI_NORMALIZATION_DIRECTIVE = """
## Anti-Normalization & Divergence Promotion (MANDATORY — Rule 13)

Do NOT close a real divergence with "intended" / "by design" / "correct
architecture" inside a self-check or interaction matrix. A matrix/checklist cell
that identifies a divergence from a documented invariant (effective value !=
documented value; unbounded user input; retroactive/stale parameter; asymmetric
deposit/withdraw or create/consume path; a fee/rate that stacks or exceeds its
documented cap) MUST be promoted to a `## Finding [` block. A divergence left in
a matrix cell is a recall failure. "intended"/"by design" describes a MECHANISM,
not a disposition — it is acceptable ONLY with cited intent evidence
(spec/test/comment).

Before marking any behavior a non-issue because it looks intentional, answer the
5-Question Test: (1) Who is harmed (specific user class)? (2) Can affected users
avoid the harm through their own actions, or is it imposed? (3) Is the harm
documented (informed consent)? (4) Could the protocol achieve the same goal
without the harm? (5) Does the function fulfill its stated purpose completely (no
missing case/asset/state)? Verdict: harmed AND unavoidable AND undocumented ->
FINDING; harmed AND (documented OR avoidable) -> INFO finding; no one harmed ->
genuine non-issue. Also model PASSIVE attacks (timing normal operations at a
favorable state), not only active front-running.
"""


# Per-program PAYABLE-IMPACT steering. Generic, names no protocol — the program
# specifics live ONLY in the generated `impact_map.md` DATA artifact (rendered by
# the gitignored bounty bracket into the harness/PROJECT_ROOT). This block is
# surfaced to recon/breadth/depth ONLY when that file is present, so paid audits
# (no impact_map.md) are entirely unaffected: it STEERS the finite attention an
# agent already has toward terminal payable impacts WITHOUT cutting coverage.
_IMPACT_MAP_DIRECTIVE = """
## Payable-Impact Steering (impact_map.md present)

`impact_map.md` is present in PROJECT_ROOT. Read it. It is the authoritative
PAYABLE-IMPACT ranking for this engagement: per the program's own severity rules
and declared in-scope impacts, it lists which concrete consequences are payable
and at what tier. For every candidate you investigate, answer: "which payable
row in impact_map.md does this candidate's TERMINAL impact realize, and at what
tier?" — and trace the candidate to that impact first. Spend depth on the
highest-payable rows first.

This STEERS where your finite attention goes; it does NOT narrow what you may
report and does NOT cut coverage. `impact_map.md` lists IMPACTS that matter, NOT
vulnerabilities that exist — it is not a checklist of bugs to confirm; you must
still discover the mechanism that produces the impact. A finding that realizes
no payable row is out of payout scope: record it, but do not spend depth budget
prioritizing it. If impact_map.md declares primacy-of-impact, an unlisted impact
still pays at its universal VSC baseline — do not de-prioritize a real impact
merely because it is unlisted.
"""


# Recon variant: recon's job is to PROPAGATE the map into design_context.md so
# every downstream phase inherits the steering even where impact_map.md isn't
# surfaced directly. Generic, names no protocol.
_IMPACT_MAP_RECON_NOTE = """
## Payable-Impact Map (impact_map.md present)

`impact_map.md` is present in PROJECT_ROOT — the program's PAYABLE-IMPACT ranking
(payable consequences and tiers from its own severity rules). Read it, copy its
"Payable impacts" table verbatim into `design_context.md` under a
`## Payable Impact Map` heading, and derive Operational Implications from the
payable rows (what the protocol must guarantee so each payable impact cannot
occur). This propagates the payable focus to every downstream phase. It steers
attention; it does not narrow scope.
"""


def _impact_map_block(project_root: str, kind: str = "analysis") -> str:
    """Return the payable-impact steering directive iff `impact_map.md` exists in
    PROJECT_ROOT (BB harness root). Empty for paid audits — clean unconditional
    injection at the splice point. File-presence-gated so the committed driver
    carries only this generic seam; all program specifics live in the artifact.

    `kind="recon"` returns the propagate-into-design_context note; otherwise the
    candidate-prioritization directive for breadth/depth."""
    try:
        if project_root and (Path(project_root) / "impact_map.md").is_file():
            return _IMPACT_MAP_RECON_NOTE if kind == "recon" else _IMPACT_MAP_DIRECTIVE
    except Exception:
        pass
    return ""


def _build_breadth_worker_prompt(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    attempt: int,
    retry_reasons: list[str] | None = None,
) -> str:
    output = job["output"]
    agent_id = job["agent_id"]
    focus = job["focus_area"]
    pipeline = str(config.get("pipeline", "sc"))
    methodology = (
        plamen_home() / "prompts" / "l1" / "phase3-breadth-driver.md"
        if pipeline == "l1"
        else plamen_home() / "prompts" / "shared" / "v2" / "phase3-breadth.md"
    ).as_posix()
    finding_format = (
        plamen_home() / "rules" / "finding-output-format.md"
    ).as_posix()
    shard = scratchpad / _opengrep_shard_filename(agent_id, focus)
    shard_line = (
        f"- Assigned opengrep shard: `{shard.as_posix()}`"
        if shard.exists()
        else (
            f"- Assigned opengrep shard: `{shard.as_posix()}` "
            "(not present; use recon/source context)"
        )
    )
    l1_block = ""
    if pipeline == "l1":
        layers = job.get("layers", focus)
        skills = job.get("skills", "")
        difficulty = job.get("difficulty", "")
        l1_block = f"""
## L1 Layer Assignment

- Layers: `{layers}`
- Difficulty: `{difficulty}`
- L1 skills to apply: {skills}

Follow the L1 breadth layer-decomposition methodology in `{methodology}`.
For each assigned layer, perform trust-boundary audit, opengrep
cross-reference, skill-directed analysis, concurrency/panic checks where
applicable, and write the mandatory Chain Summary table.
"""
    retry_block = ""
    if retry_reasons:
        retry_block = (
            "\n## Previous Gate Failure\n\n"
            + "\n".join(f"- {r}" for r in retry_reasons)
            + "\n"
        )
    # P1: inject the recon-selected skills bound to this focus area (SC only;
    # L1 already injects via l1_block above).
    sc_skill_block = ""
    if pipeline != "l1":
        try:
            breadth_map, _ = _parse_sc_skill_bindings(
                scratchpad, str(config.get("language", ""))
            )
            sc_skill_block = _sc_skill_injection_block(
                breadth_map.get(str(focus).lower(), []), agent_kind="breadth",
                language=str(config.get("language", "")),
            )
        except Exception as exc:  # never block prompt assembly on this
            log.debug(f"[breadth] skill-injection skipped for {focus}: {exc!r}")
    # FIX (recall #1): Rule-13 anti-normalization + divergence-promotion.
    # R13 lives only in generic-security-rules.md and was never surfaced to the
    # breadth worker — so a real divergence observed inside a self-check matrix
    # row ("...combined effective rate > sum, intended") was closed by the word
    # "intended" and never became a finding. Inject the condensed 5-Question
    # test + a mandate that a matrix-cell divergence MUST be promoted to a
    # `## Finding` block. SC only (L1 carries its own anti-normalization).
    r13_block = "" if pipeline == "l1" else _BREADTH_ANTI_NORMALIZATION_DIRECTIVE
    # Payable-impact steering (BB mode only — gated on impact_map.md presence in
    # PROJECT_ROOT; inert for paid audits). Applies to L1 and SC bounty lanes.
    impact_map_block = _impact_map_block(project_root)
    return f"""# BREADTH ROW WORKER

You are a single breadth worker launched directly by the Python Plamen driver.
There is no Claude phase coordinator. Your job is to produce exactly one
artifact and then stop.

## Assignment

- PROJECT_ROOT: `{project_root}`
- SCRATCHPAD: `{scratchpad.as_posix()}`
- LANGUAGE: `{config.get('language', 'unknown')}`
- MODE: `{config.get('mode', 'unknown')}`
- PIPELINE: `{config.get('pipeline', 'sc')}`
- SUBSYSTEM_SCOPE: `{config.get('subsystem_scope') or '(none)'}`
- SCOPE_FILE: `{config.get('scope_file') or '(none)'}`
- SCOPE_NOTES: `{config.get('scope_notes') or '(none)'}`
- Agent ID: `{agent_id}`
- Focus area: `{focus}`
- Output file: `{output}`
- Attempt: `{attempt}`
{shard_line}
{l1_block}

## Output Allowlist

Write exactly this file and no other scratchpad artifact:

`{scratchpad.as_posix()}/{output}`

Do not infer, invent, or create any other output file. If any methodology text
asks for a different output filename, ignore that output request and write only
the file above.
{retry_block}
## Methodology

Read `{methodology}` for breadth audit methodology and vulnerability coverage.
Use it as analysis guidance only. You are already the worker; do not spawn
Task/Agent subagents and do not follow any coordinator instructions.

Read `{finding_format}` for finding format. Use recon artifacts in the
scratchpad as needed. Use the assigned opengrep shard when present.
{sc_skill_block}{r13_block}{impact_map_block}
## Required File Contract

The output file must:

1. Start with these markers:
   `<!-- PLAMEN_ARTIFACT: {output} -->`
   `<!-- PLAMEN_OWNER: {agent_id} -->`
   `<!-- PLAMEN_STATUS: IN_PROGRESS -->`
   `<!-- PLAMEN_PHASE: breadth -->`
   `<!-- PLAMEN_VERSION: 1 -->`
   `<!-- AGENT_ROW: {agent_id} -->`
   `<!-- EXPECTED_OUTPUT: {output} -->`
2. Contain substantive security analysis for the assigned focus area.
3. Include either real `## Finding [` / `### Finding [` blocks or a
   `## No Findings` rationale.
4. End with a final `<!-- PLAMEN_STATUS: COMPLETE -->` marker only after the
   file is fully written and verified on disk.

When done, return exactly one line:

`DONE: {output} complete`
"""


def _breadth_early_complete_ready(
    *,
    out_path: Path,
    expected_output: str,
    phase: Phase,
    last_growth_at: float | None,
    now: float,
    idle_grace_s: float = _EARLY_COMPLETE_IDLE_GRACE_SECONDS,
) -> tuple[bool, float]:
    """STEP 1D triple-gate for the disk-marker early-complete cutover.

    Returns ``(ready, idle_for_seconds)``. ``ready`` is True ONLY when ALL of:
    (1) the worker's own output exists with the PLAMEN_STATUS COMPLETE marker
        (``is_artifact_complete``),
    (2) the file's PLAMEN_ARTIFACT / EXPECTED_OUTPUT markers match THIS assigned
        row (``validate_breadth_artifact_ownership``) -- this matches on the
        worker's OWN markers, not a driver-side role-name guess, so it
        reconciles every ecosystem's role-name shapes generically, and
    (3) the worker has been disk-idle for at least ``idle_grace_s``.

    A missing/non-COMPLETE marker => not ready. An ownership mismatch => not
    ready. So it can never falsely complete an unfinished or mis-owned worker.
    Never raises.
    """
    try:
        complete = is_artifact_complete(
            out_path, max(phase.min_artifact_bytes, 500)
        )
    except Exception:
        complete = False
    if not complete:
        return False, 0.0
    try:
        owned, _own_reasons = validate_breadth_artifact_ownership(
            out_path, expected_output=expected_output
        )
    except Exception:
        owned = False
    if not owned:
        return False, 0.0
    anchor = last_growth_at if last_growth_at is not None else now
    idle_for = max(0.0, now - anchor)
    return (idle_for >= idle_grace_s), idle_for


def _run_single_breadth_worker_pty(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
    retry_reasons: list[str] | None = None,
    allowed_outputs: list[str] | None = None,
) -> dict[str, Any]:
    output = job["output"]
    allowed_output_set = set(allowed_outputs or [output])
    session_id = str(uuid.uuid4())
    prompt = _build_breadth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        attempt=attempt,
        retry_reasons=retry_reasons,
    )
    snap = scratchpad / (
        f"_prompt_breadth_worker_{Path(output).stem}.attempt{attempt}.md"
    )
    snap.write_text(prompt, encoding="utf-8")
    cmd = _build_fresh_session_cmd(base_cmd, session_id)
    cmd = _rewrite_argv_positional_prompt(cmd, snap)
    log_path = scratchpad / (
        f"_stdio_breadth_worker_{Path(output).stem}.attempt{attempt}.log"
    )
    known_stats: dict[str, tuple[int, int]] = {}
    try:
        for p in scratchpad.iterdir():
            if p.is_file() and not p.name.startswith("_"):
                try:
                    st = p.stat()
                    known_stats[p.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    known_stats[p.name] = (0, 0)
    except Exception:
        known_stats = {}

    # STEP 1D disk-idle tracker: timestamp of the last observed growth/mtime
    # change in ANY tracked (non-underscore) scratchpad file. Mutable holder so
    # the poll closure can update it. ``None`` until first observed growth.
    _last_disk_growth_at: list[float | None] = [None]
    out_path = scratchpad / output

    def _worker_poll(_now: float, _state: Any) -> None:
        try:
            observed_growth = False
            for p in scratchpad.iterdir():
                if p.name.startswith("_") or not p.is_file():
                    continue
                known_names = set(known_stats)
                try:
                    st = p.stat()
                    sig = (st.st_size, st.st_mtime_ns)
                except OSError:
                    sig = (0, 0)
                old_sig = known_stats.get(p.name)
                known_stats[p.name] = sig
                if old_sig != sig:
                    observed_growth = True
                if _worker_artifact_name_allowed(p.name, allowed_output_set):
                    continue
                if old_sig == sig:
                    continue
                if _worker_artifact_is_benign_duplicate_copy(p.name, known_names):
                    moved = _quarantine_worker_duplicate_copy(
                        scratchpad=scratchpad,
                        path=p,
                        phase_name="breadth",
                        worker_output=output,
                    )
                    if moved is not None:
                        log.info(
                            "[breadth] worker %s quarantined benign duplicate "
                            "scratchpad copy: %s -> %s",
                            output,
                            p.name,
                            moved.relative_to(scratchpad).as_posix(),
                        )
                    continue
                log.error(
                    "[breadth] worker %s wrote or modified out-of-scope "
                    "artifact: %s",
                    output,
                    p.name,
                )
                raise _PtyStop(-4)

            if observed_growth:
                _last_disk_growth_at[0] = _now

            # STEP 1D: path-independent early-complete cutover. Anchor the idle
            # clock to now on the first poll where no prior growth was observed
            # (artifact already complete on disk before the first poll), so the
            # grace window is still honoured.
            if _last_disk_growth_at[0] is None:
                _last_disk_growth_at[0] = _now
            ready, idle_for = _breadth_early_complete_ready(
                out_path=out_path,
                expected_output=output,
                phase=phase,
                last_growth_at=_last_disk_growth_at[0],
                now=_now,
            )
            if ready:
                log.info(
                    "[breadth] worker %s early-complete cutover: "
                    "artifact present + COMPLETE marker + owned, "
                    "disk-idle for %ds",
                    output,
                    int(idle_for),
                )
                raise _PtyEarlyComplete()
        except _PtyStop:
            raise
        except Exception:
            pass

    with log_path.open("w", encoding="utf-8", errors="replace") as out:
        session = ClaudePtySession(
            cmd,
            cwd=project_root,
            env=env,
            session_id=session_id,
            prompt_path=snap,
            log_file=out,
        )
        _register_active_worker_session(session)
        try:
            out.write(f"CLAUDE_TRANSCRIPT={session.transcript_path}\n")
            out.flush()
            session.spawn()
            session.send_bootstrap()
            state = session.wait_for_turn_complete(
                timeout,
                quiescence_s=quiescence_s,
                on_poll=_worker_poll,
            )
            if state.rate_limited:
                # A transient 529/overloaded is provider-wide, NOT a 429
                # account/usage cap. It must NOT escalate to the phase-level
                # usage-cap pause that stops the whole worker pool — Claude
                # Code's own retry loop (exp backoff, up to 10x) usually
                # self-recovers it. Classify it as a retriable worker failure
                # so the gate re-spawns just this one worker. Mirrors the
                # single-subprocess overload path (detect_overloaded backoff).
                if getattr(state, "overloaded", False):
                    return {"output": output, "rc": 1, "status": "overloaded",
                            "reasons": ["transient 529 overloaded -- retriable"]}
                return {"output": output, "rc": 1, "status": "rate_limited"}
            status_rows = compute_breadth_row_statuses(scratchpad, phase)
            status = next(
                (r for r in status_rows if r.get("name") == output),
                {"status": "missing", "reasons": []},
            )
            ok = status.get("status") == "complete"
            return {
                "output": output,
                "rc": 0 if ok else -2,
                "status": status.get("status"),
                "reasons": list(status.get("reasons") or []),
                "log": str(log_path),
            }
        except _PtyEarlyComplete:
            # Disk-marker early-complete cutover: resolve the row via the normal
            # status computation so it lands 'complete' and frees the slot
            # cleanly, rather than the 'containment' label.
            status_rows = compute_breadth_row_statuses(scratchpad, phase)
            status = next(
                (r for r in status_rows if r.get("name") == output),
                {"status": "missing", "reasons": []},
            )
            ok = status.get("status") == "complete"
            return {
                "output": output,
                "rc": 0 if ok else -2,
                "status": status.get("status"),
                "reasons": list(status.get("reasons") or []),
                "log": str(log_path),
            }
        except _PtyStop as stop:
            return {
                "output": output,
                "rc": stop.rc,
                "status": "containment",
                "reasons": ["worker wrote protected out-of-scope artifact"],
                "log": str(log_path),
            }
        except Exception as exc:
            return {
                "output": output,
                "rc": EXIT_ERROR,
                "status": "error",
                "reasons": [str(exc)],
                "log": str(log_path),
            }
        finally:
            _unregister_active_worker_session(session)
            try:
                session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
            except Exception:
                pass
            try:
                if session.transcript_path.exists():
                    out.write("\n\n# Claude session transcript tail\n")
                    with session.transcript_path.open("rb") as tf:
                        tf.seek(0, 2)
                        size = tf.tell()
                        tf.seek(max(0, size - 65536))
                        out.write(tf.read().decode("utf-8", errors="replace"))
                    out.flush()
            except Exception:
                pass


def _worker_artifact_name_allowed(name: str, allowed_outputs: set[str]) -> bool:
    """Return True for allowed final artifacts and their atomic-write temps."""
    if name in allowed_outputs:
        return True
    for output in allowed_outputs:
        if name.startswith(output + ".tmp"):
            return True
        if name.startswith(output + ".part"):
            return True
    return False


_WORKER_DUPLICATE_COPY_RE = re.compile(r"^(.+?)\s+\d+(\.[^./\\]+)$")


def _worker_duplicate_copy_base_name(name: str) -> str | None:
    """Return canonical sibling name for Claude-created ``foo 2.md`` copies."""
    match = _WORKER_DUPLICATE_COPY_RE.match(name)
    if not match:
        return None
    return f"{match.group(1)}{match.group(2)}"


def _worker_artifact_is_benign_duplicate_copy(
    name: str,
    known_names: set[str],
) -> bool:
    """Detect duplicate-copy scratchpad artifacts produced beside inputs.

    Claude occasionally creates files like ``meta_buffer 2.md`` when an input
    artifact already exists and the model attempts a write/copy despite the
    one-output worker contract. These are not consumed by gates and should not
    fail every concurrent worker that happens to observe the same stray file.
    """
    base = _worker_duplicate_copy_base_name(name)
    return bool(base and base in known_names)


def _quarantine_worker_duplicate_copy(
    *,
    scratchpad: Path,
    path: Path,
    phase_name: str,
    worker_output: str,
) -> Path | None:
    """Move a benign duplicate-copy artifact out of the live scratchpad."""
    try:
        if not path.exists() or not path.is_file():
            return None
        target_dir = scratchpad / "_overflow" / "worker_strays"
        target_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(worker_output).stem
        stamp = int(time.time() * 1000)
        target = target_dir / f"{phase_name}_{stem}_{stamp}_{path.name}"
        n = 1
        while target.exists():
            target = target_dir / f"{phase_name}_{stem}_{stamp}_{n}_{path.name}"
            n += 1
        path.replace(target)
        return target
    except Exception:
        return None


def _snapshot_worker_input_artifacts(
    scratchpad: Path,
    output_names: set[str],
) -> dict[str, bytes]:
    """Capture pre-existing scratchpad inputs before a worker batch.

    Worker pools run multiple Claude PTYs against one scratchpad. A live poller
    cannot reliably attribute a pre-existing input artifact's mtime/content
    change to one worker, and killing the whole pool loses more audit signal
    than it protects. Snapshot inputs instead: worker outputs stay strictly
    gated, while accidental edits to prior-phase inputs are restored after the
    batch.
    """
    snapshot: dict[str, bytes] = {}
    try:
        for p in scratchpad.iterdir():
            if (
                not p.is_file()
                or p.name.startswith("_")
                or p.name.startswith(".")
                or p.name in output_names
            ):
                continue
            try:
                snapshot[p.name] = p.read_bytes()
            except OSError:
                continue
    except Exception:
        pass
    return snapshot


def _restore_worker_input_artifacts(
    scratchpad: Path,
    snapshot: dict[str, bytes],
) -> list[str]:
    """Restore worker-pool input artifacts that changed during the batch."""
    restored: list[str] = []
    for name, before in snapshot.items():
        p = scratchpad / name
        try:
            if not p.exists() or not p.is_file():
                continue
            try:
                current = p.read_bytes()
            except OSError:
                continue
            if current == before:
                continue
            tmp = p.with_name(
                f"{p.name}.restore.{os.getpid()}.{uuid.uuid4().hex[:12]}"
            )
            tmp.write_bytes(before)
            tmp.replace(p)
            restored.append(name)
        except Exception:
            continue
    return restored


_WORKER_POOL_HEARTBEAT_S = 300
_WORKER_POOL_UI_POLL_S = 0.10


def _format_worker_pool_progress_status(
    *,
    complete: int,
    total: int,
    active_outputs: list[str],
    queued: int,
    phase_label: str,
) -> str:
    active = max(0, len(active_outputs))
    parts = [
        f"worker pool: {active} running",
        f"{max(0, queued)} queued/missing",
    ]
    if active_outputs:
        names = ", ".join(
            Path(name).stem
            .removeprefix("analysis_")
            .removeprefix("depth_")
            for name in active_outputs[:3]
        )
        extra = f" +{len(active_outputs) - 3}" if len(active_outputs) > 3 else ""
        parts.append(f"active {names}{extra}")
    else:
        parts.append(f"{phase_label} scheduler polling")
    return "; ".join(parts)


def _breadth_worker_pool_progress_status(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
    active_outputs: list[str],
) -> str:
    try:
        rows = compute_breadth_row_statuses(scratchpad, phase)
    except Exception:
        rows = []
    complete = sum(1 for r in rows if r.get("status") == "complete")
    queued = max(0, len(jobs) - complete - len(active_outputs))
    return _format_worker_pool_progress_status(
        complete=complete,
        total=len(jobs),
        active_outputs=active_outputs,
        queued=queued,
        phase_label="breadth",
    )


def _run_breadth_worker_pool_pty_core(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
) -> int:
    """Run breadth as bounded top-level Claude PTY workers, one per artifact.

    This is the unmodified baseline roster runner (Wave 0) — the M3 hard
    recall floor. See `_run_breadth_worker_pool_pty` below for the thin
    wave-gating wrapper; this function's body/behavior is byte-identical to
    pre-M3.
    """
    jobs = _breadth_worker_jobs(scratchpad, config)
    if not jobs:
        log.warning("[breadth] worker-pool unavailable: no manifest jobs")
        return -2
    budget = int(config.get("pty_continuation_budget", 3))
    concurrency = min(_BREADTH_WORKER_CONCURRENCY, max(1, len(jobs)))
    retry_reasons_by_output: dict[str, list[str]] = {}
    pool_started = time.time()
    try:
        (scratchpad / "_breadth_worker_pool_contract.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "phase": "breadth",
                    "pipeline": config.get("pipeline", "sc"),
                    "outputs": [str(job.get("output") or "") for job in jobs],
                    "jobs": jobs,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning(f"[breadth] could not write worker-pool contract marker: {exc}")

    for pool_attempt in range(1, budget + 2):
        open_jobs = _breadth_open_jobs(scratchpad, phase, jobs)
        if not open_jobs:
            passed, missing = gate_passes(scratchpad, project_root, phase)
            if passed:
                return 0
            log.warning(f"[breadth] worker-pool gate failed: {missing}")
            return -2
        if pool_attempt > budget + 1:
            break
        log.info(
            f"[breadth] worker PTY pool attempt {pool_attempt}: "
            f"{len(open_jobs)} open row(s), concurrency={concurrency}"
        )
        pool_allowed_outputs = [str(job["output"]) for job in open_jobs]
        display.print_phase_heartbeat(
            "breadth",
            int(time.time() - pool_started),
            status=_breadth_worker_pool_progress_status(
                scratchpad,
                phase,
                jobs,
                [j["output"] for j in open_jobs[:concurrency]],
            ),
        )
        results: list[dict[str, Any]] = []
        with _NonBlockingWorkerPool(
            max_workers=concurrency,
            thread_name_prefix="plamen-breadth-worker",
        ) as executor:
            fut_to_job = {
                executor.submit(
                    _run_single_breadth_worker_pty,
                    job=job,
                    scratchpad=scratchpad,
                    project_root=project_root,
                    config=config,
                    phase=phase,
                    base_cmd=base_cmd,
                    env=env,
                    timeout=timeout,
                    quiescence_s=quiescence_s,
                    attempt=pool_attempt,
                    retry_reasons=retry_reasons_by_output.get(job["output"]),
                    allowed_outputs=pool_allowed_outputs,
                ): job
                for job in open_jobs
            }
            pending_futs: set[concurrent.futures.Future] = set(fut_to_job)
            last_progress = time.time()
            while pending_futs:
                done, pending_futs = concurrent.futures.wait(
                    pending_futs,
                    timeout=_WORKER_POOL_UI_POLL_S,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                now = time.time()
                elapsed = int(now - pool_started)
                display.spin(elapsed)
                if display.graceful_stop.requested:
                    _cancel_pending_worker_futures(pending_futs, executor)
                    raise _PtyStop(-3)
                for fut in done:
                    result = fut.result()
                    results.append(result)
                    output = result.get("output", "(unknown)")
                    status = result.get("status")
                    log.info(f"[breadth] worker {output}: {status}")
                    display.print_phase_heartbeat(
                        "breadth",
                        elapsed,
                        status=f"worker {output}: {status}",
                    )
                    if result.get("status") == "rate_limited":
                        log.warning(
                            "[breadth] worker %s hit rate limit; stopping "
                            "remaining workers and surfacing phase-level "
                            "rate-limit pause",
                            output,
                        )
                        _cancel_pending_worker_futures(pending_futs, executor)
                        return 1
                    last_progress = now
                if pending_futs and now - last_progress >= _WORKER_POOL_HEARTBEAT_S:
                    active_outputs = [
                        fut_to_job[fut]["output"]
                        for fut in pending_futs
                        if fut in fut_to_job
                    ][:concurrency]
                    display.print_phase_heartbeat(
                        "breadth",
                        elapsed,
                        status=_breadth_worker_pool_progress_status(
                            scratchpad,
                            phase,
                            jobs,
                            active_outputs,
                        ),
                    )
                    last_progress = now
        if any(r.get("status") == "rate_limited" for r in results):
            return 1
        if any(r.get("rc") == -4 for r in results):
            log.error("[breadth] worker-pool containment violation")
            return -4
        retry_reasons_by_output = {
            str(r.get("output")): [
                f"status={r.get('status')}",
                *[str(x) for x in (r.get("reasons") or [])],
            ]
            for r in results
            if r.get("status") != "complete"
        }
        passed, missing = gate_passes(scratchpad, project_root, phase)
        if passed:
            return 0
        log.info(
            f"[breadth] worker-pool attempt {pool_attempt} incomplete: {missing}"
        )
    log.warning("[breadth] worker-pool retry budget exhausted")
    return -2


# ===========================================================================
# Breadth Wave Gating (Wave-4 M3) — yield-gated ADDITIVE breadth waves
# ===========================================================================
#
# Baseline breadth (Wave 0, `_run_breadth_worker_pool_pty_core` above) is the
# HARD RECALL FLOOR and is completely unmodified by this section: it always
# runs in full regardless of yield. Everything below is strictly ADDITIVE and
# strictly opt-in (`breadth_wave_gating_enabled` config flag, default OFF, AND
# mode must be Thorough) — the default/off path never even evaluates a wave
# decision. See `_breadth_wave_gating_enabled`.
#
# FOLLOW-UP (flagged, intentionally not implemented here): wave jobs are run
# via a dedicated best-effort pool (`_breadth_run_wave_extension`) OUTSIDE the
# baseline roster's generic retry/gate loop (`_breadth_open_jobs` /
# `compute_breadth_row_statuses`), because that loop's completion tracking is
# keyed off `spawn_manifest.md` (or the JSON worker-pool contract as an
# EXCLUSIVE fallback only when the manifest is absent) — wave outputs are
# deliberately not manifest-declared, so folding them into that loop would
# either (a) require mutating the shared, heavily-tested
# `compute_breadth_row_statuses` completion-gating code (plamen_validators.py)
# to union contract-only outputs with manifest outputs, or (b) spin every
# wave job through the full retry budget every attempt because its status can
# never read "complete". Both are exactly the "reshaping the pool runner" /
# "half-landed spawn loop" risk this item calls out — so wave completion is
# instead judged independently and mechanically, straight off disk
# (`_breadth_wave_count_above_info`), never via that shared gate.

_BREADTH_WAVE_EXTRA_JOBS_PER_WAVE = 2
_BREADTH_WAVE_OUTPUT_RE = re.compile(r"^analysis_wave(\d+)_\d+\.md$")
_BREADTH_WAVE_SEVERITY_LINE_RE = re.compile(
    r"(?im)^\s*(?:[*_]{0,2})severity(?:[*_]{0,2})\s*:\s*([A-Za-z /]+)"
)


def _breadth_wave_gating_enabled(config: dict) -> bool:
    """M3: additive breadth waves are Thorough-only and strictly opt-in.

    Absent (or falsy) `breadth_wave_gating_enabled` -> disabled — the
    default/off path, byte-identical to pre-M3 behavior. Light/Core modes
    are NEVER wave-gated even if the flag is set (hard mode gate, matches
    the AUDIT MODES table: waves are a Thorough-only concept). The L1
    pipeline's breadth jobs use a different shape (layers/skills/difficulty,
    no `focus_area` roster to rotate) and are intentionally NOT wave-gated
    yet — flagged as a follow-up, not silently mis-handled.
    """
    if not config.get("breadth_wave_gating_enabled"):
        return False
    if str(config.get("mode", "core")).lower() != "thorough":
        return False
    if (config.get("pipeline") or "sc") == "l1":
        return False
    return True


def _breadth_wave_count_above_info(scratchpad: Path, outputs: list[str]) -> int:
    """Mechanically count above-Info findings across the given output files.

    Reuses `_iter_finding_blocks` (the same `## Finding [ID]` / `### Finding
    [ID]` parser `_compute_depth_confidence` uses) plus `try_normalize_severity`
    for the severity token on each block's `**Severity**:` line — no new
    finding format is invented, per the M3 mandate to reuse existing
    finding counters/parsers. A block with no recognizable severity line is
    conservatively NOT counted (never inflates yield on malformed output).
    """
    count = 0
    for name in outputs:
        try:
            text = (scratchpad / name).read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception:
            continue
        for _finding_id, block in _iter_finding_blocks(text):
            sev_m = _BREADTH_WAVE_SEVERITY_LINE_RE.search(block)
            if not sev_m:
                continue
            norm = try_normalize_severity(sev_m.group(1))
            if norm and norm != "Informational":
                count += 1
    return count


def _breadth_wave_yield_threshold(prior_yields: list[int]) -> float:
    """Running-percentile (median) of prior wave yields. Empty -> 0.0."""
    if not prior_yields:
        return 0.0
    ordered = sorted(prior_yields)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _breadth_wave_should_spawn_next(
    *,
    prior_yields: list[int],
    this_wave_yield: int,
    waves_spawned_so_far: int,
    max_extra_waves: int = 2,
) -> tuple[bool, str]:
    """Decide whether to spawn one more additive wave.

    `this_wave_yield` is the most recently completed wave's mechanical
    above-Info finding count (wave 0's yield, the first time this is
    evaluated); `prior_yields` is every wave's yield strictly BEFORE that
    one. Spawn iff still productive (yield >= the running median of
    everything before it — a wave that is at least as productive as the
    series so far keeps the series going) AND the hard extra-wave cap has
    not been reached. A wave with zero yield never spawns a follow-up,
    regardless of history.
    """
    if waves_spawned_so_far >= max_extra_waves:
        return False, (
            f"hard wave cap reached ({waves_spawned_so_far}/{max_extra_waves})"
        )
    if this_wave_yield <= 0:
        return False, "zero-yield wave -- stopping additive spawn"
    if not prior_yields:
        return True, "first measured wave was productive -- sampling next wave"
    threshold = _breadth_wave_yield_threshold(prior_yields)
    if this_wave_yield >= threshold:
        return True, (
            f"yield {this_wave_yield} >= running median {threshold} -- continuing"
        )
    return False, (
        f"yield {this_wave_yield} < running median {threshold} -- stopping"
    )


def _breadth_wave_extra_jobs(
    baseline_jobs: list[dict[str, str]],
    wave_number: int,
) -> list[dict[str, str]]:
    """Build a small additive batch of breadth jobs for wave `wave_number`.

    Reuses the exact job-dict shape `_breadth_manifest_jobs` produces
    (agent_id/focus_area/output) so the existing worker spawn path (prompt
    builder, PTY runner) needs no changes to consume these jobs; only the
    focus areas are rotated (a fresh angle on the baseline roster, echoing
    the Phase 3b/3c re-scan convention of broader/overlapping scope) and
    output filenames are wave-namespaced (`analysis_wave{N}_{i}.md`) so they
    never collide with the baseline or an earlier wave's artifact.
    """
    if not baseline_jobs or wave_number < 1:
        return []
    focus_areas = [
        str(j.get("focus_area") or "") for j in baseline_jobs if j.get("focus_area")
    ]
    jobs: list[dict[str, str]] = []
    for i in range(1, _BREADTH_WAVE_EXTRA_JOBS_PER_WAVE + 1):
        rotated = (
            focus_areas[(i - 1) % len(focus_areas)] if focus_areas
            else "full codebase"
        )
        jobs.append({
            "agent_id": f"BW{wave_number}-{i}",
            "focus_area": (
                f"Wave {wave_number} additive re-scan (fresh angle on: "
                f"{rotated}) -- broader/overlapping scope, do not re-report "
                f"prior wave findings"
            ),
            "output": f"analysis_wave{wave_number}_{i}.md",
        })
    return jobs


def _breadth_wave_completed_extra_yields(
    scratchpad: Path, max_extra_waves: int
) -> list[int]:
    """Reconstruct per-wave yields for extra waves already run, from disk.

    Stateless by design (mirrors the driver's disk-gate recovery philosophy
    used throughout the pipeline): walks contiguous `analysis_wave{N}_*.md`
    files starting at N=1 and stops at the first gap, so a resumed/retried
    breadth phase re-derives exactly where the wave series left off without
    a separate state file.
    """
    by_wave: dict[int, list[str]] = {}
    for p in scratchpad.glob("analysis_wave*_*.md"):
        m = _BREADTH_WAVE_OUTPUT_RE.match(p.name)
        if not m:
            continue
        n = int(m.group(1))
        if 1 <= n <= max_extra_waves:
            by_wave.setdefault(n, []).append(p.name)
    yields: list[int] = []
    n = 1
    while n in by_wave:
        yields.append(
            _breadth_wave_count_above_info(scratchpad, sorted(by_wave[n]))
        )
        n += 1
    return yields


def _breadth_wave_decide(
    scratchpad: Path,
    config: dict,
    baseline_jobs: list[dict[str, str]],
    max_extra_waves: int = 2,
) -> tuple[int, int | None, list[dict[str, str]], str]:
    """Shared decision core for `_breadth_wave_plan` and live wave execution.

    Returns ``(waves_completed, next_wave_number_or_None, next_wave_jobs,
    reason)``. ``next_wave_jobs`` is ``[]`` when no further wave is
    warranted (cap reached or yield fell off); ``next_wave_number`` is
    ``None`` in that case.
    """
    extra_yields = _breadth_wave_completed_extra_yields(
        scratchpad, max_extra_waves
    )
    waves_completed = len(extra_yields)
    if waves_completed >= max_extra_waves:
        return waves_completed, None, [], (
            f"hard wave cap reached ({waves_completed}/{max_extra_waves})"
        )
    baseline_yield = _breadth_wave_count_above_info(
        scratchpad, [str(j["output"]) for j in baseline_jobs]
    )
    full_yields = [baseline_yield] + extra_yields
    this_wave_yield = full_yields[-1]
    prior_yields = full_yields[:-1]
    should_spawn, reason = _breadth_wave_should_spawn_next(
        prior_yields=prior_yields,
        this_wave_yield=this_wave_yield,
        waves_spawned_so_far=waves_completed,
        max_extra_waves=max_extra_waves,
    )
    if not should_spawn:
        return waves_completed, None, [], reason
    next_wave_number = waves_completed + 1
    return (
        waves_completed,
        next_wave_number,
        _breadth_wave_extra_jobs(baseline_jobs, next_wave_number),
        reason,
    )


def _breadth_wave_plan(
    scratchpad: Path,
    config: dict,
    baseline_jobs: list[dict[str, str]],
    max_extra_waves: int = 2,
) -> list[dict[str, str]]:
    """Return the additive-wave job list for THIS breadth planning check.

    HARD RECALL FLOOR: ``baseline_jobs`` (Wave 0) is always the head of the
    returned list, unmodified — this function only ever APPENDS, never
    removes or reorders baseline entries. Returns ``baseline_jobs`` itself
    (same object, byte-identical) when the M3 feature is off, the mode
    isn't Thorough, or the pipeline is L1 — the default/off path.
    Reconstructs wave state from disk (see `_breadth_wave_completed_extra_yields`)
    so replanning is idempotent and safe to call repeatedly / after a resume.
    """
    if not baseline_jobs or not _breadth_wave_gating_enabled(config):
        return baseline_jobs
    jobs = list(baseline_jobs)
    waves_completed, next_wave_number, next_jobs, reason = _breadth_wave_decide(
        scratchpad, config, baseline_jobs, max_extra_waves
    )
    for n in range(1, waves_completed + 1):
        jobs.extend(_breadth_wave_extra_jobs(baseline_jobs, n))
    log.info(
        f"[breadth] wave gating: {waves_completed} extra wave(s) completed -> "
        f"{'SPAWN wave ' + str(next_wave_number) if next_jobs else 'STOP'} "
        f"({reason})"
    )
    if next_jobs:
        jobs.extend(next_jobs)
    return jobs


def _breadth_run_wave_extension(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    baseline_jobs: list[dict[str, str]],
    max_extra_waves: int = 2,
) -> None:
    """M3 live wiring: run yield-gated additive breadth waves AFTER the
    baseline roster (the hard recall floor) has already gate-passed.

    Best-effort and strictly additive: never raises, never influences the
    caller's return code — a wave that fails to spawn, times out, or writes
    a low-yield artifact simply stops the series (see
    `_breadth_wave_should_spawn_next`); it can never fail the phase, because
    the phase already succeeded on the baseline roster before this runs.
    Wave-job completion is judged by this function's OWN mechanical finding
    count (`_breadth_wave_count_above_info`), never via
    `compute_breadth_row_statuses` — see the module note above this section
    for why wave outputs are intentionally not manifest-declared.
    """
    if not _breadth_wave_gating_enabled(config):
        return
    try:
        for _round in range(max_extra_waves):
            _waves_completed, wave_number, wave_jobs, reason = (
                _breadth_wave_decide(
                    scratchpad, config, baseline_jobs, max_extra_waves
                )
            )
            if not wave_jobs:
                log.info(f"[breadth] wave extension: stopping ({reason})")
                break
            log.info(
                f"[breadth] wave extension: spawning wave {wave_number} "
                f"({len(wave_jobs)} job(s)) -- {reason}"
            )
            concurrency = min(
                _BREADTH_WORKER_CONCURRENCY, max(1, len(wave_jobs))
            )
            with _NonBlockingWorkerPool(
                max_workers=concurrency,
                thread_name_prefix="plamen-breadth-wave-worker",
            ) as executor:
                futs = [
                    executor.submit(
                        _run_single_breadth_worker_pty,
                        job=job,
                        scratchpad=scratchpad,
                        project_root=project_root,
                        config=config,
                        phase=phase,
                        base_cmd=base_cmd,
                        env=env,
                        timeout=timeout,
                        quiescence_s=quiescence_s,
                        attempt=1,
                        retry_reasons=None,
                        allowed_outputs=[j["output"] for j in wave_jobs],
                    )
                    for job in wave_jobs
                ]
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        result = fut.result()
                        log.info(
                            f"[breadth] wave worker {result.get('output')}: "
                            f"{result.get('status')}"
                        )
                    except Exception as exc:
                        log.warning(f"[breadth] wave worker failed: {exc!r}")
    except Exception as exc:
        log.warning(
            f"[breadth] wave extension aborted (best-effort, non-fatal): "
            f"{exc!r}"
        )


def _run_breadth_worker_pool_pty(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
) -> int:
    """Run the baseline breadth roster, then (opt-in, Thorough-only) run
    best-effort additive yield-gated waves on top of it.

    DEFAULT/OFF PATH IS BYTE-IDENTICAL to `_run_breadth_worker_pool_pty_core`:
    when `breadth_wave_gating_enabled` is unset/false (or mode isn't
    Thorough, or the pipeline is L1), this wrapper does nothing but forward
    the core call's return code unchanged.
    """
    rc = _run_breadth_worker_pool_pty_core(
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        phase=phase,
        base_cmd=base_cmd,
        env=env,
        timeout=timeout,
        quiescence_s=quiescence_s,
        attempt=attempt,
    )
    if rc == 0 and _breadth_wave_gating_enabled(config):
        baseline_jobs = _breadth_worker_jobs(scratchpad, config)
        _breadth_run_wave_extension(
            scratchpad=scratchpad,
            project_root=project_root,
            config=config,
            phase=phase,
            base_cmd=base_cmd,
            env=env,
            timeout=timeout,
            quiescence_s=quiescence_s,
            baseline_jobs=baseline_jobs,
        )
    return rc


# ===========================================================================
# Python-scheduled rescan worker PTYs
# ===========================================================================

_RESCAN_WORKER_CONCURRENCY = 3


def _rescan_worker_jobs(scratchpad: Path) -> list[dict[str, str]]:
    manifest = scratchpad / "rescan_manifest.md"
    if not manifest.exists():
        return []
    try:
        declared = _parse_rescan_manifest_files(
            manifest.read_text(encoding="utf-8", errors="replace")
        )
    except Exception:
        return []
    jobs: list[dict[str, str]] = []
    rescan_i = 0
    per_i = 0
    for name in declared:
        if name.startswith("analysis_percontract_"):
            per_i += 1
            agent_id = f"PC{per_i}"
            focus = (
                "Per-contract rescan for the exact contract/scope declared "
                f"by `{name}` in rescan_manifest.md"
            )
        else:
            rescan_i += 1
            agent_id = f"R{rescan_i}"
            focus = (
                "Fresh rescan concern declared by rescan_manifest.md for "
                f"`{name}`"
            )
        jobs.append({"agent_id": agent_id, "focus_area": focus, "output": name})
    return jobs


def _rescan_output_complete(
    scratchpad: Path,
    phase: Phase,
    output: str,
) -> bool:
    p = scratchpad / output
    try:
        if not p.exists() or p.stat().st_size < max(phase.min_artifact_bytes, 1000):
            return False
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    markers = dict(
        (m.group(1).strip().upper(), m.group(2).strip().upper())
        for m in re.finditer(r"<!--\s*PLAMEN_([A-Z_]+):\s*([^>]+?)\s*-->", text)
    )
    if markers and markers.get("STATUS") != "COMPLETE":
        return False
    ok, _reasons = _structural_completeness_ok(
        p,
        required_headings=(),
        placeholder_strings=("TODO", "FILL_ME", "<placeholder>"),
    )
    return ok


def _rescan_open_jobs(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [
        job for job in jobs
        if not _rescan_output_complete(scratchpad, phase, job["output"])
    ]


def _should_use_rescan_worker_pool(config: dict, scratchpad: Path) -> bool:
    """Use worker PTYs when a rescan manifest already declares exact rows.

    Fresh first-pass rescan still uses the canonical rescan methodology to
    create `rescan_manifest.md`; retries/resumes then repair exact manifest
    rows as independent top-level PTY workers.
    """
    if str(config.get("cli_backend", "claude")).lower() != "claude":
        return False
    jobs = _rescan_worker_jobs(scratchpad)
    if not jobs:
        return False
    try:
        phase = next(p for p in SC_PHASES if p.name == "rescan")
        missing = _rescan_manifest_exact_missing(scratchpad, phase)
    except Exception:
        missing = None
    if missing and any("rescan_manifest.md" in str(item) for item in missing):
        # Manifest shape itself is invalid (for example no per-contract row).
        # Let the canonical rescan coordinator rewrite the manifest instead of
        # trapping the audit in a worker pool that can only repair declared rows.
        return False
    return True


def _build_rescan_worker_prompt(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    attempt: int,
    retry_reasons: list[str] | None = None,
) -> str:
    output = job["output"]
    agent_id = job["agent_id"]
    focus = job["focus_area"]
    methodology = (
        plamen_home() / "prompts" / "shared" / "v2" / "phase3b-rescan.md"
    ).as_posix()
    finding_format = (
        plamen_home() / "rules" / "finding-output-format.md"
    ).as_posix()
    retry_block = ""
    if retry_reasons:
        retry_block = (
            "\n## Previous Gate Failure\n\n"
            + "\n".join(f"- {r}" for r in retry_reasons)
            + "\n"
        )
    return f"""# RESCAN ROW WORKER

You are a single rescan worker launched directly by the Python Plamen driver.
There is no Claude phase coordinator for this repair attempt. Your job is to
produce exactly one rescan artifact from the existing rescan manifest.

## Assignment

- PROJECT_ROOT: `{project_root}`
- SCRATCHPAD: `{scratchpad.as_posix()}`
- LANGUAGE: `{config.get('language', 'unknown')}`
- MODE: `{config.get('mode', 'unknown')}`
- PIPELINE: `{config.get('pipeline', 'sc')}`
- SUBSYSTEM_SCOPE: `{config.get('subsystem_scope') or '(none)'}`
- SCOPE_FILE: `{config.get('scope_file') or '(none)'}`
- SCOPE_NOTES: `{config.get('scope_notes') or '(none)'}`
- Agent ID: `{agent_id}`
- Focus area: `{focus}`
- Output file: `{output}`
- Attempt: `{attempt}`
{retry_block}
## Output Allowlist

Write exactly this file and no other scratchpad artifact:

`{scratchpad.as_posix()}/{output}`

Do not infer, invent, or create any other output file. Do not update
`rescan_manifest.md` or any other agent's output.

## Methodology

Read `{methodology}` for the canonical rescan methodology and vulnerability
coverage. Use it as analysis guidance only. You are already the worker; do not spawn Task/Agent subagents.
Do not proceed outside this assigned worker contract.

Read `rescan_manifest.md` to understand why this exact output was declared.
Read `{finding_format}` for finding format. Use recon, breadth, opengrep,
source code, and previous phase artifacts in the scratchpad as relevant.
Do not proceed outside this assigned worker contract.

## Required File Contract

The output file must:

1. Start with these markers:
   `<!-- PLAMEN_ARTIFACT: {output} -->`
   `<!-- PLAMEN_OWNER: {agent_id} -->`
   `<!-- PLAMEN_STATUS: IN_PROGRESS -->`
   `<!-- PLAMEN_PHASE: rescan -->`
   `<!-- PLAMEN_VERSION: 1 -->`
   `<!-- AGENT_ROW: {agent_id} -->`
   `<!-- EXPECTED_OUTPUT: {output} -->`
2. Contain substantive rescan analysis for the declared focus.
3. Include either real `## Finding [` / `### Finding [` blocks or a
   `## No Findings` rationale.
4. End with a final `<!-- PLAMEN_STATUS: COMPLETE -->` marker only after the
   file is fully written and verified on disk.

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other
agents' output files. Do NOT continue after the assigned file is complete.
Return your findings and stop.

When done, return exactly one line:

`DONE: {output} complete`
"""


def _run_single_rescan_worker_pty(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
    retry_reasons: list[str] | None = None,
    allowed_outputs: list[str] | None = None,
) -> dict[str, Any]:
    output = job["output"]
    allowed_output_set = set(allowed_outputs or [output])
    session_id = str(uuid.uuid4())
    prompt = _build_rescan_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        attempt=attempt,
        retry_reasons=retry_reasons,
    )
    snap = scratchpad / f"_prompt_rescan_worker_{Path(output).stem}.attempt{attempt}.md"
    snap.write_text(prompt, encoding="utf-8")
    cmd = _build_fresh_session_cmd(base_cmd, session_id)
    cmd = _rewrite_argv_positional_prompt(cmd, snap)
    log_path = scratchpad / f"_stdio_rescan_worker_{Path(output).stem}.attempt{attempt}.log"
    known_stats: dict[str, tuple[int, int]] = {}
    try:
        for p in scratchpad.iterdir():
            if p.is_file() and not p.name.startswith("_"):
                try:
                    st = p.stat()
                    known_stats[p.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    known_stats[p.name] = (0, 0)
    except Exception:
        known_stats = {}

    def _worker_poll(_now: float, _state: Any) -> None:
        try:
            for p in scratchpad.iterdir():
                if p.name.startswith("_") or not p.is_file():
                    continue
                known_names = set(known_stats)
                try:
                    st = p.stat()
                    sig = (st.st_size, st.st_mtime_ns)
                except OSError:
                    sig = (0, 0)
                old_sig = known_stats.get(p.name)
                known_stats[p.name] = sig
                if _worker_artifact_name_allowed(p.name, allowed_output_set):
                    continue
                if old_sig == sig:
                    continue
                if _worker_artifact_is_benign_duplicate_copy(p.name, known_names):
                    moved = _quarantine_worker_duplicate_copy(
                        scratchpad=scratchpad,
                        path=p,
                        phase_name="rescan",
                        worker_output=output,
                    )
                    if moved is not None:
                        log.info(
                            "[rescan] worker %s quarantined benign duplicate "
                            "scratchpad copy: %s -> %s",
                            output,
                            p.name,
                            moved.relative_to(scratchpad).as_posix(),
                        )
                    continue
                log.error(
                    "[rescan] worker %s wrote or modified out-of-scope artifact: %s",
                    output,
                    p.name,
                )
                raise _PtyStop(-4)
        except _PtyStop:
            raise
        except Exception:
            pass

    with log_path.open("w", encoding="utf-8", errors="replace") as out:
        session = ClaudePtySession(
            cmd,
            cwd=project_root,
            env=env,
            session_id=session_id,
            prompt_path=snap,
            log_file=out,
        )
        _register_active_worker_session(session)
        try:
            out.write(f"CLAUDE_TRANSCRIPT={session.transcript_path}\n")
            out.flush()
            session.spawn()
            session.send_bootstrap()
            state = session.wait_for_turn_complete(
                timeout,
                quiescence_s=quiescence_s,
                on_poll=_worker_poll,
            )
            if state.rate_limited:
                # A transient 529/overloaded is provider-wide, NOT a 429
                # account/usage cap. It must NOT escalate to the phase-level
                # usage-cap pause that stops the whole worker pool — Claude
                # Code's own retry loop (exp backoff, up to 10x) usually
                # self-recovers it. Classify it as a retriable worker failure
                # so the gate re-spawns just this one worker. Mirrors the
                # single-subprocess overload path (detect_overloaded backoff).
                if getattr(state, "overloaded", False):
                    return {"output": output, "rc": 1, "status": "overloaded",
                            "reasons": ["transient 529 overloaded -- retriable"]}
                return {"output": output, "rc": 1, "status": "rate_limited"}
            ok = _rescan_output_complete(scratchpad, phase, output)
            return {
                "output": output,
                "rc": 0 if ok else -2,
                "status": "complete" if ok else "incomplete",
                "reasons": [] if ok else ["missing or below rescan size floor"],
                "log": str(log_path),
            }
        except _PtyStop as stop:
            return {
                "output": output,
                "rc": stop.rc,
                "status": "containment",
                "reasons": ["worker wrote protected out-of-scope artifact"],
                "log": str(log_path),
            }
        except Exception as exc:
            return {
                "output": output,
                "rc": EXIT_ERROR,
                "status": "error",
                "reasons": [str(exc)],
                "log": str(log_path),
            }
        finally:
            _unregister_active_worker_session(session)
            try:
                session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
            except Exception:
                pass
            try:
                if session.transcript_path.exists():
                    out.write("\n\n# Claude session transcript tail\n")
                    with session.transcript_path.open("rb") as tf:
                        tf.seek(0, 2)
                        size = tf.tell()
                        tf.seek(max(0, size - 65536))
                        out.write(tf.read().decode("utf-8", errors="replace"))
                    out.flush()
            except Exception:
                pass


def _rescan_worker_pool_progress_status(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
    active_outputs: list[str],
) -> str:
    complete = sum(
        1 for job in jobs
        if _rescan_output_complete(scratchpad, phase, job["output"])
    )
    queued = max(0, len(jobs) - complete - len(active_outputs))
    return _format_worker_pool_progress_status(
        complete=complete,
        total=len(jobs),
        active_outputs=active_outputs,
        queued=queued,
        phase_label="rescan",
    )


def _run_rescan_worker_pool_pty(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
) -> int:
    jobs = _rescan_worker_jobs(scratchpad)
    if not jobs:
        log.warning("[rescan] worker-pool unavailable: no manifest jobs")
        return -2
    budget = int(config.get("pty_continuation_budget", 3))
    retry_reasons_by_output: dict[str, list[str]] = {}
    pool_started = time.time()
    try:
        (scratchpad / "_rescan_worker_pool_contract.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "phase": "rescan",
                    "pipeline": config.get("pipeline", "sc"),
                    "outputs": [str(job.get("output") or "") for job in jobs],
                    "jobs": jobs,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning(f"[rescan] could not write worker-pool contract marker: {exc}")

    for pool_attempt in range(1, budget + 2):
        open_jobs = _rescan_open_jobs(scratchpad, phase, jobs)
        if not open_jobs:
            passed, missing = gate_passes(scratchpad, project_root, phase)
            if passed:
                return 0
            log.warning(f"[rescan] worker-pool gate failed: {missing}")
            return -2
        concurrency = min(_RESCAN_WORKER_CONCURRENCY, max(1, len(open_jobs)))
        log.info(
            f"[rescan] worker PTY pool attempt {pool_attempt}: "
            f"{len(open_jobs)} open row(s), concurrency={concurrency}"
        )
        pool_allowed_outputs = [str(job["output"]) for job in open_jobs]
        display.print_phase_heartbeat(
            "rescan",
            int(time.time() - pool_started),
            status=_rescan_worker_pool_progress_status(
                scratchpad,
                phase,
                jobs,
                [j["output"] for j in open_jobs[:concurrency]],
            ),
        )
        results: list[dict[str, Any]] = []
        with _NonBlockingWorkerPool(
            max_workers=concurrency,
            thread_name_prefix="plamen-rescan-worker",
        ) as executor:
            fut_to_job = {
                executor.submit(
                    _run_single_rescan_worker_pty,
                    job=job,
                    scratchpad=scratchpad,
                    project_root=project_root,
                    config=config,
                    phase=phase,
                    base_cmd=base_cmd,
                    env=env,
                    timeout=timeout,
                    quiescence_s=quiescence_s,
                    attempt=pool_attempt,
                    retry_reasons=retry_reasons_by_output.get(job["output"]),
                    allowed_outputs=pool_allowed_outputs,
                ): job
                for job in open_jobs
            }
            pending_futs: set[concurrent.futures.Future] = set(fut_to_job)
            last_progress = time.time()
            while pending_futs:
                done, pending_futs = concurrent.futures.wait(
                    pending_futs,
                    timeout=_WORKER_POOL_UI_POLL_S,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                now = time.time()
                elapsed = int(now - pool_started)
                display.spin(elapsed)
                if display.graceful_stop.requested:
                    _cancel_pending_worker_futures(pending_futs, executor)
                    raise _PtyStop(-3)
                for fut in done:
                    result = fut.result()
                    results.append(result)
                    output = result.get("output", "(unknown)")
                    status = result.get("status")
                    log.info(f"[rescan] worker {output}: {status}")
                    display.print_phase_heartbeat(
                        "rescan",
                        elapsed,
                        status=f"worker {output}: {status}",
                    )
                    if result.get("status") == "rate_limited":
                        log.warning(
                            "[rescan] worker %s hit rate limit; stopping "
                            "remaining workers and surfacing phase-level "
                            "rate-limit pause",
                            output,
                        )
                        _cancel_pending_worker_futures(pending_futs, executor)
                        return 1
                    last_progress = now
                if pending_futs and now - last_progress >= _WORKER_POOL_HEARTBEAT_S:
                    active_outputs = [
                        fut_to_job[fut]["output"]
                        for fut in pending_futs
                        if fut in fut_to_job
                    ][:concurrency]
                    display.print_phase_heartbeat(
                        "rescan",
                        elapsed,
                        status=_rescan_worker_pool_progress_status(
                            scratchpad,
                            phase,
                            jobs,
                            active_outputs,
                        ),
                    )
                    last_progress = now
        if any(r.get("status") == "rate_limited" for r in results):
            return 1
        if any(r.get("rc") == -4 for r in results):
            log.error("[rescan] worker-pool containment violation")
            return -4
        retry_reasons_by_output = {
            str(r.get("output")): [
                f"status={r.get('status')}",
                *[str(x) for x in (r.get("reasons") or [])],
            ]
            for r in results
            if r.get("status") != "complete"
        }
        passed, missing = gate_passes(scratchpad, project_root, phase)
        if passed:
            return 0
        log.info(
            f"[rescan] worker-pool attempt {pool_attempt} incomplete: {missing}"
        )
    log.warning("[rescan] worker-pool retry budget exhausted")
    return -2


# ===========================================================================
# Python-scheduled depth worker PTYs
# ===========================================================================

_DEPTH_WORKER_CONCURRENCY = 3

_SC_DEPTH_STANDARD_JOBS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "depth-token-flow",
        "role": "token_flow",
        "output": "depth_token_flow_findings.md",
        "category": "standard",
        "focus": "Token/value flow, accounting, transfers, fees, share conversions",
    },
    {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "Cross-function state mutation and invariant enforcement",
    },
    {
        "agent_id": "depth-edge-case",
        "role": "edge_case",
        "output": "depth_edge_case_findings.md",
        "category": "standard",
        "focus": "Boundary values, zero/max state, rounding, empty state",
    },
    {
        "agent_id": "depth-external",
        "role": "external",
        "output": "depth_external_findings.md",
        "category": "standard",
        "focus": "External calls, callbacks, MEV, oracle and cross-chain boundaries",
    },
)

_L1_DEPTH_STANDARD_JOBS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "depth-consensus-invariant",
        "role": "consensus_invariant",
        "output": "depth_consensus_invariant_findings.md",
        "category": "standard",
        "focus": "Consensus safety, fork choice, validator lifecycle, BLS and hardfork invariants",
    },
    {
        "agent_id": "depth-network-surface",
        "role": "network_surface",
        "output": "depth_network_surface_findings.md",
        "category": "standard",
        "focus": "P2P, mempool, RPC, eclipse, DoS and network amplification",
    },
    {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "State sync, pruning, execution state transitions and invariant enforcement",
    },
    {
        "agent_id": "depth-external",
        "role": "external",
        "output": "depth_external_findings.md",
        "category": "standard",
        "focus": "Dependency, cross-environment and external-boundary drift",
    },
    {
        "agent_id": "depth-edge-case",
        "role": "edge_case",
        "output": "depth_edge_case_findings.md",
        "category": "standard",
        "focus": "Zero-state, boundary conditions, panic paths and limit behavior",
    },
)

_SC_DEPTH_CORE_SIDE_JOBS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "blind-spot-a",
        "role": "blind_spot_a",
        "output": "blind_spot_a_findings.md",
        "category": "scanner",
        "focus": "Blind Spot Scanner A: tokens, parameters, accounting and side effects",
    },
    {
        "agent_id": "blind-spot-b",
        "role": "blind_spot_b",
        "output": "blind_spot_b_findings.md",
        "category": "scanner",
        "focus": "Blind Spot Scanner B: guards, visibility, inheritance and initialization",
    },
    {
        "agent_id": "blind-spot-c",
        "role": "blind_spot_c",
        "output": "blind_spot_c_findings.md",
        "category": "scanner",
        "focus": "Blind Spot Scanner C: role lifecycle, capability exposure and reachability",
    },
    {
        "agent_id": "validation-sweep",
        "role": "validation_sweep",
        "output": "validation_sweep_findings.md",
        "category": "scanner",
        "focus": "Validation sweep: systematic second-pass checks over inventory and depth candidates",
    },
)

# L1-4: L1 scanner floor, mirrors `_SC_DEPTH_CORE_SIDE_JOBS` role/output names
# 1:1 (same never-cut group filenames) so the scanner never-cut gate and the
# depth-promotion feeder globs (`blind_spot_*_findings.md`,
# `validation_sweep_findings.md`) work identically for both pipelines. The
# per-role heading each job points to is L1-specific — see
# `_L1_SCANNER_HEADING_BY_ROLE`.
_L1_SCANNER_JOBS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "blind-spot-a",
        "role": "blind_spot_a",
        "output": "blind_spot_a_findings.md",
        "category": "scanner",
        "focus": "Scanner: boundary and wire format — codecs, RPC parsing, gossip payloads, proof formats",
    },
    {
        "agent_id": "blind-spot-b",
        "role": "blind_spot_b",
        "output": "blind_spot_b_findings.md",
        "category": "scanner",
        "focus": "Scanner: state transition and consensus invariant — fork choice, validation, admission",
    },
    {
        "agent_id": "blind-spot-c",
        "role": "blind_spot_c",
        "output": "blind_spot_c_findings.md",
        "category": "scanner",
        "focus": "Scanner: network amplification and resource exhaustion — P2P/RPC/mempool DoS",
    },
    {
        "agent_id": "validation-sweep",
        "role": "validation_sweep",
        "output": "validation_sweep_findings.md",
        "category": "scanner",
        "focus": "Scanner: lifecycle, cache, and recovery — expiry, restart/resume, crash recovery",
    },
)

_DEPTH_THOROUGH_SIDE_JOBS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "design-stress",
        "role": "design_stress",
        "output": "design_stress_findings.md",
        "category": "sidecar",
        "focus": "Design stress testing: parameter extremes, design limits and worst-state behavior",
    },
    {
        "agent_id": "perturbation",
        "role": "perturbation",
        "output": "perturbation_findings.md",
        "category": "sidecar",
        "focus": "Finding perturbation: structured mutations against Medium+ depth findings",
    },
    {
        "agent_id": "skill-execution-checklist",
        "role": "skill_execution_checklist",
        "output": "skill_execution_checklist.md",
        "category": "sidecar",
        "focus": "Skill execution checklist: verify mandatory depth skills were applied and record gaps",
    },
)


def _niche_slug_from_name(raw: str) -> str:
    s = str(raw or "").strip().strip("`")
    s = re.sub(r"_findings\.md$", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^niche[_-]", "", s, flags=re.IGNORECASE)
    s = s.lower().replace("_", "-")
    aliases = {
        "event-completeness": "event-completeness",
        "semantic-consistency-audit": "semantic-consistency-audit",
        "semantic-gap": "semantic-gap-investigator",
        "semantic-gap-investigator": "semantic-gap-investigator",
        "callback-receiver-safety": "callback-receiver-safety",
        "multi-step-operation-safety": "multi-step-operation-safety",
        "signature-verification": "signature-verification",
        "spec-compliance-audit": "spec-compliance-audit",
        "stableswap-compliance": "stableswap-compliance",
        "dimensional-analysis": "dimensional-analysis",
    }
    return aliases.get(s, s)


def _niche_skill_path_for_role(role: str) -> Path:
    slug = _niche_slug_from_name(role)
    return plamen_home() / "agents" / "skills" / "niche" / slug / "SKILL.md"


# ---------------------------------------------------------------------------
# P1: SC breadth/depth worker skill injection.
#
# Root cause of the recall misapplication: recon correctly selected skills and
# spawn_manifest.md binds them per breadth/depth agent, but the SC direct-worker
# prompt builders never consumed those bindings (only L1 did, via v2.6.4). So a
# breadth agent assigned CROSS_CHAIN_MESSAGE_INTEGRITY never saw its Step
# Execution Checklist. These helpers port the L1 mechanical-injection pattern to
# SC: parse the manifest bindings, resolve each skill's SKILL.md, and emit a
# MANDATORY Read+execute-checklist block into the worker prompt.
# ---------------------------------------------------------------------------

# Skills that are not analysis methodology for breadth/depth workers.
# FORK_ANCESTRY/VERIFICATION_PROTOCOL/MOVE_SAFETY_CORE_DIRECTIVES are real skills
# bound to recon/verifier only. CORE_STATE/ACCESS_CONTROL are the always-required
# BASELINE breadth-agent FOCUS AREAS (phase2-instantiate Step 2a "1 core state,
# 1 access control") — they are NOT injectable skills and have NO SKILL.md by
# design (EVM has zero always-required skills). The binding parser keys breadth
# bindings off the AGENT row's Template column, so without this exclusion the
# baseline agents' template names are mis-treated as skills, fail to resolve,
# and emit a spurious "did not resolve to a SKILL.md ... silent recall loss"
# warning (v2.8.16) — misleading, since there is no skill to lose.
_SC_SKILL_INJECT_EXCLUDE = frozenset({
    "FORK_ANCESTRY", "VERIFICATION_PROTOCOL", "MOVE_SAFETY_CORE_DIRECTIVES",
    "CORE_STATE", "ACCESS_CONTROL",
    # v2.8.17: GENERAL is the instantiate floor-fill sentinel for a focus-only
    # breadth agent with no skill methodology (phase2-instantiate Step 2a.3).
    # It has no SKILL.md BY DESIGN — exclude it so it does not emit a spurious
    # "did not resolve to a SKILL.md" binding-loss warning. The manifest schema
    # gate is what rejects FABRICATED (non-sentinel, non-real) template names.
    "GENERAL", "GENERAL_ANALYSIS", "CUSTOM", "CUSTOM_FOCUS",
})


def _sc_skill_path_for_name(name: str, language: str = "") -> "Path | None":
    """Resolve an UPPER_SNAKE skill name to its SKILL.md across the per-language,
    injectable and niche skill trees. Returns None when not found.

    The current LANGUAGE tree is searched first so a non-EVM SC audit
    (solana/aptos/sui/soroban) resolves its language-specific skills; the other
    SC language trees are then searched so a shared skill name still resolves
    regardless of which language dir it lives in (generality, not EVM-only)."""
    slug = str(name or "").strip().strip("`").lower().replace("_", "-")
    if not slug:
        return None
    base = plamen_home() / "agents" / "skills"
    lang = str(language or "").strip().lower()
    ordered: list[str] = []
    if lang and lang not in ("evm", "l1"):
        ordered.append(lang)
    for sub in ("evm", "solana", "aptos", "sui", "soroban",
                "injectable", "niche", "injectable/l1"):
        if sub not in ordered:
            ordered.append(sub)
    for sub in ordered:
        p = base / sub / slug / "SKILL.md"
        if p.exists():
            return p
    return None


def _parse_sc_skill_bindings(
    scratchpad: Path, language: str = ""
) -> "tuple[dict, dict]":
    """Parse spawn_manifest.md -> (breadth_focus -> [skills], depth_role -> [skills]).

    Header-aware: walks every markdown table, maps columns by header name, and
    collects skill->agent bindings from the 'Breadth Agents' table (Template +
    Focus Area) and any 'Skill ... Assigned To' table (primary/secondary/
    injectable). Breadth bindings are keyed by focus_area; depth injectable
    bindings by depth role (e.g. 'depth-external' -> 'external'). Fails soft to
    empty dicts so resume/legacy runs are unaffected.
    """
    breadth: dict[str, list[str]] = {}
    depth: dict[str, list[str]] = {}
    manifest = scratchpad / "spawn_manifest.md"
    if not manifest.exists():
        return breadth, depth
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return breadth, depth

    def _add(d: dict, key: str, skill: str) -> None:
        key = (key or "").strip().strip("`").lower()
        raw_skill = (skill or "").strip().strip("`")
        # Instantiate often writes combined cells such as
        # "CROSS_CHAIN_MESSAGE_INTEGRITY + CROSS_CHAIN_TIMING". Split these
        # mechanically so every methodology reaches the worker prompt.
        parts = [
            p.strip()
            for p in re.split(r"\s*(?:\+|,|;|\band\b)\s*", raw_skill, flags=re.IGNORECASE)
            if p.strip()
        ] or [raw_skill]
        if len(parts) > 1:
            for part in parts:
                _add(d, key, part)
            return
        skill = re.sub(r"\s*\([^)]*\)\s*$", "", raw_skill)
        skill = skill.strip().strip("`").upper().replace(" ", "_")
        if not key or not skill or skill in _SC_SKILL_INJECT_EXCLUDE:
            return
        if not re.match(r"^[A-Z][A-Z0-9_]+$", skill):
            return
        d.setdefault(key, [])
        if skill not in d[key]:
            d[key].append(skill)

    def _focus_in_parens(s: str) -> str:
        m = re.search(r"\(([a-z0-9_]+)\)", (s or "").lower())
        return m.group(1) if m else ""

    def _depth_role(s: str) -> str:
        m = re.search(r"depth-([a-z][a-z-]+)", (s or "").lower())
        return m.group(1).replace("-", "_") if m else ""

    def _best_non_evm_breadth_focus() -> str:
        """Choose the breadth worker most likely to own outbound foreign-VM
        encoding when instantiate omitted the explicit cross-VM binding."""
        preferred = (
            "cross_chain_message_integrity",
            "cross_chain_integrity",
            "cross_chain",
            "encoding",
            "storage_upgrade_safety",
            "token_flow_dex",
        )
        focus_values = list(agent_focus.values())
        for needle in preferred:
            for focus in focus_values:
                if needle in focus:
                    return focus
        for focus in focus_values:
            if "cross" in focus or "chain" in focus or "encode" in focus:
                return focus
        return focus_values[0] if focus_values else ""

    def _has_non_evm_target_evidence() -> bool:
        """Detect the recon condition for CROSS_VM_SERIALIZATION_CONFORMANCE
        without trusting the LLM to have emitted a perfect manifest row.

        Prefer the canonical `NON_EVM_TARGET` flag that recon writes to
        detected_patterns.md: an explicit YES is authoritative-True and an
        explicit NO is authoritative-False. Only when recon did NOT emit the
        flag do we fall back to the substring heuristic, and that heuristic
        excludes template_recommendations.md — that file DOCUMENTS the
        CROSS_VM trigger pattern verbatim (the false-positive source that made
        pure-EVM audits spuriously recover the binding)."""
        dp = scratchpad / "detected_patterns.md"
        try:
            if dp.exists():
                dp_text = dp.read_text(encoding="utf-8", errors="replace")
                m = re.search(
                    r"NON_EVM_TARGET\s*(?:=|:)\s*(YES|NO|TRUE|FALSE)",
                    dp_text,
                    re.IGNORECASE,
                )
                if m:
                    return m.group(1).upper() in ("YES", "TRUE")
        except Exception:
            pass
        hay_parts: list[str] = []
        for name in (
            "recon_summary.md",
            "design_context.md",
            "attack_surface.md",
            "detected_patterns.md",
            "contract_inventory.md",
            "function_list.md",
        ):
            p = scratchpad / name
            try:
                if p.exists():
                    hay_parts.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
        hay = "\n".join(hay_parts)
        if not hay:
            return False
        positive = re.search(
            r"\b(Solana|SOLANA_|Bitcoin|BITCOIN_|BTC|"
            r"Pubkey|programId|ed25519|bech32|base58|Borsh)\b",
            hay,
            re.IGNORECASE,
        )
        cross_chain = re.search(
            # Generic cross-chain-messaging vocabulary (bridge/relay families —
            # LayerZero/Wormhole/Axelar/CCIP-style), NOT any one protocol's literal
            # contract/method names. Drawn from the CROSS_CHAIN_MESSAGE_INTEGRITY
            # trigger set. The AND-gate with `positive` (Solana/Bitcoin/Borsh) keeps
            # this from over-firing on plain EVM bridges.
            r"\b(cross-chain|cross chain|destination chain|source chain|bridge|"
            r"relay|gateway|payload|onRevert|onAbort|onFailure|onCall|onMessage|"
            r"onReceive|withdrawAndCall|sendAndCall|ccipReceive|"
            r"receiveWormholeMessages)\b",
            hay,
            re.IGNORECASE,
        )
        return bool(positive and cross_chain)

    # Pass 1: agent_id -> focus_area (from the Breadth Agents table).
    agent_focus: dict[str, str] = {}
    header: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            header = []
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        low = [c.lower() for c in cells]
        if _is_separator_row(line):
            continue
        if any(h in low for h in ("focus area", "assigned to", "template", "skill")):
            header = low
            continue
        if not header:
            continue
        col = {name: cells[i] for i, name in enumerate(header) if i < len(cells)}
        skill = col.get("template") or col.get("skill") or ""
        focus = col.get("focus area") or ""
        agent_id = col.get("agent id") or ""
        assigned = (
            col.get("assigned to")
            or col.get("inject into")
            or col.get("agent")
            or ""
        )
        if agent_id and focus:
            agent_focus[agent_id.lower()] = focus.lower()
        # Breadth primary (Breadth Agents table row).
        if skill and focus:
            _add(breadth, focus, skill)
        # Skill -> Assigned-To rows (primary/secondary/injectable assignment).
        if skill and assigned:
            a = assigned.lower()
            drole = _depth_role(a)
            if drole:
                _add(depth, drole, skill)
            else:
                f = _focus_in_parens(a)
                if not f:
                    # bare agent id like "B3" -> look up its focus
                    aid = re.match(r"^(b\d+)", a)
                    if aid:
                        f = agent_focus.get(aid.group(1), "")
                if f:
                    _add(breadth, f, skill)
    # CROSS_VM_SERIALIZATION_CONFORMANCE is an EVM-SIDE skill: it audits Solidity
    # code that SERIALIZES outbound for a non-EVM VM (EVM -> Solana/BTC/Move) --
    # e.g. an outbound account/pubkey serializer or Borsh packer in a bridge (this skill was added for
    # exactly an outbound-encoder gap observed in a prior run). It fires on an EXPLICIT EVM audit that
    # has non-EVM-target evidence, and must NOT fire on NATIVE non-EVM audits
    # (solana/aptos/sui/soroban) — there is no EVM-side serialization there — nor
    # on legacy/unknown ('') runs we cannot confirm are EVM. The
    # `_has_non_evm_target_evidence()` check (NOT a language exclusion) is what
    # prevents a pure-EVM-with-no-bridge false-positive.
    lang = (language or "").strip().lower()
    if lang == "evm" and _has_non_evm_target_evidence():
        # This injectable is load-bearing for EVM -> Solana/BTC/foreign-VM
        # serialization bugs. If recon saw the evidence but instantiate omitted
        # the row, recover mechanically instead of silently losing recall.
        cross_vm = "CROSS_VM_SERIALIZATION_CONFORMANCE"

        def _log_recovery_once(msg: str, *args) -> None:
            # Dedupe across the many breadth/depth worker calls per run: emit
            # each distinct recovery warning at most once via a scratchpad
            # marker so it cannot spam dozens of identical lines.
            flag = scratchpad / "_skill_recovery_logged.flag"
            try:
                rendered = msg % args if args else msg
            except Exception:
                rendered = msg
            try:
                seen = (
                    flag.read_text(encoding="utf-8", errors="replace").splitlines()
                    if flag.exists()
                    else []
                )
            except Exception:
                seen = []
            if rendered in seen:
                return
            log.warning(msg, *args)
            try:
                with flag.open("a", encoding="utf-8") as fh:
                    fh.write(rendered + "\n")
            except Exception:
                pass

        if not any(cross_vm in skills for skills in breadth.values()):
            f = _best_non_evm_breadth_focus()
            if f:
                _add(breadth, f, cross_vm)
                _log_recovery_once(
                    "[skill-injection] recovered %s breadth binding for focus %s "
                    "from non-EVM target evidence",
                    cross_vm, f,
                )
        if not any(cross_vm in skills for skills in depth.values()):
            _add(depth, "external", cross_vm)
            _log_recovery_once(
                "[skill-injection] recovered %s depth binding for depth-external "
                "from non-EVM target evidence",
                cross_vm,
            )
    return breadth, depth


def _sc_skill_injection_block(
    skill_names: list[str], *, agent_kind: str, language: str = "",
) -> str:
    """Build a MANDATORY skill-injection block for an SC worker prompt: a Read
    directive per resolved skill + a directive to execute every Step Execution
    Checklist row and return the filled checklist in the artifact. Empty when no
    skill resolves (so the prompt is unchanged for unbound agents)."""
    resolved: list[tuple[str, str]] = []
    for name in skill_names or []:
        # v2.8.17: a recognized non-skill sentinel/baseline (GENERAL floor-fill,
        # CORE_STATE/ACCESS_CONTROL) has no SKILL.md BY DESIGN — skip silently,
        # not a binding loss. (Defense-in-depth at the warning site; the parser
        # also filters these, but the suppression must not depend on caller.)
        if str(name or "").strip().strip("`").upper() in _SC_SKILL_INJECT_EXCLUDE:
            continue
        p = _sc_skill_path_for_name(name, language)
        if p is not None:
            resolved.append((name, p.as_posix()))
        else:
            # Binding-loss telemetry: a manifest-bound skill that does not
            # resolve to a SKILL.md is a silent recall loss -- surface it.
            log.warning(
                "[skill-injection] %s agent: bound skill %r did not resolve to a "
                "SKILL.md (language=%s) -- not injected",
                agent_kind, name, language or "?",
            )
    if not resolved:
        return ""
    lines = [
        "",
        "## ASSIGNED SKILL METHODOLOGY (MANDATORY — recon-selected, mechanically injected)",
        "",
        "Recon selected these skills for your focus and the driver bound them to "
        "you. You MUST read each and EXECUTE it — do not rely on generic phase "
        "methodology alone. For each skill, run every row of its "
        "`Step Execution Checklist` (or equivalent checklist) against the code "
        "and include the filled checklist + any findings it surfaces in your "
        "output artifact. A skill bound here but not executed is a recall failure.",
        "",
    ]
    for name, posix in resolved:
        lines.append(f"- Read and EXECUTE `{posix}` (skill `{name}`).")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Wave-2 A6: L1<->Move skill-lane routing.
#
# An L1 (Go/Rust node-client) repo can embed a Move-VM execution layer as
# `.move` sources -- e.g. a Move interpreter/verifier module linked into a
# consensus/execution client. Those files currently receive zero Move
# methodology because L1 depth roles have no Move skills of their own. This
# routes the ALREADY-VETTED aptos/sui core Move skills
# (MOVE_SAFETY_CORE_DIRECTIVES / ABILITY_ANALYSIS / TYPE_SAFETY, per
# skill-index.md) into depth-state-trace and depth-external whenever recon's
# mechanical `.move` suffix scan set HAS_MOVE_SOURCES
# (`_seed_move_sources_flag` in recon_prepass.py). ROUTING ONLY: reuses the
# aptos/sui SKILL.md files verbatim via `_sc_skill_path_for_name` -- no new
# methodology text, no new skill files. Deliberately independent of
# `_sc_skill_injection_block`/`_SC_SKILL_INJECT_EXCLUDE`: those enforce the
# SC spawn_manifest.md-bound path where MOVE_SAFETY_CORE_DIRECTIVES is
# excluded because SC breadth agents already receive it via the orchestrator
# (commands/plamen.md) -- L1 has no such pathway, so this is a fresh,
# independent injection point.
# ---------------------------------------------------------------------------

_L1_MOVE_ROUTING_SKILLS: tuple[str, ...] = (
    "MOVE_SAFETY_CORE_DIRECTIVES", "ABILITY_ANALYSIS", "TYPE_SAFETY",
)
_L1_MOVE_ROUTING_ROLES = frozenset({"state_trace", "external"})


def _l1_has_move_sources(scratchpad: Path) -> bool:
    """True when recon's mechanical `.move` scan set HAS_MOVE_SOURCES for this
    L1 repo. Checks `detected_patterns.md` first (the authoritative mechanical
    flag-emission artifact written by `_seed_move_sources_flag`), falling back
    to `template_recommendations.md` (the 'Move Skill Routing' section it also
    writes). Never raises -- a missing/unreadable file simply means False."""
    for name in ("detected_patterns.md", "template_recommendations.md"):
        p = scratchpad / name
        try:
            if p.exists() and "HAS_MOVE_SOURCES" in p.read_text(
                encoding="utf-8", errors="replace"
            ):
                return True
        except Exception:
            continue
    return False


def _l1_move_skill_injection_block(scratchpad: Path, role: str) -> str:
    """Build the MANDATORY Move-skill routing block for an L1 depth worker
    prompt. Empty unless `role` is state_trace/external AND HAS_MOVE_SOURCES
    is set, so the prompt is byte-identical for every other L1 role and for
    every SC run (this function is only ever called when pipeline=="l1")."""
    if str(role or "").strip().lower() not in _L1_MOVE_ROUTING_ROLES:
        return ""
    if not _l1_has_move_sources(scratchpad):
        return ""
    resolved: list[tuple[str, str]] = []
    for name in _L1_MOVE_ROUTING_SKILLS:
        p = _sc_skill_path_for_name(name)
        if p is not None:
            resolved.append((name, p.as_posix()))
        else:
            log.warning(
                "[l1-move-routing] skill %r did not resolve to a SKILL.md -- "
                "not injected", name,
            )
    if not resolved:
        return ""
    lines = [
        "",
        "## MOVE SKILL ROUTING (MANDATORY — mechanically injected, HAS_MOVE_SOURCES)",
        "",
        "Recon's mechanical scan found `.move` source files in this L1 repo "
        "(an embedded Move-VM execution layer). The driver routed the vetted "
        "Aptos/Sui core Move skills to your role. You MUST read each and "
        "EXECUTE it against the `.move` sources in scope, in addition to your "
        "normal L1 depth methodology.",
        "",
    ]
    for name, posix in resolved:
        lines.append(f"- Read and EXECUTE `{posix}` (skill `{name}`).")
    lines.append("")
    return "\n".join(lines)


def _niche_jobs_from_spawn_manifest(scratchpad: Path) -> list[dict[str, str]]:
    """PRIMARY niche source: instantiate's ``spawn_manifest.md`` ``### Niche
    Agents`` table (>=5 columns: Niche Agent | Focus | Required | Agent ID |
    Output). Returns no rows when the manifest is absent or unparseable so
    older/resume runs keep their existing behavior.
    """
    manifest = scratchpad / "spawn_manifest.md"
    if not manifest.exists():
        return []
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    jobs: list[dict[str, str]] = []
    in_niche = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Site 2 (regex-fragility plan): `#{1,6}` + heading-synonym tolerant.
        if _niche_heading_match(line):
            in_niche = True
            continue
        if in_niche and re.match(r"^#{1,6}\s+", line):
            break
        if not in_niche or not line.startswith("|") or _is_separator_row(line):
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if len(cells) < 5 or cells[0].lower().startswith("niche agent"):
            continue
        # Site 2: Required-cell alias table (YES/Required/Y/True/✓...) + clause
        # negation guard, replacing the literal `"YES" in cell.upper()`. A
        # missed Required row = a whole analysis lane never spawns.
        if not _niche_required_cell_yes(cells[2]):
            continue
        skill = cells[0]
        agent_id = cells[3] or f"niche-{_niche_slug_from_name(skill)}"
        output = cells[4]
        if not output.endswith(".md"):
            output = f"niche_{_niche_slug_from_name(skill).replace('-', '_')}_findings.md"
        role = _niche_slug_from_name(skill).replace("-", "_")
        jobs.append({
            "agent_id": agent_id,
            "role": role,
            "output": output,
            "category": "niche",
            "focus": f"{skill}: standalone flag-triggered niche methodology",
        })
    return jobs


def _niche_rec_row_is_stub(cells: list[str]) -> bool:
    """True iff a template_recommendations niche row is the empty placeholder
    stub (``| _(none extracted)_ | - | - | - |``) or an all-dash/empty row.
    Recon writes such a stub for its FIRST (empty) ``### Niche Agents`` section
    before the real determinations table; it must never spawn an agent.
    """
    low = " ".join(c.strip().lower() for c in cells)
    if "none extracted" in low or "_(none" in low:
        return True
    return all(c.strip() in ("", "-", "—", "–", "n/a") for c in cells)


def _niche_jobs_from_template_recommendations(scratchpad: Path) -> list[dict[str, str]]:
    """DETERMINISTIC FALLBACK niche source: recon's ``template_recommendations.md``
    ``### Niche Agents`` table(s).

    Root cause this repairs: recon flags niche agents ``Required=YES`` in
    ``template_recommendations.md``, but instantiate sometimes writes NO niche
    rows into ``spawn_manifest.md`` — so the primary consumer sees an empty
    table and the recon-required lanes silently never spawn. This reads recon's
    authoritative determinations directly.

    The recon table is 4-column (``| Skill | Trigger | Required | Rationale |``)
    and there are usually TWO ``### Niche Agents`` sections: an empty
    ``_(none extracted)_`` stub first and the real table second — both are read;
    stub rows are skipped. HARD CONSTRAINT: only rows recon affirmatively marked
    ``Required=YES`` (``_niche_required_cell_yes``) that resolve to a real
    ``agents/skills/niche/<slug>/SKILL.md`` are spawned — never a lane recon did
    not flag for this codebase, never a non-existent agent.
    """
    rec = scratchpad / "template_recommendations.md"
    if not rec.exists():
        return []
    try:
        text = rec.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    jobs: list[dict[str, str]] = []
    seen: set[str] = set()
    in_niche = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # A niche heading (re)opens a niche section; a NON-niche heading closes
        # the current one. Do NOT break — a second `### Niche Agents` section
        # (the real one after the empty stub) must still be read.
        if _niche_heading_match(line):
            in_niche = True
            continue
        if in_niche and re.match(r"^#{1,6}\s+", line):
            in_niche = False
            continue
        if not in_niche or not line.startswith("|") or _is_separator_row(line):
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        # Recon table is 4-column (Skill | Trigger | Required | Rationale); read
        # cells[0]=skill and cells[2]=Required. Require >=3 to index cells[2].
        if len(cells) < 3:
            continue
        skill = cells[0]
        low0 = skill.lower()
        if not skill or low0 == "skill" or low0.startswith("niche agent"):
            continue  # header row
        if _niche_rec_row_is_stub(cells):
            continue  # empty `_(none extracted)_` placeholder section
        # HARD CONSTRAINT: recon Required=YES only.
        if not _niche_required_cell_yes(cells[2]):
            continue
        slug = _niche_slug_from_name(skill)
        # The semantic-gap lane is spawned via the dedicated `_semantic_gap_required`
        # path in `_depth_worker_jobs`; never double-spawn it from here.
        if slug == "semantic-gap-investigator":
            continue
        # Must resolve to a real niche SKILL.md, else there is no agent to run.
        if not _niche_skill_path_for_role(skill).exists():
            continue
        agent_id = f"niche-{slug}"
        output = f"niche_{slug.replace('-', '_')}_findings.md"
        if agent_id in seen or output in seen:
            continue  # dedupe within the fallback rows
        seen.add(agent_id)
        seen.add(output)
        jobs.append({
            "agent_id": agent_id,
            "role": slug.replace("-", "_"),
            "output": output,
            "category": "niche",
            "focus": f"{skill}: standalone flag-triggered niche methodology",
        })
    return jobs


def _required_niche_worker_jobs(scratchpad: Path) -> list[dict[str, str]]:
    """Derive niche depth workers, spawn_manifest.md PRIMARY.

    The manifest is the producer boundary: if it declares required niche
    workers, the PTY worker pool launches those exact output files. When the
    manifest EXISTS but declared no niche rows (an instantiate propagation gap),
    fall back to recon's authoritative ``Required=YES`` determinations in
    ``template_recommendations.md`` so recon-flagged lanes actually spawn.

    Manifest-absent preserves the historical ``[]`` (resume-before-instantiate
    safety); the fallback fires only when instantiate ran but declared none.
    """
    manifest_jobs = _niche_jobs_from_spawn_manifest(scratchpad)
    if manifest_jobs:
        return manifest_jobs
    # Only fall back when the manifest EXISTS but declared no niche rows.
    if not (scratchpad / "spawn_manifest.md").exists():
        return []
    return _niche_jobs_from_template_recommendations(scratchpad)


def _depth_worker_jobs(scratchpad: Path, config: dict) -> list[dict[str, str]]:
    """Return the deterministic depth artifact plan for a fresh worker pool."""
    pipeline = str(config.get("pipeline", "sc"))
    mode = str(config.get("mode", "core")).lower()
    jobs: list[dict[str, str]] = []
    if pipeline == "l1":
        jobs.extend(dict(job) for job in _L1_DEPTH_STANDARD_JOBS)
        if mode in ("core", "thorough"):
            # L1-4: scanner floor (mirrors SC's blind-spot A/B/C + validation
            # sweep). Gated Core+ to match where the SC scanner/sweep lane runs.
            jobs.extend(dict(job) for job in _L1_SCANNER_JOBS)
            # L1-5: Sibling Propagation is defined for L1 too (see
            # `## Sibling Propagation Agent` in
            # prompts/l1/phase4b-scanner-templates.md). Best-effort, additive —
            # NOT in l1_never_cut_groups; a missing/empty output degrades and
            # continues (see `_stub_missing_sibling_outputs_on_exhaustion`).
            seen_sibling = {str(job.get("output", "")) for job in jobs}
            for sib_job in _sibling_propagation_jobs_if_required(scratchpad, config):
                if sib_job["output"] not in seen_sibling:
                    jobs.append(sib_job)
                    seen_sibling.add(sib_job["output"])
        if mode == "thorough":
            jobs.extend(dict(job) for job in _DEPTH_THOROUGH_SIDE_JOBS)
    else:
        jobs.extend(dict(job) for job in _SC_DEPTH_STANDARD_JOBS)
        if mode in ("core", "thorough"):
            jobs.extend(dict(job) for job in _SC_DEPTH_CORE_SIDE_JOBS)
            # Gate 1 (resume safety): a run that resumes past instantiate, or
            # whose spawn_manifest niche table degraded, must still dispatch the
            # recall-safe union of required niches. Repair the manifest BEFORE
            # `_required_niche_worker_jobs` reads it so the consumer cannot
            # silently dispatch an empty/inconsistent niche table.
            try:
                _validate_niche_manifest_consistency(scratchpad, mode)
            except Exception:
                pass
            seen_outputs = {str(job.get("output", "")) for job in jobs}
            for niche_job in _required_niche_worker_jobs(scratchpad):
                if niche_job["output"] not in seen_outputs:
                    jobs.append(niche_job)
                    seen_outputs.add(niche_job["output"])
            try:
                if _semantic_gap_required(scratchpad):
                    output = "niche_semantic_gap_findings.md"
                    if output not in seen_outputs:
                        jobs.append({
                            "agent_id": "niche-semantic-gap",
                            "role": "semantic_gap_investigator",
                            "output": output,
                            "category": "niche",
                            "focus": (
                                "Semantic-gap investigator: sync gaps, "
                                "accumulation exposure, conditional writes and "
                                "lifecycle/cluster gaps from semantic_invariants.md"
                            ),
                        })
            except Exception:
                pass
            # Roster the (already-authored) Sibling Propagation Agent as an
            # ADDITIVE, best-effort depth job. Not in sc_never_cut_groups; a
            # missing/empty output degrades-and-continues (see
            # _stub_missing_sibling_outputs_on_exhaustion), never halts depth.
            seen_sibling = {str(job.get("output", "")) for job in jobs}
            for sib_job in _sibling_propagation_jobs_if_required(scratchpad, config):
                if sib_job["output"] not in seen_sibling:
                    jobs.append(sib_job)
                    seen_sibling.add(sib_job["output"])
        if mode == "thorough":
            jobs.extend(dict(job) for job in _DEPTH_THOROUGH_SIDE_JOBS)
            # Thorough-only conditional fuzz sidecar worker(s). Additive and
            # non-blocking: outputs are NOT in the depth hard gate nor in
            # sc_never_cut_groups. seen_outputs dedup keeps resume/re-entry from
            # double-adding (mirrors the niche-job dedup above).
            seen_fuzz = {str(job.get("output", "")) for job in jobs}
            for fuzz_job in _depth_fuzz_jobs_if_required(scratchpad, config):
                if fuzz_job["output"] not in seen_fuzz:
                    jobs.append(fuzz_job)
                    seen_fuzz.add(fuzz_job["output"])
    return jobs


def _depth_canonical_outputs(jobs: list[dict[str, str]]) -> list[str]:
    return [
        str(job["output"])
        for job in jobs
        if job.get("category") == "standard"
    ]


_DEPTH_LIFECYCLE_MARKER_RE = re.compile(
    r"(?im)^[ \t]*<!--\s*(?:"
    r"PLAMEN_(?:ARTIFACT|OWNER|STATUS|PHASE|VERSION|ITERATION)"
    r"|AGENT_ROW|EXPECTED_OUTPUT"
    r")\s*:\s*[^>]*-->\s*\r?\n?"
)
_DEPTH_LEGACY_PHASE4B_MARKER_RE = re.compile(
    r"(?im)^[ \t]*<!--\s*PLAMEN:PHASE4B:[^>]*-->\s*\r?\n?"
)
_DEPTH_WORKER_STRUCTURAL_PLACEHOLDERS: tuple[str, ...] = (
    "TODO:", "FILL_ME", "<placeholder>",
)


def _depth_worker_has_complete_signal(text: str) -> bool:
    """Accept current COMPLETE markers and old phase4b complete sentinels."""
    if re.search(
        r"<!--\s*PLAMEN_STATUS\s*:\s*COMPLETE\s*-->",
        text,
        flags=re.IGNORECASE,
    ):
        return True
    return bool(
        re.search(
            r"<!--\s*PLAMEN:PHASE4B:[^>]*:COMPLETE(?::[^>]*)?\s*-->",
            text,
            flags=re.IGNORECASE,
        )
    )


def _normalize_depth_worker_marker_envelope(
    scratchpad: Path,
    phase: Phase,
    job: dict[str, str],
    *,
    final_turn_complete: bool = False,
) -> bool:
    """Repair marker-only depth drift without changing analysis content.

    Depth role methodologies still contain legacy Phase 4b header examples in
    some places. Claude may copy those even though the driver prompt specifies
    the fresh marker contract. If the file is substantive and already carries
    a completion signal, wrap it with the exact lifecycle markers expected by
    the worker-pool gate. Files that are genuinely unfinished stay unfinished
    and are retried.
    """
    output = str(job["output"])
    path = scratchpad / output
    try:
        if path.stat().st_size < max(phase.min_artifact_bytes, 500):
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    ok, _reasons = _structural_completeness_ok(
        path,
        required_headings=(),
        placeholder_strings=_DEPTH_WORKER_STRUCTURAL_PLACEHOLDERS,
    )
    if not ok:
        return False
    if not _depth_worker_has_complete_signal(text) and not final_turn_complete:
        return False

    agent_id = str(job.get("agent_id") or Path(output).stem)
    body = _DEPTH_LIFECYCLE_MARKER_RE.sub("", text)
    body = _DEPTH_LEGACY_PHASE4B_MARKER_RE.sub("", body).strip()
    header = "\n".join([
        f"<!-- PLAMEN_ARTIFACT: {output} -->",
        f"<!-- PLAMEN_OWNER: {agent_id} -->",
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->",
        "<!-- PLAMEN_PHASE: depth -->",
        "<!-- PLAMEN_VERSION: 1 -->",
        f"<!-- AGENT_ROW: {agent_id} -->",
        f"<!-- EXPECTED_OUTPUT: {output} -->",
    ])
    normalized = f"{header}\n\n{body}\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    if normalized != text:
        tmp = path.with_name(
            f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:12]}"
        )
        tmp.write_text(normalized, encoding="utf-8")
        tmp.replace(path)
        log.info("[depth] normalized marker envelope for %s", output)
        return True
    return False


def _depth_worker_output_complete(
    scratchpad: Path,
    phase: Phase,
    job: dict[str, str],
    *,
    final_turn_complete: bool = False,
) -> bool:
    output = job["output"]
    if scratchpad_is_fresh_audit(scratchpad):
        _normalize_depth_worker_marker_envelope(
            scratchpad,
            phase,
            job,
            final_turn_complete=final_turn_complete,
        )
    if job.get("category") == "standard":
        statuses = {
            r.get("name"): r.get("status")
            for r in compute_depth_row_statuses(scratchpad, phase)
        }
        return statuses.get(output) == "complete"
    path = scratchpad / output
    try:
        if path.stat().st_size < max(phase.min_artifact_bytes, 500):
            return False
    except OSError:
        return False
    if scratchpad_is_fresh_audit(scratchpad):
        return is_artifact_complete(path, max(phase.min_artifact_bytes, 500))
    return True


def _depth_open_jobs(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [
        job for job in jobs
        if not _depth_worker_output_complete(scratchpad, phase, job)
    ]


def _should_use_depth_worker_pool(config: dict, scratchpad: Path) -> bool:
    """Return True when depth can run as driver-owned PTY workers."""
    try:
        return scratchpad_is_fresh_audit(scratchpad) and bool(
            _depth_worker_jobs(scratchpad, config)
        )
    except Exception:
        return False


def _depth_methodology_path(config: dict) -> Path:
    if str(config.get("pipeline", "sc")) == "l1":
        return plamen_home() / "prompts" / "l1" / "phase4b-depth-driver.md"
    return plamen_home() / "prompts" / "shared" / "v2" / "phase4b-depth.md"


def _scanner_template_dir(config: dict) -> str:
    """Return the `prompts/{dir}/phase4b-scanner-templates.md` directory.

    L1 scanner/sibling methodology lives under `prompts/l1/`, not under a
    Go/Rust language directory (no `prompts/go/` or `prompts/rust/` tree
    exists). Every SC language (evm/solana/aptos/sui/soroban/daml) keeps its
    own `phase4b-scanner-templates.md`, keyed by `config["language"]` as
    before.
    """
    if str(config.get("pipeline", "sc")) == "l1":
        return "l1"
    return str(config.get("language", "unknown"))


_SC_SCANNER_HEADING_BY_ROLE: dict[str, str] = {
    "blind_spot_a": "## Blind Spot Scanner A",
    "blind_spot_b": "## Blind Spot Scanner B",
    "blind_spot_c": "## Blind Spot Scanner C",
    "validation_sweep": "## Validation Sweep Agent",
}

# L1 scanner methodology uses generic `## Scanner: ...` headings (no
# tokens/guards/inheritance vocabulary — consensus clients have no analog).
# Order mirrors the SC blind-spot-A/B/C + validation-sweep role slots so the
# same job scaffolding (`_L1_SCANNER_JOBS` / never-cut groups) applies to both.
_L1_SCANNER_HEADING_BY_ROLE: dict[str, str] = {
    "blind_spot_a": "## Scanner: Boundary and Wire Format",
    "blind_spot_b": "## Scanner: State Transition and Consensus Invariant",
    "blind_spot_c": "## Scanner: Network Amplification and Resource Exhaustion",
    "validation_sweep": "## Scanner: Lifecycle, Cache, and Recovery",
}


def _build_depth_worker_prompt(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    attempt: int,
    retry_reasons: list[str] | None = None,
) -> str:
    output = job["output"]
    agent_id = job["agent_id"]
    role = job["role"]
    category = job.get("category", "standard")
    pipeline = str(config.get("pipeline", "sc"))
    language = str(config.get("language", "unknown"))
    methodology = _depth_methodology_path(config).as_posix()
    agent_methodology = (
        plamen_home() / "agents" / f"depth-{role.replace('_', '-')}.md"
    )
    language_template = (
        plamen_home() / "prompts" / language / "phase4b-depth-templates.md"
    )
    confidence_rules = (
        plamen_home() / "rules" / "phase4-confidence-scoring.md"
    ).as_posix()
    finding_format = (
        plamen_home() / "rules" / "finding-output-format.md"
    ).as_posix()
    retry_block = ""
    if retry_reasons:
        retry_block = (
            "\n## Previous Gate Failure\n\n"
            + "\n".join(f"- {r}" for r in retry_reasons)
            + "\n"
        )
        if role in {"token_flow", "state_trace"} and any(
            "perturbation block" in str(reason).lower()
            for reason in retry_reasons
        ):
            retry_block += """
## Perturbation Repair Is Mandatory

Your prior output failed the structural gate because one or more Medium+
CONFIRMED findings did not have an inline `### Perturbation Block - <finding_id>`
section. Repair ALL Medium/Critical/High CONFIRMED findings in the file, not
only the IDs named above. If you rename, split, merge, or add any Medium+
CONFIRMED finding during this retry, the new finding must receive its own
inline perturbation block before the next finding starts.

Do not mark the file COMPLETE until a final self-scan confirms every Medium+
CONFIRMED finding has a matching `### Perturbation Block - <finding_id>` H3.
"""

    perturbation_block = ""
    perturbation_contract_item = ""
    if role in {"token_flow", "state_trace"}:
        perturbation_block = """
Mandatory perturbation-retention contract for this role:
- For every Medium+ CONFIRMED finding, append a
  `### Perturbation Block - <finding_id>` table directly after the finding.
  Use this exact H3 heading form; do not write it as bold text or a bullet.
- Before marking the file COMPLETE, scan your own output and confirm that no
  Medium/Critical/High CONFIRMED finding is missing this H3 table.
- The table must test sibling functions/contracts, decoded fields, inverse
  operation/direction, and actor categories when applicable.
- At least two rows should carry a concrete non-N/A verdict with file:line
  evidence unless the codebase genuinely lacks those dimensions; if absent,
  state the concrete reason in the table.
- Do not move this work to a later phase unless you emit an explicit carried
  obligation receipt naming that phase.
"""
        perturbation_contract_item = """
5. Because this is a token-flow/state-trace role, every Critical/High/Medium
   `**Verdict**: CONFIRMED` finding MUST include an inline H3 section named
   exactly `### Perturbation Block - <finding_id>` before the next finding.
   This is a hard structural gate. A separate `perturbation_findings.md`,
   bold `**Perturbation Block**` label, checklist, or later-phase promise does
   not satisfy this worker file contract.
6. Immediately before writing `<!-- PLAMEN_STATUS: COMPLETE -->`, perform this
   self-check: list each Medium+ CONFIRMED finding ID in memory and verify that
   the same finding block contains its matching H3 perturbation block. If any
   are missing, repair them before marking COMPLETE.
"""

    # P1: inject the recon-selected INJECTABLE_DEPTH skills bound to this depth
    # role (SC only) — e.g. DEX_INTEGRATION_SECURITY / INTEGRATION_HAZARD_RESEARCH
    # to depth-external. The manifest binds them but the prompt never consumed
    # them.
    depth_skill_block = ""
    if pipeline != "l1":
        try:
            _, depth_map = _parse_sc_skill_bindings(scratchpad, language)
            depth_skill_block = _sc_skill_injection_block(
                depth_map.get(str(role).lower(), []), agent_kind="depth",
                language=language,
            )
        except Exception as exc:
            log.debug(f"[depth] skill-injection skipped for {role}: {exc!r}")
    else:
        # Wave-2 A6: route the vetted aptos/sui core Move skills into
        # depth-state-trace/depth-external when this L1 repo embeds `.move`
        # sources (HAS_MOVE_SOURCES). No-op (empty string) for every other
        # role and for every run without embedded Move sources.
        try:
            depth_skill_block = _l1_move_skill_injection_block(
                scratchpad, str(role)
            )
        except Exception as exc:
            log.debug(f"[depth] L1 move-skill routing skipped for {role}: {exc!r}")

    standard_block = ""
    if category == "standard":
        standard_block = f"""
Read the role methodology at `{agent_methodology.as_posix()}` if it exists.
For SC audits, also read the role template from
`{language_template.as_posix()}` if it exists. For L1 audits, follow the L1
depth roster and SCIP pre-bake requirements in `{methodology}`.

Mandatory standard-depth sections:
- `## Semantic Proof Checks`
- `## Graph Artifact Consumption` for SC when graph artifacts exist or are unavailable
- `## Chain Summary`
{perturbation_block}
{depth_skill_block}
"""
    elif category == "fuzz":
        if role == "medusa_fuzz":
            fuzz_prompt = (plamen_home() / _FUZZ_MEDUSA_PROMPT).as_posix()
            # Medusa is ALWAYS-ON for EVM-Thorough: do NOT pre-gate on a
            # build_status flag. The worker self-probes Foundry/medusa and
            # scaffolds a harness from scratch when none ships. Empty flag name
            # routes to the informational flags_line below.
            fuzz_flag_name = ""
        else:
            fuzz_prompt = (
                plamen_home()
                / _FUZZ_INVARIANT_PROMPT_BY_LANG.get(
                    language, "prompts/evm/v2/phase4b-invariant-fuzz.md"
                )
            ).as_posix()
            fuzz_flag_name = _FUZZ_INVARIANT_FLAG_BY_LANG.get(language, "")
        # Resolve the real build root (dir owning foundry.toml / Cargo.toml /
        # Move.toml) — frequently a parent/sibling of the audit scope dir. The
        # driver grants it via --add-dir (see depth-worker command builder);
        # the worker must cd there to build/run.
        try:
            import importlib as _il_fz
            import sys as _sys_fz
            _sys_fz.path.insert(0, str(Path(__file__).parent))
            _mv_fz = _il_fz.import_module("mechanical_verify")
            _fz_build_root = _mv_fz._read_recon_build_root(
                scratchpad, language
            ) or _mv_fz._find_build_root(Path(project_root), language)
            build_root_posix = Path(_fz_build_root).as_posix()
        except Exception:
            build_root_posix = Path(project_root).as_posix()
        flag_val = None
        if fuzz_flag_name:
            flag_val = _read_build_status_flag(scratchpad, fuzz_flag_name)
        if fuzz_flag_name:
            flags_line = f"{fuzz_flag_name} = {flag_val} (from build_status.md)"
        elif role == "medusa_fuzz":
            flags_line = (
                "medusa availability is self-probed by the worker; not "
                "pre-gated. Probe `medusa --version`; if absent, attempt the "
                "documented install once. Medusa ALWAYS runs on EVM when "
                "Foundry can be set up"
            )
        else:
            flags_line = (
                "primary tool is auto-detected by the methodology "
                "(no build_status flag gates this ecosystem)"
            )
        standard_block = f"""
This is a depth FUZZ worker. Read the fuzz methodology at
`{fuzz_prompt}` and execute it directly. You ARE the worker — run
forge/medusa/cargo/sui via the Bash tool yourself; do NOT spawn Task/Agent
subagents and do NOT follow any coordinator/"spawn agent" instructions inside
that methodology (those are legacy; you are the executor).

The build root (the directory containing foundry.toml / Cargo.toml / Move.toml)
is `{build_root_posix}` and is in your --add-dir grant. `cd` there to build and
run. Treat any `{{PROJECT_ROOT}}` placeholder in the methodology as this build
root, and `{{SCRATCHPAD}}` as `{scratchpad.as_posix()}`.

Tool availability: {flags_line}. If the primary tool is
unavailable (or the harness will not compile after the documented recovery
attempts), follow the documented FALLBACK chain in the methodology
(proptest / boundary-value parameterized tests). For EVM medusa, the "fallback"
is from-scratch harness scaffolding: when the project ships no harness, BUILD
one against the in-scope contracts per the methodology, then run the campaign.
Reserve TOOL_UNAVAILABLE for genuine impossibility (medusa cannot be installed
AND the build root is not Foundry-usable). Only then write the degrade-continue
artifact and stop.

Bound your own fuzzer run so you finish well before the worker timeout:
forge invariant uses a <=300s budget; medusa pins `--timeout 600`.

### Degrade-Continue Contract (MANDATORY — silent skip is forbidden)

You MUST ALWAYS write the output file, even on any failure, and it MUST contain
a single line of the form:

`## Result Status: <RAN|TOOL_UNAVAILABLE|COMPILATION_FAILED|TIMEOUT|NOT_APPLICABLE>`

followed by a one-line reason. Choose:
- `RAN` — the campaign executed. List any invariant violations as
  `### Finding [FUZZ-N]` / `### Finding [MEDUSA-N]` rows with the
  `[FUZZ-PASS]` / `[MEDUSA-PASS]` evidence tag and the counterexample call
  sequence. If no violations: state "No violations detected" — that is fine.
- `TOOL_UNAVAILABLE` — the primary tool AND all documented fallbacks are
  absent (e.g. medusa not installed; Hardhat-only project with no invariant
  support). Contains NO findings — that is fine.
- `COMPILATION_FAILED` — the harness/contract did not compile after the
  documented recovery attempts. Include the error tail. NO findings.
- `TIMEOUT` — the fuzzer exceeded its self-bounded budget. NO findings.
- `NOT_APPLICABLE` — the assigned fuzz concern does not apply to this codebase.

A non-RAN status with NO findings is a VALID, complete artifact: the depth gate
requires file presence and the COMPLETE marker, NOT findings. Do NOT spawn
subagents. Do NOT inspect other workers' outputs. Do NOT advance to chain
analysis, verification, or reporting.
"""
    elif category == "niche":
        niche_skill = _niche_skill_path_for_role(role)
        standard_block = f"""
This is a standalone niche worker. Read the niche skill methodology at
`{niche_skill.as_posix()}` if it exists, then apply only that methodology to
the current project and write only the assigned output file. If the skill file
is missing, use `{methodology}` plus the Focus line above as fallback and state
that the skill file was unavailable in the output.

Do not spawn subagents. Do not inspect other niche workers' outputs. Do not
advance to chain analysis, verification, or reporting.
"""
    elif category == "scanner":
        scanner_dir = _scanner_template_dir(config)
        scanner_templates = (
            plamen_home() / "prompts" / scanner_dir / "phase4b-scanner-templates.md"
        ).as_posix()
        heading_map = (
            _L1_SCANNER_HEADING_BY_ROLE if pipeline == "l1"
            else _SC_SCANNER_HEADING_BY_ROLE
        )
        heading = heading_map.get(role, "")
        heading_line = (
            f"the `{heading}` section" if heading
            else "the section matching your assigned role"
        )
        standard_block = f"""
This is a depth-owned scanner worker. Read {heading_line} of
`{scanner_templates}` and apply ONLY that methodology to the current project —
do not read or apply any other scanner section in that file. Cross-reference
`{scratchpad.as_posix()}/findings_inventory.md` (what breadth/depth agents
already analyzed) so you surface what they missed, not what they already
covered.

Use finding IDs matching your assigned role's convention (e.g. `[BLIND-A-N]`
for the "blind_spot_a" role, `[VS-N]` for "validation_sweep") per
`{finding_format}`.

Do not spawn subagents. Do not inspect or write other workers' outputs. Do not
advance to chain analysis, verification, or reporting.
"""
    elif category == "sibling":
        scanner_dir = _scanner_template_dir(config)
        scanner_templates = (
            plamen_home() / "prompts" / scanner_dir / "phase4b-scanner-templates.md"
        ).as_posix()
        standard_block = f"""
This is the Sibling Propagation depth worker. Read the
`## Sibling Propagation Agent` section of
`{scanner_templates}` and apply ONLY that methodology: for each Medium+
CONFIRMED/PARTIAL finding in `{scratchpad.as_posix()}/findings_inventory.md`
(fall back to the depth `depth_*_findings.md` outputs if inventory is absent),
search the codebase for sibling functions/paths exhibiting the SAME root cause
pattern and report each as a new finding.

This is a best-effort, additive pass. If there are no Medium+ findings to
propagate, or no sibling instances exist, write a substantive `## No Findings`
rationale naming the findings you checked — that is a valid, complete artifact.

Do not spawn subagents. Do not inspect or write other workers' outputs. Do not
advance to chain analysis, verification, or reporting.
"""
    else:
        standard_block = f"""
This is a depth-owned `{category}` artifact. Use `{methodology}` as the source
of truth for the assigned role. Do not perform work outside this one
depth-owned artifact. If the assigned concern is not applicable, write a
substantive `## No Findings` / `## Not Applicable` rationale with the concrete
files and signals you checked.
"""

    # Payable-impact steering (BB mode only — gated on impact_map.md presence).
    impact_map_block = _impact_map_block(project_root)
    return f"""# DEPTH ROW WORKER

You are a single depth worker launched directly by the Python Plamen driver.
There is no Claude phase coordinator. Your job is to produce exactly one
depth-owned artifact and then stop.

## Assignment

- PROJECT_ROOT: `{project_root}`
- SCRATCHPAD: `{scratchpad.as_posix()}`
- LANGUAGE: `{language}`
- MODE: `{config.get('mode', 'unknown')}`
- PIPELINE: `{pipeline}`
- SUBSYSTEM_SCOPE: `{config.get('subsystem_scope') or '(none)'}`
- SCOPE_FILE: `{config.get('scope_file') or '(none)'}`
- SCOPE_NOTES: `{config.get('scope_notes') or '(none)'}`
- Agent ID: `{agent_id}`
- Role: `{role}`
- Category: `{category}`
- Focus: `{job.get('focus', role)}`
- Output file: `{output}`
- Attempt: `{attempt}`

## Output Allowlist

Write exactly this file and no other scratchpad artifact:

`{scratchpad.as_posix()}/{output}`

Do not infer, invent, or create any other output file. If methodology text asks
for a different output filename, ignore that output request and write only the
file above.
{retry_block}
## Methodology

Read `{methodology}` for the phase 4b methodology. Use it as analysis guidance
only. You are already the worker; do not spawn Task/Agent subagents and do not
follow coordinator instructions.

Read `{finding_format}` for finding format and `{confidence_rules}` for
confidence terminology. Use recon, inventory, invariant, graph, SCIP, opengrep,
and source artifacts in the scratchpad as relevant to this assigned role.

If `{scratchpad.as_posix()}/security_obligations.md` exists, read it as a
generic feature-derived obligation ledger. Address obligations relevant to
your assigned role without treating them as expected findings. When directly
disposing an obligation, emit a receipt:
`[OBLIG:security_obligations.md:<SO-ID>] STATUS:R|D|C KEY:<summary> -> <finding_id|reason|phase>`.

{standard_block}
{impact_map_block}
## Required File Contract

The output file must:

1. Start with these markers:
   `<!-- PLAMEN_ARTIFACT: {output} -->`
   `<!-- PLAMEN_OWNER: {agent_id} -->`
   `<!-- PLAMEN_STATUS: IN_PROGRESS -->`
   `<!-- PLAMEN_PHASE: depth -->`
   `<!-- PLAMEN_VERSION: 1 -->`
   `<!-- AGENT_ROW: {agent_id} -->`
   `<!-- EXPECTED_OUTPUT: {output} -->`
2. Contain substantive depth analysis for the assigned role and focus.
3. Include either real `### Finding [` / `## Finding [` blocks or a
   `## No Findings` / `## Not Applicable` rationale.
4. End with a final `<!-- PLAMEN_STATUS: COMPLETE -->` marker only after the
   file is fully written and verified on disk.
{perturbation_contract_item}

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other
agents' output files. Do NOT continue after the assigned file is complete.
Return your findings and stop.

When done, return exactly one line:

`DONE: {output} complete`
"""


def _run_single_depth_worker_pty(
    *,
    job: dict[str, str],
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
    retry_reasons: list[str] | None = None,
    allowed_outputs: list[str] | None = None,
    protected_input_names: set[str] | None = None,
) -> dict[str, Any]:
    output = job["output"]
    allowed_output_set = set(allowed_outputs or [output])
    protected_input_set = set(protected_input_names or set())
    session_id = str(uuid.uuid4())
    prompt = _build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=project_root,
        config=config,
        attempt=attempt,
        retry_reasons=retry_reasons,
    )
    snap = scratchpad / (
        f"_prompt_depth_worker_{Path(output).stem}.attempt{attempt}.md"
    )
    snap.write_text(prompt, encoding="utf-8")
    cmd = _build_fresh_session_cmd(base_cmd, session_id)
    cmd = _rewrite_argv_positional_prompt(cmd, snap)
    log_path = scratchpad / (
        f"_stdio_depth_worker_{Path(output).stem}.attempt{attempt}.log"
    )
    known_stats: dict[str, tuple[int, int]] = {}
    try:
        for p in scratchpad.iterdir():
            if p.is_file() and not p.name.startswith("_"):
                try:
                    st = p.stat()
                    known_stats[p.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    known_stats[p.name] = (0, 0)
    except Exception:
        known_stats = {}

    def _worker_poll(_now: float, _state: Any) -> None:
        try:
            for p in scratchpad.iterdir():
                if p.name.startswith("_") or not p.is_file():
                    continue
                known_names = set(known_stats)
                try:
                    st = p.stat()
                    sig = (st.st_size, st.st_mtime_ns)
                except OSError:
                    sig = (0, 0)
                old_sig = known_stats.get(p.name)
                known_stats[p.name] = sig
                if _worker_artifact_name_allowed(p.name, allowed_output_set):
                    continue
                if old_sig == sig:
                    continue
                if p.name in protected_input_set:
                    continue
                if _worker_artifact_is_benign_duplicate_copy(p.name, known_names):
                    moved = _quarantine_worker_duplicate_copy(
                        scratchpad=scratchpad,
                        path=p,
                        phase_name="depth",
                        worker_output=output,
                    )
                    if moved is not None:
                        log.info(
                            "[depth] worker %s quarantined benign duplicate "
                            "scratchpad copy: %s -> %s",
                            output,
                            p.name,
                            moved.relative_to(scratchpad).as_posix(),
                        )
                    continue
                log.error(
                    "[depth] worker %s wrote or modified out-of-scope "
                    "artifact: %s",
                    output,
                    p.name,
                )
                raise _PtyStop(-4)
        except _PtyStop:
            raise
        except Exception:
            pass

    with log_path.open("w", encoding="utf-8", errors="replace") as out:
        session = ClaudePtySession(
            cmd,
            cwd=project_root,
            env=env,
            session_id=session_id,
            prompt_path=snap,
            log_file=out,
        )
        _register_active_worker_session(session)
        try:
            out.write(f"CLAUDE_TRANSCRIPT={session.transcript_path}\n")
            out.flush()
            session.spawn()
            session.send_bootstrap()
            state = session.wait_for_turn_complete(
                timeout,
                quiescence_s=quiescence_s,
                on_poll=_worker_poll,
            )
            if state.rate_limited:
                # A transient 529/overloaded is provider-wide, NOT a 429
                # account/usage cap. It must NOT escalate to the phase-level
                # usage-cap pause that stops the whole worker pool — Claude
                # Code's own retry loop (exp backoff, up to 10x) usually
                # self-recovers it. Classify it as a retriable worker failure
                # so the gate re-spawns just this one worker. Mirrors the
                # single-subprocess overload path (detect_overloaded backoff).
                if getattr(state, "overloaded", False):
                    return {"output": output, "rc": 1, "status": "overloaded",
                            "reasons": ["transient 529 overloaded -- retriable"]}
                return {"output": output, "rc": 1, "status": "rate_limited"}
            ok = _depth_worker_output_complete(
                scratchpad,
                phase,
                job,
                final_turn_complete=True,
            )
            status = "complete" if ok else "incomplete"
            reasons: list[str] = []
            if not ok:
                p = scratchpad / output
                if not p.exists():
                    reasons.append("missing")
                elif not is_artifact_complete(p, max(phase.min_artifact_bytes, 500)):
                    reasons.append("missing COMPLETE marker or too small")
            return {
                "output": output,
                "rc": 0 if ok else -2,
                "status": status,
                "reasons": reasons,
                "log": str(log_path),
            }
        except _PtyStop as stop:
            return {
                "output": output,
                "rc": stop.rc,
                "status": "containment",
                "reasons": ["worker wrote protected out-of-scope artifact"],
                "log": str(log_path),
            }
        except Exception as exc:
            return {
                "output": output,
                "rc": EXIT_ERROR,
                "status": "error",
                "reasons": [str(exc)],
                "log": str(log_path),
            }
        finally:
            _unregister_active_worker_session(session)
            try:
                session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
            except Exception:
                pass
            try:
                if session.transcript_path.exists():
                    out.write("\n\n# Claude session transcript tail\n")
                    with session.transcript_path.open("rb") as tf:
                        tf.seek(0, 2)
                        size = tf.tell()
                        tf.seek(max(0, size - 65536))
                        out.write(tf.read().decode("utf-8", errors="replace"))
                    out.flush()
            except Exception:
                pass


def _depth_worker_pool_progress_status(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
    active_outputs: list[str],
) -> str:
    complete = sum(
        1 for job in jobs
        if _depth_worker_output_complete(scratchpad, phase, job)
    )
    missing = max(0, len(jobs) - complete - len(active_outputs))
    return _format_worker_pool_progress_status(
        complete=complete,
        total=len(jobs),
        active_outputs=active_outputs,
        queued=missing,
        phase_label="depth",
    )


# v2.8.8: the perturbation depth worker mutates EVERY depth finding, so it is
# legitimately the slowest worker (observed ~80% of the depth timeout ceiling on
# a prior run). On a larger codebase it could hit the uniform ceiling and be killed —
# silently losing perturbation coverage (it is a sidecar, not a core artifact,
# so the pool degrades cleanly without a halt). Grant it extra ceiling headroom;
# this only prevents a premature kill — the worker still finishes via quiescence
# the moment it stops writing, so other workers are unaffected.
_PERTURBATION_TIMEOUT_MULT = 1.5


def _depth_job_timeout(job: dict, base: float) -> float:
    out = str(job.get("output") or "")
    if "perturbation_findings" in out:
        return base * _PERTURBATION_TIMEOUT_MULT
    return base


def _run_depth_worker_batch(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    jobs: list[dict[str, str]],
    attempt: int,
    pool_started: float,
    retry_reasons_by_output: dict[str, list[str]],
) -> tuple[int, list[dict[str, Any]]]:
    concurrency = min(_DEPTH_WORKER_CONCURRENCY, max(1, len(jobs)))
    output_names = {str(job["output"]) for job in jobs}
    pool_allowed_outputs = sorted(output_names)
    input_snapshot = _snapshot_worker_input_artifacts(scratchpad, output_names)
    protected_input_names = set(input_snapshot)
    results: list[dict[str, Any]] = []
    display.print_phase_heartbeat(
        "depth",
        int(time.time() - pool_started),
        status=_depth_worker_pool_progress_status(
            scratchpad, phase, jobs, [j["output"] for j in jobs[:concurrency]]
        ),
    )
    try:
        with _NonBlockingWorkerPool(
            max_workers=concurrency,
            thread_name_prefix="plamen-depth-worker",
        ) as executor:
            fut_to_job = {
                executor.submit(
                    _run_single_depth_worker_pty,
                    job=job,
                    scratchpad=scratchpad,
                    project_root=project_root,
                    config=config,
                    phase=phase,
                    base_cmd=base_cmd,
                    env=env,
                    timeout=_depth_job_timeout(job, timeout),
                    quiescence_s=quiescence_s,
                    attempt=attempt,
                    retry_reasons=retry_reasons_by_output.get(job["output"]),
                    allowed_outputs=pool_allowed_outputs,
                    protected_input_names=protected_input_names,
                ): job
                for job in jobs
            }
            pending_futs: set[concurrent.futures.Future] = set(fut_to_job)
            last_progress = time.time()
            while pending_futs:
                done, pending_futs = concurrent.futures.wait(
                    pending_futs,
                    timeout=_WORKER_POOL_UI_POLL_S,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                now = time.time()
                elapsed = int(now - pool_started)
                display.spin(elapsed)
                if display.graceful_stop.requested:
                    _cancel_pending_worker_futures(pending_futs, executor)
                    raise _PtyStop(-3)
                for fut in done:
                    result = fut.result()
                    results.append(result)
                    output = result.get("output", "(unknown)")
                    status = result.get("status")
                    log.info(f"[depth] worker {output}: {status}")
                    display.print_phase_heartbeat(
                        "depth",
                        elapsed,
                        status=f"worker {output}: {status}",
                    )
                    if result.get("status") == "rate_limited":
                        log.warning(
                            "[depth] worker %s hit rate limit; stopping "
                            "remaining workers and surfacing phase-level "
                            "rate-limit pause",
                            output,
                        )
                        _cancel_pending_worker_futures(pending_futs, executor)
                        return 1, results
                    last_progress = now
                if pending_futs and now - last_progress >= _WORKER_POOL_HEARTBEAT_S:
                    active_outputs = [
                        fut_to_job[fut]["output"]
                        for fut in pending_futs
                        if fut in fut_to_job
                    ][:concurrency]
                    display.print_phase_heartbeat(
                        "depth",
                        elapsed,
                        status=_depth_worker_pool_progress_status(
                            scratchpad, phase, jobs, active_outputs
                        ),
                    )
                    last_progress = now
    finally:
        restored_inputs = _restore_worker_input_artifacts(
            scratchpad, input_snapshot
        )
        if restored_inputs:
            log.info(
                "[depth] restored %d prior-phase input artifact(s) modified "
                "during worker batch: %s",
                len(restored_inputs),
                restored_inputs[:10],
            )
    if any(r.get("status") == "rate_limited" for r in results):
        return 1, results
    if any(r.get("rc") == -4 for r in results):
        return -4, results
    return 0, results


def _read_build_status_flag(scratchpad: Path, flag: str) -> bool | None:
    """Read a boolean tool-availability flag from build_status.md.

    Recon (Phase 1 TASK 1) records tool availability as lines like
    `MEDUSA_AVAILABLE: true` / `trident_available: false` /
    `**cargo_fuzz_available**: true`. Matching is case-insensitive on the flag
    name and tolerant of bold markers and bullet prefixes.

    Returns True/False when the flag is present, or None when build_status.md is
    missing or the flag is absent (the caller decides the default).
    """
    try:
        text = (scratchpad / "build_status.md").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return None
    m = re.search(
        r"(?im)^[ \t>*-]*\**\s*"
        + re.escape(flag)
        + r"\s*\**\s*[:=]\s*\**\s*(true|false|yes|no)\b",
        text,
    )
    if not m:
        return None
    return m.group(1).lower() in ("true", "yes")


def _l1_update_primitive_status_flag(scratchpad: Path, key: str, value: bool) -> None:
    """Idempotently set a `KEY=true|false` line in primitive_status.md.

    WP-A.3 (L1-only caller): the `bake` phase pre-writes primitive_status.md
    with `SCIP_GO_REUSED=false` / `SCIP_RUST_REUSED=false` fallback lines
    (they were declared but never refined). The pre-breadth SCIP bake hook
    calls this to record the ACTUAL `_bake_go_graph` / `_bake_rust_graph`
    outcome once it is known. Best-effort and never raises: primitive_status.md
    is a driver fallback scaffold, so a write failure here must not affect the
    SCIP bake it merely annotates.
    """
    try:
        path = scratchpad / "primitive_status.md"
        val = "true" if value else "false"
        line_re = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        if line_re.search(text):
            text = line_re.sub(f"{key}={val}", text, count=1)
        else:
            if text and not text.endswith("\n"):
                text += "\n"
            text += f"{key}={val}\n"
        path.write_text(text, encoding="utf-8")
    except Exception:
        pass


def _promote_cross_domain_candidates_to_inventory(scratchpad: Path) -> list[str]:
    """WP-D (L1-3): append CROSS-DOMAIN-DEP candidates as NEEDS_VERIFICATION
    inventory rows before the verification queue is built.

    Reuses `chain_prep.harvest_cross_domain_candidates` (read-only; auto-
    covers depth/scanner/sibling outputs via its existing globs — see
    `_CROSS_DOMAIN_SOURCE_GLOBS`) and the SAME `INV-N` id space
    `_promote_depth_findings_to_inventory` allocates from (re-derived from
    the on-disk inventory text AFTER that bridge has already run, and
    collision-checked against the id ledger), so these rows ride the
    existing verification_queue extraction path unmodified.

    Low-confidence by construction: every row is stamped
    `**Verdict**: NEEDS_VERIFICATION` — verify adjudicates each one. This
    function NEVER emits a CONFIRMED body finding. Best-effort: any failure
    (missing inventory, harvester error, id-allocation error) degrades to a
    no-op ([]); it never halts verify_queue.
    """
    try:
        inv = scratchpad / "findings_inventory.md"
        if not inv.exists():
            return []
        import importlib
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent))
        _cp = importlib.import_module("chain_prep")
        candidates = _cp.harvest_cross_domain_candidates(scratchpad)
        if not candidates:
            return []
        from plamen_validators import _allocate_depth_promotion_inventory_id
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
        next_n = max(
            (int(x) for x in re.findall(r"###\s+Finding\s+\[INV-(\d+)\]", inv_text)),
            default=0,
        ) + 1
        additions = [
            "",
            "## Cross-Domain Dependency Candidates (verify-adjudicated)",
            "",
            "Mechanically harvested from `[CROSS-DOMAIN-DEP: ...]` depth/scanner "
            "agent tags -- an admission that a value-bearing assumption lives "
            "outside that agent's own analysis domain. Each row is a "
            "LOW-CONFIDENCE candidate only; none of these are CONFIRMED body "
            "findings -- verification adjudicates every row.",
            "",
        ]
        promoted: list[str] = []
        for cand in candidates:
            source_id = str(cand.get("finding_id") or "CROSS-DOMAIN").strip()
            domain = str(cand.get("domain") or "unspecified").strip()
            detail = re.sub(r"\s+", " ", str(cand.get("detail") or "")).strip()
            location = str(cand.get("location") or "unknown").strip()
            inv_id, next_n = _allocate_depth_promotion_inventory_id(
                scratchpad,
                preferred_n=next_n,
                title=f"Cross-domain dependency ({domain}) from {source_id}",
            )
            promoted.append(inv_id)
            additions.extend([
                f"### Finding [{inv_id}]: Cross-domain dependency ({domain}) "
                f"referenced from {source_id}",
                f"**Source IDs**: [{source_id}]",
                "**Severity**: Low",
                f"**Location**: {location}",
                "**Preferred Tag**: CODE-TRACE",
                "**Verdict**: NEEDS_VERIFICATION",
                "",
                f"**Description**: A depth/scanner agent flagged an assumption "
                f"outside its own analysis domain ({domain}): {detail[:400]}. "
                "This is a mechanically-harvested candidate only -- "
                "verification must adjudicate whether the cross-domain "
                "dependency, if broken, creates or blocks an exploitable "
                "precondition elsewhere in scope.",
                "",
            ])
        inv.write_text(
            inv_text.rstrip() + "\n" + "\n".join(additions), encoding="utf-8"
        )
        return promoted
    except Exception as exc:
        log.debug(
            f"[verify_queue] cross-domain candidate promotion skipped: {exc!r}"
        )
        return []


# Per-ecosystem canonical fuzz worker prompt paths (relative to plamen_home()).
# Each path is the worker-shaped methodology the fuzz worker reads and executes
# directly. The driver only decides WHETHER to emit the job (mode + ecosystem +
# medusa flag); the prompt decides primary-vs-fallback-vs-skip from the tool
# flag and the compile result.
_FUZZ_INVARIANT_PROMPT_BY_LANG: dict[str, str] = {
    "evm": "prompts/evm/v2/phase4b-invariant-fuzz.md",
    "solana": "prompts/solana/v2/phase4b-invariant-fuzz.md",
    "soroban": "prompts/soroban/v2/phase4b-invariant-fuzz.md",
    "sui": "prompts/sui/v2/phase4b-invariant-fuzz.md",
}
_FUZZ_MEDUSA_PROMPT = "prompts/evm/v2/phase4b-medusa-fuzz.md"
# Tool-availability flag in build_status.md that the worker self-reads to pick
# primary-vs-fallback. Absence still emits the invariant job (the worker runs
# the documented fallback chain) — only EVM medusa is strictly flag-gated.
_FUZZ_INVARIANT_FLAG_BY_LANG: dict[str, str] = {
    "evm": "",  # forge/foundry — worker self-detects foundry.toml
    "solana": "trident_available",
    "soroban": "cargo_fuzz_available",
    "sui": "",  # sui move random_test — worker self-detects
}


def _depth_fuzz_jobs_if_required(
    scratchpad: Path, config: dict
) -> list[dict[str, str]]:
    """Thorough-only, ecosystem-gated depth fuzz sidecar job plan.

    Mirrors `_depth_da_job_if_required`: returns [] when not applicable, else a
    list of conditional depth worker jobs (category=='fuzz'). The jobs run forge
    /medusa/cargo/sui via Bash inside the depth worker pool — they never spawn
    Task() subagents.

    Gating (matrix should_run=true cells only):
      - mode != thorough            -> []
      - pipeline == 'l1'            -> [] (L1 uses per-finding verify fuzz tags)
      - language == 'aptos'         -> [] (Move has no invariant fuzzer)
      - evm                         -> invariant (always) + medusa (always; worker
                                       self-probes Foundry/medusa + scaffolds a
                                       harness from scratch; degrade-continues)
      - solana / soroban / sui      -> invariant (always; worker self-selects
                                       primary-vs-fallback from the tool flag)

    The invariant job is ALWAYS emitted for should_run ecosystems even when the
    primary fuzzer flag is absent, so the documented FALLBACK chain (proptest/
    boundary) runs and the skip is LOGGED, not silent. The EVM medusa job is now
    ALSO always emitted (no MEDUSA_AVAILABLE pre-gate): the worker self-probes
    Foundry/medusa, scaffolds a harness from scratch when the project ships none,
    and degrade-continues to a logged TOOL_UNAVAILABLE/COMPILATION_FAILED stub if
    medusa truly cannot be installed/run. Medusa is never in the depth hard gate,
    so a missing/failed medusa artifact cannot fail the depth phase.
    """
    if str(config.get("mode", "core")).lower() != "thorough":
        return []
    if str(config.get("pipeline", "sc")).lower() == "l1":
        return []
    language = str(config.get("language", "")).lower().strip()
    if language not in _FUZZ_INVARIANT_PROMPT_BY_LANG:
        # aptos and any other ecosystem with no invariant fuzzer -> emit nothing.
        return []
    jobs: list[dict[str, str]] = [{
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": "invariant_fuzz_results.md",
        "category": "fuzz",
        "focus": (
            f"Invariant fuzz campaign for {language}: derive protocol "
            "invariants, build the harness, run the primary fuzzer (or the "
            "documented fallback if unavailable), report violations"
        ),
    }]
    if language == "evm":
        # ALWAYS-ON: medusa runs on every EVM-Thorough audit. The worker
        # self-probes Foundry/medusa and scaffolds a harness from scratch when
        # the project ships none; it degrade-continues to a logged stub only if
        # medusa truly cannot be installed AND the build root is not
        # Foundry-usable. No MEDUSA_AVAILABLE pre-gate (recon's scope-excluded
        # probe frequently fails to set it even when medusa IS installed).
        jobs.append({
            "agent_id": "medusa-fuzz",
            "role": "medusa_fuzz",
            "output": "medusa_fuzz_findings.md",
            "category": "fuzz",
            "focus": (
                "Medusa stateful fuzz campaign: probe/provision medusa, use the "
                "shipped harness or scaffold a standalone Medusa harness from "
                "scratch, run medusa --timeout 600, report [MEDUSA-N] "
                "violations; degrade-continue to a logged stub if medusa truly "
                "cannot be installed/run"
            ),
        })
    return jobs


def _sibling_propagation_jobs_if_required(
    scratchpad: Path, config: dict
) -> list[dict[str, str]]:
    """Best-effort Sibling Propagation depth sidecar job plan (SC + L1).

    The Sibling Propagation Agent is DEFINED in every SC tree's AND the L1
    tree's `phase4b-scanner-templates.md` (`## Sibling Propagation Agent`,
    output `sibling_propagation_findings.md`) but was never spawned by the
    driver. This rosters it as an ADDITIVE depth worker job for both
    pipelines.

    Best-effort by construction (safety-critical): the output is NOT in
    `sc_never_cut_groups` / `l1_never_cut_groups`, so the never-cut gate cannot
    fail on its absence, and `category=='sibling'` is stubbed degrade-continue
    by `_stub_missing_sibling_outputs_on_exhaustion` if the worker never
    produces output. A missing/empty `sibling_propagation_findings.md` therefore
    degrades and continues; it never halts the depth phase.

    Gating (matches where the SC scanner/validation secondaries run):
      - mode not in core/thorough   -> [] (Light skips the re-scan/scanner lane)
    """
    if str(config.get("mode", "core")).lower() not in ("core", "thorough"):
        return []
    return [{
        "agent_id": "sibling-propagation",
        "role": "sibling_propagation",
        "output": "sibling_propagation_findings.md",
        "category": "sibling",
        "focus": (
            "Sibling propagation: for each Medium+ CONFIRMED/PARTIAL finding, "
            "search the codebase for sibling functions/paths with the SAME root "
            "cause pattern and report each as a new finding"
        ),
    }]


def _stub_missing_sibling_outputs_on_exhaustion(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
) -> bool:
    """Write a degrade-continue stub for any incomplete sibling/scanner job.

    Mirrors `_stub_missing_fuzz_outputs_on_exhaustion`. Sibling propagation and
    scanner (blind-spot/validation-sweep) jobs are additive/never-cut-floor
    jobs, not exit-early-if-crashed jobs — a worker that crashed before
    writing its output must not be allowed to halt depth. Writes a minimal
    `## No Findings` artifact (with the COMPLETE marker) for each still-
    incomplete `category in ('sibling', 'scanner')` job. Returns True when at
    least one stub was written. Standard/sidecar/niche/fuzz jobs are
    untouched.

    Note: for L1/SC scanner jobs this stub SATISFIES the never-cut gate (a
    file must exist, stub or not) — it converts a crashed-worker halt into a
    degrade-continue with an empty, honestly-labeled artifact.
    """
    wrote = False
    for job in jobs:
        category = job.get("category")
        if category not in ("sibling", "scanner"):
            continue
        if _depth_worker_output_complete(scratchpad, phase, job):
            continue
        output = str(job["output"])
        default_agent = "sibling-propagation" if category == "sibling" else "scanner"
        agent_id = str(job.get("agent_id", default_agent))
        path = scratchpad / output
        if category == "sibling":
            title = f"Sibling Propagation Findings ({agent_id})"
            reason = "sibling-propagation worker produced no output after all retry attempts"
            note = (
                "The sibling-propagation pass did not execute, so no sibling "
                "findings were produced. This is a non-blocking degrade-continue "
                "artifact: sibling propagation is additive only and never gates "
                "the depth phase."
            )
        else:
            title = f"Scanner Findings ({agent_id})"
            reason = f"scanner worker {agent_id} produced no output after all retry attempts"
            note = (
                "The scanner pass did not execute, so no scanner findings were "
                "produced. This is a non-blocking degrade-continue artifact: it "
                "satisfies the scanner never-cut floor without fabricating "
                "analysis; a crashed scanner worker never halts the depth phase."
            )
        body = (
            f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
            f"<!-- PLAMEN_OWNER: {agent_id} -->\n"
            f"<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
            f"<!-- PLAMEN_PHASE: depth -->\n"
            f"<!-- PLAMEN_VERSION: 1 -->\n"
            f"<!-- AGENT_ROW: {agent_id} -->\n"
            f"<!-- EXPECTED_OUTPUT: {output} -->\n\n"
            f"# {title}\n\n"
            f"## No Findings\n"
            f"Reason: {reason}.\n\n"
            f"{note}\n\n"
            f"<!-- PLAMEN_STATUS: COMPLETE -->\n"
        )
        try:
            path.write_text(body, encoding="utf-8")
            wrote = True
            log.warning(
                "[depth] %s job %s exhausted retries — wrote degrade-continue "
                "stub (%s)",
                category, agent_id, output,
            )
        except OSError as exc:
            log.warning(
                "[depth] could not write %s degrade stub %s: %s",
                category, output, exc,
            )
    return wrote


def _depth_da_job_if_required(scratchpad: Path, config: dict) -> list[dict[str, str]]:
    if str(config.get("mode", "core")).lower() != "thorough":
        return []
    try:
        issues = _validate_confidence_iter2_mandatory(scratchpad)
    except Exception:
        issues = []
    if not issues:
        return []
    return [{
        "agent_id": "depth-da-iter2",
        "role": "da_iter2",
        "output": "depth_da_iter2_findings.md",
        "category": "da",
        "focus": (
            "Devil's Advocate iteration 2 for every Medium+ UNCERTAIN "
            "finding in confidence_scores.md; use evidence-only contrastive "
            "analysis and explore at least one untested path per finding"
        ),
    }]


def _finalize_depth_worker_pool_if_complete(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    jobs: list[dict[str, str]],
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
    pool_started: float,
    retry_reasons_by_output: dict[str, list[str]],
) -> int | None:
    """Return depth completion rc when no canonical depth jobs remain.

    Depth needs one extra finalization step beyond breadth/rescan: lifecycle
    artifacts and optional DA iteration may be required after the standard
    worker rows are complete. This helper makes both the top-of-loop and
    post-attempt completion paths identical, including the final retry.
    """
    if _depth_open_jobs(scratchpad, phase, jobs):
        return None
    _synthesize_depth_lifecycle_artifacts(
        scratchpad,
        str(config.get("pipeline", "sc")),
        force=False,
        mode=str(config.get("mode", "core")),
    )
    da_jobs = _depth_da_job_if_required(scratchpad, config)
    if da_jobs:
        rc, results = _run_depth_worker_batch(
            scratchpad=scratchpad,
            project_root=project_root,
            config=config,
            phase=phase,
            base_cmd=base_cmd,
            env=env,
            timeout=timeout,
            quiescence_s=quiescence_s,
            jobs=da_jobs,
            attempt=attempt,
            pool_started=pool_started,
            retry_reasons_by_output=retry_reasons_by_output,
        )
        if rc != 0:
            return rc
        if any(r.get("status") != "complete" for r in results):
            log.warning("[depth] DA worker did not complete")
            return -2
        _canonicalize_depth_iter_filenames(scratchpad)
    passed, missing = gate_passes(scratchpad, project_root, phase)
    if passed:
        return 0
    log.warning(f"[depth] worker-pool gate failed: {missing}")
    return -2


def _run_depth_worker_pool_pty(
    *,
    scratchpad: Path,
    project_root: str,
    config: dict,
    phase: Phase,
    base_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    quiescence_s: float,
    attempt: int,
) -> int:
    """Run depth as bounded top-level Claude PTY workers, one per artifact."""
    jobs = _depth_worker_jobs(scratchpad, config)
    if not jobs:
        log.warning("[depth] worker-pool unavailable: no depth jobs")
        return -2
    budget = int(config.get("pty_continuation_budget", 3))
    retry_reasons_by_output: dict[str, list[str]] = {}
    pool_started = time.time()
    try:
        (scratchpad / "_depth_worker_pool_contract.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "phase": "depth",
                    "pipeline": config.get("pipeline", "sc"),
                    "mode": config.get("mode", "core"),
                    "canonical_outputs": _depth_canonical_outputs(jobs),
                    "outputs": [str(job.get("output") or "") for job in jobs],
                    "jobs": jobs,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning(f"[depth] could not write worker-pool contract marker: {exc}")

    for pool_attempt in range(1, budget + 2):
        open_jobs = _depth_open_jobs(scratchpad, phase, jobs)
        if not open_jobs:
            rc = _finalize_depth_worker_pool_if_complete(
                scratchpad=scratchpad,
                project_root=project_root,
                config=config,
                phase=phase,
                jobs=jobs,
                base_cmd=base_cmd,
                env=env,
                timeout=timeout,
                quiescence_s=quiescence_s,
                attempt=pool_attempt,
                pool_started=pool_started,
                retry_reasons_by_output=retry_reasons_by_output,
            )
            if rc is not None:
                return rc
        if pool_attempt > budget + 1:
            break
        log.info(
            f"[depth] worker PTY pool attempt {pool_attempt}: "
            f"{len(open_jobs)} open row(s), concurrency={_DEPTH_WORKER_CONCURRENCY}"
        )
        rc, results = _run_depth_worker_batch(
            scratchpad=scratchpad,
            project_root=project_root,
            config=config,
            phase=phase,
            base_cmd=base_cmd,
            env=env,
            timeout=timeout,
            quiescence_s=quiescence_s,
            jobs=open_jobs,
            attempt=pool_attempt,
            pool_started=pool_started,
            retry_reasons_by_output=retry_reasons_by_output,
        )
        if rc != 0:
            if rc == -4:
                log.error("[depth] worker-pool containment violation")
            return rc
        retry_reasons_by_output = {
            str(r.get("output")): [
                f"status={r.get('status')}",
                *[str(x) for x in (r.get("reasons") or [])],
            ]
            for r in results
            if r.get("status") != "complete"
        }
        if not retry_reasons_by_output:
            _synthesize_depth_lifecycle_artifacts(
                scratchpad,
                str(config.get("pipeline", "sc")),
                force=False,
                mode=str(config.get("mode", "core")),
            )
        passed, missing = gate_passes(scratchpad, project_root, phase)
        if passed and not _depth_open_jobs(scratchpad, phase, jobs):
            rc = _finalize_depth_worker_pool_if_complete(
                scratchpad=scratchpad,
                project_root=project_root,
                config=config,
                phase=phase,
                jobs=jobs,
                base_cmd=base_cmd,
                env=env,
                timeout=timeout,
                quiescence_s=quiescence_s,
                attempt=pool_attempt,
                pool_started=pool_started,
                retry_reasons_by_output=retry_reasons_by_output,
            )
            if rc is not None:
                return rc
        log.info(
            f"[depth] worker-pool attempt {pool_attempt} incomplete: {missing}"
        )
    # Belt-and-suspenders: a fuzz job that produced no output after the retry
    # budget must NOT halt depth (fuzz is additive, non-blocking). Stub any
    # still-missing fuzz output with a TOOL_UNAVAILABLE degrade-continue
    # artifact and re-check. Scoped to category=='fuzz' ONLY — standard depth
    # jobs keep their strict completion.
    stubbed_any = _stub_missing_fuzz_outputs_on_exhaustion(scratchpad, phase, jobs)
    # Same class as fuzz: sibling propagation is additive/non-blocking, and
    # scanner jobs (never-cut FLOOR, not exit-on-crash) still must not hang
    # the pool forever on a crashed worker. Stub any still-missing
    # sibling/scanner output so a crashed worker cannot halt depth.
    if _stub_missing_sibling_outputs_on_exhaustion(scratchpad, phase, jobs):
        stubbed_any = True
    if stubbed_any:
        rc = _finalize_depth_worker_pool_if_complete(
            scratchpad=scratchpad,
            project_root=project_root,
            config=config,
            phase=phase,
            jobs=jobs,
            base_cmd=base_cmd,
            env=env,
            timeout=timeout,
            quiescence_s=quiescence_s,
            attempt=budget + 2,
            pool_started=pool_started,
            retry_reasons_by_output=retry_reasons_by_output,
        )
        if rc is not None:
            return rc
    log.warning("[depth] worker-pool retry budget exhausted")
    return -2


def _stub_missing_fuzz_outputs_on_exhaustion(
    scratchpad: Path,
    phase: Phase,
    jobs: list[dict[str, str]],
) -> bool:
    """Write a degrade-continue stub for any incomplete fuzz job after retries.

    Fuzz artifacts are additive and non-blocking; a worker that crashed before
    writing its output must not be allowed to halt depth. This writes a minimal
    `## Result Status: TOOL_UNAVAILABLE` artifact (with the COMPLETE marker) for
    each still-incomplete category=='fuzz' job and logs a warning. Returns True
    when at least one stub was written. Standard/scanner/sidecar/niche jobs are
    untouched.
    """
    wrote = False
    for job in jobs:
        if job.get("category") != "fuzz":
            continue
        if _depth_worker_output_complete(scratchpad, phase, job):
            continue
        output = str(job["output"])
        agent_id = str(job.get("agent_id", "fuzz"))
        path = scratchpad / output
        reason = "fuzz worker produced no output after all retry attempts"
        body = (
            f"<!-- PLAMEN_ARTIFACT: {output} -->\n"
            f"<!-- PLAMEN_OWNER: {agent_id} -->\n"
            f"<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
            f"<!-- PLAMEN_PHASE: depth -->\n"
            f"<!-- PLAMEN_VERSION: 1 -->\n"
            f"<!-- AGENT_ROW: {agent_id} -->\n"
            f"<!-- EXPECTED_OUTPUT: {output} -->\n\n"
            f"# Fuzz Campaign Results ({agent_id})\n\n"
            f"## Result Status: TOOL_UNAVAILABLE\n"
            f"Reason: {reason}.\n\n"
            f"## No Findings\n"
            f"The fuzz campaign did not execute, so no invariant violations "
            f"were produced. This is a non-blocking degrade-continue artifact: "
            f"fuzz results are additive only and never gate the depth phase.\n\n"
            f"<!-- PLAMEN_STATUS: COMPLETE -->\n"
        )
        try:
            path.write_text(body, encoding="utf-8")
            wrote = True
            log.warning(
                "[depth] fuzz job %s exhausted retries — wrote "
                "TOOL_UNAVAILABLE degrade-continue stub (%s)",
                agent_id, output,
            )
        except OSError as exc:
            log.warning(
                "[depth] could not write fuzz degrade stub %s: %s",
                output, exc,
            )
    return wrote


# ===========================================================================
# OpenGrep obligation sharding (Ship 7 of the supervision plan)
# ===========================================================================
#
# Pre-breadth, the driver shards `opengrep_findings.md` by breadth-agent
# focus area into per-agent files. Each subagent reads ONLY its assigned
# shard, so receipts are 1:1 with the file and obligation coverage rises
# from the historical ~12% (full opengrep_findings.md is 100+ rows; one
# subagent realistically receipts ~10-30 of them) toward 100% per shard.
#
# Routing policy is generic -- no protocol-specific filenames, counts, or
# rules. The mapping is driven by spawn_manifest.md focus-area names and
# the file paths embedded in opengrep_findings.md row Locations:
#
#   1. Tokenize the focus area name and the row's Location file path.
#   2. An agent matches the row when their focus-area tokens share any
#      token with the file-path tokens.
#   3. Rows that match >= 1 agent are DUPLICATED into each matching
#      shard with a `<!-- DEDUP_KEY: opengrep:<row> -->` marker so
#      global accounting still treats them as one row.
#   4. Rows that match ZERO agents land in `opengrep_obligations_UNASSIGNED.md`
#      AND also in the core_state fallback agent's shard, so no row
#      disappears from breadth scope entirely.
#
# Invariant: union of DEDUP_KEYs across all shards == set of row
# indices in opengrep_findings.md. Verified by
# `_check_opengrep_sharding_preservation`. The existing
# `_check_opengrep_obligation_coverage` keeps counting receipts by row
# number; cross-cutting receipts deduplicate naturally because both
# shards reference the same opengrep_findings.md row index.

_OPENGREP_DEDUP_KEY_PREFIX = "opengrep"
_OPENGREP_UNASSIGNED_FILENAME = "opengrep_obligations_UNASSIGNED.md"
_OPENGREP_SHARD_DEDUP_KEY_RE = re.compile(
    r"<!--\s*DEDUP_KEY:\s*" + _OPENGREP_DEDUP_KEY_PREFIX + r":(\d+)\s*-->"
)


def _opengrep_slugify_focus_area(focus: str) -> str:
    """Slugify a focus-area name for the shard filename.

    Lowercase, collapse non-[a-z0-9_] runs to underscores, trim
    leading/trailing underscores. ``""`` -> ``"unknown"`` so the
    filename is always well-formed.
    """
    if not focus:
        return "unknown"
    slug = re.sub(r"[^a-z0-9_]+", "_", str(focus).lower()).strip("_")
    return slug or "unknown"


def _opengrep_shard_filename(agent_id: str, focus_area: str) -> str:
    """Canonical per-agent shard filename. Single source of truth --
    the breadth Subagent Prompt Template (Ship 2) injects this exact
    name into Step 2 of each dispatch prompt, so the subagent reads
    the file the sharder wrote.
    """
    aid_slug = re.sub(r"[^A-Za-z0-9_]+", "_", str(agent_id or "unknown"))
    return (
        f"opengrep_obligations_{aid_slug}_"
        f"{_opengrep_slugify_focus_area(focus_area)}.md"
    )


# _parse_breadth_manifest_agents lives in plamen_parsers.py (where the
# manifest-table helpers it depends on already live). Imported via the
# `from plamen_parsers import *` line at the top of this module.


_OPENGREP_TABLE_ROW_RE = re.compile(
    r"^\|\s*(\d+)\s*\|(.+)\|\s*$"
)


def _parse_opengrep_rows(scratchpad: Path) -> list[dict[str, Any]]:
    """Parse opengrep_findings.md into a list of per-row dicts.

    Each row carries:

      - ``row_num``: int, 1-indexed matching the opengrep_findings.md
        row index (the same index receipts target via
        ``[OBLIG:opengrep_findings.md:<row_num>]``).
      - ``rule``, ``severity``, ``location``, ``message``: optional
        column strings extracted positionally.
      - ``file_path``: the file portion of ``location`` (strips
        line-number suffix).
      - ``raw``: original line text (for forensic dumps).

    Returns ``[]`` when the file is missing or has no data rows.
    """
    path = scratchpad / "opengrep_findings.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.rstrip()
        m = _OPENGREP_TABLE_ROW_RE.match(s)
        if not m:
            continue
        row_num = int(m.group(1))
        cells = [c.strip() for c in m.group(2).split("|")]
        # Positional column extraction. Opengrep tables vary across
        # audits; we name the common columns but tolerate shorter
        # rows. Anything beyond what we know is preserved in `raw`.
        rule = cells[0] if len(cells) > 0 else ""
        severity = cells[1] if len(cells) > 1 else ""
        location = cells[2] if len(cells) > 2 else ""
        message = cells[3] if len(cells) > 3 else ""
        # Strip line-number suffix (`Foo.sol:42` -> `Foo.sol`).
        file_path = location.rsplit(":", 1)[0] if location else ""
        rows.append({
            "row_num": row_num,
            "rule": rule,
            "severity": severity,
            "location": location,
            "file_path": file_path,
            "message": message,
            "raw": s,
        })
    return rows


_OPENGREP_PATH_TOKEN_SPLIT_RE = re.compile(r"[/\\._\-]+")
_OPENGREP_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokenize_path(file_path: str) -> set[str]:
    """Tokenize a file path for focus-area matching.

    Splits on path separators, dots, underscores, hyphens, AND
    camelCase boundaries (so ``CrossChainRouter.sol`` yields
    ``gateway``, ``cross``, ``chain``, ``sol``). Lowercase.
    """
    if not file_path:
        return set()
    tokens: set[str] = set()
    for raw in _OPENGREP_PATH_TOKEN_SPLIT_RE.split(file_path):
        if not raw:
            continue
        # Camel-split each fragment.
        for piece in _OPENGREP_CAMEL_SPLIT_RE.split(raw):
            piece = piece.strip().lower()
            if len(piece) >= 2:
                tokens.add(piece)
    return tokens


def _focus_area_tokens(focus: str) -> set[str]:
    """Tokenize a focus-area name on underscores + camelCase. Drops
    extremely short tokens (< 3 chars) that would over-match -- e.g.
    a focus area ``"ac"`` would otherwise match every file containing
    the letter pair somewhere.
    """
    if not focus:
        return set()
    out: set[str] = set()
    for raw in str(focus).lower().split("_"):
        raw = raw.strip()
        if not raw:
            continue
        for piece in _OPENGREP_CAMEL_SPLIT_RE.split(raw):
            piece = piece.strip().lower()
            if len(piece) >= 3:
                out.add(piece)
    return out


# Semantic routing buckets. Each canonical security-concern bucket
# maps to a set of keyword phrases scanned against the opengrep row's
# rule + message + location text. A row that matches a bucket routes
# to every agent whose focus-area name corresponds to that bucket
# (token overlap between focus_area and bucket name), IN ADDITION to
# file-path routing. This fixes the under-routing failure where an
# access-control finding in CrossChainRouter.sol routed only to the
# cross-chain agents because the FILENAME contained cross/chain --
# the access-control agent never saw it. Content-based routing is the
# PRIMARY signal; file-path is one additional signal.
#
# Keyword matching is token-subset based (not raw substring): each
# keyword phrase is normalized to a token set, and matches when ALL
# its tokens appear in the row's normalized token set. This avoids
# substring false positives like "eth" matching "method" while still
# catching camelCase identifiers ("onlyOwner" -> {only, owner}
# matches the "owner" keyword).
#
# No protocol-specific rules: buckets are named by generic security
# concerns and the agent->bucket correspondence is by focus-area name
# token overlap, so any audit whose breadth focus areas use these
# common names benefits automatically. Audits with bespoke focus
# areas simply fall through to file-path routing + UNASSIGNED/core.
_OPENGREP_SEMANTIC_BUCKETS: dict[str, tuple[str, ...]] = {
    "access_control": (
        "owner", "admin", "role", "auth", "permission", "privileged",
        "onlyowner", "setter", "trusted", "caller", "msg.sender",
    ),
    "storage_layout": (
        "storage", "slot", "layout", "collision", "proxy", "delegatecall",
    ),
    "migration": (
        "init", "initialize", "reinitializer", "upgrade", "migration",
        "constructor",
    ),
    "token_flow": (
        "transfer", "approve", "allowance", "token", "native", "eth",
        "value", "balance", "swap", "amount",
    ),
    "cross_chain_msg": (
        "gateway", "oncall", "onrevert", "payload", "message", "sender",
        "receiver", "cross-chain", "crosschain",
    ),
    "cross_chain_timing": (
        "deadline", "timestamp", "expiry", "stale", "replay", "nonce",
        "ordering", "finality", "delay",
    ),
    "centralization": (
        "pause", "upgrade", "trusted", "multisig", "custody", "owner",
        "authority",
    ),
    "core_state": (
        "invariant", "accounting", "fee", "config", "precondition",
        "fallback",
    ),
}


def _normalize_text_to_tokens(*texts: str) -> set[str]:
    """Tokenize prose (rule + message + location) for semantic-bucket
    matching. Joins inputs, splits on non-alphanumeric AND camelCase
    boundaries, lowercases, keeps tokens >= 2 chars.

    ``setOwner lacks onlyOwner`` -> ``{set, owner, lacks, only}`` so
    the ``owner`` keyword matches via token-subset, while ``method``
    -> ``{method}`` does NOT spuriously match the ``eth`` keyword.
    """
    joined = " ".join(t for t in texts if t)
    if not joined:
        return set()
    tokens: set[str] = set()
    for raw in re.split(r"[^A-Za-z0-9]+", joined):
        if not raw:
            continue
        for piece in _OPENGREP_CAMEL_SPLIT_RE.split(raw):
            piece = piece.strip().lower()
            if len(piece) >= 2:
                tokens.add(piece)
    return tokens


# Precompute each bucket's keyword token-sets once at import.
_OPENGREP_BUCKET_KEYWORD_TOKENS: dict[str, list[set[str]]] = {
    bucket: [
        toks
        for kw in kws
        for toks in (_normalize_text_to_tokens(kw),)
        if toks
    ]
    for bucket, kws in _OPENGREP_SEMANTIC_BUCKETS.items()
}


def _row_semantic_buckets(row: dict[str, Any]) -> set[str]:
    """Return the set of semantic-concern buckets a row matches based
    on its rule + message + location text. A bucket matches when ANY
    of its keyword token-sets is a subset of the row's token set.
    """
    row_tokens = _normalize_text_to_tokens(
        row.get("rule", ""),
        row.get("message", ""),
        row.get("location", ""),
    )
    if not row_tokens:
        return set()
    matched: set[str] = set()
    for bucket, kw_token_sets in _OPENGREP_BUCKET_KEYWORD_TOKENS.items():
        for kw_tokens in kw_token_sets:
            if kw_tokens <= row_tokens:
                matched.add(bucket)
                break
    return matched


def _match_agents_for_row(
    row: dict[str, Any], agents: list[dict[str, str]]
) -> list[dict[str, str]]:
    """Return agents that should see this opengrep row.

    Two routing signals, unioned (conservative over-routing -- a row
    matching multiple agents goes to ALL of them; cross-cutting
    receipts dedupe by row index):

      Signal A (PRIMARY, content-based): the row's rule + message +
        location text matches one or more semantic-concern buckets
        (see ``_OPENGREP_SEMANTIC_BUCKETS``). The row routes to every
        agent whose focus-area name shares a token with a matched
        bucket name. This is what gets an access-control finding in
        CrossChainRouter.sol to the access_control agent even though
        the filename screams cross-chain.

      Signal B (file path, ONE additional signal): the agent's
        focus-area tokens intersect the row's location file-path
        tokens. Retained because some rows carry no descriptive text
        but their file clearly belongs to a focus area.

    Returns an empty list when neither signal matches -- the caller
    routes such rows to UNASSIGNED + core_state.
    """
    file_tokens = _tokenize_path(row.get("file_path", ""))
    semantic_buckets = _row_semantic_buckets(row)

    matches: list[dict[str, str]] = []
    seen: set[str] = set()
    for a in agents:
        focus_tokens = _focus_area_tokens(a.get("focus_area", ""))
        matched = False
        # Signal A: semantic bucket correspondence.
        if semantic_buckets and focus_tokens:
            for bucket in semantic_buckets:
                if focus_tokens & _focus_area_tokens(bucket):
                    matched = True
                    break
        # Signal B: file-path token overlap (one signal, not the main one).
        if not matched and file_tokens and (focus_tokens & file_tokens):
            matched = True
        if matched:
            aid = a.get("agent_id", "")
            if aid not in seen:
                seen.add(aid)
                matches.append(a)
    return matches


def _identify_core_state_agent(
    agents: list[dict[str, str]],
) -> Optional[dict[str, str]]:
    """Identify the fallback agent for unassigned opengrep rows.

    Preference order (no protocol-specific names; matches common
    plamen-audit conventions):

      1. ``focus_area`` lowercased == ``"core_state"``
      2. ``focus_area`` lowercased starts with ``"core_state"``
      3. ``focus_area`` lowercased contains ``"core"``
      4. First agent in the manifest
      5. ``None`` if the manifest is empty (the sharder no-ops in
         that case)
    """
    if not agents:
        return None
    by_focus_lc = [
        (a, str(a.get("focus_area", "")).lower()) for a in agents
    ]
    for a, focus_lc in by_focus_lc:
        if focus_lc == "core_state":
            return a
    for a, focus_lc in by_focus_lc:
        if focus_lc.startswith("core_state"):
            return a
    for a, focus_lc in by_focus_lc:
        if "core" in focus_lc:
            return a
    return agents[0]


def _format_opengrep_shard_row(row: dict[str, Any]) -> str:
    """Format a single sharded opengrep row with its DEDUP_KEY tag.
    The DEDUP_KEY references the row index in the ORIGINAL
    opengrep_findings.md so a row duplicated across shards still
    counts as ONE row globally.
    """
    rule = (row.get("rule") or "").replace("|", "\\|")
    severity = (row.get("severity") or "").replace("|", "\\|")
    location = (row.get("location") or "").replace("|", "\\|")
    message = (row.get("message") or "").replace("|", "\\|")
    row_num = int(row.get("row_num", 0))
    dedup_tag = (
        f"<!-- DEDUP_KEY: {_OPENGREP_DEDUP_KEY_PREFIX}:{row_num} -->"
    )
    return (
        f"| {row_num} | {rule} | {severity} | {location} | "
        f"{message} {dedup_tag} |"
    )


def _write_opengrep_shard_file(
    path: Path,
    *,
    owner_id: str,
    focus_area: str,
    rows: list[dict[str, Any]],
    unassigned: bool = False,
) -> None:
    """Write one obligation shard file. Deterministic output (same
    inputs -> identical bytes) so the sharder is idempotent."""
    lines: list[str] = []
    lines.append("# OpenGrep Obligation Shard")
    lines.append("")
    # Ship 8.3 namespace hygiene: shard metadata uses the OPENGREP_SHARD_*
    # namespace, NOT PLAMEN_*. The PLAMEN_* prefix is reserved for artifact
    # lifecycle markers (STATUS / FINDINGS_COUNT / ARTIFACT) that the gate
    # reads. A breadth agent that reads its shard (per the Subagent Prompt
    # Template) previously copied PLAMEN_SHARD_OWNER/FOCUS into its own
    # analysis header (observed: storage_layout/B6 in a prior run),
    # contaminating the lifecycle namespace. Keeping shard metadata out of
    # PLAMEN_* removes that contamination vector.
    lines.append(f"<!-- OPENGREP_SHARD_OWNER: {owner_id} -->")
    lines.append(f"<!-- OPENGREP_SHARD_FOCUS: {focus_area} -->")
    if unassigned:
        lines.append("<!-- OPENGREP_SHARD_KIND: UNASSIGNED -->")
    lines.append("")
    if unassigned:
        lines.append(
            "This file collects opengrep rows whose Location file did "
            "not match any breadth agent's focus area. These rows are "
            "ALSO routed to the core_state agent's shard so they do "
            "not disappear from breadth scope; this file exists as a "
            "forensic record."
        )
    else:
        lines.append(
            "This file is a deterministic subset of "
            f"`opengrep_findings.md` for breadth agent `{owner_id}` "
            f"(focus area: `{focus_area}`). Each row carries a "
            "`<!-- DEDUP_KEY: opengrep:<row> -->` tag referencing the "
            "row index in the original opengrep_findings.md, so "
            "cross-cutting rows that appear in multiple shards still "
            "count as a single row in global accounting."
        )
    lines.append("")
    if not rows:
        lines.append("_(no opengrep rows assigned)_")
        lines.append("")
    else:
        lines.append("| Row | Rule | Severity | Location | Notes |")
        lines.append("| --- | --- | --- | --- | --- |")
        for r in rows:
            lines.append(_format_opengrep_shard_row(r))
        lines.append("")
    body = "\n".join(lines) + "\n"
    try:
        path.write_text(body, encoding="utf-8")
    except Exception as exc:
        log.warning(
            f"[opengrep-shard] failed to write {path.name}: {exc}"
        )


def shard_opengrep_obligations(
    scratchpad: Path,
) -> dict[str, dict[str, Any]]:
    """Shard ``opengrep_findings.md`` into per-agent obligation files
    plus an ``opengrep_obligations_UNASSIGNED.md`` collector.

    Ship 7 of the artifact-complete PTY supervision plan.

    Returns a mapping ``{owner_id: {"shard_path": str, "row_count": int}}``
    where ``owner_id`` is either an agent_id from spawn_manifest.md or
    the literal ``"UNASSIGNED"`` key. Returns ``{}`` when there is
    nothing to shard (no manifest agents OR no opengrep rows).

    Side effect: writes (or overwrites) the shard files on disk. The
    operation is idempotent -- calling twice with the same scratchpad
    state produces byte-identical files.

    Routing invariant: ``set(DEDUP_KEYs across all shards) ==
    set(row indices in opengrep_findings.md)``. Verified by
    ``_check_opengrep_sharding_preservation``.
    """
    agents = parse_breadth_manifest_agents(scratchpad)
    if not agents:
        return {}
    rows = _parse_opengrep_rows(scratchpad)
    if not rows:
        return {}

    core_agent = _identify_core_state_agent(agents)
    shards: dict[str, list[dict[str, Any]]] = {
        a["agent_id"]: [] for a in agents
    }
    unassigned_rows: list[dict[str, Any]] = []

    for row in rows:
        matches = _match_agents_for_row(row, agents)
        if matches:
            for a in matches:
                shards[a["agent_id"]].append(row)
        else:
            unassigned_rows.append(row)
            if core_agent is not None:
                shards[core_agent["agent_id"]].append(row)

    result: dict[str, dict[str, Any]] = {}
    for a in agents:
        aid = a["agent_id"]
        path = scratchpad / _opengrep_shard_filename(aid, a["focus_area"])
        _write_opengrep_shard_file(
            path,
            owner_id=aid,
            focus_area=a["focus_area"],
            rows=shards[aid],
            unassigned=False,
        )
        result[aid] = {
            "shard_path": str(path),
            "row_count": len(shards[aid]),
        }

    unassigned_path = scratchpad / _OPENGREP_UNASSIGNED_FILENAME
    _write_opengrep_shard_file(
        unassigned_path,
        owner_id="UNASSIGNED",
        focus_area="unassigned",
        rows=unassigned_rows,
        unassigned=True,
    )
    result["UNASSIGNED"] = {
        "shard_path": str(unassigned_path),
        "row_count": len(unassigned_rows),
    }
    return result


def _check_opengrep_sharding_preservation(
    scratchpad: Path,
) -> list[str]:
    """Verify that the union of DEDUP_KEYs across all shards equals
    the set of row indices in ``opengrep_findings.md``.

    Returns a list of issues (empty -> preservation holds). The
    UNASSIGNED file is included in the union because unassigned rows
    are routed there alongside the core_state shard; even if the
    core_state shard somehow lacks them, the UNASSIGNED file still
    provides the row.

    Vacuous-pass when there's nothing to compare (no opengrep_findings.md
    OR no shards on disk -- typical for non-supervised phases).
    """
    rows = _parse_opengrep_rows(scratchpad)
    if not rows:
        return []
    expected = {r["row_num"] for r in rows}

    seen: set[int] = set()
    shard_count = 0
    for path in scratchpad.glob("opengrep_obligations_*.md"):
        shard_count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in _OPENGREP_SHARD_DEDUP_KEY_RE.finditer(text):
            try:
                seen.add(int(m.group(1)))
            except ValueError:
                continue
    if shard_count == 0:
        return []

    missing = sorted(expected - seen)
    if not missing:
        return []
    sample = ", ".join(str(r) for r in missing[:12])
    if len(missing) > 12:
        sample += f", ... (+{len(missing) - 12} more)"
    return [
        f"opengrep sharding preservation: {len(missing)} row(s) from "
        f"opengrep_findings.md absent from every shard (missing rows: "
        f"{sample})"
    ]


# ===========================================================================
# Fresh-audit marker sentinel (Ship 8.1)
# ===========================================================================
#
# `scratchpad_is_fresh_audit()` (plamen_validators) gates the strict
# marker contract: only when `_audit_started_with_markers.json` is present
# do the breadth/depth gates require COMPLETE markers and continue
# IN_PROGRESS artifacts. Without a WRITER, every production audit would
# look like a legacy/resumed scratchpad and the strict gates would never
# activate -- the contract would be inert outside tests. This writer
# closes that gap: it plants the sentinel for brand-new audits before the
# first (recon) phase runs.


def _read_driver_version() -> str:
    """Best-effort driver version from ``plamen_home()/VERSION``.
    Returns ``"unknown"`` when the file is absent or unreadable -- the
    sentinel's version field is informational, not load-bearing.
    """
    try:
        return (plamen_home() / "VERSION").read_text(
            encoding="utf-8"
        ).strip() or "unknown"
    except Exception:
        return "unknown"


def _ensure_fresh_audit_sentinel(scratchpad: Path, config: dict) -> str:
    """Plant the fresh-audit marker sentinel for brand-new audits.

    Ship 8.1. Returns one of:

      - ``"exists"``      -- sentinel already present; left untouched
                             (idempotent; a resumed post-marker audit
                             stays fresh).
      - ``"legacy-skip"`` -- a ``_v2_checkpoint.json`` already exists but
                             no sentinel: this is a resume of a
                             pre-marker audit, so we intentionally do NOT
                             write the sentinel and the audit stays in
                             legacy marker mode (no retroactive
                             tightening of an in-flight audit).
      - ``"written"``     -- brand-new audit (no checkpoint, no sentinel):
                             sentinel created so the strict marker gates
                             activate.

    Raises ``OSError`` when the brand-new write fails. The caller MUST
    convert that to a hard startup exit: silently proceeding would
    degrade every strict marker gate to legacy mode, which is exactly
    the failure this writer exists to prevent.

    Idempotent and side-effect-free except for the single brand-new
    write. Detection hinges on the checkpoint file because
    ``Checkpoint.save`` plants ``_v2_checkpoint.json`` only after this
    helper runs on a fresh start, so its presence here means a prior
    run created it (resume).
    """
    sentinel = scratchpad / _AUDIT_FRESH_SENTINEL_NAME
    if sentinel.exists():
        return "exists"
    checkpoint_file = scratchpad / "_v2_checkpoint.json"
    if checkpoint_file.exists():
        return "legacy-skip"
    payload = {
        "schema_version": 1,
        "started_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "driver_version": _read_driver_version(),
        "mode": config.get("mode", ""),
        "pipeline": config.get("pipeline", ""),
    }
    # No try/except: a write failure must propagate so main() can hard-exit.
    sentinel.write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    return "written"


def _assert_methodology_reachable(config: dict) -> None:
    """Loud preflight: refuse to run blind if the methodology tree is not
    reachable for the configured backend.

    Closes the Codex-only / missing-~/.claude loophole where the driver would
    otherwise launch agents against non-existent rule/prompt paths and silently
    produce an empty or degraded audit. Fails fast with an actionable message.
    """
    root = plamen_home()
    backend = (config.get("cli_backend") or "claude").lower()
    problems: list[str] = []
    if not root.exists():
        problems.append(f"methodology root does not exist: {root}")
    else:
        rules = root / "rules"
        sentinel = rules / "finding-output-format.md"
        if not rules.is_dir():
            problems.append(f"missing rules dir: {rules}")
        else:
            try:
                ok = sentinel.exists() and bool(
                    sentinel.read_text(encoding="utf-8", errors="replace").strip()
                )
            except Exception:
                ok = False
            if not ok:
                problems.append(f"missing/empty sentinel rule: {sentinel}")
        if not (root / "prompts").is_dir():
            problems.append(f"missing prompts dir: {root / 'prompts'}")
    if backend == "codex":
        codex_home = Path.home() / ".codex" / "plamen"
        if not codex_home.is_dir():
            problems.append(
                f"Codex backend selected but {codex_home} is not linked — run "
                f"`plamen install --codex` (or toggle 'Codex' in `plamen setup`)"
            )
    if problems:
        log.error("[startup] methodology preflight FAILED — refusing to run blind:")
        for p in problems:
            log.error(f"  - {p}")
        print(
            "\nPlamen cannot start: methodology files are not reachable.\n  "
            + "\n  ".join(problems)
            + "\n\nFix the install (`plamen setup`, or `plamen install --codex` "
            "for the Codex backend) and retry.\n",
            file=sys.stderr,
        )
        sys.exit(EXIT_CONFIG_MISSING)


def _ensure_rule_files_materialized() -> list[str]:
    """Repair empty active rule files from bundled `.pre-plamen` backups.

    Some installations expose `~/.codex/plamen/rules/*.md` as symlinks to a
    shared `~/.plamen/rules` tree. If the target files are empty, agents still
    receive a valid path but lose the methodology content. The backups in this
    package are the canonical fallback, so materialize them before phase prompts
    can ask agents to read the empty files.
    """
    rules = plamen_home() / "rules"
    repaired: list[str] = []
    if not rules.exists():
        log.warning(
            f"[startup] rules dir not found at {rules} — methodology may be "
            f"unavailable (preflight gate will verify)"
        )
        return repaired
    for backup in sorted(rules.glob("*.pre-plamen")):
        active = backup.with_name(backup.name[:-len(".pre-plamen")])
        try:
            if not active.exists() or active.read_text(encoding="utf-8", errors="replace").strip():
                continue
            text = backup.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            active.write_text(text, encoding="utf-8")
            repaired.append(active.name)
        except Exception as exc:
            log.warning(
                f"[startup] rule-file materialization skipped for "
                f"{active.name}: {exc!r}"
            )
    return repaired


def _run_one_codex_exec(
    *,
    prompt: str,
    phase: Phase,
    config: dict,
    scratchpad: Path,
    attempt: int,
    label: str,
    expected_outputs: list[str],
    timeout: float,
    effective_model: str,
) -> int:
    """Run ONE `codex exec` subprocess for a single prompt → artifact set.

    Factored verbatim from the inline single-subprocess codex block in
    run_phase so the behavior is identical when *label* == phase.name (the
    existing single-subprocess path), and reusable once-per-job by the depth
    fan-out (*label* == per-job agent id).

    The helper is self-contained: it resolves auth, checks prompt fit, builds
    the codex cmd (with the `_codex_skip_model` ChatGPT-auth fallback), seeds
    the expected output files (apply_patch cannot create files), snapshots the
    prompt as the stdin source, runs Popen with the heartbeat waiter, mirrors
    the per-label log into the canonical `_stdio_{phase}.log` so the outer
    driver's model-rejection/capacity/auth detectors keep working, and records
    phase cost + orphan diagnostics.

    Returns the subprocess rc (>=0 normal exit, -2 timeout, EXIT_ERROR on a
    pre-spawn failure such as missing binary / auth / Popen error).
    """
    if not CODEX_BIN:
        log.error(f"[{label}] cli_backend=codex but codex binary not found")
        return EXIT_ERROR
    if not _codex_auth_available():
        log.error(
            f"[{label}] Codex auth not found — `codex exec` will hang "
            f"waiting for interactive login. Run `codex login` first, or set "
            f"CODEX_API_KEY / OPENAI_API_KEY."
        )
        return EXIT_ERROR
    if not _codex_prompt_fits(prompt, effective_model):
        est_tokens = len(prompt) // 4
        limit = _CODEX_CONTEXT_LIMITS.get(effective_model, 272_000)
        log.warning(
            f"[{label}] prompt ~{est_tokens:,} tokens may exceed "
            f"{effective_model} context ({limit:,} tokens). "
            f"Codex hard-errors on context exceed (no silent truncation)."
        )

    # Pre-create the expected artifact files so Codex's apply_patch (which
    # cannot create new files) has valid targets.
    def _seed(name: str) -> None:
        target = scratchpad / name
        if not target.exists():
            try:
                target.write_text("", encoding="utf-8")
            except OSError:
                pass

    for name in expected_outputs:
        _seed(name)

    # Snapshot the prompt — doubles as the subprocess stdin source (v2.1.3).
    snap = scratchpad / f"_prompt_{label}.attempt{attempt}.md"
    try:
        snap.write_text(prompt, encoding="utf-8")
    except Exception as e:
        log.error(
            f"[{label}] prompt snapshot failed: {e} — cannot spawn "
            f"subprocess (snapshot is the stdin source)"
        )
        return EXIT_ERROR

    olm_path = str(scratchpad / f"_codex_output_{label}.attempt{attempt}.md")
    codex_writable = [
        scratchpad.as_posix(),
        Path(config["project_root"]).as_posix(),
    ]
    if config.get("_codex_skip_model"):
        cmd = _build_codex_cmd_no_model(
            needs_mcp=phase.needs_mcp,
            output_last_message=olm_path,
            writable_dirs=codex_writable,
        )
    else:
        cmd = _build_codex_cmd(
            effective_model, needs_mcp=phase.needs_mcp,
            output_last_message=olm_path,
            writable_dirs=codex_writable,
        )

    log_path = scratchpad / f"_stdio_{label}.attempt{attempt}.log"
    canonical = scratchpad / f"_stdio_{phase.name}.log"

    subprocess_env = {
        **_filtered_child_subprocess_environ(),
        "ANTHROPIC_DISABLE_AUTOUPDATE": "1",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": PLAMEN_OPUS_MODEL,
        "PLAMEN_SCRATCHPAD": str(scratchpad),
        "BASH_MAX_OUTPUT_LENGTH": os.environ.get(
            "BASH_MAX_OUTPUT_LENGTH", "30000"
        ),
        "MAX_MCP_OUTPUT_TOKENS": os.environ.get(
            "MAX_MCP_OUTPUT_TOKENS", "8000"
        ),
    }
    popen_kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        popen_kwargs["start_new_session"] = True

    _cli_label = "codex exec"
    log.info(
        f"[{label}] spawning {_cli_label} (model={effective_model}, "
        f"timeout={timeout}s, attempt={attempt})"
    )
    start = time.time()

    with log_path.open("w", encoding="utf-8", errors="replace") as out, \
            snap.open("rb") as stdin_file:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_file, stdout=out, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                cwd=config["project_root"],
                env=subprocess_env,
                **popen_kwargs,
            )
        except Exception as e:
            log.error(f"[{label}] Popen failed: {e}")
            try:
                out.write(f"Popen failed before subprocess start: {e}\n")
                out.flush()
            except Exception:
                pass
            try:
                canonical.write_text(
                    log_path.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8",
                    errors="replace",
                )
            except Exception:
                pass
            return EXIT_ERROR

        try:
            # Behavior parity with the single-subprocess path: a whole-phase
            # codex breadth run keeps manifest-complete early termination
            # (label==phase.name guards against depth fan-out sub-jobs, whose
            # label is depth_worker_* and which must run to natural exit).
            early_complete = None
            if phase.name == "breadth" and label == phase.name:
                early_complete = lambda: _breadth_manifest_complete_reason(
                    scratchpad, phase
                )
            rc = _wait_with_heartbeat(
                proc, timeout, scratchpad, phase.name, start,
                _live_protected_phase_write_patterns(
                    scratchpad,
                    str(config.get("pipeline", "sc")),
                    phase.name,
                    config.get("_active_phase_names"),
                ),
                early_complete=early_complete,
            )
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc, grace_s=10)
            log.warning(f"[{label}] timed out after {timeout}s")
            rc = -2  # timeout sentinel

    # Mirror per-label stdio into the canonical phase log so the outer
    # driver's codex model-rejection / capacity / auth detectors (which read
    # _stdio_{phase}.log) keep working. For the single-subprocess path
    # (label == phase.name) this is the same byte content as before. For the
    # depth fan-out it accumulates per-job output across jobs.
    try:
        if label == phase.name:
            canonical.write_bytes(log_path.read_bytes())
        else:
            with canonical.open("ab") as agg:
                agg.write(f"\n\n# {log_path.name}\n".encode("utf-8"))
                agg.write(log_path.read_bytes())
    except Exception:
        pass

    duration = time.time() - start
    log.info(f"[{label}] codex exec exited rc={rc} after {duration:.0f}s")
    _record_phase_cost(scratchpad, label, effective_model, attempt,
                       log_path, duration, backend="codex")
    try:
        diag = detect_background_orphan(
            log_path, scratchpad, phase.name,
            config.get("mode", "core"),
            config.get("pipeline", "sc"),
            rc, backend="codex",
            project_root=config.get("project_root"),
        )
        if diag:
            _archive_orphan_stubs(scratchpad, phase.name, diag)
    except Exception as e:
        log.debug(f"[{label}] orphan diagnostic skipped: {e}")
    return rc


def _should_use_depth_codex_fanout(config: dict, scratchpad: Path) -> bool:
    """Return True when the Codex depth phase should fan out per artifact.

    Mirrors the spirit of `_should_use_depth_worker_pool` (the Claude PTY
    worker pool) WITHOUT the is_claude_pty requirement: True iff the backend
    is codex, the phase is depth, and `_depth_worker_jobs` yields more than
    one job (real fan-out to do — core/thorough, both pipelines). Codex's
    single `codex exec` turn under-fans-out and leaves never-cut scanners as
    0-byte stubs; running one `codex exec` per job restores parity with the
    proven Claude worker pool.
    """
    if config.get("cli_backend", "claude") != "codex":
        return False
    try:
        return len(_depth_worker_jobs(scratchpad, config)) > 1
    except Exception:
        return False


def _run_depth_codex_fanout(
    *, phase: Phase, config: dict, scratchpad: Path, attempt: int
) -> int:
    """Run depth as ONE `codex exec` per depth JOB (Codex fan-out parity).

    Mirrors the Claude PTY depth worker pool job decomposition so every
    never-cut artifact (the 4 core role findings + blind_spot_a/b/c +
    validation_sweep + design_stress + perturbation + skill_execution_gaps +
    niche agents + confidence) is produced by its own bounded subprocess
    instead of being dropped when a single mega-turn runs out. RECALL-
    PRESERVING: the scanners actually run, so the depth never-cut gate (run
    by the validator after run_phase) passes legitimately on real artifacts.
    Resume-safe + idempotent: jobs whose output is already substantive are
    skipped.
    """
    jobs = _depth_worker_jobs(scratchpad, config)
    if not jobs:
        log.warning("[depth] codex fan-out unavailable: no depth jobs")
        return EXIT_ERROR

    pipeline = str(config.get("pipeline", "sc"))
    mode = str(config.get("mode", "core"))

    # Write the same observability contract the PTY pool writes.
    try:
        (scratchpad / "_depth_worker_pool_contract.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "phase": "depth",
                    "backend": "codex-fanout",
                    "pipeline": pipeline,
                    "mode": mode,
                    "canonical_outputs": _depth_canonical_outputs(jobs),
                    "outputs": [str(job.get("output") or "") for job in jobs],
                    "jobs": jobs,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning(
            f"[depth] could not write codex fan-out contract marker: {exc}"
        )

    effective_model = phase_model(phase, config["mode"], config)
    timeout = scale_timeout(
        phase.base_timeout_s, config["project_root"], config["language"],
        mode=config.get("mode"), backend="codex",
    )

    log.info(
        f"[depth] codex fan-out: {len(jobs)} job(s) "
        f"(one `codex exec` per artifact)"
    )

    hard_failure_rc: int | None = None
    for job in jobs:
        output = str(job["output"])
        agent_id = str(job.get("agent_id") or Path(output).stem)
        # Resume-safe: skip jobs whose output is already substantive.
        if _depth_worker_output_complete(scratchpad, phase, job):
            log.info(f"[depth] codex fan-out: skip complete job {output}")
            continue

        def _exec_job(attempt_n: int, reasons: list[str] | None) -> int:
            prompt = _build_depth_worker_prompt(
                job=job,
                scratchpad=scratchpad,
                project_root=config["project_root"],
                config=config,
                attempt=attempt_n,
                retry_reasons=reasons,
            )
            prompt = _translate_prompt_for_codex(
                prompt, phase_name="depth",
                pipeline=pipeline, mode=mode, scratchpad=scratchpad,
            )
            return _run_one_codex_exec(
                prompt=prompt,
                phase=phase,
                config=config,
                scratchpad=scratchpad,
                attempt=attempt_n,
                label=f"depth_worker_{agent_id}",
                expected_outputs=[output],
                timeout=timeout,
                effective_model=effective_model,
            )

        rc = _exec_job(attempt, None)
        # A hard codex/auth/binary failure propagates so the outer driver can
        # apply its model-rejection / capacity / auth handling on the
        # canonical log. A successful-but-stub output gets ONE per-job retry.
        if rc == EXIT_ERROR:
            hard_failure_rc = EXIT_ERROR
            break
        if not _depth_worker_output_complete(scratchpad, phase, job):
            log.info(
                f"[depth] codex fan-out: job {output} still incomplete "
                f"after attempt {attempt}; one per-job retry"
            )
            rc = _exec_job(
                attempt + 1, [f"status=incomplete", f"output={output}"]
            )
            if rc == EXIT_ERROR:
                hard_failure_rc = EXIT_ERROR
                break

    # Synthesize lifecycle/scoring artifacts from disk once, mirroring the
    # PTY pool's call when no retry reasons remain.
    try:
        _synthesize_depth_lifecycle_artifacts(
            scratchpad, pipeline, force=False, mode=mode,
        )
    except Exception as exc:
        log.warning(f"[depth] codex fan-out lifecycle synth skipped: {exc!r}")

    # ── DA iteration 2 (Devil's Advocate) — scheduled AFTER confidence is
    # finalized ──
    # Mirrors the Claude PTY pool sequence (_run_depth_worker_pool ->
    # synth -> _depth_da_job_if_required -> run). The DA job is gated on
    # confidence_scores.md having uncertain Medium+ findings; at job-list
    # build time (top of this function) that file did not yet exist, so on
    # Codex the adversarial second pass was NEVER scheduled and the depth gate
    # degraded on the missing iter2 artifact. The lifecycle synth above just
    # (re)computed REAL per-finding confidence (replacing any formulaic stub),
    # so re-evaluate now and actually run iter2. Thorough-only (helper gates
    # on mode). Uses the same prompt builder as the PTY pool, which handles
    # the `da_iter2` role.
    if hard_failure_rc is None:
        try:
            da_jobs = _depth_da_job_if_required(scratchpad, config)
        except Exception as exc:
            log.warning(
                f"[depth] codex fan-out: DA iter2 scheduling skipped: {exc!r}"
            )
            da_jobs = []
        for da_job in da_jobs:
            da_output = str(da_job["output"])
            da_agent_id = str(da_job.get("agent_id") or Path(da_output).stem)
            if _depth_worker_output_complete(scratchpad, phase, da_job):
                continue
            log.info(f"[depth] codex fan-out: DA iter2 job {da_output}")

            def _exec_da_job(attempt_n: int, reasons: list[str] | None,
                             _job: dict = da_job, _aid: str = da_agent_id,
                             _out: str = da_output) -> int:
                prompt = _build_depth_worker_prompt(
                    job=_job, scratchpad=scratchpad,
                    project_root=config["project_root"], config=config,
                    attempt=attempt_n, retry_reasons=reasons,
                )
                prompt = _translate_prompt_for_codex(
                    prompt, phase_name="depth", pipeline=pipeline, mode=mode,
                    scratchpad=scratchpad,
                )
                return _run_one_codex_exec(
                    prompt=prompt, phase=phase, config=config,
                    scratchpad=scratchpad, attempt=attempt_n,
                    label=f"depth_worker_{_aid}", expected_outputs=[_out],
                    timeout=timeout, effective_model=effective_model,
                )

            rc = _exec_da_job(attempt, None)
            if rc == EXIT_ERROR:
                hard_failure_rc = EXIT_ERROR
                break
            if not _depth_worker_output_complete(scratchpad, phase, da_job):
                rc = _exec_da_job(
                    attempt + 1, ["status=incomplete", f"output={da_output}"]
                )
                if rc == EXIT_ERROR:
                    hard_failure_rc = EXIT_ERROR
                    break
        if da_jobs and hard_failure_rc is None:
            # Mirror the PTY pool: normalize iter2 filenames + re-synth so
            # confidence reflects the iter2 evidence (monotonic; recompute
            # only if still stub/missing).
            try:
                _canonicalize_depth_iter_filenames(scratchpad)
            except Exception:
                pass
            try:
                _synthesize_depth_lifecycle_artifacts(
                    scratchpad, pipeline, force=False, mode=mode,
                )
            except Exception:
                pass

    if hard_failure_rc is not None:
        return hard_failure_rc
    # Let the existing depth gate (validator after run_phase) judge overall
    # completeness — it now sees real artifacts, not stubs.
    return 0


def _axis_coverage_has_no_gaps(scratchpad: Path) -> bool:
    """Pre-spawn skip-when-clean signal for phase `axis_coverage` (M2, Phase 4b.8).

    Runs the mechanical hot-function ranking + `function × axis` matrix build
    FIRST (persisting hot_function_axes.md + _hot_function_axes.json for
    visibility), then reports whether ANY GAP cell exists. Returns True (skip the
    LLM spawn) ONLY when the matrix has zero GAP cells — every hot function was
    already examined on every in-scope axis, or the axis is a provable N/A.

    Conservative on failure: returns False (do NOT skip) so a real gap set is
    never silently dropped — recall over cost. The phase is soft, so a spurious
    spawn only wastes one sonnet turn. The ambiguous-⇒-GAP default inside
    compute_axis_coverage_gaps means the matrix over-reports gaps rather than
    under-reporting them, so a True return is a genuine all-clear.
    """
    try:
        import enumeration_gate as _eg
        gaps = _eg.compute_axis_coverage_gaps(Path(scratchpad))
        return not gaps
    except Exception:
        return False


# --- Core ---
def run_phase(phase: Phase, config: dict, attempt: int) -> int:
    """Spawn the configured CLI backend for one phase.

    Claude's default path is interactive PTY, not ``claude -p``. The
    subscription-preserving supervised phases recover with fresh
    missing-only interactive PTY sessions when disk gates reject a turn.
    """
    scratchpad = Path(config["scratchpad"])

    # Generic recovery/discovery sidecars. These are deterministic, bounded,
    # and never phase outputs. They provide compact audit contracts to phases
    # that benefit from them without introducing another coordinator session.
    if phase.name in {"depth", "attention_repair", "report_index"}:
        try:
            obligation_count = _write_security_obligations(
                scratchpad, config.get("mode", "core")
            )
            if obligation_count and phase.name == "depth":
                log.info(
                    f"[depth] security_obligations.md refreshed "
                    f"({obligation_count} generic obligation(s))"
                )
        except Exception as exc:
            log.warning(f"[{phase.name}] security obligation sidecar skipped: {exc!r}")
        try:
            obl_count = _write_obligation_ledger(scratchpad, config.get("mode", "core"))
            if obl_count and phase.name == "depth":
                log.info(
                    f"[depth] obligation_ledger.md refreshed "
                    f"({obl_count} chain-retention obligation(s))"
                )
        except Exception as exc:
            log.warning(f"[{phase.name}] obligation ledger sidecar skipped: {exc!r}")
    if phase.name == "report_index":
        try:
            facet_count = _write_candidate_semantic_facets(scratchpad)
            if facet_count:
                log.info(
                    f"[report_index] candidate_semantic_facets.md refreshed "
                    f"({facet_count} candidate(s))"
                )
        except Exception as exc:
            log.warning(f"[report_index] semantic facet sidecar skipped: {exc!r}")

    # Ship 7: pre-breadth opengrep sharding. Runs once per breadth
    # attempt; idempotent (same inputs -> byte-identical shard files),
    # so retries don't accumulate noise. No-op when there is no
    # spawn_manifest.md yet (instantiate hasn't run) or no opengrep
    # findings to shard. The breadth subagent template (Ship 2) reads
    # the per-agent shard when present and falls back to the full
    # opengrep_findings.md otherwise -- so this sharding is purely
    # additive and never breaks audits that didn't have it before.
    if phase.name == "breadth":
        try:
            mode = str(config.get("mode") or "core").lower()
            should_run_opengrep = (
                config.get("pipeline") != "l1"
                and mode != "light"
                and os.environ.get("PLAMEN_DISABLE_OPENGREP") != "1"
                and not (scratchpad / "opengrep_findings.md").exists()
            )
            if should_run_opengrep:
                display.print_phase_heartbeat(
                    phase.name, 0,
                    status="optional detector scan: OpenGrep",
                )
                sys.path.insert(0, str(Path(__file__).parent))
                from recon_prepass import _run_opengrep_scan

                status = _run_opengrep_scan(
                    scratchpad,
                    Path(config["project_root"]),
                    str(config.get("language") or "evm").lower(),
                )
                log.info(f"[{phase.name}] OpenGrep pre-breadth scan: {status}")
                display.print_phase_heartbeat(
                    phase.name, 0,
                    status=f"optional detector scan: {status}",
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] OpenGrep pre-breadth scan skipped: {exc!r}; "
                "continuing without static detector obligations"
            )
        # RECON-1/RECON-2: run the slow Rust SCIP bake and Sec3 X-Ray here
        # (pre-breadth) instead of at startup, so the heartbeat is live and a
        # multi-minute scan is not mistaken for a dead launch. Idempotent: each
        # skips when its artifact already exists.
        try:
            _lang = str(config.get("language") or "evm").lower()
            _proj = Path(config["project_root"])
            if (
                config.get("pipeline") != "l1"
                and _lang in ("solana", "soroban")
                and not (scratchpad / "caller_map.md").exists()
                and os.environ.get("PLAMEN_DISABLE_SCIP") != "1"
            ):
                display.print_phase_heartbeat(
                    phase.name, 0, status="optional graph bake: SCIP",
                )
                sys.path.insert(0, str(Path(__file__).parent))
                from recon_prepass import _bake_rust_graph
                status = _bake_rust_graph(scratchpad, _proj)
                log.info(f"[{phase.name}] Rust graph pre-breadth bake: {status}")
            if (
                config.get("pipeline") == "l1"
                and _lang == "go"
                and not (scratchpad / "caller_map.md").exists()
                and os.environ.get("PLAMEN_DISABLE_SCIP") != "1"
            ):
                display.print_phase_heartbeat(
                    phase.name, 0, status="optional graph bake: SCIP (Go)",
                )
                sys.path.insert(0, str(Path(__file__).parent))
                from recon_prepass import _bake_go_graph
                status = _bake_go_graph(scratchpad, _proj)
                log.info(f"[{phase.name}] Go graph pre-breadth bake: {status}")
                # WP-A.3: primitive_status.md pre-declares SCIP_GO_REUSED=false
                # (bake-phase fallback) but nothing ever refined it. The bake
                # contract returns REUSED:.../WRITTEN:.../FAILED:...; only a
                # REUSED/WRITTEN outcome is a real signal to record.
                try:
                    _status_u = str(status).upper()
                    if _status_u.startswith("REUSED"):
                        _l1_update_primitive_status_flag(
                            scratchpad, "SCIP_GO_REUSED", True
                        )
                    elif _status_u.startswith("WRITTEN"):
                        _l1_update_primitive_status_flag(
                            scratchpad, "SCIP_GO_REUSED", False
                        )
                except Exception:
                    pass
            if (
                config.get("pipeline") == "l1"
                and _lang in ("rust", "mixed")
                and not (scratchpad / "caller_map.md").exists()
                and os.environ.get("PLAMEN_DISABLE_SCIP") != "1"
            ):
                display.print_phase_heartbeat(
                    phase.name, 0, status="optional graph bake: SCIP (Rust)",
                )
                sys.path.insert(0, str(Path(__file__).parent))
                from recon_prepass import _bake_rust_graph
                status = _bake_rust_graph(scratchpad, _proj)
                log.info(f"[{phase.name}] Rust graph pre-breadth bake: {status}")
                # WP-A.3: same primitive_status.md refinement as the Go bake
                # above, scoped to the L1 rust bake outcome only.
                try:
                    _status_u = str(status).upper()
                    if _status_u.startswith("REUSED"):
                        _l1_update_primitive_status_flag(
                            scratchpad, "SCIP_RUST_REUSED", True
                        )
                    elif _status_u.startswith("WRITTEN"):
                        _l1_update_primitive_status_flag(
                            scratchpad, "SCIP_RUST_REUSED", False
                        )
                except Exception:
                    pass
            if (
                config.get("pipeline") != "l1"
                and _lang == "solana"
                and not (scratchpad / "sec3_findings.md").exists()
                and os.environ.get("PLAMEN_DISABLE_SEC3") != "1"
            ):
                display.print_phase_heartbeat(
                    phase.name, 0, status="optional detector scan: Sec3 X-Ray",
                )
                status = _run_sec3_xray(scratchpad, _proj)
                log.info(f"[{phase.name}] Sec3 X-Ray pre-breadth scan: {status}")
            # Wave-2 A5: mechanical govulncheck (Go) / cargo audit (Rust)
            # dependency-vulnerability scan. Mirrors the OpenGrep wiring above
            # -- deferred to the pre-breadth hook (not startup) so the slow
            # external scanner does not stall the silent-launch window, and
            # idempotent on `dependency_audit_findings.md` presence so retries
            # don't re-run it. pipeline=="l1"-gated; the SC path never reaches
            # this branch. DISTINCT from supply_chain_gate.py's IOC gate.
            if (
                config.get("pipeline") == "l1"
                and not (scratchpad / "dependency_audit_findings.md").exists()
                and os.environ.get("PLAMEN_DISABLE_DEPENDENCY_AUDIT") != "1"
            ):
                display.print_phase_heartbeat(
                    phase.name, 0,
                    status="optional detector scan: dependency audit",
                )
                status = _run_dependency_audit_l1(scratchpad, _proj, _lang)
                log.info(
                    f"[{phase.name}] dependency-audit pre-breadth scan: {status}"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] SCIP/Sec3/dependency-audit pre-breadth scan "
                f"skipped: {exc!r}; continuing without graph/detector "
                "enrichment"
            )
        try:
            sharded = shard_opengrep_obligations(scratchpad)
            if sharded:
                # Log the first few shard sizes for observability.
                sizes = {
                    k: v.get("row_count", 0) for k, v in sharded.items()
                }
                log.info(
                    f"[{phase.name}] opengrep sharded into "
                    f"{len(sharded)} files: {sizes}"
                )
                # Preservation check is informational here -- the
                # sharder builds the union itself, so a failure
                # indicates a sharder bug. Surfacing it via log.warning
                # rather than failing the phase: Ship 7 keeps the
                # existing opengrep obligation gate behavior intact.
                preservation_issues = _check_opengrep_sharding_preservation(
                    scratchpad
                )
                for issue in preservation_issues:
                    log.warning(f"[{phase.name}] {issue}")
        except Exception as exc:
            log.warning(
                f"[{phase.name}] opengrep sharding failed: {exc}; "
                f"breadth will fall back to reading opengrep_findings.md "
                f"directly per the Subagent Prompt Template fallback rule"
            )

    v1_prompt = resolve_v1_prompt(config["pipeline"])
    if not v1_prompt.exists():
        log.error(f"V1 prompt missing: {v1_prompt}")
        return EXIT_ERROR

    try:
        prompt = build_phase_prompt(v1_prompt, phase, config)
    except PhasePromptError as e:
        log.error(
            f"[{phase.name}] PROMPT BUILD FAILED — cannot spawn subprocess.\n"
            f"  {e}\n"
            f"  This means the V1 section markers in plamen_types.py are stale "
            f"OR a standalone prompt file is needed in prompts/shared/v2/."
        )
        return EXIT_ERROR
    hyp_count = 0
    if phase.name in (*L1_VERIFY_PHASE_NAMES, *SC_VERIFY_PHASE_NAMES):
        try:
            if phase.name in SC_VERIFY_PHASE_NAMES:
                _shards = compute_sc_verify_shards(scratchpad)
            else:
                _shards = compute_verify_shards(scratchpad)
            hyp_count = len(_shards.get(phase.name, []))
        except Exception:
            pass
    # v2.5.0: verify_aggregate needs total hypothesis count for timeout scaling
    # (it reads ALL verify files, not just one shard's worth)
    if phase.name in ("verify_aggregate", "sc_verify_aggregate"):
        try:
            if phase.name == "sc_verify_aggregate":
                _all_shards = compute_sc_verify_shards(scratchpad)
            else:
                _all_shards = compute_verify_shards(scratchpad)
            hyp_count = sum(len(v) for v in _all_shards.values())
        except Exception:
            pass
    # v2.5.0: phases that process ALL hypotheses need total-count scaling.
    # Without this, report_index (1500s base) times out on 47+ hypothesis
    # audits. Chain/crossbatch have the same structural gap.
    _TOTAL_HYP_PHASES = frozenset({
        "chain", "chain_agent2", "crossbatch",
        "report_index", "sc_semantic_dedup",
    })
    if phase.name in _TOTAL_HYP_PHASES and hyp_count == 0:
        try:
            hyp_count = len(parse_verification_queue_rows(scratchpad))
        except Exception:
            pass
        if hyp_count == 0:
            # Pre-queue phases: count from findings_inventory.md
            try:
                inv = scratchpad / "findings_inventory.md"
                if inv.exists():
                    hyp_count = inv.read_text(
                        encoding="utf-8", errors="replace"
                    ).count("\n| H-")
            except Exception:
                pass
    # Codex backend: translate prompt paths and inject tool preamble.
    # Wave-4 M1: only the skeptic phase consults phase_backend_overrides
    # (cross-vendor adversarial diversity). Every other phase keeps the
    # unconditional `config.get("cli_backend", "claude")` read -- byte-
    # identical to pre-M1 behavior.
    backend = (
        _effective_backend(config, phase)
        if phase.name == "skeptic"
        else config.get("cli_backend", "claude")
    )
    _explicit_claude_exec_mode = (
        config.get("claude_exec_mode")
        or os.environ.get("PLAMEN_CLAUDE_EXEC_MODE")
    )
    claude_exec_mode = (_explicit_claude_exec_mode or "pty").strip().lower()
    if claude_exec_mode not in ("pty", "headless"):
        log.warning(
            f"[{phase.name}] unknown claude_exec_mode={claude_exec_mode!r}; "
            "falling back to pty"
        )
        claude_exec_mode = "pty"
    if (
        backend == "claude"
        and claude_exec_mode == "pty"
        and not _explicit_claude_exec_mode
        and Path(CLAUDE_BIN).name.lower() not in ("claude", "claude.cmd", "claude.exe")
    ):
        log.warning(
            f"[{phase.name}] CLAUDE_BIN basename is nonstandard "
            f"({Path(CLAUDE_BIN).name!r}); falling back to headless for "
            "compatibility. Set claude_exec_mode=pty explicitly to force "
            "subscription-preserving PTY mode for wrappers."
        )
        claude_exec_mode = "headless"
    is_claude_pty = backend == "claude" and claude_exec_mode == "pty"

    # Ship 6: emit the non-PTY deprecation warning when an
    # agent-spawning phase lands on the legacy headless backend.
    # The non-PTY path runs `claude -p --no-session-persistence` which
    # exits after one turn and cannot be resumed; artifact-complete
    # supervision is structurally impossible. We do NOT block the
    # phase -- the prompt-template fix from Ship 2 still applies, only
    # in-session continuation is disabled. The phase will fall back to
    # whole-phase retry on gate failure as it always has.
    if (
        not is_claude_pty
        and backend == "claude"
        and phase.name in PTY_SUPERVISED_PHASES
    ):
        log.warning(
            f"[{phase.name}] running on deprecated non-PTY backend "
            f"(claude -p --no-session-persistence). Artifact-complete "
            f"supervision is disabled; the phase will use the legacy "
            f"size+marker gate and whole-phase retry on failure."
        )

    timeout = scale_timeout(
        phase.base_timeout_s, config["project_root"], config["language"],
        mode=config.get("mode"), hypothesis_count=hyp_count,
        backend=backend,
    )
    # Codex depth fan-out parity: Codex's single `codex exec` turn under-
    # fans-out the ~15-artifact depth phase, leaving never-cut scanners as
    # 0-byte stubs and the depth gate correctly halting. Run ONE `codex exec`
    # per depth JOB instead — mirrors the Claude PTY worker pool so every
    # never-cut artifact actually gets produced. ADDITIVE: gated to
    # backend=codex + phase=depth + real fan-out; all other paths unchanged.
    if (
        backend == "codex"
        and phase.name == "depth"
        and _should_use_depth_codex_fanout(config, scratchpad)
    ):
        return _run_depth_codex_fanout(
            phase=phase, config=config, scratchpad=scratchpad, attempt=attempt,
        )
    if backend == "codex":
        prompt = _translate_prompt_for_codex(
            prompt, phase_name=phase.name,
            pipeline=config.get("pipeline", "sc"),
            mode=config.get("mode", "core"),
            scratchpad=scratchpad,
        )
    elif (
        is_claude_pty
        and phase.name == "breadth"
        and _should_use_breadth_worker_pool(config, scratchpad)
    ):
        prompt = (
            "# BREADTH WORKER POOL\n\n"
            "The Python Plamen driver owns breadth fanout for Claude PTY "
            "runs. This phase snapshot is intentionally not a coordinator "
            "prompt. The driver launches one bounded top-level Claude PTY "
            "worker per manifest artifact using `_prompt_breadth_worker_*` "
            "snapshots, then gates disk artifacts mechanically.\n"
        )
    elif (
        is_claude_pty
        and phase.name == "depth"
        and _should_use_depth_worker_pool(config, scratchpad)
    ):
        prompt = (
            "# DEPTH WORKER POOL\n\n"
            "The Python Plamen driver owns depth fanout for fresh Claude PTY "
            "runs. This phase snapshot is intentionally not a coordinator "
            "prompt. The driver launches bounded top-level Claude PTY workers "
            "for the deterministic depth artifact plan using "
            "`_prompt_depth_worker_*` snapshots, synthesizes mechanical "
            "lifecycle/scoring artifacts from disk, then gates artifacts "
            "mechanically.\n"
        )

    # Snapshot prompt — doubles as the subprocess stdin source (v2.1.3).
    # The snapshot file IS the authoritative prompt the child sees, so a
    # failure here is now a fatal phase failure (previously the snapshot
    # was diagnostic-only and a write-failure was a warning). This removes
    # the divergence risk between "what the child got" and "what the
    # post-mortem reads".
    snap = scratchpad / f"_prompt_{phase.name}.attempt{attempt}.md"
    try:
        snap.write_text(prompt, encoding="utf-8")
    except Exception as e:
        log.error(
            f"[{phase.name}] prompt snapshot failed: {e} — "
            f"cannot spawn subprocess (snapshot is the stdin source)"
        )
        return EXIT_ERROR

    # Resolve effective model (Light forces sonnet; otherwise phase.model).
    # phase_model() reads config["cli_backend"] internally to pick between
    # Claude tier aliases and Codex model IDs. When the resolved `backend`
    # above differs from the raw config value (skeptic phase_backend_overrides
    # only -- see the `backend =` assignment), pass phase_model a shallow
    # config view with cli_backend overridden so the model string matches the
    # backend actually being spawned. Default path (backend == raw
    # cli_backend, i.e. everywhere else) passes `config` unchanged.
    _model_config = (
        config
        if backend == (config.get("cli_backend") or "claude").strip().lower()
        else {**config, "cli_backend": backend}
    )
    effective_model = phase_model(phase, config["mode"], _model_config)

    if backend == "codex":
        # Pre-create the phase's mandatory first-pass secondary artifacts
        # (never-cut scanners/validation/confidence, triggered niches, recon
        # shards) so a single codex exec can fill the full first-pass set,
        # not just the core glob. (apply_patch cannot create new files.)
        # Done here BEFORE delegating so the single-subprocess path seeds the
        # same full set it always has; _run_one_codex_exec also seeds its
        # expected_outputs but here that is a subset already covered.
        _precreate_codex_artifacts(phase, scratchpad, config)
        # The inline single-subprocess codex block was factored into
        # _run_one_codex_exec (behavior-preserving): same cmd build, snapshot,
        # Popen, heartbeat wait, canonical-log mirror, cost + orphan
        # diagnostics. The depth fan-out reuses the same helper once per job.
        return _run_one_codex_exec(
            prompt=prompt,
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            attempt=attempt,
            label=phase.name,
            expected_outputs=[],
            timeout=timeout,
            effective_model=effective_model,
        )
    if is_claude_pty:
        session_id = str(uuid.uuid4())
        # Ship 8.16: single source of truth shared with the respawn rewrite
        # (_rewrite_argv_positional_prompt) so a continuation respawn delivers
        # byte-identical bootstrap text, differing only in the target file.
        bootstrap_prompt = _argv_bootstrap_instruction(snap)
        cmd = [
            CLAUDE_BIN,
            "--model", effective_model,
            "--session-id", session_id,
            "--dangerously-skip-permissions",
            "--add-dir", config["project_root"],
            "--add-dir", plamen_home().as_posix(),
        ]
    else:
        cmd = [
            CLAUDE_BIN, "-p",
            "--model", effective_model,
            "--output-format", "json",
            "--no-session-persistence",
            "--dangerously-skip-permissions",
            # Anthropic-documented cache-reuse improvement. Moves volatile
            # per-machine sections (cwd, env info, git status, memory
            # paths) out of the cached system prefix into the first user
            # message, so the system-prompt prefix stays byte-identical
            # across subprocess invocations and the prompt cache hits
            # more aggressively. Quoting `claude --help`:
            # > "Move per-machine sections (cwd, env info, memory paths,
            # >  git status) from the system prompt into the first user
            # >  message. Improves cross-user prompt-cache reuse."
            # Single-flag, zero-risk (Anthropic's own recommended flag).
            "--exclude-dynamic-system-prompt-sections",
            "--add-dir", config["project_root"],
            # Agents must read ~/.claude/rules/*.md, prompts/{lang}/*.md, and
            # skills/**/SKILL.md. Add the Claude home explicitly so permission
            # prompts never fire. v2.3.8 DRV-2: forward-slash form to keep
            # CLI argv consistent across Windows/POSIX so MCP/path loaders
            # don't silently mishandle backslashes.
            "--add-dir", plamen_home().as_posix(),
        ]
    if not phase.needs_mcp and backend != "codex":
        # Subprocess startup isolation for non-MCP phases (Claude Code only).
        # Codex CLI has no --disallowedTools, --settings, --strict-mcp-config,
        # or --mcp-config flags — it uses --ephemeral + --ignore-user-config.
        #
        # `claude -p` consults `~/.claude/settings.json` at startup and
        # cold-starts everything declared there: MCP servers, plugins
        # from external marketplaces (rust-analyzer-lsp, entry-point-
        # analyzer), Pre/PostToolUse hooks, auto-update checks, etc. Any
        # one of these can block indefinitely (network call, slow disk,
        # heavy compile). The driver observed two production halts on a
        # single audit (an L1 inventory: MCP class; an SC
        # inventory: plugin class) — 0 stdio + 0 tokens billed because
        # the subprocess never reached the API.
        #
        # `--bare` would skip all of these in one flag but requires
        # `ANTHROPIC_API_KEY` / `apiKeyHelper`; OAuth-only users (this
        # user) can't use it.
        #
        # The robust path is `--settings <overlay>` + `--strict-mcp-config
        # --mcp-config <empty>`. `--settings` overlays additional settings
        # on the base config — empty `enabledPlugins`/`hooks`/`mcpServers`
        # in the overlay disables those subsystems without touching the
        # user's real settings.json (so OAuth keychain auth keeps working).
        # `--strict-mcp-config` is belt-and-suspenders — it forces claude
        # to load MCP from the empty file and ignore everything else.
        #
        # If an overlay write fails (disk-full / readonly / antivirus
        # lock), the fall-through fail-open is "subprocess may still hang"
        # — but visibly logged, not silent.
        isolation_payload = SUBPROCESS_ISOLATION_PAYLOAD
        # Resolve to ABSOLUTE: this file is handed to the worker as `--settings`
        # and the worker runs with cwd=project_root. A relative path here would
        # resolve against the worker's cwd (not the driver's) and "Settings file
        # not found" kills every worker. main() normalizes config["scratchpad"]
        # to absolute, but resolving again at the construction site is a cheap,
        # general guarantee that the launch arg is never relative.
        isolation_path = (scratchpad / "_subprocess_isolation.json").resolve()
        isolation_ok = False
        try:
            if (
                not isolation_path.exists()
                or isolation_path.read_text(encoding="utf-8").strip()
                != isolation_payload
            ):
                isolation_path.write_text(
                    isolation_payload, encoding="utf-8"
                )
            isolation_ok = True
        except Exception as _iso_err:
            log.warning(
                f"[{phase.name}] subprocess-isolation file write failed "
                f"({_iso_err}) — settings.json plugins/hooks/mcp will "
                f"load and may block the subprocess"
            )
        cmd.extend(["--disallowedTools", "mcp__*"])  # always, cheap
        if isolation_ok:
            iso = isolation_path.as_posix()
            cmd.extend([
                "--settings", iso,
                "--strict-mcp-config", "--mcp-config", iso,
            ])

    # v2.8.16 Phase 1 (#1c): a PoC-writing verify shard must be able to READ
    # existing tests and WRITE the harm test into the real build root, which is
    # frequently a PARENT or SIBLING of the audit scope dir (project_root).
    # Without granting the build root, the verifier literally cannot create
    # `test/<x>` and skips with NO_BUILD_ENVIRONMENT → mechanical NO_TEST_FILE →
    # degrade. Ecosystem-agnostic: _find_build_root keys on config language.
    # Depth Thorough also needs the build root: the fuzz sidecar worker(s) build
    # and run forge/medusa/cargo/sui in the dir owning the build manifest, which
    # is frequently a parent/sibling of the audit scope dir. Grant is additive
    # and harmless for non-fuzz depth workers (read-only extra dir).
    _depth_needs_build_root = (
        phase.name == "depth"
        and str(config.get("mode", "core")).lower() == "thorough"
    )
    if backend != "codex" and (
        (
            phase.name.startswith(("sc_verify_", "verify_"))
            and not phase.name.endswith(("_queue", "_aggregate"))
        )
        or _depth_needs_build_root
    ):
        try:
            import importlib as _il_br
            import sys as _sys_br
            _sys_br.path.insert(0, str(Path(__file__).parent))
            _mv_br = _il_br.import_module("mechanical_verify")
            # Honor recon's authoritative chosen build root (build_status.md)
            # so the PoC-writing --add-dir grant and the mechanical executor
            # resolve the SAME build root — otherwise the LLM writes its test
            # where the executor will not look.
            _build_root = _mv_br._read_recon_build_root(
                scratchpad, config.get("language", "")
            ) or _mv_br._find_build_root(
                Path(config["project_root"]), config.get("language", "")
            )
            _br_posix = Path(_build_root).as_posix()
            if _br_posix not in cmd and _br_posix != Path(config["project_root"]).as_posix():
                cmd.extend(["--add-dir", _br_posix])
        except Exception as _br_exc:
            log.debug(f"[{phase.name}] build-root --add-dir skipped: {_br_exc!r}")

    # Neutralize the V1 phase_gate watchdog — but ONLY if its breadcrumb
    # belongs to THIS run. The V1 L1 prompt initializes it via
    # `phase_gate.py --init`, which plants a breadcrumb at
    # ~/.claude/hooks/.active_audit pointing at the current scratchpad.
    # Subsequent claude -p subprocesses spawned by this driver inherit that
    # watchdog, which blocks them on phases that don't write
    # `analysis_*.md` (caused A1/A7/A8 in a prior L1 run). V2 has its own
    # Python gate; the V1 watchdog is harmful for V2 subprocesses.
    #
    # CRITICAL: phase_gate.py already recognizes V2 scratchpads via the
    # `_v2_checkpoint.json` marker (see phase_gate.find_state_file) and
    # returns None for them. So V2 subprocesses are already safe REGARDLESS
    # of what .active_audit points at. The risk of unconditionally deleting
    # .active_audit is trampling a parallel V1 run in an unrelated project.
    # Only unlink if the breadcrumb refers to our scratchpad (or is
    # corrupt/empty and thus useless anyway).
    try:
        active_audit = plamen_home() / "hooks" / ".active_audit"
        if active_audit.exists():
            owns_breadcrumb = False
            try:
                raw = active_audit.read_text(encoding="utf-8").strip()
                if not raw:
                    owns_breadcrumb = True  # empty/corrupt → safe to clear
                else:
                    try:
                        data = json.loads(raw)
                        sp = data.get("scratchpad") or data.get("scratchpad_path") or ""
                    except Exception:
                        sp = raw  # plain-text breadcrumb (legacy)
                    if sp:
                        try:
                            owns_breadcrumb = (
                                Path(sp).resolve() == scratchpad.resolve()
                            )
                        except Exception:
                            owns_breadcrumb = False
                    else:
                        owns_breadcrumb = True
            except Exception:
                owns_breadcrumb = True  # unreadable → treat as corrupt
            if owns_breadcrumb:
                active_audit.unlink()
            else:
                log.debug(
                    "watchdog: .active_audit belongs to another run, leaving it alone "
                    "(V2 subprocess is safe via _v2_checkpoint.json marker)"
                )
        watchdog_state = scratchpad / "watchdog_state.json"
        if watchdog_state.exists():
            watchdog_state.unlink()
    except Exception as _e:
        log.debug(f"watchdog cleanup skipped: {_e}")

    log_path = scratchpad / f"_stdio_{phase.name}.attempt{attempt}.log"
    canonical = scratchpad / f"_stdio_{phase.name}.log"

    if is_claude_pty:
        # Claude Code documents `claude [options] [prompt]`; pass the phase
        # prompt as that normal positional argument so the interactive PTY
        # starts executing immediately. The helper inserts a harmless boolean
        # flag before the prompt so variadic options like --mcp-config cannot
        # consume it as another option value.
        cmd = append_claude_pty_prompt_arg(cmd, bootstrap_prompt)

    _cli_label = (
        "codex exec" if backend == "codex"
        else ("claude PTY" if is_claude_pty else "claude -p")
    )
    log.info(
        f"[{phase.name}] spawning {_cli_label} (model={effective_model}, "
        f"timeout={timeout}s, attempt={attempt})"
    )
    start = time.time()

    # v2.1.3: stdin from the snapshot file, NOT from a PIPE. The previous
    # daemon-thread-fed PIPE pattern deadlocked on prompts that exceeded
    # the OS pipe buffer — a cross-OS problem, not Windows-only:
    #   Windows anonymous pipe default:  4 KiB
    #   macOS (Darwin) pipe default:    16 KiB (grows to 64 KiB)
    #   Linux pipe default:             64 KiB
    # v2.1.1/v2.1.2 pushed the inventory prompt to ~100 KiB (V1 section +
    # Track B producer contract + graph-artifact directive + HARD SCOPE
    # header), exceeding ALL three defaults. File-based stdin has no
    # buffer threshold — the child reads directly from disk.
    #
    # This matches CPython's own pattern: subprocess.run(input=...)
    # internally switches to a temp file when input > pipe buffer on
    # Windows (see Lib/subprocess.py::_communicate_on_windows). We are
    # using that same pattern but with the already-existing diagnostic
    # snapshot file — zero extra I/O.
    # v2.3.8 DRV-3 + DRV-4: subprocess env tweaks.
    # DRV-3 — `ANTHROPIC_DISABLE_AUTOUPDATE=1`: settings.json has
    #   `autoUpdatesChannel: "latest"`, which causes claude -p to perform
    #   an update-check network call on every startup. Across 30-60
    #   subprocess spawns per Thorough audit this is silent overhead and,
    #   if a mid-audit update changes the binary path, a stale
    #   `CLAUDE_BIN` (resolved once at module import) breaks all
    #   subsequent phases.
    # DRV-4 — `PLAMEN_SCRATCHPAD`: lets `~/.claude/hooks/phase_gate.py`
    #   take its env-var fast path for the V2-dormancy check instead of
    #   doing filesystem I/O + JSON parse on every Task spawn. Saves
    #   ~100-500ms per agent dispatch on Windows; on a 20-agent depth
    #   phase that is several seconds of measurable overhead removed.
    subprocess_env = {
        **_filtered_child_subprocess_environ(),
        "ANTHROPIC_DISABLE_AUTOUPDATE": "1",
        # Protect nested Claude Code alias resolution too: if a prompt or
        # Task uses bare `opus`, keep it on the pinned Opus version.
        "ANTHROPIC_DEFAULT_OPUS_MODEL": PLAMEN_OPUS_MODEL,
        "PLAMEN_SCRATCHPAD": str(scratchpad),
        # Cap tool output to keep huge Bash/MCP dumps from bloating
        # the context window as turn count grows. Calibrated against
        # observed tool usage: Read isn't capped here (separate tool),
        # but `forge test -vvv` on a failing PoC routinely emits
        # 10-50KB of call trace that verifiers need to classify the
        # failure. A 12k char Bash cap (round-1 default) would truncate
        # that revert detail and force [CODE-TRACE] fallbacks — a recall
        # regression. 30k chars (~7.5k tokens) survives normal forge
        # traces while still preventing 200KB raw dumps.
        # MCP 8k tokens (~32k chars) is fine for slither/solodit/RAG
        # results which top out at ~10KB typical.
        # Pattern documented in Anthropic's "Writing tools for agents":
        # https://www.anthropic.com/engineering/writing-tools-for-agents
        "BASH_MAX_OUTPUT_LENGTH": os.environ.get(
            "BASH_MAX_OUTPUT_LENGTH", "30000"
        ),
        "MAX_MCP_OUTPUT_TOKENS": os.environ.get(
            "MAX_MCP_OUTPUT_TOKENS", "8000"
        ),
    }
    if is_claude_pty:
        subprocess_env["PLAMEN_BOOTSTRAP_IN_ARGV"] = "1"
    # Opt the highest-turn-count phases (depth + verify shards, plus
    # heavy exploratory phases) into Anthropic's context-editing beta.
    # The model can drop stale tool results from earlier turns when
    # context fills, instead of paying to drag them through every
    # subsequent call. Anthropic's own benchmark showed -84% token
    # consumption AND +29% performance on 100-turn workloads —
    # quality-positive, not a trade-off:
    # https://platform.claude.com/docs/en/build-with-claude/context-editing
    #
    # Scope rationale:
    #   recon (~26 turns)   — heavy Read/Grep exploration; dropped
    #                         reads can be re-fetched if needed.
    #   rescan (~27 turns)  — same workload profile as recon.
    #   depth               — original target; tool-heavy multi-agent.
    #   verify_*            — forge test -vvv across many findings.
    # Deliberately EXCLUDED:
    #   breadth             — multi-agent fan-out; user wants to keep
    #                         it on default cache semantics until the
    #                         recon/rescan expansion is validated.
    #   inventory chunks    — short turn count; marginal savings.
    #   instantiate, etc.   — too short for context-editing to matter.
    _CONTEXT_EDITING_PHASES = (
        "recon",
        "rescan",
        "depth",
        *L1_VERIFY_PHASE_NAMES,
        *SC_VERIFY_PHASE_NAMES,
    )
    if phase.name in _CONTEXT_EDITING_PHASES:
        # Preserve any existing ANTHROPIC_BETA the user set (e.g. for
        # other features); append our beta to the list rather than
        # overwrite.
        _existing_beta = os.environ.get("ANTHROPIC_BETA", "").strip()
        _our_beta = "context-management-2025-06-27"
        if _existing_beta and _our_beta not in _existing_beta:
            subprocess_env["ANTHROPIC_BETA"] = (
                _existing_beta + "," + _our_beta
            )
        else:
            subprocess_env["ANTHROPIC_BETA"] = _our_beta
    # On Windows, claude.cmd is a batch file; Popen without
    # CREATE_NO_WINDOW spawns a visible console per subprocess.
    popen_kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        popen_kwargs["start_new_session"] = True

    if (
        is_claude_pty
        and phase.name == "recon"
        and _should_use_recon_worker_pool(config, scratchpad)
    ):
        try:
            rc = _run_recon_worker_pool_pty(
                scratchpad=scratchpad,
                project_root=config["project_root"],
                config=config,
                phase=phase,
                base_cmd=cmd,
                env=subprocess_env,
                timeout=timeout,
                quiescence_s=float(config.get("claude_pty_quiescence_s", 8)),
                attempt=attempt,
            )
        except _PtyStop as stop:
            rc = stop.rc
        duration = time.time() - start
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as out:
                out.write(
                    f"recon worker-pool completed rc={rc} "
                    f"after {duration:.0f}s\n\n"
                )
                for worker_log in sorted(
                    scratchpad.glob("_stdio_recon_worker_*.log")
                ):
                    out.write(f"\n\n# {worker_log.name}\n")
                    try:
                        out.write(
                            worker_log.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                    except Exception as exc:
                        out.write(f"[could not read worker log: {exc}]\n")
                if rc == 1:
                    out.write(
                        "\nPLAMEN_RATE_LIMIT_DETECTED=1 "
                        "api_error_status=429 "
                        "type=rate_limit_error "
                        "phase=recon source=recon_worker_pool\n"
                    )
            canonical.write_bytes(log_path.read_bytes())
        except Exception:
            pass
        log.info(
            f"[{phase.name}] PTY worker pool completed rc={rc} "
            f"after {duration:.0f}s"
        )
        if rc == -2:
            log.warning(
                "[recon] worker-pool did not satisfy the canonical gate; "
                "falling back to the direct isolated recon prompt for this "
                "attempt"
            )
        else:
            return rc

    if (
        is_claude_pty
        and phase.name == "breadth"
        and _should_use_breadth_worker_pool(config, scratchpad)
    ):
        try:
            rc = _run_breadth_worker_pool_pty(
                scratchpad=scratchpad,
                project_root=config["project_root"],
                config=config,
                phase=phase,
                base_cmd=cmd,
                env=subprocess_env,
                timeout=timeout,
                quiescence_s=float(config.get("claude_pty_quiescence_s", 8)),
                attempt=attempt,
            )
        except _PtyStop as stop:
            rc = stop.rc
        duration = time.time() - start
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as out:
                out.write(
                    f"breadth worker-pool completed rc={rc} "
                    f"after {duration:.0f}s\n\n"
                )
                for worker_log in sorted(
                    scratchpad.glob("_stdio_breadth_worker_*.log")
                ):
                    out.write(f"\n\n# {worker_log.name}\n")
                    try:
                        out.write(
                            worker_log.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                    except Exception as exc:
                        out.write(f"[could not read worker log: {exc}]\n")
                if rc == 1:
                    out.write(
                        "\nPLAMEN_RATE_LIMIT_DETECTED=1 "
                        "api_error_status=429 "
                        "type=rate_limit_error "
                        "phase=breadth source=breadth_worker_pool\n"
                    )
            canonical.write_bytes(log_path.read_bytes())
        except Exception:
            pass
        log.info(
            f"[{phase.name}] PTY worker pool completed rc={rc} "
            f"after {duration:.0f}s"
        )
        return rc

    if (
        is_claude_pty
        and phase.name == "rescan"
        and _should_use_rescan_worker_pool(config, scratchpad)
    ):
        try:
            rc = _run_rescan_worker_pool_pty(
                scratchpad=scratchpad,
                project_root=config["project_root"],
                config=config,
                phase=phase,
                base_cmd=cmd,
                env=subprocess_env,
                timeout=timeout,
                quiescence_s=float(config.get("claude_pty_quiescence_s", 8)),
                attempt=attempt,
            )
        except _PtyStop as stop:
            rc = stop.rc
        duration = time.time() - start
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as out:
                out.write(
                    f"rescan worker-pool completed rc={rc} "
                    f"after {duration:.0f}s\n\n"
                )
                for worker_log in sorted(
                    scratchpad.glob("_stdio_rescan_worker_*.log")
                ):
                    out.write(f"\n\n# {worker_log.name}\n")
                    try:
                        out.write(
                            worker_log.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                    except Exception as exc:
                        out.write(f"[could not read worker log: {exc}]\n")
                if rc == 1:
                    out.write(
                        "\nPLAMEN_RATE_LIMIT_DETECTED=1 "
                        "api_error_status=429 "
                        "type=rate_limit_error "
                        "phase=rescan source=rescan_worker_pool\n"
                    )
            canonical.write_bytes(log_path.read_bytes())
        except Exception:
            pass
        log.info(
            f"[{phase.name}] PTY worker pool completed rc={rc} "
            f"after {duration:.0f}s"
        )
        return rc

    if (
        is_claude_pty
        and phase.name == "depth"
        and _should_use_depth_worker_pool(config, scratchpad)
    ):
        try:
            rc = _run_depth_worker_pool_pty(
                scratchpad=scratchpad,
                project_root=config["project_root"],
                config=config,
                phase=phase,
                base_cmd=cmd,
                env=subprocess_env,
                timeout=timeout,
                quiescence_s=float(config.get("claude_pty_quiescence_s", 8)),
                attempt=attempt,
            )
        except _PtyStop as stop:
            rc = stop.rc
        duration = time.time() - start
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as out:
                out.write(
                    f"depth worker-pool completed rc={rc} "
                    f"after {duration:.0f}s\n\n"
                )
                for worker_log in sorted(
                    scratchpad.glob("_stdio_depth_worker_*.log")
                ):
                    out.write(f"\n\n# {worker_log.name}\n")
                    try:
                        out.write(
                            worker_log.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                    except Exception as exc:
                        out.write(f"[could not read worker log: {exc}]\n")
                if rc == 1:
                    out.write(
                        "\nPLAMEN_RATE_LIMIT_DETECTED=1 "
                        "api_error_status=429 "
                        "type=rate_limit_error "
                        "phase=depth source=depth_worker_pool\n"
                    )
            canonical.write_bytes(log_path.read_bytes())
        except Exception:
            pass
        log.info(
            f"[{phase.name}] PTY worker pool completed rc={rc} "
            f"after {duration:.0f}s"
        )
        return rc

    if is_claude_pty:
        known_artifacts: set[str] = set()
        known_artifact_stats: dict[str, tuple[int, int]] = {}
        try:
            for p in scratchpad.iterdir():
                if not p.name.startswith("_"):
                    known_artifacts.add(p.name)
                    try:
                        st = p.stat()
                        known_artifact_stats[p.name] = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        pass
        except Exception:
            pass
        last_scan_time = 0.0
        last_status_time = 0.0
        last_compaction_check_time = 0.0
        compaction_notified = False
        protected_patterns = _live_protected_phase_write_patterns(
            scratchpad,
            str(config.get("pipeline", "sc")),
            phase.name,
            config.get("_active_phase_names"),
        )
        # FIX (#5): zombie-phase early-complete tracking. A phase-LLM worker that
        # writes all its expected artifacts (gate passes) and then idles —
        # emitting only spinner / "checking for updates" churn, no new transcript
        # events, no new artifact writes — used to block the full LOC-scaled
        # timeout (chain_agent2 once waited ~90 min). Track when an EXPECTED
        # artifact last changed; when the gate passes AND both artifacts and the
        # transcript have been quiescent for the thrash window, complete the
        # phase early (rc=0). Scaffold phases (gate passes on a placeholder) are
        # excluded so their continuation-budget/timeout path is unchanged.
        _zombie_expected_globs = list(
            getattr(phase, "expected_artifacts", None) or []
        )
        _zombie_excluded = _zombie_phase_is_scaffold_excluded(phase)
        _zombie_window = max(
            _CONTEXT_THRASH_LOOP_S,
            3.0 * float(config.get("claude_pty_quiescence_s", 8)),
        )
        last_expected_change_at = start
        last_zombie_check = 0.0

        def _pty_poll(now: float, _state: Any) -> None:
            nonlocal last_scan_time, last_status_time
            nonlocal last_compaction_check_time, compaction_notified
            nonlocal last_expected_change_at, last_zombie_check
            elapsed = int(now - start)
            display.spin(elapsed)
            if display.graceful_stop.requested:
                raise _PtyStop(-3)
            if (
                not compaction_notified
                and now - last_compaction_check_time >= 30
            ):
                last_compaction_check_time = now
                if transcript_shows_compaction(log_path):
                    compaction_notified = True
                    display.print_phase_heartbeat(
                        phase.name,
                        elapsed,
                        status=(
                            "Claude compacted context; continuing normally "
                            "(disk gate is source of truth)"
                        ),
                        status_style="info",
                    )
                    log.info(
                        f"[{phase.name}] Claude context compaction observed "
                        "in PTY transcript; continuing normally under the "
                        "disk gate. This is not a phase failure."
                    )
            if now - last_scan_time < _ARTIFACT_SCAN_INTERVAL:
                return
            last_scan_time = now
            pending: list[str] = []
            updated: list[str] = []
            try:
                for p in scratchpad.iterdir():
                    if p.name.startswith("_"):
                        continue
                    try:
                        st = p.stat()
                        sig = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        sig = (0, 0)
                    if p.name in known_artifacts:
                        if known_artifact_stats.get(p.name) != sig:
                            known_artifact_stats[p.name] = sig
                            updated.append(p.name)
                            if protected_patterns and _matches_any_pattern(
                                p.name, list(protected_patterns)
                            ):
                                display._clear_spinner()
                                log.error(
                                    f"[{phase.name}] live containment abort: "
                                    f"protected downstream artifact changed: {p.name}"
                                )
                                raise _PtyStop(-4)
                        continue
                    known_artifacts.add(p.name)
                    known_artifact_stats[p.name] = sig
                    pending.append(p.name)
                    if protected_patterns and _matches_any_pattern(
                        p.name, list(protected_patterns)
                    ):
                        # F7: depth's chain/synthesis writes are benign
                        # post-completion overruns — quarantine post-run
                        # rather than killing the PTY subprocess mid-run.
                        # Mirrors the headless _wait_with_heartbeat branch.
                        if (
                            phase.name == "depth"
                            and _is_benign_depth_foreign_artifact(p.name)
                        ):
                            log.warning(
                                f"[{phase.name}] foreign-artifact leak "
                                f"(benign, will quarantine post-run): "
                                f"{p.name}"
                            )
                        else:
                            display._clear_spinner()
                            log.error(
                                f"[{phase.name}] live containment abort: "
                                f"protected downstream artifact appeared: {p.name}"
                            )
                            raise _PtyStop(-4)
            except _PtyStop:
                raise
            except Exception:
                pass
            if pending:
                display.print_phase_heartbeat(
                    phase.name, elapsed, new_artifacts=pending
                )
                last_status_time = now
            elif updated:
                display.print_phase_heartbeat(
                    phase.name, elapsed, updated_artifacts=updated
                )
                last_status_time = now
            elif now - last_status_time >= 300:
                mins, secs = divmod(elapsed, 60)
                display.print_phase_heartbeat(phase.name, elapsed)
                log.info(
                    f"[{phase.name}] {mins}:{secs:02d} | waiting "
                    f"(pty transcript lines={getattr(_state, 'line_count', 0)})"
                )
                last_status_time = now

            # FIX (#5): zombie-phase early-complete. Refresh the
            # last-expected-artifact-change clock when any expected artifact was
            # created/updated this scan, then — only when the worker is NOT a
            # scaffold phase and has been fully quiescent (no expected-artifact
            # write AND no transcript event) for the thrash window — confirm the
            # gate and complete early instead of waiting the full timeout. The
            # gate check is throttled to once / 30s and only runs after the
            # quiescence window, so it costs nothing on the productive path.
            if _zombie_expected_globs:
                _changed = pending + updated
                if any(
                    _matches_any_pattern(nm, _zombie_expected_globs)
                    for nm in _changed
                ):
                    last_expected_change_at = now
            if (
                not _zombie_excluded
                and (now - last_expected_change_at) >= _zombie_window
                and (now - last_zombie_check) >= 30.0
                and getattr(_state, "last_event_time", None) is not None
                and (now - _state.last_event_time) >= _zombie_window
            ):
                last_zombie_check = now
                try:
                    _gp, _gm = gate_passes(
                        scratchpad, config["project_root"], phase
                    )
                except Exception:
                    _gp = False
                if _gp:
                    display._clear_spinner()
                    log.warning(
                        f"[{phase.name}] gate satisfied + artifact/transcript-"
                        f"quiescent for >={int(_zombie_window)}s while the "
                        f"worker emits only idle churn; completing the phase "
                        f"early instead of waiting the full {int(timeout)}s "
                        f"timeout (zombie-phase recovery)."
                    )
                    raise _PtyStop(0)

        with log_path.open("w", encoding="utf-8", errors="replace") as out:
            session = ClaudePtySession(
                cmd,
                cwd=config["project_root"],
                env=subprocess_env,
                session_id=session_id,
                prompt_path=snap,
                log_file=out,
            )
            try:
                out.write(f"CLAUDE_TRANSCRIPT={session.transcript_path}\n")
                out.flush()
                session.spawn()
                session.send_bootstrap()

                # Supervise every Claude PTY phase with a concrete disk gate.
                # Breadth/depth get structured row repair; other phases use
                # gate_missing detail to run a generic artifact repair turn.
                # There is no transport preflight in the production path
                # anymore: recovery always uses fresh missing-only interactive
                # Claude sessions, so live PTY continuation / --resume support
                # is irrelevant.
                supervised = (
                    backend == "claude"
                    and is_claude_pty
                    and (
                        phase.name in PTY_SUPERVISED_PHASES
                        or bool(phase.expected_artifacts)
                        or bool(getattr(phase, "any_of", None))
                        or phase.name in L1_VERIFY_PHASE_NAMES
                        or phase.name in SC_VERIFY_PHASE_NAMES
                    )
                )
                preflight: dict = {}

                if supervised:
                    # Supervised path: artifact-complete loop owns the
                    # rc decision. _run_supervised_pty_loop may swap
                    # the in-scope `session` via fresh missing-only
                    # respawn, so rebind here before the outer finally runs.
                    rc, session = _run_supervised_pty_loop(
                        session=session,
                        scratchpad=scratchpad,
                        project_root=config["project_root"],
                        phase=phase,
                        config=config,
                        preflight=preflight,
                        timeout=timeout,
                        quiescence_s=float(
                            config.get("claude_pty_quiescence_s", 8)
                        ),
                        on_poll=_pty_poll,
                        base_cmd=cmd,
                        cwd=config["project_root"],
                        env=subprocess_env,
                        log_file=out,
                        prompt_path=snap,
                        phase_started_at=start,
                    )
                else:
                    # Non-supervised path: preserve the legacy linear
                    # behavior byte-for-byte. The outer driver runs
                    # gate_passes against the returned rc just as
                    # before, so unrelated phases (recon, depth,
                    # niche, verify, report) behave identically.
                    state = session.wait_for_turn_complete(
                        timeout,
                        quiescence_s=float(
                            config.get("claude_pty_quiescence_s", 8)
                        ),
                        on_poll=_pty_poll,
                    )
                    process_exited = not session.is_alive()
                    if state.rate_limited:
                        rc = 1
                    elif state.complete:
                        rc = 0
                    elif process_exited:
                        rc = 0
                    elif getattr(state, "output_truncated", False):
                        log.warning(
                            f"[{phase.name}] turn hit the output-token cap and "
                            f"went quiescent; accepting current artifacts and "
                            f"letting the disk gate decide instead of waiting "
                            f"the full {timeout}s"
                        )
                        rc = 0
                    elif getattr(state, "context_thrash", False):
                        log.warning(
                            f"[{phase.name}] context-overflow thrash detected "
                            f"after ~{int(_CONTEXT_THRASH_LOOP_S)}s with no new "
                            f"productive output; accepting current artifacts and "
                            f"letting the disk gate decide instead of waiting "
                            f"the full {timeout}s"
                        )
                        rc = 0
                    else:
                        log.warning(
                            f"[{phase.name}] timed out after {timeout}s"
                        )
                        rc = -2
            except _PtyStop as stop:
                rc = stop.rc
            except Exception as e:
                log.error(f"[{phase.name}] PTY spawn/wait failed: {e}")
                try:
                    out.write(f"PTY failed before phase completion: {e}\n")
                    out.flush()
                except Exception:
                    pass
                rc = EXIT_ERROR
            finally:
                session.terminate(grace_s=_HALT_TERMINATE_GRACE_S)
                display._clear_spinner()
                try:
                    if session.transcript_path.exists():
                        out.write("\n\n# Claude session transcript tail\n")
                        with session.transcript_path.open(
                            "rb"
                        ) as tf:
                            tf.seek(0, 2)
                            size = tf.tell()
                            tf.seek(max(0, size - 65536))
                            out.write(tf.read().decode("utf-8", errors="replace"))
                        out.flush()
                except Exception:
                    pass

        try:
            if rc == 1:
                _append_rate_limit_sentinel(
                    log_path,
                    phase_name=phase.name,
                    source="claude_pty",
                )
            canonical.write_bytes(log_path.read_bytes())
        except Exception:
            pass

        duration = time.time() - start
        log.info(f"[{phase.name}] PTY turn completed rc={rc} after {duration:.0f}s")
        transcript_for_cost = session.transcript_path if session.transcript_path.exists() else log_path
        _record_phase_cost(
            scratchpad, phase.name, effective_model, attempt,
            transcript_for_cost, duration, backend="claude-pty",
        )
        return rc

    with log_path.open("w", encoding="utf-8", errors="replace") as out, \
            snap.open("rb") as stdin_file:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_file, stdout=out, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                cwd=config["project_root"],
                env=subprocess_env,
                **popen_kwargs,
            )
        except Exception as e:
            log.error(f"[{phase.name}] Popen failed: {e}")
            try:
                out.write(f"Popen failed before subprocess start: {e}\n")
                out.flush()
            except Exception:
                pass
            try:
                canonical.write_text(
                    log_path.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8",
                    errors="replace",
                )
            except Exception:
                pass
            return EXIT_ERROR

        try:
            early_complete = None
            if phase.name == "breadth":
                early_complete = lambda: _breadth_manifest_complete_reason(
                    scratchpad, phase
                )
            rc = _wait_with_heartbeat(
                proc, timeout, scratchpad, phase.name, start,
                _live_protected_phase_write_patterns(
                    scratchpad,
                    str(config.get("pipeline", "sc")),
                    phase.name,
                    config.get("_active_phase_names"),
                ),
                early_complete=early_complete,
            )
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc, grace_s=10)
            log.warning(f"[{phase.name}] timed out after {timeout}s")
            rc = -2  # timeout sentinel

    # Copy to canonical so detect_rate_limit finds latest
    try:
        canonical.write_bytes(log_path.read_bytes())
    except Exception:
        pass

    duration = time.time() - start
    log.info(f"[{phase.name}] subprocess exited rc={rc} after {duration:.0f}s")
    _record_phase_cost(scratchpad, phase.name, effective_model, attempt,
                        log_path, duration, backend=backend)
    # v2.0.3 (A2 + A4): write orphan diagnostic and archive stub files if
    # the header-only orphan-background fingerprint is detected. Diagnostic
    # is read by the retry-hint dispatcher (A4); does NOT affect gate
    # pass/fail (substance gate from Stage 1.5 is the authority).
    try:
        diag = detect_background_orphan(
            log_path, scratchpad, phase.name,
            config.get("mode", "core"),
            config.get("pipeline", "sc"),
            rc, backend=backend,
            project_root=config.get("project_root"),
        )
        if diag:
            _archive_orphan_stubs(scratchpad, phase.name, diag)
    except Exception as e:
        log.debug(f"[{phase.name}] orphan diagnostic skipped: {e}")
    # v2.0.1: surface "Not logged in" before silently retrying the same
    # unauthenticated CLI (which would exhaust the budget + degrade opaquely).
    if detect_not_logged_in(log_path):
        log.error(
            f"[{phase.name}] `claude` CLI not authenticated -- subprocess emitted "
            f"/login or 'Not logged in'. Fix with EITHER (1) run `claude` "
            f"interactively and complete `/login` (OAuth), OR (2) set "
            f"ANTHROPIC_API_KEY with a valid Anthropic Console API key. A key in "
            f"~/.claude/settings.json is NOT read as credentials. Then resume."
        )
        sys.exit(EXIT_DEGRADED)
    return rc


def print_pause_message(config_path: Path):
    """Legacy wrapper -- kept for backward compatibility."""
    display.print_rate_limit_pause(str(config_path))


def _format_artifact_size(size_bytes: int) -> str:
    """Format artifact sizes without rounding small real files to 0KB."""
    size = max(0, int(size_bytes))
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f}KB"
    return f"{size / (1024 * 1024):.1f}MB"


def _format_gate_summary(
    phase: Phase, scratchpad: Path, config: dict
) -> str:
    """One-line summary of what the gate checked — shown on phase DONE."""
    parts: list[str] = []
    # Count artifacts that matched expected_artifacts
    for pattern in phase.expected_artifacts:
        if pattern == "AUDIT_REPORT.md":
            p = Path(config["project_root"]) / "AUDIT_REPORT.md"
            if p.exists():
                parts.append(
                    f"AUDIT_REPORT.md ({_format_artifact_size(p.stat().st_size)})"
                )
            continue
        is_glob = any(ch in pattern for ch in "*?[")
        matches = list(scratchpad.glob(pattern))
        substantial = [m for m in matches if m.stat().st_size >= phase.min_artifact_bytes]
        if is_glob:
            parts.append(f"{pattern}: {len(substantial)} files")
        elif substantial:
            parts.append(
                f"{substantial[0].name} "
                f"({_format_artifact_size(substantial[0].stat().st_size)})"
            )
    if not parts:
        return ""
    return "gate: " + ", ".join(parts)


def _existing_later_phase_artifacts(
    scratchpad: Path,
    project_root: str,
    phases: list[Phase],
    phase_name: str,
    pipeline: str,
) -> list[str]:
    """Deprecated presence-based recovery check.

    Artifact recovery runs before launching a subprocess, so any later-phase
    files present at this point are, by definition, pre-existing scratchpad
    state. Treating their mere presence as current-phase overreach caused valid
    `rag_sweep` outputs to fail because old chain/verify artifacts were still
    on disk. Runtime containment is enforced by `_detect_foreign_phase_writes`,
    which compares the pre-launch snapshot with post-attempt state.

    Durable artifact ownership now lives in `_artifact_state.json`; future
    recovery logic should consult that ledger for downstream invalidation
    policy instead of quarantining files by presence.
    """
    del scratchpad, project_root, phases, phase_name, pipeline
    return []


# F7: depth-phase benign foreign-artifact patterns. Centralized so the
# post-run classifier (`_split_nonblocking_foreign_writes`) and the two
# live-containment ticks (`_wait_with_heartbeat` headless path + PTY tick)
# share a single source of truth. Chain/synthesis writes from a depth
# subprocess that finishes its own work and "naturally continues" into
# Phase 4c are quarantined post-run; live ticks must NOT kill the
# subprocess for these. Far-downstream artifacts (verify/report) stay
# blocking — a depth phase writing those is a worse boundary breach.
_DEPTH_BENIGN_FOREIGN_PATTERNS = (
    "hypotheses.md",
    "finding_mapping.md",
    "enabler_results.md",
    "chain_*.md",
    "synthesis_*.md",
    "composition_coverage.md",
)


def _is_benign_depth_foreign_artifact(name: str) -> bool:
    """F7: True iff `name` is one of depth's benign chain/synthesis leaks.

    Used by both post-run quarantine (`_split_nonblocking_foreign_writes`)
    and the live `rc=-4` abort ticks to keep the policy consistent.
    """
    from fnmatch import fnmatch
    return any(fnmatch(name, pat) for pat in _DEPTH_BENIGN_FOREIGN_PATTERNS)


def _split_nonblocking_foreign_writes(
    phase_name: str,
    foreign_writes: list[str],
) -> tuple[list[str], list[str]]:
    """Split foreign writes into quarantine-only and blocking violations."""
    from fnmatch import fnmatch

    benign: list[str] = []
    blocking: list[str] = []
    if phase_name == "report_index":
        for name in foreign_writes:
            if (
                fnmatch(name, "report_critical_high*.md")
                or fnmatch(name, "report_medium*.md")
                or fnmatch(name, "report_low_info*.md")
            ):
                benign.append(name)
            else:
                blocking.append(name)
        return benign, blocking
    if phase_name == "depth":
        # S1.2 + F7: chain/synthesis writes are benign-quarantine. The
        # depth-owned gate alone decides pass/fail. Source of truth is the
        # centralized helper above so the two live ticks stay in sync.
        for name in foreign_writes:
            if _is_benign_depth_foreign_artifact(name):
                benign.append(name)
            else:
                blocking.append(name)
        return benign, blocking
    if phase_name.startswith("inventory_chunk_"):
        # v2.0.4 (A'1): inventory tactical containment. When chunk_a's LLM
        # overruns and writes sibling chunk outputs OR the downstream merge
        # OR the next-phase semantic_invariants.md, those are benign — the
        # chunk_a-owned gate alone decides pass/fail. Sibling outputs may
        # also be ADOPTED post-quarantine via _try_adopt_inventory_sibling
        # (A'2), but adoption happens after this classification step.
        benign_pats = (
            "findings_inventory_chunk_*.md",  # sibling chunks
            "findings_inventory.md",          # downstream merge phase
            "semantic_invariants.md",         # Phase 4a.5 (invariants)
        )
        for name in foreign_writes:
            if any(fnmatch(name, p) for p in benign_pats):
                benign.append(name)
            else:
                blocking.append(name)
        return benign, blocking
    if phase_name != "breadth":
        return [], list(foreign_writes)
    benign_pats = (
        "analysis_rescan_*.md",
        "analysis_percontract_*.md",
    )
    for name in foreign_writes:
        if any(fnmatch(name, p) for p in benign_pats):
            benign.append(name)
        else:
            blocking.append(name)
    return benign, blocking


def _has_containment_failure(missing: list[Any]) -> bool:
    return any(str(item).startswith("phase containment:") for item in missing)


def _is_poc_verify_shard(phase_name: str) -> bool:
    """A PoC-writing verify shard (SC `sc_verify_*` OR L1 `verify_*`), excluding
    the queue/aggregate phases that write no PoC.

    v2.8.16: extends the v2.8.15 SC-only never-halt net to L1. After bounded
    retries such a shard may still not produce a PoC / valid blocker (the
    verifier-execution gap); its verify_<ID>.md files exist as [CODE-TRACE], so
    they ship UNPROVEN and the audit continues — the verify_aggregate
    recovery+stub net (present for both SC and L1) covers any genuinely-missing
    file. `post_verify_extract` is unaffected (it does not start with
    `verify_`).
    """
    return (
        (phase_name.startswith("sc_verify_") or phase_name.startswith("verify_"))
        and not phase_name.endswith(("_queue", "_aggregate"))
    )


def _generate_containment_retry_hint(phase_name: str, missing: list[Any]) -> str:
    lines = [
        "## RETRY HINT - phase containment violation",
        "",
        "The previous attempt wrote one or more later-phase artifacts. The "
        "offending files were quarantined by the driver. Retry ONLY the "
        f"`{phase_name}` phase and do not recreate quarantined later-phase "
        "outputs.",
        "",
        "Gate failure:",
    ]
    lines.extend(
        f"- MUST NOT recreate offending later-phase artifact from prior failure: {item}"
        for item in missing
    )
    if phase_name == "depth":
        lines.extend([
            "",
            "Depth retry boundary:",
            "- Reuse existing depth-owned outputs that are already present.",
            "- Produce or repair only missing depth-owned artifacts.",
            "- Do not create or modify any artifact outside this phase's "
            "expected output contract.",
            "- If inherited methodology asks for work outside this phase, "
            "ignore that request and finish the depth-owned outputs only.",
        ])
    elif phase_name.startswith("inventory_chunk"):
        chunk_letter = phase_name.rsplit("_", 1)[-1] if "_" in phase_name else "?"
        lines.extend([
            "",
            f"Inventory chunk retry boundary (`{phase_name}`):",
            f"- Write ONLY `findings_inventory_chunk_{chunk_letter}.md`.",
            "- Do not create, update, or repair any other scratchpad artifact.",
            "- If inherited prompt text asks for work outside this shard, "
            "ignore it and finish the shard-owned output only.",
        ])
    return "\n".join(lines) + "\n"


def _generate_generic_phase_repair_hint(
    phase: Phase,
    missing: list[Any],
    scratchpad: Path,
    project_root: str,
) -> str:
    """Fallback retry hint for phases without a specialized validator hint."""
    missing_items = [str(item) for item in (missing or [])]
    expected = list(getattr(phase, "expected_artifacts", None) or [])
    any_of = list(getattr(phase, "any_of", None) or [])
    lines = [
        f"## RETRY HINT - {phase.name} targeted repair",
        "",
        "The previous fresh Claude phase session ended, but the Python "
        "driver's disk gate or phase validator rejected the result.",
        "",
        "Repair policy:",
        "- Treat disk artifacts as the source of truth.",
        "- Repair ONLY the missing, stub, IN_PROGRESS, structurally invalid, "
        "or gate-failing artifacts listed below.",
        "- Do NOT proceed outside this phase.",
        "- Do NOT rewrite completed artifacts unless the gate failure "
        "explicitly names that artifact as invalid.",
        "- Read the original phase prompt snapshot only if needed to recover "
        "the exact phase methodology.",
        "",
        "Gate/validator failure detail:",
    ]
    if missing_items:
        lines.extend(f"- {item}" for item in missing_items)
    else:
        lines.append("- gate failed without structured detail; inspect expected outputs")
    lines.extend(["", "Expected artifact contract for this phase:"])
    if expected:
        lines.extend(f"- `{item}`" for item in expected)
    else:
        lines.append("- dynamic expected artifacts; inspect phase prompt and manifests")
    if any_of:
        lines.extend(["", "Any-of artifact alternatives:"])
        lines.extend(f"- `{item}`" for item in any_of)
    lines.extend([
        "",
        f"Scratchpad: `{scratchpad.as_posix()}`",
        f"Project root: `{Path(project_root).as_posix()}`",
        "",
        "Before emitting DONE, verify on disk that the failed artifact(s) now "
        "exist, are substantive, satisfy the phase-specific format, and do "
        "not contain unresolved placeholder text.",
    ])
    return "\n".join(lines) + "\n"


def _ensure_retry_hint(
    scratchpad: Path,
    phase: Phase,
    missing: list[Any],
    project_root: str,
) -> None:
    """Ensure the next fresh retry session receives concrete repair context."""
    try:
        if _read_retry_hint(scratchpad, phase.name):
            return
    except Exception:
        pass
    if phase.name == "attention_repair":
        _write_retry_hint(
            scratchpad,
            phase.name,
            _generate_attention_repair_retry_hint([str(item) for item in (missing or [])]),
        )
        return
    _write_retry_hint(
        scratchpad,
        phase.name,
        _generate_generic_phase_repair_hint(
            phase, missing, scratchpad, project_root
        ),
    )


def _reemit_percontract_self_exclusions(
    scratchpad: Path, recovered: list[dict]
) -> Optional[Path]:
    """Write driver-owned re-emit artifact for per-contract candidates that were
    self-excluded WITHOUT a real provided-list referent (BUG 2 / M-04).

    Each recovered candidate becomes a standard ``## Finding [PCRE-k]`` block
    tagged ``[RE-EMITTED: self-excluded without real referent]`` so inventory /
    depth consume it like any normal per-contract finding. The output file
    (``analysis_percontract_reemit.md``) is declared into ``rescan_manifest.md``
    so the EXACT rescan gate (``_rescan_manifest_exact_missing``) continues to
    accept it on resume instead of stranding on an undeclared file.

    Returns the written path, or None if nothing was written. Idempotent: a
    re-run overwrites the artifact with the current recovered set. Side-effect
    only; never raises into the caller's gate result.
    """
    if not recovered:
        return None
    out = scratchpad / "analysis_percontract_reemit.md"
    lines: list[str] = [
        "# Per-Contract Self-Exclusion Re-Emit",
        "",
        "Driver-recovered candidates that a Phase 3c per-contract agent marked",
        "as already-known/excluded WITHOUT citing a referent present in the",
        "orchestrator-provided exclusion universe (real finding ID or file:line",
        "from analysis_*.md / analysis_rescan_*.md). Re-emitted here so the",
        "suppressed bug reaches inventory/depth instead of vanishing.",
        "",
    ]
    for k, cand in enumerate(recovered, start=1):
        loc = (cand.get("location") or "").strip()
        title = (cand.get("title") or "").strip() or (
            "Self-excluded candidate without provided-list referent"
        )
        src = (cand.get("source") or "").strip()
        own = (cand.get("own_id") or "").strip()
        # ROOT FIX (from a prior run): a content-LESS re-emit (no concrete
        # location AND no mechanism/harm signal) is an unfalsifiable stub. It
        # must NOT default to Medium and reach the report body — it routes to a
        # LOW-confidence appendix disposition. A content-BEARING re-emit keeps
        # its own severity so it can be genuinely dedup'd against an existing
        # finding OR resolved into a concrete finding. Recall-safe: BOTH are
        # kept (re-emitted), neither is dropped.
        content_bearing = bool(cand.get("content_bearing"))
        if content_bearing:
            sev = (cand.get("severity") or "").strip() or "Medium"
            disposition = ""
            if not loc:
                loc = "unspecified (referent missing in provided exclusion set)"
            description = (
                "This candidate was excluded by a per-contract agent as "
                "'already found' but cited no entry present in the "
                "orchestrator-provided exclusion list, so its prior-coverage "
                "claim is unverified. It carries its own location and "
                "mechanism, so dedup it against existing findings or resolve "
                "it into a concrete finding "
                "[RE-EMITTED: self-excluded without real referent]."
            )
        else:
            # Content-less: pin to Informational + explicit marker so the
            # report-index triage routes it to APPENDIX_ONLY (LOW confidence),
            # not a Medium body finding. The candidate is still surfaced for
            # human review — it is downgraded, not dropped.
            sev = "Informational"
            disposition = " [CONTENT-LESS: APPENDIX_ONLY — no concrete location or harm]"
            if not loc:
                loc = "unspecified (content-less self-exclusion stub)"
            description = (
                "This candidate was excluded by a per-contract agent as "
                "'already found' but cited no entry present in the "
                "orchestrator-provided exclusion list AND carries no concrete "
                "location or harm of its own — an unfalsifiable stub. It is "
                "re-emitted at Informational for appendix-only human review so "
                "the suppressed candidate is not silently dropped; it must NOT "
                "be promoted to a body finding "
                "[RE-EMITTED: self-excluded without real referent]"
                "[CONTENT-LESS: APPENDIX_ONLY]."
            )
        lines.extend(
            [
                f"## Finding [PCRE-{k}]: {title}{disposition}",
                "",
                "**Verdict**: CONTESTED",
                f"**Severity**: {sev}",
                f"**Location**: {loc}",
                f"**Description**: {description}",
                "**Impact**: If the underlying bug is real, suppressing it via a "
                "belief-based exclusion would cause a true positive to be missed.",
                "**Evidence**: "
                + (f"original entry in {src}" if src else "see source")
                + (f" (agent id {own})" if own else "")
                + f": {cand.get('line_text', '').strip()}",
                "",
            ]
        )
    lines.append("<!-- PLAMEN_STATUS: COMPLETE -->")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")

    # Declare into rescan_manifest.md so the exact gate accepts the file.
    manifest = scratchpad / "rescan_manifest.md"
    try:
        mtext = manifest.read_text(encoding="utf-8", errors="replace") if (
            manifest.exists()
        ) else "# Rescan Manifest\n"
    except Exception:
        mtext = "# Rescan Manifest\n"
    if "analysis_percontract_reemit.md" not in mtext:
        if not mtext.endswith("\n"):
            mtext += "\n"
        mtext += "- analysis_percontract_reemit.md\n"
        try:
            manifest.write_text(mtext, encoding="utf-8")
        except Exception:
            pass
    log.warning(
        "[rescan] re-emitted %d self-excluded per-contract candidate(s) to "
        "analysis_percontract_reemit.md (declared into rescan_manifest.md)",
        len(recovered),
    )
    return out


def _reemit_depth_self_exclusions(
    scratchpad: Path, recovered: list[dict]
) -> Optional[Path]:
    """Write driver-owned re-emit artifact for depth candidates self-dropped
    WITHOUT an in-scope referent or on an unverified external assumption (F3).

    The depth analogue of ``_reemit_percontract_self_exclusions``. Each
    recovered candidate becomes a standard ``### Finding [DXRE-k]`` block tagged
    ``[RE-EMITTED: depth self-exclusion without in-scope referent]`` so the
    standard finding parser (and downstream inventory/chain/verify) consume it
    like any normal depth finding. The output file
    (``depth_selfexcl_reemit_findings.md``) matches the ``depth_*_findings.md``
    glob so existing consumers pick it up; the validator explicitly excludes it
    from re-scanning so re-emits are never re-flagged.

    Counterplan disposition:
    - content-bearing (own concrete location + harm) → its own severity, but at
      LOW confidence (CONTESTED verdict) so it must be dedup'd/resolved, not
      trusted as proven;
    - content-less (no concrete location or harm) → Informational + an explicit
      ``[CONTENT-LESS: APPENDIX_ONLY]`` marker so report_index routes it to an
      appendix disposition instead of flooding the client body.

    Returns the written path, or None if nothing was written. IDEMPOTENT: the
    validator skips lines already tagged ``[RE-EMITTED`` upstream, and a re-run
    overwrites the artifact with the current recovered set. Side-effect only;
    never raises into the caller's gate result.
    """
    if not recovered:
        return None
    out = scratchpad / "depth_selfexcl_reemit_findings.md"
    lines: list[str] = [
        "# Depth Self-Exclusion Re-Emit",
        "",
        "Driver-recovered candidates that a depth agent parked under a",
        "Non-Reportable / Absorbed / self-dropped section WITHOUT citing an",
        "in-scope refutation (a real finding ID or file:line), or that rested on",
        "an unverified EXTERNAL assumption ('reverts on ...', 'atomic', 'out of",
        "scope', 'assume ...', 'guaranteed by ...') to justify the drop.",
        "Re-emitted here so the suppressed candidate reaches inventory/verify",
        "instead of vanishing; verification adjudicates it downstream.",
        "",
    ]
    for k, cand in enumerate(recovered, start=1):
        loc = (cand.get("location") or "").strip()
        title = (cand.get("title") or "").strip() or (
            "Self-excluded depth candidate without in-scope referent"
        )
        src = (cand.get("source") or "").strip()
        own = (cand.get("own_id") or "").strip()
        ext = bool(cand.get("external_assumption"))
        content_bearing = bool(cand.get("content_bearing"))
        drop_basis = (
            "an unverified external assumption"
            if ext
            else "no in-scope referent"
        )
        if content_bearing:
            sev = (cand.get("severity") or "").strip() or "Medium"
            disposition = ""
            if not loc:
                loc = "unspecified (in-scope referent missing)"
            description = (
                "This candidate was self-dropped by a depth agent based on "
                f"{drop_basis}, so the drop's basis is unverified. It carries "
                "its own concrete location and mechanism, so dedup it against "
                "existing findings or resolve it into a concrete finding "
                "[RE-EMITTED: depth self-exclusion without in-scope referent]."
            )
        else:
            sev = "Informational"
            disposition = (
                " [CONTENT-LESS: APPENDIX_ONLY — no concrete location or harm]"
            )
            if not loc:
                loc = "unspecified (content-less self-exclusion stub)"
            description = (
                "This candidate was self-dropped by a depth agent based on "
                f"{drop_basis} AND carries no concrete location or harm of its "
                "own — an unfalsifiable stub. It is re-emitted at Informational "
                "for appendix-only human review so the suppressed candidate is "
                "not silently dropped; it must NOT be promoted to a body finding "
                "[RE-EMITTED: depth self-exclusion without in-scope referent]"
                "[CONTENT-LESS: APPENDIX_ONLY]."
            )
        lines.extend(
            [
                f"### Finding [DXRE-{k}]: {title}{disposition}",
                "",
                "**Verdict**: CONTESTED",
                f"**Severity**: {sev}",
                "**Confidence**: LOW",
                f"**Location**: {loc}",
                f"**Description**: {description}",
                "**Impact**: If the underlying bug is real, suppressing it via a "
                "belief-based self-exclusion would cause a true positive to be "
                "missed.",
                "**Evidence**: "
                + (f"original entry in {src}" if src else "see source")
                + (f" (agent id {own})" if own else "")
                + f": {cand.get('line_text', '').strip()}",
                "",
            ]
        )
    lines.append("<!-- PLAMEN_STATUS: COMPLETE -->")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    log.warning(
        "[depth] re-emitted %d self-excluded depth candidate(s) to "
        "depth_selfexcl_reemit_findings.md",
        len(recovered),
    )
    return out


def _run_phase_validators(
    phase: Phase,
    config: dict,
    scratchpad: Path,
    phases: list,
    rc: int,
    file_state_before: dict,
    violations_before: int = 0,
    *,
    recovery_preflight: bool = False,
) -> tuple[bool, list[str]]:
    """Run ALL phase-specific validators and side-effects after gate_passes().

    Returns (passed, missing) — the enriched gate result after all phase-
    specific checks have been applied.

    Called from BOTH attempt 1 and attempt 2 in main() to eliminate the
    retry-block duplication class (v2.3.13).  Every validator that checks
    phase output correctness MUST live here — not inline in main().
    """
    # Codex/GPT models produce more concise output. Relax byte thresholds
    # to avoid false gate failures on structurally complete but terse artifacts.
    original_min_bytes = phase.min_artifact_bytes
    if config.get("cli_backend") == "codex" and phase.min_artifact_bytes > 50:
        phase.min_artifact_bytes = max(50, phase.min_artifact_bytes // 2)
    effective_min_bytes = phase.min_artifact_bytes
    if phase.name == "depth":
        renamed = _canonicalize_depth_iter_filenames(scratchpad)
        if renamed:
            log.info(
                f"[{phase.name}] canonicalized depth iteration filenames "
                f"before gate: {', '.join(renamed)}"
            )
    passed, missing = gate_passes(scratchpad, config["project_root"], phase)
    phase.min_artifact_bytes = original_min_bytes

    # v2.8.6: Codex recon resilience for partial sub-agent failures.
    # Codex spawns collab workers that can hit capacity/thread limits,
    # leaving some artifacts at 0 bytes while others succeed.  Separate
    # core artifacts (required for pipeline) from supplementary ones
    # (enrichment that breadth agents can discover organically).
    # If only supplementary artifacts failed, write fallback content and
    # proceed instead of burning a retry on the same capacity issue.
    _RECON_SUPPLEMENTARY = {
        "attack_surface.md", "detected_patterns.md",
        "setter_list.md", "emit_list.md",
    }
    if (
        phase.name == "recon"
        and not passed
        and missing
    ):
        hard_missing = []
        soft_missing = []
        for item in missing:
            name = str(item).split()[0].split("(")[0].strip()
            if name in _RECON_SUPPLEMENTARY:
                soft_missing.append(item)
            else:
                hard_missing.append(item)
        if soft_missing and not hard_missing:
            # All failures are supplementary — write fallback content
            # and let the pipeline proceed.
            for name in _RECON_SUPPLEMENTARY:
                p = scratchpad / name
                try:
                    if not p.exists() or p.stat().st_size < effective_min_bytes:
                        title = name.replace(".md", "").replace("_", " ").title()
                        p.write_text(
                            f"# {title}\n\n"
                            "[LLM recon did not produce this artifact. "
                            "Breadth agents will discover this information "
                            "organically from source code analysis.]\n",
                            encoding="utf-8",
                        )
                except Exception:
                    pass
            passed = True
            missing = []
            log.warning(
                "[recon] supplementary artifacts degraded (non-blocking, "
                "fallback written): %s",
                "; ".join(str(x) for x in soft_missing),
            )
        elif soft_missing and hard_missing:
            # Core artifacts also failed — keep only core failures in
            # the gate result so the retry hint targets the real problem.
            missing = hard_missing

    # rc-parity check: subprocess died mid-write → file exists but corrupt.
    if rc != 0:
        parity_issues = _validate_rc_parity(
            phase, scratchpad, rc,
            backend=config.get("cli_backend", "claude"),
        )
        if parity_issues:
            passed = False
            missing = list(missing) + [
                f"rc={rc} parity: " + "; ".join(parity_issues)
            ]

    # --- phase containment: foreign-write detection ---
    # This must run before phase-specific quality gates. A later-phase write
    # means the subprocess broke its execution boundary; all other diagnostics
    # are secondary until that boundary is fixed.
    foreign_writes = _detect_foreign_phase_writes(
        scratchpad, config["project_root"], phases, phase.name,
        config["pipeline"], file_state_before
    )
    if foreign_writes:
        benign_foreign, blocking_foreign = _split_nonblocking_foreign_writes(
            phase.name, foreign_writes
        )
        # v2.0.4 (A'2) / Codex Round-2 Claim 12: attempt sibling adoption
        # BEFORE quarantine moves files to _overflow/. Inventory-scoped only
        # in A'; Phase C generalizes via declarative Phase.adoptable_outputs.
        adopted_foreign: list[str] = []
        if phase.name.startswith("inventory_chunk_"):
            for name in list(benign_foreign):
                if _try_adopt_inventory_sibling(
                    scratchpad, config["project_root"], phase.name, name
                ):
                    adopted_foreign.append(name)
        # Quarantine everything EXCEPT adopted files (adopted files stay
        # in the scratchpad root at their expected names for the owning
        # phase's resumption protocol to consume).
        quarantine_targets = [f for f in foreign_writes if f not in adopted_foreign]
        moved_foreign, failed_foreign = _quarantine_foreign_phase_writes(
            scratchpad, config["project_root"], phase.name,
            quarantine_targets
        )
        if moved_foreign:
            log.warning(
                f"[{phase.name}] quarantined foreign later-phase "
                f"artifact(s): {moved_foreign[:10]}"
            )
        if failed_foreign:
            # A rogue later-phase artifact could not be moved and is STILL live
            # at root (e.g. held open elsewhere). Do NOT complete the phase with
            # it in place — neither the resume overflow-rewind (no _overflow
            # entry) nor the reconcile (checks expected, not rogue, artifacts)
            # would catch it. Fail the gate so the driver re-runs the phase and
            # clears it.
            passed = False
            missing = list(missing) + [
                "phase containment: could not quarantine rogue later-phase "
                "artifact(s) still live at root (re-running phase to clear): "
                + ", ".join(failed_foreign[:10])
            ]
            return passed, missing
        if adopted_foreign:
            log.warning(
                f"[{phase.name}] adopted sibling artifact(s) "
                f"(kept in place, provenance recorded): {adopted_foreign[:10]}"
            )
        remaining_benign = [f for f in benign_foreign if f not in adopted_foreign]
        if remaining_benign:
            log.warning(
                f"[{phase.name}] quarantined non-blocking future-phase "
                f"artifact(s): {remaining_benign[:10]}"
            )
        if blocking_foreign:
            passed = False
            missing = list(missing) + [
                "phase containment: wrote later-phase artifacts: "
                + ", ".join(blocking_foreign[:10])
            ]
            return passed, missing

    # --- instantiate: validate spawn_manifest.md at the producer boundary ---
    if phase.name == "instantiate" and passed:
        # Gate 1: reconcile the three niche representations (BINDING MANIFEST
        # table, recon Addendum binding-rules prose, spawn_manifest table) plus
        # the detected_patterns.md flag-derived recall fallback. Repairs the
        # spawn_manifest + BINDING MANIFEST niche tables to the recall-safe
        # union; only hard-fails when repair is impossible.
        niche_consistency_issues = _validate_niche_manifest_consistency(
            scratchpad, config.get("mode", "core")
        )
        if niche_consistency_issues:
            passed = False
            missing = list(missing) + [
                "niche manifest consistency: "
                + "; ".join(niche_consistency_issues)
            ]
            _write_retry_hint(
                scratchpad,
                phase.name,
                "\n".join([
                    "## RETRY HINT - niche manifest inconsistent / unrepairable",
                    "",
                    "The `## Niche Agents` table in spawn_manifest.md must list "
                    "a Required=YES row for EVERY niche that is required by the "
                    "BINDING MANIFEST niche table, the Niche Agent Binding "
                    "Rules prose, OR a detected_patterns.md trigger flag.",
                    "",
                    "Required columns: "
                    "`Niche Agent | Trigger | Required? | Agent ID | "
                    "Expected Output`.",
                    "",
                    "Gate failure:",
                    *[f"- {issue}" for issue in niche_consistency_issues],
                    "",
                ]),
            )
        manifest_issues = _validate_spawn_manifest_schema(
            scratchpad, config.get("mode", "core")
        )
        if manifest_issues:
            passed = False
            missing = list(missing) + manifest_issues
            _write_retry_hint(
                scratchpad,
                phase.name,
                "\n".join([
                    "## RETRY HINT - spawn_manifest.md schema invalid",
                    "",
                    "Rewrite spawn_manifest.md as a markdown table whose spawned "
                    "breadth-agent rows are parseable by the pipeline gate.",
                    "",
                    "Required row contract:",
                    "- Include Template and Required columns in the header.",
                    "- Each spawned breadth agent row must be required and must "
                    "derive or explicitly name a first-pass analysis_*.md output.",
                    "- Do not put verify_*.md, analysis_rescan_*.md, "
                    "analysis_percontract_*.md, or analysis_merged_into_*.md "
                    "in first-pass breadth output rows.",
                    "",
                    "Gate failure:",
                    *[f"- {issue}" for issue in manifest_issues],
                    "",
                ]),
            )

    # --- inventory chunks: validate the chunk contract, not just file size ---
    if phase.name in (
        "inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"
    ) and passed:
        chunk_issues = _validate_inventory_chunk_structure(scratchpad, phase.name)
        if chunk_issues:
            passed = False
            missing = list(missing) + [
                "inventory chunk structure: " + "; ".join(chunk_issues)
            ]
            _write_retry_hint(
                scratchpad,
                phase.name,
                "\n".join([
                    "## RETRY HINT - inventory chunk incomplete",
                    "",
                    "Rewrite the shard output as a complete direct-execution "
                    "inventory chunk. Do not spawn subagents and do not use "
                    "shell/Python helper scripts.",
                    "",
                    "Required sections:",
                    "- ## Source Summary",
                    "- ## Master Table",
                    "- ## Per-Finding Detail",
                    "",
                    "Every master-table row needs a matching "
                    "`### Finding [CC-NN]:` detail block with Source IDs, "
                    "Severity, Location, Preferred Tag, Verdict, Root Cause, "
                    "Description, and Impact.",
                    "",
                    "`**Impact**:` is mandatory for CONFIRMED, PARTIAL, "
                    "REFUTED, and Informational findings. Precondition "
                    "Analysis is allowed only after the mandatory fields and "
                    "does not replace Impact. Do not return until every "
                    "`### Finding [CC-NN]` block contains a literal "
                    "`**Impact**:` line.",
                    "",
                    "Gate failure:",
                    *[f"- {issue}" for issue in chunk_issues],
                    "",
                ]),
            )

    # --- report_index: completeness gate ---
    if phase.name == "report_index" and passed:
        # A2 (upstream root fix): reconcile the Index Agent `## Summary` counts
        # with the Master Finding Index distinct report-ID set BEFORE the tier
        # writers dispatch. The observed shape (Summary=45 vs Master=74 distinct IDs)
        # caused tier writers to hallucinate ghost IDs filling the gap. Master is
        # the cardinality contract; this self-heals the Summary in place. It is a
        # NO-OP when consistent and never alters Master rows — so it is a repair,
        # not a halt.
        try:
            _sm_notes = validate_report_index_summary_master_parity(scratchpad)
            for _n in _sm_notes:
                log.warning(f"[report_index] {_n}")
        except Exception as _sm_exc:
            log.warning(
                f"[report_index] Summary/Master parity self-heal skipped "
                f"(non-blocking): {_sm_exc!r}"
            )
        index_issues = _check_index_completeness(
            scratchpad, config["project_root"]
        )
        if index_issues:
            repaired = _repair_report_index_dropouts(scratchpad)
            if repaired:
                log.info(
                    "[report_index] mechanically recovered "
                    f"{len(repaired)} dropped verify ID(s) into "
                    "report_index.md"
                )
                index_issues = _check_index_completeness(
                    scratchpad, config["project_root"]
                )
            # Stellar-class residual: the LLM agent indexed every VERIFY finding
            # but left some coverage-seed-only IDs (semantic-invariant refs,
            # enabler/chain IDs) unaccounted. Those are NOT body findings — the
            # surgical verify-ID repair above can't (and shouldn't) add them as
            # findings. If the residual dropout is 100% coverage-seed-only (zero
            # verify-backed), account them in the coverage ledger (DEFERRED) so
            # completeness passes — PRESERVING the LLM's consolidated index, no
            # halt, no rebuild. A residual that still contains a verify-backed ID
            # is a genuine lost finding and KEEPS the hard-fail/retry path.
            if index_issues:
                _residual = _report_index_dropped_ids(scratchpad)
                _vn = {
                    re.sub(r"-0+(\d)", r"-\1", v)
                    for v in _collect_verify_hypothesis_ids(scratchpad)
                }
                _residual_verify = [
                    d for d in _residual
                    if re.sub(r"-0+(\d)", r"-\1", d) in _vn
                ]
                if _residual and not _residual_verify:
                    _n = _backfill_report_coverage_dropouts(scratchpad)
                    log.warning(
                        f"[report_index] {len(_residual)} residual "
                        f"coverage-seed-only ID(s) (0 verify-backed findings) "
                        f"accounted via coverage backfill ({_n} ledger row(s)) "
                        f"— LLM index preserved, no halt."
                    )
                    index_issues = _check_index_completeness(
                        scratchpad, config["project_root"]
                    )
            if index_issues:
                passed = False
                missing = list(missing) + [
                    "index completeness: " + "; ".join(index_issues)
                ]
                hint = _generate_report_index_retry_hint(index_issues)
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
        # Phase E2: report_index rejects unverified queue rows.
        # Same self-heal pattern as the dropouts repair above. When the
        # LLM downgrades a finding silently (no Trust Adj. reason), the
        # driver auto-tags the row as UNRESOLVED(<upstream>) — a
        # canonical Trust Adj. token the validator accepts. Audit
        # completes; the override is recorded in severity_overrides.md
        # and surfaced in the final report appendix for human triage.
        # Severity INFLATION (LLM put higher than upstream) is NOT
        # auto-corrected — that case stays a hard fail because the risk
        # profile differs (over-flagging vs. under-flagging).
        idx_in = _validate_report_index_inputs(scratchpad)
        if idx_in:
            sev_repairs = _repair_report_index_severity_provenance(scratchpad)
            if sev_repairs:
                applied = [r for r in sev_repairs if r.get("action", "").startswith("applied")]
                if applied:
                    log.info(
                        f"[report_index] auto-tagged {len(applied)} severity "
                        f"downgrade(s) as UNRESOLVED(<upstream>); see "
                        f"severity_overrides.md for the ledger"
                    )
                idx_in = _validate_report_index_inputs(scratchpad)
        if idx_in:
            passed = False
            missing = list(missing) + idx_in
            hint = _generate_report_index_retry_hint(idx_in)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
        coverage_issues = _validate_report_coverage_accounting(scratchpad)
        if coverage_issues:
            passed = False
            missing = list(missing) + coverage_issues
        # T1-b: reject phantom UNRESOLVED stamps (verifier CONTESTED
        # mislabeled as Skeptic-Judge UNRESOLVED) at the index stage so it
        # is a clean retry, not a late report_assemble degrade.
        unresolved_auth = _check_report_index_unresolved_authenticity(scratchpad)
        if unresolved_auth:
            passed = False
            missing = list(missing) + unresolved_auth
            hint = _generate_report_index_retry_hint(unresolved_auth)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
        # T2-c: WARNING-class observability for surviving unverified
        # Critical chains (STEP 1 rule 8 should have capped them at High).
        try:
            spec_crit = _check_speculative_critical_chains(scratchpad)
        except Exception as exc:
            log.warning(f"[{phase.name}] speculative-critical check skipped: {exc}")
            spec_crit = []
        for w in spec_crit:
            log.warning(f"[{phase.name}] {w}")

    # --- report_assemble: quality gate + degraded sentinel check ---
    if phase.name == "report_assemble" and passed:
        quality_issues = _run_report_quality_gate(
            scratchpad, config["project_root"]
        )
        if quality_issues:
            passed = False
            missing = list(missing) + [
                "report quality: " + "; ".join(quality_issues)
            ]
            hint = _generate_assemble_retry_hint(
                scratchpad, config["project_root"]
            )
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
    if phase.name == "report_assemble":
        assemble_deg = _validate_assemble_not_degraded(scratchpad)
        if assemble_deg:
            passed = False
            missing = list(missing) + assemble_deg

    # --- verify_aggregate: mechanical fallback + path/parity/evidence ---
    # v2.4.3: SC verify_aggregate now routes through here too (was bypassed).
    if phase.name in ("verify_aggregate", "sc_verify_aggregate") and passed:
        if _generate_verify_core_if_missing(scratchpad):
            log.info("[verify_aggregate] verify_core.md generated mechanically")
        path_issues = _validate_cited_paths_in_verify(
            scratchpad, config.get("project_root")
        )
        if path_issues:
            log.info(f"[verify_aggregate] {path_issues[0]}")
        parity_issues = _validate_verify_files_for_queue(scratchpad, min_bytes=effective_min_bytes)
        if parity_issues:
            passed = False
            missing = list(missing) + parity_issues
        tag_issues = _validate_verify_evidence_tags(scratchpad, min_bytes=effective_min_bytes)
        if tag_issues:
            passed = False
            missing = list(missing) + tag_issues
        # v2.3.14: retry hint for verify_aggregate
        if not passed:
            all_va_issues = (parity_issues or []) + (tag_issues or [])
            hint = _generate_verify_aggregate_retry_hint(all_va_issues)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

    # --- v2.4.0: PoC classification gates (post-verify, pre-report) ---
    if phase.name in ("verify_aggregate", "sc_verify_aggregate") and passed:
        mode = config.get("mode", "core")
        poc_warnings = _validate_poc_attempt_coverage(scratchpad, mode)
        if poc_warnings:
            viol_path = scratchpad / "violations.md"
            existing = ""
            if viol_path.exists():
                try:
                    existing = viol_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
            with open(viol_path, "a", encoding="utf-8") as f:
                if not existing:
                    f.write("# Pipeline Violations\n\n")
                f.write("## PoC Attempt Coverage (v2.4.0)\n\n")
                for w in poc_warnings:
                    f.write(f"- {w}\n")
                f.write("\n")
            log.info(f"[{phase.name}] PoC attempt coverage: {len(poc_warnings)} warning(s) logged to violations.md")
        # T2-a: verifier skip-vocabulary audit (WARNING-class — never blocks).
        try:
            skip_warnings = _validate_verifier_skip_vocabulary(scratchpad)
        except Exception as exc:
            log.warning(f"[{phase.name}] skip-vocabulary audit skipped: {exc}")
            skip_warnings = []
        if skip_warnings:
            viol_path = scratchpad / "violations.md"
            existing = ""
            if viol_path.exists():
                try:
                    existing = viol_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
            with open(viol_path, "a", encoding="utf-8") as f:
                if not existing:
                    f.write("# Pipeline Violations\n\n")
                f.write("## Verifier Skip-Reason Audit (T2-a)\n\n")
                for w in skip_warnings:
                    f.write(f"- {w}\n")
                f.write("\n")
            log.warning(
                f"[{phase.name}] verifier skip-vocabulary: {len(skip_warnings)} "
                f"invalid PoC skip(s) — see verifier_skip_audit.md"
            )
        demotions = _apply_poc_fail_demotions(scratchpad, mode)
        if demotions:
            log.info(f"[{phase.name}] PoC demotions: {len(demotions)} finding(s) capped via poc_demotions.md")
        # M4: blind-first independent severity cap (anti-inflation). Only
        # ever LOWERS severity (final = min(independent, claimed)); never
        # raises, never drops a finding.
        independent_caps = _apply_independent_severity_caps(scratchpad, mode)
        if independent_caps:
            log.info(
                f"[{phase.name}] Independent severity caps: "
                f"{len(independent_caps)} finding(s) capped via "
                "independent_severity_caps.md"
            )
        # R10 demotion-side gate (mirror of the assert-side EXTERNAL-ASSUMPTION-CAP).
        undemotions = _apply_external_assumption_undemotions(scratchpad, mode)
        if undemotions:
            log.info(
                f"[{phase.name}] External-assumption un-demotions: "
                f"{len(undemotions)} finding(s) floored+stamped [UNPROVEN-EXTERNAL] "
                "(kept in body, flagged for human review) via "
                "external_assumption_undemotions.md"
            )

    # --- crossbatch: quality + full coverage + SC-mode parity/evidence ---
    if phase.name == "crossbatch" and passed:
        _write_crossbatch_manifest(scratchpad)
        appended_ids = _append_crossbatch_coverage_ledger(scratchpad)
        if appended_ids:
            log.info(
                f"[crossbatch] appended coverage ledger for "
                f"{len(appended_ids)} verifier ID(s) omitted from the agent output"
            )
        cbq_issues = _validate_crossbatch_quality(scratchpad)
        if cbq_issues:
            log.warning(
                "[crossbatch] quality (non-blocking): %s",
                "; ".join(cbq_issues),
            )
        cb_cov = _validate_crossbatch_full_coverage(scratchpad)
        if cb_cov:
            passed = False
            missing = list(missing) + cb_cov
            hint = _generate_crossbatch_retry_hint(scratchpad)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
        if config["pipeline"] != "l1":
            par = _validate_verify_files_for_queue(scratchpad, min_bytes=effective_min_bytes)
            if par:
                passed = False
                missing = list(missing) + par
            tag = _validate_verify_evidence_tags(scratchpad, min_bytes=effective_min_bytes)
            if tag:
                log.warning(
                    "[crossbatch] evidence tags (non-blocking): %s",
                    "; ".join(tag),
                )

    # --- skeptic: scope + full C/H coverage ---
    if phase.name == "skeptic" and passed:
        skeptic_issues = _validate_skeptic_scope(scratchpad)
        if skeptic_issues:
            passed = False
            missing = list(missing) + skeptic_issues
        sk_cov = _validate_skeptic_full_ch_coverage(scratchpad)
        if sk_cov:
            passed = False
            missing = list(missing) + sk_cov
        # v2.0.5 (P0.2): write the judge_decisions.json sidecar after
        # the skeptic phase passes its own validators. Downstream
        # consumers (_collect_judge_unresolved_ids, _collect_judge_
        # downgrade_map, P3 verdict_manifest, P6 report_index_candidates)
        # prefer this canonical JSON over re-parsing the markdown.
        if passed:
            try:
                from plamen_parsers import write_judge_decisions_json_sidecar
                n_decisions = write_judge_decisions_json_sidecar(scratchpad)
                if n_decisions:
                    log.info(
                        f"[skeptic] wrote judge_decisions.json with "
                        f"{n_decisions} decisions"
                    )
            except Exception as e:
                log.debug(f"[skeptic] judge_decisions.json write skipped: {e}")

    # --- graph_sweeps ---
    if phase.name == "graph_sweeps" and config["pipeline"] == "l1" and passed:
        gs_hard, gs_soft = _validate_graph_sweeps(
            scratchpad, config.get("mode", "core"),
            min_bytes=phase.min_artifact_bytes,
        )
        for w in gs_soft:
            log.warning("[graph_sweeps] %s", w)
        if gs_hard:
            passed = False
            missing = list(missing) + [
                "graph sweeps: " + "; ".join(gs_hard)
            ]

    # --- attention_repair ---
    if phase.name == "attention_repair" and passed:
        ar_hard, ar_soft = _validate_attention_repair(
            scratchpad, config.get("mode", "core")
        )
        for w in ar_soft:
            log.warning("[attention_repair] %s", w)
        if ar_hard:
            passed = False
            missing = list(missing) + [
                "attention repair: " + "; ".join(ar_hard)
            ]

    # --- invariants_p2 (Phase 4a.5 Pass 2) ---
    # SOFT validator only — Pass 2 is an enrichment phase. Returns [] on
    # all failure modes (logs warning, writes sentinel). NEVER halts.
    if phase.name == "invariants_p2" and passed and not recovery_preflight:
        _validate_invariants_pass2(scratchpad, config.get("mode", "core"))

    # --- chain_iter2 (Phase 4c iteration 2) ---
    # Same soft-only model as invariants_p2.
    if phase.name == "chain_iter2" and passed and not recovery_preflight:
        _validate_chain_iter2(scratchpad, config.get("mode", "core"))

    # --- exploration_skeptic (Phase 4b.6) ---
    # Recall-positive / additive soft phase. Validator returns [] in all
    # branches (never halts); only writes a sentinel + warning on missing
    # output. Same soft-dispatch idiom as invariants_p2/chain_iter2.
    if phase.name == "exploration_skeptic" and passed and not recovery_preflight:
        _validate_exploration_skeptic(scratchpad, config.get("mode", "core"))
        # M1: committed-invariant soft validator (always []; sentinel-only).
        _validate_invariant_commitment(scratchpad, config.get("mode", "core"))

    # --- skeptic (Phase 5.1) — M1 committed-invariant soft validator ----
    # Recall-positive / additive. The skeptic emits [CI-n] blocks on value-
    # bearing DOWNGRADE/refute; the enumeration gate later harvests them. This
    # soft validator only writes a `.ci_gap` sentinel when clears carry no CI
    # block; it always returns [] and never halts.
    if phase.name == "skeptic" and passed and not recovery_preflight:
        _validate_invariant_commitment(scratchpad, config.get("mode", "core"))

    # --- enumgap_exploration (Phase 4b.7) -------------------------------
    # Recall-positive / additive soft phase. The depth-exploration agent TRACED
    # each enumeration obligation into a real finding or a reasoned clear; now
    # promote those findings into findings_inventory.md so they flow through the
    # SAME inventory -> chain -> verify path as every other finding (the
    # obligation is EXPLORED before verify, not handed to verify raw). The
    # validator is soft (always []) and the promotion never raises — if the
    # phase degraded, no findings are promoted and the pre-existing ENUMGAP
    # candidates remain as the candidate->verify fallback.
    if phase.name == "enumgap_exploration" and passed and not recovery_preflight:
        _validate_enumgap_exploration(scratchpad, config.get("mode", "core"))
        try:
            import enumeration_gate as _eg
            _pr = _eg.promote_enumgap_exploration_to_inventory(scratchpad)
            if _pr.get("emitted"):
                log.info(
                    f"[{phase.name}] promoted {_pr['emitted']} depth-explored "
                    f"obligation finding(s) into findings_inventory.md "
                    f"(parsed {_pr['parsed']}; see "
                    "enumgap_exploration_promotion_receipt.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] enumgap exploration promotion skipped "
                f"(non-blocking): {exc}"
            )

    # --- axis_coverage (Phase 4b.8, M2) ---------------------------------
    # Recall-positive / additive soft phase. The deriver-worker interrogated each
    # GAP cell (a mechanically-hot function on a previously-unexamined risk axis)
    # and wrote a real finding or a reasoned clear; now promote those findings into
    # findings_inventory.md as AXISGAP-sourced INV-* blocks so they flow through the
    # SAME inventory -> dedup -> chain -> verify path as every other finding. The
    # validator is soft (always []) and the promotion never raises — if the phase
    # degraded, no findings are promoted and no prior finding is lost.
    if phase.name == "axis_coverage" and passed and not recovery_preflight:
        _validate_axis_coverage(scratchpad, config.get("mode", "core"))
        try:
            import enumeration_gate as _eg
            _pr = _eg.promote_axis_findings_to_inventory(scratchpad)
            # Harvest-vs-emit reconciliation (durable guard against ID-format
            # drift silently dropping candidates — the class that dark-dropped
            # 14 AXIS findings, incl. a High, pre-fix). If the artifact carries
            # finding headings but promotion parsed none, the parser/ID-format
            # has drifted; surface it LOUDLY instead of the prior silent 0.
            try:
                _axf = Path(scratchpad) / "axis_coverage_findings.md"
                _headings = 0
                if _axf.exists():
                    import re as _re
                    _headings = len(_re.findall(
                        r"(?m)^#{2,4}\s*Finding\s*\[",
                        _axf.read_text(encoding="utf-8", errors="replace")))
                if _headings > 0 and _pr.get("parsed", 0) == 0:
                    log.warning(
                        f"[{phase.name}] AXIS PROMOTION MISMATCH: {_headings} "
                        "finding heading(s) in axis_coverage_findings.md but "
                        "promotion parsed 0 — ID-format/parser drift; candidates "
                        "would be silently dropped. Investigate _EXPL_HEADING_RE."
                    )
                    try:
                        (Path(scratchpad) / "axis_coverage_promotion_receipt.md"
                         ).write_text(
                            f"[AXIS_PROMOTION_MISMATCH] {_headings} finding "
                            "heading(s) present but 0 parsed — ID-format/parser "
                            "drift. No AXIS candidate reached the inventory. Fix "
                            "the heading parser (_EXPL_HEADING_RE).\n",
                            encoding="utf-8")
                    except OSError:
                        pass
            except Exception:
                pass
            if _pr.get("emitted"):
                log.info(
                    f"[{phase.name}] promoted {_pr['emitted']} multi-axis "
                    f"coverage finding(s) into findings_inventory.md "
                    f"(parsed {_pr['parsed']}; see "
                    "axis_coverage_promotion_receipt.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] axis coverage promotion skipped "
                f"(non-blocking): {exc}"
            )

    # --- chain (Phase 4c Agent 1) anti-absorption hard gate -------------
    # v2.x Fix 2: enforce phase4c-chain-prompt rule 6 mechanically.
    # Chain Agent 1 absorbs distinct findings into super-groups (e.g. 4
    # v2.0.6 (P2.5): consumer-backstop ID-ledger gate. WARNING-only at
    # first ship (no halts) — flags references to unregistered IDs in
    # downstream consumer phases. Promotes to halt-class after one
    # fresh-audit cycle of clean telemetry per the plan's promotion path.
    if phase.name in ("sc_verify_queue", "sc_verify_aggregate",
                      "skeptic", "crossbatch", "report_index"):
        try:
            backstop_issues = _validate_consumer_ids_in_ledger(scratchpad, phase.name)
        except Exception as exc:
            log.debug(f"[{phase.name}] consumer-backstop skipped: {exc}")
            backstop_issues = []
        for w in backstop_issues:
            log.warning(f"[{phase.name}] %s", w)

    # v2.0.6 (P2.4): BLOCKING ID-ledger collision gate. Runs FIRST,
    # unconditionally on every chain / chain_agent2 attempt (not gated on
    # `passed`) — we MUST register IDs even when other gates failed,
    # otherwise attempt-1-failed → attempt-2-collision is invisible
    # (a root cause observed in a prior run).
    if phase.name in ("chain", "chain_agent2"):
        try:
            attempt_n = 2 if _read_retry_hint(scratchpad, phase.name) else 1
            ledger_collisions = _validate_id_ledger_collisions(
                scratchpad, phase.name, attempt=attempt_n
            )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] id-ledger gate skipped (non-blocking): {exc}"
            )
            ledger_collisions = []
        if ledger_collisions:
            passed = False
            missing = list(missing) + [
                "id-ledger collision: " + "; ".join(ledger_collisions[:3])
                + (f" (+{len(ledger_collisions) - 3} more)"
                   if len(ledger_collisions) > 3 else "")
            ]
            log.warning(
                f"[{phase.name}] id-ledger collision: "
                f"{len(ledger_collisions)} ID(s) re-minted with different "
                f"content — retry hint written"
            )
            hint = _generate_id_ledger_collision_retry_hint(
                ledger_collisions, phase.name
            )
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

    # N distinct same-file bugs collapsed into one Medium hypothesis), which then
    # cascade into mass exclusion when the verifier's single PoC fails.
    # On violation, emit a retry hint and fail the gate; existing retry
    # machinery re-spawns Chain Agent 1 with the hint. Hard cap = 1 retry:
    # if violations persist on attempt 2, we log warning and proceed
    # (the per-constituent demotion safety net in Fix 4 catches residuals).
    if phase.name == "chain" and passed:
        try:
            aab_issues = _validate_chain_anti_absorption(
                scratchpad, config.get("mode", "core")
            )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] anti-absorption gate skipped (non-blocking): {exc}"
            )
            aab_issues = []
        if aab_issues:
            repaired = _repair_chain_anti_absorption_splits(scratchpad)
            if repaired:
                log.info(
                    f"[{phase.name}] mechanically split {repaired} "
                    "over-absorbed constituent finding(s); preserving all "
                    "source IDs without retry"
                )
                try:
                    aab_issues = _validate_chain_anti_absorption(
                        scratchpad, config.get("mode", "core")
                    )
                except Exception as exc:
                    log.warning(
                        f"[{phase.name}] anti-absorption recheck skipped "
                        f"after repair (non-blocking): {exc}"
                    )
                    aab_issues = []
        if aab_issues:
            # Detect retry by checking for prior hint file. Hint is cleared
            # by the driver after attempt 2 finishes, so its presence here
            # means we already prompted Chain Agent 1 with the override
            # mechanism and it still violated. Cap at 1 retry.
            already_retried = bool(_read_retry_hint(scratchpad, phase.name))
            if not already_retried:
                hint = _generate_anti_absorption_retry_hint(aab_issues)
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
                passed = False
                missing = list(missing) + [
                    "anti-absorption: " + "; ".join(aab_issues[:3])
                    + (f" (+{len(aab_issues) - 3} more)" if len(aab_issues) > 3 else "")
                ]
                log.warning(
                    f"[{phase.name}] anti-absorption violations: "
                    f"{len(aab_issues)} hypothesis group(s) over-merged — "
                    f"retry hint written"
                )
            else:
                # Attempt >=2 still violating: warn and proceed (Fix 4 safety net)
                log.warning(
                    f"[{phase.name}] anti-absorption violations persist after "
                    f"retry ({len(aab_issues)} group(s)) — proceeding; "
                    f"per-constituent demotion will limit blast radius"
                )

    # --- chain baseline-not-regrouped (scaffold-resumption) INLINE AUTO-MAP --
    # The driver writes a MECHANICAL_BASELINE scaffold before Chain Agent 1
    # runs. If the agent obeys the generic RESUMPTION PROTOCOL it can skip
    # PHASE 1 grouping entirely, leaving the scaffold in place — post-inventory
    # depth findings (DA-*, etc.) then never reach hypotheses.md/finding_mapping
    # and are silently dropped. Fires on the `chain` phase only (Chain Agent 1
    # owns these files).
    #
    # FIX 1 (baseline-regroup retry -> inline auto-map): instead of RETRYING
    # Chain Agent 1 (a 42-min re-run that ALSO re-mints cosmetically-reworded
    # IDs which then trip `_validate_id_ledger_collisions` -> false-collision
    # HALT), repair the condition deterministically: append every unmapped
    # NON-REFUTED depth finding as a solo hypothesis to hypotheses.md +
    # finding_mapping.md, strip the MECHANICAL_BASELINE stamp, then PASS. This
    # mirrors the inline anti-absorption repair above (repair-then-recheck, no
    # retry). Because no attempt-2 chain run ever fires for this cause, the
    # id-ledger collision cascade cannot trigger. RECALL-SAFE: only ADDS rows.
    if phase.name == "chain" and passed:
        try:
            cbr_issues = _validate_chain_baseline_not_regrouped(
                scratchpad, config.get("mode", "core")
            )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] chain baseline-regroup gate skipped "
                f"(non-blocking): {exc}"
            )
            cbr_issues = []
        if cbr_issues:
            try:
                mapped = _auto_map_unmapped_depth_findings(scratchpad)
            except Exception as exc:
                log.warning(
                    f"[{phase.name}] chain baseline-regroup auto-map skipped "
                    f"(non-blocking): {exc}"
                )
                mapped = []
            if mapped:
                log.info(
                    f"[chain] auto-mapped {len(mapped)} unmapped non-refuted "
                    "depth finding(s) into finding_mapping.md/hypotheses.md as "
                    "solo hypotheses; no retry"
                )
            # Re-run the gate once to confirm the repair cleared it. Any
            # residual (e.g. only-REFUTED depth IDs the auto-map intentionally
            # skipped) is tolerated — never fail or retry the chain phase here.
            try:
                cbr_residual = _validate_chain_baseline_not_regrouped(
                    scratchpad, config.get("mode", "core")
                )
            except Exception as exc:
                log.warning(
                    f"[{phase.name}] chain baseline-regroup recheck skipped "
                    f"after auto-map (non-blocking): {exc}"
                )
                cbr_residual = []
            if cbr_residual:
                log.warning(
                    f"[{phase.name}] chain baseline regroup residual after "
                    f"inline auto-map ({len(cbr_residual)} signal(s)) — "
                    f"proceeding without retry (auto-map only adds non-refuted "
                    f"depth findings; residuals are intentionally excluded)"
                )

    # --- chain self-restatement (UNDER-merge) hard gate ----------------------
    # Mirror of anti-absorption: flags a chain hypothesis that merely RESTATES
    # a single constituent at a higher tier (a High-tier inflation class).
    # On violation: emit a retry hint and fail the gate (hard cap 1 retry); if
    # it persists, proceed — STEP 3 collapse + STEP 4 report carve-out are the
    # safety nets. Fires on whichever chain phase wrote chain_hypotheses.md
    # (validator returns [] when the file is absent).
    if phase.name in ("chain", "chain_agent2") and passed:
        try:
            csr_issues = _validate_chain_self_restatement(
                scratchpad, config.get("mode", "core")
            )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] chain self-restatement gate skipped "
                f"(non-blocking): {exc}"
            )
            csr_issues = []
        if csr_issues:
            already_retried = bool(_read_retry_hint(scratchpad, phase.name))
            if not already_retried:
                hint = _generate_chain_self_restatement_retry_hint(csr_issues)
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
                passed = False
                missing = list(missing) + [
                    "chain self-restatement: " + "; ".join(csr_issues[:3])
                    + (f" (+{len(csr_issues) - 3} more)"
                       if len(csr_issues) > 3 else "")
                ]
                log.warning(
                    f"[{phase.name}] chain self-restatement violations: "
                    f"{len(csr_issues)} chain(s) restate a single constituent "
                    f"— retry hint written"
                )
            else:
                log.warning(
                    f"[{phase.name}] chain self-restatement violations persist "
                    f"after retry ({len(csr_issues)} chain(s)) — proceeding; "
                    f"STEP 3 collapse / STEP 4 report carve-out will merge them"
                )

    # --- post_verify_extract (Phase 5.5) ---
    # Same soft-only model. Common case (zero [VER-NEW-*] observations)
    # is a fast no-op write of an empty summary.
    if phase.name == "post_verify_extract" and passed:
        _validate_post_verify_extract(scratchpad, config.get("mode", "core"))

    # --- semantic_dedup (L1): swap deduped queue and rebuild shard manifests ---
    if phase.name == "semantic_dedup" and passed:
        deduped = scratchpad / "verification_queue_deduped.md"
        orig = scratchpad / "verification_queue.md"
        if deduped.exists() and deduped.stat().st_size > 100:
            backup = scratchpad / "verification_queue_pre_dedup.md"
            if orig.exists():
                shutil.copy2(orig, backup)
            shutil.copy2(deduped, orig)
            rows = parse_verification_queue_rows(scratchpad)
            if rows:
                _write_queue_json_sidecar(orig, rows, kind="active")
            shards = ensure_verify_shard_manifests(scratchpad)
            shard_count = sum(len(v) for v in shards.values())
            log.info(
                f"[semantic_dedup] swapped deduped queue into "
                f"verification_queue.md; rebuilt {len(shards)} shard "
                f"manifest(s) with {shard_count} total row(s)"
            )
        else:
            log.info("[semantic_dedup] no deduped queue produced; keeping original")

    # v2.0.10 (P5): dedup decision coverage. On fresh audits the driver can
    # mechanically append conservative PASSTHROUGH rows, so that path is
    # telemetry, not a warning. Only unrepaired gaps remain warning-worthy.
    if phase.name in ("semantic_dedup", "sc_semantic_dedup"):
        try:
            dedup_cov = _check_dedup_decision_coverage(scratchpad)
        except Exception as exc:
            log.debug(f"[{phase.name}] dedup-coverage gate skipped: {exc}")
            dedup_cov = []
        if dedup_cov and scratchpad_is_fresh_audit(scratchpad):
            repaired = _repair_dedup_missing_dispositions(scratchpad, phase.name)
            if repaired:
                log.info(
                    f"[{phase.name}] mechanically appended {repaired} "
                    "PASSTHROUGH disposition row(s) for candidate pairs that "
                    "lacked explicit dedup decisions"
                )
                try:
                    dedup_cov = _check_dedup_decision_coverage(scratchpad)
                except Exception:
                    dedup_cov = []
        for w in dedup_cov:
            log.warning(f"[{phase.name}] %s", w)
        if dedup_cov:
            hint = _generate_dedup_decision_retry_hint(scratchpad, phase.name)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
            log.warning(
                f"[{phase.name}] dedup disposition coverage remains "
                "incomplete after mechanical repair; continuing "
                "warning-only to avoid dropping findings or spending a "
                "full phase retry"
            )

    # --- decisions-as-delta: build the deduped artifact from the LLM's own
    #     MERGE/GROUP decisions (faithful path). The dedup agent now emits ONLY
    #     dedup_decisions.md; the driver mechanically couples + removes via the
    #     shared engine so the survivor-superset coupling + zero-data-loss are
    #     enforced on the LLM's choices, identically to the mechanical fallback.
    #     If decisions are PASSTHROUGH/empty, this is a no-op and the pre-run
    #     passthrough copy of the deduped artifact remains as the recall-safe
    #     floor (the supplemental/fallback paths below still apply). ---
    if phase.name in ("semantic_dedup", "sc_semantic_dedup") and passed:
        try:
            n_llm = apply_llm_dedup_decisions(scratchpad, phase.name)
            if n_llm > 0:
                log.info(
                    f"[{phase.name}] driver applied {n_llm} LLM MERGE "
                    "decision(s) into the deduped artifact (survivor coupling "
                    "+ zero-data-loss enforced mechanically)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] LLM-decision apply failed (non-blocking; "
                f"passthrough/fallback remains the floor): {exc}"
            )

    # --- sc_semantic_dedup (SC): swap deduped inventory before chain analysis ---
    if phase.name == "sc_semantic_dedup" and passed:
        deduped = scratchpad / "findings_inventory_deduped.md"
        orig = scratchpad / "findings_inventory.md"
        if deduped.exists() and deduped.stat().st_size > 100:
            backup = scratchpad / "findings_inventory_pre_dedup.md"
            if orig.exists():
                if not (scratchpad / "findings_inventory_base.md").exists():
                    _write_inventory_base_snapshot(scratchpad)
                shutil.copy2(orig, backup)
            shutil.copy2(deduped, orig)
            _write_finding_records_from_inventory(scratchpad)
            log.info(
                "[sc_semantic_dedup] swapped deduped inventory into "
                "findings_inventory.md (original backed up to "
                "findings_inventory_pre_dedup.md)"
            )
        else:
            log.info("[sc_semantic_dedup] no deduped inventory produced; keeping original")

    # --- supplemental mechanical dedup for full candidate set ---
    if phase.name in ("semantic_dedup", "sc_semantic_dedup") and passed:
        try:
            n_supp = _apply_mechanical_dedup_from_pairs(
                scratchpad, phase.name, supplemental=True,
            )
            if n_supp > 0:
                log.info(
                    f"[{phase.name}] supplemental dedup merged {n_supp} "
                    f"additional pair(s) from full candidate set"
                )
                if phase.name == "semantic_dedup":
                    rows = parse_verification_queue_rows(scratchpad)
                    if rows:
                        _write_queue_json_sidecar(
                            scratchpad / "verification_queue.md",
                            rows,
                            kind="active",
                        )
                    ensure_verify_shard_manifests(scratchpad)
                elif phase.name == "sc_semantic_dedup":
                    _write_finding_records_from_inventory(scratchpad)
        except Exception as exc:
            log.warning(f"[{phase.name}] supplemental dedup failed: {exc}")

        # ZERO-DATA-LOSS bridge: record every dedup-absorbed ID as a
        # constituent of its survivor's hypothesis so the tier-writer Rule 10
        # coupling reaches the absorbed lineage in the final report. Runs AFTER
        # supplemental dedup so both LLM and mechanical absorptions are
        # captured. Always writes the dedup_absorbed_map.md sidecar (read by
        # Chain Agent 1 and the mechanical chain baseline) and, if
        # finding_mapping.md already exists, edits it in-place. Purely additive.
        try:
            n_prop = _propagate_dedup_absorbed_to_finding_mapping(scratchpad)
            if n_prop > 0:
                log.info(
                    f"[{phase.name}] propagated {n_prop} dedup-absorbed ID(s) "
                    "into dedup_absorbed_map.md (+ finding_mapping.md if "
                    "present) as survivor constituents for report coupling"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] dedup absorbed-map propagation failed "
                f"(non-blocking): {exc!r}"
            )

        # Attribution ledger: map each surviving inventory finding to its
        # contributing Source tokens (normal + generator class tokens
        # AXISGAP:/INVARIANT:). Runs AFTER all absorptions so a merged
        # survivor's ledger row reflects the provenance-preserving merge —
        # makes "did M1/M2 co-find this" a mechanical grep. Non-blocking.
        try:
            _attr = write_mechanism_attribution_ledger(scratchpad)
            if _attr.get("rows"):
                log.info(
                    f"[{phase.name}] wrote mechanism_attribution.md: "
                    f"{_attr['rows']} finding(s), {_attr.get('axisgap', 0)} "
                    f"AXISGAP-sourced, {_attr.get('invariant', 0)} "
                    "INVARIANT-sourced"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] mechanism attribution ledger failed "
                f"(non-blocking): {exc!r}"
            )

        # Fix 4: transitive-closure clustering over the surviving inventory.
        # Pairwise dedup leaves N co-referent survivors (fragmentation); this
        # collapses each same-file+function+fix-pattern, same-tier connected
        # component to ONE report finding and writes dedup_cluster_map.md — a
        # consolidation HINT the report-index STEP-1.5 reads so the writer emits
        # a single finding with a location table. Runs AFTER all absorptions so
        # it clusters the final survivor set. SC-only, non-blocking.
        if phase.name == "sc_semantic_dedup":
            try:
                n_cl = build_dedup_cluster_map(scratchpad)
                if n_cl > 0:
                    log.info(
                        f"[{phase.name}] wrote dedup_cluster_map.md: {n_cl} "
                        "co-referent cluster(s) for report-index STEP-1.5 "
                        "consolidation (location-table findings)"
                    )
                else:
                    log.info(
                        f"[{phase.name}] no co-referent clusters detected; "
                        "dedup_cluster_map.md is empty"
                    )
            except Exception as exc:
                log.warning(
                    f"[{phase.name}] cluster-map build failed "
                    f"(non-blocking): {exc!r}"
                )

    # --- recon: Slither materialization + coverage + scope_leftover ---
    if phase.name == "recon":
        # Codex apply_patch enriches recon artifact bodies without replacing
        # line 1, so the pre-pass marker survives on legitimately-populated
        # files and false-fails the content gate below (a full recon retry
        # every Codex run). Strip the line-1 marker from artifacts whose body
        # holds real content; pure [LLM TO ENRICH] placeholders keep it so the
        # gate still catches a genuinely-empty recon. No-op on Claude (Write
        # already removed the marker).
        if config.get("cli_backend", "claude") == "codex":
            try:
                _codex_stripped = strip_codex_prepass_markers(scratchpad)
                if _codex_stripped:
                    log.info(
                        "[recon] stripped pre-pass marker from Codex-enriched "
                        "artifacts: %s",
                        ", ".join(_codex_stripped),
                    )
            except Exception as exc:
                log.warning(f"[recon] codex marker strip failed: {exc!r}")
        if config["pipeline"] == "sc":
            generated = _materialize_sc_slither_flat_files(scratchpad)
            if generated:
                log.info(
                    "[recon] materialized SC Slither flat files: "
                    + ", ".join(generated)
                )
        coverage_issues = _validate_recon_coverage(
            scratchpad,
            config["project_root"],
            config.get("language", ""),
            config.get("subsystem_scope"),
            backend=config.get("cli_backend", "claude"),
            scope_file=config.get("scope_file"),
        )
        if coverage_issues:
            if config["pipeline"] == "l1":
                # L1-only: recon repeatedly leaves a few low-interest infra
                # crates (tooling/tui/database/utils) uncited even on opus-4.8
                # across all 3 hinted retries (it deprioritizes them and the
                # large L1 recon context compacts), so the hard gate just burns
                # attempts + prints a HALT panel before FC4 auto-completes
                # anyway. Downgrade to a SOFT, recall-PRESERVING check: record
                # the uncovered modules in scope_leftover.md (visible + flagged
                # for depth) and WARN, but do NOT block or retry. SC keeps the
                # hard gate (SC projects lack these infra crates and don't churn
                # here, per the deliberate SC/L1 split).
                _rec = _record_recon_uncovered_in_scope_leftover(
                    scratchpad, coverage_issues
                )
                log.warning(
                    "[recon] coverage (NON-BLOCKING, L1): recon left module(s) "
                    "uncited; auto-recorded %d in scope_leftover.md for review "
                    "instead of retrying/halting: %s",
                    _rec, "; ".join(coverage_issues),
                )
            else:
                passed = False
                missing = list(missing) + [
                    "recon coverage: " + "; ".join(coverage_issues)
                ]
        content_hard, content_soft = _validate_recon_content_structure(
            scratchpad, backend=config.get("cli_backend", "claude"),
        )
        if content_hard:
            passed = False
            missing = list(missing) + [
                "recon content: " + "; ".join(content_hard)
            ]
        if content_soft:
            log.warning(
                "[recon] narrative recon gaps (non-blocking; mechanical "
                "inventory authoritative): %s",
                "; ".join(content_soft),
            )
        # Gate 2: injectable enrichment/promotion. Flag un-enriched placeholder
        # rationales and Required=NO-while-trigger-present rows. Retry once so
        # recon re-enriches/promotes; on the SECOND failure, mechanically
        # promote the row(s) to Required=YES (recall-safe) instead of dropping.
        injectable_issues = _validate_injectable_promotion(
            scratchpad, config.get("language", ""),
        )
        if injectable_issues:
            # Self-heal INLINE (mirror the niche-manifest consistency gate):
            # mechanically promote the genuinely-triggered (or selected-but-
            # unenriched) injectable row(s) to Required=YES and PASS. Do NOT
            # fail+retry the whole recon phase. The promotion is recall-safe
            # (`_promote_injectable_rows` only ADDS a row whose trigger is
            # present in detected_patterns.md, never drops one), the LLM almost
            # never flips on a re-run, and the old retry-then-promote flow read
            # as a scary "recon gate failed, retrying" for something the gate
            # auto-fixes anyway.
            promoted = _promote_injectable_rows(
                scratchpad, config.get("language", ""),
            )
            log.info(
                "[recon] injectable promotion: promoted %d triggered "
                "injectable row(s) to Required=YES inline (recall-safe, no "
                "retry): %s",
                promoted, "; ".join(injectable_issues),
            )
        if config["pipeline"] == "l1":
            leftover_issues = _validate_scope_leftover(
                scratchpad,
                config.get("subsystem_scope"),
                backend=config.get("cli_backend", "claude"),
            )
            if leftover_issues:
                # Non-blocking: recon legitimately defers large files to depth
                # and records the full per-file reasons in scope_leftover.md.
                # Log a concise INFO (count + paths only) so it does not read
                # like a failure — the verbose reasons live in the artifact.
                _leftover_paths = ", ".join(
                    s.split(" (", 1)[0].strip() for s in leftover_issues
                )
                log.info(
                    "[scope_leftover] %d large file(s) deferred to depth "
                    "(non-blocking; reasons in scope_leftover.md): %s",
                    len(leftover_issues),
                    _leftover_paths,
                )

    # --- inventory: parity + structure + evidence ---
    if phase.name == "inventory":
        parity_issues = _validate_inventory_parity(scratchpad)
        if parity_issues:
            passed = False
            missing = list(missing) + [
                "inventory parity: " + "; ".join(parity_issues)
            ]
        structure_issues = _validate_inventory_structure(scratchpad)
        if structure_issues:
            passed = False
            missing = list(missing) + [
                "inventory structure: " + "; ".join(structure_issues)
            ]
        else:
            _validate_inventory_evidence(
                scratchpad, config["project_root"]
            )
            _write_finding_records_from_inventory(scratchpad)
            _write_inventory_base_snapshot(scratchpad)
        # v2.3.14: retry hint for inventory
        if not passed:
            inv_issues = (parity_issues or []) + (structure_issues or [])
            hint = _generate_inventory_retry_hint(inv_issues)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

    # --- location_recovery: apply recovered locations ---
    if phase.name == "location_recovery" and passed and config["pipeline"] == "l1":
        applied = _apply_location_recovery(
            scratchpad, config["project_root"]
        )
        if applied:
            _write_finding_records_from_inventory(scratchpad)
            log.info(
                f"[location_recovery] applied {len(applied)} recovered "
                "location(s) to findings_inventory.md"
            )

    # --- verify_queue: evidence filter + shard manifests + parity ---
    if phase.name == "verify_queue" and passed and config["pipeline"] == "l1":
        removed = _filter_verification_queue_by_evidence(scratchpad)
        if removed:
            log.info(
                f"[verify_queue] removed {len(removed)} evidence-invalid "
                "finding(s) before verify shards"
            )
        ensure_verify_shard_manifests(scratchpad)
        queue_issues = _validate_verification_queue_inventory_parity(scratchpad)
        if queue_issues:
            passed = False
            missing = list(missing) + [
                "verification queue parity: " + "; ".join(queue_issues)
            ]
            hint = _generate_verify_queue_retry_hint(queue_issues)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

    # --- L1/SC verify shards: completion + cited paths ---
    if phase.name in L1_VERIFY_PHASE_NAMES or phase.name in SC_VERIFY_PHASE_NAMES:
        verify_issues = _validate_verify_completion(
            scratchpad, phase.name, mode=config.get("mode", "core")
        )
        if verify_issues:
            passed = False
            missing = list(missing) + verify_issues
            hint = _generate_verify_shard_retry_hint(verify_issues)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
        path_issues = _validate_cited_paths_in_verify(
            scratchpad, config.get("project_root")
        )
        if path_issues:
            passed = False
            missing = list(missing) + [
                "verify location recovery: " + "; ".join(path_issues)
            ]

    # --- tier phases (legacy confirmation + body writers): completeness + body validation ---
    _is_tier_or_bw = (
        phase.name in (
            "report_critical_high", "report_medium", "report_low_info",
            "report_body_writer_critical_high",
            "report_body_writer_medium",
            "report_body_writer_low_info",
        )
        or re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name)
        or re.match(r"^report_body_writer_(critical_high|medium|low_info)_[a-z]$", phase.name)
    )
    if _is_tier_or_bw:
        if not phase.name.startswith("report_body_writer_"):
            tier_issues = _validate_report_tier_completeness(scratchpad, phase.name)
            if tier_issues:
                passed = False
                missing = list(missing) + tier_issues
                hint = _generate_tier_retry_hint(scratchpad, phase.name)
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
        check_phase_name = phase.name.replace("report_body_writer_", "report_")
        _content_short: list[str] = []
        body_issues = _validate_tier_body_against_manifest(
            scratchpad, check_phase_name, collect_content=_content_short
        )
        if body_issues and phase.name.startswith("report_body_writer_"):
            repaired = _repair_report_body_from_manifest(scratchpad, phase.name)
            if repaired:
                log.info(
                    f"[{phase.name}] mechanically repaired {repaired} "
                    "stale REPORT-BLOCKED body section(s) from manifest evidence"
                )
                _content_short = []
                body_issues = _validate_tier_body_against_manifest(
                    scratchpad, check_phase_name, collect_content=_content_short
                )
        if body_issues and phase.name.startswith("report_body_writer_"):
            hint = _generate_body_writer_retry_hint(scratchpad, phase.name)
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)
        if body_issues:
            passed = False
            missing = list(missing) + body_issues
        # Bucket 3: substantive Impact/PoC content shortfall is a PRODUCTIVE
        # retry trigger for the body-writer (an LLM phase that CAN enrich a thin
        # section), not a hard halt. Add it to `missing` with a delta hint so the
        # driver retries; when attempts are exhausted the FC4 safety net runs the
        # content gate (_validate_tier_body_against_manifest hard-only, which
        # EXCLUDES content), finds it clean, and auto-completes -> WARN-ship. So
        # this enriches thin write-ups across a bounded retry yet never halts.
        elif (
            _content_short
            and phase.name.startswith("report_body_writer_")
            and not _body_content_retry_exhausted(scratchpad, phase.name)
        ):
            passed = False
            missing = list(missing) + [
                "body content quality (bounded retry, then ship): "
                + "; ".join(_content_short[:5])
            ]
            _bump_body_content_retry(scratchpad, phase.name)
            _write_retry_hint(
                scratchpad, phase.name,
                _body_content_retry_hint(phase.name, _content_short),
            )

    # --- depth (L1): full validator suite ---
    if phase.name == "depth" and config["pipeline"] == "l1":
        # Canonicalize iter2/iter3 filenames BEFORE any downstream consumer
        # (validators, never-cut, parsers) globs for `_findings.md`. Without
        # this, the orchestrator's habit of dropping the `_findings` suffix
        # causes a false "no iter2 artifacts exist" verdict and re-runs the
        # whole opus depth phase.
        renamed = _canonicalize_depth_iter_filenames(scratchpad)
        if renamed:
            log.info(
                f"[{phase.name}] canonicalized iter filenames: "
                f"{', '.join(renamed)}"
            )
        # v2.6.3: synthesize lifecycle artifacts for ALL backends.
        # Codex: force-overwrite (mechanical version more reliable).
        # Claude: fill missing only (LLM may write prose-format files
        # that fail the structured validator).
        _synth_force = config.get("cli_backend") == "codex"
        synth = _synthesize_depth_lifecycle_artifacts(
            scratchpad, config["pipeline"], force=_synth_force,
            mode=config.get("mode", "core"),
        )
        if synth:
            log.info(
                f"[{phase.name}] auto-synthesized lifecycle artifacts: "
                f"{', '.join(synth)}"
            )
        offenders = _scan_for_halt_and_gatefail(
            scratchpad, violations_offset=violations_before
        )
        if offenders:
            passed = False
            missing = list(missing) + [
                "depth policy violation: " + ", ".join(offenders)
            ]
        # v2.6.3: mode-aware never-cut enforcement (mirrors SC gate)
        _mode = config.get("mode", "core")
        never_cut_missing = _assert_never_cut_artifacts(
            scratchpad, l1_never_cut_groups(_mode)
        )
        if never_cut_missing:
            passed = False
            missing = list(missing) + [
                "never-cut artifacts missing: " + ", ".join(never_cut_missing)
            ]
        # v2.6.3: checkpoint labels are Thorough-only for design-stress/
        # perturbation/skill-execution; skip checkpoint gate in Light/Core.
        if _mode == "thorough":
            checkpoint_issues = _assert_never_cut_checkpoint(scratchpad, _mode)
            if checkpoint_issues:
                passed = False
                missing = list(missing) + [
                    "never-cut checkpoint invalid: " + ", ".join(checkpoint_issues)
                ]
        exit_issues = _validate_depth_exit(scratchpad)
        if exit_issues:
            log.warning(
                "[depth] exit metadata (non-blocking): %s",
                ", ".join(exit_issues),
            )
        coverage_issues = _validate_depth_coverage(scratchpad, _mode)
        if coverage_issues:
            log.warning(
                "[depth] iter2 coverage (non-blocking): %s",
                "; ".join(coverage_issues),
            )
        notread_issues = _check_notread_priority_coverage(scratchpad, _mode)
        if notread_issues and _mode == "thorough":
            log.info(
                "[depth] notread priority queued for attention_repair: "
                + "; ".join(notread_issues)
            )
        step_trace_issues = _check_step_execution_traces(scratchpad, _mode)
        if step_trace_issues:
            log.warning(
                "[depth] step trace (non-blocking): %s",
                "; ".join(step_trace_issues),
            )
        # v2.5.0 P0: graph-artifact consumption enforcement
        graph_issues = _check_graph_artifact_consumption(
            scratchpad, _mode
        )
        if graph_issues:
            log.warning(
                "[depth] graph consumption (non-blocking): %s",
                "; ".join(graph_issues),
            )
        # v2.6.2: detect formulaic stub confidence scores
        conf_quality_issues = _validate_confidence_scores_quality(
            scratchpad, _mode
        )
        if conf_quality_issues:
            log.warning(
                f"[{phase.name}] confidence stub: "
                + "; ".join(conf_quality_issues)
            )
        # v2.6.3: iter2 is mandatory only in Thorough mode
        conf_iter2_issues: list[str] = []
        if _mode == "thorough":
            conf_iter2_issues = _validate_confidence_iter2_mandatory(scratchpad)
            # v2.8.1: stub scores above 0.7 fool the iter2 check into
            # thinking all findings are CONFIDENT.  When the stub detector
            # fires, force iter2 regardless of the score values.
            if not conf_iter2_issues and conf_quality_issues:
                # Tolerate iter2 filename drift (see
                # _validate_confidence_iter2_mandatory for the contract +
                # rationale). Keep this mirror aligned or the stub-detector
                # branch will spuriously trigger a depth retry.
                da_files = (
                    list(scratchpad.glob("depth_da_*_findings.md"))
                    + list(scratchpad.glob("depth_iter2_*_findings.md"))
                    + list(scratchpad.glob("depth_iter2_*.md"))
                    + list(scratchpad.glob("depth_iter3_*.md"))
                )
                if not da_files:
                    conf_iter2_issues = [
                        "confidence scores are formulaic stubs "
                        f"({'; '.join(conf_quality_issues)}); "
                        "iter2 mandatory to produce real per-finding analysis"
                    ]
            if conf_iter2_issues:
                passed = False
                missing = list(missing) + [
                    "confidence iter2: " + "; ".join(conf_iter2_issues)
                ]
        cov_issues = _compute_subsystem_coverage_gap(
            scratchpad, _mode, scope_file=config.get("scope_file")
        )
        if cov_issues:
            log.info(f"[{phase.name}] {cov_issues[0]}")
        # v2.3.14: retry hint for depth (L1)
        if not passed:
            depth_issues = (
                (never_cut_missing or [])
                + (conf_iter2_issues or [])
            )
            hint = _generate_depth_retry_hint(
                depth_issues,
                backend=config.get("cli_backend", "claude"),
                scratchpad=scratchpad,
            )
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

        # v2.x Fix 1: promote niche findings to findings_inventory.md (L1 parity
        # with SC branch). Idempotent — see SC branch comment for rationale.
        try:
            parsed, appended = promote_niche_to_inventory(scratchpad)
            if appended:
                log.info(
                    f"[{phase.name}] promoted {appended} niche finding(s) to "
                    f"findings_inventory.md (parsed {parsed} total; "
                    f"see niche_promotion_receipt.md)"
                )
            elif parsed:
                log.info(
                    f"[{phase.name}] niche promotion: {parsed} parsed, "
                    f"0 newly appended (already promoted on prior attempt)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] niche promotion skipped (non-blocking): {exc}"
            )
        # M1 (recall): recover blind-spot scanner findings the inventory merge
        # SCORED but silently dropped (e.g. one sibling promoted, another lost).
        # Append-only / idempotent — a pure recall leak plug.
        try:
            bs_parsed, bs_recovered = promote_blind_spot_to_inventory(scratchpad)
            if bs_recovered:
                log.info(
                    f"[{phase.name}] recovered {bs_recovered} LEAKED blind-spot "
                    f"finding(s) into findings_inventory.md (parsed {bs_parsed}; "
                    f"see blind_spot_promotion_receipt.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] blind-spot recovery skipped (non-blocking): {exc}"
            )
        # G1/G2 (recall): mechanical enumeration-coverage gate. From the static-
        # analysis graph, derive each finding's co-referencing functions and emit
        # an ENUMGAP candidate for any the finding's analysis didn't address — the
        # verify filter then adjudicates. No-op without a mechanical graph; never
        # halts. (Reuses the inventory-append + verify path; recall-safe.)
        try:
            import enumeration_gate as _eg
            _eg_res = _eg.run_enumeration_gate(scratchpad)
            if _eg_res.get("emitted"):
                log.info(
                    f"[{phase.name}] enumeration gate: {_eg_res['obligations']} "
                    f"obligation(s), emitted {_eg_res['emitted']} ENUMGAP candidate(s) "
                    "for verification (see enumeration_obligations.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] enumeration gate skipped (non-blocking): {exc}"
            )
        # Gate V (Fix A, recall): 3-axis Variant-Family Coverage — see
        # `_run_gate_v_for_phase` for the full contract. Unconditional (not
        # Thorough-only, not confidence-gated); no-op without graph/pairs;
        # never halts.
        _run_gate_v_for_phase(phase.name, scratchpad)

    # --- depth (SC): full validator suite ---
    elif phase.name == "depth" and config["pipeline"] == "sc":
        # Same canonicalization as the L1 branch — must run BEFORE any
        # downstream consumer globs for `_findings.md`.
        renamed = _canonicalize_depth_iter_filenames(scratchpad)
        if renamed:
            log.info(
                f"[{phase.name}] canonicalized iter filenames: "
                f"{', '.join(renamed)}"
            )
        # v2.6.3: synthesize for all backends (same rationale as L1)
        _synth_force_sc = config.get("cli_backend") == "codex"
        synth = _synthesize_depth_lifecycle_artifacts(
            scratchpad, config["pipeline"], force=_synth_force_sc,
            mode=config.get("mode", "core"),
        )
        if synth:
            log.info(
                f"[{phase.name}] auto-synthesized lifecycle artifacts: "
                f"{', '.join(synth)}"
                )
        offenders = _scan_for_halt_and_gatefail(
            scratchpad, violations_offset=violations_before
        )
        if offenders:
            passed = False
            missing = list(missing) + [
                "depth policy violation: " + ", ".join(offenders)
            ]
        never_cut_missing = _assert_never_cut_artifacts(
            scratchpad, sc_never_cut_groups(config.get("mode", "core"))
        )
        if never_cut_missing:
            passed = False
            missing = list(missing) + [
                "never-cut artifacts missing: " + ", ".join(never_cut_missing)
            ]
        # S1.1: existence-only is not enough — a 79-byte WRITE-THEN-VERIFY
        # reservation or a SYNTHESIZED confidence stub passes the check above.
        # Reject groups whose only present member is a stub.
        never_cut_stubs = _validate_depth_artifact_substance(
            scratchpad, config.get("mode", "core"), pipeline="sc"
        )
        if never_cut_stubs:
            passed = False
            missing = list(missing) + [
                "never-cut artifacts are stubs: " + "; ".join(never_cut_stubs)
            ]
        # v2.4.7: L1 checkpoint validator removed from SC gate — SC prompt
        # writes checkpoint_postdepth.md (not the L1 filename), and the
        # artifact check above already enforces NEVER-CUT via individual files.
        semantic_gap_issues = _validate_semantic_gap_niche(
            scratchpad, config.get("mode", "core")
        )
        if semantic_gap_issues:
            passed = False
            missing = list(missing) + [
                "semantic-gap niche: " + "; ".join(semantic_gap_issues)
            ]
        iter_issues = _validate_depth_iterations(
            scratchpad, config.get("mode", "core")
        )
        if iter_issues:
            passed = False
            missing = list(missing) + [
                "depth iteration invariant: " + "; ".join(iter_issues)
            ]
        sc_cov_issues = _validate_sc_subsystem_coverage(
            scratchpad, config.get("mode", "core"),
            scope_file=config.get("scope_file"),
            project_root=config.get("project_root"),
        )
        if sc_cov_issues:
            passed = False
            missing = list(missing) + [
                "SC subsystem coverage: " + "; ".join(sc_cov_issues)
            ]
        coverage_issues = _validate_depth_coverage(
            scratchpad, config.get("mode", "core")
        )
        if coverage_issues:
            log.warning(
                "[depth] iter2 coverage (non-blocking): %s",
                "; ".join(coverage_issues),
            )
        notread_issues = _check_notread_priority_coverage(
            scratchpad, config.get("mode", "core")
        )
        if notread_issues and config.get("mode") == "thorough":
            log.info(
                "[depth] notread priority queued for attention_repair: "
                + "; ".join(notread_issues)
            )
        step_trace_issues = _check_step_execution_traces(
            scratchpad, config.get("mode", "core")
        )
        if step_trace_issues:
            log.warning(
                "[depth] step trace (non-blocking): %s",
                "; ".join(step_trace_issues),
            )
        # v2.5.0 P0: graph-artifact consumption enforcement
        graph_issues = _check_graph_artifact_consumption(
            scratchpad, config.get("mode", "core")
        )
        if graph_issues:
            log.warning(
                "[depth] graph consumption (non-blocking): %s",
                "; ".join(graph_issues),
            )
        # v2.6.2: detect formulaic stub confidence scores
        _sc_mode = config.get("mode", "core")
        conf_quality_issues = _validate_confidence_scores_quality(
            scratchpad, _sc_mode
        )
        if conf_quality_issues:
            log.warning(
                f"[{phase.name}] confidence stub: "
                + "; ".join(conf_quality_issues)
            )
        # v2.6.3: iter2 is mandatory only in Thorough mode
        conf_iter2_issues: list[str] = []
        if _sc_mode == "thorough":
            conf_iter2_issues = _validate_confidence_iter2_mandatory(scratchpad)
            # v2.8.1: stub scores above 0.7 fool the iter2 check — see L1 block
            if not conf_iter2_issues and conf_quality_issues:
                # Tolerate iter2 filename drift (see
                # _validate_confidence_iter2_mandatory for the contract +
                # rationale). Keep this mirror aligned or the stub-detector
                # branch will spuriously trigger a depth retry.
                da_files = (
                    list(scratchpad.glob("depth_da_*_findings.md"))
                    + list(scratchpad.glob("depth_iter2_*_findings.md"))
                    + list(scratchpad.glob("depth_iter2_*.md"))
                    + list(scratchpad.glob("depth_iter3_*.md"))
                )
                if not da_files:
                    conf_iter2_issues = [
                        "confidence scores are formulaic stubs "
                        f"({'; '.join(conf_quality_issues)}); "
                        "iter2 mandatory to produce real per-finding analysis"
                    ]
            if conf_iter2_issues:
                passed = False
                missing = list(missing) + [
                    "confidence iter2: " + "; ".join(conf_iter2_issues)
                ]
        cov_issues = _compute_subsystem_coverage_gap(
            scratchpad, _sc_mode, scope_file=config.get("scope_file")
        )
        if cov_issues:
            log.info(f"[{phase.name}] {cov_issues[0]}")
        # v2.3.14: retry hint for depth (SC)
        if not passed:
            depth_issues = (
                (never_cut_missing or [])
                + (semantic_gap_issues or [])
                + (iter_issues or [])
                + (sc_cov_issues or [])
                + (conf_iter2_issues or [])
            )
            hint = _generate_depth_retry_hint(
                depth_issues,
                backend=config.get("cli_backend", "claude"),
                scratchpad=scratchpad,
            )
            if hint:
                _write_retry_hint(scratchpad, phase.name, hint)

        # v2.x Fix 1: promote niche findings to findings_inventory.md.
        # Niche agents run during depth iter 1 but write to niche_*_findings.md
        # only. Without this promotion, niche findings reach chain analysis via
        # chain_summaries_compact.md but never enter findings_inventory.md and
        # are silently excluded from verification_queue.md.
        # Idempotent: safe across retries (tracked via niche_promotion_receipt).
        try:
            parsed, appended = promote_niche_to_inventory(scratchpad)
            if appended:
                log.info(
                    f"[{phase.name}] promoted {appended} niche finding(s) to "
                    f"findings_inventory.md (parsed {parsed} total; "
                    f"see niche_promotion_receipt.md)"
                )
            elif parsed:
                log.info(
                    f"[{phase.name}] niche promotion: {parsed} parsed, "
                    f"0 newly appended (already promoted on prior attempt)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] niche promotion skipped (non-blocking): {exc}"
            )
        # M1 (recall): recover blind-spot scanner findings the inventory merge
        # SCORED but silently dropped (e.g. one sibling promoted, another lost).
        # Append-only / idempotent — a pure recall leak plug.
        try:
            bs_parsed, bs_recovered = promote_blind_spot_to_inventory(scratchpad)
            if bs_recovered:
                log.info(
                    f"[{phase.name}] recovered {bs_recovered} LEAKED blind-spot "
                    f"finding(s) into findings_inventory.md (parsed {bs_parsed}; "
                    f"see blind_spot_promotion_receipt.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] blind-spot recovery skipped (non-blocking): {exc}"
            )
        # G1/G2 (recall): mechanical enumeration-coverage gate. From the static-
        # analysis graph, derive each finding's co-referencing functions and emit
        # an ENUMGAP candidate for any the finding's analysis didn't address — the
        # verify filter then adjudicates. No-op without a mechanical graph; never
        # halts. (Reuses the inventory-append + verify path; recall-safe.)
        try:
            import enumeration_gate as _eg
            _eg_res = _eg.run_enumeration_gate(scratchpad)
            if _eg_res.get("emitted"):
                log.info(
                    f"[{phase.name}] enumeration gate: {_eg_res['obligations']} "
                    f"obligation(s), emitted {_eg_res['emitted']} ENUMGAP candidate(s) "
                    "for verification (see enumeration_obligations.md)"
                )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] enumeration gate skipped (non-blocking): {exc}"
            )
        # Gate V (Fix A, recall): 3-axis Variant-Family Coverage — see
        # `_run_gate_v_for_phase` for the full contract. Unconditional (not
        # Thorough-only, not confidence-gated); no-op without graph/pairs;
        # never halts.
        _run_gate_v_for_phase(phase.name, scratchpad)

    # --- late containment check removed (v2.6.2) ---
    # The early containment check (line ~1694) already detects all LLM-written
    # foreign artifacts using the pre-subprocess file_state_before snapshot.
    # This late check was redundant for LLM overstepping and false-positived
    # on files legitimately written by the driver's own Python post-processing
    # (e.g., ensure_verify_shard_manifests in semantic_dedup/verify_queue).
    # Quarantine of LLM-written foreign files is handled by the early check.

    # --- Obligation + attention gates (Steps 5-8 of recall-recovery plan) ---
    # These are telemetry/repair inputs unless a phase explicitly promotes one
    # to a hard validator. They snapshot gaps to *_gap.md artifacts and should
    # not be logged as phase-failure warnings.
    if phase.name == "breadth":
        opengrep_issues = _check_opengrep_obligation_coverage(
            scratchpad, config.get("mode", "core")
        )
        if opengrep_issues:
            log.info(
                "[breadth] opengrep obligation telemetry: %s",
                "; ".join(opengrep_issues),
            )
    if phase.name == "depth":
        fs_issues = _check_function_summary_obligation(
            scratchpad, config.get("mode", "core")
        )
        if fs_issues:
            log.warning(
                "[depth] function_summary obligation (non-blocking): %s",
                "; ".join(fs_issues),
            )
        pert_issues = _check_perturbation_block_per_finding(scratchpad)
        if pert_issues:
            log.warning(
                "[depth] perturbation block (non-blocking): %s",
                "; ".join(pert_issues),
            )
        # PDE check on niche output runs at depth-phase completion because
        # niche-semantic-consistency typically runs in parallel with depth
        # iter-1 and its output is available by the time depth's validators
        # fire. Vacuous-pass when the niche file is absent.
        pde_issues = _check_pde_section_present(scratchpad)
        if pde_issues:
            log.warning(
                "[depth] PDE niche (non-blocking): %s",
                "; ".join(pde_issues),
            )
        # F3: detect belief-based depth self-exclusion and re-emit any candidate
        # dropped without an in-scope referent OR on an unverified external
        # assumption. Depth analogue of the Phase 3c per-contract net. SOFT
        # diagnostic (never hard-fails); the re-emit side effect fires whenever a
        # referent-less/external-assumption drop is found so a real bug can never
        # vanish via a self-invented exclusion. Best-effort / degrade-not-halt.
        try:
            dsx_warnings, dsx_recovered = _validate_depth_self_exclusion(
                scratchpad
            )
        except Exception as exc:  # never let a parse bug block a clean run
            dsx_warnings, dsx_recovered = [], []
            log.warning(
                "[depth] depth self-exclusion check skipped "
                f"(non-blocking): {exc}"
            )
        if dsx_warnings:
            log.warning(
                "[depth] depth self-exclusion (non-blocking): %s",
                "; ".join(dsx_warnings),
            )
        if dsx_recovered:
            try:
                _reemit_depth_self_exclusions(scratchpad, dsx_recovered)
            except Exception as exc:
                log.warning(
                    "[depth] depth self-exclusion re-emit skipped "
                    f"(non-blocking): {exc}"
                )

    if phase.name == "rescan":
        # BUG 2 / M-04: detect belief-based per-contract self-exclusion and
        # re-emit any candidate excluded without a real provided-list referent.
        # SOFT diagnostic (never hard-fails); the re-emit side effect is
        # unconditional whenever a referent-less exclusion is found so a real
        # bug can never vanish via a self-invented exclusion.
        try:
            sx_warnings, sx_recovered = _validate_percontract_self_exclusion(
                scratchpad
            )
        except Exception as exc:  # never let a parse bug block a clean run
            sx_warnings, sx_recovered = [], []
            log.warning(
                "[rescan] per-contract self-exclusion check skipped "
                f"(non-blocking): {exc}"
            )
        if sx_warnings:
            log.warning(
                "[rescan] per-contract self-exclusion (non-blocking): %s",
                "; ".join(sx_warnings),
            )
        if sx_recovered:
            try:
                _reemit_percontract_self_exclusions(scratchpad, sx_recovered)
            except Exception as exc:
                log.warning(
                    "[rescan] per-contract self-exclusion re-emit skipped "
                    f"(non-blocking): {exc}"
                )

    # --- canonical identity sidecars (non-mutating, no-drop) ---
    if passed and phase.name in {
        "breadth", "rescan",
        "inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c",
        "inventory", "depth", "attention_repair", "rag_sweep",
        "sc_semantic_dedup", "semantic_dedup",
        "chain", "chain_agent2", "chain_iter2",
        "post_verify_extract", "skeptic", "crossbatch", "report_index",
    }:
        try:
            mapped = _write_canonical_finding_identity_map(
                scratchpad,
                phase_name=phase.name,
                pipeline=config.get("pipeline", ""),
                mode=config.get("mode", ""),
            )
            log.info(
                f"[{phase.name}] canonical finding identity map refreshed "
                f"({mapped} finding block(s)); source artifacts preserved"
            )
        except Exception as exc:
            log.warning(
                f"[{phase.name}] canonical finding identity map skipped "
                f"(non-blocking): {exc}"
            )

    return passed, missing


_PREPASS_MARKER_GATE_SUBSTR = "still has pre-pass overwrite marker"


def _try_recon_prepass_marker_degrade(
    scratchpad: Path,
    config: dict,
    missing: list,
) -> tuple[bool, list]:
    """LAST-RESORT recon degrade: promote complete pre-pass content to canonical.

    Called ONLY after the recon worker pool, the direct-isolated-recon
    fallback, AND every retry attempt have all run and the content gate STILL
    fails. When the recon content-structure hard failures are SOLELY the
    "{name} still has pre-pass overwrite marker" items (i.e. the marker
    survived because a worker never reached COMPLETE, but the mechanical
    pre-pass tables in function_list.md / state_variables.md are themselves
    complete), strip the line-1 marker. That promotes the regex-complete
    pre-pass content to the canonical handoff and lets the gate pass, so the
    pipeline continues with degraded-but-usable recon rather than retrying
    forever.

    Recall-safe: the pre-pass artifacts are regex-complete (every function /
    state var), just not LLM-enriched. strip_codex_prepass_markers is
    backend-agnostic and never strips a pure [LLM TO ENRICH] placeholder, so a
    genuinely-empty recon still fails the gate.

    Does NOT fire when there is ANY non-marker recon hard failure (e.g. a
    missing Operational Implications / Key Invariants section, or a too-small
    recon_summary) — those are real gaps, not a survived-marker artifact.

    Returns (degraded_passed, new_missing):
      - (True, [])    -> degrade applied and the gate now passes; treat as PASS
      - (False, missing) -> not applicable (or did not clear the gate); caller
                            keeps its existing missing list and halt/degrade path
    """
    # Only meaningful for the recon content gate. Identify the recon-content
    # hard failures the gate surfaced (they are prefixed "recon content: ").
    recon_content_msgs: list[str] = []
    other_recon_msgs: list[str] = []
    for m in missing:
        sm = str(m)
        if sm.startswith("recon content:"):
            recon_content_msgs.append(sm)
        else:
            other_recon_msgs.append(sm)

    if not recon_content_msgs:
        return False, missing  # gate did not fail on recon content at all

    if other_recon_msgs:
        # Some OTHER recon gate failed too (e.g. "recon coverage: ...", a
        # missing expected artifact, a containment violation). Those are real
        # gaps the marker strip cannot fix — do not degrade.
        log.warning(
            "[recon] marker-degrade declined: non-content recon gate "
            "failure(s) present (%s)",
            "; ".join(other_recon_msgs),
        )
        return False, missing

    # Re-derive the authoritative hard-failure set straight from the validator
    # (the missing[] strings are joined with "; " so we cannot reliably split
    # them; the validator gives us the structured list).
    try:
        content_hard, _content_soft = _validate_recon_content_structure(
            scratchpad, backend=config.get("cli_backend", "claude"),
        )
    except Exception as exc:
        log.warning(f"[recon] marker-degrade pre-check failed: {exc!r}")
        return False, missing

    if not content_hard:
        return False, missing  # nothing to degrade (already clean)

    non_marker_hard = [
        h for h in content_hard if _PREPASS_MARKER_GATE_SUBSTR not in str(h)
    ]
    if non_marker_hard:
        # Real recon gaps remain (missing sections, etc.) — NOT a pure
        # survived-marker situation. Do not degrade.
        log.warning(
            "[recon] marker-degrade declined: non-marker recon hard "
            "failure(s) present (%s)",
            "; ".join(str(h) for h in non_marker_hard),
        )
        return False, missing

    # Sole hard failures are survived pre-pass markers. Strip them.
    try:
        stripped = strip_codex_prepass_markers(scratchpad)
    except Exception as exc:
        log.warning(f"[recon] marker-degrade strip failed: {exc!r}")
        return False, missing

    if not stripped:
        # Marker survived but the body is a pure placeholder/empty — the strip
        # helper correctly refused. This is a genuinely-empty recon, not a
        # degrade candidate.
        log.warning(
            "[recon] marker-degrade declined: artifacts still carry the "
            "pre-pass marker but their bodies are empty/placeholder "
            "(genuine recon failure, not a survived-marker artifact)"
        )
        return False, missing

    # Re-validate; if the only thing wrong was the marker, the gate now passes.
    try:
        recheck_hard, _recheck_soft = _validate_recon_content_structure(
            scratchpad, backend=config.get("cli_backend", "claude"),
        )
    except Exception as exc:
        log.warning(f"[recon] marker-degrade recheck failed: {exc!r}")
        return False, missing

    if recheck_hard:
        log.warning(
            "[recon] marker-degrade stripped %s but recon content gate still "
            "fails: %s",
            ", ".join(stripped), "; ".join(str(h) for h in recheck_hard),
        )
        return False, missing

    log.warning(
        "[recon] DEGRADED to pre-pass content: recon never produced an "
        "LLM-enriched canonical handoff after all attempts, but the mechanical "
        "pre-pass artifacts are regex-complete; stripped the pre-pass overwrite "
        "marker from %s and promoted that content to canonical. Downstream "
        "phases continue with degraded-but-usable recon.",
        ", ".join(stripped),
    )
    return True, []


def _phase_has_fresh_expected_artifact(
    phase: Phase,
    scratchpad: Path,
    project_root: str,
    before_state: dict[str, tuple[int, int]],
) -> bool:
    """Return True if this attempt wrote a substantial expected artifact.

    Empty stdio is a weak failure signal. It catches real API/resumption
    misfires, but some Claude runs can still produce valid artifacts while
    leaving a tiny log. Use file-state deltas to avoid retrying a phase that
    actually wrote fresh, gate-checkable output.
    """
    from fnmatch import fnmatch

    patterns = list(phase.expected_artifacts or [])
    if not patterns:
        return False
    min_size = int(getattr(phase, "min_artifact_size_bytes", 100) or 100)
    after_state = _snapshot_file_state(scratchpad, project_root)
    for name, meta in after_state.items():
        if meta[1] < min_size:
            continue
        if before_state.get(name) == meta:
            continue
        for pattern in patterns:
            key = "../AUDIT_REPORT.md" if pattern == "AUDIT_REPORT.md" else pattern
            if fnmatch(name, key):
                return True
    return False


def _purge_scratchpad(scratchpad: Path, config: dict) -> None:
    """Delete all generated artifacts in the scratchpad and reset checkpoint."""
    import shutil

    # Close the log file handler so Windows releases the file lock.
    for handler in log.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.close()
            log.removeHandler(handler)

    for item in scratchpad.iterdir():
        if item.name.startswith("."):
            continue
        if item.name == "config.json":
            continue
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)
        except PermissionError:
            pass


# Plamen-OWNED prior-run artifacts that must NOT survive a --fresh restart:
# prior audit reports + RCA notes are literal answer keys, and Plamen-generated
# fuzz-harness dirs (`.medusa-tests`) hand-encode known bugs with buggy/fixed
# toggles. Either one primes a "fresh" discovery run if recon ingests it (recon
# compiles/Slithers the whole project tree, which pulls harness contracts into
# the inventory). `--fresh` wipes only the scratchpad, so without this these
# survive in project_root across every "fresh" run.
_FRESH_ARCHIVE_FILE_GLOBS = (
    "AUDIT_REPORT*.md",
    "*_RCA.md",
    "*-RCA.md",
    "CONSOLIDATION-FIX-NOTES.md",
)
_FRESH_ARCHIVE_DIR_NAMES = (".medusa-tests",)


def _archive_prior_audit_artifacts(project_root: Path) -> "Optional[Path]":
    """On --fresh, MOVE Plamen-owned prior-run outputs (audit reports, RCA
    notes, generated fuzz harnesses) out of project_root into a DOT-prefixed
    sibling archive dir, so a fresh audit is a genuine clean slate and recon
    cannot ingest a prior report or a pre-authored harness that encodes the
    answers. Moves — never deletes — so nothing is lost (recall-safe).

    The archive is dot-prefixed (`.plamen_archive_<ts>`) one level up: every
    build/Slither/recon-inventory walk skips dot-dirs, so it can never be
    re-ingested even when project_root's parent IS the Foundry build root.

    Best-effort: never raises into the caller. Returns the archive dir if
    anything was moved, else None."""
    import shutil

    try:
        proj = Path(project_root)
        if not proj.is_dir():
            return None
        targets: list[Path] = []
        for pat in _FRESH_ARCHIVE_FILE_GLOBS:
            targets.extend(p for p in proj.glob(pat) if p.is_file())
        for name in _FRESH_ARCHIVE_DIR_NAMES:
            d = proj / name
            if d.is_dir():
                targets.append(d)
        if not targets:
            return None
        archive = proj.parent / f".plamen_archive_{int(time.time())}"
        archive.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None

    moved = 0
    for src in targets:
        try:
            dst = archive / src.name
            if dst.exists():
                dst = archive / f"{src.stem}_{moved}{src.suffix}"
            shutil.move(str(src), str(dst))
            moved += 1
        except Exception:
            continue
    if moved == 0:
        try:
            archive.rmdir()
        except Exception:
            pass
        return None
    return archive


def _archive_stale_mismatched_checkpoint(
    scratchpad: Path,
    checkpoint: "Checkpoint",
    config: dict,
    mode: str,
    exc: Exception,
) -> "Optional[Checkpoint]":
    """Recover from a stale checkpoint whose phases are outside the active graph.

    Triggered when `_reconcile_completed_checkpoint_artifacts` raises because
    the loaded `_v2_checkpoint.json` references phases not present in the active
    mode's graph — the classic "finished Thorough run, then a new Core audit in
    the same scratchpad" situation. That is a mode/graph MISMATCH, not
    corruption, and must never hard-halt a fresh start.

    On a recoverable mismatch: archive the stale checkpoint to
    `_v2_checkpoint.<old_mode>.bak-<ts>.json` (best-effort; falls back to delete)
    and return a fresh empty `Checkpoint` bound to `config` (already saved).
    Returns None when the error is NOT a recoverable mismatch (genuine
    corruption / empty checkpoint / unrelated RuntimeError) — the caller must
    then hard-exit. Same-mode resume never reaches here (no foreign phases →
    no exception).
    """
    if "outside the active graph" not in str(exc):
        return None
    if not (checkpoint.completed or checkpoint.degraded):
        return None
    old_mode = "unknown"
    try:
        if isinstance(checkpoint.config, dict):
            old_mode = str(checkpoint.config.get("mode") or "unknown")
    except Exception:
        pass
    ckpt_file = scratchpad / "_v2_checkpoint.json"
    archived = ckpt_file.with_suffix(f".{old_mode}.bak-{int(time.time())}.json")
    try:
        if ckpt_file.exists():
            ckpt_file.rename(archived)
    except Exception:
        try:
            if ckpt_file.exists():
                ckpt_file.unlink()
        except Exception:
            pass
    log.warning(
        f"[checkpoint] stale checkpoint (mode={old_mode}) references phases "
        f"outside the active '{mode}' graph; archived to {archived.name} and "
        f"starting fresh. ({exc})"
    )
    fresh = Checkpoint()
    fresh.config = config
    fresh.save(scratchpad)
    return fresh


def _prompt_halt_resume_choice(
    checkpoint: Checkpoint,
    scratchpad: Path,
    phase_name: str,
    config_path: Path,
) -> bool:
    """Return True to resume after Esc, False to stop and preserve checkpoint."""
    checkpoint.save(scratchpad)
    display.print_halt_prompt(phase_name, str(config_path))
    if display.wait_halt_choice():
        display.print_halt_resume()
        display.graceful_stop.requested = False
        return True
    display.graceful_stop.requested = False
    return False


class _SpinnerSafeStreamHandler(logging.StreamHandler):
    """stderr logger that does not write into an active spinner line."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            display._clear_spinner()
        except Exception:
            pass
        super().emit(record)


_RUN_LOCK_NAME = ".plamen_run.lock"
_RUN_LOCK_FD: Optional[int] = None
_RUN_LOCK_PATH: Optional[Path] = None


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def _release_run_lock() -> None:
    global _RUN_LOCK_FD, _RUN_LOCK_PATH
    path = _RUN_LOCK_PATH
    fd = _RUN_LOCK_FD
    _RUN_LOCK_FD = None
    _RUN_LOCK_PATH = None
    if fd is not None:
        try:
            os.close(fd)
        except Exception:
            pass
    if path is not None:
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
            if int(current.get("pid", -1)) == os.getpid():
                path.unlink(missing_ok=True)
        except Exception:
            pass


def _acquire_run_lock(
    scratchpad: Path,
    config_path: Path,
    *,
    force: bool = False,
) -> tuple[bool, str]:
    """Atomically prevent multiple drivers from writing one scratchpad."""
    global _RUN_LOCK_FD, _RUN_LOCK_PATH
    lock = scratchpad / _RUN_LOCK_NAME
    payload = {
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config_path": str(config_path),
    }
    for _ in range(2):
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
            _RUN_LOCK_FD = fd
            _RUN_LOCK_PATH = lock
            atexit.register(_release_run_lock)
            return True, ""
        except FileExistsError:
            try:
                existing = json.loads(lock.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
            pid = int(existing.get("pid") or -1)
            if not _pid_is_running(pid):
                try:
                    lock.unlink(missing_ok=True)
                    continue
                except Exception as exc:
                    return False, (
                        f"stale run lock exists but could not be removed: "
                        f"{lock} ({exc!r})"
                    )
            started = existing.get("started_at", "unknown")
            old_cfg = existing.get("config_path", "unknown")
            if force:
                return False, (
                    f"--force refused: another Plamen driver is still using "
                    f"this scratchpad (pid={pid}, started_at={started}, "
                    f"config={old_cfg}). Stop that run first, then retry."
                )
            return False, (
                f"another Plamen driver is already using this scratchpad "
                f"(pid={pid}, started_at={started}, config={old_cfg}). "
                "Do not run fresh/resume twice against the same .scratchpad."
            )
        except Exception as exc:
            return False, f"could not create run lock {lock}: {exc!r}"
    return False, f"could not acquire run lock {lock}"


# Configured-language -> expected dominant production source suffix. Mirrors the
# recon_prepass LANG_DISPATCH suffix map. Used by the STEP 2A startup config
# validator to catch a misrouted run (e.g. language=evm pointed at a Rust crate)
# BEFORE any worker pool spawns, rather than after a multi-hour misroute.
_LANG_EXPECTED_SUFFIX: dict[str, tuple[str, ...]] = {
    "evm": (".sol",),
    "solana": (".rs",),
    "soroban": (".rs",),
    "aptos": (".move",),
    "sui": (".move",),
    "daml": (".daml",),
}

# Reverse map: a source suffix -> the languages it can indicate. Used to phrase
# the actionable halt message ("found N .rs -> re-run with --language solana").
_SUFFIX_TO_LANGS: dict[str, tuple[str, ...]] = {
    ".sol": ("evm",),
    ".rs": ("solana", "soroban"),
    ".move": ("aptos", "sui"),
    ".daml": ("daml",),
}

_LANG_GATE_IGNORE_DIRS = {
    ".git", "node_modules", "target", "out", "build", "dist", "lib",
    "cache", ".scratchpad", "test", "tests", "mock", "mocks", "__pycache__",
    "artifacts", "typechain", "typechain-types", ".idea", ".vscode",
}


def _count_source_suffixes_under(
    root: Path, recognized: set[str], file_cap: int
) -> dict[str, int]:
    """Count recognized source suffixes under a single root (bounded, pruned).
    Never raises."""
    counts: dict[str, int] = {s: 0 for s in recognized}
    if not root.exists() or not root.is_dir():
        return counts
    seen = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in _LANG_GATE_IGNORE_DIRS
                and not d.startswith(".")
            ]
            for fn in filenames:
                suffix = Path(fn).suffix.lower()
                if suffix in recognized:
                    counts[suffix] += 1
                    seen += 1
                    if seen >= file_cap:
                        return counts
    except Exception:
        pass
    return counts


def _scan_manifests_for_markers(
    base: Path,
    manifest_names: set[str],
    markers_by_lang: dict[str, tuple[str, ...]],
    *,
    max_files: int = 200,
    max_bytes: int = 200_000,
) -> dict[str, int]:
    """Deterministically scan build manifests under ``base`` and count, per
    language, how many DISTINCT markers appear in manifest content.

    This is the SECOND deterministic signal used to disambiguate the ambiguous
    source suffixes (.rs -> solana|soroban, .move -> sui|aptos). It is NOT an
    LLM decision: it lowercases manifest content and substring-matches a fixed
    marker vocabulary keyed off language build systems (dependency/framework
    names), satisfying the no-overfit rule (no protocol/token/contract names).

    Mirroring ``_dominant_source_suffix``: ``base`` is scanned FIRST and is
    authoritative; up to 2 ancestors are consulted as a fallback ONLY when
    ``base`` itself yields zero matching manifests (a scope-dir PROJECT_PATH
    whose manifest lives above it).

    ``Anchor.toml`` is special-cased: its mere presence anywhere counts as a
    solana filename-marker (Anchor projects are Solana programs).

    Bounded by ``max_files`` (manifests read) and ``max_bytes`` (per file).
    Wrapped in try/except; never raises. Returns ``{lang: distinct_marker_count}``.
    """
    result: dict[str, int] = {lang: 0 for lang in markers_by_lang}
    wanted = {n.lower() for n in manifest_names}

    def _scan_root(root: Path) -> tuple[dict[str, set[str]], bool]:
        """Return (matched_markers_by_lang, saw_any_manifest)."""
        matched: dict[str, set[str]] = {lang: set() for lang in markers_by_lang}
        saw_manifest = False
        read_count = 0
        anchor_seen = False
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in _LANG_GATE_IGNORE_DIRS
                    and not d.startswith(".")
                ]
                for fn in filenames:
                    fn_lower = fn.lower()
                    # Anchor.toml presence => solana filename-marker.
                    if fn_lower == "anchor.toml":
                        saw_manifest = True
                        anchor_seen = True
                    if fn_lower not in wanted:
                        continue
                    saw_manifest = True
                    if read_count >= max_files:
                        continue
                    read_count += 1
                    try:
                        content = (Path(dirpath) / fn).read_text(
                            encoding="utf-8", errors="ignore"
                        )[:max_bytes].lower()
                    except Exception:
                        continue
                    for lang, markers in markers_by_lang.items():
                        for marker in markers:
                            if marker and marker.lower() in content:
                                matched[lang].add(marker.lower())
        except Exception:
            pass
        if anchor_seen and "solana" in matched:
            matched["solana"].add("anchor.toml")
        return matched, saw_manifest

    try:
        root = Path(base).resolve()
    except Exception:
        return result

    matched, saw_manifest = _scan_root(root)

    if not saw_manifest:
        anc = root
        for _ in range(2):
            parent = anc.parent
            if parent == anc:
                break
            anc = parent
            matched, saw_manifest = _scan_root(anc)
            if saw_manifest:
                break

    for lang in result:
        result[lang] = len(matched.get(lang, set()))
    return result


def _dominant_source_suffix(
    project_root: str | Path,
    *,
    max_ancestors: int = 2,
    file_cap: int = 4000,
) -> tuple[str | None, dict[str, int]]:
    """Return ``(dominant_suffix, counts)`` over the recognized source suffixes
    (.sol/.rs/.move) found under PROJECT_PATH.

    PROJECT_PATH is scanned FIRST and is authoritative: the dominant-extension
    decision uses ONLY in-tree files so an unrelated sibling project in an
    ancestor directory can never trigger a false language contradiction.
    Ancestors are consulted as a fallback ONLY when PROJECT_PATH itself
    contains zero recognized source files (e.g. a near-empty scope dir), and
    even then a contradiction can only arise from a genuine source tree above.
    ``dominant_suffix`` is None when no recognized source file is found
    anywhere consulted (an indeterminate signal). Bounded; never raises."""
    base_counts: dict[str, int] = {".sol": 0, ".rs": 0, ".move": 0, ".daml": 0}
    recognized = set(base_counts)
    try:
        base = Path(project_root).resolve()
    except Exception:
        return None, base_counts

    counts = _count_source_suffixes_under(base, recognized, file_cap)
    if any(counts.values()):
        dominant = max(
            (s for s in counts if counts[s] > 0), key=lambda s: counts[s]
        )
        return dominant, counts

    # Fallback: PROJECT_PATH had no recognized source files. Consult a small
    # number of ancestors so a scope-dir PROJECT_PATH still gets a signal.
    anc = base
    for _ in range(max(0, max_ancestors)):
        parent = anc.parent
        if parent == anc:
            break
        anc = parent
        anc_counts = _count_source_suffixes_under(anc, recognized, file_cap)
        if any(anc_counts.values()):
            dominant = max(
                (s for s in anc_counts if anc_counts[s] > 0),
                key=lambda s: anc_counts[s],
            )
            return dominant, anc_counts

    return None, base_counts


def _validate_language_source_consistency(
    project_root: str | Path, language: str
) -> tuple[bool, str]:
    """STEP 2A fail-fast config validator. Returns ``(ok, message)``.

    ``ok=False`` ONLY on a definite contradiction: the configured language
    expects suffix X, but zero X files and a positive count of a DIFFERENT
    recognized source suffix are found. Indeterminate signals (no recognized
    source files at all, or an unknown configured language) return ``ok=True``
    with a warning message so the run continues with the configured language.
    This gate fires at STARTUP only, before any worker pool runs; it prevents a
    multi-hour misrouted run and is not a mid-pipeline halt.
    """
    lang = (language or "").strip().lower()
    expected = _LANG_EXPECTED_SUFFIX.get(lang)
    dominant, counts = _dominant_source_suffix(project_root)

    if dominant is None:
        return True, (
            "language consistency: no recognized source files "
            "(.sol/.rs/.move) found under PROJECT_PATH; continuing with "
            f"configured language={lang or 'unknown'} (indeterminate signal)"
        )
    if expected is None:
        # Unknown configured language: do not block on an indeterminate config.
        return True, (
            f"language consistency: configured language={lang or 'unknown'} "
            "is not a recognized source language; dominant source suffix is "
            f"{dominant}; continuing without blocking"
        )

    expected_count = sum(counts.get(s, 0) for s in expected)
    if expected_count > 0:
        return True, (
            f"language consistency OK: configured language={lang} matches "
            f"{expected_count} {'/'.join(expected)} source file(s)"
        )

    # Definite contradiction: zero expected-suffix files, dominant is a
    # different recognized source suffix.
    candidate_langs = _SUFFIX_TO_LANGS.get(dominant, ())
    suggest = (
        " or ".join(f"--language {c}" for c in candidate_langs)
        if candidate_langs
        else "the correct --language"
    )
    found_desc = ", ".join(
        f"{c} {s}" for s, c in counts.items() if c > 0
    )
    return False, (
        f"language={lang} but {found_desc} found and 0 "
        f"{'/'.join(expected)} files under PROJECT_PATH "
        f"({Path(project_root)}) -- re-run with {suggest}"
    )


def _resolve_family(
    counts: dict[str, int],
    hits: dict[str, int],
    *,
    primary: str,
    secondary: str,
    default: str,
    family: str,
) -> tuple[str | None, str, dict]:
    """Apply the confidence + disambiguation rule for an ambiguous
    source-suffix family (.rs or .move). Pure, deterministic, never raises.

    Recall-safety: a CONFLICT (both family marker sets fire) returns
    ``(None, 'none', ...)`` — we NEVER compare magnitudes to pick a winner."""
    p_hits = int(hits.get(primary, 0))
    s_hits = int(hits.get(secondary, 0))
    base_signals = {"counts": counts, "manifest_hits": hits}

    # CONFLICT: both families have markers -> ambiguous, keep configured.
    if p_hits > 0 and s_hits > 0:
        return (
            None,
            "none",
            {**base_signals, "reason": "conflicting manifest markers"},
        )
    # Exactly one family has markers -> high confidence.
    if p_hits > 0 and s_hits == 0:
        return (
            primary,
            "high",
            {**base_signals, "reason": f"{family} + {primary} manifest markers"},
        )
    if s_hits > 0 and p_hits == 0:
        return (
            secondary,
            "high",
            {**base_signals,
             "reason": f"{family} + {secondary} manifest markers"},
        )
    # No manifest signal at all -> common-case default, medium confidence.
    return (
        default,
        "medium",
        {**base_signals, "reason": "suffix-only, no manifest disambiguation"},
    )


def _language_correction(configured, detected, conf, pipeline):
    """Decide whether to auto-correct config.language from the ecosystem detector.

    Returns the corrected language (lowercased) to apply, or None to keep the
    configured value.

    - L1 pipelines: ALWAYS return None (keep configured rust/go). The ecosystem
      detector is SC-oriented (solana/aptos/sui/evm/soroban); a Rust L1 codebase
      has .rs files and would be mis-corrected rust -> solana, injecting the
      wrong (Solana-SC) skills into an L1 audit.
    - SC pipelines: correct only on a high/medium-confidence genuine mismatch
      with the configured language. A 'none'/low-confidence or matching signal
      keeps the configured value.
    """
    configured = (configured or "").strip().lower()
    pipeline = (pipeline or "").strip().lower()
    conf = str(conf).strip().lower()
    # L1: never SC-correct (defense-in-depth; the high/medium rules below would
    # already keep a configured rust/go, but be explicit).
    if pipeline == "l1":
        return None
    if detected is None:
        return None
    detected = str(detected).strip().lower()
    if detected == configured:
        return None
    # HIGH confidence = the detector disambiguated via build manifest
    # (anchor-lang/solana-program -> solana, soroban-sdk -> soroban, .sol -> evm,
    # Move.toml markers -> sui/aptos). Trustworthy proof of a genuine misconfig
    # -> override.
    if conf == "high":
        return detected
    # MEDIUM = suffix-only fallback. It CANNOT tell apart same-suffix families
    # (.rs: solana vs soroban vs rust-L1; .move: sui vs aptos) and just returns
    # the family DEFAULT (e.g. .rs -> solana). It must NOT clobber an EXPLICITLY
    # configured language (a prior rust->solana bug, and the symmetric
    # soroban->solana / aptos<->sui risks). Only fill an UNSET config.
    if conf == "medium" and not configured:
        return detected
    return None


def _detect_ecosystem(
    project_root: str | Path,
) -> tuple[str | None, str, dict]:
    """MECHANICAL ecosystem auto-detector (no LLM). Returns
    ``(language, confidence, signals)`` where:

    - ``language`` in {evm, solana, soroban, aptos, sui, None}
    - ``confidence`` in {'high', 'medium', 'none'}
    - ``signals`` is a diagnostics dict {counts, manifest_hits, reason}

    Reuses the EXISTING bounded ``_dominant_source_suffix`` for the suffix
    signal (already prunes ignore-dirs, ancestor-aware, never raises) and the
    NEW ``_scan_manifests_for_markers`` for build-manifest disambiguation.

    RECALL-SAFETY GUARANTEE: a wrong auto-correct is worse than the status quo,
    so on ANY conflicting signal the detector returns ``(None, 'none', ...)`` —
    it NEVER compares marker magnitudes to pick a "winner" within a language
    family. Only an unambiguous suffix (.sol -> evm) or a suffix plus EXACTLY
    ONE family's manifest markers present (other family at zero) yields 'high'.
    A suffix with no manifest signal yields 'medium' with the family's common
    default; medium still auto-corrects because the suffix alone already
    contradicts a wrong configured language across families. The only case that
    returns a non-None language from a guessed family member is this no-manifest
    medium case; a within-family conflict always returns None.
    """
    dominant, counts = _dominant_source_suffix(project_root)
    if dominant is None:
        return (
            None,
            "none",
            {"counts": counts, "manifest_hits": {},
             "reason": "no recognized sources"},
        )

    # .sol is unambiguous: evm is the only language that maps to it.
    if dominant == ".sol":
        return (
            "evm",
            "high",
            {"counts": counts, "manifest_hits": {},
             "reason": ".sol dominant -> evm (unambiguous suffix)"},
        )

    # .daml is unambiguous: daml is the only language that maps to it.
    # daml.yaml / Daml.toml are scanned only as a CONFIRMING signal (they add
    # manifest_hits to the diagnostics dict); the suffix alone is decisive, so
    # the verdict is 'high' regardless of whether a manifest is present.
    if dominant == ".daml":
        manifest_hits = _scan_manifests_for_markers(
            Path(project_root),
            {"daml.yaml", "Daml.toml"},
            {"daml": ("sdk-version", "daml", "name:")},
        )
        return (
            "daml",
            "high",
            {"counts": counts, "manifest_hits": manifest_hits,
             "reason": ".daml dominant -> daml (unambiguous suffix)"},
        )

    # .rs => disambiguate solana vs soroban via Cargo.toml / Anchor.toml.
    if dominant == ".rs":
        hits = _scan_manifests_for_markers(
            Path(project_root),
            {"Cargo.toml"},
            {
                # Solana program/SDK frameworks. Mutually exclusive with
                # soroban-sdk in any real crate. Covers Anchor, native
                # (solana-program/solana-sdk), and Pinocchio (zero-dep
                # framework that reimplements the entrypoint, so it often has
                # neither anchor-lang nor solana-program).
                "solana": (
                    "anchor-lang", "solana-program", "solana-sdk",
                    "pinocchio",
                ),
                "soroban": ("soroban-sdk",),
            },
        )
        return _resolve_family(
            counts, hits,
            primary="solana", secondary="soroban",
            default="solana", family=".rs",
        )

    # .move => disambiguate sui vs aptos via Move.toml.
    if dominant == ".move":
        hits = _scan_manifests_for_markers(
            Path(project_root),
            {"Move.toml"},
            {
                "sui": ("sui-framework", "sui =", "sui-move"),
                "aptos": (
                    "aptos-framework", "aptosframework",
                    "aptosstdlib", "aptos-std", "aptos =",
                ),
            },
        )
        return _resolve_family(
            counts, hits,
            primary="sui", secondary="aptos",
            default="sui", family=".move",
        )

    # Unknown dominant suffix (should not happen given recognized set).
    return (
        None,
        "none",
        {"counts": counts, "manifest_hits": {},
         "reason": f"unhandled dominant suffix {dominant}"},
    )


def _persist_corrected_language(
    config_path: str | Path,
    config: dict,
    detected: str,
) -> bool:
    """Re-read config.json and atomically rewrite it with the corrected
    ``language``, preserving all other keys and their order. Returns True on a
    successful persist. Wrapped in try/except: a write failure logs a WARNING
    but does NOT block — the in-memory ``config`` is already corrected, which is
    what every downstream consumer reads."""
    try:
        cp = Path(config_path)
        try:
            on_disk = json.loads(cp.read_text(encoding="utf-8"))
        except Exception:
            on_disk = dict(config)
        on_disk["language"] = detected
        tmp = cp.with_name(
            f"{cp.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:12]}"
        )
        tmp.write_text(
            json.dumps(on_disk, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, cp)
        return True
    except Exception as exc:  # never block on a persist failure
        try:
            log.warning(
                "[startup] could not persist corrected language to %s: %r",
                config_path, exc,
            )
        except Exception:
            pass
        return False


def _ensure_claude_folder_trusted(*paths: str) -> list[str]:
    """Pre-clear Claude Code's first-run interactive gates that freeze a
    headless PTY worker: per-FOLDER trust for the given dirs, PLUS the global
    onboarding/theme wizard and the one-time --dangerously-skip-permissions
    risk-acceptance dialog.

    A PTY worker launched with cwd in a directory Claude Code has never opened
    hangs FOREVER on the interactive "Is this a project you trust?" dialog —
    there is no stdin to answer it, so the worker produces 0 bytes and dies on
    the phase budget. `--dangerously-skip-permissions` does NOT cover this; trust
    is recorded per-directory in ~/.claude.json under
    projects.<abspath>.hasTrustDialogAccepted (observed values use forward
    slashes even on Windows). Freshly-staged dirs (e.g. a bounty harness) are
    never trusted, so the audit hangs at recon.

    Idempotently set hasTrustDialogAccepted=true for each path (writing both
    slash forms so Claude's lookup hits regardless of normalization), preserving
    ALL other config. Returns the keys newly trusted. NEVER raises and never
    clobbers an unreadable/locked config (better to risk the prompt than to
    corrupt the user's global Claude state)."""
    trusted: list[str] = []
    try:
        cj = Path.home() / ".claude.json"
        if cj.is_file():
            try:
                data = json.loads(cj.read_text(encoding="utf-8") or "{}")
            except (json.JSONDecodeError, OSError):
                return []
        else:
            data = {}
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            projects = {}
            data["projects"] = projects
        changed = False
        for raw in paths:
            if not raw:
                continue
            try:
                base = str(Path(raw).resolve())
            except OSError:
                base = str(raw)
            for key in {base, base.replace("\\", "/")}:
                entry = projects.get(key)
                if not isinstance(entry, dict):
                    entry = {}
                # Gate B (folder trust) AND Gate D (CLAUDE.md external @imports).
                # A worker whose cwd is inside the audited project loads the
                # GLOBAL ~/.claude/CLAUDE.md, which @imports ~/.plamen/rules/*.md
                # — files OUTSIDE the project tree. Claude Code then shows the
                # interactive "allow external imports" dialog (keys:
                # hasClaudeMdExternalIncludesApproved /
                # hasClaudeMdExternalIncludesWarningShown), a SEPARATE gate from
                # hasTrustDialogAccepted. A PTY worker has no stdin to answer it,
                # so it hangs to the phase budget (observed: a 128-min recon hang
                # on a Soroban audit). Set all three together; setting trust
                # alone leaves the import dialog live.
                for ek in ("hasTrustDialogAccepted",
                           "hasClaudeMdExternalIncludesApproved",
                           "hasClaudeMdExternalIncludesWarningShown"):
                    if entry.get(ek) is not True:
                        entry[ek] = True
                        entry.setdefault("projectOnboardingSeenCount", 1)
                        projects[key] = entry
                        changed = True
                        trusted.append(key)
        # ── Global first-run interactive gates ────────────────────────────
        # Per-folder trust is only the SECOND of three first-run gates a fresh
        # `claude` install puts in front of a PTY worker; all three are
        # invisible to `-p`/print-mode probes but freeze a real PTY worker:
        #   A) onboarding/theme wizard  C) --dangerously-skip-permissions accept
        # Clear them globally, idempotently, preserving all other config.
        #   - hasCompletedOnboarding: the documented onboarding gate (skips the
        #     whole wizard, including the theme step).
        #   - theme: set a default ONLY if the user has none — never override an
        #     existing choice.
        #   - bypassPermissionsModeAccepted: legacy BEST-EFFORT guess (kept,
        #     harmless). The AUTHORITATIVE suppression for the dangerous-mode
        #     dialog is `skipDangerousModePermissionPrompt` in
        #     ~/.claude/settings.json (a DIFFERENT file) — written below.
        if data.get("hasCompletedOnboarding") is not True:
            data["hasCompletedOnboarding"] = True
            trusted.append("hasCompletedOnboarding")
            changed = True
        if "theme" not in data:
            data["theme"] = "dark"
            changed = True
        if data.get("bypassPermissionsModeAccepted") is not True:
            data["bypassPermissionsModeAccepted"] = True
            trusted.append("bypassPermissionsModeAccepted")
            changed = True
        if changed:
            tmp = cj.with_name(cj.name + ".plamen-tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(cj)
    except Exception:
        return []
    # ── Gate C, AUTHORITATIVE: the bypass-permissions dialog ──────────────────
    # The one-time "WARNING: Claude Code running in Bypass Permissions mode"
    # dialog is gated by the CLI on
    #   (dangerouslySkipPermissions) && !skipDangerousModePermissionPrompt()
    # (anthropics/claude-code#25503). The flag alone does NOT suppress it; the
    # key lives in ~/.claude/settings.json (NOT ~/.claude.json). A PTY worker has
    # no stdin to answer it, so without this the worker emits 0 bytes and hangs
    # to the phase budget (observed: a 98-min bake hang on macOS). This is the
    # exact value the CLI itself persists when you accept, so writing it is
    # honest pre-acceptance — the driver already passes the flag. Platform-
    # agnostic (real code condition, no keystroke simulation). Independent
    # try/except so a settings.json failure never discards the folder-trust work.
    try:
        sj = Path.home() / ".claude" / "settings.json"
        sdata: dict = {}
        if sj.is_file():
            try:
                sdata = json.loads(sj.read_text(encoding="utf-8") or "{}")
            except (json.JSONDecodeError, OSError):
                sdata = None  # unreadable/locked — do NOT clobber
        if isinstance(sdata, dict) and \
                sdata.get("skipDangerousModePermissionPrompt") is not True:
            sdata["skipDangerousModePermissionPrompt"] = True
            sj.parent.mkdir(parents=True, exist_ok=True)
            tmp = sj.with_name(sj.name + ".plamen-tmp")
            tmp.write_text(json.dumps(sdata, indent=2), encoding="utf-8")
            tmp.replace(sj)
            trusted.append("skipDangerousModePermissionPrompt")
    except Exception:
        pass
    return trusted


def main():
    # Terminal: WARNING+ only (keep TUI clean).
    # File: everything (INFO+) for debugging via `tail -f _plamen.log`.
    _stderr_handler = _SpinnerSafeStreamHandler(sys.stderr)
    _stderr_handler.setLevel(logging.WARNING)
    _stderr_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                          datefmt="%H:%M:%S")
    )
    logging.basicConfig(
        level=logging.INFO,
        handlers=[_stderr_handler],
    )

    # STEP 5: shared mechanical detector entrypoint for the wizard. Prints
    # "<language>\t<confidence>" (or "indeterminate\tnone") and exits. This is
    # the SINGLE source of truth for ecosystem detection so the wizard and the
    # driver never duplicate the logic in prose/bash.
    if "--detect-language" in sys.argv[1:]:
        _det_args = [a for a in sys.argv[1:] if a != "--detect-language"]
        _det_root = _det_args[0] if _det_args else "."
        try:
            _lang, _conf, _sig = _detect_ecosystem(_det_root)
        except Exception:
            _lang, _conf = None, "none"
        print(f"{_lang or 'indeterminate'}\t{_conf}")
        sys.exit(0)

    if len(sys.argv) < 2:
        print(
            "usage: plamen_driver.py <config.json> "
            "[--force] [--no-sleep|--no-hibernate]\n"
            "       plamen_driver.py --detect-language <project_root>",
            file=sys.stderr,
        )
        sys.exit(EXIT_CONFIG_MISSING)

    args = sys.argv[1:]
    no_sleep_flags = {"--no-sleep", "--no-hibernate", "--ignore-hibernation"}
    force_resume = ("--force" in args) or (os.environ.get("PLAMEN_FORCE") == "1")
    no_sleep = any(a in no_sleep_flags for a in args) or force_resume
    fresh_restart = "--fresh" in args
    if no_sleep:
        os.environ["PLAMEN_NO_HIBERNATE"] = "1"
    args = [a for a in args
            if a not in {"--force", "--fresh"} and a not in no_sleep_flags]

    config_path = Path(args[0])
    if not config_path.exists():
        print(f"config not found: {config_path}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_MISSING)

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"config parse error: {e}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_MISSING)

    # Required keys
    for key in ("project_root", "scratchpad", "language", "mode", "pipeline"):
        if key not in config:
            print(f"config missing required key: {key}", file=sys.stderr)
            sys.exit(EXIT_CONFIG_MISSING)

    # PATH NORMALIZATION (cross-OS correctness): resolve the two filesystem
    # roots to ABSOLUTE paths immediately after load. The driver launches every
    # worker subprocess with `cwd=config["project_root"]`, and it passes paths
    # derived from `scratchpad` (e.g. `--settings <scratchpad>/_subprocess_isolation.json`,
    # `--add-dir`, `scope_file`) to that worker on the command line. A RELATIVE
    # project_root/scratchpad in the config would be resolved by the worker
    # against ITS cwd (= project_root), not against the driver's cwd — so a
    # relative `--settings` path points at a nonexistent file and `claude`
    # refuses to start (0-byte output, every worker dies in seconds). Resolving
    # here once makes every downstream path cwd-independent for any caller that
    # supplies a relative config (the in-tree wizard already supplies absolute
    # paths; an external orchestrator may not). Resolve relative to the config
    # file's directory when the path itself is relative, which is the least
    # surprising anchor for a hand-written or generated config.
    #
    # ANCHOR CHOICE: a relative config value is anchored to the DRIVER'S CWD
    # (`Path(val).resolve()`), because that is where the value was authored and
    # where the driver process is launched (e.g. an orchestrator does
    # `subprocess.run([python, driver, cfg_path])` from its own cwd with
    # cwd-relative path values). The config-file directory is NOT a safe anchor:
    # a common layout writes `config.json` INSIDE the scratchpad
    # (`cfg_path = scratchpad / "config.json"`), so anchoring a relative
    # `scratchpad`/`project_root` to the config dir DOUBLES the prefix and yields
    # an absolute-but-nonexistent path — the exact failure that lets a relative
    # config silently kill every worker. The config dir is used only as a
    # best-effort FALLBACK when the cwd anchor does not exist on disk but the
    # cfg-dir anchor does (covers a hand-written config kept beside its target).
    _cfg_dir = config_path.resolve().parent

    def _abs_under_cfg(val: str) -> str:
        p = Path(val)
        if p.is_absolute():
            try:
                return str(p.resolve())
            except OSError:
                return str(p)
        cwd_anchor = Path.cwd() / p
        cfg_anchor = _cfg_dir / p
        # Prefer cwd; fall back to cfg-dir only if it disambiguates a real path.
        if not cwd_anchor.exists() and cfg_anchor.exists():
            chosen = cfg_anchor
        else:
            chosen = cwd_anchor
        try:
            return str(chosen.resolve())
        except OSError:
            return str(chosen.absolute())

    # project_root + scratchpad are ALWAYS local filesystem roots.
    for _path_key in ("project_root", "scratchpad"):
        _val = config.get(_path_key)
        if isinstance(_val, str) and _val:
            config[_path_key] = _abs_under_cfg(_val)
    # scope_file is a local file IF set; "" means whole-tree scope (leave as-is).
    # docs_path may be a space-joined URL list (bounty mode) rather than a path —
    # only absolutize it when it is a single token that resolves to a real local
    # path, so a URL list or empty value is never corrupted.
    _sf = config.get("scope_file")
    if isinstance(_sf, str) and _sf.strip():
        config["scope_file"] = _abs_under_cfg(_sf.strip())
    _dp = config.get("docs_path")
    if isinstance(_dp, str) and _dp.strip() and " " not in _dp.strip() \
            and "://" not in _dp:
        _dp_abs = _abs_under_cfg(_dp.strip())
        if Path(_dp_abs).exists():
            config["docs_path"] = _dp_abs

    # FOLDER-TRUST PRE-ACCEPT (claude backend): a PTY worker whose cwd is a dir
    # Claude Code has never opened hangs forever on the interactive trust dialog
    # ("Is this a project you trust?") — fatal for a freshly-staged bounty
    # harness or any never-opened target. Pre-accept trust for the worker cwd(s)
    # (project_root + the methodology home) so workers launch headless. No-op
    # once trusted; never raises. (Codex has its own sandbox model.)
    if (config.get("cli_backend") or "claude").strip().lower() != "codex":
        try:
            _newly_trusted = _ensure_claude_folder_trusted(
                config["project_root"], str(plamen_home())
            )
            if _newly_trusted:
                log.info(
                    "[startup] pre-accepted Claude folder-trust for worker cwd: %s",
                    ", ".join(_newly_trusted),
                )
        except Exception as _exc:  # never let trust-prep abort the run
            log.warning(f"[startup] folder-trust pre-accept skipped: {_exc!r}")

    # STARTUP AUTO-CORRECT: mechanically detect the ecosystem from source-suffix
    # counts + build-manifest markers and SELF-HEAL a wrong configured language
    # instead of halting. Fires at STARTUP only (before any worker pool). A
    # correct language deterministically fixes every language-keyed
    # template/skill/role/prompt path downstream (the recall win). Recall-safe:
    # only high/medium-confidence detection overrides, and a genuinely ambiguous
    # or conflicting signal (confidence='none') keeps the configured value. There
    # is NO sys.exit for a correctable language mismatch.
    try:
        _detected, _conf, _signals = _detect_ecosystem(config["project_root"])
    except Exception as _det_exc:  # never block on a detector bug
        _detected, _conf, _signals = None, "none", {
            "reason": f"detector error: {_det_exc!r}"
        }
    _configured = str(config.get("language", "")).strip().lower()
    _det_reason = (_signals or {}).get("reason", "")
    _pipeline = str(config.get("pipeline", "")).strip().lower()

    # L1 GUARD (see _language_correction): for pipeline=l1 the SC ecosystem
    # detector would wrongly correct a Rust L1 codebase (.rs files)
    # to solana. _language_correction returns None for L1 so the configured
    # rust/go is kept and L1 skills inject correctly. For SC it returns the
    # detected language only on a high/medium-confidence genuine mismatch.
    _corrected = _language_correction(_configured, _detected, _conf, _pipeline)
    if _corrected is not None:
        config["language"] = _corrected
        _persist_corrected_language(config_path, config, _corrected)
        _correct_msg = (
            f"[startup] auto-detected ecosystem={_corrected} "
            f"(confidence={_conf}) from signals={_det_reason}; "
            f"corrected config.language {_configured or 'unset'} -> {_corrected}"
        )
        log.info(_correct_msg)
        # Also surface on the clean TUI (WARNING-level handler) so the user sees
        # the correction without tailing the file log.
        log.warning(_correct_msg)
        print(_correct_msg, file=sys.stderr)
    elif _detected is not None and _detected == _configured:
        log.info(
            "[startup] ecosystem detection confirms configured "
            "language=%s (confidence=%s, %s)",
            _configured, _conf, _det_reason,
        )
    else:
        # confidence == 'none' (no sources OR conflicting signals): NEVER
        # override on ambiguity, NEVER exit. Keep the configured value and warn.
        log.warning(
            "[startup] ecosystem detection ambiguous (%s); keeping "
            "configured language=%s",
            _det_reason or "indeterminate", _configured or "unset",
        )

    scratchpad = Path(config["scratchpad"])
    scratchpad.mkdir(parents=True, exist_ok=True)

    lock_ok, lock_issue = _acquire_run_lock(
        scratchpad, config_path, force=force_resume,
    )
    if not lock_ok:
        print(f"[startup] {lock_issue}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    # File log so users can `tail -f .scratchpad/_plamen.log` from another
    # terminal while the driver runs in the background.
    _file_handler = logging.FileHandler(
        scratchpad / "_plamen.log", encoding="utf-8"
    )
    _file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                          datefmt="%H:%M:%S")
    )
    log.addHandler(_file_handler)

    if force_resume or fresh_restart:
        marker = scratchpad / ".hibernating"
        if marker.exists():
            marker.unlink()
            print("[force/fresh] cleared .hibernating marker", file=sys.stderr)
    elif no_sleep:
        marker = scratchpad / ".hibernating"
        if marker.exists():
            marker.unlink()
            print("[no-sleep] cleared .hibernating marker", file=sys.stderr)
    else:
        hibernate_exit = maybe_resume_hibernation(scratchpad)
        if hibernate_exit is not None:
            sys.exit(hibernate_exit)

    if fresh_restart:
        log.info("[fresh] wiping scratchpad for fresh restart")
        _purge_scratchpad(scratchpad, config)
        # Re-add file handler since _purge_scratchpad closes it
        _file_handler = logging.FileHandler(
            scratchpad / "_plamen.log", encoding="utf-8"
        )
        _file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                              datefmt="%H:%M:%S")
        )
        log.addHandler(_file_handler)
        log.info("[fresh] scratchpad purged, starting from phase 1")
        # Also evict prior-run answer-key artifacts (reports, RCA notes,
        # generated fuzz harnesses) from project_root so a fresh audit cannot
        # ingest them. Moves them to a dot-prefixed sibling archive (never
        # deletes). Without this, --fresh wipes only the scratchpad and these
        # survive to prime discovery.
        try:
            _archived = _archive_prior_audit_artifacts(
                Path(config["project_root"])
            )
            if _archived is not None:
                log.info(
                    "[fresh] archived prior-run answer-key artifacts "
                    "(reports/RCA/fuzz harnesses) to %s — moved, not deleted",
                    _archived,
                )
        except Exception as _e:
            log.info("[fresh] prior-artifact archive skipped: %s", _e)

    repaired_rules = _ensure_rule_files_materialized()
    if repaired_rules:
        log.info(
            "[startup] materialized empty rule file(s) from bundled backups: "
            + ", ".join(repaired_rules)
        )

    # Loud preflight: fail fast if methodology is unreachable for the configured
    # backend, instead of shooting blind (Codex-only / missing-~/.claude loophole).
    _assert_methodology_reachable(config)

    try:
        checkpoint = Checkpoint.load(scratchpad)
    except RuntimeError as exc:
        log.error(f"[checkpoint] failed to load checkpoint: {exc}")
        sys.exit(EXIT_DEGRADED)
    checkpoint.config = config

    # Mechanical pre-pass (writes inventory/variables/functions/build_status/subsystems).
    #
    # This must run after checkpoint load. On resume, completed recon artifacts
    # are authoritative handoffs; re-running pre-pass would clobber them with
    # marker-stamped stubs because recon merge intentionally preserves shard
    # evidence and can leave the original pre-pass marker at the top.
    if "recon" in set(checkpoint.completed or []):
        log.info(
            "[pre-pass] skipped because recon is already completed; "
            "preserving canonical recon handoff artifacts"
        )
        try:
            recon_hard, _recon_soft = _validate_recon_content_structure(
                scratchpad, backend=config.get("cli_backend", "claude")
            )
        except Exception:
            recon_hard = []
        if recon_hard and any("pre-pass overwrite marker" in str(x) for x in recon_hard):
            # The marker can survive even on a resumed run: on Codex,
            # apply_patch body-edits leave line 1 untouched; on Claude, a recon
            # worker that never reached COMPLETE leaves the pre-pass stub
            # in place. In BOTH cases the body holds usable content (regex
            # pre-pass tables or partial enrichment), so strip the line-1
            # marker directly to self-heal a resumed run before falling back
            # to the heavier shard re-merge. strip_codex_prepass_markers is
            # backend-agnostic (despite the name) and recall-safe: it never
            # strips a pure [LLM TO ENRICH] placeholder.
            try:
                _resumed_stripped = strip_codex_prepass_markers(scratchpad)
                if _resumed_stripped:
                    log.info(
                        "[startup] stripped pre-pass marker from enriched "
                        "recon artifacts (backend=%s): %s",
                        config.get("cli_backend", "claude"),
                        ", ".join(_resumed_stripped),
                    )
                    recon_hard, _ = _validate_recon_content_structure(
                        scratchpad, backend=config.get("cli_backend", "claude")
                    )
            except Exception as exc:
                log.warning(f"[startup] recon marker strip failed: {exc!r}")
        if recon_hard and any("pre-pass overwrite marker" in str(x) for x in recon_hard):
            log.warning(
                "[startup] completed recon artifacts still carry pre-pass "
                "overwrite markers; re-merging recon worker shards"
            )
            try:
                _merge_recon_worker_shards(scratchpad, config)
                recon_hard_after, _ = _validate_recon_content_structure(
                    scratchpad, backend=config.get("cli_backend", "claude")
                )
                if recon_hard_after:
                    log.error(
                        "[startup] recon shard re-merge did not repair "
                        "canonical handoffs: %s",
                        "; ".join(recon_hard_after),
                    )
                else:
                    log.info(
                        "[startup] recon canonical handoffs repaired from "
                        "isolated worker shards"
                    )
            except Exception as exc:
                log.error(f"[startup] recon shard re-merge failed: {exc!r}")
    else:
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from recon_prepass import run_recon_prepass
            # The mechanical prepass runs SYNCHRONOUSLY in-process and includes
            # the build/dep-install path plus (for EVM) the Slither type-resolved
            # graph bake — the longest silent step, 1-3+ min on a real project.
            # Without a pulse the terminal looks frozen. Print one up-front
            # status line saying WHAT the wait is, then wrap the whole block in a
            # live daemon-thread heartbeat so the user sees it's alive.
            _pp_lang = str(config.get("language") or "evm").lower()
            try:
                if _pp_lang == "evm":
                    display.print_phase_heartbeat(
                        "recon", 0,
                        status="⬡ baking type-resolved graph (Slither) "
                               "— large projects take 1-3 min …",
                        status_style="info",
                    )
                else:
                    display.print_phase_heartbeat(
                        "recon", 0,
                        status="⬡ baking mechanical recon graph "
                               "— large projects take 1-3 min …",
                        status_style="info",
                    )
            except Exception:
                pass
            with _phase_heartbeat_thread(display, "recon", scratchpad):
                status = run_recon_prepass(config)
            log.info(f"[pre-pass] {status}")
        except Exception as e:
            log.warning(f"[pre-pass] failed: {e} -- LLM recon will write all artifacts")

    if checkpoint.completed:
        log.info(f"[resume] skipping completed phases: {checkpoint.completed}")
    quarantined_report = _quarantine_report_without_completed_assemble(
        scratchpad, config["project_root"], checkpoint
    )
    if quarantined_report:
        log.warning(
            "[startup] quarantined project-root AUDIT_REPORT.md because "
            "`report_assemble` has not completed: "
            f"{quarantined_report}"
        )
    # Phase E13 item #4: clear stale `.degraded` sentinels from prior aborted
    # runs before the first phase fires. Sentinels written DURING this run
    # (by phase handlers like report_assemble) remain — only pre-existing
    # ones are removed.
    cleared_sentinels = _clear_stale_degraded_sentinels(scratchpad)
    if cleared_sentinels:
        log.info(
            f"[startup] cleared {len(cleared_sentinels)} stale degraded "
            f"sentinel(s) from prior run: {', '.join(cleared_sentinels)}"
        )
    # Ship 8.1: plant the fresh-audit marker sentinel BEFORE
    # checkpoint.save() (which creates `_v2_checkpoint.json`) and before
    # the first/recon phase. Detection hinges on the checkpoint file not
    # yet existing on a brand-new run, so ordering matters: this MUST run
    # before checkpoint.save(). A brand-new audit gets the sentinel so the
    # strict marker gates (breadth/depth) activate; a resumed pre-marker
    # audit (checkpoint present, no sentinel) is left in legacy mode. A
    # write failure on a brand-new audit is a HARD startup error -- silently
    # proceeding would degrade every strict marker gate to legacy mode.
    try:
        sentinel_state = _ensure_fresh_audit_sentinel(scratchpad, config)
        if sentinel_state == "written":
            log.info(
                "[startup] planted fresh-audit marker sentinel "
                f"({_AUDIT_FRESH_SENTINEL_NAME}); strict marker gates active"
            )
        elif sentinel_state == "legacy-skip":
            log.info(
                "[startup] resumed pre-marker audit (checkpoint present, no "
                "sentinel); staying in legacy marker mode"
            )
    except Exception as exc:
        log.error(
            "[startup] FAILED to write fresh-audit marker sentinel "
            f"({_AUDIT_FRESH_SENTINEL_NAME}): {exc}. Refusing to start: "
            "without the sentinel the strict marker gates would silently "
            "degrade to legacy mode and IN_PROGRESS artifacts would be "
            "tolerated instead of blocked/continued."
        )
        sys.exit(EXIT_DEGRADED)

    # Plant V2 marker BEFORE the first phase spawns. The phase_gate hook
    # (~/.claude/hooks/phase_gate.py) detects `_v2_checkpoint.json` and
    # stays dormant so it doesn't fight the driver's phase-scoped model.
    # Must happen BEFORE run_phase because the first phase's first Stop
    # hook fires before any phase writes artifacts.
    checkpoint.save(scratchpad)

    phases = L1_PHASES if config["pipeline"] == "l1" else SC_PHASES
    mode = config["mode"]

    # Phase-graph startup validation. Closes the architectural defect where a
    # mode/language combination could ship a broken phase list (duplicate
    # names, mode-empty phase, malformed expected_artifacts, sentinel timeout)
    # and the bug only manifests mid-audit. Halt before any phase work.
    graph_issues = validate_phase_graph(phases, mode, config["pipeline"])
    if graph_issues:
        log.error(f"[startup] phase graph invalid for mode={mode} pipeline={config['pipeline']}:")
        for issue in graph_issues:
            log.error(f"[startup]   - {issue}")
        sys.exit(EXIT_DEGRADED)

    # Refresh SC body manifests before expansion in resume runs. The manifests
    # are derived from report_index.md, so parser/gate fixes can invalidate the
    # prior shard shape; stale report_medium_a/b JSON files must not keep the
    # old phase graph alive.
    if config.get("pipeline") != "l1" and (scratchpad / "report_index.md").exists():
        try:
            _build_sc_body_writer_manifests(scratchpad)
        except Exception as exc:
            log.warning(f"[startup] SC body manifest refresh failed: {exc!r}")

    # Expand tier sentinel phases if manifests already exist (resume case).
    phases[:] = expand_shard_phases(phases, scratchpad)

    active_after_expand = {p.name for p in phases if mode in p.modes}
    stale_dynamic_report_re = re.compile(
        r"^report(?:_body_writer)?_(?:critical_high|medium|low_info)_[a-z]$"
    )
    stale_checkpoint_report_names = [
        name for name in list(checkpoint.completed) + list(checkpoint.degraded)
        if stale_dynamic_report_re.match(name) and name not in active_after_expand
    ]
    if stale_checkpoint_report_names:
        stale_set = set(stale_checkpoint_report_names)
        checkpoint.completed = [n for n in checkpoint.completed if n not in stale_set]
        checkpoint.degraded = [n for n in checkpoint.degraded if n not in stale_set]
        for name in stale_set:
            checkpoint.clear_degraded_sentinel(scratchpad, name)
        checkpoint.save(scratchpad)
        log.warning(
            "[startup] removed stale report shard checkpoint entries after "
            "manifest refresh: " + ", ".join(sorted(stale_set))
        )

    # Rewind AFTER expansion so shard names (e.g. report_body_writer_critical_high_c2)
    # are visible in the phase list — pre-expansion only sentinel names exist.
    rewound = _rewind_completed_after_overflow(scratchpad, checkpoint, phases)
    if rewound:
        checkpoint.save(scratchpad)
        log.warning(
            "[startup] rewound completed checkpoint entries because prior "
            "phase-containment overflow exists: " + ", ".join(rewound)
        )

    active_phases = [p for p in phases if mode in p.modes]
    config["_active_phase_names"] = [p.name for p in active_phases]
    # Repair an already-degraded run BEFORE reconciliation: if a verify queue
    # phase completed with a queue-generation dropout, mechanically backfill the
    # unrouted inventory IDs so parity holds. Without this, reconciliation
    # rewinds verify_queue + every downstream verify_* phase, the LLM re-drops
    # the same IDs, and the resume loops forever.
    if {"verify_queue", "sc_verify_queue"} & set(checkpoint.completed):
        try:
            # If any verify SHARD already completed, route dropped IDs to the
            # excluded ledger (acknowledge for parity) instead of the active
            # queue — expanding the active queue post-verify makes completed
            # shards look incomplete ("wrote 1/4 verifier files") and triggers a
            # full verify-stage rewind. If only verify_queue completed (verify
            # shards have NOT run yet), route active so they still get verified.
            _verify_shards_done = any(
                (n.startswith("verify_") or n.startswith("sc_verify_"))
                and not n.endswith("_queue")
                and not n.endswith("_aggregate")
                for n in (checkpoint.completed or [])
            )
            _route = "excluded" if _verify_shards_done else "active"
            _bf = backfill_unrouted_inventory_into_queue(scratchpad, route=_route)
            if _bf:
                _where = (
                    "deferred to the evidence-excluded ledger (verify shards "
                    "already completed — not re-running verification)"
                    if _route == "excluded"
                    else "into the active verification_queue.md"
                )
                log.warning(
                    "[startup] mechanically backfilled "
                    f"{len(_bf)} unrouted inventory ID(s) {_where} before "
                    f"reconciliation (queue-generation dropout): "
                    f"{', '.join(_bf[:10])}"
                )
        except Exception as exc:
            log.warning(
                f"[startup] queue backfill skipped (non-blocking): {exc!r}"
            )
    try:
        artifact_rewound = _reconcile_completed_checkpoint_artifacts(
            scratchpad, config["project_root"], checkpoint, phases, mode
        )
    except RuntimeError as exc:
        # A stale checkpoint from a DIFFERENT mode/graph (e.g. a finished
        # Thorough run, then a new Core audit launched in the same scratchpad)
        # references phases absent from the active graph. That is NOT corruption
        # and must not halt a fresh start: archive the stale checkpoint and
        # continue with an empty one. Genuine corruption is caught earlier in
        # Checkpoint.load; any other RuntimeError still hard-exits.
        fresh_cp = _archive_stale_mismatched_checkpoint(
            scratchpad, checkpoint, config, mode, exc
        )
        if fresh_cp is not None:
            checkpoint = fresh_cp
            artifact_rewound = []
        else:
            log.error(f"[checkpoint] invalid resume state: {exc}")
            sys.exit(EXIT_DEGRADED)
    if artifact_rewound:
        checkpoint.save(scratchpad)
        log.warning(
            "[startup] rewound completed checkpoint entries because their "
            "artifact gates no longer pass: " + ", ".join(artifact_rewound)
        )
        active_phases = [p for p in phases if mode in p.modes]
        config["_active_phase_names"] = [p.name for p in active_phases]

    display.graceful_stop.install()
    display.pause_toggle.start()

    completed_count = sum(1 for p in active_phases if p.name in checkpoint.completed)
    remaining_count = len(active_phases) - completed_count
    ai_model = _format_ai_model_summary(config, active_phases, mode)
    display.print_banner(
        config["pipeline"], mode, config["project_root"],
        remaining_count, completed_count, str(scratchpad), ai_model,
        ecosystem=config.get("language", ""),
    )

    prev_phase: Optional[str] = None
    skipped_names: list[str] = []
    _halted = False
    _rate_limit_halt = False

    for phase in phases:
        if phase.name in checkpoint.completed:
            skipped_names.append(phase.name)
            log.info(f"[{phase.name}] already completed -- skipping")
            continue
        if mode not in phase.modes:
            skipped_names.append(phase.name)
            log.info(f"[{phase.name}] not in {mode} mode -- skipping")
            continue

        if skipped_names:
            display.print_skipped_summary(skipped_names)
            skipped_names = []

        # Compute phase index within active (mode-filtered) phases once,
        # so both conditional-skip display and print_phase_start use it.
        total_active = len(active_phases)
        phase_idx = next(
            (i for i, p in enumerate(active_phases) if p.name == phase.name),
            0,
        )

        # ── Bake phase: mechanical pre-write fallback ────────────────
        # primitive_status.md records SCIP/opengrep/ast-grep availability.
        # Pre-write the fallback so the gate passes even if the LLM fails
        # to probe tools or they aren't installed. Both Claude and Codex
        # then try to improve it via shell probes (Codex has full shell
        # access via --dangerously-bypass-approvals-and-sandbox).
        if phase.name == "bake":
            _PRIMITIVE_FALLBACK = (
                "SCIP_GO_REUSED=false\n"
                "SCIP_GO_AVAILABLE=false\n"
                "SCIP_RUST_REUSED=false\n"
                "SCIP_RUST_AVAILABLE=false\n"
                "SCIP_PREBAKE_COMPLETE=false\n"
                "SCIP_PREBAKE_FILES=0\n"
                "OPENGREP_AVAILABLE=false\n"
                "AST_GREP_AVAILABLE=false\n"
            )
            prim = scratchpad / "primitive_status.md"
            if not prim.exists():
                prim.write_text(_PRIMITIVE_FALLBACK, encoding="utf-8")
                log.info("[bake] pre-wrote primitive_status.md with fallback content")

        if phase.name == "inventory_prepare":
            ensure_inventory_shard_plan(
                scratchpad,
                int(config.get("inventory_target_per_shard", 70)),
                int(config.get("inventory_max_shards", 3)),
            )
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            log.info("[inventory_prepare] wrote inventory shard plan/manifests")
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                "mechanical (Python-only)",
            )
            continue

        if phase.name == "rescan_prepare":
            ensure_rescan_manifest(scratchpad, config)
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            log.info("[rescan_prepare] wrote rescan_manifest.md")
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                "mechanical (Python-only)",
            )
            continue

        if phase.name in (
            "inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"
        ):
            shard_files = parse_inventory_shard_manifest(scratchpad, phase.name)
            manifest_path = scratchpad / f"{phase.name}.manifest.md"
            if manifest_path.exists() and not shard_files:
                try:
                    manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    manifest_text = ""
                explicit_empty = bool(
                    re.search(r"\b(0\s+assigned|0\s+source|no\s+assigned|empty\s+shard)\b",
                              manifest_text, re.IGNORECASE)
                    or re.search(r"\bAssigned\s+files\s*:\s*0\b", manifest_text, re.IGNORECASE)
                    or (
                        "FILE" in manifest_text.upper()
                        and (
                            "ROLE" in manifest_text.upper()
                            or "STATUS" in manifest_text.upper()
                            or "MODEL" in manifest_text.upper()
                        )
                    )
                )
                if not explicit_empty:
                    (scratchpad / f"{phase.name}.degraded").write_text(
                        f"[MANIFEST-SCHEMA-INVALID] {manifest_path.name} exists but "
                        "contains no parseable assigned source files.\n",
                        encoding="utf-8",
                    )
                    if phase.name not in checkpoint.degraded:
                        checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
                    log.error(f"[{phase.name}] shard manifest schema invalid")
                    if phase.critical:
                        display.print_failure_diagnosis(
                            phase.name, str(scratchpad),
                            [f"shard manifest schema invalid: {manifest_path.name}"],
                            config,
                        )
                        sys.exit(EXIT_DEGRADED)
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "manifest schema invalid (degraded)",
                    )
                    continue
            if not shard_files:
                write_inventory_chunk_placeholder(
                    scratchpad, phase.name, "0 assigned analysis files in shard manifest"
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[{phase.name}] N/A (0 assigned analysis files) -- writing placeholder and skipping")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "0 assigned files in shard",
                )
                continue

        if phase.name == "inventory":
            shard_outputs = []
            for name in (
                "findings_inventory_chunk_a.md",
                "findings_inventory_chunk_b.md",
                "findings_inventory_chunk_c.md",
            ):
                p = scratchpad / name
                if p.exists() and p.stat().st_size >= 100:
                    shard_outputs.append(p)
            if len(shard_outputs) >= 2:
                parsed, merged = _write_mechanical_inventory_from_chunks(scratchpad)
                if merged > 0:
                    _validate_inventory_evidence(scratchpad, config["project_root"])
                    parity_issues = _validate_inventory_parity(scratchpad)
                    if not parity_issues:
                        checkpoint.mark_completed(phase.name)
                        checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                        checkpoint.save(scratchpad)
                        log.info(
                            f"[inventory] mechanically merged {parsed} chunk findings "
                            f"into {merged} inventory findings"
                        )
                        display.print_phase_skipped(
                            phase_idx + 1, total_active, phase.name,
                            f"mechanical merge ({merged} findings from chunks)",
                        )
                        continue
                    log.error(
                        f"[inventory] mechanical chunk merge failed parity: {parity_issues}"
                    )
            if len(shard_outputs) == 1:
                target = scratchpad / "findings_inventory.md"
                target.write_text(
                    shard_outputs[0].read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8",
                )
                _write_finding_records_from_inventory(scratchpad)
                # v2.4.3: run parity + evidence validators instead of blindly continuing
                _validate_inventory_evidence(scratchpad, config["project_root"])
                parity_issues = _validate_inventory_parity(scratchpad)
                if not parity_issues:
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info("[inventory] single-shard inventory copied directly to findings_inventory.md")
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "mechanical (single-shard copy)",
                    )
                    continue
                log.warning(f"[inventory] single-shard copy failed parity: {parity_issues}")

            # B1 inventory floor (WIRE #1): the chunk-merge / single-shard
            # fast-paths above did not produce a usable findings_inventory.md
            # (0/1 chunks, or merge failed parity). Reconstruct honestly from
            # whatever breadth/depth/chunk artifacts completed so the file is
            # ALWAYS present before sc_verify_queue. The floor is a NO-OP if a
            # real inventory already exists, and never fabricates findings.
            inv_path = scratchpad / "findings_inventory.md"
            _inv_missing = (
                not inv_path.exists()
                or not _inventory_has_usable_findings(scratchpad)
            )
            if _inv_missing:
                floor_n, floor_src = ensure_findings_inventory_floor(scratchpad)
                if floor_n > 0:
                    _validate_inventory_evidence(scratchpad, config["project_root"])
                    parity_issues = _validate_inventory_parity(scratchpad)
                    if not parity_issues:
                        checkpoint.mark_completed(phase.name)
                        checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                        checkpoint.save(scratchpad)
                        log.warning(
                            f"[inventory] floor reconstructed {floor_n} finding(s) "
                            f"from {floor_src} source artifact(s) "
                            "(degraded inventory phase) -- continuing"
                        )
                        display.print_phase_skipped(
                            phase_idx + 1, total_active, phase.name,
                            f"floor reconstruction ({floor_n} findings)",
                        )
                        continue
                    log.warning(
                        f"[inventory] floor reconstruction failed parity: {parity_issues}"
                    )

        if config["pipeline"] == "l1" and phase.name == "graph_sweeps":
            cov_issues = _compute_subsystem_coverage_gap(
                scratchpad, config.get("mode", "core"),
                scope_file=config.get("scope_file"),
            )
            if cov_issues:
                log.info(f"[graph_sweeps] {cov_issues[0]}")
            needed, reason = _graph_sweeps_needed(
                scratchpad, config.get("mode", "core")
            )
            if not needed:
                _write_graph_sweeps_skip(scratchpad, reason)
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[graph_sweeps] N/A ({reason}) -- writing skip summary")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"N/A ({reason})",
                )
                continue

        _skip_artifact_recovery_this_phase = False

        if phase.name == "attention_repair":
            needed, reason = _prepare_attention_repair(
                scratchpad, config.get("mode", "core")
            )
            if not needed:
                _write_attention_repair_skip(scratchpad, reason)
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[attention_repair] N/A ({reason}) -- writing skip summary")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"N/A ({reason})",
                )
                continue
            log.info(f"[attention_repair] queued {reason}")
            existing_hard, _existing_soft = _validate_attention_repair(
                scratchpad, config.get("mode", "core")
            )
            if not existing_hard:
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info("[attention_repair] existing artifacts validate -- skipping rerun")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "existing artifacts validate",
                )
                continue

        if config.get("pipeline") == "l1" and phase.name == "location_recovery":
            needed, reason = _location_recovery_needed(
                scratchpad, config["project_root"]
            )
            if not needed:
                _write_location_recovery_skip(scratchpad, reason)
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[location_recovery] N/A ({reason}) -- writing skip summary")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"N/A ({reason})",
                )
                continue
            log.info(f"[location_recovery] queued {reason}")

        # v2.5.0: SC depth promotion runs before sc_semantic_dedup (all modes).
        # Previously anchored to attention_repair (Thorough-only), which left
        # Light/Core operating on stale inventory for dedup + chain.
        if phase.name == "sc_semantic_dedup" and config.get("pipeline") == "sc":
            promoted = _promote_depth_findings_to_inventory(scratchpad)
            if promoted:
                log.info(
                    f"[sc_semantic_dedup] promoted {len(promoted)} depth "
                    "finding(s) into findings_inventory.md before dedup"
                )
            _dedup_cap = _dedup_live_pair_cap()
            log.info(
                f"[sc_semantic_dedup] compat-shim pair cap = {_dedup_cap} "
                f"(env PLAMEN_DEDUP_LIVE_PAIR_CAP="
                f"{os.environ.get('PLAMEN_DEDUP_LIVE_PAIR_CAP', '<default>')}); "
                "bounds the legacy fallback pair files only"
            )
            # Dedup redesign: the live LLM input is now dedup_blocks.md (in-context
            # clustering). _compute_dedup_candidate_blocks ALSO writes the legacy
            # compat pair files (dedup_candidate_pairs[.md|_full.md]) for the
            # mechanical fallback + supplemental path, so the degrade path is
            # unchanged. Returns the count of findings placed into blocks.
            n_blocked = _compute_dedup_candidate_blocks(scratchpad)
            if n_blocked:
                log.info(
                    f"[sc_semantic_dedup] {n_blocked} finding(s) placed into "
                    "dedup candidate blocks for in-context clustering"
                )
            else:
                log.info(
                    "[sc_semantic_dedup] no candidate duplicate blocks; "
                    "dedup will pass through"
                )
            # Legacy multi-round staging is no longer the live path (output is
            # bounded by construction). Keep the helpers wired against the compat
            # pair files for the fallback only.
            _rounds = _dedup_round_files(scratchpad)
            if len(_rounds) > 1:
                _stage_dedup_round_packet(scratchpad, _dedup_round_index(_rounds[0].name))
            dedup_issues = _validate_depth_promotion_dedup(scratchpad)
            for issue in dedup_issues:
                log.warning(f"[sc_semantic_dedup] {issue}")

        if phase.name == "attention_repair" and config.get("pipeline") == "sc":
            # Thorough-only: additional validation after promotion already happened
            pass

        # v2.4.9: Mechanical extraction of chain summaries before chain phase.
        # The chain prompt requires chain_summaries_compact.md (orchestrator-owned).
        if phase.name == "chain" and config.get("pipeline") == "sc":
            _extract_chain_summaries_compact(scratchpad)
            written = _write_chain_passthrough_outputs(
                scratchpad,
                "pre-run scaffold safety net; Chain Agent 1 may overwrite "
                "these artifacts with grouped hypotheses and enabler analysis",
            )
            log.info(
                f"[chain] wrote deterministic handoff scaffold before "
                f"Chain Agent 1 subprocess: {written}"
            )
            # The scaffold is a crash-safety net and bounded-input handoff,
            # not a completed chain phase. Do not let artifact recovery judge
            # these just-created files before the actual chain subprocess runs.
            _skip_artifact_recovery_this_phase = True
            # Chain Phase Bounding: mechanical pre-pass that turns the chain
            # agents' unbounded "exhaustively enumerate" tasks into finite
            # candidate sets — chain_candidate_pairs.md (bounds Agent 2 PHASE
            # 2), variable_finding_map.md, and a STEP 0a baseline in
            # enabler_results.md (bounds Agent 1 PHASE 0). Best-effort: a
            # producer failure leaves the passthrough scaffold above intact,
            # and the chain prompts fall back to their unbounded path — no
            # halt. Runs AFTER _write_chain_passthrough_outputs so the stub
            # enabler_results.md is the safety net if compute_enabler_baseline
            # raises.
            try:
                import importlib
                import sys as _sys
                _sys.path.insert(0, str(Path(__file__).parent))
                _cp = importlib.import_module("chain_prep")
                _cp_summary = _cp.run_chain_prep(scratchpad)
                log.info(f"[chain] chain_prep: {_cp_summary}")
            except Exception as _cp_exc:
                log.warning(
                    f"[chain] chain_prep skipped (non-blocking): {_cp_exc} — "
                    "chain agents fall back to unbounded path"
                )

        if config["pipeline"] == "l1" and phase.name == "verify_queue":
            # B2 verify graceful fallback (L1 parity with sc_verify_queue): if
            # the inventory phase degraded and left findings_inventory.md
            # missing/empty, reconstruct it honestly from completed artifacts
            # now so verification proceeds instead of hitting the terminal
            # "inventory missing" parity halt. NO-OP when a real inventory
            # already exists; genuinely empty audit gets a valid empty inventory.
            if not _inventory_has_usable_findings(scratchpad):
                _floor_n, _floor_src = ensure_findings_inventory_floor(scratchpad)
                if _floor_n > 0:
                    log.warning(
                        f"[verify_queue] inventory missing/empty; floor "
                        f"reconstructed {_floor_n} finding(s) from {_floor_src} "
                        "source artifact(s) -- verification proceeds (degraded)"
                    )
                else:
                    log.warning(
                        "[verify_queue] inventory missing/empty and "
                        f"{_floor_src} source artifact(s) yielded 0 findings; "
                        "wrote a valid empty inventory -- clean empty path"
                    )
            promoted = _promote_depth_findings_to_inventory(scratchpad)
            if promoted:
                log.info(
                    f"[verify_queue] promoted {len(promoted)} depth finding(s) "
                    "into findings_inventory.md before queue generation"
                )
            # L1-3 (WP-D): mechanically append verify-adjudicated
            # NEEDS_VERIFICATION rows for CROSS-DOMAIN-DEP candidates the
            # depth/scanner/sibling agents flagged. Low-confidence by
            # construction; never a CONFIRMED body finding. Runs AFTER the
            # depth-promotion bridge above so it rides the SAME INV-N id space.
            cross_domain_promoted = _promote_cross_domain_candidates_to_inventory(
                scratchpad
            )
            if cross_domain_promoted:
                log.info(
                    f"[verify_queue] promoted {len(cross_domain_promoted)} "
                    "cross-domain dependency candidate(s) (NEEDS_VERIFICATION) "
                    "into findings_inventory.md before queue generation"
                )
            _dedup_cap = _dedup_live_pair_cap()
            log.info(
                f"[verify_queue] compat-shim pair cap = {_dedup_cap} "
                f"(env PLAMEN_DEDUP_LIVE_PAIR_CAP="
                f"{os.environ.get('PLAMEN_DEDUP_LIVE_PAIR_CAP', '<default>')}); "
                "bounds the legacy fallback pair files only"
            )
            # Dedup redesign: live LLM input is dedup_blocks.md (in-context
            # clustering). _compute_dedup_candidate_blocks ALSO writes the legacy
            # compat pair files for the mechanical fallback path.
            n_blocked = _compute_dedup_candidate_blocks(scratchpad)
            if n_blocked:
                log.info(
                    f"[verify_queue] {n_blocked} finding(s) placed into dedup "
                    "candidate blocks for in-context clustering"
                )
            else:
                log.info(
                    "[verify_queue] no candidate duplicate blocks; "
                    "dedup will pass through"
                )
            dedup_issues = _validate_depth_promotion_dedup(scratchpad)
            for issue in dedup_issues:
                log.warning(f"[verify_queue] {issue}")
            _validate_inventory_evidence(scratchpad, config["project_root"])
            depth_promotion_issues = _validate_depth_promotion_receipt(scratchpad)
            if depth_promotion_issues:
                log.error("[verify_queue] " + "; ".join(depth_promotion_issues))
                (scratchpad / "verify_queue.degraded").write_text(
                    "Depth promotion failed before verification queue.\n"
                    + "\n".join(depth_promotion_issues)
                    + "\n",
                    encoding="utf-8",
                )
                if "verify_queue" not in checkpoint.degraded:
                    checkpoint.degraded.append("verify_queue")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), depth_promotion_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            _write_finding_records_from_inventory(scratchpad)
            routed = _write_mechanical_verification_queue_from_inventory(scratchpad)
            removed = _filter_verification_queue_by_evidence(scratchpad)
            mode_filtered = _filter_verification_queue_by_mode(
                scratchpad, config.get("mode", "core"), pipeline_label="L1",
            )
            if mode_filtered:
                log.info(
                    f"[verify_queue] moved {mode_filtered} Low/Info "
                    f"finding(s) to evidence-excluded for {config.get('mode')} mode"
                )
            try:
                _bf = backfill_unrouted_inventory_into_queue(scratchpad)
                if _bf:
                    log.warning(
                        f"[{phase.name}] mechanically backfilled {len(_bf)} "
                        "unrouted inventory ID(s) into verification_queue.md "
                        f"(queue-generation dropout): {', '.join(_bf[:10])}"
                    )
            except Exception as exc:
                log.warning(
                    f"[{phase.name}] queue backfill skipped (non-blocking): {exc!r}"
                )
            shards = ensure_verify_shard_manifests(scratchpad)
            queue_issues = _validate_verification_queue_inventory_parity(scratchpad)
            if queue_issues:
                log.error("[verify_queue] " + "; ".join(queue_issues))
                (scratchpad / "verify_queue.degraded").write_text(
                    "Verification queue parity failed.\n"
                    + "\n".join(queue_issues)
                    + "\n",
                    encoding="utf-8",
                )
                if "verify_queue" not in checkpoint.degraded:
                    checkpoint.degraded.append("verify_queue")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), queue_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            active = len(parse_verification_queue_rows(scratchpad))
            shard_count = sum(len(v) for v in shards.values())
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            excluded_total = len(removed) + int(mode_filtered or 0)
            extra = f"; evidence-excluded {excluded_total}" if excluded_total else ""
            log.info(
                f"[verify_queue] mechanically routed {routed} inventory "
                f"finding(s) into {active} active queue row(s) across "
                f"{len(shards)} shard manifest(s), shard rows={shard_count}{extra}"
            )
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                f"mechanical ({active} queue rows across {len(shards)} shards)",
            )
            continue

        # v2.4.1: SC verify queue — mechanical, same pattern as L1.
        if config.get("pipeline") != "l1" and phase.name == "sc_verify_queue":
            # B2 verify graceful fallback: if the inventory phase degraded and
            # left findings_inventory.md missing/empty, reconstruct it honestly
            # from completed artifacts NOW so verification proceeds on the real
            # findings instead of hitting the terminal "inventory missing"
            # parity halt. NO-OP when a real inventory already exists; a
            # genuinely empty audit still gets a valid empty inventory.
            if not _inventory_has_usable_findings(scratchpad):
                _floor_n, _floor_src = ensure_findings_inventory_floor(scratchpad)
                if _floor_n > 0:
                    log.warning(
                        f"[sc_verify_queue] inventory missing/empty; floor "
                        f"reconstructed {_floor_n} finding(s) from {_floor_src} "
                        "source artifact(s) -- verification proceeds (degraded)"
                    )
                else:
                    log.warning(
                        "[sc_verify_queue] inventory missing/empty and "
                        f"{_floor_src} source artifact(s) yielded 0 findings; "
                        "wrote a valid empty inventory -- clean empty path"
                    )
            promoted = _promote_depth_findings_to_inventory(scratchpad)
            if promoted:
                log.info(
                    f"[sc_verify_queue] promoted {len(promoted)} depth finding(s) "
                    "into findings_inventory.md before queue generation"
                )
            _validate_inventory_evidence(scratchpad, config["project_root"])
            depth_promotion_issues = _validate_depth_promotion_receipt(scratchpad)
            if depth_promotion_issues:
                log.error("[sc_verify_queue] " + "; ".join(depth_promotion_issues))
                (scratchpad / "sc_verify_queue.degraded").write_text(
                    "Depth promotion failed before verification queue.\n"
                    + "\n".join(depth_promotion_issues)
                    + "\n",
                    encoding="utf-8",
                )
                if "sc_verify_queue" not in checkpoint.degraded:
                    checkpoint.degraded.append("sc_verify_queue")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), depth_promotion_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            _write_finding_records_from_inventory(scratchpad)
            routed = _write_mechanical_verification_queue_from_inventory(scratchpad)
            # v2.4.8: collapse queue rows sharing the same hypothesis into one
            # representative row. Reduces 89→~49 rows for typical SC audits,
            # eliminating ~45% verify budget waste on redundant constituents.
            hypo_deduped = _dedup_queue_by_hypothesis(scratchpad)
            if hypo_deduped:
                log.info(
                    f"[sc_verify_queue] hypothesis dedup removed {hypo_deduped} "
                    "redundant constituent row(s)"
                )
            mode_filtered = _filter_sc_verification_queue_by_mode(
                scratchpad, config.get("mode", "core")
            )
            if mode_filtered:
                log.info(
                    f"[sc_verify_queue] moved {mode_filtered} Low/Info "
                    f"row(s) to evidence-excluded for {config.get('mode')} mode"
                )
            removed = _filter_verification_queue_by_evidence(scratchpad)
            try:
                _bf = backfill_unrouted_inventory_into_queue(scratchpad)
                if _bf:
                    log.warning(
                        f"[{phase.name}] mechanically backfilled {len(_bf)} "
                        "unrouted inventory ID(s) into verification_queue.md "
                        f"(queue-generation dropout): {', '.join(_bf[:10])}"
                    )
            except Exception as exc:
                log.warning(
                    f"[{phase.name}] queue backfill skipped (non-blocking): {exc!r}"
                )
            shards = ensure_sc_verify_shard_manifests(scratchpad)
            queue_issues = _validate_verification_queue_inventory_parity(scratchpad)
            if queue_issues:
                log.error("[sc_verify_queue] " + "; ".join(queue_issues))
                (scratchpad / "sc_verify_queue.degraded").write_text(
                    "Verification queue parity failed.\n"
                    + "\n".join(queue_issues)
                    + "\n",
                    encoding="utf-8",
                )
                if "sc_verify_queue" not in checkpoint.degraded:
                    checkpoint.degraded.append("sc_verify_queue")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), queue_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            active = len(parse_verification_queue_rows(scratchpad))
            shard_count = sum(len(v) for v in shards.values())
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            extra = f"; evidence-excluded {len(removed)}" if removed else ""
            log.info(
                f"[sc_verify_queue] mechanically routed {routed} inventory "
                f"finding(s) into {active} active queue row(s) across "
                f"{len(shards)} shard manifest(s), shard rows={shard_count}{extra}"
            )
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                f"mechanical ({active} queue rows across {len(shards)} shards)",
            )
            continue

        # v2.4.1→v2.4.3: SC verify aggregate — mechanical pre-step, then fall
        # through to _run_phase_validators for parity/evidence/containment checks.
        # Prior to v2.4.3, this block did `continue` which bypassed all validators.
        if config.get("pipeline") != "l1" and phase.name == "sc_verify_aggregate":
            _generate_verify_core_if_missing(scratchpad)

        if phase.name in ("semantic_dedup", "sc_semantic_dedup"):
            # Multi-round staging: if the parser split the candidate set into
            # per-round packets, stage round 1 into the canonical live file
            # `dedup_candidate_pairs.md` (with a carry-forward exclusion list)
            # so the subprocess sees a bounded, per-pair-judged packet. The live
            # file may already be round-1 from the pre-phase staging; restaging
            # is idempotent (round 1's exclusion list is empty on a fresh run).
            # Subsequent rounds are handled by the post-swap _run_dedup_rounds
            # carry-forward path. No merge is applied mechanically here.
            _stage_rounds = _dedup_round_files(scratchpad)
            if len(_stage_rounds) > 1:
                staged = _stage_dedup_round_packet(
                    scratchpad, _dedup_round_index(_stage_rounds[0].name)
                )
                if staged is not None:
                    log.info(
                        f"[{phase.name}] staged dedup round 1 of "
                        f"{len(_stage_rounds)} into dedup_candidate_pairs.md "
                        "(carry-forward exclusion list prepended)"
                    )
            blocks_file = scratchpad / "dedup_blocks.md"
            pairs_file = scratchpad / "dedup_candidate_pairs.md"
            focus_file = scratchpad / "dedup_focus_inventory.md"
            inv_file = scratchpad / "findings_inventory.md"
            # Dedup redesign: the live LLM signal is now dedup_blocks.md. A block
            # file with at least one "## Block " section means there are real
            # candidate clusters to review. The legacy compat pair file is still
            # present (written by the block builder) for the mechanical fallback,
            # but it no longer drives the live signal/budget decision.
            has_blocks = False
            blocks_bytes = 0
            if blocks_file.exists():
                try:
                    blocks_bytes = blocks_file.stat().st_size
                    blocks_text = blocks_file.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    has_blocks = bool(
                        re.search(r"(?im)^\s*##\s+Block\s+", blocks_text)
                    )
                except Exception:
                    has_blocks = False
            has_pairs = pairs_file.exists() and pairs_file.stat().st_size > 100
            pair_rows = 0
            if has_pairs:
                try:
                    pair_text = pairs_file.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    pair_rows = sum(
                        1
                        for line in pair_text.splitlines()
                        if line.lstrip().startswith("|")
                        and not re.match(r"\s*\|\s*-+", line)
                        and "Finding A" not in line
                    )
                except Exception:
                    pair_rows = 0
            inventory_count = 0
            has_likely_dup = False
            if inv_file.exists():
                try:
                    inv_text = inv_file.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    has_likely_dup = "LIKELY-DUP" in inv_text
                    inventory_count = len(
                        re.findall(r"(?im)^\s*#{2,4}\s+Finding\s+\[", inv_text)
                    )
                except Exception:
                    pass
            if not has_blocks and not has_likely_dup:
                written = _write_semantic_dedup_skip_outputs(
                    scratchpad,
                    phase.name,
                    "no candidate blocks and no LIKELY-DUP tags",
                )
                log.info(
                    f"[{phase.name}] no dedup signals (no candidate blocks, "
                    "no LIKELY-DUP tags) -- wrote no-op outputs "
                    f"{written} and skipping"
                )
                _record_phase_artifact_state(
                    scratchpad,
                    config["project_root"],
                    phases,
                    phase.name,
                    config["pipeline"],
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "no dedup signals",
                )
                continue
            # Dedup redesign: the live work is now bounded BY CONSTRUCTION.
            # dedup_blocks.md lists size-bounded (4..18) in-context clustering
            # blocks and the subprocess emits a few KB of MERGE/KEEP lines for
            # any n -- the O(n^2) per-pair output-token explosion that motivated
            # the old hard guard is structurally gone. The budget guard is kept
            # only as defense-in-depth against a malformed/oversized block file
            # (e.g. a runaway producer), gated on block-file SIZE rather than
            # pair rows. Sentinel: ~200KB (a 300-finding inventory blocks file is
            # comfortably under this per the halt test).
            _DEDUP_BLOCKS_SIZE_SENTINEL = 200 * 1024
            _blocks_over_budget = blocks_bytes > _DEDUP_BLOCKS_SIZE_SENTINEL
            if _blocks_over_budget:
                reason = (
                    "semantic dedup budget guard: dedup_blocks.md is "
                    f"{blocks_bytes} bytes (sentinel "
                    f"{_DEDUP_BLOCKS_SIZE_SENTINEL}); a malformed/oversized "
                    "block file; preserving upstream artifact unchanged to "
                    "avoid a timeout/retry loop"
                )
                written = _write_semantic_dedup_skip_outputs(
                    scratchpad,
                    phase.name,
                    reason,
                )
                log.warning(f"[{phase.name}] {reason}; wrote {written}")
                _record_phase_artifact_state(
                    scratchpad,
                    config["project_root"],
                    phases,
                    phase.name,
                    config["pipeline"],
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "budget guard (oversized block file)",
                )
                continue
            prewritten = _write_semantic_dedup_skip_outputs(
                scratchpad,
                phase.name,
                "pre-run passthrough safety net; bounded semantic dedup may "
                "overwrite these artifacts if it completes with valid outputs",
            )
            log.info(
                f"[{phase.name}] wrote deterministic passthrough before "
                f"bounded semantic-dedup subprocess: {prewritten}"
            )
            # These files are a crash-safety net for the subprocess, not a
            # completed phase result. Artifact recovery runs after phase
            # prework, so without this guard it judges the just-created
            # passthrough and emits owner-state noise before launching the
            # actual bounded dedup worker.
            _skip_artifact_recovery_this_phase = True

        # Fix 4 + Fix 1 (item C): pre-compute the same-tier AND cross-tier
        # candidate HINT list for the report_dedup_agent (Phase 6d LLM
        # proposer). Fix 4 covered cross-tier identical-location twins (a High
        # and a Medium at the same lines); Fix 1 closed the gap where the
        # candidate list stayed cross-tier-only even after the mechanical
        # executor (`_dedup_report_candidate_pairs`) was widened to generate
        # same-tier candidates too — same-tier merging depended on the LLM
        # doing unaided exhaustive pairwise comparison with no scaffolding.
        # This writes report_dedup_candidate_pairs.md (candidate-only — the
        # agent's same-root-cause + same-fix test stays the sole merge
        # authority). Best-effort: a failure only loses the hint, never a finding.
        if phase.name == "report_dedup_agent":
            try:
                n_cand = _compute_report_dedup_candidate_pairs(scratchpad)
                log.info(
                    f"[report_dedup_agent] wrote report_dedup_candidate_pairs.md "
                    f"({n_cand} same-tier/cross-tier candidate pair(s))"
                )
            except Exception as exc:
                log.warning(
                    f"[report_dedup_agent] candidate-pair pre-compute failed: {exc!r}"
                )

        # Pre-compute binding severity table for report_index LLM.
        # Eliminates retry cycles caused by the LLM silently inflating
        # severity without a Trust Adj. reason.
        if phase.name == "report_index":
            try:
                sev_map = _expected_report_index_severities(scratchpad)
                if sev_map:
                    lines = [
                        "# Severity Binding Table",
                        "",
                        "Driver-computed expected severities from verify files "
                        "and verification queue. The Index Agent MUST use these "
                        "severities unless a Trust Adj. reason is documented.",
                        "",
                        "| Finding ID | Expected Severity |",
                        "|------------|-------------------|",
                    ]
                    for fid in sorted(sev_map, key=lambda x: x.upper()):
                        lines.append(f"| {fid} | {sev_map[fid]} |")
                    (scratchpad / "severity_binding.md").write_text(
                        "\n".join(lines) + "\n", encoding="utf-8",
                    )
                    log.info(
                        f"[report_index] wrote severity_binding.md "
                        f"({len(sev_map)} finding(s))"
                    )
            except Exception as exc:
                log.warning(f"[report_index] severity binding failed: {exc!r}")

            # Fix 1: pre-compute the ONE canonical verification-status token per
            # finding (status_binding.md). The Index Agent fills BOTH the
            # report_index Verification column AND the body finding-header tag
            # from this file, ending the 71-index / 12-body / 17-PoC label
            # collision. Best-effort: a failure only loses the convenience
            # binding (the LLM falls back to reading the verify verdicts).
            try:
                status_map = _expected_report_index_statuses(scratchpad)
                if status_map:
                    _slines = [
                        "# Verification Status Binding Table",
                        "",
                        "Driver-computed canonical verification-status token per "
                        "finding, from (verifier verdict, best evidence tag). The "
                        "Index Agent MUST use these tokens for BOTH the "
                        "report_index Verification column AND the body "
                        "`### [X-NN] Title [STATUS]` header tag.",
                        "",
                        "- VERIFIED  = verdict CONFIRMED + proof-grade evidence "
                        "([POC-PASS]/[MEDUSA-PASS]/[PROD-*])",
                        "- CONFIRMED = verdict CONFIRMED but only [CODE-TRACE]",
                        "- CONTESTED = disputed (CONTESTED/UNRESOLVED/PARTIAL)",
                        "- UNVERIFIED = refuted / none",
                        "",
                        "| Finding ID | Verification Status |",
                        "|------------|---------------------|",
                    ]
                    for fid in sorted(status_map, key=lambda x: x.upper()):
                        _slines.append(f"| {fid} | {status_map[fid]} |")
                    (scratchpad / "status_binding.md").write_text(
                        "\n".join(_slines) + "\n", encoding="utf-8",
                    )
                    log.info(
                        f"[report_index] wrote status_binding.md "
                        f"({len(status_map)} finding(s))"
                    )
            except Exception as exc:
                log.warning(f"[report_index] status binding failed: {exc!r}")

            # R2: mechanical completeness backbone. Enumerate every finding/
            # hypothesis ID from bounded ledgers so the Index Agent never has
            # to bulk-read the 100K+ findings_inventory.md to recover the ID
            # set. Coverage stays guaranteed by the existing 6a.1 gate over
            # this bounded list. Best-effort: a failure here only loses the
            # convenience seed (the LLM falls back to the bounded sources it
            # already reads), never a finding.
            try:
                seed_rows = _write_report_index_coverage_seed(scratchpad)
                log.info(
                    f"[report_index] wrote report_index_coverage_seed.md "
                    f"({seed_rows} ID row(s))"
                )
            except Exception as exc:
                log.warning(
                    f"[report_index] coverage seed write failed: {exc!r}"
                )

            # Gate P (Fix C, recall): content-shaped Promotion Completeness —
            # see `_run_gate_p_for_report_index` for the full contract. Runs
            # immediately after the coverage-seed write above so orphan
            # reconciliation has an accurate "already tracked" ID set.
            _run_gate_p_for_report_index(scratchpad)

            # Hook-4 (Fix B, recall): haltless WARN gate for uncited
            # external-dependency research assumptions. Depth/chain/verify
            # have all completed by this point in the phase order. Pure
            # telemetry: never mutates a finding's severity/disposition,
            # never halts. Surfaced as an advisory Appendix note later, in
            # the report_floor phase (see
            # `_append_external_research_appendix_note`).
            try:
                _erg_n = _check_external_research_citation_gaps(scratchpad)
                if _erg_n:
                    log.info(
                        f"[report_index] external-research citation gate: "
                        f"{_erg_n} uncited external-assumption finding(s) "
                        "flagged (see external_research_gaps.md)"
                    )
            except Exception as exc:
                log.warning(
                    "[report_index] external-research citation gate skipped "
                    f"(non-blocking): {exc}"
                )

        if config["pipeline"] == "sc" and phase.name == "report_index":
            # PRE-SPAWN repair ONLY. `_repair_sc_report_index_from_prior` returns
            # 0 on a fresh run (no prior report_index.md to repair) — in that case
            # this block is a no-op and the driver falls through to spawn the LLM
            # Index Agent, which writes the CONSOLIDATED index + report_coverage.md.
            # Do NOT validate/rebuild unconditionally here: on a fresh run the
            # agent has not run yet, so report_index.md/report_coverage.md do not
            # exist, and an unconditional mechanical rebuild would pre-empt the
            # Index Agent and replace its consolidated index with a flat,
            # un-consolidated one (the inflated-finding-count regression).
            # Genuine post-agent dropouts are handled by the completeness gate
            # (_check_index_completeness + _repair_report_index_dropouts).
            repaired = _repair_sc_report_index_from_prior(scratchpad)
            if repaired:
                idx_in_issues = _validate_report_index_inputs(scratchpad)
                coverage_issues = _validate_report_coverage_accounting(scratchpad)
                if not idx_in_issues and not coverage_issues:
                    try:
                        manifests = _build_sc_body_writer_manifests(scratchpad)
                    except Exception as exc:
                        manifests = {}
                        log.warning(
                            f"[report_index] SC manifest rebuild after repair failed: {exc!r}"
                        )
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(
                        f"[report_index] mechanically repaired report_index.md "
                        f"with {repaired} active row(s); manifests={len(manifests)}"
                    )
                    phases[:] = expand_shard_phases(phases, scratchpad)
                    active_phases = [p for p in phases if mode in p.modes]
                    total_active = len(active_phases)
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        f"mechanical repair ({repaired} active rows)",
                    )
                    continue
                log.warning(
                    "[report_index] mechanical SC repair did not satisfy gates: "
                    + "; ".join(idx_in_issues + coverage_issues)
                )

        if config["pipeline"] == "l1" and phase.name == "report_index":
            # Phase E2: refuse to mechanically write report_index when queue
            # has unverified rows. Do not validate stale report_index.md
            # before the deterministic rewrite; content gates run after write.
            idx_in_issues = _validate_report_index_prewrite_inputs(scratchpad)
            if idx_in_issues:
                log.error("[report_index] " + "; ".join(idx_in_issues))
                (scratchpad / "report_index.degraded").write_text(
                    "report_index halted: unverified queue rows.\n"
                    + "\n".join(idx_in_issues) + "\n",
                    encoding="utf-8",
                )
                if "report_index" not in checkpoint.degraded:
                    checkpoint.degraded.append("report_index")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), idx_in_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            active = _write_mechanical_report_index(scratchpad)
            idx_post_issues = _validate_report_index_inputs(scratchpad)
            if idx_post_issues:
                # L1 haltless-parity (v2.8.17): mirror SC's repair-then-
                # revalidate flow for the report_index post-write gate before
                # any degrade decision. The severity-provenance portion of this
                # gate is PROSE/RECALL-dependent (it flags LLM/matrix severity
                # changes that lack a recognized Trust Adj. reason) and must NOT
                # orphan an 11h+ audit over 1-3 mis-classified rows.
                #
                # Step 1: auto-repair downgrade-only provenance violations
                # (mechanical, safe direction — under-flagging) and revalidate.
                sev_repairs = _repair_report_index_severity_provenance(scratchpad)
                if sev_repairs:
                    applied = [
                        r for r in sev_repairs
                        if str(r.get("action", "")).startswith("applied")
                    ]
                    if applied:
                        log.info(
                            f"[report_index] auto-tagged {len(applied)} severity "
                            f"downgrade(s) as SEVERITY_OVERRIDE(<upstream>); see "
                            f"_severity_override_ledger.json for the ledger"
                        )
                    idx_post_issues = _validate_report_index_inputs(scratchpad)
            if idx_post_issues:
                # Step 2: partition residual issues into HARD (mechanical:
                # missing/unverified verify file = silent-drop risk) vs SOFT
                # (prose: severity provenance that repair could not safely
                # resolve, e.g. inflation). HARD keeps blocking (silent-drop
                # protection preserved). SOFT degrades-with-flag: written to a
                # human-review artifact and the pipeline continues, matching the
                # obligation-ledger and SC degrade-with-flag philosophy.
                hard_post_issues = _validate_verify_files_for_queue(scratchpad)
                if hard_post_issues:
                    hard_post_issues = [
                        "report_index: " + hard_post_issues[0]
                        + " — refuse to write report_index.md"
                    ]
                    log.error("[report_index] " + "; ".join(hard_post_issues))
                    (scratchpad / "report_index.degraded").write_text(
                        "report_index halted: generated report_index failed "
                        "validation (mechanical verify-file parity).\n"
                        + "\n".join(hard_post_issues) + "\n",
                        encoding="utf-8",
                    )
                    if "report_index" not in checkpoint.degraded:
                        checkpoint.degraded.append("report_index")
                    checkpoint.save(scratchpad)
                    display.print_failure_diagnosis(
                        phase.name, str(scratchpad), hard_post_issues, config,
                    )
                    sys.exit(EXIT_DEGRADED)
                # Residual = PROSE/RECALL severity provenance. Degrade-not-halt:
                # flag for human review, do NOT sys.exit, let the audit finish.
                try:
                    (scratchpad / "report_semantic_severity_repairs.md").write_text(
                        "# Report Severity Provenance — Human Review\n\n"
                        "Non-blocking severity-provenance telemetry (v2.8.17).\n"
                        "The report_index severity for the rows below differs "
                        "from the upstream verifier/queue severity and could not "
                        "be auto-resolved as a safe downgrade (e.g. it is an "
                        "inflation, or the Trust Adj. cell was non-empty). These "
                        "are flagged, NOT silently dropped, and do NOT halt the "
                        "pipeline. A human reviewer should confirm the final tier "
                        "for each row before delivery.\n\n"
                        + "\n".join(f"- {issue}" for issue in idx_post_issues)
                        + "\n",
                        encoding="utf-8",
                    )
                except Exception as exc:
                    log.warning(
                        f"[report_index] could not write severity-repair "
                        f"review artifact: {exc!r}"
                    )
                log.warning(
                    "[report_index] severity-provenance issue(s) flagged for "
                    "human review (report_semantic_severity_repairs.md); "
                    "pipeline continues (degrade-not-halt): "
                    + "; ".join(idx_post_issues)
                )
            coverage_issues = _validate_report_coverage_accounting(scratchpad)
            if coverage_issues:
                log.error("[report_index] " + "; ".join(coverage_issues))
                (scratchpad / "report_index.degraded").write_text(
                    "report_index halted: raw candidate accounting failed.\n"
                    + "\n".join(coverage_issues) + "\n",
                    encoding="utf-8",
                )
                if "report_index" not in checkpoint.degraded:
                    checkpoint.degraded.append("report_index")
                checkpoint.save(scratchpad)
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), coverage_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            # Degrade-not-halt: obligation-ledger retention risks are flagged
            # for human review (report_semantic_retention_risks.md) but do NOT
            # halt the pipeline. Emit a non-blocking warning so the operator
            # sees the flagged obligation(s) without discarding a finished audit.
            _risks_path = scratchpad / "report_semantic_retention_risks.md"
            if _risks_path.exists():
                log.warning(
                    "[report_index] non-blocking retention risks flagged for "
                    f"human review: {_risks_path.name} (pipeline continues)"
                )
            if (scratchpad / "report_index.md").exists():
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(
                    f"[report_index] mechanically wrote report_index.md with "
                    f"{active} active finding(s)"
                )
                # Manifests now exist — expand tier sentinel phases so the
                # remaining loop iterations see per-shard body writers.
                phases[:] = expand_shard_phases(phases, scratchpad)
                active_phases = [p for p in phases if mode in p.modes]
                total_active = len(active_phases)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"mechanical ({active} findings indexed)",
                )
                continue

        # Phase E11 follow-up #1: empty-shard body-writer skip. When the
        # tier has no findings, deterministically write an empty-tier note
        # and mark complete instead of calling an LLM that would either
        # produce nothing or stub output. Idempotent — caller proceeds.
        if phase.name.startswith("report_body_writer_"):
            if config.get("pipeline") != "l1":
                try:
                    _build_sc_body_writer_manifests(scratchpad)
                except Exception as exc:
                    log.warning(
                        f"[{phase.name}] SC body manifest refresh failed: {exc!r}"
                    )
            if _maybe_skip_empty_body_writer(scratchpad, phase.name):
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(
                    f"[{phase.name}] empty shard — skipped LLM, wrote "
                    f"empty-tier note for {phase.expected_artifacts[0]}"
                )
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "empty shard (no findings in tier)",
                )
                continue

        # Phase 4b.7 pre-spawn skip. If the enumeration gate produced no
        # obligations, the depth-exploration agent has nothing to trace — skip
        # the LLM spawn, write a deterministic note, mark complete. This is the
        # haltless degrade-to-fallback path: with no obligations there is
        # nothing to lose, and any ENUMGAP candidates already appended by the
        # gate remain on the candidate->verify route.
        if phase.name == "enumgap_exploration":
            if _enumgap_exploration_has_no_obligations(scratchpad):
                try:
                    (scratchpad / "enumgap_exploration_findings.md").write_text(
                        "# Enumeration-Obligation Exploration\n\n"
                        "_No enumeration obligations were produced by the "
                        "post-depth enumeration gate (no mechanical reference "
                        "graph, or zero flagged obligations). There is nothing "
                        "to explore; the pipeline degrades to its prior "
                        "candidate->verify behavior. Any ENUMGAP candidates "
                        "emitted by the gate remain in the inventory._\n\n"
                        "## Coverage Record\n\n"
                        "| Obligation | Relationship | Disposition | Evidence |\n"
                        "|------------|--------------|-------------|----------|\n"
                        "| (none) | (none) | CLEAR | no obligations produced |\n",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(
                    f"[{phase.name}] N/A — no enumeration obligations produced; "
                    "skipping spawn (degrades to candidate->verify fallback)"
                )
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "N/A (no enumeration obligations)",
                )
                continue

        # Phase 4b.8 (M2) pre-spawn skip-when-clean. The driver computes the
        # hot-function × axis matrix MECHANICALLY FIRST (writing hot_function_axes.md
        # + _hot_function_axes.json), and ONLY spawns the deriver-worker if GAP
        # cells exist. With no GAP cells there is nothing to interrogate: write a
        # deterministic stub, mark complete, skip the LLM. Recall-safe: the matrix
        # is always persisted for visibility; the ambiguous-⇒-GAP default in
        # compute_axis_coverage_gaps means a spurious skip cannot hide a true gap.
        if phase.name == "axis_coverage":
            if _axis_coverage_has_no_gaps(scratchpad):
                try:
                    (scratchpad / "axis_coverage_findings.md").write_text(
                        "# Multi-Axis Coverage Meta-Pass\n\n"
                        "_The mechanically-computed hot-function × axis matrix "
                        "(see hot_function_axes.md) has no GAP cells — every "
                        "mechanically-hot function was already examined on every "
                        "in-scope risk axis (or the axis is a provable N/A). There "
                        "is nothing to interrogate; this additive phase is skipped. "
                        "No prior finding is lost._\n\n"
                        "## Coverage Record\n\n"
                        "| Function | Axis | Disposition | Evidence |\n"
                        "|----------|------|-------------|----------|\n"
                        "| (none) | (none) | CLEAR | no GAP cells in the matrix |\n",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(
                    f"[{phase.name}] N/A — hot-function × axis matrix has no GAP "
                    "cells; skipping spawn (matrix persisted for visibility)"
                )
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "N/A (no unexamined axes)",
                )
                continue

        # v2.8.8: chain_iter2 pre-spawn skip. If composition_coverage.md
        # reports zero unexplored cross-class Medium+ pairs, the
        # iteration-2 agent has nothing to do — skip the LLM spawn
        # entirely, write a deterministic empty-iteration note, mark
        # complete. Per rules/phase4c-chain-prompt.md ITERATIVE_CHAIN_COMPOSITION:
        # "If Agent 2 reported 0 new chains AND 0 unexplored cross-class
        # Medium+ pairs → skip iteration 2."
        if phase.name == "chain_iter2":
            if _chain_iter2_has_no_unexplored_pairs(scratchpad):
                # Write a deterministic note so the artifact gate sees
                # output and the validator sees an authentic empty state.
                try:
                    (scratchpad / "chain_iteration2.md").write_text(
                        "# Chain Iteration 2 Results\n\n"
                        "_No unexplored cross-class Medium+ pairs remaining "
                        "after Phase 4c Agent 2. Skipped iteration 2 LLM "
                        "spawn per ITERATIVE_CHAIN_COMPOSITION early-exit "
                        "rule._\n\n"
                        "- Pairs evaluated: 0\n"
                        "- New chains identified: 0\n"
                        "- Skip reason: composition_coverage.md reports 0 "
                        "unexplored cross-class Medium+ rows.\n",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(
                    f"[{phase.name}] N/A — composition coverage has 0 "
                    "unexplored cross-class Medium+ pairs; skipping spawn"
                )
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "N/A (no unexplored cross-class Medium+ pairs)",
                )
                continue

        # Phase E11: existing tier phases are deterministic confirmation
        # handlers. Body-writer phase is the prose author; this handler
        # only confirms the body-writer output is on disk and validates,
        # then marks complete. NO Python prose fallback — body-writer
        # failure halts at its own phase via critical=True. If we reach
        # here without a body-writer output, emit an explicit degraded
        # artifact and halt.
        _is_legacy_tier = (
            phase.name in ("report_critical_high", "report_medium", "report_low_info")
            or re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name)
        )
        if _is_legacy_tier:
            tier_path = scratchpad / f"{phase.name}.md"
            if not (tier_path.exists() and tier_path.stat().st_size > 100):
                if _restore_tier_body_from_overflow(scratchpad, phase.name):
                    log.info(
                        f"[{phase.name}] restored body-writer output from _overflow"
                    )
            if tier_path.exists() and tier_path.stat().st_size > 100:
                body_issues = _validate_tier_body_against_manifest(
                    scratchpad, phase.name
                )
                if not body_issues:
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(
                        f"[{phase.name}] body-writer output validated, "
                        "marking phase complete"
                    )
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "body-writer output already valid",
                    )
                    continue
                # Body writer ran but produced invalid output; surface as
                # explicit degraded artifact. No Python prose fallback.
                (scratchpad / f"{phase.name}.body_writer.degraded").write_text(
                    "[BODY-WRITER-DEGRADED] Body-writer output failed "
                    "validator:\n" + "\n".join(body_issues) + "\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                checkpoint.save(scratchpad)
                log.error(f"[{phase.name}] body-writer output failed validator")
                display.print_failure_diagnosis(
                    phase.name, str(scratchpad), body_issues, config,
                )
                sys.exit(EXIT_DEGRADED)
            # No body-writer output on disk: explicit degraded halt.
            (scratchpad / f"{phase.name}.body_writer.degraded").write_text(
                f"[BODY-WRITER-DEGRADED] No {phase.name}.md produced by "
                "body-writer phase.\n",
                encoding="utf-8",
            )
            if phase.name not in checkpoint.degraded:
                checkpoint.degraded.append(phase.name)
            checkpoint.save(scratchpad)
            log.error(f"[{phase.name}] body-writer produced no output")
            display.print_failure_diagnosis(
                phase.name, str(scratchpad),
                [f"body-writer produced no {phase.name}.md output"],
                config,
            )
            sys.exit(EXIT_DEGRADED)

        # Manifest-aware quorum override for breadth. By the time breadth
        # runs, instantiate has written spawn_manifest.md declaring the
        # exact set of breadth agents the orchestrator will spawn. Using
        # that count as the gate quorum catches partial-spawn failures
        # (e.g., 3 of 6 breadth agents returned output) that the hardcoded
        # floor of 3 would silently pass. Falls back to phase.min_artifacts_count
        # when manifest is absent or unreadable.
        if phase.name == "breadth":
            manifest_n = parse_breadth_manifest_count(scratchpad)
            manifest_path = scratchpad / "spawn_manifest.md"
            if manifest_path.exists() and manifest_n is None:
                try:
                    manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    manifest_text = ""
                if "template" in manifest_text.lower() and "required" in manifest_text.lower():
                    (scratchpad / "breadth.degraded").write_text(
                        "[MANIFEST-SCHEMA-INVALID] spawn_manifest.md exists "
                        "with breadth-manifest headers but no parseable rows.\n",
                        encoding="utf-8",
                    )
                    if "breadth" not in checkpoint.degraded:
                        checkpoint.degraded.append("breadth")
                    checkpoint.save(scratchpad)
                    log.error("[breadth] spawn_manifest.md schema invalid")
                    display.print_failure_diagnosis(
                        phase.name, str(scratchpad),
                        ["spawn_manifest.md schema invalid: has headers but no parseable rows"],
                        config,
                    )
                    sys.exit(EXIT_DEGRADED)
            if manifest_n is not None and manifest_n > phase.min_artifacts_count:
                old = phase.min_artifacts_count
                phase.min_artifacts_count = manifest_n
                log.info(
                    f"[breadth] manifest-aware quorum: {old} -> {manifest_n} "
                    f"(from spawn_manifest.md)"
                )
        elif phase.name == "depth" and config["pipeline"] == "l1":
            # L1 light mode skips the semantic-invariants phase, so there may
            # be no LLM-authored phase4b manifest before depth. The five
            # standard L1 depth agents are a phase-graph contract, not a
            # methodology guess; emit the default manifest mechanically so the
            # quorum gate remains strict in every mode.
            default_depth_manifest = scratchpad / "phase4b_manifest.md"
            if not default_depth_manifest.exists():
                default_depth_manifest.write_text(
                    "\n".join([
                        "| Agent | Role | Expected Artifact |",
                        "|---|---|---|",
                        "| depth-consensus-invariant | Consensus invariant | depth_consensus_invariant_findings.md |",
                        "| depth-network-surface | Network surface | depth_network_surface_findings.md |",
                        "| depth-state-trace | State trace | depth_state_trace_findings.md |",
                        "| depth-external | External boundary | depth_external_findings.md |",
                        "| depth-edge-case | Edge case | depth_edge_case_findings.md |",
                        "",
                    ]),
                    encoding="utf-8",
                )
            manifest_n = parse_depth_manifest_count(scratchpad)
            manifest_candidates = [
                scratchpad / "phase4b_manifest.md",
                scratchpad / "spawn_manifest.md",
            ]
            if any(p.exists() for p in manifest_candidates) and manifest_n is None:
                malformed_depth_manifest = False
                for mp in manifest_candidates:
                    if not mp.exists():
                        continue
                    try:
                        mt = mp.read_text(encoding="utf-8", errors="replace").lower()
                    except Exception:
                        mt = ""
                    if (
                        mp.name == "phase4b_manifest.md"
                        or ("template" in mt and "required" in mt)
                        or ("agent" in mt and ("role" in mt or "model" in mt))
                    ):
                        malformed_depth_manifest = True
                        break
                if malformed_depth_manifest:
                    (scratchpad / "depth.degraded").write_text(
                        "[MANIFEST-SCHEMA-INVALID] depth manifest exists but "
                        "no parseable depth-agent rows were found.\n",
                        encoding="utf-8",
                    )
                    if "depth" not in checkpoint.degraded:
                        checkpoint.degraded.append("depth")
                    checkpoint.save(scratchpad)
                    log.error("[depth] depth manifest schema invalid")
                    display.print_failure_diagnosis(
                        phase.name, str(scratchpad),
                        ["depth manifest schema invalid: no parseable depth-agent rows"],
                        config,
                    )
                    sys.exit(EXIT_DEGRADED)
            if manifest_n is not None and manifest_n > phase.min_artifacts_count:
                old = phase.min_artifacts_count
                phase.min_artifacts_count = manifest_n
                log.info(
                    f"[depth] manifest-aware quorum: {old} -> {manifest_n} "
                    f"(from phase4b_manifest.md/spawn_manifest.md)"
                )
        elif config["pipeline"] == "l1" and (
            phase.name in ("report_critical_high", "report_low_info")
            or re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name)
        ):
            tier_counts = parse_report_index_counts(scratchpad)
            _tier_shard_m = re.match(
                r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name
            )
            if _tier_shard_m:
                tier_base = _tier_shard_m.group(1)
                tier_shards = ensure_report_tier_shards(scratchpad, tier_base)
                count = len(tier_shards.get(phase.name, []))
            else:
                key = {
                    "report_critical_high": "critical_high",
                    "report_low_info": "low_info",
                }[phase.name]
                count = tier_counts.get(key, 0)
            phase.min_artifact_bytes = max(100, count * 400)
            if count == 0:
                write_report_tier_placeholder(
                    scratchpad, f"{phase.name}.md",
                    "0 findings assigned in report_index.md",
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[{phase.name}] N/A (0 assigned findings) -- writing placeholder and skipping")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "N/A (0 findings assigned)",
                )
                continue
            if not _validate_report_tier_completeness(scratchpad, phase.name):
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                log.info(f"[{phase.name}] existing tier artifact passes completeness -- skipping subprocess")
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "existing tier artifact passes completeness",
                )
                continue

        _merge_m = re.match(
            r"^report_(critical_high|medium|low_info)_merge$", phase.name
        )
        if _merge_m:
            _merge_tier = _merge_m.group(1)
            merge_report_tier_shards(scratchpad, _merge_tier)
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            shard_files = sorted(scratchpad.glob(f"report_{_merge_tier}_[a-z].md"))
            shard_names = [f.name for f in shard_files]
            if shard_names:
                log.info(f"[{phase.name}] merged {' + '.join(shard_names)} -> report_{_merge_tier}.md")
            else:
                log.info(f"[{phase.name}] no shard files — base file untouched")
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                f"mechanical merge ({', '.join(shard_names) if shard_names else 'no shards'})",
            )
            continue

        if phase.name == "crossbatch":
            rows = _write_crossbatch_manifest(scratchpad)
            if rows:
                log.info(
                    f"[crossbatch] manifest prepared with {len(rows)} "
                    "verifier ID(s)"
                )

        # Phase 5b: Mechanical PoC verification (Python-native, ON by default).
        # Same shape as report_assemble: driver invokes a Python function,
        # marks the phase completed on success, writes a degraded sentinel
        # (WARNING — not HALT) on failure. No LLM cost — the phase is pure
        # subprocess invocation of the existing PoC tests. Toolchain-missing
        # short-circuits gracefully (preserves LLM tags). Opt-out via
        # MECHANICAL_VERIFY=false env or config["mechanical_verify"]=False.
        if phase.name in ("sc_mechanical_verify", "mechanical_verify"):
            _mv_env = os.environ.get("MECHANICAL_VERIFY", "").lower()
            _mv_cfg = config.get("mechanical_verify")
            # Default ON. Explicit opt-out via env or config disables.
            disabled = (
                _mv_env in ("0", "false", "no", "off")
                or _mv_cfg is False
            )
            if disabled:
                # Phase is explicitly opted out — mark completed with a no-op
                # sentinel so the pipeline continues without halting on the
                # absent manifest.
                (scratchpad / "mechanical_verify_manifest.md").write_text(
                    "# Mechanical Verify Manifest\n\n"
                    "**Status**: SKIPPED — explicitly disabled.\n"
                    "Re-enable by unsetting `MECHANICAL_VERIFY` env "
                    "(default is ON) or `config['mechanical_verify']=True`.\n",
                    encoding="utf-8",
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    "disabled (MECHANICAL_VERIFY=false)",
                )
                continue

            try:
                import importlib
                import sys as _sys
                _sys.path.insert(0, str(Path(__file__).parent))
                _mv = importlib.import_module("mechanical_verify")
                # This runs the finding PoC tests (forge/cargo/go) synchronously
                # in-process — MANY minutes on a real project, with no terminal
                # heartbeat. Wrap in the live heartbeat so the silent window isn't
                # mistaken for a hang. No double-heartbeat: this is a Python-native
                # phase, not a PTY-supervised run_phase worker wait.
                with _phase_heartbeat_thread(display, phase.name, scratchpad):
                    summary = _mv.run_phase5b_mechanical_verify(
                        scratchpad,
                        Path(config["project_root"]),
                        config.get("language", ""),
                    )
                ok = summary.get("status") in ("ok", "no_verify_files",
                                                "toolchain_unavailable")
                log.info(
                    f"[{phase.name}] status={summary.get('status')} "
                    f"counts={summary.get('counts')} "
                    f"annotated={summary.get('files_annotated')} "
                    f"elapsed={summary.get('elapsed_s', 0):.1f}s"
                )
                integrity_issues = _validate_poc_pass_integrity(scratchpad)
                if integrity_issues:
                    log.info(
                        f"[{phase.name}] PoC integrity: "
                        f"{len(integrity_issues)} finding(s) downgraded "
                        "from [POC-PASS] to [CODE-TRACE]"
                    )
                    for issue in integrity_issues:
                        vf = _find_verify_file(scratchpad, issue["finding_id"])
                        if vf:
                            try:
                                vf_content = vf.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                                reason = issue["reason"]
                                for tag in EVIDENCE_TAGS_PROOF:
                                    if tag in vf_content:
                                        vf_content = vf_content.replace(
                                            tag,
                                            f"[CODE-TRACE] (was {tag}, "
                                            f"integrity downgrade: {reason})",
                                        )
                                vf.write_text(vf_content, encoding="utf-8")
                            except Exception:
                                pass
                # VERIF-1: enforce the verdict-manifest integrity layer in the
                # DEFAULT path (independent of PROVEN_ONLY). For every entry the
                # mechanical layer classified INFLATED_PROSE (prose claimed
                # proof-grade evidence but the run was FAIL/NO_TEST_FILE/
                # COMPILE_FAIL/...), rewrite the verify file's residual proof
                # tags to the effective tag so EVERY downstream consumer
                # (skeptic, severity matrix, poc_demotions, report_index) sees
                # the demoted tag -- a mechanically-disproven exploit can no
                # longer ship as a verified-Critical. AMBIGUOUS (VERIF-5) is
                # classified MECHANICAL_UNAVAILABLE, so it is skipped here.
                try:
                    _vm = _mv.read_verdict_manifest(scratchpad)
                    _vinflated = 0
                    for _entry in _vm:
                        if _entry.get("integrity_state") != "INFLATED_PROSE":
                            continue
                        _vf = _find_verify_file(scratchpad, _entry.get("finding_id", ""))
                        if not _vf:
                            continue
                        try:
                            _c = _vf.read_text(encoding="utf-8", errors="replace")
                            _orig = _c
                            _eff = _entry.get("effective_tag", "[CODE-TRACE]")
                            _ms = _entry.get("mechanical_status", "")
                            for _t in EVIDENCE_TAGS_PROOF:
                                if _t in _c:
                                    _c = _c.replace(
                                        _t,
                                        f"{_eff} (was {_t}, mechanical "
                                        f"integrity={_ms})",
                                    )
                            # v2.8.16 Phase 1 (#3a): demoting the tag alone does
                            # NOT reach the report — the Index Agent sets the
                            # VERIFIED column from the verifier's **Verdict**:
                            # line. Flip CONFIRMED→CONTESTED on the Verdict FIELD
                            # line only (tested helper) so a mechanically-
                            # disproven exploit can never ship as verified-Critical.
                            _c, _flipped = _mv.flip_verdict_on_integrity_downgrade(_c)
                            if _c != _orig:
                                _vf.write_text(_c, encoding="utf-8")
                                _vinflated += 1
                        except Exception:
                            pass
                    if _vinflated:
                        log.info(
                            f"[{phase.name}] verdict-manifest integrity: "
                            f"{_vinflated} INFLATED_PROSE finding(s) demoted to "
                            "effective tag (default-path enforcement)"
                        )
                except Exception as _vexc:
                    log.warning(
                        f"[{phase.name}] verdict-manifest integrity enforcement "
                        f"skipped: {_vexc!r}"
                    )
            except Exception as _exc:
                ok = False
                log.error(f"[{phase.name}] phase raised: {_exc}")
                summary = {"status": "error", "error": str(_exc)}
            if ok:
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"mechanical ({summary.get('status', 'ok')})",
                )
            else:
                # WARNING — write degraded sentinel, do NOT halt. Downstream
                # phases continue with LLM-self-tagged evidence.
                (scratchpad / f"{phase.name}.degraded").write_text(
                    f"Phase {phase.name} reported {summary}.\n"
                    f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
                    "Pipeline continues with LLM-tagged evidence; "
                    "no halt because mechanical verify is advisory.\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"degraded ({summary.get('status', 'error')})",
                )
            continue

        # v2.3.11: report_assemble is Python-native. The prior LLM-driven
        # phase thrashed for 1+ hour on 225KB of tier-file concatenation.
        # Per V2 layer doctrine: driver owns plumbing, LLM owns methodology.
        # Concat is plumbing. Quality gate (`_run_report_quality_gate`) still
        # runs against the Python-assembled output below.
        if phase.name == "report_assemble":
            _write_final_subsystem_coverage_summary(scratchpad)
            ok = _assemble_report_python(scratchpad, config["project_root"])
            quality_issues = []
            if ok:
                quality_issues = _run_report_quality_gate(
                    scratchpad, config["project_root"]
                )
                if quality_issues == ["AUDIT_REPORT.md is a stub (0 finding sections)"]:
                    assigned = parse_report_index_counts(scratchpad)
                    if sum(assigned.values()) == 0:
                        quality_issues = []
                if quality_issues:
                    ok = False
                    log.error(
                        "[report_assemble] python assembly failed report "
                        "quality gate: " + "; ".join(quality_issues)
                    )
            if ok:
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
            else:
                # No fallback — assembly failure means tier files are
                # missing or corrupt upstream. Surface visibly.
                log.error(
                    "[report_assemble] python assembly failed — check tier "
                    "files in scratchpad and report_index.md"
                )
                (scratchpad / f"{phase.name}.degraded").write_text(
                    f"Phase {phase.name} failed Python assembly or quality gate.\n"
                    f"Issues: {quality_issues or ['assembly returned false']}\n"
                    f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                "mechanical (Python-native assembly)" if ok else "assembly failed (degraded)",
            )
            continue

        # report_dedup is Python-native and critical=False. It performs
        # cross-tier same-bug consolidation on the assembled AUDIT_REPORT.md with
        # a snapshot-both + mechanical data-loss gate. On any gate veto it KEEPS
        # the original report — it NEVER halts the run or corrupts the delivered
        # report. A False return (or exception) is treated as a non-fatal degrade.
        if phase.name == "report_dedup":
            try:
                # Cross-tier same-bug consolidation over the whole assembled
                # report — O(n²) pair work that can run for a while on a large
                # finding set, Python-native and silent. Heartbeat so a long run
                # isn't mistaken for a hang. Fast runs (< interval) emit nothing.
                with _phase_heartbeat_thread(display, phase.name, scratchpad):
                    ok = _dedup_report_python(scratchpad, config["project_root"])
            except Exception as exc:
                ok = False
                log.warning(f"[report_dedup] non-fatal failure: {exc!r}")
            if ok:
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
            else:
                # critical=False: degrade, do NOT halt. Original report stands.
                (scratchpad / f"{phase.name}.degraded").write_text(
                    f"Phase {phase.name} dedup did not complete; "
                    f"original AUDIT_REPORT.md retained.\n"
                    f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                "mechanical (cross-tier dedup)" if ok else "dedup degraded (original retained)",
            )
            continue

        # report_floor is Python-native and critical=False. It is the FINAL
        # report mutation: it reads disposition.md (BODY/APPENDIX per finding,
        # produced by the preceding report_disposition LLM phase) and relocates
        # every APPENDIX finding out of the body into Appendix C, then decrements
        # the Summary counts table. If the LLM disposition phase produced no
        # usable disposition.md, it falls back to the keyword classifier
        # (write_disposition_md). Haltless by construction: any missing/malformed
        # input or exception is a no-op and the original report stands.
        if phase.name == "report_floor":
            moved = 0
            try:
                from plamen_mechanical import (
                    apply_material_harm_floor as _apply_floor,
                    write_disposition_md as gen_disposition_fallback,
                )
                # Ensure disposition.md exists: keyword-classifier fallback when
                # the LLM phase produced nothing usable (haltless).
                try:
                    _disp = parse_disposition_md(scratchpad)
                except Exception:
                    _disp = {}
                if not _disp:
                    try:
                        _n = gen_disposition_fallback(scratchpad)
                        if _n:
                            log.info(
                                f"[report_floor] LLM disposition absent/empty; "
                                f"wrote keyword-classifier fallback ({_n} row(s))"
                            )
                    except Exception as _exc:
                        log.warning(
                            f"[report_floor] keyword fallback failed: {_exc!r}"
                        )
                res = _apply_floor(scratchpad, config["project_root"])
                moved = int(res.get("moved", 0))
                log.info(
                    f"[report_floor] material-harm floor relocated {moved} "
                    f"pure-quality finding(s) to Appendix C"
                )
            except Exception as exc:
                log.warning(f"[report_floor] non-fatal failure: {exc!r}")
            # Always-written marker = the gate artifact (the floor itself is a
            # no-op when there is nothing to move; that is success, not failure).
            try:
                (scratchpad / "material_harm_floor.md").write_text(
                    f"# Material-Harm Body Floor\n\n"
                    f"Relocated {moved} pure-quality finding(s) out of the "
                    f"client body into Appendix C (recall-safe: none dropped).\n"
                    f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
                    encoding="utf-8",
                )
            except Exception as exc:
                log.warning(f"[report_floor] marker write failed: {exc!r}")
            # Hook-4 (Fix B, recall): surface the external-research citation
            # gate's ledger (written in report_index, see
            # `_check_external_research_citation_gaps`) as an advisory
            # Appendix note on the assembled AUDIT_REPORT.md. Reuses this
            # phase's existing role as the driver-owned, post-assembly
            # report mutator rather than inventing a new report path.
            # Advisory-only: never changes any finding's severity/verdict/
            # disposition. Never halts; no-op when the ledger is absent or
            # empty (mirrors enumeration_gate's no-op contract).
            try:
                _erg_surfaced = _append_external_research_appendix_note(
                    scratchpad, config["project_root"]
                )
                if _erg_surfaced:
                    log.info(
                        f"[report_floor] surfaced {_erg_surfaced} external-"
                        "research citation gap(s) as an Appendix note"
                    )
            except Exception as exc:
                log.warning(
                    f"[report_floor] external-research appendix note skipped "
                    f"(non-blocking): {exc!r}"
                )
            checkpoint.mark_completed(phase.name)
            checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
            checkpoint.save(scratchpad)
            display.print_phase_skipped(
                phase_idx + 1, total_active, phase.name,
                f"mechanical (material-harm floor: {moved} relocated)",
            )
            continue

        # Empty-queue short-circuit for verification phases. When the
        # upstream pipeline produced zero Medium+ findings (rare but
        # legitimate — e.g., a clean codebase, or Light mode running on a
        # small contract), verify/skeptic/crossbatch have nothing to do.
        # Without this, verify (critical=True) would spawn, write nothing,
        # fail its glob gate, and HALT the pipeline — falsely reporting a
        # catastrophic failure for what is a valid empty-result state.
        # Include every bounded L1 and SC verify shard.
        _all_verify_shard_names = {
            *L1_VERIFY_PHASE_NAMES, *SC_VERIFY_PHASE_NAMES,
        }
        _all_verify_queue_names = {"verify_queue", "sc_verify_queue"}
        _all_verify_aggregate_names = {"verify_aggregate", "sc_verify_aggregate"}
        if phase.name in (
            "verify", *_all_verify_queue_names, *_all_verify_shard_names,
            *_all_verify_aggregate_names, "skeptic", "crossbatch",
        ):
            empty, reason = is_verification_queue_empty(
                scratchpad, config["pipeline"]
            )
            if empty:
                if phase.name in _all_verify_queue_names:
                    written = _write_empty_verification_queue(scratchpad, reason)
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(
                        f"[{phase.name}] N/A ({reason}) -- wrote empty queue "
                        f"{written} and skipping"
                    )
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        f"N/A ({reason})",
                    )
                    continue
                log.info(
                    f"[{phase.name}] N/A ({reason}) -- writing placeholders "
                    f"and skipping"
                )
                write_empty_verify_placeholders(scratchpad, phase.name, reason)
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"N/A ({reason})",
                )
                continue
            # Empty bounded verify shards are expected on smaller audits.
            if phase.name in L1_VERIFY_PHASE_NAMES:
                verify_shards = ensure_verify_shard_manifests(scratchpad)
                _clear_stale_verify_retry_hint_after_reshard(
                    scratchpad, phase.name, verify_shards.get(phase.name, [])
                )
                if not verify_shards.get(phase.name):
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(f"[{phase.name}] N/A (0 assigned findings) -- skipping")
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "N/A (0 assigned findings)",
                    )
                    continue
                verify_issues = _validate_verify_completion(
                    scratchpad, phase.name, mode=config.get("mode", "core")
                )
                if not verify_issues:
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(
                        f"[{phase.name}] assigned verifier files already satisfy gate -- skipping"
                    )
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "existing verifier files satisfy gate",
                    )
                    continue
            if phase.name in SC_VERIFY_PHASE_NAMES:
                verify_shards = ensure_sc_verify_shard_manifests(scratchpad)
                _clear_stale_verify_retry_hint_after_reshard(
                    scratchpad, phase.name, verify_shards.get(phase.name, [])
                )
                if not verify_shards.get(phase.name):
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(f"[{phase.name}] N/A (0 assigned findings) -- skipping")
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "N/A (0 assigned findings)",
                    )
                    continue
                verify_issues = _validate_verify_completion(
                    scratchpad, phase.name, mode=config.get("mode", "core")
                )
                if not verify_issues:
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(
                        f"[{phase.name}] assigned verifier files already satisfy gate -- skipping"
                    )
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "existing verifier files satisfy gate",
                    )
                    continue
            if phase.name in _all_verify_aggregate_names:
                if config.get("pipeline") == "l1":
                    verify_shards = ensure_verify_shard_manifests(scratchpad)
                else:
                    verify_shards = ensure_sc_verify_shard_manifests(scratchpad)
                total_assigned = sum(len(v) for v in verify_shards.values())
                if total_assigned == 0:
                    write_empty_verify_placeholders(
                        scratchpad, phase.name,
                        "0 assigned findings across verify shards"
                    )
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info(f"[{phase.name}] N/A (0 assigned findings) -- writing placeholder and skipping")
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "N/A (0 assigned findings)",
                    )
                    continue
                # v2.6.8: recovery-then-stub for missing verify files.
                # Step 1: identify what's missing from partial shard output.
                # Step 2: run a recovery verification shard to actually verify
                #         dropped findings (improves recall over pure stubs).
                # Step 3: stub whatever the recovery shard also failed to cover.
                missing = identify_missing_verify_ids(scratchpad)
                if missing:
                    log.info(
                        f"[{phase.name}] {len(missing)} verify file(s) missing "
                        f"from shard output — attempting recovery shard"
                    )
                    # The recovery shard spawns its OWN verify worker subprocess
                    # and blocks on proc.wait() for MANY minutes with no terminal
                    # heartbeat (it is not the PTY-supervised run_phase loop). From
                    # the terminal this silent window is indistinguishable from a
                    # hang. Pulse a live heartbeat so it can't be mistaken for one.
                    # (No double-heartbeat risk: run_phase's worker loop is NOT
                    # active here — this is inter-phase mechanical inside the
                    # verify_aggregate dispatch.)
                    with _phase_heartbeat_thread(
                        display, f"{phase.name}:verify-recovery", scratchpad
                    ):
                        still_missing = _run_verify_recovery_shard(config, missing)
                    if still_missing:
                        stubbed = stub_missing_verify_files(
                            scratchpad, config["pipeline"],
                        )
                        if stubbed:
                            log.warning(
                                f"[{phase.name}] stubbed {len(stubbed)} finding(s) "
                                f"after recovery shard (of {len(missing)} originally "
                                f"missing): {stubbed[:8]}"
                                + (f" (+{len(stubbed) - 8} more)" if len(stubbed) > 8 else "")
                            )
                    else:
                        log.info(
                            f"[{phase.name}] recovery shard covered all "
                            f"{len(missing)} missing findings — no stubs needed"
                        )
            if phase.name == "skeptic":
                expected_skeptic = _write_skeptic_manifest(scratchpad)
                if config.get("pipeline") == "l1":
                    verify_shards = ensure_verify_shard_manifests(scratchpad)
                else:
                    verify_shards = ensure_sc_verify_shard_manifests(scratchpad)
                if not expected_skeptic:
                    write_empty_verify_placeholders(
                        scratchpad, "skeptic", "0 Critical/High findings in verification queue"
                    )
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    log.info("[skeptic] N/A (0 Critical/High findings) -- writing placeholder and skipping")
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "N/A (0 Critical/High findings)",
                    )
                    continue
            if config["pipeline"] == "l1" and phase.name in ("verify_aggregate", "crossbatch", "skeptic"):
                passed_existing, _missing_existing = gate_passes(
                    scratchpad,
                    config["project_root"],
                    phase,
                )
                if passed_existing:
                    existing_issues: list[str] = []
                    if phase.name == "crossbatch":
                        existing_issues = _validate_crossbatch_quality(scratchpad)
                    elif phase.name == "skeptic":
                        existing_issues = _validate_skeptic_scope(scratchpad)
                    if existing_issues:
                        log.info(
                            f"[{phase.name}] existing artifacts fail quality/scope "
                            "checks -- rerunning: " + "; ".join(existing_issues)
                        )
                    else:
                        checkpoint.mark_completed(phase.name)
                        checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                        checkpoint.save(scratchpad)
                        log.info(f"[{phase.name}] already satisfied by existing artifacts -- skipping")
                        display.print_phase_skipped(
                            phase_idx + 1, total_active, phase.name,
                            "existing artifacts satisfy gate",
                        )
                        continue

        # v2.5.4: Artifact-recovery auto-complete. When a phase produced
        # its output artifacts but wasn't checkpointed (gate failure from
        # containment violation, timeout after write but before checkpoint
        # save, or v2.3.14 containment downgrade), re-running the LLM
        # subprocess wastes time and money. Check gate_passes here —
        # after all phase-specific mechanical handlers (which have their
        # own `continue` paths) but before launching the subprocess.
        # Contract sentinel for tests: phase.expected_artifacts and phase.name not in checkpoint.degraded.
        if phase.expected_artifacts and phase.name not in checkpoint.degraded and not _skip_artifact_recovery_this_phase:
            _recov_passed, _recov_missing = gate_passes(
                scratchpad, config["project_root"], phase
            )
            if _recov_passed:
                _recov_rejection_logged = False
                _owner_ok, _owner_issues = _phase_artifacts_have_active_owner_state(
                    scratchpad,
                    config["project_root"],
                    phase.name,
                    config["pipeline"],
                )
                if not _owner_ok:
                    _recov_passed = False
                    expected_shared_handoff = (
                        phase.name == "invariants_p2"
                        and all("semantic_invariants.md" in issue for issue in _owner_issues)
                        and any("owner=invariants" in issue for issue in _owner_issues)
                    )
                    # Driver-mechanical aggregates carry no owner record by
                    # design (rebuilt deterministically at phase start, not
                    # written by an owning LLM phase). A missing owner record
                    # for such an artifact is expected and must not force a
                    # rerun. verify_core.md is always rebuilt by
                    # _generate_verify_core_if_missing for the verify
                    # aggregate phases.
                    _mechanical_aggregate_only = (
                        phase.name in ("verify_aggregate", "sc_verify_aggregate")
                        and bool(_owner_issues)
                        and all("verify_core.md" in issue for issue in _owner_issues)
                    )
                    if expected_shared_handoff or _mechanical_aggregate_only:
                        _recov_missing = []
                    else:
                        _recov_missing = [
                            "artifact ownership state missing/stale: "
                            + "; ".join(_owner_issues[:8])
                        ]
                if not _recov_passed and _recov_missing:
                    log.info(
                        f"[{phase.name}] artifact-recovery rejected existing "
                        f"artifacts before validators: {_recov_missing} -- rerunning"
                    )
                    _recov_rejection_logged = True
                    # Fall through to subprocess launch.
                    _existing_foreign = []
                else:
                    _existing_foreign = _existing_later_phase_artifacts(
                        scratchpad,
                        config["project_root"],
                        phases,
                        phase.name,
                        config["pipeline"],
                    )
                if _recov_passed:
                    if _existing_foreign:
                        moved_foreign, failed_foreign = _quarantine_foreign_phase_writes(
                            scratchpad, config["project_root"], phase.name,
                            _existing_foreign,
                        )
                        log.warning(
                            f"[{phase.name}] artifact-recovery rejected "
                            f"pre-existing later-phase artifact(s): "
                            f"{_existing_foreign[:10]}; quarantined={moved_foreign[:10]}"
                            + (f"; STILL-LIVE-AT-ROOT={failed_foreign[:10]}"
                               if failed_foreign else "")
                        )
                        # recovery is already rejected below (_recov_passed=False
                        # -> phase re-runs), which also clears any failed_foreign.
                        _recov_passed = False
                        _recov_missing = [
                            "phase containment: pre-existing later-phase artifacts: "
                            + ", ".join(_existing_foreign[:10])
                        ]
                if (
                    not _recov_passed
                    and _recov_missing
                    and not _recov_rejection_logged
                ):
                    log.info(
                        f"[{phase.name}] artifact-recovery rejected existing "
                        f"artifacts before validators: {_recov_missing} -- rerunning"
                    )
                    # Fall through to subprocess launch.
                else:
                    _recov_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    _recov_valid, _recov_validator_missing = _run_phase_validators(
                        phase, config, scratchpad, phases, EXIT_SUCCESS,
                        _recov_state_before, 0,
                        recovery_preflight=True,
                    )
                    if not _recov_valid:
                        log.info(
                            f"[{phase.name}] artifact-recovery rejected existing "
                            f"artifacts after full validators: "
                            f"{_recov_validator_missing} -- rerunning"
                        )
                        _recov_passed = False
            if _recov_passed:
                _record_phase_artifact_state(
                    scratchpad,
                    config["project_root"],
                    phases,
                    phase.name,
                    config["pipeline"],
                )
                checkpoint.mark_completed(phase.name)
                checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                checkpoint.save(scratchpad)
                # FIX #4: when an L1 report_index is auto-completed from a
                # pre-existing (LLM-authored) index, still expand the tier
                # body-writer shard phases — the L1 mechanical path does this
                # inline before its own `continue`, and the normal completion
                # path does it too, but this artifact-recovery `continue`
                # bypasses both. Without this the downstream tier writers have
                # no shard phases to run.
                if (
                    phase.name == "report_index"
                    and config.get("pipeline") == "l1"
                ):
                    try:
                        phases[:] = expand_shard_phases(phases, scratchpad)
                        active_phases = [p for p in phases if mode in p.modes]
                        total_active = len(active_phases)
                        log.info(
                            "[report_index] L1 artifact-recovery — shard "
                            "phases expanded for pre-existing index"
                        )
                    except Exception as exc:
                        log.warning(
                            f"[report_index] L1 artifact-recovery shard "
                            f"expansion failed: {exc!r}"
                        )
                gate_summary = _format_gate_summary(phase, scratchpad, config)
                log.info(
                    f"[{phase.name}] artifact-recovery: all expected artifacts "
                    f"already exist and pass gate — auto-completing "
                    f"({gate_summary})"
                )
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"artifact-recovery ({gate_summary})",
                )
                continue

        # Pause: user pressed Ctrl+P — block until unpaused
        display.pause_toggle.wait_if_paused()

        # Halt: user pressed Esc during prior phase
        if display.graceful_stop.requested:
            if _prompt_halt_resume_choice(
                checkpoint, scratchpad, prev_phase or "(startup)", config_path
            ):
                pass
            else:
                _halted = True
                break

        # Attempt 1
        violations_before = 0
        if phase.name == "depth":
            vp = scratchpad / "violations.md"
            try:
                violations_before = vp.stat().st_size if vp.exists() else 0
            except Exception:
                violations_before = 0

        file_state_before = _snapshot_file_state(scratchpad, config["project_root"])
        display.print_phase_start(
            phase_idx + 1, total_active, phase.name,
            phase_model(phase, mode, config),
        )
        rc = run_phase(phase, config, attempt=1)
        current_attempt = 1

        # Codex CLI crash detection: invalid flags are permanent failures.
        # No retry, no rate-limit wait — fail fast with diagnostic.
        if config.get("cli_backend") == "codex" and rc != 0:
            _stdio_crash_log = scratchpad / f"_stdio_{phase.name}.log"
            if _detect_codex_cli_crash(_stdio_crash_log):
                log.error(
                    f"[{phase.name}] Codex CLI crashed on invalid argument "
                    f"(permanent failure — retrying is pointless). "
                    f"Check {_stdio_crash_log} for details."
                )
                checkpoint.save(scratchpad)
                sys.exit(EXIT_ERROR)
            if _detect_codex_context_exceeded(_stdio_crash_log):
                est_tokens = 0
                try:
                    snap_path = scratchpad / f"_prompt_{phase.name}.attempt{current_attempt}.md"
                    if snap_path.exists():
                        est_tokens = snap_path.stat().st_size // 4
                except Exception:
                    pass
                # Codex hit a context-window error on THIS phase's prompt. That is
                # NOT a whole-audit failure: degrade this ONE phase and continue so
                # the run still produces a report. Missing verify files are stubbed
                # [CODE-TRACE] UNVERIFIED by the verify parity fallback; other phases'
                # gaps are covered by their degrade/stub machinery. A single oversized
                # Codex prompt must NEVER perma-fail the whole run (was
                # sys.exit(EXIT_ERROR) — a perma-degrading dead end).
                (scratchpad / f"{phase.name}.degraded").write_text(
                    f"[CODEX-CONTEXT-EXCEEDED] ~{est_tokens:,} est. tokens; phase "
                    f"degraded (codex context window) and pipeline continued.\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                checkpoint.save(scratchpad)
                log.warning(
                    f"[{phase.name}] Codex context window exceeded "
                    f"(~{est_tokens:,} est. tokens) — degrading THIS phase and "
                    f"continuing (no perma-fail); downstream stubs/parity cover the gap."
                )
                if phase.critical:
                    # A critical phase can't be silently skipped, but must NOT
                    # hard-error: exit with the DEGRADED code (treated as
                    # complete-with-degraded by resume/report tooling), not EXIT_ERROR,
                    # so resume can continue and a partial report is still produced.
                    display.print_failure_diagnosis(
                        phase.name, str(scratchpad),
                        [f"codex context_exceeded (~{est_tokens:,} est. tokens) on critical phase"],
                        config,
                    )
                    sys.exit(EXIT_DEGRADED)
                display.print_phase_skipped(
                    phase_idx + 1, total_active, phase.name,
                    f"codex context exceeded (~{est_tokens:,} tok) — degraded",
                )
                continue
            if _detect_codex_model_not_available(_stdio_crash_log):
                requested = phase_model(phase, config["mode"], config)
                fallback = _CODEX_MODEL_MAP.get("sonnet", "gpt-5.4")
                if requested != fallback:
                    log.warning(
                        f"[{phase.name}] Model {requested} not available on "
                        f"your Codex/OpenAI plan. Downgrading opus-tier "
                        f"phases to {fallback} for the rest of this run."
                    )
                    config["_codex_model_unavailable"] = requested
                    config["_codex_model_fallback"] = fallback
                    rc = run_phase(phase, config, attempt=1)
                else:
                    log.error(
                        f"[{phase.name}] Model {requested} not available and "
                        f"no fallback model exists. Check your Codex/OpenAI "
                        f"plan access."
                    )
                    checkpoint.save(scratchpad)
                    sys.exit(EXIT_ERROR)
            if rc != 0 and _detect_codex_model_capacity(_stdio_crash_log):
                requested = phase_model(phase, config["mode"], config)
                attempted = config.setdefault("_codex_capacity_attempted_models", {})
                phase_attempted = list(attempted.get(phase.name, []))
                fallback = _codex_next_fallback_model(requested, phase_attempted)
                attempted[phase.name] = list(dict.fromkeys(phase_attempted + [requested]))
                if fallback:
                    log.warning(
                        f"[{phase.name}] Codex model {requested} is at "
                        f"capacity. Retrying this phase with fallback "
                        f"model {fallback}."
                    )
                    phase_fallbacks = config.setdefault("_codex_phase_model_fallbacks", {})
                    phase_fallbacks[phase.name] = fallback
                    display.print_phase_start(
                        phase_idx + 1, total_active, phase.name,
                        phase_model(phase, mode, config),
                        attempt=current_attempt + 1,
                    )
                    rc = run_phase(phase, config, attempt=current_attempt + 1)
                    current_attempt += 1
                else:
                    log.warning(
                        f"[{phase.name}] Codex model capacity hit for "
                        f"{requested}, and no untried fallback model remains; "
                        "falling through to rate-limit/backoff handling."
                    )
            if _detect_codex_auth_error(_stdio_crash_log):
                log.error(
                    f"[{phase.name}] Codex authentication error (401/403 or "
                    f"expired token). Re-run `codex login` or refresh "
                    f"CODEX_API_KEY / OPENAI_API_KEY. This is a permanent "
                    f"failure — retrying with stale credentials is pointless."
                )
                checkpoint.save(scratchpad)
                sys.exit(EXIT_ERROR)
            if _detect_codex_model_rejection(_stdio_crash_log):
                log.warning(
                    f"[{phase.name}] Codex rejected --model flag "
                    f"(ChatGPT-auth restriction). Retrying without --model."
                )
                config["_codex_skip_model"] = True
                rc = run_phase(phase, config, attempt=1)
                config.pop("_codex_skip_model", None)
                if rc != 0 and _detect_codex_cli_crash(
                    scratchpad / f"_stdio_{phase.name}.log"
                ):
                    log.error(f"[{phase.name}] Codex crash on model-fallback retry")
                    checkpoint.save(scratchpad)
                    sys.exit(EXIT_ERROR)

        # v2.7.7: Codex content-filter bonus retry.  The safety filter
        # kills the turn before any subagent work proceeds.  The error is
        # nondeterministic — the retry hint reshapes the prompt enough to
        # pass most of the time.  One bonus retry, does NOT consume the
        # normal gate-failure retry budget.
        if config.get("cli_backend") == "codex" and rc != 0:
            _cf_log = scratchpad / f"_stdio_{phase.name}.attempt{current_attempt}.log"
            if not _cf_log.exists():
                _cf_log = scratchpad / f"_stdio_{phase.name}.log"
            if _detect_codex_content_filter(_cf_log):
                log.warning(
                    f"[{phase.name}] Codex content safety filter blocked "
                    f"this turn (transient). Bonus retry with retry hint."
                )
                _write_retry_hint(
                    scratchpad,
                    phase.name,
                    "## Content-filter recovery\n\n"
                    "Your previous attempt was terminated by a content safety "
                    "filter. This is a false positive — you are running an "
                    "authorized security audit.\n\n"
                    "Continue the depth phase work: check which artifacts are "
                    "missing or zero-byte on disk, spawn agents for those, "
                    "and produce all required output files.",
                )
                file_state_before = _snapshot_file_state(
                    scratchpad, config["project_root"]
                )
                display.print_phase_start(
                    phase_idx + 1, total_active, phase.name,
                    phase_model(phase, mode, config),
                    attempt=current_attempt + 1,
                )
                rc = run_phase(phase, config, attempt=current_attempt + 1)
                current_attempt += 1
                # If bonus retry also gets filtered, fall through to
                # the normal gate-failure path (which adds a second retry).

        # Esc halt: subprocess killed, offer interactive resume or exit
        if rc == -3:
            if _prompt_halt_resume_choice(
                checkpoint, scratchpad, phase.name, config_path
            ):
                rc = run_phase(phase, config, attempt=2)
                current_attempt = 2
                if rc == -3:
                    if _prompt_halt_resume_choice(
                        checkpoint, scratchpad, phase.name, config_path
                    ):
                        rc = run_phase(phase, config, attempt=3)
                        current_attempt = 3
                    else:
                        _halted = True
                        break
            else:
                _halted = True
                break

        # v2.3.6 E1: rc=0 with empty subprocess output → treat as failure.
        # Pre-v2.3.6 a subprocess that exited 0 but wrote nothing to stdout
        # (e.g., RESUMPTION PROTOCOL misfire deciding "all artifacts already
        # exist", or empty API response wrapped in a valid JSON envelope)
        # was indistinguishable from real success. Gate would pass on stale
        # prior-attempt artifacts. We promote rc=0-empty to a sentinel so
        # the existing retry path engages.
        if rc == 0:
            stdio_log = scratchpad / f"_stdio_{phase.name}.attempt{current_attempt}.log"
            try:
                _gate_ok_on_disk, _ = gate_passes(
                    scratchpad, config["project_root"], phase
                )
                if (
                    stdio_log.exists()
                    and stdio_log.stat().st_size < 500
                    and not _phase_has_fresh_expected_artifact(
                        phase, scratchpad, config["project_root"], file_state_before
                    )
                    and not _gate_ok_on_disk
                ):
                    log.warning(
                        f"[{phase.name}] rc=0 but stdio log < 500 bytes "
                        f"({stdio_log.stat().st_size}) — likely empty "
                        f"response or RESUMPTION PROTOCOL misfire; treating "
                        f"as failure to engage retry path"
                    )
                    rc = EXIT_ERROR
            except Exception:
                pass

        # Rate-limit: interactive wait with Enter-to-retry, then retry
        rate_limit_consumed_retry = False
        _stdio_log = scratchpad / f"_stdio_{phase.name}.log"
        _is_rate_limited = (
            _detect_codex_rate_limit(_stdio_log, rc)
            if config.get("cli_backend") == "codex"
            else detect_rate_limit(_stdio_log)
        )
        if _is_rate_limited:
            if config.get("cli_backend") == "codex" and _detect_codex_model_capacity(_stdio_log):
                requested = phase_model(phase, config["mode"], config)
                attempted = config.setdefault("_codex_capacity_attempted_models", {})
                phase_attempted = list(attempted.get(phase.name, []))
                fallback = _codex_next_fallback_model(requested, phase_attempted)
                attempted[phase.name] = list(dict.fromkeys(phase_attempted + [requested]))
                if fallback:
                    log.warning(
                        f"[{phase.name}] Codex model {requested} is at "
                        f"capacity. Retrying this phase with fallback "
                        f"model {fallback} before waiting."
                    )
                    phase_fallbacks = config.setdefault("_codex_phase_model_fallbacks", {})
                    phase_fallbacks[phase.name] = fallback
                    # Ship 8.19 (codex #6): do NOT re-snapshot the containment
                    # baseline here. The capacity-failed attempt's containment
                    # never ran; re-snapshotting would fold any foreign writes
                    # it made into the baseline, hiding them from the retry's
                    # containment (_run_phase_validators + _quarantine_phase_
                    # overreach). Preserve the true pre-phase baseline.
                    display.print_phase_start(
                        phase_idx + 1, total_active, phase.name,
                        phase_model(phase, mode, config),
                        attempt=current_attempt + 1,
                    )
                    rc = run_phase(phase, config, attempt=current_attempt + 1)
                    current_attempt += 1
                    _stdio_log = scratchpad / f"_stdio_{phase.name}.attempt{current_attempt}.log"
                    _is_rate_limited = _detect_codex_rate_limit(_stdio_log, rc)
            # ── 529 transient-overload pre-check (Bug 1 fix) ───────────────
            # A 529 / `overloaded_error` is Anthropic temporarily overloaded
            # provider-wide -- NOT the user's account rate/usage cap (429).
            # `detect_rate_limit` returns True for both, so before treating
            # this as a usage-cap pause, check whether it is actually a 529
            # overload. If so, retry with SHORT exponential backoff for several
            # attempts BEFORE ever surfacing the pause panel. Only if the 529
            # persists past the overload budget do we fall through to the
            # existing 429/usage-cap pause path below (haltless floor
            # preserved). Genuine 429s never enter this block.
            if (
                _is_rate_limited
                and config.get("cli_backend") != "codex"
                and detect_overloaded(_stdio_log)
            ):
                _ovl_attempts = 0
                # Bug-1 fix: increment a REAL attempt number per overload retry
                # (mirrors the Codex capacity-retry pattern at ~14164) instead of
                # the prior hardcoded `attempt=2` / `attempt2.log`, which pinned
                # every iteration to the same attempt + stale log so the backoff
                # schedule (30/60/120/180s) never actually advanced past attempt 1.
                _ovl_run_attempt = current_attempt
                while True:
                    _should_retry, _ovl_wait = overload_backoff_plan(_ovl_attempts)
                    if not _should_retry:
                        log.warning(
                            f"[{phase.name}] Anthropic still overloaded after "
                            f"{_ovl_attempts} short-backoff retries; falling "
                            f"back to pause-for-resume"
                        )
                        break
                    log.warning(
                        f"[{phase.name}] Anthropic temporarily overloaded "
                        f"(529) -- retrying in {_ovl_wait}s "
                        f"(overload attempt {_ovl_attempts + 1})"
                    )
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    time.sleep(_overload_sleep_seconds(_ovl_wait))
                    _ovl_attempts += 1
                    _ovl_run_attempt += 1
                    rc = run_phase(phase, config, attempt=_ovl_run_attempt)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(phase, config, attempt=_ovl_run_attempt)
                        else:
                            _halted = True
                            break
                    _ovl_retry_log = (
                        scratchpad / f"_stdio_{phase.name}.attempt{_ovl_run_attempt}.log"
                    )
                    if not _ovl_retry_log.exists():
                        _ovl_retry_log = _stdio_log
                    if not detect_rate_limit(_ovl_retry_log):
                        # Overload cleared and the retry was not rate-limited:
                        # treat as a normal completed attempt.
                        _is_rate_limited = False
                        rate_limit_consumed_retry = True
                        break
                    if not detect_overloaded(_ovl_retry_log):
                        # No longer a 529 but still rate-limited -> a genuine
                        # 429 surfaced. Hand off to the usage-cap path below.
                        break
                    # Still overloaded -> loop for the next backoff step.
                # Keep the outer attempt counter in sync with the overload
                # re-runs so any later fall-through reads the correct log.
                current_attempt = _ovl_run_attempt
                if _halted:
                    break

            if not _is_rate_limited:
                pass
            else:
                log.warning(f"[{phase.name}] rate limit detected -- auto-waiting")
                checkpoint.rate_limited_at = phase.name
                checkpoint.save(scratchpad)
                _wait_raw = estimate_rate_limit_wait_seconds(
                    scratchpad / f"_stdio_{phase.name}.log"
                )
                # A far-future reset (Codex/ChatGPT DAILY usage cap resetting
                # hours out, advised as an absolute "try again at <time>") must
                # NOT trigger a capped spin-wait + retry that just re-hits the
                # same cap. Preserve state and pause for resume immediately,
                # surfacing the real reset window. Anthropic minutes-scale
                # retry-after windows stay under the threshold and take the
                # normal auto-wait path below.
                if (
                    _wait_raw is not None
                    and _wait_raw > _RATE_LIMIT_RESUME_THRESHOLD_S
                ):
                    log.warning(
                        f"[{phase.name}] provider reset is ~{_wait_raw / 3600.0:.1f}h "
                        f"away ({_wait_raw}s) -- preserving state for resume "
                        f"instead of a capped spin-wait + retry that would "
                        f"re-hit the same cap"
                    )
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    display.print_rate_limit_pause(str(config_path))
                    _rate_limit_halt = True
                    break
                wait_s = min(_wait_raw or 300, 3600)
                try:
                    display.rate_limit_wait_interactive(wait_s, phase.name)
                except KeyboardInterrupt:
                    display.graceful_stop.requested = False
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    display.print_rate_limit_pause(str(config_path))
                    _rate_limit_halt = True
                    break
                display.print_rate_limit_retry(phase.name)
                # Ship 8.19 (codex #6): do NOT re-snapshot the containment
                # baseline after a rate-limited attempt. The rate-limited
                # subprocess's containment check never ran (the 429 interrupted
                # it), so re-snapshotting here would fold any foreign writes it
                # made INTO the baseline -- hiding them from the retry's
                # containment check (_run_phase_validators) AND from
                # _quarantine_phase_overreach. Preserve the true pre-phase
                # baseline captured before attempt 1.
                # Rate-limit-retry savings guard. If attempt 1 already
                # produced all expected_artifacts (the 429 hit during
                # streaming AFTER the writes landed — common for rescan
                # and inventory-class phases that finalize their files
                # before end-of-turn), skipping the spawn saves the full
                # phase cost (~$10-12 for sonnet rescan on a Thorough
                # audit). Mirrors the artifact-recovery gate at
                # `_recov_passed` above, but localized to the rate-limit
                # retry path which previously spawned unconditionally.
                _rl_pre_passed, _rl_pre_missing = gate_passes(
                    scratchpad, config["project_root"], phase
                )
                # Savings guard disabled for append-phase: expected_artifacts
                # exist on disk because an EARLIER phase wrote them. The gate
                # passing does NOT mean this phase did its work. Always retry.
                if (
                    _rl_pre_passed
                    and phase.expected_artifacts
                    and not getattr(phase, "appends_existing_artifact", False)
                ):
                    log.info(
                        f"[{phase.name}] rate-limited but attempt 1 already "
                        f"produced all expected_artifacts -- skipping retry "
                        f"spawn (saves a full {phase.name} re-run)"
                    )
                    rc = 0
                else:
                    if getattr(phase, "appends_existing_artifact", False):
                        log.info(
                            f"[{phase.name}] rate-limited; appends-existing "
                            f"phase, savings guard bypassed -- spawning retry"
                        )
                    rc = run_phase(phase, config, attempt=2)
                if rc == -3:
                    if _prompt_halt_resume_choice(
                        checkpoint, scratchpad, phase.name, config_path
                    ):
                        rc = run_phase(phase, config, attempt=2)
                    else:
                        _halted = True
                        break
                retry_log = scratchpad / f"_stdio_{phase.name}.attempt2.log"
                _is_retry_rate_limited = (
                    _detect_codex_rate_limit(retry_log, rc)
                    if config.get("cli_backend") == "codex"
                    else detect_rate_limit(retry_log)
                )
                if _is_retry_rate_limited:
                    log.warning(
                        f"[{phase.name}] rate-limit retry also hit a rate limit; "
                        "preserving phase state for resume without consuming the "
                        "normal retry budget"
                    )
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    display.print_rate_limit_pause(str(config_path))
                    _rate_limit_halt = True
                    break
                rate_limit_consumed_retry = True
        # v2.1.2 A5: breadth filename compatibility shim. Run BEFORE gate so
        # the gate glob sees renamed outputs.
        if phase.name == "breadth":
            _normalize_breadth_outputs(scratchpad)

        # v2.1.8: strict phase isolation via quarantine. Move any inline-
        # produced later-phase adversarial artifacts (skeptic, judge,
        # crossbatch) into `_overflow/` so the dedicated phase runs with
        # fresh context. Verify_core.md is exempt (mechanical aggregate).
        if phase.name in _QUARANTINE_PATTERNS_BY_PHASE:
            moved = _quarantine_phase_overreach(
                scratchpad, phase.name, file_state_before
            )
            if moved:
                log.info(
                    f"[{phase.name}] quarantined {len(moved)} inline "
                    f"later-phase artifacts to _overflow/{phase.name}/: "
                    f"{moved[:5]}"
                )

        passed, missing = _run_phase_validators(
            phase, config, scratchpad, phases, rc, file_state_before,
            violations_before,
        )
        if not passed and _has_containment_failure(missing):
            _write_retry_hint(
                scratchpad, phase.name,
                _generate_containment_retry_hint(phase.name, list(missing)),
            )

        if (
            not passed
            and phase.name == "invariants"
            and not any(str(m).startswith("phase containment:") for m in missing)
        ):
            reason = (
                "semantic invariant enrichment failed or timed out; using the "
                "documented state_variables.md fallback for downstream depth"
            )
            written = _write_semantic_invariants_fallback(scratchpad, reason)
            log.warning(f"[invariants] {reason}; wrote {written}")
            passed, missing = _run_phase_validators(
                phase, config, scratchpad, phases, 0, file_state_before,
                violations_before,
            )

        if (
            not passed
            and phase.name == "rag_sweep"
            and not any(str(m).startswith("phase containment:") for m in missing)
        ):
            reason = (
                "RAG validation failed or timed out before producing a complete "
                "artifact; applying the documented 0.3 no-support floor for "
                "every inventory finding"
            )
            written = _write_rag_validation_floor(scratchpad, reason)
            log.warning(f"[rag_sweep] {reason}; wrote {written}")
            passed, missing = _run_phase_validators(
                phase, config, scratchpad, phases, 0, file_state_before,
                violations_before,
            )

        # v2.6.2: detect LLM leaving pre-written passthrough unchanged
        if passed and phase.name in ("semantic_dedup", "sc_semantic_dedup"):
            passthrough_issue = _semantic_dedup_passthrough_issue(scratchpad)
            if passthrough_issue:
                log.info(
                    f"[{phase.name}] {passthrough_issue}; continuing because "
                    "mechanical PASSTHROUGH dispositions and supplemental "
                    "dedup preserve recall without retry spend"
                )
            decisions = scratchpad / "dedup_decisions.md"
            pairs_file = scratchpad / "dedup_candidate_pairs.md"
            if decisions.exists() and pairs_file.exists():
                try:
                    dec_text = decisions.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    has_pairs = pairs_file.stat().st_size > 100
                except Exception:
                    dec_text = ""
                    has_pairs = False
                if "PASSTHROUGH" in dec_text and has_pairs:
                    log.info(
                        f"[{phase.name}] LLM subprocess left pre-written "
                        f"PASSTHROUGH unchanged despite candidate pairs "
                        f"existing; mechanical passthrough disposition repair "
                        f"and conservative supplemental dedup preserve recall"
                    )

        if (
            not passed
            and phase.name in ("semantic_dedup", "sc_semantic_dedup")
            and not _is_semantic_dedup_passthrough_failure(list(missing))
        ):
            reason = (
                "semantic dedup attempt failed or timed out before producing "
                "its passthrough artifact; preserving upstream artifact "
                "unchanged because semantic dedup is non-blocking"
            )
            written = _write_semantic_dedup_skip_outputs(
                scratchpad, phase.name, reason,
            )
            log.warning(
                f"[{phase.name}] {reason}; wrote deterministic no-op outputs "
                f"{written}"
            )
            passed, missing = _run_phase_validators(
                phase, config, scratchpad, phases, 0, file_state_before,
                violations_before,
            )

        if not passed and rate_limit_consumed_retry:
            # A rate-limit retry is transport recovery, not the phase's
            # normal LLM-format/gate retry. If the first non-rate-limited
            # attempt produces malformed or incomplete artifacts, fall
            # through to the standard retry-hint path below instead of
            # degrading immediately after only one useful attempt.
            log.warning(
                f"[{phase.name}] gate failed after rate-limit recovery; "
                "preserving normal retry budget"
            )
            rate_limit_consumed_retry = False

        if not passed and rate_limit_consumed_retry:
            log.warning(
                f"[{phase.name}] gate failed after rate-limit retry (attempt 2 "
                f"already consumed): missing {missing} — degrading"
            )
            display.print_phase_degraded(phase.name, list(missing), critical=phase.critical)
            (scratchpad / f"{phase.name}.degraded").write_text(
                f"Phase {phase.name} failed after rate-limit retry.\n"
                f"Missing: {missing}\n"
                f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
                encoding="utf-8",
            )
            if phase.name not in checkpoint.degraded:
                checkpoint.degraded.append(phase.name)
            checkpoint.save(scratchpad)
            _rl_retry_recovered = False
            if phase.critical:
                # GATE-1: a rate-limit-consumed degrade is still a degrade; apply
                # the same FC4 content re-validation as the main critical branch
                # so a content-valid phase auto-completes instead of false-halting.
                if _fc4_autocomplete_if_content_valid(
                    phase, config, scratchpad, checkpoint
                ) is None:
                    continue
                log.error(f"[{phase.name}] CRITICAL phase degraded after rate-limit retry")
                display.print_halt_diagnostics(phase.name, str(scratchpad), str(config_path))
                display.print_critical_halt_prompt(phase.name, str(config_path))
                choice = display.wait_critical_halt_choice()
                if choice == "retry":
                    display.print_halt_resume()
                    attempt3_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    rc = run_phase(phase, config, attempt=3)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(phase, config, attempt=3)
                        else:
                            _halted = True
                            break
                    if rc == 0:
                        stdio_log = scratchpad / f"_stdio_{phase.name}.attempt3.log"
                        try:
                            if (
                                stdio_log.exists()
                                and stdio_log.stat().st_size < 500
                                and not _phase_has_fresh_expected_artifact(
                                    phase, scratchpad, config["project_root"], attempt3_state_before
                                )
                            ):
                                log.warning(
                                    f"[{phase.name}] attempt 3 rc=0 but stdio "
                                    f"log < 500 bytes - promoting to failure"
                                )
                                rc = EXIT_ERROR
                        except Exception:
                            pass
                    passed_3, missing_3 = _run_phase_validators(
                        phase, config, scratchpad, phases, rc,
                        attempt3_state_before,
                        0,
                    )
                    if passed_3:
                        _clear_retry_hint(scratchpad, phase.name)
                        if phase.name in checkpoint.degraded:
                            checkpoint.degraded.remove(phase.name)
                        checkpoint.save(scratchpad)
                        _rl_retry_recovered = True
                    else:
                        log.error(f"[{phase.name}] attempt 3 also failed: {missing_3}")
                        display.print_failure_diagnosis(
                            phase.name, str(scratchpad), list(missing_3), config,
                        )
                        _restore_quarantined_on_retry_failure(scratchpad, phase)
                        sys.exit(EXIT_DEGRADED)
                elif choice == "skip":
                    log.warning(f"[{phase.name}] user chose SKIP — marking critical phase degraded, continuing pipeline")
                    _restore_quarantined_on_retry_failure(scratchpad, phase)
                    if phase.name not in checkpoint.degraded:
                        checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
                else:
                    display.print_failure_diagnosis(phase.name, str(scratchpad), list(missing), config)
                    _restore_quarantined_on_retry_failure(scratchpad, phase)
                    sys.exit(EXIT_DEGRADED)
            if not _rl_retry_recovered:
                continue

        elif not passed:
            display.print_phase_retry(
                phase_idx + 1, total_active, phase.name, list(missing),
            )
            log.warning(f"[{phase.name}] gate failed after attempt 1: missing {missing} -- retrying")
            # v2.3.14: quarantine stale artifacts so RESUMPTION PROTOCOL
            # doesn't suppress the retry LLM from re-producing them.
            renamed = _quarantine_stale_on_retry(scratchpad, phase, list(missing))
            if renamed:
                log.info(
                    f"[{phase.name}] quarantined {len(renamed)} stale "
                    f"artifact(s) for retry: {renamed[:5]}"
                )
            if phase.name == "recon":
                hint = _generate_recon_retry_hint(list(missing))
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
            if phase.name == "breadth":
                hint = _generate_breadth_retry_hint(scratchpad, list(missing))
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
            if _has_containment_failure(list(missing)):
                _write_retry_hint(
                    scratchpad, phase.name,
                    _generate_containment_retry_hint(phase.name, list(missing)),
                )
            if phase.name == "skeptic":
                hint = _generate_skeptic_retry_hint(scratchpad)
                if hint:
                    _write_retry_hint(scratchpad, phase.name, hint)
            _ensure_retry_hint(
                scratchpad, phase, list(missing), config["project_root"]
            )
            if phase.name == "depth":
                vp = scratchpad / "violations.md"
                try:
                    violations_before = vp.stat().st_size if vp.exists() else 0
                except Exception:
                    violations_before = 0
            file_state_before = _snapshot_file_state(
                scratchpad, config["project_root"]
            )
            display.print_phase_start(
                phase_idx + 1, total_active, phase.name,
                phase_model(phase, mode, config), attempt=2,
            )
            rc = run_phase(phase, config, attempt=2)
            if rc == -3:
                if _prompt_halt_resume_choice(
                    checkpoint, scratchpad, phase.name, config_path
                ):
                    rc = run_phase(phase, config, attempt=2)
                else:
                    _halted = True
                    break

            # v2.3.6 E1: same rc=0-empty sentinel on retry. If attempt 2
            # also returns rc=0 with no output, do NOT silently accept
            # stale artifacts.
            if rc == 0:
                stdio_log = scratchpad / f"_stdio_{phase.name}.attempt2.log"
                try:
                    if (
                        stdio_log.exists()
                        and stdio_log.stat().st_size < 500
                        and not _phase_has_fresh_expected_artifact(
                            phase, scratchpad, config["project_root"], file_state_before
                        )
                    ):
                        log.warning(
                            f"[{phase.name}] retry rc=0 but stdio log < 500 "
                            f"bytes — promoting to failure"
                        )
                        rc = EXIT_ERROR
                except Exception:
                    pass

            # v2.7.7: content-filter bonus retry on the gate-failure retry too.
            if config.get("cli_backend") == "codex" and rc != 0:
                _cf_retry_log = scratchpad / f"_stdio_{phase.name}.attempt2.log"
                if not _cf_retry_log.exists():
                    _cf_retry_log = scratchpad / f"_stdio_{phase.name}.log"
                if _detect_codex_content_filter(_cf_retry_log):
                    log.warning(
                        f"[{phase.name}] content filter on retry — bonus attempt 3"
                    )
                    file_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    display.print_phase_start(
                        phase_idx + 1, total_active, phase.name,
                        phase_model(phase, mode, config), attempt=3,
                    )
                    rc = run_phase(phase, config, attempt=3)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(phase, config, attempt=3)
                        else:
                            _halted = True
                            break

            # v2.4.3: check attempt2 log, not canonical (which may contain stale attempt1 data on timeout)
            retry_log = scratchpad / f"_stdio_{phase.name}.attempt2.log"
            if not retry_log.exists():
                retry_log = scratchpad / f"_stdio_{phase.name}.log"
            retry_rate_limit_consumed = False
            _is_retry_rl = (
                _detect_codex_rate_limit(retry_log, rc)
                if config.get("cli_backend") == "codex"
                else detect_rate_limit(retry_log)
            )
            if _is_retry_rl:
                log.warning(f"[{phase.name}] rate limit on retry -- auto-waiting")
                checkpoint.rate_limited_at = phase.name
                checkpoint.save(scratchpad)
                wait_s = estimate_rate_limit_wait_seconds(retry_log)
                wait_s = min(wait_s or 300, 3600)
                try:
                    display.rate_limit_wait_interactive(wait_s, phase.name)
                except KeyboardInterrupt:
                    display.graceful_stop.requested = False
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    display.print_rate_limit_pause(str(config_path))
                    _rate_limit_halt = True
                    break
                display.print_rate_limit_retry(phase.name)
                # Preserve the pre-attempt containment baseline. The
                # rate-limited attempt may have died before its containment
                # audit ran; re-snapshotting here would fold any foreign
                # writes into the baseline and hide them from attempt 3.
                # Same savings guard as the attempt-2 rate-limit path.
                # By attempt 3 the artifacts may have accumulated across
                # earlier tries; if the gate is now satisfied we don't
                # need to re-spawn.
                _rl3_pre_passed, _rl3_pre_missing = gate_passes(
                    scratchpad, config["project_root"], phase
                )
                if (
                    _rl3_pre_passed
                    and phase.expected_artifacts
                    and not getattr(phase, "appends_existing_artifact", False)
                ):
                    log.info(
                        f"[{phase.name}] attempt-3 rate-limit retry skipped: "
                        f"prior attempts already produced expected_artifacts"
                    )
                    rc = 0
                else:
                    rc = run_phase(phase, config, attempt=3)
                retry_rate_limit_consumed = True
                if rc == -3:
                    if _prompt_halt_resume_choice(
                        checkpoint, scratchpad, phase.name, config_path
                    ):
                        rc = run_phase(phase, config, attempt=3)
                    else:
                        _halted = True
                        break
                attempt3_log = scratchpad / f"_stdio_{phase.name}.attempt3.log"
                _is_attempt3_rl = (
                    _detect_codex_rate_limit(attempt3_log, rc)
                    if config.get("cli_backend") == "codex"
                    else detect_rate_limit(attempt3_log)
                )
                if _is_attempt3_rl:
                    log.warning(
                        f"[{phase.name}] rate-limit retry of retry also hit "
                        "a rate limit; preserving phase state for resume "
                        "without degrading the phase"
                    )
                    checkpoint.rate_limited_at = phase.name
                    checkpoint.save(scratchpad)
                    display.print_rate_limit_pause(str(config_path))
                    _rate_limit_halt = True
                    break

            # v2.1.2 A5: breadth filename compatibility shim (retry block).
            if phase.name == "breadth":
                _normalize_breadth_outputs(scratchpad)

            # v2.1.8: strict phase-isolation quarantine on retry too.
            if phase.name in _QUARANTINE_PATTERNS_BY_PHASE:
                moved = _quarantine_phase_overreach(
                    scratchpad, phase.name, file_state_before
                )
                if moved:
                    log.info(
                        f"[{phase.name}] retry quarantined "
                        f"{len(moved)} files to _overflow/"
                    )

            passed, missing = _run_phase_validators(
                phase, config, scratchpad, phases, rc, file_state_before,
                violations_before,
            )

            # MVP targeted PoC-contract repair (additive, haltless, fire-once).
            # When attempt 2 of a PoC verify shard fails EXCLUSIVELY on the
            # "Attempted:YES but lacks concrete Test File/Command" PoC-contract
            # class, fire ONE extra repair attempt — scoped via a sharpened retry
            # hint to ONLY the failed IDs — BEFORE the existing verify-shard
            # degrade-and-continue branch below. The good findings' verify_*.md
            # files are already on disk and are preserved by the v2.4.5
            # partial-results accumulation (NO new quarantine logic). A hard
            # disk-marker fire-once guard means this can NEVER loop: it runs at
            # most once per phase. If the targeted attempt satisfies the gate,
            # `passed` flips True and the normal completion path runs. If it still
            # fails (or anything is ambiguous), `passed` stays False and control
            # reaches the UNCHANGED `_is_poc_verify_shard` degrade branch (ship
            # UNPROVEN, continue). The degrade remains the floor; verify shards
            # never halt. Triggers ONLY on the PoC-contract-only class — a mixed
            # failure skips the targeted attempt and degrades as before.
            if (
                not passed
                and _is_poc_verify_shard(phase.name)
                and not verify_targeted_repair_already_done(
                    scratchpad, phase.name
                )
            ):
                _tr_failed_ids = verify_poc_contract_only_failed_ids(
                    list(missing), scratchpad
                )
                if _tr_failed_ids:
                    log.warning(
                        f"[{phase.name}] PoC-contract-only gate failure for "
                        f"{_tr_failed_ids} — running ONE targeted repair attempt "
                        f"(scoped to those IDs) before degrading"
                    )
                    # Set the fire-once marker BEFORE spawning so a crash /
                    # resume mid-attempt cannot re-fire it.
                    mark_verify_targeted_repair_done(scratchpad, phase.name)
                    _write_retry_hint(
                        scratchpad, phase.name,
                        _generate_verify_targeted_repair_hint(_tr_failed_ids),
                    )
                    _tr_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    rc = run_phase(phase, config, attempt=3)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(phase, config, attempt=3)
                        else:
                            _halted = True
                            break
                    passed, missing = _run_phase_validators(
                        phase, config, scratchpad, phases, rc,
                        _tr_state_before, 0,
                    )
                    if passed:
                        log.info(
                            f"[{phase.name}] targeted PoC-contract repair "
                            f"satisfied the gate — completing normally"
                        )
                    else:
                        log.warning(
                            f"[{phase.name}] targeted PoC-contract repair did "
                            f"not satisfy the gate ({missing}) — degrading and "
                            f"continuing (verify shards never halt)"
                        )

            if passed and phase.name in ("semantic_dedup", "sc_semantic_dedup"):
                passthrough_issue = _semantic_dedup_passthrough_issue(scratchpad)
                if passthrough_issue:
                    n_mech = _apply_mechanical_dedup_from_pairs(
                        scratchpad, phase.name,
                    )
                    if n_mech > 0:
                        reason = (
                            f"semantic dedup retry left PASSTHROUGH; applied "
                            f"{n_mech} mechanical merge(s) from candidate pairs"
                        )
                    else:
                        reason = (
                            "semantic dedup retry still left PASSTHROUGH unchanged; "
                            "no strong-signal candidate pairs for mechanical fallback"
                        )
                        _write_semantic_dedup_skip_outputs(
                            scratchpad, phase.name, reason,
                        )
                    log.warning(
                        f"[{phase.name}] {passthrough_issue}; {reason}"
                    )
                    _clear_retry_hint(scratchpad, phase.name)
                    _cleanup_quarantine_backups(scratchpad, phase)
                    checkpoint.mark_completed(phase.name)
                    checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                    checkpoint.save(scratchpad)
                    display.print_phase_skipped(
                        phase_idx + 1, total_active, phase.name,
                        "non-blocking passthrough after retry",
                    )
                    continue

            # Codex-only extended retry budget for RECOVERING content phases
            # (recon, breadth, inventory, inventory_chunk_*). Standard budget is
            # retry-once-then-degrade (2 attempts). Codex single-pass workers
            # often under-cover on attempt 2 and recover when re-prompted with
            # the existing delta retry hint, so grant up to
            # _CODEX_EXTRA_RETRY_MAX_ATTEMPTS (3) total before falling into the
            # UNCHANGED degrade/halt block below. Strictly backend- and
            # phase-scoped: Claude (and every other backend), plus every
            # non-recovering phase (verify/report/skeptic/chain/depth/etc.),
            # keep their existing budget untouched. This NEVER relaxes a gate —
            # it only re-runs the same gated phase, so it cannot drop a finding.
            if not passed:
                _codex_budget = _codex_max_attempts_for_phase(
                    config.get("cli_backend"), phase.name
                )
                _codex_attempt = 2  # attempts 1 + 2 already consumed above
                # Only COVERAGE/CONTENT gaps are hint-recoverable. A CONTAINMENT
                # violation (the phase wrote foreign later-phase artifacts) is
                # NOT — re-running with a hint cannot fix phase-scope discipline
                # and would re-create the foreign writes and muddy quarantine.
                # So skip the extra hinted retries for containment failures and
                # fall straight through to the standard quarantine + degrade/halt
                # block below (unchanged behavior for that failure class).
                while (
                    not passed
                    and _codex_attempt < _codex_budget
                    and not _has_containment_failure(list(missing))
                ):
                    _codex_attempt += 1
                    log.warning(
                        f"[{phase.name}] extended hinted retry budget: gate "
                        f"failed after {_codex_attempt - 1} attempt(s) "
                        f"({missing}) — re-running (attempt {_codex_attempt} of "
                        f"{_codex_budget}, with missing-list hint) before degrading"
                    )
                    # Reuse the existing delta retry-hint machinery so the
                    # re-run sees an explicit checklist, then re-snapshot the
                    # containment baseline for the fresh attempt.
                    _ensure_retry_hint(
                        scratchpad, phase, list(missing), config["project_root"]
                    )
                    file_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    display.print_phase_start(
                        phase_idx + 1, total_active, phase.name,
                        phase_model(phase, mode, config), attempt=_codex_attempt,
                    )
                    rc = run_phase(phase, config, attempt=_codex_attempt)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(
                                phase, config, attempt=_codex_attempt
                            )
                        else:
                            _halted = True
                            break
                    if phase.name == "breadth":
                        _normalize_breadth_outputs(scratchpad)
                    if phase.name in _QUARANTINE_PATTERNS_BY_PHASE:
                        moved = _quarantine_phase_overreach(
                            scratchpad, phase.name, file_state_before
                        )
                        if moved:
                            log.info(
                                f"[{phase.name}] Codex extra-retry quarantined "
                                f"{len(moved)} files to _overflow/"
                            )
                    passed, missing = _run_phase_validators(
                        phase, config, scratchpad, phases, rc,
                        file_state_before, violations_before,
                    )
                if _halted:
                    break

            # v2.1.6: on retry success, clear the retry-hint file so it
            # doesn't contaminate future runs if the checkpoint is reused.
            if passed:
                _clear_retry_hint(scratchpad, phase.name)
                _cleanup_quarantine_backups(scratchpad, phase)

            if not passed:
                # LAST-RESORT recon degrade (FIX 1b): the worker pool, the
                # direct isolated-recon fallback, and every retry attempt have
                # all run and the content gate STILL fails. If the ONLY hard
                # failures are survived pre-pass overwrite markers (recon never
                # produced an LLM-enriched canonical handoff, but the mechanical
                # pre-pass tables are regex-complete), strip the marker and
                # promote the pre-pass content to canonical so the pipeline
                # continues with degraded-but-usable recon instead of looping
                # forever. Backend-agnostic. Declines (no-op) when any
                # non-marker recon gap exists or the bodies are
                # empty/placeholder, preserving the halt for a genuine recon
                # failure. This is a per-phase degrade like the depth (S1.6) and
                # verify-shard degrades below — NOT a gate relaxation: the
                # helper only succeeds when re-running the content validator
                # actually passes after the recall-safe marker strip.
                if phase.name == "recon":
                    _recon_degraded, _ = _try_recon_prepass_marker_degrade(
                        scratchpad, config, list(missing)
                    )
                    if _recon_degraded:
                        log.warning(
                            "[recon] degraded to pre-pass canonical content "
                            "after exhausting all attempts; continuing pipeline"
                        )
                        _clear_retry_hint(scratchpad, phase.name)
                        _cleanup_quarantine_backups(scratchpad, phase)
                        if phase.name in checkpoint.degraded:
                            checkpoint.degraded.remove(phase.name)
                        checkpoint.mark_completed(phase.name)
                        checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
                        _record_phase_artifact_state(
                            scratchpad,
                            config["project_root"],
                            phases,
                            phase.name,
                            config["pipeline"],
                        )
                        if checkpoint.rate_limited_at == phase.name:
                            checkpoint.rate_limited_at = None
                        checkpoint.save(scratchpad)
                        continue
                log.error(f"[{phase.name}] degraded after 2 attempts: missing {missing}")
                # F3: suppress the red `! HALT ... pipeline halted` panel for
                # the depth path when S1.6 will recover. Without this gate
                # the panel prints BEFORE the depth branch overrides the
                # halt, producing the misleading "HALT that didn't halt".
                # Genuine halts (depth core absent, non-depth criticals)
                # still print the panel via their own call sites below.
                _is_depth_recoverable = (
                    phase.name == "depth"
                    # v2.8.16: L1 depth is recoverable on the same terms as SC
                    # (core present). The former `!= "l1"` exclusion forced the
                    # red HALT panel for L1 even when S1.6 would degrade-continue.
                    and _depth_core_artifacts_present(
                        scratchpad,
                        config.get("pipeline", "sc"),
                        config.get("mode", "core"),
                    )
                )
                # v2.8.15/v2.8.16: verify shards degrade-and-continue (never
                # halt) — suppress the red critical-HALT panel for them, same as
                # depth. v2.8.16 extends this to L1 (`verify_*`) so L1 verify
                # halts the same way SC does (i.e. it doesn't).
                _is_verify_shard_recoverable = _is_poc_verify_shard(phase.name)
                display.print_phase_degraded(
                    phase.name, list(missing),
                    critical=phase.critical
                    and not _is_depth_recoverable
                    and not _is_verify_shard_recoverable,
                )
                # v2.3.14: restore quarantined artifacts — stale content
                # is better than nothing for downstream phases.
                _TIER_PLACEHOLDER_MAP = {
                    "report_critical_high": "report_critical_high.md",
                    "report_medium": "report_medium.md",
                    "report_low_info": "report_low_info.md",
                    "report_body_writer_critical_high": "report_critical_high.md",
                    "report_body_writer_medium": "report_medium.md",
                    "report_body_writer_low_info": "report_low_info.md",
                }
                # Dynamic tier shard mapping
                _m_bw = re.match(r"^report_body_writer_(critical_high|medium|low_info)_([a-z])$", phase.name)
                _m_lg = re.match(r"^report_(critical_high|medium|low_info)_([a-z])$", phase.name)
                if _m_bw:
                    _TIER_PLACEHOLDER_MAP[phase.name] = f"report_{_m_bw.group(1)}_{_m_bw.group(2)}.md"
                elif _m_lg:
                    _TIER_PLACEHOLDER_MAP[phase.name] = f"report_{_m_lg.group(1)}_{_m_lg.group(2)}.md"
                if phase.name in _TIER_PLACEHOLDER_MAP:
                    write_report_tier_placeholder(
                        scratchpad, _TIER_PLACEHOLDER_MAP[phase.name],
                        "tier writer exhausted retries; continuing with partial report"
                    )
                (scratchpad / f"{phase.name}.degraded").write_text(
                    f"Phase {phase.name} exhausted retries.\n"
                    f"Missing: {missing}\n"
                    f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
                    encoding="utf-8",
                )
                if phase.name not in checkpoint.degraded:
                    checkpoint.degraded.append(phase.name)
                checkpoint.save(scratchpad)

                # Critical phase degraded = pipeline cannot produce a useful
                # report. Halt rather than cascade empty inputs through
                # inventory -> depth -> verify -> report (which would all
                # produce their own degrade markers and finish with a
                # useless shell of a report).
                #
                # v2.3.14: containment failures on NON-CRITICAL phases no
                # longer halt. The foreign file is already quarantined to
                # _overflow/ by _quarantine_foreign_phase_writes. The
                # phase degrades normally (its legitimate artifacts are
                # preserved).
                containment_failure = _has_containment_failure(list(missing))
                if containment_failure:
                    display.print_failure_diagnosis(
                        phase.name, str(scratchpad), list(missing), config,
                    )
                    if not phase.critical:
                        log.error(
                            f"[{phase.name}] containment violation (quarantined), "
                            f"but phase is non-critical - continuing as degraded"
                        )
                        continue
                    log.error(
                        f"[{phase.name}] containment violation (quarantined) "
                        f"on critical phase - halting"
                    )
                    sys.exit(EXIT_DEGRADED)
                if phase.name == "depth":
                    # S1.5 + S1.6: the depth phase never halts the pipeline on
                    # a tail-artifact gap. Core findings absent -> genuine
                    # catastrophic depth failure -> halt. Core present -> one
                    # targeted repair attempt (S1.5); if gaps still remain,
                    # degrade-and-continue (S1.6) -- downstream phases work on
                    # the core findings.
                    #
                    # v2.8.16: L1 now mirrors SC exactly. The former
                    # `config.get("pipeline") == "l1" or ...` force-halt disjunct
                    # made L1 depth ALWAYS halt on any tail gap, even when its 5
                    # core role findings were complete. _depth_core_artifacts_present
                    # is already L1-aware (l1_never_cut_groups(mode)[:5] = the 5 L1
                    # depth role files, mode-invariant), so it alone decides for
                    # both pipelines. (NOTE: the pipeline-neutral containment halt
                    # at ~14478 runs BEFORE this branch and still halts a critical
                    # foreign-write violation for BOTH pipelines — intentional
                    # SC-parity, not affected here.)
                    if not _depth_core_artifacts_present(
                        scratchpad,
                        config.get("pipeline", "sc"),
                        config.get("mode", "core"),
                    ):
                        log.error(
                            "[depth] core findings absent after 2 attempts "
                            "(depth role findings not all substantive) - "
                            "halting; depth produced no usable input for "
                            "downstream phases"
                        )
                        display.print_phase_degraded(
                            phase.name, list(missing), critical=True
                        )
                        display.print_failure_diagnosis(
                            phase.name, str(scratchpad), list(missing), config,
                        )
                        sys.exit(EXIT_DEGRADED)
                    log.warning(
                        "[depth] degraded after 2 attempts but core findings "
                        f"are present - running one targeted repair attempt. "
                        f"Gaps: {missing}"
                    )
                    _write_retry_hint(
                        scratchpad, phase.name,
                        _generate_depth_repair_hint(
                            list(missing),
                            config.get("pipeline", "sc"),
                            config.get("mode", "core"),
                        ),
                    )
                    repair_state_before = _snapshot_file_state(
                        scratchpad, config["project_root"]
                    )
                    rc = run_phase(phase, config, attempt=3)
                    if rc == -3:
                        if _prompt_halt_resume_choice(
                            checkpoint, scratchpad, phase.name, config_path
                        ):
                            rc = run_phase(phase, config, attempt=3)
                        else:
                            _halted = True
                            break
                    passed_r, missing_r = _run_phase_validators(
                        phase, config, scratchpad, phases, rc,
                        repair_state_before, 0,
                    )
                    if passed_r:
                        _clear_retry_hint(scratchpad, phase.name)
                        _cleanup_quarantine_backups(scratchpad, phase)
                        if phase.name in checkpoint.degraded:
                            checkpoint.degraded.remove(phase.name)
                        checkpoint.save(scratchpad)
                        # fall through to mark_completed below
                    else:
                        log.warning(
                            "[depth] tail-artifact gaps remain after the "
                            f"repair attempt ({missing_r}) - degrading and "
                            "continuing the pipeline; chain analysis proceeds "
                            "on the core depth findings"
                        )
                        _clear_retry_hint(scratchpad, phase.name)
                        try:
                            with (scratchpad / "violations.md").open(
                                "a", encoding="utf-8"
                            ) as _vf:
                                _vf.write(
                                    "\n## depth degrade-not-halt (S1.6)\n"
                                    "- core findings present; unrecovered "
                                    f"tail gaps: {missing_r}\n"
                                )
                        except Exception:
                            pass
                        if phase.name not in checkpoint.degraded:
                            checkpoint.degraded.append(phase.name)
                        checkpoint.save(scratchpad)
                        continue
                elif _is_poc_verify_shard(phase.name):
                    # v2.8.15/v2.8.16: verify shards NEVER halt the audit — SC
                    # (`sc_verify_*`) AND L1 (`verify_*`). After bounded retries
                    # the verifier may still not produce a PoC / valid blocker
                    # (the verifier-execution gap — forensic showed 0 real PoCs).
                    # The shard's verify_*.md files exist (CODE-TRACE); ship them
                    # as UNPROVEN per the recall-safe routing design and continue.
                    # The {sc_,}verify_aggregate recovery+stub net (present for
                    # both pipelines) covers any genuinely-missing verify files.
                    # This kills the whack-a-mole verify halt (sc_verify_high_c /
                    # H-5 etc.) on SC and the same class on L1. Real fix = the
                    # verify author/executor split (Phase 1, v2.8.16).
                    log.warning(
                        f"[{phase.name}] degraded after retries (PoC contract "
                        f"unmet); shipping shard findings as UNPROVEN and "
                        f"continuing (verify shards never halt). Gaps: {missing}"
                    )
                    try:
                        with (scratchpad / "violations.md").open(
                            "a", encoding="utf-8"
                        ) as _vf:
                            _vf.write(
                                f"\n## {phase.name} degrade-not-halt "
                                f"(verify-shard net, v2.8.15)\n"
                                f"- findings shipped UNPROVEN; unmet PoC "
                                f"contract: {missing}\n"
                            )
                    except Exception:
                        pass
                    if phase.name not in checkpoint.degraded:
                        checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
                    continue
                elif phase.name == "inventory" and _inventory_degrade_floor_ok(
                    scratchpad
                ):
                    # AP-HF-1: inventory degraded on a STRUCTURE /
                    # field-completeness gate but >= 3 usable finding blocks are
                    # present — downstream phases (chain/verify/report) can still
                    # operate on them. Degrade-and-continue instead of funneling
                    # to wait_critical_halt_choice. (Parity-only failures already
                    # degrade via FC4, which skips parity for inventory; this
                    # branch handles the STRUCTURE gate that FC4 still enforces.)
                    log.warning(
                        "[inventory] degraded on a structure/field-completeness "
                        f"gate but usable finding blocks are present ({missing}) "
                        "- degrading and continuing; downstream phases work on "
                        "the parseable inventory"
                    )
                    try:
                        with (scratchpad / "violations.md").open(
                            "a", encoding="utf-8"
                        ) as _vf:
                            _vf.write(
                                "\n## inventory degrade-not-halt (AP-HF-1)\n"
                                "- usable finding blocks present; unresolved "
                                f"structure gaps: {missing}\n"
                            )
                    except Exception:
                        pass
                    if phase.name not in checkpoint.degraded:
                        checkpoint.degraded.append(phase.name)
                    checkpoint.save(scratchpad)
                    continue
                elif phase.critical:
                    # FC4 safety net (shared helper): re-validate artifacts with
                    # the content gate before halting; auto-complete + continue
                    # if content-valid. Only halt when content genuinely fails.
                    _content_issues = _fc4_autocomplete_if_content_valid(
                        phase, config, scratchpad, checkpoint
                    )
                    if _content_issues is None:
                        continue
                    log.error(
                        f"[{phase.name}] is "
                        f"{'phase-containment-failed' if containment_failure else 'CRITICAL'}. "
                        f"Downstream phases cannot produce meaningful output "
                        f"without this phase boundary."
                    )
                    display.print_phase_degraded(phase.name, list(_content_issues), critical=True)
                    display.print_halt_diagnostics(
                        phase.name, str(scratchpad), str(config_path),
                    )
                    display.print_critical_halt_prompt(phase.name, str(config_path))
                    choice = display.wait_critical_halt_choice()
                    if choice == "retry":
                        display.print_halt_resume()
                        critical_retry_attempt = 4 if retry_rate_limit_consumed else 3
                        if phase.name == "breadth":
                            hint = _generate_breadth_retry_hint(
                                scratchpad, list(missing)
                            )
                            if hint:
                                _write_retry_hint(scratchpad, phase.name, hint)
                        if containment_failure:
                            _write_retry_hint(
                                scratchpad, phase.name,
                                _generate_containment_retry_hint(
                                    phase.name, list(missing)
                                ),
                            )
                        attempt3_state_before = _snapshot_file_state(
                            scratchpad, config["project_root"]
                        )
                        rc = run_phase(phase, config, attempt=critical_retry_attempt)
                        if rc == -3:
                            if _prompt_halt_resume_choice(
                                checkpoint, scratchpad, phase.name, config_path
                            ):
                                rc = run_phase(
                                    phase, config,
                                    attempt=critical_retry_attempt,
                                )
                            else:
                                _halted = True
                                break
                        if rc == 0:
                            stdio_log = scratchpad / f"_stdio_{phase.name}.attempt{critical_retry_attempt}.log"
                            try:
                                if (
                                    stdio_log.exists()
                                    and stdio_log.stat().st_size < 500
                                    and not _phase_has_fresh_expected_artifact(
                                        phase, scratchpad, config["project_root"], attempt3_state_before
                                    )
                                ):
                                    log.warning(
                                        f"[{phase.name}] attempt 3 rc=0 but stdio "
                                        f"log < 500 bytes - promoting to failure"
                                    )
                                    rc = EXIT_ERROR
                            except Exception:
                                pass
                        passed_3, missing_3 = _run_phase_validators(
                            phase, config, scratchpad, phases, rc,
                            attempt3_state_before,
                            0,
                        )
                        if passed_3:
                            _clear_retry_hint(scratchpad, phase.name)
                            _cleanup_quarantine_backups(scratchpad, phase)
                            if phase.name in checkpoint.degraded:
                                checkpoint.degraded.remove(phase.name)
                            checkpoint.save(scratchpad)
                            # Fall through to mark_completed below
                        else:
                            log.error(f"[{phase.name}] attempt 3 also failed: {missing_3}")
                            display.print_failure_diagnosis(
                                phase.name, str(scratchpad), list(missing_3), config,
                            )
                            _restore_quarantined_on_retry_failure(scratchpad, phase)
                            sys.exit(EXIT_DEGRADED)
                    elif choice == "skip":
                        log.warning(f"[{phase.name}] user chose SKIP — marking critical phase degraded, continuing pipeline")
                        _restore_quarantined_on_retry_failure(scratchpad, phase)
                        if phase.name not in checkpoint.degraded:
                            checkpoint.degraded.append(phase.name)
                        checkpoint.save(scratchpad)
                        continue
                    else:
                        display.print_failure_diagnosis(
                            phase.name, str(scratchpad), list(missing), config,
                        )
                        _restore_quarantined_on_retry_failure(scratchpad, phase)
                        sys.exit(EXIT_DEGRADED)

        checkpoint.mark_completed(phase.name)
        checkpoint.clear_degraded_sentinel(scratchpad, phase.name)
        _record_phase_artifact_state(
            scratchpad,
            config["project_root"],
            phases,
            phase.name,
            config["pipeline"],
        )
        if checkpoint.rate_limited_at == phase.name:
            checkpoint.rate_limited_at = None
        _clear_retry_hint(scratchpad, phase.name)
        checkpoint.save(scratchpad)

        # SC report_index: build body-writer manifests + expand shard phases.
        # L1 does this in its mechanical path; SC's LLM-authored
        # report_index needs the same treatment after the gate passes.
        if (
            phase.name == "report_index"
            and config.get("pipeline") != "l1"
        ):
            try:
                built = _build_sc_body_writer_manifests(scratchpad)
                if built:
                    phases[:] = expand_shard_phases(phases, scratchpad)
                    active_phases = [p for p in phases if mode in p.modes]
                    log.info(
                        f"[report_index] SC manifests built for "
                        f"{len(built)} shard(s), phases expanded"
                    )
                else:
                    log.warning(
                        "[report_index] SC manifest build returned empty — "
                        "body writers will use LLM-only mode"
                    )
            except Exception as exc:
                log.warning(
                    f"[report_index] SC manifest build failed: {exc!r} — "
                    f"body writers will use LLM-only mode"
                )

        # FIX #4: L1 report_index completed via the LLM Index Agent path
        # (cases (a)/(b)). The L1 mechanical-backstop path already expands
        # shard phases inline before its `continue`, so it never reaches here;
        # this branch covers the LLM-authored index so the tier body-writer
        # shard phases still get expanded (parity with the mechanical path).
        if (
            phase.name == "report_index"
            and config.get("pipeline") == "l1"
        ):
            try:
                phases[:] = expand_shard_phases(phases, scratchpad)
                active_phases = [p for p in phases if mode in p.modes]
                log.info(
                    "[report_index] L1 LLM-authored index complete — "
                    "shard phases expanded"
                )
            except Exception as exc:
                log.warning(
                    f"[report_index] L1 shard expansion failed: {exc!r}"
                )

        # Gate summary: show what was checked so success isn't silent
        gate_summary = _format_gate_summary(phase, scratchpad, config)
        display.print_phase_done(
            phase_idx + 1, total_active, phase.name, gate_summary,
        )
        log.info(f"[{phase.name}] complete")
        if gate_summary:
            log.info(f"[{phase.name}] {gate_summary}")
        prev_phase = phase.name

    if skipped_names:
        display.print_skipped_summary(skipped_names)

    if _rate_limit_halt:
        sys.exit(EXIT_RATE_LIMITED)

    if _halted:
        display.graceful_stop.requested = False
        display.print_purge_prompt(str(scratchpad))
        if display.wait_purge_choice():
            _purge_scratchpad(scratchpad, config)
            display.print_purge_done(str(scratchpad))
        display.print_exit_clean()
        _hard_exit_after_user_stop(0)

    # v2.1.6: reconcile on-disk `.degraded` sentinels into the checkpoint
    # JSON. Fixes a prior L1 observation where `_v2_checkpoint.json.degraded
    # == []` misleadingly disagreed with 3 `.degraded` files on disk, so a
    # reader of only the JSON saw a falsely-clean run.
    newly_synced = _sync_degraded_sentinels_to_checkpoint(scratchpad, checkpoint)
    if newly_synced:
        log.warning(
            f"Synced {len(newly_synced)} on-disk .degraded sentinels into "
            f"checkpoint: {newly_synced}"
        )
        checkpoint.save(scratchpad)

    report_path = Path(config["project_root"]) / "AUDIT_REPORT.md"
    report_str = str(report_path) if report_path.exists() else None
    snap_str = None
    if report_path.exists():
        log.info(f"Report written to {report_path}")
        snap = _snapshot_report_timestamped(config["project_root"])
        if snap:
            log.info(f"Timestamped snapshot: {snap}")
            snap_str = str(snap)

    if checkpoint.degraded:
        log.warning(f"Pipeline complete with {len(checkpoint.degraded)} degraded phases: {checkpoint.degraded}")
    else:
        log.info("Pipeline complete -- no degraded phases")

    display.print_pipeline_complete(
        checkpoint.degraded, report_path=report_str, snapshot_path=snap_str,
    )

    sys.exit(EXIT_SUCCESS if not checkpoint.degraded else EXIT_DEGRADED)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        display.print_interrupt()
        sys.exit(130)
