from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from plamen_types import *  # noqa: F403,F401
from plamen_parsers import *  # noqa: F403,F401
from plamen_validators import *  # noqa: F403,F401

logger = logging.getLogger(__name__)

__all__ = [
    "_LEGITIMATE_SUBPRODUCER_PATTERNS",
    "_L1_ALWAYS_ON_DEPTH",
    "_L1_DEPTH_AGENT_ROLES",
    "_L1_SKILL_BASE",
    "_L1_SKILL_DEPTH_ROUTING",
    "_PLAMEN_EXECUTION_CONTRACT_CLAUDE",
    "_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY",
    "_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_UNSUPERVISED",
    "_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_BREADTH",
    "_PLAMEN_EXECUTION_CONTRACT_CODEX",
    "PLAMEN_STUB_SENTINEL",
    "_render_reservation_header",
    "_SECTION_HEADER_RE",
    "_build_graph_sweeps_artifact_directive",
    "_build_l1_depth_skill_injection",
    "_check_prompt_name_consistency",
    "_find_prompt_phase_boundary_violations",
    "_glob_to_regex",
    "_inline_stripped_rescan_prompt",
    "_is_direct_execution_phase",
    "_parse_l1_required_skills",
    "_phase_uses_task",
    "_derive_claude_exec_mode",
    "_prune_l1_verify_shard_prompt",
    "_prune_sc_verify_shard_prompt",
    "_render_execution_contract",
    "_render_id_ledger_directive",
    "_render_expected_output_block",
    "_render_phase_isolation_block",
    "_render_forbidden_output_block",
    "_render_runtime_placeholders",
    "_resolve_l1_skill_paths",
    "_resolve_recon_prompt",
    "build_phase_prompt",
    "count_loc",
    "extract_phase_sections",
    "PhasePromptError",
    "resolve_v1_prompt",
    "scale_timeout",
]


class PhasePromptError(Exception):
    """Raised when a phase's prompt cannot be built safely.

    This replaces the old behavior of dumping the entire 60-74KB V1 prompt
    into a subprocess when section markers don't match. The full-prompt
    fallback repeatedly caused agents to enter later phases, corrupting
    the scratchpad. A clean halt is always better than a runaway agent.
    """
    pass


# --- Helpers ---
def resolve_v1_prompt(pipeline: str) -> Path:
    if pipeline == "l1":
        return plamen_home() / "commands" / "plamen-l1.md"
    return plamen_home() / "commands" / "plamen.md"


# Section markers that define preamble / TOC. Sections ABOVE the first
# "## Step" or "## Phase" heading are global (rules, protocols, config
# parsing, Ã‚Â§WRITE-THEN-VERIFY, Ã‚Â§SCIP-PREBAKE, checkpoint manifest). We
# preserve these always because they define the subprocess's operating
# contract.
_SECTION_HEADER_RE = re.compile(r"^(##+)\s+(.+?)\s*$", re.MULTILINE)


def extract_phase_sections(v1_prompt_text: str, markers: list) -> str:
    """Return the subset of the V1 prompt relevant to this phase.

    Keep:
    - Everything ABOVE the first `## Step|## Phase` heading (global rules).
    - For each marker, the section starting at its heading and continuing
      until the next heading at the same level.

    Raises PhasePromptError if no markers match -- caller must handle via
    standalone prompt file or hard fail. Never returns the full prompt.

    This is the single biggest prompt-token reduction in the V2 driver.
    A 63KB plamen.md typically reduces to 6-12KB for any one phase,
    eliminating the mid-run compaction thrashing that caused the depth
    phase rapid_refill_breaker failure.
    """
    # Find all section headers with their positions.
    headers = []
    for m in _SECTION_HEADER_RE.finditer(v1_prompt_text):
        headers.append({
            "level": len(m.group(1)),
            "title": m.group(2),
            "start": m.start(),
            "end_of_header": m.end(),
        })

    if not headers:
        return v1_prompt_text

    # Global preamble = everything before the first section header of level 2
    first_level2 = next((h for h in headers if h["level"] == 2), None)
    preamble = v1_prompt_text[:first_level2["start"]] if first_level2 else ""

    # Marker matching: we want the FULL marker (minus parenthetical
    # comments in the marker itself) to appear in the heading, OR the
    # heading to start with the marker's phase/step identifier.
    #
    # Previous over-tolerant matcher caused false positives like:
    # marker "Phase 4c: Chain Analysis" matching "Phase 4a.5: Semantic
    # Invariant..." because "phase 4" was treated as a prefix.
    _PHASE_ID_RE = re.compile(r"^(Phase|Step)\s+([\w.]+)[:\s]")

    def _marker_id(text: str) -> str:
        """Extract the phase/step identifier like 'Phase 4c' or 'Step 1.5'."""
        m = _PHASE_ID_RE.match(text.strip())
        if m:
            return f"{m.group(1)} {m.group(2)}".lower()
        return ""

    def _marker_matches(marker: str, title: str) -> bool:
        # Strip parenthetical comments from the marker (our driver uses
        # them for developer notes like "(+ sub-step)")
        marker_clean = re.sub(r"\s*\([^)]*\)", "", marker).strip()
        m_lc = marker_clean.lower()
        t_lc = title.lower()
        # 1. Full marker substring in title
        if m_lc in t_lc:
            return True
        # 2. Exact phase/step identifier match (e.g. "Phase 4c" == "Phase 4c")
        m_id = _marker_id(marker_clean)
        t_id = _marker_id(title)
        if m_id and t_id and m_id == t_id:
            return True
        # 3. Marker-before-colon match (e.g. "Phase 3b: Breadth Re-Scan"
        #    without caring whether the title says "(THOROUGH mode only)")
        marker_before_colon = marker_clean.split(":", 1)[0].strip().lower()
        title_before_colon = title.split(":", 1)[0].strip().lower()
        if marker_before_colon and marker_before_colon == title_before_colon:
            return True
        return False

    selected = []
    matched_titles = []
    for marker in markers:
        # Find ALL matching headers; prefer the most specific match
        # (longest-match-wins on title, then deepest level). This avoids
        # `Phase 4c` accidentally matching the broad `## Phase 4:` header.
        candidates = []
        for i, h in enumerate(headers):
            if _marker_matches(marker, h["title"]):
                # Score: higher level (deeper) = more specific; longer
                # title overlap = more specific.
                overlap = 0
                m_lc = marker.lower()
                t_lc = h["title"].lower()
                for L in range(len(m_lc), 3, -1):
                    if m_lc[:L] in t_lc:
                        overlap = L
                        break
                score = (h["level"], overlap)
                candidates.append((score, i, h))
        if not candidates:
            continue
        candidates.sort(key=lambda x: x[0], reverse=True)
        _, i, h = candidates[0]
        # Section extends to the next header at the SAME or SHALLOWER level.
        end_pos = len(v1_prompt_text)
        for later in headers[i + 1:]:
            if later["level"] <= h["level"]:
                end_pos = later["start"]
                break
        selected.append(v1_prompt_text[h["start"]:end_pos])
        matched_titles.append(h["title"])

    if not selected:
        # v2.5.0: NEVER return full prompt. The old fallback (returning the
        # entire 60-74KB V1 prompt) repeatedly caused agents to enter later
        # phases, corrupting the scratchpad. Raise so the caller can try
        # standalone prompt files or hard-fail cleanly.
        raise PhasePromptError(
            f"Section markers {markers!r} matched no heading in V1 prompt "
            f"({len(v1_prompt_text)} chars). Either the V1 heading was "
            f"renamed without updating plamen_types.py, or this phase needs "
            f"a standalone prompt file in prompts/shared/v2/."
        )

    # v2.4.6: NO pipeline TOC. Giving the subprocess a list of all phases
    # lets it "helpfully" run subsequent phases after completing its own.
    # The subprocess needs ONLY its assigned section. Prior-phase context
    # comes from scratchpad artifacts, not from knowing the phase list.

    # Strip preamble of orchestrator-level references that leak later-phase
    # awareness (e.g., "## Orchestration Protocol" referencing rules that
    # describe the full pipeline). Keep only lines before the first section
    # that mentions orchestration/pipeline-level concerns.
    preamble_lines = preamble.rstrip().splitlines()
    stripped_preamble_lines = []
    for line in preamble_lines:
        ll = line.lower()
        if "orchestration protocol" in ll or "orchestrator" in ll:
            break
        stripped_preamble_lines.append(line)
    stripped_preamble = "\n".join(stripped_preamble_lines).rstrip()

    # Hard STOP directive appended after all selected sections
    stop_directive = (
        "\n\n---\n\n"
        "## PHASE BOUNDARY -- HARD STOP\n\n"
        "Your assigned phase is COMPLETE when you have written the artifacts "
        "listed above. **Do NOT proceed outside this assigned phase.** "
        "Do NOT create artifacts outside the expected output contract. "
        "Do NOT read or follow instructions from other phases. "
        "Return your results and exit immediately.\n"
    )

    parts = [stripped_preamble, ""] + selected + [stop_directive]
    return "\n".join(parts)


def _inline_stripped_rescan_prompt(text: str) -> str:
    """Inline phase3b-rescan-prompt.md with the Inventory Merge section removed.

    The V1 prompt says "Read full prompt from: phase3b-rescan-prompt.md".
    In V2 the subprocess follows this, reads the file, and executes the
    Inventory Merge sub-step -- writing findings_inventory.md, which belongs
    to the inventory phase. Instead of adding a "don't do X" directive,
    read the file, strip the section, and inline the cleaned content so
    the subprocess never sees the merge instructions.
    """
    ref_re = re.compile(
        r"\*\*Read full prompt from\*\*:\s*`[^`]*phase3b-rescan-prompt\.md`"
    )
    m = ref_re.search(text)
    if not m:
        return text
    prompt_path = plamen_home() / "rules" / "phase3b-rescan-prompt.md"
    if not prompt_path.exists():
        return text
    content = prompt_path.read_text(encoding="utf-8")
    # Strip from the --- before "## Inventory Merge" through its closing ---.
    # Leaves a single --- separator connecting the preceding section to
    # ## Budget Impact.
    content = re.sub(
        r"\n---\s*\n+##\s+Inventory Merge\b.*?\n---",
        "\n---",
        content,
        count=1,
        flags=re.DOTALL,
    )
    return text[:m.start()] + content.strip() + text[m.end():]


def _prune_l1_verify_shard_prompt(text: str) -> str:
    """Remove downstream Step 5 sub-phases from bounded L1 verifier prompts.

    The V1 L1 prompt groups verifier rows, crossbatch, skeptic-judge, and
    aggregation under the same `## Step 5: Verification` heading. Bounded
    verifier shards must see only the row-verification contract; showing
    Step 5.4/5.5/5.6 gives a verifier enough future-phase instructions to
    imitate those phases.
    """
    cut = re.search(r"(?m)^###\s+Step\s+5\.3\s*:", text)
    if not cut:
        return text
    return (
        text[:cut.start()].rstrip()
        + "\n\n"
        + "### Out-of-scope instructions intentionally withheld\n\n"
        + "This bounded shard must execute only the selected contract. "
        + "The driver owns every other subprocess boundary with fresh context.\n"
    )


def _prune_sc_verify_shard_prompt(text: str) -> str:
    """Remove downstream Phase 5 sub-phases from bounded SC verifier prompts.

    SC V1 prompt groups per-finding verification, skeptic-judge, and
    cross-batch under the same `## Phase 5: Verification` heading.
    Bounded verifier shards must see only per-finding verification;
    Phase 5.1/5.2 belong to later phases.
    """
    cut = re.search(r"(?m)^###?\s+Phase\s+5\.1", text)
    if not cut:
        return text
    return (
        text[:cut.start()].rstrip()
        + "\n\n"
        + "### Out-of-scope instructions intentionally withheld\n\n"
        + "This bounded shard must execute only the selected contract. "
        + "The driver owns every other subprocess boundary with fresh context.\n"
    )


_SC_VERIFY_CONTRACT_HEADINGS: dict[str, str] = {
    "sc_verify_queue": "SC Verify Queue Contract",
    "sc_verify_aggregate": "SC Verify Aggregate Contract",
}


def _select_sc_verify_contract(text: str, phase_name: str) -> str:
    """Keep only the SC verification contract for this phase."""
    heading = _SC_VERIFY_CONTRACT_HEADINGS.get(phase_name)
    if not heading and phase_name in SC_VERIFY_PHASE_NAMES:
        heading = "SC Verify Shard Contract"
    if not heading:
        return text
    m = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not m:
        raise PhasePromptError(
            f"SC verification prompt is missing required section: {heading}"
        )
    next_heading = re.search(r"(?m)^##\s+", text[m.end():])
    end = m.end() + next_heading.start() if next_heading else len(text)
    return text[m.start():end].strip() + "\n"


def _is_sc_verify_phase(config: dict, phase_name: str) -> bool:
    return config.get("pipeline") != "l1" and (
        phase_name == "sc_verify_queue"
        or phase_name == "sc_verify_aggregate"
        or phase_name in SC_VERIFY_PHASE_NAMES
    )


def _sanitize_sc_no_subagent_wrapper(text: str) -> str:
    """Remove generic wrapper child-agent examples from SC verification prompts."""
    text = re.sub(
        r"3\.\s+\*\*Use the Task tool for parallel subagent work\*\*.*?\n\n4\.",
        "3. **Do not create child agents.** Execute the selected verification "
        "contract directly in this phase.\n\n4.",
        text,
        count=1,
        flags=re.DOTALL,
    )
    text = re.sub(
        r"## CONTEXT DELEGATION PROTOCOL .*?(?=\n## RESUMPTION PROTOCOL)",
        "## NO-SUBAGENT CONTEXT POLICY\n\n"
        "This SC verification phase is intentionally direct-execution only. "
        "Read only the files allowed by the selected verification contract and "
        "the Python override. Do not delegate reads or create child agents.\n\n",
        text,
        count=1,
        flags=re.DOTALL,
    )
    text = re.sub(
        r"## RESUMPTION PROTOCOL .*?(?=\n(?:\*\*RETRY EXCEPTION\*\*|## SCIP|## VERIFY|## REPORT|## BREADTH|## INVENTORY|## PRIOR PHASE OUTPUTS))",
        "## RESUMPTION PROTOCOL\n\n"
        "Check whether your assigned output already exists and is complete. "
        "If complete, stop. Otherwise execute the selected verification "
        "contract directly.\n\n",
        text,
        count=1,
        flags=re.DOTALL,
    )
    return text


_OVERRIDE_SELF_CONTAINED_PHASES: frozenset[str] = frozenset({
    "sc_semantic_dedup",
    "semantic_dedup",
    "inventory_prepare",
    "rescan_prepare",
    "inventory_chunk_a",
    "inventory_chunk_b",
    "inventory_chunk_c",
    "inventory",
})
"""Phases whose override directives are fully self-contained AND have no
matching section in the V1 prompt (commands/plamen.md or plamen-l1.md).

When extract_phase_sections would fall back to the full V1 prompt
(marker not found), these phases get a minimal stub instead.
Their phase_cost_directive or phase-specific scope directive already
specifies: inputs, outputs, methodology, and an explicit stop instruction.

NOTE: attention_repair was removed -- it HAS a V1 section (Phase 4b.4)
that extraction finds successfully, providing verdict definitions and
repair priority methodology the override directive alone doesn't cover.
"""


def _is_direct_execution_phase(phase_name: str, pipeline: str,
                               *, backend: str = "") -> bool:
    """Return True for phases that must not receive orchestration guidance.

    The generic wrapper says "use Task" and "delegate large reads"; that is
    correct for orchestration phases such as breadth/depth, but harmful for
    single-agent reducer/formatter phases. Those phases already have a bounded
    input/output contract and should execute directly.

    Codex backend: multi-agent phases (breadth, depth, rescan, recon) use
    spawn_agent for parallel sub-agents and get the CONTEXT DELEGATION
    PROTOCOL (Codex variant). All other Codex phases are direct execution.
    """
    if backend == "codex":
        return phase_name not in CODEX_MULTI_AGENT_PHASES
    if phase_name.startswith("inventory_chunk_"):
        return True
    if phase_name.startswith("report_body_writer_"):
        return True
    if re.match(r"^report_(critical_high|medium|low_info)(?:_[a-z]|_merge)?$", phase_name):
        return True
    direct = {
        "bake",
        "recon",
        "instantiate",
        "inventory_prepare",
        "rescan_prepare",
        "inventory",
        "location_recovery",
        "invariants",
        "invariants_p2",
        "attention_repair",
        "rag_sweep",
        "sc_semantic_dedup",
        "semantic_dedup",
        "chain",
        "chain_agent2",
        "chain_iter2",
        "sc_verify_queue",
        "verify_queue",
        "sc_verify_aggregate",
        "verify_aggregate",
        "post_verify_extract",
        "skeptic",
        "crossbatch",
        "report_index",
        "report_assemble",
    }
    if phase_name in direct:
        return True
    if pipeline != "l1" and phase_name in SC_VERIFY_PHASE_NAMES:
        return True
    if pipeline == "l1" and phase_name in L1_VERIFY_PHASE_NAMES:
        return True
    return False


def _phase_uses_task(phase_name: str, pipeline: str, *, backend: str = "") -> bool:
    """v2.0.3 (A1): True iff the phase's prompt instructs the subprocess to
    spawn parallel agents (Task on Claude, spawn_agent on Codex).

    Backend-aware: signature mirrors _is_direct_execution_phase. The predicate
    is the inverse of direct-execution â€” a phase either runs as a single
    bounded reducer/formatter OR it fans out into parallel sub-agents.
    Multi-agent phases need the PLAMEN V2 EXECUTION CONTRACT injected so
    the LLM cannot orphan its agents via background mode.
    """
    return not _is_direct_execution_phase(phase_name, pipeline, backend=backend)


# v2.0.3 (A1): PLAMEN V2 EXECUTION CONTRACT â€” two backend-specific variants.
# Injected by build_phase_prompt into every Task-using phase prompt. Source
# of truth for the single-turn / no-background / no-wave contract. Markdown
# templates that hand-roll equivalent directives are NOT updated here â€”
# Phase B's source-of-truth audit migrates them to reference these constants.
_PLAMEN_EXECUTION_CONTRACT_CLAUDE = """\
## PLAMEN V2 EXECUTION CONTRACT (MANDATORY -- overrides any conflicting Task tool guidance below)

This subprocess runs in `claude -p` single-turn mode. There is exactly ONE turn.
When you call end_turn (implicit when your message completes), the subprocess
exits and any in-flight background agents are killed without their output
being collected.

Hard rules:

1. **All Task calls MUST be foreground (synchronous).** Do NOT pass
   `run_in_background: true` to any Task invocation. The Claude Code
   documentation describes background mode as a valid option; in V2
   subprocess mode it is FORBIDDEN.

2. **Do NOT plan in "Wave 1 / Wave 2" terms.** You have one wave. If your
   assigned section describes multiple waves, collapse them into a single
   set of parallel Task calls in a single message.

3. **Do NOT end_turn until every spawned Task has returned a result.**
   Emitting a "Waiting for completion" message and then exiting is the
   same as orphaning the agents -- they are killed when the subprocess
   exits.

4. **WRITE-THEN-VERIFY's reservation header is for crash recovery, not
   for background-agent reservation.** A file containing only its header
   (e.g. `# Depth State Trace Findings\\n`) is a stub. The driver's
   substance gate treats it as missing.

5. **Stay inside this phase's expected_artifacts.** The driver will
   quarantine out-of-scope writes and treat them as containment violations.
"""

# Ship 8.8: PTY-aware variant. The default claude exec mode is "pty" -- a
# PERSISTENT interactive session, NOT `claude -p` single-turn. Under PTY the
# driver's supervision loop (Ship 6) may CONTINUE this phase after a turn, and
# completion is derived from disk artifacts (PLAMEN_STATUS markers), never from
# the turn boundary. The single-turn / one-wave / "exiting orphans agents"
# framing of _PLAMEN_EXECUTION_CONTRACT_CLAUDE is FALSE under PTY and actively
# harmful (it pushes the coordinator to emit a premature DONE). This variant
# keeps the still-true rules (foreground Task calls, stay-in-scope, reservation
# header = crash recovery) and adds the disk-derived-completion contract.
_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY = """\
## PLAMEN V2 EXECUTION CONTRACT (MANDATORY -- overrides any conflicting Task tool guidance below)

You are in a PERSISTENT PTY session. This phase is supervised by the driver:
if your turn ends with required artifacts incomplete, the driver may continue
or respawn only the incomplete rows. You are not in the headless single-shot
transport, but you still must finish the phase before emitting DONE.

Completion is DISK-derived, never memory-derived.

Hard rules:

1. **All Task calls MUST be foreground (synchronous).** Do NOT pass
   `run_in_background: true` to any Task invocation. A backgrounded agent whose
   result you never collect leaves its output file as a header-only stub, which
   the driver's substance gate treats as missing.

2. **Before you emit DONE, verify completion against DISK -- not memory.**
   Use this phase's required output list / canonical role list from the prompt
   and confirm EACH required file exists with a final `PLAMEN_STATUS: COMPLETE`
   marker AND contains at least one `Finding [` block (depth findings use the
   `### Finding [DT-1]:` form; breadth uses `## Finding [`) OR a
   `## No Findings` / `## Negative Result` rationale. Grep for the substring
   `Finding [` rather than a specific heading level. The driver's mechanical
   disk gate is authoritative -- if unsure, emit DONE and let the gate decide;
   do NOT read full analysis bodies.

3. **NEVER trust prior chat memory, a status summary, or a compaction summary
   for completion.** If this conversation was auto-compacted, your in-context
   memory of "all agents finished" is unreliable -- re-derive completion from
   disk before emitting DONE. A premature DONE while manifest rows are still
   incomplete is the single failure mode this contract exists to prevent.

4. **WRITE-THEN-VERIFY's reservation header is for crash recovery, not for
   background-agent reservation.** A file containing only its header
   (e.g. `# Depth State Trace Findings\\n`) is a stub. The driver's substance
   gate treats it as missing.

5. **Stay inside this phase's expected_artifacts.** The driver will quarantine
   out-of-scope writes and treat them as containment violations.
"""

_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_UNSUPERVISED = """\
## PLAMEN V2 EXECUTION CONTRACT (MANDATORY -- overrides any conflicting Task tool guidance below)

You are in a PERSISTENT PTY session, not the headless single-shot transport. This
phase is NOT one of the driver's supervised continuation phases, so do not rely
on a future continuation turn to finish missing work. Complete the phase's
required outputs before emitting DONE.

Completion is DISK-derived, never memory-derived.

Hard rules:

1. **All Task calls MUST be foreground (synchronous).** Do NOT pass
   `run_in_background: true` to any Task invocation. A backgrounded agent whose
   result you never collect can leave required output missing while the
   coordinator appears alive.

2. **Before you emit DONE, verify completion against DISK -- not memory.**
   Use this phase's required output list from the prompt and confirm every
   required file exists and satisfies the phase-specific completion contract.
   For marker-based findings artifacts, require a final
   `PLAMEN_STATUS: COMPLETE` marker and either a finding block or a
   no-findings rationale. Use targeted `grep` / file existence checks -- do
   NOT read full analysis bodies.

3. **NEVER trust prior chat memory, a status summary, or a compaction summary
   for completion.** If this conversation was auto-compacted, re-derive
   completion from disk before emitting DONE.

4. **Stay inside this phase's expected_artifacts.** The driver will quarantine
   out-of-scope writes and treat them as containment violations.
"""

_PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_BREADTH = """\
## PLAMEN V2 EXECUTION CONTRACT (MANDATORY -- overrides any conflicting Task tool guidance below)

You are in a PERSISTENT PTY session. This breadth coordinator exists to launch
independent breadth workers, not to analyze the protocol itself.

Completion is DISK-derived, never memory-derived.

Hard rules:

1. **Spawn every missing breadth row immediately as background Task workers.**
   Read `spawn_manifest.md`, derive every missing or stub `analysis_*.md`
   output, then issue ALL corresponding Task calls in one assistant message with
   `run_in_background: true`. Do NOT run a single agent to completion before
   spawning the rest. Do NOT split 7+ rows into waves.

2. **After launching all background workers, keep the coordinator alive and
   collect/monitor them until the disk gate is satisfied.** Background mode is
   allowed here only because the PTY session is persistent and the driver gates
   completion from files. Do NOT emit DONE while any expected output is missing,
   still `IN_PROGRESS`, or header-only.

3. **Before you emit DONE, verify completion against DISK -- not memory.**
   Read `spawn_manifest.md`, derive the expected output file for each row, and
   confirm EACH one exists with a final `PLAMEN_STATUS: COMPLETE` marker AND
   either a `## Finding [` block or a `## No Findings` rationale. Use targeted
   `grep` / file existence checks -- do NOT read full analysis bodies.

4. **NEVER trust prior chat memory, a status summary, or a compaction summary
   for completion.** If this conversation was auto-compacted, your in-context
   memory of "all agents finished" is unreliable -- re-derive completion from
   disk before emitting DONE. A premature DONE while manifest rows are still
   incomplete is the single failure mode this contract exists to prevent.

5. **WRITE-THEN-VERIFY's reservation header is for crash recovery.** A file
   containing only its header is a stub. The driver's substance gate treats it
   as missing until the worker appends findings/no-findings rationale and a
   final `PLAMEN_STATUS: COMPLETE`.

6. **Stay inside this phase's expected_artifacts.** The driver will quarantine
   out-of-scope writes and treat them as containment violations.
"""

_PLAMEN_EXECUTION_CONTRACT_CODEX = """\
## PLAMEN V2 EXECUTION CONTRACT (MANDATORY)

This subprocess runs as a single Codex `exec` invocation. There is exactly ONE
exec. When the exec exits, in-flight `spawn_agent` calls that have not been
collected via `wait_agent` are lost; their output files remain as headers only.

Hard rules:

1. **After every `spawn_agent` call, you MUST eventually call `wait_agent`
   for that agent before exec exits.** Do NOT spawn-and-exit -- the agent
   is killed when the exec exits.

2. **Do NOT plan in waves.** Spawn all parallel work in one block, then
   `wait_agent` on all of them before exit.

3. **WRITE-THEN-VERIFY's reservation header is for crash recovery only.**
   A file containing only its header is a stub. The driver's substance
   gate treats it as missing.

4. **Stay inside this phase's expected_artifacts.** Later-phase writes
   are quarantined as containment violations.
"""


def _render_id_ledger_directive(phase_name: str, scratchpad: Path) -> str:
    """v2.0.6 (P2.3): emit the ID-ledger allocation directive for chain
    phases.

    The directive lists IDs already allocated by upstream phases / prior
    attempts (read from `_id_ledger.json`) and the next-available number
    per prefix. Chain Agent 1 / Agent 2 must:
      - REUSE existing IDs when the grouping has the same root cause.
      - Allocate from the next-available pool for new groupings.
      - NEVER re-mint an existing ID for different content (the driver
        post-phase collision gate hard-fails on this).

    Returns "" when the ledger is empty or the phase is not chain.
    """
    if phase_name not in ("chain", "chain_agent2"):
        return ""
    try:
        from plamen_parsers import (
            id_ledger_all_records, id_ledger_next_available,
        )
    except ImportError:
        return ""
    records = id_ledger_all_records(scratchpad)
    # Chain Agent 1 mints HC/HH/HM/HL/HI/GRP/H- prefixes.
    # Chain Agent 2 mints CH-.
    if phase_name == "chain":
        relevant_prefixes = ("HC-", "HH-", "HM-", "HL-", "HI-", "GRP-", "H-")
    else:  # chain_agent2
        relevant_prefixes = ("CH-",)

    # Allocations relevant for this phase's directive: every record
    # whose ID starts with a relevant prefix (inventory's INV-* are NOT
    # in chain's prefix set, so they don't pollute the directive).
    allocated = [r for r in records
                 if any(r.get("id", "").upper().startswith(p)
                        for p in relevant_prefixes)]
    next_for_prefix = {
        p: id_ledger_next_available(scratchpad, p) for p in relevant_prefixes
    }

    lines = [
        "## ID LEDGER (driver-allocated; STRICT)",
        "",
        "The driver maintains a canonical ID ledger at `_id_ledger.json`. "
        "Every ID minted in this audit is recorded with its allocating phase "
        "and a content hash. The driver runs a BLOCKING post-phase gate that "
        "fails this phase if you re-mint an existing ID with DIFFERENT content.",
        "",
    ]
    if allocated:
        lines.append("### Already-allocated IDs (DO NOT re-mint with different content)")
        lines.append("")
        lines.append("| ID | Owner Phase / Attempt | Title Preview |")
        lines.append("|----|------------------------|----------------|")
        for r in allocated[:200]:  # cap to keep prompt bounded
            fid = r.get("id", "?")
            owner = (
                f"{r.get('owner_phase','?')} / a{r.get('owner_attempt','?')}"
            )
            preview = (r.get("title_preview", "") or "")[:80].replace("|", "\\|")
            lines.append(f"| {fid} | {owner} | {preview} |")
        if len(allocated) > 200:
            lines.append(f"| ... | ... | (+{len(allocated) - 200} more allocations) |")
        lines.append("")
    else:
        lines.append("(No prior allocations in this phase's prefix space.)")
        lines.append("")

    lines.append("### Next-available numbers (use these for NEW groupings)")
    lines.append("")
    for p, nxt in next_for_prefix.items():
        if nxt:
            lines.append(f"- Next `{p}` = `{nxt}`")
    lines.append("")
    lines.extend([
        "### Allocation rules",
        "",
        "1. If your grouping has the SAME root cause as an already-allocated "
        "ID, REUSE that ID (same number, same title scope).",
        "2. If your grouping is NEW, mint the next-available number for the "
        "prefix.",
        "3. NEVER reuse an existing ID for different content. The driver's "
        "post-phase ledger gate will FAIL the phase if you do; the retry "
        "hint will list the offending collisions.",
        "",
    ])
    return "\n".join(lines)


def _derive_claude_exec_mode(config: dict) -> str:
    """Ship 8.8: derive the claude exec mode the same way run_phase does
    (config -> PLAMEN_CLAUDE_EXEC_MODE env -> default "pty"). Returns "pty"
    or "headless". The run_phase binary-name fallback (non-standard claude
    binary -> headless) is intentionally NOT replicated here: it is a
    runtime concern, and the prompt builder defaults to the common case
    (pty). An explicit config / env value always wins.
    """
    explicit = config.get("claude_exec_mode") or os.environ.get(
        "PLAMEN_CLAUDE_EXEC_MODE"
    )
    mode = (explicit or "pty").strip().lower()
    return mode if mode in ("pty", "headless") else "pty"


def _render_execution_contract(phase_name: str, pipeline: str, *,
                                backend: str = "claude",
                                exec_mode: str = "pty") -> str:
    """v2.0.3 (A1): return the PLAMEN V2 EXECUTION CONTRACT block for the
    phase, or "" if the phase is direct-execution (no parallel agents).

    Backend / exec-mode dispatch:
      - Codex -> spawn_agent/wait_agent variant (Codex exec is single-shot).
      - Claude + headless (`claude -p`) -> legacy single-turn variant.
      - Claude + pty (DEFAULT, Ship 8.8) -> PERSISTENT-session variant with
        disk-derived completion; the single-turn / one-wave framing is
        removed because it is false (and harmful) under PTY supervision.
    """
    if not _phase_uses_task(phase_name, pipeline, backend=backend):
        return ""
    if backend == "codex":
        return _PLAMEN_EXECUTION_CONTRACT_CODEX
    if exec_mode == "pty":
        if phase_name == "breadth":
            return _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_BREADTH
        if phase_name == "depth":
            return _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY
        return _PLAMEN_EXECUTION_CONTRACT_CLAUDE_PTY_UNSUPERVISED
    return _PLAMEN_EXECUTION_CONTRACT_CLAUDE


# v2.0.5 (B2): WRITE-THEN-VERIFY sentinel comment. A file containing only
# its header + this sentinel is UNAMBIGUOUSLY a stub. The substance gate
# (`_depth_artifact_is_stub`) treats the sentinel as a definite stub
# marker; legacy audits without the sentinel fall back to existing
# size/shape heuristics.
PLAMEN_STUB_SENTINEL = (
    "<!-- PLAMEN-STUB: header-only reservation, content to follow -->"
)


def _render_reservation_header(title: str) -> str:
    """v2.0.5 (B2): generate the canonical WRITE-THEN-VERIFY reservation
    header that subagents write as their FIRST ACTION. The PLAMEN-STUB
    sentinel makes the header-only state unambiguous to the driver's
    substance gate.

    Source-of-truth for all reservation injection sites. Markdown
    templates that hand-roll the header should be migrated to reference
    this function (B2 prompt audit). Backward-compatible: legacy files
    without the sentinel are still classified by the existing size/shape
    heuristic in `_depth_artifact_is_stub`.
    """
    return f"# {title}\n{PLAMEN_STUB_SENTINEL}\n"



_STANDALONE_V2_DIR = plamen_home() / "prompts" / "shared" / "v2"

_STANDALONE_PROMPT_MAP: dict[str, str] = {
    # Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬ Phase families: shared methodology files Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬
    # Verification (SC)
    "sc_verify_queue": "phase5-verification-sc.md",
    "sc_verify_crithigh": "phase5-verification-sc.md",
    "sc_verify_high_b": "phase5-verification-sc.md",
    "sc_verify_high_c": "phase5-verification-sc.md",
    "sc_verify_high_d": "phase5-verification-sc.md",
    "sc_verify_high_e": "phase5-verification-sc.md",
    "sc_verify_high_f": "phase5-verification-sc.md",
    "sc_verify_high_g": "phase5-verification-sc.md",
    "sc_verify_high_h": "phase5-verification-sc.md",
    "sc_verify_high_i": "phase5-verification-sc.md",
    "sc_verify_high_j": "phase5-verification-sc.md",
    "sc_verify_medium_a": "phase5-verification-sc.md",
    "sc_verify_medium_b": "phase5-verification-sc.md",
    "sc_verify_medium_c": "phase5-verification-sc.md",
    "sc_verify_medium_d": "phase5-verification-sc.md",
    "sc_verify_medium_e": "phase5-verification-sc.md",
    "sc_verify_medium_f": "phase5-verification-sc.md",
    "sc_verify_medium_g": "phase5-verification-sc.md",
    "sc_verify_medium_h": "phase5-verification-sc.md",
    "sc_verify_medium_i": "phase5-verification-sc.md",
    "sc_verify_medium_j": "phase5-verification-sc.md",
    "sc_verify_low_a": "phase5-verification-sc.md",
    "sc_verify_low_b": "phase5-verification-sc.md",
    "sc_verify_low_c": "phase5-verification-sc.md",
    "sc_verify_low_d": "phase5-verification-sc.md",
    "sc_verify_low_e": "phase5-verification-sc.md",
    "sc_verify_low_f": "phase5-verification-sc.md",
    "sc_verify_low_g": "phase5-verification-sc.md",
    "sc_verify_low_h": "phase5-verification-sc.md",
    "sc_verify_low_i": "phase5-verification-sc.md",
    "sc_verify_low_j": "phase5-verification-sc.md",
    "sc_verify_aggregate": "phase5-verification-sc.md",
    # Verification (L1)
    "verify_queue": "phase5-verification-l1.md",
    "verify_crithigh": "phase5-verification-l1.md",
    "verify_high_b": "phase5-verification-l1.md",
    "verify_high_c": "phase5-verification-l1.md",
    "verify_high_d": "phase5-verification-l1.md",
    "verify_high_e": "phase5-verification-l1.md",
    "verify_high_f": "phase5-verification-l1.md",
    "verify_high_g": "phase5-verification-l1.md",
    "verify_high_h": "phase5-verification-l1.md",
    "verify_high_i": "phase5-verification-l1.md",
    "verify_high_j": "phase5-verification-l1.md",
    "verify_medium_a": "phase5-verification-l1.md",
    "verify_medium_b": "phase5-verification-l1.md",
    "verify_medium_c": "phase5-verification-l1.md",
    "verify_medium_d": "phase5-verification-l1.md",
    "verify_medium_e": "phase5-verification-l1.md",
    "verify_medium_f": "phase5-verification-l1.md",
    "verify_low_a": "phase5-verification-l1.md",
    "verify_low_b": "phase5-verification-l1.md",
    "verify_low_c": "phase5-verification-l1.md",
    "verify_low_d": "phase5-verification-l1.md",
    "verify_aggregate": "phase5-verify-aggregate-l1.md",
    # Inventory family (SC + L1)
    "inventory_prepare": "phase4a-inventory-base.md",
    "inventory_chunk_a": "phase4a-inventory-base.md",
    "inventory_chunk_b": "phase4a-inventory-base.md",
    "inventory_chunk_c": "phase4a-inventory-base.md",
    "inventory": "phase4a-inventory-base.md",
    "location_recovery": "phase4a-inventory-base.md",
    # Report tier-writers (SC + L1)
    "report_body_writer_critical_high": "phase6b-tier-writers.md",
    "report_body_writer_medium": "phase6b-tier-writers.md",
    "report_body_writer_low_info": "phase6b-tier-writers.md",
    "report_critical_high": "phase6b-tier-writers.md",
    "report_critical_high_merge": "phase6b-tier-writers.md",
    "report_medium": "phase6b-tier-writers.md",
    "report_medium_merge": "phase6b-tier-writers.md",
    "report_low_info": "phase6b-tier-writers.md",
    "report_low_info_merge": "phase6b-tier-writers.md",

    # Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬ Individual phase standalones Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬
    "instantiate": "phase2-instantiate.md",
    "breadth": "phase3-breadth.md",
    # rescan_prepare is mechanical (driver writes rescan_manifest.md). Mapped
    # for completeness only; it is also in _OVERRIDE_SELF_CONTAINED_PHASES, so
    # if ever spawned it receives a DRIVER-CONTRACT-ERROR stub, not this body.
    "rescan_prepare": "phase3b-rescan.md",
    "rescan": "phase3b-rescan.md",
    "depth": "phase4b-depth.md",
    "attention_repair": "phase4b4-attention-repair.md",
    "invariants": "phase4a5-invariants.md",
    # v2.8.8: Pass 2 recursive gap trace. V1 ran this in Thorough but the
    # V1â†’V2 refactor dropped the phase definition while leaving the prompt
    # and mode-matrix references intact. Wiring it now via a standalone
    # phase entry (see SC_PHASES / L1_PHASES `invariants_p2`).
    "invariants_p2": "phase4a5-invariants-p2.md",
    "rag_sweep": "phase4b5-rag-sweep.md",
    "exploration_skeptic": "phase4b6-exploration-skeptic.md",
    "enumgap_exploration": "phase4b7-enumgap-exploration.md",
    # Phase 4b.8 Multi-Axis Coverage Meta-Pass (M2). Deriver-worker prompt handed
    # ONLY the GAP rows the driver mechanically computed; strictly additive.
    "axis_coverage": "phase4b8-axis-coverage.md",
    # sc_semantic_dedup and semantic_dedup: NOT mapped here.
    # Their cost directives point the agent to read phase4e-semantic-dedup.md
    # directly. Loading it as body would leak cross-pipeline artifacts.
    # Both use _OVERRIDE_SELF_CONTAINED_PHASES instead.
    "chain": "phase4c-chain-agent1.md",
    "chain_agent2": "phase4c-chain-agent2.md",
    # v2.8.8: Iteration 2 cross-class composition. Same V1â†’V2 wiring gap
    # class as invariants_p2: prompt file existed at this path but no
    # Phase entry consumed it. Driver pre-check (skip if 0 unexplored
    # cross-class Medium+ pairs) runs before LLM spawn.
    "chain_iter2": "phase4c-chain-iter2.md",
    # v2.8.8: Phase 5.5 post-verification extraction. Same V1â†’V2 wiring
    # gap. The documentation at commands/plamen.md:1224 describes
    # scanning verify_*.md for [VER-NEW-*] observations; no driver
    # phase consumed it. Sonnet, Thorough-only, soft phase.
    "post_verify_extract": "phase5_5-post-verify-extract.md",
    "skeptic": "phase5-skeptic.md",
    "crossbatch": "phase5-crossbatch.md",
    "report_index": "phase6a-report-index.md",
    "report_assemble": "phase6c-assembler.md",
    # Phase 6d LLM consolidation proposer — reads the assembled report and
    # proposes cross-tier/no-location MERGES + QO reclassifications. Real LLM
    # phase (NOT short-circuited); writes report_dedup_agent_decisions.md only.
    "report_dedup_agent": "phase6d-report-dedup-agent.md",
    # Phase 6d cross-tier report dedup — Python-native; stub prompt exists so
    # build_phase_prompt doesn't crash. Driver short-circuits this phase to
    # plamen_mechanical._dedup_report_python(). critical=False; never halts.
    "report_dedup": "phase6d-report-dedup.md",
    # Phase 6e material-harm disposition — REAL LLM phase (NOT short-circuited).
    # Reads the final deduped AUDIT_REPORT.md and writes disposition.md
    # (BODY/APPENDIX per finding). critical=False; the floor phase below has a
    # keyword-classifier fallback if this produces nothing usable.
    "report_disposition": "phase6e-disposition.md",
    # Phase 6e material-harm floor — Python-native; stub prompt exists so
    # build_phase_prompt doesn't crash. Driver short-circuits this phase to
    # plamen_mechanical.apply_material_harm_floor(). critical=False; FINAL
    # report mutation; never halts.
    "report_floor": "phase6e-floor.md",
    # Phase 5b mechanical PoC verification â€” Python-native; stub prompt
    # exists so build_phase_prompt doesn't crash. Driver short-circuits
    # this phase to mechanical_verify.run_phase5b_mechanical_verify().
    "sc_mechanical_verify": "phase5b-mechanical-verify.md",
    "mechanical_verify": "phase5b-mechanical-verify.md",

    # Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬ Supplementary (depth sub-agents read these directly) Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬
    "scoring": "phase4b-scoring.md",
    "variable_map": "phase4b-variable-map.md",
    "perturbation": "phase4b-perturbation.md",
    "skill_checklist": "phase4b-skill-checklist.md",
    "rescore": "phase4b-rescore.md",
    "final_scoring": "phase4b-final-scoring.md",
}
"""Complete phase-name Ã¢â€ ' standalone-prompt mapping (v2.5.0).

Architecture: standalone-first. When a standalone file exists for a phase,
it is used as the PRIMARY methodology source. V1 section extraction is the
FALLBACK for phases not yet migrated (recon, bake, graph_sweeps).

This decouples the runtime pipeline from the monolithic V1 prompt files
(plamen.md, plamen-l1.md). V1 heading renames no longer break phases.
The cost_directive provides phase-specific scoping on top of the shared
standalone methodology.
"""


def _resolve_recon_prompt(config: dict) -> Optional[Path]:
    """Return the concrete language-specific recon prompt for this pipeline."""
    pipeline = config.get("pipeline", "sc")
    language = (config.get("language") or "evm").strip().lower()
    base = plamen_home() / "prompts"
    prompt_dir = base / ("l1" if pipeline == "l1" else language)
    # Ship 8.14: prefer the V2 single-agent direct-execution recon prompt over
    # the legacy multi-agent orchestrator prompt. The legacy prompt spawns
    # Agent 1A/1B/2; under the V2 foreground-Task contract those run SERIALLY
    # (observed: 1A 4min -> 1B 6min -> Slither 32min -> 3000s timeout -> rc=-2
    # truncated recon_summary -> gate fail). The v2 prompt does the same work
    # in one context with a DRAFT-FIRST budget. Legacy stays a fallback for any
    # language that ships only the legacy file.
    for candidate in (
        prompt_dir / "v2" / "phase1-recon-prompt.md",
        prompt_dir / "phase1-recon-prompt.md",
    ):
        if candidate.exists():
            return candidate
    return None


def _sanitize_recon_prompt_contract(text: str) -> str:
    """Remove obsolete placeholder/stub examples from recon prompts.

    Recon gates reject placeholder handoffs. Older language prompts still
    described "minimum valid stubs" with `[LLM TO ENRICH]`, creating a direct
    prompt-vs-gate contradiction. Keep write-early resilience, but make early
    writes substantive drafts that remain legal if timeout hits.
    """
    text = re.sub(r"(?i)stub-first", "draft-first", text)
    text = re.sub(r"(?i)\bstubs\b", "drafts", text)
    text = re.sub(r"(?i)\bstub\b", "draft", text)
    text = text.replace("[LLM TO ENRICH]", "best-known findings so far")
    text = text.replace("[LLM TO LIST]", "best-known skill list")
    text = text.replace("{TBD}", "best-known target")
    text = re.sub(
        r"(?i)deferred during enrichment",
        "explicitly unavailable after bounded inspection",
        text,
    )
    # Ship 8.14: the recon TURN BUDGET POLICY names `claude -p`, which is false
    # under the default PTY transport (a persistent session, not headless
    # single-turn). Keep the valuable DRAFT-FIRST guidance; make the transport
    # reference neutral so the rendered prompt carries no stale `claude -p`
    # framing (codex adjustment 3).
    text = text.replace("inside `claude -p`", "inside a bounded subprocess")
    return text


def _render_recon_handoff_directive(phase: Phase) -> str:
    """Render the non-negotiable recon artifact contract."""
    required = "\n".join(f"- `{name}`" for name in phase.expected_artifacts)
    return f"""
## RECON CLEAN HANDOFF CONTRACT (MANDATORY)

This phase may coordinate recon workers, but the final handoff is not optional
and not a placeholder exercise.

Before any long-running research, MCP/RAG probe, broad source sweep, or
large-file read, ensure every required recon artifact exists with a
substantive draft. A substantive draft may say `UNAVAILABLE` or `NOT DETECTED`
with the reason; it must not contain placeholder tokens.

Required recon artifacts:
{required}

Finalization rules:
1. Treat mechanical pre-pass files as seeds. You may overwrite or enrich any
   recon artifact seeded by pre-pass if the result is more accurate.
2. `detected_patterns.md`, `setter_list.md`, and `emit_list.md` are first-class
   required outputs, not optional appendix files.
3. `build_status.md` must record attempted build/static-analysis commands or
   the explicit reason they were unavailable/skipped.
4. `recon_summary.md` must be a clean downstream handoff: target, language,
   scope, key components, detected patterns, risk themes, selected templates,
   and produced artifact list.
5. Do not leave `TODO`, `TBD`, `[LLM TO ...]`, placeholder text, or draft-only
   markers in any required recon artifact.
6. If time is nearly exhausted, stop exploration and refresh these exact files
   with the best real content available before returning.
"""


def _resolve_standalone_prompt(phase_name: str) -> Optional[Path]:
    """Find a standalone prompt file for the given phase.

    Returns the Path if found and readable, None otherwise.
    Uses explicit mapping first, then a glob-based heuristic for phases
    that follow the naming convention (phase_name contains a recognizable
    fragment of the filename).
    """
    # 1. Explicit mapping -- most reliable
    if phase_name in _STANDALONE_PROMPT_MAP:
        candidate = _STANDALONE_V2_DIR / _STANDALONE_PROMPT_MAP[phase_name]
        if candidate.exists():
            return candidate
    if re.match(r"^report_body_writer_(critical_high|medium|low_info)_[a-z]$", phase_name):
        candidate = _STANDALONE_V2_DIR / "phase6b-tier-writers.md"
        if candidate.exists():
            return candidate
    if re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase_name):
        candidate = _STANDALONE_V2_DIR / "phase6b-tier-writers.md"
        if candidate.exists():
            return candidate

    # 2. Heuristic: strip common prefixes and look for filename match
    # This is intentionally conservative -- only exact substring matches
    if not _STANDALONE_V2_DIR.exists():
        return None

    # Strip pipeline prefix (removeprefix, not lstrip which strips chars)
    normalized = phase_name
    for prefix in ("sc_", "l1_"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    normalized = normalized.replace("_", "-")

    for f in _STANDALONE_V2_DIR.iterdir():
        if f.suffix == ".md" and normalized in f.stem:
            return f

    return None


def _render_runtime_placeholders(text: str, config: dict) -> str:
    """Replace runtime placeholders while leaving schema exemplars intact.

    Handles both uppercase (V1 convention) and lowercase (L1 recon convention)
    placeholder styles so downstream models don't see literal {path}/{scratchpad}.
    """
    scratchpad = str(config.get("scratchpad", ""))
    project_root = str(config.get("project_root", ""))
    docs_path = str(config.get("docs_path", "") or "(none)")
    scope_file = str(config.get("scope_file", "") or "(none)")
    # Ship 8.14: recon prompts reference {network_if_provided} and
    # {scope_notes_if_provided}; without these the literal placeholder tokens
    # leaked into the rendered prompt (codex adjustment 3).
    network = str(config.get("network", "") or "(none)")
    scope_notes = str(config.get("scope_notes", "") or "(none)")

    replacements = {
        # Uppercase (V1 convention â€” used by most prompts)
        "{SCRATCHPAD}": scratchpad,
        "{PROJECT_ROOT}": project_root,
        "{PROJECT_PATH}": project_root,
        "{LANGUAGE}": str(config.get("language", "")),
        "{MODE}": str(config.get("mode", "")),
        "{PIPELINE}": str(config.get("pipeline", "")),
        # Lowercase (L1 recon convention)
        "{scratchpad}": scratchpad,
        "{path}": project_root,
        "{docs_path_or_url_if_provided}": docs_path,
        "{scope_file_if_provided}": scope_file,
        "{network_if_provided}": network,
        "{scope_notes_if_provided}": scope_notes,
        # Installation root (Codex portability)
        "{PLAMEN_BASE}": plamen_home().as_posix(),
        "{plamen_base}": plamen_home().as_posix(),
    }
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    return text


_FOREIGN_SUBSECTION_CUTS: dict[str, list[str]] = {
    "breadth": [
        r"###\s+Phase\s+3b",
    ],
    "inventory_prepare": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
        r"###\s+Phase\s+4b\.4",
        r"###\s+Phase\s+4b\.5",
    ],
    "inventory_chunk_a": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
    ],
    "inventory_chunk_b": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
    ],
    "inventory_chunk_c": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
    ],
    "inventory": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
    ],
    "chain": [
        r"###\s+Phase\s+4a\.5",
        r"###\s+Phase\s+4b",
    ],
    "depth": [
        r"##\s+Phase\s+4b\.5\b",
        r"##\s+Phase\s+4c\b",
        r"##\s+Phase\s+5\b",
        r"##\s+Phase\s+6\b",
        r"##\s+Step\s+4c\b",
        r"##\s+Step\s+4d\b",
        r"##\s+Step\s+5\b",
        r"##\s+Step\s+6\b",
    ],
}

# Phases whose extraction should have the Phase 4 routing table stripped.
# The table lists ALL pipeline steps with prompt file paths -- useful for the
# V1 orchestrator but pure noise for isolated V2 subprocesses.
_STRIP_ROUTING_TABLE_PHASES: frozenset[str] = frozenset({
    "inventory_prepare", "inventory_chunk_a", "inventory_chunk_b",
    "inventory_chunk_c", "inventory", "chain",
})


def _strip_foreign_subsections(text: str, phase_name: str) -> str:
    """Remove subsections belonging to OTHER V2 phases from extracted text.

    When extract_phase_sections extracts a broad section (e.g., ## Phase 3
    which includes ### Phase 3b as a nested subsection), the subprocess sees
    instructions for later phases. This function cuts at the first foreign
    subsection heading, preserving only the content the phase actually needs.
    """
    patterns = _FOREIGN_SUBSECTION_CUTS.get(phase_name)
    if patterns:
        earliest_cut = len(text)
        for pat in patterns:
            m = re.search(rf"(?m)^{pat}", text)
            if m and m.start() < earliest_cut:
                earliest_cut = m.start()
        if earliest_cut < len(text):
            text = text[:earliest_cut].rstrip() + "\n"
    # Strip the Phase 4 routing table for phases that don't need it.
    if phase_name in _STRIP_ROUTING_TABLE_PHASES:
        text = re.sub(
            r"\*\*Read prompts from the corresponding phase file:\*\*"
            r"\s*\n\s*\|.*?\n(?:\s*\|.*?\n)*",
            "",
            text,
        )
    return text


def _sanitize_depth_forward_refs(text: str) -> str:
    """Strip forward-execution instructions from the depth phase extraction.

    The depth section contains inline phrases like "proceed directly to
    Phase 4c chain analysis" and "After Phase 5, if verifiers returned..."
    that could cause the subprocess to spawn chain/verify agents. These are
    replaced with phase-neutral language or removed entirely.
    """
    # Light mode: "proceed directly to Phase 4c chain analysis (single merged
    # agent per override #6)" -> stop after depth
    text = re.sub(
        r"proceed directly to Phase 4c chain analysis"
        r"\s*\([^)]*\)\s*\.?",
        "STOP after completing this phase-owned work.",
        text,
    )
    # Core mode: "proceed to chain analysis and verification as-is"
    text = re.sub(
        r"[Pp]roceed to chain analysis and verification as-is\.?",
        "depth phase complete for these findings.",
        text,
    )
    # Remove any post-verification feedback section. Depth subprocesses have
    # no Phase 5 outputs and must not spawn after verifier results.
    text = re.sub(
        r"(?ms)^##\s+Post-Verification Error Trace Feedback\b.*?"
        r"(?=^##\s+|\Z)",
        "",
        text,
    )
    # V1-style numbered item variant.
    text = re.sub(
        r"(?m)^5\.\s+\*\*Post-verification error trace feedback\*\*.*$",
        "5. *(Feedback handling is outside this subprocess.)*",
        text,
    )
    text = re.sub(
        r"(?ms)^##\s+Phase\s+4b\.5\s*:\s+RAG\s+Validation\s+Sweep\b.*?(?=^##\s+|\Z)",
        "",
        text,
    )
    text = re.sub(
        r"(?i)Spawn\s+a\s+depth\s+agent\s+and\s+RAG\s+deep\s+search\s+during\s+the\s+depth\s+loop",
        "Spawn a depth agent for more code evidence during the depth loop",
        text,
    )
    text = re.sub(
        r"(?i)RAG\s+deep\s+search\s+during\s+the\s+depth\s+loop",
        "record additional-search-needed inside depth-owned outputs",
        text,
    )
    text = re.sub(
        r"(?i);\s*flag\s+for\s+later\s+verification",
        "; record follow-up-needed inside depth-owned outputs",
        text,
    )
    text = re.sub(
        r"(?im)^\s*goto\s+Phase\s+4c\s*$",
        "return from the depth subprocess",
        text,
    )
    text = re.sub(
        r"(?i)cannot\s+proceed\s+to\s+Phase\s+4c",
        "cannot mark depth complete",
        text,
    )
    text = re.sub(
        r"(?i)proceed\s+to\s+Phase\s+4c",
        "return from the depth subprocess",
        text,
    )
    return text


_NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|forbid|forbidden|not\s+execute|"
    r"not\s+write|not\s+run|skip|separate\s+phase|later\s+phase|"
    r"future\s+subprocess|record\s+.*needed|read-only|read\s+only)\b",
    re.IGNORECASE,
)

_PHASE_PROMPT_FORBIDDEN_TOKENS: dict[str, tuple[str, ...]] = {
    "depth": (
        "Phase 4b.5", "Phase 4c", "Phase 5", "Phase 6",
        "RAG Validation Sweep", "rag_validation.md",
        "chain_summaries_compact.md", "hypotheses.md", "finding_mapping.md",
        "enabler_results.md", "chain_hypotheses.md",
        "composition_coverage.md", "synthesis_full.md",
        "verification_queue.md", "verify_*.md", "verify_H", "verify_CH",
        "report_index.md", "AUDIT_REPORT.md",
    ),
    "breadth": (
        "Phase 3b", "analysis_rescan_", "analysis_percontract_",
        "findings_inventory.md", "depth_*_findings.md",
        "rag_validation.md", "hypotheses.md", "verification_queue.md",
        "verify_*.md", "report_index.md", "AUDIT_REPORT.md",
    ),
}


def _find_prompt_phase_boundary_violations(prompt_text: str, phase_name: str) -> list[str]:
    """Return executable-looking future-phase tokens in a rendered prompt.

    Negative-scope lines are allowed because the wrapper must tell the model
    what not to do. Positive references to downstream phase names or artifacts
    are blocked before the subprocess starts; runtime containment is only the
    backstop.
    """
    tokens = _PHASE_PROMPT_FORBIDDEN_TOKENS.get(phase_name)
    if not tokens:
        return []
    violations: list[str] = []
    for lineno, line in enumerate(prompt_text.splitlines(), 1):
        if _NEGATIVE_SCOPE_RE.search(line):
            continue
        for token in tokens:
            if token in line:
                violations.append(f"line {lineno}: {token}: {line.strip()[:160]}")
                break
    return violations


def _sanitize_breadth_forward_refs(text: str) -> str:
    """Remove executable post-breadth work from breadth prompts.

    Breadth owns only manifest-derived `analysis_<focus>.md` artifacts. Later
    discovery-expansion phases have their own subprocesses and must not appear
    as runnable work in the breadth prompt.
    """
    text = re.sub(
        r"(?ms)^#{2,4}\s+Phase\s+3b\b.*?(?=^#{2,4}\s+|\Z)",
        "",
        text,
    )
    text = re.sub(
        r"(?im)^.*(?:Breadth\s+Re-Scan|phase3b-rescan-prompt\.md|analysis_rescan_|analysis_percontract_).*$\n?",
        "",
        text,
    )
    return text


def _render_forbidden_output_block(phase_name: str) -> str:
    """Render model-facing output scope without leaking other phase names."""
    allowlist_blocks = {
        "recon": """## OUTPUT ALLOWLIST (HARD)

Your allowed output files are exactly the recon files listed in this phase's
Expected Output Contract. Do not infer, invent, pre-fill, or create any other
scratchpad artifact. Template recommendations are written only inside
`template_recommendations.md`; do not create a separate roster, manifest, or
coordination artifact.
""",
        "breadth": """## OUTPUT ALLOWLIST (HARD)

Your allowed output files are exactly the breadth files named in
`spawn_manifest.md` for rows assigned to this subprocess. Do not infer,
invent, or create any other scratchpad artifact. If a methodology note asks
for an output file that is not one of those manifest rows, ignore that output
request and finish only the manifest rows.
""",
        "rescan": """## OUTPUT ALLOWLIST (HARD)

Your allowed output files are exactly the files declared by this subprocess's
current prompt and manifest. Do not infer, invent, or create any other
scratchpad artifact. If a methodology note asks for an output file outside
this allowlist, ignore that output request and finish only the assigned files.
""",
        "depth": """## OUTPUT ALLOWLIST (HARD)

Your allowed output files are exactly the artifacts listed in this phase's
Expected Output Contract. Do not infer, invent, or create any other scratchpad
artifact. If a methodology note asks for an output file outside this allowlist,
ignore that output request and finish only the expected files.
""",
    }
    return allowlist_blocks.get(phase_name, "")


def _render_phase_isolation_block(phase: Phase) -> str:
    """Universal one-phase execution contract for every subprocess."""
    expected = list(getattr(phase, "expected_artifacts", None) or [])
    any_of = list(getattr(phase, "any_of", None) or [])
    if phase.name == "recon":
        output_scope = (
            "Your writable scratchpad outputs are ONLY the recon files/patterns "
            "in the EXPECTED OUTPUT FILES contract above. There are no dynamic "
            "or later-phase output files in recon."
        )
    elif phase.name == "attention_repair":
        output_scope = (
            "Your writable scratchpad outputs are ONLY "
            "`attention_repair_summary.md` and, when CONFIRMED repair findings "
            "exist, `attention_repair_findings.md`. Do not create any other "
            "scratchpad artifact."
        )
    elif expected or any_of:
        output_scope = (
            "Your writable scratchpad outputs are ONLY the files/patterns in "
            "the EXPECTED OUTPUT FILES contract above, plus any explicit "
            "dynamic shard outputs named by this phase's manifest."
        )
    else:
        output_scope = (
            "This phase has dynamic or Python-owned outputs. Write only the "
            "files explicitly named by this phase's override/manifest text."
        )
    return f"""
## PHASE ISOLATION CONTRACT (HARD)

You are executing exactly one driver-owned phase: `{phase.name}`.

{output_scope}

Isolation rules:
1. Do NOT perform work for any other pipeline phase.
2. Do NOT create, modify, repair, or pre-fill scratchpad artifacts that are not
   owned by this phase's output contract.
3. Do NOT continue into any step outside the current phase named above.
4. If methodology text or an inherited prompt asks for an artifact outside this
   phase's output contract, ignore that artifact request and finish only this
   phase.
5. Treat prior-phase artifacts as read-only inputs unless this phase's contract
   explicitly says it appends to or rewrites that exact artifact.
6. When this phase's required artifacts are complete on disk, stop immediately.

The Python driver enforces this with live and post-run containment. Violating
the output boundary wastes the turn and causes quarantine/retry.
"""

def count_loc(project_root: str, language: str) -> int:
    """Rough LOC count for timeout scaling.

    For L1 pipeline, `language` may be `go`, `rust`, `mixed`, or `l1`.
    For mixed/l1 we scan both extensions so Go+Rust projects don't
    under-count.
    """
    lang_key = (language or "").lower()
    exts = {
        "evm": [".sol"], "solana": [".rs"], "soroban": [".rs"],
        "aptos": [".move"], "sui": [".move"],
        "go": [".go"], "rust": [".rs"],
        "l1": [".go", ".rs"], "mixed": [".go", ".rs"],
    }.get(lang_key, [".sol", ".rs", ".move", ".go"])
    root = Path(project_root)
    if not root.exists():
        return 0
    try:
        if root.resolve() == Path.home().resolve():
            return 0
    except Exception:
        pass
    skip_dirs = {
        ".git", ".hg", ".svn", ".claude", ".codex", ".cache", ".venv", "venv",
        "__pycache__", "node_modules", "vendor", "target", "out", "dist",
        "build", "coverage", ".pytest_cache", ".mypy_cache",
        "custom-mcp", "mcp-packages", "pipeline_audit_20260506-103601",
    }
    ext_set = set(exts)
    total = 0
    files_seen = 0
    # Use os.walk so we can prune directories before descending. Path.rglob()
    # over a home directory or large workspace can burn minutes before the first
    # timeout is even computed.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs
            and not d.startswith(".")
            and not d.startswith("pipeline_audit_")
            and not d.startswith("pipeline_audit_iter_")
        ]
        for name in filenames:
            if Path(name).suffix not in ext_set:
                continue
            files_seen += 1
            p = Path(dirpath) / name
            try:
                with p.open("r", encoding="utf-8", errors="replace") as f:
                    total += sum(1 for _ in f)
            except Exception:
                pass
            if total > 500_000 or files_seen > 5_000:
                return total
    return total


def scale_timeout(
    base: int,
    project_root: str,
    language: str,
    ceiling: int = 14400,
    mode: Optional[str] = None,
    hypothesis_count: int = 0,
    backend: str = "",
) -> int:
    """Scale phase timeout by LOC and hypothesis count.

    v2.3.6 I1: ceiling is now mode-aware. Thorough mode runs 3 depth
    iterations with up to 100 agents and reasonably needs 2-3x the
    Light/Core ceiling on large repos. Pre-v2.3.6 the hard 5400s ceiling
    silently capped Thorough budget -- explained the depth-phase timeouts
    on a large L1 run (50K+ LOC Rust monorepo).

    v2.4.1: hypothesis_count adds +90s per hypothesis above 8 for verify
    shard phases. The old 2700s monolithic verify could handle ~32
    hypotheses; sharding gives each severity tier its own budget, but
    a shard with 20+ rows still needs proportionally more time.

    v2.6.1-codex: backend="codex" applies 3x multiplier (capped at
    effective_ceiling). Codex runs multi-agent phases sequentially in a
    single model turn â€” work that Claude Code parallelises via Task tool
    takes ~3x wall-clock on Codex.
    """
    try:
        loc = count_loc(project_root, language)
    except Exception:
        loc = 0
    extra_loc = max(0, (loc - 5000) // 1000)
    extra_hyp = max(0, hypothesis_count - 8) * 90
    effective_ceiling = ceiling
    if mode == "thorough":
        effective_ceiling = min(ceiling * 2, 14400)  # cap at 4 hours (matches validator)
    if backend == "codex":
        effective_ceiling = min(effective_ceiling * 3, 21600)  # 6 hours max
    scaled = min(base + extra_loc * 60 + extra_hyp, effective_ceiling)
    if backend == "codex":
        scaled = min(scaled * 3, effective_ceiling)
    return scaled


def _render_expected_output_block(
    phase: Phase, scratchpad: Optional[Path] = None
) -> str:
    """Render `phase.expected_artifacts` as a producer contract for the LLM.

    SINGLE SOURCE OF TRUTH: the patterns the gate checks (gate_passes) and the
    names the producing LLM is told to write are derived from the same
    `phase.expected_artifacts` (and `phase.any_of`) fields. This prevents the
    Track B class of bug: the producer writes `findings_breadth_*.md` while the
    gate globs `analysis_*.md`, so the gate silently fails (or the LLM picks a
    new name on retry).

    Rules:
    - Literal filename (no `*`): instruct "write to this exact filename."
    - Glob (`prefix_*_suffix.md` or `prefix_*.md`): instruct "replace `*` with
      a per-agent / per-shard token. Example: prefix_01.md, prefix_02.md, ...".
    - `any_of` groups: render as OR-sets -- any one pattern per group satisfies.
    - `min_artifacts_count > 1`: spell out the minimum file count explicitly.

    Phases with both empty `expected_artifacts` and empty `any_of` return "".
    (These phases -- e.g. L1 verify_crithigh -- derive their output names from
    the verification queue manifest at runtime; their producer contract is
    emitted elsewhere.)
    """
    expected = list(phase.expected_artifacts or [])
    any_of_groups = list(getattr(phase, "any_of", []) or [])
    if not expected and not any_of_groups:
        return ""

    # T2-4 (SW19): state the gate's ACTUAL minimum, not a hardcoded 200. The
    # gate uses `phase.min_artifact_bytes` (100 default; 50 for instantiate;
    # halved again for Codex). Stating the true floor stops the contract from
    # claiming a threshold the gate does not enforce.
    _min_b = getattr(phase, "min_artifact_bytes", 100)

    tokens = list(getattr(phase, "example_tokens", []) or [])

    def _glob_example(pattern: str) -> str:
        # v2.1.4: prefer phase.example_tokens when set. Phase-authoritative
        # tokens prevent the Class-A drift observed when auto-generated
        # numeric examples contradicted the intended convention (e.g. depth
        # agents using role names like `token_flow`, not shard indices).
        # Per LLM instruction-following research, examples dominate prose --
        # accurate examples are the single highest-leverage anti-drift lever.
        if "*" not in pattern:
            return ""
        if tokens:
            shown = tokens[:4]
            examples = ", ".join(
                f"`{pattern.replace('*', t, 1)}`" for t in shown
            )
            suffix = ", ..." if len(tokens) > 4 else ""
            return examples + suffix
        # Numeric-shard fallback for phases where shard indexing is the
        # intended convention (breadth, rescan, and any glob where a per-
        # agent numeric token is authoritative).
        ex1 = pattern.replace("*", "01", 1)
        ex2 = pattern.replace("*", "02", 1)
        ex3 = pattern.replace("*", "03", 1)
        return f"`{ex1}`, `{ex2}`, `{ex3}`, ..."

    lines = []
    lines.append("## EXPECTED OUTPUT FILES (HARD CONTRACT -- GATE WILL FAIL IF VIOLATED)")
    lines.append("")
    lines.append(
        "The Python driver's phase gate globs the scratchpad AFTER your subprocess "
        "exits and verifies that files matching the patterns below exist with "
        f"substantial content (>= {_min_b} bytes). **Files written under "
        "any OTHER name are invisible to the gate and will be treated as missing, "
        "causing a retry or degrade even if the content is correct.** The patterns "
        "below are the single source of truth -- they match the driver's internal "
        "`phase.expected_artifacts` for this phase."
    )
    lines.append("")
    lines.append(
        "You (and every Task subagent you spawn) MUST write to filenames that "
        "match the patterns below. Do NOT invent alternate names like "
        "`findings_breadth_*.md`, `breadth_findings.md`, "
        "`output.md`, etc. -- those will silently fail the gate."
    )
    lines.append("")

    if phase.name == "breadth" and scratchpad is not None:
        manifest_outputs = parse_breadth_manifest_outputs(scratchpad) or []
        if manifest_outputs:
            lines.append("### Manifest-exact breadth outputs")
            lines.append("")
            lines.append(
                "The breadth manifest is stricter than the generic glob. "
                f"Produce these exact files, each >= {_min_b} bytes:"
            )
            lines.append("")
            for name in manifest_outputs:
                lines.append(f"- `{name}`")
            lines.append("")
            lines.append(
                "Do not satisfy breadth with numeric aliases such as "
                "`analysis_01.md` or `analysis_1.md`; they are ignored when "
                "the manifest names focus-area outputs."
            )
            lines.append("")
            expected = []

    if expected:
        lines.append("### Required outputs (ALL patterns in this list must be satisfied)")
        lines.append("")
        min_count = max(1, int(getattr(phase, "min_artifacts_count", 1) or 1))
        for pat in expected:
            if "*" in pat:
                ex = _glob_example(pat)
                if min_count > 1:
                    lines.append(
                        f"- **`{pat}`** -- glob. Produce AT LEAST {min_count} "
                        f"substantial files matching this pattern. Replace `*` "
                        f"with a per-agent / per-shard / per-finding token. "
                        f"Example filenames: {ex}."
                    )
                else:
                    lines.append(
                        f"- **`{pat}`** -- glob. Produce at least one substantial "
                        f"file matching this pattern. Replace `*` with a "
                        f"per-agent / per-shard / per-finding token. "
                        f"Example filenames: {ex}."
                    )
            else:
                lines.append(
                    f"- **`{pat}`** -- exact filename. Write your output to this "
                    f"exact name."
                )
        lines.append("")

    if any_of_groups:
        lines.append(
            "### Alternative naming accepted (each group is OR -- any one pattern "
            "per group satisfies the gate for that group)"
        )
        lines.append("")
        for idx, group in enumerate(any_of_groups, start=1):
            alts = ", ".join(f"`{g}`" for g in group)
            lines.append(f"- **Group {idx}**: {alts}")
        lines.append("")

    lines.append(
        "If a phase-specific directive elsewhere in this prompt (INVENTORY "
        "SHARD OBJECTIVE, REPORT PHASE OVERRIDE, VERIFY COST OVERRIDE, etc.) "
        "names a MORE SPECIFIC output filename, that directive wins within its "
        "scope -- but the resulting filename MUST still match one of the patterns "
        "above, or the gate will fail."
    )
    lines.append("")
    return "\n".join(lines)


def _render_verify_shard_checklist(config: dict, phase_name: str) -> str:
    """Render exact verify shard IDs/output files into the phase prompt."""
    scratchpad = Path(config.get("scratchpad", ""))
    if not scratchpad:
        return "- Manifest unavailable at prompt-build time; read the shard manifest before verifying."
    try:
        if phase_name in SC_VERIFY_PHASE_NAMES:
            rows = compute_sc_verify_shards(scratchpad).get(phase_name, [])
        else:
            rows = compute_verify_shards(scratchpad).get(phase_name, [])
    except Exception:
        rows = []
    if not rows:
        return (
            "- No rows assigned to this shard. If the manifest also has zero rows, "
            "return N/A without creating verifier files."
        )
    lines = []
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        title = re.sub(r"\s+", " ", row.get("title", "")).strip()
        sev = normalize_severity(row.get("severity", ""))
        lines.append(f"- {fid} -> verify_{fid}.md | {sev} | {title[:120]}")
    return "\n".join(lines) if lines else "- No parseable assigned finding IDs; treat this as a manifest error."


# v2.1.4: pre-flight prompt-gate consistency check.
#
# Catches the Class-B drift category (prompt and gate reference different
# filenames) BEFORE the subprocess spawns -- rather than discovering the
# mismatch after a 30-60 minute phase run. When the extracted V1 prompt
# contains a filename-like token that does NOT match any of the phase's
# canonical patterns (expected_artifacts + any_of groups + a conservative
# allowlist of legitimately-produced-but-not-gate-checked names like
# blind_spot_* / niche_* / design_stress_*), we log a warning pointing at
# the conflict so it can be repaired at the prompt source.
#
# SOFT by design: never fails the phase, only logs. Prompt authors may
# legitimately reference older / alternate / documentation-only names in
# prose. Hard-failing here would regress false-positive a lot. The signal
# is valuable for post-run audit + future pipeline versions.
# Allowlist of filename patterns that may legitimately appear in prompts
# but aren't in any phase's `expected_artifacts`. These are subproducer
# outputs (scanner / niche / DA / design-stress agents run inside a
# parent phase subprocess; their files exist but aren't gate-checked at
# the phase level). Also literal secondary artifacts consumed by later
# phases. Any filename pattern NOT in this list and NOT in the current
# phase's expected_artifacts triggers a consistency warning.
_LEGITIMATE_SUBPRODUCER_PATTERNS = {
    # --- Scratchpad: depth-phase subproducers (not gate-checked at phase level
    #     but legitimately written by agents inside the depth subprocess) ---
    "analysis_*.md",
    "analysis_rescan_*.md",
    "analysis_percontract_*.md",
    "depth_*_findings.md",
    "blind_spot_*_findings.md",
    "scanner_*_findings.md",  # alias for blind_spot (documented in rules)
    "niche_*_findings.md",
    "niche_coverage_gaps.md",
    "depth_da_*_findings.md",
    "validation_sweep_findings.md",
    "scanner_validation_findings.md",  # alias for validation_sweep
    "design_stress_findings.md",
    "perturbation_findings.md",
    "skill_execution_gaps.md",
    "skill_execution_checklist.md",
    "sibling_propagation_findings.md",
    "resweep_findings.md",

    # --- v2.2.0 artifacts (A.1 step-trace + A.4 NOTREAD gate) ---
    # A.1: per-Thorough-depth-agent step execution trace + driver aggregate.
    # The directive in commands/plamen-l1.md Ã‚Â§STEP-TRACE shows concrete and
    # placeholder forms; both should be allowlisted.
    "step_execution_trace_*.md",
    "step_execution_gaps_mechanical.md",
    # A.4: NOTREAD-priority directive file written by driver, read by iter2.
    "notread_priority_gaps.md",
    "attention_repair_queue.md",
    "attention_repair_findings.md",

    # --- v2.3.0 SCIP-experiment artifacts (driver-written, agent-read) ---
    "subsystem_coverage_gap.md",
    "path_unresolved.md",
    "graph_sweep_summary.md",
    "coverage_fill_*.md",
    "panic_audit_*.md",
    "panic_audit_summary.md",
    "symmetric_pair_findings.md",
    "field_validation_matrix.md",
    "primitive_correctness_findings.md",
    "network_amplification_findings.md",
    "lifecycle_replay_findings.md",

    # --- M2 multi-axis coverage meta-pass (4b.8): driver-written matrix the
    #     axis-coverage worker reads; findings artifact is the phase's own
    #     expected_artifact and is allowlisted per-phase, but the matrix support
    #     files are referenced in the prompt and must not warn. ---
    "hot_function_axes.md",
    "axis_coverage_findings.md",

    # --- Scratchpad: orchestrator-produced coordination artifacts ---
    "rag_validation.md",
    "chain_summaries_compact.md",
    "composition_coverage.md",
    "enabler_results.md",
    "finding_mapping.md",
    "synthesis_full.md",
    "chain_candidate_pairs.md",
    "variable_finding_map.md",
    "iter1_coverage_gap.md",
    "confidence_scores.md",
    "confidence_scores_batch_*.md",
    "confidence_distribution.md",
    "adaptive_loop_log.md",
    "phase4b_manifest.md",
    "phase4_gates.md",
    "checkpoint_postdepth.md",
    "pipeline_checkpoint.md",
    "violations.md",
    "spawn_manifest.md",
    "consensus_map.md",
    "symmetric_pairs.md",
    "depth_candidates.md",
    "state_dependency_map.md",
    "verification_error_traces.md",
    "verification_consistency.md",
    "file_coverage.md",
    "test_infrastructure.md",
    "dedup_candidate_pairs.md",
    "poc_demotions.md",

    # --- Scratchpad: EVM Thorough-only fuzz artifacts ---
    "invariant_fuzz_results.md",
    "medusa_fuzz_findings.md",

    # --- Scratchpad: verify / skeptic / judge ---
    "verification_queue.md",
    "verification_queue_*.md",
    "verify_core.md",
    "verify_*.md",
    "verify_F-*.md",  # L1 legacy convention; _validate_verify_completion accepts both
    "skeptic_*.md",
    "skeptic_findings.md",
    "skeptic_judge_decisions.md",
    "judge_*.md",

    # --- Scratchpad: report pipeline ---
    "report_index.md",
    "report_*.md",  # tier files + misc
    "report_coverage.md",
    "report_quality.md",
    "AUDIT_REPORT.md",
    "AUDIT_REPORT-*.md",  # timestamped snapshot

    # --- Scratchpad: recon outputs (SC + L1) ---
    "recon_summary.md", "design_context.md", "attack_surface.md",
    "state_variables.md", "function_list.md", "contract_inventory.md",
    "template_recommendations.md", "build_status.md", "threat_model.md",
    "subsystem_map.md", "trust_boundaries.md", "scope_leftover.md",
    "primitive_status.md", "call_graph.md", "external_interfaces.md",
    "external_production_behavior.md", "event_definitions.md",
    "emit_list.md", "setter_list.md", "modifiers.md",
    "constraint_variables.md", "static_analysis.md", "test_results.md",
    "detected_patterns.md", "meta_buffer.md", "fork_ancestry.md",
    "integration_points.md",

    # --- Scratchpad: v2.1.1 derived graph artifacts ---
    "caller_map.md", "callee_map.md", "state_write_map.md",
    "function_summary.md",

    # --- T2-6 (SW16): gate-mandated / driver artifacts the consistency checker
    # flagged as false "drift" (each is a real, gate- or driver-owned file). ---
    "rescan_manifest.md",      # Ship 8.17 authoritative rescan gate input
    "opengrep_findings.md",    # driver-sharded opengrep source ([OBLIG:...])
    "severity_binding.md",     # v2.8.3 driver-written severity provenance
    "status_binding.md",       # Fix 1 driver-written canonical verification-status
    "security_obligations.md", # generic feature-derived audit obligations
    "candidate_semantic_facets.md",
    "candidate_semantic_facets.json",
    "report_semantic_retention_risks.md",

    # --- Scratchpad: L1 bake / SCIP artifacts (under .scratchpad/scip/) ---
    "bake_validation.md",
    "opengrep_hits_ranked.md",
    "repo_map.md", "repo_map_full.md",
    "xref_map.md", "type_hierarchy.md",
    "concurrency_inventory.md", "panic_sites.md",
    "call_graph_*.md",  # covers call_graph_p2p/consensus/execution/etc.

    # --- Scratchpad: inventory + invariants ---
        "findings_inventory_chunk_*.md",
        "inventory_shard_plan.md",
        "inventory_merge_receipt.md",
        "findings_inventory.md",
    "semantic_invariants.md",
    "hypotheses.md",
    "chain_hypotheses.md",
    "chain_iteration2.md",
    "cross_batch_consistency.md",

    # --- Scratchpad: diagnostics written by driver itself ---
    "_prompt_*.md", "_stdio_*.log", "_v2_checkpoint.json",

    # --- Reference files: rules/, agents/, prompts/ (read by agents, never
    #     written to scratchpad). Adding these silences consistency-checker
    #     noise from prose references in prompts. They cannot drift because
    #     the filesystem path is fixed (~/.claude/...) and agents only READ,
    #     never WRITE, these names. ---
    # Top-level
    "CLAUDE.md", "README.md", "MEMORY.md", "SETUP.md", "CHANGELOG.md",
    "SECURITY.md",
    # Rules
    "orchestrator-rules.md",
    "finding-output-format.md", "phase3b-rescan-prompt.md",
    "phase4-confidence-scoring.md", "phase4c-chain-prompt.md",
    "phase5-poc-execution.md", "phase6-report-prompts.md",
    "report-template.md", "skill-index.md",
    "post-audit-improvement-protocol.md",
    # Commands / orchestrators
    "plamen.md", "plamen-l1.md", "plamen-v1-archive.md",
    "plamen-wizard.md", "plamen-l1-wizard.md", "plamen-l1-post-depth.md",
    # Per-language prompts (template filenames, not scratchpad artifacts)
    "phase1-recon-prompt.md", "phase3-breadth-driver.md",
    "phase4a-inventory-prompt.md", "phase4b-loop.md",
    "phase4b-depth-driver.md", "phase4b-depth-templates.md",
    "phase4b-scanner-templates.md", "phase4b-invariant-fuzz.md",
    "phase4b-required-artifacts.md", "phase4b-da-iter2.md",
    "phase4b-rescore.md", "phase4b-skill-checklist.md",
    "phase4b-scoring.md", "phase5-verification-prompt.md",
    "generic-security-rules.md", "breadth-semantic-operator-kernel.md",
    "self-check-checklists.md",
    "mcp-tools-reference.md", "phase05-bake.md",
    "phase3-breadth-spawner.md", "phase4b-depth-spawner.md",
    "phase4c-chain-agent1.md", "phase6-report-overrides.md",
    "v2-full-assessment.md",
    # Agent definitions
    "depth-*.md",
    "depth-consensus-invariant.md", "depth-network-surface.md",
    "depth-token-flow.md", "depth-state-trace.md",
    "depth-edge-case.md", "depth-external.md",
    # Skill files (SKILL.md is EVERYWHERE as a cross-reference)
    "SKILL.md",
    "templates.md", "advanced.md",
    # Skill name references (prose cross-links between skills)
    "TOKEN_FLOW_TRACING.md", "SEMI_TRUSTED_ROLES.md",
    "FLASH_LOAN_INTERACTION.md", "ORACLE_ANALYSIS.md",
    "ZERO_STATE_RETURN.md", "STAKING_RECEIPT_TOKENS.md",
    "EVENT_CORRECTNESS.md", "MIGRATION_ANALYSIS.md",
    "CROSS_CHAIN_TIMING.md", "TEMPORAL_PARAMETER_STALENESS.md",
    "CENTRALIZATION_RISK.md", "SHARE_ALLOCATION_FAIRNESS.md",
    "FORK_ANCESTRY.md", "ECONOMIC_DESIGN_AUDIT.md",
    "EXTERNAL_PRECONDITION_AUDIT.md", "VERIFICATION_PROTOCOL.md",
    "STORAGE_LAYOUT_SAFETY.md", "CROSS_CHAIN_MESSAGE_INTEGRITY.md",
    # Docs (referenced in prose, never written to scratchpad)
    "design.md", "severity-matrix.md",
    # Project sentinels that appear in setup/recon prose
    "Move.toml", "Cargo.toml", "foundry.toml", "hardhat.config.js",
    "package.json", "Anchor.toml",
    # Special shorthand: self-check lists compress blind_spot_A/B/C_findings.md
    # as "A/B/C_findings.md" which the regex picks up as C_findings.md.
    "C_findings.md", "A_findings.md", "B_findings.md",
    # Blind-spot scanner shorthand variants seen in prompts
    "blind_spot_c*.md",
    "scanner*c*findings.md",
    # DA iter2 variant seen in shared prompts
    "depth_iter2*findings*.md",

    # --- Additional scratchpad artifacts surfaced by the v2.1.4 audit ---
    # v2 megaplan Slither-derived artifacts (drafted but opt-in today)
    "inheritance_tree.md",
    "access_control_map.md",
    "detector_findings.md",
    "authentication.md",
    "config_parameter_usage.md",
    # Codex end-of-run validation
    "audit_validation.md",
    # Chain-specific fuzz outputs
    "trident_fuzz_findings.md",
    "cargo_fuzz_findings.md",
    # L1 recon / bake / scope
    "integration_hazard_catalog.md",
    "never_cut_checkpoint.md",
    "depth_exit.md",
    "audit_scope.md",
    "file_coverage_ledger.md",
    "inventory_evidence_validation.md",
    "location_recovery.md",
    "report_records.json",
    "module_inventory.md",
    "program_inventory.md",
    "package_inventory.md",
    "da_commitment_inventory.md",
    "p2p_surface.md",
    "rpc_surface.md",
    "peer_scoring_symmetry.md",
    "tx_type_caps.md",
    "xenv_boundaries.md",
    # Consolidation doc referenced in post-audit-improvement-protocol
    "shared-checks.md",
    # Glob variant for AUDIT_REPORT without the dash separator
    "AUDIT_REPORT*.md",
    # V2 chain-phase spawner
    "phase4c-chain-agent2.md",

    # --- More skill cross-references (caps-snake convention) ---
    "ABILITY_ANALYSIS.md", "ACCOUNT_VALIDATION.md", "TYPE_SAFETY.md",
    "TOKEN_2022_EXTENSIONS.md", "TRIDENT_API_REFERENCE.md",
}


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Convert a simple shell glob (only `*`) to a compiled regex.

    Supports only `*` (matches any chars except `/`). `?` and `[...]` are
    NOT translated -- our patterns don't use them.
    """
    # Escape regex metacharacters, then replace the escaped `*` with `.*`.
    esc = re.escape(pattern).replace(r"\*", r"[^/\\]*")
    return re.compile(rf"^{esc}$")


def _check_prompt_name_consistency(
    prompt_text: str, phase: Phase
) -> list[str]:
    """Scan the rendered prompt for filename tokens and flag drift.

    Returns a list of warning strings: each entry is a filename token that
    appears in the prompt but matches neither the phase's canonical
    patterns (expected_artifacts + any_of) NOR the legitimate-subproducer
    allowlist. Caller decides what to do with the warnings -- currently the
    driver logs them at WARNING level and proceeds.

    Implementation: grep the prompt for `<identifier>.md` tokens, strip
    backtick/code-fence framing, dedupe, then check each against the
    combined allowlist. Tokens that look like prose or variables
    (`{SCRATCHPAD}`, `{N}`, `<placeholder>`, ...) are skipped.
    """
    # Extract candidate tokens: `word.md` or `word_*.md` inside backticks,
    # brackets, or free text. Accept `-` and `_` and `*` and alphanumeric.
    token_re = re.compile(r"(?:`|\b)([A-Za-z][A-Za-z0-9_\-\*]*\.md)(?:`|\b)")
    found_tokens = set(token_re.findall(prompt_text))

    # Build allowed pattern list for this specific phase.
    allowed_patterns = set(phase.expected_artifacts or [])
    for group in getattr(phase, "any_of", []) or []:
        allowed_patterns.update(group)
    allowed_patterns |= _LEGITIMATE_SUBPRODUCER_PATTERNS

    # Compile globs ONCE.
    compiled = [_glob_to_regex(p) for p in allowed_patterns]

    unknowns: list[str] = []
    for tok in sorted(found_tokens):
        if "{" in tok or "<" in tok:
            continue  # template placeholder, skip
        # Match against any allowed pattern.
        if any(rx.match(tok) for rx in compiled):
            continue
        unknowns.append(tok)
    return unknowns


# ---------------------------------------------------------------------------
# L1 Skill Injection â€” mechanical routing of injectable skills to depth agents
# ---------------------------------------------------------------------------

_L1_SKILL_DEPTH_ROUTING: dict[str, tuple[str, ...]] = {
    "CONSENSUS_SAFETY_INVARIANTS":              ("consensus_invariant",),
    "CONSENSUS_MATH_CORRECTNESS":               ("consensus_invariant", "edge_case"),
    "FORK_CHOICE_AUDIT":                        ("consensus_invariant",),
    "P2P_DOS_AND_ECLIPSE":                      ("network_surface",),
    "MEMPOOL_ASYMMETRIC_DOS":                   ("network_surface", "state_trace"),
    "LIGHT_CLIENT_PROOF_VERIFICATION":          ("consensus_invariant", "external"),
    "RPC_SURFACE_AUDIT":                        ("network_surface",),
    "BLS_AGGREGATION_AUDIT":                    ("consensus_invariant", "external"),
    "STATE_SYNC_PRUNING":                       ("state_trace", "edge_case"),
    "EXECUTION_CLIENT_HARDENING":               ("state_trace", "consensus_invariant"),
    "CROSS_ENVIRONMENT_SEMANTIC_DRIFT":         ("external", "state_trace"),
    "VALIDATOR_LIFECYCLE_AND_SLASHING":          ("state_trace", "consensus_invariant"),
    "HARDFORK_ACTIVATION_AND_PROTOCOL_UPGRADE": ("state_trace", "consensus_invariant"),
    "DATA_AVAILABILITY_ENFORCEMENT":            ("consensus_invariant", "state_trace"),
    "PEER_SCORING_CORRECTNESS":                 ("network_surface",),
    "GOSSIP_CACHE_INVARIANCE":                  ("network_surface", "consensus_invariant"),
    "CONSENSUS_TX_IDENTITY_INVARIANTS":         ("consensus_invariant", "state_trace"),
    "CONFIG_CORRECTNESS":                       ("edge_case", "state_trace"),
    "WRITE_ERROR_DIVERGENCE":                   ("state_trace", "edge_case"),
    "COSMOS_SDK_MODULE_SAFETY":                 ("consensus_invariant", "state_trace"),
    "COSMOS_IBC_SECURITY":                      ("consensus_invariant", "external"),
    "GO_CONCURRENCY_SAFETY":                    (),
    "RUST_UNSAFE_AUDIT":                        (),
    "DEPENDENCY_AUDIT_NODECLIENT":              (),
}

_L1_ALWAYS_ON_DEPTH: dict[str, list[str]] = {
    "go":    ["GO_CONCURRENCY_SAFETY", "DEPENDENCY_AUDIT_NODECLIENT"],
    "rust":  ["RUST_UNSAFE_AUDIT",     "DEPENDENCY_AUDIT_NODECLIENT"],
    "mixed": ["GO_CONCURRENCY_SAFETY", "RUST_UNSAFE_AUDIT", "DEPENDENCY_AUDIT_NODECLIENT"],
}

_L1_DEPTH_AGENT_ROLES = [
    "consensus_invariant", "network_surface", "state_trace", "edge_case", "external",
]

_L1_SKILL_BASE = plamen_home() / "agents" / "skills" / "injectable" / "l1"


def _parse_l1_required_skills(scratchpad: Path) -> tuple[list[str], set[str]]:
    """Parse template_recommendations.md for Required=YES/NO injectable skills.

    Returns (required_names, explicitly_excluded_names).
    Skips rows under ``## Niche Agents`` headings â€” niche agents are standalone
    agents spawned by the orchestrator, not injectable skill methodology.
    """
    tr = scratchpad / "template_recommendations.md"
    if not tr.exists():
        return [], set()
    required: list[str] = []
    excluded: set[str] = set()
    in_niche_section = False
    try:
        text = tr.read_text(encoding="utf-8")
    except OSError:
        return [], set()
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^#{2,3}\s+", stripped):
            in_niche_section = bool(re.search(r"(?i)niche\s+agent", stripped))
            continue
        if in_niche_section:
            continue
        if not stripped.startswith("|"):
            continue
        # PARSE-2: preserve empty interior cells so the Required? column stays at
        # its true index. The prior empty-filter shifted indices when a cell was
        # blank, silently failing to inject a mechanically-Required L1 skill (the
        # exact recall loss v2.6.4 was built to prevent).
        cols = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cols) < 3:
            continue
        name_raw = cols[0].strip("`").strip("*").strip()
        req_raw = cols[2].strip("`").strip("*").strip().upper()
        if not name_raw or name_raw.lower() in ("skill", "skill / template"):
            continue
        if req_raw == "YES":
            required.append(name_raw)
        elif req_raw == "NO":
            excluded.add(name_raw)
    return required, excluded


def _resolve_l1_skill_paths(skill_names: list[str]) -> dict[str, Path]:
    """Convert UPPER_SNAKE skill names to file paths, return those that exist."""
    result: dict[str, Path] = {}
    for name in skill_names:
        kebab = name.lower().replace("_", "-")
        path = _L1_SKILL_BASE / kebab / "SKILL.md"
        if path.exists():
            result[name] = path
        else:
            logger.warning("L1 skill %s: SKILL.md not found at %s", name, path)
    return result


def _build_l1_depth_skill_injection(scratchpad: Path, language: str) -> str:
    """Build the L1 SKILL INJECTION MANIFEST block for the depth phase prompt."""
    required, excluded = _parse_l1_required_skills(scratchpad)
    resolved = _resolve_l1_skill_paths(required)

    always_on_names = _L1_ALWAYS_ON_DEPTH.get(language, [])
    always_on_filtered: list[str] = []
    for ao in always_on_names:
        if ao in excluded:
            continue
        if ao not in resolved:
            kebab = ao.lower().replace("_", "-")
            path = _L1_SKILL_BASE / kebab / "SKILL.md"
            if path.exists():
                resolved[ao] = path
                always_on_filtered.append(ao)
        else:
            always_on_filtered.append(ao)

    if not resolved:
        return ""

    agent_skills: dict[str, list[str]] = {r: [] for r in _L1_DEPTH_AGENT_ROLES}
    for skill_name in resolved:
        targets = _L1_SKILL_DEPTH_ROUTING.get(skill_name, ())
        if not targets:
            for role in _L1_DEPTH_AGENT_ROLES:
                if skill_name not in agent_skills[role]:
                    agent_skills[role].append(skill_name)
        else:
            for t in targets:
                if t in agent_skills and skill_name not in agent_skills[t]:
                    agent_skills[t].append(skill_name)

    lines = [
        "## L1 SKILL INJECTION MANIFEST (MANDATORY â€” mechanically generated by driver)",
        "",
        "The driver resolved `template_recommendations.md` and computed skill-to-agent",
        "routing. You MUST include the listed Read directives in each depth agent's",
        "Task prompt. Do NOT re-parse template_recommendations.md â€” this manifest is",
        "authoritative.",
        "",
        "### Per-Agent Skill Assignments",
        "",
    ]
    for role in _L1_DEPTH_AGENT_ROLES:
        skills = agent_skills[role]
        if not skills:
            continue
        lines.append(f"#### depth-{role.replace('_', '-')}")
        lines.append("Include these Read directives in this agent's Task prompt:")
        for s in skills:
            path = resolved[s]
            posix = str(path).replace("\\", "/")
            annotation = ""
            if s in always_on_filtered:
                annotation = f" (always-on for {language})"
            lines.append(f"- Read `{posix}`{annotation}")
        lines.append("")

    lines.extend([
        "### Skill Injection Protocol",
        "",
        "When spawning each depth Task subagent listed above, your prompt MUST include:",
        '1. The directive: "Read the following skill methodology files and apply them:"',
        "2. The exact file paths listed for that agent",
        '3. The instruction: "For each numbered skill section, execute the analysis',
        '   steps. Record skill coverage in your output header."',
        "",
        "Do NOT summarize or omit skills. The post-depth step-execution-gap checker",
        "validates skill coverage.",
        "",
        "### L1 Artifact Name Mapping",
        "",
        "L1 recon produces `threat_model.md`, not `design_context.md`. When depth",
        "methodology references `{SCRATCHPAD}/design_context.md`, read",
        "`{SCRATCHPAD}/threat_model.md` instead. If neither exists, record",
        "`[MISSING: design_context/threat_model]` in your output.",
        "",
    ])
    return "\n".join(lines)


def _build_graph_sweeps_artifact_directive(scratchpad: Path) -> str:
    """Build an explicit artifact checklist mirroring the graph_sweeps validator.

    The validator (_validate_graph_sweeps) checks for conditional artifacts
    based on surface-detection helpers.  The V1 prompt describes these outputs
    in natural language across 7 sweep sections, but the EXPECTED OUTPUT FILES
    block (generated from phase.expected_artifacts) only lists the summary
    file.  On Codex, the DIRECT EXECUTION CONTEXT POLICY further reinforces
    "write only graph_sweep_summary.md then stop", causing the model to ignore
    the V1 sweep sections.

    This function reads the SAME scratchpad surfaces as the validator and
    generates an explicit MANDATORY ARTIFACT CHECKLIST that overrides the
    static expected_artifacts directive.
    """
    stats = _parse_subsystem_coverage_gap(scratchpad)
    low_coverage = stats["uncited"] > 0 and stats["coverage"] < 60.0
    panic_sites = _panic_sites_available(scratchpad)
    field_validation = _field_validation_sweep_relevant(scratchpad)
    primitive = _primitive_sweep_relevant(scratchpad)
    network_amplification = _network_amplification_sweep_relevant(scratchpad)
    lifecycle_replay = _lifecycle_replay_sweep_relevant(scratchpad)

    conditions = [
        low_coverage, panic_sites, field_validation,
        primitive, network_amplification, lifecycle_replay,
    ]
    if not any(conditions):
        return ""

    lines = [
        "## MANDATORY ARTIFACT CHECKLIST (mechanically generated by driver)",
        "",
        "The EXPECTED OUTPUT FILES section above lists only the minimum gate",
        "artifact.  This phase has ADDITIONAL MANDATORY outputs based on",
        "detected surfaces.  **Writing only `graph_sweep_summary.md` will FAIL",
        "the quality gate and force a retry.**",
        "",
        "You MUST write ALL of the following files before exiting:",
        "",
        "| # | Artifact | Condition | Sweep |",
        "|---|----------|-----------|-------|",
        "| 1 | `graph_sweep_summary.md` | Always | Summary |",
    ]
    n = 2
    if low_coverage:
        lines.append(
            f"| {n} | `coverage_fill_1.md` (shard with `coverage_fill_{{N}}.md`) "
            f"| Coverage={stats['coverage']:.1f}% with "
            f"{int(stats['uncited'])} uncited files | Sweep B |"
        )
        n += 1
    if panic_sites:
        lines.append(
            f"| {n} | `panic_audit_1.md` + `panic_audit_summary.md` "
            f"| panic_sites.md is non-empty | Sweep A |"
        )
        n += 1
    if field_validation:
        lines.append(
            f"| {n} | `field_validation_matrix.md` "
            f"| Field-validation surface detected | Sweep D |"
        )
        n += 1
    if primitive:
        lines.append(
            f"| {n} | `primitive_correctness_findings.md` "
            f"| Primitive/serialization surface detected | Sweep E |"
        )
        n += 1
    if network_amplification:
        lines.append(
            f"| {n} | `network_amplification_findings.md` "
            f"| Network-amplification surface detected | Sweep F |"
        )
        n += 1
    if lifecycle_replay:
        lines.append(
            f"| {n} | `lifecycle_replay_findings.md` "
            f"| Lifecycle/replay surface detected | Sweep G |"
        )
        n += 1

    lines.extend([
        "",
        f"**Total required artifacts: {n - 1}.**  All conditions above are",
        "mechanically verified by the driver after subprocess exit.",
        "",
        "**DO NOT** exit after writing only `graph_sweep_summary.md`.",
        "**DO NOT** skip sweeps whose condition is listed as detected above.",
        "The gate checks each artifact independently and will fail on ANY",
        "missing file.  Each file must be >= 200 bytes of substantive content.",
    ])

    # Per-sweep content schema. `_validate_graph_sweeps` soft-warns when these
    # tokens are missing from the corresponding sweep artifact.
    if network_amplification or lifecycle_replay:
        lines.extend([
            "",
            "### Per-sweep content schema",
            "",
            "Each conditional sweep artifact must contain these tokens "
            "(case-insensitive substring match is sufficient):",
            "",
        ])
        if network_amplification:
            lines.extend([
                "**`network_amplification_findings.md`** (Sweep F)",
                "- `ingress`  â€” where untrusted bytes enter the node",
                "- `dedup`    â€” deduplication / replay-resistance mechanism",
                "- `validation` â€” input shape / size / bound checks",
                "- `egress`   â€” outbound propagation cost analysis",
                "- `verdict`  â€” CONFIRMED / PARTIAL / REFUTED per finding",
                "- `evidence` â€” file:line cited code excerpt per finding",
                "",
            ])
        if lifecycle_replay:
            lines.extend([
                "**`lifecycle_replay_findings.md`** (Sweep G)",
                "- `insert`   â€” message / record write path",
                "- `consume`  â€” message / record read path",
                "- `evict`    â€” eviction / expiry / pruning policy",
                "- `replay`   â€” replay-attack defense (nonce, txid, hash)",
                "- `verdict`  â€” CONFIRMED / PARTIAL / REFUTED per finding",
                "- `evidence` â€” file:line cited code excerpt per finding",
                "",
            ])
    return "\n".join(lines) + "\n"


def build_phase_prompt(v1_prompt: Path, phase: Phase, config: dict) -> str:
    """Wrap the V1 prompt with a phase-scoping directive and config.

    Two routes for Step 0 skip: (1) a $ARGUMENTS-shaped string that matches
    plamen.md's shortcut-parse auto-skip logic, and (2) a prose directive at
    the top. Either alone is error-prone; both together make skip reliable.

    V1 prompt is section-extracted to the phase's assigned sections plus
    the global preamble -- reduces ~65KB to ~10KB typical, prevents
    mid-run compaction thrashing.
    """
    # v2.5.0: STANDALONE-FIRST architecture.
    # Priority: override (cost_directive IS full instruction) > standalone > V1 fallback.
    # This decouples the pipeline from the monolithic V1 prompt -- heading
    # renames in plamen.md/plamen-l1.md no longer break phases.
    using_standalone_body = False
    standalone_source_name = ""
    if phase.name == "recon":
        recon_prompt = _resolve_recon_prompt(config)
        if recon_prompt:
            full = _sanitize_recon_prompt_contract(
                recon_prompt.read_text(encoding="utf-8")
            )
            using_standalone_body = True
            try:
                standalone_source_name = str(
                    recon_prompt.relative_to(plamen_home())
                )
            except ValueError:
                standalone_source_name = recon_prompt.name
            log.debug(
                f"[{phase.name}] Using language recon prompt: "
                f"{standalone_source_name}"
            )
        else:
            full_text = v1_prompt.read_text(encoding="utf-8")
            try:
                full = extract_phase_sections(full_text, phase.section_markers)
            except PhasePromptError as e:
                raise PhasePromptError(
                    f"Phase '{phase.name}' cannot build a safe recon prompt. "
                    f"No language phase1-recon-prompt.md exists for "
                    f"{config.get('language')!r}, and markers "
                    f"{phase.section_markers!r} don't match any V1 heading."
                ) from e
    elif phase.name in _OVERRIDE_SELF_CONTAINED_PHASES:
        full = (
            "# V1 prompt section not applicable to this phase.\n"
            "# Follow the OVERRIDE directive above -- it contains your full instructions.\n"
        )
        using_standalone_body = True
        standalone_source_name = phase.name
    else:
        standalone = _resolve_standalone_prompt(phase.name)
        if standalone:
            full = standalone.read_text(encoding="utf-8")
            if phase.name in ("breadth", "rescan"):
                full = re.sub(r"(?m)^<!-- BUILD-STRIP:.*?-->\r?\n?", "", full)
            using_standalone_body = True
            standalone_source_name = standalone.name
            log.debug(f"[{phase.name}] Using standalone prompt: {standalone.name}")
        else:
            # Fallback: V1 section extraction (bake, graph_sweeps only).
            full_text = v1_prompt.read_text(encoding="utf-8")
            try:
                full = extract_phase_sections(full_text, phase.section_markers)
            except PhasePromptError as e:
                raise PhasePromptError(
                    f"Phase '{phase.name}' cannot build a safe prompt. "
                    f"No standalone prompt in prompts/shared/v2/, markers "
                    f"{phase.section_markers!r} don't match any V1 heading. "
                    f"Add this phase to _STANDALONE_PROMPT_MAP or fix the markers."
                ) from e
            except Exception as e:
                raise PhasePromptError(
                    f"Phase '{phase.name}' V1 extraction failed ({e}) "
                    f"and no standalone prompt file exists."
                ) from e
    full = _render_runtime_placeholders(full, config)
    if config.get("pipeline") == "l1" and phase.name in L1_VERIFY_PHASE_NAMES:
        full = _prune_l1_verify_shard_prompt(full)
    if _is_sc_verify_phase(config, phase.name):
        full = _select_sc_verify_contract(full, phase.name)
    if config.get("pipeline") != "l1" and phase.name in SC_VERIFY_PHASE_NAMES:
        full = _prune_sc_verify_shard_prompt(full)
    if phase.name == "rescan":
        full = _inline_stripped_rescan_prompt(full)
    if phase.name == "breadth":
        full = _sanitize_breadth_forward_refs(full)
    if phase.name == "depth":
        full = _sanitize_depth_forward_refs(full)
    # v2.4.6: strip subsections that belong to OTHER V2 phases.
    full = _strip_foreign_subsections(full, phase.name)
    markers = ", ".join(f"`{m}`" for m in phase.section_markers)
    pipeline_name = "L1 node-client" if config["pipeline"] == "l1" else "smart-contract"

    # $ARGUMENTS-shaped string that triggers plamen.md Step 0 auto-skip.
    # plamen.md looks for: MODE + absolute PROJECT_PATH + (docs: OR nodocs)
    # + proven-only: + wrapper-launch. When all present, it skips the whole
    # wizard and jumps to Step 1.
    docs_val = config.get("docs_path") or config.get("docs_path_or_url_if_provided")
    docs_token = f"docs: {docs_val}" if docs_val else "nodocs"
    scope_val = config.get("scope_file") or config.get("scope_file_if_provided")
    scope_token = f"scope: {scope_val}" if scope_val else ""
    notes_val = config.get("scope_notes") or config.get("scope_notes_if_provided")
    notes_token = f"notes: {notes_val}" if notes_val else ""
    network_val = config.get("network") or config.get("network_if_provided")
    network_token = f"network: {network_val}" if network_val else ""
    subsystem_scope = _normalize_subsystem_scope(config.get("subsystem_scope"))
    subsystem_token = f"subsystem-scope: {subsystem_scope}" if subsystem_scope else ""
    proven = bool(config.get("proven_only", False))
    proven_token = f"proven-only: {'true' if proven else 'false'}"
    arg_parts = [
        config["mode"], config["project_root"], docs_token,
        scope_token, notes_token, network_token, subsystem_token, proven_token,
        "wrapper-launch",
    ]
    arguments_str = " ".join(x for x in arg_parts if x)

    # Variables for the RESUMPTION PROTOCOL block below.
    phase_name = phase.name
    # v2.3.6 H2: when a phase has no static expected_artifacts (e.g. verify
    # shards whose output names are determined at runtime from the
    # verification queue manifest), give the LLM an explicit signal rather
    # than a trailing-blank string. Pre-v2.3.6 the empty join produced
    # "Expected artifacts for phase `X`: " -- the LLM read this as "no
    # expected outputs" and skipped the RESUMPTION PROTOCOL's stale-artifact
    # check, re-running all subagents on resume.
    expected_artifacts_list = ", ".join(phase.expected_artifacts) or (
        "(dynamic -- determined at runtime; check the relevant manifest "
        "and any prior-attempt artifacts in the scratchpad)"
    )

    # Producer-contract block: renders phase.expected_artifacts as a hard
    # naming directive. Single source of truth shared with gate_passes().
    expected_output_block = _render_expected_output_block(
        phase, Path(config["scratchpad"])
    )
    phase_isolation_directive = _render_phase_isolation_block(phase)

    report_scope_directive = ""
    inventory_scope_directive = ""
    breadth_scope_directive = ""
    recon_scope_directive = ""
    forbidden_output_directive = _render_forbidden_output_block(phase.name)
    # v2.0.3 (A1): PLAMEN V2 EXECUTION CONTRACT -- single-turn / no-background
    # / no-wave directive injected only into Task-using (multi-agent) phases.
    # Backend-aware via config["cli_backend"]: Claude variant uses Task tool
    # vocabulary, Codex variant uses spawn_agent/wait_agent vocabulary.
    execution_contract_directive = _render_execution_contract(
        phase.name, config.get("pipeline", "sc"),
        backend=config.get("cli_backend", "claude"),
        exec_mode=_derive_claude_exec_mode(config),
    )
    # v2.0.6 (P2.3): ID ledger directive for chain phases. Lists
    # already-allocated IDs and next-available numbers so the LLM does not
    # re-mint an existing ID with different content.
    id_ledger_directive = _render_id_ledger_directive(
        phase.name, Path(config["scratchpad"])
    )
    subsystem_scope_directive = ""
    prior_phase_outputs_block = f"""
## PRIOR PHASE OUTPUTS

The scratchpad `{config['scratchpad']}` contains artifacts from previous
phases. Read them as your phase's instructions require -- do NOT
regenerate them. A mechanical pre-pass may have also written mechanical
artifacts (contract_inventory.md, state_variables.md, function_list.md,
build_status.md, subsystem_map.md). Use them; do NOT rewrite them from
scratch, only enrich interpretive artifacts (design_context.md,
attack_surface.md, template_recommendations.md, recon_summary.md).
"""
    if phase.name == "recon":
        recon_scope_directive = _render_recon_handoff_directive(phase)
        prior_phase_outputs_block = f"""
## PRIOR PHASE OUTPUTS

The scratchpad `{config['scratchpad']}` may contain deterministic recon
pre-pass artifacts. Treat them as seed material, not immutable final output.
You may overwrite or enrich any expected recon artifact when doing so makes
the handoff more accurate or removes placeholder/draft content. The final
artifact set must match the RECON CLEAN HANDOFF CONTRACT above exactly.
"""
    if subsystem_scope:
        subsystem_scope_directive = f"""
## SUBSYSTEM SCOPE - HARD CONSTRAINT

The configured `subsystem_scope` is `{subsystem_scope}`.

Audit ONLY files under `{subsystem_scope}/`. Files outside this prefix are
OUT OF SCOPE for this run.

Mandatory scope rules:
1. Keep analysis focused on `{subsystem_scope}/`.
2. Do NOT survey, analyze, or cite out-of-scope files except as one-hop
   dependencies needed to explain a scoped finding. Dependency context is not
   a separate finding surface.
3. In `scope_leftover.md`, list skipped out-of-scope top-level modules with
   `ACKNOWLEDGED: out of configured subsystem_scope` when the phase writes a
   scope ledger.
4. If a V1 prompt asks for whole-repository coverage, this subsystem scope
   directive overrides it.
"""

    # Phase E11: body-writer phase prompt overrides. Each shard gets a tight
    # manifest-driven directive that constrains the LLM to: (a) read only the
    # shard's body_manifests/<shard>.json + cited verify files + cited source
    # excerpts, (b) write rich finding bodies into the assigned tier file, and
    # (c) emit nothing not in the manifest. The post-phase validator catches
    # drift; the prompt here is the front door.
    if phase.name.startswith("report_body_writer_"):
        shard_key = phase.name.replace("report_body_writer_", "report_")
        out_file = phase.expected_artifacts[0] if phase.expected_artifacts else f"{shard_key}.md"
        # Resolve actual manifest path(s). _build_body_writer_manifests
        # splits tiers into _a/_b/... shards when finding count exceeds the
        # per-tier cap. The unsuffixed manifest may not exist if the tier
        # was split (e.g. report_low_info Ã¢â€ ' report_low_info_a + _b).
        _sp = Path(config["scratchpad"])
        _unsuffixed = _sp / "body_manifests" / f"{shard_key}.json"
        if _unsuffixed.exists():
            manifest_rel = f"body_manifests/{shard_key}.json"
        else:
            _shard_files = sorted((_sp / "body_manifests").glob(f"{shard_key}_*.json"))
            if _shard_files:
                manifest_rel = " + ".join(f"body_manifests/{f.name}" for f in _shard_files)
            else:
                manifest_rel = f"body_manifests/{shard_key}.json"
        report_scope_directive = f"""
## BODY-WRITER PHASE OVERRIDE

You are the body writer for shard `{shard_key}`. Your ONLY output is
`{out_file}`. The driver has already produced the deterministic structure
(IDs, severities, locations, dedup, exclusions) in the per-shard manifest
at `{manifest_rel}`. That manifest is your SINGLE SOURCE OF TRUTH for
which findings to write.

## Inputs (READ ONLY)

1. `{manifest_rel}` -- the authoritative list of findings you must write up.
   Every entry has: `report_id`, `finding_id`, `severity`, `title`,
   `location`, `evidence_tag`, `verify_file`, `verify_files`, `description`,
   `poc_result`, `recommendation`, `report_blocked`. The `description`,
   `poc_result`, and `recommendation` fields contain the verifier's own
   narrative -- use them as substance and rephrase for clarity, do not invent
   new claims.
2. The `verify_files` referenced for each manifest entry -- only when the
   manifest's `description`/`recommendation` need additional context. For
   consolidated findings, read every file in `verify_files` and preserve each
   distinct proven location/impact in the body without exposing internal IDs.
3. Cited source files, line-bounded -- only when you need to inline a
   short code excerpt the verifier already proved.

Read only the manifest and the evidence files explicitly referenced inside
that manifest. Ignore every other scratchpad artifact for this phase. The
manifest already contains every field you need.

## Output rules

- Write ONLY `{out_file}`.
- Cover EVERY finding in the manifest. Missing one is a hard halt.
- Write NOTHING outside the manifest. Inventing a report ID is a hard halt.
- Use the `report_id` from the manifest as the finding section heading
  (`### [<report_id>] <title>`). Preserve the severity ordering implied by
  the manifest.
- Each finding section MUST include: Severity, Location (verbatim from
  the manifest), Description (rephrased substance from
  `description` + `verify_files`), Impact (derived from the verifier's
  Impact line and the cited postcondition), Evidence Tag (verbatim from
  the manifest), and Recommendation (rephrased substance from
  `recommendation`).
- For Critical, High, and Medium findings, each section MUST also include
  `**PoC Result**:` with substantive verifier-backed text. Use manifest
  `poc_result` first; if it is empty, read the referenced `verify_files` and
  summarize the `PoC Attempt`, `Execution Result`, `PoC Result`, or
  `Execution Output` section. If no executable PoC was run, state the
  verifier's explicit not-executed/blocker reason and evidence tag; do NOT
  claim a passing PoC.
- For any manifest entry whose `report_blocked` is `true`, prefix the
  section heading with `[REPORT-BLOCKED: insufficient evidence]` and use
  conservative prose -- do NOT speculate to fill the gap.
- No internal pipeline IDs in the prose (no `INV-NNN`, no `BLIND-N`,
  no `[CC-N]`, etc.). Use only the `report_id`.

## Acceptance gate

After you write `{out_file}`, the driver runs
`_validate_tier_body_against_manifest`. It will halt the pipeline if
your file is missing any manifest entry, contains any extra report IDs,
references any location not in the manifest, or omits the
`[REPORT-BLOCKED: ...]` tag for blocked findings. There is no Python
prose fallback -- the only escape is an explicit BODY-WRITER-DEGRADED
artifact written by the driver after a hard halt.
"""
    if phase.name == "breadth":
        # Ship-C hotfix: under the default Claude PTY transport, spawn EVERY
        # open breadth row at once as BACKGROUND Task calls. The persistent PTY
        # session + disk-derived gate make background safe (results are
        # collected from files, not from the turn). Foreground + "batches of 6"
        # serialized a live breadth attempt in a prior run (produced only
        # analysis_cross_chain.md, then halted). Headless/Codex keep the
        # foreground batched loop (background would orphan workers there).
        _breadth_em = _derive_claude_exec_mode(config)
        _breadth_pty = (
            config.get("cli_backend", "claude") == "claude"
            and _breadth_em == "pty"
        )
        if _breadth_pty:
            _breadth_spawn_steps = (
                "5. Spawn ALL of OPEN_OUTPUTS in ONE assistant message as\n"
                "   BACKGROUND Task calls (`run_in_background: true`) -- one\n"
                "   Task per missing/stub row, all issued together. Do NOT run\n"
                "   a single agent to completion before spawning the rest. Do\n"
                "   NOT split OPEN_OUTPUTS into batches. Do NOT use \"Wave 1 /\n"
                "   Wave 2\" phasing. Background mode is REQUIRED here: this is\n"
                "   a persistent PTY session and the driver collects results\n"
                "   from disk.\n"
                "6. After launching every background worker, keep the\n"
                "   coordinator alive and monitor/collect them, but treat\n"
                "   Task completion text as advisory only. Re-derive\n"
                "   OPEN_OUTPUTS from disk; if any row is still missing, stub,\n"
                "   IN_PROGRESS, lacks a final PLAMEN_STATUS: COMPLETE, or has\n"
                "   no real finding/no-findings body after its worker returns,\n"
                "   re-spawn ONLY those exact rows -- again all at once,\n"
                "   background. Never serialize.\n"
                "7. Repeat steps 3-6 until OPEN_OUTPUTS is empty.\n"
                "8. Each breadth agent writes exactly one\n"
                "   `analysis_<focus_area>.md` file and then stops."
            )
        else:
            # Headless / Codex: unchanged foreground batched loop (background
            # would orphan workers when the single turn ends). Wording is kept
            # byte-identical to the pre-hotfix directive.
            _breadth_spawn_steps = (
                "5. If OPEN_OUTPUTS is non-empty, spawn ONLY those missing or stub breadth\n"
                "   agents. Do not spawn all agents again.\n"
                "6. Spawn OPEN_OUTPUTS in bounded batches of at most 6 parallel Task calls.\n"
                "   If 7+ outputs are open, wait for the first batch, close completed agents,\n"
                "   then return to step 3 before spawning the next batch.\n"
                "7. Repeat steps 3-6 until OPEN_OUTPUTS is empty.\n"
                "8. Each breadth agent writes exactly one `analysis_<focus_area>.md` file and\n"
                "   then stops."
            )
        breadth_scope_directive = """
## BREADTH PHASE OVERRIDE

Run ONLY the breadth analysis phase.

Output ownership:
- Your only valid outputs are manifest-derived breadth files named
  `analysis_<focus_area>.md`.
- Do not create any other artifact family. Files outside the manifest-derived
  breadth set are ignored by the breadth gate and are moved aside by the
  phase-boundary checker.
- When all required breadth files are COMPLETE on disk, stop immediately.

Manifest completion loop:
1. Read `spawn_manifest.md` first.
2. For every required spawned breadth-agent row in `spawn_manifest.md`, derive
   its expected output file as `analysis_<focus_area>.md` unless the manifest
   explicitly names an output file. Ignore rows whose type/status/role says
   `skill`, `injectable`, `template`, `methodology`, `checklist`, `binding`,
   `merged into ...`, `covered by ...`, or `no separate agent`; those rows
   modify an agent prompt and do not own standalone `analysis_*.md` files.
3. Build COMPLETE_OUTPUTS from expected files that pass disk verification:
   the file exists, the LAST PLAMEN_STATUS marker is COMPLETE, and the file
   has at least one real `## Finding [` / `### Finding [` block OR a
   `## No Findings` / `## Negative Result` rationale.
4. Build OPEN_OUTPUTS from expected files that are missing, stub-sized, still
   IN_PROGRESS, missing a final PLAMEN_STATUS: COMPLETE, or lacking a real
   finding/no-findings body. Ignore stale COMPLETE/PENDING text in the
   manifest Status column.
""" + _breadth_spawn_steps + """

Do not consider a returned worker to mean the phase is complete. Completion is
manifest-exact, not batch-exact, and disk-derived. A background Task that says
DONE without a COMPLETE artifact on disk is still incomplete. Never return
with 7/12, 9/12, or any partial manifest completion.

The gate counts only valid breadth outputs. Non-manifest `analysis_*` files
are not counted.
"""
    if phase.name.startswith("inventory_chunk_"):
        shard_files = parse_inventory_shard_manifest(
            Path(config["scratchpad"]), phase.name
        )
        out_name = f"findings_{phase.name}.md"
        l1_inventory_note = ""
        if config.get("pipeline") == "l1":
            l1_inventory_note = (
                "\nL1 phase-order note: inventory consumes `analysis_*.md` "
                "files from the L1 breadth phase. Depth and\n  niche outputs "
                "are promoted into inventory later by the driver, after the "
                "depth phase runs.\n"
            )
        inventory_scope_directive = """
## INVENTORY SHARD OBJECTIVE

This is an inventory shard phase. Read ONLY these analysis artifacts:
- {files}
{l1_inventory_note}

Write ONLY `{output}`.

Output format requirements for EVERY shard finding:
- heading style: `### Finding [CC-N]: <title>` (CC-N = Consolidated Chunk ID,
  numbered sequentially from CC-01 within THIS shard; driver downstream
  parses CC-\\d+ as a valid internal ID)
- include explicit `**Source IDs**:` containing the original upstream IDs
- include `**Severity**:`, `**Location**:`, and `**Preferred Tag**:`
- preserve the original source IDs even if you rename the local shard ID

ID PRESERVATION RULE: The global "no internal IDs in the client-facing
report body" rule in rules/report-template.md does NOT apply to this
intermediate artifact. CC-N and upstream source IDs MUST appear here --
they are the contract the downstream inventory-merge and report-index
phases rely on to map shard output back to report IDs. ID stripping
happens ONLY in the tier-writer phases (report_critical_high, report_medium_*,
report_low_info), not here and not in any `*_assignments.md`
manifest.

Execution model:
- Do this work directly in this subprocess. Do NOT spawn Task subagents.
- Read the assigned files one at a time. They are the only large inputs you
  need, and they are already shard-bounded by the driver.
- Do NOT create shell/Python helper scripts or temporary `/tmp` files to
  assemble the final artifact. Write the final markdown artifact directly.
- Do NOT run tests, invoke external tools, or inspect source files. This phase
  consolidates already-written analysis artifacts only.

Required file structure:
1. `## Source Summary` with one row for every assigned input file and a final
   total row.
2. `## Master Table` with one row for every local CC finding.
3. `## Per-Finding Detail` with one `### Finding [CC-NN]: <title>` block for
   every row in the master table.

Every detail block must include:
- `**Source IDs**:`
- `**Severity**:`
- `**Location**:`
- `**Preferred Tag**:`
- `**Verdict**:`
- `**Root Cause**:`
- `**Description**:`
- `**Impact**:`

Use this exact detail-block skeleton for every finding; do not omit any field
and do not substitute another section for it:

```markdown
### Finding [CC-NN]: <title>

**Source IDs**: <source IDs>
**Severity**: <Critical|High|Medium|Low|Informational>
**Location**: <file:line or N/A>
**Preferred Tag**: <tag>
**Verdict**: <CONFIRMED|PARTIAL|REFUTED|INFO>
**Root Cause**: <why the issue exists, or why it is blocked>
**Description**: <what happens and the relevant evidence>
**Impact**: <security/economic/operational effect; for PARTIAL, REFUTED,
or Informational findings, explicitly state the blocked or residual impact>
```

`**Impact**:` is mandatory even when the verdict is PARTIAL, REFUTED, or
Informational. Precondition analysis may appear only after the mandatory
fields; it does not replace `**Impact**:`. Never end a finding block after
`Precondition Analysis` without a separate `**Impact**:` line in that same
block.

Completion checklist before returning:
- Count master-table rows and detail headings. They must be equal.
- For every `### Finding [CC-NN]` block, verify the block contains a literal
  `**Impact**:` line. If any block lacks it, fix the block before returning.
- Every source ID that appears in a source finding is either listed in exactly
  one detail block or explicitly listed in the Source Summary as deduplicated
  into another CC finding.
- The only file you wrote is `{output}`.

Do local dedup only within this shard. Do not read unrelated `analysis_*.md`
files.

**OUTPUT ALLOWLIST**

Write ONLY `{output}`. Do not create, update, or repair any other scratchpad
artifact. Any non-allowlisted write triggers phase containment and retry.

If your assigned input set tempts you to keep working past your own
chunk's checklist, STOP. Each sibling chunk has its own assigned input
set and its own subprocess. Cross-chunk consolidation is outside this shard.

After the checklist passes, return one line and stop.
""".format(
            files="\n- ".join(shard_files) if shard_files else "(none assigned)",
            l1_inventory_note=l1_inventory_note,
            output=out_name,
        )
    elif phase.name == "inventory":
        inventory_scope_directive = """
## INVENTORY TERMINAL OBJECTIVE

Your only job in this phase is to produce a complete, authoritative
`findings_inventory.md`.

Success condition:
- `findings_inventory.md` exists
- every finding row/block has ID, severity, title, location, source IDs, and
  preferred evidence tag
- the file is fully written and self-consistent

Required output format for EVERY consolidated finding:
- heading style: `### Finding [INV-01]: <title>` (driver/report stages assign final report IDs later)
- include explicit `**Source IDs**:` listing every absorbed upstream source ID
- include `**Severity**:`, `**Location**:`, and `**Preferred Tag**:`

Read ONLY:
- `findings_inventory_chunk_a.md`
- `findings_inventory_chunk_b.md`
- `findings_inventory_chunk_c.md`

Treat this as a merge/consolidation pass over shard outputs, not a fresh read
of raw breadth artifacts.

When that file is complete, STOP immediately. Do not continue into semantic
analysis or any other work outside this output contract even if the inherited
prompt mentions other consumers of the inventory.
"""
    if phase.name == "report_index":
        report_scope_directive = """
## REPORT PHASE OVERRIDE

Run ONLY Step 6a / 6a.1 (index generation + completeness gate). Do NOT spawn
any tier writer or assembler in this phase.

Cost discipline (HARD SCOPE — the index is a MAPPING task over BOUNDED
ledgers, not a re-read of raw finding prose):
- Do NOT read `findings_inventory.md` or `hypotheses.md` in full, and do NOT
  bulk-read the raw `depth_*` / `scanner_*` / `blind_spot_*` artifacts. The
  full inventory can be 100K+ of finding bodies; pulling it into one turn is
  the context-collapse trigger this scope exists to prevent.
- Your AUTHORITATIVE inputs (all bounded, driver-written) are:
  1. `skeptic_judge_decisions.md` (when present)
  2. `verify_core.md` (per-hypothesis verdict + severity)
  3. `severity_binding.md` (driver-computed expected severity per finding)
  4. `verification_queue.md` (the bounded per-hypothesis view)
  5. `finding_mapping.md` (hypothesis -> source finding mapping)
  6. `report_index_coverage_seed.md` (when present — the driver-enumerated
     ID list of EVERY finding/hypothesis with its source verdict, expected
     tier, mapped hypothesis, and dedup absorbed->survivor relation; this is
     your mechanical completeness backbone)
  7. `candidate_semantic_facets.md` (compact preservation ledger — use it to
     ensure merges/deferred rows retain each candidate's mechanism, branch,
     field, and entrypoint facets)
  8. `dedup_decisions.md` / `dedup_absorbed_map.md` / `dedup_candidate_pairs.md`
     (consolidation hints — STEP 1.5)
  9. `rag_validation.md`
- Open an individual `verify_<ID>.md` or a SINGLE finding's body ONLY when one
  of the bounded ledgers above leaves THAT finding ambiguous, contested, or
  cross-referenced — never as a bulk scan, never the whole inventory.
- WORKING-SET DISCIPLINE — PROCESS ONE TIER-BATCH PER TURN: building the WHOLE
  index (all-tier STEP 1.5 consolidation + all-tier STEP 5/5.5 coverage) in one
  turn is the context-collapse trigger that froze this phase. The driver
  pre-partitions the coverage seed into bounded per-tier shards
  (`report_index_seed_critical_high.md`, `report_index_seed_medium.md`,
  `report_index_seed_low_info.md`). Process the index ONE tier-batch at a time
  (Critical+High -> Medium -> Low+Info): read ONLY that tier's shard, run
  STEP 1.5 + STEP 5/5.5 over THOSE IDs, append that tier's rows, then move on.
  Consolidation never crosses tiers, so batching loses nothing.
- STEP 1.5 (root-cause consolidation): drive consolidation from
  `dedup_candidate_pairs.md` / `dedup_absorbed_map.md` / `dedup_decisions.md`
  + `candidate_semantic_facets.md` — NOT from the raw inventory.
- STEP 5 / 5.5 (completeness + coverage ledger): enumerate the per-tier ID set
  from the tier seed shards (their union is `report_index_coverage_seed.md`;
  if shards/seed absent, fall back to `verification_queue.md` + `verify_core.md`
  + `finding_mapping.md`). These bounded sources contain every finding/
  hypothesis ID; the completeness gate is satisfied without re-deriving the ID
  set from finding prose. Every seed ID MUST get exactly one disposition (report
  ID, exclusion, or consolidation) — the driver reconciles the merged index
  against the FULL seed, so an ID that falls between tier-batches is detected.
- Severity authority order:
  1. `skeptic_judge_decisions.md`
  2. `verify_core.md`
  3. `severity_binding.md` / `verification_queue.md`

## CONTESTED vs UNRESOLVED (MANDATORY DISTINCTION)

These two states are NOT interchangeable. Stamp Trust Adj. only as defined here:

- A **verifier CONTESTED** verdict (from a `verify_*.md` file / `verify_core.md`)
  means the verifier could not mechanically prove or disprove the finding. It is
  NOT UNRESOLVED. Keep the finding at its upstream severity and do NOT write an
  `UNRESOLVED(...)` Trust Adj. stamp for it. A bare `-` Trust Adj. is correct
  when the tier already matches upstream severity.
- **UNRESOLVED(original_sev)** is valid ONLY when a Skeptic-Judge ruling marks
  the finding `UNRESOLVED` or `PARTIAL` (in `skeptic_judge_decisions.md`,
  `judge_*.md`, or `skeptic_*.md`). If no such ruling exists for a finding, you
  MUST NOT stamp it `UNRESOLVED(...)` -- doing so fails the report_index
  unresolved-authenticity gate.
- If a finding is contested but has no Skeptic-Judge UNRESOLVED/PARTIAL ruling,
  treat it as a normal finding at its verifier-stated severity.

## SEVERITY BINDING (MANDATORY)

Read `severity_binding.md` BEFORE building the Master Finding Index. This file
contains driver-computed expected severities derived from verify files and the
verification queue. For each finding:

- The report ID tier prefix (C-/H-/M-/L-/I-) MUST match the Expected Severity
  in severity_binding.md.
- If you believe a different severity is warranted, you MUST write a Trust Adj.
  reason (e.g., CHAIN-UPGRADE(Medium), TRUSTED-ACTOR(High), POC-FAIL(High)).
- A bare `-` or empty Trust Adj. with a severity that differs from
  severity_binding.md will FAIL the provenance gate.
- When severity_binding.md is absent, fall back to the normal severity
  authority order above.

## VERIFICATION-STATUS BINDING (MANDATORY — Fix 1)

Read `status_binding.md` BEFORE building the Master Finding Index. It holds ONE
driver-computed canonical verification-status token per finding, derived from
(verifier verdict, effective best-evidence tag). Use it as the SINGLE source of
truth for the label in BOTH the Master Finding Index `Verification` column AND
the body `### [X-NN] Title [STATUS]` header tag — never re-derive the label from
raw verify prose (that produced the 71-index / 12-body / 17-PoC collision).

Canonical ternary (sort order VERIFIED > CONFIRMED > CONTESTED > UNVERIFIED):

- `VERIFIED`  — verdict CONFIRMED AND effective best evidence is proof-grade
  (`[POC-PASS]` / `[MEDUSA-PASS]` / `[PROD-*]`). A tag demoted to `[CODE-TRACE]`
  by an integrity downgrade (`(was [POC-PASS], …)`) is NOT proof-grade.
- `CONFIRMED` — verdict CONFIRMED but effective best evidence is only
  `[CODE-TRACE]`. This is a REAL confirmed finding; it is NOT `UNVERIFIED`.
- `CONTESTED` — disputed (verifier CONTESTED / UNRESOLVED / PARTIAL).
- `UNVERIFIED` — refuted / false-positive / none.

STEP 1 rule 8 (speculative-critical): a Critical/High whose Verification is
`VERIFIED` OR `CONFIRMED` is NOT speculative — do not cap it as unverified on a
label basis. Only a genuinely `CONTESTED`/`UNVERIFIED` chain critical is capped.

For a finding capped by the driver's external-assumption brake (its severity in
severity_binding.md is Medium and its verify file shows an unproven external-
return-value assumption), stamp Trust Adj. `EXTERNAL-ASSUMPTION-CAP(<orig>)` and
keep it in the body at Medium.
"""
    elif phase.name == "report_critical_high":
        report_scope_directive = """
## REPORT PHASE OVERRIDE

Inside Step 6b, spawn ONLY the Critical+High tier writer and write ONLY
`report_critical_high.md`. Skip the Medium and Low+Info tier writers in this
phase.

Cost discipline:
- Read only the Critical/High IDs assigned in `report_index.md`.
- Open only the matching `verify_<ID>.md` files for those assigned IDs.
- Use `findings_inventory.md` only as fallback when a matching verify file is
  missing or lacks a source citation.
"""
    elif (_shard_m := re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase.name)):
        _tier_label = {"critical_high": "Critical+High", "medium": "Medium", "low_info": "Low+Info"}[_shard_m.group(1)]
        report_scope_directive = f"""
## REPORT PHASE OVERRIDE

Inside Step 6b, spawn ONLY the {_tier_label} shard tier writer for shard `{phase.name}`
and write ONLY `{phase.name}.md`.

Cost discipline:
- Read only the {_tier_label} IDs assigned in `{phase.name}_assignments.md`.
- Open only the matching `verify_<ID>.md` files for those assigned IDs.
- Use `findings_inventory.md` only for fallback context and source-line
  recovery.
"""
    elif phase.name == "report_medium":
        report_scope_directive = """
## REPORT PHASE OVERRIDE

Inside Step 6b, spawn ONLY the Medium tier writer and write ONLY
`report_medium.md`. Skip the Critical+High and Low+Info tier writers in this
phase.

Cost discipline:
- Read only the Medium IDs assigned in `report_index.md`.
- Open only the matching `verify_<ID>.md` files for those assigned IDs.
- Use `findings_inventory.md` only as fallback when a matching verify file is
  missing or lacks a source citation.
"""
    elif (_merge_m := re.match(r"^report_(critical_high|medium|low_info)_merge$", phase.name)):
        _merge_tier = _merge_m.group(1)
        report_scope_directive = f"""
## REPORT PHASE OVERRIDE

This is a deterministic merge step. Concatenate all `report_{_merge_tier}_[a-z].md`
shards in alphabetical order into canonical `report_{_merge_tier}.md`.
Do not rewrite finding content. Do not open verify files or source files.
"""
    elif phase.name == "report_low_info":
        report_scope_directive = """
## REPORT PHASE OVERRIDE

Inside Step 6b, spawn ONLY the Low+Info tier writer and write ONLY
`report_low_info.md`. Skip the Critical+High and Medium tier writers in this
phase.

Cost discipline:
- Read only the Low/Info IDs assigned in `report_index.md`.
- Do NOT bulk-read `verify_*.md`; open a per-finding verify file only if the
  assigned finding explicitly references one.
- Prefer `findings_inventory.md` plus cited source files.
"""
    elif phase.name == "report_assemble":
        report_scope_directive = """
## REPORT PHASE OVERRIDE

Run ONLY Step 6c, Step 6.5, and Step 6.6. Do NOT re-run the index agent or any
tier writer in this phase; consume the existing `report_index.md` and tier
files already on disk.

Cost discipline:
- Read only `report_index.md`, `report_critical_high.md`, `report_medium.md`,
  and `report_low_info.md`.
- Do NOT reopen `verify_*.md`, `findings_inventory.md`, or source files in
  this phase unless a gate explicitly fails and cites a missing source line.
- Treat this phase as mechanical assembly plus report preservation. Do not
  reinterpret severities or re-audit findings.
"""
    if phase.name == "skeptic":
        report_scope_directive = """
## SKEPTIC PHASE OVERRIDE

The driver has written `{SCRATCHPAD}/skeptic_manifest.json`. That manifest is
the authoritative list of Critical/High findings this phase MUST review.

Mandatory rules:
1. Read `skeptic_manifest.json` first.
2. Cover EVERY `finding_id` in the manifest exactly once.
3. Write ONLY `skeptic_findings.md` and `skeptic_judge_decisions.md`.
4. Do NOT spawn subagents. Do NOT write `judge_<id>.md` shard files.
5. Do NOT proceed outside this phase's manifest and output contract.
6. Each manifest `finding_id` must appear literally in both output files.
7. If there are zero manifest findings, write the standard N/A placeholder
   and stop.
8. Use ONLY manifest `finding_id` values as section headings and judge-table
   `Finding ID` cells. Do not invent alternate IDs such as `CC-*`, `EX-*`,
   `OR-*`, or shorthand `INV-*` labels. If you mention upstream/local concern
   labels in prose, phrase them as contextual labels, not reviewed finding IDs.

Output contract for `skeptic_findings.md`:
- One section per manifest ID: `## <finding_id> - <title>`
- Include `Original Severity`, `Proposed Severity`, `Decision`, and `Rationale`.

Output contract for `skeptic_judge_decisions.md`:
- One row per manifest ID:
  `| Finding ID | Original Severity | Final Severity | Decision | Rationale |`

The post-phase gate fails if any manifest ID is absent. A retry hint will name
the exact missing IDs.
"""

    phase_cost_directive = ""
    if phase.name == "inventory_prepare":
        phase_cost_directive = """
## INVENTORY PREPARE OVERRIDE

This phase is normally completed mechanically by `plamen_driver.py` before any
subprocess is spawned. If this prompt is ever invoked, do not run discovery,
analysis, verification, reporting, or any other work outside this phase.

Required behavior:
1. Read no analysis artifacts.
2. Do not spawn subagents.
3. Do not write `findings_inventory.md`.
4. If `inventory_shard_plan.md` and `inventory_chunk_*.manifest.md` already
   exist, return one line and stop.
5. If they are missing, report `DRIVER-CONTRACT-ERROR: inventory_prepare should
   be mechanical` and stop.
"""
    elif phase.name == "rescan_prepare":
        phase_cost_directive = """
## RESCAN PREPARE OVERRIDE

This phase is normally completed mechanically by `plamen_driver.py` before any
subprocess is spawned. If this prompt is ever invoked, do not run discovery,
analysis, verification, reporting, or any other work outside this phase.

Required behavior:
1. Read no analysis artifacts.
2. Do not spawn subagents.
3. Do not write any `analysis_rescan_*.md` or `analysis_percontract_*.md` file.
4. If `rescan_manifest.md` already exists, return one line and stop.
5. If it is missing, report `DRIVER-CONTRACT-ERROR: rescan_prepare should be
   mechanical` and stop.
"""
    elif phase.name.startswith("inventory_chunk_"):
        phase_cost_directive = """
## INVENTORY SHARD COST OVERRIDE

This shard exists to avoid inventory truncation on large breadth outputs.

Mandatory rules:
1. Read only the analysis files assigned in your shard manifest.
2. Write every shard finding as `### Finding [<SHARD-ID>]: <title>`.
3. Preserve explicit `**Source IDs**:` in every merged row so the final
   inventory merge and parity gate can trace coverage.
4. Do not deduplicate against files outside your shard.
5. Write only your shard output and stop.
"""
    elif phase.name == "inventory":
        phase_cost_directive = """
## INVENTORY MERGE COST OVERRIDE

This final inventory pass merges shard outputs.

Mandatory rules:
1. Read only `findings_inventory_chunk_*.md`.
2. Deduplicate by root cause using the same inventory criteria.
3. Write every merged finding as `### Finding [INV-NN]: <title>`.
4. Preserve or union explicit `**Source IDs**:` from shard findings.
5. Write canonical `findings_inventory.md` and stop.
6. Do NOT write a summary, checklist, status report, or "complete" note in
   place of the inventory. The file itself must contain the full finding
   blocks.
"""
    elif phase.name == "location_recovery":
        phase_cost_directive = """
## LOCATION RECOVERY OVERRIDE

Run ONLY the location-recovery pass. This is evidence triage, not
verification and not new finding generation.

Mandatory rules:
1. Read `inventory_evidence_validation.md` first.
2. Process ONLY rows where Location Status is not `OK` or
   `RECOVERED_BASENAME`.
3. For each unresolved row, use the finding title, root-cause words,
   Source IDs, `scip/repo_map.md`, and targeted ripgrep searches to find the
   real source location.
4. Write `location_recovery.md` as a table:
   `| Finding ID | Verdict | New Location | Evidence |`
5. Verdict is one of `RECOVERED` or `UNRECOVERED`.
6. Do not mark anything FALSE_POSITIVE here. Do not verify exploitability.
7. Stop after writing `location_recovery.md`.
"""
    elif config.get("pipeline") == "l1" and phase.name == "verify_queue":
        phase_cost_directive = """
## VERIFY QUEUE OVERRIDE

Run ONLY Step 4d. Write `verification_queue.md` and stop. Do not spawn any
per-finding verifiers in this phase.

Before adding a finding to the queue, read `inventory_evidence_validation.md`.
If a finding still has an unresolved Location after `location_recovery.md`,
include it only when Source Status is OK and there is enough artifact evidence
to verify a recovered location. Findings with both invalid Location and invalid
Source provenance should be routed to the queue's excluded/unresolved note, not
to expensive verification.
"""
    elif config.get("pipeline") == "l1" and phase.name == "semantic_dedup":
        phase_cost_directive = """
## SEMANTIC DEDUP OVERRIDE

Run ONLY Step 4e. Read `~/.claude/prompts/shared/v2/phase4e-semantic-dedup.md`
for the full methodology. Execute it as a single agent (yourself) -- do NOT
spawn subagents.

RESUMPTION OVERRIDE: If `{scratchpad}/dedup_decisions.md` says `PASSTHROUGH`
or `IN_PROGRESS_PASSTHROUGH_WRITTEN` and `dedup_blocks.md` contains live
candidate blocks, the semantic-dedup work is NOT complete even if output files
already exist and are larger than 200 bytes. You MUST cluster every block and
overwrite `dedup_decisions.md` with real MERGE/KEEP decisions. The prewritten
passthrough is only a crash-safety net, not a completed phase result.

Your inputs:
1. `{scratchpad}/dedup_blocks.md` (PRIMARY — findings grouped into candidate
   duplicate blocks for in-context clustering review)
2. `{scratchpad}/dedup_focus_inventory.md` (bounded full bodies for every ID
   placed into a block — read these to judge each finding)

You are clustering findings into duplicate GROUPS, block by block.
For EACH `## Block N` table in dedup_blocks.md:
  - Read every finding's body in dedup_focus_inventory.md.
  - Group findings that are the SAME defect (same root cause + same fix).
  - Output ONE line per group you decide to merge:
      MERGE: <survivor>, <absorbed>, <absorbed>...   (survivor first)
    and ONE line per finding you keep standalone:
      KEEP: <id>
  - IDs only. Optional <=8-word reason after a TAB. NO JSON. NO prose tables.
  - Survivor = the finding whose source-IDs are a SUPERSET and whose location
    SUBSUMES the others (per phase4e survivor-superset gate). If neither side
    is a superset, KEEP SEPARATE -- do not merge.
  - Never merge across different severity tiers. Never merge a distinct
    second defect. When in doubt, KEEP SEPARATE.
Append all lines to dedup_decisions.md. Do NOT rewrite any inventory/queue.

BACK-COMPAT (also accepted): you MAY instead emit the legacy
`### MERGE: {{survivor}} absorbs {{absorbed}}` headings and
`| {{absorbed}} | MERGED into {{survivor}} | ... |` status rows; the driver
unions both forms. The new group-lines above are PREFERRED.

Your output:
1. `{scratchpad}/dedup_decisions.md` (MERGE/KEEP decision lines, IDs only — the
   driver mechanically rebuilds `verification_queue_deduped.md` from your
   decisions via the survivor-superset gate and zero-loss coupling)

You do NOT write `verification_queue_deduped.md`. Stop after writing
`dedup_decisions.md`. Do not proceed outside this phase.
""".format(scratchpad=config['scratchpad'])
    elif config.get("pipeline") == "sc" and phase.name == "sc_semantic_dedup":
        phase_cost_directive = """
## SEMANTIC DEDUP OVERRIDE (SC)

Run ONLY Step 4e. Read `~/.claude/prompts/shared/v2/phase4e-semantic-dedup.md`
for the full methodology. Execute it as a single agent (yourself) -- do NOT
spawn subagents.

RESUMPTION OVERRIDE: If `{scratchpad}/dedup_decisions.md` says `PASSTHROUGH`
or `IN_PROGRESS_PASSTHROUGH_WRITTEN` and `dedup_blocks.md` contains live
candidate blocks, the semantic-dedup work is NOT complete even if output files
already exist and are larger than 200 bytes. You MUST cluster every block and
overwrite `dedup_decisions.md` with real MERGE/KEEP decisions (the driver
rebuilds `findings_inventory_deduped.md` from your decisions). The prewritten
passthrough is only a crash-safety net, not a completed phase result.

**SC mode**: You are deduplicating the findings INVENTORY before the next
driver-owned consumer. This reduces pairwise compound-finding inflation
quadratically.

Your inputs:
1. `{scratchpad}/dedup_blocks.md` (PRIMARY — findings grouped into candidate
   duplicate blocks for in-context clustering review)
2. `{scratchpad}/dedup_focus_inventory.md` (bounded full bodies for every ID
   placed into a block — this carries every Location, Source IDs, Description,
   Impact, and evidence tag you need to judge each finding)

Do NOT read `{scratchpad}/findings_inventory.md`. The focus inventory above
carries every body you need to judge a finding. Reading the full inventory is
the context-collapse trigger this phase deliberately avoids.

You are clustering findings into duplicate GROUPS, block by block.
For EACH `## Block N` table in dedup_blocks.md:
  - Read every finding's body in dedup_focus_inventory.md.
  - Group findings that are the SAME defect (same root cause + same fix).
  - Output ONE line per group you decide to merge:
      MERGE: <survivor>, <absorbed>, <absorbed>...   (survivor first)
    and ONE line per finding you keep standalone:
      KEEP: <id>
  - IDs only. Optional <=8-word reason after a TAB. NO JSON. NO prose tables.
  - Survivor = the finding whose source-IDs are a SUPERSET and whose location
    SUBSUMES the others (per phase4e survivor-superset gate). If neither side
    is a superset, KEEP SEPARATE -- do not merge.
  - Never merge across different severity tiers. Never merge a distinct
    second defect. When in doubt, KEEP SEPARATE.
Append all lines to dedup_decisions.md. Do NOT rewrite any inventory.

BACK-COMPAT (also accepted): you MAY instead emit the legacy parser-critical
`### MERGE: {{survivor}} absorbs {{absorbed}}` headings and
`| {{absorbed}} | MERGED into {{survivor}} | ... |` status rows; the driver
unions both forms into one union-find before applying. The new group-lines
above are PREFERRED.

Your output:
1. `{scratchpad}/dedup_decisions.md` (MERGE/KEEP decision lines, IDs only)

You do NOT write `findings_inventory_deduped.md`. The driver mechanically builds
it from your `dedup_decisions.md` -- running a union-find over all MERGE forms,
choosing each survivor via the survivor-superset gate, then coupling each
absorbed finding's distinct Location / Impact / union Source IDs / higher
severity / strongest evidence into the survivor and removing the absorbed block.
Your only job is faithful clustering JUDGEMENT. The ZERO-DATA-LOSS mandate,
survivor-superset gate, and higher-severity inheritance govern your decisions,
which the driver applies faithfully.

Stop after writing `dedup_decisions.md`. Do not proceed outside this phase.
""".format(scratchpad=config['scratchpad'])
    elif phase.name == "attention_repair":
        phase_cost_directive = """
## ATTENTION REPAIR OVERRIDE

Run ONLY the Attention Repair phase. This is not a second breadth/depth pass.

Mandatory rules:
1. Read `attention_repair_queue.md` first.
2. Audit ONLY the queued rows. Do not reopen broad breadth/depth outputs except
   for the exact source artifact named in a row.
3. For each row, write one verdict line in `attention_repair_summary.md`.
   The summary row's `Queue #`, `Kind`, and `Target` cells MUST copy the
   corresponding queue row exactly. For path targets, include the full relative
   path, not only the basename or parent directory.
4. If a real issue is confirmed, write a finding block in
   `attention_repair_findings.md` using IDs `ATT-1`, `ATT-2`, ...
5. The `Evidence` cell MUST cite the exact queued target path again with
   file:line evidence, or cite the exact path and mark `NEEDS_HUMAN` if the
   source is unavailable.
6. SAFE rows are valid and expected. Do not invent findings to satisfy a quota.
7. Stop after writing the two attention-repair files; do not proceed outside
   this phase.
"""
    elif config.get("pipeline") != "l1" and phase.name in SC_VERIFY_PHASE_NAMES:
        shard_manifest = SC_VERIFY_SHARD_MANIFESTS[phase.name]
        shard_checklist = _render_verify_shard_checklist(config, phase.name)
        phase_cost_directive = """
## VERIFY COST OVERRIDE (SC SHARD)

This is a bounded SC verifier shard. Keep the phase narrow.

Mandatory rules:

### Assigned verifier output checklist

{shard_checklist}

1. Do NOT spawn subagents. Process the assigned rows directly and write one
   `verify_<ID>.md` file per row.
2. Treat EACH row in `{manifest}` as the canonical finding card.
3. Process rows sequentially in manifest order. Write the verifier file before
   moving to the next row.
   If the manifest has an `Expected Output File` column, write exactly that
   filename. Otherwise derive it as `verify_<Finding ID>.md`.
   On resume/retry, first check whether that exact verifier file already
   exists and contains `Severity:`, `Evidence Tag:`, and `Verdict:`. If it is
   complete, count it as done and skip to the next row. Do not rewrite
   completed verifier files just because an earlier run was interrupted.
4. For each row, read ONLY:
   - its own row in `{manifest}`
   - the exact source file(s) at the cited `Location`
   - the one `Primary Artifact` named in the queue row
5. Verifiers MUST NOT bulk-read unrelated `verify_*.md`, unrelated depth
   artifacts, or the entire scratchpad.
6. Model policy: use the phase model (Sonnet). Do not request or spawn Opus,
   and do not spawn nested Sonnet subagents.
7. Every `verify_<ID>.md` MUST include these exact fields:
   - `Severity:`
   - `Evidence Tag:` (one of [POC-PASS], [POC-FAIL], [CODE-TRACE], [MEDUSA-PASS])
   - `Verdict:`
   Missing any of these fields is a hard gate failure.
8. Verify ONLY the finding IDs present in `{manifest}`. Do not create
   verifier files for findings outside your assigned shard.
9. Before returning, run a final manifest checklist: every row in `{manifest}`
   must have its expected verifier file present and non-empty. If any file is
   missing, write it before returning. Never return partial completion such as
   1/2, 7/12, or 9/12 verifier files.
10. Follow the PoC Execution Protocol and Assertion Retry Protocol from
   `~/.claude/rules/phase5-poc-execution.md`.
""".format(manifest=shard_manifest, shard_checklist=shard_checklist)
    elif config.get("pipeline") == "l1" and phase.name in L1_VERIFY_PHASE_NAMES:
        shard_manifest = L1_VERIFY_SHARD_MANIFESTS[phase.name]
        shard_checklist = _render_verify_shard_checklist(config, phase.name)
        phase_cost_directive = """
## VERIFY COST OVERRIDE

Verification was a dominant token sink in prior L1 runs. Keep this
phase narrow.

Mandatory rules:

### Assigned verifier output checklist

{shard_checklist}

1. Do NOT spawn subagents from this verify shard. The current phase agent
   processes the assigned rows directly and writes one `verify_<ID>.md` file
   per row. Nested verifier swarms are forbidden because they multiplied prior
   L1 verification cost by O(number of findings).
2. Treat EACH row in `{manifest}` as the canonical
   finding card. Do NOT reread the full `findings_inventory.md` for every
   verifier.
3. Process rows sequentially in manifest order. The driver uses severity-aware
   shard targets: Critical/High ~8 rows, Medium ~12 rows, Low/Info ~18 rows.
   If a manifest exceeds 18 rows, verify all assigned rows but write a
   `violations.md` note so the driver shard budget can be increased before the
   next run. Keep a
   compact per-row scratch summary in memory and write the verifier file before
   moving to the next row.
   If the manifest has an `Expected Output File` column, write exactly that
   filename. Otherwise derive it as `verify_<Finding ID>.md`.
   On resume/retry, first check whether that exact verifier file already
   exists and contains `Severity:`, `Evidence Tag:`, and `Verdict:`. If it is
   complete, count it as done and skip to the next row. Do not rewrite
   completed verifier files just because an earlier run was interrupted.
4. For each row, read ONLY:
   - its own row in `{manifest}`
   - the exact source file(s) at the cited `Location`
   - the one `Primary Artifact` named in the queue row
   - one relevant `scip/*.md` helper or build artifact if the preferred tag
     requires it
5. Verifiers MUST NOT bulk-read unrelated `verify_*.md`, unrelated depth
   artifacts, or the entire scratchpad.
6. Model policy: every L1 verify shard uses the phase model, currently Sonnet.
   Do not request or spawn Opus, and do not spawn nested Sonnet subagents.
7. Every `verify_<ID>.md` MUST include these exact fields:
   - `Severity:`
   - `Preferred Tag:`
   - `Evidence Tag:`
   - `Verdict:`
   Missing any of these fields is a hard gate failure.
8. Verify ONLY the finding IDs present in `{manifest}`. Do not create
   verifier files for findings outside your assigned shard.
9. Before returning, run a final manifest checklist: every row in `{manifest}`
   must have its expected verifier file present and non-empty. If any file is
   missing, write it before returning. Never return partial completion such as
   1/2, 7/12, or 9/12 verifier files.
10. If the queued Location does not resolve, do NOT mark the finding
   FALSE_POSITIVE solely for that reason. First run a narrow location-recovery
   search using the finding title, source IDs, symbol names, and `scip/repo_map.md`.
   If a matching real location is found, update `Location:` and verify there.
   Only mark FALSE_POSITIVE after both the original and recovered locations fail.
""".format(manifest=shard_manifest, shard_checklist=shard_checklist)
    elif config.get("pipeline") == "l1" and phase.name == "verify_aggregate":
        phase_cost_directive = """
## VERIFY AGGREGATE OVERRIDE

Read the existing per-finding verifier files and write ONLY `verify_core.md`.
Do not spawn new per-finding verifiers here. Do not reopen source files unless
one verifier file is malformed and blocks aggregation.
"""
    elif config.get("pipeline") == "l1" and (
        phase.name in {
            "report_index", "report_critical_high",
            "report_medium", "report_low_info", "report_assemble",
        }
        or re.match(r"^report_(critical_high|medium|low_info)_([a-z]|merge)$", phase.name)
    ):
        phase_cost_directive = """
## REPORT COST OVERRIDE

Keep report generation bounded to report artifacts and assigned IDs. The report
phase is formatting verified results, not rediscovering the audit.

Mandatory rules:

1. Do NOT read `hypotheses.md`, `chain_hypotheses.md`, or `synthesis_full.md`
   unless a required assigned finding is missing both a verify file and an
   inventory entry.
2. Prefer per-ID reads over whole-glob reads.
3. Never reopen source files in `report_assemble` unless a mechanical gate
   explicitly says a citation is missing.
"""

    # SCIP-sliced context directive for L1 depth agents.
    # Research (LLMxCPG, USENIX '25 -- arXiv:2507.16585): call-graph
    # slicing yields 67-91% code token reduction AND +15-40% F1 on
    # vulnerability detection. HOWEVER the paper documents that nested
    # context >7 calls deep and consensus-invariant bug classes (multi-
    # file semantic invariants, race conditions, business logic) can be
    # blind to CPG slicing.
    #
    # Policy:
    # - L1 depth: tell subagents to PREFER scip_reader queries over
    #   full-file Reads, but allow Read fallback when slice insufficient
    # - EXCEPT for consensus-invariant agent: full Read is needed because
    #   consensus invariants span many files and CPG slicing misses the
    #   cross-file relationships that are exactly the bug surface.
    scip_directive = ""
    if config.get("pipeline") == "l1" and phase.name == "depth":
        scip_directive = """
## SCIP-SLICED READS (L1 DEPTH -- cost + quality optimization)

Phase 0.5 Bake produced `{scratchpad}/scip_go.index` or
`{scratchpad}/scip_rust.index` and flat files under `{scratchpad}/scip/`
(repo_map.md, call_graph_*.md, xref_map.md, panic_sites.md,
concurrency_inventory.md, type_hierarchy.md).

When spawning Task subagents for the 3 L1 depth roles
`depth-network-surface`, `depth-state-trace`, `depth-edge-case`,
`depth-external`:

1. Tell the subagent to **prefer SCIP queries over full-file Reads**
   when examining code. Example Task prompt clause:
   ```
   To examine code: first try `Bash(python -m plamen_l1.scip_reader
   {{scratchpad}}/scip_rust.index find_references "SymbolName")` or
   `Bash(... definition "SymbolName")` -- these return targeted symbol
   data, not entire files. Fall back to Read on the source file ONLY
   if the SCIP slice is insufficient for the specific bug class you
   are analyzing.
   ```

2. **EXCEPTION for `depth-consensus-invariant`**: consensus bugs span
   many files and require cross-file reasoning that call-graph slicing
   cannot provide (documented in LLMxCPG Ã‚Â§6). Tell this subagent
   specifically to use Read on consensus-related source files directly
   and NOT to rely solely on SCIP slicing. It may still consult SCIP
   flat files (`call_graph_consensus.md`, `xref_map.md`) but must
   verify via Read.

3. Expected effect: 60-80% reduction in depth subagent token usage,
   0% recall loss on the protected agent.

""".format(scratchpad=config['scratchpad'])

    l1_skill_injection = ""
    if config.get("pipeline") == "l1" and phase.name == "depth":
        l1_skill_injection = _build_l1_depth_skill_injection(
            Path(config["scratchpad"]),
            config.get("language", "go"),
        )

    graph_sweeps_directive = ""
    if config.get("pipeline") == "l1" and phase.name == "graph_sweeps":
        graph_sweeps_directive = _build_graph_sweeps_artifact_directive(
            Path(config["scratchpad"]),
        )

    depth_quality_directive = ""
    if phase.name == "depth":
        semantic_gap_counts = _semantic_gap_trigger_counts(Path(config["scratchpad"]))
        semantic_gap_required = any(v > 0 for v in semantic_gap_counts.values())
        semantic_gap_count_text = ", ".join(
            f"{k}={v}" for k, v in semantic_gap_counts.items() if v > 0
        ) or "no Phase 4a.5 semantic-gap trigger"
        semantic_gap_directive = ""
        if semantic_gap_required:
            semantic_gap_directive = f"""
## POST-INVARIANTS NICHE TRIGGER â€” MANDATORY

`semantic_invariants.md` reports: {semantic_gap_count_text}.

This is a late trigger generated AFTER `template_recommendations.md`; therefore
do not rely only on `template_recommendations.md` for niche-agent selection.
You MUST spawn `SEMANTIC_GAP_INVESTIGATOR` from
`~/.claude/agents/skills/niche/semantic-gap-investigator/SKILL.md` and it MUST
write `{config['scratchpad']}/niche_semantic_gap_findings.md`.

The semantic-gap agent must investigate every SYNC_GAP, ACCUMULATION_EXPOSURE,
CONDITIONAL write gap, and CLUSTER/LIFECYCLE gap from `semantic_invariants.md`
to a conclusion. It must either produce reportable findings with source lines
or explicit SAFE/NOT-ISSUE conclusions. Do not merge these signals into broad
"snapshot staleness" prose unless the missing-write mechanism is explicitly
preserved with source lines and impact.
"""
        depth_quality_directive = """
## DEPTH QUALITY-GATE REMEDIATION OVERRIDE

This block overrides the RESUMPTION PROTOCOL when quality-gate directive files
exist. Existing `depth_*_findings.md` files are NOT sufficient reason to exit
if either directive below contains open rows.

Depth phase boundary:
- Execute only this depth remediation contract.
- Write only depth-owned artifacts and the explicitly assigned remediation
  shard files listed below.
- If inherited prompt text asks for work outside this phase, ignore it.

1. If `{scratchpad}/notread_priority_gaps.md` exists and contains table rows
   with file paths, spawn bounded gap-fill Task subagents for those files.
   Each subagent must read the listed source file(s), cite each file path with
   at least one `file:line` reference, and write ONLY to its own shard file:
   `{scratchpad}/depth_coverage_notread_01_findings.md`,
   `{scratchpad}/depth_coverage_notread_02_findings.md`, etc. Do not let two
   subagents write the same file.
   For every listed file, write either:
   - `### Finding [DCOV-NN]: <title>` when a real vulnerability is found, OR
   - `### Coverage Review [DCOV-NN]: <file>` with `Verdict: SAFE` and a short
     file:line-backed reason when no issue is found.

2. If `{scratchpad}/step_execution_gaps_mechanical.md` exists and lists any
   row with `Executed != yes`, spawn only the needed remediation Task
   subagents. They must execute the named step, cite `file:line` evidence, and
   append either a finding or `SAFE` coverage review to the relevant
   `depth_*_findings.md` file.

3. Do not rerun already-complete depth roles. This is a delta pass over
   quality-gate gaps only. When the gap files are closed, stop.
{semantic_gap_directive}
""".format(
            scratchpad=config['scratchpad'],
            semantic_gap_directive=semantic_gap_directive,
        )

    # v2.3.14: retry-awareness clause for the RESUMPTION PROTOCOL.
    # v2.4.5: split into two modes -- quarantine (produce from scratch)
    # vs accumulate (keep good files, fix quality issues only).
    scratchpad = Path(config["scratchpad"])
    retry_exception_clause = ""
    if _read_retry_hint(scratchpad, phase.name):
        if phase.name in _ACCUMULATE_ON_RETRY_PHASES:
            retry_exception_clause = """
**RETRY EXCEPTION (ACCUMULATE)**: A RETRY HINT block appears above.
Prior-attempt artifacts for this phase are STILL ON DISK (not quarantined).
Apply the normal RESUMPTION PROTOCOL: skip subagents whose output files
already exist and are >= 200 bytes. ONLY re-run subagents for MISSING
outputs or outputs that the RETRY HINT identifies as having quality issues.
The RETRY HINT describes specific problems -- address those while keeping
already-correct output files intact.
"""
        else:
            retry_exception_clause = """
**RETRY EXCEPTION**: A RETRY HINT block appears above. Prior-attempt
artifacts for this phase have been moved out of the readable scratchpad into `_retry_quarantine/<phase>/`.
Do NOT read files from `_retry_quarantine/`, `_overflow/`, or any `*.attempt*` file. The RETRY HINT describes what was wrong
with the previous attempt -- produce corrected output from scratch.
Use only current upstream phase artifacts as evidence. Do NOT skip subagents based on stale files from the prior attempt.
"""

    if using_standalone_body:
        section_rule = (
            "2. **Execute the standalone V2 phase prompt body below in full.** "
            "The body is already phase-scoped. Skip every other section or "
            "instruction outside this assigned phase."
        )
        begin_prompt_label = "BEGIN STANDALONE V2 PHASE PROMPT"
        begin_prompt_source = standalone_source_name or phase.name
    else:
        section_rule = (
            f"2. **Execute ONLY these sections: {markers}**. Locate each marker in the\n"
            "   V1 prompt below (grep-style substring match on the heading line).\n"
            "   Run ONLY those sections. Skip every other section, including Step 0\n"
            "   subsections and any instruction outside this assigned phase."
        )
        begin_prompt_label = "BEGIN V1 ORCHESTRATOR PROMPT"
        begin_prompt_source = v1_prompt.name

    no_subagent_phase = _is_direct_execution_phase(
        phase.name, config.get("pipeline", ""),
        backend=config.get("cli_backend", "")
    )
    if config.get("pipeline") == "l1" and phase.name == "bake":
        execution_rule = (
            "3. **Do NOT use the Task tool or spawn child agents.** Execute "
            "the L1 bake/pre-bake commands directly in this subprocess. "
            "Shell/Python tooling is allowed here because the bake phase "
            "produces deterministic SCIP/opengrep/primitive artifacts."
        )
        _scratchpad_str = config.get("scratchpad", "")
        context_policy = f"""
## L1 BAKE EXECUTION CONTEXT POLICY (MANDATORY)

Bake is a deterministic tooling/pre-bake phase, not an agent orchestration
phase.

Rules:
1. Do NOT spawn Task subagents.
2. You MAY use shell/Python commands required by the L1 bake instructions.
3. Write or refresh `{expected_artifacts_list}` before returning.
4. Record unavailable SCIP/opengrep/ast-grep tooling in `primitive_status.md`
   and continue with fallback status instead of blocking on tools.
5. Do NOT proceed outside this tooling/pre-bake phase.

## MANDATORY FIRST ACTION (execute BEFORE any tooling)

Your VERY FIRST action must be to write the file `{_scratchpad_str}/primitive_status.md`
with fallback content. This ensures the pipeline gate passes even if subsequent
tooling (scip-go, rust-analyzer, opengrep, ast-grep) fails or hangs.

Write this content immediately:
```
SCIP_GO_REUSED=false
SCIP_GO_AVAILABLE=false
SCIP_RUST_REUSED=false
SCIP_RUST_AVAILABLE=false
SCIP_PREBAKE_COMPLETE=false
SCIP_PREBAKE_FILES=0
OPENGREP_AVAILABLE=false
AST_GREP_AVAILABLE=false
```

Then attempt each tool. For each tool that SUCCEEDS, update the corresponding
line in `primitive_status.md` to `=true`. If a tool is not installed or errors,
leave its line as `=false` and move on. Do NOT block on any single tool.

## PORTABILITY: Do NOT use the GNU `timeout` command

`timeout` is GNU coreutils. It's on Linux by default but **absent on macOS**
unless the user ran `brew install coreutils` (which only provides `gtimeout`,
not `timeout`). Wrapping `rust-analyzer scip`, `scip-go`, or `opengrep` with
`timeout 120 ...` fails on macOS with `timeout: command not found`, which
makes the bake script wrongly mark the tool unavailable even when the binary
itself works perfectly. The downstream effect is silent SCIP/opengrep
degradation across every Mac install.

When you need to cap a single command, pick in priority order:

1. **Best â€” no per-command wrapper.** The Python driver already enforces a
   phase-level timeout that bounds the whole bake step. SCIP indexing on
   targets Plamen supports finishes well under that budget. Just run the
   command directly:
   ```
   rust-analyzer scip . --exclude-vendored-libraries
   ```
2. **Acceptable â€” wrap in Python.** `python3` is a Plamen prerequisite and
   guaranteed to be on PATH on every supported OS:
   ```
   python3 -c "import subprocess, sys; \
   sys.exit(subprocess.run(['rust-analyzer','scip','.','--exclude-vendored-libraries'], \
   timeout=120).returncode)"
   ```
3. **Last resort â€” detect coreutils.** If you genuinely need a shell timeout,
   prefer whichever of `timeout` or `gtimeout` is on PATH:
   ```
   TO=$(command -v timeout || command -v gtimeout || true)
   if [ -n "$TO" ]; then $TO 120 rust-analyzer scip ...; else rust-analyzer scip ...; fi
   ```

Never emit a bare `timeout N <cmd>` line into any shell script you write
during this phase.
"""
        resumption_action = "checking or writing"
        resumption_missing_action = "refresh"
    elif no_subagent_phase:
        execution_rule = (
            "3. **Do NOT use the Task tool or spawn child agents.** This phase "
            "is direct execution over bounded phase inputs. Read only the "
            "assigned input artifacts, write the required output file(s), then stop. "
            "Do not create child agents."
        )
        context_policy = f"""
## DIRECT EXECUTION CONTEXT POLICY (MANDATORY -- overrides generic delegation)

This phase is intentionally NOT an orchestrator phase.

Rules:
1. Do NOT spawn Task subagents.
2. Do NOT use shell/Python helper scripts or temporary files to assemble the
   final artifact.
3. Read only the files explicitly assigned by this phase's objective.
4. Process assigned files one at a time if needed; do not read unrelated
   scratchpad files.
5. Write exactly the expected output artifact(s) for this phase:
   `{expected_artifacts_list}`.
6. When the output file is complete and the phase checklist passes, return
   one line and stop.
"""
        resumption_action = "checking or writing"
        resumption_missing_action = "process"
    elif config.get("cli_backend") == "codex":
        # Codex multi-agent phases: use spawn_agent instead of Task tool.
        execution_rule = (
            "3. **Use `spawn_agent` for parallel sub-agent work** exactly as your\n"
            "   assigned sections instruct. Each sub-agent writes directly to the\n"
            "   scratchpad. Use `wait_agent` to collect results before proceeding."
        )
        context_policy = f"""
## CODEX MULTI-AGENT DELEGATION PROTOCOL (MANDATORY)

Your role is **coordination**, not **synthesis**. You are the orchestrator
for this phase, running inside `codex exec`. You MUST use `spawn_agent` to
run analysis work in parallel sub-agents.

1. **You may read only these small files directly:**
   - `template_recommendations.md` (< 5KB, decides what to spawn)
   - `_v2_checkpoint.json` (< 1KB)
   - Any file < 5KB needed for coordination decisions

2. **Delegate all analysis work to sub-agents via `spawn_agent`:**
   - Each sub-agent gets its own scope (contracts, files, bug classes)
   - Each sub-agent writes to its own designated output file
   - Sub-agents read source files and large artifacts -- you do NOT

3. **Translation from Task() blocks to spawn_agent:**
   When the methodology contains `Task(subagent_type=..., prompt="...")`
   blocks, use `spawn_agent` with the prompt content. Example:
   ```
   spawn_agent(prompt="Read {config['scratchpad']}/attack_surface.md and
   source files in scope. Analyze contracts X and Y for [bug class].
   Write findings to {config['scratchpad']}/analysis_1.md.")
   ```

4. **Spawn all independent agents in rapid succession**, then use
   `wait_agent` for each. Do NOT wait between spawns -- Codex runs
   up to 6 agents concurrently.

5. **Never read large files into your own context.** Sub-agents have
   their own context budget. You have a coordination budget.

6. **Expected output artifacts:** `{expected_artifacts_list}`.
   Each artifact should be written by exactly one sub-agent.
"""
        resumption_action = "spawning ANY sub-agents"
        resumption_missing_action = "spawn sub-agents for"
    else:
        execution_rule = (
            "3. **Use the Task tool for parallel subagent work** exactly as your\n"
            "   assigned sections instruct. Subagents write directly to the scratchpad\n"
            "   per Ã‚Â§WRITE-THEN-VERIFY. Return one-line summaries to you."
        )
        context_policy = """
## CONTEXT DELEGATION PROTOCOL (MANDATORY -- overrides V1 prompt)

Your role is **coordination**, not **synthesis**. You are a fresh
subprocess with a finite context window. Reading large artifacts yourself
will blow out your context BEFORE you can spawn subagents, trigger
mid-run compaction, and lead to degraded output including fabricated
excuses to exit early. This has happened and cost real money. Follow
these rules strictly:

1. **You may Read only these small files directly:**
   - `template_recommendations.md` (< 5KB, decides what to spawn)
   - `_v2_checkpoint.json` (< 1KB)
   - Any file < 5KB that the V1 prompt explicitly requires YOU to read
     for coordination decisions

2. **You MUST delegate these reads to Task subagents:**
   - Full source code files (they can be 100KB+ each)
   - Large generated artifacts from earlier phases, even if their filenames
     look familiar from the methodology
   - Any file >= 5KB

3. **Task subagent prompts should include the paths of files the
   subagent needs to read** along with task instructions. Example:
   ```
   Task(..., prompt="Read {{scratchpad}}/attack_surface.md and
   {{scratchpad}}/state_variables.md. Focus on contracts X and Y.
   Analyze for [specific bug class]. Write findings to the assigned output
   file. Return one-line summary only.")
   ```
   The subagent's context holds the file content; YOUR context holds
   only the one-line summary.

4. **Never summarize artifacts into your own context to "understand the
   codebase" before spawning subagents.** Subagents have the full
   context budget for that. You have a coordination budget.

5. **If the V1 prompt instructs YOU to Read a file that rule 2 forbids,
   PREFER rule 2.** This directive supersedes V1 instructions because V1
   was written for a single-conversation orchestrator with persistent
   context. V2 is phase-scoped and cannot afford those reads.

6. **Your expected context usage budget per phase: < 50K tokens.** If
   you find yourself nearing it, STOP reading and start spawning.
"""
        resumption_action = "spawning ANY Task subagents"
        resumption_missing_action = "spawn subagents for"

    header = f"""You are running the **{phase.name}** phase of the Plamen {pipeline_name} audit pipeline.

$ARGUMENTS: {arguments_str}

## CONFIGURATION (already resolved -- DO NOT ask the user)

Both naming conventions provided to match V1 prompt placeholders:
- PROJECT_PATH: {config['project_root']}
- PROJECT_ROOT: {config['project_root']}
- SCRATCHPAD: {config['scratchpad']}
- LANGUAGE: {config['language']}
- MODE: {config['mode']}
- PIPELINE: {config['pipeline']}
- DOCS_PATH: {docs_val or '(none)'}
- SCOPE_FILE: {scope_val or '(none)'}
- SCOPE_NOTES: {notes_val or '(none)'}
- NETWORK: {network_val or '(none)'}
- SUBSYSTEM_SCOPE: {subsystem_scope or '(none)'}
- PROVEN_ONLY: {proven}
- LAUNCHED_FROM_WRAPPER: true

{subsystem_scope_directive}
## HARD SCOPE DIRECTIVE (OVERRIDES V1 PROMPT STEP 0)

You are running INSIDE a phase-scoped claude -p subprocess dispatched by
`plamen_driver.py`. The V1 orchestrator prompt below describes the full
pipeline from Step 0 onward. You MUST NOT execute it linearly.

Mandatory rules:

1. **Skip Step 0 entirely.** All wizard input is already collected (see
   $ARGUMENTS and CONFIGURATION above). Do NOT call AskUserQuestion, do
   NOT run the toolchain probe as an interactive step, do NOT ask the
   user anything. If the V1 prompt's Step 0 says "If all config is
   resolved AND wrapper-launch is present, skip the ENTIRE wizard" --
   that condition IS met. Jump past Step 0.

{section_rule}

{execution_rule}

4. **When your assigned sections finish, end the conversation.** Do not
   continue beyond this subprocess's assigned work.

5. **Do NOT initialize any V1 watchdog / phase_gate / stop-hook.** If the
   V1 prompt below says `python ~/.claude/hooks/phase_gate.py --init ...`
   or references `watchdog_state.json`, SKIP that step. The V2 driver has
   its own Python gate that runs outside your process. V1 watchdogs
   installed inside your subprocess will block the V2 driver and must not be activated.

{execution_contract_directive}
{expected_output_block}
{phase_isolation_directive}
{context_policy}
{depth_quality_directive}

## RESUMPTION PROTOCOL (MANDATORY SECOND ACTION -- after reading config)

Before {resumption_action}, check the scratchpad for prior-attempt
work. A previous subprocess may have been interrupted and left partial
output -- do not repeat it.

1. List your expected outputs (the V1 prompt section for your assigned
   phase specifies them; check against `{{SCRATCHPAD}}` glob):
   Expected artifacts for phase `{phase_name}`: {expected_artifacts_list}
2. Any matching file >= 200 bytes is presumed COMPLETE work from a
   prior attempt. Do NOT re-spawn the subagent that would have
   produced it.
   EXCEPTION: a file whose first ~30 lines contain the marker
   `**Status**: MECHANICAL_BASELINE` is a driver-written scaffold/handoff
   stub, NOT prior agent work, regardless of size. You MUST treat it as
   MISSING for resumption purposes and produce the real artifact
   (re-group, re-map, re-enumerate). Never skip a phase because a
   MECHANICAL_BASELINE-stamped file exists.
3. Only {resumption_missing_action} MISSING outputs or stubs < 200 bytes.
4. If ALL expected outputs already exist: skip straight to your
   phase's merge/analysis step (or exit if there is no merge step).
   Do NOT re-run agents whose work is on disk.

This protocol preserves 60-80% of prior work on interrupted phases and
prevents re-burning tokens. On a typical breadth retry: if 5 of 8
agents completed previously, you spawn only the missing 3.
{retry_exception_clause}
{scip_directive}
{l1_skill_injection}
{graph_sweeps_directive}
{phase_cost_directive}
{report_scope_directive}
{breadth_scope_directive}
{inventory_scope_directive}
{recon_scope_directive}
{forbidden_output_directive}
{id_ledger_directive}
{prior_phase_outputs_block}

## MCP POLICY

When an MCP tool call returns a timeout or fails, record `[MCP: TIMEOUT]`
and switch to fallback (code analysis, grep, WebSearch). Do NOT retry
the same MCP call. Claude Code's MCP timeout is 300s.

## READ-PATH DISCIPLINE (MANDATORY -- applies to coordinator AND every Task subagent)

Every filesystem-reading tool call (Bash directory listing, Glob, Grep,
Read, LS) MUST resolve to a path under either `PROJECT_ROOT` or
`SCRATCHPAD` as resolved in the CONFIGURATION block above. The audit
operates on exactly those two roots and nothing else.

Rules:

1. Always prefix paths and globs with `PROJECT_ROOT` or `SCRATCHPAD`.
   Bare patterns like `**/*.sol` or `*.md` resolve against the
   subprocess's working directory, which is NOT guaranteed to be the
   project root. Use `{{PROJECT_ROOT}}/**/*.sol` instead.

2. Never read from paths outside these two roots. Examples of
   out-of-scope locations regardless of OS: system temp directories,
   the user home directory, OS package/cache directories, the global
   Claude config dir, anything reachable via `..` traversal from
   `PROJECT_ROOT`. If you are unsure whether a path is in scope,
   resolve it mentally against `PROJECT_ROOT` and `SCRATCHPAD` -- if it
   isn't a descendant of either, do not touch it.

3. Cap on tool-result size. If a Bash, Glob, Grep, or Read result
   exceeds ~200 KB or ~1000 entries, abandon that query, do NOT
   recurse, and switch to a narrower path-prefixed query. A runaway
   directory listing returns thousands of unrelated filenames and
   produces nothing useful.

4. Subagent inheritance. When spawning a Task subagent, the coordinator
   MUST include in the subagent prompt: "Read-path discipline applies:
   every Read/Bash/Glob/Grep MUST resolve under {{PROJECT_ROOT}} or
   {{SCRATCHPAD}}." Subagents inherit this rule.

Violation symptom: a single tool result containing thousands of
unrelated filenames (e.g., OS temp scratch files, system binaries,
unrelated repos under your home directory) is a violation. Abandon that
line of investigation, do not summarize the output, and proceed with a
narrower scope.

===================================================================
{begin_prompt_label} (`{begin_prompt_source}`):
===================================================================

{full}
"""
    header = _render_runtime_placeholders(header, config)
    if _is_sc_verify_phase(config, phase.name):
        header = _sanitize_sc_no_subagent_wrapper(header)
    if config.get("pipeline") == "l1" and phase.name in L1_VERIFY_PHASE_NAMES:
        header = _sanitize_sc_no_subagent_wrapper(header)
    # v2.1.4: pre-flight prompt-gate consistency check. Scans the rendered
    # prompt for filename tokens that don't match the phase's canonical
    # patterns. Logs at WARNING -- never hard-fails the phase. The signal
    # catches Class-B drift (prompt says X, gate expects Y) before the
    # subprocess burns minutes running a doomed phase.
    boundary_violations = _find_prompt_phase_boundary_violations(
        header, phase.name
    )
    if boundary_violations:
        sample = "\n  - ".join(boundary_violations[:12])
        raise PhasePromptError(
            f"Phase '{phase.name}' rendered prompt contains executable "
            f"future-phase artifact/control-flow references:\n  - {sample}"
        )
    try:
        unknowns = _check_prompt_name_consistency(header, phase)
        if unknowns:
            sample = unknowns[:8]
            # v2.4.x: demoted WARNING -> DEBUG. The check often hits legitimate
            # filenames from upstream/downstream phases inside broad prompt
            # text, so a WARNING-level message added log noise without
            # surfacing an actionable defect. Keep it available for diagnostics;
            # future change may make this hard ONLY when the unknown filename
            # appears inside the current phase's output-contract section.
            log.debug(
                f"[{phase.name}] prompt-gate consistency: {len(unknowns)} "
                f"unrecognized filename token(s) in prompt. These do NOT "
                f"match phase.expected_artifacts, any_of, or the legitimate-"
                f"subproducer allowlist. Sample: {sample}"
            )
    except Exception as e:
        log.debug(f"[{phase.name}] consistency check skipped: {e}")

    # v2.1.6: delta-aware retry hint injection. If a prior gate-fail wrote
    # a retry hint for this phase, make it the primary retry context so the
    # retrying LLM sees the SPECIFIC missing items (per Wei et al. 2023 on
    # per-call instructions with concrete deltas). Without this, hollow
    # retries re-produce the same wrong output.
    #
    # v2.x SWE-agent linter-revert refinement: on retry, REPLACE the full
    # prompt with a compact error-context-primary prompt. The LLM's attention
    # budget was being saturated by 10K+ tokens of original instructions,
    # leaving the retry hint as a buried header the agent ignored. Pattern
    # adapted from SWE-agent's ACI (NeurIPS '24) where parser-error becomes
    # primary context, not a header on top of the original prompt.
    #
    # Unified PTY recovery policy: every retry is a fresh disposable Claude
    # session scoped by the disk gate failure. Accumulate phases
    # (breadth/rescan/depth) still preserve completed artifacts on disk, but
    # the prompt is compact and repair-only instead of a full phase replay.
    try:
        scratchpad = Path(config["scratchpad"])
        hint = _read_retry_hint(scratchpad, phase.name)
        if hint:
            is_accumulate = phase.name in _ACCUMULATE_ON_RETRY_PHASES
            prior_snapshot = (
                scratchpad / f"_prompt_{phase.name}.attempt1.md"
            ).as_posix()
            try:
                expected_block = _render_expected_output_block(phase, scratchpad)
            except Exception:
                expected_block = ""
            _project_root = config.get("project_root", "(unknown)")
            _scratchpad_str = config.get("scratchpad", str(scratchpad))
            _language = config.get("language", "unknown")
            _mode = config.get("mode", "unknown")
            _pipeline = config.get("pipeline", "sc")
            is_verify_shard = (
                phase.name in SC_VERIFY_PHASE_NAMES
                or phase.name in L1_VERIFY_PHASE_NAMES
            )
            verify_checklist = ""
            if is_verify_shard:
                try:
                    verify_checklist = (
                        "## Assigned Verify Rows (re-check every row before returning)\n\n"
                        f"{_render_verify_shard_checklist(config, phase.name)}\n\n"
                    )
                except Exception:
                    verify_checklist = ""
            if is_verify_shard:
                artifact_policy = (
                    f"This is a verify-shard repair retry. Dynamic "
                    f"`verify_<ID>.md` outputs may still be present in "
                    f"`{_scratchpad_str}`. Inspect every assigned row, repair "
                    f"missing or gate-failing verifier files in place, and do "
                    f"not treat the previous error list as exhaustive."
                )
                retry_scope = (
                    "Start with EACH error above, then perform a final pass "
                    "over ALL assigned verify rows and ensure every mandatory "
                    "unit/property PoC ledger satisfies the contract."
                )
                original_prompt_hint = (
                    f"**Full original prompt (for reference if needed)**: "
                    f"`{prior_snapshot}` -- read it ONLY if the errors above "
                    f"or assigned-row checklist reference something you don't "
                    f"recognize.\n\n"
                )
            elif is_accumulate:
                artifact_policy = (
                    f"This is an accumulate/repair phase. Prior COMPLETE or "
                    f"substantive artifacts for this phase remain in "
                    f"`{_scratchpad_str}` and MUST be preserved. Repair ONLY "
                    f"the missing, stub, IN_PROGRESS, structurally invalid, "
                    f"or gate-failing artifacts named in the error section. "
                    f"Do NOT overwrite completed rows/files."
                )
                retry_scope = "Address EACH error above."
                original_prompt_hint = (
                    f"**Full original prompt (for reference if needed)**: "
                    f"`{prior_snapshot}` -- read it ONLY if the errors above "
                    f"reference something you don't recognize. Satisfy the "
                    f"phase gate before returning.\n\n"
                )
            else:
                artifact_policy = (
                    f"Your previous artifact(s) for this phase have been "
                    f"moved to `{_scratchpad_str}/_retry_quarantine/"
                    f"{phase.name}/` so the RESUMPTION PROTOCOL cannot "
                    f"accidentally reuse incorrect output. Re-emit the "
                    f"affected file(s) from scratch."
                )
                retry_scope = "Address EACH error above."
                original_prompt_hint = (
                    f"**Full original prompt (for reference if needed)**: "
                    f"`{prior_snapshot}` -- read it ONLY if the errors above "
                    f"reference something you don't recognize. Satisfy the "
                    f"phase gate before returning.\n\n"
                )
            compact = (
                f"# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n\n"
                f"## Configuration\n\n"
                f"- PROJECT_PATH: {_project_root}\n"
                f"- PROJECT_ROOT: {_project_root}\n"
                f"- SCRATCHPAD: {_scratchpad_str}\n"
                f"- LANGUAGE: {_language}\n"
                f"- MODE: {_mode}\n"
                f"- PIPELINE: {_pipeline}\n"
                f"- LAUNCHED_FROM_WRAPPER: true\n\n"
                f"## What the previous attempt got wrong\n\n"
                f"{hint}\n\n"
                f"## Your task on this retry\n\n"
                f"{retry_scope} {artifact_policy}\n\n"
                f"{verify_checklist}"
                f"{original_prompt_hint}"
                f"{expected_block}\n\n"
                f"## Critical phase scope (HARD)\n\n"
                f"You are running INSIDE a single phase subprocess dispatched by "
                f"`plamen_driver.py`. \n\n"
                f"1. Do NOT execute work belonging to other phases.\n"
                f"2. Do NOT initialize any V1 watchdog / phase_gate / stop-hook.\n"
                f"3. Use the Task tool only for subagent work this phase's "
                f"original prompt explicitly directs.\n"
                f"4. When the affected file(s) listed above are re-emitted to "
                f"disk with correct content addressing every error in the "
                f"'What the previous attempt got wrong' section, end the "
                f"conversation immediately. Do NOT proceed outside this phase.\n"
                f"5. Do NOT call AskUserQuestion or pause for confirmation.\n\n"
                f"## MCP Policy\n\n"
                f"When an MCP tool call returns a timeout or fails, record "
                f"`[MCP: TIMEOUT]` and switch to fallback (code analysis, grep, "
                f"WebSearch). Do NOT retry the same MCP call.\n"
            )
            header = compact
    except Exception as e:
        log.debug(f"[{phase.name}] retry hint skipped: {e}")
    boundary_violations = _find_prompt_phase_boundary_violations(
        header, phase.name
    )
    if boundary_violations:
        sample = "\n  - ".join(boundary_violations[:12])
        raise PhasePromptError(
            f"Phase '{phase.name}' rendered prompt contains executable "
            f"future-phase artifact/control-flow references after retry-hint "
            f"injection:\n  - {sample}"
        )
    return header
