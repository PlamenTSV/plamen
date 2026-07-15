#!/usr/bin/env python3
"""
Codex Adapter Generator

Reads Plamen's Claude-side manifests and generates Codex-compatible config files.
This prevents drift -- when Claude-side files change, re-running this script
updates the Codex files automatically.

Usage:
    python scripts/codex_adapter.py [--output-dir codex-adapter/]

NOTE: The output directory is named `codex-adapter/` (not `codex/`) so that
when ~/.plamen is on PATH it does not shadow the Codex CLI binary.

Sources:
    - scripts/plamen_types.py       (phase/artifact specs)
    - settings.json.example        (MCP server configs, permissions)
    - mcp.json.example             (MCP server definitions)
    - CLAUDE.md                    (orchestrator rules)
    - agents/depth-*.md            (agent role definitions)

NOTE: Phase 1 generator. Most output content is templated, not fully derived
from Claude-side manifests. The following IS manifest-driven:
  - config.toml MCP servers (from mcp.json.example)
  - Phase sequence (from plamen_types.py SC_PHASES/L1_PHASES)
  - Agent role file list (from agents/depth-*.md listing)
The following is TEMPLATED and must be updated manually if Claude-side changes:
  - AGENTS.md orchestrator rules
  - SKILL.md phase sequence
  - Agent role developer_instructions

Phase 2 goal: derive more content from CLAUDE.md and commands/plamen.md parsing.
"""

import json
import os
import sys
import textwrap
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PLAMEN_HOME = SCRIPT_DIR.parent
OUTPUT_DIR = PLAMEN_HOME / "codex-adapter"


def load_json(path: Path) -> dict:
    """Load a JSON file, return empty dict on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  Warning: Could not load {path}: {e}", file=sys.stderr)
        return {}


def toml_escape(value: str) -> str:
    """Escape a string for TOML double-quoted strings."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _windows_inherited_env() -> dict[str, str]:
    """Preserve critical Windows environment variables for wrapped MCP servers.

    Codex's `env` block replaces, rather than augments, the child environment.
    Python MCP servers on Windows need a real home/temp/PATH context to start.
    """
    if sys.platform != "win32":
        return {}

    keys = [
        "SystemRoot",
        "windir",
        "PATH",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    ]
    inherited = {}
    for key in keys:
        value = os.environ.get(key)
        if value:
            inherited[key] = value
    return inherited


# ---------------------------------------------------------------------------
# Generator: AGENTS.md
# ---------------------------------------------------------------------------

def generate_agents_md(out_dir: Path) -> None:
    """Generate codex-adapter/AGENTS.md -- condensed orchestrator rules for Codex."""
    content = textwrap.dedent("""\
    # Plamen -- Web3 Security Auditing Agent

    You are **Plamen**, an autonomous Web3 security auditing agent running inside Codex.
    Your methodology, prompts, and skill files live in `~/.codex/plamen/`.

    ## Audit Modes

    | Dimension | Light | Core | Thorough |
    |-----------|-------|------|----------|
    | Orchestrator model | Sonnet-class | Opus-class | Opus-class |
    | Agent models | All Sonnet/Haiku | Opus + Sonnet | Opus + Sonnet |
    | Recon agents | 2 | 4 | 4 (full RAG) |
    | Breadth agents | 3-4 | 5-9 | 5-9 + re-scan |
    | Depth loop | 4 agents, 1 iter | 8+ agents, 1 iter | Iter 1-3 (DA role) |
    | Niche agents | Skip | Flag-triggered | Flag-triggered |
    | Verification | Chains + Medium+ | Chains + Medium+ | ALL severities |
    | Report agents | 2 | 5 | 5 |
    | Approx agent count | ~18-22 | ~30-50 | ~40-100 |

    ## Critical Rules

    1. **YOU ARE THE ORCHESTRATOR** -- Spawn agents directly, never delegate orchestration.
    2. **MCP TOOLS VIA AGENTS** -- Recon agent calls MCP tools, not you directly.
    3. **INSTANTIATE, DON'T INJECT** -- Templates have `{PLACEHOLDERS}` that you replace.
       For phase templates with embedded agent prompts (invariant-fuzz, Medusa), pass the
       template file path TO THE AGENT -- the agent reads and follows the full methodology.
    4. **DYNAMIC AGENT COUNT** -- Scale based on protocol complexity.
    5. **PARALLEL ANALYSIS** -- All analysis agents for a phase spawn in ONE message.
       Every agent prompt for phases 3/4b MUST end with:
       `"SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents'
       output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop."`
    6. **CONTEXT PROTECTION** -- Don't read large files; agents read them.
    7. **METHODOLOGY NOT ANSWERS** -- Tell agents WHAT to analyze, not WHAT to find.
    8. **NO REPORT BEFORE VERIFICATION** -- Verify before reporting.
    9. **SEVERITY MATRIX** -- Use Impact x Likelihood.
    10. **MCP TIMEOUT POLICY** -- Agents that call MCP tools must NOT retry on timeout.
        Record `[MCP: TIMEOUT]` and switch to fallback.

    ## Phase Sequence

    Follow the phase sequence defined in `scripts/plamen_types.py` (`SC_PHASES`/`L1_PHASES`):

    ```
    Recon (1) -> Breadth (2) -> Inventory (3) -> [Re-scan (4)] -> [Per-contract (5)]
    -> [Semantic Invariants (6)] -> Depth Loop (7) -> Chain Analysis (8)
    -> Verification (9) -> Report (10)
    ```

    Phases in brackets are mode-dependent. Each phase has required artifacts that
    MUST exist before proceeding to the next phase (enforced by `plamen_driver.py` gate checks).

    ## File References

    | Purpose | Location |
    |---------|----------|
    | Finding format | `~/.codex/plamen/rules/finding-output-format.md` |
    | Confidence scoring | `~/.codex/plamen/rules/phase4-confidence-scoring.md` |
    | Chain prompt | `~/.codex/plamen/rules/phase4c-chain-prompt.md` |
    | PoC execution | `~/.codex/plamen/rules/phase5-poc-execution.md` |
    | Report prompts | `~/.codex/plamen/rules/phase6-report-prompts.md` |
    | Report template | `~/.codex/plamen/rules/report-template.md` |
    | Skill index | `~/.codex/plamen/rules/skill-index.md` |
    | Depth agents | `~/.codex/plamen/agents/depth-*.md` |
    | Language prompts | `~/.codex/plamen/prompts/{LANGUAGE}/` |
    | Skills | `~/.codex/plamen/agents/skills/{LANGUAGE}/` |

    Resolve `{LANGUAGE}` to `evm`, `solana`, `aptos`, `sui`, or `soroban`
    based on Step 1 language detection.

    ## Path Resolution (MANDATORY)

    All methodology files reference paths starting with `~/.claude/`.
    On Codex, these paths resolve to `~/.codex/plamen/` instead.

    When you see ANY path starting with `~/.claude/`:
    - Replace `~/.claude/` with `~/.codex/plamen/`
    - Example: `~/.claude/agents/skills/evm/token-flow-tracing/SKILL.md`
      becomes `~/.codex/plamen/agents/skills/evm/token-flow-tracing/SKILL.md`

    This applies to ALL file reads throughout the audit -- in methodology files,
    skill files, prompt templates, agent definitions, and any cross-references.

    ## Agent Roles

    Use the TOML role definitions in `~/.codex/agents/` to spawn sub-agents.
    Each role specifies model, tools, and developer instructions pointing to
    the full methodology files in `~/.codex/plamen/`.

    ## Artifact Discipline

    - Write ONLY to your assigned output file in the scratchpad directory.
    - The scratchpad is created at `{PROJECT_ROOT}/.scratchpad/` on audit start.
    - Each agent writes to exactly one file (e.g., `depth_token_flow_findings.md`).
    - Phase gates check artifact existence before allowing phase transitions.
    """)

    path = out_dir / "AGENTS.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Generated {path.relative_to(PLAMEN_HOME)}")


# ---------------------------------------------------------------------------
# Generator: config.toml
# ---------------------------------------------------------------------------

def generate_config_toml(out_dir: Path) -> None:
    """Generate codex-adapter/config.toml -- Codex main config with MCP server mappings."""
    # SECURITY: NEVER write real API keys into generated files.
    # Generated config.toml uses PLACEHOLDERS only. Users fill in their own keys
    # after install. This file is gitignored to prevent accidental key leaks.
    example_mcp = load_json(PLAMEN_HOME / "mcp.json.example")
    servers = example_mcp.get("mcpServers", {})

    codex_shared_root = Path.home() / ".codex" / "plamen"
    codex_shared_root_str = str(codex_shared_root).replace("\\", "/")

    lines = [
        '# Model for the orchestrator and agents that inherit from global config.',
        '# Change to match your Codex account:',
        '#   ChatGPT Plus/Pro/Team: use an ENTITLED base model (gpt-5.5 / gpt-5.4).',
        '#     `-codex`/preview suffixes (e.g. gpt-5.3-codex) are REJECTED on ChatGPT',
        '#     auth with HTTP 400 "model is not supported when using Codex with a',
        '#     ChatGPT account" (openai/codex #14735). Run `codex --available-models`.',
        '#   API key (OPENAI_API_KEY): any model, incl. larger-context variants.',
        'model = "gpt-5.4"',
        '# DO NOT set model_context_window: codex bug #16068 corrupts the token',
        '# counter when it is set, producing a bogus "context window exceeded',
        '# (~N tokens)" PERMANENT failure even on small prompts. Use server defaults',
        '# and force early compaction instead (#19409 workaround).',
        'model_auto_compact_token_limit = 220000',
        '# service_tier MUST be a built-in value (flex|fast). "default"/"priority"',
        '# are rejected by older parsers (#27297) and break spawn_agent child-model',
        '# resolution ("could not resolve the child model for service tier validation").',
        '# Children inherit model + service_tier from this top-level config.',
        'service_tier = "flex"',
        'approval_mode = "full-auto"',
        'approval_policy = "never"',
        'sandbox_mode = "danger-full-access"',
        '',
        '[agents]',
        'max_threads = 8',
        'max_depth = 1',
        '',
    ]

    import shutil

    python_bin = (
        (shutil.which("python") or sys.executable)
        if sys.platform == "win32"
        else (shutil.which("python3") or "python3")
    )
    slither_bin = shutil.which("slither-mcp") or "slither-mcp"
    node_bin = shutil.which("node") or "node"
    node_wrapper = (
        f"{codex_shared_root_str}/mcp-packages/run-node-mcp.cmd"
        if sys.platform == "win32"
        else node_bin
    )
    sanitizer = f"{codex_shared_root_str}/mcp-packages/schema-sanitizer.js"
    npm_node_modules = codex_shared_root / "mcp-packages" / "node_modules"
    npm_servers = {
        "evm-chain-data": "@mcpdotdirect/evm-mcp-server/build/index.js",
        "foundry-suite": "@pranesh.asp/foundry-mcp-server/dist/index.js",
        "tavily-search": "tavily-mcp/build/index.js",
        "helius": "@mcp-dockmaster/mcp-server-helius/build/index.js",
    }
    sanitized_npm_servers = {"evm-chain-data"}
    wrapped_python_servers = {
        "slither-analyzer",
        "unified-vuln-db",
        "farofino",
        "solana-fender",
    }
    incompatible_servers = {"evm-chain-data"}

    for name, srv in servers.items():
        command = srv.get("command", "")
        args = srv.get("args", [])
        cwd = srv.get("cwd", "")
        env = srv.get("env", {})
        comment = srv.get("_comment", "")

        # Normalize command: use fully qualified executables where possible.
        if command in ("python", "python3"):
            command = python_bin
        elif command == "slither-mcp":
            command = slither_bin

        # Resolve npx/node to absolute paths from user's Claude mcp.json
        # Bare "npx" inside Codex sandbox can't find the local npm cache
        if command in ("npx", "node"):
            resolved = shutil.which(command)
            if resolved:
                command = resolved.replace("\\", "/")

        # Normalize cwd: point at the Codex-owned shared methodology tree.
        if cwd.startswith("./"):
            cwd = codex_shared_root_str + "/" + cwd[2:]
        elif cwd.startswith("custom-mcp/"):
            cwd = codex_shared_root_str + "/" + cwd

        lines.append(f'[mcp_servers.{name}]')
        if comment:
            lines.append(f'# {comment}')
        lines.append(f'type = "stdio"')
        lines.append(f'required = false')
        lines.append(f'startup_timeout_sec = 30')
        if name in npm_servers:
            entry_js = str(npm_node_modules / npm_servers[name]).replace("\\", "/")
            lines.append(f'command = "{node_wrapper}"')
            if name in sanitized_npm_servers:
                lines.append("args = [")
                lines.append(f'  "{sanitizer}",')
                lines.append(f'  "{entry_js}",')
                lines.append("]")
            else:
                lines.append(f'args = ["{entry_js}"]')
        elif name in wrapped_python_servers:
            child_args = [command, *args]
            lines.append(f'command = "{node_bin}"')
            child_args_str = ", ".join(f'"{a}"' for a in ([sanitizer] + child_args))
            lines.append(f'args = [{child_args_str}]')
        else:
            lines.append(f'command = "{command}"')

            # Format args as TOML array
            args_str = ", ".join(f'"{a}"' for a in args)
            lines.append(f'args = [{args_str}]')

        if cwd:
            lines.append(f'cwd = "{cwd}"')
        if name == "foundry-suite":
            lines.append('startup_timeout_sec = 90')
        elif name == "evm-chain-data":
            lines.append('startup_timeout_sec = 60')

        if name in incompatible_servers:
            commented_start = len(lines) - 1
            while commented_start >= 0 and not lines[commented_start].startswith(f'[mcp_servers.{name}]'):
                commented_start -= 1
            for i in range(commented_start, len(lines)):
                if lines[i] and not lines[i].startswith('#'):
                    lines[i] = '# ' + lines[i]
            lines.append('# ^ Disabled in Codex: incompatible MCP protocol version')
            lines.append('')
            continue

        # Skip servers whose REQUIRED env vars are still placeholders.
        has_placeholder = any(v.startswith("YOUR_") for v in env.values()) if env else False
        if has_placeholder:
            # Comment out the entire server block
            commented_start = len(lines) - 1
            while commented_start >= 0 and not lines[commented_start].startswith(f'[mcp_servers.{name}]'):
                commented_start -= 1
            for i in range(commented_start, len(lines)):
                if lines[i] and not lines[i].startswith('#'):
                    lines[i] = '# ' + lines[i]
            lines.append(f'# ^ Disabled: replace YOUR_* placeholders in env to enable')
            lines.append('')
            continue

        merged_env = dict(env)
        if sys.platform == "win32" and name in wrapped_python_servers:
            for key, value in _windows_inherited_env().items():
                merged_env.setdefault(key, value)

        if merged_env:
            lines.append(f'[mcp_servers.{name}.env]')
            for k, v in merged_env.items():
                lines.append(f'{k} = "{toml_escape(v)}"')

        lines.append('')

    path = out_dir / "config.toml"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  Generated {path.relative_to(PLAMEN_HOME)}")


# ---------------------------------------------------------------------------
# Generator: agents/*.toml
# ---------------------------------------------------------------------------

# Shared platform awareness directive injected into all agent roles.
# Recon has a custom version (includes MCP timeout); all others use this.
PLATFORM_DIRECTIVE = (
    "PLATFORM: On Windows (PowerShell), translate bash commands from methodology:\n"
    "- grep/rg -> Get-ChildItem -Recurse | Select-String\n"
    "- find -> Get-ChildItem -Recurse -Filter\n"
    "- cat -> Get-Content; wc -l -> (Get-Content file).Count\n"
    "- Do NOT use fc, glob **/*.sol, or Set-Content -NoNewline\n"
    "- If git commands fail, skip and note \"not a git repo\""
)


def _load_breadth_semantic_operator_kernel() -> str:
    """Load the versioned SC breadth floor shared with the PTY driver."""
    path = (
        PLAMEN_HOME
        / "prompts"
        / "shared"
        / "v2"
        / "breadth-semantic-operator-kernel.md"
    )
    try:
        text = path.read_text(encoding="utf-8").strip()
        if (
            "PLAMEN_BREADTH_SEMANTIC_KERNEL: BEGIN v1.0.0" not in text
            or "PLAMEN_BREADTH_SEMANTIC_KERNEL: END v1.0.0" not in text
        ):
            raise ValueError("version markers missing")
        return text
    except Exception as exc:
        print(f"  Warning: SC breadth kernel unavailable: {exc}", file=sys.stderr)
        return (
            "## [BREADTH-KERNEL-UNAVAILABLE] Human review required\n\n"
            f"The mandatory SC breadth kernel could not be loaded from `{path}`. "
            "Do not treat this worker as complete security-method coverage."
        )


_BREADTH_SEMANTIC_OPERATOR_KERNEL = _load_breadth_semantic_operator_kernel()


# Tiered model mapping for Codex backend.  Imported from plamen_types.py to
# maintain a single source of truth shared with the V2 driver.  The V1 adapter
# previously had independent (and divergent) mappings -- that drift caused a 7x
# cost difference on the "sonnet" tier.  If the import fails (e.g. running the
# adapter in isolation without the driver on sys.path), fall back to the same
# defaults that plamen_types uses.
try:
    from plamen_types import _CODEX_MODEL_MAP as CODEX_MODEL_TIERS  # noqa: N811
except ImportError:
    # PARITY-7: these MUST equal plamen_types._CODEX_MODEL_MAP exactly so an
    # import failure is a true no-op, not a silent tier drift (the old values
    # reintroduced the documented 7x-cost sonnet drift).
    CODEX_MODEL_TIERS: dict[str, str] = {
        "opus": os.environ.get("PLAMEN_CODEX_OPUS_MODEL", "gpt-5.5"),
        "sonnet": os.environ.get("PLAMEN_CODEX_SONNET_MODEL", "gpt-5.4"),
        "haiku": os.environ.get("PLAMEN_CODEX_HAIKU_MODEL", "gpt-5.4-mini"),
    }

# Role definitions: (filename, name, description, developer_instructions)
AGENT_ROLES = [
    {
        "filename": "recon.toml",
        "name": "recon",
        "model": None,  # inherits from config.toml
        "description": "Reconnaissance sub-agent: one of 4 parallel recon agents (see SKILL.md Phase 1)",
        "instructions": textwrap.dedent("""\
            You are a Recon Sub-Agent. Read your full methodology from:
            ~/.codex/plamen/prompts/{LANGUAGE}/phase1-recon-prompt.md

            The orchestrator assigns you a SUBSET of recon tasks. You are one of
            4 parallel recon agents:
            - Agent 1A (RAG): TASK 0 steps 1-5 -- fire-and-forget
            - Agent 1B (Docs/External/Fork): TASK 0 step 6, TASK 3, TASK 11
            - Agent 2 (Build/Static/Tests): TASK 1, 2, 8, 9
            - Agent 3 (Patterns/Surface/Templates): TASK 4, 5, 6, 7, 10

            Execute ONLY the tasks assigned to you by the orchestrator.

            PLATFORM: The methodology templates contain bash commands. On Windows
            (PowerShell), translate them:
            - grep/rg -> Get-ChildItem -Recurse | Select-String
            - find -> Get-ChildItem -Recurse -Filter
            - wc -l -> (Get-Content file).Count
            - cat -> Get-Content
            - Do NOT use fc (collides with Format-Custom), glob patterns like **/*.sol,
              or Set-Content -NoNewline
            - If git commands fail (not a git repo), skip them and note "not a git repo"

            When an MCP tool call returns a timeout error or fails, do NOT retry.
            Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider.

            SCOPE: Write ONLY to your assigned output files. Do NOT proceed to
            subsequent pipeline phases. Return your summary and stop."""),
    },
    {
        "filename": "breadth.toml",
        "name": "breadth",
        "model": None,  # inherits from config.toml
        "description": "Breadth analysis: broad vulnerability scanning across the codebase",
        "instructions": textwrap.dedent("""\
            You are Breadth Agent #{N}. Read your full methodology from:
            ~/.codex/plamen/prompts/{LANGUAGE}/generic-security-rules.md
            ~/.codex/plamen/rules/finding-output-format.md

            Apply the following exact versioned semantic floor in addition to
            any recon-selected conditional skills:

""" + _BREADTH_SEMANTIC_OPERATOR_KERNEL + """

            Analyze your assigned scope for security vulnerabilities.
            Use the finding output format for all findings.

            Write to {SCRATCHPAD}/analysis_{N}.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT read or write
            other agents' output files. Do NOT proceed to subsequent pipeline phases.
            Return your findings and stop."""),
    },
    {
        "filename": "depth-token-flow.toml",
        "name": "depth-token-flow",
        "model": None,  # inherits from config.toml
        "description": "Deep analysis of token entry/exit paths, donation attacks, type separation",
        "instructions": textwrap.dedent("""\
            You are the TOKEN_FLOW Depth Agent. Read your full methodology from:
            ~/.codex/plamen/agents/depth-token-flow.md
            ~/.codex/plamen/agents/skills/{LANGUAGE}/token-flow-tracing/SKILL.md

            Write findings to {SCRATCHPAD}/depth_token_flow_findings.md only.

            """ + PLATFORM_DIRECTIVE + """

            Do NOT proceed to subsequent pipeline phases."""),
    },
    {
        "filename": "depth-state-trace.toml",
        "name": "depth-state-trace",
        "model": None,  # inherits from config.toml
        "description": "Cross-function state mutation tracing, constraint enforcement verification",
        "instructions": textwrap.dedent("""\
            You are the STATE_TRACE Depth Agent. Read your full methodology from:
            ~/.codex/plamen/agents/depth-state-trace.md

            Write findings to {SCRATCHPAD}/depth_state_trace_findings.md only.

            """ + PLATFORM_DIRECTIVE + """

            Do NOT proceed to subsequent pipeline phases."""),
    },
    {
        "filename": "depth-edge-case.toml",
        "name": "depth-edge-case",
        "model": None,  # inherits from config.toml
        "description": "Zero-state return, dust analysis, boundary conditions with real constants",
        "instructions": textwrap.dedent("""\
            You are the EDGE_CASE Depth Agent. Read your full methodology from:
            ~/.codex/plamen/agents/depth-edge-case.md
            ~/.codex/plamen/agents/skills/{LANGUAGE}/zero-state-return/SKILL.md

            Write findings to {SCRATCHPAD}/depth_edge_case_findings.md only.

            """ + PLATFORM_DIRECTIVE + """

            Do NOT proceed to subsequent pipeline phases."""),
    },
    {
        "filename": "depth-external.toml",
        "name": "depth-external",
        "model": None,  # inherits from config.toml
        "description": "External call side effects, cross-chain timing windows, MEV analysis",
        "instructions": textwrap.dedent("""\
            You are the EXTERNAL Depth Agent. Read your full methodology from:
            ~/.codex/plamen/agents/depth-external.md

            Write findings to {SCRATCHPAD}/depth_external_findings.md only.

            """ + PLATFORM_DIRECTIVE + """

            Do NOT proceed to subsequent pipeline phases."""),
    },
    {
        "filename": "scanner.toml",
        "name": "scanner",
        "model": None,  # inherits from config.toml
        "description": "Blind spot scanning and validation sweep",
        "instructions": textwrap.dedent("""\
            You are the Scanner Agent. Read your full methodology from:
            ~/.codex/plamen/prompts/{LANGUAGE}/phase4b-scanner-templates.md

            Run the blind spot scanner checks and validation sweep.
            Write findings to {SCRATCHPAD}/blind_spot_{type}_findings.md
            or {SCRATCHPAD}/validation_sweep_findings.md.

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output files. Do NOT proceed to
            subsequent pipeline phases. Return your findings and stop."""),
    },
    {
        "filename": "inventory.toml",
        "name": "inventory",
        "model": None,  # inherits from config.toml
        "description": "Findings inventory: consolidation, deduplication, categorization",
        "instructions": textwrap.dedent("""\
            You are the Findings Inventory Agent. Read your full methodology from:
            ~/.codex/plamen/prompts/{LANGUAGE}/phase4a-inventory-prompt.md

            Consolidate all breadth findings into a single inventory.
            Write to {SCRATCHPAD}/findings_inventory.md.

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT proceed to
            subsequent pipeline phases. Return your summary and stop."""),
    },
    {
        "filename": "chain-analyzer.toml",
        "name": "chain-analyzer",
        "model": None,  # inherits from config.toml
        "description": "Chain analysis: enabler enumeration, grouping, postcondition-precondition matching",
        "instructions": textwrap.dedent("""\
            You are the Chain Analysis Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase4c-chain-prompt.md

            Perform enabler enumeration, hypothesis grouping, and chain matching.
            Write to {SCRATCHPAD}/hypotheses.md, {SCRATCHPAD}/finding_mapping.md,
            {SCRATCHPAD}/synthesis_full.md, {SCRATCHPAD}/chain_hypotheses.md.

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output files. Do NOT proceed to
            subsequent pipeline phases. Return your summary and stop."""),
    },
    {
        "filename": "verifier.toml",
        "name": "verifier",
        "model": None,  # inherits from config.toml
        "description": "PoC verification: write and execute tests to prove/disprove hypotheses",
        "instructions": textwrap.dedent("""\
            You are the Security Verifier. Read your full methodology from:
            ~/.codex/plamen/agents/security-verifier.md
            ~/.codex/plamen/agents/skills/{LANGUAGE}/verification-protocol/SKILL.md
            ~/.codex/plamen/rules/phase5-poc-execution.md

            Write and execute PoC tests for each assigned hypothesis.
            Write results to {SCRATCHPAD}/verify_{batch}.md.

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT proceed to
            subsequent pipeline phases. Return your verdicts and stop."""),
    },
    {
        "filename": "rescan.toml",
        "name": "rescan",
        "model": CODEX_MODEL_TIERS["sonnet"],
        "description": "Breadth re-scan: second-pass analysis with exclusion list to counter attention saturation",
        "instructions": textwrap.dedent("""\
            You are a Breadth Re-Scan Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase3b-rescan-prompt.md
            ~/.codex/plamen/rules/finding-output-format.md

            You perform a SECOND PASS analysis. You receive an exclusion list of
            already-known findings. Do NOT re-report excluded findings.
            Focus on vulnerability classes that attention saturation typically masks.

            Write to {SCRATCHPAD}/analysis_rescan_{N}.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT read or write
            other agents' output files. Do NOT proceed to subsequent pipeline phases.
            Return your findings and stop."""),
    },
    {
        "filename": "per-contract.toml",
        "name": "per-contract",
        "model": CODEX_MODEL_TIERS["sonnet"],
        "description": "Per-contract focused analysis: maximum depth on a single contract/cluster",
        "instructions": textwrap.dedent("""\
            You are a Per-Contract Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase3b-rescan-prompt.md (Phase 3c section)
            ~/.codex/plamen/rules/finding-output-format.md

            You analyze ONLY your assigned contract cluster at maximum depth.
            You receive an exclusion list -- do NOT re-report excluded findings.
            For each function: check state completeness, conditional branches,
            boundary values, pairing audits, and fee/reward traces.

            Write to {SCRATCHPAD}/analysis_percontract_{N}.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT proceed to
            subsequent pipeline phases. Return your findings and stop."""),
    },
    {
        "filename": "semantic-invariant.toml",
        "name": "semantic-invariant",
        "model": None,  # inherits from config.toml
        "description": "Semantic invariant pre-computation: extract protocol invariants for depth agents",
        "instructions": textwrap.dedent("""\
            You are the Semantic Invariant Agent. Your task is to extract and
            formalize protocol-level semantic invariants from the codebase.

            Read design_context.md and state_variables.md from the scratchpad.
            Identify invariants: conservation laws, monotonicity constraints,
            access control boundaries, temporal ordering requirements.

            Write to {SCRATCHPAD}/semantic_invariants.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT proceed to
            subsequent pipeline phases. Return your invariants and stop."""),
    },
    {
        "filename": "scoring.toml",
        "name": "scoring",
        "model": CODEX_MODEL_TIERS["haiku"],
        "description": "Confidence scoring: mechanical 4-axis formula application per finding",
        "instructions": textwrap.dedent("""\
            You are the Confidence Scoring Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase4-confidence-scoring.md

            For each finding, compute 4-axis scores (Evidence, Consensus,
            Analysis Quality, RAG Match) using the formulas in the methodology.
            This is a MECHANICAL task -- apply formulas, do not reason about
            finding validity.

            Read: findings_inventory.md, consensus_map.md, rag_validation.md
            Write to {SCRATCHPAD}/confidence_scores.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Return scores and stop."""),
    },
    {
        "filename": "rag-sweep.toml",
        "name": "rag-sweep",
        "model": CODEX_MODEL_TIERS["sonnet"],
        "description": "RAG validation sweep: validate every finding against historical vulnerability databases",
        "instructions": textwrap.dedent("""\
            You are the RAG Validation Sweep Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase4-confidence-scoring.md (Phase 4b.5 section)

            For EVERY finding in findings_inventory.md:
            1. Call validate_hypothesis with the finding's root cause
            2. Call search_solodit_live with the vulnerability class
            3. Record the result

            Fallback chain: If MCP tools fail, use WebSearch. If WebSearch fails,
            record floor score (0.3).

            Write to {SCRATCHPAD}/rag_validation.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Return validation
            results and stop."""),
    },
    {
        "filename": "niche-agent.toml",
        "name": "niche-agent",
        "model": None,  # inherits from config.toml
        "description": "Generic niche agent template: flag-triggered focused analysis on a specific concern",
        "instructions": textwrap.dedent("""\
            You are a Niche Agent. Read your specific SKILL.md from the path
            provided by the orchestrator:
            ~/.codex/plamen/agents/skills/niche/{SKILL_NAME}/SKILL.md

            Follow the methodology in your skill file exactly.
            Write findings using the standard finding output format from:
            ~/.codex/plamen/rules/finding-output-format.md

            Write to the EXACT output filename provided by the orchestrator.
            The orchestrator MUST pass you the mapped filename using this table:

            | Skill | Output Filename |
            |-------|----------------|
            | EVENT_COMPLETENESS | niche_event_findings.md |
            | SEMANTIC_GAP_INVESTIGATOR | niche_semantic_gap_findings.md |
            | SEMANTIC_CONSISTENCY_AUDIT | niche_semantic_consistency_findings.md |
            | SIGNATURE_VERIFICATION_AUDIT | niche_signature_findings.md |
            | SPEC_COMPLIANCE_AUDIT | niche_spec_compliance_findings.md |
            | MULTI_STEP_OPERATION_SAFETY | niche_multi_step_safety_findings.md |
            | CALLBACK_RECEIVER_SAFETY | niche_callback_safety_findings.md |
            | DIMENSIONAL_ANALYSIS | niche_dimensional_analysis_findings.md |
            | STABLESWAP_COMPLIANCE | niche_stableswap_compliance_findings.md |

            If no mapped filename is provided, use: {SCRATCHPAD}/niche_{SKILL_NAME_LOWER}_findings.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Do NOT proceed to
            subsequent pipeline phases. Return your findings and stop."""),
    },
    {
        "filename": "report-index.toml",
        "name": "report-index",
        "model": CODEX_MODEL_TIERS["haiku"],
        "description": "Report index: assign clean report IDs, tier assignments, consolidation, completeness check",
        "instructions": textwrap.dedent("""\
            You are the Report Index Agent. Read your full methodology from:
            ~/.codex/plamen/rules/phase6-report-prompts.md (Step 6a section)
            ~/.codex/plamen/rules/report-template.md

            Create the master finding index: determine final severities, apply
            root-cause consolidation, assign sequential report IDs (C-01, H-01,
            M-01, L-01, I-01), create tier assignments, cross-reference map,
            and verify completeness.

            Write to:
            - {SCRATCHPAD}/report_index.md
            - {SCRATCHPAD}/report_coverage.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to those two assigned output files. Return index summary
            and stop."""),
    },
    {
        "filename": "report-tier-writer.toml",
        "name": "report-tier-writer",
        "model": None,  # inherits from config.toml
        "description": "Report tier writer: write full finding sections for an assigned severity tier",
        "instructions": textwrap.dedent("""\
            You are a Report Tier Writer. Read your full methodology from:
            ~/.codex/plamen/rules/phase6-report-prompts.md (Step 6b section)
            ~/.codex/plamen/rules/report-template.md

            Write full finding sections for EACH finding in your assigned tier.
            Use report IDs from report_index.md -- NEVER use internal pipeline IDs.
            Every finding gets its own ### section with Description, Impact,
            PoC Result, and Recommendation.

            Write to {SCRATCHPAD}/report_{TIER}.md

            """ + PLATFORM_DIRECTIVE + """

            SCOPE: Write ONLY to your assigned output file. Return your finding
            count and stop."""),
    },
    {
        "filename": "report-assembler.toml",
        "name": "report-assembler",
        "model": CODEX_MODEL_TIERS["haiku"],
        "description": "Report assembler: merge tier sections into final AUDIT_REPORT.md with quality checks",
        "instructions": textwrap.dedent("""\
            You are the Report Assembler. Read your full methodology from:
            ~/.codex/plamen/rules/phase6-report-prompts.md (Step 6c section)
            ~/.codex/plamen/rules/report-template.md

            Merge the tier sections into the final audit report:
            1. Combine report header, executive summary, and all tier sections
            2. Add priority remediation order
            3. Run quality checks (finding count, no internal IDs, valid cross-refs)
            4. Write report_quality.md with check results

            """ + PLATFORM_DIRECTIVE + """

            Write the final report to {PROJECT_ROOT}/AUDIT_REPORT.md
            Write quality check to {SCRATCHPAD}/report_quality.md"""),
    },
    {
        "filename": "report-writer.toml",
        "name": "report-writer",
        "model": None,  # inherits from config.toml
        "description": "Report generation: index, tier writing, assembly (legacy single-agent fallback)",
        "instructions": textwrap.dedent("""\
            You are the Report Writer. Read your full methodology from:
            ~/.codex/plamen/rules/phase6-report-prompts.md
            ~/.codex/plamen/rules/report-template.md

            Generate the audit report following the tier-based writing process:
            1. Create report index (report_index.md)
            2. Write Critical+High findings (report_critical_high.md)
            3. Write Medium findings (report_medium.md)
            4. Write Low+Info findings (report_low_info.md)
            5. Assemble final AUDIT_REPORT.md

            """ + PLATFORM_DIRECTIVE + """

            Write the final report to {PROJECT_ROOT}/AUDIT_REPORT.md."""),
    },
]


def generate_agent_tomls(out_dir: Path) -> None:
    """Generate codex-adapter/agents/*.toml -- one TOML per agent role."""
    agents_dir = out_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    for role in AGENT_ROLES:
        lines = [
            f'name = "{role["name"]}"',
            f'description = "{role["description"]}"',
        ]

        # Only emit model if the role overrides the global default.
        # Roles without an explicit model inherit from config.toml.
        if role.get("model"):
            lines.append(f'model = "{role["model"]}"')

        lines += [
            '',
            f'developer_instructions = """',
            role["instructions"].rstrip(),
            '"""',
        ]

        path = agents_dir / role["filename"]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"  Generated {path.relative_to(PLAMEN_HOME)}")


# ---------------------------------------------------------------------------
# Generator: skills/plamen/SKILL.md
# ---------------------------------------------------------------------------

def generate_skill_md(out_dir: Path) -> None:
    """Generate codex-adapter/skills/plamen/SKILL.md -- the /plamen orchestrator skill for Codex."""
    scripts_dir = str(Path.home() / ".codex" / "plamen" / "scripts").replace("\\", "\\\\")
    content = textwrap.dedent(f"""\
    ---
    name: plamen
    description: "Launch the Plamen deterministic Web3 security audit pipeline"
    ---

    # Plamen V2 Wizard Launcher For Codex

    Use this skill whenever the user invokes `$plamen`, `/plamen`, asks to
    start, resume, or configure a Plamen audit, or asks for the Plamen wizard
    inside Codex.

    ## Hard Rule

    Do not manually orchestrate Plamen phases. Do not spawn recon, breadth,
    depth, verification, or report agents yourself. The Python driver is the
    sole owner of phase sequencing for both Claude and Codex routes.

    Your job is the same job as the Claude `/plamen` command wizard:

    1. Detect an existing audit and offer resume/fresh/new.
    2. Collect missing launch parameters.
    3. Write or reuse `{{PROJECT_ROOT}}/.scratchpad/config.json`.
    4. Launch the deterministic driver.
    5. Report the resume command and basic status.

    For new Codex launches, `config.json` must set `"cli_backend": "codex"`.
    For existing audits, do not rewrite the config on resume.

    ## Wizard Files

    Follow the Codex-native wizard references in this skill directory:

    - Smart-contract audits: `plamen-wizard.md`
    - L1 infrastructure audits: `plamen-l1-wizard.md`

    Read only the relevant file:

    - If the user says `l1`, `L1`, `infra`, `client`, `go`, `rust node`, or
      the target looks like a chain/client codebase, use `plamen-l1-wizard.md`.
    - Otherwise use `plamen-wizard.md`.

    ## Invocation Syntax

    ```text
    $plamen [l1] [light|core|thorough] [path] [docs:<path-or-url>] [scope:<path>] [notes:<text>] [--fresh]
    $plamen resume [path-or-config]
    ```

    Defaults:

    - `pipeline`: `sc`
    - `mode`: `core`
    - `project_root`: current working directory
    - `cli_backend`: `codex`

    Do not ask a model-selection question from this skill. The user is already
    running inside the model/backend they chose.

    ## Driver Commands

    Codex route:

    ```
    python {scripts_dir}\\plamen_driver.py "{{CONFIG_PATH}}"
    ```

    Fresh restart:

    ```
    python {scripts_dir}\\plamen_driver.py --fresh "{{CONFIG_PATH}}"
    ```
    """)

    skills_dir = out_dir / "skills" / "plamen"
    skills_dir.mkdir(parents=True, exist_ok=True)
    with open(skills_dir / "SKILL.md", "w", encoding="utf-8") as f:
        f.write(content)

    aliases = {
        "plamen-l1": (
            "Launch the Plamen deterministic L1 infrastructure audit pipeline",
            "Use the base plamen skill and `plamen/plamen-l1-wizard.md`. "
            "New configs must set `pipeline = l1` and `cli_backend = codex`."
        ),
        "plamen-wizard": (
            "Run the Plamen smart-contract audit wizard in Codex",
            "Use the base plamen skill and `plamen/plamen-wizard.md`. "
            "New configs must set `cli_backend = codex`."
        ),
        "plamen-l1-wizard": (
            "Run the Plamen L1 infrastructure audit wizard in Codex",
            "Use the base plamen skill and `plamen/plamen-l1-wizard.md`. "
            "New configs must set `pipeline = l1` and `cli_backend = codex`."
        ),
    }
    for name, (description, body) in aliases.items():
        alias_dir = out_dir / "skills" / name
        alias_dir.mkdir(parents=True, exist_ok=True)
        alias = textwrap.dedent(f"""\
        ---
        name: {name}
        description: "{description}"
        ---

        # {name}

        {body}

        Do not manually orchestrate phases. Do not spawn audit agents yourself.
        Do not ask a model-selection question from inside Codex.
        """)
        with open(alias_dir / "SKILL.md", "w", encoding="utf-8") as f:
            f.write(alias)

    print(f"  Generated {skills_dir.relative_to(PLAMEN_HOME)}/SKILL.md and Plamen skill aliases")
    return

    content = textwrap.dedent("""\
    ---
    name: plamen
    description: "Launch Plamen Web3 security audit pipeline"
    ---

    # Plamen Security Audit Pipeline (Codex Orchestrator)

    ## Usage

    ```
    /plamen [light|core|thorough] [path/to/project]
    ```

    When invoked, follow this orchestration sequence.

    ## Step 0: Parse Arguments

    Parse `$ARGUMENTS`:
    - If it contains "light", "core", or "thorough", set `MODE` accordingly (default: core).
    - If it contains a path, set `PROJECT_ROOT` to that path. Otherwise use cwd.
    - If it contains `docs:` followed by a path, set `DOCS_PATH`.
    - If it contains `scope:` followed by a path, set `SCOPE_FILE`.
    - If it contains `notes:` followed by text, set `SCOPE_NOTES`.

    ## Step 0.5: Interactive Setup (when no arguments given)

    If MODE was not specified in arguments:

    1. Display: "Plamen Web3 Security Auditor -- Codex Runtime"
    2. Ask the user: "Which audit mode? [light/core/thorough] (default: core)"
    3. Wait for response. Set MODE accordingly. If empty or unrecognized, default to core.
    4. Confirm: "Starting {MODE} audit on {PROJECT_ROOT}"

    If a path was not specified, use cwd and confirm:
    "Target: {cwd} -- correct? [y/n]"
    If the user answers "n", ask for the correct path before proceeding.

    ## Step 1: Language Detection

    Detect the project's smart contract language by scanning `PROJECT_ROOT`:

    | Detection | Language |
    |-----------|----------|
    | `foundry.toml` or `.sol` files | `evm` |
    | `Anchor.toml` or `programs/` with `.rs` | `solana` |
    | `Move.toml` with `[addresses]` + `aptos` deps | `aptos` |
    | `Move.toml` with `sui` deps | `sui` |
    | `Cargo.toml` with `soroban-sdk` | `soroban` |

    Set `LANGUAGE` to the detected value. This resolves all `{LANGUAGE}` placeholders
    in file paths throughout the pipeline.

    ## Step 2: Create Scratchpad

    ```bash
    mkdir -p {PROJECT_ROOT}/.scratchpad
    ```

    Set `SCRATCHPAD = {PROJECT_ROOT}/.scratchpad`.

    ## Step 3: Execute Phase Sequence

    The V2 driver (`plamen_driver.py`) handles phase sequencing, artifact gates,
    and retry logic automatically. Execute phases in order per the driver's config.

    ### Phase 1: Reconnaissance (4-Agent Split)

    Do NOT spawn a single monolithic recon agent. Split into 4 parallel agents
    for timeout isolation (confirmed failure on large projects with single agent).

    Read the full recon prompt structure from:
    `~/.codex/plamen/prompts/{LANGUAGE}/phase1-recon-prompt.md`

    **Agent 1A: RAG Meta-Buffer** (FIRE-AND-FORGET)
    - Tasks: TASK 0 steps 1-5 (vuln-db probe + Solodit queries)
    - Model: defined in agent role TOML (lightweight model -- mechanical query+format task)
    - Spawn with `spawn_agent` and do NOT wait for completion
    - Writes: `meta_buffer.md`
    - If still running after Agents 1B/2/3 finish, abandon it and write:
      `meta_buffer.md` with `## RAG: UNAVAILABLE - agent timed out`

    **Agent 1B: Docs + External + Fork** (foreground)
    - Tasks: TASK 0 step 6 (fork ancestry), TASK 3 (docs), TASK 11 (external)
    - Model: defined in agent role TOML (global model -- web search + design reasoning)
    - Role: `~/.codex/agents/recon.toml` (with task subset)
    - Writes: `design_context.md`, `external_production_behavior.md`

    **Agent 2: Build + Static + Tests** (foreground)
    - Tasks: TASK 1 (build), TASK 2 (static analysis), TASK 8 (tests), TASK 9 (coverage)
    - Model: defined in agent role TOML (lightweight model -- tool execution + output formatting)
    - Role: `~/.codex/agents/recon.toml` (with task subset)
    - Writes: `build_status.md`, `function_list.md`, `call_graph.md`,
      `state_variables.md`, `modifiers.md`, `event_definitions.md`,
      `external_interfaces.md`, `static_analysis.md`, `test_results.md`

    **Agent 3: Patterns + Surface + Templates** (foreground)
    - Tasks: TASK 4 (patterns), TASK 5 (inventory), TASK 6 (surface), TASK 7 (flags),
      TASK 10 (templates)
    - Model: defined in agent role TOML (global model -- attack surface + template selection requires reasoning)
    - Role: `~/.codex/agents/recon.toml` (with task subset)
    - Writes: `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`,
      `setter_list.md`, `emit_list.md`, `constraint_variables.md`,
      `template_recommendations.md`

    Wait for Agents 1B, 2, 3 to complete. Check Agent 1A status:
    - If complete: read its `meta_buffer.md` output
    - If still running: write empty `meta_buffer.md` and proceed
    Then write `recon_summary.md` (orchestrator, not an agent).
    Verify all required artifacts exist per the phase sequence in `plamen_types.py`.

    ### Phase 2: Breadth Analysis

    Read `{SCRATCHPAD}/template_recommendations.md` for agent count and scope split.
    Spawn breadth agents in batches of max 6 (from `~/.codex/agents/breadth.toml`):
    - Each agent gets a unique `{N}` and scope assignment
    - If 7+ agents needed: spawn agents 1-6, wait for all to complete, then spawn 7+
    - Wait for all batches to complete
    - Verify at least 3 `analysis_*.md` files exist

    ### Phase 3: Findings Inventory

    Spawn the `inventory` agent (from `~/.codex/agents/inventory.toml`):
    - Reads all `analysis_*.md` files
    - Produces `findings_inventory.md`

    ### Phase 4/5: Re-Scan and Per-Contract (Thorough only)

    If MODE is thorough:
    - Read `~/.codex/plamen/rules/phase3b-rescan-prompt.md` for re-scan methodology
    - Spawn 2-3 `rescan` agents (from `~/.codex/agents/rescan.toml`) with exclusion list
    - Then spawn `per-contract` agents (from `~/.codex/agents/per-contract.toml`),
      one per contract cluster
    - Merge new findings into inventory

    ### Phase 6: Semantic Invariants (Core/Thorough)

    If MODE is core or thorough:
    - Spawn `semantic-invariant` agent (from `~/.codex/agents/semantic-invariant.toml`)
    - Produces `semantic_invariants.md`

    ### Phase 7: Depth Loop

    Spawn in 2 batches to respect the 8-thread limit:

    **Batch 1** (4 agents): Spawn depth agents from their respective TOML roles:
    - `depth-token-flow.toml`
    - `depth-state-trace.toml`
    - `depth-edge-case.toml`
    - `depth-external.toml`
    Wait for all 4 to complete.

    **Batch 2** (up to 6 agents): Spawn scanners + niche agents:
    - Scanner agents from `scanner.toml`
    - For Core/Thorough: flag-triggered niche agents from `niche-agent.toml`
    Wait for all to complete.

    For Thorough mode:
    - Run confidence scoring via `scoring.toml` agent
    - Run iterations 2-3 with DA (Devil's Advocate) role
    - Run RAG sweep via `rag-sweep.toml` agent
    Read `~/.codex/plamen/rules/phase4-confidence-scoring.md` for the full process.

    ### Phase 8: Chain Analysis

    Spawn `chain-analyzer` agents sequentially:
    1. Agent 1: Enabler enumeration + grouping
    2. Agent 2: Chain matching + composition coverage

    Read `~/.codex/plamen/rules/phase4c-chain-prompt.md` for prompts.

    ### Phase 9: Verification

    Spawn `verifier` agents in batches of 6 for each hypothesis batch:
    - Read `~/.codex/plamen/rules/phase5-poc-execution.md` for PoC rules
    - Batch hypotheses by severity (Critical first)
    - If more than 6 hypotheses: spawn verifiers 1-6, wait, then spawn 7+
    - Execute PoCs and record verdicts

    ### Phase 10: Report Generation

    Spawn report agents sequentially per `~/.codex/plamen/rules/phase6-report-prompts.md`:
    1. `report-index.toml` agent (1 agent -- assigns clean report IDs, tier assignments). Wait for completion.
    2. Three parallel `report-tier-writer.toml` agents (Critical+High, Medium, Low+Info). Wait for all 3.
    3. `report-assembler.toml` agent (1 agent -- combines into AUDIT_REPORT.md). Wait for completion.

    ## Artifact Gate Enforcement

    The V2 driver enforces artifact gates between phases automatically via
    `gate_passes()` in `plamen_driver.py`. If artifacts are missing, the driver
    retries the phase before proceeding.

    ## Mode Support Status

    Not all Claude pipeline features have full Codex parity yet. This table
    shows what is supported, what is experimental, and what is not yet implemented.

    | Phase | Light | Core | Thorough | Notes |
    |-------|-------|------|----------|-------|
    | Recon (4-agent split) | Supported | Supported | Supported | |
    | Breadth | Supported | Supported | Supported | |
    | Inventory | Supported | Supported | Supported | |
    | Re-scan (3b) | N/A | N/A | Experimental | Convergence not validated on Codex |
    | Per-contract (3c) | N/A | N/A | Experimental | Clustering logic untested |
    | Semantic Invariants | N/A | Supported | Supported | |
    | Depth Loop iter 1 | Supported | Supported | Supported | |
    | Depth Loop iter 2-3 | N/A | N/A | Experimental | DA role + anti-dilution untested |
    | Niche Agents | N/A | Supported | Supported | |
    | Confidence Scoring | N/A | Supported | Experimental | 4-axis scoring untested |
    | RAG Sweep | N/A | Supported | Supported | Fallback chain may differ |
    | Chain Analysis | Supported | Supported | Supported | |
    | Verification + PoC | Supported | Supported | Experimental | No fuzz variant support |
    | Skeptic-Judge | N/A | N/A | Not implemented | Requires Claude pipeline feature |
    | Invariant Fuzz | N/A | N/A | Not implemented | Foundry-specific, needs adaptation |
    | Medusa Fuzz | N/A | N/A | Not implemented | Parallel campaign, needs adaptation |
    | Design Stress Test | N/A | N/A | Experimental | 1 agent slot, untested |
    | Finding Perturbation | N/A | N/A | Not implemented | |
    | Report (multi-agent) | Supported | Supported | Supported | |

    ## Mode-Specific Behavior

    | Step | Light | Core | Thorough |
    |------|-------|------|----------|
    | Re-scan (3b/3c) | Skip | Skip | Full |
    | Semantic invariants | Skip | Yes | Yes |
    | Depth iterations | 1 | 1 | Up to 3 |
    | Confidence scoring | Skip | 2-axis | 4-axis |
    | Niche agents | Skip | Flag-triggered | Flag-triggered |
    | RAG sweep | Skip | 1 agent | 1 agent |
    | Verification scope | Chains + Medium+ | Chains + Medium+ | ALL severities |
    """)

    skills_dir = out_dir / "skills" / "plamen"
    skills_dir.mkdir(parents=True, exist_ok=True)
    path = skills_dir / "SKILL.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Generated {path.relative_to(PLAMEN_HOME)}")


# ---------------------------------------------------------------------------
# Generator: hooks.json
# ---------------------------------------------------------------------------

def generate_commands(out_dir: Path) -> None:
    """Generate codex-adapter/commands/plamen*.md for Codex slash-command discovery."""
    commands_dir = out_dir / "commands"
    commands_dir.mkdir(parents=True, exist_ok=True)
    driver_path = str(Path.home() / ".codex" / "plamen" / "scripts" / "plamen_driver.py").replace("\\", "\\\\")


    commands = {
        "plamen.md": (
            "Launch or resume a Plamen smart-contract audit through the deterministic driver.",
            "[light|core|thorough|resume|--fresh] [project-or-config]",
            "Follow `~/.codex/skills/plamen/SKILL.md` with the smart-contract wizard reference. "
            "New configs must set `cli_backend = codex`."
        ),
        "plamen-wizard.md": (
            "Open the Plamen smart-contract audit wizard in Codex.",
            "[light|core|thorough] [project]",
            "Follow `~/.codex/skills/plamen/plamen-wizard.md`. Do not ask a model-selection question."
        ),
        "plamen-l1.md": (
            "Launch or resume a Plamen L1 infrastructure audit through the deterministic driver.",
            "[light|core|thorough|resume|--fresh] [project-or-config]",
            "Follow `~/.codex/skills/plamen/SKILL.md` with the L1 wizard reference. "
            "New configs must set `pipeline = l1` and `cli_backend = codex`."
        ),
        "plamen-l1-wizard.md": (
            "Open the Plamen L1 infrastructure audit wizard in Codex.",
            "[light|core|thorough] [project]",
            "Follow `~/.codex/skills/plamen/plamen-l1-wizard.md`. Do not ask a model-selection question."
        ),
    }

    for filename, (description, hint, body) in commands.items():
        content = textwrap.dedent(f"""\
        ---
        description: {description}
        argument-hint: {hint}
        ---

        # {filename[:-3]}

        Arguments: `$ARGUMENTS`

        {body}

        Do not manually orchestrate Plamen phases and do not spawn audit agents yourself.
        Launch only the shared Python driver:

        ```
        python {driver_path} "{{CONFIG_PATH}}"
        ```

        Fresh restart:

        ```
        python {driver_path} --fresh "{{CONFIG_PATH}}"
        ```
        """)
        with open(commands_dir / filename, "w", encoding="utf-8") as f:
            f.write(content)

    print(f"  Generated {commands_dir.relative_to(PLAMEN_HOME)}/plamen*.md")


# ---------------------------------------------------------------------------
# Generator: README.md
# ---------------------------------------------------------------------------

def generate_readme(out_dir: Path) -> None:
    """Generate codex-adapter/README.md -- usage and installation docs."""
    content = textwrap.dedent("""\
    # Plamen Codex Adapter

    This directory contains Codex-compatible configuration files generated from the
    Plamen audit pipeline's Claude-side manifests. These files allow Plamen to run
    inside the [Codex CLI](https://github.com/openai/codex) in addition to Claude Code.

    ## Installation

    ```bash
    # From the Plamen repo directory:
    plamen install --codex

    # Or manually:
    python scripts/codex_adapter.py
    ```

    The installer:
    1. Generates Codex config files into this `codex/` directory
    2. Creates `~/.codex/` if it does not exist
    3. Symlinks `~/.codex/plamen/` to the Plamen repo (shared methodology files)
    4. Copies Codex-specific files (`config.toml`, agent TOMLs, `AGENTS.md`) into `~/.codex/`

    ## Usage

    After installation, open the Codex CLI and use the Plamen skill:

    ```bash
    codex
    # Then inside Codex:
    /plamen core /path/to/project
    /plamen thorough /path/to/project --docs /path/to/whitepaper.pdf
    ```

    ## Architecture

    ### What is shared (via symlink)

    The Plamen methodology files are shared between Claude Code and Codex via a
    symlink at `~/.codex/plamen/` pointing to the Plamen repo. This includes:

    - `prompts/` -- language-specific phase prompts (recon, inventory, depth, verification)
    - `agents/` -- depth agent definitions and skill files
    - `rules/` -- finding format, confidence scoring, chain analysis, report templates
    - `custom-mcp/` -- MCP server source code

    ### What is Codex-specific (in this directory)

    - `AGENTS.md` -- Condensed orchestrator rules (under 32KB for Codex context)
    - `config.toml` -- Codex main config with model, MCP server mappings
    - `agents/*.toml` -- Role TOML files for each agent type
    - `skills/plamen/SKILL.md` -- The `/plamen` orchestrator skill for Codex

    ### Regenerating

    If you update Claude-side files (CLAUDE.md, mcp.json.example,
    agent definitions), regenerate the Codex files:

    ```bash
    python scripts/codex_adapter.py
    ```

    ## Current Limitations

    - **Phase 1 generator**: Most adapter output content is templated, not fully
      derived from Claude-side manifests. MCP servers (from mcp.json.example)
      and agent role file lists (from agents/depth-*.md) are manifest-driven.
      AGENTS.md orchestrator rules, SKILL.md phase sequence, and agent
      developer_instructions are templated and must be updated manually when
      Claude-side files change. Phase 2 goal is to derive more content from
      CLAUDE.md and commands/plamen.md parsing.
    - **Model**: Codex uses `gpt-5.3-codex` (272K context) vs Claude Code's Opus (1M context).
      Thorough mode may require more careful context management.
    - **Thorough mode parity**: Several Thorough-only features are experimental or
      not yet implemented on Codex. See the Mode Support Status table in
      `skills/plamen/SKILL.md` for details. Skeptic-Judge, invariant fuzz,
      Medusa fuzz, and finding perturbation are not yet available.
    - **MCP servers**: All servers are mapped but may need manual API key configuration
      in `config.toml` (replace `YOUR_*_API_KEY` placeholders).
    - **Platform**: Generated configs assume macOS/Linux (`python3`, forward slashes).
      Windows users should use WSL or adjust paths manually.
    """)

    path = out_dir / "README.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Generated {path.relative_to(PLAMEN_HOME)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Codex-compatible config from Plamen manifests")
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR),
                        help="Output directory for generated files (default: codex/)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating Codex adapter files into {out_dir}...")
    print()

    generate_agents_md(out_dir)
    generate_config_toml(out_dir)
    generate_agent_tomls(out_dir)
    generate_skill_md(out_dir)
    generate_commands(out_dir)
    generate_readme(out_dir)

    print()
    print(f"Done. Generated files in {out_dir.relative_to(PLAMEN_HOME)}/")
    print()
    print("Next steps:")
    print(f"  1. Review generated files in {out_dir.relative_to(PLAMEN_HOME)}/")
    print("  2. Run 'plamen install --codex' to install into ~/.codex/")
    print("  3. Replace API key placeholders in config.toml")


if __name__ == "__main__":
    main()
