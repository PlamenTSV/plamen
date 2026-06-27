---
description: "Launch the V2 deterministic Smart Contract audit pipeline (same as /plamen-wizard). Usage: /plamen [light|core|thorough] [path] | /plamen monitor <minutes> [path]"
---

# Plamen Audit Pipeline

## Step -1: Route to V2 Wizard (MANDATORY first check)

> **For interactive users**: this is the entry point for the V2 deterministic
> driver. Reads better as `/plamen-wizard` if you want clarity, but `/plamen`
> works identically and is what most users type.

**Routing rule** (evaluate `$ARGUMENTS` exactly once, before any other step):

- If `$ARGUMENTS` contains the literal token `monitor`:
  - **STOP processing this file.** Execute **Monitor Mode** (the "Monitor Mode"
    section immediately after this routing block) and do nothing else. Do NOT
    route to the wizard and do NOT launch the driver — this mode only watches an
    audit that is **already running**; it never starts one.

- If `$ARGUMENTS` is empty OR does NOT contain the literal token `wrapper-launch`:
  - **STOP processing this file.** Read and execute `~/.claude/commands/plamen-wizard.md`
    from its Step 1 onward, passing `$ARGUMENTS` through unchanged. The wizard
    collects audit parameters and launches the deterministic Python driver at
    `~/.claude/scripts/plamen_driver.py`. The driver runs each phase as an
    isolated subprocess with gates, dynamic retry, and crash-resumable
    checkpoints — replacing the legacy V1 LLM orchestrator that previously
    lived in this file.
  - Do NOT run any of the Step 0..Step 6 sections below in interactive mode.
    Those sections remain in this file ONLY because the driver invokes them
    via `claude -p --resume` with `wrapper-launch` set, section-extracting one
    phase block at a time. They are NOT a complete interactive pipeline.

- If `$ARGUMENTS` contains `wrapper-launch`:
  - You are running INSIDE a driver subprocess. The driver has section-
    extracted a specific phase block from this file and you should execute
    only that block. Proceed to Step 0 below; the existing logic handles
    the per-phase invocation correctly.

> **Why this routing exists**: pre-v2.0.0, `/plamen` was an LLM-orchestrator
> prompt that ran the entire audit pipeline inside a single Claude Code
> conversation. That worked on small audits but drifted on large ones —
> context saturation late in the run caused mandatory steps to be silently
> skipped, output files to be claimed-written-but-missing on disk, and
> findings to be lost to compaction. v2.0.0 replaced the LLM orchestrator
> with a deterministic Python driver. The interactive surface now points at
> the V2 wizard so users get the reliable path by default, while the driver
> still uses this file's per-phase sections as subprocess prompts.

---

## Monitor Mode

> **Reached only when `$ARGUMENTS` contains `monitor`** (interactive use). This
> mode arms a periodic status heartbeat over an audit that is already running in
> another session — it does not start, resume, or modify any audit.
>
> **CLAUDE BACKEND ONLY.** This relies on the Claude Code `Monitor` tool, which
> streams a script's stdout lines into the chat as notifications. The Codex
> backend (`codex exec`) has no equivalent — under Codex, tell the user that
> `monitor` is Claude-only and that they can instead
> `tail -f <scratchpad>/_plamen.log`, then stop.

Usage: `/plamen monitor <minutes> [path]`

Steps:

1. **Parse the interval.** Take the first integer token after `monitor` as
   `<minutes>` (the heartbeat cadence). If none is given, default to `15`.

2. **Locate the scratchpad** (`S`):
   - If `$ARGUMENTS` contains a path token, use `<path>/.scratchpad` (or the
     token itself if it already ends in `.scratchpad`).
   - Otherwise search the current directory: prefer `./.scratchpad`, then a
     single-level `./*/.scratchpad` (e.g. `core/.scratchpad`). The correct
     scratchpad is the one containing `_v2_checkpoint.json`.
   - If no scratchpad with `_v2_checkpoint.json` is found, tell the user no
     running audit was detected and stop.

3. **Arm the watch.** Call the `Monitor` tool with `persistent: true` and:

   ```
   bash ~/.claude/scripts/plamen_monitor.sh <S> <minutes>
   ```

   Use a specific `description` such as `plamen audit status (every <minutes>m)`.
   The script emits a report immediately on arm and then every `<minutes>`,
   plus event-driven `PROGRESS` / `ALERT-STALL` lines, and a terminal `DONE`
   (report present) or `ALERT-DEAD` (driver gone, no report) when the run ends.

4. Confirm to the user that the monitor is armed and that they can stop it any
   time with `TaskStop` (or by ending the session). Then stop — do not proceed
   to any audit step.

---



## Orchestration Protocol

**MANDATORY**: Before starting any audit work, read and apply `~/.claude/rules/orchestrator-rules.md`. It contains the AUDIT MODES table, CRITICAL RULES 1-16, and the orchestration architecture. You are the orchestrator " those rules govern how you spawn agents, manage phases, and enforce completeness.

## Step 0: Interactive Setup Wizard

**Shortcut handling**: Parse `$ARGUMENTS` for pre-filled values:
- If it contains "light", "core", or "thorough", set `MODE` accordingly.
- **If it contains "l1" (L1 infrastructure audit mode, experimental)**: set `MODE=l1` and **delegate the entire audit flow to `~/.claude/commands/plamen-l1.md`**. Read that file and follow its instructions from Step 0 onwards. This file (plamen.md) covers smart-contract modes only. Do NOT attempt to run L1 audits through the smart-contract pipeline " the phase shape, depth roles, skill set, and verification protocol are all different. L1-specific wizard, Phase 0.5 Bake, layer-decomposed recon/breadth, new depth agent roles (depth-consensus-invariant, depth-network-surface), removed Phase 4c, and the new evidence-tag verification live in `plamen-l1.md`.
- If it contains an absolute path (e.g., `D:\...` or `/home/...`), set `PROJECT_PATH` to that path. Otherwise use cwd.
- If it contains `docs:` followed by a path or URL, set `DOCS_PATH` to that value and skip Step 0c.
- If it contains `nodocs`, set `DOCS_PATH` to empty and skip Step 0c.
- If it contains `network:` followed by a network name (e.g., `ethereum`, `arbitrum`, `optimism`, `base`, `polygon`, `bsc`, `avalanche`, or an RPC URL), set `NETWORK` to that value. Used for production verification and fork testing.
- If it contains `scope:` followed by a file path, set `SCOPE_FILE` to that path. The file should list in-scope contracts/files.
- If it contains `notes:` followed by text (up to end of arguments or next known prefix), set `SCOPE_NOTES` to that text. Passed to recon as additional audit context (e.g., "focus on vault module, ignore governance").
- If it contains `proven-only:` followed by `true` (or just `proven-only: true`), set `PROVEN_ONLY = true`. When enabled, findings whose best evidence is `[CODE-TRACE]` (no executed PoC or fuzzer counterexample) are capped at Low severity in the report. Default: false.
- If it contains `wrapper-launch`, set `LAUNCHED_FROM_WRAPPER = true`. The user already confirmed the launch in the terminal wrapper " skip Step 0d (cost estimate + confirmation) entirely and jump directly to Step 1 (language detection). Do NOT show a second confirmation prompt.
- If MODE, PROJECT_PATH, DOCS_PATH (or nodocs), AND `proven-only:` are all resolved AND `wrapper-launch` is present, skip the ENTIRE wizard " jump directly to Step 1 (language detection). No cost estimate, no confirmation.
- If MODE, PROJECT_PATH, DOCS_PATH (or nodocs), AND `proven-only:` are all resolved but NO `wrapper-launch`, skip the wizard " jump to "Step 0d: Cost Estimate + Launch Confirmation".
- If MODE, PROJECT_PATH, and DOCS_PATH (or nodocs) are resolved but `scope:` and `proven-only:` are NOT specified, skip to Step 0c.5 (scope selection).
- If MODE is set but docs status is unknown (no `docs:` and no `nodocs`), skip to Step 0c only.
- If `$ARGUMENTS` contains "compare", jump directly to the compare flow (Step 0e). If it also contains `report:` followed by a file path, set `REPORT_PATH`. If it contains `ground_truth:` followed by a file path, set `GROUND_TRUTH_PATH`. If both are set, skip the interactive file selection in Step 0e and proceed directly.
- If `$ARGUMENTS` is empty, run the full interactive wizard starting at Step 0a.

### Step 0a: Banner + Toolchain Check + Mode Selection

First, output the banner as text (no tool calls):

```
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•—      â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—
â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ–ˆâ–ˆâ•”â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘
â–ˆâ–ˆâ•”â•â•â•â• â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘
â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â•šâ•â• â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘
â•šâ•â•     â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•â•šâ•â•     â•šâ•â•â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•â•â•
```

**Web3 Security Auditor** v2.1.4

### Version Check (MANDATORY " run before toolchain probe)

Read the VERSION file and compare against the version in your CLAUDE.md context:

```bash
cat ~/.claude/VERSION 2>/dev/null || cat ~/.plamen/VERSION 2>/dev/null || echo "unknown"
```

The VERSION file should say `2.1.4`. Compare this against the version in the header of this prompt (`v2.1.4`). If they differ, warn the user:

> **Version mismatch detected.** Your CLAUDE.md rules are from v{your version} but the repo is at v{VERSION file}. Run `cd ~/.plamen && git pull && plamen install` to update. Proceeding with stale rules may cause wrong agent counts or skipped pipeline steps.

If the VERSION file says a NEWER version than `2.1.4` (the version hardcoded in this prompt), it means the repo was updated but `plamen install` was not re-run to re-inject the updated CLAUDE.md. The same warning applies.

**Do NOT skip this check.** A version mismatch means the orchestrator rules (agent counts, mandatory steps, mode table) in CLAUDE.md are out of sync with the skills, prompts, and templates on disk.

Then run a quick toolchain probe (via Bash, all in one command):

```bash
export PATH="$HOME/.foundry/bin:$HOME/.local/share/solana/install/active_release/bin:$HOME/.avm/bin:$HOME/.cargo/bin:$HOME/.aptoscli/bin:$HOME/.local/bin:$HOME/go/bin:$PATH" && \
echo "Toolchain:" && \
echo -n "  Required: " && \
(command -v claude >/dev/null 2>&1 && echo -n "✓claude " || echo -n "✗claude ") && \
(command -v python >/dev/null 2>&1 && echo -n "✓python " || (command -v python3 >/dev/null 2>&1 && echo -n "✓python " || echo -n "✗python ")) && \
(command -v npx >/dev/null 2>&1 && echo -n "✓npx " || echo -n "✗npx ") && \
(command -v git >/dev/null 2>&1 && echo -n "✓git" || echo -n "✗git") && echo "" && \
echo -n "  EVM:      " && \
(command -v forge >/dev/null 2>&1 && echo -n "✓forge " || echo -n "○forge ") && \
(command -v slither >/dev/null 2>&1 && echo -n "✓slither " || echo -n "○slither ") && \
(command -v medusa >/dev/null 2>&1 && echo -n "✓medusa" || echo -n "○medusa") && echo "" && \
echo -n "  Solana:   " && \
(command -v solana >/dev/null 2>&1 && echo -n "✓solana " || echo -n "○solana ") && \
(command -v anchor >/dev/null 2>&1 && echo -n "✓anchor " || echo -n "○anchor ") && \
(command -v trident >/dev/null 2>&1 && echo -n "✓trident" || echo -n "○trident") && echo "" && \
echo -n "  Move:     " && \
(command -v aptos >/dev/null 2>&1 && echo -n "✓aptos " || echo -n "○aptos ") && \
(command -v sui >/dev/null 2>&1 && echo -n "✓sui" || echo -n "○sui") && echo "" && \
echo -n "  Soroban:  " && \
(command -v stellar >/dev/null 2>&1 && echo -n "✓stellar " || echo -n "○stellar ") && \
(cargo scout-audit --version >/dev/null 2>&1 && echo -n "✓scout" || echo -n "○scout") && echo ""
```

Display the output to the user. If any required tools (claude, python, npx, git) show ✗, warn:
> **Warning**: Missing required tools. Run `plamen setup` in your terminal to install them.

If optional tools are missing, note briefly:
> Optional tools with ○ are not installed " the pipeline degrades gracefully but coverage may be reduced. Run `plamen setup` to install.

Then proceed to mode selection using `AskUserQuestion` with previews:

```
AskUserQuestion(questions=[{
  question: "Which audit mode would you like to run?",
  header: "Mode",
  multiSelect: false,
  options: [
    {
      label: "Light (Pro plan)",
      description: "Lightweight audit " all Sonnet agents, fits Pro rate limits",
      preview: "~18-22 agents (all Sonnet/Haiku " no Opus)\n\nPipeline:\n  Recon (2) â†’ Breadth (3-4) â†’ Inventory\n  â†’ Depth (4 merged) â†’ Chain (1)\n  â†’ Verify Medium+ â†’ Report ALL (2)\n\nReports all severities. PoC verification targets Medium+.\n\nSkips:\n  · RAG meta-buffer + fork ancestry\n  · Semantic invariants (state consistency\n    bugs harder to detect " use Core for\n    DeFi protocols with complex state)\n  · Niche agents\n  · Confidence scoring + RAG Sweep\n  · Invariant/Medusa fuzz\n\nBest for: Pro plan, codebases < 3000 lines"
    },
    {
      label: "Core (Recommended)",
      description: "Standard audit " reports all severities, PoC-verifies Medium+",
      preview: "~30-50 agents (requires Max plan)\n\nPipeline:\n  Breadth (5-9) â†’ Inventory â†’ Depth (iter 1)\n  â†’ Niche agents â†’ Chains â†’ Verify Medium+\n  â†’ Report ALL\n\nReports all severities (Low/Info included).\nPoC verification targets Medium+ findings.\n\nSkips:\n  · Breadth re-scan (3b/3c)\n  · Depth iterations 2-3\n  · Design stress testing\n  · Invariant fuzz campaign\n  · Fuzz variants in verification\n\nScoring: 2-axis (Evidence + Analysis Quality)"
    },
    {
      label: "Thorough",
      description: "Deep audit " iterative depth, fuzz variants, re-scan",
      preview: "~40-100 agents (requires Max plan)\n\nPipeline:\n  Breadth (5-9) â†’ Re-scan (2 iters) â†’ Per-contract\n  â†’ Inventory â†’ Depth (1-3 iters, Devil's Advocate)\n  â†’ Niche agents (up to 8) â†’ Chains\n  â†’ Verify ALL severities (with fuzz)\n  â†’ Skeptic-Judge for HIGH/CRIT\n\nIncludes:\n  · Breadth re-scan + per-contract analysis\n  · Invariant fuzz campaign (EVM)\n  · Medusa stateful fuzzing (EVM, if installed)\n  · Design stress testing (unconditional)\n  · Skeptic-Judge adversarial verification (HIGH/CRIT)\n  · Fuzz variants in verification\n  · Low/Info findings verified\n  · Cross-batch consistency check\n\nScoring: 4-axis (Evidence, Consensus, Quality, RAG)"
    },
    {
      label: "Compare",
      description: "Diff a past Plamen report against a ground truth report",
      preview: "Post-audit improvement mode\n\nYou provide:\n  · Your Plamen audit report\n  · A ground truth / reference report\n\nOutputs:\n  · Finding alignment matrix\n  · Recall & precision metrics\n  · Root cause classification\n  · Targeted methodology improvements"
    }
  ]
}])
```

Set `MODE` based on the user's selection. If "Compare" is selected, jump to Step 0e.

### Step 0b: Target Project

Use `AskUserQuestion` to confirm the project directory:

```
AskUserQuestion(questions=[{
  question: "Is this the project you want to audit?",
  header: "Target",
  multiSelect: false,
  options: [
    {
      label: "Yes, use {cwd}",
      description: "Audit the current working directory"
    },
    {
      label: "No, let me specify",
      description: "I'll provide a different project path"
    }
  ]
}])
```

If the user selects "No" or "Other", ask them to type the path. Set `PROJECT_PATH` accordingly.

### Step 0c: Documentation

Use `AskUserQuestion` to ask about documentation:

```
AskUserQuestion(questions=[{
  question: "Do you have project docs that describe trust roles or actor permissions? (used to calibrate finding severity " e.g., 'admin is a 5/7 multisig with timelock')",
  header: "Docs",
  multiSelect: false,
  options: [
    {
      label: "No docs",
      description: "Trust roles will be inferred from code patterns (onlyOwner, role modifiers, etc.)"
    },
    {
      label: "Yes, local files",
      description: "Whitepaper, spec, or design doc with trust/role information"
    },
    {
      label: "Yes, a URL",
      description: "Link to docs describing trust model or actor permissions"
    }
  ]
}])
```

If the user selects local files or URL, ask them to provide the path or URL. Store as `DOCS_PATH`.

### Step 0c.5: Scope

Use `AskUserQuestion` to ask about scope constraints:

```
AskUserQuestion(questions=[{
  question: "Do you want to limit the audit scope?",
  header: "Scope",
  multiSelect: false,
  options: [
    {
      label: "Full project",
      description: "Audit everything in the target directory"
    },
    {
      label: "Scope file",
      description: "I have a scope.txt listing specific files/contracts"
    },
    {
      label: "Scope notes",
      description: "I'll describe the focus areas in plain text"
    }
  ]
}])
```

If the user selects "Scope file", ask them to provide the path. Store as `SCOPE_FILE`.
If the user selects "Scope notes", ask them to describe the focus. Store as `SCOPE_NOTES`.
If "Full project", leave both empty.

### Step 0c.6: Proven-Only Mode

Use `AskUserQuestion` to ask about severity strictness:

```
AskUserQuestion(questions=[{
  question: "Enable proven-only mode? (findings without executed PoC evidence are capped at Low severity " useful for benchmark comparisons)",
  header: "Proven-Only",
  multiSelect: false,
  options: [
    {
      label: "No (default)",
      description: "Standard severity rules " manual code traces can support any severity"
    },
    {
      label: "Yes",
      description: "Unproven findings ([CODE-TRACE] only) capped at Low"
    }
  ]
}])
```

If "Yes", set `PROVEN_ONLY = true`.

### Step 0d: Cost Estimate + Launch Confirmation

Before starting the pipeline, get a cost estimate by calling `plamen.py`'s `estimate_cost()` function directly via Bash. Do NOT calculate costs manually " the Python function is the single source of truth.

#### Step 0d.1: Get Estimate

Run via Bash:

```bash
PY_CMD=$(command -v python3 2>/dev/null || command -v python 2>/dev/null) && "$PY_CMD" ~/.claude/plamen.py --estimate "{PROJECT_PATH}" {MODE} {SCOPE_ARGS}
```

Where `{SCOPE_ARGS}` is:
- `--scope "{SCOPE_FILE}"` if SCOPE_FILE is set
- `--scope-notes "{SCOPE_NOTES}"` if SCOPE_NOTES is set (and no scope file)
- omitted if neither is set

If `plamen.py --estimate` is not available (old version), use this fallback:

```bash
PY_CMD=$(command -v python3 2>/dev/null || command -v python 2>/dev/null) && "$PY_CMD" -c "
import sys, os; sys.path.insert(0, os.path.expanduser('~/.claude'))
from plamen import estimate_cost
import json
r = estimate_cost('{PROJECT_PATH}', '{MODE}', scope_file='{SCOPE_FILE}', scope_notes='{SCOPE_NOTES}')
print(json.dumps(r))
"
```

Parse the JSON output to get: `files`, `lines`, `agents`, `input_mtok`, `output_mtok`, `api_cost`, `pct_pro`, `pct_x5`, `pct_x20`, `scoped`.

#### Step 0d.2: Display Summary + Warnings

Output as a formatted markdown block:

```
**Launch Summary**

| | |
|---|---|
| **Mode** | {Light/Core/Thorough} Audit |
| **Target** | `{PROJECT_PATH}` |
| **Network** | {NETWORK} |  â† only if set
| **Docs** | {docs status or "none"} |
| **Scope** | {SCOPE_FILE basename or "full project"} |  â† only if set
| **Notes** | {SCOPE_NOTES} |  â† only if set
| **Proven-only** | ON " unproven findings capped at Low |  â† only if true
| **Codebase** | ~{lines} lines, {files} files{" (scoped)" if scoped} |
| **Agents** | ~{agents} |
| **Tokens** | ~{input_mtok}M in / ~{output_mtok}M out |
| **API cost** | ~${api_cost} USD |
| **Pro** | ~{pct_pro}% of weekly allowance |  â† with severity indicator
| **Max x5** | ~{pct_x5}% of weekly allowance |  â† with severity indicator
| **Max x20** | ~{pct_x20}% of weekly allowance |  â† with severity indicator
```

**Severity indicators for plan usage %:**
- **<= 40%**: append `(ok)` " comfortable headroom
- **41-80%**: append `(!)` " significant usage, warn the user
- **> 80%**: append `(!!)` " may exceed weekly allowance, strongly warn

**Warnings** (output after the table):
- If `pct_pro > 80` AND MODE is not "light": `> **Warning**: This audit may exceed your Pro plan's weekly allowance. Consider using Light mode or upgrading to Max.`
- If `pct_x5 > 80`: `> **Warning**: This audit may consume most of your Max x5 weekly allowance. Consider scoping to fewer files or using Core mode.`
- If `pct_pro > 40` AND MODE == "light": `> **Note**: This audit will use a significant portion of your Pro weekly allowance.`
- Always: `> *Rough estimates only. Actual usage varies with protocol complexity and findings count.*`

#### Step 0d.4: Confirm

Use `AskUserQuestion` to let the user confirm, go back, or cancel:

```
AskUserQuestion(questions=[{
  question: "Proceed with the audit?",
  header: "Confirm",
  multiSelect: false,
  options: [
    {
      label: "Yes, launch",
      description: "Start the audit pipeline"
    },
    {
      label: "Go back",
      description: "Change settings"
    },
    {
      label: "Cancel",
      description: "Abort the audit"
    }
  ]
}])
```

- If "Yes, launch" â†’ proceed to Step 1.
- If "Go back" â†’ return to Step 0c.6 (Proven-Only).
- If "Cancel" â†’ stop, output `Cancelled.` and do not proceed.

### Step 0e: Compare Flow

If the user selected "Compare":
1. If `REPORT_PATH` and `GROUND_TRUTH_PATH` are both set from `$ARGUMENTS`, skip to step 3.
2. Otherwise, use `AskUserQuestion` to ask for both report paths (both must be `.md` files " PDFs cannot be diffed).
3. Read both files and follow the Post-Audit Improvement Protocol from `~/.claude/rules/post-audit-improvement-protocol.md`.

Do NOT proceed to Step 1.

---

## Step 0.5: Network Resolution (EVM only)

If `NETWORK` is set and `LANGUAGE` is `evm`, resolve to an RPC URL for production verification and fork testing:

| Network | RPC URL |
|---------|---------|
| `ethereum` | `https://eth.llamarpc.com` or `$ETH_RPC_URL` env var |
| `arbitrum` | `https://arb1.arbitrum.io/rpc` or `$ARBITRUM_RPC_URL` env var |
| `optimism` | `https://mainnet.optimism.io` or `$OPTIMISM_RPC_URL` env var |
| `base` | `https://mainnet.base.org` or `$BASE_RPC_URL` env var |
| `polygon` | `https://polygon-rpc.com` or `$POLYGON_RPC_URL` env var |
| `bsc` | `https://bsc-dataseed1.binance.org` or `$BSC_RPC_URL` env var |
| `avalanche` | `https://api.avax.network/ext/bc/C/rpc` or `$AVALANCHE_RPC_URL` env var |
| Other (URL) | Use as-is |

**Priority**: Environment variable > default public RPC. Store resolved URL as `RPC_URL` " used by Phase 1 TASK 11 (production verification) and Phase 5 (fork testing with `--fork-url`).

If `NETWORK` is not set: orchestrator infers from codebase (chainId constants, deployment configs, foundry.toml `[rpc_endpoints]`). If inference fails, production verification runs without fork testing.

---

## Step 1: Language Detection

Detect the target language before anything else:

| Indicator | Language | `LANGUAGE` value |
|-----------|----------|-----------------|
| `*.sol` files + `foundry.toml` or `hardhat.config.*` | **EVM/Solidity** | `evm` |
| `*.rs` files + `Anchor.toml` or `Cargo.toml` with `solana-program`/`anchor-lang` | **Solana/Anchor** | `solana` |
| `*.rs` files + `Cargo.toml` WITHOUT `solana-program`/`anchor-lang` | **Native Solana (no Anchor)** | `solana` (with `ANCHOR=false` flag) |
| `*.move` files + `Move.toml` with `aptos_framework`/`aptos_std`/`aptos_token`/`fungible_asset` | **Aptos Move** | `aptos` |
| `*.move` files + `Move.toml` with `sui::object`/`sui::transfer`/`sui::tx_context`/`sui::coin` | **Sui Move** | `sui` |
| `*.rs` files + `Cargo.toml` with `soroban-sdk` | **Soroban/Stellar** | `soroban` |

**Detection procedure** (decide PRIMARILY from the dominant source EXTENSION; use manifests only to disambiguate within a language family):
1. **Count source files recursively** under PROJECT_PATH (excluding `node_modules/`, `target/`, `build/`, `lib/`): how many `*.sol`, how many `*.rs`, how many `*.move`. The most common recognized suffix is the dominant signal.
2. **Walk UP** from PROJECT_PATH to the nearest `Cargo.toml` / `Move.toml` — the manifest is commonly an ancestor of a scope-dir PROJECT_PATH (e.g. `.../<crate>/src/`), so a manifest grep in the literal project root alone is unreliable. Locate the manifest by ascending parent directories until found.
3. **If `*.sol` dominant** → `LANGUAGE=evm`.
4. **If `*.rs` dominant**: grep the located `Cargo.toml` — `soroban-sdk` → `soroban`; `anchor-lang`/`solana-program` (or `*.rs` markers `#[program]`/`#[derive(Accounts)]`) → `solana` with `ANCHOR=true`; native Rust Solana → `solana` with `ANCHOR=false`. The manifest grep ONLY disambiguates solana-vs-soroban; it never overrides the dominant-extension decision.
5. **If `*.move` dominant**: grep the located `Move.toml` for Aptos indicators (`AptosFramework`, `aptos_framework`, `aptos_std`, `aptos_token`, `fungible_asset`) → `aptos`; Sui indicators (`sui::object`, `sui::transfer`, `sui::tx_context`, `sui::coin`) → `sui`. If still ambiguous, grep `*.move` for `use aptos_framework::` (Aptos) or `use sui::` (Sui).
6. **Use explicit if/elif blocks** — never a chained `&&`/`||` one-liner (precedence is wrong). Do NOT silently default to `evm`: if no recognized source files are found, treat the language as **indeterminate** and confirm explicitly rather than guessing. The Python driver runs a STARTUP language<->source-extension consistency gate that HALTS the run on a definite contradiction (e.g. `language=evm` but only `*.rs` found), so a misroute is caught before breadth rather than after a multi-hour run.
7. Set `LANGUAGE` variable: `evm`, `solana`, `aptos`, `sui`, or `soroban`.
8. Set `ANCHOR` variable: `true` or `false` (Solana only).

## Step 1.5: Scratchpad + Artifact Folders

Before Phase 1 recon:

```bash
mkdir -p {PROJECT_ROOT}/.scratchpad
mkdir -p {PROJECT_ROOT}/artifacts/call-graphs
```

Set `SCRATCHPAD = {PROJECT_ROOT}/.scratchpad`.

Rule: generated auxiliary files belong under `{PROJECT_ROOT}/artifacts/`, never
in the project root. For EVM call-graph DOT exports, always use
`{PROJECT_ROOT}/artifacts/call-graphs/`.

**Tree architecture " path resolution**:
- **Language-specific prompts**: `~/.claude/prompts/{LANGUAGE}/`
- **Shared rules**: `~/.claude/rules/`
- **Skills**: `~/.claude/agents/skills/{LANGUAGE}/`
- **Injectable skills**: `~/.claude/agents/skills/injectable/`
- **Niche agents**: `~/.claude/agents/skills/niche/`
- **Depth agents**: `~/.claude/agents/depth-*.md`

---

## §WRITE-THEN-VERIFY: Subagent Output Protocol

> **Why**: The old pattern where agents return full output (~10-30 KB each) fills the orchestrator's context by Phase 4b, triggering context anxiety and self-imposed step skips. With 30+ agents at ~15 KB each, the orchestrator accumulates ~450 KB of agent output " leaving no room for depth iteration 2, niche agents, Skeptic-Judge, or later phases. The v1.1.5 dHEDGE audit proved this: the orchestrator skipped 20 agents and 0/19 manifest artifacts were produced.

**Protocol** (include in EVERY agent spawn prompt after the output file path):

```
Write your output directly to {SCRATCHPAD}/{expected_filename} using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to {filename}"
Do NOT return your full output as text " the orchestrator's context budget is limited.
```

**Orchestrator verification** (runs after EACH agent returns " mechanical, no reasoning):

```bash
FILE="{SCRATCHPAD}/{expected_filename}"
if [ -f "$FILE" ] && [ "$(wc -c < "$FILE")" -gt 100 ]; then
  echo "[VERIFY OK] $FILE ($(wc -l < "$FILE") lines)"
else
  echo "[VERIFY FAIL] $FILE missing or empty" | tee -a "{SCRATCHPAD}/violations.md"
fi
```

If VERIFY FAIL: re-prompt the agent with `"Your Write to {FILE} failed. Return your full output as text now."` Then Write from the main session.

**Context savings**: ~50 bytes per agent return vs ~15 KB. With 40 agents: ~2 KB total vs ~600 KB.

## §STEP-TRACE: Depth Agent Step Execution Trace Directive (advisory)

> **Mode gate**: Thorough mode only. Light/Core depth agents do NOT need to emit a step trace.
> **Inject Into**: every Thorough-mode SC depth agent prompt (depth-token-flow, depth-state-trace, depth-edge-case, depth-external).
> **Why**: Per-skill-step coverage observability.
>
> **v2.3.3 status**: Agent-emit is now ADVISORY. The Python driver auto-synthesizes
> `step_execution_trace_{role}.md` from your `depth_{role}_findings.md` evidence-tag density
> if you don't emit a richer one. Agents that DO follow the directive get per-skill
> granularity preserved; agents that don't no longer halt the pipeline.

Include this block verbatim in every Thorough-mode SC depth agent prompt:

> Before returning, you SHOULD write `{SCRATCHPAD}/step_execution_trace_{your_role}.md` (where `{your_role}` is the suffix of your output filename " e.g., `token_flow`, `state_trace`, `edge_case`, `external`). If you do not, the driver will synthesize this file from your findings' evidence-tag density.
>
> This file accounts for whether each numbered section in your inherited skills was executed. Format:
>
> ```markdown
> # Step Execution Trace " depth-{your_role}
>
> | Skill | Step | Executed | Evidence | Result |
> |-------|------|----------|----------|--------|
> | {SKILL_NAME_A} | 1 | yes | {your-codebase}/{file}.sol:L{line} | {finding-id} |
> | {SKILL_NAME_A} | 2 | yes | {your-codebase}/{file}.sol:L{line} | safe ({brief justification}) |
> | {SKILL_NAME_A} | 3 | partial | {your-codebase}/{file}.sol:L{line} | partial: {what's left} |
> | {SKILL_NAME_A} | 4 | no | - | - |
> | {SKILL_NAME_B} | 1 | yes | {your-codebase}/{file}.{ext}:L{line} | {finding-id} |
> ```
>
> The `{...}` tokens above are placeholders showing the schema " replace with REAL values from the codebase you are auditing. Do NOT copy the placeholder text verbatim. Cite real file paths from THIS audit's source tree, not from any example or prior audit. File extensions vary by language: `.sol` (Solidity), `.rs` (Soroban / Solana / Aptos / Sui), `.move` (Move). Use whatever extension matches your audit target.
>
> **One row per (skill, numbered-section) pair** for every skill listed in `template_recommendations.md` BINDING MANIFEST as `Required = YES` and routed to your role per `~/.claude/rules/skill-index.md` "Inject Into" column. Resolve the numbered sections by reading each skill's `SKILL.md` " sections start with `## N. Title`.
>
> **Allowed `Executed` values**:
> - `yes` " section executed; Evidence MUST contain a `file:line` token (e.g. `Vault.sol:L45` or `Vault.sol:L45-67`). The driver hard-rejects ceremonial `yes` rows without `file:line` evidence.
> - `partial` " partially executed; Evidence MUST cite what WAS analyzed and Result MUST state what's left.
> - `no` " not executed; Evidence may be `-`. The driver aggregates these for the next phase.
>
> **Result column**:
> - For `yes` rows: a finding ID (e.g. `DEPTH-TF-3`, `BLIND-1`) OR `safe (justification)` if the analysis confirmed no bug.
> - For `partial`/`no` rows: empty or `-`. The driver consumes these via `step_execution_gaps_mechanical.md` to spawn iter2 / DA / skill-checklist coverage.
>
> If you skipped a skill entirely because its trigger conditions are not met in the codebase (e.g., `FLASH_LOAN_INTERACTION` when no flash-loan callbacks exist), write ONE row per skill with `Step = N/A`, `Executed = no`, `Result = trigger condition absent: <reason>`. Do not silently omit skills.
>
> **Why this matters**: Iteration-1 depth agents that produce 7-15 findings while leaving 60% of inherited skill sections unexecuted is the documented root cause of Plamen's recall ceiling on L1 mode. The same dynamic likely applies to SC. The trace makes execution mechanically observable; the driver derives the iter2 directive from it deterministically.

## Anti-Context-Anxiety Directive

> **You have a 1M token context window. You are NOT running out of space.** Do NOT skip mandatory steps due to perceived context pressure. If you find yourself reasoning about "context budget", "practical constraints", or "efficiency" when deciding whether to execute a pipeline step " STOP. That reasoning is context anxiety, not a real constraint. Execute the step. If compaction occurs, read `{SCRATCHPAD}/pipeline_checkpoint.md` to recover state.

## Checkpoint Manifest (written at every phase boundary)

After EACH phase completes (1, 2, 3, 3b, 4a, 4a.5, 4b, 4c, 5, 6), the orchestrator writes:

```bash
cat > "{SCRATCHPAD}/pipeline_checkpoint.md" << 'CHECKPOINT'
# Pipeline Checkpoint
Phase: {current_phase}
Mode: {MODE}
Language: {LANGUAGE}
Completed: {comma-separated list of completed phases}
Next: {next phase and first step}
Findings: {total count from findings_inventory.md}
Artifacts: {comma-separated list of scratchpad .md files}
CHECKPOINT
```

This file survives compaction (read from disk). After any compaction event, the orchestrator reads it to recover pipeline state instead of relying on in-context memory.

---

## WORKFLOW OVERVIEW

> **ARCHITECTURE**: Recon -> Instantiation -> Parallel Breadth -> [Thorough: Re-Scan + Per-Contract] -> Inventory -> [Core/Thorough: Semantic Invariants] -> Adaptive Depth Loop -> Chain Analysis -> Verification -> Report

| Phase | Agent(s) | Output | Light | Core | Thorough |
|-------|----------|--------|-------|------|----------|
| **Phase 1** | Recon Agent(s) | Artifacts + templates | 2 sonnet (no RAG/fork) | 4 agents | 4 agents |
| **Phase 2** | Orchestrator | Instantiated prompts | All | All | All |
| **Phase 3** | Breadth Agents | Findings files | 3-4 sonnet | 5-9 claude-opus-4-8 | 5-9 claude-opus-4-8 |
| **Phase 3b** | Re-Scan + Per-Contract | Masked findings | Skip | Skip | Thorough only |
| **Phase 4a** | Inventory Agent | Findings inventory | 1 sonnet | 1 sonnet | 1 sonnet |
| **Phase 4a.5** | Semantic Invariant Agent | Write-sites + invariants | Skip | Pass 1 | Pass 1+2 |
| **Phase 4b** | Depth Loop | Deep analysis | 4 merged sonnet, no scoring | 8+ agents, 2-axis scoring | 8+ agents, 4-axis scoring |
| **Phase 4c** | Chain Analysis | Hypotheses + chains | 1 sonnet (merged) | 2 agents | 2 agents + iter 2 |
| **Phase 5** | Verifiers | PoC tests (Medium+) | Medium+ (sonnet) | Medium+ | ALL severities + fuzz |
| **Phase 5.1** | Skeptic-Judge | Adversarial re-verify | Skip | Skip | HIGH/CRIT |
| **Phase 5.2** | Cross-batch consistency | Contradiction check | Skip | 1 haiku | 1 haiku |
| **Phase 6** | Report pipeline | AUDIT_REPORT.md | 2 agents (sonnet+haiku) | 5 agents | 5 agents |

### Light Mode Orchestration

When `MODE == light`, the orchestrator applies these overrides:

1. **All agents use Sonnet or Haiku** " no Opus spawns. Use `model="sonnet"` for all analysis/verification agents, `model="haiku"` for assembler only.
2. **Recon**: Spawn 2 sonnet agents (not 4). Agent L1 = build + static analysis + tests (Tasks 1,2,8,9). Agent L2 = docs + patterns + surface + templates (Tasks 3,4,5,6,7,10). Skip RAG meta-buffer (Task 0) and fork ancestry entirely.
3. **Breadth**: Cap at 3-4 sonnet agents (not 5-9 claude-opus-4-8). Use same merge hierarchy.
4. **Semantic Invariants**: Skip entirely. Depth agents read `state_variables.md` directly.
5. **Depth Loop**: Spawn 4 merged sonnet agents " (a) combined token-flow + state-trace, (b) combined edge-case + external, (c) combined scanner A+B+C, (d) validation sweep. No niche agents, no injectable investigation agents. Iteration 1 only, no confidence scoring. **Note**: Merges (a) and (c) are deliberate exceptions to the standard merge hierarchy " token-flow + state-trace and 3-scanner compression reduce agent count at the cost of per-domain attention depth. This is a known tradeoff accepted for Pro plan rate limit compliance.
6. **Chain Analysis**: Single sonnet agent performs both enabler enumeration and chain matching in one pass.
7. **Verification**: ALL Medium+ (same scope as Core), but all verifiers are sonnet.
8. **Report**: 1 sonnet writer (all tiers) + 1 haiku assembler. No separate index agent " writer handles ID assignment inline.
9. **Report disclaimer**: Include at the top of the report: *"This audit was performed in Light mode (all Sonnet agents). For maximum coverage, use Core or Thorough mode with a Max plan."*

---

## Phase 1: Reconnaissance

### Step 0.9: Initialize Scratchpad

After creating the scratchpad directory and before spawning recon agents, ensure `violations.md` exists:

```bash
echo “# Plamen violations log” > “{scratchpad}/violations.md”
```

The V2 driver (`plamen_driver.py`) handles artifact gate enforcement between phases automatically. Every workflow violation per CLAUDE.md Rule 12 is logged to `violations.md`.

### Step 1: Read Recon Prompt
**Read full prompt from**: `~/.claude/prompts/{LANGUAGE}/phase1-recon-prompt.md`

Replace placeholders: `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}`

### Step 1b: Spawn 4 Recon Agents (MANDATORY SPLIT)

**Do NOT spawn a single monolithic recon agent.** Read the ORCHESTRATOR SPLIT DIRECTIVE in the prompt header and split into 4 agents. The prompt file may contain 4 separate `Task()` blocks (Solana/Aptos/Sui) or 1 monolithic block with a split directive (EVM) " in either case, split as follows:

| Agent | Spawn | Model | Await? |
|-------|-------|-------|--------|
| **1A (RAG)** | `run_in_background: true` | sonnet | **NO** " fire-and-forget |
| **1B (Docs + External)** | foreground | claude-opus-4-8 (Core/Thorough) or sonnet (Light) | YES |
| **2 (Build + Slither)** | foreground | sonnet | YES |
| **3 (Patterns + Surface)** | foreground | claude-opus-4-8 (Core/Thorough) or sonnet (Light) | YES |

**Agent 1A is FIRE-AND-FORGET**: spawn in background, never block on it. If it hasn't returned when 1B/2/3 finish, write fallback `meta_buffer.md` and proceed.

**Light mode override**: Spawn only 2 merged agents (both sonnet, both foreground). Skip RAG (Agent 1A) and fork ancestry entirely per Light Mode Orchestration override #2.

### After Agents 1B, 2, 3 Return
1. Verify artifacts exist: `ls {scratchpad}/`
2. Read: `recon_summary.md`, `template_recommendations.md`, `attack_surface.md`
2b. **Operational Implications quality gate (Rule 14)**: Read `{scratchpad}/design_context.md`. Verify it contains an `## Operational Implications` section with at least one implication per documented Key Invariant. If the section is missing or contains fewer implications than invariants, re-prompt Agent 1B: `"The Operational Implications section in design_context.md is incomplete. For each Key Invariant, state what it means for how the system's accounting works " not what it checks, but what it tells you about the system's model. Derive from invariant formulas and data structure signatures."` This gate prevents downstream agents from analyzing a protocol they don't understand.
3. **RAG resilience check**: If `meta_buffer.md` does not exist or is empty (Agent 1A still running or failed):
   - Spawn lightweight RAG-retry agent (haiku, <2 min, 3 queries only):
     1. get_common_vulnerabilities(protocol_type)
     2. get_attack_vectors(primary_pattern)
     3. search_solodit_live(protocol_category=[category], quality_score=3, max_results=10)
   - Write results to meta_buffer.md
   - If retry also fails: proceed with empty meta_buffer.md
4. **Hard gate**: ALL artifacts must exist before Phase 2
5. **Mandatory closeout**: Close completed recon agents before Phase 2. Do not
   carry finished recon workers into breadth.
6. **Overreach rule**: If a recon agent writes files outside the recon artifact
   set, ignore those extra files for phase progression, record a violation, and
   continue using only the expected recon outputs.

---

## Phase 2: Orchestrator Instantiation

### Step 2a: Determine Agent Count
| Condition | Agent Count |
|-----------|-------------|
| Simple (<5 deps, <2000 lines) | 3 agents |
| Medium (5-10 deps, 2000-5000 lines) | 5-7 agents |
| Complex (>10 deps or >5000 lines) | 7-9 agents |

**Minimum always**: 1 core state, 1 access control, 1 per major external dep (overrides Simple tier if needed)

**Breadth-to-depth redirect**: When actual breadth agent count is below the Medium baseline (5), the saved slots increase the depth budget floor: `depth_floor = 12 + (5 - actual_breadth_count)`.

### Step 2a.1: Merge Hierarchy (when required templates exceed target count)

| Priority | Merge | Rationale |
|----------|-------|-----------|
| M1 | TEMPORAL_PARAMETER_STALENESS + core state agent | Cached params are state mutations |
| M2 | SEMI_TRUSTED_ROLES + access control agent | Roles are access control |
| M3 | SHARE_ALLOCATION_FAIRNESS + core state agent | Allocation fairness is state correctness |
| M4 | ECONOMIC_DESIGN_AUDIT + core state agent | Monetary params are state correctness |
| M5 | EXTERNAL_PRECONDITION_AUDIT + external dependency agent | External preconditions are external dep analysis |

**Rules**: Never merge two skills both requiring >5 analysis steps. Never merge across incompatible domains. **Never merge FLASH_LOAN_INTERACTION or ORACLE_ANALYSIS with any other skill.** **Max 2 templates per agent (including injectables) AND max 300 combined SKILL.md lines.** If a 2-template merge would exceed 300 lines, split into an additional breadth agent instead. Narrower scope per agent improves depth " agents reliably execute ~300 lines of skill payload but degrade on larger prompts (validated by multi-agent audit research: LLMBugScanner, iAudit).

### Step 2a.2: Move-Safety Agent (Aptos/Sui only)

For Aptos and Sui audits, the 4 always-required skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, REF_LIFECYCLE/OBJECT_OWNERSHIP) total ~900-950 lines " far exceeding the 300-line breadth agent cap. These are split into two delivery layers:

1. **Core directives** (~130 lines): Loaded into EVERY breadth agent via `~/.claude/agents/skills/{LANGUAGE}/move-safety-core-directives/SKILL.md`. Contains inventory greps + flag tables. Counts toward the 300-line cap but leaves ~170 lines for conditional skills.
2. **Move-Safety Agent** (1 dedicated agent): Spawned in Phase 3 alongside breadth agents. Loads ALL 4 full skill files (~950 lines). Runs the complete trace methodology that breadth agents cannot fit. Costs 1 breadth agent slot.

The Move-Safety Agent prompt: load all 4 always-required SKILLs into a single agent with scope = "full Move-specific safety analysis." It is a breadth producer and MUST write `analysis_move_safety.md`; inventory consumes it through the normal `analysis_*.md` input set. It must not write `findings_inventory.md` directly. Depth agents still receive full skills per their injection rules (depth agents have separate context windows, not subject to the breadth merge cap).

**EVM/Solana**: No Move-Safety Agent needed. EVM has no always-required skills. Solana has ACCOUNT_VALIDATION (130 lines) which fits within the 300-line cap.

### Step 2b: Instantiate Templates
For each template in `template_recommendations.md`:
1. Read template from `~/.claude/agents/skills/{LANGUAGE}/{template-name}/SKILL.md` (folder name is lowercase-hyphenated version of the template name, e.g., ORACLE_ANALYSIS â†’ oracle-analysis)
2. For Aptos/Sui breadth agents: load `move-safety-core-directives/SKILL.md` instead of the 4 individual always-required skills. The full skills go to the Move-Safety Agent only.
3. Replace `{PLACEHOLDERS}` with instantiation parameters
4. **Conditional loading**: Strip sections wrapped in `<!-- LOAD_IF: FLAG -->...<!-- END_LOAD_IF: FLAG -->` when the flag was NOT detected
5. Compose agent prompt with instantiated template

### Step 2b.1: Load Injectable Skills (Split Delivery)
1. Read protocol type from `{scratchpad}/template_recommendations.md` â†’ `## Injectable Skills`
2. For each recommended injectable: Read from `~/.claude/agents/skills/injectable/{skill-name}/SKILL.md`
3. **Breadth agents**: Extract ONLY section headers + key questions (1-line per section, ~200 tokens max)
4. **Depth agents (Phase 4b)**: Generate specific investigation questions per depth domain. Spawn **dedicated Injectable Investigation Agents** (sonnet, 1 per domain) IN PARALLEL with main depth agents
5. Injectable skills spawn up to 4 dedicated sonnet agents (1 per domain), each costing 1 depth budget slot

### Step 2b.2: Merge Cap Enforcement Gate (MANDATORY)

**BEFORE composing any agent prompt**, the orchestrator MUST verify the 300-line cap mechanically:

```
For each planned breadth agent:
  combined_lines = 0
  For each SKILL.md assigned to this agent:
    line_count = wc -l ~/.claude/agents/skills/{LANGUAGE}/{skill-name}/SKILL.md
    combined_lines += line_count
  ASSERT: combined_lines <= 300
  If FAIL:
    Log: "MERGE CAP VIOLATED: Agent {N} has {combined_lines} lines ({skill_list}). Splitting."
    Split the largest skill into its own dedicated agent.
    Re-run this gate.
```

**This is a mechanical check " run `wc -l` on actual files, do not estimate.** The 300-line cap was validated by multi-agent audit research (LLMBugScanner, iAudit): agents reliably execute ~300 lines of skill payload but degrade on larger prompts. Violations of this cap directly cause RC-AGENT misses where methodology exists but agents don't execute it.

**Soroban note**: Soroban skills average 30% larger than Solana equivalents. Merges that fit at Solana sizes often exceed 300 lines at Soroban sizes. Always check " never assume a merge that works for one language works for another.

### Step 2c: Agent Prompt Structure
```
You are Analysis Agent #{N}: {FOCUS_AREA}

## Protocol Context
{Brief from design_context.md}

## Your Analysis Task
{INSTANTIATED_TEMPLATE}

## Analysis Strategy " Targeted Sweeps
Do NOT attempt to find all vulnerability types in a single pass.
Instead, for each vulnerability class in your methodology:
1. Sweep the ENTIRE scope for THIS class specifically
2. Write findings for this class before moving on
3. Proceed to the next vulnerability class

## Artifacts Available
{list scratchpad files}

## Output Requirements
Write to {SCRATCHPAD}/analysis_{focus_area}.md
Use finding IDs: [{PREFIX}-1], [{PREFIX}-2]...

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases (re-scan, per-contract, inventory, semantic invariants, depth, RAG, chain analysis, verification, report). Return your findings and stop.
```

### Step 2c.1: MCP Timeout Directive (MANDATORY " Rule 11)

Every agent prompt that makes MCP tool calls (recon agents, depth agents, chain agents, verifiers, RAG sweep) MUST include this directive at the end of its prompt:

*"When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider " switch immediately to fallback (code analysis, grep, WebSearch). Claude Code's tool timeout is set to 300s (5 min) via MCP_TOOL_TIMEOUT in settings.json to accommodate ChromaDB cold start. You cannot cancel a pending call " but you control what happens after the error returns."*

The orchestrator MUST append this text when composing prompts for MCP-calling agents. Agents that do not make MCP calls (pure code analysis breadth agents, report writers) do not need it.

### Step 2d: Spawn Verification Gate (MANDATORY)

**BEFORE spawning agents**:
1. Read BINDING MANIFEST from `{scratchpad}/template_recommendations.md`
2. Verify agent queued for EACH template marked `Required? = YES` or `Required = YES`
3. If ANY required template missing â†’ **HALT and add**

**Write spawn manifest** to `{scratchpad}/spawn_manifest.md`:
```markdown
# Spawn Manifest
| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | CORE_STATE | YES | B1 | core_state | analysis_core_state.md | QUEUED |
**Gate Check**: All REQUIRED templates have agents? [YES/NO]
```

`spawn_manifest.md` is a machine-read contract. Put only spawned first-pass
breadth agents in `Row Type = AGENT` rows. Every AGENT row must name exactly
one `analysis_<focus>.md` Expected Output. Put skill/injectable/template
bindings in a separate `## Skill Bindings` section, not in the AGENT table.
Never include `verify_*.md`, `analysis_rescan_*.md`,
`analysis_percontract_*.md`, inventory, depth, chain, verification, or report
artifacts as first-pass breadth outputs.
Spawn only templates marked required (`Required? = YES` / `Required = YES`).
Optional templates may be folded into an existing spawned agent and recorded
under `## Skill Bindings`; they must not create AGENT rows unless promoted to
required.

---

## Phase 3: Parallel Analysis

**CRITICAL**: Spawn ALL analysis agents in a SINGLE message as parallel Task calls.

After all return:
1. Verify: `ls {scratchpad}/analysis_*`
2. **Post-spawn verification**: For each REQUIRED template in spawn manifest:
   - `{scratchpad}/analysis_{focus_area}.md` exists
   - File contains findings (not empty/error)
   - Template methodology was applied
3. If ANY required file missing â†’ **Re-spawn that agent before Phase 4a**
4. Update spawn_manifest.md with completion status
5. Do NOT read analysis files " inventory agent reads them
6. Close completed breadth agents before inventory begins.
7. If any breadth agent wrote later-phase files (inventory/depth/chain/verify/report),
   treat those files as invalid overreach for sequencing purposes. Record the
   violation, close the offending agent, and continue the pipeline from inventory
   using only valid `analysis_*` outputs.

### Phase 3b: Breadth Re-Scan (THOROUGH mode only)

**Skip in Light and Core mode.**

**Read full prompt from**: `~/.claude/rules/phase3b-rescan-prompt.md`

**Flow**: first-pass breadth runs first, then re-scan loop (sonnet, 2-3 agents, max 2 iterations, exit on 0 new findings above Info), then per-contract analysis (3c), then Phase 4a inventory consumes first-pass, re-scan, and per-contract outputs before Phase 4a.5. Re-scan/per-contract phases do not write `findings_inventory.md`.

---

## Phase 4: Synthesis, Adaptive Depth, Chain Analysis

**Read prompts from the corresponding phase file:**

| Step | Prompt File | Agent | Trigger |
|------|-------------|-------|---------|
| 4a | `~/.claude/prompts/{LANGUAGE}/phase4a-inventory-prompt.md` | Inventory (+ side effect trace) | Always |
| 3b | `~/.claude/rules/phase3b-rescan-prompt.md` | Breadth Re-Scan (sonnet) | Thorough only (after Phase 3, before 4a) |
| 4a.5 | (inline below) | Semantic Invariant Agent (sonnet) | Core/Thorough |
| 4b (loop) | `~/.claude/prompts/{LANGUAGE}/phase4b-loop.md` | Orchestrator | Always |
| 4b (depth) | `~/.claude/prompts/{LANGUAGE}/phase4b-depth-templates.md` | 4 Depth Agents | Always |
| 4b (scanners) | `~/.claude/prompts/{LANGUAGE}/phase4b-scanner-templates.md` | 3 Scanners + Validation + Design Stress | Always |
| 4b.4 | inline below | Attention Repair | Thorough only |
| 4c | `~/.claude/rules/phase4c-chain-prompt.md` | Chain Analysis (+ enabler enumeration) | Always |
| 5 | `~/.claude/prompts/{LANGUAGE}/phase5-verification-prompt.md` + `~/.claude/rules/phase5-poc-execution.md` | Verifiers (with PoC execution) | Both (scope differs) |
| 5.5 | (orchestrator inline) | Post-verification finding extraction | Always |
| 6a-c | `~/.claude/rules/phase6-report-prompts.md` | Index â†’ Tier Writers â†’ Assembler | Core/Thorough (Light: 2-agent override) |

### Gate Enforcement

**After Step 4a**: Read `{scratchpad}/phase4_gates.md`
- **Gate 1 BLOCKED** (missing agents): MUST re-spawn before Step 4b
- **VIOLATION**: Proceeding past BLOCKED gate without resolution

### Phase 4a.5: Semantic Invariant Pre-Computation

> **Skip in Light mode.** Depth agents read `state_variables.md` directly.
> **Timeout fallback**: If the semantic invariant agent times out or fails, proceed to Phase 4b without `semantic_invariants.md`. Depth agents fall back to reading `state_variables.md` directly (same as Light mode). Log: "Phase 4a.5 TIMEOUT " depth agents using state_variables.md fallback."

> **Purpose**: Enumerate write sites, define semantic invariants, group variables into semantic clusters. Pass 2 (Thorough only) reverses direction for functionâ†’cluster coverage and recursive stale-read traces.
> **Models**: Pass 1 sonnet, Pass 2 sonnet (sequential)

Spawn between Phase 4a (inventory) and Phase 4b (depth loop).

**Pass 1 Agent** (Variable â†’ Write Sites + Semantic Clustering):

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are Semantic Invariant Agent " Pass 1. You enumerate write sites, define semantic invariants, and group variables into semantic clusters.

## Your Inputs
Read:
- {SCRATCHPAD}/state_variables.md (all state variables from recon)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files referenced in state_variables.md

## Your Task

For EACH accumulator, snapshot, or total-tracking variable in state_variables.md:

1. **Enumerate write sites**: Use grep to find ALL locations that write to this variable.
2. **State the semantic invariant**: In ONE sentence, what SHOULD this variable represent?
3. **Enumerate value-changing functions**: Find ALL functions that change the UNDERLYING VALUE the variable tracks " whether or not they update the variable.
4. **Annotate conditional writes**: For each write site, check if the write is inside a conditional block. If YES, annotate as CONDITIONAL(condition_expression).
4a. **Detect asymmetric branches**: For each CONDITIONAL write, check if the SAME function also writes UNCONDITIONALLY to a different tracking variable. If YES, flag as ASYMMETRIC_BRANCH.
5. **Detect mirror variables**: Identify variable PAIRS tracking the same concept in different storage. For each pair, list ALL functions that write to EITHER. If any function writes to one but not the other â†’ flag as SYNC_GAP.
6. **Flag time-weighted accumulation inputs**: For (value x time_delta) calculations, note controllable inputs and whether time_delta can grow unboundedly. Flag as ACCUMULATION_EXPOSURE if both true.

## Semantic Clustering

Group ALL enumerated variables into semantic clusters " groups of variables collectively representing a single domain or lifecycle. For each cluster, identify which functions write ALL members (full-write) vs only SOME members (partial-write).

## Output

Write to {SCRATCHPAD}/semantic_invariants.md:

### Main Table
| Variable | Contract/Module | Semantic Invariant | Write Sites (with CONDITIONAL annotations) | Value-Changing Functions | Potential Gaps |

### Mirror Variable Pairs
| Variable A | Variable B | Same Concept | Functions Writing A Only | Functions Writing B Only | Sync Gaps |

### Time-Weighted Accumulators
| Accumulator | Formula Pattern | Controllable Input | Time Source | Unbounded Delta? | Exposure |

### Semantic Clusters
| Cluster Name | Variables | Lifecycle Functions | Full-Write Functions | Partial-Write Functions |

Return: 'DONE: {N} variables, {M} gaps, {C} conditional, {S} sync_gaps, {A} accumulation, {K} clusters'
")
```

**Pass 2 Agent** (THOROUGH mode only " Function â†’ Cluster Coverage + Recursive Gap Trace):

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are Semantic Invariant Agent " Pass 2. You reverse the analysis direction: for each function, check which clusters it touches incompletely, then recursively trace consequences of stale reads.

## Your Inputs
Read:
- {SCRATCHPAD}/semantic_invariants.md (Pass 1 output)
- {SCRATCHPAD}/function_list.md
- Source files for all Partial-Write Functions from the Semantic Clusters table

## STEP 1: Cluster Coverage Audit

For each Partial-Write Function in the Semantic Clusters table:
1. Which cluster members does it write? Which does it SKIP?
2. For each skipped member: describe in ONE factual sentence WHY it is skipped. This is a FACTUAL ANNOTATION " do NOT judge whether the skip is safe.
3. Flag ALL skips as CLUSTER_GAP " no exceptions.

## STEP 2: Recursive Consequence Trace

For each CLUSTER_GAP, SYNC_GAP, and CONDITIONAL where the skip path is reachable:
1. **Level 0**: Identify the stale variable and the function that leaves it stale
2. **Level 1**: Find ALL functions that READ the stale variable. What value do they produce stale vs correct?
3. **Level 2**: For each Level 1 reader that WRITES a different variable using the stale-derived value, find readers of THAT variable.
4. **Level 3**: Repeat one more level. If error still propagates â†’ flag as DEEP_PROPAGATION.

## STEP 3: Cross-Verify Pass 1 Write Sites

For each function in function_list.md that Pass 1 did NOT list as a write site for ANY variable:
1. Read the function source
2. Check: does it write to ANY state variable from the Main Table?
3. If YES and Pass 1 missed it â†’ add as MISSED_WRITE_SITE

## STEP 4: Branch Path Completeness

For each function with >=2 branches:
1. List variables written on EACH branch path
2. If any branch writes a variable that another branch does NOT â†’ flag as BRANCH_ASYMMETRY
3. For each asymmetry: is the missing write a stale-read source for any consumer?

## Output

Append to {SCRATCHPAD}/semantic_invariants.md:

### Cluster Coverage Gaps
| Function | Cluster | Written Members | Skipped Members | Skip Context (factual) | Flag |

### Recursive Consequence Traces
| Gap Source | Stale Variable | L0 Function | L1 Readers â†’ Impact | L2 Readers â†’ Impact | L3? | Max Window |

### Missed Write Sites (Cross-Verification)
| Variable | Missed Function | Write Type |

### Branch Path Asymmetries
| Function | Condition | Written on True | Written on False | Consumer Impact |

Return: 'DONE: {G} cluster_gaps, {T} consequence traces ({D} deep_propagation), {W} missed_write_sites, {B} branch_asymmetries'
")
```

### THOROUGH CHECKPOINT: Pre-Depth (orchestrator inline)

When `MODE == thorough` AND `LANGUAGE == evm`:

**Step A: Invariant Fuzz Campaign** (MANDATORY " zero budget cost)
Read template: `~/.claude/prompts/{LANGUAGE}/phase4b-invariant-fuzz.md`
Spawn agent. Await completion. Write results to `invariant_fuzz_results.md`.
The template has a 5-minute timeout built in. Do NOT skip this to save time.

**Step B: Medusa Campaign** (MANDATORY if MEDUSA_AVAILABLE " zero budget cost)
Read from `~/.claude/prompts/{LANGUAGE}/phase4b-loop.md` Medusa section.
Spawn agent IN PARALLEL with Step A. Await completion.
Write results to `medusa_fuzz_findings.md`.

**Step C: Assert Completion**
```
ASSERT: invariant_fuzz_results.md exists (or COMPILATION_FAILED logged)
ASSERT: medusa_fuzz_findings.md exists (or MEDUSA_UNAVAILABLE logged)
IF either missing AND no failure logged â†’ VIOLATION: "Fuzz campaign skipped without failure reason"
```

If violations are detected, log them to `{SCRATCHPAD}/violations.md` but continue " the violation log is the enforcement mechanism.

### Phase 4b: Adaptive Depth Loop

> **Reference**: `~/.claude/rules/phase4-confidence-scoring.md` for scoring model, anti-dilution rules, and convergence criteria.

The orchestrator runs the full loop autonomously:

1. **Light mode override**: When `MODE == light`, skip the standard 8-agent spawn. Instead spawn 4 merged sonnet agents per Light Mode Orchestration override #5: (a) combined token-flow + state-trace, (b) combined edge-case + external, (c) combined scanner A+B+C, (d) validation sweep. Skip niche agents, skip confidence scoring, skip iterations 2-3. After iteration 1 completes, proceed directly to Phase 4c chain analysis (single merged agent per override #6).

1. **Iteration 1 (Core/Thorough)**: Spawn ALL 8 standard agents + niche agents in parallel:
   - 4 depth agents (token-flow, state-trace, edge-case, external)
   - Blind Spot Scanner A (Tokens & Parameters)
   - Blind Spot Scanner B (Guards, Visibility & Inheritance + Override Safety)
   - Blind Spot Scanner C (Role Lifecycle, Capability Exposure & Reachability)
   - Validation Sweep Agent
   - **Niche agents**: For each REQUIRED niche agent in `template_recommendations.md` â†’ `Niche Agents` section, read its definition from `~/.claude/agents/skills/niche/{name}/SKILL.md` and spawn alongside depth agents. Each niche agent = 1 budget slot.
   - **Timeout split-and-retry**: If any agent times out, split its findings into 2 "lite" agents (max 3 findings each, no static analyzer, max 5 files). 2 lite agents = 1 budget unit.
   - **§STEP-TRACE injection (Thorough only " MANDATORY)**: Each of the 4 depth-agent prompts (token-flow, state-trace, edge-case, external) MUST include the §STEP-TRACE directive verbatim (see top of this file). Without it, the agent will not emit `step_execution_trace_{role}.md` and the driver's `_check_step_execution_traces` gate will hard-fail the depth phase. Light/Core mode depth spawns SKIP §STEP-TRACE " the gate is mode-gated to Thorough only. Scanners and niche agents do NOT need §STEP-TRACE (different agent class; gate operates on `depth_*_findings.md` only).

2. **Score all findings** (MANDATORY for Core/Thorough " Light mode skips scoring). Orchestrator MUST spawn the scoring agent and await `confidence_scores.md` before deciding whether to proceed to iteration 2. Skipping scoring to "go straight to chain analysis" is a VIOLATION. Spawn sonnet scoring agent â†’ `confidence_scores.md`
   - **Core mode**: 2-axis scoring (Evidence x 0.5 + Analysis Quality x 0.5)
   - **Thorough mode**: 4-axis scoring (Evidence x 0.25 + Consensus x 0.25 + Analysis Quality x 0.3 + RAG Match x 0.2)
   - CONFIDENT (>= 0.7): no more depth needed
   - UNCERTAIN (0.4-0.7): targeted depth
   - LOW CONFIDENCE (< 0.4): targeted depth + production verification + RAG deep search

3. **Iteration 2**:
   - **Core mode**: Skip iteration 2 entirely. Uncertain findings proceed to chain analysis and verification as-is.
   - **Thorough mode**: Spawn targeted Devil's Advocate depth agents per domain for ALL uncertain findings. Hard DA role: agents are structurally adversarial. Severity-weighted budget: spawn_priority = (1 - confidence) * severity_weight.
   - Anti-dilution: evidence-only finding cards, max 5 per agent
   - Re-score with new-evidence-only rule
   - **Loop dynamics detection**: Classify as CONTRACTIVE/OSCILLATORY/EXPLORATORY. If OSCILLATORY â†’ force CONTESTED, exit.

4. **Iteration 3 (Thorough mode only, if still uncertain and progress was made)**: Final targeted pass
   - Force remaining < 0.4 to CONTESTED verdict
   - Write `adaptive_loop_log.md`

5. **Post-verification error trace feedback** (Core/Thorough only): After Phase 5, if verifiers returned CONTESTED with error traces AND budget remains, spawn targeted depth with error traces as investigation questions (AD-6).

**Convergence**: Hard cap 3 iterations (Core: 1, Light: 1 with no scoring), dynamic budget cap `min(max(12, ceil(findings/5)+7), 20)`, progress check after each iteration.

> **Light mode: Phase 4b.5 RAG Sweep** " Skip entirely. RAG validation is not performed in Light mode (no confidence scoring axis requires it).

6. **Design Stress Testing (Thorough mode only)**: ALWAYS spawn Design Stress Testing Agent. 1 slot is pre-reserved and UNCONDITIONAL " not a "budget redirect." This agent runs regardless of remaining budget.

7. **Finding Perturbation Agent (Thorough mode only " MANDATORY)**: After depth iteration completes, spawn the Finding Perturbation Agent (sonnet, 1 pre-reserved budget slot). Full spawn template + mutation operators in `~/.claude/prompts/{LANGUAGE}/phase4b-loop.md` §FINDING PERTURBATION AGENT. Expected output: `{SCRATCHPAD}/perturbation_findings.md` with `[PERT-N]` IDs. This agent applies 5 structured mutation operators (DIRECTION_FLIP, BOUNDARY_SHIFT, CONDITION_NEGATE, OPERAND_SWAP, TEMPORAL_INVERT) to each CONFIRMED depth finding and tests for adjacent vulnerabilities. Catches the "single-hit satisfaction" class where agents find one variant of a bug and stop. Research: AdverTest Feb 2026 +8.56% FDR, Meta mutation-guided test gen FSE 2025. Runs in parallel with step 8. **This is a MANDATORY THOROUGH STEP per CLAUDE.md Rule 12** " the never-cut gate enforces the output file; omission is a workflow violation.

8. **Skill Execution Checklist (Thorough mode only " MANDATORY)**: After depth iteration completes, spawn the Depth Skill Execution Checklist Agent (haiku, negligible cost, runs in parallel with step 7). Full spawn template in `~/.claude/prompts/{LANGUAGE}/phase4b-loop.md` §DEPTH SKILL EXECUTION CHECKLIST. Expected output: `{SCRATCHPAD}/skill_execution_gaps.md` (also satisfies `skill_execution_checklist.md` via any_of group). Verifies each depth agent executed each step of its assigned skill and produces a coverage table `| Agent | Skill Step | Evidence in Output? | Gap? |`. Gaps become investigation questions for DA iteration 2 per AD-6. **This is a MANDATORY THOROUGH STEP per CLAUDE.md Rule 12** " the never-cut gate enforces the output file; omission is a workflow violation.

> **Steps 6-8 run in parallel.** Spawn the 3 agents (DST + perturbation + checklist) in a single message with 3 Task calls, then `await` all three. Do NOT serialize " they operate on depth outputs independently and have no dependencies on each other.

### THOROUGH CHECKPOINT: Post-Depth (orchestrator inline " STATIC MANIFEST CHECK)

**Do NOT write checkpoint assertions from memory.** Read the static manifest and verify against it:

```
// STEP 0: Mode gate " this check is Thorough-only
if MODE != THOROUGH:
    // Core/Light: only assert confidence_scores.md + adaptive_loop_log.md exist, then proceed
    ASSERT: confidence_scores.md exists (Core) OR skip scoring (Light)
    ASSERT: adaptive_loop_log.md exists
    LOG to {SCRATCHPAD}/checkpoint_postdepth.md
    goto Phase 4c

// STEP 1: Read the static manifest (orchestrator MUST NOT modify this file)
manifest = Read("~/.claude/prompts/{LANGUAGE}/phase4b-required-artifacts.md")

// STEP 2: Check EVERY required artifact exists
missing = []
for each file in manifest.required_artifacts_table:
    if not exists({SCRATCHPAD}/{file}):
        missing.append({file, producer})

// STEP 3: Check niche agent artifacts
for each niche agent marked Required: YES in {SCRATCHPAD}/template_recommendations.md:
    if not exists({SCRATCHPAD}/{niche_file}):
        missing.append({niche_file, niche_agent_name})

// STEP 4: If missing â†’ spawn, do NOT proceed
if len(missing) > 0:
    LOG to {SCRATCHPAD}/violations.md: "PHASE 4b INCOMPLETE: {missing}"
    for each missing file:
        spawn the responsible agent (see Producer column in manifest)
    re-run STEP 2 after agents complete
    ASSERT len(missing) == 0 " HARD GATE, cannot proceed to Phase 4c

// STEP 5: Standard assertions
ASSERT: confidence_scores.md is non-empty
ASSERT: IF uncertain Medium+ findings exist after iter 1 â†’ adaptive_loop_log shows iter >= 2

LOG checkpoint result to {SCRATCHPAD}/checkpoint_postdepth.md
```

**WHY STATIC MANIFEST**: The orchestrator previously wrote its own checkpoint " verifying only what it remembered to do, silently skipping what it forgot. The static manifest file is defined outside the orchestrator's generation context. Missing artifacts trigger agent spawns, not silent passes.

### Phase 4b.4: Attention Repair (Thorough only)

Run only when the driver writes `{SCRATCHPAD}/attention_repair_queue.md`.
This phase repairs proven coverage/attention gaps; it is not another breadth
or depth iteration.

Inputs:
- `{SCRATCHPAD}/attention_repair_queue.md`
- The exact source file or artifact named in each queue row
- `function_list.md`, `contract_inventory.md`, `call_graph.md`, and
  `state_variables.md` only when the queued row needs symbol resolution

Do not read all `analysis_*.md`, all `depth_*_findings.md`, all `verify_*.md`,
or the full scratchpad. Do not re-audit the whole protocol.

For every queue row, write one row to `attention_repair_summary.md`:

| Queue # | Kind | Target | Verdict | Evidence | Notes |
|---------|------|--------|---------|----------|-------|

Receipt contract:
- `Queue #`, `Kind`, and `Target` must copy the queue row exactly.
- Path targets must use the full relative path, not only the basename.
- `Evidence` must cite the exact target path again with file:line evidence,
  or cite the exact target path and mark `NEEDS_HUMAN` if unavailable.

Allowed verdicts:
- `SAFE`: reviewed and no issue; include file:line evidence or a concrete
  reason why the row is unreachable.
- `CONFIRMED`: issue exists; write a finding block in
  `attention_repair_findings.md`.
- `NO_FINDING`: row was stale or already covered by a precise existing finding;
  cite the existing finding/source.
- `NEEDS_HUMAN`: only if source is unavailable or semantics depend on deployment
  data outside the repository.

Confirmed findings must use IDs `ATT-1`, `ATT-2`, ... and standard fields:

```markdown
### Finding [ATT-1]: title
**Severity**: High
**Location**: contracts/path/Contract.sol:L123
**Preferred Tag**: CODE-TRACE
**Evidence Tag**: CODE-TRACE
**Source IDs**: attention_repair_queue.md row N
**Description**: ...
```

Repair priorities:
- NOTREAD or uncovered files: inspect every externally reachable function in
  the queued file for access control, value flow, external-call side effects,
  accounting invariants, stale reads, upgrade/storage layout, and unbounded
  iteration.
- Uncited security files: inspect only the named file and direct callers/callees
  needed to determine reachability.
- Graph/coverage rows: resolve the exact uncertain row and either confirm it
  with evidence or mark it SAFE with the missing edge explained.

SCOPE: Write ONLY to `attention_repair_summary.md` and, if needed,
`attention_repair_findings.md`. Do NOT proceed to RAG, chain analysis,
verification, or report.

---

### Phase 4b.5: RAG Validation Sweep (MANDATORY for Core/Thorough)

Read: `~/.claude/rules/phase4-confidence-scoring.md` â†’ "Phase 4b.5" section.
Spawn sonnet RAG sweep agent. This is NOT optional.
If MCP tools fail â†’ agent falls back to WebSearch â†’ if that fails â†’ floor scores (0.3).
The sweep MUST be attempted. Writing floor scores without attempting is a VIOLATION.

> **If RAG is not built**: The unified-vuln-db MCP server may not be running. The sweep agent will detect this on the first tool call and fall back to WebSearch automatically. The pipeline continues with reduced historical context. To enable RAG, the user should run `plamen rag` in their terminal before the next audit.

### Phase 5: Verification (Batched Spawning)

> **Read templates from**: `~/.claude/prompts/{LANGUAGE}/phase5-verification-prompt.md` + `~/.claude/rules/phase5-poc-execution.md`

**Step 5.0: Compute verification scope**

Read `{SCRATCHPAD}/hypotheses.md` (first 100 lines ONLY " hypothesis table). Count hypotheses per severity tier.

| Mode | Scope |
|------|-------|
| Light | ALL Medium+ (all sonnet) |
| Core | ALL Medium+ (claude-opus-4-8 for High/Chain, sonnet for Medium) |
| Thorough | ALL severities (claude-opus-4-8 for High/Chain, sonnet for Medium, sonnet for Low/Info) + fuzz variants |

**Step 5.0.1: Crash resume " skip already-verified hypotheses**

Before spawning, scan `{SCRATCHPAD}/` for existing `verify_*.md` files. For each file, extract the hypothesis IDs it covers (from the `## Scope:` header or `### H-XX` sections). Remove those IDs from the verification queue. Only spawn verifiers for MISSING hypotheses.

**Step 5.0.2: Batched spawning (when total verifiers > 8)**

If total verifiers to spawn **â‰¤ 8**: spawn ALL in a single parallel message (standard behavior " no batching needed).

If total verifiers to spawn **> 8**: split into severity-tier batches. Spawn each batch, await ALL agents in that batch, then spawn the next batch.

| Batch | Contains | Model | Max parallel agents |
|-------|----------|-------|---------------------|
| A | Chain hypotheses (CH-*) + High standalone | claude-opus-4-8 | all (typically 7-10) |
| B | Medium (first half, up to 6) | sonnet | 6 |
| C | Medium (second half) | sonnet | 6 |
| D | Low + Info (single agent covering ALL) | sonnet | 1 |

> **Batch sizing**: If a tier has â‰¤ 6 hypotheses, it fits in one batch. If > 6, split into sub-batches of â‰¤ 6. Chains + High are always in the same batch (both claude-opus-4-8, rarely > 10 combined).

> **Between batches**: Do NOT read the `verify_*.md` files written by the completed batch. Only note the short return message from each agent. Detailed output lives on disk " the orchestrator does not need it until Phase 5.5/6.

> **Batch D (Low/Info)**: Always a SINGLE agent that handles all Low + Info hypotheses via code trace. This is already the standard approach " no change here.

**Step 5.0.3: Verifier output convention**

Each verifier writes its full output to `{SCRATCHPAD}/verify_{id}.md` (on disk). The agent return message to the orchestrator MUST be short:

```
Return: '{HYPOTHESIS_ID}: {VERDICT} | {evidence_tag} | {1-sentence justification}'
```

This keeps return messages to ~50 tokens per agent instead of the full verification output accumulating in orchestrator context.

### Phase 5.1: Skeptic-Judge Verification (Thorough mode only, HIGH/CRIT)

> **Read templates from**: `~/.claude/prompts/{LANGUAGE}/phase5-verification-prompt.md` â†’ "Skeptic-Judge Verification" section

After ALL standard Phase 5 verifiers complete:
1. Identify all HIGH/CRIT findings with standard verdicts
2. For EACH, spawn a skeptic agent (sonnet) with INVERSION MANDATE
3. If skeptic AGREES â†’ final verdict = standard verdict (high confidence)
4. If skeptic DISAGREES â†’ spawn haiku judge ("prove it or lose it" " stronger mechanical evidence wins)
5. Apply final verdict per the ruling table in the verification prompt

**Skip in Light and Core mode.**
**Thorough mode**: This step MUST execute for every HIGH and CRITICAL finding. "All PoCs passed so skeptic is unnecessary" is not a valid skip reason.

### Phase 5.2: Cross-Batch Consistency Check (Core/Thorough)

> **Skip in Light mode.**

After ALL verification batches complete (including Skeptic-Judge in Thorough mode), spawn a haiku agent to check for contradictions between verifier outputs:

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Cross-Batch Consistency Agent. Check for contradictions across verification batches.

Read ALL verify_*.md files in {SCRATCHPAD}/.

For EACH finding that was verified by multiple agents or referenced across batches:
1. Check: do any two verifiers reach OPPOSITE conclusions about the same finding?
2. Check: does any verifier's PoC contradict another verifier's assumptions?
3. Check: are there severity inconsistencies for findings with the same root cause?

Write to {SCRATCHPAD}/cross_batch_consistency.md:
| Finding | Verifier A | Verdict A | Verifier B | Verdict B | Contradiction? | Resolution |

If contradictions found: flag them for the report index agent to resolve (higher-evidence verdict wins).
If no contradictions: write 'No cross-batch contradictions detected.'

Return: 'DONE: {N} findings checked, {C} contradictions found'
")
```

### Phase 5.5: Post-Verification Finding Extraction

After ALL verifiers complete:
1. Read all `verify_*.md` files in the scratchpad
2. Extract any `[VER-NEW-*]` observations from "New Observations" sections
3. For each: check if already covered by an existing hypothesis
4. If NOT covered: create a new hypothesis and add to `hypotheses.md`
5. Assign severity using the standard matrix
6. These do NOT require re-verification

### Phase 6: Report Generation

> **Light mode override**: Do NOT read `~/.claude/rules/phase6-report-prompts.md`. Instead, spawn 2 agents: (1) a single sonnet writer handling ID assignment, root-cause consolidation, and all severity tiers inline; (2) a haiku assembler that merges the writer output with the report header template. No separate index agent or tier-split writers. Include the Light mode disclaimer per override #9.

> **Core/Thorough**: Read `~/.claude/rules/phase6-report-prompts.md` and follow the full 5-agent pipeline (Index â†’ 3 Tier Writers â†’ Assembler).

> **V2 driver sharded execution (v2.1.2)**: When this prompt is invoked by the V2 driver (`plamen_driver.py`) in Core/Thorough mode, each sub-step below is a SEPARATE `claude -p` subprocess with its own timeout. The driver extracts ONLY the relevant sub-step section for each subprocess (via `extract_phase_sections`). Do NOT attempt to run multiple sub-steps in one conversation when the incoming prompt contains only ONE of the sub-sections below " that signals a sharded execution and you must execute only the one section you received and then stop. V1 (LLM-orchestrator) runs all sub-steps in one conversation as before.

#### Step 6a: Index Agent

**Scope**: Produce the Master Finding Index (`report_index.md`) and `report_coverage.md` from `findings_inventory.md`, `verify_*.md` files, `rag_validation.md`, `finding_mapping.md`, and chain outputs. Apply STEP 1.5 Root-Cause Consolidation and STEP 5.5 Promotion Coverage Audit.

**Execution**: Read `~/.claude/rules/phase6-report-prompts.md` §Step 6a and follow it verbatim. The Index Agent is ONE `general-purpose` subagent with `model="haiku"`. Verify completeness inline per §Step 6a.1.

**Output contract**: `{SCRATCHPAD}/report_index.md` (Master Finding Index, summary counts, tier assignments, consolidation map, cross-reference map, excluded findings) AND `{SCRATCHPAD}/report_coverage.md` (raw candidate ledger, uncovered mode-limited recommendations, promotion failures repaired).

#### Step 6b: Tier Writers

**Scope**: Produce `report_critical_high.md`, `report_medium.md`, and `report_low_info.md` by spawning THREE tier-writer agents in parallel (one message, three `Task()` calls). Each tier writer follows the Tier Writer Common Rules from `~/.claude/rules/phase6-report-prompts.md` §Step 6b.

**Execution**: Read `~/.claude/rules/phase6-report-prompts.md` §Step 6b and spawn the three tier writers per that spec. The V2 driver overrides Critical+High to `model="sonnet"` for cost discipline; Medium and Low+Info also use `model="sonnet"`.

**Output contract**: Three tier files, each with one `###` section per finding assigned by the Index Agent. Every section â‰¥ 400 chars. NO internal pipeline IDs in the body. Cross-references use only report IDs.

#### Step 6c: Assembler

**Scope**: Merge the three tier files + `report_index.md` header + Executive Summary + Priority Remediation + Appendix A into `{PROJECT_ROOT}/AUDIT_REPORT.md`.

**Execution**: Read `~/.claude/rules/phase6-report-prompts.md` §Step 6c and follow its STEP 1 (assemble), STEP 1.5 (runtime metadata hygiene), STEP 2 (quality checks), STEP 3 (write) verbatim.

**Output contract**: `{PROJECT_ROOT}/AUDIT_REPORT.md` exists with header + summary table + every finding from the three tier files + remediation order + Appendix A. The V2 driver runs a mechanical `report_quality.md` gate after this phase exits (v2.1.2): section count per tier matches the summary table, no internal-ID leakage outside Appendix A, no Claude-era runtime metadata, non-stub. Assembler does NOT need to produce `report_quality.md` itself " the driver generates it mechanically. A timestamped snapshot `AUDIT_REPORT-YYYYMMDD-HHMM.md` is written by the driver on successful pipeline exit.

---

## FINDING OUTPUT FORMAT

**Full format in**: `~/.claude/rules/finding-output-format.md` " ALL agents MUST read this file and use its format for findings. Includes finding template, Rules Applied table (R4-R16), enforcement rules, and Depth Evidence Tags.

---

## GENERIC SECURITY RULES

**Full rules (R1-R16) in**: `~/.claude/prompts/{LANGUAGE}/generic-security-rules.md` " agents MUST read this file. Key enforcement: CONTESTED â†’ adversarial assumption (R4), REFUTED â†’ requires chain analysis for enablers first (R12).

---

## SELF-CHECK

**Full checklists in**: `~/.claude/prompts/{LANGUAGE}/self-check-checklists.md` " orchestrator MUST read and verify before Phase 5.

Quick checks before verification:
- [ ] All external deps identified?
- [ ] All patterns detected?
- [ ] Fork ancestry research completed?
- [ ] Static analysis fallback used if primary analyzer failed?
- [ ] Production fetch completed?
- [ ] FLASH_LOAN_INTERACTION skill instantiated if FLASH_LOAN or FLASH_LOAN_EXTERNAL flag?
- [ ] ORACLE_ANALYSIS skill instantiated if ORACLE flag?
- [ ] Inventory agent completed side effect trace audit?
- [ ] Static analysis findings promoted?
- [ ] Adaptive depth loop completed?
- [ ] Confidence scores computed?
- [ ] Adaptive loop converged?
- [ ] Chain analysis completed enabler enumeration?
- [ ] Worst-state severity used? (Rule 10)
- [ ] Anti-normalization check applied? (Rule 13)
- [ ] Post-verification finding extraction completed?

## End-Of-Run Validation

After report assembly, the V2 driver (`plamen_driver.py`) runs artifact gate
checks and quality validation automatically. Treat `{SCRATCHPAD}/audit_validation.md`
as mandatory end-of-run evidence. If validation fails, the run is not clean
enough to claim mode correctness.

