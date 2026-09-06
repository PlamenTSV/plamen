---
description: "Plamen v2 L1 infrastructure audit wizard. Collects config, launches deterministic driver."
---

# Plamen v2 — L1 Infrastructure Audit Wizard

> This wizard collects L1 audit parameters and launches `plamen_driver.py`.
> The driver handles ALL phase sequencing deterministically.

## Step 1: Banner

Output:

```
██████╗ ██╗      █████╗ ███╗   ███╗███████╗███╗   ██╗
██╔══██╗██║     ██╔══██╗████╗ ████║██╔════╝████╗  ██║
██████╔╝██║     ███████║██╔████╔██║█████╗  ██╔██╗ ██║
██╔═══╝ ██║     ██╔══██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║
██║     ███████╗██║  ██║██║ ╚═╝ ██║███████╗██║ ╚████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝
```

**L1 Infrastructure Auditor** v2.2.4 — Deterministic Driver

```
┌─ L1 Infrastructure Mode ──────────────────────────────┐
│  Scope: Go / Rust node clients (50k-500k LOC)         │
│  Tiers: T0 patch  |  T1 subsystem  |  T2 whole-client │
│  Chain analysis: REMOVED (point vulnerabilities)       │
│  Evidence: [DIFF-PASS] [NON-DET-PASS] [LSP-TRACE]     │
└────────────────────────────────────────────────────────┘
```

Then run the toolchain probe. **CRITICAL**: Copy the bash block below VERBATIM into the Bash tool. Do NOT rewrite it in PowerShell or any other syntax. The Bash tool always runs bash, even on Windows.

```bash
export PATH="$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:$PATH" && \
echo "L1 Toolchain:" && \
echo -n "  Required:  " && \
(command -v codex >/dev/null 2>&1 && echo -n "codex " || echo -n "MISSING:codex ") && \
(command -v python >/dev/null 2>&1 && echo -n "python " || echo -n "MISSING:python ") && \
(command -v git >/dev/null 2>&1 && echo -n "git" || echo -n "MISSING:git") && echo "" && \
echo -n "  Go:        " && \
(command -v go >/dev/null 2>&1 && echo -n "go " || echo -n "-go ") && \
(command -v scip-go >/dev/null 2>&1 && echo -n "scip-go " || echo -n "-scip-go ") && \
(command -v opengrep >/dev/null 2>&1 && echo -n "opengrep" || (command -v semgrep >/dev/null 2>&1 && echo -n "semgrep" || echo -n "-opengrep")) && echo "" && \
echo -n "  Rust:      " && \
(command -v cargo >/dev/null 2>&1 && echo -n "cargo " || echo -n "-cargo ") && \
(command -v rust-analyzer >/dev/null 2>&1 && echo -n "rust-analyzer" || echo -n "-rust-analyzer") && echo ""
```

## Step 1.5: Detect Existing Audit

Before collecting config, check if an existing audit can be resumed. Search for `.scratchpad/config.json` in the current directory (or the path from `$ARGUMENTS` if provided):

```bash
if [ -f ".scratchpad/config.json" ]; then echo "FOUND:.scratchpad/config.json"
elif [ -f "src/.scratchpad/config.json" ]; then echo "FOUND:src/.scratchpad/config.json"
else echo "NONE"; fi
```

If a config is found, read the checkpoint file (`_v2_checkpoint.json` in that scratchpad) to determine progress, then offer:

```
AskUserQuestion(questions=[{
  question: "Existing audit detected. What would you like to do?",
  header: "Existing Audit Found",
  options: [
    { label: "Resume", description: "Continue from last checkpoint ({LAST_PHASE} → next)" },
    { label: "New audit", description: "Preserve this run; configure a distinct clean destination" }
  ]
}])
```

- **Resume**: First validate the existing backend without changing the file.
  L1 Claude execution is not a supported contained route; an L1 run may resume
  here only with its unchanged supported Codex configuration. Otherwise preserve
  the run and create a distinct clean Codex configuration. Never rewrite,
  auto-migrate, or rebind existing evidence in place.
- **New audit**: Preserve every existing file, then fall through to Step 2. The
  selected project and scratchpad MUST be a distinct clean destination; never
  reuse, delete, move, rename, or overwrite the existing run root.

If no config found, fall through to Step 2.

## Step 2: Codebase Scan

Run a quick codebase scan to detect language and size. **CRITICAL**: Copy the bash block below VERBATIM into the Bash tool — do NOT rewrite in PowerShell.

```bash
cd "{PROJECT_PATH}" && \
echo "Language detection:" && \
GO_LOC=$(find . -name "*.go" -not -path "*/vendor/*" -not -path "*_test.go" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}') && \
RS_LOC=$(find . -name "*.rs" -not -path "*/target/*" -not -name "*test*" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}') && \
echo "  Go: ${GO_LOC:-0} LOC" && \
echo "  Rust: ${RS_LOC:-0} LOC" && \
echo "Modules:" && \
ls -d */ 2>/dev/null | head -20
```

Determine:
- `LANGUAGE`: "go" if Go LOC > Rust LOC, else "rust"
- `LOC`: total lines
- `DETECTED_TIER`: T0 if <2k, T1 if 5-30k, T2 if 30-100k, T3 if >100k
- `IS_FORK`: check for fork indicators (upstream remote, README mentions)

## Step 3: Interactive Questioning (ALL mandatory, ALL use AskUserQuestion)

**Q1 — Target**:

```
AskUserQuestion(questions=[{
  question: "Is this the L1 target?",
  header: "Target ({LANGUAGE}, {LOC} LOC)",
  options: [
    { label: "Yes, use {PROJECT_PATH}", description: "{LANGUAGE} codebase, {LOC} LOC" },
    { label: "No, let me specify", description: "I'll provide a different path" }
  ]
}])
```

**Q2 — Tier** (ALWAYS ask, never auto-select):

```
AskUserQuestion(questions=[{
  question: "Select audit tier:",
  header: "Tier (detected: {DETECTED_TIER} based on {LOC} LOC)",
  options: [
    { label: "T0 — Patch (<=2k LOC diff)", description: "PR/commit review" },
    { label: "T1 — Subsystem (5-30k LOC)", description: "One module cluster" },
    { label: "T2 — Whole-client (30-100k LOC)", description: "Full codebase, all subsystems" },
    { label: "T3 — Full client screen (>100k)", description: "First-pass, breadth over depth" }
  ]
}])
```

**Q3 — Depth mode**:

```
AskUserQuestion(questions=[{
  question: "Audit depth?",
  header: "Depth",
  options: [
    { label: "Core (Recommended)", description: "~25-40 agents. Standard L1 audit depth." },
    { label: "Thorough", description: "~35-55 agents. Iterative depth, re-scan, skeptic-judge." },
    { label: "Light", description: "~15-20 agents. Quick scan, Pro plan compatible." }
  ]
}])
```

**Q4 — Module selection** (T1 only): Enumerate detected modules with LOC:

```bash
for dir in $(ls -d */ 2>/dev/null); do
  LOC_MOD=$(find "$dir" -name "*.go" -o -name "*.rs" | grep -v test | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
  echo "  $(basename $dir): ${LOC_MOD:-0} LOC"
done
```

```
AskUserQuestion(questions=[{
  question: "Which modules to audit?",
  header: "Module Selection (T1)",
  multiSelect: true,
  options: [
    // One option per detected module: { label: "module_name (LOC LOC)", description: "path" }
  ]
}])
```

Set `SUBSYSTEM_SCOPE` to selected paths. Warn if total >30k LOC.

**Q5 — Fork** (only if fork detected):

```
AskUserQuestion(questions=[{
  question: "Fork detected. Upstream comparison?",
  header: "Fork Analysis",
  options: [
    { label: "Diff against upstream", description: "Focus on fork-specific changes" },
    { label: "Audit as standalone", description: "Treat as independent codebase" },
    { label: "Both", description: "Upstream diff + standalone analysis" }
  ]
}])
```

**Q6 — Proven-only policy**:

```
AskUserQuestion(questions=[{
  question: "Apply proven-only severity policy?",
  header: "Proven Only",
  options: [
    { label: "No", description: "Use Impact x Likelihood; CODE-TRACE may remain reportable with conservative caps" },
    { label: "Yes", description: "Cap unproven CODE-TRACE findings aggressively for benchmark-style strictness" }
  ]
}])
```

Set `PROVEN_ONLY` from this answer.

**Q7 — Docs**:

```
AskUserQuestion(questions=[{
  question: "Project docs available?",
  header: "Docs",
  options: [
    { label: "No docs", description: "Protocol behavior inferred from code" },
    { label: "Yes, local files", description: "Architecture doc, spec, or design doc" },
    { label: "Yes, a URL", description: "Link to docs" }
  ]
}])
```

**Q8 — Confirmed launch**: Show summary and confirm:

```
┌─ L1 Audit Configuration ─────────────────────────────┐
│  Target:   {PROJECT_PATH} ({LANGUAGE}, {LOC} LOC)     │
│  Tier:     {TIER}    Scope: {SCOPE or "full"}         │
│  Modules:  {MODULE_LIST or "all"}                     │
│  Depth:    {MODE}    Fork: {FORK_MODE or "no"}        │
│  Proven:   {PROVEN_ONLY}                              │
│  Docs:     {DOCS_PATH or "none"}                      │
└───────────────────────────────────────────────────────┘
```

```
AskUserQuestion(questions=[{
  question: "Launch audit?",
  header: "Confirm",
  options: [
    { label: "Launch", description: "Start the L1 audit pipeline" },
    { label: "Change settings", description: "Go back to Q1" },
    { label: "Cancel", description: "Abort" }
  ]
}])
```

## Step 4: Write config.json and launch

```python
config = {
    "project_root": PROJECT_PATH,
    "scratchpad": f"{PROJECT_PATH}/.scratchpad",
    "mode": MODE,               # "light" | "core" | "thorough"
    "pipeline": "l1",
    "language": LANGUAGE,       # "go" | "rust"
    "cli_backend": "codex",
    "tier": TIER,               # "t0" | "t1" | "t2" | "t3"
    "subsystem_scope": SUBSYSTEM_SCOPE or "",
    "fork_mode": FORK_MODE or "standalone",
    "docs_path": DOCS_PATH or "",
    "proven_only": PROVEN_ONLY or False
}
```

Write this JSON to `{PROJECT_PATH}/.scratchpad/config.json` (create .scratchpad/ if needed).

Claude is not a supported contained backend for L1 audits. Do not create a
Claude compatibility configuration. Use Codex for this L1 run, or stop and
create a distinct clean configuration for another supported audit route; never
change provider metadata or migrate evidence inside an existing run.

Before launching, print the pre-launch message:

```
Launching V2 deterministic driver (L1 mode) in background...

Config: {PROJECT_PATH}/.scratchpad/config.json

Monitor progress:  tail -f "{PROJECT_PATH}/.scratchpad/_plamen.log"
Check checkpoint:  cat "{PROJECT_PATH}/.scratchpad/_v2_checkpoint.json"

If the audit is interrupted (usage cap, crash, Ctrl+C), resume with:
  python3 ~/.claude/scripts/plamen_driver.py "{PROJECT_PATH}/.scratchpad/config.json"
```

Then launch the driver **in the background** so the Claude Code session remains interactive. Use a single Bash tool call with `run_in_background: true`:

```bash
python3 ~/.claude/scripts/plamen_driver.py "{PROJECT_PATH}/.scratchpad/config.json"
```

Set `run_in_background: true` on the Bash tool call. Do NOT use `&` or `nohup` — Claude Code's `run_in_background` parameter handles this natively and will notify when the process completes.

**HARD RULE**: After launching the background Bash call, do NOT launch any additional Bash commands, background processes, or agents related to the audit. The driver is the sole owner of the pipeline. Tell the user the audit is running and they can continue using this session.

## Step 5: Handle Driver Completion

The driver runs in the background. When it completes, Claude Code will notify you. At that point, check the exit code:

- **Exit 0**: Pipeline completed. Tell the user: `Report is at {PROJECT_PATH}/AUDIT_REPORT.md`
- **Exit 3 (degraded)**: Pipeline execution completed in a degraded state. Preserve the scratchpad and inspect its runtime debt and violations before resuming.
- **Exit 5 (startup decision required)**: The resume attempt stopped during startup without launching a new audit-model generation. Read the typed external startup-decision receipt and follow its exact restore-or-distinct-destination action; do not repeat resume unchanged.
- **Exit 2 (rate limit / usage exhausted)**: The driver saved a checkpoint. Tell the user:

```
Pipeline paused — rate limit or usage cap reached.

Resume when quota refreshes:
  python3 ~/.claude/scripts/plamen_driver.py "{PROJECT_PATH}/.scratchpad/config.json"

The driver auto-resumes from the last successful phase. No data is lost.
```

- **Exit 1 (error)**: Check `{PROJECT_PATH}/.scratchpad/violations.md` for details. The driver can still be resumed — it will re-attempt failed phases:

```
Pipeline stopped with errors. Check violations:
  cat "{PROJECT_PATH}/.scratchpad/violations.md"

Resume (re-attempts failed phases):
  python3 ~/.claude/scripts/plamen_driver.py "{PROJECT_PATH}/.scratchpad/config.json"
```
