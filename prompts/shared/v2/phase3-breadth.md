# Phase 3: Parallel Breadth Analysis

> **Loaded by**: The V2 driver's Phase 3 subprocess (breadth analysis).
> **Purpose**: Parallel spawn rule, post-spawn verification, overreach handling,
> output file conventions, and agent closeout. This is execution procedure, not vulnerability coverage;
> each smart-contract worker receives the versioned semantic-operator kernel and
> any applicable conditional skills separately.

---

## Spawn Rule

Spawn every missing breadth agent immediately.

- For Claude PTY execution, spawn ALL missing breadth agents in ONE assistant
  message as background Task calls (`run_in_background: true`). This is the
  intended breadth execution shape: launch the full independent roster first,
  then monitor/collect until disk verification passes.
- Do NOT split 7+ breadth agents into waves. Do NOT complete one agent before
  launching the rest. Breadth rows are independent by design.
- If a higher-level execution contract explicitly forbids background mode
  (headless `claude -p`), still issue all missing breadth Task calls in one
  parallel block rather than serial batches.
- On retry, count only missing or stub breadth outputs from `spawn_manifest.md`; do not include already substantial outputs in the batch size.
- Each agent operates on its own scope independently and writes to its exact
  `Expected Output` from `spawn_manifest.md`.

---

## Discovery Stance (amplify, do not self-refute)

Include this directive in every breadth subagent prompt you spawn.

> During breadth DISCOVERY your job is to AMPLIFY candidate attacks, not filter
> them. If an attack path looks blocked, escalate to the worst reachable variant
> and RECORD it as a candidate with its precondition — never argue yourself out
> of one. Refutation is the verifier/skeptic gate's job, not discovery's.

---

## Post-Spawn Verification

Completion is manifest-exact, not batch-exact, and disk-derived. A returned
batch does not mean the phase is complete.

Before exit, run this loop:

1. Parse `spawn_manifest.md` and build `EXPECTED_OUTPUTS`:
   - Include only rows that represent spawned breadth agents.
   - Do not include skill, injectable, template, methodology, checklist,
     binding, `merged into ...`, `covered by ...`, or `no separate agent`
     rows. Those rows modify an agent prompt; they do not own standalone
     `analysis_*.md` files.
   - Use the explicit output filename if the manifest names one.
   - Otherwise derive `{SCRATCHPAD}/analysis_<focus_area>.md`.
2. Build `COMPLETE_OUTPUTS` from expected files that pass disk verification:
   - the file exists;
   - the LAST `PLAMEN_STATUS:` marker in the file is `COMPLETE`;
   - the file has at least one real `## Finding [` / `### Finding [` block OR
     a `## No Findings` / `## Negative Result` rationale.
3. Build `OPEN_OUTPUTS` from expected files that are missing, stub-sized,
   still `IN_PROGRESS`, missing a final `PLAMEN_STATUS: COMPLETE`, or lacking
   a real finding/no-findings body.
4. If `OPEN_OUTPUTS` is non-empty:
   - Spawn agents for every `OPEN_OUTPUTS` row immediately.
   - Every Task prompt MUST be constructed verbatim from the Â§Subagent
     Prompt Template below. The template makes the first tool call a
     `Write` of the assigned `analysis_<focus_area>.md` with an
     `<!-- PLAMEN_STATUS: IN_PROGRESS -->` marker, so the file exists on
     disk before any Read tool calls. Do NOT substitute your own
     structure; the template is load-bearing against context-window
     exhaustion (the root cause of an observed breadth failure).
   - Do not identify outputs by numeric agent id; `analysis_1.md` is invalid
     when the manifest expects `analysis_core_state.md`.
   - In Claude PTY, use background Task calls and keep the coordinator alive
     until disk verification proves completion.
   - Wait for/monitor all spawned agents and close completed agents, but treat
     Task completion text as advisory only. A background worker that says DONE
     without a COMPLETE artifact on disk is still OPEN_OUTPUTS and must be
     re-spawned.
   - Return to step 2.
5. Exit only when `OPEN_OUTPUTS` is empty.

Do not stop because the current batch returned. Do not proceed with 7/12,
9/12, or any partial manifest completion. If any required file is missing,
re-spawn that exact agent before returning from Phase 3.

Update `spawn_manifest.md` with completion status for each agent only after
the corresponding output file passes the disk verification above. Never mark a
row complete from Task UI text alone.

---

## Subagent Prompt Template

Each `Task()` you spawn for a breadth agent MUST be constructed verbatim
from the structure below. The previous "FIRST ACTION: write a one-line
header" footnote was a soft label, not a numbered step; subagents ignored
it and started with Read tool calls. In an observed breadth failure, six of
eight subagents exhausted their context window before reaching any
`Write`, leaving no on-disk artifact. The template below makes `Write`
structurally the first tool call so a crash-safety stub always lands on
disk.

Render `{agent_id}`, `{expected_output}`, `{focus_area_title}`,
`{skill_names}`, `{scope_list}`, and either
`{opengrep_obligation_shard_path}` (preferred when sharding lands)
OR a fallback reference to `{SCRATCHPAD}/opengrep_findings.md` based on
what `spawn_manifest.md` provides for this agent.

Body of every breadth subagent prompt (do not paraphrase):

```
You are Breadth Agent {agent_id} for this audit.

AGENT_ROW: {agent_id}
EXPECTED_OUTPUT: {expected_output}

(The two lines above are routing markers consumed by the driver's
continuation loop: `parse_transcript_agentids()` greps them out of the
session transcript to correlate any returned `agentId:` handle with
your manifest row. They are NOT instructions to you -- they exist so
that if your context window saturates and you return an `agentId`
handle without finishing, the driver can name your row precisely in
a follow-up continuation message. Keep them verbatim; do not delete
them, do not echo them in your final response.)

Your focus area is {focus_area_title}. Finding ID prefix per
spawn_manifest.md.

Step 1 -- REQUIRED FIRST TOOL CALL: Write.
Use the Write tool to create {SCRATCHPAD}/{expected_output} with EXACTLY
this body (do not omit any marker line):

    <!-- PLAMEN_ARTIFACT: {expected_output} -->
    <!-- PLAMEN_OWNER: {agent_id} -->
    <!-- PLAMEN_STATUS: IN_PROGRESS -->
    <!-- PLAMEN_PHASE: breadth -->
    <!-- PLAMEN_VERSION: 1 -->
    <!-- AGENT_ROW: {agent_id} -->
    <!-- EXPECTED_OUTPUT: {expected_output} -->

    # {focus_area_title}

    > Agent: {agent_id} -- {skill_names}
    > Scope: {scope_list}

    ## Findings

    (findings appended below as they are discovered)

    ## Obligation Receipts

    (one row per opengrep obligation in your assigned scope, appended below)

The AGENT_ROW and EXPECTED_OUTPUT markers are required for the driver's
continuation loop to map your subagent handle back to your manifest row
on retry. Do NOT remove these markers, do NOT omit them in the initial
Write, and do NOT change their values mid-run.

DO NOT call Read, Glob, or Grep before this Write completes. The marker
file is your crash-safety net: if your context window saturates later,
your assigned file is already on disk in IN_PROGRESS state and the
driver can ask you to finish without losing the slot.

Step 2 -- Read recon context (NO CAP on recon artifact reads).
Read EVERY recon artifact relevant to your focus area. The recon phase
exists specifically so subagents do not have to re-derive context from
raw source. Typical reads (read whichever exist; this list is not a
cap):

    {SCRATCHPAD}/design_context.md
    {SCRATCHPAD}/attack_surface.md
    {SCRATCHPAD}/state_variables.md
    {SCRATCHPAD}/function_list.md
    {SCRATCHPAD}/function_summary.md
    {SCRATCHPAD}/caller_map.md
    {SCRATCHPAD}/callee_map.md
    {SCRATCHPAD}/state_write_map.md
    {SCRATCHPAD}/constraint_variables.md
    {SCRATCHPAD}/external_production_behavior.md
    {SCRATCHPAD}/detected_patterns.md
    {SCRATCHPAD}/slither/detector_findings.md

PLUS any skill-specific files named in your dispatch prompt (for example
`emit_list.md`, `setter_list.md`, recon focus-area files).

PLUS your assigned opengrep obligation file. Fallback rule:
- If a per-agent obligation shard exists at the canonical path
  `{SCRATCHPAD}/opengrep_obligations_{agent_id}_{focus_area_slug}.md`
  (Ship 7+), read that path. The shard contains ONLY the rows in
  your assigned scope; each row carries a
  `<!-- DEDUP_KEY: opengrep:<row_num> -->` tag so cross-cutting rows
  that appear in multiple shards still dedupe to one row in global
  accounting. Receipts are 1:1 with the shard file.
- Otherwise read the full {SCRATCHPAD}/opengrep_findings.md and apply
  the obligation receipt rules from the existing Â§One-Line Addition to
  Each Breadth Agent Prompt section: report, dismiss, or carry every
  row whose Location falls inside your scope.

The driver writes the per-agent shard immediately before this phase
spawns subagents; if both `spawn_manifest.md` and
`opengrep_findings.md` are present, the canonical shard at the path
above is guaranteed to exist. Read that path verbatim.

IMPORTANT: the shard file's `OPENGREP_SHARD_OWNER` / `OPENGREP_SHARD_FOCUS`
comments are obligation-file metadata, NOT artifact lifecycle markers. Do
NOT copy them into your analysis file. Your analysis file uses ONLY the
`PLAMEN_*` markers from Step 1 (PLAMEN_ARTIFACT/OWNER/STATUS/PHASE/VERSION
plus the final PLAMEN_STATUS: COMPLETE). Never put `OPENGREP_SHARD_*` or any
shard metadata into your `analysis_<focus>.md`.

Step 3 -- TARGETED source reads.
Use function_summary.md, callee_map.md, and state_write_map.md to
identify the SPECIFIC functions in scope for your focus area. Then
read source files in one of these targeted ways:

    (a) Read only the contract files that contain in-scope functions
        (typically 1-3 contracts out of the project total).
    (b) Use `Grep -n -B N -A N` with focus-relevant patterns to pull
        targeted line ranges across multiple files.

DO NOT `Glob **/*.sol` and then `Read` every contract you find. That
pattern exhausted six of eight subagent context windows in an observed
breadth failure. Targeted source reads keep enough budget for
analysis AND the final marker Edits.

Step 4 -- Edit (not Write) to append findings.
For each finding you confirm, use the `Edit` tool to APPEND the finding
under the `## Findings` heading of {SCRATCHPAD}/{expected_output}.
`Edit` preserves prior findings; a second `Write` would overwrite the
file and lose earlier findings plus the marker header.

Use the per-agent finding ID prefix from spawn_manifest.md (e.g.
`[CS-1]`, `[AC-1]`, `[TF-1]`). Follow the finding-output format from
~/.claude/rules/finding-output-format.md.
When a finding has a clear pairing hint, you MAY add the optional
`**Discovery Steer**:` line using generic terms only (shared variable/function,
branch condition, terminal effect, or candidate ID). This is not proof, not a
required section, and must not create any additional artifact.

Step 5 -- Edit obligation receipts.
For every opengrep row in your assigned scope (per Step 2's source),
append one receipt line under the `## Obligation Receipts` heading of
{SCRATCHPAD}/{expected_output}. Receipt formats and status codes
(R/D/C) are defined in Â§One-Line Addition below; use the strict-line
form when in doubt. Every in-scope row must end up as exactly one
receipt; rows outside your scope are owned by another agent and must be
skipped.

Step 6 -- Final Edit: mark COMPLETE.
Once findings and receipts are appended, use `Edit` to APPEND the
following two marker lines at the END of {SCRATCHPAD}/{expected_output}:

    <!-- PLAMEN_STATUS: COMPLETE -->
    <!-- PLAMEN_FINDINGS_COUNT: {N} -->

`{N}` is the count of confirmed findings you wrote in Step 4. The
driver's structural check inspects the LAST `PLAMEN_STATUS:` line in
the file, so this Edit (after the initial IN_PROGRESS marker from
Step 1) flips the artifact to COMPLETE. Do NOT replace the original
IN_PROGRESS line in place; appending a second COMPLETE line is the
documented final-write-wins pattern.

If `{N} == 0` (no confirmed findings in your scope), you MUST ALSO
ensure a `## No Findings` heading is present in the file with a brief
rationale explaining what you analyzed and why nothing rose to a
reportable finding. A `PLAMEN_FINDINGS_COUNT: 0` artifact without a
`## No Findings` (or `## Negative Result`) rationale section fails the
structural completeness check and the driver treats the file as still
IN_PROGRESS for continuation purposes. Empty skeletons cannot pass as
complete.

Step 7 -- Return (STATUS LINE ONLY).
Return exactly this single line and nothing else:

    DONE: {N} findings written to {expected_output}

Your assigned file on disk is the canonical output -- ALL analysis stays
on disk. Do NOT paste finding bodies, code snippets, evidence, or any
analysis prose into your return message. Do NOT include an
<ANALYSIS_TEXT> block or any other transcript echo of your findings. The
coordinator recovers incomplete work from DISK (the manifest + your
file's PLAMEN_STATUS marker), never from chat: echoing your analysis
into the return only inflates the coordinator's context and brings on
the auto-compaction that causes premature-DONE failures. One status
line. Nothing else.

SCOPE: Write ONLY to {SCRATCHPAD}/{expected_output}. Do NOT read or
write any other breadth agent's output file. Do NOT spawn further
subagents. Return and stop.
```

The Subagent Prompt Template is the only sanctioned way to construct a
breadth subagent prompt. Deviating from it (re-ordering steps, omitting
the IN_PROGRESS Write, capping recon reads, glob-reading every source
file, marking COMPLETE without findings + rationale) reintroduces the
observed breadth failure class.

---

## Output File Conventions

Each breadth agent writes to a single file:
```
{SCRATCHPAD}/analysis_{focus_area}.md
```

Where `{focus_area}` is the lowercase, hyphenated or underscored version of the agent's focus area (e.g., `analysis_core_state.md`, `analysis_access_control.md`, `analysis_oracle.md`).
The manifest `Expected Output` column is authoritative. If it names a file,
the agent must write that exact filename.

Finding IDs use a per-agent prefix:
- Core state agent: `[CS-1]`, `[CS-2]`, ...
- Access control agent: `[AC-1]`, `[AC-2]`, ...
- Token flow agent: `[TF-1]`, `[TF-2]`, ...
- External dependency: `[EX-1]`, `[EX-2]`, ...
- (Other prefixes assigned per focus area)

---

## Output Discipline

Breadth agents write exactly one manifest-derived `analysis_<focus_area>.md`
file each. No other artifact family is a breadth output. The driver's
gate ONLY accepts manifest-derived `analysis_*.md` filenames; anything
else is invisible to the gate and discarded.

Each breadth subagent writes ONLY its single assigned
`analysis_<focus_area>.md` from the manifest -- nothing else. This phase
produces only the manifest-named breadth outputs. If any skill, template, or
methodology block asks for any other output file, ignore that output request.
Any file written during breadth that is not a manifest-named breadth output is
quarantined by the driver (not counted, not ingested) and wastes session
tokens.

If a spawned agent emits a file outside the manifest, record the
violation in `{SCRATCHPAD}/violations.md`, close the offending agent,
and rely on the remaining valid `analysis_*` outputs.

---

## Agent Closeout

- Do NOT read analysis files after agents return; reading them here only wastes your context budget.
- Close completed breadth agents before returning. Do not carry finished workers forward.

---

## Context Budget Protection

The orchestrator does NOT read agent output files. Agent outputs stay
on disk. This protects the orchestrator's context from saturation.

Per the WRITE-THEN-VERIFY protocol, each agent:
1. Writes output directly to `{SCRATCHPAD}/{expected_filename}` using the Write tool
2. Returns ONLY a one-line summary: `"DONE: {N} findings written to {filename}"`

The orchestrator verifies final artifact state mechanically after each return:
the expected file must exist, end with `PLAMEN_STATUS: COMPLETE`, and contain a
real finding block or no-findings rationale. Task return text alone is not
completion.

---

## Mode-Specific Agent Counts

| Mode | Agent Count | Model |
|------|-------------|-------|
| Light | 3-4 | sonnet |
| Core | 5-9 | opus |
| Thorough | 5-9 | opus |

Light mode caps at 3-4 sonnet agents. Core/Thorough use 5-9 opus agents based on complexity determination from Phase 2 Step 2a.

---

## Scope Containment Directive

Every breadth agent prompt MUST end with:

```
SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Return your findings and stop.
```

For the breadth orchestrator itself: always reuse existing COMPLETE
manifest-derived breadth outputs and spawn only rows that are missing, stubbed,
or still incomplete per the disk verification loop above. Re-run the completion
loop until all expected outputs are COMPLETE on disk. As soon as the completion
loop has zero open outputs, return immediately with a one-line summary.
Producing additional files beyond
the manifest-derived breadth set is discarded by the driver and wastes
session tokens.

---

## One-Line Addition to Each Breadth Agent Prompt (compact)

When constructing each breadth subagent's Task() prompt, also include
this directive verbatim. Obligation receipts are COVERAGE TELEMETRY, not a
completeness gate: emitting them is requested and valuable, but their
absence does NOT mark your artifact incomplete and does NOT fail the
artifact gate (the driver's receipt check is warning-only). Emit them when
you can; do not block your own completion on them.

> **Obligation Receipts (coverage telemetry, not enforced).** If
> `{SCRATCHPAD}/opengrep_findings.md` exists, you are ASKED to end your
> `analysis_<focus>.md` with a `## Obligation Receipts â€” opengrep_findings.md`
> section for coverage telemetry. This is NOT required for artifact
> completeness -- omitting it produces at most a warning, never a gate
> failure. When you do emit it, open `opengrep_findings.md`, read every row,
> and for EVERY row whose `Location` falls in your assigned scope, emit one
> of the two equivalent forms:
>
> **(a) Strict line form (preferred, unambiguous):**
> `[OBLIG:opengrep_findings.md:<row#>] STATUS:R|D|C KEY:<rule>@<file:L> -> <finding_id|reason|followup>`
>
> **(b) Table form (also accepted by the gate):**
> ```
> | Row | Rule | Location | Addressed By | Notes |
> |-----|------|----------|--------------|-------|
> | 7 | reentrancy-eth | Vault.sol:212 | (none) | guarded by nonReentrant â€” false positive |
> | 12 | use-ownable2step | Owner.sol:14 | AC-4 | single-step ownership, raised in access_control |
> ```
> The table form requires a numeric first column (the opengrep row index).
> Status is inferred from the row contents: notes containing `style|gas|
> false positive|non-security|by design` â†’ DISMISSED; notes containing
> `carry|defer|followup` -> CARRIED; any other non-empty
> Addressed-By cell (a finding ID like `AC-4`, `BLIND-A-1`, prose, etc.)
> â†’ REPORTED. Rows where every non-first cell is empty / `N/A` / `-` are
> NOT counted as receipts.
>
> STATUS short codes in the line form: `R` (Reported â€” you raised a finding
> for it), `D` (Dismissed â€” give the concrete reason it is not a bug), or
> `C` (Carried -- needs followup). When you emit receipts,
> account for every in-scope row; skip rows outside your scope (another
> agent owns them). Unaccounted rows lower the coverage telemetry number
> but do NOT fail your artifact.

The Python check (`_check_opengrep_obligation_coverage`) parses receipts
in both forms â€” strict-line first (canonical), then section-bounded
table form under any `## ... Obligation Receipts ... opengrep ...`
heading. It is COVERAGE TELEMETRY ONLY: the pipeline never halts on
missing receipts, and a missing receipts section never contributes to
the artifact gate. Zero receipts when opengrep rows exist is recorded as
a telemetry gap (a warning), not a completeness failure.

---

## Orchestrator Termination Contract (HARD STOP)

As soon as every expected `analysis_<focus>.md` from `spawn_manifest.md`
passes disk verification (exists, final `PLAMEN_STATUS: COMPLETE`, and real
finding/no-finding body), return immediately:

```
DONE: {N} breadth analyses complete: {comma-separated filenames}
```

Any output written by the orchestrator after that signal is discarded
by the driver and wastes session tokens. The orchestrator's job is
spawning subagents and verifying their outputs â€” not producing analyses
itself, not writing other artifact families, not exploring beyond the
manifest.

Do not write any artifact outside the manifest-derived breadth set.
Quarantined overflow from this phase is discarded for cost discipline.
