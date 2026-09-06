# Phase 4b: Adaptive Depth Loop

> **Loaded by**: The V2 driver's Phase 4b subprocess (depth analysis loop).
> **Reference**: `~/.claude/rules/phase4-confidence-scoring.md` for scoring model,
> anti-dilution rules, and convergence criteria.
> **Purpose**: Self-contained methodology for the adaptive depth loop including
> iteration 1-3, agent roles, scoring integration, convergence criteria, blind
> spot scanners, validation sweep, niche agents, DST, perturbation, and skill
> execution checklist.

---

## Phase Boundary

Depth may write only depth-owned artifacts: depth/scanner/niche findings,
initial confidence scoring, adaptive loop logs, design stress, perturbation,
skill execution gaps, invariant fuzz results, Medusa fuzz findings, and the
depth lifecycle markers. Record any extra context inside a depth-owned
output and stop.

If `{SCRATCHPAD}/security_obligations.md` exists, treat it as the compact
Markdown projection of the driver-owned typed security-obligation authority
(generic vulnerability-class
questions, e.g. "are asset-in/out/recipient/amount bound to trusted context
before value moves?"). It is NOT an expected-finding list. For each obligation
relevant to your assigned role, either produce a normal finding with file:line
evidence where the obligation is violated, or record why the obligation is
satisfied, unreachable, or irrelevant in this codebase. Answer the obligation
question as asked — do not treat a nearby unrelated issue as coverage of a
different obligation. The `Exact Trigger Aliases` table is an enumerate-all
denominator: every alias is separate application work even when aliases share
one SO-ID. For `STATUS:R`, copy the complete generated marker
`PLAMEN_SECURITY_OBLIGATION_EVIDENCE` for that alias into the referenced
finding section. The marker binds the exact subject, object, relation, and
symbol; normalized prose or identifier overlap is not application evidence.
If the marker cannot be emitted exactly, the alias remains queueable.

## Light Mode Override

When `MODE == light`, skip the standard 8-agent spawn. Instead spawn 4 merged sonnet agents, but still write the canonical output files that the driver gates:
- (a) combined token-flow + state-trace writes `depth_token_flow_findings.md` and `depth_state_trace_findings.md`
- (b) combined edge-case + external writes `depth_edge_case_findings.md` and `depth_external_findings.md`
- (c) combined scanner A+B+C writes `blind_spot_a_findings.md`, `blind_spot_b_findings.md`, and `blind_spot_c_findings.md`
- (d) validation sweep writes `validation_sweep_findings.md` or `scanner_validation_findings.md`

Skip niche agents, skip confidence scoring, skip iterations 2-3. After iteration 1 completes, write the required depth outputs and stop.

---

## Iteration 1 (Core/Thorough): Full Agent Spawn

Spawn ALL standard agents + niche agents in a SINGLE message as parallel Task calls:

### Standard Depth Agents (4)

| Agent | Role | Output File | Domain |
|-------|------|-------------|--------|
| depth-token-flow | Token/value flow tracing | `depth_token_flow_findings.md` | Balance changes, transfer paths, fee calculations, share conversions |
| depth-state-trace | State transition correctness | `depth_state_trace_findings.md` | State variable updates, conditional writes, storage layout, role transitions |
| depth-edge-case | Boundary conditions | `depth_edge_case_findings.md` | Zero/max values, first/last user, overflow, rounding, empty state |
| depth-external | External interactions | `depth_external_findings.md` | Oracle calls, external contracts, cross-chain, reentrancy, callback handling |

Each depth agent reads:
- `{SCRATCHPAD}/findings_inventory.md` (breadth findings to investigate)
- `{SCRATCHPAD}/semantic_invariants.md` (if exists; else `state_variables.md`)
- `{SCRATCHPAD}/design_context.md` (protocol context)
- `{SCRATCHPAD}/spec_expectations.md` (if present; tests/mocks/harnesses as
  expectation evidence only, not as reportable production targets)
- Source files relevant to their domain

### Discovery Stance (amplify, do not self-refute) — COPY INTO EACH OF THE 4 PROMPTS

> During depth DISCOVERY your job is to AMPLIFY a candidate attack, not filter
> it. If a path looks blocked, escalate to the worst reachable variant and
> RECORD it as a candidate with its precondition — never argue yourself out of
> one. Refutation is a later gate's job (e.g. the ANCHORING REJECTION LIST in
> the language depth template), not discovery's — do not filter candidates here.

### Standard Depth Agent Semantic Proof Block (COPY INTO EACH OF THE 4 PROMPTS)

When spawning `depth-token-flow`, `depth-state-trace`, `depth-edge-case`, and
`depth-external`, paste this block verbatim into each agent prompt. Record these
checks inside the assigned depth output file only; do not create new artifacts.

```
## MANDATORY SEMANTIC-PROOF CHECKS

For every investigated candidate touching value movement, accounting,
authorization or lifecycle state, shares or claims, fees, limits, or guarded
arithmetic / branch-dependent updates:

1. Semantic invariant challenge: state the intended invariant in code-level
   terms, then try to falsify it across reachable write paths, not only the
   originally reported path.
2. Read-site expectation check: identify where the written or derived value is
   later read, trusted, or consumed, and compare writer semantics against reader
   expectations. If no read site is found, record that as an unresolved evidence
   gap, not proof of safety.
3. Branch-formula matrix for guarded arithmetic: for each guard or conditional
   that changes arithmetic, conversions, caps, rounding, or accumulator updates,
   record condition -> formula/effect -> boundary inputs -> expected
   postcondition. Check branch inversion, skipped branch, equality boundary,
   zero/empty-state, and max/cap cases when applicable.
4. Intent-proof before no-finding: do not mark SAFE, REFUTED, by-design,
   expected behavior, or no-finding for the candidate unless you cite concrete
   intent evidence from specs, docs, tests, comments, interfaces, or consistent
   call/read-site behavior. Absence of a failing trace, lack of exploitability
   work, or "guard exists" is not intent proof.

If intent proof is missing, classify the candidate as unresolved/non-reportable
only with the missing proof and remaining risk recorded; do not treat it as
SAFE/REFUTED.

In your output file, include a section named exactly:

## Semantic Proof Checks

Summarize the challenged invariant(s), read-site expectation(s), branch matrix
entries, and intent evidence or evidence gap for each relevant candidate.

For live findings, you MAY add the optional `**Discovery Steer**:` finding
field when it preserves a bounded downstream pairing hint (shared
variable/function, branch condition, postcondition/precondition link,
terminal mechanism, or candidate ID). This is not proof, not a required
section, and must stay inside your assigned output file.
```

### Finding Severity / Disposition Contract (MANDATORY)

For every `### Finding [...]` block, the `**Severity**:` field MUST contain
exactly one canonical severity:

`Critical`, `High`, `Medium`, `Low`, or `Informational`

Never write disposition text in the severity field. Invalid examples:

- `N/A`
- `N/A (absorbed into DE-2)`
- `REFINED`
- `absorbed into ...`
- `duplicate`
- `refuted`

If a candidate is absorbed/refined/duplicate/not independently reportable, do
not emit it as a live finding block. Put that decision in a separate
`## Non-Reportable / Absorbed Candidates` section or the Chain Summary table,
with the canonical severity cell set to `Informational` if a severity cell is
required. The Python verifier treats disposition-as-severity as contract drift.

### Pre-Return Self-Exclusion Check (COPY INTO EVERY DEPTH WORKER PROMPT)

Paste this block verbatim into every standard depth-agent prompt and every
iteration-2/3 depth-worker prompt that may emit or exclude candidates. This is
a pre-return recall check, not negative lifecycle authority.

```
## MANDATORY PRE-RETURN SELF-EXCLUSION CHECK

Immediately before returning, re-open your assigned output file and examine
EVERY candidate that you omitted from live findings or classified under
`Non-Reportable`, `Absorbed`, `Duplicate`, `Already Known`, `Self-Excluded`, or
equivalent wording. Compare each such candidate against the provided upstream
exclusion source: the concrete finding IDs and `file:Lnnn` locations present in
the supplied `findings_inventory.md`, `analysis_*.md`, or
`analysis_rescan_*.md` inputs. Your belief that another worker probably covered
the issue is not an exclusion source.

For each candidate, apply all of these rules before submitting:

1. Exclude or absorb it as already covered only when the entry cites a concrete
   referent that actually appears in that provided exclusion source.
2. A proposed in-scope refutation must cite the exact project-source
   `file:Lnnn` guard or path that refutes the mechanism. An unverified external
   assumption such as "atomic", "out of scope", "assume", "guaranteed by", or
   "reverts on" is not a valid refutation or exclusion referent.
3. If no valid provided referent or concrete in-scope refutation exists,
   restore the candidate as a normal live finding for downstream verification;
   never silently drop it as already known.
4. If the exclusion is valid, keep it out of the live finding blocks and record
   it under `## Non-Reportable / Absorbed Candidates` with the excluded
   candidate's own location, mechanism, one-line harm, and the cited provided
   referent inline. This preserves enough content to check the classification.

The driver's post-return self-exclusion recovery remains defense in depth. Do
not rely on that recovery to repair your output, and do not use this check to
invent terminal `SAFE`/`REFUTED` authority.
```

### Negative-Proposal Boundary and Committed-Invariant Emission (MANDATORY)

Depth workers are generators, not terminal negative authorities. Whenever you
reach a proposed `CLEAR`/`REFUTED` conclusion, emit it as
`REFUTATION_PROPOSAL` or `CONTESTED`, never as a terminal closure. The proposal
must name its exact premise, guard locus, paths/variants checked, and evidence
tags; an independent discriminator must bind premise to evidence before any
terminal negative disposition.

For every value-bearing negative proposal (value
movement, supply/shares, accounting, authorization, or a funds/liveness-gating
boundary), you MUST additionally emit a `committed-invariant [CI-n]` block naming
the local guard that makes the path safe — this is the Code-Augur "commit the
invariant behind every safe judgment" locus. Depth is the richest reservoir of
code-derived negative proposals, so it is the PRIMARY CI emitter (the skeptic
phases remain secondary). Emit the block as exactly ONE of the six generic SHAPES —
`CONSERVATION`, `REQUESTED_EQ_DELIVERED`, `APPROVE_EQ_SPEND`,
`NO_REVERT_AT_BOUNDARY`, `ROUNDTRIP`, `FRESHNESS` — with symbols resolved at the
locus but no protocol constant baked as "the answer":

Immediately inside the same negative-proposal section, bind the disposition to
that block with exactly `Invariant Commitment: CI:<CI-id>`. The CI block's
`Provenance` MUST repeat the exact candidate/finding ID. A non-value-bearing
proposal may instead use the following exact one-line form (with a real reason):

`Invariant Commitment: NOT_REQUIRED_NON_VALUE_BEARING: <specific reason>`
Missing, duplicated, malformed, or cross-bound CI identities make the negative
proposal fail closed and re-open as a candidate. One CI can never close
multiple negative proposals.

```
committed-invariant [CI-n]
Locus: <file>:L<nn>  (fn: <enclosing function>)
Shape: <one of the six shapes>
Assertion: <the falsifiable relation, symbols resolved>
Falsify Class: <property | boundary | roundtrip | conservation>
Provenance: depth REFUTATION_PROPOSAL @ <candidate>
```

This is MANDATORY for every value-bearing negative proposal and strictly
additive — it changes no verdict, severity, or prior finding. A non-value-bearing
proposal (pure view, no funds/liveness/accounting/authorization stake) does not
require a block. Emitted blocks are mechanically harvested downstream into
falsifiable candidates for the fuzz/PoC gates. The six shapes are generic
relational forms; NEVER encode a specific protocol/token/function as "the answer"
— symbols resolve at the locus at runtime.

**FALSIFIABILITY-AWARE SHAPE SELECTION (MANDATORY).** Emit the shape whose
falsifier could actually FAIL at this locus. If the shape you first reach for is
*true by construction* — its assertion cannot be violated by any reachable input
because the code trivially satisfies it (for example a 1:1 unwrap step
trivially satisfies `CONSERVATION`, so a conservation falsifier can never break)
— that block is worthless as a downstream PoC target. In that case you MUST ALSO
add at least one shape that CAN break at the same locus: a
`NO_REVERT_AT_BOUNDARY` block (does the boundary/limit case revert, brick, or
mis-round?) and/or a `REQUESTED_EQ_DELIVERED` block (does the amount/asset the
caller requested equal what the callee actually delivered, across a
conversion/bridge/wrap boundary?). You MAY emit **2–3 CI blocks per locus** for
exactly this reason — one per distinct falsifiable relation. This is a generic
HOW-directive about picking a *breakable* invariant; it names no protocol, token,
or function (a native↔wrapped conversion is only an illustrative example of a
boundary where `CONSERVATION` looks satisfied yet `REQUESTED_EQ_DELIVERED` can
still diverge). Symbols always resolve at the locus at runtime.

### Language-Specific Depth Template Binding (MANDATORY)

Before spawning any of the 4 standard depth agents, read:

`~/.claude/prompts/{LANGUAGE}/phase4b-depth-templates.md`

Use the matching role template from that file as the base prompt for each standard
depth agent. Do not summarize, weaken, or omit template requirements. The shared
V2 prompt defines phase orchestration; the language-specific depth template
defines the actual per-role analysis contract.

Every standard depth-agent prompt MUST include the language template's
graph-artifact section verbatim. If any of these graph artifacts exist in
`{SCRATCHPAD}`, every standard depth output MUST reference every produced graph
artifact by filename, or emit an explicit unavailable tag:

- `{SCRATCHPAD}/caller_map.md`
- `{SCRATCHPAD}/callee_map.md`
- `{SCRATCHPAD}/state_write_map.md`
- `{SCRATCHPAD}/function_summary.md`
- `[GRAPH-ARTIFACT: UNAVAILABLE:<file>]`

The Python gate enforces this contract after the phase. Treat missing graph
references as a first-attempt failure, not as something to leave for retry.

### Standard Depth Agent Graph Block (COPY INTO EACH OF THE 4 PROMPTS)

When spawning `depth-token-flow`, `depth-state-trace`, `depth-edge-case`, and
`depth-external`, paste this block verbatim into each agent prompt. Do not
replace it with a summary.

```
## MANDATORY GRAPH-ARTIFACT CONSUMPTION

Before investigating findings, read or check these four graph artifacts:

1. `{SCRATCHPAD}/caller_map.md`
2. `{SCRATCHPAD}/callee_map.md`
3. `{SCRATCHPAD}/state_write_map.md`
4. `{SCRATCHPAD}/function_summary.md`
5. `{SCRATCHPAD}/security_obligations.md` when present

In your output file, include a section named exactly:

## Graph Artifact Consumption

That section MUST contain one bullet for each artifact basename. Use the
consumed form when the artifact exists and was read; use the unavailable form
only when the artifact is absent or unreadable:

- `[GRAPH-ARTIFACT: caller_map.md]` - consumed; relevant calls/callers used:
  <brief note>
- `[GRAPH-ARTIFACT: UNAVAILABLE:caller_map.md]` - <reason>
- `[GRAPH-ARTIFACT: callee_map.md]` - consumed; relevant callees used:
  <brief note>
- `[GRAPH-ARTIFACT: UNAVAILABLE:callee_map.md]` - <reason>
- `[GRAPH-ARTIFACT: state_write_map.md]` - consumed; relevant state writes used:
  <brief note>
- `[GRAPH-ARTIFACT: UNAVAILABLE:state_write_map.md]` - <reason>
- `[GRAPH-ARTIFACT: function_summary.md]` - consumed; relevant functions used:
  <brief note>
- `[GRAPH-ARTIFACT: UNAVAILABLE:function_summary.md]` - <reason>

Mentioning only the absolute path is not enough; the tag must contain the
basename exactly. Missing this section or any of the four artifact basenames
causes the Python gate to fail the whole depth phase.
```

Before returning from the depth phase, re-open the four standard depth output files and verify each contains `## Graph Artifact Consumption` plus all four graph-artifact basenames. If any output is missing the section, repair that output before returning; do not rely on the driver retry.

### Standard Depth Agent Artifact Marker Block (COPY INTO EACH OF THE 4 PROMPTS)

When spawning `depth-token-flow`, `depth-state-trace`, `depth-edge-case`, and
`depth-external`, paste this block verbatim into each agent prompt. It is the
depth analog of the breadth Subagent Prompt Template's marker contract. On a
fresh audit the driver's gate requires each canonical depth output file to
carry a `COMPLETE` marker AND pass a depth-appropriate structural check; an
agent that exhausts its context window before its final `Write` would
otherwise leave NO artifact (an observed breadth failure class). The
IN_PROGRESS-first Write makes that survivable: the file is on disk in
`IN_PROGRESS` state and the driver's supervision loop continues the agent.

```
AGENT_ROW: {role}
EXPECTED_OUTPUT: depth_{role}_findings.md

(The two lines above are routing markers consumed by the driver's
continuation loop -- keep them verbatim, do not echo them in your final
response. `{role}` is one of: token_flow, state_trace, edge_case, external.)

Step 1 -- REQUIRED FIRST TOOL CALL: Write.
Create {SCRATCHPAD}/depth_{role}_findings.md with EXACTLY this header
(do not omit any marker line):

    <!-- PLAMEN_ARTIFACT: depth_{role}_findings.md -->
    <!-- PLAMEN_OWNER: depth-{role} -->
    <!-- PLAMEN_STATUS: IN_PROGRESS -->
    <!-- PLAMEN_PHASE: depth -->
    <!-- PLAMEN_VERSION: 1 -->
    <!-- AGENT_ROW: {role} -->
    <!-- EXPECTED_OUTPUT: depth_{role}_findings.md -->

    # Depth Analysis: {role}

Do NOT call Read, Glob, or Grep before this Write completes -- the marker
file is your crash-safety net.

Steps 2-N -- Analyze and Edit (not Write).
Read your inputs, perform the role's analysis per the language template, and
APPEND each `### Finding [ID]:` block to the file using the Edit tool. Edit
preserves prior findings and the marker header; a second Write would
overwrite them. Include the mandatory `## Semantic Proof Checks`,
`## Graph Artifact Consumption`, and `## Obligation Receipts` sections per
the other blocks in this prompt.

OUTPUT-BUDGET DISCIPLINE (avoid a single oversized turn that hits the output-
token cap mid-write and leaves the file IN_PROGRESS):
- Write your findings FIRST, then the four required section headers, then APPEND
  the `PLAMEN_STATUS: COMPLETE` marker AS SOON AS findings + the four section
  headers exist. Add any remaining receipt detail AFTER the marker — a complete-
  but-terse file is far better than an uncapped turn that never marks COMPLETE.
- Keep every Obligation Receipt to ONE line.
- If your `function_summary.md` partition exceeds ~40 rows, emit individual
  receipts for all Reported (R) and Carried (C) rows, but BATCH Dismissed (D)
  rows into grouped one-line receipts:
  `[OBLIG:function_summary.md:<contract>.*] STATUS:D KEY:<shared reason> -> rows: f1,f2,...`
  (the receipt gate is WARNING-only, so batching D-rows cannot fail a gate).

Final Step -- Edit: mark COMPLETE.
Once all findings and required sections are written, APPEND at the END of the
file:

    <!-- PLAMEN_STATUS: COMPLETE -->
    <!-- PLAMEN_FINDINGS_COUNT: {N} -->

`{N}` is the count of `### Finding [ID]:` blocks you wrote. If `{N} == 0`
(no confirmed findings in your domain), you MUST ALSO include a
`## No Findings` section with a brief rationale describing what you analyzed
and why nothing rose to a reportable finding. A `PLAMEN_FINDINGS_COUNT: 0`
file without a `## No Findings` (or `## Negative Result`) rationale fails the
structural check and the driver treats the file as still IN_PROGRESS. Do not
leave residual placeholder strings (`TODO:`, `FILL_ME`, `<placeholder>`) in a
COMPLETE file. Note: depth findings use the `### Finding [ID]:` block format,
NOT a breadth-style `## Findings` heading -- the depth structural check does
NOT require a `## Findings` heading.
```

The driver's depth gate (`compute_depth_row_statuses`) checks the canonical
four `depth_{role}_findings.md` files (derived from this phase's role set).
On fresh audits each must be COMPLETE + structurally sound; on legacy/resumed
scratchpads the legacy quorum applies and unmarked files are tolerated with a
warning.

### Two Mandatory Additions to Each Depth Agent Prompt

When constructing each depth agent's Task() prompt, include the two
directives below VERBATIM. They are MANDATORY, not optional. Prior audits
showed 35-40% compliance when they were phrased as soft one-liners — they
are now hard obligations with worked examples. They are still compact
(no 300-token blocks) so they do not strain the per-session token cap.

For all 4 standard depth roles (token-flow, state-trace, edge-case,
external):

> **MANDATORY — Generic Security Obligations.** If
> `{SCRATCHPAD}/security_obligations.md` exists, read it before finalizing your
> output. It is a typed graph/recon feature-derived obligation projection, not a list of
> expected findings. Address obligations relevant to your role and emit a
> receipt for each one you directly evaluated:
> `[OBLIG:security_obligations.md:<SO-ID>] ALIAS:<SOT-ID> STATUS:R|D|C KEY:<one-line> -> <finding_id|reason|phase>`.
> Emit one receipt per evaluated alias when multiple aliases are listed; omit
> `ALIAS:` only when the obligation has exactly one alias.
> For every `STATUS:R` receipt, copy the complete generated marker
> `PLAMEN_SECURITY_OBLIGATION_EVIDENCE` from that alias row into the
> referenced finding section. Do not reconstruct it from memory or substitute
> normalized prose. A missing, partial, or changed marker leaves the alias
> unbound and it remains queueable for repair.
> Use `R` only when you reported a finding, `D` only with concrete code
> evidence for safety/refutation, and `C` only when a named later phase owns
> the remaining work.

> **MANDATORY — Obligation Receipts.** If `{SCRATCHPAD}/function_summary.md`
> exists, your output file is INCOMPLETE until it ends with a single
> `## Obligation Receipts — function_summary.md` section. For EVERY row in
> your role's partition (state-trace owns state-writer rows; token-flow owns
> external-caller rows; edge-case and external own either) emit one receipt:
> `[OBLIG:function_summary.md:<contract>.<function>] STATUS:R|D|C KEY:<one-line> -> <finding_id|reason>`
> STATUS is `R` (Reported a finding), `D` (Dismissed — concrete reason it is
> safe), or `C` (Carried to a named later phase). Every partition row needs
> a receipt; an un-receipted row is an unaccounted obligation.
>
> Worked example — `function_summary.md` row `Vault.withdraw` is in your
> state-trace partition and you found no bug:
> `[OBLIG:function_summary.md:Vault.withdraw] STATUS:D KEY:burns shares before transfer, CEI order correct -> no finding, balances reconcile`

For token-flow and state-trace ONLY (edge-case/external are covered by the
post-depth Perturbation Agent):

> **MANDATORY — Perturbation Block.** For EACH Medium+ CONFIRMED finding you
> produce, append a `### Perturbation Block — <finding_id>` table directly
> after the finding. The table has one row per operator: `SIBLING` (each
> sibling contract/function that shares the pattern), `FIELD` (each decoded
> calldata/struct field), `DIRECTION_FLIP` (the inverse operation, or N/A),
> `ACTOR` (the Rule 12 actor categories). At least 2 rows MUST carry a
> non-N/A verdict with a `file:line` citation — a perturbation block where
> every row is N/A is non-compliant.
>
> Worked example for a deposit-rounding finding `DT-3`:
> ```
> ### Perturbation Block — DT-3
> | Operator | Probe | Verdict |
> |----------|-------|---------|
> | SIBLING | Pool.mint() shares same rounding helper | VULNERABLE — Pool.sol:88 rounds down identically |
> | FIELD | amount field | safe — bounded by balanceOf check at Vault.sol:140 |
> | DIRECTION_FLIP | withdraw() inverse path | VULNERABLE — Vault.sol:201 rounds down on burn too |
> | ACTOR | first depositor | N/A |
> ```

The Python gates (`_check_function_summary_obligation` and
`_check_perturbation_block_per_finding`) parse the resulting receipts and
perturbation blocks. Both gates are WARNING-only — the pipeline never halts
on missing receipts — but an output with zero receipts or a Medium+ finding
with no perturbation block is a documented quality failure.

### Blind Spot Scanners (3)

| Scanner | Focus | Output File |
|---------|-------|-------------|
| Scanner A | Tokens and Parameters | `blind_spot_a_findings.md` |
| Scanner B | Guards, Visibility, Inheritance + Override Safety | `blind_spot_b_findings.md` |
| Scanner C | Role Lifecycle, Capability Exposure + Reachability | `blind_spot_c_findings.md` |

Scanner C CHECK 5 contains the untrusted-call-target check that catches guard parameter injection. ALL 3 scanners are NEVER-CUT in Thorough mode.

### Validation Sweep Agent (1)

Output: `validation_sweep_findings.md` or `scanner_validation_findings.md`

Performs cross-cutting validation across all contracts: write-site completeness, accumulator co-dependencies, loop iteration bounds, event emission coverage.

### Niche Agents (flag-triggered)

For each REQUIRED niche agent in `template_recommendations.md` -> `Niche Agents` section:
- Read definition from `~/.claude/agents/skills/niche/{name}/SKILL.md`
- Spawn alongside depth agents
- Each niche agent = 1 budget slot
- Output: `{SCRATCHPAD}/niche_{name}_findings.md`

Late trigger: after reading `semantic_invariants.md`, if it reports
`sync_gaps >= 1`, `accumulation_exposures >= 1`, `conditional_writes >= 1`,
or `cluster_gaps >= 1`, spawn `SEMANTIC_GAP_INVESTIGATOR` even if it is not
listed in `template_recommendations.md`. It writes
`{SCRATCHPAD}/niche_semantic_gap_findings.md` and must preserve every
missing-write / lifecycle-gap mechanism as a standalone finding or explicit
SAFE conclusion.

Every Phase 4b subagent prompt MUST end with this containment line:

`SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.`

### Timeout Split-and-Retry

If any spawned agent stalls or times out, do not wait until the whole phase
expires. Close or abandon only that stalled agent, then split its assigned scope
into 2 "lite" agents (max 3 findings each, no static analyzer, max 5 files).
2 lite agents = 1 budget unit.

The phase may return only after every required output file below passes disk
verification, or after a replacement lite agent has produced and finalized the
missing output:

Disk verification means:
- the file exists;
- if the file is a depth/scanner/niche findings artifact, the LAST
  `PLAMEN_STATUS:` marker in the file is `COMPLETE`;
- findings artifacts contain at least one real `### Finding [` / `## Finding [`
  block OR a `## No Findings` / `## Negative Result` rationale;
- files are not header-only reservation stubs.

- `depth_token_flow_findings.md`
- `depth_state_trace_findings.md`
- `depth_edge_case_findings.md`
- `depth_external_findings.md`
- `blind_spot_a_findings.md`
- `blind_spot_b_findings.md`
- `blind_spot_c_findings.md`
- `validation_sweep_findings.md` or `scanner_validation_findings.md`
- `confidence_scores.md` (Core/Thorough)
- `adaptive_loop_log.md`
- `design_stress_findings.md` or `depth_design_stress_findings.md` (Thorough)
- `perturbation_findings.md` or `depth_perturbation_findings.md` (Thorough)
- `skill_execution_gaps.md` or `skill_execution_checklist.md` (Thorough)

This is a first-attempt completion requirement. Do not rely on the driver retry
path to repair missing standard depth files, never-cut artifacts, or graph
artifact references.

---

## STEP-TRACE Injection (Thorough Only — MANDATORY)

Each standard depth agent (SC and L1) MUST include exactly one
`## Step Execution Trace` table **inside its assigned findings output**. It
must not write another artifact. The driver extracts the table rows verbatim
into `step_execution_trace_{role}.md` and binds that derived sidecar to the
exact findings SHA-256.

- Light/Core mode depth spawns SKIP STEP-TRACE — the gate is mode-gated to Thorough only.
- Scanners and niche agents do NOT need STEP-TRACE (different agent class; gate operates on `depth_*_findings.md` only).
- A `yes` row is proof only with a resolvable project-source `file:Lline` in
  Evidence. Bare tags, finding IDs, `(general)`, and lenient line prose are not
  proof. A missing/malformed embedded table, stale digest, or row mismatch is
  recorded as actionable UNKNOWN; the driver never infers YES from findings or
  evidence-tag density.

---

## Transient Routing Proposal (MANDATORY for Core/Thorough)

After iteration-1 workers return, ask the lightweight helper defined in
`~/.claude/prompts/shared/v2/phase4b-scoring.md` to return a compact routing
table to this coordinator. The helper has no scratchpad write authority. The
table is transient routing advice, not a verdict, proof, demotion, or clean
conclusion.

MUST NOT create, update, or modify
`{SCRATCHPAD}/confidence_scores.md`,
`{SCRATCHPAD}/confidence_consensus_authority.json`, or
`{SCRATCHPAD}/consensus_map.md`. The deterministic driver independently
publishes those canonical artifacts after this depth wave returns. If the
helper fails or its proposal is incomplete, treat every unresolved Medium+
candidate as UNCERTAIN and allocate targeted depth rather than skipping it.

Preserve original depth/scanner/niche IDs such as `DCI-3`, `DST-4`, `DX-2`,
`DN-1`, `PERT-1`, `SLITHER-1`, `VS-1`, and `BLIND-1` in the transient table.

### Core Mode: 2-Axis Scoring
```
composite = Evidence x 0.5 + Analysis_Quality x 0.5
```

### Thorough Mode: 3 Code-Evidence Axes
```
composite = Evidence x 0.25 + Consensus x 0.25 + Analysis_Quality x 0.3
```

### Classification Thresholds

| Composite Score | Classification | Action |
|----------------|---------------|--------|
| >= 0.7 | **CONFIDENT** | No more depth needed for this finding |
| 0.4-0.7 | **UNCERTAIN** | Spawn targeted depth agent for this finding's domain during the depth loop |
| < 0.4 | **LOW CONFIDENCE** | Spawn a depth agent for more code evidence during the depth loop; record `VERIFICATION_NEEDED` inside depth-owned outputs only |

---

## Iteration 2 (Thorough Only)

**Core mode**: Skip iteration 2 entirely. Record uncertain findings in depth outputs, then stop.

**Thorough mode**: Spawn targeted Devil's Advocate depth agents per domain for ALL uncertain findings.

### Hard DA Role (Anti-Dilution Rule AD-2)

Iteration 2+ agents receive structural adversarial framing:

*"You are the Devil's Advocate Depth Agent. Your PRIMARY job is to find what the previous analysis MISSED - not to re-confirm what it found."*

Key rules:
- Hard Devil's Advocate role: agents are structurally adversarial
- Severity-weighted budget: `spawn_priority = (1 - confidence) * severity_weight`
- Anti-dilution: evidence-only finding cards (AD-1), max 5 per agent (AD-3)
- Fresh tool calls mandatory (AD-4)
- New-evidence-only re-scoring (AD-5)
- Contrastive conditioning via analysis path summaries
- Read `step_execution_gaps_mechanical.md` before choosing targets. Every
  `no`, `partial`, or `unknown` row is mandatory. A named skill/step must be
  executed directly; an `agent-trace` UNKNOWN requires rerunning the original
  assigned role methodology and every injected skill. Findings prose or tags
  alone cannot close the row; cite a resolvable project source `file:Lline`.

### Loop Dynamics Detection

Classify score changes as:
- **CONTRACTIVE**: Scores converging (improving) -> continue
- **OSCILLATORY**: >50% of changes are reversals -> force CONTESTED, exit
- **EXPLORATORY**: New findings discovered -> continue

---

## Iteration 3 (Thorough Only, Conditional)

Only if still uncertain findings exist AND progress was made in iteration 2.

After iteration 3:
- Retain every unresolved candidate and route it to mandatory verification or
  visible human-review debt; confidence telemetry cannot change its verdict
- Write `adaptive_loop_log.md` with iteration count, spawns used, exit condition triggered

---

## Convergence Criteria

| Criterion | Value |
|-----------|-------|
| Hard iteration cap | 3 (Core: 1, Light: 1 with no scoring) |
| Dynamic spawn cap | `min(max(depth_floor, ceil(findings/5)+7), hard_cap)` |
| Progress check | If NO finding's confidence improved in an iteration -> exit early |
| Zero uncertain | If 0 findings score < 0.7 after any iteration -> exit loop |
| Unresolved after cap | Retain candidate; mandatory verification or visible review debt |
| Oscillation detection | >50% reversals -> retain unresolved candidates, record routing debt, exit |
| Iteration 2 skip policy | May ONLY skip if all UNCERTAIN findings are Low/Info. Medium+ UNCERTAIN = MANDATORY iter 2. |

---

## Post-Iteration Mandatory Steps (Thorough Only)

Steps 6-8 run IN PARALLEL. Spawn all 3 agents in a single message with 3 Task calls.

### Step 6: Design Stress Testing (UNCONDITIONAL)

ALWAYS spawn Design Stress Testing Agent. 1 slot is pre-reserved and UNCONDITIONAL — not a "budget redirect." This agent runs regardless of remaining budget.

Output: `{SCRATCHPAD}/design_stress_findings.md`

### Step 7: Finding Perturbation Agent (MANDATORY)

After depth iteration completes, spawn the Finding Perturbation Agent (sonnet, 1 pre-reserved budget slot).

- Applies 5 structured mutation operators (DIRECTION_FLIP, BOUNDARY_SHIFT, ROLE_SWAP, TIMING_INVERT, PARAMETER_SWAP) to each CONFIRMED depth finding
- Tests for adjacent vulnerabilities
- Catches the "single-hit satisfaction" class
- Output: `{SCRATCHPAD}/perturbation_findings.md` with `[PERT-N]` IDs

Use the standalone prompt `~/.claude/prompts/shared/v2/phase4b-perturbation.md`.

### Step 8: Skill Execution Checklist (MANDATORY)

After depth iteration completes, spawn the Depth Skill Execution Checklist Agent (haiku, negligible cost).

- Verifies each depth agent executed each step of its assigned skill
- Produces coverage table: `| Agent | Skill Step | Evidence in Output? | Gap? |`
- Gaps become investigation questions for DA iteration 2 per AD-6
- Output: `{SCRATCHPAD}/skill_execution_gaps.md` (also satisfies `skill_execution_checklist.md` via any_of group)

Use the standalone prompt `~/.claude/prompts/shared/v2/phase4b-skill-checklist.md`.

---

## THOROUGH CHECKPOINT: Post-Depth (Static Manifest Check)

**Do NOT write checkpoint assertions from memory.** Read the static manifest and verify against it:

```
// STEP 0: Mode gate — this check is Thorough-only
if MODE != THOROUGH:
    // Core/Light: only assert confidence_scores.md + adaptive_loop_log.md exist, then proceed
    ASSERT: confidence_scores.md exists (Core) OR skip scoring (Light)
    ASSERT: adaptive_loop_log.md exists
    LOG to {SCRATCHPAD}/checkpoint_postdepth.md
    return from the depth subprocess

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

// STEP 3b: Check late semantic-gap trigger from semantic_invariants.md
if semantic_invariants.md reports sync_gaps/accumulation_exposures/conditional_writes/cluster_gaps > 0:
    if not exists({SCRATCHPAD}/niche_semantic_gap_findings.md):
        missing.append({"niche_semantic_gap_findings.md", "SEMANTIC_GAP_INVESTIGATOR"})

// STEP 4: If missing -> spawn, do NOT proceed
if len(missing) > 0:
    LOG to {SCRATCHPAD}/violations.md: "PHASE 4b INCOMPLETE: {missing}"
    for each missing file:
        spawn the responsible agent (see Producer column in manifest)
    re-run STEP 2 after agents complete
    ASSERT len(missing) == 0 — HARD GATE, cannot mark depth complete

// STEP 5: Standard assertions
ASSERT: confidence_scores.md is non-empty
ASSERT: IF uncertain Medium+ findings exist after iter 1 -> adaptive_loop_log shows iter >= 2

LOG checkpoint result to {SCRATCHPAD}/checkpoint_postdepth.md
```

**WHY STATIC MANIFEST**: The orchestrator previously wrote its own checkpoint — verifying only what it remembered to do, silently skipping what it forgot. The static manifest file is defined outside the orchestrator's generation context. Missing depth-owned artifacts trigger depth-agent spawns, not silent passes.

---

## THOROUGH FUZZ CAMPAIGN (driver-scheduled — do NOT spawn from here)

In V2 the invariant/Medusa fuzz campaign is scheduled by the Python driver as a
Thorough-only **depth fuzz sidecar worker** (one per ecosystem, plus EVM Medusa
when `MEDUSA_AVAILABLE`). It is NOT a coordinator spawn:

- The driver emits the worker(s) per `(mode == thorough, ecosystem,
  build_status tool flags)` and points each at the canonical per-ecosystem
  worker prompt (`prompts/{LANGUAGE}/v2/phase4b-invariant-fuzz.md`, and EVM
  `prompts/evm/v2/phase4b-medusa-fuzz.md`). The worker runs forge/medusa/cargo
  /sui via Bash itself.
- It is **additive and non-blocking**: fuzz results add `[FUZZ-N]`/`[MEDUSA-N]`
  invariant-violation findings only. A tool-absent/failed/timed-out run writes a
  degrade-continue results artifact (`## Result Status: TOOL_UNAVAILABLE /
  COMPILATION_FAILED / TIMEOUT`) and never halts depth. Fuzz artifacts are NOT
  in the depth hard gate and NOT never-cut.
- Do **NOT** spawn a fuzz agent from this prompt, and do not ASSERT fuzz-artifact
  existence here — the driver owns completion via the worker pool, and the
  artifacts are intentionally outside the depth hard gate.

---

## Depth Exit

When all depth-owned artifacts pass disk verification, write `depth_exit.md`
with the structured format below and stop. Do not continue into later pipeline
phases.

```markdown
- criterion: {1-4}
- rationale: {why this exit criterion was met}
- explored_paths:
- {path 1 explored by depth agents}
- {path 2 explored by depth agents}
- {path 3 explored by depth agents}
```

Exit criteria:
1. All iterations exhausted (hard cap reached)
2. Zero uncertain findings remain (all >= 0.7 confidence)
3. No confidence improvement in latest iteration (stalled)
4. Full convergence (requires >= 3 explored paths documented)
