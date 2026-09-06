# Phase 6: Report Generation Prompt Templates

> **Usage**: Orchestrator reads this file and spawns the report pipeline: Index → 3 Tier Writers → Assembler.
> Replace placeholders `{SCRATCHPAD}`, `{PROJECT_ROOT}`, `{PASTE_VERDICTS}`, etc. with actual values.

> **Architecture**: Index Agent → 3 Parallel Tier Writers → Assembler Agent
> **Why**: A single report agent gets overwhelmed on 30+ hypotheses, producing catch-all tables and invisible findings. Splitting by severity tier ensures every finding gets a proper write-up.

---

## Step 6a: Index Agent

> **Model**: haiku (mechanical task - fast, cheap)
> **Purpose**: Creates master index mapping internal hypothesis IDs to clean report IDs. Assigns each hypothesis to exactly one tier.

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Report Index Agent. You create the master finding index for the audit report.

## Your Inputs
Read:
- {SCRATCHPAD}/verify_core.md — **OPTIONAL but primary when present**. SC and L1 pipelines normally produce this via the verification aggregate phase. When absent, enumerate `verify_*.md` files directly and derive per-hypothesis verdicts. Do NOT fail the phase on its absence.
- {SCRATCHPAD}/precedent_report_context.md (OPTIONAL, eligible-only driver projection of typed
  precedent authority; labelled context only under
  `precedent-evidence-policy.md`, never confidence/verdict/severity authority)
- {SCRATCHPAD}/finding_mapping.md (hypothesis → agent finding mapping)
- {SCRATCHPAD}/verification_queue.md (the bounded per-hypothesis view — coverage source)
- {SCRATCHPAD}/severity_binding.md (driver-computed expected severity per finding)
- {SCRATCHPAD}/report_index_coverage_seed.md (OPTIONAL, PRIMARY when present — driver-enumerated ID list of EVERY finding/hypothesis with source verdict, expected tier, mapped hypothesis, dedup absorbed→survivor relation. Completeness backbone for STEP 5/5.5 — enumerate the full ID set from here, NOT the raw inventory.)
- {SCRATCHPAD}/candidate_semantic_facets.md (preservation ledger for merges/deferred rows)
- {SCRATCHPAD}/contract_inventory.md (component list for report header)
- {SCRATCHPAD}/recon_summary.md (themes and risk areas)
- {SCRATCHPAD}/template_recommendations.md (niche/analysis lanes)
- The index is a MAPPING task over BOUNDED ledgers. `findings_inventory.md`,
  `hypotheses.md`, and raw `depth_*` / `blind_spot_*` / `scanner_*` /
  `validation_sweep_*` artifacts are fallback-only, single-finding, on-demand
  reads — open one finding's block ONLY when a bounded ledger leaves THAT finding
  ambiguous. NEVER bulk-read `findings_inventory.md` / `hypotheses.md` in full
  (100K+ of prose → context collapse; the driver scope override enforces this).
- When `verify_core.md` provides the status, do NOT open `finding_mapping.md`,
  raw depth, or scanner findings up front (fallback-only, missing detail only).
  If it is absent, read `verify_*.md` files directly — each carries its own
  hypothesis ID + verdict header.
- {SCRATCHPAD}/dedup_candidate_pairs.md (OPTIONAL — same-file pairs with high title/identifier overlap. HINTS for Step 1.5 consolidation, not mandates.)
- {SCRATCHPAD}/poc_demotion_proposals.json and poc_demotion_proposals.md (OPTIONAL — non-authoritative negative-review proposals. They MUST NOT lower severity, exclude, refute, merge, or otherwise dispose of a finding.)
- {SCRATCHPAD}/poc_demotion_scope_receipt.json and poc_demotion_scope_recovery_status.json (OPTIONAL — exact grouped-PoC scope and repair state. Scope/reverification evidence only; constituents retain pre-proposal severity.)
- {SCRATCHPAD}/independent_severity_caps.md (OPTIONAL — min(independent, claimed) caps; STEP 1 rule 9; cap-only.)

Forbidden inputs:
- Do NOT read raw `{SCRATCHPAD}/rag_validation.md`; only the deterministic
  `precedent_report_context.md` projection may supply external-source context.
- Do NOT read `{SCRATCHPAD}/report_index.md`, `{SCRATCHPAD}/report_coverage.md`,
  or any `*.attempt*` file when a retry hint is present. Previous report-index
  outputs are known-bad artifacts, not evidence.
- Do NOT read `_prompt_*`, `_stdio_*`, `tool_calls.jsonl`, `_retry_quarantine/`,
  or `_overflow/`.

Verification verdicts from orchestrator:
{PASTE_VERDICTS}

## Working-Set Discipline — PROCESS ONE TIER-BATCH PER TURN (MANDATORY)

Building the WHOLE Master Finding Index in one turn — all-tier STEP 1.5
consolidation plus all-tier STEP 5/5.5 coverage — is the context-collapse
trigger that has frozen this phase for tens of minutes. Do NOT hold every
finding's working set at once.

The driver pre-partitions the coverage seed into bounded per-tier shards:

- `report_index_seed_critical_high.md` (Critical + High IDs)
- `report_index_seed_medium.md` (Medium IDs)
- `report_index_seed_low_info.md` (Low + Informational IDs)

Process the index **one tier-batch at a time**, in this order: Critical+High →
Medium → Low+Info. For each tier-batch:

1. Read ONLY that tier's seed shard (a small, bounded ID list).
2. Run STEP 1.5 (root-cause consolidation) and STEP 5/5.5 (coverage) over
   THOSE IDs only. Consolidation never crosses tiers (the consolidation test
   already requires same-severity tier), so per-tier batching loses nothing.
3. Append that tier's rows to the Master Finding Index, Excluded Findings,
   Consolidation Map, and `report_coverage.md`, then move to the next tier.

Every ID in EVERY shard MUST receive exactly one disposition (a report ID, an
exclusion row, or a consolidation-absorbed entry). The union of the three
shards equals the full `report_index_coverage_seed.md`; the driver reconciles
the merged `report_index.md` against the FULL seed after you finish, so an ID
that falls between tier-batches is mechanically detected and a retry hint names
it. Cross-tier chains/cross-references are recorded once in the Cross-Reference
Map after all tiers are written.

### Disposition Authority Contract (MANDATORY)

Index/disposition Markdown only accounts/proposes. Non-body treatment requires
an exact same-identity, full-claim typed refutation or zero-harm decision, or an
applied hash-bound alias naming its delivered survivor. Missing/stale/partial/
contested authority defaults to BODY at upstream severity with
`UNRESOLVED-DISPOSITION`; `DEFERRED` remains debt. Lexical rules may veto, never
authorize.

## Your Task

### Severity Authority Contract (READ BEFORE TIERING)

Report indexing is a mapping task, not a new severity-assessment phase. Do NOT
recalibrate severity from your own impact judgment, economic intuition, title
wording, or evidence tag. The final report tier must be mechanically derived
from upstream severity plus explicit, auditable adjustment rules.

For every Master Finding Index row:

1. Read the mapped `verify_<ID>.md` file and the matching
   `verification_queue.md` row.
2. The row's final `Severity` and Report ID prefix (`C-`, `H-`, `M-`, `L-`,
   `I-`) MUST match the upstream verifier/queue severity unless one of the
   canonical adjustments below applies.
3. `[CODE-TRACE]` does NOT imply Low. When `PROVEN_ONLY: false`, a
   Medium/High/Critical `[CODE-TRACE]` finding stays at its upstream severity.
4. If final severity differs from upstream, the `Trust Adj.` column MUST
   contain one canonical reason with the original severity:
   - `TRUSTED-ACTOR(original_sev)`
   - `UNRESOLVED(original_sev)` or `PARTIAL(original_sev)`
   - `SEVERITY_OVERRIDE(original_sev)` only when supplied by the
     driver-only `_severity_override_ledger.json`
   - `POC-FAIL-PROPOSAL(no-tier-change)` only for visible review context
   - `PROVEN(original_sev)` only when `PROVEN_ONLY: true`
   - `CHAIN-UPGRADE(original_sev)` / `CHAIN-DOWNGRADE(original_sev)` with the
     chain ID and enabling relation
5. A bare `-` / `—` Trust Adj. is valid only when final severity equals
   upstream severity.
6. If no canonical adjustment applies, restore the upstream severity and
   matching report-ID tier. Do not silently move Medium verified findings into
   Low rows, and do not silently upgrade Informational findings to Low.

### STEP 1: Determine Final Severities

For each hypothesis, apply this priority order:
1. If a verifier returned a verdict → use verifier's final severity
2. If chain analysis upgraded severity → use upgraded severity
3. Otherwise → use the severity from hypotheses.md
4. **Trust claims**: Inventory trust labels are advisory. Only an exact, evidence-bound `FULLY_TRUSTED_ACTOR` typed-ledger event authorizes `TRUSTED-ACTOR(original_sev)`; otherwise preserve severity and show uncertainty. `WITHIN-BOUNDS` is context only.
5. **Proven-only mode**: Only when `PROVEN_ONLY: true`, cap `[CODE-TRACE]`-only findings at Low and record `PROVEN(original_sev)`; count demotions for the header note. When false, `[CODE-TRACE]` doesn't affect severity. EXCEPTION: a genuine structural-untestability ledger reason keeps verifier severity — record `STRUCTURAL-UNTESTABLE(original_sev)`; `[PROD-*]` is proof-grade, never capped.
6. **UNRESOLVED/PARTIAL**: Preserve the highest supported tier, record `UNRESOLVED(original_sev)` for visibility, retain the body, and flag human review. These states never discount severity by themselves.
7. **Skeptic boundary**: skeptic artifacts are proposal-only. A distinct typed adjudicator and validated report-authoritative ledger are required for any state change; absent/stale/ambiguous authority preserves severity and body placement.
8. **PoC-fail proposal boundary**: If `poc_demotion_proposals.json` exists, keep each listed finding at its highest supported pre-proposal severity and in the report body. A failed/non-established execution describes the encoded attempt; it MUST NOT lower severity, exclude, refute, merge, or close the candidate. Record `POC-FAIL-PROPOSAL(no-tier-change)` only as visible review context. Grouped scope rows identify which constituents require review; `P0-O REVERIFIED SUPPLEMENT` remains additive evidence and never creates a negative lifecycle effect.
9. **Driver-only severity overrides**: If `_severity_override_ledger.json`
   exists, apply only the listed override rows and record
   `SEVERITY_OVERRIDE(original_sev)` in Trust Adj. Agents must not invent this
   token without the driver-only ledger.
10. Obey driver `status_binding.md`/`severity_binding.md` tokens (Fix 1/3; see `report-template.md`).

### STEP 1.25: Client-Worthiness Triage (CONSERVATIVE)

This is presentation triage, not a new analysis phase.

**Material-Harm Body Floor (MANDATORY, recall-safe — also driver-enforced).**
The body is for findings with a real security consequence; independently
confirmed zero-harm quality findings may go to the appendix. `disposition.md`
is proposal-only. The driver derives `report_disposition_authority.json` from
exact verifier receipts/typed decisions and applies only authorized APPENDIX
proposals into **Appendix C: Quality & Hardening
Observations** (never dropped) — so prefer matching this floor here to avoid
churn:

Every relocation preserves the complete original section in
`report_appendix_full_content.json` and validates a client-field diff. Missing
or contradictory authority leaves BODY unchanged.

- A finding -> **APPENDIX** ONLY if it has ZERO security consequence — i.e. it
  is pure quality/hardening/observability/style with no runtime consequence;
  the exact typed decision must agree.
- Otherwise -> **BODY.** ANY real security consequence keeps it in the body AT
  ANY SEVERITY, even if trusted-actor-gated, self-inflicted-precondition, or
  bounded/dust: direct fund loss/extraction; funds/assets locked or frozen;
  privilege escalation; a liveness brick denying a core user action; accounting
  corruption leading to loss.
- **Recall-safe default: when in doubt, BODY.** Burying a real finding in the
  appendix is the unacceptable error; an extra body finding is cheap.
- Unsupported High/Medium quality labels remain BODY at upstream severity;
  Low/Info also remain BODY unless the exact independent zero-harm decision is
  present. A Low/Info with a real consequence is always BODY.
  DROP/FALSE_POSITIVE (independently typed full-claim refutation) is SEPARATE from
  APPENDIX — those go to Appendix A (Excluded), not Appendix C.

Propose one status: `REPORTABLE`; `MERGE_INTO:<id>`; `APPENDIX_ONLY`;
`DROP_FALSE_POSITIVE`; `DROP_NON_SECURITY`; `DROP_DESIGN_CONFIRMATION`;
`DROP_UNACTIONABLE_SPECULATION`; or `UNRESOLVED_EVIDENCE`. These are proposals;
only the typed authority contract makes a non-body state effective.

Never silently delete a candidate: preserve its identity in `report_coverage.md`
and the Consolidation Map or Excluded Findings. Every severity defaults to `REPORTABLE`.
Only an exact independent full-claim decision or applied alias can
override that default. `APPENDIX_ONLY` additionally requires typed zero security
consequence, no contradiction, and Low/Informational upstream severity. Missing
proof, `PARTIAL`, `CONTESTED`, `UNRESOLVED`, or external-premise uncertainty stay
in BODY at upstream severity with visible review debt. Design confirmations use
`DROP_DESIGN_CONFIRMATION`; repetitive non-security prose belongs outside BODY.

For an authorized non-body outcome, the Excluded Findings reason starts with the
exact status, cites the authority event, and names any alias survivor. Prose-only
rows are rejected and restored to BODY.

### STEP 1.5: Root-Cause Consolidation (MANDATORY)

Before assigning report IDs, consolidate hypotheses that share the same root cause into single report findings. This prevents inflated finding counts from pipeline fragmentation.

**Pre-computed hints**: Both sources are hints only; final semantic decision uses the test below and neither hint mechanically blocks/removes findings.

1. **`[LIKELY-DUP]` tags in `findings_inventory.md`**: same file and >=80% title overlap. Evaluate first; consolidate only when root cause and fix are the same.

2. **`dedup_candidate_pairs.md`**: same-file pairs with >=50% title overlap or shared code identifiers. Evaluate with the consolidation test.

**When in doubt, do NOT merge.** A duplicate finding in the report is a cosmetic issue. A dropped true positive is a missed vulnerability.

**Semantic retention rule**: Preserve the broken invariant, branch precondition, terminal mechanism, verification disposition, and source IDs from bounded inputs (`verify_core.md`, `verify_*.md`, `finding_mapping.md`, `findings_inventory.md`, dedup hints). Retain, do not rediscover: no fresh analysis or bulk raw-artifact reads; read minimal fallback only for missing detail.

**Consolidation test** - merge two hypotheses into ONE report finding if ALL of these are true:
1. **Same fix pattern**: Same type of code change.
2. **Same severity tier**: Both are in the same tier after STEP 1 adjustments
3. **Same vulnerability class**: Same bug pattern.
4. **Describable together**: A reader can understand all affected locations from a single description + location table
5. **No semantic loss**: The merged finding preserves every distinct invariant, branch, terminal mechanism, disposition, and source ID in title/description, locations, Consolidation Reason, or coverage ledger

**Do NOT merge if**:
- Findings are in different severity tiers
- Root causes/fixes differ (for example missing event vs wrong event parameters)
- Merging would exceed 6 locations per finding (split into 2 findings for readability)
- Merging would drop, blur, or overwrite a distinct branch precondition or terminal mechanism. Different branches/mechanisms stay separate unless a shared finding can state both clearly.

**Chain carve-out (EXCEPTION to the tier rule)**: When one finding is a chain
hypothesis (constituent set in `chain_hypotheses.md` / `finding_mapping.md`) and
the other is its sole constituent — OR its two constituents share file+function
and root cause — AND the chain carries NO Combined-Impact justification
(`Severity-Upgrade-Justified: NO`, missing line, or `Combined-Impact: NONE`),
**MERGE the chain INTO the constituent at the constituent severity** and record
`CHAIN-RESTATEMENT` in the Consolidation Reason. A tier gap from an unjustified
chain upgrade is NOT a reason to keep them separate. Set the merged row's
`Trust Adj.` to `CHAIN-DOWNGRADE(<chain's original severity>)` for an auditable
trail. A chain that DOES carry a justified Combined-Impact is a genuine compound
finding — keep it separate and record `CHAIN-UPGRADE(<highest constituent
severity>)` with the chain ID instead.

**Common consolidation patterns**: missing events, invalid admin setter values, missing staleness checks, retroactive parameter changes, and same-role trust findings when severity/root cause/fix match.

**Output**: For each consolidation, record:
```
CONSOLIDATED: H-{A} + H-{B} [+ H-{C}...] → single finding
  Title: {consolidated title}
  Locations: {list all affected locations}
  Severity: {shared severity}
  Internal refs: {all absorbed hypothesis IDs}
```

In `Consolidation Reason`, include shared root cause/fix plus preserved invariant, branch, terminal mechanism, disposition, and source IDs. Do not add Master Finding Index columns.

Hypotheses NOT consolidated remain as standalone findings.

### STEP 2: Assign Report IDs

Sort all findings (consolidated and standalone) by severity tier, then by verification status (VERIFIED first), then by impact.

Assign clean sequential IDs:
- Critical: C-01, C-02, ...
- High: H-01, H-02, ...
- Medium: M-01, M-02, ...
- Low: L-01, L-02, ...
- Informational: I-01, I-02, ...

### STEP 3: Create Tier Assignments

Assign each finding to exactly ONE tier writer:
- **Critical+High Tier**: All C-XX and H-XX findings
- **Medium Tier**: All M-XX findings
- **Low+Info Tier**: All L-XX and I-XX findings

### STEP 4: Create Cross-Reference Map

For chain findings that reference component findings, note the cross-references using REPORT IDs only.
Example: If chain hypothesis CH-1 (now C-01) references standalone hypothesis H-5 (now H-03), record: 'C-01 references H-03'

### STEP 5: Verify Completeness (MANDATORY)

Enumerate the per-tier ID set from the tier seed shards
(`report_index_seed_critical_high.md`, `report_index_seed_medium.md`,
`report_index_seed_low_info.md`) — one shard per tier-batch — whose union is
the full `report_index_coverage_seed.md`. When the shards are absent, fall back
to the full `report_index_coverage_seed.md`; when that too is absent, derive the
full ID set from `verification_queue.md` + `verify_core.md` +
`finding_mapping.md` — these bounded sources contain every hypothesis and every
standalone finding ([VS-*], [BLIND-*], [SE-*], [EN-*], [SLITHER-*]) ID. Do NOT
re-derive the ID set by bulk-reading `hypotheses.md` or `findings_inventory.md`.

Cross-check: For EVERY ID in that bounded set:
- Is it assigned a report ID in the Master Finding Index above?
- If NO and NOT marked FALSE_POSITIVE by a verifier → ASSIGN a report ID and tier

**HARD RULE**: The ONLY valid exclusion reasons are the conservative triage
statuses from Step 1.25, an explicit false-positive/refuted verifier verdict,
or an explicit duplicate/merge already listed with the absorbing report ID.
"Not grouped into a hypothesis" is NOT a valid exclusion reason.

### STEP 5.5: Promotion Coverage Audit (MANDATORY)

Before finalizing the index, produce an accounting receipt in `report_coverage.md`.
Keep this bounded: use `verification_queue.md`, `verify_core.md`,
`finding_mapping.md`, and the final Master Finding Index as sources.
Do NOT bulk-read raw breadth/depth/scanner artifacts in this phase — raw
promotion checks are enforced mechanically by the Python gate; the indexer owns
the reportable verification-to-report mapping.

Coverage reasoning preserves upstream semantics: keep invariant, branch, terminal mechanism, disposition, and source IDs visible in `Report ID / Refutation / Reason` when they affect promotion, duplicate, false-positive, or deferred status. `DUPLICATE` reasons must show no distinct branch/mechanism was dropped; otherwise assign a report ID or use the correct non-duplicate status.

For each verification/finding-mapping candidate, assign one of:
- `PROMOTED`: mapped to a report ID
- `MERGED`: absorbed into an existing report ID with no semantic loss
- `APPENDIX_ONLY`: accounted in Excluded Findings but intentionally outside the body
- `DROP_FALSE_POSITIVE`: explicitly refuted by verifier/judge evidence
- `DROP_NON_SECURITY`: no security-relevant impact after verification
- `DROP_DESIGN_CONFIRMATION`: positive/safe/design-confirmation row, not a finding
- `DROP_UNACTIONABLE_SPECULATION`: no reachable path, impacted actor, or actionable fix
- `DUPLICATE`: absorbed into an existing report ID; use only when equivalent to `MERGED`
- `FALSE_POSITIVE`: legacy alias for `DROP_FALSE_POSITIVE`
- `DEFERRED`: hypothesis remains unproven, but must still appear in the ledger

**HARD RULES**:
1. A Medium+ candidate from verification_queue/finding_mapping MUST NOT disappear silently.
2. If a Medium+ candidate is not promoted, the ledger must name the absorbing
   report ID or the exact verifier/judge evidence supporting the non-body
   triage status.
3. If recon recommends a niche lane (e.g. `EVENT_COMPLETENESS`) that did not run
   in the current mode, record it in the ledger as `DEFERRED: mode-limited`.
4. If a candidate appears in verification_queue/verify_core but not in
   `finding_mapping.md`, treat it as a promotion failure: assign a report ID or
   explicitly mark it duplicate / false positive / deferred with reasoning.
5. Do not use `DUPLICATE`, `MERGED`, `APPENDIX_ONLY`, or any `DROP_*` status for
   convenience when a distinct invariant, branch, terminal mechanism,
   disposition, or source ID is not retained by the absorbing report ID and
   ledger reason.

This step catches the failure mode where a verified candidate is dropped before
the final report, without making report_index an unbounded raw-artifact scanner.

### Excluded Findings (for Appendix A)
| Internal ID | Severity | Title | Exclusion Reason (APPENDIX_ONLY / DROP_* / FALSE_POSITIVE / DUPLICATE OF X-NN / MERGE_INTO X-NN only) |

## Output

Write to {SCRATCHPAD}/report_index.md:

```markdown
# Report Index

## Report Header Info
- Project Name: {from design_context.md}
- Date: {today}
- Contracts: {from contract_inventory.md}
- Build Status: {from build_status.md}

## Summary Counts
| Severity | Count |
|----------|-------|
| Critical | {N} |
| High | {N} |
| Medium | {N} |
| Low | {N} |
| Informational | {N} |

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|-----------|--------------------|
| C-01 | [critical upstream title] | Critical | [location] | VERIFIED | - | <critical-internal-id> |
| H-01 | [high upstream title] | High | [location] | CONFIRMED | - | <high-internal-id> |
| M-01 | [trusted-actor-demoted high title] | Medium | [location] | UNVERIFIED | TRUSTED-ACTOR(High) | <trusted-actor-internal-id> |
| ... | ... | ... | ... | ... | ... | ... |

**CRITICAL FORMAT RULES for Master Finding Index:**
0. **Example rows use placeholders only.** Do not copy their report tier, report ID, or internal ID shape for real findings.
1. **Internal Hypothesis column MUST be LAST** — downstream validation extracts the last matching ID per row.
2. **Do NOT include an Agent Sources column.** Agent source traceability belongs in `report_coverage.md`, not in the client-facing report.
3. **No parenthetical constituent IDs** — write `CH-3` or `H-2+H-13`, NOT `CH-3 (H-2, H-13)`. Parenthetical constituent IDs in the same cell cause duplicate binding failures.
4. **Consolidated rows may use `+`-joined IDs** — write `H-2+H-13` in Internal Hypothesis and list the same IDs in the Consolidation Map. Use `CH-3` only when a chain has its own verifier file; otherwise use joined constituents so writers can read every evidence file.
5. **Section headings must be EXACT** — use `## Master Finding Index` and `## Excluded Findings`; suffixes create duplicate parsing.

## Tier Assignments

### Critical+High Tier (for Opus writer)
[List of report IDs with their internal hypothesis refs and verification file paths]

### Medium Tier (for Sonnet writer)
[List of report IDs with their internal hypothesis refs]

### Low+Info Tier (for Sonnet writer)
[List of report IDs with their internal hypothesis refs]

## Consolidation Map
| Report ID | Consolidated From | Consolidation Reason |
|-----------|------------------|---------------------|
| L-03 | H-39, H-40, H-55 | Same fix pattern: add zero-value validation to admin setters |
| L-08 | H-70, H-71 | Same fix pattern: add event emission to admin state changes |

## Cross-Reference Map
| Report ID | References | Context |
|-----------|-----------|---------|
| C-01 | H-03, M-05 | Chain: C-01 combines the bugs described in H-03 and M-05 |

## Excluded Findings (for Appendix A)
| Internal ID | Severity | Title | Exclusion Reason (FALSE_POSITIVE or DUPLICATE OF X-NN only) |
```

Also write to `{SCRATCHPAD}/report_coverage.md`:

```markdown
# Report Coverage Audit

## Raw Candidate Ledger
| Source File | Candidate ID / Label | Severity Signal | Status | Report ID / Refutation / Reason |
|-------------|----------------------|-----------------|--------|---------------------------------|

## Uncovered Mode-Limited Recommendations
| Source | Recommended Lane | Why Not Run | Risk of Miss |
|--------|------------------|-------------|--------------|

## Promotion Failures Repaired
| Raw Source | Candidate | Action Taken |
|------------|----------|--------------|
```

### Terminal Stop Rule

After writing both `report_index.md` and `report_coverage.md`, stop immediately.
Do not reopen either output to polish it. Do not run another self-audit loop.
The Python driver owns post-write validation and will retry with a precise hint
if anything is still wrong.

Forbidden outputs in this phase:
- Do NOT write `report_critical_high.md` or `report_critical_high_*.md`.
- Do NOT write `report_medium.md` or `report_medium_*.md`.
- Do NOT write `report_low_info.md` or `report_low_info_*.md`.
- Do NOT write `AUDIT_REPORT.md`.

If you notice any of those files already exist, ignore them. They belong to
later subprocesses and are not part of your task.

Return: 'DONE: {N_total} findings indexed ({N_consolidated} consolidated from {N_original} hypotheses) - {C} Critical, {H} High, {M} Medium, {L} Low, {I} Info'
")
```

---

### Step 6a.1: Completeness Verification (Orchestrator Inline)

After Index Agent returns, orchestrator performs:
1-4. Count hypothesis IDs (`| H-` in `hypotheses.md`), report IDs (Master Finding Index), excluded IDs (Excluded Findings), and consolidated IDs (absorbed via STEP 1.5).
5. **ASSERT**: `hypothesis_count == report_ids + excluded_count + consolidated_absorbed_count`
6. If **MISMATCH**: diff ID sets to find missing hypotheses; log `"INDEX COMPLETENESS FAILURE: {missing_list}"`; re-spawn Index Agent with `"Assign report IDs to these missing hypotheses: {list}"`; re-run this verification.

> **This is a mechanical check - the orchestrator does it inline, no new agent needed.**

Then verify `{SCRATCHPAD}/report_coverage.md` exists with at least one ledger row
per depth/scanner artifact in the scratchpad.

---

## Step 6b: Tier Writers (3 Parallel Agents)

> **Spawn ALL THREE in a single message as parallel Task calls.**
> Each tier writer receives ONLY its assigned findings from report_index.md.

### Tier Writer Common Rules (referenced by all 3 writers)

All tier writers MUST follow these rules:
1. **NO internal IDs** (hypothesis IDs, chain IDs, agent IDs) anywhere in output
2. **Every finding gets its own ### section** - no tables, no groups, no summaries, no catch-all dumps
3. **Write as if the reader has never seen the audit pipeline** - no references to breadth agents, chain analysis, etc.
4. **Cross-references use report IDs only** - include finding title in parentheses for context: `see H-03 (example title)`
5. **Trust context**: For a ledger-authorized `TRUSTED-ACTOR`, include after Severity: "Severity adjusted from {original} - attack requires {actor} to violate stated trust assumption: {assumption}." An inventory tag alone is rendered as unresolved trust context without changing severity. For `WITHIN-BOUNDS`, note bounds context in Description without changing severity.
6. **Missing verify_*.md**: Never stub. Write the full body from hypothesis/inventory data, mark header `[VERIFICATION NOT EXECUTED]`, include the Phase 5 no-PoC sentence, and populate Severity, Location, Description, Impact, Recommendation.
7. **Minimum length**: Every `### [X-NN]` body must be at least 400 characters or the quality gate retries the writer.
8. **Chunk scoping**: If the driver prefix lists "Findings assigned to THIS chunk", write only those IDs in order.
9. **Minimal-input override**: If the driver prefix supplies a minimal read set, obey it; avoid broad `hypotheses.md`, `chain_hypotheses.md`, `synthesis_full.md`, or unrelated `verify_*.md` reads unless assigned detail is missing.
10. **Constituent root-cause preservation**: Via `finding_mapping.md`, identify all source findings grouped into the hypothesis; read each one's Root Cause line in `findings_inventory.md`. If a source finding has a distinct root-cause angle (a different function, missing write, or mechanism) not in your Description, add it. Describing only the hypothesis's dominant framing while dropping an absorbed constituent's distinct root cause is a recall gap in the delivered report.

### Critical+High Tier Writer

> **Model**: opus (highest quality for most important findings)

```
Task(subagent_type="general-purpose", model="opus", prompt="
You are the Critical+High Findings Writer. You write the Critical and High severity sections of the audit report.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/report_critical_high.md` with a one-line header `# Critical and High Findings`. Reserves write budget so the file exists if interrupted; overwrite with full content at the end.

## Your Inputs
Read:
- {SCRATCHPAD}/report_index.md (your tier assignments under 'Critical+High Tier')
- assigned `verify_*.md` files only (verification results with PoC details)
- {SCRATCHPAD}/findings_inventory.md (fallback detail and source citations)
- {SCRATCHPAD}/finding_mapping.md (hypothesis → source finding mapping — for rule 10 constituent angle check)
- Optional fallback only if an assigned verify file is missing: {SCRATCHPAD}/hypotheses.md, {SCRATCHPAD}/chain_hypotheses.md
- ~/.claude/rules/report-template.md (finding format and rules)

## Your Task

For EACH finding assigned to your tier in report_index.md:

1. Write a full finding section using the EXACT format from report-template.md
2. Use the report ID from report_index.md (C-01, H-01, etc.) - NEVER use internal pipeline IDs
3. Include code snippets from the actual source files
4. For chain findings: describe the COMPLETE attack sequence in the Description - the reader should understand the full attack without reading other findings
5. For verified findings: include PoC results from verify_*.md
6. Cross-reference other findings using ONLY report IDs from report_index.md

## HARD RULES
Follow ALL Tier Writer Common Rules above (no internal IDs, own ### per finding, reader-naive perspective, report-ID cross-refs with title).

## Output

Write to {SCRATCHPAD}/report_critical_high.md:

```markdown
## Critical Findings

### [C-01] Title [VERIFIED]
[full section]

...

## High Findings

### [H-01] Title [VERIFIED/CONFIRMED/UNVERIFIED/CONTESTED]
[full section]

...
```

Return: 'DONE: {C} Critical + {H} High findings written'
")
```

### Medium Tier Writer

> **Model**: sonnet (good quality, cost-effective for medium tier)

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Medium Findings Writer. You write the Medium severity section of the audit report.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/report_medium.md` with a one-line header `# Medium Findings`. Reserves write budget so the file exists if interrupted; overwrite with full content at the end.

## Your Inputs
Read:
- {SCRATCHPAD}/report_index.md (your tier assignments under 'Medium Tier')
- assigned `verify_*.md` files only when present
- {SCRATCHPAD}/findings_inventory.md (agent finding details)
- {SCRATCHPAD}/finding_mapping.md (hypothesis → source finding mapping — for rule 10 constituent angle check)
- Optional fallback only if an assigned verify file is missing: {SCRATCHPAD}/hypotheses.md, {SCRATCHPAD}/chain_hypotheses.md
- ~/.claude/rules/report-template.md (finding format and rules)

For each finding, read cited source files directly when you need a code snippet.

## Your Task

For EACH finding assigned to your tier in report_index.md:

1. Write a full finding section using the EXACT format from report-template.md
2. Use the report ID from report_index.md (M-01, M-02, etc.) - NEVER use internal pipeline IDs
3. Include code snippets from the actual source files
4. Include a clear Recommendation with fix guidance

## HARD RULES
Follow ALL Tier Writer Common Rules above. Additionally: do NOT create catch-all sections - every finding is equally important.

## Output

Write to {SCRATCHPAD}/report_medium.md:

```markdown
## Medium Findings

### [M-01] Title [UNVERIFIED]
[full section]

### [M-02] Title [UNVERIFIED]
[full section]

...
```

Return: 'DONE: {M} Medium findings written'
")
```

### Low+Informational Tier Writer

> **Model**: sonnet (good quality, cost-effective for lower tiers)

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Low+Informational Findings Writer. You write the Low and Informational severity sections of the audit report.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/report_low_info.md` with a one-line header `# Low and Informational Findings`. Reserves write budget so the file exists if interrupted; overwrite with full content at the end.

## Your Inputs
Read:
- {SCRATCHPAD}/report_index.md (your tier assignments under 'Low+Info Tier')
- {SCRATCHPAD}/findings_inventory.md (agent finding details)
- {SCRATCHPAD}/finding_mapping.md (hypothesis → source finding mapping — for rule 10 constituent angle check)
- assigned `verify_*.md` files only when an assigned finding explicitly references one
- Optional fallback only if required detail is missing: {SCRATCHPAD}/hypotheses.md
- ~/.claude/rules/report-template.md (finding format and rules)

For each finding, read cited source files directly when you need a code snippet.

## Your Task

For EACH finding assigned to your tier in report_index.md:

1. **Classify**: Does this finding belong in the Quality Observations megasection?
   It qualifies ONLY if ALL hold: (a) Severity is Low or Informational; (b) the
   title/description matches a cosmetic class (dead code, unused imports/variables,
   naming, typos, magic numbers, missing docs, code style, gas optimization,
   redundant code/checks, variable shadowing); (c) NO plausible security impact
   (missing validation, missing events, access control, centralization risk are
   NOT cosmetic even at Low).

2. **Full-section findings**: Write using the EXACT format from report-template.md.
   Use report IDs (L-01, I-01, etc.). Include code snippets where relevant.
   Low: Recommendation field optional. Informational: PoC Result optional.

3. **Quality Observation findings**: Write as a single row in the megasection table.
   Include: ID, Title, Severity, Location, Class (from list above), 1-sentence Description.

**When in doubt, use full-section format.** The megasection is for unambiguous cosmetic observations only. A finding that could have security implications always gets a full section.

## HARD RULES
Follow ALL Tier Writer Common Rules above. Additionally: even simple Low/Info findings that get full sections deserve 3-5 sentences of Description and a clear Location.

## Output

Write to {SCRATCHPAD}/report_low_info.md:

```markdown
## Low Findings

### [L-01] Title
[full section]

...

## Informational Findings

### [I-01] Title
[full section]

...

## Quality Observations

| ID | Title | Severity | Location | Class | Description |
|----|-------|----------|----------|-------|-------------|
| I-03 | Unused import SafeMath | Info | src/Vault.sol:L5 | Unused imports | SafeMath imported but never used post-0.8 |
| L-04 | Dead code in _legacy() | Low | src/Router.sol:L200 | Dead code | Unreachable after v2 migration |
```

If no findings qualify for Quality Observations, omit the section entirely.

Return: 'DONE: {L} Low + {I} Informational findings written ({Q} as quality observations)'
")
```

---

## Step 6c: Assembler Agent

> **Model**: haiku for ≤25 findings, sonnet for >25 findings (haiku truncated on large reports in prior audits)
> **Purpose**: Merges the three tier sections into the final AUDIT_REPORT.md with header, summary, remediation order, and optional appendix.

```
Task(subagent_type="general-purpose", model="{haiku_or_sonnet}", prompt="
You are the Report Assembler. You merge the tier sections into the final audit report.

## Your Inputs
Read:
- {SCRATCHPAD}/report_index.md (header info, summary counts, cross-reference map, excluded findings)
- {SCRATCHPAD}/report_critical_high.md (Critical + High sections)
- {SCRATCHPAD}/report_medium.md (Medium section)
- {SCRATCHPAD}/report_low_info.md (Low + Informational sections)
- ~/.claude/rules/report-template.md (report structure template)

## Your Task

### STEP 1: Assemble Report

Combine sections in this order:
1. **Report Header** - from report_index.md header info
2. **Executive Summary** - 2-3 paragraphs summarizing the audit (write this yourself based on the findings)
3. **Summary Table** - from report_index.md counts
4. **Components Audited Table** - from report_index.md
5-9. **Findings sections** - paste Critical + High from report_critical_high.md, Medium from report_medium.md, Low + Informational from report_low_info.md, in that tier order
10. **Priority Remediation Order** - generate from report_index.md, ordered: Critical → High → Medium
11. **Appendix A: Excluded Findings** - client-facing exclusion summary only; internal traceability stays in report_index.md/report_coverage.md

### STEP 1.5: Output Sanitization

- Strip control characters, ANSI escape sequences, form-feed, and other
  non-printable bytes from headers, prose, and code fences (unless required
  source code) before writing the report.

### STEP 2: Quality Checks

Before writing, verify:
1. **Finding count matches summary** - count ### sections per severity tier, must equal summary table
2. **No internal IDs anywhere in AUDIT_REPORT.md** - scan for [CS-, [AC-, [TF-, [BLIND-, [EN-, [SE-, [VS-, [DEPTH-, [SLITHER-, [RS-, [PC-, [SP-, [DST-, [DE-, [DX-, [DS-, [DT-, CH-, and bracketed H- followed by numbers. NONE should appear in the delivered report.
3. **Cross-references valid** - check the cross-reference map from report_index.md, ensure referenced IDs exist
4. **No duplicate findings** - no two sections describe the same bug
5. **All tier files present** - if any tier file is missing or empty, note it as 'Section pending'

If any quality check fails, fix the issue in the assembled output. Document what was fixed.

### STEP 3: Write Final Report

Write the assembled report to: {PROJECT_ROOT}/AUDIT_REPORT.md

## Output

Write to {PROJECT_ROOT}/AUDIT_REPORT.md

Do NOT write `{SCRATCHPAD}/report_quality.md`. In V2, report quality is a
mechanical Python gate owned by the driver after assembly. The assembler owns
only `{PROJECT_ROOT}/AUDIT_REPORT.md`.

Return: 'DONE: Report assembled - {N} Critical, {N} High, {N} Medium, {N} Low, {N} Info - Quality: {PASS/ISSUES}'
")
```

> **Assembler Model Selection**: If total finding count from report_index.md > 25, use `model="sonnet"` not `model="haiku"` (haiku truncates on large reports).
