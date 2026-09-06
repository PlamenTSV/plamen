# Phase 6a: Report Index Agent

Execute the instructions below directly and stop. Do not spawn subagents.

> **Loaded by**: The V2 driver's Phase 6a subprocess (report index generation).
> **Model**: sonnet — reasoning task (severity reconciliation, conservative triage, semantic consolidation, coverage audit), NOT mechanical mapping. haiku produces binary-bucket stubs on large indexes (same lesson as confidence scoring). Matches the Phase definition in `plamen_types.py`.
> **Purpose**: Creates master index mapping internal hypothesis IDs to clean report
> IDs. Assigns each hypothesis to exactly one tier. Performs root-cause
> consolidation, completeness verification, and promotion coverage audit.
> Self-contained methodology for the index agent.

---

## Your Inputs

Read:
- `{SCRATCHPAD}/obligation_ledger.json` (OPTIONAL but authoritative when present - typed driver-generated retention obligations. Active Medium+ `exact_value_binding` and `chain_upgrade_retention` rows must map to a report ID, be absorbed by a named report ID with no semantic loss, or be explicitly refuted.)
- `{SCRATCHPAD}/verify_core.md` - **OPTIONAL but primary when present**. Both current SC and L1 pipelines normally produce this via the verification aggregate phase. When absent, enumerate `verify_*.md` files directly and derive the per-hypothesis verdicts from them. Do NOT fail the phase on its absence.
- `{SCRATCHPAD}/precedent_report_context.md` (OPTIONAL, eligible-only driver projection of typed
  precedent authority; labelled context only under
  `precedent-evidence-policy.md`, never confidence/verdict/severity authority)
- `{SCRATCHPAD}/finding_mapping.md` (hypothesis -> agent finding mapping)
- `{SCRATCHPAD}/contract_inventory.md` (SC component list for report header, if present)
- `{SCRATCHPAD}/subsystem_map.md` (L1 component/subsystem list for report header, if present)
- `{SCRATCHPAD}/findings_inventory.md` (complete agent finding inventory)
- `{SCRATCHPAD}/recon_summary.md` (audit themes and risk areas)
- `{SCRATCHPAD}/design_context.md` (SC project context, if present)
- `{SCRATCHPAD}/threat_model.md` (L1 project context, if present)
- `{SCRATCHPAD}/build_status.md` (SC build/static-analysis status, if present)
- `{SCRATCHPAD}/primitive_status.md` (L1 primitive bake/static-analysis status, if present)
- `{SCRATCHPAD}/template_recommendations.md` (recommended niche/analysis lanes)
- If `verify_core.md` exists and already provides the needed status, do NOT open `finding_mapping.md`, raw depth findings, or scanner findings up front. Treat those as fallback-only inputs for missing detail, not default reads.
- If `verify_core.md` is absent, read `verify_*.md` files directly - each contains its own hypothesis ID and verdict header.
- `{SCRATCHPAD}/depth_*_findings.md` (raw depth findings and chain summaries)
- `{SCRATCHPAD}/blind_spot_*_findings.md` or `{SCRATCHPAD}/scanner_*_findings.md` (scanner findings)
- `{SCRATCHPAD}/validation_sweep_findings.md` or `{SCRATCHPAD}/scanner_validation_findings.md` (validation findings)
- `{SCRATCHPAD}/dedup_candidate_pairs.md` (OPTIONAL — pre-computed same-file finding pairs with high title overlap or shared code identifiers, produced by the depth promotion pipeline. Use as HINTS for Step 1.5 consolidation.)
- `{SCRATCHPAD}/dedup_cluster_map.md` (OPTIONAL — pre-computed transitive-closure CLUSTERS of co-referent survivors (`CLUSTER: A, B, C` lines) that share the same file+function+fix-pattern AND the same tier, each with a ready-made consolidated Location table. These are the STRONGEST Step 1.5 hint: consolidate each cluster's members into ONE report finding and reuse its location table. Recall-safe (same-tier, same-mechanism only); still apply the consolidation test before merging.)
- `{SCRATCHPAD}/poc_demotion_proposals.json` and `{SCRATCHPAD}/poc_demotion_proposals.md` (OPTIONAL — non-authoritative negative-review proposals. They MUST NOT lower severity, exclude, refute, merge, or otherwise dispose of a finding.)
- `{SCRATCHPAD}/poc_demotion_scope_receipt.json` and `{SCRATCHPAD}/poc_demotion_scope_recovery_status.json` (OPTIONAL — exact grouped-PoC proposal scope and driver-validated repair state. These are scope/reverification evidence only; every constituent retains its pre-proposal severity.)

Forbidden inputs:
- Do NOT read raw `{SCRATCHPAD}/rag_validation.md`; only the deterministic
  `precedent_report_context.md` projection may supply external-source context.
- Do NOT read `{SCRATCHPAD}/report_index.md`, `{SCRATCHPAD}/report_coverage.md`,
  or any `*.attempt*` file when a retry hint is present. Previous report-index
  outputs are known-bad artifacts, not evidence.
- Do NOT read `_prompt_*`, `_stdio_*`, `tool_calls.jsonl`, `_retry_quarantine/`,
  or `_overflow/`.

Verification verdicts: Read from `{SCRATCHPAD}/verify_core.md` (summary index of
all per-ID verifier results) and individual `{SCRATCHPAD}/verify_*.md` files when
needed. For Thorough mode, also read `{SCRATCHPAD}/skeptic_findings.md` and
`{SCRATCHPAD}/skeptic_judge_decisions.md` when present. If the run produced
legacy shard outputs, also read `{SCRATCHPAD}/judge_*.md`. These are challenge
and presentation inputs only. They are not severity or disposition authority.
Only a report-authoritative, driver-validated typed severity decision ledger may
authorize a tier change; otherwise preserve the upstream supported severity.

## Disposition Authority Contract (READ BEFORE EXCLUDING OR MERGING)

This agent accounts for identities and proposes presentation; it does not
authorize a finding to leave the body. An Excluded Findings, Consolidation Map,
`report_coverage.md`, `REFUTED`, `LOW_CONFIDENCE`, `CONTESTED`, `DUPLICATE`,
`CONSOLIDATED`, `APPENDIX_ONLY`, or `DEFERRED` string is never authority by
itself. Every non-body proposal must cite one exact event for the same identity
and full claim scope:

- an independently executed/refereed typed refutation;
- an independent typed zero-security-consequence decision with no contradicting
  mechanism, impact, or unresolved premise; or
- an already-applied, hash-bound semantic alias naming the delivered survivor.

If that exact authority is missing, stale, mismatched, partial, contested, or
unresolved, assign a body report ID at upstream severity and mark it
`UNRESOLVED-DISPOSITION` for human review. Coverage-only `DEFERRED` is visible
debt, not delivery. The driver enforces this distinction between
`identity_accounted` and `disposition_authorized`; lexical prose can only
propose or veto, never establish a non-body state.

---

## Working-Set Discipline — PROCESS ONE TIER-BATCH PER TURN (MANDATORY)

On a large audit, building the WHOLE Master Finding Index — all-tier STEP 1.5
consolidation plus all-tier STEP 5/5.5 coverage — in a single turn is the
context-collapse trigger that froze this phase for tens of minutes on large
audits. Do NOT hold every finding's working set at once.

The driver pre-partitions the coverage seed into bounded per-tier shards:

- `{SCRATCHPAD}/report_index_seed_critical_high.md` (Critical + High IDs)
- `{SCRATCHPAD}/report_index_seed_medium.md` (Medium IDs)
- `{SCRATCHPAD}/report_index_seed_low_info.md` (Low + Informational IDs)

Process the index **one tier-batch at a time**, in order Critical+High →
Medium → Low+Info. For each tier-batch: read ONLY that tier's seed shard, run
STEP 1.5 (consolidation) + STEP 5/5.5 (coverage) over THOSE IDs only, append
that tier's rows to the Master Finding Index / Excluded Findings /
Consolidation Map / `report_coverage.md`, then move on. Consolidation never
crosses tiers (the consolidation test already requires same-severity tier), so
batching loses nothing.

Every ID in EVERY shard MUST receive exactly one disposition (report ID,
exclusion, or consolidation-absorbed). The union of the three shards equals the
full `{SCRATCHPAD}/report_index_coverage_seed.md`; the driver reconciles the
merged `report_index.md` against the FULL seed afterward, so an ID that falls
between tier-batches is mechanically detected and a retry hint names it. Record
cross-tier chains/cross-references once in the Cross-Reference Map after all
tiers are written.

---

## Severity Authority Contract (READ BEFORE TIERING)

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
   - `POC-FAIL-PROPOSAL(no-tier-change)` only for visible review context
   - `PROVEN(original_sev)` only when `PROVEN_ONLY: true`
   - `CHAIN-UPGRADE(original_sev)` / `CHAIN-DOWNGRADE(original_sev)` with the
     chain ID and enabling relation
   `UNRESOLVED(original_sev)` and `PARTIAL(original_sev)` are visibility
   statuses only and are never reasons for a tier difference.
5. A bare `-` / `—` Trust Adj. is valid only when final severity equals
   upstream severity.
6. If no canonical adjustment applies, restore the upstream severity and
   matching report-ID tier. Do not silently move Medium verified findings into
   Low rows, and do not silently upgrade Informational findings to Low.

## STEP 1: Determine Final Severities

For each hypothesis, apply this priority order:

1. If a verifier returned a verdict -> use verifier's final severity
2. If chain analysis upgraded severity -> use upgraded severity
3. Otherwise -> use the severity from hypotheses.md
4. **Trust claims are not severity authority**: An inventory trust classification is a claim;
   `[ASSUMPTION-DEP: TRUSTED-ACTOR]` tag records a producer claim only. Preserve
   the upstream severity unless the typed severity decision ledger contains an
   independent `FULLY_TRUSTED_ACTOR` modifier for the exact finding/constituents,
   bound to the named actor/capability, an explicit project scope/trust source,
   the concrete action required for harm, and a modifier-applicability evidence
   receipt. A generic admin/governance/multisig label, a semi-trusted role, or
   missing/conflicting evidence never authorizes a downgrade. Render unresolved
   trust context visibly without changing severity. `WITHIN-BOUNDS` remains
   context only. The report index is a projection consumer and cannot invent,
   remove, or override the severity decision ledger.
5. **Proven-only demotion** (ONLY if the resolved configuration says `PROVEN_ONLY: true`): For each finding whose BEST evidence tag is `[CODE-TRACE]` (no `[POC-PASS]`, `[MEDUSA-PASS]`, `[PROD-ONCHAIN]`, `[PROD-SOURCE]`, or `[PROD-FORK]`), cap severity at Low. Record the original severity in the "Trust Adj." column as `PROVEN(original_sev)`. Count total demotions for the report header note: *"Proven-only mode enabled: {N} findings capped at Low from {severities} due to unproven evidence ([CODE-TRACE] only)."* If `PROVEN_ONLY: false`, this rule is disabled and `[CODE-TRACE]` does not change severity.

   **v2.0.8 (P3) — evidence source authority**: "BEST evidence tag" means the value from `{SCRATCHPAD}/verdict_manifest.json` `effective_tag` field, NOT the verifier's prose `Evidence Tag` field. The verdict manifest is the canonical machine-readable record written by the driver after mechanical PoC execution. A verifier file that prose-claims `[POC-PASS]` but whose mechanical execution returned `NO_TEST_FILE` / `FAIL` is flagged `integrity_state: INFLATED_PROSE` and has `effective_tag` downgraded to `[CODE-TRACE] [INTEGRITY-DOWNGRADE]`. Use the effective_tag in all evidence-comparison logic. Do NOT inflate findings back to `[POC-PASS]` based on prose alone.
6. **UNRESOLVED visibility + body retention**: `UNRESOLVED` and `PARTIAL`
   are evidence/disagreement states, not severity discounts. Preserve the
   highest still-supported upstream Impact x Likelihood tier unless the shared
   typed severity ledger contains a distinct-worker, premise/evidence-bound,
   report-authoritative decision for the exact identity/constituents. Record
   `UNRESOLVED(original_sev)` in Trust Adj. as a visibility status without
   changing severity. The finding remains in the report body and the tier
   writer flags `[UNRESOLVED - needs human review]`. Adjudicator failure or
   missing evidence retains this same upstream tier and body placement.

   **CONTESTED is not UNRESOLVED.** Keep its upstream severity and body status.
   An `UNRESOLVED(original_sev)` marker requires a literal challenge proposal
   or typed unresolved decision for the exact identity. It never authorizes a
   demotion. If no skeptic/adjudication artifact exists, do not invent the
   marker.
7. **PoC-fail proposal boundary**: If `{SCRATCHPAD}/poc_demotion_proposals.json` exists, keep every listed finding at its highest supported pre-proposal severity and in the report body. A failed/non-established execution describes the encoded attempt; it MUST NOT lower severity, exclude, refute, merge, or close the candidate. Record `POC-FAIL-PROPOSAL(no-tier-change)` only as visible review context. Grouped scope rows identify the exact constituents needing review; a missing/invalid/unresolved recovery status preserves all of them. `P0-O REVERIFIED SUPPLEMENT` is additive evidence, never negative lifecycle authority.

8. **Speculative-Critical cap (T2-c)** : `Critical` is the highest-impact tier and must not be assigned to unproven speculation. A `Critical` severity assigned to a **chain / compound hypothesis** (`CH-*`, or any finding whose claimed impact depends on combining multiple sub-findings that are not each independently confirmed) MUST be capped at `High` UNLESS the chain itself has verifier confirmation — i.e. a `verify_*.md` for the chain (or all its constituents) with `[POC-PASS]` / `[MEDUSA-PASS]` evidence and a `VERIFIED` disposition. An unverified speculative chain is `High` at most. Critical requires EITHER (a) verifier-confirmed exploitation, OR (b) a single, directly-demonstrated fund-loss / permanent-lock mechanism in one finding. When you apply this cap, record `CHAIN-DOWNGRADE(Critical)` in the Trust Adj. column with the chain ID. The driver logs any surviving unverified Critical chain for review. **When the cap does NOT apply because all constituents are independently confirmed (`[POC-PASS]`/`[MEDUSA-PASS]` in each constituent `verify_*.md`), keep the `Critical` severity and set the Verification column to `VERIFIED (constituents)` — do NOT leave it as `UNVERIFIED`, which mislabels a constituent-backed chain as speculative and trips the driver's review log.**

---

## STEP 1.25: Client-Worthiness Triage (CONSERVATIVE)

This step reduces client-report bloat without deleting traceability. It is a
triage decision for presentation, not a new vulnerability-analysis phase.

For each verified or mapped candidate, propose exactly one triage status. Only
the authority contract above can make a non-body proposal effective:

- `REPORTABLE`: client-facing report body section.
- `MERGE_INTO:<report-or-internal-id>`: same root cause, same fix, no semantic
  loss; preserve source ID in the Consolidation Map.
- `APPENDIX_ONLY`: true or plausible observation, but not client-body material.
- `DROP_FALSE_POSITIVE`: verifier explicitly refuted the claim or showed the
  claimed harm cannot occur.
- `DROP_NON_SECURITY`: behavior is not a security issue and has no plausible
  loss, privilege, liveness, accounting, integrity, or observability impact.
- `DROP_DESIGN_CONFIRMATION`: the item only confirms expected behavior or an
  intentionally safe design property.
- `DROP_UNACTIONABLE_SPECULATION`: speculative claim with no reachable path,
  no concrete impacted actor, and no actionable fix after verification.
- `UNRESOLVED_EVIDENCE`: contested or low-confidence candidate with no
  reproducible code path, no trace, or insufficient evidence after the prior
  analysis/verification phases.

Safety rules:

1. Never silently delete a candidate. Non-`REPORTABLE` candidates MUST appear in
   `report_coverage.md` and either the Consolidation Map or Excluded Findings.
2. Every severity defaults to `REPORTABLE`. A non-body proposal is effective
   only with the exact independent typed full-claim decision or applied-alias
   event defined above. Verifier/judge/report prose and low confidence are not
   substitutes for that event.
3. Low/Informational candidates may be proposed `APPENDIX_ONLY` only when an
   independent typed material-harm decision concludes zero security consequence
   and no mechanism/impact/premise record contradicts it. Unsupported
   High/Medium quality labels remain body findings at upstream severity.
4. Design confirmations, positive properties, safe invariants, and
   "works as intended" rows are not report-body findings. Use
   `DROP_DESIGN_CONFIRMATION` unless they are needed as context for a real
   reportable issue.
5. Do not use triage to hide uncertainty. `PARTIAL`, `CONTESTED`, `UNRESOLVED`,
   missing proof, and external-premise uncertainty remain `REPORTABLE` at the
   upstream severity with a visible human-review marker unless an exact later
   full-claim decision resolves them.
6. A report that is structurally complete but contains dozens of weak,
   repetitive, design-confirmation, or non-security body sections is a quality
   failure. Prefer a smaller client body plus complete traceability.
7. **Stub findings (T2-c)**: A candidate that names neither a concrete
   vulnerability MECHANISM (how the bug is triggered — the specific call,
   state, or sequence) NOR a concrete IMPACT (what is lost, corrupted, or
   locked, and who is harmed) is a stub. Assign it
   `DROP_UNACTIONABLE_SPECULATION` only as a proposal. Without an exact typed
   full-claim zero-harm/refutation decision, retain it in the body or the
   hash-bound delivered-human-review projection as unresolved debt.

Use the existing `Excluded Findings` table to record authorized `APPENDIX_ONLY`
and `DROP_*` outcomes. The Exclusion Reason MUST begin with the exact triage
status token, cite the structured authority event ID, and name the surviving
report ID for an alias. A prose-only row will be rejected and restored to body.

---

## STEP 1.5: Root-Cause Consolidation (MANDATORY)

Before assigning report IDs, consolidate hypotheses that share the same root cause into single report findings. This prevents inflated finding counts from pipeline fragmentation.

**This step is MANDATORY and is routinely under-applied.** Pipeline fragmentation typically produces 2-4 separate hypotheses per real root cause (a breadth finding, its depth re-discovery, a scanner hit, a per-contract hit). If you emit roughly as many report findings as there are raw inventory entries, you almost certainly skipped consolidation. Actively scan for the common patterns in the table below and merge aggressively where the consolidation test passes — a de-inflated report of real findings is the goal.

### Pre-computed Hints

Three sources of dedup signals exist. All are HINTS — the LLM makes the final semantic decision using the consolidation test below. No source ever blocks or removes findings mechanically.

1. **`[LIKELY-DUP]` tags in `findings_inventory.md`**: Depth-promoted findings that share the same file AND >=80% title overlap with an existing inventory entry carry a `**Dedup Signal**: [LIKELY-DUP of "..." score=X.XX]` line. These are the strongest mechanical signal — evaluate them first. If the two findings describe the SAME root cause with the SAME fix, consolidate. If they describe different bugs that happen to use similar words, keep them separate.

2. **`dedup_cluster_map.md`**: Pre-computed transitive-closure CLUSTERS (each a `CLUSTER: A, B, C` line under a `## Cluster CL-n` heading) of co-referent survivors that ALREADY passed the pairwise consolidation predicate at the SAME code site (file+function), SAME root-cause/fix-pattern, AND SAME tier — the exact fragmentation that pairwise dedup cannot collapse on its own. For each cluster, consolidate ALL its members into ONE report finding and reuse the ready-made **Consolidated Location table** verbatim as that finding's Location. This is the highest-value Step 1.5 input; still confirm the consolidation test below before merging (the cluster is same-tier and same-mechanism by construction, so it should pass).

3. **`dedup_candidate_pairs.md`**: Pre-computed same-file finding pairs with >=50% title overlap or shared function/struct identifiers. Broader than the cluster map — evaluate each pair using the consolidation test below.

**When in doubt, do NOT merge.** A duplicate finding in the report is a cosmetic issue. A dropped true positive is a missed vulnerability.

### Semantic Retention Rule

During consolidation, preserve the semantic content already established upstream. For each candidate, carry forward the broken invariant, branch preconditions, terminal failure mechanism, verification disposition, and source IDs when those details are present in the bounded inputs (`verify_core.md`, `verify_*.md`, `finding_mapping.md`, `findings_inventory.md`, and the dedup hints). This is retention, not rediscovery: do not perform fresh vulnerability analysis, and do not bulk-read raw breadth/depth/scanner artifacts by default. If a single candidate is missing detail needed to avoid dropping semantics, read only the minimal fallback source for that candidate.

### Consolidation Test

Merge two hypotheses into ONE report finding if ALL of these are true:
1. **Same fix pattern**: Both require the same TYPE of code change
2. **Same severity tier**: Both are in the same tier after STEP 1 adjustments
3. **Same vulnerability class**: Both are instances of the same bug pattern
4. **Describable together**: A reader can understand all affected locations from a single description + location table
5. **No semantic loss**: The merged finding can preserve every distinct broken invariant, branch precondition, terminal failure mechanism, verification disposition, and source ID in its title/description, locations, Consolidation Reason, or coverage ledger
6. **Obligation retention**: If `obligation_ledger.json` contains an active Medium+ obligation for either source, the merged finding must preserve that obligation ID or exact field/chain relationship in the Consolidation Map or `report_coverage.md`. Similar-topic coverage is not enough for exact value-binding obligations.

### Do NOT Merge If

- Findings are in different severity tiers
- The root causes are genuinely different (e.g., "missing event" vs "wrong event parameters")
- **Same location, DIFFERENT mechanism is NOT a duplicate.** Two findings at the same
  file/function but with different root-cause mechanisms (e.g. an assembly decoder that
  reads a field at the WRONG WIDTH/corrupts valid input vs the SAME decoder reading
  OUT-OF-BOUNDS on short input; or a wrong-binding bug vs a missing-check bug) require
  DIFFERENT fixes and MUST stay separate. Do not normalize the less-obvious mechanism
  into the more-obvious adjacent one — that silently drops a true positive.
- Merging would exceed 6 locations per finding (split into 2 findings for readability)
- Merging would drop, blur, or overwrite a distinct branch precondition or terminal failure mechanism. If two candidates fail through different branches or end in different mechanisms, keep them separate unless the shared report finding can state both without ambiguity.

### Common Consolidation Patterns

| Pattern | Example Hypotheses | Consolidated Title |
|---------|-------------------|-------------------|
| Missing events on state changes | "setX no event" + "setY no event" + "setZ no event" | "Missing event emission on admin state changes" |
| Admin setters accept zero/invalid | "paramA accepts zero" + "paramB accepts zero" | "Admin setters lack zero-value validation" |
| Missing staleness checks | "no staleness on X" + "no max staleness on Y" | "Rate provider staleness not validated" |
| Retroactive parameter changes | "paramA retroactive" + "paramB retroactive" | "Global parameter changes retroactively affect pending state" |
| Same-role trust findings | "ROLE can do X" + "ROLE can do Y" (same role, same trust level) | "ROLE capabilities exceed stated trust level" |
| Same missing-guard across entry points | "fn A permissionless" + "fn B permissionless via same missing check" (one absent access/precondition guard reached through several functions) | "Missing access/precondition guard exposes <asset/action> across multiple entry points" |
| Same primitive abused several ways | "collision via path X" + "collision via path Y" (one underlying primitive: predictable id, unchecked write, missing CEI) reached through different call paths | "<primitive> enables <impact> via multiple paths" |

Note: the merge is gated by the Consolidation Test (same fix, same tier, same class, no semantic loss) — distinct branches/mechanisms still stay separate. These two rows target the common fragmentation where ONE root cause (a single absent guard, or a single abused primitive) is reported as many findings; merge them only when a single fix at the root would resolve all listed locations.

### Output

For each consolidation, record:
```
CONSOLIDATED: H-{A} + H-{B} [+ H-{C}...] -> single finding
  Title: {consolidated title}
  Locations: {list all affected locations}
  Severity: {shared severity}
  Internal refs: {all absorbed hypothesis IDs}
```

In the `Consolidation Reason` free-text field, include the shared root cause and fix pattern, plus any preserved semantic distinctions that matter for downstream writing: broken invariant, branch precondition, terminal mechanism, verification disposition, and source IDs. Do not add columns to the Master Finding Index.

Hypotheses NOT consolidated remain as standalone findings.

---

## STEP 2: Assign Report IDs

Sort all findings (consolidated and standalone) by severity tier, then by verification status (VERIFIED first), then by impact.

Assign clean sequential IDs:
- Critical: C-01, C-02, ...
- High: H-01, H-02, ...
- Medium: M-01, M-02, ...
- Low: L-01, L-02, ...
- Informational: I-01, I-02, ...

---

## STEP 3: Create Tier Assignments

Assign each finding to exactly ONE tier writer:
- **Critical+High Tier**: All C-XX and H-XX findings
- **Medium Tier**: All M-XX findings
- **Low+Info Tier**: All L-XX and I-XX findings

---

## STEP 4: Create Cross-Reference Map

For chain findings that reference component findings, note the cross-references using REPORT IDs only.
Example: If chain hypothesis CH-1 (now C-01) references standalone hypothesis H-5 (now H-03), record: 'C-01 references H-03'

---

## STEP 5: Verify Completeness (MANDATORY)

Enumerate the per-tier ID set from the tier seed shards
(`report_index_seed_critical_high.md`, `report_index_seed_medium.md`,
`report_index_seed_low_info.md`) — one shard per tier-batch — whose union is the
full `report_index_coverage_seed.md`. When the shards are absent, fall back to
the full `report_index_coverage_seed.md`; when that too is absent, derive the ID
set from `verification_queue.md` + `verify_core.md` + `finding_mapping.md`. Do
NOT bulk-read `hypotheses.md` or `findings_inventory.md` to re-derive the ID set
— those are 100K+ of finding prose and pulling them into one turn is the
context-collapse trigger this phase's scope prevents.

Cross-check: For EVERY ID in that bounded set (covering every hypothesis and
every standalone finding [VS-*], [BLIND-*], [SE-*], [EN-*], [SLITHER-*]):
- Is it assigned a report ID in the Master Finding Index above?
- If NO and NOT marked FALSE_POSITIVE by a verifier -> ASSIGN a report ID and tier

**HARD RULE**: The ONLY valid exclusion reasons are the conservative triage
statuses from Step 1.25, an explicit false-positive/refuted verifier verdict,
or an explicit duplicate/merge already listed with the absorbing report ID.
"Not grouped into a hypothesis" is NOT a valid exclusion reason.

---

## STEP 5.5: Promotion Coverage Audit (MANDATORY)

Before finalizing the index, produce an accounting receipt in
`report_coverage.md`. Keep this bounded: use `verification_queue.md`,
`verify_core.md`, `finding_mapping.md`, and the final Master Finding Index as
the coverage sources. Also read `candidate_semantic_facets.md` when present;
it is a compact driver-extracted preservation ledger, not a raw analysis
artifact. Do NOT bulk-read raw breadth/depth/scanner artifacts in this phase.
Raw promotion checks are enforced mechanically by the Python gate; the indexer
owns the reportable verification-to-report mapping.

Coverage reasoning must preserve upstream semantics, not re-derive them. For each candidate, keep the broken invariant, branch precondition, terminal failure mechanism, verification disposition, and source IDs visible in the existing `Report ID / Refutation / Reason` free-text field when those details affect whether the candidate is promoted, duplicated, false-positive, or deferred. If a candidate is marked `DUPLICATE`, the reason must make clear that no distinct branch precondition or terminal mechanism was dropped; otherwise assign it a separate report ID or mark it with the correct non-duplicate status.

If `obligation_ledger.json` exists, include coverage rows for active Medium+ obligations:
- `exact_value_binding`: preserve the exact `field_a <-> field_b` relationship in the report row/reason, or cite an absorbing report ID that names both fields and the relationship.
- `chain_upgrade_retention`: preserve the `CH-*` chain/composition impact in a report heading, a Chain Impact subsection, or an absorbing report ID.
- Do not close an obligation with `MERGED`, `DUPLICATE`, or `APPENDIX_ONLY` unless the absorbing report ID is named and the retained reason states the exact relationship or chain impact being preserved.

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

### HARD RULES

1. A Medium+ candidate from verification_queue/finding_mapping MUST NOT disappear silently.
2. If a Medium+ candidate is not promoted, the ledger must name the absorbing report ID or the exact verifier/judge evidence supporting the non-body triage status.
3. If recon recommends a niche lane (for example `EVENT_COMPLETENESS`) and that lane did not run in the current mode, record the uncovered recommendation in the ledger as `DEFERRED: mode-limited`.
4. If a candidate appears in verification_queue/verify_core but not in
   `finding_mapping.md`, treat that as a promotion failure and either assign it
   a report ID or explicitly mark it duplicate / false positive / deferred with
   reasoning.
5. Do not use `DUPLICATE`, `MERGED`, `APPENDIX_ONLY`, or any `DROP_*` status as a convenience status when the candidate carries a distinct broken invariant, branch precondition, terminal mechanism, verification disposition, or source ID that is not retained by the absorbing report ID and ledger reason.
6. In Thorough mode, do NOT use `DEFERRED: mode-limited` for Medium+ candidates.
   Thorough runs the full methodology; a Medium+ non-body decision needs a real
   verifier/judge/refutation reason or an absorbing report ID.

---

## Output Format

Write to `{SCRATCHPAD}/report_index.md`:

```markdown
# Report Index

## Report Header Info
- Project Name: {from design_context.md or threat_model.md}
- Date: {today}
- Components: {from contract_inventory.md or subsystem_map.md}
- Build / Bake Status: {from build_status.md or primitive_status.md}

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
| C-01 | [title] | Critical | [location] | VERIFIED | - | H-1 |
| H-01 | [title] | High | [location] | VERIFIED | - | H-2 |
| M-01 | [title] | Medium | [location] | UNVERIFIED | TRUSTED-ACTOR(High) | H-18 |
| ... | ... | ... | ... | ... | ... | ... |

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

## Cross-Reference Map
| Report ID | References | Context |
|-----------|-----------|---------|
| C-01 | H-03, M-05 | Chain: C-01 combines the bugs described in H-03 and M-05 |

## Excluded Findings (for Appendix A)
| Internal ID | Severity | Title | Exclusion Reason (APPENDIX_ONLY / DROP_* / FALSE_POSITIVE / DUPLICATE OF X-NN / MERGE_INTO X-NN only) |
```

### CRITICAL FORMAT RULES for Master Finding Index

1. **Internal Hypothesis column MUST be the LAST column** — the downstream validator extracts the last matching ID per row.
2. **Do NOT include an Agent Sources column.** Agent source traceability belongs in `report_coverage.md`, not in the client-facing report.
3. **No parenthetical constituent IDs** — write `CH-3` or `H-2+H-13`, NOT `CH-3 (H-2, H-13)`.
4. **Consolidated rows may use `+`-joined IDs** — if one report finding intentionally absorbs multiple verified hypotheses, write the Internal Hypothesis cell as `H-2+H-13` and also list the same IDs in the Consolidation Map. Do not use comma prose or parentheticals. If a chain has its own verifier file (`verify_CH-3.md`), use `CH-3`; if only constituent verifier files exist, use the `+`-joined constituent IDs so downstream body writers can read every evidence file.
5. **Section headings must be EXACT** — use `## Master Finding Index` and `## Excluded Findings` exactly. Do NOT append suffixes.

---

## Also Write: Report Coverage Audit

Write to `{SCRATCHPAD}/report_coverage.md`:

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

---

## Terminal Stop Rule

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

---

## Step 6a.1: Completeness Verification (Orchestrator Inline)

After Index Agent returns, orchestrator performs this mechanical check:

1. Count hypothesis IDs in `{SCRATCHPAD}/hypotheses.md` (grep for `| H-`)
2. Count report IDs in `{SCRATCHPAD}/report_index.md` Master Finding Index
3. Count excluded IDs in `{SCRATCHPAD}/report_index.md` Excluded Findings
4. Count consolidated IDs (hypotheses absorbed into another report finding via STEP 1.5)
5. **ASSERT**: `hypothesis_count == report_ids + excluded_count + consolidated_absorbed_count`
6. If **MISMATCH**:
   - Diff ID sets to find missing hypotheses
   - Log: `"INDEX COMPLETENESS FAILURE: {missing_list}"`
   - Re-spawn Index Agent with: `"Assign report IDs to these missing hypotheses: {list}"`
   - Re-run this verification after re-spawn

Then verify `{SCRATCHPAD}/report_coverage.md` exists and has at least one ledger row for every depth/scanner artifact present in the scratchpad.

---

SCOPE: Write ONLY to `{SCRATCHPAD}/report_index.md` and `{SCRATCHPAD}/report_coverage.md`. Do NOT read or write tier report files. Do NOT proceed to tier writing, assembly, or any subsequent pipeline phase. Return and stop.
