# Inventory Agent Base Methodology

> **This file defines**: What the inventory agent does, how it assigns
> IDs, dedup rules, required fields, trust-assumption tagging, and the
> LIKELY-DUP signal format.

---

## 1. Purpose

The inventory agent merges discovery-phase output files into a
consolidated `findings_inventory.md`. This is the canonical finding
registry. No finding enters the audit pipeline without passing through
inventory.

Input files vary by pipeline:
- **SC**: `analysis_*.md` files, plus `analysis_rescan_*.md` and
  `analysis_percontract_*.md` when present.
- **L1**: `analysis_*.md` files, plus `graph_sweep_summary.md`,
  `coverage_fill_*.md`, `panic_audit_*.md`, `panic_audit_summary.md`,
  `symmetric_pair_findings.md`, and graph-sweep matrices/findings when
  present.

---

## 2. ID Format Rules

### Primary Inventory IDs

After deduplication, assign clean sequential IDs to each unique finding:

| Pipeline | ID Format | Example |
|----------|-----------|---------|
| SC | Preserves source agent prefixes in detail, assigns sequential `#` in the master table | `[CS-1]`, `[AC-2]`, `[TF-3]`, `[SE-1]`, `[SLITHER-1]` |
| L1 | `[F-N]` (sequential) | `[F-1]`, `[F-2]`, `[F-37]` |

**SC detail**: The SC inventory preserves the original agent-assigned IDs
(e.g., `[CS-1]` from core-state agent, `[AC-2]` from access-control
agent). The master table uses a `#` column for row numbering but
`Finding ID` remains the source ID.

**L1 detail**: The L1 inventory assigns new sequential `[F-N]` IDs and
records original source IDs (`[CI-3]`, `[NS-1]`, etc.) in a separate
`Original IDs` field.

### Chunk / Merge IDs (SC only)

When the inventory merge agent appends findings from rescan or
per-contract passes, it uses the source agent's ID format:
- Rescan findings: `[RS{N}-M]` (e.g., `[RS1-2]`)
- Per-contract findings: `[PC{N}-M]` (e.g., `[PC3-1]`)
- Side effect findings: `[SE-N]`
- Slither promoted findings: `[SLITHER-N]`

---

## 3. Required Fields Per Finding

Every finding in `findings_inventory.md` MUST contain these fields:

| Field | Required | Description |
|-------|----------|-------------|
| Finding ID | YES | Unique identifier per ID format rules above |
| Title | YES | Concise vulnerability description |
| Severity | YES | Critical / High / Medium / Low / Informational |
| Verdict | YES | CONFIRMED / PARTIAL / REFUTED / CONTESTED |
| Location | YES | `file:line` or `file:L{start}-L{end}` |
| Source IDs | YES | Which agent(s) reported this finding |
| Root Cause (1-line) | YES | One sentence describing the underlying bug mechanism |
| Preferred Tag | YES | Best evidence tag: `[CODE]`, `[PROD-ONCHAIN]`, `[MEDUSA-PASS]`, etc. |

### Additional fields by pipeline

**SC-specific** (when available):
- Step Execution
- Rules Applied
- Precedent Context (`UNSCORED` only; never numeric and never decision authority)
- Precondition Type / Postcondition Type (for chain summary)

**L1-specific**:
- Subsystem (consensus / network / mempool / rpc / state / da / execution / external / other)
- Trust Boundary (p2p peer / rpc caller / validator / producer / operator / n/a)
- Convergent (Yes/No — reported by 2+ independent agents)
- Depth Evidence Tags (union of `[BOUNDARY:...]`, `[TRACE:...]`, etc.)

---

## 4. Deduplication Methodology

### Dedup Key

Two findings are duplicates if BOTH conditions are true:

1. **Same location**: They reference the same `file:line` or overlapping
   line ranges (within +/-5 lines).
2. **Same root cause mechanism**: They describe the same underlying bug
   -- not just the same symptom, same title, or same code area. Two
   findings at the same line with DIFFERENT root causes are NOT
   duplicates.

### Merge Rules (when duplicates are found)

- **Severity**: Take the HIGHEST severity across the merged set.
- **Verdict**: Take the STRONGEST in this order:
  `CONFIRMED > PARTIAL > CONTESTED > REFUTED`.
- **Source**: Record ALL source agents that reported it.
- **Evidence tags**: Union all depth evidence tags (no duplicates within
  the union).
- **Description/Impact/Evidence**: Preserve the most detailed block.
  When in doubt, concatenate under sub-headings rather than paraphrase.

### What is NOT a duplicate

- Same vulnerability CLASS at different locations (e.g., two missing
  validation checks in two different functions) -- these are separate
  findings.
- Same location but different exploit mechanisms -- separate findings.
- Findings that require DIFFERENT fixes -- separate findings.

---

## 5. Trust-Assumption Tagging

After building the inventory, cross-reference each finding against the
Trust Assumption Table from `design_context.md`.

### Tagging Rules

| Condition | Tag | Severity Effect |
|-----------|-----|----------------|
| Attack may require an explicitly fully-trusted actor to violate a project-stated assumption | `[ASSUMPTION-DEP: TRUSTED-ACTOR]` | Advisory claim; independent evidence-bound adjudication required |
| Attack requires `SEMI_TRUSTED` actor to act maliciously | No tag | No change -- Likelihood axis handles this |
| Attack requires `SEMI_TRUSTED` actor to act WITHIN stated bounds | `[ASSUMPTION-DEP: WITHIN-BOUNDS]` | Flag only -- no severity change |
| Attack requires `SEMI_TRUSTED` actor to EXCEED stated bounds | No tag | Real finding -- no change |
| Attack requires `UNTRUSTED` actor or exploits `PRECONDITION` violation | No tag | Real finding -- no change |

### Hard Rules

- `TRUSTED-ACTOR` is a producer claim only and is ONLY eligible for explicitly
  scoped `FULLY_TRUSTED` actors. Record the exact actor/capability and source.
  NEVER tag `SEMI_TRUSTED` actors, and never apply a severity change here.
- Only tag if the finding's ENTIRE attack path depends on the
  assumption. If BOTH a trusted-actor path AND an untrusted-actor path
  exist, do NOT tag.
- `WITHIN-BOUNDS` means the attack's impact does not exceed what the
  stated bounds already allow. If impact goes BEYOND stated bounds, do
  NOT tag (real bug).
- When uncertain whether impact exceeds bounds, do NOT tag. Err on the
  side of preserving severity.

### Output Format

Append this table to the inventory output file assigned by the current phase:

```markdown
## Assumption Dependency Audit
| Finding ID | Attack Actor | Actor Trust Level | Within Bounds? | Tag | Original Severity |
|------------|-------------|-------------------|---------------|-----|-------------------|
```

---

## 6. LIKELY-DUP Signal Format

The Python driver pre-computes deduplication signals for findings that
share the same file AND have high title overlap or overlapping line
ranges with existing inventory entries. These signals are injected
inline into each finding's detail block as a `**Dedup Signal**` line.

### Signal Format

```markdown
**Dedup Signal**: [LIKELY-DUP of "Original Finding Title" score=0.85]
**Dedup Signal**: [LIKELY-DUP of "Original Finding Title" location overlap L40-40 vs L42-65]
```

### Signal Thresholds (computed by driver)

| Condition | Threshold | Blocked? |
|-----------|-----------|----------|
| Title overlap >= 90% (any file) | Hard signal | YES -- finding blocked from promotion |
| Location overlap AND title overlap >= 50% | Hard signal | YES -- finding blocked from promotion |
| Title overlap >= 80% OR location overlap (without 50% title) | Soft signal | NO -- tagged but still promoted |

### Downstream Consumption

LIKELY-DUP tags are advisory hints. Their consumers evaluate each tagged pair
using a same-fix-pattern test before merging. The tag never blocks or removes
a finding mechanically -- it surfaces a candidate for review.

### Invariant

A `[LIKELY-DUP]` tag is a HINT, not a mandate. Two findings with a
LIKELY-DUP tag that describe genuinely different bugs (different root
cause, different fix) MUST remain separate. When in doubt, do NOT
merge -- a duplicate finding in the report is a cosmetic issue; a
dropped true positive is a missed vulnerability.

---

## 7. Output Structure

The inventory agent writes to the output file assigned by the current phase.
The exact sections vary by pipeline and producer role but always include:

### Required Sections (all pipelines)

1. **Source Summary**: Table of input files read, finding counts per
   source, pre-dedup and post-dedup totals. This is a mechanical receipt:
   every discovery source file read must have exactly one row, and the sum of
   source finding counts must reconcile with the per-finding detail blocks
   after documented deduplication. Do not report a self-consistent subset.
2. **Master Table**: One row per deduplicated finding with all required
   fields.
3. **Per-Finding Detail**: Full finding blocks preserving Description,
   Impact, Evidence verbatim from source (no paraphrasing).

### SC-Specific Sections

- Chain Summary (precondition/postcondition types for downstream chain matching)
- REFUTED Findings
- CONTESTED Findings
- Incomplete Analysis Flags (step execution gaps)
- Rule Application Violations
- Assumption Dependency Audit
- Side Effect Trace Audit (when applicable)
- Elevated Signal Audit (when applicable)

### L1-Specific Sections

- Convergent Findings (High-Signal) -- reported by 2+ agents

---

## 8. Scope Containment

The inventory agent MUST:
- Write ONLY to its assigned output files
- MAY read discovery producer outputs (`analysis_*.md`,
  `analysis_rescan_*.md`, `analysis_percontract_*.md`, and pipeline-specific
  graph/panic/coverage producer files) as read-only inputs
- NOT modify other agents' output files
- NOT spawn sub-agents
- Return a one-line summary and stop

---

## 9. Preservation Rule

Do NOT paraphrase, summarize, or shorten the Location, Description,
Evidence, or Impact blocks from source findings. Copy them verbatim.
The only content the inventory agent synthesizes is:
- Root Cause (1-liner)
- Trust-assumption tags
- Dedup decisions
- Coverage/gap annotations
