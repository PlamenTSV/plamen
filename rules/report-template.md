# Report Template

> **CRITICAL**: The final audit report MUST be written to `AUDIT_REPORT.md` in the project root.
> **This is the LAST step.** If writing before verification is complete, STOP and go back.

---

## ID System - MANDATORY

The report uses **clean sequential severity-prefixed IDs only**:
- Critical: `C-01`, `C-02`, ...
- High: `H-01`, `H-02`, ...
- Medium: `M-01`, `M-02`, ...
- Low: `L-01`, `L-02`, ...
- Informational: `I-01`, `I-02`, ...

**HARD RULES**:
1. **NO internal pipeline IDs** appear anywhere in the client-facing report. This means NO hypothesis IDs (H-1 from hypotheses.md), NO chain IDs (CH-1), NO agent finding IDs (CS-1, AC-2, TF-4, BLIND-3, EN-1, SE-1, VS-1, DEPTH-X-N, SLITHER-N), and NO mapping references. These are internal audit infrastructure - the reader has never seen them.
2. Cross-references between findings use ONLY report IDs (e.g., "see C-01" or "related to H-03").
3. Each severity tier numbers independently starting from 01.
4. The Index Agent (Step 6a) assigns these IDs. Tier writers and assembler use them as-is.

---

## Severity Matrix (Impact × Likelihood)

| | **Likelihood: High** (no prerequisites, anyone) | **Likelihood: Medium** (specific conditions) | **Likelihood: Low** (unlikely/complex setup) |
|---|---|---|---|
| **Impact: High** (direct fund loss/permanent lock) | **Critical** | **High** | **Medium** |
| **Impact: Medium** (conditional fund loss, protocol breakage) | **High** | **Medium** | **Medium** |
| **Impact: Low** (broken views, incorrect data, non-fund) | **Medium** | **Low** | **Low** |
| **Impact: Informational** (quality, style, unused code) | **Informational** | **Informational** | **Informational** |

**Downgrade modifiers** (applied after matrix lookup):
- On-chain-only exploit (no UI/off-chain path) → −1 tier. NOTE: this applies ONLY when the impact is confined to on-chain state. If the impact crosses the on-chain/off-chain boundary (e.g., corrupted events affecting indexers, frontends, or monitoring systems), do NOT downgrade.
- View-function-only impact → cap at Medium
- Attack path requires fully-trusted actor (per project's stated trust assumptions) to act maliciously → −1 tier (floor: Informational). This applies ONLY to `FULLY_TRUSTED` actors (governance multisig, DAO, timelock). Semi-trusted actors (admin, operator, keeper, oracle) are NOT downgraded here - their likelihood is already captured by the matrix ("specific conditions" or "unlikely/complex setup"). Finding is still reported with a note: *"Severity adjusted - attack requires {actor} to violate stated trust assumption: {assumption}."*

---

## Root-Cause Consolidation Rule

Findings that share the same root cause MUST be consolidated into a single finding. Same **variable** does not mean same root cause - if findings require **different fixes**, they are separate root causes.
- Use the **highest severity** from the matrix across all sub-impacts
- List each sub-impact as a bullet under **Impact**
- The **Location** field lists all affected sites
- Example: "Missing validation in `setFee()`" causing both overpayment and broken accounting → one finding, list both impacts

**Consolidated findings**: When the Index Agent merges multiple hypotheses into one report finding (same fix pattern + same severity + same vulnerability class), the tier writer MUST:
- Use a class-level title (e.g., "Missing event emission on admin state changes"), not a single-location title
- List ALL affected locations in a table under **Location**:
  ```
  | Contract | Function | Line | Issue |
  |----------|----------|------|-------|
  ```
- Provide ONE consolidated recommendation covering all locations
- Reference the Consolidation Map in report_index.md for the internal hypothesis list

---

## Finding Section Format - MANDATORY FOR EVERY FINDING

**Every finding gets its own full section.** No catch-all tables, no grouped summaries, no "remaining findings" dumps. A finding that only appears in a table row is effectively invisible to the reader.

```markdown
### [X-NN] Title [VERIFIED/UNVERIFIED/CONTESTED]

**Severity**: Critical/High/Medium/Low/Informational
**Location**: `SourceFile:L123-L145`
**Confidence**: HIGH/MEDIUM/LOW (N agents confirmed, Static Analysis: Y/N, PoC: PASS/FAIL/SKIPPED)

**Description**:
[Clear explanation of what's wrong. Include relevant code snippet. Do NOT reference any internal audit IDs - describe the bug directly.]

**Impact**:
[What can happen. Quantify where possible. If multiple sub-impacts from root-cause consolidation, list each as a bullet.]

**PoC Result**:
[Test output summary, or "Verification skipped - no build environment"]

**Recommendation**:
[How to fix. Include code snippet where helpful.]
```

**Rules for descriptions**:
- Write as if the reader has never seen the audit pipeline. No "as identified by the breadth agent" or "this chain combines H-1 with H-3."
- For chain findings (multiple bugs combining): describe the full attack sequence from start to finish in the Description. The reader should understand the complete attack path without needing to read other findings.
- Reference OTHER report findings by their report ID only: "This finding is exacerbated when combined with H-03 (example title)."
- Code snippets: include the actual problematic code, not just a line reference.

---

## Report Structure

```markdown
# Security Audit Report - [Project Name]

**Date**: [YYYY-MM-DD]
**Auditor**: Automated Security Analysis (Claude Opus 4.6)
**Scope**: [description]
**Language/Version**: [language and version]
**Build Status**: [Compiled successfully / Failed - reason]
**Static Analysis Status**: [Available / Unavailable - reason]

---

## Executive Summary

[2-3 paragraph overview: what the protocol does, what was found at a high level, and the most critical risks. Written for a non-technical stakeholder.]

## Summary

| Severity | Count |
|----------|-------|
| Critical | [count] |
| High | [count] |
| Medium | [count] |
| Low | [count] |
| Informational | [count] |

### Components Audited

| Component | Path | Lines | Description |
|----------|------|-------|-------------|

---

## Critical Findings

### [C-01] Title [VERIFIED]
[Full finding section per format above]

### [C-02] Title [VERIFIED]
[Full finding section]

---

## High Findings

### [H-01] Title [VERIFIED/UNVERIFIED/CONTESTED]
[Full finding section]

### [H-02] Title [VERIFIED/UNVERIFIED/CONTESTED]
[Full finding section]

[... every High finding gets its own section ...]

---

## Medium Findings

### [M-01] Title [VERIFIED/FALSE_POSITIVE/CONTESTED]
[Full finding section]

### [M-02] Title [VERIFIED/FALSE_POSITIVE/CONTESTED]
[Full finding section]

[... every Medium finding gets its own section ...]

---

## Low Findings

### [L-01] Title
[Full finding section - Recommendation field optional for Low]

### [L-02] Title
[Full finding section]

[... every Low finding gets its own section ...]

---

## Informational Findings

### [I-01] Title
[Full finding section - PoC Result field optional for Informational]

[... every Informational finding gets its own section ...]

---

## Priority Remediation Order

[Numbered list from most to least urgent. Use report IDs only.]

1. **C-01**: [one-line reason] - Immediate
2. **C-02**: [one-line reason] - Immediate
3. **H-01**: [one-line reason] - Before launch
...

---

## Appendix A: Internal Audit Traceability (Optional)

> **NOTE**: This appendix is for the audit team's internal reference only. It maps internal pipeline IDs to report IDs. It is NOT required for the client and may be omitted from client-facing deliverables.

| Report ID | Internal Hypothesis | Chain | Verification | Agent Sources |
|-----------|-------------------|-------|--------------|---------------|
| C-01 | [internal ref] | [chain ref] | CONFIRMED | [agent list] |
| H-01 | [internal ref] | - | CONFIRMED | [agent list] |
| ... | ... | ... | ... | ... |

### Excluded Findings

| Internal ID | Severity | Title | Exclusion Reason |
|-------------|----------|-------|-----------------|
| [internal ref] | Medium | [title] | FALSE_POSITIVE - verified not exploitable |
| [internal ref] | Low | [title] | Duplicate of M-03 |
```

---

## Quality Gates

Before the report is considered complete, verify:

1. **Every finding has its own section** - no finding exists only in a table row
2. **No internal IDs in body** - search the report for patterns like `[CS-`, `[AC-`, `[TF-`, `[BLIND-`, `[EN-`, `[SE-`, `[VS-`, `[DEPTH-`, `[SLITHER-`, `CH-`, and hypothesis `H-` followed by a number in brackets. NONE should appear outside Appendix A.
3. **Finding count matches summary** - the number of `###` sections per severity tier equals the count in the summary table
4. **Cross-references valid** - every `see X-NN` reference points to a finding that exists in the report
5. **Severity consistency** - if a verifier downgraded/upgraded a finding, the report reflects the FINAL severity, not the original hypothesis severity
