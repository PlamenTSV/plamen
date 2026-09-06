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

## Verification-Status Legend - MANDATORY

Every finding carries ONE canonical verification-status token in both the
`report_index.md` Master Finding Index `Verification` column and the body
`### [X-NN] Title [STATUS]` header. The driver pre-computes this per finding in
`status_binding.md` from (verifier verdict, effective best-evidence tag); use it
verbatim — do NOT re-derive the label from raw verify prose.

| Status | Meaning | Evidence |
|--------|---------|----------|
| `VERIFIED` | Verdict CONFIRMED **and** the candidate-bound typed report evidence record is `PROOF_GRADE_HARM` | Authenticated execution, established result, harm scope, harm-capable independently authorized oracle; labels alone are insufficient |
| `CONFIRMED` | Verdict CONFIRMED but effective best evidence is only `[CODE-TRACE]` | A real confirmed finding — **NOT** `UNVERIFIED` |
| `CONTESTED` | Disputed (verifier CONTESTED / UNRESOLVED / PARTIAL) | — |
| `UNVERIFIED` | Refuted / false-positive / none | — |

Sort strength: `VERIFIED` > `CONFIRMED` > `CONTESTED` > `UNVERIFIED`. `CONFIRMED`
is a **non-speculative** status: a Critical/High that is `VERIFIED` or
`CONFIRMED` is never capped as "unverified" on a label basis.

The status token is not evidence authority. Before body rendering, the driver
dual-writes `report_evidence_records.json` and per-shard
`report_evidence_manifests/*.json`. Those typed records separately bind verdict,
evidence authenticity/result, proof scope/capabilities, source digests, and
limitations. `[CONFIRMED]`, `[POC-*]`, `[FUZZ-*]`, or similar Markdown text can
never mint proof-grade language. A code-trace confirmation is presented as a
confirmed mechanism, not as executed proof of harm.

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
- An independently adjudicated, evidence-bound `FULLY_TRUSTED_ACTOR` modifier may apply −1 tier (floor: Informational) only when the exact actor/capability and project-stated trust assumption are proven. Inventory labels and generic role names are not authority. Semi-trusted actors (admin, operator, keeper, oracle) are never adjusted here; their likelihood belongs in the matrix. Missing/conflicting trust evidence retains upstream severity with a visible uncertainty note.

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

## Material-Harm Body Floor (BODY vs APPENDIX) - MANDATORY

The report **body** is reserved for findings with a real security consequence.
Pure-quality findings are routed to **Appendix C: Quality & Hardening
Observations** (a table), never deleted. This is **mechanically enforced** by
the driver against `report_disposition_authority.json`. `disposition.md` and
lexical classification are proposal/veto inputs only. Non-body status requires
an exact independent typed full-claim refutation, a typed zero-security-
consequence decision with no contradictory mechanism/impact/premise record, or
an already-applied hash-bound alias naming its delivered survivor. Missing,
stale, partial, contested, or mismatched authority defaults to BODY at upstream
severity with visible human-review debt.

For every finding, classify BODY or APPENDIX:

- A finding -> **APPENDIX** ONLY if it has ZERO security consequence — i.e. it
  is pure quality/hardening/observability/style: missing events; missing
  zero-address/range checks with no demonstrated loss; one-step ownership / no
  two-step ownership / `renounceOwnership`; defense-in-depth ("add
  `nonReentrant`" with no shown reentrancy loss); signature/EIP-712 binding
  hardening with no shown exploit; missing asserts/gates ("does not validate
  X") with no consequence; UX/allowance friction; naming; typos; error-message
  wording; magic numbers; gas; docs; test-harness quality; interface-vs-impl
  parity; `supportsInterface` omissions; latent/none-at-present hazards.
- Otherwise -> **BODY.** ANY real security consequence keeps it in the body AT
  ANY SEVERITY, even if trusted-actor-gated, self-inflicted-precondition, or
  bounded/dust: direct fund loss/extraction; funds/assets locked or frozen;
  privilege escalation; a liveness brick denying a core user action; accounting
  corruption leading to loss.
- **Recall-safe default: when in doubt, BODY.** Burying a real finding in the
  appendix is the unacceptable error; an extra body finding is cheap.
- Unsupported High/Medium quality labels remain BODY at upstream severity.
  Low/Info also remain BODY unless the exact independent zero-harm decision is
  present. A Low/Info with a real consequence is always BODY.
- DROP/FALSE_POSITIVE (verifier-refuted) is unchanged and **separate** from
  APPENDIX — those go to Appendix A (Excluded Findings), not Appendix C.

---

## Finding Section Format - MANDATORY FOR EVERY FINDING

**Every finding gets its own full section.** No catch-all tables, no grouped summaries, no "remaining findings" dumps. A finding that only appears in a table row is effectively invisible to the reader.

```markdown
### [X-NN] Title [VERIFIED/CONFIRMED/UNVERIFIED/CONTESTED]

**Severity**: Critical/High/Medium/Low/Informational
**Location**: `SourceFile:L123-L145`
**Confidence**: HIGH/MEDIUM/LOW (N agents confirmed, Static Analysis: Y/N, PoC: PASS/FAIL/SKIPPED)
**Evidence assurance**: Proof-grade harm evidence / Confirmed mechanism; harm proof not established / Evidence limited

**Description**:
[Clear explanation of what's wrong. Include relevant code snippet. Do NOT reference any internal audit IDs - describe the bug directly.]

**Impact**:
[What can happen. Quantify where possible. If multiple sub-impacts from root-cause consolidation, list each as a bullet.]

**PoC Result**:
[Test output summary, or "Verification skipped - no build environment"]

**Recommendation**:
[How to fix. If the verifier generated a `### Suggested Fix` diff in verify_{id}.md, paste it here verbatim. Otherwise provide a text recommendation.]

> **Evidence and report limitation**: [Required when the typed record retains
> unresolved proof-scope or report-field debt after the single bounded repair.
> Keep the finding and name the limitation; do not invent missing prose or
> silently omit the section.]
```

### UNRESOLVED finding format

When independent skeptic/adjudication artifacts record `UNRESOLVED` for a
finding, the finding stays in the **report body** at the highest still-supported
upstream or typed-adjudicated severity. `UNRESOLVED` is an evidence/disagreement
state, not an automatic severity discount. Use this format:

```markdown
### [X-NN] Title [UNRESOLVED — needs human review]

**Severity**: {highest still-supported upstream or typed-adjudicated tier}
**Location**: `SourceFile:L123-L145`
**Confidence**: CONTESTED — verifier and skeptic disagree

**Description**:
[The bug as the verifier described it.]

**Verifier case**:
[1-2 paragraphs: what the verifier confirmed, with cited evidence.]

**Skeptic case**:
[1-2 paragraphs: what the skeptic argued is wrong with the verifier's analysis or what defense was missed.]

**Impact**:
[Conditional impact under each case.]

**Recommendation**:
Human reviewer: confirm deployment-context assumption {X} before triage. If verifier is correct, treat as {original_severity}. If skeptic is correct, treat as informational/false-positive.
```

The Trust Adj. column in `report_index.md` records
`UNRESOLVED(original_sev)` as a visibility marker only. A tier change requires a
separate, exact-identity, premise/evidence-bound, distinct-worker decision in the
typed severity ledger. If that authority is absent, incomplete, stale, or
ambiguous, preserve the upstream tier and flag human review.

**Why body and not Appendix A**: in security audits, the cost of missing a real exploit (false negative) exceeds the cost of an extra body section flagged for human triage (false positive). Burying UNRESOLVED in Appendix A inverts that tradeoff and historically caused real findings to disappear from human attention.

### SEVERITY_OVERRIDE token

`SEVERITY_OVERRIDE(original_sev)` is a driver-only Trust Adj. token. It may be
used only when `_severity_override_ledger.json` exists and names the affected
finding, original severity, final severity, and reason. Report agents must not
invent severity overrides from prose; without the ledger, use the normal
severity matrix plus mechanically authorized trusted-actor or chain rules.
`poc_demotion_proposals` is review evidence only: a failed/non-established PoC
MUST NOT lower severity or authorize a negative lifecycle effect. `UNRESOLVED`
and `PARTIAL` never authorize a tier change by themselves.

### EXTERNAL-ASSUMPTION-CAP token

`EXTERNAL-ASSUMPTION-CAP(original_sev)` is the Trust Adj. token for the driver's
narrow always-on severity brake: a High/Critical whose only in-scope-proven fact
is the ABSENCE of a balance-delta check and whose fund-loss harm materializes
ONLY under an assumed worst-case UNTRUSTED-EXTERNAL return value (over-report /
return-inflation / misrouted output), with no PoC attempted (an
external/deployment/structural no-fork blocker). The driver caps it to **Medium
(floor Medium, in-body, never Low)** in `severity_binding.md`; stamp
`EXTERNAL-ASSUMPTION-CAP(<orig>)` and keep the finding in the body. It is NOT a
false positive — it is a real hardening gap whose severity must not ride at High
on an assumed external behavior. A finding whose PoC was actually attempted and
PASSED is NOT capped (carve-out).

### INDEPENDENT-MIN token

`INDEPENDENT-MIN(claimed_sev)` is the Trust Adj. token for the verifier's
blind-first independent-severity cap (M4, anti-inflation). Every verifier
assesses an **Independent Severity** from the code and evidence ALONE, before
reconciling with the pre-assigned/claimed severity from the verification
queue — this prevents rubber-stamping an inflated pre-assigned severity. The
driver mechanically computes `final = min(independent, claimed)` in
`independent_severity_caps.md` / `severity_binding.md`: if the independent
assessment is LOWER than the claimed severity, the finding is capped and
stamped `INDEPENDENT-MIN(<claimed>)`; it stays in the body at the capped
severity. This is **cap-only**: it can never raise a severity above what was
claimed, and a REFUTED verdict, or a missing/unparseable Independent Severity
field, produces no cap at all (falls back to the claimed severity — recall-safe).

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
**Auditor**: Plamen Automated Security Analysis
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

### [H-01] Title [VERIFIED/CONFIRMED/UNVERIFIED/CONTESTED]
[Full finding section]

### [H-02] Title [VERIFIED/CONFIRMED/UNVERIFIED/CONTESTED]
[Full finding section]

[... every High finding gets its own section ...]

---

## Medium Findings

### [M-01] Title [VERIFIED/CONFIRMED/FALSE_POSITIVE/CONTESTED]
[Full finding section]

### [M-02] Title [VERIFIED/CONFIRMED/FALSE_POSITIVE/CONTESTED]
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

## Quality Observations (optional megasection)

> Low/Informational findings that are **unambiguously cosmetic** (dead code, unused imports, naming inconsistencies, typos, missing docs, gas optimization, code style, redundant checks, variable shadowing, magic numbers) MAY be grouped into a compact megasection table instead of individual finding sections. This reduces report length without losing signal.
>
> **Only these classes qualify**: dead_code, unused_import, unused_variable, naming, typo, magic_number, missing_docs, code_style, gas_optimization, redundant_code, shadowing.
>
> **Anything with plausible security impact** (missing validation, missing events, access control, centralization risk) MUST keep its full finding section even at Low/Info severity.

```markdown
## Quality Observations

| ID | Title | Severity | Location | Class | Description |
|----|-------|----------|----------|-------|-------------|
| I-03 | Unused import `SafeMath` | Info | src/Vault.sol:L5 | Unused imports | SafeMath imported but never used after Solidity 0.8+ migration |
| L-04 | Dead code in `_legacy()` | Low | src/Router.sol:L200-L220 | Dead code | Function unreachable after v2 migration, can be safely removed |
| I-05 | Magic number 86400 | Info | src/Staking.sol:L45 | Magic numbers | Hardcoded seconds-per-day; extract to named constant |
```

---

## Priority Remediation Order

[Numbered list from most to least urgent. Use report IDs only.]

1. **C-01**: [one-line reason] - Immediate
2. **C-02**: [one-line reason] - Immediate
3. **H-01**: [one-line reason] - Before launch
...

---

## Appendix A: Excluded Findings (Optional)

> **CLIENT-FACING ONLY**: Do not include internal pipeline IDs, hypothesis IDs,
> chain IDs, agent-source IDs, or report-index traceability columns in the
> delivered report. Internal traceability belongs in `report_index.md` and
> `report_coverage.md`, not in `AUDIT_REPORT.md`.

| Severity | Title | Exclusion Reason |
|----------|-------|------------------|
| Medium | [title] | FALSE_POSITIVE - verified not exploitable |
| Low | [title] | Duplicate of M-03 |

---

## Appendix C: Quality & Hardening Observations (Optional)

> Findings dispositioned **APPENDIX** by the material-harm body floor — real but
> with ZERO security consequence (pure quality/hardening/observability/style).
> This is **DISTINCT** from Appendix A (Excluded = false-positive/duplicate):
> Appendix C findings are valid observations, just not body material. The driver
> mechanically relocates any authorized APPENDIX finding that still has a body
> `###` section into this table and preserves the full original section bytes
> in `report_appendix_full_content.json`, with a validated client-field diff.
> It is never dropped. One row per finding.

| ID | Severity | Title | Location | Reason |
|----|----------|-------|----------|--------|
| M-04 | Medium | Admin setter emits no event | `src/Vault.sol:L40` | Observability / missing events |
| L-07 | Low | Missing zero-address check in setter | `src/Vault.sol:L88` | Input hardening (no demonstrated loss) |
```

---

## Quality Gates

Before the report is considered complete, verify:

1. **Every finding has its own section** - no finding exists only in a table row (exceptions: findings routed to the Quality Observations megasection, and APPENDIX-dispositioned findings routed to Appendix C by the material-harm body floor, appear as table rows by design)
1a. **Material-harm body floor applied** - the body contains findings with a real security consequence plus every unresolved/unauthorized non-body proposal; only independently authorized zero-harm observations appear in Appendix C. Driver-enforced against typed disposition authority with a lossless sidecar.
2. **No internal IDs anywhere in AUDIT_REPORT.md** - search the report for patterns like `[CS-`, `[AC-`, `[TF-`, `[BLIND-`, `[EN-`, `[SE-`, `[VS-`, `[DEPTH-`, `[SLITHER-`, `[RS-`, `[PC-`, `[SP-`, `[DST-`, `[DE-`, `[DX-`, `[DS-`, `[DT-`, `CH-`, and hypothesis `H-` followed by a number in brackets. NONE should appear in the delivered report.
3. **Finding count matches summary** - the number of `###` sections per severity tier equals the count in the summary table
4. **Cross-references valid** - every `see X-NN` reference points to a finding that exists in the report
5. **Severity consistency** - if a verifier downgraded/upgraded a finding, the report reflects the FINAL severity, not the original hypothesis severity
6. **Coverage ledger exists** - `report_coverage.md` must explain how raw recon/depth/scanner candidates were promoted, deduplicated, refuted, or deferred
7. **No silent drops** - a Medium+ candidate present in raw depth/scanner outputs must not disappear without a duplicate or verifier-refutation reference
8. **No control characters in final output** - remove form-feed, ANSI escape codes, and other non-printable bytes copied from tool output
