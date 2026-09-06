# Phase 6b: Tier Writer Shared Methodology (v2.4.8)

Execute the instructions below directly and stop. Do not spawn subagents.

> **Loaded by**: Every tier-writer subprocess (Critical+High, Medium, Low+Info).
> **NOT loaded by**: Index Agent (Step 6a), Assembler (Step 6c), or the orchestrator.
> **Purpose**: Single source of truth for finding-section format, common rules, and quality gates.
> Tier-specific inputs and model assignments come from the driver's cost directive, not this file.

---

## Tier Writer Common Rules (MANDATORY)

All tier writers MUST follow these rules without exception:

1. **NO internal IDs** (hypothesis IDs, chain IDs, agent IDs) anywhere in output. This means NO `H-1`, `CH-1`, `CS-1`, `AC-2`, `TF-4`, `BLIND-3`, `EN-1`, `SE-1`, `VS-1`, `DEPTH-X-N`, `SLITHER-N`, `RS-N`, `PC-N`, `SP-N`, `DST-N`, `DE-N`, `DX-N`, `DS-N`, `DT-N`, or any other internal pipeline identifier.
2. **Every finding gets its own ### section** - no tables, no groups, no summaries, no catch-all dumps. A finding that only appears in a table row is effectively invisible to the reader.
3. **Write as if the reader has never seen the audit pipeline** - no references to breadth agents, depth agents, chain analysis, scanners, hypothesis grouping, or any pipeline internals.
4. **Cross-references use report IDs only** - include finding title in parentheses for context: `see H-03 (Insufficient oracle staleness check)`.
5. **Trust assumption context**: If report_index.md marks a finding with `TRUSTED-ACTOR` in the Trust Adj. column, include after Severity: *"Severity adjusted from {original} - attack requires {actor} to violate stated trust assumption: {assumption}."* For `WITHIN-BOUNDS` flags: include a note in Description that the impact falls within the protocol's stated operational bounds for the semi-trusted actor. Do NOT change the severity for WITHIN-BOUNDS - flag only.
6. **Missing verify_*.md handling**: If the verify_*.md for a finding is MISSING, do NOT stub the section. Still write the full finding body using the hypothesis and inventory data. Mark the header as `### [X-NN] Title [VERIFICATION NOT EXECUTED]` and include in the Description: *"Phase 5 verification did not produce a PoC for this finding. Treat as UNVERIFIED."* Populate Severity, Location, Description (3-5 sentences), Impact, and Recommendation from the hypothesis text and findings_inventory.md.
7. **Per-section structural completeness**: Every `### [X-NN]` section body MUST contain `Severity`, `Location`, and a `Description` of at least 3 sentences (Critical/High/Medium also need `Impact`). Do NOT pad prose to hit a length target. If a Low/Informational finding is a genuine one-liner with no security nuance, route it to the `## Quality Observations` megasection instead of inflating it. (A length floor may still flag obvious stubs, but any retry will name the specific short sections and tell you to add concrete detail or move them to the megasection — it will never re-issue an identical prompt, since that cannot converge.)
8. **Chunk scoping (driver-imposed)**: If the driver's prefix to your prompt lists a specific subset of finding IDs under "## Findings assigned to THIS chunk", you MUST write ONLY those IDs, in the order listed. Do NOT write any finding NOT in that list — another tier-writer agent owns those.
9. **Minimal-input override (driver-imposed)**: If the driver's prefix tells you to use a minimal read set, obey that instead of the broad-input list below. In minimal-input mode, prefer your assigned manifest (`body_manifests/<shard>.json`), assigned `verify_*.md` files, `findings_inventory.md`, and cited source files. Do NOT bulk-read `report_index.md`, `hypotheses.md`, `chain_hypotheses.md`, `synthesis_full.md`, or unrelated `verify_*.md` files unless a required assigned finding is otherwise missing.
10. **Typed evidence boundary (mandatory when present)**: Before rendering, read
    `report_evidence_manifests/<shard>.json` matching the assigned body manifest.
    Its embedded `report_evidence` record is authoritative for verdict,
    evidence authenticity/result, proof scope, capabilities, source digests,
    limitations, mechanism, preconditions, impact, locations, and
    recommendation. The legacy body manifest remains the assignment/recovery
    input, but `[CONFIRMED]`, `[POC-*]`, `[FUZZ-*]`, or similar prose tags can
    never upgrade the typed evidence authority. Only
    `presentation_assurance=PROOF_GRADE_HARM` may be described as executed
    proof of harm. `CONFIRMED_MECHANISM` means the mechanism is supported but
    executed harm is not established. Preserve every assigned finding.
11. **Bounded semantic-repair result**: If the typed record still contains
    `REPORT_FIELD_MISSING:*` after the one exact repair delta, do not invent the
    missing content and do not omit the section. Render an `Evidence and report
    limitation` note naming the incomplete client field(s). Copy other typed
    fields faithfully. The deterministic projection binds the final section to
    the record digest and rejects hidden debt.

---

## Finding Section Format (MANDATORY FOR EVERY FINDING)

```markdown
### [X-NN] Title [VERIFIED/UNVERIFIED/CONTESTED]

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
```

### Field Rules

- **Severity**: Must match the FINAL severity from the manifest or report_index.md (after all demotions/upgrades).
- **Location**: Use backtick-wrapped `file:line` format. For consolidated findings, use a location table (see Root-Cause Consolidation below).
- **Confidence**: Derive from agent consensus count, static analysis availability, and PoC execution result.
- **Description**: Minimum 3-5 sentences. Include the actual problematic code snippet, not just a line reference. For chain findings (multiple bugs combining): describe the full attack sequence from start to finish — the reader must understand the complete attack path without reading other findings.
- **Impact**: Quantify where possible (dollar amounts, percentage loss, permanent vs temporary). For root-cause consolidation, list each sub-impact as a bullet.
- **PoC Result**: Summarize test output within the typed proof scope. A
  `[POC-PASS]` or `[FUZZ-PASS]` label without a candidate-bound authenticated
  execution assessment is not proof-grade. For an authenticated established
  result, include key assertions without widening beyond the typed scope. For
  an authenticated negative result, state only the maximum negative scope in
  the typed record. For skipped/unbound execution, state the limitation.
- **Recommendation**: Actionable fix guidance. If a verifier-generated diff exists in verify_{id}.md, paste it verbatim. Low findings: Recommendation field is optional. Informational findings: PoC Result field is optional.

### Verification Status Tags (header)

| Tag | Meaning |
|-----|---------|
| `[VERIFIED]` | Typed evidence record says `PROOF_GRADE_HARM`; a PoC/fuzzer label alone is insufficient |
| `[UNVERIFIED]` | No PoC execution attempted or PoC skipped |
| `[CONTESTED]` | Evidence is conflicting or confidence is low |
| `[FALSE_POSITIVE]` | Verified NOT exploitable (appears only if retained in report for context) |
| `[VERIFICATION NOT EXECUTED]` | verify_*.md file missing for this finding |
| `[REPORT-BLOCKED]` | Manifest flagged this finding as report-blocked (e.g. severity demotion, dedup absorption); writer must keep the finding body but mark the tag. Body validator at `_validate_report_body` accepts this tag in addition to `[UNVERIFIED]` / `[VERIFICATION NOT EXECUTED]` when the manifest entry has `report_blocked=true`. |
| `[UNRESOLVED — needs human review]` | Independent skeptic/adjudication disagreement; severity is preserved unless the typed severity ledger authorizes a distinct change |

---

## UNRESOLVED Finding Format

When independent skeptic/adjudication artifacts record `UNRESOLVED` (or
`PARTIAL`) for a finding, it stays in the **report body** at the highest
still-supported upstream or typed-adjudicated tier. These are
evidence/disagreement states, not severity discounts. Use this format:

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

`UNRESOLVED(original_sev)` is a visibility marker only. A tier change requires
an exact-identity, premise/evidence-bound, distinct-worker decision in the typed
severity ledger. Missing, stale, incomplete, or ambiguous authority preserves
the upstream tier and adds human-review debt.

**Why body and not Appendix A**: in security audits, the cost of missing a real exploit (false negative) exceeds the cost of an extra body section flagged for human triage (false positive). Burying UNRESOLVED in Appendix A historically caused real findings to disappear from human attention.

---

## PoC-Fail Review Context

When report_index.md marks a finding with `POC-FAIL-PROPOSAL(no-tier-change)` (derived from the non-authoritative `poc_demotion_proposals` projection), explain only that the encoded execution did not establish its assertion and requires independent review. It MUST NOT lower severity, imply candidate-wide refutation, or remove the finding from the body. Preserve the highest supported pre-proposal severity.

---

## Root-Cause Consolidation (Merged Findings)

When the Index Agent merges multiple hypotheses into one report finding (noted in the Consolidation Map in report_index.md), the tier writer MUST:

1. **Use a class-level title** (e.g., "Missing event emission on admin state changes"), not a single-location title.
2. **List ALL affected locations** in a table under Location:
   ```markdown
   | Contract | Function | Line | Issue |
   |----------|----------|------|-------|
   | Vault.sol | setFee() | L45 | No event on fee change |
   | Vault.sol | setMaxDeposit() | L78 | No event on cap change |
   | Router.sol | updateOracle() | L112 | No event on oracle swap |
   ```
3. **Provide ONE consolidated recommendation** covering all locations.
4. **Use the highest severity** from the matrix across all sub-impacts.
5. **List each sub-impact as a bullet** under Impact if they differ.
6. Reference the Consolidation Map in report_index.md for the internal hypothesis list (this is for your awareness — do NOT expose internal IDs in the output).

---

## Cross-Reference Format

When referencing another finding in the same report:
- Use ONLY report IDs: `see C-01 (Title of that finding)`
- Include the finding title in parentheses so the reader can identify it without scrolling.
- Never use internal pipeline IDs for cross-references.
- For chain findings that reference component findings: describe the relationship in prose. Example: *"This vulnerability is exacerbated when combined with H-03 (Unrestricted oracle update), which allows the attacker to manipulate the price feed before executing this attack."*

---

## Code Snippets

- Include the actual problematic code, not just a line reference.
- Use fenced code blocks with the appropriate language tag (```solidity, ```rust, ```move, etc.).
- Highlight the vulnerable line(s) with a comment if the snippet is long.
- Keep snippets focused — include only enough context to understand the bug (typically 5-15 lines).
- If the finding spans multiple locations, include the most critical snippet in Description and reference additional locations in the Location table.

---

## Quality Observations Megasection (Low+Info Tier Only)

Low/Informational findings that are **unambiguously cosmetic** MAY be grouped into a compact table instead of individual sections. This reduces report length without losing signal.

**Only these classes qualify**: dead_code, unused_import, unused_variable, naming, typo, magic_number, missing_docs, code_style, gas_optimization, redundant_code, shadowing.

**Anything with plausible security impact** (missing validation, missing events, access control, centralization risk) MUST keep its full finding section even at Low/Info severity.

**When in doubt, use full-section format.** The megasection is for unambiguous cosmetic observations only.

```markdown
## Quality Observations

| ID | Title | Severity | Location | Class | Description |
|----|-------|----------|----------|-------|-------------|
| I-03 | Unused import SafeMath | Info | src/Vault.sol:L5 | Unused imports | SafeMath imported but never used post-0.8 |
| L-04 | Dead code in _legacy() | Low | src/Router.sol:L200 | Dead code | Unreachable after v2 migration |
```

---

## Output File Convention

Each tier writer writes to the exact output filename assigned by the driver in
the driver-injected phase override. In sharded runs this may be suffixed, e.g.
`report_medium_a.md` or `report_low_info_b.md`. Do not infer or normalize the
filename from severity; the driver-owned manifest is the only authority.

**FIRST ACTION on spawn**: Use the Write tool to create the output file with a one-line header (e.g., `# Critical and High Findings`). This reserves the write budget so the file exists on disk even if analysis is interrupted. Overwrite with full content at the end.

---

## Anti-Hallucination Rules

1. **Do NOT invent code that does not exist in the source files.** Every code snippet must be copied from an actual source file you read during this session.
2. **Do NOT extrapolate line numbers.** Use only line numbers from findings_inventory.md, verify_*.md, or your own file reads.
3. **Do NOT fabricate PoC results.** If you did not find a verify_*.md file for a finding, state that verification was not executed — do not invent test output.
4. **Do NOT assume severity.** Use the exact severity from the manifest (or report_index.md if no manifest).

---

SCOPE: Write ONLY the exact driver-assigned tier output file named in the phase override. If the driver provided a `body_manifests/<shard>.json`, that manifest plus its matching `report_evidence_manifests/<shard>.json` typed authority are your SINGLE SOURCE OF TRUTH — do NOT read `report_index.md` (it lists ALL findings across all shards and causes scope violations). Read ONLY those manifests and the `verify_*.md` files they reference. If NO manifest was provided, fall back to `report_index.md` for your tier assignments. Do NOT read or write other tier files or the final report. Do NOT proceed to assembly or any subsequent phase. Return and stop.
