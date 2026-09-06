# Finding Output Format (ALL AGENTS)

> **Usage**: Every breadth agent, depth agent, scanner, niche agent, and validation sweep agent must use this format for findings.
> **Read by**: Agents during Phase 3, Phase 3b, Phase 4b. Referenced by inventory, chain analysis, and report writers.

---

Every finding MUST use this format:

```markdown
## Finding [{PREFIX}-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: ✓1,2,3,5 | ✗4(N/A) | ?6,7(uncertain)
**Rules Applied**: [R4:✓, R5:✓, R6:✗(no role), R8:✗(single-step), R10:✓]
**Depth Evidence** (depth agents only): [BOUNDARY:tested X=0,MAX], [VARIATION:param changed from A→B], [TRACE:followed to revert at L120]
**Preferred Tag**: CODE-TRACE / POC-PASS / POC-FAIL / FUZZ-PASS / MEDUSA-PASS / CONTESTED
**Severity**: Critical/High/Medium/Low/Informational
**Location**: SourceFile:LineN
**Description**: What's wrong
**Impact**: What can happen (if finding is in a shared utility/library, list impact at EACH consumption point)
**Material Harm** (MANDATORY): The concrete CONSEQUENCE in one sentence — not the mechanism, the harm. State WHO loses WHAT (specific user class + funds/privilege/liveness/accounting/integrity consequence), e.g. "depositors lose 25-50% of their pro-rata share" or "any peer can permanently halt block production". A finding whose only stated harm is a MECHANISM ("state is corrupted", "a guard is missing", "the function is callable", "value diverges") without a concrete consequence is NOT a body finding: cap it at Informational and route it to the Quality Observations megasection. "Could be exploited" / "may be unsafe" without a named consequence does not qualify.
**Evidence**: Code snippets

### Precondition Analysis (if PARTIAL or REFUTED)
**Missing Precondition**: [What blocks this attack]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE
**Why This Blocks**: [Specific reason]

### Postcondition Analysis (if CONFIRMED or PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [STATE, ACCESS, TIMING, EXTERNAL, BALANCE]
**Who Benefits**: [Who can use these]
```

---

## Semantic Preservation Fields (OPTIONAL)

Agents MAY add these fields when applicable to preserve analysis context. These
fields are optional notes only; they are not hard-required schema fields or phase
gate requirements unless validators are updated later.

```markdown
**Semantic Invariant** (OPTIONAL): The protocol property, relationship, or safety condition considered by this finding.
**Branch Preconditions** (OPTIONAL): The generic conditions required for the relevant execution branch to be reachable.
**Terminal Mechanism** (OPTIONAL): The final mechanism that creates, blocks, or resolves the candidate issue.
**Refutation Basis** (OPTIONAL): The concrete reason a candidate is REFUTED or downgraded, when that reasoning should be preserved.
**Composition Candidates** (OPTIONAL): Related conditions, findings, or mechanisms that may compose with this issue in later analysis.
**Discovery Steer** (OPTIONAL): Compact hint for later pairing, such as shared variable/function/branch/effect or candidate ID; not proof and not a required field.
```

Use these fields sparingly for semantic invariant, branch feasibility,
refutation, and composition context that would otherwise be lost between
breadth, depth, scanner, chain, and report phases.

---

## Step Execution Interpretation

- `✓` = completed
- `✗(valid reason)` = acceptable skip (N/A, single entity, no external deps)
- `✗(no reason)` or `?` = **FLAG FOR DEPTH REVIEW**

---

## Rules Applied Field (MANDATORY)

| Code | Rule | When Required | Report |
|------|------|---------------|--------|
| R4 | CONTESTED/unknown → adversarial escalation | When evidence is uncertain or external deps involved | ✓ or ✗(evidence clear, no externals) |
| R5 | Combinatorial impact analysis | N-entity systems | ✓ or ✗(single entity) |
| R6 | Bidirectional Role | Semi-trusted role involved | ✓ or ✗(no role) |
| R8 | Cached Parameters / Stored External State | Multi-step operations OR stored external state | ✓ or ✗(single-step, no stored external state) |
| R10 | Worst-State Severity | Any severity assessment | ✓ or ✗(single fixed state) |
| R11 | Unsolicited Token Transfer | External tokens involved | ✓ or ✗(no external tokens) |
| R12 | Exhaustive Enabler Enumeration | Finding identifies dangerous state | ✓ or ✗(no dangerous precondition) |
| R13 | User Impact / Anti-Normalization | Behavior marked as "by design" | ✓ or ✗(not design-related) |
| R14 | Cross-Variable Invariant + Constraint Coherence + Setter Regression | Aggregate/total variables, independently-settable limits, admin setters of bounds | ✓ or ✗(no aggregate variables or settable constraints) |
| R15 | Flash Loan Precondition Manipulation | Balance/oracle/threshold preconditions accessible via flash loan | ✓ or ✗(no flash-loan-accessible state) |
| R16 | Oracle Integrity | Oracle-dependent logic (staleness, decimals, zero, failure modes) | ✓ or ✗(no oracle dependency) |

---

## Rule Application Enforcement

- Findings with `✗(no reason)` for applicable rules → **FLAG FOR DEPTH REVIEW**
- R6 violation (role involved but ✗) → **MANDATORY depth review**
- R8 violation (multi-step or stored external state but ✗) → **Check for parameter/external state staleness**
- R10 violation (severity uses current snapshot) → **Recalibrate with worst-state**
- R10 violation — **UNRESEARCHED-EXTERNAL burden inversion (the "valid-but-unresearched" fallacy)** → **MANDATORY**: when a finding's harm mechanism is CONFIRMED in-scope and ONLY an unresearched / out-of-scope / not-inspectable EXTERNAL factor could render it safe, do NOT default severity to Informational/Low "pending external research." That inverts the burden of proof. Apply R10: assume the WORST realistic external condition, report at that impact severity, tag `[EXTERNAL-ASSUMPTION: <assumed condition>]`, and route to verification. An unresearched external dependency is a **verification obligation, not a severity discount.** Demoting requires POSITIVE in-scope evidence of the safe external condition — its mere possibility does not rebut a mechanism already proven in-scope. (E.g. an EVM `abi.encode` payload sent to a Solana consumer is CONFIRMED-mismatch at impact severity even when the consumer's decoder is external and uninspectable — not Informational.)
  - **Citation requirement (mandatory, no exceptions)**: any finding carrying `[EXTERNAL-ASSUMPTION: ...]` MUST also carry `[EXT-CITED: <dependency>, source=<url>, fetched=<date>]` (matching a row in `{SCRATCHPAD}/external_dependency_research.md`) OR a `NEEDS_DEPENDENCY_RESEARCH: <dependency>:<file:line>: <what you need to know>` escalation line. A tag with neither is scored `[CODE-TRACE]`-equivalent on Evidence-quality Axis 1 and cannot support a VERIFIED/proof-grade disposition — identical to an uncited SCIP `[LSP-TRACE]` claim capping at `[CODE-TRACE]`. This is a gating rule on the existing tag, not a new confidence axis or weight.
- R14 violation (setter for limit but ✗) → **Check constraint coherence and regression below accumulated state**
- R15 violation (flash-loan-accessible state but ✗) → **MANDATORY flash loan skill analysis**
- R13 violation (behavior marked "by design" but ✗) → **MANDATORY**: Document terminal user-facing consequence (e.g., "users lose X under condition Y") before REFUTED closure. "By design" describes mechanism, not impact - impact assessment is still required.
- R16 violation (oracle dependency but ✗) → **MANDATORY oracle analysis**

---

## Depth Evidence Tags

Used by depth agents and iteration 2+ agents:

| Tag | What It Proves | Example |
|-----|---------------|---------|
| `[BOUNDARY:X=val]` | Agent substituted a concrete boundary value into the expression | `[BOUNDARY:windowSize=0 → weight=MAX_INT]` |
| `[VARIATION:param A→B]` | Agent tested behavior change when a parameter varies | `[VARIATION:decimals 18→6 → price inflated 1e12x]` |
| `[TRACE:path→outcome]` | Agent traced execution to a terminal state (revert, return, state change) | `[TRACE:withdraw(maxUint)→revert at L120 "insufficient"]` |
| `[MEDUSA-PASS]` | Medusa found a counterexample to the encoded invariant. The tag authenticates that result, not protocol-harm scope; oracle provenance, environment/reachability, preconditions, external premises, and proof scope are recorded separately. | `[MEDUSA-PASS: encoded invariant violated after a generated sequence]` |
| `[CROSS-DOMAIN-DEP: {domain}]` | Agent identified an assumption outside its own domain that could enable exploitation if broken | `[CROSS-DOMAIN-DEP: external — assumes oracle price is fresh within 1 hour]` |
| `[EXTERNAL-ASSUMPTION: {condition}]` | Severity assumes the WORST realistic external condition (R10) for an in-scope-confirmed mechanism whose safety hinges on an unresearched / out-of-scope factor; a verification obligation, NOT a severity discount to Informational. **Citation-gated**: MUST be paired with either `[EXT-CITED: ...]` (next row) or a `NEEDS_DEPENDENCY_RESEARCH` escalation line — see "Citation requirement" under Rule Application Enforcement above | `[EXTERNAL-ASSUMPTION: destination gateway deserializes with Borsh; non-issue only if it abi.decodes]` |
| `[EXT-CITED: {dependency}, source={url}, fetched={date}]` | Grounds a paired `[EXTERNAL-ASSUMPTION: ...]` tag in a matching row of the recon-baked `{SCRATCHPAD}/external_dependency_research.md` ledger — proof the worst-case assumption was researched, not guessed. An `[EXTERNAL-ASSUMPTION: ...]` tag carrying NEITHER this tag NOR a `NEEDS_DEPENDENCY_RESEARCH: <dependency>:<file:line>: <what you need>` escalation line is scored `[CODE-TRACE]`-equivalent on Evidence-quality Axis 1 (`phase4-confidence-scoring.md`) and cannot support a VERIFIED/proof-grade disposition — identical to an uncited `[LSP-TRACE]` claim capping at `[CODE-TRACE]` | `[EXT-CITED: cross-chain messenger dependency, source=https://docs.example-messenger.io/spec, fetched=2026-07-12]` |
| `[REGRESS:symptom→cause]` | Agent traced a varying symptom backward to its architectural root cause | `[REGRESS:overflow threshold varies by decimals→missing decimal normalization]` |
| `[PERTURBATION:operator]` | Perturbation agent found adjacent vulnerability via structured mutation of an existing finding (Thorough only) | `[PERTURBATION:DIRECTION_FLIP — deposit rounding found → withdrawal rounding also vulnerable]` |
