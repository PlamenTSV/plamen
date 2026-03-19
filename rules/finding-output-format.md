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
**Severity**: Critical/High/Medium/Low/Info
**Location**: SourceFile:LineN
**Description**: What's wrong
**Impact**: What can happen (if finding is in a shared utility/library, list impact at EACH consumption point)
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
| `[MEDUSA-PASS]` | Medusa fuzzer found a counterexample violating an invariant - mechanical proof (same weight as `[POC-PASS]`) | `[MEDUSA-PASS: fuzz_totalSupplyInvariant violated after 3-call sequence]` |
