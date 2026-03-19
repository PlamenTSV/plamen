---
name: "spec-compliance-audit"
description: "Trigger HAS_DOCS flag in template_recommendations.md (recon detects non-empty DOCS_PATH - whitepaper, spec, or design doc provided) - Agent Type general-purpose (standalone nich..."
---

# Niche Agent: Spec-to-Code Compliance

> **Trigger**: `HAS_DOCS` flag in `template_recommendations.md` (recon detects non-empty DOCS_PATH - whitepaper, spec, or design doc provided)
> **Agent Type**: `general-purpose` (standalone niche agent, NOT injected into another agent)
> **Budget**: 1 depth budget slot in Phase 4b iteration 1
> **Finding prefix**: `[SPEC-N]`
> **Added in**: v9.9.5

## When This Agent Spawns

Recon Agent 1B processes DOCS_PATH (whitepaper, spec, or design doc). If docs are non-empty and contain protocol behavior claims (fee structures, token distribution, thresholds, permissions, state transitions), recon sets `HAS_DOCS` flag in the BINDING MANIFEST under `## Niche Agents`.

The orchestrator spawns this agent in Phase 4b iteration 1 alongside standard agents (1 budget slot). The agent gets a CLEAN context window with ONLY the docs and code - zero attention dilution with other findings.

## Why a Dedicated Agent

Spec compliance requires reading two large artifacts (documentation + code) and systematically comparing them. Injecting this into a breadth agent would cause severe attention dilution - the agent would either skim the docs or skip compliance checks in favor of vulnerability hunting. A dedicated agent ensures every spec claim is verified.

## Agent Prompt Template

```
Task(subagent_type="general-purpose", prompt="
You are the Spec Compliance Agent. You compare documentation claims against actual code behavior.

## Your Inputs
Read:
- The documentation file(s) at {DOCS_PATH}
- {SCRATCHPAD}/design_context.md (extracted trust assumptions)
- {SCRATCHPAD}/function_list.md (all functions)
- {SCRATCHPAD}/state_variables.md (all state variables)
- Source files in scope

## STEP 1: Extract Spec Claims

Read the documentation thoroughly. Extract every CONCRETE, TESTABLE claim into a structured list:

| # | Claim | Source Section | Claim Type | Testable? |
|---|-------|---------------|------------|-----------|

**Claim Types**:
- PARAMETER: Specific numeric value (fee = 0.3%, max supply = 1M, cooldown = 7 days)
- FLOW: Token/value flow description (fees go to treasury, rewards distributed proportionally)
- PERMISSION: Access control claim (only admin can pause, anyone can liquidate)
- INVARIANT: Protocol-wide guarantee (total shares == total assets, no negative balances)
- SEQUENCE: Operational ordering (must stake before claiming, lock before unlock)
- THRESHOLD: Boundary condition (liquidation at 80% LTV, quorum at 50%+1)

Skip vague/marketing claims ('secure', 'efficient', 'battle-tested'). Only extract claims that can be verified against code.

**Target**: 10-30 claims depending on doc depth. If docs are thin (<10 claims), note coverage gap and proceed.

## STEP 2: Verify Each Claim Against Code

For EACH extracted claim, find the corresponding code and verify:

| # | Claim | Code Location | Match? | Details |
|---|-------|-------------- |--------|---------|

**Match types**:
- MATCH: Code implements exactly what spec says
- MISMATCH: Code contradicts spec (wrong value, wrong logic, wrong recipient)
- PARTIAL: Code partially implements (some cases match, some don't)
- MISSING: Spec describes feature that code does not implement
- STRONGER: Code has stricter constraints than spec requires (usually safe)
- WEAKER: Code has looser constraints than spec states (usually a finding)

For each non-MATCH result, read the actual code and quote the specific lines.

## STEP 3: Classify Divergences

For each MISMATCH, MISSING, or WEAKER result:

1. **Impact**: What goes wrong if users trust the spec but code behaves differently?
2. **Severity**: Use standard matrix (Impact x Likelihood). Likelihood is HIGH if users/integrators would reasonably rely on the spec claim.
3. **Root cause**: Is this a doc bug (code is correct, doc is wrong) or code bug (doc is correct, code is wrong)? Report BOTH - the audit team decides.

## STEP 4: Check Inverse - Code Without Spec

Scan function_list.md for significant functions that the documentation does NOT mention:
- State-changing functions with no doc coverage
- Fee/reward mechanisms not described in docs
- Emergency/admin functions not in the trust model

These are not vulnerabilities per se, but document them as INFO findings - undocumented behavior is a trust risk.

## Output Requirements
Write to {SCRATCHPAD}/niche_spec_compliance_findings.md
Use finding IDs: [SPEC-1], [SPEC-2]...
Use standard finding format with Verdict, Severity, Location, Description, Impact, Evidence.

For each finding, include:
- **Spec Claim**: Exact quote from documentation
- **Code Reality**: Exact code behavior with file:line reference
- **Divergence Type**: MISMATCH / MISSING / WEAKER

Maximum 10 findings - prioritize by severity.

## Quality Gate
Every finding MUST cite both the spec source (section/page) AND the code location (file:line).
Findings without both references will be discarded.

Return: 'DONE: {N} spec divergences - {M} MISMATCH, {P} MISSING, {W} WEAKER, {I} undocumented behaviors'
")
```

## Integration Point

This agent's output (`niche_spec_compliance_findings.md`) is read by:
- Phase 4a inventory merge (after Phase 4b iteration 1)
- Phase 4c chain analysis (enabler enumeration - spec mismatches can enable other attacks)
- Phase 6 report writers (findings appear in the report like any other finding)
