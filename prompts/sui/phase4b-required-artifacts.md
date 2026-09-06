# Phase 4b Required Artifacts (Thorough Mode Only)

> **Purpose**: Static manifest of files that MUST exist in {SCRATCHPAD}/ before Phase 4b exits.
> **Mode gate**: This manifest applies ONLY when `MODE == THOROUGH`. Core and Light skip this check.
> **Enforcement**: The orchestrator runs `ls {SCRATCHPAD}/` and checks EVERY line below.
> **This file is READ-ONLY** — the orchestrator MUST NOT modify it.

## Required Artifacts

| File | Producer | Phase |
|------|----------|-------|
| `depth_token_flow_findings.md` | depth-token-flow agent | 4b iter 1 |
| `depth_state_trace_findings.md` | depth-state-trace agent | 4b iter 1 |
| `depth_edge_case_findings.md` | depth-edge-case agent | 4b iter 1 |
| `depth_external_findings.md` | depth-external agent | 4b iter 1 |
| `blind_spot_a_findings.md` | Scanner A | 4b iter 1 |
| `blind_spot_b_findings.md` | Scanner B | 4b iter 1 |
| `blind_spot_c_findings.md` | Scanner C | 4b iter 1 |
| `validation_sweep_findings.md` | Validation Sweep | 4b iter 1 |
| `design_stress_findings.md` | Design Stress Testing | 4b iter 1 |
| `perturbation_findings.md` | Finding Perturbation Agent | 4b post |
| `skill_execution_gaps.md` | Skill Execution Checklist | 4b post |
| `confidence_scores.md` | Deterministic driver confidence transaction | 4b post-wave |
| `adaptive_loop_log.md` | Orchestrator | 4b exit |

## Niche Agent Artifacts (conditional — check template_recommendations.md)

For each niche agent marked `Required: YES` in `{SCRATCHPAD}/template_recommendations.md`:

| Flag | Expected File |
|------|---------------|
| MISSING_EVENT | `niche_event_findings.md` |
| sync_gaps >= 1 from Phase 4a.5 | `niche_semantic_gap_findings.md` |
| HAS_MULTI_CONTRACT | `niche_semantic_consistency_findings.md` |
| HAS_SIGNATURES | `niche_signature_findings.md` |
| HAS_DOCS | `niche_spec_compliance_findings.md` |
| MULTI_STEP_OPS | `niche_multi_step_safety_findings.md` |
| STABLESWAP_FORK | `niche_stableswap_compliance_findings.md` |
| MIXED_DECIMALS | `niche_dimensional_analysis_findings.md` |
| OUTCOME_CALLBACK (EVM only) | `niche_callback_safety_findings.md` |

## Checkpoint Protocol

```
if MODE != THOROUGH:
    skip this entire check — Core/Light have different artifact sets

missing = []
for each row in Required Artifacts table:
    if not exists({SCRATCHPAD}/{file}):
        missing.append({file, producer})

for each niche agent marked Required: YES in {SCRATCHPAD}/template_recommendations.md:
    if not exists({SCRATCHPAD}/{expected_file}):
        missing.append({expected_file, niche_agent})

if len(missing) > 0:
    log to {SCRATCHPAD}/violations.md: "PHASE 4b INCOMPLETE: {missing}"
    for each missing file:
        spawn the responsible agent (see Producer column)
    re-check after agents complete

ASSERT len(missing) == 0 before proceeding to Phase 4c
```
