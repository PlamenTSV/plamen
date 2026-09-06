---
description: "Phase 4b transient post-DA confidence-routing proposal"
---

# Phase 4b Transient Post-DA Routing Proposal

Use the parent-supplied iteration-1 routing table and the completed
Devil's-Advocate outputs to propose iteration-3 routing. Apply AD-5 and the
mode-specific formulas in
`~/.claude/rules/phase4-confidence-scoring.md`. Scores may rise only when a DA
output adds a new code reference, tool result, or production-verification
result. Restated prose and external precedent do not qualify.

Return a compact Markdown table in your response with the prior score, current
score, new-evidence anchor, classification, and loop dynamics. Preserve each
source finding ID. This response is routing advice only; it has no verdict,
demotion, clean-conclusion, or proof authority.

MUST NOT create, update, or modify
`{SCRATCHPAD}/confidence_scores.md`,
`{SCRATCHPAD}/confidence_consensus_authority.json`, or
`{SCRATCHPAD}/consensus_map.md`. The deterministic driver publishes the
canonical post-wave artifacts. If the proposal cannot be completed, return
`ROUTING_PROPOSAL_UNAVAILABLE`; the parent must retain every unresolved
Medium+ candidate as UNCERTAIN.

SCOPE: Read only the parent-supplied table and DA evidence. Return the proposal
to the parent coordinator. Do not write scratchpad files, spawn subagents, or
proceed to iteration 3.
