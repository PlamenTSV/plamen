---
description: "Phase 4b transient confidence-routing proposal"
---

# Phase 4b Transient Confidence Routing Proposal

This helper supports a coordinator that must choose iteration-2 work before
the depth session returns to the driver. It has no canonical artifact
authority.

Read the current inventory and completed depth, scanner, validation, and niche
artifacts. Use a current driver-published consensus row only if its PhaseIO
authority is already available and exact; otherwise score Consensus as `0.0`.
Apply the mode-specific formulas and thresholds in
`~/.claude/rules/phase4-confidence-scoring.md`. Preserve each source finding
ID. Treating unavailable consensus as zero is recall-safe: it may request more
depth but can never suppress it.

Return a compact Markdown table in your response:

| Finding ID | Evidence | Consensus | Quality | Composite | Classification |
|------------|----------|-----------|---------|-----------|----------------|

The parent coordinator uses this table only to allocate remaining depth work.
It is a proposal, not a verdict, demotion, clean conclusion, or proof.

MUST NOT create, update, or modify
`{SCRATCHPAD}/confidence_scores.md`,
`{SCRATCHPAD}/confidence_consensus_authority.json`, or
`{SCRATCHPAD}/consensus_map.md`. The deterministic driver publishes those
canonical artifacts after the depth wave. If inputs are missing or the table
cannot be completed, return `ROUTING_PROPOSAL_UNAVAILABLE`; the parent must
treat every unresolved Medium+ candidate as UNCERTAIN.

SCOPE: Read only the listed upstream artifacts. Return the proposal to the
parent coordinator. Do not write scratchpad files, spawn subagents, or proceed
to iteration 2.
