# Phase 4c Chain Analysis Iteration 2 — Targeted Cross-Class Composition

You are the Chain Composition Agent, ITERATION 2 (targeted cross-class pass).
Execute the instructions below directly and stop. Do not spawn subagents.

> **Trigger**: Chain Agent 2 reported at least one unexplored cross-class
> Medium+ finding pair. If `composition_coverage.md` shows zero
> unexplored cross-class Medium+ rows, this phase should not have been
> spawned — return immediately with `DONE: 0 new chains (no unexplored pairs)`.
> **Reference (not load-bearing)**: Full multi-agent methodology is in
> `~/.claude/rules/phase4c-chain-prompt.md`.

---

## Your Inputs

Read:
- `{SCRATCHPAD}/chain_candidate_pairs_iter2.md` (**authoritative bounded tail packet; evaluate EVERY real row**)
- `{SCRATCHPAD}/composition_coverage.md` (focus on NOT EXPLORED rows, especially cross-class Medium+ pairs)
- `{SCRATCHPAD}/chain_hypotheses.md` (do NOT duplicate existing chains)
- `{SCRATCHPAD}/precedent_context.md` (OPTIONAL deterministic investigation
  projection; consult only after the code-derived disposition/plan is sealed)
- `{SCRATCHPAD}/findings_inventory.md` — **FALLBACK-ONLY, single-finding, on-demand.** Open ONE finding's block only for a specific unexplored-pair detail. **Do NOT bulk-read this file** — on large audits it is 100K+ of prose and pulling it into one turn triggers context-collapse / autocompact-thrash (zombie-hangs the phase). Work from `composition_coverage.md` + `chain_hypotheses.md`.

The first chain analysis identified `{M}` chains. Analyze every row in the
current mechanically bounded shard (normally at most 15). The driver owns the
full exact denominator and advances a digest-bound cursor through later shards;
do not infer anything about pairs not present in this shard. Remaining pairs
stay explicit unresolved-composition work in the typed ledger and bounded
assurance projection; never relabel them EXCLUDED/no-signal.

---

## Your Task

For EACH manifest-bound pair in the current shard (all severities/classes):
1. Read both findings' full details
2. Check: does A's postcondition enable B's precondition? And vice versa?
3. If YES: create CHAIN HYPOTHESIS using the Chain Hypothesis Format (see Agent 2 prompt at `~/.claude/prompts/shared/v2/phase4c-chain-agent2.md` → Chain Hypothesis Format section)
4. After sealing the code-derived disposition and first test plan, optionally
   read `precedent_context.md` for additive positive paths/test ideas. Do not
   call RAG, vulnerability-database, WebSearch, or WebFetch tools. Precedent
   cannot validate the code, support a negative, change severity/disposition,
   force `CONTESTED`, satisfy proof, or reduce investigation.

Optional Discovery Steer or `discovery: ...` signals in the pair details are
only hints for what to inspect first. They are not proof and do not create any
new output requirement.

For a `role: mutual-zero` row, confirm both complementary facts in source: an
authentication anchor is operational while zero/unarmed, and an accepted
degenerate input derives to zero/null. Reject armed/inert-until-armed anchors
and fail-closed zero rejection. Compose only if the conjunction reaches a
privileged or otherwise harmful effect not established by either half alone.

---

## Output

Write only `{SCRATCHPAD}/chain_iteration2.md` — the iteration-2 summary, every
new chain hypothesis in full, and the exact tail-pair disposition delta. Treat
`chain_hypotheses.md` and `composition_coverage.md` as immutable inputs. After
your output passes its gates, a deterministic driver merge applies the delta
with before/after hashes and identity-parity checks.

In `chain_iteration2.md`, emit this exact reconciliation table with one row for
EVERY pair in `chain_candidate_pairs_iter2.md`:

`## Tail Pair Dispositions`

`| Pair ID | Finding A | Finding B | Disposition | Evidence |`

Copy each `Pair ID` exactly from the shard. Disposition must be `EXPLORED`,
`COMPOSED`, `REJECTED`, or `DEFERRED`. A `COMPOSED` row must cite the new
`CH-N` section identity in Evidence; the chain is a candidate for ordinary
independent verification, never proof at this phase.
`Evidence` must state the concrete semantic comparison/result; a blank or dash
does not count as consumed. Never omit a shard row.

Return: `DONE: {N} new chains from {U} unexplored pairs`

SCOPE: You MAY read `chain_candidate_pairs_iter2.md`, `composition_coverage.md`, `chain_hypotheses.md`, `findings_inventory.md`, and directly referenced source files as read-only inputs. Write ONLY to `chain_iteration2.md`. MUST NOT modify `chain_hypotheses.md`, `composition_coverage.md`, upstream inventory, depth, verification, or report artifacts. Do NOT proceed to verification or report. Return your findings and stop.
