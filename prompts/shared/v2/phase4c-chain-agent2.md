# Phase 4c Chain Analysis Agent 2 — Chain Matching and Composition Coverage

You are Chain Analysis Agent 2: Chain Matching and Composition Coverage.
Execute the instructions below directly and stop. Do not spawn subagents.

> **Prerequisite**: Chain Agent 1 has already run and produced
> `hypotheses.md`, `finding_mapping.md`, and `enabler_results.md`. You
> read those outputs; do NOT redo the grouping or enabler enumeration.
> **Reference (not load-bearing)**: Full multi-agent methodology is in
> `~/.claude/rules/phase4c-chain-prompt.md`. This file contains only the
> Agent 2 directive.

---

## Your Inputs

Read:
- `{SCRATCHPAD}/hypotheses.md` (grouped hypotheses from Agent 1)
- `{SCRATCHPAD}/finding_mapping.md` (finding → hypothesis mapping from Agent 1)
- `{SCRATCHPAD}/enabler_results.md` (enabler enumeration + cross-state interactions from Agent 1)
- `{SCRATCHPAD}/variable_finding_map.md` (qualified state-symbol→finding cross-reference from the driver-owned graph resolver; if missing, grep is only a degraded recall fallback and cannot establish enumeration completeness)
- `{SCRATCHPAD}/chain_candidate_pairs.md` (pre-filtered pairs with shared state/identifier — driver-produced bounded Agent-2 packet. Evaluate every listed pair. Additional real-signal pairs are routed to a bounded iteration-2 packet or a durable coverage-gap ledger; they are not automatically covered.)
- `{SCRATCHPAD}/findings_inventory.md` — **FALLBACK-ONLY, single-finding, on-demand.** Open ONE specific finding's block only when a candidate pair's detail is missing from the bounded inputs above (hypotheses / finding_mapping / enabler_results / variable_finding_map / chain_candidate_pairs). **Do NOT bulk-read this file** — on large audits it is 100K+ of finding prose, and pulling it into one turn is the context-collapse / autocompact-thrash trigger this phase MUST avoid (it zombie-hangs the phase). The bounded ledgers are the authoritative working set.

The pre-filter may include optional `discovery: ...` Shared Signal values
derived from finding metadata. Treat them as prioritization hints only; they
are not proof and must be confirmed from finding details or source.

A `role: mutual-zero` signal is also nomination-only. Confirm BOTH halves in
source: an authentication anchor can remain zero/unarmed while verification is
operational, and a degenerate input derives to zero/null and is accepted. Reject
the pair if arming is atomic/inert-until-armed or the verifier rejects the
degenerate/zero result fail-closed. Create a chain only when the conjunction
reaches a privileged or otherwise harmful effect that neither half proves alone.

For specific chain candidates, read the relevant source files directly.

After all code-derived pair dispositions and first test plans are sealed, you
may additionally read `{SCRATCHPAD}/precedent_context.md` when present. It is a
deterministic investigation projection, never negative or decision authority.

---

## PHASE 2: CHAIN ANALYSIS — Match Postconditions to Preconditions

### Step 2.0: Load Pre-Filtered Pairs (if available)

Read `{SCRATCHPAD}/chain_candidate_pairs.md`. If present:
- Evaluate ONLY the pairs listed in the STATE Pairs and TYPE Pairs tables
- For each pair: read both findings' full details, verify the mechanical match is semantically valid, and apply the semantic composition checks in Step 2.0a within this same allowed pair set
- If a pair's Shared Signal mentions discovery metadata, use it only to focus the review; source behavior still decides whether composition exists.
- Create CHAIN HYPOTHESIS for valid matches
- Mark each evaluated pair in `composition_coverage.md` as EXPLORED, COMPOSED, REJECTED, or DEFERRED with the reason
- Do not disposition out-of-packet pairs. The driver reconciles the complete
  set into the iteration-2 packet and durable coverage-gap ledger; never emit
  an aggregate EXCLUDED count from the bounded file.

If `chain_candidate_pairs.md` is MISSING, fall back to the original algorithm below.

### Step 2.0a: Semantic Composition Within Candidate Pairs

Do not stop at exact postcondition-to-precondition matching. For each allowed pair, check whether the two findings compose through shared semantic meaning even when their descriptions use different vulnerability classes.

Create a chain hypothesis when the pair has a plausible ordered attack sequence and at least one of these generic composition patterns is supported by the finding details or source:

1. **Branch precondition + arithmetic/rounding/terminal-effect**: one finding can make a branch condition, threshold, guard, or mode reachable; the other finding turns that reachable branch into arithmetic loss, rounding bias, accounting skew, liquidation/settlement behavior, stuck value, denial of service, or another terminal effect.
2. **Shared-state lifecycle pair**: one finding writes, initializes, skips, delays, resets, or finalizes state that the other finding later assumes has a different lifecycle phase, freshness, monotonicity, or authorization history.
3. **Write/read meaning drift**: one finding writes a value with one unit, scale, sign, epoch, owner, status, or accounting meaning; the other reads or compares that value under a different meaning, causing a harmful decision or calculation.

Use bounded prioritization:
- With `chain_candidate_pairs.md`: evaluate semantic composition only for the listed pairs; do not add out-of-file pairs.
- Without `chain_candidate_pairs.md`: prioritize pairs sharing an explicit variable, function, branch condition, modifier/guard, arithmetic mechanism, token/accounting effect, or lifecycle state. Evaluate exact shared-state/function pairs first, then branch+effect pairs, then meaning-drift pairs.
- Cap fallback exploration at the highest-signal set needed to avoid runtime blowups: at most 5 candidate enablers per blocked/partial finding and at most 50 evaluated pairs total unless the file already lists fewer. Mark additional plausible but unevaluated pairs as DEFERRED in `composition_coverage.md` with the prioritization reason.

Rejection must be explicit. Reject a semantic pair when ordering is impossible, the shared term is only nominal, required attacker control is missing, source behavior contradicts the composition, or the combined impact does not exceed either standalone finding.

### Step 2.1: Original Algorithm (fallback if no pre-filter)

For each PARTIAL or REFUTED finding:
1. Extract its missing precondition and type (STATE/ACCESS/TIMING/EXTERNAL/BALANCE)
2. **For STATE-type preconditions**: extract the specific qualified state symbol(s). Use `variable_finding_map.md` to find ALL findings mechanically bound to the SAME symbol (declaration/read/write/reference). Do not merge same-bare fields from different contracts or modules, and do not infer extra pairs outside the driver-owned bounded ledgers.
3. Search CONFIRMED/PARTIAL findings for matching postconditions and the semantic composition patterns above — across ALL severity tiers and vulnerability classes, using the bounded prioritization limits from Step 2.0a
4. If found: Create CHAIN HYPOTHESIS with combined attack sequence

### Chain Hypothesis Format

```
## Chain Hypothesis CH-{N}
### Blocked Finding (A)
- ID: [XX-N], Title: [Attack that was blocked]
- Original Verdict: REFUTED/PARTIAL, Missing Precondition: [What was missing], Type: [TYPE]
### Enabler Finding (B)
- ID: [YY-M], Title: [Finding that creates the precondition]
- Original Verdict: CONFIRMED/PARTIAL, Postcondition Created: [What it creates], Type: [TYPE]
### Chain Match
- Match Strength: STRONG / MODERATE / WEAK
- Match Reasoning: B creates the exact precondition A needs
### Combined Attack Sequence
1. [Step from B]: Execute enabler action
2. [Step from A]: Execute previously-blocked attack
3. [Impact]: Combined effect
### Severity Reassessment
```

Chain Severity Matrix:

| Original A | Original B | Chain Severity |
|------------|------------|----------------|
| REFUTED | Any | Re-evaluate A with B's postcondition |
| LOW | LOW | MEDIUM |
| LOW | MEDIUM+ | HIGH |
| MEDIUM | MEDIUM | HIGH |
| MEDIUM | HIGH | HIGH |
| HIGH | Any | HIGH or CRITICAL |
| CRITICAL | Any | CRITICAL |

Chain severity is NEVER lower than the higher of Finding A or Finding B.
- Upgrade if: combined impact > $100k AND profitability > 2x → CRITICAL
- Upgrade if: combined impact > $10k AND profitability > 2x → minimum HIGH

### Composition Coverage Map

After chain matching, write a coverage map of finding pairs you considered:

| Finding A | Finding B | Explored? | Result | Notes |
|-----------|-----------|-----------|--------|-------|

Rules: List pairs where at least one has a postcondition or missing precondition. Cross-class pairs (state + token, access + external) are HIGH PRIORITY.

Each row must record one of:
- `EXPLORED`: evaluated but no chain created yet because more evidence is needed
- `COMPOSED`: semantic or mechanical composition produced a chain hypothesis; include the CH id
- `REJECTED`: evaluated and rejected; include the concrete reason
- `DEFERRED`: plausible but not evaluated because of bounded prioritization; include what shared variable/function/branch/arithmetic mechanism caused it to be noticed

Coverage must explicitly state whether branch+effect, shared-state lifecycle, and write/read meaning-drift pairs were explored, composed, rejected, or deferred. Do not silently drop these semantic pairs just because they are not exact postcondition/precondition matches.

---

## PHASE 3: CENTRALIZED PRECEDENT STEERS (ADDITIVE ONLY)

After every code-derived pair disposition and first chain test plan is sealed,
you may read the driver-produced `precedent_context.md`. Do not call RAG,
vulnerability-database, WebSearch, or WebFetch tools. The projection may add a
positive path or test idea to an already open/positive row. It may not reject a
pair, support a negative disposition, change confidence/severity/verdict,
satisfy proof, or reduce remaining composition work. If the projection is
absent/unavailable, continue from code with no penalty and no inferred safety.

---

## Output

Do **not** update `{SCRATCHPAD}/hypotheses.md`. It is an immutable Agent-1
artifact. Downstream consumers read your dedicated chain delta directly.

Write:
- `{SCRATCHPAD}/synthesis_full.md` — full analysis (enabler + grouping + chain results)
- `{SCRATCHPAD}/chain_hypotheses.md` — chain summary with:
  1. Chain summary table: `Chain ID | Finding A | Missing Precondition | Finding B | Postcondition Match | Chain Severity`
  2. Detailed chain hypotheses
  3. Findings status update (which findings upgraded)
  4. Verification priority order
- `{SCRATCHPAD}/composition_coverage.md` — composition coverage map

Do NOT rely on `chain_hypotheses.md` to implicitly serve as composition coverage. `composition_coverage.md` must be written as its own file.

Return: `DONE: {M} chains identified, {K} severity upgrades, {U} unexplored pairs remaining, verification priority: [list]`

SCOPE: You MAY read the inputs listed in "Your Inputs" as read-only inputs. Write ONLY to `chain_hypotheses.md`, `composition_coverage.md`, and `synthesis_full.md`. MUST NOT modify `hypotheses.md`, `finding_mapping.md`, `enabler_results.md`, `variable_finding_map.md`, `chain_candidate_pairs.md`, `findings_inventory.md`, or other artifacts. Return your findings and stop.
