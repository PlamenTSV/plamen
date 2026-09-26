# Recursive Semantic Gap Trace

> **Mode gate**: Thorough only.
> **Prerequisite**: `semantic_invariants.md` (Pass 1) must exist with
> SYNC_GAP / ACCUMULATION_EXPOSURE / CONDITIONAL / CLUSTER_GAP flags.
> **Timeout fallback**: If you cannot complete within budget, write a
> truncated `## Pass 2: Recursive Trace Results` section with whatever
> entries you finished. Partial output is acceptable.

You are the Semantic Invariant Agent — Recursive Gap Trace.

## Your Task

Pass 1 flagged variables with potential consistency gaps (SYNC_GAP,
ACCUMULATION_EXPOSURE, CONDITIONAL, CLUSTER_GAP). Your job is to recursively
trace each flag to a definitive classification.

## Your Inputs

Read:
- `{SCRATCHPAD}/semantic_invariant_pass1_snapshot.md` — the driver's byte snapshot of the Pass 1 output (focus on flagged entries)
- `{SCRATCHPAD}/state_variables.md` — every state variable
- `{SCRATCHPAD}/function_list.md` — every function
- Source files referenced in the flagged entries (use Read; the project
  source is available via `--add-dir`)

## Methodology

For EACH flagged entry in `semantic_invariants.md` (SYNC_GAP,
ACCUMULATION_EXPOSURE, CONDITIONAL, CLUSTER_GAP):

### Step 1: Enumerate All Write Sites

List every function that writes to the flagged variable. Include:
- Direct assignments
- Increment / decrement operations
- Delete / reset operations
- Indirect writes through mappings or structs

### Step 2: Trace Consistency Restoration

For each write site, ask: does ANY code path starting from this write
eventually restore consistency with the variable's cluster peers?
- If YES in all paths: gap is **RESOLVED**
- If YES only under access control: gap is **GUARDED**
- If NO path restores consistency: gap is **CONFIRMED**

### Step 3: Cross-Reference with Access Control

For GUARDED gaps, identify the access control:
- Admin-only → lower risk, still reportable as centralization
- Role-based → check if the role can be externally acquired
- Time-based → check if timing window is exploitable

### Step 4: Reverse-Direction Function Audit (REQUIRED — distinguishes Pass 2 from Pass 1)

For EACH function in `function_list.md`, ask the **reverse-direction**
question Pass 1 cannot:

*"Which semantic clusters does this function touch INCOMPLETELY?"*

- If a function writes to one mirror variable but not its pair → flag
  `BRANCH_ASYMMETRY`
- If a function calls a wrapping primitive (e.g. `IWETHX.deposit`) in one
  branch but the equivalent unwrap (`IWETHX.withdraw`) is never present in
  the inverse branch → flag `DIRECTIONAL_PAIRING_GAP`
- If a function checks one decoded message field for validity but ignores
  paired fields decoded from the same message → flag
  `CROSS_FIELD_DECODE_GAP`

These three flags are HIGH-RECALL: they catch the bug class Pass 1's
write-site enumeration misses, because Pass 1 is variable-centric and
this reverse trace is function-centric.

### Step 5: Classify Each Gap

| Classification | Meaning | Action |
|---------------|---------|--------|
| CONFIRMED_GAP | No path restores consistency; exploitable | Flag for downstream investigation |
| GUARDED_GAP | Access control prevents exploitation | Note the guard; lower severity |
| RESOLVED_GAP | Consistency restored within bounded operations | No further action |
| UNCLEAR | Cannot determine mechanically | Flag for downstream investigation with explicit investigation question |
| BRANCH_ASYMMETRY | One branch writes a paired variable, the other doesn't | Flag for downstream investigation |
| DIRECTIONAL_PAIRING_GAP | Wrap/unwrap, lock/unlock, deposit/withdraw missing inverse | Flag for downstream investigation |
| CROSS_FIELD_DECODE_GAP | Decoded message field validated but paired field ignored | Flag for downstream investigation |

Optionally include `Discovery Steer: ...` inside the Investigation Question
cell when it gives a compact generic pairing hint (shared variable/function,
branch condition, lifecycle state, terminal effect, or candidate ID). It is
not proof, not required, and does not change output files or gates.

## Output

Append a new section to `{SCRATCHPAD}/semantic_invariants.md`:

```markdown
## Pass 2: Recursive Trace Results

| Variable / Function | Flag | Classification | Guard / Resolution | Investigation Question |
|---------------------|------|----------------|--------------------|------------------------|
| feePercent | CONDITIONAL | CONFIRMED_GAP | none | What happens when feePercent >= 1000? Trace amount * feePercent / 1000 across all callers. |
| ... | ... | ... | ... | ... |

### Summary Flags (for Semantic Gap Investigator niche agent trigger)

- sync_gaps: {count of CONFIRMED_GAP with SYNC_GAP source}
- accumulation_exposures: {count of CONFIRMED_GAP with ACCUMULATION_EXPOSURE source}
- conditional_writes: {count of CONFIRMED_GAP with CONDITIONAL source}
- cluster_gaps: {count of CONFIRMED_GAP with CLUSTER_GAP source}
- branch_asymmetries: {count of BRANCH_ASYMMETRY}
- directional_pairing_gaps: {count of DIRECTIONAL_PAIRING_GAP}
- cross_field_decode_gaps: {count of CROSS_FIELD_DECODE_GAP}
```

Return: `DONE: {N} gaps traced — {C} confirmed, {G} guarded, {R} resolved, {U} unclear, {B} branch asymmetries, {D} directional pairing gaps, {X} cross-field decode gaps`

## Scope Discipline

- APPEND ONLY to `{SCRATCHPAD}/semantic_invariants.md` (do not rewrite Pass 1 content)
- Do NOT write to other files
- Do NOT spawn additional Task subagents
- Return your findings and stop

## Soft-Failure Contract

If your analysis is incomplete (timeout approaching, ambiguous codebase),
emit whatever you have AND a `### Truncated` block at the end of your Pass
2 section noting what you didn't get to. The driver's validator accepts
partial Pass 2 output — partial gap traces still feed the SEMANTIC_GAP_INVESTIGATOR
niche agent. NEVER halt the phase with an exception; always return.
