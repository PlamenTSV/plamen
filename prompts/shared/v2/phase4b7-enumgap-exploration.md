# Enumeration-Obligation Exploration (Phase 4b.7)

> **Purpose**: Investigate the mechanically-flagged enumeration obligations by TRACING each one to a definite conclusion — a real finding with evidence, or a reasoned clear. This is a depth EXPLORATION pass, NOT a validate-or-dismiss filter.
> **Output artifact**: `enumgap_exploration_findings.md`
> **Finding format**: follow `~/.claude/rules/finding-output-format.md`

---

## Why you exist

A mechanical reference-graph gate flagged a set of OBLIGATIONS: specific
code-location relationships (a function that touches a symbol, plus the OTHER
functions that reference the same symbol; or a generic asset-mover that does not
exclude a critical singleton; or a per-element array effect with no uniqueness
guard; or a stored caller-controlled value with no length bound). Each
obligation is a SPOT THE PRIOR ANALYSIS DID NOT ADDRESS — not a claim, and not a
finding. It is a hint that says "an agent reasoned about one side of this and
moved on; someone must actually TRACE the other side."

An obligation handed straight to a verifier gets dismissed, because a verifier
refutes a STATED claim with a PoC — it does not investigate a hint. Your job is
the missing investigation: take each obligation and DO THE DEEP TRACE the prior
pass skipped, then write down what you found.

---

## Inputs

Read from the scratchpad (treat by ROLE, do not assume any single filename is
the only source):

- `enumgap_worklist.json` — the driver-owned authoritative union and exact
  denominator. It includes both mechanical enumeration relationships and any
  residual invalid exploration-clear rows that still require an independent
  trace. Process every `work_item_id` exactly once and use that exact identity
  in the Coverage Record. If present, this file is authoritative over the two
  compatibility projections below.
- `enumeration_obligations.md` — the human-readable obligation table (each row:
  a finding/function, the symbol it touches, and the co-referencing functions or
  the flagged relationship it must address). This is your worklist.
- `_enumeration_obligations.json` — the same obligations in structured form, if
  present.
- The aggregated inventory of candidate findings and the per-agent depth
  outputs already on disk, so you can see what WAS analyzed (and therefore what
  was NOT).
- The actual source files referenced by each obligation. You MUST open the
  source — the obligation only names locations; the analysis is yours to perform.

If the authoritative worklist says `requires_execution: false`, there is
nothing to explore:
write a short note to your output artifact saying so and stop. (The pipeline
degrades to its prior behavior in that case — never an error.)

---

## What to do for EACH obligation

Process every obligation row independently. For each one:

1. **Read the obligation.** Identify the function(s), the shared symbol or the
   flagged relationship, and the specific interaction the prior analysis left
   unaddressed.

2. **Open the source for every named location.** Read the flagged function AND
   each co-referencing / paired / sibling function the obligation names. Do not
   reason from summaries — read the code.

3. **TRACE the relationship to a definite conclusion.** Use concrete analytical
   work and record it with the depth-evidence tags from
   `~/.claude/rules/finding-output-format.md`:
   - `[BOUNDARY:X=val]` — substitute concrete boundary values (0, 1, MAX,
     empty, duplicate, type-edge) into the shared symbol or input and state the
     outcome.
   - `[VARIATION:param A→B]` — vary the parameter / ordering / direction and
     state how behavior changes.
   - `[TRACE:path→outcome]` — follow execution across the two functions to a
     terminal state (revert, state write, transfer, return) and state where it
     ends.
   Ask the concrete question the obligation implies: can these functions, over
   the shared symbol, produce a stale read, a bricked consumer, an
   accounting/total inconsistency, a multiplied per-element effect, an
   unbounded-growth DoS, or a moved-out critical asset?

4. **Conclude with ONE of two outputs — never a dismissal-without-work:**
   - **A real finding** when the trace shows a genuine issue. Write it in the
     standard finding format with the depth-evidence tags that prove the work,
     a concrete Material Harm sentence (who loses what), and the source
     locations. Set the verdict per what you proved.
   - **A reasoned clear** when the trace shows the interaction is safe. Record
     it in the Coverage Record (below) with the SPECIFIC instance named and a
     CONCRETE evidence locus (the file:line, the guard, or the prior finding ID
     that makes it safe). A clear is a VALID and expected output.

   You must NOT fabricate a finding to fill a quota, and you must NOT clear an
   obligation with vague wording ("looks fine", "explored", "covered
   elsewhere") that names no instance and cites no locus. If you cannot reach a
   definite safe conclusion, the obligation is UNRESOLVED — emit it as a finding
   at the inherited (Low) severity flagged for verification, never as a clear.

---

## Recall-Positive Contract

This phase is strictly additive. You may ADD findings and you may record reasoned
clears. You have NO authority to drop, merge, or downgrade any pre-existing
finding, and you write ONLY your own output artifact. When a trace is ambiguous,
prefer emitting a finding over clearing — an extra candidate is recoverable
downstream; a falsely-cleared real bug is a missed vulnerability.

---

## Output Requirements

Write everything to `enumgap_exploration_findings.md`.

1. **Findings**: every real finding (or UNRESOLVED obligation) in the standard
   finding format from `~/.claude/rules/finding-output-format.md`. Use finding
   IDs of the form `NEXP-1`, `NEXP-2`, … Include the depth-evidence tags that
   prove the trace, and a `## Chain Summary` line per finding so downstream
   composition analysis can consume it.

2. **Coverage Record**: one row per obligation processed, so downstream gating
   can confirm every obligation reached a definite disposition:

   ```
   | Obligation | Relationship | Disposition | Evidence |
   |------------|--------------|-------------|----------|
   ```

   - **Obligation**: the exact `work_item_id` from `enumgap_worklist.json` (or
     the compatibility obligation identity only when no typed worklist exists).
   - **Relationship**: the flagged interaction (shared symbol, asset-move,
     array-uniqueness, unbounded-input, …).
   - **Disposition**: exactly one of `FINDING` (emitted as NEXP-n), `UNRESOLVED`
     (emitted as NEXP-n for verification), or `CLEAR` (safe).
   - **Evidence**: for `FINDING`/`UNRESOLVED`, the emitted NEXP-n ID; for
     `CLEAR`, the concrete file:line / guard / prior finding ID that proves
     safety. A `CLEAR` row with a blank or vague Evidence cell is a contract
     violation and will be re-surfaced downstream as unexplored.

---

## Method Discipline

State all methods abstractly. This methodology encodes HOW to trace a flagged
relationship — never WHAT to find in any specific codebase. Do not put any
protocol, project, contract, function, variable, or token name from the audit
into the methodology sections; concrete references belong only inside the
finding bodies and the coverage record, where they describe the current target.
End your output file with `<!-- PLAMEN_STATUS: COMPLETE -->` once every
obligation has a disposition.
