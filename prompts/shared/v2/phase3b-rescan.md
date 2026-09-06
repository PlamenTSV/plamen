# Phase 3b: Additional Breadth Pass (Thorough Mode Only)

This phase runs after first-pass breadth and before inventory. It owns only
additional analysis artifacts produced before inventory synthesis.

> **Loaded by**: The V2 driver's `rescan` subprocess.
> **Mode gate**: Thorough mode ONLY. Skip in Light and Core mode.
> **Purpose**: Counter attention saturation after first-pass breadth by running
> a smaller, independent breadth pass over under-explored surfaces.

---

## V2 Phase Position

This phase runs after first-pass breadth analysis. Its job is to add
under-explored breadth coverage by writing additional `analysis_*.md`
files. This subprocess does NOT merge findings or perform finding-level
synthesis.

---

## Inputs

Read first-pass breadth outputs matching `{SCRATCHPAD}/analysis_*.md` and
the recon artifacts needed to assign under-explored surfaces. Treat existing
first-pass findings as an exclusion set:

- Do not report the same root cause.
- Do not report the same location with only a renamed title.
- Prefer vulnerability classes and files that are weakly represented in the
  first-pass breadth outputs.

On retry, ignore this phase's own prior outputs when building the first-pass
exclusion set; use them only to determine which declared additional outputs are
already substantive and can be skipped.

### EXCLUSION SOURCE RULE (MANDATORY — recall-safe, no belief-based drops)

**RS-X — Referent-bound exclusion preservation.** Apply this step to every
rescan/per-contract row. An exclusion is valid only with the provided concrete
referent and the excluded candidate's own location, mechanism, and harm.

You may mark a candidate as a duplicate and exclude it from your output ONLY
when you can cite a CONCRETE entry that already exists in the provided
exclusion universe — i.e. a real finding ID (e.g. `[B1-2]`, `[RS1-3]`) or a
real `file:Lnnn` location that appears in the first-pass `analysis_*.md` or
`analysis_rescan_*.md` outputs you were given.

- A bug you BELIEVE is "already known" but cannot point to in the provided
  exclusion list MUST be emitted as a new `[PCn-k]` finding. When in doubt,
  EMIT — never drop a real bug on the assumption that someone else found it.
- Self-generated exclusion sections (e.g. `## Exclusion List (Already Found)`,
  "already known", "not duplicated") that assert prior knowledge WITHOUT a
  cited provided-list referent are PROHIBITED. The provided exclusion set is
  the only authority on what is already known; your own belief is not.
- Every exclusion entry you do write MUST carry its referent inline, e.g.
  `EXCLUDED [PCn-x] dup of [B1-2]` or
  `EXCLUDED [PCn-x] dup of Vault.sol:L88`.
- Every exclusion entry MUST ALSO carry the EXCLUDED CANDIDATE'S OWN content:
  its concrete `file:Lnnn` location, the mechanism (WHAT is wrong), and a
  one-line harm (WHAT goes wrong if real). Example:
  `EXCLUDED [PCn-x] encoder byte-width mismatch at Encoder.sol:L412 —
  truncates the high byte so a crafted account passes validation → asset
  mis-routing; dup of [B1-2]`.
  A bare `EXCLUDED [PCn-x] already known` with no location and no harm is a
  CONTENT-LESS stub: if its referent is also missing it cannot be dedup'd or
  resolved, and downstream it is routed to an APPENDIX-only disposition — it
  will NOT reach the client body. Carry real content so a genuinely-unique
  excluded bug can be resolved into a concrete finding instead of an
  unverifiable stub.

A referent-less exclusion is treated by the driver as a suppressed real bug:
the candidate is re-emitted downstream so it cannot vanish. A content-BEARING
re-emit (own location + harm) is dedup'd against existing findings or resolved
normally; a CONTENT-LESS re-emit is kept at Informational in the appendix for
human review (downgraded, never dropped).

---

## Work Plan

### RS-0 — Under-explored-surface selection

Use recon plus first-pass outputs to select a concrete weakly represented
surface within the assigned focus. Record the evidence for that selection;
the output filename or worker number is not itself a focus.

Spawn 2-3 additional breadth agents in bounded parallel calls. Each agent gets
one broad non-overlapping or intentionally cross-checking scope, depending on
the gaps visible from first-pass breadth and recon artifacts.

Focus areas that usually reveal attention-saturation misses (the driver assigns
these typed steps across independent workers):

1. **RS-1 — Cross-function state:** cross-function state inconsistencies.
2. **RS-2 — Asymmetric operations:** asymmetric operations and branches.
3. **RS-3 — Paired encoding:** parameter/encoding mismatches between paired functions.
4. **RS-4 — Economic edges:** economic assumptions violated under edge conditions.
5. **RS-5 — Time/lifecycle:** time-dependent state that goes stale under operation sequences.

In Thorough mode, a focused per-contract/cluster pass is mandatory. Keep it in
this same subprocess unless the phase graph launches a separate per-contract
producer. Write it under this phase's owned additional-analysis output family.

### RS-PC — Localized per-contract/cluster pass

For the exact assigned contract or cluster, enumerate its externally reachable
state transitions and boundaries, apply RS-1 through RS-5 where relevant, and
record which were applicable. This is one localized operator; it does not
authorize reading or writing another worker's output.

---

## Subagent Output Contract (MANDATORY -- include in every Task prompt)

Each Task subagent you spawn for this phase must obey the following contract.
The coordinator MUST include these rules verbatim in the spawned subagent's
prompt.

1. **Reservation write is OK as crash insurance.** Writing a short header
   (e.g. `# Per-Contract Agent N: <cluster>`) at the start of your work to
   reserve the output file is allowed and encouraged -- it lets the driver
   recover partial work if your subprocess is interrupted.

2. **The reservation is NOT your output.** Your final output is the same file
   overwritten with your full findings. A subagent that returns analytical
   content as text while leaving the file at its reservation header has
   produced an empty output as far as the rest of the pipeline is concerned.

3. **End-of-task write assertion (HARD GATE).** Immediately before returning,
   you MUST:
   - Read your assigned output file from disk.
   - If its size is below 1 KB OR it contains only the reservation header,
     overwrite it now with your full findings (or with a substantive
     explanation of why no findings apply, per the scope-review fallback in
     the Output Contract above).
   - Only after the file contains your real content may you return.

4. **Return message is status only.** Your return value to the coordinator is
   a one-line status (e.g. `DONE: 3 findings in <cluster>` or
   `DONE: scope-review only -- no clustered findings`). Do NOT put findings,
   analysis, or any other substantive content in the return value -- that is
   the file's job. Substantive content in the return message is a contract
   violation: the coordinator discards it and the pipeline cannot consume it.

5. **A stub return is a violation.** If you find yourself wanting to return
   findings as text because "the file is just a reservation," stop -- that is
   the failure mode this contract exists to prevent. Overwrite the file
   first, then return the one-line status.

---

## FIRST ACTION (MANDATORY): declare your output manifest

Before spawning any rescan/per-contract worker, write
`{SCRATCHPAD}/rescan_manifest.md` listing the EXACT output filenames you intend
to produce this phase -- one concrete filename per planned worker. Example:

```
# Rescan Manifest
- analysis_rescan_1.md
- analysis_rescan_2.md
- analysis_percontract_core.md
- analysis_percontract_scope_review.md
```

Rules:
- List concrete filenames (e.g. `analysis_rescan_1.md`), NOT the glob form
  `analysis_rescan_*.md`.
- Declare 2-3 `analysis_rescan_*.md` files and at least one
  `analysis_percontract_*.md` (or `analysis_percontract_scope_review.md` if no
  meaningful per-contract cluster exists).
- The driver gate is EXACT against this manifest: every declared file must
  exist and be substantive before the phase passes. Declare only files you
  will actually produce, and produce every file you declare. Do NOT declare
  files you cannot complete.

## Output Contract

Write only this phase's additional analysis files (every file you declared in
`rescan_manifest.md`):

- `analysis_rescan_*.md`
- at least one `analysis_percontract_*.md`

Each additional agent writes exactly one output file. If no meaningful
per-contract cluster exists, still write
`analysis_percontract_scope_review.md` with a substantive explanation of why
clustered per-contract analysis is not applicable and what files were checked.

---

## Orchestrator Termination Contract (HARD STOP)

<!-- BUILD-STRIP: raw contract tokens for standalone contract tests only: depth_*.md -->

As soon as every filename declared in `rescan_manifest.md` is on disk and
substantive (not a reservation stub, not a placeholder, and large enough for
the driver gate), return immediately:

```
DONE: rescan {N} files, per-contract {M} files written
```

Any output written by the orchestrator beyond this contract is
discarded by the driver and wastes session tokens. Do not produce
files outside the two artifact families above.
