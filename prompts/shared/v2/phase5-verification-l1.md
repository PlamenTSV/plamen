# Phase 5: L1 Verification (Shard-Local Model)

> **Audience**: V2 driver subprocess running a verify shard for L1 infrastructure audits.
> **Architecture**: Inline shard-local verification — no nested subagents.
> **Excludes**: all downstream verification review, consistency, aggregate, and report phases.
> **Isolation**: Downstream Step 5 sub-phases intentionally withheld from this shard prompt.

---

## Verification Model

Read only the shard manifest named in the driver prefix for this phase. Do not
open other shard manifests.

Process the assigned rows directly in the current phase agent. Do NOT spawn one
subagent per finding. Prior L1 runs showed that nested verifier swarms dominate
usage and do not improve promotion quality compared with bounded shard-local
verification.

The driver uses severity-aware bounded shards and runs every verify shard on
Sonnet: Critical/High target ~8 rows, Medium target ~12 rows, Low/Info target
~18 rows. Empty shard slots are skipped by the driver, so this does not add
cost on smaller audits.

---

## Bug-Class Routing Table

| Bug class | Preferred evidence tag |
|---|---|
| Fork-diff / cross-env | `[DIFF-PASS]` |
| Non-determinism | `[NON-DET-PASS]` |
| Consensus invariant | `[CONFORMANCE-PASS]` |
| Network DoS | `[FUZZ-PASS]` |
| Light-client proof | `[CONFORMANCE-PASS]` |
| RPC / execution | `[POC-PASS]` |
| BLS / crypto | `[CONFORMANCE-PASS]` |
| SCIP-backed trace | `[LSP-TRACE]` |
| Fallback (no mechanical path) | `[CODE-TRACE]` |

### Evidence Tag Definitions

| Tag | Meaning | Weight |
|-----|---------|--------|
| `[DIFF-PASS]` | Cross-client or fork-diff comparison confirms behavioral divergence | Mechanical proof |
| `[CONFORMANCE-PASS]` | Verified against protocol specification or formal invariant | Mechanical proof |
| `[NON-DET-PASS]` | Demonstrated non-deterministic execution under controlled conditions | Mechanical proof |
| `[FUZZ-PASS]` | Fuzzer found a triggering input or resource exhaustion path | Mechanical proof |
| `[LSP-TRACE]` | SCIP index citation proving call graph / data flow path | Strong trace (requires scip/ citation) |
| `[POC-PASS]` | Compiled, executed, assertions PASSED | Mechanical proof |
| `[CODE-TRACE]` | Manual trace with concrete values, no execution | Fallible — caps at CONTESTED |

---

## Verifier row template

For each assigned finding in the shard manifest, execute verification inline using
this template:

```
Phase 5 Verifier for {FINDING_ID}: {TITLE}
Location: {LOCATION} | Bug class: {CLASS} | Preferred tag: {TAG} | Primary Artifact: {PRIMARY_ARTIFACT}
PoC Class: {POC_CLASS} | Optional test infrastructure: {SCRATCHPAD}/test_infrastructure.md
Produce mechanical verification per preferred workflow. If it fails, try one variant before
falling back to [LSP-TRACE] (requires scip/ citation) or [CODE-TRACE] (caps at CONTESTED).
Read ONLY:
1. your row in `{SCRATCHPAD}/verification_queue.md`
2. the exact source file(s) at `{LOCATION}`
3. `{SCRATCHPAD}/{PRIMARY_ARTIFACT}`
4. one relevant `scip/*.md` helper or build artifact if the preferred workflow requires it
5. `{SCRATCHPAD}/test_infrastructure.md` ONLY IF IT EXISTS (for poc_class:
   unit|property — use constructors and patterns; if absent, inspect the
   project test files/build system directly)
Do NOT read unrelated verifier files, unrelated depth artifacts, or the full
`findings_inventory.md` unless `{PRIMARY_ARTIFACT}` is missing.
Write ONLY `{SCRATCHPAD}/verify_{FINDING_ID}.md`. Do NOT write
later-phase report, consistency, aggregate, or review artifacts. Those are
produced in dedicated subsequent phases that the V2 driver runs separately.
Inline writes from a verify shard are quarantined to `_overflow/`
automatically (v2.1.8) but recurring violations indicate methodology drift;
respect the phase boundary.
Write your result to {SCRATCHPAD}/verify_{FINDING_ID}.md per section WRITE-THEN-VERIFY.
Return ONLY: "DONE: {FINDING_ID} verdict={VERDICT} tag={TAG}"
```

---

## Driver owns the final Evidence Tag (read this first)

A mechanical executor RE-RUNS your test after this phase using the node client's
own toolchain (`go test` for Go, `cargo test` for Rust), and the DRIVER — not
you — stamps the authoritative `[POC-PASS]`/`[POC-FAIL]` from that run. A
`[POC-PASS]` you write that is NOT backed by a test the executor can locate and
run to a real pass is **auto-demoted to `[CODE-TRACE]` and your `Verdict:` flips
`CONFIRMED → CONTESTED [INTEGRITY-DOWNGRADE]`.** To earn a real `[POC-PASS]`,
write a real test asserting the harm and fill `Test File:`/`Test Function:`/
`Command:` with the exact values. `[DIFF-PASS]`/`[CONFORMANCE-PASS]`/
`[NON-DET-PASS]`/`[FUZZ-PASS]`/`[LSP-TRACE]` are unaffected (the cargo/go
executor only governs `[POC-PASS]`). If you cannot run a test, declare it
honestly — the executor degrades to UNPROVEN without penalty and never halts.

## Output File Schema

Each `verify_{FINDING_ID}.md` MUST contain:

```markdown
# Verification: {FINDING_ID}

**Preferred Tag**: {TAG from queue row}
**Evidence Tag**: {ACTUAL_TAG_USED}
**Verdict**: CONFIRMED / REFUTED / CONTESTED / INFEASIBLE / FALSE_POSITIVE
**Test File**: {path under the test dir, *_test.go (Go) or tests/*.rs (Rust), or N/A}
**Test Function**: {exact test function name the executor runs, or N/A}
**Command**: {full `go test`/`cargo test` command, or N/A}

### PoC Attempt
- PoC Required: YES/NO
- PoC Class: {unit|property|integration|structural}
- Attempted: YES/NO
- PoC Not Attempted Because: {NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|N/A}
- Test File: {path or N/A}
- Command: {command or N/A}

### Execution Result
- Compiled: YES/NO/N/A
- Result: PASS/FAIL/REVERT/NOT_EXECUTED
- Output: {assertions, revert reasons, or skip justification}

## Execution Output
{Mechanical evidence: diff output, test output, SCIP citation, or code trace}

## Suggested Fix
{If CONFIRMED — minimal diff-style fix. Omit if REFUTED/FALSE_POSITIVE.}
```

**Ledger honesty — `Attempted:` is about a real executed test, not analysis**:
For rust/go node-client findings where NO local build, fork, or test harness is
available, the HONEST ledger answer is `Attempted: NO` with blocker
`NO_BUILD_ENVIRONMENT` (or `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS` when a live
external dependency cannot be forked or addressed). Doing a manual code trace is
NOT execution — a `[CODE-TRACE]` finding is `Attempted: NO`, never
`Attempted: YES`. Only write `Attempted: YES` when a named test file AND a
runnable `go test`/`cargo test` command actually exist and were run; in that
case `Test File:`/`Command:` MUST be filled with the real values. Do not guess
`Attempted: YES` to look thorough, and do not guess `Attempted: NO` to avoid
work — fill the ledger to match what you actually did. This is a documentation
rule only: it does NOT instruct you to skip analysis, and the driver's executor
degrades an unproven finding to UNPROVEN without penalty and never halts.

**Schema rules**:
- Missing `Preferred Tag:` line is a schema failure.
- `Evidence Tag` must be one of the 7 tags from the routing table above.
- For a `[POC-PASS]` claim, `Test File:`/`Test Function:` MUST name a real
  executable test (the executor re-runs it; an unbacked claim is demoted).
- If the preferred tag workflow fails and fallback is used, document why in Execution Output.
- **MANDATORY for `unit`/`property` PoC Class**: the `### PoC Attempt` AND
  `### Execution Result` ledger sections above are NOT optional — they are a
  hard per-finding contract gate. A `unit`/`property` verify file missing
  either section is rejected. If you legitimately cannot execute, still write
  BOTH sections with `Attempted: NO` and a real blocker code; do not omit them.
- **POST-WRITE VERIFICATION**: after writing `verify_{FINDING_ID}.md`, READ THE
  FILE BACK and confirm it contains both the `### PoC Attempt` and
  `### Execution Result` sections (for `unit`/`property` findings) before
  returning. This guarantees the ledger is flushed to disk and prevents the
  gate from reading a partially-written file.

---

## Fallback Ladder

When the preferred verification workflow fails:

1. **Preferred tag workflow** — attempt first per bug-class routing table
2. **One variant** — relax one dimension (timing, amount, ordering, initial state) and retry
3. **`[LSP-TRACE]`** — requires a concrete `scip/*.md` citation proving the call graph or data flow path. Stronger than CODE-TRACE but not mechanical proof.
4. **`[CODE-TRACE]`** — manual trace with concrete values substituted. Caps verdict at CONTESTED unless the trace is complete with real constants from the codebase.

Do NOT retry the same workflow more than once. Move down the ladder.

---

## Scope Containment

SCOPE: Verify ONLY findings assigned to this shard. Write each finding's
`verify_<ID>.md` and matching `verify_<ID>.severity_proposal.json`, then continue to
the next assigned row. After all assigned rows are written, return and stop.

Do NOT:
- Read or write other shards' verify files
- Write artifacts outside the verifier Markdown + severity-proposal pair contract
- Spawn nested subagents
