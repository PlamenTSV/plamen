# Phase 5: SC Verification - Isolated Contracts

> **Purpose**: Shared source file for SC verification phases. The V2 prompt
> builder selects exactly one contract below for each phase:
> `sc_verify_queue`, one `sc_verify_*` shard, or `sc_verify_aggregate`.
>
> This file intentionally contains no child-agent spawn template.

---

## SC Verify Queue Contract

Build the verification queue only.

### Inputs

- `{SCRATCHPAD}/findings_inventory.md`
- `{SCRATCHPAD}/chain_hypotheses.md` if present
- `{SCRATCHPAD}/hypotheses.md` if present

### Method

1. Read only the inputs above and route findings that require
   verification into `{SCRATCHPAD}/verification_queue.md`.
2. Preserve finding IDs, severity, location, primary artifact, and concise
   verification objective for each queued row.
3. Do not verify findings in this phase.
4. Do not spawn any Task subagents — this is queue construction only.

### Output

Write ONLY `{SCRATCHPAD}/verification_queue.md`.

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other
agents' output files. Do NOT proceed to subsequent pipeline phases. Return
your findings and stop.

---

## SC Verify Shard Contract

Verify only the rows assigned to this shard by the driver's
`VERIFY COST OVERRIDE (SC SHARD)` block.

### Mandatory Reads

For each assigned row, read only:

- the row in this shard's manifest
- `~/.claude/rules/phase5-poc-execution.md`
- the exact source file(s) at the row's `Location`
- the one `Primary Artifact` named in the queue row

Do NOT open legacy language-specific prompt files from inside a shard.
This standalone shard contract plus `phase5-poc-execution.md` is the
complete verifier methodology.

### Method

1. Do not spawn subagents. The current verifier shard processes assigned rows
   directly.
2. Verify only finding IDs present in the shard manifest named by the Python
   override.
3. Process rows sequentially. Write each row's verifier file before moving to
   the next row.
   On resume/retry, if the row's exact `verify_<ID>.md` file already exists
   and contains `Severity:`, `Evidence Tag:`, and `Verdict:`, count that row as
   complete only if either the row is not `unit`/`property`, or the file also
   contains `### PoC Attempt` and `### Execution Result` with a real attempted
   test or a valid blocker. Do not skip a ledgerless `unit`/`property`
   verifier file; repair it in place. Do not rewrite completed verifier files
   just because the previous shard run was interrupted.
4. Prove or refute the claimed harm using the language-specific methodology
   and PoC execution protocol.
5. Do not bulk-read unrelated `verify_*.md`, unrelated depth artifacts, or the
   whole scratchpad.

### Driver owns the final Evidence Tag (read this first)

A mechanical executor RE-RUNS your test after this phase, in the audit's own
ecosystem toolchain (Foundry `forge`, Solana/Soroban `cargo`, Aptos/Sui Move
`aptos`/`sui`, L1 Go/Rust `go`/`cargo`), and the DRIVER — not you — stamps the
authoritative Evidence Tag from that run. Therefore:

- Any `committed-invariant [CI-n]` newly emitted by a verifier has authority
  `HUMAN_REVIEW_NEXT_RUN`. It is created after the current verification queue
  was frozen and MUST NOT be claimed as current-run verified or current-run
  fuzzed. The driver may preserve it for a later run or explicit human review.

- A `[POC-PASS]` you write that is NOT backed by a test the executor can locate
  and run to a real pass is **automatically demoted to `[CODE-TRACE]` and your
  `Verdict:` is flipped `CONFIRMED → CONTESTED [INTEGRITY-DOWNGRADE]`.** Claiming
  proof you don't have is worse than useless — it gets caught and your finding
  drops out of the verified set.
- To get a real `[POC-PASS]`, write a REAL test that asserts the claimed HARM,
  at a concrete path the executor can find, using the ecosystem framework named
  in the cost-directive block. Populate `Test File:`, `Command:`, and
  `Test Function:` with the exact values you used — these are the executor's
  inputs, not decoration. The test path must use the ecosystem-correct extension
  (`*.t.sol` / `*.rs` / `*.move` / `*_test.go`) under the project's test
  directory.
- If you genuinely cannot run a test (no toolchain, external-only dependency
  with no fork), say so honestly via the skip ledger. The executor degrades that
  to UNPROVEN without penalty — it never fabricates a pass and never halts.

This is the single mechanism that keeps the verified set honest. Write the test
for real, or declare the blocker for real.

### PoC Testability Triage (Mandatory)

Before accepting `[CODE-TRACE]`, classify the row from the shard manifest:

- `PoC Class = unit` or `property`: attempt an executable PoC/test first.
  In a Foundry/Hardhat/cargo/Move/Soroban project, "no test written" is not a
  valid result for a testable row. Write the smallest harm-assertion test that
  targets the queued Location and run it.
- `PoC Class = structural` or `integration`: executable proof is still
  preferred, but `[CODE-TRACE]` is acceptable only when you document why no
  meaningful local harness exists.
- Critical/High rows with `unit` or `property` class MUST NOT be marked
  `CONFIRMED` on `[CODE-TRACE]` alone. If execution cannot be completed, mark
  `CONTESTED` and document the blocker.

Every verifier file MUST include this ledger:

```markdown
### PoC Attempt
- PoC Required: YES/NO
- PoC Class: <unit|property|integration|structural>
- Attempted: YES/NO
- PoC Not Attempted Because: <NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|CROSS_VM_ENCODING_NO_RUNTIME|N/A>
- Test File: <ecosystem-correct path under the test dir (*.t.sol/*.rs/*.move/*_test.go), or N/A>
- Test Function: <exact test function name the executor runs, or N/A>
- Command: <full build/test command in the audit ecosystem, or N/A>

### Execution Result
- Compiled: YES/NO (attempts: N)
- Result: PASS / FAIL / REVERT / NOT_EXECUTED
- Output: <relevant output or compiler/runtime blocker>
```

For `unit` and `property` rows, `Compiled: N/A`, `Result: N/A`, and "no test
written" are invalid unless `PoC Not Attempted Because` names a real
environmental blocker. Do not use `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`
for a `unit` or `property` queue row; that means the queue classification must
be challenged, not silently bypassed.

For `unit` and `property` rows, default to `Attempted: YES`.
`Attempted: NO` is allowed only if all of the following are true:

1. The skip code is one of the exact allowed codes in the ledger.
2. You cite the concrete blocker in the verifier file, with a source/config/log
   reference where applicable.
3. You explain why a minimal mock, harness, fork, or property test cannot
   assert the claimed harm.
4. You do not mark the finding `CONFIRMED` on the basis of the skipped PoC
   alone. If the harm is still plausible but unexecuted, use `CONTESTED` or
   a non-PoC evidence tag with the blocker documented.

Before writing each `verify_<ID>.md`, self-check: if the queue row says
`PoC Class = unit` or `property`, the file must either contain a real attempted
test command/result or a mechanically valid skip reason with concrete blocker
evidence. The driver audits invalid skips and records them as violations.

**Skip codes have validity preconditions** — see `phase5-poc-execution.md`
§ "Skip-Reason Validity Preconditions". In short: `NO_BUILD_ENVIRONMENT` is
invalid when the build succeeded; `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS` is
invalid when the dependency can be mocked (mock it and run the PoC);
`DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL` is invalid on a `unit`-class row;
`N/A` is invalid on a `unit`/`property` row when a build harness exists. The
driver mechanically audits these and logs violations to
`verifier_skip_audit.md`.

**For Critical/High/Medium `unit`/`property` rows, "needs a mock", "complex
setup", "disproportionate for this severity", "full mock setup required", and
"not necessary" are NOT valid blockers.** If the project's own test suite
already mocks the dependency (look for a `*Mock`/`*Stub`/`*Fake`/`*Harness`
used by any passing test), you MUST build the same minimal harness and run the
PoC. The driver hard-gates this exact skip for Medium+ rows: the shard is
retried until you either attempt a real PoC or non-silently reclassify the PoC
Class (`structural`/`integration`) with justification in your own ledger.

### Output

For each assigned row, write exactly the verifier pair:
`{SCRATCHPAD}/verify_<ID>.md` and
`{SCRATCHPAD}/verify_<ID>.severity_proposal.json`.

Every verifier file MUST include:

- `Severity:`
- `Evidence Tag:` with one of `[POC-PASS]`, `[POC-FAIL]`, `[CODE-TRACE]`,
  `[MEDUSA-PASS]`
- `Verdict:`

Return one compact line per row:

`<ID>: <VERDICT> | <EVIDENCE_TAG> | <1-sentence justification>`

SCOPE: Write ONLY the `verify_<ID>.md` and matching
`verify_<ID>.severity_proposal.json` files for IDs assigned in this shard's
manifest. Do NOT read or write other verifier shards' files. Do NOT write
any artifact outside this contract. Return your findings and stop.

---

## SC Verify Aggregate Contract

Aggregate existing verifier outputs only.

### Inputs

- `{SCRATCHPAD}/verification_queue.md`
- `{SCRATCHPAD}/verify_*.md`

### Method

1. Read existing per-finding verifier files and the verification queue.
2. Confirm each required queued ID has a corresponding verifier file or record
   it as missing in the aggregate.
3. Summarize verdicts, evidence tags, and any malformed verifier records.
4. Do not open source files unless a verifier file is malformed and blocks
   aggregation.
5. Do not spawn new per-finding verifiers.

### Output

Write ONLY `{SCRATCHPAD}/verify_core.md`.

SCOPE: Write ONLY `{SCRATCHPAD}/verify_core.md`. You MAY read upstream
`verify_*.md` files and `verification_queue.md` to aggregate them, but you MUST
NOT modify those inputs or create new per-finding verifier files. Return and stop.
