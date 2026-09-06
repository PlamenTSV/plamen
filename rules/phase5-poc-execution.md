# Phase 5: Mandatory PoC Execution

External precedent is governed by
`~/.claude/rules/precedent-evidence-policy.md`. Generic methodology literature
supplies context only. RAG may suggest test cases, but may never clear or
demote, force `CONTESTED`, change severity, satisfy proof, or reduce the
required execution depth. Exact precedent still requires matching mechanism
class and matching preconditions and remains context/priority only.

> **Core principle**: A PoC that is written but never executed provides ZERO mechanical evidence. Execution authenticates the observed result; typed oracle provenance and scope determine what that result proves.

---

## Evidence Tags

| Tag | Meaning |
|-----|---------|
| `[POC-PASS]` | Compiled execution established the encoded assertion; proof scope is recorded separately |
| `[POC-FAIL]` | Compiled execution did not establish the encoded assertion; this is not a candidate-wide refutation without exhaustive typed scope |
| `[CODE-TRACE]` | Manual trace with concrete values, no execution - fallible |
| `[MEDUSA-PASS]` | Medusa found a counterexample to the encoded oracle; execution is authentic, while mechanism/reachability/harm scope remains separate |

**Rules**: Tags are display labels, not proof authority. Confirmation or demotion requires a candidate-bound typed assessment of oracle provenance, reachability/environment fidelity, precondition coverage, external-premise state, and proof scope. A negative result cannot dispose of a candidate beyond its independently established exhaustive scope. `[CODE-TRACE]` caps at CONTESTED unless the trace is complete with real constants.

---

## Impact Premise Verification (MANDATORY — HARD GATE)

Before writing the PoC, identify the finding's claimed HARM in one sentence — not the mechanism, but the consequence. The PoC MUST assert the HARM directly. A PoC that only proves a function can be called, a state can be reached, or a path exists is NOT a `[POC-PASS]` — it is a mechanism test, not a harm test.

**Examples of mechanism tests (INSUFFICIENT for [POC-PASS])**:
- "startLiquidation succeeds while market is active" — proves a function call, not user loss
- "parameter can be set to zero" — proves a setter works, not that the zero value causes harm
- "reentrancy callback is triggered" — proves a callback fires, not that state is corrupted

**Examples of harm tests (REQUIRED for [POC-PASS])**:
- "claimant receives 15% less than their pro-rata share after attack sequence"
- "user's withdrawal reverts permanently after parameter is set to zero"
- "attacker extracts 1.5x their fair share via reentrancy before guard triggers"

If you cannot construct a harm assertion, the finding is `[CODE-TRACE]` at best. If the harm assertion fails (user receives correct amounts, withdrawal succeeds, no excess extracted), the finding is `[POC-FAIL]`.

## PoC Testability Ledger (MANDATORY)

Every verifier output MUST include a structured PoC ledger before the evidence
tag is finalized:

```markdown
### PoC Attempt
- PoC Required: YES/NO
- PoC Class: <unit|property|integration|structural>
- Attempted: YES/NO
- PoC Not Attempted Because: <NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|N/A>
- Test File: <path or N/A>
- Command: <command or N/A>
```

### Grouped PoC constituent scope (conditional, mandatory for grouped rows)

When the assigned queue row represents two or more constituent findings, an
executed `[POC-FAIL]` is not group-wide evidence by default. Add this exact
table after `### Execution Result`:

```markdown
### PoC Constituent Evidence Scope

| Constituent ID | Harm Premise ID | Assertion ID | Proof Scope | Binding Kind |
|---|---|---|---|---|
| <exact mapped ID> | <stable local harm-premise ID> | <executed assertion ID> | HARM / MECHANISM_ONLY | EXACT / SHARED |
```

- `EXACT` binds only that constituent. Unlisted constituents remain at their
  prior severity and require separate verification.
- `SHARED` is valid only when every mapped constituent has a row with the same
  harm-premise and assertion IDs. Otherwise it is ambiguous and demotes none.
- `MECHANISM_ONLY` never authorizes a severity reduction.
- Title similarity, shared vocabulary, and a hypothesis-level result are
  routing hints only; they are not proof scope.

The driver hashes the verifier bytes and execution ledger into the evidence
receipt. Missing/malformed scope fails recall-safe: no grouped constituent is
demoted and the driver emits bounded re-verification/human-review debt.

For `unit` and `property` findings, a local executable attempt is mandatory
when a project build/test harness exists. `Compiled: N/A`, `Result: N/A`, "no
test written", and direct `[CODE-TRACE]` fallback are invalid unless the ledger
names a real environmental blocker. In **Thorough** mode this attempt mandate
applies to **every severity**, including Low and Informational; Light and Core
retain their mode-specific severity threshold. A blank `Attempted` field or
verifier-authored blocker prose does not waive the mandate. Non-execution is
valid only when a separately produced typed blocker binds concrete evidence and
is independently validated by an authority other than its proposer. A typed
blocker cannot waive a locally testable row while its build/test harness is
available; bounded repair and execution remain required. Truly infeasible rows
remain `UNPROVEN` and may skip only under that independently validated typed
blocker. `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`
is not an allowed skip reason for `unit` or `property` rows; reclassify the row
or attempt the test.

**Cargo languages (soroban / solana / l1_rust)**: for `unit` and `property`
rows, the PoC MUST be placed in-crate under the target workspace member's
`src/` (e.g. `src/poc_{id}.rs` wired via `#[cfg(test)] mod`), never authored
only as a bare top-level `tests/*.rs` or inlined into `lib.rs`. See the
language-specific `phase5-verification-prompt.md` for the exact file/command
shape. `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` remains DISALLOWED for
`unit`/`property` rows in these languages whenever a build/test harness
exists — the in-crate placement removes the linking blocker that would
otherwise justify a structural skip.

Allowed no-execution reasons:

- `NO_BUILD_ENVIRONMENT`
- `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS`
- `DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL`
- `PURE_SPEC_OR_DOCS_ONLY`
- `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` (structural/integration only)

## Force-by-Default Skip Justification (MANDATORY — closed taxonomy)

`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` is NOT a valid skip reason for a
finding with a concrete Material Harm (a fund, state, privilege, liveness, or
accounting delta — see Material Harm in `finding-output-format.md`). The
default for such a finding is to FORCE the PoC. A skip requires citing a
SPECIFIC blocker from this CLOSED taxonomy, with a CODE-GROUNDED
justification the driver will check:

- `FULLY_TRUSTED_DESIGN` — name the fully-trusted governance/upgrade actor
  AND the absent control that would otherwise gate the action.
- `DEPLOY_OR_TX_ORDERING` — name the initializer/setup function AND the
  cross-transaction deploy-gap race the harm depends on.
- `EXTERNAL_DEP_NO_FORK` — name the out-of-scope external call or address
  the harm depends on.
- `LIVE_ARTIFACT_REQUIRED` — name the separately-compiled/deployed artifact
  the PoC needs that is not available in this run.
- `SPEC_DOCS_NO_STATE_DELTA` — the claim has no on-chain state delta to
  assert (pure spec/docs mismatch).
- A `REFUTED` verifier verdict (the harm does not hold, so no PoC is owed).

A bare `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` with no named blocker from
this list is a phase failure for a Material-Harm finding — reclassify the
row and attempt the test, or cite the specific taxonomy entry above instead.

A forced attempt that genuinely cannot assert the harm — after applying the
Assertion Retry Protocol below — records `[CODE-TRACE]` plus the specific
named blocker, NOT `[POC-FAIL]`. `[POC-FAIL]` is reserved for a
harm-asserting test that compiled, ran, and the claimed harm did not
reproduce; it is never the tag for "could not construct a harm assertion."

**TTL / liveness / archival is testable, not structural.** For Soroban and
other cargo-based ledgers with an explicit entry-lifetime model, TTL and
archival-eviction harms ARE testable in-process: advance the ledger sequence
via `Ledger::with_mut` (`li.sequence_number += N`) and read the entry's
remaining lifetime via `get_ttl()` (or the SDK's equivalent) to assert
eviction or extension behavior directly. "`Env::default()` cannot model
eviction" is NOT a valid `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`
justification for a TTL/archival finding — the ledger-clock advance above is
exactly the tool that models it.

## Execution Protocol

1. **Write** the PoC using templates from the language-specific prompt
2. **Compile** using the language-specific build command. On failure: read error, apply targeted fix, retry. Recovery ladder for common failures:
   - Missing import → add to remappings or install dependency
   - Type mismatch → check actual function signatures in source (anti-hallucination rule 3)
   - Constructor args → read deployment script or setUp() patterns from existing tests
   - Interface changes → re-read source file for current function signatures
   - Foundry version incompatibility → try `--via-ir` or pin solc version
   Max 5 attempts. After 5 failures → `[CODE-TRACE]` fallback, verdict CONTESTED
3. **Execute** using the language-specific test command. Record pass/fail/revert and paste relevant output
4. **Fuzz variant** (Medium+ only, Thorough mode): after the specific PoC, write a second test with the key parameters fuzzed (amounts, timing, ordering) and run it. Use the language-specific fuzz command. This explores the neighborhood around the finding mechanically - catching attack variants the agent didn't manually consider. If the specific PoC failed but the fuzz variant finds a violation, report the working variant.
5. **Record** in the verification file:

```markdown
### Execution Result
- **Compiled**: YES/NO (attempts: N)
- **Result**: PASS / FAIL / REVERT / NOT_EXECUTED
- **Fuzz variant** (Thorough only, Medium+): PASS (N runs) / VIOLATION_FOUND / SKIPPED / NOT_APPLICABLE
- **Output**: {test output - assertions, revert reasons}
- **Evidence Tag**: [POC-PASS] / [POC-FAIL] / [CODE-TRACE]
```

If execution was not attempted, explain why (no build environment, no test framework). Silent omission is not acceptable.

6. **Generate fix** (`[POC-PASS]` findings only): After a passing PoC confirms the bug, write a minimal diff-style fix. The verifier already has deep context from the PoC — this is incremental work, not a separate analysis task.

```markdown
### Suggested Fix
```diff
- vulnerable line(s)
+ fixed line(s)
```
**Fix scope**: {1-sentence description of what the fix does}
**Verified**: {YES — re-ran PoC with fix applied and it no longer triggers / NO — fix not mechanically verified}
```

   **Rules for fix generation**:
   - Only when the candidate-bound typed assessment establishes HARM scope. A bare `[POC-PASS]` tag is insufficient. `[CODE-TRACE]` and negative execution results do NOT get fixes.
   - Keep fixes minimal — the smallest change that eliminates the vulnerability. Do not refactor surrounding code.
   - If the fix is non-trivial (architectural change, multi-file, or could introduce new issues): write `**Fix**: Architectural change required — {1-sentence description}. No inline diff provided.`
   - If time permits, re-run the PoC with the fix applied to verify it no longer triggers. Tag as `Verified: YES/NO`.
   - Tier writers paste the fix verbatim into the report — do not regenerate.

---

## Fork PoC mandate (external-integration findings)

> Applies to any Medium+ finding whose HARM is an **external-integration fund
> drain / misrouting** — funds drained, over-paid, or routed to the wrong
> recipient/chain because an **untrusted external contract's return value** is
> consumed verbatim. Such a finding is NOT `structural`: it has a concrete,
> fork-testable harm. Self-declaring `PoC Class: structural` (or `spec`/`docs`)
> to zero the PoC requirement is not permitted for this class — the effective
> PoC class is floored to `integration`.

**Decision rule:**

1. **Single-chain external dependency at a KNOWN deployed address** → **mandate
   a fork PoC.** Pin the block and fork against the real deployed contract:

   ```
   forge test --match-test test_{ID} --fork-url {RPC_URL} --fork-block-number {PINNED} -vvv
   ```

   Assert the CLAIMED HARM directly (funds drained / misrouted / over-paid), not
   merely that a function is callable. A passing fork run is `[PROD-FORK]` and
   authenticates the encoded result; HARM authority still requires a bound
   oracle, faithful environment/preconditions, and resolved external premises.
   A harm-assertion not being established is `[POC-FAIL]` and is limited to its
   typed negative scope.

2. **Cross-chain relay / message-passing harm** (the external leg is a
   destination chain's consumer that no single-node fork can execute) →
   **structured skip.** There is no off-the-shelf simulator for the relayed leg;
   record `PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS`
   (or `DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL`) with the concrete reason.

3. **No reachable fork RPC in the audit environment** → the mandate is **inert**.
   Keep the structured skip and stamp the finding `[UNPROVEN-EXTERNAL]`: the harm
   mechanism is in-scope-proven but its external leg is unverified for want of a
   fork. The finding STAYS IN THE BODY at its **proven-mechanism severity**; R10
   must NOT promote it ABOVE that severity on the assumed worst-case external
   behavior (and never demotes it below).

> The `[UNPROVEN-EXTERNAL]` stamp is an evidence-honesty marker that co-exists
> with `[CODE-TRACE]`. It is NOT proof-grade and NEVER upgrades a finding's
> evidence. It records exactly "in-scope mechanism proven; external leg
> unproven for lack of a fork" so a reader (and R10) can calibrate severity
> honestly.

---

## Language-Specific Commands

| Language | Build | Test | Fuzz |
|----------|-------|------|------|
| **EVM (Foundry)** | `forge build` | `forge test --match-test test_{ID} -vvv` | `forge test --match-test testFuzz_{ID} -vvv` (use `bound()` inputs) |
| **EVM (Hardhat only)** | `npx hardhat compile` | `npx hardhat test --grep "{ID}"` | Skip fuzz variant (no native invariant fuzzer) |
| **Soroban** | `stellar contract build` | `cargo test --features testutils test_{id}` | `cargo +nightly fuzz run fuzz_{id}` (if nightly); proptest fallback |
| **Solana (Anchor)** | `cargo build-sbf` or `anchor build` | `cargo test test_{id} -- --nocapture` | Trident (preferred): `cd trident-tests && trident fuzz run fuzz_0`; fallback: proptest with bounded inputs |
| **Solana (native)** | `cargo build-sbf` | `cargo test test_{id} -- --nocapture` | proptest with bounded inputs, or boundary-value parameterized tests |
| **Aptos** | `aptos move compile` | `aptos move test --filter test_{id}` | No built-in fuzzer - write boundary-value parameterized tests (`#[test]` with multiple concrete value sets covering min/mid/max) |
| **Sui** | `sui move build` | `sui move test test_{id}` (positional filter; module/function path accepted) | `#[random_test]` with `sui move test --rand-num-iters {N} test_{id}`; fallback to boundary-value parameterized tests |
| **DAML (Canton)** | `daml build` | `daml test --files daml-test/PoC_{id}.daml` (or `daml script --dar .daml/dist/*.dar --script-name {Module}:{id} --ledger-host localhost --ledger-port 6865`) | No native fuzzer or SAST (DLint = style only) — boundary-value parameterized `Script ()` (min/mid/max), Aptos-style |

**Fork testing** (EVM only): `forge test --match-test test_{ID} --fork-url {RPC_URL} -vvv`

---

## Verification Completeness Assert (Orchestrator Inline)

After all verification batches complete, the orchestrator runs this mechanical check:

```
For mode=Thorough:
  verified_ids = set(all hypothesis IDs in verify_batch*.md files)
  required_ids = set(h.id for h in hypotheses)  // ALL severities including Low/Info
  unverified = required_ids - verified_ids
  ASSERT: len(unverified) == 0
  If FAIL: spawn additional verification batch for unverified hypotheses
  Log: "Verification coverage: {len(verified_ids)}/{len(required_ids)} total hypotheses"

For mode=Core:
  required_ids = set(h.id for h in hypotheses if h.severity >= MEDIUM) + chain_hypothesis_ids
  // Same assertion logic - Core now verifies ALL Medium+, skips fuzz variants only
```

---

## Assertion Retry Protocol (MANDATORY on assertion failure)

> **Purpose**: Distinguish "test setup was wrong" from "bug doesn't exist" with ONE retry.

When your test's assertion FAILS (the system behaves correctly, contradicting the finding):

**Step 1: Self-diagnosis (no code yet)**

Ask yourself:
- Did I test the EXACT function at the EXACT location from the finding?
- Did my setup create the EXACT preconditions described in the finding?
- Is my assertion testing the CLAIMED HARM, not just a mechanism step?
- Did I use realistic values from the codebase (not made-up constants)?

If ANY answer is "no" → Step 2A (fix setup). If ALL answers are "yes" → Step 2B (accept failure).

**Step 2A: Fix Setup (one retry)**

Rewrite ONLY the test setup/inputs. You MUST keep the SAME target function call, the SAME harm assertion, and the SAME finding location. Compile and run. If PASS → `[POC-PASS]`. If FAIL again → Step 2B.

**Step 2B: Accept failure**

Conclude `[POC-FAIL]`. Do NOT weaken the assertion to force a pass or change what harm you're testing.

**Anti-gaming rules:**
- Attempt 2 tests a DIFFERENT function than the Location field → `[CODE-TRACE]`, not `[POC-PASS]`
- Attempt 2 assertion checks different harm than Attempt 1 → `[CODE-TRACE]`

---

## Variant Exploration Before FALSE_POSITIVE

Before marking FALSE_POSITIVE, test at least ONE relaxed variant of the attack. Relax along whichever dimension caused the failure: timing (same-block → multi-block), amount (specific → range), ordering (A-then-B → B-then-A), or initial state (current → post-loss/post-pause/empty).

If the variant passes → report the working variant. After 2+ variant failures → FALSE_POSITIVE is justified.

---

## Non-EVM Fuzz Guidance

### Solana - Trident (preferred) or proptest (fallback)

**Trident** is a dedicated Solana fuzzing framework by Ackee Blockchain Security. v0.11+ uses built-in TridentSVM (no honggfuzz/AFL required - works on Linux, macOS, and Windows). Has found Critical bugs in Kamino, Marinade, and Wormhole.

**Detection**: Check `build_status.md` for `trident_available: true/false` (set by recon TASK 1).

**If Trident is available** (Anchor project + `trident-cli` installed):
```bash
# Initialize (if not already done - creates trident-tests/ scaffolding)
trident init
# Run fuzz target from trident-tests/ directory (v0.11+)
cd trident-tests && trident fuzz run fuzz_0
# Run with specific seed for reproducibility
trident fuzz run fuzz_0 12345
# Enable detailed logging
TRIDENT_LOG=1 trident fuzz run fuzz_0
```
Trident generates handler scaffolding from the program IDL. The verifier customizes the generated `fuzz_instructions.rs` to target the specific finding's instruction sequence, adds invariant checks, and runs the campaign. Violations are written to `.fuzz-artifacts/`.

**If Trident is NOT available** (native Solana program, or `trident-cli` not installed):
Use proptest as fallback:
```rust
use proptest::prelude::*;
proptest! {
    #[test]
    fn test_fuzz_hypothesis(amount in 1u64..1_000_000_000u64, delay in 0u64..86400u64) {
        // setup, execute, assert invariant
    }
}
```
If proptest is also not available, fall back to boundary-value parameterized tests (3-5 concrete values covering min, typical, max).

### Soroban - cargo-fuzz (preferred) or proptest (fallback)

**cargo-fuzz** is the standard Rust fuzzing tool using libFuzzer. Requires nightly Rust. Soroban contracts need `crate-type = ["cdylib", "rlib"]` in Cargo.toml for fuzz crate linking.

**Detection**: Check `build_status.md` for `cargo_fuzz_available: true/false` (set by recon TASK 1 — tests `cargo +nightly fuzz --version`).

**If cargo-fuzz is available** (nightly Rust installed):
```bash
# Initialize (if not already done - creates fuzz/ directory)
cargo fuzz init
# Run fuzz target
cargo +nightly fuzz run fuzz_target_1
# Run with timeout
cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300
```
The verifier writes a fuzz harness using `soroban-sdk` testutils with `Env::default()`, registers the contract, and fuzzes the key parameters. Use `#[derive(Arbitrary)]` or `SorobanArbitrary` for input generation. NEVER use `panic!()` in fuzzable code — use `panic_with_error!` or return errors.

**If cargo-fuzz is NOT available** (no nightly, or Windows issues):
Use proptest as fallback (works on stable Rust, all platforms):
```rust
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
proptest! {
    #[test]
    fn test_fuzz_hypothesis(amount in 1i128..1_000_000_000i128, timestamp in 0u64..86400u64) {
        let env = Env::default();
        // setup, execute, assert invariant
    }
}
```
If proptest is also not available, fall back to boundary-value parameterized tests (3-5 concrete values covering 0, 1, typical, i128::MAX).

### Aptos - parameterized boundary tests
Aptos Move lacks a built-in random-input fuzzer. Write multiple `#[test]`
functions with concrete boundary values:
```move
#[test] fun test_hypothesis_min() { run_test(0, 1); }
#[test] fun test_hypothesis_mid() { run_test(500_000, 86400); }
#[test] fun test_hypothesis_max() { run_test(MAX_U64, MAX_U64); }
```
This provides 3+ data points instead of 1, catching boundary-dependent bugs without a full fuzzer.

### Sui - random-input tests with boundary fallback
Prefer Sui Move random-input tests for fuzz variants:

```move
#[random_test]
fun test_hypothesis_random(input: u64) {
    run_test(input);
}
```

Run with `sui move test --rand-num-iters 100 test_hypothesis_random`. If the
random-input test cannot compile for the target harness, fall back to the
boundary-value parameterized test pattern above and document the limitation.

### DAML (Canton) - boundary-value Scripts
DAML has NO native fuzzer and NO security SAST (DLint is style-only). Write a
shared helper and call it from min/mid/max top-level `Script ()` functions;
`daml test --files <file>` runs every Script in the file (no per-test name
filter). Assert the boundary invariant inside the helper (e.g. an `ensure`-gap
becoming creatable, or an arithmetic `Int`/`Decimal` operation aborting →
liveness brick, never a silent wrap):
```daml
runBoundary : Int -> Script ()
runBoundary amount = do
    p <- allocateParty "P"
    -- exercise the target choice with `amount`, assert the boundary invariant
    pure ()

boundaryMin : Script ()
boundaryMin = runBoundary 0

boundaryMid : Script ()
boundaryMid = runBoundary 500000

boundaryMax : Script ()
boundaryMax = runBoundary maxIntValue
```
This provides 3+ data points instead of 1, catching boundary-dependent bugs
without a full fuzzer.
