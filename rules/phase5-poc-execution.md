# Phase 5: Mandatory PoC Execution (v9.9.5)

> **Core principle**: A PoC that is written but never executed provides ZERO mechanical evidence. Only executed tests produce ground truth.

---

## Evidence Tags

| Tag | Meaning |
|-----|---------|
| `[POC-PASS]` | Compiled, executed, assertions PASSED - mechanical proof |
| `[POC-FAIL]` | Compiled, executed, assertions FAILED - attack does not work as described |
| `[CODE-TRACE]` | Manual trace with concrete values, no execution - fallible |
| `[MEDUSA-PASS]` | Medusa fuzzer found a counterexample - mechanical proof (same weight as `[POC-PASS]`) |

**Rules**: `[POC-PASS]` is the only tag that supports CONFIRMED as ground truth. `[POC-FAIL]` defaults to the attack not working - to override, demonstrate the failure is test setup error, not a defense. `[CODE-TRACE]` caps at CONTESTED unless the trace is complete with real constants.

---

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

---

## Language-Specific Commands

| Language | Build | Test | Fuzz |
|----------|-------|------|------|
| **EVM (Foundry)** | `forge build` | `forge test --match-test test_{ID} -vvv` | `forge test --match-test testFuzz_{ID} -vvv` (use `bound()` inputs) |
| **EVM (Hardhat only)** | `npx hardhat compile` | `npx hardhat test --grep "{ID}"` | Skip fuzz variant (no native invariant fuzzer) |
| **Solana (Anchor)** | `cargo build-sbf` or `anchor build` | `cargo test test_{id} -- --nocapture` | Trident (preferred): `cd trident-tests && trident fuzz run fuzz_0`; fallback: proptest with bounded inputs |
| **Solana (native)** | `cargo build-sbf` | `cargo test test_{id} -- --nocapture` | proptest with bounded inputs, or boundary-value parameterized tests |
| **Aptos** | `aptos move compile` | `aptos move test --filter test_{id}` | No built-in fuzzer - write boundary-value parameterized tests (`#[test]` with multiple concrete value sets covering min/mid/max) |
| **Sui** | `sui move build` | `sui move test --filter test_{id}` | No built-in fuzzer - write boundary-value parameterized tests (`#[test]` with multiple concrete value sets covering min/mid/max) |

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

### Aptos / Sui - parameterized boundary tests
Move lacks a fuzzer. Write multiple `#[test]` functions with concrete boundary values:
```move
#[test] fun test_hypothesis_min() { run_test(0, 1); }
#[test] fun test_hypothesis_mid() { run_test(500_000, 86400); }
#[test] fun test_hypothesis_max() { run_test(MAX_U64, MAX_U64); }
```
This provides 3+ data points instead of 1, catching boundary-dependent bugs without a full fuzzer.
