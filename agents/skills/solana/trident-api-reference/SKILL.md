---
name: "trident-api-reference"
description: "Type Reference document (prevents method signature hallucination) - Trigger trident_available true in build_status.md"
---

# Skill: Trident API Reference (v0.12.0)

> **Type**: Reference document (prevents method signature hallucination)
> **Trigger**: `trident_available: true` in `build_status.md`
> **Loaded by**: Invariant fuzz generator (Phase 4b), security-verifier Template 6 (Phase 5)
> **Version**: Trident v0.12.0 (Ackee Blockchain Security)
> **Important**: Check `trident --version` before using. If version differs, warn and proceed with caution.

---

## CLI Commands

```bash
# Initialize scaffolding (creates trident-tests/ from program IDL)
trident init

# Run fuzz campaign (v0.11+ uses built-in TridentSVM - no honggfuzz/AFL needed)
# Run from the trident-tests/ directory
cd trident-tests && trident fuzz run fuzz_0

# Run with a specific seed for reproducibility
trident fuzz run fuzz_0 12345

# Enable detailed transaction logging
TRIDENT_LOG=1 trident fuzz run fuzz_0

# Build without running (useful for CI or pre-checks)
trident fuzz run fuzz_0 --skip-build
```

**Platform support**: Trident v0.11+ works on **Linux, macOS (including Apple Silicon), and Windows**. Earlier versions (<=0.10) required honggfuzz (Linux-only).

## Project Structure

```
trident-tests/
  fuzz_tests/
    fuzz_0/
      fuzz_instructions.rs    # Handler definitions (auto-generated, customize)
      test_fuzz.rs             # Entry point (auto-generated)
  .fuzz-artifacts/             # Crash/violation files written here (v0.11+)
  Trident.toml                 # Configuration (iterations, coverage, regression)
```

## Key Types and Traits

### FuzzInstruction Enum

```rust
// Auto-generated from IDL. Each variant = one program instruction.
// Customize: add bounds to parameters, constrain account selection.
#[derive(Arbitrary, DisplayIx, FuzzTestExecutor, FuzzDeserialize)]
pub enum FuzzInstruction {
    InstructionName(InstructionNameData),
    // ...
}
```

### Instruction Data Structs

```rust
#[derive(Arbitrary, Debug)]
pub struct InstructionNameData {
    // Fields mirror the instruction's arguments
    pub amount: u64,
    pub authority: AccountId,  // AccountId = index into AccountsStorage
    // ...
}
```

### AccountsStorage

```rust
// Manages test accounts. Use AccountId (u8) to reference accounts.
// Trident creates/reuses accounts automatically.

// Read account state:
let account = fuzz_accounts.token_account.storage().get(&account_id);

// Custom account setup (e.g., mock oracle):
fn set_account_custom(
    &mut self,
    account_id: AccountId,
    data: &[u8],
    owner: &Pubkey,
) -> Pubkey;
```

### Invariant Hooks

```rust
impl FuzzInstruction {
    // Called after EACH instruction execution
    fn check_invariant(&self, pre_state: &Snapshot, post_state: &Snapshot) {
        // Assert protocol invariants here
        // Panic = violation found = crash file generated
        assert!(
            post_state.total_supply == post_state.sum_balances(),
            "Supply invariant violated"
        );
    }
}
```

### Snapshot Pattern

```rust
// Capture state before instruction for comparison
struct Snapshot {
    total_supply: u64,
    vault_balance: u64,
    // Add fields for each invariant
}

impl Snapshot {
    fn capture(accounts: &AccountsStorage) -> Self {
        // Read relevant account states
    }
}
```

## Common Pitfalls

1. **Check `.fuzz-artifacts/` for violations**: Trident v0.11+ writes crash/violation files to `.fuzz-artifacts/` (not `fuzzing/fuzz_0/` like older versions). Always check this directory even if stdout shows no errors.
2. **AccountId reuse**: Multiple instruction fields using the same AccountId type will be assigned the same account. Use distinct account pools for distinct roles.
3. **Silent reverts**: If handler setup fails (wrong PDA, missing prerequisite), the instruction silently reverts. Check success rate -- if all calls revert, the campaign is trivial.
