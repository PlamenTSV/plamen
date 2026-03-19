# Verification Protocol - Test Templates (Solana)

> Part of the Solana Verification Protocol skill. Read `SKILL.md` for the core workflow.

## LiteSVM Test Templates

### Template 1: Basic Exploit (Account State Manipulation)

```rust
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

/// BUG: {2-sentence description}
/// EXPECTED: {what should happen}
/// ACTUAL: {what does happen}
#[test]
fn test_exploit_basic() {
    // === SETUP ===
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique(); // or load deployed program

    // Deploy the program under test
    let program_bytes = std::fs::read("target/deploy/program_name.so")
        .expect("Program binary not found");
    svm.add_program(program_id, &program_bytes);

    // Create actors
    let attacker = Keypair::new();
    let victim = Keypair::new();
    let authority = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap(); // 10 SOL
    svm.airdrop(&victim.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&authority.pubkey(), 10_000_000_000).unwrap();

    // Initialize protocol state (config, vaults, token mints, etc.)
    // ... setup instructions ...

    // === RECORD BEFORE STATE ===
    let state_before = svm.get_account(&state_account_pubkey);
    println!("=== BEFORE ===");
    // Deserialize and log relevant fields

    // === EXECUTE EXPLOIT ===
    println!("=== EXPLOIT ACTION ===");
    let exploit_ix = Instruction::new_with_borsh(
        program_id,
        &exploit_instruction_data,
        vec![
            AccountMeta::new(attacker.pubkey(), true),  // signer
            AccountMeta::new(target_account, false),     // writable
            // ... other accounts
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[exploit_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // === RECORD AFTER STATE ===
    println!("=== AFTER ===");
    let state_after = svm.get_account(&state_account_pubkey);
    // Deserialize and log relevant fields

    // === PROVE BUG ===
    println!("=== VERIFICATION ===");
    assert!(result.is_ok(), "Exploit transaction should succeed");
    // THE ASSERTION THAT PROVES THE BUG
    // Design this so it PASSES when the bug EXISTS
}
```

### Template 2: Account Substitution Attack

Tests whether an instruction properly validates account ownership, type, or PDA derivation.

```rust
#[test]
fn test_account_substitution() {
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    svm.add_program(program_id, &program_bytes);

    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();

    // === CREATE LEGITIMATE ACCOUNT ===
    // ... initialize a real protocol account ...

    // === CREATE FAKE ACCOUNT WITH CRAFTED DATA ===
    // Craft account data that mimics the expected type but with malicious values
    let fake_account_keypair = Keypair::new();
    let mut fake_data = vec![0u8; expected_account_size];

    // Write the 8-byte Anchor discriminator (if Anchor program)
    // let discriminator = hash("account:AccountTypeName");
    // fake_data[..8].copy_from_slice(&discriminator[..8]);

    // Write crafted fields at known offsets
    // e.g., set balance field to max value
    // fake_data[offset..offset+8].copy_from_slice(&u64::MAX.to_le_bytes());

    // Allocate the fake account with the WRONG owner (attacker's program or system)
    // If the instruction does not check owner, this will be accepted
    let create_fake_ix = system_instruction::create_account(
        &attacker.pubkey(),
        &fake_account_keypair.pubkey(),
        svm.minimum_balance_for_rent_exemption(fake_data.len()),
        fake_data.len() as u64,
        &program_id, // or &wrong_program_id to test owner check
    );

    // Set the fake account data
    // svm.set_account(fake_account_keypair.pubkey(), fake_account);

    // === ATTEMPT SUBSTITUTION ===
    let exploit_ix = Instruction::new_with_borsh(
        program_id,
        &instruction_data,
        vec![
            AccountMeta::new(attacker.pubkey(), true),
            // Pass fake account where legitimate account is expected
            AccountMeta::new(fake_account_keypair.pubkey(), false),
            // ... other accounts
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[exploit_ix],
        Some(&attacker.pubkey()),
        &[&attacker, &fake_account_keypair],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // === VERIFY ===
    // If the bug EXISTS: transaction succeeds with fake account (no validation)
    // If the bug is FIXED: transaction fails with constraint violation
    assert!(
        result.is_ok(),
        "Account substitution should succeed if validation is missing"
    );
    // Check that attacker gained something from the substitution
}
```

### Template 3: CPI Attack (Malicious Program Substitution)

Tests whether the protocol validates CPI target program IDs.

```rust
#[test]
fn test_cpi_attack() {
    let mut svm = LiteSVM::new();

    // Deploy the LEGITIMATE target program
    let target_program_id = Pubkey::new_unique();
    svm.add_program(target_program_id, &target_program_bytes);

    // Deploy the protocol under test
    let protocol_program_id = Pubkey::new_unique();
    svm.add_program(protocol_program_id, &protocol_program_bytes);

    // Deploy MALICIOUS program that mimics the target's interface
    // but returns attacker-favorable results
    let malicious_program_id = Pubkey::new_unique();
    svm.add_program(malicious_program_id, &malicious_program_bytes);

    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();

    // === SETUP LEGITIMATE STATE ===
    // ... initialize protocol with legitimate target program ...

    // === ATTEMPT CPI WITH MALICIOUS PROGRAM ===
    // Pass malicious_program_id where target_program_id is expected
    let exploit_ix = Instruction::new_with_borsh(
        protocol_program_id,
        &instruction_data,
        vec![
            AccountMeta::new(attacker.pubkey(), true),
            // Account that should be the target program but is malicious
            AccountMeta::new_readonly(malicious_program_id, false),
            // ... other accounts the CPI expects
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[exploit_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // === VERIFY ===
    // If bug EXISTS: CPI to malicious program succeeds
    // If bug FIXED: transaction fails with "incorrect program id" error
    assert!(
        result.is_ok(),
        "CPI to malicious program should succeed if program ID not validated"
    );
}
```

### Template 4: Multi-Instruction Composition (Flash-Loan-Like Pattern)

Tests atomic borrow+use+repay patterns within a single transaction.

```rust
#[test]
fn test_multi_instruction_exploit() {
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    svm.add_program(program_id, &program_bytes);

    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();

    // === SETUP ===
    // ... initialize protocol, fund pools, create accounts ...

    // === RECORD BEFORE STATE ===
    let attacker_balance_before = /* read token balance */;
    let pool_balance_before = /* read pool balance */;

    // === BUILD MULTI-INSTRUCTION TRANSACTION ===
    // All instructions execute atomically in a single transaction
    // Same Clock values, same slot, all-or-nothing

    let ix_1_borrow = Instruction::new_with_borsh(
        program_id,
        &borrow_instruction_data, // Borrow large amount
        borrow_accounts.clone(),
    );

    let ix_2_exploit = Instruction::new_with_borsh(
        program_id,
        &exploit_instruction_data, // Use borrowed funds to manipulate state
        exploit_accounts.clone(),
    );

    let ix_3_extract = Instruction::new_with_borsh(
        program_id,
        &extract_instruction_data, // Extract value from manipulated state
        extract_accounts.clone(),
    );

    let ix_4_repay = Instruction::new_with_borsh(
        program_id,
        &repay_instruction_data, // Repay borrowed amount
        repay_accounts.clone(),
    );

    // All 4 instructions in ONE transaction (atomic)
    let tx = Transaction::new_signed_with_payer(
        &[ix_1_borrow, ix_2_exploit, ix_3_extract, ix_4_repay],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // === VERIFY ===
    assert!(result.is_ok(), "Multi-instruction exploit should succeed");

    let attacker_balance_after = /* read token balance */;
    let profit = attacker_balance_after - attacker_balance_before;
    assert!(
        profit > 0,
        "Attacker should profit from atomic multi-instruction exploit"
    );

    println!("Profit: {} tokens", profit);
    println!("Pool balance change: {}", pool_balance_before - /* pool after */);
}
```

### Template 5: PDA Collision/Seed Manipulation

Tests whether PDA derivation is unique and cannot collide across different logical entities.

```rust
#[test]
fn test_pda_collision() {
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    svm.add_program(program_id, &program_bytes);

    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();

    // === DERIVE TWO PDAs THAT SHOULD BE DIFFERENT ===
    // If seed schema is weak, different logical entities may share a PDA

    let (pda_entity_a, bump_a) = Pubkey::find_program_address(
        &[b"account", entity_a_key.as_ref()],
        &program_id,
    );

    let (pda_entity_b, bump_b) = Pubkey::find_program_address(
        &[b"account", entity_b_key.as_ref()], // Different entity, same seed prefix
        &program_id,
    );

    // === CHECK FOR COLLISION ===
    // These SHOULD be different addresses for different entities
    assert_ne!(
        pda_entity_a, pda_entity_b,
        "PDAs for different entities should not collide"
    );

    // === TEST CROSS-ENTITY ACCESS ===
    // Try to use entity_a's PDA in an instruction meant for entity_b
    let cross_access_ix = Instruction::new_with_borsh(
        program_id,
        &instruction_data_for_entity_b,
        vec![
            AccountMeta::new(attacker.pubkey(), true),
            AccountMeta::new(pda_entity_a, false), // Wrong PDA!
            // ... other accounts
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[cross_access_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // If bug EXISTS: cross-entity access succeeds (seeds not checked)
    // If bug FIXED: transaction fails with seeds constraint error
    assert!(
        result.is_err(),
        "Cross-entity PDA access should be rejected"
    );
}
```

---

## Template 6: Trident Fuzz Test (Anchor Programs Only)

> **Prerequisite**: `trident_available: true` in `build_status.md`. If false, skip to proptest or boundary-value tests.

Trident generates scaffolding from the program IDL. The verifier customizes the generated handlers to target the finding's instruction sequence and adds invariant assertions.

### Step 1: Initialize (if trident-tests/ does not exist)
```bash
trident init
```
This creates `trident-tests/fuzz_tests/` with handler templates derived from the program's IDL.

### Step 2: Customize Fuzz Instructions
Edit `trident-tests/fuzz_tests/fuzz_0/fuzz_instructions.rs`:
```rust
use trident_fuzz::*;

// Trident auto-generates FuzzInstruction enum from IDL.
// Customize: add invariant checks, bound parameters, add pre/post hooks.

impl FuzzInstruction {
    // Add custom invariant check after each instruction
    fn check_invariant(&self, accounts: &AccountsStorage) {
        // e.g., verify total_supply == sum(balances)
        // e.g., verify vault.amount >= total_shares
    }
}
```

### Step 3: Run Campaign (v0.11+ - no honggfuzz needed)
```bash
# Windows: set OpenSSL env vars if needed (auto-detect from common install paths)
# On Linux/macOS this is not needed (system OpenSSL is used)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]] && [ -z "$OPENSSL_DIR" ]; then
  for base in "/c/Program Files/OpenSSL-Win64" "/c/Program Files/OpenSSL"; do
    if [ -d "$base/include/openssl" ]; then
      export OPENSSL_DIR="$base" OPENSSL_LIB_DIR="$base/lib/VC/x64/MD" OPENSSL_INCLUDE_DIR="$base/include"
      break
    fi
  done
fi
# Run from trident-tests/ directory
cd trident-tests && trident fuzz run fuzz_0
# With detailed logging:
TRIDENT_LOG=1 trident fuzz run fuzz_0
```

### Step 4: Check for Violations
```bash
# Trident v0.11+ writes violations to .fuzz-artifacts/
ls -la trident-tests/.fuzz-artifacts/ 2>/dev/null
# Re-run with specific seed for reproduction:
trident fuzz run fuzz_0 <SEED>
```

### Evidence Tagging
- Trident violation with reproducible seed -> `[POC-PASS]` (mechanical proof)
- Trident campaign completes with no violations -> supports `[POC-FAIL]` for the fuzz variant
- Evidence tag: `[TRIDENT-FUZZ]` (subtype of `[CODE]`) - valid for both CONFIRMED and REFUTED

---

## Fork Testing Equivalent (Production Account Loading)

Solana does not have a direct Anvil-fork equivalent. Use this approach:

### Step 1: Dump Production Accounts
```bash
# Dump all accounts the protocol uses
solana account <config_account> --output json > config_dump.json
solana account <vault_account> --output json > vault_dump.json
solana account <user_account> --output json > user_dump.json
# Repeat for all relevant accounts
```

### Step 2: Load into LiteSVM
```rust
use solana_sdk::account::Account;

#[test]
fn test_with_production_state() {
    let mut svm = LiteSVM::new();

    // Load production account dumps
    let config_data: Account = serde_json::from_str(
        &std::fs::read_to_string("config_dump.json").unwrap()
    ).unwrap();
    svm.set_account(config_pubkey, config_data);

    let vault_data: Account = serde_json::from_str(
        &std::fs::read_to_string("vault_dump.json").unwrap()
    ).unwrap();
    svm.set_account(vault_pubkey, vault_data);

    // Deploy the program (use production program binary if available)
    svm.add_program(program_id, &program_bytes);

    // Now test against REAL production state
    // Evidence tag: [PROD-LITESVM]
}
```

### Step 3: Evidence Tagging
- Account dumps from mainnet RPC -> data tagged [PROD-ONCHAIN]
- LiteSVM tests with production data -> tagged [PROD-LITESVM]
- [PROD-LITESVM] is valid for REFUTED verdicts (equivalent to [PROD-FORK] on EVM)

---

