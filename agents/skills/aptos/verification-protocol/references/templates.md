# Verification Protocol - Test Templates (Aptos Move)

> Part of the Aptos Verification Protocol skill. Read `SKILL.md` for the core workflow.

## Test File Template

```move
#[test_only]
module test_addr::test_hypothesis_N {
    use std::signer;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin;
    use aptos_framework::timestamp;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;

    // Import protocol modules under test
    // use protocol_addr::module_name;

    /// BUG: {2 sentence description}
    /// EXPECTED: {what should happen}
    /// ACTUAL: {what does happen}

    // === CONSTANTS ===
    const INITIAL_BALANCE: u64 = 1_000_000_000; // 10 APT (8 decimals)
    const ATTACK_AMOUNT: u64 = 100_000_000;     // 1 APT

    // === SETUP HELPER ===
    fun setup_test(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        // Initialize timestamp for time-dependent tests
        timestamp::set_time_has_started_for_testing(aptos_framework);

        // Create test accounts
        account::create_account_for_test(signer::address_of(admin));
        account::create_account_for_test(signer::address_of(attacker));
        account::create_account_for_test(signer::address_of(victim));

        // Initialize and fund with AptosCoin if needed
        // let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(aptos_framework);
        // coin::register<aptos_coin::AptosCoin>(attacker);
        // aptos_coin::mint(aptos_framework, signer::address_of(attacker), INITIAL_BALANCE);

        // Deploy and configure protocol
        // module_name::initialize(admin, ...);
    }

    // === TEST: Direct bug demonstration ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123,
        victim = @0x456
    )]
    fun test_HN_bug_demonstration(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        setup_test(aptos_framework, admin, attacker, victim);

        // 1. RECORD BEFORE
        // let value_before = module_name::get_critical_value();

        // 2. ACTION -- perform the operation that triggers the bug
        // module_name::vulnerable_function(attacker, ATTACK_AMOUNT);

        // 3. RECORD AFTER
        // let value_after = module_name::get_critical_value();

        // 4. PROVE BUG -- assertion PASSES when bug EXISTS
        // assert!(value_after != value_before, 0); // or specific condition
    }

    // === TEST: Impact demonstration (optional) ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123,
        victim = @0x456
    )]
    fun test_HN_impact(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
        victim: &signer,
    ) {
        setup_test(aptos_framework, admin, attacker, victim);

        // Show cumulative impact or attacker profit
        // Multiple iterations of exploit if repeatable
    }

    // === TEST: Expected revert (if testing access control) ===
    #[test(
        aptos_framework = @aptos_framework,
        admin = @protocol_addr,
        attacker = @0x123
    )]
    #[expected_failure(abort_code = 0x50003, location = protocol_addr::module_name)]
    fun test_HN_should_revert_but_doesnt(
        aptos_framework: &signer,
        admin: &signer,
        attacker: &signer,
    ) {
        // If this test FAILS (does NOT abort), the access control is broken
        // setup...
        // module_name::admin_only_function(attacker); // should abort but doesn't
    }
}
```

### Move Test Patterns

**Time manipulation**:
```move
// Advance time by N seconds
timestamp::fast_forward_seconds(3600); // 1 hour
```

**Account creation**:
```move
account::create_account_for_test(signer::address_of(user));
```

**Coin setup (legacy Coin standard)**:
```move
let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(aptos_framework);
coin::register<AptosCoin>(user);
aptos_coin::mint(aptos_framework, user_addr, amount);
```

**Fungible Asset setup (new FA standard)**:
```move
// FA objects are typically created in module init
// For testing, use the module's initialization function
```

**Object creation for testing**:
```move
let constructor_ref = object::create_object(signer::address_of(admin));
let object_signer = object::generate_signer(&constructor_ref);
```

**Expected failure annotation**:
```move
#[expected_failure]                                    // any abort
#[expected_failure(abort_code = 1)]                    // specific code
#[expected_failure(abort_code = 0x10001, location = module_addr::module)] // category + reason
```

---
