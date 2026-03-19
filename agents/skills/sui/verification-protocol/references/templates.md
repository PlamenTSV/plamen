# Verification Protocol - Test Templates (Sui Move)

> Part of the Sui Verification Protocol skill. Read `SKILL.md` for the core workflow.

## Test File Templates

### Template 1: Basic Exploit (Shared Object Mutation Without Authorization)

```move
#[test_only]
module exploit::test_shared_object_mutation {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    // Import the target module
    use target_package::target_module;

    /// BUG: {2-sentence description}
    /// EXPECTED: {what should happen}
    /// ACTUAL: {what does happen}
    #[test]
    fun test_unauthorized_shared_object_mutation() {
        let admin = @0xAD;
        let attacker = @0xAA;

        // === SETUP: Deploy protocol and create shared objects ===
        let mut scenario = test_scenario::begin(admin);
        {
            // Initialize protocol -- creates shared config, pools, etc.
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === RECORD BEFORE STATE ===
        let value_before;
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            value_before = target_module::get_balance(&pool);
            std::debug::print(&value_before);
            test_scenario::return_shared(pool);
        };

        // === EXECUTE EXPLOIT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            // Attacker calls function on shared object WITHOUT holding required capability
            // If bug exists: this succeeds (no auth check)
            // If bug fixed: this aborts with auth error
            target_module::vulnerable_function(
                &mut pool,
                /* malicious args */
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(pool);
        };

        // === VERIFY IMPACT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let value_after = target_module::get_balance(&pool);
            // THE ASSERTION THAT PROVES THE BUG
            // Design this so it PASSES when the bug EXISTS
            assert!(value_after != value_before, 0);
            test_scenario::return_shared(pool);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 2: Capability Object Theft/Misuse

Tests whether capability objects with `store` ability can be transferred and misused.

```move
#[test_only]
module exploit::test_capability_theft {
    use sui::test_scenario;
    use sui::transfer;

    use target_package::target_module::{Self, AdminCap};

    #[test]
    fun test_admin_cap_transfer_and_misuse() {
        let admin = @0xAD;
        let attacker = @0xAA;

        // === SETUP: Create protocol with admin capability ===
        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === ADMIN TRANSFERS CAP (simulating social engineering or compromised key) ===
        // This tests whether the protocol allows cap transfer at all (store ability)
        test_scenario::next_tx(&mut scenario, admin);
        {
            let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
            // If AdminCap has `store`, this succeeds via public_transfer
            // If AdminCap lacks `store`, only module-defined transfer works
            transfer::public_transfer(admin_cap, attacker);
        };

        // === ATTACKER USES STOLEN CAP ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);

            // Attacker performs admin action with stolen cap
            target_module::admin_withdraw(
                &admin_cap,
                &mut pool,
                /* drain all funds */
                test_scenario::ctx(&mut scenario),
            );

            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_shared(pool);
        };

        // === VERIFY: Attacker received funds ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&coin) > 0, 0);
            test_scenario::return_to_sender(&scenario, coin);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 3: Dynamic Field Manipulation

Tests unauthorized dynamic field addition or missing cleanup.

```move
#[test_only]
module exploit::test_dynamic_field_attack {
    use sui::test_scenario;
    use sui::dynamic_field;

    use target_package::target_module;

    #[test]
    fun test_dynamic_field_pollution() {
        let admin = @0xAD;
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === ATTACKER ADDS UNAUTHORIZED DYNAMIC FIELD ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut shared_obj = test_scenario::take_shared<target_module::SharedState>(&scenario);
            // If access control is missing, attacker can add dynamic fields
            // to shared object, potentially corrupting namespace
            target_module::add_field(
                &mut shared_obj,
                b"malicious_key",
                /* malicious value */
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(shared_obj);
        };

        // === VERIFY: Dynamic field exists and corrupts protocol logic ===
        test_scenario::next_tx(&mut scenario, admin);
        {
            let shared_obj = test_scenario::take_shared<target_module::SharedState>(&scenario);
            // Check that the malicious field exists and affects behavior
            let malicious_value = dynamic_field::borrow<vector<u8>, u64>(
                target_module::uid(&shared_obj),
                b"malicious_key",
            );
            assert!(*malicious_value > 0, 0);
            test_scenario::return_shared(shared_obj);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 4: Object Wrapping Value Loss

Tests whether destroying a wrapper object loses the wrapped value.

```move
#[test_only]
module exploit::test_wrapping_value_loss {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    use target_package::target_module;

    #[test]
    fun test_wrapped_balance_lost_on_destroy() {
        let user = @0xBB;

        let mut scenario = test_scenario::begin(user);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === USER DEPOSITS (balance gets wrapped inside protocol object) ===
        test_scenario::next_tx(&mut scenario, user);
        {
            let coin = coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut scenario));
            let mut protocol_obj = test_scenario::take_shared<target_module::Vault>(&scenario);
            target_module::deposit(
                &mut protocol_obj,
                coin,
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(protocol_obj);
        };

        // === TRIGGER DESTRUCTION PATH (if exists) ===
        test_scenario::next_tx(&mut scenario, user);
        {
            let mut protocol_obj = test_scenario::take_shared<target_module::Vault>(&scenario);
            // Call function that destroys/unwraps without returning inner balance
            // If bug exists: balance is silently dropped (if drop ability) or tx aborts
            // If safe: balance is returned to user or error prevents destruction
            target_module::close_vault(
                &mut protocol_obj,
                test_scenario::ctx(&mut scenario),
            );
            test_scenario::return_shared(protocol_obj);
        };

        // === VERIFY: User's funds are not lost ===
        test_scenario::next_tx(&mut scenario, user);
        {
            // If funds were properly returned, user should have a Coin
            // If funds were lost, this take_from_sender will fail
            let coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&coin) == 1000, 0);
            test_scenario::return_to_sender(&scenario, coin);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 5: Programmable Transaction Block (PTB) Multi-Command Exploit

Tests atomic multi-step attacks within a single transaction. In Sui, PTBs allow composing multiple Move calls atomically.

```move
#[test_only]
module exploit::test_ptb_exploit {
    use sui::test_scenario;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    use target_package::target_module;

    /// Simulates a PTB that chains multiple calls atomically.
    /// In test_scenario, each block within next_tx represents a single tx.
    /// To simulate PTB-like atomicity, chain operations within a single block.
    #[test]
    fun test_atomic_multi_step_exploit() {
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(attacker);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === RECORD BEFORE STATE ===
        test_scenario::next_tx(&mut scenario, attacker);
        let balance_before = {
            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let val = target_module::get_total_value(&pool);
            test_scenario::return_shared(pool);
            val
        };

        // === EXECUTE PTB-LIKE ATOMIC EXPLOIT ===
        // All operations in a single next_tx block are atomic
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);

            // Step 1: Manipulate state (e.g., flash borrow)
            let borrowed = target_module::flash_borrow(
                &mut pool,
                1_000_000,
                test_scenario::ctx(&mut scenario),
            );

            // Step 2: Use borrowed funds to manipulate price/state
            target_module::swap_to_manipulate(
                &mut pool,
                &borrowed,
                test_scenario::ctx(&mut scenario),
            );

            // Step 3: Extract value at manipulated price
            let profit = target_module::extract_at_manipulated_price(
                &mut pool,
                test_scenario::ctx(&mut scenario),
            );

            // Step 4: Repay flash loan
            target_module::flash_repay(
                &mut pool,
                borrowed,
                test_scenario::ctx(&mut scenario),
            );

            test_scenario::return_shared(pool);

            // Transfer profit to attacker
            transfer::public_transfer(profit, attacker);
        };

        // === VERIFY PROFIT ===
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let profit_coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&profit_coin) > 0, 0);
            test_scenario::return_to_sender(&scenario, profit_coin);

            let pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let balance_after = target_module::get_total_value(&pool);
            assert!(balance_after < balance_before, 0); // Pool lost funds
            test_scenario::return_shared(pool);
        };

        test_scenario::end(scenario);
    }
}
```

### Template 6: Concurrent Shared Object Access (Ordering Attack)

Tests whether protocol behavior depends on transaction ordering for shared objects.

```move
#[test_only]
module exploit::test_ordering_attack {
    use sui::test_scenario;

    use target_package::target_module;

    #[test]
    fun test_front_run_shared_object() {
        let admin = @0xAD;
        let user = @0xBB;
        let attacker = @0xAA;

        let mut scenario = test_scenario::begin(admin);
        {
            target_module::initialize(test_scenario::ctx(&mut scenario));
        };

        // === SCENARIO A: Normal ordering (admin sets fee, then user trades) ===
        test_scenario::next_tx(&mut scenario, admin);
        {
            let mut config = test_scenario::take_shared<target_module::Config>(&scenario);
            target_module::set_fee(&mut config, 100, test_scenario::ctx(&mut scenario)); // 1%
            test_scenario::return_shared(config);
        };

        test_scenario::next_tx(&mut scenario, user);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let config = test_scenario::take_shared<target_module::Config>(&scenario);
            let result_normal = target_module::swap(
                &mut pool, &config, /* ... */
                test_scenario::ctx(&mut scenario),
            );
            // Record normal result
            test_scenario::return_shared(pool);
            test_scenario::return_shared(config);
        };

        // === SCENARIO B: Attacker front-runs (attacker acts before admin's fee change) ===
        // Simulate by reversing order: attacker trades BEFORE admin updates fee
        // If protocol reads fee from shared config at execution time,
        // attacker can front-run a fee increase
        test_scenario::next_tx(&mut scenario, attacker);
        {
            let mut pool = test_scenario::take_shared<target_module::Pool>(&scenario);
            let config = test_scenario::take_shared<target_module::Config>(&scenario);
            let result_frontrun = target_module::swap(
                &mut pool, &config, /* same params */
                test_scenario::ctx(&mut scenario),
            );
            // Compare: attacker got better rate than user due to ordering
            test_scenario::return_shared(pool);
            test_scenario::return_shared(config);
        };

        test_scenario::end(scenario);
    }
}
```

---

