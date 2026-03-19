# Verification Protocol - Advanced Reference (Sui Move)

> Part of the Sui Verification Protocol skill. Read `SKILL.md` for the core workflow first.

## RAG Queries Before PoC (MANDATORY for HIGH/CRITICAL)

Before writing PoC tests for HIGH/CRITICAL findings:

### Step 1: Get Attack Vectors
```
mcp__unified-vuln-db__get_attack_vectors(bug_class="{category}")
```
Returns step-by-step attack strategies from real exploits.

### Step 2: Get PoC Templates
```
mcp__unified-vuln-db__get_poc_template(bug_class="{category}", framework="move_test")
```
Returns example test structures for this vulnerability type.

### Step 3: Get Similar Exploit Code
```
mcp__unified-vuln-db__get_similar_findings(pattern="{vulnerability description}")
```
Returns similar historical findings with code examples.

### Step 4: Validate Before Committing
```
mcp__unified-vuln-db__validate_hypothesis(hypothesis="{your finding summary}")
```
Returns supporting/contradicting evidence from historical exploits.

### Step 5: Live Search for Sui-Specific Precedents
```
mcp__unified-vuln-db__search_solodit_live(
  keywords="{sui move vulnerability pattern}",
  impact=["HIGH", "CRITICAL"],
  tags=["Access Control", "Logic Error"],
  language="Move",
  quality_score=3,
  max_results=15
)
```

### RAG Integration Rules

| RAG Result | Impact on Verification |
|------------|----------------------|
| Attack vector found | Use documented steps as test basis |
| Similar exploit exists | Extract key attack pattern |
| PoC template available | Adapt template to Sui test_scenario |
| No similar findings | Proceed with manual analysis, note uncertainty |

### Document RAG Evidence

In the verification output, add:
```markdown
### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching Sui/Move vulnerabilities]
```

---

## RAG Confidence Override

| RAG Confidence | Local Verdict | Final Verdict | Action |
|----------------|---------------|---------------|--------|
| >= 7/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- strong precedent |
| >= 6/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- significant precedent |
| < 6/8 matches | FALSE_POSITIVE | FALSE_POSITIVE | Allowed -- limited precedent |

---

## Chain Hypothesis PoC Requirements

Chain hypotheses receive PRIORITY verification. Multi-step exploits must test the COMPLETE sequence:

```move
#[test]
fun test_chain_hypothesis_full() {
    let admin = @0xAD;
    let attacker = @0xAA;

    let mut scenario = test_scenario::begin(admin);
    {
        target_module::initialize(test_scenario::ctx(&mut scenario));
    };

    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute action that creates the postcondition
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let mut shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Execute enabler action that creates the precondition for Finding A
        target_module::enabler_action(
            &mut shared_obj,
            /* enabler args */
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert the precondition for Finding A is now met
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Verify the enabler created the necessary state
        let postcondition_value = target_module::get_state(&shared_obj);
        assert!(postcondition_value == expected_postcondition, 0);
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute previously-blocked attack using postcondition
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let mut shared_obj = test_scenario::take_shared<target_module::Pool>(&scenario);
        // Execute the attack that was previously blocked
        target_module::blocked_attack(
            &mut shared_obj,
            /* attack args */
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_shared(shared_obj);
    };

    // ========================================
    // VERIFY CHAIN IMPACT
    // Combined impact should exceed either finding alone
    // ========================================
    test_scenario::next_tx(&mut scenario, attacker);
    {
        let profit_coin = test_scenario::take_from_sender<Coin<SUI>>(&scenario);
        let profit = coin::value(&profit_coin);
        assert!(profit > 0, 0);
        test_scenario::return_to_sender(&scenario, profit_coin);
    };

    test_scenario::end(scenario);
}
```

### Chain Dismissal Requirements

To mark a chain hypothesis as FALSE_POSITIVE, you MUST:
1. Prove enabler finding does NOT create the postcondition, OR
2. Prove blocked finding still blocked EVEN WITH the postcondition, OR
3. Prove chain sequence is impossible due to object ownership/access/state constraints

Each proof requires [PROD-ONCHAIN], [PROD-SOURCE], or [CODE] evidence -- no [MOCK] evidence allowed.

### Bidirectional Chain Analysis (Rule 6 Extension)
For chain hypotheses where enabler OR blocked finding involves a semi-trusted role (operator/keeper/crank):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role timing/ordering to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED with note: "Chain bidirectional analysis incomplete."

---

## Chain Hypothesis Protection

> **CRITICAL**: Chain hypotheses receive elevated protection because they represent multi-step attacks initially missed.

### Protection Rules

1. **RAG >= 6/8 + Chain**: Cannot be dismissed as FALSE_POSITIVE
2. **3+ agents flagged + Chain**: Need PRODUCTION evidence to refute
3. **Chain PoC MUST test full sequence**: Both enabler AND blocked finding

---

## Sui-Specific Testing Considerations

### No Fork Testing Equivalent

Sui does not have an Anvil-like mainnet fork. Use these alternatives:

1. **Published package testing**: If the protocol is deployed on testnet/mainnet, use the published package address in Move.toml dependencies and write tests against the actual on-chain bytecode. Evidence tag: [PROD-PUBLISHED].

2. **Object state dumps**: Use Sui RPC to dump production object state:
```bash
sui client object <object_id> --json > object_dump.json
```
Then reconstruct the object state in test_scenario setup. Evidence tag: [PROD-ONCHAIN] for the dump, [CODE] for the reconstructed test.

3. **Package source verification**: Use Sui Explorer to verify published package source matches audited code. Evidence tag: [PROD-SOURCE].

### PTB-Aware Testing

Programmable Transaction Blocks (PTBs) allow composing multiple Move calls atomically in a single Sui transaction. When testing:

- **Atomic composition**: Multiple commands in a PTB share the same transaction context. Objects returned by one command can be passed to the next. In test_scenario, simulate this by performing multiple operations within a single `next_tx` block.
- **Move call chaining**: PTB allows calling functions from different packages in sequence. Test cross-package interactions within a single block.
- **Object passing between commands**: PTB can split a Coin, use part in one call and part in another. Simulate with explicit `coin::split` in tests.
- **Gas estimation**: PTB gas is the sum of all commands. Complex atomic exploits may hit gas limits on mainnet that test_scenario does not enforce.

### Shared Object Concurrency Testing

test_scenario processes transactions sequentially, but on mainnet, transactions touching the same shared object go through consensus and may be reordered. To test ordering sensitivity:

1. **Test both orderings**: Write two tests with the same operations but different `next_tx` ordering. If outcomes differ, the protocol is ordering-sensitive.
2. **Test interleaved operations**: Alternate between two actors (user and attacker) operating on the same shared object to simulate concurrent access.
3. **Document ordering assumptions**: If the protocol assumes "admin action happens before user action," flag this as an ordering dependency.

---

## Dual-Perspective Verification (MANDATORY)

### Phase 1 - ATTACKER: Assume you ARE the attacker.
- What is the complete transaction sequence?
- What objects do you need to create/acquire?
- What is the profit/damage with real coin amounts?
- Can you compose multiple operations in a single PTB for atomicity?
- Why would this succeed? (Which access control or validation is missing/wrong?)

### Phase 2 - DEFENDER: Assume you are the protocol team.
- What capability check prevents this?
- What object ownership model blocks unauthorized access?
- What module-level access restriction (`public(package)` vs `public`) prevents external calls?
- Why is this safe by design?

### Phase 3 - VERDICT: Which argument won?

---

## Realistic Parameter Validation

Substitute ACTUAL protocol constants (basis points, fee rates, thresholds, maximum values).
Apply Rule 10: Use worst realistic operational state, not current snapshot.

```
State: 'With real constants [fee_bps=X, max_leverage=Y, tvl=Z] at worst-state
[max_users, max_positions], bug triggers when [condition]'
OR: 'With real constants, bug does NOT trigger because [reason]'
```

---

## Anti-Downgrade Guard (MANDATORY for VS/BLIND findings)

When verifying a finding from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the function fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Module A has protection X but Module B lacks it for the same user action -> defense parity gap, NOT "by design". Minimum severity: Medium.

---

## New Observations (MANDATORY)

If during verification you discover a NEW bug, object ownership gap, or edge case NOT covered by any existing hypothesis, document it under:

### New Observations
- [VER-NEW-1]: {title} -- {module::function} -- {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

---

## Error Trace Output (MANDATORY for CONTESTED/FALSE_POSITIVE)

When verdict is CONTESTED or FALSE_POSITIVE, document the failure details:

### Error Trace
- **Failure Type**: ABORT_CODE / OBJECT_NOT_FOUND / TYPE_MISMATCH / BORROW_ERROR / ARITHMETIC / UNEXPECTED_STATE
- **Location**: {module}::{function} (approximate line in source)
- **Error Code**: {Move abort code or custom error constant, if any}
- **State at Failure**: {key object fields and their values when test failed}
- **Investigation Question**: {What would need to be answered to resolve this}

---

## Bidirectional Role Analysis (MANDATORY)

> **CRITICAL**: Semi-trusted role findings CANNOT be marked REFUTED unless BOTH directions are analyzed.

### HALT CONDITIONS for Semi-Trusted Role Findings

Before marking ANY finding involving OPERATOR/KEEPER/CRANK roles as REFUTED:

- [ ] **Direction 1 analyzed**: ROLE -> USER harm scenarios
- [ ] **Direction 2 analyzed**: USER -> ROLE exploitation
- [ ] **Precondition Griefability table completed**: All role function preconditions checked
- [ ] **User exploitation scenarios documented**

### Direction 2 Enforcement

If Direction 2 (USER -> ROLE) is NOT analyzed:
- CANNOT return REFUTED
- MUST return CONTESTED with note: "Direction 2 not analyzed"
- Finding flagged for depth review

---

