---
name: "event-correctness"
description: "Trigger 15 events detected in recon event_definitions.md (optional skill) - Used By breadth agents (assigned to core state or dedicated agent)"
---

# Skill: EVENT_CORRECTNESS

> **Trigger**: >15 events detected in recon event_definitions.md (optional skill)
> **Used By**: breadth agents (assigned to core state or dedicated agent)
> **Purpose**: Verify emitted event parameters match actual state changes

## Methodology

### Step 1: Inventory All Emit Statements
From `{SCRATCHPAD}/emit_list.md`, extract every `emit` statement with:
- Event name, parameter values passed, source location
- The state-changing operation(s) that precede the emit

### Step 2: Parameter Semantic Check
For EACH emit statement, verify:

| # | Check | Question |
|---|-------|----------|
| 1 | **Value accuracy** | Does each parameter reflect the ACTUAL post-operation state? (not a stale pre-operation value, not an input parameter that was modified before use) |
| 2 | **Index correctness** | If the event indexes an entity (ID, address, index), is the index the CORRECT entity? (not off-by-one, not a different entity's ID, not a loop variable after increment) |
| 3 | **Ordering** | Is the emit placed AFTER all state changes it describes? (not before a conditional that could change the values) |
| 4 | **Conditional coverage** | If the function has branching logic, does EVERY branch that modifies state emit the appropriate event? (no silent state changes) |
| 5 | **Parameter count** | Do the emitted parameters match the event definition? (Solidity allows emitting fewer params - missing params default to zero) |
| 6 | **Semantic correctness** | Does each emitted variable match the SEMANTIC INTENT of the parameter name? If the event parameter is named `tokensReceived`, is the emitted value the actual tokens received (output), or is it the input amount (e.g., DAI spent)? Compare the parameter name against the variable being emitted - a mismatch between name semantics and actual value is a finding even if types match. |

### Step 3: Off-Chain Impact Assessment
For events consumed by off-chain systems (indexers, frontends, monitoring):
- If event parameters are wrong → off-chain state diverges from on-chain state
- Severity: typically LOW-MEDIUM unless financial decisions depend on indexed events

## Output
Findings use IDs `[EVT-N]`. Include the emit location, the incorrect parameter, and the correct value it should emit.
