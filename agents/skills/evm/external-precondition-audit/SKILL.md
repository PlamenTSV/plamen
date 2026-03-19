---
name: "external-precondition-audit"
description: "Trigger Pattern Any external contract interaction detected in attack_surface.md - Inject Into Breadth agents (merged via M7 hierarchy)"
---

# EXTERNAL_PRECONDITION_AUDIT Skill

> **Trigger Pattern**: Any external contract interaction detected in attack_surface.md
> **Inject Into**: Breadth agents (merged via M7 hierarchy)
> **Constraint**: Interface-level inference only -- no production fetch required

For every external contract the protocol interacts with:

## 1. Interface-Level Requirement Inference

From the interface/import used by the protocol, infer what the external contract requires:

| External Function Called | Parameters Passed | Likely Preconditions (from interface) | Our Protocol Validates? |
|-------------------------|-------------------|---------------------------------------|------------------------|

**Inference method**: Read the function signature, parameter names, NatSpec comments (if any),
and common patterns for that function type. Example: `IVault.swap(FundManagement memory funds)`
-> infer that `funds.sender` must be authorized, `funds.recipient` determines where output goes.

## 2. Return Value Consumption

| External Call | Return Type | How Protocol Uses Return | Failure Mode if Return Unexpected |
|--------------|-------------|-------------------------|----------------------------------|

For each return value: what happens if it returns 0? What happens if it returns MAX?
What happens if the external call reverts?

## 3. State Dependency Mapping

| Protocol State | Depends on External State | External State Can Change Without Our Knowledge? |
|---------------|--------------------------|--------------------------------------------------|

For each dependency: model what happens when the external state changes between
our protocol's read and use.

## Step Execution Checklist
| Section | Required | Completed? |
|---------|----------|------------|
| 1. Interface-Level Requirement Inference | YES | Y/N/? |
| 2. Return Value Consumption | YES | Y/N/? |
| 3. State Dependency Mapping | YES | Y/N/? |
