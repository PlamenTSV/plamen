# Plamen Terminal-Negative Provider Forensic

Date: 2026-07-24  
Status: blocker specification; not implemented or accepted  
Scope: P0-C/R/V/X, generic P0-AF, P1-L, challenge/backend parity

## 1. Verdict

The terminal-negative provider is not production-reachable and is unsafe to
activate under its current contract.

Four constraints must be added first:

1. A provider cannot self-declare its domain exhaustive.
2. WER `assessors` are declared labels, not proof that a reviewer executed.
3. The broker must pin the executable/module, argv, parser, enumerator, and
   oracle implementation.
4. Every consumer must require exact candidate content and premise identities,
   not either/or fallback.

Claude/Codex should produce typed negative challenges. They should not become
generic terminal-negative authorities. Terminal providers are backend-neutral
code or proof/checker executions over a finite code-owned domain.

## 2. Current production reachability

| Path | Current state | Authority |
|---|---|---|
| Applied semantic equivalence | Live adapter | Exact alias-to-survivor authority |
| Claude application skeptic | Live WER-backed transport | Proposal/challenge only |
| Codex application skeptic | Explicit unsupported debt | Reopen/debt |
| Fixture subprocess | Tests only | None |
| Mechanical-scope provider | Registry/schema/replay/tests | No launcher, WorkPlan, PhaseIO, registration |
| Exhaustive-negative provider | Registry/schema/replay/tests | No launcher, WorkPlan, PhaseIO, registration |
| Broker consumers | Live | Usually empty provider denominator; fail open |
| Generic compound evaluator/report binder | Library/tests | No production caller |
| L1 composition | Live shadow adapter | Producer refutations remain eligible |
| Severity | Shadow unless cut over | No default report-tier authority |
| Report disposition | Live | BODY retention without central authority |

No non-test production call was found to:

- `register_completed_negative_closure_provider`
- `evaluate_compound_work_item`
- `bind_compound_report`
- `validate_compound_report_bindings`

Focused fail-open safety evidence: 57 passed, 2 opt-in live canaries skipped.

## 3. Activation blockers

1. No provider launcher or provider PhaseIO contract.
2. Provider output can self-label `FULL`/`EXHAUSTIVE`.
3. WER launches one worker; assessor labels do not run an assessor.
4. Broker does not pin the actual implementation.
5. Provider subject/evidence manifests lack code-owned planning provenance.
6. Consumers use inexact premise/content fallback.
7. A model capability is incorrectly marked terminal-negative-capable.
8. Claude/Codex proposal parity is incomplete.
9. Compound evaluation/report binding is test-only.
10. L1 central negative adapter is shadow-only.
11. Any unrelated malformed bundle can veto all decisions instead of scoped
    debt.
12. Process containment terminology is conflated with semantic eligibility.
13. Markdown regex harvest is proposal-only and cannot establish completeness.
14. Future severity downrates may depend on negative premises unless centrally
    constrained.

## 4. Two separate systems

### 4.1 NegativeChallengeWorkPlan

Models, skeptics, verifiers, inventory, report agents, compound analysis, and
L1 facts may challenge a candidate or propose a refutation. Failure, absence,
unsupported backend, or disagreement reopens or retains the candidate.

### 4.2 TerminalNegativeProviderWorkPlan

Code-owned providers run only for:

- exact deterministic scope exclusion;
- already-applied lossless equivalence;
- complete finite enumeration;
- checked proof/model checking with an exact finite obligation set and checker.

Temporal, economic, environmental, externally contingent, open-ended,
model-reviewed, fuzzed, or merely bounded claims return `UNSUPPORTED`.

## 5. Production flow

Initially run one explicit negative-authority phase after verification and before
report disposition in both SC and L1:

```text
negative-producing sources
  -> exact challenge ledger
  -> code-owned provider-support planner
  -> subject/domain/oracle manifests
  -> PhaseIO prepare
  -> observed provider execution
  -> independently observed review or broker recomputation
  -> exact denominator reconciliation
  -> central bundle registration
  -> broker replay
  -> lifecycle/report/compound/L1 consumers
```

Every broken edge yields reopening, BODY retention, mandatory re-verification,
or visible human-review debt.

## 6. Challenge ledger

Every negative assertion records:

```text
challenge_id
run_id
snapshot_digest
origin_phase
origin_artifact + exact record digest
candidate_id
work_item_id
candidate_content_sha256
candidate_premise_ids
requested_effect
producer identities/invocations
supporting evidence identities/digests
challenge_digest
```

Each row reconciles to exactly one of:

- authorized terminal decision;
- authorized alias;
- reopened candidate;
- BODY retention;
- mandatory human review;
- unsupported-provider debt.

## 7. Provider plan and manifests

### 7.1 Provider WorkPlan

Root:

```text
schema_version
run_id
pipeline
mode
snapshot_digest
provider_registry_digest
challenge_denominator
work_items
shards
expected_output_denominator
work_plan_digest
```

Each work item:

```text
provider_work_item_id
challenge_id
candidate/work/premise/content binding
requested_effect
provider_id/version/kind
provider_support_state = READY | UNSUPPORTED | DEBT
unsupported_reason
subject/domain/oracle manifest IDs and digests
expected worker output
expected reviewer output
```

The code-owned registry calculates support. A model cannot select `READY`.

### 7.2 Domain manifest

Candidate premises are not an execution domain.

```text
domain_kind = MECHANICAL_SCOPE | FINITE_ENUMERATION | CHECKED_PROOF
enumerator identity/version/code digest
source/build/snapshot digest
dimensions and partitions
ordered member denominator or partition manifests
premise-to-domain mapping
unrepresented dimensions
coverage witness
coverage_state
manifest digest
```

The provider does not authoritatively set `coverage_state=COMPLETE`. The
independent reviewer derives it from expected and observed members.

### 7.3 Oracle manifest

```text
oracle identity/version/code digest
author identity/independence binding
property per premise/harm claim
input/result interpretation
environment-fidelity contract
positive/negative controls
ambiguity/conflict policy
manifest digest
```

Failed controls, ambiguity, conflicts, unresolved external dimensions, or
environment mismatch remove terminal eligibility.

## 8. Provider result and review

The provider emits raw member results, never authoritative `exhaustive`.

The separate review receipt binds:

```text
subject/domain/oracle digests
worker completion/publish digests
provider output digest
expected/observed/missing/duplicate/unexpected members
oracle control results
unresolved/conflicting results
calculated coverage state
proposed effect
reviewer executable/code digest
reviewer completion/publish digests
review digest
```

The broker rechecks every inexpensive invariant. For proof engines it validates
the certificate and checker identity.

WER assessor metadata is not review evidence. Either run a separately observed
reviewer or deterministically recompute completeness in the broker.

## 9. Central bundle

Bundle v2 must include:

- planner PhaseIO receipt;
- exact snapshot/challenge identity;
- worker WER;
- real reviewer WER or deterministic recomputation receipt;
- domain and oracle manifests;
- review receipt;
- provider executable/argv/parser/enumerator/oracle binding;
- atomic registration receipt.

Resolution has no premise-or-content fallback. Both are mandatory.

## 10. Authority rules

Mechanical scope can cover only decidable structured boundaries. It cannot infer
expected behavior, trust, harmlessness, or externality from prose. A
cross-boundary claim remains eligible if it affects in-scope consumers.

Exhaustive authority requires:

- an exactly bound property;
- every relevant input/state/actor/order/temporal/external dimension represented
  or formally abstracted;
- exact source/build/environment;
- every member/proof obligation accounted for;
- an independent/protocol-authored exact oracle;
- independent checking;
- no positive witness or conflict.

Fuzzing, one PoC failure, bounded symbolic execution, model agreement, and a
`formal proof` label are supporting-only.

## 11. Required production seams

- one explicit post-verification negative-authority phase in SC and L1;
- driver planning, worker/reviewer launch, registration, replay, delivery;
- PhaseIO contracts for each stage;
- code/tool terminal provider capabilities; model terminal flag removed;
- broker domain/oracle/reviewer validation and scoped debt;
- exact content+premise binding in application skeptic, inventory, lifecycle,
  security obligations, and report disposition;
- live compound evaluator→report binder→validator chain;
- live L1 central adapter;
- severity distinction between positive lower-severity evidence and
  negative-premise authority;
- typed candidate-negative sidecars primary, Markdown legacy/proposal-only.

## 12. Red-to-green matrix

Semantic:

1. Claimed exhaustive with a missing member.
2. Unexpected/duplicate member.
3. Premise without domain mapping.
4. Unresolved temporal/external/environment dimension.
5. Provider and oracle share an unauthorized principal.
6. Reviewer listed but never launched.
7. Arbitrary executable under a registered provider name.
8. Stale provider/enumerator/oracle/source/build/candidate digest.
9. Bounded run mislabeled exhaustive.
10. Known-positive control not detected.
11. Oracle conflict.
12. Exact candidate versus sibling.
13. Matching content but different premises, and vice versa.

Fault/PhaseIO:

- inject failure at plan, prepare, WER arm, launch, partial output, completion,
  publish, reviewer, registration, ledger publication, and consumer replay;
- resume is idempotent, produces no duplicate authority, and preserves/reopens;
- timeout, nonzero exit, oversized streams, malformed JSON/Unicode, unexpected
  output, pre-existing output, missing executable, lock contention, concurrent
  mutation, disk failure, path escape, case collision, stale projection, and
  unrelated bundle corruption.

Backend/ecosystem:

- Claude/Codex challenge transports produce equivalent reopen/debt semantics;
- terminal providers are backend-neutral;
- representative SC ecosystems and Go/Rust L1;
- Windows, Linux, macOS path/process behavior;
- compound and L1 adapters;
- all modes with empty/unsupported/partial/supported denominators.

For unsupported ecosystems, the correct result is `UNSUPPORTED` plus retained
BODY/re-verification.

## 13. Rollout

1. Finish PhaseIO and worker lifecycle authority first.
2. Correct authority flags/names, require content+premise, and scope broker debt.
3. Implement challenge ledger, provider plan, domain/oracle contracts,
   implementation pinning, and real reviewer boundary.
4. Run shadow-only with no report suppression.
5. Cut over the narrow mechanical-scope provider after multi-ecosystem,
   fault/resume, and held-out checks.
6. Add exhaustive adapters one provable finite domain at a time.
7. Wire live compound evaluation/report binding.
8. Add the L1 central adapter.
9. Add Codex challenge parity.
10. Run bounded non-ground-truth Claude canaries and resumes.

## 14. Plan correction

Replace “Codex terminal provider parity” with:

“Claude/Codex challenge-provider parity; terminal providers are backend-neutral
code.”

Also require:

- actual reviewer execution;
- provider executable/argv/parser/enumerator/oracle pinning;
- calculated, not self-declared, completeness;
- exact content-and-premise matching;
- provider PhaseIO and denominator delivery;
- subject-scoped versus global broker debt.
