# Plamen Program Facts Stage-2 Emit-Only Author Handoff

Date: 2026-07-29
Status: DRAFT - BLOCKED ON CHAIN-TAIL AND WHOLE-RUNTIME REFREEZE
Disposition: NO AUTHOR PASS; INDEPENDENT REVIEW IS REQUIRED

## 0. Review boundary

This is an author handoff, not a certification. The author implemented and
tested the narrow Program Facts Stage-2 EVM emit-only driver integration. The
author must not issue the independent PASS disposition.

No commit, push, live audit, model launch, or provider activation was performed
by this workstream. No Program Facts output is consumed by prompts, ranking,
chain analysis, verification, or reporting in Stage 2.

The implementation follows the scope and cutover constraints in:

- <LOCAL_USER_ROOT>\Downloads\Plamen_Typed_CPG_Implementation_Blueprint_2026-07-24.md
- Blueprint sections 12 through 16 govern this Stage-2 integration.

The production implementation is frozen while final closure evidence is
collected. A separate CI/toolchain owner is repairing the public Windows
copy-install omission described in section 8.

## 1. Implemented production surface

### 1.1 New driver integration

File:

- scripts/program_facts_driver_integration.py

Responsibilities:

- Treat the driver hook as a model-free PhaseIO publisher.
- Run only for EVM smart-contract audits.
- Return an exact no-op for Solana, Soroban, Aptos, Sui, Go L1, Rust L1, and
  Daml L1.
- Capture an immutable run and audit-snapshot predecessor at
  _program_facts_inputs/checkpoint_capture.v1.json.
- Capture the reviewed installed methodology inputs through PhaseIO.
- Build the Stage-2 EVM PROVIDER_UNAVAILABLE bundle truthfully.
- Publish exactly these three sidecars:
  - mechanical_program_facts.v1.json
  - mechanical_program_facts_receipt.v1.json
  - mechanical_program_facts_debt.v1.json
- Commit every output through PhaseIO and ArtifactLedger authority.
- Recover a partially published bake without re-arming its immutable inputs.
- Reject run, snapshot, source, methodology, registry, tool, build, launch, or
  output drift.
- Keep consumer_activation false by construction.
- Never interpret missing facts as negative authority.

### 1.2 PhaseIO contracts

File:

- scripts/phase_io_contracts.py

Added or corrected contracts:

- program_facts_checkpoint_capture
  - model-free DRIVER work unit
  - zero inputs
  - one immutable CREATE output
- program_facts_methodology_capture
  - consumes the immutable checkpoint capture
  - publishes the reviewed methodology authority sidecars
- program_facts_bake
  - consumes the immutable checkpoint capture and methodology outputs
  - publishes exactly the three Program Facts sidecars

Authority is intentionally three-way:

- Methodology inputs must replay their exact methodology producer, contract,
  and launch authority.
- The checkpoint capture must replay its exact checkpoint producer, contract,
  and launch authority.
- Other reviewed _program_facts_inputs JSON files are same-run DRIVER
  producers with exact self-contract and launch replay, without pretending
  that they share one fixed predecessor key.

Unknown or unreviewed input paths remain rejected.

### 1.3 Driver hook and durable degradation

File:

- scripts/plamen_driver.py

Startup order is:

1. Acquire the run lock and initialize file logging.
2. Clear only stale degradation projection.
3. Establish the fresh-audit sentinel.
4. Save the snapshot-bound checkpoint.
5. Run Program Facts Stage-2 emit-only publication.
6. Run the legacy recon pre-pass.

If Program Facts publication fails, the driver records a process-level,
checkpoint-bound runtime debt:

- _program_facts_stage2_runtime_debt.json
- debt ID PROGRAM-FACTS-STAGE2-EMIT-ONLY

The checkpoint binds the exact debt-receipt SHA-256. A later recon projection
cleanup cannot erase that authority. A successful exact Program Facts
publication compare-and-clears the prior debt and receipt. If the debt itself
cannot be persisted, the driver exits degraded; it cannot continue
false-clean.

## 2. Key design corrections made during implementation

### 2.1 Immutable checkpoint capture

The first draft bound later Program Facts work to the live
_v2_checkpoint.json. That file is legitimate mutable runtime state: completed
phases, phase commits, and other driver state change after startup. Binding
the bake directly to that live file would turn normal checkpoint progression
into input-authority drift.

The repair introduced a one-time, zero-input PhaseIO checkpoint capture
containing only:

- audit_snapshot
- run_id

The exact canonical bytes become the immutable predecessor for methodology
capture and bake. Live checkpoint churn and private runtime configuration
churn no longer invalidate the Program Facts publication, while a real run,
snapshot, or visible audit-configuration change still fails closed.

### 2.2 Durable haltless degradation

A recon.degraded text projection alone was insufficient because a later clean
recon commit can remove it. The repair binds a canonical runtime-debt receipt
to Checkpoint.runtime_debts. Haltless continuation is allowed only after this
durable human-visible debt exists. Failure to persist the debt halts degraded.

### 2.3 Dynamic reviewed-input producer authority

The original PhaseIO fixture model incorrectly treated every reviewed
_program_facts_inputs file as if it were produced by one fixed predecessor.
The migrated adversarial fixtures exposed this as an authority mismatch. The
repair preserves exact producer, contract, launch, run, and digest replay for
each reviewed dynamic input while continuing to reject unknown paths.

## 3. Frozen production hashes

The following hashes were replayed after the last production edit:

- scripts/program_facts_driver_integration.py
  - SHA-256:
    0D7826682C72113860DF003B9BC52A91131F00031EA382CBF250809E53F229F5
- scripts/phase_io_contracts.py
  - SHA-256:
    365BC6D3C2446020956DB66C2CFDA169D60C9DE9BF2DCBEE0FB4D97A6F741469
- scripts/plamen_driver.py
  - SHA-256:
    041FBC305FF11B202B92F701FD5FB828E0E6FE732864803086290517AD0D1B64

Any independent-review result applies only while these exact hashes remain
unchanged.

## 4. Test migration and red-to-green evidence

### 4.1 Controlled driver integration

File:

- scripts/test_program_facts_driver_integration_stage2.py

Coverage includes:

- zero-input checkpoint predecessor contract
- exact three-sidecar publication
- canonical and content-addressed checkpoint capture
- legitimate live-checkpoint and private-runtime churn reuse
- visible audit-config drift rejection
- run and snapshot drift rejection
- crash after the first bake output and deterministic resume
- exact no-op for seven non-EVM ecosystem and pipeline combinations
- driver ordering before legacy recon
- no false-clean continuation when debt persistence fails
- debt survival after recon projection deletion and exact compare-and-clear
- Windows, Linux, and macOS platform normalization
- amd64 and arm64 normalization
- fail-closed unsupported OS and architecture handling
- native publication beyond the legacy Windows MAX_PATH boundary
- no active prompt, ranker, chain, verifier, or report consumer

Latest result:

- 24 passed
- command:
  python -m pytest -q
  scripts/test_program_facts_driver_integration_stage2.py

### 4.2 Original adversarial PhaseIO fixtures

Migrated files:

- scripts/test_program_facts_phase_io_contract.py
- scripts/test_program_facts_phase_io_authority_regression.py
- scripts/test_program_facts_bake_stage2.py

Before migration, the new checkpoint-predecessor contract made 66 old fixture
cases red. The original fail-closed test intent was preserved; fixtures now
commit the immutable checkpoint capture before methodology or bake.

Post-migration result:

- 94 passed
- phase_io_contract: 65
- authority_regression: 25
- bake_stage2: 4

### 4.3 Final full Program Facts denominator

Result:

- 538 collected
- 537 passed
- 1 expected xfail
- exit code 0
- elapsed: 1112.26 seconds
- log:
  review_fixtures/program_facts_full_author_20260729.stdout.log

The one expected xfail is:

- scripts/test_program_facts_authority_round5_independent_adversarial.py::
  test_lexically_captured_semantic_compiler_is_not_reflection_mutable
- reason:
  OUT_OF_THREAT_MODEL_TCB_CODE_MUTATION_REQUIRES_OS_PROCESS_INTEGRITY

This fixture mutates governed in-process trusted-code-base implementation
state. It is not an ecosystem, OS, packaging, driver, or provider gap.

## 5. Portability, adjacency, compilation, and replay evidence

### 5.1 Cross-OS and native long-path checks

Result:

- 29 passed

Covered:

- Windows and Linux positive semantic-row portability
- byte-identical Windows and Linux PROVIDER_UNAVAILABLE payloads
- portable and replayable source manifests
- shared rooted-path contracts
- native Windows long-path ArtifactLedger locks, publication, interruption,
  cleanup, resume, reparse rejection, alias rejection, and contention

### 5.2 Successor authority and consumer isolation

Result:

- 109 passed

Covered suites:

- driver successor planning
- transaction-bound successor authority
- mechanical successor consumers
- mechanical successor receipts
- adversarial successor review

The Stage-2-specific static check separately proves that the exact Program
Facts sidecar names and future slicing/obligation identifiers are absent from
active driver successor, prompt, mechanical, type, and validator consumers.

### 5.3 Compilation

Result:

- 14 production files compiled successfully with python -m py_compile
- denominator: all scripts/program_facts*.py production modules plus
  scripts/plamen_driver.py and scripts/phase_io_contracts.py

### 5.4 Pre-B3 Program Facts runtime-closure replay

Result:

- derived runtime closure: 180 files
- checked manifest bytes equal freshly rendered bytes: true
- checked and rendered SHA-256:
  0c5ebd82fa9288421139b74607b01eb32388cac7f0c1feb9d35fc0d2a9b9e7f8

This is historical evidence for the frozen Program Facts integration, not the
final whole-runtime closure. CI subsequently typed additional B1/B2/B3
requirement and evidence assets, so the final denominator and manifest hash
must be replayed after the whole-runtime quiescence release.

### 5.5 Source and public-archive packaging

Result:

- 12 passed

Covered:

- exact runtime-required denominator
- required Program Facts Stage-2 runtime files
- public archive contains the runtime denominator
- Python source packaging contracts
- public archive privacy and required live assets

## 6. Recall and precision safety properties

This Stage-2 cut is intentionally emit-only:

- It can add no candidate.
- It can drop no candidate.
- It can change no verdict.
- It can change no severity.
- It can alter no prompt.
- It can route no work.
- It can assert no negative fact.

Its current recall value is infrastructure-only: it establishes a typed,
source/snapshot/tool/build/methodology-bound publication path that later
reviewed releases can consume. Its current precision risk is constrained by
PROVIDER_UNAVAILABLE truthfulness and zero consumers.

The three sidecars are not proof. The receipt records publication and
authority. The debt records unavailable or partial capability. Only later
separately reviewed consumer releases may turn facts into additive analysis
work.

## 7. Ecosystem and OS boundary

Stage 2 provides an EVM emit-only publication. It does not claim an active EVM
fact provider. It returns exact no-op for every other supported ecosystem.
This is deliberate anti-theater behavior: no placeholder graph is presented
as semantic coverage.

Supported normalized host identities:

- windows/amd64
- windows/arm64
- linux/amd64
- linux/arm64
- macos/amd64
- macos/arm64

Unreviewed OS or architecture identities fail closed for EVM Program Facts.
The rest of the audit can continue only with durable Program Facts runtime
debt.

## 8. Packaging and whole-runtime blocker owned outside this workstream

The combined packaging/install check initially produced:

- 20 passed
- 1 failed

Failing node:

- scripts/test_windows_copy_fallback_install.py::
  test_claude_copy_install_includes_verification_policy_and_uninstalls

Cause:

- plamen.py::_run_symlink_install copied only top-level rules/*.md and
  rules/*.json.
- The exact 180-file runtime closure includes eight required nested
  rules/schemas/program_facts*.json files.
- The Windows copy fallback omitted those nested schema assets, so an
  installed copy was not runtime-closure complete.

Ownership:

- The CI/toolchain author and independent reviewer own the generic
  manifest-derived recursive copy and uninstall repair.
- This Program Facts author did not edit plamen.py.

### 8.1 Interim B3 release and broad replay

The CI owner later released this exact B3 slice:

- plamen.py SHA-256:
  c1b290e8038d82339d3ab86b47aebe63c2475afd4f237dd7ab0534582b8126be
- scripts/toolchain_control_authority.py SHA-256:
  46d8fdbb9fb2e711961caac253be0569c4c1eabe2d76a4dde7d3764b94f0d404
- verification_policy/toolchain_runtime_closure.v1.json SHA-256:
  a2a0cc362692bcc2f7572d41872370b569827b39c87227c908494b6f0368f1d7
- owner focused result: 12 passed

The Program Facts author replayed the original broad packaging denominator:

- scripts/test_python_packaging_contracts.py
- scripts/test_public_packaging_freeze.py
- scripts/test_windows_copy_fallback_install.py

Result:

- 20 passed
- 3 failed
- elapsed: 913.63 seconds
- stdout SHA-256:
  0e58519e69c5a606529dc418f75b3c81643f8a50a738c6796a3cb94f29a71be
- stderr SHA-256:
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Failed nodes:

- test_claude_copy_install_includes_verification_policy_and_uninstalls
- test_claude_install_uses_runtime_denominator_for_generic_nested_rule
- test_doctor_hard_fails_incomplete_claude_verification_policy

The common observation was that the synthetic source or install denominator
reported requirements-ci-resolver.lock and
verification_policy/ci_dependency_provenance.v2.schema.json missing. CI was
legitimately regenerating B1/B2 requirement and evidence assets while this
broad replay was active. The three released B3 hashes still matched exactly
after the run.

Disposition of this replay:

- INCONCLUSIVE SHARED-TREE OR TEST-ORDER EVIDENCE
- not a confirmed installer regression
- not a B3 PASS
- no repair authorized from this result

The final replay must run only after CI releases one whole-runtime quiescent
state covering B1, B2, B3, the requirement locks, evidence assets, runtime
manifest, and package fixtures.

### 8.2 First whole-runtime release was invalidated during PF replay

CI issued an R3 whole-runtime handoff:

- review_fixtures/ci_toolchain_supply_chain_author_handoff_r3_20260729.md
- handoff whole-file SHA-256:
  1a31526030df3fa4a762e056d3651ff6f2c38dc64f59e1e88e69b0ced2aa7c1d
- runtime manifest SHA-256:
  7ca33afa1609b4e7c7f81ec7ff71c059e53ec7309c3c4f02db55958d4bc41501
- 58-file census SHA-256:
  5ee20fc21fa007811533bb32b9f30f4e628108fffb346b32e94b70374f69eaba

Before launch, the PF author independently verified:

- the handoff whole-file hash
- all 29 critical file hashes
- the reconstructed 58-file census

The clean-process broad replay then produced:

- 17 passed
- 6 failed
- elapsed: 110.17 seconds
- stdout SHA-256:
  2dbf75f4f8a5af4d2f87374546020b9739372137db2252ed2d0cfed09c8d4840
- stderr SHA-256:
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Failed nodes:

- test_intended_public_archive_has_complete_runtime_and_no_private_files
- test_claude_provider_policy_is_visible_in_a_fresh_public_archive
- test_clean_archive_compiles_and_imports_runtime_from_itself
- test_claude_copy_install_includes_verification_policy_and_uninstalls
- test_claude_install_uses_runtime_denominator_for_generic_nested_rule
- test_doctor_hard_fails_incomplete_claude_verification_policy

All six failures converged on a missing runtime member:

- scripts/chain_tail_authority.py

The run was not an immutable-boundary replay. The chain-tail workstream changed
that runtime member during or immediately after the replay:

- manifest asset SHA-256:
  09d9e6430046ff30382f447afa28b140233c53c22b419137fdfde371b9451ea5
- live post-run SHA-256:
  1e2ce74d37e25f27fa8e1157a07b7758791a1f2556cc0f50fa69db6edad450fc
- live post-run size: 160527 bytes
- live post-run LastWriteTime: 2026-07-29 23:16:34 local

The checked and derived file sets both contained 222 paths, but their manifest
bytes differed:

- checked manifest SHA-256:
  7ca33afa1609b4e7c7f81ec7ff71c059e53ec7309c3c4f02db55958d4bc41501
- freshly rendered manifest SHA-256:
  82758b57952b36f180a08d713b4441b9693beb701b49b1124c852f62d3321a8d

Disposition:

- SUCCESSFUL FAIL-CLOSED QUIESCENCE TEST
- not a Program Facts defect
- not a packaging PASS
- not a reproducible R3-boundary result
- no production or fixture repair is authorized from these six failures

The next replay requires chain-tail production quiescence followed by a fresh
CI runtime-manifest regeneration and review.

Final Program Facts author handoff conditions:

1. Chain-tail production becomes quiescent.
2. CI regenerates, validates, reviews, and releases the whole-runtime
   manifest after that chain-tail freeze.
3. Re-run the Windows copy fallback and packaging/install suites.
4. Require a green installed-copy result on that exact released state.
5. Recompute the final runtime closure and exact production hashes.
6. Submit the exact frozen state to an independent reviewer.

## 9. Independent-review checklist

The independent reviewer should verify:

1. The three frozen production hashes match section 3.
2. The checkpoint capture is zero-input, immutable, canonical, and
   run/snapshot bound.
3. No live mutable checkpoint file is an input to methodology capture or bake.
4. Exactly three Stage-2 sidecars are published.
5. All publication occurs through PhaseIO and ArtifactLedger.
6. Partial publication resumes without input re-arm or prestate overwrite.
7. Unknown input paths, mismatched producers, contract drift, launch drift,
   run drift, digest drift, and output drift fail closed.
8. Non-EVM paths are exact no-ops with no artifacts.
9. consumer_activation cannot become true.
10. No active prompt, ranker, chain, verifier, or report consumer reads the
    sidecars.
11. PROVIDER_UNAVAILABLE is truthful and cannot imply negative authority.
12. Runtime degradation survives phase-projection cleanup.
13. Failure to persist runtime debt exits degraded.
14. The installed Windows copy contains every nested runtime-closure schema.
15. Uninstall removes every manifest-derived installed asset safely.
16. Cross-OS, long-path, resume, archive, closure, and packaging tests replay
    on the exact reviewed hashes.

## 10. Current author disposition

Implementation: COMPLETE AND FROZEN
Author validation: PF-LOCAL GREEN; WHOLE-RUNTIME REPLAY BLOCKED ON REFREEZE
Independent validation: NOT YET GRANTED
Cutover: NOT AUTHORIZED BY THIS DOCUMENT

This document must remain DRAFT until chain-tail is frozen, the runtime
manifest is regenerated and reviewed, the broad installed-copy replay is
green, and the final denominators and hashes are replayed.
