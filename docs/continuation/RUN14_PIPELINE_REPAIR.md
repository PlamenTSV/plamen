# Run14 pipeline repair checkpoint

This records execution defects, not audit findings or recall measurements.
The failed scratchpad remains unchanged. Native runtime expansion is paused
while the current V3 driver is tested through the explicit POSIX compatibility
route. That route has reduced isolation and does not establish release readiness.

## Initial severity live cutover (2026-09-12, SOURCE IN PROGRESS)

Closure 83508/test 52616: **100 passed in 41.82s**, exit 0. This closes the
new resolver/storage failures from the first batch, including previously masked
negative cases, real durable-stage interruption/recovery and two-vector retained
witness coexistence. Existing successor-plan/transaction/cache and shared writer
parity checks pass. The source historical actor check now uses the always-bound
output_authority_actor. These tests do not exercise that source gate or prove
multi-candidate grouped history. The historical walker now calls stored issuance
replay; its frozen-prefix/current-bundle recursion case requires a new positive
fixture. Typed binder/live handler/final report/DODO remain unproven. The real
same-run fixture has been extended through nonempty planning and awaits execution.

Closure 19094/test 96510: **87 passed, nine failed in 39.27s**, exit 1. This
first ordered-bind batch covers resolver, shared DRIVER materializer, raw
postimage CAS, existing successor-plan/transaction authority, output-control
cache and test infrastructure. Failures are one REPLACE/immutable-input overlap
in the new resolver and eight new CAS cases (retained Darwin stage-abandoned
witnesses rejected; operational/injected exception expectations incorrect).
Negative CAS tests failing in setup are not proof of their intended rejection.
Repairs are pending. Historical multi-candidate successor replay has no positive
test yet and still needs its stored-issuance helper wired instead of live
current-state rederivation. No provider, audit, installation or report proof.

Closure 75967/test 6340: **one passed in 591.45s**, exit 0. This reruns the
actual real-Forge/queue/verifier recovery fixture on the shared validation
context and initial aggregate output pair. Fault after canonical output 1
leaves the immutable initial snapshot absent; recovery publishes exact matching
bytes and commits both outputs under the aggregate producer. Earlier source
halt/resume, same-gate clearances, no duplicate verifier child and read-only
replay assertions also pass. Typed nonempty planning, bind successors, live
handler/report integration, production PoC authority and DODO remain unproven.
Subsequent ordered-bind and historical-replay edits are not covered by this run.

Closure 86894/test 58134: **47 passed in 306.79s**, exit 0. This composes the
actual empty source, capture, typed planning and zero-reconciliation publishers
for SC/L1 and proves recovery/read-only replay plus the newly reviewed prearm
producer and planning-namespace boundaries. Fixture queue ancestry and host-tool
observations remain component-scoped; this is not live handler, MODEL execution,
nonempty adjudication, native qualification or DODO proof. Initial source-pair
full verifier integration still awaits a rerun; three native AG3 worker failures
from batch 67197 remain unwaived.

Typed planning next-boundary review: initial snapshot publication/capture and
snapshot-only pure planning are now implemented; the new typed publisher is
under test. Its prearm checks must authenticate exact current producers and
reject stray context/prompt/launch-intent/tool-policy files before any receipt
is created; complete census and input checks repeat before commit. Optional
skeptic presence still requires a separate authenticated capture (currently
refused, not silently ignored). The live handler is not cut over yet.

Next nonempty successor seam: register ordered bind.NNNN.candidate outputs as
receipt CREATE, decision REPLACE, canonical ledger REPLACE, in that order. Bind
must consume current planning/worker artifacts; the immutable initial snapshot
is never a replacement target. A grouped source_decisions unit needs historical
bundle-member replay during successor-plan issuance: artifact_ledger currently
replays all sibling bytes as live, so binding A prevents later B from the same
unit. Reuse only `_registered_successor_bundle_member_authority`-proven sibling
exemptions, retaining exact B prestate and registered contiguous handoff checks.
Required proof: two candidates in one source unit; A then B succeeds, while
missing/tampered A history or skipped ordinal fails. Dynamic verifier source
replay also needs that exact historical chain; no blanket current-byte bypass.

Recovery baseline: closure 2052/test 60777 exited 0, **one passed in 824.78s**.
The real-Forge fixture proved initial source halt/resume, four exact checkpoint
clearances, no duplicate verifier launch, aggregate output interruption/recovery,
and unchanged committed replay. Aggregate was called directly inside the live
fixture session, not through the severity handler. This does not prove typed
planning/adjudication, production PoC execution authority, report assembly or
DODO E2E. A subsequent invocation-local validation-context reuse edit awaits
its own regression; it must retain all validators and finish-time drift checks.

Closure 30116/test 43127: **32 passed, one failed in 468.12s**. The fixture ran
Forge 1.5.1/solc 0.8.26 offline against three exact dependency-free Solidity
selectors and retained each Success row plus full output/tool/test hashes.
Real queue and verifier MODEL/control completed. Fault after first decision
publication resumed the initial-source transaction to OUTPUT_COMMITTED, but
the coordinator then raised because its former COMPLETED_WITH_DEBT phase had
no explicit same-gate clearance. No aggregate assertion was reached. This is a
production lifecycle defect, not a forged PoC or an environment failure.
The repair now routes dynamic verifier precommit BLOCK_AS_AUTHORITY failures
through the established INCOMPLETE_WITH_DEBT/retry-arm boundary so genuine
revalidation can produce the existing same-gate clearance events. New assertions
check incomplete state, absence from completed phases, and exact recovered gates.
The repair and aggregate execution remain pending rerun.
Review also found the coordinator discarded the incomplete commit and could
advance anyway. It now emits the existing failure diagnosis and exits degraded
after durable INCOMPLETE_WITH_DEBT; the integration fixture expects this exact
stop and then explicitly resumes the same coordinator. No legacy verifier
fallback or silent downstream continuation is allowed.

Diagnostic evidence: closure 72185/quick check chunk d1036b passed 18 resolver
and infrastructure tests in 0.64s. Test 51664 then failed in 128.65s after real
queue publication, on a nonexistent sc_verify_lowinfo fixture phase selector.
The selector now uses the production coordinator map. Closure 55037/test 38945
failed in 144.08s after one local verifier child, before source publication:
all three Low fixture items retained `mandatory structural PoC not attempted
with valid blocker` debt. The explicit execution policy overrides the old
legacy Low exemption; the non-PoC fixture cannot prove current positive
completion. No source transaction was armed, and no recovery success is claimed.
The next fixture must execute a real local contract test, without validator
patches, an invented blocker, or an unexecuted Attempted:YES assertion. Such a
fixture still cannot prove the missing production candidate terminal/control
integration, Core acceptance, provider quality or report assembly.

The dynamic verifier control output denominator now includes each
verify_<ID>.receipt.json, previously raw-written but absent from method_receipt
ownership. The completion gate gains explicit publication mode only for the
post-control source transaction; ordinary replay remains read-only. A completed
unit retries only that gate/source boundary, before any child launch logic.
The exception path cannot replace OUTPUT_COMMITTED control artifacts with debt.
Source contract requires nonempty distinct decision-only outputs and complete
queue/roster/verifier inputs. New source module rejects preexisting raw sidecars
and derives initial decisions from committed MODEL/control execution. These
changes are not yet validated; the aggregate producer and successor chain remain
open. Dynamic source-shard provenance must not be mistaken for execution phase
membership: the runtime may execute several original shards at one coordinator.

Core PoC investigation found no honest existing success fixture: candidate
compat execution emits selected_test_body_execution=UNPROVEN, while dynamic
verifier completion currently accepts prose Attempted:YES plus file/command.
The actual mechanical candidate loop is still on the older direct process runner
and does not join an authenticated terminal into dynamic control. Required seam:
post-MODEL generated-test binding -> authenticated candidate execution/full
streams -> exact selected-test receipt -> verifier control/replay consumers.
Until then, genuine Low/Thorough source tests are component evidence only.

Primary-source research for that follow-up: Foundry v1.5.1's result implementation
represents suites by path/contract and individual test signatures with distinct
Success/Failure/Skipped states; its ensure_ok checks failures, not an expected
test count. Therefore an exit code alone is not exact selected-test evidence
(implementation inference). Pin parser behavior to the admitted tool version and
verify the actual suite/signature/result, not arbitrary model prose or a generic
process-start receipt. See the
[Foundry v1.5.1 result implementation](https://raw.githubusercontent.com/foundry-rs/foundry/v1.5.1/crates/forge/src/result.rs).

## Severity input and reconciliation integration (2026-09-12, INCOMPLETE)

Final governed batch: closure 91737/test 4459 passed **125 checks in 187.69s**.
It ran test_test_infrastructure_contracts.py, test_severity_planning_inputs.py,
test_severity_bind_postimages.py, test_severity_zero_reconciliation.py,
test_audit_snapshot_verification_policy_binding_p0.py,
test_method_card_runtime_authority_r2.py,
test_program_facts_source_r7_transitive_builder_provenance_adversarial.py,
test_program_facts_source_r8_transitive_provenance.py, and
test_posix_v2_compat_severity_execution.py with managed Python 3.12, -B and
PYTHONDONTWRITEBYTECODE=1. Cross-platform ambiguous relative paths and late
receipt appearance after genuine worker replay are now rejected. The complete
postimage read-set is reread and receipt absence/presence checked before return;
this remains bounded validation, not an atomic namespace lease or typed commit.

Final tested SHA256:
- severity_bind_postimages.py: 3c4fea9a05e8d7045cb1cb5a2592645f24dd08144b8ef71c87849802853257a4
- test_severity_bind_postimages.py: d2d1753c0c1d13c74f0ec5e2a5062b475ece93c081ef4fcab2f71f65cfe1f368
- severity_planning_inputs.py: 9d3b61e4fab0fa030771626d14272438595c0137b295ba3473c9a9ffb0417057
- test_severity_planning_inputs.py: 1d5b970f84c250816c2fce90553f88fc2bede413e9eb8b54402c5c9ebc60767f
- audit_snapshot.py: 509f0d3864f205d3bd6f5c02657561ed83c11ea3ab0b05403a430c87b40fe4ee
- phase_io_contracts.py: 1369c7353fa217ec5189b9a6b2c2247d4a0d5be46007fd722bcd20eb83c91804

No source module was edited during closure/tests. Subsequent checkpoint-only
documentation changes require a fresh closure render before later governed
execution. No install or provider audit was run; native qualification and
multi-candidate typed successor integration remain open.

Next live insertion design: publish per-verifier-unit initial decisions after
MODEL/control receipt commits; replace the three verifier completion checks
that currently require an aggregate with typed per-shard replay. A single
source_aggregate at severity entry then consumes all assigned typed sidecars.
Core proof needs a real PoC-backed nonempty fixture; the existing same-run
Low/Thorough success is genuine but cannot establish Core acceptance. Preserve
mandatory PoC gates and the native broker gate rather than bypassing them.

Closure 93338/test 50625 passed 15 pure-postimage checks in 38.59s after the
fixture migrated to a genuine local compatibility child. The production helper
uses bounded no-follow reads, strict JSON/candidate validation, exact captured
decision denominator, worker/verifier replay and byte rechecks. It returns
transaction preimages separately from transitive authority read-set bytes;
mutable artifact-state is used to locate committed worker evidence, not treated
as an immutable semantic input. Tests prove no writes and exact parity of all
three calculated output files, receipt-first pending equivalence, exact replay,
and invalid receipt/caller/candidate rejection. No typed successor is published.
Further relative-path and late-receipt drift tests precede the wider batch.

Initial nonempty source ownership review: bind_shadow_severity_for_shard writes
decision sidecars and aggregate without PhaseIO in Core and Thorough. Genuine
upstream owners are verifier method_model/method_receipt work units, neither of
which declares those severity outputs. Only source_empty currently owns the
aggregate through a registered transaction. Required live path must produce
initial decisions and full aggregate deterministically from authenticated
upstream receipts before capturing planning's source. Never infer ownership from
a filename, existing self-consistent JSON or raw writer success.

Closure 75611/test 12575 ended nine failed, 62 passed in 94.93s. Command:
`env PYTHONDONTWRITEBYTECODE=1 .venv-dev/bin/python -B -m pytest -q --tb=short`
with test_test_infrastructure_contracts.py, test_severity_planning_inputs.py,
test_severity_bind_postimages.py, test_severity_zero_reconciliation.py,
test_audit_snapshot_verification_policy_binding_p0.py, and
test_posix_v2_compat_severity_execution.py. The complete input capture suite
passes after stable root identity correction; SC/L1 capture/replay, all eight
fault points, strict run IDs, and mid-publication source/root drift reject as
intended. Semantic config enumeration, zero reconciliation and compatibility
regressions pass. All nine pure-postimage tests fail before derivation at the
old native-only worker fixture's unavailable INITIAL_AUTHORITY. Its migration
to the already-tested harmless compatibility child is not a native waiver.

Tested input capture SHA256: 9d3b61e4fab0fa030771626d14272438595c0137b295ba3473c9a9ffb0417057.
Tested capture test SHA256: 1d5b970f84c250816c2fce90553f88fc2bede413e9eb8b54402c5c9ebc60767f.
Tested audit snapshot SHA256: 509f0d3864f205d3bd6f5c02657561ed83c11ea3ab0b05403a430c87b40fe4ee.
Tested PhaseIO contracts SHA256: 1369c7353fa217ec5189b9a6b2c2247d4a0d5be46007fd722bcd20eb83c91804.
Capture is not live planning integration or immutable source-ledger ancestry.

Closure 10047/test 84412 passed 81 checks in 136.18s across infrastructure,
severity_zero_reconciliation, audit_snapshot_verification_policy_binding_p0,
method_card_runtime_authority_r2, Program Facts R7/R8 provenance, and
posix_v2_compat_severity_execution. This proves the zero reconciliation
component's exact SC/L1 ownership, faults and replay, selected L1 methodology
fingerprinting, and exercised SC consumer/compatibility regressions. It does not
prove live planning, report assembly, L1 E2E or provider execution.

Preserved diagnostic sequence: closure 9708/test 38379 ended 21 failed, 15
passed, 32 errors in 91.56s (invalid fixture tool policy, missing explicit EVM
coverage limitation, and outdated forged-helper signatures). Closure 30625/test
80834 ended one failed, six passed in 18.17s; closure 25624/test 62972 ended one
failed, 67 passed in 105.22s. The last two failures expected a later rejection
message although the earlier existing validator correctly rejected stale worker
artifacts. Fixture/signature/expected-message fixes did not bypass validators.

The next planning-input capture batch, closure 37318/test 61742, failed its first
positive SC test in 8.23s. Directory link count was captured before the producer's
own child-directory creation, causing false root drift. Stable object identity
and strict run-ID/mid-publication drift coverage are being corrected and tested.

Static integration review confirms bind_shadow_adjudication_for_candidate
rewrites both the candidate decision and aggregate ledger, including on replay.
The registered bind contract is not armed by that writer. Planning cannot retain
the live aggregate as an immutable input across those raw rewrites. Required
repair: exact retained source snapshot plus registered contiguous typed bind
successors, precomputed postimages and sealed receipt-first recovery. Historical
commit validation alone does not establish a chain to the live owner. New pure
postimage extraction is a prerequisite, not this integration's completion.

## Severity compatibility routing repair (2026-09-12, SOURCE IN PROGRESS)

Latest source validation: closure 9937/test 62433 passed all 17 checks in 39.24s,
including the actual SC/Core driver handler through worker launch, adjudication
binding and COMPLETED reconciliation; replay from a fresh interpreter preserves
the historical worker/ledger bytes with no child relaunch. Genuine failure after
MODEL commit but before first worker-run publication recovers successfully.
The deleted-after-publication case now expects Darwin quarantine rejection;
its platform-specific marker was then added. Closure 81238/test 49937 reran the
compatibility suite plus empty-source, renderer and older live/native suites:
seven failed, 74 passed in 55.70s. The exact seven failures remain the prior
NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE failures, with no new regression in
this exercised batch. No native gate is waived. Compatibility planning ancestry
remains raw; report integration, actual provider E2E, other OS/backend acceptance,
and a new installed generation remain unproven.

Current source SHA256:
- severity_compat_runtime.py: 3d388b6910670478552d462de21fe0e2c4d4a64d5b20650bd2af729d8c938d3a
- severity_compat_authority.py: 55db7a7916c65e825e009cca0be2dca8bd38f813eaedc171da3156e9147b2035
- severity_adjudication_work.py: f2f6440fce41c4bcfe775895450e60c374dc45ff0c8433ce7c491c3897f0cff9
- test_posix_v2_compat_severity_execution.py: 64a50a7ebc9fb5e9646815f7e38b229e77aee8d18f1ea31a6d985fbcf4779a6e

Closure 74588 passed; focused test 65137 ended one failed, four passed in 2.40s.
The real child launched and completed. Semantic admission rejected an adapter
bug: its output denominator used filenames instead of the runtime's exact
`scratchpad:<filename>` identities. Correcting that context and refreshing
closure 28556 yielded test 2707: one failed, eight passed in 7.53s. The positive
worker and same-session committed replay now pass with unchanged output/ledger
bytes and no second child. Malformed staged proposals, foreign sessions, and
false terminal states reject. The remaining observed failure at this checkpoint
is the tamper fixture trying to write a sealed read-only receipt before its
replay assertion; explicit adversarial chmod is required in the fixture, not a
production permission relaxation. Additional recovery/driver tests are pending.

Closure 71690 and expanded test 96554 completed: one failed, 13 passed in
17.49s. This adds successful after-execution and after-commit recovery without
relaunch, sealed-receipt tamper rejection, simultaneous session collision
rejection, and foreign post-execution mutation rejection before MODEL commit.
The remaining test incorrectly deletes an already published write-once receipt
and expects reconstruction. Darwin's retained quarantine rejects the orphaned
destination (`DARWIN_ORPHANED_QUARANTINE_PRESERVED`), as required; do not relax
the durable writer. Split this into deletion rejection and an actual fault
after MODEL commit but before the first worker-run publication. A fresh-process
session replay and full severity handler case remain the next execution scope.

The seven native execution failures from batch 90538 expose a live routing gap:
the severity handler builds a transactional executor for Claude only, while Codex
falls through execute_adjudication_worker into native-only run_observed_worker.
The installed reduced-isolation compatibility session explicitly denies native
broker/WER authority. Fabricating native arm/completion/publish receipts would
therefore be an invalid repair.

New source separates compatibility execution and authority into two small modules
rather than expanding the near-cap driver. The driver explicitly selects the
compatibility transport and registers the real issued session. Planned native
staging instructions remain unchanged; compatibility prompts refer to logical
outputs that the existing runtime maps into its private staging area. The adapter
arms the exact worker.<shard> MODEL contract, supplies the existing proposal
parser as the staged gate, and checks that only its exact outputs, diagnostics
and successful receipt changed before MODEL incorporation. A compact digest of
the pre-child file/link census is retained in the staged context for replay; no
whole receipt or worker-transaction directory is blanket-allowlisted.

The additive worker-run variant binds real compatibility evidence and standard
MODEL incorporation under posix_v2_compat_severity. Native v2 remains strict and
unchanged. Revalidation must require the exact registered live session, historical
stable session fields, plan/intent/output roster, transaction schemas and staged
validator implementation/context/input bindings. The first review caught a label
mismatch and overly broad noncommitted-state acceptance; both are corrected.
Committed replay must not write a new current-session identity into historical
authority. Implementation/test freeze and execution evidence are pending.

Tests use a real local compatibility session and a deterministic route-aware
child, not remote model calls or WER fakes. Raw planning preparation remains an
explicitly limited fixture/production prerequisite until the typed producer is
implemented; a compatibility worker pass will not prove that ancestry or DODO
E2E. No new installation or provider audit occurred in this source work.

## Severity source and planning diagnostics (2026-09-11, SOURCE ONLY)

Latest closure 73523 completed and batch 90538 terminated **seven failed, 61
passed in 29.18s** across empty source, live severity phase, adjudication work,
and test-infrastructure modules. Empty-source producer/replay/fault/collision
checks, valid nonempty no-write behavior, SC/L1 canonical-empty driver paths,
and five new renderer/reconciliation tests pass. The remaining seven failures
are native execution refusals in existing real-child tests, four in the live
handler and three in the lower-level work module. These preserve the actual
`NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE`/`NATIVE_BRIDGE_UNAVAILABLE` boundary;
no environment gate or provider authority validator was patched away.

Production refactor SHA256 for severity_adjudication_work.py:
`504933ab55c00e0348c7eb513e2481a9d73613dc123cb7a7c2327c15bd134149`.
The public read-only `derive_adjudication_work` returns manifest, plan and exact
output bytes; legacy publishing/recovery wrappers retain their behavior.
`build_adjudication_work_reconciliation` is read-only, and the validator no
longer rewrites or repairs reconciliation. Regression cases cover zero, one,
five, and oversized denominator behavior, byte-preserving public publication,
idempotent read-only derivation and tamper-preserving validation. These are
component proofs, not typed planning/BB/report completion or worker E2E.

Next authority detail: skeptic input capture must distinguish true absence from
invalid present `skeptic_challenges.json`, require the fixed two source names
and skeptic_manifest.json, and replay skeptic/challenge_reconcile. The parser's
legacy empty-object fallback is not enough for typed planning. The exact severity
methodology and snapshot/config must also be replay-bound rather than accepting
caller digest strings. No reusable general severity capture was identified by
the scoped review; queue/Program Facts receipts cannot be repurposed silently.

Closure 21164 completed; batch 97422 terminated **one failed, seven passed in
20.91s**. Input tampering was rejected at the stricter producer prebind check,
not the later check named in the test. The assertion was corrected without
changing the rejection boundary. Closure 94270 completed; full focused batch
44818 terminated **ten failed, 38 passed in 31.28s**. Three failures were missing
input exceptions exposed as RootedPathIOError, two used the wrong fixture run ID,
one had malformed missing-source fixture roots, and four older real-child positives
lacked the current auxiliary-root startup binding. The source helper now normalizes
read errors into ArtifactLedgerError; fixtures use exact run IDs, a complete typed
nonempty queue, and the real durable startup permit. Rerun is pending.

Static review confirms source_empty is only the first missing producer. Planning
has a registered contract but the live prepare function writes manifest, plan and
shard inputs without activating it. Reconciliation changes after worker progress
and cannot be an immutable planning output. Extracting deterministic derivation
and a read-only reconciliation builder is the next step toward the complete typed
planning/empty-reconciliation chain, not a substitute for that chain. Preserve
nonempty worker semantics and exact methodology/snapshot/skeptic input bindings.

The source_empty helper binds expected output bytes before publication, replays
committed bytes without repair, supports SC/L1 and rejects observed stale sidecars.
Repeated sidecar scans do not make namespace absence atomic against concurrent
creation during ledger commit; that stronger concurrency guarantee is unproven
and remains explicit debt. Tests for after-arm/after-output collision injection
must not be described as arbitrary-concurrency proof. No installation, remote
provider run, report-assembly success or DODO acceptance is claimed here.

## Assembly severity prerequisite failure (2026-09-11, SOURCE ONLY)

Corrected the new fixture to run all three body writers before confirmation/
merge and to check assembly's ACTIVE authority before its legitimate assurance
successor. Test SHA256 is
`7bb1f7b96886f009f4a3313bbf2e92807a9e8f85d60aa37dcf41793862e98cc4`.
Closure 86181 exited zero. Test 16287 was repeatedly confirmed live on the same
handle/PID and allowed to finish without source changes or a timeout restart.
It terminated **one failed, four passed in 934.84s** at the PRE_ASSEMBLE
severity projection, after all body writer/confirmation/merge assertions:

`canonical severity artifact ownership mismatch: expected exactly severity_decision_ledger.shadow.json, found []`

This is not an assembly pass. The exact error comes from the physical canonical
filename-presence check in `severity_runtime._canonical_file`, before PhaseIO
input replay: this fixture omitted the severity phase entirely. Separately,
source review confirms that the existing zero-row severity phase writes the
ledger without a PhaseIO owner, while the subsequent report projection requires
it as an owned immutable input. Therefore adding the raw writer alone is not a
complete repair. A typed `severity_adjudication_shadow/source_empty` producer is
now being implemented, and the fixture will execute the actual severity phase,
trust/BB reconciliation and checkpoint commit before report prework. A source
contract and driver hook are edited but not yet validated. The production
validator remains unchanged. Static review also found the legacy empty-tier
writer has no PhaseIO output transaction, but this run stopped before assembly
could demonstrate that consumer failure. Do not conflate the two seams.

To preserve the running test's source identity, proposed empty-tier helper/tests
were drafted in a separate temporary directory outside the repository. They
were not imported, invoked, installed, or applied. Review remains required for
actual evidence-row shapes, exact repaired producer owners, global-empty input
selection and rooted/no-follow output writes. The genuine per-tier proof must
bind owned report/evidence rosters: per-tier manifests are legitimately absent
when another tier is nonempty, whereas globally empty routing emits canonical
`report_empty.json` manifests. Current installed generation is unchanged.

Parallel read-only SC dedup review found live packet creation is unowned and
MODEL contract resolution can omit the actual `dedup_blocks.md` prompt input.
SC gate repair/apply/supplemental steps may change decisions before the generic
tail seals MODEL output; `sc_semantic_dedup/canonical_apply` is declared as a
consumer but lacks its producer contract/helper. The planned repair preserves
raw decisions, derives typed supplemental dispositions separately, and folds
primary plus supplemental changes into the five-output canonical transaction
before chain. Existing L1 plumbing can be extracted, but its supplemental
policy is stricter than SC in overlapping ranges, aggregate veto, severity checks
and decision-only exclusions. Explicit per-pipeline parity tests are required;
silently dropping supplemental behavior or rewriting MODEL bytes is not a fix.

Read-only performance review identified duplicated semantic/producer replay
inside each R10 report-input resolution. An existing invocation-local
`_ArtifactValidationContext` may safely deduplicate only context-backed replay
within one read-only epoch, with `finish()` revalidating observed paths/bytes
and ledger identity. It must not survive arm/commit barriers or cache direct
verifier/semantic reads not covered by that context. No caching change was made.

## Assembly integration fixture review (2026-09-11, SOURCE ONLY)

The previous goal turn made progress: interruption test 90744 passed, the tested
batch was installed, and public DODO planning passed. The new assembly fixture
and serial/slow classification are not in that installed generation.

Closure 16729 exited zero. Test 72457 was deliberately interrupted after source
review found two fixture mistakes: it interleaved each body writer with its
confirmation/merge instead of running all three bodies first, and expected the
assembly output to remain ACTIVE after the legitimate assurance successor.
The same process was confirmed live before SIGINT; this was not an observation
timeout or a production failure. It terminated exit 1 with KeyboardInterrupt
and pytest tmp_path teardown KeyError. No assembly pass is claimed from this
aborted run. Source edits resumed only after its PID and session were terminal.
The fixture is being corrected to mirror actual phase order and to check
assembly's ACTIVE binding before assurance, then its retained committed record
and the assurance successor's live binding afterwards. Validators are unchanged.

## Tested report batch installed (2026-09-11)

After recording the interruption result, closure 77957 exited zero and the
managed CPython 3.12 compatibility installer 14821 exited zero. Generation
`a3c91914456bdb33701b41d30b1a797a825cc218beb5b30b0a5bd9bb0e6bdc24`
contains 7,407 entries. Installed driver, SC no-op helper, and Core interruption
test hashes match the tested source. This remains explicitly reduced-isolation.

Public help 42246 exited zero. Doctor 3209 verified the exact package census
and Python dependency cache, then exited 1 with the existing scip-go 0.2.4 vs
0.2.7 mismatch and incomplete Claude runtime and verification-policy projections.
Authentication remains unprobed, Slither remains nonauthoritative, and ordinary
POSIX install/setup is still refused. These are real release debts, not hidden
or waived failures. No ambient Python or Keychain diagnostic was invoked.

Public DODO plan 64263 exited zero: EVM, Thorough/Codex, 75 phases,
launchable=true, no planning issues, fallback disabled, provider_invocations=0.
The target is clean at `d4834a468f7dad56b007b4450397289d4f767757`.
This is planning/installation evidence, not provider access or audit success.
No new/resumed DODO audit occurred. Requirements reconciliation still reports
195 open rows, zero proven, completion_claim=false. The next assembly test is
source-only after this installation; post-install notes do not change the
installed package identity or require another install by themselves.

## Core report publication interruption (2026-09-11, SOURCE ONLY)

The preceding status turn was a verified wait on live test handle 90744, not
an implementation turn. That same handle now completed exit zero: **one passed
in 624.34s**, after closure 1197. No test restart or source edit occurred while
it was live. The full-prerequisite Core fixture injects an exception immediately
after canonical `report_index.md` publication, observes the armed partial state,
recovers via the actual canonical transaction, and validates committed replay.
Report-child relaunch is forbidden after the initial harmless local MODEL
worker. Its execution authority is unchanged; all four mapped IDs remain in
coverage; every T9 public output remains byte-identical and safe to consume.
The fixture's executable-discovery patch now substitutes only codex.

Test SHA256: `ac07e0c82e5d2822aa8599b11321e36dba7f27bc684eed4dbf595a4e9d3f44ab`.
Production sources are unchanged from the preceding 52-check batch. This proves
in-process injected-interruption recovery with fixture-authored upstream input,
not cold-process resume, nonempty verification, final report assembly, real
provider execution or DODO E2E. Installation of this tested batch is next.

Read-only readiness reconciliation also corrected stale next-action guidance:
Decision 27 already selects Yarn through the schema-v2 unique manifest-consistent
assessment. Dependency materialization and selected-test/PoC authority remain
open; a user lockfile choice is not needed. The earlier provider refusal/access
disposition was explicitly requested from the user and remains unanswered.
Provider calls are paused, run17 stays terminal, and local implementation can
continue. The existing scip-go and Claude doctor failures are not initial
EVM/Codex launch blockers, but remain real release debts.

## Authenticated SC no-op and Core report entry (2026-09-11, SOURCE ONLY)

This continuation makes production and integration progress. The prior status
turn itself was no progress; work resumed from the observed missing dedup input.

Implemented `sc_semantic_dedup/noop_passthrough` in the contract resolver and
new `sc_semantic_dedup_noop.py`; the driver no-signal and oversized-block early
exits now call it. Its exact input is owned `findings_inventory.md`; its exact
outputs are conservative `dedup_decisions.md` and a byte-identical
`findings_inventory_deduped.md`. Canonical inventory is not mutated, no aliases
are created, and unavailable semantic review is explicit. An applied-merge
receipt is neither required nor claimed for this preserve-all operation.

The initial helper chose the wrong generic historical-successor API. Real
execution rejected it because new outputs have no historical producer bundle
intersection. Root replaced it with ordinary arm/commit, binding the expected
output records and invocation reason digest in preexecution authority. Partial
recovery requires exact ABSENT prestates and accepts only absent/exact-derived
live bytes; committed replay validates without rewriting. Inventory-read bytes
must match the actual bound input hash/size, closing the read-to-arm race.
Same-run/configuration, producer, collision and symlink rejection remain strict.

Validation chronology (all sessions terminal):

- Closure 7224; test 79604: 13 failed, 6 passed in 2.21s. Test setup used an
  unregistered resolver work-unit name and a nonexistent main-source delimiter.
  Root changed the seed to an explicit typed fixture inventory contract and
  corrected the bounded source slice; no production resolver fallback was added.
- Closure 6503; test 55568: 10 failed, 9 passed in 4.18s, exposing the wrong
  historical-successor API. No artifact-ledger validator was relaxed.
- Closure 83310; test 10489: 18 passed, one failed in 5.80s solely because the
  expected cross-run error text did not match the earlier configuration guard.
- Closure 75902; test 49227: 23 passed, one failed in 262.33s. Actual report
  prework now passed. The remaining assertion incorrectly forbade the empty
  roster that production queue validation legitimately materializes. The test
  now asserts empty ordered IDs/work units; it does not fabricate a roster.
- Closure 83886; test 7635: **26 passed in 782.59s**. This includes 24 focused
  no-op/infrastructure checks and two genuine Core integration cases. One case
  reaches prework; the other launches a harmless local report worker using the
  full resolved report contract and actual R10 readiness, then passes canonical
  publication and committed replay. Coverage retains INV-1, INV-2, INV-3 and H-1
  as HUMAN_REVIEW_DELIVERED with `report_dropout_retention.json` present.
- Affected-consumer test 22945: **26 passed in 14.15s**, the existing applied
  semantic-dedup authority module and legacy SC/L1 no-op content-gate case.

No production validator doubles were introduced. Upstream inventory/chain
inputs are fixture-authored; the report child emits deterministic benign prose
and uses fake local auth. The DRIVER helper's backend-label cases do not prove
real Claude execution. These results do not prove actual model reasoning,
nonempty verification, main-loop report assembly, or live DODO E2E.

Next: inject canonical interruption after the first report output publication
in this genuine full-prerequisite child fixture; resume without model relaunch,
assert exact T9 output conservation, and retain the committed-replay check.
Narrow its `shutil.which` stub to codex when extending it. Normal SC MODEL packet
and canonical-apply authority remain separate open work, as do all nonempty,
provider, OS and final release requirements. Driver size is 4,190,382 bytes
(3,922 below the unchanged cap). No installation or provider call occurred.

## Core policy-empty report-entry experiment (2026-09-11, SOURCE ONLY)

Added `test_core_empty_report_entry_integration.py` to compose the existing
Core/Low queue fixture with production empty aggregate, R10, and report prework.
It retains the exact three policy-excluded INV rows and snapshots T9 outputs.
No production validators are substituted. Upstream queue builders still seed
fixture inputs; this is not an execution proof of every upstream model phase.

- Closure 64466 exited zero. Test 11197 failed at R10 after 145.56s: missing
  authenticated external-dependency research producer.
- Added the production `_ensure_recon_dependency_parity` before queue
  publication. It enumerates the real trivial source, publishes zero dependency
  obligations and an owned nonempty reconciliation ledger; no external worker
  or handwritten stub is used.
- Closure 72477 exited zero. Test 18718 failed after 167.98s at report prework:
  `scratchpad:dedup_decisions.md: semantic input missing at binding`. Earlier
  assertions now pass through actual R10 CLEAN_ZERO. This is partial evidence,
  not a green report-entry test. Investigating the proper SC dedup producer.

Report child, canonical completion/recovery, nonempty verification, provider
execution, and clean DODO E2E remain unproven. No installation was performed.

Follow-up source review identified a production gap behind the missing fixture
input: SC's no-signal and oversized-block early exits use an unowned raw
passthrough renderer. L1 has a typed no-op producer; SC does not. A bounded
`sc_semantic_dedup/noop_passthrough` DRIVER transaction is being implemented
for the exact pair `dedup_decisions.md` and `findings_inventory_deduped.md`.
Its sole semantic input is the owned canonical inventory, which it must leave
untouched and copy byte-for-byte. Decisions explicitly make no merge or
absence-of-duplicates claim; the legacy block packet has no typed authority.
This is not MODEL execution and creates no alias/application receipt.

Independent consumer review confirms SC queue consumption continues to use
the unchanged canonical inventory; applied dedup receipts are required for
actual inventory mutation, not this no-merge pair. Normal SC MODEL packet and
canonical-apply authority remain a separate open gap. The new source changes
are not yet tested or installed.

## Canonical lineage and armed Summary recovery (2026-09-11, SOURCE ONLY)

The previous goal turn made concrete progress (retained originals and 64
passing component checks). This turn connects that evidence to canonical
input/staging selection and interrupted Summary recovery.

- `canonical_report_model_lineage.py` selects only the expected current
  MODEL/Summary/mechanical head. Fresh canonical execution checks active live
  head bindings and exact original/derived bytes. Existing canonical units
  select from their full SC2/L1MODEL3 prestates, permitting partial publication
  without adopting arbitrary live bytes. Retained non-owning attempts are not
  confused with selected owners. Mechanical selection makes no MODEL claim;
  ordinary mechanical/canonical validation is still required.
- Driver canonical contract resolution includes the stable report lineage read
  set, and the post-arm path rechecks the head join. Existing input validation
  and staging copy every declared original/worker/receipt file. Existing
  committed replay, partial-publication checks, and target validation remain.
- `report_summary_recovery.py` authenticates the exact armed ordinary Summary
  transaction and retained MODEL originals. Before-write recovery permits an
  absent receipt; after-write recovery requires the exact canonical receipt
  reproduced from the original bytes. Full passthrough outputs must remain
  unchanged. No generic successor-plan/progress journal is invented.
- Driver armed Summary recovery uses that derivation throughout receipt and
  postimage checks. Summary/canonical attempt recovery now occurs before
  selecting contracts or receipt names, including config without a saved counter.
- Summary receipt live bindings additionally require ACTIVE_AUTHORITY.

Validation:

- Closure 40845 exited zero; test 59530: **79 passed in 242.91s**. This includes
  15 new cases plus the previous 64-check group. New positive cases use a real
  harmless report child, actual Summary arm/publication, actual canonical input
  arm and staging, and historical replay from the resulting stage. Negative
  cases preserve rejection of mixed/wrong-attempt owners, damaged bindings,
  arbitrary live/prestate bytes, altered receipts and passthroughs.
- Consumer test 5721: eight passed, one failed in 83.25s. The L1 parity fixture
  incorrectly called its newly migrated SC-only R10 setup. `_prepare_model_attempt`
  now selects that setup only for SC and retains `_seed_model_inputs` for L1.
  Production `_r10_report_consumer_ready_issues` was not relaxed.
- Closure 10261 exited zero; corrected consumer test 28204: **10 passed in
  25.38s**. The two existing staged-verifier enumeration cases isolate R10 with
  their existing double; the legacy Claude L1 parity case simulates its write
  boundary. These are scoped regressions, not full R10 or real Claude execution.
- Driver size is 4,189,982 bytes (4,322 below the unchanged 4 MiB cap).

Open: full report driver-entry and crash/retry acceptance through authentic
T0-T9/R10/prework; nonempty verifier/mandatory-PoC integration; real backend and
cross-platform validation; clean DODO E2E and all other release requirements.
The new tests use a minimal report MODEL input contract and do not prove that
complete prerequisite chain. No provider call, installation, or DODO launch
occurred. Source remains uninstalled. A read-only next-step investigation is
checking the already-supported Core/Low policy-empty same-run publication as
an authentic zero-active R10/report case, without replacing the nonempty goal.

That read-only investigation identified a concrete supported continuation from
the Core fixture: `_write_empty_verify_aggregate_projection` with the exact
empty-queue reason and `sc_verify_aggregate` phase, followed by
`_close_empty_verify_aggregate_r10`, `_run_report_index_prework_transaction`, and
`_r10_report_consumer_ready_issues`. The first helper supplies owned verify_core.md;
R10 and prework supply the remaining projections. This sequence has NOT yet
been executed here. Do not construct an empty dynamic verifier roster or relax
gates. If it passes, use a genuine report child with zero-row semantics and
retained Core exclusions to test the full canonical entry.

## Retained MODEL bytes and committed Summary lineage (2026-09-11, SOURCE ONLY)

The prior user-facing status turn was no progress; this goal continuation
changes production report retention/replay and yields new real-process evidence.

- `report_model_preimages.py` captures only strictly current, committed MODEL
  outputs using bounded, no-follow, single-link reads and durable write-once
  publication. The private store is keyed by execution authority digest. Its
  side-effect-free reader verifies the stored expected contract/launch, matching
  commit/execution authority, all three worker records, and every original
  artifact hash/size. Retry IDs follow the actual report resolver. Missing or
  damaged originals cannot be reconstructed from later successor bytes.
- Driver capture runs after ordinary POSIX report incorporation and at the
  successful `_record_report_index_model_preimage` tail. Generic typed artifact
  recovery does not capture potentially transformed bytes. Mechanical/no-model
  paths do not invoke this capture.
- `report_model_lineage.py` joins the authenticated originals to an optional
  committed Summary using exact stored contract/launch/commit/prestates, full
  pure re-derivation of the canonical Summary receipt, and unchanged coverage
  (plus L1 records where applicable). It returns immutable head bytes, stable
  evidence paths, and an exact downstream-prestate join. POSIX committed
  Summary replay now invokes this reader; existing live-byte checks remain.
- Summary's real protocol uses ordinary deterministic arm/commit, not generic
  successor_plan/progress. A review suggestion to require a nonexistent progress
  journal was rejected against the actual producer and successful transaction
  fixture. Do not reopen that stopped generic historical DRIVER API task.
- The genuine POSIX child fixture can now emit supplied harmless report text
  before MODEL commit. New tests execute real MODEL transport and real Summary
  DRIVER arm/commit, then replay the original derivation after live bytes change.
  They also cover missing/tampered evidence, strict late-capture rejection,
  expected contract/launch drift, retry identities, receipt canonicality, and
  full-head predecessor mismatches. New child-based modules are serial/slow.

Validation chronology:

- Closure 41456 exited zero. Test 75300: 23 passed, one failed in 103.96s.
  The retry negative constructed an invalid dataclass (output owner keys no
  longer matched its changed key), so the constructor failed before the
  intended assertion. No production validator was relaxed.
- The fixture now resolves a genuine alternate Summary attempt. Closure 70889
  exited zero. Test 48513: **64 passed in 186.42s** across report preimages,
  report lineage, worker historical replay, Summary receipt codec, test-lane
  contracts, and existing POSIX report execution lineage.
- Driver size: 4,187,906 bytes, 6,398 below the unchanged 4 MiB cap.

This is component transaction evidence from a minimal MODEL contract, not a
full R10 report input chain, remote model semantics, installation, or DODO E2E.
No installer or provider invocation occurred. Canonical input/staging/read-time
integration and Summary interrupted-postimage recovery still need the new
original-byte lineage. Existing canonical live/partial-publication checks must
remain. The Summary R10 fixture ancestry and Thorough mandatory-PoC fixture debt
remain open. The installed generation is unchanged.

## Historical replay prerequisites (2026-09-11, SOURCE ONLY)

The preceding goal turn produced additional diagnostic evidence rather than
a clean E2E. Test 4580 failed two fixture setups in 89.29 seconds: missing R10
producer ancestry in the migrated Summary test, and inherited Thorough mode
where the new Low test expected Core. Run 32519 passed 14 report/infrastructure
tests and failed the Core/Low nonempty-queue expectation in 154.02 seconds.
The actual T2 receipt proves Core intentionally excludes those three Low rows;
T9 retains them with the normalized AUTHORIZED_EXCLUDED code. The new test
now checks that policy separately from Thorough's active verifier path.
Run 68104 failed both cases in 256.75 seconds. Core's assertion expected the
earlier descriptive reason instead of the normalized public code. Thorough
launched the harmless real child, but all three INV items retained validation
debt: mandatory structural PoC not attempted with a valid blocker. This is
not an audit finding, dropped candidate, or successful verification result.
The Core assertion is fixed; the Thorough fixture remains red and its
production PoC requirement was not bypassed.

Current production changes:

- `worker_transaction.py` separates immutable historical execution-record
  replay from its existing strict live-output comparison. The new frozen
  result authenticates the original projected hashes/sizes and exactly three
  receipt paths; it does NOT retain or return original report file bytes.
  Scalar-only identifiers and canonical paths prevent mutable/aliased return
  values. Native integer and compatibility digest generations are both
  supported, retaining cross-record equality checks.
- `report_index_summary_authority.py` contains the existing five Summary
  receipt functions extracted mechanically from the driver. Driver aliases
  preserve callsites; driver size is 4,186,827 bytes, below the unchanged cap.
- New real-child preimage replay and pure receipt-codec tests cover the new
  seams. Worker-child tests are in the serial/slow lane. The Summary fixture
  migration is also classified serial/slow; its R10 ancestry remains open.

Validation chronology (failures remain evidence):

- Closure 52573; run 94413: 16 passed, 8 failed in 15.49 seconds. The borrowed
  native fixture failed before launch at unavailable INITIAL_AUTHORITY. It
  was replaced with the existing admitted POSIX local-child transport, not
  a native-broker or validator bypass.
- Closure 4028; run 77758: 18 passed, 8 failed, 14 setup errors in 83.93
  seconds. The new scalar guard incorrectly required an integer generation;
  the actual compatibility producer uses a SHA-256 generation. Root corrected
  the guard to admit the two existing scalar forms.
- Closure 80914; run 86780: all 40 focused tests passed in 87.46 seconds.
  The tests retain genuine local execution records, change both report outputs,
  require historical replay while strict replay rejects, damage each of the
  three records, and reject malformed denominators/nested values/path aliases.
- Run 84900, same production source: all 25 affected breadth/verifier/report
  staging and Core policy-conservation tests passed in 188.15 seconds.

The initial design for a generic historical DRIVER-progress API was withdrawn
before any source edit: actual Summary code uses ordinary deterministic
arm/commit, not a successor-plan journal. Canonical's current successor
validation remains appropriate for its live/partial-publication state.
Next integration must preserve original MODEL report bytes before mutation,
replay their exact worker record hashes, validate the precise Summary
commit/prestate/receipt transformation and unchanged passthrough outputs, and
bind those inputs into canonical staging. The current canonical read set
does not yet include the report MODEL trio or Summary receipt. No report
lineage completion, full pipeline, provider audit, or release claim follows
from these 65 targeted passing checks. Installed generation ef370327 remains
unchanged; no live DODO/provider run or new installation occurred.

## Report MODEL execution lineage follow-up (2026-09-11, SOURCE ONLY)

Read-only production tracing found ordinary POSIX report-index execution used
legacy descriptor capture just as breadth had before the previous repair.
The successful compatibility handoff now admits the exact ordinary report
case (report_index contract/label, no agent ID or custom staged validator).
The raw-preimage recorder requires matching unit/commit execution authority
and replays its three physical records; missing authority remains debt without
adopting bytes. Non-POSIX legacy paths are unchanged. Review caught and fixed
an initial wrong-function placement of the scoped predicate before tests.

Run 32431 passed two negative preimage cases in 11.98 seconds. First real-child
diagnostic 94137 passed those two and failed eight before launch because the
fixture's run ID was not canonical UUIDv4. With an honest UUID and serial/slow
CI classification, closure 27874 preceded run 88804: 14 passed in 40.92 seconds.
The minimal resolved report contract deliberately tests local-child transport
and raw MODEL admission, not full report methodology or remote model quality.

Expanded ten-file run 95473: 122 passed, 14 failed, 1115.23 seconds. All fourteen
failures are in `test_report_index_summary_parity_successor_a0_a1.py`: its old
setup lacks mandatory R10 consumer-ready authority. Breadth/verifier execution,
the new report cases, report routing and both canonical crash/retry cases pass.
The complete command is retained in session 95473. This is not a green suite.

Further tracing confirms a remaining production handoff gap. Canonicalization
calls the raw-preimage recorder only if report_index has no binding. Otherwise
the generic predecessor gate checks current ownership/bytes without reopening
the report MODEL execution records. Existing Summary/canonical receipts validate
their individual transitions, but no helper spans the original MODEL execution
through both optional successors. The verifier-specific exact-record reader
cannot simply be reused after report mutation: it only sanctions verify_*.md
successors. Preserve stable canonical contract identity across publication and
resume, and validate the real transition chain instead of following arbitrary
owner strings or skipping current-byte checks. This gap remains OPEN.

This batch is intentionally not installed. Installed generation ef370327 below
remains current. The same-run integration file's Low/Core adapter landed before
the final test closure despite an inaccurate agent handoff claiming no patch;
the root verified file state/mtime. A positive queue-conservation test has now
been added but is not yet run. No provider, live DODO or completion claim.

## Genuine breadth execution-retention follow-up (2026-09-11)

The source repair is now validated. New `posix_compat_model_incorporation.py`
reuses the existing dynamic-verifier receipt-to-MODEL transaction construction
for ordinary single-output breadth workers, independently revalidates the live
compatibility receipt, and retains the original atomic writer and verifier
schemas. Breadth success commits this lineage before its postworker hook;
missing lineage can no longer fall back to legacy descriptor capture there.
Both the postworker hook and breadth status/resume path replay the three
standard execution records before treating typed output as complete.

Intermediate run 81518 passed 14 and failed 6 missing/tampered-record cases,
revealing that generic artifact validation did not reopen those physical
records. After explicit replay, run 24566 passed 20. Expanded run 8648 passed
142 and failed two stale prompt fixtures. Those fixtures now preserve required
bound methodology when testing an absent kernel and distinguish descriptive
finding-format metadata from future-phase commands. Run 9530 (closure 34691)
passed 206, skipped 3 platform-specific native-execution cases, and failed one
newly added unsupported exact prompt assertion in 770.10 seconds. Its genuine
report crash/retry cases and same-run queue-to-blocked-report case passed.

Only the failing test assertion changed after 9530: it now checks the actual
unconditional one-file allowlist and stop directives. Closure 6001 preceded
five-file run 62435: all 43 tests passed in 61.56 seconds. That selection covers
breadth retention, worker pool, semantic kernel, CI infrastructure, and dynamic
verifier execution authority. Production hashes are unchanged since 9530.
The eight real-child retention cases cover healthy retention after outer
refusal and checkpoint reload, missing authority, and missing/tampered attempt,
provider and incorporation files, without launching either child twice.

These are deterministic protocol-double transaction tests, not model semantic
proof. Generic breadth replay validates its standard execution records but does
not separately reopen the nested raw compatibility receipt after restart;
initial incorporation validates that receipt with the live session. Full E2E,
native platform qualification and overall release acceptance remain open.
Installed after closure 28229 through managed compatibility installer 76340:
generation `ef370327f0cb0853b246d8c9b1aca2115c891246185ed666fc688ebe1b2981c6`,
7,392 entries. Help 45194 passes. Doctor 61085 verifies the exact package and
dependency cache and retains three setup failures: scip-go mismatch, incomplete
Claude runtime, and incomplete Claude verification-policy installation. All
eight changed production/test files match their tested source hashes. Reduced
isolation and existing provider/authentication coverage limitations remain.
Reconciliation still reports 195 open, zero proven, no completion claim. No
live DODO or provider call was made. Do not reinstall merely for this note.

Installed DODO dry plan 78108 passed with 75 resolved SC/Thorough phases,
fallback disabled, and zero provider invocations. This validates planning,
not live audit readiness or provider authorization.

The new real-local-child breadth retention fixture exposed a production gap.
The first two diagnostics were fixture errors: 4799 (1 failed, 4 passed) lacked
the two row-specific Opengrep inputs; 50450 (1 failed, 4 passed) wrote the
canonical output rather than the provider's private staging route. Production
correctly rejected both. After correcting those inputs and parsing the actual
provider-effective routing block, run 44089 (1 failed, 4 passed, 7.00 seconds)
reached the healthy sibling's ACTIVE/OUTPUT_COMMITTED unit but found no
`execution_authority`. The standard postworker hook had used
`LEGACY_DESCRIPTOR_CAPTURE` even though the child had a genuine compatibility
execution receipt. This is a production handoff omission, not semantic model
proof and not merely an assertion mismatch.

The initial repair plan was to factor the existing dynamic-verifier compatibility
receipt-to-MODEL transaction construction for ordinary typed breadth success.
Its original receipt, session, model, prompt, input/output and publication
validation must remain intact. Dependency research and attention retain their
specialized semantic gates. Missing execution lineage must become debt rather
than being adopted through legacy capture. The new fixture uses deterministic
harmless child processes only; it does not call a real provider, audit a target,
or prove a finding. Current tests additionally exercise missing/tampered worker
transaction records and retention of healthy output/refusal evidence.

Root also classified the heavyweight same-run queue-to-blocked-report module
and new breadth retention module in the serial/slow CI lane. The independent
report fixture review confirms that historical seeded output and real local
process authority do not establish real model semantic verification. Local
positive transaction tests remain useful, but full same-run live audit and
semantic verification acceptance remain separate and incomplete.

## Checkpoint rewind and refusal-stop repairs (2026-09-11)

Regression run 46794 reproduced three failures (5 passed): ordinary artifact
rewind and opt-in overflow rewind retained typed phase commits for removed
completed phases, making the saved checkpoint invalid on reload; breadth
fanout rewrote and retried an explicitly refused provider row.

The driver now retires the invalid suffix's typed commits together with its
completion projection. Opt-in overflow rewind also clears removed degradation
sentinels and stale rate-limit state, retaining findings and archived overflow
bytes. Default heal-aware overflow behavior remains unchanged. Breadth fanout
now retains healthy sibling commits, quarantines refused bytes, and returns the
refusal code to the existing terminal handler before retry construction. The
refusal-specific rewritten prompt and retry reason were removed; ordinary
quota retries remain separate. No provider was invoked for these tests.

Closure 59850 preceded focused run 33325: all 8 cases passed in 6.37 seconds.
Expanded ten-file run 81458 passed 165 and failed one in 32.01 seconds. The
remaining failure is a source-inspection fixture expecting the obsolete exact
launch expression `rc = run_phase(phase, config, attempt=1)`; its input-binding
ordering assertion is being migrated without relaxing production behavior.
These repairs are not installed yet. No live DODO audit is running, and this
component coverage does not close full E2E or release acceptance.
The breadth regression checks the healthy sibling's typed-commit hook and
retained bytes using mocked worker dispatch. A full healthy breadth sibling's
ACTIVE PhaseIO receipt surviving outer refusal commit and checkpoint reload
is not established by this fixture and remains a separate integration gap.

The obsolete fixture now uses AST to require both input binding and ordinary
launch calls, and orders the first binding before the first launch. Closure
44843 preceded final run 67311: all 169 selected tests passed in 32.33 seconds.
Selection: the ten complete files from run 81458 (artifact rewind, breadth
refusal, provider refusal stop, checkpoint reconciliation, semantic resume,
stale checkpoint mode, PTY execution, signals/rate limits, halt E2E, and phase
containment), plus the dynamic-verifier exact refusal and coordinator stop
cases and semantic-freshness typed sibling preservation case. This includes a
real harmless child termination check, not a live audit-provider invocation.
The complete command is retained in the execution record. Installation follows
this green source checkpoint; previous red observations remain retained.

Installed after closure 22867 through the managed compatibility installer
(93470): generation
`03664c0cb33dd01a7b517aa49157487dec0c81dcb3cda2bb4f03edd159784924`,
7,390 entries. Help 41184 passed. Doctor 63360 verified the exact package and
Python dependency cache and exited 1 on the unchanged three setup failures:
scip-go version mismatch, incomplete Claude runtime, and incomplete Claude
verification-policy installation. Reduced isolation, user-writable drift
detection, unprobed authentication, and nonauthoritative precise Slither
coverage remain explicit limitations. All five repaired production/test files
match their tested source hashes. Requirements reconciliation remains 195 open
and zero proven; no completion claim or live audit. Do not reinstall merely
to publish this post-install note.

## Observed defects

- Depth outer retries reused invocation identifiers, causing `INVOCATION_REPLAY`.
  The corrective code allocates nonoverlapping continuation ranges per retry.
- Attention validation replaced a committed receipt with byte-identical content
  but a different file identity. This invalidated the entire three-output
  producer cohort. Validation is now read-only; publication belongs to the
  driver's coupled output transaction.
- Exploration repair dispatched phase/model/timeout values that differed from
  its sealed launch. The repair now uses its dedicated registered launch.
- Late invariant recovery modified the canonical inventory and finding records
  without an authorized successor transaction. Subsequent inventory consumers
  and chain inputs were therefore invalid. Recovery now uses a coupled
  successor transaction; commitment validation does not mutate artifacts.
- Generic soft-debt handling allowed authority failures to reach later consumers.
  The verified correction classifies authority debt before generic schema debt
  and blocks affected mutation/progression. Legitimate degraded additive
  analysis remains supported; this is not a blanket halt on degraded phases.

## Verified so far

- Run14 depth and PhaseIO lineage regressions: 22 passed under normal test
  governance.
- Eight selected late-invariant transaction regressions passed, including
  interrupted publication, unauthorized prewrites, tampered partial vectors,
  rollback, and replay. Older synthetic recovery fixtures now register their
  producers through the real PhaseIO path; that suite passes all six cases,
  including explicit rejection of an unregistered source. Production checks
  were not relaxed.
- Depth additive, late recall-floor, and attention compatibility transaction
  suites: 29 passed under normal governance.
- JavaScript bootstrap authority: 34 passed; real source-to-staged package
  transaction: passed. Archive identities were not changed.
- Legacy compatibility retirement: three focused cases passed. Legacy identity
  grants retirement/skill ownership only, never current runtime admission.

Additional affected regression suites passed: authority progression 6, shared
P1-DM cutover 30, phase-commit controller 24, structural/checkpoint recovery 15,
and compatibility front-end 19. The clean temporary source-install test passed.

## Run16 startup evidence

Installed generation `5f83faf6e9fa91b44dacee7b36f68ff004be4441744415003fab020cf3474e5a`
passed the installed 7,363-entry census. The public command started the SC /
Thorough driver and supply-chain scanning, but stopped before any audit-model
launch. It did not reach recon execution.

- The snapshot comparator treated an optional EVM projection absent from both
  valid snapshots as changed. Stored/current snapshot digests were identical.
  The source fix compares membership over the union; added, removed, or changed
  projections remain drift. Four new tests cover EVM and non-EVM absent cases
  and the full projection membership/change matrix.
- Program Facts dropped `_snapshot_input_preparation` when copying its config.
  Rebuilding the snapshot therefore changed limitation metadata over the same
  source roster (179 files, 4,970,978 bytes). The narrow repair preserves that
  field; no source files changed.

Run16 remains untouched. Run17 is the next fresh diagnostic destination.
These results are component evidence, not a completed E2E run. Doctor still
reports dependency-cache, Go-indexer, and Claude-package gaps, and unavailable
RAG/Slither tooling. Tool unavailability and isolation limitations must remain
visible in run artifacts and the eventual report.

## Run17 execution checkpoint

Installed generation:
`4f3140a561bdb7995ae80025884e2aac1c4b429bd54be924b9339f255a118490`
(7,365-entry compatibility census). Run ID:
`482d8963-aa3b-45df-a7cd-ec953d05ec1f`.

The public command passed both run16 startup checks. Four recon workers
executed, their canonical output gate passed, and prompt instantiation passed.
At 23:23:43 local time on 2026-09-10, breadth analysis began with five planned
workers. Breadth completed at 23:30:45; re-scan completed at 23:38:20. The driver
then entered inventory preparation and `inventory_chunk_a`. Re-scan refreshed
the canonical identity map to 27 finding blocks, preserving source artifacts.
Two content-less self-exclusions were re-emitted for appendix disposition,
not silently discarded. These are unverified candidates, not audit findings.
This is active diagnostic evidence, not an end-to-end success claim.

The current source is newer than that installed generation: a narrow Program
Facts unadmitted-compiler handling fix and test/governance fixture corrections
have passed focused validation. Do not copy source edits into the active installation,
rewrite run17 artifacts, or resume it with another runtime generation.

Newly observed debt: Program Facts supplied literal `UNAVAILABLE` to a strict
numeric toolchain-version field before it could publish unavailable-provider
sidecars. The source correction represents an absent compiler observation
without inventing a numeric version. Its five focused tests passed under normal
governance (7.83 seconds). This includes structural replay of typed zero-fact
unavailability sidecars, not a claim of full driver or compiler execution.

External dependency research recorded 0 researched / 25 unresolved items.
The R-EXT worker actually issued five populated browser queries and claimed
24 researched rows, but the compatibility branch returned before the native
branch prepared JSON event capture and the research staged validator/context.
The artifact ledger correctly refused legacy canonical-byte adoption without
transactional research authority. The source adapter repair is in progress;
run17's prose claims must not be retroactively promoted to validated research.
The intended repair binds explicit compatibility-qualified evidence, the exact
research gate, and the driver's fetch receipt rather than fabricating native
execution authority.

Additional source validation: snapshot runtime-entry observability 15 passed;
snapshot baseline 50 passed / 1 existing skip; governance contract 10 passed.
The snapshot fixture correction retained the fail-closed path and changed only
an outdated assumption about limitation ordering. No quarantine entries or
node/marker rosters were removed.

Late-pipeline queue suites completed under normal governance with 34 passed /
16 skipped in 815.92 seconds: 50 collected, all 34 Darwin-applicable cases
executed, and 16 explicitly Windows-only cases skipped. There were no quarantine
skips. The unexecuted cases cover Windows share mode (1), handle retirement (1),
directory barriers (12, including 4 hardlink-boundary parameters), and handle
publication (2). The POSIX directory-fsync case executed. This is not evidence
that the Windows contracts work or that audit verification has completed.

### Run17 continuation: candidate conservation and invariant handoff

The inventory initially committed 20 findings, but read-only reconciliation
found seven additional pre-pass candidates missing from its input denominator:
`PSET-1` through `PSET-7` in `niche_permissionless_setters_findings.md` have
canonical identities yet no inventory retained/merged/refuted/drop-with-reason
dispositions. The shared source allow-list now includes the two exact registered
pre-pass niche filenames. Its two normal-governance regressions passed, covering
planning/reconciliation agreement, duplicate patterns, empty inputs, and
rejection of arbitrary niche markdown. This source fix is not installed yet.
The other 20 analysis candidates were accounted for. A subsequent
`ADDITIVE_REEMIT` receipt explicitly duplicates those 20 into `INV-021` through
`INV-040`. Read-only replay found that all 20 had exactly one initial source-ID
match, but preservation validation detected root-cause changes in all 20 and
impact changes in eight. The re-emission is the intended preservation response
to that semantic debt, not an identity-matching defect. It is not being removed
or normalized away.
Both content-less `PCRE-1/2` candidates have appendix-only dispositions.

At 23:45:24, invariant enrichment fell back despite the worker receipt recording
`COMPLETED`, return code 0, no timeout, and an 87,612-byte output. The first
gate rejection was a payload digest mismatch: the worker hashed compact sorted
JSON with a trailing LF, whereas the validator requires canonical bytes without
that LF. All 181 rows otherwise passed row validation. The source prompt now
specifies the exact canonical algorithm; the strict validator is unchanged.
The fallback formerly erased the original mismatch and committed `CLEAN`.
The source correction retains it as `COMPLETED_WITH_DEBT`; three focused tests
passed under normal governance. The separate 181-state conflict remains
upstream quality debt, not the cause of the digest rejection.

### Run17 terminal boundary and pending validation

Run17 entered depth with 15 planned jobs and concurrency 3. Two Sol workers
returned explicit service-side cybersecurity refusals. The old driver called
these transient, asserted a false positive, and rewrote a prompt for a bonus
retry. On identifying that behavior, the orchestrator interrupted the exact
driver and terminated its remaining Codex child. The public launcher exited
130 and confirmed checkpoint/artifact preservation. Those processes are gone.
Do not resume run17 to repeat this behavior or swap in a new runtime generation.

The source repair will record explicit provider-refusal debt and an incomplete
checkpoint, without automatic prompt reshaping, model switching, or refusal
retries. OpenAI's [official guidance](https://learn.chatgpt.com/docs/cyber-safety)
directs suspected Codex false positives to `/feedback` and makes access dependent
on the approved identity/model/surface. Account access was not established by
this investigation; no feedback or access application was submitted.

The combined research/invariant/Program Facts regression run collected normally
and returned 10 passed / 4 failed (22.37 seconds). Research execution, custom
commit/replay, and seven malformed-JSONL cases passed, but retry input delivery
and fetch-only recovery tests failed and remain under correction. The invariant
failure was a missing fixture config key, corrected before its three-test pass.
The Program Facts integration test now reaches the real provider constructor
and exposed a second production mapping bug: a path-shaped workspace alias was
used where an opaque root ID is required. Its source fix and stronger integration
test are pending another governed run. Do not equate the earlier five structural
passes with proof of this driver path.

Precise EVM tools also remain unavailable by construction: compatibility input
materialization is deferred, tool authority is unadmitted, and the workspace
execution helper unconditionally rejects even supplied native custody because
its production API is unfinished. Installing binaries alone cannot close that
gap. The observed `evm-source` graph is approximate and cannot establish precise
graph/static-analysis or full E2E acceptance.

## Verified repair publication (2026-09-11)

The combined focused and existing regression selection passed **127 tests in
72.32 seconds**, using `.venv-dev/bin/python -B -m pytest` with normal repository
governance. This includes inventory delivery; research execute/commit/replay,
negative evidence/input tests and fetch-only recovery; invariant fallback debt;
Program Facts real driver publication/replay and malformed projection inputs;
provider-refusal handling; and prior compatibility, research, inventory and
semantic regression suites. It is a selected regression result, not a full
suite, cross-platform, or live E2E claim.

The final Program Facts replay failure was a fixture substitution: adding the
snapshot-visible resolver authority after capture invalidated the fixture's
issued snapshot capability. The corrected fixture captures coherent config,
snapshot, checkpoint and workspace authority; production anti-substitution
checks remain unchanged. The research tamper fixture now explicitly changes
only its temporary owned file's permissions to exercise replay rejection;
production retained evidence remains read-only.

The existing installer successfully published generation
`c11f9a2f0bd71a40983d6294077bf1f509e292be2ff8a8f7ea6200be84730a9e`
with a 7,371-entry source census to `/Users/ptsanev/.plamen`. The public
`plamen --help` command returned 0 and reports version 3.0.0. This remains
explicit POSIX compatibility mode with reduced isolation. Run17 was not resumed
or rewritten with this generation.

Post-install `plamen doctor` independently verified the exact committed
7,371-entry installed census. It exited 1 with four existing setup failures:
missing/mismatched full Python dependency drift cache, scip-go 0.2.4 versus
0.2.7, incomplete Claude runtime package, and incomplete Claude verification
policy install. RAG and Slither remain unavailable warnings. These failures
are not repaired by this pipeline patch batch and remain release requirements.

### Remaining source-graph defect

Read-only run17 analysis found that raw declaration matching included function
locals and collapsed bare names across contracts. The graph had 71 bare-name
rows (31 local-only); the inventory had 110 file-qualified rows (44 local-only).
Their mismatched identities inflated the semantic worklist to 181 rows. At
least three custom-typed state declarations were missing. The schema-health
flag itself is not a precision claim; simply flipping it would not repair the
producer. A shared contract-scope declaration extractor, qualified identities,
declaration loci, and regressions are being implemented in source. Approximate
precision and genuine uncertainty must remain explicit. This correction is
not part of the installed generation above.

Core Python stamp/imports are valid. The missing full dependency census cache
and absent chromadb/sentence-transformers packages are real optional/RAG release
debt but did not block this selected compatibility execution route.

### Broader graph and Program Facts regression check (2026-09-11)

The next normal-governance selection completed with **86 passed / 9 failed in
43.15 seconds** (execution session 78625). Selection: source-state membership,
EVM source graph, state-symbol P0-AB, semantic invariants P1-D, enumeration
locality/type IR P1-AB, run13 semantic regressions, and the existing Program
Facts driver stage2 integration suite. The three new state-membership tests
passed; this is not acceptance of the entire graph change.

Two older EVM wrapper fixtures lack the workspace authority now required for
graph publication. Six older Program Facts fixture/contract cases likewise
lack the workspace receipt predecessor. The remaining state-resolution test
fails replay of its active producer authority. These failures remain under
investigation; production authority checks must not be bypassed to make the
tests pass.

Independent source review also identified a new regression in the proposed
graph patch: enumerating contract scopes only from their state declarations
drops functions from stateless contracts and derived contracts without their
own fields. The shared scope extractor must preserve that function universe
without pretending to resolve inherited state. This correction and its
regression coverage are pending. No new audit or installation was launched.

### Expanded graph/consumer check (2026-09-11)

The next governed run completed with **150 passed / 1 failed in 97.22 seconds**
(execution session 61159). It reran the broader selection and added scoped
asset-mover candidates, permissionless setters, enumeration graph health,
existing enumeration consumers, Rust/Go source graphs, and the real unavailable
Program Facts driver integration. The sole remaining failure is a test's
incorrect ordered-input expectation: the workspace receipt is required, but
does not occupy the assumed second slot after methodology inputs are ordered.
Publication, crash recovery, immutable replay, and graph tests passed.

The source graph now preserves stateless-contract, derived-contract, free, and
same-line overloaded named functions. Local variables and struct fields no
longer become contract state. File/contract/member identities join the state
inventory without permissive aliases. Unbalanced contract bodies produce an
explicit source-parse failure; ambiguous overload and inherited-state links
remain unresolved. The language-shape check uses the primary
[Solidity 0.8.26 grammar](https://docs.soliditylang.org/en/v0.8.26/grammar.html),
which distinguishes state declarations from other body elements and permits
free functions and multiple type-name forms. This lexical implementation still
does not provide compiler type or reference-polarity authority.

The downstream critical-asset mover check now retains qualified state identity
and scopes EVM candidates to their direct declaring contract. Unknown scope
and inherited relationships produce explicit shortfall records. An additional
same-line overloaded-mover regression is being added before publication to
prevent bare function names or line-only candidate keys from suppressing a
distinct candidate. No installation or live audit has been started from this
source revision.

### Graph repair batch published (2026-09-11)

The final combined selection passed **324 tests in 141.84 seconds**, exit 0
(session 25528), using normal repository governance. It includes all prior
127-test repair coverage plus graph/state membership, scoped candidate identity,
legacy EVM and non-EVM enumeration consumers, permissionless setters, Program
Facts workspace/crash/replay integration, and strict verification/report
hardening assertions. The source and directory census were frozen throughout.
This is selected regression evidence, not a full-suite or live E2E claim.

The final overloaded-mover regression preserves a distinct no-reference
overload even when a same-name overload references the state. EVM candidate IDs
bind file, contract, function line/column, and qualified state. Non-EVM candidate
IDs retain their prior bare-name form, including when the provider uses a
qualified SCIP key; their namespace has not been silently migrated.

The installer exited 0 (session 48461), publishing generation
`2b6893e12fe2d73b07d468b713e943554cd5c96ae4706adc816f19fcb8985c17`
with a 7,373-entry census. Public `plamen --help` exited 0 and reports 3.0.0
(session 19865). Public `plamen doctor` verified the exact committed census
(session 49720), then exited 1 for the same four setup gaps listed above. Its
RAG, Slither, and reduced-isolation warnings remain unresolved. No live audit
was running during installation, and run17 was not resumed or rewritten.

No fresh live E2E success is claimed. Applicable provider-policy access remains
unestablished after run17's refusals. Both-backend, precise-tool, native runtime,
and full cross-platform acceptance remain open. Documentation updates after
this installation do not mutate the installed generation.

### Verification/report baseline (2026-09-11)

The next normal-governance baseline completed with **104 passed / 5 failed in
1084.86 seconds**, exit 1 (session 45904). It covers live verification-queue
semantic closure, queue JSON, report-index PhaseIO/mechanical commit, committed
report-source replay, dropout retention, late-candidate lifecycle, and report
producer handoff. Source remained frozen throughout. The long-running process
was observed alive and CPU-active, not restarted on quiet output.

One SC mechanical report-index fixture fails at transaction arm. Four committed
report-source attack fixtures fail earlier than their intended assertion:
the consumer reports an absent producer work-unit receipt. These are unresolved
baseline failures, not yet evidence of either production defects or harmless
fixture drift. Repairs must preserve actual authenticated predecessor authority
and the specific attack checks; generic rejection is not an adequate substitute.

A separate same-run integration is being developed to connect the production
queue phase entry and a real checkpoint through dynamic verifier execution,
report prework, canonicalization, routing, and crash/replay. Existing adjacent
fixtures do not by themselves prove this combined handoff. External model output
may be deterministic in this test; provider execution and full DODO E2E remain
separate acceptance requirements.

Read-only sampling identified repeated parent-directory scans during fail-closed
artifact path validation as the dominant baseline cost. The queue tests amplify
this by executing 14 DAGs and 142 child commits. No validation was disabled and
no performance patch was applied. Separately, the Claude package diagnosis
traced its two doctor failures to a stale v2 projection lacking the verification
policy tree; the toolchain script itself exists. No installation was changed.

### Report capture production repair (2026-09-11)

The four report-source failures exposed a real production incompatibility:
`read_artifact_ledger` returns `_RootBoundWorkUnit`, a dictionary subclass that
retains the safely opened ledger root. Two report-source consumer seams instead
required `type(unit) is dict`, rejecting valid committed producers before their
authority checks. They now accept the returned `Mapping` without copying away
its root binding. Active commit, writer, run, schema, contract, launch, live
input, and exact byte checks remain enforced. A positive committed source-capture
roundtrip regression was added; all four attack-specific rejection assertions
remain unchanged. A read-only scan found no additional instance of this exact
work-unit wrapper mismatch in the verification/report consumers inspected.

The mechanical SC failure was separately traced to an outdated focused fixture
that omitted committed report-prework/R10 consumer readiness. That fixture now
crosses the real prework transaction with an explicitly empty upstream R10
universe; its consumer-ready and mechanical producer checks are not mocked.
It is not evidence of full nonempty queue-to-report composition.

Normal-governance focused validation passed **15 tests in 36.24 seconds**, exit
0 (session 73569). The expanded report capture, producer closure, source path,
configuration binding, mutation/replay, and mechanical selection then passed
**111 tests in 294.22 seconds**, exit 0 (session 10958). This does not erase the
earlier 104/5 baseline or mean that all 109 baseline cases were rerun together.
The repaired source was then published through the explicit compatibility
installer (session 62253, exit 0) as generation
`f1cc3126da81bfcff19820c8655aadfa7922380ff7224f68fa82cea1121ff83c`.
Public help exited 0 (session 62180). Doctor verified the exact 7,373-entry
committed census, then exited 1 with the same four known setup gaps (session
72457). The installed report-reader SHA256 matches the tested source:
`448bd4cbdcea890928d8ac49d7ee8d6c5caeb5579019e44392a084566acf5153`.
No audit process was running during publication. This remains a reduced-isolation
compatibility installation, not native runtime or E2E acceptance.

### Same-run queue-to-report integration: first execution (2026-09-11)

The new provider-free integration entered the real queue parent boundary with
a complete audit snapshot and persisted checkpoint, committed T0--T9, and
validated its public publication. Its first run then failed in **126.11 seconds**
(session 88897, exit 1): the fixture expected a grouped `H-1` row, whereas the
real queue retained `INV-1`, `INV-2`, and `INV-3`. The queue recorded advisory
evidence-projection debt with `PRESERVE_ALL_FOR_VERIFICATION`. This is an
unresolved test-denominator expectation, not evidence that candidates were lost.
Verification and report execution were not reached in this first test run.
The fixture must follow the actual conserved denominator without injecting a
preferred queue or bypassing its authority checks.

The second run retained all three queue candidates and reached the verifier,
then failed in **143.16 seconds** (session 8215, exit 1). The initial critical/high
unit recorded one validation debt. The test incorrectly treated the phase
handler's `True` (handled) return as proof of a completed unit, then forbade
execution on a replay of that incomplete work. Its resulting attempted relaunch
is not yet evidence of a production idempotency defect. The original validation
debt and actual completion receipt must be checked before asserting replay.
Report execution remains unreached. The deterministic external-output fixture
also needs honest PoC status: its reused payload must not be accepted as proof
of an actual test execution merely because its prose claims `POC-PASS`.

The second-run initial debt was subsequently identified as a harness API error:
`QueueWorkPlan` has no `items` attribute. The deterministic executor now reads
typed queue work items through the existing driver reader, and assertions require
an actual `COMPLETED` unit receipt before replay. No production change was needed.

The third diagnostic run reached completed verifier receipts and unchanged-child
replay, then failed at the real aggregate validator with `AuditInputDriftError`
for `source_scope` (**204.72 seconds**, session 89317, exit 1). Repository source
was frozen; the fixture's project-snapshot coherence remains to be repaired.
The guard must not be bypassed or its snapshot rebound after execution begins.

Separately, evidence review rejected this fixture as positive execution proof:
its synthetic `POC-PASS` text and verifier-output receipt bind model bytes, not
an actual PoC execution. The report's proof-grade gate does not promote those
bytes to `VERIFIED` without candidate-bound execution-scope evidence. Thorough
High findings require an attempted execution or an authenticated blocker; a
nonexecuted positive result cannot simply be supplied as deterministic prose.
The replacement test will be explicitly scoped to typed unresolved-debt and
`CONTESTED` denominator retention. That negative/degraded test does not replace
the outstanding genuine successful-verification and full audit E2E requirement.

The honest negative/degraded rewrite reached the typed aggregate debt, preserved
all three candidates with `proof_authority=NONE` / `UNRESOLVED` / `CONTESTED`,
then failed its report-prework expectation because an intervening required
post-verification prerequisite was absent (**158.06 seconds**, session 2099,
exit 1). Its next assertion must describe that actual nonconsumable boundary,
not invent prerequisite authority or claim a complete report path.

### Newly traced production verification blockers (2026-09-11)

Read-only production tracing identified three separate gaps. They are not fixed
by the installed report-capture repair and must not be concealed by launch mocks:

1. Dynamic verifier launch always calls the native headless-worker path. It has
   no explicit POSIX compatibility branch, unlike the working generic Codex
   executor. Its caller also converts the config to `dict`, losing the exact
   native `_DriverConfig` authority type required at the POSIX effect boundary.
   Repair of this launch/replay seam is now assigned, using existing supported
   session adapters. MODEL-process authority must remain distinct from PoC proof.
2. `ATTEMPT_REQUIRED` currently accepts Markdown `Attempted: YES` with a command
   and test-file name, without consuming an authenticated runner/tool-event
   receipt. The stronger `verification_policy.ExecutionReceipt` API is not wired
   into that production path. A real attempted-execution producer and consumer
   are required; simply adding another hard stop is not a complete repair.
3. Mechanical execution does not currently carry the opaque compatibility
   session through its execution boundary. A local PASS also provides only
   baseline execution scope; the richer candidate-bound HARM sidecar has no
   production writer identified by the trace. The report's proof-grade guard
   correctly refuses VERIFIED promotion without that independent scope evidence.
   Genuine positive PoC/report acceptance remains unavailable until these
   producer/consumer seams are implemented and exercised.

The root used OpenAI Docs to check the supported CLI boundary. Official
[non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode)
describes `codex exec`, its JSONL event stream, and final structured model output
as distinct interfaces. This supports preserving execution-event authority
separately from model-written summaries; it does not establish Plamen's own
candidate-specific execution receipts or prove a command ran.

The launch repair is in progress, not yet tested or installed. Its v2 verifier
gate binds the MODEL execution-authority digest. A downstream impact scan found
two additional production consumers requiring the same semantic validation:
aggregate completion in `plamen_validators.py` and report admission in
`report_disposition_authority.py`. Hashing an arbitrary gate file is insufficient.
The driver/lifecycle repair and these downstream consumers have separate owners;
they must share a real worker-replay contract and retain legitimate governed
mechanical successors without admitting arbitrary output drift. Legacy v1 gates
remain unbound evidence, not silently upgraded successful executions.

The revised same-run negative test now explicitly expects report prework to
refuse the absent `external_assumption_undemotion_compute.json` prerequisite.
That revision has not been executed. Its intended coverage ends at preserved
candidate debt and blocked report prework, not a generated final report.

Follow-up read-only PoC tracing clarified the current operational path: the
generic owned-process runner has no reduced-isolation compatibility allowance.
It requires its stronger platform capability, and mechanical callers currently
provide no writable roots, which would also prevent normal compiler output
under an active write sandbox. No runtime probe established that capability on
this host. The proposed next repair therefore reuses the existing explicit
compatibility session's actual child-process mechanics through a separate tool
execution entry point, not its Codex MODEL entry point. Any resulting receipt
must retain reduced-isolation limitations and bind candidate, command, test/source
bytes, executable, environment, output, and observed terminal status. It must
not claim native isolation or exhaustive escaped-descendant termination. This
is an implementation proposal, not completed or tested PoC execution support.

### Dynamic verifier launch: first behavioral batch (2026-09-11)

The first source-closure render failed before pytest because the expanded driver
was 4,199,642 bytes, exceeding the existing 4 MiB per-source bound (session
24184). Extraction of compatibility receipt replay into the shared helper
reduced the driver to 4,186,785 bytes without changing that bound. An extraction
syntax typo and omitted session argument were corrected before testing; closure
renders 71931 and 3256 then exited 0. No Python interpreter crash occurred.

The first governed test batch ended **20 passed, 1 failed in 13.62 seconds**
(session 88949). The genuine harmless fake-Codex child had executed and committed;
the fixture then asserted an optional `actor` field without declaring its
`required_commit_actor`. Declaring `MODEL` in the fixture contract retained the
assertion and required the actual commit to satisfy it.

The exact batch rerun passed **21 tests in 13.62 seconds**, exit 0 (session 6861):
the complete new `test_dynamic_verifier_backend_execution_authority_p0.py`,
`test_codex_provider_policy_refusal_stop.py`, and seven low-level dynamic tests
covering unit-receipt strictness, coordinator selection, rejected Claude PTY,
missing transaction authority, and backend executable selection. The positive
case launches a real harmless fake executable through the real compatibility
session and commits/replays MODEL authority without a second child invocation.
It is not a real provider call or a PoC execution test.

The replay case creates a new opaque session handle in the same interpreter;
its stable session binding can remain unchanged. A separate true
cross-interpreter restart test is still required. Aggregate/lifecycle/report
fixture migration, coordinator-level refusal stopping, actual PoC receipts, and
full E2E remain open. This patch is not installed. Subsequent source edits must
be revalidated rather than inheriting this result.

### True restart, positive report admission, and negative integration

The next governed batch added an actual fresh Python interpreter. It issues a
different session binding, reconstructs the exact contract/launch, forbids
provider executable resolution, and must replay the original authority without
incrementing the real fake-provider child counter. This passed, while the first
positive report-admission test exposed a new production reader defect:
`PhaseIOContract.to_dict()` stores phase/work-unit dimensions in its canonical
`key`, not separate fields. The batch ended **9 passed, 1 failed in 26.68
seconds** (session 33233). The reader now validates the matching six-component
canonical key before deriving those dimensions; it does not relax the authority
check. The exact rerun passed **10 tests in 26.47 seconds**, exit 0 (session
38711), including positive report admission and absent/forged authority vetoes.

The full report-disposition file then passed all **35 cases**. Its companion
negative same-run integration failed an added fixture assertion that looked for
a nonexistent `verification status` field on queue-denominator rows (**35 passed,
1 failed in 173.84 seconds**, session 72297). The fixture now joins those exact
candidate IDs to the actual authenticated status projection. The negative-only
rerun passed **1 test in 168.10 seconds**, exit 0 (session 45887), source SHA256
`5c07bfe7e3cee91f8c3f0a93eee54633161ed69e0cdab9c334bc27880ce59884`.
This finally verifies that fixture's deliberately limited boundary: three
unresolved candidates retained as CONTESTED, no implicit verifier relaunch, and
no report authority when the mandatory R10 prerequisite is absent.

Lifecycle/mechanical-successor and coordinator refusal regressions remain to be
run against the cleaned fixtures. Direct aggregate-consumer coverage is being
added. Actual PoC execution support is still an out-of-repository draft and not
wired into production. No new installation or live audit follows from these
component results alone.

### Lifecycle and aggregate authority batch (2026-09-11)

The combined lifecycle, direct aggregate gate-v2, real-child/restart, and
provider-refusal batch ended **22 failed, 15 passed in 29.30 seconds** (session
99427). All 22 failures stopped in a shared fixture: its prelaunch/control
LaunchSpecs still named Claude while the contracts named Codex. The contract
dimension check correctly rejected the mismatch. Both fixture launches now
derive the backend from their respective contracts; production checks were
not relaxed.

After closure render 5481 exited 0, the same batch reached **36 passed, 1 failed
in 60.82 seconds** (session 3256). All direct aggregate gate-v2 cases and the
coordinator refusal-stop regression passed, including persisted
`INCOMPLETE_WITH_DEBT` and no next-unit launch. The remaining missing-ledger
lifecycle test correctly retained verification debt but expected the previous
debt category; the new gate-v2 reader detects missing authority earlier. The
exact classification is under review before a final rerun. Neither result is
a live provider audit, actual PoC execution, installation, or E2E acceptance.

The missing-ledger assertion was aligned with that exact earlier gate category,
retaining its `VERIFICATION_DEBT` assertion. Closure render 54678 exited 0.
The expanded rerun (session 32326) included all four prior files plus the whole
`test_dynamic_verifier_runtime_integration_p0_ak.py`: **65 passed, 3 failed in
98.00 seconds**. All 37 lifecycle/aggregate/child/restart/refusal cases passed.
The three failures are the older multi-unit, rate-limit-retry, and Codex-route
fixtures that mock launch success without committing current MODEL execution
authority. Their migration must preserve the existing assertions while using
the real harmless child/transaction path; production authority checks stay
strict. No new installation or live audit was performed.

The separate PoC-source-path investigation ended in an explicit provider policy
refusal. It was not retried or reassigned to evade the refusal. Generic
process-runner draft review continues separately, with timeout cleanup,
interruption propagation, bounded stream accounting, and truthful wrapper/tool
launch distinctions still under review. Python's primary subprocess reference
supports using `start_new_session` and an explicit `env` instead of thread-unsafe
`preexec_fn`, and requires explicit cleanup after a communication timeout:
https://docs.python.org/3.12/library/subprocess.html . This is design-review
evidence, not execution acceptance.

### Generic verifier failure classification (implementation pending tests)

Review of the three expanded failures exposed a separate production defect:
the dynamic coordinator classified every child exit code 1 as
`RATE_LIMIT_DEBT`, including execution-authority and launch failures. The driver
now uses the existing backend-specific log detectors before assigning that
category; absent quota evidence stays `WORKER_EXECUTION_DEBT`. Explicit refusal,
untrusted transport, and timeout categories retain precedence. A missing current
compatibility attempt log also replaces the mutable latest-attempt projection
with an explicit missing-log diagnostic rather than reusing a previous quota
signal. Per-attempt logs remain unchanged.

The new focused regression file covers ordinary exit 1, missing logs, actual
structured rate limits, authentication errors, terminal-category precedence,
success rejection, and stale-log exclusion. These edits are not yet tested or
installed. They do not authorize a provider retry or change refusal handling.

### Launch/retry and downstream regression closure (2026-09-11)

The three older dynamic fixtures now launch a real harmless fake-Codex child
through the compatibility session, produce staged outputs, and commit actual
MODEL execution authority. The multi-unit test checks exact shared-input
ownership and no relaunch on replay/tamper. The rate-limit case emits an actual
quota diagnostic on its first child invocation and completes its second
attempt. No real provider or PoC test is involved.

The first focused batch ended **14 passed, 2 failed in 36.43 seconds** (50653).
Both failures expected redundant `--add-dir` arguments even though the sole
writable root was already the `-C` working directory. Assertions now check the
exact cwd and existing `workspace-write` sandbox profile without changing runtime
permissions. The next batch ended **15 passed, 1 failed in 41.62 seconds**
(94858): the fixture expected the execution-plan schema in the separate artifact
commit-authority record. That assertion now requires the real
`plamen.artifact-output-commit.v1` schema and checks MODEL output ownership.

After closure render 50689 exited 0, the expanded seven-file batch passed
**116 tests in 139.81 seconds**, exit 0 (34742), under normal repository
governance. Files: `test_security_obligation_lifecycle_p1_c.py`,
`test_verifier_completion_authority_v2.py`,
`test_dynamic_verifier_backend_execution_authority_p0.py`,
`test_codex_provider_policy_refusal_stop.py`,
`test_dynamic_verifier_runtime_integration_p0_ak.py`,
`test_dynamic_verifier_execution_debt_reason.py`, and
`test_report_disposition_authority_p0_r.py` (all under `scripts/`).

This validates the MODEL launch/replay and affected downstream authority repair,
including genuine quota versus generic execution errors and stale-log exclusion.
It is not full-suite, native release, actual PoC execution, provider audit, or
E2E acceptance. The generic process-runner draft remains outside the repository;
review identified concurrent reservation cleanup and ambiguous operation-key
encoding defects that must be corrected before application. The installation
of this tested Task-A repair is the next step, not yet part of this observation.

The normal compatibility installer subsequently exited 0 (40391), publishing
generation `63e3b563847f1ddde2edd5bbfec66e914ae87e3cabe8965545a892eb2910213e`
with a 7,378-entry source census. Public `plamen --help` exited 0 and reports
3.0.0 (41759). Public `plamen doctor` independently verified the exact committed
7,378-entry census, but exited 1 (65154) with the same four known hard failures:
Python dependency drift cache absent/mismatched, scip-go 0.2.4 versus required
0.2.7, incomplete Claude runtime package, and incomplete Claude verification
policy. Optional RAG dependencies and Slither remain unavailable; Claude
authentication was not probed. Doctor did not pass overall.

No prior audit scratchpad was resumed or changed, and no new provider audit was
launched. The installed Task-A repair retains explicit reduced isolation; the
unapplied generic process-runner draft is not part of this generation.

### Compatibility mechanical runner: captured-output repair (2026-09-11)

The separate generic TOOL process entry is now applied in source, not installed
and not yet invoked by `mechanical_verify.py`. Its initial real-child batch
passed 15 tests in 1.40 seconds (82893). Root review found two output-evidence
defects: controller exceptions were mixed into child stderr, and a failed
capture could be labelled complete merely because its reader existed. Those
paths now retain a bounded child-only prefix, put controller diagnostics in a
separate field, leave full-output hash/count unknown on capture failure, and
close finished readers without blocking on a still-active pipe reader.

The focused runner/collection batch passed 21 tests in 1.71 seconds (6881),
then the expanded 14-file batch passed 213 tests in 180.52 seconds (61812).
Further review identified an integration blocker: captured stream bytes were
discarded after hashing, so a later tool-specific consumer could not inspect
the actual compiler/test output. The runner now persists separate read-only,
byte-exact stdout/stderr sidecars before terminal publication. Its live issuer
record binds their file identities and hashes; both terminal replay and the new
`project_posix_v2_compat_mechanical_poc_streams` API reject changed, replaced,
missing, or symlinked stream files. The API returns retained bytes, not decoded
text, and completeness remains a separate explicit observation. Sidecars avoid
embedding potentially 64 MiB of raw streams into the 16 MiB JSON receipt bound.
Partial persistence burns the attempt and issues no terminal; orphan bytes are
diagnostics only. Session close removes live authority, not retained diagnostics.

The revised focused batch passed **30 tests in 2.26 seconds** (14780), and the
revised expanded batch passed **222 tests in 181.70 seconds** (38359), both exit
0 under normal governance after runtime-closure rendering. The expanded command
used these complete files, all under `scripts/`:

- `test_posix_v2_compat_poc_execution.py`
- `test_test_infrastructure_contracts.py`
- `test_posix_v2_compat_runtime.py`
- `test_posix_v2_compat_prelaunch_recovery.py`
- `test_posix_v2_compat_output_recovery.py`
- `test_posix_v2_compat_supply_chain.py`
- `test_posix_v2_compat_front_driver.py`
- `test_security_obligation_lifecycle_p1_c.py`
- `test_verifier_completion_authority_v2.py`
- `test_dynamic_verifier_backend_execution_authority_p0.py`
- `test_codex_provider_policy_refusal_stop.py`
- `test_dynamic_verifier_runtime_integration_p0_ak.py`
- `test_dynamic_verifier_execution_debt_reason.py`
- `test_report_disposition_authority_p0_r.py`

Windows collection was also corrected at the fixture boundary: POSIX-family
modules are excluded before import on NT, while mixed generic modules lazily
load and skip only their POSIX real-child fixtures. Portable native-config and
coordinator cases remain collectable. The runner file is assigned to the serial,
non-slow lane. The local structural tests prove that selection policy, not an
actual Windows execution or complete Windows acceptance.

Read-only integration tracing confirmed that a production prewarm call swap is
not yet valid. `gate_supply_chain` returns `None`, not a bound aggregate admission;
there is no dedicated prewarm work authority or published disposable workspace;
the two driver mechanical entry calls omit exact session/run/driver inputs; and
the current warm-up uses ambient environment/executable resolution in the
original build root. A resolved build root may also be outside the session's
project root. The next work must establish those actual bindings and connect the
workspace/cache consumer before routing primary and optional Cargo test-target
warm-up through PREWARM_BUILD. It must not fabricate authority hashes.

Every new terminal still reports reduced isolation, no native/WER authority,
no exhaustive descendant termination or network-denial proof, and no
cross-process recovery authority. `poc_attempted` remains false: process start
or exit zero does not establish a candidate-specific test attempt. The provider
refusal on the separate source-artifact investigation was not retried or
reassigned. No provider audit, installation, prior-scratchpad mutation, complete
PoC/report path, or full E2E acceptance occurred in this batch.

### Mechanical handoff and scanner admission repair (2026-09-11)

The two mechanical driver routes now share `_run_mechanical_verification`,
which passes the exact run ID, digest of the executing driver, and live
compatibility session. The mechanical entry rejects wrong or forged session,
run, project, scratchpad, or driver bindings before tool lookup or effects.
The gate receives that same session; a legacy unbound checkpoint cannot
silently activate the compatibility route. Seventeen new cases cover this
handoff, including both normal and recovery call sites. They do not execute a
compiler or prove a candidate test attempt.

The compatibility gate now returns an opaque, process-local
`SupplyChainAdmission`. Its immutable projection binds the session, scan root,
physical input denominator, fresh scanner receipts, and applicability. Replay
rejects altered inputs/evidence, forged shells, expired sessions, and other-run
admission. Actual scanner observations are tied to their current gate nonce;
a success-shaped mock or stale receipt cannot create admission. Unique receipts
no longer overwrite an earlier scanner execution. Not-applicable admission is
explicit and is not a dependency-safety conclusion.

Review found that rechecking live files before/after a scan did not prevent
swap-and-restore while the scanner read them. The gate now captures bounded
exact input bytes and uses those bytes for heuristics and private,
adjacency-preserving per-scanner staging. The staged input digest is bound into
the receipt and aggregate; originals are checked again afterward. Review also
found replacement-decoded output being hashed as if it were raw bytes. Stdout
now requires strict UTF-8; stdout/stderr hashes cover exact captured bytes,
while replacement decoding is retained only for stderr diagnostics.

Retained test observations (all under normal repository governance):

- 94699: 29 passed, 2 failed in 17.27 seconds; new projection expectations
  needed correction.
- 49335: 285 passed, 9 failed, 3 skipped in 42.88 seconds; old preparation,
  source-AST, scanner-mock, and MODEL-success-only fixtures needed migration.
- 57075: the old dual-lock mock failed because it did not accept the current
  gate nonce and could not prove actual execution; replaced with real harmless
  scanner children.
- 32555: 293 passed, 2 failed, 3 skipped in 50.35 seconds; staged-input fixture
  shell quoting and the clean preparation fixture's invalid lock format were
  corrected.
- 9132 after closure 80229: **297 passed, 3 skipped in 50.77 seconds**. The
  skips are Windows-only case-insensitive path cases, not executed on macOS.

The 15 complete files are `test_mechanical_driver_execution_bindings.py`,
`test_posix_v2_compat_supply_chain_admission.py`,
`test_test_infrastructure_contracts.py`, `test_supply_chain_gate.py`,
`test_posix_v2_compat_supply_chain.py`, `test_posix_v2_compat_front_driver.py`,
`test_mechanical_verify_phase.py`, `test_mechanical_verify_profile.py`,
`test_mechanical_successor_receipts_p0_ag1.py`,
`test_mechanical_successor_adversarial_review.py`,
`test_verification_transaction_commit_p0_ac.py`,
`test_post_verify_late_candidate_lifecycle_p0_g.py`,
`test_verification_operator_consumers_p0_ai_g.py`, `test_build_timeout_fix.py`,
and `test_posix_v2_compat_poc_execution.py`, all under `scripts/`.

#### Research found an offline scanner false-success assumption

After the green component batch, inspection of installed npm and
[upstream npm source](https://raw.githubusercontent.com/npm/cli/latest/workspaces/arborist/lib/audit-report.js)
confirmed that `offline === true` returns without querying advisories. The
report serializer can still emit an empty vulnerabilities object and zero
counts. Therefore `npm audit --offline` is not an offline vulnerability scan
and must not qualify for admission, even with valid JSON and exit zero. The
297-test observation predates this correction and is not scanner acceptance.
No online registry fallback is authorized by this repair.

[OSV's official offline documentation](https://google.github.io/osv-scanner/usage/offline-mode/)
describes actual comparison against a pre-provisioned local database, with an
error when that database is missing. Its
[supported-artifact list](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
includes package-lock, Yarn, and pnpm locks. The local OSV binary reports 2.5.1
with OSV-Scalibr 0.5.2; this version/help observation is not evidence of a
successful dependency scan. The previously assumed default OSV cache paths
were absent on inspection, so actual database readiness remains unproven.

The dedicated PREWARM publisher and work authority remain absent. The existing
driver snapshot-drift check can authenticate the accepted audit snapshot;
its `source_scope.digest` is an audit input census, not automatically a full
build-root/workspace census. The generic runner only checks the shape of the
work/admission/snapshot/census hashes; it cannot supply their missing semantic
authority. Retain and replay live admission at the actual compiler consumer,
publish the bound workspace and build manifest, and connect its cache to
subsequent execution before claiming production integration. No generated-PoC
source investigation or provider refusal was retried. No installation, live
audit, candidate PoC/report success, or full E2E acceptance occurred here.

#### Offline-provider correction and actual scanner observation

Production scanner discovery now offers OSV and cargo-audit only; package-lock
uses OSV. Direct npm scanner calls return `UNAVAILABLE` before either process
transport, even if a caller supplies an explicit executable. Legacy npm JSON
schema tests now test parsing only, not a fictitious offline admission.
Shrinkwrap remains in the input denominator but has no supported provider;
it fails explicitly rather than becoming an empty or silently skipped scan.
The existing native and compatibility OSV transport tests retain exact flags,
neutral configuration, process-group timeout, and receipt-property assertions.

The first corrected 15-file batch passed **298 tests, 3 skipped in 51.88
seconds** (60194; closure 53311). Root then strengthened invalid UTF-8 coverage:
the child now emits otherwise-valid JSON containing an invalid byte, which
replacement decoding would incorrectly admit. New gate-level cases verify
npm-only installations cannot admit locks in either route and unsupported
shrinkwrap cannot silently pass. The final same-file batch passed **301 tests,
3 skipped in 50.53 seconds**, exit 0 (60987; closure 37667). All three skips
remain the Windows-only case-insensitive lookup cases.

A separate real OSV **2.5.1 / Scalibr 0.5.2** invocation used an npm v3 lock with
one synthetic nonexistent dependency, neutral configuration, `scan --offline
--offline-vulnerabilities -L <fixture-lock> --format json --config <neutral>`.
It extracted one package, loaded a local npm advisory database, and exited 0
(78153). The actual cache location is `Library/Caches/osv-scalibr/npm/all.zip`
under the account home; the earlier absent-path observation used the older
`osv-scanner` directory name. No database download occurred.

The same synthetic project then ran through the source gate with a freshly
issued exact compatibility session (93557, exit 0). The gate returned an
APPLICABLE/ADMITTED result with one OSV scanner receipt; immediate live replay
succeeded, and the original lock hash was unchanged. Its admission digest was
`61b1a39c4e7dc864179fcbeca6d7c44790e287ea98670d65d7d4ac418278aa9e`.
The fixture lock hash was
`e274a3f0e388f4c5d8cfff5b75e0e97fddb93489f7bda0dbb11f3597a0da06dd`;
the local diagnostic script hash was
`cf4c216f7eb11c78453da60cde88f0152a818001f5d8c780131499e6226694c5`.
These are unsealed local observations, not a portable release dossier or a
database authenticity/freshness attestation. The fixture did not install
packages, compile target code, invoke a provider, or run a candidate PoC.

The installed generation remains the earlier Task-A generation. No install or
live audit was launched. PREWARM work/workspace publication, actual test-attempt
and independent scope evidence, downstream report completion, setup gaps,
cross-platform/backend release acceptance, and the full requirement ledger
remain open. A green scanner component is not the requested flawless E2E.

### Compiler prewarm integration checkpoint (2026-09-11, unvalidated draft)

The next source changes connect the mechanical compatibility entry to a
dedicated `mechanical_prewarm` publisher/runner adapter. The driver passes the
accepted snapshot and a callback to its existing fresh-snapshot drift check;
the callback captures the original run and snapshot bytes and rejects rebinding
before or during the check. It keeps the original driver config object rather
than downgrading its authority to a dictionary copy. The mechanical entry
retains the live scanner admission, receives the published workspace/cache,
and passes that execution root to the existing subsequent consumer. Its
summary keeps the original source build root distinct. Primary warm-up and
optional Cargo test-target compilation have separate outcomes.

This is source work in progress, not an installed or tested pipeline change.
Review of the first publisher draft found request directory-identity mismatch,
missing copied-tree versus selected-census comparison, incomplete bounded walk
error handling, incompatible snapshot canonicalization, fixed executable search
paths, and incomplete concurrent/partial-attempt replay. These are being
corrected before a governed execution test. Root's consumer tests stop at the
candidate boundary; they do not generate or execute a candidate PoC. The
separately refused source-artifact investigation is not being retried.

Tool-readiness inspection found the native Solidity 0.8.26 compiler in SVM's
macOS application-support directory. The `solc` on PATH is a Python
solc-select shim, which was not invoked. Explicit secondary compiler identity
and offline tool-data binding still need to be supported before declaring a
real Foundry build ready. No account HOME/environment restoration or compiler
download is implied by this observation.

The requested public DODO repository was cloned into a separate clean source
checkout (10234, exit 0). Its HEAD is
`d4834a468f7dad56b007b4450397289d4f767757`, exactly matching the prior source
checkout. The clean repository is approximately 3.9 MB; the older tree is
approximately 12 GB and contains all prior scratchpads. No previous scratchpad
was modified, resumed, or copied into the new checkout. Dependencies have not
been materialized in this fresh tree, and no new audit has started.

A separate read-only review of the retained-stream patch found no additional
concrete defect in persistence ordering, byte/identity authentication, or
projection. This is review evidence only, not an extension of test coverage or
an independent full-system acceptance claim.

### Compiler prewarm validation (2026-09-11)

The preceding draft checkpoint is superseded only for the tested component
scope below. The publisher now uses the runner's exact directory-identity
format, snapshot canonicalization and language normalization, bounded copy and
independent staged/source censuses, explicit executable/PATH input bindings,
and process-local serialized reservations. Replay checks retained workspace
identity and its terminal post-tree, authenticates output streams, and rejects
changed inputs. Primary/Cargo outcomes remain distinct; a second-launch failure
preserves the primary result and an explicit incomplete Cargo disposition.
Snapshot, admission and original-source checks run after compiler execution as
well as before it. Callback reentry cannot publish duplicate same-source work.

The first three-file test run (46828) ended 25 passed and 11 failed in 18.00
seconds: the new test fixture lacked auditable source, so all new cases failed
at snapshot construction. Root added minimal Solidity/Rust sources. Subsequent
runs (19973: 3 passed, 1 failed; 25124: 10 passed, 1 failed) exposed assertions
expecting a lower-level error when the real snapshot guard correctly rejected
links, special files or walk failure earlier. The revised tests exercise both
the direct census check and the intact snapshot guard; production validation
was not mocked away. The 16-file batch then passed 316 tests with 3 Windows-only
skips in 53.46 seconds (97546).

A new opt-in local compiler canary uses explicitly supplied native Forge and
Solidity paths, refuses script/shim magic, and selects solc in the fixture's
`foundry.toml`. This is a supported Foundry configuration, checked against
the [primary configuration documentation](https://github.com/foundry-rs/foundry/blob/master/crates/config/README.md).
The canary runs through the real compatibility session, supply-chain gate
(explicitly N/A for its dependency-free fixture), snapshot, publisher and child
runner. It checks nonempty compiled bytecode and Foundry's cache in the new
workspace, unchanged original source and compiler bytes, and exact no-relaunch
replay. The terminal remains PREWARM_BUILD with `poc_attempted=false`.
The focused canary passed (91412, 1 test, 9.33 seconds).

Root added failed-compiler diagnostic/no-relaunch and executable-drift replay
regressions. With both explicit native tool paths selected, the final same
16-file batch passed **319 tests, 3 skipped in 54.64 seconds**, exit 0 (30670;
closure 74782). The only skips were the three Windows-specific case-lookup
tests. The canary was executed, not skipped, in this batch. The five principal
source hashes and the two native tool hashes are retained in
`EV-COMPAT-PREWARM-319-20260911` in the evidence index.

No compiler download, Python solc-select invocation, account HOME restoration,
DODO dependency installation, provider launch, candidate PoC or live audit
occurred. This canary's explicit compiler path is not production proof of
version-selected solc discovery, secondary compiler byte admission, or offline
tool-data provisioning. Those are still required for the untouched DODO config.
Actual candidate execution evidence, independent scope adjudication, report
completion and release/platform/backend acceptance also remain open. The
installed generation is unchanged; these are unsealed source-component results.

### Version-selected native compiler repair (2026-09-11)

The next real-child diagnostic used `solc = "0.8.26"` instead of an absolute
compiler path. Forge exited 1 with an authenticated missing-offline-compiler
message (35869); the diagnostic wrapper exited 0 only because it printed the
failure disposition. This confirmed a real gap, not a passing compiler check:
the workspace HOME could not see the installed SVM cache.

The publisher now reads bounded default-profile compiler selection from the
admitted Foundry manifest (`solc`, `solc_version`, or `solc-version`). For a
version pin it follows SVM's existing-home-cache/platform-data-directory
selection; for an explicit path it selects that exact external binary. It
rejects conflicting selectors, relative commands, target-controlled binaries,
non-native scripts/shims, missing files and non-executable files without a
download or alternate compiler attempt. The cache path behavior was checked
against [SVM's primary path implementation](https://github.com/alloy-rs/svm-rs/blob/master/crates/svm-rs/src/paths.rs).

The selected source path, full file identity and content hash enter the retained
input/work binding. A bounded byte-checked copy is published under the private
workspace HOME with mode 0500, its identity is bound to the work record, and
`FOUNDRY_SOLC` selects that exact copy. Original and copied compiler identities
are rechecked before/after child execution and on replay. Source config and the
account compiler cache are not changed; the child keeps its workspace HOME and
offline environment. This is reduced-isolation local byte admission, not signed
compiler provenance, proof of unmodifiable memory during execution, automatic
unpinned multi-version selection, or native broker/WER acceptance.

The focused native/path/version group passed 16 tests (45554, 21.35 seconds).
New selection rejection, platform-path and copy-tamper cases were then added.
The complete 16-file batch passed **328 tests, 3 Windows-only skips in 67.30
seconds** (4389; closure 18030). All three real native compiler canaries ran.
Linux directory-selection logic was simulated on this Mac; no Linux runtime
execution or acceptance is claimed.

A fresh diagnostic using this Mac's real installed SVM cache and DODO's exact
`solc-version = "0.8.26"` spelling then passed (25464, exit 0), produced the
fixture contract artifact, preserved the original source census, and replayed
the same result without recompiling. It used a tiny dependency-free fixture,
not DODO contracts. The earlier failed diagnostic and its workspace remain
untouched. No new installation or live provider audit occurred. The remaining
DODO dependency, actual candidate execution/scope/report, cross-platform,
backend and release requirements remain open.

### Installed prewarm batch and readiness checks (2026-09-11)

After revalidating the source hashes and observing no running Plamen driver,
the existing compatibility installer ran under the managed CPython 3.12 with
`-I -B` (63422, exit 0; source closure 19898). It published generation
`a3171d62c0d952689967de4a17d3792de9c42546bc9a261233ebfbff0ad2b3d1`
with a 7,383-entry census. The installed `mechanical_prewarm.py` and
`mechanical_verify.py` hashes exactly match the tested source hashes.
Public help exited 0 and reports 3.0.0 (92008). Public doctor (77130) verified
the exact committed census, but exited 1 with the same four hard failures:
missing/mismatched Python dependency drift cache, scip-go 0.2.4 versus 0.2.7,
incomplete Claude runtime package, and incomplete Claude verification policy.
Optional RAG modules and Slither remain unavailable. No auth/Keychain probe was
performed, and no old audit scratchpad was resumed or changed.

A read-only dependency-resolution diagnostic used the managed CPython and
`pip --isolated install --dry-run --ignore-installed --require-hashes
--only-binary=:all:` against the unchanged full runtime lock (69551, exit 0).
The lock SHA-256 was
`6fc1be30eb61fa8c2d86801750a4064a144aaf9056764c2adbfe3737148b6bcf`.
All selected macOS ARM64 wheels resolved; missing wheels were downloaded to
pip's cache, but no package was installed into the managed runtime. This is
wheel-resolution/hash evidence, not import, RAG, dependency-census or runtime
acceptance. The command retains the protections documented in
[pip's secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/)
and the non-installing behavior of its
[dry-run option](https://pip.pypa.io/en/stable/cli/pip_install/).

Source inspection confirms that doctor's generic `plamen install` remediation
is not currently usable on this macOS compatibility installation: the public
POSIX guard rejects install/setup, and the explicit compatibility installer
does not perform the full Python dependency/stamp repair. This is a remaining
maintenance/recovery gap, not a reason to manufacture a cache or bypass native
production qualification. No full dependency installation was attempted.

The installed public `plamen plan light` command against the clean DODO
`omni-chain-contracts` directory with `--codex --json` exited 0 (43504). It
reported EVM/light, 18 source files, 2,735 lines, 51 phase entries, zero provider
invocations and no config/routing issues. The output's `launchable=true` is
limited to that planner scope; it does not override doctor failures or prove
candidate execution, report completion, credentials or an E2E audit. It used
the default light routing only as an observation, not a model substitution or
new provider attempt. Git status of the clean target remained empty.

The user has been asked whether the earlier provider refusals received a
provider-side review/resolution. No new provider attempt, refusal retry or
model/prompt change was made. Local process-receipt integration work continues
without reopening the separately refused source-artifact investigation.

## Exec-start observation and dependency-repair checkpoint (2026-09-11)

The first frozen-source check of the new process observer and the neutral
execution-policy result ended **72 passed, 6 failed** (70374, 1.77 seconds;
closure render 12032). Every failure was in the real-child compatibility
runner tests: the helper returned 125 without a start acknowledgement, so the
success output was absent, timeout/overflow were observed as nonzero exits,
and binary/stderr capture tests had no child bytes. This is a transport
regression, not successful candidate execution. The batch is not installed.

The policy introduces `EXECUTED_UNPROVEN` with mandatory
`SEMANTIC_RESULT_UNASSESSED` debt, UNPROVEN scope, no successful-receipt reuse,
and bounded retry-budget consumption. The process projection separately
represents exec-start and completion and never claims selected-test-body
execution. Its CPython 3.12 `close_fds=True` launch relies on the documented
exec-error handoff, not wrapper exit status; see the
[CPython 3.12 implementation](https://github.com/python/cpython/blob/v3.12.12/Lib/subprocess.py).
The actual failed canaries above take precedence over that design expectation.
Generic helper diagnosis and compatibility dependency-repair implementation
continue with source writes coordinated before further tests. No provider,
audit, dependency installation, or installed-generation change occurred.

The helper failure was subsequently isolated to opening `subprocess.DEVNULL`
inside Seatbelt: CPython opens it read/write, which the existing write-denial
profile rejects with `PermissionError`, errno 1. The helper now inherits stdin
already opened by the controller instead of reopening it. It retains
`close_fds=True`, no shell, and a non-inheritable private acknowledgement pipe.
No sandbox rule was relaxed. Bounded failure diagnostics expose only a fixed
stage name, exception class and numeric errno, never argv or exception text.

The next batch ended **143 passed, 1 failed** (80532, 70.15 seconds;
closure 18650). All helper and policy cases passed. The remaining isolated CLI
fixture used a tiny front that merely echoed argv and therefore did not emit
the new repair protocol. Its explicit inert response double was updated; it
does not install packages or prove real dependency materialization.

The expanded frozen-source batch then passed **446 tests with 3 Windows-only
skips** (30837, 109.11 seconds; closure 49123). It covered eighteen complete
test files: the preceding sixteen-file handoff/admission/prewarm/verification
group plus the execution-policy and compatibility-installer files. All three
native Forge/Solidity canaries executed. The installed generation remains
unchanged at this checkpoint; actual full-lock materialization, full-suite,
native platform/backend qualification, selected-test semantic proof and DODO
E2E are not established by these results.

The real maintenance-route source trace confirms that the exact installed
compatibility admission can reach the existing full-lock bootstrap repair,
import probe, pip check and census replay. Installer subprocess lifetime now
includes timeout, overflow, interruption/finally cleanup, residual-group
rejection and leader reaping. Package snapshot rollback does not imply rollback
of Python site-package changes; provenance explicitly distinguishes these.
An unsuccessful pip operation may leave an already-invalid dependency stamp
present, but that stamp cannot pass the census or permit commit. No stamp is
fabricated to make doctor green.

The first real compatibility installation of that batch failed (17174, exit 2;
closure 82474): pip reported the base Python environment as externally managed.
The full-lock bootstrap incorrectly used `managed_python.resolve()` for four
child launches. On this symlink-backed venv that invokes Homebrew's base
interpreter instead of the managed environment. PEP 668 refused the operation;
no override was used. Package provenance was restored to generation
`a3171d62c0d952689967de4a17d3792de9c42546bc9a261233ebfbff0ad2b3d1`
(7,383 entries), public help still passed, and no matching repair/pip child
remained. A managed-interpreter `-I -B` observation confirmed distinct venv and
base prefixes. This matches the
[documented venv identity](https://docs.python.org/3.12/library/venv.html#how-venvs-work)
and preserves [PEP 668's protection](https://peps.python.org/pep-0668/).

All four child launches now keep the admitted venv entrypoint spelling;
resolved binary identity checks remain unchanged. Pip children additionally
use Python `-I` isolation. Execution-level tests extract the real bootstrap
function with controlled process authorities and assert the repair, full import,
pip-check and valid-cache child argv. A genuine stdlib venv child verifies its
prefix independently. These and the test-lane checks passed **7 tests** (1634).
The expanded nineteen-file batch then passed **449 tests, 3 Windows-only skips**
(41730, 110.43 seconds; closure 42900), including all native compiler canaries.
This is the tested source for the next installation attempt, not evidence that
the actual full dependency repair has succeeded.

The second real installation **succeeded** (97749, exit 0; closure 24450),
publishing generation
`214c3fc7e331f0250b39b135e5814631260ebc814f5297783e737fe6c1af1e6d`
with 7,385 entries. The supported child completed full-lock dependency repair,
import/pip-check postconditions and exact census replay before commit. This is
actual dependency materialization/validation evidence, not just a dry run or
fixture. No PEP 668 override, ambient Python 3.14, Keychain probe or provider
invocation was used. The installed front and exec helper compare byte-for-byte
with the tested source.

Public help passed (11595). Doctor (50961) verified the exact 7,385-entry census
and now reports the Python dependency drift cache as exactly replaying.
`sentence_transformers` and `chromadb` are present; Slither 0.11.5 matches its
version pin, though precise-provider authority is still unavailable and remains
explicit coverage debt. Doctor exits 1 with **three** hard failures: scip-go
0.2.4 versus 0.2.7, incomplete Claude runtime package, and incomplete Claude
verification-policy installation. Codex's runtime-required denominator is
complete. Reduced isolation and user-writable cache trust are still explicit;
this is not native execution or cross-backend release qualification.

The new installed generation's provider-free DODO plan passed (70045):
EVM/light, 18 files, 2,735 lines, 51 phase entries, no routing/config issues and
zero provider invocations. Its default Terra route was observed only, not
launched or used as a model substitution. Git status of the clean target is
unchanged. `launchable=true` remains a planner-scope fact, not E2E readiness.

The next verification handoff still needs an authority-aware receipt mint:
replay the typed queue, work plan, verifier output/current bytes/proposal and
trusted launch, then derive the candidate-only work binding and project the
opaque live process terminal inside the mint. Constructible DTOs and caller
digests are not authority. The follow-up read-only prewarm review also confirms
there is no authenticated harness-availability fact: compiler success cannot
become `harness_available=True` or selected-test-body proof. Preserve that gap
instead of claiming a completed candidate execution/report path. The separately
refused investigation remains closed, run17 remains stopped, and no live audit
was started.

The final source-closure refresh initially detected a concurrent root-index
change while a Git status check was running (6194). The serialized retry passed
(56084). Keep Git operations outside closure derivation as well as test/import
windows; this was a source-freeze procedure failure, not an installed-package
or audit result. No production code changed after the 449-test batch.

## Unknown assessments and exact verifier launch joins (2026-09-11)

The following goal turn made concrete progress rather than merely restating
readiness: the pending policy change was reviewed and exercised, and two
previously missing authority joins were reproduced and repaired. Installation
generation `214c3fc7e331f0250b39b135e5814631260ebc814f5297783e737fe6c1af1e6d`
remained unchanged during source tests.

`VerificationWorkItem` now represents unassessed local testability and harness
availability as `None`, rejecting non-boolean/non-None values. Unknown is not
unavailable and cannot validate a non-execution blocker. Severity-required
attempts and the fuzz matrix remain intact. Both assessment debts survive
optional/required projection, receipts, retry and reconciliation. No compiler
or prewarm result is promoted to harness availability or semantic proof.
The policy/authority baseline passed **121 tests** (95712, 22.31 seconds;
closure 65447). The nineteen-file transport/prewarm/policy/install regression
batch passed **472 tests with 3 Windows-only skips** (68693, 106.36 seconds).

The aggregate verifier-completion gate replayed receipt bytes and a genuine
MODEL/control chain, but initially compared the receipt's launch/backend to
its own values rather than to the current dynamic launch. Two regressions
injected mismatched values before genuine harmless-child and DRIVER
transactions; both were incorrectly accepted (87592). The new receipt/spec
comparison passed **153 tests** (79628, 43.65 seconds). Public lifecycle already
calls this aggregate gate before its private byte reader, so it inherits the
repair without a duplicate production implementation. End-consumer regressions
require explicit `VERIFICATION_DEBT`, retained rows and the exact completion
authority debt reason. The broader eleven-file report/authority batch passed
**212 tests** (88307, 328.90 seconds). During that long run, a read-only native
process sample showed directory traversal, not a Python crash; the original
test process remained live and completed without restart.

Review also found that the parsed launch spec's work-unit ID, resume digest
and exact output set were not joined to the current roster assignment. The
first regression run (95790) reproduced two false acceptances; the unit-ID case
instead failed during fixture setup because its foreign prompt location was
absent. Supplying the same harmless fixture prompt at that location allowed
the real child to run, and all three cases then reproduced false acceptance
(35182, 8.64 seconds). The production gate now applies the same exact
spec/assignment checks already used by report disposition, before the
receipt/spec join. The final nine-file affected-consumer batch passed
**201 tests** (54001, 58.24 seconds; closure 18855). These tests do not contact
an external provider and do not constitute a live DODO audit or proof of
candidate harm.

The next integration point is the mechanical per-candidate loop: replay the
current queue/plan/roster, verifier completion and run/session bindings before
execution; derive candidate work authority; then project the opaque terminal
inside the receipt issuer. Emit the attempt receipt before mechanical manifest
and successor publication, and reconcile it at mechanical precommit. Do not
make receipt issuance depend on its later manifest/successor, which would
create an ordering cycle. Recovery must replay the original verifier prefix
through any existing mechanical successor. Unknown assessments can remain
explicit debts while an actual attempt is recorded; no invented positive
harness fact is needed. This adapter is not implemented by the above fixes.

The tested policy/launch-join batch was subsequently installed successfully
(94659, exit 0; closure 25947) as generation
`6ae0ba5cb03f914d76d691a1bfd327bfddf35297a89330e0346e5109da620bfa`,
with 7,385 entries. Installed policy and validator bytes match the tested
source. Public help passed (70364); doctor (81265) verifies exact package and
Python dependency-cache replay but retains the same three hard failures
(scip-go version and both Claude installation gaps). The installed provider-free
DODO plan passed (31359), with 18 files, 2,735 lines, 51 phase entries and zero
provider invocations. Default Terra routes were displayed only, not executed.
No live audit was started and no prior scratchpad was resumed or changed.

Following the user's explicit parallel-work request, three existing agents
were assigned disjoint work: the generic candidate bridge and its own tests;
the live policy converter and its integration tests; and read-only mechanical
precommit/recovery integration analysis. Root owns integration/governance and
the continuation evidence. Source tests/imports/Git remain serialized after
all writers freeze. The bridge review identified an additional necessary
boundary: authenticated process argv and a candidate-purpose label alone do
not prove that the invocation is the assigned candidate test. Do not issue
mandatory attempt coverage without the corresponding bound runner/selection
authority, and do not substitute an unconditional fail-closed placeholder for
the requested successful execution path.

The live policy projection repair is now implemented in the two scoped
validator functions. Queue PoC class remains classification, not measured
local testability, and both missing and explicit compiler success/failure are
excluded as harness-availability authority. The modern execution-policy branch
no longer calls `_build_succeeded`; the legacy positional route is unchanged.
New tests cover unknown assessments, missing/failed/successful build signals,
required/optional mode projection, debt conservation and invalid blocker
waivers. Root also registered the three genuine-child modules
(`test_dynamic_verifier_backend_execution_authority_p0`,
`test_security_obligation_lifecycle_p1_c`,
`test_verifier_completion_authority_v2`) in the serial integration/slow taxonomy
and its ratcheted structural contract. CI already runs the integration lane
serially; this does not exclude these tests from CI or our explicit commands.
The thirteen-file regression batch passed **280 tests** (29819, 59.45 seconds;
closure 36438). This follow-up source batch is not yet installed.

The candidate bridge review ended without creating the proposed module/tests.
The live session, queue/plan/roster, exact verifier/model completion, resolved
policy and supply-chain admission can already be replayed, but there is no
production authority independently binding the candidate subject/test selector
to the runner invocation. `runner_spec` is explicitly inert argv metadata;
method compilation is not terminal authority. The opaque process outcome
authenticates execution of caller-selected request data, not independent test
selection, and currently omits the request's subject path/hash/test-function
fields. Do not interpret its candidate-purpose label as mandatory coverage.

The proposed missing public interface is
`replay_current_candidate_runner_authority(scratchpad, session_authority, *, finding_id, constituent_id, attempt_number)`.
It must replay a DRIVER-owned pre-execution record tied to current MODEL/work
authority, with exact subject identity/bytes, selector, runner/executable/argv,
working directory, closed environment, limits, expected outputs, admission,
snapshot/workspace and run/session/policy/attempt bindings. Its return would be
a projection only, never caller-provided authority. Receipt minting must replay
that record itself and compare it with the opaque terminal. This is a required
design/integration gap, not an implemented API or a new authorization to
reopen the separately refused source-artifact investigation.

The independent mechanical consumer review identifies these actual seams:
`_run_mechanical_verification` owns normal and ordinary resume entry and can
resolve policy, exact driver identity and the live compatibility session.
`_validate_verification_precommit`'s mechanical branch is the common final
gate through `_commit_verification_transaction`; it currently has config/run
and disk evidence but no live session parameter. Integration must thread the
actual process-local session explicitly if replay needs it and check config
run identity against checkpoint run identity. Existing append-only
`mechanical_execution_evidence` records are not consumed by
`_mechanical_successor_authority_view`; neither those records nor the unused
generic `ImmutableGateExecutionLedger` is current candidate-attempt authority.
Keep the attempt receipt independent of its later manifest/successor, then
bind/reconcile the complete result set before successor publication and again
at precommit. Missing authority must retain findings and verification debt.

All parallel workers are now frozen. An asynchronous question asks whether
the account/access issue behind the earlier provider refusals was reviewed
and resolved; no answer has arrived at this checkpoint. No new provider
attempt, target audit, or old-run resume occurred.

The 280-test policy-projection/CI batch was then installed successfully (38674)
as generation
`511ec20dd1f8f3923f3654dc93fc881c3ddc9dea93d89970e190f87e48d24632`
(7,385 entries). Source and installed policy/validator/CI files compare exactly.
Public help passed (38049); doctor (94091) confirms exact package and Python
cache replay, with the same three hard failures and explicit compatibility
limitations. No provider invocation or new DODO audit occurred.

The next read-only boundary reviews identified three concrete defects for a
new coordinated source batch. Startup ordinarily copies checkpoint run ID into
config, but verification commit does not recheck that invariant: validators
and digest resolution may use config's run while the controller records the
checkpoint run. Mechanical precommit and successor validation also accept
canonical zero-result manifests without joining the mandatory typed queue
denominator; a downstream report check is too late to certify mechanical
coverage. Finally, append-only execution evidence correctly preserves each
duration-only observation, but execution-scope matching ignores duration and
then demands a single match, invalidating the supported second observation.
These are review findings until the assigned regressions and fixes run.

The successor authority itself already handles materially changed reruns
safely: the new manifest becomes a pending generation, immutable successor
comparison rejects it, and the summary/verdict projection becomes degraded.
Do not change that consumer to select a latest record. The duration-only repair
must instead select the unique fully validated observation exactly matching
the canonical manifest result, retaining other timing observations as telemetry
without allowing them to substitute for absent/tampered canonical evidence.

The three repairs are now applied in source. The first closure render (7477)
rejected the driver at 4,195,669 bytes against its existing 4 MiB source cap.
The queue-coverage implementation was extracted into
`scripts/mechanical_precommit_coverage.py`; the driver retains its small public
wrapper and the source limit is unchanged. Closure render 95218 then passed.
The first thirteen-file regression run (10073) finished with **292 passed,
3 failed, 3 Windows-only skips** in 74.63 seconds. Two execution-scope negative
tests expected an inner diagnostic, but immutable-derived-source replay correctly
rejects earlier; those assertions were corrected without weakening the rejection,
byte-preservation, or invalid-assessment checks. The third failure is an older
R10 fixture returning mocked worker success without committed MODEL execution
authority. Its migration to a genuine harmless-child transaction is in progress.
These results do not certify the batch green or installed. R10 and its three
fixture-consuming modules are assigned to the serial integration/slow CI lane.

The focused replay/taxonomy/R10 rerun (68599) passed 26 tests and failed the
R10 fixture during setup: operator application was generated before production
created `method_dispatch.json`. The fixture now delays preparation until the
real Codex execution seam, preserves `-B` for its harmless child, and invokes
the captured real executor. Focused rerun 57393 reaches a real completed child
but still returns `WORKER_EXECUTION_DEBT` (1 failed, 47.03 seconds); the exact
post-execution rejection is under read-only investigation. Neither failure is
an external provider invocation or a successful report handoff. The installed
generation remains unchanged.

The exact worker rejection was `MODEL_BINDING_MISMATCH`: the harmless fixture
hardcoded `gpt-5.4` while the selected fixture route requested `gpt-5.6-terra`.
Root now derives the simulated banner from the real executor's `effective_model`
argument; there is no external model substitution. The existing output writer
already uses private staged `route['path']`, not the canonical destination.
Closure 42203 passed. Rerun 65157 now completes the genuine MODEL/control
handoff and R10 prework, then fails at report canonicalization's verify-output
parity gate for GRP-022A, GRP-022B and H-22 (1 failed, 97.56 seconds). Preserve
this later failure and investigate its exact report-consumer seam; do not keep
treating the now-fixed model mismatch as the blocker. No installation occurred.

Further replay established that all three canonical-root verifier decisions
were valid. The actual isolated report stage omitted the three files named by
each MODEL unit's execution authority (attempt completion, provider completion,
and incorporation), even though its copied ledger still referenced them. The
initial suggestion of fixture-cache contamination was not the cause of that
report failure. The new genuine-child stage regression first needed two fixture
corrections (orthogonal R10-ready scaffolding and the same separately copied
mutable ledger used by production); session 52373 then reproduced the actual
missing `.worker_transactions` authority in the stage.

The new `validated_verifier_model_execution_read_set` helper replays the
existing successor-aware worker authority and contributes exactly its three
validated record paths to `_report_verifier_phaseio_graph_paths`. It does not
copy receipt directories or mint execution proof. The graph reader now also
recognizes governed mechanical successors only for MODEL-owned verifier output
artifacts; other artifacts and semantic inputs retain strict byte equality.
The denominator manifest reader now applies its byte budget during the read,
not after loading the whole file.

Focused tests passed 62 cases (99883), then 74 including genuine live/staged
MODEL authority, a valid mechanical successor and all six missing/tampered
receipt-file cases (14844, 14.14 seconds; closure 6490). The expanded twenty-file
run (23485) finished **397 passed, 1 failed, 3 Windows-only skips** in 230.51
seconds. Crucially, the original R10 report canonicalization/routing fixture
now passes (139.69 seconds). A native process sample during that run showed
active directory enumeration, not a Python crash or hung provider.

The remaining expanded-run failure is
`test_primary_operator_denominator_is_current_exact_and_missing_is_debt`:
its fixture unexpectedly selected native startup and reported missing auxiliary
root authority. It passes in a fresh interpreter (42410, 9.08 seconds), and
after the whole backend-execution fixture module (18259, 9 passed in 16.76
seconds), so investigate test-order/module-state contamination rather than
weakening runtime startup. The operator-consumer and dynamic-runtime fixture
modules are now explicitly assigned to serial integration/slow CI. This source
batch remains uninstalled pending a clean broader run.

The order-dependent fixture cause is now confirmed: an R10 test reloads
`plamen_driver`, so the operator test's collection-time driver and its lazily
imported borrowed fixture referenced different module objects. The fixture now
binds its `D` to the exact driver under test and asserts genuine compatibility
activation. No startup predicate or native permit is fabricated. After closure
62867, the same twenty-file batch (85986) passed **398 tests with 3 Windows-only
skips in 233.78 seconds**, including the original R10 handoff (140.13 seconds)
and the formerly order-dependent operator test. The preceding red observations
remain evidence. The tested production hashes were rechecked before packaging;
supported installation and public CLI verification are next. No live provider
or DODO audit was invoked, and this is not full E2E acceptance.

The supported managed-3.12 compatibility installer succeeded (28582), publishing
generation `2fe42c61bb624003b57728763c7a66c3d6a39b313299a97478bf62ba7da4e889`
with 7,388 source entries after closure 91108. The requirements reconciliation
remains 131 active requirements plus 64 child proofs open, zero proven, and no
completion claim. Installed repair/test hashes match the tested source. Public
help passed (87967); doctor (93122) exited 1 after validating the exact package
census and Python dependency cache. The same three hard failures remain:
scip-go 0.2.4 versus required 0.2.7, incomplete Claude runtime package, and
incomplete Claude verification-policy installation. Reduced isolation,
user-writable cache trust, unprobed authentication, and Slither source fallback
remain explicit limitations. No live audit was started or resumed. This note
postdates the installed package and does not require another installation.

A parallel read-only setup review confirms that scip-go's supported repair is
the interactive `plamen setup` L1 (Go) selection, which derives exact
`go install github.com/scip-code/scip-go/cmd/scip-go@v0.2.7` from the lock.
Go must be operator-provided; do not substitute mutable `@latest`. This would
repair version readiness only: the lock still marks executable content
OBSERVED_NONAUTHORITATIVE without reviewed content hashes, so precise SCIP
authority remains unavailable and Go source fallback remains explicit. This
Go/L1 setup issue is not the DODO EVM execution blocker. No tool was installed
by this review; the parallel Claude integration repair review is separate.

Correction to that review: the recipe exists, but its public command is not
currently admitted on POSIX. `_early_refuse_unsupported_posix_production_command`
rejects ordinary `install` and `setup` even with compatibility installation
active; only the exact installed compatibility dependency-repair maintenance
leaf is exempt. Therefore the setup selection above is not a runnable repair
on this Mac. Doctor's ordinary install/setup advice must reflect that platform
boundary without weakening admission or removing the underlying hard failures.

Public installed probes confirm that boundary: `plamen install` (36032) and
`plamen setup` (49621) both returned exit 3 before mutation. The bounded Claude
review found no supported public POSIX projection repair route. The admitted
dependency-only leaf repairs Python dependency census, explicitly grants no
native install authority, and does not project the Claude runtime/policy trees.
The blocked legacy installer is broader than a missing-file repair (package,
config/MCP and dependency changes); its credential behavior was not established
by this review. Do not invoke it through an internal bypass or treat dependency
maintenance as Claude integration. Doctor guidance is being corrected while
the actual backend installation requirement remains open.

The parallel report recovery review identified a coverage gap, not a confirmed
production defect: the new real MODEL execution-record staging tests do not
yet combine with canonicalization crash/retry. Existing crash-prefix tests use
older fixture authority. A scoped regression is in progress to preserve the
exact three receipt bytes through interruption, retry the canonical transaction,
and validate completion without relaunching the verifier.

The first combined diagnostic/recovery batch (83117; closure 30963) finished
**78 passed, 5 failed in 143.09 seconds**. New doctor behavior tests passed,
including retained hard failures and preserving the exact admitted compatibility
Python dependency maintenance advice. Three older CLI/probe tests need fixture
migration: an obsolete literal bootstrap call search, a shim-render mock missing
the platform keyword, and a POSIX deadline test trying to execute the nonexistent
fake `selected-member` path. Both new report crash/retry cases returned before
their intended fault seams; their early result/setup is under investigation.
This is a red source batch, not installation or recovery acceptance. Source
repair also keeps Windows noninteractive install advice distinct from setup's
real-terminal requirement. The installed generation is unchanged.

The three CLI/probe fixture repairs are now green. The bootstrap-order test
recognizes the current source-discovery guard while retaining the dependency
closure assertions. The shim mock accepts and checks platform forwarding. The
deadline fixture uses a harmless managed-Python child on POSIX: simulated
authority replay consumes 50 seconds, then member execution advances the clock
to 70, proving that a 60-second member budget is not incorrectly started before
authority replay. Windows retains the fake owned-scope branch.

Combined rerun 39622 finished **83 passed, 2 failed in 146.11 seconds** after
closure 99898. Explicit model-preimage registration did not resolve the early
recovery stop, so the earlier inference was incomplete. Diagnostic run 78017
(closure 55097) captured the actual result: `PostVerifyCandidateDeltaError:
T9 publication plan authority is absent`. The reused fixture had selected its
historical mode. Root added an optional `live_t9` argument to the existing
strict R10 fixture and enabled its already-supported authenticated live queue
publication for these two cases; no historical stage capability was fabricated.
The before-commit case then passed (27593, 132.38 seconds; closure 78399).

The next complete batch, 6208, finished **84 passed, 1 failed in 323.80 seconds**.
The after-first-output crash fired correctly, but the test wrongly required a
live journal before that later output had been published. At this prefix the
armed ledger and immutable recovery source manifest govern retry. The assertion
now checks that manifest, preserving the live-journal assertion for the later
before-commit point. Final closure 72518 and batch **68763 passed all 85 tests
in 356.25 seconds**. Both cases preserve all three MODEL transaction record
bytes, prohibit verifier relaunch, retry to ACTIVE/OUTPUT_COMMITTED, and replay
live verifier completion plus the report receipt's run binding. This validates
generic report recovery with a genuine harmless verifier worker, not remote
model execution, semantic finding proof or a full DODO audit. Installation of
this source follow-up is next; prior failures remain retained evidence.

The follow-up is now installed. Closure 42100 and requirements reconciliation
passed; the ledger remains 195 open and zero complete proof claims. The managed
3.12 compatibility installer (61062) published generation
`675df90cfa08e12a3ddf599f808335d6087052c8dd760b641369884a505bd998`,
7,389 source entries. The installed frontend and five changed test files match
their tested source hashes. Public help passed (34838). Doctor (35677) verified
the exact package and Python dependency cache, then exited 1 with the same
scip-go mismatch and two Claude projection failures. Those failures now explain
that ordinary POSIX install/setup is refused; valid dependency maintenance is
not conflated with Claude or toolchain repair. Reduced isolation, user-writable
cache trust, unprobed authentication and Slither fallback remain explicit.
No live provider invocation or new/resumed DODO audit occurred. This post-install
note is not itself part of that installed generation and requires no reinstall.
