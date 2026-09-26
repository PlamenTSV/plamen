# Typed artifact boundary decision

Status: accepted implementation direction; staged migration required

Date: 2026-09-23

## Decision

Plamen will keep its existing domain-typed immutable JSON, PhaseIO,
content-addressed storage, and exact-reconciliation architecture.  Model-authored
Markdown will cease to be a canonical machine-to-machine phase interface.

Every migrated model work unit will instead publish a closed, domain-specific
JSON result packet under a provider-enforced output schema.  The driver will
validate that packet against exact input, roster, identity, ownership, and
semantic rules; commit the accepted typed records through PhaseIO; and render
Markdown as a deterministic projection.  No downstream phase may parse that
projection back into semantic authority.

The tolerant Markdown reader remains a compatibility adapter for unmigrated
and historical artifacts.  It is not the terminal architecture.

## Why the current implementation is insufficient

The current target architecture is correct, but the migration is incomplete.
Many live work units still combine four concerns in one Markdown file:

1. provider transport completion;
2. structured semantic records;
3. producer and transition provenance; and
4. human-readable presentation.

The driver consequently attempts to reconstruct identities, relationships,
and dispositions from presentation.  A tolerant reader reduces incidental
format failures, but it cannot prove producer ownership, distinguish two
plausible identity columns, or make a multi-file transition atomic.  Repairs
then accumulate at individual consumers and the same ambiguity reappears in a
later phase.

Runs 50-68 demonstrate three distinct classes that must not be conflated:

- representation failures, such as inventory selecting a provenance column as
  the local finding identity;
- authority failures, such as a valid artifact being attributed to a stale or
  different producer transaction; and
- ownership failures, such as recon and depth both claiming the same graph
  projections.

The inventory column fix correctly repairs the first class.  The graph handoff
change correctly repairs the third class by enforcing one producer.  Neither
can eliminate the whole family while Markdown remains the semantic exchange
format.

### Real-run denominator

The DODO run history makes this an architectural decision rather than a parser
preference.  Of runs 50-67, twelve reached a late semantic boundary and then
stopped because a representation reconstructed from Markdown, a producer
binding, or a successor relationship could not be authenticated.  Those
failures were not one recurring regex bug:

| Runs | Observed terminal class | Architectural implication |
|---|---|---|
| 50 | inventory producer-authority mismatch | a valid payload and its owner were separate truths |
| 51 | chain critical-boundary failure | a whole artifact remained the retry/failure unit |
| 52-53 | inventory representation/facet reconciliation | presentation was still parsed as semantic state |
| 54-59 | verify-queue/post-verify producer and transition mismatches | downstream consumers reconstructed lineage after the fact |
| 60-62 | workspace/dependency capture | separate hermetic-input defect, not an artifact-format failure |
| 63-64 | verify-queue projection/delivery authority | typed and legacy paths still met at a mixed boundary |
| 65 | startup/no completed phase | no evidence for an artifact-validator diagnosis |
| 66 | inventory identity-column ambiguity | provenance and local identity shared one Markdown namespace |
| 67 | recon/depth graph double ownership | two phases attempted to own the same canonical outputs |

Run 68 is the first fresh canary containing both the disjoint inventory
identity parser and the single-owner graph handoff.  Its result can validate
those two fixes, but it cannot validate the terminal architecture while later
phases still accept model-authored Markdown as authority.

### Concrete live gap

The report boundary demonstrated the unfinished migration.  A deterministic,
recall-safe report-index producer and a DRIVER-owned PhaseIO transaction already
existed, but only L1 used that path normally.  A fresh smart-contract audit
still fell through to a model that wrote `report_index.md` and
`report_coverage.md`; the deterministic producer was used only as a repair
after those files existed.  The older `report_index_machinery.py`
candidate/action JSON protocol is tested but is not imported by the production
driver, and its opt-in switch defaults off.

That was not the best currently available design.  The source generation now
routes fresh SC and L1 indexes through the same deterministic PhaseIO producer;
the historical SC model path remains only for replay/repair.  This cutover is
source-only until the active Run 68 generation finishes, is installed, and a
fresh real audit crosses it.  If model judgment is retained for consolidation,
it must be a schema-constrained proposal input to the renderer or to the later
zero-loss dedup transaction, never the writer of the canonical index.

## Considered designs

### Continue tolerant Markdown parsing and targeted repair

Rejected as the end state.  It remains necessary during migration and for
historical replay, but it leaves correctness dependent on presentation and
requires every consumer to understand formatting variants.

### Add SQLite or another mutable finding database

Rejected.  It would introduce a second state authority, a large migration, and
new transaction/recovery semantics while duplicating PhaseIO and the artifact
ledger.  The existing decision against a big-bang SQLite ledger remains valid.

### Adopt Temporal, LangGraph, or another workflow runtime

Rejected as a runtime dependency.  Their durable execution, checkpoint,
idempotency, and retry principles are applicable, but Plamen already has a
phase state machine, run-generation identity, PhaseIO, and replay contracts.
Replacing the orchestrator while semantic artifacts remain ambiguous would
move rather than solve the defect.

### Schema-constrained typed results plus existing PhaseIO

Accepted.  Codex already supports `exec --output-schema`, and Plamen already
has the necessary ownership, content binding, canonical JSON, and deterministic
projection primitives.  This design removes an authority surface instead of
adding another one.

## Boundary protocol

A migrated work unit follows this sequence:

1. The driver freezes a work plan containing the exact run/generation,
   work-unit and attempt identities, input artifacts and digests, semantic
   roster, output schema identity and digest, model route, and tool policy.
2. The provider runs in an attempt-private staging namespace.  It cannot write
   canonical phase artifacts.
3. Codex returns a schema-constrained JSON result.  When the task creates test,
   fuzz, or PoC files, the result contains a closed manifest of staged paths,
   hashes, commands, and claimed outcomes; it does not make those claims
   authoritative.
4. After the process tree is closed, the driver validates the result and any
   staged files against the frozen plan.
5. PhaseIO incorporates accepted typed records and staged payloads in one
   recoverable publication.  A late or foreign attempt cannot commit.
6. The driver renders Markdown or report text deterministically from committed
   typed records.  Presentation validation can never change semantic state.
7. A phase commit requires exact roster reconciliation: every planned record
   is either incorporated or represented by an explicit typed debt outcome.

## Validation classes

Validation is deliberately split so a formatting issue cannot masquerade as a
security invariant:

| Class | Examples | Action |
|---|---|---|
| Transport/schema | malformed provider result, missing required JSON member, invalid enum | One bounded result repair; no canonical publication |
| Authenticity/transition | wrong run, input drift, foreign producer, double owner, stale attempt, impossible state transition | Hard stop before mutation |
| Record semantics | unknown referent, incomplete evidence, unresolved source facet, unsupported tool result | Preserve the affected record as typed debt and continue when recall-safe; never drop siblings |
| Presentation | Markdown heading, table decoration, column order, wording | Deterministic renderer correction or warning; never a phase halt |

A hard stop is therefore reserved for cases where proceeding could give
unowned, stale, or incomplete bytes false authority.  It is not used because a
human-facing representation differs from a parser's preferred spelling.

## Schema rules

- Use a small common envelope only for run, attempt, input, schema, roster, and
  outcome bindings.  Each domain owns a closed record schema; do not create a
  generic `dict[str, Any]` finding protocol.
- Set `additionalProperties: false` at every object layer supported by the
  provider schema dialect.  Required nullable fields represent intentional
  absence.
- JSON Schema proves structure, not protocol truth.  Referential integrity,
  source hashes, severity/disposition authority, tool execution, and state
  transitions remain application validation.
- Canonical on-disk JSON is produced by the driver, not trusted byte-for-byte
  from the provider.  The provider response and its digest remain retained
  transport evidence.
- Schema versions are immutable.  Evolution uses an explicit successor schema
  and deterministic upcaster where lossless; historical bytes are never
  relabeled.
- Valid sibling records are committed independently or retained for the final
  atomic phase barrier.  One invalid row must not trigger whole-artifact
  regeneration.

## Migration order

1. **Report index and report writer inputs.** The driver is now the sole fresh
   report-index renderer in source for both SC and L1.  Install and cross that
   boundary in a fresh real audit, then either remove the dormant
   `report_index_machinery.py` action protocol or finish its PhaseIO ownership
   and Codex structured-output path strictly as non-authoritative consolidation
   proposals.  Retire the historical SC model-index compatibility branch after
   replay coverage no longer requires it.
2. **Inventory chunks.** Emit one typed result row per assigned source action;
   render chunk Markdown only for review.  The canonical aggregate consumes
   typed rows directly.
3. **Chain, exploration, and verification proposals.** Give every candidate a
   stable source identity at first emission and carry relations as typed edges
   rather than Markdown tables.
4. **Discovery and depth findings.** Migrate first emission to typed records,
   keeping narrative Markdown as a view.  This is the point at which most
   downstream reconciliation parsing can be deleted.
5. **Historical compatibility retirement.** After consecutive fresh real-audit
   canaries and replay coverage, prohibit new-generation Markdown authority and
   retain the tolerant reader only for older schema generations.

Each cutover replaces its legacy semantic parser/repair path.  It must not only
add a parallel representation indefinitely.

## Acceptance criteria

A phase is migrated only when:

- the provider-enforced schema and driver validator reject malformed,
  duplicate, missing, foreign, stale, and contradictory records;
- presentation metamorphisms produce the same typed records and no phase-state
  change;
- valid rows survive invalid siblings without another model call;
- crash points before/after provider return, validation, incorporation,
  projection, and phase commit replay to one result;
- both Codex and Claude adapters produce the same logical denominator when the
  backend is supported;
- a fresh real DODO audit crosses the migrated boundary without invoking the
  legacy semantic parser; and
- the replacement deletes or disables the corresponding legacy authority path.

## Research basis

- OpenAI Structured Outputs recommends strict JSON Schema when downstream code
  requires type-safe output and distinguishes schema conformance from ordinary
  JSON mode.
- JSON Schema separates structural assertions from annotations and explicitly
  leaves application semantics to the application layer.
- Temporal and LangGraph document durable replay and the need for deterministic,
  idempotent side effects across retries.
- Bazel's hermetic action model binds declared inputs, outputs, and content
  identities; in-toto similarly binds step materials and products.
- OpenAI Agents SDK guardrails distinguish rejecting one output/tool result and
  continuing from raising a workflow-stopping exception.

These systems support the separation above; Plamen adopts the invariants using
its existing PhaseIO authority rather than importing another orchestrator.

Primary references:

- OpenAI Structured Outputs:
  <https://developers.openai.com/api/docs/guides/structured-outputs>
- JSON Schema validation draft 2020-12:
  <https://json-schema.org/draft/2020-12/json-schema-validation>
- Temporal durable execution:
  <https://docs.temporal.io/>
- Bazel hermeticity:
  <https://docs.bazel.build/versions/main/hermeticity.html>
- in-toto materials/products model:
  <https://in-toto.io/docs/getting-started/>
- OpenAI Agents SDK guardrails:
  <https://openai.github.io/openai-agents-python/guardrails/>
- LangGraph persistence/checkpoint design source:
  <https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/graph-api.mdx>

## Run 69: durable identity is content plus provenance, not inode

The real DODO Run 69 crossed recon, breadth, rescan, inventory, semantic
invariants, the full graph-assisted depth fan-out, fuzz/Medusa execution, and
the exploration skeptic.  It stopped at enumgap because late-CI recovery
published `findings_inventory.md` through a raw atomic replace even though its
postimage was byte-identical.  That changed inode/mtime, and replay treated the
physical churn as a semantic producer change.  Strict replay then invalidated
the predecessor's unchanged coupled siblings as well.  No finding or canonical
byte had changed.

The boundary rule is now explicit:

- durable artifact identity across validation epochs is SHA-256, exact size,
  run/work-unit ownership, input set, and authenticated transaction lineage;
- a live artifact must still be a no-follow, regular, single-link file;
- device/inode/mtime seal one validation epoch and detect a concurrent path
  swap, but are not semantic identity across separate driver calls; and
- exact driver publication is universally idempotent: a byte-identical safe
  postimage is a physical no-op, while a real content transition remains an
  atomic replacement.

This is defense in depth rather than another phase-local exception.  The shared
publisher avoids needless churn, while PhaseIO replay accepts a safe exact-byte
rematerialization even if a legacy or future publisher forgets the no-op
optimization.  Changed content, symlink/reparse targets, hardlink aliases,
foreign owners, stale runs, and unregistered successor transitions remain
invalid.  Successor preimages and unchanged producer siblings use the same
content/provenance rule, so the policy applies to early phases, depth,
verification, and report transactions.

The design follows established content-addressed systems.  Bazel's remote
execution protocol addresses blobs in CAS by digest and associates action
digests with results; OCI descriptors identify content by digest and size; Git
objects are content-addressed while mutable refs select objects; and in-toto
binds step materials/products by hashes and provenance.  AWS's idempotent API
guidance supplies the retry complement: persist request/transaction identity
with the mutation and return the same semantic outcome for the same request.

Primary references:

- Bazel Remote Execution API:
  <https://github.com/bazelbuild/remote-apis/blob/main/build/bazel/remote/execution/v2/remote_execution.proto>
- OCI Image Specification descriptor:
  <https://github.com/opencontainers/image-spec/blob/main/descriptor.md>
- Git objects and refs:
  <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>
- in-toto specification:
  <https://github.com/in-toto/specification/blob/master/in-toto-spec.md>
- AWS Builders' Library, idempotent APIs:
  <https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/>

## Run 68 evidence and corrective cutover

Run 68 was a fresh, real DODO audit at commit
`d4834a468f7dad56b007b4450397289d4f767757`. It crossed recon, breadth,
rescan, inventory, semantic invariants, depth, attention repair, exploration,
RAG, chain synthesis, Chain Agent 2, and eight bounded Chain Iteration 2
shards. Medusa executed 141,070 calls over 100 branches with three passing
properties and no failures. The run stopped at `sc_verify_queue`, before any
verifier worker launch, for two representation/authority defects:

1. Three rescan findings had exact source-file, source-ID, and SHA-256
   referents in the canonical inventory, but an earlier Markdown-heading
   classifier had labeled their source rows `RESIDUAL_DEBT`. Exact delivery
   now takes precedence over that presentation classification; only residuals
   for the exactly delivered action are cleared, so unrelated debt remains
   fail-closed.
2. Five substantive depth-iteration-2 carryover findings used legitimate
   `BLIND-*`, `VS-*`, `PERT-*`, and `MEDUSA-*` identities outside the old
   `depth_core` local-ID grammar. They now have one artifact-scoped
   `depth_da_carryover` producer namespace. Ordinary depth artifacts remain
   owned by `depth_core`, preventing an overlapping-writer escape hatch.
3. Run 79 exposed the remaining derived-identity gap: the DA worker correctly
   qualified reviewed upstream actions as `DA2-<upstream-id>`, but the registry
   approximated that family with a numeric-suffix regex. The qualified grammar
   is now mechanically derived from the declared upstream carryover grammar.
   This accepts `DA2-BLIND-A1`, `DA2-DS1`, and later-iteration equivalents
   without accepting arbitrary DA-prefixed or canonical inventory/report IDs.

The same run also exposed `UNOWNED_EXISTING_OUTPUT` in
`sc_semantic_dedup`: a legacy crash-safety passthrough published canonical
files before the model contract was armed. That prewrite is retired. The live
supervisor waits only for the model-owned `dedup_decisions.md`; the raw proposal
is committed first, then the common five-output semantic-dedup transaction
atomically publishes the inventory, record projection, applied receipt,
absorbed map, and review projection. Replay reuses the exact terminal paired
mutation events instead of re-arming against its own postimage.

Report boundaries received the same treatment. Fresh SC and L1 report indexes
are DRIVER-rendered from typed evidence. If bounded report-body model attempts
exhaust, an authenticated typed-evidence renderer is a registered terminal
successor for that exact shard; it cannot invent or change finding semantics.
Missing or tampered typed evidence still fails closed.

## Run 70: graph providers must expose one downstream interface

Fresh real DODO Run 70 validated the content-addressed boundary through recon,
breadth, rescan, inventory, and both semantic-invariant passes. It did not hit
an artifact-format, ownership, byte-identity, or quarantine loop. It stopped
before launching Depth because the EVM approximate provider published the
authenticated `_mechanical_graph.json`, while only the precise SCIP provider
published `caller_map.md`, `callee_map.md`, `state_write_map.md`,
`function_summary.md`, and `_mechanical_graph_generation.json`. The
Inventory-to-Depth handoff correctly required the complete provider-neutral
denominator, so the missing adapter became a hard precondition failure.

The correction is a distinct deterministic DRIVER PhaseIO transaction,
`inventory/mechanical_graph_projection`. It binds the exact mechanical graph,
derives all four projections, seals their hashes and sizes with the mechanical
graph in one generation manifest, and publishes the set once. A complete
precise-provider generation is validated against its own manifest and reused;
a partial, stale, or colliding generation is never adopted or overwritten.
The downstream handoff is not armed until this projection transaction is
clean, preventing a missing provider adapter from leaving a poisoned
`INPUTS_BOUND_PREEXECUTION` handoff in the ledger.

This is interface normalization at the provider boundary, not an EVM-only
validator exception. Precise, approximate, and future graph providers now
have one required consumer contract. Semantic invariants and every standard
Depth role can therefore bind the same graph denominator without knowing which
provider produced it.

## Run 71: models state semantics; the driver seals machine identity

Fresh real DODO Run 71 crossed the normalized graph handoff, both semantic
invariant passes, the full graph-assisted Depth fan-out, authenticated Forge
and Medusa campaigns, attention repair, exploration, enumgap, axis coverage,
application skepticism, semantic dedup, RAG, and both primary chain agents.
Three remaining instances of one architectural smell were removed from the
next generation while the installed run continued:

1. Attention-repair workers copied a shard hash into otherwise valid rows.
   The PhaseIO plan already binds queue and shard bytes, so copied hashes are
   now inert presentation. Exact row identity, denominator, verdict, evidence,
   and application receipt remain mandatory.
2. Axis base/repair workers copied run, worklist, repair, source, evidence,
   receipt, commitment, and document hashes. They now emit only disposition,
   rationale, evidence kind/reference, and the falsifiable invariant claim.
   The driver routes rows by the exact request denominator and derives action
   IDs, loci, provenance, source/receipt hashes, and all compound digests.
   Partial valid base rows still survive into the bounded repair transaction;
   semantic defects remain repair work.
3. The one-shot report-evidence repair asked the model to copy request and
   record digests. It now accepts semantic deltas only. The raw response stays
   byte-exact and MODEL-owned, while the driver projects canonical request and
   record identity before arming the deterministic apply transaction.

The same run exposed a separate ownership violation in SC semantic dedup. The
model proposal was committed at 924 bytes, after which a validator appended
about 13 KiB of conservative PASSTHROUGH rows to that same file. The resulting
hash warning was correct. Missing dispositions are now published in a distinct
DRIVER-owned `dedup_coverage_repair.json` sidecar bound to the exact candidate
pair bytes and exact model-proposal bytes. The proposal is never edited.

This is the general boundary rule: a model artifact contains judgments and
evidence references; PhaseIO/driver artifacts contain routing, identity,
digests, ownership, and transaction state. Strict validation remains for the
semantic denominator and allowed claims. Representation-only metadata cannot
halt an otherwise valid transition, and deterministic repair cannot rewrite a
MODEL-owned source artifact.

The Run 71 fuzz work was real execution rather than fixture evidence. The
driver materialized fresh isolated harnesses, compiled 77 Solidity files for
the Forge invariant campaign, and authenticated a one-call failing sequence.
Medusa compiled the isolated target, executed roughly 259,000 calls, shrank a
one-call counterexample, and reported the same writable-flag violation. Binary
identity, argv, environment, raw logs, return codes, runner witnesses, and
result-index projection are separately bound; the model Markdown correctly
remains an execution request rather than retroactively claiming tool output.

## Run 71 verification cutover: paths are typed data, not prose matches

Run 71 completed both chain-analysis iterations and entered
`sc_verify_queue`. The cutover then raised macOS `ENAMETOOLONG` before queue
publication. A whole-document regular expression had interpreted a long
finding-description suffix ending in `contracts/GatewayTransferNative.sol` as
one source pathname. Relative/traversal checks passed, but the first component
exceeded the filesystem's encoded `NAME_MAX` boundary.

The repair has two layers. First, live source discovery now consumes only
typed `location` fields from `finding_records.json` and explicitly anchored
`Location:` fields from the inventory projection. Descriptions and arbitrary
JSON prose are never searched for paths. The source grammar disallows spaces
inside a component, recognizes only supported source suffixes, and keeps line
coordinates separate from path identity.

Second, `portable_path_contract.py` establishes one pre-I/O invariant for all
model/provider-derived relative paths: strict UTF-8, no NUL/line delimiters,
at most 1,024 encoded bytes overall, and at most 255 encoded bytes in any
component. Existing traversal, namespace, glob, and ownership policies remain
at their respective boundaries. The lexical invariant is now used by worker
transactions, graph/security-obligation paths, chain-tail and chain-candidate
transactions, semantic dedup, every live/pre-verification queue layer,
post-verification candidate import, report evidence, report mutation, report
assembly, and real-audit bundle export. Optional evidence paths degrade to
explicit missing-evidence debt; authoritative paths fail as typed contract
errors. Neither path reaches `exists`, `stat`, `resolve`, or `read` first.

Depth filename drift received the same ownership correction. Alias discovery
no longer renames a model artifact or rewrites its embedded markers. A
DRIVER-owned `depth/alias_projection.<digest>` work unit binds the immutable
raw bytes and publishes an exact-byte canonical alias. Never-cut validation is
observational. Semantic-dedup coverage repair is likewise a formal DRIVER
work unit with exact pair/proposal inputs and one sidecar output; replay never
edits the model proposal.

## Run 72: one canonical transition, one transactional owner

Fresh real DODO Run 72 crossed the graph handoff, recon, breadth, rescan,
inventory, both semantic-invariant passes, the complete 15-job Depth fan-out
and DA iteration, attention repair, exploration, enumgap, axis coverage, and
application skepticism. It stopped at SC semantic dedup because a legacy raw
promotion bridge became a second writer over the canonical inventory triple.
The bridge appended 59 late actions, then correctly invalidated semantic
descendants—including the exact enumgap producer generation Gate P was about
to consume. Gate P consequently saw stale producer authority rather than a
content or syntax defect.

The correction is an ownership cutover, not another validator exception:

1. Accepted-depth finalization owns the depth-to-inventory transition.
2. Enumgap and axis own their typed action transitions.
3. Gate P's coupled successor owns remaining late registered actions before
   semantic dedup.
4. Semantic dedup owns the destructive precision transition.
5. Preverification freezes that exact post-dedup generation and may only
   derive queue projections from it.

There are now zero production calls to the raw promotion helper at semantic
dedup or the verify-queue boundary. A source-level invariant test prevents the
second-writer call pattern from returning. Phase-local delivery admission
recomputes current registered-action semantics from the exact source
denominator and current inventory; it does not compare against a superseded
pre-successor JSON/Markdown presentation receipt. The final preverification
transaction still publishes and strictly validates a fresh exact receipt for
downstream consumers.

Run 72 also exposed three neighboring denominator defects. Conditional output
absence is now compared with its exact committed `MISSING` plus
`NOT_TRIGGERED` state rather than being mislabeled sibling drift. The
edge-case depth role has an exact artifact-scoped namespace accepting its
native `DE-*` and storage-layout `SLS-*` identities without widening generic
depth producers. Gate P's 64-per-file and 512-per-run limits are explicit
denial-of-service bounds rather than hidden recall budgets; the real 53-action
application-skeptic artifact is admitted completely, while actual overflow
still produces a lower-bound shortfall receipt.

This matches the external systems pattern used by content-addressed build and
supply-chain protocols: semantic content is the durable identity; a committed
successor has one replayable owner; exact digests bind subjects and
provenance; physical inode/mtime observations remain epoch-local race checks.
Agent output is treated as a typed proposal, while deterministic code derives
routing, identifiers, digests, receipts, and successor state. Structured
output constraints reduce representational variance, but they do not replace
transactional ownership or current-state replay validation.

## Run 79/81: volatile ledgers, derived ID grammars, and one output contract

Run 79 proved that transaction bookkeeping must never become part of its own
semantic denominator. `_artifact_state.json` is still sealed and copied for
race detection, but PhaseIO and Gate P now exclude it from semantic inputs and
self-mutation comparison. The same run exposed valid DA2 carryover identities
whose grammar had drifted from the upstream depth-role manifests. The accepted
grammar is now derived from those manifests, including compact ordinal forms,
instead of being maintained as a second hand-written list.

Fresh real DODO Run 81 crossed both repaired boundaries. Gate P harvested the
registered depth actions, accepted their DA2 identities, and published a
761.7-KiB deduplicated inventory without a ledger mutation or ID rejection.
This is live successor replay, not a fixture-only result.

Run 81 also found a generation/validation contradiction in application
skepticism. Codex lacks terminal-negative authority in that workflow, so the
prompt and staged validator forbid `AGREE_NEGATIVE`; however, the packet's
strict JSON Schema still advertised that outcome. Two workers followed the
schema and were rejected after producing complete JSON. Provider-specific
schema projection now removes the forbidden branch before launch. The default
schema retains it for providers that possess that authority. Generation,
staged validation, and consumer loading therefore share one outcome contract
instead of relying on prose to narrow a broader schema.

This follows the Structured Outputs rule at the transaction boundary: encode
the actual allowed result in the schema, keep all fields required and closed,
and handle unsupported or incomplete outcomes explicitly. A validator remains
strict, but it must not contradict the schema shown to the producer.
