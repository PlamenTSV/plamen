# DODO run89 resume failure and cross-phase repair (2026-09-26)

Run89 (`e9350578-a31e-4b40-8c4d-4477325d3a5d`) was paused after 44/75
phase commits, during `sc_verify_low_a`. The public `plamen resume` command
found a finalized `SEMANTIC_DEDUP_TRANSACTION_*_RECORDS` event with no typed
descendants and no checkpoint acknowledgement. It treated the empty fan-out as
unknown coverage, removed all 44 completed phase commits, then failed recon
because recon prepass dispatch authority is new-run-only. No external input
drift was reported. The signed event's postimage matched the live
`finding_records.json` bytes. The resume also found `_artifact_state.json` at
33,686,873 bytes, above its 32 MiB read bound. Preserve run89 as failure
evidence; do not edit its checkpoint into apparent completion.

The immediate installed fix, generation
`cf818759c6d75fec7b9af16f2527f9777463a34b97182ace0aed580546c74465`,
raised the artifact ownership ledger's shared read/write bound to 128 MiB,
acknowledged changed semantic-dedup events at the owning phase commit, and
recognized an exact committed same-run semantic-dedup postimage at resume.
Run90 is a fresh real DODO Thorough/Codex audit on target commit
`d4834a468f7dad56b007b4450397289d4f767757`. It uses that installed
generation; do not replace the package while its driver is live.

Further source-only repair (not in run90's installed generation): the paired
transaction callback previously used `config.get` for its pending mutation
queue, silently dropping the first event when the queue was absent. It now
creates the queue at the producer boundary. Report transactions were the only
other direct semantic-event finalizers outside the ordinary driver helper.
Each signed report successor is now checked and acknowledged before a later
report rewrite can supersede its live postimage. Resume recognizes a fully
committed signed report transaction with empty fan-out as an in-run successor,
while ordinary unproven mutations still trigger conservative repair. Targeted
tests: 60 passed across resume, report producer handoff, and report mutation
transaction suites. Regenerate `toolchain_runtime_closure.v1.json` after any
further runtime-source change, then install only after the live run stops.

A wider 96-test semantic suite reported 81 passed / 15 failed. Thirteen
adversarial-fixture failures occur while arming an unowned raw input, before
the changed resume code is reached; one stale backend-policy fixture conflicts
with its own explicit `claude-headless`/`pty` settings, and one legacy L1
expectation no longer matches the current semantic successor. These are not
evidence that the new resume branch failed, but they remain test-debt and must
not be misreported as a green full suite.

Run90 reached `sc_verify_crithigh`. Verifier unit 0013 produced legitimate
Solidity harm and fuzz functions but wrote both names in the singular
`Test Function` display field, joined by `and`. The staged source bridge
rejected that metadata before publication; the driver's one bounded retry
succeeded. Source-only repair now accepts at most two joined function labels
only when both declarations exist in the exact fenced source. The executor's
existing parser deterministically selects the first harm test. This repair is
not in run90's installed generation; focused source-bridge plus resume/report
regressions pass (50 tests).

Medium verifier units exposed a second display shorthand,
`test_H12_and_fuzz_H12`, for source declarations `test_H12` and
`testFuzz_H12`, plus the prior plain-English two-name form. Both bounded
retries completed. The source bridge and executor parser now recognize only
the exact shared-ID shorthand and require both real declarations before
selecting the primary harm test. The verifier prompt explicitly requests a
single primary identifier. Focused tests now pass (51 tests).

One medium unit also attempted a terminal-negative verifier verdict while its
typed operator proposal retained method/context debt. The validator correctly
rejected that unproven negative before publication and scheduled the bounded
retry. Source-only generated verifier instructions now state the cross-field
rule explicitly: any BLOCKED operator or CONTEXT_UNRESOLVED context requires a
non-terminal CONTESTED verdict. The 83-test focused source suite passes; the
live retry outcome must be observed separately.

Architecture rationale: an event and checkpoint are two durable records, so
the crash gap must be handled by replayable, idempotent reconciliation rather
than interpreting an empty dependent set as corruption. The signed transaction
receipt supplies the exact pre/postimage authority; the checkpoint ack records
that the event was observed. This mirrors the transactional-outbox recovery
problem and idempotent request identity described by
[Microservices.io](https://microservices.io/patterns/data/transactional-outbox)
and the [AWS Builders' Library](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/).
