# Plamen RunBundle V2 R10 Authority Scope Implementation Shapes

Date: 2026-07-29
Status: SPEC ANALYSIS ONLY; SCOPE ADJUDICATION PENDING
Production edits: none

This artifact is ASCII only. It prepares two implementation shapes for the
R9-B01 authority question. It does not authorize implementation, cutover,
commit, push, provider work, benchmark claims, or audits.

## 0. Bound evidence

Governing blueprint:

`Downloads/Plamen_RunBundle_Evaluator_Implementation_Blueprint_2026-07-24.md`

Independent R9 review:

`plamen-codex-implementation/review_fixtures/runbundle_v2_independent_review_r9.md`

- whole-file SHA-256:
  `9f0b6080b51dc220913b4ee4943751a08b8738651cae35b2fa991129fe875f44`

Independent R10 fix design:

`plamen-codex-implementation/review_fixtures/runbundle_v2_r10_blocker_fix_design_20260729.md`

- whole-file SHA-256:
  `76c87aa0b6f464714e3c95f46cca093221db86b33819cbf86a8e1a688f017771`
- embedded payload SHA-256:
  `f7f89382fd3f820f65faf20a335c8c316d3808867d85b556c6f9929dec15489d`
- independently recomputed embedded hash: MATCH

Fixture-first evidence against exact R9:

- production: 4 failed, 58 deselected in 3.36s;
- neutral evaluator forgery conformance: 1 failed, 4 deselected in 2.96s;
- failures reproduce forged READY acceptance, silent direct/recovered cleanup
  debt, and non-idempotent RETIRED retry; and
- production runtime has not been edited after those red fixtures.

## 1. The scope conflict

The current exporter accepts only `USER_RUN` and `B0_LOCAL`. Its module
contract says those exports carry explicitly unauthenticated evidence and
cannot self-promote to B1.

The governing blueprint separately says:

- current unkeyed receipts remain useful integrity records for user runs;
- B1 additionally requires signed external preservation, launch, isolation,
  adjudication, and publication authorities;
- the USER_RUN path is user-owned and never `B1_ISOLATED`;
- external B1 authorities and keys are not locally implementable evidence;
  and
- local completion must never auto-promote a result to B1.

R9 nevertheless named an unkeyed sibling READY object the only production
harvest authority and claimed it could not be forged. That claim is false.
Canonical JSON and SHA-256 prove self-consistency, not who performed the
bounded observations.

The scope decision is therefore not whether a checksum can be strengthened.
It is whether every local export must acquire a distinct external signature,
or whether local integrity and governed publication authority must be
represented by different contracts and APIs.

## 2. Shape A - mandatory signed READY for every production export

### 2.1 Contract

Every direct or recovered export, including USER_RUN and B0_LOCAL, requires
an independently trusted publication-transition signer. No signer means no
READY and no successful production export.

READY v2 includes:

- schema and status;
- run ID and output basename;
- trust profile and unchanged publication ceiling;
- bundle seal and verification digest;
- exact public-case-lock digest;
- exact promotion transaction or journal digest;
- both bounded observations and their set digest;
- source-stability scope and claim limitation;
- exporter code and policy digests;
- publication-authority key ID and claim scope;
- semantic-body integrity digest; and
- domain-separated signature.

The exact public case lock adds a distinct publication-transition public key.
It must not reuse audit, allocation, run-context, isolation, adjudication, or
evaluator publication authority.

The signer capability remains outside:

- project root;
- scratchpad and report;
- output parent and RunBundle;
- staging and promotion journal; and
- ordinary environment variables or CLI private-key arguments.

A narrow OS-protected handle or external signing service is required. A raw
private key available to the arbitrary output-parent writer does not repair
R9-B01.

### 2.2 API shape

New concepts:

- `PublicationTransitionAuthority` public verification contract;
- `PublicationSigner` narrow signing protocol;
- `PublicationSignerUnavailableError`;
- signed `plamen.runbundle-publication-ready.v2`; and
- atomic same-parent no-replace publication of READY.

`export_materialized_payload`, `export_from_run`, and `recover_export` receive
or resolve a signer handle before mutation. They fail closed if it is absent,
wrong-keyed, unavailable, or returns an invalid signature. There is no
unsigned fallback.

`validate_publication_ready` remains structural. A separate authority
validator verifies:

- exact key ID and public key from the public lock;
- domain separator and signature algorithm;
- complete body signature;
- promotion transaction binding; and
- run/output/lock/seal/verification bindings.

`verify_export` accepts only signed READY v2. READY v1 is legacy,
non-authoritative, and rejected by the authoritative API.

### 2.3 Recovery implications

The signing service must be idempotent by promotion transaction ID:

- a retry returns the exact previously signed READY bytes; or
- it refuses a changed body for the same transaction.

An authenticated READY is checked before current source replay. Later source
drift does not invalidate its bounded observation claim. Missing or invalid
READY falls through to live recovery and requires a signer before completion.

### 2.4 Advantages

- Directly closes the exact forged READY counterexample, even if every public
  digest and the journal are recomputed or deleted.
- Supports the R9 hostile-output-parent authenticity claim.
- Gives one authoritative `verify_export` contract.
- Makes all materialized and live-source READY transitions equally
  authenticated.

### 2.5 Costs and risks

- Changes the documented USER_RUN/B0 availability contract.
- Makes ordinary local audits depend on external key provisioning.
- Adds key lifecycle, signer availability, rotation, revocation, ACL, service
  authentication, idempotency, and cross-OS integration.
- A signer callable by the same arbitrary writer is security theater.
- Passing private key bytes into the exporter is unacceptable.
- A signer that signs an unverified request merely authenticates the request,
  not that the observations occurred.
- Crash recovery requires durable external signer transaction state.
- The public-lock schema and every fixture/producer must change.
- Open-source offline operation becomes materially harder.
- Haltless behavior degrades unless unsigned output is explicitly retained as
  non-authoritative evidence.

### 2.6 When Shape A is required

Choose Shape A if the normative threat model requires a path-only
`verify_export` call to authenticate publication history against a malicious
writer with full write access to the output parent.

No unkeyed local design can satisfy that requirement.

## 3. Shape B - explicit local-integrity and governed-authority split

### 3.1 Contract

USER_RUN and B0_LOCAL retain an unkeyed local completion marker, but it is
never called publication authority and never raises the trust profile or
publication ceiling.

The local marker has an explicit schema and state such as:

- `plamen.runbundle-local-integrity-ready.v1`;
- `authority_class: UNAUTHENTICATED_LOCAL_INTEGRITY`;
- `claim_scope: HONEST_EXPORTER_BOUNDED_OBSERVATION_RECORD`;
- trust profile `USER_RUN` or `B0_LOCAL`;
- unchanged publication ceiling;
- bundle and bounded-observation integrity bindings; and
- an explicit statement that same-principal/output-parent writers can
  recreate it.

A separately signed governed acceptance receipt is required for any
authenticated publication claim. That receipt is created and verified by the
governed import/publication layer, not silently synthesized by the local
exporter.

### 3.2 API separation

Use different names and result types:

- `verify_local_export_integrity(...)` validates the bundle and local marker;
- `verify_governed_publication(...)` requires a separately trusted signed
  authority chain; and
- an existing `verify_export` name must either be removed, become an explicit
  local-integrity alias, or require a declared authority level. It must not
  ambiguously return "accepted."

The result carries:

- `integrity_state`;
- `authority_class`;
- `trust_profile`;
- `publication_ceiling`;
- `authenticated_publication: false` for local runs; and
- an optional governed authority receipt reference.

Security-sensitive callers request an explicit minimum:

`required_authority = LOCAL_INTEGRITY | SIGNED_TRANSITION | GOVERNED_B1`

There is no silent downgrade. If `SIGNED_TRANSITION` or `GOVERNED_B1` is
requested, an unsigned local marker is rejected.

The neutral evaluator continues to import sealed foreign content without
adopting local READY authority. Its governed publication gate separately
checks signed B1 evidence.

### 3.3 Optional signed transition within Shape B

Shape B can support the distinct signed READY v2 from Shape A when a local
publication-transition authority is provisioned. The important difference is
that unprovisioned USER_RUN/B0 remains explicitly local and usable rather than
pretending to be authenticated or failing all export.

The two artifacts must remain separate:

- local integrity marker: unkeyed, local, no authenticity;
- signed transition receipt: distinct external key, narrow
  `LOCAL_RUNBUNDLE_PUBLICATION_TRANSITION_ONLY` scope; and
- governed B1 publication receipt: separate B1 publication authority and
  complete external authority chain.

A signed local transition still cannot promote USER_RUN/B0 to B1.

### 3.4 Fixture disposition

The exact forged READY fixture remains a negative control for:

- `required_authority=SIGNED_TRANSITION`;
- governed publication verification; and
- any code path that claims the observations are authenticated.

The local-integrity verifier may accept a self-consistent marker only if its
result remains explicitly unauthenticated and cannot satisfy any
authoritative caller. Tests must prove:

- recomputed marker plus deleted journal still has no publication authority;
- no caller can confuse the local result with a signed result;
- trust profile and publication ceiling remain local;
- report/evaluator publication gates reject it as B1 evidence; and
- documentation never claims local marker unforgeability.

If the scope adjudicator requires the exact existing fixture to make
path-only `verify_export` reject, Shape B must rename or narrow that API and
make authoritative verification a different mandatory call. Relabeling the
same ambiguous result is insufficient.

### 3.5 Advantages

- Matches the blueprint's explicit USER_RUN/B0 versus external B1 split.
- Preserves offline and ordinary local audit usability.
- Avoids fake security from a key held by the same local principal.
- Makes trust claims mechanically visible in schemas, APIs, receipts, and
  CLI output.
- Allows governed deployments to add real signatures without coupling every
  open-source audit to external infrastructure.
- Keeps the evaluator's neutral content-import boundary clean.

### 3.6 Costs and risks

- Does not authenticate a local marker against a malicious same-privilege
  output-parent writer.
- Requires strict call-site migration so no consumer treats local integrity
  as publication authority.
- Two or three authority levels are more explicit but more complex.
- Existing `verify_export` terminology and the R9 handoff must be corrected.
- A boolean `ready=true` is too ambiguous and must not survive the split.
- If downstream code ignores `authority_class`, the old defect reappears as
  a semantic integration bug.

### 3.7 When Shape B is correct

Choose Shape B if the normative local threat model is integrity and
crash-recovery under an honest user-owned workspace, while authenticated
publication belongs to separately governed infrastructure.

That is the model stated by the current blueprint.

## 4. Common repair required under either shape

R9-B02 and R9-B03 do not depend on the scope decision.

### 4.1 Atomic control publication

READY/local-integrity, signed READY, RETIRED, failure, mutation, and cleanup
control files need an atomic same-parent no-replace file protocol:

1. create a fresh plain temporary sibling;
2. write all bytes and fsync the file;
3. promote using native no-replace semantics;
4. fsync the parent where supported;
5. reload exact final bytes; and
6. clean or report incomplete temporary debt without treating it as final.

A crash during `open(..., "xb")` on the final READY pathname must not leave a
partial final artifact.

### 4.2 Loud shared cleanup

One `_complete_promotion_cleanup` helper is shared by direct and recovery:

1. validate the authorized promotion transaction and journal path;
2. reload the accepted local or signed completion artifact;
3. unlink the exact journal if present;
4. verify absence;
5. durably persist the parent state; and
6. raise typed `RunBundleCleanupDebtError` on failure.

Ordering:

1. publish completion artifact;
2. reload and validate it;
3. set the internal accepted/verified state;
4. run cleanup;
5. return ordinary success only after cleanup succeeds.

Cleanup failure must not retire an already valid completion artifact. The
exception identifies the target, journal, transaction, and completion
receipt. A cleanup-only recovery validates the completion artifact first,
does not replay current sources, retries durable cleanup, and succeeds only
when cleanup completes.

### 4.3 Idempotent retirement

Replace fresh-write retirement with:

- `_load_or_create_publication_retirement`;
- `_validate_publication_retirement`;
- `_complete_retirement`; and
- topology classification before ordinary source recovery.

The first retirement receipt binds:

- output and run;
- original control receipt name and digest;
- exporter code and policy;
- retirement rule;
- exact bundle generation seal or verification digest;
- fixed original timestamp;
- retirement digest; and
- derived quarantine basename.

Retry loads and reuses exact existing bytes. It never generates a new
timestamp, digest, or quarantine path.

Topology rules:

| Target | Quarantine | Result |
|---|---|---|
| present | absent | validate generation; retry no-replace quarantine |
| absent | exact bound present | validate; retirement already complete |
| present | present | fail closed as ambiguous/collision |
| absent | absent | fail closed as lost/inconsistent |

Do not remove `SEALED.sha256` when quarantine fails. RETIRED is the deny
state, and the intact seal is needed to bind/recover the generation.

After quarantine, journal cleanup is a separate idempotent transition.

### 4.4 Crash matrix

Both shapes must test every durable prefix:

- before and after promotion journal durability;
- before and after directory promotion;
- between bounded observations;
- before, during, and after completion-artifact publication;
- before and after exact artifact reload;
- before unlink, after unlink, and before parent durability;
- after retirement receipt durability;
- before and after quarantine rename;
- before retirement postcondition verification;
- before journal cleanup after quarantine; and
- repeated recovery from every persisted state.

## 5. Decision matrix

| Criterion | Shape A | Shape B |
|---|---|---|
| Reject malicious output-parent READY forgery | yes, with genuinely external signer | no for local marker; yes for signed/governed verifier |
| Matches current USER_RUN/B0 blueprint | requires policy amendment | yes |
| Preserves offline local audit flow | no, unless signer is provisioned | yes |
| Prevents B1 self-promotion | yes if key scopes stay distinct | yes by explicit contract split |
| Key/service operational burden | high and mandatory | optional locally; mandatory only for governed claims |
| Cross-OS/open-source complexity | high | moderate |
| Single verification API | possible | unsafe; explicit authority APIs required |
| Exact R9 hostile-parent claim | satisfies | withdraws for local marker |
| Honest local crash recovery | satisfies | satisfies |
| External B1 publication security | necessary but not sufficient | separate governed chain; necessary authority remains external |

## 6. Recommendation subject to adjudication

The blueprint supports Shape B:

- keep USER_RUN/B0 local evidence explicitly unauthenticated;
- remove every claim that a local marker authenticates who performed source
  observations;
- make authority class and minimum required authority mandatory at every
  consumer boundary;
- add optional signed publication-transition receipts for deployments that
  actually possess a distinct signer; and
- keep governed B1 publication authority in the evaluator/governance layer.

Shape A is the only honest choice if path-only production verification must
resist a malicious output-parent writer for every local audit. If that threat
model is selected, the program must accept the external signer dependency and
must not implement a same-principal key as a cosmetic substitute.

The scope adjudicator should therefore answer one precise question:

Does `verify_export` mean local integrity completion in a user-owned
workspace, or authenticated publication history against a hostile writer of
that workspace?

Until that answer is GO/AMEND/BLOCK, production should remain unchanged.
