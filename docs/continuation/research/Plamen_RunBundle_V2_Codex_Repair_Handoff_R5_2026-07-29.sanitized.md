# RunBundle V2 R3-blocker repair handoff R5

Date: 2026-07-29  
Author role: repair implementer; **not** acceptance authority  
Disposition: **IMPLEMENTATION COMPLETE — INDEPENDENT BLOCKING RE-REVIEW REQUIRED**  
Claim scope: local implementation, deterministic replay, packaging, and fixture validation only  
B1 effectiveness claim: **NONE**

## 0. Incoming blocked boundary

The implementation in this handoff responds to:

`<LOCAL_USER_ROOT>\plamen-codex-implementation\review_fixtures\runbundle_v2_independent_review_r3.md`

SHA-256:

`a5f9e7028103005cf73a5f16bca49cfe01d3731df8737dafb66e0c09b20b3228`

The independent R3 disposition was `BLOCK` for two residual defects:

1. Pashov retained-byte lineage and derived projections could be forged after
   recomputing every public digest.
2. A schema-valid `first_occurrence_id` could appear in visible prose because
   the blind identity universe was inferred from incomplete key-name matching.

The repair author does not clear either blocker. This document submits a new
exact boundary for an independent adversarial verdict.

Repository HEADs remain context only because both trees are shared and dirty:

| Repository | HEAD |
|---|---|
| production | `67a0f85adc7a8169d79a286908b00bef7adb764a` |
| evaluator | `345d016d0c86b6201e90cec908c37c6a66f739c3` |

## 1. Fixture-first evidence

Before runtime changes:

- the Pashov adversarial suite changed byte ranges/digests, candidate IDs,
  titles, descriptions, severity, debts, occurrence IDs, event counts, report
  severity, and normative ordering, then recomputed the adapter payload,
  adapter receipt, and outer receipt digests;
- all **11** forged variants were accepted, so the new tests failed as
  intended;
- a schema-valid canonical candidate with
  `first_occurrence_id = occurrence-secret` and visible title containing that
  value rendered successfully, so the privacy test failed as intended.

Those exact tests are green only after the repairs below.

## 2. B04 retained-byte replay closure

### Single derivation authority

`src/plamen_eval/adapters/pashov_v3.py` now exposes one pure
`replay_pashov_v3()` derivation. The producer and semantic validator use that
same deterministic parser over one immutable `CapturedInventory`.

It derives, in one authority:

- exact source byte ranges and record digests;
- candidate IDs, titles, descriptions, severities, and quality debts;
- candidate and occurrence ordering;
- occurrence rows and alias-edge roster;
- debt rows;
- event rows; and
- final-report projection rows.

The CLI invokes that replay once for every emitted projection. The validator
reconstructs the inventory from retained base64 bytes and requires exact
structural equality for all six derived projection families. A re-signed false
assertion is therefore rejected because it differs from replayed bytes, not
because an unkeyed digest changed.

### Pin and public-case-lock authority

The parse receipt now requires `public_case_lock_b64`, containing the exact
canonical public case-lock bytes. Validation:

1. strictly decodes canonical JSON;
2. validates it as `plamen.public-case-lock.v2`;
3. recomputes both raw-file and canonical-value digests;
4. reconstructs the adapter pin from authenticated receipt metadata;
5. recomputes the pin digest;
6. requires that digest in the retained case lock's allowed-document roster;
7. recomputes diagnostics and the inventory roster; and
8. replays the pinned parser over retained artifacts.

The schema remains closed. Legacy receipts without retained case-lock bytes
fail closed; a dedicated migration/error fixture proves there is no permissive
fallback.

### B04 focused result

`tests/test_pashov_v3_adapter.py`: **25 passed**

Coverage includes the original one-capture/TOCTOU tests, 11 re-signed derived
projection forgeries, pin-metadata and case-lock-authority mutations, row
reordering, and the legacy-receipt migration boundary.

## 3. B05 schema-authoritative identity closure

### Complete candidate-set input

Blind rendering no longer accepts an unbound candidate array. It requires and
validates the complete:

`plamen.real-audit-candidate-set.v2`

document, including wrapper-level `run_id`. The CLI rejects legacy bare arrays;
this is locked by an explicit migration/error fixture.

### Versioned identity-path policy

The identity authority is now:

`plamen.blind-identity-path-policy.v1`

The exact policy covers:

- `run_id`;
- candidate and first-occurrence IDs;
- every native candidate ID;
- producer adapter, work-unit, artifact, and record IDs;
- every location source-record ID;
- every evidence reference;
- severity authority-receipt ID; and
- audit-cluster ID.

Case identity is supplied separately. Validated private-case context,
comparison/adapter identity contexts, and explicit confidential identities are
merged before rendering. Existing substring-based discovery remains only
defense in depth; it is not the identity authority.

Unknown candidate-set schema versions fail closed if no matching policy exists.
The private map binds:

- identity-policy version;
- identity-policy SHA-256;
- the sorted unique private-token roster; and
- private-token-set SHA-256.

Unblinding revalidates those bindings and re-scans the final public packet.

### B05 focused result

Blinding, schema, and CLI subset: **33 passed**

Fixtures cover every canonical identity path, wrapper `run_id`,
`first_occurrence_id`, normalized representations, cross-leaf fragmentation,
external contexts, unknown schema versions, random keyed case commitments,
policy/token-map tampering, and legacy-array rejection.

## 4. Exact R5 freeze authority

Manifest:

`<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R5_2026-07-29.json`

| Binding | Value |
|---|---|
| Raw manifest SHA-256 | `ca2cd67231ef375098ad17d6b8c10fb7eeda7cb25296962f0e3f31a862e9822a` |
| Embedded canonical self-digest | `5090a614e2e3394e55433037bad6798e290f840331e3015da267c18db2f29b4d` |
| Schema | `plamen.runbundle-v2-local-freeze.v2` |
| Claim scope | `LOCAL_IMPLEMENTATION_AND_FIXTURE_VALIDATION_ONLY` |
| `not_B1_effectiveness_evidence` | `true` |

Final replay:

```json
{"freeze_manifest_sha256":"5090a614e2e3394e55433037bad6798e290f840331e3015da267c18db2f29b4d","status":"REPLAYED"}
```

### Source/API/protocol hashes

| Source set | Files | Tree SHA-256 |
|---|---:|---|
| production runtime | 7 | `89f8b180f421c5079bb35b5fe21227778a8a9a57c4d4cd80da5697f0a93c53e2` |
| production tests | 6 | `31be45ad9521c54feefb80ff2da289be0d1453780450867fd4c75069f7266e67` |
| evaluator source | 28 | `56b1ca75d0532557c865a10c2e83e8bc3927640bf1cbd440d93285a70b1d2210` |
| evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| evaluator tests | 29 | `10bfd436291d6aed1605cdf75bf64c6ab7996f2d8cdb97dfcbdb0503e0a5bbe4` |
| evaluator packaging | 2 | `a3621c2063bed999b412613eb6157c7faaab9b64bf11fdc2b665c059cce1b765` |
| freeze tooling | 2 | `f671a36b95190c07d9a1b69fcc4836f4c6b9022c52139d8592e78a2645b4924b` |

| Public API | Symbols | SHA-256 |
|---|---:|---|
| production runtime | 107 | `dd507961432faa427d6a20f917ea78dabb6aa08e42e246357fbb673a48e664a3` |
| evaluator source | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

Protocol hashes are unchanged:

- smart-contract: `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae`
- L1: `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`

## 5. Immutable wheels

### Incoming R3 wheel, preserved unchanged

`dist/frozen-v2/plamen_eval_control-0.2.0-py3-none-any.whl`

SHA-256:

`b51883f100137115523794561711132a7040526d4e27df58d9fd2460fc09fb67`

### R5 source wheel

`dist/frozen-v4/plamen_eval_control-0.2.0-py3-none-any.whl`

| Binding | Value |
|---|---|
| SHA-256 | `19023fba9fbf4f786b185c50a6de495cecb976bed278e84faa0e873064d8b1fd` |
| Size | 159,828 bytes |
| Members | 80 |
| Member-roster SHA-256 | `f261c5781075b551a116036734b023343a813c86ded0b8d84adac900281f88ca` |

The freeze-replay test built two independent external clean copies and both
matched this exact preserved wheel. The R3 wheel was not overwritten.

The exact V4 wheel was installed offline with `--no-index --no-deps` into a
fresh environment and invoked with `python -I`, empty `HOME`/`USERPROFILE`,
`PYTHONNOUSERSITE=1`, and no `PYTHONPATH`. Version `0.2.0`, evaluator modules,
and all 47 installed schemas loaded from the isolated environment. The
temporary environment was removed after verification.

## 6. R5 repair-file hashes

Paths are relative to `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`.

| File | SHA-256 |
|---|---|
| `src/plamen_eval/adapters/pashov_v3.py` | `38b0a772f2c936818eda27d43ce2cc2878011c692148c9230ef7407b2e1ce52a` |
| `src/plamen_eval/contracts.py` | `4e8910b9581b0ccfd8bfdde47b431af26643a8541a6a1db710989f46cbf75a4f` |
| `src/plamen_eval/cli.py` | `716659a54554f5632b291498da1d9fd2c1f768395b1b92a8235a8deb779de25b` |
| `src/plamen_eval/blinding.py` | `b38c66124fd532fa31562d875c9b25ac61d339ba55d723faa575a3b2669af367` |
| `schemas/pashov_v3_parse_receipt.v1.schema.json` | `766bd84bcb239aa22a4cd23ed7065328fc947cf2e2b5032a53604dadf44500d2` |
| `tests/test_pashov_v3_adapter.py` | `72a5393cffc7fb390fa4337668d4212da5442b3048ebeada4638b6021676d687` |
| `tests/test_real_v2_blinding_comparison.py` | `c1aefb5114aedf24ab573d033c8cbf7e304ecc78c3d2cb8e728df15e667f8680` |
| `tests/test_real_v2_cli.py` | `92ac0a01a35cab20066d097234dd8932a11a9ea42b52301b52e5f9502f01bab8` |
| `tools/runbundle_v2_freeze.py` | `ceba104b3685d67adcd3fb7ce39febce7e1c42e9ddf6f551af6dc3cbf4293517` |
| `docs/runbundle-v2-freeze.md` | `19d4158600743a6cd40b33172bab9c1aca9a0df4c337d3f1d0113a6369c4c393` |

The unchanged freeze-replay test remains:

`tests/test_runbundle_v2_freeze_replay.py`

SHA-256:

`bbe629252b4b8b7f1f9baadb4942323da443cf6b893890cadddd064350be4d79`

## 7. Final validation denominators

| Validation | Result |
|---|---:|
| Pashov replay/authority focused | **25 passed** |
| Blinding + schema + CLI focused | **33 passed** |
| Full neutral evaluator | **202 passed, 6 subtests passed** |
| Production RunBundle exact six-file suite | **509 passed** |
| Production Python packaging contract | **2 passed** |
| Public packaging/fresh-archive suite | **7 passed** |
| Cross-OS/toolchain pre-handoff gate | **22 passed** |
| Native Windows alias focus | **3 passed, 10 deselected** |
| V4 double-clean-build equality | **PASS** |
| V4 isolated offline install/import | **PASS** |
| R5 exact freeze replay | **REPLAYED** |
| `git diff --check` | **PASS**; only pre-existing line-ending warnings |

No production RunBundle source changed in this R3-to-R5 repair. Its exact
source/test aggregates and all 509 tests remain unchanged.

## 8. Required independent re-review

The reviewer should not use this author's conclusions as the oracle. Please:

1. verify the R5 raw hash and embedded self-digest;
2. replay all source, API, protocol, key-file, tool, and wheel preimages;
3. independently mutate every Pashov-derived field, retained source range,
   projection roster, order, pin field, and retained case-lock binding, then
   recompute all public digests;
4. independently enumerate identity-bearing paths from the canonical
   candidate-set schema and diff that universe against the versioned policy;
5. attack normalization, formatting characters, fragmentation, cross-leaf
   assembly, private-context omission, policy-map tampering, and wrapper IDs;
6. repeat double clean builds and isolated-wheel installation;
7. verify that both the R3 and V4 wheel artifacts remain exact and distinct;
8. issue a new hash-stamped blocking disposition.

No commit, push, merge, cutover, provider run, benchmark campaign, or live
audit was performed or authorized. B1 effectiveness and audit-quality claims
remain outside this local structural handoff.
