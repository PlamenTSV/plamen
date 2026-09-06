# Program Facts G3-00 parity launcher R3.11 closed-semantic native-profile amendment

Status: `NEW_ONLY_FROZEN_AUTHOR_SELF_REVIEW_READY_FOR_TWO_FRESH_INDEPENDENT_REVIEWS`

Disposition: `AUTHOR_FIXTURE_PASS_IS_NOT_INDEPENDENT_REVIEW_NATIVE_EVIDENCE_OR_ADMISSION_AUTHORITY`

Admission: `BLOCKED_PENDING_TWO_FRESH_INDEPENDENT_REVIEWS_HOST_NATIVE_EVIDENCE_AND_LATER_ADMISSION_BRIDGE`

R3.11 is a new-only successor to frozen R3.10. It changes no R3.10 or earlier
artifact. Its normative implementation family is
`Temp/program_facts_g3_launcher_r3_11_20260809/`. This amendment records a pure
Python/JSON design model and validator. It performs no native operation, worker
spawn, provider call, provisioning, installation, publication, commit, push,
cutover, or admission transition.

## 1. Normative repair inputs and advisory boundary

The two fresh R3.10 reviews are frozen `REPAIR` inputs, not PASS lineage:

| Input | SHA-256 | Disposition |
|---|---|---|
| `PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_10_STATE_OPERATIONAL_REVIEW_4c0c125b9b51a56a.md` | `e775a3f015a50d1b8f6e3b54f1c0ea9858aa2b4e77d755eea91f37cae977571f` | `REPAIR` |
| `PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_10_NATIVE_CONTRACT_REVIEW_4c0c125b9b51a56a.md` | `642a4788afe6c4f3343db383e54d791f0316d44df3841eb336a3ba53472a2236` | `REPAIR` |

The reviewed predecessor boundary is also pinned exactly:

| Input | SHA-256 |
|---|---|
| R3.10 amendment | `4c0c125b9b51a56a3bcc191654468c9f94b7e2f470483e713641074901a729c9` |
| R3.10 family manifest | `6cffa880db08a37b0087105d796c5907281c7114a4a46b8e3fefa7ce7b31ebcd` |
| R3.10 implementation handoff | `53290f0e3a788b730f18fa949a525cf467d56ffa6eec1061b7ee178ce5347ad7` |
| R3.8 predecessor roster | `a7ed6304dc1863719f62021152acf3e76e5961bebbc29f3385f05c46dc06f0cf` |
| R3.8 lineage roster | `b1aed55351a64a050275c259346623fac9a759a81aeac561b789b0b8877ea35d` |

The platform advice supplied to the author had no independent artifact or
hash. It is advisory input only. Its requested Linux, macOS, and Windows
properties become reviewable here because they are expressed in the externally
pinned contract and executable negatives; the advice itself is not treated as
authority or independent review.

## 2. Acceptance boundary

`r3_11_validator.py` accepts one bytes value and no case identifier or expected
answer. Its accepted language is deliberately small:

1. at most one terminal LF is transport-only; CR, NUL, and multiple terminal
   LF are forbidden;
2. a locally implemented strict canonical-JSON decoder rejects duplicate keys,
   floats, non-finite numbers, excess depth, excess collection work, and
   noncanonical encoding;
3. a locally implemented SHA-256 authenticates the contract and all governed
   subject domains;
4. all frozen predecessor, lineage, review, amendment, manifest, and handoff
   dependencies must match validator-compiled identities;
5. candidate dependency, conservation, lineage, review, authority, and complete
   semantic state must be recursively type/key/value equal to the external
   contract; and
6. every governed subject hash must verify before acceptance.

This intentionally replaces an open nested schema with an exact closed
semantic state. Pair-editing candidate fields cannot redefine accepted policy.
Candidate-local review nodes remain `PENDING`; their principals differ from the
author and cannot promote themselves to PASS.

The validator does not self-certify its own executable bytes or Python runtime.
The external R3.11 handoff pins the validator and manifest identities, and a
later governed launcher must pin the interpreter/runtime before starting a
fresh validator process for each governed candidate. The in-process dependency
cache is only a test-throughput optimization for an unchanged frozen set; it is
not permitted to cross a governed validation process boundary.

## 3. R3.10 state/schema repairs represented in R3.11

The successor encodes the following repair surfaces for fresh review:

- exact recursive types, keys, ordering, values, and multiplicity for every
  candidate-visible semantic object, including formerly encoded source/frame
  semantics;
- contract-derived platform, policy, profile, architecture, artifact, API,
  operation, result, and root values rather than mutually consistent candidate
  pairs;
- an exact bidirectional operation/root roster, exact completion class, exact
  occurrence count, and joined clone/reconciliation identity;
- exact review artifacts, reviewed-subject identity, `REPAIR` disposition,
  author/reviewer separation, and two non-authoritative pending R3.11 reviews;
- exact 2,227-row predecessor file and canonical row-stream identities;
- exact 67-row predecessor-lineage file and row-stream identities plus 67
  executable, fully resealed successor recipes with exact diagnostics;
- embedded canonical JSON and SHA-256 rather than imported `json`/`hashlib` in
  the acceptance validator; and
- one contract/executable resource policy: depth `64`, collection work
  `100,000`, and subject size `1,000,000` bytes.

The 67 recipes are conservation evidence, not 67 mutually distinct successor
properties: each predecessor atom is explicitly bound to one executable R3.11
negative from the 39-case semantic suite. Fresh reviewers must decide whether
those mappings are semantically adequate; their presence is not self-certified
restoration.

## 4. Linux native design profile

Only the exact Linux x86-64 and AArch64 profiles carry local
`POWER_LOSS_NAMESPACE_DURABILITY` in the synthetic design model. For each:

- source and destination parent directory FDs remain retained through
  validation, mutation, reconciliation, and barriers;
- `statx` `STATX_MNT_ID` and exact `st_dev` must be equal across both parents;
- create-only publication is `renameat2` with exactly `RENAME_NOREPLACE`
  (`flags_u32=1`), preserving both names/inodes if the target exists;
- replacement is `renameat2` with exactly `RENAME_EXCHANGE`
  (`flags_u32=2`) only under an OFD write lock and exact-name/inode
  validate-then-exchange;
- no fallback is allowed;
- staged files and bottom-up tree directories are fsynced before namespace
  mutation; and
- both retained parent directory FDs are fsynced after mutation.

An ambiguous/no-return result is reconciled from an independent exact
name-and-inode poststate. Replay is always false. The contract therefore
rejects different mount IDs despite equal `st_dev`, overwrite-on-target-exists,
ambiguous replay, and either missing parent-directory barrier.

This is synthetic design evidence only. No filesystem or kernel behavior was
executed or observed, and no global native/admission authority follows from the
two local design-profile booleans.

## 5. macOS and Windows native design profiles

macOS is exactly `UNAVAILABLE` before spawn. `RENAME_EXCL` and `F_FULLFSYNC`
are recorded only as insufficient substitutes; neither can create an accepting
platform instance.

Windows is exactly
`WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_V1` and never power-loss
authoritative. Its closed profile requires:

- an exact canonical protected-root path, owner SID, DACL digest, non-world-
  writable state, no reparse point, volume serial, root file ID, retained root
  handle ID, retained destination-directory handle ID, and no-follow reopen;
- staged `CREATE_NEW`, `FILE_FLAG_WRITE_THROUGH`, and `FlushFileBuffers`;
- `SetFileInformationByHandle` with information class `FileRenameInfoEx`, the
  documented `FILE_RENAME_INFO` request structure, flags exactly zero, a null
  root-directory member, the retained destination-directory identity, exact
  destination path, length excluding NUL, and zero-initialized tail; and
- a hard `PROCESS_CRASH_RECOVERY_ONLY` authority ceiling.

`FILE_RENAME_INFO_EX` is not an admitted type. `MoveFileExW`, `ReplaceFileW`,
`REPLACEFILE_WRITE_THROUGH`, and directory-flush assumptions are forbidden.
Target-exists overwrite, nonzero flags, power-loss requests, unnamed durability
primitives, and owner/DACL/reparse/root-ID drift are executable negatives.

## 6. Failure, degradation, and authority ceiling

All global authority values are literal false. Evidence mode is
`SYNTHETIC_DESIGN_MODEL_ONLY`; the claim ceiling is
`NO_HOST_NATIVE_NO_PROVIDER_NO_ADMISSION`. Linux local design-profile acceptance
cannot promote these global fields.

Malformed, noncanonical, over-depth, over-work, or over-size candidate inputs
return deterministic rejection. Missing or mismatched governed dependencies
return dependency rejection; bounded unexpected validation exceptions return
`INTERNAL_DEBT / FAIL_CLOSED_VALIDATION_EXCEPTION`. None grants authority and
none halts the surrounding pipeline by design.

The family grants no native-execution, provider, worker-spawn, publication,
installation, cutover, or admission capability. Host-native proof and a later
admission bridge remain separate work.

## 7. Fixture-first and executable evidence

The RED boundary was frozen before the R3.11 successor:

- exact old model SHA-256:
  `a7bc8e35bd577a869c5f140b7f4390e162263f546e4b75cf330a0b89b7e7dc6c`;
- exact old validator SHA-256:
  `e6285a56efb92714bad21d0c87e2836fc8f856e5c53ccf2093cc975405e0a32a`;
- 24 distinct fully resealed accepted-invalid candidates; and
- frozen RED artifact SHA-256:
  `0220269c91f2dd5e17fa9205895375dca338baf1a10669cb9172295f3877f2bd`.

R3.11 rejects 39 distinct fully resealed semantic candidates at exact expected
primary/subcode pairs. The 67 lineage recipes execute against the successor
validator. Parser, transport, resource, dependency-read, embedded-hash,
platform-positive, all-global-false, and manifest-identity tests are included.

Exact author commands and results:

```text
python Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_red_against_r3_10.py --write
24 / 24 accepted-invalid rows frozen

python Temp/program_facts_g3_launcher_r3_11_20260809/materialize_r3_11.py
baseline accepted; RED 24; GREEN 39; lineage recipes 67

python -m pytest -q -p no:cacheprovider Temp/program_facts_g3_launcher_r3_11_20260809/test_r3_11_contract.py --tb=short
57 passed
```

These are author evidence, not independent certification.

## 8. Frozen family identities

Every listed family asset has final LF and zero CR. The manifest lists the 14
other family assets and intentionally does not self-pin; this amendment and the
external handoff pin the manifest.

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `build_r3_11_lineage_recipes.py` | 2,937 | `484521029b1252e8f0685a24d2b693f6feb6f5461cffed8bc82cffdf9b448f35` |
| `materialize_r3_11.py` | 8,377 | `15cd84c1460568b128bcfc67b95079b4ec565deaf611162e994a6415e36e4b92` |
| `r3_11_accepted_baseline.v1.json` | 15,219 | `5d11cf2859b45e3c5d33a700b66614efe8a791ab15e64a3e90ddc8ef54787477` |
| `r3_11_contract.v1.json` | 13,942 | `bccff97f0beb7b08c8dadba2ea3aacc212485dbfedccbb5621a1d4092e0e0b9e` |
| `r3_11_contract_source.py` | 14,900 | `baff6c365ab5fe71c9161d6469d96aeb36e0f48b1a0d792a6be7b0dbf716e902` |
| `R3_11_FIXTURE_FIRST_RECEIPT.md` | 2,340 | `30ed54e67e126a6f4e3eba2a8671de32b79c4bf16f3d3f3f046e1f491edec2ca` |
| `r3_11_identity_manifest.v1.json` | 3,782 | `e2dc9ce6c2f423021dbf11f5b66b33becf57dbefcd5e6d5bf206e8958697be96` |
| `r3_11_lineage_recipes.v1.json` | 40,388 | `29dc8afa8c6c5b7550527af2ef41b3fbecbf008126f8a463081a282aeb17d903` |
| `r3_11_model.py` | 3,122 | `a954e39d53e162407d8371bba13093107329e6b512274b545c0df75af1492e35` |
| `r3_11_mutation_results.v1.json` | 15,407 | `3bdd1b98e0929c21c8622eae39c1bc037b0f57057276f0a194d62f14e3b8d48d` |
| `r3_11_mutations.py` | 12,814 | `9f29d819cd1fac4d3dae9049631680a3dfed51b6b5c96f6361fa067104908f23` |
| `r3_11_red_against_r3_10.py` | 17,568 | `25b522ee27646cd3e370212cb26db97d2168bb5ed82d02e1dcd3c69e4bf0f7a7` |
| `r3_11_red_against_r3_10.v1.json` | 5,935 | `0220269c91f2dd5e17fa9205895375dca338baf1a10669cb9172295f3877f2bd` |
| `r3_11_validator.py` | 24,000 | `be60449c2c936e86422bc69eb9e6cce3b9b92c8e0b0a948d3e35ebb408cf5b38` |
| `test_r3_11_contract.py` | 8,350 | `295f156347f6b3abf82dd6c835202aaa077ead8fe1fa7272016f66027d4f701d` |

## 9. Required independent review boundary

Stop at this exact byte set for two fresh reviewers who did not author R3.11:

1. state/schema/operational review: replay every identity, all 24 REDs, all 39
   semantic negatives, all 67 lineage recipes, strict parser/resource bounds,
   recursive exactness, dependency closure, review independence, and the
   external executable/interpreter boundary; and
2. native/platform/authority review: challenge the precise Linux flags,
   serialization, mount/handle/barrier/reconciliation contract; macOS
   unavailability; Windows protected-root/process-crash contract; all-local
   versus all-global authority; and synthetic-only claim ceiling.

Neither reviewer may infer host-native correctness from fixture acceptance.
No production/native/provider/admission cutover is authorized at this boundary.
