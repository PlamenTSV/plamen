from __future__ import annotations

from dataclasses import replace
import hashlib
from collections.abc import Iterator, Mapping

import pytest

from program_facts_provider_api import (
    FactContribution,
    ParsedProviderOutput,
    ProgramFactsProvider,
    ProgramFactsProviderAPIError,
    ProviderSourceInputSnapshot,
    ProviderResult,
    ZeroPositiveAccounting,
    replay_provider_source_input_snapshot,
    snapshot_provider_source_inputs,
    validate_fact_contribution,
    validate_parsed_provider_output,
    validate_provider_result,
)
from test_program_facts_provider_api import (
    H7,
    PFB,
    _contribution,
    _plan,
    _resources,
    _result,
)


RAW = b'{"facts":[],"nodes":[]}\n'


def _parsed_output(plan) -> ParsedProviderOutput:
    result = _result(plan, RAW)
    return ParsedProviderOutput(
        result=result,
        parsed_payload_schema="fixture.parsed_program_facts.v1",
        parsed_payload={
            "nodes": [],
            "occurrences": [],
            "facts": [],
            "detailed_debt": [],
        },
    )


def _empty_contribution(plan, result: ProviderResult) -> FactContribution:
    zero = ZeroPositiveAccounting(
        capability_id="fixture.calls.v1",
        result_digest=result.result_digest,
        source_authority_digest=result.source_authority_digest,
        denominators=(
            {
                "build_variant_id": PFB,
                "denominator_kind": "fixture.call_sites.v1",
                "denominator_ids": [],
            },
        ),
    )
    return FactContribution(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        result_digest=result.result_digest,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        build_variant_ids=(PFB,),
        capability_ids=("fixture.calls.v1",),
        nodes=(),
        occurrences=(),
        facts=(),
        debt_codes=(),
        capability_accounting=(
            {
                "capability_id": "fixture.calls.v1",
                "disposition": "PARSED",
                "emitted_fact_ids": [],
                "debt_codes": [],
                "zero_positive_accounting": zero.to_dict(),
            },
        ),
    )


def _validate_empty(contribution: FactContribution):
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan, RAW)
    return validate_fact_contribution(
        contribution,
        plan=plan,
        result=result,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=RAW,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )


def _contribution_from_wire(value: dict[str, object]) -> FactContribution:
    return FactContribution(
        audit_run_id=value["audit_run_id"],
        methodology_authority_digest=value["methodology_authority_digest"],
        registry_digest=value["registry_digest"],
        context_digest=value["context_digest"],
        source_manifest_digest=value["source_manifest_digest"],
        source_authority_digest=value["source_authority_digest"],
        plan_id=value["plan_id"],
        result_digest=value["result_digest"],
        provider_id=value["provider_id"],
        provider_run_id=value["provider_run_id"],
        build_variant_ids=tuple(value["build_variant_ids"]),
        capability_ids=tuple(value["capability_ids"]),
        nodes=tuple(value["nodes"]),
        occurrences=tuple(value["occurrences"]),
        facts=tuple(value["facts"]),
        debt_codes=tuple(value["debt_codes"]),
        capability_accounting=tuple(value["capability_accounting"]),
    )


def test_parsed_output_is_stateless_immutable_and_raw_replayable() -> None:
    _registry, _context, _observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    output = _parsed_output(plan)

    replayed = ParsedProviderOutput.from_bytes(output.canonical_bytes())
    validated = validate_parsed_provider_output(
        replayed,
        raw_output=RAW,
        plan=plan,
        expected_result=output.result,
    )

    assert validated.to_dict() == output.to_dict()
    assert validated.parsed_payload["nodes"] == ()
    with pytest.raises(TypeError):
        validated.parsed_payload["nodes"] = ("forged",)


@pytest.mark.parametrize(
    "mutation, match",
    [
        (
            lambda value: value["parsed_payload"].update({"nodes": ["forged"]}),
            "payload.*digest|carrier.*digest",
        ),
        (
            lambda value: value.update({"parsed_payload_digest": "f" * 64}),
            "payload.*digest",
        ),
        (
            lambda value: value["result"].update(
                {"source_authority_digest": "f" * 64}
            ),
            "result digest|source|carrier",
        ),
        (
            lambda value: value["result"].update(
                {"result_digest": "f" * 64}
            ),
            "result digest|carrier",
        ),
    ],
)
def test_parsed_output_rejects_payload_hash_source_and_result_mutation(
    mutation,
    match: str,
) -> None:
    plan = _plan()[3].plan
    assert plan is not None
    forged = _parsed_output(plan).to_dict()
    mutation(forged)
    with pytest.raises(ProgramFactsProviderAPIError, match=match):
        ParsedProviderOutput.from_dict(forged)


def test_parsed_output_rejects_wrong_raw_plan_source_and_expected_result() -> None:
    plan = _plan()[3].plan
    assert plan is not None
    output = _parsed_output(plan)

    with pytest.raises(ProgramFactsProviderAPIError, match="raw output"):
        validate_parsed_provider_output(
            output,
            raw_output=b'{"different":true}\n',
            plan=plan,
            expected_result=output.result,
        )

    with pytest.raises(ProgramFactsProviderAPIError, match="source|plan"):
        validate_parsed_provider_output(
            output,
            raw_output=RAW,
            plan=replace(plan, source_authority_digest=H7),
            expected_result=output.result,
        )

    different_result = replace(
        output.result,
        raw_output_sha256=hashlib.sha256(b"different").hexdigest(),
        raw_output_size=len(b"different"),
    )
    with pytest.raises(ProgramFactsProviderAPIError, match="expected result"):
        validate_parsed_provider_output(
            output,
            raw_output=RAW,
            plan=plan,
            expected_result=different_result,
        )


def test_exact_empty_denominator_is_accounted_without_negative_authority() -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan, RAW)
    contribution = _empty_contribution(plan, result)

    validated = validate_fact_contribution(
        contribution,
        plan=plan,
        result=result,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=RAW,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )

    row = validated.capability_accounting[0]["zero_positive_accounting"]
    assert row["denominators"][0]["denominator_count"] == 0
    assert row["authority"] == {
        "semantic_authority": "ACCOUNTING_ONLY",
        "terminal_negative_authority": False,
        "can_suppress": False,
        "can_demote": False,
        "can_refute": False,
        "can_mark_examined": False,
        "can_certify_clean": False,
    }


@pytest.mark.parametrize(
    "mutate, match",
    [
        (
            lambda zero: zero["denominators"][0].update(
                {"denominator_digest": "f" * 64}
            ),
            "denominator digest",
        ),
        (
            lambda zero: zero.update({"result_digest": "f" * 64}),
            "result",
        ),
        (
            lambda zero: zero.update({"source_authority_digest": "f" * 64}),
            "source",
        ),
        (
            lambda zero: zero.update(
                {"capability_id": "fixture.other.v1"}
            ),
            "capability",
        ),
        (
            lambda zero: zero["denominators"].append(
                dict(zero["denominators"][0])
            ),
            "build.variant|sorted|unique|total",
        ),
        (
            lambda zero: zero["authority"].update(
                {"can_certify_clean": True}
            ),
            "authority",
        ),
    ],
)
def test_forged_zero_positive_accounting_is_rejected(
    mutate,
    match: str,
) -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan, RAW)
    contribution = _empty_contribution(plan, result).to_dict()
    zero = contribution["capability_accounting"][0][
        "zero_positive_accounting"
    ]
    mutate(zero)
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match=(
            f"{match}|accounting digest|denominator digest|"
            "build.variant|sorted|unique"
        ),
    ):
        forged = _contribution_from_wire(contribution)
        validate_fact_contribution(
            forged,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=RAW,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


@pytest.mark.parametrize("field", ["result_digest", "source_authority_digest"])
def test_internally_valid_zero_accounting_cannot_rebind_parent(
    field: str,
) -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan, RAW)
    contribution = _empty_contribution(plan, result).to_dict()
    kwargs = {
        "capability_id": "fixture.calls.v1",
        "result_digest": result.result_digest,
        "source_authority_digest": result.source_authority_digest,
        "denominators": (
            {
                "build_variant_id": PFB,
                "denominator_kind": "fixture.call_sites.v1",
                "denominator_ids": [],
            },
        ),
    }
    kwargs[field] = "f" * 64
    contribution["capability_accounting"][0][
        "zero_positive_accounting"
    ] = ZeroPositiveAccounting(**kwargs).to_dict()
    forged = _contribution_from_wire(contribution)
    with pytest.raises(ProgramFactsProviderAPIError, match=field.split("_")[0]):
        validate_fact_contribution(
            forged,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=RAW,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_disappearance_still_requires_fact_debt_or_exact_zero_accounting() -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan, RAW)
    vanished = _empty_contribution(plan, result).to_dict()
    del vanished["capability_accounting"][0]["zero_positive_accounting"]
    contribution = _contribution_from_wire(vanished)
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match="disappeared|zero-positive|emitted facts|debt",
    ):
        validate_fact_contribution(
            contribution,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=RAW,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_legacy_provider_and_positive_contribution_remain_compatible() -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan)

    class LegacyProvider:
        def plan(self, _context):
            return plan

        def parse_raw(self, raw, _plan):
            return _result(plan, raw)

        def normalize(self, provider_result, _plan):
            return _contribution(plan, provider_result, precision="EXACT")

    legacy = LegacyProvider()
    assert isinstance(legacy, ProgramFactsProvider)
    contribution = legacy.normalize(legacy.parse_raw(b'{"facts":[]}\n', plan), plan)
    assert "zero_positive_accounting" not in (
        contribution.to_dict()["capability_accounting"][0]
    )
    assert validate_fact_contribution(
        contribution,
        plan=plan,
        result=result,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=b'{"facts":[]}\n',
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    ).to_dict() == contribution.to_dict()


class _SplitViewSourceBytes(Mapping[str, bytes]):
    def __init__(self, checked: bytes, used: bytes) -> None:
        self.checked = checked
        self.used = used
        self.iterations = 0
        self.item_reads = 0
        self.get_reads = 0
        self.values_reads = 0

    def __iter__(self) -> Iterator[str]:
        self.iterations += 1
        yield "PFS-" + "a" * 24

    def __len__(self) -> int:
        return 1

    def __getitem__(self, key: str) -> bytes:
        assert key == "PFS-" + "a" * 24
        self.item_reads += 1
        return self.used

    def get(self, key: str, default=None):
        self.get_reads += 1
        return self.checked if key == "PFS-" + "a" * 24 else default

    def values(self):
        self.values_reads += 1
        return (self.checked,)


class _OneReadMapping(Mapping[str, object]):
    def __init__(self, value: Mapping[str, object]) -> None:
        self._value = dict(value)
        self.iterations = 0
        self.reads = 0

    def __iter__(self) -> Iterator[str]:
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("caller mapping was read more than once")
        yield from self._value

    def __len__(self) -> int:
        return len(self._value)

    def __getitem__(self, key: str) -> object:
        self.reads += 1
        return self._value[key]


def test_source_boundary_snapshot_collapses_split_view_to_one_exact_read() -> None:
    checked = b"contract A {}\n"
    used = b"contract B {}\n"
    split = _SplitViewSourceBytes(checked, used)

    snapshot = snapshot_provider_source_inputs(
        source_bytes_by_id=split,
        source_manifest={
            "eligible_files": [
                {
                    "source_file_id": "PFS-" + "a" * 24,
                    "byte_count": len(checked),
                    "sha256": hashlib.sha256(checked).hexdigest(),
                }
            ]
        },
        build_inputs={"build_variant_ids": [PFB]},
    )

    assert isinstance(snapshot, ProviderSourceInputSnapshot)
    assert snapshot.source_bytes_by_id["PFS-" + "a" * 24] == used
    assert split.item_reads == 1
    assert split.get_reads == 0
    assert split.values_reads == 0
    assert replay_provider_source_input_snapshot(snapshot).binding_digest == (
        snapshot.binding_digest
    )
    assert split.item_reads == 1
    assert split.get_reads == 0
    assert split.values_reads == 0


def test_source_boundary_snapshot_survives_post_capture_nested_mutation() -> None:
    source_id = "PFS-" + "a" * 24
    original = b"contract A {}\n"
    source_bytes = {source_id: original}
    nested_manifest = {
        "eligible_files": [
            {
                "source_file_id": source_id,
                "byte_count": len(original),
                "sha256": hashlib.sha256(original).hexdigest(),
            }
        ]
    }
    nested_build = {
        "variants": [{"build_variant_id": PFB, "sources": [source_id]}]
    }
    manifest_once = _OneReadMapping(nested_manifest)
    build_once = _OneReadMapping(nested_build)
    snapshot = snapshot_provider_source_inputs(
        source_bytes_by_id=source_bytes,
        source_manifest=manifest_once,
        build_inputs=build_once,
    )
    before = snapshot.binding_digest

    source_bytes[source_id] = b"contract B {}\n"
    nested_manifest["eligible_files"][0]["sha256"] = "f" * 64
    nested_build["variants"][0]["sources"].clear()

    replayed = replay_provider_source_input_snapshot(snapshot)
    assert replayed.binding_digest == before
    assert replayed.source_bytes_by_id[source_id] == original
    assert replayed.source_manifest["eligible_files"][0]["sha256"] == (
        hashlib.sha256(original).hexdigest()
    )
    assert replayed.build_inputs["variants"][0]["sources"] == (source_id,)
    assert manifest_once.iterations == 1
    assert build_once.iterations == 1
    with pytest.raises(TypeError):
        replayed.source_bytes_by_id[source_id] = b"forged"
    with pytest.raises(TypeError):
        replayed.source_manifest["eligible_files"][0]["sha256"] = "f" * 64


def test_source_boundary_snapshot_rejects_duplicate_or_nonbyte_source_view() -> None:
    class DuplicateItems(Mapping[str, bytes]):
        def __iter__(self) -> Iterator[str]:
            yield "PFS-" + "a" * 24

        def __len__(self) -> int:
            return 1

        def __getitem__(self, key: str) -> bytes:
            return b"ok"

        def items(self):
            return (
                ("PFS-" + "a" * 24, b"first"),
                ("PFS-" + "a" * 24, b"second"),
            )

    with pytest.raises(ProgramFactsProviderAPIError, match="duplicate"):
        snapshot_provider_source_inputs(
            source_bytes_by_id=DuplicateItems(),
            source_manifest={},
            build_inputs={},
        )
    with pytest.raises(ProgramFactsProviderAPIError, match="exact bytes"):
        snapshot_provider_source_inputs(
            source_bytes_by_id={"PFS-" + "a" * 24: bytearray(b"mutable")},
            source_manifest={},
            build_inputs={},
        )


def test_provider_result_raw_size_cannot_exceed_signed_plan_ceiling() -> None:
    ceiling = 32
    registry, context, observed, decision = _plan(
        resources=_resources(output_bytes=ceiling)
    )
    plan = decision.plan
    assert plan is not None
    oversized = b"x" * (ceiling + 1)
    result = _result(plan, oversized)

    with pytest.raises(ProgramFactsProviderAPIError, match="resource|ceiling"):
        validate_provider_result(
            result,
            plan=plan,
            raw_output=oversized,
            registry=registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
    with pytest.raises(ProgramFactsProviderAPIError, match="resource|ceiling"):
        validate_parsed_provider_output(
            ParsedProviderOutput(
                result=result,
                parsed_payload_schema="fixture.parsed_program_facts.v1",
                parsed_payload={"rows": []},
            ),
            raw_output=oversized,
            plan=plan,
            expected_result=result,
        )


def test_provider_result_accepts_raw_bytes_at_exact_plan_ceiling() -> None:
    ceiling = 32
    registry, context, observed, decision = _plan(
        resources=_resources(output_bytes=ceiling)
    )
    plan = decision.plan
    assert plan is not None
    exact = b"x" * ceiling
    result = _result(plan, exact)
    assert validate_provider_result(
        result,
        plan=plan,
        raw_output=exact,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    ).result_digest == result.result_digest


def test_contribution_sink_snapshots_nested_build_inputs_only_once() -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    raw = b'{"facts":[]}\n'
    result = _result(plan, raw)
    contribution = _contribution(plan, result, precision="EXACT")
    source_config = _OneReadMapping(
        {
            "project_root": "root-0",
            "variants": [{"build_variant_id": PFB}],
        }
    )
    source_ledger = _OneReadMapping(
        {
            "source_manifest_digest": plan.source_manifest_digest,
            "build_variant_ids": [PFB],
        }
    )

    assert validate_fact_contribution(
        contribution,
        plan=plan,
        result=result,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=raw,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
        source_config=source_config,
        expected_source_ledger_binding=source_ledger,
    ).contribution_id == contribution.contribution_id
    assert source_config.iterations == 1
    assert source_ledger.iterations == 1
