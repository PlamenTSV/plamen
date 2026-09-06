"""Adversarial fixtures for provider-authored typed PhaseIO output.

The fixtures use the local Python interpreter as a native worker.  They do not
mock provider completion: every accepted value must survive the real
WorkPlan -> worker-execution receipt/CAS -> PhaseIO incorporation replay.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import stat
import sys
import types

import pytest

import artifact_ledger as ledger
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
from typed_worker_output_authority import (
    FIXTURE_TYPED_OUTPUT_ROLE,
    METHOD_CARD_PRODUCER_TYPED_ROLE,
    METHOD_CARD_REVIEWER_TYPED_ROLE,
    STRICT_CANONICAL_JSON_PARSER_ID,
    TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA,
    TypedWorkerOutputAuthorityError,
    TypedWorkerOutputReplayWitness,
    canonical_typed_worker_output_authority_bytes,
    replay_typed_worker_output,
    trusted_typed_worker_output_parser,
    validate_typed_worker_output_authority,
)
import typed_worker_output_authority as typed_authority
import worker_execution_receipts as worker_receipts
import worker_transaction as worker_tx


pytestmark = pytest.mark.integration


PAYLOAD_SCHEMA = "fixture.typed-worker-output.v1"
PAYLOAD_KEYS = frozenset({"schema", "subject_digest", "disposition"})
RUN_ID = "typed-output-run"


def test_closed_typed_json_parser_matches_canonical_oracle_corpus() -> None:
    values = [
        None,
        True,
        False,
        0,
        1,
        -1,
        10**100,
        -(10**100),
        "",
        'quote"slash\\',
        "\b\t\n\f\r\x1f",
        "ASCII",
        "é Ω 中 😀",
        "\u0301",
        [],
        [None, True, False, 0, -7, "x"],
        {},
        {"Z": 1, "a": 2, "é": 3, "😀": 4},
        {"nested": [{"a": [1, 2, 3]}, {"b": "value"}]},
    ]
    for index in range(128):
        values.append(
            {
                "flag": index % 2 == 0,
                "index": index - 64,
                "items": [index, str(index), None],
                "unicode": chr(0x20 + index),
            }
        )

    for value in values:
        expected = {"schema": PAYLOAD_SCHEMA, "value": value}
        raw = canonical_file_bytes(expected)
        assert typed_authority._typed_json_parse_document(raw) == expected
        assert typed_authority._registered_canonical_json_parser(
            Path("ignored"), raw
        ) == _sha(raw[:-1])


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1}',
        b'{"a":1}\n\n',
        b'\xef\xbb\xbf{"a":1}\n',
        b'{"a":\xff}\n',
        b' {"a":1}\n',
        b'{"a":1} \n',
        b'{"b":1,"a":2}\n',
        b'{"a":1,"a":2}\n',
        b'{"a" :1}\n',
        b'{"a": 1}\n',
        b'{"a":01}\n',
        b'{"a":-0}\n',
        b'{"a":1.0}\n',
        b'{"a":1e2}\n',
        b'{"a":NaN}\n',
        b'{"a":Infinity}\n',
        b'{"a":"\\/"}\n',
        b'{"a":"\\u0061"}\n',
        b'{"a":"\\u000A"}\n',
        b'{"a":"\\u000a"}\n',
        b'{"a":"\\u0000"}\n',
        b'{"a":"\\ud800"}\n',
        b'{"a":"line\nfeed"}\n',
        b'[1,2,3]\n',
    ],
)
def test_closed_typed_json_parser_rejects_malformed_or_noncanonical_bytes(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError):
        typed_authority._typed_json_parse_document(raw)
    if not raw.startswith(b"["):
        with pytest.raises(ProgramFactsTypeError):
            strict_json_loads(
                raw,
                require_final_lf=True,
                require_canonical=True,
            )


def test_closed_typed_json_parser_bounds_depth_items_bytes_ints_and_unicode() -> None:
    too_deep = (
        b'{"v":'
        + (b"[" * (typed_authority._TYPED_JSON_MAX_DEPTH + 1))
        + b"0"
        + (b"]" * (typed_authority._TYPED_JSON_MAX_DEPTH + 1))
        + b"}\n"
    )
    too_many_items = (
        b'{"v":['
        + (
            b"0," * typed_authority._TYPED_JSON_MAX_ITEMS
        )
        + b"0]}\n"
    )
    too_large = (
        b'{"v":"'
        + b"a" * typed_authority._TYPED_JSON_MAX_BYTES
        + b'"}\n'
    )
    too_many_digits = (
        b'{"v":1'
        + b"0" * typed_authority._TYPED_JSON_MAX_INTEGER_DIGITS
        + b"}\n"
    )
    decomposed = '{"v":"e\u0301"}\n'.encode("utf-8")

    for raw in (
        too_deep,
        too_many_items,
        too_large,
        too_many_digits,
        decomposed,
    ):
        with pytest.raises(ValueError):
            typed_authority._typed_json_parse_document(raw)

    with pytest.raises(ProgramFactsTypeError):
        strict_json_loads(
            decomposed,
            require_final_lf=True,
            require_canonical=True,
        )


def test_registered_parser_closure_is_local_and_has_exact_native_edges() -> None:
    spec = typed_authority._registered_parser_spec(
        typed_role=FIXTURE_TYPED_OUTPUT_ROLE,
        payload_schema=PAYLOAD_SCHEMA,
        parser_id=STRICT_CANONICAL_JSON_PARSER_ID,
    )
    assert spec._fields == (
        "typed_role",
        "payload_schema",
        "parser_id",
        "payload_keys",
        "code_sha256",
    )
    assert not any(callable(value) for value in spec)
    closure = typed_authority._TYPED_PARSER_TRUSTED_CLOSURE
    strong = worker_receipts._trusted_module_callable_binding(
        typed_authority._registered_canonical_json_parser,
        label="registered parser denominator fixture",
        positional_parameters=2,
        expected_module=typed_authority._TYPED_PARSER_EXPECTED_MODULE,
    )
    assert spec.code_sha256 == strong["code_sha256"]
    assert all(
        registered.code_sha256 == strong["code_sha256"]
        for registered in typed_authority._TYPED_PARSER_REGISTRY.values()
    )
    assert closure.binding_sha256 == hashlib.sha256(
        closure.binding_bytes
    ).hexdigest()
    binding = json.loads(closure.binding_bytes)
    assert {
        row["identity"] for row in binding["functions"]
    } == {
        "typed_worker_output_authority:_registered_canonical_json_parser",
        "typed_worker_output_authority:_registered_canonical_json_payload",
        "typed_worker_output_authority:_typed_json_parse_document",
        "typed_worker_output_authority:_typed_json_parse_integer",
        "typed_worker_output_authority:_typed_json_parse_string",
        "typed_worker_output_authority:_typed_json_parse_value",
    }
    assert [row["name"] for row in binding["modules"]] == [
        "typed_worker_output_authority"
    ]
    native_edges = {
        row["name"]: row["binding"]["identity"]
        for row in binding["edges"]
        if row.get("name")
        in {"_TYPED_JSON_SHA256", "_TYPED_JSON_IS_NORMALIZED"}
    }
    assert native_edges == {
        "_TYPED_JSON_SHA256": "_hashlib:openssl_sha256",
        "_TYPED_JSON_IS_NORMALIZED": "unicodedata:is_normalized",
    }
    assert b"program_facts_types" not in closure.binding_bytes
    assert b"canonical_json_bytes" not in closure.binding_bytes
    assert b"strict_json_loads" not in closure.binding_bytes
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(
            closure,
            "callback",
            _typed_json_parser,
        )
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(
            closure,
            "object_references",
            (),
        )
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(
            spec,
            "code_sha256",
            "0" * 64,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "current_bytes_stale_digest",
        "exact_tuple_reconstruction",
        "altered_reference_denominator",
        "callback_substitution",
        "module_substitution",
    ],
)
def test_reconstructed_parser_closure_tuple_is_never_authority(
    mutation: str,
) -> None:
    callback = typed_authority._registered_canonical_json_parser
    original = typed_authority._TYPED_PARSER_TRUSTED_CLOSURE
    values = {
        "callback": callback,
        "expected_module": original.expected_module,
        "binding_bytes": original.binding_bytes,
        "binding_sha256": original.binding_sha256,
        "object_references": original.object_references,
    }
    replay_callback = callback
    if mutation == "current_bytes_stale_digest":
        values["binding_sha256"] = "0" * 64
    elif mutation == "altered_reference_denominator":
        values["object_references"] = original.object_references[:-1]
    elif mutation == "callback_substitution":
        values["callback"] = _typed_json_parser
    elif mutation == "module_substitution":
        values["expected_module"] = types.ModuleType(
            typed_authority.__name__
        )
    reconstructed = worker_receipts._TrustedCallableClosure(**values)

    with pytest.raises(
        worker_receipts.WorkerExecutionError,
        match="digest|registered closure|identity|module",
    ):
        worker_receipts._replay_trusted_callable_closure(
            replay_callback,
            reconstructed,
            label="reconstructed parser fixture",
            positional_parameters=2,
        )


def test_replacing_registered_closure_global_with_exact_tuple_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = typed_authority._TYPED_PARSER_TRUSTED_CLOSURE
    reconstructed = worker_receipts._TrustedCallableClosure(*original)
    assert reconstructed == original and reconstructed is not original
    monkeypatch.setattr(
        typed_authority,
        "_TYPED_PARSER_TRUSTED_CLOSURE",
        reconstructed,
    )

    with pytest.raises(
        TypedWorkerOutputAuthorityError,
        match="registered closure|parser closure",
    ):
        trusted_typed_worker_output_parser(
            typed_role=FIXTURE_TYPED_OUTPUT_ROLE,
            payload_schema=PAYLOAD_SCHEMA,
            parser_id=STRICT_CANONICAL_JSON_PARSER_ID,
        )


def _typed_json_parser(_path: Path, raw: bytes) -> str:
    value = strict_json_loads(
        raw,
        require_final_lf=True,
        require_canonical=True,
    )
    if not isinstance(value, dict):
        raise ValueError("typed worker output must be an object")
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_mutable(path: Path, raw: bytes) -> None:
    path.chmod(stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes(raw)


def _resign(value: dict, digest_field: str) -> dict:
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    return {**unsigned, digest_field: _sha(canonical_json_bytes(unsigned))}


@dataclass(frozen=True)
class TypedFixture:
    scratchpad: Path
    project_root: Path
    payload: dict
    witness: TypedWorkerOutputReplayWitness
    execution: object
    incorporation: object


def build_typed_fixture(
    tmp_path: Path,
    *,
    payload: dict | None = None,
    unit: str = "typed-output-producer",
    output_name: str = "typed_output.json",
    semantic_inputs: dict[str, bytes] | None = None,
    scratchpad_override: Path | None = None,
    project_root_override: Path | None = None,
    run_id_override: str = RUN_ID,
    source_snapshot_digest_override: str = "2" * 64,
    typed_role_override: str | None = None,
    parser_id_override: str = STRICT_CANONICAL_JSON_PARSER_ID,
) -> TypedFixture:
    scratchpad = scratchpad_override or (tmp_path / "scratchpad")
    project_root = project_root_override or (tmp_path / "project")
    scratchpad.mkdir(parents=True, exist_ok=True)
    project_root.mkdir(parents=True, exist_ok=True)
    value = payload or {
        "schema": PAYLOAD_SCHEMA,
        "subject_digest": "a" * 64,
        "disposition": "CONFIRMED",
    }
    raw = canonical_file_bytes(value)
    payload_schema = str(value.get("schema") or PAYLOAD_SCHEMA)
    roles = {
        PAYLOAD_SCHEMA: FIXTURE_TYPED_OUTPUT_ROLE,
        "plamen.method-card-producer-application-typed-output.v2": (
            METHOD_CARD_PRODUCER_TYPED_ROLE
        ),
        "plamen.method-card-independent-application-review-typed-output.v2": (
            METHOD_CARD_REVIEWER_TYPED_ROLE
        ),
    }
    typed_role = typed_role_override or roles.get(payload_schema)
    if typed_role is None:
        raise ValueError(f"fixture has no registered typed role for {payload_schema}")
    parser_callback = trusted_typed_worker_output_parser(
        typed_role=typed_role,
        payload_schema=payload_schema,
        parser_id=parser_id_override,
    )
    semantic = semantic_inputs or {
        "scratchpad:typed_subject.json": canonical_file_bytes(
            {"schema": "fixture.subject.v1", "value": "current"}
        )
    }
    for identity, data in semantic.items():
        root_name, relative = identity.split(":", 1)
        root = scratchpad if root_name == "scratchpad" else project_root
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            assert path.read_bytes() == data
        else:
            path.write_bytes(data)

    prompt = b"emit the exact assigned typed JSON output\n"
    allowlist = worker_receipts.environment_allowlist_sha256(())
    launch_inputs = {
        "manifest.json": b"{}\n",
        "intent.json": canonical_file_bytes(
            {
                "effective_backend": "native",
                "effective_model": "python-fixture",
                "environment_allowlist_sha256": allowlist,
            }
        ),
        "context.md": b"typed worker output fixture\n",
        "prompt.md": prompt,
        "tool_policy.json": b'{"network":false}\n',
    }
    launch_root = Path(".typed_output_launch") / unit
    for name, data in launch_inputs.items():
        path = scratchpad / launch_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "native", "typed_output", unit
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        phase="typed_output",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output_name,
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version=payload_schema,
                minimum_gate="TYPED_WORKER_OUTPUT_AUTHORSHIP",
            ),
        ),
        immutable_inputs=tuple(sorted(semantic)),
        model_invoked=True,
        required_commit_actor="MODEL",
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        model="python-fixture",
        timeout_s=30,
        exec_mode="native",
    )
    prelaunch = ledger.record_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id_override,
    )
    prestate = prelaunch["output_prestates"][f"scratchpad:{output_name}"]
    executable = Path(sys.executable).resolve(strict=True)
    provider = {
        "backend": "native",
        "model": "python-fixture",
        "transport": "native",
        "resolved_executable": str(executable),
        "executable_sha256": _sha(executable.read_bytes()),
        "argv": [
            str(executable),
            "-I",
            "-c",
            (
                "import base64,sys;"
                "sys.stdout.buffer.write(base64.b64decode(sys.argv[1]))"
            ),
            base64.b64encode(raw).decode("ascii"),
        ],
        "environment_allowlist_digest": allowlist,
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 64 * 1024,
            "stderr_bytes": 4096,
            "staged_member_bytes": 64 * 1024,
        },
    }
    parser_binding = worker_receipts._callable_binding(parser_callback)
    assignment = {
        "assignment_id": f"{unit}-typed-output",
        "members": [
            {
                "staged_relative_path": output_name,
                "canonical_identity": f"scratchpad:{output_name}",
                "parser_binding": parser_binding,
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": prestate,
            }
        ],
    }
    denominator = worker_tx.compile_phase_work_roster_denominator(
        run_id=run_id_override,
        phase="typed_output",
        generation=1,
        required_work_unit_ids=(unit,),
    )
    plan = worker_tx.compile_worker_plan(
        run_id=run_id_override,
        phase="typed_output",
        work_unit_id=unit,
        generation=1,
        phase_roster_denominator_digest=denominator[
            "roster_denominator_digest"
        ],
        phase_io_contract_digest=contract.digest,
        phase_io_launch_digest=launch.digest,
        phase_io_input_set_digest=prelaunch["input_set_digest"],
        prompt_template_sha256=_sha(prompt),
        methodology_digests=("1" * 64,),
        source_snapshot_digest=source_snapshot_digest_override,
        provider=provider,
        assignment=assignment,
        write_scope={"mode": "ATTEMPT_ONLY", "roots": ["output"]},
        child_denominator={"required": [], "optional": []},
        completion_policy={
            "accepted_signals": ["PROCESS_EXIT_ZERO"],
            "canonical_projection": "PHASE_IO_ONLY",
        },
        retry_policy={
            "max_attempts": 1,
            "retry_requires_new_attempt_id": True,
        },
        terminal_debt_policy={"safe_authority": False},
    )
    adapter = worker_tx.NativeCommandAdapter(
        scratchpad=scratchpad,
        cwd=project_root,
        input_relative_paths={
            "manifest": launch_root.joinpath("manifest.json").as_posix(),
            "intent": launch_root.joinpath("intent.json").as_posix(),
            "context": launch_root.joinpath("context.md").as_posix(),
            "prompt": launch_root.joinpath("prompt.md").as_posix(),
            "tool_policy": launch_root.joinpath("tool_policy.json").as_posix(),
        },
        parser_digest=parser_callback,
        environment={},
        environment_allowlist=(),
    )
    execution = worker_tx.execute_worker_transaction(plan, adapter)
    incorporation = worker_tx.incorporate_worker_execution(
        execution,
        contract,
        phase_io_launch=launch,
        work_plan=plan,
        parser_digest=parser_callback,
        scratchpad=scratchpad,
        project_root=project_root,
        run_id=run_id_override,
    )
    authority = ledger.read_artifact_ledger(scratchpad)["work_units"][key][
        "execution_authority"
    ]
    witness = TypedWorkerOutputReplayWitness(
        scratchpad=scratchpad,
        project_root=project_root,
        execution_authority=authority,
        work_plan=plan,
        phase_io_contract=contract,
        phase_io_launch=launch,
        run_id=run_id_override,
        typed_role=typed_role,
        payload_schema=payload_schema,
        parser_id=parser_id_override,
        expected_output_identity=f"scratchpad:{output_name}",
        expected_input_sha256={
            identity: _sha(data) for identity, data in semantic.items()
        },
        expected_writer_role="MODEL",
    )
    return TypedFixture(
        scratchpad=scratchpad,
        project_root=project_root,
        payload=value,
        witness=witness,
        execution=execution,
        incorporation=incorporation,
    )


def test_replays_real_provider_cas_phaseio_and_returns_only_incorporated_payload(
    tmp_path: Path,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    result = replay_typed_worker_output(fixture.witness)

    assert result.payload == fixture.payload
    assert result.raw == canonical_file_bytes(fixture.payload)
    assert result.authority["schema"] == TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA
    assert result.authority["canonical_output_identity"] == (
        fixture.witness.expected_output_identity
    )
    assert result.authority["phase_io_input_set_digest"] == (
        fixture.witness.work_plan["phase_io_input_set_digest"]
    )
    assert result.authority["writer_role"] == "MODEL"
    parser = trusted_typed_worker_output_parser(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    parser_spec = typed_authority._registered_parser_spec(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    expected_binding = worker_receipts._trusted_module_callable_binding(
        parser,
        label="fixture parser",
        positional_parameters=2,
        expected_module=typed_authority._TYPED_PARSER_EXPECTED_MODULE,
    )
    expected_binding["closure_sha256"] = (
        worker_receipts._replay_trusted_callable_closure(
            parser,
            typed_authority._TYPED_PARSER_TRUSTED_CLOSURE,
            label="fixture parser",
            positional_parameters=2,
        )
    )
    assert result.authority["parser_binding"] == expected_binding


def test_same_incorporated_bytes_cannot_be_given_a_different_semantic_value(
    tmp_path: Path,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    first = replay_typed_worker_output(fixture.witness)
    second = replay_typed_worker_output(fixture.witness)
    assert first == second
    with pytest.raises(TypeError):
        replay_typed_worker_output(  # type: ignore[call-arg]
            fixture.witness,
            payload={**fixture.payload, "disposition": "REJECTED"},
        )


def _same_binding_parser_impostor(original, *, side_effect=None):
    def impostor(path: Path, raw: bytes) -> str:
        if side_effect is not None:
            side_effect()
        return original(path, raw)

    impostor.__module__ = original.__module__
    impostor.__name__ = original.__name__
    impostor.__qualname__ = original.__qualname__
    impostor.__code__ = impostor.__code__.replace(
        co_name=original.__code__.co_name,
        co_qualname=original.__code__.co_qualname,
        co_filename=original.__code__.co_filename,
        co_firstlineno=original.__code__.co_firstlineno,
    )
    assert impostor.__code__.co_code != original.__code__.co_code
    assert worker_receipts._callable_binding(impostor) == (
        worker_receipts._callable_binding(original)
    )
    return impostor


def test_same_name_source_parser_replacement_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    original = trusted_typed_worker_output_parser(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    impostor = _same_binding_parser_impostor(original)

    with pytest.raises(TypeError, match="parser_digest"):
        replace(fixture.witness, parser_digest=impostor)
    monkeypatch.setattr(
        typed_authority,
        "_registered_canonical_json_parser",
        impostor,
    )
    with pytest.raises(TypedWorkerOutputAuthorityError, match="parser"):
        replay_typed_worker_output(fixture.witness)


def test_registry_code_digest_rejects_in_place_parser_code_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    original = trusted_typed_worker_output_parser(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    replacement_code = _typed_json_parser.__code__.replace(
        co_name=original.__code__.co_name,
        co_qualname=original.__code__.co_qualname,
        co_filename=original.__code__.co_filename,
        co_firstlineno=original.__code__.co_firstlineno,
    )
    assert replacement_code.co_consts != original.__code__.co_consts
    monkeypatch.setattr(original, "__code__", replacement_code)

    with pytest.raises(TypedWorkerOutputAuthorityError, match="code|parser"):
        replay_typed_worker_output(fixture.witness)


def test_registry_rejects_same_origin_sys_modules_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    original_module = sys.modules[typed_authority.__name__]
    original_parser = trusted_typed_worker_output_parser(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    fake_module = types.ModuleType(typed_authority.__name__)
    fake_module.__spec__ = original_module.__spec__
    setattr(
        fake_module,
        original_parser.__qualname__,
        original_parser,
    )
    monkeypatch.setitem(sys.modules, typed_authority.__name__, fake_module)

    with pytest.raises(
        TypedWorkerOutputAuthorityError,
        match="module|parser|closure",
    ):
        replay_typed_worker_output(fixture.witness)


def test_parser_time_incorporation_arm_mutation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    arm_path = Path(fixture.incorporation.incorporation_path).parent / "arm.json"
    arm = json.loads(arm_path.read_text(encoding="utf-8"))
    arm["members"][0]["source_size"] += 1
    mutated_arm = canonical_file_bytes(_resign(arm, "arm_digest"))
    invocations = 0

    def mutate_after_initial_chain_snapshot() -> None:
        nonlocal invocations
        invocations += 1
        if invocations == 2:
            _write_mutable(arm_path, mutated_arm)

    original = trusted_typed_worker_output_parser(
        typed_role=fixture.witness.typed_role,
        payload_schema=fixture.witness.payload_schema,
        parser_id=fixture.witness.parser_id,
    )
    impostor = _same_binding_parser_impostor(
        original,
        side_effect=mutate_after_initial_chain_snapshot,
    )
    real_resolver = worker_receipts._resolve_registered_callable

    def compromised_resolver(callback, persisted_binding, **kwargs):
        resolved, binding = real_resolver(
            callback,
            persisted_binding,
            **kwargs,
        )
        if callback is original:
            return impostor, binding
        return resolved, binding

    monkeypatch.setattr(
        worker_receipts,
        "_resolve_registered_callable",
        compromised_resolver,
    )

    with pytest.raises(
        TypedWorkerOutputAuthorityError,
        match="incorporation|changed|post-parser",
    ):
        replay_typed_worker_output(fixture.witness)


def test_forged_resigned_typed_authority_cannot_replace_live_replay(
    tmp_path: Path,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    current = replay_typed_worker_output(fixture.witness)
    forged = dict(current.authority)
    forged["payload_digest"] = "f" * 64
    forged = _resign(forged, "authority_digest")

    with pytest.raises(
        TypedWorkerOutputAuthorityError,
        match="differs from exact current",
    ):
        validate_typed_worker_output_authority(forged, fixture.witness)


def test_provider_completion_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = build_typed_fixture(tmp_path)
    path = Path(fixture.execution.provider_execution.receipt_path)
    completion = json.loads(path.read_text(encoding="utf-8"))
    completion["outputs"][0]["raw_sha256"] = "e" * 64
    completion = _resign(completion, "completion_sha256")
    _write_mutable(path, canonical_json_bytes(completion))

    with pytest.raises(TypedWorkerOutputAuthorityError, match="provider|completion"):
        replay_typed_worker_output(fixture.witness)


def test_provider_cas_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = build_typed_fixture(tmp_path)
    receipt = Path(fixture.execution.provider_execution.receipt_path)
    completion = json.loads(receipt.read_text(encoding="utf-8"))
    blob = receipt.parent / completion["outputs"][0]["cas_blob"]["relative_path"]
    _write_mutable(blob, b'{"schema":"attacker"}\n')

    with pytest.raises(TypedWorkerOutputAuthorityError, match="CAS|provider"):
        replay_typed_worker_output(fixture.witness)


def test_phaseio_incorporation_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = build_typed_fixture(tmp_path)
    path = Path(fixture.incorporation.incorporation_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["input_set_digest"] = "d" * 64
    value = _resign(value, "incorporation_digest")
    _write_mutable(path, canonical_file_bytes(value))

    with pytest.raises(TypedWorkerOutputAuthorityError, match="incorporation"):
        replay_typed_worker_output(fixture.witness)


def test_phaseio_input_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = build_typed_fixture(tmp_path)
    path = fixture.scratchpad / "typed_subject.json"
    _write_mutable(
        path,
        canonical_file_bytes({"schema": "fixture.subject.v1", "value": "stale"}),
    )

    with pytest.raises(TypedWorkerOutputAuthorityError, match="input"):
        replay_typed_worker_output(fixture.witness)


def test_payload_schema_and_closed_root_are_taken_from_incorporated_bytes(
    tmp_path: Path,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    wrong_schema = replace(
        fixture.witness,
        payload_schema="fixture.other.v1",
    )
    with pytest.raises(TypedWorkerOutputAuthorityError, match="schema"):
        replay_typed_worker_output(wrong_schema)

    alternate_parser = replace(
        fixture.witness,
        parser_id="fixture.alternate-parser.v1",
    )
    with pytest.raises(TypedWorkerOutputAuthorityError, match="parser|registered"):
        replay_typed_worker_output(alternate_parser)

    missing_key_fixture = build_typed_fixture(
        tmp_path / "missing-key",
        payload={
            "schema": PAYLOAD_SCHEMA,
            "subject_digest": "a" * 64,
        },
    )
    with pytest.raises(TypedWorkerOutputAuthorityError, match="closed"):
        replay_typed_worker_output(missing_key_fixture.witness)


def test_canonical_authority_bytes_are_structural_but_full_validation_replays(
    tmp_path: Path,
) -> None:
    fixture = build_typed_fixture(tmp_path)
    result = replay_typed_worker_output(fixture.witness)
    raw = canonical_typed_worker_output_authority_bytes(result.authority)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert validate_typed_worker_output_authority(raw, fixture.witness) == result
