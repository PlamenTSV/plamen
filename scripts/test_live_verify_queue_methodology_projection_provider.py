"""Fixture-first contract for live verify-queue methodology projection.

The live queue currently names ``methodology_registry.json`` and
``methodology_reachability_manifest.json`` as context, but existence alone is
not methodology authority.  Production must derive both from the repository's
versioned verification-policy sources in a current-run, driver-owned PhaseIO
transaction and must expose the committed receipt to the driver adapter.

Required production module/API
------------------------------

``live_verify_queue_methodology_projection.py`` must export:

``LiveVerifyQueueMethodologyProjectionError``
    Raised before replacing or blessing foreign, stale, or drifted bytes.

``prepare_live_verify_queue_methodology_projection(*, scratchpad,
project_root, config, run_id)``
    The only public preparation entrypoint.  Policy paths, policy payloads,
    source digests, engine digests, evaluation results, and output paths are
    not caller-injectable.

The provider reads exactly:

* ``verification_policy/verification_method_registry.v1.json``; and
* ``verification_policy/methodology_reachability.v1.json``.

It writes exactly:

* ``methodology_registry.json``;
* ``methodology_reachability_manifest.json``; and
* ``live_verify_queue_methodology_projection.receipt.json``.

The registry projection is semantically identical to the source registry.
The reachability projection preserves the complete evaluated result, including
all issues.  Reachability debt is visible and haltless; it cannot be collapsed
to a clean Boolean or silently omitted.  The receipt binds the source bytes,
the output bytes, the provider/compiler engine bytes, and the exact
run/snapshot/backend tuple.

The implementation-root override used below is an internal test seam only.
It must not be a public entrypoint parameter.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Callable, Mapping

import pytest

from artifact_ledger import LEDGER_NAME, read_artifact_ledger
import test_live_verify_queue_driver_adapter_cutover as ADAPTER_FIXTURE


SCRIPTS = Path(__file__).resolve().parent
IMPLEMENTATION_ROOT = SCRIPTS.parent
SUT_PATH = SCRIPTS / "live_verify_queue_methodology_projection.py"
ADAPTER_PATH = SCRIPTS / "live_verify_queue_driver_adapter.py"

PUBLIC_ENTRYPOINT = "prepare_live_verify_queue_methodology_projection"
ERROR_NAME = "LiveVerifyQueueMethodologyProjectionError"
REGISTRY_SOURCE = (
    "verification_policy/verification_method_registry.v1.json"
)
REACHABILITY_SOURCE = (
    "verification_policy/methodology_reachability.v1.json"
)
REGISTRY_OUTPUT = "methodology_registry.json"
REACHABILITY_OUTPUT = "methodology_reachability_manifest.json"
RECEIPT_OUTPUT = "live_verify_queue_methodology_projection.receipt.json"
OUTPUTS = (REGISTRY_OUTPUT, REACHABILITY_OUTPUT, RECEIPT_OUTPUT)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_digest(value: Any) -> str:
    return _sha(_canonical_bytes(value))


def _load_module(path: Path, name: str):
    assert path.is_file(), f"production must add {path.name}"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_sut():
    return _load_module(
        SUT_PATH,
        "_plamen_live_verify_queue_methodology_projection_acceptance",
    )


def _entrypoint() -> Callable[..., Mapping[str, Any]]:
    candidate = getattr(_load_sut(), PUBLIC_ENTRYPOINT, None)
    assert callable(candidate), (
        f"production must expose {PUBLIC_ENTRYPOINT}"
    )
    return candidate


def _error_type() -> type[BaseException]:
    candidate = getattr(_load_sut(), ERROR_NAME, None)
    assert isinstance(candidate, type) and issubclass(
        candidate, BaseException
    ), f"production must expose {ERROR_NAME}"
    return candidate


def _copy_file(source_root: Path, destination_root: Path, relative: str) -> None:
    source = source_root / relative
    assert source.is_file(), f"fixture source is absent: {relative}"
    destination = destination_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _copy_engine_fixture(tmp_path: Path) -> Path:
    """Copy only the policy/evaluator denominator required by this provider."""

    engine = tmp_path / "engine"
    manifest = json.loads(
        (IMPLEMENTATION_ROOT / REACHABILITY_SOURCE).read_text(
            encoding="utf-8"
        )
    )
    relatives = {
        REGISTRY_SOURCE,
        REACHABILITY_SOURCE,
        "scripts/verification_method_compiler.py",
        "scripts/live_verify_queue_methodology_projection.py",
        *map(str, manifest["scan_paths"]),
    }
    for entry in manifest["entries"]:
        for field in ("consumer_path", "test_path"):
            value = entry.get(field)
            if isinstance(value, str) and value:
                relatives.add(value)
    for relative in sorted(relatives):
        _copy_file(IMPLEMENTATION_ROOT, engine, relative)
    return engine


def _bind_engine_fixture(
    monkeypatch: pytest.MonkeyPatch,
    engine: Path,
) -> None:
    module = _load_sut()
    resolver = getattr(module, "_implementation_root", None)
    assert callable(resolver), (
        "provider must isolate fixed implementation-root discovery behind "
        "_implementation_root() so source authority is not caller-injectable"
    )
    monkeypatch.setattr(module, "_implementation_root", lambda: engine)


def _audit_fixture(
    tmp_path: Path,
    *,
    pipeline: str = "sc",
    backend: str = "claude",
) -> tuple[Path, Path, dict[str, Any], str]:
    project = tmp_path / "audit"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    run_id = f"methodology-projection-{pipeline}-{backend}"
    ecosystem = "evm" if pipeline == "sc" else "rust"
    phase = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": ecosystem,
        "ecosystem": ecosystem,
        "cli_backend": backend,
        "backend": backend,
        "phase_name": phase,
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": run_id,
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    return project, root, config, run_id


def _invoke(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> Mapping[str, Any]:
    return _entrypoint()(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=run_id,
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _assert_run_binding(
    binding: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    run_id: str,
) -> None:
    assert binding == {
        "audit_snapshot_digest": config["_audit_snapshot"][
            "snapshot_digest"
        ],
        "backend": config["backend"],
        "ecosystem": config["ecosystem"],
        "mode": config["mode"],
        "phase_name": config["phase_name"],
        "pipeline": config["pipeline"],
        "run_id": run_id,
    }


def _assert_source_rows(
    rows: Any,
    *,
    engine: Path,
) -> None:
    assert isinstance(rows, list)
    assert [row["identity"] for row in rows] == [
        "implementation:" + REGISTRY_SOURCE,
        "implementation:" + REACHABILITY_SOURCE,
    ]
    for row in rows:
        assert set(row) == {"identity", "sha256", "size"}
        relative = row["identity"][len("implementation:"):]
        raw = (engine / relative).read_bytes()
        assert row["sha256"] == _sha(raw)
        assert row["size"] == len(raw)


def _evaluation_input_paths(engine: Path) -> list[str]:
    manifest = _read_json(engine / REACHABILITY_SOURCE)
    values = set(map(str, manifest["scan_paths"]))
    for entry in manifest["entries"]:
        for field in ("consumer_path", "test_path"):
            value = entry.get(field)
            if isinstance(value, str) and value:
                values.add(value)
    values.difference_update({REGISTRY_SOURCE, REACHABILITY_SOURCE})
    return sorted(values)


def _assert_evaluation_input_rows(
    rows: Any,
    *,
    engine: Path,
) -> None:
    assert isinstance(rows, list)
    assert [row["identity"] for row in rows] == [
        "implementation:" + relative
        for relative in _evaluation_input_paths(engine)
    ]
    for row in rows:
        assert set(row) == {"identity", "sha256", "size"}
        relative = row["identity"][len("implementation:"):]
        raw = (engine / relative).read_bytes()
        assert row["sha256"] == _sha(raw)
        assert row["size"] == len(raw)


def _assert_engine_authority(
    authority: Mapping[str, Any],
    *,
    engine: Path,
) -> None:
    assert authority["provider_id"] == (
        "live_verify_queue_methodology_projection"
    )
    assert isinstance(authority["files"], list)
    assert [row["identity"] for row in authority["files"]] == [
        "implementation:scripts/live_verify_queue_methodology_projection.py",
        "implementation:scripts/verification_method_compiler.py",
    ]
    for row in authority["files"]:
        assert set(row) == {"identity", "sha256", "size"}
        relative = row["identity"][len("implementation:"):]
        raw = (engine / relative).read_bytes()
        assert row["sha256"] == _sha(raw)
        assert row["size"] == len(raw)
    assert authority["digest"] == _stable_digest(authority["files"])


def _assert_output_authority(
    rows: Any,
    *,
    root: Path,
) -> None:
    assert isinstance(rows, list)
    assert [row["identity"] for row in rows] == [
        "scratchpad:" + REGISTRY_OUTPUT,
        "scratchpad:" + REACHABILITY_OUTPUT,
    ]
    for row in rows:
        assert set(row) == {"identity", "sha256", "size"}
        raw = (root / row["identity"][len("scratchpad:"):]).read_bytes()
        assert row["sha256"] == _sha(raw)
        assert row["size"] == len(raw)


def _assert_projection(
    result: Mapping[str, Any],
    *,
    engine: Path,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> None:
    assert result["schema_version"] == (
        "plamen.live_verify_queue_methodology_projection.v1"
    )
    assert result["state"] in {
        "COMMITTED_CLEAN",
        "COMMITTED_WITH_VISIBLE_DEBT",
    }
    assert result["safe_to_consume"] is True
    assert result["status_json_is_authority"] is False
    assert result["output_paths"] == [
        REGISTRY_OUTPUT,
        REACHABILITY_OUTPUT,
    ]
    assert result["receipt_path"] == RECEIPT_OUTPUT
    assert result["phase_io_owner_key"]

    registry_source = _read_json(engine / REGISTRY_SOURCE)
    registry_projection = _read_json(root / REGISTRY_OUTPUT)
    assert registry_projection == registry_source

    reachability = _read_json(root / REACHABILITY_OUTPUT)
    assert reachability["schema_version"] == (
        "plamen.live_methodology_reachability_projection.v1"
    )
    assert reachability["source_schema_version"] == (
        "plamen.methodology_reachability.v1"
    )
    assert reachability["state"] == result["state"]
    assert reachability["safe_to_consume"] is True
    assert reachability["proof_authority"] == "NONE"
    _assert_run_binding(
        reachability["runtime_binding"], config=config, run_id=run_id
    )
    assert isinstance(reachability["evaluation"], dict)
    assert isinstance(reachability["evaluation"]["issues"], list)
    assert reachability["issue_count"] == len(
        reachability["evaluation"]["issues"]
    )
    unsigned_reachability = {
        key: value
        for key, value in reachability.items()
        if key != "projection_digest"
    }
    assert reachability["projection_digest"] == _stable_digest(
        unsigned_reachability
    )

    receipt = _read_json(root / RECEIPT_OUTPUT)
    assert receipt["schema_version"] == (
        "plamen.live_verify_queue_methodology_projection_receipt.v1"
    )
    assert receipt["state"] == result["state"]
    assert receipt["safe_to_consume"] is True
    assert receipt["proof_authority"] == "NONE"
    assert receipt["reachability_issue_count"] == len(
        reachability["evaluation"]["issues"]
    )
    _assert_run_binding(
        receipt["runtime_binding"], config=config, run_id=run_id
    )
    _assert_source_rows(receipt["source_authority"], engine=engine)
    assert receipt["source_set_digest"] == _stable_digest(
        receipt["source_authority"]
    )
    _assert_evaluation_input_rows(
        receipt["evaluation_input_authority"], engine=engine
    )
    assert receipt["evaluation_input_digest"] == _stable_digest(
        receipt["evaluation_input_authority"]
    )
    assert receipt["methodology_input_digest"] == _stable_digest([
        *receipt["source_authority"],
        *receipt["evaluation_input_authority"],
    ])
    assert all(
        HEX64.fullmatch(str(receipt[key]))
        for key in (
            "source_set_digest",
            "evaluation_input_digest",
            "methodology_input_digest",
        )
    )
    assert reachability["methodology_input_digest"] == receipt[
        "methodology_input_digest"
    ]
    _assert_engine_authority(
        receipt["engine_authority"], engine=engine
    )
    _assert_output_authority(
        receipt["output_authority"], root=root
    )
    unsigned_receipt = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    }
    assert receipt["receipt_digest"] == _stable_digest(unsigned_receipt)
    assert HEX64.fullmatch(str(receipt["receipt_digest"]))
    assert result["receipt_digest"] == receipt["receipt_digest"]

    ledger = read_artifact_ledger(root)
    work = ledger["work_units"][result["phase_io_owner_key"]]
    assert work["run_id"] == run_id
    assert work["execution_state"] == "OUTPUT_COMMITTED"
    assert work["model_invoked"] is False
    for relative in OUTPUTS:
        identity = "scratchpad:" + relative
        binding = ledger["artifact_bindings"][identity]
        raw = (root / relative).read_bytes()
        assert binding["owner_key"] == result["phase_io_owner_key"]
        assert binding["writer"] == "DRIVER"
        assert binding["run_id"] == run_id
        assert binding["status"] == "ACTIVE"
        assert binding["sha256"] == _sha(raw)
        assert binding["size"] == len(raw)


def test_projection_provider_exports_one_narrow_noninjectable_api() -> None:
    module = _load_sut()
    entry = _entrypoint()
    _error_type()
    signature = inspect.signature(entry)
    assert tuple(signature.parameters) == (
        "scratchpad",
        "project_root",
        "config",
        "run_id",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert all(
        name not in signature.parameters
        for name in (
            "implementation_root",
            "registry_path",
            "reachability_path",
            "registry_payload",
            "reachability_payload",
            "source_digest",
            "methodology_digest",
            "engine_digest",
            "reachability_evaluation",
            "output_paths",
        )
    )
    assert callable(getattr(module, PUBLIC_ENTRYPOINT))


@pytest.mark.parametrize(
    ("pipeline", "backend"),
    (
        ("sc", "claude"),
        ("sc", "codex"),
        ("l1", "claude"),
        ("l1", "codex"),
    ),
)
def test_authoritative_sources_generate_current_run_phaseio_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: str,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(
        tmp_path, pipeline=pipeline, backend=backend
    )
    assert not any((root / relative).exists() for relative in OUTPUTS)

    result = _invoke(
        root=root, project=project, config=config, run_id=run_id
    )

    _assert_projection(
        result,
        engine=engine,
        root=root,
        project=project,
        config=config,
        run_id=run_id,
    )
    assert result["state"] == "COMMITTED_CLEAN"


def test_projection_exact_replay_is_byte_and_ledger_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    first = _invoke(
        root=root, project=project, config=config, run_id=run_id
    )
    before = {
        relative: (root / relative).read_bytes()
        for relative in (*OUTPUTS, LEDGER_NAME)
    }

    second = _invoke(
        root=root, project=project, config=config, run_id=run_id
    )

    after = {
        relative: (root / relative).read_bytes()
        for relative in (*OUTPUTS, LEDGER_NAME)
    }
    assert second == first
    assert after == before


@pytest.mark.parametrize(
    "source_relative",
    (
        REGISTRY_SOURCE,
        REACHABILITY_SOURCE,
        "prompts/shared/v2/phase5-verification-sc.md",
    ),
)
def test_committed_projection_rejects_authoritative_policy_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_relative: str,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    _invoke(root=root, project=project, config=config, run_id=run_id)
    before = {
        relative: (root / relative).read_bytes() for relative in OUTPUTS
    }
    source = engine / source_relative
    source.write_bytes(source.read_bytes() + b"\n")

    with pytest.raises(
        _error_type(),
        match=r"(?i)(source|policy|methodology).*(drift|changed|mismatch)",
    ):
        _invoke(root=root, project=project, config=config, run_id=run_id)

    assert {
        relative: (root / relative).read_bytes() for relative in OUTPUTS
    } == before


@pytest.mark.parametrize(
    "output_relative",
    (REGISTRY_OUTPUT, REACHABILITY_OUTPUT, RECEIPT_OUTPUT),
)
def test_committed_projection_rejects_output_or_methodology_digest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_relative: str,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    _invoke(root=root, project=project, config=config, run_id=run_id)
    target = root / output_relative
    target.write_bytes(target.read_bytes() + b" ")
    drifted = target.read_bytes()

    with pytest.raises(
        _error_type(),
        match=r"(?i)(output|postimage|methodology|receipt).*(drift|changed|mismatch|invalid)",
    ):
        _invoke(root=root, project=project, config=config, run_id=run_id)

    assert target.read_bytes() == drifted


@pytest.mark.parametrize(
    "dimension",
    ("run_id", "snapshot", "backend"),
)
def test_projection_rejects_current_run_authority_tuple_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dimension: str,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    _invoke(root=root, project=project, config=config, run_id=run_id)
    changed = dict(config)
    changed["_audit_snapshot"] = dict(config["_audit_snapshot"])
    changed_run = run_id
    if dimension == "run_id":
        changed_run = run_id + "-different"
        changed["_run_id"] = changed_run
    elif dimension == "snapshot":
        changed["_audit_snapshot"]["snapshot_digest"] = "b" * 64
    else:
        changed["backend"] = "codex"
        changed["cli_backend"] = "codex"

    with pytest.raises(
        _error_type(),
        match=r"(?i)(run|snapshot|backend|runtime|authority|owner|phaseio).*(drift|changed|mismatch|invalid|conflict)",
    ):
        _invoke(
            root=root,
            project=project,
            config=changed,
            run_id=changed_run,
        )


def test_projection_rejects_engine_authority_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    _invoke(root=root, project=project, config=config, run_id=run_id)
    compiler = engine / "scripts/verification_method_compiler.py"
    compiler.write_bytes(compiler.read_bytes() + b"\n# engine drift\n")

    with pytest.raises(
        _error_type(),
        match=r"(?i)(engine|compiler|methodology).*(drift|changed|mismatch)",
    ):
        _invoke(root=root, project=project, config=config, run_id=run_id)


def test_reachability_issues_are_committed_as_visible_haltless_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    source = (
        engine / "prompts/evm/phase5-verification-prompt.md"
    )
    source.write_text(
        source.read_text(encoding="utf-8")
        + "\n## UNMAPPED FIXTURE RULE (MANDATORY)\n",
        encoding="utf-8",
    )
    project, root, config, run_id = _audit_fixture(tmp_path)

    result = _invoke(
        root=root, project=project, config=config, run_id=run_id
    )

    _assert_projection(
        result,
        engine=engine,
        root=root,
        project=project,
        config=config,
        run_id=run_id,
    )
    assert result["state"] == "COMMITTED_WITH_VISIBLE_DEBT"
    reachability = _read_json(root / REACHABILITY_OUTPUT)
    issues = reachability["evaluation"]["issues"]
    assert any(
        issue["code"] == "ORPHAN_MANDATORY_RULE" for issue in issues
    )
    assert reachability["issue_count"] == len(issues) > 0
    receipt = _read_json(root / RECEIPT_OUTPUT)
    assert receipt["reachability_issue_count"] == len(issues)
    assert "ORPHAN_MANDATORY_RULE" in receipt[
        "reachability_issue_codes"
    ]


def test_arbitrary_preseed_cannot_become_projection_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _copy_engine_fixture(tmp_path)
    _bind_engine_fixture(monkeypatch, engine)
    project, root, config, run_id = _audit_fixture(tmp_path)
    foreign = _canonical_bytes({"artifact": REGISTRY_OUTPUT})
    (root / REGISTRY_OUTPUT).write_bytes(foreign)

    with pytest.raises(
        _error_type(),
        match=r"(?i)(foreign|pre.?existing|create|authority|projection)",
    ):
        _invoke(root=root, project=project, config=config, run_id=run_id)

    assert (root / REGISTRY_OUTPUT).read_bytes() == foreign
    assert not (root / RECEIPT_OUTPUT).exists()


def test_live_driver_adapter_invokes_real_provider_and_consumes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _load_module(
        ADAPTER_PATH,
        "_plamen_live_verify_queue_driver_adapter_methodology_acceptance",
    )
    provider_module = getattr(adapter, "_methodology_projection", None)
    assert provider_module is not None, (
        "live_verify_queue_driver_adapter must import the methodology "
        "projection provider as _methodology_projection"
    )
    real_provider = getattr(
        provider_module, PUBLIC_ENTRYPOINT, None
    )
    assert callable(real_provider)
    calls: list[dict[str, Any]] = []

    def observed_provider(**kwargs: Any) -> Mapping[str, Any]:
        calls.append(dict(kwargs))
        return real_provider(**kwargs)

    monkeypatch.setattr(
        provider_module,
        PUBLIC_ENTRYPOINT,
        observed_provider,
    )
    project = tmp_path / "adapter"
    root, config, run_id = ADAPTER_FIXTURE._seed(
        project, pipeline="sc", backend="claude"
    )
    # The legacy fixture's arbitrary context placeholders are deliberately
    # removed.  Only the provider may create these live methodology artifacts.
    for relative in (REGISTRY_OUTPUT, REACHABILITY_OUTPUT):
        (root / relative).unlink(missing_ok=True)

    result = adapter.run_live_verify_queue_driver_cutover(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=run_id,
    )

    assert len(calls) == 1
    assert calls[0] == {
        "scratchpad": root.resolve(),
        "project_root": project.resolve(),
        "config": {
            **config,
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "ecosystem": "evm",
            "cli_backend": "claude",
            "backend": "claude",
            "phase_name": "sc_verify_queue",
            "project_root": str(project.resolve()),
            "scratchpad": str(root.resolve()),
            "_run_id": run_id,
        },
        "run_id": run_id,
    }
    projection = result["methodology_projection"]
    receipt = _read_json(root / RECEIPT_OUTPUT)
    assert projection["receipt_digest"] == receipt["receipt_digest"]
    assert RECEIPT_OUTPUT in result["effective_upstream_roster"]
    assert RECEIPT_OUTPUT in result["plan"]["external_input_denominator"]
    assert set(projection["output_paths"]) == {
        REGISTRY_OUTPUT,
        REACHABILITY_OUTPUT,
    }
    assert set(projection["output_paths"]) <= set(
        result["context_capture"]["exact_inputs"]
    )
    ledger = read_artifact_ledger(root)
    receipt_binding = ledger["artifact_bindings"][
        "scratchpad:" + RECEIPT_OUTPUT
    ]
    assert receipt_binding["owner_key"] == projection[
        "phase_io_owner_key"
    ]
    assert receipt_binding["run_id"] == run_id
    producer_rows = result["runtime_authority_evidence"][
        "producer_ledger"
    ]["rows"]
    assert any(
        row["identity"] == "scratchpad:" + RECEIPT_OUTPUT
        and row["producer_work_unit_key"]
        == projection["phase_io_owner_key"]
        for row in producer_rows
    )
