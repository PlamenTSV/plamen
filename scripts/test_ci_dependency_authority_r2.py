"""R2 adversarial contracts for CI dependency and package authority."""

from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest

import ci_dependency_authority as AUTH
import refresh_ci_dependency_evidence as REFRESH
import test_public_packaging_freeze as PUBLIC_PACKAGE
import toolchain_control_authority as TOOLCHAIN


ROOT = Path(__file__).resolve().parents[1]


def _validation_now() -> datetime:
    """Use the actual validation clock for checked live repository evidence."""

    return datetime.now(timezone.utc)


def _copy_authority(tmp_path: Path) -> Path:
    destination = tmp_path / "repo"
    paths = (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-ci.constraints",
        "requirements-ci.lock",
        "requirements-ci-resolver.in",
        "requirements-ci-resolver.lock",
        "verification_policy/ci_dependency_authority.v1.json",
        "verification_policy/ci_dependency_provenance.v2.json",
        "verification_policy/ci_dependency_provenance.v2.schema.json",
        "verification_policy/ci_release_metadata_evidence.v1.json",
        "verification_policy/ci_advisory_evidence.v1.json",
        ".github/workflows/tests.yml",
        ".github/workflows/install-smoke.yml",
    )
    for relative in paths:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for relative in (
        AUTH.RELEASE_RESPONSE_DIR,
        AUTH.ADVISORY_REQUEST_PATH.parent,
    ):
        shutil.copytree(ROOT / relative, destination / relative)
    return destination


def _replace_locked_project(
    text: str,
    *,
    project: str,
    version: str,
    digest: str,
) -> str:
    logical: list[str] = []
    rows = text.splitlines(keepends=True)
    start = None
    end = None
    for ordinal, row in enumerate(rows):
        if row.startswith(f"{project}=="):
            start = ordinal
            continue
        if start is not None and ordinal > start and row and not row[0].isspace():
            end = ordinal
            break
    assert start is not None
    if end is None:
        end = len(rows)
    replacement = (
        f"{project}=={version} \\\n"
        f"    --hash=sha256:{digest}\n"
        "    # via -r requirements-dev.txt\n"
    )
    logical.extend(rows[:start])
    logical.append(replacement)
    logical.extend(rows[end:])
    return "".join(logical)


def test_generated_lock_bytes_are_cross_platform_lf_canonical() -> None:
    assert AUTH._canonical_generated_lock_bytes(b"alpha\r\nbeta\r\n") == (
        b"alpha\nbeta\n"
    )
    assert AUTH._canonical_generated_lock_bytes(b"alpha\nbeta\n") == (
        b"alpha\nbeta\n"
    )
    with pytest.raises(
        AUTH.CIDependencyAuthorityError, match="bare carriage return"
    ):
        AUTH._canonical_generated_lock_bytes(b"alpha\rbeta\n")
    with pytest.raises(
        AUTH.CIDependencyAuthorityError, match="final newline"
    ):
        AUTH._canonical_generated_lock_bytes(b"alpha")


def test_host_resolution_allows_only_inactive_marker_rows_to_be_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    checked = {
        "common": AUTH.LockedRequirement("1.0", (digest,)),
        "windows-only": AUTH.LockedRequirement(
            "2.0",
            (digest,),
            'platform_system == "Windows"',
        ),
    }
    regenerated = {"common": checked["common"]}

    monkeypatch.setattr(
        "packaging.markers.default_environment",
        lambda: {
            "implementation_name": "cpython",
            "implementation_version": "3.12.0",
            "os_name": "posix",
            "platform_machine": "x86_64",
            "platform_python_implementation": "CPython",
            "platform_release": "test",
            "platform_system": "Linux",
            "platform_version": "test",
            "python_full_version": "3.12.0",
            "python_version": "3.12",
            "sys_platform": "linux",
        },
    )
    AUTH._verify_host_resolution(checked, regenerated)

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="omits active checked rows",
    ):
        AUTH._verify_host_resolution(checked, {})

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="differs from checked lock row",
    ):
        AUTH._verify_host_resolution(
            checked,
            {"common": AUTH.LockedRequirement("9.9", (digest,))},
        )

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="differs from checked lock row",
    ):
        AUTH._verify_host_resolution(
            checked,
            {
                "common": checked["common"],
                "unreviewed": AUTH.LockedRequirement("1.0", (digest,)),
            },
        )


def test_installable_lock_downgrade_fails_static_gate_before_resolver(
    tmp_path: Path,
) -> None:
    repository = _copy_authority(tmp_path)
    lock_path = repository / "requirements-ci.lock"
    lock_path.write_text(
        _replace_locked_project(
            lock_path.read_text(encoding="utf-8"),
            project="pytest",
            version="9.0.3",
            digest=(
                "2c5efc453d45394fdd706ade797c0a81091eccd1d6e4bccfcd"
                "476e2b8e0ab5d9"
            ),
        ),
        encoding="utf-8",
        newline="\n",
    )
    receipt_path = (
        repository
        / "verification_policy"
        / "ci_dependency_provenance.v2.json"
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["lock_authority"]["output_sha256"] = hashlib.sha256(
        lock_path.read_bytes()
    ).hexdigest()
    for row in receipt["locked_projects"]:
        if row["name"] == "pytest":
            row["version"] = "9.0.3"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="pytest.*requirements input|requirements input.*pytest",
    ):
        AUTH.verify_static_bindings(repository)


def test_static_gate_rejects_an_unparsed_manifest_requirement(
    tmp_path: Path,
) -> None:
    repository = _copy_authority(tmp_path)
    requirements = repository / "requirements.txt"
    requirements.write_text(
        requirements.read_text(encoding="utf-8")
        + "\nunreviewed-dependency>=1\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt_path = repository / AUTH.RECEIPT_PATH
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["lock_authority"]["input_sha256"]["requirements.txt"] = (
        hashlib.sha256(requirements.read_bytes()).hexdigest()
    )
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="unsupported requirement|unreviewed-dependency",
    ):
        AUTH.verify_static_bindings(repository)


@pytest.mark.parametrize(
    ("project", "mutation", "expected"),
    [
        ("markdown-it-py", "absent", "project denominator"),
        ("jsonschema", "widened", "exact-pin denominator"),
        ("protobuf", "version", "requirements input requires"),
        ("jsonschema", "case-alias", "duplicate requirements input"),
        ("protobuf", "unsupported", "unsupported requirement authority row"),
        ("markdown-it-py", "constraint-drift", "conflicting requirements input"),
    ],
)
def test_current_runtime_declarations_fail_closed_before_receipt_or_resolver(
    tmp_path: Path,
    project: str,
    mutation: str,
    expected: str,
) -> None:
    repository = _copy_authority(tmp_path)
    requirements = repository / "requirements.txt"
    constraints = repository / "requirements-ci.constraints"
    locked = AUTH.parse_lock(repository / "requirements-ci.lock")
    version = locked[project].version
    direct_rows = {
        "markdown-it-py": f"markdown-it-py=={version}",
        "jsonschema": "jsonschema>=4.26,<5",
        "protobuf": f"protobuf=={version}",
    }
    row = direct_rows[project]
    constraint_row = f"{project}=={version}"
    requirements_text = requirements.read_text(encoding="utf-8")
    assert row in requirements_text
    constraint_text = constraints.read_text(encoding="utf-8")
    assert constraint_row in constraint_text
    if mutation == "absent":
        requirements_text = requirements_text.replace(row, "", 1)
        constraint_text = constraint_text.replace(constraint_row, "", 1)
    elif mutation == "widened":
        constraint_text = constraint_text.replace(
            constraint_row, f"{project}>={version}", 1
        )
    elif mutation == "version":
        requirements_text = requirements_text.replace(row, f"{project}==0", 1)
        constraint_text = constraint_text.replace(
            constraint_row, f"{project}==0", 1
        )
    elif mutation == "case-alias":
        requirements_text += f"\n{project.upper()}=={version}\n"
    elif mutation == "unsupported":
        requirements_text = requirements_text.replace(
            row, f"{project} @ https://example.invalid/{project}.whl", 1
        )
    elif mutation == "constraint-drift":
        constraint_text = constraint_text.replace(
            constraint_row, f"{project}==0", 1
        )
    else:  # pragma: no cover - the closed parametrization controls this.
        raise AssertionError(mutation)
    requirements.write_text(
        requirements_text,
        encoding="utf-8",
        newline="\n",
    )
    constraints.write_text(
        constraint_text,
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(AUTH.CIDependencyAuthorityError, match=expected):
        AUTH.verify_static_bindings(repository, verify_workflows=False)


def test_current_runtime_declarations_match_all_checked_dependency_axes(
    tmp_path: Path,
) -> None:
    repository = _copy_authority(tmp_path)
    locked = AUTH.parse_lock(repository / "requirements-ci.lock")
    exact, _, declared = AUTH._read_requirement_inputs(repository)
    receipt = AUTH.load_receipt(repository)
    receipt_versions = {
        row["name"]: row["version"] for row in receipt["locked_projects"]
    }
    targets = {
        "markdown-it-py": "4.2.0",
        "jsonschema": "4.26.0",
        "protobuf": "7.35.1",
    }
    assert set(targets) <= set(declared)
    for project, version in targets.items():
        assert exact[project] == version
        assert locked[project].version == version
        assert receipt_versions[project] == version
        universal = [
            artifact
            for artifact in receipt["universal_wheels"]
            if artifact["project"] == project
        ]
        platform = [
            artifact
            for target in receipt["wheel_coverage"]
            for artifact in target["artifacts"]
            if artifact["project"] == project
        ]
        assert len(universal) == 1 or len(platform) == len(receipt["wheel_coverage"])
        assert all(
            artifact["sha256"] in locked[project].hashes
            for artifact in [*universal, *platform]
        )

    (repository / AUTH.RECEIPT_PATH).write_bytes(AUTH.render_receipt(repository))
    AUTH.verify_static_bindings(repository, verify_workflows=False)


def test_receipt_rejects_incompatible_wheel_source_and_timestamps() -> None:
    receipt = AUTH.load_receipt(ROOT)
    mutated = deepcopy(receipt)
    target = next(
        row
        for row in mutated["wheel_coverage"]
        if row["python"] == "3.11"
        and row["platform"] == "linux-x86_64"
    )
    artifact = next(
        row
        for row in target["artifacts"]
        if row["project"] == "pydantic-core"
    )
    artifact["filename"] = (
        "pydantic_core-2.46.4-cp312-cp312-win_amd64.whl"
    )
    mutated["github_actions"][0]["source"] = (
        "https://example.invalid/untrusted-action-claim"
    )
    mutated["checked_at"] = "not-a-timestamp"
    mutated["release_metadata"]["observed_at"] = (
        "2099-01-01T00:00:00Z"
    )
    mutated["advisory_review"]["observed_at"] = "not-a-timestamp"

    with pytest.raises(AUTH.CIDependencyAuthorityError):
        AUTH.validate_receipt_payload(
            ROOT,
            mutated,
            now=_validation_now(),
        )


def test_receipt_rejects_duplicate_and_missing_project_coverage() -> None:
    mutated = deepcopy(AUTH.load_receipt(ROOT))
    source = mutated["universal_wheels"][0]
    mutated["universal_wheels"][1] = deepcopy(source)
    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="duplicate|denominator|coverage",
    ):
        AUTH.validate_receipt_payload(
            ROOT,
            mutated,
            now=_validation_now(),
        )


def _target_artifact(payload: dict, project: str = "pydantic-core") -> dict:
    target = next(
        row
        for row in payload["wheel_coverage"]
        if row["python"] == "3.11"
        and row["platform"] == "linux-x86_64"
    )
    return next(
        row for row in target["artifacts"] if row["project"] == project
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: _target_artifact(payload).__setitem__(
            "sha256",
            "230a75ddfc2de4806e56696ce9640c1cdfdb6543b7cfce98d42a4c0a0e7bdb87",
        ),
        lambda payload: payload["universal_wheels"][0].__setitem__(
            "project", "attrs"
        ),
        lambda payload: payload["universal_wheels"][0].__setitem__(
            "filename", "annotated_types-0.7.0-py3-none-any.whl"
        ),
        lambda payload: payload["wheel_coverage"].__setitem__(
            1, deepcopy(payload["wheel_coverage"][0])
        ),
        lambda payload: payload["github_actions"][0].__setitem__(
            "commit_sha", "0" * 40
        ),
        lambda payload: payload["github_actions"][0].__setitem__(
            "source", "https://example.invalid/action"
        ),
        lambda payload: payload.__setitem__(
            "checked_at", "2099-01-01T00:00:00Z"
        ),
        lambda payload: payload["release_metadata"].__setitem__(
            "observed_at", "2026-07-29T16:00:00Z"
        ),
        lambda payload: payload.__setitem__("schema", "wrong"),
        lambda payload: payload.__setitem__("unreviewed", True),
    ),
    ids=(
        "filename-digest",
        "canonical-project",
        "filename-version",
        "target-denominator",
        "action-commit",
        "action-source",
        "future-checked-at",
        "incoherent-evidence-time",
        "schema-marker",
        "schema-extra-field",
    ),
)
def test_receipt_rejects_each_strict_provenance_axis(mutate) -> None:
    payload = deepcopy(AUTH.load_receipt(ROOT))
    mutate(payload)
    with pytest.raises(AUTH.CIDependencyAuthorityError):
        AUTH.validate_receipt_payload(
            ROOT,
            payload,
            now=_validation_now(),
        )


@pytest.mark.parametrize(
    ("evidence_relative", "mutate"),
    (
        (
            "verification_policy/ci_advisory_evidence.v1.json",
            lambda evidence: evidence["response"]["results"].pop(),
        ),
        (
            "verification_policy/ci_release_metadata_evidence.v1.json",
            lambda evidence: evidence["responses"].__setitem__(
                "pytest", "0" * 64
            ),
        ),
    ),
)
def test_receipt_rejects_internally_unbound_external_evidence(
    tmp_path: Path,
    evidence_relative: str,
    mutate,
) -> None:
    repository = _copy_authority(tmp_path)
    evidence_path = repository / evidence_relative
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    mutate(evidence)
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt_path = repository / AUTH.RECEIPT_PATH
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    binding = (
        "advisory_review"
        if "advisory" in evidence_relative
        else "release_metadata"
    )
    receipt[binding]["evidence_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    with pytest.raises(AUTH.CIDependencyAuthorityError):
        AUTH.validate_receipt_payload(
            repository,
            receipt,
            now=_validation_now(),
        )


def test_receipt_applies_requires_python_to_universal_projects(
    tmp_path: Path,
) -> None:
    repository = _copy_authority(tmp_path)
    evidence_path = repository / AUTH.RELEASE_EVIDENCE_PATH
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    response = evidence["responses"]["rich"]
    raw_path = repository / response["raw_path"]
    raw_payload = json.loads(raw_path.read_text(encoding="utf-8"))
    raw_payload["info"]["requires_python"] = ">=99"
    for file_row in raw_payload["urls"]:
        if file_row.get("packagetype") == "bdist_wheel":
            file_row["requires_python"] = None
    raw = AUTH._compact_json_bytes(raw_payload)
    raw_path.write_bytes(raw)
    response["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    response["canonical_response_sha256"] = hashlib.sha256(
        AUTH._compact_json_bytes(raw_payload)
    ).hexdigest()
    release = evidence["releases"]["rich"]
    release["requires_python"] = ">=99"
    release["response_sha256"] = response["raw_sha256"]
    for metadata in release["artifact_metadata"].values():
        metadata["requires_python"] = None
    evidence["response_set_sha256"] = hashlib.sha256(
        AUTH._canonical_json_bytes(evidence["responses"])
    ).hexdigest()
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt_bytes = AUTH.render_receipt(repository)
    (repository / AUTH.RECEIPT_PATH).write_bytes(receipt_bytes)
    receipt = json.loads(receipt_bytes)
    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="Requires-Python.*rich",
    ):
        AUTH.validate_receipt_payload(
            repository,
            receipt,
            now=_validation_now(),
        )


def test_repository_gate_binds_workflow_action_commits(
    tmp_path: Path,
) -> None:
    repository = _copy_authority(tmp_path)
    workflow = repository / ".github" / "workflows" / "tests.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@" + ("0" * 40),
        ),
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="workflow.*Action|Action.*workflow",
    ):
        AUTH.verify_repository(
            repository,
            now=_validation_now(),
            regenerate_lock=False,
        )


def test_online_refresh_preserves_action_observation_and_raw_response_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _copy_authority(tmp_path)
    policy_path = repository / AUTH.POLICY_PATH
    before = json.loads(policy_path.read_text(encoding="utf-8"))
    release_evidence = json.loads(
        (repository / AUTH.RELEASE_EVIDENCE_PATH).read_text(encoding="utf-8")
    )
    advisory_evidence = json.loads(
        (repository / AUTH.ADVISORY_EVIDENCE_PATH).read_text(encoding="utf-8")
    )

    def request(url: str, body: bytes | None = None) -> bytes:
        if url == "https://api.osv.dev/v1/querybatch":
            assert body is not None
            return (
                repository / advisory_evidence["raw_response_path"]
            ).read_bytes()
        name = url.split("/pypi/", 1)[1].split("/", 1)[0]
        return (
            repository / release_evidence["responses"][name]["raw_path"]
        ).read_bytes()

    monkeypatch.setattr(REFRESH, "_request", request)
    monkeypatch.setattr(
        REFRESH,
        "_utc_now",
        lambda: "2026-07-29T18:00:00Z",
    )
    REFRESH.refresh(repository)
    after = json.loads(policy_path.read_text(encoding="utf-8"))
    refreshed_advisory = json.loads(
        (repository / AUTH.ADVISORY_EVIDENCE_PATH).read_text(encoding="utf-8")
    )
    assert after["github_actions"] == before["github_actions"]
    canonical_response = AUTH._compact_json_bytes(refreshed_advisory["response"])
    assert refreshed_advisory["response_sha256"] == hashlib.sha256(
        canonical_response
    ).hexdigest()
    raw_response = (
        repository / refreshed_advisory["raw_response_path"]
    ).read_bytes()
    assert refreshed_advisory["source_response_sha256"] == hashlib.sha256(
        raw_response
    ).hexdigest()
    assert (
        repository / AUTH.RECEIPT_PATH
    ).read_bytes() == AUTH.render_receipt(repository)


@pytest.mark.parametrize("replace_ordinal", range(1, 13))
def test_refresh_rolls_back_the_entire_governed_output_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_ordinal: int,
) -> None:
    repository = _copy_authority(tmp_path)
    release_evidence = json.loads(
        (repository / AUTH.RELEASE_EVIDENCE_PATH).read_text(encoding="utf-8")
    )
    advisory_evidence = json.loads(
        (repository / AUTH.ADVISORY_EVIDENCE_PATH).read_text(encoding="utf-8")
    )

    def request(url: str, body: bytes | None = None) -> bytes:
        if url == "https://api.osv.dev/v1/querybatch":
            assert body is not None
            return (
                repository / advisory_evidence["raw_response_path"]
            ).read_bytes()
        name = url.split("/pypi/", 1)[1].split("/", 1)[0]
        return (
            repository / release_evidence["responses"][name]["raw_path"]
        ).read_bytes()

    governed = (
        AUTH.RELEASE_RESPONSE_DIR,
        AUTH.ADVISORY_REQUEST_PATH.parent,
        AUTH.RELEASE_EVIDENCE_PATH,
        AUTH.ADVISORY_EVIDENCE_PATH,
        AUTH.POLICY_PATH,
        AUTH.RECEIPT_PATH,
    )

    def snapshot() -> dict[str, bytes]:
        rows: dict[str, bytes] = {}
        for relative in governed:
            target = repository / relative
            if target.is_dir():
                for path in sorted(target.rglob("*")):
                    if path.is_file():
                        rows[path.relative_to(repository).as_posix()] = (
                            path.read_bytes()
                        )
            else:
                rows[relative.as_posix()] = target.read_bytes()
        return rows

    before = snapshot()
    real_replace = REFRESH.os.replace
    injected = False
    replace_count = 0

    def fail_once(source, destination) -> None:
        nonlocal injected, replace_count
        replace_count += 1
        if not injected and replace_count == replace_ordinal:
            injected = True
            raise OSError("injected transactional replacement failure")
        real_replace(source, destination)

    monkeypatch.setattr(REFRESH, "_request", request)
    monkeypatch.setattr(
        REFRESH,
        "_utc_now",
        lambda: "2026-07-29T18:00:00Z",
    )
    monkeypatch.setattr(REFRESH.os, "replace", fail_once)
    with pytest.raises(OSError, match="transactional replacement"):
        REFRESH.refresh(repository)
    assert injected
    assert snapshot() == before


def test_every_governed_runtime_script_is_public_but_unknown_fifth_is_private() -> None:
    governed = {
        "scripts/application_skeptic_workflow_discriminator_r12_contract.py",
        "scripts/fast_lane_skip_governance_r10_contract.py",
        "scripts/niche_lifecycle_authority.py",
        "scripts/release_fast_lane_fixture_governance_gate.py",
    }
    ignored = {
        relative for relative in governed if PUBLIC_PACKAGE._is_forbidden(relative)
    }
    assert ignored == set()
    assert PUBLIC_PACKAGE._is_forbidden(
        "scripts/r25_unknown_runtime_candidate.py"
    )


def test_checked_receipt_is_exact_generator_output() -> None:
    checked = (
        ROOT
        / "verification_policy"
        / "ci_dependency_provenance.v2.json"
    ).read_bytes()
    assert AUTH.render_receipt(ROOT) == checked
    AUTH.verify_repository(
        ROOT,
        now=_validation_now(),
        regenerate_lock=False,
    )


def test_dependency_snapshot_exposes_exact_lock_denominator() -> None:
    snapshot = AUTH.build_dependency_snapshot(
        ROOT,
        sha="a" * 40,
        ref="refs/heads/main",
        run_id="123",
        scanned="2026-07-29T18:00:00Z",
    )
    manifest = snapshot["manifests"]["requirements-ci.lock"]
    locked = AUTH.parse_lock(ROOT / "requirements-ci.lock")
    assert set(manifest["resolved"]) == {
        f"pkg:pypi/{name}@{row.version}"
        for name, row in locked.items()
    }
    assert all(
        row["relationship"] == "direct"
        for row in manifest["resolved"].values()
    )


def test_ast_runtime_closure_manifest_is_exact_and_cycle_safe() -> None:
    manifest = TOOLCHAIN.load_runtime_closure_manifest(ROOT)
    derived = TOOLCHAIN.derive_runtime_dependency_closure(ROOT)
    assert manifest["files"] == list(derived)
    assert (
        TOOLCHAIN.render_runtime_closure_manifest(ROOT)
        == (
            ROOT
            / "verification_policy"
            / "toolchain_runtime_closure.v1.json"
        ).read_bytes()
    )
    assert len(derived) == len(set(derived))
    required_seams = {
        "scripts/artifact_ledger.py",
        "scripts/phase_io_contracts.py",
        "scripts/provider_command_authority.py",
        "scripts/program_facts_evm_wtx.py",
        "scripts/rooted_path_io.py",
        "scripts/worker_execution_receipts.py",
        "scripts/worker_transaction.py",
        "scripts/linux_cgroup_exec.py",
        "scripts/owned_process_runner.py",
        "scripts/owned_process_scope.py",
        "scripts/program_facts_evm_helper.py",
    }
    assert required_seams <= set(derived)


def test_ast_runtime_closure_resolves_package_relative_imports() -> None:
    modules = {
        "plamen_l1": "plamen_l1/__init__.py",
        "plamen_l1.scip_reader": "plamen_l1/scip_reader.py",
    }
    targets = TOOLCHAIN._local_import_targets(
        ast.parse("from . import scip_reader\n"),
        importer="plamen_l1",
        importer_is_package=True,
        modules=modules,
    )
    assert "plamen_l1/scip_reader.py" in targets


def test_every_runtime_closure_path_has_omission_authority(
    tmp_path: Path,
) -> None:
    required = TOOLCHAIN.TOOLCHAIN_RUNTIME_REQUIRED_FILES
    digest_bound = {
        row["path"] for row in TOOLCHAIN.TOOLCHAIN_RUNTIME_ASSET_ROWS
    }
    for relative in required:
        root = tmp_path / hashlib.sha256(relative.encode()).hexdigest()[:16]
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        assert TOOLCHAIN.runtime_required_missing(
            root,
            required_files=(relative,),
        ) == ()
        if relative in digest_bound:
            target.write_bytes(b"x")
            assert TOOLCHAIN.runtime_required_missing(
                root,
                required_files=(relative,),
            ) == (relative,)
        target.unlink()
        assert TOOLCHAIN.runtime_required_missing(
            root,
            required_files=(relative,),
        ) == (relative,)


def test_public_archive_ships_ci_authority_and_runtime_closure(
    tmp_path: Path,
) -> None:
    archive = PUBLIC_PACKAGE._temporary_public_archive(tmp_path)
    members = PUBLIC_PACKAGE._archive_members(archive)
    required = {
        ".github/dependabot.yml",
        "requirements-ci.constraints",
        "requirements-ci.lock",
        "requirements-ci-resolver.lock",
        "scripts/ci_dependency_authority.py",
        "verification_policy/ci_dependency_authority.v1.json",
        "verification_policy/ci_dependency_provenance.v2.json",
        "verification_policy/ci_dependency_provenance.v2.schema.json",
        "verification_policy/ci_release_metadata_evidence.v1.json",
        "verification_policy/ci_advisory_evidence.v1.json",
        "verification_policy/toolchain_runtime_closure.v1.json",
    }
    assert required <= members
