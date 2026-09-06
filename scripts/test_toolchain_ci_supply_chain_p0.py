"""Offline contracts for CI dependency and GitHub Action provenance.

These fixtures never contact a package index or GitHub.  They make mutable
Action tags and best-effort/unpinned pip fallbacks structurally impossible in
the two cross-OS workflows.  The reviewed ``requirements-ci.lock`` and its
point-in-time provenance receipt are mandatory shipped controls.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import audit_snapshot as SNAPSHOT
import ci_dependency_authority as CI_AUTHORITY
import test_public_packaging_freeze as PUBLIC_PACKAGE


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
WORKFLOWS = tuple(
    sorted((*WORKFLOW_ROOT.glob("*.yml"), *WORKFLOW_ROOT.glob("*.yaml")))
)
ACTION_USE = re.compile(
    r"(?m)^\s*-\s+uses:\s+"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"@(?P<revision>[0-9a-f]{40})"
    r"\s+#\s+v(?P<version>[0-9]+(?:\.[0-9]+){1,2})\s*$"
)
MUTABLE_ACTION_TAG = re.compile(
    r"(?m)^\s*-\s+uses:\s+"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?![0-9a-f]{40}(?:\s|#|$))"
)
PIP_INSTALL = re.compile(
    r"(?m)^(?P<indent>\s*)(?:python\s+-m\s+)?pip\s+install\b(?P<args>.*)$"
)
REQUIRED_NORMATIVE_ASSETS = {
    "architecture/method-application-rfc.md",
    "architecture/ecosystem-graph-provider-contract.md",
    "methodology/method-cards-v1.yaml",
    "architecture/finding-ledger-migration.md",
    "benchmarks/application-coverage-evaluation-plan.md",
    "architecture/work-unit-scheduler.md",
    "architecture/premise-and-disposition-policy.md",
}
REVIEWED_ACTION_IDENTITIES = {
    "actions/checkout": (
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "7.0.1",
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "7.0.0",
    ),
    "actions/dependency-review-action": (
        "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
        "5.0.0",
    ),
}
MANDATORY_WORKFLOW_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
}
DIRECT_CI_REQUIREMENTS = {
    "inquirerpy",
    "jsonschema",
    "markdown-it-py",
    "protobuf",
    "pydantic",
    "pytest",
    "pytest-xdist",
    "pywinpty",
    "rich",
}
PROVENANCE_RECEIPT = (
    ROOT / "verification_policy" / "ci_dependency_provenance.v2.json"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def test_github_actions_are_full_sha_pinned_with_version_comments() -> None:
    assert {
        "install-smoke.yml",
        "tests.yml",
    } <= {workflow.name for workflow in WORKFLOWS}
    for workflow in WORKFLOWS:
        text = _text(workflow)
        assert MUTABLE_ACTION_TAG.search(text) is None, workflow
        matches = list(ACTION_USE.finditer(text))
        used = re.findall(
            r"(?m)^\s*-\s+uses:\s+"
            r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
            text,
        )
        assert used, f"{workflow} has no governed GitHub Actions"
        assert len(matches) == len(used), (
            f"{workflow} has an Action without a full commit SHA and "
            "human-readable version comment"
        )
        action_names = {match.group("action") for match in matches}
        assert MANDATORY_WORKFLOW_ACTIONS <= action_names
        assert action_names <= set(REVIEWED_ACTION_IDENTITIES)
        for match in matches:
            assert (
                match.group("revision"),
                match.group("version"),
            ) == REVIEWED_ACTION_IDENTITIES[match.group("action")]


def test_ci_has_no_unpinned_or_best_effort_pip_fallback() -> None:
    for workflow in WORKFLOWS:
        text = _text(workflow)
        assert "pip install --upgrade pip" not in text
        assert "requirements.txt pytest" not in text
        assert "requirements-dev.txt" not in text
        assert "install pytest" not in text.casefold()
        assert "if [ ! -f requirements-ci.lock ]" in text
        assert "exit 1" in text
        installs = list(PIP_INSTALL.finditer(text))
        assert installs, f"{workflow} installs no reviewed CI dependency set"
        for install in installs:
            args = install.group("args")
            assert "--require-hashes" in args
            assert "--only-binary=:all:" in args
            assert "-r requirements-ci.lock" in args
            assert "--disable-pip-version-check" in args


def _locked_requirements() -> dict[str, str]:
    lock = ROOT / "requirements-ci.lock"
    assert lock.is_file(), "requirements-ci.lock is a mandatory CI authority"
    logical_rows: list[str] = []
    current = ""
    for raw in _text(lock).splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].strip()
            continue
        logical_rows.append(current)
        current = ""
    assert not current, "unterminated lockfile continuation"
    assert logical_rows
    locked: dict[str, str] = {}
    for row in logical_rows:
        if row == "--only-binary :all:":
            continue
        requirement = row.split()[0]
        assert not requirement.startswith("--"), row
        assert "==" in requirement, row
        name, version = requirement.split("==", 1)
        normalized = name.casefold().replace("_", "-")
        assert normalized not in locked, f"duplicate locked project: {name}"
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version), row
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", row)
        assert hashes, f"unhashed locked project: {name}"
        assert len(hashes) == len(set(hashes)), f"duplicate hash: {name}"
        locked[normalized] = version
    return locked


def test_ci_lock_is_complete_exact_and_hash_bound() -> None:
    locked = _locked_requirements()
    assert DIRECT_CI_REQUIREMENTS <= set(locked)
    assert len(locked) >= len(DIRECT_CI_REQUIREMENTS)
    for workflow in WORKFLOWS:
        text = _text(workflow)
        bootstrap = text.index(
            "python -I scripts/ci_dependency_authority.py "
            "bootstrap-gate --root ."
        )
        guard = text.index("if [ ! -f requirements-ci.lock ]")
        install = text.index("-r requirements-ci.lock", guard)
        assert bootstrap < guard < install
        assert text.count("bootstrap-gate --root .") == 1
        assert "ci_dependency_authority.py static --root ." not in text
        assert "-r requirements-ci-resolver.lock" not in text
        assert "requirements-ci.lock is required" in text


def test_ci_dependency_provenance_covers_matrix_and_lock_hashes() -> None:
    receipt = json.loads(_text(PROVENANCE_RECEIPT))
    assert receipt["schema"] == "plamen.ci-dependency-provenance.v2"
    assert receipt["authority"] == "generated-reviewed-point-in-time"
    assert receipt["clean_claim"]["valid_after_checked_at"] is False
    assert receipt["clean_claim"]["online_recheck_required"] is True
    assert receipt["clean_claim"]["offline_install_behavior"] == (
        "fail-loud-no-network-fallback"
    )
    assert (
        receipt["advisory_review"]["source"]
        == "https://api.osv.dev/v1/querybatch"
    )
    assert (
        receipt["release_metadata"]["source"]
        == "https://pypi.org/pypi/{name}/{version}/json"
    )
    assert {
        row["name"]: (row["commit_sha"], row["version"])
        for row in receipt["github_actions"]
    } == REVIEWED_ACTION_IDENTITIES
    assert receipt["matrix"] == {
        "python": ["3.11", "3.12"],
        "platform": [
            "linux-x86_64",
            "macos-arm64",
            "macos-x86_64",
            "windows-x86_64",
        ],
    }
    lock_text = _text(ROOT / "requirements-ci.lock")
    locked = _locked_requirements()
    for project in receipt["locked_projects"]:
        normalized = project["name"].casefold().replace("_", "-")
        assert locked[normalized] == project["version"]
    assert {
        project["name"].casefold().replace("_", "-")
        for project in receipt["locked_projects"]
    } == set(locked)
    universal = {
        artifact["project"].casefold().replace("_", "-")
        for artifact in receipt["universal_wheels"]
    }
    binary = set(locked) - universal
    assert binary == {
        "protobuf",
        "pydantic-core",
        "pywinpty",
        "rpds-py",
    }
    assert universal.isdisjoint(binary)
    assert universal | binary == set(locked)
    for artifact in receipt["universal_wheels"]:
        assert artifact["filename"].endswith(
            ("-py3-none-any.whl", "-py2.py3-none-any.whl")
        )
        assert artifact["sha256"] in lock_text
    targets = {
        (row["python"], row["platform"])
        for row in receipt["wheel_coverage"]
    }
    assert targets == {
        (python, platform)
        for python in ("3.11", "3.12")
        for platform in (
            "linux-x86_64",
            "macos-arm64",
            "macos-x86_64",
            "windows-x86_64",
        )
    }
    for target in receipt["wheel_coverage"]:
        expected = {"pydantic-core", "protobuf", "rpds-py"}
        if target["platform"] == "windows-x86_64":
            expected.add("pywinpty")
        assert {artifact["project"] for artifact in target["artifacts"]} == expected
        for artifact in target["artifacts"]:
            assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
            assert artifact["sha256"] in lock_text, artifact["filename"]
    CI_AUTHORITY.verify_repository(ROOT, regenerate_lock=False)


def test_cross_os_matrices_remain_complete() -> None:
    workflows = {workflow.name: workflow for workflow in WORKFLOWS}
    install_smoke = _text(workflows["install-smoke.yml"])
    tests = _text(workflows["tests.yml"])
    for os_name in (
        "ubuntu-latest",
        "windows-latest",
        "macos-latest",
    ):
        assert os_name in install_smoke
        assert os_name in tests
    assert 'python: ["3.12"]' in install_smoke
    assert 'python: ["3.11", "3.12"]' in tests


def test_workflows_are_read_only_and_advisory_policy_is_not_silent() -> None:
    workflows = {workflow.name: _text(workflow) for workflow in WORKFLOWS}
    for text in workflows.values():
        assert re.search(
            r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$",
            text,
        )
        assert "persist-credentials: false" in text
    tests = workflows["tests.yml"]
    assert "actions/dependency-review-action@" in tests
    assert "fail-on-severity: high" in tests
    assert "warn-only: false" in tests
    dependabot = _text(ROOT / ".github" / "dependabot.yml")
    assert 'package-ecosystem: "pip"' in dependabot
    assert dependabot.count('interval: "daily"') >= 2
    assert "requirements-ci.lock" in dependabot


def test_action_updates_have_a_codeowned_review_path() -> None:
    dependabot = _text(ROOT / ".github" / "dependabot.yml")
    assert 'package-ecosystem: "github-actions"' in dependabot
    assert 'directory: "/"' in dependabot
    assert 'interval: "daily"' in dependabot
    codeowners = _text(ROOT / ".github" / "CODEOWNERS")
    assert ".github/" in codeowners
    assert ".github/workflows/" in codeowners


def test_normative_top_level_roots_enter_the_public_archive_contract() -> None:
    assert {
        "architecture",
        "methodology",
        "benchmarks",
    } <= PUBLIC_PACKAGE._PUBLIC_UNTRACKED_ROOTS
    assert REQUIRED_NORMATIVE_ASSETS <= (
        PUBLIC_PACKAGE._REQUIRED_LIVE_ASSETS
    )


def test_normative_asset_bytes_bind_the_methodology_snapshot(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "plamen"
    assets = {
        "architecture/method-application-rfc.md": "architecture-v1\n",
        "methodology/method-cards-v1.yaml": "method-cards-v1\n",
        "benchmarks/application-coverage-evaluation-plan.md": "benchmark-v1\n",
    }
    for relative, content in assets.items():
        path = implementation / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    baseline = SNAPSHOT.build_methodology_snapshot_component(implementation)
    assert baseline["file_count"] == len(assets)

    for relative, content in assets.items():
        path = implementation / relative
        path.write_text(f"{content.rstrip()}-changed\n", encoding="utf-8")
        changed = SNAPSHOT.build_methodology_snapshot_component(implementation)
        assert changed["path_set_digest"] == baseline["path_set_digest"]
        assert changed["digest"] != baseline["digest"], relative
        path.write_text(content, encoding="utf-8")


def test_ci_control_bytes_bind_the_toolchain_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = tmp_path / "plamen"
    controls = {
        ".github/workflows/tests.yml": "name: tests-v1\n",
        ".github/dependabot.yml": "version: 2\n",
        ".github/CODEOWNERS": ".github/ @reviewer\n",
        "requirements-ci.lock": "pytest==0 --hash=sha256:fixture\n",
    }
    for relative, content in controls.items():
        path = implementation / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    monkeypatch.setattr(SNAPSHOT, "_runtime_tool_entries", lambda **_: [])
    baseline = SNAPSHOT._toolchain_component(implementation)
    assert baseline["file_count"] == len(controls)

    for relative, content in controls.items():
        path = implementation / relative
        path.write_text(f"{content.rstrip()}-changed\n", encoding="utf-8")
        changed = SNAPSHOT._toolchain_component(implementation)
        assert changed["path_set_digest"] == baseline["path_set_digest"]
        assert changed["digest"] != baseline["digest"], relative
        path.write_text(content, encoding="utf-8")
