"""Refresh reviewed PyPI/OSV evidence for the exact CI lock.

This command is deliberately separate from offline CI.  It contacts only the
primary PyPI and OSV APIs, preserves each response digest, and writes
deterministic normalized evidence.  The resulting diff remains a human review
boundary; CI never converts service unavailability into a clean result.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request

import ci_dependency_authority as authority


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _request(url: str, body: bytes | None = None) -> bytes:
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Plamen-CI-Dependency-Evidence/1",
        },
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.geturl() != url:
            raise RuntimeError(
                f"primary-source evidence request redirected: {url}"
            )
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError as exc:
                raise RuntimeError(
                    f"primary-source response length is invalid: {url}"
                ) from exc
            if declared <= 0 or declared > authority._MAX_RAW_RESPONSE_BYTES:
                raise RuntimeError(
                    f"primary-source response length is outside bounds: {url}"
                )
        raw = response.read(authority._MAX_RAW_RESPONSE_BYTES + 1)
        if not raw or len(raw) > authority._MAX_RAW_RESPONSE_BYTES:
            raise RuntimeError(
                f"primary-source response size is outside bounds: {url}"
            )
        return raw


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _seed_policy(root: Path, source: Path, observed_at: str) -> dict:
    receipt = json.loads(source.read_text(encoding="utf-8"))
    return {
        "schema": authority.POLICY_SCHEMA,
        "resolver": {
            "name": "pip-tools",
            "version": "7.5.2",
            "python_implementation": "CPython",
            "python_version": "3.12",
            "index_url": "https://pypi.org/simple",
            "command": [
                "python",
                "-I",
                "-m",
                "piptools",
                "compile",
                "--generate-hashes",
                "--allow-unsafe",
                "--strip-extras",
                "--resolver=backtracking",
                "--no-config",
                "--pip-args=--only-binary=:all:",
                "--output-file",
                "requirements-ci.lock",
                "requirements-dev.txt",
            ],
        },
        "paths": {
            "requirements": "requirements-dev.txt",
            "constraints": "requirements-ci.constraints",
            "lock": "requirements-ci.lock",
            "resolver_input": "requirements-ci-resolver.in",
            "resolver_lock": "requirements-ci-resolver.lock",
            "receipt": authority.RECEIPT_PATH.as_posix(),
            "receipt_schema": authority.SCHEMA_PATH.as_posix(),
            "release_evidence": authority.RELEASE_EVIDENCE_PATH.as_posix(),
            "advisory_evidence": authority.ADVISORY_EVIDENCE_PATH.as_posix(),
        },
        "matrix": receipt["matrix"],
        "checked_at": observed_at,
        # Dependency evidence refresh is not Action tag/commit observation.
        # Preserve the prior reviewed Action observation until a dedicated
        # primary-source Action review replaces it.
        "github_actions": receipt["github_actions"],
        "universal_wheels": receipt["universal_wheels"],
        "wheel_coverage": receipt["wheel_coverage"],
        "clean_claim": {
            "valid_after_checked_at": False,
            "online_recheck_required": True,
            "offline_ci_claim": "hash-identity-compatibility-only",
            "offline_install_behavior": "fail-loud-no-network-fallback",
        },
    }


def _remove_managed_path(root: Path, path: Path) -> None:
    root = root.resolve(strict=True)
    candidate = path.absolute()
    if not candidate.is_relative_to(root):
        raise RuntimeError(f"managed refresh path escapes root: {candidate}")
    if candidate.is_symlink() or candidate.is_file():
        candidate.unlink()
    elif candidate.is_dir():
        shutil.rmtree(candidate)


def _replace_outputs_transactionally(
    root: Path,
    stage: Path,
    relatives: tuple[Path, ...],
) -> None:
    """Replace the governed output group with rollback on any failure."""

    backup = stage / ".rollback"
    backup.mkdir()
    displaced: list[Path] = []
    installed: list[Path] = []
    try:
        for relative in relatives:
            source = stage / relative
            destination = root / relative
            if not source.exists() or source.is_symlink():
                raise RuntimeError(
                    f"staged refresh output is missing/linked: {relative}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                preserved = backup / relative
                preserved.parent.mkdir(parents=True, exist_ok=True)
                os.replace(destination, preserved)
                displaced.append(relative)
            os.replace(source, destination)
            installed.append(relative)
    except BaseException as exc:
        rollback_errors: list[str] = []
        for relative in reversed(installed):
            try:
                _remove_managed_path(root, root / relative)
            except OSError as rollback_exc:
                rollback_errors.append(
                    f"remove {relative}: {type(rollback_exc).__name__}"
                )
        for relative in reversed(displaced):
            try:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(backup / relative, destination)
            except OSError as rollback_exc:
                rollback_errors.append(
                    f"restore {relative}: {type(rollback_exc).__name__}"
                )
        if rollback_errors:
            raise RuntimeError(
                "CI evidence refresh failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise


def refresh(root: Path, *, bootstrap_source: Path | None = None) -> None:
    root = root.resolve()
    observed_at = _utc_now()
    policy_path = root / authority.POLICY_PATH
    if policy_path.exists():
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["checked_at"] = observed_at
    elif bootstrap_source is not None:
        policy = _seed_policy(root, bootstrap_source, observed_at)
    else:
        raise RuntimeError(
            "policy missing; pass --bootstrap-source for the one-time migration"
        )

    locked = authority.parse_lock(root / "requirements-ci.lock")
    releases: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(
        prefix=".plamen-ci-evidence-",
        dir=root,
    ) as raw_stage:
        stage = Path(raw_stage)
        response_rows: dict[str, dict] = {}
        for name, row in sorted(locked.items()):
            url = f"https://pypi.org/pypi/{name}/{row.version}/json"
            raw = _request(url)
            payload = authority._parse_json_bytes(
                raw,
                f"PyPI refresh response {name}",
            )
            if not isinstance(payload, dict):
                raise RuntimeError(
                    f"PyPI refresh response root is invalid: {name}"
                )
            raw_path = (
                authority.RELEASE_RESPONSE_DIR
                / f"{name}-{row.version}.json"
            )
            staged_raw = stage / raw_path
            staged_raw.parent.mkdir(parents=True, exist_ok=True)
            staged_raw.write_bytes(raw)
            response_rows[name] = {
                "canonical_response_sha256": hashlib.sha256(
                    authority._compact_json_bytes(payload)
                ).hexdigest(),
                "project": name,
                "raw_path": raw_path.as_posix(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "request_url": url,
                "version": row.version,
            }
            artifacts: dict[str, str] = {}
            artifact_metadata: dict[str, dict] = {}
            for file_row in payload["urls"]:
                if file_row.get("packagetype") != "bdist_wheel":
                    continue
                filename = file_row["filename"]
                if filename in artifacts:
                    raise RuntimeError(
                        f"duplicate PyPI wheel filename: {name}:{filename}"
                    )
                artifacts[filename] = file_row["digests"]["sha256"]
                artifact_metadata[filename] = {
                    "requires_python": file_row.get("requires_python"),
                    "url": file_row["url"],
                    "yanked": file_row["yanked"],
                }
            releases[name] = {
                "artifact_metadata": dict(sorted(artifact_metadata.items())),
                "artifacts": dict(sorted(artifacts.items())),
                "requires_python": (
                    payload["info"].get("requires_python") or ""
                ),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "version": row.version,
            }
        response_set_sha256 = hashlib.sha256(
            _canonical_bytes(response_rows)
        ).hexdigest()
        release_evidence = {
            "schema": authority.RELEASE_SCHEMA,
            "source": "https://pypi.org/pypi/{name}/{version}/json",
            "observed_at": observed_at,
            "response_set_sha256": response_set_sha256,
            "responses": response_rows,
            "releases": releases,
        }

        osv_request = {
            "queries": [
                {
                    "package": {"ecosystem": "PyPI", "name": name},
                    "version": row.version,
                }
                for name, row in sorted(locked.items())
            ]
        }
        request_bytes = json.dumps(
            osv_request, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        osv_raw = _request(
            "https://api.osv.dev/v1/querybatch", request_bytes
        )
        osv_payload = authority._parse_json_bytes(
            osv_raw,
            "OSV refresh response",
        )
        if not isinstance(osv_payload, dict):
            raise RuntimeError("OSV refresh response root is invalid")
        for relative, content in (
            (authority.ADVISORY_REQUEST_PATH, request_bytes),
            (authority.ADVISORY_RESPONSE_PATH, osv_raw),
        ):
            staged = stage / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(content)
        ids = sorted(
            {
                vuln["id"]
                for result in osv_payload.get("results", [])
                for vuln in result.get("vulns", [])
            }
        )
        advisory_evidence = {
            "schema": authority.ADVISORY_SCHEMA,
            "source": "https://api.osv.dev/v1/querybatch",
            "observed_at": observed_at,
            "request": osv_request,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "raw_request_path": authority.ADVISORY_REQUEST_PATH.as_posix(),
            "raw_request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "response": osv_payload,
            "response_sha256": hashlib.sha256(
                authority._compact_json_bytes(osv_payload)
            ).hexdigest(),
            "raw_response_path": authority.ADVISORY_RESPONSE_PATH.as_posix(),
            "source_response_sha256": hashlib.sha256(osv_raw).hexdigest(),
            "query_count": len(locked),
            "result": (
                "none-observed-at-check" if not ids else "advisories-observed"
            ),
            "advisory_ids": ids,
            "limitation": (
                "Point-in-time primary-source observation; advisory data may "
                "change and must be refreshed before release."
            ),
        }
        authority._validate_release_evidence(
            release_evidence,
            root=stage,
            locked=locked,
            receipt={
                "source": release_evidence["source"],
                "observed_at": observed_at,
            },
            checked=datetime.fromisoformat(
                observed_at[:-1] + "+00:00"
            ),
        )
        authority._validate_advisory_evidence(
            advisory_evidence,
            root=stage,
            locked=locked,
            receipt={
                "source": advisory_evidence["source"],
                "observed_at": observed_at,
                "query_count": len(locked),
                "result": advisory_evidence["result"],
            },
            checked=datetime.fromisoformat(
                observed_at[:-1] + "+00:00"
            ),
        )
        staged_outputs = {
            authority.POLICY_PATH: _canonical_bytes(policy),
            authority.RELEASE_EVIDENCE_PATH: _canonical_bytes(
                release_evidence
            ),
            authority.ADVISORY_EVIDENCE_PATH: _canonical_bytes(
                advisory_evidence
            ),
        }
        for relative, content in staged_outputs.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

        _, traversed, _ = authority._read_requirement_inputs(root)
        receipt_inputs = {
            *traversed,
            "requirements-ci.lock",
            "requirements-ci-resolver.in",
            "requirements-ci-resolver.lock",
            authority.SCHEMA_PATH.as_posix(),
        }
        for relative_text in sorted(receipt_inputs):
            relative = Path(relative_text)
            target = stage / relative
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, target)
        receipt_bytes = authority.render_receipt(stage)
        receipt_path = stage / authority.RECEIPT_PATH
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_bytes(receipt_bytes)
        authority.validate_receipt_payload(
            stage,
            json.loads(receipt_bytes),
            now=datetime.fromisoformat(observed_at[:-1] + "+00:00"),
        )

        replacement_order = (
            authority.RELEASE_RESPONSE_DIR,
            authority.ADVISORY_REQUEST_PATH.parent,
            authority.RELEASE_EVIDENCE_PATH,
            authority.ADVISORY_EVIDENCE_PATH,
            authority.POLICY_PATH,
            authority.RECEIPT_PATH,
        )
        _replace_outputs_transactionally(root, stage, replacement_order)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--bootstrap-source", type=Path)
    args = parser.parse_args()
    refresh(args.root, bootstrap_source=args.bootstrap_source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
