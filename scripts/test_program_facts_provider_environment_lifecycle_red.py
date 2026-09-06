from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


INSTALLER_MODULE = "program_facts_evm_environment_installer"


def _distribution(
    name: str,
    version: str,
    wheel_sha256: str,
    *,
    native: bool = False,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = [
        {
            "portable_path": f"site-packages/{name}/__init__.py",
            "size": 32,
            "sha256": "1" * 64,
            "record_sha256": "1" * 64,
            "file_class": "PYTHON",
        },
        {
            "portable_path": (
                f"site-packages/{name}/_native.pyd"
                if native
                else f"site-packages/{name}/core.py"
            ),
            "size": 64,
            "sha256": "2" * 64,
            "record_sha256": "2" * 64,
            "file_class": "NATIVE_EXTENSION" if native else "PYTHON",
        },
    ]
    if native:
        files[1]["dynamic_library_closure_digest"] = "3" * 64
    return {
        "name": name,
        "version": version,
        "artifact": {
            "kind": "WHEEL",
            "sha256": wheel_sha256,
            "governed_source_build_receipt": None,
        },
        "record_files": files,
    }


def _positive_lifecycle() -> dict[str, Any]:
    governed = [
        {"name": "crytic-compile", "version": "0.3.11", "sha256": "a" * 64},
        {"name": "slither-analyzer", "version": "0.11.3", "sha256": "b" * 64},
    ]
    observed = [
        _distribution("crytic_compile", "0.3.11", "a" * 64),
        _distribution(
            "slither_analyzer",
            "0.11.3",
            "b" * 64,
            native=True,
        ),
    ]
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_evm_provider_environment_lifecycle.v1",
        "environment_id": "pf-evm-windows-amd64-r1",
        "semantic_prefix": "provider://pf-evm-windows-amd64-r1/",
        "governed_distribution_artifacts": governed,
        "observed_distributions": observed,
        "observed_imports": [
            {
                "module": "crytic_compile",
                "origin": (
                    "provider://pf-evm-windows-amd64-r1/"
                    "site-packages/crytic_compile/__init__.py"
                ),
                "distribution": "crytic-compile",
            },
            {
                "module": "slither",
                "origin": (
                    "provider://pf-evm-windows-amd64-r1/"
                    "site-packages/slither_analyzer/__init__.py"
                ),
                "distribution": "slither-analyzer",
            },
        ],
        "install_observation": {
            "offline": True,
            "used_network": False,
            "used_index": False,
            "used_mutable_cache": False,
            "used_mutable_resolver": False,
            "user_site_enabled": False,
            "system_site_enabled": False,
        },
        "lifecycle": {
            "uninstall_generation": 1,
            "reinstall_generation": 2,
            "exclusive_owner_replayed": True,
            "process_quiescence_replayed": True,
            "unknown_bytes_after_uninstall": [],
            "used_prior_install_state": False,
            "used_prior_cache_state": False,
        },
        "advisory_history": {
            "historical_receipt_sha256": "c" * 64,
            "captured_advisory_snapshot_sha256": "d" * 64,
            "current_advisory_snapshot_sha256": "e" * 64,
            "historical_receipt_before_refresh_sha256": "c" * 64,
            "historical_receipt_after_refresh_sha256": "c" * 64,
        },
    }
    document["lifecycle_body_sha256"] = body_digest(
        document, "lifecycle_body_sha256"
    )
    _assert_local_positive(document)
    return document


def _normalized_distribution_names(
    rows: list[Mapping[str, Any]],
) -> set[str]:
    return {
        str(row["name"]).replace("_", "-").casefold()
        for row in rows
    }


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    governed = document["governed_distribution_artifacts"]
    observed = document["observed_distributions"]
    assert _normalized_distribution_names(governed) == (
        _normalized_distribution_names(observed)
    )
    governed_versions = {
        (
            row["name"].replace("_", "-").casefold(),
            row["version"],
            row["sha256"],
        )
        for row in governed
    }
    observed_versions = {
        (
            row["name"].replace("_", "-").casefold(),
            row["version"],
            row["artifact"]["sha256"],
        )
        for row in observed
    }
    assert governed_versions == observed_versions
    for distribution in observed:
        assert distribution["artifact"]["kind"] == "WHEEL"
        assert (
            distribution["artifact"]["governed_source_build_receipt"]
            is None
        )
        for row in distribution["record_files"]:
            assert row["sha256"] == row["record_sha256"]
            if row["file_class"] == "NATIVE_EXTENSION":
                assert row["dynamic_library_closure_digest"]
    prefix = document["semantic_prefix"]
    assert all(
        row["origin"].startswith(prefix)
        for row in document["observed_imports"]
    )
    install = document["install_observation"]
    assert install == {
        "offline": True,
        "used_network": False,
        "used_index": False,
        "used_mutable_cache": False,
        "used_mutable_resolver": False,
        "user_site_enabled": False,
        "system_site_enabled": False,
    }
    lifecycle = document["lifecycle"]
    assert lifecycle["reinstall_generation"] > lifecycle[
        "uninstall_generation"
    ]
    assert lifecycle["unknown_bytes_after_uninstall"] == []
    assert lifecycle["used_prior_install_state"] is False
    assert lifecycle["used_prior_cache_state"] is False
    advisory = document["advisory_history"]
    assert advisory[
        "historical_receipt_before_refresh_sha256"
    ] == advisory["historical_receipt_after_refresh_sha256"]
    assert document["lifecycle_body_sha256"] == body_digest(
        document, "lifecycle_body_sha256"
    )


def _resign(document: dict[str, Any]) -> None:
    document["lifecycle_body_sha256"] = body_digest(
        document, "lifecycle_body_sha256"
    )


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        INSTALLER_MODULE,
        "validate_provider_environment_lifecycle_v1",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_local_positive(document)
    require_accepts(validator, law, document)


def _require_targeted_rejection(
    validator: Callable[..., Any],
    law: str,
    reason_code: str,
    document: Mapping[str, Any],
) -> None:
    try:
        result = validator(document)
    except Exception as exc:
        assert reason_code in str(exc), (
            f"R21_B0_RED[{law}]: wrong rejection cause: "
            f"{exc.__class__.__name__}: {exc}; expected {reason_code}"
        )
        return
    assert isinstance(result, Mapping), (
        f"R21_B0_RED[{law}]: rejection must carry {reason_code}"
    )
    assert result.get("accepted") is False
    assert result.get("reason_code") == reason_code


def test_a14_missing_extra_or_drifted_distribution_rejected() -> None:
    law = "A14/exact-installed-distribution-set"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["observed_distributions"].append(
        _distribution("unexpected_plugin", "1.0.0", "f" * 64)
    )
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_DISTRIBUTION_SET_DIVERGED",
        mutation,
    )


def test_a14_record_owned_file_and_native_extension_drift_rejected() -> None:
    law = "A14/record-and-native-closure-byte-authority"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    native_row = next(
        file_row
        for distribution in mutation["observed_distributions"]
        for file_row in distribution["record_files"]
        if file_row["file_class"] == "NATIVE_EXTENSION"
    )
    native_row["sha256"] = "f" * 64
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_RECORD_OR_NATIVE_FILE_DRIFT",
        mutation,
    )


def test_a14_import_origin_outside_self_contained_prefix_rejected() -> None:
    law = "A14/import-origin-self-contained-prefix"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["observed_imports"][0]["origin"] = (
        "host-user-site://site-packages/crytic_compile/__init__.py"
    )
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_IMPORT_ORIGIN_OUTSIDE_PREFIX",
        mutation,
    )


def test_a14_ungoverned_source_build_rejected() -> None:
    law = "A14/source-build-requires-governed-receipt"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    artifact = mutation["observed_distributions"][0]["artifact"]
    artifact["kind"] = "SOURCE_BUILD"
    artifact["governed_source_build_receipt"] = None
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_UNGOVERNED_SOURCE_BUILD",
        mutation,
    )


def test_a14_mutable_cache_or_index_fallback_rejected() -> None:
    law = "A14/no-index-cache-or-mutable-resolution"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field in ("used_index", "used_mutable_cache"):
        mutation = deepcopy(positive)
        mutation["install_observation"][field] = True
        _resign(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A14_MUTABLE_INSTALL_FALLBACK",
            mutation,
        )


def test_a14_uninstall_reinstall_cannot_reuse_stale_state() -> None:
    law = "A14/reinstall-is-fresh-after-exact-uninstall"
    positive = _positive_lifecycle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["lifecycle"]["used_prior_install_state"] = True
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_STALE_INSTALL_STATE_REUSED",
        mutation,
    )


def test_a14_advisory_refresh_does_not_change_historical_receipt() -> None:
    law = "A14/advisory-refresh-is-forward-only"
    positive = _positive_lifecycle()
    assert (
        positive["advisory_history"][
            "captured_advisory_snapshot_sha256"
        ]
        != positive["advisory_history"][
            "current_advisory_snapshot_sha256"
        ]
    )
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["advisory_history"][
        "historical_receipt_after_refresh_sha256"
    ] = "f" * 64
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A14_HISTORICAL_RECEIPT_REWRITTEN",
        mutation,
    )
