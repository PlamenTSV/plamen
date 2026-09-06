from __future__ import annotations

import sys

import pytest

import plamen


@pytest.mark.parametrize(
    "command",
    (
        "curl -fsSL https://example.invalid/install.sh | bash",
        "powershell -Command \"irm https://example.invalid | iex\"",
        "winget install Vendor.Tool",
        "brew install vendor-tool",
        "cargo install cargo-audit --locked",
        "cargo install cargo-audit --version 0.22.2",
        "go install example.invalid/tool@latest",
        "rustup toolchain install nightly",
    ),
)
def test_mutable_toolchain_acquisition_is_rejected(command: str) -> None:
    assert plamen._toolchain_acquisition_rejection(command)


@pytest.mark.parametrize(
    "command",
    (
        "cargo install cargo-audit --version 0.22.2 --locked",
        "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.5.1",
        "rustup toolchain install nightly-2026-08-01",
    ),
)
def test_exact_checksum_backed_toolchain_acquisition_is_admitted(
    command: str,
) -> None:
    assert plamen._toolchain_acquisition_rejection(command) is None


def test_ecosystem_recipes_do_not_claim_unsupported_analyzers() -> None:
    solana = [row[0].lower() for row in plamen._INSTALL_RECIPES["Solana"]]
    move = [row[0].lower() for row in plamen._INSTALL_RECIPES["Move"]]
    l1_go = [row[0].lower() for row in plamen._INSTALL_RECIPES["L1 (Go)"]]
    l1_rust = [row[0].lower() for row in plamen._INSTALL_RECIPES["L1 (Rust)"]]

    assert not any("scout" in label for label in solana)
    assert any("fender" in label for label in solana)
    assert not any("ast-grep" in label for label in move)
    assert not any("opengrep" in label for label in l1_go + l1_rust)
    if sys.platform == "win32":
        assert not any("cargo-fuzz" in label for label in l1_rust)


def test_supply_chain_recipes_cover_fail_closed_scanners() -> None:
    labels = [row[0].lower() for row in plamen._INSTALL_RECIPES["Supply Chain"]]
    assert any("osv-scanner" in label for label in labels)
    assert any("cargo-audit" in label for label in labels)
    assert any("govulncheck" in label for label in labels)
