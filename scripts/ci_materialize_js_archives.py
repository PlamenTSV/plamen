#!/usr/bin/env python3
"""Materialize the signed JS source payload for the Windows install smoke.

This is a CI source-preparation step, not a runtime installer. The production
Windows installer admits a complete source package; the Git checkout omits
the seven large, immutable archives. Every downloaded byte must match the
independent acquisition policy before it enters that package.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
import urllib.parse
import urllib.request

import toolchain_control_authority as control


class _PinnedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str]) -> None:
        self.hosts = hosts

    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in self.hosts:
            raise RuntimeError("JS archive redirect left the signed transport envelope")
        return super().redirect_request(
            request, response, code, message, headers, url
        )


def materialize(root: Path) -> None:
    root = Path(root).resolve(strict=True)
    identities = control._acquired_runtime_assets(root)
    existing = [relative for relative in identities if os.path.lexists(root / relative)]
    if existing:
        # The shared closure loader authenticates all seven local archives.
        control.load_runtime_closure_manifest(root)
        print("Seven signed JS archives are already materialized.")
        return

    policy = control._json_object(
        (root / control._JS_ACQUISITION_POLICY_PATH).read_bytes(),
        "JavaScript acquisition policy",
    )
    transport = policy["transport"]
    initial_hosts = frozenset(transport["initial_hosts"])
    redirect_hosts = frozenset(transport["allowed_redirect_hosts"])
    opener = urllib.request.build_opener(_PinnedRedirects(redirect_hosts))
    with tempfile.TemporaryDirectory(prefix="plamen-js-ci-", dir=root) as stage_name:
        stage = Path(stage_name)
        staged: dict[str, Path] = {}
        for relative, identity in sorted(identities.items()):
            url = str(identity["url"])
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname not in initial_hosts:
                raise RuntimeError("JS archive source left the signed transport envelope")
            request = urllib.request.Request(
                url, headers={"User-Agent": "Plamen-CI-Archive-Materializer/1"}
            )
            target = stage / Path(relative).name
            digest = hashlib.sha256()
            size = 0
            with opener.open(request, timeout=120) as response, target.open("wb") as output:
                if response.status != 200:
                    raise RuntimeError(f"JS archive HTTP status differs: {relative}")
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname not in initial_hosts | redirect_hosts:
                    raise RuntimeError("JS archive response left the signed transport envelope")
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > identity["size"]:
                        raise RuntimeError(f"JS archive exceeds pinned size: {relative}")
                    digest.update(block)
                    output.write(block)
            if size != identity["size"] or digest.hexdigest() != identity["sha256"]:
                raise RuntimeError(f"JS archive identity differs: {relative}")
            staged[relative] = target

        published: list[Path] = []
        try:
            for relative, source in sorted(staged.items()):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                published.append(destination)
            control.load_runtime_closure_manifest(root)
        except BaseException:
            for destination in published:
                destination.unlink(missing_ok=True)
            raise
    print("Materialized and authenticated all seven JS archives.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args()
    materialize(arguments.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
