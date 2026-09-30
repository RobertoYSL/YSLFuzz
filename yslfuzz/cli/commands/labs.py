"""Labs command handler."""

from __future__ import annotations

import argparse
import json

from yslfuzz.labs import LabCatalog


def run_labs_command(args: argparse.Namespace) -> int:
    """Run the labs catalog command and return a process exit code."""
    manifests = LabCatalog.discover(args.root)
    if args.labs_command == "list":
        for manifest in manifests:
            print(
                f"{manifest.lab_id}\t{manifest.lab_name}\t"
                f"{manifest.lab_version}\t{manifest.api_style.value}"
            )
        return 0

    lab_id = args.lab
    for manifest in manifests:
        if manifest.lab_id == lab_id:
            print(json.dumps(manifest.catalog_summary(), indent=2, sort_keys=True))
            return 0
    raise ValueError(f"Unknown lab: {lab_id}")
