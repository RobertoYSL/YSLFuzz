"""Benchmark command handler."""

from __future__ import annotations

import argparse

from yslfuzz.benchmark import BenchmarkConfigLoader, BenchmarkRunner


def run_benchmark_command(args: argparse.Namespace) -> int:
    """Run the benchmark command and return a process exit code."""
    config = BenchmarkConfigLoader().load(args.config)
    result = BenchmarkRunner(
        config,
        args.output_dir,
        fail_fast=bool(args.fail_fast),
        force_dry_run=bool(args.dry_run),
        overwrite=bool(args.overwrite),
        verbose=bool(args.verbose),
    ).run()
    failed_jobs = sum(1 for job in result.jobs if job.status == "failed")
    print(
        "YSLFuzz benchmark complete: "
        f"benchmark_id={result.benchmark_id}, jobs={len(result.jobs)}, "
        f"failed={failed_jobs}, status={result.status}, output_dir={args.output_dir}"
    )
    return 1 if result.status == "failed" else 0
