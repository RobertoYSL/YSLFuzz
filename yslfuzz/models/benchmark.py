"""Benchmark harness data models."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import AttackCategory


class BenchmarkJobConfig(YSLFuzzModel):
    """Configuration for one benchmark scan/evaluation job."""

    job_id: str
    job_name: str
    target_name: str
    base_url: str
    openapi_path: str
    ground_truth_path: str | None = None
    output_subdir: str | None = None
    max_requests: int | None = None
    timeout: float = 10.0
    dry_run: bool = True
    allow_destructive: bool = False
    include_boundary_payloads: bool = False
    include_invalid_payloads: bool = False
    include_mutated_payloads: bool = False
    include_attack_payloads: bool = False
    execute_mutations: bool = False
    execute_attacks: bool = False
    enabled_attack_categories: list[AttackCategory] = Field(default_factory=list)
    max_mutations_per_payload: int = 50
    max_mutations_per_field: int = 4
    max_attack_requests_per_endpoint: int = 5
    i_understand_attack_execution_is_authorized: bool = False
    i_understand_mutation_execution_is_authorized: bool = False
    notes: str | None = None

    @model_validator(mode="after")
    def validate_authorization_and_limits(self) -> "BenchmarkJobConfig":
        """Require explicit authorization for attack and mutation execution."""
        if self.execute_attacks and not self.i_understand_attack_execution_is_authorized:
            raise ValueError("execute_attacks requires attack execution authorization")
        if self.execute_mutations and not self.i_understand_mutation_execution_is_authorized:
            raise ValueError("execute_mutations requires mutation execution authorization")
        if self.max_requests is not None and self.max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if self.max_mutations_per_payload < 0:
            raise ValueError("max_mutations_per_payload must be non-negative")
        if self.max_mutations_per_field < 0:
            raise ValueError("max_mutations_per_field must be non-negative")
        if self.max_attack_requests_per_endpoint < 0:
            raise ValueError("max_attack_requests_per_endpoint must be non-negative")
        return self

    @property
    def effective_output_subdir(self) -> str:
        """Return the deterministic output directory name for the job."""
        return self.output_subdir or self.job_id


class BenchmarkConfig(YSLFuzzModel):
    """Configuration for a benchmark run."""

    benchmark_id: str
    benchmark_name: str
    benchmark_version: str
    description: str | None = None
    random_seed: int = 0
    output_naming_strategy: str = "job_id"
    jobs: list[BenchmarkJobConfig]

    @model_validator(mode="after")
    def validate_jobs(self) -> "BenchmarkConfig":
        """Require at least one job and unique job IDs."""
        if not self.jobs:
            raise ValueError("benchmark config requires at least one job")
        job_ids = [job.job_id for job in self.jobs]
        if len(job_ids) != len(set(job_ids)):
            raise ValueError("benchmark job_id values must be unique")
        return self


class BenchmarkArtifact(YSLFuzzModel):
    """Artifact produced by a benchmark job or run."""

    artifact_id: str = Field(default_factory=lambda: prefixed_id("benchmark_artifact"))
    artifact_type: str
    path: str


BenchmarkJobStatus = Literal["completed", "failed", "skipped"]


class BenchmarkJobResult(YSLFuzzModel):
    """Result for one benchmark job."""

    job_id: str
    job_name: str
    target_name: str
    status: BenchmarkJobStatus
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    scan_report_path: str | None = None
    evaluation_output_dir: str | None = None
    error_message: str | None = None
    metrics_summary: dict[str, Any] = Field(default_factory=dict)
    reproducibility: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[BenchmarkArtifact] = Field(default_factory=list)


class BenchmarkRunResult(YSLFuzzModel):
    """Complete benchmark run result."""

    benchmark_id: str
    benchmark_name: str
    benchmark_version: str
    status: BenchmarkJobStatus
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    random_seed: int = 0
    config_hash: str
    jobs: list[BenchmarkJobResult] = Field(default_factory=list)
    artifacts: list[BenchmarkArtifact] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
