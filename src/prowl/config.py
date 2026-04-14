from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    project_type: str = "auto"
    detection_categories: list[str] = Field(default_factory=lambda: [
        "auth", "data_access", "crypto", "input", "financial",
        "privilege", "memory", "injection", "concurrency",
    ])

class ReconConfig(BaseModel):
    min_likelihood_score: float = 1.0
    max_review_chunks: int = 100
    interaction_targets: bool = True
    auto_exclude: bool = True
    auto_exclude_override: list[str] = Field(default_factory=list)

class ScoringConfig(BaseModel):
    hypothesis_confidence_threshold: float = 0.7
    batch_confidence_threshold: float = 0.4
    max_promoted_findings: int = 100

class TriageConfig(BaseModel):
    reachability: bool = True
    chain_analysis: bool = True
    patch: bool = True
    patch_iterations: int = 3

class ValidationConfig(BaseModel):
    enabled: bool = True
    severity_gate: str = "high"
    max_exploits: int = 10
    max_iterations_simple: int = 3
    max_iterations_medium: int = 5
    max_iterations_memory: int = 5
    max_iterations_chain: int = 8
    instrumentation: list[str] = Field(default_factory=lambda: ["asan", "ubsan", "coverage"])
    # Claw backend settings
    claw_timeout_default: int = 720
    claw_timeout_memory: int = 1080
    claw_timeout_build: int = 1800
    claw_max_turns: int = 30
    claw_max_turns_build: int = 50
    claw_api_key_env: str | None = None

class SandboxConfig(BaseModel):
    runtime: str = "docker"
    timeout_default: int = 180
    timeout_race_condition: int = 720
    timeout_max: int = 1800
    timeout_startup: int = 180
    mem_limit: str = "512m"
    mem_limit_build: str = "2g"
    cpu_quota: int = 200000
    cpu_quota_build: int = 400000
    pids_limit: int = 256
    network: str = "none"
    tier3_services: list[str] = Field(default_factory=lambda: ["postgres", "mysql", "redis"])

class ConcurrencyConfig(BaseModel):
    max_concurrent_hypotheses: int = 8
    max_concurrent_triage: int = 4
    max_concurrent_validations: int = 2

class BudgetConfig(BaseModel):
    max_tokens_per_scan: int | None = None
    max_cost_per_scan: float | None = None
    layer3_budget_fraction: float = 0.4

class CacheConfig(BaseModel):
    enabled: bool = True
    invalidation: str = "interface"
    cross_cutting_invalidation: bool = True

class OutputConfig(BaseModel):
    format: str = "text"
    include_poc: bool = True
    include_reasoning: bool = False

class ResumeConfig(BaseModel):
    enabled: bool = True
    state_dir: str = ".prowl/scan-state"

class LLMLayerConfig(BaseModel):
    provider: str | None = None
    model: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None

class LLMConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-opus-4-6"
    api_key_env: str | None = None
    base_url: str | None = None
    temperature: float = 0.0
    hypothesis: LLMLayerConfig = Field(default_factory=LLMLayerConfig)
    triage: LLMLayerConfig = Field(default_factory=LLMLayerConfig)
    validation: LLMLayerConfig = Field(default_factory=LLMLayerConfig)

class ArgusConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    reconnaissance: ReconConfig = Field(default_factory=ReconConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    resume: ResumeConfig = Field(default_factory=ResumeConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)

def load_config(project_root: Path) -> ArgusConfig:
    config_path = project_root / "prowl.yml"
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return ArgusConfig.model_validate(data)
    return ArgusConfig()
