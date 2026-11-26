"""Configuration loading: TOML file + GAPSCAN_ env vars, validated with pydantic.

Precedence (highest first): env vars > config file > defaults. The config file is
located via the GAPSCAN_CONFIG env var, an explicit path, or by searching upward
from the current directory for `gapscan.toml`.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

CONFIG_ENV_VAR = "GAPSCAN_CONFIG"
CONFIG_FILENAME = "gapscan.toml"

# Hosts we accept for the LLM endpoint. Hard rule #2: localhost or an explicitly
# configured internal host only — never a public URL.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
# Names reserved for private networks: mDNS (.local), ICANN's private-use TLD (.internal, 2024),
# home networks (.home.arpa, RFC 8375) and loopback names (.localhost, RFC 6761).
_INTERNAL_SUFFIXES = (".local", ".internal", ".home.arpa", ".localhost")


def endpoint_allowed(url: str, internal_hosts: Iterable[str] = ()) -> bool:
    """Hard rule #2: localhost, a private address, a private-use name, or a host the owner listed
    in `llm.internal_hosts` (exact name, or `*.corp.example.com` for every name under it)."""
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if not host:
        return False
    if host in _LOCAL_HOSTS or host.endswith(_INTERNAL_SUFFIXES) or _is_private_host(host):
        return True
    for entry in internal_hosts:
        entry = entry.strip().lower().rstrip(".")
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif entry and host == entry:
            return True
    return False


def remote_endpoint_ok(url: str) -> bool:
    """A hosted model endpoint the user opted into (`llm.allow_remote`): HTTPS with a host name."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname)


def endpoint_is_remote(cfg: LLMConfig) -> bool:
    """True when triage will send prompts off this machine and its private network."""
    return cfg.allow_remote and not endpoint_allowed(cfg.endpoint, cfg.internal_hosts)


class GeneralConfig(BaseModel):
    max_llm_findings: int = 200
    vuln_data_max_age_days: int = 30
    asvs_level: int = Field(default=2, ge=1, le=3)  # which ASVS requirements coverage targets


class DataConfig(BaseModel):
    dir: Path = Path("data")
    kb_dir: Path = Path("data/kb")
    # Offline mirrors of CISA KEV (kev.json) and FIRST EPSS (epss.csv), from the bundle.
    enrichment_dir: Path = Path("data/enrichment")
    eval_dir: Path = Path(
        "data/eval-targets"
    )  # benchmark apps for `gapscan eval` (never committed)


class ModelProfile(BaseModel):
    """A named, swappable model choice with the budgets that suit its size."""

    model: str
    context_tokens: int = 16384  # the context window to request
    code_context_tokens: int = 4000  # budget for one finding's code context
    note: str = ""


# Built-in profiles. Picked by judgement (not yet benchmarked): swap via llm.profile or
# `gapscan model bench` when it underperforms;
# override or add profiles under [llm.profiles.<name>] in gapscan.toml.
BUILTIN_PROFILES: dict[str, ModelProfile] = {
    "best": ModelProfile(model="qwen3-coder:30b", context_tokens=32768, code_context_tokens=8000,
                         note="default; ~19 GB, MoE (3B active), code-specific"),
    "tiny": ModelProfile(model="granite4.2:3b", context_tokens=8192, code_context_tokens=2000,
                         note="~2 GB; benchmarked: NOT recommended (confirms almost everything)"),
    "small": ModelProfile(model="granite4.2:8b", context_tokens=16384, code_context_tokens=4000,
                          note="~5 GB"),
    "balanced": ModelProfile(model="qwen2.5-coder:14b", context_tokens=16384,
                             code_context_tokens=6000, note="stronger on code; ~9 GB"),
}  # fmt: skip


class TierConfig(BaseModel):
    """A hardware tier: which profile it uses and, optionally, which (internal) server runs it."""

    profile: str
    endpoint: str = ""  # empty: the main `endpoint`
    note: str = ""


# Same prompts at every tier; only the model (and where it runs) changes.
BUILTIN_TIERS: dict[str, TierConfig] = {
    "ci": TierConfig(profile="small", note="CI runners and small laptops (8B class)"),
    "laptop": TierConfig(profile="balanced", note="developer laptops (14B class)"),
    "server": TierConfig(profile="best", note="a GPU server for the team platform (30B class)"),
}


class LLMConfig(BaseModel):
    backend: str = "ollama"
    endpoint: str = "http://localhost:11434"
    # Pick a model by profile name, or set `model` to any Ollama/OpenAI-compatible model id
    # (an explicit `model` always wins; so does GAPSCAN_LLM__MODEL).
    profile: str = "best"
    profiles: dict[str, ModelProfile] = Field(default_factory=dict)  # user additions/overrides
    # Or pick by hardware tier (ci / laptop / server, or your own under [llm.tiers.<name>]). A tier
    # sets the profile and may point at a different internal server; explicit settings still win.
    tier: str = ""
    tiers: dict[str, TierConfig] = Field(default_factory=dict)
    model: str = ""
    think: bool = False  # ask reasoning models to skip their thinking phase (faster, JSON-safe)
    embedding_model: str = "nomic-embed-text"
    embedding_endpoint: str = ""  # empty: the same server as `endpoint`
    # Internal model servers known by DNS name: ["llm.corp.example.com", "*.gpu.example.com"].
    # Private addresses and .local/.internal/.home.arpa names need no entry. Never a public service.
    internal_hosts: list[str] = Field(default_factory=list)
    # Opt-in: let triage use any hosted model over HTTPS: an OpenAI-compatible API (OpenAI,
    # Anthropic, Gemini, Mistral, Groq, DeepSeek, OpenRouter, Azure, a gateway) or a hosted Ollama.
    # Off by default; turning it on is the user's agreement to send prompts there. `scan` never
    # calls a model either way; what is sent is the bounded, secret-masked prompt for each finding.
    # The API key is read from the environment variable named here, never from this file.
    allow_remote: bool = False
    api_key_env: str = "GAPSCAN_LLM_API_KEY"
    # "Authorization" sends `Bearer <key>`; any other name (Azure: "api-key") sends the key as is.
    api_key_header: str = "Authorization"
    temperature: float = 0.0
    seed: int = 7
    timeout_s: int = 120
    context_tokens: int = 16384  # the model's context window
    code_context_tokens: int = 4000  # budget for one finding's code context

    @model_validator(mode="after")
    def _apply_tier(self) -> LLMConfig:
        if not self.tier:
            return self
        tiers = {**BUILTIN_TIERS, **self.tiers}
        if self.tier not in tiers:
            raise ValueError(f"unknown llm.tier {self.tier!r}; choose one of {sorted(tiers)}")
        chosen = tiers[self.tier]
        explicit = self.model_fields_set
        if "profile" not in explicit:
            self.profile = chosen.profile
        if chosen.endpoint and "endpoint" not in explicit:
            self.endpoint = chosen.endpoint  # checked with every other endpoint below
        return self

    @model_validator(mode="after")
    def _apply_profile(self) -> LLMConfig:
        available = {**BUILTIN_PROFILES, **self.profiles}
        if self.profile not in available:
            raise ValueError(
                f"unknown llm.profile {self.profile!r}; choose one of {sorted(available)} "
                "or define [llm.profiles.<name>]"
            )
        chosen = available[self.profile]
        explicit = self.model_fields_set
        if not self.model:
            self.model = chosen.model
        # Budgets follow the profile unless set explicitly.
        if "context_tokens" not in explicit:
            self.context_tokens = chosen.context_tokens
        if "code_context_tokens" not in explicit:
            self.code_context_tokens = chosen.code_context_tokens
        return self

    @property
    def all_profiles(self) -> dict[str, ModelProfile]:
        return {**BUILTIN_PROFILES, **self.profiles}

    @model_validator(mode="after")
    def _endpoints_must_be_local(self) -> LLMConfig:
        from urllib.parse import urlparse

        local = endpoint_allowed(self.endpoint, self.internal_hosts)
        if self.allow_remote and not local and not remote_endpoint_ok(self.endpoint):
            raise ValueError("llm.endpoint must be an https:// URL when llm.allow_remote is on")
        for name in ("endpoint", "embedding_endpoint"):
            url = getattr(self, name)
            if name == "embedding_endpoint" and not url:
                continue
            if name == "endpoint" and self.allow_remote:
                continue  # checked above; the knowledge-base embeddings always stay local
            if not endpoint_allowed(url, self.internal_hosts):
                raise ValueError(
                    f"llm.{name} host {urlparse(url).hostname or url!r} is not local or internal. "
                    "GapScan refuses public endpoints (hard rule: no network at scan time); list "
                    "an internal model server by name in llm.internal_hosts, or opt in to a "
                    "hosted model for triage with llm.allow_remote (see docs/ai-upgrades.md)."
                )
        return self


class AgentConfig(BaseModel):
    use_tools: bool = True  # let the model call read-only tools before answering
    max_tool_calls: int = Field(default=4, ge=0, le=10)  # then the verdict is forced
    # Deep-dive pass: confirmed findings at or above this priority get a
    # detailed investigation with a larger tool budget.
    deep_dive_tool_calls: int = Field(default=12, ge=1, le=30)
    deep_dive_min_priority: float = Field(default=60.0, ge=0, le=100)


class FlywheelConfig(BaseModel):
    """Opt-in, on-premises: reviewer decisions can be exported as a fine-tuning dataset for this
    organization's own model. Nothing is ever sent anywhere; the export is a local file."""

    enabled: bool = False
    holdout_percent: int = Field(default=20, ge=5, le=50)  # kept out of training, for evaluation


class KBConfig(BaseModel):
    policies_dir: Path = Path("policies")  # optional folder of the owner's own Markdown policies


class SemgrepConfig(BaseModel):
    rules_path: Path = Path("data/semgrep-rules")


class OSVConfig(BaseModel):
    db_dir: Path = Path("data/osv-db")


class TrivyConfig(BaseModel):
    cache_dir: Path = Path("data/trivy-cache")


class ScannersConfig(BaseModel):
    timeout_s: int = 300
    # Packs allowed to register scanners (`gapscan.packs` entry points). Any other installed pack is
    # ignored before its code runs: a scanner runs during `scan`, so only an admin may add one.
    packs: list[str] = Field(default_factory=lambda: ["security"])
    enabled: list[str] = Field(
        default_factory=lambda: [
            "semgrep",
            "osv",
            "trivy",
            "gitleaks",
            "checkov",
            "bandit",
            "taint",
            "malware",
        ]
    )
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    osv: OSVConfig = Field(default_factory=OSVConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)


def _is_private_host(host: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


class Config(BaseSettings):
    """Top-level GapScan configuration."""

    model_config = SettingsConfigDict(
        env_prefix="GAPSCAN_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    data: DataConfig = Field(default_factory=DataConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    flywheel: FlywheelConfig = Field(default_factory=FlywheelConfig)
    kb: KBConfig = Field(default_factory=KBConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: env > TOML file (passed in via init kwargs) > defaults.
        return (env_settings, dotenv_settings, init_settings, file_secret_settings)


def find_config_file(explicit: Path | None = None, start: Path | None = None) -> Path | None:
    """Resolve the config file path, or None if there isn't one."""
    if explicit is not None:
        return explicit
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return Path(env_path)
    cursor = (start or Path.cwd()).resolve()
    for directory in [cursor, *cursor.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def _read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load_config(config_path: Path | None = None, start: Path | None = None) -> Config:
    """Load configuration from TOML (if present) overlaid with GAPSCAN_ env vars."""
    path = find_config_file(config_path, start)
    file_values: dict[str, Any] = {}
    if path is not None:
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")
        file_values = _read_toml(path)
    # Env vars take precedence over file values via BaseSettings resolution.
    return Config(**file_values)
