"""The interfaces between layers (ARCHITECTURE.md section 3).

Core declares them; domain packs and mode adapters implement them; apps wire the implementations
together. Nothing here does I/O or knows which mode it runs in. Implementations conform
structurally (`typing.Protocol`), so they do not import this module to subclass it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from .models import Control as Control  # declared with the models; re-exported here
from .models import ControlRef as ControlRef
from .models import Finding

# --- Scanner -------------------------------------------------------------------------------------


@runtime_checkable
class Scanner(Protocol):
    """Runs one tool over a target and returns findings. Never executes, builds, installs or
    imports the scanned code (hard rule 1)."""

    name: str

    def is_available(self) -> bool: ...
    def version(self) -> str: ...
    def run(self, target: Path, workdir: Path) -> list[Finding]: ...


# --- TargetPack ----------------------------------------------------------------------------------


@runtime_checkable
class TargetPack(Protocol):
    """A versioned standard: its controls, and the mapping from a finding's evidence to them.
    The mapping is data from the standard's own tables, never model output."""

    id: str
    name: str
    version: str

    def controls(self) -> list[Control]: ...
    def controls_for(self, finding: Finding) -> list[ControlRef]: ...

    def checkable(self) -> frozenset[str]:
        """Control ids that automated evidence can speak to (a scanner rule or a weakness class
        maps to them). For the others, no finding never means "met": they need manual review."""
        ...


# --- Annotator ---------------------------------------------------------------------------------

AnnotatorStage = Literal["evidence", "context"]


@runtime_checkable
class Annotator(Protocol):
    """A domain pack's step inside normalize: adds facts to findings from the source tree or the
    pack's offline data (for security: secret facts, dependency reachability, KEV and EPSS).

    `evidence` annotators run before findings are merged and may merge or drop findings
    themselves; `context` annotators run after the stable IDs are assigned, before scoring."""

    stage: AnnotatorStage

    def annotate(self, findings: list[Finding], target: Path) -> list[Finding]: ...

    def data_dates(self) -> dict[str, str]:
        """Snapshot date of each offline dataset it read, shown with the report."""
        ...


# --- LLMProvider ---------------------------------------------------------------------------------


class LLMError(RuntimeError):
    """The model server failed, was unreachable, or returned an unusable response."""


@dataclass
class ChatResult:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_s: float = 0.0


@runtime_checkable
class LLMProvider(Protocol):
    """Chat completions. Callers validate structured output against its schema (hard rule 6).
    The local provider asserts a localhost or configured internal endpoint; a hosted provider
    receives redacted context only and is not built before the cloud threat model."""

    @property
    def model(self) -> str: ...

    def answer_settings(self) -> dict[str, Any]:
        """Settings besides the model that can change an answer (sampling, context window,
        backend). Part of the response cache key, so differently set-up providers never share
        cached answers."""
        ...

    def list_models(self) -> list[dict[str, Any]]: ...
    def chat(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | None = None,
        model: str | None = None,
        max_tokens: int = 700,
    ) -> ChatResult: ...


# --- Store -------------------------------------------------------------------------------------

ProjectId = TypeVar("ProjectId", contravariant=True)  # int in the local app, str in the team server


@runtime_checkable
class DecisionStore(Protocol[ProjectId]):
    """Reviewers' decisions per finding: accepted_risk, false_positive or fixed, with a note."""

    def decisions(self, project_id: ProjectId) -> list[dict[str, Any]]: ...
    def set_decision(
        self, project_id: ProjectId, finding_id: str, decision: str, note: str
    ) -> None: ...
    def clear_decision(self, project_id: ProjectId, finding_id: str) -> None: ...


@runtime_checkable
class MemoryStore(Protocol[ProjectId]):
    """Reviewers' triage memories per project (`gapscan.memory`), stored as their JSON form."""

    def memories(self, project_id: ProjectId) -> list[dict[str, Any]]: ...
    def save_memory(self, project_id: ProjectId, memory: dict[str, Any]) -> None: ...
    def delete_memory(self, project_id: ProjectId, memory_id: str) -> bool: ...


@runtime_checkable
class Store(DecisionStore[ProjectId], MemoryStore[ProjectId], Protocol[ProjectId]):
    """What the engine reads and writes per project. Both apps keep their own schema on the shared
    SQL layer (`gapscan/store/sql.py`); the team server implements `DecisionStore` only."""


# --- Egress --------------------------------------------------------------------------------------


class EgressDisabled(RuntimeError):
    """Something tried to send data out of a composition that has no egress."""


@runtime_checkable
class Egress(Protocol):
    """The only way data leaves the engine (hard rule 2). The cloud implementation sends redacted
    evidence and fingerprints to the configured service host only."""

    def send(self, kind: str, payload: BaseModel) -> None: ...


class NoEgress:
    """The local composition's egress: refuses every send, so nothing can fall back to the cloud
    silently. A send here is a bug in the caller, so it raises instead of dropping the data."""

    def send(self, kind: str, payload: BaseModel) -> None:
        raise EgressDisabled(f"no egress in this composition; refused to send {kind!r}")
