"""Shared records for a hunt run."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class ToolCall:
    """One function call requested by the model."""

    id: str
    name: str
    arguments: dict


@dataclass
class ChatResponse:
    """Normalized chat result, independent of the vendor SDK."""

    text: str
    tool_calls: list[ToolCall]
    prompt_tokens: int
    completion_tokens: int
    estimated: bool = False


@dataclass
class EmbedResponse:
    """Embedding vectors in the same order as the input texts."""

    vectors: list[list[float]]
    prompt_tokens: int
    estimated: bool = False


@dataclass
class Claim:
    """A defect claim. The reproducer stays out of the published report."""

    text: str
    class_label: str
    files: list[str]
    functions: list[str]
    reproducer: str
    origin: str
    candidate_id: str | None = None

    def public_dict(self) -> dict:
        """Fields safe to keep in stage JSON. The reproducer is omitted."""

        return {
            "text": self.text,
            "class": self.class_label,
            "files": list(self.files),
            "functions": list(self.functions),
            "origin": self.origin,
            "candidate_id": self.candidate_id,
        }


@dataclass
class Atom:
    """One ingredient of a defect combination."""

    kind: str
    id: str
    text: str
    file: str | None = None
    function: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    """A sampled (source, mechanism, sink-or-invariant) triple."""

    id: str
    source: Atom
    mechanism: Atom
    other: Atom
    coherence: float | None = None
    path: list[str] = field(default_factory=list)
    named_functions: list[str] = field(default_factory=list)
    unavailability: float | None = None
    z_coherence: float | None = None
    z_unavailability: float | None = None
    score_0_7: float | None = None
    score_0_4: float | None = None
    incoherent: bool | None = None
    path_exists: bool | None = None

    def triple_text(self) -> str:
        return f"{self.source.text} || {self.mechanism.text} || {self.other.text}"

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["text"] = self.triple_text()
        return payload


@dataclass
class Confirmation:
    """Result of trying to observe a claim."""

    confirmed: bool
    why: str
    exit_code: int | None = None
    output: str = ""
    calls: list[str] = field(default_factory=list)


@dataclass
class KnownAdvisory:
    """A public advisory a claim may cite when its symbols and class match."""

    id: str
    class_label: str
    symbols: list[str]
    cve: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)
