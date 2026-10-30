"""USD budget. A run stops before the next paid call once 80% is spent."""

from __future__ import annotations

from dataclasses import dataclass, field

from alien_hunt.config import Prices


class BudgetStop(Exception):
    """Raised when another paid call would pass the stop line."""


@dataclass
class Charge:
    """One billed model call."""

    stage: str
    usd: float
    prompt_tokens: int
    completion_tokens: int
    estimated: bool


@dataclass
class Budget:
    """Accumulates token spend and refuses work past 80% of the limit."""

    limit_usd: float
    entries: list[Charge] = field(default_factory=list)

    @property
    def spent(self) -> float:
        return sum(entry.usd for entry in self.entries)

    def should_stop(self) -> bool:
        """True once spend has reached the stop line, or the limit is empty."""

        if self.limit_usd <= 0:
            return True
        return self.spent >= 0.8 * self.limit_usd

    def charge_tokens(
        self,
        stage: str,
        prompt_tokens: int,
        completion_tokens: int,
        prices: Prices,
        *,
        embedding: bool = False,
        estimated: bool = False,
    ) -> float:
        """Add the cost of one call. Embedding calls bill the input price only."""

        if embedding:
            usd = (prompt_tokens / 1_000_000) * prices.embedding_per_mtok
            completion_tokens = 0
        else:
            usd = (prompt_tokens / 1_000_000) * prices.input_per_mtok
            usd += (completion_tokens / 1_000_000) * prices.output_per_mtok
        self.entries.append(
            Charge(
                stage=stage,
                usd=usd,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                estimated=estimated,
            )
        )
        return usd

    def spent_on(self, stage: str) -> float:
        return sum(entry.usd for entry in self.entries if entry.stage == stage)

    def as_dict(self) -> dict:
        return {
            "limit_usd": self.limit_usd,
            "spent_usd": self.spent,
            "stop_line_usd": 0.8 * self.limit_usd,
            "entries": [entry.__dict__ for entry in self.entries],
        }
