"""Run configuration. The API key is named here and read from the environment."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    """The config file is missing a field or has a bad value."""


@dataclass(frozen=True)
class Prices:
    """USD per million tokens."""

    input_per_mtok: float
    output_per_mtok: float
    embedding_per_mtok: float


@dataclass(frozen=True)
class Endpoint:
    """A second OpenAI-compatible endpoint, for embeddings only (`[embedding]` in the config)."""

    base_url: str
    model: str
    api_key_env: str

    def api_key(self) -> str:
        """Read the key from the environment. Never log the return value."""

        return _env_key(self.api_key_env)


@dataclass(frozen=True)
class Config:
    """Model endpoint and hunt limits. The key itself is not stored."""

    base_url: str
    model: str
    embedding_model: str
    api_key_env: str
    prices: Prices
    max_tokens_per_hunt: int
    container_image: str
    max_tool_rounds_review: int = 8
    max_tool_rounds_hunt: int = 6
    sample_limit: int = 80
    coherence_batch: int = 10
    embedding: Endpoint | None = None
    temperature: float | None = 0.0  # None: the parameter is not sent (some models refuse it)
    max_output_tokens: int = 4000  # one reply's limit: a review's claims with reproducers, a batch of ratings
    min_coherence: float = 3.0  # candidates rated below this are not hunted
    fallback_hunts: int = 3  # when none reaches the floor, hunt this many of the best rated 2

    def api_key(self) -> str:
        """Read the key from the environment. Never log the return value."""

        return _env_key(self.api_key_env)

    def secrets(self) -> tuple[str, ...]:
        """Every key this run uses, for redaction."""

        return (self.api_key(),) + ((self.embedding.api_key(),) if self.embedding else ())


def _env_key(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"environment variable {name} is not set")
    return value


def _required(data: dict, key: str) -> object:
    if key not in data:
        raise ConfigError(f"config is missing {key}")
    return data[key]


def _positive_float(data: dict, key: str) -> float:
    value = _required(data, key)
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be a number") from exc
    if number < 0:
        raise ConfigError(f"{key} must be >= 0")
    return number


def _rating(data: dict, key: str, default: float) -> float:
    try:
        number = float(data.get(key, default))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be a number") from exc
    if not 1 <= number <= 5:
        raise ConfigError(f"{key} must be between 1 and 5")
    return number


def _count(data: dict, key: str, default: int) -> int:
    try:
        number = int(data.get(key, default))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if number < 0:
        raise ConfigError(f"{key} must be >= 0")
    return number


def _positive_int(data: dict, key: str, default: int | None = None) -> int:
    if key not in data:
        if default is None:
            raise ConfigError(f"config is missing {key}")
        return default
    try:
        number = int(data[key])
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if number <= 0:
        raise ConfigError(f"{key} must be > 0")
    return number


def _temperature(data: dict) -> float | None:
    """0 when absent, as before; `temperature = false` leaves the parameter out of every chat request."""

    if "temperature" not in data:
        return 0.0
    value = data["temperature"]
    if value is False:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 2:
        raise ConfigError("temperature must be a number from 0 to 2, or false to leave it out")
    return float(value)


def load_config(path: Path) -> Config:
    """Load a TOML config. The key field is the name of an environment variable."""

    if not path.is_file():
        raise ConfigError(f"config file {path} does not exist")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"could not parse {path}: {exc}") from exc
    prices = Prices(
        input_per_mtok=_positive_float(data, "price_input_per_mtok"),
        output_per_mtok=_positive_float(data, "price_output_per_mtok"),
        embedding_per_mtok=_positive_float(data, "price_embedding_per_mtok"),
    )
    embedding = None
    if "embedding" in data:
        table = data["embedding"]
        if not isinstance(table, dict):
            raise ConfigError("[embedding] must be a table")
        embedding = Endpoint(
            base_url=str(_required(table, "base_url")).rstrip("/"),
            model=str(_required(table, "model")),
            api_key_env=str(_required(table, "api_key_env")),
        )
    return Config(
        embedding=embedding,
        base_url=str(_required(data, "base_url")).rstrip("/"),
        model=str(_required(data, "model")),
        embedding_model=embedding.model if embedding else str(_required(data, "embedding_model")),
        api_key_env=str(_required(data, "api_key_env")),
        prices=prices,
        max_tokens_per_hunt=_positive_int(data, "max_tokens_per_hunt"),
        container_image=str(_required(data, "container_image")),
        max_tool_rounds_review=_positive_int(data, "max_tool_rounds_review", 8),
        max_tool_rounds_hunt=_positive_int(data, "max_tool_rounds_hunt", 6),
        sample_limit=_positive_int(data, "sample_limit", 80),
        coherence_batch=_positive_int(data, "coherence_batch", 10),
        temperature=_temperature(data),
        max_output_tokens=_positive_int(data, "max_output_tokens", 4000),
        min_coherence=_rating(data, "min_coherence", 3.0),
        fallback_hunts=_count(data, "fallback_hunts", 3),
    )
