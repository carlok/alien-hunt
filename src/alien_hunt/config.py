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

    def api_key(self) -> str:
        """Read the key from the environment. Never log the return value."""

        value = os.environ.get(self.api_key_env, "")
        if not value:
            raise ConfigError(f"environment variable {self.api_key_env} is not set")
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
    return Config(
        base_url=str(_required(data, "base_url")).rstrip("/"),
        model=str(_required(data, "model")),
        embedding_model=str(_required(data, "embedding_model")),
        api_key_env=str(_required(data, "api_key_env")),
        prices=prices,
        max_tokens_per_hunt=_positive_int(data, "max_tokens_per_hunt"),
        container_image=str(_required(data, "container_image")),
        max_tool_rounds_review=_positive_int(data, "max_tool_rounds_review", 8),
        max_tool_rounds_hunt=_positive_int(data, "max_tool_rounds_hunt", 6),
        sample_limit=_positive_int(data, "sample_limit", 80),
        coherence_batch=_positive_int(data, "coherence_batch", 10),
    )
