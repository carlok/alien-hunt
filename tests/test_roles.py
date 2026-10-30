"""A second endpoint for embeddings, both keys redacted, and the pip container hardened too."""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path

import pytest

from alien_hunt.config import ConfigError, load_config
from alien_hunt.confirm import HARDENING, podman_pip_argv
from alien_hunt.redact import redact

BASE = """
base_url = "https://chat.example/v1/"
model = "chat-model"
embedding_model = "unused-when-[embedding]-is-set"
api_key_env = "AH_TEST_CHAT"
price_input_per_mtok = 1
price_output_per_mtok = 2
price_embedding_per_mtok = 0.02
max_tokens_per_hunt = 8000
container_image = "python:3.12-slim"
"""

EMBED = """
[embedding]
base_url = "https://embed.example/v1"
model = "embed-model"
api_key_env = "AH_TEST_EMBED"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "c.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_without_an_embedding_table_one_endpoint_serves_both(tmp_path, monkeypatch):
    monkeypatch.setenv("AH_TEST_CHAT", "chat-secret-1")
    config = load_config(write(tmp_path, BASE))
    assert config.embedding is None
    assert config.embedding_model == "unused-when-[embedding]-is-set"
    assert config.secrets() == ("chat-secret-1",)


def test_an_embedding_table_names_its_own_endpoint_model_and_key(tmp_path, monkeypatch):
    monkeypatch.setenv("AH_TEST_CHAT", "chat-secret-1")
    monkeypatch.setenv("AH_TEST_EMBED", "embed-secret-2")
    config = load_config(write(tmp_path, BASE + EMBED))
    assert (config.embedding.base_url, config.embedding.model, config.embedding_model) == (
        "https://embed.example/v1",
        "embed-model",
        "embed-model",
    )
    assert config.secrets() == ("chat-secret-1", "embed-secret-2")
    monkeypatch.delenv("AH_TEST_EMBED")
    with pytest.raises(ConfigError, match="AH_TEST_EMBED"):
        config.secrets()


def test_a_bad_embedding_table_is_refused(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, BASE + "\n[embedding]\nbase_url = \"https://x\"\n"))


def test_the_model_uses_two_clients_and_filters_both_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("AH_TEST_CHAT", "chat-secret-1")
    monkeypatch.setenv("AH_TEST_EMBED", "embed-secret-2")
    made = []

    class FakeOpenAI:
        def __init__(self, base_url, api_key):
            made.append((base_url, api_key))

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    from alien_hunt.llm import OpenAIModel

    model = OpenAIModel(load_config(write(tmp_path, BASE + EMBED)))
    assert made == [("https://chat.example/v1", "chat-secret-1"), ("https://embed.example/v1", "embed-secret-2")]
    assert model._embed_client is not model._client
    record = logging.LogRecord("alien_hunt", logging.INFO, __file__, 1, "keys %s %s", ("chat-secret-1", "embed-secret-2"), None)
    for filt in logging.getLogger("alien_hunt").filters:
        filt.filter(record)
    assert "secret" not in record.getMessage()


def test_redact_takes_several_secrets():
    assert redact("a chat-secret-1 b embed-secret-2", ("chat-secret-1", "embed-secret-2")) == "a [redacted] b [redacted]"
    assert redact("nothing here", ("x", "y")) == "nothing here"


def test_the_pip_container_is_hardened_too(tmp_path):
    argv = podman_pip_argv("python:3.12-slim", tmp_path / "w", tmp_path / "d", tmp_path / "r" / "requirements.txt")
    for flag in HARDENING:
        assert flag in argv
    assert argv[argv.index("--network") + 1] == "none"
