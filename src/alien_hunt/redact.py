"""Keep the API key out of logs, exceptions, and reports."""

from __future__ import annotations

import logging
import re

from alien_hunt.types import Claim, KnownAdvisory

_REDACTED = "[redacted]"


def redact(value: object, secret: str | tuple[str, ...] | list[str] | None) -> object:
    """Replace `secret` (or each of several) inside strings. Other objects pass through."""

    if isinstance(secret, (tuple, list)):
        for one in secret:
            value = redact(value, one)
        return value
    if not secret or not isinstance(value, str):
        return value
    if secret not in value:
        return value
    return value.replace(secret, _REDACTED)


class SecretFilter(logging.Filter):
    """Logging filter that strips a secret from the message and its arguments."""

    def __init__(self, secret: str) -> None:
        super().__init__()
        self._secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.msg, self._secret)
        if isinstance(record.args, dict):
            record.args = {key: redact(item, self._secret) for key, item in record.args.items()}
        elif isinstance(record.args, tuple):
            record.args = tuple(redact(item, self._secret) for item in record.args)
        return True


def install_secret_filter(secret: str) -> None:
    """Attach the filter to loggers that might echo an HTTP client."""

    if not secret:
        return
    filt = SecretFilter(secret)
    for name in ("", "alien_hunt", "openai", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        if any(isinstance(existing, SecretFilter) and existing._secret == secret for existing in logger.filters):
            continue
        logger.addFilter(filt)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


def symbol_hit(functions: list[str], symbol: str) -> bool:
    """True when `symbol` is a whole dotted component of a function name."""

    for name in functions:
        if name == symbol or name.endswith("." + symbol) or name.startswith(symbol + "."):
            return True
        if f".{symbol}." in f".{name}.":
            return True
    return False


_GENERIC = {"error", "errors", "issue", "issues", "defect", "bug", "bugs", "flaw", "vulnerability", "weakness"}


def _class_words(label: str) -> set[str]:
    return {word for word in re.split(r"[^a-z0-9]+", label.lower()) if len(word) >= 4 and word not in _GENERIC}


def class_hit(label: str, advisory: KnownAdvisory) -> bool:
    """The claim's class names the advisory's: equal, or sharing a word (of four letters or more, not a generic one like
    "error") with its class or one of its `classes`. On PyJWT the hunt said "algorithm-confusion" for an advisory filed
    as "key confusion", and the report did not cite it."""

    words = _class_words(label)
    for name in [advisory.class_label, *advisory.classes]:
        if label.strip().lower() == name.strip().lower() or words & _class_words(name):
            return True
    return False


def file_hit(files: list[str], symbol: str) -> bool:
    """True when a dotted module symbol names one of the claim's files (`jwt.algorithms` for `jwt/algorithms.py`)."""

    path = symbol.replace(".", "/")
    for name in files:
        clean = name.replace("\\", "/").removesuffix(".py")
        if clean == path or clean.endswith("/" + path):
            return True
    return False


def matching_advisory(claim: Claim, known: list[KnownAdvisory]) -> KnownAdvisory | None:
    """Cite an advisory only when both the class and a symbol match; a symbol matches a function or a file."""

    for advisory in known:
        if not class_hit(claim.class_label, advisory):
            continue
        if any(symbol_hit(claim.functions, symbol) or file_hit(claim.files, symbol) for symbol in advisory.symbols):
            return advisory
    return None
