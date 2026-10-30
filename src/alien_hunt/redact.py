"""Keep the API key out of logs, exceptions, and reports."""

from __future__ import annotations

import logging

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


def matching_advisory(claim: Claim, known: list[KnownAdvisory]) -> KnownAdvisory | None:
    """Cite an advisory only when both the class and a symbol match."""

    for advisory in known:
        if claim.class_label != advisory.class_label:
            continue
        if any(symbol_hit(claim.functions, symbol) for symbol in advisory.symbols):
            return advisory
    return None
