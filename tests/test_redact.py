"""The API key stays out of logs and rendered text."""

import logging

from alien_hunt.redact import install_secret_filter, redact


def test_redact_replaces_the_secret():
    assert redact("token sk-abc", "sk-abc") == "token [redacted]"
    assert redact("plain", "sk-abc") == "plain"
    assert redact("plain", "") == "plain"


def test_log_record_is_redacted(caplog):
    secret = "sk-test-secret-value-xyz"
    install_secret_filter(secret)
    caplog.set_level(logging.INFO)
    logging.getLogger("alien_hunt").info("header %s", secret)
    assert secret not in caplog.text
    assert "[redacted]" in caplog.text
