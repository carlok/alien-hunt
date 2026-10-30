"""URL checks that do not touch the network."""

import pytest

from alien_hunt.checkout import CheckoutError, parse_github_url, validate_sha
from alien_hunt.cli import main


def test_accepts_a_public_github_url():
    assert parse_github_url("https://github.com/jpadilla/pyjwt") == ("jpadilla", "pyjwt")
    assert parse_github_url("https://github.com/jpadilla/pyjwt.git") == ("jpadilla", "pyjwt")


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:jpadilla/pyjwt.git",
        "https://gitlab.com/jpadilla/pyjwt",
        "https://user:token@github.com/jpadilla/pyjwt",
        "http://github.com/jpadilla/pyjwt",
    ],
)
def test_rejects_non_public_github_urls(url: str):
    with pytest.raises(CheckoutError):
        parse_github_url(url)


def test_commit_must_be_hex():
    assert validate_sha("98620ab2a396a5c887a494259d49552c2093e1ad")
    with pytest.raises(CheckoutError):
        validate_sha("main")


def test_cli_rejects_a_non_github_url_before_config(capsys):
    code = main(["run", "https://example.com/a/b", "--commit", "abc1234", "--budget", "1"])
    assert code == 2
    assert "github.com" in capsys.readouterr().err


def test_cli_rejects_a_branch_name(capsys):
    code = main(["run", "https://github.com/jpadilla/pyjwt", "--commit", "main", "--budget", "1"])
    assert code == 2
    captured = capsys.readouterr()
    assert "hex" in captured.err
