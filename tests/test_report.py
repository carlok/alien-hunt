"""The published report keeps unknown defects to an alias and a class."""

from alien_hunt.budget import Budget
from alien_hunt.config import Prices
from alien_hunt.report import overlap_functions, public_rows, render_report, unique_confirmed
from alien_hunt.types import Candidate, Claim, Confirmation, KnownAdvisory, Atom


def _claim(origin: str, functions: list[str], class_label: str, reproducer: str) -> Claim:
    return Claim(
        text="narrative that must stay local",
        class_label=class_label,
        files=["secret.py"],
        functions=functions,
        reproducer=reproducer,
        origin=origin,
    )


def test_duplicates_collapse_and_overlap_is_the_intersection():
    plain = _claim("plain", ["pkg.one", "pkg.two"], "deserialisation", "print(1)")
    plain_again = _claim("plain", ["pkg.two", "pkg.one"], "deserialisation", "print(1)")
    directed = _claim("hunt", ["pkg.two"], "deserialisation", "print(2)")
    other = _claim("hunt", ["pkg.only_hunt"], "broken-length", "print(3)")
    pairs = [
        (plain, Confirmation(True, "ok")),
        (plain_again, Confirmation(True, "ok")),
        (directed, Confirmation(True, "ok")),
        (other, Confirmation(False, "no")),
    ]
    confirmed = unique_confirmed(pairs)
    assert len(confirmed) == 2
    assert overlap_functions(confirmed) == ["pkg.two"]


def test_report_aliases_unknown_claims_and_cites_an_allowlist_hit():
    known = [
        KnownAdvisory(
            id="GHSA-ffqj-6fqr-9h24",
            cve="CVE-2022-29217",
            class_label="key confusion",
            symbols=["PyJWK"],
        )
    ]
    claims = [
        _claim("plain", ["pkg.load_config"], "deserialisation", "SECRET_REPRO"),
        _claim("hunt", ["jwt.api_jwk.PyJWK"], "key confusion", "SECRET_REPRO"),
    ]
    budget = Budget(limit_usd=5)
    budget.charge_tokens("plain", 1_000_000, 0, Prices(1, 1, 1))
    budget.charge_tokens("hunt", 2_000_000, 0, Prices(1, 1, 1))
    top = [
        Candidate(
            id="c000",
            source=Atom("source", "s", "s"),
            mechanism=Atom("mechanism", "m", "do not print this mechanism"),
            other=Atom("invariant", "i", "i"),
            coherence=5,
            incoherent=True,
        )
    ]
    text = render_report(
        run_id="t",
        target="fixture",
        commit="local",
        budget=budget,
        claims=claims,
        top=top,
        known=known,
        stopped=False,
        secret="sk-live-key",
    )
    assert "AH-1: deserialisation (plain)" in text
    assert "AH-2: key confusion (directed) GHSA-ffqj-6fqr-9h24" in text
    assert "SECRET_REPRO" not in text
    assert "do not print this mechanism" not in text
    assert "load_config" not in text
    assert "PyJWK" not in text
    assert "sk-live-key" not in text
    assert "Confirmed per USD: 1.0000" in text
    assert "Miss rate among ratings of 4 or 5: 1.0000" in text
    rows = public_rows(claims, known)
    assert set(rows[0]) == {"alias", "class", "side"}
    assert rows[1]["advisory"] == "GHSA-ffqj-6fqr-9h24"
