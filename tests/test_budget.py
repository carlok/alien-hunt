"""Budget stop line."""

from alien_hunt.budget import Budget
from alien_hunt.config import Prices


def test_stops_at_eighty_percent():
    prices = Prices(1_000_000, 1_000_000, 1_000_000)
    budget = Budget(limit_usd=10)
    budget.charge_tokens("plain", prompt_tokens=7, completion_tokens=0, prices=prices)
    assert budget.spent == 7
    assert not budget.should_stop()
    budget.charge_tokens("plain", prompt_tokens=1, completion_tokens=0, prices=prices)
    assert budget.spent == 8
    assert budget.should_stop()


def test_empty_budget_stops_immediately():
    budget = Budget(limit_usd=0)
    assert budget.should_stop()


def test_stage_totals_stay_separate():
    prices = Prices(1_000_000, 0, 1_000_000)
    budget = Budget(limit_usd=100)
    budget.charge_tokens("plain", 2, 0, prices)
    budget.charge_tokens("hunt", 3, 0, prices)
    budget.charge_tokens("score", 0, 0, prices, embedding=True)
    budget.charge_tokens("score", 4, 0, prices, embedding=True)
    assert budget.spent_on("plain") == 2
    assert budget.spent_on("hunt") == 3
    assert budget.spent_on("score") == 4
