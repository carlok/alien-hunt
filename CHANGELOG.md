# Changelog

## 0.2.0 (2026-11-18)

### New

- **`alien-hunt replay RUN`** confirms a run's saved claims again with the current check. It makes no model call and needs no API key. With `--against <sha>` (or `--against-local PATH`) the claims confirmed on the run's commit are confirmed again on a second commit, such as the fix for an advisory, and each one is marked *fixed there* or *fires there too*. The second is the case the check alone cannot tell from a defect: a test that comes out true for correct behaviour. See the README's Replay section.
- **`alien-hunt pool`** prints the atoms a run keeps and the pairs it would draw, for a GitHub commit or a local checkout, before any money is spent. No model, no key; `--json` gives the raw list.
- **`--arms N`** hunts N picks per selection rule (the combined score, coherence alone, a random draw) from one pool, and `alien-hunt arms` adds such runs up with hand labels, to test whether the score chooses anything (PR #10).
- **`alien-hunt --version`**, and every run writes `run.json` (version, target, full commit, container image, seed) before anything else; the report names the version. `replay` reads it.
- **`scripts/pool_ceiling.py`** and **`scripts/bench_cases.py`** measure offline how often the candidate pool can reach the code a published fix changed, on cases built from GitHub's advisory database (PR #11, `reports/offline-tune/SUMMARY.md`).

### Changed

- **Confirmation is stricter** (PRs #9, #11). The marker must be printed from a branch that a repository result decides; constant tests, patching, shadowing or mocking the repository, calls made while an import runs, and code outside the library files do not count. The trace records the file and line of each function entered, and threads are traced. What it still does not stop is listed in the README.
- **The pool draws better** (PR #11). Pairs that reach new functions come first, closest first, and each kind of atom keeps the functions that do the most work instead of every Nth atom. Measured offline on held-out advisories, the share of draws that include a pair touching the fixed code rose from 22.2% to 28.8%.
- **A run keeps what it paid for** (PR #9). However the search ends (the budget, model errors, Ctrl-C), the claims it collected are confirmed and reported, and each claim is written to `local/claims.jsonl` as it arrives (what `replay` reads). A failed review or hunt is skipped and named, and three in a row end the search.
- **Smaller changes from PR #9:** `search` skips symlinks and anything outside the checkout; coherence is rated with the code around the atoms; plain reviews sample at `plain_temperature` (default 0.8); containers get a CPU limit, a container that times out is killed, and wheels are checked against the index's sha256.

### Fixed

- A method's receiver is dropped by its position (the first parameter of a function in a class body, unless it is a staticmethod) instead of by the names `self` and `cls`.
- Two classes with a same-named method and parameter shared an atom id, and one of them dropped out of the pool.
- A loop seen from both a function and a closure inside it was two sinks.

### Measured, not shipped

- **Sources from every kind of parameter.** Half of the pool's remaining misses are in code that yields no atom, and positional-only, keyword-only, `*args` and `**kwargs` parameters gave no source. Reading them all lowered held-out drawn_hit from 36.4% to 35.7%, and without `*args`/`**kwargs` it was still 0.5 points down: under the fixed cap of 80 sources the new ones pushed lighter functions' sources out, and no held-out case gained a hit. Sources still come from ordinary parameters.

**What ships, measured the same way** (`scripts/pool_ceiling.py`, against master before this release at 38ad734, on 123 tuning and 86 held-out advisory cases rebuilt on 2026-11-18, so not the cases in SUMMARY.md):

| | tuning | held-out |
|---|---|---|
| drawn_hit | 35.2% → 35.4% | 36.4% → 36.7% |
| fixes of at most 5 functions | 30.0% → 30.0% | 31.0% → 31.5% |
| touch_share | 6.9% → 6.9% | 5.5% → 5.5% |
| atom_hit | 63.4% → 63.4% | 66.3% → 62.8% |

The atom_hit drop is three held-out cases: with the id fix, same-named methods no longer collapse into one atom, and the extra ones compete for the same 80 places. The share of draws that reach the fixed code, which is what a run's hunts see, did not fall. The variant was picked with these held-out numbers in view, so they are a check, not an unbiased estimate.

## 0.1.0 (2026-10-30, not tagged)

The public research prototype (PRs #1 to #8): plain reviews against directed hunts sampled from library atoms, co-located pairs and model-picked mechanisms; confirmation in Podman with no network and offline wheels from before the commit; a stop at 80% of the budget; reports that give undisclosed findings an alias; MIT licence and CI.
