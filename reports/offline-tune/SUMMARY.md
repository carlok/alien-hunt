# Offline tune of alien-hunt

Branch `tune/offline`, 2026-11-08. No model was called and no embeddings were computed. Nothing from a target repository ran on the host: the pool measurement only parses target code with `ast`, and reproducers run only through `confirm_podman`.

## Executive summary

- **The pool now reaches the fixed code more often.** Over 20 seeds with the pipeline's pair limit (20 pairs), the share of draws that contain a pair touching a function the fix changed went from 22.2% to 28.8% on the held-out cases (92 measured), and from 24.7% to 34.3% on the tuning cases (138). For fixes that change at most five functions it went from 18.7% to 28.0% held-out. The tuning gain is larger than the held-out gain, which is what tuning on a split looks like.
- **Dilution did not get worse; it improved a little.** The share of kept pairs that touch a fix function rose from 3.7% to 4.6% held-out and from 4.8% to 6.6% on tuning. Both stay far from good: 93 to 95 of every 100 pairs the pool offers still miss the fix.
- **Four changes were kept, two were rejected on held-out.** The kept changes record the function each atom sits in, draw pairs that reach new functions first, break ties toward busier functions, and keep the atoms of the heaviest functions instead of every Nth atom. Two more retention changes (a per-file cap, tiered sinks) raised the tuning number by 4.3 and 4.1 points and lowered the held-out number by 1.0 and 0.6. They are not in the branch.
- **What is left is mostly extraction, not selection.** With the 80/80/40 caps removed, an atom sits in a fixed function in 95.7% of held-out cases (92.8% on tuning); with the caps and the new retention it is 57.6% (65.2%). The retention agent found that about half of the cases still missing are fixes in code that yields no atom at all (zero-parameter or keyword-only functions, module-level code).
- **The confirmation check is much harder to fool, and not unfoolable.** Four red-team reads wrote reproducers the check confirmed without any defect observed. Scripts that passed the syntax stage fell from 43 to 9, 18 to 13, 18 to 12 and 17 to 2 across the four routes. The shapes that stay open are listed below and in the README.
- **Not done:** the fifth red-team route (trace tampering) was skipped on purpose; the second round of per-family tuning agents was not run; and the effect on real hunts is unmeasured, because the brief forbade model calls. See "What was not checked".
- **One measurement mistake was made and fixed along the way** (a `--src` that silently measured the installed copy). It is described under "Process", and the fix is a tested commit.

## Workstream 1: the pool's ceiling

### What was measured

`scripts/pool_ceiling.py` takes cases (a vulnerable tree and the tree after the fix), finds the functions the fix changed (a function-level diff by `ast.dump`, docstrings stripped), builds the pool with alien-hunt's own `extract_atoms`, `colocated_pairs` and `pool_pairs`, and records per case:

| rate | meaning |
|---|---|
| atom_hit | some source, sink or invariant atom sits in a fix function (same file, line inside the function) |
| pair_hit | some co-located pair, before the pair limit, has an atom in a fix function |
| drawn_hit | share of 20 seeds whose kept pairs (limit `max(1, sample_limit // 4)` = 20) include such a pair |
| touch_share | share of the pool's pairs that touch a fix function ("dilution"; higher is better) |

Cases come from GitHub's advisory database (`scripts/bench_cases.py`): reviewed, not withdrawn, PyPI, with a fix commit in the package's own repository, and the fix changes a non-test `.py` file. Advisories published before 2025-01-01 are the tuning split, the rest are held out. 159 tuning and 94 held-out cases were snapshotted; 138 and 92 have a target (21 and 2 have a fix that changes no function present in the vulnerable tree and are counted apart).

Only the orchestrating session read the held-out set, and only after a proposal was fixed. The agents that proposed changes saw the tuning cases only, and a separate auditor checked each proposal's diff for names taken from the tuning cases (about 6,000 identifier-like names), for `_NOT_LIBRARY_DIRS`, for model calls and for tests. All six commits the agents proposed passed the audit; four are kept (see below).

The keep rule (`pool_ceiling.py compare`): held-out drawn_hit rises, and touch_share stays at least four fifths of what it was.

### Result, tuning split (138 cases)

| group | cases | atom_hit | pair_hit | drawn_hit | pool | touch_share |
|---|---|---|---|---|---|---|
| all | 138 | 56.5% -> 65.2% | 56.5% -> 65.2% | 24.7% -> 34.3% | 6399 -> 6287 | 4.8% -> 6.6% |
| fix of at most 5 functions | 107 | 45.8% -> 56.1% | 45.8% -> 56.1% | 16.2% -> 27.1% | 6290 -> 6190 | 3.0% -> 3.5% |
| authn-authz | 24 | 66.7% -> 70.8% | 66.7% -> 70.8% | 28.3% -> 33.3% | 5852 -> 5617 | 4.7% -> 5.1% |
| crash-and-errors | 1 | 0.0% -> 0.0% | 0.0% -> 0.0% | 0.0% -> 0.0% | 9323 -> 9480 | 0.0% -> 0.0% |
| crypto-and-tls | 4 | 50.0% -> 50.0% | 50.0% -> 50.0% | 15.0% -> 0.0% | 8197 -> 7884 | 0.4% -> 1.8% |
| deserialization | 9 | 66.7% -> 66.7% | 66.7% -> 66.7% | 36.7% -> 40.6% | 6349 -> 6044 | 8.1% -> 9.1% |
| info-disclosure | 10 | 30.0% -> 60.0% | 30.0% -> 60.0% | 19.0% -> 33.0% | 5403 -> 5403 | 2.8% -> 3.8% |
| injection | 34 | 58.8% -> 61.8% | 58.8% -> 61.8% | 23.8% -> 32.1% | 6492 -> 6492 | 4.9% -> 7.8% |
| input-validation | 1 | 0.0% -> 100.0% | 0.0% -> 100.0% | 0.0% -> 0.0% | 3913 -> 4500 | 0.0% -> 3.9% |
| memory-and-numeric | 1 | 100.0% -> 100.0% | 100.0% -> 100.0% | 100.0% -> 100.0% | 8480 -> 8400 | 65.0% -> 89.3% |
| other | 22 | 40.9% -> 59.1% | 40.9% -> 59.1% | 18.4% -> 32.3% | 7260 -> 7072 | 4.2% -> 5.1% |
| path-and-file | 15 | 73.3% -> 73.3% | 73.3% -> 73.3% | 22.3% -> 37.3% | 6654 -> 6730 | 2.3% -> 4.3% |
| resource-exhaustion | 13 | 61.5% -> 69.2% | 61.5% -> 69.2% | 28.1% -> 46.2% | 5260 -> 5035 | 4.7% -> 6.5% |
| ssrf-redirect-xxe | 4 | 50.0% -> 75.0% | 50.0% -> 75.0% | 33.8% -> 45.0% | 7077 -> 6948 | 7.2% -> 10.2% |

### Result, held-out split (92 cases)

| group | cases | atom_hit | pair_hit | drawn_hit | pool | touch_share |
|---|---|---|---|---|---|---|
| all | 92 | 52.2% -> 57.6% | 52.2% -> 57.6% | 22.2% -> 28.8% | 6578 -> 6501 | 3.7% -> 4.6% |
| fix of at most 5 functions | 71 | 46.5% -> 52.1% | 46.5% -> 52.1% | 18.7% -> 28.0% | 6433 -> 6337 | 2.4% -> 2.7% |
| authn-authz | 23 | 43.5% -> 43.5% | 43.5% -> 43.5% | 11.1% -> 17.0% | 7045 -> 7059 | 1.7% -> 3.4% |
| crypto-and-tls | 9 | 66.7% -> 66.7% | 66.7% -> 66.7% | 22.2% -> 32.8% | 6461 -> 6154 | 1.9% -> 2.1% |
| deserialization | 4 | 50.0% -> 25.0% | 50.0% -> 25.0% | 1.2% -> 25.0% | 8414 -> 8049 | 0.6% -> 1.0% |
| info-disclosure | 1 | 100.0% -> 100.0% | 100.0% -> 100.0% | 100.0% -> 100.0% | 1520 -> 1120 | 7.6% -> 10.6% |
| injection | 7 | 71.4% -> 85.7% | 71.4% -> 85.7% | 60.0% -> 70.7% | 4332 -> 4262 | 21.6% -> 23.6% |
| input-validation | 2 | 100.0% -> 50.0% | 100.0% -> 50.0% | 60.0% -> 50.0% | 5200 -> 4678 | 11.9% -> 10.7% |
| other | 7 | 28.6% -> 71.4% | 28.6% -> 71.4% | 1.4% -> 24.3% | 5764 -> 5644 | 1.1% -> 2.0% |
| path-and-file | 7 | 71.4% -> 57.1% | 71.4% -> 57.1% | 20.0% -> 30.0% | 6322 -> 6470 | 1.9% -> 1.9% |
| resource-exhaustion | 19 | 57.9% -> 68.4% | 57.9% -> 68.4% | 28.9% -> 30.8% | 6990 -> 7063 | 3.0% -> 3.2% |
| ssrf-redirect-xxe | 13 | 30.8% -> 46.2% | 30.8% -> 46.2% | 18.5% -> 15.4% | 7052 -> 6837 | 1.6% -> 2.9% |

Several families have a handful of cases, so their rows move by whole cases (one held-out case in a four-case family is 25 points of atom_hit). Families that got worse: crypto-and-tls on tuning (4 cases, 15.0% -> 0.0%), ssrf-redirect-xxe on held-out (13 cases, 18.5% -> 15.4%), input-validation on held-out (2 cases), and atom_hit in path-and-file and deserialization on held-out (7 and 4 cases) even though their drawn_hit rose. The keep rule looks at the pooled number, so these losses were accepted, not fixed.

### Changes, in order

drawn_hit before -> after with all earlier kept changes in place; small-fix is the slice of fixes touching at most five functions.

| commit | change | tuning | held-out | small-fix (held-out) | verdict |
|---|---|---|---|---|---|
| 57afd12 | `Atom.scope`: the innermost function holding an atom's line | no change | no change | no change | kept; the next change needs it |
| 60ee797 | `colocated_pairs` draws closest first (function, file, folder) and prefers pairs that bring functions no kept pair used | 24.7 -> 28.3 | 22.2 -> 23.8 | 18.7 -> 20.3 | kept |
| e1dd5b2 | among equal pairs, take those whose functions hold more atoms first | 28.3 -> 29.2 | 23.8 -> 24.0 | 20.3 -> 20.2 | kept, marginal: +0.2 held-out is within the noise between seed sets |
| 9e04348 | keep the atoms of the heaviest functions (count of ifs, loops, try, raise, calls), at most 1 source, 2 sinks, 2 invariants per function, instead of every Nth atom | 29.2 -> 34.3 | 24.0 -> 28.8 | 20.2 -> 28.0 | kept |
| not committed | at most four atoms of a kind per file | 34.3 -> 38.6 | 28.8 -> 27.8 | 28.0 -> 26.6 | rejected: held-out falls |
| not committed | sinks in tiers (calls and decodes, then loops, then multiplications) | 38.6 -> 42.7 | 27.8 -> 27.2 | 26.6 -> 25.0 | rejected: held-out falls |

The two rejected changes are the clearest case in this tune of a gain that was fitted to the tuning cases: both are tuned numbers (a per-file cap picked by comparing 3 with 4, a tier order read off the sinks of the tuning fixes), and the tuning split rewarded them while held-out did not. Their code is not on the branch.

Variants the agents tried and dropped, all on the tuning split (baseline 24.7%, small-fix 16.2%): same-function pairs first, uniform (20.1%) or spread over functions (23.0%); reserving a half or a quarter of the slots for same-function pairs (27.1%, 27.2%); a tier-ordered pass (27.4%); preferring public names (28.2%), non-methods (26.9%) or both (27.6%); public names then busier functions (28.7%). For retention: public-first ranking (the signal is 1.03x), a per-file cap of 3, caps raised to 120/160 (atom_hit 69.6/71.7 but drawn_hit falls to 37.8/37.2), caps lowered to 40 or 60, a fair-share per-file cap, bonuses for sources, for annotations, for env/argv, and a stdlib call-name vocabulary (slightly better, dropped as name-like). About 14 draw variants were tried, which is over the guideline of eight.

### What limits the ceiling now

- **Draw.** The pool holds about 141 functions with atoms per case and 20 pairs touch at most 40 of them. A perfect draw of 40 distinct functions would reach about 32% on tuning before retention; the draw lever is close to spent.
- **Retention.** Removing the caps entirely gives atom_hit of 92.8% (tuning) and 95.7% (held-out). The kept retention reaches 65.2% and 57.6%. Raising the caps raised atom_hit and lowered drawn_hit, so the keep rule refuses it.
- **Extraction.** Half of the cases still missing have no atom in the fixed function: zero-parameter or keyword-only functions, module-level code, config readers. `extract_atoms` reads only `args.args`, so keyword-only parameters produce no source. That is an extraction change and was left alone. It is the next thing to look at.

### Caveats

- **Upper bound.** atom_hit and pair_hit use the atoms before a model filters the invariants. A real run sees fewer. The measure says whether the pool can reach the code, not whether a hunt will find the defect.
- **Two readings of atom_hit.** The headline counts an atom as in a fix function when it sits in the file and its line lies inside the function (a sink's `function` field names the callee, not the function around it). The literal reading, where the atom's own `function` field names the fix function, is recorded as `atom_hit_literal`: 52.9% -> 63.0% on tuning, 48.9% -> 56.5% held-out.
- **Snapshots are pruned.** To keep the cases small, each snapshot holds only the `.py` files `extract_atoms` reads (no tests, docs, examples, setup files or data). The pool is built from those files either way; the full checkout was never kept.
- **Selection.** The cases are advisories that link a fix commit in the package's own repository. Fixes that were never linked, and defects never fixed, are not in the sample.
- **`mechanisms.json` and the semgrep rules** do not change the atoms or the pairs, so this measure cannot see changes to them. Nothing was tuned there.
- **Seeds are fixed** (20 per case, the same for every run), so a before/after difference is not sampling noise but is also not a confidence interval. Differences of a point or less are within what a different seed set would move.

## Workstream 2: false confirmations

Five helpers each wrote reproducers the check confirmed without observing a defect; four ran and one was halted by a safety classifier before running anything. Each confirmed bypass became a failing test in `tests/test_confirm.py` and then a change in `confirm.py` (commit 7d89712).

| route | what it tried | scripts through the syntax stage, before -> after |
|---|---|---|
| A | markers that are always true (`if True`, `x or True`, `elif`, `assert`, `__name__`) | 43 -> 9 (of 43) |
| B | `except` and `try`/`else` shapes that print the marker without the call failing | 18 -> 13 (of 21) |
| C | meaningless calls: stub arguments, wrong function, calls at import time, same-named classes, threads | 18 -> 12 (of 21); three more are refused when the trace runs |
| D | state the script made itself (a value it assigned, then tested) | 17 -> 2 (of 17) |
| E | tampering with the trace in the shared process | not run (see below) |

What the check now requires: the branch that prints the marker must be decided by the repository (an `if` whose test reads a repository name or a value assigned from one, or an `except` / `try`-`else` whose body calls the repository and raises nothing itself); a test that is constant whatever the call returned decides nothing; patching, shadowing, subclassing or `mock` of the repository is refused; the trace records the file and first line of each library function entered, calls made while an import runs do not count, and a claim's `Class.fn` must be that class's `fn`. `tests/test_confirm.py` also pins the honest shapes, so a stricter rule that refuses a real finding fails a test.

### Left open

These cannot be closed without refusing legitimate reproducers, so the README lists them under what the check does not stop. Each one has the same outer form as a real finding; telling them apart takes a differential run (the same script must stay silent against the fixed version).

A test that comes out true for correct behaviour:

```python
from samplelib import allocate
got = allocate(3)
if len(got) == 3:                 # true when the code is right
    print("DEFECT-OBSERVED")
```

A correct rejection reported as a defect:

```python
try:
    allocate(None)
except TypeError:                 # the library did the right thing
    print("DEFECT-OBSERVED")
```

A print after a call that did not raise:

```python
try:
    allocate(3)
    print("DEFECT-OBSERVED")
except Exception:
    sys.exit(1)
```

Arguments that test nothing:

```python
out = draw_tree(Stub(), child_iter=lambda n: [], text_str=lambda n: "X")
if out == "X":                    # the stub decided the output
    print("DEFECT-OBSERVED")
```

Two more are in the README without a script: a claim that names several functions counts when any one ran (and an inherited method matches by its bare name), and a marker built from pieces and printed beside an honest print that never runs.

## What was not checked

- **Route E, trace tampering.** The script shares its process with the trace; the blocked modules and attributes stop the obvious routes to forging it, but a script written to fool the trace could still. This route was skipped, by choice, after the helper for it was halted by a safety classifier. The README says the same.
- **Round 2 of the pool tuning.** The plan had one agent per CWE family work on the remaining misses on top of the tuned tip. It was not run: the held-out gate had just rejected two of three retention changes as overfit, the remaining misses are mostly extraction, and the session was asked to wrap up at that point.
- **Real hunts.** No model was called, so nothing here says how much a better pool changes confirmed findings per dollar. The pool is only the part of the funnel this measure can see.
- **The mechanisms the model proposes per pair** (up to four) and the semgrep scan.
- **Candidates outside the library**: the pool never reads tests, docs or examples (`_NOT_LIBRARY_DIRS` is untouched), so a fix there is invisible by design.

## Process

- The tuning agents ran in isolated worktrees and reported commits; each report was audited by a separate agent before anything was merged into the branch.
- **A measurement mistake.** `pool_ceiling.py --src` expected a `src/` folder; when given a checkout root it found no package there and fell back to the installed copy, so four stacked-change runs and one held-out run measured the wrong code. The tell was identical numbers across steps that should have differed. They were discarded and re-run; the decision on the third draw commit, which had been made on a bad run, was redone (it moved from "rejected" to "kept, marginal"). The script now takes a checkout or its `src/`, stops when neither holds `alien_hunt`, checks where the module loaded from, and writes the measured package path into the result file. Commit d89ec06 has the tests.
- The earlier baselines and the tuning runs of the draw commits happened to measure the right code (the main checkout held it at that moment) and were reproduced by the agents in their own worktrees.

## Reproduce

```bash
python scripts/bench_cases.py select --help      # read a clone of github/advisory-database, write a manifest
python scripts/bench_cases.py snapshot --help    # fetch both commits per case, keep library .py files only
python -I scripts/pool_ceiling.py measure CASES --src CHECKOUT --jobs 8 --json out.json
python -I scripts/pool_ceiling.py compare before.json after.json
python -I scripts/pool_ceiling.py explain CASES/GHSA-xxxx-xxxx-xxxx   # a case's fix functions and the atoms in them
```

The case snapshots were deleted after the run (they hold third-party code); `bench_cases.py` rebuilds them from the advisory database.
