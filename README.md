# alien-hunt

`alien-hunt` looks for defects that a plain review of a repository does not already produce, then checks whether a reproducer can actually observe them.

The score is the cheap version of the sampler in [The Alien Space of Science](https://arxiv.org/abs/2603.01092) ([code](https://github.com/alejandrohdez00/alien-space-of-science), MIT). There is no trained coherence or availability model. A candidate triple is

```text
score = (1 - β) · z(coherence) + β · z(unavailability)
unavailability = 1 - max cosine similarity to the plain-review claims
```

Candidates are built from atoms of the library itself (not its tests, docs or examples): a source and a sink or invariant that live in the same file, else the same top-level folder; the model picks up to three of the 60 mechanisms that could join them, and one more is drawn at random, so the pool keeps some unlikely ones. Only candidates rated `min_coherence` (default 3) or more are hunted; unavailability orders them. Coherence is a 1–5 rating from the configured model. Unavailability is embedding distance from the texts that three plain reviews (and any local scanners) already produced. The run keeps the top 20 at β = 0.7 and also stores the ranking at β = 0.4.

## What is measured

`out/<run>/REPORT.md` records:

- confirmed claims and USD for the plain reviews, and the same for the directed hunts; claims on one side that share a function and have the same class, or near-identical text, count once
- confirmed claims per USD on each side
- overlap of those confirmed claims by function name
- how many of the top candidates the directed hunt judged incoherent, and that fraction among the ones rated 4 or 5

A claim counts only when its reproducer imports the repository, calls the named function, and exits 0. A script that reads source text does not count. Confirmation runs in Podman with `--network none`, the checkout mounted read-only, and third-party dependencies installed from wheels uploaded on or before the commit: the declared ones, the packages the reproducers import, and their own dependencies (read from each wheel's METADATA). A package with no such wheel is named in the log and left out. Nothing is built from source.

The run stops before the next paid call once 80% of `--budget` is spent, and still writes the report.

## Run

```bash
pip install -e .
cp config.example.toml alien-hunt.toml
export ALIEN_HUNT_API_KEY=...   # name is api_key_env in the config; the value stays in the environment

alien-hunt run https://github.com/jpadilla/pyjwt \
  --commit 98620ab2a396a5c887a494259d49552c2093e1ad \
  --budget 5 \
  --known cases/pyjwt.toml

alien-hunt run https://github.com/mbr/asciitree \
  --commit fcde62d5c0f1e5c36dc0100265b3c735ca9673a2 \
  --budget 5
```

The first commit is PyJWT 2.3.0, before the public fix for GHSA-ffqj-6fqr-9h24. The allowlist lets the report cite that advisory when a confirmed claim has class `key confusion` and touches the listed symbols. The second target is [asciitree](https://github.com/mbr/asciitree) at `fcde62d5c0f1e5c36dc0100265b3c735ca9673a2`: pure Python, tests in tree, 91 GitHub stars, and no OSV advisory at the time it was pinned. Its report uses aliases only.

These two commands are the case studies. They send the target tree only to the endpoint in `alien-hunt.toml`. This repository does not contain their results: no API key was configured when the tool was added.

Chat and embeddings both use that OpenAI-compatible endpoint, unless the config has an `[embedding]` table. Then embeddings go to that table's `base_url` and `model`, with the key in its own `api_key_env`. Use it when the chat provider has no embeddings API (Anthropic's OpenAI-compatible endpoint, for one) or when the two roles should use two keys. If the endpoint used for embeddings has none, the run stops. Prices in the config are USD per million tokens and are what the budget uses. Every key the run uses is filtered from logs and redacted from the report. Chat requests send `temperature = 0` unless the config sets another value, or `temperature = false` for a model that refuses the parameter (Claude Sonnet 5.5 through Anthropic's OpenAI-compatible endpoint, for one).

A review or a hunt gets a last turn that can only submit (on its last round, or once 75% of its token cap is used), and a reply cut at `max_output_tokens` (default 4000) is asked again once, with at most three claims. A coherence batch that does not parse is asked again in halves. The report says how many claims each side made, how many coherence ratings parsed, and how many top candidates got a verdict.

The wheels are for the container's CPython: `container_image` names it (`python:3.12-slim` fetches cp312 wheels). When no candidate reaches `min_coherence`, the best `fallback_hunts` (default 3) rated 2 are hunted instead. A known advisory is cited when a claim's class shares a word with the advisory's `class` or one of its `classes`, and a symbol names one of the claim's functions or files.

Both containers that touch model-written code (the reproducer and the offline wheel install) run with no network, all capabilities dropped, no privilege gain, and a pids and a memory limit.

## Tests

```bash
python -m pytest
```

`tests/fixtures/samplelib` is a library we planted:

- `load_config` unpickles caller bytes. The scripted plain review returns this claim.
- `allocate` documents that the result length equals `n` for `n >= 0`, and `allocate(0)` returns `[0]`. The scripted directed hunt returns this claim only when the prompt is about that invariant.

That test checks the pipeline split. It does not show that a live model misses `allocate`. The Podman test runs the fixture reproducer when `podman` is installed and skips otherwise.

## Boundaries

Public GitHub repositories, or a local tree via `--local`. The tool does not push, open issues, or comment. The API key is read from the environment variable named in the config and is redacted from logs and from the report. `out/` is gitignored. Full reproducers stay in `out/<run>/local/`. In the report, a confirmed defect outside a public advisory is an alias (`AH-1`, …) and a class. Publishing anything beyond that is a person's decision.
