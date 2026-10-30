# alien-hunt

`alien-hunt` looks for defects that a plain review of a repository does not already produce, then checks whether a reproducer can actually observe them.

**Status:** a research prototype, tried on three Python libraries so far (results below). A run spends money on a model API (0.5 to 1.5 USD in those runs) and executes reproducers the model wrote, inside Podman with no network.

The score is the cheap version of the sampler in [The Alien Space of Science](https://arxiv.org/abs/2603.01092) ([code](https://github.com/alejandrohdez00/alien-space-of-science), MIT). There is no trained coherence or availability model. A candidate triple is

```text
score = (1 - β) · z(coherence) + β · z(unavailability)
unavailability = 1 - max cosine similarity to the plain-review claims
```

Candidates are built from atoms of the library itself (not its tests, docs or examples): a source and a sink or invariant that live in the same file, else the same top-level folder; the model picks up to three of the 62 mechanisms that could join them, and one more is drawn at random, so the pool keeps some unlikely ones. Only candidates rated `min_coherence` (default 3) or more are hunted, in order of that score. Coherence is a 1–5 rating from the configured model. Unavailability is embedding distance from the texts that three plain reviews (and any local scanners) already produced. The run keeps the top 20 at β = 0.7 and also stores the ranking at β = 0.4.

## What is measured

`out/<run>/REPORT.md` records:

- confirmed claims and USD for the plain reviews, and the same for the directed hunts; claims on one side that share a function count once when they also have the same class or near-identical text
- confirmed claims per USD on each side
- how many functions both sides' confirmed claims share (their names stay in `out/<run>/local/detail.json`)
- how many of the top candidates the directed hunt judged incoherent, and that fraction among the ones rated 4 or 5

A claim counts only when its reproducer imports the repository, calls the named function, and exits 0. A script that reads source text does not count. Confirmation runs in Podman with `--network none`, the checkout mounted read-only, and third-party dependencies installed from wheels uploaded on or before the commit: the declared ones, the packages the reproducers import, and their own dependencies (read from each wheel's METADATA). A package with no such wheel is named in the log and left out. Nothing is built from source.

The run stops before the next paid call once 80% of `--budget` is spent, and still writes the report.

## Run

You need Python 3.11 or later, `git`, and [Podman](https://podman.io/) (rootless is enough). Without Podman a run still spends its budget on the reviews and hunts, then refuses every claim.

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

alien-hunt run https://github.com/authlib/joserfc \
  --commit 26a10275e88276184f91ae2a6409647bfac7fea5 \
  --budget 4 \
  --known cases/joserfc.toml
```

The first commit is PyJWT 2.3.0, before the public fix for GHSA-ffqj-6fqr-9h24. The allowlist lets the report cite that advisory when a confirmed claim has class `key confusion` and touches the listed symbols. The second target is [asciitree](https://github.com/mbr/asciitree) at `fcde62d5c0f1e5c36dc0100265b3c735ca9673a2`: pure Python, tests in tree, 91 GitHub stars, and no OSV advisory at the time it was pinned. Its report uses aliases only.

joserfc needs Python 3.11 or later, so its run needs `container_image = "docker.io/library/python:3.12-slim"`. Its commit is the parent of the first fix for its two denial-of-service advisories (GHSA-jpxq-7h8p-2q76 and GHSA-9pg5-8c7x-5hfx).

A case file's `url`, `commit` and `budget` record the run for the reader: the CLI takes them as arguments and reads only the advisories from `--known`. These commands are the case studies. They send the target tree only to the endpoints in `alien-hunt.toml`. The run folders stay out of this repository; the results are summarised below.

Chat and embeddings both use that OpenAI-compatible endpoint, unless the config has an `[embedding]` table. Then embeddings go to that table's `base_url` and `model`, with the key in its own `api_key_env`. Use it when the chat provider has no embeddings API (Anthropic's OpenAI-compatible endpoint, for one) or when the two roles should use two keys. If the endpoint used for embeddings has none, the run stops. Prices in the config are USD per million tokens and are what the budget uses. Every key the run uses is filtered from logs and redacted from the report. Chat requests send `temperature = 0` unless the config sets another value, or `temperature = false` for a model that refuses the parameter (Claude Sonnet 5.5 through Anthropic's OpenAI-compatible endpoint, for one).

A review or a hunt gets a last turn that can only submit (on its last round, or once 75% of its token cap is used), and a reply cut at `max_output_tokens` (default 4000) is asked again once, with at most three claims. A coherence batch that does not parse is asked again in halves. The report says how many claims each side made, how many coherence ratings parsed, and how many top candidates got a verdict.

The wheels are for the container's CPython: `container_image` names it (`python:3.12-slim` fetches cp312 wheels). When no candidate reaches `min_coherence`, the best `fallback_hunts` (default 3) rated 2 are hunted instead. A known advisory is cited when a claim's class shares a word with the advisory's `class` or one of its `classes`, and a symbol names one of the claim's functions or files.

Both containers that touch model-written code (the reproducer and the offline wheel install) run with no network, all capabilities dropped, no privilege gain, and a pids and a memory limit.

## Results so far

Nine runs on 2026-10-30, all with Claude Sonnet 5.5 for chat and `text-embedding-3-small` for embeddings. Together they logged about 10.7 USD at list prices. Several runs exposed a fault in the tool, fixed before the next run.

- **PyJWT 2.3.0, 4 runs.** The plain reviews never reported GHSA-ffqj-6fqr-9h24 (CVE-2022-29217, an ssh-ed25519 public key accepted as an HMAC secret). The directed hunts claimed it in run 3, where confirmation stopped on the missing `cryptography` extra (a replay with it installed confirmed both claims), and confirmed it in run 4. The CVE is public, so the model may have recognised it rather than found it.
- **asciitree, 1 run.** No candidate reached the coherence floor and nothing was hunted. That run added the fallback to the best candidates rated 2.
- **joserfc, 3 complete runs and 1 cut short when the API credit ran out.**
  - A directed hunt confirmed that `JWTClaimsRegistry.validate_exp` accepted a token whose `exp` equals the current time, against RFC 7519 §4.1.4. It was still present upstream and was sent as [authlib/joserfc#109](https://github.com/authlib/joserfc/pull/109).
  - A plain review confirmed that `validate_iss` reported the wrong claim name. Upstream had fixed it independently after the pinned commit.
  - Neither advisory was found. The sinks and mechanisms for that kind of defect were added afterwards. In the last run they reached the candidate pool, but the sampler drew no candidate in the advisories' functions.
- Other confirmed claims were minor and aren't listed.

## Tests

```bash
pip install -e ".[test]"
python -m pytest
```

`tests/fixtures/samplelib` is a library we planted:

- `load_config` unpickles caller bytes. The scripted plain review returns this claim.
- `allocate` documents that the result length equals `n` for `n >= 0`, and `allocate(0)` returns `[0]`. The scripted directed hunt returns this claim only when the prompt is about that invariant.

That test checks the pipeline split. It does not show that a live model misses `allocate`. The Podman test runs the fixture reproducer when `podman` is installed and skips otherwise.

## Boundaries

Public GitHub repositories, or a local tree via `--local`. The tool does not push, open issues, or comment. The API key is read from the environment variable named in the config and is redacted from logs and from the report. `out/` is gitignored. Full reproducers stay in `out/<run>/local/`. In the report, a confirmed defect outside a public advisory is an alias (`AH-1`, …) and a class. Publishing anything beyond that is a person's decision.

## Credits

The idea of sampling coherent but unavailable directions, and of ranking them by coherence and distance from what is already produced, comes from [The Alien Space of Science: Sampling Coherent but Cognitively Unavailable Research Directions](https://arxiv.org/abs/2603.01092) and its [code](https://github.com/alejandrohdez00/alien-space-of-science) (MIT). alien-hunt applies it to defects in code, with a model's ratings in place of the paper's trained models.

## License

MIT. See [LICENSE](LICENSE).
