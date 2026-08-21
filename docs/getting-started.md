# Getting started

## Requirements

| | |
|---|---|
| Python | 3.9+ |
| [`gh` CLI](https://cli.github.com/) | authenticated (`gh auth login`) — **every** GHSA fetch shells out to it |
| AI credentials | optional; only the "Refine with AI" pass needs them |
| `NVD_API_KEY` | optional; without it NVD costs ~7 s per CWE instead of ~0.7 s |

Everything else is standard library. `requirements.txt` is just Flask and click.

## Run it locally

```bash
cp .env.example .env      # then put YOUR own AI token in .env — never commit it
./run.sh                  # creates .venv, installs Flask, launches
# open http://127.0.0.1:5000
```

`run.sh` is idempotent; re-run it after pulling. To run without it:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app.py            # honours HOST / PORT
```

## Run it in Docker

```bash
cp .env.example .env                          # optional AI / NVD keys
GH_TOKEN=$(gh auth token) docker compose up --build
# open http://127.0.0.1:5000
```

Two things to know:

- Compose publishes on **loopback only** (`127.0.0.1:5000`).
- The container **cannot** reuse a host `gh auth login`, because that token lives
  in the OS keyring. Pass `GH_TOKEN` on the command line as above, or put it in
  `.env`.

The advisory cache and the OSV zips persist in the `vulnsight-data` volume, so a
rebuild does not re-download them. See
[Operations → caches](operations.md#caches-and-disk).

## AI provider (optional)

The AI pass speaks either the Anthropic Messages shape or the OpenAI
chat-completions shape, selected by `CVE_AI_PROVIDER`. Configure it in `.env`
(git-ignored):

```shell
# Anthropic-compatible endpoint
CVE_AI_PROVIDER=anthropic
ANTHROPIC_BASE_URL=https://your-endpoint.example.com
ANTHROPIC_TOKEN=<your token>
ANTHROPIC_MODEL=model-xyz

# or GLM / BigModel (OpenAI chat-completions shape)
CVE_AI_PROVIDER=glm
GLM_TOKEN=key1,key2,key3          # comma-separated keys are rotated
GLM_MODEL=glm-4
```

Each provider reads its own prefixed variables, falling back to the generic
`AI_*` names, so both can live in `.env` at once. Multiple comma-separated
tokens enable [key rotation](ai-classification.md#multi-key-rotation).

Full list: [Configuration](configuration.md).

## Your first search

1. Open the app. **Broken Access Control** and **maven** are preselected.
2. Type `idor` into **Find a bug**. You get the BAC class and `CWE-639`
   (*Authorization Bypass Through User-Controlled Key*) with its aliases.
3. Press `Enter` to add whichever you want, or just leave the preselection.
4. Click **Search raw advisories** (free) — or `⌘/Ctrl + Enter`, the same thing.
5. Click **Refine with AI** if you configured credentials. The button tells you
   the cost first: *N selected · N AI passes per advisory*.
6. Tick **Confirmed only** to keep the AI-confirmed matches, then **Export**.

**Run intelligent scan** does steps 4–6 in one click and picks the sources for
you; it costs AI budget, which is why it is the loud button and the free search
is the quiet one.

Next: [Using the UI](usage.md) for the details, or
[Data sources](data-sources.md) to understand what each source adds.
