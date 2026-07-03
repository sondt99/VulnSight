"""AI refinement layer for advisory classification.

CWE filtering already narrows the result set, but GHSA CWE tagging is imperfect:
some advisories are mislabeled, some carry an umbrella CWE (e.g. CWE-284) that
is too vague, and titles rarely say "BOLA" or "BFLA" explicitly. This module
asks an LLM to read each advisory and decide whether it *really* belongs to the
target bug class, returning a structured verdict we can filter/sort on.

Provider is configured via environment (see .env.example):

  CVE_AI_PROVIDER=anthropic          # only "anthropic" implemented for now
  AI_BASE_URL=https://your-ai-endpoint.example.com
  AI_TOKEN=sk-...
  AI_MODEL=model-xyz

The endpoint is Anthropic Messages-API compatible: POST {BASE_URL}/v1/messages
with headers x-api-key + anthropic-version. We use only the Python stdlib
(urllib) so the app has no extra runtime dependency beyond Flask.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .cwe_categories import CATEGORIES, cwe_label

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Retry policy for transient failures (rate limits, gateway hiccups, Cloudflare
# throttling, network blips). Client errors like a bad API key are NOT retried.
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.5          # seconds; grows exponentially with jitter
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 403, 520, 522, 524}

# The provider's "PRO" model is a reasoning model (GLM): it spends output tokens
# "thinking" before answering. Too small a budget truncates the JSON verdict or
# leaves an empty visible answer, so give it generous room.
CLASSIFY_MAX_TOKENS = 2000


class AIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None,
                 retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


@dataclass
class AIConfig:
    provider: str
    base_url: str
    token: str
    model: str

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token and self.model)

    @property
    def messages_url(self) -> str:
        return self.base_url.rstrip("/") + "/v1/messages"


def load_config() -> AIConfig:
    return AIConfig(
        provider=os.environ.get("CVE_AI_PROVIDER", "anthropic").strip().lower(),
        base_url=os.environ.get("AI_BASE_URL", "").strip(),
        token=os.environ.get("AI_TOKEN", "").strip(),
        model=os.environ.get("AI_MODEL", "").strip(),
    )


# ---------------------------------------------------------------------------
# Low-level Anthropic Messages call (stdlib only)
# ---------------------------------------------------------------------------

def _call_messages(cfg: AIConfig, system: str, user: str,
                   max_tokens: int = 512, timeout: int = 45) -> str:
    payload = {
        "model": cfg.model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(cfg.messages_url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("x-api-key", cfg.token)
    req.add_header("anthropic-version", ANTHROPIC_VERSION)
    # Some proxies also accept a bearer token; harmless to send both.
    req.add_header("authorization", f"Bearer {cfg.token}")
    # Some proxy endpoints sit behind Cloudflare which returns error 1010 for the default
    # urllib client signature. Present a normal browser-ish User-Agent + Accept.
    req.add_header("user-agent", USER_AGENT)
    req.add_header("accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise AIError(f"AI HTTP {e.code}: {detail}", status=e.code,
                      retryable=e.code in RETRYABLE_STATUS) from e
    except urllib.error.URLError as e:
        # Network-level failure (DNS, connection reset, timeout) — transient.
        raise AIError(f"AI request failed: {e.reason}", retryable=True) from e
    except TimeoutError as e:
        raise AIError("AI request timed out", retryable=True) from e

    try:
        obj = json.loads(body)
    except json.JSONDecodeError as e:
        raise AIError(f"AI returned non-JSON: {body[:300]}") from e

    # Anthropic shape: {"content":[{"type":"text","text":"..."}], ...}
    content = obj.get("content")
    if isinstance(content, list):
        texts = [c.get("text", "") for c in content if c.get("type") == "text"]
        if texts:
            return "".join(texts)
    # OpenAI-compatible fallback (some proxies normalise to this shape).
    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message", {})
        if msg.get("content"):
            return msg["content"]
    # A reasoning model can burn the whole budget thinking and return no text —
    # transient, so mark retryable.
    raise AIError(f"unexpected AI response shape: {body[:300]}", retryable=True)


def _call_messages_retrying(cfg: AIConfig, system: str, user: str,
                            max_tokens: int = 512, timeout: int = 45,
                            retries: int = MAX_RETRIES) -> str:
    """_call_messages with exponential backoff on transient failures."""
    last: AIError | None = None
    for attempt in range(retries + 1):
        try:
            return _call_messages(cfg, system, user, max_tokens, timeout)
        except AIError as e:
            last = e
            if not e.retryable or attempt == retries:
                raise
            # exponential backoff with jitter so concurrent workers desync
            delay = RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.6)
            time.sleep(delay)
    assert last is not None
    raise last


def ping(cfg: AIConfig | None = None) -> dict:
    """Health check used by the UI 'Test AI' button."""
    cfg = cfg or load_config()
    if not cfg.configured:
        return {"ok": False, "error": "AI not configured (missing env vars)"}
    try:
        # Give reasoning models (e.g. GLM behind "PRO") enough room that the
        # visible answer isn't swallowed by hidden thinking tokens.
        out = _call_messages_retrying(
            cfg,
            system="You are a health check. Reply with the single word PONG.",
            user="ping",
            max_tokens=256,
            timeout=25,
            retries=1,
        )
        reply = out.strip() or "(reachable, empty text)"
        return {"ok": True, "model": cfg.model, "reply": reply[:60]}
    except AIError as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a precise application-security triage assistant. You read a "
    "software vulnerability advisory and decide whether it genuinely belongs "
    "to a specified vulnerability class. Be strict: base the decision on the "
    "described root cause, not on superficial keyword matches. Always answer "
    "with a single JSON object and nothing else."
)


def _build_user_prompt(adv: dict, category: str) -> str:
    cat = CATEGORIES.get(category, {})
    label = cat.get("label", category)
    desc = cat.get("description", "")
    cwe_lines = ", ".join(f"CWE-{c} ({cwe_label(c)})"
                          for c in (cat.get("core", []) + cat.get("extended", [])))
    adv_cwes = ", ".join(adv.get("cwes") or []) or "none"
    packages = ", ".join(
        f"{p.get('ecosystem')}:{p.get('name')}" for p in (adv.get("packages") or [])
    ) or "n/a"
    description = (adv.get("description") or "")[:2500]

    return f"""Target vulnerability class: {label}
Definition: {desc}
Representative CWEs: {cwe_lines}

Advisory under review:
- GHSA: {adv.get('ghsa_id')}  CVE: {adv.get('cve_id')}
- Tagged CWEs: {adv_cwes}
- Affected packages: {packages}
- Summary: {adv.get('summary')}
- Description: {description}

Decide whether THIS advisory is genuinely an instance of "{label}".
Return ONLY this JSON object:
{{
  "is_match": true|false,
  "confidence": 0.0-1.0,
  "vuln_type": "short specific label, e.g. 'BOLA/IDOR', 'BFLA', 'missing authz', 'SQLi', 'reflected XSS', or 'other'",
  "reason": "one concise sentence citing the root cause"
}}"""


def _coerce_bool(value) -> bool:
    """Strict truthiness for model output: string 'false'/'no' must be False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "y", "1")
    return bool(value)


def _coerce_confidence(value) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _parse_verdict(text: str) -> dict:
    text = text.strip()
    # Extract the outermost JSON object (this also copes with markdown code
    # fences around it). A truncated / empty reasoning reply has no complete
    # object — that is transient, so mark it retryable.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise AIError(f"no JSON object in AI reply: {text[:200] or '(empty)'}",
                      retryable=True)
    try:
        obj = json.loads(text[start : end + 1])
    except json.JSONDecodeError as e:
        raise AIError(f"malformed JSON in AI reply: {e}", retryable=True) from e
    return {
        "is_match": _coerce_bool(obj.get("is_match")),
        "confidence": _coerce_confidence(obj.get("confidence", 0.0)),
        "vuln_type": str(obj.get("vuln_type", "") or "")[:60],
        "reason": str(obj.get("reason", "") or "")[:400],
        "cached": False,
    }


def classify_one(cfg: AIConfig, adv: dict, category: str,
                 retries: int = MAX_RETRIES) -> dict:
    """Classify one advisory, retrying the WHOLE call+parse on transient errors.

    Retries cover both the network layer (rate limits, gateway errors) and the
    parse layer (truncated / empty reasoning replies), because both clear up on
    a fresh attempt.
    """
    system = _SYSTEM_PROMPT
    user = _build_user_prompt(adv, category)
    last: AIError | None = None
    for attempt in range(retries + 1):
        try:
            text = _call_messages(cfg, system, user, max_tokens=CLASSIFY_MAX_TOKENS)
            return _parse_verdict(text)
        except AIError as e:
            last = e
            if not e.retryable or attempt == retries:
                raise
            time.sleep(RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.6))
    assert last is not None
    raise last


def classify_many(
    cfg: AIConfig,
    advisories: list[dict],
    category: str,
    max_workers: int = 6,
    on_result: Callable[[str, dict], None] | None = None,
) -> dict[str, dict]:
    """Classify many advisories concurrently. Returns {ghsa_id: verdict}.

    Failures are captured per-advisory as {error:...} so one bad call does not
    sink the whole batch. `on_result(ghsa_id, verdict)` is called as each
    completes (used to persist to cache incrementally).
    """
    results: dict[str, dict] = {}
    if not advisories:
        return results

    def _job(adv: dict) -> tuple[str, dict]:
        gid = adv.get("ghsa_id") or ""
        try:
            return gid, classify_one(cfg, adv, category)
        except AIError as e:
            return gid, {"error": str(e), "is_match": None,
                         "confidence": 0.0, "cached": False}
        except Exception as e:
            # Any unexpected bug must degrade to a per-advisory error verdict,
            # not propagate through fut.result() and sink the whole batch.
            logger.exception("unexpected classify error for %s", gid)
            return gid, {"error": str(e), "is_match": None,
                         "confidence": 0.0, "cached": False}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_job, a) for a in advisories]
        for fut in as_completed(futures):
            gid, verdict = fut.result()
            results[gid] = verdict
            if on_result and "error" not in verdict:
                try:
                    on_result(gid, verdict)
                except Exception:
                    logger.warning("on_result callback failed for %s", gid,
                                   exc_info=True)
    return results
