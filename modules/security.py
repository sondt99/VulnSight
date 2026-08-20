"""Request security: CSRF origin checks, optional API token, rate limits."""

from __future__ import annotations

import hmac
import ipaddress
import os
import threading
import time
from collections import deque
from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_CROSS_SITE = frozenset({"cross-site", "same-site"})


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "enabled")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def configured_host(value: str) -> str:
    """Normalize an allowlisted host from config (name, IPv4/IPv6, optional port)."""
    text = (value or "").strip()
    if not text:
        return ""
    bare = text.strip("[]")
    try:
        return canonical_host(str(ipaddress.ip_address(bare)))
    except ValueError:
        pass
    if "://" not in text:
        text = "http://" + text
    host, ok = _hostname_from_url(text)
    return host if ok else ""


def public_hosts_from_env() -> list[str]:
    raw = os.environ.get("VULNSIGHT_PUBLIC_HOST", "")
    hosts: list[str] = []
    for part in raw.split(","):
        host = configured_host(part)
        if host:
            hosts.append(host)
    return hosts


def canonical_host(host: str | None) -> str:
    """Lowercase hostname; compress IPs; map every loopback address to one of LOOPBACK_HOSTS."""
    if not host:
        return ""
    text = host.strip().lower().rstrip(".")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text
    if ip.is_loopback:
        return "127.0.0.1" if ip.version == 4 else "::1"
    return ip.compressed


def is_loopback_bind(host: str) -> bool:
    """True if *host* is a loopback listen address (not 0.0.0.0 / ::)."""
    text = (host or "").strip().lower().strip("[]")
    if text in {"127.0.0.1", "localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def has_loaded_secrets() -> bool:
    keys = (
        "GLM_TOKEN",
        "AI_TOKEN",
        "ANTHROPIC_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "NVD_API_KEY",
    )
    return any(os.environ.get(key, "").strip() for key in keys)


def assert_safe_bind(host: str) -> None:
    """Refuse a non-loopback bind while credentials are loaded, unless overridden."""
    if is_loopback_bind(host):
        return
    if not has_loaded_secrets():
        return
    if not env_flag("VULNSIGHT_EXPOSE", False):
        raise SystemExit(
            f"Refusing to bind {host} while API credentials are loaded. "
            "Use HOST=127.0.0.1, or set VULNSIGHT_EXPOSE=1 and "
            "VULNSIGHT_API_TOKEN to listen on a non-loopback interface."
        )
    if not os.environ.get("VULNSIGHT_API_TOKEN", "").strip():
        raise SystemExit(
            f"Refusing to bind {host} with credentials loaded and no "
            "VULNSIGHT_API_TOKEN. Set a shared secret, or use HOST=127.0.0.1."
        )


def _hostname_from_url(value: str) -> tuple[str, bool]:
    """Return (canonical hostname, ok). ok is False if the URL is unusable as an Origin."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return "", False
    if parts.scheme not in ("http", "https"):
        return "", False
    # Reject userinfo and parser tricks such as http://evil@127.0.0.1
    if "@" in (parts.netloc or ""):
        return "", False
    if parts.username is not None or parts.password is not None:
        return "", False
    try:
        # Invalid ports (e.g. http://127.0.0.1:5000.evil.com) raise here.
        # hostname itself still returns 127.0.0.1, so this check is required.
        parts.port
    except ValueError:
        return "", False
    host = canonical_host(parts.hostname)
    if not host:
        return "", False
    return host, True


def origin_allowed(origin: str, request_host: str, extra_hosts: list[str] | None = None) -> bool:
    """Allow an Origin/Referer only for loopback, configured hosts, or a matching literal IP."""
    host, ok = _hostname_from_url(origin)
    if not ok:
        return False
    if host in LOOPBACK_HOSTS:
        return True
    extras = {configured_host(item) for item in (extra_hosts or []) if item}
    extras.discard("")
    if host in extras:
        return True
    try:
        req_host = canonical_host(urlsplit("//" + (request_host or "")).hostname)
    except ValueError:
        req_host = ""
    if not req_host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return host == req_host


def mutating_request_allowed(
    *,
    origin: str | None,
    referer: str | None,
    host: str,
    sec_fetch_site: str | None,
    extra_hosts: list[str] | None = None,
) -> bool:
    """CSRF gate for POST/PUT/PATCH/DELETE.

    A present Origin/Referer must parse to an allowed host. Missing Origin is
    allowed for non-browser clients, unless Sec-Fetch-Site says the request
    is cross-site (or same-site from another host).
    """
    extras = extra_hosts or []
    origin_value = (origin or "").strip()
    if origin_value:
        return origin_allowed(origin_value, host, extras)

    site = (sec_fetch_site or "").strip().lower()
    if site in _CROSS_SITE:
        return False

    referer_value = (referer or "").strip()
    if referer_value:
        return origin_allowed(referer_value, host, extras)
    return True


def extract_request_token(x_token: str | None, authorization: str | None) -> str:
    if x_token and x_token.strip():
        return x_token.strip()
    if authorization:
        scheme, _, remainder = authorization.strip().partition(" ")
        if scheme.lower() == "bearer" and remainder.strip():
            return remainder.strip()
    return ""


def token_matches(expected: str, provided: str) -> bool:
    """Constant-time compare. Empty *expected* means auth is not configured."""
    if not expected:
        return True
    if not provided:
        return False
    left = provided.encode("utf-8")
    right = expected.encode("utf-8")
    if len(left) != len(right):
        hmac.compare_digest(right, right)
        return False
    return hmac.compare_digest(left, right)


class RateLimiter:
    """In-process sliding window. *max_requests* hits per *window_seconds* per key."""

    def __init__(self, max_requests: int, window_seconds: int, max_keys: int = 4096):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(1, int(window_seconds))
        self.max_keys = max(1, int(max_keys))
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self.max_keys:
                    stale = min(
                        self._hits.items(),
                        key=lambda item: item[1][0] if item[1] else now,
                    )[0]
                    del self._hits[stale]
                bucket = deque()
                self._hits[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True
