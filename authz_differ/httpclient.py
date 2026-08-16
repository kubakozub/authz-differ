"""Replay a single logical request under one identity, using only urllib.

Design choices that matter for *authorization* testing:

* Redirects are NOT followed. A 3xx to ``/login`` is itself the answer -- if we
  followed it we would capture the login page's 200 instead of the deny.
* We read at most ``max_read_bytes`` and compare at most ``max_compare_bytes``.
* A transparent, tool-identifying User-Agent is sent unless overridden.

This module never decides anything; it only observes. All verdict logic lives
in :mod:`authz_differ.analyze`.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Dict, Optional

from .models import Identity, IdentityResult, RequestSpec, Settings

ID_TOKEN = "{{ID}}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that refuses to redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _merge_headers(base: Dict[str, str], override: Dict[str, str]) -> Dict[str, str]:
    """Case-insensitive header merge; ``override`` wins (e.g. per-identity Cookie)."""
    merged = {}  # lower-name -> (display-name, value)
    for name, val in base.items():
        merged[name.lower()] = (name, val)
    for name, val in override.items():
        merged[name.lower()] = (name, val)
    return {name: val for (name, val) in merged.values()}


def _substitute(text: str, object_id: Optional[str]) -> str:
    if object_id is None:
        return text
    return text.replace(ID_TOKEN, str(object_id))


def _one_line(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        return collapsed[:limit] + "…"
    return collapsed


def _make_opener(is_https: bool, settings: Settings):
    handlers = []
    if not settings.follow_redirects:
        handlers.append(_NoRedirect())
    if is_https:
        ctx = ssl.create_default_context()
        if not settings.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def build_effective_url(request: RequestSpec, identity: Identity) -> str:
    return _substitute(request.url, identity.object_id)


def build_effective_headers(request: RequestSpec, identity: Identity,
                            settings: Settings) -> Dict[str, str]:
    headers = _merge_headers(request.headers, identity.headers)
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = settings.user_agent
    return headers


def replay(request: RequestSpec, identity: Identity, settings: Settings) -> IdentityResult:
    """Send exactly one request for ``identity`` and capture the response."""
    url = build_effective_url(request, identity)
    headers = build_effective_headers(request, identity, settings)

    body = request.body
    if body is not None and identity.object_id is not None and ID_TOKEN.encode() in body:
        body = body.replace(ID_TOKEN.encode(), str(identity.object_id).encode())

    result = IdentityResult(
        name=identity.name,
        role=identity.role,
        url=url,
        object_id=identity.object_id,
    )

    is_https = url.lower().startswith("https")
    opener = _make_opener(is_https, settings)

    req = urllib.request.Request(url, data=body, method=request.method.upper())
    for name, value in headers.items():
        req.add_header(name, value)

    started = time.time()
    raw = b""
    try:
        try:
            resp = opener.open(req, timeout=settings.timeout)
            result.status = getattr(resp, "status", None)
            if result.status is None:
                result.status = resp.getcode()
            result.reason = getattr(resp, "reason", "") or ""
            result.location = resp.headers.get("Location")
            raw = resp.read(settings.max_read_bytes + 1)
            resp.close()
        except urllib.error.HTTPError as exc:
            # 3xx (no-redirect), 4xx and 5xx all surface here.
            result.status = exc.code
            result.reason = getattr(exc, "reason", "") or ""
            if exc.headers is not None:
                result.location = exc.headers.get("Location")
            try:
                raw = exc.read(settings.max_read_bytes + 1)
            except Exception:  # pragma: no cover - defensive
                raw = b""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError) as exc:
        result.error = _describe_error(exc)
    except Exception as exc:  # pragma: no cover - defensive catch-all
        result.error = "%s: %s" % (type(exc).__name__, exc)

    result.elapsed_ms = int((time.time() - started) * 1000)

    if len(raw) > settings.max_read_bytes:
        result.truncated = True
        raw = raw[: settings.max_read_bytes]

    result.length = len(raw)
    result.content_hash = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", "replace")
    result.compare_text = text[: settings.max_compare_bytes]
    result.snippet = _one_line(text, settings.snippet_chars)
    return result


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
        reason = getattr(exc, "reason", exc)
        return "connection error: %s" % (reason,)
    if isinstance(exc, socket.timeout):
        return "timed out"
    return "%s: %s" % (type(exc).__name__, exc)
