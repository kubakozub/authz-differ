"""Redaction helpers.

The whole point of the tool is to prove that *different* credentials produced
the *same* response. To do that in a report we need to show that identity A and
identity B really were distinct principals -- without ever leaking the secret
itself.

We therefore replace every sensitive header value with a placeholder of the
form ``<redacted len=42 fp=1a2b3c4d>`` where ``fp`` is a truncated,
non-reversible SHA-256 fingerprint. Two identities with the same fingerprint
used the same secret; two different fingerprints prove genuinely different
sessions -- all without printing the token.
"""
from __future__ import annotations

import hashlib
from typing import Dict

# Header names that are always sensitive.
_SENSITIVE_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "authentication",
}

# Substrings that mark a header (or cookie) name as carrying a secret.
_SENSITIVE_HINTS = (
    "token",
    "secret",
    "session",
    "auth",
    "apikey",
    "api-key",
    "api_key",
    "key",
    "password",
    "passwd",
    "credential",
    "cookie",
    "signature",
    "csrf",
    "xsrf",
    "sig",
)


def is_sensitive(name: str) -> bool:
    """True if a header name should have its value redacted."""
    n = name.strip().lower()
    if n in _SENSITIVE_HEADERS:
        return True
    return any(hint in n for hint in _SENSITIVE_HINTS)


def fingerprint(value: str) -> str:
    """Short, non-reversible fingerprint of a secret (first 8 hex of SHA-256)."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def _placeholder(value: str) -> str:
    return "<redacted len=%d fp=%s>" % (len(value), fingerprint(value))


def redact_cookie(value: str) -> str:
    """Redact each cookie value but keep the cookie *names* visible."""
    parts = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            name, _, val = chunk.partition("=")
            parts.append("%s=%s" % (name.strip(), _placeholder(val)))
        else:  # flag-style cookie attribute (e.g. HttpOnly)
            parts.append(chunk)
    return "; ".join(parts)


def redact_header(name: str, value) -> str:
    """Return a display-safe version of a single header value."""
    text = value if isinstance(value, str) else str(value)
    if not is_sensitive(name):
        return text
    if name.strip().lower() in ("cookie", "set-cookie"):
        return redact_cookie(text)
    # Keep a scheme prefix like "Bearer" / "Basic" for context, redact the rest.
    stripped = text.strip()
    for scheme in ("Bearer ", "Basic ", "Digest ", "Token ", "bearer ", "basic "):
        if stripped.startswith(scheme):
            secret = stripped[len(scheme):]
            return "%s%s" % (scheme, _placeholder(secret))
    return _placeholder(text)


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact an entire header mapping (order preserved)."""
    return {name: redact_header(name, val) for name, val in headers.items()}


def identity_auth_summary(headers: Dict[str, str]) -> str:
    """A short, redacted description of an identity's auth-bearing headers.

    Used in the evidence block so a reader can see the two identities really
    differed, without seeing the credentials.
    """
    picked = []
    for name, val in headers.items():
        if is_sensitive(name):
            picked.append("%s: %s" % (name, redact_header(name, val)))
    return "; ".join(picked) if picked else "(none)"
