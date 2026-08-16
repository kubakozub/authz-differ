"""Build a :class:`~authz_differ.models.Job` from user input.

Three input surfaces are supported:

1. a structured config file (JSON, or the YAML subset in :mod:`yamlmini`);
2. a raw HTTP request file (Burp / ``.http`` style) for the shared request;
3. command-line identity specs for quick one-liners.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional

from . import yamlmini
from .models import (
    ConfigError,
    Identity,
    Job,
    RequestSpec,
    Settings,
    normalize_role,
)

_IDENTITY_RE = re.compile(
    r"^(?P<name>[^:#=]+)"
    r"(?::(?P<role>[^#=]+))?"
    r"(?:#(?P<id>[^=]+))?$"
)


# --------------------------------------------------------------------------- #
# Structured config (JSON / YAML-subset)                                       #
# --------------------------------------------------------------------------- #
def load_config_text(text: str, fmt: Optional[str] = None) -> Job:
    data = parse_config_text(text, fmt)
    return build_job_from_dict(data)


def parse_config_text(text: str, fmt: Optional[str] = None):
    if fmt == "json":
        return json.loads(text)
    if fmt == "yaml":
        return yamlmini.load(text)
    # Auto-detect: JSON first (stricter), fall back to the YAML subset.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yamlmini.load(text)


def load_config_file(path: str) -> Job:
    text = _read_text(path)
    lowered = path.lower()
    if lowered.endswith((".yaml", ".yml")):
        fmt = "yaml"
    elif lowered.endswith(".json"):
        fmt = "json"
    else:
        fmt = None
    try:
        data = parse_config_text(text, fmt)
    except (json.JSONDecodeError, yamlmini.YamlMiniError) as exc:
        raise ConfigError("could not parse config %s: %s" % (path, exc))
    return build_job_from_dict(data)


def build_job_from_dict(data) -> Job:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping with 'request' and 'identities'")

    req_data = data.get("request")
    if not isinstance(req_data, dict):
        raise ConfigError("config must contain a 'request' mapping")
    request = _request_from_dict(req_data)

    ident_data = data.get("identities")
    if not isinstance(ident_data, list) or not ident_data:
        raise ConfigError("config must contain a non-empty 'identities' list")
    identities = [_identity_from_dict(item) for item in ident_data]

    settings = settings_from_dict(data.get("settings"))
    return Job(request=request, identities=identities, settings=settings)


def _request_from_dict(data: dict) -> RequestSpec:
    method = str(data.get("method", "GET")).upper()
    url = data.get("url")
    if not url or not isinstance(url, str):
        raise ConfigError("request.url is required")
    headers = _string_map(data.get("headers", {}), "request.headers")
    body = _body_from_config(data)
    return RequestSpec(method=method, url=url, headers=headers, body=body)


def _body_from_config(data: dict) -> Optional[bytes]:
    if data.get("body_file"):
        return _read_bytes(str(data["body_file"]))
    if "body" in data and data["body"] is not None:
        body = data["body"]
        if isinstance(body, (dict, list)):
            return json.dumps(body).encode("utf-8")
        return str(body).encode("utf-8")
    return None


def _identity_from_dict(data) -> Identity:
    if not isinstance(data, dict):
        raise ConfigError("each identity must be a mapping")
    name = data.get("name")
    if not name:
        raise ConfigError("each identity needs a 'name'")
    role = normalize_role(data.get("role"))
    headers = _string_map(data.get("headers", {}), "identity.headers")

    # Ergonomic shortcuts that expand into headers.
    if data.get("cookie"):
        headers.setdefault("Cookie", str(data["cookie"]))
    if data.get("bearer"):
        headers["Authorization"] = "Bearer " + str(data["bearer"])
    elif data.get("authorization"):
        headers["Authorization"] = str(data["authorization"])

    object_id = data.get("id", data.get("object_id"))
    if object_id is not None:
        object_id = str(object_id)
    return Identity(name=str(name), role=role, headers=headers, object_id=object_id)


def settings_from_dict(data) -> Settings:
    settings = Settings()
    if not data:
        return settings
    if not isinstance(data, dict):
        raise ConfigError("'settings' must be a mapping")
    mapping = {
        "delay": ("delay", float),
        "similarity_threshold": ("similarity_threshold", float),
        "similarity": ("similarity_threshold", float),
        "length_tolerance": ("length_tolerance", float),
        "timeout": ("timeout", float),
        "verify_tls": ("verify_tls", bool),
        "follow_redirects": ("follow_redirects", bool),
        "max_read_bytes": ("max_read_bytes", int),
        "max_compare_bytes": ("max_compare_bytes", int),
        "snippet_chars": ("snippet_chars", int),
        "user_agent": ("user_agent", str),
    }
    for key, value in data.items():
        if key not in mapping:
            continue
        attr, caster = mapping[key]
        setattr(settings, attr, caster(value))
    return settings


# --------------------------------------------------------------------------- #
# Raw HTTP request files                                                       #
# --------------------------------------------------------------------------- #
def parse_raw_http(text: str, default_scheme: str = "https",
                   host_override: Optional[str] = None) -> RequestSpec:
    # Normalise newlines and split headers from body on the first blank line.
    normalized = text.replace("\r\n", "\n")
    if "\n\n" in normalized:
        head, _, body_text = normalized.partition("\n\n")
    else:
        head, body_text = normalized, ""
    lines = [ln for ln in head.split("\n") if ln.strip() != ""]
    if not lines:
        raise ConfigError("raw request file is empty")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ConfigError("malformed request line: %r" % lines[0])
    method, target = parts[0].upper(), parts[1]

    headers: Dict[str, str] = {}
    host = host_override
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if name.lower() == "host":
            if host is None:
                host = value
            continue  # the URL carries the host; avoid a duplicate header
        headers[name] = value

    if target.lower().startswith(("http://", "https://")):
        url = target
    else:
        if not host:
            raise ConfigError("raw request has no Host header; pass --host")
        url = "%s://%s%s" % (default_scheme, host, target)

    body = body_text.encode("utf-8") if body_text.strip() != "" else None
    return RequestSpec(method=method, url=url, headers=headers, body=body)


# --------------------------------------------------------------------------- #
# Identities from the CLI / a JSON file                                        #
# --------------------------------------------------------------------------- #
def parse_identity_flag(spec: str) -> Identity:
    """Parse ``NAME[:ROLE][#ID][=Header-Name: value]``."""
    descriptor, sep, header_line = spec.partition("=")
    match = _IDENTITY_RE.match(descriptor.strip())
    if not match:
        raise ConfigError("could not parse --identity %r" % spec)
    name = match.group("name").strip()
    role = normalize_role(match.group("role"))
    object_id = match.group("id")
    if object_id is not None:
        object_id = object_id.strip()

    headers: Dict[str, str] = {}
    if sep and header_line.strip():
        if ":" not in header_line:
            raise ConfigError(
                "identity header must be 'Header-Name: value' (got %r)" % header_line)
        hname, _, hvalue = header_line.partition(":")
        headers[hname.strip()] = hvalue.strip()
    return Identity(name=name, role=role, headers=headers, object_id=object_id)


def load_identities_file(path: str) -> List[Identity]:
    data = json.loads(_read_text(path))
    if not isinstance(data, list):
        raise ConfigError("identities file must be a JSON array")
    return [_identity_from_dict(item) for item in data]


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def _string_map(value, where: str) -> Dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict):
        raise ConfigError("%s must be a mapping of header name -> value" % where)
    return {str(k): str(v) for k, v in value.items()}


def _read_text(path: str) -> str:
    if not os.path.exists(path):
        raise ConfigError("file not found: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _read_bytes(path: str) -> bytes:
    if not os.path.exists(path):
        raise ConfigError("file not found: %s" % path)
    with open(path, "rb") as handle:
        return handle.read()
