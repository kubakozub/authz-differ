"""A tiny, dependency-free parser for a *subset* of YAML.

This exists so a config file can be written in friendly YAML without pulling in
PyYAML (the whole tool is stdlib-only). It is intentionally small and supports
only what the authz-differ config schema needs:

* block mappings (``key: value``) with 2-space nested indentation
* block sequences (``- item``) of scalars and of mappings
* scalars: quoted ("..." / '...'), integers, floats, booleans, null (``~``)
* ``#`` comments (outside quotes) and ``---`` document markers

It is NOT a general YAML implementation -- flow style ({}, []), anchors, multi
-line block scalars, and merge keys are all unsupported. Feed it real YAML and
it will either parse the supported subset or raise ``YamlMiniError``.
"""
from __future__ import annotations

from typing import Any, List, Tuple


class YamlMiniError(ValueError):
    """Raised on input outside the supported YAML subset."""


def _strip_comment(line: str) -> str:
    in_single = in_double = escaped = False
    for i, ch in enumerate(line):
        if in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                return line[:i]
    return line


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        stripped = line.strip()
        if stripped == "" or stripped in ("---", "..."):
            continue
        leading = line[: len(line) - len(line.lstrip(" "))]
        if "\t" in leading:
            raise YamlMiniError("tabs are not allowed for indentation")
        indent = len(leading)
        out.append((indent, stripped))
    return out


def _unescape_double(s: str) -> str:
    out = []
    escaped = False
    for ch in s:
        if escaped:
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(ch, ch))
            escaped = False
        elif ch == "\\":
            escaped = True
        else:
            out.append(ch)
    return "".join(out)


def _scalar(token: str) -> Any:
    t = token.strip()
    if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
        return _unescape_double(t[1:-1])
    if len(t) >= 2 and t[0] == "'" and t[-1] == "'":
        return t[1:-1].replace("''", "'")
    if t in ("", "~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return t


def _split_kv(content: str):
    """Return (key, value) if ``content`` is a ``key: value`` entry, else None.

    A separator is a colon followed by whitespace or end-of-line (so ``://`` in
    a URL is not mistaken for one). Quoted regions are skipped.
    """
    in_single = in_double = escaped = False
    for i, ch in enumerate(content):
        if in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == ":" and (i + 1 == len(content) or content[i + 1] in " \t"):
                key = content[:i].strip()
                value = content[i + 1:].strip()
                return key, value
    return None


def load(text: str) -> Any:
    """Parse a YAML-subset document into Python objects."""
    lines = _logical_lines(text)
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamlMiniError("could not parse (stopped near: %r)" % (lines[idx][1],))
    return value


# Alias mirroring json.loads naming.
loads = load


def _parse_block(lines, i, indent):
    content = lines[i][1]
    if content == "-" or content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_map(lines, i, indent):
    result = {}
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise YamlMiniError("unexpected indent at: %r" % content)
        kv = _split_kv(content)
        if kv is None:
            raise YamlMiniError("expected 'key: value' but got: %r" % content)
        key, value = kv
        key = _scalar(key)
        if value == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                child, i = _parse_block(lines, i + 1, lines[i + 1][0])
                result[key] = child
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _scalar(value)
            i += 1
    return result, i


def _parse_list(lines, i, indent):
    result = []
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise YamlMiniError("unexpected indent in list at: %r" % content)
        if not (content == "-" or content.startswith("- ")):
            break
        item = content[1:].strip()
        if item == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                child, i = _parse_block(lines, i + 1, lines[i + 1][0])
                result.append(child)
            else:
                result.append(None)
                i += 1
        elif _split_kv(item) is not None:
            # A mapping item, e.g. "- name: owner". Treat the text after the
            # "- " as the first line of a mapping indented by two columns, so
            # subsequent sibling keys attach to the same dict.
            lines[i] = (indent + 2, item)
            child, i = _parse_map(lines, i, indent + 2)
            result.append(child)
        else:
            result.append(_scalar(item))
            i += 1
    return result, i
