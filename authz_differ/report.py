"""Human table, machine JSON, and a copy-paste-ready evidence block.

Every rendered surface routes identity/request headers through
:mod:`authz_differ.redact` so credentials are never printed.
"""
from __future__ import annotations

import datetime
import json
from typing import List, Optional

from . import redact
from .models import (
    Analysis,
    IdentityResult,
    OVERALL_INCONCLUSIVE,
    OVERALL_LIKELY_OK,
    OVERALL_NEEDS_REVIEW,
    OVERALL_VULNERABLE,
    V_BASELINE,
    V_MISSING_AUTHN,
    V_POSSIBLE_IDOR,
)

_RESET = "\033[0m"
_COLORS = {
    "red": "\033[31;1m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}

_VERDICT_COLOR = {
    V_POSSIBLE_IDOR: "red",
    V_MISSING_AUTHN: "red",
    "ACCESS_DENIED": "green",
    "NOT_FOUND": "green",
    "NEEDS_REVIEW": "yellow",
    "REQUEST_ERROR": "magenta",
    V_BASELINE: "cyan",
}

_OVERALL_COLOR = {
    OVERALL_VULNERABLE: "red",
    OVERALL_LIKELY_OK: "green",
    OVERALL_NEEDS_REVIEW: "yellow",
    OVERALL_INCONCLUSIVE: "magenta",
    "BASELINE_FAILED": "magenta",
}


class _Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, color: Optional[str]) -> str:
        if not self.enabled or color is None:
            return text
        return "%s%s%s" % (_COLORS.get(color, ""), text, _RESET)


def _fmt_status(res: IdentityResult) -> str:
    if res.error:
        return "ERR"
    if res.status is None:
        return "-"
    return str(res.status)


def _fmt_sim(res: IdentityResult) -> str:
    if res.verdict == V_BASELINE:
        return "baseline"
    if res.similarity is None:
        return "-"
    return "%.2f" % res.similarity


def _fmt_delta(res: IdentityResult) -> str:
    if res.verdict == V_BASELINE or res.length_delta is None:
        return "-"
    return "%+d" % res.length_delta


# --------------------------------------------------------------------------- #
# Human output                                                                 #
# --------------------------------------------------------------------------- #
def render_human(analysis: Analysis, color: bool = False,
                 show_evidence: bool = True, stream=None) -> None:
    import sys

    out = stream or sys.stdout
    paint = _Painter(color)
    job = analysis.job
    owner = analysis.owner

    lines: List[str] = []
    lines.append(paint("=== authz-differ report ===", "bold"))
    lines.append("target : %s %s" % (job.request.method, job.request.url))
    if owner.object_id is not None:
        lines.append("object : id=%s (owner identity: %s)" % (owner.object_id, owner.name))
    lines.append("params : similarity>=%.2f  length_tol=%.2f  delay=%.2fs" % (
        job.settings.similarity_threshold,
        job.settings.length_tolerance,
        job.settings.delay,
    ))
    lines.append("time   : %s" % _now_iso())
    lines.append("")

    # Table.
    headers = ["IDENTITY", "ROLE", "ID", "STATUS", "LEN", "dLEN", "SIM", "VERDICT"]
    rows = []
    for res in analysis.results:
        rows.append([
            res.name,
            res.role,
            "" if res.object_id is None else str(res.object_id),
            _fmt_status(res),
            str(res.length),
            _fmt_delta(res),
            _fmt_sim(res),
            res.verdict or "-",
        ])
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render_row(cells, colorize_verdict=False):
        parts = []
        for i, cell in enumerate(cells):
            padded = cell.ljust(widths[i])
            if colorize_verdict and i == len(cells) - 1:
                padded = paint(padded, _VERDICT_COLOR.get(cell.strip(), None))
            parts.append(padded)
        return "  ".join(parts).rstrip()

    lines.append(paint(render_row(headers), "bold"))
    lines.append("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for res, row in zip(analysis.results, rows):
        lines.append(render_row(row, colorize_verdict=True))
    lines.append("")

    # Notes.
    lines.append(paint("notes:", "bold"))
    for res in analysis.results:
        lines.append("  - %-14s %s" % (res.name + ":", res.notes))
    lines.append("")

    overall_color = _OVERALL_COLOR.get(analysis.overall)
    lines.append("%s %s" % (paint("OVERALL:", "bold"),
                            paint(analysis.overall, overall_color)))
    lines.append("")

    out.write("\n".join(lines) + "\n")

    if show_evidence:
        out.write("\n" + build_evidence_markdown(analysis) + "\n")


# --------------------------------------------------------------------------- #
# Evidence (Markdown, ready to paste into a report)                            #
# --------------------------------------------------------------------------- #
def build_evidence_markdown(analysis: Analysis) -> str:
    job = analysis.job
    owner = analysis.owner
    lines: List[str] = []
    lines.append("----- evidence (copy into your report) -----")
    lines.append("")
    lines.append("### Broken access control -- %s" % analysis.overall)
    lines.append("")
    lines.append("**Endpoint:** `%s %s`" % (job.request.method, job.request.url))
    if owner.object_id is not None:
        lines.append("**Object under test:** `%s` (owned by identity `%s`)"
                     % (owner.object_id, owner.name))
    lines.append("")
    lines.append("| Identity | Role | Auth (redacted) | Status | Length | Similarity | Verdict |")
    lines.append("|---|---|---|---|---|---|---|")
    for res in analysis.results:
        ident = _identity_by_name(job, res.name)
        auth = redact.identity_auth_summary(ident.headers) if ident else "(none)"
        sim = "baseline" if res.verdict == V_BASELINE else (
            "-" if res.similarity is None else "%.2f" % res.similarity)
        lines.append("| %s | %s | %s | %s | %d | %s | %s |" % (
            res.name, res.role, auth, _fmt_status(res), res.length, sim, res.verdict))
    lines.append("")
    lines.append(_evidence_explanation(analysis))
    lines.append("")
    lines.append("**How to reproduce:** replay the exact request above, changing only the "
                 "session/authorization to each identity shown. The `fp=` fingerprints are "
                 "truncated SHA-256 hashes that prove the identities used different, "
                 "non-overlapping credentials without disclosing them.")
    lines.append("")
    lines.append("_Generated by authz-differ. Confirm manually before submitting._")
    return "\n".join(lines)


def _evidence_explanation(analysis: Analysis) -> str:
    idor = [r.name for r in analysis.results if r.verdict == V_POSSIBLE_IDOR]
    missing = [r.name for r in analysis.results if r.verdict == V_MISSING_AUTHN]
    if analysis.overall == OVERALL_VULNERABLE:
        bits = []
        if idor:
            bits.append("the non-owner identity(ies) %s received a response matching the "
                        "owner's, indicating the endpoint does not enforce per-object "
                        "authorization (IDOR / BOLA)" % ", ".join("`%s`" % n for n in idor))
        if missing:
            bits.append("the unauthenticated identity(ies) %s received protected data, "
                        "indicating missing authentication" % ", ".join("`%s`" % n for n in missing))
        return "**What this shows:** " + "; ".join(bits) + "."
    if analysis.overall == OVERALL_LIKELY_OK:
        return ("**What this shows:** every non-owner identity was refused (401/403/404), "
                "so per-object authorization appears to be enforced for this request.")
    if analysis.overall == OVERALL_NEEDS_REVIEW:
        return ("**What this shows:** at least one identity returned an ambiguous response "
                "(2xx with differing content, a redirect, or a client error). Inspect the "
                "snippets manually before drawing a conclusion.")
    if analysis.overall == "BASELINE_FAILED":
        return ("**What this shows:** the owner/baseline request did not return 2xx, so no "
                "reliable comparison could be made. Refresh the owner session and retry.")
    return ("**What this shows:** the result was inconclusive (transport errors or only a "
            "baseline). Re-run and inspect the per-identity notes.")


# --------------------------------------------------------------------------- #
# JSON output                                                                  #
# --------------------------------------------------------------------------- #
def build_json(analysis: Analysis) -> dict:
    job = analysis.job
    return {
        "tool": "authz-differ",
        "generated_at": _now_iso(),
        "overall": analysis.overall,
        "request": {
            "method": job.request.method,
            "url": job.request.url,
            "headers": redact.redact_headers(job.request.headers),
            "has_body": job.request.has_body(),
        },
        "settings": {
            "similarity_threshold": job.settings.similarity_threshold,
            "length_tolerance": job.settings.length_tolerance,
            "delay": job.settings.delay,
            "timeout": job.settings.timeout,
            "verify_tls": job.settings.verify_tls,
            "follow_redirects": job.settings.follow_redirects,
        },
        "identities": [
            {
                "name": ident.name,
                "role": ident.role,
                "object_id": ident.object_id,
                "headers": redact.redact_headers(ident.headers),
            }
            for ident in job.identities
        ],
        "results": [_result_json(res) for res in analysis.results],
        "findings": [
            {"identity": r.name, "role": r.role, "verdict": r.verdict, "note": r.notes}
            for r in analysis.results
            if r.verdict in (V_POSSIBLE_IDOR, V_MISSING_AUTHN)
        ],
    }


def _result_json(res: IdentityResult) -> dict:
    return {
        "name": res.name,
        "role": res.role,
        "object_id": res.object_id,
        "url": res.url,
        "status": res.status,
        "reason": res.reason,
        "length": res.length,
        "length_delta": res.length_delta,
        "truncated": res.truncated,
        "content_sha256": res.content_hash,
        "content_sha256_short": res.short_hash,
        "similarity": res.similarity,
        "verdict": res.verdict,
        "notes": res.notes,
        "snippet": res.snippet,
        "location": res.location,
        "error": res.error,
        "elapsed_ms": res.elapsed_ms,
    }


def render_json(analysis: Analysis) -> str:
    return json.dumps(build_json(analysis), indent=2)


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def _identity_by_name(job, name: str):
    for ident in job.identities:
        if ident.name == name:
            return ident
    return None


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
