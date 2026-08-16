"""Turn captured responses into authorization verdicts.

The heuristics (and their thresholds) are documented in the README. In short:

* Establish a baseline from the *owner* identity (it must return 2xx).
* For each non-owner identity, compare its response to the owner's:
    - 2xx + (byte-identical OR difflib ratio >= threshold AND similar length)
        -> the non-owner received the owner's data:
            * unauthenticated -> MISSING_AUTHENTICATION
            * otherwise       -> POSSIBLE_IDOR
    - 2xx but the body differs        -> NEEDS_REVIEW (own object? filtered view?)
    - 401 / 403                       -> ACCESS_DENIED (correct)
    - 404                             -> NOT_FOUND (not accessible / not enumerable)
    - 3xx / other 4xx                 -> NEEDS_REVIEW
    - 5xx / transport error           -> REQUEST_ERROR
* Overall: any positive -> VULNERABLE; any review -> NEEDS_REVIEW; all denied
  -> LIKELY_OK; otherwise INCONCLUSIVE.
"""
from __future__ import annotations

import difflib
from typing import List, Optional, Tuple

from .models import (
    Analysis,
    IdentityResult,
    Job,
    ROLE_UNAUTH,
    Settings,
    V_ACCESS_DENIED,
    V_BASELINE,
    V_MISSING_AUTHN,
    V_NEEDS_REVIEW,
    V_NOT_FOUND,
    V_POSSIBLE_IDOR,
    V_REQUEST_ERROR,
    OVERALL_BASELINE_FAILED,
    OVERALL_INCONCLUSIVE,
    OVERALL_LIKELY_OK,
    OVERALL_NEEDS_REVIEW,
    OVERALL_VULNERABLE,
    _DENIED_VERDICTS,
    _POSITIVE_VERDICTS,
)


def similarity_ratio(a: str, b: str, cap: int) -> float:
    """difflib similarity of two texts (0.0 .. 1.0), computed on a capped slice."""
    a = a[:cap]
    b = b[:cap]
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    # quick_ratio is a cheap upper bound; if it can't clear a useful floor the
    # exact ratio is not worth computing precisely.
    if matcher.quick_ratio() == 0.0:
        return 0.0
    return matcher.ratio()


def _is_2xx(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


def _length_similar(owner_len: int, other_len: int, tolerance: float) -> bool:
    if owner_len <= 0:
        return other_len == 0
    return abs(other_len - owner_len) / owner_len <= tolerance


def classify(owner: IdentityResult, res: IdentityResult, settings: Settings) -> Tuple[str, Optional[float], str]:
    """Return (verdict, similarity_or_None, human_note) for one non-owner result."""
    if res.error or res.status is None:
        return V_REQUEST_ERROR, None, "request failed: %s" % (res.error or "no response")

    status = res.status

    if _is_2xx(status):
        exact = bool(res.content_hash) and res.content_hash == owner.content_hash
        if exact:
            ratio = 1.0
        else:
            ratio = similarity_ratio(res.compare_text, owner.compare_text, settings.max_compare_bytes)
        length_ok = _length_similar(owner.length, res.length, settings.length_tolerance)
        looks_same = exact or (ratio >= settings.similarity_threshold and length_ok)

        if looks_same:
            how = ("a byte-identical copy of" if exact
                   else "a response %.0f%% similar to" % (ratio * 100.0))
            if res.role == ROLE_UNAUTH:
                return (V_MISSING_AUTHN, ratio,
                        "unauthenticated request received %s the owner's protected response" % how)
            return (V_POSSIBLE_IDOR, ratio,
                    "non-owner identity received %s the owner's response" % how)

        note = ("received HTTP %d but the body differs from the owner's (%.0f%% similar); "
                "could be the caller's own object, a filtered/empty view, or a generic 200 "
                "error page -- verify manually" % (status, ratio * 100.0))
        return V_NEEDS_REVIEW, ratio, note

    if status in (401, 403):
        return V_ACCESS_DENIED, None, "properly denied (HTTP %d)" % status
    if status == 404:
        return V_NOT_FOUND, None, "not found (HTTP 404) -- object not accessible / not enumerable"
    if 300 <= status < 400:
        loc = res.location or "?"
        return (V_NEEDS_REVIEW, None,
                "redirect (HTTP %d) to %s -- often a login/deny redirect; verify" % (status, loc))
    if 400 <= status < 500:
        return V_NEEDS_REVIEW, None, "client error (HTTP %d) -- verify the request is well-formed" % status
    return V_REQUEST_ERROR, None, "server error (HTTP %d)" % status


def _overall(owner: IdentityResult, others: List[IdentityResult]) -> str:
    if owner.error or not _is_2xx(owner.status):
        return OVERALL_BASELINE_FAILED
    if not others:
        return OVERALL_INCONCLUSIVE

    verdicts = [r.verdict for r in others]
    if any(v in _POSITIVE_VERDICTS for v in verdicts):
        return OVERALL_VULNERABLE
    if any(v == V_NEEDS_REVIEW for v in verdicts):
        return OVERALL_NEEDS_REVIEW

    denied = [v for v in verdicts if v in _DENIED_VERDICTS]
    errors = [v for v in verdicts if v == V_REQUEST_ERROR]
    if denied:
        # At least one identity was correctly refused; errors (if any) are noted
        # but do not overturn a clean denial.
        return OVERALL_LIKELY_OK
    if errors:
        return OVERALL_INCONCLUSIVE
    return OVERALL_LIKELY_OK


def analyze(job: Job, results: List[IdentityResult]) -> Analysis:
    """Attach verdicts to ``results`` and compute the overall outcome."""
    owner = next((r for r in results if r.is_owner), results[0] if results else None)
    if owner is None:
        raise ValueError("no results to analyze")

    owner.verdict = V_BASELINE
    owner.similarity = None
    owner.length_delta = 0
    if owner.error or not _is_2xx(owner.status):
        owner.notes = "baseline did NOT return 2xx -- check the owner's session and URL"
    else:
        owner.notes = "authorized baseline (owner)"

    others = [r for r in results if r is not owner]
    for res in others:
        verdict, similarity, note = classify(owner, res, job.settings)
        res.verdict = verdict
        res.similarity = similarity
        res.length_delta = res.length - owner.length
        res.notes = note

    overall = _overall(owner, others)
    findings = [r for r in others if r.verdict in _POSITIVE_VERDICTS]
    return Analysis(job=job, results=results, owner=owner, overall=overall, findings=findings)
