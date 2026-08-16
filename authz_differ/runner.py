"""Orchestration: replay every identity (politely, in order) then analyze.

This is the one place that actually sends traffic, so it is deliberately small
and easy to audit:

* the owner runs first (it is the baseline the others are diffed against);
* requests are strictly sequential with a configurable delay between them;
* exactly one request is sent per identity -- this is not a scanner or fuzzer.
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from .analyze import analyze
from .httpclient import replay
from .models import Analysis, Identity, IdentityResult, Job, ROLE_OWNER, ROLE_UNAUTH


ProgressFn = Callable[..., None]


def apply_owner_id(job: Job) -> None:
    """Fill in each identity's object id from the owner when it is unset.

    This encodes the classic IDOR test: by default every identity targets the
    *owner's* object, so we are asking "can a different principal reach the
    owner's resource?".
    """
    owner = job.owner()
    owner_id = owner.object_id if owner is not None else None
    if owner_id is None:
        return
    for identity in job.identities:
        if identity.object_id is None:
            identity.object_id = owner_id


def order_identities(identities: List[Identity]) -> List[Identity]:
    """Owner(s) first, then others in their original order, unauth last."""
    def sort_key(item):
        idx, ident = item
        if ident.role == ROLE_OWNER:
            bucket = 0
        elif ident.role == ROLE_UNAUTH:
            bucket = 2
        else:
            bucket = 1
        return (bucket, idx)

    return [ident for _, ident in sorted(enumerate(identities), key=sort_key)]


def run_job(job: Job, progress: Optional[ProgressFn] = None) -> Analysis:
    """Execute the job and return the completed :class:`Analysis`."""
    apply_owner_id(job)
    ordered = order_identities(job.identities)
    results: List[IdentityResult] = []

    for index, identity in enumerate(ordered):
        if progress is not None:
            progress("start", identity, None)
        result = replay(job.request, identity, job.settings)
        results.append(result)
        if progress is not None:
            progress("done", identity, result)
        is_last = index == len(ordered) - 1
        if not is_last and job.settings.delay > 0:
            time.sleep(job.settings.delay)

    return analyze(job, results)
