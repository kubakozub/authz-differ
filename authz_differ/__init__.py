"""authz-differ: replay one request under multiple identities and diff the responses.

A small, stdlib-only assistant for *authorized* access-control testing. It does
not attack on its own: you supply the target, the request, and your own
credentials, and it replays that single request once per identity and diffs the
results to surface IDOR / BOLA / missing-authentication.

Public API::

    from authz_differ import Job, RequestSpec, Identity, Settings, run_job

See the README for the detection heuristics, thresholds, and the (mandatory)
authorized-testing policy.
"""
from __future__ import annotations

from .analyze import analyze, classify, similarity_ratio
from .models import (
    Analysis,
    ConfigError,
    Identity,
    IdentityResult,
    Job,
    RequestSpec,
    Settings,
    ROLE_OTHER,
    ROLE_OWNER,
    ROLE_UNAUTH,
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
    normalize_role,
)
from .runner import run_job

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Analysis",
    "ConfigError",
    "Identity",
    "IdentityResult",
    "Job",
    "RequestSpec",
    "Settings",
    "analyze",
    "classify",
    "similarity_ratio",
    "run_job",
    "normalize_role",
    "ROLE_OWNER",
    "ROLE_OTHER",
    "ROLE_UNAUTH",
    "V_BASELINE",
    "V_POSSIBLE_IDOR",
    "V_MISSING_AUTHN",
    "V_ACCESS_DENIED",
    "V_NOT_FOUND",
    "V_NEEDS_REVIEW",
    "V_REQUEST_ERROR",
    "OVERALL_VULNERABLE",
    "OVERALL_LIKELY_OK",
    "OVERALL_NEEDS_REVIEW",
    "OVERALL_BASELINE_FAILED",
    "OVERALL_INCONCLUSIVE",
]
