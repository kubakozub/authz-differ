"""Core data structures, role/verdict vocabularies, and small helpers.

Everything here is plain stdlib (``dataclasses``) with no behaviour beyond
holding state, so it can be imported by every other module without creating a
dependency cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# --------------------------------------------------------------------------- #
# Roles                                                                        #
# --------------------------------------------------------------------------- #
# An identity plays exactly one role in an authorization test:
#   owner  -> the legitimate owner of the object under test (the baseline).
#   other  -> a *different* authenticated principal (the would-be attacker).
#   unauth -> no credentials at all (anonymous / public).
ROLE_OWNER = "owner"
ROLE_OTHER = "other"
ROLE_UNAUTH = "unauth"

_ROLE_ALIASES = {
    "owner": ROLE_OWNER,
    "victim": ROLE_OWNER,
    "baseline": ROLE_OWNER,
    "self": ROLE_OWNER,
    "other": ROLE_OTHER,
    "attacker": ROLE_OTHER,
    "adversary": ROLE_OTHER,
    "lowpriv": ROLE_OTHER,
    "low-priv": ROLE_OTHER,
    "user": ROLE_OTHER,
    "authenticated": ROLE_OTHER,
    "unauth": ROLE_UNAUTH,
    "unauthenticated": ROLE_UNAUTH,
    "anon": ROLE_UNAUTH,
    "anonymous": ROLE_UNAUTH,
    "none": ROLE_UNAUTH,
    "public": ROLE_UNAUTH,
    "guest": ROLE_UNAUTH,
}


def normalize_role(raw: Optional[str]) -> str:
    """Map a user-supplied role string onto the controlled vocabulary."""
    if not raw:
        return ROLE_OTHER
    return _ROLE_ALIASES.get(str(raw).strip().lower(), ROLE_OTHER)


# --------------------------------------------------------------------------- #
# Verdicts                                                                     #
# --------------------------------------------------------------------------- #
# Per-identity verdicts.
V_BASELINE = "BASELINE"                       # the owner row (reference point)
V_POSSIBLE_IDOR = "POSSIBLE_IDOR"             # non-owner saw the owner's data
V_MISSING_AUTHN = "MISSING_AUTHENTICATION"    # unauth saw protected data
V_ACCESS_DENIED = "ACCESS_DENIED"             # properly 401/403
V_NOT_FOUND = "NOT_FOUND"                      # 404 (not accessible / not enumerable)
V_NEEDS_REVIEW = "NEEDS_REVIEW"               # ambiguous, human should look
V_REQUEST_ERROR = "REQUEST_ERROR"             # transport error / 5xx

# Overall run verdicts.
OVERALL_VULNERABLE = "VULNERABLE"
OVERALL_LIKELY_OK = "LIKELY_OK"
OVERALL_NEEDS_REVIEW = "NEEDS_REVIEW"
OVERALL_BASELINE_FAILED = "BASELINE_FAILED"
OVERALL_INCONCLUSIVE = "INCONCLUSIVE"

# Verdicts that mean "this identity was correctly kept out".
_DENIED_VERDICTS = {V_ACCESS_DENIED, V_NOT_FOUND}
# Verdicts that constitute a positive finding.
_POSITIVE_VERDICTS = {V_POSSIBLE_IDOR, V_MISSING_AUTHN}


class ConfigError(ValueError):
    """Raised when the user's configuration / input cannot be used."""


# --------------------------------------------------------------------------- #
# Job definition (input)                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class RequestSpec:
    """The single logical request to replay (shared by every identity)."""

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None

    def has_body(self) -> bool:
        return self.body is not None and len(self.body) > 0


@dataclass
class Identity:
    """A named principal: a set of headers (auth) plus an optional object id."""

    name: str
    role: str = ROLE_OTHER
    headers: Dict[str, str] = field(default_factory=dict)
    object_id: Optional[str] = None  # substituted into the {{ID}} placeholder

    def __post_init__(self) -> None:
        self.role = normalize_role(self.role)


@dataclass
class Settings:
    """Tunable knobs. Defaults are deliberately conservative and polite."""

    delay: float = 1.0                    # seconds between requests (rate limit)
    similarity_threshold: float = 0.90    # difflib ratio to call two bodies "same"
    length_tolerance: float = 0.25        # allowed |len delta| / owner_len
    timeout: float = 20.0                 # per-request timeout (seconds)
    verify_tls: bool = True               # verify TLS certs (disable with care)
    follow_redirects: bool = False        # off: a 3xx to /login should be visible
    max_read_bytes: int = 2_000_000       # cap bytes read per response
    max_compare_bytes: int = 8192         # cap chars fed to difflib (keeps it fast)
    snippet_chars: int = 200              # length of the display snippet
    user_agent: str = "authz-differ/0.1 (+authorized-testing)"


@dataclass
class Job:
    """A fully-resolved unit of work: one request, N identities, settings."""

    request: RequestSpec
    identities: List[Identity]
    settings: Settings = field(default_factory=Settings)

    def owner(self) -> Optional[Identity]:
        for ident in self.identities:
            if ident.role == ROLE_OWNER:
                return ident
        return self.identities[0] if self.identities else None


# --------------------------------------------------------------------------- #
# Results (output)                                                             #
# --------------------------------------------------------------------------- #
@dataclass
class IdentityResult:
    """What we captured (and later concluded) for one identity's replay."""

    name: str
    role: str
    url: str
    object_id: Optional[str] = None

    # captured
    status: Optional[int] = None
    reason: str = ""
    length: int = 0
    truncated: bool = False
    content_hash: str = ""       # sha256 hex of the (capped) body
    compare_text: str = ""       # decoded, capped text used for similarity (not serialized)
    snippet: str = ""            # short one-line display snippet
    location: Optional[str] = None  # Location header on a 3xx
    error: Optional[str] = None
    elapsed_ms: int = 0

    # concluded (filled in by analyze)
    verdict: str = ""
    similarity: Optional[float] = None
    length_delta: Optional[int] = None
    notes: str = ""

    @property
    def short_hash(self) -> str:
        return self.content_hash[:12]

    @property
    def is_owner(self) -> bool:
        return self.role == ROLE_OWNER


@dataclass
class Analysis:
    """The complete outcome of a run: results plus an overall verdict."""

    job: Job
    results: List[IdentityResult]
    owner: IdentityResult
    overall: str
    findings: List[IdentityResult] = field(default_factory=list)

    def non_owner_results(self) -> List[IdentityResult]:
        return [r for r in self.results if r is not self.owner]

    def get(self, name: str) -> Optional[IdentityResult]:
        for r in self.results:
            if r.name == name:
                return r
        return None
