"""Command-line interface and the safety gate.

``authz-differ`` will not send a single request unless BOTH conditions hold:

* a concrete target (request + >= 2 identities) was supplied, and
* the operator passed ``--i-am-authorized`` to attest they are permitted to
  test that target.

Without the flag the tool prints a scope reminder and a redacted dry-run
preview, then exits non-zero having sent nothing.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import loader, report, runner
from .models import (
    ConfigError,
    Identity,
    Job,
    ROLE_OWNER,
    RequestSpec,
    Settings,
    OVERALL_BASELINE_FAILED,
    OVERALL_VULNERABLE,
)
from .redact import identity_auth_summary, redact_headers

__version__ = "0.1.0"

# Exit codes (documented in the README).
EXIT_OK = 0            # ran; no finding
EXIT_FINDING = 1       # ran; a positive finding (VULNERABLE)
EXIT_USAGE = 2         # argparse usage error (argparse default)
EXIT_REFUSED = 3       # refused: --i-am-authorized not supplied
EXIT_ERROR = 4         # configuration / baseline error

_BANNER = (
    "authz-differ v%s -- broken object/function-level authorization differ\n"
    "AUTHORIZED TESTING ONLY. Run this only against targets you own or are\n"
    "explicitly permitted to test (e.g. an in-scope bug-bounty asset). You are\n"
    "responsible for staying in scope and for every request this tool sends."
    % __version__
)


# --------------------------------------------------------------------------- #
# Argument parser                                                              #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authz-differ",
        description="Detect IDOR / BOLA / missing access control by replaying one "
                    "request under multiple identities and diffing the responses.",
        epilog="AUTHORIZED TESTING ONLY. You must be permitted to test the target.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version="authz-differ %s" % __version__)
    sub = parser.add_subparsers(dest="cmd")

    run = sub.add_parser(
        "run",
        help="replay one request under multiple identities and diff the responses",
        description="Replay a single request under multiple identities and diff "
                    "the responses to detect broken access control.",
    )
    src = run.add_argument_group("request source (use --config, or --request-file, or --url)")
    src.add_argument("--config", metavar="PATH",
                     help="JSON or YAML-subset job file (request + identities + settings)")
    src.add_argument("--request-file", metavar="PATH",
                     help="raw HTTP request file (Burp/.http style) for the shared request")
    src.add_argument("--url", metavar="URL", help="target URL (may contain {{ID}})")
    src.add_argument("--method", default="GET", help="HTTP method for --url (default GET)")
    src.add_argument("--header", action="append", default=[], metavar="'K: V'",
                     help="base header for --url (repeatable)")
    src.add_argument("--data", metavar="BODY", help="request body for --url")
    src.add_argument("--data-file", metavar="PATH", help="request body read from a file")
    src.add_argument("--scheme", default="https",
                     help="scheme for a raw request with a path-only target (default https)")
    src.add_argument("--host", help="Host for a raw request that lacks a Host header")

    idg = run.add_argument_group("identities")
    idg.add_argument("--identities", metavar="PATH", help="JSON array of identities")
    idg.add_argument("--identity", action="append", default=[], metavar="SPEC",
                     help="identity as NAME[:ROLE][#ID]=Header-Name: value (repeatable)")

    safe = run.add_argument_group("safety")
    safe.add_argument("--i-am-authorized", action="store_true",
                      help="REQUIRED to send traffic: attests you are authorized to test this target")
    safe.add_argument("--dry-run", action="store_true",
                      help="show what would be sent (redacted) without sending anything")

    tune = run.add_argument_group("tuning")
    tune.add_argument("--delay", type=float, metavar="SEC", help="delay between requests (default 1.0)")
    tune.add_argument("--similarity", type=float, metavar="R",
                      help="difflib similarity threshold 0..1 (default 0.90)")
    tune.add_argument("--length-tolerance", type=float, metavar="F",
                      help="allowed |len delta|/owner_len (default 0.25)")
    tune.add_argument("--compare-bytes", type=int, metavar="N",
                      help="max chars fed to difflib (default 8192)")
    tune.add_argument("--timeout", type=float, metavar="SEC", help="per-request timeout (default 20)")
    tune.add_argument("--insecure", action="store_true", help="do NOT verify TLS certificates")
    tune.add_argument("--follow-redirects", action="store_true",
                      help="follow 3xx (off by default so deny-redirects stay visible)")
    tune.add_argument("--user-agent", help="override the User-Agent header")

    outg = run.add_argument_group("output")
    outg.add_argument("--json", action="store_true", help="emit JSON to stdout")
    outg.add_argument("--output", metavar="PATH", help="also write the JSON report to a file")
    outg.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    outg.add_argument("--no-evidence", action="store_true", help="omit the evidence block")
    outg.add_argument("--quiet", action="store_true", help="suppress the banner and progress")

    ex = sub.add_parser("example", help="print an example config / request / identities file")
    ex.add_argument("--format", choices=["json", "yaml"], default="json",
                    help="format for the example config (default json)")
    ex.add_argument("--request", action="store_true", help="print an example raw HTTP request")
    ex.add_argument("--identities", action="store_true", help="print an example identities file")
    return parser


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "example":
        return cmd_example(args)
    if args.cmd == "run":
        return cmd_run(args)
    parser.print_help()
    return EXIT_OK


# --------------------------------------------------------------------------- #
# run                                                                          #
# --------------------------------------------------------------------------- #
def cmd_run(args) -> int:
    human = sys.stderr if args.json else sys.stdout

    try:
        job = build_job(args)
        apply_cli_settings(job.settings, args)
        validate_job(job, human, args.quiet)
    except ConfigError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    color = want_color(args, human)
    if not args.quiet:
        print(_BANNER, file=human)
        print("", file=human)

    runner.apply_owner_id(job)  # resolve {{ID}} inheritance for the preview

    if not args.i_am_authorized:
        print("REFUSING TO SEND: pass --i-am-authorized to confirm you are authorized to\n"
              "test this target. Showing a redacted dry-run preview instead.\n", file=human)
        _print_preview(job, human)
        return EXIT_REFUSED

    if args.dry_run:
        print("Dry run (--dry-run): no requests will be sent.\n", file=human)
        _print_preview(job, human)
        return EXIT_OK

    if not args.quiet:
        _print_scope_ack(job, human)

    def progress(event, identity, result):
        if args.quiet or event != "done":
            return
        status = result.status if result.status is not None else "ERR"
        flag = " [error]" if result.error else ""
        print("  [*] %-14s (%-6s) -> %s  %d bytes%s"
              % (identity.name, identity.role, status, result.length, flag), file=human)

    analysis = runner.run_job(job, progress=progress)
    if not args.quiet:
        print("", file=human)

    if args.json:
        json_text = report.render_json(analysis)
        print(json_text)
        if args.output:
            _write_file(args.output, json_text)
    else:
        report.render_human(analysis, color=color,
                            show_evidence=not args.no_evidence, stream=sys.stdout)
        if args.output:
            _write_file(args.output, report.render_json(analysis))

    if analysis.overall == OVERALL_BASELINE_FAILED:
        print("\nwarning: the owner/baseline request did not return 2xx; results are "
              "unreliable. Refresh the owner session and the URL, then retry.", file=human)
        return EXIT_ERROR
    return EXIT_FINDING if analysis.overall == OVERALL_VULNERABLE else EXIT_OK


# --------------------------------------------------------------------------- #
# building the job                                                             #
# --------------------------------------------------------------------------- #
def build_job(args) -> Job:
    sources = [bool(args.config), bool(args.request_file), bool(args.url)]
    if sum(sources) == 0:
        raise ConfigError("no target given: use --config, --request-file, or --url")
    if sum(sources) > 1:
        raise ConfigError("choose exactly one of --config / --request-file / --url")

    if args.config:
        return loader.load_config_file(args.config)

    if args.request_file:
        request = loader.parse_raw_http(
            _read(args.request_file), default_scheme=args.scheme, host_override=args.host)
    else:
        request = _request_from_url(args)

    identities = _identities_from_args(args)
    return Job(request=request, identities=identities, settings=Settings())


def _request_from_url(args) -> RequestSpec:
    headers = {}
    for item in args.header:
        if ":" not in item:
            raise ConfigError("bad --header %r (expected 'Name: value')" % item)
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    body = None
    if args.data_file:
        body = _read_bytes(args.data_file)
    elif args.data is not None:
        body = args.data.encode("utf-8")
    return RequestSpec(method=args.method.upper(), url=args.url, headers=headers, body=body)


def _identities_from_args(args) -> List[Identity]:
    identities: List[Identity] = []
    if args.identities:
        identities.extend(loader.load_identities_file(args.identities))
    for spec in args.identity:
        identities.append(loader.parse_identity_flag(spec))
    if not identities:
        raise ConfigError("no identities given: use --identities FILE and/or --identity SPEC")
    return identities


def apply_cli_settings(settings: Settings, args) -> None:
    if args.delay is not None:
        settings.delay = args.delay
    if args.similarity is not None:
        settings.similarity_threshold = args.similarity
    if args.length_tolerance is not None:
        settings.length_tolerance = args.length_tolerance
    if args.compare_bytes is not None:
        settings.max_compare_bytes = args.compare_bytes
    if args.timeout is not None:
        settings.timeout = args.timeout
    if args.insecure:
        settings.verify_tls = False
    if args.follow_redirects:
        settings.follow_redirects = True
    if args.user_agent:
        settings.user_agent = args.user_agent


def validate_job(job: Job, human, quiet: bool) -> None:
    if not job.request.url:
        raise ConfigError("no target URL")
    if len(job.identities) < 2:
        raise ConfigError("need at least 2 identities (an owner and at least one other)")
    owners = [i for i in job.identities if i.role == ROLE_OWNER]
    if len(owners) == 0:
        job.identities[0].role = ROLE_OWNER
        if not quiet:
            print("note: no identity marked 'owner'; treating '%s' as the baseline owner.\n"
                  % job.identities[0].name, file=human)
    elif len(owners) > 1:
        raise ConfigError(
            "multiple identities marked 'owner' (%s); exactly one baseline owner is required"
            % ", ".join(o.name for o in owners))


# --------------------------------------------------------------------------- #
# previews / banners                                                           #
# --------------------------------------------------------------------------- #
def _print_scope_ack(job: Job, human) -> None:
    print("Authorization confirmed (--i-am-authorized). Sending %d request(s), "
          "one per identity, %.2fs apart:" % (len(job.identities), job.settings.delay),
          file=human)
    print("  target: %s %s\n" % (job.request.method, job.request.url), file=human)


def _print_preview(job: Job, human) -> None:
    print("Would send %s %s under %d identities:"
          % (job.request.method, job.request.url, len(job.identities)), file=human)
    from .httpclient import build_effective_headers, build_effective_url
    for ident in job.identities:
        url = build_effective_url(job.request, ident)
        headers = build_effective_headers(job.request, ident, job.settings)
        print("  - %-14s role=%-6s -> %s" % (ident.name, ident.role, url), file=human)
        print("      auth: %s" % identity_auth_summary(ident.headers), file=human)
        safe = redact_headers(headers)
        shown = {k: v for k, v in safe.items() if k.lower() != "user-agent"}
        if shown:
            print("      headers: %s" % "; ".join("%s: %s" % kv for kv in shown.items()),
                  file=human)
    print("", file=human)


# --------------------------------------------------------------------------- #
# example subcommand                                                           #
# --------------------------------------------------------------------------- #
def cmd_example(args) -> int:
    if args.request:
        print(_EXAMPLE_RAW_REQUEST)
    elif args.identities:
        print(_EXAMPLE_IDENTITIES)
    elif args.format == "yaml":
        print(_EXAMPLE_YAML)
    else:
        print(_EXAMPLE_JSON)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def want_color(args, stream) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _write_file(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


_EXAMPLE_JSON = """{
  "request": {
    "method": "GET",
    "url": "https://api.example.com/api/v1/accounts/{{ID}}",
    "headers": { "Accept": "application/json" },
    "body": null
  },
  "identities": [
    { "name": "owner",    "role": "owner", "id": "1001",
      "headers": { "Cookie": "session=REPLACE_WITH_OWNER_SESSION" } },
    { "name": "attacker", "role": "other",
      "headers": { "Cookie": "session=REPLACE_WITH_ANOTHER_USER_SESSION" } },
    { "name": "anon",     "role": "unauth", "headers": {} }
  ],
  "settings": { "delay": 1.0, "similarity_threshold": 0.9, "timeout": 20 }
}"""

_EXAMPLE_YAML = """# authz-differ job (YAML subset)
request:
  method: GET
  url: https://api.example.com/api/v1/accounts/{{ID}}
  headers:
    Accept: application/json
identities:
  - name: owner
    role: owner
    id: 1001
    headers:
      Cookie: session=REPLACE_WITH_OWNER_SESSION
  - name: attacker
    role: other
    headers:
      Cookie: session=REPLACE_WITH_ANOTHER_USER_SESSION
  - name: anon
    role: unauth
settings:
  delay: 1.0
  similarity_threshold: 0.9
  timeout: 20"""

_EXAMPLE_IDENTITIES = """[
  { "name": "owner",    "role": "owner", "id": "1001",
    "headers": { "Cookie": "session=REPLACE_WITH_OWNER_SESSION" } },
  { "name": "attacker", "role": "other",
    "headers": { "Cookie": "session=REPLACE_WITH_ANOTHER_USER_SESSION" } },
  { "name": "anon",     "role": "unauth", "headers": {} }
]"""

_EXAMPLE_RAW_REQUEST = """GET /api/v1/accounts/{{ID}} HTTP/1.1
Host: api.example.com
Accept: application/json

"""
