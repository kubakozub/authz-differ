"""Test suite for authz-differ (stdlib unittest only).

Highlights:

* ``TestIDORDetection`` spins up a real local HTTP server that simulates an
  IDOR endpoint (/account/1 hands Alice's data to anyone; /account/2 is
  properly guarded) and asserts the tool's verdicts end to end.
* ``TestClassifyAndSimilarity`` unit-tests the diff/similarity heuristics.
* ``TestRedaction`` proves cookies/tokens never survive into output.
* ``TestYamlMini`` / ``TestLoader`` cover the parsers.
* ``TestCli`` covers the JSON output, the exit codes, and -- importantly --
  that the tool sends NOTHING without ``--i-am-authorized``.
"""
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Make the package importable when running from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authz_differ import (  # noqa: E402
    Identity,
    Job,
    RequestSpec,
    Settings,
    analyze,
    classify,
    cli,
    run_job,
    similarity_ratio,
)
from authz_differ import loader, redact, report, yamlmini  # noqa: E402
from authz_differ.models import (  # noqa: E402
    IdentityResult,
    ROLE_OTHER,
    ROLE_OWNER,
    ROLE_UNAUTH,
    V_ACCESS_DENIED,
    V_MISSING_AUTHN,
    V_NEEDS_REVIEW,
    V_NOT_FOUND,
    V_POSSIBLE_IDOR,
    OVERALL_LIKELY_OK,
    OVERALL_VULNERABLE,
)

ALICE = json.dumps(
    {"id": 1, "name": "Alice", "email": "alice@example.com",
     "balance": 4211, "ssn": "111-11-1111"},
    indent=2,
)
BOB = json.dumps(
    {"id": 2, "name": "Bob", "email": "bob@example.com",
     "balance": 77, "ssn": "222-22-2222"},
    indent=2,
)

_TOKENS = {"alice-token": "alice", "bob-token": "bob"}


class _IDORHandler(BaseHTTPRequestHandler):
    """A deliberately vulnerable-and-safe pair of endpoints for testing."""

    hits = 0

    def log_message(self, *args):  # silence the server
        pass

    def _who(self):
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                token = part[len("session="):]
        return _TOKENS.get(token)

    def _send(self, code, payload):
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).hits += 1
        who = self._who()
        if self.path == "/account/1":
            # VULNERABLE: object-level authorization is missing entirely, so
            # any caller (including an unauthenticated one) gets Alice's data.
            self._send(200, ALICE)
        elif self.path == "/account/2":
            # SAFE: only the owner (Bob) may read account 2.
            if who == "bob":
                self._send(200, BOB)
            else:
                self._send(403, {"error": "forbidden"})
        else:
            self._send(404, {"error": "not found"})


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _IDORHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    return server, base


def _mk_result(name, role, status, body_text, error=None):
    raw = body_text.encode("utf-8")
    return IdentityResult(
        name=name,
        role=role,
        url="http://x/",
        status=status,
        length=len(raw),
        content_hash=hashlib.sha256(raw).hexdigest(),
        compare_text=body_text,
        error=error,
    )


# --------------------------------------------------------------------------- #
class TestClassifyAndSimilarity(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(delay=0.0)
        self.owner = _mk_result("owner", ROLE_OWNER, 200, ALICE)

    def test_similarity_identical(self):
        self.assertEqual(similarity_ratio(ALICE, ALICE, 8192), 1.0)

    def test_similarity_disjoint(self):
        ratio = similarity_ratio("aaaaaaaaaa", "zzzzzzzzzz", 8192)
        self.assertLess(ratio, 0.2)

    def test_similarity_near_identical(self):
        a = ALICE
        b = ALICE.replace("4211", "4212")  # one digit differs
        self.assertGreater(similarity_ratio(a, b, 8192), 0.95)

    def test_similarity_empty(self):
        self.assertEqual(similarity_ratio("", "", 8192), 1.0)
        self.assertEqual(similarity_ratio("x", "", 8192), 0.0)

    def test_other_identical_is_idor(self):
        res = _mk_result("attacker", ROLE_OTHER, 200, ALICE)
        verdict, sim, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, V_POSSIBLE_IDOR)
        self.assertEqual(sim, 1.0)

    def test_unauth_identical_is_missing_authn(self):
        res = _mk_result("anon", ROLE_UNAUTH, 200, ALICE)
        verdict, _, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, V_MISSING_AUTHN)

    def test_forbidden_is_access_denied(self):
        res = _mk_result("attacker", ROLE_OTHER, 403, '{"error":"forbidden"}')
        verdict, _, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, V_ACCESS_DENIED)

    def test_not_found(self):
        res = _mk_result("attacker", ROLE_OTHER, 404, '{"error":"nope"}')
        verdict, _, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, V_NOT_FOUND)

    def test_2xx_but_different_is_review(self):
        # Non-owner gets 200 but sees their own (different) object.
        res = _mk_result("attacker", ROLE_OTHER, 200, BOB)
        verdict, sim, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, V_NEEDS_REVIEW)
        self.assertLess(sim, 0.9)

    def test_error_is_request_error(self):
        res = _mk_result("attacker", ROLE_OTHER, None, "", error="timed out")
        verdict, _, _ = classify(self.owner, res, self.settings)
        self.assertEqual(verdict, "REQUEST_ERROR")


# --------------------------------------------------------------------------- #
class TestRedaction(unittest.TestCase):
    def test_cookie_value_is_hidden(self):
        out = redact.redact_header("Cookie", "session=supersecretvalue; theme=dark")
        self.assertNotIn("supersecretvalue", out)
        self.assertIn("session=", out)      # cookie name kept
        self.assertIn("redacted", out)
        self.assertIn("theme=", out)        # non-sensitive cookie name kept too

    def test_bearer_token_is_hidden(self):
        out = redact.redact_header("Authorization", "Bearer abc.def.ghijkl")
        self.assertNotIn("abc.def.ghijkl", out)
        self.assertIn("Bearer", out)        # scheme kept for context
        self.assertIn("redacted", out)

    def test_api_key_header_hidden(self):
        out = redact.redact_header("X-Api-Key", "9f8e7d6c5b4a")
        self.assertNotIn("9f8e7d6c5b4a", out)
        self.assertIn("redacted", out)

    def test_non_sensitive_passthrough(self):
        self.assertEqual(redact.redact_header("Accept", "application/json"),
                         "application/json")

    def test_fingerprint_stable_and_distinct(self):
        self.assertEqual(redact.fingerprint("alice"), redact.fingerprint("alice"))
        self.assertNotEqual(redact.fingerprint("alice"), redact.fingerprint("bob"))

    def test_headers_map_redacted(self):
        red = redact.redact_headers({"Cookie": "session=zzz", "Accept": "*/*"})
        self.assertNotIn("zzz", json.dumps(red))
        self.assertEqual(red["Accept"], "*/*")

    def test_auth_summary(self):
        summary = redact.identity_auth_summary({"Cookie": "session=zzz"})
        self.assertNotIn("zzz", summary)
        self.assertEqual(redact.identity_auth_summary({}), "(none)")


# --------------------------------------------------------------------------- #
class TestYamlMini(unittest.TestCase):
    def test_matches_expected(self):
        doc = (
            "request:\n"
            "  method: POST\n"
            "  url: https://api.example.com/x/{{ID}}\n"
            "  headers:\n"
            "    Accept: application/json\n"
            "identities:\n"
            "  - name: owner\n"
            "    role: owner\n"
            "    id: 1001\n"
            "  - name: anon\n"
            "    role: unauth\n"
            "settings:\n"
            "  delay: 0.5\n"
            "  verify_tls: false\n"
        )
        got = yamlmini.load(doc)
        self.assertEqual(got["request"]["method"], "POST")
        self.assertEqual(got["request"]["url"], "https://api.example.com/x/{{ID}}")
        self.assertEqual(got["request"]["headers"]["Accept"], "application/json")
        self.assertEqual(len(got["identities"]), 2)
        self.assertEqual(got["identities"][0], {"name": "owner", "role": "owner", "id": 1001})
        self.assertEqual(got["identities"][1], {"name": "anon", "role": "unauth"})
        self.assertEqual(got["settings"], {"delay": 0.5, "verify_tls": False})

    def test_comments_and_url_colons(self):
        got = yamlmini.load("url: https://h/p  # trailing comment\nn: 3\n")
        self.assertEqual(got, {"url": "https://h/p", "n": 3})

    def test_example_yaml_builds_a_job(self):
        job = loader.build_job_from_dict(yamlmini.load(cli._EXAMPLE_YAML))
        self.assertEqual(len(job.identities), 3)
        self.assertEqual(job.owner().name, "owner")


# --------------------------------------------------------------------------- #
class TestLoader(unittest.TestCase):
    def test_identity_flag(self):
        ident = loader.parse_identity_flag("attacker:other#42=Cookie: session=bob")
        self.assertEqual(ident.name, "attacker")
        self.assertEqual(ident.role, ROLE_OTHER)
        self.assertEqual(ident.object_id, "42")
        self.assertEqual(ident.headers["Cookie"], "session=bob")

    def test_identity_flag_unauth_no_header(self):
        ident = loader.parse_identity_flag("anon:unauth")
        self.assertEqual(ident.role, ROLE_UNAUTH)
        self.assertEqual(ident.headers, {})

    def test_raw_http(self):
        raw = ("GET /account/{{ID}} HTTP/1.1\r\n"
               "Host: api.example.com\r\n"
               "Accept: application/json\r\n\r\n")
        req = loader.parse_raw_http(raw)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "https://api.example.com/account/{{ID}}")
        self.assertEqual(req.headers["Accept"], "application/json")
        self.assertNotIn("Host", req.headers)

    def test_identity_shortcuts(self):
        job = loader.build_job_from_dict({
            "request": {"url": "https://h/x"},
            "identities": [
                {"name": "o", "role": "owner", "bearer": "TOK"},
                {"name": "a", "role": "unauth"},
            ],
        })
        self.assertEqual(job.identities[0].headers["Authorization"], "Bearer TOK")


# --------------------------------------------------------------------------- #
class _ServerTestCase(unittest.TestCase):
    def setUp(self):
        _IDORHandler.hits = 0
        self.server, self.base = _start_server()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _job(self, owner_id, cookies):
        """Build a job hitting /account/{{ID}} for the given identities.

        ``cookies`` maps identity name -> (role, cookie-or-None).
        """
        identities = []
        for name, (role, cookie) in cookies.items():
            headers = {"Cookie": cookie} if cookie else {}
            oid = owner_id if role == ROLE_OWNER else None
            identities.append(Identity(name=name, role=role, headers=headers, object_id=oid))
        request = RequestSpec(method="GET", url=self.base + "/account/{{ID}}")
        return Job(request=request, identities=identities, settings=Settings(delay=0.0))


class TestIDORDetection(_ServerTestCase):
    def test_vulnerable_account1_flags_idor_and_missing_authn(self):
        job = self._job("1", {
            "owner": (ROLE_OWNER, "session=alice-token"),
            "attacker": (ROLE_OTHER, "session=bob-token"),
            "anon": (ROLE_UNAUTH, None),
        })
        result = run_job(job)

        owner = result.get("owner")
        self.assertEqual(owner.status, 200)

        attacker = result.get("attacker")
        self.assertEqual(attacker.status, 200)
        self.assertEqual(attacker.verdict, V_POSSIBLE_IDOR)

        anon = result.get("anon")
        self.assertEqual(anon.status, 200)
        self.assertEqual(anon.verdict, V_MISSING_AUTHN)

        self.assertEqual(result.overall, OVERALL_VULNERABLE)

    def test_safe_account2_is_likely_ok(self):
        job = self._job("2", {
            "owner": (ROLE_OWNER, "session=bob-token"),     # Bob owns account 2
            "attacker": (ROLE_OTHER, "session=alice-token"),
            "anon": (ROLE_UNAUTH, None),
        })
        result = run_job(job)

        self.assertEqual(result.get("owner").status, 200)
        self.assertEqual(result.get("attacker").status, 403)
        self.assertEqual(result.get("attacker").verdict, V_ACCESS_DENIED)
        self.assertEqual(result.get("anon").status, 403)
        self.assertEqual(result.get("anon").verdict, V_ACCESS_DENIED)
        self.assertEqual(result.overall, OVERALL_LIKELY_OK)

    def test_id_inheritance_makes_attacker_target_owner_object(self):
        # attacker/anon have no id of their own; they must inherit the owner's.
        job = self._job("1", {
            "owner": (ROLE_OWNER, "session=alice-token"),
            "attacker": (ROLE_OTHER, "session=bob-token"),
        })
        run_job(job)
        for ident in job.identities:
            self.assertEqual(ident.object_id, "1")


# --------------------------------------------------------------------------- #
class TestCli(_ServerTestCase):
    def _write_config(self, owner_id, identities):
        cfg = {
            "request": {"method": "GET", "url": self.base + "/account/{{ID}}"},
            "identities": identities,
            "settings": {"delay": 0},
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as handle:
            json.dump(cfg, handle)
        self.addCleanup(os.remove, path)
        return path

    def test_cli_json_reports_vulnerable_and_exits_1(self):
        path = self._write_config("1", [
            {"name": "owner", "role": "owner", "id": "1", "headers": {"Cookie": "session=alice-token"}},
            {"name": "attacker", "role": "other", "headers": {"Cookie": "session=bob-token"}},
            {"name": "anon", "role": "unauth", "headers": {}},
        ])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["run", "--config", path, "--i-am-authorized",
                             "--delay", "0", "--json"])
        self.assertEqual(code, 1)  # EXIT_FINDING
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["overall"], OVERALL_VULNERABLE)
        verdicts = {r["name"]: r["verdict"] for r in payload["results"]}
        self.assertEqual(verdicts["attacker"], V_POSSIBLE_IDOR)
        self.assertEqual(verdicts["anon"], V_MISSING_AUTHN)
        # The secret cookie value must never appear in output.
        self.assertNotIn("alice-token", stdout.getvalue())
        self.assertNotIn("bob-token", stdout.getvalue())

    def test_cli_safe_scenario_exits_0(self):
        path = self._write_config("2", [
            {"name": "owner", "role": "owner", "id": "2", "headers": {"Cookie": "session=bob-token"}},
            {"name": "attacker", "role": "other", "headers": {"Cookie": "session=alice-token"}},
            {"name": "anon", "role": "unauth", "headers": {}},
        ])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["run", "--config", path, "--i-am-authorized",
                             "--delay", "0", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn(OVERALL_LIKELY_OK, stdout.getvalue())

    def test_cli_refuses_without_authorization_flag(self):
        path = self._write_config("1", [
            {"name": "owner", "role": "owner", "id": "1", "headers": {"Cookie": "session=alice-token"}},
            {"name": "attacker", "role": "other", "headers": {"Cookie": "session=bob-token"}},
        ])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["run", "--config", path, "--delay", "0"])
        self.assertEqual(code, 3)  # EXIT_REFUSED
        # Crucially: NOTHING was sent to the target.
        self.assertEqual(_IDORHandler.hits, 0)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertIn("REFUSING TO SEND", combined)
        self.assertNotIn("alice-token", combined)

    def test_cli_dry_run_sends_nothing(self):
        path = self._write_config("1", [
            {"name": "owner", "role": "owner", "id": "1", "headers": {"Cookie": "session=alice-token"}},
            {"name": "attacker", "role": "other", "headers": {"Cookie": "session=bob-token"}},
        ])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["run", "--config", path, "--i-am-authorized",
                             "--dry-run", "--delay", "0"])
        self.assertEqual(code, 0)
        self.assertEqual(_IDORHandler.hits, 0)


# --------------------------------------------------------------------------- #
class TestEvidenceAndJson(unittest.TestCase):
    def _analysis(self):
        owner = _mk_result("owner", ROLE_OWNER, 200, ALICE)
        attacker = _mk_result("attacker", ROLE_OTHER, 200, ALICE)
        anon = _mk_result("anon", ROLE_UNAUTH, 200, ALICE)
        job = Job(
            request=RequestSpec(method="GET", url="https://api.example.com/account/1"),
            identities=[
                Identity("owner", ROLE_OWNER, {"Cookie": "session=alice-token"}, "1"),
                Identity("attacker", ROLE_OTHER, {"Cookie": "session=bob-token"}, "1"),
                Identity("anon", ROLE_UNAUTH, {}, "1"),
            ],
            settings=Settings(delay=0.0),
        )
        return analyze(job, [owner, attacker, anon])

    def test_evidence_markdown_has_table_and_no_secret(self):
        md = report.build_evidence_markdown(self._analysis())
        self.assertIn("| Identity | Role |", md)
        self.assertIn(V_POSSIBLE_IDOR, md)
        self.assertIn(V_MISSING_AUTHN, md)
        self.assertNotIn("alice-token", md)
        self.assertNotIn("bob-token", md)

    def test_json_report_redacts_headers(self):
        payload = report.build_json(self._analysis())
        blob = json.dumps(payload)
        self.assertNotIn("alice-token", blob)
        self.assertNotIn("bob-token", blob)
        self.assertEqual(payload["overall"], OVERALL_VULNERABLE)
        self.assertEqual(len(payload["findings"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
