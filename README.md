# authz-differ

[![tests](https://github.com/kubakozub/authz-differ/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/authz-differ/actions/workflows/tests.yml)

**Replay one HTTP request under multiple identities and diff the responses to catch broken access control (IDOR / BOLA / missing authentication).**

`authz-differ` is a small, dependency-free assistant for **authorized** access-control testing. You hand it one request, two or more identities (your own sessions/tokens), and it sends that *single* request once per identity and diffs the results. If a different user — or nobody at all — gets back the owner's data, you have a finding.

- **Zero dependencies.** Pure Python 3.9+ standard library (`urllib`, `argparse`, `json`, `hashlib`, `difflib`, `ssl`). No `pip install` of anything.
- **Not a scanner.** Exactly one logical request per identity. No fuzzing, no crawling, no payloads, no target discovery.
- **Safe by construction.** It refuses to send anything until you pass `--i-am-authorized`, and it never prints your cookies or tokens.
- **Report-ready.** Emits a verdict table, machine-readable `--json`, and a copy-paste Markdown evidence block for your bug report.

---

## Why this bug class

Broken access control is the **#1 category in the OWASP Top 10 (2021)** and the single most common source of high-impact bug-bounty payouts. Two flavours dominate:

- **BOLA / IDOR (broken *object*-level authorization):** the endpoint authenticates you but never checks that *this* object is *yours*. `GET /api/accounts/1001` returns account 1001 to whoever asks, so changing the id to `1002` leaks someone else's data.
- **Broken *function*-level authorization / missing authentication:** an endpoint that should require a session (or an admin role) serves data to a lower-privileged or unauthenticated caller.

These bugs are invisible to a single-session proxy replay — the request *looks* perfectly normal. The only reliable way to see them is **differential**: send the same request as different principals and compare. That comparison, done carefully and safely, is the entire job of this tool.

---

## Install

```bash
git clone https://github.com/<you>/authz-differ.git
cd authz-differ
python -m authz_differ --help          # run straight from source, no install
# or
pip install .                          # installs the `authz-differ` command
```

Requires Python 3.9 or newer. There are no third-party dependencies.

---

## Worked example (two sessions → a verdict)

You have two accounts on an app you're allowed to test. Alice (the *owner*) can read `GET /account/1`. You want to know whether Bob (a *different* user) or an anonymous client can read it too. Write a job file:

```json
{
  "request": {
    "method": "GET",
    "url": "https://target.example/account/{{ID}}",
    "headers": { "Accept": "application/json" }
  },
  "identities": [
    { "name": "owner",    "role": "owner",  "id": "1", "headers": { "Cookie": "session=ALICE_SESSION" } },
    { "name": "attacker", "role": "other",             "headers": { "Cookie": "session=BOB_SESSION" } },
    { "name": "anon",     "role": "unauth",            "headers": {} }
  ],
  "settings": { "delay": 1.0 }
}
```

Run it (note the required authorization flag):

```bash
authz-differ run --config job.json --i-am-authorized
```

Against a vulnerable endpoint you get:

```
IDENTITY  ROLE    ID  STATUS  LEN  dLEN  SIM       VERDICT
-------------------------------------------------------------------------
owner     owner   1   200     83   -     baseline  BASELINE
attacker  other   1   200     83   +0    1.00      POSSIBLE_IDOR
anon      unauth  1   200     83   +0    1.00      MISSING_AUTHENTICATION

OVERALL: VULNERABLE
```

`attacker` (a real but *different* user) and `anon` (no credentials) both received a byte-identical copy of Alice's response. The tool follows up with a Markdown **evidence block** you can paste straight into a report. Against a properly-guarded endpoint every non-owner is refused and the overall verdict is `LIKELY_OK`.

The `{{ID}}` placeholder is substituted per identity. Identities without their own `id` **inherit the owner's** — so by default everyone targets the owner's object, which is exactly the IDOR question. Set an identity's own `id` when you want it to fetch its own resource instead.

---

## Defining the request

Pick **one** request source:

**1. A config file** (JSON, or the built-in YAML subset) — the full job in one file:

```bash
authz-differ run --config job.yaml --i-am-authorized
authz-differ example --format yaml > job.yaml     # print a template to start from
```

**2. A raw HTTP request file** (Burp / `.http` style) plus identities:

```bash
authz-differ run --request-file req.http --identities ids.json --i-am-authorized
authz-differ example --request > req.http
authz-differ example --identities > ids.json
```

**3. A one-liner** for quick checks:

```bash
authz-differ run \
  --url 'https://target.example/account/{{ID}}' \
  --identity 'owner:owner#1=Cookie: session=ALICE' \
  --identity 'attacker:other=Cookie: session=BOB' \
  --identity 'anon:unauth' \
  --i-am-authorized
```

Identity spec format: `NAME[:ROLE][#ID]=Header-Name: value`. Roles are normalised: `owner`/`victim` → owner, `attacker`/`other`/`user` → other, `anon`/`unauthenticated`/`public` → unauth.

### Config schema

| Key | Meaning |
|---|---|
| `request.method` | HTTP method (default `GET`). |
| `request.url` | Target URL, may contain `{{ID}}`. |
| `request.headers` | Base headers shared by every identity. |
| `request.body` / `request.body_file` | Optional body (string, JSON value, or file). `{{ID}}` is substituted here too. |
| `identities[]` | 2+ principals. Each has `name`, `role`, optional `id`, and `headers`. Shortcuts: `cookie`, `bearer`, `authorization`. |
| `settings` | `delay`, `similarity_threshold`, `length_tolerance`, `timeout`, `verify_tls`, `follow_redirects`, … |

Exactly one identity should be the `owner` (the baseline). If none is marked, the first is used and a note is printed.

---

## Detection heuristics (and their thresholds)

The **owner** identity establishes the baseline and **must** return `2xx`; if it doesn't, the run is `BASELINE_FAILED` (refresh the owner session). For every other identity:

| Observation | Verdict |
|---|---|
| `2xx` **and** body is byte-identical to the owner (SHA-256 match) **or** difflib similarity ≥ **0.90** *and* length within **±25 %** — from a **non-owner** authenticated identity | `POSSIBLE_IDOR` |
| …the same, but from the **unauthenticated** identity | `MISSING_AUTHENTICATION` |
| `2xx` but the body **differs** from the owner's | `NEEDS_REVIEW` (their own object? a filtered/empty view? a generic 200 error?) |
| `401` / `403` | `ACCESS_DENIED` (correctly refused) |
| `404` | `NOT_FOUND` (not accessible / not enumerable) |
| `3xx` or other `4xx` | `NEEDS_REVIEW` (often a login/deny redirect) |
| `5xx` or a transport error | `REQUEST_ERROR` |

**Overall:** any `POSSIBLE_IDOR`/`MISSING_AUTHENTICATION` → `VULNERABLE`; any `NEEDS_REVIEW` → `NEEDS_REVIEW`; all non-owners denied → `LIKELY_OK`; otherwise `INCONCLUSIVE`.

Similarity uses `difflib.SequenceMatcher` (`autojunk=False`) on the first `max_compare_bytes` characters (default **8192**, keeps it fast); an exact SHA-256 match short-circuits to `1.00`. Tune with `--similarity`, `--length-tolerance`, and `--compare-bytes`.

### Output & exit codes

- Default: a coloured verdict table + notes + the Markdown evidence block.
- `--json`: the full machine-readable report on stdout (all human text goes to stderr).
- `--output PATH`: also write the JSON report to a file.

| Exit code | Meaning |
|---|---|
| `0` | Ran; no finding (`LIKELY_OK` / `NEEDS_REVIEW` / dry-run). |
| `1` | Ran; a positive finding (`VULNERABLE`). |
| `2` | Usage error. |
| `3` | Refused: `--i-am-authorized` was not supplied (nothing was sent). |
| `4` | Configuration error or `BASELINE_FAILED`. |

---

## Authorized testing only / responsible disclosure

**This tool sends real HTTP requests to whatever target you point it at. Only use it against systems you own or are explicitly authorized to test** — for example an asset that is *in scope* for a bug-bounty program you are enrolled in, or your own staging environment.

By design it will not act on its own:

- It **sends nothing** until you pass `--i-am-authorized`, attesting that you are permitted to test the target. Without it you get a redacted dry-run preview and a non-zero exit.
- It has **no stored or hard-coded targets**, no target discovery, and no allowlist to smuggle traffic around — *you* supply every target and every credential.
- It sends **exactly one request per identity**, sequentially, with a configurable polite `--delay` (default 1s). It is not a scanner or a fuzzer.
- It sends a transparent, tool-identifying `User-Agent` by default.
- It **never prints your cookies or tokens.** Sensitive header values are replaced with `<redacted len=N fp=xxxxxxxx>`, where `fp` is a truncated, non-reversible SHA-256 fingerprint — enough to prove in a report that two identities used genuinely different credentials, without disclosing them.

When you find something: follow the target program's disclosure policy, report privately through the proper channel, include the (redacted) evidence block, and give the vendor time to fix it before any public disclosure. You are responsible for staying within scope and within the law. This project is provided for legitimate security research and comes with no warranty (see `LICENSE`).

---

## Limitations (read before you trust a verdict)

`authz-differ` is a **triage aid, not an oracle.** Always confirm a finding by hand.

- **False positives.** Endpoints that legitimately return the *same public data* to everyone (a public profile, a health check, a shared catalogue) will look like `POSSIBLE_IDOR`/`MISSING_AUTHENTICATION` because the responses genuinely match. Verify the data is actually private.
- **False negatives.** If a leak is *partial* (the attacker sees a redacted subset), the similarity may fall below threshold and land in `NEEDS_REVIEW` rather than `POSSIBLE_IDOR` — so read the review rows, don't just trust `LIKELY_OK`. Lower `--similarity` for noisy responses.
- **Volatile bodies.** Responses containing timestamps, CSRF tokens, request ids, or other per-request nonces will differ even when the underlying object is the same; a real leak can be masked as `NEEDS_REVIEW`. Compare snippets manually.
- **Stateful / non-idempotent endpoints.** The tool will happily replay a `POST`/`DELETE` several times. Only aim it at safe, idempotent reads unless you fully understand the side effects — running a mutating request under three identities performs that mutation three times.
- **Session assumptions.** A stale or logged-out owner session yields `BASELINE_FAILED`; anti-automation (WAF, rate limits, bot detection) can turn real denials into misleading `4xx`/`5xx`.
- **Not authorization-model aware.** It knows nothing about your app's roles or ownership rules beyond the identities you give it. It answers one narrow question — *did a different principal get the same response?* — and leaves the judgement to you.

---

## Development

```bash
python -m unittest discover -v      # run the test suite (stdlib unittest, no deps)
```

The tests spin up a local mock server that simulates a vulnerable IDOR endpoint and a safe one, and assert the end-to-end verdicts, alongside unit tests for the similarity/diff logic, the redaction, the parsers, and the CLI safety gate.

## License

MIT © 2026 Jakub Kozub. See [`LICENSE`](LICENSE).
