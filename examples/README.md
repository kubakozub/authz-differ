# Examples

Templates to copy and adapt. **Replace every `REPLACE_WITH_*` value with your own
test-account sessions on a target you are authorized to test**, then pass
`--i-am-authorized` to run.

| File | Use with |
|---|---|
| `idor-config.json` | `authz-differ run --config idor-config.json --i-am-authorized` |
| `idor-config.yaml` | `authz-differ run --config idor-config.yaml --i-am-authorized` |
| `raw-request.http` + `identities.json` | `authz-differ run --request-file raw-request.http --identities identities.json --i-am-authorized` |

All three describe the same classic BOLA/IDOR test: an `owner` reads their own
object, while a different authenticated user (`attacker`) and an
`unauthenticated` client attempt the same request. Because `attacker` and
`unauthenticated` declare no object `id`, they inherit the owner's (`1001`) — so
the tool is asking "can someone else reach the owner's object?".

Generate fresh copies any time with:

```bash
authz-differ example --format json   > my-job.json
authz-differ example --format yaml   > my-job.yaml
authz-differ example --request       > my-req.http
authz-differ example --identities    > my-ids.json
```
