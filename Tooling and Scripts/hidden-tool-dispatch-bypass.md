# Hidden Tool/Endpoint Excluded from a "List" Response but Still Live in the Dispatcher

A recurring anti-pattern in any framework that separates "what can I call"
(a discovery/listing endpoint) from "actually call it" (a dispatch/execute
endpoint): a service hides sensitive functionality by omitting it from the
listing response, while the dispatcher underneath validates the requested
name/id against the **full internal registry**, not the filtered list it
just chose to advertise. This shows up under different names depending on
the framework — MCP tool servers (`tools/list` vs `tools/call`), REST APIs
with an OpenAPI/discovery doc that's manually curated separately from the
router, GraphQL schemas with introspection disabled on some fields but the
resolver still wired up, admin CLIs with a `--help` list that's shorter
than the actual subcommand dispatch table.

## The mechanism

```python
VISIBLE_TOOLS = {"safe.thing_a": ..., "safe.thing_b": ...}
HIDDEN_TOOLS  = {"admin._dangerous_thing": ...}
ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}   # <- dispatch validates against this

@app.route('/tools/list')
def list_tools():
    return jsonify(VISIBLE_TOOLS)      # hidden tools never appear here

@app.route('/tools/call', methods=['POST'])
def call_tool():
    if not check_auth(): return 401
    name = request.json['name']
    if name not in ALL_TOOLS: return 404   # <- HIDDEN_TOOLS pass this check too
    ...  # dispatches to the hidden tool exactly like a visible one
```

The bug isn't a missing auth check — the same `X-API-Key`/token/session
gate that protects the visible tools also nominally "protects" the hidden
one. The actual flaw is that **omission from a list is not an
authorization boundary** — it's UI/discoverability sugar. The hidden
tool's real access control is "don't tell anyone the name exists," which
collapses the instant the name leaks through any other channel: source
code disclosure, a config file, an error message, a changelog, client-side
JS that still references it, or simply guessing a plausible name
(`_admin`, `_debug`, `_internal`, `_dump` are common tells).

## Why this keeps happening

Developers reason about the *listing* endpoint as the access-control
surface ("nobody will call a tool they don't know exists") and treat the
dispatcher's validation as a formality, not realizing the dispatcher is the
actual authorization boundary and needs its own explicit allow-list —
usually the exact same `VISIBLE_TOOLS` dict the list endpoint already
returns, not a merged superset that silently includes more.

## How to find it

1. Get the visible tool/endpoint/command list via the normal discovery
   channel.
2. Get the source (via a file-read primitive, decompiled client, leaked
   repo, verbose error/stack trace, etc.) or brute-force plausible hidden
   names against the dispatch endpoint directly, bypassing discovery
   entirely.
3. Compare the discovery list against every name the dispatcher will
   actually accept. Any name accepted by dispatch but absent from
   discovery is this pattern.
4. Call it directly through the dispatch endpoint with whatever auth the
   visible tools already require — if that succeeds, the "hiding" was the
   only protection it ever had.

## Fix pattern (what to look for when patch-diffing this class of bug)

The dispatcher must validate against the **same** set it advertises via
discovery — no separate/broader internal registry that dispatch checks
against but discovery doesn't. If genuinely privileged internal tooling
needs to exist in the same process, it needs its own explicit, stronger
authorization check (a different credential, a different network binding,
a hard-coded deny unless a specific caller context is present) — not
"leave it out of `/list`."

## Seen on
- [[devhub#Privesc|DevHub]] — a custom Flask "OPSMCP" service running as
  root on `127.0.0.1:5000`, gated by a static `X-API-Key`. `/tools/list`
  only returned four benign `ops.*` tools; `/tools/call` validated against
  `ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}`, so a hidden
  `ops._admin_dump` tool (discovered only by reading the analyst-readable
  source after a separate pivot) was fully callable with the same static
  API key. `ops._admin_dump(target="ssh_keys")` read `/root/.ssh/id_rsa`
  directly, since the Flask process itself ran as root — a straight line
  from "found the tool name" to full root SSH access.
