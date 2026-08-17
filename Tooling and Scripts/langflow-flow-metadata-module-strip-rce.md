# Langflow/Flow-Builder Component Resolution: Stripping the Module Reference Forces Raw Code Exec

A pattern seen on Langflow 1.8.2, but the underlying shape generalizes to
any low-code/no-code "flow" or "pipeline" builder that lets a component
carry **both** a resolvable class reference (a Python/JS module path, a
plugin ID, a registered component name) **and** an editable source-code
field for the same node, and where the build/execution backend has to
decide which one to trust.

## The pattern

In Langflow, every node in a flow's JSON definition has two parallel
fields describing the same component:

- `data.type` / `data.node.metadata.module` — a real import path
  (e.g. `lfx.components.input_output.chat_output.ChatOutput`) the backend
  resolves via a normal Python import to get the actual class.
- `data.node.template.code.value` — the component's full Python source,
  editable in the UI so a user can customize a component's behavior
  in-place.

Differential testing on a live target is the fastest way to establish which
field actually wins at runtime, without needing source access first:

1. Submit a modified `code` value **while leaving `metadata.module`
   intact**. If the change has no observable effect (a monkeypatch
   silently doesn't run, a deliberate `raise` never fires), the backend is
   ignoring the submitted source for execution — but check whether it's
   still being *compiled*: submit deliberately invalid Python syntax in
   the same field. If that produces a compile error in the response,
   the server does parse/compile whatever text is submitted; it just
   doesn't use the compiled result when a `module` path is present and
   resolvable.
2. Strip the module reference (empty `metadata` object, or remove the
   field entirely) and resubmit the same source-code hijack. If the
   custom code now executes, the resolver's real logic is "prefer the
   module import, fall back to compiling+instantiating the submitted
   source" — and critically, nothing on the server re-derives the correct
   module path from the component's own declared type/name before falling
   back, so the client fully controls which branch it takes.

Where this becomes **unauthenticated** RCE rather than just an
authenticated code-injection primitive: any endpoint whose own documented
purpose is to build/execute flow data supplied directly by the caller for
a flow that's legitimately marked public (Langflow's
`POST /api/v1/build_public_tmp/{flow_id}/flow`, whose docstring literally
states it exists to build a public flow "without requiring authentication"
and runs "using the flow owner's permissions"). The vulnerability isn't
that unauthenticated callers can submit flow data at all — that's the
endpoint's intended, documented behavior — it's that the server trusts a
client-suppliable metadata field to decide code-vs-import resolution
instead of re-deriving it itself from something only the server controls.

## Payload shape

Replace the target component's `code` with a full drop-in replacement class
matching the same interface (same input/output field names the flow's
edges expect), with the actual command inside its output method:

```python
class ChatOutput(ChatComponent):
    # ... same inputs/outputs signature as the real component ...
    async def message_response(self) -> Message:
        import subprocess
        out = subprocess.getoutput(<attacker-controlled command>)
        return Message(text=out)
```

then null out (or delete) the metadata block that would otherwise let the
backend import the real class instead:

```python
node["data"]["node"]["template"]["code"]["value"] = malicious_code
node["data"]["node"]["metadata"] = {}
```

Submit that modified flow JSON to the public-build endpoint and read the
result back out of the build's own event stream (Langflow: poll
`GET /api/v1/build_public_tmp/{job_id}/events`, look at the hijacked
node's `end_vertex` event, `data.build_data.data.results.<output>.data.text`).

## How to spot this class on a new target

- Any flow/pipeline/automation builder (Langflow, n8n, Node-RED-style
  tools, custom internal "workflow" products) that (a) lets a component's
  source be edited from the UI, and (b) exposes *any* endpoint that
  accepts caller-supplied flow/pipeline definitions — even one gated
  "public/shared flow only" — is worth this exact differential test.
- The tell that you're dealing with dual-resolution (module-or-code) is
  usually visible directly in an exported/fetched flow definition: look
  for a field that looks like an import path or component registry ID
  sitting right next to a field that looks like full source code, on the
  same node.

## Seen on

- [[Fireflow#Foothold|Fireflow]] — unauthenticated RCE as `www-data`
  against Langflow 1.8.2's `build_public_tmp` endpoint, discovered via
  live differential testing rather than a documented CVE (adjacent to, but
  mechanistically distinct from, CVE-2025-3248's `/api/v1/validate/code`
  and CVE-2026-5027's path-traversal file-write — see the writeup's CVE
  triage section for why neither matched directly).
