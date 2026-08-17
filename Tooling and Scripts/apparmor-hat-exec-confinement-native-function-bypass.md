# AppArmor `mod_apparmor` Hats: Recognizing and Bypassing Per-Vhost Exec Confinement

## What it looks like

`mod_apparmor` lets Apache switch (`aa_change_hat()`) into a named AppArmor
sub-profile ("hat") for every request served out of a specific
`<Directory>`/vhost, independent of standard Unix file permissions. The
config tell is a line like:

```apache
<Directory /var/www/html>
    AAHatName cobblestone
</Directory>
```

The hat itself lives at `/etc/apparmor.d/<parent-profile>.d/<hat-name>` (or
similarly named, package-dependent) and typically looks like:

```
^cobblestone {
   #include <abstractions/base>
   /var/www/html/** r,
   /usr/bin/dash ixr,
   /usr/bin/cat ixr,
   /usr/bin/id ixr,
   deny /usr/bin/bash xr,
   deny /usr/bin/python3 xr,
   deny /bin/sh xr,
   ...
}
```

This is a real, independent confinement layer from file permissions — a
directory can be fully writable at the Unix level while any process spawned
via `execve()` from a request served there is still restricted to an
explicit allow-list of binaries.

## The trap: a "confirmed working" webshell/payload can still be dead on arrival

A webshell that writes and executes fine on an attacker's own unconfined
test box can fail silently once deployed against the real, hardened target
— specifically at the second-order exec, not the first. PHP's `system()`
(and most `exec()`-family functions) spawn via `execve("/bin/sh", ["sh",
"-c", cmd])`. On Debian, `/bin/sh` is a symlink to `/usr/bin/dash`. AppArmor
exec mediation resolves the **canonical target** of that symlink, not the
literal path string used — so if the hat allows `/usr/bin/dash ixr`, that
first exec succeeds even if `deny /bin/sh xr` is also listed (redundant, not
reachable via this call path).

The trap: if the payload then asks that shell to exec something *else*
(`bash -c '...'`, `python3 -c '...'`, a reverse-shell one-liner that shells
out to `nc`), and that second binary has no matching allow rule, that exec
fails **silently** — no error surfaces to the HTTP response, the request
just returns normally with no visible effect. This is easy to mistake for
"the payload didn't fire at all" rather than "the payload fired and its
second stage was blocked," especially if the exec chain is only reachable
through a rare/gated trigger (an admin-only endpoint, a one-shot injection
opportunity) where re-testing burns a scarce resource.

## Diagnosis

1. If any file-read primitive exists on the target (LFI, SQLi `LOAD_FILE`,
   etc.), read the vhost config for `AAHatName` directives and pull the hat
   file directly (`/etc/apparmor.d/<profile>.d/<name>`, or grep
   `/etc/apparmor.d/` broadly) — it is very frequently world-readable, since
   AppArmor profiles aren't secrets by design.
2. If a shell/webshell is already live but produces no output from a
   command that should obviously work (`hostname`, `uname -a`, a spawned
   reverse shell that never connects), test the allow-listed binaries first
   (`id`, `whoami`, `ls`, `cat`, `pwd`, `ps`, `ss` are common defaults) —
   getting output from those but not from anything else is the fingerprint
   of exec-hat confinement rather than a broken payload.
3. Match the confirmed-allowed binary set against what a normal reverse
   shell needs (`bash`, `python3`, `nc`, `perl` are commonly on the deny
   list specifically because they're the standard reverse-shell tools).

## The fix: don't shell out at all

The most reliable bypass is to avoid subprocess `exec()` entirely and use
the host language's own compiled-in capabilities instead — these aren't
mediated by AppArmor's exec rules because no `execve()` ever happens:

- PHP: `mysqli`/`PDO` for direct DB access, `curl_exec()` for outbound HTTP
  (including hitting a loopback-only internal service the exec confinement
  would otherwise block reaching via `curl`/`wget` binaries), `file_get_contents()`/
  `file_put_contents()` for file I/O.
- Python: the standard library's `socket`/`http.client`/`urllib` modules,
  `sqlite3`/DB-API drivers, instead of `subprocess`.

If the allow-list does include a usable shell (`dash`, `sh`) and some
allow-listed binaries, a payload can also be built entirely from what's
permitted — e.g. `dash`'s own `echo ... > file` redirection needs no second
exec at all, just the one already-allowed shell invocation.

## Seen on

[[cobblestone#Rabbit Holes|Cobblestone]] — an `AAHatName cobblestone` hat
denied `bash`/`python3`/`sh` while allowing `dash`/`id`/`cat`/`pwd`; the
final root-chain exploit was rewritten as a PHP-native `curl_exec()` port of
CVE-2024-47533 specifically to avoid triggering this confinement at all,
rather than trying to build a payload from the narrow allow-list.
