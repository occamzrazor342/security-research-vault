# SQLi FILE-Write: Target Web-Servable Directories, Not Just the Defaults

## The mistake this corrects

When a SQL injection point carries the `FILE` privilege and `INTO OUTFILE`/
`INTO DUMPFILE` fails against the obvious default targets — `/tmp`, the
database's own datadir, a schema's own data directory — it's tempting to
conclude the write capability itself is blocked (by `secure_file_priv`, an
AppArmor profile, a hardening patch, whatever) and move on to a different
vector entirely (waiting on a stored-XSS/admin-bot trigger, hunting for a
different injection point, etc.).

That conclusion is usually wrong. Those three defaults fail for mundane,
well-documented reasons that have nothing to do with the write primitive
being globally disabled:

- `/tmp` and the DB's own datadir are frequently root/mysql-owned with no
  write access for the DB service account itself at the OS level, or are
  explicitly excluded by `secure_file_priv`.
- A schema's own datadir is almost always owned `mysql:mysql`, not writable
  by the connecting account beyond what MySQL's own internal machinery uses
  it for.

None of that says anything about whether a **different**, web-servable
directory the *application itself* writes to (upload directories, avatar/
skin/attachment folders, cache directories) is writable by the DB process.
Those directories are frequently made world-writable (or group-writable to
the web server's group) specifically so the PHP/Node/whatever application
can write to them at runtime — and if the SQL service account runs under
the same OS user (or a group that directory's permissions grant to), the
`FILE` privilege can write there too, with zero relationship to
`secure_file_priv`'s directory restriction if that variable is unset/NULL.

## The concrete check

1. Confirm the account has `FILE`:
   ```sql
   SELECT GROUP_CONCAT(privilege_type SEPARATOR ',')
   FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", SUBSTRING_INDEX(CURRENT_USER(),'@',1), "'@'", SUBSTRING_INDEX(CURRENT_USER(),'@',-1), "'");
   ```
2. Enumerate the actual application's own upload/asset/cache directories —
   from disclosed source (a file-read primitive, a public repo, framework
   convention) rather than guessing blind. Check their permissions directly
   if any read primitive exists (`LOAD_FILE` existence + a `stat`-style
   check, or an authenticated directory listing).
3. Test the write against **that specific directory**, not the OS/DB
   defaults:
   ```sql
   ... UNION SELECT 1,1,1,1,1 INTO OUTFILE '/var/www/html/<app-writable-dir>/testwrite.txt' -- -
   ```
4. If it lands, confirm it's web-fetchable (`curl` the same path over HTTP)
   before building a webshell — a directory can be filesystem-writable by
   the DB account without being under the app's `DocumentRoot` at all.

## Multi-column UNION write gotcha

`INTO DUMPFILE` (unlike `INTO OUTFILE`, which adds row/column delimiters)
concatenates **every** selected column's value with **no separator and no
trailing newline**. If padding unused columns to match a table's column
count, pad with empty-string literals (`''`), not digit placeholders — a
stray digit landing directly after a webshell payload's closing `;` (inside
an unterminated `<?php` block, a common minimal-webshell design choice) is a
hard PHP parse error, not a silent no-op.

## Once the write lands: avoid subprocess exec if any confinement is suspected

If the target directory sits inside a hardened vhost (AppArmor `mod_apparmor`
hats, SELinux contexts, a restrictive `open_basedir`), a `system()`/`exec()`-
based webshell can succeed at the file-write step and still fail at the
command-execution step. Prefer webshells built on the target language's own
compiled-in capabilities instead of shelling out — PHP's `mysqli`/`curl_exec()`,
for instance — since those aren't mediated by exec-level confinement at all.
See [[apparmor-hat-exec-confinement-native-function-bypass]] for the
matching technique on the confinement side.

## Seen on

[[cobblestone#Foothold|Cobblestone]] — a second-order SQLi's `FILE`
privilege was declared "permanently patched" across multiple sessions after
failing against `/tmp` and MariaDB's own datadir; it worked immediately
against `/var/www/html/skins/`, a world-writable, web-servable directory
that had only ever been considered as a write *destination* for a different
(admin-gated) vulnerability, never tested directly.
