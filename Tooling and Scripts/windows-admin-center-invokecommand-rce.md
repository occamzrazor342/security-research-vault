# Windows Admin Center: Reverse-Engineering the Login/RCE Schema and Getting a Durable Shell

Windows Admin Center (WAC) is a browser-based Windows Server management
gateway that runs an Angular SPA against an undocumented REST API. When
public documentation doesn't cover the wire format you need (its login
flow, its command-execution endpoint), WAC ships its own answer in plain
sight: the served JS bundle and the login page's own inline `<script>`.
Reverse-engineer from that directly rather than guessing plausible field
names — it's faster and it's authoritative. ([Windows Admin Center overview
— Microsoft
Learn](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview))

## Login flow

Don't assume WAC's client-side crypto is JWE just because it "looks
JOSE-shaped." Pull the login page's inline script directly
(`curl -sk https://<target>:6600/`) and read what it actually does:
`POST /api/user/key` for an RSA JWK, then **plain RSA-OAEP-SHA256
encryption** (no JWE/JOSE envelope at all) of `{username,password,csrf}`,
base64-encoded as a `"packet"` field, POSTed to `/api/user/login`. The
`csrf` value is the login page's hidden `<input id="csrf">` field, **not**
the (empty, pre-login) `XSRF-TOKEN` cookie. A wrong crypto format produces
a misleading `400 — not authorized` that reads exactly like a valid,
RBAC-denied login — don't conclude "authenticated but denied" from that
response without first confirming the wire format against the page's own
script.

## Finding the real command-execution route

WAC's REST namespace isn't `/api/nodes/{node}/...` — that family 404s
identically for real and nonsense node names on a modern install. Pull the
actual Angular bundle (`main.<hash>.js`) and grep for its own static route
constants (`gatewayApi`, `gatewayNodeApi`, `serviceWinRest`,
`controllerPowerShell`) to find the real, live pattern:

```
POST /api/services/WinREST/PowerShell/nodes/{node}/InvokeCommand
Headers: X-XSRF-TOKEN: <XSRF-TOKEN cookie>, Cookie: <full session>
Body:    {"properties": {"script": "<powershell>"}}
```

A flat `{"command": "..."}`-shaped body (the obvious first guess) produces
a generic `CommandNotFound` for any well-formed JSON object — that
response doesn't mean the endpoint or verb is wrong, it means the model
binder deserialized *something* but the resulting DTO carried no usable
script property. Confirm the real DTO type name from a deliberately
malformed body (a bare JSON array against an object-expecting endpoint
returns a `JsonException` naming the exact backend type,
e.g. `Microsoft.WindowsAdminCenter.Features.PowerShell.PowerShellRequestEntity`)
before assuming the route itself is wrong.

## Reading a file the live gateway service has locked

`[System.IO.File]::ReadAllBytes()` throws `IOException` against any file
the WAC service (or any other live service) holds open. Open it explicitly
with `FileShare.ReadWrite` instead:

```powershell
$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$ms = New-Object System.IO.MemoryStream
$fs.CopyTo($ms); $fs.Close()
[System.Convert]::ToBase64String($ms.ToArray())
```

Generalizes to any locked file on the box, not just WAC's own SQLite
database — base64 out over whatever RCE channel is available, decode
locally.

## Getting a durable shell once `InvokeCommand` works

WMI process creation (`Invoke-CimMethod -ClassName Win32_Process -MethodName
Create`, or raw COM `SWbemLocator`) and `schtasks.exe /Create` can both
silently fail for a WAC-authenticated account even though the account
isn't otherwise locked down — check the *side effect* (does the expected
file/process actually appear), not just the HTTP response, since a `202`/
never-resolves response looks identical whether the command is slow or
silently rejected. If both fail, check the account's logon-session type
(`whoami /groups`) before assuming a system-wide WDAC/AppLocker block: a
**Network-type logon** (`NT AUTHORITY\NETWORK`, common for
browser-authenticated sessions like WAC's) is documented to be rejected by
Task Scheduler's COM API and DCOM-based WMI process creation for non-admin
accounts, as anti-credential-relay hardening — a completely different
account reached via a **local/console-type logon**
(`NT AUTHORITY\INTERACTIVE`/`CONSOLE LOGON`) on the exact same box can run
both successfully. Either way, `Start-Process` launching a binary directly
(a plain `CreateProcess` child, not routed through WMI/DCOM/Task Scheduler)
sidesteps the restriction entirely:

```powershell
Start-Process -FilePath powershell.exe -ArgumentList '-NoP -NonI -W Hidden -Enc <b64>' -WindowStyle Hidden
```

The resulting process is not tied to the originating HTTP request/response
cycle, but it's also not indefinitely persistent — expect it to die
unprompted after a few minutes (most plausibly the WAC gateway's own
job-object cleanup), and treat that as "re-trigger," not "debug."

## Seen on

- [[DanglingTree#Foothold|DanglingTree]] — `anderson.w`'s WAC login and the
  `InvokeCommand` RCE schema were both reverse-engineered this way after an
  initial JWE-based login attempt produced a misleading "authenticated but
  denied" false negative; `FileShare.ReadWrite` read WAC's own internal
  SQLite RBAC database to completion, and the Network-vs-Interactive
  logon-session-type distinction explained why `Invoke-CimMethod`/
  `schtasks.exe` silently failed for the WAC-derived account but worked
  cleanly for a different account reached via local RCE on the same box.
