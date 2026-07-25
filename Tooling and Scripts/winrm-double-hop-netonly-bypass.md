# WinRM Double-Hop Bypass via `CreateProcessWithLogonW`/`LOGON_NETCREDENTIALS_ONLY`

The classic Kerberos "double-hop" problem: a WinRM (network-type) logon's
delegated credential material isn't delegatable to a third hop. Concretely —
you WinRM into host A as some user, and any command A runs that itself needs
to authenticate *outbound* to host B (a `repadmin`/`net use`/UNC-path call,
a SQL/LDAP query using the caller's identity, etc.) fails, because the
Kerberos ticket A holds for your session was never granted delegation rights
for a further hop, regardless of what AD rights the account itself has.

## Diagnosing it

The failure mode is distinctive and easy to misattribute to an ACL problem:

```
Error: The operation being requested was not performed because the user has not been authenticated. (1244)
```

or similar "not authenticated"/"access denied to a resource you should be
able to reach" errors on the *second* hop specifically, while direct
first-hop commands work fine. On [[garfield#Root|Garfield]], this produced a
different error (`1244`) than the genuine downstream ACL denial the account
hit *after* the double-hop was fixed — two structurally different failures
that happened to occur at the same step, worth telling apart rather than
assuming one fix resolves both.

## The usual workarounds, and why they often don't apply to a non-admin WinRM foothold

- **CredSSP** — needs the *target* to be configured for CredSSP delegation,
  not something an attacker can enable from a non-admin foothold.
- **Constrained/resource-based delegation configured server-side** — same
  problem, needs prior admin-level setup.
- **`Start-Process -Credential`** — the obvious first thing to try, but fails
  with `Access is denied` in a non-interactive WinRM session, because it
  needs an interactive window station that session doesn't have. Confirmed
  failing this way (with and without `-WindowStyle Hidden`) on Garfield.

## The fix: `CreateProcessWithLogonW` with `LOGON_NETCREDENTIALS_ONLY`

This is the programmatic equivalent of `runas /netonly` — it spawns a new
process that uses the *caller's* existing token locally, but creates a fresh
LSA logon session carrying the *specified* credentials for any outbound
network authentication. Critically, it doesn't need an interactive window
station, so it works fine from inside a plain non-interactive WinRM session:

```powershell
$sig = @"
using System; using System.Runtime.InteropServices;
public class NetOnly {
    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(string lpUsername, string lpDomain, string lpPassword, int dwLogonFlags, string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
}
"@
Add-Type -TypeDefinition $sig -Language CSharp
$LOGON_NETCREDENTIALS_ONLY = 0x2; $CREATE_NO_WINDOW = 0x08000000
$si = New-Object NetOnly+STARTUPINFO; $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object NetOnly+PROCESS_INFORMATION
$app = "C:\Windows\System32\cmd.exe"
$cmdline = 'C:\Windows\System32\cmd.exe /c <your outbound-auth command> > C:\Windows\Temp\out.txt 2>&1'
[NetOnly]::CreateProcessWithLogonW("<user>","<DOMAIN>","<password>",$LOGON_NETCREDENTIALS_ONLY,$app,$cmdline,$CREATE_NO_WINDOW,[IntPtr]::Zero,"C:\Windows\Temp",[ref]$si,[ref]$pi)
```

Redirect output to a file and read it back separately (`CreateProcessWithLogonW`
doesn't hand you a pipe directly) — same reasoning as any detached-process
pattern where the launcher can't block on the child's stdout.

## What this fixes vs. what it doesn't

This resolves the *transport* problem — the spawned process now has real,
delegatable network credentials for the second hop. It does **not** grant
any AD right the account didn't already have. On Garfield, fixing the
double-hop this way got `repadmin /rodcpwdrepl` to actually run at the
protocol level, but it still hit a genuine downstream ACL denial (`"Secret
Synchronization" control access right`) that the account simply didn't have
— a different, unrelated blocker the double-hop fix correctly stopped
masking.

## Seen on

- [[garfield#Root|Garfield]] — used to get `repadmin /rodcpwdrepl` running
  as a WinRM foothold account against a remote RODC, surfacing the real
  (separate) missing-right blocker underneath instead of a misleading
  authentication error.
