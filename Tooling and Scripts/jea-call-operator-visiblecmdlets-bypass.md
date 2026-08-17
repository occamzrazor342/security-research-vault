# JEA `& { }` Bypass: a VisibleCmdlets Gap, Not a Language-Mode Gap

Just Enough Administration (JEA) restricted endpoints
([Overview of JEA — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview))
combine two independent restrictions that are easy to conflate:

1. **`SessionType = 'RestrictedRemoteServer'`** — caps the *visible command
   surface* to a curated allowlist (`VisibleCmdlets`/`VisibleFunctions` in a
   `.psrc` role-capability file, or PowerShell's own small built-in default
   set — `Clear-Host`, `Exit-PSSession`, `Get-Command`, `Get-FormatData`,
   `Get-Help`, `Measure-Object`, `Out-Default`, `Select-Object` — if no
   `RoleDefinitions`/role-capability override is configured at all).
2. **`LanguageMode = 'ConstrainedLanguage'`** — separately restricts what the
   *scripting language itself* can do (blocks arbitrary .NET type
   construction/method invocation, limits reflection, etc.), independent of
   which cmdlets are nominally visible.
   ([about_Language_Modes — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes))

A well-known, generic bypass class targets restriction #1 specifically, not
#2: wrapping a script in the call operator, **`& { <arbitrary PowerShell> }`**,
can execute cmdlets/functions that never appear in `Get-Command`'s own output
and are not on the endpoint's `VisibleCmdlets` allowlist at all. This works
because the endpoint's enforcement of "which cmdlet names are callable" is a
property of how the interactive command-dispatch layer resolves a typed
command name — not a hard gate the underlying PowerShell engine itself applies
to every code path a script block can reach. Where exactly the gap sits varies
by JEA configuration (module-restricted-vs-not, whether `NoLanguage` mode is
actually in effect at the transport layer vs. `ConstrainedLanguage` at the
runspace layer), so it's not guaranteed to work on every JEA deployment — but
it's a distinct, independently-worth-trying bypass class from any
ConstrainedLanguage-specific escape attempt (blocked `.NET` type construction,
blocked method invocation, etc.), and testing one does not rule out the other.

## Practical notes from weaponizing it

- **`evil-winrm` cannot drive this reliably**, because its own interactive
  command loop wraps every typed line in `Invoke-Expression` before sending
  it — which is itself not something the JEA session's dispatch layer treats
  as a bare cmdlet invocation the way a raw PSRP pipeline add would. Use a
  real PSRP client instead (`pypsrp`'s
  `RunspacePool(..., configuration_name='<jea-endpoint-name>')` +
  `PowerShell.add_script(...)`), which adds the wrapped `& { ... }` script
  directly to the pipeline the way `Enter-PSSession -ConfigurationName
  <name>` itself would.
- **A blocked `.NET`-type-construction bypass failing does not mean this
  bypass will also fail** — they're different gaps in different layers.
  Exhaustively testing one (e.g. every "core type" reachable under
  ConstrainedLanguage) and concluding the JEA endpoint is fully closed
  without separately trying `& { }` is a common false stopping point.
- Once inside via `& { }`, you're still bound by whatever *else* the calling
  identity's real Windows token can do (file ACLs, group membership, etc.) —
  this bypass restores ordinary unrestricted-session command execution as
  that identity, it doesn't itself grant any new Windows-level privilege.

## Seen on

- [[PingPong#Privesc|PingPong]] — the `restricted` JEA endpoint on DC1 was
  investigated across sessions 2–14 (13 sessions) and repeatedly, correctly
  found to have an exhaustively-enumerated 8-cmdlet/6-alias visible surface
  with no reachable `.NET`-type-construction escape (confirmed via a real,
  concretely-tested ConstrainedLanguage core-type sweep in session 14) — and
  was declared closed on that basis. Session 15 (via a single, narrowly
  user-authorized walkthrough consult after 14 sessions of independent effort,
  per this vault's routine walkthrough-override policy) tried `& { whoami }`/
  `& { Get-ChildItem C:\ }` against the exact same endpoint and got real,
  unrestricted output — directly contradicting session 14's own "no further
  code-execution surface" conclusion, because session 14 had only tested the
  ConstrainedLanguage bypass class, never this one. This is the canonical
  "don't declare a JEA endpoint closed after exhausting only one bypass
  class" lesson — see [[PingPong#Rabbit Holes|PingPong's Rabbit Holes]] for
  the full near-miss writeup.
