# The "HOST" Alias Trick: SPN Substitution on a Computer Account

Active Directory automatically maps a computer account's `HOST/` SPN onto a
fixed list of built-in alias service classes. Unless a service has been
specifically registered under its own dedicated account, requesting a
ticket for any of the following prefixes is transparently satisfied by the
same `HOST/<hostname>` SPN/key material a machine account already has:

| Requested prefix | Mapped service under `HOST/` |
|---|---|
| `cifs/` | SMB / file sharing / Remote Registry |
| `http/` | IIS / WinRM / web services |
| `rpcss/` | RPC endpoint mapper |
| `wsman/` | Windows Remote Management |
| `termsrv/` | Remote Desktop (RDP) |

**Attacker takeaway**: if a delegation primitive (RBCD, constrained
delegation, S4U2Self/S4U2Proxy, or a forged/injected ticket riding a trust)
gets you a service ticket for `cifs/`or `HOST/` on a target computer
account, that same ticket's underlying key material backs *all* of the
aliased services above — you don't need a separate delegation grant per
service. Rewriting the ticket's `sname` (e.g. `impacket-getST -altservice`)
or simply requesting the SPN you actually want in the first place both
work, since the KDC resolves any of these prefixes to the same computer
account key. This is the same underlying idea documented in
[[s4u2proxy-spn-hijack-altservice-ticket]] (rewriting `sname` post-hoc) —
the alias table above is *why* that rewrite has such a wide blast radius
on a typical Windows host: one delegation grant to `cifs/` effectively
opens `http/`, `wsman/`, `rpcss/`, and `termsrv/` too.

**Practical check before assuming a service is unreachable**: don't
conclude a target service (WinRM, RDP, RPC) is closed to a delegation/
ticket primitive just because it wasn't explicitly named in
`msDS-AllowedToDelegateTo` or the ticket's original `sname` — test the
aliased prefix directly, since the underlying key is shared regardless of
which specific SPN string was requested first.

## Seen on

Not yet applied in this vault — recorded ahead of use, for the next box
where a delegation/ticket primitive only appears to grant one specific
service class.
