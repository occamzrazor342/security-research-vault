# Escalating a Narrow Constrained-Delegation Grant by Moving the SPN

If an account has constrained delegation with protocol transition
(`TRUSTED_TO_AUTH_FOR_DELEGATION` + `msDS-AllowedToDelegateTo` naming one
specific SPN string, e.g. `http/WEB01.pirate.htb`) but you actually need to
reach a *different* server, and the delegating account (or something it
controls) has `WriteProperty` on `servicePrincipalName` for the real
target, it's possible to redirect the whole grant to a different computer
object without ever changing `msDS-AllowedToDelegateTo` itself.

## Why this works — the two protocol facts underneath it

1. **S4U2Proxy's allow-list check is a string match against
   `msDS-AllowedToDelegateTo`, not an ownership check.** It confirms the
   *requested SPN string* is on the delegating account's allow-list; it
   never separately re-verifies that the SPN currently belongs to the
   computer object it was originally provisioned for. If the SPN string
   itself has been moved to a different computer object since the
   delegation was configured, the check still passes — but the KDC now
   encrypts the resulting service ticket with the *new* owner's key,
   because SPN → account key resolution happens at ticket-issuance time,
   against current directory state.
2. **A Kerberos `Ticket`'s `sname` (service name) sits in the unencrypted
   outer structure, not inside `EncTicketPart`** (see
   [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3) for
   the `Ticket`/`EncTicketPart` split) — so it carries no integrity
   protection and can be freely rewritten client-side after the KDC issues
   the ticket. `impacket-getST`'s `-altservice` flag automates exactly
   this: request the ticket for one SPN, then relabel `sname` to a
   different service class before use. Windows services generally accept a
   ticket the moment it decrypts correctly with their own account key —
   they don't independently re-check that `sname` matches the service
   class they're fronting.

Combine the two: move the *allowed* SPN string onto the real target's
computer object (changing which account's key the KDC uses to encrypt any
ticket issued for that exact string), request S4U2Proxy for that string
(still passes the allow-list check unchanged, but the ticket now comes back
keyed to the new owner), then rewrite `sname` via `-altservice` to whatever
service class the tool you actually want to run needs (e.g.
`CIFS/<target>` for `wmiexec`/`secretsdump`-style tooling). Net effect: a
ticket usable directly against a target the delegation was never nominally
authorized to reach.

## Preconditions

- Protocol-transition constrained delegation
  (`TRUSTED_TO_AUTH_FOR_DELEGATION`) on some account, naming an SPN string
  you can also move.
- Write access to `servicePrincipalName` on **both** ends of the move: the
  current SPN owner (to remove it — often trivially available since a
  computer account has default SELF/validated-write on its own SPN list if
  you hold that machine's own credential/hash) and the real target (to add
  it — this is the actual privilege being abused, typically a `WriteSPN`-
  style ACE via group membership).
- **Use a precise `MODIFY_DELETE`/`MODIFY_ADD` LDAP operation on the single
  SPN value being moved, not a full attribute replace.** A tool that
  replaces the whole multivalued `servicePrincipalName` attribute (e.g.
  `bloodyAD set object -v` in its default form) will silently wipe every
  other SPN the target computer object carries — write a small `ldap3`
  script targeting just the one value instead.

## Cleanup

This is a real, live AD state change (an SPN moved between two computer
objects), not a read-only technique — revert it (delete from the new
owner, re-add to the original owner) once the resulting ticket has done
its job, independent of whatever else needs cleaning up in the same
session.

## Seen on

- [[Pirate#Root|Pirate]] — `a.white_adm` had `TRUSTED_TO_AUTH_FOR_
  DELEGATION` to `http/WEB01.pirate.htb`/`HTTP/WEB01` only, and (via `IT`
  group membership) `WriteSPN` on `DC01$`. Moved `HTTP/WEB01.pirate.htb`
  off `WEB01$` (using `WEB01$`'s own recovered NTLM hash for the SELF
  write) onto `DC01$`, ran `impacket-getST -spn 'http/WEB01.pirate.htb'
  -impersonate Administrator -altservice 'CIFS/DC01.pirate.htb'`, and used
  the resulting ccache with `impacket-wmiexec -k` directly against DC01 —
  turning a delegation grant nominally scoped to a web server on a member
  box into `wmiexec` on the domain controller.
