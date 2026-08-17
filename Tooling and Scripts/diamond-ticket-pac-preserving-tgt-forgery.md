# Diamond Ticket: Modifying a Real TGT Instead of Forging One From Scratch

A Kerberos ticket-forgery technique that evades detections built
specifically around Golden Tickets, by starting from a **genuine** TGT
issued by the real DC and modifying it in place, rather than fabricating
one wholesale from a stolen `krbtgt` hash.

## How it differs from a Golden Ticket mechanically

A Golden Ticket is built entirely offline: the attacker has the
`krbtgt` key and constructs a full TGT (including a fabricated PAC)
without any AS-REQ ever reaching a real DC. A Diamond Ticket instead:

1. Requests a **real** TGT for a real (often low-privileged) account via
   a normal AS-REQ — this genuinely reaches the DC and gets a real
   response.
2. Decrypts that TGT using the `krbtgt` key (same prerequisite as a
   Golden Ticket — this is not a lower-privilege technique, just a
   stealthier use of the same key).
3. Modifies the **PAC** inside the decrypted ticket — swapping in
   arbitrary group memberships/SIDs (e.g. Domain Admins) for the account
   the ticket already legitimately belongs to.
4. Recalculates the PAC's signatures and re-encrypts the ticket with the
   `krbtgt` key, producing a ticket that is byte-for-byte a real,
   DC-issued TGT except for the tampered authorization data inside it.

**Rubeus** implements this via its `diamond` command, automating steps
1-4 end to end (request → decrypt → modify → re-sign → re-encrypt).

## Why this evades Golden-Ticket-specific detection

Most Golden Ticket detection logic looks for the *absence* of a
corresponding AS-REQ at the DC for the TGT being used (since a real
Golden Ticket is never actually requested), or specific known-bad default
values Golden Ticket tools historically left in ticket fields (lifetime,
encryption type, RC4 use when AES was expected, etc.). A Diamond Ticket
defeats both: the AS-REQ genuinely happened, and ticket metadata like
timestamps and lifetime came from the DC's own real response rather than
attacker-supplied defaults — only the PAC's authorization data was
altered after the fact.

## Relationship to this vault's existing U2U note

This is a different mechanism from
[[kerberos-nt-hash-session-key-equalization-u2u]] (which manipulates an
account's *NT hash* to make a U2U exchange decrypt with a known session
key, for a downstream S4U2Proxy chain) — that note's technique doesn't
touch the PAC at all. They're both "make Kerberos accept a ticket that
says something untrue," via entirely separate mechanisms, and could in
principle both be relevant on the same box if one is blocked.

**A further evolution — the "Sapphire Ticket" — is reported (Kerberos
security research community, not independently source-verified by this
note) to avoid PAC tampering entirely by instead assembling a **real**
PAC via S4U2Self+U2U (obtaining a genuine PAC for the target identity
directly from the KDC, rather than editing a fabricated one) — which
would make it detect even less than a Diamond Ticket, since every field
including the PAC itself was genuinely issued by AD. This mechanism, if
confirmed, would use the exact S4U2Self+U2U primitive
[[kerberos-nt-hash-session-key-equalization-u2u]] already documents for a
different purpose. **Treat the Sapphire Ticket mechanism as unconfirmed
until pulled from a primary source directly** — this note's Diamond
Ticket content above was independently verified via WebFetch against the
cited Semperis article; the Sapphire description was not.

## Seen on

Not yet applied in this vault — recorded ahead of use. Relevant any time a
`krbtgt` hash is held (the same prerequisite as Golden Ticket use already
covered elsewhere in this vault) and there's reason to believe
Golden-Ticket-specific detection is in play — Diamond Ticket is a strict
stealth upgrade with no additional privilege required over what a Golden
Ticket already needs.

## Source

[Semperis: "A Diamond Ticket in the Ruff"](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
