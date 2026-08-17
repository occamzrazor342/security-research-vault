# Golden gMSA: Offline gMSA Password Derivation from the KDS Root Key

A way to compute the current (and every future) cleartext password for
*any* gMSA in the domain entirely offline, once the domain's KDS root key
material has been read once — no ongoing LDAP access to the gMSA object
itself is needed afterward, and rotating the gMSA's password does nothing
to stop it.

## Why this is different from the "normal" gMSA read

The standard gMSA technique this vault already covers (see
[[windows-active-directory-attack-surface-checklist]] §2) is an *online*
LDAP read: whoever holds the right group membership reads
`msDS-ManagedPassword` directly off the gMSA object, and a DC computes that
value on-demand server-side. Golden gMSA replaces that live read with an
**offline computation** the attacker performs themselves, using material
that isn't scoped to any one gMSA and is never rotated.

## The mechanism

Domain controllers derive a gMSA's password on-demand from two ingredients:
the **KDS root key** (a domain-wide secret, not per-account) and the
target gMSA's own `msDS-ManagedPasswordID` attribute (a timestamp,
readable by any authenticated domain user). The KDS root key object's
attributes — `msKds-RootKeyData`, `msKds-SecretAgreementParam`,
`msKds-KDFParam`, `msKds-KDFAlgorithmID`, `msKds-SecretAgreementAlgorithmID`,
`msKds-CreateTime`/`UseStartTime`/`Version`, `msKds-DomainID`,
`msKds-PrivateKeyLength`/`PublicKeyLength` — are enough, combined with a
target gMSA's `msDS-ManagedPasswordID`, to reproduce the exact same
derivation the DC itself performs (`KdsGetGmsaPasswordBasedOnKeyId` /
`_GenerateGmsaPassword`): derive `L0KeyID`/`L1KeyID`/`L2KeyID` from the
timestamp, build a Group Key Envelope from the root-key attributes, then
generate the 256-byte cleartext password for that specific gMSA — entirely
offline, no further DC interaction required per gMSA.

**[GoldenGMSA](https://github.com/Semperis/GoldenGMSA)** (Semperis)
automates this end to end: dump the KDS root key attributes once, then
compute the password for any gMSA SID in the domain at will.

## Privilege required, and why this still matters post-compromise

Reading the KDS root key object needs read/extended rights on it, which
only Domain Admins (or an equivalent Tier-0 principal) hold by default —
so this isn't a privilege-escalation primitive on its own, it's a
**persistence/re-escalation** one. Once any Tier-0 compromise happens
(even briefly), dumping the KDS root key turns that into standing,
silent access to every gMSA's password, indefinitely:

- **Regular gMSA password rotation is irrelevant.** The DC recomputes the
  same value from the same root key + the same derivation on its normal
  rotation schedule — an attacker holding the root key recomputes the new
  value the same way, without ever touching the gMSA object again.
- **The KDS root key itself has no rotation mechanism.** Per Semperis's
  own writeup, there is no supported way to rotate it — the only real
  remediation is provisioning entirely new gMSAs under a fresh KDS root
  key and retiring the old ones.
- **No security event fires by default** when the KDS root key's
  `msKds-RootKeyData` is read. A SACL has to be deliberately configured on
  the KDS root key container to get any audit signal at all.

## Practical takeaway for this vault

Worth checking on any AD engagement where DA (or equivalent) is reached
even transiently: dump the KDS root key while access is live, since it
converts a possibly-temporary compromise into silent, durable access to
every gMSA in the domain — including ones tied to services not otherwise
reachable from the current foothold.

## Seen on

Not yet applied in this vault — recorded ahead of use. Relevant any time a
gMSA is in scope and any Tier-0-equivalent access is reached, even
briefly, since the value of dumping the root key immediately rather than
just reading the one gMSA needed at the time is that it pays off for every
gMSA discovered later in the same engagement.

## Source

[Semperis: "Golden gMSA Attack"](https://www.semperis.com/blog/golden-gmsa-attack/)
