# ESC4 Variant: Re-Creating an Orphaned/Published-but-Nonexistent Certificate Template

A CA's own `certificateTemplates` published-name list and the actual set
of `pKICertificateTemplate` objects under `CN=Certificate Templates,...`
are two independently-maintained facts. If a name is ever removed from the
AD side (an incomplete provisioning script, a rollback, manual cleanup)
without also being unpublished from the CA, the CA is left trusting a name
with **no backing object at all** — a distinct misconfiguration class from
the usual ESC4 story (an *existing* template with a dangerous ACL you can
reconfigure).

## Recognizing it — and the trap that looks identical

A CA-side enrollment attempt against an orphaned name returns
`CERTSRV_E_UNSUPPORTED_CERT_TYPE` from the CA's own policy module,
consistently, for every account tested — including one you'd otherwise
expect to have rights (a low-priv identity, a service account with broad
AD visibility). **This is the exact same observable signature an
ACL-protected object produces if its explicit DACL genuinely denies
template-resolution to everyone but its owner.** Don't stop at "the CA
denies this identically for everyone I can test" and conclude it's an
access-control problem — that conclusion is unfalsifiable from CA-side
enrollment behavior alone, since both a real ACL denial and a genuinely
missing object look the same from outside.

## The decisive check: does the object exist at all?

Resolve it with a direct existence probe against the AD side, not another
enrollment attempt:

```python
# ldap3, or any raw LDAP client
conn.delete("CN=<TemplateName>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...")
```

- `insufficientAccessRights` → the object exists and you're genuinely ACL-blocked.
- `noSuchObject` (or a plain zero-result search for that exact DN) → **the
  object doesn't exist.** This is the orphaned-name case.

(A `delete()` attempt is a cheap, fast existence probe even with no intent
to actually delete anything — a real ACE-holding account will fail with an
access-control error before the delete would ever be attempted against a
real object; an account with no rights at all against a genuinely
nonexistent DN gets the "doesn't exist" answer regardless.)

## Weaponizing it

If orphaned, any principal holding `CreateChild` on the `CN=Certificate
Templates` **container** (a much more common right to hold than `WriteDacl`
on any individual template, and structurally the standard ESC4-via-new-
template right) can simply create a fresh object under the exact orphaned
name:

```powershell
New-ADObject -Name "<OrphanedTemplateName>" -Type pKICertificateTemplate `
    -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=..." `
    -OtherAttributes @{
      'flags'=0; 'revision'=100; 'pKIDefaultKeySpec'=1; 'pKIMaxIssuingDepth'=0
      'pKIExtendedKeyUsage'=@('1.3.6.1.5.5.7.3.2')          # Client Authentication
      'msPKI-Enrollment-Flag'=0                               # no manager approval
      'msPKI-Private-Key-Flag'=0                              # do NOT clone this verbatim from a stock template
      'msPKI-Certificate-Name-Flag'=1                         # ENROLLEE_SUPPLIES_SUBJECT
      'msPKI-Minimal-Key-Size'=2048
      'msPKI-Template-Schema-Version'=2; 'msPKI-Template-Minor-Revision'=1
      'msPKI-Cert-Template-OID'="1.3.6.1.4.1.311.21.8.<random>.<random>.1.2"
      'msPKI-Certificate-Application-Policy'=@('1.3.6.1.5.5.7.3.2')
      'pKIExpirationPeriod'=<clone from CN=User>; 'pKIOverlapPeriod'=<clone from CN=User>
    }
```

Because the CA already trusted the name (it was in its published list the
whole time), the new object is treated as enabled **immediately** — no
separate publish step, and critically, **no `ManageCa` right is needed at
all**, unlike the normal "define a template from scratch" ESC4 path, which
requires `ManageCa` to add a genuinely new name to the CA's published
list.

Two non-obvious pitfalls when building the object from scratch:
- Cloning `msPKI-Private-Key-Flag` verbatim from a stock `User`-class
  template (often `0x01010000`, including `CT_FLAG_HELLO_LOGON_KEY`)
  produces a generic `Denied by Policy Module` on request — zero it
  instead unless you specifically need that flag's semantics.
- Omitting `pKIExpirationPeriod`/`pKIOverlapPeriod` entirely (easy to miss
  since GUI-driven template creation sets them implicitly) produces
  `ERROR_INVALID_TIME` (Win32 1901) from the policy module — clone both
  byte-for-byte from an existing template.

Then enroll normally — `ENROLLEE_SUPPLIES_SUBJECT` plus an explicit
`-sid <target objectSid>` (mandatory on any DC enforcing KB5014754 strong
certificate mapping by default, which includes Server 2025) gets a
certificate for any target identity.

## Seen on

- [[DanglingTree#Root|DanglingTree]] — three custom templates
  (`RemoteAccessVPN`, `EmployeeAuthTemplate`, `VPNUserTemplate`) sat
  published-but-orphaned for the whole engagement; an earlier session
  wrongly closed the question as "ACL-protected" based purely on the
  identical CA-side rejection (see the box's own Rabbit Holes section),
  and it took a direct `noSuchObject` existence check with real
  credentials to find the true mechanism. `Template_Editors`' `CreateChild`
  right (independently discovered, no `ManageCa` anywhere in reach) was
  sufficient once the orphaned-name theory was confirmed.
