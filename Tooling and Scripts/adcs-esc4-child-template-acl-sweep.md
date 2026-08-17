# ESC4: Sweep Every Individual Certificate Template's Own ACL, Not Just the Container

ESC4 is a dangerous-permissions condition on a certificate template object
itself: if a principal holds `WriteOwner`/`WriteDacl`/`GenericWrite`-class
rights on a template, they can reconfigure that template's settings (most
usefully, flip `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` on) to make it vulnerable
to ESC1, then enroll for a certificate carrying an arbitrary UPN/SID — a
straight line to impersonating any account, including Domain Admin, via
PKINIT. ([ADCSESC4 — SpecterOps](https://bloodhound.specterops.io/resources/edges/adcs-esc4),
[Certipy Wiki: Privilege Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation))

## The sweep gap this catches

`certipy-ad find -vulnerable` catches this automatically when run against an
identity that already has the write rights — but a **manual LDAP ACL sweep**
of an AD CS setup, if scoped only to `CN=Certificate Templates,CN=Public Key
Services,...` (the *container*) rather than each individual template object
underneath it, will miss a template-specific ACE entirely. A container-level
ACL sweep answers "who can create/delete templates here," which is a
different, usually much more restricted, question than "who has rights on
*this specific, already-existing* template object." The two need to be swept
independently — a clean container ACL says nothing about any one child
template's own DACL.

This is the same class of gap as the container-vs-child distinction for
regular OU/group sweeps, but it's easy to miss specifically in AD CS
enumeration because the interesting templates (the ones that matter for
ESC1/ESC13/etc.) are usually already being inspected individually for their
own *enrollment*/EKU/issuance-policy settings — it's easy to check a
template's enrollment rights and issuance policy carefully while never
separately pulling its full DACL for a *different* principal than the one
already flagged as interesting.

## Weaponization once found

1. Confirm the write access is real by using it (grant yourself/your identity
   `GenericAll` on the template), not just by decoding the ACE — a
   demonstrated write is stronger evidence than a theoretical one and catches
   any tooling/decode error before it's relied on.
2. Flip `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (bit `0x1`) on
   `msPKI-Certificate-Name-Flag` — this is the actual ESC4→ESC1 conversion.
   If the template already has a Client Authentication EKU, no further change
   is needed.
3. Request a certificate with an arbitrary target UPN. On a DC hardened per
   [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
   (strong certificate mapping enforced), a UPN-only request will fail PKINIT
   with `KDC_ERR_CERTIFICATE_MISMATCH`/"Object SID mismatch" — pass the
   target account's real objectSid explicitly (`certipy-ad req ... -sid
   <target-SID>`) so the certificate carries the `szOID_NTDS_CA_SECURITY_EXT`
   SID extension the strong-mapping check requires.

## Seen on

- [[PingPong#Root|PingPong]] — three separate sessions (4, 6, 16) swept
  `ping.htb\CA Managers`' rights and correctly found **zero** ACEs at the
  `Certificate Templates` container level, the CA's own registry-based
  security descriptor, and every other AD-CS-related container — a real,
  thorough, correctly-executed closure of that specific question. What none
  of those sweeps ever did was individually query
  `CN=SmartcardAuthentication,CN=Certificate Templates,...` — a *sibling*
  template to the one already known to matter (`TemporaryWinRM`, the ESC13
  foothold vector) — by name. Session 18 (again reached via a single,
  narrowly-scoped, user-authorized walkthrough consult pointing at this one
  specific gap) pulled that template's raw `nTSecurityDescriptor` directly
  and found `CA Managers` held a standalone ACE there
  (`WriteOwner`+`WriteDacl`+most of `GenericWrite`) that no container-level
  sweep had ever surfaced, since it lived on the child object, not the
  container. Weaponized end-to-end (`GenericAll` grant → flip
  `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` → `certipy-ad req -sid
  <Administrator's real SID>` to satisfy KB5014754 strong mapping →
  `certipy-ad auth` PKINIT) to obtain full `ping.htb\Administrator` and
  capture root.txt, closing an 18-session engagement.
