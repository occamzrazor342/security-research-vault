# ADCS ESC9/ESC10: Certificate-Mapping Downgrade (Domain-Level, Not Template-Level)

A distinct ADCS escalation class from the template misconfigurations
already covered in [[windows-active-directory-attack-surface-checklist]]
§6 (ESC1/ESC4/ESC8) — ESC9 and ESC10 exploit a *domain-level* Schannel/KDC
setting rather than a template ACL or EKU misconfiguration, so a
template-only ESC1/ESC4 sweep coming back clean does not rule these out.
Worth checking explicitly rather than assuming `certipy-ad find
-vulnerable`'s annotations alone will always surface it (they generally
do, but understanding the actual mechanism matters for judging whether
it's still exploitable on a given patch level — see below).

## The setting that governs both

Microsoft's **KB5014754** (Nov 2022) introduced a new certificate
extension, `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`),
which embeds the *requesting* user's SID into every certificate a CA
issues — a "strong" binding the KDC/Schannel can check against independent
of whatever Subject Alternative Name (SAN) the certificate carries. Two
registry values on the DC control how strictly that strong binding is
enforced:

- **`StrongCertificateBindingEnforcement`**
  (`HKLM\SYSTEM\CurrentControlSet\Services\Kdc`): `0` = disabled (no
  strong-mapping check at all), `1` = compatibility mode (prefers strong
  mapping, but falls back to weak/SAN-based mapping if the strong
  extension is absent or doesn't match) — this was the **default** in the
  post-patch compatibility window — `2` = full enforcement (weak mapping
  rejected outright).
- **`CertificateMappingMethods`** (Schannel): a bitmask; the `0x4` bit
  re-enables UPN/SAN-based weak mapping. Pre-patch default was `0x1F` (all
  methods including weak SAN mapping); post-patch default narrowed this,
  but many environments still have `0x4` set, deliberately or via legacy
  config drift.

## The two escalation paths

- **ESC9 — per-template.** A certificate template has the
  `CT_FLAG_NO_SECURITY_EXTENSION` flag set (i.e. the strong SID extension
  is deliberately suppressed for that template) while still allowing
  enrollee-supplied SAN. Request a cert under that template with an
  arbitrary admin SAN — no strong binding to contradict it, so weak
  SAN-based mapping (if enabled per above) authenticates as that SAN.
- **ESC10 — domain-wide, no vulnerable template needed at all.** Even if
  every template is otherwise hardened (correctly carries the strong
  extension), if the *domain's* Schannel/KDC settings above are in
  compatibility mode or disabled, weak mapping is still accepted
  domain-wide. This is the more dangerous variant precisely because
  fixing every template doesn't close it — the fix has to happen at the
  domain/registry level.

## Exploitation, once a vulnerable configuration is confirmed

1. Enroll for a certificate under a template that permits
   enrollee-supplied SAN (`certipy-ad req -ca <ca> -template <template>
   -upn administrator@<domain>` or equivalent), setting the target
   admin's UPN/SAN.
2. Authenticate (PKINIT for Kerberos, or Schannel/LDAPS directly) with the
   resulting certificate. If the DC is in compatibility mode (or
   disabled) and the weak-mapping bit is set, the DC maps the
   certificate to the SAN-named account rather than requiring the
   embedded SID extension to match — impersonating that admin without
   ever knowing their password.

## Why the patch timeline actually matters here (don't just cite the CVE class)

This is a genuinely time-sensitive vector, not a permanent misconfiguration
class like ESC1/ESC4: **compatibility mode was the *default* immediately
after KB5014754 shipped (Nov 2022) and was scheduled to sunset into full
enforcement on May 9, 2023.** A DC patched after that enforcement date,
with no explicit registry override rolling it back to compatibility mode,
is not exploitable via ESC9/ESC10 at all — so confirm the actual
`StrongCertificateBindingEnforcement`/`CertificateMappingMethods` values
on the target DC directly (`certipy-ad find` reports these, or a direct
registry read if already on-box) rather than assuming a modern patch
level rules this in or out either way. This vault's own patch-diff
discipline applies here as much as it does to a code-level CVE: the
"vulnerable" window is a specific configuration state, not just an OS
build number.

## Seen on

Not yet applied in this vault — recorded ahead of use. Run alongside the
existing ESC1/ESC4/ESC8 checks in
[[windows-active-directory-attack-surface-checklist]] §6, but check it
independently of template state given ESC10 needs no vulnerable template
at all.

## Source

[SpecterOps: "Certificates and Pwnage and Patches, Oh My!"](https://specterops.io/blog/2022/11/09/certificates-and-pwnage-and-patches-oh-my/)
