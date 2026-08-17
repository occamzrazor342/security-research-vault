# Unmasking an AD Container Hidden Behind a Deny ACE via Side Channels

A container-level deny ACE (most often placed on the default `CN=Users`
container, or occasionally a whole OU) blocks LDAP search and SAMR
enumeration cleanly — `ldapsearch`/`bloodhound-python`/`GetADUsers.py`
return `numEntries: 0`, not a bind error, which is AD's deliberate
anti-enumeration behavior (masking a real access-denied as "nothing here"
rather than confirming the container's existence to an unauthorized
principal). BloodHound's own collector output is the tell: a **missing**
default container (`CN=Users` absent from the container list entirely,
rather than present-but-empty) is a much stronger signal than any single
empty-search result, since every domain has that container by default.

The deny ACE, though, is scoped to LDAP directory reads specifically — it
has no reason to also block several structurally different, genuinely
independent access-check subsystems that happen to reveal the same
underlying facts.

## Side channels that survive the deny ACE

1. **Kerberos AS-REQ pre-auth validation.** A username-enumeration probe
   (`kerbrute userenum`, or `impacket-GetNPUsers -no-pass`) against a
   candidate list reveals "principal exists / doesn't exist" by checking
   the KDC's own principal database — not a directory read at all. If the
   domain has an established naming convention (`firstname.lastinitial`,
   a company/theme-specific pattern already confirmed for one known
   account), build a wordlist off that convention rather than a generic
   breach-corpus list.

2. **LSA SID→name resolution** (`rpcclient lookupsids <SID>`) and **SAMR
   local BUILTIN-alias membership** (`rpcclient queryaliasmem builtin
   <RID>`, e.g. Administrators, Remote Desktop Users, Remote Management
   Users) are separate access-check code paths from an LDAP object read.
   Resolving an already-known SID string back to a name, or listing a
   local group's member SIDs, doesn't require reading the AD object those
   SIDs point at — so a hidden account can still be named and its local
   Windows rights enumerated this way, entirely independent of whether its
   own LDAP object is readable.

3. **SYSVOL GPO security settings (`GptTmpl.inf`)** are readable by any
   authenticated (sometimes even null-session) user regardless of the
   deny ACE — and its `[Privilege Rights]` section lists **raw,
   unresolved SIDs** for local rights like `SeInteractiveLogonRight`/
   `SeRemoteInteractiveLogonRight`. A hand-edited GPO (check the file's own
   modification timestamp against the domain's build-date cluster) with
   SIDs that don't resolve via normal enumeration is a strong, concrete
   starting point for step 2 above — mine every domain-relative RID out of
   it and resolve each one.

4. **A different account's own logon token.** If a deny ACE turns out to
   be scoped to a specific OU (rather than `Domain Users` broadly — worth
   checking any account's real DN, findable via a direct SID-rooted-DN
   bind: `ldapsearch -b "<SID=S-1-5-...>" -s base`), any account outside
   that OU was never denied in the first place. Once any credential for an
   out-of-OU account is obtained, its own `ActiveDirectory`
   PowerShell-module/LDAP access can read the hidden container directly —
   the fastest and most complete of all four channels, but it requires a
   credential first, so it's usually the *last* of these four to become
   available, not the first.

## Practical workflow

1. Note any default container BloodHound's collection is missing entirely.
2. Pull every GPO's `GptTmpl.inf` from SYSVOL, diff modification dates
   against the domain's build-date cluster, mine every raw SID out of
   `[Privilege Rights]`.
3. Resolve each SID via `rpcclient lookupsids`; walk every non-default
   BUILTIN alias via `queryaliasmem` for group membership these accounts
   might hold.
4. Build a naming-convention-targeted Kerberos userenum wordlist off any
   already-known account's naming pattern to catch accounts not referenced
   in the GPO at all.
5. Once any credential lands (any account, any privilege level), check
   whether its own DN sits outside whatever OU the original low-priv
   account was scoped to — if so, re-run the full AD enumeration as that
   identity before assuming the deny ACE still applies.

## Seen on

- [[DanglingTree#Recon|DanglingTree]] — this exact sequence found four
  hidden accounts (`jake.h`, `noah.b`, `svc_mail`, `alex.o`) and three
  hidden groups (`Helpdesk_Cert_Support`, `DevOps_PKI`, `support-it`) none
  of which BloodHound/LDAP/SAMR enumeration as the starting account
  (`anderson.w`) could see directly. `svc_mail`, reached later via a
  SmarterMail RCE chain, turned out to live outside the deny-ACE-scoped OU
  entirely, unblocking full LDAP visibility into the hidden container for
  the rest of the engagement.
