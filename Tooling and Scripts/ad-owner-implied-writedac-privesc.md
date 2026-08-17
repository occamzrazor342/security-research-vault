# AD Owner-Implied WriteDac: the ACL Sweep Blind Spot Every Hand-Rolled DACL Decoder Has

Every Windows security descriptor has two independent access-control facts: the
**DACL** (the explicit list of ACEs granting/denying rights to specific
principals) and the **Owner** field. Most AD ACL-abuse tooling — and every
hand-rolled ACL-sweep script that just walks `nTSecurityDescriptor`'s ACE list
— only ever inspects the DACL. That misses a real, standard Windows access-check
rule: **the owner of an object is implicitly granted `READ_CONTROL` and
`WRITE_DAC` on it, independent of whatever the DACL's own ACEs say** — and
critically, this evaluates by *group membership*, not just an exact principal
match, when the Owner field itself holds a group SID rather than a user SID.
([MS-ADTS: Blocking Implicit Owner Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c),
[Reading an Object's Security Descriptor (Win32)](https://learn.microsoft.com/en-us/windows/win32/ad/reading-an-objectampaposs-security-descriptor))

## Why this is easy to miss

A group can be set as an AD object's Owner (e.g. by whoever created the object,
or by an earlier `WriteOwner`/`takeownership`-equivalent action) with **zero**
corresponding ACE for that group anywhere in the DACL. A DACL-only decode —
which is what most people write first, since it's the obvious/visible part of
the security descriptor — will report the object as having no interesting
rights for that group at all. The Owner field is a completely separate query
(`OwnerSid` on the same `SR_SECURITY_DESCRIPTOR` structure `impacket.ldap.ldaptypes`
already decodes) that's trivial to add but easy to never think to check, because
nothing about a routine DACL walk surfaces its absence.

`bloodyAD`'s `get writable` command implements the *full* Windows access-check
semantics (DACL **and** owner-implied rights), which is why it catches this and
a DACL-only sweep never will — if you're hand-rolling ACL enumeration instead
of using a validated tool, add an explicit Owner-SID check against your list of
controlled principals, not just a DACL walk.

## Weaponizing it once found

Owner-implied `WRITE_DAC` lets you rewrite the object's DACL arbitrarily (e.g.
grant yourself `GenericAll`), which then lets you do anything else the object
supports — including, if the object is a **group**, adding a member. Two
additional AD group-scope rules commonly block that follow-on member-add and
both have a legal, mechanical fix:

1. **`ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER`** — a **Global** group can
   only hold same-domain members. If the identity you're adding is from a
   different domain/forest, convert the group's `groupType` to **Universal**
   first (a plain LDAP attribute write, no special tooling needed once you
   hold `GenericAll`/`WRITE_DAC`).
2. **`ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS`** — a **Universal** group accepts
   members from anywhere in the *same forest*, but still rejects a **Foreign
   Security Principal** (an account from a different, trust-joined forest).
   Convert `groupType` a second time, from Universal to **Domain Local** —
   Domain Local groups are the one scope that accepts FSPs directly, which is
   the standard, legitimate mechanism for "add a trusted-domain user to a
   local group" in the first place.

Both conversions are legal, single-attribute AD writes (`groupType`:
`-2147483646` Global → `-2147483640` Universal → `-2147483644` Domain Local),
not a workaround or a bug — just the normal group-scope transition chain,
applied here as a weaponization step rather than an admin convenience.

## When the right exists but the standard client tool can't exercise it

Owner-implied `WRITE_DAC` being real doesn't guarantee every client tool can
actually use it. `[ADSI]`'s `ActiveDirectorySecurity.AddAccessRule()` +
`CommitChanges()` and the external `dsacls.exe` tool can both still return
`Access is denied` against an object you genuinely own, for reasons that
don't trace back to the AD-side right itself (a client-side elevation
check, a stale cached token, an RPC-transport quirk) — don't take that
denial as proof the owner-implied right doesn't apply here. Try an
LDAP-native tool that implements the write differently before concluding
the right is unusable: `bloodyAD add genericAll <DN> <principal>` uses the
raw `LDAP_SERVER_SD_FLAGS` control directly over LDAP, a structurally
different code path from either ADSI or `dsacls.exe`, and can succeed
immediately where both of those fail identically.

## Seen on

- [[PingPong#Privesc|PingPong]] — session 12's breakthrough after 10 sessions
  of DACL-only sweeps found nothing: `bloodyAD get writable --transitive`
  (crossing a forest trust) flagged `pong.htb\gMSA Managers` as writable for
  `c.roberts`, a fact that traced back to `PING\IT` (a real, non-PAC-injected
  group `c.roberts` belonged to) sitting in that group's **Owner** field —
  something two independent hand-rolled DACL sweeps (sessions 2 and 6) had
  each already run against that exact object and missed, since neither ever
  queried `OwnerSid`. Weaponized through both group-scope conversions above
  (Global → Universal blocked by the cross-domain-member rule, Universal →
  Domain Local blocked by the FSP rule, each diagnosed and fixed in turn) to
  add `c.roberts` as a real member, which then unlocked `msDS-ManagedPassword`
  read on two gMSAs and, eventually, resolved a JEA-endpoint mystery six prior
  sessions couldn't explain. A follow-up session (13) confirmed the technique
  doesn't generalize past this one edge in either trust direction for either
  identity held on the box, and a dedicated side investigation (owner-field
  sweep for a third identity, `R.Martinelli`, across all 10 LDAP naming
  contexts in both domains) validated the sweep methodology against this exact
  known-true positive before trusting a clean negative elsewhere — worth
  doing on any box before relying on a from-scratch Owner-field sweep tool.
- [[DanglingTree#Root|DanglingTree]] — a freshly-created certificate template
  object's own owner (`jake.h`, right after `New-ADObject`) still got
  `Access is denied` from both `[ADSI]`'s `CommitChanges()` and
  `dsacls.exe` when trying to grant himself full control — `bloodyAD add
  genericAll` succeeded on the first attempt against the identical object,
  identical principal, no other change made.
