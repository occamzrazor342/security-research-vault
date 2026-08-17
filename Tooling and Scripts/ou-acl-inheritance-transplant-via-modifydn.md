# OU-ACL Inheritance Transplant via ModifyDN (Object Move)

A way to make an *inherited* AD ACL edge apply to an account it doesn't
currently apply to, by moving the account into a different OU — without
touching the account's own group memberships at all, and without needing any
direct ACE on the account itself.

## The underlying fact

Two categories of AD access travel differently when an object moves between
OUs:

- **Group membership** (`member`/`memberOf`) is stored on the group and the
  member object directly — it is completely independent of where the object
  sits in the directory tree. Moving an account to a new OU does not add or
  remove any group membership.
- **Inherited ACL edges** (an ACE placed on a parent OU with a
  container-inherit flag, e.g. `GenericWrite`/`GenericAll` granted to some
  principal "on this OU and everything under it") apply based on the
  object's *current* location in the tree. Move the object, and the
  inherited edge from its old parent stops applying while the inherited
  edge from its new parent starts applying — immediately, no re-collection
  or replication delay needed beyond normal LDAP consistency.

If principal A holds `GenericWrite` (or any other useful inherited edge)
over every object under OU X, and some specific low-value account currently
sits in OU Y (where A has nothing), moving that account from Y into X
transplants A's edge onto it — turning a previously useless account into
a fresh, exploitable target for whatever the edge grants (Shadow
Credentials, a targeted SPN for Kerberoasting, a password reset, etc.).

## Preconditions for the move itself

An LDAP `ModifyDN` (the AD "move" operation) needs two separate rights, both
of which must be held by the identity performing the move:

1. **`CREATE_CHILD` for the object's class** on the *destination* OU (the
   object is effectively being re-parented under it).
2. **`WRITE` on `name`/`cn`** (or equivalent rename rights) on the *object
   itself* — AD requires you be able to rename the object as part of a
   cross-OU move, even if the RDN string doesn't actually change.

Both of these can be genuinely held even when the identity has **no**
`WriteDacl`/`WriteOwner`/`GenericAll` anywhere — they're much narrower,
easy-to-overlook rights, and BloodHound-legacy's collector can miss the
`CREATE_CHILD` right specifically (see caveat below).

## Executing the move

`bloodyAD`'s `set object <target> distinguishedName -v <new_dn>` internally
detects a DN change and performs a real `ModifyDN` (with `newSuperior` when
the OU component changes) — read the tool's own source
(`network/ldap.py`, `bloodymodify()`) to confirm this before trusting it, since
the CLI help text doesn't document a dedicated "move" subcommand:

```bash
bloodyAD --host <dc> -d <domain> -k set object <target-sam> distinguishedName \
    -v "CN=<Same CN>,OU=<Destination OU>,OU=...,DC=...,DC=..."
```

**Verify the move actually landed with a fresh, independent re-query** —
don't trust the tool's own success message alone:

```bash
bloodyAD --host <dc> -d <domain> -k get object <target-sam> --attr distinguishedName
```

Then confirm the transplanted edge actually applies from the controlling
principal's own vantage point — comparing the moved object's full
`get writable --detail` output line-for-line against a known-good baseline
(another account already confirmed to sit under the edge's real OU) is a
stronger check than inferring it from the ACL structure alone.

## A caveat on why the underlying `CREATE_CHILD` right can be invisible

BloodHound-legacy's collector resolves extended/`CreateChild`-class rights
via schema GUIDs, and has a known gap where it simply doesn't surface these
on OU objects at all — a live `bloodyAD get writable --detail` query (a real
LDAP ACL read, not a cached graph) is the tool that actually finds this
class of right. Don't conclude "no useful OU-level right exists" purely from
a BloodHound sweep coming back empty; cross-check with a live tool.

## Seen on

- [[hercules#Privesc|Hercules]] — `bob.w` had `CREATE_CHILD`
  (user/computer/group) on `OU=Web Department`/`OU=Security Department`/
  `OU=Engineering Department` plus `name`/`cn: WRITE` on every existing
  `Security Department` member, a right BloodHound-legacy's own collector
  showed nothing for. Moving `stephen.m` (a `Security Helpdesk` member,
  otherwise unreachable) from `Security Department` into `Web Department`
  transplanted `Web Support`'s already-weaponized `GenericWrite` edge onto
  him, unlocking a Shadow-Credentials attack against an account that had
  previously been out of reach, which in turn led to a `ForceChangePassword`
  against `auditor` (a `Remote Management Users` member) and the
  engagement's first native WinRM code execution.
