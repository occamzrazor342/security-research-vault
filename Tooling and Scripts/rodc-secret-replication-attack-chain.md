# RODC Password Replication Policy Abuse and the Key-List Attack

Reusable mechanism notes for any Read-Only Domain Controller (RODC) target,
distilled from [[garfield#Root|Garfield]] — that box needed nearly the whole
chain below, plus two real impacket bugs, before a genuinely misconfigured
PRP actually produced a usable secret.

## The three attributes that matter, and how they interact

Every RODC computer object carries:

- **`msDS-RevealOnDemandGroup`** — the allow list. Members (directly or
  transitively) may have their secrets cached on this RODC.
- **`msDS-NeverRevealGroup`** — the deny list. Takes precedence over the
  allow list.
- **`msDS-RevealedUsers`** — history/authorization record: every principal
  that has *ever* had its secret replicated to this RODC. This is what most
  writeups (including early passes on Garfield) check to conclude "this
  account is revealed" — but it records *authorization*, not current
  *presence*. A principal can legitimately appear here while the actual
  secret bytes are absent from this specific RODC instance (e.g. after a
  fresh provisioning/replication cycle hasn't caught up yet).

**The deny-list check is transitive group membership, not a literal-DN
match.** Don't just check whether a target account's own DN appears in
`msDS-NeverRevealGroup` — resolve full nested membership on both sides.
Built-in defaults are a common trap: `Denied RODC Password Replication
Group` nests `Domain Admins`/`Enterprise Admins`/`Schema Admins`/`krbtgt`,
and `Administrators` (builtin) is usually listed directly too — so the real
`Administrator` account is almost always doubly, transitively blocked by
default even though its own DN never appears anywhere in the deny list. On
Garfield, four separate sessions concluded "not denied" from a literal-DN
check before this was caught.

## Getting write access to `msDS-NeverRevealGroup`/`msDS-RevealOnDemandGroup`

These attributes belong to the `Account-Restrictions` property set on the
RODC computer object — the same property set that guards
`msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD). If you already have
`WriteProperty` on that property set for RBCD purposes, you already have
write access to the PRP config too.

## RODC-delegated-admin rights: a real primitive, but not a full solve

An RODC computer object can be delegated to a non-Tier-0 admin via the
`managedBy` attribute (ADUC's "Managed By" tab). Whoever it's set to gets a
real, broad `WriteProperty`/`ReadProperty` grant on the RODC object and its
sub-objects across several property-set GUIDs. On Garfield, a custom `Tier 1`
group held a `DS_SELF` ("Self-Membership") ACE on a `RODC Administrators`
group with zero current members — self-adding to it, then setting the target
RODC's `managedBy` to yourself, is a legitimate, fully AD-native way to
become that RODC's delegated admin without ever touching a DACL directly.

**This does not itself grant `Secret Synchronization`.** `repadmin
/rodcpwdrepl` (the dedicated on-demand secret pre-population command) still
requires that specific extended control-access right, which stays
Domain-Admin-only regardless of `managedBy`/`RODC Administrators`
membership. Don't expect this delegation path to unlock `/rodcpwdrepl` —
its real value is unlocking write access to the PRP attributes themselves
(see above), not a replication-trigger shortcut.

## The Key-List (`KERB-KEY-LIST-REQ`) attack — the actual bypass mechanism

Once PRP genuinely allows a target user, the mechanism that respects/exploits
that config (distinct from DRSUAPI or `/rodcpwdrepl`) is a legitimate,
documented Kerberos protocol feature (MS-KILE): an RODC forges a **partial
TGT** for the target user, encrypted with its own `krbtgt_<N>` key, and
presents it as a TGS-REQ to the *writable* DC's KDC with `KERB-KEY-LIST-REQ`
padata (type 161). If the writable DC's own PRP evaluation for that RODC
allows the user, the TGS-REP returns the user's real long-term keys directly.
This exists so a freshly-revealed user's tickets can actually be decrypted by
the RODC — it is the intended abuse surface for a misconfigured PRP, not a
vulnerability in Kerberos itself.

`impacket-keylistattack` implements this. Two gotchas:

- `-rodcNo` must be the RODC krbtgt account's **`msDS-SecondaryKrbTgtNumber`**
  (e.g. `8245`), not its RID.
- The RODC krbtgt's **AES key** is needed (not just its NTLM hash) —
  `mimikatz lsadump::lsa /inject /name:krbtgt_<N>`, run as SYSTEM on the
  RODC, gets it.

## Two real impacket bugs to know about before assuming a PRP config is wrong

### Bug 1 — `secretsdump.py -use-vss`/WMINTDS silently drops every RODC domain account

`NTDSHashes.__getPek()`/`dump()` filter every parsed ESE row with
`instanceType & 4` ("object is writable on this directory") in addition to
the account-type check. True for every row on a writable DC (no-op there);
**false for every row in the domain naming context on an RODC**, since that
NC is entirely read-only there — so every account, including genuinely
revealed ones, gets dropped before `__decryptHash` runs, with zero error.
Confirmed via [[garfield#Root|Garfield]]'s writeup, patch reproduced there —
drop the `instanceType & 4` clause, keep only the account-type check; safe on
a writable DC too since every row there already satisfies it.

Distinct from (though related in spirit to) `fortra/impacket#1552`/`#1668`,
which describe DRSUAPI's remote `GetNCChangesGuid` failing against an RODC
with `Unknown DCE RPC fault status code: 00000057` — a genuine,
transport-independent protocol rejection, not fixed by adding network
reachability, and not fixed by the `instanceType` patch either (they're
separate codepaths: DRSUAPI-remote vs. local-`ntds.dit`-parse).

### Bug 2 — `keylistattack.py`'s forged partial TGT has no PAC, and any DC patched for CVE-2021-42287 rejects it

Stock `KeyListSecrets.createPartialTGT()` builds the forged ticket with
`encTicketPart['authorization-data'] = noValue` — no PAC at all. Since
Microsoft's November 2021 PAC-signature-enforcement patches
(CVE-2021-42287/CVE-2021-42278, "noPac"), a patched writable DC rejects a
PAC-less RODC-issued ticket during the KERB-KEY-LIST exchange with
`KDC_ERR_TGT_REVOKED` (error code 20) — surfaced by impacket's own wrapper as
the misleading, PRP-flavored message `"User <x> is not allowed to have
passwords replicated in RODCs"`. **This makes a broken tool look
indistinguishable from a correctly-denying PRP config** — the only way to
tell them apart is reproducing the raw Kerberos exchange to get the real
KRB-ERROR code, or (more directly) testing against a fully-permissive PRP
control case and seeing the identical failure.

Fixed in `fortra/impacket` PR #2233 (in review as of this writing): embeds a
full, RODC-krbtgt-signed PAC (`PAC_LOGON_INFO`, `PAC_CLIENT_INFO`, and
critically `PAC_ATTRIBUTES_INFO`+`PAC_REQUESTOR`, the pair CVE-2021-42287's
patch actually validates — it checks the requestor's claimed SID against the
ticket's client principal) into the forged ticket's `authorization-data`. If
your installed impacket predates this fix, patch a local copy (loaded via
`PYTHONPATH` precedence if you don't have root to touch the system install)
rather than concluding the target's PRP is misconfigured — check the raw
KRB-ERROR code first.

## Seen on

- [[garfield#Root|Garfield]] — the full chain: transitive-deny-group
  discovery, `RODC Administrators` self-membership + `managedBy` delegation,
  both impacket bugs found, patch-diffed, and fixed locally, ending in
  `Administrator`'s real NTLM hash via the Key-List attack.
