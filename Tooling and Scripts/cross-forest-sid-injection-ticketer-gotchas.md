# Cross-Forest Golden-Ticket SID Injection: the Right SID, and Two impacket Bugs That Block It Anyway

Forging a golden/inter-realm ticket to ride a cross-forest trust with an
injected extra-SID is a well-documented technique
([dirkjanm.io: "How does SID filtering work?"](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
and its follow-up,
["Trust transitivity and finding a trust bypass"](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)) —
but getting a real, accepted ticket out of `impacket-ticketer` +
`getST`-style tooling has two independent, non-obvious failure modes that
look like "the target is hardened" when they're actually tooling defaults/
bugs. Both have to be fixed before the SID-filtering question itself can
even be tested.

## 1. Picking the right SID at all

A forest trust with `TREAT_AS_EXTERNAL` set filters **domain-relative SIDs
with RID < 1000** and any non-domain-relative well-known/alias SID
(`S-1-5-32-*` BUILTIN aliases) — but **passes a domain-relative SID with
RID ≥ 1000 through regardless of which domain's ticket it's riding in**.
This is the actual mechanism behind the classic "inject a nested high-RID
group" cross-forest bypass. It is easy to test the *wrong* SID and
conclude the technique doesn't work here:

- A well-known/low-RID alias (`S-1-5-32-544` `BUILTIN\Administrators`,
  `S-1-5-32-551` `BUILTIN\Backup Operators`) is exactly the class the rule
  is designed to strip — testing it and getting denied proves nothing
  about the RID≥1000 rule.
- A genuinely domain-relative SID from the **target** domain, but with a
  RID under 1000 (e.g. `<target-domain-sid>-512` Domain Admins) is also
  filtered — same mistake, different flavor.
- The SID that actually survives filtering has to be **domain-relative to
  the target domain** (i.e. `<target-domain-sid>-<RID>`, not a well-known
  authority) **and** have **RID ≥ 1000**. Enumerate real candidates with
  `impacket-lookupsid` rather than guessing — a locally-privileged group
  (nested into `Backup Operators`, `DnsAdmins`, or similar) with a RID in
  that range is the actual target to inject.

## 2. `impacket-ticketer`'s `-user-id` default trips CVE-2021-42287 hardening

`ticketer.py` defaults `-user-id` to `500` and builds `PAC_REQUESTOR`'s
`UserSid` as `<domain-sid>-<user-id>`. If the ticket is forged for a
principal whose real RID *isn't* 500 (i.e. any non-Administrator account),
the ticket claims to be that principal but asserts a mismatched SID in
`PAC_REQUESTOR` — exactly the inconsistency the `KB5008380`/
`PACRequestorEnforcement` hardening (from CVE-2021-42287) is designed to
catch, and it will reject the ticket with `KDC_ERR_TGT_REVOKED` on any
modern-patched KDC, with an error that gives no hint the actual cause is a
CLI default rather than a cryptographic problem. **Always pass
`-user-id <the real RID of the principal being forged>`** — a plain LDAP
lookup or an existing DCSync dump has this value.

## 3. impacket's `getKerberosTGS` reuses the wrong KDC on a cross-realm referral

`getKerberosTGS()` (`impacket/krb5/kerberosv5.py`) correctly detects a
cross-realm referral (comparing the returned ticket's service name against
what was requested) and correctly recurses to request the final service
ticket — but the recursive call passes along the **same** `kdcHost`
parameter instead of resolving the referred realm's own KDC:

```python
else:
    domain = spn.components[1]
    return getKerberosTGS(serverName, domain, kdcHost, r, cipher, newSessionKey)
```

So a referral ticket for the trusted realm gets resent to the *home*
realm's own KDC, which correctly rejects it (`KDC_ERR_WRONG_REALM`), or —
depending on invocation — the target KDC rejects an SPN it's never heard
of (`KDC_ERR_S_PRINCIPAL_UNKNOWN`). Either failure looks like a
target-side rejection of the cross-realm chain itself. The fix is to do
the two hops manually: request the referral ticket against the **home**
realm's KDC, then request the final service ticket against the
**target** realm's own KDC, explicitly — don't rely on the library's
built-in referral-chasing for this specific two-hop case.

## Net effect

All three fixes are independent and all three are required simultaneously
before a cross-forest SID-injection ticket will actually reach the point
of being tested for real — get any one wrong and the failure mode (bad
integrity, revoked TGT, wrong realm, principal unknown) looks exactly like
a hardened, closed target rather than a tooling default/bug, which is
exactly what caused this technique to be re-tested and "conclusively"
closed multiple times against the wrong combination before all three were
fixed together.

## 4. Default forest trusts (no `TREAT_AS_EXTERNAL`) still apply mandatory, unconditional SID filtering

Everything above describes SID filtering's RID-based nuance on a trust that
has `TREAT_AS_EXTERNAL` set (or an actual external, non-forest trust) — a
selective filter that a RID≥1000 domain-relative SID survives. A **plain
forest trust with only `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` set** (no
`TREAT_AS_EXTERNAL`, no `QUARANTINED_DOMAIN`) — Microsoft's out-of-the-box
default when two separate forests are joined — is a structurally different
case: SID filtering across a genuine forest boundary is mandatory and
forest-wide by default, not RID-gated the same way. Don't assume the
RID≥1000-survives rule from section 1 transfers to this trust type without
testing it directly — confirm which regime you're actually facing
(`trustAttributes` on the `trustedDomain` object: bit `0x8` alone is plain
forest-transitive, `0x40` is the `TREAT_AS_EXTERNAL` case section 1
describes) before predicting which injected SIDs, if any, would survive.

The strongest possible evidence for whether filtering fired is a direct
decode of the DC's own `tokenGroups` computation for the ticket-derived
identity (an authenticated LDAP `-s base "(objectClass=*)" tokenGroups`
against the target realm's own root DSE or the identity's own object),
not just an outcome-based "did I get elevated access" inference — the
latter can have other explanations (a real ACL gap unrelated to SID
filtering, wrong target object, etc.) that a direct PAC/tokenGroups read
rules out categorically.

## Seen on

- [[DarkZeroReturns#Root|DarkZeroReturns]] — repeated passes injected
  `S-1-5-32-544`, `S-1-5-32-551`, and `<target-domain-sid>-512` (all
  filtered, correctly) using `impacket-ticketer`'s default `-user-id 500`
  (tripping `KDC_ERR_TGT_REVOKED` independently of SID choice) against
  `getst_crossrealm.py`'s single-hop referral logic (hitting the
  `getKerberosTGS` same-KDC bug independently of both of the above). The
  working combination: `-user-id` set to the real forged principal's RID,
  `-extra-sid` set to two real, domain-relative, RID≥1000 SIDs native to
  the target forest (`DnsAdmins` RID 1101, and `InfrastructureAdministrators`
  RID 1603 — itself nested inside `Backup Operators`), and a hand-written
  two-hop referral script instead of relying on `getKerberosTGS`'s
  recursion. See also [[gitea-actions-fork-pr-approval-bypass-notifier-gap]]
  and [[ksu-default-aname-lname-fallback]] for the other two reusable
  techniques from the same engagement.
- [[PingPong#Rabbit Holes|PingPong]] — a plain, unmodified forest trust
  (`trustAttributes: 8`, `FOREST_TRANSITIVE` only) between ping.htb and
  pong.htb. Forged an inter-realm TGT for a real pong.htb account with
  `-extra-sid` set to the **target** domain's own `Domain Admins`/
  `Enterprise Admins` SIDs (RID 512/519 — both under 1000, so this doesn't
  even test the RID≥1000 question from section 1 above, a distinct point
  worth flagging for anyone reusing this as a template). The KDC accepted
  the forged ticket and issued a real service ticket (proving the trust key
  itself was correct — extracted fresh via `mimikatz lsadump::trust
  /patch`), but a direct `tokenGroups` decode of the resulting identity on
  the target DC showed **every** injected SID had been stripped —
  confirmed via the strongest evidence standard described in section 4, not
  merely an outcome-based "no elevated access" inference. A genuine,
  cleanly-closed dead end distinct from DarkZeroReturns' case above:
  correctly-executed section-1-style RID≥1000 injection was never actually
  what was being tested here.
