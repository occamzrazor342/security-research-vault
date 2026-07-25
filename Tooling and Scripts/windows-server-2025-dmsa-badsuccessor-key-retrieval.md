
# Windows Server 2025 dMSA / CVE-2025-53779 (BadSuccessor) — Correct Key-Retrieval Mechanism

Generalized from [[checkpoint#Privesc|Checkpoint]] — most of this engagement's
time on this technique was spent chasing a wrong theory (dMSA password
"still materializing") before finding the actual, by-design mechanism, and
even after finding it, an earlier pass mistook a partial negative result for
a conclusive one. This note exists so a future box doesn't repeat either
detour.

## The trap: `msDS-ManagedPassword` looking empty on a dMSA is not a timing issue

A gMSA's `msDS-ManagedPassword` is a constructed LDAP attribute — read it,
the DC computes and hands back the password blob, done. A **dMSA**
(`msDS-DelegatedManagedServiceAccount`, the Windows Server 2025 class this
CVE targets) looks superficially identical but **permanently and
unconditionally refuses to serve this attribute over LDAP, regardless of
ACL or wait time** — Microsoft's own docs confirm it's "denied by default in
the `defaultSecurityDescriptor`, and there is an additional DC-side
validation that blocks LDAP reads regardless of ACL... intentionally
different from gMSA" ([Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview),
[FAQ](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-faq)).

**Do not chase this as a KDS-root-key-effective-time / materialization-delay
problem.** Isolate it in one cheap test instead: create a plain gMSA and a
plain (unlinked) dMSA side by side, wait 5-10 seconds, read both. The gMSA
will have a real password; the dMSA will still be empty — and will *stay*
empty no matter how long you wait, because it's blocked by design, not by
timing. If your own investigation is heading toward "let's wait N more
hours," stop and re-derive from this note instead.

## The real, correct retrieval mechanism: Kerberos S4U2Self + `KERB_DMSA_KEY_PACKAGE`

A dMSA's key material is retrieved via a Kerberos `S4U2Self` exchange
requesting a ticket *as* the dMSA (from an account listed in its
`msDS-GroupMSAMembership`/`PrincipalsAllowedToRetrieveManagedPassword`).
The KDC returns the key material as supplemental `encrypted_pa_data` —
`KERB_DMSA_KEY_PACKAGE`, PA-DATA type 171 — inside the TGS-REP. This is not
optional/alternate; it's the only working path for a dMSA.

**The key package has (at least) two fields, and they mean different
things — read both, not just the obvious one:**

- **`current-keys`** — the dMSA's own key material. A TGT obtained with
  these keys authenticates *as the dMSA itself*. Whether that ticket also
  carries the impersonated (`msDS-ManagedAccountPrecededByLink`) target's
  group privileges in its PAC is exactly the question the August 2025 CU's
  mutual-link enforcement gates — and on a patched DC, it does not, even
  with a fully correct, bidirectional BadSuccessor/BetterSuccessor link in
  place (verified via a direct, repeatable practical test — see below).
- **`previous-keys`** — key material for "preceding managed accounts,"
  i.e. whatever `msDS-ManagedAccountPrecededByLink` points at. Per
  Microsoft's dMSA design, this field exists so a dMSA can decrypt tickets/
  service state issued under a real predecessor account during a genuine
  migration — it is populated directly from the linked account's own keys,
  **and the mutual-link check the August 2025 patch added does not gate
  this field at all** (it only gates PAC/privilege merging into the dMSA's
  own ticket via `current-keys`). If the `msDS-ManagedAccountPrecededByLink`
  attacker-set is on your dMSA and points at a target you want, this field
  hands you that target's real, static key material directly — an
  RC4-HMAC key here is byte-identical to the target account's NT hash,
  directly usable for pass-the-hash, no ticket/PAC games required at all.

**This means a patched, fully up-to-date DC can still be fully compromised
via BadSuccessor/BetterSuccessor — just via credential disclosure
(`previous-keys`) rather than the original privilege-merge mechanism
(`current-keys`) the patch was built to stop.** Test both fields before
concluding the technique is closed on any given box; a clean negative
result on `current-keys` alone is not evidence the whole primitive is dead.

**Working, verified toolchain** (two independent implementations,
cross-validated to produce byte-identical `current-keys` material against
the same target; `previous-keys` independently re-confirmed byte-identical
across two entirely separate box resets, weeks apart):

1. **Creation** — `bloodyAD add badSuccessor <name> -t <target_dn> --ou <ou_dn>`
   handles the dMSA-class-vs-gMSA-default pitfall and the dMSA class's
   tighter default security descriptor correctly out of the box. Without
   `--prepatch` it also writes the target's reciprocal
   `msDS-Superseded*` attributes automatically — but only if the calling
   account has write access to the target; if not, run with `--prepatch`
   and complete the reciprocal write separately (whichever account
   actually holds `GenericWrite` on the target does
   `Set-ADObject -Replace @{'msDS-SupersededManagedAccountLink'=<dmsa_dn>}`
   and `... @{'msDS-SupersededServiceAccountState'=1}`).

   **Known, root-caused bug**: `bloodyAD`'s own `add badSuccessor`
   (in `bloodyAD/cli_modules/add.py`) crashes with a `TypeError` on its
   final URL-rebuild step, on *every* invocation, not just an edge-case
   fallback branch:
   ```diff
   - url = parse.urlunparse(parsed._replace(netloc=new_netloc, query=query_params))
   + url = parse.urlunparse(parsed._replace(netloc=new_netloc, query=parse.urlencode(query_params, doseq=True)))
   ```
   `parse_qs` returns a `dict`, and `urlunparse` requires every tuple
   component to be a `str` — handing it the raw, un-re-encoded dict raises
   `TypeError: Cannot mix str and non-str arguments`. This happens *after*
   the actual AD writes complete, so it's cosmetic for object creation
   (verify state directly via LDAP rather than trusting the crash to mean
   the write failed) — but it's fatal for `bloodyAD`'s own built-in
   key-retrieval follow-on step, which never runs. Even with this patched,
   `bloodyAD`'s internal S4U2Self call can still fail separately with
   `KDC_ERR_ETYPE_NOTSUPP` on an AES-only-hardened domain, since the URL it
   builds doesn't set an explicit `?etype=18` — a second, independent
   limitation from the `parse_qs` bug.

2. **Key retrieval** — given the above, the more reliable path is calling
   `kerbad` (the library `bloodyAD` uses internally for Kerberos,
   `pip install kerbad`) directly, bypassing `bloodyAD`'s own broken
   pre-check and setting the etype explicitly:
   ```python
   from kerbad.common.factory import KerberosClientFactory
   from kerbad.common.spn import KerberosSPN
   from kerbad.protocol.external.ticketutil import get_KRBKeys_From_TGSRep

   cu = KerberosClientFactory.from_url(
       "kerberos+password://DOMAIN\\user:password@DC_IP/?etype=18")  # etype=18 (AES256) needed explicitly on AES-only-hardened domains, default preauth attempt uses an etype the KDC will reject with KDC_ERR_ETYPE_NOTSUPP
   client = cu.get_client()
   service_spn = KerberosSPN.from_spn("krbtgt/domain.tld", default_realm=cu.domain)
   target_user = KerberosSPN.from_upn("dmsaname$@domain.tld", default_realm=cu.domain)
   await client.with_clock_skew(client.get_TGT)
   tgs, encTGSRepPart, key = await client.with_clock_skew(
       client.S4U2self, target_user, service_spn, is_dmsa=True)
   dmsa_pack = get_KRBKeys_From_TGSRep(encTGSRepPart)
   # dmsa_pack['current-keys']  -> the dMSA's own keys (privilege-merge question, patch-gated)
   # dmsa_pack['previous-keys'] -> the impersonated target's real keys (credential-disclosure, NOT patch-gated)
   ```
   Full working script: `Tooling and Scripts/exploits/checkpoint/get_dmsa_key.py`
   (mirrors `kerbad`'s own bundled `examples/getS4U2self.py` reference
   usage — legitimate library reference, not exploit-specific code).

3. **Cross-validation with Rubeus** (if you want/need a second
   implementation to confirm `current-keys`): this compiled-binaries
   GhostPack build has `/dmsa` support but **two real, independently-confirmed
   bugs**:
   - `Rubeus.exe asktgt ... /ptt` followed by a separate
     `asktgs /dmsa /targetuser:X$` (no explicit `/ticket`) silently uses
     the **wrong identity** — `Ask.TGS()` only honors `/dmsa`/`/targetuser`
     on the explicit-`/ticket:` code path; without it, Rubeus falls back to
     the current LSA session's own ticket and *silently ignores*
     `dmsa`/`targetUser` (no error, just an all-zero session key and no key
     package). **Fix**: run `asktgt ... /nowrap`, capture the single-line
     base64 kirbi from its own stdout, feed it explicitly to
     `asktgs /ticket:$captured_b64 ...`.
   - Even with an explicit `/ticket`, `/dmsa` alone builds a TGS-REQ with
     **no S4U impersonation PA-DATA at all** — in `TGS_REQ.NewTGSReq`, the
     real `PA_S4U_X509_USER` padata is only added when `/opsec` is *also*
     passed; the `dmsa`-specific fallback branch skips it too. Without
     `/opsec`, the KDC just returns an ordinary ticket with no
     `encrypted_pa_data`, and Rubeus crashes with an unhandled
     `NullReferenceException` reading `encRepPart.encryptedPaData.PA_DMSA_KEY_PACKAGE`
     off a null `encryptedPaData`. **Fix**: always pass `/opsec` alongside
     `/dmsa`.
   - Working command: `Rubeus.exe asktgs /ticket:$b64 /service:krbtgt/domain.tld /dmsa /opsec /targetuser:dmsaname$ /nowrap`

## Verifying the actual privilege-inheritance question (post-patch `current-keys` behavior)

Having the dMSA's own key material and a valid TGT for it is not the same as
having inherited the linked target's group memberships — that's precisely
what the August 2025 patch (build 26100.4946+) is designed to prevent, even
when the full "BetterSuccessor" mutual-link bypass preconditions
(`CreateChild` on the dMSA-hosting OU + `GenericWrite` on the impersonation
target) are genuinely satisfied. Test practically across at least two
independent protocols before concluding either way — a valid SMB *session*
(the ticket itself works) is not evidence of inherited privilege; check
actual access to a resource gated by the target's specific group
membership (share tree-connect, WinRM auth, WMI/DCOM) and expect a clean,
consistent denial if the patch holds for this field specifically.

**But do not stop there.** A clean, repeatable denial on `current-keys`
only answers the privilege-merge question — it says nothing about
`previous-keys`, which is returned in the exact same TGS-REP and is not
subject to the same check. Test both fields as two genuinely separate
hypotheses before writing the technique off as "patched, closed" on a given
target.

## A related, easy-to-make timezone mistake when timing anything against a DC

If you ever do need to reason about elapsed time on a DC (e.g. for an
unrelated KDS-root-key-effective-time check), be aware there can be **three
different clock domains** in play simultaneously, and conflating any two
produces a wrong "hours elapsed" figure:
1. The DC's own **local** wall clock (`Get-Date` run on-box — what AD
   attribute timestamps like `whenCreated` are rendered in).
2. The DC's own **UTC**, as reported by its SMB2 "System Time" field
   (`nmap --script smb2-time`) — can differ from (1) by the DC's configured
   timezone offset, independent of anything else.
3. The **attacker sandbox's own real-world UTC clock** — can differ from
   (2) by a completely separate, pre-existing clock skew (the reason
   `libfaketime`-based Kerberos clock-sync workarounds exist at all).
Only ever compare timestamps that came from the *same* one of these three
sources; mixing any two produces an offset that's a sum of unrelated
things and will misdirect an otherwise-sound investigation.

See also [[CVE-2025-53779]] and [[checkpoint#Privesc|Checkpoint]].
