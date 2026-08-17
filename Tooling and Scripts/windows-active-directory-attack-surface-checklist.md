# Windows / Active Directory Attack-Surface Checklist

Windows/AD boxes have burned disproportionate time in this vault relative to
web/Linux targets (13+ sessions on Checkpoint's dMSA chain before it was
conclusively closed; repeated clock-skew breakage on Garfield; Fries stalling
on a stale-cert-pin dead end after two recon passes; four independent
sessions on Pirate exhausting Kerberoasting/ADCS/RBCD-precondition/noPac/
Certifried/DCSync/ADFS-DKM/GPP/LAPS before the actual initial-access
credential — a pre2k default computer-account password — turned out to have
been sitting there the entire time, findable in the first session if
checked early rather than last). Some of that is legitimately hard-box
difficulty, but a lot of it is re-deriving the same attack surface from
scratch each engagement instead of working off a known-complete list. This
checklist exists so recon/exploit/privesc always cover the same ground
systematically — each item either finds a path or rules one out with a
concrete, citable reason (useful for the writeup, not just yourself), the
same discipline as [[docker-container-escape-enumeration-checklist]].

## Use real tools — don't hand-roll what already exists

**None of the tools below are "too heavy" or off-limits for an authorized lab
box.** PowerView/pywerview, BloodHound, Certipy, Rubeus, Mimikatz, the full
Impacket suite, netexec/CrackMapExec, bloodyAD, Responder, and Metasploit's
AD-relevant auxiliary/exploit/post modules (`smb_login`, `psexec`, `kiwi`,
`ms17_010`, etc.) are all fair game. Picking the slow manual-only path when a
known tool already implements the technique correctly is not extra rigor —
it's wasted turns and a higher chance of a subtle implementation bug. If a
tool isn't installed, install it (`pipx install`, `go install`, `git clone` +
build) rather than skip the technique. Confirmed already present in this
environment as of 2026-07-22: `certipy-ad`, `netexec`/`crackmapexec`,
`evil-winrm`, `bloodhound-python`, `bloodyAD`, `pywerview`, `responder`,
`mimikatz`, and the full impacket console-script suite
(`impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-secretsdump`,
`impacket-ntlmrelayx`, etc.). `kerbrute` and genuine `PowerView.ps1`/
`Rubeus.exe`/`SharpGPOAbuse.exe` (for once an actual Windows landing point
exists — the Linux ports don't always surface everything the real PowerShell
tool does) may need fetching per-engagement.

## 0. Environment prerequisites

- **Clock sync.** Kerberos tooling silently breaks (or produces confusing
  errors that look like a credential problem) if attacker/DC clocks drift
  more than ~5 minutes — this has bitten this vault at least twice. Check
  skew early (`nmap -p445 --script smb2-time` or `rdate`/`ntpdate` against
  the DC) and wrap Kerberos-dependent tools in `faketime` if genuine skew
  exists and can't be fixed at the OS level, rather than treating auth
  failures as credential-invalid without ruling this out first.
- **Name resolution.** Add the DC hostname + domain to `/etc/hosts` (or point
  `resolv.conf`/`--dns-server` at the DC) before anything Kerberos-dependent
  — SPN validation and ticket requests are hostname-sensitive, not just
  IP-sensitive.
- **Don't trust scraped usernames.** A website's "team" page, `git log`
  authors, or similar OSINT is a *hypothesis* for usernames, not a
  confirmed account list — verify against the DC itself (Kerberos pre-auth
  response, RID cycling, or an authenticated LDAP query) before spending
  budget on password attempts against them. (Fries: SSH prompted for a
  password against every guessed name whether or not the account existed —
  the prompt itself was not evidence of a real account.)

## 1. Unauthenticated / pre-auth enumeration

- **SMB null session:** `rpcclient -U "" -N`, `smbclient -N -L //<dc>/`,
  `enum4linux-ng.py -A`. Check for null-session share/user/group disclosure
  before assuming it's blocked — don't skip this because "modern DCs block
  it," verify. Also check every share's *own* ACL (`smbcacls`) for a
  Guests-vs-authenticated-users divergence, not just whether the null
  session connects at all — a share can be genuinely unreadable to
  `Domain Users` while still Guests-readable, which is enough on its own to
  leak a real credential from an internal document (DanglingTree: an
  IT-share `Security` subfolder was null-session-readable but
  authenticated-user-denied, containing an assessment PDF with a real
  domain password).
- **LDAP anonymous bind:** `ldapsearch -x -H ldap://<dc> -s base` (RootDSE
  always works if LDAP is up) then attempt a real bind-less search; try
  `ldapdomaindump`/`windapsearch --dc-ip <dc> -m ...` for a structured dump.
- **Kerberos username enumeration (no credential needed):**
  `kerbrute userenum` or `impacket-GetNPUsers <domain>/ -usersfile <list>
  -no-pass` — a `PRINCIPAL UNKNOWN` vs. a real (even pre-auth-required)
  response distinguishes a real account from a guessed one. Do this *before*
  trusting any username list scraped from elsewhere. If a generic/breach-
  frequency wordlist finds nothing, don't stop there — a box's own naming
  theme (a comic strip, a company's product line, whatever the box's flavor
  text points at) can be the real convention (Garfield: `f.last` built from
  the strip's own character surnames, found only after generic lists of
  ~40,000 candidates came back empty).
- **Pre-Windows 2000 compatible computer accounts (`pre2k`), early, not as
  a last resort.** Any computer object with `userAccountControl`'s
  `PASSWD_NOTREQD` bit set and no completed domain join (`lastLogon: 0`,
  no SPNs) is a candidate for the legacy default password
  (lowercase-`sAMAccountName`-without-`$`). Run
  [`pre2k`](https://github.com/garrettfoster13/pre2k) (unauthenticated
  hostname-spray mode, or authenticated `pre2k auth` once any credential
  exists) as a standard, early step — see
  [[pre2k-default-computer-account-passwords]] for the full mechanism and
  why an SMB-only test can produce a false negative. On [[Pirate]] this sat
  unfound for four sessions' worth of otherwise-thorough enumeration
  because it was never tried until every other lead (Kerberoasting, ADCS,
  BloodHound ACL sweep, coercion/relay) had already been exhausted first.
- **DNS:** zone transfer attempt (`dig axfr @<dc> <domain>`), then
  `adidnsdump` with any credential once one exists — internal AD-integrated
  DNS often reveals extra hostnames/services a port scan alone won't.
- **SMB signing/relay feasibility:** `netexec smb <targets> --gen-relay-list
  relay.txt` (or `nmap --script smb2-security-mode`) to know upfront which
  hosts are relay targets before planning a coercion chain (§5).

## 2. Credentialed enumeration & attack-path mapping

Do this the moment *any* valid credential exists, even a low-priv one —
don't wait for something that looks obviously high-value.

- **BloodHound collection:** `bloodhound-python -u <user> -p <pass> -d
  <domain> -ns <dc-ip> -c All` (or `SharpHound.exe -c All` from an actual
  Windows foothold — some collection methods, e.g. session enumeration, are
  more complete from inside). Use *All*, not a narrow collection method, on
  first pass. Its default collection doesn't surface every real write right,
  though — a property-specific/validated-write ACE (e.g. write access to a
  user's `scriptPath` attribute) can be genuinely real and confirmed
  independently via raw LDAP while never appearing as a named edge in the
  graph (Garfield). Don't treat "BloodHound didn't show an edge" as proof a
  write right doesn't exist if a raw LDAP write against the specific
  attribute in question hasn't actually been tried.
- **A default container (`CN=Users`, most often) genuinely missing from
  BloodHound's own container list — not merely empty — is the signature of
  a real container-level deny ACE, not an empty/pruned domain.** LDAP
  search against a hidden container returns `numEntries: 0` rather than a
  bind/permission error (AD deliberately masks access-denied as "doesn't
  exist" here), so don't stop at "this container has nothing in it." Read
  [[ad-hidden-container-deny-ace-side-channel-enumeration]] for the four
  independent side channels (SYSVOL `GptTmpl.inf` raw-SID mining, LSA
  `lookupsids`, SAMR BUILTIN-alias membership walks, naming-convention-
  targeted Kerberos userenum) that routinely survive a deny ACE scoped to
  LDAP reads, and re-run full AD enumeration as any newly-obtained
  credential whose own DN sits *outside* whatever OU/group the deny ACE
  turns out to be scoped to.
- **PowerView-equivalent from Linux:** `pywerview` or `netexec`/`bloodyAD`
  for `Get-Domain*`-style queries. If/when a real Windows shell exists,
  upload genuine `PowerView.ps1` too — the Linux ports don't always expose
  every cmdlet or edge case.
- **Review every ACL/ACE edge BloodHound surfaces for a principal you
  actually control** — `GenericAll`, `GenericWrite`, `WriteDACL`,
  `WriteOwner`, `ForceChangePassword`, `AddMember`, `ReadGMSAPassword`,
  `ReadLAPSPassword`. A missed edge here is the single most common way a
  legitimate path gets overlooked. **This includes re-checking after any
  new credential lands** — an ACE granted to a group you didn't previously
  hold membership in (e.g. via a newly-recovered computer account) only
  becomes visible once you're scoping the sweep to that new principal, not
  just the one you started the engagement with (Pirate: `ReadGMSAPassword`
  on two gMSAs was granted to a group whose sole member was a computer
  account nobody could authenticate as until the pre2k credential above was
  found).
- **A domain-wide `nTSecurityDescriptor` sweep needs the
  `LDAP_SERVER_SD_FLAGS` control (`sdflags=0x04`) explicitly**, or the
  attribute comes back empty from a subtree search and looks like a false
  "no extra rights" conclusion — and a sweep scoped only to objects already
  known from context can miss a real ACE placed somewhere less obvious
  (Garfield: a `DS_SELF` self-membership ACE on an otherwise-invisible
  admin-delegation group only turned up once the sweep covered every object
  in the domain, not just the ones already in the story).
- **GPO enumeration:** who has edit rights or link rights on GPOs applied to
  DC/Tier-0 OUs — that's SYSTEM on every linked computer at the next policy
  refresh (`SharpGPOAbuse`, or manual GPT modification via a writable
  SYSVOL path).
- **LAPS deployment:** who can read `ms-Mcs-AdmPwd` (legacy) or
  `msLAPS-Password` (Windows LAPS) — `netexec ldap ... -M laps` or a direct
  BloodHound edge. If the module comes back with an ambiguous "no result
  found," confirm whether the attribute exists in the schema at all
  (`CN=Schema,CN=Configuration,...`) before concluding it's an ACL-read
  problem rather than "never deployed" — the two look identical from the
  module's own output alone (Pirate: confirmed the latter, schema-level
  absence, by querying the schema directly).
- **gMSA/dMSA objects:** enumerate and check who can read a gMSA's
  `msDS-ManagedPassword`. **If a dMSA (`msDS-DelegatedManagedServiceAccount`,
  Windows Server 2025) is involved, read
  [[windows-server-2025-dmsa-badsuccessor-key-retrieval]] before spending
  any time on it** — its LDAP read is permanently blocked by design, not a
  timing issue, and this vault has already burned 13+ sessions on that trap
  once.
- **RODC computer objects:** if a Read-Only Domain Controller is anywhere in
  scope, read [[rodc-secret-replication-attack-chain]] before assuming a
  `msDS-RevealedUsers` hit means the secret is actually retrievable — the
  Password Replication Policy's deny-list evaluation is transitive group
  membership, not a literal-DN check, and getting a genuinely open PRP to
  actually yield a secret needs the Key-List attack, not DRSUAPI or
  `/rodcpwdrepl`, against a modern (post-2021) patched writable DC.

## 3. Kerberos ticket attacks

- **Kerberoasting:** `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip
  <dc> -request` (or `Rubeus.exe kerberoast` inside Windows) → crack with
  `hashcat -m 13100`.
- **AS-REP roasting:** `impacket-GetNPUsers` against any account flagged
  "does not require pre-authentication" (BloodHound surfaces this directly)
  → `hashcat -m 18200`.
- **RC4 downgrade:** if AES is enabled but the client can request RC4
  tickets, a weaker crackable hash may still be obtainable — check
  `impacket`'s `-etype` handling before assuming AES-only tickets are a dead
  end.

## 4. Delegation abuse

- **Unconstrained delegation:** BloodHound/`netexec` flags this directly.
  Coerce the delegation-holding box to auth to you (§5) and capture the
  incoming TGT in memory (`Rubeus.exe monitor` or `mimikatz
  sekurlsa::tickets` on an actual Windows landing point).
- **Constrained delegation (S4U2Self/S4U2Proxy):** `impacket-getST -spn
  <target-spn> -impersonate <victim> <domain>/<delegating-account>`. If the
  delegation's allowed-SPN string is narrower than the actual host you need
  to reach, and you separately hold `WriteSPN` on the real target, see
  [[s4u2proxy-spn-hijack-altservice-ticket]] — moving the SPN string onto
  the real target and rewriting the ticket's `sname` via `-altservice` can
  turn a narrowly-scoped grant into access against a different box
  entirely.
- **Resource-Based Constrained Delegation (RBCD):** if you control (or can
  create) a computer object and have `WriteProperty` on a target's
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, use `impacket-rbcd` to write it
  then `impacket-getST` to impersonate. Machine account quota
  (`ms-DS-MachineAccountQuota`, default 10) usually allows creating a fresh
  computer object for this if you don't already control one. **No
  pre-existing ACL edge onto the target is strictly required** if the
  target is coercible and its SMB server doesn't enforce signing — see
  [[rbcd-via-coercion-relay]] for writing RBCD onto a target using nothing
  but its own captured authentication.
- **dMSA/BadSuccessor (CVE-2025-53779):** see
  [[windows-server-2025-dmsa-badsuccessor-key-retrieval]] — `bloodyAD`'s `add
  badSuccessor` module implements the real chain; don't assume a dMSA
  `msDS-ManagedPassword` will "eventually" populate over LDAP, it never will.

## 5. Coercion → relay chains

- **Coercion primitives:** PetitPotam (MS-EFSRPC, works over an anonymous
  SMB null session in many configs), PrinterBug/MS-RPRN (needs some auth
  level, forces the DC to auth back to you), DFSCoerce, ShadowCoerce — the
  `Coercer` tool or impacket's per-technique PoC scripts fire these.
- **Relay target:** `impacket-ntlmrelayx` to LDAP/LDAPS (write RBCD or Shadow
  Credentials on the DC computer object) or to an ADCS HTTP enrollment
  endpoint (ESC8, §6) for a certificate. **Set this whole chain up and test
  the coercion step even before a credential exists** — an anonymous-only
  test at least rules the transport layer in/out, and if a credential
  surfaces later from an unrelated vector, the relay chain is then a
  30-second re-run instead of a from-scratch build (Fries: this exact chain
  was fully rehearsed pre-auth and confirmed ready, just gated correctly on
  the auth-only step).
- **If a plain relay fails with "The client requested signing," try
  `--remove-mic`** (CVE-2019-1040) before concluding the target enforces
  signing server-side — the failure can be purely the *client's* signing
  request on the coercion callback, independent of what the LDAP server
  itself requires, and the two need different diagnosis. Test per machine,
  not per patch baseline: see [[rbcd-via-coercion-relay]] for a case where
  two hosts on the identical build differed in real exposure to this
  bypass.
- **A relay's target NAT-translated behind a pivot can take well over a
  minute to actually land** — don't trust a short (<60s) packet-capture
  window as proof the coercion callback never arrives; see
  [[rbcd-via-coercion-relay]]'s NAT-delay note.
- **Shadow Credentials:** if `GenericWrite` exists on a target's
  `msDS-KeyCredentialLink`, write a certificate-based key credential
  (`certipy-ad shadow auto`) and authenticate via PKINIT without ever
  knowing/resetting the password.

## 6. AD CS (Certipy) — run this the instant *any* authenticated foothold exists

`certipy-ad find -u <user> -p <pass> -dc-ip <dc> -vulnerable` — a full
ESC1–ESC13 sweep, even from a low-priv account, since certificate template
enrollment rights are frequently broader than the rest of the domain's ACLs.

- **ESC1:** template allows client-auth EKU + enrollee-supplies-subject →
  request a cert with `SAN` set to a target admin, use for PKINIT.
- **ESC4:** template's own ACL is writable → rewrite it to be ESC1-vulnerable,
  then exploit that. **A CA's `certificateTemplates` published list can also
  reference a name with no backing AD object at all** — a consistent
  `CERTSRV_E_UNSUPPORTED_CERT_TYPE` from the CA for every account tested
  looks exactly like an ACL denying template resolution to everyone, but a
  direct existence check (LDAP `delete`/`search` returning `noSuchObject`
  rather than `insufficientAccessRights`) can reveal the object was never
  there at all — see
  [[adcs-esc4-orphaned-template-name-recreation]]. If orphaned, a bare
  `CreateChild` right on the templates container (no `ManageCa` needed at
  all) is enough to weaponize it by recreating the object under the exact
  orphaned name.
- **ESC8:** CA web enrollment lacks EPA/HTTPS-signing → coerce (§5) + relay
  NTLM to the enrollment endpoint, get a cert for the coerced (often DC)
  account, use it for domain dominance (DCSync-equivalent).
- Full ESC1–13 reference: check `certipy-ad find`'s own output annotations
  first — it names the specific ESC condition per vulnerable template rather
  than requiring separate lookup.
- **On any DC enforcing KB5014754 strong certificate mapping by default**
  (Windows Server 2022 23H2+/2025) — pass the target's real `objectSid`
  explicitly (`certipy-ad req ... -sid <target-SID>`) alongside the UPN, or
  `certipy-ad auth` rejects the resulting certificate with an "Object SID
  mismatch" error even though the enrollment itself succeeded.

## 7. Credential dumping & lateral movement (post-foothold)

- **DCSync:** `impacket-secretsdump <domain>/<user>:<pass>@<dc> -just-dc` if
  the account has (or was just granted via an ACL abuse above)
  `DS-Replication-Get-Changes[-All]`.
- **Local secrets:** `impacket-secretsdump` against any box's SAM/LSA once
  admin on it; `mimikatz sekurlsa::logonpasswords` if interactively on a
  Windows box (richer than a remote dump — catches in-memory-only
  credentials). Don't stop at SAM hashes — LSA secrets
  (`impacket-secretsdump`'s `DefaultPassword`/`$MACHINE.ACC`/cached-logon
  output) can carry a plaintext domain password for an entirely different
  account than the one being dumped (Pirate: WEB01's LSA secrets held a
  plaintext password for `a.white`, a domain user, not a local WEB01
  account).
- **Windows Credential Manager (`cmdkey /list`) can hold a saved credential
  for a completely different account than the one you're logged on as** —
  cheap to check the moment any new interactive/console logon context is
  reached, and worth decrypting via `impacket`'s `dpapi.py`
  masterkey/credential subcommands (not the generic
  `CryptUnprotectData`/`ProtectedData.Unprotect` APIs, which don't
  understand Credential Manager's on-disk wrapper format) using the
  *owning* account's own known password. See
  [[windows-credential-manager-cross-account-creds]].
- **Pass-the-hash / pass-the-ticket / overpass-the-hash:** impacket's
  `wmiexec`/`psexec`/`smbexec -hashes <nt-hash>`, or `impacket-getTGT` +
  `KRB5CCNAME` export for ticket reuse; Metasploit's `psexec`/`smb_login`
  modules are equally legitimate here — use whichever gets it done fastest.
  If `wmiexec`'s output retrieval is flaky (AV/EDR interference,
  "Could not retrieve output file"), a direct `smbclient` read against
  `C$`/`ADMIN$` with the same credential is a reliable, cheap fallback for
  simple file reads (e.g. grabbing a flag file) even without full command
  execution.

## 8. Trust & cross-domain

- Enumerate trusts (`nxc ldap ... --trusted-for-delegation`, `netexec`, or
  `nltest /domain_trusts` from an actual Windows box) before assuming a
  single domain is the whole scope.
- SID history / `ExtraSids` abuse across a trust, and foreign security
  principals sitting in local groups, are both easy to miss if enumeration
  stopped at the first domain found.

## 9. Password spraying

Cross-reference [[credential_spray_hard_cap]] (vault memory) before doing
this at all — it's a distinct, low-cap risk category (~20-30 guesses per
account), never a full wordlist without an explicit ask, and never against
an account nobody actually pointed you at. `kerbrute passwordspray` respects
a lockout-aware pace better than hand-rolled loops if spraying is genuinely
authorized for this engagement.

## When everything above comes back clean

That's a real, citable conclusion — "full ACL/Kerberos/delegation/ADCS/
coercion surface checked, nothing exploitable at this credential level" —
not a dead end to gloss over in the writeup. The next real move is usually
one of: a credential from an entirely different surface (web app, file
share, config file — loop back to §2 once you have it), waiting for a
scheduled/simulated interactive logon to catch a live session (Garfield's
logon-script hijack), or a version-fingerprinted CVE specific to whatever
service is actually running (patch-diff it per this vault's standing
requirement, don't just cite the CVE ID). **Re-check §1's pre2k step
specifically before declaring a genuine dead end** — it's cheap, it's easy
to skip in favor of higher-drama vectors, and on Pirate it was the one item
on this entire list that four sessions of otherwise-correct methodology
kept deferring past.

## Seen on

- [[checkpoint#Privesc|Checkpoint]] — dMSA/BadSuccessor (CVE-2025-53779)
  chased for 13+ sessions before conclusively closing it as by-design
  LDAP-blocked, not a timing problem; see
  [[windows-server-2025-dmsa-badsuccessor-key-retrieval]] for the corrected
  mechanism so a future box doesn't repeat the detour.
- [[garfield#Root|Garfield]] — full chain from a logon-script hijack
  (`scriptPath` write, not a named BloodHound edge) through `ForceChangePassword`,
  RBCD onto an RODC, a real network-layer pivot, and a genuinely misconfigured
  `msDS-NeverRevealGroup`/`msDS-RevealOnDemandGroup` PRP (transitive group
  membership, not a literal-DN check) to the domain `Administrator`'s real
  NTLM hash via the RODC Key-List attack — two real impacket bugs found and
  patched along the way. Also the box where clock skew (~8h) first broke
  Kerberos tooling in this vault. See
  [[rodc-secret-replication-attack-chain]],
  [[single-port-reverse-relay-pivot-design]],
  [[ligolo-ng-windows-agent-cross-compile]], and
  [[winrm-double-hop-netonly-bypass]].
- [[fries]] — full coercion (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce) →
  `ntlmrelayx` LDAP-relay chain rehearsed and confirmed ready against a null
  session; blocked correctly at the auth-only gate, not a missed vector. AD
  CS role discovered late (§6 should have run day one once *any* credential
  existed, not been left for "later").
- [[Pirate]] — a pre2k default computer-account password (§1) unlocked the
  entire chain, but wasn't tried until four sessions of Kerberoasting/ADCS/
  BloodHound-ACL-sweep/coercion-relay/noPac/Certifried/DCSync/ADFS-DKM/GPP/
  LAPS had already been exhausted first — see
  [[pre2k-default-computer-account-passwords]]. From there: `ReadGMSAPassword`
  reachable only via a newly-recovered principal's group membership (§2),
  RBCD written via coercion with no pre-existing ACL (§4,
  [[rbcd-via-coercion-relay]]), and a narrow constrained-delegation grant
  escalated to a different host entirely via an SPN move + `-altservice`
  ticket rewrite (§4, [[s4u2proxy-spn-hijack-altservice-ticket]]).
- [[DanglingTree]] — a whole hidden `CN=Users` container (four accounts,
  three groups) unmasked via §2's side-channel technique
  ([[ad-hidden-container-deny-ace-side-channel-enumeration]]) after
  BloodHound's collection showed every default container except that one; a
  25-session engagement whose real blocking unknown turned out to be sitting
  in a different account's own Windows Credential Manager
  ([[windows-credential-manager-cross-account-creds]]); and root via §6's
  new orphaned-template ESC4 variant
  ([[adcs-esc4-orphaned-template-name-recreation]]), with a KB5014754
  `-sid` mismatch hit and fixed along the way.
