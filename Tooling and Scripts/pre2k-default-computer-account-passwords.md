# Pre-Windows 2000 Compatible Computer Accounts — Default Password Check

A computer object created (or provisioned via a script) with the legacy
"Assign this computer account as a pre-Windows 2000 computer" behavior gets
its initial password set to the lowercase `sAMAccountName` **without** the
trailing `$` — e.g. a computer account `MS01$` gets password `ms01`. This is
a 20+ year old default, not a bug, but it survives in real (and lab)
environments any time a computer object gets created and never actually
completes domain join / never has its password changed by a live machine.

## Why this is easy to miss

The account looks like a normal, unremarkable computer object in a plain
LDAP/BloodHound dump — nothing flags it as interesting unless you cross-
reference two separate signals:

- **`userAccountControl` carries `PASSWD_NOTREQD` (`0x0020`).** This bit
  means the DC never enforced a password-complexity/length policy on the
  account — the strongest available signal that whatever password is
  currently set (if any) might still be the created-time default rather
  than something a real machine negotiated.
- **No completed domain join.** `lastLogon: 0`, `logonCount: 0`, no SPNs,
  and often no `dNSHostName` at all — the object was created and then
  abandoned rather than actually joined by a real machine.

Neither signal alone proves the default password is live; together, on an
account that was clearly pre-staged and never finished setup, it's the
single highest-value thing to try next.

## How to check it

**Dedicated tool (does this systematically, across every computer object in
the domain, in one pass):**
[`pre2k`](https://github.com/garrettfoster13/pre2k) (`pip3 install` /
`pipx install git+https://github.com/garrettfoster13/pre2k.git`) —
unauthenticated mode sprays a list of recovered hostnames; authenticated
mode (`pre2k auth -u <user> -p <pass> -d <domain> -dc-ip <dc>`) enumerates
every computer object via LDAP and tries the derived default password
against each one directly. Confirms via Kerberos AS-REQ pre-auth, so a
"VALID CREDENTIALS" result is not a false positive from a permissive SMB
logon path.

**Manual equivalent, if `pre2k` isn't available or you want to confirm by
hand:** pull `userAccountControl` for every computer object and flag any
with the `PASSWD_NOTREQD` bit set, then try
`impacket-getTGT '<domain>/<SAMACCOUNTNAME>$:<samaccountname-lowercase>'
-dc-ip <dc>`. A successful TGT request — and specifically a ticket that
carries the `pre_authent` flag (check with `impacket-describeTicket`) — is
definitive proof the password is correct: Kerberos AS-REQ pre-authentication
only succeeds once the KDC has decrypted the client's encrypted timestamp
using the account's real long-term key. A wrong password produces a
completely different KDC error (`KDC_ERR_PREAUTH_FAILED`), not a ticket at
all.

**Don't rely on an SMB-only test to rule this out.** A computer account
often can't complete the SMB (NTLM) logon flow the same way a user account
can — you'll see `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`, which is an
account-type/logon-type mismatch, not a "wrong password" response
(`STATUS_LOGON_FAILURE`). If you only try SMB and see that error, it's easy
to wrongly conclude the guess was wrong when it was actually right —
Kerberos is the definitive channel to test this on.

## Why it matters even when the account itself has no interesting rights

The account rarely holds anything valuable by itself. What makes it worth
finding is that it's a **credential**, and credentials unlock whatever
group membership or ACL the account happens to sit in — which may be a
group nobody thought to check because the account controlling it wasn't in
scope until this credential existed. On [[Pirate#Foothold|Pirate]], `MS01$`
(recovered exactly this way) turned out to be the sole member of a
non-default group holding `ReadGMSAPassword` on two gMSAs, neither of which
was reachable from any identity checked before that credential was found.

## When to run this

**Early — as a standard step in any AD computer-account enumeration pass,
not an afterthought reached for only after every other vector is
exhausted.** It costs one LDAP query (`userAccountControl` for every
computer object) plus one Kerberos round-trip per pre-staged-looking
account; there's no reason to defer it behind Kerberoasting, ADCS, or a
BloodHound ACL sweep the way it ended up being deferred on Pirate.

## Seen on

- [[Pirate#Foothold|Pirate]] — `MS01$`/`EXCH01$` both carried
  `PASSWD_NOTREQD` and neither ever completed domain join; `MS01$:ms01`
  worked and was the credential the entire rest of the chain (gMSA hash
  read → DC01 WinRM → WEB01 pivot → RBCD → root) built on. Found via manual
  `userAccountControl` reasoning in one session before the dedicated
  `pre2k` tool was run in a later session to reconfirm it — both routes
  reach the same result, the tool just automates the check.
